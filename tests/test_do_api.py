"""The environments API for DigitalOcean (S20, P4 J1): the HTTP half of S18's service rules, over the routes.

P4 tests 62 (the production fences' API side: Activate's typed name, retire and un-retire, Deactivate, Delete's
phrases and its audit without a snapshot), 64 (create's refusals with their field, ``?check=true`` with the cost,
the typed total, the limit, the rows written, no secret in an audit row), 65 (grow, Add slot and Remove slot), 67
(``GET /environments/{id}/cloud``), 68 (the permission matrix, the new kinds' retries), 88's API half (the
pending-resize phrase), 52's API half (a Slipway-kept backup: ``?check=true`` and Delete), and the traffic PATCH
rules, the certificate route, resolve's 502 and Decision 21's first deploy.

FakeDigitalOcean answers every DigitalOcean read and fails the test when it is called while the account row is
locked (test 88). Jobs are queued and never run.
"""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select, update

from slipway.db.session import get_sessionmaker
from slipway.models import (
    AppSetting,
    AuditEvent,
    Backup,
    Deployment,
    Environment,
    Host,
    Instance,
    ProviderAccount,
    Repository,
    Resource,
)
from slipway.services import backup_store, cloudflare, deployer, digitalocean, do_rules, environments, provider_accounts
from tests import do_fixtures as dof
from tests import fake_digitalocean as fdo
from tests.test_data_api import client_with, clients, storage  # noqa: F401  (storage: autouse)
from tests.test_do_create import ADMIN, FILES, ONE, TWO, reader
from tests.test_final_remote import ShellRemote

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")

API = "/api/v1/environments"
SPEND = "Creating a DigitalOcean environment needs the providers:spend permission"


@pytest.fixture(autouse=True)
def submitted(monkeypatch) -> list[uuid.UUID]:
    """Jobs are queued, never run."""
    found: list[uuid.UUID] = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, keys: found.append(dep_id))
    return found


@dataclass
class World:
    c: dict[str, httpx.AsyncClient]
    repo_id: uuid.UUID
    account_id: uuid.UUID
    fake: fdo.FakeDigitalOcean
    files: dict[str, str | None]
    calls: list[str] = field(default_factory=list)
    locked: list[bool] = field(default_factory=lambda: [False])

    @property
    def admin(self) -> httpx.AsyncClient:
        return self.c["admin"]


@pytest.fixture
async def w(make_client, monkeypatch) -> World:
    """The four signed-in roles, a repository, a DigitalOcean account (the fake's token), Cloudflare on example.com
    and GitHub as a dict of files. The fake fails the test when called while the account row is locked."""
    provider_accounts.clear_catalog_cache()
    fake = fdo.FakeDigitalOcean()
    fdo.use_fake(monkeypatch, fake)
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=4242, full_name="acme/serversherpa", owner="acme", name="serversherpa",
                          html_url="https://github.com/acme/serversherpa", detected_config={})
        db.add(repo)
        db.add(AppSetting(key=cloudflare.SETTING_KEY, value={"zone": "example.com", "public_ip": None,
                                                             "proxied": False}, secret="c" * 40))
        await db.commit()
    files: dict[str, str | None] = dict(FILES)
    world = World(c=await clients(make_client), repo_id=repo.id, account_id=await dof.make_account(), fake=fake,
                  files=files)

    async def handler(request: httpx.Request) -> httpx.Response:
        assert not world.locked[0], f"DigitalOcean was called while the account row was locked: {request.url.path}"
        world.calls.append(request.url.path)
        return fake.handler(request)

    monkeypatch.setattr(digitalocean, "transport_factory", lambda: httpx.MockTransport(handler))
    real_get = provider_accounts.get

    async def get(db, account_id, *, lock=False):
        if lock:
            world.locked[0] = True
        return await real_get(db, account_id, lock=lock)

    monkeypatch.setattr(provider_accounts, "get", get)
    monkeypatch.setattr(environments, "github_reader", lambda user: reader(files))
    return world


def create_body(w: World, **kw: Any) -> dict[str, Any]:
    placement = {"provider": "digitalocean", "account_id": str(w.account_id), "region": "nyc3",
                 "droplet_size": "s-1vcpu-1gb", "db_size": "db-s-1vcpu-1gb", "db_standby": False,
                 "acme_staging": False, "slots": 1, **kw.pop("placement", {})}
    body: dict[str, Any] = {"name": "shop", "repository_id": str(w.repo_id), "data_mode": "managed",
                            "settings": {"STACK_DOMAIN": "shop.example.com"},
                            "traffic": {"switch": "do_lb", "dns": {"proxied": False}}, "first_admin": ADMIN,
                            "placement": placement}
    body.update(kw)
    return body


async def post_create(w: World, client: httpx.AsyncClient | None = None, *, check: bool = False,
                      **kw: Any) -> httpx.Response:
    resp = await (client or w.admin).post(API, json=create_body(w, **kw), params={"check": "true"} if check else None)
    w.locked[0] = False
    return resp


def typed_total(resp: httpx.Response) -> str:
    """The figure a 422 ``Type <x> to confirm about $<x> a month`` asks for."""
    found = re.match(r"Type ([0-9.]+) to confirm", resp.json()["detail"])
    assert found, resp.text
    return found.group(1)


async def count(model: Any, *where: Any) -> int:
    async with get_sessionmaker()() as db:
        return int(await db.scalar(select(func.count()).select_from(model).where(*where)) or 0)


async def audits(action: str) -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        return list(await db.scalars(select(AuditEvent).where(AuditEvent.action == action)
                                     .order_by(AuditEvent.created_at)))


async def set_rows(model: Any, ident: uuid.UUID, **values: Any) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(update(model).where(model.id == ident).values(**values))
        await db.commit()


async def set_account(w: World, **values: Any) -> None:
    async with get_sessionmaker()() as db:
        row = await db.get(ProviderAccount, w.account_id)
        direct = {k: v for k, v in values.items() if k in ("production", "secret")}
        if direct:
            await db.execute(update(ProviderAccount).where(ProviderAccount.id == w.account_id).values(**direct))
        rest = {k: v for k, v in values.items() if k not in direct}
        if rest:
            row.config = {**row.config, **rest}
        await db.commit()


async def built(env: dof.DoEnv, slot: str, *, size: str = "s-1vcpu-1gb", live: bool = True) -> None:
    """``slot``'s droplet as prepare leaves it (built, pinned), and with a live release when ``live``."""
    await set_rows(Host, env.host_ids[slot], provider_state={"phase": "ready", "size": size},
                   host_key="ssh-ed25519 AAAA", hostname=f"203.0.113.{10 + len(slot)}")
    if live:
        await set_rows(Instance, env.ids[slot], current_commit_sha=dof.SHA, status="running",
                       app_state={"live": {"release": "r1", "sha": dof.SHA, "deployment": "11" * 16}})


def secrets_absent(text: str, *extra: str) -> None:
    for secret in (dof.TOKEN, ADMIN["password"], *extra):
        assert secret not in text


# ------------------------------------------------------------------ test 64: create over HTTP


async def test_64_create_refuses_with_its_text_and_field_and_writes_nothing(w, make_client):
    spender = await client_with(make_client, "writer@example.com", ["environments:write", "environments:read"])
    resp = await post_create(w, spender)
    assert (resp.status_code, resp.json()) == (403, {"detail": SPEND, "field": "placement"})
    resp = await post_create(w, traffic={"switch": "switchyard", "dns": None})
    assert (resp.status_code, resp.json()["field"]) == (409, "traffic.switch")
    assert resp.json()["detail"] == environments.DO_NEEDS_LB
    async with get_sessionmaker()() as db:
        host = Host(name="h-blue", hostname="10.0.0.11", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
        db.add(host)
        await db.commit()
    plain = {"name": "plain", "repository_id": str(w.repo_id), "data_mode": "slot", "hosts": {"blue": str(host.id)},
             "settings": {"STACK_DOMAIN": "plain.example.com", "STACK_PROXY_IP": "10.0.0.2"},
             "traffic": {"switch": "do_lb", "dns": None}, "first_admin": ADMIN}
    resp = await w.admin.post(API, json=plain)
    assert (resp.status_code, resp.json()) == (409, {"detail": environments.LB_NEEDS_DO, "field": "traffic.switch"})
    # The typed total: missing or wrong 422; the estimate moved since the page showed it 409.
    resp = await post_create(w, confirm_cost="1.00")
    assert (resp.status_code, resp.json()["field"]) == (422, "confirm_cost")
    assert resp.json()["detail"] == f"Type {ONE} to confirm about ${ONE} a month"
    w.fake.sizes[0]["price_monthly"] = 7.0
    resp = await post_create(w, confirm_cost=ONE)
    assert (resp.status_code, resp.json()["detail"]) == (
        409, "The estimate changed to $39.00 a month (DigitalOcean's prices moved): check it again")
    # The account's limit, against the stored totals.
    await set_account(w, monthly_limit_cents=3000)
    resp = await post_create(w, confirm_cost="39.00")
    assert (resp.status_code, resp.json()["field"]) == (409, "confirm_cost")
    assert "over its limit of $30.00" in resp.json()["detail"]
    await set_account(w, monthly_limit_cents=None)
    # DigitalOcean down while the catalog is read: 502 with the client's text, never the token.
    w.fake.down = True
    resp = await post_create(w)
    assert resp.status_code == 502 and resp.json()["field"] == "placement"
    secrets_absent(resp.text)
    w.fake.down = False
    assert await count(Environment) == 0 and await count(Instance) == 0
    assert await count(Host, Host.provider == "digitalocean") == 0


async def test_64_check_answers_the_cost_and_the_planned_slots_and_writes_nothing(w):
    resp = await post_create(w, check=True, placement={"slots": 2})
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["cost"]["total"] == TWO and out["plan"]["cloud"]["plan"]["droplets"] == 2
    assert out["plan"]["slots"]["blue"] == {"host_id": None, "host": "slipway-shop-blue", "role": "app",
                                            "slug": "shop-blue", "planned": "digitalocean"}
    assert out["plan"]["slots"]["data"]["managed"] is True
    secrets_absent(resp.text)
    assert await count(Environment) == 0 and await count(AuditEvent, AuditEvent.action.like("environment.%")) == 0


async def test_64_and_80_create_writes_the_rows_and_answers_the_environment(w):
    resp = await post_create(w, placement={"slots": 2}, confirm_cost=TWO)
    assert resp.status_code == 201, resp.text
    out = resp.json()
    assert out["provider"] == "digitalocean" and out["production"] is False and out["retiring_at"] is None
    assert out["data_mode"] == "managed" and out["traffic"]["switch"] == "do_lb"
    slots = {s["slot"]: s for s in out["slots"]}
    assert slots["data"]["host"] is None and slots["data"]["role"] == "data"
    assert slots["blue"]["host"]["name"] == "slipway-shop-blue" and slots["green"]["resize_pending"] is None
    cloud = out["cloud"]
    assert cloud["account"]["name"] == "do-main" and cloud["region"] == "nyc3"
    assert cloud["sizes"]["droplet_size"] == "s-1vcpu-1gb" and cloud["sizes"]["droplets"] == 2
    assert cloud["cost"]["total_cents"] == 4400 and cloud["billing_open"] is False and cloud["objects"] == 0
    summary = [e for e in (await w.admin.get(API)).json() if e["name"] == "shop"][0]
    assert {s["slot"]: s["host_name"] for s in summary["slots"]} == {
        "blue": "slipway-shop-blue", "green": "slipway-shop-green", "data": None}
    again = await w.admin.get(f"{API}/{out['id']}")
    assert again.status_code == 200 and again.json()["cloud"]["sizes"]["db_size"] == "db-s-1vcpu-1gb"
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, uuid.UUID(out["id"]))
        assert await db.scalar(select(func.count()).select_from(Host).where(
            Host.owner_environment_id == env.id)) == 2
        assert await db.scalar(select(func.count()).select_from(Instance).where(Instance.host_id.is_(None))) == 1
        secrets = list(env.app_secrets.values())
    events = await audits("environment.create") + await audits("environment.cost_confirmed")
    assert {e.action for e in events} == {"environment.create", "environment.cost_confirmed"}
    secrets_absent(str([e.details for e in events]), *secrets)
    secrets_absent(again.text, *secrets)
    # The owner answers GET and PATCH with no host (P4 §3.4).
    owner = (await w.admin.get(f"/api/v1/instances/{slots['data']['instance_id']}")).json()
    assert owner["host"] is None and owner["host_id"] is None and owner["slot"] == "data"


async def test_create_needs_writers_and_spenders_in_the_matrix(w):
    """Test 68, create: viewer and developer lack environments:write; the maintainer has providers:spend."""
    for role in ("viewer", "developer"):
        assert (await post_create(w, w.c[role], check=True)).status_code == 403
    resp = await post_create(w, w.c["maintainer"], check=True)
    assert resp.status_code == 200, resp.text


# ----------------------------------------------------------- tests 65 and 88: grow and Add slot


async def test_88_patch_grows_the_sizes_with_the_typed_total_and_shows_the_pending_resize(w, make_client):
    env = await dof.make_do_env(name="grow", account_id=w.account_id, slots=("blue",))
    await built(env, "blue")
    url = f"{API}/{env.env_id}"
    grow = {"cloud": {"droplet_size": "s-1vcpu-2gb"}}
    plain = await client_with(make_client, "plain@example.com", ["environments:write", "environments:read"])
    resp = await plain.patch(url, json={**grow, "confirm_cost": "1.00"})
    w.locked[0] = False
    assert (resp.status_code, resp.json()["field"]) == (403, "cloud")
    resp = await w.admin.patch(url, json={**grow, "confirm_cost": "1.00"})
    w.locked[0] = False
    assert (resp.status_code, resp.json()["field"]) == (422, "confirm_cost")
    total = typed_total(resp)
    resp = await w.admin.patch(url, json={"cloud": {"droplet_size": "s-1vcpu-512mb-10gb"}, "confirm_cost": total})
    w.locked[0] = False
    assert (resp.status_code, resp.json()["field"]) == (409, "cloud.droplet_size")
    calls = len(w.calls)
    resp = await w.admin.patch(url, json={**grow, "confirm_cost": total})
    w.locked[0] = False
    assert resp.status_code == 200, resp.text
    assert len(w.calls) > calls  # the catalog was read live, and never under the account's lock
    out = resp.json()
    blue = next(s for s in out["slots"] if s["slot"] == "blue")
    assert blue["resize_pending"] == "Resize pending: applies at blue's next deploy"
    assert out["cloud"]["pending_resizes"] == {"blue": "Resize pending: applies at blue's next deploy"}
    assert out["actions"]["grow"]["pending"] == out["cloud"]["pending_resizes"]
    assert out["cloud"]["sizes"]["droplet_size"] == "s-1vcpu-2gb"
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        assert row.cloud["droplet_size"] == row.cloud["plan"]["droplet_size"] == "s-1vcpu-2gb"
    assert [e.details["to"]["droplet_size"] for e in await audits("environment.resize")] == ["s-1vcpu-2gb"]
    assert len(await audits("environment.cost_confirmed")) == 1


async def test_65_add_slot_on_digitalocean_and_remove_slot(w):
    env = await dof.make_do_env(name="one", account_id=w.account_id, slots=("blue",))
    url = f"{API}/{env.env_id}/slots"
    resp = await w.admin.post(url, json={"host_id": str(uuid.uuid4())})
    assert (resp.status_code, resp.json()["field"]) == (422, "host_id")
    resp = await w.c["developer"].post(url, json={})
    assert resp.status_code == 403
    resp = await w.admin.post(url, json={"confirm_cost": "1.00"})
    w.locked[0] = False
    assert (resp.status_code, resp.json()) == (422, {"detail": f"Type {TWO} to confirm about ${TWO} a month",
                                                     "field": "confirm_cost"})
    resp = await w.admin.post(url, json={"confirm_cost": TWO})
    w.locked[0] = False
    assert resp.status_code == 201, resp.text
    out = resp.json()
    assert out["slot"] == "green" and out["host"]["name"] == "slipway-one-green" and out["deployment"] is None
    assert out["note"] == "Deploy to green to build it"
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        assert row.cloud["plan"]["droplets"] == 2 and row.cloud["cost"]["total_cents"] == 4400
    assert [e.details["droplet"] for e in await audits("environment.slot_add")] == ["slipway-one-green"]
    resp = await w.admin.post(url, json={"confirm_cost": TWO})
    assert (resp.status_code, resp.json()["detail"]) == (409, "one already has two slots")
    # Remove slot: the name typed, then the queued job (its slot step removes the droplet and lowers the cost).
    resp = await w.admin.request("DELETE", f"{url}/green", json={"confirm": "nope"})
    assert resp.status_code == 422
    resp = await w.admin.request("DELETE", f"{url}/green", json={"confirm": "one"})
    assert resp.status_code == 202, resp.text
    assert resp.json()["kind"] == "remove_slot"


# --------------------------------------------------------------- traffic follows placement (PATCH)


async def test_patch_traffic_follows_placement(w):
    env = await dof.make_do_env(name="tr", account_id=w.account_id, slots=("blue",))
    url = f"{API}/{env.env_id}"
    await set_rows(Environment, env.env_id, traffic={"switch": "do_lb", "dns": {
        "provider": "cloudflare", "address": "203.0.113.50", "proxied": False}})
    cases = [({"switch": "switchyard", "dns": {"proxied": False}}, "traffic.switch"),
             ({"switch": "none", "dns": {"proxied": False}}, "traffic.switch"),
             ({"switch": "do_lb", "dns": {"address": "198.51.100.9"}}, "traffic.dns.address"),
             ({"switch": "do_lb", "dns": None}, "traffic.dns")]
    for traffic, where in cases:
        resp = await w.admin.patch(url, json={"traffic": traffic})
        assert (resp.status_code, resp.json()["field"]) == (409, where), (traffic, resp.text)
    resp = await w.admin.patch(url, json={"traffic": {"switch": "do_lb", "dns": {"proxied": True,
                                                                                "address": "203.0.113.50"}}})
    assert resp.status_code == 200, resp.text
    assert resp.json()["traffic"]["dns"] == {"provider": "cloudflare", "address": "203.0.113.50", "proxied": True}
    # do_lb on an SSH environment.
    async with get_sessionmaker()() as db:
        host = Host(name="ssh-1", hostname="10.0.0.21", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
        repo = await db.get(Repository, w.repo_id)
        plain = Environment(name="plain", repository=repo, branch="main", data_mode="slot", app_settings={},
                            app_secrets={}, env={}, traffic={"switch": "none", "dns": None}, status="new")
        db.add_all([host, plain])
        await db.flush()
        db.add(Instance(name="plain blue", slug="plain-blue", branch="main", host_id=host.id, repository=repo, env={},
                        ports=[], volumes=[], build_source="app", environment_id=plain.id, slot="blue"))
        await db.commit()
    resp = await w.admin.patch(f"{API}/{plain.id}", json={"traffic": {"switch": "do_lb", "dns": None}})
    assert (resp.status_code, resp.json()) == (409, {"detail": environments.LB_NEEDS_DO, "field": "traffic.switch"})


# ----------------------------------------------------------- test 62: production over HTTP


async def prod(w: World, **kw: Any) -> dof.DoEnv:
    await set_account(w, production=True)
    return await dof.make_do_env(name="prod", account_id=w.account_id, production=True, **kw)


async def test_62_activate_needs_the_name_and_a_retiring_production_only_goes_dark(w):
    env = await prod(w)
    await built(env, "blue")
    await built(env, "green")
    url = f"{API}/{env.env_id}"
    resp = await w.admin.post(f"{url}/activate", json={"slot": "blue"})
    assert (resp.status_code, resp.json()["detail"]) == (422, "Type the environment's name, prod, exactly to confirm")
    # Retire: the name typed, environments:delete; then no slot can be activated.
    assert (await w.c["developer"].post(f"{url}/retire", json={"confirm": "prod"})).status_code == 403
    resp = await w.admin.post(f"{url}/retire", json={})
    assert (resp.status_code, resp.json()["field"]) == (422, "confirm")
    resp = await w.c["maintainer"].post(f"{url}/retire", json={"confirm": "prod"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["retiring_at"] is not None and resp.json()["actions"]["unretire"]["available"] is True
    resp = await w.admin.post(f"{url}/retire", json={"confirm": "prod"})
    assert (resp.status_code, resp.json()["detail"]) == (409, "prod is already retiring")
    resp = await w.admin.post(f"{url}/activate", json={"slot": "blue", "confirm": "prod"})
    assert (resp.status_code, resp.json()["detail"]) == (409, "prod is retiring: it only goes dark")
    # Un-retire, then retire again.
    resp = await w.admin.request("DELETE", f"{url}/retire", json={"confirm": "prod"})
    assert resp.status_code == 200 and resp.json()["retiring_at"] is None
    assert [e.action for e in await audits("environment.retire") + await audits("environment.unretire")] == [
        "environment.retire", "environment.unretire"]
    resp = await w.admin.request("DELETE", f"{url}/retire", json={"confirm": "prod"})
    assert (resp.status_code, resp.json()["detail"]) == (409, "prod isn't retiring")


async def test_62_deactivate_takes_a_retiring_production_off_the_air(w):
    env = await prod(w)
    await built(env, "blue")
    await set_rows(Environment, env.env_id, active_slot_id=env.ids["blue"], status="live")
    url = f"{API}/{env.env_id}/deactivate"
    assert (await w.c["developer"].post(url, json={"confirm": "prod"})).status_code == 403  # no environments:delete
    resp = await w.admin.post(url, json={"confirm": "nope"})
    assert resp.status_code == 422
    resp = await w.admin.post(url, json={"confirm": "prod"})
    assert resp.status_code == 409 and "retir" in resp.json()["detail"]
    await set_rows(Environment, env.env_id, retiring_at=datetime.now(UTC))
    resp = await w.admin.post(url, json={"confirm": "prod"})
    assert resp.status_code == 202, resp.text
    assert resp.json()["kind"] == "deactivate"
    [event] = await audits("environment.deactivate")
    assert event.target_id == str(env.env_id) and event.details["slot"] == "blue"
    assert event.details["deployment"] == resp.json()["id"]


async def test_62_delete_of_production_needs_retiring_dark_the_phrase_and_a_snapshot(w):
    env = await prod(w)
    await built(env, "blue")
    await set_rows(Instance, env.ids["data"], fresh_data="seeded")  # it holds data
    url = f"{API}/{env.env_id}"
    resp = await w.admin.request("DELETE", url, json={"confirm": "prod"})
    assert (resp.status_code, resp.json()["field"]) == (422, "confirm_production")
    phrase = {"confirm": "prod", "confirm_production": "delete production prod"}
    resp = await w.admin.request("DELETE", url, json=phrase)
    assert resp.status_code == 409 and resp.json()["detail"].startswith("Retire prod first")
    await set_rows(Environment, env.env_id, retiring_at=datetime.now(UTC), active_slot_id=env.ids["blue"])
    resp = await w.admin.request("DELETE", url, json=phrase)
    assert (resp.status_code, resp.json()["detail"]) == (409, "Deactivate prod first: it still takes traffic")
    await set_rows(Environment, env.env_id, active_slot_id=None)
    resp = await w.admin.request("DELETE", url, json=phrase)
    assert (resp.status_code, resp.json()) == (422, {"detail": "A production environment is deleted only after a "
                                                               "snapshot", "field": "snapshot"})
    assert await count(Deployment) == 0


async def test_62_delete_of_production_that_never_held_data_goes_without_a_snapshot_with_the_note(w):
    env = await prod(w)
    await set_rows(Environment, env.env_id, retiring_at=datetime.now(UTC))
    resp = await w.admin.request("DELETE", f"{API}/{env.env_id}",
                                 json={"confirm": "prod", "confirm_production": "delete production prod",
                                       "snapshot": {"name": "prod-last"}})
    assert resp.status_code == 202, resp.text
    out = resp.json()
    assert out["kind"] == "teardown" and out["note"] == "prod never held data, so there is nothing to snapshot"
    assert await audits("environment.delete_without_snapshot") == []


async def test_62_production_with_every_droplet_gone_needs_the_second_phrase_and_audits_it(w):
    env = await prod(w)
    await set_rows(Instance, env.ids["blue"], current_commit_sha=dof.SHA, status="running")  # it held data
    await set_rows(Environment, env.env_id, retiring_at=datetime.now(UTC))
    url = f"{API}/{env.env_id}"
    body = {"confirm": "prod", "confirm_production": "delete production prod"}
    resp = await w.admin.request("DELETE", url, json=body)
    assert (resp.status_code, resp.json()["field"]) == (422, "confirm_no_snapshot")
    body["confirm_no_snapshot"] = "delete production prod without a snapshot"
    resp = await w.admin.request("DELETE", url, json=body)
    assert (resp.status_code, resp.json()["field"]) == (409, "drop_data")
    resp = await w.admin.request("DELETE", url, json={**body, "drop_data": True})
    assert resp.status_code == 202, resp.text
    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, uuid.UUID(resp.json()["id"]))
        assert dep.kind == "teardown" and dep.options["no_snapshot"] is True and dep.options["drop_data"] is True
    [event] = await audits("environment.delete_without_snapshot")
    assert event.details["why"] and event.details["deployment"] == resp.json()["id"]


async def test_62_managed_data_goes_without_a_snapshot_only_with_drop_data_and_data_reset(w, make_client):
    env = await dof.make_do_env(name="uat", account_id=w.account_id)
    await built(env, "blue")
    await set_rows(Instance, env.ids["data"], fresh_data="seeded")
    url = f"{API}/{env.env_id}"
    resp = await w.admin.request("DELETE", url, json={"confirm": "uat"})
    assert (resp.status_code, resp.json()) == (409, {
        "detail": "uat's data is in its managed database, which Delete destroys: take a snapshot first, or confirm "
                  "that the data goes with it", "field": "drop_data"})
    deleter = await client_with(make_client, "deleter@example.com", ["environments:delete", "environments:read"])
    resp = await deleter.request("DELETE", url, json={"confirm": "uat", "drop_data": True})
    assert (resp.status_code, resp.json()["field"]) == (403, "drop_data")
    resp = await w.admin.request("DELETE", url, json={"confirm": "uat", "drop_data": True})
    assert resp.status_code == 202, resp.text
    [event] = await audits("environment.delete_without_snapshot")
    assert event.details["why"].startswith("drop_data")


# ------------------------------------------------------ the certificate, the cloud, resolve, deploy


async def record(env: dof.DoEnv, kind: str, provider_id: str, name: str, **details: Any) -> None:
    async with get_sessionmaker()() as db:
        db.add(Resource(environment_id=env.env_id, provider="digitalocean", kind=kind, provider_id=provider_id,
                        name=name, origin="created", details=details))
        await db.commit()


async def test_renew_the_certificate_now(w):
    env = await dof.make_do_env(name="crt", account_id=w.account_id, slots=("blue",), status="live")
    url = f"{API}/{env.env_id}/certificate"
    resp = await w.admin.post(url)
    assert (resp.status_code, resp.json()["detail"]) == (409, "crt has no load balancer yet: deploy it first")
    await record(env, "load_balancer", "lb-1", do_rules.lb_name("crt"))
    assert (await w.c["viewer"].post(url)).status_code == 403
    resp = await w.c["developer"].post(url)  # traffic:switch
    assert resp.status_code == 202, resp.text
    assert resp.json()["kind"] == "certificate"


async def test_67_the_cloud_lists_each_object_ok_gone_or_changed_and_502_when_down(w):
    env = await dof.make_do_env(name="cl", account_id=w.account_id)
    tags = [do_rules.BASE_TAG, do_rules.env_tag(env.env_id)]
    blue = w.fake.add_droplet(name="slipway-cl-blue", tags=tags, status="off")
    db_live = w.fake.add_database(name="someone-elses-db", tags=tags)
    await record(env, "droplet", str(blue["id"]), "slipway-cl-blue")
    await record(env, "droplet", "99999", "slipway-cl-green")
    await record(env, "database", str(db_live["id"]), do_rules.database_name("cl"))
    await record(env, "bucket", "cl-bucket", "cl-bucket")
    await record(env, "vpc", "pending:0123456789abcdef", do_rules.vpc_name("cl"))
    resp = await w.c["viewer"].get(f"{API}/{env.env_id}/cloud")
    assert resp.status_code == 200, resp.text
    out = resp.json()
    found = {(o["kind"], o["name"]): o for o in out["objects"]}
    assert found[("droplet", "slipway-cl-blue")]["status"] == "ok"
    assert found[("droplet", "slipway-cl-blue")]["power"] == "off"
    assert found[("droplet", "slipway-cl-blue")]["monthly_cents"] is None or isinstance(
        found[("droplet", "slipway-cl-blue")]["monthly_cents"], int)
    assert found[("droplet", "slipway-cl-green")]["status"] == "gone"
    assert found[("database", do_rules.database_name("cl"))]["status"] == "changed"
    assert found[("bucket", "cl-bucket")]["status"] == "ok"
    assert out["notes"] == ["slipway-cl-blue is powered off"]
    assert [p["kind"] for p in out["pending"]] == ["vpc"]
    assert out["account"]["name"] == "do-main" and out["region"] == "nyc3"
    secrets_absent(resp.text)
    w.fake.down = True
    resp = await w.admin.get(f"{API}/{env.env_id}/cloud")
    assert resp.status_code == 502
    secrets_absent(resp.text)


async def test_resolve_answers_502_when_digitalocean_cant_be_read(w, monkeypatch):
    from slipway.services import env_jobs

    env = await dof.make_do_env(name="rs", account_id=w.account_id)

    async def down(*args, **kw):
        raise digitalocean.Unreachable("DigitalOcean didn't answer")

    monkeypatch.setattr(env_jobs, "resolve", down)
    resp = await w.admin.post(f"{API}/{env.env_id}/traffic/resolve", json={"confirm": "rs"})
    assert (resp.status_code, resp.json()["detail"]) == (502, "DigitalOcean didn't answer")


async def test_decision_21_the_first_deploy_of_a_managed_environment_goes_to_blue(w):
    env = await dof.make_do_env(name="fd", account_id=w.account_id)
    resp = await w.admin.post(f"{API}/{env.env_id}/deploy", json={})
    assert resp.status_code == 202, resp.text
    assert resp.json()["instance_id"] == str(env.ids["blue"])
    resp = await w.admin.post(f"{API}/{env.env_id}/deploy", json={"target": "data"})
    assert (resp.status_code, resp.json()["detail"]) == (
        409, "fd's data is in its managed database: it has no data server to deploy")


# ----------------------------------------------------- test 68: the new kinds' retries


async def failed(env: dof.DoEnv, kind: str, *, slot: str | None = None, **options: Any) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=env.ids[slot] if slot else None, environment_id=env.env_id, kind=kind,
                         status="failed", branch="main", steps=[], options=options,
                         finished_at=datetime.now(UTC))
        db.add(dep)
        await db.commit()
        return dep.id


async def test_68_retries_of_the_new_kinds_ask_their_permissions_and_names(w, make_client):
    env = await dof.make_do_env(name="rt", account_id=w.account_id, status="live")
    retry = "/api/v1/deployments/{}/retry"
    cert = await failed(env, "certificate")
    assert (await w.c["viewer"].post(retry.format(cert), json={})).status_code == 403
    assert (await w.c["developer"].post(retry.format(cert), json={})).status_code not in (403, 422)
    dark = await failed(env, "deactivate")
    assert (await w.c["developer"].post(retry.format(dark), json={"confirm": "rt"})).status_code == 403
    resp = await w.admin.post(retry.format(dark), json={})
    assert (resp.status_code, resp.json()["detail"]) == (422, "Type the environment's name, rt, exactly to confirm")
    detail = (await w.admin.get(f"/api/v1/deployments/{dark}")).json()["actions"]["retry"]
    assert detail["needs_confirm"] is True and detail["also_needs"] == ["environments:delete"]
    for kind in ("vm_snapshot", "vm_drop"):
        dep = await failed(env, kind, slot="blue")
        assert (await w.c["developer"].post(retry.format(dep), json={})).status_code == 403  # no machines:write
        assert (await w.c["maintainer"].post(retry.format(dep), json={})).status_code not in (403, 422)
    revert = await failed(env, "vm_revert", slot="blue")
    machines = await client_with(make_client, "vm@example.com", ["deployments:create", "machines:write",
                                                                  "deployments:read"])
    assert (await machines.post(retry.format(revert), json={"confirm": "rt"})).status_code == 403  # data:reset
    resp = await w.c["maintainer"].post(retry.format(revert), json={})
    assert resp.status_code == 422
    assert (await w.c["maintainer"].post(retry.format(revert), json={"confirm": "rt"})).status_code not in (403, 422)
    detail = (await w.admin.get(f"/api/v1/deployments/{revert}")).json()["actions"]["retry"]
    assert detail["needs_confirm"] is True and "data:reset" in detail["also_needs"]
    # forget_vms and drop_data only where they mean something.
    resp = await w.admin.post(retry.format(cert), json={"forget_vms": True, "confirm": "rt"})
    assert resp.status_code == 422
    resp = await w.admin.post(retry.format(revert), json={"drop_data": True, "confirm": "rt"})
    assert resp.status_code == 422


async def test_a_production_teardown_retry_asks_the_phrase_again(w):
    env = await prod(w)
    await set_rows(Environment, env.env_id, retiring_at=datetime.now(UTC), status="deleting")
    dep = await failed(env, "teardown", confirmed=True, confirm_production="delete production prod")
    url = f"/api/v1/deployments/{dep}/retry"
    resp = await w.admin.post(url, json={"confirm": "prod"})
    assert (resp.status_code, resp.json()["detail"]) == (422, "Type delete production prod to confirm")
    detail = (await w.admin.get(f"/api/v1/deployments/{dep}")).json()["actions"]["retry"]
    assert detail["needs_phrases"] == ["confirm_production"] and detail["offers_forget_vms"] is True
    resp = await w.admin.post(url, json={"confirm": "prod", "confirm_production": "delete production prod"})
    assert resp.status_code == 202, resp.text
    async with get_sessionmaker()() as db:
        new = await db.get(Deployment, uuid.UUID(resp.json()["id"]))
        assert new.options["confirm_production"] == "delete production prod"


# ----------------------------------------------- test 52's API half: backups kept on Slipway


NAME = "20261116T090000Z-0a1b2c3d"


async def stored_backup(env: dof.DoEnv, tmp_path, name: str = NAME) -> uuid.UUID:
    """A ready backup of the owner, pulled into Slipway's storage as the data runner leaves one."""
    incoming = tmp_path / "runner"
    incoming.mkdir(parents=True, exist_ok=True)
    dump = incoming / f"{name}.dump"
    dump.write_bytes(b"PGDMP" + os.urandom(4096))
    import hashlib

    backup = Backup(instance_id=env.ids["data"], name=name, reason="manual", status="ready", format="pg-custom",
                    db_bytes=dump.stat().st_size, db_sha256=hashlib.sha256(dump.read_bytes()).hexdigest(),
                    has_files=False, identity_fp="x" * 64, taken_at=datetime(2026, 11, 16, 9, tzinfo=UTC),
                    location="slipway")
    stored = await backup_store.pull(ShellRemote("sh", dict(os.environ)), env.ids["data"], backup,
                                     sources={"dump": str(dump)})
    backup_store.apply(backup, stored)
    async with get_sessionmaker()() as db:
        db.add(backup)
        await db.commit()
        return backup.id


async def test_52_check_and_delete_of_a_backup_kept_on_slipway(w, tmp_path, storage):  # noqa: F811
    env = await dof.make_do_env(name="bk", account_id=w.account_id)
    ok = await stored_backup(env, tmp_path)
    gone = await stored_backup(env, tmp_path, "20261116T080000Z-0a1b2c3e")
    keyless = await stored_backup(env, tmp_path, "20261116T070000Z-0a1b2c3f")
    await set_rows(Backup, keyless, data_key="not base64!")  # its key can't be read any more
    owner = f"/api/v1/instances/{env.ids['data']}/backups"
    out = (await w.admin.get(owner)).json()
    assert {b["location"] for b in out["backups"]} == {"slipway"}
    for path in (storage / "backups" / env.ids["data"].hex).glob("20261116T080000Z-*"):
        path.unlink()
    resp = await w.admin.get(owner, params={"check": "true"})
    assert resp.status_code == 200, resp.text
    status = {b["id"]: b["status"] for b in resp.json()["backups"]}
    assert status == {str(ok): "ready", str(gone): "missing", str(keyless): "changed"}
    resp = await w.admin.delete(f"{owner}/{ok}")
    assert resp.status_code == 204, resp.text
    assert not list((storage / "backups").rglob(f"{NAME}*"))
    resp = await w.admin.delete(f"{owner}/{gone}")
    assert resp.status_code == 204
    resp = await w.admin.delete(f"{owner}/{keyless}")  # delete-only: its files go without the key
    assert resp.status_code == 204
    assert not list((storage / "backups").rglob("20261116T070000Z-*"))
    assert await count(Backup) == 0
    events = await audits("backup.delete")
    assert [e.details.get("forgotten", False) for e in events] == [False, True, False]
    assert {e.details["location"] for e in events} == {"slipway"}


async def test_68_account_writes_are_admin_only_and_reads_need_providers_read(w):
    accounts = "/api/v1/provider-accounts"
    body = {"provider": "digitalocean", "name": "do-two", "secret": fdo.TOKEN, "region": "nyc3",
            "ssh_sources": ["198.51.100.0/24"]}
    for role in ("viewer", "developer", "maintainer"):
        assert (await w.c[role].post(accounts, json=body)).status_code == 403, role
        assert (await w.c[role].request("DELETE", f"{accounts}/{w.account_id}",
                                        json={"confirm": "do-main"})).status_code == 403
        assert (await w.c[role].patch(f"{accounts}/{w.account_id}", json={"region": "sfo3"})).status_code == 403
    assert (await w.c["viewer"].get(accounts)).status_code == 403
    for role in ("developer", "maintainer", "admin"):
        assert (await w.c[role].get(accounts)).status_code == 200, role
    assert (await w.admin.post(accounts, json=body)).status_code not in (401, 403)
    # Grow and Add slot: the maintainer has providers:spend, the developer environments:write neither.
    env = await dof.make_do_env(name="mx", account_id=w.account_id, slots=("blue",))
    resp = await w.c["maintainer"].patch(f"{API}/{env.env_id}", json={"cloud": {"droplet_size": "s-1vcpu-2gb"}})
    w.locked[0] = False
    assert (resp.status_code, resp.json()["field"]) == (422, "confirm_cost")
    assert (await w.c["developer"].patch(f"{API}/{env.env_id}", json={"cloud": {}})).status_code == 403
    resp = await w.c["maintainer"].post(f"{API}/{env.env_id}/slots", json={})
    w.locked[0] = False
    assert (resp.status_code, resp.json()["field"]) == (422, "confirm_cost")
    for role in ("viewer", "developer", "maintainer"):
        assert (await w.c[role].get(f"{API}/{env.env_id}")).status_code == 200


async def test_a_deploy_retry_that_makes_a_gone_cluster_again_needs_data_reset_and_the_name(w, make_client):
    env = await dof.make_do_env(name="rb", account_id=w.account_id, slots=("blue",))
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=env.ids["blue"], environment_id=env.env_id, kind="deploy", status="failed",
                         branch="main", commit_sha=dof.SHA, steps=[], options={"slot": "blue", "go_live": True},
                         finished_at=datetime.now(UTC))
        db.add(dep)
        await db.commit()
    url = f"/api/v1/deployments/{dep.id}/retry"
    resp = await w.c["developer"].post(url, json={"rebuild_data": True, "confirm": "rb"})
    assert resp.status_code == 403  # data:reset
    resp = await w.admin.post(url, json={"rebuild_data": True})
    assert resp.status_code == 422
    resp = await w.admin.post(url, json={"rebuild_data": True, "confirm": "rb"})
    assert resp.status_code == 202, resp.text
    async with get_sessionmaker()() as db:
        new = await db.get(Deployment, uuid.UUID(resp.json()["id"]))
        assert new.options["rebuild_data"] is True
    [event] = [e for e in await audits("deployment.retry")]
    assert event.details["rebuild_data"] is True
