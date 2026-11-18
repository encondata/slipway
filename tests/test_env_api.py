"""The environments API (phase 3 §11, tests 53-59 of §16.2; test 52, the permissions matrix, is in
tests/test_permissions.py): typed names, the member instance endpoints, create, hostname uniqueness both ways,
the Cloudflare and Switchyard settings, the traffic dry run and DNS claim, and environment-level jobs as
deployments (their output, list filter and retry).

Jobs are queued and never run (``submitted``). Switchyard and Cloudflare are the fakes, GitHub a dict of files:
nothing here leaves the machine.
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
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
    FirstAdmin,
    Host,
    Instance,
    Resource,
    Snapshot,
)
from slipway.services import cloudflare, deployer, environments, switchyard, traffic
from tests import fake_switchyard
from tests.fake_cloudflare import TOKEN, ZONE, FakeCloudflare
from tests.test_data_api import clients, client_with, storage  # noqa: F401  (storage: autouse)
from tests.test_env_rules import (
    ADMIN,
    FILES,
    MAN,
    SECRETS,
    SHA,
    T0,
    _failed_green,
    _job,
    _reader,
    _world,
)

PROD = {"STACK_DOMAIN": "prod.example.com", "STACK_PROXY_IP": "10.0.0.2"}
API = "api.uat.example.com"
SPACES = "spaces.uat.example.com"
HOSTNAMES = [{"hostname": API, "service": "api", "container": 8000, "follows": "active", "health": "/healthz"},
             {"hostname": SPACES, "service": "spaces", "container": 8333, "follows": "server", "health": "/"}]


@pytest.fixture(autouse=True)
def submitted(monkeypatch) -> list[tuple[uuid.UUID, tuple]]:
    """Jobs are queued, never run."""
    found: list[tuple[uuid.UUID, tuple]] = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, keys: found.append((dep_id, keys)))
    return found


@pytest.fixture(autouse=True)
def sy(monkeypatch) -> fake_switchyard.FakeSwitchyard:
    """Every Switchyard client talks to a FakeSwitchyard (the seeded settings row names http://sy.lan)."""
    return fake_switchyard.install(monkeypatch)


@pytest.fixture(autouse=True)
def cf(monkeypatch) -> FakeCloudflare:
    fake = FakeCloudflare()
    fake.zone_id = fake.add_zone(ZONE)
    monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(fake.handle))
    return fake


@pytest.fixture(autouse=True)
def no_public_checks(monkeypatch):
    def refuse(verify: bool):
        def handle(request):
            raise AssertionError(f"unexpected request to {request.url}")
        return httpx.MockTransport(handle)
    monkeypatch.setattr(traffic, "transport_factory", refuse)


@pytest.fixture(autouse=True)
def github(monkeypatch) -> dict[str, str | None]:
    """GitHub, as the files of the repository at its branch."""
    files: dict[str, str | None] = dict(FILES)
    monkeypatch.setattr(environments, "github_reader", lambda user: _reader(files))
    return files


async def _update(model, row_id, **values) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(update(model).where(model.id == row_id).values(**values))
        await db.commit()


async def _fake_key() -> None:
    """The seeded Switchyard row with the key FakeSwitchyard accepts."""
    async with get_sessionmaker()() as db:
        await db.execute(update(AppSetting).where(AppSetting.key == switchyard.SETTING_KEY)
                         .values(secret=fake_switchyard.KEY))
        await db.commit()


async def _get(model, row_id):
    async with get_sessionmaker()() as db:
        return await db.get(model, row_id)


async def _count(model, *where) -> int:
    async with get_sessionmaker()() as db:
        return int(await db.scalar(select(func.count()).select_from(model).where(*where)) or 0)


async def _audits(action: str) -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        return list(await db.scalars(select(AuditEvent).where(AuditEvent.action == action)))


def _create_body(ids: dict[str, uuid.UUID], **kw: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "prod", "repository_id": str(ids["repo"]), "data_mode": "server",
        "hosts": {"blue": str(ids["host_blue"]), "green": str(ids["host_green"]), "data": str(ids["host_data"])},
        "settings": PROD, "traffic": {"switch": "switchyard", "dns": None}, "first_admin": ADMIN,
    }
    body.update(kw)
    return body


async def _backup(owner_id: uuid.UUID) -> uuid.UUID:
    from slipway.services import data

    bid = uuid.uuid4()
    identity = {k: SECRETS[k] for k in MAN.identity_keys()}
    async with get_sessionmaker()() as db:
        db.add(Backup(id=bid, instance_id=owner_id, name=data.backup_name(bid, T0), reason="manual", status="ready",
                      format="pg-custom", db_bytes=10, identity_keys=sorted(identity), identity=identity,
                      identity_fp=data.identity_fp(bid, identity, identity), taken_at=T0))
        await db.commit()
    return bid


# ------------------------------------------------------------------------- 53: typed names


async def test_typed_names_are_the_environments_and_come_first(make_client):
    c = await clients(make_client)
    ids = await _world()
    m, e = c["maintainer"], f"/api/v1/environments/{ids['env']}"

    # Remove a slot: the instance's own name doesn't do; a mismatch is 422 before the 404 of an unknown slot.
    r = await m.request("DELETE", f"{e}/slots/green", json={"confirm": "uat green"})
    assert r.status_code == 422 and r.json()["detail"] == "Type the environment's name, uat, exactly to confirm"
    assert (await m.request("DELETE", f"{e}/slots/purple", json={"confirm": "nope"})).status_code == 422
    assert (await m.request("DELETE", f"{e}/slots/purple", json={"confirm": "uat"})).status_code == 404
    r = await m.request("DELETE", f"{e}/slots/green", json={"confirm": "uat"})
    assert r.status_code == 202, r.text
    assert r.json()["kind"] == "remove_slot" and r.json()["instance_id"] is None and r.json()["slot"] == "green"
    removing = uuid.UUID(r.json()["id"])

    # Delete: 422 before the 409 of the remove_slot job still queued.
    r = await m.request("DELETE", e, json={"confirm": "UAT"})
    assert r.status_code == 422
    r = await m.request("DELETE", e, json={"confirm": "uat"})
    assert r.status_code == 409 and "A job is already running for uat (Remove slot on green)" in r.json()["detail"]
    await _update(Deployment, removing, status="cancelled")

    # Resolve: 422 before the 409 (nothing is split).
    r = await c["developer"].post(f"{e}/traffic/resolve", json={"confirm": "uat data"})
    assert r.status_code == 422
    r = await c["developer"].post(f"{e}/traffic/resolve", json={"confirm": "uat"})
    assert r.status_code == 409 and r.json()["detail"] == "Traffic of uat isn't split: there is nothing to resolve"

    # Phase 2's data endpoints on the data owner take the environment's name, not the instance's.
    bid = await _backup(ids["data"])
    d = f"/api/v1/instances/{ids['data']}"
    r = await m.post(f"{d}/data/restore", json={"backup_id": str(bid), "confirm": "uat data"})
    assert r.status_code == 422 and r.json()["detail"] == "Type the environment's name, uat, exactly to confirm"
    r = await m.post(f"{d}/data/restore", json={"backup_id": str(uuid.uuid4()), "confirm": "uat data"})
    assert r.status_code == 422  # before the 404 of an unknown backup
    r = await m.post(f"{d}/data/reset", json={"confirm": "uat data", "first_admin": ADMIN})
    assert r.status_code == 422
    r = await m.post(f"{d}/data/restore", json={"backup_id": str(bid), "confirm": "uat"})
    assert r.status_code == 202, r.text
    assert r.json()["kind"] == "restore" and r.json()["environment"]["name"] == "uat"
    assert r.json()["instance_id"] == str(ids["data"])


# ------------------------------------------------------------- 54: member instance endpoints


async def test_member_instance_endpoints(make_client, monkeypatch):
    c = await clients(make_client)
    ids = await _world()
    m = c["maintainer"]
    blue, green, dat = (f"/api/v1/instances/{ids[s]}" for s in ("blue", "green", "data"))
    locked = "uat green is the green slot of environment uat: change it on the environment"
    for body in ({"branch": "next"}, {"app_settings": {"STACK_DOMAIN": "x.example.com"}}, {"app_services": ["wiki"]},
                 {"env": {"A": "1"}}, {"routes": [{"hostname": "x.example.com", "container": 80}]},
                 {"keep_backups": 3}, {"seed_content": False}, {"seed_snapshot_id": None},
                 {"host_id": str(ids["host_blue"])}, {"build_source": "compose"}, {"deploy_dir": "/srv/x"},
                 {"clear_env": True}, {"name": "renamed", "branch": "next"}):
        r = await m.patch(green, json=body)
        assert r.status_code == 409 and r.json()["detail"] == locked, (body, r.text)
    r = await m.patch(green, json={"name": "uat green 2", "auto_ports": False})
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "uat green 2" and r.json()["slug"] == "uat-green" and r.json()["auto_ports"] is False
    assert r.json()["environment"] == {"id": str(ids["env"]), "name": "uat"} and r.json()["slot"] == "green"

    r = await m.post(f"{blue}/deploy")
    assert r.status_code == 409 and r.json()["detail"] == "Deploy uat from its page: Slipway picks the slot"
    r = await m.delete(green)
    assert r.status_code == 409 and r.json()["detail"] == "Remove the slot from uat instead"
    r = await m.delete(dat)
    assert r.status_code == 409 and r.json()["detail"] == "Delete uat instead"
    r = await m.post(f"{blue}/proxy/sync")
    assert r.status_code == 409 and r.json()["detail"] == "uat's names are published by the environment"

    # Data endpoints on an app slot: its data is the environment's, on the data server.
    shared = ("uat's data is shared by its slots and lives on h-data: back it up, restore or reset it from the "
              "environment page")
    bid = await _backup(ids["data"])
    for method, url, body in (
        ("get", f"{blue}/backups", None), ("post", f"{blue}/backups", {}),
        ("post", f"{blue}/data/restore", {"backup_id": str(bid), "confirm": "uat"}),
        ("post", f"{blue}/data/reset", {"confirm": "uat", "first_admin": ADMIN}),
        ("post", f"{blue}/data/start-over", {"confirm": "uat"}), ("post", f"{blue}/snapshots", {"name": "s-1"}),
        ("delete", f"{blue}/backups/{bid}", None), ("get", f"{blue}/first-admin", None),
        ("put", f"{blue}/first-admin", ADMIN),
    ):
        kw = {"json": body} if body is not None else {}
        r = await getattr(m, method)(url, **kw)
        assert r.status_code == 409 and r.json()["detail"] == shared, (method, url, r.text)
    # Create it now and Add starter content asked on an app slot are the data owner's jobs (§7.3).
    r = await m.post(f"{blue}/first-admin/run")
    assert r.status_code == 409 and r.json()["detail"] == "No first admin is waiting to be created in uat data"
    r = await m.post(f"{blue}/content/run")
    assert r.status_code == 409 and r.json()["detail"] == "uat data has no starter content waiting to be added"
    # ...and on the data owner they run (Back up now queues a job on it).
    r = await m.post(f"{dat}/backups", json={})
    assert r.status_code == 202, r.text
    assert r.json()["instance_id"] == str(ids["data"]) and r.json()["environment"]["name"] == "uat"
    await _update(Deployment, uuid.UUID(r.json()["id"]), status="cancelled")

    # Control stays allowed; a stale slot refuses start, and a start counts for the data owner.
    ran: list[str] = []

    async def fake_run(instance, command, **kw):
        ran.append(instance.slug)
        return "ok"

    monkeypatch.setattr(deployer, "run_on_instance", fake_run)
    r = await c["developer"].post(f"{green}/actions/stop")
    assert r.status_code == 200, r.text
    await _update(Instance, ids["green"], slot_state={"stale": {"reason": "Stopped when uat's data was restored",
                                                                 "at": T0.isoformat()}})
    r = await c["developer"].post(f"{green}/actions/start")
    assert r.status_code == 409
    assert r.json()["detail"] == "Deploy to green first: it was stopped when the data was restored"
    r = await c["developer"].post(f"{blue}/actions/restart")
    assert r.status_code == 200, r.text
    assert ran == ["uat-green", "uat-blue"]
    assert (await _get(Instance, ids["data"])).last_control_at is not None
    assert (await _get(Instance, ids["blue"])).last_control_at is None
    # Under the data owner's hold, a start of any app slot is refused with the hold text.
    await _update(Instance, ids["data"], data_dirty={"hold": True, "last": {"kind": "restore"}})
    r = await c["developer"].post(f"{blue}/actions/start")
    assert r.status_code == 409 and r.json()["detail"].startswith("uat's last restore stopped part-way")
    await _update(Instance, ids["data"], data_dirty=None)
    # A control action waits for no job: one of the environment's jobs running answers 409.
    async with get_sessionmaker()() as db:
        db.add(_job(ids["data"], ids["env"], "backup", "running"))
        await db.commit()
    r = await c["developer"].post(f"{blue}/actions/stop")
    assert r.status_code == 409 and r.json()["detail"].startswith("A job is already running for uat (")


async def test_reserved_slugs_on_create_and_claim(make_client):
    c = await clients(make_client)
    ids = await _world(slots=("blue", "data"), live=("blue", "data"))
    m = c["maintainer"]
    r = await m.post("/api/v1/instances", json={"name": "uat-green", "repository_id": str(ids["repo"]),
                                                "host_id": str(ids["host_blue"]), "deploy": False})
    assert r.status_code == 409 and r.json()["detail"] == "uat-green is reserved for environment uat's green slot"
    r = await m.post(f"/api/v1/hosts/{ids['host_blue']}/claim",
                     json={"name": "uat-green", "repository_id": str(ids["repo"]), "deploy": False,
                           "group": {"kind": "compose", "project": "shop"}})
    assert r.status_code == 409 and r.json()["detail"] == "uat-green is reserved for environment uat's green slot"
    # Another name is free; a deleted environment's slugs are free again.
    r = await m.post("/api/v1/instances", json={"name": "uat-blue-2", "repository_id": str(ids["repo"]),
                                                "host_id": str(ids["host_blue"]), "deploy": False})
    assert r.status_code == 201, r.text


# ---------------------------------------------------------------------------- 55: create


async def test_create_writes_the_environment_its_slots_and_no_secret_in_the_audit(make_client):
    c = await clients(make_client)
    ids = await _world()
    m = c["maintainer"]
    before = (await _count(Environment), await _count(Instance), await _count(Deployment))

    # Refusals answer {detail, field} so the flow page can jump to the step.
    r = await m.post("/api/v1/environments", json=_create_body(ids, name="a" * 27))
    assert r.status_code == 422 and r.json() == {"detail": environments.NAME_RULE, "field": "name"}
    r = await m.post("/api/v1/environments", json=_create_body(ids, name="uat"))
    assert r.status_code == 409 and r.json() == {"detail": "An environment named uat already exists", "field": "name"}
    r = await m.post("/api/v1/environments", json=_create_body(ids, hosts={"blue": str(ids["host_blue"]),
                                                                            "green": str(ids["host_green"]),
                                                                            "data": str(ids["host_blue"])}))
    assert r.status_code == 409 and r.json()["field"] == "hosts.data"
    r = await m.post("/api/v1/environments", json=_create_body(ids, first_admin=None))
    assert r.status_code == 422 and r.json() == {"detail": "Enter the first admin", "field": "first_admin"}

    # The check writes nothing and answers the plan, with the warning for two slots on one host.
    r = await m.post("/api/v1/environments?check=true", json=_create_body(
        ids, hosts={"blue": str(ids["host_blue"]), "green": str(ids["host_blue"]), "data": str(ids["host_data"])}))
    assert r.status_code == 200, r.text
    plan = r.json()
    assert plan["ok"] is True and plan["warnings"] and "h-blue" in plan["warnings"][0]
    assert plan["plan"]["slots"]["green"]["slug"] == "prod-green"
    assert sorted(plan["plan"]["secrets"]) == sorted(s.key for s in MAN.secrets)
    assert (await _count(Environment), await _count(Instance), await _count(Deployment)) == before

    r = await m.post("/api/v1/environments", json=_create_body(ids, keep_backups=7, seed_content=False))
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["name"] == "prod" and out["status"] == "new" and out["data_mode"] == "server"
    assert out["warnings"] == [] and out["active_slot"] is None
    assert [s["slot"] for s in out["slots"]] == ["blue", "green", "data"]
    assert {s["slot"]: s["host"]["name"] for s in out["slots"]} == {"blue": "h-blue", "green": "h-green",
                                                                    "data": "h-data"}
    assert sorted(out["secrets"]) == sorted(s.key for s in MAN.secrets)
    assert out["data"]["keep_backups"] == 7 and out["data"]["seed_content"] is False
    assert out["data"]["first_admin"]["fields"] == ADMIN["fields"] and out["data"]["first_admin"]["has_password"]
    assert out["actions"]["deploy"]["slot"] == "data" and out["actions"]["deploy"]["available"], out["actions"]
    assert ADMIN["password"] not in json.dumps(out)
    assert {h["hostname"] for h in out["hostnames"]} >= {"api.prod.example.com", "spaces.prod.example.com"}
    env_id = uuid.UUID(out["id"])
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        assert set(env.app_secrets) == {s.key for s in MAN.secrets} and env.secrets_version == 0
        rows = {i.slot: i for i in await db.scalars(select(Instance).where(Instance.environment_id == env_id))}
        assert {s: (i.slug, i.status, i.app_secrets) for s, i in rows.items()} == {
            "blue": ("prod-blue", "created", None), "green": ("prod-green", "created", None),
            "data": ("prod-data", "created", None)}
        owner = rows["data"]
        assert (owner.keep_backups, owner.seed_content) == (7, False)
        admin = await db.scalar(select(FirstAdmin).where(FirstAdmin.instance_id == owner.id))
        assert admin is not None and admin.status == "pending"
        assert await db.scalar(select(func.count()).select_from(FirstAdmin).where(
            FirstAdmin.instance_id.in_([rows["blue"].id, rows["green"].id]))) == 0
        secrets = dict(env.app_secrets)
    created = await _audits("environment.create")
    assert len(created) == 1
    text = json.dumps({"summary": created[0].summary, "details": created[0].details})
    assert all(value not in text for value in secrets.values())
    assert ADMIN["password"] not in text
    assert created[0].details["secrets"] == sorted(secrets) and created[0].details["first_admin"] == "ada@example.com"
    # No job was queued: Deploy starts the data server, then the chain.
    assert await _count(Deployment) == before[2]
    r = await m.post(f"/api/v1/environments/{env_id}/deploy")
    assert r.status_code == 202, r.text
    assert r.json()["slot"] == "data" and r.json()["options"]["chain"] is True


# ------------------------------------------------------------- 56: hostnames both ways


async def test_hostnames_are_unique_between_instances_and_environments(make_client):
    c = await clients(make_client)
    ids = await _world()
    await _update(Environment, ids["env"], hostnames=HOSTNAMES)
    m = c["maintainer"]
    r = await m.post("/api/v1/instances", json={"name": "shop", "repository_id": str(ids["repo"]),
                                                "host_id": str(ids["host_blue"]), "deploy": False,
                                                "routes": [{"hostname": API, "container": 80}]})
    assert r.status_code == 409 and r.json()["detail"] == f"{API} is a hostname of environment uat"
    r = await m.post("/api/v1/instances", json={"name": "shop", "repository_id": str(ids["repo"]),
                                                "host_id": str(ids["host_blue"]), "deploy": False})
    assert r.status_code == 201, r.text
    shop = r.json()["id"]
    r = await m.patch(f"/api/v1/instances/{shop}", json={"routes": [{"hostname": SPACES, "container": 80}]})
    assert r.status_code == 409 and r.json()["detail"] == f"{SPACES} is a hostname of environment uat"

    # The other way: a name the standalone instance's last deploy published.
    await _update(Instance, uuid.UUID(shop), app_state={"routes": [{"hostname": "api.prod.example.com"}]})
    r = await m.post("/api/v1/environments?check=true", json=_create_body(ids))
    assert r.status_code == 409
    assert r.json() == {"detail": "api.prod.example.com is already a hostname of instance shop", "field": "hostnames"}
    # A deleted environment's names are free again.
    await _update(Instance, uuid.UUID(shop), app_state=None)
    await _update(Environment, ids["env"], status="deleted", deleted_at=T0)
    r = await m.post("/api/v1/instances", json={"name": "shop2", "repository_id": str(ids["repo"]),
                                                "host_id": str(ids["host_blue"]), "deploy": False,
                                                "routes": [{"hostname": API, "container": 80}]})
    assert r.status_code == 201, r.text


# ---------------------------------------------------------------- 57: integration settings


async def test_cloudflare_settings_and_the_switchyard_traffic_address(make_client, cf):
    c = await clients(make_client)
    a = c["admin"]
    r = await a.get("/api/v1/settings/cloudflare")
    assert r.status_code == 200 and r.json()["configured"] is False
    assert (await c["maintainer"].get("/api/v1/settings/cloudflare")).status_code == 403
    r = await a.put("/api/v1/settings/cloudflare", json={"zone": ZONE, "public_ip": "203.0.113.7"})
    assert r.status_code == 422 and r.json()["detail"] == "Enter the Cloudflare API token"
    r = await a.put("/api/v1/settings/cloudflare", json={"zone": "other.org", "token": TOKEN})
    assert r.status_code == 422 and "No active zone other.org" in r.json()["detail"]
    r = await a.put("/api/v1/settings/cloudflare", json={"zone": ZONE, "public_ip": "2001:db8::1", "token": TOKEN})
    assert r.status_code == 422 and "IPv4" in r.json()["detail"]
    assert cf.writes() == []

    r = await a.put("/api/v1/settings/cloudflare", json={"zone": "Example.COM.", "public_ip": "203.0.113.7",
                                                         "proxied": True, "token": TOKEN})
    assert r.status_code == 200, r.text
    assert r.json() == {"configured": True, "zone": ZONE, "zone_id": cf.zone_id, "public_ip": "203.0.113.7",
                        "proxied": True, "has_token": True, "token_hint": TOKEN[-4:]}
    # Write-only: an empty token keeps the stored one.
    r = await a.put("/api/v1/settings/cloudflare", json={"zone": ZONE, "public_ip": "203.0.113.8"})
    assert r.status_code == 200 and r.json()["has_token"] and r.json()["public_ip"] == "203.0.113.8"
    async with get_sessionmaker()() as db:
        row = await db.scalar(select(AppSetting).where(AppSetting.key == cloudflare.SETTING_KEY))
        assert row.secret == TOKEN
    events = await _audits("settings.cloudflare")
    assert len(events) == 2 and all(TOKEN not in json.dumps([e.summary, e.details]) for e in events)
    assert events[0].details["token_replaced"] is True or events[1].details["token_replaced"] is True

    r = await a.post("/api/v1/settings/cloudflare/test")
    assert r.status_code == 200
    assert r.json()["message"] == ("Connected: zone example.com; the token is active and can read its records. "
                                   "Slipway can't check that it may edit them without changing one.")
    cf.deny = True
    r = await a.post("/api/v1/settings/cloudflare/test")
    assert r.status_code == 502 and TOKEN not in r.text
    cf.deny = False

    # Removal is refused while an environment publishes DNS through it.
    ids = await _world()
    await _update(Environment, ids["env"], traffic={"switch": "switchyard",
                                                    "dns": {"provider": "cloudflare", "address": None, "proxied": False}})
    r = await a.put("/api/v1/settings/cloudflare", json={"clear": True})
    assert r.status_code == 409
    assert r.json()["detail"] == "Environments uat publish DNS records through Cloudflare; turn that off on them first"
    await _update(Environment, ids["env"], traffic={"switch": "switchyard", "dns": None})
    r = await a.put("/api/v1/settings/cloudflare", json={"clear": True})
    assert r.status_code == 200 and r.json()["configured"] is False

    # Switchyard's traffic address is saved, kept by a save that doesn't send it, and checked.
    sy_in = {"url": "https://sy.example.test", "api_key": fake_switchyard.KEY}
    r = await a.put("/api/v1/settings/switchyard", json={**sy_in, "traffic_address": "10.0.0.2:8443"})
    assert r.status_code == 200 and r.json()["traffic_address"] == "10.0.0.2:8443"
    r = await a.put("/api/v1/settings/switchyard", json={"url": "https://sy.example.test"})
    assert r.status_code == 200 and r.json()["traffic_address"] == "10.0.0.2:8443"
    async with get_sessionmaker()() as db:
        assert (await switchyard.load_config(db)).traffic_address == "10.0.0.2:8443"
    r = await a.put("/api/v1/settings/switchyard", json={"url": "https://sy.example.test", "traffic_address": "a b"})
    assert r.status_code == 422
    r = await a.put("/api/v1/settings/switchyard", json={"url": "https://sy.example.test", "traffic_address": ""})
    assert r.status_code == 200 and r.json()["traffic_address"] == ""


# -------------------------------------------------------------- 58: the dry run, DNS, claim


async def test_traffic_plan_only_reads_and_answers_502_when_switchyard_is_down(make_client, sy, cf, monkeypatch):
    from tests.fake_hosts import configure_cloudflare

    c = await clients(make_client)
    ids = await _world()
    await _fake_key()
    await configure_cloudflare()
    await _update(Environment, ids["env"], hostnames=HOSTNAMES,
                  traffic={"switch": "switchyard", "dns": {"provider": "cloudflare", "address": None,
                                                           "proxied": False}})
    v, e = c["viewer"], f"/api/v1/environments/{ids['env']}"
    r = await v.get(f"{e}/traffic/plan")
    assert r.status_code == 200, r.text
    plan = r.json()
    assert set(plan) == {"switch", "dns", "routes"}
    assert {x["hostname"] for x in plan["routes"]} == {API, SPACES}
    assert plan["switch"]["backend"] == "switchyard" and plan["dns"]["backend"] == "cloudflare"
    assert {x["hostname"]: x["status"] for x in plan["dns"]["changes"]} == {API: "create", SPACES: "create"}
    r = await v.get(f"{e}/traffic/plan?slot=green")
    assert r.status_code == 200 and {x["follows"] for x in r.json()["routes"]} == {"active", "server"}
    assert (await v.get(f"{e}/traffic/plan?slot=data")).status_code == 422
    assert sy.api_calls() and all(call.method == "GET" for call in sy.api_calls())
    assert cf.writes() == []
    assert await _count(Resource) == 0

    # DNS records as Cloudflare has them, and Claim of one Slipway didn't make.
    cf.add_record(cf.zone_id, "A", API, "198.51.100.9")
    r = await v.get(f"{e}/dns")
    assert r.status_code == 200
    by_name = {x["hostname"]: x for x in r.json()["records"]}
    assert r.json()["zone"] == ZONE and by_name[API]["status"] == "claimable" and by_name[API]["origin"] is None
    assert by_name[SPACES]["status"] == "create"
    assert (await v.post(f"{e}/dns/claim", json={"hostname": API})).status_code == 403
    r = await c["developer"].post(f"{e}/dns/claim", json={"hostname": SPACES})
    assert r.status_code == 409 and "can't be claimed (create)" in r.json()["detail"]
    r = await c["developer"].post(f"{e}/dns/claim", json={"hostname": API})
    assert r.status_code == 200, r.text
    async with get_sessionmaker()() as db:
        row = await db.scalar(select(Resource).where(Resource.name == API))
        assert (row.origin, row.provider, row.kind, row.provider_id) == ("claimed", "cloudflare", "dns_record",
                                                                       r.json()["record_id"])
    assert len(await _audits("resource.claim")) == 1
    r = await v.get(f"{e}/dns")
    assert {x["hostname"]: (x["status"], x["origin"]) for x in r.json()["records"]}[API] == ("update", "claimed")
    r = await c["developer"].post(f"{e}/dns/claim", json={"hostname": API})
    assert r.status_code == 409
    assert cf.writes() == []

    # Switchyard down: 502 with the client's text, and nothing written.
    def down(request):
        raise httpx.ConnectError("connection refused", request=request)

    monkeypatch.setattr(switchyard, "transport_factory", lambda: httpx.MockTransport(down))
    r = await v.get(f"{e}/traffic/plan")
    assert r.status_code == 502 and r.json()["detail"]
    r = await c["developer"].post(f"{e}/activate", json={"slot": "green"})
    assert r.status_code == 502 and "Switchyard" in r.json()["detail"]
    assert await _count(Deployment, Deployment.kind == "activate") == 0


async def test_activate_answers_the_plans_blockers_before_queueing(make_client, sy):
    c = await clients(make_client)
    ids = await _world()
    await _fake_key()
    await _update(Environment, ids["env"], hostnames=HOSTNAMES)
    e = f"/api/v1/environments/{ids['env']}"
    r = await c["developer"].post(f"{e}/activate", json={"slot": "blue"})
    assert r.status_code == 409 and r.json()["detail"] == "blue already takes the traffic"
    # Green's ports aren't published, so the plan has blockers: nothing is queued.
    r = await c["developer"].post(f"{e}/activate", json={"slot": "green"})
    assert r.status_code == 409 and r.json()["detail"].endswith("; Slipway changed nothing"), r.text
    assert await _count(Deployment, Deployment.kind == "activate") == 0
    for slot, iid in (("blue", ids["blue"]), ("green", ids["green"]), ("data", ids["data"])):
        port = 8000 if slot != "data" else 8333
        service = "api" if slot != "data" else "spaces"
        await _update(Instance, iid, published_ports=[{"service": service, "container": port, "host": 18000,
                                                        "protocol": "tcp"}])
    r = await c["developer"].post(f"{e}/activate", json={"slot": "green"})
    assert r.status_code == 202, r.text
    assert r.json()["kind"] == "activate" and r.json()["slot"] == "green" and r.json()["options"]["from_slot"] == "blue"
    assert all(call.method == "GET" for call in sy.api_calls())
    # Switch back is the activate of the slot that was active before.
    await _update(Deployment, uuid.UUID(r.json()["id"]), status="succeeded")
    await _update(Environment, ids["env"], active_slot_id=ids["green"],
                  traffic_state={"last": {"from_slot": "blue", "to_slot": "green", "back": False,
                                          "at": T0.isoformat()}})
    r = await c["developer"].post(f"{e}/activate", json={"slot": "blue"})
    assert r.status_code == 202, r.text
    assert r.json()["options"]["back"] is True


# --------------------------------------------------------- 59: environment jobs as deployments


async def test_environment_jobs_as_deployments_and_their_retry(make_client):
    c = await clients(make_client)
    ids = await _world()
    env_id = ids["env"]
    switch = {"backend": "switchyard", "from_slot": "blue", "to_slot": "green", "applied": True, "apply_n": 7,
              "before": {API: {"forward_host": "10.0.0.11"}}, "created": [], "deleted": [],
              "changed": [{"hostname": API, "id": "3"}]}
    async with get_sessionmaker()() as db:
        activate = _job(None, env_id, "activate", "failed", at=T0 + timedelta(hours=1),
                        options={"slot": "green", "from_slot": "blue", "switch": switch},
                        steps=[{"key": "check", "status": "succeeded"}, {"key": "switch", "status": "failed"}])
        publish = _job(None, env_id, "publish", "failed", at=T0 + timedelta(hours=2), options={})
        remove = _job(None, env_id, "remove_slot", "failed", at=T0 + timedelta(hours=3), options={"slot": "green"})
        teardown = _job(None, env_id, "teardown", "failed", at=T0 + timedelta(hours=4), options={"confirmed": True},
                        steps=[{"key": "check", "status": "succeeded"}, {"key": "unroute", "status": "failed"}])
        discard = _job(None, env_id, "discard", "failed", at=T0 + timedelta(minutes=90), options={"slot": "green"})
        db.add_all([activate, publish, remove, teardown, discard])
        await db.commit()
    v = c["viewer"]
    r = await v.get(f"/api/v1/deployments/{activate.id}")
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["instance_id"] is None and out["instance_name"] is None
    assert out["environment"] == {"id": str(env_id), "name": "uat"} and out["slot"] == "green"
    assert out["options"]["switch"] == {"backend": "switchyard", "from_slot": "blue", "to_slot": "green",
                                        "created": [], "changed": [API], "deleted": [], "applied": True}
    assert out["actions"]["retry"]["available"] and out["actions"]["retry"]["permission"] == "traffic:switch"
    assert out["actions"]["rollback"]["available"] is False
    r = await v.get(f"/api/v1/deployments/{teardown.id}")
    assert r.json()["actions"]["retry"]["needs_confirm"] and r.json()["actions"]["retry"]["offers_forget_traffic"]

    listed = (await v.get(f"/api/v1/deployments?environment={env_id}")).json()
    assert {d["id"] for d in listed} >= {str(d.id) for d in (activate, publish, remove, teardown)}
    assert all(d["environment"]["id"] == str(env_id) for d in listed)
    ours = (await v.get(f"/api/v1/environments/{env_id}/deployments")).json()
    assert {d["id"] for d in ours} == {d["id"] for d in listed}
    assert (await v.get(f"/api/v1/deployments?environment={uuid.uuid4()}")).json() == []

    # Retry of each kind with its permission.
    only_switch = await client_with(make_client, "switcher@example.com",
                                    ["environments:read", "deployments:create", "traffic:switch"])
    only_create = await client_with(make_client, "creator@example.com", ["environments:read", "deployments:create"])
    assert (await only_create.post(f"/api/v1/deployments/{activate.id}/retry")).status_code == 403
    r = await only_switch.post(f"/api/v1/deployments/{activate.id}/retry")
    assert r.status_code == 202, r.text
    assert r.json()["retry_of_id"] == str(activate.id) and r.json()["options"]["slot"] == "green"
    assert r.json()["options"].get("switch") is None  # the first attempt's switch record isn't carried over
    await _update(Deployment, uuid.UUID(r.json()["id"]), status="cancelled")
    # Discard needs both deployments:create and traffic:switch; nothing is left to discard here.
    assert (await only_create.post(f"/api/v1/deployments/{discard.id}/retry")).status_code == 403
    r = await only_switch.post(f"/api/v1/deployments/{discard.id}/retry")
    assert r.status_code == 409 and r.json()["detail"] == "green has no failed deploy to discard"
    r = await only_switch.post(f"/api/v1/deployments/{publish.id}/retry")
    assert r.status_code == 202, r.text
    await _update(Deployment, uuid.UUID(r.json()["id"]), status="cancelled")
    assert (await c["developer"].post(f"/api/v1/deployments/{remove.id}/retry",
                                      json={"confirm": "uat"})).status_code == 403
    r = await c["maintainer"].post(f"/api/v1/deployments/{remove.id}/retry", json={"confirm": "uat green"})
    assert r.status_code == 422
    r = await c["maintainer"].post(f"/api/v1/deployments/{remove.id}/retry", json={"confirm": "uat"})
    assert r.status_code == 202, r.text
    await _update(Deployment, uuid.UUID(r.json()["id"]), status="cancelled")
    r = await c["maintainer"].post(f"/api/v1/deployments/{publish.id}/retry", json={"forget_traffic": True})
    assert r.status_code == 422
    r = await c["maintainer"].post(f"/api/v1/deployments/{teardown.id}/retry",
                                   json={"confirm": "uat", "forget_traffic": True})
    assert r.status_code == 202, r.text
    assert r.json()["kind"] == "teardown" and r.json()["options"]["forget_traffic"] is True
    assert (await _get(Environment, env_id)).status == "deleting"
    assert len(await _audits("deployment.retry")) == 4

    # A retry after traffic moved is refused (§9.5).
    await _update(Deployment, uuid.UUID(r.json()["id"]), status="cancelled")
    await _update(Environment, env_id, status="live", active_slot_id=ids["green"])
    r = await only_switch.post(f"/api/v1/deployments/{activate.id}/retry")
    assert r.status_code == 409 and r.json()["detail"] == "Traffic moved since: activate again instead"
    assert (await c["maintainer"].post(f"/api/v1/deployments/{activate.id}/rollback",
                                       json={"confirm": "uat"})).status_code == 409


# ------------------------------------------------------------------ the other routes of §11


async def test_deploy_picks_the_slot_and_the_data_server_first(make_client):
    c = await clients(make_client)
    ids = await _world(live=(), active=None, status="new")
    d, e = c["developer"], f"/api/v1/environments/{ids['env']}"
    # A new environment with a data server starts with it; the chain then deploys blue.
    r = await d.post(f"{e}/deploy")
    assert r.status_code == 202, r.text
    first = r.json()
    assert (first["slot"], first["instance_id"], first["options"]["chain"]) == ("data", str(ids["data"]), True)
    assert [s["key"] for s in first["steps"]][:2] == ["resolve", "source"]
    r = await d.post(f"{e}/deploy")
    assert r.status_code == 409 and r.json()["detail"].startswith("A job is already running for uat (")
    await _update(Deployment, uuid.UUID(first["id"]), status="cancelled")
    # Asking for blue before the data server is live: its refusal.
    r = await d.post(f"{e}/deploy", json={"slot": "blue"})
    assert r.status_code == 409 and r.json()["detail"] == (
        "Deploy uat's data server first: the app slots need its address and ports")


async def test_deploy_to_the_idle_slot_and_the_lag_checkbox(make_client):
    c = await clients(make_client)
    ids = await _world()
    d, e = c["developer"], f"/api/v1/environments/{ids['env']}"
    r = await d.post(f"{e}/deploy", json={"slot": "blue"})
    assert r.status_code == 409 and r.json()["detail"] == "blue serves traffic: deploy to green, then activate it"
    r = await d.post(f"{e}/deploy", json={"acknowledge_schema": True})
    assert r.status_code == 202, r.text
    out = r.json()
    assert out["slot"] == "green" and out["options"]["go_live"] is False and out["options"]["behind_ok"] is True
    assert "proxy" not in [s["key"] for s in out["steps"]] and "traffic" in [s["key"] for s in out["steps"]]
    events = await _audits("deployment.create")
    assert events[-1].details["environment"] == "uat" and events[-1].details["slot"] == "green"
    await _update(Deployment, uuid.UUID(out["id"]), status="cancelled")
    r = await d.post(f"{e}/deploy", json={"target": "data"})
    assert r.status_code == 202 and r.json()["slot"] == "data" and "chain" not in r.json()["options"]


async def test_get_patch_and_env(make_client, github):
    c = await clients(make_client)
    ids = await _world(env={"EXTRA": "1"})
    m, e = c["maintainer"], f"/api/v1/environments/{ids['env']}"
    r = await c["viewer"].get(e)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["active_slot"] == "blue" and out["env_keys"] == ["EXTRA"]
    assert {s["slot"]: (s["role"], s["active"]) for s in out["slots"]} == {
        "blue": ("app", True), "green": ("app", False), "data": ("data", False)}
    assert out["slots"][0]["live"]["sha"] == SHA and out["slots"][0]["live"]["settings_differ"] is False
    assert {p["service"] for p in out["slots"][2]["ports"]} == {"spaces", "db"}
    assert out["data_owner_id"] == str(ids["data"]) and "restore" in out["data"]["capabilities"]
    assert set(out["actions"]) >= {"deploy", "discard", "rollback", "update_data_server", "activate", "switch_back",
                                   "publish", "continue", "add_slot", "delete"}
    assert all(v not in json.dumps(out) for v in SECRETS.values())
    assert (await c["viewer"].get(f"{e}/env")).status_code == 403
    assert (await m.get(f"{e}/env")).json() == {"env": {"EXTRA": "1"}}
    listed = (await c["viewer"].get("/api/v1/environments")).json()
    assert [x["name"] for x in listed] == ["uat"] and listed[0]["active_slot"] == "blue"

    r = await m.patch(e, json={"settings": {"STACK_DOMAIN": "uat2.example.com", "STACK_PROXY_IP": "10.0.0.2"},
                               "env": {"EXTRA": "2", "MORE": "x"}, "keep_backups": 9, "auto_activate": True})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["settings"]["STACK_DOMAIN"] == "uat2.example.com" and out["data"]["keep_backups"] == 9
    assert out["auto_activate"] is True and "api.uat2.example.com" in {h["hostname"] for h in out["hostnames"]}
    assert out["slots"][0]["live"]["settings_differ"] is True
    update_audit = (await _audits("environment.update"))[-1]
    assert "2" not in json.dumps(update_audit.details) and "variables (EXTRA, MORE)" in update_audit.summary
    r = await m.patch(e, json={"route_tls": {"nope.example.com": "internal"}})
    assert r.status_code == 422 and r.json()["field"] == "route_tls"
    r = await m.patch(e, json={"keep_backups": 0})
    assert r.status_code == 422 and r.json() == {"detail": "Keep 1 to 100 backups", "field": "keep_backups"}
    r = await m.patch(e, json={"traffic": {"switch": "none"}})
    assert r.status_code == 409 and r.json()["field"] == "traffic"
    r = await m.patch(e, json={"traffic": {"switch": "switchyard", "dns": {}}})
    assert r.status_code == 409 and r.json() == {"detail": environments.SET_UP_CLOUDFLARE, "field": "traffic.dns"}
    github["slipway.yml"] = None
    r = await m.patch(e, json={"settings": {"STACK_DOMAIN": "x.example.com"}})
    assert r.status_code == 409 and r.json()["field"] == "manifest_file"
    # While a job of the environment runs, nothing changes.
    async with get_sessionmaker()() as db:
        db.add(_job(ids["green"], ids["env"], "deploy", "running"))
        await db.commit()
    r = await m.patch(e, json={"keep_backups": 3})
    assert r.status_code == 409 and "A job is already running for uat" in r.json()["detail"]
    # A deleted environment is still shown, and no longer changed.
    await _update(Environment, ids["env"], status="deleted", deleted_at=T0)
    assert (await c["viewer"].get(e)).status_code == 200
    assert (await m.patch(e, json={"keep_backups": 3})).status_code == 404
    assert (await c["viewer"].get("/api/v1/environments")).json() == []
    assert len((await c["viewer"].get("/api/v1/environments?include_deleted=true")).json()) == 1


async def test_publish_discard_and_the_chain_notice(make_client):
    c = await clients(make_client)
    ids = await _world()
    d, e = c["developer"], f"/api/v1/environments/{ids['env']}"
    r = await d.post(f"{e}/publish")
    assert r.status_code == 202, r.text
    assert r.json()["kind"] == "publish" and [s["key"] for s in r.json()["steps"]] == ["check", "traffic"]
    await _update(Deployment, uuid.UUID(r.json()["id"]), status="succeeded")
    r = await d.post(f"{e}/discard", json={"slot": "green"})
    assert r.status_code == 409 and r.json()["detail"] == "green has no failed deploy to discard"
    async with get_sessionmaker()() as db:
        failed = await _failed_green(db, ids)
    r = await d.post(f"{e}/discard", json={"slot": "green"})
    assert r.status_code == 202, r.text
    assert [s["key"] for s in r.json()["steps"]] == ["check", "stop_slot", "smoke", "settle"]
    assert (await c["viewer"].post(f"{e}/discard", json={"slot": "green"})).status_code == 403
    await _update(Deployment, uuid.UUID(r.json()["id"]), status="cancelled")
    # Roll back on shared data needs data:reset as well, and runs on the data owner.
    r = await d.post(f"/api/v1/deployments/{failed.id}/rollback", json={"confirm": "uat"})
    assert r.status_code == 403 and "data:reset" in r.json()["detail"]
    r = await c["maintainer"].post(f"/api/v1/deployments/{failed.id}/rollback", json={"confirm": "uat green"})
    assert r.status_code == 422
    r = await c["maintainer"].post(f"/api/v1/deployments/{failed.id}/rollback", json={"confirm": "uat"})
    assert r.status_code == 202, r.text
    assert r.json()["kind"] == "rollback" and r.json()["instance_id"] == str(ids["data"])
    await _update(Deployment, uuid.UUID(r.json()["id"]), status="cancelled")
    await _update(Instance, ids["data"], data_dirty=None)

    # The chain notice's button: the follow-up, with its own permission, once.
    async with get_sessionmaker()() as db:
        done = _job(ids["green"], ids["env"], "deploy", "succeeded", at=T0 + timedelta(hours=5),
                    options={"slot": "green", "go_live": True})
        db.add(done)
        await db.commit()
    notice = {"text": "Slipway stopped after Deploy to green succeeded, before it started Activate green",
              "at": T0.isoformat(), "deployment_id": done.id.hex, "next": {"kind": "activate", "slot": "green"}}
    await _update(Environment, ids["env"], notice=notice)
    r = await c["viewer"].post(f"{e}/notice/continue")
    assert r.status_code == 403 and "traffic:switch" in r.json()["detail"]
    for iid, service, port in ((ids["green"], "api", 8000), (ids["data"], "spaces", 8333)):
        await _update(Instance, iid, published_ports=[{"service": service, "container": port, "host": 18000}])
    r = await d.post(f"{e}/notice/continue")
    assert r.status_code == 202, r.text
    assert r.json()["kind"] == "activate" and r.json()["options"]["after"] == done.id.hex
    assert (await _get(Environment, ids["env"])).notice is None
    r = await d.post(f"{e}/notice/continue")
    assert r.status_code == 409 and r.json()["detail"] == "uat has no stopped chain to continue"


async def test_add_and_remove_a_slot_and_delete(make_client, github):
    c = await clients(make_client)
    ids = await _world(slots=("blue", "data"), live=("blue", "data"))
    m, e = c["maintainer"], f"/api/v1/environments/{ids['env']}"
    r = await m.post(f"{e}/slots", json={"host_id": str(ids["host_data"])})
    assert r.status_code == 409 and r.json()["detail"].startswith("The data server needs a host of its own")
    await _update(Host, ids["host_green"], host_key=None)
    r = await m.post(f"{e}/slots", json={"host_id": str(ids["host_green"])})
    assert r.status_code == 409 and r.json()["detail"] == "Check host h-green first: Slipway hasn't verified its key"
    await _update(Host, ids["host_green"], host_key="ssh-ed25519 AAAA")
    github["slipway.yml"] = FILES["slipway.yml"].replace("  migrations: expand_contract\n", "")
    r = await m.post(f"{e}/slots", json={"host_id": str(ids["host_green"])})
    assert r.status_code == 409 and "doesn't declare data.migrations: expand_contract" in r.json()["detail"]
    github["slipway.yml"] = FILES["slipway.yml"]
    assert (await c["developer"].post(f"{e}/slots", json={"host_id": str(ids["host_green"])})).status_code == 403
    r = await m.post(f"{e}/slots", json={"host_id": str(ids["host_green"]), "update_data_server": True})
    assert r.status_code == 201, r.text
    out = r.json()
    assert (out["slot"], out["status"], out["host"]["name"]) == ("green", "created", "h-green")
    assert out["deployment"]["slot"] == "data" and out["deployment"]["options"]["chain"] is True
    assert len(await _audits("environment.slot_add")) == 1
    r = await m.post(f"{e}/slots", json={"host_id": str(ids["host_green"])})
    assert r.status_code == 409 and r.json()["detail"] == "uat already has two slots"
    await _update(Deployment, uuid.UUID(out["deployment"]["id"]), status="cancelled")

    r = await m.request("DELETE", f"{e}/slots/blue", json={"confirm": "uat"})
    assert r.status_code == 409 and r.json()["detail"] == "blue takes the traffic: activate green first"
    r = await m.request("DELETE", f"{e}/slots/data", json={"confirm": "uat"})
    assert r.status_code == 409 and r.json()["detail"] == "The data server goes with the environment"

    # Delete with a snapshot first: the snapshot job, then the teardown follows it.
    assert (await c["developer"].request("DELETE", e, json={"confirm": "uat"})).status_code == 403
    r = await m.request("DELETE", e, json={"confirm": "uat", "snapshot": {"name": "uat-before-delete"}})
    assert r.status_code == 202, r.text
    assert r.json()["kind"] == "snapshot" and r.json()["options"]["then"] == "teardown"
    assert r.json()["instance_id"] == str(ids["data"])
    async with get_sessionmaker()() as db:
        snap = await db.scalar(select(Snapshot).where(Snapshot.name == "uat-before-delete"))
        assert snap is not None and str(snap.deployment_id) == r.json()["id"]
    assert (await _get(Environment, ids["env"])).status == "live"  # deleting only once the teardown is queued
    await _update(Deployment, uuid.UUID(r.json()["id"]), status="cancelled")
    r = await m.request("DELETE", e, json={"confirm": "uat"})
    assert r.status_code == 202 and r.json()["kind"] == "teardown"
    assert (await _get(Environment, ids["env"])).status == "deleting"
    r = await m.request("DELETE", e, json={"confirm": "uat"})
    assert r.status_code == 409
