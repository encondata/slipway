"""Create, Add slot, grow, retire and Delete rules for DigitalOcean environments (S18, the service half): P4 tests
62 (production fences), 64 (every §15.1 refusal with its field, ``?check=true``, the confirmation and the rows
written), 80 (create's half: a host-less owner only for managed data) and 88 (the catalog is read before the
account row is locked; a confirmed grow writes the sizes and the plan together and the slot shows its pending
resize). The API half (status codes over HTTP, S20) is tests/test_do_api.py.

FakeDigitalOcean answers the catalog reads; nothing else of DigitalOcean is called (create makes nothing there).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
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
    ProviderAccount,
    Repository,
)
from slipway.services import cloudflare, digitalocean, environments, jobs, provider_accounts
from slipway.services.environments import CreateRefused, NewEnvironment
from tests import do_fixtures as dof
from tests import fake_digitalocean as fdo
from tests.conftest import make_user

ROOT = Path(__file__).resolve().parents[1]
DO_YML = (ROOT / "docs/examples/serversherpa.slipway.yml").read_text()
ENV_EXAMPLE = "STACK_ENV=CHANGEME\nSTACK_DOMAIN=CHANGEME\nSS_SPACES_BUCKET=serversherpa\nSS_JWT_SECRET=CHANGEME\n"
FILES = {"slipway.yml": DO_YML, "deploy/stack/env.example": ENV_EXAMPLE}
ADMIN = {"fields": {"first_name": "Ada", "last_name": "Lovelace", "email": "ada@example.com"}, "mode": "password",
         "password": "correct-horse-battery"}
# s-1vcpu-1gb $6, db-s-1vcpu-1gb × 1 $15, the load balancer $12, Spaces $5: $38.00 (one droplet), $44.00 (two).
ONE, TWO = "38.00", "44.00"


@dataclass
class Ctx:
    """The caller (``AuthContext``'s ``user`` and ``can``), with exactly ``perms``."""

    user: Any = None
    perms: set[str] = field(default_factory=lambda: {"*"})

    def can(self, permission: str) -> bool:
        return "*" in self.perms or permission in self.perms


@dataclass
class World:
    repo_id: uuid.UUID
    account_id: uuid.UUID
    user: Any
    fake: fdo.FakeDigitalOcean
    calls: list[str] = field(default_factory=list)  # catalog paths DigitalOcean was asked for
    locked: list[bool] = field(default_factory=lambda: [False])  # the account row is held FOR UPDATE

    def ctx(self, *perms: str) -> Ctx:
        return Ctx(self.user, set(perms) if perms else {"*"})


def reader(files: dict[str, str | None] | None = None):
    files = FILES if files is None else files

    async def read(repo, branch, path):
        return files.get(path)

    return read


@pytest.fixture
async def world(monkeypatch) -> World:
    """A repository, a DigitalOcean account (FakeDigitalOcean's token), Cloudflare on example.com, and the fake
    behind the client: it fails the test when it is called while the account row is locked (test 88)."""
    provider_accounts.clear_catalog_cache()
    fake = fdo.FakeDigitalOcean()
    fdo.use_fake(monkeypatch, fake)
    user = await make_user(f"admin-{uuid.uuid4().hex[:6]}@example.com", roles=["admin"])
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=4242, full_name="acme/serversherpa", owner="acme", name="serversherpa",
                          html_url="https://github.com/acme/serversherpa", detected_config={})
        db.add(repo)
        db.add(AppSetting(key=cloudflare.SETTING_KEY, value={"zone": "example.com", "public_ip": None,
                                                             "proxied": False}, secret="c" * 40))
        await db.commit()
    w = World(repo_id=repo.id, account_id=await dof.make_account(), user=user, fake=fake)

    async def handler(request: httpx.Request) -> httpx.Response:
        assert not w.locked[0], f"DigitalOcean was called while the account row was locked: {request.url.path}"
        w.calls.append(request.url.path)
        return fake.handler(request)

    monkeypatch.setattr(digitalocean, "transport_factory", lambda: httpx.MockTransport(handler))
    real_get = provider_accounts.get

    async def get(db, account_id, *, lock=False):
        if lock:
            w.locked[0] = True
        return await real_get(db, account_id, lock=lock)

    monkeypatch.setattr(provider_accounts, "get", get)
    return w


def body(w: World, **kw: Any) -> NewEnvironment:
    placement = {"provider": "digitalocean", "account_id": w.account_id, "region": "nyc3",
                 "droplet_size": "s-1vcpu-1gb", "db_size": "db-s-1vcpu-1gb", "db_standby": False,
                 "acme_staging": False, "slots": 1, **kw.pop("placement", {})}
    values: dict[str, Any] = dict(name="shop", repository_id=w.repo_id, data_mode="managed", hosts={},
                                  settings={"STACK_DOMAIN": "shop.example.com"},
                                  traffic={"switch": "do_lb", "dns": {"proxied": False}}, first_admin=ADMIN,
                                  placement=placement)
    values.update(kw)
    return NewEnvironment(**values)


async def refused(w: World, request: NewEnvironment, *, files=None, ctx: Ctx | None = None) -> CreateRefused:
    async with get_sessionmaker()() as db:
        with pytest.raises(CreateRefused) as err:
            await environments.validate_create(db, request, ctx or w.ctx(), read_file=reader(files))
    return err.value


async def counts() -> tuple[int, ...]:
    async with get_sessionmaker()() as db:
        return tuple([await db.scalar(select(func.count()).select_from(m))
                      for m in (Environment, Instance, Host, FirstAdmin)])


async def created(w: World, request: NewEnvironment, *, ctx: Ctx | None = None) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        plan = await environments.validate_create(db, request, ctx or w.ctx(), read_file=reader())
        env = await environments.create(db, plan, ctx or w.ctx())
        await db.commit()
        w.locked[0] = False
        return env.id


async def set_account(w: World, **config: Any) -> None:
    async with get_sessionmaker()() as db:
        row = await db.get(ProviderAccount, w.account_id)
        values = {k: v for k, v in config.items() if k in ("production", "secret", "removed_at", "provider")}
        if values:
            await db.execute(update(ProviderAccount).where(ProviderAccount.id == w.account_id).values(**values))
        rest = {k: v for k, v in config.items() if k not in values}
        if rest:
            row.config = {**row.config, **rest}
        await db.commit()


# ------------------------------------------------------------------- test 64: create's refusals


async def test_64_every_refusal_of_create_with_its_text_and_field(world, monkeypatch):
    w = world
    before = await counts()

    async def no(request, status, detail, where, **kw):
        err = await refused(w, request, **kw)
        assert (err.status, err.detail, err.field) == (status, detail, where), err.detail
        return err

    # 1. Spending money.
    await no(body(w), 403, "Creating a DigitalOcean environment needs the providers:spend permission", "placement",
             ctx=w.ctx("environments:write"))
    await no(body(w, hosts={"blue": uuid.uuid4()}), 422, "A DigitalOcean environment makes its droplets: leave hosts "
             "out", "hosts")
    # 2. The account.
    await no(body(w, placement={"account_id": uuid.uuid4()}), 422, "Unknown account", "placement.account_id")
    await set_account(w, secret=None)
    await no(body(w), 409, "Slipway can't read do-main's token any more: enter it again", "placement.account_id")
    await set_account(w, secret=dof.TOKEN, ssh_sources=[])
    await no(body(w), 409, "do-main has no SSH sources: set the addresses Slipway connects from on the account first",
             "placement.account_id")
    await set_account(w, ssh_sources=dof.SSH_SOURCES, production=True)
    await no(body(w), 409, "do-main is for production environments", "placement.account_id")
    await set_account(w, production=False)
    await no(body(w, production=True, placement={"slots": 2}), 409,
             "do-main isn't a production account: a production environment needs one", "placement.account_id")
    async with get_sessionmaker()() as db:
        pve = ProviderAccount(provider="proxmox", name="lab", secret="x", config={"url": "https://pve.test"})
        db.add(pve)
        await db.commit()
    await no(body(w, placement={"account_id": pve.id}), 409, "lab is a Proxmox account: choose Hosts under Where",
             "placement.account_id")
    # Production's own rules (§13).
    await set_account(w, production=True)
    await no(body(w, production=True), 409, "Production runs Blue and Green", "placement.slots")
    await no(body(w, production=True, placement={"slots": 2, "acme_staging": True}), 409,
             "A production environment can't use Let's Encrypt staging certificates", "placement.acme_staging")
    await set_account(w, production=False)
    # 3. The manifest.
    no_edge = DO_YML[:DO_YML.index("\nedge:")] + DO_YML[DO_YML.index("\ndata:"):]
    await no(body(w), 409, "acme/serversherpa's slipway.yml at main doesn't say how it runs on managed data behind a "
             "load balancer (data.managed and edge)", "placement", files={**FILES, "slipway.yml": no_edge})
    no_migrations = DO_YML.replace("  migrations: expand_contract\n", "")
    err = await refused(w, body(w, placement={"slots": 2}), files={**FILES, "slipway.yml": no_migrations})
    assert (err.status, err.field) == (409, "placement.slots") and "expand_contract" in err.detail
    # 4. The catalog, read live.
    w.fake.regions[0]["available"] = False
    await no(body(w), 409, "nyc3 isn't open for new objects in DigitalOcean", "placement.region")
    w.fake.regions[0]["available"] = True
    provider_accounts.clear_catalog_cache()
    err = await refused(w, body(w, placement={"region": "sfo3", "droplet_size": "s-9vcpu-99gb"}))
    assert (err.status, err.detail, err.field) == (
        409, "s-9vcpu-99gb isn't a droplet size DigitalOcean offers in sfo3", "placement.droplet_size")
    await no(body(w, placement={"db_size": "db-s-1vcpu-1gb", "db_standby": True}), 409,
             "db-s-1vcpu-1gb has no 2-node layout", "placement.db_size")
    w.fake.db_options["options"]["pg"]["versions"] = ["17"]
    await no(body(w), 409, "PostgreSQL 16 isn't offered by DigitalOcean here (17)", "placement")
    w.fake.db_options["options"]["pg"]["versions"] = list(fdo.DB_VERSIONS)
    w.fake.down = True  # DigitalOcean doesn't answer: 502, with the client's text and never the token
    err = await refused(w, body(w))
    assert (err.status, err.field) == (502, "placement") and err.detail.startswith(
        "Slipway couldn't read DigitalOcean's catalog for do-main: ") and dof.TOKEN not in err.detail
    w.fake.down = False
    # 5. Cloudflare and the zone.
    err = await refused(w, body(w, settings={"STACK_DOMAIN": "shop.example.org"}))
    assert (err.status, err.field) == (409, "traffic.dns") and "isn't in the Cloudflare zone example.com" in err.detail
    err = await refused(w, body(w, traffic={"switch": "do_lb", "dns": {"address": "203.0.113.9"}}))
    assert (err.status, err.field) == (422, "traffic.dns")
    # 6. The droplets' host names.
    async with get_sessionmaker()() as db:
        db.add(Host(name="slipway-shop-blue", hostname="10.9.9.9", username="deploy", metrics={}))
        await db.commit()
    await no(body(w), 409, "A host named slipway-shop-blue already exists: rename it, or pick another environment name",
             "name")
    async with get_sessionmaker()() as db:
        await db.execute(Host.__table__.delete().where(Host.name == "slipway-shop-blue"))
        await db.commit()
    # 7. Traffic follows placement, both ways.
    await no(body(w, traffic={"switch": "switchyard", "dns": None}), 409, environments.DO_NEEDS_LB, "traffic.switch")
    async with get_sessionmaker()() as db:
        host = Host(name="h-blue", hostname="10.0.0.11", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
        db.add(host)
        await db.commit()
    ssh_body = NewEnvironment(name="plain", repository_id=w.repo_id, data_mode="slot", hosts={"blue": host.id},
                              settings={"STACK_DOMAIN": "plain.example.com", "STACK_PROXY_IP": "10.0.0.2"},
                              traffic={"switch": "do_lb", "dns": None}, first_admin=ADMIN)
    await no(ssh_body, 409, environments.LB_NEEDS_DO, "traffic.switch")
    await no(NewEnvironment(**{**ssh_body.__dict__, "data_mode": "managed"}), 422,
             "Managed data comes only with DigitalOcean placement: choose DigitalOcean under Where", "data_mode")
    await no(NewEnvironment(**{**ssh_body.__dict__, "traffic": {"switch": "none", "dns": None}, "production": True}),
             409, "Only a DigitalOcean environment can be a production environment", "production")
    # 8. The account's limit: the other environments' stored totals plus this one.
    other = await dof.make_do_env(name="older", account_id=w.account_id)  # its stored total is $47.00
    await set_account(w, monthly_limit_cents=8000)
    await no(body(w), 409, "This would bring do-main's estimate to $85.00 a month, over its limit of $80.00",
             "confirm_cost")
    await set_account(w, monthly_limit_cents=None)
    # Nothing was written by any refusal (the older environment and the hosts above aside).
    async with get_sessionmaker()() as db:
        names = set(await db.scalars(select(Environment.name)))
    assert names == {"older"} and other.name == "older"
    assert (await counts())[3] == before[3]


async def test_64_check_answers_the_cost_the_cloud_objects_and_the_planned_slots_and_writes_nothing(world):
    w = world
    before = await counts()
    async with get_sessionmaker()() as db:
        plan = await environments.validate_create(db, body(w, placement={"slots": 2}), w.ctx(), read_file=reader())
    out = plan.to_json()
    assert out["cost"]["total"] == TWO and out["cost"]["note"].startswith("Estimated, prices as of ")
    assert [line["object"] for line in out["cost"]["lines"]] == [
        "droplet", "database", "load_balancer", "spaces", "vpc", "firewall", "certificate"]
    assert out["cost"]["lines"][0]["label"] == "2 × droplet s-1vcpu-1gb (1 vCPU, 1 GB, 25 GB)"
    cloud = out["plan"]["cloud"]
    assert cloud["region"] == "nyc3" and cloud["account"]["name"] == "do-main"
    assert cloud["plan"]["droplets"] == 2 and cloud["database"]["version"] == "16"
    assert [d["name"] for d in cloud["droplets"]] == ["slipway-shop-blue", "slipway-shop-green"]
    assert out["plan"]["slots"]["blue"] == {"host_id": None, "host": "slipway-shop-blue", "role": "app",
                                            "slug": "shop-blue", "planned": "digitalocean"}
    assert out["plan"]["slots"]["data"]["host_id"] is None and out["plan"]["slots"]["data"]["managed"] is True
    assert out["plan"]["traffic"] == {"switch": "do_lb", "dns": {"provider": "cloudflare", "address": None,
                                                                 "proxied": False}}
    assert "machines" not in out["plan"]
    assert await counts() == before
    assert set(w.calls) == {"/v2/regions", "/v2/sizes", "/v2/databases/options"}
    assert dof.TOKEN not in str(out)


async def test_64_a_mistyped_total_is_422_and_a_moved_estimate_409_and_nothing_is_written(world):
    w = world
    async with get_sessionmaker()() as db:  # the check the page showed: $38.00
        shown = await environments.validate_create(db, body(w), w.ctx(), read_file=reader())
    assert shown.do.cost.total == ONE
    before = await counts()
    for typed in (None, "38", "$37.00"):
        async with get_sessionmaker()() as db:
            plan = await environments.validate_create(db, body(w, confirm_cost=typed), w.ctx(), read_file=reader())
            with pytest.raises(CreateRefused) as err:
                await environments.create(db, plan, w.ctx())
        assert (err.value.status, err.value.detail, err.value.field) == (
            422, "Type 38.00 to confirm about $38.00 a month", "confirm_cost")
    # DigitalOcean's droplet price moves after the page was shown: the figure shown answers 409.
    w.fake.sizes[0]["price_monthly"] = 7.0
    async with get_sessionmaker()() as db:
        plan = await environments.validate_create(db, body(w, confirm_cost="$ 38.00 "), w.ctx(), read_file=reader())
        with pytest.raises(CreateRefused) as err:
            await environments.create(db, plan, w.ctx())
    assert (err.value.status, err.value.detail) == (
        409, "The estimate changed to $39.00 a month (DigitalOcean's prices moved): check it again")
    assert await counts() == before
    await created(w, body(w, confirm_cost="39.00"))
    assert (await counts())[0] == before[0] + 1


async def test_64_and_80_create_writes_the_environment_planned_hosts_slots_and_the_hostless_owner(world):
    w = world
    env_id = await created(w, body(w, placement={"slots": 2, "db_standby": True, "db_size": "db-s-1vcpu-2gb"},
                                   confirm_cost="89.00", keep_backups=7))
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        mem = await environments.members(db, env)
        assert env.provider == "digitalocean" and env.provider_account_id == w.account_id and not env.production
        assert env.data_mode == "managed" and env.status == "new"
        assert env.traffic == {"switch": "do_lb", "dns": {"provider": "cloudflare", "address": None, "proxied": False}}
        cloud = env.cloud
        assert (cloud["region"], cloud["droplet_size"], cloud["db_size"], cloud["db_nodes"], cloud["db_version"]) == (
            "nyc3", "s-1vcpu-1gb", "db-s-1vcpu-2gb", 2, "16")
        assert cloud["plan"]["droplets"] == 2 and cloud["plan"]["db_nodes"] == 2
        assert cloud["cost"]["total_cents"] == 8900 and cloud["cost"]["confirmed_by_id"] == str(w.user.id)
        assert cloud["lb_ip"] is None and cloud["edge"] is None and cloud["slipway_addresses"] == []
        # The planned droplet hosts, owned by the environment, never built, with keys Slipway made.
        for slot in ("blue", "green"):
            host = mem[slot].host
            assert host.name == f"slipway-shop-{slot}" and host.provider == "digitalocean"
            assert host.owner_environment_id == env.id and host.provider_state == {"phase": "planned"}
            assert host.username == "slipway" and host.hostname.endswith(".invalid") and host.host_key is None
            assert mem[slot].status == "created" and mem[slot].slug == f"shop-{slot}"
        # The managed data owner: no host, the owner's fields, the first admin.
        owner = mem["data"]
        assert owner.host_id is None and owner.keep_backups == 7 and owner.seed_content is True
        admin = await db.scalar(select(FirstAdmin).where(FirstAdmin.instance_id == owner.id))
        assert admin is not None and admin.mode == "password"
        events = {e.action: e for e in await db.scalars(select(AuditEvent).where(AuditEvent.target_id == str(env.id)))}
        assert set(events) == {"environment.create", "environment.cost_confirmed"}
        create = events["environment.create"].details
        assert create["provider"] == "digitalocean" and create["account"] == "do-main"
        assert create["slots"] == {"blue": "slipway-shop-blue", "green": "slipway-shop-green"}
        cost = events["environment.cost_confirmed"].details
        assert cost["total"] == "89.00" and cost["typed"] == "89.00" and len(cost["lines"]) == 7
        text = str([e.details for e in events.values()])
        for secret in (dof.TOKEN, "correct-horse-battery", *env.app_secrets.values()):
            assert secret not in text
    # Test 80's create half: a mode server environment's owner has its host; only managed data has none.
    async with get_sessionmaker()() as db:
        assert await db.scalar(select(func.count()).select_from(Instance).where(Instance.host_id.is_(None))) == 1


async def test_a_production_create_takes_two_slots_a_production_account_and_one_per_app(world):
    w = world
    await set_account(w, production=True)
    prod = body(w, production=True, placement={"slots": 2}, confirm_cost=TWO)
    env_id = await created(w, prod)
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        assert env.production and env.retiring_at is None and not env.auto_activate
    shop2 = {"name": "shop2", "settings": {"STACK_DOMAIN": "shop2.example.com"}}
    err = await refused(w, body(w, production=True, placement={"slots": 2}, **shop2))
    assert (err.status, err.detail, err.field) == (
        409, "acme/serversherpa's slipway.yml already has a production environment, shop; retire it first",
        "production")
    err = await refused(w, body(w, production=True, placement={"slots": 2}, auto_activate=True, **shop2))
    assert (err.status, err.field) == (409, "production")  # the app's production comes first
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        await environments.retire(db, env, w.ctx(), "shop")
        await db.commit()
    err = await refused(w, body(w, production=True, placement={"slots": 2}, auto_activate=True, **shop2))
    assert (err.status, err.detail, err.field) == (
        409, "A production environment waits for Activate: turn Activate automatically off", "auto_activate")
    await created(w, body(w, production=True, placement={"slots": 2}, confirm_cost=TWO, **shop2))


# ------------------------------------------------------------- test 88: no HTTP under the account's lock


async def test_88_create_add_slot_and_grow_read_the_catalog_before_the_account_row_is_locked(world):
    w = world
    env_id = await created(w, body(w, confirm_cost=ONE))
    assert w.calls  # the catalog was read, and never while the row was locked (the handler asserts it)
    # Add slot: the new total and the delta, confirmed.
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        plan = await environments.add_slot_plan(db, env, {"confirm_cost": TWO}, w.ctx(), read_file=reader())
        assert plan.to_json()["cost"]["total"] == TWO and plan.to_json()["cost"]["delta"] == "+$6.00 a month"
        inst = await environments.add_slot(db, plan, w.ctx())
        await db.commit()
        w.locked[0] = False
        env = await db.get(Environment, env_id, populate_existing=True)
        assert inst.slot == "green" and env.cloud["plan"]["droplets"] == 2 and env.cloud["cost"]["total_cents"] == 4400
        green = await db.get(Host, inst.host_id)
        assert green.name == "slipway-shop-green" and green.owner_environment_id == env.id
    # Grow: blue's droplet size and the cluster, confirmed; cloud's sizes and plan change together.
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        blue = (await environments.members(db, env))["blue"]
        await db.execute(update(Host).where(Host.id == blue.host_id)
                         .values(provider_state={"phase": "ready", "size": "s-1vcpu-1gb"}))
        await db.commit()
        grown = await environments.grow_plan(db, env, {"droplet_size": "s-1vcpu-2gb", "db_size": "db-s-1vcpu-2gb",
                                                       "db_standby": True}, w.ctx(), confirm_cost="101.00")
        assert grown.to_json()["cost"]["delta"] == "+$57.00 a month"
        await environments.grow(db, grown, w.ctx())
        await db.commit()
        w.locked[0] = False
        env = await db.get(Environment, env_id, populate_existing=True)
        assert (env.cloud["droplet_size"], env.cloud["plan"]["droplet_size"]) == ("s-1vcpu-2gb", "s-1vcpu-2gb")
        assert (env.cloud["db_nodes"], env.cloud["plan"]["db_nodes"]) == (2, 2)
        assert env.cloud["cost"]["total_cents"] == 10100 and env.cloud["db_size"] == "db-s-1vcpu-2gb"
        pending = await environments.pending_resizes(db, env)
        assert pending == {"blue": "Resize pending: applies at blue's next deploy"}  # green isn't made yet
        actions = await environments.actions(db, env, w.ctx())
        assert actions["grow"]["pending"] == pending
        events = [e.action for e in await db.scalars(select(AuditEvent).where(AuditEvent.target_id == str(env.id))
                                                     .order_by(AuditEvent.created_at))]
        assert events.count("environment.cost_confirmed") == 3 and "environment.resize" in events
        assert "environment.slot_add" in events
        resize = await db.scalar(select(AuditEvent).where(AuditEvent.action == "environment.resize"))
        assert resize.details["from"]["droplet_size"] == "s-1vcpu-1gb" and resize.details["delta"] == "+$57.00 a month"


async def test_grow_refuses_a_shrink_a_standby_removal_and_while_retiring(world):
    w = world
    env = await dof.make_do_env(name="big", account_id=w.account_id, droplet_size="s-2vcpu-4gb",
                                db_size="db-s-1vcpu-2gb", db_nodes=2)
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        cases = [({"droplet_size": "s-1vcpu-2gb"}, "s-1vcpu-2gb isn't larger than s-2vcpu-4gb in every way",
                  "cloud.droplet_size"),
                 ({"droplet_size": "c-2"}, "c-2 is another kind of droplet than s-2vcpu-4gb: a droplet only grows "
                                           "within its kind (s)", "cloud.droplet_size"),
                 ({"db_standby": False}, "A standby node can be added but not removed", "cloud.db_standby"),
                 ({}, "Choose a larger size, or add a standby node", "cloud")]
        for sizes, detail, where in cases:
            with pytest.raises(CreateRefused) as err:
                await environments.grow_plan(db, row, sizes, w.ctx())
            assert (err.value.detail, err.value.field) == (detail, where)
        with pytest.raises(CreateRefused) as err:
            await environments.grow_plan(db, row, {"droplet_size": "s-4vcpu-8gb"}, w.ctx("environments:write"))
        assert err.value.status == 403
        plan = await environments.grow_plan(db, row, {"droplet_size": "s-4vcpu-8gb"}, w.ctx(), confirm_cost="1.00")
        with pytest.raises(CreateRefused) as err:
            await environments.grow(db, plan, w.ctx())
        assert err.value.status == 422 and err.value.field == "confirm_cost"


async def test_add_slot_on_digitalocean_needs_spend_no_host_and_the_total(world):
    w = world
    env = await dof.make_do_env(name="one", account_id=w.account_id, slots=("blue",))
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        with pytest.raises(CreateRefused) as err:
            await environments.add_slot_plan(db, row, {}, w.ctx("environments:write"), read_file=reader())
        assert (err.value.status, err.value.detail) == (403, "Adding a droplet needs the providers:spend permission")
        with pytest.raises(CreateRefused) as err:
            await environments.add_slot_plan(db, row, {"host_id": uuid.uuid4()}, w.ctx(), read_file=reader())
        assert (err.value.status, err.value.field) == (422, "host_id")
        plan = await environments.add_slot_plan(db, row, {"confirm_cost": "1.00"}, w.ctx(), read_file=reader())
        with pytest.raises(CreateRefused) as err:
            await environments.add_slot(db, plan, w.ctx())
        assert (err.value.status, err.value.detail) == (422, "Type 44.00 to confirm about $44.00 a month")
        await set_account(w, monthly_limit_cents=4000)
        with pytest.raises(CreateRefused) as err:
            await environments.add_slot_plan(db, row, {"confirm_cost": TWO}, w.ctx(), read_file=reader())
        assert err.value.detail == "This would bring do-main's estimate to $44.00 a month, over its limit of $40.00"


# ---------------------------------------------------------------- test 62: production's fences


async def prod_env(w: World, **kw: Any) -> dof.DoEnv:
    await set_account(w, production=True)
    return await dof.make_do_env(name="prod", account_id=w.account_id, production=True, **kw)


async def held_data(env: dof.DoEnv) -> None:
    """The owner holds data: blue went live once on it."""
    await _set(Instance, env.ids["blue"], current_commit_sha=dof.SHA, status="running")


async def runner(env: dof.DoEnv, slot: str = "blue") -> None:
    """``slot``'s droplet is built and has a live release: it can run the data commands."""
    await _set(Host, env.host_ids[slot], provider_state={"phase": "ready", "size": "s-1vcpu-1gb"},
               host_key="ssh-ed25519 AAAA")
    await _set(Instance, env.ids[slot], current_commit_sha=dof.SHA, status="running",
               app_state={"live": {"release": "r1", "sha": dof.SHA, "deployment": "11" * 16}})


async def _set(model: Any, ident: uuid.UUID, **values: Any) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(update(model).where(model.id == ident).values(**values))
        await db.commit()


async def queue(w: World, env: dof.DoEnv, kind: str, **opts: Any) -> Deployment:
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        dep = await jobs.queue_job(db, environment=row, user=w.user, kind=kind, options=opts,
                                   retry_of=opts.pop("retry_of", None))
        await db.commit()
        return dep


async def queue_refused(w: World, env: dof.DoEnv, kind: str, **opts: Any) -> jobs.JobRefused:
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        retry_of = await db.get(Deployment, opts.pop("retry_of")) if "retry_of" in opts else None
        with pytest.raises(jobs.JobRefused) as err:
            await jobs.queue_job(db, environment=row, user=w.user, kind=kind, options=opts, retry_of=retry_of)
    return err.value


async def delete(w: World, env: dof.DoEnv, ctx: Ctx | None = None, **raw: Any) -> environments.DeletePlan:
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        return await environments.delete_problem(db, row, {"confirm": env.name, **raw}, ctx or w.ctx(),
                                                 read_vms=False)


async def delete_refused(w: World, env: dof.DoEnv, ctx: Ctx | None = None, **raw: Any) -> CreateRefused:
    with pytest.raises(CreateRefused) as err:
        await delete(w, env, ctx, **raw)
    return err.value


async def test_62_activate_needs_the_name_and_a_retiring_production_only_goes_dark(world):
    w = world
    env = await prod_env(w)
    err = await queue_refused(w, env, "activate", slot="blue")
    assert (err.status, err.text) == (422, "Type the environment's name, prod, exactly to confirm")
    err = await queue_refused(w, env, "activate", slot="blue", confirm="prod")
    assert err.status == 409 and err.text != "prod is retiring: it only goes dark"  # past the name: blue isn't built
    # The first deploy's chained activate (nothing live yet) moves no traffic away: no name.
    err = await queue_refused(w, env, "activate", slot="blue", chain=True)
    assert err.status == 409
    await _set(Environment, env.env_id, retiring_at=datetime.now(UTC))
    err = await queue_refused(w, env, "activate", slot="green", confirm="prod")
    assert (err.status, err.text) == (409, "prod is retiring: it only goes dark")
    # Deactivate is only for a retiring production with a live slot.
    plain = await dof.make_do_env(name="plain", account_id=await dof.make_account("do-dev"))
    err = await queue_refused(w, plain, "deactivate")
    assert (err.status, err.text) == (409, "Only a retiring production environment is taken off the air: retire "
                                           "plain first")
    err = await queue_refused(w, env, "deactivate")
    assert (err.status, err.text) == (409, "prod has no live slot: there is no traffic to take off")


async def test_62_delete_of_production_retiring_dark_with_the_phrase_and_a_snapshot(world):
    w = world
    env = await prod_env(w)
    await held_data(env)
    await runner(env)
    err = await delete_refused(w, env)
    assert (err.status, err.detail, err.field) == (422, "Type delete production prod to confirm", "confirm_production")
    phrase = {"confirm_production": "delete production prod"}
    err = await delete_refused(w, env, **phrase)
    assert (err.status, err.detail) == (409, "Retire prod first: a production environment is deleted only after it "
                                             "is retired")
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        with pytest.raises(CreateRefused) as typed:
            await environments.retire(db, row, w.ctx(), "nope")
        assert typed.value.status == 422
        await environments.retire(db, row, w.ctx(), "prod")
        await db.commit()
        event = await db.scalar(select(AuditEvent).where(AuditEvent.action == "environment.retire"))
        assert event is not None and event.actor_id == w.user.id
    await _set(Environment, env.env_id, active_slot_id=env.ids["blue"], status="live")
    err = await delete_refused(w, env, **phrase)
    assert (err.status, err.detail) == (409, "Deactivate prod first: it still takes traffic")
    await _set(Environment, env.env_id, active_slot_id=None)
    err = await delete_refused(w, env, **phrase)
    assert (err.status, err.detail, err.field) == (422, "A production environment is deleted only after a snapshot",
                                                   "snapshot")
    err = await delete_refused(w, env, w.ctx("environments:delete"), snapshot={"name": "before-delete"}, **phrase)
    assert err.status == 403
    plan = await delete(w, env, snapshot={"name": "before-delete"}, **phrase)
    assert plan.snapshot and not plan.without_snapshot
    assert plan.snapshot_options() == {"then": "teardown",
                                       "then_options": {"confirm_production": "delete production prod"}}
    # The teardown the snapshot's chain queues carries the phrase and that a snapshot came first.
    snap_dep = Deployment(instance_id=env.ids["data"], environment_id=env.env_id, kind="snapshot",
                          status="succeeded", branch="main", options=plan.snapshot_options())
    async with get_sessionmaker()() as db:
        db.add(snap_dep)
        await db.commit()
        nxt = await environments.next_job(db, snap_dep)
    assert nxt.kind == "teardown" and nxt.options == {"confirmed": True, "snapshot_first": True,
                                                      "confirm_production": "delete production prod"}
    # Queued without the phrase, or without a snapshot first, the teardown is refused.
    err = await queue_refused(w, env, "teardown", confirmed=True)
    assert (err.status, err.text) == (422, "Type delete production prod to confirm")
    err = await queue_refused(w, env, "teardown", confirmed=True, **phrase)
    assert (err.status, err.text) == (422, "A production environment is deleted only after a snapshot")
    dep = await queue(w, env, "teardown", **nxt.options)
    # A retry of the teardown asks the phrase again.
    await _set(Deployment, dep.id, status="failed")
    err = await queue_refused(w, env, "teardown", retry_of=dep.id)
    assert (err.status, err.text) == (422, "Type delete production prod to confirm")
    retried = await queue(w, env, "teardown", retry_of=await _dep(dep.id), **phrase)
    assert retried.options["snapshot_first"] is True


async def _dep(dep_id: uuid.UUID) -> Deployment:
    async with get_sessionmaker()() as db:
        return await db.get(Deployment, dep_id)


async def test_62_a_production_that_never_held_data_is_deleted_without_a_snapshot(world):
    w = world
    env = await prod_env(w)
    await _set(Environment, env.env_id, retiring_at=datetime.now(UTC))
    plan = await delete(w, env, confirm_production="delete production prod", snapshot={"name": "s1"})
    assert not plan.snapshot and plan.note == "prod never held data, so there is nothing to snapshot"
    dep = await queue(w, env, "teardown", **plan.options)
    assert dep.kind == "teardown"


async def test_62_holding_data_with_every_droplet_gone_needs_the_second_phrase_and_drop_data(world):
    w = world
    env = await prod_env(w)
    await held_data(env)  # blue went live once; neither droplet is built now
    await _set(Environment, env.env_id, retiring_at=datetime.now(UTC))
    phrase = {"confirm_production": "delete production prod"}
    err = await delete_refused(w, env, snapshot={"name": "s1"}, **phrase)
    assert (err.status, err.detail) == (409, "No slot can run the data commands: deploy to blue first")
    err = await delete_refused(w, env, **phrase)
    assert (err.status, err.field) == (422, "confirm_no_snapshot")
    second = {"confirm_no_snapshot": "delete production prod without a snapshot"}
    err = await delete_refused(w, env, w.ctx("data:reset"), drop_data=True, **phrase, **second)
    assert (err.status, err.field) == (403, "confirm_no_snapshot")
    err = await delete_refused(w, env, **phrase, **second)
    assert (err.status, err.detail, err.field) == (
        409, "prod's data is in its managed database, which Delete destroys: take a snapshot first, or confirm that "
             "the data goes with it", "drop_data")
    plan = await delete(w, env, drop_data=True, **phrase, **second)
    assert plan.without_snapshot and plan.why == "prod has no slot that can run its data commands: deploy to blue first"
    assert plan.options["no_snapshot"] is True
    dep = await queue(w, env, "teardown", **plan.options)
    # Its retry asks both phrases again.
    await _set(Deployment, dep.id, status="failed")
    err = await queue_refused(w, env, "teardown", retry_of=dep.id, **phrase)
    assert (err.status, err.text) == (422, "Type delete production prod without a snapshot to confirm")
    retried = await queue(w, env, "teardown", retry_of=await _dep(dep.id), **phrase, **second)
    assert retried.options["no_snapshot"] is True


async def test_62_a_managed_environment_that_holds_data_goes_without_a_snapshot_only_with_drop_data(world):
    w = world
    env = await dof.make_do_env(name="shop", account_id=w.account_id)
    await held_data(env)
    await runner(env)
    err = await delete_refused(w, env)
    assert (err.status, err.field) == (409, "drop_data")
    err = await delete_refused(w, env, w.ctx("environments:delete"), drop_data=True)
    assert (err.status, err.detail) == (403, "Deleting shop's data with it needs the data:reset permission")
    plan = await delete(w, env, drop_data=True)
    assert plan.without_snapshot and plan.options == {"confirmed": True, "drop_data": True} and not plan.snapshot
    plan = await delete(w, env, snapshot={"name": "keep"})
    assert plan.snapshot and not plan.without_snapshot
    # A backup that reached ready (missing now) alone also counts as data held.
    other = await dof.make_do_env(name="other", account_id=w.account_id)
    async with get_sessionmaker()() as db:
        db.add(Backup(instance_id=other.ids["data"], name="b1", status="missing", location="slipway", reason="manual",
                      format="pg_dump", identity_fp="0" * 64, taken_at=datetime.now(UTC), db_bytes=10,
                      db_sha256="1" * 64, finished_at=datetime.now(UTC)))
        await db.commit()
    assert (await delete_refused(w, other)).field == "drop_data"


async def test_unretire_is_refused_while_another_production_of_the_app_runs(world):
    w = world
    env = await prod_env(w, manifest_file="slipway.yml")
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        with pytest.raises(CreateRefused) as err:
            await environments.unretire(db, row, w.ctx(), "prod")
        assert (err.value.status, err.value.detail) == (409, "prod isn't retiring")
        await environments.retire(db, row, w.ctx(), "prod")
        await db.commit()
        row = await db.get(Environment, env.env_id)
        twin = Environment(name="prod2", repository_id=row.repository_id, branch="main", data_mode="managed",
                           manifest_file="slipway.yml", app_settings={}, app_secrets={}, env={},
                           traffic={"switch": "do_lb", "dns": None}, hostnames=[], provider="digitalocean",
                           provider_account_id=w.account_id, production=True, cloud={})
        db.add(twin)
        await db.commit()
        twin_id = twin.id
        row = await db.get(Environment, env.env_id)
        with pytest.raises(CreateRefused) as err:
            await environments.unretire(db, row, w.ctx(), "prod")
        assert err.value.status == 409 and err.value.detail.endswith(
            "already has a production environment, prod2; retire it first")
        await db.rollback()
        twin = await db.get(Environment, twin_id)
        twin.retiring_at = datetime.now(UTC)
        await db.commit()
        row = await db.get(Environment, env.env_id)
        await environments.unretire(db, row, w.ctx(), "prod")
        await db.commit()
        row = await db.get(Environment, env.env_id, populate_existing=True)
        assert row.retiring_at is None
        acts = [e.action for e in await db.scalars(select(AuditEvent).where(AuditEvent.target_id == str(env.env_id)))]
        assert {"environment.retire", "environment.unretire"} <= set(acts)


async def test_actions_offer_retire_deactivate_grow_and_renew_by_their_rules(world):
    w = world
    env = await prod_env(w)
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        acts = await environments.actions(db, row, w.ctx())
        assert acts["retire"]["available"] and not acts["unretire"]["available"]
        assert acts["deactivate"]["reason"] == "Only a retiring production environment is taken off the air: retire " \
                                               "prod first"
        assert acts["delete"]["reason"] == "Retire prod first: a production environment is deleted only after it " \
                                           "is retired"
        assert acts["grow"]["available"]
        assert acts["renew_certificate"]["reason"] == "prod has no load balancer yet: deploy it first"
        assert acts["update_data_server"]["reason"] == "prod's data is in its managed database, so it has no data " \
                                                       "server to update"
        # A managed environment's first Deploy goes to blue, never to the data owner (Decision 21).
        assert acts["deploy"]["slot"] == "blue"
        acts = await environments.actions(db, row, w.ctx("environments:write", "environments:read"))
        assert acts["grow"]["reason"] == "You need the providers:spend permission"
        assert acts["vm_snapshots"]["available"] is False and acts["resize"] == {} and acts["forget"] == {}


def test_the_create_body_takes_placement_production_and_the_typed_total():
    from slipway.schemas import EnvironmentCreate, EnvironmentDelete, SlotAdd, TrafficIn

    made = EnvironmentCreate(name="shop", repository_id=uuid.uuid4(), data_mode="managed",
                             placement={"provider": "digitalocean", "account_id": uuid.uuid4(),
                                        "droplet_size": "s-1vcpu-1gb", "db_size": "db-s-1vcpu-1gb", "slots": 2},
                             production=True, confirm_cost="44.00", traffic={"switch": "do_lb"})
    assert made.hosts == {} and made.placement.slots == 2 and TrafficIn(switch="do_lb").switch == "do_lb"
    assert NewEnvironment.of(made).placement["provider"] == "digitalocean"
    assert SlotAdd(confirm_cost="44.00").host_id is None
    assert EnvironmentDelete(drop_data=True, forget_vms=True).confirm_production is None
