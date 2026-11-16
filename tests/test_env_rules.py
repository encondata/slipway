"""Environment rules and the job queue (phase 3, tests 17-22 of §16.2): which slot a deploy goes to and whether
it goes live, the data owner, runner keys, typed names, what refuses a new environment, the queue's fences, the
chain hook, and the roll back and discard rules on shared data."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

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
    Repository,
    Snapshot,
)
from slipway.services import data, environments, jobs, manifest
from slipway.services.environments import CreateRefused, NewEnvironment
from tests.conftest import make_user

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = (ROOT / "docs/examples/serversherpa.slipway.yml").read_text()
MAN = manifest.parse(EXAMPLE)
MAN_JSON = MAN.to_json()
ENV_EXAMPLE = """\
STACK_ENV=CHANGEME
STACK_DOMAIN=CHANGEME
SS_SPACES_BUCKET=serversherpa
SS_JWT_SECRET=CHANGEME
"""
SHA = "0123456789abcdef0123456789abcdef01234567"
SHA2 = "fedcba9876543210fedcba9876543210fedcba98"
T0 = datetime(2026, 11, 15, 10, 0, tzinfo=UTC)
SETTINGS = {"STACK_DOMAIN": "uat.example.com", "STACK_PROXY_IP": "10.0.0.2"}
SECRETS = manifest.new_secrets(MAN, {})
ADDRESSES = {"blue": "10.0.0.11", "green": "10.0.0.12", "data": "10.0.0.13"}
ADMIN = {"fields": {"first_name": "Ada", "last_name": "Lovelace", "email": "ada@example.com"}, "mode": "password",
         "password": "correct-horse-battery"}


@dataclass
class Who:
    """A user stand-in with exactly ``perms`` (queue_job asks ``can`` and ``id``)."""

    perms: set[str] = field(default_factory=lambda: {"*"})
    id: uuid.UUID | None = None

    def can(self, permission: str) -> bool:
        return "*" in self.perms or permission in self.perms


@dataclass
class Ctx:
    user: Any = field(default_factory=Who)

    def can(self, permission: str) -> bool:
        return self.user.can(permission)


EVERYONE = Who()


def _live(slot: str, *, host_ports: dict[str, int] | None = None) -> dict[str, Any]:
    live: dict[str, Any] = {"release": f"{SHA[:12]}-11111111", "deployment": "11" * 16, "sha": SHA,
                            "settings": SETTINGS, "services": None, "projects": [], "volumes": [],
                            "host_ports": host_ports or {}}
    if slot == "data":
        live["clients"] = [ADDRESSES["blue"], ADDRESSES["green"]]
        live["host_ports"] = host_ports or {"spaces": 9000, "db": 5432}
    return {"manifest": MAN_JSON, "live": live, "routes": []}


async def _world(*, mode: str = "server", slots: tuple[str, ...] = ("blue", "green", "data"),
                 live: tuple[str, ...] = ("blue", "green", "data"), active: str | None = "blue",
                 pinned: bool = True, **env_fields: Any) -> dict[str, uuid.UUID]:
    """An environment ``uat`` with its hosts (10.0.0.11-13), instances and the Switchyard settings row."""
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=7, full_name="acme/serversherpa", owner="acme", name="serversherpa",
                          html_url="https://github.com/acme/serversherpa", detected_config={})
        db.add(repo)
        hosts = {s: Host(name=f"h-{s}", hostname=ADDRESSES[s], username="deploy",
                         host_key="ssh-ed25519 AAAA" if pinned else None, metrics={}) for s in ("blue", "green", "data")}
        db.add_all(hosts.values())
        db.add(AppSetting(key="switchyard", value={"url": "http://sy.lan", "default_tls_mode": "auto"},
                          secret="sy_" + "k" * 30))
        await db.flush()
        values = dict(name="uat", repository_id=repo.id, branch="main", data_mode=mode, app_settings=SETTINGS,
                      app_secrets=SECRETS, env={}, traffic={"switch": "switchyard", "dns": None}, status="live")
        values.update(env_fields)
        env = Environment(**values)
        db.add(env)
        await db.flush()
        ids: dict[str, uuid.UUID] = {"env": env.id, "repo": repo.id, **{f"host_{s}": h.id for s, h in hosts.items()}}
        for slot in slots:
            inst = Instance(name=f"uat {slot}", slug=f"uat-{slot}", repository_id=repo.id, host_id=hosts[slot].id,
                            branch="main", build_source="app", environment_id=env.id, slot=slot,
                            status="running" if slot in live else "created",
                            current_commit_sha=SHA if slot in live else None,
                            app_state=_live(slot) if slot in live else None,
                            live_identity={k: SECRETS[k] for k in MAN.identity_keys()}
                            if slot == environments.owner_slot(env) else None)
            db.add(inst)
            await db.flush()
            ids[slot] = inst.id
            if slot in live:
                db.add(Deployment(instance_id=inst.id, environment_id=env.id, kind="deploy", status="succeeded",
                                  branch="main", commit_sha=SHA, created_at=T0, finished_at=T0, options={"slot": slot}))
        if active:
            env.active_slot_id = ids[active]
        await db.commit()
        return ids


async def _load(db, ids) -> tuple[Environment, dict[str, Instance]]:
    env = await db.get(Environment, ids["env"], populate_existing=True)
    return env, await environments.members(db, env)


def _job(instance_id, env_id, kind="deploy", status="running", *, at=T0, **kw) -> Deployment:
    return Deployment(id=kw.pop("id", uuid.uuid4()), instance_id=instance_id, environment_id=env_id, kind=kind,
                      status=status, branch="main", commit_sha=kw.pop("commit_sha", SHA2), created_at=at,
                      finished_at=None if status in ("queued", "running") else at + timedelta(minutes=1),
                      steps=kw.pop("steps", []), **kw)


async def _set(db, model, row_id, **values) -> None:
    """Change a row in SQL (objects a rollback expired are never touched), and commit."""
    await db.execute(update(model).where(model.id == row_id).values(**values))
    await db.commit()


async def _count(db, model) -> int:
    return int(await db.scalar(select(func.count()).select_from(model)))


# ---------------------------------------------------------------- 17: target and go-live


def _members(*slots: str) -> dict[str, Instance]:
    return {s: Instance(id=uuid.uuid4(), slot=s, name=f"uat {s}", slug=f"uat-{s}") for s in slots}


def test_target_slot_and_goes_live():
    two = _members("blue", "green", "data")
    env = Environment(name="uat", data_mode="server", auto_activate=False)
    # Nothing active: blue, and it goes live.
    assert environments.target_slot(env, two) == "blue"
    assert environments.goes_live(env, "blue", two) and environments.goes_live(env, "green", two)
    # Blue active: the idle slot, and it waits for Activate unless auto_activate is on.
    env.active_slot_id = two["blue"].id
    assert environments.target_slot(env, two) == "green"
    assert not environments.goes_live(env, "green", two)
    env.auto_activate = True
    assert environments.goes_live(env, "green", two)
    env.active_slot_id = two["green"].id
    assert environments.target_slot(env, two) == "blue"
    # One app slot: always that slot; after it went live a deploy is in place, auto_activate or not.
    one = _members("blue", "data")
    single = Environment(name="solo", data_mode="server", auto_activate=True)
    assert environments.target_slot(single, one) == "blue" and environments.goes_live(single, "blue", one)
    single.active_slot_id = one["blue"].id
    assert environments.target_slot(single, one) == "blue"
    assert not environments.goes_live(single, "blue", one)
    # The data server never takes traffic.
    assert not environments.goes_live(env, "data", two)


# ------------------------------------------------- 18: owner, keys, typed names, shared data


async def test_owner_keys_confirm_name_and_shared_reason():
    ids = await _world()
    solo = await _world_slot()
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, ids)
        assert (await environments.owner_of(db, mem["blue"])).id == ids["data"]
        assert (await environments.owner_of(db, mem["data"])).id == ids["data"]
        assert (await environments.owner_of(db, env)).id == ids["data"]
        senv, smem = await _load(db, solo)
        assert (await environments.owner_of(db, smem["blue"])).id == solo["blue"]
        standalone = await _standalone(db)
        assert await environments.owner_of(db, standalone) is standalone

        # Runner keys (D8): the instance id alone outside environments.
        assert data.runner_keys(standalone, "deploy") == (standalone.id,)
        both = ((env.id, "data"), (env.id, "traffic"))
        assert data.runner_keys(mem["green"], "deploy") == both
        assert data.runner_keys(mem["data"], "restore") == both
        assert data.runner_keys(mem["blue"]) == both  # a change that isn't a job
        assert data.env_keys(env.id, "activate") == ((env.id, "traffic"),)
        assert data.runner_keys(mem["data"], "backup") == ((env.id, "data"),)
        assert data.runner_keys(mem["data"], "snapshot", {"stop_app": False}) == ((env.id, "data"),)
        assert data.runner_keys(mem["data"], "snapshot", {"stop_app": True}) == both
        assert data.env_keys(env.id, "teardown") == both and data.env_keys(env.id, "publish") == both
        assert not data.keys_meet(data.env_keys(env.id, "activate"), data.env_keys(env.id, "backup"))

        # Typed names: the environment's for a member.
        assert data.confirm_name(mem["data"]) == "uat" and data.confirm_name(mem["blue"]) == "uat"
        assert data.confirm_name(standalone) == "shop"

        # Shared data: an app slot in mode server answers the text; the owner and mode slot answer as phase 2.
        assert data.data_shared_reason(mem["green"], owner=mem["data"]) == (
            "uat's data is shared by its slots and lives on h-data: back it up, restore or reset it from the "
            "environment page")
        assert "lives on its data server" in data.data_shared_reason(mem["green"])
        assert data.data_shared_reason(mem["data"]) is None
        assert data.data_shared_reason(smem["blue"]) is None
        smem["blue"].app_state = {**smem["blue"].app_state,
                                  "live": {**smem["blue"].app_state["live"], "data_elsewhere": True}}
        assert "outside h-solo" in data.data_shared_reason(smem["blue"])
        assert data.data_shared_reason(standalone) is None


async def _world_slot(**kw: Any) -> dict[str, uuid.UUID]:
    """A single-slot environment ``solo`` (mode slot) of its own repository."""
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=8, full_name="acme/solo", owner="acme", name="solo",
                          html_url="https://github.com/acme/solo", detected_config={})
        host = Host(name="h-solo", hostname="10.0.0.21", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
        db.add_all([repo, host])
        await db.flush()
        env = Environment(name="solo", repository_id=repo.id, branch="main", data_mode="slot", app_settings=SETTINGS,
                          app_secrets=SECRETS, traffic={"switch": "none", "dns": None}, status="live", **kw)
        db.add(env)
        await db.flush()
        blue = Instance(name="solo blue", slug="solo-blue", repository_id=repo.id, host_id=host.id, branch="main",
                        build_source="app", environment_id=env.id, slot="blue", status="running",
                        current_commit_sha=SHA, app_state=_live("blue"))
        db.add(blue)
        await db.flush()
        env.active_slot_id = blue.id
        await db.commit()
        return {"env": env.id, "blue": blue.id}


async def _standalone(db) -> Instance:
    repo = Repository(github_id=9, full_name="acme/shop", owner="acme", name="shop",
                      html_url="https://github.com/acme/shop", detected_config={})
    host = Host(name="prod-01", hostname="10.0.0.1", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
    inst = Instance(name="shop", slug="shop", branch="main", host=host, repository=repo, build_source="app",
                    status="running", current_commit_sha=SHA, app_state=_live("blue"))
    db.add(inst)
    await db.commit()
    return await db.get(Instance, inst.id, populate_existing=True)


async def test_data_values_plan_identity_and_attach_problems():
    ids = await _world()
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, ids)
        owner = mem["data"]
        values = environments.data_values(env, owner, MAN, template=ENV_EXAMPLE)
        assert values["db"] == {"host": "10.0.0.13", "port": "5432", "database": "serversherpa", "user": "serversherpa",
                                "password": SECRETS["POSTGRES_PASSWORD"], "tls": "disable", "ca_b64": ""}
        assert values["objects"]["endpoint"] == "https://spaces.uat.example.com"
        assert values["objects"]["secret_key"] == SECRETS["SPACES_SECRET_KEY"]
        # A data server that moved ports serves the slots on its live ports.
        owner.app_state = {**owner.app_state, "live": {**owner.app_state["live"], "host_ports": {"db": 5433,
                                                                                                    "spaces": 9001}}}
        assert environments.data_values(env, owner, MAN, template=ENV_EXAMPLE)["db"]["port"] == "5433"

        # The identity values of the server role: blank in its .env, the environment's in plan_identity.
        plan = manifest.plan(MAN, template=ENV_EXAMPLE, builtins=environments.owner_builtins(env, owner,
                                                                                            owner.app_state["live"]),
                             settings=SETTINGS, chosen=None, host_ports={}, secrets=SECRETS, env={}, role="server",
                             server_values={"host": "10.0.0.13", "clients": ["10.0.0.11"]})
        keys = MAN.identity_keys()
        assert data.rendered_identity(plan.env, keys) == {k: "" for k in keys}
        assert data.plan_identity(plan, keys) == {k: SECRETS[k] for k in keys}
        app = manifest.plan(MAN, template=ENV_EXAMPLE, builtins=environments.owner_builtins(env, owner,
                                                                                           owner.app_state["live"]),
                            settings=SETTINGS, chosen=None, host_ports={}, secrets=SECRETS, env={})
        assert data.plan_identity(app, keys) == data.rendered_identity(app.env, keys)

        # The refusals a slot deploy meets before it is queued (§6).
        assert environments.attach_problem(env, owner, mem["green"]) is None
        assert environments.attach_problem(env, owner, mem["data"]) is None
        owner.app_state = {**owner.app_state, "live": {**owner.app_state["live"], "clients": ["10.0.0.11"]}}
        assert environments.attach_problem(env, owner, mem["green"]) == (
            "uat's data server doesn't let h-green (10.0.0.12) in yet: update the data server first "
            "(Deploy → Data server)")
        mem["green"].host.lan_address = None
        mem["green"].host.hostname = "green.lan"
        assert environments.attach_problem(env, owner, mem["green"]) == (
            "Host h-green's address is green.lan; uat's data server lets clients in by IP address: set the host's "
            "LAN address (or proxy address) to its IP")
        mem["green"].host.lan_address = "10.0.0.11"  # a multi-homed host: its LAN address counts
        assert environments.attach_problem(env, owner, mem["green"]) is None
        owner.app_state = {"manifest": MAN_JSON}
        assert environments.attach_problem(env, owner, mem["blue"]) == (
            "Deploy uat's data server first: the app slots need its address and ports")
        with pytest.raises(environments.DataValuesError, match="Deploy uat's data server first"):
            environments.data_values(env, owner, MAN, template=ENV_EXAMPLE)


# ---------------------------------------------------------------- 19: create refusals


def _reader(files: dict[str, str | None], seen: list[str] | None = None):
    async def read(repo, branch, path):
        if seen is not None:
            seen.append(path)
        return files.get(path)

    return read


FILES = {"slipway.yml": EXAMPLE, "deploy/stack/env.example": ENV_EXAMPLE}


def _request(ids, **kw) -> NewEnvironment:
    values: dict[str, Any] = dict(name="prod", repository_id=ids["repo"], data_mode="server",
                                  hosts={"blue": ids["host_blue"], "green": ids["host_green"], "data": ids["host_data"]},
                                  settings={"STACK_DOMAIN": "prod.example.com", "STACK_PROXY_IP": "10.0.0.2"},
                                  traffic={"switch": "switchyard", "dns": None}, first_admin=ADMIN)
    values.update(kw)
    return NewEnvironment(**values)


async def _refused(db, request, *, files=None, ctx=None) -> CreateRefused:
    with pytest.raises(CreateRefused) as err:
        await environments.validate_create(db, request, ctx or Ctx(), read_file=_reader(FILES if files is None else files))
    return err.value


async def test_validate_create_refusals_and_the_check():
    ids = await _world(slots=("blue", "green", "data"))
    async with get_sessionmaker()() as db:
        before = (await _count(db, Environment), await _count(db, Instance), await _count(db, Deployment))

        # 1. The name: the pattern (27 characters is one too many), a live environment, a reserved slug.
        err = await _refused(db, _request(ids, name="a" * 27))
        assert (err.status, err.detail, err.field) == (422, environments.NAME_RULE, "name")
        assert (await _refused(db, _request(ids, name="Prod"))).status == 422
        err = await _refused(db, _request(ids, name="uat"))
        assert (err.status, err.detail, err.field) == (409, "An environment named uat already exists", "name")
        db.add(Instance(name="Old green", slug="prod-green", repository_id=ids["repo"], host_id=ids["host_blue"],
                        branch="main"))
        await db.commit()
        err = await _refused(db, _request(ids))
        assert (err.status, err.detail) == (409, "Instance Old green already uses the slug prod-green; pick another name")
        await db.execute(Instance.__table__.delete().where(Instance.slug == "prod-green"))
        await db.commit()
        before = (await _count(db, Environment), await _count(db, Instance), await _count(db, Deployment))

        # 2. The repository's slipway.yml.
        err = await _refused(db, _request(ids), files={})
        assert (err.status, err.detail, err.field) == (409, "acme/serversherpa has no slipway.yml at main", "manifest_file")
        err = await _refused(db, _request(ids), files={"slipway.yml": "version: 1\nname: x\nnonsense: 1\n"})
        assert err.status == 409 and err.detail.startswith("slipway.yml") and err.field == "manifest_file"

        # 3. The shape.
        no_migrations = EXAMPLE.replace("  migrations: expand_contract\n", "")
        err = await _refused(db, _request(ids), files={**FILES, "slipway.yml": no_migrations})
        assert err.detail == ("acme/serversherpa's slipway.yml at main doesn't declare data.migrations: expand_contract. "
                              "With two slots, blue keeps running on the database green migrates, so its migrations "
                              "must add before they remove.") and err.field == "data_mode"
        no_server = EXAMPLE[:EXAMPLE.index("  # The data server:")] + EXAMPLE[EXAMPLE.index("\ncommands:"):]
        err = await _refused(db, _request(ids), files={**FILES, "slipway.yml": no_server})
        assert err.detail == ("acme/serversherpa's slipway.yml doesn't describe a data server (data.server), so "
                              "Slipway can't run two slots on one set of data")
        err = await _refused(db, _request(ids, data_mode="slot", hosts={"blue": ids["host_blue"],
                                                                        "green": ids["host_green"]}))
        assert (err.status, err.field) == (409, "data_mode")

        # 4. The hosts: pinned, IP addresses for a data server's clients, a data server of its own.
        green = await db.get(Host, ids["host_green"])
        green.host_key = None
        await db.commit()
        err = await _refused(db, _request(ids))
        assert (err.status, err.detail, err.field) == (
            409, "Check host h-green first: Slipway hasn't verified its key", "hosts.green")
        green.host_key, green.hostname = "ssh-ed25519 AAAA", "green.lan"
        await db.commit()
        err = await _refused(db, _request(ids))
        assert err.detail == ("Host h-green's address is green.lan; prod's data server lets clients in by IP address: "
                              "set the host's LAN address (or proxy address) to its IP") and err.field == "hosts.green"
        green.hostname = "10.0.0.12"
        await db.commit()
        err = await _refused(db, _request(ids, hosts={"blue": ids["host_blue"], "green": ids["host_green"],
                                                      "data": ids["host_blue"]}))
        assert (err.status, err.field) == (409, "hosts.data")
        assert err.detail == ("The data server needs a host of its own: a container on h-blue reaches its database "
                              "from a Docker address, which prod's data server can't let in by host address")

        # 5. Settings and variables.
        err = await _refused(db, _request(ids, settings={"STACK_PROXY_IP": "10.0.0.2"}))
        assert (err.status, err.field) == (422, "settings") and "Base domain (STACK_DOMAIN)" in err.detail
        err = await _refused(db, _request(ids, env={"STACK_DB_HOST": "elsewhere"}))
        assert (err.status, err.field) == (422, "env") and "STACK_DB_HOST" in err.detail

        # 6. The names.
        db.add(Instance(name="shop", slug="shop", repository_id=ids["repo"], host_id=ids["host_blue"], branch="main",
                        routes=[{"hostname": "api.prod.example.com", "service": None, "container": 80}]))
        await db.commit()
        err = await _refused(db, _request(ids))
        assert (err.status, err.detail, err.field) == (
            409, "api.prod.example.com is already a hostname of instance shop", "hostnames")
        env = await db.get(Environment, ids["env"])
        env.hostnames = [{"hostname": "portal.uat.example.com", "follows": "active"}]
        await db.commit()
        err = await _refused(db, _request(ids, name="other", settings=SETTINGS))
        assert err.detail == "portal.uat.example.com is already a hostname of environment uat"
        await db.execute(Instance.__table__.delete().where(Instance.slug == "shop"))
        await db.commit()

        # 7. Traffic.
        err = await _refused(db, _request(ids, traffic={"switch": "none", "dns": None}))
        assert (err.status, err.field) == (409, "traffic")
        err = await _refused(db, _request(ids, traffic={"switch": "switchyard", "dns": {"proxied": False}}))
        assert (err.status, err.detail, err.field) == (409, environments.SET_UP_CLOUDFLARE, "traffic.dns")
        db.add(AppSetting(key="cloudflare", value={"zone": "example.org", "zone_id": "z1", "public_ip": "203.0.113.10"},
                          secret="t" * 40))
        await db.commit()
        err = await _refused(db, _request(ids, traffic={"switch": "switchyard", "dns": {}}))
        assert err.detail == "api.prod.example.com isn't in the Cloudflare zone example.org"
        sy = await db.scalar(select(AppSetting).where(AppSetting.key == "switchyard"))
        await db.delete(sy)
        await db.commit()
        err = await _refused(db, _request(ids))
        assert (err.status, err.detail) == (409, environments.SET_UP_SWITCHYARD)
        db.add(AppSetting(key="switchyard", value={"url": "http://sy.lan"}, secret="sy_" + "k" * 30))
        await db.commit()

        # 8. The seed snapshot and the first admin.
        snap = Snapshot(name="uat-1", status="ready", origin="instance", app="serversherpa", repository="acme/serversherpa",
                        identity_keys=MAN.identity_keys(), file_sha256="a" * 64, db_sha256="b" * 64)
        db.add(snap)
        await db.commit()
        err = await _refused(db, _request(ids, seed_snapshot_id=snap.id), ctx=Ctx(Who({"environments:write"})))
        assert (err.status, err.field) == (403, "seed_snapshot_id")
        err = await _refused(db, _request(ids, first_admin=None))
        assert (err.status, err.detail, err.field) == (422, "Enter the first admin", "first_admin")
        err = await _refused(db, _request(ids, first_admin={**ADMIN, "password": "short"}))
        assert (err.status, err.field) == (422, "first_admin")

        # Nothing was written by any refusal.
        assert (await _count(db, Environment), await _count(db, Instance), await _count(db, Deployment)) == before

        # ?check=true: the plan and the warnings (two app slots on one host), still nothing written.
        seen: list[str] = []
        plan = await environments.validate_create(
            db, _request(ids, hosts={"blue": ids["host_blue"], "green": ids["host_blue"], "data": ids["host_data"]}),
            Ctx(), read_file=_reader(FILES, seen))
        assert seen == ["slipway.yml", "deploy/stack/env.example"]
        out = plan.to_json()
        assert out["ok"] and out["warnings"] == [
            "Blue and green both run on h-blue: a problem with that host stops both, and Switch back can't help with it"]
        assert out["plan"]["slots"]["data"] == {"host_id": str(ids["host_data"]), "host": "h-data", "role": "data",
                                                "slug": "prod-data"}
        assert out["plan"]["secrets"] == sorted(MAN.secret_keys())
        names = {h["hostname"]: h for h in out["plan"]["hostnames"]}
        assert names["spaces.prod.example.com"]["follows"] == "server"
        assert names["api.prod.example.com"] == {"hostname": "api.prod.example.com", "service": "api",
                                                 "container": 8000, "follows": "active", "health": "/healthz"}
        assert names["portal.prod.example.com"]["health"] == "/"
        assert not any(s in str(out) for s in plan.secrets.values())
        assert (await _count(db, Environment), await _count(db, Instance), await _count(db, Deployment)) == before


async def test_create_writes_the_environment_its_slots_and_the_owner_fields():
    ids = await _world()
    async with get_sessionmaker()() as db:
        plan = await environments.validate_create(db, _request(ids, keep_backups=9, seed_content=False), Ctx(),
                                                  read_file=_reader(FILES))
        env = await environments.create(db, plan, Ctx())
        await db.commit()
        env = await db.get(Environment, env.id, populate_existing=True)
        mem = await environments.members(db, env)
        assert env.status == "new" and env.data_mode == "server" and env.secrets_version == 0
        assert set(env.app_secrets) == MAN.secret_keys() and env.traffic == {"switch": "switchyard", "dns": None}
        assert {s: m.slug for s, m in mem.items()} == {"blue": "prod-blue", "green": "prod-green", "data": "prod-data"}
        assert all(m.status == "created" and m.app_secrets is None and m.build_source == "app" for m in mem.values())
        assert mem["data"].keep_backups == 9 and mem["data"].seed_content is False
        assert mem["blue"].keep_backups == 5  # an app slot leaves the owner's fields at their defaults
        admin = await db.scalar(select(FirstAdmin).where(FirstAdmin.instance_id == mem["data"].id))
        assert admin is not None and admin.mode == "password"
        event = await db.scalar(select(AuditEvent).where(AuditEvent.action == "environment.create"))
        assert event.details["slots"] == {"blue": "h-blue", "green": "h-green", "data": "h-data"}
        assert event.details["first_admin"] == "ada@example.com"
        assert not any(v in str(event.details) for v in env.app_secrets.values())
        assert "correct-horse-battery" not in str(event.details)
        # The slugs are now reserved, slot or not.
        found = await environments.reserved_slug(db, "prod-green")
        assert found is not None and found[0].id == env.id and found[1] == "green"
        assert environments.reserved_text("prod-green", *found) == "prod-green is reserved for environment prod's green slot"
        assert await environments.reserved_slug(db, "prod-staging") is None
        assert await environments.reserved_slug(db, "nope-blue") is None


# ---------------------------------------------------------------- 20: the queue's fences


async def _refusal(db, **kw) -> jobs.JobRefused:
    with pytest.raises(jobs.JobRefused) as err:
        await jobs.queue_job(db, user=kw.pop("user", EVERYONE), **kw)
    await db.rollback()
    return err.value


async def test_queue_job_fences():
    ids = await _world()
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, ids)

        # Busy: a deploy to green holds both keys; the text names the kind and the slot.
        running = _job(ids["green"], env.id, "deploy", options={"slot": "green"})
        running_id = running.id
        db.add(running)
        await db.commit()
        env, mem = await _load(db, ids)
        err = await _refusal(db, instance=mem["data"], kind="backup")
        assert (err.status, err.text) == (409, "A job is already running for uat (Deploy on green); wait for it to "
                                               "finish")
        # An activate (the traffic key only) is refused beside a deploy too.
        env, mem = await _load(db, ids)
        assert (await _refusal(db, environment=env, kind="activate", options={"slot": "green"})).status == 409
        await _set(db, Deployment, running_id, status="succeeded", finished_at=T0)

        # An activate queues beside a running Back up now, and beside a snapshot that doesn't stop the app.
        backup = _job(ids["data"], ids["env"], "backup")
        backup_id = backup.id
        db.add(backup)
        await db.commit()
        await _set(db, Environment, ids["env"], active_slot_id=ids["green"])  # blue is idle, deployed and running
        env, mem = await _load(db, ids)
        act = await jobs.queue_job(db, environment=env, user=EVERYONE, kind="activate", options={"slot": "blue"})
        assert act.instance_id is None and act.environment_id == env.id and act.commit_sha == SHA
        assert act.options["from_slot"] == "green"
        assert [s["key"] for s in act.steps] == ["check", "smoke", "switch"]
        assert act.steps[2]["name"] == "Switch traffic to blue"
        await db.rollback()
        await _set(db, Deployment, backup_id, status="succeeded", finished_at=T0)
        snap = _job(ids["data"], ids["env"], "snapshot", options={"stop_app": False})
        snap_id = snap.id
        db.add(snap)
        await db.commit()
        env, mem = await _load(db, ids)
        await jobs.queue_job(db, environment=env, user=EVERYONE, kind="activate", options={"slot": "blue"})
        await db.rollback()
        # ...but not beside a snapshot that stops the app, nor beside a restore.
        await _set(db, Deployment, snap_id, options={"stop_app": True})
        env, mem = await _load(db, ids)
        assert "(Take snapshot on the data server)" in (await _refusal(db, environment=env, kind="activate",
                                                                       options={"slot": "blue"})).text
        await _set(db, Deployment, snap_id, kind="restore", options={})
        env, mem = await _load(db, ids)
        assert "(Restore on the data server)" in (await _refusal(db, environment=env, kind="activate",
                                                                 options={"slot": "blue"})).text
        await _set(db, Deployment, snap_id, status="failed", finished_at=T0)
        await _set(db, Environment, ids["env"], active_slot_id=ids["blue"])

        # An unpinned host.
        await _set(db, Host, ids["host_green"], host_key=None)
        env, mem = await _load(db, ids)
        err = await _refusal(db, instance=mem["green"], kind="deploy")
        assert (err.status, err.text) == (400, "Host h-green has not been verified yet; run a connection check first")
        await _set(db, Host, ids["host_green"], host_key="ssh-ed25519 AAAA")

        # A deploy queues with the slot and whether it goes live; it can't go live without traffic:switch.
        env, mem = await _load(db, ids)
        dep = await jobs.queue_job(db, instance=mem["green"], user=EVERYONE, kind="deploy")
        assert dep.environment_id == env.id and dep.options == {"slot": "green", "go_live": False}
        # The queued steps are the member's (§8.4), not phase 2's: smoke and traffic in place of proxy.
        keys = [s["key"] for s in dep.steps]
        assert keys[-3:] == ["finish", "smoke", "traffic"] and "proxy" not in keys, keys
        await db.rollback()
        await _set(db, Environment, ids["env"], auto_activate=True)
        env, mem = await _load(db, ids)
        err = await _refusal(db, instance=mem["green"], kind="deploy", user=Who({"deployments:create"}))
        assert (err.status, err.text) == (403, "Deploying green makes it live, which needs the traffic:switch "
                                               "permission")
        env, mem = await _load(db, ids)
        dep = await jobs.queue_job(db, instance=mem["green"], user=Who({"deployments:create", "traffic:switch"}),
                                   kind="deploy")
        assert dep.options["go_live"] is True
        await db.rollback()
        # The active slot of two is never deployed to.
        env, mem = await _load(db, ids)
        assert (await _refusal(db, instance=mem["blue"], kind="deploy")).text == (
            "blue serves traffic: deploy to green, then activate it")

        # The data owner's hold refuses deploys to any member, activate and control start; not a restore.
        failed = _job(ids["data"], ids["env"], "restore", "failed",
                      steps=[{"key": "restore", "name": "Restore", "status": "failed"}])
        dirty = data.mark_dirty(None, failed, step="restore", at=T0)
        db.add(failed)
        await db.commit()
        await _set(db, Instance, ids["data"], data_dirty=dirty)
        await _set(db, Environment, ids["env"], active_slot_id=ids["green"])
        env, mem = await _load(db, ids)
        held = await data.hold_text(db, mem["green"])
        assert held.startswith("uat's last restore stopped part-way")
        assert (await _refusal(db, instance=mem["blue"], kind="deploy")).text == held
        env, mem = await _load(db, ids)
        assert (await _refusal(db, instance=mem["data"], kind="deploy")).text == held
        env, mem = await _load(db, ids)
        assert (await _refusal(db, environment=env, kind="activate", options={"slot": "blue"})).text == held
        env, mem = await _load(db, ids)
        assert await jobs.control_refusal(db, mem["blue"], "start") == held
        assert await jobs.control_refusal(db, mem["blue"], "stop") is None
        await jobs.queue_job(db, instance=mem["data"], user=EVERYONE, kind="restore")
        await db.rollback()

        # Dirty but not held: activate is refused...
        dirty_deploy = _job(ids["blue"], ids["env"], "deploy", "failed", at=T0 + timedelta(minutes=1),
                            steps=[{"key": "start", "name": "Start", "status": "failed"}])
        dirty, d8 = data.mark_dirty(None, dirty_deploy, step="start", at=T0), dirty_deploy.id.hex[:8]
        db.add(dirty_deploy)
        await db.commit()
        await _set(db, Instance, ids["data"], data_dirty=dirty)
        env, mem = await _load(db, ids)
        err = await _refusal(db, environment=env, kind="activate", options={"slot": "blue"})
        assert err.text == (f"uat's data may not be what blue expects since deployment {d8} failed: "
                            "discard or retry it first")
        # ...except of the recorded active slot while a switch is unresolved, which restores the known state.
        await _set(db, Environment, ids["env"], traffic_state={
            "unresolved": {"deployment_id": "ab" * 16, "message": "Slipway restarted during the switch"}})
        env, mem = await _load(db, ids)
        assert (await _refusal(db, environment=env, kind="activate", options={"slot": "blue"})).status == 409
        env, mem = await _load(db, ids)
        await jobs.queue_job(db, environment=env, user=EVERYONE, kind="activate", options={"slot": "green"})
        await db.rollback()
        await _set(db, Instance, ids["data"], data_dirty=None)

        # An unresolved switch: slot deploys, remove_slot and restore kinds refused; the rest allowed.
        env, mem = await _load(db, ids)
        unresolved = environments.unresolved_text(env)
        assert unresolved == ("Traffic of uat may be split between its slots since deployment abababab (Slipway "
                              "restarted during the switch). Activate a slot, or use Resolve once Switchyard is right")
        assert (await _refusal(db, instance=mem["blue"], kind="deploy")).text == unresolved
        env, mem = await _load(db, ids)
        assert (await _refusal(db, environment=env, kind="remove_slot", options={"slot": "blue"})).text == unresolved
        env, mem = await _load(db, ids)
        assert (await _refusal(db, instance=mem["data"], kind="restore")).text == unresolved
        for kw in ({"slot": "data", "kind": "deploy"}, {"slot": "data", "kind": "backup"}, {"kind": "publish"},
                   {"kind": "activate", "options": {"slot": "green"}}):
            env, mem = await _load(db, ids)
            target = {"instance": mem[kw.pop("slot")]} if "slot" in kw else {"environment": env}
            queued = await jobs.queue_job(db, user=EVERYONE, **target, **kw)
            assert queued.id is not None
            await db.rollback()
        await _set(db, Environment, ids["env"], traffic_state={})

        # A deleting environment refuses everything but its teardown's retry.
        await _set(db, Environment, ids["env"], status="deleting")
        env, mem = await _load(db, ids)
        assert (await _refusal(db, instance=mem["data"], kind="backup")).text == (
            "uat is being deleted: only its teardown's retry can run")
        env, mem = await _load(db, ids)
        assert (await _refusal(db, environment=env, kind="teardown")).status == 409


async def test_queue_job_for_standalone_instances_is_unchanged():
    async with get_sessionmaker()() as db:
        inst = await _standalone(db)
        dep = await jobs.queue_job(db, instance=inst, user=EVERYONE, kind="deploy")
        assert dep.environment_id is None and dep.options == {}
        assert [s["key"] for s in dep.steps] == ["resolve", "source", "upload", "manifest", "ports", "settings",
                                                 "build", "backup", "start", "finish", "proxy"]
        await db.commit()
        err = await _refusal(db, instance=await db.get(Instance, inst.id), kind="backup")
        assert (err.status, err.text) == (409, "A job is already running for this instance (Deploy); wait for it to "
                                               "finish")


# ---------------------------------------------------------------- 21: the chain


async def test_after_job_chains_once_and_records_refusals():
    ids = await _world(live=("data",), active=None, status="new")
    submitted: list[tuple[uuid.UUID, tuple]] = []

    def submit(dep_id, keys):
        submitted.append((dep_id, keys))

    async with get_sessionmaker()() as db:
        env, mem = await _load(db, ids)
        user_id = (await make_user("admin@example.com")).id  # the first user is an admin
        server = _job(ids["data"], env.id, "deploy", "succeeded", options={"slot": "data", "chain": True},
                      triggered_by_id=user_id)
        failed = _job(ids["data"], env.id, "deploy", "failed", options={"slot": "data", "chain": True},
                      at=T0 + timedelta(minutes=1))
        server_id, failed_id = server.id, failed.id
        db.add_all([server, failed])
        await db.commit()
    # Failures queue nothing.
    assert await environments.after_job(failed_id, submit=submit) is None
    # The data server's first deploy queues blue's, which goes live; called twice, it queues once.
    first = await environments.after_job(server_id, submit=submit)
    again = await environments.after_job(server_id, submit=submit)
    assert first is not None and again == first and len(submitted) == 1
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, ids)
        blue = await db.get(Deployment, first)
        assert blue.instance_id == ids["blue"] and blue.kind == "deploy"
        assert blue.options == {"chain": True, "go_live": True, "slot": "blue", "after": server_id.hex}
        assert submitted[0] == (blue.id, ((env.id, "data"), (env.id, "traffic")))
        # Blue's deploy with go_live succeeds: an activate of blue.
        blue.status, blue.finished_at = "succeeded", T0
        mem["blue"].current_commit_sha, mem["blue"].status = SHA, "running"
        mem["blue"].app_state = _live("blue")
        blue_id = blue.id
        await db.commit()
    activate = await environments.after_job(blue_id, submit=submit)
    async with get_sessionmaker()() as db:
        act = await db.get(Deployment, activate)
        assert act.kind == "activate" and act.instance_id is None and act.options["slot"] == "blue"
        assert act.options["chain"] and act.options["after"] == blue_id.hex
        assert submitted[-1] == (act.id, ((ids["env"], "traffic"),))
        # The first activation lists seed after the switch (D24).
        assert [s["key"] for s in act.steps] == ["check", "smoke", "switch", "seed"]
        act.status, act.finished_at = "succeeded", T0
        await db.commit()
        # A snapshot with then=teardown queues the teardown, its typed name checked, and the environment is deleting.
        snap = _job(ids["data"], ids["env"], "snapshot", "succeeded", options={"then": "teardown"},
                    at=T0 + timedelta(minutes=5), triggered_by_id=user_id)
        snap_id = snap.id
        db.add(snap)
        await db.commit()
    teardown = await environments.after_job(snap_id, submit=submit)
    async with get_sessionmaker()() as db:
        td = await db.get(Deployment, teardown)
        assert td.kind == "teardown" and td.options["confirmed"] is True
        assert [s["key"] for s in td.steps] == ["check", "unroute", "undns", "slots", "data_server", "forget"]
        assert (await db.get(Environment, ids["env"])).status == "deleting"


async def test_a_refused_follow_up_leaves_the_notice_and_shutdown_writes_its_own():
    ids = await _world(live=("data",), active=None, status="new")
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, ids)
        server = _job(ids["data"], env.id, "deploy", "succeeded", options={"slot": "data", "chain": True})
        server_id = server.id
        db.add(server)
        mem["blue"].host.host_key = None  # blue's host can't be used: the follow-up is refused
        await db.commit()
    assert await environments.after_job(server_id, submit=lambda *a: pytest.fail("nothing to submit")) is None
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, ids["env"])
        assert env.notice["text"] == ("Deploy to blue didn't start after Update the data server succeeded: Host h-blue "
                                      "has not been verified yet; run a connection check first")
        assert env.notice["next"] == {"kind": "deploy", "slot": "blue"} and env.notice["deployment_id"] == server_id.hex
        event = await db.scalar(select(AuditEvent).where(AuditEvent.action == "environment.chain_stopped"))
        assert event.details["why"] == "refused" and event.details["finished"] == server_id.hex
        assert await _count(db, Deployment) == 2  # the data server's two deploys, and nothing queued
        env.notice = None
        await db.commit()
    # A success recorded while Slipway was shutting down queues nothing and says so.
    assert await environments.chain_notice(server_id, why="shutdown")
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, ids["env"])
        assert env.notice["text"] == "Slipway stopped after Update the data server succeeded, before it started Deploy to blue"
        assert await db.scalar(select(func.count()).select_from(Deployment).where(Deployment.kind == "deploy",
                                                                                 Deployment.instance_id == ids["blue"])) == 0
        # A queued follow-up clears the notice.
        env, mem = await _load(db, ids)
        mem["blue"].host.host_key = "ssh-ed25519 AAAA"
        await db.commit()
        env, mem = await _load(db, ids)
        await jobs.queue_job(db, instance=mem["blue"], user=EVERYONE, kind="deploy", options={"chain": True})
        assert env.notice is None


# ------------------------------------------- 22: latest job, roll back, discard, field routing


async def _failed_green(db, ids, *, active: str | None = "blue") -> Deployment:
    """Green's deploy failed after its start began: the owner is dirty, with green's pre-deploy backup."""
    env, mem = await _load(db, ids)
    dep = _job(ids["green"], env.id, "deploy", "failed", at=T0 + timedelta(hours=1),
               steps=[{"key": "start", "name": "Start", "status": "failed"}])
    db.add(dep)
    await db.flush()
    bid = uuid.uuid4()
    identity = dict(mem["data"].live_identity)
    backup = Backup(id=bid, instance_id=ids["data"], deployment_id=dep.id, name=data.backup_name(bid, T0),
                    reason="pre_deploy", status="ready", format="pg-custom", db_bytes=10,
                    identity_keys=sorted(identity), identity=identity, identity_fp=data.identity_fp(bid, identity, identity),
                    taken_at=T0)
    db.add(backup)
    dep.backup_id = bid
    await db.flush()
    mem["data"].data_dirty = data.mark_dirty(None, dep, step="start", at=T0)
    env.active_slot_id = ids[active] if active else None
    await db.commit()
    return dep


async def test_latest_job_and_roll_back_read_the_owner():
    ids = await _world()
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, ids)
        server = _job(ids["data"], env.id, "deploy", "succeeded", at=T0 + timedelta(minutes=30))
        db.add(server)
        await db.commit()
        env, mem = await _load(db, ids)
        assert (await data.latest_changing_job(db, mem["blue"])).id == server.id
        assert (await data.latest_changing_job(db, ids["green"])).id == server.id
        failed = await _failed_green(db, ids)
        env, mem = await _load(db, ids)
        assert (await data.latest_changing_job(db, mem["blue"])).id == failed.id

        roll = await data.rollback_state(db, failed)
        assert roll.available and roll.needs_reset and roll.owner_id == ids["data"]
        assert roll.backup.instance_id == ids["data"]
        # No active slot other than the failed one: refused.
        env.active_slot_id = None
        await db.commit()
        assert (await data.rollback_state(db, failed)).reason.startswith("Nothing is live to start again")
        env, mem = await _load(db, ids)
        env.active_slot_id = ids["green"]
        await db.commit()
        assert not (await data.rollback_state(db, failed)).available
        # A later job anywhere in the environment makes it not the latest.
        env, mem = await _load(db, ids)
        env.active_slot_id = ids["blue"]
        db.add(_job(ids["blue"], env.id, "admin", "succeeded", at=T0 + timedelta(hours=2)))
        await db.commit()
        assert "ran after this deployment" in (await data.rollback_state(db, failed)).reason

    # Mode slot: phase 2's rules on the slot itself, without data:reset.
    solo = await _world_slot()
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, solo)
        blue = mem["blue"]
        dep = _job(blue.id, env.id, "deploy", "failed", steps=[{"key": "start", "name": "Start", "status": "failed"}])
        db.add(dep)
        await db.flush()
        bid = uuid.uuid4()
        blue.live_identity = {k: SECRETS[k] for k in MAN.identity_keys()}
        db.add(Backup(id=bid, instance_id=blue.id, name=data.backup_name(bid, T0), reason="pre_deploy", status="ready",
                      format="pg-custom", db_bytes=10, identity_keys=sorted(blue.live_identity), identity=blue.live_identity,
                      identity_fp=data.identity_fp(bid, blue.live_identity, blue.live_identity), taken_at=T0))
        dep.backup_id = bid
        await db.flush()
        blue.data_dirty = data.mark_dirty(None, dep, step="start", at=T0)
        await db.commit()
        roll = await data.rollback_state(db, dep)
        assert roll.available and not roll.needs_reset and roll.owner_id == blue.id


async def test_discard_state():
    ids = await _world()
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, ids)
        assert (await data.discard_state(db, env, "green")).reason == "green has no failed deploy to discard"
        failed = await _failed_green(db, ids)
        env, mem = await _load(db, ids)
        state = await data.discard_state(db, env)
        assert state.available and state.slot == "green" and state.deployment_id == failed.id.hex
        assert tuple(state) == (True, None)
        assert (await data.discard_state(db, env, "blue")).reason == "blue has no failed deploy to discard"
        # Refused under the hold, and when the dirty state names another job.
        restore = _job(ids["data"], env.id, "restore", "failed", at=T0 + timedelta(hours=2))
        db.add(restore)
        await db.flush()
        mem["data"].data_dirty = data.mark_dirty(mem["data"].data_dirty, restore, step="restore", at=T0)
        await db.commit()
        env, mem = await _load(db, ids)
        assert (await data.discard_state(db, env)).reason == await data.hold_text(db, mem["data"])
        mem["data"].data_dirty = data.mark_dirty(None, restore, step="stop", at=T0)
        await db.commit()
        env, mem = await _load(db, ids)
        assert (await data.discard_state(db, env, "green")).reason == "green has no failed deploy to discard"
        # Green is active: nothing to check the data with but the failed slot itself.
        await _failed_green(db, ids, active="green")
        env, mem = await _load(db, ids)
        assert (await data.discard_state(db, env, "green")).reason.startswith("green takes the traffic")
        await _failed_green(db, ids, active=None)
        env, mem = await _load(db, ids)
        assert (await data.discard_state(db, env, "green")).reason == (
            "Nothing is live to check the data with: roll back or retry")
        # The queue asks the same.
        assert (await _refusal(db, environment=env, kind="discard", options={"slot": "green"})).text == (
            "Nothing is live to check the data with: roll back or retry")
    one = await _world_slot()
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, one)
        assert (await data.discard_state(db, env, "blue")).reason == "Roll back or retry instead: blue is solo's only slot"


def test_owner_writes_routes_the_fields():
    server = Environment(name="uat", data_mode="server")
    solo = Environment(name="solo", data_mode="slot")
    green = Instance(slot="green", environment_id=uuid.uuid4())
    datas = Instance(slot="data", environment_id=uuid.uuid4())
    blue = Instance(slot="blue", environment_id=uuid.uuid4())
    alone = Instance(name="shop")
    w = data.owner_writes
    # A slot deploy that failed after its start began marks the owner; one that changed nothing writes nothing.
    assert w("deploy", "changed", green, environment=server) == {"data_dirty": "mark"}
    assert w("deploy", "unchanged", green, environment=server) == {}
    # Its success clears the dirty state only when it names this slot; the data server's never clears it.
    assert w("deploy", "succeeded", green, environment=server) == {
        "live_identity": "if_unset", "fresh_data": "clear", "seed_snapshot_id": "clear",
        "data_dirty": "clear_if_same_slot"}
    assert w("deploy", "succeeded", datas, environment=server) == {
        "live_identity": "if_unset", "fresh_data": "keep", "seed_snapshot_id": "clear"}
    assert w("deploy", "changed", datas, environment=server) == {"data_dirty": "mark"}
    # Restore kinds on the owner, discard, control: as the table says.
    for kind in ("restore", "rollback", "reset"):
        assert w(kind, "succeeded", datas, environment=server) == {"data_dirty": "clear", "live_identity": "restore"}
        assert w(kind, "changed", datas, environment=server) == {"data_dirty": "mark"}
    assert w("discard", "succeeded", green, environment=server) == {"data_dirty": "clear"}
    assert w("discard", "changed", green, environment=server) == {}
    assert w("control", "succeeded", green, environment=server) == {"last_control_at": "now"}
    assert w("backup", "succeeded", datas, environment=server) == {}
    # Mode slot and standalone instances: phase 2's rules.
    p2 = {"data_dirty": "clear", "live_identity": "set", "fresh_data": "clear", "seed_snapshot_id": "clear"}
    assert w("deploy", "succeeded", blue, environment=solo) == p2
    assert w("deploy", "succeeded", alone) == p2
    assert w("content", "succeeded", alone) == {"content_pending": "clear"}
    with pytest.raises(ValueError):
        w("deploy", "maybe", alone)


# ------------------------------------------------------------ steps, labels, hostnames, actions


async def test_env_steps_labels_and_hostname_conflicts():
    ids = await _world()
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, ids)
        mem["green"].status = "stopped"
        env.traffic = {"switch": "switchyard", "dns": {"provider": "cloudflare", "address": None, "proxied": False}}
        steps = environments.env_steps_for(env, "activate", {"slot": "green"}, mem)
        assert [(s["key"], s["name"]) for s in steps] == [
            ("check", "Check uat"), ("start_slot", "Start green"), ("smoke", "Check green on h-green"),
            ("dns", "Update DNS records"), ("switch", "Switch traffic to green")]
        assert [s["name"] for s in environments.env_steps_for(env, "discard", {"slot": "green"}, mem)] == [
            "Check uat", "Stop green", "Check blue on h-blue", "Mark the data as checked"]
        assert [s["key"] for s in environments.env_steps_for(env, "publish", {}, mem)] == ["check", "traffic", "dns"]
        assert [s["name"] for s in environments.env_steps_for(env, "remove_slot", {"slot": "green"}, mem)] == [
            "Check uat", "Remove green"]
        with pytest.raises(ValueError):
            environments.env_steps_for(env, "deploy", {}, mem)
        assert data.job_label("deploy", slot="data") == "Update the data server"
        assert data.job_label("deploy", slot="green") == "Deploy to green"
        assert data.job_label("activate", slot="blue", back=True) == "Switch back to blue"
        assert data.job_label("teardown") == "Delete environment" and data.kind_label("publish") == "Publish names"
        assert set(data.ENV_KINDS) <= set(data.KIND_LABELS) and set(data.ENV_KINDS) <= set(data.KIND_NOUNS)
        assert data.RETRY_PERMISSION["activate"] == "traffic:switch"
        assert data.RETRY_PERMISSION["teardown"] == "environments:delete"

        # Hostnames both ways: an environment's against standalone instances, an instance's against environments.
        env.hostnames = [{"hostname": "api.uat.example.com", "follows": "active"}]
        db.add(Instance(name="shop", slug="shop", repository_id=ids["repo"], host_id=ids["host_blue"], branch="main",
                        app_state={"routes": [{"hostname": "shop.example.com"}]}))
        await db.commit()
        assert await environments.hostname_conflict(db, ["shop.example.com"]) == (
            "shop.example.com is already a hostname of instance shop")
        assert await environments.hostname_conflict(db, ["api.uat.example.com"]) == (
            "api.uat.example.com is already a hostname of environment uat")
        assert await environments.hostname_conflict(db, ["api.uat.example.com"], environment_id=env.id) is None
        assert await environments.environment_with_hostname(db, ["API.uat.example.com"]) == (
            "api.uat.example.com is a hostname of environment uat")


async def test_actions_follow_the_rules():
    ids = await _world()
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, ids)
        out = await environments.actions(db, env, Ctx())
        assert out["deploy"] == {"available": True, "reason": None, "slot": "green", "go_live": False,
                                 "needs_traffic_switch": False, "behind": False, "stale": None}
        assert out["activate"]["slot"] == "green" and out["activate"]["available"]
        assert out["update_data_server"]["available"] and out["publish"]["available"]
        assert not out["discard"]["available"] and out["rollback"]["reason"] == "Nothing to roll back"
        assert out["add_slot"]["reason"] == "uat already has two slots"
        assert out["delete"]["available"] and out["continue"] is None
        assert out["switch_back"] == {"available": False, "reason": "Nothing was live before", "slot": None}
        # After a switch back, the lag check's hint shows; a viewer gets permission reasons.
        env.traffic_state = {"last": {"from_slot": "green", "to_slot": "blue", "back": True, "at": T0.isoformat()}}
        await db.commit()
        env, mem = await _load(db, ids)
        out = await environments.actions(db, env, Ctx())
        assert out["deploy"]["behind"] is True
        assert out["switch_back"]["slot"] == "green" and out["switch_back"]["available"]
        viewer = await environments.actions(db, env, Ctx(Who({"environments:read"})))
        assert viewer["deploy"]["reason"] == "You need the deployments:create permission"
        assert viewer["activate"]["reason"] == "You need the traffic:switch permission"
        # A failed idle deploy: Discard first, Roll back second.
        failed = await _failed_green(db, ids)
        env, mem = await _load(db, ids)
        out = await environments.actions(db, env, Ctx())
        assert out["discard"] == {"available": True, "reason": None, "slot": "green"}
        assert out["rollback"] == {"available": True, "reason": None, "deployment_id": failed.id.hex}
        assert out["activate"]["reason"].startswith("uat's data may not be what green expects")
        no_reset = await environments.actions(db, env, Ctx(Who({"deployments:create", "data:restore",
                                                                "traffic:switch"})))
        assert no_reset["rollback"]["reason"] == "You need the data:reset permission"
    # A new mode server environment deploys its data server first.
    new = await _world_new()
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, new)
        out = await environments.actions(db, env, Ctx())
        assert out["deploy"]["slot"] == "data" and out["deploy"]["available"]
        assert out["activate"]["reason"] == "Deploy to blue first"


async def _world_new() -> dict[str, uuid.UUID]:
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=10, full_name="acme/new", owner="acme", name="new",
                          html_url="https://github.com/acme/new", detected_config={})
        hosts = [Host(name=f"n-{s}", hostname=f"10.0.1.{i}", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
                 for i, s in enumerate(("blue", "data"))]
        db.add_all([repo, *hosts])
        await db.flush()
        env = Environment(name="fresh", repository_id=repo.id, branch="main", data_mode="server",
                          app_secrets=SECRETS, traffic={"switch": "none", "dns": None})
        db.add(env)
        await db.flush()
        ids = {"env": env.id}
        for host, slot in zip(hosts, ("blue", "data"), strict=True):
            inst = Instance(name=f"fresh {slot}", slug=f"fresh-{slot}", repository_id=repo.id, host_id=host.id,
                            branch="main", build_source="app", environment_id=env.id, slot=slot)
            db.add(inst)
            await db.flush()
            ids[slot] = inst.id
        await db.commit()
        return ids


async def test_the_dirty_snapshot_text_names_the_environment_for_its_data_owner():
    """A snapshot refused while the owner's data is half-changed names the environment, as hold_text does (§7.5)."""
    ids = await _world()
    async with get_sessionmaker()() as db:
        dep = await _failed_green(db, ids)
        env, mem = await _load(db, ids)
        assert data.dirty_snapshot_text(mem["data"]) == (
            f"uat's data was left half-changed by deployment {dep.id.hex[:8]}; a snapshot of it would seed others "
            "with that. Retry, restore or roll back first.")
