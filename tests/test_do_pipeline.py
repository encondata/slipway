"""Whole DigitalOcean chains through the services (S23): P4 tests 53, 54, 70, 81, 82 and 83's remainder, the
pending grow of a Single environment (Decision 14), a restart between the resize's power off and power on, and a
scan of every audit row the chains wrote for secrets.

Everything outside Slipway is a fake: FakeDigitalOcean (its clock drives every wait), FakeSpaces over its Spaces
keys, FakeAcme validating DNS-01 through FakeCloudflare's records, FakeCloudflare for the zone, the public check
answered by FakeSites, and the droplets as hosts of the address-keyed MultiRemote (tests/do_fixtures.py ``Cloud``),
each running ServerSherpa's faked ``ss-stack`` in a real shell. The environment is made by
``environments.validate_create`` and ``create`` and every job is queued by ``jobs.queue_job``, as the API does,
then run by ``deployer.run_deployment``; nothing between them is mocked.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import types
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import select, update

from slipway.db.session import get_sessionmaker
from slipway.models import (
    AuditEvent,
    Backup,
    Deployment,
    Environment,
    Host,
    Instance,
    Repository,
    User,
)
from slipway.services import (
    acme,
    backup_store,
    certs,
    cloudflare,
    deployer,
    do_lb,
    do_provision,
    environments,
    jobs,
    provider_accounts,
    traffic,
)
from slipway.services.environments import NewEnvironment
from tests import do_fixtures as dof
from tests import fake_digitalocean as fdo
from tests.conftest import make_user
from tests.fake_acme import FakeAcme, FakeCloudflareTxt
from tests.fake_cloudflare import FakeCloudflare
from tests.fake_hosts import configure_cloudflare
from tests.golden import test_phase3_golden as golden
from tests.test_traffic import FakeSites

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")

ROOT = Path(__file__).resolve().parents[1]
DO_YML = (ROOT / "docs/examples/serversherpa.slipway.yml").read_text()
ZONE = "example.com"
DOMAIN = "shop.example.com"
NAMES = sorted(f"{s}.{DOMAIN}" for s in ("api", "portal", "kiosk", "wiki", "learn", "status"))
ADMIN = {"fields": {"first_name": "Ada", "last_name": "Lovelace", "email": "ada@example.com"}, "mode": "password",
         "password": "correct-horse-battery"}
ENV_EXAMPLE = golden.ENV_EXAMPLE


@dataclass
class Ctx:
    """``validate_create``'s caller: an admin, who holds every permission."""

    user: Any

    def can(self, permission: str) -> bool:
        return True


def github(manifest: str, env_example: str = ENV_EXAMPLE) -> type:
    """ServerSherpa's repository at the resolved commit: the golden's source tarball, and slipway.yml read
    through the contents API as ``prepare`` reads it. ``GH.manifest`` can be changed between jobs."""
    base = golden.github(manifest, env_example)

    class GH(base):  # type: ignore[misc, valid-type]
        texts: dict[str, str] = {"slipway.yml": manifest, "deploy/stack/env.example": env_example}
        asked: list[tuple[str, str]] = []  # (path, ref) of every contents read

        async def get_file(self, repo_id: Any, path: str, ref: str, **_kw: Any) -> str | None:
            type(self).asked.append((path, ref))
            return type(self).texts.get(path)

        fail_source = False  # the source download fails (a job that stops right after the DigitalOcean steps)

        async def download_tarball(self, repo_id, sha, dest: Path):
            if type(self).fail_source:
                raise RuntimeError("GitHub answered 502")
            files = {**type(self).texts, "deploy/stack/ss-stack": golden.SS_STACK}
            return golden._archive(dest, files)

    return GH


class World:
    """One DigitalOcean environment on every fake (see the module docstring)."""

    def __init__(self, tmp: Path, monkeypatch: Any) -> None:
        provider_accounts.clear_catalog_cache()
        self.tmp, self.monkeypatch = tmp, monkeypatch
        self.cloud = dof.Cloud(tmp, monkeypatch)
        self.do, self.multi = self.cloud.do, self.cloud.multi
        # The certificate: FakeCloudflare holds the zone and the challenge records, FakeAcme checks them.
        self.cf = FakeCloudflare()
        self.zone_id = self.cf.add_zone(ZONE)
        monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(self.cf.handle))
        self.acme = FakeAcme(FakeCloudflareTxt(self.cf, self.zone_id).lookup)
        monkeypatch.setattr(acme, "transport_factory", lambda: httpx.MockTransport(self.acme.handle))
        settings = types.SimpleNamespace(acme_directory=self.acme.directory_url,
                                         acme_staging_directory=self.acme.directory_url + "-staging")
        monkeypatch.setattr(do_provision, "get_settings", lambda: settings)
        # The public check through the load balancer's address, and every settle and wait, instantly.
        self.sites = FakeSites()
        monkeypatch.setattr(traffic, "transport_factory", self.sites.factory)
        for module in (traffic, do_lb, certs, acme):
            monkeypatch.setattr(module, "sleep", self._no_wait)
        self.submitted: list[uuid.UUID] = []
        monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, keys: self.submitted.append(dep_id))
        # The managed database: one folder every droplet's ss-stack finds (STACK_EXTERNAL_DATA=1).
        self.database = tmp / "managed-db"
        self.database.mkdir()
        self.roots = tmp / "roots"
        self.gh = github(DO_YML)
        self.env_id: uuid.UUID | None = None
        self.user_id: uuid.UUID | None = None
        self.name = "shop"

    @staticmethod
    async def _no_wait(_seconds: float) -> None:
        return None

    # -------------------------------------------------------------------- create

    async def create(self, *, name: str = "shop", slots: int = 2, droplet_size: str = "s-1vcpu-1gb",
                     **placement: Any) -> uuid.UUID:
        """``POST /environments`` through its service, the typed total confirmed."""
        self.name = name
        await configure_cloudflare(ZONE)
        user = await make_user(f"admin-{uuid.uuid4().hex[:6]}@example.com", roles=["admin"])
        self.user_id = user.id
        account_id = await dof.make_account()
        async with get_sessionmaker()() as db:
            repo = Repository(github_id=4242, full_name="acme/serversherpa", owner="acme", name="serversherpa",
                              html_url="https://github.com/acme/serversherpa", detected_config={})
            db.add(repo)
            await db.commit()
            repo_id = repo.id

        async def read(_repo, _branch, path):
            return self.gh.texts.get(path)

        def request(confirm: str | None) -> NewEnvironment:
            return NewEnvironment(
                name=name, repository_id=repo_id, data_mode="managed", hosts={},
                settings={"STACK_DOMAIN": f"{name}.example.com"},
                traffic={"switch": "do_lb", "dns": {"proxied": False}}, first_admin=dict(ADMIN),
                placement={"provider": "digitalocean", "account_id": account_id, "region": "nyc3",
                           "droplet_size": droplet_size, "db_size": "db-s-1vcpu-1gb", "db_standby": False,
                           "acme_staging": False, "slots": slots, **placement},
                confirm_cost=confirm)

        async with get_sessionmaker()() as db:
            user = await db.get(User, self.user_id)
            plan = await environments.validate_create(db, request(None), Ctx(user), read_file=read)
            total = plan.to_json()["cost"]["total"]
        async with get_sessionmaker()() as db:
            user = await db.get(User, self.user_id)
            plan = await environments.validate_create(db, request(total), Ctx(user), read_file=read)
            env = await environments.create(db, plan, Ctx(user))
            await db.commit()
            self.env_id = env.id
            for slot, member in (await environments.members(db, env)).items():
                if member.host_id is None:
                    continue
                host = await db.get(Host, member.host_id)
                # A droplet's deploy root is a folder of the test's, so its shell commands run for real.
                host.deploy_root = str(self.roots / slot)
                (self.roots / slot).mkdir(parents=True, exist_ok=True)
                self.cloud.host_env[host.name] = {"SS_DATA_STATE": str(self.database)}
            await db.commit()
        return self.env_id

    # ---------------------------------------------------------------------- jobs

    async def members(self) -> tuple[Environment, dict[str, Instance]]:
        async with get_sessionmaker()() as db:
            env = await db.get(Environment, self.env_id)
            return env, await environments.members(db, env)

    async def queue(self, *, slot: str | None = None, kind: str = "deploy", **kw: Any) -> uuid.UUID:
        """A job as the API queues it (``jobs.queue_job``)."""
        async with get_sessionmaker()() as db:
            user = await db.get(User, self.user_id)
            env = await db.get(Environment, self.env_id)
            mem = await environments.members(db, env)
            if slot is not None:
                dep = await jobs.queue_job(db, instance=mem[slot], environment=env, user=user, kind=kind, **kw)
            else:
                dep = await jobs.queue_job(db, environment=env, user=user, kind=kind, **kw)
            await db.commit()
            return dep.id

    async def run(self, dep_id: uuid.UUID) -> Deployment:
        await deployer.run_deployment(dep_id, connect=self.cloud.connect, github=self.gh)
        async with get_sessionmaker()() as db:
            return await db.get(Deployment, dep_id)

    async def next(self) -> Deployment:
        """Run the job a chain queued."""
        return await self.run(self.submitted.pop(0))

    # ------------------------------------------------------------------- reading

    def droplet(self, slot: str) -> dict[str, Any] | None:
        want = f"slipway-{self.name}-{slot}"
        found = [d for d in self.do.droplets.values() if d["name"] == want]
        return found[-1] if found else None

    def ip(self, slot: str) -> str:
        droplet = self.droplet(slot)
        assert droplet is not None
        return next(n["ip_address"] for n in droplet["networks"]["v4"] if n["type"] == "public")

    def host(self, slot: str):
        return self.multi[self.ip(slot)]

    def lb(self) -> dict[str, Any]:
        (lb,) = self.do.load_balancers.values()
        return lb


@pytest.fixture
def world(tmp_path, monkeypatch) -> World:
    return World(tmp_path, monkeypatch)


def steps(dep: Deployment) -> dict[str, str]:
    return {r["key"]: r["status"] for r in dep.steps or []}


def keys(dep: Deployment) -> list[str]:
    return [r["key"] for r in dep.steps or []]


def notes(dep: Deployment) -> dict[str, str | None]:
    return {r["key"]: r.get("note") for r in dep.steps or []}


def ok(dep: Deployment) -> None:
    assert dep.status == "succeeded", (dep.kind, dep.error, steps(dep), dep.log[-6000:])


def env_file(world: World, slot: str) -> dict[str, str]:
    """The ``.env`` the slot's last deploy wrote on its droplet, as keys and values."""
    text = (world.roots / slot / f"{world.name}-{slot}" / "shared" / ".env").read_text()
    out = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            out[key] = value
    return out


async def get(model: Any, ident: uuid.UUID) -> Any:
    async with get_sessionmaker()() as db:
        return await db.get(model, ident)


async def set_rows(model: Any, ident: uuid.UUID, **values: Any) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(update(model).where(model.id == ident).values(**values))
        await db.commit()


async def owner_backups(world: World) -> list[Backup]:
    _env, mem = await world.members()
    async with get_sessionmaker()() as db:
        return list(await db.scalars(select(Backup).where(Backup.instance_id == mem["data"].id)
                                     .order_by(Backup.taken_at)))


def writes_since(world: World, mark: int) -> list[tuple[str, str]]:
    return [(r["method"], r["path"]) for r in world.do.requests[mark:] if r["method"] != "GET"]


def actions_since(world: World, mark: int, droplet_id: int) -> list[str]:
    """The droplet actions Slipway sent since ``mark`` (power_off, resize, power_on...)."""
    return [r["body"]["type"] for r in world.do.requests[mark:]
            if (r["method"], r["path"]) == ("POST", f"/droplets/{droplet_id}/actions")]


async def chain(world: World, *, slots: int = 2) -> None:
    """Create the environment and run its first chain: blue's deploy, then the chained activate."""
    await world.create(slots=slots)
    ok(await world.run(await world.queue(slot="blue", options={"chain": True})))
    ok(await world.next())
    world.multi.clear()


# ------------------------------------------------------------------------ test 53: the first chain


async def test_53_the_first_chain_builds_blue_and_its_activate_goes_live_through_the_load_balancer(world):
    await world.create(slots=2)
    blue = await world.run(await world.queue(slot="blue", options={"chain": True}))
    ok(blue)
    # resolve, then the DigitalOcean steps, then source (Decision 12).
    assert keys(blue) == ["resolve", "prepare", "database", "edge", "source", "upload", "manifest", "ports",
                          "settings", "build", "backup", "start", "finish", "first_admin", "smoke", "traffic"]
    # prepare read slipway.yml at the resolved commit and stored its hash; manifest checked it.
    assert world.gh.asked == [("slipway.yml", blue.commit_sha)]
    assert blue.options["manifest_sha256"] == hashlib.sha256(DO_YML.encode()).hexdigest()
    assert steps(blue)["manifest"] == "succeeded"
    # What prepare, database and edge made.
    droplet = world.droplet("blue")
    assert droplet is not None and droplet["status"] == "active"
    (cluster,) = world.do.databases.values()
    assert [r["value"] for r in world.do.db_rules[cluster["id"]]] == [str(droplet["id"])]
    lb = world.lb()
    host = await get(Host, (await world.members())[1]["blue"].host_id)
    assert host.provider_state["phase"] == "ready" and host.hostname == world.ip("blue")
    # Blue's .env per P4 §5.4: managed data, the bucket, the edge, and no SS_CERT_* key.
    values = env_file(world, "blue")
    env, _mem = await world.members()
    bucket = f"slipway-shop-{env.id.hex[:8]}"
    assert values["STACK_EXTERNAL_DATA"] == "1" and values["STACK_DB_SSLMODE"] == "require"
    assert values["STACK_DB_HOST"].startswith("private-slipway-shop-db-") and values["STACK_DB_PORT"] == "25060"
    assert values["SS_DATABASE_URL"] == (f"postgresql+asyncpg://serversherpa:{env.app_secrets['POSTGRES_PASSWORD']}"
                                         f"@{values['STACK_DB_HOST']}:25060/serversherpa")
    assert values["SS_DATABASE_SSL"] == "require" and values["SS_DATABASE_CA_B64"]
    assert values["SS_SPACES_ENDPOINT"] == "https://nyc3.digitaloceanspaces.com"
    assert values["SS_SPACES_BUCKET"] == bucket and values["SS_SPACES_USE_PATH_STYLE"] == "false"
    (key_row,) = [r for r in await dof.rows(dof.DoEnv(env.id, "shop", env.provider_account_id, world.user_id),
                                             "spaces_key") if (r.details or {}).get("role") == "bucket"]
    assert values["SS_SPACES_ACCESS_KEY"] == key_row.provider_id
    assert values["SS_SPACES_SECRET_KEY"] == world.do.spaces_keys[key_row.provider_id]["secret_key"]
    assert (values["STACK_CADDY"], values["STACK_PROXY_IP"], values["STACK_BIND_IP"]) == (
        "1", "172.30.0.2", "127.0.0.1")
    assert values["STACK_HOSTS_IP"] == lb["ip"] and values["STACK_TRUSTED_PROXIES"] == env.cloud["vpc_range"]
    assert not [k for k in values if k.startswith("SS_CERT_")]
    # The probe signs in with sslmode=require on blue's droplet.
    probes = [line for line in world.host("blue").docker() if "-tAc select 1" in line]
    assert probes and all("sslmode=require" in line and "user=serversherpa" in line for line in probes)
    # backup: no data yet, asked through blue (the data runner); then the first admin and the smoke test.
    assert notes(blue)["backup"] == "No data yet: commands.has_data found none"
    assert "has-data" in " ".join(world.host("blue").calls())
    assert steps(blue)["first_admin"] == "succeeded"
    assert world.host("blue").log("ADMIN_LOG")[0].startswith("args=--email ada@example.com")
    assert steps(blue)["smoke"] == "succeeded"
    assert sorted(world.host("blue").log("CURL_LOG")) == NAMES
    assert (steps(blue)["traffic"], notes(blue)["traffic"]) == ("skipped", "Nothing is live yet; Activate follows")
    assert lb["droplet_ids"] == []  # nothing on the load balancer before the activate

    # The chained activate: DNS at the load balancer, the do_lb switch, blue active, live, starter content.
    (queued,) = world.submitted
    world.multi.clear()
    activate = await world.next()
    ok(activate)
    assert activate.kind == "activate" and keys(activate) == ["check", "smoke", "dns", "switch", "seed"]
    assert {r["name"]: (r["type"], r["content"]) for r in world.cf.records.values()} == {
        name: ("A", lb["ip"]) for name in NAMES}
    assert world.lb()["droplet_ids"] == [droplet["id"]]
    assert {r["host"] for r in world.sites.requests} == set(NAMES)
    assert all(r["sni"] in NAMES for r in world.sites.requests)
    env, mem = await world.members()
    assert env.active_slot_id == mem["blue"].id and env.status == "live"
    assert steps(activate)["seed"] == "succeeded"
    assert "seed" in " ".join(world.host("blue").calls())
    assert (world.database / "db").read_text().splitlines()[-1] == "SEEDED"
    await no_secret_in_audits(world)


# ------------------------------------------------------------------------- test 54: deploy to green


async def test_54_deploy_to_green_builds_its_droplet_and_backs_up_on_blue_through_slipway(world):
    await chain(world)
    (world.database / "rev").write_text("0042_expand\n")  # the managed database's revision
    _env, mem = await world.members()
    blue_release = mem["blue"].app_state["live"]["release"]
    mark = len(world.do.requests)
    green = await world.run(await world.queue(slot="green"))
    ok(green)
    assert keys(green)[:5] == ["resolve", "prepare", "database", "edge", "source"]
    assert "first_admin" not in keys(green) and "seed" not in keys(green)
    # Green's droplet, built and added to the cluster's trusted sources.
    droplet = world.droplet("green")
    assert droplet is not None and droplet["status"] == "active"
    assert ("POST", "/droplets") in writes_since(world, mark)
    (cluster,) = world.do.databases.values()
    assert sorted(r["value"] for r in world.do.db_rules[cluster["id"]]) == sorted(
        str(world.droplet(s)["id"]) for s in ("blue", "green"))
    # The role SQL again, on green's droplet.
    (sql,) = world.host("green").sql()
    assert 'CREATE ROLE "serversherpa"' in sql and "PASSWORD 'SCRAM-SHA-256$" in sql
    # The pre-deploy backup: dumped on blue's droplet by blue's live release, kept on Slipway, gone from blue.
    blue_calls = world.host("blue").calls()
    assert f"pgdump {blue_release}" in blue_calls and f"revision {blue_release}" in blue_calls
    (backup,) = await owner_backups(world)
    assert (backup.location, backup.status, backup.reason) == ("slipway", "ready", "pre_deploy")
    assert green.backup_id == backup.id
    _env, mem = await world.members()
    assert (await backup_store.check(mem["data"], backup)).status == "ok"
    left = [p.name for p in (world.roots / "blue" / "shop-blue").rglob("*") if p.is_file() and "backups" in p.parts]
    assert left == []
    # Green's accepts on the revision, then the lag check: blue's live release accepts it too.
    green_release = (await world.members())[1]["green"].app_state["live"]["release"]
    assert f"accepts {green_release}" in world.host("green").calls()
    assert f"accepts {blue_release}" in blue_calls
    assert "blue (a1b2c3d) can run the data at revision" in green.log
    assert (steps(green)["traffic"], notes(green)["traffic"]) == (
        "skipped", "Traffic stays on blue; activate green to move it")
    assert world.lb()["droplet_ids"] == [world.droplet("blue")["id"]]
    await no_secret_in_audits(world)


# ---------------------------------------------------------------------------------- no secrets


async def secrets_of(world: World) -> list[str]:
    """Every secret the chains handled: the token, Cloudflare's, the doadmin passwords, the Spaces secrets, the
    environment's secrets and the first admin's password."""
    from tests.fake_cloudflare import TOKEN as CF_TOKEN
    out = [fdo.TOKEN, CF_TOKEN, ADMIN["password"]]
    out += [d["connection"]["password"] for d in world.do.databases.values()]
    out += [k["secret_key"] for k in world.do.spaces_keys.values()]
    async with get_sessionmaker()() as db:
        for env in await db.scalars(select(Environment)):
            out += [str(v) for v in (env.app_secrets or {}).values() if v]
    return [s for s in out if s and len(s) >= 8]


async def no_secret_in_audits(world: World) -> None:
    """No audit row (nor any job's log or error) carries a token, a password, a key, the ACME account key or a
    certificate's private key (P4 §4.2)."""
    secrets = await secrets_of(world)
    async with get_sessionmaker()() as db:
        audited = [json.dumps([a.action, a.summary, a.details], default=str)
                   for a in await db.scalars(select(AuditEvent))]
        logged = [f"{d.log}\n{d.error or ''}\n{json.dumps(d.options, default=str)}"
                  for d in await db.scalars(select(Deployment))]
    assert audited
    for text in audited + logged:
        for secret in secrets:
            assert secret not in text
        assert "PRIVATE KEY" not in text and "SCRAM-SHA-256$" not in text


# ------------------------------------------------- test 70: phase 3 with the phase 4 example (LAN)

LAN_GOLDEN = ROOT / "tests" / "golden" / "phase4_serversherpa_lan.json"
LAN_ENV_EXAMPLE = "".join(line + "\n" for line in ENV_EXAMPLE.splitlines() if not line.startswith("SS_SPACES_BUCKET="))


@pytest.fixture
def golden_tmp(tmp_path: Path) -> Path:
    """The scenarios' temporary folder: pytest's own. The scenarios move into a folder of exactly the length
    phase3.json was recorded in themselves (tests/golden/test_phase3_golden.py ``scenario_folder``)."""
    return tmp_path


def env_files(record: Any) -> list[str]:
    """Every ``.env`` a scenario's jobs wrote."""
    found: list[str] = []
    if isinstance(record, dict):
        for key, value in record.items():
            if key == "env_file" and isinstance(value, str):
                found.append(value)
            else:
                found += env_files(value)
    elif isinstance(record, list):
        for value in record:
            found += env_files(value)
    return found


@pytest.mark.parametrize("name", sorted(golden.SCENARIOS))
async def test_70_phase_3_scenarios_run_with_the_phase_4_example_exactly_as_recorded(name, golden_tmp, monkeypatch):
    """The phase 4 example's edge and data.managed blocks change nothing on SSH hosts: the same record as
    phase3.json (step keys, .env bytes, Switchyard and Cloudflare calls). This test never writes phase3.json."""
    got = json.loads(json.dumps(await golden.SCENARIOS[name](DO_YML, golden_tmp, monkeypatch), sort_keys=True,
                                default=str))
    want = json.loads(golden.GOLDEN.read_text())[name]
    for part in want:
        assert got.get(part) == want[part], f"{name}: {part} differs from phase 3"
    assert set(got) == set(want)
    # data.managed.env's SS_SPACES_BUCKET never reaches a LAN .env: the only line is the env_file's own default.
    written = env_files(got)
    assert written and all([line for line in text.splitlines() if line.startswith("SS_SPACES_BUCKET")]
                           == ["SS_SPACES_BUCKET=serversherpa"] for text in written)


@pytest.mark.parametrize("name", ["single", "standalone"])
async def test_70_a_lan_slot_of_the_phase_4_example_gets_no_spaces_bucket_line(name, golden_tmp, monkeypatch):
    """The Single and standalone scenarios with an env_file that has no SS_SPACES_BUCKET line: data.managed's env
    (which sets it) never reaches a LAN slot's .env, so no such line appears. Recorded in
    phase4_serversherpa_lan.json (``SLIPWAY_WRITE_GOLDEN=1`` writes this file only). Blue/Green in mode server
    can't drop the line: its data server's ``provides.objects.bucket`` is ``{SS_SPACES_BUCKET}``, so the test
    above checks there that the env_file's default is the only one."""
    import os
    got = json.loads(json.dumps(await golden.SCENARIOS[name](DO_YML, golden_tmp, monkeypatch,
                                                            env_example=LAN_ENV_EXAMPLE),
                                sort_keys=True, default=str))
    written = env_files(got)
    assert written and not [text for text in written if "SS_SPACES_BUCKET" in text]
    if os.environ.get("SLIPWAY_WRITE_GOLDEN"):
        stored = json.loads(LAN_GOLDEN.read_text()) if LAN_GOLDEN.exists() else {}
        stored[name] = got
        LAN_GOLDEN.write_text(json.dumps(stored, indent=1, sort_keys=True) + "\n")
        return
    want = json.loads(LAN_GOLDEN.read_text())[name]
    for part in want:
        assert got.get(part) == want[part], f"{name}: {part} differs from the recorded LAN case"
    assert set(got) == set(want)


def delete_droplet(world: World, slot: str) -> dict[str, Any]:
    """Someone deletes the slot's droplet in DigitalOcean's control panel: it leaves the load balancer too, and
    its disk (the fake's deploy root) goes with it."""
    droplet = world.droplet(slot)
    assert droplet is not None
    del world.do.droplets[droplet["id"]]
    for lb in world.do.load_balancers.values():
        lb["droplet_ids"] = [d for d in lb["droplet_ids"] if d != droplet["id"]]
    shutil.rmtree(world.roots / slot)
    (world.roots / slot).mkdir()
    return droplet


def delete_droplet(world: World, slot: str) -> dict[str, Any]:
    """Someone deletes the slot's droplet in DigitalOcean's control panel: it leaves the load balancer and the
    cluster's trusted sources, its address stops answering, and its disk (the fake's deploy root) goes with it."""
    droplet = world.droplet(slot)
    assert droplet is not None
    ip = world.ip(slot)
    del world.do.droplets[droplet["id"]]
    for lb in world.do.load_balancers.values():
        lb["droplet_ids"] = [d for d in lb["droplet_ids"] if d != droplet["id"]]
    for rules in world.do.db_rules.values():
        rules[:] = [r for r in rules if r["value"] != str(droplet["id"])]
    world.multi.firewalled(ip)
    shutil.rmtree(world.roots / slot)
    (world.roots / slot).mkdir()
    return droplet


async def host_of(world: World, slot: str) -> Host:
    _env, mem = await world.members()
    return await get(Host, mem[slot].host_id)


# -------------------------------------------------------- test 81: Single, its droplet deleted


async def test_81_a_deleted_single_droplet_is_rebuilt_by_the_next_deploy_and_put_back_on_the_load_balancer(world):
    await chain(world, slots=1)
    old = delete_droplet(world, "blue")
    old_key = (await host_of(world, "blue")).host_key
    assert world.lb()["droplet_ids"] == []
    # D28: a deploy to the active slot is allowed (in a Single environment always); prepare makes a new droplet.
    dep = await world.run(await world.queue(slot="blue"))
    ok(dep)
    assert "Droplet slipway-shop-blue is gone from DigitalOcean; it is made again with a new host key" in dep.log
    new = world.droplet("blue")
    assert new is not None and new["id"] != old["id"]
    host = await host_of(world, "blue")
    old_ip = next(n["ip_address"] for n in old["networks"]["v4"] if n["type"] == "public")
    assert host.provider_state["phase"] == "ready" and host.hostname == world.ip("blue") != old_ip
    assert host.host_key and host.host_key != old_key
    assert host.host_key.split()[:2] == world.do.host_keys[new["id"]].split()[:2]
    async with get_sessionmaker()() as db:
        audited = [a.action for a in await db.scalars(select(AuditEvent).where(AuditEvent.action.like("resource.%")))]
    assert "resource.rebuild" in audited
    assert "droplet" in dep.options["rebuild"]
    # The old release went with the old disk: the backup ran with this deploy's new release (P4 §10.4 rule 3).
    new_release = (await world.members())[1]["blue"].app_state["live"]["release"]
    assert f"pgdump {new_release}" in world.host("blue").calls()
    assert steps(dep)["backup"] == "succeeded"
    # Its traffic step is the sync repair: the load balancer sends to the new droplet.
    assert steps(dep)["traffic"] == "succeeded"
    assert world.lb()["droplet_ids"] == [new["id"]]
    (cluster,) = world.do.databases.values()
    assert [r["value"] for r in world.do.db_rules[cluster["id"]]] == [str(new["id"])]

    # A load balancer deleted by hand is made again by the next deploy's edge (with no targets, D11); that
    # deploy stops at the source download, so it is Publish that puts the active slot's droplet back.
    lb_ip = world.lb()["ip"]
    world.do.load_balancers.clear()
    world.gh.fail_source = True
    failed = await world.run(await world.queue(slot="blue"))
    world.gh.fail_source = False
    assert failed.status == "failed" and steps(failed)["edge"] == "succeeded" and steps(failed)["source"] == "failed"
    lb = world.lb()
    assert lb["droplet_ids"] == [] and lb["ip"] != lb_ip
    publish = await world.run(await world.queue(kind="publish"))
    ok(publish)
    assert {r["key"]: r["name"] for r in publish.steps}["traffic"] == "Update the load balancer"
    assert steps(publish)["traffic"] == "succeeded"
    assert world.lb()["droplet_ids"] == [new["id"]]
    # Its dns step moves the names to the new load balancer's address.
    assert {r["content"] for r in world.cf.records.values()} == {lb["ip"]}
    await no_secret_in_audits(world)


# -------------------------------------------------- test 82: Blue/Green, the active droplet deleted


async def blue_gone_then_green(world: World) -> Deployment:
    """Blue/Green with blue active, blue's droplet deleted, then green's first deploy."""
    await chain(world, slots=2)
    delete_droplet(world, "blue")
    green = await world.run(await world.queue(slot="green"))
    ok(green)
    return green


async def test_82_with_the_active_droplet_gone_green_deploys_activates_and_runs_the_data_commands(world):
    green = await blue_gone_then_green(world)
    # Green's prepare found blue's droplet gone: blue's host isn't built any more (it serves nothing).
    assert "Droplet slipway-shop-blue is gone from DigitalOcean: deploy to blue to build it again" in green.log
    assert (await host_of(world, "blue")).provider_state["phase"] == "gone"
    # The pre-deploy backup ran on green's new release (rule 3), never on blue.
    _env, mem = await world.members()
    green_release = mem["green"].app_state["live"]["release"]
    assert f"pgdump {green_release}" in world.host("green").calls()
    assert steps(green)["backup"] == "succeeded" and len(await owner_backups(world)) == 1
    assert (steps(green)["traffic"], notes(green)["traffic"]) == (
        "skipped", "Traffic stays on blue; activate green to move it")

    # Activate green works.
    world.multi.clear()
    activate = await world.run(await world.queue(kind="activate", options={"slot": "green"}))
    ok(activate)
    env, mem = await world.members()
    assert env.active_slot_id == mem["green"].id
    assert world.lb()["droplet_ids"] == [world.droplet("green")["id"]]

    # Back up now runs on green (rule 1: green leads now).
    world.multi.clear()
    backup = await world.run(await world.queue(slot="data", kind="backup"))
    ok(backup)
    assert f"pgdump {green_release}" in world.host("green").calls()
    assert len(await owner_backups(world)) == 2

    # A deploy to blue builds it again; its traffic step repairs nothing while green is active.
    world.multi.clear()
    blue = await world.run(await world.queue(slot="blue"))
    ok(blue)
    assert (await host_of(world, "blue")).provider_state["phase"] == "ready"
    assert f"pgdump {green_release}" in world.host("green").calls()  # its backup ran on green (rule 1)
    assert (steps(blue)["traffic"], notes(blue)["traffic"]) == (
        "skipped", "Traffic stays on green; activate blue to move it")
    assert world.lb()["droplet_ids"] == [world.droplet("green")["id"]]
    await no_secret_in_audits(world)


async def test_82_a_deploy_to_blue_while_it_is_still_recorded_active_repairs_the_load_balancer(world):
    await blue_gone_then_green(world)
    env, mem = await world.members()
    assert env.active_slot_id == mem["blue"].id
    green_release = mem["green"].app_state["live"]["release"]
    # D28: the active slot's host isn't built, so a deploy to it is allowed.
    world.multi.clear()
    blue = await world.run(await world.queue(slot="blue"))
    ok(blue)
    # Rule 2: blue's droplet is built again by now, but its old release went with the old one.
    assert "blue has no live release; running the data commands on green" in blue.log
    assert f"pgdump {green_release}" in world.host("green").calls()
    assert steps(blue)["traffic"] == "succeeded"
    assert world.lb()["droplet_ids"] == [world.droplet("blue")["id"]]
    await no_secret_in_audits(world)


# ------------------------------------------------------------------- test 83: frozen values


@pytest.mark.parametrize("change", [
    ("  port: 80\n  health: /healthz\n", "  port: 8080\n  health: /healthz\n",
     "a1b2c3d changes edge.port from 80 to 8080, but shop's load balancer and firewall were made for 80: a new port "
     "needs a new environment. Slipway changed nothing"),
    ("  port: 80\n  health: /healthz\n", "  port: 80\n  health: /ready\n",
     "a1b2c3d changes edge.health from /healthz to /ready, but shop's load balancer was made for /healthz: a new "
     "health path needs a new environment. Slipway changed nothing"),
    ('db:      {version: "16",', 'db:      {version: "17",',
     "a1b2c3d changes data.managed.db.version from 16 to 17, but shop's database cluster was made for 16: a new "
     "version needs a new environment. Slipway changed nothing"),
], ids=["edge.port", "edge.health", "db.version"])
async def test_83_a_release_changing_a_frozen_value_fails_prepare_before_any_write_or_start(world, change):
    await chain(world, slots=2)
    old, new, text = change
    assert DO_YML.count(old) == 1
    world.gh.texts = {**world.gh.texts, "slipway.yml": DO_YML.replace(old, new)}
    mark = len(world.do.requests)
    dep = await world.run(await world.queue(slot="green"))
    assert dep.status == "failed" and dep.error == text
    assert steps(dep)["resolve"] == "succeeded" and steps(dep)["prepare"] == "failed"
    assert {k for k, v in steps(dep).items() if v != "pending"} == {"resolve", "prepare"}  # start never ran
    assert writes_since(world, mark) == []  # nothing written to DigitalOcean
    assert world.droplet("green") is None
    assert not any(h.calls() for h in world.multi.hosts.values())  # no command on any droplet
    _env, mem = await world.members()
    assert mem["blue"].status == "running" and mem["green"].current_commit_sha is None


# ------------------------------------------- a pending grow (Decision 14) and a restart in its middle

BIGGER = "s-1vcpu-2gb"


async def grow(world: World, droplet_size: str = BIGGER) -> None:
    """``PATCH /environments/{id} {cloud}`` through its services: the new size confirmed, applied at the next
    deploy's ``resize`` step."""
    async with get_sessionmaker()() as db:
        user = await db.get(User, world.user_id)
        env = await db.get(Environment, world.env_id)
        total = (await environments.grow_plan(db, env, {"droplet_size": droplet_size}, Ctx(user))).to_json()
        plan = await environments.grow_plan(db, env, {"droplet_size": droplet_size}, Ctx(user),
                                            confirm_cost=total["cost"]["total"])
        await environments.grow(db, plan, Ctx(user))
        await db.commit()


async def test_a_pending_grow_is_applied_after_the_backup_with_one_power_off_and_on(world):
    await chain(world, slots=1)
    await grow(world)
    droplet = world.droplet("blue")
    # A deploy refused before its resize step (a frozen value changed) never powers the droplet off.
    world.gh.texts = {**world.gh.texts, "slipway.yml": DO_YML.replace("  port: 80\n", "  port: 8080\n")}
    mark = len(world.do.requests)
    refused = await world.run(await world.queue(slot="blue"))
    assert refused.status == "failed" and "resize" in keys(refused) and steps(refused)["resize"] == "pending"
    assert actions_since(world, mark, droplet["id"]) == [] and world.do.droplets[droplet["id"]]["status"] == "active"
    world.gh.texts = {**world.gh.texts, "slipway.yml": DO_YML}
    # The deploy: resize right after backup, named for the size; one power off, the resize, one power on.
    mark = len(world.do.requests)
    dep = await world.run(await world.queue(slot="blue"))
    ok(dep)
    order = keys(dep)
    assert order[order.index("backup") + 1] == "resize" and order.index("resize") < order.index("start")
    assert actions_since(world, mark, droplet["id"]) == ["power_off", "resize", "power_on"]
    assert world.do.droplets[droplet["id"]]["size_slug"] == BIGGER
    assert world.do.droplets[droplet["id"]]["status"] == "active"
    assert (await host_of(world, "blue")).provider_state["size"] == BIGGER
    # The next deploy has nothing to resize.
    again = await world.run(await world.queue(slot="blue"))
    ok(again)
    assert "resize" not in keys(again)


async def test_a_restart_between_power_off_and_power_on_is_noticed_and_the_next_prepare_powers_it_on(
        world, monkeypatch):
    await chain(world, slots=1)
    await grow(world)
    droplet = world.droplet("blue")

    class Restart(BaseException):
        """Slipway's process ends: no ``finally`` of the job runs."""

    real_action, real_power_on_after = do_provision._action, do_provision._power_on_after

    async def action(client, droplet_id, kind, *args, **kw):
        if kind == "resize":
            raise Restart
        return await real_action(client, droplet_id, kind, *args, **kw)

    async def no_power_on(*_args, **_kw):
        return None

    monkeypatch.setattr(do_provision, "_action", action)
    monkeypatch.setattr(do_provision, "_power_on_after", no_power_on)
    dep_id = await world.queue(slot="blue")
    with pytest.raises(Restart):
        await world.run(dep_id)
    # A killed process runs no handler: the row still says the resize step is running (the step's own handler
    # marked it failed on the way out here, which a real end of the process never does).
    cut = await get(Deployment, dep_id)
    assert cut.status == "running"
    await set_rows(Deployment, dep_id, steps=[{**r, "status": "running"} if r["key"] == "resize" else r
                                              for r in cut.steps])
    monkeypatch.setattr(do_provision, "_action", real_action)
    monkeypatch.setattr(do_provision, "_power_on_after", real_power_on_after)
    assert world.do.droplets[droplet["id"]]["status"] == "off"
    # The restart's recovery: the job fails and the notice names the slot whose droplet may be off.
    await deployer.DeployRunner().recover_interrupted()
    cut = await get(Deployment, dep_id)
    assert cut.status == "failed"
    env = await get(Environment, world.env_id)
    assert env.notice["text"] == "blue's droplet may be powered off: deploy to blue again"
    assert env.notice["deployment_id"] == dep_id.hex
    # The next deploy's prepare powers it on before anything else, then its resize step applies the size.
    dep = await world.run(await world.queue(slot="blue"))
    ok(dep)
    assert "slipway-shop-blue is powered off (a resize was cut short); powering it on" in dep.log
    assert world.do.droplets[droplet["id"]]["status"] == "active"
    assert world.do.droplets[droplet["id"]]["size_slug"] == BIGGER


# ------------------------------------------------------------- every audit row of a long chain


async def test_no_audit_row_of_a_whole_environment_life_carries_a_secret(world):
    """Create, the first chain, green, Switch to green, Back up now, a restore, a grow, then Delete (dropping the
    data): every audit row written on the way, and every job's log, error and options, are free of secrets."""
    await chain(world, slots=2)
    ok(await world.run(await world.queue(slot="green")))
    ok(await world.run(await world.queue(kind="activate", options={"slot": "green"})))
    ok(await world.run(await world.queue(slot="data", kind="backup")))
    (*_, last) = await owner_backups(world)
    ok(await world.run(await world.queue(slot="data", kind="restore", restore_backup_id=last.id)))
    await grow(world)
    ok(await world.run(await world.queue(slot="blue")))
    teardown = await world.run(await world.queue(kind="teardown", options={"confirmed": True, "drop_data": True}))
    ok(teardown)
    assert world.do.droplets == {} and world.do.databases == {} and world.do.load_balancers == {}
    async with get_sessionmaker()() as db:
        actions = {a.action for a in await db.scalars(select(AuditEvent))}
    assert {"environment.create", "environment.cost_confirmed", "environment.team_frozen", "resource.create",
            "host.key_pinned", "environment.edge_frozen", "certificate.issue", "environment.activate",
            "environment.resize", "resource.delete"} <= actions
    await no_secret_in_audits(world)
