"""A managed environment's data owner (S14b): the data runner, Reset's wipe, backups kept on Slipway and the
owner's job lists (P4 §5.3, §10.4-§10.6, §11.5): P4 tests 55, 56, 57, 58, 59, 84 and 85, and the slot deploy's
backup on the runner.

The environment is placed on DigitalOcean (``tests/do_fixtures.make_do_env``): blue and green on droplet hosts,
the data owner with no host. Both droplets are fake hosts of a ``MultiRemote`` (built and pinned, as ``prepare``
leaves them), sharing one "managed database": a folder every host's app finds as ``$MANAGED_DB``. The
DigitalOcean steps of a deploy are stood in for (``prepare`` records the slipway.yml hash, ``database`` and
``edge`` do nothing); the cluster, the bucket and its key are recorded as the steps would record them, and
Reset's bucket is FakeSpaces' under FakeDigitalOcean's keys. Nothing else is mocked: the deployer runs its
commands in a real shell on each fake host.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import os
import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select, update

from slipway.db.session import get_sessionmaker
from slipway.models import Backup, Deployment, Environment, FirstAdmin, Host, Instance, Snapshot
from slipway.services import backup_store, data, deployer, do_provision, do_rules, hosts, resources, traffic
from tests import do_fixtures as dof
from tests.test_data_jobs import DataGitHub, _make_snapshot

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")

ENV_EXAMPLE = "APP_ENV=dev\nAPP_DOMAIN=example.com\nAPP_SECRET=CHANGEME\nAPP_KEY=CHANGEME\nDB_PASSWORD=CHANGEME\n"

# The phase 3 test app on managed data behind a load balancer: its database is the managed one (data.attach and
# data.managed), its uploads are in the bucket, and each slot keeps a cache volume of its own (holds: other).
MANAGED_YML = """\
version: 1
name: Demo
env_file: deploy/env.example
placeholder: CHANGEME
settings:
  APP_DOMAIN: {label: Base domain, required: true}
vars:
  APP_ENV: "{slipway.slug}"
  APP_REPO: "{slipway.release}"
  APP_SLOT: "{slipway.slot}"
secrets:
  APP_SECRET: hex
  APP_KEY: {kind: fernet, identity: true}
  DB_PASSWORD: hex
services:
  web: {port: 8080, port_var: APP_WEB_PORT, hostname: "www.{APP_DOMAIN}", health: /healthz}
projects: ["demo-{APP_ENV}-web"]
images: ["demo-web:{slipway.sha12}"]
edge:
  port: 80
  health: /healthz
  env:
    APP_PROXY: "{edge.address}"
    APP_TRUSTED: "{edge.trusted}"
data:
  app: demo
  format: demo-v1
  migrations: expand_contract
  files: {format: demo-files-v1, label: Uploads}
  volumes:
    - {name: "demo-{APP_ENV}-db_data", holds: database}
    - {name: "demo-{APP_ENV}-cache", holds: other}
  attach:
    needs: {db: postgres, objects: s3}
    env:
      APP_EXTERNAL: "1"
      DB_HOST: "{data.db.host}"
      DB_PORT: "{data.db.port}"
      DB_SSLMODE: "{data.db.tls}"
  managed:
    db: {version: "16", database: demo, user: demo, password: "{secret.DB_PASSWORD}"}
    objects: {cors: []}
    env:
      APP_MANAGED: "1"
      APP_BUCKET: "{data.objects.bucket}"
    commands:
      has_data: [sh, deploy/app, has-data, "{slipway.env_dir}", --external]
commands:
  build: [sh, deploy/app, build, "{slipway.env_dir}"]
  start: [sh, deploy/app, up, "{slipway.env_dir}"]
  stop: [sh, deploy/app, down, "{slipway.env_dir}"]
  has_data: [sh, deploy/app, has-data, "{slipway.env_dir}"]
  data_up: [sh, deploy/app, data, "{slipway.env_dir}"]
  dump: [sh, deploy/app, pgdump, "{slipway.env_dir}", "{slipway.out}"]
  verify_dump: [sh, deploy/app, verify-dump, "{slipway.env_dir}", "{slipway.in}"]
  revision: [sh, deploy/app, revision, "{slipway.env_dir}"]
  accepts: [sh, deploy/app, accepts, "{slipway.env_dir}", "{slipway.in}"]
  restore: [sh, deploy/app, restore, "{slipway.env_dir}", "{slipway.in}"]
  export_files: [sh, deploy/app, export-objects, "{slipway.env_dir}", "{slipway.out}"]
  import_files: [sh, deploy/app, import-objects, "{slipway.env_dir}", "{slipway.in}"]
  after_import: [sh, deploy/app, clear-sessions, "{slipway.env_dir}"]
  seed: [sh, deploy/app, seed, "{slipway.env_dir}"]
first_admin:
  command: [sh, deploy/app, admin, "{slipway.env_dir}", --email, "{admin.email}", --name, "{admin.name}"]
  fields:
    email: {label: Email, kind: email}
    name: {label: Name}
  password: {stdin: true, args: [--password-stdin]}
  exists_codes: [10]
"""

# The app. Each call is logged in $APP_LOG with the release whose .env it saw. On managed data (APP_MANAGED=1 in
# its .env) the database is $MANAGED_DB/db and the bucket's objects $MANAGED_DB/files, the same for every host.
SCRIPT = r"""
cmd=$1; dir=$2; shift 2
val() { sed -n "s/^$1=//p" "$dir/.env"; }
repo=$(val APP_REPO)
echo "$cmd ${repo##*/}" >> "$APP_LOG"
if [ "$(val APP_MANAGED)" = 1 ]; then db="$MANAGED_DB"; else db="$dir/../state"; fi
mkdir -p "$db"
case "$cmd" in
  build|down|data|clear-sessions) ;;
  up)
    [ -n "$FAIL_UP" ] && { echo "migration failed" >&2; exit 1; }
    echo "MIGRATED $(val APP_SLOT)" >> "$db/db"
    [ -n "$NEW_REV" ] && echo "$NEW_REV" > "$db/rev"
    val APP_KEY > "$dir/../keys" ;;
  has-data)
    [ -n "$HAS_DATA_RC" ] && exit "$HAS_DATA_RC"
    [ -f "$db/db" ] && exit 0; exit 3 ;;
  pgdump) { echo "DB:"; cat "$db/db"; } > "$1" ;;
  verify-dump) [ "$(head -n 1 "$1")" = "DB:" ] ;;
  revision) cat "$db/rev" 2>/dev/null ;;
  accepts) exit 0 ;;
  restore) echo "restore-from $1" >> "$APP_LOG"; tail -n +2 "$1" > "$db/db" ;;
  export-objects) { echo "FILES:"; cat "$db/files" 2>/dev/null; } > "$1" ;;
  import-objects) echo "bucket $(val APP_BUCKET)" >> "$APP_LOG"; tail -n +2 "$1" > "$db/files" ;;
  seed) echo SEEDED >> "$db/db" ;;
  admin)
    IFS= read -r pw || pw=""
    echo "args=$* pwlen=${#pw}" >> "$ADMIN_LOG"
    exit "${ADMIN_RC:-0}" ;;
esac
exit 0
"""

# In front of the fake hosts' docker shim: a psql run that drops the database empties the managed "database"
# folder too (the shim only records the SQL), so has_data answers as a real cluster would after Reset.
DOCKER_FRONT = """#!/bin/sh
if [ "$1" = run ] && echo "$*" | grep -q psql; then
  sql=$(cat)
  printf '%s\\n' "$sql" | "$NEXT_BIN/docker" "$@"; rc=$?
  if printf '%s\\n' "$sql" | grep -q 'DROP DATABASE'; then rm -f "$MANAGED_DB/db"; fi
  exit $rc
fi
exec "$NEXT_BIN/docker" "$@"
"""

SECRETS = {"APP_SECRET": "5" * 64, "APP_KEY": "k" * 43 + "=", "DB_PASSWORD": "d" * 32 + "pw"}
ADMIN_PASSWORD = "doadmin-" + "7" * 24
DB_HOST = "private-slipway-shop-db-do-user-1-0.b.db.ondigitalocean.com"
CA_B64 = base64.b64encode(b"-----BEGIN CERTIFICATE-----\nMIIfake\n-----END CERTIFICATE-----\n").decode()
LB_IP, VPC_RANGE = "203.0.113.50", "10.116.0.0/20"
ADDRESSES = {"blue": "10.0.0.11", "green": "10.0.0.12"}


class GH(DataGitHub):
    files = {"slipway.yml": MANAGED_YML, "deploy/env.example": ENV_EXAMPLE, "deploy/app": SCRIPT}

    async def get_file(self, repo_id: Any, path: str, ref: str, **_kw: Any) -> str | None:
        return self.files.get(path)


class World:
    """One managed environment on its fakes (see the module docstring)."""

    def __init__(self, tmp_path: Path, monkeypatch: Any) -> None:
        self.tmp = tmp_path
        self.cloud = dof.Cloud(tmp_path, monkeypatch)
        self.multi = self.cloud.multi
        self.cluster = tmp_path / "cluster"
        self.cluster.mkdir()
        front = tmp_path / "front"
        front.mkdir()
        (front / "docker").write_text(DOCKER_FRONT)
        (front / "docker").chmod(0o755)
        for slot in ADDRESSES:
            host = self.multi[slot]  # the MultiRemote's own blue and green (10.0.0.11, 10.0.0.12)
            host.env.update(MANAGED_DB=str(self.cluster), NEXT_BIN=str(self.multi.bin_dir),
                            PATH=f"{front}:{host.env['PATH']}")
        self.env: dof.DoEnv | None = None
        self.submitted: list[uuid.UUID] = []
        monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, keys: self.submitted.append(dep_id))
        monkeypatch.setattr(traffic, "sleep", self._no_wait)
        monkeypatch.setattr(do_provision, "prepare", self._prepare)
        monkeypatch.setattr(do_provision, "database", self._nothing)
        monkeypatch.setattr(do_provision, "edge", self._edge)

    @staticmethod
    async def _no_wait(_seconds: float) -> None:
        return None

    @staticmethod
    async def _nothing(_ctx: Any, **_kw: Any) -> None:
        return None

    @staticmethod
    async def _edge(_ctx: Any, **_kw: Any) -> do_provision.Edged:
        return do_provision.Edged(lb_id="lb-1", lb_ip=LB_IP, certificate={})

    async def _prepare(self, ctx: do_provision.ProvisionContext, *, read_manifest: Any) -> do_provision.Prepared:
        """The droplet is already built and pinned: prepare records only what it read (P4 §14.3)."""
        text = await read_manifest()
        digest = hashlib.sha256(text.encode()).hexdigest()
        ctx.manifest_sha256 = digest
        await do_provision._set_options(ctx, manifest_sha256=digest)
        async with get_sessionmaker()() as db:
            inst = await db.get(Instance, ctx.instance_id)
        assert self.env is not None
        return do_provision.Prepared(host_id=self.env.host_ids[str(inst.slot)], droplet_id="1",
                                     public_ip=ADDRESSES[str(inst.slot)], private_ip="10.116.0.2")

    async def setup(self, *, slots: tuple[str, ...] = ("blue", "green")) -> dof.DoEnv:
        env = await dof.make_do_env(slots=slots, cloud={"lb_ip": LB_IP, "vpc_range": VPC_RANGE})
        self.env = env
        domain = "shop.example.com"
        async with get_sessionmaker()() as db:
            row = await db.get(Environment, env.env_id)
            row.app_settings = {"APP_DOMAIN": domain}
            row.app_secrets = dict(SECRETS)
            row.hostnames = [{"hostname": f"www.{domain}", "service": "web", "container": 8080, "follows": "active",
                              "health": "/healthz"}]
            for slot in slots:
                host = await db.get(Host, env.host_ids[slot])
                fake = self.multi[slot]
                host.hostname = fake.address
                host.deploy_root = str(fake.root)
                host.host_key = self.multi.new_key(slot)
                hosts.set_phase(host, hosts.PHASE_READY, size="s-1vcpu-1gb", droplet_name=host.name)
            await db.commit()
        # What prepare and database record: the cluster (with doadmin's password), the bucket and its own key.
        await resources.record(env.env_id, "digitalocean", "database", "db-1", do_rules.database_name(env.name),
                               "created", details={"host": DB_HOST, "port": 25060, "version": "16", "ca_b64": CA_B64},
                               credentials={"admin_password": ADMIN_PASSWORD})
        self.bucket = do_rules.bucket_name(env.name, env.env_id)
        await resources.record(env.env_id, "digitalocean", "bucket", self.bucket, self.bucket, "created",
                               details={"region": "nyc3"})
        key = self.cloud.do.add_spaces_key(f"{self.bucket}-rw", [{"bucket": self.bucket, "permission": "readwrite"}])
        self.bucket_key = key["access_key"]
        await resources.record(env.env_id, "digitalocean", "spaces_key", key["access_key"], key["name"], "created",
                               details={"role": "bucket"}, credentials={"secret_key": key["secret_key"]})
        self.cloud.spaces.buckets[self.bucket] = {}
        return env

    # ------------------------------------------------------------------ jobs

    async def run(self, dep_id: uuid.UUID) -> Deployment:
        await deployer.run_deployment(dep_id, connect=self.multi.connect, github=GH)
        return await get(Deployment, dep_id)

    async def deploy(self, slot: str, **options: Any) -> Deployment:
        assert self.env is not None
        async with get_sessionmaker()() as db:
            inst = await db.get(Instance, self.env.ids[slot])
            env = await db.get(Environment, self.env.env_id)
            from slipway.services import environments
            mem = await environments.members(db, env)
            provider = await deployer.provider_steps(db, inst, env, mem)
            rows = deployer.steps_for(inst, environment=env, members=mem, provider=provider)
            dep = Deployment(instance_id=inst.id, environment_id=env.id, kind="deploy", branch="main", log="",
                             triggered_by_id=self.env.user_id, steps=rows, options={"slot": slot, **options})
            db.add(dep)
            await db.commit()
        return await self.run(dep.id)

    async def owner_job(self, kind: str, **fields: Any) -> Deployment:
        """A job on the owner as ``queue_job`` records it: the runner's live commit, steps set when it starts."""
        assert self.env is not None
        owner = await get(Instance, self.env.ids["data"])
        sha = ((owner.app_state or {}).get("live") or {}).get("sha")
        async with get_sessionmaker()() as db:
            dep = Deployment(instance_id=self.env.ids["data"], environment_id=self.env.env_id, kind=kind,
                             branch="main", log="", triggered_by_id=self.env.user_id, commit_sha=sha,
                             options=fields.pop("options", {}), **fields)
            db.add(dep)
            await db.commit()
        return await self.run(dep.id)

    async def live(self, *, active: str | None = "blue", slots: tuple[str, ...] = ("blue", "green")) -> None:
        """Each slot deployed, ``active`` taking the traffic (what Activate records)."""
        assert self.env is not None
        for slot in slots:
            dep = await self.deploy(slot)
            assert dep.status == "succeeded", (slot, dep.error, dep.log[-4000:])
        if active:
            await set_rows(Environment, self.env.env_id, active_slot_id=self.env.ids[active], status="live")
            # The owner's view of its runner follows the active slot (as the next owner job refreshes it).
            async with get_sessionmaker()() as db:
                from slipway.services import environments
                env = await db.get(Environment, self.env.env_id)
                mem = await environments.members(db, env)
                owner = mem["data"]
                owner.app_state = data.runner_live(owner, data.runner_choice(env, mem).instance)
                await db.commit()
        self.multi.clear()
        for slot in slots:
            self.multi[slot].env["FAKE_PS"] = "0123456789ab"  # its projects list a container: stop and start act

    def db_text(self) -> str:
        path = self.cluster / "db"
        return path.read_text() if path.exists() else ""


@pytest.fixture
def world(tmp_path, monkeypatch) -> World:
    return World(tmp_path, monkeypatch)


async def get(model: Any, ident: uuid.UUID) -> Any:
    async with get_sessionmaker()() as db:
        return await db.get(model, ident)


async def set_rows(model: Any, ident: uuid.UUID, **values: Any) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(update(model).where(model.id == ident).values(**values))
        await db.commit()


async def owner_backups(env: dof.DoEnv) -> list[Backup]:
    async with get_sessionmaker()() as db:
        return list(await db.scalars(select(Backup).where(Backup.instance_id == env.ids["data"])
                                     .order_by(Backup.taken_at)))


def keys(dep: Deployment) -> list[str]:
    return [r["key"] for r in dep.steps]


def statuses(dep: Deployment) -> dict[str, str]:
    return {r["key"]: r["status"] for r in dep.steps}


def note(dep: Deployment, key: str) -> str:
    return next((r.get("note") or "") for r in dep.steps if r["key"] == key)


def stored_files(env: dof.DoEnv) -> list[str]:
    folder = backup_store.owner_dir(env.ids["data"])
    return sorted(p.name for p in folder.iterdir()) if folder.is_dir() else []


def incoming(world: World, slot: str) -> list[str]:
    folder = world.multi[slot].folder(f"shop-{slot}") / "backups" / ".incoming"
    return sorted(p.name for p in folder.rglob("*") if p.is_file()) if folder.is_dir() else []


# --------------------------------------------------------------- the slot deploys and Back up now (53, 54)


async def test_the_first_deploy_backs_up_through_its_own_slot_and_renders_the_managed_env(world):
    env = await world.setup()
    dep = await world.deploy("blue")
    assert dep.status == "succeeded", (dep.error, dep.log[-4000:])
    assert statuses(dep)["backup"] == "skipped" and note(dep, "backup").startswith("No data yet")  # rule 3
    text = (world.multi["blue"].folder("shop-blue") / "shared" / ".env").read_text()
    values = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    # data.attach.env with the cluster's values, data.managed.env, then the edge (P4 §5.3).
    assert values["DB_HOST"] == DB_HOST and values["DB_PORT"] == "25060" and values["DB_SSLMODE"] == "require"
    assert values["APP_MANAGED"] == "1" and values["APP_BUCKET"] == world.bucket
    assert values["APP_PROXY"] == LB_IP and values["APP_TRUSTED"] == VPC_RANGE
    # The database probe signed in with sslmode=require from blue's droplet (P4 §10.2).
    assert any("sslmode=require" in line for line in world.multi["blue"].docker())
    blue = await get(Instance, env.ids["blue"])
    assert blue.app_state["live"]["edge"] == {"address": LB_IP, "trusted": VPC_RANGE}  # P4 §11.5
    # The owner's view of its runner: blue's live release.
    owner = await get(Instance, env.ids["data"])
    assert owner.app_state["live"]["runner"] == "blue" and owner.app_state["live"]["sha"] == blue.current_commit_sha
    assert owner.status == "created" and owner.live_identity == {"APP_KEY": SECRETS["APP_KEY"]}
    assert world.db_text() == "MIGRATED blue\n"


async def test_54_a_deploy_to_green_backs_up_on_blues_droplet_and_keeps_the_copy_on_slipway(world):
    env = await world.setup()
    await world.live(slots=("blue",))
    dep = await world.deploy("green")
    assert dep.status == "succeeded", (dep.error, dep.log[-4000:])
    assert statuses(dep)["backup"] == "succeeded"
    blue = await get(Instance, env.ids["blue"])
    release = blue.app_state["live"]["release"]
    # The dump ran on blue's droplet with blue's live release, not on green.
    assert f"pgdump {release}" in world.multi["blue"].calls()
    assert not any(c.startswith("pgdump") for c in world.multi["green"].calls())
    [row] = await owner_backups(env)
    assert row.location == "slipway" and row.status == "ready" and row.reason == "pre_deploy"
    assert row.data_key and row.stored_bytes and dep.backup_id == row.id
    assert stored_files(env) == [f"{row.name}.db.sbc"]
    assert incoming(world, "blue") == []  # the runner's copy went once it was safe on Slipway
    assert f"Kept backup {row.name} on Slipway" in dep.log
    assert ADMIN_PASSWORD not in dep.log and SECRETS["DB_PASSWORD"] not in dep.log


async def test_back_up_now_runs_on_the_lead_slot_and_names_its_droplet(world):
    env = await world.setup()
    await world.live()
    (world.cluster / "rev").write_text("rev-1\n")
    dep = await world.owner_job("backup")
    assert dep.status == "succeeded", (dep.error, dep.log[-4000:])
    assert keys(dep) == ["release", "backup"]
    names = {r["key"]: r["name"] for r in dep.steps}
    assert names["release"] == "Check blue's live release"
    assert names["backup"] == "Back up the data on slipway-shop-blue"
    assert "shop's data commands run on blue (slipway-shop-blue)" in dep.log
    [row] = [b for b in await owner_backups(env) if b.deployment_id == dep.id]
    assert row.location == "slipway" and row.reason == "manual" and row.revision == "rev-1"
    assert row.commit_sha == (await get(Instance, env.ids["blue"])).current_commit_sha
    assert any(c.startswith("pgdump") for c in world.multi["blue"].calls())
    owner = await get(Instance, env.ids["data"])
    assert owner.status == "created"  # the owner's status never changes
    # Green's lock was read and released (the migration lock), blue's lock released.
    for slot in ("blue", "green"):
        lock = world.multi[slot].folder(f"shop-{slot}") / ".slipway-lock"
        assert not lock.exists() or dep.id.hex not in lock.read_text().replace("-", "")


async def test_rule_2_runs_the_data_commands_on_green_when_blues_droplet_is_gone(world):
    env = await world.setup()
    await world.live()
    async with get_sessionmaker()() as db:
        host = await db.get(Host, env.host_ids["blue"])
        hosts.set_phase(host, hosts.PHASE_GONE)
        await db.commit()
    dep = await world.owner_job("backup")
    assert dep.status == "succeeded", (dep.error, dep.log[-4000:])
    assert "blue's droplet isn't built; running the data commands on green" in dep.log
    assert any(c.startswith("pgdump") for c in world.multi["green"].calls())
    assert not world.multi["blue"].calls()


async def test_back_up_now_is_queued_through_the_api_with_the_runners_commit(world, admin_client):
    env = await world.setup()
    await world.live()
    resp = await admin_client.post(f"/api/v1/instances/{env.ids['data']}/backups", json={})
    assert resp.status_code in (200, 201, 202), resp.text
    async with get_sessionmaker()() as db:
        dep = await db.scalar(select(Deployment).where(Deployment.instance_id == env.ids["data"],
                                                       Deployment.kind == "backup"))
        blue = await db.get(Instance, env.ids["blue"])
    assert dep is not None and dep.commit_sha == blue.current_commit_sha
    assert keys(dep) == ["release", "backup"] and world.submitted == [dep.id]
    done = await world.run(dep.id)
    assert done.status == "succeeded", (done.error, done.log[-4000:])


async def test_rule_4_refuses_owner_jobs_when_no_slot_can_run_them(world, admin_client):
    env = await world.setup()
    # Nothing deployed: queue time (the API) and run time say rule 4's text.
    resp = await admin_client.post(f"/api/v1/instances/{env.ids['data']}/backups", json={})
    assert resp.status_code == 409
    assert resp.json()["detail"] == "shop has no slot that can run its data commands: deploy to blue first"
    await world.live(slots=("blue",))
    async with get_sessionmaker()() as db:
        owner = await db.get(Instance, env.ids["data"])
        assert await data.hostless_refusal(db, owner) is None
        assert (await data.data_runner_of(db, owner)).slot == "blue"
        host = await db.get(Host, env.host_ids["blue"])
        hosts.set_phase(host, hosts.PHASE_GONE)
        await db.commit()
    dep = await world.owner_job("backup")
    assert dep.status == "failed"
    assert dep.error == "Could not start the deployment: shop has no slot that can run its data commands: deploy to " \
                        "blue first"


# ---------------------------------------------------------------------------------- 55: restore


async def _backup_then_change(world: World, env: dof.DoEnv) -> Backup:
    dep = await world.owner_job("backup")
    assert dep.status == "succeeded", (dep.error, dep.log[-4000:])
    [row] = [b for b in await owner_backups(env) if b.deployment_id == dep.id]
    (world.cluster / "db").write_text("LATER\n")
    world.multi.clear()
    return row


async def test_55_restore_on_managed_data(world):
    env = await world.setup()
    await world.live()
    row = await _backup_then_change(world, env)
    blue = await get(Instance, env.ids["blue"])
    release = blue.app_state["live"]["release"]
    dep = await world.owner_job("restore", restore_backup_id=row.id)
    assert dep.status == "succeeded", (dep.error, dep.log[-4000:])
    # No release, manifest, settings, build, stop or start of the owner's own (P4 §10.6).
    assert keys(dep) == ["check", "backup", "stop_slots", "restore", "start_slots", "finish", "traffic"]
    assert all(statuses(dep)[k] in ("succeeded", "skipped", "warning") for k in keys(dep))
    calls = world.multi["blue"].calls()
    # The backup was pushed to the runner (blue), restored there, and the copy removed.
    restore_from = next(c for c in calls if c.startswith("restore-from "))
    assert f"/backups/.incoming/{row.name}.db" in restore_from
    assert incoming(world, "blue") == []
    assert f"Copied backup {row.name} from Slipway to" in dep.log
    # Both slots stopped first; blue started again with its live start before finish; green as it was (P3).
    for slot in ("blue", "green"):
        assert any(f"compose -p demo-shop-{slot}-web stop" in line for line in world.multi[slot].docker()), slot
    assert calls.index(f"up {release}") > calls.index(next(c for c in calls if c.startswith("restore ")))
    assert any("compose -p demo-shop-green-web start" in line for line in world.multi["green"].docker())
    assert world.db_text() == f"MIGRATED blue\nMIGRATED green\nMIGRATED blue\n"
    for slot in ("blue", "green"):
        assert (await get(Instance, env.ids[slot])).status == "running"
    owner = await get(Instance, env.ids["data"])
    assert owner.status == "created" and owner.data_dirty is None and owner.current_commit_sha is None


async def test_55_refusals_come_before_any_stop(world):
    env = await world.setup()
    await world.live()
    row = await _backup_then_change(world, env)
    backup_store.delete(env.ids["data"], row)  # its files went from Slipway's storage
    dep = await world.owner_job("restore", restore_backup_id=row.id)
    assert dep.status == "failed" and statuses(dep)["check"] == "failed"
    assert dep.error == f"The backup {row.name} on Slipway is missing. Nothing was changed."
    assert all(statuses(dep)[k] == "pending" for k in ("backup", "stop_slots", "restore", "start_slots"))
    for slot in ("blue", "green"):
        assert not any(line.endswith(" stop") or " stop" in line for line in world.multi[slot].docker()
                       if "compose" in line), slot
    assert world.db_text() == "LATER\n"


async def test_55_a_runner_that_cant_be_reached_fails_the_first_step(world):
    env = await world.setup()
    await world.live()
    row = await _backup_then_change(world, env)
    world.multi.firewalled(ADDRESSES["blue"])
    dep = await world.owner_job("restore", restore_backup_id=row.id)
    assert dep.status == "failed" and statuses(dep)["check"] == "failed"
    assert "timed out" in dep.error and "timed out" in note(dep, "check")


# ---------------------------------------------------------------------------------- 56: reset


async def test_56_reset_on_managed_data(world):
    env = await world.setup()
    await world.live()
    for slot in ("blue", "green"):
        volumes = world.multi[slot].tmp / "volumes"
        volumes.write_text(f"demo-shop-{slot}-cache demo-shop-{slot}-web\n")
        world.multi[slot].env["FAKE_VOLUME_FILE"] = str(volumes)
    world.cloud.spaces.put(world.bucket, "uploads/a.png", b"A")
    world.cloud.spaces.put(world.bucket, "uploads/b.png", b"B")
    world.cloud.spaces.start_upload(world.bucket, "uploads/c.png")
    async with get_sessionmaker()() as db:
        db.add(FirstAdmin(instance_id=env.ids["data"], fields={"email": "ada@example.com", "name": "Ada"},
                          mode="password", password="correct-horse-battery", status="pending"))
        await db.execute(update(Instance).where(Instance.id == env.ids["data"]).values(seed_content=True))
        await db.commit()
    keys_before = set(world.cloud.do.spaces_keys)
    dep = await world.owner_job("reset", options={"seed": True})
    assert dep.status == "succeeded", (dep.error, dep.log[-4000:])
    assert keys(dep) == ["backup", "stop_slots", "wipe", "start_slots", "finish", "first_admin", "seed", "traffic"]
    assert {r["key"]: r["name"] for r in dep.steps}["wipe"] == "Empty the database and the bucket"
    # The database dropped and made again as doadmin, on the runner (blue).
    [sql] = world.multi["blue"].sql()
    assert sql.startswith('DROP DATABASE IF EXISTS "demo" WITH (FORCE);')
    assert "CREATE DATABASE \"demo\" OWNER \"demo\"" in sql and sql.endswith("\\gexec")
    assert not world.multi["green"].sql()
    assert ADMIN_PASSWORD not in dep.log and ADMIN_PASSWORD not in "".join(world.multi["blue"].docker())
    # The bucket emptied with a temporary full-access key, deleted afterwards.
    assert world.cloud.spaces.buckets[world.bucket] == {} and not world.cloud.spaces.uploads.get(world.bucket)
    assert set(world.cloud.do.spaces_keys) == keys_before
    made = [r for r in world.cloud.do.requests if r["method"] == "POST" and r["path"] == "/spaces/keys"]
    gone = [r for r in world.cloud.do.requests if r["method"] == "DELETE" and r["path"].startswith("/spaces/keys/")]
    assert len(made) == 2 and len(gone) == 2  # the check's before the slots stop (review 45 F4), and the wipe's
    # Each slot's own volume removed on its droplet.
    for slot in ("blue", "green"):
        assert f"volume rm -- demo-shop-{slot}-cache" in world.multi[slot].docker(), slot
    # first_admin and seed after start_slots, on blue (the lead), on the new empty data.
    order = keys(dep)
    assert order.index("start_slots") < order.index("first_admin") < order.index("seed")
    assert statuses(dep)["first_admin"] == "succeeded" and statuses(dep)["seed"] == "succeeded"
    assert world.multi["blue"].log("ADMIN_LOG") and not world.multi["green"].log("ADMIN_LOG")
    assert world.db_text() == "MIGRATED blue\nSEEDED\n"
    [taken] = [b for b in await owner_backups(env) if b.deployment_id == dep.id]
    assert taken.reason == "pre_reset" and taken.location == "slipway"


async def test_84_wipe_retried_after_a_run_cut_between_drop_and_create(world):
    env = await world.setup()
    await world.live()
    flag = world.tmp / "drop-fails"
    flag.write_text("")
    world.multi["blue"].env["FAKE_PSQL_DROP_FAILS"] = str(flag)
    first = await world.owner_job("reset")
    assert first.status == "failed" and statuses(first)["wipe"] == "failed"
    assert "psql exited 2" in first.error and "Retry: the reset ends with an empty one either way" in first.error
    [cut] = world.multi["blue"].sql()
    assert cut.endswith("-- cut") and "CREATE DATABASE" not in cut
    owner = await get(Instance, env.ids["data"])
    assert owner.data_dirty and owner.data_dirty.get("hold")  # the data was half changed: held
    async with get_sessionmaker()() as db:
        retry = Deployment(instance_id=env.ids["data"], environment_id=env.env_id, kind="reset", branch="main",
                           log="", triggered_by_id=env.user_id, retry_of_id=first.id, commit_sha=first.commit_sha,
                           options={"override_hold": True})
        db.add(retry)
        await db.commit()
    dep = await world.run(retry.id)
    assert dep.status == "succeeded", (dep.error, dep.log[-4000:])
    blocks = world.multi["blue"].sql()
    assert len(blocks) == 2
    assert blocks[1].startswith('DROP DATABASE IF EXISTS "demo" WITH (FORCE);')
    assert 'CREATE DATABASE "demo" OWNER "demo"' in blocks[1]  # it ends with an empty database owned by the role


async def test_start_over_backs_up_with_the_newest_release_and_wipes(world):
    env = await world.setup(slots=("blue",))
    world.multi["blue"].env["FAIL_UP"] = "1"
    failed = await world.deploy("blue")
    assert failed.status == "failed" and statuses(failed)["start"] == "failed"
    world.multi["blue"].env.pop("FAIL_UP")
    (world.cluster / "db").write_text("HALF\n")
    world.multi.clear()
    dep = await world.owner_job("reset", options={"start_over": True})
    assert dep.status == "succeeded", (dep.error, dep.log[-4000:])
    assert keys(dep) == ["backup", "stop_slots", "wipe"]
    assert any(c.startswith("pgdump") for c in world.multi["blue"].calls())
    [taken] = [b for b in await owner_backups(env) if b.deployment_id == dep.id]
    assert taken.location == "slipway" and taken.status == "ready"
    assert world.multi["blue"].sql() and world.db_text() == ""
    owner = await get(Instance, env.ids["data"])
    assert owner.fresh_data == "empty" and owner.data_dirty is None and owner.status == "created"


async def test_a_snapshot_of_managed_data_exports_on_the_runner_and_stops_both_slots(world):
    env = await world.setup()
    await world.live()
    async with get_sessionmaker()() as db:
        snap = Snapshot(name="shop-1", status="pending", origin="instance", app="demo", source="shop",
                        source_instance_id=env.ids["data"])
        db.add(snap)
        await db.commit()
    dep = await world.owner_job("snapshot", snapshot_id=snap.id, options={"stop_app": True})
    assert dep.status == "succeeded", (dep.error, dep.log[-4000:])
    assert keys(dep) == ["release", "stop_slots", "export", "start_slots", "store"]
    assert {r["key"]: r["name"] for r in dep.steps}["export"] == "Export the data on slipway-shop-blue"
    assert any(c.startswith("pgdump") for c in world.multi["blue"].calls())
    for slot in ("blue", "green"):
        docker = world.multi[slot].docker()
        stop = docker.index(f"compose -p demo-shop-{slot}-web stop")
        assert docker.index(f"compose -p demo-shop-{slot}-web start") > stop
    row = await get(Snapshot, snap.id)
    assert row.status == "ready" and row.identity_keys == ["APP_KEY"] and row.source_instance_id == env.ids["data"]


async def test_create_the_first_admin_now_runs_on_the_lead_slot(world):
    env = await world.setup()
    await world.live()
    async with get_sessionmaker()() as db:
        db.add(FirstAdmin(instance_id=env.ids["data"], fields={"email": "ada@example.com", "name": "Ada"},
                          mode="password", password="correct-horse-battery", status="pending"))
        await db.commit()
    dep = await world.owner_job("admin")
    assert dep.status == "succeeded", (dep.error, dep.log[-4000:])
    assert keys(dep) == ["release", "first_admin"] and statuses(dep)["first_admin"] == "succeeded"
    assert world.multi["blue"].log("ADMIN_LOG") and not world.multi["green"].log("ADMIN_LOG")


# -------------------------------------------------------------------------- 57: a seeded environment


async def test_57_a_seeded_environment_seeds_on_blues_first_deploy(world):
    env = await world.setup()
    identity_key = "s" * 43 + "="
    sid = await _make_snapshot(files_text="FILES:\nphoto\n", identity={"APP_KEY": identity_key},
                               repository="acme/serversherpa-shop")
    await set_rows(Instance, env.ids["data"], seed_snapshot_id=sid, fresh_data="snapshot")
    dep = await world.deploy("blue")
    assert dep.status == "succeeded", (dep.error, dep.log[-4000:])
    assert dep.snapshot_id == sid
    order = keys(dep)
    assert order[order.index("build") + 1:order.index("start")] == ["check", "backup", "stop", "restore", "files",
                                                                     "after_import"]
    calls = world.multi["blue"].calls()
    assert any(c.startswith("restore ") for c in calls) and any(c.startswith("import-objects") for c in calls)
    assert f"bucket {world.bucket}" in world.multi["blue"].log("APP_LOG")  # import-objects wrote to the bucket
    assert (world.cluster / "files").read_text() == "photo\n"
    assert world.db_text() == "FROM-SNAP\nMIGRATED blue\n"
    # The snapshot's identity became the environment's secrets and the owner's identity.
    row = await get(Environment, env.env_id)
    assert row.app_secrets["APP_KEY"] == identity_key
    owner = await get(Instance, env.ids["data"])
    assert owner.live_identity == {"APP_KEY": identity_key}
    assert owner.seed_snapshot_id is None and owner.fresh_data is None


# -------------------------------------------------------------------------- 58, 59: the lock, has_data


async def test_58_a_d_line_left_in_greens_lock_makes_back_up_now_on_blue_wait(world):
    env = await world.setup()
    await world.live()
    lock = world.multi["green"].folder("shop-green") / ".slipway-lock"
    lock.write_text(f"{uuid.uuid4()} - {os.getpid()} start d\n")
    dep = await world.owner_job("backup")
    assert dep.status == "failed" and statuses(dep)["release"] == "failed"
    assert "start" in dep.error and f"(pid {os.getpid()}) is still running on slipway-shop-green" in dep.error
    assert not any(c.startswith("pgdump") for c in world.multi["blue"].calls())
    assert [b for b in await owner_backups(env) if b.deployment_id == dep.id] == []
    blue_lock = world.multi["blue"].folder("shop-blue") / ".slipway-lock"
    assert not blue_lock.exists() or str(dep.id) not in blue_lock.read_text()  # its own lock was released
    assert str(dep.id) not in lock.read_text()  # green's line was left as it was


async def test_59_has_data_exit_4_on_the_runner_fails_with_the_managed_text(world):
    env = await world.setup()
    await world.live()
    world.multi["blue"].env["HAS_DATA_RC"] = "4"
    dep = await world.owner_job("backup")
    assert dep.status == "failed" and statuses(dep)["backup"] == "failed"
    assert dep.error == ("shop's data is managed; data.managed.commands.has_data must answer for the managed database "
                         '(exit 4 means "elsewhere")')
    assert [b for b in await owner_backups(env) if b.deployment_id == dep.id] == []


# ------------------------------------------------------------------- 85: data.py on Slipway backups


async def _stored_row(env: dof.DoEnv, name: str, *, reason: str = "pre_deploy", status: str = "ready",
                      key: bool = True, at: int = 0) -> Backup:
    """A backup kept on Slipway, its file written as pull writes it."""
    owner = env.ids["data"]
    plain = f"DB:\n{name}\n".encode()
    data_key = os.urandom(32)
    folder = backup_store.owner_dir(owner)
    folder.mkdir(parents=True, exist_ok=True)
    from slipway.services import snapfile
    with open(backup_store.stored_path(owner, name, "dump"), "wb") as out:
        writer = snapfile.ContainerWriter(out, data_key)
        writer.write(plain)
        writer.close()
        stored_bytes = writer.file_bytes
    async with get_sessionmaker()() as db:
        row = Backup(instance_id=owner, name=name, reason=reason, status=status, format="demo-v1",
                     db_bytes=len(plain), db_sha256=hashlib.sha256(plain).hexdigest(), identity_fp="x" * 64,
                     taken_at=dt.datetime(2026, 11, 16, 9, at, tzinfo=dt.UTC), location="slipway",
                     data_key=backup_store.encode_key(data_key) if key else None, stored_bytes=stored_bytes)
        db.add(row)
        await db.commit()
        return row


def _name(i: int) -> str:
    return f"20261116T09{i:02d}00Z-{i:08x}"


async def test_85_retention_on_managed_data_deletes_the_slipway_files_with_no_ssh(world):
    env = await world.setup()
    rows = [await _stored_row(env, _name(i), at=i) for i in range(4)]
    said: list[str] = []

    async def say(line: str) -> None:
        said.append(line)

    async with get_sessionmaker()() as db:
        owner = await db.get(Instance, env.ids["data"])
        owner.keep_backups = 2
        removed = await data.apply_retention(None, db, owner, None, just_taken=rows[-1].id, say=say)
        await db.commit()
    assert removed == [rows[0].name]  # the newest two kept, and the one just taken
    assert stored_files(env) == [f"{r.name}.db.sbc" for r in rows[1:]]
    assert [b.name for b in await owner_backups(env)] == [r.name for r in rows[1:]]
    assert said == [f"Removed old backups from Slipway: {rows[0].name} (keeping the newest 2)"]
    assert not world.multi.opened  # no SSH


async def test_85_check_and_settle_read_the_slipway_files(world):
    env = await world.setup()
    ok, missing, changed = [await _stored_row(env, _name(i), at=i) for i in range(3)]
    backup_store.delete(env.ids["data"], missing)
    path = backup_store.stored_path(env.ids["data"], changed.name, "dump")
    blob = bytearray(path.read_bytes())
    blob[-20] ^= 0xFF
    path.write_bytes(bytes(blob))
    async with get_sessionmaker()() as db:
        rows = list(await db.scalars(select(Backup).where(Backup.instance_id == env.ids["data"])))
        found = await data.check_backups(None, db, rows, None, None, rehash=True)
        await db.commit()
    assert found.warning is None
    assert found.statuses == {ok.id: "ready", missing.id: "missing", changed.id: "changed"}
    assert {b.name: b.status for b in await owner_backups(env)} == {ok.name: "ready", missing.name: "missing",
                                                                   changed.name: "changed"}
    async with get_sessionmaker()() as db:
        row = await db.get(Backup, ok.id)
        assert await data.confirm_backup(None, db, row, None, None) is None
        gone = await db.get(Backup, missing.id)
        assert await data.confirm_backup(None, db, gone, None, None) == \
            f"The backup {missing.name} on Slipway is missing"
    # Unverified after a restart: whole files under a readable key are kept; one cut before its key was recorded
    # can never be read, so its files go and the row is forgotten.
    whole = await _stored_row(env, _name(5), status="unverified", at=5)
    keyless = await _stored_row(env, _name(6), status="unverified", key=False, at=6)
    async with get_sessionmaker()() as db:
        owner = await db.get(Instance, env.ids["data"])
        lines = await data.settle_unverified(None, db, owner, None)
        await db.commit()
    assert lines == [f"Backup {whole.name} was kept on Slipway before Slipway restarted; checked it and kept it",
                     f"Backup {keyless.name} never finished before Slipway restarted; forgot it"]
    assert (await get(Backup, whole.id)).status == "ready" and await get(Backup, keyless.id) is None
    assert f"{keyless.name}.db.sbc" not in stored_files(env)
    assert not world.multi.opened


async def test_85_a_lost_key_makes_a_slipway_backup_delete_only(world):
    env = await world.setup()
    await world.live()
    row = await _stored_row(env, _name(1), key=False, status="changed")
    async with get_sessionmaker()() as db:
        owner = await db.get(Instance, env.ids["data"])
        fresh = await db.get(Backup, row.id)
        assert data.restorable(owner, fresh).reason == backup_store.KEY_LOST
        assert await data.confirm_backup(None, db, fresh, None, None) == backup_store.KEY_LOST


# ----------------------------------------------------------------------------------------- the texts


def test_the_managed_probe_text_names_the_trusted_sources_not_a_lan_address():
    slot = Instance(name="shop blue", slot="blue")
    text = traffic.probe_problem("psql: error: connection refused\n", slot=slot, env_name="shop", host=DB_HOST,
                                 port=25060, managed=True)
    assert "pg_hba" not in text and "LAN" not in text
    assert text.endswith("The managed database lets in only the droplets in its trusted sources: deploy to blue "
                         "again, which sets them before anything uses the database")


async def test_the_owners_step_lists_on_managed_data(world):
    env = await world.setup()
    async with get_sessionmaker()() as db:
        from slipway.services import environments
        row = await db.get(Environment, env.env_id)
        mem = await environments.members(db, row)
        owner = mem["data"]

        def listed(kind: str, **kw: Any) -> list[str]:
            return [r["key"] for r in deployer.steps_for(owner, kind, environment=row, members=mem, **kw)]

        assert listed("restore", files=True, first_admin=True) == [
            "check", "backup", "stop_slots", "restore", "files", "start_slots", "finish", "first_admin", "traffic"]
        assert listed("rollback") == ["check", "backup", "stop_slots", "restore", "start_slots", "finish", "traffic"]
        assert listed("reset", start_over=True) == ["backup", "stop_slots", "wipe"]
        assert listed("reset", snapshot=True) == [
            "check", "backup", "stop_slots", "wipe", "restore", "files", "after_import", "start_slots", "finish",
            "traffic"]
        assert listed("backup") == ["release", "backup"]
        assert listed("snapshot", stop_app=True) == ["release", "stop_slots", "export", "start_slots", "store"]
        assert listed("admin") == ["release", "first_admin"] and listed("content") == ["release", "seed"]


async def test_resolve_moves_the_owners_mirror_to_the_slot_that_now_leads(world):
    """Gate 7: the host-less owner's mirror of its data runner follows a change of the lead slot that env_jobs
    writes (Activate, Deactivate, Resolve, Remove slot), not only the next owner job."""
    from slipway.services import env_jobs

    env = await world.setup()
    await world.live(active="blue")
    owner = await get(Instance, env.ids["data"])
    assert owner.app_state["live"]["runner"] == "blue"
    green = await get(Instance, env.ids["green"])
    await env_jobs._resolved(env.env_id, green, actor=None, request=None)
    owner = await get(Instance, env.ids["data"])
    assert owner.app_state["live"]["runner"] == "green"
    assert owner.app_state["live"]["sha"] == green.app_state["live"]["sha"]


async def test_61_a_half_streamed_backup_is_swept_then_forgotten_by_the_next_settle(world):
    """P4 test 61, settle half (S19 has the sweep half): a pull cut by a restart leaves a ``.part`` and an
    unverified row; start-up's sweep removes the ``.part``, and the owner's next settle forgets the row, with no
    SSH. A whole copy beside it is checked and kept."""
    env = await world.setup()
    whole = await _stored_row(env, _name(1), status="unverified", at=1)
    cut = await _stored_row(env, _name(2), status="unverified", at=2)
    final = backup_store.stored_path(env.ids["data"], cut.name, "dump")
    part = final.with_name(final.name + backup_store.PART)
    final.rename(part)
    part.write_bytes(part.read_bytes()[:40])
    assert backup_store.sweep() == 1
    assert not part.exists()
    async with get_sessionmaker()() as db:
        owner = await db.get(Instance, env.ids["data"])
        lines = await data.settle_unverified(None, db, owner, None)
        await db.commit()
    assert lines == [f"Backup {whole.name} was kept on Slipway before Slipway restarted; checked it and kept it",
                     f"Backup {cut.name} never finished before Slipway restarted; forgot it"]
    assert (await get(Backup, whole.id)).status == "ready" and await get(Backup, cut.id) is None
    assert stored_files(env) == [f"{whole.name}.db.sbc"]
    assert not world.multi.opened
