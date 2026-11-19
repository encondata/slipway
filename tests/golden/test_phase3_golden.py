"""Phase 3 as built, recorded (P5 test 64, the phase 3 half of P4 test 70; plan Decision 31).

Phases 4 and 5 change the engine under environments on SSH hosts; none of that may change what Slipway does for
them, or for an instance outside an environment. This module runs three scenarios through the real API-level
services (``environments.validate_create`` and ``create``, ``jobs.queue_job``, the deployer and ``env_jobs``) on
the fake hosts of tests/fake_hosts.py, with ServerSherpa's phase 3 slipway.yml frozen next to this file
(``serversherpa_p3.slipway.yml``, a copy of docs/examples/serversherpa.slipway.yml before phase 4 changed it), and
compares what happened with ``phase3.json``:

- ``bluegreen``: a Blue/Green environment in mode server: the chain (data server, blue, activate), a deploy to the
  idle slot, Activate green, a data server deploy, Publish, the data owner's backup, snapshot, restore and reset, a
  failed deploy and its Discard, Remove a slot, and Delete;
- ``single``: a Single environment in mode slot: its chain, a deploy in place, a backup and a restore;
- ``standalone``: an instance outside any environment, deployed twice.

For every job: the steps as queued (key and name, as ``deployer.steps_for`` and ``environments.env_steps_for``
give them) and as run (with status and note), its status and error, what the app ran on each host (its log, the
docker commands, the names the smoke test asked for, the first admin's arguments), every Switchyard and
Cloudflare request with its body, the names the public check asked for, and the ``.env`` the job wrote. Ids, the
temporary folder, times and sizes are replaced, so the record doesn't depend on the run.

Some step notes hold a raw path under the scenario's folder and are clipped at a fixed width (300 characters), so
what survives the clip depends on how long the folder's path is. Each scenario therefore runs in a folder of
exactly ``TMP_LEN`` characters (``scenario_folder``), wherever pytest's temporary folder is and however long it is,
and ``Norm`` replaces a path the clip cut short as well as whole ones.

The scenarios are importable: ``await bluegreen(manifest_text, tmp_path, monkeypatch)`` (and ``single``,
``standalone``) returns the record, so a later test can run them with another slipway.yml (P4 test 70 runs them
with the phase 4 example). ``SLIPWAY_WRITE_GOLDEN=1`` rewrites phase3.json from this run; nothing else may change
it, and CI never sets it.
"""

from __future__ import annotations

import atexit
import io
import json
import os
import re
import shutil
import tarfile
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from slipway.db.session import get_sessionmaker
from slipway.models import Backup, Deployment, Environment, Host, Instance, Repository, Snapshot, User
from slipway.services import cloudflare, deployer, environments, jobs, traffic
from tests import fake_switchyard
from tests.conftest import make_user
from tests.fake_cloudflare import ZONE, FakeCloudflare
from tests.fake_hosts import MultiRemote, configure_cloudflare
from tests.test_deployer import ARCHIVE_TOP, FakeGitHub

HERE = Path(__file__).parent
FROZEN = HERE / "serversherpa_p3.slipway.yml"
GOLDEN = HERE / "phase3.json"

ENV_EXAMPLE = """\
STACK_ENV=CHANGEME
STACK_DOMAIN=CHANGEME
STACK_PROXY_IP=CHANGEME
STACK_REPO_DIR=CHANGEME
STACK_IMAGE_TAG=CHANGEME
STACK_APPS=none
SS_LOG_LEVEL=INFO
SS_SPACES_BUCKET=serversherpa
POSTGRES_PASSWORD=CHANGEME
SPACES_SECRET_KEY=CHANGEME
SS_JWT_SECRET=CHANGEME
SS_TOTP_ENCRYPTION_KEY=CHANGEME
SS_PASSWORD_PEPPER=CHANGEME
SS_WIKI_SERVICE_TOKEN=CHANGEME
"""

# ServerSherpa's deploy/stack/ss-stack, faked. Each call is logged in $APP_LOG with the release whose .env it saw.
# The database is the file <state>/db: an app slot attached to the data server (STACK_EXTERNAL_DATA=1) uses the
# data server's state folder, which the test gives its host as $SS_DATA_STATE. The database lives in a "volume"
# (a line in the host's $FAKE_VOLUME_FILE, which the fake docker lists and removes) that starting the data
# services creates: a new one is empty, so a Reset that removes the volume empties the database.
SS_STACK = r"""#!/bin/sh
cmd=$1; dir=$2; shift 2
val() { sed -n "s/^$1=//p" "$dir/.env"; }
repo=$(val STACK_REPO_DIR)
echo "$cmd ${repo##*/}" >> "$APP_LOG"
if [ "$(val STACK_EXTERNAL_DATA)" = 1 ]; then db="$SS_DATA_STATE"; else db="$dir/../state"; fi
mkdir -p "$db"
volume() {
  [ "$(val STACK_EXTERNAL_DATA)" = 1 ] && return 0
  e=$(val STACK_ENV)
  if ! grep -q "^ss-$e-db_pgdata " "$FAKE_VOLUME_FILE" 2>/dev/null; then
    rm -f "$db/db" "$db/files"; echo "ss-$e-db_pgdata ss-$e-db" >> "$FAKE_VOLUME_FILE"
  fi
}
case "$cmd" in
  build|down|clear-sessions) ;;
  data) volume ;;
  up)
    volume
    [ -n "$FAIL_FLAG" ] && [ -f "$FAIL_FLAG" ] && { echo "migration failed" >&2; exit 1; }
    echo "MIGRATED $(val STACK_ENV)" >> "$db/db" ;;
  has-data)
    if [ "$(val STACK_EXTERNAL_DATA)" != 1 ] && ! grep -q "^ss-$(val STACK_ENV)-db_pgdata " "$FAKE_VOLUME_FILE" 2>/dev/null
    then exit 3; fi
    if [ "$1" = --server ]; then [ -f "$db/db" ] && exit 0; exit 3; fi
    [ "$(val STACK_DB_PUBLISH)" = 1 ] && exit 4
    [ -f "$db/db" ] && exit 0; exit 3 ;;
  pgdump) { echo "DB:"; cat "$db/db"; } > "$1" ;;
  verify-dump) [ "$(head -n 1 "$1")" = "DB:" ] ;;
  revision) cat "$db/rev" 2>/dev/null ;;
  accepts) exit 0 ;;
  restore) tail -n +2 "$1" > "$db/db" ;;
  export-objects) { echo "FILES:"; cat "$db/files" 2>/dev/null; } > "$1" ;;
  import-objects) tail -n +2 "$1" > "$db/files" ;;
  seed) echo SEEDED >> "$db/db" ;;
  admin)
    IFS= read -r pw || pw=""
    echo "args=$* pwlen=${#pw}" >> "$ADMIN_LOG"
    exit 0 ;;
esac
exit 0
"""

SETTINGS = {"STACK_DOMAIN": "uat.example.com", "STACK_PROXY_IP": "10.0.0.2"}
SECRETS = {"POSTGRES_PASSWORD": "p" * 64, "SPACES_SECRET_KEY": "s" * 64, "SS_JWT_SECRET": "j" * 64,
           "SS_TOTP_ENCRYPTION_KEY": "t" * 43 + "=", "SS_PASSWORD_PEPPER": "e" * 64, "SS_WIKI_SERVICE_TOKEN": "w" * 64}
ADMIN = {"fields": {"first_name": "Ada", "last_name": "Lovelace", "email": "ada@example.com"}, "mode": "password",
         "password": "correct-horse-battery"}
HOSTS = {"blue": "10.0.0.11", "green": "10.0.0.12", "data": "10.0.0.13", "solo": "10.0.0.21"}
TRAFFIC_ADDRESS = "10.0.0.2"
USER_EMAIL = "golden@example.com"
# How long the scenario's folder is, resolved: the length phase3.json was recorded with.
TMP_LEN = 117
CUT_TMP = "<TMP, cut>"


def _host_id(name: str) -> uuid.UUID:
    """A fixed id per name, unlike the others in its first 8 characters too (``Norm`` replaces those)."""
    return uuid.uuid5(uuid.NAMESPACE_URL, f"https://slipway.invalid/golden/{name}")


def _archive(dest: Path, files: dict[str, str]) -> int:
    """A GitHub-style source tarball; scripts under deploy/ are executable, as they are in the repository."""
    with tarfile.open(dest, "w:gz") as tar:
        top = tarfile.TarInfo(ARCHIVE_TOP)
        top.type, top.mode = tarfile.DIRTYPE, 0o755
        tar.addfile(top)
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(f"{ARCHIVE_TOP}/{name}")
            info.size, info.mode = len(data), 0o755 if name == "deploy/stack/ss-stack" else 0o644
            tar.addfile(info, io.BytesIO(data))
    return dest.stat().st_size


def github(manifest_text: str, env_example: str) -> type[FakeGitHub]:
    files = {"slipway.yml": manifest_text, "deploy/stack/env.example": env_example, "deploy/stack/ss-stack": SS_STACK}

    class GH(FakeGitHub):
        async def download_tarball(self, repo_id, sha, dest: Path):
            FakeGitHub.calls.append(f"tarball {repo_id}@{sha}")
            return _archive(dest, files)

    return GH


# ------------------------------------------------------------------------------- normalising


def scenario_folder(tmp: Path) -> Path:
    """A new, empty, resolved folder whose path is exactly ``TMP_LEN`` characters long.

    It is made inside ``tmp``, or its parent, when the path fits there (pytest cleans both up); otherwise under the
    system's temporary folder or /tmp, removed when the test run ends.
    """
    tmp = Path(os.path.realpath(tmp))
    for base, mine in ((tmp, True), (tmp.parent, True), (Path(tempfile.gettempdir()), False), (Path("/tmp"), False)):
        base = Path(os.path.realpath(base))
        pad = TMP_LEN - len(str(base)) - 1 - len("g-") - 8
        if pad < 0 or not base.is_dir():
            continue
        while True:
            path = base / f"g-{uuid.uuid4().hex[:8]}{'x' * pad}"
            try:
                path.mkdir()
                break
            except FileExistsError:
                continue
        if not mine:
            atexit.register(shutil.rmtree, path, True)
        assert len(str(path)) == TMP_LEN and os.path.realpath(path) == str(path), path
        return path
    raise RuntimeError(f"No temporary folder is short enough for a {TMP_LEN}-character scenario folder")


class Norm:
    """Replaces what changes between runs. Rows the scenario names (``label``) become ``<name>`` in every form an
    id takes in text (with dashes, hex, and the 12 and 8 character prefixes); other ids become ``<ID>``."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = str(tmp)
        self.names: dict[str, str] = {}

    def label(self, value: uuid.UUID | str, name: str) -> None:
        self.names[str(value)] = name

    def text(self, value: str) -> str:
        value = value.replace(os.path.realpath(self.tmp), "<TMP>").replace(self.tmp, "<TMP>")
        value = self._cut_tail(value)
        for ident, name in sorted(self.names.items(), key=lambda kv: -len(kv[0])):
            hexed = ident.replace("-", "")
            for form in (ident, hexed, hexed[:12], hexed[:8]):
                value = value.replace(form, f"<{name}>")
        value = re.sub(r"\b[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}\b", "<ID>", value)
        value = re.sub(r"\d{8}T\d{6}Z?", "<STAMP>", value)
        value = re.sub(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?(\.\d+)?( UTC|Z|\+00:00)?", "<TIME>", value)
        value = re.sub(r"\b\d+(\.\d+)? (B|KiB|MiB|GiB|bytes)\b", "<SIZE>", value)
        return value

    def _cut_tail(self, value: str) -> str:
        """A clipped text that ends in the first characters of the folder's path ends in ``CUT_TMP`` instead: those
        characters name this machine's temporary folder, not anything Slipway did."""
        for form in dict.fromkeys((os.path.realpath(self.tmp), self.tmp)):
            for k in range(len(form) - 1, 1, -1):
                if value.endswith(form[:k]) and (len(value) == k or value[-k - 1].isspace()):
                    return value[:-k] + CUT_TMP
        return value

    def value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.value(v) for v in value]
        if isinstance(value, dict):
            return {self.text(str(k)): self.value(v) for k, v in value.items()}
        return value


class Sites:
    """What the public check through Switchyard's traffic address reaches: 200 for every name, recorded."""

    def __init__(self) -> None:
        self.asked: list[str] = []

    def factory(self, verify: bool) -> httpx.MockTransport:
        def handle(request: httpx.Request) -> httpx.Response:
            self.asked.append(request.headers["host"])
            return httpx.Response(200)

        return httpx.MockTransport(handle)


@dataclass
class Ctx:
    """``validate_create``'s context: the golden user, who holds every permission."""

    user: Any

    def can(self, permission: str) -> bool:
        return True


@dataclass
class World:
    """One scenario: the fake hosts, Switchyard, Cloudflare and the public check, and what each job did."""

    tmp: Path
    multi: MultiRemote
    gh: type[FakeGitHub]
    sy: fake_switchyard.FakeSwitchyard
    cf: FakeCloudflare
    sites: Sites
    norm: Norm
    submitted: list[tuple[uuid.UUID, tuple]] = field(default_factory=list)
    user_id: uuid.UUID | None = None
    env_id: uuid.UUID | None = None
    _sy: int = 0
    _cf: int = 0
    _sites: int = 0

    async def user(self, db) -> User:
        return await db.get(User, self.user_id)

    async def queue(self, *, slot: str | None = None, kind: str = "deploy", **kw: Any) -> uuid.UUID:
        """A job as the API queues it (``jobs.queue_job``): a member's job when ``slot`` is given, else an
        environment-level job; or a standalone instance's job with ``instance_id``."""
        async with get_sessionmaker()() as db:
            user = await self.user(db)
            instance_id = kw.pop("instance_id", None)
            if instance_id is not None:
                dep = await jobs.queue_job(db, instance=await db.get(Instance, instance_id), user=user, kind=kind,
                                           **kw)
            else:
                env = await db.get(Environment, self.env_id)
                mem = await environments.members(db, env)
                if slot is not None:
                    dep = await jobs.queue_job(db, instance=mem[slot], environment=env, user=user, kind=kind, **kw)
                else:
                    dep = await jobs.queue_job(db, environment=env, user=user, kind=kind, **kw)
            await db.commit()
            return dep.id

    async def run(self, name: str, dep_id: uuid.UUID, *, env_file: tuple[str, str] | None = None) -> dict:
        """Run a queued job and record it as ``name``. ``env_file``: (host, slug) whose .env to keep."""
        self.norm.label(dep_id, name)
        async with get_sessionmaker()() as db:
            queued = await db.get(Deployment, dep_id)
            queued_steps = [[s["key"], s["name"]] for s in queued.steps or []]
        await deployer.run_deployment(dep_id, connect=self.multi.connect, github=self.gh)
        async with get_sessionmaker()() as db:
            dep = await db.get(Deployment, dep_id)
        n = self.norm
        out: dict[str, Any] = {
            "kind": dep.kind, "status": dep.status, "error": n.text(dep.error or ""),
            "options": n.value({k: v for k, v in (dep.options or {}).items() if k != "confirm"}),
            "queued": [[k, n.text(v)] for k, v in queued_steps],
            "steps": [[s["key"], n.text(s["name"]), s["status"], n.text(s.get("note") or "")] for s in dep.steps or []],
            "hosts": {}, "switchyard": [], "cloudflare": [], "checked": [],
        }
        for host in self.multi.hosts.values():
            seen = {"app": host.calls(), "docker": host.docker(), "smoke": host.log("CURL_LOG"),
                    "admin": host.log("ADMIN_LOG")}
            seen = {k: [n.text(line) for line in v] for k, v in seen.items() if v}
            if seen:
                out["hosts"][host.name] = seen
        calls = self.sy.calls[self._sy:]
        self._sy = len(self.sy.calls)
        out["switchyard"] = [{"call": str(c), "body": n.value(c.body)} if c.method else str(c) for c in calls]
        cf_calls = self.cf.calls[self._cf:]
        self._cf = len(self.cf.calls)
        out["cloudflare"] = [n.value(c) for c in cf_calls]
        out["checked"] = self.sites.asked[self._sites:]
        self._sites = len(self.sites.asked)
        if env_file is not None:
            path = self.multi[env_file[0]].folder(env_file[1]) / "shared" / ".env"
            out["env_file"] = n.text(path.read_text()) if path.exists() else None
        out["submitted"] = [self.norm.names.get(str(d), "<new>") for d, _ in self.submitted]
        self.multi.clear()
        return out

    async def next_submitted(self) -> uuid.UUID:
        dep_id, _keys = self.submitted.pop(0)
        return dep_id

    async def environment(self) -> dict:
        """The environment row's phase 3 fields."""
        async with get_sessionmaker()() as db:
            env = await db.get(Environment, self.env_id)
            if env is None:
                return {"gone": True}
            mem = await environments.members(db, env)
            active = environments.active_member(env, mem)
            return self.norm.value({
                "status": env.status, "data_mode": env.data_mode, "active": active.slot if active else None,
                "hostnames": env.hostnames, "traffic": env.traffic, "secrets_version": env.secrets_version,
                "notice": {k: v for k, v in (env.notice or {}).items() if k != "at"} or None,
                "members": {s: {"slug": m.slug, "status": m.status, "host": m.host.name if m.host else None}
                            for s, m in sorted(mem.items())},
                "deleted": env.deleted_at is not None,
            })


async def _world(tmp: Path, monkeypatch, manifest_text: str, env_example: str) -> World:
    tmp = scenario_folder(tmp)  # everything the scenario makes lives here, at the recorded length
    sy = fake_switchyard.install(monkeypatch)
    await fake_switchyard.configure(traffic_address=TRAFFIC_ADDRESS)
    sites = Sites()
    monkeypatch.setattr(traffic, "transport_factory", sites.factory)

    async def instantly(_seconds):
        return None

    monkeypatch.setattr(traffic, "sleep", instantly)
    cf = FakeCloudflare()
    zone_id = cf.add_zone(ZONE)
    monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(cf.handle))
    await configure_cloudflare()
    multi = MultiRemote(tmp / "hosts", names=HOSTS)
    for host in multi.hosts.values():
        host.env["FAKE_VOLUME_FILE"] = str(host.tmp / "volumes")
    world = World(tmp=tmp, multi=multi, gh=github(manifest_text, env_example), sy=sy, cf=cf, sites=sites,
                  norm=Norm(tmp))
    world.norm.label(zone_id, "zone")
    for name in (*HOSTS, "repo"):
        world.norm.label(_host_id(name), f"host-{name}" if name != "repo" else "repo")
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, keys: world.submitted.append((dep_id, keys)))
    user = await make_user(USER_EMAIL)
    world.user_id = user.id
    async with get_sessionmaker()() as db:
        for name, address in HOSTS.items():
            db.add(Host(id=_host_id(name), name=f"h-{name}", hostname=address, username="deploy",
                        host_key="ssh-ed25519 AAAA", metrics={}, deploy_root=str(multi[name].root)))
        db.add(Repository(id=_host_id("repo"), github_id=7, full_name="acme/serversherpa", owner="acme",
                          name="serversherpa", html_url="https://github.com/acme/serversherpa", detected_config={}))
        await db.commit()
    return world


async def _create(world: World, manifest_text: str, env_example: str, *, name: str, data_mode: str,
                  hosts: dict[str, str], traffic: dict) -> dict:
    """``POST /environments`` through its service: the plan (``?check=true``'s answer) and the rows."""

    async def read(repo, branch, path):
        return {"slipway.yml": manifest_text, "deploy/stack/env.example": env_example}.get(path)

    async with get_sessionmaker()() as db:
        user = await world.user(db)
        request = environments.NewEnvironment(
            name=name, repository_id=_host_id("repo"), data_mode=data_mode,
            hosts={slot: _host_id(h) for slot, h in hosts.items()}, settings=dict(SETTINGS), traffic=traffic,
            first_admin=dict(ADMIN))
        plan = await environments.validate_create(db, request, Ctx(user), read_file=read)
        answer = plan.to_json()
        env = await environments.create(db, plan, Ctx(user))
        env.app_secrets = dict(SECRETS)  # the generated ones, made fixed for the record
        await db.commit()
        world.env_id = env.id
        world.norm.label(env.id, f"env-{name}")
        for slot, member in (await environments.members(db, env)).items():
            world.norm.label(member.id, f"{name}-{slot}")
    world.norm.label(world.user_id, "user")
    return world.norm.value(answer)


def _data_state(world: World, data_host: str, slug: str, *slots: str) -> None:
    """The attached slots' hosts find the data server's database (see SS_STACK)."""
    for host in slots:
        world.multi[host].env["SS_DATA_STATE"] = str(world.multi[data_host].folder(slug) / "state")


async def _latest_backup(world: World, slot: str) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, world.env_id)
        owner = (await environments.members(db, env))[slot]
        return await db.scalar(select(Backup.id).where(Backup.instance_id == owner.id)
                               .order_by(Backup.taken_at.desc()).limit(1))


# ---------------------------------------------------------------------------------- scenarios


async def bluegreen(manifest_text: str, tmp: Path, monkeypatch, *, env_example: str = ENV_EXAMPLE) -> dict:
    """(a) Blue/Green in mode server on three SSH hosts."""
    world = await _world(tmp, monkeypatch, manifest_text, env_example)
    out: dict[str, Any] = {}
    out["create"] = await _create(world, manifest_text, env_example, name="uat", data_mode="server",
                                  hosts={"blue": "blue", "green": "green", "data": "data"},
                                  traffic={"switch": "switchyard", "dns": {}})
    _data_state(world, "data", "uat-data", "blue", "green")
    w = world

    # The chain: the data server, then blue (it goes live), then blue's activate.
    out["deploy_data"] = await w.run("deploy-data", await w.queue(slot="data", options={"chain": True}),
                                     env_file=("data", "uat-data"))
    out["deploy_blue"] = await w.run("deploy-blue", await w.next_submitted(), env_file=("blue", "uat-blue"))
    out["activate_blue"] = await w.run("activate-blue", await w.next_submitted())
    out["after_chain"] = await w.environment()
    # A deploy to the idle slot, then Switch to it.
    out["deploy_green"] = await w.run("deploy-green", await w.queue(slot="green"), env_file=("green", "uat-green"))
    out["activate_green"] = await w.run("activate-green", await w.queue(options={"slot": "green"},
                                                                        kind="activate"))
    # The data server again: its sync, and the check of the active slot.
    out["update_data"] = await w.run("update-data", await w.queue(slot="data"), env_file=("data", "uat-data"))
    out["publish"] = await w.run("publish", await w.queue(kind="publish"))
    # The data owner's jobs.
    out["backup"] = await w.run("backup", await w.queue(slot="data", kind="backup"))
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, w.env_id)
        owner = (await environments.members(db, env))["data"]
        snap = Snapshot(name="uat-golden", status="pending", origin="instance", app="serversherpa", source="uat",
                        source_instance_id=owner.id)
        db.add(snap)
        await db.commit()
        w.norm.label(snap.id, "snapshot")
    out["snapshot"] = await w.run("snapshot", await w.queue(slot="data", kind="snapshot", snapshot_id=snap.id))
    backup_id = await _latest_backup(w, "data")
    out["restore"] = await w.run("restore", await w.queue(slot="data", kind="restore", restore_backup_id=backup_id))
    out["reset"] = await w.run("reset", await w.queue(slot="data", kind="reset", options={"seed": True}))
    out["after_data_jobs"] = await w.environment()
    # A deploy to blue (now idle) that fails at start, and its Discard.
    flag = w.tmp / "fail-blue"
    flag.write_text("")
    w.multi["blue"].env["FAIL_FLAG"] = str(flag)
    out["failed_blue"] = await w.run("failed-blue", await w.queue(slot="blue"))
    flag.unlink()
    out["discard_blue"] = await w.run("discard-blue", await w.queue(kind="discard", options={"slot": "blue"}))
    out["remove_blue"] = await w.run("remove-blue", await w.queue(kind="remove_slot", options={"slot": "blue"}))
    out["teardown"] = await w.run("teardown", await w.queue(kind="teardown", options={"confirmed": True}))
    out["after_teardown"] = await w.environment()
    out["left"] = {"switchyard": sorted(w.norm.value(list(w.sy.hosts_by_domain()))),
                   "dns": sorted(r["name"] for r in w.cf.records.values())}
    return out


async def single(manifest_text: str, tmp: Path, monkeypatch, *, env_example: str = ENV_EXAMPLE) -> dict:
    """(b) A Single environment in mode slot: blue keeps the data."""
    world = await _world(tmp, monkeypatch, manifest_text, env_example)
    w = world
    out: dict[str, Any] = {}
    out["create"] = await _create(w, manifest_text, env_example, name="one", data_mode="slot", hosts={"blue": "blue"},
                                  traffic={"switch": "switchyard", "dns": None})
    out["deploy_blue"] = await w.run("deploy-blue", await w.queue(slot="blue", options={"chain": True}),
                                     env_file=("blue", "one-blue"))
    while w.submitted:  # the chain's activate
        dep_id = await w.next_submitted()
        out.setdefault("chain", []).append(await w.run(f"chain-{len(out.get('chain', []))}", dep_id))
    out["after_chain"] = await w.environment()
    out["redeploy_blue"] = await w.run("redeploy-blue", await w.queue(slot="blue"), env_file=("blue", "one-blue"))
    out["backup"] = await w.run("backup", await w.queue(slot="blue", kind="backup"))
    backup_id = await _latest_backup(w, "blue")
    out["restore"] = await w.run("restore", await w.queue(slot="blue", kind="restore", restore_backup_id=backup_id))
    out["after"] = await w.environment()
    return out


async def standalone(manifest_text: str, tmp: Path, monkeypatch, *, env_example: str = ENV_EXAMPLE) -> dict:
    """(c) An instance outside any environment, with its own data, published through Switchyard."""
    world = await _world(tmp, monkeypatch, manifest_text, env_example)
    w = world
    async with get_sessionmaker()() as db:
        inst = Instance(name="solo", slug="solo-prod", branch="main", host_id=_host_id("solo"),
                        repository_id=_host_id("repo"), env={}, ports=[], volumes=[], build_source="app",
                        app_settings={"STACK_DOMAIN": "solo.example.com", "STACK_PROXY_IP": "10.0.0.2"},
                        app_secrets=dict(SECRETS),
                        routes=[{"hostname": "api.solo.example.com", "service": "api", "container": 8000,
                                 "tls_mode": "auto"}])
        db.add(inst)
        await db.commit()
        w.norm.label(inst.id, "solo")
    w.norm.label(w.user_id, "user")
    out: dict[str, Any] = {}
    out["deploy1"] = await w.run("deploy-1", await w.queue(instance_id=inst.id), env_file=("solo", "solo-prod"))
    out["deploy2"] = await w.run("deploy-2", await w.queue(instance_id=inst.id), env_file=("solo", "solo-prod"))
    out["backup"] = await w.run("backup", await w.queue(instance_id=inst.id, kind="backup"))
    return out


SCENARIOS = {"bluegreen": bluegreen, "single": single, "standalone": standalone}


# ------------------------------------------------------------------------------------- compare


def check(name: str, got: dict) -> None:
    """Compare ``got`` with phase3.json's ``name`` (or store it there with SLIPWAY_WRITE_GOLDEN=1)."""
    got = json.loads(json.dumps(got, sort_keys=True, default=str))
    if os.environ.get("SLIPWAY_WRITE_GOLDEN"):
        stored = json.loads(GOLDEN.read_text()) if GOLDEN.exists() else {}
        stored[name] = got
        GOLDEN.write_text(json.dumps(stored, indent=1, sort_keys=True) + "\n")
        return
    want = json.loads(GOLDEN.read_text())[name]
    for key in want:
        assert got.get(key) == want[key], f"{name}: {key} differs from phase 3"
    assert set(got) == set(want), f"{name}: the record has other parts than phase 3's"


@pytest.mark.parametrize("name", sorted(SCENARIOS))
async def test_phase_3_behaves_as_recorded(name, tmp_path, monkeypatch):
    check(name, await SCENARIOS[name](FROZEN.read_text(), tmp_path, monkeypatch))


def test_the_frozen_manifest_is_phase_3s():
    """The scenarios' input never follows the example's later edits."""
    text = FROZEN.read_text()
    assert "edge:" not in text and "managed:" not in text and text.startswith("# slipway.yml for ServerSherpa")
