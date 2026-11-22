"""Data safety in the deployer (phase 2): the pre-deploy backup with the live release's commands, the host lock,
the step lists, redaction, the live state saved at finish, the first admin and starter content; restore, roll back,
reset, Start over, Back up now, snapshots (take, seed, reset from one), retry, destroy, folder moves and recovery.

The app is a small shell script (APP_SCRIPT) whose "database" is the file ``$STATE/db``; commands run in a real
shell through ShellRemote, with the fake ``docker`` and ``df`` first on PATH. Nothing here mocks the deployer.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select, update

from slipway.db.session import get_sessionmaker
from slipway.models import AuditEvent, Backup, Deployment, FirstAdmin, Host, Instance, Repository, Snapshot
from slipway.services import data, deployer, manifest, snapfile, snapshots, ssh
from tests.conftest import make_user
from tests.test_deployer import SHA, FakeGitHub, FakeRemote, _connect, _instance, write_source_archive
from tests.test_final_remote import SHELLS, ShellRemote, _local, docker_shim  # noqa: F401

DATA_YML = """\
version: 1
name: Demo
env_file: deploy/env.example
placeholder: CHANGEME
settings:
  APP_DOMAIN: {label: Base domain, required: true}
vars:
  APP_ENV: "{slipway.slug}"
  APP_REPO: "{slipway.release}"
secrets:
  APP_SECRET: hex
  APP_KEY: {kind: fernet, identity: true}
services:
  web: {port: 8080, port_var: APP_WEB_PORT, hostname: "www.{APP_DOMAIN}"}
projects: ["demo-{APP_ENV}-web", "demo-{APP_ENV}-db"]
images: ["demo-web:{slipway.sha12}"]
data:
  app: demo
  format: demo-v1
  volumes:
    - {name: "demo-{APP_ENV}-db_data", holds: database}
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
  seed: [sh, deploy/app, seed, "{slipway.env_dir}"]
first_admin:
  command: [sh, deploy/app, admin, "{slipway.env_dir}", --email, "{admin.email}", --name, "{admin.name}"]
  fields:
    email: {label: Email, kind: email}
    name: {label: Name}
  password: {stdin: true, args: [--password-stdin]}
  invite: {label: Email them a link, args: [--invite]}
  exists_codes: [10]
  messages: {5: "The app refused the account."}
"""

# The same app with a files store: snapshots and resets carry the files too.
FILES_YML = DATA_YML.replace("""  volumes:
    - {name: "demo-{APP_ENV}-db_data", holds: database}
""", """  volumes:
    - {name: "demo-{APP_ENV}-db_data", holds: database}
  files: {format: demo-files-v1, label: Uploads}
""").replace("""  seed: [sh, deploy/app, seed, "{slipway.env_dir}"]
""", """  seed: [sh, deploy/app, seed, "{slipway.env_dir}"]
  export_files: [sh, deploy/app, export-objects, "{slipway.env_dir}", "{slipway.out}"]
  import_files: [sh, deploy/app, import-objects, "{slipway.env_dir}", "{slipway.in}"]
  after_import: [sh, deploy/app, clear-sessions, "{slipway.env_dir}"]
""")

ENV_EXAMPLE = "APP_ENV=dev\nAPP_DOMAIN=example.com\nAPP_SECRET=CHANGEME\nAPP_KEY=CHANGEME\n"

# The app: its database is $STATE/db. Each call is logged with the release whose .env it saw (APP_REPO).
APP_SCRIPT = r"""
cmd=$1; dir=$2; shift 2
repo=$(sed -n 's/^APP_REPO=//p' "$dir/.env")
echo "$cmd ${repo##*/}" >> "$APP_LOG"
mkdir -p "$STATE"
# With $FAKE_VOLUME_FILE the database lives in a "volume" that starting the data services creates: a new one is empty.
volume() {
  if [ -n "$FAKE_VOLUME_FILE" ] && ! grep -q 'db_data ' "$FAKE_VOLUME_FILE" 2>/dev/null; then
    e=$(sed -n 's/^APP_ENV=//p' "$dir/.env"); rm -f "$STATE/db"; echo "demo-$e-db_data demo-$e-db" >> "$FAKE_VOLUME_FILE"
  fi
}
case "$cmd" in
  build|down) ;;
  data) volume ;;
  up)
    [ -n "$LEAK" ] && { echo "secret is $(sed -n 's/^APP_SECRET=//p' "$dir/.env") and $(sed -n 's/^DATABASE_URL=//p' "$dir/.env")"; exit 1; }
    volume
    [ -n "$FAIL_FLAG" ] && [ -f "$FAIL_FLAG" ] && { echo "migration failed" >&2; exit 1; }
    echo MIGRATED >> "$STATE/db"
    sed -n 's/^APP_KEY=//p' "$dir/.env" > "$STATE/keys" ;;
  has-data)
    case "$(cat "$STATE/where" 2>/dev/null)" in elsewhere) exit 4 ;; broken) exit 9 ;; esac
    [ -n "$FAKE_VOLUME_FILE" ] && ! grep -q 'db_data ' "$FAKE_VOLUME_FILE" 2>/dev/null && exit 3
    [ -f "$STATE/db" ] && exit 0; exit 3 ;;
  pgdump)
    [ -n "$DUMP_SLEEP" ] && sleep "$DUMP_SLEEP"
    [ -n "$DUMP_FAIL" ] && { echo "pg_dump: connection refused" >&2; exit 1; }
    [ -n "$DUMP_EMPTY" ] && { : > "$1"; exit 0; }
    { echo "DB:"; cat "$STATE/db"; } > "$1" ;;
  verify-dump) [ "$(head -n 1 "$1")" = "DB:" ] ;;
  revision) cat "$STATE/rev" 2>/dev/null; echo "noise on stderr" >&2 ;;
  accepts)
    r=$(cat "$1")
    for u in $UNKNOWN_REVS; do [ "$r" = "$u" ] && { echo "unknown revision $r"; exit 3; }; done
    exit 0 ;;
  restore)
    [ -n "$RESTORE_SLEEP" ] && sleep "$RESTORE_SLEEP"
    [ -n "$RESTORE_FAIL" ] && { : > "$STATE/db"; echo "pg_restore: error: could not read input" >&2; exit 1; }
    tail -n +2 "$1" > "$STATE/db" ;;
  export-objects) { echo "FILES:"; cat "$STATE/files" 2>/dev/null; } > "$1" ;;
  import-objects) [ -n "$IMPORT_FAIL" ] && { echo "import failed" >&2; exit 1; }; tail -n +2 "$1" > "$STATE/files" || exit 1 ;;
  clear-sessions) ;;
  seed) [ -n "$SEED_FAIL" ] && exit 1; echo SEEDED >> "$STATE/db" ;;
  admin)
    IFS= read -r pw || pw=""
    echo "args=$* pwlen=${#pw}" >> "$ADMIN_LOG"
    exit "${ADMIN_RC:-0}" ;;
esac
exit 0
"""

DF_SHIM = """#!/bin/sh
if [ -n "$FAKE_DF_KB" ]; then
  echo "Filesystem 1024-blocks Used Available Capacity Mounted on"
  echo "fake 999999999 1 $FAKE_DF_KB 1% /"
  exit 0
fi
exec /bin/df "$@"
"""


class DataGitHub(FakeGitHub):
    files = {"slipway.yml": DATA_YML, "deploy/env.example": ENV_EXAMPLE, "deploy/app": APP_SCRIPT}

    async def download_tarball(self, repo_id, sha, dest: Path):
        FakeGitHub.calls.append(f"tarball {repo_id}@{sha}")
        return write_source_archive(dest, self.files)


def _github(yml: str = DATA_YML, script: str = APP_SCRIPT) -> type[DataGitHub]:
    class GH(DataGitHub):
        files = {"slipway.yml": yml, "deploy/env.example": ENV_EXAMPLE, "deploy/app": script}
    return GH


class App:
    """One app instance on a "host" in ``tmp``: its folder, its state, its logs and the remote that runs it."""

    def __init__(self, tmp: Path, env: dict[str, str], shell: str = "sh") -> None:
        self.tmp = tmp
        self.root = tmp / "root"
        self.base = self.root / "web-prod"
        self.state = tmp / "state"
        self.app_log = tmp / "app.log"
        self.admin_log = tmp / "admin.log"
        self.env = {**env, "APP_LOG": str(self.app_log), "STATE": str(self.state), "ADMIN_LOG": str(self.admin_log),
                    "FAKE_DF_KB": str(100 * 1024 * 1024)}
        self.remote = ShellRemote(shell, self.env)
        self.instance_id: uuid.UUID | None = None
        self.user_id: uuid.UUID | None = None

    @property
    def backups(self) -> Path:
        return self.base / "backups"

    def calls(self) -> list[str]:
        return self.app_log.read_text().splitlines() if self.app_log.exists() else []

    def release_of(self, dep_id: uuid.UUID) -> str:
        return f"{SHA[:12]}-{dep_id.hex[:8]}"

    async def seed(self, *, env: dict[str, str] | None = None, **fields) -> None:
        user = await make_user(f"admin-{uuid.uuid4().hex[:6]}@example.com")
        async with get_sessionmaker()() as db:
            host = Host(name="prod-01", hostname="10.0.0.1", username="deploy", host_key="ssh-ed25519 AAAA", metrics={},
                        deploy_root=str(self.root))
            repo = Repository(github_id=42, full_name="acme/web", owner="acme", name="web",
                              html_url="https://github.com/acme/web", detected_config={})
            inst = Instance(name="web", slug="web-prod", branch="main", host=host, repository=repo, env=env or {},
                            ports=[], volumes=[], build_source="app", app_settings={"APP_DOMAIN": "uat.example.com"},
                            **fields)
            db.add(inst)
            await db.commit()
            self.instance_id, self.user_id = inst.id, user.id

    async def queue(self, **fields) -> uuid.UUID:
        async with get_sessionmaker()() as db:
            dep = Deployment(instance_id=self.instance_id, branch="main", triggered_by_id=self.user_id, log="", **fields)
            db.add(dep)
            await db.commit()
            return dep.id

    async def deploy(self, github: type[DataGitHub] = DataGitHub, **fields) -> Deployment:
        dep_id = await self.queue(**fields)
        await deployer.run_deployment(dep_id, connect=_local(self.remote), github=github)
        return await _get(Deployment, dep_id)

    async def instance(self) -> Instance:
        return await _get(Instance, self.instance_id)

    async def backups_rows(self) -> list[Backup]:
        async with get_sessionmaker()() as db:
            return list((await db.scalars(select(Backup).where(Backup.instance_id == self.instance_id)
                                          .order_by(Backup.taken_at))).all())


async def _get(model, ident):
    async with get_sessionmaker()() as db:
        return await db.get(model, ident)


def _steps(dep: Deployment) -> dict[str, str]:
    return {s["key"]: s["status"] for s in dep.steps}


def _note(dep: Deployment, key: str) -> str:
    return next((s.get("note") or "") for s in dep.steps if s["key"] == key)


@pytest.fixture
def app(tmp_path, docker_shim):  # noqa: F811
    env, _ = docker_shim
    df = Path(env["PATH"].split(":")[0]) / "df"
    df.write_text(DF_SHIM)
    df.chmod(0o755)
    return App(tmp_path, env)


@pytest.fixture(params=SHELLS)
def shell_app(request, tmp_path, docker_shim):  # noqa: F811
    env, _ = docker_shim
    df = Path(env["PATH"].split(":")[0]) / "df"
    df.write_text(DF_SHIM)
    df.chmod(0o755)
    return App(tmp_path, env, shell=request.param)


async def _add_first_admin(instance_id: uuid.UUID, *, mode: str = "password", password: str | None = "correct-horse-9",
                           fields: dict | None = None) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        row = FirstAdmin(instance_id=instance_id, fields=fields or {"email": "ada@example.com", "name": "Ada Lovelace"},
                         mode=mode, password=password if mode == "password" else None)
        db.add(row)
        await db.commit()
        return row.id


# ------------------------------------------------------------------ app_command (test 2)


def test_slots_are_quoted_as_one_argument_and_a_missing_one_names_the_command():
    cmd = {"argv": ["deploy/dump", "--to", {"slot": "out"}], "stream": None}
    assert deployer.app_command("/r", cmd, slots={"out": "a'; rm -rf /@x.io"}) == \
        "cd /r && ./deploy/dump --to 'a'\"'\"'; rm -rf /@x.io'"
    with pytest.raises(deployer.DeployError, match=r"^commands\.dump: Slipway gave no value for \{slipway\.out\}$"):
        deployer.app_command("/r", cmd, name="dump")
    admin = {"argv": ["manage", "--email", {"slot": "admin.email"}], "stream": None}
    with pytest.raises(deployer.DeployError, match=r"^first_admin\.command: Slipway gave no value for \{admin\.email\}$"):
        deployer.app_command("/r", admin, name="first_admin")


def test_stream_mode_renders_the_redirect_and_needs_its_file():
    dump = {"argv": ["pg_dump", "-Fc", "db"], "stream": "stdout"}
    restore = {"argv": ["pg_restore", "-d", "db"], "stream": "stdin"}
    assert deployer.app_command("/r", dump, stream_path="/b/x y.partial") == "cd /r && pg_dump -Fc db > '/b/x y.partial'"
    assert deployer.app_command("/r", restore, stream_path="/b/in") == "cd /r && pg_restore -d db < /b/in"
    with pytest.raises(deployer.DeployError, match="no file for its stdout"):
        deployer.app_command("/r", dump, name="dump")
    # The revision is captured from stdout of a plain command.
    assert deployer.app_command("/r", ["show"], stream_path="/j/rev", stream="stdout") == "cd /r && show > /j/rev"


def test_the_lock_line_comes_first_and_the_program_is_execed():
    lock = deployer.LockLine("/b/.slipway-lock", uuid.UUID(int=7), "dump", True)
    command = deployer.app_command("/r", ["deploy/dump", "x"], lock=lock, umask=True)
    assert command.startswith("cd /r && umask 077 && { BOOT=")
    assert command.endswith(" d > /b/.slipway-lock && exec ./deploy/dump x; }")
    plain = deployer.app_command("/r", ["sh", "deploy/app", "up"], lock=deployer.LockLine("/b/l", uuid.UUID(int=7),
                                                                                          "start", False))
    assert "umask" not in plain and plain.endswith(" - > /b/l && exec sh deploy/app up; }")
    # Without a lock, umask or stdin variable the command is exactly what phase 1 ran.
    assert deployer.app_command("/r", ["deploy/run", "a b"]) == "cd /r && ./deploy/run 'a b'"
    assert deployer.UMASK_COMMANDS >= {"dump", "restore", "has_data", "first_admin"}
    assert not deployer.UMASK_COMMANDS & {"build", "start", "stop"}


@pytest.mark.parametrize("shell", SHELLS)
def test_a_locked_command_names_its_own_pid_and_the_password_reaches_the_variable(tmp_path, shell):
    import subprocess
    lock = tmp_path / ".slipway-lock"
    dep = uuid.uuid4()
    prog = tmp_path / "r" / "show"
    prog.parent.mkdir()
    prog.write_text('#!/bin/sh\necho "pid=$$ pw=$PW"\n')
    prog.chmod(0o755)
    command = deployer.app_command(str(prog.parent), ["./show"], lock=deployer.LockLine(str(lock), dep, "first_admin", True),
                                   umask=True, env_from_stdin="PW")
    out = subprocess.run([shell, "-c", command], input="s3cret pass\n", capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    pid = out.stdout.split()[0].removeprefix("pid=")
    words = lock.read_text().split()
    assert words[0] == str(dep) and words[2] == pid and words[3:] == ["first_admin", "d"]  # exec kept the PID
    assert out.stdout.strip().endswith("pw=s3cret pass")
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600  # written under umask 077
    # Nothing on stdin: exit 97, and the program never ran.
    out = subprocess.run([shell, "-c", command], input="", capture_output=True, text=True, timeout=30)
    assert out.returncode == 97 and "pid=" not in out.stdout


# -------------------------------------------------------------- steps (I7 regression, test 30)


def test_dockerfile_and_compose_keep_their_exact_steps():
    assert [s["key"] for s in deployer.new_steps(_instance())] == [
        "resolve", "source", "upload", "settings", "ports", "build", "start", "finish", "proxy"]
    assert [s["key"] for s in deployer.new_steps(_instance(build_source="compose"))] == [
        "resolve", "source", "upload", "settings", "ports", "build", "start", "finish", "proxy"]
    app = _instance(build_source="app")
    assert [s["key"] for s in deployer.steps_for(app)] == [
        "resolve", "source", "upload", "manifest", "ports", "settings", "build", "backup", "start", "finish", "proxy"]
    seeded = deployer.steps_for(app, snapshot=True, first_admin=True)
    assert [s["key"] for s in seeded][6:] == ["build", "check", "backup", "stop", "restore", "files", "after_import",
                                              "start", "finish", "first_admin", "proxy"]
    assert {s["key"]: s["name"] for s in seeded}["restore"] == "Restore the snapshot's database"
    rollback = deployer.steps_for(app, "rollback", rollback_of=uuid.UUID(int=0xABCDEF12 << 96))
    assert {s["key"]: s["name"] for s in rollback}["restore"] == "Restore the backup from before deployment abcdef12"
    assert [s["key"] for s in deployer.steps_for(app, "reset", start_over=True)] == ["release", "backup", "stop", "reset"]
    assert [s["key"] for s in deployer.steps_for(app, "backup", stopped=True)] == ["release", "backup", "restop"]
    assert [s["key"] for s in deployer.steps_for(app, "snapshot", stop_app=True)] == [
        "release", "stop", "export", "restart", "store"]
    assert [s["key"] for s in deployer.steps_for(app, "admin")] == ["release", "first_admin"]


@pytest.mark.parametrize("build_source", ["dockerfile", "compose"])
async def test_dockerfile_and_compose_deploys_get_no_host_lock(build_source):
    from tests.test_deployer import _seed
    dep_id = await _seed({})
    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, dep_id)
        await db.execute(update(Instance).where(Instance.id == dep.instance_id).values(build_source=build_source))
        await db.commit()
    remote = FakeRemote()
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded", dep.log
    assert [s["key"] for s in dep.steps] == ["resolve", "source", "upload", "settings", "ports", "build", "start",
                                             "finish", "proxy"]
    # (take_dir only accepts a folder holding these names as Slipway's own; it writes neither.)
    ran = [c for c in remote.commands if deployer.DIR_MARK not in c]
    assert not any(".slipway-lock" in c or "BOOT=" in c or "/backups" in c for c in ran)


async def test_an_app_without_data_gets_one_skipped_backup_step_and_unchanged_commands(app):
    from tests.test_app_manifest import APP_SCRIPT as PLAIN_SCRIPT, APP_YML, ENV_EXAMPLE as PLAIN_ENV

    class Plain(DataGitHub):
        files = {"slipway.yml": APP_YML, "deploy/env.example": PLAIN_ENV, "deploy/app": PLAIN_SCRIPT}

    await app.seed()
    dep = await app.deploy(Plain)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert _steps(dep)["backup"] == "skipped" and _note(dep, "backup") == "slipway.yml declares no data"
    assert list(_steps(dep)) == ["resolve", "source", "upload", "manifest", "ports", "settings", "build", "backup",
                                 "start", "finish", "proxy"]
    ran = [c for c in app.remote.commands if "deploy/app" in c]
    assert len(ran) == 2 and not any("umask" in c for c in ran)  # build and start only, no umask
    assert not any("slipway-probe" in c or "df -Pk" in c for c in app.remote.commands)  # never probed
    assert not (app.base / "backups").exists() and not (app.base / ".slipway-lock").exists()
    assert (await app.backups_rows()) == []


# -------------------------------------------------------------- first deploy (test 7)


async def test_a_first_deploy_with_no_data_creates_the_first_admin_then_seeds(shell_app):
    app = shell_app
    await app.seed(env={"DATABASE_URL": "postgres://u:pw@h/db"})
    admin_id = await _add_first_admin(app.instance_id)
    dep = await app.deploy()
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert list(_steps(dep)) == ["resolve", "source", "upload", "manifest", "ports", "settings", "build", "backup",
                                 "start", "finish", "first_admin", "seed", "proxy"]
    assert _steps(dep)["backup"] == "skipped" and _note(dep, "backup").startswith("No data yet: ")
    assert _steps(dep)["first_admin"] == "succeeded" and _steps(dep)["seed"] == "succeeded"
    release = app.release_of(dep.id)
    assert app.calls() == [f"build {release}", f"has-data {release}", f"up {release}", f"admin {release}",
                           f"seed {release}"]
    assert (app.state / "db").read_text() == "MIGRATED\nSEEDED\n"
    assert dep.options["started_empty"] is True

    # The password went on stdin, and is nowhere Slipway keeps text.
    assert (app.admin_log.read_text().strip() ==
            "args=--email ada@example.com --name Ada Lovelace --password-stdin pwlen=15")
    assert all("correct-horse-9" not in c for c in app.remote.commands)
    assert [n for _, _, n in app.remote.inputs] == [16]
    assert "correct-horse-9" not in dep.log and "correct-horse-9" not in json.dumps(dep.steps)
    row = await _get(FirstAdmin, admin_id)
    assert row.status == "done" and row.password is None and row.deployment_id == dep.id and not row.existed

    inst = await app.instance()
    live = inst.app_state["live"]
    assert live["release"] == release and live["deployment"] == dep.id.hex and live["sha"] == SHA
    assert live["settings"] == {"APP_DOMAIN": "uat.example.com"} and live["projects"] == ["demo-web-prod-web",
                                                                                           "demo-web-prod-db"]
    assert live["volumes"] == [{"name": "demo-web-prod-db_data", "holds": "database"}] and live["host_ports"]
    assert "postgres" not in json.dumps(live)  # env_fp is a salted hash, not the values
    assert inst.live_identity == {"APP_KEY": inst.app_secrets["APP_KEY"]}
    assert inst.fresh_data is None and inst.data_dirty is None and inst.status == "running"
    # The lock is gone, and the work area is empty or absent.
    assert not (app.base / ".slipway-lock").exists()
    assert not (app.base / "backups" / ".incoming").exists() or not any((app.base / "backups" / ".incoming").iterdir())


async def test_the_first_admin_step_never_fails_the_deploy(app):
    await app.seed()
    admin_id = await _add_first_admin(app.instance_id)
    app.env["ADMIN_RC"] = "5"
    dep = await app.deploy()
    assert dep.status == "succeeded", dep.error
    assert _steps(dep)["first_admin"] == "warning"
    assert _note(dep, "first_admin").startswith("The app refused the account. Change the first admin")
    row = await _get(FirstAdmin, admin_id)
    assert row.status == "pending" and row.password == "correct-horse-9" and "refused" in row.last_error

    # An exists code counts as done; an invite has no stdin at all.
    async with get_sessionmaker()() as db:
        await db.delete(await db.get(FirstAdmin, admin_id))
        await db.commit()
    await _add_first_admin(app.instance_id, mode="invite")
    app.env["ADMIN_RC"] = "10"
    app.remote.inputs.clear()
    dep = await app.deploy()
    assert _steps(dep)["first_admin"] == "succeeded" and "already existed" in _note(dep, "first_admin")
    assert app.remote.inputs == [] and app.admin_log.read_text().splitlines()[-1].endswith("--invite pwlen=0")


@pytest.mark.parametrize(("fields", "problem"), [
    ({"email": "a\x1b[31m@example.com", "name": "Ada"}, "Email isn't an email address"),
    ({"email": "a\x07b@example.com", "name": "Ada"}, "Email isn't an email address"),
    ({"email": "ada@example.com", "name": "\n\x1c Ada\x1f\n"}, "Name must be 1 to 200 characters of plain text"),
    ({"email": "ada@example.com", "name": "Ada\n"}, "Name must be 1 to 200 characters of plain text"),
    ({"email": "ada@example.com", "name": "  Ada Lovelace  "}, None),
])
def test_first_admin_fields_are_checked_as_they_reach_the_command(fields, problem):
    spec = manifest.parse(DATA_YML).first_admin
    assert spec is not None
    got = deployer.first_admin_problem(spec, fields, "password", "correct-horse-9")
    assert (got is None) if problem is None else (got or "").startswith(problem), got


def test_an_email_field_keeps_to_its_declared_max():
    spec = manifest.FirstAdmin(command=(), fields=(manifest.AdminField(name="email", label="Email", kind="email",
                                                                       max=20),),
                               invite=manifest.AdminInvite(label="Invite"))
    assert deployer.first_admin_problem(spec, {"email": "ada@example.com"}, "invite", None) is None
    assert deployer.first_admin_problem(spec, {"email": "ada.lovelace@example.com"}, "invite", None) == \
        "Email isn't an email address"


async def test_the_first_admin_command_gets_the_text_fields_without_their_blanks(app):
    await app.seed()
    await _add_first_admin(app.instance_id, fields={"email": "ada@example.com", "name": "  Ada Lovelace "})
    dep = await app.deploy()
    assert _steps(dep)["first_admin"] == "succeeded", dep.log
    assert app.admin_log.read_text().strip() == \
        "args=--email ada@example.com --name Ada Lovelace --password-stdin pwlen=15"
    assert "'Ada Lovelace'" in dep.log


async def test_a_failed_seed_is_a_warning_and_leaves_content_pending(app):
    await app.seed()
    app.env["SEED_FAIL"] = "1"
    dep = await app.deploy()
    assert dep.status == "succeeded" and _steps(dep)["seed"] == "warning"
    assert (await app.instance()).content_pending is True


async def test_seed_isnt_listed_for_an_app_without_a_seed_command(app):
    await app.seed()
    dep = await app.deploy(_github(DATA_YML.replace('  seed: [sh, deploy/app, seed, "{slipway.env_dir}"]\n', "")))
    assert dep.status == "succeeded", dep.error
    assert "seed" not in _steps(dep) and f"{deployer.STEP_MARK}9/11: Start" in dep.log


# ------------------------------------------------------- second deploy with data (test 8)


async def test_the_second_deploy_backs_up_with_the_live_release_first(shell_app):
    app = shell_app
    await app.seed()
    first = await app.deploy()
    assert first.status == "succeeded", first.error
    (app.state / "rev").write_text("rev-0042\n")
    app.app_log.write_text("")
    second = await app.deploy()
    assert second.status == "succeeded", (second.error, second.log)
    live, new = app.release_of(first.id), app.release_of(second.id)
    # The live release's commands, with its own .env, then the new release's accepts and up with the new one.
    assert app.calls() == [f"build {new}", f"has-data {live}", f"data {live}", f"revision {live}", f"pgdump {live}",
                           f"verify-dump {live}", f"accepts {new}", f"up {new}"]
    assert f"Put back the settings of release {SHA[:7]}" in second.log
    assert f"APP_REPO={app.base}/releases/{new}\n" in (app.base / "shared" / ".env").read_text()
    assert _steps(second)["backup"] == "succeeded" and "seed" not in _steps(second)

    [row] = await app.backups_rows()
    assert row.status == "ready" and row.reason == "pre_deploy" and row.format == "demo-v1"
    assert row.revision == "rev-0042" and "noise" not in row.revision  # stdout only
    assert row.release == live and row.commit_sha == SHA and row.deployment_id == second.id
    assert row.identity_keys == ["APP_KEY"] and row.identity == (await app.instance()).live_identity
    assert row.db_bytes == len("DB:\nMIGRATED\nSEEDED\n") and second.backup_id == row.id
    assert row.db_sha256 is None or len(row.db_sha256) == 64
    dump = app.backups / f"{row.name}.dump"
    assert dump.read_text() == "DB:\nMIGRATED\nSEEDED\n"
    assert stat.S_IMODE(app.backups.stat().st_mode) == 0o700 and stat.S_IMODE(dump.stat().st_mode) == 0o600
    sidecar = json.loads((app.backups / f"{row.name}.json").read_text())
    assert sidecar["format"] == "slipway-backup" and sidecar["app"] == "demo" and sidecar["db_bytes"] == row.db_bytes
    assert row.identity["APP_KEY"] not in json.dumps(sidecar)
    assert list((app.backups / ".incoming").iterdir()) == []
    assert f"Backed up the data: {row.name}" in second.log


async def test_a_deploy_backs_up_with_the_values_its_data_was_made_with(app):
    """An instance variable that changes an identity key for the new release: the dump runs with the old key."""
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    inst = await app.instance()
    old_key = inst.app_secrets["APP_KEY"]
    new_key = manifest.Secret("APP_KEY", "fernet").generate()
    async with get_sessionmaker()() as db:
        await db.execute(update(Instance).where(Instance.id == app.instance_id).values(env={"APP_KEY": new_key}))
        await db.commit()
    dep = await app.deploy()
    assert dep.status == "succeeded", (dep.error, dep.log)
    [row] = await app.backups_rows()
    assert row.identity == {"APP_KEY": old_key}
    assert (app.state / "keys").read_text().strip() == new_key  # what the new release went live with
    assert (await app.instance()).live_identity == {"APP_KEY": new_key}
    assert old_key not in dep.log and new_key not in dep.log


async def test_a_variable_that_replaced_an_identity_key_can_be_removed_once_deployed(app):
    """An instance variable that sets APP_KEY over the stored one: once deployed, its value is the stored secret
    too, so following the restore refusal's advice (remove the variable) leaves restore, deploy and backup working."""
    _, row = await _deployed_with_backup(app)
    old_key = (await app.instance()).app_secrets["APP_KEY"]
    new_key = _fernet()
    await _set(Instance, app.instance_id, env={"APP_KEY": new_key})
    dep = await app.deploy()
    assert dep.status == "succeeded", (dep.error, dep.log)
    inst = await app.instance()
    assert inst.app_secrets["APP_KEY"] == new_key and inst.live_identity == {"APP_KEY": new_key}
    assert "Kept APP_KEY from the instance's environment variables as the app's secrets" in dep.log
    assert new_key not in dep.log and old_key not in dep.log
    rule = data.restorable(inst, await _get(Backup, row.id))
    assert not rule.ok and rule.reason == data.env_pin_message("APP_KEY")

    await _set(Instance, app.instance_id, env={})  # the advice: remove the variable
    inst = await app.instance()
    rule = data.restorable(inst, await _get(Backup, row.id))
    assert rule.ok and rule.override == {"APP_KEY": old_key}
    assert (await app.deploy(kind="backup")).status == "succeeded"
    assert (await app.deploy()).status == "succeeded"
    restore = await app.deploy(kind="restore", restore_backup_id=row.id, options={"restore_identity": True})
    assert restore.status == "succeeded", (restore.error, restore.log)
    inst = await app.instance()
    assert inst.app_secrets["APP_KEY"] == old_key and inst.live_identity == {"APP_KEY": old_key}


async def test_a_generated_identity_secret_no_backup_holds_is_never_replaced_by_a_variable(app):
    """A variable over APP_KEY deployed without a backup: the generated secret is in no backup, so it stays the
    stored secret, and removing the variable then deploying brings it back."""
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    old_key = (await app.instance()).app_secrets["APP_KEY"]
    new_key = _fernet()
    await _set(Instance, app.instance_id, env={"APP_KEY": new_key})
    dep = await app.deploy(options={"skip_backup": True})
    assert dep.status == "succeeded", (dep.error, dep.log)
    inst = await app.instance()
    assert inst.app_secrets["APP_KEY"] == old_key and inst.live_identity == {"APP_KEY": new_key}
    assert ("Warning: APP_KEY now comes from the instance's environment variables, and no backup holds the stored "
            "secret it replaces, so Slipway keeps that secret. Removing the variable brings it back.") in dep.log
    assert "as the app's secrets" not in dep.log and old_key not in dep.log and new_key not in dep.log

    await _set(Instance, app.instance_id, env={})  # E was wrong
    again = await app.deploy()  # its backup runs the live release with the key its data was made with
    assert again.status == "succeeded", (again.error, again.log)
    assert "Backing up with the APP_KEY the data was made with" in again.log
    [row] = [r for r in await app.backups_rows() if r.reason == "pre_deploy"]
    assert row.identity == {"APP_KEY": new_key}
    inst = await app.instance()
    assert inst.app_secrets["APP_KEY"] == old_key and inst.live_identity == {"APP_KEY": old_key}


async def test_a_deploy_without_identity_variables_leaves_the_stored_secrets_alone(app):
    await app.seed(env={"OTHER": "x"})
    assert (await app.deploy()).status == "succeeded"
    stored = dict((await app.instance()).app_secrets)
    dep = await app.deploy()
    assert dep.status == "succeeded" and "as the app's secrets" not in dep.log
    assert (await app.instance()).app_secrets == stored


# ---------------------------------------------------------- refusals before start (tests 10, 11)


@pytest.mark.parametrize(("env", "message"), [
    ({"DUMP_FAIL": "1"}, "The backup failed (commands.dump exited 1), so Slipway changed nothing"),
    ({"DUMP_EMPTY": "1"}, "commands.dump exited 0 but wrote nothing to "),
])
async def test_a_failed_dump_stops_the_deploy_before_start(app, env, message):
    await app.seed()
    first = await app.deploy()
    assert first.status == "succeeded"
    app.env.update(env)
    app.app_log.write_text("")
    dep = await app.deploy()
    assert dep.status == "failed" and message in dep.error
    assert "Retry without the backup" in dep.error if "DUMP_FAIL" in env else True
    assert not any(c.startswith("up ") for c in app.calls())  # never migrated
    assert (app.base / "current").resolve().name == app.release_of(first.id)
    assert await app.backups_rows() == [] and list((app.backups / ".incoming").iterdir()) == []
    inst = await app.instance()
    assert inst.data_dirty is None and inst.status == "failed"  # failed before start: nothing changed


async def test_too_little_free_space_fails_before_anything_runs(app):
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    app.app_log.write_text("")
    app.env.update(FAKE_DF_KB=str(800 * 1024), FAKE_VOLUME_SIZES="demo-web-prod-db_data 2GB")
    dep = await app.deploy()
    assert dep.status == "failed"
    assert dep.error.startswith(f"Only 800 MiB is free in {app.backups} on prod-01; the backup needs about 3.3 GiB.")  # 1.25 × 2 GB + 1 GiB
    assert "Nothing was changed." in dep.error
    assert not any(c.split()[0] in ("data", "revision", "pgdump", "up") for c in app.calls())


async def test_the_new_release_must_accept_the_live_revision(app):
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    (app.state / "rev").write_text("r-old\n")
    app.env["UNKNOWN_REVS"] = "r-old"
    app.app_log.write_text("")
    dep = await app.deploy()
    assert dep.status == "failed"
    assert dep.error.startswith(f"Release {SHA[:7]} can't run the data at revision r-old: unknown revision r-old. "
                                "Nothing was changed.")
    assert not any(c.startswith("up ") for c in app.calls())
    # "Skip the revision check" lets it through with a warning.
    dep = await app.deploy(options={"skip_revision_check": True})
    assert dep.status == "succeeded" and _steps(dep)["backup"] == "warning"
    assert "Deploying anyway" in _note(dep, "backup")


async def test_has_data_exit_codes(app):
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    (app.state / "where").write_text("broken")
    dep = await app.deploy()
    assert dep.status == "failed" and "commands.has_data exited 9; Slipway can't tell whether web has data" in dep.error
    (app.state / "where").write_text("elsewhere")
    dep = await app.deploy()
    assert dep.status == "succeeded" and _steps(dep)["backup"] == "succeeded"  # backed up all the same
    assert (await app.instance()).app_state["live"]["data_elsewhere"] is True
    assert data.data_shared_reason(await app.instance()) is not None
    # A deploy that skipped its backup never probed: the record stands, so Restore and Reset stay refused.
    dep = await app.deploy(options={"skip_backup": True})
    assert dep.status == "succeeded" and _steps(dep)["backup"] == "warning"
    assert (await app.instance()).app_state["live"]["data_elsewhere"] is True


async def test_without_has_data_the_declared_volumes_tell(app, tmp_path):
    yml = DATA_YML.replace('  has_data: [sh, deploy/app, has-data, "{slipway.env_dir}"]\n', "")
    volumes = tmp_path / "volumes"
    app.env["FAKE_VOLUME_FILE"] = str(volumes)
    await app.seed()
    dep = await app.deploy(_github(yml))
    assert dep.status == "succeeded" and _note(dep, "backup") == "No data yet: demo-web-prod-db_data is not on prod-01"
    volumes.write_text("demo-web-prod-db_data demo-web-prod-db\n")
    dep = await app.deploy(_github(yml))
    assert dep.status == "succeeded" and _steps(dep)["backup"] == "succeeded"
    app.env["FAKE_NO_DOCKER"] = "1"
    dep = await app.deploy(_github(yml))
    assert dep.status == "failed" and "Couldn't check prod-01 for the app's data: docker didn't answer" in dep.error


async def test_a_failed_start_after_a_backup_leaves_the_data_dirty(app, tmp_path):
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    flag = tmp_path / "fail"
    flag.write_text("")
    app.env["FAIL_FLAG"] = str(flag)
    dep = await app.deploy()
    assert dep.status == "failed" and "migration failed" in dep.error
    [row] = await app.backups_rows()
    dirty = (await app.instance()).data_dirty
    assert dirty["first"] == {"deployment_id": dep.id.hex, "kind": "deploy", "backup_id": row.id.hex,
                              "at": dirty["first"]["at"]}
    assert dirty["last"]["step"] == "start" and dirty["hold"] is False
    # A backup taken while dirty is labelled; the next good deploy clears the state.
    flag.unlink()
    dep = await app.deploy()
    assert dep.status == "succeeded"
    rows = await app.backups_rows()
    assert rows[-1].dirty_of == uuid.UUID(dirty["first"]["deployment_id"])
    assert "this backup holds that state" in dep.log
    assert (await app.instance()).data_dirty is None


async def test_a_retry_keeps_the_first_attempts_backup(app, tmp_path):
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    flag = tmp_path / "fail"
    flag.write_text("")
    app.env["FAIL_FLAG"] = str(flag)
    failed = await app.deploy()
    assert failed.status == "failed"
    flag.unlink()
    app.app_log.write_text("")
    retry = await app.deploy(retry_of_id=failed.id, backup_id=failed.backup_id, options={"inherit": True})
    assert retry.status == "succeeded", (retry.error, retry.log)
    assert not any(c.startswith("pgdump") for c in app.calls())  # one dump in the whole chain
    [row] = await app.backups_rows()
    assert _steps(retry)["backup"] == "skipped" and _note(retry, "backup").startswith(
        f"Keeping the backup taken before the first attempt: {row.name}")
    assert retry.backup_id == row.id


async def test_a_retry_after_a_manual_start_backs_up_again(app, tmp_path):
    from slipway.db.base import utcnow
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    flag = tmp_path / "fail"
    flag.write_text("")
    app.env["FAIL_FLAG"] = str(flag)
    failed = await app.deploy()
    async with get_sessionmaker()() as db:  # someone pressed Start on the instance page since
        await db.execute(update(Instance).where(Instance.id == app.instance_id).values(last_control_at=utcnow()))
        await db.commit()
    flag.unlink()
    retry = await app.deploy(retry_of_id=failed.id, backup_id=failed.backup_id, options={"inherit": True})
    assert retry.status == "succeeded", retry.error
    rows = await app.backups_rows()
    assert [r.reason for r in rows] == ["pre_deploy", "pre_retry"]
    assert retry.backup_id == rows[0].id  # the chain's pre-change backup stays the first one
    assert rows[1].dirty_of == failed.id  # taken of half-changed data, and labelled so


async def test_a_retry_whose_backup_is_gone_says_so_and_takes_none(app, tmp_path):
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    flag = tmp_path / "fail"
    flag.write_text("")
    app.env["FAIL_FLAG"] = str(flag)
    failed = await app.deploy()
    [row] = await app.backups_rows()
    (app.backups / f"{row.name}.dump").unlink()
    flag.unlink()
    retry = await app.deploy(retry_of_id=failed.id, backup_id=failed.backup_id, options={"inherit": True})
    assert retry.status == "succeeded" and _steps(retry)["backup"] == "warning"
    assert "is no longer on prod-01; a new one now would hold half-changed data" in _note(retry, "backup")
    assert retry.backup_id is None and (await _get(Backup, row.id)).status == "missing"


async def test_skip_backup_is_a_warning(app):
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    app.app_log.write_text("")
    dep = await app.deploy(options={"skip_backup": True})
    assert dep.status == "succeeded" and _steps(dep)["backup"] == "warning"
    assert "the data is changed without a backup" in _note(dep, "backup")
    assert not any(c.startswith("pgdump") for c in app.calls())


async def test_a_retry_without_the_backup_that_fails_in_start_leaves_the_data_dirty(app, tmp_path):
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    app.env["DUMP_FAIL"] = "1"
    failed = await app.deploy()
    assert failed.status == "failed" and _steps(failed)["backup"] == "failed"
    assert (await app.instance()).data_dirty is None  # nothing changed yet
    del app.env["DUMP_FAIL"]
    flag = tmp_path / "fail"
    flag.write_text("")
    app.env["FAIL_FLAG"] = str(flag)  # the migration runs, then fails part-way
    retry = await _retry(app, failed, skip_backup=True)
    assert retry.status == "failed" and _steps(retry)["backup"] == "warning" and _steps(retry)["start"] == "failed"
    dirty = (await app.instance()).data_dirty
    assert dirty is not None and dirty["first"]["deployment_id"] == retry.id.hex
    assert dirty["last"]["deployment_id"] == retry.id.hex and dirty["last"]["step"] == "start"
    assert data.dirty_snapshot_text(await app.instance())  # Take snapshot is refused on the half-migrated data


async def test_an_inherited_retry_that_fails_in_start_again_becomes_the_last_failure(app, tmp_path):
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    flag = tmp_path / "fail"
    flag.write_text("")
    app.env["FAIL_FLAG"] = str(flag)
    failed = await app.deploy()
    assert failed.status == "failed"
    retry = await _retry(app, failed)
    assert retry.status == "failed" and _steps(retry)["backup"] == "skipped"  # it kept the first backup
    dirty = (await app.instance()).data_dirty
    assert dirty["first"]["deployment_id"] == failed.id.hex
    assert dirty["last"]["deployment_id"] == retry.id.hex and dirty["last"]["backup_id"] == failed.backup_id.hex


async def test_retention_keeps_the_newest_and_never_the_pinned(app):
    await app.seed(keep_backups=1)
    assert (await app.deploy()).status == "succeeded"
    for _ in range(3):
        assert (await app.deploy()).status == "succeeded"
    rows = await app.backups_rows()
    # keep_backups=1 plus the one the latest deploy took (pinned as its pre-change backup).
    assert len(rows) == 2 and all((app.backups / f"{r.name}.dump").exists() for r in rows)
    assert len(list(app.backups.glob("*.dump"))) == 2


# ---------------------------------------------------------------------- the live render (D3)


async def test_the_live_render_refuses_a_moved_current(app):
    await app.seed()
    first = await app.deploy()
    assert first.status == "succeeded"
    other = app.base / "releases" / "elsewhere"
    other.mkdir()
    (app.base / "current").unlink()
    (app.base / "current").symlink_to(other)
    dep = await app.deploy()
    assert dep.status == "failed"
    assert f"The live release on prod-01 isn't the one Slipway recorded (current points at {other})" in dep.error


async def test_the_live_render_refuses_other_project_names(app):
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, app.instance_id)
        state = dict(inst.app_state)
        state["live"] = {**state["live"], "projects": ["something-else"]}
        inst.app_state = state
        await db.commit()
    dep = await app.deploy()
    assert dep.status == "failed" and "would now run under other names (projects demo-web-prod-web" in dep.error


# ------------------------------------------------------------------------- host lock (test 28)


async def test_a_timed_out_dump_keeps_the_lock_until_it_ends(app):
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    app.env["DUMP_SLEEP"] = "30"
    app.remote.timeout_on = "pgdump"
    try:
        dep = await app.deploy()
        assert dep.status == "failed" and "timed out" in dep.error
        words = (app.base / ".slipway-lock").read_text().split()
        assert words[0] == str(dep.id) and words[3:] == ["dump", "d"]
        pid = words[2]
        # The job that left the lock names the PID to stop (§4.5), read back from the line the dump wrote.
        assert f"dump (pid {pid}) may still be running on prod-01; the next job waits until it has ended" in dep.log
        app.remote.timeout_on = None
        app.env.pop("DUMP_SLEEP")
        blocked = await app.deploy()
        assert blocked.status == "failed"
        assert blocked.error.startswith(f"Job {dep.id.hex[:8]}'s dump (pid {pid}) is still running on prod-01")
        assert "kill " + pid in blocked.error
        assert _steps(blocked)["upload"] == "failed" and _steps(blocked)["backup"] == "pending"
    finally:
        app.remote.stop_timed_out()
    dep2 = await app.deploy()
    assert dep2.status == "succeeded", dep2.error
    assert f"Took over the lock of job {dep.id.hex[:8]} (its dump has ended)" in dep2.log
    assert not (app.base / ".slipway-lock").exists()


async def test_a_live_lock_without_data_only_warns(app):
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    other = uuid.uuid4()
    (app.base / ".slipway-lock").write_text(f"{other} - {os.getpid()} build -\n")
    dep = await app.deploy()
    assert dep.status == "succeeded"
    assert f"Warning: job {other.hex[:8]}'s build (pid {os.getpid()}) may still be running on prod-01" in dep.log


@pytest.mark.skipif(not Path("/proc/sys/kernel/random/boot_id").exists(), reason="the host has no boot id")
async def test_a_lock_from_before_a_restart_is_taken_over(app):
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    other = uuid.uuid4()
    (app.base / ".slipway-lock").write_text(f"{other} another-boot {os.getpid()} restore d\n")
    dep = await app.deploy()
    assert dep.status == "succeeded" and f"Took over the lock of job {other.hex[:8]} (its restore has ended)" in dep.log


# ------------------------------------------------------------------------ redaction (tests 5, 31)


async def test_secrets_are_hidden_in_the_log_notes_and_error(app):
    await app.seed(env={"DATABASE_URL": "postgres://u:pw@h/db", "SHORT": "abcde"})
    app.env["LEAK"] = "1"
    dep = await app.deploy()
    assert dep.status == "failed"
    inst = await app.instance()
    secret = inst.app_secrets["APP_SECRET"]
    for text in (dep.log, dep.error, json.dumps(dep.steps)):
        assert secret not in text and "postgres://u:pw@h/db" not in text
    assert "secret is [hidden] and [hidden]" in dep.log and "secret is [hidden]" in dep.error
    assert "secret is [hidden]" in _note(dep, "start")


async def test_a_secret_straddling_the_note_cut_stays_hidden():
    sink = deployer.LogSink(uuid.uuid4())
    secret = "x" * 20
    sink.hide.add(secret)
    sink.hide.add("abcde")  # five characters: too short to hide
    steps = deployer.Steps(uuid.uuid4(), [{"key": "start", "name": "Start", "status": "pending"}], sink)
    await steps.begin("start")
    await steps.end("failed", note="y" * 290 + secret + " abcde")
    note = steps.rows[0]["note"]
    assert "x" not in note and note.startswith("y" * 290 + "[hidden]")
    long_line = "z" * (deployer.MAX_LINE_CHARS - 5) + secret
    assert sink.scrub(long_line).endswith("[hidden]") and sink.scrub("abcde") == "abcde"


def test_the_cancelled_or_timed_out_lock_message_names_the_command():
    assert data.lock_left_message("dump", None, "prod-01") == \
        "dump may still be running on prod-01; the next job waits until it has ended"


def test_the_shell_tools_exist():
    assert shutil.which("od") and shutil.which("head")


# =============================================================================================================
# Pass two: restore, roll back, reset, Start over, the data-only jobs, retry, destroy, moves and recovery.


@pytest.fixture(autouse=True)
def _fresh_snapshot_state():
    snapshots.reset_state()
    yield
    snapshots.reset_state()


def _fernet() -> str:
    return manifest.Secret("APP_KEY", "fernet").generate()


async def _retry(app: App, parent: Deployment, github: type[DataGitHub] = DataGitHub, **options) -> Deployment:
    """Queue and run a retry the way queue_deployment(retry_of=) builds it (deployer.retry_values)."""
    async with get_sessionmaker()() as db:
        values = await deployer.retry_values(db, await db.get(Deployment, parent.id))
    values.pop("branch")
    values["options"].update(options)
    return await app.deploy(github, retry_of_id=parent.id, **values)


async def _set(model, ident, **fields) -> None:
    async with get_sessionmaker()() as db:
        row = await db.get(model, ident)
        for key, value in fields.items():
            setattr(row, key, value)
        await db.commit()


async def _make_snapshot(*, db_text: str = "DB:\nFROM-SNAP\n", files_text: str | None = None,
                         identity: dict[str, str] | None = None, app: str = "demo", fmt: str = "demo-v1",
                         repository: str | None = "acme/web", revision: str | None = None,
                         name: str = "snap-1") -> uuid.UUID:
    """A ready snapshot stored as Slipway stores one: an .sbx under its own data key."""
    snapshots.require_storage()
    raw_db = db_text.encode()
    raw_files = files_text.encode() if files_text is not None else None
    man = snapfile.build_manifest(
        app=app, app_name="Demo", source="uat", repository=repository,
        database={"format": fmt, "revision": revision, "bytes": len(raw_db), "sha256": hashlib.sha256(raw_db).hexdigest()},
        files=({"format": "demo-files-v1", "bytes": len(raw_files), "sha256": hashlib.sha256(raw_files).hexdigest()}
               if raw_files is not None else None),
        identity=identity)
    sid = uuid.uuid4()
    key = snapfile.new_data_key()
    bundle = snapshots.NewBundle(stem=str(sid))
    writer = bundle.encrypting(key)
    snapfile.write_tar(writer, man, identity=identity, database=io.BytesIO(raw_db),
                       files=io.BytesIO(raw_files) if raw_files is not None else None)
    writer.close()
    bundle.install(sid)
    async with get_sessionmaker()() as db:
        row = Snapshot(id=sid, name=name, status="ready", origin="upload", data_key=snapshots.encode_key(key),
                       file_bytes=bundle.bytes, file_sha256=bundle.sha256)
        snapshots.apply_manifest(row, man)
        db.add(row)
        await db.commit()
    return sid


def _docker_log(app: App) -> list[str]:
    return Path(app.env["DOCKER_LOG"]).read_text().splitlines()


async def _deployed_with_backup(app: App, **seed) -> tuple[Deployment, Backup]:
    """A deployed instance (its database "MIGRATED, SEEDED") and a backup taken by hand of it."""
    await app.seed(**seed)
    first = await app.deploy()
    assert first.status == "succeeded", (first.error, first.log)
    (app.state / "rev").write_text("rev-1\n")
    backup = await app.deploy(kind="backup")
    assert backup.status == "succeeded", (backup.error, backup.log)
    [row] = await app.backups_rows()
    assert row.reason == "manual" and row.revision == "rev-1"
    return first, row


# ----------------------------------------------------------------------------- restore (tests 15, 16)


async def test_a_restore_runs_the_live_release_again_with_what_it_went_live_with(shell_app, tmp_path):
    app = shell_app
    first, row = await _deployed_with_backup(app)
    (app.state / "db").write_text("MIGRATED\nSEEDED\nLATER\n")
    # A failed deploy with another setting: the .env it wrote stays behind, and the data is dirty.
    await _set(Instance, app.instance_id, app_settings={"APP_DOMAIN": "other.example.com"})
    flag = tmp_path / "fail"
    flag.write_text("")
    app.env["FAIL_FLAG"] = str(flag)
    failed = await app.deploy()
    assert failed.status == "failed" and "APP_DOMAIN=other.example.com" in (app.base / "shared" / ".env").read_text()
    flag.unlink()
    app.app_log.write_text("")
    calls = len(FakeGitHub.calls)
    dep = await app.deploy(kind="restore", restore_backup_id=row.id)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert len(FakeGitHub.calls) == calls  # GitHub is never asked (D2)
    assert list(_steps(dep)) == ["release", "manifest", "settings", "build", "check", "backup", "stop", "restore",
                                 "start", "finish", "proxy"]
    assert _steps(dep)["build"] == "skipped"  # its images are tagged per release, and are there
    live = app.release_of(first.id)
    assert app.calls() == [f"accepts {live}", f"has-data {live}", f"data {live}", f"revision {live}", f"pgdump {live}",
                           f"verify-dump {live}", f"down {live}", f"data {live}", f"restore {live}", f"up {live}"]
    assert (app.state / "db").read_text() == "MIGRATED\nSEEDED\nMIGRATED\n"  # the backup, then the live migrations
    env = (app.base / "shared" / ".env").read_text()
    assert "APP_DOMAIN=uat.example.com" in env and f"APP_REPO={app.base}/releases/{live}" in env  # app_state.live's
    rows = await app.backups_rows()
    pre = next(r for r in rows if r.reason == "pre_restore")
    assert dep.backup_id == pre.id and pre.dirty_of == failed.id  # the half-changed data, labelled
    assert dep.options["prev_status"] == "failed"
    inst = await app.instance()
    assert inst.status == "running" and inst.data_dirty is None and inst.current_commit_sha == SHA
    assert inst.app_state["live"]["release"] == live and inst.app_state["live"]["deployment"] == first.id.hex
    assert not (app.base / ".slipway-lock").exists()


async def test_a_restore_rebuilds_a_release_whose_images_arent_tagged_per_release(app):
    yml = DATA_YML.replace('images: ["demo-web:{slipway.sha12}"]', 'images: ["demo-web:latest"]')
    await app.seed()
    assert (await app.deploy(_github(yml))).status == "succeeded"
    assert (await app.deploy(_github(yml), kind="backup")).status == "succeeded"
    [row] = await app.backups_rows()
    dep = await app.deploy(_github(yml), kind="restore", restore_backup_id=row.id)
    assert dep.status == "succeeded", dep.error
    assert _steps(dep)["build"] == "succeeded" and f"Rebuilding release {SHA[:7]}: its images aren't tagged" in dep.log


async def test_a_restore_reuses_images_tagged_per_release_through_a_var(app):
    """ServerSherpa's form: images: ["serversherpa-api:{STACK_IMAGE_TAG}"] with vars.STACK_IMAGE_TAG: "{slipway.sha12}"."""
    yml = DATA_YML.replace('  APP_REPO: "{slipway.release}"\n',
                           '  APP_REPO: "{slipway.release}"\n  APP_IMAGE_TAG: "{slipway.sha12}"\n') \
        .replace('images: ["demo-web:{slipway.sha12}"]', 'images: ["demo-web:{APP_IMAGE_TAG}"]')
    assert 'images: ["demo-web:{APP_IMAGE_TAG}"]' in yml and "APP_IMAGE_TAG: " in yml
    await app.seed()
    assert (await app.deploy(_github(yml))).status == "succeeded"
    assert (await app.deploy(_github(yml), kind="backup")).status == "succeeded"
    [row] = await app.backups_rows()
    dep = await app.deploy(_github(yml), kind="restore", restore_backup_id=row.id)
    assert dep.status == "succeeded", dep.error
    assert _steps(dep)["build"] == "skipped" and "Rebuilding release" not in dep.log


@pytest.mark.parametrize(("images", "variables", "expected"), [
    (["a:{slipway.sha12}", "b:{slipway.deployment}"], {}, True),
    (["a:{TAG}"], {"TAG": "{slipway.sha12}"}, True),
    (["a:{TAG}"], {"BASE": "r-{slipway.sha}", "TAG": "{BASE}-x"}, True),  # through an earlier var
    (["a:{TAG}", "b:latest"], {"TAG": "{slipway.sha12}"}, False),
    (["a:{TAG}"], {"TAG": "fixed"}, False),
    (["a:{{slipway.sha12}}"], {}, False),  # {{ and }} are literal braces
    (["a:{TAG}"], {"TAG": "{{slipway.sha12}}"}, False),
    ([], {"TAG": "{slipway.sha12}"}, False),
])
def test_images_per_release_follows_vars(images, variables, expected):
    assert deployer.images_per_release(images, variables) is expected


def test_serversherpas_images_are_tagged_per_release():
    text = (Path(__file__).resolve().parent.parent / "docs" / "examples" / "serversherpa.slipway.yml").read_text()
    man = manifest.parse(text)
    assert man.images and deployer._images_per_release(man)
    from slipway.web import pages
    assert pages.rebuild_note(man.to_json(), "abc1234") is None


@pytest.mark.parametrize("case", ["missing", "changed", "format", "revision", "identity"])
async def test_a_restore_refuses_before_anything_stops(app, case):
    _, row = await _deployed_with_backup(app)
    dump = app.backups / f"{row.name}.dump"
    expected = {
        "missing": f"The backup {row.name} on prod-01 is missing. Nothing was changed.",
        "changed": "has changed since Slipway took it (size or checksum differ); Slipway won't restore it",
        "format": f"Taken in format demo-v0; release {SHA[:7]} restores demo-v1. Nothing was changed.",
        "revision": f"Release {SHA[:7]} can't open a database at revision rev-1: unknown revision rev-1. Nothing was",
        "identity": "This backup was made with other identity keys; restoring it puts them back.",
    }[case]
    if case == "missing":
        dump.unlink()
    elif case == "changed":
        dump.write_text(dump.read_text() + "x")
    elif case == "format":
        await _set(Backup, row.id, format="demo-v0")
    elif case == "revision":
        app.env["UNKNOWN_REVS"] = "rev-1"
    else:
        other = {"APP_KEY": _fernet()}
        await _set(Backup, row.id, identity=other, identity_fp=data.identity_fp(row.id, ["APP_KEY"], other))
    app.app_log.write_text("")
    dep = await app.deploy(kind="restore", restore_backup_id=row.id)
    assert dep.status == "failed" and expected in dep.error, dep.error
    assert _steps(dep)["check"] == "failed" and _steps(dep)["stop"] == "pending"
    assert not any(c.startswith(("down", "restore")) for c in app.calls())
    inst = await app.instance()
    assert inst.status == "running" and inst.data_dirty is None  # the old app still runs


async def test_skipping_the_backup_never_restores_data_that_lives_elsewhere(app):
    _, row = await _deployed_with_backup(app)
    (app.state / "where").write_text("elsewhere")  # an instance variable now points the app at a shared database
    first = await app.deploy(kind="restore", restore_backup_id=row.id)
    assert first.status == "failed" and _steps(first)["backup"] == "failed"
    assert "web's data lives outside prod-01 (commands.has_data says so)" in first.error
    inst = await app.instance()
    assert data.data_shared_reason(inst)  # the probe's answer is kept although the job failed
    async with get_sessionmaker()() as db:
        assert not (await data.retry_state(db, await db.get(Deployment, first.id)))["offers_skip_backup"]
    retry = await _retry(app, first, skip_backup=True)  # however it was queued, its check refuses it
    assert retry.status == "failed" and _steps(retry)["check"] == "failed" and _steps(retry)["stop"] == "pending"
    # Without the kept answer (an older Slipway's failure left none), the skipped backup still asks has_data.
    state = dict(inst.app_state)
    await _set(Instance, app.instance_id, app_state={**state, "live": {**state["live"], "data_elsewhere": False}})
    app.app_log.write_text("")
    retry = await _retry(app, retry, skip_backup=True)
    assert retry.status == "failed" and _steps(retry)["backup"] == "failed" and _steps(retry)["stop"] == "pending"
    assert "web's data lives outside prod-01" in retry.error
    assert not any(c.startswith(("down", "restore")) for c in app.calls())
    assert (await app.instance()).data_dirty is None
    # Once the data is back on the host, the next probe says so and restores are allowed again.
    (app.state / "where").unlink()
    assert (await app.deploy(kind="backup")).status == "succeeded"
    assert data.data_shared_reason(await app.instance()) is None


async def test_restoring_other_identity_keys_needs_the_tick_and_puts_them_back_together(app):
    _, row = await _deployed_with_backup(app)
    old = (await app.instance()).app_secrets["APP_KEY"]
    other = _fernet()
    await _set(Backup, row.id, identity={"APP_KEY": other},
               identity_fp=data.identity_fp(row.id, ["APP_KEY"], {"APP_KEY": other}))
    # The restore fails part-way: nothing about the keys changed (I3).
    app.env["RESTORE_FAIL"] = "1"
    dep = await app.deploy(kind="restore", restore_backup_id=row.id, options={"restore_identity": True})
    assert dep.status == "failed" and _steps(dep)["restore"] == "failed"
    inst = await app.instance()
    assert inst.app_secrets["APP_KEY"] == old and inst.live_identity == {"APP_KEY": old}
    assert f"APP_KEY={old}" in (app.base / "shared" / ".env").read_text()
    app.env.pop("RESTORE_FAIL")
    dep = await _retry(app, dep)
    assert dep.status == "succeeded", (dep.error, dep.log)
    inst = await app.instance()
    assert inst.app_secrets["APP_KEY"] == other and inst.live_identity == {"APP_KEY": other}
    assert (app.state / "keys").read_text().strip() == other  # the app started with them
    assert inst.identity_source == f"backup {row.name}" and inst.identity_changed_at is not None
    assert other not in dep.log and old not in dep.log and "APP_KEY now come from backup" in dep.log
    async with get_sessionmaker()() as db:
        events = (await db.scalars(select(AuditEvent).where(AuditEvent.action == "instance.identity_secrets"))).all()
    assert [e.details for e in events] == [{"keys": ["APP_KEY"], "source": f"backup {row.name}"}]
    assert other not in json.dumps([e.summary for e in events])


async def test_a_restore_that_fails_part_way_holds_and_its_retry_finishes(app):
    _, row = await _deployed_with_backup(app, keep_backups=1)
    app.env["RESTORE_FAIL"] = "1"
    dep = await app.deploy(kind="restore", restore_backup_id=row.id)
    assert dep.status == "failed"
    pre = next(r for r in await app.backups_rows() if r.reason == "pre_restore")
    assert dep.error.startswith("commands.restore exited 1: the database may be empty or half-restored, and the app is "
                                f"stopped. Retry this job, or restore another backup (the one taken just before is "
                                f"{pre.name}).")
    inst = await app.instance()
    assert inst.status == "failed" and inst.data_dirty["hold"] is True and inst.data_dirty["last"]["step"] == "restore"
    async with get_sessionmaker()() as db:
        held = await data.hold_text(db, await db.get(Instance, app.instance_id))
    assert held.startswith("web's last restore stopped part-way (step 8/") and pre.name in held
    app.env.pop("RESTORE_FAIL")
    retry = await _retry(app, dep)
    assert retry.status == "succeeded", (retry.error, retry.log)
    assert retry.options.get("inherit") is True and retry.backup_id == pre.id
    assert _steps(retry)["backup"] == "skipped" and "Keeping the backup taken before the first attempt" in retry.log
    assert _steps(retry)["check"] == "succeeded" and _steps(retry)["restore"] == "succeeded"
    assert (app.state / "db").read_text() == "MIGRATED\nSEEDED\nMIGRATED\n"
    inst = await app.instance()
    assert inst.data_dirty is None and inst.status == "running"
    # Retention never pruned the hold's backup (keep_backups=1), and Undo offers it.
    assert {r.id for r in await app.backups_rows()} >= {row.id, pre.id}
    async with get_sessionmaker()() as db:
        undo = await data.undo_state(db, await db.get(Deployment, retry.id))
    assert undo["available"] is True and undo["backup_id"] == str(pre.id)


# ------------------------------------------------------------------------- roll back (tests 13, 18)


async def test_roll_back_restores_the_backup_from_before_the_failed_deploy(app, tmp_path):
    await app.seed()
    first = await app.deploy()
    assert first.status == "succeeded"
    (app.state / "rev").write_text("rev-1\n")
    flag = tmp_path / "fail"
    flag.write_text("")
    app.env["FAIL_FLAG"] = str(flag)
    failed = await app.deploy()
    assert failed.status == "failed"
    flag.unlink()
    async with get_sessionmaker()() as db:
        state = await data.rollback_state(db, await db.get(Deployment, failed.id))
    assert state.available, state.reason
    dep = await app.deploy(kind="rollback", restore_backup_id=state.backup.id,
                           options={"rollback_of": failed.id.hex})
    assert dep.status == "succeeded", (dep.error, dep.log)
    names = {s["key"]: s["name"] for s in dep.steps}
    assert names["restore"] == f"Restore the backup from before deployment {failed.id.hex[:8]}"
    assert (app.state / "db").read_text() == "MIGRATED\nSEEDED\nMIGRATED\n"
    assert [r.reason for r in await app.backups_rows()] == ["pre_deploy", "pre_rollback"]
    assert (app.base / "current").resolve().name == app.release_of(first.id)
    inst = await app.instance()
    assert inst.data_dirty is None and inst.status == "running"
    async with get_sessionmaker()() as db:
        assert (await data.undo_state(db, await db.get(Deployment, dep.id)))["available"] is False
        assert not (await data.rollback_state(db, await db.get(Deployment, failed.id))).available


async def test_rolling_back_two_failed_deploys_goes_back_to_before_the_first(app, tmp_path):
    await app.seed(keep_backups=1)
    assert (await app.deploy()).status == "succeeded"
    flag = tmp_path / "fail"
    flag.write_text("")
    app.env["FAIL_FLAG"] = str(flag)
    b = await app.deploy()
    c = await app.deploy()
    assert b.status == c.status == "failed"
    async with get_sessionmaker()() as db:
        state = await data.rollback_state(db, await db.get(Deployment, c.id))
    assert state.available and state.backup.id == b.backup_id
    assert state.also_undoes.startswith(f"This also undoes failed deployment {b.id.hex[:8]} before it")
    flag.unlink()
    dep = await app.deploy(kind="rollback", restore_backup_id=state.backup.id, options={"rollback_of": c.id.hex})
    assert dep.status == "succeeded", dep.error
    assert (await _get(Backup, b.backup_id)) is not None  # pinned through retention with keep_backups=1


# ---------------------------------------------------------------------------- reset (tests 19, 20)


def _volumes(app: App, tmp_path: Path) -> Path:
    path = tmp_path / "volumes"
    app.env["FAKE_VOLUME_FILE"] = str(path)
    return path


async def test_reset_to_empty_deletes_the_volumes_and_starts_afresh(app, tmp_path):
    volumes = _volumes(app, tmp_path)
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    assert "demo-web-prod-db_data demo-web-prod-db" in volumes.read_text()
    (app.state / "db").write_text("MIGRATED\nSEEDED\nUSERS\n")
    admin_id = await _add_first_admin(app.instance_id)
    dep = await app.deploy(kind="reset", options={"seed": True})
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert list(_steps(dep)) == ["release", "manifest", "settings", "build", "backup", "stop", "reset", "start",
                                 "finish", "first_admin", "seed", "proxy"]
    [row] = await app.backups_rows()
    assert row.reason == "pre_reset" and (app.backups / f"{row.name}.dump").read_text() == "DB:\nMIGRATED\nSEEDED\nUSERS\n"
    docker = _docker_log(app)
    down = docker.index("compose -p demo-web-prod-web down --remove-orphans")
    assert docker.index("volume rm -- demo-web-prod-db_data") > down
    assert (app.state / "db").read_text() == "MIGRATED\nSEEDED\n"  # an empty start, migrated and seeded
    assert (await _get(FirstAdmin, admin_id)).status == "done"
    assert "Deleted the data: demo-web-prod-db_data" in dep.log


@pytest.mark.parametrize("case", ["foreign", "unlabelled", "busy", "elsewhere"])
async def test_reset_refusals(app, tmp_path, case):
    volumes = _volumes(app, tmp_path)
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    if case == "foreign":
        volumes.write_text("demo-web-prod-db_data someone-else\n")
    elif case == "unlabelled":
        volumes.write_text("demo-web-prod-db_data\n")
    elif case == "busy":
        app.env["FAKE_VOLUME_BUSY"] = "demo-web-prod-db_data"
    else:
        (app.state / "where").write_text("elsewhere")
    app.app_log.write_text("")
    dep = await app.deploy(kind="reset")
    assert dep.status == "failed"
    inst = await app.instance()
    if case == "busy":
        assert dep.error == ("Could not delete demo-web-prod-db_data: Error response from daemon: remove "
                             "demo-web-prod-db_data: volume is in use")
        assert _steps(dep)["reset"] == "failed" and inst.data_dirty["hold"] is True
        return
    text = {"foreign": "The volume demo-web-prod-db_data belongs to the Compose project someone-else, not to this app",
            "unlabelled": "The volume demo-web-prod-db_data has no Compose project label",
            "elsewhere": "web's data lives outside prod-01 (commands.has_data says so)"}[case]
    assert text in dep.error and _steps(dep)["backup"] == "failed"
    assert not any(c.startswith("down") for c in app.calls()) and not any("volume rm" in c for c in _docker_log(app))
    assert inst.status == "running" and inst.data_dirty is None


async def test_reset_from_a_snapshot_brings_its_data_files_and_keys(shell_app, tmp_path):
    app = shell_app
    _volumes(app, tmp_path)
    gh = _github(FILES_YML)
    await app.seed()
    first = await app.deploy(gh)
    assert first.status == "succeeded", first.error
    snap_key = _fernet()
    sid = await _make_snapshot(files_text="FILES:\nphoto\n", identity={"APP_KEY": snap_key})
    app.app_log.write_text("")
    dep = await app.deploy(gh, kind="reset", snapshot_id=sid)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert list(_steps(dep)) == ["release", "manifest", "settings", "build", "check", "backup", "stop", "reset",
                                 "restore", "files", "after_import", "start", "finish", "proxy"]
    live = app.release_of(first.id)
    assert app.calls() == [
        f"has-data {live}", f"data {live}", f"revision {live}", f"pgdump {live}", f"verify-dump {live}",
        f"export-objects {live}", f"down {live}", f"has-data {live}", f"has-data {live}", f"data {live}",
        f"restore {live}", f"import-objects {live}", f"clear-sessions {live}", f"up {live}"]
    assert (app.state / "db").read_text() == "FROM-SNAP\nMIGRATED\n" and (app.state / "files").read_text() == "photo\n"
    assert (app.state / "keys").read_text().strip() == snap_key
    inst = await app.instance()
    assert inst.app_secrets["APP_KEY"] == snap_key and inst.live_identity == {"APP_KEY": snap_key}
    assert inst.identity_source == "snapshot snap-1" and snap_key not in dep.log
    [row] = await app.backups_rows()
    assert row.reason == "pre_reset" and row.has_files
    assert list((app.backups / ".incoming").iterdir()) == []  # the staged copy is gone


async def test_a_failed_snapshot_restore_leaves_the_keys_alone(app, tmp_path):
    _volumes(app, tmp_path)
    gh = _github(FILES_YML)
    await app.seed()
    assert (await app.deploy(gh)).status == "succeeded"
    old = (await app.instance()).app_secrets["APP_KEY"]
    sid = await _make_snapshot(identity={"APP_KEY": _fernet()})
    app.env["RESTORE_FAIL"] = "1"
    dep = await app.deploy(gh, kind="reset", snapshot_id=sid)
    assert dep.status == "failed" and _steps(dep)["restore"] == "failed"
    inst = await app.instance()
    assert inst.app_secrets["APP_KEY"] == old and inst.live_identity == {"APP_KEY": old}
    assert f"APP_KEY={old}" in (app.base / "shared" / ".env").read_text()
    assert inst.data_dirty["hold"] is True


@pytest.mark.parametrize("case", ["app", "repository", "revision"])
async def test_a_snapshot_is_refused_in_check(app, tmp_path, case):
    _volumes(app, tmp_path)
    gh = _github(FILES_YML)
    await app.seed()
    assert (await app.deploy(gh)).status == "succeeded"
    if case == "app":
        sid = await _make_snapshot(app="other")
        text = "This snapshot is of app other (Demo); web runs demo. Nothing was changed."
    elif case == "repository":
        sid = await _make_snapshot(repository="acme/elsewhere")
        text = ("Snapshot snap-1 was made from acme/elsewhere; seeding web (acme/web) from it needs the "
                "snapshots:download permission")
        maintainer = await make_user("maint@example.com", roles=["maintainer"])
        app.user_id = maintainer.id
    else:
        sid = await _make_snapshot(revision="r-new")
        app.env["UNKNOWN_REVS"] = "r-new"
        text = f"Release {SHA[:7]} can't open a database at revision r-new: unknown revision r-new"
    app.app_log.write_text("")
    dep = await app.deploy(gh, kind="reset", snapshot_id=sid)
    assert dep.status == "failed" and text in dep.error, dep.error
    assert _steps(dep)["check"] == "failed"
    assert not any("volume rm" in c for c in _docker_log(app)) and not any(c.startswith("down") for c in app.calls())
    assert (await app.instance()).status == "running"


async def test_a_snapshot_without_an_identity_key_keeps_the_instances_own(app, tmp_path):
    _volumes(app, tmp_path)
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    old = (await app.instance()).app_secrets["APP_KEY"]
    sid = await _make_snapshot()
    dep = await app.deploy(kind="reset", snapshot_id=sid)
    assert dep.status == "succeeded", dep.error
    assert _steps(dep)["check"] == "warning" and "The snapshot has no APP_KEY" in _note(dep, "check")
    assert (await app.instance()).app_secrets["APP_KEY"] == old


# ------------------------------------------------------------------- seeded first deploy (test 21)


async def test_a_seeded_first_deploy_restores_before_up_and_a_retry_skips_what_was_done(app, tmp_path):
    _volumes(app, tmp_path)
    gh = _github(FILES_YML)
    sid = await _make_snapshot(files_text="FILES:\nphoto\n")
    await app.seed(seed_snapshot_id=sid)
    await _add_first_admin(app.instance_id)
    app.env["IMPORT_FAIL"] = "1"
    dep = await app.deploy(gh)
    assert dep.status == "failed"
    assert list(_steps(dep))[6:] == ["build", "check", "backup", "stop", "restore", "files", "after_import", "start",
                                     "finish", "first_admin", "proxy"]
    assert _steps(dep)["restore"] == "succeeded" and _steps(dep)["files"] == "failed"
    assert dep.snapshot_id == sid
    inst = await app.instance()
    assert inst.seed_snapshot_id == sid and inst.fresh_data == "snapshot"  # cleared only when the job succeeds
    app.env.pop("IMPORT_FAIL")
    app.app_log.write_text("")
    retry = await _retry(app, dep, gh)
    assert retry.status == "succeeded", (retry.error, retry.log)
    assert _steps(retry)["restore"] == "skipped" and _note(retry, "restore") == \
        f"Done by the first attempt ({dep.id.hex[:8]}); not repeated"
    assert _steps(retry)["files"] == "succeeded" and _steps(retry)["first_admin"] == "succeeded"
    assert not any(c.startswith("restore") for c in app.calls())
    assert (app.state / "files").read_text() == "photo\n" and (app.state / "db").read_text() == "FROM-SNAP\nMIGRATED\n"
    inst = await app.instance()
    assert inst.seed_snapshot_id is None and inst.fresh_data is None and inst.status == "running"
    # A deploy after it is an ordinary one: no seed, no snapshot.
    again = await app.deploy(gh)
    assert again.status == "succeeded" and "seed" not in _steps(again) and "check" not in _steps(again)


async def test_seeding_onto_a_host_that_already_has_data_is_refused_before_staging(app, tmp_path):
    volumes = _volumes(app, tmp_path)
    volumes.write_text("demo-web-prod-db_data demo-web-prod-db\n")
    app.state.mkdir()
    (app.state / "db").write_text("SOMEONE ELSE'S\n")
    sid = await _make_snapshot()
    # Without the secrets that data was made with, the manifest step refuses the volumes already.
    await app.seed(seed_snapshot_id=sid)
    dep = await app.deploy()
    assert dep.status == "failed" and _steps(dep)["manifest"] == "failed" and "already has the volumes" in dep.error
    # With them, the check step refuses to seed over it.
    await _set(Instance, app.instance_id, env={"APP_SECRET": "ab" * 32, "APP_KEY": _fernet()})
    dep = await app.deploy()
    assert dep.status == "failed" and _steps(dep)["check"] == "failed"
    assert dep.error.startswith("prod-01 already has data for this app (commands.has_data found data). Seeding from "
                                "snapshot snap-1 would replace it")
    assert not (app.backups / ".incoming").exists() or list((app.backups / ".incoming").iterdir()) == []
    assert (app.state / "db").read_text() == "SOMEONE ELSE'S\n"


# Like ss-stack: "down" stops the data services too, "data" starts them, and import-objects and clear-sessions
# need them running.
SERVICES_SCRIPT = APP_SCRIPT.replace("  build|down) ;;", "  build) ;;\n  down) rm -f \"$STATE/services-up\" ;;") \
    .replace("  data) volume ;;", "  data) volume; touch \"$STATE/services-up\" ;;") \
    .replace("  import-objects) [ -n", "  import-objects) [ -f \"$STATE/services-up\" ] || "
                                      "{ echo 'seaweedfs: could not connect' >&2; exit 1; }; [ -n") \
    .replace("  clear-sessions) ;;", "  clear-sessions) [ -f \"$STATE/services-up\" ] || "
                                     "{ echo 'db is not running' >&2; exit 1; } ;;")


async def test_a_retry_that_skips_the_restore_still_starts_the_data_services_for_the_files(app, tmp_path):
    """Review finding 11: stop runs again on a retry and may stop the data services; the files import needs them."""
    assert SERVICES_SCRIPT != APP_SCRIPT
    _volumes(app, tmp_path)
    gh = _github(FILES_YML, SERVICES_SCRIPT)
    sid = await _make_snapshot(files_text="FILES:\nphoto\n")
    await app.seed(seed_snapshot_id=sid)
    app.env["IMPORT_FAIL"] = "1"
    dep = await app.deploy(gh)
    assert dep.status == "failed" and _steps(dep)["files"] == "failed"
    app.env.pop("IMPORT_FAIL")
    app.app_log.write_text("")
    retry = await _retry(app, dep, gh)
    assert retry.status == "succeeded", (retry.error, retry.log)
    assert _steps(retry)["restore"] == "skipped" and _steps(retry)["files"] == "succeeded"
    calls = [c.split()[0] for c in app.calls()]
    after_stop = calls[calls.index("down"):]
    assert after_stop[:3] == ["down", "data", "import-objects"], calls
    assert after_stop.count("data") == 1  # import-objects and clear-sessions share one data_up
    assert (app.state / "files").read_text() == "photo\n"


async def test_a_retry_after_start_over_restores_the_snapshot_again(app, tmp_path):
    """Review finding 5: Start over deleted what the first attempt restored, so the retry can't skip it."""
    _volumes(app, tmp_path)
    gh = _github(FILES_YML)
    key = _fernet()
    sid = await _make_snapshot(files_text="FILES:\nphoto\n", identity={"APP_KEY": key})
    await app.seed(seed_snapshot_id=sid)
    app.env["IMPORT_FAIL"] = "1"
    d1 = await app.deploy(gh)
    assert d1.status == "failed" and _steps(d1)["restore"] == "succeeded", d1.error
    app.env.pop("IMPORT_FAIL")
    over = await app.deploy(gh, kind="reset", options={"start_over": True})
    assert over.status == "succeeded", (over.error, over.log)
    async with get_sessionmaker()() as db:
        parent = await db.get(Deployment, d1.id)
        assert (await data.retry_inheritance(db, parent)).done_by == {}  # Start over ran after it
        assert (await data.retry_state(db, parent))["available"] is True
    retry = await _retry(app, d1, gh)
    assert retry.status == "succeeded", (retry.error, retry.log)
    assert _steps(retry)["restore"] == "succeeded" and _steps(retry)["files"] == "succeeded"
    assert "FROM-SNAP" in (app.state / "db").read_text() and (app.state / "files").read_text() == "photo\n"
    inst = await app.instance()
    assert inst.app_secrets["APP_KEY"] == key and inst.live_identity == {"APP_KEY": key}


async def test_a_retry_wont_drop_or_swap_a_seed_changed_since_the_first_attempt(app, tmp_path):
    """Review findings 15 and 20: the seed set (or cleared) after the first attempt isn't bypassed by Retry."""
    _volumes(app, tmp_path)
    await app.seed()
    flag = tmp_path / "fail"
    flag.write_text("")
    app.env["FAIL_FLAG"] = str(flag)
    d1 = await app.deploy()
    assert d1.status == "failed" and d1.snapshot_id is None
    flag.unlink()
    sid = await _make_snapshot()
    await _set(Instance, app.instance_id, seed_snapshot_id=sid)  # what PATCH seed_snapshot_id does (data:reset)
    async with get_sessionmaker()() as db:
        state = await data.retry_state(db, await db.get(Deployment, d1.id))
    assert state["available"] is False and state["reason"] == (
        "This deployment started web empty, and web now starts from snapshot snap-1: "
        "deploy the instance instead")
    retry = await _retry(app, d1)  # queued before the seed changed: the job refuses it when it starts
    assert retry.status == "failed" and "now starts from snapshot snap-1" in retry.error
    inst = await app.instance()
    assert inst.seed_snapshot_id == sid and inst.current_commit_sha is None
    # The deploy the message points at takes the seed.
    dep = await app.deploy()
    assert dep.status == "succeeded" and dep.snapshot_id == sid and _steps(dep)["restore"] == "succeeded"


async def test_a_reset_whose_snapshot_was_deleted_isnt_retried_without_its_files(app, tmp_path):
    """Review finding 6: with the snapshot gone, the files it still had to import can't be imported."""
    _volumes(app, tmp_path)
    gh = _github(FILES_YML)
    await app.seed()
    assert (await app.deploy(gh)).status == "succeeded"
    sid = await _make_snapshot(files_text="FILES:\nphoto\n")
    app.env["IMPORT_FAIL"] = "1"
    r1 = await app.deploy(gh, kind="reset", snapshot_id=sid)
    assert r1.status == "failed" and _steps(r1)["restore"] == "succeeded" and _steps(r1)["files"] == "failed"
    app.env.pop("IMPORT_FAIL")
    async with get_sessionmaker()() as db:  # the row goes, and deployments.snapshot_id is set to null with it
        await db.delete(await db.get(Snapshot, sid))
        await db.execute(update(Deployment).where(Deployment.snapshot_id == sid).values(snapshot_id=None))
        await db.commit()
    async with get_sessionmaker()() as db:
        state = await data.retry_state(db, await db.get(Deployment, r1.id))
    assert state["available"] is False
    assert state["reason"] == "The snapshot this job restores was deleted; start a new reset instead"
    retry = await _retry(app, r1, gh)
    assert retry.status == "failed" and "The snapshot this job restores was deleted" in retry.error
    inst = await app.instance()
    assert inst.data_dirty["hold"] is True  # still held: the files were never imported
    assert not (app.state / "files").exists()


# --------------------------------------------------------------------------------- Start over (test 22)


async def test_start_over_removes_what_failed_first_deploys_left(app, tmp_path):
    volumes = _volumes(app, tmp_path)
    flag = tmp_path / "fail"
    flag.write_text("")
    app.env["FAIL_FLAG"] = str(flag)
    await app.seed()
    admin_id = await _add_first_admin(app.instance_id)
    failed = await app.deploy()
    assert failed.status == "failed"
    (app.state / "db").write_text("HALF\n")  # what the failed migration left
    await _set(FirstAdmin, admin_id, status="done", password=None)
    dep = await app.deploy(kind="reset", options={"start_over": True})
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert list(_steps(dep)) == ["release", "backup", "stop", "reset"]
    [row] = await app.backups_rows()
    assert row.reason == "pre_reset" and (app.backups / f"{row.name}.dump").read_text() == "DB:\nHALF\n"
    assert "_db_data" not in volumes.read_text() and "volume rm -- demo-web-prod-db_data" in _docker_log(app)
    inst = await app.instance()
    assert inst.fresh_data == "empty" and inst.status == "failed"  # the status stays as it was
    assert (await _get(FirstAdmin, admin_id)).status == "pending"
    # The next deploy is an empty start: it seeds, and the first admin is made again.
    flag.unlink()
    await _set(FirstAdmin, admin_id, password="correct-horse-9")
    dep = await app.deploy()
    assert dep.status == "succeeded", dep.error
    assert _note(dep, "backup").startswith("No data yet") and _steps(dep)["seed"] == "succeeded"
    assert (app.state / "db").read_text() == "MIGRATED\nSEEDED\n" and (await _get(FirstAdmin, admin_id)).status == "done"


# Data volumes declared, but no dump (and so no restore): a valid slipway.yml whose data Slipway can't copy.
NO_DUMP_YML = DATA_YML.replace("""  app: demo
  format: demo-v1
""", "")
for _line in ("has_data", "data_up", "dump", "verify_dump", "revision", "accepts", "restore", "seed"):
    NO_DUMP_YML = "\n".join(ln for ln in NO_DUMP_YML.split("\n") if not ln.startswith(f"  {_line}: "))


async def test_start_over_wont_delete_data_it_cant_back_up_unless_told_to(app, tmp_path):
    volumes = _volumes(app, tmp_path)
    flag = tmp_path / "fail"
    flag.write_text("")
    app.env["FAIL_FLAG"] = str(flag)
    await app.seed()
    gh = _github(NO_DUMP_YML)
    failed = await app.deploy(gh)
    assert failed.status == "failed", failed.error
    assert "demo-web-prod-db_data" in volumes.read_text()
    dep = await app.deploy(kind="reset", options={"start_over": True})
    assert dep.status == "failed" and _steps(dep)["backup"] == "failed" and _steps(dep)["stop"] == "pending"
    assert dep.error == ("web has data on prod-01 (demo-web-prod-db_data), and slipway.yml has no dump command, so "
                         "Slipway can't back it up first. Nothing was changed. To delete it anyway, Retry without the "
                         "backup.")
    assert "demo-web-prod-db_data" in volumes.read_text() and not any("volume rm" in c for c in _docker_log(app))
    inst = await app.instance()
    assert inst.data_dirty["last"]["deployment_id"] == failed.id.hex and inst.status == "failed"  # as it was
    async with get_sessionmaker()() as db:
        assert (await data.retry_state(db, await db.get(Deployment, dep.id)))["offers_skip_backup"]
    # Retry without the backup (data:reset, the typed name, audited) is the one way to delete it anyway.
    retry = await _retry(app, dep, skip_backup=True)
    assert retry.status == "succeeded", (retry.error, retry.log)
    assert _steps(retry)["backup"] == "warning" and "demo-web-prod-db_data" not in volumes.read_text()


async def test_start_over_refuses_projects_its_failed_deploys_didnt_use(app, tmp_path):
    # The projects and volumes come from a setting; someone edits it after the failed deploy, then starts over.
    yml = DATA_YML.replace("""  APP_DOMAIN: {label: Base domain, required: true}
vars:
  APP_ENV: "{slipway.slug}"
""", """  APP_DOMAIN: {label: Base domain, required: true}
  APP_ENV: {label: Environment, required: true}
vars:
""")
    volumes = _volumes(app, tmp_path)
    flag = tmp_path / "fail"
    flag.write_text("")
    app.env["FAIL_FLAG"] = str(flag)
    await app.seed()
    await _set(Instance, app.instance_id, app_settings={"APP_DOMAIN": "uat.example.com", "APP_ENV": "uat"})
    gh = _github(yml)
    failed = await app.deploy(gh)
    assert failed.status == "failed", failed.error
    async with get_sessionmaker()() as db:  # another, live instance on the host runs the "prod" projects
        inst = await db.get(Instance, app.instance_id)
        other = Instance(name="prod", slug="prod", branch="main", host_id=inst.host_id, repository_id=inst.repository_id,
                         env={}, ports=[], volumes=[], build_source="app", status="running", current_commit_sha="a" * 40,
                         app_state={"projects": ["demo-prod-web", "demo-prod-db"],
                                    "known_projects": ["demo-prod-web", "demo-prod-db"]})
        db.add(other)
        await db.commit()
        other_id = other.id
    with volumes.open("a") as fh:
        fh.write("demo-prod-db_data demo-prod-db\n")
    await _set(Instance, app.instance_id, app_settings={"APP_DOMAIN": "uat.example.com", "APP_ENV": "prod"})
    app.app_log.write_text("")
    dep = await app.deploy(kind="reset", options={"start_over": True})
    assert dep.status == "failed" and _steps(dep)["release"] == "failed"
    assert (f"Release {SHA[:7]} would now run under other Compose projects (demo-prod-web, demo-prod-db) than web's "
            "deploys used (demo-uat-web, demo-uat-db)") in dep.error
    assert "demo-prod-db_data demo-prod-db" in volumes.read_text()
    assert not any(c.startswith("down") for c in app.calls())
    assert not any("demo-prod" in c for c in _docker_log(app) if "down" in c or "volume rm" in c)
    # A project another instance on the host also has is refused too, even when this instance's deploys used it.
    await _set(Instance, app.instance_id, app_settings={"APP_DOMAIN": "uat.example.com", "APP_ENV": "uat"})
    await _set(Instance, other_id, app_state={"known_projects": ["demo-prod-web", "demo-prod-db", "demo-uat-db"]})
    dep = await app.deploy(kind="reset", options={"start_over": True})
    assert dep.status == "failed" and "the Compose project demo-uat-db is also instance prod's" in dep.error
    assert not any(c.startswith("down") for c in app.calls())


async def test_a_start_over_that_fails_in_reset_doesnt_hold_off_the_next_deploy(app, tmp_path):
    _volumes(app, tmp_path)
    flag = tmp_path / "fail"
    flag.write_text("")
    app.env["FAIL_FLAG"] = str(flag)
    await app.seed()
    assert (await app.deploy()).status == "failed"
    app.env["FAKE_VOLUME_BUSY"] = "demo-web-prod-db_data"
    dep = await app.deploy(kind="reset", options={"start_over": True})
    assert dep.status == "failed" and _steps(dep)["reset"] == "failed"
    inst = await app.instance()
    assert inst.data_dirty["last"]["deployment_id"] == dep.id.hex and inst.data_dirty["hold"] is False
    async with get_sessionmaker()() as db:
        assert await data.hold_text(db, inst) is None
    del app.env["FAKE_VOLUME_BUSY"]
    flag.unlink()
    dep = await app.deploy()
    assert dep.status == "succeeded", dep.error
    assert (await app.instance()).data_dirty is None


# ------------------------------------------------------------------- data-only jobs (tests 23, 24, 25)


async def test_back_up_now_on_a_stopped_app_stops_its_data_services_again(app, tmp_path):
    await app.seed()
    first = await app.deploy()
    assert first.status == "succeeded"
    flag = tmp_path / "fail"
    flag.write_text("")
    app.env["FAIL_FLAG"] = str(flag)
    assert (await app.deploy()).status == "failed"  # its .env is the failed release's now
    await _set(Instance, app.instance_id, status="stopped")
    app.env["FAKE_PS"] = "aaaaaaaaaaaa"
    app.app_log.write_text("")
    dep = await app.deploy(kind="backup")
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert list(_steps(dep)) == ["release", "backup", "restop"] and _steps(dep)["restop"] == "succeeded"
    live = app.release_of(first.id)
    assert app.calls()[0] == f"has-data {live}"  # the live render rewrote the .env
    assert f"APP_REPO={app.base}/releases/{live}" in (app.base / "shared" / ".env").read_text()
    assert not any(c.startswith(("down", "up")) for c in app.calls())  # never slipway.yml's stop or start (D17)
    assert "compose -p demo-web-prod-web stop" in _docker_log(app)
    inst = await app.instance()
    assert inst.status == "stopped" and [r.reason for r in await app.backups_rows()][-1] == "manual"


async def test_retry_of_a_back_up_taken_while_stopped_never_stops_an_app_started_since(app):
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    await _set(Instance, app.instance_id, status="stopped")
    app.env["FAKE_PS"] = "aaaaaaaaaaaa"
    dep = await app.deploy(kind="backup", options={"files": False, "restop": True})
    assert "restop" in _steps(dep)
    await _set(Deployment, dep.id, status="failed")
    await _set(Instance, app.instance_id, status="running")  # started again by an operator
    async with get_sessionmaker()() as db:
        values = await deployer.retry_values(db, await db.get(Deployment, dep.id))
    assert values["options"]["restop"] is False
    before = len(_docker_log(app))
    retry = await _retry(app, dep, restop=True)  # even a copied restop is worked out again when the job starts
    assert retry.status == "succeeded", (retry.error, retry.log)
    assert "restop" not in _steps(retry) and retry.options["restop"] is False
    assert not any(line.endswith(" stop") for line in _docker_log(app)[before:])
    assert (await app.instance()).status == "running"


async def test_back_up_now_refuses_an_undeployed_identity_key(app):
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    await _set(Instance, app.instance_id, env={"APP_KEY": _fernet()})
    dep = await app.deploy(kind="backup")
    assert dep.status == "failed" and _steps(dep)["release"] == "failed"
    assert dep.error.startswith("APP_KEY differs from the value web's data was made with")
    assert (await app.instance()).status == "running"


async def test_create_it_now_and_add_starter_content(app):
    await app.seed()
    app.env["SEED_FAIL"] = "1"
    assert (await app.deploy()).status == "succeeded"
    assert (await app.instance()).content_pending is True
    admin_id = await _add_first_admin(app.instance_id)
    dep = await app.deploy(kind="admin")
    assert dep.status == "succeeded" and list(_steps(dep)) == ["release", "first_admin"]
    assert (await _get(FirstAdmin, admin_id)).status == "done"
    app.env.pop("SEED_FAIL")
    dep = await app.deploy(kind="content")
    assert dep.status == "succeeded" and _steps(dep)["seed"] == "succeeded"
    inst = await app.instance()
    assert inst.content_pending is False and inst.status == "running"


async def _pending_snapshot(app: App, name: str = "uat-1") -> uuid.UUID:
    async with get_sessionmaker()() as db:
        row = Snapshot(name=name, status="pending", origin="instance", app="demo", source="web",
                       source_instance_id=app.instance_id)
        db.add(row)
        await db.commit()
        return row.id


async def test_take_a_snapshot_while_the_app_is_stopped(shell_app, tmp_path):
    app = shell_app
    gh = _github(FILES_YML)
    await app.seed()
    assert (await app.deploy(gh)).status == "succeeded"
    (app.state / "files").write_text("photo\n")
    sid = await _pending_snapshot(app)
    app.env["FAKE_PS"] = "aaaaaaaaaaaa"
    dep = await app.deploy(gh, kind="snapshot", snapshot_id=sid, options={"stop_app": True})
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert list(_steps(dep)) == ["release", "stop", "export", "restart", "store"]
    docker = _docker_log(app)
    assert docker.index("compose -p demo-web-prod-web stop") < docker.index("compose -p demo-web-prod-web start")
    row = await _get(Snapshot, sid)
    assert row.status == "ready" and row.db_format == "demo-v1" and row.files_format == "demo-files-v1"
    assert row.identity_keys == ["APP_KEY"] and row.repository == "acme/web" and row.deployment_id == dep.id
    path = snapshots.bundle_path(sid)
    raw = path.read_bytes()
    assert raw.startswith(snapfile.MAGIC) and row.file_bytes == len(raw)
    assert hashlib.sha256(raw).hexdigest() == row.file_sha256
    with path.open("rb") as f:
        assert snapfile.read_preamble(f).keyblock == {"kdf": "none"}
    held: dict[str, bytes] = {}
    with path.open("rb") as f:
        contents = snapfile.validate_container(
            f, snapshots.data_key(row),
            sink=lambda name, chunk: held.__setitem__(name, held.get(name, b"") + (chunk or b"")))
    inst = await app.instance()
    assert contents.identity == inst.live_identity and held == {"database": b"DB:\nMIGRATED\nSEEDED\n",
                                                                "files": b"FILES:\nphoto\n"}
    assert inst.live_identity["APP_KEY"].encode() not in raw  # encrypted at rest
    assert list((app.backups / ".incoming").iterdir()) == [] and inst.status == "running"


async def test_a_snapshot_that_cant_be_stored_fails_with_the_app_running_again(app, tmp_path, monkeypatch):
    from slipway.core.config import get_settings
    gh = _github(FILES_YML)
    await app.seed()
    assert (await app.deploy(gh)).status == "succeeded"
    sid = await _pending_snapshot(app)
    monkeypatch.setattr(get_settings(), "snapshot_total_bytes", 10)
    app.env["FAKE_PS"] = "aaaaaaaaaaaa"
    dep = await app.deploy(gh, kind="snapshot", snapshot_id=sid, options={"stop_app": True})
    assert dep.status == "failed" and "SLIPWAY_SNAPSHOT_TOTAL_BYTES" in dep.error
    assert _steps(dep)["restart"] == "succeeded" and _steps(dep)["store"] == "failed"
    assert "compose -p demo-web-prod-web start" in _docker_log(app)
    row = await _get(Snapshot, sid)
    assert row.status == "failed" and "SLIPWAY_SNAPSHOT_TOTAL_BYTES" in row.error
    assert not snapshots.bundle_path(sid).exists() and list(snapshots.incoming_dir().iterdir()) == []
    assert list((app.backups / ".incoming").iterdir()) == []
    assert (await app.instance()).status == "running"


# --------------------------------------------------------------------------- destroy and moves (test 27)


async def test_destroy_keeps_the_backups_with_their_keys(app):
    _, row = await _deployed_with_backup(app)
    inst = await app.instance()
    report: dict = {}
    note = await deployer.destroy(inst, connect=_local(app.remote), report=report)
    kept = app.root / ".slipway-kept" / f"web-prod-{inst.id.hex[:8]}.backups"
    assert sorted(p.name for p in kept.iterdir()) == sorted(
        [f"{row.name}.dump", f"{row.name}.json", f"{row.name}.identity.env"])
    identity = kept / f"{row.name}.identity.env"
    assert identity.read_text() == f"APP_KEY={inst.live_identity['APP_KEY']}\n"
    assert stat.S_IMODE(identity.stat().st_mode) == 0o600
    assert "1 backup (with their identity keys)" in note and str(app.root / ".slipway-kept") in note
    assert report["backups"] == [{"name": row.name, "db_sha256": row.db_sha256}] and report["kept_backups"] == str(kept)
    assert not app.base.exists()


async def test_removing_from_slipway_only_keeps_the_keys_of_backups_taken_with_others(app):
    """Delete with purge=false: the backup rows go, so a dump taken with other identity keys than the data's gets
    its <name>.identity.env next to it; nothing else on the host changes."""
    _, row = await _deployed_with_backup(app)
    inst = await app.instance()
    assert await deployer.keep_identity_files(inst, connect=_local(app.remote)) is None
    assert not (app.backups / f"{row.name}.identity.env").exists()  # the .env opens it: nothing to write
    other = _fernet()
    await _set(Backup, row.id, identity={"APP_KEY": other},
               identity_fp=data.identity_fp(row.id, ["APP_KEY"], {"APP_KEY": other}))
    before = sorted(p.name for p in app.base.rglob("*"))
    app.remote.commands.clear()
    assert await deployer.keep_identity_files(inst, connect=_local(app.remote)) is None
    identity = app.backups / f"{row.name}.identity.env"
    assert identity.read_text() == f"APP_KEY={other}\n" and stat.S_IMODE(identity.stat().st_mode) == 0o600
    assert sorted(p.name for p in app.base.rglob("*")) == sorted([*before, identity.name])
    assert not any(("docker" in c or "rm " in c) for c in app.remote.commands)

    def unreachable(target, **kw):
        raise ssh.SSHError("Could not connect to 10.0.0.1: timed out")
    note = await deployer.keep_identity_files(inst, connect=unreachable)
    assert note == (f"The identity keys of backup {row.name} could not be written next to it on prod-01 (Could not "
                    "connect to 10.0.0.1: timed out); Slipway no longer has a copy")


async def test_destroy_with_containers_left_moves_nothing(app):
    _, row = await _deployed_with_backup(app)
    app.env["FAKE_PS"] = "aaaaaaaaaaaa"
    with pytest.raises(deployer.DeployError, match="still on"):
        await deployer.destroy(await app.instance(), connect=_local(app.remote))
    assert (app.backups / f"{row.name}.dump").exists() and not (app.root / ".slipway-kept").exists()
    assert (await _get(Backup, row.id)).status == "ready"


async def test_a_folder_move_takes_the_backups_and_checks_the_room(app, tmp_path):
    _, row = await _deployed_with_backup(app)
    new_dir = tmp_path / "elsewhere" / "web"
    app.env["FAKE_DF_KB"] = "1"
    with pytest.raises(deployer.DeployError, match=r" on prod-01 has 1 KiB free; moving web needs .* \(its backups "
                                                   r"included\)\. Free some space or delete old backups first\."):
        await deployer.move_instance_dir(await app.instance(), str(new_dir), save=_noop, connect=_local(app.remote))
    app.env["FAKE_DF_KB"] = str(100 * 1024 * 1024)

    async def save() -> None:
        await _set(Instance, app.instance_id, deploy_dir=str(new_dir))

    notes = await deployer.move_instance_dir(await app.instance(), str(new_dir), save=save, connect=_local(app.remote))
    assert notes == [] and not app.base.exists()
    assert (new_dir / "backups" / f"{row.name}.dump").exists()
    dep = await app.deploy(kind="restore", restore_backup_id=row.id)
    assert dep.status == "succeeded", (dep.error, dep.log)


async def _noop() -> None:
    return None


# ------------------------------------------------------------------------------- host lock (test 28)


async def test_a_timed_out_restore_keeps_the_lock_and_its_retry_waits(app):
    _, row = await _deployed_with_backup(app)
    app.env["RESTORE_SLEEP"] = "30"
    app.remote.timeout_on = "deploy/app restore"
    try:
        dep = await app.deploy(kind="restore", restore_backup_id=row.id)
        assert dep.status == "failed" and "timed out" in dep.error
        words = (app.base / ".slipway-lock").read_text().split()
        assert words[0] == str(dep.id) and words[3:] == ["restore", "d"]
        app.remote.timeout_on = None
        app.env.pop("RESTORE_SLEEP")
        blocked = await _retry(app, dep)
        assert blocked.status == "failed" and _steps(blocked)["release"] == "failed"
        assert blocked.error.startswith(f"Job {dep.id.hex[:8]}'s restore (pid {words[2]}) is still running on prod-01")
    finally:
        app.remote.stop_timed_out()
    again = await _retry(app, blocked)
    assert again.status == "succeeded", (again.error, again.log)
    assert f"Took over the lock of job {dep.id.hex[:8]} (its restore has ended)" in again.log
    assert (await app.instance()).data_dirty is None


# ------------------------------------------------------------------------- recover_interrupted (test 29)


async def test_recovery_after_a_restart(app):
    _, row = await _deployed_with_backup(app)
    # A backup that was written but not recorded, and one that never got its file.
    kept_id, lost_id = uuid.uuid4(), uuid.uuid4()
    taken = row.taken_at
    kept_name, lost_name = data.backup_name(kept_id, taken), data.backup_name(lost_id, taken)
    (app.backups / f"{kept_name}.dump").write_text("DB:\nWRITTEN\n")
    async with get_sessionmaker()() as db:
        for bid, name in ((kept_id, kept_name), (lost_id, lost_name)):
            db.add(Backup(id=bid, instance_id=app.instance_id, name=name, reason="manual", status="pending",
                          format="demo-v1", identity_keys=[], identity_fp="x", taken_at=taken))
        db.add(Snapshot(name="half", status="pending", origin="instance"))
        steps = deployer.steps_for(await db.get(Instance, app.instance_id), "restore")
        for s in steps:
            s["status"] = {"release": "succeeded", "manifest": "succeeded", "settings": "succeeded",
                           "build": "skipped", "check": "succeeded", "backup": "succeeded", "stop": "succeeded",
                           "restore": "running"}.get(s["key"], "pending")
        dep = Deployment(instance_id=app.instance_id, branch="main", log="", kind="restore", status="running",
                         steps=steps, options={"prev_status": "running"}, restore_backup_id=row.id, backup_id=row.id)
        db.add(dep)
        (await db.get(Instance, app.instance_id)).status = "deploying"
        await db.commit()
    await deployer.runner.recover_interrupted()
    inst = await app.instance()
    assert inst.status == "failed" and inst.data_dirty["hold"] is True and inst.data_dirty["last"]["step"] == "restore"
    assert (await _get(Backup, kept_id)).status == "unverified" and (await _get(Backup, lost_id)).status == "unverified"
    async with get_sessionmaker()() as db:
        half = await db.scalar(select(Snapshot).where(Snapshot.name == "half"))
    assert half.status == "failed" and "take it again" in half.error
    # The next job settles the unverified rows both ways.
    backup = await app.deploy(kind="backup")
    assert backup.status == "succeeded", backup.error
    kept = await _get(Backup, kept_id)
    assert kept.status == "ready" and kept.db_bytes == len("DB:\nWRITTEN\n")
    assert await _get(Backup, lost_id) is None and f"Backup {lost_name} never finished" in backup.log


async def test_an_interrupted_restore_that_changed_nothing_puts_the_status_back(app):
    _, row = await _deployed_with_backup(app)
    async with get_sessionmaker()() as db:
        steps = deployer.steps_for(await db.get(Instance, app.instance_id), "restore")
        for s in steps:
            s["status"] = {"release": "succeeded", "check": "succeeded", "backup": "running"}.get(s["key"], "pending")
        db.add(Deployment(instance_id=app.instance_id, branch="main", log="", kind="restore", status="running",
                          steps=steps, options={"prev_status": "running"}, restore_backup_id=row.id))
        (await db.get(Instance, app.instance_id)).status = "deploying"
        await db.commit()
    await deployer.runner.recover_interrupted()
    inst = await app.instance()
    assert inst.status == "running" and inst.data_dirty is None


# --------------------------------------------------------------------------------------- retry values


async def test_retry_values_inherit_only_after_a_change_began(app, tmp_path):
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    flag = tmp_path / "fail"
    flag.write_text("")
    app.env["FAIL_FLAG"] = str(flag)
    failed = await app.deploy(options={"skip_revision_check": True, "started_empty": False})
    async with get_sessionmaker()() as db:
        values = await deployer.retry_values(db, await db.get(Deployment, failed.id))
    assert values["kind"] == "deploy" and values["backup_id"] == failed.backup_id
    assert values["options"] == {"started_empty": False, "inherit": True}  # one-shot flags are not copied
    # A backup taken by hand in between doesn't move "the latest job" (D10): the retry still inherits.
    assert (await app.deploy(kind="backup")).status == "succeeded"
    async with get_sessionmaker()() as db:
        assert (await deployer.retry_values(db, await db.get(Deployment, failed.id)))["options"].get("inherit") is True


async def test_a_deploy_that_changes_the_format_and_fails_can_be_rolled_back(app, tmp_path):
    """Test 9: the pre-deploy dump is the live release's, in the live format, so Roll back can restore it."""
    await app.seed()
    first = await app.deploy()
    assert first.status == "succeeded"
    flag = tmp_path / "fail"
    flag.write_text("")
    app.env["FAIL_FLAG"] = str(flag)
    failed = await app.deploy(_github(DATA_YML.replace("format: demo-v1", "format: demo-v2")))
    assert failed.status == "failed"
    [row] = await app.backups_rows()
    assert row.format == "demo-v1"
    async with get_sessionmaker()() as db:
        state = await data.rollback_state(db, await db.get(Deployment, failed.id))
    assert state.available, state.reason
    flag.unlink()
    dep = await app.deploy(kind="rollback", restore_backup_id=row.id, options={"rollback_of": failed.id.hex})
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert (await app.instance()).app_state["manifest"]["data"]["format"] == "demo-v1"


async def test_after_a_folder_move_the_data_jobs_use_the_new_paths(app, tmp_path):
    """Test 14: a move never rewrites app_state; the live render uses today's folder (D3)."""
    gh = _github(FILES_YML)
    await app.seed()
    assert (await app.deploy(gh)).status == "succeeded"
    new_dir = tmp_path / "moved" / "web"

    async def save() -> None:
        await _set(Instance, app.instance_id, deploy_dir=str(new_dir))

    assert await deployer.move_instance_dir(await app.instance(), str(new_dir), save=save,
                                            connect=_local(app.remote)) == []
    backup = await app.deploy(gh, kind="backup")
    assert backup.status == "succeeded", (backup.error, backup.log)
    [row] = await app.backups_rows()
    assert (new_dir / "backups" / f"{row.name}.dump").exists()
    assert f"APP_REPO={new_dir}/releases/" in (new_dir / "shared" / ".env").read_text()
    sid = await _pending_snapshot(app)
    snap = await app.deploy(gh, kind="snapshot", snapshot_id=sid)
    assert snap.status == "succeeded", (snap.error, snap.log)
    await _add_first_admin(app.instance_id)
    admin = await app.deploy(gh, kind="admin")
    assert admin.status == "succeeded" and _steps(admin)["first_admin"] == "succeeded"
    assert str(app.base) not in "".join(c for c in app.remote.commands[-20:])


async def test_a_take_commits_ready_before_it_drops_its_quota_reservation(app, monkeypatch):
    """Finding 37 by the take's path: between dropping its reservation and committing READY, the take's
    bytes were counted nowhere, so an upload checking the quota then could pass it."""
    gh = _github(FILES_YML)
    await app.seed()
    assert (await app.deploy(gh)).status == "succeeded"
    sid = await _pending_snapshot(app)
    real = snapshots.reserve
    at_release: list[str] = []

    @contextlib.asynccontextmanager
    async def watching(db, expected):
        async with real(db, expected) as guard:
            yield guard
            async with get_sessionmaker()() as other:
                at_release.append((await other.get(Snapshot, sid)).status)

    monkeypatch.setattr(snapshots, "reserve", watching)
    dep = await app.deploy(gh, kind="snapshot", snapshot_id=sid)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert at_release == ["ready"]


# ------------------------------------- after finish, and commands left running (review findings 8, 10, 14, 24, 34)

# APP_SCRIPT whose first-admin command can hang ($ADMIN_SLEEP), as one that waits on a slow database would.
SLEEPY_ADMIN = APP_SCRIPT.replace("  admin)\n", "  admin)\n    [ -n \"$ADMIN_SLEEP\" ] && sleep \"$ADMIN_SLEEP\"\n")


def _cut_off_on(app: App, text: str) -> None:
    """The next command containing ``text`` is cut off: Slipway is shutting down (shutdown cancels the job)."""
    real = app.remote.run

    async def run(command, **kw):
        if text in command:
            app.remote.run = real
            raise asyncio.CancelledError
        return await real(command, **kw)

    app.remote.run = run


async def _run_cut_off(app: App, **fields) -> Deployment:
    dep_id = await app.queue(**fields)
    with pytest.raises(asyncio.CancelledError):
        await deployer.run_deployment(dep_id, connect=_local(app.remote), github=DataGitHub)
    return await _get(Deployment, dep_id)


async def _rollback_offered(dep_id: uuid.UUID) -> bool:
    async with get_sessionmaker()() as db:
        return (await data.rollback_state(db, await db.get(Deployment, dep_id))).available


async def test_a_timed_out_first_admin_keeps_its_lock_line_and_seed_waits(app):
    """Finding 8: seed used to rewrite the lock line with its own PID, so the next job took over the lock while
    the first admin command still ran. Now the line keeps naming first_admin, and seed doesn't run."""
    gh = _github(DATA_YML, SLEEPY_ADMIN)
    await app.seed(seed_content=True)
    await _add_first_admin(app.instance_id)
    app.env["ADMIN_SLEEP"] = "30"
    app.remote.timeout_on = "--password-stdin"
    try:
        dep = await app.deploy(gh)
        assert dep.status == "succeeded", (dep.error, dep.log)
        assert _steps(dep)["first_admin"] == "warning" and "timed out" in _note(dep, "first_admin")
        words = (app.base / ".slipway-lock").read_text().split()
        assert words[0] == str(dep.id) and words[3:] == ["first_admin", "d"]
        pid = words[2]
        assert [p for p in app.remote.timed_out if p.poll() is None]  # the first admin command still runs
        assert _steps(dep)["seed"] == "warning"
        assert _note(dep, "seed") == (f"The starter content wasn't added: first_admin (pid {pid}) may still be running "
                                      "on prod-01. Add starter content once it has ended.")
        assert not any(c.startswith("seed ") for c in app.calls())
        assert (await app.instance()).content_pending is True
        assert f"first_admin (pid {pid}) may still be running on prod-01; the next job waits until it has ended" in dep.log
        app.remote.timeout_on = None
        blocked = await app.deploy(gh)
        assert blocked.status == "failed"
        assert blocked.error.startswith(f"Job {dep.id.hex[:8]}'s first_admin (pid {pid}) is still running on prod-01")
    finally:
        app.remote.stop_timed_out()
    app.env.pop("ADMIN_SLEEP")
    again = await app.deploy(gh)
    assert again.status == "succeeded", (again.error, again.log)
    assert f"Took over the lock of job {dep.id.hex[:8]} (its first_admin has ended)" in again.log


async def test_a_timed_out_pre_retry_dump_stops_the_retry_before_anything_changes(app, tmp_path):
    """Finding 8, the other way in: a pre_retry backup's failure is only a warning, but when its dump may still
    run, nothing else may run under the lock, so the retry stops in its backup step."""
    from slipway.db.base import utcnow
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    flag = tmp_path / "fail"
    flag.write_text("")
    app.env["FAIL_FLAG"] = str(flag)
    failed = await app.deploy()
    await _set(Instance, app.instance_id, last_control_at=utcnow())
    flag.unlink()
    app.env["DUMP_SLEEP"] = "30"
    app.remote.timeout_on = "pgdump"
    app.app_log.write_text("")
    try:
        retry = await app.deploy(retry_of_id=failed.id, backup_id=failed.backup_id, options={"inherit": True})
        assert retry.status == "failed" and "timed out" in retry.error
        assert _steps(retry)["backup"] == "failed" and _steps(retry)["start"] == "pending"
        assert not any(c.startswith("up ") for c in app.calls())
        words = (app.base / ".slipway-lock").read_text().split()
        assert words[0] == str(retry.id) and words[3:] == ["dump", "d"]
        assert f"dump (pid {words[2]}) may still be running on prod-01" in retry.log
    finally:
        app.remote.stop_timed_out()


async def test_a_deploy_cut_off_after_finish_still_succeeds(app):
    """Finding 10: a shutdown after finish used to fail the deploy and mark the data half-changed, so Roll back
    restored the old dump into the release that stayed live. The job went live: it succeeds (D12)."""
    await app.seed()
    first = await app.deploy()
    assert first.status == "succeeded"
    await _add_first_admin(app.instance_id)
    _cut_off_on(app, "deploy/app admin")
    dep = await _run_cut_off(app)
    assert dep.status == "succeeded" and dep.error is None, (dep.error, dep.log)
    steps = _steps(dep)
    assert steps["finish"] == "succeeded" and steps["first_admin"] == "warning" and steps["proxy"] == "skipped"
    assert _note(dep, "first_admin") == "Interrupted: Slipway is shutting down"
    assert _note(dep, "proxy").startswith("Not run: Slipway is shutting down. Use Sync proxy")
    assert f"cut off after release {SHA[:7]} went live (Slipway is shutting down)" in dep.log
    inst = await app.instance()
    assert inst.status == "running" and inst.current_commit_sha == SHA and inst.data_dirty is None
    assert inst.app_state["live"]["deployment"] == dep.id.hex and inst.app_state["went_live"] == dep.id.hex
    assert (app.base / "current").resolve().name == app.release_of(dep.id)
    assert not await _rollback_offered(dep.id)
    row = (await app.backups_rows())[-1]
    assert row.reason == "pre_deploy" and row.dirty_of is None


async def test_a_deploy_cut_off_as_finish_saves_the_live_state_still_succeeds(app, monkeypatch):
    """A cancel landing in finish's save, after its commit, used to leave job.went_live unset: the job ended
    cancelled with the data marked half-changed, though app_state already named it as live (D12)."""
    first, row = await _deployed_with_backup(app)
    real = deployer._save_instance

    async def save(instance, **fields):
        await real(instance, **fields)
        if (fields.get("app_state") or {}).get("went_live") not in (None, first.id.hex):  # this job's finish
            monkeypatch.setattr(deployer, "_save_instance", real)
            raise asyncio.CancelledError

    monkeypatch.setattr(deployer, "_save_instance", save)
    dep = await _run_cut_off(app)
    assert dep.status == "succeeded" and dep.error is None, (dep.error, dep.log)
    assert f"cut off after release {SHA[:7]} went live (Slipway is shutting down)" in dep.log
    inst = await app.instance()
    assert inst.status == "running" and inst.current_commit_sha == SHA and inst.data_dirty is None
    assert not await _rollback_offered(dep.id)


async def test_a_job_cut_off_between_commands_keeps_its_lock_without_reading_a_pid(app):
    """Cut off between commands, the lock is kept for the job's kind, and no lock line ever names that: the
    PID read is skipped, so a dead link can't hold up the shutdown."""
    first, row = await _deployed_with_backup(app)
    seen: list[str] = []
    real = app.remote.run

    async def record(command, **kw):
        seen.append(command)
        return await real(command, **kw)

    app.remote.run = record
    _cut_off_on(app, "ln -sfn")
    dep = await _run_cut_off(app)
    app.remote.run = real
    assert dep.status == "cancelled"
    assert "deploy may still be running on prod-01; the next job waits until it has ended" in dep.log
    assert not any(" own $lpid" in c for c in seen)
    assert (app.base / ".slipway-lock").read_text().split()[0] == str(dep.id)  # the lock stays


async def test_a_first_deploy_cut_off_in_seed_is_live_with_starter_content_pending(app):
    await app.seed(seed_content=True)
    _cut_off_on(app, "deploy/app seed")
    dep = await _run_cut_off(app)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert _steps(dep)["seed"] == "warning" and _steps(dep)["proxy"] == "skipped"
    inst = await app.instance()
    assert inst.status == "running" and inst.current_commit_sha == SHA and inst.data_dirty is None
    assert inst.content_pending is True and inst.fresh_data is None
    assert inst.live_identity == {"APP_KEY": inst.app_secrets["APP_KEY"]}  # saved at finish


async def test_a_deploy_lost_after_finish_is_recovered_as_live(app):
    """Finding 10, after a hard restart: app_state.went_live names the job, so recovery records it as live."""
    first, row = await _deployed_with_backup(app)
    new_sha = "b" * 40
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, app.instance_id)
        steps = deployer.steps_for(inst, "deploy", first_admin=True, seed=True)
        done = {"resolve", "source", "upload", "manifest", "ports", "settings", "build", "backup", "start", "finish"}
        for s in steps:
            s["status"] = "succeeded" if s["key"] in done else {"first_admin": "warning", "seed": "running"}.get(
                s["key"], "pending")
        dep = Deployment(instance_id=app.instance_id, branch="main", log="", kind="deploy", status="running",
                         steps=steps, commit_sha=new_sha, backup_id=row.id)
        db.add(dep)
        await db.flush()
        state = dict(inst.app_state)
        inst.app_state = {**state, "went_live": dep.id.hex, "live": {**state["live"], "sha": new_sha}}
        inst.status = "deploying"
        await db.commit()
        dep_id = dep.id
    await deployer.runner.recover_interrupted()
    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded" and dep.error is None
    assert _steps(dep)["seed"] == "warning" and _note(dep, "seed") == "Interrupted by a Slipway restart"
    assert _steps(dep)["first_admin"] == "warning" and _steps(dep)["proxy"] == "skipped"
    assert "Use Sync proxy" in _note(dep, "proxy")
    inst = await app.instance()
    assert inst.status == "running" and inst.current_commit_sha == new_sha and inst.data_dirty is None
    assert not await _rollback_offered(dep_id)


async def test_a_deploy_lost_before_finish_switched_is_still_failed(app):
    """The other side of finding 10: without went_live naming the job, a job cut off after start fails dirty."""
    first, row = await _deployed_with_backup(app)
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, app.instance_id)
        steps = deployer.steps_for(inst, "deploy")
        done = {"resolve", "source", "upload", "manifest", "ports", "settings", "build", "backup", "start"}
        for s in steps:
            s["status"] = "succeeded" if s["key"] in done else ("running" if s["key"] == "finish" else "pending")
        dep = Deployment(instance_id=app.instance_id, branch="main", log="", kind="deploy", status="running",
                         steps=steps, commit_sha="b" * 40, backup_id=row.id)
        db.add(dep)
        inst.status = "deploying"
        await db.commit()
        dep_id = dep.id
    await deployer.runner.recover_interrupted()
    assert (await _get(Deployment, dep_id)).status == "failed"
    inst = await app.instance()
    assert inst.status == "failed" and inst.current_commit_sha == SHA and inst.data_dirty["first"]["deployment_id"] == dep_id.hex


async def test_a_failed_prune_after_the_switch_doesnt_fail_the_deploy(app, monkeypatch):
    """Finding 14: an SSH error while finish tidied up after `ln -sfn` failed a deploy whose release was live."""
    await app.seed()
    assert (await app.deploy()).status == "succeeded"

    async def lost(*a, **kw):
        raise deployer.ssh.SSHError("SSH command failed: Connection lost")

    monkeypatch.setattr(deployer, "_prune_app_images", lost)
    dep = await app.deploy()
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert _steps(dep)["finish"] == "succeeded"
    assert "Warning: old releases and images could not be removed: SSH command failed: Connection lost" in dep.log
    inst = await app.instance()
    assert inst.status == "running" and inst.data_dirty is None and inst.app_state["live"]["deployment"] == dep.id.hex
    assert (app.base / "current").resolve().name == app.release_of(dep.id)
    assert not await _rollback_offered(dep.id)


async def test_a_snapshot_whose_restart_failed_leaves_the_instance_stopped(app, monkeypatch):
    """Finding 24, in-process: the app stopped for the export and couldn't start again shows as Stopped."""
    gh = _github(FILES_YML)
    await app.seed()
    assert (await app.deploy(gh)).status == "succeeded"
    sid = await _pending_snapshot(app)
    app.env["FAKE_PS"] = "aaaaaaaaaaaa"
    real = deployer._control

    async def control(c, action):
        if action == "start":
            raise deployer.DeployError("docker compose start failed")
        await real(c, action)

    monkeypatch.setattr(deployer, "_control", control)
    dep = await app.deploy(gh, kind="snapshot", snapshot_id=sid, options={"stop_app": True})
    assert dep.status == "failed" and _steps(dep)["restart"] == "failed"
    assert (await app.instance()).status == "stopped"


async def test_a_snapshot_cut_off_with_the_app_stopped_is_recovered_as_stopped(app):
    """Finding 24, after a hard restart: recovery sees the stop without its restart."""
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    rows = [{"key": k, "name": k, "status": s} for k, s in (("release", "succeeded"), ("stop", "succeeded"),
                                                            ("export", "running"), ("restart", "pending"),
                                                            ("store", "pending"))]
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=app.instance_id, branch="main", log="", kind="snapshot", status="running",
                         steps=rows, options={"stop_app": True})
        db.add(dep)
        await db.commit()
        dep_id = dep.id
    await deployer.runner.recover_interrupted()
    dep = await _get(Deployment, dep_id)
    assert dep.status == "failed" and dep.error == (
        "Interrupted by a Slipway restart. The app was stopped for the snapshot and Slipway didn't start it again; "
        "start it on the instance page.")
    assert (await app.instance()).status == "stopped"


async def test_a_snapshot_cut_off_after_its_restart_leaves_the_status(app):
    await app.seed()
    assert (await app.deploy()).status == "succeeded"
    rows = [{"key": k, "name": k, "status": s} for k, s in (("release", "succeeded"), ("stop", "succeeded"),
                                                            ("export", "succeeded"), ("restart", "succeeded"),
                                                            ("store", "running"))]
    async with get_sessionmaker()() as db:
        db.add(Deployment(instance_id=app.instance_id, branch="main", log="", kind="snapshot", status="running",
                          steps=rows, options={"stop_app": True}))
        await db.commit()
    await deployer.runner.recover_interrupted()
    assert (await app.instance()).status == "running"


def test_the_lock_line_a_job_left_gives_its_pid_only_while_it_runs(tmp_path):
    """Finding 34: the job that leaves the lock reads the PID back from it."""
    lock = str(tmp_path / ".slipway-lock")
    me, other = uuid.uuid4(), uuid.uuid4()

    def own(key: str) -> str | None:
        out = subprocess.run(["sh", "-c", data.lock_own_command(lock, me)], capture_output=True, text=True).stdout
        return data.parse_own_lock(out, key)

    assert own("dump") is None  # no lock file
    Path(lock).write_text(f"{me} - {os.getpid()} dump d\n")
    assert own("dump") == str(os.getpid())
    assert own("restore") is None  # another command wrote the line
    ended = subprocess.Popen(["true"])
    ended.wait()
    Path(lock).write_text(f"{me} - {ended.pid} dump d\n")
    assert own("dump") is None  # it has ended
    Path(lock).write_text(f"{other} - {os.getpid()} dump d\n")
    assert own("dump") is None  # another job's line
    assert data.lock_left_message("dump", 4242, "prod-01") == \
        "dump (pid 4242) may still be running on prod-01; the next job waits until it has ended"
