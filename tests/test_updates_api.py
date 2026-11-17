"""The Updates API and service: configuration, checks, starting runs and reading them back.

The server is a fake that answers the docker, git and file commands Slipway sends; nothing real is touched.
"""

from __future__ import annotations

import asyncio
import json
import re
import shlex
import uuid
from contextlib import asynccontextmanager

import pytest
from sqlalchemy import select

from slipway.db.session import get_sessionmaker
from slipway.models import AppSetting, AuditEvent, Deployment, Host, Instance, Repository
from slipway.services import ssh, updates
from tests.conftest import login, make_user

CID = "0123456789ab"
CONTAINER = CID + "cd" * 26
DIR = "/mnt/user/slipway"
FROM = "a" * 40
NEW = "b" * 40
SIDE = "c" * 40
OLDER = "d" * 40
FEATURE = "e" * 40
BOOT = "11111111-2222-3333-4444-555555555555"
FINGERPRINT = "SHA256:tower-key"
ID_PATTERN = re.compile(r"[0-9]{8}-[0-9]{6}-[0-9a-f]{6}")


def inner(command: str) -> str:
    """The script a locked command runs: the argument after the first ``sh -c``."""
    tokens = shlex.split(command)
    return tokens[tokens.index("-c") + 1]


class FakeServer:
    """Answers the commands the updates service sends, from state the test controls."""

    def __init__(self) -> None:
        self.commands: list[str] = []
        self.files: dict[str, tuple[str, int]] = {}
        self.labels = {
            "com.docker.compose.project": "slipway",
            "com.docker.compose.service": "slipway",
            "com.docker.compose.project.working_dir": DIR,
        }
        self.container = CONTAINER
        self.install_ok = True
        self.symbolic_ref = "main"
        self.head = FROM
        self.dirty = ""
        self.origin = "https://github.com/encondata/slipway.git"
        self.lock_held = False
        self.fetch_fails = ""
        self.fetch_gate: asyncio.Event | None = None
        # name -> (sha, date, author, subject)
        self.branches: dict[str, tuple[str, str, str, str]] = {
            "main": (NEW, "2026-11-16T10:00:00+00:00", "Jimmy", "Add the updates page"),
            "sideways": (SIDE, "2026-11-15T10:00:00+00:00", "Jimmy", "Something else"),
            "x/<img src=x onerror=alert(1)>": (FEATURE, "2026-11-14T10:00:00+00:00", "Eve", "</script><script>"),
        }
        self.descends = {NEW: True, SIDE: False, FROM: True, FEATURE: True}
        self.privileged = {NEW: ["Dockerfile"], FEATURE: []}
        self.log_commits = [
            (NEW, "2026-11-16T10:00:00+00:00", "Jimmy", "Add the updates page"),
            ("f" * 40, "2026-11-15T09:00:00+00:00", "Jimmy", "Fix\x1fa bug"),
        ]
        self.migrations = ["alembic/versions/0012_add_things.py"]
        self.in_history = True
        self.boot_id = BOOT
        self.alive = True
        self.status: dict[str, str] = {}  # run id -> raw json
        self.logs: dict[str, str] = {}
        self.launches: list[str] = []
        self.on_launch = None
        self.write_status_on_launch = True
        self.launch_pid = 4242
        self.listing: list[str] | None = None

    # The service's commands, recognised by a part of their text.
    async def run(self, command, *, check=True, on_line=None, timeout=None):
        self.commands.append(command)
        assert timeout is not None, "every remote command has a timeout"
        sep = (re.findall(r"::slipway-[0-9a-f]{16}::", command) or [""])[0]
        status, out = await self._answer(command, sep)
        if check and status != 0:
            raise ssh.CommandFailed(command, status, out)
        return status, out

    async def _answer(self, command: str, sep: str) -> tuple[int, str]:
        if command.startswith("docker inspect"):
            if self.container is None:
                return 1, "Error: No such object: " + CID
            return 0, self.container + "\n" + json.dumps(self.labels)
        if command.startswith("test -f"):
            return (0, "") if self.install_ok else (1, "")
        if "git symbolic-ref" in command:
            return 0, self.symbolic_ref
        if "flock -n" in command:
            return await self._read_checkout(command, sep)
        if "git log --max-count" in command:
            return self._compare(command, sep)
        if "mkdir -p .slipway-updates" in command:
            return 0, ""
        if "setsid nohup" in command:
            return await self._launch(command)
        if "kill -0" in command:
            run_id = re.search(r"upgrade-([0-9-a-f]+)\.sh", command).group(1)
            if self.alive:
                return 0, "alive"
            return 0, f"dead\n{sep}\n{self.status.get(run_id, '')}"
        if "ls -1t" in command:
            ids = self.listing if self.listing is not None else sorted(self.status, reverse=True)
            return 0, "\n".join(f"{i}.json" for i in ids)
        if "tail -n 20" in command:
            run_id = ID_PATTERN.search(command).group(0)
            return 0, self.logs.get(run_id, "")
        if ".json ]; then head -c" in command:
            run_id = ID_PATTERN.search(command).group(0)
            out = f"{self.status.get(run_id, '')}\n{sep}\n{self.boot_id}\n"
            if "tail -c" in command:
                out += f"{sep}\n{self.logs.get(run_id, '')}"
            return 0, out
        raise AssertionError(f"unexpected command: {command}")

    async def _read_checkout(self, command: str, sep: str) -> tuple[int, str]:
        if self.lock_held:
            return 1, ""
        if self.fetch_gate is not None:
            await self.fetch_gate.wait()
        if self.fetch_fails:
            return 4, self.fetch_fails
        fmt = lambda name, b: "\x1f".join([b[0], "refs/remotes/origin/" + name, b[1], b[2], b[3]])  # noqa: E731
        script = inner(command)
        line = next(x for x in script.splitlines() if x.startswith("git for-each-ref") and "--count" not in x)
        wanted = shlex.split(line)[-1][len("refs/remotes/origin/"):]
        followed = [fmt(n, b) for n, b in self.branches.items() if n == wanted]
        parts = ["", self.head, self.dirty, self.origin, "\n".join(followed)]
        if "--count=" in script:
            parts.append("\n".join([fmt("HEAD", (NEW, "", "", "")), *(fmt(n, b) for n, b in self.branches.items())]))
        return 0, f"\n{sep}\n".join(parts)

    def _compare(self, command: str, sep: str) -> tuple[int, str]:
        if not self.in_history:
            return 0, f"fatal: bad revision\nrc=128\n{sep}\n\n{sep}\n\n{sep}\n"
        log = "\n".join("\x1f".join([c[0], c[0][:7], c[1], c[2], c[3]]) for c in self.log_commits) + "\nrc=0"
        shas = re.search(r"for s in ([0-9a-f ]+); do", command).group(1).split()
        ancestry = []
        for s in shas:
            if self.descends.get(s):
                ancestry.append(f"{s} yes")
                ancestry += [f"{s} f {p}" for p in self.privileged.get(s, [])]
            else:
                ancestry.append(f"{s} no")
        return 0, f"\n{sep}\n".join([log, str(len(self.log_commits)), "\n".join(self.migrations), "\n".join(ancestry)])

    async def _launch(self, command: str) -> tuple[int, str]:
        self.launches.append(command)
        run_id = ID_PATTERN.search(command).group(0)
        if self.on_launch is not None:
            await self.on_launch(run_id)
        if self.write_status_on_launch:
            self.status[run_id] = status_json(run_id)
            self.logs[run_id] = "==> preflight: Checks the tools\n"
        return 0, f"started {self.launch_pid}"

    async def write_text(self, remote, content, mode=0o600):
        self.files[remote] = (content, mode)


def status_json(run_id: str, **kw) -> str:
    data = {"id": run_id, "status": "running", "step": "preflight", "from": FROM, "to": NEW, "branch": "main",
            "started_at": "2026-11-17T10:00:00Z", "finished_at": None, "message": None, "backup": None,
            "db_changed": False, "pid": 4242, "boot_id": BOOT, "heartbeat_at": "2026-11-17T10:00:01Z"}
    data.update(kw)
    return json.dumps(data)


@pytest.fixture
def server(monkeypatch):
    fake = FakeServer()
    targets: list[ssh.SSHTarget] = []

    @asynccontextmanager
    async def factory(target):
        targets.append(target)
        yield fake

    monkeypatch.setattr(updates, "connect", factory)
    monkeypatch.setattr(updates, "in_docker", lambda: True)
    monkeypatch.setattr(updates, "container_id", lambda: CID)
    monkeypatch.setattr(updates, "script_text", lambda: "#!/usr/bin/env bash\necho stand-in\n")
    monkeypatch.setattr(updates, "LAUNCH_WAIT", 0.2)
    monkeypatch.setattr(updates, "LAUNCH_POLL", 0.01)
    monkeypatch.setenv("SLIPWAY_COMMIT", FROM)
    monkeypatch.setenv("SLIPWAY_BRANCH", "main")
    monkeypatch.setenv("SLIPWAY_BUILT_AT", "2026-11-01T08:00:00Z")
    fake.targets = targets
    return fake


async def _host(name: str = "tower", **kw) -> Host:
    async with get_sessionmaker()() as db:
        host = Host(name=name, hostname=kw.pop("hostname", "10.0.0.2"), port=22, username="root", metrics={},
                    auth_method="password", password="pw", host_key=kw.pop("host_key", "ssh-ed25519 AAAA"),
                    host_key_fingerprint=kw.pop("fingerprint", FINGERPRINT), **kw)
        db.add(host)
        await db.commit()
        return host


async def _configured(client, server) -> Host:
    host = await _host()
    resp = await client.put("/api/v1/updates/config", json={"host_id": str(host.id)})
    assert resp.status_code == 200, resp.text
    return host


async def _checked(client, server) -> dict:
    await _configured(client, server)
    resp = await client.post("/api/v1/updates/check")
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _state() -> dict:
    async with get_sessionmaker()() as db:
        row = await db.scalar(select(AppSetting).where(AppSetting.key == "updates"))
        return row.value if row else {}


async def _events(action: str) -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        return list((await db.scalars(select(AuditEvent).where(AuditEvent.action == action))).all())


async def _store_run(run_id: str, host: Host, **kw) -> None:
    async with get_sessionmaker()() as db:
        row = await db.scalar(select(AppSetting).where(AppSetting.key == "updates"))
        value = dict(row.value)
        run = {"id": run_id, "host_id": str(host.id), "host_name": host.name, "hostname": host.hostname, "port": host.port,
               "username": host.username, "host_fingerprint": host.host_key_fingerprint, "dir": DIR, "branch": "main",
               "from": FROM, "to": NEW, "by": None, "by_name": "admin", "started_at": "2026-11-17T10:00:00Z",
               "status": "running", "finished_at": None}
        run.update(kw)
        value["runs"] = [run, *value.get("runs", [])]
        row.value = value
        await db.commit()


# ------------------------------------------------------------------------ permissions


async def test_routes_need_updates_run(client, server):
    await make_user("admin@example.com")
    await make_user("maint@example.com", roles=["maintainer"])
    await login(client, "maint@example.com")
    for method, url, body in [
        ("GET", "/api/v1/updates", None), ("PUT", "/api/v1/updates/config", {"host_id": str(uuid.uuid4())}),
        ("POST", "/api/v1/updates/check", None), ("POST", "/api/v1/updates/runs", {"branch": "main", "sha": NEW}),
        ("GET", "/api/v1/updates/runs", None), ("GET", "/api/v1/updates/runs/20261117-100000-abcdef", None),
    ]:
        resp = await client.request(method, url, json=body)
        assert resp.status_code == 403, (url, resp.text)
        assert "updates:run" in resp.json()["detail"]
    assert server.commands == []


async def test_only_admin_holds_updates_run():
    from slipway.core.permissions import PERMISSION_DESCRIPTIONS, SYSTEM_ROLES, Perm
    assert Perm.UPDATES_RUN == "updates:run"
    assert "root on Slipway itself" in PERMISSION_DESCRIPTIONS[Perm.UPDATES_RUN]
    for name, role in SYSTEM_ROLES.items():
        assert (Perm.UPDATES_RUN in role["permissions"] or "*" in role["permissions"]) == (name == "admin")


async def test_writes_need_the_csrf_header(admin_client, server):
    host = await _host()
    token = admin_client.headers.pop("X-CSRF-Token")
    for method, url, body in [("PUT", "/api/v1/updates/config", {"host_id": str(host.id)}),
                              ("POST", "/api/v1/updates/runs", {"branch": "main", "sha": NEW}),
                              ("POST", "/api/v1/updates/check", None)]:
        resp = await admin_client.request(method, url, json=body)
        assert resp.status_code == 403 and "CSRF" in resp.json()["detail"], url
    admin_client.headers["X-CSRF-Token"] = token
    assert server.commands == []


async def test_api_tokens_cannot_configure_or_start(admin_client, make_client, server):
    host = await _configured(admin_client, server)
    raw = (await admin_client.post("/api/v1/tokens", json={"name": "ci"})).json()["token"]
    bot = make_client()
    bot.headers["Authorization"] = f"Bearer {raw}"
    assert (await bot.get("/api/v1/updates")).status_code == 200
    assert (await bot.post("/api/v1/updates/check")).status_code == 200
    resp = await bot.put("/api/v1/updates/config", json={"host_id": str(host.id)})
    assert resp.status_code == 403 and resp.json()["detail"] == "Upgrades can only be started from the web UI"
    before = len(server.commands)
    resp = await bot.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})
    assert resp.status_code == 403 and resp.json()["detail"] == "Upgrades can only be started from the web UI"
    assert len(server.commands) == before and server.launches == []
    refused = await _events("updates.refused")
    assert refused and refused[-1].details["reason"] == "Upgrades can only be started from the web UI"


# ------------------------------------------------------------------------ overview


async def test_overview_running_version_and_reasons(admin_client, server, monkeypatch):
    body = (await admin_client.get("/api/v1/updates")).json()
    assert body["running"]["commit"] == FROM and body["running"]["branch"] == "main"
    assert body["running"]["built_at"].startswith("2026-11-01T08:00:00")
    assert body["config"] is None and body["can_upgrade"] is False
    assert body["reason"] == "Choose the host Slipway runs on first"
    assert body["steps"] == ["preflight", "fetch", "build", "backup", "switch", "health", "rollback", "cleanup"]

    monkeypatch.setattr(updates, "in_docker", lambda: False)
    body = (await admin_client.get("/api/v1/updates")).json()
    assert body["in_docker"] is False and body["reason"].startswith("Slipway isn't running in Docker")
    monkeypatch.setattr(updates, "in_docker", lambda: True)

    await _configured(admin_client, server)
    body = (await admin_client.get("/api/v1/updates")).json()
    assert body["config"]["dir"] == DIR and body["config"]["branch"] == "main"
    assert "admin" in body["config"]["exposed_roles"] and "maintainer" in body["config"]["exposed_roles"]
    assert "viewer" not in body["config"]["exposed_roles"]
    assert body["reason"] == "Check for updates first"

    await admin_client.post("/api/v1/updates/check")
    body = (await admin_client.get("/api/v1/updates")).json()
    assert body["can_upgrade"] is True and body["reason"] is None
    assert body["running"]["commit_url"] == f"https://github.com/encondata/slipway/commit/{FROM}"

    monkeypatch.setenv("SLIPWAY_COMMIT", NEW)  # upgraded since the check
    assert (await admin_client.get("/api/v1/updates")).json()["reason"].startswith("Slipway's version changed")
    monkeypatch.setenv("SLIPWAY_COMMIT", FROM)


async def test_overview_up_to_date_dirty_and_deploying(admin_client, server):
    server.branches["main"] = (FROM, "2026-11-16T10:00:00+00:00", "Jimmy", "Current")
    server.log_commits = []
    await _checked(admin_client, server)
    assert (await admin_client.get("/api/v1/updates")).json()["reason"] == "Slipway is up to date"

    server.branches["main"] = (NEW, "2026-11-16T10:00:00+00:00", "Jimmy", "New")
    server.dirty = " M docker-compose.yml"
    check = (await admin_client.post("/api/v1/updates/check")).json()
    assert check["dirty"] is True and check["dirty_files"] == [" M docker-compose.yml"]
    assert (await admin_client.get("/api/v1/updates")).json()["reason"] == "Local changes in the install folder"

    server.dirty = ""
    await admin_client.post("/api/v1/updates/check")
    async with get_sessionmaker()() as db:
        host = (await db.scalars(select(Host))).first()
        repo = Repository(github_id=1, full_name="a/b", owner="a", name="b", html_url="https://github.com/a/b", detected_config={})
        inst = Instance(name="b", slug="b", branch="main", host=host, repository=repo, env={}, ports=[], volumes=[])
        db.add(inst)
        await db.flush()
        db.add(Deployment(instance_id=inst.id, branch="main", status="running", log=""))
        await db.commit()
    body = (await admin_client.get("/api/v1/updates")).json()
    assert body["reason"] == "A deployment is running. Try again when it finishes." and body["deploying"] is True
    resp = await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})
    assert resp.status_code == 409 and resp.json()["detail"] == "A deployment is running. Try again when it finishes."
    assert server.launches == []


# ------------------------------------------------------------------------ config


async def test_config_stores_the_host_and_detected_folder(admin_client, server):
    host = await _host()
    server.symbolic_ref = "--output=x"  # not a branch: ignored, main is used
    resp = await admin_client.put("/api/v1/updates/config", json={"host_id": str(host.id)})
    assert resp.status_code == 200, resp.text
    assert resp.json()["config"]["branch"] == "main"
    state = await _state()
    assert state["host_id"] == str(host.id) and state["dir"] == DIR and state["host_fingerprint"] == FINGERPRINT
    assert (state["hostname"], state["port"], state["username"]) == ("10.0.0.2", 22, "root")
    assert server.commands[0] == f"docker inspect --format '{{{{println .Id}}}}{{{{json .Config.Labels}}}}' {CID}"
    assert f"test -f {DIR}/docker-compose.yml && test -d {DIR}/.git" in server.commands
    event = (await _events("updates.configured"))[-1]
    assert event.details["host_id"] == str(host.id) and event.details["old_host_id"] is None
    assert event.details["dir"] == DIR and event.details["host_name"] == "tower"

    server.symbolic_ref = "develop"
    resp = await admin_client.put("/api/v1/updates/config", json={"host_id": str(host.id), "branch": "release/2"})
    assert resp.json()["config"]["branch"] == "release/2"


@pytest.mark.parametrize("branch", ["-x", "a..b", "/abs", "trail/", "x.lock", "sp ace", "$(id)"])
async def test_config_rejects_bad_branches(admin_client, server, branch):
    host = await _host()
    resp = await admin_client.put("/api/v1/updates/config", json={"host_id": str(host.id), "branch": branch})
    assert resp.status_code == 422
    assert resp.json()["detail"][0]["loc"][-1] == "branch"
    assert server.commands == []


async def test_config_refusals(admin_client, server, monkeypatch):
    host = await _host()
    put = lambda: admin_client.put("/api/v1/updates/config", json={"host_id": str(host.id)})  # noqa: E731

    unpinned = await _host("other", host_key=None, fingerprint=None)
    resp = await admin_client.put("/api/v1/updates/config", json={"host_id": str(unpinned.id)})
    assert resp.status_code == 409 and resp.json()["field"] == "host_id" and "pins its SSH key" in resp.json()["detail"]

    server.container = None
    resp = await put()
    assert resp.status_code == 409 and resp.json()["detail"] == f"tower doesn't run this Slipway: no container {CID} there"
    server.container = "f" * 64  # another container's id
    assert (await put()).status_code == 409
    server.container = CONTAINER

    server.labels["com.docker.compose.project"] = "other"
    assert (await put()).status_code == 409
    server.labels["com.docker.compose.project"] = "slipway"
    for bad in ["relative/dir", "/mnt/user/../etc", "/mnt/x\nrm -rf /", "/" + "a" * 1100]:
        server.labels["com.docker.compose.project.working_dir"] = bad
        assert (await put()).status_code == 409, bad
    server.labels["com.docker.compose.project.working_dir"] = DIR
    server.install_ok = False
    resp = await put()
    assert resp.status_code == 409 and "isn't a Slipway install folder" in resp.json()["detail"]
    server.install_ok = True

    monkeypatch.setattr(updates, "container_id", lambda: "slipway-box")
    assert (await put()).status_code == 409
    monkeypatch.setattr(updates, "container_id", lambda: CID)
    monkeypatch.setattr(updates, "in_docker", lambda: False)
    resp = await put()
    assert resp.status_code == 409 and resp.json()["detail"].startswith("Slipway isn't running in Docker")
    assert (await _state()) == {}


async def test_changed_host_is_refused_until_saved_again(admin_client, server):
    host = await _configured(admin_client, server)
    resp = await admin_client.patch(f"/api/v1/hosts/{host.id}", json={"hostname": "10.9.9.9"})
    assert resp.status_code == 200, resp.text
    before = len(server.commands)
    for method, url, body in [("POST", "/api/v1/updates/check", None),
                              ("POST", "/api/v1/updates/runs", {"branch": "main", "sha": NEW})]:
        resp = await admin_client.request(method, url, json=body)
        assert resp.status_code == 409, resp.text
        assert resp.json()["detail"] == "tower changed since updates were set up: save it on the Updates page again"
    assert len(server.commands) == before
    assert len(await _events("updates.host_changed")) == 2
    body = (await admin_client.get("/api/v1/updates")).json()
    assert body["config"]["host_changed"] is True and body["reason"].startswith("tower changed")

    async with get_sessionmaker()() as db:  # saving it again re-pins what Slipway trusts
        h = await db.get(Host, host.id)
        await db.delete(h)
        await db.commit()
    resp = await admin_client.post("/api/v1/updates/check")
    assert resp.status_code == 409 and "changed since updates were set up" in resp.json()["detail"]


# ------------------------------------------------------------------------ check


async def test_check_parses_commits_branches_and_changes(admin_client, server):
    check = await _checked(admin_client, server)
    assert check["from"] == FROM and check["branch"] == "main"
    assert check["head"] == {"sha": NEW, "short": NEW[:7], "date": "2026-11-16T10:00:00+00:00", "author": "Jimmy",
                             "subject": "Add the updates page"}
    assert check["ahead"] == 2 and check["descends"] is True
    assert [c["sha"] for c in check["commits"]] == [NEW, "f" * 40]
    assert check["commits"][1]["subject"] == "Fixa bug"  # the subject is the last field; control characters dropped
    assert check["migrations"] == ["alembic/versions/0012_add_things.py"]
    assert check["privileged_changes"] == ["Dockerfile"]
    assert check["github"] == {"owner": "encondata", "repo": "slipway"}
    assert check["compare_url"] == f"https://github.com/encondata/slipway/compare/{FROM}...{NEW}"
    by_name = {b["name"]: b for b in check["branches"]}
    assert "HEAD" not in by_name
    assert by_name["main"]["followed"] and by_name["main"]["can_switch"]
    assert by_name["sideways"]["descends"] is False and by_name["sideways"]["can_switch"] is False
    evil = by_name["x/<img src=x onerror=alert(1)>"]
    assert evil["can_switch"] is False and evil["compare_url"] is None  # not a valid branch name
    stored = await _state()
    assert "branches" not in stored["last_check"] and len(stored["branches"]) == 3
    assert stored["last_check"]["error"] is None
    fetch = next(c for c in server.commands if "flock -n" in c)
    assert fetch.startswith("if command -v flock >/dev/null 2>&1; then flock -n /tmp/slipway-upgrade.lock sh -c ")
    script = inner(fetch)
    assert script.startswith(f"cd -- {DIR} || exit 3\n")
    assert "git fetch --quiet --prune origin '+refs/heads/*:refs/remotes/origin/*'" in script
    assert "GIT_TERMINAL_PROMPT=0" in script and "git status --porcelain --untracked-files=no" in script
    compare = next(c for c in server.commands if "git log --max-count" in c)
    assert f"--end-of-options {FROM}..{NEW}" in compare
    event = (await _events("updates.checked"))[-1]
    assert event.details == {"branch": "main", "head": NEW, "ahead": 2}


async def test_check_validates_what_the_server_sends(admin_client, server):
    server.branches = {
        "main": (NEW, "2026-11-16T10:00:00+00:00", "J" * 500, "S" * 500),
        "bad-sha": ("--output=/root/.ssh/authorized_keys", "2026", "x", "y"),
        **{f"b{i}": (FEATURE, "2026-01-01T00:00:00+00:00", "x", "y") for i in range(250)},
    }
    server.origin = "javascript:alert(1)//github.com/a/b"
    server.migrations = ["alembic/versions/0013.py", "../../etc/passwd"]
    check = await _checked(admin_client, server)
    assert len(check["head"]["author"]) == 200 and len(check["head"]["subject"]) == 200
    names = {b["name"] for b in check["branches"]}
    assert "bad-sha" not in names and len(check["branches"]) <= 200
    assert check["github"] is None and check["compare_url"] is None
    assert check["migrations"] == ["alembic/versions/0013.py"]
    assert not any("--output" in c for c in server.commands if "git log" in c)


async def test_commit_unknown_is_refused(admin_client, server, monkeypatch):
    await _configured(admin_client, server)
    monkeypatch.setenv("SLIPWAY_COMMIT", "")
    server.head = "--output=x"
    resp = await admin_client.post("/api/v1/updates/check")
    assert resp.status_code == 409 and resp.json()["detail"] == "Slipway can't tell which commit it runs"
    assert not any("git log" in c for c in server.commands)
    resp = await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})
    assert resp.status_code == 409 and resp.json()["detail"] == "Slipway can't tell which commit it runs"
    monkeypatch.setenv("SLIPWAY_COMMIT", "not-a-sha")
    server.head = FROM
    resp = await admin_client.post("/api/v1/updates/check")
    assert resp.status_code == 409 and resp.json()["detail"] == "Slipway can't tell which commit it runs"
    assert (await admin_client.get("/api/v1/updates")).json()["reason"] == "Slipway can't tell which commit it runs"

    monkeypatch.setenv("SLIPWAY_COMMIT", "")  # unstamped image: the checkout's HEAD is the running commit
    check = (await admin_client.post("/api/v1/updates/check")).json()
    assert check["from"] == FROM


async def test_check_skipped_while_an_upgrade_holds_the_lock(admin_client, server):
    await _checked(admin_client, server)
    before = (await _state())["last_check"]
    server.lock_held = True
    resp = await admin_client.post("/api/v1/updates/check")
    assert resp.status_code == 409 and resp.json()["detail"] == "An upgrade is running"
    assert (await _state())["last_check"] == before  # not stored as an error


async def test_fetch_errors_are_stored_and_redacted(admin_client, server):
    await _configured(admin_client, server)
    server.fetch_fails = "fatal: unable to access 'https://jimmy:ghp_secret@github.com/x/y.git/': 403"
    resp = await admin_client.post("/api/v1/updates/check")
    assert resp.status_code == 502 and "ghp_secret" not in resp.text and "://***@github.com" in resp.text
    error = (await _state())["last_check"]["error"]
    assert "ghp_secret" not in error and "git fetch failed" in error
    assert (await admin_client.get("/api/v1/updates")).json()["reason"] == "Check for updates first"


async def test_background_check_stores_errors(admin_client, server):
    await _checked(admin_client, server)
    server.fetch_fails = "fatal: could not read from remote"
    await updates.background_check()
    assert "could not read from remote" in (await _state())["last_check"]["error"]
    assert len(await _events("updates.checked")) == 1  # only manual checks are audited
    server.fetch_fails = ""
    await updates.background_check()
    assert (await _state())["last_check"]["error"] is None


async def test_loops_are_off_when_their_interval_is_zero():
    await asyncio.wait_for(updates.check_forever(), 1)
    await asyncio.wait_for(updates.reconcile_forever(), 1)


async def test_check_does_not_drop_a_run_recorded_meanwhile(admin_client, server):
    host = await _configured(admin_client, server)
    server.fetch_gate = asyncio.Event()
    checking = asyncio.create_task(admin_client.post("/api/v1/updates/check"))
    await asyncio.sleep(0.05)  # the check is now waiting in its fetch, having read the setting
    async with get_sessionmaker()() as db:
        async with updates.edit_state(db) as state:
            state["runs"].insert(0, {"id": "20261117-100000-abcdef", "host_id": str(host.id), "dir": DIR,
                                     "status": "succeeded", "branch": "main", "from": FROM, "to": NEW})
    server.fetch_gate.set()
    resp = await checking
    assert resp.status_code == 200, resp.text
    state = await _state()
    assert [r["id"] for r in state["runs"]] == ["20261117-100000-abcdef"]
    assert state["last_check"]["head"]["sha"] == NEW


# ------------------------------------------------------------------------ starting a run


async def test_start_run_records_first_then_launches(admin_client, server):
    host = await _checked(admin_client, server) and (await _host_row())
    seen = {}

    async def on_launch(run_id):
        state = await _state()
        seen["status"] = state["runs"][0]["status"]
        seen["started"] = len(await _events("updates.started"))

    server.on_launch = on_launch
    resp = await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})
    assert resp.status_code == 202, resp.text
    run_id = resp.json()["id"]
    assert ID_PATTERN.fullmatch(run_id)
    assert seen == {"status": "running", "started": 1}

    script, mode = server.files[f"{DIR}/.slipway-updates/upgrade-{run_id}.sh"]
    assert script.startswith("#!/usr/bin/env bash") and mode == 0o700
    assert server.launches == [
        f"cd -- {DIR} && umask 077 && if command -v setsid >/dev/null 2>&1; then "
        f"(setsid nohup bash .slipway-updates/upgrade-{run_id}.sh --id {run_id} --target {NEW} --branch main --from {FROM} "
        f"> .slipway-updates/{run_id}.log 2>&1 < /dev/null & echo \"started $!\"); else "
        f"(nohup bash .slipway-updates/upgrade-{run_id}.sh --id {run_id} --target {NEW} --branch main --from {FROM} "
        f"> .slipway-updates/{run_id}.log 2>&1 < /dev/null & echo \"started $!\"); fi"
    ]
    mkdir = next(c for c in server.commands if "mkdir -p" in c)
    assert mkdir == f"cd -- {DIR} && umask 077 && mkdir -p .slipway-updates && chmod 700 .slipway-updates"
    fetch = next(inner(c) for c in server.commands if "flock -n" in c and "refs/heads/main:" in c)
    assert "git fetch --quiet origin +refs/heads/main:refs/remotes/origin/main </dev/null" in fetch

    run = (await _state())["runs"][0]
    assert run["status"] == "running" and run["host_id"] == str(host.id) and run["from"] == FROM and run["to"] == NEW
    started = (await _events("updates.started"))[-1]
    assert started.details == {"run_id": run_id, "host_id": str(host.id), "host_name": "tower", "dir": DIR,
                               "branch": "main", "from": FROM, "to": NEW, "migrations": 1,
                               "privileged_changes": ["Dockerfile"]}
    body = (await admin_client.get("/api/v1/updates")).json()
    assert body["run"]["id"] == run_id and body["reason"] == "Another upgrade is running"

    resp = await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})
    assert resp.status_code == 409 and resp.json()["detail"] == "Another upgrade is running"
    assert len(server.launches) == 1


async def _host_row() -> Host:
    async with get_sessionmaker()() as db:
        return (await db.scalars(select(Host))).first()


async def test_unstamped_image_starts_without_from(admin_client, server, monkeypatch):
    await _checked(admin_client, server)
    monkeypatch.setenv("SLIPWAY_COMMIT", "")
    resp = await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})
    assert resp.status_code == 202, resp.text
    assert "--from" not in server.launches[0]


async def test_branch_names_are_quoted_in_the_launch(admin_client, server):
    await _checked(admin_client, server)
    server.branches["feat/x"] = (FEATURE, "2026-11-14T10:00:00+00:00", "Eve", "Feature")
    resp = await admin_client.post("/api/v1/updates/runs", json={"branch": "feat/x", "sha": FEATURE})
    assert resp.status_code == 202, resp.text
    assert "--branch feat/x" in server.launches[0]


@pytest.mark.parametrize("body", [
    {"branch": "main", "sha": NEW[:12]}, {"branch": "main", "sha": "B" * 40}, {"branch": "main", "sha": "-" * 40},
    {"branch": "a..b", "sha": NEW}, {"branch": "-x", "sha": NEW},
])
async def test_start_run_validates_its_input(admin_client, server, body):
    await _configured(admin_client, server)
    before = len(server.commands)
    resp = await admin_client.post("/api/v1/updates/runs", json=body)
    assert resp.status_code == 422
    assert len(server.commands) == before


async def test_start_run_refusals_are_audited(admin_client, server):
    await _checked(admin_client, server)
    cases = [
        ({"branch": "main", "sha": SIDE}, "main has moved on: check again"),
        ({"branch": "sideways", "sha": SIDE}, "doesn't come after the running version"),
        ({"branch": "nope", "sha": NEW}, "nope has moved on: check again"),
    ]
    for body, detail in cases:
        resp = await admin_client.post("/api/v1/updates/runs", json=body)
        assert resp.status_code == 409 and detail in resp.json()["detail"], resp.text
    server.dirty = " M docker-compose.yml"
    resp = await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})
    assert resp.status_code == 409 and resp.json()["detail"] == "Local changes in the install folder"
    server.dirty = ""
    server.lock_held = True
    resp = await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})
    assert resp.status_code == 409 and resp.json()["detail"] == "Another upgrade is running"
    assert server.launches == []
    refused = await _events("updates.refused")
    assert len(refused) == 5
    assert refused[0].details["branch"] == "main" and refused[0].details["sha"] == SIDE
    assert (await _state())["runs"] == []


async def test_a_second_click_is_refused_at_once(admin_client, server):
    await _checked(admin_client, server)
    gate = asyncio.Event()

    async def slow_launch(run_id):
        await gate.wait()

    server.on_launch = slow_launch
    first = asyncio.create_task(admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW}))
    await asyncio.sleep(0.05)
    second = await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})
    assert second.status_code == 409 and second.json()["detail"] == "Another upgrade is running"
    gate.set()
    assert (await first).status_code == 202
    assert len(server.launches) == 1


async def test_a_launch_that_never_starts_is_marked_failed(admin_client, server):
    await _checked(admin_client, server)
    server.write_status_on_launch = False
    server.alive = False  # bash couldn't run the script: its process is gone and it wrote no status

    async def log_only(run_id):
        server.logs[run_id] = "bash: .slipway-updates/upgrade.sh: Permission denied\n"

    server.on_launch = log_only
    resp = await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})
    assert resp.status_code == 502 and "didn't start" in resp.json()["detail"]
    run = (await _state())["runs"][0]
    assert run["status"] == "failed" and "Permission denied" in run["launch_log"]
    finished = await _events("updates.finished")
    assert len(finished) == 1 and finished[0].details["status"] == "failed"
    assert (await admin_client.get("/api/v1/updates")).json()["reason"] is None  # free to try again


# ------------------------------------------------------------------------ reading runs


async def test_reading_a_run_audits_its_end_once(admin_client, server):
    await _checked(admin_client, server)
    run_id = (await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})).json()["id"]
    server.logs[run_id] = (
        "\x1b[1m==> fetch\x1b[0m: Fetches main\n"
        "fatal: unable to access 'https://jimmy:ghp_secret@github.com/x/y.git/'\n"
    )
    run = (await admin_client.get(f"/api/v1/updates/runs/{run_id}")).json()
    assert run["status"] == "running" and run["final"] is False and run["step"] == "preflight"
    assert "ghp_secret" not in run["log"] and "https://***@github.com" in run["log"] and "\x1b" not in run["log"]
    assert run["log"].startswith("==> fetch: Fetches main")

    server.status[run_id] = status_json(run_id, status="rolled_back", step="rollback", db_changed=True,
                                        backup=f".slipway-updates/{run_id}-before.dump",
                                        finished_at="2026-11-17T10:09:00Z", message="The new version didn't pass its health check.")
    reads = await asyncio.gather(*(admin_client.get(f"/api/v1/updates/runs/{run_id}") for _ in range(3)))
    assert all(r.status_code == 200 and r.json()["status"] == "rolled_back" for r in reads)
    await admin_client.get(f"/api/v1/updates/runs/{run_id}")
    finished = await _events("updates.finished")
    assert len(finished) == 1
    assert finished[0].actor_id is None
    assert finished[0].details["status"] == "rolled_back" and finished[0].details["db_changed"] is True
    assert finished[0].details["by"] is not None and finished[0].details["backup"].endswith("-before.dump")
    stored = (await _state())["runs"][0]
    assert stored["status"] == "rolled_back" and stored["finished_at"].startswith("2026-11-17T10:09")


async def test_the_overview_reconciles_a_running_run(admin_client, server):
    await _checked(admin_client, server)
    run_id = (await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})).json()["id"]
    server.status[run_id] = status_json(run_id, status="succeeded", step="cleanup", finished_at="2026-11-17T10:05:00Z")
    body = (await admin_client.get("/api/v1/updates")).json()
    assert body["run"]["status"] == "succeeded"
    assert len(await _events("updates.finished")) == 1
    before = len(server.commands)
    async with get_sessionmaker()() as db:
        await updates.reconcile_runs(db)  # nothing left running: no SSH, no second audit
    assert len(server.commands) == before
    assert len(await _events("updates.finished")) == 1


@pytest.mark.parametrize("change", ["dead", "rebooted"])
async def test_a_killed_run_becomes_interrupted(admin_client, server, change):
    await _checked(admin_client, server)
    run_id = (await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})).json()["id"]
    if change == "dead":
        server.alive = False
    else:
        server.boot_id = "99999999-2222-3333-4444-555555555555"
    run = (await admin_client.get(f"/api/v1/updates/runs/{run_id}")).json()
    assert run["status"] == "interrupted" and run["final"] is True
    assert run["message"].startswith("The upgrade stopped before it finished")
    finished = await _events("updates.finished")
    assert len(finished) == 1 and finished[0].details["status"] == "interrupted"
    body = (await admin_client.get("/api/v1/updates")).json()
    assert body["run"]["status"] == "interrupted" and body["reason"] is None


async def test_a_run_that_finished_between_reads_is_not_interrupted(admin_client, server):
    await _checked(admin_client, server)
    run_id = (await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})).json()["id"]
    server.alive = False
    original = server._answer

    async def finishing(command, sep):
        if "kill -0" in command:
            server.status[run_id] = status_json(run_id, status="succeeded", step="cleanup", finished_at="2026-11-17T10:05:00Z")
        return await original(command, sep)

    server._answer = finishing
    run = (await admin_client.get(f"/api/v1/updates/runs/{run_id}")).json()
    assert run["status"] == "succeeded"


async def test_a_run_missing_from_the_setting_is_read_from_the_server(admin_client, server):
    await _checked(admin_client, server)
    run_id = "20261116-080000-0a0b0c"  # e.g. lost when a backup from before it was restored by hand
    server.status[run_id] = status_json(run_id, status="succeeded", step="cleanup", finished_at="2026-11-16T08:05:00Z")
    server.logs[run_id] = "==> cleanup\n"
    run = (await admin_client.get(f"/api/v1/updates/runs/{run_id}")).json()
    assert run["status"] == "succeeded" and run["run"]["id"] == run_id and run["log"].strip() == "==> cleanup"
    assert [r["id"] for r in (await _state())["runs"]] == [run_id]
    await admin_client.get(f"/api/v1/updates/runs/{run_id}")
    assert len(await _events("updates.finished")) == 1

    other = "20261115-080000-0d0e0f"
    server.status[other] = status_json(other, status="failed", step="build", finished_at="2026-11-15T08:05:00Z")
    runs = (await admin_client.get("/api/v1/updates/runs")).json()
    assert [r["id"] for r in runs] == [run_id, other]
    assert len(await _events("updates.finished")) == 2

    resp = await admin_client.get("/api/v1/updates/runs/20261114-080000-ffffff")  # no file either
    assert resp.status_code == 404


async def test_bad_run_ids_never_reach_the_server(admin_client, server):
    await _checked(admin_client, server)
    before = len(server.commands)
    for bad in ["..%2F..%2Fetc%2Fshadow", "20261117-100000-ABCDEF", "20261117-100000-abcdef%3Bid", "x", "%2E%2E",
                "20261117-100000-abcdef.json"]:
        resp = await admin_client.get(f"/api/v1/updates/runs/{bad}")
        assert resp.status_code == 404, bad
    assert len(server.commands) == before


async def test_runs_are_read_from_their_own_host_and_folder(admin_client, server):
    host = await _checked(admin_client, server) and (await _host_row())
    other = await _host("old-box", hostname="10.0.0.9")
    run_id = "20261110-080000-0a0b0c"
    async with get_sessionmaker()() as db:
        async with updates.edit_state(db) as state:
            state["runs"].append({"id": run_id, "host_id": str(other.id), "host_name": "old-box", "hostname": "10.0.0.9",
                                  "port": 22, "username": "root", "host_fingerprint": FINGERPRINT, "dir": "/srv/slipway",
                                  "status": "succeeded", "branch": "main", "from": FROM, "to": NEW})
    server.status[run_id] = status_json(run_id, status="succeeded", step="cleanup", finished_at="2026-11-10T08:05:00Z")
    await admin_client.get(f"/api/v1/updates/runs/{run_id}")
    assert server.targets[-1].hostname == "10.0.0.9"
    assert "cd -- /srv/slipway" in server.commands[-1]
    assert host is not None


def test_parse_status_rejects_anything_off():
    rid = "20261117-100000-abcdef"
    good = updates.parse_status(status_json(rid), rid)
    assert good["status"] == "running" and good["valid"] and good["pid"] == 4242
    bad = [
        "", "not json", "[]", status_json("20261117-100000-000000"), status_json(rid, status="pwned"),
        status_json(rid, step="exfiltrate"), status_json(rid, to="--output=x"), status_json(rid, **{"from": "abc"}),
        status_json(rid, backup="/etc/shadow"), status_json(rid, db_changed="yes"), status_json(rid, pid="1; id"),
        status_json(rid, branch="a..b"), status_json(rid, started_at="yesterday"), status_json(rid, pid=True),
        "{" + " " * (70 * 1024) + "}",
    ]
    for raw in bad:
        parsed = updates.parse_status(raw, rid)
        assert parsed["status"] == "unknown" and not parsed["valid"], raw[:80]
    long = updates.parse_status(status_json(rid, message="x\x00" * 400), rid)
    assert len(long["message"]) == 400 and "\x00" not in long["message"]
    assert updates.parse_status(status_json(rid, **{"from": None}), rid)["valid"]


def test_validators_and_links():
    assert updates.valid_branch("main") and updates.valid_branch("release/2.0") and updates.valid_branch("feat_x-1")
    for bad in ["", "-x", "/a", "a/", "a..b", "x.lock", "a/.hidden", "a//b", "a b", "$(id)", "a" * 101, "a;b"]:
        assert not updates.valid_branch(bad), bad
    assert updates.valid_sha(NEW) and not updates.valid_sha(NEW.upper()) and not updates.valid_sha(NEW[:39])
    assert updates.valid_id(updates.new_run_id())
    assert updates.parse_github("git@github.com:encondata/slipway.git") == {"owner": "encondata", "repo": "slipway"}
    assert updates.parse_github("https://u:t@github.com/encondata/slipway") == {"owner": "encondata", "repo": "slipway"}
    for bad in ["javascript:alert(1)", "https://github.com.evil/a/b", "https://gitlab.com/a/b", "https://github.com/a b/c"]:
        assert updates.parse_github(bad) is None, bad
    assert updates.commit_url({"owner": "a", "repo": "b"}, NEW) == f"https://github.com/a/b/commit/{NEW}"
    assert updates.commit_url({"owner": "a\"><x", "repo": "b"}, NEW) is None
    assert updates.commit_url({"owner": "a", "repo": "b"}, "javascript:x") is None
    assert updates.redact("https://user:tok@github.com/x \x1b[31mred\x1b[0m") == "https://***@github.com/x red"


async def test_a_moved_install_folder_is_refused(admin_client, server):
    await _checked(admin_client, server)
    server.labels["com.docker.compose.project.working_dir"] = "/mnt/user/slipway2"
    resp = await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})
    assert resp.status_code == 409
    assert resp.json()["detail"] == "Slipway now runs from /mnt/user/slipway2 on tower: save it on the Updates page again"
    assert server.launches == []


# ------------------------------------------------------------------------ starts Slipway can't confirm


async def test_a_slow_start_stays_running_and_is_read_later(admin_client, server):
    await _checked(admin_client, server)
    server.write_status_on_launch = False  # e.g. a disk spinning up: the script hasn't written its status yet
    resp = await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})
    assert resp.status_code == 202, resp.text
    run_id = resp.json()["id"]
    stored = (await _state())["runs"][0]
    assert stored["status"] == "running" and stored["launch_pid"] == 4242
    assert stored["message"] == updates.MSG_LAUNCH_PENDING
    body = (await admin_client.get("/api/v1/updates")).json()
    assert body["can_upgrade"] is False and body["reason"] == "Another upgrade is running"
    run = (await admin_client.get(f"/api/v1/updates/runs/{run_id}")).json()
    assert run["status"] == "running" and run["final"] is False and run["message"] == updates.MSG_LAUNCH_PENDING

    server.status[run_id] = status_json(run_id, status="running", step="build")
    run = (await admin_client.get(f"/api/v1/updates/runs/{run_id}")).json()
    assert run["status"] == "running" and run["step"] == "build"
    assert "launch_pid" not in (await _state())["runs"][0]
    server.status[run_id] = status_json(run_id, status="succeeded", step="cleanup", finished_at="2026-11-17T10:05:00Z")
    run = (await admin_client.get(f"/api/v1/updates/runs/{run_id}")).json()
    assert run["status"] == "succeeded"
    assert [e.details["status"] for e in await _events("updates.finished")] == ["succeeded"]


async def test_a_lost_connection_after_the_launch_is_read_later(admin_client, server):
    await _checked(admin_client, server)
    original = server._launch

    async def drop(command):
        await original(command)  # the script started and wrote its status
        raise ssh.SSHError("SSH command failed: Connection lost")

    server._launch = drop
    resp = await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})
    assert resp.status_code == 202, resp.text
    run_id = resp.json()["id"]
    run = (await admin_client.get(f"/api/v1/updates/runs/{run_id}")).json()
    assert run["status"] == "running" and run["final"] is False
    assert await _events("updates.finished") == []


async def test_a_start_that_never_writes_its_status_fails_after_the_grace_period(admin_client, server):
    await _checked(admin_client, server)
    server.write_status_on_launch = False
    run_id = (await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})).json()["id"]
    async with get_sessionmaker()() as db:
        async with updates.edit_state(db) as state:
            state["runs"][0]["launch_deadline"] = "2026-01-01T00:00:00Z"
    run = (await admin_client.get(f"/api/v1/updates/runs/{run_id}")).json()
    assert run["status"] == "failed" and run["final"] is True
    assert "didn't write a status file within 10 minutes" in run["message"]
    assert [e.details["status"] for e in await _events("updates.finished")] == ["failed"]


async def test_a_start_whose_process_ends_without_a_status_is_failed_at_once(admin_client, server):
    await _checked(admin_client, server)
    server.write_status_on_launch = False
    run_id = (await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})).json()["id"]
    server.alive = False  # gone later, still without a status file
    run = (await admin_client.get(f"/api/v1/updates/runs/{run_id}")).json()
    assert run["status"] == "failed" and "Its process ended without writing a status file." in run["message"]


@pytest.mark.parametrize("answer", [(3, ""), (-1, ""), (0, "something else")])
async def test_a_failed_liveness_check_leaves_the_run_running(admin_client, server, answer):
    await _checked(admin_client, server)
    run_id = (await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})).json()["id"]
    original = server._answer

    async def flaky(command, sep):
        if "kill -0" in command:
            return answer  # the check itself failed; the script is alive
        return await original(command, sep)

    server._answer = flaky
    run = (await admin_client.get(f"/api/v1/updates/runs/{run_id}")).json()
    assert run["status"] == "running" and run["final"] is False
    server._answer = original
    server.status[run_id] = status_json(run_id, status="succeeded", step="cleanup", finished_at="2026-11-17T10:05:00Z")
    assert (await admin_client.get(f"/api/v1/updates/runs/{run_id}")).json()["status"] == "succeeded"
    assert [e.details["status"] for e in await _events("updates.finished")] == ["succeeded"]


# ------------------------------------------------------------------------ while a run is being started


async def test_checks_wait_while_a_run_is_being_started(admin_client, server):
    await _checked(admin_client, server)
    gate, entered = asyncio.Event(), asyncio.Event()
    original = server.write_text

    async def slow_write(remote, content, mode=0o600):
        entered.set()
        await gate.wait()
        await original(remote, content, mode)

    server.write_text = slow_write
    start = asyncio.create_task(admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW}))
    await entered.wait()
    mark = len(server.commands)
    resp = await admin_client.post("/api/v1/updates/check")
    assert resp.status_code == 409 and resp.json()["detail"] == "An upgrade is running"
    await updates.background_check()
    assert not any("flock -n" in c for c in server.commands[mark:])  # neither took the script's lock
    gate.set()
    assert (await start).status_code == 202


async def test_a_stalled_script_write_times_out(admin_client, server, monkeypatch):
    await _checked(admin_client, server)
    monkeypatch.setattr(updates, "QUICK_TIMEOUT", 0.2)
    never = asyncio.Event()

    async def stalled(remote, content, mode=0o600):
        await never.wait()

    server.write_text = stalled
    resp = await asyncio.wait_for(admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW}), 5)
    assert resp.status_code == 502 and "timed out" in resp.json()["detail"]
    assert not updates._start_lock.locked()
    assert server.launches == [] and (await _state())["runs"] == []
    assert len(await _events("updates.start_failed")) == 1


async def test_starts_that_fail_before_the_run_is_recorded_are_audited(admin_client, server):
    await _checked(admin_client, server)
    server.fetch_fails = "fatal: unable to access 'https://jimmy:ghp_secret@github.com/x/y.git/'"
    resp = await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})
    assert resp.status_code == 502
    server.fetch_fails = ""
    original = server._answer

    async def broken(command, sep):
        if "mkdir -p" in command:
            raise ssh.SSHError("SSH command failed: Connection lost")
        return await original(command, sep)

    server._answer = broken
    resp = await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})
    assert resp.status_code == 502 and "Connection lost" in resp.json()["detail"]
    failed = await _events("updates.start_failed")
    assert len(failed) == 2 and all(e.details["sha"] == NEW for e in failed)
    assert "git fetch failed" in failed[0].details["reason"] and "ghp_secret" not in failed[0].details["reason"]
    assert failed[1].details["reason"] == "SSH command failed: Connection lost"
    assert await _events("updates.started") == [] and await _events("updates.refused") == []


# ------------------------------------------------------------------------ deployments and upgrades


async def test_deployments_are_refused_while_an_upgrade_runs(admin_client, server, monkeypatch):
    from slipway.services import deployer
    submitted: list = []
    monkeypatch.setattr(deployer.runner, "submit", lambda *a: submitted.append(a))  # never deploy for real
    await _checked(admin_client, server)
    async with get_sessionmaker()() as db:
        host = (await db.scalars(select(Host))).first()
        repo = Repository(github_id=1, full_name="a/b", owner="a", name="b", html_url="https://github.com/a/b", detected_config={})
        inst = Instance(name="b", slug="b", branch="main", host=host, repository=repo, env={}, ports=[], volumes=[])
        db.add(inst)
        await db.commit()
        inst_id = inst.id
    run_id = (await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})).json()["id"]
    resp = await admin_client.post(f"/api/v1/instances/{inst_id}/deploy")
    assert resp.status_code == 409 and resp.json()["detail"] == updates.MSG_UPGRADING
    async with get_sessionmaker()() as db:
        assert (await db.scalars(select(Deployment))).all() == []
    assert submitted == [] and run_id


# ------------------------------------------------------------------------ the running commit


async def test_unstamped_image_after_an_unfinished_run_is_refused(admin_client, server, monkeypatch):
    monkeypatch.setenv("SLIPWAY_COMMIT", "")
    server.head = NEW  # the run moved the checkout to its target, then was cut off; the old image still runs
    host = await _configured(admin_client, server)
    await _store_run("20261117-100000-abcdef", host, status="interrupted", to=NEW, finished_at="2026-11-17T10:05:00Z")
    resp = await admin_client.post("/api/v1/updates/check")
    assert resp.status_code == 409 and resp.json()["detail"] == updates.MSG_COMMIT_UNSURE
    resp = await admin_client.post("/api/v1/updates/runs", json={"branch": "main", "sha": NEW})
    assert resp.status_code == 409 and resp.json()["detail"] == updates.MSG_COMMIT_UNSURE
    assert server.launches == []


async def test_unstamped_image_after_a_clean_run_uses_the_checkout(admin_client, server, monkeypatch):
    monkeypatch.setenv("SLIPWAY_COMMIT", "")
    host = await _configured(admin_client, server)
    await _store_run("20261117-100000-abcdef", host, status="rolled_back", to=NEW, finished_at="2026-11-17T10:05:00Z")
    check = (await admin_client.post("/api/v1/updates/check")).json()
    assert check["from"] == FROM  # rolled back: HEAD is back at what runs


# ------------------------------------------------------------------------ a host saved again


async def test_saving_the_host_again_lets_a_run_on_it_finish(admin_client, server):
    host = await _configured(admin_client, server)
    run_id = "20261117-100000-abcdef"
    await _store_run(run_id, host)
    server.status[run_id] = status_json(run_id, status="succeeded", step="cleanup", finished_at="2026-11-17T10:05:00Z")
    async with get_sessionmaker()() as db:  # the host gets a new address while the run is still stored running
        h = await db.get(Host, host.id)
        h.hostname = "tower.lan"
        await db.commit()
    body = (await admin_client.get("/api/v1/updates")).json()
    assert body["run"]["status"] == "running"  # can't be read: the host changed
    resp = await admin_client.put("/api/v1/updates/config", json={"host_id": str(host.id)})
    assert resp.status_code == 200, resp.text
    body = (await admin_client.get("/api/v1/updates")).json()
    assert body["run"]["status"] == "succeeded" and body["reason"] != "Another upgrade is running"
    stored = (await _state())["runs"][0]
    assert stored["hostname"] == "tower.lan"
    assert server.targets[-1].hostname == "tower.lan"


def test_parse_status_reads_the_failed_step():
    rid = "20261117-100000-abcdef"
    assert updates.parse_status(status_json(rid, failed_step="health"), rid)["failed_step"] == "health"
    assert updates.parse_status(status_json(rid), rid)["failed_step"] is None
    assert updates.parse_status(status_json(rid, failed_step="pwned"), rid)["status"] == "unknown"
