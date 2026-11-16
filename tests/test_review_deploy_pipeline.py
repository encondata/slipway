"""Regression tests for the deploy pipeline review: placement locks, teardown, delete races,
DB connection use around SSH, releases, compose env files, the failure path and repo identity."""

from __future__ import annotations

import asyncio
import functools
import os
import sqlite3
import stat
import subprocess
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path

import pytest
from sqlalchemy import event, select, text

from slipway.api.v1 import instances as instances_api
from slipway.core import crypto
from slipway.core.permissions import PERMISSION_DESCRIPTIONS, Perm
from slipway.db.base import utcnow
from slipway.db.session import get_engine, get_sessionmaker
from slipway.models import AuditEvent, Deployment, Host, Instance, Repository
from slipway.services import deployer, ssh
from slipway.services.github import CommitInfo, GitHubError
from tests.test_deployer import SHA, FakeGitHub, FakeRemote, _connect, _instance, _seed

FAKE_DOCKER = """#!/bin/sh
echo "$@" >> "$DOCKER_LOG"
[ -n "$FAKE_WARN" ] && echo "$FAKE_WARN" >&2
case "$1" in
  container) [ "$2" = inspect ] && echo "$FAKE_OWNER" ;;
  ps)
    [ -n "$FAKE_PS_FAILS" ] && { echo "Cannot connect to the Docker daemon" >&2; exit 1; }
    [ -n "$FAKE_PS" ] && echo "$FAKE_PS" ;;
  image)
    case "$2 $*" in "ls "*com.docker.compose.project=*) [ -n "$FAKE_COMPOSE_IMAGES" ] && echo "$FAKE_COMPOSE_IMAGES" ;; esac ;;
  run)
    [ -n "$FAKE_RUN_FAILS" ] && exit 1
    prev=""; src=""
    for a in "$@"; do [ "$prev" = "-v" ] && src="${a%%:/r}"; prev="$a"; done
    target="$src/${a#/r/}"
    chmod -R u+w "$target" && rm -rf "$target" ;;
esac
exit 0
"""


@pytest.fixture
def fake_docker(tmp_path):
    """Environment for running generated commands locally with a fake ``docker`` first on PATH."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = bin_dir / "docker"
    script.write_text(FAKE_DOCKER)
    script.chmod(0o755)
    log = tmp_path / "docker.log"
    log.write_text("")
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "DOCKER_LOG": str(log), "HOME": str(tmp_path)}
    return env, log


def _sh(command: str, env: dict[str, str], input: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["/bin/sh", "-c", command], env=env, capture_output=True, text=True, input=input)


class LocalRemote:
    """Runs commands with /bin/sh on this machine (stdin from ``input``, lines scrubbed as RemoteSession does)."""

    def __init__(self, env: dict[str, str]) -> None:
        self.env = env
        self.commands: list[str] = []

    async def run(self, command, *, check=True, on_line=None, timeout=None, input=None, scrub=None):
        self.commands.append(command)
        result = await asyncio.to_thread(_sh, command, self.env, input)
        output = result.stdout + result.stderr
        if scrub is not None:
            output = "\n".join(scrub(line) for line in output.splitlines())
        if on_line is not None:
            for line in output.splitlines():
                await on_line(line)
        if check and result.returncode:
            raise ssh.CommandFailed(command, result.returncode, output)
        return result.returncode, output

    async def write_text(self, remote, content, mode=0o600):
        Path(remote).write_text(content)
        os.chmod(remote, mode)

    async def read_stream(self, path, chunk=None):
        with open(path, "rb") as fh:
            while block := fh.read(chunk or 1024 * 1024):
                yield block

    async def write_stream(self, path, chunks, mode=0o600):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "wb") as fh:
            async for block in chunks:
                fh.write(block)
        os.chmod(path, mode)
        return os.path.getsize(path)


def _local(remote):
    @asynccontextmanager
    async def factory(target):
        yield remote
    return factory


async def _add_instance(status: str = "running", *, build_source: str = "dockerfile", deployment: dict | None = None,
                        env: dict | None = None) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    """Seed an instance on a pinned host. Returns (instance id, its host id, a second host id)."""
    async with get_sessionmaker()() as db:
        host = Host(name="prod-01", hostname="10.0.0.1", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
        other = Host(name="prod-02", hostname="10.0.0.2", username="deploy", host_key="ssh-ed25519 BBBB", metrics={})
        repo = Repository(github_id=42, full_name="acme/web", owner="acme", name="web",
                          html_url="https://github.com/acme/web", detected_config={})
        inst = Instance(name="web", slug="web-prod", branch="main", host=host, repository=repo, env=env or {},
                        status=status, build_source=build_source, ports=[], volumes=[])
        db.add_all([inst, other])
        await db.flush()
        if deployment is not None:
            db.add(Deployment(instance_id=inst.id, branch="main", log="", **deployment))
        await db.commit()
        return inst.id, host.id, other.id


async def _get(model, ident):
    async with get_sessionmaker()() as db:
        return await db.get(model, ident)


@contextmanager
def _db_hook(fn):
    engine = get_engine().sync_engine
    event.listen(engine, "before_cursor_execute", fn)
    try:
        yield
    finally:
        event.remove(engine, "before_cursor_execute", fn)


@pytest.fixture
def fast_retries(monkeypatch):
    monkeypatch.setattr(deployer, "FINISH_RETRY_DELAYS", (0, 0, 0, 0, 0, 0, 0))


# --------------------------------------------- placement is fixed once deployed (68, 46, 43, 69)


@pytest.mark.parametrize("change", [
    {"host_id": "other"}, {"build_source": "compose"}, {"compose_file": "deploy/compose.yml"},
    {"dockerfile_path": "docker/Dockerfile"}, {"build_context": "src"},
])
async def test_failed_instance_cannot_change_host_or_build(admin_client, change):
    # A redeploy that failed at `docker build` leaves the previous container running.
    inst_id, host_id, other_id = await _add_instance("failed", deployment={"status": "failed", "started_at": utcnow()})
    body = {k: (str(other_id) if v == "other" else v) for k, v in change.items()}
    r = await admin_client.patch(f"/api/v1/instances/{inst_id}", json=body)
    assert r.status_code == 400 and "Delete it" in r.json()["detail"]
    inst = await _get(Instance, inst_id)
    assert inst.host_id == host_id and inst.build_source == "dockerfile"
    # Other edits, and resending the current values (as the edit form does), still work.
    r = await admin_client.patch(f"/api/v1/instances/{inst_id}", json={
        "env": {"A": "1"}, "host_id": str(host_id), "build_source": "dockerfile", "dockerfile_path": "Dockerfile"})
    assert r.status_code == 200, r.text


async def test_never_deployed_instance_can_move(admin_client):
    inst_id, _, other_id = await _add_instance("created")
    r = await admin_client.patch(f"/api/v1/instances/{inst_id}", json={"host_id": str(other_id), "build_source": "compose"})
    assert r.status_code == 200 and r.json()["host"] == "prod-02"


async def test_created_instance_with_started_deployment_is_fixed(admin_client):
    inst_id, _, other_id = await _add_instance(
        "created", deployment={"status": "cancelled", "started_at": utcnow()})
    r = await admin_client.patch(f"/api/v1/instances/{inst_id}", json={"host_id": str(other_id)})
    assert r.status_code == 400


async def test_move_refused_while_a_deployment_is_queued(admin_client):
    inst_id, _, other_id = await _add_instance("created", deployment={"status": "queued"})
    r = await admin_client.patch(f"/api/v1/instances/{inst_id}", json={"host_id": str(other_id)})
    assert r.status_code == 409



async def test_host_change_holds_off_a_deploy_until_it_is_saved(admin_client, monkeypatch):
    # A deploy queued between the PATCH's checks and its commit must run on the new host.
    inst_id, _, other_id = await _add_instance("created")
    paused, resume = asyncio.Event(), asyncio.Event()
    real = instances_api._ever_deployed

    async def slow_ever_deployed(db, instance):
        result = await real(db, instance)
        paused.set()
        await resume.wait()
        return result

    hosts: list[str] = []

    @asynccontextmanager
    async def connect(target):
        hosts.append(target.hostname)
        yield FakeRemote()

    monkeypatch.setattr(instances_api, "_ever_deployed", slow_ever_deployed)
    monkeypatch.setattr(
        deployer, "run_deployment", functools.partial(deployer.run_deployment, connect=connect, github=FakeGitHub)
    )
    patch = asyncio.create_task(admin_client.patch(f"/api/v1/instances/{inst_id}", json={"host_id": str(other_id)}))
    await asyncio.wait_for(paused.wait(), 5)
    assert (await admin_client.post(f"/api/v1/instances/{inst_id}/deploy")).status_code == 202
    await asyncio.sleep(0.3)  # long enough for a deploy that does not wait to finish
    resume.set()
    assert (await patch).status_code == 200
    await asyncio.gather(*deployer.runner._tasks)
    inst = await _get(Instance, inst_id)
    assert inst.host_id == other_id and inst.status == "running"
    assert hosts == ["10.0.0.2"]


async def test_host_change_refused_while_a_deploy_task_is_pending(admin_client, monkeypatch):
    inst_id, _, other_id = await _add_instance("created")
    gate = asyncio.Event()

    async def slow_deploy(deployment_id):
        await gate.wait()

    monkeypatch.setattr(deployer, "run_deployment", slow_deploy)
    deployer.runner.submit(uuid.uuid4(), (inst_id,))
    try:
        r = await admin_client.patch(f"/api/v1/instances/{inst_id}", json={"host_id": str(other_id)})
        assert r.status_code == 409
        # Edits that do not move the instance are not held up.
        r = await admin_client.patch(f"/api/v1/instances/{inst_id}", json={"env": {"A": "1"}})
        assert r.status_code == 200
    finally:
        gate.set()
        await asyncio.gather(*deployer.runner._tasks)
    assert (await _get(Instance, inst_id)).host_id != other_id


# ------------------------------------------- teardown covers both modes (43, 69, 58, 100, 50)


@pytest.mark.parametrize("source", ["dockerfile", "compose"])
def test_teardown_removes_both_modes(source):
    inst = _instance(build_source=source)
    cmd = deployer.teardown_command(inst)
    label = "label=slipway.instance=00000000-0000-0000-0000-000000000001"
    assert f"docker ps -aq --filter {label} | xargs -r docker rm -f -v" in cmd
    assert "docker compose -p slipway-web-prod rm -f -s -v" in cmd
    assert "docker compose -p slipway-web-prod down --remove-orphans" in cmd
    assert "--rmi local" in cmd
    assert f"docker image ls -aq --filter {label}" in cmd  # also catches dangling images
    assert "docker rm -f slipway-web-prod" not in cmd


def test_each_mode_removes_the_other_modes_leftovers():
    label = "label=slipway.instance=00000000-0000-0000-0000-000000000001"
    _, cleanup, _ = deployer.build_commands(_instance(), "/r", SHA)
    assert f"docker ps -aq --filter {label} | xargs -r docker rm -f -v" in cleanup
    assert "docker compose -p slipway-web-prod down --remove-orphans" in cleanup
    _, cleanup, up = deployer.build_commands(_instance(build_source="compose"), "/r", SHA)
    assert f"docker ps -aq --filter {label} | xargs -r docker rm -f -v" in cleanup and "up -d" in up


def test_dockerfile_mode_never_touches_another_instances_container(fake_docker):
    # A compose instance 'shop' owns slipway-shop-web-1, the container_name of a Dockerfile instance 'shop-web-1'.
    env, log = fake_docker
    env = {**env, "FAKE_OWNER": "some-other-instance-id"}
    inst = _instance(slug="shop-web-1")
    _, cleanup, _ = deployer.build_commands(inst, "/r", SHA)
    for cmd in (cleanup, deployer.teardown_command(inst)):
        assert _sh(cmd, env).returncode == 0
    stop = _sh(deployer.control_command(inst, "stop"), env)
    logs = _sh(deployer.logs_command(inst), env)
    assert stop.returncode != 0 and "belongs to this instance" in stop.stdout
    assert "belongs to this instance" in logs.stdout
    calls = log.read_text().splitlines()
    assert not any(c.startswith(("rm", "stop", "logs")) for c in calls), calls
    # The instance's own container is still controlled by name.
    assert _sh(deployer.control_command(inst, "stop"), {**env, "FAKE_OWNER": str(inst.id)}).returncode == 0
    assert log.read_text().splitlines()[-1] == "stop slipway-shop-web-1"


def test_prune_removes_dangling_and_superseded_images():
    cmd = deployer.prune_command(_instance(), "/opt/slipway/web-prod/releases/a1b2c3d4e5f6-0000abcd")
    assert "docker image prune -f --filter label=slipway.instance=00000000-0000-0000-0000-000000000001" in cmd
    assert "docker image prune -f --filter label=com.docker.compose.project=slipway-web-prod" in cmd
    assert "tail -n +4 | xargs -r docker image rm" in cmd



def test_teardown_removes_compose_images_when_current_is_missing(tmp_path, fake_docker):
    # The first compose deploy built its images, then failed at `up`, so there is no `current`.
    env, log = fake_docker
    root = tmp_path / "root"
    (root / "web-prod" / "releases").mkdir(parents=True)
    inst = _instance(build_source="compose",
                     host=Host(name="h", hostname="10.0.0.1", port=22, username="deploy", deploy_root=str(root)))
    result = _sh(deployer.teardown_command(inst), {**env, "FAKE_COMPOSE_IMAGES": "0123456789ab"})
    assert result.returncode == 0
    assert "image rm -f 0123456789ab" in log.read_text().splitlines()


# ------------------------------------------------------ delete vs. deploy (42, 62, 82)


async def test_delete_refused_while_deploying(admin_client, monkeypatch):
    called = []

    async def fake_destroy(instance, **kw):
        called.append(instance.id)

    monkeypatch.setattr(deployer, "destroy", fake_destroy)
    inst_id, _, _ = await _add_instance("deploying", deployment={"status": "running", "started_at": utcnow()})
    for purge in ("true", "false"):
        r = await admin_client.delete(f"/api/v1/instances/{inst_id}?purge={purge}")
        assert r.status_code == 409
    assert called == [] and await _get(Instance, inst_id) is not None


async def test_delete_refused_while_runner_holds_the_instance(admin_client, monkeypatch):
    inst_id, _, _ = await _add_instance("running", deployment={"status": "succeeded", "started_at": utcnow()})
    gate = asyncio.Event()

    async def slow_deploy(deployment_id):
        await gate.wait()

    monkeypatch.setattr(deployer, "run_deployment", slow_deploy)
    deployer.runner.submit(uuid.uuid4(), (inst_id,))
    try:
        r = await admin_client.delete(f"/api/v1/instances/{inst_id}")
        assert r.status_code == 409
    finally:
        gate.set()
        await asyncio.gather(*deployer.runner._tasks)
    assert not deployer.runner.busy((inst_id,))


async def test_deploys_during_delete_never_reach_the_host(admin_client, monkeypatch):
    inst_id, _, _ = await _add_instance("running", deployment={"status": "succeeded", "started_at": utcnow()})
    entered, gate = asyncio.Event(), asyncio.Event()

    async def slow_destroy(instance, **kw):
        entered.set()
        await gate.wait()

    remote = FakeRemote()
    monkeypatch.setattr(deployer, "destroy", slow_destroy)
    monkeypatch.setattr(
        deployer, "run_deployment",
        functools.partial(deployer.run_deployment, connect=_connect(remote), github=FakeGitHub),
    )
    delete = asyncio.create_task(admin_client.delete(f"/api/v1/instances/{inst_id}"))
    await asyncio.wait_for(entered.wait(), 5)

    r = await admin_client.post(f"/api/v1/instances/{inst_id}/deploy")
    assert r.status_code == 409 and "being deleted" in r.json()["detail"]
    # A deployment that slipped in anyway waits for the delete, then finds its row gone.
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=inst_id, branch="main", log="")
        db.add(dep)
        await db.commit()
    deployer.runner.submit(dep.id, (inst_id,))
    await asyncio.sleep(0.05)

    gate.set()
    assert (await delete).status_code == 204
    await asyncio.gather(*deployer.runner._tasks)
    assert remote.commands == []
    assert await _get(Instance, inst_id) is None


# --------------------------------------------- DB connection released during SSH (95, 65)


async def test_ssh_calls_do_not_hold_a_db_connection(admin_client, monkeypatch):
    inst_id, _, _ = await _add_instance("running", deployment={"status": "succeeded", "started_at": utcnow()})
    held = []

    async def fake_run(instance, command, **kw):
        held.append(get_engine().pool.checkedout())
        return '{"Names": "slipway-web-prod"}'

    async def fake_destroy(instance, **kw):
        held.append(get_engine().pool.checkedout())

    monkeypatch.setattr(deployer, "run_on_instance", fake_run)
    monkeypatch.setattr(deployer, "destroy", fake_destroy)
    assert (await admin_client.get(f"/api/v1/instances/{inst_id}/containers")).status_code == 200
    assert (await admin_client.get(f"/api/v1/instances/{inst_id}/logs")).status_code == 200
    assert (await admin_client.post(f"/api/v1/instances/{inst_id}/actions/stop")).status_code == 200
    assert (await _get(Instance, inst_id)).status == "stopped"
    assert (await admin_client.delete(f"/api/v1/instances/{inst_id}")).status_code == 204
    assert held == [0, 0, 0, 0]


# ---------------------------------------------------------- releases (52, 53)


async def test_same_sha_redeploy_never_touches_the_live_release():
    first = await _seed({})
    remote = FakeRemote()
    await deployer.run_deployment(first, connect=_connect(remote), github=FakeGitHub)
    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, first)
        second = Deployment(instance_id=dep.instance_id, branch="main", log="")
        db.add(second)
        await db.commit()
    live = f"/opt/slipway/web-prod/releases/a1b2c3d4e5f6-{first.hex[:8]}"
    start = len(remote.commands)
    await deployer.run_deployment(second.id, connect=_connect(remote), github=FakeGitHub)
    assert (await _get(Deployment, second.id)).status == "succeeded"

    new = f"/opt/slipway/web-prod/releases/a1b2c3d4e5f6-{second.id.hex[:8]}"
    later = remote.commands[start:]
    assert not any(live in c for c in later)
    switch = later.index(f"ln -sfn {new} /opt/slipway/web-prod/current")
    assert switch > max(i for i, c in enumerate(later) if c.startswith("docker run"))


def test_prune_keeps_current_and_new_release_and_uses_root_fallback(tmp_path, fake_docker):
    env, log = fake_docker
    root = tmp_path / "root"
    inst = _instance(host=Host(name="h", hostname="10.0.0.1", port=22, username="deploy", deploy_root=str(root)))
    releases = root / "web-prod" / "releases"
    names = ["r1", "r2", "r3", "r4", "r5", "r6"]
    for n, name in enumerate(names):
        (releases / name).mkdir(parents=True)
        os.utime(releases / name, (1_000_000 + n, 1_000_000 + n))
    # r1 holds files a container wrote as another user; plain rm cannot delete them.
    locked = releases / "r1" / "pgdata"
    locked.mkdir()
    (locked / "PG_VERSION").write_text("16")
    locked.chmod(stat.S_IRUSR | stat.S_IXUSR)
    os.utime(releases / "r1", (1_000_000, 1_000_000))
    (root / "web-prod" / "current").symlink_to(releases / "r2")  # current points at an old release
    try:
        result = _sh(deployer.prune_command(inst, str(releases / "r6")), env)
    finally:
        if locked.exists():
            locked.chmod(0o755)
    assert result.returncode == 0, result.stdout + result.stderr
    assert sorted(p.name for p in releases.iterdir()) == ["r2", "r4", "r5", "r6"]
    assert any(c.startswith("run --rm --network none -v") and c.endswith("/r/r1") for c in log.read_text().splitlines())



def test_prune_removes_stale_uploads(tmp_path, fake_docker):
    env, _ = fake_docker
    root = tmp_path / "root"
    inst = _instance(host=Host(name="h", hostname="10.0.0.1", port=22, username="deploy", deploy_root=str(root)))
    releases = root / "web-prod" / "releases"
    (releases / "r1").mkdir(parents=True)
    old, fresh = releases / ".upload-old.tar.gz", releases / ".upload-new.tar.gz"
    old.write_text("partial")
    fresh.write_text("partial")
    os.utime(old, (time.time() - 7200, time.time() - 7200))
    result = _sh(deployer.prune_command(inst, str(releases / "r1")), env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not old.exists() and fresh.exists() and (releases / "r1").exists()


def _release_and_upload(dep_id: uuid.UUID) -> tuple[str, str]:
    releases = "/opt/slipway/web-prod/releases"
    return f"{releases}/a1b2c3d4e5f6-{dep_id.hex[:8]}", f"{releases}/.upload-{dep_id.hex}.tar.gz"


async def test_failed_build_removes_its_release_and_upload():
    dep_id = await _seed({})
    remote = FakeRemote(fail_on="docker build")
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    release, upload = _release_and_upload(dep_id)
    assert dep.status == "failed" and "Removed unused release" in dep.log
    assert any(c.startswith(f"rm -f -- {upload}; rm -rf -- {release} ") for c in remote.commands)
    assert not any(c.startswith("ln -sfn") for c in remote.commands)


async def test_failed_upload_removes_the_partial_file():
    dep_id = await _seed({})

    class BrokenUpload(FakeRemote):
        async def put(self, local, remote):
            raise ssh.SSHError("SFTP upload failed")

    remote = BrokenUpload()
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    assert (await _get(Deployment, dep_id)).status == "failed"
    _, upload = _release_and_upload(dep_id)
    assert any(c.startswith(f"rm -f -- {upload};") for c in remote.commands)


async def test_failed_compose_up_keeps_a_release_its_containers_use():
    dep_id = await _seed({})
    async with get_sessionmaker()() as db:
        await db.execute(text("UPDATE instances SET build_source = 'compose', compose_file = 'docker/compose.yml'"))
        await db.commit()
    release, upload = _release_and_upload(dep_id)

    class HalfUp(FakeRemote):
        async def run(self, command, *, check=True, on_line=None, timeout=None, **kw):
            if "com.docker.compose.project.working_dir" in command:
                self.commands.append(command)
                return 0, f"{DOCKER_WARNING}\n/opt/slipway/web-prod/releases/older/docker\n{release}/docker\n"
            return await super().run(command, check=check, on_line=on_line, timeout=timeout, **kw)

    remote = HalfUp(fail_on=" up -d")
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "failed" and f"Kept {release}" in dep.log
    assert f"rm -f -- {upload}" in remote.commands
    assert not any(f"rm -rf -- {release}" in c for c in remote.commands)


class _Lines:
    def __init__(self) -> None:
        self.lines: list[str] = []

    async def line(self, text: str) -> None:
        self.lines.append(text)


async def test_discard_release_commands_work_on_the_host(tmp_path, fake_docker):
    env, _ = fake_docker
    root = tmp_path / "root"
    inst = _instance(build_source="compose",
                     host=Host(name="h", hostname="10.0.0.1", port=22, username="deploy", deploy_root=str(root)))
    releases = root / "web-prod" / "releases"
    release, upload = releases / "a1b2c3d4e5f6-0000abcd", releases / ".upload-x.tar.gz"
    (release / "docker").mkdir(parents=True)
    upload.write_text("partial")
    # A container of the project was started from the release: only the upload goes.
    in_use = {**env, "FAKE_PS": "0123456789ab", "FAKE_OWNER": f"{release}/docker", "FAKE_WARN": DOCKER_WARNING}
    await deployer._discard_release(LocalRemote(in_use), inst, str(release), str(upload), _Lines())
    assert release.exists() and not upload.exists()
    # Docker cannot say which containers exist: keep the release.
    await deployer._discard_release(LocalRemote({**env, "FAKE_PS_FAILS": "1"}), inst, str(release), str(upload), _Lines())
    assert release.exists()
    # Unused, with files a container wrote as root: removed through the throwaway container.
    upload.write_text("partial")
    locked = release / "docker" / "data"
    locked.mkdir()
    (locked / "f").write_text("x")
    locked.chmod(stat.S_IRUSR | stat.S_IXUSR)
    sink = _Lines()
    try:
        await deployer._discard_release(LocalRemote({**env, "FAKE_WARN": DOCKER_WARNING}), inst, str(release),
                                        str(upload), sink)
    finally:
        if locked.exists():
            locked.chmod(0o755)
    assert not release.exists() and not upload.exists()
    assert sink.lines == [f"Removed unused release {release}"]


# ------------------------------------------------------- destroy fallback (53, decision 7)


def _destroy_setup(tmp_path):
    root = tmp_path / "root"
    inst = _instance(host=Host(name="h", hostname="10.0.0.1", port=22, username="deploy", deploy_root=str(root)))
    locked = root / "web-prod" / "releases" / "abc" / "pgdata"
    locked.mkdir(parents=True)
    (locked / "base").write_text("x")
    (root / "web-prod" / "shared").mkdir()
    (root / "web-prod" / "shared" / ".env").write_text("SECRET=1\n")
    locked.chmod(stat.S_IRUSR | stat.S_IXUSR)
    return inst, root / "web-prod", locked


async def test_destroy_removes_container_written_files_through_docker(tmp_path, fake_docker):
    env, _ = fake_docker
    inst, base, locked = _destroy_setup(tmp_path)
    try:
        assert await deployer.destroy(inst, connect=_local(LocalRemote(env))) is None
    finally:
        if locked.exists():
            locked.chmod(0o755)
    assert not base.exists()


async def test_destroy_warns_when_files_are_left(tmp_path, fake_docker):
    env, _ = fake_docker
    inst, base, locked = _destroy_setup(tmp_path)
    try:
        warning = await deployer.destroy(inst, connect=_local(LocalRemote({**env, "FAKE_RUN_FAILS": "1"})))
    finally:
        locked.chmod(0o755)
    assert warning and str(base) in warning


async def test_destroy_refuses_when_containers_remain(tmp_path, fake_docker):
    env, _ = fake_docker
    inst, base, locked = _destroy_setup(tmp_path)
    try:
        with pytest.raises(deployer.DeployError):
            await deployer.destroy(inst, connect=_local(LocalRemote({**env, "FAKE_PS": "3f4e5d6c7b8a"})))
    finally:
        locked.chmod(0o755)
    assert base.exists()



DOCKER_WARNING = "WARNING: Error loading config file: /home/deploy/.docker/config.json: permission denied"


async def test_destroy_is_not_fooled_by_docker_warnings(tmp_path, fake_docker):
    # Docker prints the warning on stderr, which the SSH session mixes into the output.
    env, _ = fake_docker
    inst, base, locked = _destroy_setup(tmp_path)
    try:
        assert await deployer.destroy(inst, connect=_local(LocalRemote({**env, "FAKE_WARN": DOCKER_WARNING}))) is None
    finally:
        if locked.exists():
            locked.chmod(0o755)
    assert not base.exists()


async def test_destroy_stops_when_docker_cannot_list_containers(tmp_path, fake_docker):
    env, _ = fake_docker
    inst, base, locked = _destroy_setup(tmp_path)
    try:
        with pytest.raises(ssh.CommandFailed):
            await deployer.destroy(inst, connect=_local(LocalRemote({**env, "FAKE_PS_FAILS": "1"})))
    finally:
        locked.chmod(0o755)
    assert base.exists()


async def test_delete_with_leftover_files_deletes_row_and_reports(admin_client, monkeypatch):
    inst_id, _, _ = await _add_instance("running", deployment={"status": "succeeded", "started_at": utcnow()})

    async def partial_destroy(instance, **kw):
        return "Could not remove /opt/slipway/web-prod on prod-01; delete it by hand"

    monkeypatch.setattr(deployer, "destroy", partial_destroy)
    r = await admin_client.delete(f"/api/v1/instances/{inst_id}")
    assert r.status_code == 200 and "/opt/slipway/web-prod" in r.json()["warning"]
    assert await _get(Instance, inst_id) is None
    async with get_sessionmaker()() as db:
        ev = await db.scalar(select(AuditEvent).where(AuditEvent.action == "instance.delete"))
        assert "/opt/slipway/web-prod" in ev.summary and ev.details["warning"]


# ------------------------------------------------------------ compose env (44, 45, 54)


def test_compose_commands_pass_the_env_file_everywhere():
    inst = _instance(build_source="compose", compose_file="docker/compose.yml")
    flag = "--env-file /opt/slipway/web-prod/shared/.env -f docker/compose.yml"
    env_cmd, _, up = deployer.build_commands(inst, "/opt/slipway/web-prod/releases/x", SHA)
    assert env_cmd.startswith("cd /opt/slipway/web-prod/releases/x/docker &&")
    for cmd in (up, deployer.control_command(inst, "restart"), deployer.logs_command(inst), deployer.teardown_command(inst)):
        assert flag in cmd, cmd


def test_compose_env_merge_keeps_repo_defaults(tmp_path, fake_docker):
    env, _ = fake_docker
    root = tmp_path / "root"
    inst = _instance(build_source="compose", compose_file="docker/compose.yml",
                     host=Host(name="h", hostname="10.0.0.1", port=22, username="deploy", deploy_root=str(root)))
    release = root / "web-prod" / "releases" / "x"
    (release / "docker").mkdir(parents=True)
    (release / "docker" / ".env").write_text("PG_VERSION=16\nSECRET_KEY=from-repo")  # no trailing newline
    shared = root / "web-prod" / "shared"
    shared.mkdir()
    (shared / "slipway.env").write_text(deployer.render_compose_env({"SECRET_KEY": "pa$sw0rd #1"}))
    (shared / ".env").write_text("OLD=1\n")
    (shared / ".env").chmod(0o644)

    result = _sh(deployer.build_commands(inst, str(release), SHA)[0], env)
    assert result.returncode == 0, result.stderr
    assert (shared / ".env").read_text() == "PG_VERSION=16\nSECRET_KEY=from-repo\nSECRET_KEY='pa$sw0rd #1'\n"
    assert stat.S_IMODE((shared / ".env").stat().st_mode) == 0o600
    assert os.readlink(release / "docker" / ".env") == str(shared / ".env")


async def test_compose_deploy_writes_quoted_values_then_merges():
    dep_id = await _seed({"DB_PASSWORD": "pa$sw0rd #1"})
    async with get_sessionmaker()() as db:
        await db.execute(text("UPDATE instances SET build_source = 'compose', compose_file = 'docker/compose.yml'"))
        await db.commit()
    remote = FakeRemote()
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    assert (await _get(Deployment, dep_id)).status == "succeeded"
    assert remote.files["/opt/slipway/web-prod/shared/slipway.env"] == "DB_PASSWORD='pa$sw0rd #1'\n"
    assert "/opt/slipway/web-prod/shared/.env" not in remote.files  # built on the host from the repo's .env + slipway.env
    merge = next(i for i, c in enumerate(remote.commands) if "cat /opt/slipway/web-prod/shared/slipway.env" in c)
    up = next(i for i, c in enumerate(remote.commands) if " up -d --build" in c)
    switch = next(i for i, c in enumerate(remote.commands) if c.startswith("ln -sfn") and c.endswith("/current"))
    assert merge < up < switch


def _compose_dotenv_value(raw: str) -> str:
    """Compose's (compose-go) dotenv rules for a value, enough to check our quoting."""
    if raw[:1] not in ("'", '"'):
        # Unquoted: read literally up to a " #" comment, outer whitespace trimmed, $ interpolated.
        assert "$" not in raw and "#" not in raw and raw == raw.strip()
        return raw
    quote, body, out, i = raw[0], raw[1:], [], 0
    assert quote in "'\"" and body.endswith(quote)
    body = body[:-1]
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body) and body[i + 1] in (quote, "\\") and quote == '"':
            out.append(body[i + 1])
            i += 2
            continue
        assert c != quote, "unescaped quote inside value"
        if quote == '"' and c == "$":
            assert body[i + 1] == "$", "unescaped $ would be interpolated"
            out.append("$")
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


@pytest.mark.parametrize("value", [
    "pa$sw0rd #1", "abc$", "$HOME/x", "secret  ", '"start-no-close', "it's", 'a"b\'c', "back\\slash", "ends\\",
    "it's\\", "${OTHER}", "",
])
def test_compose_env_values_survive_dotenv_parsing(value):
    line = deployer.render_compose_env({"KEY": value})
    assert line.startswith("KEY=") and line.endswith("\n") and line.count("\n") == 1
    assert _compose_dotenv_value(line[4:-1]) == value
    # docker run --env-file reads values literally, so Dockerfile mode keeps the plain format.
    assert deployer.render_env({"KEY": value}) == f"KEY={value}\n"



def _old_compose_reads_to_the_end(raw: str) -> bool:
    """Older Compose releases end a quoted value at the first quote not preceded by a backslash."""
    if raw[:1] not in ("'", '"'):
        return True
    for i in range(1, len(raw)):
        if raw[i] == raw[0] and raw[i - 1] != "\\":
            return i == len(raw) - 1
    return False


@pytest.mark.parametrize("value", ["ends\\", "C:\\Program Files\\", "a\\b\\", "\\"])
def test_trailing_backslash_is_written_unquoted(value):
    line = deployer.render_compose_env({"KEY": value})
    assert line == f"KEY={value}\n"
    assert _compose_dotenv_value(line[4:-1]) == value


@pytest.mark.parametrize("value", [
    "pa$sw0rd #1", "abc$", "$HOME/x", "secret  ", '"start-no-close', "it's", 'a"b\'c', "back\\slash", "ends\\",
    "${OTHER}", "", "a\\b\\",
])
def test_compose_env_values_parse_in_older_compose(value):
    # Only a value that needs quoting and ends in a backslash (e.g. "it's\\") needs a newer Compose.
    assert _old_compose_reads_to_the_end(deployer.render_compose_env({"KEY": value})[4:-1])


def test_env_values_with_nul_are_rejected():
    with pytest.raises(ValueError):
        deployer.clean_env({"KEY": "a\x00b"})


# ------------------------------------------------- failure path (51, 59, 63, 84, 97)


def _rejects_nul(conn, cursor, statement, parameters, context, executemany):
    if any(isinstance(p, str) and "\x00" in p for p in (parameters or ())):
        raise sqlite3.DataError('invalid byte sequence for encoding "UTF8": 0x00')


class NulRemote(FakeRemote):
    async def run(self, command, *, check=True, on_line=None, timeout=None, **kw):
        self.commands.append(command)
        if "docker build" in command:
            await on_line("#7 0.21 PK\x03\x04\x00\x00binary")
            raise ssh.CommandFailed(command, 1, "#7 0.21 PK\x03\x04\x00\x00binary\nERROR: failed")
        return 0, ""


async def test_nul_bytes_in_build_output_do_not_wedge_the_deployment(fast_retries):
    dep_id = await _seed({})
    with _db_hook(_rejects_nul):
        await deployer.run_deployment(dep_id, connect=_connect(NulRemote()), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "failed" and dep.instance.status == "failed"
    assert "\x00" not in dep.error and "�" in dep.error
    assert "�" in dep.log and "Deployment failed" in dep.log


async def test_db_outage_during_failure_is_retried(fast_retries):
    dep_id = await _seed({})
    outage = {"left": 0}

    class OutageRemote(FakeRemote):
        async def run(self, command, *, check=True, on_line=None, timeout=None, **kw):
            if "docker build" in command:
                outage["left"] = 5
            return await super().run(command, check=check, on_line=on_line, timeout=timeout, **kw)

    def hook(conn, cursor, statement, parameters, context, executemany):
        if outage["left"] > 0:
            outage["left"] -= 1
            raise sqlite3.OperationalError("server closed the connection unexpectedly")

    with _db_hook(hook):
        await deployer.run_deployment(dep_id, connect=_connect(OutageRemote(fail_on="docker build")), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert outage["left"] == 0
    assert dep.status == "failed" and dep.instance.status == "failed" and dep.finished_at is not None


async def test_failed_log_write_does_not_fail_a_working_deploy(fast_retries):
    dep_id = await _seed({})
    failures = {"left": 1}

    def hook(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("UPDATE deployments SET log") and failures["left"]:
            failures["left"] -= 1
            raise sqlite3.OperationalError("database is locked")

    class ChattyRemote(FakeRemote):
        async def run(self, command, *, check=True, on_line=None, timeout=None, **kw):
            if on_line and "docker build" in command:
                for n in range(250):  # forces a flush in the middle of the build
                    await on_line(f"build line {n}")
            return await super().run(command, check=check, on_line=on_line, timeout=timeout, **kw)

    with _db_hook(hook):
        await deployer.run_deployment(dep_id, connect=_connect(ChattyRemote()), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert failures["left"] == 0
    assert dep.status == "succeeded", dep.error
    assert "build line 0" in dep.log and "build line 249" in dep.log


async def test_undecryptable_env_fails_the_deploy(fast_retries):
    dep_id = await _seed({"SECRET": "x"})
    async with get_sessionmaker()() as db:
        await db.execute(text("UPDATE instances SET env = 'not-a-fernet-token'"))
        await db.commit()
    remote = FakeRemote()
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    async with get_sessionmaker()() as db:
        status, error = (await db.execute(text("SELECT status, error FROM deployments"))).one()
    assert status == "failed" and "decrypt" in error
    assert remote.commands == []


async def test_env_never_set_deploys_with_no_variables():
    dep_id = await _seed(None)
    remote = FakeRemote()
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    assert (await _get(Deployment, dep_id)).status == "succeeded"
    assert remote.files["/opt/slipway/web-prod/shared/.env"] == ""


async def test_env_that_decrypts_to_nothing_fails_the_deploy(fast_retries, monkeypatch):
    # The fail-soft decryption hands back None for values it cannot read.
    dep_id = await _seed({"SECRET": "x"})
    async with get_sessionmaker()() as db:
        await db.execute(text("UPDATE instances SET env = 'unreadable'"))
        await db.commit()
    real = crypto.decrypt
    monkeypatch.setattr(crypto, "decrypt", lambda token: "null" if token == "unreadable" else real(token))
    remote = FakeRemote()
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "failed" and dep.error == deployer.ENV_UNREADABLE
    assert remote.commands == []


# ---------------------------------------------------------------- log cap (72)


async def test_build_log_is_capped_keeping_head_and_tail(monkeypatch):
    monkeypatch.setattr(deployer, "LOG_HEAD_CHARS", 2000)
    monkeypatch.setattr(deployer, "LOG_TAIL_CHARS", 2000)
    dep_id = await _seed({})

    class LoudRemote(FakeRemote):
        async def run(self, command, *, check=True, on_line=None, timeout=None, **kw):
            if on_line and "docker build" in command:
                for n in range(3000):
                    await on_line(f"line {n:05d} " + "x" * 80)
            return await super().run(command, check=check, on_line=on_line, timeout=timeout, **kw)

    await deployer.run_deployment(dep_id, connect=_connect(LoudRemote()), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded"
    assert len(dep.log) < 6000
    assert "line 00000" in dep.log and "line 02999" in dep.log and "Deployment succeeded" in dep.log
    assert "truncated" in dep.log and "omitted" in dep.log


# -------------------------------------------------------- repository identity (19)


async def test_deploy_refuses_a_repository_with_another_id():
    dep_id = await _seed({})

    class Hijacked(FakeGitHub):
        async def get_repository(self, repo_id):
            return {"id": 999, "full_name": "acme/web", "owner": {"login": "acme"}, "name": "web",
                    "html_url": "https://github.com/acme/web"}

        async def download_tarball(self, repo_id, sha, dest):
            raise AssertionError("must not download")

    remote = FakeRemote()
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=Hijacked)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "failed" and "different repository" in dep.error and remote.commands == []


async def test_deploy_fails_when_repository_is_gone():
    dep_id = await _seed({})

    class Gone(FakeGitHub):
        async def get_repository(self, repo_id):
            raise GitHubError("GitHub API /repositories/42: Not Found", 404)

    await deployer.run_deployment(dep_id, connect=_connect(FakeRemote()), github=Gone)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "failed" and "not found" in dep.error


async def test_renamed_repository_is_refreshed_and_fetched_by_id():
    dep_id = await _seed({})
    FakeGitHub.calls.clear()

    class Renamed(FakeGitHub):
        async def get_repository(self, repo_id):
            return {"id": 42, "full_name": "acme-new/web", "owner": {"login": "acme-new"}, "name": "web",
                    "html_url": "https://github.com/acme-new/web"}

    await deployer.run_deployment(dep_id, connect=_connect(FakeRemote()), github=Renamed)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded" and "acme-new/web" in dep.log
    repo = await _get(Repository, dep.instance.repository_id)
    assert (repo.full_name, repo.owner, repo.html_url) == ("acme-new/web", "acme-new", "https://github.com/acme-new/web")
    assert FakeGitHub.calls == ["commit 42@main", f"tarball 42@{SHA}"]


# --------------------------------------------------- commit metadata (57, 70)


async def test_commit_metadata_fits_its_columns():
    dep_id = await _seed({})

    class Odd(FakeGitHub):
        async def get_commit(self, repo_id, ref):
            return CommitInfo(sha=SHA, message="fix\x00" + "m" * 600, author="A" * 150, date=None)

    await deployer.run_deployment(dep_id, connect=_connect(FakeRemote()), github=Odd)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded", dep.error
    assert len(dep.commit_author) == 100 and len(dep.commit_message) == 500
    assert "\x00" not in dep.commit_message


# ------------------------------------------------------------ permissions (37)


def test_permission_descriptions_say_compose_means_root():
    assert "root" in PERMISSION_DESCRIPTIONS[Perm.DEPLOYMENTS_CREATE]
    assert "root" in PERMISSION_DESCRIPTIONS[Perm.INSTANCES_WRITE]
