"""Regression tests for the final review of remote execution: login shells other than sh, images
that must not be pulled (and Docker CLIs too old for --pull=never), paths that start with '-',
stdin, memory use of streamed output (and what clipping its lines must not break) and symbolic
links in the deployed repository."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import tarfile
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import asyncssh
import pytest
from pydantic import ValidationError
from sqlalchemy import text

from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Host, Instance, Repository
from slipway.schemas import InstanceCreate, InstanceUpdate
from slipway.services import deployer, ssh
from tests.conftest import make_user
from tests.test_deployer import (
    ARCHIVE_TOP,
    SHA,
    FakeGitHub,
    FakeRemote,
    _connect,
    _instance,
    _seed,
    write_source_archive,
)

# The shells a deploy user may log in with. zsh (the macOS default) used to break deploys.
SHELLS = [s for s in ("sh", "dash", "bash", "zsh") if shutil.which(s)]
LABEL = "label=slipway.instance=00000000-0000-0000-0000-000000000001"

DOCKER_SHIM = """#!/bin/sh
echo "$*" >> "$DOCKER_LOG"
case "$1" in
  build) echo "#1 [internal] load build definition from Dockerfile" ;;
  ps)
    [ -n "$FAKE_PS_FAILS" ] && { echo "Cannot connect to the Docker daemon" >&2; exit 1; }
    [ -n "$FAKE_PS" ] && printf '%s\\n' $FAKE_PS ;;
  container)
    shift 4  # container inspect -f FORMAT ID...
    for id in "$@"; do
      case "$id" in ""|*[!0-9a-f]*) echo "Error: No such container: $id" >&2; exit 1 ;; esac
      echo "/w/$id"
    done ;;
  image)
    case "$2" in
      inspect) [ -n "$FAKE_NO_IMAGE" ] && { echo "Error: No such image: $5" >&2; exit 1; } ;;
      ls) [ -n "$FAKE_IMAGES" ] && printf '%s\\n' $FAKE_IMAGES ;;
    esac ;;
  volume) [ -n "$FAKE_VOLUMES" ] && printf '%s\\n' $FAKE_VOLUMES ;;
  run)
    if [ -n "$FAKE_OLD_DOCKER" ]; then  # Docker before 20.10
      case " $* " in *" --pull"*) printf "unknown flag: --pull\\nSee 'docker run --help'.\\n" >&2; exit 125 ;; esac
    fi
    [ -n "$FAKE_RUN_FAILS" ] && exit 1 ;;
esac
exit 0
"""


@pytest.fixture
def docker_shim(tmp_path):
    """Environment with a fake ``docker`` first on PATH, and the file it logs its calls to."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = bin_dir / "docker"
    script.write_text(DOCKER_SHIM)
    script.chmod(0o755)
    log = tmp_path / "docker.log"
    log.write_text("")
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "DOCKER_LOG": str(log), "HOME": str(tmp_path)}
    return env, log


def _in_shell(shell: str, command: str, env: dict[str, str]) -> subprocess.CompletedProcess:
    """Run ``command`` the way sshd does: ``<login shell> -c <command>``."""
    return subprocess.run([shell, "-c", command], env=env, capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=60)


class ShellRemote:
    """A RemoteSession stand-in that runs every command in ``shell`` on this machine."""

    def __init__(self, shell: str, env: dict[str, str]) -> None:
        self.shell, self.env = shell, env
        self.commands: list[str] = []

    async def run(self, command, *, check=True, on_line=None, timeout=None):
        self.commands.append(command)
        result = await asyncio.to_thread(_in_shell, self.shell, command, self.env)
        output = result.stdout + result.stderr
        if on_line is not None:
            for line in output.splitlines():
                await on_line(line)
        if check and result.returncode:
            raise ssh.CommandFailed(command, result.returncode, output)
        return result.returncode, output

    async def put(self, local, remote):
        shutil.copyfile(local, remote)

    async def write_text(self, remote, content, mode=0o600):
        Path(remote).write_text(content)
        os.chmod(remote, mode)


def _local(remote):
    @asynccontextmanager
    async def factory(target):
        yield remote
    return factory


def _at(root: Path, **kw) -> Instance:
    return _instance(host=Host(name="h", hostname="10.0.0.1", port=22, username="deploy", deploy_root=str(root)), **kw)


async def _seed_at(root: Path, **fields) -> tuple[uuid.UUID, uuid.UUID]:
    """An instance deployed into ``root``. Returns (instance id, id of the user deploying it)."""
    user = await make_user("admin@example.com")
    async with get_sessionmaker()() as db:
        host = Host(name="prod-01", hostname="10.0.0.1", username="deploy", host_key="ssh-ed25519 AAAA", metrics={},
                    deploy_root=str(root))
        repo = Repository(github_id=42, full_name="acme/web", owner="acme", name="web",
                          html_url="https://github.com/acme/web", detected_config={})
        inst = Instance(name="web", slug="web-prod", branch="main", host=host, repository=repo, env={"A": "1"},
                        ports=[], volumes=[], **fields)
        db.add(inst)
        await db.commit()
        return inst.id, user.id


async def _queue(instance_id: uuid.UUID, user_id: uuid.UUID) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=instance_id, branch="main", triggered_by_id=user_id, log="")
        db.add(dep)
        await db.commit()
        return dep.id


async def _deployment(dep_id: uuid.UUID) -> Deployment:
    async with get_sessionmaker()() as db:
        return await db.get(Deployment, dep_id)


# ------------------------------------------------------- 1: any login shell (zsh)


def test_unpack_command_works_in_every_login_shell(tmp_path, docker_shim):
    env, _ = docker_shim
    for shell in SHELLS:
        releases = tmp_path / shell / "releases"
        releases.mkdir(parents=True)
        upload, release = releases / ".upload-x.tar.gz", releases / "r1"
        write_source_archive(upload, {"Dockerfile": "FROM node:22\n", "src/app.js": "1"})
        result = _in_shell(shell, deployer.unpack_command(str(release), str(upload)), env)
        assert result.returncode == 0, (shell, result.stderr)
        assert (release / "Dockerfile").read_text() == "FROM node:22\n" and (release / "src" / "app.js").exists()
        assert not upload.exists(), shell
        # A broken upload fails the step, and is removed all the same.
        upload.write_bytes(b"not a tarball")
        result = _in_shell(shell, deployer.unpack_command(str(releases / "r2"), str(upload)), env)
        assert result.returncode != 0 and not upload.exists(), shell


def _releases(root: Path) -> Path:
    releases = root / "web-prod" / "releases"
    for n, name in enumerate(["r1", "r2", "r3", "r4", "r5", "r6"]):
        (releases / name).mkdir(parents=True)
        os.utime(releases / name, (1_000_000 + n, 1_000_000 + n))
    (root / "web-prod" / "current").symlink_to(releases / "r2")
    return releases


IMAGES = "slipway/web-prod:t5 slipway/web-prod:t4 slipway/web-prod:t3 slipway/web-prod:t2 slipway/web-prod:t1"
def _image_calls(label: str = LABEL) -> list[str]:
    """The docker calls with which prune removes superseded images and dangling layers."""
    return [
        "image ls --format {{.Repository}}:{{.Tag}} slipway/web-prod",
        "image rm slipway/web-prod:t2 slipway/web-prod:t1",
        f"image prune -f --filter {label}",
        "image prune -f --filter label=com.docker.compose.project=slipway-web-prod",
    ]


def test_prune_command_works_in_every_login_shell(tmp_path, docker_shim):
    env, log = docker_shim
    for shell in SHELLS:
        root = tmp_path / shell
        releases = _releases(root)
        log.write_text("")
        result = _in_shell(shell, deployer.prune_command(_at(root), str(releases / "r6")), {**env, "FAKE_IMAGES": IMAGES})
        assert result.returncode == 0, (shell, result.stderr)
        assert sorted(p.name for p in releases.iterdir()) == ["r2", "r4", "r5", "r6"], shell
        # The image clean-up after the release loop runs in every shell.
        assert log.read_text().splitlines() == _image_calls(), shell


def test_prune_reports_a_release_it_could_not_remove_and_still_prunes_images(tmp_path, docker_shim):
    env, log = docker_shim
    for shell in SHELLS:
        root = tmp_path / shell
        releases = _releases(root)
        locked = releases / "r1" / "pgdata"
        locked.mkdir()
        (locked / "PG_VERSION").write_text("16")
        locked.chmod(0o500)
        os.utime(releases / "r1", (1_000_000, 1_000_000))
        log.write_text("")
        try:
            result = _in_shell(shell, deployer.prune_command(_at(root), str(releases / "r6")),
                               {**env, "FAKE_IMAGES": IMAGES, "FAKE_RUN_FAILS": "1"})
        finally:
            locked.chmod(0o755)
        assert result.returncode == 1, (shell, result.stderr)
        assert (releases / "r1").exists() and not (releases / "r3").exists(), shell
        assert [c for c in log.read_text().splitlines() if c.startswith("image")] == _image_calls(), shell


def test_release_users_command_works_in_every_login_shell(docker_shim):
    env, _ = docker_shim
    command = deployer.release_users_command(_instance(build_source="compose"))
    for shell in SHELLS:
        two = _in_shell(shell, command, {**env, "FAKE_PS": "aaaaaaaaaaaa bbbbbbbbbbbb"})
        assert two.returncode == 0, (shell, two.stderr)
        assert two.stdout.splitlines() == ["/w/aaaaaaaaaaaa", "/w/bbbbbbbbbbbb"], shell
        none = _in_shell(shell, command, env)
        assert none.returncode == 0 and none.stdout == "", shell
        # Docker cannot list the containers: fail, so the release is kept.
        assert _in_shell(shell, command, {**env, "FAKE_PS_FAILS": "1"}).returncode != 0, shell


async def test_deploys_succeed_whatever_the_login_shell(tmp_path, docker_shim):
    env, log = docker_shim
    root = tmp_path / "root"
    inst_id, user_id = await _seed_at(root)
    releases = root / "web-prod" / "releases"
    for shell in SHELLS:
        log.write_text("")
        dep_id = await _queue(inst_id, user_id)
        remote = ShellRemote(shell, {**env, "FAKE_IMAGES": IMAGES})
        await deployer.run_deployment(dep_id, connect=_local(remote), github=FakeGitHub)
        dep = await _deployment(dep_id)
        assert dep.status == "succeeded", (shell, dep.error, dep.log)
        release = releases / f"a1b2c3d4e5f6-{dep_id.hex[:8]}"
        assert (release / "Dockerfile").exists() and os.readlink(root / "web-prod" / "current") == str(release)
        assert not list(releases.glob(".upload-*")), shell
        assert (root / "web-prod" / "shared" / ".env").read_text() == "A=1\n"
        calls = log.read_text().splitlines()
        assert any(c.startswith("run -d ") for c in calls), (shell, calls)
        pruned = [c for c in calls if c.startswith("image ") and "inspect" not in c]
        assert pruned == _image_calls(f"label=slipway.instance={inst_id}"), (shell, calls)


class _OpenServer(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return False  # no authentication required


@pytest.fixture
async def ssh_server():
    """Start an in-process SSH server with a process factory; yields a connected-target factory."""
    servers = []

    async def start(process_factory) -> ssh.SSHTarget:
        host_key = asyncssh.generate_private_key("ssh-ed25519")
        server = await asyncssh.create_server(_OpenServer, "127.0.0.1", 0, server_host_keys=[host_key],
                                              process_factory=process_factory)
        servers.append(server)
        port = server.sockets[0].getsockname()[1]
        pinned = host_key.export_public_key("openssh").decode().strip()
        return ssh.SSHTarget(hostname="127.0.0.1", port=port, username="deploy", password="pw", pinned_host_key=pinned)

    yield start
    for server in servers:
        server.close()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(server.wait_closed(), 5)


LOGIN_SHELL = shutil.which("zsh") or shutil.which("bash") or "/bin/sh"


async def test_run_hands_the_command_to_sh_whatever_the_login_shell(ssh_server, tmp_path):
    received: list[str] = []

    async def login_shell(process: asyncssh.SSHServerProcess) -> None:
        # What sshd does with an exec request: run it with the user's login shell (zsh here).
        received.append(process.command)
        proc = await asyncio.create_subprocess_exec(
            LOGIN_SHELL, "-c", process.command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, env={"PATH": os.environ["PATH"], "HOME": str(tmp_path)},
        )
        out, _ = await proc.communicate()
        process.stdout.write(out.decode())
        process.exit(proc.returncode)

    target = await ssh_server(login_shell)
    status_var = "true; status=$?; echo cleanup-ran; exit $status"  # zsh: read-only variable: status
    exit_in_pipe = "printf 'a\\nb\\n' | { while read d; do :; done; exit 0; }; echo after"
    failing = "echo \"it's $((6 * 7))\" >&2; exit 4"
    async with ssh.open_session(target) as remote:
        assert await remote.run(status_var, timeout=30) == (0, "cleanup-ran")
        assert await remote.run(exit_in_pipe, timeout=30) == (0, "after")
        with pytest.raises(ssh.CommandFailed) as exc:
            await remote.run(failing, timeout=30)
    assert received == [f"exec /bin/sh -c {shlex.quote(c)}" for c in (status_var, exit_in_pipe, failing)]
    # Errors name the command as Slipway built it, not the wrapper.
    assert exc.value.command == failing and exc.value.exit_status == 4 and "it's 42" in str(exc.value)


# -------------------------------------------- 3: a build that loaded no image


def test_dockerfile_mode_never_pulls_its_image():
    build, _, run = deployer.build_commands(_instance(), "/opt/slipway/web-prod/releases/r", SHA)
    assert build.startswith("docker run --pull=never --help >/dev/null 2>&1 || ")
    assert build.endswith(" . && docker image inspect --format . slipway/web-prod:a1b2c3d4e5f6 >/dev/null")
    assert run.startswith("docker run -d --pull=never ") and run.endswith(" slipway/web-prod:a1b2c3d4e5f6")


async def test_docker_without_pull_never_fails_before_the_container_is_removed(tmp_path, docker_shim):
    # docker run --pull came with Docker 20.10; an older CLI rejects it only when run is called.
    env, log = docker_shim
    root = tmp_path / "root"
    inst_id, user_id = await _seed_at(root)
    for docker, works in (({"FAKE_OLD_DOCKER": "1"}, False), ({}, True)):
        log.write_text("")
        dep_id = await _queue(inst_id, user_id)
        await deployer.run_deployment(dep_id, connect=_local(ShellRemote("/bin/sh", {**env, **docker})), github=FakeGitHub)
        dep = await _deployment(dep_id)
        calls = log.read_text().splitlines()
        assert calls[0] == "run --pull=never --help", calls  # parses run's flags, before anything else
        if works:
            assert dep.status == "succeeded", dep.error
            assert calls[1].startswith("build ") and any(c.startswith("run -d --pull=never ") for c in calls), calls
        else:
            assert dep.status == "failed" and dep.error.endswith(deployer.PULL_NEVER_UNSUPPORTED), dep.error
            # Nothing built, removed or started; the failed release's clean-up only lists containers.
            assert calls == ["run --pull=never --help", "ps -aq --filter label=com.docker.compose.project=slipway-web-prod"]
            assert "unknown flag" not in dep.log  # the check's own message stands alone


async def test_build_without_a_local_image_fails_before_the_container_is_removed(tmp_path, docker_shim):
    # e.g. a docker-container buildx builder: the build exits 0 but loads nothing.
    env, log = docker_shim
    root = tmp_path / "root"
    inst_id, user_id = await _seed_at(root)
    dep_id = await _queue(inst_id, user_id)
    remote = ShellRemote("/bin/sh", {**env, "FAKE_NO_IMAGE": "1"})
    await deployer.run_deployment(dep_id, connect=_local(remote), github=FakeGitHub)
    dep = await _deployment(dep_id)
    assert dep.status == "failed" and "No such image: slipway/web-prod:a1b2c3d4e5f6" in dep.error
    calls = log.read_text().splitlines()
    assert any(c.startswith("build ") for c in calls)
    removal = f"ps -aq --filter label=slipway.instance={inst_id}"
    assert not any(c.startswith(removal) or c.startswith("run -d ") for c in calls), calls


# ------------------------------------------------ 4: paths starting with '-'


@pytest.mark.parametrize("value", ["-", "-f", "--help", "./-", "--version/Dockerfile", "-h/x"])
def test_paths_starting_with_a_dash_are_rejected(value):
    for allow_dot in (False, True):
        with pytest.raises(ValueError, match="must not start with '-'"):
            deployer.clean_relative_path(value, allow_dot=allow_dot)
    ids = {"name": "web", "repository_id": uuid.uuid4(), "host_id": uuid.uuid4()}
    for field in ("dockerfile_path", "build_context", "compose_file"):
        with pytest.raises(ValidationError):
            InstanceCreate(**ids, **{field: value})
        with pytest.raises(ValidationError):
            InstanceUpdate(**{field: value})
    # A dash further in cannot be read as an option or as stdin.
    assert deployer.clean_relative_path(f"docker/{value}") == posixpath.normpath(f"docker/{value}")
    assert deployer.clean_relative_path("my-app", allow_dot=True) == "my-app"


async def test_api_refuses_a_build_context_starting_with_a_dash(admin_client):
    body = {"name": "web", "repository_id": str(uuid.uuid4()), "host_id": str(uuid.uuid4()), "deploy": False}
    for field, value in (("build_context", "--help"), ("dockerfile_path", "-"), ("compose_file", "-f")):
        r = await admin_client.post("/api/v1/instances", json={**body, field: value})
        assert r.status_code == 422, r.text
        assert "must not start with '-'" in r.text


async def test_remote_commands_see_end_of_input(ssh_server):
    async def read_stdin(process: asyncssh.SSHServerProcess) -> None:  # like `docker build -`
        data = await process.stdin.read()
        process.stdout.write(f"stdin closed after {len(data)} bytes\n")
        process.exit(0)

    async with ssh.open_session(await ssh_server(read_stdin)) as remote:
        assert await remote.run("docker build -", timeout=3) == (0, "stdin closed after 0 bytes")


# ------------------------------------------------ 14: memory of streamed output

LINES = 100_000


async def test_streamed_output_is_not_kept(ssh_server):
    async def flood(process: asyncssh.SSHServerProcess) -> None:
        for start in range(0, LINES, 10_000):
            process.stdout.write("".join(f"#5 1.0 line {n}\n" for n in range(start, start + 10_000)))
            await process.stdout.drain()
        process.exit(0)

    seen = {"count": 0, "last": ""}

    async def on_line(line: str) -> None:
        seen["count"] += 1
        seen["last"] = line

    async with ssh.open_session(await ssh_server(flood)) as remote:
        status, output = await remote.run("docker build .", on_line=on_line, timeout=120)
    assert status == 0 and seen == {"count": LINES, "last": f"#5 1.0 line {LINES - 1}"}
    assert len(output) < 1000
    assert output.splitlines() == [f"#5 1.0 line {n}" for n in range(LINES - 15, LINES)]  # what CommandFailed shows


async def test_kept_lines_are_clipped(ssh_server):
    long, cap = "x" * 100_000, deployer.MAX_LINE_CHARS  # the deployment log's per-line cap

    async def long_line(process: asyncssh.SSHServerProcess) -> None:
        process.stdout.write(f"{long}\nend\n")
        process.exit(1)

    seen: list[str] = []

    async def on_line(line: str) -> None:
        seen.append(line)

    clipped = "x" * cap + " [line truncated]"  # marked as in the deployment log, e.g. in the logs view
    async with ssh.open_session(await ssh_server(long_line)) as remote:
        status, output = await remote.run("cat big", check=False, timeout=30)
        assert status == 1 and output == f"{clipped}\nend"
        with pytest.raises(ssh.CommandFailed) as exc:
            await remote.run("cat big", on_line=on_line, timeout=30)
    assert seen == [long, "end"]  # the line callback (the deployment log caps it) gets every line whole
    assert exc.value.output == f"{clipped}\nend" and len(str(exc.value)) < cap + 100
    assert ssh.MAX_LINE_CHARS == cap
    # Lines at the cap are left alone.
    assert ssh.clip_line("y" * cap) == "y" * cap


async def test_containers_with_many_labels_are_still_listed(admin_client, ssh_server, monkeypatch):
    # Labels (an image's included) can make `docker ps --format '{{json .}}'` rows longer than the cap.
    container = {
        "ID": "0123456789ab", "Names": "slipway-web-prod", "Image": "slipway/web-prod:a1b2c3d4e5f6",
        "Command": '"node server.js"', "State": "running", "Status": "Up 2 hours",
        "Ports": "0.0.0.0:8080->3000/tcp", "RunningFor": "2 hours ago",
        "Labels": ",".join(f"org.example.label{n}={'v' * 200}" for n in range(100)),
    }
    rows: list[str] = []

    async def docker_ps(process: asyncssh.SSHServerProcess) -> None:
        # As docker renders --format: {{json .Field}} is that field as JSON, {{json .}} all of them.
        # (The command arrives as one argument to `exec /bin/sh -c`.)
        argv = shlex.split(process.command.removeprefix("exec /bin/sh -c "))
        argv = shlex.split(argv[0]) if len(argv) == 1 else argv
        fmt = argv[argv.index("--format") + 1]
        row = re.sub(r"\{\{json \.(\w*)\}\}", lambda m: json.dumps(container[m[1]] if m[1] else container), fmt)
        rows.append(row)
        process.stdout.write(row + "\n")
        process.exit(0)

    target = await ssh_server(docker_ps)
    run_on_instance = deployer.run_on_instance

    async def via_server(instance, command, **kw):
        return await run_on_instance(instance, command, connect=lambda _: ssh.open_session(target), **kw)

    monkeypatch.setattr(deployer, "run_on_instance", via_server)
    async with get_sessionmaker()() as db:
        host = Host(name="prod-01", hostname="10.0.0.1", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
        repo = Repository(github_id=42, full_name="acme/web", owner="acme", name="web",
                          html_url="https://github.com/acme/web", detected_config={})
        inst = Instance(name="web", slug="web-prod", branch="main", host=host, repository=repo, env={},
                        ports=[], volumes=[], status="running")
        db.add(inst)
        await db.commit()
    r = await admin_client.get(f"/api/v1/instances/{inst.id}/containers")
    assert r.status_code == 200, r.text
    shown = ("Names", "Image", "State", "Status", "Ports", "RunningFor")  # what the containers endpoint reads
    assert r.json() == [{k: container[k] for k in shown}]
    assert len(rows) == 1 and len(rows[0]) < 300  # only the fields the page shows


# ------------------------------------------------------ 15: links in the repository

ESCAPE = "../../../other-app/shared"


@pytest.mark.parametrize(("fields", "archive", "message"), [
    ({"build_context": "app"}, {"symlinks": {"app": ESCAPE}}, "The build context 'app' is a symbolic link"),
    ({"build_context": "app"}, {"symlinks": {"app": "/home/deploy/.ssh"}}, "The build context 'app' is a symbolic link"),
    ({"build_context": "app/web"}, {"symlinks": {"app": ESCAPE}}, "'app' in the build context path 'app/web' is a symbolic link"),
    ({"build_context": "app/web"}, {"dirs": ("app",), "symlinks": {"app/web": ESCAPE}},
     "The build context 'app/web' is a symbolic link"),
    ({"build_context": "app"}, {"files": {"app": "not a directory"}}, "The build context 'app' is not a directory"),
    ({}, {"files": {"real": "FROM x"}, "symlinks": {"Dockerfile": "/etc/passwd"}},
     "The Dockerfile 'Dockerfile' is a symbolic link"),
    ({}, {"files": {"real": "FROM x"}, "hardlinks": {"Dockerfile": f"{ARCHIVE_TOP}/real"}},
     "The Dockerfile 'Dockerfile' is a hard link"),
    ({"dockerfile_path": "docker/Dockerfile"}, {"symlinks": {"docker": ESCAPE}},
     "'docker' in the Dockerfile path 'docker/Dockerfile' is a symbolic link"),
    ({"build_source": "compose", "compose_file": "deploy/compose.yml"}, {"symlinks": {"deploy": ESCAPE}},
     "'deploy' in the compose file path 'deploy/compose.yml' is a symbolic link"),
    ({"build_source": "compose", "compose_file": "compose.yml"}, {"symlinks": {"compose.yml": "/etc/hostname"}},
     "The compose file 'compose.yml' is a symbolic link"),
])
def test_archive_with_linked_build_paths_is_refused(tmp_path, fields, archive, message):
    tarball = tmp_path / "source.tar.gz"
    write_source_archive(tarball, **{"files": {}, **archive})
    with pytest.raises(deployer.DeployError) as exc:
        deployer.check_source_archive(tarball, deployer.guarded_paths(_instance(**fields)))
    assert str(exc.value) == f"{message} in the repository; refusing to deploy"


def test_links_elsewhere_in_the_repository_are_fine(tmp_path):
    tarball = tmp_path / "source.tar.gz"
    write_source_archive(tarball, {"app/Dockerfile": "FROM x", "docker/compose.yml": "services: {}"},
                         dirs=("app", "docker"), symlinks={"README": "docs/README.md", "app/shared": ESCAPE, ".env": "x"})
    for fields in ({}, {"build_context": "app", "dockerfile_path": "app/Dockerfile"},
                   {"build_source": "compose", "compose_file": "docker/compose.yml"}):
        deployer.check_source_archive(tarball, deployer.guarded_paths(_instance(**fields)))


def _one_link(tarball: Path, name: str) -> Path:
    with tarfile.open(tarball, "w:gz") as tar:
        info = tarfile.TarInfo(name)
        info.type, info.linkname = tarfile.SYMTYPE, ESCAPE
        tar.addfile(info)
    return tarball


@pytest.mark.parametrize("name", ["top/app", "top//app/", "top/./app", "top/app/.", "top/app//"])
def test_archive_member_names_are_read_as_tar_strips_them(tmp_path, name):
    # Each of these lands on <release>/app with `tar --strip-components=1`.
    guarded = deployer.guarded_paths(_instance(build_context="app"))
    with pytest.raises(deployer.DeployError, match="The build context 'app' is a symbolic link"):
        deployer.check_source_archive(_one_link(tmp_path / "source.tar.gz", name), guarded)


@pytest.mark.parametrize("name", ["app", "./top/app", "top/sub/app", "top/application"])
def test_archive_members_elsewhere_are_not_mistaken_for_build_paths(tmp_path, name):
    guarded = deployer.guarded_paths(_instance(build_context="app"))
    deployer.check_source_archive(_one_link(tmp_path / "source.tar.gz", name), guarded)


def test_unsafe_or_unreadable_archives_are_refused(tmp_path):
    guarded = deployer.guarded_paths(_instance(build_context="app"))
    tarball = tmp_path / "source.tar.gz"
    # GNU tar and bsdtar put absolute names in different places; tar skips '..' names.
    for name in ("top/x/../app", "/top/app", "//top/./app", "../app"):
        with pytest.raises(deployer.DeployError, match=f"unsafe path '{re.escape(name)}'"):
            deployer.check_source_archive(_one_link(tarball, name), guarded)
    tarball.write_bytes(b"not a tarball")
    with pytest.raises(deployer.DeployError, match="could not be read"):
        deployer.check_source_archive(tarball, guarded)


async def test_deploy_of_a_linked_build_context_is_refused_before_reaching_the_host():
    dep_id = await _seed({})
    async with get_sessionmaker()() as db:
        await db.execute(text("UPDATE instances SET build_context = 'app'"))
        await db.commit()

    class LinkedContext(FakeGitHub):
        async def download_tarball(self, repo_id, sha, dest):
            return write_source_archive(dest, {"Dockerfile": "FROM alpine\nCOPY . /s\nRUN cat /s/.env\n"},
                                        symlinks={"app": ESCAPE})

    connected: list[str] = []
    remote = FakeRemote()

    @asynccontextmanager
    async def connect(target):
        connected.append(target.hostname)
        yield remote

    await deployer.run_deployment(dep_id, connect=connect, github=LinkedContext)
    dep = await _deployment(dep_id)
    assert dep.status == "failed"
    assert dep.error == "The build context 'app' is a symbolic link in the repository; refusing to deploy"
    assert dep.instance.status == "failed" and connected == [] and remote.commands == [] and remote.files == {}


async def test_deploy_with_a_regular_build_context_still_works():
    dep_id = await _seed({})
    async with get_sessionmaker()() as db:
        await db.execute(text("UPDATE instances SET build_context = 'app', dockerfile_path = 'app/Dockerfile'"))
        await db.commit()

    class Monorepo(FakeGitHub):
        async def download_tarball(self, repo_id, sha, dest):
            return write_source_archive(dest, {"app/Dockerfile": "FROM node:22\n"}, dirs=("app",),
                                        symlinks={"web": "app"})

    remote = FakeRemote()
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=Monorepo)
    assert (await _deployment(dep_id)).status == "succeeded"
    assert any("-f app/Dockerfile" in c and " app && docker image inspect" in c for c in remote.commands)
