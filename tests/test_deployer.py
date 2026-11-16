"""Deployment pipeline tests with fake GitHub and SSH backends."""

from __future__ import annotations

import io
import tarfile
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Host, Instance, Repository
from slipway.services import deployer, ssh
from slipway.services.github import CommitInfo
from tests.conftest import make_user

SHA = "a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0"
ARCHIVE_TOP = "acme-web-a1b2c3d"


def write_source_archive(dest: Path, files: dict[str, str] | None = None, *, dirs: tuple[str, ...] = (),
                         symlinks: dict[str, str] | None = None, hardlinks: dict[str, str] | None = None) -> int:
    """A GitHub-style source tarball: every member below one top-level directory. Returns its size."""
    files = {"Dockerfile": "FROM node:22\n"} if files is None else files
    with tarfile.open(dest, "w:gz") as tar:
        tar.addfile(_member(ARCHIVE_TOP, tarfile.DIRTYPE))
        for name in dirs:
            tar.addfile(_member(f"{ARCHIVE_TOP}/{name}", tarfile.DIRTYPE))
        for name, content in files.items():
            data = content.encode()
            info = _member(f"{ARCHIVE_TOP}/{name}", tarfile.REGTYPE)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for kind, links in ((tarfile.SYMTYPE, symlinks or {}), (tarfile.LNKTYPE, hardlinks or {})):
            for name, target in links.items():
                tar.addfile(_member(f"{ARCHIVE_TOP}/{name}", kind, target))
    return dest.stat().st_size


def _member(name: str, kind: bytes, linkname: str = "") -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type, info.linkname = kind, linkname
    info.mode = 0o755 if kind == tarfile.DIRTYPE else 0o644
    return info


def test_validation_helpers():
    assert deployer.slugify("Slipway Web (prod)") == "slipway-web-prod"
    with pytest.raises(ValueError):
        deployer.slugify("!!!")
    assert deployer.clean_relative_path("./docker/Dockerfile") == "docker/Dockerfile"
    assert deployer.clean_relative_path(".", allow_dot=True) == "."
    for bad in ("../etc/passwd", "/etc/passwd", "a/../../b", "x; rm -rf /", "$(id)"):
        with pytest.raises(ValueError):
            deployer.clean_relative_path(bad)
    assert deployer.clean_deploy_root("/opt/slipway/") == "/opt/slipway"
    for bad in ("/", "relative", "/opt/../etc"):
        with pytest.raises(ValueError):
            deployer.clean_deploy_root(bad)
    with pytest.raises(ValueError):
        deployer.clean_env({"BAD-KEY": "x"})
    with pytest.raises(ValueError):
        deployer.clean_env({"KEY": "line1\nline2"})
    assert deployer.render_env({"B": "2", "A": "x y"}) == "A=x y\nB=2\n"


def _instance(**kw) -> Instance:
    host = Host(name="prod-01", hostname="10.0.0.1", port=22, username="deploy", deploy_root="/opt/slipway")
    repo = Repository(github_id=1, full_name="acme/web", owner="acme", name="web", html_url="https://github.com/acme/web")
    defaults = dict(
        id=uuid.UUID("00000000-0000-0000-0000-000000000001"), name="web", slug="web-prod", branch="main",
        build_source="dockerfile", dockerfile_path="Dockerfile", build_context=".", compose_file="docker-compose.yml",
        ports=[{"host": 8080, "container": 3000, "protocol": "tcp"}], volumes=[{"source": "/var/lib/web", "target": "/data"}],
        env={}, host=host, repository=repo,
    )
    defaults.update(kw)
    return Instance(**defaults)


def test_dockerfile_commands_are_quoted():
    inst = _instance(dockerfile_path="docker/Dockerfile prod", build_context="src")
    build, rm, run = deployer.build_commands(inst, "/opt/slipway/web-prod/releases/a1b2c3d4e5f6", SHA)
    assert "-f 'docker/Dockerfile prod'" in build
    assert build.endswith(" src && docker image inspect --format . slipway/web-prod:a1b2c3d4e5f6 >/dev/null")
    assert "-t slipway/web-prod:a1b2c3d4e5f6" in build
    assert rm.startswith("docker ps -aq --filter label=slipway.instance=00000000-0000-0000-0000-000000000001")
    assert "-p 8080:3000/tcp" in run and "-v /var/lib/web:/data" in run
    assert "--env-file /opt/slipway/web-prod/shared/.env" in run
    assert "--label slipway.instance=00000000-0000-0000-0000-000000000001" in run


def test_compose_commands():
    inst = _instance(build_source="compose", compose_file="compose.yaml")
    env_cmd, _, cmd = deployer.build_commands(inst, "/opt/slipway/web-prod/releases/x", SHA)
    compose = "docker compose -p slipway-web-prod --env-file /opt/slipway/web-prod/shared/.env -f compose.yaml"
    assert f"{compose} up -d --build" in cmd
    assert env_cmd.startswith("cd /opt/slipway/web-prod/releases/x &&")
    assert "ln -sfn /opt/slipway/web-prod/shared/.env .env" in env_cmd
    assert deployer.control_command(inst, "stop").endswith(f"{compose} stop")
    assert "rm -rf -- /opt/slipway/web-prod" in deployer.remove_dir_command(inst)
    with pytest.raises(ValueError):
        deployer.control_command(inst, "explode")


# ------------------------------------------------------------------- pipeline


class FakeGitHub:
    calls: list[str] = []
    archive: bytes = b""  # the last tarball handed out

    def __init__(self, token):
        self.token = token

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def get_repository(self, repo_id):
        FakeGitHub.calls.append(f"repo {repo_id}")
        return {"id": repo_id, "full_name": "acme/web", "owner": {"login": "acme"}, "name": "web",
                "html_url": "https://github.com/acme/web"}

    async def get_commit(self, repo_id, ref):
        FakeGitHub.calls.append(f"commit {repo_id}@{ref}")
        return CommitInfo(sha=SHA, message="feat: ship it", author="octocat", date=None)

    async def download_tarball(self, repo_id, sha, dest: Path):
        FakeGitHub.calls.append(f"tarball {repo_id}@{sha}")
        size = write_source_archive(dest)
        FakeGitHub.archive = dest.read_bytes()
        return size


class FakeRemote:
    """``responses`` maps a command substring to its output (a callable gets the remote and the command).

    ``docker compose config`` prints a compose file with no services unless a response says otherwise.
    """

    def __init__(self, fail_on: str | None = None, responses: dict | None = None):
        self.commands: list[str] = []
        self.files: dict[str, str | bytes] = {}
        self.fail_on = fail_on
        self.responses = responses or {}

    async def run(self, command, *, check=True, on_line=None, timeout=None):
        self.commands.append(command)
        if on_line and "docker build" in command:
            await on_line("Step 1/3 : FROM node:22")
        if self.fail_on and self.fail_on in command:
            raise ssh.CommandFailed(command, 1, "build exploded")
        for needle, out in self.responses.items():
            if needle in command:
                return 0, out(self, command) if callable(out) else out
        if " config --format json" in command:
            return 0, '{"services": {}}'
        return 0, ""

    async def put(self, local, remote):
        self.files[remote] = Path(local).read_bytes()

    async def write_text(self, remote, content, mode=0o600):
        self.files[remote] = content


async def _seed(env: dict[str, str]) -> uuid.UUID:
    user = await make_user("admin@example.com")
    async with get_sessionmaker()() as db:
        host = Host(name="prod-01", hostname="10.0.0.1", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
        repo = Repository(github_id=42, full_name="acme/web", owner="acme", name="web",
                          html_url="https://github.com/acme/web", detected_config={})
        inst = Instance(name="web", slug="web-prod", branch="main", host=host, repository=repo, env=env,
                        ports=[{"host": 8080, "container": 3000, "protocol": "tcp"}], volumes=[])
        db.add(inst)
        await db.flush()
        dep = Deployment(instance_id=inst.id, branch="main", triggered_by_id=user.id, log="")
        db.add(dep)
        await db.commit()
        return dep.id


def _connect(remote: FakeRemote):
    @asynccontextmanager
    async def factory(target):
        assert target.hostname == "10.0.0.1"
        yield remote
    return factory


async def test_successful_deployment():
    dep_id = await _seed({"NODE_ENV": "production"})
    remote = FakeRemote()
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)

    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, dep_id)
        assert dep.status == "succeeded", dep.log
        assert dep.commit_sha == SHA and dep.commit_message == "feat: ship it"
        assert dep.instance.status == "running" and dep.instance.current_commit_sha == SHA
        assert "Step 1/3" in dep.log and "Deployment succeeded" in dep.log
    release = f"/opt/slipway/web-prod/releases/a1b2c3d4e5f6-{dep_id.hex[:8]}"
    assert remote.files["/opt/slipway/web-prod/shared/.env"] == "NODE_ENV=production\n"
    assert remote.files[f"/opt/slipway/web-prod/releases/.upload-{dep_id.hex}.tar.gz"] == FakeGitHub.archive
    assert any("docker build" in c for c in remote.commands)
    assert f"ln -sfn {release} /opt/slipway/web-prod/current" in remote.commands
    assert FakeGitHub.calls[-3:] == ["repo 42", "commit 42@main", f"tarball 42@{SHA}"]
    # The GitHub token never appears in anything sent to the host.
    assert not any("token" in c.lower() for c in remote.commands)


async def test_failed_deployment_records_error():
    dep_id = await _seed({})
    remote = FakeRemote(fail_on="docker build")
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, dep_id)
        assert dep.status == "failed" and "build exploded" in dep.error
        assert dep.instance.status == "failed"
        assert not any(c.startswith("docker run -d") for c in remote.commands)


async def test_recover_interrupted_marks_stale_deployments():
    dep_id = await _seed({})
    await deployer.runner.recover_interrupted()
    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, dep_id)
        assert dep.status == "failed" and "restart" in dep.error
