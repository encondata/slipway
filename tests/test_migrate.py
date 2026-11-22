"""Migrating an instance to another host: the plan, the run, undoing a failed one, the old copy."""

from __future__ import annotations

import asyncio
import shlex
import uuid
from contextlib import asynccontextmanager

import asyncssh
import pytest

from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Host, Instance, Repository
from slipway.services import deployer, migrate, ssh
from tests.conftest import login, make_user
from tests.test_deployer import SHA, FakeGitHub, FakeRemote

MOUNTS = (
    "volume\tslipway-web-prod_data\t/var/lib/docker/volumes/slipway-web-prod_data/_data\n"
    f"volume\t{'ab' * 32}\t/var/lib/docker/volumes/{'ab' * 32}/_data\n"
    "bind\t\t/srv/web/uploads\n"
    "bind\t\t/var/run/docker.sock\n"
    "bind\t\t/opt/slipway/web-prod/shared/config\n"
    "bind\t\t/opt/slipway/web-prod/releases/aaa/data\n"
)
VOLUMES = 'slipway-web-prod_data\tlocal\tnull\t{"com.docker.compose.project":"slipway-web-prod"}\n'


class Remote(FakeRemote):
    """A FakeRemote that can also stream to another one (``pipe_fails``: a read command substring that fails)."""

    def __init__(self, *, pipe_fails: str | None = None, **kw):
        super().__init__(**kw)
        self.pipe_fails = pipe_fails

    async def pipe_to(self, target, read_command, write_command, *, on_progress=None, idle_timeout=None):
        self.commands.append(f"PIPE {read_command}")
        target.commands.append(f"PIPED {write_command}")
        if self.pipe_fails and self.pipe_fails in read_command:
            raise ssh.CommandFailed(read_command, 2, "tar: read error")
        return 4096


def source_remote(**kw) -> Remote:
    responses = {
        "range .Mounts": MOUNTS,
        "docker volume inspect -f '{{.Name}}": VOLUMES,
        "elif [ -f /m/$i ]": "0 dir\n1 dir\n",
        "du -sk": "folder 12\n0 2048\n1 100\n",
        **kw.pop("responses", {}),
    }
    return Remote(responses=responses, **kw)


def _connect(remotes: dict[str, Remote]):
    @asynccontextmanager
    async def factory(target):
        yield remotes[target.hostname]
    return factory


async def _seed(*, status="running", migration_extra=None, **inst_kw):
    user = await make_user("admin@example.com")
    async with get_sessionmaker()() as db:
        src = Host(name="old", hostname="10.0.0.1", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
        dst = Host(name="new", hostname="10.0.0.2", username="deploy", host_key="ssh-ed25519 BBBB", metrics={},
                   deploy_root="/srv/slipway")
        repo = Repository(github_id=42, full_name="acme/web", owner="acme", name="web",
                          html_url="https://github.com/acme/web", detected_config={})
        fields = dict(name="web", slug="web-prod", branch="main", host=src, repository=repo, env={"A": "1"},
                      ports=[{"host": 8080, "container": 3000, "protocol": "tcp"}], volumes=[], status=status,
                      current_commit_sha=SHA)
        fields.update(inst_kw)
        inst = Instance(**fields)
        db.add_all([inst, dst])
        await db.flush()
        migration = {"source_host_id": str(src.id), "source_host": "old", "target_host_id": str(dst.id),
                     "target_host": "new", "target_dir": None, "skip": [], **(migration_extra or {})}
        dep = Deployment(instance_id=inst.id, branch="main", triggered_by_id=user.id, log="", kind="migrate",
                         options={"migration": migration}, steps=deployer.migrate_steps(inst))
        db.add(dep)
        await db.commit()
        return dep.id, inst.id, src.id, dst.id


async def _get(model, ident):
    async with get_sessionmaker()() as db:
        return await db.get(model, ident)


def _index(commands: list[str], needle: str) -> int:
    return next(i for i, c in enumerate(commands) if needle in c)


# ---------------------------------------------------------------------------- plan


async def test_plan_sorts_what_to_copy_from_what_to_leave():
    _, inst_id, _, dst_id = await _seed()
    src, dst = source_remote(), Remote(responses={"docker version --format .": "bind /srv/web/uploads\n"})
    inst, target = await _get(Instance, inst_id), await _get(Host, dst_id)
    plan = await migrate.build_plan(inst, target, None, src, dst)

    by_id = {i.id: i for i in plan.items}
    assert plan.source_dir == "/opt/slipway/web-prod" and plan.target_dir == "/srv/slipway/web-prod"
    assert by_id["folder"].copy and by_id["folder"].size_kb == 12
    vol = by_id["volume:slipway-web-prod_data"]
    assert vol.copy and vol.size_kb == 2048 and vol.labels == {"com.docker.compose.project": "slipway-web-prod"}
    assert not by_id[f"volume:{'ab' * 32}"].copy and "Anonymous" in by_id[f"volume:{'ab' * 32}"].note
    uploads = by_id["bind:/srv/web/uploads"]
    assert uploads.copy and uploads.size_kb == 100 and "already exists on new" in uploads.conflict
    assert not by_id["bind:/var/run/docker.sock"].copy
    assert "copied with it" in by_id["bind:/opt/slipway/web-prod/shared/config"].note
    assert "release" in by_id["bind:/opt/slipway/web-prod/releases/aaa/data"].note
    # The folder moves, so the mount by path into it needs updating.
    assert any("/opt/slipway/web-prod/shared/config" in n for n in plan.notes)
    # The conflict blocks until it is unticked.
    assert plan.blocking(set()) and plan.blocking({"bind:/srv/web/uploads"}) == []
    assert plan.total_kb({"bind:/srv/web/uploads"}) == 12 + 2048
    # Source reads never create a missing path; nothing is written on either host while planning.
    probe = next(c for c in src.commands if "elif [ -f /m/$i ]" in c)
    assert "--mount type=bind,source=/srv/web/uploads,target=/m/1,readonly" in probe
    assert not any("docker volume create" in c or "mkdir" in c for c in src.commands + dst.commands)


async def test_plan_reports_a_taken_folder_and_missing_docker():
    _, inst_id, _, dst_id = await _seed()
    dst = Remote(responses={"docker version --format .": "nodocker\nfolder\nvolume slipway-web-prod_data\n"})
    plan = await migrate.build_plan(await _get(Instance, inst_id), await _get(Host, dst_id), None, source_remote(), dst)
    assert any("Docker is not running on new" in p for p in plan.problems)
    assert any("/srv/slipway/web-prod already exists on new" in p for p in plan.problems)
    assert "already exists on new" in next(i for i in plan.items if i.kind == "volume" and i.copy).conflict


def test_copy_commands_preserve_owners_and_never_create_on_the_source():
    source, target = deployer.InstancePaths("/opt/slipway", "web"), deployer.InstancePaths("/srv", "web")
    vol = migrate.Item("volume:data", "volume", "data")
    read, write = migrate.copy_commands(vol, source, target)
    assert "--mount type=volume,source=data,target=/v,readonly" in read and "tar --numeric-owner -C /v -cf - ." in read
    assert write.startswith("docker run --rm -i --network none -v data:/v ") and "-xpf -" in write
    f = migrate.Item("bind:/etc2/app.yml", "bind", "/srv/app/app.yml", is_file=True)
    read, write = migrate.copy_commands(f, source, target)
    assert "target=/s/app.yml,readonly" in read and read.endswith("-cf - app.yml")
    assert "-v /srv/app:/d " in write
    folder = migrate.Item("folder", "folder", "/opt/slipway/web/shared")
    assert migrate.copy_commands(folder, source, target) == ("cd /opt/slipway/web && tar -cf - shared", "tar -C /srv/web -xf -")
    assert migrate.size_text(2048) == "2.0 MiB" and migrate.size_text(None) == "size unknown"


# ----------------------------------------------------------------------------- run


async def test_migration_copies_deploys_the_same_commit_and_switches_hosts():
    dep_id, inst_id, src_id, dst_id = await _seed(port_overrides=[{"service": "web", "container": 80, "host": 8081, "auto": True}])
    src, dst = source_remote(), Remote()
    FakeGitHub.calls = []
    await deployer.run_deployment(dep_id, connect=_connect({"10.0.0.1": src, "10.0.0.2": dst}), github=FakeGitHub)

    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded", dep.log
    inst = await _get(Instance, inst_id)
    assert inst.host_id == dst_id and inst.status == "running" and inst.current_commit_sha == SHA
    assert inst.port_overrides == []  # the old host's moved ports are not carried over
    assert inst.migrated_from["host_id"] == str(src_id) and inst.migrated_from["dir"] == "/opt/slipway/web-prod"
    assert inst.migrated_from["volumes"] == ["slipway-web-prod_data"] and inst.migrated_from["binds"] == ["/srv/web/uploads"]
    assert f"commit 42@{SHA}" in FakeGitHub.calls  # the running commit, not the branch's tip

    # Stopped before the copy; never started again on the old host.
    stop = _index(src.commands, "docker stop")
    assert stop < _index(src.commands, "PIPE cd /opt/slipway/web-prod && tar -cf - shared")
    assert not any("docker start" in c for c in src.commands)
    # Folder taken, volume created with its labels, then filled; the build runs on the new host only.
    assert _index(dst.commands, "/srv/slipway/web-prod/.slipway-instance") < _index(dst.commands, "PIPED tar -C /srv/slipway/web-prod")
    create = next(c for c in dst.commands if "docker volume create" in c)
    assert "--label com.docker.compose.project=slipway-web-prod slipway-web-prod_data" in create
    assert _index(dst.commands, "docker volume create") < _index(dst.commands, "PIPED docker run --rm -i --network none -v slipway-web-prod_data:/v")
    assert any("PIPED docker run --rm -i --network none -v /srv/web/uploads:/d" in c for c in dst.commands)
    assert any("docker build" in c for c in dst.commands) and not any("docker build" in c for c in src.commands)
    assert "/srv/slipway/web-prod/shared/.env" in dst.files
    assert "Migration succeeded" in dep.log and "stays there until you remove it" in dep.log


async def test_unticked_items_are_not_copied():
    dep_id, inst_id, _, _ = await _seed(migration_extra={"skip": ["bind:/srv/web/uploads"]})
    src, dst = source_remote(), Remote(responses={"docker version --format .": "bind /srv/web/uploads\n"})
    await deployer.run_deployment(dep_id, connect=_connect({"10.0.0.1": src, "10.0.0.2": dst}), github=FakeGitHub)
    assert (await _get(Deployment, dep_id)).status == "succeeded"
    assert not any("/srv/web/uploads" in c for c in dst.commands if c.startswith("PIPED"))
    assert (await _get(Instance, inst_id)).migrated_from["binds"] == []


async def test_a_blocked_migration_changes_nothing():
    dep_id, inst_id, src_id, _ = await _seed()
    src, dst = source_remote(), Remote(responses={"docker version --format .": "folder\n"})
    await deployer.run_deployment(dep_id, connect=_connect({"10.0.0.1": src, "10.0.0.2": dst}), github=FakeGitHub)
    dep, inst = await _get(Deployment, dep_id), await _get(Instance, inst_id)
    assert dep.status == "failed" and dep.error.startswith("Nothing was changed")
    assert inst.host_id == src_id and inst.status == "running" and inst.migrated_from is None
    assert not any("docker stop" in c for c in src.commands)
    assert not any(c.startswith("PIPED") or "slipway-instance" in c for c in dst.commands)
    assert "Undoing" not in dep.log


async def test_a_half_failed_stop_starts_the_instance_again():
    dep_id, inst_id, _, _ = await _seed()
    src, dst = source_remote(fail_on="docker stop"), Remote()
    await deployer.run_deployment(dep_id, connect=_connect({"10.0.0.1": src, "10.0.0.2": dst}), github=FakeGitHub)
    dep, inst = await _get(Deployment, dep_id), await _get(Instance, inst_id)
    assert dep.status == "failed" and inst.status == "running"
    assert any("docker start" in c for c in src.commands)
    assert not any(c.startswith("PIPED") for c in dst.commands)


async def test_a_failed_deploy_is_undone_and_the_old_host_starts_again():
    dep_id, inst_id, src_id, _ = await _seed()
    src, dst = source_remote(), Remote(fail_on="docker build")
    await deployer.run_deployment(dep_id, connect=_connect({"10.0.0.1": src, "10.0.0.2": dst}), github=FakeGitHub)

    dep, inst = await _get(Deployment, dep_id), await _get(Instance, inst_id)
    assert dep.status == "failed" and "build exploded" in dep.error
    assert inst.host_id == src_id and inst.status == "running" and inst.migrated_from is None
    assert inst.ports == [{"host": 8080, "container": 3000, "protocol": "tcp"}]
    # Copies on the new host removed: containers, folder, the volume made, the bind path written.
    after = dst.commands[_index(dst.commands, "docker build"):]
    assert any("label=slipway.instance=" in c and "docker rm -f" in c for c in after)
    assert any("cd /srv/slipway/web-prod" in c and "rmdir" in c for c in after)
    assert "docker volume rm slipway-web-prod_data >/dev/null" in after
    assert any("rm -rf -- /r/uploads" in c and "-v /srv/web:/r" in c for c in after)
    # Started again where it was.
    assert _index(src.commands, "docker stop") < _index(src.commands, "docker start")
    assert "Started web on old again" in dep.log


async def test_a_failed_copy_is_undone_and_a_stopped_instance_stays_stopped():
    dep_id, inst_id, _, _ = await _seed(status="stopped")
    src, dst = source_remote(pipe_fails="source=slipway-web-prod_data"), Remote()
    await deployer.run_deployment(dep_id, connect=_connect({"10.0.0.1": src, "10.0.0.2": dst}), github=FakeGitHub)
    dep, inst = await _get(Deployment, dep_id), await _get(Instance, inst_id)
    assert dep.status == "failed" and "tar: read error" in dep.log
    assert inst.status == "stopped"
    assert not any("docker stop" in c or "docker start" in c for c in src.commands)
    assert "docker volume rm slipway-web-prod_data >/dev/null" in dst.commands
    assert not any("docker build" in c for c in dst.commands)


async def test_remove_old_copy_tears_down_the_old_host_and_keeps_outside_paths():
    _, inst_id, src_id, dst_id = await _seed()
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, inst_id)
        inst.host_id = dst_id
        inst.migrated_from = {"host_id": str(src_id), "host_name": "old", "dir": "/opt/slipway/web-prod",
                              "volumes": ["slipway-web-prod_data"], "binds": ["/srv/web/uploads"]}
        await db.commit()
    old = Remote()
    warning = await migrate.remove_old_copy(inst_id, connect=_connect({"10.0.0.1": old}))
    assert any("docker rm -f" in c and "label=slipway.instance=" in c for c in old.commands)
    assert any("cd /opt/slipway/web-prod" in c and "rmdir" in c for c in old.commands)
    assert "docker volume rm slipway-web-prod_data" in old.commands
    assert "Kept /srv/web/uploads on old" in warning


# ----------------------------------------------------------------------------- API


async def _api_client(client):
    await login(client, "admin@example.com")
    return client


async def test_api_refuses_what_cannot_migrate(client):
    dep_id, inst_id, src_id, dst_id = await _seed()
    async with get_sessionmaker()() as db:  # the seeded migration would answer 409 "in progress" first
        await db.delete(await db.get(Deployment, dep_id))
        await db.commit()
    await _api_client(client)
    r = await client.post(f"/api/v1/instances/{inst_id}/migrate", json={"host_id": str(src_id)})
    assert r.status_code == 400 and "already runs on old" in r.json()["detail"]
    r = await client.post(f"/api/v1/instances/{inst_id}/migrate", json={"host_id": str(uuid.uuid4())})
    assert r.status_code == 400 and r.json()["detail"] == "Unknown host"
    async with get_sessionmaker()() as db:
        (await db.get(Host, dst_id)).host_key = None
        await db.commit()
    r = await client.post(f"/api/v1/instances/{inst_id}/migrate/check", json={"host_id": str(dst_id)})
    assert r.status_code == 400 and "new has not been verified" in r.json()["detail"]
    async with get_sessionmaker()() as db:
        (await db.get(Host, dst_id)).host_key = "ssh-ed25519 BBBB"
        (await db.get(Instance, inst_id)).migrated_from = {"host_name": "older"}
        await db.commit()
    r = await client.post(f"/api/v1/instances/{inst_id}/migrate", json={"host_id": str(dst_id)})
    assert r.status_code == 409 and "still on older" in r.json()["detail"]


async def test_api_queues_a_migration(client, monkeypatch):
    dep_id, inst_id, _, dst_id = await _seed()
    async with get_sessionmaker()() as db:  # only the seeded migration's own row would block
        await db.delete(await db.get(Deployment, dep_id))
        db.add(Deployment(instance_id=inst_id, branch="main", log="", status="succeeded", commit_sha=SHA,
                          commit_message="Ship it"))
        await db.commit()
    submitted = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep, keys: submitted.append(dep))
    await _api_client(client)
    r = await client.post(f"/api/v1/instances/{inst_id}/migrate",
                          json={"host_id": str(dst_id), "deploy_dir": "/data/web", "skip": ["bind:/x", "bind:/x"]})
    assert r.status_code == 202, r.text
    body = r.json()
    migration = body["options"]["migration"]
    assert body["kind"] == "migrate" and migration["target_host"] == "new"
    assert migration["target_dir"] == "/data/web" and migration["skip"] == ["bind:/x"]
    assert submitted == [uuid.UUID(body["id"])]
    assert [s["key"] for s in body["steps"]][:3] == ["migrate_check", "migrate_stop", "migrate_copy"]
    assert body["commit_sha"] == SHA and body["commit_message"] == "Ship it"  # named like the deploy that put it live
    page = await client.get(f"/deployments/{body['id']}")
    assert page.status_code == 200 and "old → new" in page.text and "From old to new" in page.text


async def test_api_check_returns_the_plan(client, monkeypatch):
    dep_id, inst_id, _, dst_id = await _seed()
    async with get_sessionmaker()() as db:
        await db.delete(await db.get(Deployment, dep_id))
        await db.commit()
    remotes = {"10.0.0.1": source_remote(), "10.0.0.2": Remote()}
    monkeypatch.setattr(ssh, "open_session", _connect(remotes))
    await _api_client(client)
    r = await client.post(f"/api/v1/instances/{inst_id}/migrate/check", json={"host_id": str(dst_id)})
    assert r.status_code == 200, r.text
    plan = r.json()
    assert plan["target_dir"] == "/srv/slipway/web-prod" and plan["blocking"] == []
    assert {i["id"] for i in plan["items"] if i["copy"]} == {"folder", "volume:slipway-web-prod_data", "bind:/srv/web/uploads"}
    page = await client.get(f"/instances/{inst_id}")
    assert "migrate-dialog" in page.text and 'data-root="/srv/slipway"' in page.text


async def test_api_keeps_or_removes_the_old_copy(client, monkeypatch):
    dep_id, inst_id, src_id, _ = await _seed()
    async with get_sessionmaker()() as db:
        await db.delete(await db.get(Deployment, dep_id))
        (await db.get(Instance, inst_id)).migrated_from = {"host_id": str(src_id), "host_name": "old", "dir": "/x"}
        await db.commit()
    await _api_client(client)
    page = await client.get(f"/instances/{inst_id}")
    assert "A stopped copy is still on old" in page.text and "migrate-dialog" not in page.text

    calls = []

    async def fake_remove(instance_id, **kw):
        calls.append(instance_id)
        return "Kept /srv on old"

    monkeypatch.setattr(migrate, "remove_old_copy", fake_remove)
    r = await client.post(f"/api/v1/instances/{inst_id}/old-copy/remove")
    assert r.status_code == 200 and r.json()["warning"] == "Kept /srv on old" and calls == [inst_id]
    assert (await _get(Instance, inst_id)).migrated_from is None
    r = await client.post(f"/api/v1/instances/{inst_id}/old-copy/remove?purge=false")
    assert r.status_code == 400


# ------------------------------------------------------------- the real stream


async def _shell(process: asyncssh.SSHServerProcess) -> None:
    """Run the command for real, passing every byte both ways before reporting its exit status."""
    words = shlex.split(process.command or "")
    proc = await asyncio.create_subprocess_exec(
        *words[1:], stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

    async def feed() -> None:
        try:
            while data := await process.stdin.read(65536):
                proc.stdin.write(data)
                await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            proc.stdin.close()

    async def pump(src, dst) -> None:
        while data := await src.read(65536):
            dst.write(data)
            await dst.drain()

    feeder = asyncio.create_task(feed())
    await asyncio.gather(pump(proc.stdout, process.stdout), pump(proc.stderr, process.stderr))
    status = await proc.wait()
    feeder.cancel()
    process.exit(status)


class _Open(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return False  # no authentication: the test server runs commands for anyone


@pytest.fixture
async def shell_server():
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.create_server(_Open, "127.0.0.1", 0, server_host_keys=[host_key], process_factory=_shell,
                                          encoding=None)
    port = server.sockets[0].getsockname()[1]
    pinned = host_key.export_public_key("openssh").decode()
    yield ssh.SSHTarget(hostname="127.0.0.1", port=port, username="deploy", password="x", pinned_host_key=pinned)
    server.close()
    await server.wait_closed()


async def test_pipe_to_streams_between_two_sessions(shell_server, tmp_path):
    src_dir, dst_dir = tmp_path / "a", tmp_path / "b"
    (src_dir / "data").mkdir(parents=True)
    dst_dir.mkdir()
    (src_dir / "data" / "big.bin").write_bytes(bytes(range(256)) * 8192)  # 2 MiB, several chunks
    seen = []

    async def progress(n):
        seen.append(n)

    async with ssh.open_session(shell_server) as one, ssh.open_session(shell_server) as two:
        copied = await one.pipe_to(two, f"tar -C {src_dir} -cf - data", f"tar -C {dst_dir} -xf -", on_progress=progress)
        assert (dst_dir / "data" / "big.bin").read_bytes() == (src_dir / "data" / "big.bin").read_bytes()
        assert copied >= 2 * 1024 * 1024 and seen[-1] == copied and len(seen) > 1

        with pytest.raises(ssh.CommandFailed) as exc:
            await one.pipe_to(two, f"tar -C {tmp_path / 'missing'} -cf - .", f"tar -C {dst_dir} -xf -")
        assert "missing" in exc.value.command and exc.value.exit_status != 0

        with pytest.raises(ssh.CommandFailed) as exc:
            await one.pipe_to(two, f"tar -C {src_dir} -cf - data", "echo full >&2; exit 4")
        assert exc.value.exit_status == 4 and "full" in exc.value.output


# ------------------------------------------------------------- on main: steps, refusals, retry, restart


async def test_a_migration_runs_as_numbered_steps():
    dep_id, _, _, _ = await _seed()
    src, dst = source_remote(), Remote()
    await deployer.run_deployment(dep_id, connect=_connect({"10.0.0.1": src, "10.0.0.2": dst}), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded", dep.log
    status = {s["key"]: s["status"] for s in dep.steps}
    assert list(status) == ["migrate_check", "migrate_stop", "migrate_copy", "resolve", "source", "upload",
                            "settings", "ports", "build", "start", "finish", "migrate_switch", "proxy"]
    assert all(v == "succeeded" for k, v in status.items() if k != "proxy") and status["proxy"] == "skipped"
    assert "Step 1/13: Check both hosts" in dep.log and "(the commit the old host runs)" in dep.log


async def test_a_migration_of_a_stopped_instance_skips_the_stop():
    dep_id, _, _, _ = await _seed(status="stopped")
    src, dst = source_remote(), Remote()
    await deployer.run_deployment(dep_id, connect=_connect({"10.0.0.1": src, "10.0.0.2": dst}), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    stop = next(s for s in dep.steps if s["key"] == "migrate_stop")
    assert dep.status == "succeeded" and stop["status"] == "skipped" and "was not running on old" in stop["note"]


async def test_a_blocked_migration_fails_its_check_step():
    dep_id, _, _, _ = await _seed()
    src, dst = source_remote(), Remote(responses={"docker version --format .": "folder\n"})
    await deployer.run_deployment(dep_id, connect=_connect({"10.0.0.1": src, "10.0.0.2": dst}), github=FakeGitHub)
    status = {s["key"]: s["status"] for s in (await _get(Deployment, dep_id)).steps}
    assert status["migrate_check"] == "failed" and status["migrate_stop"] == "pending"


def test_refusal_names_what_cannot_move():
    ssh_host = Host(name="a", hostname="10.0.0.9", username="u", provider="ssh")
    droplet = Host(name="drop-1", hostname="10.0.0.8", username="u", provider="digitalocean")
    base = dict(name="web", slug="web", branch="main", build_source="compose", host=ssh_host)
    assert migrate.refusal(Instance(**base)) is None
    assert "slot of an environment" in migrate.refusal(Instance(**base, environment_id=uuid.uuid4()))
    assert "slipway.yml app" in migrate.refusal(Instance(**{**base, "build_source": "app"}))
    assert "drop-1 is a server a provider made" in migrate.refusal(Instance(**{**base, "host": droplet}))
    assert "Migrate moves to SSH hosts only" in migrate.refusal(Instance(**base), droplet)


async def test_api_and_page_refuse_an_app_with_the_reason(client):
    dep_id, inst_id, _, dst_id = await _seed(build_source="app")
    async with get_sessionmaker()() as db:
        await db.delete(await db.get(Deployment, dep_id))
        await db.commit()
    await _api_client(client)
    r = await client.post(f"/api/v1/instances/{inst_id}/migrate/check", json={"host_id": str(dst_id)})
    assert r.status_code == 409 and "slipway.yml app" in r.json()["detail"]
    page = await client.get(f"/instances/{inst_id}")
    assert "migrate-dialog" not in page.text
    assert 'disabled title="web is a slipway.yml app, whose data and backups Slipway keeps on its host' in page.text


async def test_a_migration_is_not_retried(client):
    dep_id, _, _, _ = await _seed()
    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, dep_id)
        dep.status = "failed"
        await db.commit()
    await _api_client(client)
    r = await client.post(f"/api/v1/deployments/{dep_id}/retry")
    assert r.status_code == 409 and "start a new one with Migrate" in r.json()["detail"]


async def test_a_restart_during_a_migration_says_where_the_instance_is():
    dep_id, inst_id, _, _ = await _seed()
    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, dep_id)
        dep.status, dep.started_at = "running", deployer.utcnow()
        (await db.get(Instance, inst_id)).status = "deploying"
        await db.commit()
    await deployer.runner.recover_interrupted()
    dep = await _get(Deployment, dep_id)
    assert dep.status == "failed"
    assert "during a migration. web still belongs to old, but it may be stopped there" in dep.error
    assert "Anything copied to new was left there" in dep.error
