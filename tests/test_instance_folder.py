"""An instance's own folder on its host: anywhere, owned by Slipway, movable, and safe on Unraid."""

from __future__ import annotations

import pytest
from sqlalchemy import select, update

from slipway.api.v1 import instances as instances_api
from slipway.db.session import get_sessionmaker
from slipway.models import Host, Instance
from slipway.services import deployer, hosts, ssh
from tests.test_deployer import FakeGitHub, FakeRemote, _connect, _instance, _seed
from tests.test_move_deploy_root import _layout, _Saved
from tests.test_review_deploy_hosts import _seed_repo
from tests.test_review_deploy_pipeline import LocalRemote, _local, _sh, fake_docker  # noqa: F401 (fixture)


@pytest.mark.parametrize("value", ["/mnt/user/appdata/shop", "/srv/apps/shop", "/opt/slipway/web", "/mnt/disk1/apps/x/"])
def test_folders_of_their_own_are_accepted(value):
    assert deployer.clean_instance_dir(value) == value.rstrip("/")


@pytest.mark.parametrize("value", [
    "/", "/mnt", "/mnt/user", "/mnt/user/", "/mnt/user/appdata", "/mnt/disk1", "/mnt/cache", "/opt", "/etc/shop",
    "/boot/config/x", "/usr/local/app", "/var/lib/docker/volumes/x", "relative/path", "/mnt/user/../etc", "/a b",
])
def test_system_folders_and_roots_are_refused(value):
    with pytest.raises(ValueError):
        deployer.clean_instance_dir(value)


def test_folder_defaults_to_the_deploy_root_and_can_be_anywhere():
    inst = _instance()
    assert deployer.instance_dir(inst) == "/opt/slipway/web-prod"
    inst.deploy_dir = "/mnt/user/appdata/shop"
    paths = deployer.paths_for(inst)
    assert (paths.base, paths.root, paths.slug) == ("/mnt/user/appdata/shop", "/mnt/user/appdata", "shop")
    assert paths.env_file == "/mnt/user/appdata/shop/shared/.env"


def test_ram_backed_only_on_unraid():
    unraid = Host(name="t", hostname="x", username="root", deploy_root="/opt/slipway", os_info="Unraid 6.12.10")
    other = Host(name="u", hostname="x", username="root", deploy_root="/opt/slipway", os_info="Ubuntu 24.04")
    assert deployer.ram_backed(unraid, "/opt/slipway/web") and not deployer.ram_backed(other, "/opt/slipway/web")
    assert not deployer.ram_backed(unraid, "/mnt/user/appdata/web") and not deployer.ram_backed(unraid, "/boot/x")


# ------------------------------------------------------------------- on the host


def _take(inst, env):
    return _sh(deployer.take_dir_command(inst), env)


def test_taking_a_folder(tmp_path, fake_docker):  # noqa: F811
    env, _ = fake_docker
    inst = _instance(deploy_dir=str(tmp_path / "apps" / "shop"))
    base = tmp_path / "apps" / "shop"
    assert _take(inst, env).returncode == 0  # created
    assert (base / ".slipway-instance").read_text().strip() == str(inst.id)
    assert _take(inst, env).returncode == 0  # already this instance's
    # Someone else's files: refused, nothing written.
    other = tmp_path / "theirs"
    other.mkdir()
    (other / "photos").mkdir()
    inst2 = _instance(deploy_dir=str(other))
    r = _take(inst2, env)
    assert r.returncode == 1 and "slipway-dir: other photos" in r.stdout
    assert not (other / ".slipway-instance").exists()
    assert "already holds files that are not Slipway's (photos)" in str(deployer.take_dir_error(inst2, r.stdout))
    # Another instance's folder: refused.
    inst3 = _instance(id=__import__("uuid").uuid4(), deploy_dir=str(base))
    r = _take(inst3, env)
    assert r.returncode == 1 and "belongs to another Slipway instance" in str(deployer.take_dir_error(inst3, r.stdout))


def test_a_folder_from_before_the_marker_is_accepted(tmp_path, fake_docker):  # noqa: F811
    env, _ = fake_docker
    base = _layout(tmp_path / "opt")  # releases, shared, current; no marker
    inst = _instance(deploy_dir=str(base))
    assert _take(inst, env).returncode == 0 and (base / ".slipway-instance").exists()


def test_removing_keeps_files_slipway_did_not_put_there(tmp_path, fake_docker):  # noqa: F811
    env, _ = fake_docker
    base = _layout(tmp_path / "opt")
    (base / ".slipway-instance").write_text("x\n")
    (base / "backup.tar").write_text("mine")
    r = _sh(deployer._remove_base_command(deployer.InstancePaths.of(str(base))), env)
    assert r.returncode == 1 and deployer.left_behind(r.stdout) == "backup.tar"
    assert sorted(p.name for p in base.iterdir()) == ["backup.tar"]
    (base / "backup.tar").unlink()
    r = _sh(deployer._remove_base_command(deployer.InstancePaths.of(str(base))), env)
    assert r.returncode == 0 and not base.exists()
    # Nothing there at all: fine.
    assert _sh(deployer._remove_base_command(deployer.InstancePaths.of(str(base))), env).returncode == 0


async def test_destroy_reports_kept_files(tmp_path, fake_docker):  # noqa: F811
    env, _ = fake_docker
    base = _layout(tmp_path / "opt")
    (base / "notes.txt").write_text("keep me")
    inst = _instance(deploy_dir=str(base))
    warning = await deployer.destroy(inst, connect=_local(LocalRemote(env)))
    assert warning == f"Kept {base} on prod-01: it also holds files Slipway did not put there (notes.txt)"
    assert (base / "notes.txt").exists() and not (base / "releases").exists()


async def test_moving_one_instance(tmp_path, fake_docker):  # noqa: F811
    env, _ = fake_docker
    old = _layout(tmp_path / "opt")
    host = Host(name="tower", hostname="10.0.0.1", port=22, username="root", deploy_root=str(tmp_path / "opt"))
    inst = _instance(host=host, build_source="compose", compose_file="docker/compose.yml")
    new = tmp_path / "user" / "appdata" / "shop"
    save = _Saved()
    notes = await deployer.move_instance_dir(inst, str(new), save=save, connect=_local(LocalRemote(env)))
    assert notes == [] and save.calls == 1 and not old.exists()
    assert (new / "current").resolve() == (new / "releases" / "bbb").resolve()
    assert (new / "releases" / "aaa" / "docker" / ".env").resolve() == (new / "shared" / ".env").resolve()
    with pytest.raises(deployer.DeployError, match="system folder"):
        await deployer.move_instance_dir(inst, "/mnt/user", save=save, connect=_local(LocalRemote(env)))


# ----------------------------------------------------------------- deployments


async def test_deploy_takes_the_folder_and_warns_on_unraid():
    dep_id = await _seed({})
    async with get_sessionmaker()() as db:
        await db.execute(update(Host).values(os_info="Unraid 6.12.10"))
        await db.commit()
    remote = FakeRemote()
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    async with get_sessionmaker()() as db:
        from slipway.models import Deployment
        dep = await db.get(Deployment, dep_id)
    assert dep.status == "succeeded", dep.log
    assert any(".slipway-instance" in c for c in remote.commands)
    assert "runs Unraid, which clears /opt/slipway/web-prod when it restarts" in dep.log


async def test_deploy_stops_on_a_folder_with_other_files():
    dep_id = await _seed({})
    remote = FakeRemote()
    remote.run_original = remote.run

    async def run(command, *, check=True, on_line=None, timeout=None):
        if ".slipway-instance" in command and "mkdir -p --" in command:
            remote.commands.append(command)
            return 1, "slipway-dir: other photos "
        return await remote.run_original(command, check=check, on_line=on_line, timeout=timeout)

    remote.run = run
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    async with get_sessionmaker()() as db:
        from slipway.models import Deployment
        dep = await db.get(Deployment, dep_id)
    assert dep.status == "failed" and "already holds files that are not Slipway's (photos)" in dep.error
    assert not any("docker build" in c for c in remote.commands)


# ------------------------------------------------------------------------- API


async def _host_and_repo(admin_client):
    repo_id = await _seed_repo()
    host = (await admin_client.post("/api/v1/hosts", json={"name": "tower", "hostname": "10.0.0.5", "username": "root"})).json()
    return host, repo_id


async def test_api_folder_rules(admin_client):
    host, repo_id = await _host_and_repo(admin_client)
    base = {"repository_id": repo_id, "host_id": host["id"], "deploy": False}
    r = await admin_client.post("/api/v1/instances", json={**base, "name": "shop", "deploy_dir": "/mnt/user/appdata/shop/"})
    assert r.status_code == 201, r.text
    shop = r.json()
    assert shop["deploy_dir"] == "/mnt/user/appdata/shop" and shop["folder"] == "/mnt/user/appdata/shop"
    r = await admin_client.post("/api/v1/instances", json={**base, "name": "web"})
    assert r.json()["folder"] == "/opt/slipway/web" and r.json()["deploy_dir"] is None
    for bad in ("/mnt/user", "/etc/web2", "web2"):
        r = await admin_client.post("/api/v1/instances", json={**base, "name": "web2", "deploy_dir": bad})
        assert r.status_code == 422, bad
    r = await admin_client.post("/api/v1/instances", json={**base, "name": "web2", "deploy_dir": "/mnt/user/appdata/shop/data"})
    assert r.status_code == 409 and "the folder of instance shop" in r.text
    # Not deployed yet: the folder just changes.
    r = await admin_client.patch(f"/api/v1/instances/{shop['id']}", json={"deploy_dir": "/srv/shop"})
    assert r.status_code == 200 and r.json()["folder"] == "/srv/shop"
    r = await admin_client.patch(f"/api/v1/instances/{shop['id']}", json={"deploy_dir": ""})
    assert r.status_code == 200 and r.json()["folder"] == "/opt/slipway/shop"


async def test_api_moves_a_deployed_instance(admin_client, monkeypatch):
    host, repo_id = await _host_and_repo(admin_client)
    r = await admin_client.post("/api/v1/instances", json={"repository_id": repo_id, "host_id": host["id"], "deploy": False,
                                                           "name": "shop"})
    shop = r.json()
    async with get_sessionmaker()() as db:
        await db.execute(update(Instance).values(status="running"))
        await db.commit()
    calls = []

    async def fake_move(instance, new_dir, *, save):
        calls.append((deployer.instance_dir(instance), new_dir))
        await save()
        return []

    monkeypatch.setattr(instances_api.deployer, "move_instance_dir", fake_move)
    r = await admin_client.patch(f"/api/v1/instances/{shop['id']}", json={"deploy_dir": "/mnt/user/appdata/shop", "name": "Shop"})
    assert r.status_code == 200, r.text
    assert calls == [("/opt/slipway/shop", "/mnt/user/appdata/shop")]
    assert r.json()["folder"] == "/mnt/user/appdata/shop" and r.json()["name"] == "Shop"
    audit = (await admin_client.get("/api/v1/audit?action=instance.move")).json()
    assert "from /opt/slipway/shop to /mnt/user/appdata/shop" in audit[0]["summary"]

    async def failing(instance, new_dir, *, save):
        raise deployer.DeployError("/srv/x already exists on tower; remove it or choose another folder")

    monkeypatch.setattr(instances_api.deployer, "move_instance_dir", failing)
    r = await admin_client.patch(f"/api/v1/instances/{shop['id']}", json={"deploy_dir": "/srv/x"})
    assert r.status_code == 400 and (await admin_client.get(f"/api/v1/instances/{shop['id']}")).json()["folder"] == "/mnt/user/appdata/shop"
    # The host's deploy root moving leaves an instance with its own folder where it is.
    from slipway.api.v1 import hosts as hosts_api

    async def root_move(host_, instances, new_root, *, save):
        assert instances == []
        await save()
        return []

    monkeypatch.setattr(hosts_api.deployer, "move_deploy_root", root_move)
    r = await admin_client.patch(f"/api/v1/hosts/{host['id']}", json={"deploy_root": "/mnt/user/appdata"})
    assert r.status_code == 200 and (await admin_client.get(f"/api/v1/instances/{shop['id']}")).json()["folder"] == "/mnt/user/appdata/shop"


# ---------------------------------------------------------------------- Unraid


async def _check_with(monkeypatch, os_info: str, **host_fields) -> Host:
    async def probe(target):
        return ssh.ProbeResult(host_key="ssh-ed25519 AAAA", fingerprint="SHA256:x", os_info=os_info, cpus=4,
                               cpu_percent=1.0, mem_total_mb=8000, mem_percent=10.0, docker_version="27.0",
                               docker_error=None, containers_running=0)
    monkeypatch.setattr(hosts.ssh, "probe", probe)
    async with get_sessionmaker()() as db:
        host = Host(name=f"tower-{__import__('uuid').uuid4().hex[:6]}", hostname="10.0.0.9", username="root",
                    metrics={}, **host_fields)
        db.add(host)
        await db.commit()
        await hosts.check_host(db, host)
        return await db.scalar(select(Host).where(Host.id == host.id))


async def test_unraid_gets_a_deploy_root_that_survives_restarts(monkeypatch):
    host = await _check_with(monkeypatch, "Unraid 6.12.10")
    assert host.deploy_root == "/mnt/user/appdata"


async def test_a_chosen_root_and_other_systems_are_left_alone(monkeypatch):
    assert (await _check_with(monkeypatch, "Unraid 6.12.10", deploy_root="/srv/apps")).deploy_root == "/srv/apps"
    assert (await _check_with(monkeypatch, "Ubuntu 24.04")).deploy_root == "/opt/slipway"
