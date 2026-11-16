"""Changing a host's deploy root while instances are deployed on it moves their files."""

from __future__ import annotations

import os
import stat

import pytest
from sqlalchemy import update

from slipway.api.v1 import hosts as hosts_api
from slipway.db.session import get_sessionmaker
from slipway.models import Host, Instance
from slipway.services import deployer
from tests.test_deployer import _instance
from tests.test_review_deploy_hosts import _seed_repo
from tests.test_review_deploy_pipeline import LocalRemote, _local, fake_docker  # noqa: F401 (fixture)


def _layout(root, slug="web-prod"):
    """An instance directory as a deploy leaves it: two releases, shared files and Slipway's links."""
    base = root / slug
    for name in ("aaa", "bbb"):
        (base / "releases" / name / "docker").mkdir(parents=True)
        (base / "releases" / name / "docker" / "compose.yml").write_text("services: {}\n")
        os.symlink(f"{base}/shared/.env", base / "releases" / name / "docker" / ".env")
    (base / "shared").mkdir()
    (base / "shared" / ".env").write_text("SECRET=1\n")
    os.symlink(f"{base}/releases/bbb", base / "current")
    os.symlink("compose.yml", base / "releases" / "bbb" / "docker" / "relative-link")
    return base


def _on(root, **kw):
    host = Host(name="tower", hostname="10.0.0.1", port=22, username="root", deploy_root=str(root))
    return host, _instance(host=host, build_source="compose", compose_file="docker/compose.yml", **kw)


class _Saved:
    def __init__(self):
        self.calls = 0

    async def __call__(self):
        self.calls += 1


async def test_move_copies_relinks_and_removes_the_old_directory(tmp_path, fake_docker):  # noqa: F811
    env, _ = fake_docker
    old_root, new_root = tmp_path / "opt" / "slipway", tmp_path / "appdata" / "slipway"
    old = _layout(old_root)
    host, inst = _on(old_root)
    save = _Saved()
    notes = await deployer.move_deploy_root(host, [inst], str(new_root), save=save, connect=_local(LocalRemote(env)))

    new = new_root / "web-prod"
    assert notes == [] and save.calls == 1
    assert not old.exists() and not (new_root / ".web-prod.moving").exists()
    assert os.readlink(new / "current") == f"{new}/releases/bbb"
    for name in ("aaa", "bbb"):
        assert os.readlink(new / "releases" / name / "docker" / ".env") == f"{new}/shared/.env"
    assert os.readlink(new / "releases" / "bbb" / "docker" / "relative-link") == "compose.yml"
    assert (new / "current" / "docker" / ".env").read_text() == "SECRET=1\n"


async def test_move_keeps_an_old_directory_a_container_still_mounts(tmp_path, fake_docker):  # noqa: F811
    env, _ = fake_docker
    old_root, new_root = tmp_path / "opt", tmp_path / "srv"
    old = _layout(old_root)
    host, inst = _on(old_root)
    mounted = {**env, "FAKE_PS": "0123456789ab", "FAKE_OWNER": f"{old}/releases/bbb/docker/data"}
    notes = await deployer.move_deploy_root(host, [inst], str(new_root), save=_Saved(), connect=_local(LocalRemote(mounted)))
    assert old.exists() and (new_root / "web-prod" / "current").is_symlink()
    assert len(notes) == 1 and f"Kept {old}" in notes[0] and "Redeploy web" in notes[0]

    # Docker can't say: keep it too.
    old2 = _layout(old_root, "api")
    host, inst = _on(old_root, slug="api", name="api")
    notes = await deployer.move_deploy_root(
        host, [inst], str(new_root), save=_Saved(), connect=_local(LocalRemote({**env, "FAKE_PS_FAILS": "1"}))
    )
    assert old2.exists() and "could not say" in notes[0]


async def test_move_with_nothing_on_the_host_only_saves(tmp_path, fake_docker):  # noqa: F811
    """Unraid clears /opt when it restarts: there is nothing to copy, the new root is still saved."""
    env, _ = fake_docker
    host, inst = _on(tmp_path / "opt")
    save = _Saved()
    notes = await deployer.move_deploy_root(host, [inst], str(tmp_path / "srv"), save=save, connect=_local(LocalRemote(env)))
    assert save.calls == 1 and "had no files to move" in notes[0]
    assert not (tmp_path / "srv" / "web-prod").exists()


async def test_move_refuses_when_the_target_is_taken(tmp_path, fake_docker):  # noqa: F811
    env, _ = fake_docker
    old = _layout(tmp_path / "opt")
    (tmp_path / "srv" / "web-prod").mkdir(parents=True)
    (tmp_path / "srv" / "web-prod" / "notes.txt").write_text("someone else's")
    host, inst = _on(tmp_path / "opt")
    save = _Saved()
    with pytest.raises(deployer.DeployError, match="already exists"):
        await deployer.move_deploy_root(host, [inst], str(tmp_path / "srv"), save=save, connect=_local(LocalRemote(env)))
    assert save.calls == 0 and (old / "current").is_symlink()
    assert (tmp_path / "srv" / "web-prod" / "notes.txt").exists()


async def test_move_into_an_empty_folder_made_in_advance(tmp_path, fake_docker):  # noqa: F811
    env, _ = fake_docker
    _layout(tmp_path / "opt")
    (tmp_path / "srv" / "web-prod").mkdir(parents=True)  # e.g. an Unraid share folder made first
    host, inst = _on(tmp_path / "opt")
    save = _Saved()
    await deployer.move_deploy_root(host, [inst], str(tmp_path / "srv"), save=save, connect=_local(LocalRemote(env)))
    assert save.calls == 1 and (tmp_path / "srv" / "web-prod" / "current").is_symlink()
    assert not (tmp_path / "opt" / "web-prod").exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads the locked file")
async def test_failed_copy_changes_nothing(tmp_path, fake_docker):  # noqa: F811
    env, _ = fake_docker
    old = _layout(tmp_path / "opt")
    _layout(tmp_path / "opt", "api")
    locked = old / "releases" / "aaa" / "secret"
    locked.write_text("x")
    locked.chmod(0)
    first, second = _on(tmp_path / "opt", slug="api", name="api")[1], _on(tmp_path / "opt")[1]
    save = _Saved()
    try:
        with pytest.raises(deployer.DeployError, match="Nothing was changed"):
            await deployer.move_deploy_root(
                first.host, [first, second], str(tmp_path / "srv"), save=save,
                connect=_local(LocalRemote({**env, "FAKE_RUN_FAILS": "1"})),
            )
    finally:
        locked.chmod(stat.S_IRUSR | stat.S_IWUSR)
    assert save.calls == 0
    assert sorted(os.listdir(tmp_path / "srv")) == []  # the copy of api went again
    assert (old / "current").is_symlink() and (tmp_path / "opt" / "api" / "current").is_symlink()


def test_move_refuses_overlapping_folders():
    inst = _instance()
    with pytest.raises(deployer.DeployError, match="overlaps"):
        deployer.check_move([inst], "/opt/slipway", "/opt/slipway/web-prod")
    claimed = _instance(claim={"working_dir": "/mnt/user/appdata/switchyard"})
    with pytest.raises(deployer.DeployError, match="claimed from"):
        deployer.check_move([claimed], "/opt/slipway", "/mnt/user/appdata/switchyard")
    deployer.check_move([claimed], "/opt/slipway", "/mnt/user/appdata/slipway")


def test_copy_falls_back_to_docker_for_root_owned_files():
    old, new = deployer.InstancePaths("/opt/slipway", "web-prod"), deployer.InstancePaths("/mnt/user/appdata/slipway", "web-prod")
    command = deployer.move_copy_command(old, new)
    assert "-v /opt/slipway:/o:ro -v /mnt/user/appdata/slipway:/n alpine:3.20" in command
    assert "cp -a /o/web-prod /n/.web-prod.moving" in command


# ------------------------------------------------------------------ API


async def _deployed_host(admin_client) -> tuple[str, str]:
    repo_id = await _seed_repo()
    host = (await admin_client.post("/api/v1/hosts", json={"name": "a", "hostname": "10.0.0.5", "username": "deploy"})).json()
    r = await admin_client.post("/api/v1/instances", json={"name": "web", "repository_id": repo_id, "host_id": host["id"], "deploy": False})
    assert r.status_code == 201, r.text
    async with get_sessionmaker()() as db:
        await db.execute(update(Instance).values(status="running"))
        await db.commit()
    return host["id"], f"/api/v1/hosts/{host['id']}"


async def test_patch_moves_deployed_instances(admin_client, monkeypatch):
    _, url = await _deployed_host(admin_client)
    calls = []

    async def fake_move(host, instances, new_root, *, save):
        calls.append((host.deploy_root, [i.name for i in instances], new_root))
        await save()
        return ["Kept /opt/slipway/web-prod: web's containers mount files from it."]

    monkeypatch.setattr(hosts_api.deployer, "move_deploy_root", fake_move)
    r = await admin_client.patch(url, json={"deploy_root": "/mnt/user/appdata/slipway/", "description": "tower"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["deploy_root"] == "/mnt/user/appdata/slipway" and body["description"] == "tower"
    assert "Kept /opt/slipway/web-prod" in body["warning"]
    assert calls == [("/opt/slipway", ["web"], "/mnt/user/appdata/slipway")]
    audit = (await admin_client.get("/api/v1/audit?action=host.update")).json()
    assert any("moved web from /opt/slipway to /mnt/user/appdata/slipway" in e["summary"] for e in audit)
    # Same root again: nothing to move.
    assert (await admin_client.patch(url, json={"deploy_root": "/mnt/user/appdata/slipway"})).status_code == 200
    assert len(calls) == 1


async def test_patch_keeps_the_old_root_when_the_move_fails(admin_client, monkeypatch):
    _, url = await _deployed_host(admin_client)

    async def failing_move(host, instances, new_root, *, save):
        raise deployer.DeployError("/srv/slipway/web already exists on a; remove it or choose another folder")

    monkeypatch.setattr(hosts_api.deployer, "move_deploy_root", failing_move)
    r = await admin_client.patch(url, json={"deploy_root": "/srv/slipway", "description": "x"})
    assert r.status_code == 400 and "already exists" in r.json()["detail"]
    after = (await admin_client.get(url)).json()
    assert after["deploy_root"] == "/opt/slipway" and after["description"] == ""


async def test_patch_moves_the_root_on_its_own(admin_client, monkeypatch):
    _, url = await _deployed_host(admin_client)

    async def unexpected(*a, **kw):
        raise AssertionError("no move expected")

    monkeypatch.setattr(hosts_api.deployer, "move_deploy_root", unexpected)
    r = await admin_client.patch(url, json={"deploy_root": "/srv/slipway", "hostname": "10.0.0.6"})
    assert r.status_code == 400 and "on its own" in r.json()["detail"]
    assert (await admin_client.get(url)).json()["hostname"] == "10.0.0.5"
    # Without deployed instances it is a plain setting.
    async with get_sessionmaker()() as db:
        await db.execute(update(Instance).values(status="created"))
        await db.commit()
    r = await admin_client.patch(url, json={"deploy_root": "/srv/slipway", "hostname": "10.0.0.6"})
    assert r.status_code == 200 and r.json()["deploy_root"] == "/srv/slipway"


async def test_patch_waits_for_deployments(admin_client, monkeypatch):
    _, url = await _deployed_host(admin_client)
    async with get_sessionmaker()() as db:
        await db.execute(update(Instance).values(status="deploying"))
        await db.commit()
    r = await admin_client.patch(url, json={"deploy_root": "/srv/slipway"})
    assert r.status_code == 409 and "in progress" in r.json()["detail"]
