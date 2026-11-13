"""Unmanaged containers: discovering them, claiming them, and deploying claimed instances safely."""

from __future__ import annotations

import json
import re
import uuid

import pytest
from sqlalchemy import select, update

from slipway.api.v1 import unmanaged
from slipway.db.base import utcnow
from slipway.db.session import get_sessionmaker
from slipway.models import AuditEvent, Deployment, Host, Instance, Repository, Role
from slipway.services import deployer, discovery, ports
from tests.conftest import login, make_user
from tests.test_deployer import FakeGitHub, FakeRemote, _connect, _instance, _seed

WEB = "a" * 64
DB_ = "b" * 64
SOLO = "c" * 64
MANAGED = "d" * 64
OURS = "e" * 64


def _container(cid, name, *, image="nginx", state="running", project=None, service=None, instance=None,
               working_dir=None, config_files=None, network_mode="bridge", ports_=None, mounts=None) -> str:
    data = {"id": cid, "name": "/" + name, "image": image, "state": state, "started_at": "2026-11-01T10:00:00Z",
            "network_mode": network_mode, "instance": instance, "project": project, "service": service,
            "working_dir": working_dir, "config_files": config_files}
    return "\n".join([
        "container " + json.dumps(data),
        f"ports {cid} " + json.dumps(ports_ or {}),
        f"mounts {cid} " + json.dumps(mounts or []),
    ])


def _volume(name, target):
    return {"Type": "volume", "Name": name, "Source": f"/var/lib/docker/volumes/{name}/_data", "Destination": target, "RW": True}


def _bind(source, target, rw=True):
    return {"Type": "bind", "Source": source, "Destination": target, "RW": rw}


DISCOVER_OUTPUT = "\n".join([
    _container(WEB, "shop-web-1", project="shop", service="web", working_dir="/home/me/shop",
               config_files="/home/me/shop/docker-compose.yml",
               ports_={"80/tcp": [{"HostIp": "", "HostPort": "8080"}]},
               mounts=[_bind("/home/me/shop/uploads", "/srv/uploads")]),
    _container(DB_, "shop-db-1", image="postgres:16", project="shop", service="db", working_dir="/home/me/shop",
               config_files="/home/me/shop/docker-compose.yml", state="exited",
               mounts=[_volume("shop_pgdata", "/var/lib/postgresql/data")]),
    _container(SOLO, "blog", image="ghost:5",
               ports_={"2368/tcp": [{"HostIp": "0.0.0.0", "HostPort": "2368"}, {"HostIp": "::", "HostPort": "2368"}],
                       "9000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "9000"}], "9100/tcp": [{"HostIp": "", "HostPort": ""}]},
               mounts=[_volume("ghost-content", "/var/lib/ghost/content"), _volume("f" * 64, "/cache"),
                       _bind("/etc/ghost", "/config", rw=False)]),
    _container(MANAGED, "slipway-web-prod", instance="00000000-0000-0000-0000-000000000001"),
    _container(OURS, "slipway-api-db-1", project="slipway-api", service="db"),
    "Error response from daemon: No such object: 0123",
    "permission denied while trying to connect to the Docker daemon socket",
])


# ------------------------------------------------------------------------ parsing


def test_parse_groups_unmanaged_containers():
    groups = discovery.parse(DISCOVER_OUTPUT)
    assert [(g.kind, g.name) for g in groups] == [("compose", "shop"), ("container", "blog")]
    shop, blog = groups
    assert shop.key == "compose:shop" and shop.project == "shop" and shop.state == "partial"
    assert [c.name for c in shop.containers] == ["shop-db-1", "shop-web-1"]  # by service
    assert shop.images == ["postgres:16", "nginx"]
    assert shop.working_dir == "/home/me/shop" and shop.compose_file == "docker-compose.yml"
    assert [(p.service, p.container, p.host) for p in shop.ports] == [("web", 80, 8080)]
    assert [(m.type, m.source, m.service) for m in shop.mounts] == [
        ("volume", "shop_pgdata", "db"), ("bind", "/home/me/shop/uploads", "web")]
    assert any("inside the project directory" in w and "/home/me/shop/uploads" in w for w in shop.warnings)

    assert blog.key == f"container:{SOLO}" and blog.container_id == SOLO and blog.state == "running"
    assert discovery.dockerfile_ports(blog) == [
        {"host": 2368, "container": 2368, "protocol": "tcp"}, {"host": 9000, "container": 9000, "protocol": "tcp"}]
    assert discovery.dockerfile_volumes(blog) == [
        {"source": "ghost-content", "target": "/var/lib/ghost/content"}, {"source": "f" * 64, "target": "/cache"},
        {"source": "/etc/ghost", "target": "/config"}]
    text = "\n".join(blog.warnings)
    assert "9100/tcp has no fixed host port" in text
    assert "published only on 127.0.0.1" in text
    assert "anonymous volume at /cache is kept by its id" in text
    assert "/etc/ghost is mounted read-only" in text


def test_parse_skips_claimed_groups_and_reports_unreadable_lines():
    groups = discovery.parse(DISCOVER_OUTPUT, claimed_projects={"shop"}, claimed_containers={SOLO})
    assert groups == []
    # A ports line cut at the SSH line limit no longer parses: the container stays, with a warning.
    cut = _container(SOLO, "blog").replace(f"ports {SOLO} {{}}", f"ports {SOLO} {{\"80/tcp\": [{{\"Host")
    (blog,) = discovery.parse(cut)
    assert blog.ports == [] and blog.warnings == ["Could not read the ports of blog"]


def test_compose_file_suggestion_and_published_rows():
    out = _container(WEB, "x-web-1", project="x", service="web", working_dir="/srv/x",
                     config_files="/srv/x/deploy/compose.prod.yml,/srv/x/compose.override.yml",
                     ports_={"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]})
    (g,) = discovery.parse(out)
    assert g.compose_file == "deploy/compose.prod.yml"
    assert discovery.published_rows(g) == [
        {"service": "web", "container": 80, "protocol": "tcp", "host": 8080, "host_ip": "127.0.0.1"}]
    (bad,) = discovery.parse(_container(WEB, "y", project="Bad Name", service="web"))
    assert "cannot be claimed" in bad.warnings[0]


def test_env_import_leaves_out_the_image_variables_and_conflicts():
    out = "\n".join([
        f"env {WEB} " + json.dumps(["PATH=/usr/bin", "SECRET=s3", "MODE=a"]) + " " + json.dumps(["PATH=/usr/bin"]),
        f"env {DB_} " + json.dumps(["SECRET=s3", "MODE=b", "bad-name=x"]) + " null",
        f"env {SOLO} " + json.dumps(["OTHER=1"]) + " []",  # not asked for
        "Error: No such image",
    ])
    env, skipped = discovery.parse_env(out, [WEB, DB_])
    assert env == {"SECRET": "s3"} and skipped == ["MODE", "bad-name"]
    command = discovery.env_command([WEB])
    assert WEB in command and "json .Config.Env" in command
    with pytest.raises(ValueError):
        discovery.env_command(["x; rm -rf /"])


def test_discover_command_is_posix_and_quoted():
    assert "docker ps -aq --no-trunc" in discovery.DISCOVER_COMMAND
    assert "xargs docker container inspect --format '" in discovery.DISCOVER_COMMAND
    assert "Env" not in discovery.DISCOVER_COMMAND  # the listing never reads environment variables


# --------------------------------------------------- claimed compose project name


def _claimed_compose(**kw) -> Instance:
    return _instance(build_source="compose", compose_file="docker-compose.yml", compose_project_name="shop",
                     claim={"kind": "compose", "name": "shop", "working_dir": "/home/me/shop", "replaced": False}, **kw)


def test_claimed_compose_project_name_is_used_everywhere():
    inst = _claimed_compose()
    assert inst.compose_project == "shop"
    assert "-p shop " in deployer.build_commands(inst, "/opt/slipway/web-prod/releases/x", "a" * 40)[2]
    # On a Compose older than 2.24.4 moved ports come in a resolved file; the project name stays.
    resolved = deployer.build_commands(inst, "/opt/slipway/web-prod/releases/x", "a" * 40,
                                       resolved="/opt/slipway/web-prod/shared/compose.resolved.json")[2]
    assert "docker compose -p shop " in resolved and "--project-directory /opt/slipway/web-prod/releases/x " in resolved
    assert "label=com.docker.compose.project=shop" in deployer.status_command(inst)
    assert deployer.logs_command(inst).startswith("cd / && docker compose -p shop logs")  # no release yet
    assert deployer.control_command(inst, "restart") == "cd / && docker compose -p shop restart"
    assert "label=com.docker.compose.project=shop" in deployer.prune_command(inst, "/opt/slipway/web-prod/releases/x")
    assert "label=com.docker.compose.project=shop" in deployer.leftovers_command(inst)
    assert "label=com.docker.compose.project=shop" in deployer.release_users_command(inst)
    teardown = deployer.teardown_command(inst)
    assert "docker compose -p shop rm -f -s;" in teardown and " -v" not in teardown
    scan = "docker\t\tshop\tshop-web-1\t0.0.0.0:8080->80/tcp"
    found = ports.parse_scan(scan, instance_id=str(inst.id), compose_project=inst.compose_project)
    assert found.user(8080, "tcp") is None  # its own port

    inst.claim = {**inst.claim, "replaced": True}
    assert "cd /opt/slipway/web-prod/current &&" in deployer.logs_command(inst)
    # Without a claim the project is still slipway-<slug>, and its anonymous volumes go on destroy.
    plain = _instance(build_source="compose")
    assert plain.compose_project == "slipway-web-prod"
    assert "rm -f -s -v" in deployer.teardown_command(plain)


def test_claimed_container_commands_use_its_id():
    inst = _instance(claim={"kind": "container", "name": "blog", "container_id": SOLO, "container_name": "blog",
                            "replaced": False})
    assert inst.claimed_container == SOLO and inst.running_container_name == "blog"
    assert deployer.control_command(inst, "stop") == f"docker stop {SOLO}"
    assert deployer.logs_command(inst, 50) == f"docker logs --tail 50 --timestamps {SOLO} 2>&1"
    assert f"--filter id={SOLO}" in deployer.status_command(inst)
    assert f"docker ps -aq --filter id={SOLO}" in deployer.leftovers_command(inst)
    teardown = deployer.teardown_command(inst)
    assert f"docker rm -f {SOLO} >/dev/null" in teardown and " -v" not in teardown
    _, stop, run = deployer.build_commands(inst, "/opt/slipway/web-prod/releases/x", "a" * 40)
    assert stop.startswith(f"if docker container inspect {SOLO} >/dev/null 2>&1; then docker stop {SOLO}")
    assert run.startswith("docker run -d")
    inst.claim = {**inst.claim, "replaced": True}
    assert inst.claimed_container is None and deployer.control_command(inst, "stop").endswith("docker stop slipway-web-prod")


# ------------------------------------------------------------------- pipeline


async def _seed_claimed(**fields) -> object:
    dep_id = await _seed({"SECRET": "s"})
    async with get_sessionmaker()() as db:
        await db.execute(update(Instance).values(status="running", **fields))
        await db.commit()
    return dep_id


async def _get(model, id_):
    async with get_sessionmaker()() as db:
        return await db.get(model, id_)


async def _redeploy(inst_id) -> object:
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=inst_id, branch="main", log="")
        db.add(dep)
        await db.commit()
        return dep.id


def _no_volume_removal(commands: list[str], *ids: str) -> None:
    for c in commands:
        assert not re.search(r"\bdown\b[^;|&]*\s-v\b", c), c
        assert "volume rm" not in c and "volume prune" not in c and "system prune" not in c, c
        assert "--volumes" not in c, c
        assert not re.search(r"docker (compose -p \S+ )?rm -f( -s)? -v", c), c
        for cid in ids:
            assert f"-v {cid}" not in c, c


async def test_claimed_compose_project_keeps_its_name_across_redeploys():
    config = {"services": {"web": {"ports": [{"target": 80, "published": "8080", "protocol": "tcp"}]}}}
    remote = FakeRemote(responses={
        " config --format json": json.dumps(config),
        # The claimed project's own container holds 8080; another app holds 5432.
        "/proc/net": "docker\t\tshop\tshop-web-1\t0.0.0.0:8080->80/tcp\ndocker\t\tother\tother-db-1\t0.0.0.0:5432->5432/tcp",
    })
    dep_id = await _seed_claimed(
        build_source="compose", compose_file="docker-compose.yml", compose_project_name="shop", ports=[],
        claim={"kind": "compose", "name": "shop", "working_dir": "/home/me/shop", "replaced": False})
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded", dep.log
    assert "instead" not in dep.log  # 8080 is the project's own port
    ups = [c for c in remote.commands if " up -d --build" in c]
    assert len(ups) == 1 and "docker compose -p shop " in ups[0]
    inst = dep.instance
    assert inst.compose_project_name == "shop" and inst.claim["replaced"] is True
    assert inst.published_ports == [{"service": "web", "container": 80, "protocol": "tcp", "host": 8080}]

    first = len(remote.commands)
    dep2 = await _redeploy(inst.id)
    await deployer.run_deployment(dep2, connect=_connect(remote), github=FakeGitHub)
    assert (await _get(Deployment, dep2)).status == "succeeded"
    later = remote.commands[first:]
    assert any(" up -d --build" in c and "docker compose -p shop " in c for c in later)
    assert not any("slipway-web-prod" in c for c in remote.commands if "docker compose" in c)
    # Nothing touches the project's own directory, and no volume is removed.
    assert not any("/home/me/shop" in c for c in remote.commands)
    _no_volume_removal(remote.commands)


async def test_first_deploy_replaces_the_claimed_container():
    remote = FakeRemote(responses={
        ".State.Running": "true",
        "/proc/net": "docker\t\t\tblog\t0.0.0.0:8080->3000/tcp",  # the claimed container holds the port
    })
    dep_id = await _seed_claimed(claim={"kind": "container", "name": "blog", "container_id": SOLO,
                                        "container_name": "blog", "replaced": False})
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded", dep.log
    assert "instead" not in dep.log and any("-p 8080:3000/tcp" in c for c in remote.commands)
    stop = next(i for i, c in enumerate(remote.commands) if f"docker stop {SOLO}" in c)
    run = next(i for i, c in enumerate(remote.commands) if c.startswith("docker run -d"))
    remove = next(i for i, c in enumerate(remote.commands) if f"docker rm -f {SOLO}" in c)
    assert stop < run < remove
    assert "Removed the claimed container blog; its volumes were kept" in dep.log
    inst = dep.instance
    assert inst.claim["replaced"] is True and inst.claimed_container is None
    assert not any(f"docker start {SOLO}" in c for c in remote.commands)
    _no_volume_removal(remote.commands, SOLO)

    # The next deploy treats the instance like any other: the old container is not touched again.
    first = len(remote.commands)
    dep2 = await _redeploy(inst.id)
    await deployer.run_deployment(dep2, connect=_connect(remote), github=FakeGitHub)
    assert (await _get(Deployment, dep2)).status == "succeeded"
    assert not any(SOLO in c for c in remote.commands[first:])


async def test_failed_first_deploy_starts_the_claimed_container_again():
    remote = FakeRemote(fail_on="docker run -d", responses={".State.Running": "true"})
    dep_id = await _seed_claimed(claim={"kind": "container", "name": "blog", "container_id": SOLO,
                                        "container_name": "blog", "replaced": False})
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "failed"
    assert f"docker start {SOLO}" in remote.commands
    assert "Started the claimed container blog again" in dep.log
    assert not any(f"docker rm -f {SOLO}" in c for c in remote.commands)
    assert dep.instance.claimed_container == SOLO  # still claimed: the next deploy tries again


async def test_failed_build_leaves_a_stopped_claimed_container_alone():
    remote = FakeRemote(fail_on="docker build", responses={".State.Running": "false"})
    dep_id = await _seed_claimed(claim={"kind": "container", "name": "blog", "container_id": SOLO,
                                        "container_name": "blog", "replaced": False})
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    assert (await _get(Deployment, dep_id)).status == "failed"
    assert not any(f"docker start {SOLO}" in c or f"docker stop {SOLO}" in c for c in remote.commands)


async def test_destroy_keeps_a_claimed_directory_inside_the_instance_directory():
    inst = _claimed_compose()
    inst.claim = {**inst.claim, "working_dir": "/opt/slipway/web-prod/app"}
    remote = FakeRemote()
    warning = await deployer.destroy(inst, connect=_connect(remote))
    assert "Kept /opt/slipway/web-prod" in warning
    assert not any("rm -rf" in c for c in remote.commands)
    _no_volume_removal(remote.commands)


# ------------------------------------------------------------------------ the API


async def _host_and_repo() -> tuple[Host, Repository]:
    async with get_sessionmaker()() as db:
        host = Host(name="prod-01", hostname="10.0.0.1", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
        repo = Repository(github_id=42, full_name="acme/shop", owner="acme", name="shop",
                          html_url="https://github.com/acme/shop", detected_config={})
        db.add_all([host, repo])
        await db.commit()
        return host, repo


@pytest.fixture
def host_remote(monkeypatch):
    remote = FakeRemote(responses={
        "docker ps -aq --no-trunc": DISCOVER_OUTPUT,
        "printf 'env ": f"env {SOLO} " + json.dumps(["TOKEN=abc", "PATH=/bin"]) + " " + json.dumps(["PATH=/bin"]),
    })
    monkeypatch.setattr(unmanaged, "open_session", _connect(remote))
    submitted = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, inst_id: submitted.append(dep_id))
    remote.submitted = submitted
    return remote


async def test_list_unmanaged(admin_client, host_remote):
    host, _ = await _host_and_repo()
    r = await admin_client.get(f"/api/v1/hosts/{host.id}/unmanaged")
    assert r.status_code == 200, r.text
    assert [(g["key"], g["state"]) for g in r.json()] == [("compose:shop", "partial"), (f"container:{SOLO}", "running")]
    assert r.json()[0]["containers"][0]["name"] == "shop-db-1"
    assert host_remote.commands == [discovery.DISCOVER_COMMAND]


async def test_list_unmanaged_needs_instances_read(client, host_remote):
    await make_user("admin@example.com")
    async with get_sessionmaker()() as db:
        db.add(Role(name="host-viewer", description="", permissions=["hosts:read"]))
        await db.commit()
    await make_user("ops@example.com", roles=["host-viewer"])
    host, _ = await _host_and_repo()
    await login(client, "ops@example.com")
    r = await client.get(f"/api/v1/hosts/{host.id}/unmanaged")
    assert r.status_code == 403 and "instances:read" in r.text
    assert host_remote.commands == []


async def test_claim_compose_project_register_only(admin_client, host_remote):
    host, repo = await _host_and_repo()
    groups = (await admin_client.get(f"/api/v1/hosts/{host.id}/unmanaged")).json()
    body = {"group": groups[0], "repository_id": str(repo.id), "branch": "main", "name": "shop", "deploy": False}
    r = await admin_client.post(f"/api/v1/hosts/{host.id}/claim", json=body)
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["build_source"] == "compose" and data["compose_project"] == "shop"
    assert data["compose_file"] == "docker-compose.yml" and data["status"] == "running"  # one of two runs
    assert data["deployment_id"] is None and data["env_keys"] == [] and data["env_imported"] == []
    assert data["published_ports"] == [{"service": "web", "container": 80, "protocol": "tcp", "host": 8080}]
    assert data["claim"]["working_dir"] == "/home/me/shop" and data["claim"]["replaced"] is False
    assert host_remote.submitted == []
    assert not any("printf 'env " in c for c in host_remote.commands)  # env import is opt-in
    async with get_sessionmaker()() as db:
        event = await db.scalar(select(AuditEvent).where(AuditEvent.action == "instance.claim"))
        assert "Claimed compose project shop on prod-01 as shop" in event.summary and "register only" in event.summary
        assert event.details["register_only"] is True
    # It is no longer unmanaged, and can't be claimed twice.
    groups = (await admin_client.get(f"/api/v1/hosts/{host.id}/unmanaged")).json()
    assert [g["key"] for g in groups] == [f"container:{SOLO}"]
    r = await admin_client.post(f"/api/v1/hosts/{host.id}/claim", json={**body, "name": "shop2"})
    assert r.status_code == 404
    # The claimed app's ports are reserved on the host like any deployed instance's.
    reserved = await deployer._reserved_ports(Instance(id=None, host_id=host.id))
    assert (8080, "tcp", "shop") in reserved


async def test_claim_container_with_env_and_deploy(admin_client, host_remote):
    host, repo = await _host_and_repo()
    group = {"kind": "container", "container_id": SOLO}
    body = {"group": group, "repository_id": str(repo.id), "name": "blog", "import_env": True}
    r = await admin_client.post(f"/api/v1/hosts/{host.id}/claim", json=body)
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["build_source"] == "dockerfile" and data["branch"] == "main"
    assert data["ports"] == [{"host": 2368, "container": 2368, "protocol": "tcp"},
                             {"host": 9000, "container": 9000, "protocol": "tcp"}]
    assert {"source": "ghost-content", "target": "/var/lib/ghost/content"} in data["volumes"]
    assert data["env_keys"] == ["TOKEN"] and data["env_imported"] == ["TOKEN"]
    assert data["claim"]["container_id"] == SOLO and data["claim"]["container_name"] == "blog"
    assert data["deployment_id"] and host_remote.submitted == [uuid.UUID(data["deployment_id"])]
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, uuid.UUID(data["id"]))
        assert inst.env == {"TOKEN": "abc"} and inst.claimed_container == SOLO
        event = await db.scalar(select(AuditEvent).where(AuditEvent.action == "instance.claim"))
        assert "abc" not in json.dumps(event.details) and event.details["env_imported"] == ["TOKEN"]


async def test_claim_refuses_unsafe_requests(admin_client, host_remote):
    host, repo = await _host_and_repo()
    base = {"repository_id": str(repo.id), "branch": "main", "deploy": False}
    compose = {"kind": "compose", "project": "shop"}
    # The project directory would end up inside Slipway's own directory for the instance.
    async with get_sessionmaker()() as db:
        await db.execute(update(Host).values(deploy_root="/home/me"))
        await db.commit()
    r = await admin_client.post(f"/api/v1/hosts/{host.id}/claim", json={**base, "group": compose, "name": "shop"})
    assert r.status_code == 400 and "overlaps /home/me/shop" in r.text
    r = await admin_client.post(f"/api/v1/hosts/{host.id}/claim",
                                json={**base, "group": compose, "name": "shop", "build_source": "dockerfile"})
    assert r.status_code == 400
    r = await admin_client.post(f"/api/v1/hosts/{host.id}/claim",
                                json={**base, "group": {"kind": "compose", "project": "slipway-api"}, "name": "x"})
    assert r.status_code == 400
    r = await admin_client.post(f"/api/v1/hosts/{host.id}/claim",
                                json={**base, "group": {"kind": "container", "container_id": MANAGED}, "name": "x"})
    assert r.status_code == 404  # Slipway's own container is never offered
    async with get_sessionmaker()() as db:
        assert (await db.scalars(select(Instance))).all() == []


async def test_claim_and_deploy_needs_deployments_create(client, host_remote):
    await make_user("admin@example.com")
    async with get_sessionmaker()() as db:
        db.add(Role(name="configurer", description="", permissions=["instances:write", "hosts:read", "instances:read"]))
        await db.commit()
    await make_user("dev@example.com", roles=["configurer"])
    host, repo = await _host_and_repo()
    await login(client, "dev@example.com")
    body = {"group": {"kind": "container", "container_id": SOLO}, "repository_id": str(repo.id), "name": "blog"}
    r = await client.post(f"/api/v1/hosts/{host.id}/claim", json=body)
    assert r.status_code == 403
    r = await client.post(f"/api/v1/hosts/{host.id}/claim", json={**body, "deploy": False})
    assert r.status_code == 201, r.text


async def test_register_only_instance_shows_the_claimed_containers(admin_client, host_remote, monkeypatch):
    host, repo = await _host_and_repo()
    body = {"group": {"kind": "container", "container_id": SOLO}, "repository_id": str(repo.id), "name": "blog",
            "deploy": False}
    inst_id = (await admin_client.post(f"/api/v1/hosts/{host.id}/claim", json=body)).json()["id"]
    seen = []

    async def fake_run(instance, command, **kw):
        seen.append(command)
        return '{"Names": "blog", "State": "running"}'

    monkeypatch.setattr(deployer, "run_on_instance", fake_run)
    r = await admin_client.get(f"/api/v1/instances/{inst_id}/containers")
    assert r.status_code == 200 and r.json()[0]["Names"] == "blog"
    assert f"--filter id={SOLO}" in seen[0]
    assert (await admin_client.post(f"/api/v1/instances/{inst_id}/actions/restart")).status_code == 200
    assert seen[1] == f"docker restart {SOLO}"
    page = await admin_client.get(f"/instances/{inst_id}")
    assert "Claimed, not deployed by Slipway yet" in page.text and "blog" in page.text


async def test_claimed_paths_can_change_until_the_first_deploy(admin_client, host_remote):
    host, repo = await _host_and_repo()
    body = {"group": {"kind": "compose", "project": "shop"}, "repository_id": str(repo.id), "branch": "main",
            "name": "shop", "deploy": False}
    inst_id = (await admin_client.post(f"/api/v1/hosts/{host.id}/claim", json=body)).json()["id"]
    r = await admin_client.patch(f"/api/v1/instances/{inst_id}", json={"compose_file": "deploy/compose.yml"})
    assert r.status_code == 200 and r.json()["compose_file"] == "deploy/compose.yml"
    r = await admin_client.patch(f"/api/v1/instances/{inst_id}", json={"build_source": "dockerfile"})
    assert r.status_code == 400  # the build mode follows what was claimed
    page = await admin_client.get(f"/instances/{inst_id}/edit")
    assert 'id="cf" name="compose_file"  value' in page.text and "the paths can change until the first deployment" in page.text
    async with get_sessionmaker()() as db:
        # Once Slipway deployed it, the paths are fixed like any instance's.
        db.add(Deployment(instance_id=uuid.UUID(inst_id), branch="main", log="", status="succeeded", started_at=utcnow()))
        await db.execute(update(Instance).values(claim={"kind": "compose", "name": "shop", "replaced": True}))
        await db.commit()
    r = await admin_client.patch(f"/api/v1/instances/{inst_id}", json={"compose_file": "compose.yml"})
    assert r.status_code == 400


# ------------------------------------------------------------------ env files


def _dotenv_block(index: int, text: str) -> str:
    data = text.encode()
    rows = [" ".join(f"{b:02x}" for b in data[i:i + 16]) for i in range(0, len(data), 16)]
    return "\n".join([f"dotenv-begin {index}", *(" " + r for r in rows), f"dotenv-end {index}"])


def test_env_files_default_to_the_project_dotenv_and_follow_env_file():
    (shop, _) = discovery.parse(DISCOVER_OUTPUT)
    assert shop.env_files == ["/home/me/shop/.env"]
    out = _container(WEB, "x-web-1", project="x", service="web", working_dir="/srv/x", config_files="/srv/x/compose.yml")
    out = out.replace('"config_files": "/srv/x/compose.yml"',
                      '"config_files": "/srv/x/compose.yml", "env_files": "/srv/x/prod.env,/etc/x/extra.env"')
    (g,) = discovery.parse(out)
    assert g.env_files == ["/srv/x/prod.env", "/etc/x/extra.env"]


def test_parse_dotenv_like_compose():
    text = "\n".join([
        "# comment", "export A=1", "B = two words # note", 'C="x\\ty ${A} $$lit"', "D='raw ${A}'",
        "E=${MISSING:-def}/${A}", 'F="multi', 'line"', "G=after#nohash", "H=${A:+set}${MISSING+no}", "",
    ])
    values, skipped = discovery.parse_dotenv(text)
    assert values == {"A": "1", "B": "two words", "C": "x\ty 1 $lit", "D": "raw ${A}", "E": "def/1",
                      "F": "multi\nline", "G": "after#nohash", "H": "set"}
    assert skipped == []
    assert discovery.parse_dotenv("A='unterminated\n")[1] == ["A"]


def test_parse_env_files_reads_hex_blocks_in_order():
    out = "\n".join([
        _dotenv_block(0, "PORT=8080\nSECRET=one\nMULTI=\"a\nb\"\n"),
        "WARNING: something on stderr",
        _dotenv_block(1, "SECRET=two\nURL=http://h:${PORT}\n"),
        "dotenv-missing 2",
        "dotenv-unreadable 3",
    ])
    files = discovery.parse_env_files(out, ["/a/.env", "/b/.env", "/c/.env", "/d/.env", "/e/.env"])
    assert files.values == {"PORT": "8080", "SECRET": "two", "URL": "http://h:8080"}
    assert files.read == ["/a/.env", "/b/.env"] and files.missing == ["/c/.env"]
    assert files.unreadable == ["/d/.env", "/e/.env"]  # /e/.env: no answer at all
    assert files.skipped == ["MULTI"]  # Slipway stores single-line values only


def test_env_command_reads_the_env_files_safely():
    command = discovery.env_command([WEB], ["/home/me/my app/.env"])
    assert "head -c 262144 -- '/home/me/my app/.env' | od -An -v -tx1" in command
    assert "docker run --rm --network none -v '/home/me/my app':/r:ro alpine:3.20 test -f /r/.env" in command
    for bad in ("relative/.env", "/a:b/.env", "/"):
        with pytest.raises(ValueError):
            discovery.env_command([WEB], [bad])


async def test_claim_imports_the_project_env_file(admin_client, host_remote):
    host, repo = await _host_and_repo()
    env_out = "\n".join([
        f"env {WEB} " + json.dumps(["SECRET=from-container", "ONLY_IN_CONTAINER=1"]) + " []",
        f"env {DB_} " + json.dumps(["POSTGRES_PASSWORD=pw"]) + " []",
        _dotenv_block(0, "WEB_PORT=8080\nSECRET=from-dotenv\nDATA_DIR=/mnt/user/shop\n"),
    ])
    host_remote.responses["printf 'env "] = env_out
    body = {"group": {"kind": "compose", "project": "shop"}, "repository_id": str(repo.id), "branch": "main",
            "name": "shop", "deploy": False, "import_env": True}
    r = await admin_client.post(f"/api/v1/hosts/{host.id}/claim", json=body)
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["env_files_read"] == ["/home/me/shop/.env"] and data["warning"] is None
    assert data["env_imported"] == ["DATA_DIR", "ONLY_IN_CONTAINER", "POSTGRES_PASSWORD", "SECRET", "WEB_PORT"]
    command = next(c for c in host_remote.commands if "printf 'env " in c)
    assert "/home/me/shop/.env" in command
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, uuid.UUID(data["id"]))
        assert inst.env["SECRET"] == "from-dotenv"  # what Compose substituted and passed with env_file
        assert inst.env["WEB_PORT"] == "8080" and inst.env["DATA_DIR"] == "/mnt/user/shop"
        event = await db.scalar(select(AuditEvent).where(AuditEvent.action == "instance.claim"))
        assert "from-dotenv" not in json.dumps(event.details) and event.details["env_files_read"] == ["/home/me/shop/.env"]


async def test_claim_warns_when_the_env_file_cannot_be_read(admin_client, host_remote):
    host, repo = await _host_and_repo()
    host_remote.responses["printf 'env "] = "dotenv-unreadable 0"
    body = {"group": {"kind": "compose", "project": "shop"}, "repository_id": str(repo.id), "branch": "main",
            "name": "shop", "deploy": False, "import_env": True}
    r = await admin_client.post(f"/api/v1/hosts/{host.id}/claim", json=body)
    assert r.status_code == 201, r.text
    assert r.json()["env_files_unreadable"] == ["/home/me/shop/.env"]
    assert "Could not read /home/me/shop/.env" in r.json()["warning"]
