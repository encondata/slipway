"""Host port checks: reading the host and compose file, moving taken ports, passing them back to Compose."""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest
from sqlalchemy import text, update

from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Host, Instance
from slipway.services import deployer, ports, ssh
from tests.test_deployer import FakeGitHub, FakeRemote, _connect, _seed

ID = "00000000-0000-0000-0000-000000000001"

# docker compose config --format json / --no-interpolate for:
#   web: ports ["${WEB_PORT:-8080}:80", "127.0.0.1:9000:9000/udp"], APP_URL uses ${WEB_PORT}
#   db:  ports [{target: 5432, published: "5432"}, "6000-6001:7000-7001", "5433"]
CONFIG = {"services": {
    "web": {"image": "nginx", "ports": [
        {"mode": "ingress", "target": 80, "published": "8080", "protocol": "tcp"},
        {"mode": "ingress", "host_ip": "127.0.0.1", "target": 9000, "published": "9000", "protocol": "udp"},
    ]},
    "db": {"image": "postgres", "ports": [
        {"mode": "ingress", "target": 5432, "published": "5432", "protocol": "tcp"},
        {"mode": "ingress", "target": 7000, "published": "6000", "protocol": "tcp"},
        {"mode": "ingress", "target": 7001, "published": "6001", "protocol": "tcp"},
        {"mode": "ingress", "target": 5433, "protocol": "tcp"},
    ]},
}}
RAW = {"services": {
    "web": {"ports": ["${WEB_PORT:-8080}:80", "127.0.0.1:9000:9000/udp"]},
    "db": {"ports": [{"target": 5432, "published": "5432"}, {"target": 7000, "published": "6000"}]},
}}


def test_compose_bindings_skip_unpublished_ports_and_find_variables():
    got = ports.compose_bindings(CONFIG, RAW)
    assert [(b.service, b.container, b.protocol, b.host, b.host_ip, b.var) for b in got] == [
        ("db", 5432, "tcp", 5432, "", None),
        ("db", 7000, "tcp", 6000, "", None),
        ("db", 7001, "tcp", 6001, "", None),
        ("web", 80, "tcp", 8080, "", "WEB_PORT"),
        ("web", 9000, "udp", 9000, "127.0.0.1", None),
    ]


@pytest.mark.parametrize("raw, var", [
    ("${PORT}:80", "PORT"), ("${PORT-8080}:80", "PORT"), ("$PORT:80", "PORT"), ("0.0.0.0:${P:-1}:80/tcp", "P"),
    ("8080:80", None), ("${A}${B}:80", None), ("${PORT:?missing}:80", None),
])
def test_port_variables(raw, var):
    found = ports._raw_variables({"services": {"web": {"ports": [raw]}}})
    assert found.get(("web", 80, "tcp")) == var


def test_parse_scan():
    output = "\n".join([
        "proc tcp 00000000:1F90",  # 8080
        "proc tcp6 00000000000000000000000000000000:0016",  # 22
        "proc udp 00000000:0035",  # 53
        "proc tcp 0100007F:1F91",  # 8081, held by this instance's own container
        "docker\t\tother\tother-web-1\t0.0.0.0:8080->80/tcp, [::]:8080->80/tcp",
        "docker\t" + ID + "\t\tslipway-web-prod\t0.0.0.0:8081->3000/tcp",
        "docker\t\tslipway-web-prod\tslipway-web-prod-db-1\t0.0.0.0:6000-6001->7000-7001/tcp, 5432/tcp",
        "permission denied while trying to connect to the Docker daemon socket",
    ])
    found = ports.parse_scan(output, instance_id=ID, compose_project="slipway-web-prod")
    assert found.user(8080, "tcp") == "container other-web-1"
    assert found.user(22, "tcp") == "a process on the host"
    assert found.user(53, "udp") == "a process on the host" and found.user(53, "tcp") is None
    assert found.user(8081, "tcp") is None  # a redeploy frees it
    assert found.user(6000, "tcp") is None and found.user(6001, "tcp") is None
    assert found.user(5432, "tcp") is None


def _host(taken: dict[tuple[int, str], str] | None = None) -> ports.HostPorts:
    return ports.HostPorts(taken=dict(taken or {}))


def test_plan_moves_taken_ports_to_the_next_free_one():
    declared = ports.compose_bindings(CONFIG, RAW)
    host = _host({(8080, "tcp"): "container a", (8081, "tcp"): "container b", (5432, "tcp"): "a process on the host"})
    p = ports.plan(declared, host, auto=True, host_name="prod-01")
    assert {b.key: b.host for b in p.bindings} == {
        ("db", 5432, "tcp"): 5433, ("db", 7000, "tcp"): 6000, ("db", 7001, "tcp"): 6001,
        ("web", 80, "tcp"): 8082, ("web", 9000, "udp"): 9000,
    }
    assert [(w.host, g.host, why) for w, g, why in p.moved] == [
        (5432, 5433, "used by a process on the host"), (8080, 8082, "used by container a"),
    ]


def test_plan_does_not_give_two_mappings_the_same_port():
    # a's port is taken; it moves past 8081, which b asks for.
    declared = [ports.Binding("a", 80, "tcp", 8080), ports.Binding("b", 80, "tcp", 8081)]
    p = ports.plan(declared, _host({(8080, "tcp"): "x"}), auto=True, host_name="h")
    assert [b.host for b in p.bindings] == [8082, 8081]
    # Two mappings of the instance itself ask for the same port.
    declared = [ports.Binding("a", 80, "tcp", 8080), ports.Binding("b", 80, "tcp", 8080)]
    p = ports.plan(declared, _host(), auto=True, host_name="h")
    assert [b.host for b in p.bindings] == [8080, 8081]
    assert p.moved[0][2] == "used by a of this instance"


def test_plan_without_auto_names_the_clash():
    declared = [ports.Binding("web", 80, "tcp", 8080)]
    with pytest.raises(ports.PortError, match=r"8080/tcp \(web container port 80\) is already used by container a on prod-01"):
        ports.plan(declared, _host({(8080, "tcp"): "container a"}), auto=False, host_name="prod-01")


def test_plan_applies_overrides_and_checks_them_too():
    declared = [ports.Binding("web", 80, "tcp", 8080)]
    p = ports.plan(declared, _host(), overrides={("web", 80, "tcp"): 9090}, auto=False, host_name="h")
    assert p.bindings[0].host == 9090 and not p.moved and len(p.changed) == 1
    p = ports.plan(declared, _host({(9090, "tcp"): "x"}), overrides={("web", 80, "tcp"): 9090}, auto=True, host_name="h")
    assert p.bindings[0].host == 9091


def test_compose_changes_use_the_variable_when_there_is_one():
    declared = ports.compose_bindings(CONFIG, RAW)
    p = ports.plan(declared, _host({(8080, "tcp"): "x"}), auto=True, host_name="h")
    assert ports.compose_changes(p, CONFIG) == ({"WEB_PORT": "8081"}, None)


def test_compose_changes_override_literal_ports_with_the_whole_list():
    declared = ports.compose_bindings(CONFIG, RAW)
    p = ports.plan(declared, _host({(6000, "tcp"): "x", (6001, "tcp"): "y"}), auto=True, host_name="h")
    variables, override = ports.compose_changes(p, CONFIG)
    assert variables == {}
    lines = override.splitlines()
    assert lines[1:4] == ["services:", '  "db":', "    ports: !override"]
    entries = [json.loads(line.removeprefix("      - ")) for line in lines[4:]]
    assert [(e["target"], e.get("published")) for e in entries] == [(5432, "5432"), (7000, "6002"), (7001, "6003"), (5433, None)]


def test_compose_changes_without_changes():
    p = ports.plan(ports.compose_bindings(CONFIG, RAW), _host(), auto=True, host_name="h")
    assert ports.compose_changes(p, CONFIG) == ({}, None)


# ------------------------------------------------------- with the real Docker Compose


def _docker_compose() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "compose", "version"], capture_output=True).returncode == 0


@pytest.mark.skipif(not _docker_compose(), reason="needs docker compose")
def test_real_compose_applies_the_variable_and_the_override(tmp_path):
    (tmp_path / "compose.yml").write_text(
        "services:\n"
        "  web:\n    image: nginx\n    ports: ['${WEB_PORT:-8080}:80']\n"
        "    environment:\n      APP_URL: http://localhost:${WEB_PORT:-8080}\n"
        "  db:\n    image: postgres\n    ports: ['5432:5432', '127.0.0.1:6000:6000/udp']\n"
    )

    def config(*files: str, env_file: str | None = None, interpolate: bool = True) -> dict:
        cmd = ["docker", "compose", "-p", "t", *(["--env-file", env_file] if env_file else []), "-f", "compose.yml"]
        cmd += [arg for f in files for arg in ("-f", f)] + ["config", "--format", "json"]
        cmd += [] if interpolate else ["--no-interpolate"]
        return json.loads(subprocess.run(cmd, cwd=tmp_path, capture_output=True, text=True, check=True).stdout)

    resolved, raw = config(), config(interpolate=False)
    declared = ports.compose_bindings(resolved, raw)
    p = ports.plan(declared, _host({(8080, "tcp"): "x", (5432, "tcp"): "y"}), auto=True, host_name="h")
    variables, override = ports.compose_changes(p, resolved)
    assert variables == {"WEB_PORT": "8081"}
    (tmp_path / ".env.slipway").write_text(deployer.render_compose_env(variables))
    (tmp_path / "ports.yml").write_text(override)
    applied = config("ports.yml", env_file=".env.slipway")
    assert {(b.service, b.container, b.protocol, b.host_ip, b.host) for b in ports.compose_bindings(applied)} == {
        ("web", 80, "tcp", "", 8081), ("db", 5432, "tcp", "", 5433), ("db", 6000, "udp", "127.0.0.1", 6000),
    }
    assert applied["services"]["web"]["environment"]["APP_URL"] == "http://localhost:8081"


# ------------------------------------------------------------------- the pipeline


async def _get(model, id_):
    async with get_sessionmaker()() as db:
        return await db.get(model, id_)


def _compose_remote(scan: str, *, applied: dict | None = None) -> FakeRemote:
    """A host whose compose file is CONFIG, with ``scan`` as its ports in use."""
    def config(remote, command):
        if "compose.ports.yml" in command or "WEB_PORT" in str(remote.files.get("/opt/slipway/web-prod/shared/slipway.env")):
            return json.dumps(applied if applied is not None else CONFIG)
        return json.dumps(RAW if "--no-interpolate" in command else CONFIG)
    return FakeRemote(responses={" config --format json": config, "/proc/net": scan})


async def _compose_seed(**fields) -> object:
    dep_id = await _seed({"SECRET": "s"})
    async with get_sessionmaker()() as db:
        await db.execute(text("UPDATE instances SET build_source = 'compose', compose_file = 'compose.yml'"))
        if fields:
            await db.execute(update(Instance).values(**fields))
        await db.commit()
    return dep_id


def _moved_config(**published: str) -> dict:
    cfg = json.loads(json.dumps(CONFIG))
    for svc in cfg["services"].values():
        for p in svc["ports"]:
            key = f"p{p['target']}"
            if key in published:
                p["published"] = published[key]
    return cfg


async def test_compose_deploy_moves_a_taken_port_and_keeps_it():
    dep_id = await _compose_seed()
    # 6001 is free but db's next mapping asks for it, so 6000 moves past it to 6002.
    remote = _compose_remote("docker\t\tother\tother-db-1\t0.0.0.0:6000->6000/tcp", applied=_moved_config(p7000="6002"))
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)

    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded", dep.log
    assert "Host port 6000/tcp (db container port 7000) is used by container other-db-1; using 6002 instead" in dep.log
    override = remote.files["/opt/slipway/web-prod/shared/compose.ports.yml"]
    assert "ports: !override" in override and '"published": "6002"' in override
    up = next(c for c in remote.commands if " up -d --build" in c)
    assert "-f compose.yml -f /opt/slipway/web-prod/shared/compose.ports.yml up -d" in up
    # The check runs before the old containers are removed.
    assert remote.commands.index(next(c for c in remote.commands if "/proc/net" in c)) < remote.commands.index(
        next(c for c in remote.commands if c.startswith("docker ps -aq --filter label=slipway.instance")))
    inst = dep.instance
    assert inst.port_overrides == [{"service": "db", "container": 7000, "protocol": "tcp", "host": 6002, "auto": True}]
    assert {"service": "db", "container": 7000, "protocol": "tcp", "host": 6002, "declared": 6000} in inst.published_ports
    # No secret from the compose configuration reaches the log.
    assert "SECRET" not in dep.log


async def test_compose_deploy_sets_the_port_variable():
    dep_id = await _compose_seed()
    remote = _compose_remote("proc tcp 00000000:1F90", applied=_moved_config(p80="8081"))
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded", dep.log
    assert "Set WEB_PORT=8081 for the compose file" in dep.log
    assert remote.files["/opt/slipway/web-prod/shared/slipway.env"] == "SECRET='s'\nWEB_PORT='8081'\n"
    assert "/opt/slipway/web-prod/shared/compose.ports.yml" not in remote.files
    up = next(c for c in remote.commands if " up -d --build" in c)
    assert "compose.ports.yml" not in up
    # The merged .env is rebuilt with the variable before the check and the up.
    merges = [i for i, c in enumerate(remote.commands) if "mv -f /opt/slipway/web-prod/shared/.env.new" in c]
    assert len(merges) == 2 and merges[1] < remote.commands.index(up)


def _old_compose_remote(scan: str, *, resolved_works: bool = True) -> FakeRemote:
    """Compose before 2.24.4: ``!override`` adds ports, and ``--no-interpolate`` fails on a port variable."""
    def config(remote, command):
        if "--no-interpolate" in command:
            raise ssh.CommandFailed(command, 1, "error decoding 'Ports': Invalid ip address: ${WEB_PORT")
        if "compose.resolved.json" in command:
            written = json.loads(remote.files["/opt/slipway/web-prod/shared/compose.resolved.json"])
            return json.dumps(written if resolved_works else CONFIG)
        if "compose.ports.yml" in command:  # the old port and the new one
            cfg = json.loads(json.dumps(CONFIG))
            cfg["services"]["db"]["ports"].append({"target": 5432, "published": "5433", "protocol": "tcp"})
            return json.dumps(cfg)
        return json.dumps(CONFIG)
    return FakeRemote(responses={" config --format json": config, "/proc/net": scan})


async def test_compose_deploy_falls_back_to_the_resolved_file_on_old_compose():
    dep_id = await _compose_seed()
    remote = _old_compose_remote("proc tcp 00000000:1538")  # 5432 taken
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded", dep.log
    assert "does not support !override (it needs 2.24.4 or later)" in dep.log
    resolved = json.loads(remote.files["/opt/slipway/web-prod/shared/compose.resolved.json"])
    assert resolved["services"]["db"]["ports"][0] == {"mode": "ingress", "target": 5432, "published": "5433", "protocol": "tcp"}
    assert resolved["services"]["web"] == CONFIG["services"]["web"]
    up = next(c for c in remote.commands if " up -d --build" in c)
    assert ("--project-directory /opt/slipway/web-prod/releases/" in up
            and "-f /opt/slipway/web-prod/shared/compose.resolved.json up -d" in up
            and "-f compose.yml" not in up)
    # The override was removed again, so nothing later picks it up.
    assert any(c == "rm -f -- /opt/slipway/web-prod/shared/compose.ports.yml" for c in remote.commands)


async def test_compose_deploy_fails_when_no_way_applies_the_ports():
    dep_id = await _compose_seed()
    remote = _old_compose_remote("proc tcp 00000000:1538", resolved_works=False)
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "failed"
    assert "did not apply the new host ports (expected db 5433->5432/tcp; got db 5432->5432/tcp)" in dep.error
    assert not any(" up -d" in c for c in remote.commands)


async def test_old_compose_reads_port_variables_from_the_repository_file(monkeypatch):
    # --no-interpolate fails, so WEB_PORT is found in the compose file from the source archive.
    monkeypatch.setattr(FakeGitHub, "download_tarball", _tarball_with({
        "compose.yml": 'services:\n  web:\n    ports: ["${WEB_PORT:-8080}:80", "127.0.0.1:9000:9000/udp"]\n'
                       "  db:\n    ports: !reset []\n",
    }))
    dep_id = await _compose_seed()
    remote = _old_compose_remote("proc tcp 00000000:1F90")  # 8080 taken
    moved = _moved_config(p80="8081")
    base = remote.responses[" config --format json"]
    remote.responses[" config --format json"] = lambda r, c: (
        json.dumps(moved) if "WEB_PORT" in str(r.files.get("/opt/slipway/web-prod/shared/slipway.env")) and "--no-interpolate" not in c
        else base(r, c))
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded", dep.log
    assert "Set WEB_PORT=8081 for the compose file" in dep.log and "resolved" not in dep.log


def _tarball_with(files):
    async def download_tarball(self, repo_id, sha, dest):
        from tests.test_deployer import write_source_archive
        size = write_source_archive(dest, files)
        FakeGitHub.archive = dest.read_bytes()
        return size
    return download_tarball


def test_compose_output_arrives_byte_for_byte():
    data = {"services": {"web": {"environment": {"PW": "pässwörd 🔑 $$x"}}}}
    raw = json.dumps(data, ensure_ascii=False).encode()
    dump = "\n".join(" " + " ".join(f"{b:02x}" for b in raw[i:i + 16]) for i in range(0, len(raw), 16))
    assert ports.parse_compose_output("motd: welcome\n" + dump + "\n") == data
    assert ports.parse_compose_output(json.dumps(data)) == data  # plain JSON still reads


def test_load_compose_yaml_reads_compose_tags():
    data = ports.load_compose_yaml("services:\n  web:\n    ports: !override ['${P:-1}:80']\n    environment: !reset {}\n")
    assert data == {"services": {"web": {"ports": ["${P:-1}:80"], "environment": {}}}}
    assert ports.load_compose_yaml("a: [") is None and ports.load_compose_yaml("- 1") is None


def test_resolved_with_ports():
    p = ports.plan(ports.compose_bindings(CONFIG), _host({(9000, "udp"): "x"}), auto=True, host_name="h")
    out = json.loads(ports.resolved_with_ports(CONFIG, p))
    assert out["services"]["web"]["ports"][1] == {"mode": "ingress", "host_ip": "127.0.0.1", "target": 9000,
                                                   "published": "9001", "protocol": "udp"}
    assert out["services"]["db"] == CONFIG["services"]["db"]


async def test_compose_deploy_without_auto_stops_before_anything_changes():
    dep_id = await _compose_seed(auto_ports=False)
    remote = _compose_remote("proc tcp 00000000:1F90")
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "failed"
    assert "Host port 8080/tcp (web container port 80) is already used by a process on the host on prod-01" in dep.error
    assert not any(" up -d" in c or c.startswith("docker ps -aq --filter label=slipway.instance") for c in remote.commands)
    assert dep.instance.port_overrides == []


async def test_compose_override_from_the_user_is_applied():
    dep_id = await _compose_seed(
        auto_ports=False, port_overrides=[{"service": "web", "container": 80, "protocol": "tcp", "host": 8090}])
    remote = _compose_remote("proc tcp 00000000:1F90", applied=_moved_config(p80="8090"))
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded", dep.log
    assert "Using host port 8090 for web container port 80 (port override)" in dep.log
    assert "WEB_PORT='8090'" in remote.files["/opt/slipway/web-prod/shared/slipway.env"]


async def test_dockerfile_deploy_moves_a_port_another_instance_reserved():
    dep_id = await _seed({})
    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, dep_id)
        # A stopped instance on the same host was given 8080; nothing listens on it right now.
        db.add(Instance(name="other", slug="other", branch="main", host_id=dep.instance.host_id,
                        repository_id=dep.instance.repository_id, env={}, status="stopped",
                        ports=[{"host": 8080, "container": 80, "protocol": "tcp"}], volumes=[]))
        await db.commit()
    remote = FakeRemote()
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded", dep.log
    assert "is used by Slipway instance other; using 8081 instead" in dep.log
    assert dep.instance.ports == [{"host": 8081, "container": 3000, "protocol": "tcp"}]
    assert any("-p 8081:3000/tcp" in c for c in remote.commands)


async def test_dockerfile_redeploy_keeps_its_own_port():
    dep_id = await _seed({})
    inst_id = (await _get(Deployment, dep_id)).instance_id
    remote = FakeRemote(responses={"/proc/net": f"proc tcp 00000000:1F90\ndocker\t{inst_id}\t\tslipway-web-prod\t0.0.0.0:8080->3000/tcp"})
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded", dep.log
    assert any("-p 8080:3000/tcp" in c for c in remote.commands) and "instead" not in dep.log


# ------------------------------------------------------------------------ the API


async def test_api_stores_port_settings(admin_client):
    async with get_sessionmaker()() as db:
        host = Host(name="h1", hostname="10.0.0.9", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
        db.add(host)
        await db.commit()
    from slipway.models import Repository
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=7, full_name="acme/app", owner="acme", name="app",
                          html_url="https://github.com/acme/app", detected_config={})
        db.add(repo)
        await db.commit()
    body = {"name": "app", "repository_id": str(repo.id), "host_id": str(host.id), "branch": "main",
            "build_source": "compose", "deploy": False}
    r = await admin_client.post("/api/v1/instances", json=body)
    assert r.status_code == 201, r.text
    assert r.json()["auto_ports"] is True and r.json()["port_overrides"] == []
    inst_id = r.json()["id"]
    override = {"service": "web", "container": 80, "host": 8090}
    r = await admin_client.patch(f"/api/v1/instances/{inst_id}", json={"auto_ports": False, "port_overrides": [override]})
    assert r.status_code == 200, r.text
    assert r.json()["auto_ports"] is False
    assert r.json()["port_overrides"] == [{**override, "protocol": "tcp", "auto": False}]
    r = await admin_client.patch(f"/api/v1/instances/{inst_id}", json={"port_overrides": [override, {**override, "host": 1}]})
    assert r.status_code == 422
    r = await admin_client.patch(f"/api/v1/instances/{inst_id}", json={"port_overrides": [{**override, "service": "bad name"}]})
    assert r.status_code == 422
