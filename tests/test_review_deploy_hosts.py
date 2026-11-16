"""Regression tests for the host / SSH review fixes (probe parsing, poller, host keys, host edits)."""

from __future__ import annotations

import asyncio
import contextlib

import asyncssh
import pytest
from asyncssh.connection import SSHServerConnection
from sqlalchemy import event, inspect, select, text, update

from slipway.core.config import get_settings
from slipway.db.session import get_engine, get_sessionmaker
from slipway.models import Host, HostAuthMethod, Instance, Repository
from slipway.services import hosts, ssh

WARNING = "WARNING: Error loading config file: /home/deploy/.docker/config.json: open /home/deploy/.docker/config.json: permission denied"


def _probe_output(docker: str = "27.3.1\nrc=0", os_info: str = "Ubuntu 24.04 LTS", load: str = "1.00 0.50 0.25 1/200 1234",
                  meminfo: str = "MemTotal:        8000000 kB\nMemAvailable:    6000000 kB", nproc: str = "4", containers: str = "3") -> str:
    sep = "\n::slipway::\n"
    return sep.join([os_info, nproc, load, meminfo, docker, containers]) + "\n"


def _public(key: asyncssh.SSHKey) -> str:
    return key.export_public_key("openssh").decode().strip()


def _result(host_key: str, **kw) -> ssh.ProbeResult:
    fields = dict(host_key=host_key, fingerprint=ssh.fingerprint(host_key), os_info="Debian 13", cpus=2, cpu_percent=10,
                  mem_total_mb=4096, mem_percent=40, docker_version="27.0", docker_error=None, containers_running=0)
    fields.update(kw)
    return ssh.ProbeResult(**fields)


async def _sql(statement: str) -> None:
    async with get_engine().begin() as conn:
        await conn.execute(text(statement))


async def _emulate_postgres_lengths() -> None:
    """SQLite ignores VARCHAR lengths; PostgreSQL rejects over-long values. Emulate that."""
    if get_engine().dialect.name != "sqlite":  # a real PostgreSQL enforces them already
        return
    await _sql(
        "CREATE TRIGGER pg_varchar BEFORE UPDATE ON hosts "
        "WHEN length(NEW.docker_version) > 64 OR length(NEW.os_info) > 255 "
        "BEGIN SELECT RAISE(ABORT, 'value too long for type character varying'); END"
    )


async def _add_pinned_host(name: str, host_key: str, **kw) -> Host:
    async with get_sessionmaker()() as db:
        host = Host(name=name, hostname=kw.pop("hostname", f"{name}.example"), port=kw.pop("port", 22), username="deploy",
                    deploy_root="/opt/slipway", metrics={}, auth_method="password", password="pw", host_key=host_key,
                    host_key_fingerprint=ssh.fingerprint(host_key) if host_key else None, **kw)
        db.add(host)
        await db.commit()
        return host


async def _host(name: str) -> Host:
    async with get_sessionmaker()() as db:
        return (await db.scalars(select(Host).where(Host.name == name))).one()


async def _seed_repo() -> str:
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=7, full_name="acme/web", owner="acme", name="web", html_url="https://github.com/acme/web",
                          detected_config={"dockerfile": True, "compose_file": None, "files": ["Dockerfile"]})
        db.add(repo)
        await db.commit()
        return str(repo.id)


# ------------------------------------------------------------------ probe parsing


def test_parse_probe_takes_version_from_last_line_and_keeps_warnings():
    key = _public(asyncssh.generate_private_key("ssh-ed25519"))
    noisy = ssh.parse_probe(_probe_output(docker=f"{WARNING}\n27.3.1\nrc=0"), key)
    assert noisy.docker_version == "27.3.1"
    assert noisy.docker_error == WARNING
    podman = ssh.parse_probe(_probe_output(docker="Emulate Docker CLI using podman. Create /etc/containers/nodocker to quiet msg.\n4.9.4\nrc=0"), key)
    assert podman.docker_version == "4.9.4" and "podman" in podman.docker_error
    assert hosts.status_from_probe(noisy) == "healthy"

    long_line = ssh.parse_probe(_probe_output(docker="v" * 300 + "\nrc=0", os_info="Linux\x00 " + "x" * 400), key)
    assert len(long_line.docker_version) == 64
    assert "\x00" not in long_line.os_info and len(long_line.os_info) == 255
    failed = ssh.parse_probe(_probe_output(docker="E" * 2000 + "\nrc=1"), key)
    assert failed.docker_version is None and len(failed.docker_error) == 500


def test_parse_probe_never_raises_on_garbage():
    key = _public(asyncssh.generate_private_key("ssh-ed25519"))
    result = ssh.parse_probe(
        _probe_output(load="nan 1 1", meminfo="MemTotal: lots kB\nMemAvailable: 9" + "9" * 5000 + " kB", nproc="²",
                      containers="１２"),
        key,
    )
    assert result.cpus == 1 and result.cpu_percent == 0.0 and result.containers_running == 0
    assert result.mem_total_mb == 0 and result.mem_percent == 0.0
    assert ssh.parse_probe("garbage without separators", key).docker_error == "docker not found"


async def test_noisy_docker_output_is_storable_on_postgres(admin_client, monkeypatch):
    await _emulate_postgres_lengths()
    host = (await admin_client.post("/api/v1/hosts", json={"name": "a", "hostname": "10.0.0.5", "username": "deploy"})).json()
    key = _public(asyncssh.generate_private_key("ssh-ed25519"))

    async def noisy_probe(target):
        return ssh.parse_probe(_probe_output(docker=f"{WARNING}\n27.3.1\nrc=0"), key)

    monkeypatch.setattr(hosts.ssh, "probe", noisy_probe)
    checked = (await admin_client.post(f"/api/v1/hosts/{host['id']}/check")).json()
    assert checked["host_key_fingerprint"] and checked["docker_version"] == "27.3.1"
    assert "permission denied" in checked["last_error"]

    async def oversized_probe(target):  # check_host itself caps values too
        return _result(key, docker_version="9" * 200, os_info="y" * 400, docker_error="z\x00" * 5000)

    monkeypatch.setattr(hosts.ssh, "probe", oversized_probe)
    checked = (await admin_client.post(f"/api/v1/hosts/{host['id']}/check")).json()
    assert len(checked["docker_version"]) == 64 and len(checked["os_info"]) == 255
    assert "\x00" not in checked["last_error"] and len(checked["last_error"]) <= 2000


# ------------------------------------------------------------------ poller


async def test_poller_keeps_checking_other_hosts_after_failures(monkeypatch):
    key = _public(asyncssh.generate_private_key("ssh-ed25519"))
    for name in ("a", "b", "c", "d"):
        await _add_pinned_host(name, key)
    probed: list[str] = []

    def fail_c(mapper, connection, target):  # c's result cannot be written, as with a database error
        if target.name == "c" and inspect(target).attrs.status.history.has_changes():
            raise RuntimeError("boom")

    async def fake_probe(target):
        assert get_engine().pool.checkedout() == 0, "a DB connection is held during SSH"
        probed.append(target.hostname)
        if target.hostname == "b.example":
            raise RuntimeError("unexpected")
        return _result(key)

    failures: list[tuple] = []
    monkeypatch.setattr(hosts.ssh, "probe", fake_probe)
    monkeypatch.setattr(hosts.log, "exception", lambda *args, **kw: failures.append(args))
    event.listen(Host, "before_update", fail_c)
    try:
        await hosts.poll_once()  # b's probe blows up and c's write fails
    finally:
        event.remove(Host, "before_update", fail_c)
    assert probed == ["a.example", "b.example", "c.example", "d.example"]
    for name in ("a", "d"):
        host = await _host(name)
        assert host.status == "healthy" and host.last_checked_at is not None and host.docker_version == "27.0"
    assert (await _host("c")).status == "unknown"
    assert len(failures) == 2


async def test_poller_survives_a_row_that_cannot_be_decrypted(monkeypatch):
    key = _public(asyncssh.generate_private_key("ssh-ed25519"))
    for name in ("a", "b", "c"):
        await _add_pinned_host(name, key)
    await _sql("UPDATE hosts SET password = 'not-a-fernet-token' WHERE name = 'b'")
    probed: list[str] = []

    async def fake_probe(target):
        probed.append(target.hostname)
        return _result(key)

    monkeypatch.setattr(hosts.ssh, "probe", fake_probe)
    await hosts.poll_once()
    assert {"a.example", "c.example"} <= set(probed)
    assert (await _host("c")).status == "healthy"


async def test_poll_loop_survives_a_failed_round(monkeypatch):
    calls: list[int] = []

    async def fake_poll_once():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("database down")
        raise asyncio.CancelledError

    monkeypatch.setattr(get_settings(), "host_poll_interval", 0.01)
    monkeypatch.setattr(hosts, "poll_once", fake_poll_once)
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(hosts.poll_hosts_forever(), timeout=2)
    assert len(calls) == 2


# ------------------------------------------------------------------ check endpoint


async def test_check_does_not_hold_a_db_connection_during_ssh(admin_client, monkeypatch):
    host = (await admin_client.post("/api/v1/hosts", json={"name": "a", "hostname": "10.0.0.5", "username": "deploy"})).json()
    key = _public(asyncssh.generate_private_key("ssh-ed25519"))
    held: list[int] = []

    async def fake_probe(target):
        held.append(get_engine().pool.checkedout())
        return _result(key)

    monkeypatch.setattr(hosts.ssh, "probe", fake_probe)
    r = await admin_client.post(f"/api/v1/hosts/{host['id']}/check")
    assert r.status_code == 200 and r.json()["status"] == "healthy"
    assert held == [0]
    events = (await admin_client.get("/api/v1/audit?action=host.key_pinned")).json()
    assert len(events) == 1 and events[0]["actor"] == "admin@example.com"


async def test_check_result_is_discarded_if_host_is_moved_during_probe(admin_client, monkeypatch):
    host = (await admin_client.post("/api/v1/hosts", json={"name": "a", "hostname": "10.0.0.5", "username": "deploy"})).json()
    key = _public(asyncssh.generate_private_key("ssh-ed25519"))

    async def probe_while_moving(target):
        r = await admin_client.patch(f"/api/v1/hosts/{host['id']}", json={"hostname": "10.0.0.99"})
        assert r.status_code == 200
        return _result(key)

    monkeypatch.setattr(hosts.ssh, "probe", probe_while_moving)
    checked = (await admin_client.post(f"/api/v1/hosts/{host['id']}/check")).json()
    assert checked["hostname"] == "10.0.0.99"
    assert checked["host_key_fingerprint"] is None and checked["status"] == "unknown" and checked["docker_version"] is None


async def test_check_of_host_deleted_during_probe_returns_404(admin_client, monkeypatch):
    host = (await admin_client.post("/api/v1/hosts", json={"name": "a", "hostname": "10.0.0.5", "username": "deploy"})).json()
    key = _public(asyncssh.generate_private_key("ssh-ed25519"))

    async def probe_while_deleting(target):
        assert (await admin_client.delete(f"/api/v1/hosts/{host['id']}")).status_code == 204
        return _result(key)

    monkeypatch.setattr(hosts.ssh, "probe", probe_while_deleting)
    assert (await admin_client.post(f"/api/v1/hosts/{host['id']}/check")).status_code == 404


# ------------------------------------------------------------------ real SSH servers


class _OpenServer(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return False  # no authentication required


async def _abort_mid_command(process: asyncssh.SSHServerProcess) -> None:
    process.stdout.write("partial output\n")
    await asyncio.sleep(0.05)
    process.get_extra_info("connection").abort()


@pytest.fixture
async def start_server():
    servers = []

    async def start(host_keys, **kw) -> int:
        server = await asyncssh.create_server(_OpenServer, "127.0.0.1", 0, server_host_keys=host_keys, **kw)
        servers.append(server)
        return server.sockets[0].getsockname()[1]

    yield start
    for server in servers:
        server.close()
        with contextlib.suppress(TimeoutError):  # a connection left open by a failed test must not hang
            await asyncio.wait_for(server.wait_closed(), 5)


def _target(port: int, pinned: str | None = None) -> ssh.SSHTarget:
    return ssh.SSHTarget(hostname="127.0.0.1", port=port, username="deploy", password="pw", pinned_host_key=pinned)


async def test_errors_after_connect_become_ssh_errors(start_server, tmp_path):
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    port = await start_server([host_key], process_factory=_abort_mid_command, sftp_factory=True)
    async with ssh.open_session(_target(port, _public(host_key))) as remote:
        with pytest.raises(ssh.SSHError, match="Could not write"):
            await remote.write_text(str(tmp_path / "missing" / ".env"), "A=1\n")
        with pytest.raises(ssh.SSHError, match="Could not upload"):
            await remote.put(tmp_path / "does-not-exist.tar.gz", str(tmp_path / "x.tar.gz"))
        with pytest.raises(ssh.SSHError, match="SSH command failed"):
            await remote.run("anything")


def _print_two_lines(process: asyncssh.SSHServerProcess) -> None:
    process.stdout.write("one\ntwo\n")
    process.exit(0)


@pytest.mark.parametrize("error", [ConnectionRefusedError(61, "Connect call failed ('10.0.0.2', 5432)"), TimeoutError("db")])
async def test_errors_from_the_line_callback_are_not_blamed_on_ssh(start_server, error):
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    port = await start_server([host_key], process_factory=_print_two_lines)
    seen: list[str] = []

    async def failing_sink(line: str) -> None:  # e.g. the deployment log failing to reach the database
        seen.append(line)
        raise error

    async with ssh.open_session(_target(port, _public(host_key))) as remote:
        with pytest.raises(type(error)) as exc:
            await remote.run("deploy", on_line=failing_sink, timeout=10)
        assert exc.value is error and not isinstance(exc.value, ssh.SSHError)
        assert seen == ["one"]
        assert await remote.run("again") == (0, "one\ntwo")


async def test_check_of_host_with_invalid_hostname_is_unreachable(admin_client):
    for hostname in ("web..example.com", "x" * 70 + ".example"):
        with pytest.raises(ssh.SSHError, match="Invalid hostname"):
            await ssh.connect(ssh.SSHTarget(hostname=hostname, port=22, username="deploy", password="pw"), allow_unpinned=True)
    # The API refuses such names up front; connect() still guards hosts stored before that check existed.
    for hostname in ("web..example.com", "x" * 70 + ".example", "-bad.example"):
        r = await admin_client.post("/api/v1/hosts", json={"name": "typo", "hostname": hostname, "username": "deploy"})
        assert r.status_code == 422, r.text
    async with get_sessionmaker()() as db:
        host = Host(name="typo", hostname="web..example.com", username="deploy", auth_method=HostAuthMethod.PASSWORD, password="pw")
        db.add(host)
        await db.commit()
        host_id = host.id
    r = await admin_client.post(f"/api/v1/hosts/{host_id}/check")
    assert r.status_code == 200 and r.json()["status"] == "unreachable"
    assert "Invalid hostname" in r.json()["last_error"]


async def test_refused_session_marks_host_unreachable(admin_client, start_server):
    port = await start_server([asyncssh.generate_private_key("ssh-ed25519")])  # no process factory: sessions refused
    with pytest.raises(ssh.SSHError):
        await ssh.probe(_target(port))
    host = (await admin_client.post("/api/v1/hosts", json={"name": "a", "hostname": "127.0.0.1", "port": port, "username": "deploy"})).json()
    r = await admin_client.post(f"/api/v1/hosts/{host['id']}/check")
    assert r.status_code == 200 and r.json()["status"] == "unreachable"


@pytest.mark.parametrize("server_behaviour", ["disconnect", "drop"])
async def test_host_key_type_change_is_a_mismatch(start_server, monkeypatch, admin_client, server_behaviour):
    if server_behaviour == "drop":  # like OpenSSH: close the connection without a disconnect message
        original = SSHServerConnection.choose_server_host_key

        def drop_connection(self, peer_host_key_algs):
            found = original(self, peer_host_key_algs)
            if not found:
                self.abort()
            return found

        monkeypatch.setattr(SSHServerConnection, "choose_server_host_key", drop_connection)
    pinned_rsa = _public(asyncssh.generate_private_key("ssh-rsa"))
    port = await start_server([asyncssh.generate_private_key("ssh-ed25519")])  # server rebuilt with ed25519 only
    with pytest.raises(ssh.HostKeyMismatch, match="ssh-ed25519"):
        await ssh.connect(_target(port, pinned_rsa))

    host = await _add_pinned_host("rebuilt", pinned_rsa, hostname="127.0.0.1", port=port)
    checked = (await admin_client.post(f"/api/v1/hosts/{host.id}/check")).json()
    assert checked["status"] == "error" and "pinned ssh-rsa key" in checked["last_error"]

    async def hang_up(reader, writer):  # a plain connection drop is not reported as a mismatch
        writer.close()

    server = await asyncio.start_server(hang_up, "127.0.0.1", 0)
    try:
        with pytest.raises(ssh.SSHError) as exc:
            await ssh.connect(_target(server.sockets[0].getsockname()[1], pinned_rsa))
        assert not isinstance(exc.value, ssh.HostKeyMismatch)
    finally:
        server.close()
        await server.wait_closed()


async def test_first_check_pins_ed25519_and_pinned_key_types_still_connect(start_server):
    rsa, ed = asyncssh.generate_private_key("ssh-rsa"), asyncssh.generate_private_key("ssh-ed25519")
    port = await start_server([rsa, ed], process_factory=lambda p: p.exit(0))
    async with ssh.open_session(_target(port), allow_unpinned=True) as tofu:
        assert tofu.server_host_key() == _public(ed)
    for pinned in (rsa, ed):  # a host pinned earlier on its RSA key keeps working
        async with ssh.open_session(_target(port, _public(pinned))) as remote:
            assert remote.server_host_key() == _public(pinned)


# ------------------------------------------------------------------ credentials and keys


async def test_undecryptable_credentials_give_a_clear_error(admin_client):
    with pytest.raises(ssh.SSHError, match="could not be decrypted"):
        await ssh.connect(ssh.SSHTarget(hostname="127.0.0.1", port=1, username="deploy"), allow_unpinned=True)
    host = (await admin_client.post("/api/v1/hosts", json={"name": "a", "hostname": "127.0.0.1", "port": 1, "username": "deploy"})).json()
    await _sql("UPDATE hosts SET private_key = NULL")  # what a failed decryption leaves behind
    checked = (await admin_client.post(f"/api/v1/hosts/{host['id']}/check")).json()
    assert checked["status"] == "unreachable" and "could not be decrypted" in checked["last_error"]


@pytest.mark.parametrize("comment", ["x'; touch /tmp/pwned; echo '", "John's laptop", "a\nssh-ed25519 AAAA evil", "$(id)`id`"])
async def test_public_key_comment_is_safe_for_the_setup_snippet(admin_client, comment):
    key = asyncssh.generate_private_key("ssh-ed25519", comment=comment)
    priv = key.export_private_key("openssh").decode()
    created = (await admin_client.post("/api/v1/hosts", json={
        "name": "a", "hostname": "10.0.0.1", "username": "deploy", "auth_method": "key", "private_key": priv})).json()
    public = created["public_key"]
    algorithm, data, *rest = public.split(" ")
    assert len(rest) <= 1 and all(ch.isalnum() or ch in "@._-" for ch in "".join(rest))
    assert asyncssh.import_public_key(public).public_data == key.public_data
    assert ssh.public_key_from_private(priv) == public
    assert ssh.generate_keypair(comment)[1].count(" ") <= 2


# ------------------------------------------------------------------ host edits


async def test_deploy_root_change_is_a_plain_setting_before_any_deploy(admin_client):
    repo_id = await _seed_repo()
    host = (await admin_client.post("/api/v1/hosts", json={"name": "a", "hostname": "10.0.0.5", "username": "deploy"})).json()
    r = await admin_client.post("/api/v1/instances", json={"name": "web", "repository_id": repo_id, "host_id": host["id"], "deploy": False})
    assert r.status_code == 201, r.text
    url = f"/api/v1/hosts/{host['id']}"
    assert (await admin_client.patch(url, json={"deploy_root": "/srv/slipway"})).json()["deploy_root"] == "/srv/slipway"
    assert (await admin_client.patch(url, json={"deploy_root": "/srv/slipway/", "description": "x"})).status_code == 200


async def test_address_change_clears_pinned_key_and_is_audited(admin_client, monkeypatch):
    host = (await admin_client.post("/api/v1/hosts", json={"name": "a", "hostname": "10.0.0.5", "username": "deploy"})).json()
    key = _public(asyncssh.generate_private_key("ssh-ed25519"))

    async def fake_probe(target):
        return _result(key)

    monkeypatch.setattr(hosts.ssh, "probe", fake_probe)
    url = f"/api/v1/hosts/{host['id']}"
    fingerprint = (await admin_client.post(f"{url}/check")).json()["host_key_fingerprint"]
    assert (await admin_client.patch(url, json={"hostname": "10.0.0.5", "description": "same box"})).json()["host_key_fingerprint"] == fingerprint

    for change in ({"hostname": "10.0.0.6"}, {"port": 2222}):
        assert (await admin_client.post(f"{url}/check")).json()["host_key_fingerprint"] == fingerprint
        moved = (await admin_client.patch(url, json=change)).json()
        assert moved["host_key_fingerprint"] is None and moved["status"] == "unknown"
    resets = (await admin_client.get("/api/v1/audit?action=host.key_reset")).json()
    assert len(resets) == 2 and all(fingerprint in e["summary"] for e in resets)
    updates = (await admin_client.get("/api/v1/audit?action=host.update")).json()
    assert any("10.0.0.5 -> 10.0.0.6" in e["summary"] for e in updates)
