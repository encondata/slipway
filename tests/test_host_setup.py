"""Setting up a new Ubuntu server: a one-time admin login, then the host's own user, key and Docker."""

from __future__ import annotations

import shlex
import subprocess
import uuid

import asyncssh
import pytest
from sqlalchemy import select

from slipway.db.session import get_sessionmaker
from slipway.models import AuditEvent, Host, HostSetupStatus, HostStatus
from slipway.services import hosts, provisioning, ssh

ADMIN_PASSWORD = "admin-s3cret"


class _AdminServer(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username in ("root", "admin") and password == ADMIN_PASSWORD


@pytest.fixture
async def admin_server():
    """An SSH server that plays a fresh Ubuntu box: it records the setup command and what arrived on stdin."""
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    seen: dict = {"commands": [], "stdin": [], "reply": (0, "")}

    async def handle(process: asyncssh.SSHServerProcess) -> None:
        words = shlex.split(process.command or "")
        command = words[3] if words[:3] == ["exec", "/bin/sh", "-c"] else process.command
        seen["commands"].append(command)
        seen["stdin"].append(await process.stdin.read())
        status, output = seen["reply"]
        process.stdout.write(output)
        process.exit(status)

    server = await asyncssh.create_server(_AdminServer, "127.0.0.1", 0, server_host_keys=[host_key], process_factory=handle)
    seen["port"] = server.sockets[0].getsockname()[1]
    seen["host_key"] = host_key.export_public_key("openssh").decode().strip()
    yield seen
    server.close()
    await server.wait_closed()


def _probe_ok(host_key: str, **kw) -> ssh.ProbeResult:
    fields = dict(host_key=host_key, fingerprint=ssh.fingerprint(host_key), os_info="Ubuntu 24.04.1 LTS", cpus=2,
                  cpu_percent=5, mem_total_mb=4096, mem_percent=20, docker_version="27.3.1", docker_error=None,
                  containers_running=0)
    fields.update(kw)
    return ssh.ProbeResult(**fields)


def _new_host(port: int, **kw) -> dict:
    body = {"name": "fresh", "hostname": "127.0.0.1", "port": port, "username": "deploy", "os_type": "ubuntu",
            "setup": "new", "admin_username": "root", "admin_password": ADMIN_PASSWORD}
    body.update(kw)
    return body


async def _host(host_id: str) -> Host:
    async with get_sessionmaker()() as db:
        return await db.get(Host, uuid.UUID(host_id))


async def _actions(host_id: str) -> list[str]:
    async with get_sessionmaker()() as db:
        rows = await db.scalars(select(AuditEvent).where(AuditEvent.target_id == host_id).order_by(AuditEvent.created_at))
        return [e.action for e in rows]


# ---------------------------------------------------------------------- script


def test_script_quotes_values_and_announces_every_step():
    script = provisioning.ubuntu_script(username="deploy", public_key="ssh-ed25519 AAAA slipway@x", deploy_root="/opt/slip way")
    assert "user=deploy\n" in script and "key='ssh-ed25519 AAAA slipway@x'\n" in script and "root='/opt/slip way'\n" in script
    assert 'useradd --create-home --shell /bin/bash --user-group "$user"' in script
    announced = [line.split()[1] for line in script.splitlines() if line.startswith("step ")]
    assert announced == ["os", "user", "key", "docker", "deploy_root"]
    assert [name for name, _ in provisioning.STEPS] == ["connect", *announced, "verify"]
    assert "install docker.io docker-compose-v2" in script and 'usermod -aG docker "$user"' in script


def test_script_is_valid_posix_sh():
    for script in (provisioning.ubuntu_script(username="deploy", public_key="ssh-ed25519 AAAA c", deploy_root="/opt/slipway"),):
        subprocess.run(["sh", "-n", "-c", provisioning.as_root(script)], check=True)


def test_as_root_feeds_sudo_from_stdin():
    command = provisioning.as_root("echo hi")
    assert 'sudo -S -p ""' in command and '"$(id -u)" -eq 0' in command
    assert ADMIN_PASSWORD not in command


def test_sudo_problems_are_explained():
    assert "did not accept" in provisioning.sudo_problem("Sorry, try again.\nsudo: 1 incorrect password attempt", "admin")
    assert "may not use sudo" in provisioning.sudo_problem("admin is not in the sudoers file.", "admin")
    assert provisioning.sudo_problem("E: Unable to locate package docker-ce", "admin") is None


def test_admin_login_repr_hides_the_password():
    assert ADMIN_PASSWORD not in repr(provisioning.AdminLogin("root", ADMIN_PASSWORD))


# ------------------------------------------------------------------------- API


async def test_new_server_is_set_up_and_verified(admin_client, admin_server, monkeypatch):
    probed: list[ssh.SSHTarget] = []

    async def fake_probe(target):
        probed.append(target)
        return _probe_ok(target.pinned_host_key)

    monkeypatch.setattr(hosts.ssh, "probe", fake_probe)
    admin_server["reply"] = (0, f"{provisioning.STEP_MARK} os\nUbuntu 24.04.1 LTS\n{provisioning.STEP_MARK} user\n"
                                f"Created user deploy\n{provisioning.STEP_MARK} docker\necho {ADMIN_PASSWORD}\n")
    resp = await admin_client.post("/api/v1/hosts", json=_new_host(admin_server["port"]))
    assert resp.status_code == 201, resp.text
    created = resp.json()
    assert created["setup_status"] == "running" and created["os_type"] == "ubuntu" and created["auth_method"] == "key"
    await provisioning.runner.wait(uuid.UUID(created["id"]))

    setup = (await admin_client.get(f"/api/v1/hosts/{created['id']}/setup")).json()
    assert setup["status"] == "succeeded", setup
    assert setup["step"] == "verify" and setup["error"] is None
    assert "Created user deploy" in setup["log"] and "Docker 27.3.1" in setup["log"]
    assert ADMIN_PASSWORD not in setup["log"]  # scrubbed from the output

    host = await _host(created["id"])
    assert host.host_key == admin_server["host_key"] and host.status == HostStatus.HEALTHY
    assert host.password is None and host.private_key and host.public_key
    # The setup script carried Slipway's public key; the password only went to stdin.
    assert host.public_key in admin_server["commands"][0]
    assert all(ADMIN_PASSWORD not in c for c in admin_server["commands"])
    assert admin_server["stdin"][0] == ADMIN_PASSWORD + "\n"
    # Verified as the new user with its key, not the admin login.
    assert probed[0].username == "deploy" and probed[0].private_key and probed[0].password is None
    actions = await _actions(created["id"])
    assert actions[:3] == ["host.create", "host.setup_started", "host.key_pinned"] and "host.setup" in actions
    async with get_sessionmaker()() as db:
        details = " ".join(str(e.details) + e.summary for e in await db.scalars(select(AuditEvent)))
    assert ADMIN_PASSWORD not in details


async def test_wrong_sudo_password_fails_with_a_plain_reason(admin_client, admin_server, monkeypatch):
    monkeypatch.setattr(hosts.ssh, "probe", lambda target: pytest.fail("must not verify after a failed setup"))
    admin_server["reply"] = (1, "Sorry, try again.\nsudo: 1 incorrect password attempt\n")
    resp = await admin_client.post("/api/v1/hosts", json=_new_host(admin_server["port"], admin_username="admin"))
    host_id = resp.json()["id"]
    await provisioning.runner.wait(uuid.UUID(host_id))
    setup = (await admin_client.get(f"/api/v1/hosts/{host_id}/setup")).json()
    assert setup["status"] == "failed" and setup["error"] == "sudo did not accept the password for admin"
    assert "host.setup_failed" in await _actions(host_id)

    # Retrying with the right login runs it again against the pinned key.
    monkeypatch.setattr(hosts.ssh, "probe", lambda target: _async(_probe_ok(target.pinned_host_key)))
    admin_server["reply"] = (0, "")
    resp = await admin_client.post(f"/api/v1/hosts/{host_id}/setup", json={"admin_username": "root", "admin_password": ADMIN_PASSWORD})
    assert resp.status_code == 202, resp.text
    await provisioning.runner.wait(uuid.UUID(host_id))
    assert (await _host(host_id)).setup_status == HostSetupStatus.SUCCEEDED


async def _async(value):
    return value


async def test_bad_admin_login_is_reported(admin_client, admin_server):
    resp = await admin_client.post("/api/v1/hosts", json=_new_host(admin_server["port"], admin_password="nope"))
    host_id = resp.json()["id"]
    await provisioning.runner.wait(uuid.UUID(host_id))
    host = await _host(host_id)
    assert host.setup_status == HostSetupStatus.FAILED and "Authentication failed for root@" in host.setup_error
    assert host.host_key is None


async def test_new_server_needs_a_password_and_a_separate_user(admin_client):
    resp = await admin_client.post("/api/v1/hosts", json=_new_host(22, admin_password=None))
    assert resp.status_code == 400 and "admin password" in resp.text
    resp = await admin_client.post("/api/v1/hosts", json=_new_host(22, username="root"))
    assert resp.status_code == 400 and "rather than root" in resp.text
    resp = await admin_client.post("/api/v1/hosts", json=_new_host(22, os_type="debian"))
    assert resp.status_code == 422
    async with get_sessionmaker()() as db:
        assert (await db.scalars(select(Host))).all() == []


async def test_existing_server_ignores_the_admin_login(admin_client):
    body = _new_host(22, setup="existing")
    resp = await admin_client.post("/api/v1/hosts", json=body)
    assert resp.status_code == 201
    assert resp.json()["setup_status"] is None and resp.json()["os_type"] == "ubuntu"
    assert not provisioning.runner.running(uuid.UUID(resp.json()["id"]))


async def test_host_changes_wait_for_a_running_setup(admin_client):
    resp = await admin_client.post("/api/v1/hosts", json={"name": "busy", "hostname": "10.0.0.9", "username": "deploy"})
    host_id = resp.json()["id"]
    async with get_sessionmaker()() as db:
        host = await db.get(Host, uuid.UUID(host_id))
        provisioning.begin(host)
        await db.commit()
    for method, url, body in (
        ("PATCH", f"/api/v1/hosts/{host_id}", {"description": "x"}),
        ("DELETE", f"/api/v1/hosts/{host_id}", None),
        ("POST", f"/api/v1/hosts/{host_id}/check", None),
        ("POST", f"/api/v1/hosts/{host_id}/setup", {"admin_password": "x"}),
    ):
        resp = await admin_client.request(method, url, json=body)
        assert resp.status_code == 409, (method, url, resp.text)

    await provisioning.runner.recover_interrupted()
    host = await _host(host_id)
    assert host.setup_status == HostSetupStatus.INTERRUPTED and "restarted" in host.setup_error


async def test_setup_needs_a_key_host(admin_client):
    resp = await admin_client.post(
        "/api/v1/hosts", json={"name": "pw", "hostname": "10.0.0.8", "username": "deploy", "auth_method": "password", "password": "x"}
    )
    resp = await admin_client.post(f"/api/v1/hosts/{resp.json()['id']}/setup", json={"admin_password": "x"})
    assert resp.status_code == 400 and "key" in resp.text


# ------------------------------------------------------------------------- web


async def test_add_dialog_offers_os_and_new_or_existing(admin_client):
    page = (await admin_client.get("/hosts")).text
    assert 'name="os_type"' in page and '<option value="ubuntu" selected>Ubuntu</option>' in page
    assert 'name="setup" value="new"' in page and 'name="setup" value="existing" checked' in page
    assert 'data-show-when="setup=existing auth_method=key"' in page


async def test_host_page_shows_a_failed_setup_with_retry(admin_client):
    resp = await admin_client.post("/api/v1/hosts", json={"name": "half", "hostname": "10.0.0.7", "username": "deploy"})
    host_id = resp.json()["id"]
    page = (await admin_client.get(f"/hosts/{host_id}")).text
    assert "Set up with an admin login" in page and 'id="setup-host"' in page and "data-host-setup" not in page
    async with get_sessionmaker()() as db:
        host = await db.get(Host, uuid.UUID(host_id))
        host.setup_status, host.setup_error = HostSetupStatus.FAILED, "sudo did not accept the password for admin"
        await db.commit()
    page = (await admin_client.get(f"/hosts/{host_id}")).text
    assert f'data-host-setup="/api/v1/hosts/{host_id}/setup"' in page and "Try again" in page
    assert "did not finish" in page
    assert "Setup failed" in (await admin_client.get("/hosts")).text
    # The edit dialog doesn't offer the setup choice.
    assert page.count('name="setup"') == 0
