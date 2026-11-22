"""The fake hosts' phase 4 and 5 part (P4 §20.1, P5 §16.1): hosts found by address, hosts added later, host keys
checked like ``ssh.connect``, booting and firewalled hosts, and the cloud-init, psql and ``$SSH_CONNECTION``
shims. Phase 3's name-keyed use is covered by the phase 3 tests that use ``MultiRemote``."""

from __future__ import annotations

import base64
import json

import pytest

from slipway.services import do_rules, ssh, traffic
from tests.fake_hosts import ADDRESSES, SLIPWAY_ADDRESS, MultiRemote


@pytest.fixture
def multi(tmp_path):
    return MultiRemote(tmp_path)


def _target(hostname: str, pinned: str | None = "ssh-ed25519 AAAA") -> ssh.SSHTarget:
    return ssh.SSHTarget(hostname=hostname, port=22, username="slipway", private_key="key", pinned_host_key=pinned)


async def _run(multi: MultiRemote, hostname: str, command: str, *, pinned: str | None = "ssh-ed25519 AAAA",
               check: bool = True, input: str | None = None) -> tuple[int, str]:
    async with multi.connect(_target(hostname, pinned)) as session:
        return await session.run(command, check=check, input=input)


# ------------------------------------------------------------------------------ addresses


async def test_hosts_are_found_by_address_and_by_name(multi):
    assert multi["10.0.0.11"] is multi["blue"] and multi[ADDRESSES["data"]] is multi["data"]
    assert "10.0.0.12" in multi and "green" in multi and "10.0.0.99" not in multi
    assert (await _run(multi, "10.0.0.11", "echo here"))[1].strip() == "here"
    assert (await _run(multi, "green", "echo there"))[1].strip() == "there"  # a name works as the hostname too
    assert multi.opened == ["10.0.0.11", "green"]
    assert [t.hostname for t in multi.targets] == ["10.0.0.11", "green"]
    with pytest.raises(ssh.SSHError, match=r"Could not connect to 10\.0\.0\.99:22"):
        await _run(multi, "10.0.0.99", "true")
    assert multi.opened == ["10.0.0.11", "green"]  # a failed connect opened nothing


async def test_a_host_added_later_has_its_own_folder_logs_and_shims(multi, tmp_path):
    droplet = multi.add("slipway-uat-blue", "203.0.113.10")
    assert multi["203.0.113.10"] is droplet and droplet.root == tmp_path / "host-slipway-uat-blue" / "root"
    code, out = await _run(multi, "203.0.113.10", "cloud-init status; echo $STATE")
    assert code == 0 and out.splitlines() == ["status: done", str(tmp_path / "host-slipway-uat-blue" / "state")]
    assert droplet.cloud_init() == ["status"] and multi["blue"].cloud_init() == []
    with pytest.raises(ValueError):
        multi.add("blue", "203.0.113.11")
    with pytest.raises(ValueError):
        multi.add("other", "203.0.113.10")


# ------------------------------------------------------------------------------ host keys


async def test_a_host_without_a_key_checks_no_pin(multi):
    # Phase 3's hosts carry a placeholder pin; the fake accepts any.
    assert multi.pinned_key("10.0.0.11") is None
    assert (await _run(multi, "10.0.0.11", "true", pinned="ssh-ed25519 AAAA"))[0] == 0
    assert (await _run(multi, "10.0.0.11", "true", pinned=None))[0] == 0


async def test_a_host_with_a_key_accepts_only_that_key(multi):
    key = multi.new_key("10.0.0.11")
    assert multi.pinned_key("10.0.0.11") == key and key.startswith("ssh-ed25519 ") and key.endswith("root@blue")
    assert (await _run(multi, "10.0.0.11", "true", pinned=key))[0] == 0
    # The comment isn't part of the key.
    assert (await _run(multi, "10.0.0.11", "true", pinned=" ".join(key.split()[:2]) + " slipway@x"))[0] == 0
    _private, other = ssh.generate_keypair("someone")
    with pytest.raises(ssh.HostKeyMismatch, match="does not match the pinned key"):
        await _run(multi, "10.0.0.11", "true", pinned=other)
    with pytest.raises(ssh.HostKeyNotPinned):
        await _run(multi, "10.0.0.11", "true", pinned=None)
    # A rebuilt machine presents another key: the old pin now fails, the new one works.
    multi.present_key("blue", other)
    with pytest.raises(ssh.HostKeyMismatch):
        await _run(multi, "10.0.0.11", "true", pinned=key)
    assert (await _run(multi, "10.0.0.11", "true", pinned=other))[0] == 0
    multi.present_key("blue", None)
    assert (await _run(multi, "10.0.0.11", "true", pinned=key))[0] == 0
    # Only blue changed.
    assert multi.pinned_key("10.0.0.12") is None and (await _run(multi, "10.0.0.12", "true"))[0] == 0


async def test_a_key_given_when_the_host_is_added(multi):
    _private, key = ssh.generate_keypair("root@slipway-uat-green")
    multi.add("slipway-uat-green", "203.0.113.12", host_key=key)
    assert multi.pinned_key("203.0.113.12") == key
    with pytest.raises(ssh.HostKeyMismatch):
        await _run(multi, "203.0.113.12", "true")
    assert (await _run(multi, "203.0.113.12", "true", pinned=key))[0] == 0


# -------------------------------------------------------------------- booting and firewalls


async def test_a_booting_host_refuses_its_first_connects(multi):
    multi.booting("10.0.0.12", 2)
    for _ in range(2):
        with pytest.raises(ssh.SSHError, match=r"Could not connect to 10\.0\.0\.12:22: .*Connect call failed"):
            await _run(multi, "10.0.0.12", "true")
    assert (await _run(multi, "10.0.0.12", "true"))[0] == 0
    assert (await _run(multi, "10.0.0.12", "true"))[0] == 0
    assert multi.opened == ["10.0.0.12", "10.0.0.12"] and len(multi.targets) == 4


async def test_a_firewalled_host_times_out_until_the_rule_lets_slipway_in(multi):
    multi.firewalled("10.0.0.13")
    for _ in range(3):
        with pytest.raises(ssh.SSHError, match=r"Could not connect to 10\.0\.0\.13:22: timed out"):
            await _run(multi, "10.0.0.13", "true")
    assert (await _run(multi, "10.0.0.11", "true"))[0] == 0  # only that host
    multi.firewalled("10.0.0.13", False)
    assert (await _run(multi, "10.0.0.13", "true"))[0] == 0
    assert multi.opened == ["10.0.0.11", "10.0.0.13"]
    # A firewall drop isn't a key problem, so it isn't a HostKeyMismatch, and it comes before the key check.
    multi.new_key("10.0.0.13")
    multi.firewalled("10.0.0.13")
    with pytest.raises(ssh.SSHError) as err:
        await _run(multi, "10.0.0.13", "true", pinned=None)
    assert not isinstance(err.value, (ssh.HostKeyMismatch, ssh.HostKeyNotPinned))


# ------------------------------------------------------------------------------- the shims


async def test_ssh_connection_names_slipways_address(multi):
    out = (await _run(multi, "10.0.0.11", "printf '%s' \"$SSH_CONNECTION\""))[1]
    assert out == f"{SLIPWAY_ADDRESS} 51234 10.0.0.11 22" and out.split()[0] == "198.51.100.7"
    multi.set_slipway_address("192.0.2.40")
    multi.add("slipway-uat-blue", "203.0.113.10")
    for hostname in ("10.0.0.11", "203.0.113.10"):
        out = (await _run(multi, hostname, "printf '%s' \"$SSH_CONNECTION\""))[1]
        assert out == f"192.0.2.40 51234 {hostname} 22"


async def test_cloud_init_status_in_each_form(multi):
    blue = multi["blue"]
    assert await _run(multi, "blue", "cloud-init status --wait") == (0, "status: done\n")
    code, out = await _run(multi, "blue", "cloud-init status --format json")
    assert code == 0 and json.loads(out)["status"] == "done" and json.loads(out)["errors"] == []
    code, out = await _run(multi, "blue", "cloud-init status --wait --format=json")
    assert json.loads(out)["extended_status"] == "done"

    blue.env["FAKE_CLOUD_INIT"] = "running"
    assert await _run(multi, "blue", "cloud-init status") == (0, "status: running\n")
    assert (await _run(multi, "blue", "cloud-init status --wait"))[1].splitlines()[-1] == "status: done"

    blue.env["FAKE_CLOUD_INIT"] = "degraded"
    code, out = await _run(multi, "blue", "cloud-init status --wait --format json", check=False)
    assert code == 2 and json.loads(out)["status"] == "done" and json.loads(out)["extended_status"] == "degraded done"

    blue.env["FAKE_CLOUD_INIT"] = "error"
    blue.env["FAKE_CLOUD_INIT_ERROR"] = "Failed to install packages: ['docker.io']"
    code, out = await _run(multi, "blue", "cloud-init status --wait", check=False)
    assert code == 1 and out.splitlines() == ["status: error", "errors: Failed to install packages: ['docker.io']"]
    code, out = await _run(multi, "blue", "cloud-init status --format json", check=False)
    assert code == 1 and json.loads(out)["errors"] == ["Failed to install packages: ['docker.io']"]
    # P4 §9.2 step 9's readiness line runs it with its output thrown away; the exit code still tells.
    assert (await _run(multi, "blue", "cloud-init status --wait >/dev/null 2>&1", check=False))[0] == 1

    assert blue.cloud_init()[:3] == ["status --wait", "status --format json", "status --wait --format=json"]
    assert len(blue.cloud_init()) == 9 and multi["green"].cloud_init() == []


CA_B64 = base64.b64encode(b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n").decode()
ADMIN_PASSWORD = "doadmin-Pa55word-0123456789"


def _psql(sql: str) -> tuple[str, str]:
    """P4's managed-database command and its stdin (do_rules), as the database step sends them."""
    command = do_rules.psql_command(host="db-uat.example.ondigitalocean.com", port=25060, version="16")
    return command, do_rules.psql_stdin(admin_password=ADMIN_PASSWORD, ca_b64=CA_B64, sql=sql)


async def test_psql_records_the_sql_it_reads_never_the_password(multi):
    blue = multi["blue"]
    setup = do_rules.setup_sql("serversherpa", "serversherpa",
                               verifier=do_rules.scram_sha256("app-password", salt=b"0" * 16))
    command, stdin = _psql(setup)
    code, out = await _run(multi, "blue", command, input=stdin)
    assert code == 0 and out.strip() == "1"
    assert blue.sql() == [setup.rstrip("\n")]
    logs = "".join(blue.root.parent.joinpath(f).read_text() for f in ("psql.log", "docker.log"))
    assert ADMIN_PASSWORD not in logs and CA_B64 not in logs
    [line] = [d for d in blue.docker() if "psql" in d]
    assert "postgres:16-alpine" in line and ADMIN_PASSWORD not in line

    # Phase 3's probe: the password line is read by its shell, so psql reads nothing and nothing is recorded.
    probe = traffic.probe_command(host="10.0.0.13", port=5432, database="demo", user="demo")
    code, out = await _run(multi, "blue", probe, input="probe-password\n")
    assert code == 0 and out.strip() == "1" and len(blue.sql()) == 1
    assert any(d.startswith("probe: PGPASSWORD set (14 characters)") for d in blue.docker())

    # $FAKE_PSQL still fails every run.
    blue.env["FAKE_PSQL"] = 'psql: error: connection to server failed: FATAL:  password authentication failed'
    code, out = await _run(multi, "blue", command, input=stdin, check=False)
    assert code == 2 and "password authentication failed" in out


async def test_psql_can_fail_right_after_the_drop(multi, tmp_path):
    blue = multi["blue"]
    reset = do_rules.reset_sql("serversherpa", "serversherpa")
    command, stdin = _psql(reset)
    flag = tmp_path / "drop-fails"
    flag.write_text("")
    blue.env["FAKE_PSQL_DROP_FAILS"] = str(flag)
    code, out = await _run(multi, "blue", command, input=stdin, check=False)
    assert code == 2 and "server closed the connection unexpectedly" in out
    [cut] = blue.sql()
    assert cut.splitlines() == [reset.splitlines()[0], "-- cut"] and "CREATE DATABASE" not in cut
    assert not flag.exists()
    # The retry runs the whole script.
    code, _ = await _run(multi, "blue", command, input=stdin)
    assert code == 0 and blue.sql()[1] == reset.rstrip("\n")
    # Without the flag file a DROP passes the first time.
    code, _ = await _run(multi, "blue", command, input=stdin)
    assert code == 0 and len(blue.sql()) == 3


async def test_clear_empties_every_log(multi):
    await _run(multi, "blue", "cloud-init status")
    command, stdin = _psql("SELECT 1;\n")
    await _run(multi, "blue", command, input=stdin)
    assert multi["blue"].cloud_init() and multi["blue"].sql() and multi.targets
    multi.clear()
    assert not multi["blue"].cloud_init() and not multi["blue"].sql() and not multi["blue"].docker()
    assert not multi.opened and not multi.targets
