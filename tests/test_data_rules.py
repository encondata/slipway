"""services.data: backup names, the host-side shell snippets (run in real shells), retention, what can be
restored (§9.2), the identity fingerprint and overrides, roll back, retry inheritance and the queue checks."""

from __future__ import annotations

import asyncio
import hashlib
import os
import shlex
import shutil
import signal
import subprocess
import uuid
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from slipway.db.session import get_sessionmaker
from slipway.models import Backup, Deployment, Host, Instance, Repository, Snapshot
from slipway.services import data, ssh

SHELLS = [s for s in ("sh", "dash", "bash", "zsh") if shutil.which(s)]
SHA = "0123456789abcdef0123456789abcdef01234567"
SHA2 = "fedcba9876543210fedcba9876543210fedcba98"
KEY_A = "aa" * 32
KEY_B = "bb" * 32
T0 = datetime(2026, 11, 15, 10, 15, 0, tzinfo=UTC)

MANIFEST = {
    "capabilities": ["backup", "verify", "restore", "files", "reset", "snapshot", "seed", "first_admin"],
    "data": {"app": "shop", "format": "pg-custom", "identity_label": "sign-in keys",
             "identity_help": "People sign in with the keys the data was made with."},
    "secrets": [{"key": "APP_KEY", "kind": "hex", "identity": True}, {"key": "JWT", "kind": "hex", "identity": False}],
}


class Shell:
    """A RemoteSession stand-in that runs each command in ``shell`` on this machine, as sshd would."""

    def __init__(self, shell: str = "sh", env: dict[str, str] | None = None) -> None:
        self.shell, self.env = shell, env
        self.commands: list[str] = []

    async def run(self, command, *, check=True, on_line=None, timeout=None):
        self.commands.append(command)
        result = await asyncio.to_thread(subprocess.run, [self.shell, "-c", command], env=self.env,
                                         capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)
        output = result.stdout + result.stderr
        if check and result.returncode:
            raise ssh.CommandFailed(command, result.returncode, output)
        return result.returncode, output


class Broken:
    async def run(self, command, **kw):
        raise ssh.SSHError("Connection lost")


def run_in(shell: str, command: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([shell, "-c", command], env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                          timeout=60)


# --------------------------------------------------------------------- names


def test_backup_names_follow_the_pattern_and_anything_else_is_refused():
    bid = uuid.UUID("1a2b3c4d-0000-4000-8000-000000000000")
    name = data.backup_name(bid, datetime(2026, 11, 15, 12, 15, tzinfo=timezone(timedelta(hours=1))))
    assert name == "20261115T111500Z-1a2b3c4d"
    assert data.NAME_RE.match(name)
    assert data.FILE_RE.match(f"{name}.dump") and data.FILE_RE.match(f"{name}.json")
    assert not data.FILE_RE.match(f"{name}.dump.partial")
    assert data.backup_file("/srv/a/backups", name, "files") == f"/srv/a/backups/{name}.files"
    assert data.partial_file("/srv/a/backups", name, "dump") == f"/srv/a/backups/.incoming/{name}.dump.partial"
    for bad in ("../etc/passwd", "20261115T111500Z-1A2B3C4D", f"{name} ", "x; rm -rf /", f"{name}/..", ""):
        with pytest.raises(data.DataError):
            data.check_name(bad)
        with pytest.raises(data.DataError):
            data.backup_file("/b", bad, "dump")
    with pytest.raises(data.DataError):
        data.file_check_command("/b", ["../x.dump"])
    with pytest.raises(data.DataError):
        data.remove_backup_command("/b", ["*"])


def test_short_revisions_sizes_and_docker_sizes():
    assert data.revision_short(None) is None
    assert data.revision_short("0042\n") == "0042"
    assert data.revision_short("[X] shop.0001_initial\n[X] shop.0002_more\n\n") == "[X] shop.0002_more"
    assert len(data.revision_short("x" * 100)) == data.REVISION_SHORT_CHARS
    assert data.human_bytes(812 * data.MIB) == "812 MiB"
    assert data.human_bytes(int(1.9 * 1024 * data.MIB)) == "1.9 GiB"
    # The same wording as the Snapshots page (snapshots.human_bytes is this function).
    assert data.human_bytes(20 * 1024 * data.MIB) == "20 GiB" and data.human_bytes(1536) == "1.5 KiB"
    assert data.human_bytes(512) == "512 bytes" and data.human_bytes(None) == "an unknown size"
    assert data.parse_docker_size("1.5GB") == 1_500_000_000
    assert data.parse_docker_size("512kB") == 512_000
    assert data.parse_docker_size("0B") == 0
    assert data.parse_docker_size("2MiB") == 2 * data.MIB
    assert data.parse_docker_size("N/A") is None
    assert data.parse_volume_sizes("shop_pgdata 1.5GB\nother 10MB\ngarbage\n") == {"shop_pgdata": 1_500_000_000,
                                                                                  "other": 10_000_000}


def test_estimate_uses_the_last_backup_then_the_volumes_then_a_fallback():
    vols = [{"name": "db", "holds": "database"}, {"name": "objs", "holds": "files"}, {"name": "x", "holds": "other"}]
    assert data.estimate_backup(last_db_bytes=800, last_files_bytes=200, include_files=True, volumes=vols,
                                volume_sizes=None).bytes == 1250
    assert data.estimate_backup(last_db_bytes=800, last_files_bytes=200, include_files=False, volumes=vols,
                                volume_sizes=None).bytes == 1000
    first = data.estimate_backup(last_db_bytes=None, last_files_bytes=None, include_files=True, volumes=vols,
                                 volume_sizes={"db": 400, "objs": 400, "x": 10_000})
    assert first.bytes == 1000 and first.notes == []
    fallback = data.estimate_backup(last_db_bytes=None, last_files_bytes=None, include_files=False, volumes=vols,
                                    volume_sizes=None)
    assert fallback.bytes == int(data.FALLBACK_ESTIMATE * 1.25) and "256 MiB" in fallback.notes[0]


def test_free_space_refusal_names_what_is_free_and_what_is_needed():
    estimate = int(0.9 * 1024 * data.MIB)  # + the 1024 MiB margin: about 1.9 GiB
    assert data.free_space_problem(free_kb=812 * 1024, estimate=estimate, where="/srv/shop/backups", host="prod-01") == (
        "Only 812 MiB is free in /srv/shop/backups on prod-01; the backup needs about 1.9 GiB. Free some space "
        "(old backups are on the Backups card) and retry. Nothing was changed.")
    assert data.free_space_problem(free_kb=10 * 1024 * 1024, estimate=estimate, where="/b", host="h") is None


# --------------------------------------------------------- shell, in real shells


def _file(path: Path, content: bytes) -> str:
    path.write_bytes(content)
    return hashlib.sha256(content).hexdigest()


@pytest.mark.parametrize("shell", SHELLS)
def test_file_check_reports_sizes_hashes_links_and_a_missing_folder(shell, tmp_path):
    backups = tmp_path / "back ups"
    backups.mkdir()
    a, b, c = "20261115T101500Z-aaaaaaaa", "20261115T101500Z-bbbbbbbb", "20261115T101500Z-cccccccc"
    sha_a = _file(backups / f"{a}.dump", b"DB: hello")
    (tmp_path / "elsewhere").write_bytes(b"not a backup")
    (backups / f"{c}.dump").symlink_to(tmp_path / "elsewhere")
    command = data.file_check_command(str(backups), [f"{b}.dump", f"{c}.dump"], hashed=[f"{a}.dump"])
    found = data.parse_file_check(run_in(shell, command).stdout)
    assert not found.nodir
    assert found.sizes == {f"{a}.dump": 9, f"{b}.dump": None, f"{c}.dump": None}  # a link is never a backup
    assert found.shas == {f"{a}.dump": sha_a}
    nodir = data.parse_file_check(run_in(shell, data.file_check_command(str(tmp_path / "gone"), [f"{a}.dump"])).stdout)
    assert nodir.nodir and nodir.sizes == {}


@pytest.mark.parametrize("shell", SHELLS)
def test_sha_and_free_space_commands(shell, tmp_path):
    target = tmp_path / "some file"
    expected = _file(target, b"x" * 10_000)
    assert data.parse_sha(run_in(shell, data.sha_command(str(target))).stdout) == expected
    assert data.parse_sha(run_in(shell, data.sha_command(str(tmp_path / "missing"))).stdout) is None
    free = data.parse_free_kb(run_in(shell, data.free_space_command(str(tmp_path))).stdout)
    assert isinstance(free, int) and free > 0


def test_sha_falls_back_to_openssl_and_says_nothing_without_a_tool(tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("no openssl")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("sed", "cat"):
        (bin_dir / tool).symlink_to(shutil.which(tool))
    (bin_dir / "openssl").symlink_to(shutil.which("openssl"))
    target = tmp_path / "f"
    expected = _file(target, b"payload")
    env = {"PATH": str(bin_dir)}
    sh = shutil.which("sh")
    assert data.parse_sha(run_in(sh, data.sha_command(str(target)), env).stdout) == expected
    (bin_dir / "openssl").unlink()
    assert data.parse_sha(run_in(sh, data.sha_command(str(target)), env).stdout) is None


@pytest.mark.parametrize("shell", SHELLS)
def test_partial_check_refuses_empty_files_and_links_and_makes_good_ones_private(shell, tmp_path):
    good = tmp_path / "n.dump.partial"
    expected = _file(good, b"DB: data")
    good.chmod(0o644)
    found = data.parse_file_check(run_in(shell, data.partial_check_command(str(good))).stdout)
    assert found.sizes == {"n.dump.partial": 8} and found.shas == {"n.dump.partial": expected}
    assert good.stat().st_mode & 0o777 == 0o600
    empty = tmp_path / "e.dump.partial"
    empty.write_bytes(b"")
    assert f"{data.BK_MARK} empty e.dump.partial" in run_in(shell, data.partial_check_command(str(empty))).stdout
    link = tmp_path / "l.dump.partial"
    link.symlink_to(good)
    assert f"{data.BK_MARK} empty" in run_in(shell, data.partial_check_command(str(link))).stdout
    assert data.empty_output_message("dump", str(empty)) == f"commands.dump exited 0 but wrote nothing to {empty}"


@pytest.mark.parametrize("shell", SHELLS)
def test_backups_folder_is_prepared_private_and_partials_are_removed_by_name(shell, tmp_path):
    backups = tmp_path / "backups"
    assert run_in(shell, data.prepare_backups_command(str(backups))).returncode == 0
    assert (backups / ".incoming").is_dir()
    assert backups.stat().st_mode & 0o777 == 0o700 and (backups / ".incoming").stat().st_mode & 0o777 == 0o700
    name = "20261115T101500Z-aaaaaaaa"
    other = "20261115T101500Z-aaaaaaab"
    for f in (f"{name}.dump.partial", f"{name}.files.partial", f"{other}.dump.partial", f"{name}.keep"):
        (backups / ".incoming" / f).write_text("x")
    assert run_in(shell, data.discard_partials_command(str(backups), name)).returncode == 0
    assert sorted(p.name for p in (backups / ".incoming").iterdir()) == sorted([f"{other}.dump.partial", f"{name}.keep"])
    final = data.backup_file(str(backups), name, "dump")
    (backups / ".incoming" / f"{name}.dump.partial").write_text("DB: x")
    assert run_in(shell, data.finalize_command({data.partial_file(str(backups), name, "dump"): final})).returncode == 0
    assert Path(final).read_text() == "DB: x"
    assert run_in(shell, data.empty_incoming_command(str(backups))).returncode == 0
    assert not (backups / ".incoming").exists() and Path(final).exists()
    # A link where the folder should be is refused, not followed.
    linked = tmp_path / "linked"
    linked.symlink_to(tmp_path / "elsewhere")
    result = run_in(shell, data.prepare_backups_command(str(linked)))
    assert result.returncode == 1 and f"{data.BK_MARK} link" in result.stdout


DOCKER = """#!/bin/sh
case "$1 $2" in
  "volume ls")
    [ -n "$FAKE_NO_DOCKER" ] && { echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock" >&2; exit 1; }
    cut -d' ' -f1 "$FAKE_VOLUME_FILE" ;;
  "volume inspect")
    v="$6"; grep "^$v " "$FAKE_VOLUME_FILE" | cut -d' ' -f2 ;;
esac
"""


@pytest.fixture
def docker(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text(DOCKER)
    (bin_dir / "docker").chmod(0o755)
    volumes = tmp_path / "volumes"
    volumes.write_text("shop-uat_pgdata shop-uat\nloose \n")
    return {"PATH": f"{bin_dir}:{os.environ['PATH']}", "FAKE_VOLUME_FILE": str(volumes)}


@pytest.mark.parametrize("shell", SHELLS)
def test_volume_probe_reports_labels_and_refuses_when_docker_does_not_answer(shell, docker):
    command = data.volume_probe_command(["shop-uat_pgdata", "shop-uat_objects", "loose"])
    probe = data.parse_volume_probe(run_in(shell, command, docker).stdout + run_in(shell, command, docker).stderr,
                                    host="prod-01")
    assert probe.present == {"shop-uat_pgdata": "shop-uat", "loose": ""}
    assert probe.absent == ["shop-uat_objects"]
    vols = [{"name": "shop-uat_pgdata", "holds": "database"}, {"name": "shop-uat_objects", "holds": "files"},
            {"name": "loose", "holds": "other"}]
    here = data.volumes_result(probe, vols, host="prod-01")
    assert here.state == "here" and here.present == ["shop-uat_pgdata"]
    empty = data.volumes_result(data.VolumeProbe(present={"loose": ""}, absent=[]), vols, host="prod-01")
    assert empty.state == "empty" and empty.reason == "shop-uat_pgdata, shop-uat_objects are not on prod-01"
    result = run_in(shell, command, {**docker, "FAKE_NO_DOCKER": "1"})
    assert result.returncode == 1
    with pytest.raises(data.DataError) as err:
        data.parse_volume_probe(result.stdout + result.stderr, host="prod-01")
    assert str(err.value) == ("Couldn't check prod-01 for the app's data: docker didn't answer "
                              "(Cannot connect to the Docker daemon at unix:///var/run/docker.sock)")
    with pytest.raises(data.DataError):
        data.volume_probe_command(["$(reboot)"])


def test_has_data_answers_and_the_reset_label_check():
    assert data.has_data_result(0, name="shop").state == "here"
    assert data.has_data_result(3, name="shop").state == "empty"
    assert data.has_data_result(4, name="shop").state == "elsewhere"
    with pytest.raises(data.DataError) as err:
        data.has_data_result(1, name="shop")
    assert str(err.value) == "commands.has_data exited 1; Slipway can't tell whether shop has data. Nothing was changed."
    assert data.foreign_volume({"a": "shop-uat"}, ["shop-uat"]) is None
    assert data.foreign_volume({"a": "other"}, ["shop-uat"]) == (
        "The volume a belongs to the Compose project other, not to this app; Slipway won't delete it. Nothing was deleted.")
    assert "no Compose project label" in data.foreign_volume({"a": ""}, ["shop-uat"])


@pytest.mark.parametrize("shell", SHELLS)
def test_lock_names_a_live_data_command_and_is_taken_over_once_it_ended(shell, tmp_path):
    lock = str(tmp_path / ".slipway-lock")
    holder, me = uuid.uuid4(), uuid.uuid4()
    proc = subprocess.Popen([shell, "-c", data.lock_line_command(lock, holder, "restore", data=True) + " && exec sleep 30"],
                            stdin=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if Path(lock).exists() and Path(lock).read_text().strip():
                break
            subprocess.run(["sleep", "0.05"])
        line = Path(lock).read_text().split()
        assert line[0] == str(holder) and line[2] == str(proc.pid) and line[3:] == ["restore", "d"]
        held = data.parse_lock(run_in(shell, data.lock_read_command(lock, me)).stdout)
        assert held is not None and held.alive and held.data and held.job == holder.hex[:8]
        with pytest.raises(data.DataError) as err:
            data.lock_verdict(held, host="prod-01")
        assert str(err.value) == (
            f"Job {holder.hex[:8]}'s restore (pid {proc.pid}) is still running on prod-01; Slipway lost track of it when "
            f"it restarted or the command timed out. Wait for it to end and retry, or stop it (kill {proc.pid}) and retry.")
        assert data.lock_verdict(held, host="prod-01", take_over=True).startswith("Warning: took over the lock")
        # The job's own lock never blocks it.
        assert data.parse_lock(run_in(shell, data.lock_read_command(lock, holder)).stdout) is None
        # Releasing as another job leaves it in place.
        run_in(shell, data.lock_release_command(lock, me))
        assert Path(lock).exists()
    finally:
        proc.send_signal(signal.SIGKILL)
        proc.wait()
    ended = data.parse_lock(run_in(shell, data.lock_read_command(lock, me)).stdout)
    assert ended is not None and not ended.alive
    assert data.lock_verdict(ended, host="prod-01") == f"Took over the lock of job {holder.hex[:8]} (its restore has ended)"
    run_in(shell, data.lock_release_command(lock, holder))
    assert not Path(lock).exists()
    assert data.parse_lock(run_in(shell, data.lock_read_command(lock, me)).stdout) is None


def _busybox_ps(tmp_path: Path) -> dict[str, str]:
    """An environment whose ``ps`` acts like BusyBox's: no ``-p``, so it prints its usage and exits 1."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "ps"
    fake.write_text("#!/bin/sh\necho 'Usage: ps [-o COL1,COL2=HEADER] [-T]' >&2\nexit 1\n")
    fake.chmod(0o755)
    return {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}


def _write_lock(lock: str, holder: uuid.UUID, pid: int) -> None:
    Path(lock).write_text(f"{holder} - {pid} restore d\n")


@pytest.mark.parametrize("shell", SHELLS)
def test_a_live_holder_stays_alive_where_ps_has_no_p(shell, tmp_path):
    lock, holder, me = str(tmp_path / ".slipway-lock"), uuid.uuid4(), uuid.uuid4()
    env = _busybox_ps(tmp_path)
    proc = subprocess.Popen(["sleep", "30"], stdin=subprocess.DEVNULL)
    try:
        _write_lock(lock, holder, proc.pid)
        held = data.parse_lock(run_in(shell, data.lock_read_command(lock, me), env=env).stdout)
        assert held is not None and held.alive and held.data
        with pytest.raises(data.DataError):
            data.lock_verdict(held, host="prod-01")
        # Checking sends no signal: the holder is still running.
        assert proc.poll() is None
    finally:
        proc.kill()
        proc.wait()
    ended = data.parse_lock(run_in(shell, data.lock_read_command(lock, me)).stdout)
    assert ended is not None and not ended.alive


@pytest.mark.skipif(Path("/proc/self").exists(), reason="the host has /proc, so liveness can always be checked")
@pytest.mark.parametrize("shell", SHELLS)
def test_a_holder_counts_as_alive_when_nothing_can_check(shell, tmp_path):
    lock, holder, me = str(tmp_path / ".slipway-lock"), uuid.uuid4(), uuid.uuid4()
    gone = subprocess.Popen(["true"])
    gone.wait()
    _write_lock(lock, holder, gone.pid)
    # No /proc and no usable ps -p: an ended holder can't be told apart from one owned by someone else.
    held = data.parse_lock(run_in(shell, data.lock_read_command(lock, me), env=_busybox_ps(tmp_path)).stdout)
    assert held is not None and held.alive
    # With a working ps -p the same holder is seen to have ended.
    assert not data.parse_lock(run_in(shell, data.lock_read_command(lock, me)).stdout).alive


def _busybox_image() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        found = subprocess.run(["docker", "image", "inspect", "busybox:1.36"], capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return False
    return found.returncode == 0


@pytest.mark.skipif(not _busybox_image(), reason="needs docker and the busybox:1.36 image")
def test_lock_liveness_on_busybox(tmp_path):
    holder, me = uuid.uuid4(), uuid.uuid4()
    lock = "/tmp/.slipway-lock"
    script = (
        f"sh -c {shlex.quote(data.lock_line_command(lock, holder, 'restore', data=True) + ' && exec sleep 30')} & pid=$!; "
        f"while [ ! -s {lock} ]; do sleep 0.05; done; "
        f"{data.lock_read_command(lock, me)}; "
        'kill -0 "$pid" && echo still-running; kill "$pid"; wait "$pid"; '
        f"{data.lock_read_command(lock, me)}"
    )
    result = subprocess.run(["docker", "run", "--rm", "--pull", "never", "--network", "none", "busybox:1.36",
                             "sh", "-c", script], capture_output=True, text=True, timeout=120)
    lines = [line for line in result.stdout.splitlines() if line.startswith(data.LOCK_MARK)]
    assert len(lines) == 2, result.stdout + result.stderr
    live, ended = (data.parse_lock(line) for line in lines)
    assert live is not None and live.alive and live.data and live.pid.isdigit()
    assert "still-running" in result.stdout
    assert ended is not None and not ended.alive


def test_a_live_plain_command_only_warns():
    held = data.HeldLock(deployment=str(uuid.UUID(int=5)), boot="-", pid="42", key="start", data=False, alive=True)
    assert data.lock_verdict(held, host="h") == f"Warning: job {uuid.UUID(int=5).hex[:8]}'s start (pid 42) may still be running on h"


# ---------------------------------------------------------------- identity keys


def test_fingerprint_is_stable_salted_and_order_free():
    a, b = uuid.uuid4(), uuid.uuid4()
    fp = data.identity_fp(a, ["APP_KEY", "PEPPER"], {"APP_KEY": KEY_A, "PEPPER": KEY_B})
    assert fp == data.identity_fp(a, ["PEPPER", "APP_KEY"], {"PEPPER": KEY_B, "APP_KEY": KEY_A, "OTHER": "x"})
    assert fp != data.identity_fp(b, ["APP_KEY", "PEPPER"], {"APP_KEY": KEY_A, "PEPPER": KEY_B})  # salted per row
    assert fp != data.identity_fp(a, ["APP_KEY", "PEPPER"], {"APP_KEY": KEY_B, "PEPPER": KEY_B})
    assert data.identity_fp(a, ["APP_KEY"], {}) != data.identity_fp(a, ["APP_KEY"], {"APP_KEY": ""})
    assert KEY_A not in fp and len(fp) == 64


def test_override_and_its_validation():
    assert data.restore_override({"APP_KEY": KEY_B, "GONE": "x", "JWT": "y"}, ["APP_KEY", "JWT"],
                                 {"APP_KEY": KEY_A, "JWT": "y"}) == {"APP_KEY": KEY_B}
    assert data.rendered_identity({"APP_KEY": KEY_A, "JWT": "z"}, ["APP_KEY", "MISSING"]) == {"APP_KEY": KEY_A}
    fernet = "A" * 43 + "="
    assert data.identity_value_ok(KEY_A, "hex") and not data.identity_value_ok("AA" * 32, "hex")
    assert not data.identity_value_ok("ab" * 8 + "a", "hex") and not data.identity_value_ok("ab" * 15, "hex")
    assert data.identity_value_ok(fernet, "fernet") and not data.identity_value_ok("A" * 44, "fernet")
    assert data.identity_value_ok("tok_" + "x" * 20, "token") and not data.identity_value_ok("short", "token")
    assert not data.identity_value_ok(KEY_A + "\n", "hex")
    assert not data.identity_value_ok(KEY_A, "hex", placeholder=KEY_A)
    data.check_override({"APP_KEY": KEY_B}, MANIFEST)
    with pytest.raises(data.DataError) as err:
        data.check_override({"APP_KEY": "nope"}, MANIFEST)
    assert str(err.value) == "The snapshot's APP_KEY isn't a valid hex key"
    assert data.env_pinned({"APP_KEY": KEY_B, "B": "x"}, {"APP_KEY": KEY_A}) == ["APP_KEY"]


def test_override_refuses_the_placeholder_of_a_stored_manifest():
    """check_override reads the placeholder from what Manifest.to_json stored for the live release."""
    from slipway.services import manifest

    text = (
        "version: 1\nname: Shop\nplaceholder: " + KEY_B + "\nsecrets:\n  APP_KEY: {kind: hex, identity: true}\n"
        "commands:\n  start: [up]\n"
    )
    stored = manifest.parse(text).to_json()
    assert stored["placeholder"] == KEY_B
    data.check_override({"APP_KEY": KEY_A}, stored)
    with pytest.raises(data.DataError) as err:
        data.check_override({"APP_KEY": KEY_B}, stored)
    assert str(err.value) == "The snapshot's APP_KEY isn't a valid hex key"


# ----------------------------------------------------------------- database rows


async def _instance(**fields) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        host = Host(name="prod-01", hostname="10.0.0.1", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
        repo = Repository(github_id=42, full_name="acme/shop", owner="acme", name="shop",
                          html_url="https://github.com/acme/shop", detected_config={})
        values = dict(
            name="shop", slug="shop", branch="main", host=host, repository=repo, build_source="app", status="running",
            current_commit_sha=SHA, live_identity={"APP_KEY": KEY_A}, env={},
            app_state={"manifest": MANIFEST, "live": {"release": f"{SHA[:12]}-11111111", "deployment": "11" * 16,
                                                      "sha": SHA, "projects": ["shop-uat"], "volumes": []}},
        )
        values.update(fields)
        inst = Instance(**values)
        db.add(inst)
        await db.commit()
        return inst.id


async def _load(db, instance_id) -> Instance:
    return await db.get(Instance, instance_id, populate_existing=True)


def _backup(instance_id, *, at=T0, reason="pre_deploy", status="ready", identity=None, size=10, **kw) -> Backup:
    bid = uuid.uuid4()
    identity = {"APP_KEY": KEY_A} if identity is None else identity
    return Backup(id=bid, instance_id=instance_id, name=data.backup_name(bid, at), reason=reason, status=status,
                  format=kw.pop("format", "pg-custom"), db_bytes=size, identity_keys=sorted(identity), identity=identity,
                  identity_fp=data.identity_fp(bid, identity, identity), taken_at=at, **kw)


def _job(instance_id, kind="deploy", status="failed", *, at=T0, steps=None, **kw) -> Deployment:
    return Deployment(id=kw.pop("id", uuid.uuid4()), instance_id=instance_id, kind=kind, status=status, branch="main",
                      commit_sha=kw.pop("commit_sha", SHA2), created_at=at, finished_at=at + timedelta(minutes=1),
                      steps=steps or [], **kw)


def _rows(**status) -> list[dict]:
    return [{"key": k, "name": k.title(), "status": s} for k, s in status.items()]


async def test_latest_changing_job_ignores_backups_and_snapshots():
    iid = await _instance()
    async with get_sessionmaker()() as db:
        deploy = _job(iid, "deploy", at=T0)
        db.add_all([deploy, _job(iid, "backup", "succeeded", at=T0 + timedelta(minutes=5)),
                    _job(iid, "snapshot", "failed", at=T0 + timedelta(minutes=6))])
        await db.commit()
        assert (await data.latest_changing_job(db, iid)).id == deploy.id
        admin = _job(iid, "admin", "succeeded", at=T0 + timedelta(minutes=7))
        db.add(admin)
        await db.commit()
        assert (await data.latest_changing_job(db, await _load(db, iid))).id == admin.id


async def test_retention_keeps_manual_pinned_and_two_dirty_and_rm_only_confirmed_files(tmp_path):
    iid = await _instance(keep_backups=2)
    backups = tmp_path / "backups"
    backups.mkdir()
    async with get_sessionmaker()() as db:
        clean = [_backup(iid, at=T0 + timedelta(hours=i)) for i in range(6)]
        manual = [_backup(iid, at=T0 - timedelta(days=i + 1), reason="manual") for i in range(3)]
        dirty_job = _job(iid, "deploy", at=T0 + timedelta(hours=10))
        db.add(dirty_job)
        await db.flush()
        dirty = [_backup(iid, at=T0 + timedelta(hours=20 + i), reason="pre_deploy", dirty_of=dirty_job.id)
                 for i in range(4)]
        missing = _backup(iid, at=T0 - timedelta(days=30), status="missing")
        rows = [*clean, *manual, *dirty, missing]
        db.add_all(rows)
        await db.flush()
        # The roll back point (first) and the latest changing job's backup are pinned.
        inst = await _load(db, iid)
        inst.data_dirty = {"first": {"deployment_id": dirty_job.id.hex, "kind": "deploy",
                                     "backup_id": clean[0].id.hex, "at": T0.isoformat()},
                           "last": {"deployment_id": dirty_job.id.hex, "kind": "deploy", "step": "start",
                                    "backup_id": clean[0].id.hex, "at": T0.isoformat()}, "hold": False}
        latest = _job(iid, "restore", at=T0 + timedelta(hours=30), backup_id=clean[1].id, restore_backup_id=clean[2].id)
        db.add(latest)
        await db.commit()
        for row in rows:
            for part in ("dump", "json"):
                (backups / f"{row.name}.{part}").write_bytes(b"x" * (row.db_bytes if part == "dump" else 3))
        # clean[3] changed size on the host since: it must not be removed, and is marked changed.
        (backups / f"{clean[3].name}.dump").write_bytes(b"y" * 99)
        (backups / "not-ours.dump").write_text("keep me")
        said: list[str] = []

        async def say(line):
            said.append(line)

        remote = Shell("sh")
        removed = await data.apply_retention(remote, db, await _load(db, iid), str(backups), just_taken=dirty[0].id,
                                             say=say)
        await db.commit()
        # Clean, unpinned: clean[5], clean[4] kept (keep 2); clean[3] changed; pinned: clean[0..2].
        # Dirty: dirty[0] just taken (pinned), then dirty[3], dirty[2] kept; dirty[1] removed.
        assert sorted(removed) == sorted([dirty[1].name])
        left = {r.name: r.status for r in (await db.scalars(select(Backup).where(Backup.instance_id == iid))).all()}
        assert dirty[1].name not in left
        assert left[clean[3].name] == "changed"
        assert all(left[r.name] == "ready" for r in (*clean[:3], *clean[4:], *manual))
        assert left[missing.name] == "missing"
        on_disk = {p.name for p in backups.iterdir()}
        assert f"{dirty[1].name}.dump" not in on_disk and f"{dirty[1].name}.json" not in on_disk
        assert {f"{clean[3].name}.dump", f"{missing.name}.dump", "not-ours.dump"} <= on_disk
        assert said == [f"Removed old backups: {dirty[1].name} (keeping the newest 2)"]
        # The rm only names files the check had just confirmed.
        rm = next(c for c in remote.commands if c.startswith("rm -f"))
        assert clean[3].name not in rm and missing.name not in rm


def test_choose_doomed_counts_only_unpinned_ready_automatic_backups():
    iid = uuid.uuid4()
    rows = [_backup(iid, at=T0 + timedelta(hours=i)) for i in range(4)]
    pending = _backup(iid, at=T0 - timedelta(hours=1), status="pending")
    assert data.choose_doomed([*rows, pending], [], 2) == [rows[1], rows[0]]
    assert data.choose_doomed(rows, [rows[3].id], 2) == [rows[0]]


async def test_retention_failure_only_warns():
    iid = await _instance(keep_backups=1)
    async with get_sessionmaker()() as db:
        db.add_all([_backup(iid, at=T0 + timedelta(hours=i)) for i in range(3)])
        await db.commit()
        said: list[str] = []

        async def say(line):
            said.append(line)

        assert await data.apply_retention(Broken(), db, await _load(db, iid), "/nowhere", just_taken=None, say=say) == []
        assert said[0].startswith("Warning: couldn't remove old backups: Couldn't check the backups on prod-01")
        assert len((await db.scalars(select(Backup))).all()) == 3


async def test_host_check_marks_missing_changed_and_reappeared_rows_and_a_missing_folder_changes_nothing(tmp_path):
    iid = await _instance()
    backups = tmp_path / "backups"
    backups.mkdir()
    async with get_sessionmaker()() as db:
        ok = _backup(iid, at=T0)
        gone = _backup(iid, at=T0 + timedelta(hours=1))
        resized = _backup(iid, at=T0 + timedelta(hours=2))
        back = _backup(iid, at=T0 + timedelta(hours=3), status="missing")
        pending = _backup(iid, at=T0 + timedelta(hours=4), status="pending")
        db.add_all([ok, gone, resized, back, pending])
        await db.commit()
        for row in (ok, back):
            (backups / f"{row.name}.dump").write_bytes(b"x" * 10)
        (backups / f"{resized.name}.dump").write_bytes(b"x" * 11)
        rows = [ok, gone, resized, back, pending]
        nodir = await data.check_backups(Shell("sh"), db, rows, str(tmp_path / "nope"), "prod-01")
        assert nodir.warning == f"{tmp_path / 'nope'} isn't on prod-01; showing what Slipway recorded"
        assert nodir.statuses == {}
        found = await data.check_backups(Shell("sh"), db, rows, str(backups), "prod-01")
        await db.commit()
        assert found.warning is None
        assert found.statuses == {ok.id: "ready", gone.id: "missing", resized.id: "changed", back.id: "ready"}
        fresh = {r.id: (r.status, r.checked_at) for r in (await db.scalars(select(Backup))).all()}
        assert fresh[pending.id] == ("pending", None) and fresh[back.id][0] == "ready" and fresh[gone.id][1] is not None


async def test_confirm_rehashes_and_refuses_a_changed_or_missing_backup(tmp_path):
    iid = await _instance()
    backups = tmp_path / "backups"
    backups.mkdir()
    async with get_sessionmaker()() as db:
        row = _backup(iid, size=10, has_files=True, files_format="objs-v1", files_bytes=4)
        row.db_sha256 = _file(backups / f"{row.name}.dump", b"0123456789")
        db.add(row)
        await db.commit()
        # No .files yet: fine when the restore doesn't put files back.
        assert await data.confirm_backup(Shell("sh"), db, row, str(backups), "prod-01") is None
        assert await data.confirm_backup(Shell("sh"), db, row, str(backups), "prod-01", files=True) == (
            f"The backup {row.name} on prod-01 is missing")
        row.status = "ready"
        await db.commit()
        (backups / f"{row.name}.dump").write_bytes(b"9876543210")  # same size, other content
        assert await data.confirm_backup(Shell("sh"), db, row, str(backups), "prod-01") == (
            f"The backup {row.name} on prod-01 has changed since Slipway took it (size or checksum differ); "
            "Slipway won't restore it")
        await db.commit()
        assert (await db.get(Backup, row.id, populate_existing=True)).status == "changed"


async def test_unverified_rows_are_kept_when_their_file_is_there_and_forgotten_otherwise(tmp_path):
    iid = await _instance()
    backups = tmp_path / "backups"
    backups.mkdir()
    async with get_sessionmaker()() as db:
        kept = _backup(iid, status="unverified", size=None)
        lost = _backup(iid, at=T0 + timedelta(hours=1), status="unverified", size=None)
        db.add_all([kept, lost])
        await db.commit()
        sha = _file(backups / f"{kept.name}.dump", b"DB: twelve b")
        lines = await data.settle_unverified(Shell("sh"), db, await _load(db, iid), str(backups))
        await db.commit()
        rows = {r.id: r for r in (await db.scalars(select(Backup).execution_options(populate_existing=True))).all()}
        assert lost.id not in rows
        assert (rows[kept.id].status, rows[kept.id].db_bytes, rows[kept.id].db_sha256) == ("ready", 12, sha)
        assert lines == [f"Backup {kept.name} was written before Slipway restarted; checked it and kept it (12 bytes)",
                         f"Backup {lost.name} never finished before Slipway restarted; forgot it"]


# --------------------------------------------------------------- what can be restored


async def test_restorable_matrix_with_exact_messages():
    iid = await _instance(identity_changed_at=datetime(2026, 11, 1, tzinfo=UTC), identity_source="snapshot uat-1")
    async with get_sessionmaker()() as db:
        inst = await _load(db, iid)
        good = _backup(iid)
        assert data.restorable(inst, good) == data.Restorable(ok=True)

        def reason(row, instance=inst):
            return data.restorable(instance, row).reason

        assert reason(_backup(iid, status="pending")) == "Being taken"
        assert reason(_backup(iid, status="unverified")) == "Not checked since Slipway restarted"
        assert reason(_backup(iid, status="missing", checked_at=datetime(2026, 11, 15, 9, 30, tzinfo=UTC))) == (
            "Not on prod-01 any more (checked 2026-11-15 09:30 UTC)")
        assert reason(_backup(iid, status="changed")) == "Its size on prod-01 changed since Slipway took it"
        assert reason(_backup(iid, format="mysql")) == "Taken in format mysql; release 0123456 restores pg-custom"
        other = _backup(iid, identity={"APP_KEY": KEY_B})
        rule = data.restorable(inst, other)
        assert rule.ok and rule.override == {"APP_KEY": KEY_B} and rule.needs_reset_perm
        assert rule.identity_note == ("Restoring it also puts back the sign-in keys it was made with (APP_KEY; changed "
                                      "2026-11-01: snapshot uat-1). People sign in with the keys the data was made with.")
        unreadable = _backup(iid, identity={"APP_KEY": KEY_B})
        unreadable.identity = None
        assert reason(unreadable) == (
            "Taken with other sign-in keys, which Slipway can't decrypt any more (SLIPWAY_ENCRYPTION_KEY changed): put "
            "the old key back first in the list and run slipway rotate-encryption-key")
        inst.env = {"APP_KEY": KEY_A}
        assert reason(other) == ("Taken with another APP_KEY, and the instance's environment variable APP_KEY sets this "
                                 "one: remove the variable (its value stays the stored secret), then restore")
        inst.env = {}
        inst.app_state = {**inst.app_state, "live": {**inst.app_state["live"], "data_elsewhere": True}}
        assert reason(good) == ("shop's data lives outside prod-01 (an external or shared database); Slipway backs it "
                                "up but won't restore, reset or seed it yet")
        inst.app_state = {**inst.app_state, "manifest": {**MANIFEST, "capabilities": ["backup"]}}
        assert reason(good) == "0123456's slipway.yml has no restore command"
        inst.app_state = {"manifest": MANIFEST}
        assert reason(good) == "Deploy the instance first"
        dirty_job = _job(iid, "deploy", commit_sha=SHA2)
        dirty = _backup(iid, dirty_of=dirty_job.id)
        assert data.restorable(inst, dirty, dirty_job=dirty_job).dirty_note == (
            f"Holds data changed by failed deployment {dirty_job.id.hex[:8]} (fedcba9)")
        await db.rollback()


async def test_backup_views_carry_pins_and_reasons():
    iid = await _instance()
    async with get_sessionmaker()() as db:
        first, other = _backup(iid), _backup(iid, at=T0 + timedelta(hours=1), status="missing")
        failed = _job(iid, "deploy", backup_id=first.id)
        db.add_all([first, other, failed])
        await db.flush()
        inst = await _load(db, iid)
        inst.data_dirty = data.mark_dirty(None, failed, step="start")
        await db.commit()
        views = {v.row.id: v for v in await data.backup_views(db, inst, [first, other])}
        assert views[first.id].pinned and views[first.id].restorable
        assert views[first.id].pinned_reason == f"it is the roll back point of failed deployment {failed.id.hex[:8]}"
        assert not views[other.id].pinned and views[other.id].reason_text.startswith("Not on prod-01 any more")


# ------------------------------------------------------------------- roll back


async def _failed_deploy(db, iid, *, at, backup=None, began=True, **kw) -> Deployment:
    dep = _job(iid, "deploy", at=at, backup_id=backup.id if backup else None,
               steps=_rows(backup="succeeded", start="failed" if began else "pending"), **kw)
    db.add(dep)
    await db.flush()
    if began:
        inst = await _load(db, iid)
        inst.data_dirty = data.mark_dirty(inst.data_dirty, dep, step="start")
    return dep


async def test_rollback_state_for_every_reason_and_two_failed_deploys():
    iid = await _instance()
    async with get_sessionmaker()() as db:
        b1 = _backup(iid, at=T0)
        db.add(b1)
        first = await _failed_deploy(db, iid, at=T0, backup=b1)
        await db.commit()
        state = await data.rollback_state(db, first)
        available, why = state
        assert available and why is None and state.backup.id == b1.id and state.also_undoes is None

        # A second failed deploy: the rollback point stays the backup from before the first one.
        b2 = _backup(iid, at=T0 + timedelta(hours=1), dirty_of=first.id)
        db.add(b2)
        second = await _failed_deploy(db, iid, at=T0 + timedelta(hours=1), backup=b2)
        await db.commit()
        state = await data.rollback_state(db, second)
        assert state.available and state.backup.id == b1.id
        assert state.also_undoes == f"This also undoes failed deployment {first.id.hex[:8]} before it (fedcba9)."
        assert tuple(await data.rollback_state(db, first)) == (
            False, f"Deployment {second.id.hex[:8]} ran after this deployment; restore a backup instead")

        succeeded = _job(iid, "deploy", "succeeded", at=T0 + timedelta(hours=2))
        assert tuple(await data.rollback_state(db, succeeded)) == (False, "Only a failed deployment can be rolled back")
        assert tuple(await data.rollback_state(db, _job(iid, "restore", at=T0 + timedelta(hours=2)))) == (
            False, "Only a failed deployment can be rolled back")

        # A backup job after it doesn't move "the latest job" (D10).
        db.add(_job(iid, "backup", "succeeded", at=T0 + timedelta(hours=3)))
        await db.commit()
        assert (await data.rollback_state(db, second)).available

        inst = await _load(db, iid)
        inst.app_state = {**inst.app_state, "manifest": {**MANIFEST, "capabilities": ["backup"]}}
        assert (await data.rollback_state(db, second)).reason == "0123456's slipway.yml has no restore command"
        inst.app_state = {**inst.app_state, "manifest": MANIFEST}
        b1.status = "missing"
        await db.flush()
        assert (await data.rollback_state(db, second)).reason == (
            "There is no backup from before the first failed deploy (it had no data yet, or the backup is gone)")
        b1.status = "ready"
        inst.current_commit_sha = None
        await db.flush()
        assert (await data.rollback_state(db, second)).reason == "This was the first deploy: use Start over instead"
        inst.current_commit_sha = SHA
        b1.format = "mysql"
        await db.flush()
        assert (await data.rollback_state(db, second)).reason == "Taken in format mysql; release 0123456 restores pg-custom"
        b1.format = "pg-custom"
        inst.live_identity = {"APP_KEY": KEY_B}
        await db.flush()
        assert (await data.rollback_state(db, second)).reason == (
            "The backup from before the first failed deploy was made with other sign-in keys; restore it from the "
            "Backups card instead")
        inst.live_identity = {"APP_KEY": KEY_A}
        inst.data_dirty = None
        await db.flush()
        assert (await data.rollback_state(db, second)).reason == (
            "Nothing to roll back: this deployment failed before it changed the data; shop still runs 0123456")


async def test_rollback_needs_a_pre_deploy_backup():
    iid = await _instance()
    async with get_sessionmaker()() as db:
        dep = await _failed_deploy(db, iid, at=T0, backup=None)
        await db.commit()
        assert (await data.rollback_state(db, dep)).reason.startswith("There is no backup from before the first failed")


# ------------------------------------------------------------- dirty, retry, actions


def test_mark_dirty_keeps_first_and_holds_after_a_failed_restore():
    iid = uuid.uuid4()
    b1, b2 = uuid.uuid4(), uuid.uuid4()
    deploy = _job(iid, "deploy", backup_id=b1, steps=_rows(build="succeeded", backup="succeeded", start="failed"))
    dirty = data.mark_dirty(None, deploy, step="start", at=T0)
    assert dirty == {"first": {"deployment_id": deploy.id.hex, "kind": "deploy", "backup_id": b1.hex, "at": T0.isoformat()},
                     "last": {"deployment_id": deploy.id.hex, "kind": "deploy", "step": "start", "backup_id": b1.hex,
                              "at": T0.isoformat(), "step_text": "step 3/3: Start"},
                     "hold": False}
    restore = _job(iid, "restore", backup_id=b2,
                   steps=_rows(release="succeeded", check="succeeded", backup="succeeded", stop="succeeded",
                               restore="failed", start="pending"))
    after = data.mark_dirty(dirty, restore, step="restore", at=T0)
    assert after["first"] == dirty["first"] and after["last"]["backup_id"] == b2.hex and after["hold"]
    assert after["last"]["step_text"] == "step 5/6: Restore"
    assert data.mark_dirty(after, deploy, step="start")["hold"]  # a hold stays until a job succeeds


def test_a_start_over_that_fails_in_reset_leaves_the_data_dirty_but_no_hold():
    # A never-live instance has no backup to restore and no live app to keep off: Deploy is its way forward.
    iid = uuid.uuid4()
    start_over = _job(iid, "reset", options={"start_over": True},
                      steps=_rows(release="succeeded", backup="succeeded", stop="succeeded", reset="failed"))
    dirty = data.mark_dirty(None, start_over, step="reset", at=T0)
    assert dirty["last"]["step"] == "reset" and dirty["hold"] is False
    reset = _job(iid, "reset", steps=_rows(backup="succeeded", stop="succeeded", reset="failed"))
    assert data.mark_dirty(None, reset, step="reset")["hold"] is True  # a live instance's reset still holds


def test_which_failures_began_a_change():
    iid = uuid.uuid4()
    assert not data.change_began(_job(iid, "deploy", steps=_rows(build="failed", start="pending")))
    assert data.change_began(_job(iid, "deploy", steps=_rows(build="succeeded", start="failed")))
    assert data.change_began(_job(iid, "reset", steps=_rows(backup="succeeded", stop="failed", reset="pending")))
    assert not data.change_began(_job(iid, "reset", steps=_rows(check="failed", stop="pending")))
    assert not data.change_began(_job(iid, "backup", steps=_rows(backup="failed")))
    # Retry inheritance counts only the steps that replace data (and a deploy's start).
    assert not data.replacing_began(_job(iid, "reset", steps=_rows(stop="failed", reset="pending")))
    assert data.replacing_began(_job(iid, "reset", steps=_rows(stop="succeeded", reset="running")))


async def test_retry_inherits_only_when_the_parent_began_changing_the_data():
    iid = await _instance()
    async with get_sessionmaker()() as db:
        b1 = _backup(iid)
        db.add(b1)
        await db.flush()
        before = _job(iid, "deploy", at=T0, backup_id=b1.id, steps=_rows(backup="succeeded", start="pending"))
        db.add(before)
        await db.commit()
        got = await data.retry_inheritance(db, before)
        assert (got.inherit, got.backup_id, got.pre_retry) == (False, None, False)  # nothing changed: a fresh backup

        began = _job(iid, "deploy", at=T0 + timedelta(hours=1), backup_id=b1.id,
                     steps=_rows(backup="succeeded", start="failed"))
        db.add(began)
        await db.commit()
        got = await data.retry_inheritance(db, began)
        assert (got.inherit, got.backup_id, got.pre_retry) == (True, b1.id, False)
        assert not (await data.retry_inheritance(db, before)).inherit  # not the latest changing job

        inst = await _load(db, iid)
        inst.last_control_at = began.finished_at + timedelta(minutes=5)  # started by hand since
        await db.flush()
        assert (await data.retry_inheritance(db, began)).pre_retry

        parent = _job(iid, "reset", at=T0 + timedelta(hours=2), backup_id=b1.id,
                      steps=[{"key": "reset", "status": "skipped", "done_by": "ab" * 16},
                             {"key": "restore", "status": "succeeded"}, {"key": "files", "status": "failed"}])
        db.add(parent)
        await db.commit()
        got = await data.retry_inheritance(db, parent)
        assert got.inherit and got.done_by == {"reset": "ab" * 16, "restore": parent.id.hex}


async def test_job_actions_offer_retry_rollback_and_undo():
    iid = await _instance()
    async with get_sessionmaker()() as db:
        b1 = _backup(iid)
        db.add(b1)
        dep = await _failed_deploy(db, iid, at=T0, backup=b1)
        dep.steps = _rows(backup="failed", start="pending")
        await db.commit()
        actions = await data.job_actions(db, dep)
        assert actions["retry"]["available"] and actions["retry"]["offers_skip_backup"]
        assert not actions["retry"]["needs_confirm"]
        assert actions["rollback"]["available"] and actions["rollback"]["backup_id"] == str(b1.id)
        assert actions["undo"]["available"] is False

        b2 = _backup(iid, at=T0 + timedelta(hours=1), reason="pre_restore", has_files=True, files_bytes=3,
                     files_format="objs-v1")
        db.add(b2)
        await db.flush()
        restore = _job(iid, "restore", "succeeded", at=T0 + timedelta(hours=1), backup_id=b2.id, restore_backup_id=b1.id)
        db.add(restore)
        await db.commit()
        actions = await data.job_actions(db, restore)
        assert actions["undo"] == {"available": True, "backup_id": str(b2.id), "files": True, "reason": None}
        assert actions["retry"] == {**actions["retry"], "available": False,
                                    "reason": "Only a failed or interrupted deployment can be retried"}
        old = await data.job_actions(db, dep)
        assert not old["rollback"]["available"]

        failed_restore = _job(iid, "restore", "failed", at=T0 + timedelta(minutes=30))
        db.add(failed_restore)
        await db.commit()
        retry = (await data.job_actions(db, failed_restore))["retry"]
        assert retry["needs_confirm"] and retry["reason"] == (
            f"Only the most recent job of shop can be retried; restore {restore.id.hex[:8]} ran after it")

        reset = _job(iid, "reset", "failed", at=T0 + timedelta(hours=2), steps=_rows(check="succeeded", restore="failed"))
        db.add(reset)
        await db.commit()
        assert (await data.job_actions(db, reset))["retry"]["reason"] == (
            "The snapshot this job restores was deleted; start a new reset instead")
        snap = Snapshot(name="uat-1", status="ready", origin="upload", app="shop", file_sha256="a" * 64,
                        db_sha256="b" * 64)
        db.add(snap)
        await db.flush()
        reset.snapshot_id = snap.id
        await db.commit()
        assert (await data.job_actions(db, reset))["retry"]["available"]
        running = _job(iid, "backup", "running", at=T0 + timedelta(hours=3))
        db.add(running)
        await db.commit()
        assert (await data.job_actions(db, reset))["retry"]["reason"] == (
            "A job is already running for this instance (Back up); wait for it to finish")


async def test_retry_never_offers_to_skip_the_backup_of_data_that_lives_elsewhere():
    live = {"release": f"{SHA[:12]}-11111111", "deployment": "11" * 16, "sha": SHA, "projects": ["shop-uat"],
            "volumes": [], "data_elsewhere": True}
    iid = await _instance(app_state={"manifest": MANIFEST, "live": live})
    async with get_sessionmaker()() as db:
        restore = _job(iid, "restore", steps=_rows(check="succeeded", backup="failed", stop="pending"))
        deploy = _job(iid, "deploy", at=T0 - timedelta(hours=1), steps=_rows(backup="failed", start="pending"))
        db.add_all([restore, deploy])
        await db.commit()
        retry = (await data.job_actions(db, restore))["retry"]
        assert retry["available"] and retry["offers_skip_backup"] is False
        # A deploy only backs up such data, never replaces it: its backup can still be skipped.
        assert (await data.job_actions(db, deploy))["retry"]["offers_skip_backup"] is True


async def test_retry_of_a_never_live_start_over_refused_as_elsewhere_offers_no_skip():
    # A never-live instance has no app_state.live to cache data_elsewhere in: the backup step's note is the record.
    iid = await _instance(app_state={"manifest": MANIFEST}, current_commit_sha=None, status="failed")
    note = ("shop's data lives outside prod-01 (commands.has_data says so); Slipway backs it up but won't restore, "
            "reset or seed it yet. Nothing was changed.")
    async with get_sessionmaker()() as db:
        reset = _job(iid, "reset", options={"start_over": True},
                     steps=[{"key": "check", "name": "Check", "status": "succeeded"},
                            {"key": "backup", "name": "Backup", "status": "failed", "note": note},
                            {"key": "stop", "name": "Stop", "status": "pending"}])
        other = _job(iid, "reset", at=T0 - timedelta(hours=1), options={"start_over": True},
                     steps=_rows(check="succeeded", backup="failed", stop="pending"))
        db.add_all([reset, other])
        await db.commit()
        retry = (await data.job_actions(db, reset))["retry"]
        assert retry["available"] and retry["offers_skip_backup"] is False
        assert data.refused_elsewhere({"status": "failed", "note": note})
        assert not data.refused_elsewhere({"status": "failed", "note": "The dump failed"})


# ---------------------------------------------------------------- queue checks


async def _refused(db, instance, kind, **kw) -> tuple[int, str]:
    with pytest.raises(HTTPException) as err:
        await data.require_data_job(db, instance, kind, **kw)
    return err.value.status_code, err.value.detail


async def test_require_data_job_refusals():
    iid = await _instance()
    async with get_sessionmaker()() as db:
        inst = await _load(db, iid)
        assert (await data.require_data_job(db, inst, "restore"))["sha"] == SHA
        assert data.data_scope_key(inst) == str(iid)

        inst.build_source = "compose"
        assert await _refused(db, inst, "backup") == (
            400, "Only app instances (slipway.yml) can back up, restore or reset their data")
        inst.build_source = "app"
        state = inst.app_state
        inst.app_state = {"manifest": MANIFEST}
        assert await _refused(db, inst, "backup") == (409, data.not_live_text(inst))
        assert "deploy it once more" in data.not_live_text(inst)
        inst.app_state = {**state, "manifest": {**MANIFEST, "capabilities": []}}
        assert await _refused(db, inst, "restore") == (
            409, "The live release's slipway.yml has no dump command, so Slipway can't back up the data first")
        inst.app_state = {**state, "manifest": {**MANIFEST, "capabilities": ["backup"]}}
        assert await _refused(db, inst, "rollback") == (409, "The live release's slipway.yml has no restore command")
        inst.app_state = {**state, "manifest": {**MANIFEST, "capabilities": ["backup", "restore"]}}
        assert await _refused(db, inst, "reset") == (
            409, "slipway.yml at 0123456 declares no data volumes and restore command, so Slipway can't reset it")
        inst.app_state = state

        inst.data_dirty = {"first": {"deployment_id": "cd" * 16, "kind": "deploy"},
                           "last": {"deployment_id": "cd" * 16, "kind": "restore", "step": "restore",
                                    "step_text": "step 9/14: Restore the database"}, "hold": True}
        assert await _refused(db, inst, "admin") == (409, (
            "shop's last restore stopped part-way (step 9/14: Restore the database), so its database may be empty or "
            "half-restored. Retry it, or restore an earlier backup. Start, Restart and Deploy are off until then."))
        await data.require_data_job(db, inst, "restore")  # restore and back up stay allowed
        await data.require_data_job(db, inst, "backup")
        inst.data_dirty = {**inst.data_dirty, "hold": False}
        assert await _refused(db, inst, "snapshot") == (409, (
            "shop's data was left half-changed by deployment cdcdcdcd; a snapshot of it would seed others with that. "
            "Retry, restore or roll back first."))
        inst.data_dirty = None

        inst.app_state = {**state, "live": {**state["live"], "data_elsewhere": True}}
        assert (await _refused(db, inst, "reset"))[1].startswith("shop's data lives outside prod-01")
        await data.require_data_job(db, inst, "backup")  # it is still backed up
        inst.app_state = state

        assert await _refused(db, inst, "reset", start_over=True) == (409, "shop has gone live; use Reset data")
        inst.current_commit_sha = None
        assert await data.require_data_job(db, inst, "reset", start_over=True) == {}
        inst.current_commit_sha = SHA

        db.add(_job(iid, "deploy", "running"))
        await db.flush()
        assert await _refused(db, inst, "backup") == (
            409, "A job is already running for this instance (Deploy); wait for it to finish")
        await db.rollback()


async def test_lost_identity_keys_and_the_manual_cap(monkeypatch):
    iid = await _instance(live_identity=None)
    async with get_sessionmaker()() as db:
        inst = await _load(db, iid)
        await data.require_data_job(db, inst, "backup")  # never set: deployed before phase 2
        inst.live_identity = None
    # Simulate a value Slipway can no longer read: the column holds something that decrypts to nothing.
    async with get_sessionmaker()() as db:
        from sqlalchemy import text
        await db.execute(text("UPDATE instances SET live_identity = 'gAAAA-not-a-token' WHERE id = :i"), {"i": iid.hex})
        await db.commit()
    async with get_sessionmaker()() as db:
        inst = await _load(db, iid)
        assert inst.live_identity is None
        assert await _refused(db, inst, "restore") == (409, (
            "Deploy shop once: Slipway lost the keys its data was made with (SLIPWAY_ENCRYPTION_KEY changed)"))
        monkeypatch.setattr(data, "get_settings", lambda: type("S", (), {"manual_backups_max": 2})())
        db.add(_backup(iid, reason="manual"))
        await db.commit()
        assert await data.manual_cap_text(db, inst) is None
        db.add(_backup(iid, reason="manual", at=T0 + timedelta(hours=1)))
        await db.commit()
        assert await data.manual_cap_text(db, inst) == "shop already has 2 backups you took yourself; delete one first"


def test_sidecar_holds_metadata_never_identity_values():
    row = _backup(uuid.uuid4(), identity={"APP_KEY": KEY_B}, commit_sha=SHA, release="r", revision="0042\n")
    text = data.sidecar(row, app="shop")
    assert KEY_B not in text
    assert '"identity_keys": [\n    "APP_KEY"\n  ]' in text and '"revision_short": "0042"' in text
    assert '"format": "slipway-backup"' in text and '"files_bytes": null' in text
