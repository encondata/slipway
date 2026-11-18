"""The upgrade script and the updates service read each other's files and locks the same way.

These run the real script (as shipped in the package) in the install folder of the script tests' Rig, with its
fake docker, and read the results back through the service's own remote commands, run locally under /bin/sh
the way RemoteSession runs them over SSH (stderr merged into stdout, lines joined with newlines).
"""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from slipway.services import updates
from slipway.web import pages
from tests.test_upgrade_script import BOOT_ID, RUN_ID, Rig, _no_flock

pytestmark = pytest.mark.skipif(shutil.which("bash") is None or shutil.which("git") is None,
                                reason="needs bash and git")

SCRIPT = Path(updates.__file__).resolve().parent.parent / "updates" / "upgrade.sh"


class LocalRemote:
    """Runs the service's remote commands on this machine, like RemoteSession.run does over SSH."""

    def __init__(self, env: dict[str, str]) -> None:
        self.env = env
        self.commands: list[str] = []

    async def run(self, command: str, *, check: bool = True, on_line=None, timeout: float | None = None) -> tuple[int, str]:
        self.commands.append(command)
        proc = await asyncio.to_thread(
            subprocess.run, ["/bin/sh", "-c", command], env=self.env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout or 60,
        )
        output = "\n".join(line.rstrip("\r") for line in proc.stdout.splitlines())
        return proc.returncode, output

    async def write_text(self, remote: str, content: str, mode: int = 0o600) -> None:
        Path(remote).write_text(content)
        os.chmod(remote, mode)


@pytest.fixture
def rig(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Rig:
    rig = Rig(tmp_path)
    monkeypatch.setattr(updates, "BOOT_ID_FILE", str(rig.boot_file))
    monkeypatch.setattr(updates, "LOCK_FILE", str(rig.lock))
    return rig


async def _read(rig: Rig, run_id: str = RUN_ID, **kw) -> dict:
    return await updates.read_run(LocalRemote(rig.env()), str(rig.dir), run_id, **kw)


# ------------------------------------------------------------------ names on both sides


def test_every_step_and_status_the_script_writes_is_known_to_the_service_and_page():
    text = SCRIPT.read_text()
    steps = set(re.findall(r"set_step (\w+) ", text))
    assert steps == set(updates.STEPS)
    assert set(updates.STEPS) == set(pages.UPDATE_STEPS)
    assert set(re.findall(r"finish (\w+) ", text)) | {"running"} == set(updates.SCRIPT_STATUSES)
    # The id, sha and branch rules the service sends are ones the script accepts.
    assert updates.ID_RE.pattern in text and updates.SHA_RE.pattern in text and updates.BRANCH_RE.pattern in text
    assert f"STATE_DIR={updates.WORK_DIR}" in text
    assert "LOCK=${SLIPWAY_UPGRADE_LOCK:-/tmp/slipway-upgrade.lock}" in text
    assert "BOOT_ID_FILE=${SLIPWAY_UPGRADE_BOOT_ID_FILE:-/proc/sys/kernel/random/boot_id}" in text


def test_the_service_ships_the_same_script():
    assert updates.script_text() == SCRIPT.read_text()


# ------------------------------------------------------------ status files the script writes


@pytest.mark.parametrize("outcome", ["succeeded", "rolled_back", "restored", "rollback_failed", "failed", "locked"])
async def test_every_outcome_parses_as_a_valid_status(rig: Rig, outcome: str):
    expect = {"succeeded": (0, "succeeded"), "rolled_back": (2, "rolled_back"), "restored": (2, "rolled_back"),
              "rollback_failed": (3, "rollback_failed"), "failed": (1, "failed"), "locked": (75, "failed")}[outcome]
    if outcome in ("rolled_back", "restored", "rollback_failed"):
        rig.control(f"health_fail_{rig.c2}")
    if outcome == "restored":
        rig.control("migrate_to", f"{rig.c2} rev2\n")
    if outcome == "rollback_failed":
        rig.control(f"health_fail_{rig.c1}")
    if outcome == "failed":
        rig.control("build_fail")
    if outcome == "locked":
        _no_flock(rig)
        held = Path(f"{rig.lock}.d")
        held.mkdir()
        (held / "owner").write_text(f"{os.getpid()} {BOOT_ID}\n")

    r = rig.run(from_=rig.c1)
    assert r.returncode == expect[0], rig.log

    parsed = await _read(rig, with_log=True)
    assert parsed["valid"] and parsed["exists"], parsed
    assert parsed["status"] == expect[1] and parsed["status"] in updates.FINAL_STATUSES
    assert (parsed["from"], parsed["to"], parsed["branch"]) == (rig.c1, rig.c2, "main")
    assert parsed["boot_id"] == BOOT_ID and isinstance(parsed["pid"], int)
    assert parsed["finished_at"] and parsed["started_at"] and parsed["message"]
    assert parsed["db_changed"] is (outcome == "restored")
    if outcome in ("succeeded", "rolled_back", "restored", "rollback_failed"):
        assert parsed["backup"] == f"{updates.WORK_DIR}/{RUN_ID}-before.dump"
    else:
        assert parsed["backup"] is None
    assert "Finished: " in parsed["log"] and (outcome == "locked" or "==> preflight: " in parsed["log"])


async def test_a_running_status_with_a_live_pid_stays_running_and_a_dead_one_is_interrupted(rig: Rig):
    assert rig.run().returncode == 0, rig.log
    status = json.loads((rig.state / f"{RUN_ID}.json").read_text())
    sleeper = subprocess.Popen(["sleep", "30"])
    try:
        status.update(status="running", finished_at=None, pid=sleeper.pid)
        (rig.state / f"{RUN_ID}.json").write_text(json.dumps(status))
        assert (await _read(rig))["status"] == "running"
    finally:
        sleeper.kill()
        sleeper.wait()
    assert (await _read(rig))["status"] == "interrupted"
    # Another boot id: interrupted without asking about the pid.
    rig.boot_file.write_text("99999999-2222-3333-4444-555555555555\n")
    assert (await _read(rig))["status"] == "interrupted"


async def test_listing_finds_the_scripts_status_files(rig: Rig):
    assert rig.run().returncode == 0, rig.log
    (rig.state / f"{RUN_ID}.json.tmp").write_text("{}")
    assert await updates._list_remote_ids(LocalRemote(rig.env()), str(rig.dir)) == [RUN_ID]


# ------------------------------------------------------------------------- the launch


async def test_the_service_launch_command_starts_the_script_detached(rig: Rig):
    remote = LocalRemote(rig.env())
    path = rig.state / f"upgrade-{RUN_ID}.sh"
    path.unlink()
    await remote.write_text(str(path), updates.script_text(), mode=0o700)
    status, out = await remote.run(updates.launch_command(str(rig.dir), RUN_ID, rig.c2, "main", rig.c1))
    started = re.fullmatch(r"started ([0-9]+)", out.splitlines()[-1])
    assert status == 0 and started, out

    parsed: dict = {}
    for _ in range(600):
        parsed = await updates.read_run(remote, str(rig.dir), RUN_ID, with_log=True)
        if parsed["status"] in updates.FINAL_STATUSES:
            break
        assert parsed["status"] in ("running", "unknown"), parsed  # unknown: not written yet
        await asyncio.sleep(0.05)
    assert parsed["status"] == "succeeded", parsed.get("log")
    assert parsed["pid"] == int(started.group(1))  # the pid it printed is the script's own
    assert parsed["from"] == rig.c1 and parsed["to"] == rig.c2
    assert rig.head() == rig.c2
    assert "==> cleanup: " in parsed["log"]
    assert oct(os.stat(rig.state / f"{RUN_ID}.log").st_mode & 0o777) == "0o600"


# ---------------------------------------------------------------------------- the lock


async def test_the_services_check_honours_the_scripts_lock_folder(rig: Rig):
    """When flock doesn't work the script holds <lock>.d; the service's locked read must see it too."""
    _no_flock(rig)  # a flock on PATH that fails as it does without lock support
    remote = LocalRemote(rig.env())
    held = Path(f"{rig.lock}.d")
    held.mkdir()
    (held / "owner").write_text(f"{os.getpid()} {BOOT_ID}\n")
    status, _ = await remote.run(updates._locked("echo ran; exit 0"))
    assert status == 1
    assert rig.run().returncode == 75  # and the script agrees

    held.joinpath("owner").unlink()
    held.rmdir()
    status, out = await remote.run(updates._locked("echo ran; exit 0"))
    assert (status, out) == (0, "ran")
    status, _ = await remote.run(updates._locked("exit 4"))
    assert status == 4


@pytest.mark.skipif(shutil.which("flock") is None, reason="needs flock")
async def test_the_services_check_and_the_script_share_the_flock(rig: Rig):
    remote = LocalRemote(rig.env())
    with open(rig.lock, "a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        status, _ = await remote.run(updates._locked("exit 0"))
        assert status == 1
        assert rig.run().returncode == 75
    assert (await remote.run(updates._locked("exit 0")))[0] == 0


async def test_a_lock_folder_without_an_owner_counts_while_young_on_both_sides(rig: Rig):
    _no_flock(rig)
    remote = LocalRemote(rig.env())
    held = Path(f"{rig.lock}.d")
    held.mkdir()  # its holder was killed (or is still) between mkdir and writing the owner file
    status, _ = await remote.run(updates._locked("echo ran; exit 0"))
    assert status == 1
    assert rig.run().returncode == 75
    old = time.time() - 120
    os.utime(held, (old, old))
    status, out = await remote.run(updates._locked("echo ran; exit 0"))
    assert (status, out) == (0, "ran")  # stale: the script takes it over too
    assert rig.run().returncode == 0, rig.log
