"""Phase 3 S8a: jobs of environment members through the real deployer, on several fake hosts (MultiRemote):
the first chain, deploys to the idle slot, secrets, the data owner's jobs with the app slots stopped and started
around them, the lag check, the database probe, runner keys, recovery and ``_finish`` (tests 30-43, 62-66, 69).

The data server, blue and green are three "hosts" whose commands run in a real shell (tests/fake_hosts.py).
Switchyard and Cloudflare are their fakes. Nothing here mocks the deployer.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import uuid
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, text, update

from slipway.db.session import get_sessionmaker
from slipway.models import Backup, Deployment, Environment, FirstAdmin, Host, Instance, Resource, Snapshot
from slipway.services import cloudflare, data, deployer, traffic
from tests import fake_switchyard
from tests.fake_cloudflare import FakeCloudflare
from tests.fake_hosts import (
    ENV_SCRIPT,
    ENV_YML,
    SECRETS,
    EnvGitHub,
    MultiRemote,
    Seeded,
    configure_cloudflare,
    github,
    queue,
    seed_env,
)


async def _get(model, ident):
    async with get_sessionmaker()() as db:
        return await db.get(model, ident)


async def _set(model, ident, **values) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(update(model).where(model.id == ident).values(**values))
        await db.commit()


def _steps(dep: Deployment) -> dict[str, str]:
    return {s["key"]: s["status"] for s in dep.steps}


def _note(dep: Deployment, key: str) -> str:
    return next((s.get("note") or "") for s in dep.steps if s["key"] == key)


def _env_file(multi: MultiRemote, host: str, slug: str) -> dict[str, str]:
    text = (multi[host].folder(slug) / "shared" / ".env").read_text()
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line and not line.startswith("#"))


@pytest.fixture
def multi(tmp_path):
    return MultiRemote(tmp_path)


@pytest.fixture(autouse=True)
def no_waits(monkeypatch):
    """The smoke test's and the public check's 10 s gaps between tries."""
    async def instantly(_seconds):
        return None
    monkeypatch.setattr(traffic, "sleep", instantly)


@pytest.fixture
def submitted(monkeypatch) -> list[tuple[uuid.UUID, tuple]]:
    """Jobs the chain queues are recorded, not run: each test runs them itself."""
    found: list[tuple[uuid.UUID, tuple]] = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, keys: found.append((dep_id, keys)))
    return found


async def _run(multi: MultiRemote, dep_id: uuid.UUID, gh=EnvGitHub) -> Deployment:
    await deployer.run_deployment(dep_id, connect=multi.connect, github=gh)
    return await _get(Deployment, dep_id)


async def _deploy(multi: MultiRemote, seeded: Seeded, slot: str, gh=EnvGitHub, **fields) -> Deployment:
    options = {"slot": slot, **(fields.pop("options", None) or {})}
    return await _run(multi, await queue(seeded, slot, options=options, **fields), gh)


async def _activate(seeded: Seeded, slot: str) -> None:
    """What S8b's Activate records once its switch passed (§9.5 step 6)."""
    await _set(Environment, seeded.env_id, active_slot_id=seeded.ids[slot], status="live")


async def _live_env(multi: MultiRemote, *, slots=("blue", "green"), active: str | None = "blue", gh=EnvGitHub,
                    **kw) -> Seeded:
    """A mode server environment whose data server and slots are deployed, ``active`` taking the traffic."""
    seeded = await seed_env(multi, slots=slots, **kw)
    for slot in ("data", *slots):
        dep = await _deploy(multi, seeded, slot, gh)
        assert dep.status == "succeeded", (slot, dep.error, dep.log[-3000:])
    if active:
        await _activate(seeded, active)
    multi.clear()
    return seeded


# --------------------------------------------------------------------- test 30: the first chain


async def test_the_first_chain_deploys_the_data_server_then_blue(multi, submitted, monkeypatch):
    sy = fake_switchyard.install(monkeypatch)
    await fake_switchyard.configure()
    cf = FakeCloudflare()
    cf.add_zone("example.com")
    monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(cf.handle))
    await configure_cloudflare()
    seeded = await seed_env(multi, slots=("blue",), traffic={"switch": "switchyard", "dns": {"provider": "cloudflare",
                                                                                             "address": None}},
                            seed_content=True)
    async with get_sessionmaker()() as db:
        db.add(FirstAdmin(instance_id=seeded.ids["data"], fields={"email": "ada@example.com", "name": "Ada"},
                          mode="password", password="correct-horse-9"))
        await db.commit()

    first = await _run(multi, await queue(seeded, "data", options={"chain": True, "slot": "data"}))
    assert first.status == "succeeded", (first.error, first.log)
    assert list(_steps(first)) == ["resolve", "source", "upload", "manifest", "ports", "settings", "build", "backup",
                                   "start", "finish", "dns", "traffic"]
    server = _env_file(multi, "data", "uat-data")
    assert server["DB_PUBLISH"] == "1" and server["DB_ALLOW"] == "10.0.0.11" and server["DB_PASSWORD"] == SECRETS[
        "DB_PASSWORD"]
    assert server["APP_SECRET"] == "" and server["APP_KEY"] == "" and server["APP_SLOT"] == "data"
    assert "APP_WEB_PORT" not in server and server["APP_FILES_PORT"]
    assert multi["data"].calls()[-1].startswith("data-start ")
    owner = await _get(Instance, seeded.ids["data"])
    live = owner.app_state["live"]
    assert live["clients"] == ["10.0.0.11"] and set(live["host_ports"]) == {"files", "db"}
    assert owner.live_identity == {"APP_KEY": SECRETS["APP_KEY"]}  # the environment's, not the blank line (I3)
    # Names that don't move went out first (D24): the DNS records and the files host, no app name.
    assert {r["name"] for r in cf.records.values()} == {"www.uat.example.com", "files.uat.example.com"}
    assert [h["domains"] for h in sy.hosts.values()] == [["files.uat.example.com"]]
    async with get_sessionmaker()() as db:
        rows = (await db.scalars(select(Resource).where(Resource.environment_id == seeded.env_id))).all()
    assert {(r.provider, r.name) for r in rows} == {("cloudflare", "www.uat.example.com"),
                                                    ("cloudflare", "files.uat.example.com"),
                                                    ("switchyard", "files.uat.example.com")}

    # The hook queued blue's deploy, going live.
    [(blue_id, keys)] = submitted
    assert keys == ((seeded.env_id, "data"), (seeded.env_id, "traffic"))
    queued = await _get(Deployment, blue_id)
    assert queued.options["go_live"] is True and queued.options["after"] == first.id.hex
    sy_calls = len(sy.calls)
    blue = await _run(multi, blue_id)
    assert blue.status == "succeeded", (blue.error, blue.log)
    assert list(_steps(blue)) == ["resolve", "source", "upload", "manifest", "ports", "settings", "build", "backup",
                                  "start", "finish", "first_admin", "smoke", "traffic"]
    assert "seed" not in _steps(blue)  # a new environment seeds at its first Activate (D24)
    env = _env_file(multi, "blue", "uat-blue")
    assert env["APP_EXTERNAL"] == "1" and env["DB_HOST"] == "10.0.0.13" and env["DB_PORT"] == str(live["host_ports"]["db"])
    assert env["APP_SECRET"] == SECRETS["APP_SECRET"] and env["APP_KEY"] == SECRETS["APP_KEY"]
    assert "APP_FILES_PORT" not in env  # files runs on the data server
    # The probe ran on blue's host, the password reaching docker through its environment only.
    probe = [line for line in multi["blue"].docker() if "psql" in line]
    assert probe and all(SECRETS["DB_PASSWORD"] not in line for line in probe)
    assert any(line.startswith("probe: PGPASSWORD set") for line in multi["blue"].docker())
    assert SECRETS["DB_PASSWORD"] not in blue.log
    # The backup ran on the data host: "No data yet".
    assert _steps(blue)["backup"] == "skipped" and _note(blue, "backup").startswith("No data yet")
    assert any(c.startswith("has-data ") for c in multi["data"].calls())
    # The first admin was created on blue, from the data owner's row; its password on stdin only.
    assert multi["blue"].log("ADMIN_LOG") == ["args=--email ada@example.com --name Ada --password-stdin pwlen=15"]
    assert "correct-horse-9" not in blue.log
    async with get_sessionmaker()() as db:
        row = await db.scalar(select(FirstAdmin).where(FirstAdmin.instance_id == seeded.ids["data"]))
    assert row.status == "done"
    assert _steps(blue)["smoke"] == "succeeded" and "www.uat.example.com" in multi["blue"].log("CURL_LOG")
    assert _steps(blue)["traffic"] == "skipped" and _note(blue, "traffic") == "Nothing is live yet; Activate follows"
    assert len(sy.calls) == sy_calls  # blue's deploy made no Switchyard call
    # The migration ran on the shared data, on the data host's folder.
    assert (multi["data"].folder("uat-data") / "state" / "db").read_text() == "MIGRATED blue\n"
    slot = await _get(Instance, seeded.ids["blue"])
    assert slot.app_secrets is None and slot.live_identity is None and slot.status == "running"
    environment = await _get(Environment, seeded.env_id)
    assert environment.traffic_state["last_slot_deploy"]["slot"] == "blue"
    assert {h["hostname"]: h["follows"] for h in environment.hostnames} == {"www.uat.example.com": "active",
                                                                             "files.uat.example.com": "server"}
    # Then the hook queued blue's activate (S8b runs it).
    activate = await _get(Deployment, submitted[1][0])
    assert activate.kind == "activate" and activate.options["slot"] == "blue" and submitted[1][1] == (
        (seeded.env_id, "traffic"),)


async def test_a_chain_job_that_succeeds_during_shutdown_queues_nothing_and_leaves_the_notice(
        multi, submitted, monkeypatch):
    """Test 21's last clause: after_job isn't called from _finish. The data server's first deploy is cancelled
    after its finish (so it is recorded as succeeded, D12): the chain queues nothing and the notice says why."""
    seeded = await seed_env(multi, slots=("blue",))
    dep_id = await queue(seeded, "data", options={"chain": True, "slot": "data"})
    dep = await _cancelled_at(multi, dep_id, monkeypatch, "_traffic")
    assert dep.status == "succeeded" and _steps(dep)["finish"] == "succeeded"
    assert submitted == []
    env = await _get(Environment, seeded.env_id)
    assert env.notice and env.notice["next"] == {"kind": "deploy", "slot": "blue"}
    assert env.notice["text"] == "Slipway stopped after Update the data server succeeded, before it started Deploy to blue"


# -------------------------------------------------------- test 31: deploy to green with blue active


async def test_a_deploy_to_green_backs_up_on_the_data_host_and_checks_both_releases(multi, submitted, monkeypatch):
    sy = fake_switchyard.install(monkeypatch)
    await fake_switchyard.configure()
    seeded = await _live_env(multi, traffic={"switch": "switchyard", "dns": None})
    calls_before = len(sy.calls)
    (multi["data"].folder("uat-data") / "state" / "rev").write_text("rev-1\n")
    multi["green"].env["LOCK_PEEK"] = str(multi["data"].folder("uat-data") / ".slipway-lock")
    green = await _deploy(multi, seeded, "green")
    assert green.status == "succeeded", (green.error, green.log)
    data_calls = multi["data"].calls()
    # The backup, then (after green's start) the revision again: expand/contract, did green's migration move it?
    assert [c.split()[0] for c in data_calls] == ["has-data", "data", "revision", "pgdump", "verify-dump", "revision"]
    owner = await _get(Instance, seeded.ids["data"])
    assert all(c.endswith(owner.app_state["live"]["release"]) for c in data_calls)  # the data server's live release
    blue = await _get(Instance, seeded.ids["blue"])
    green_calls = multi["green"].calls()
    assert [c.split()[0] for c in green_calls[:2]] == ["build", "accepts"]
    assert multi["blue"].calls() == [f"accepts {blue.app_state['live']['release']}"]  # the lag check
    # While green's start ran, the data server's lock carried a d line for this job; it's gone now.
    peek = next(line for line in green_calls if line.startswith("lock: "))
    assert str(green.id) in peek and peek.split()[-2:] == ["start", "d"]
    assert not (multi["data"].folder("uat-data") / ".slipway-lock").exists()
    assert (multi["data"].folder("uat-data") / "state" / "db").read_text().splitlines()[-1] == "MIGRATED green"
    [row] = [b for b in await _backups(seeded) if b.deployment_id == green.id]
    assert row.instance_id == seeded.ids["data"] and row.reason == "pre_deploy" and green.backup_id == row.id
    assert (multi["data"].folder("uat-data") / "backups" / f"{row.name}.dump").exists()
    assert _steps(green)["smoke"] == "succeeded"
    assert _note(green, "traffic") == "Traffic stays on blue; activate green to move it"
    assert len(sy.calls) == calls_before  # Switchyard got no call
    assert submitted == []  # no auto_activate: nothing chained


async def test_with_auto_activate_a_deploy_to_green_chains_an_activate(multi, submitted):
    seeded = await _live_env(multi, auto_activate=True)
    dep_id = await queue(seeded, "green", options={"slot": "green", "go_live": True})
    green = await _run(multi, dep_id)
    assert green.status == "succeeded", green.error
    [(activate_id, _)] = submitted
    assert (await _get(Deployment, activate_id)).kind == "activate"


async def _backups(seeded: Seeded) -> list[Backup]:
    async with get_sessionmaker()() as db:
        return list((await db.scalars(select(Backup).where(Backup.instance_id == seeded.ids["data"])
                                      .order_by(Backup.taken_at))).all())


# ----------------------------------------------------------------------------- test 32: secrets


async def test_both_slots_share_the_environments_secrets_and_a_new_one_is_saved_once(multi, submitted):
    seeded = await _live_env(multi)
    blue, green = _env_file(multi, "blue", "uat-blue"), _env_file(multi, "green", "uat-green")
    for key in SECRETS:
        assert blue[key] == green[key] == SECRETS[key]
    before = (await _get(Environment, seeded.env_id)).secrets_version
    newer = github(ENV_YML.replace("  DB_PASSWORD: hex\n", "  DB_PASSWORD: hex\n  APP_PEPPER: hex\n"))
    green_dep = await _deploy(multi, seeded, "green", newer)
    assert green_dep.status == "succeeded", green_dep.error
    env = await _get(Environment, seeded.env_id)
    assert env.secrets_version == before + 1 and len(env.app_secrets["APP_PEPPER"]) == 64
    assert "Generated 1 secret(s) and kept them with environment uat: APP_PEPPER" in green_dep.log
    await _activate(seeded, "green")
    blue_dep = await _deploy(multi, seeded, "blue", newer)
    assert blue_dep.status == "succeeded", blue_dep.error
    assert (await _get(Environment, seeded.env_id)).secrets_version == before + 1  # generated once
    assert _env_file(multi, "blue", "uat-blue")["APP_PEPPER"] == _env_file(multi, "green", "uat-green")["APP_PEPPER"] \
        == env.app_secrets["APP_PEPPER"]
    for slot in ("blue", "green", "data"):
        assert (await _get(Instance, seeded.ids[slot])).app_secrets is None


async def test_a_concurrent_change_of_the_secrets_fails_the_step(multi, submitted, monkeypatch):
    seeded = await _live_env(multi)
    newer = github(ENV_YML.replace("  DB_PASSWORD: hex\n", "  DB_PASSWORD: hex\n  APP_PEPPER: hex\n"))
    real = deployer._secrets_saved

    async def someone_edits_first(job, secrets):
        await _set(Environment, seeded.env_id, secrets_version=Environment.secrets_version + 1)
        await real(job, secrets)

    monkeypatch.setattr(deployer, "_secrets_saved", someone_edits_first)
    dep = await _deploy(multi, seeded, "green", newer)
    assert dep.status == "failed" and dep.error == "uat's secrets changed while this job ran; retry it"
    assert _steps(dep)["manifest"] == "failed" and "APP_PEPPER" not in (await _get(Environment, seeded.env_id)).app_secrets


async def test_a_member_job_fails_when_the_environments_secrets_were_lost(multi, submitted):
    seeded = await _live_env(multi)
    async with get_sessionmaker()() as db:  # the stored value can't be decrypted: the column reads as None
        await db.execute(update(Environment).where(Environment.id == seeded.env_id).values(app_secrets=None))
        await db.commit()
    async with get_sessionmaker()() as db:
        await db.execute(text("UPDATE environments SET app_secrets = 'not-a-fernet-token'"))
        await db.commit()
    dep = await _deploy(multi, seeded, "green")
    assert dep.status == "failed"
    # A deploy may take them from the environment's variables instead; these set none (test_fix3_member_finish).
    assert dep.error == ("Slipway lost uat's secrets (SLIPWAY_ENCRYPTION_KEY changed): put the old key back first in "
                         "the list and run slipway rotate-encryption-key, or set each of them as a variable of uat: "
                         "APP_SECRET, APP_KEY, DB_PASSWORD (their old values, or the app's existing data won't open)")


# ------------------------------------------------------------- test 33: expand/contract and smoke


async def test_a_migration_by_green_checks_blue_too_and_a_failure_is_a_warning(multi, submitted):
    seeded = await _live_env(multi)
    (multi["data"].folder("uat-data") / "state" / "rev").write_text("rev-1\n")
    multi["green"].env["NEW_REV"] = "rev-2"
    multi["blue"].env["FAKE_HTTP_CODES"] = "www.uat.example.com=502"
    blue = await _get(Instance, seeded.ids["blue"])
    dep = await _deploy(multi, seeded, "green")
    assert dep.status == "succeeded", dep.error
    assert _steps(dep)["smoke"] == "warning"
    note = _note(dep, "smoke")
    assert f"Migrated the database from rev-1 to rev-2; blue ({blue.current_commit_sha[:7]}) keeps running on it" in note
    assert "www.uat.example.com answered 502 on /healthz" in note
    assert (await _get(Instance, seeded.ids["blue"])).slot_state["last_check"]["ok"] is False
    assert (await _get(Instance, seeded.ids["green"])).slot_state["last_check"]["ok"] is True


# ------------------------------------------------------------ test 65: the lag check


async def test_the_lag_check_refuses_a_deploy_blue_cant_run_beside(multi, submitted):
    seeded = await _live_env(multi)
    (multi["data"].folder("uat-data") / "state" / "rev").write_text("rev-9\n")
    multi["blue"].env["UNKNOWN_REVS"] = "rev-9"
    blue = await _get(Instance, seeded.ids["blue"])
    dep = await _deploy(multi, seeded, "green")
    assert dep.status == "failed" and _steps(dep)["backup"] == "failed" and _steps(dep)["start"] == "pending"
    assert dep.error.startswith(f"blue ({blue.current_commit_sha[:7]}) already runs on a database migrated past it "
                                "(revision rev-9, by green's")
    assert "deploy again confirming that this release removes nothing blue uses." in dep.error
    assert not any(c.startswith("up ") for c in multi["green"].calls())
    assert (await _get(Instance, seeded.ids["data"])).data_dirty is None  # nothing began changing
    confirmed = await _deploy(multi, seeded, "green", options={"behind_ok": True})
    assert confirmed.status == "succeeded", confirmed.error
    assert "deploying anyway, as confirmed" in confirmed.log
    multi["blue"].env["UNKNOWN_REVS"] = ""
    again = await _deploy(multi, seeded, "green")
    assert again.status == "succeeded" and "can run the data at revision rev-9 too" in again.log


# ------------------------------------------------------------ test 66: the database probe


async def test_a_probe_that_cant_sign_in_fails_settings_before_build(multi, submitted):
    seeded = await _live_env(multi, active=None)
    multi["green"].env["FAKE_PSQL"] = ('psql: error: connection to server at "10.0.0.13", port 5432 failed: FATAL:  '
                                       'no pg_hba.conf entry for host "172.17.0.5", user "demo", database "demo"')
    dep = await _deploy(multi, seeded, "green")
    assert dep.status == "failed" and _steps(dep)["settings"] == "failed" and _steps(dep)["build"] == "pending"
    assert "uat green on green-host can't sign in to uat's database at 10.0.0.13:" in dep.error
    assert "set host green-host's LAN address to 172.17.0.5 and update the data server" in dep.error
    assert multi["green"].calls() == []  # nothing ran, nothing restarted
    assert SECRETS["DB_PASSWORD"] not in dep.log
    assert all(SECRETS["DB_PASSWORD"] not in line for line in multi["green"].docker())


async def test_a_slot_the_data_server_doesnt_let_in_is_refused(multi, submitted):
    seeded = await seed_env(multi, slots=("blue",))
    assert (await _deploy(multi, seeded, "data")).status == "succeeded"
    await _set(Instance, seeded.ids["blue"], host_id=seeded.host_ids["data"])  # moved onto another host
    async with get_sessionmaker()() as db:
        await db.execute(update(Host).where(Host.id == seeded.host_ids["blue"]).values(lan_address="10.0.0.99"))
        await db.commit()
    await _set(Instance, seeded.ids["blue"], host_id=seeded.host_ids["blue"])
    dep = await _deploy(multi, seeded, "blue")
    assert dep.status == "failed" and _steps(dep)["manifest"] == "failed"
    assert dep.error == ("uat's data server doesn't let blue-host (10.0.0.99) in yet: update the data server first "
                         "(Deploy → Data server)")


# ------------------------------------------------ tests 34, 35, 62, 63, 64: the data owner's jobs


def _containers(multi: MultiRemote, *slots: str) -> None:
    """The slots' hosts list a container for each of their projects, so stop and start act on them."""
    for slot in slots:
        multi[slot].env["FAKE_PS"] = "0123456789ab"


async def _owner_job(multi: MultiRemote, seeded: Seeded, kind: str, gh=EnvGitHub, **fields) -> Deployment:
    """A job on the data owner, queued as ``queue_job`` records it (the live release's commit)."""
    owner = await _get(Instance, seeded.ids["data"])
    sha = owner.app_state["live"]["sha"]
    return await _run(multi, await queue(seeded, "data", kind=kind, commit_sha=sha, **fields), gh)


async def _failed_green(multi: MultiRemote, seeded: Seeded, tmp: Path) -> Deployment:
    flag = tmp / "fail-green"
    flag.write_text("")
    multi["green"].env["FAIL_FLAG"] = str(flag)
    failed = await _deploy(multi, seeded, "green")
    assert failed.status == "failed" and _steps(failed)["start"] == "failed"
    flag.unlink()
    return failed


async def test_green_failing_at_start_marks_the_owner_and_roll_back_stops_and_starts_the_slots(
        multi, submitted, tmp_path):
    seeded = await _live_env(multi)
    (multi["data"].folder("uat-data") / "state" / "db").write_text("MIGRATED blue\nUSERS\n")
    failed = await _failed_green(multi, seeded, tmp_path)
    owner = await _get(Instance, seeded.ids["data"])
    first = owner.data_dirty["first"]
    assert first["deployment_id"] == failed.id.hex and first["backup_id"] == failed.backup_id.hex
    assert owner.data_dirty["hold"] is False and (await _get(Instance, seeded.ids["green"])).data_dirty is None
    [row] = [b for b in await _backups(seeded) if b.id == failed.backup_id]
    assert (multi["data"].folder("uat-data") / "backups" / f"{row.name}.dump").read_text() == "DB:\nMIGRATED blue\nUSERS\n"
    # A data server deploy doesn't clear it (§7.5).
    update_data = await _deploy(multi, seeded, "data")
    assert update_data.status == "succeeded", update_data.error
    assert (await _get(Instance, seeded.ids["data"])).data_dirty["first"]["deployment_id"] == failed.id.hex

    multi.clear()
    _containers(multi, "blue", "green")
    dep = await _owner_job(multi, seeded, "rollback", restore_backup_id=row.id, options={"rollback_of": failed.id.hex})
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert list(_steps(dep)) == ["release", "manifest", "settings", "build", "check", "backup", "stop_slots", "stop",
                                 "restore", "start", "start_slots", "finish", "traffic"]
    assert [c.split()[0] for c in multi["data"].calls()] == [
        "has-data", "data", "revision", "pgdump", "verify-dump", "down", "data", "restore", "data-start"]
    blue_calls = multi["blue"].calls()
    assert blue_calls[-1].startswith("up ")  # blue's live start, before finish: it migrates forward
    assert any("compose -p demo-uat-blue-web stop" in line for line in multi["blue"].docker())
    assert any("compose -p demo-uat-green-web stop" in line for line in multi["green"].docker())
    assert not any(" start" in line for line in multi["green"].docker() if "compose" in line)
    green = await _get(Instance, seeded.ids["green"])
    assert green.status == "stopped" and green.slot_state["stale"]["reason"].startswith(
        "Stopped when uat's data was rolled back")
    assert (await _get(Instance, seeded.ids["blue"])).status == "running"
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.data_dirty is None and owner.status == "running"
    assert (multi["data"].folder("uat-data") / "state" / "db").read_text() == "MIGRATED blue\nUSERS\nMIGRATED blue\n"
    assert dep.options["slots_were"] == {"blue": "running", "green": "failed"} and dep.options["lead"] == "blue"


async def test_a_retry_of_the_failed_deploy_keeps_its_backup_and_clears_the_owner(multi, submitted, tmp_path):
    seeded = await _live_env(multi)
    failed = await _failed_green(multi, seeded, tmp_path)
    async with get_sessionmaker()() as db:
        parent = await db.get(Deployment, failed.id)
        values = await deployer.retry_values(db, parent)
    retry = await _run(multi, await queue(seeded, "green", retry_of_id=failed.id, **values))
    assert retry.status == "succeeded", (retry.error, retry.log)
    assert _steps(retry)["backup"] == "skipped" and "Keeping the backup taken before the first attempt" in _note(
        retry, "backup")
    assert retry.backup_id == failed.backup_id
    assert (await _get(Instance, seeded.ids["data"])).data_dirty is None


# The app with ServerSherpa's stacks (test 35): ``down`` and ``restore`` act on each stack's compose file, and a
# data server (``DB_PUBLISH=1``, which only data.server.env sets) runs only the db and storage stacks, as
# ss-stack's STACKS does on a data VM. So the compose files the data host's $DOCKER_LOG names show which role's
# .env the data server's stop and restore were given.
STACK_SCRIPT = ENV_SCRIPT.replace(
    'case "$cmd" in\n',
    'stacks() { if [ "$(val DB_PUBLISH)" = 1 ]; then echo "db storage"; else echo "db storage web"; fi; }\n'
    'dc() { s=$1; shift; docker compose --env-file "$dir/.env" -f "$s/compose.yml" "$@"; }\n'
    'case "$cmd" in\n', 1).replace(
    '  build|down) ;;\n',
    '  build) ;;\n  down) for s in $(stacks); do dc "$s" down; done ;;\n', 1).replace(
    '  restore) tail',
    '  restore) for s in $(stacks); do case $s in db|storage) ;; *) dc "$s" stop ;; esac; done\n'
    '    dc db exec -T postgres pg_restore; tail', 1)
assert "stacks() {" in STACK_SCRIPT and STACK_SCRIPT.count('dc "$s"') == 2 and "dc db exec" in STACK_SCRIPT


class StackGitHub(EnvGitHub):
    files = {**EnvGitHub.files, "deploy/app": STACK_SCRIPT}


def _compose_files(lines: list[str]) -> set[str]:
    """The compose files ``docker compose -f`` calls in ``lines`` name."""
    found = set()
    for line in lines:
        words = line.split()
        if words[:1] == ["compose"]:
            found |= {words[i + 1] for i, w in enumerate(words[:-1]) if w == "-f"}
    return found


async def _restore_on_owner(multi: MultiRemote, seeded: Seeded, gh=EnvGitHub) -> Deployment:
    """Back up the owner, change its data, and restore that backup (the slots' hosts list their containers)."""
    (multi["data"].folder("uat-data") / "state" / "rev").write_text("rev-1\n")
    backup = await _owner_job(multi, seeded, "backup", gh)
    assert backup.status == "succeeded", backup.error
    [row] = [b for b in await _backups(seeded) if b.deployment_id == backup.id]
    (multi["data"].folder("uat-data") / "state" / "db").write_text("LATER\n")
    multi.clear()
    _containers(multi, "blue", "green")
    dep = await _owner_job(multi, seeded, "restore", gh, restore_backup_id=row.id)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert list(_steps(dep)) == ["release", "manifest", "settings", "build", "check", "backup", "stop_slots", "stop",
                                 "restore", "start", "start_slots", "finish", "traffic"]
    return dep


async def test_restore_on_the_owner_stops_both_slots_and_starts_them_before_finish(multi, submitted):
    seeded = await _live_env(multi, gh=StackGitHub)
    dep = await _restore_on_owner(multi, seeded, StackGitHub)
    blue = await _get(Instance, seeded.ids["blue"])
    # check ran accepts with blue's live release, on blue's host (the lead slot, §7.1).
    assert multi["blue"].calls()[0] == f"accepts {blue.app_state['live']['release']}"
    assert not any(c.startswith("accepts") for c in multi["data"].calls())
    order = [r["key"] for r in dep.steps]
    assert order.index("start_slots") < order.index("finish")
    # The data server's stop and restore ran its live release with the server role's .env: they name only the
    # db and storage compose files, and restore stops no app stack (§16.2 test 35).
    owner = await _get(Instance, seeded.ids["data"])
    release = owner.app_state["live"]["release"].rsplit("/", 1)[-1]
    assert [c for c in multi["data"].calls() if c.startswith(("down", "restore"))] == [
        f"down {release}", f"restore {release}"]
    docker = multi["data"].docker()
    assert _compose_files(docker) == {"db/compose.yml", "storage/compose.yml"}, docker
    assert any(line.endswith(" down") for line in docker) and any("pg_restore" in line for line in docker)
    assert not any(line.endswith(" stop") for line in docker if line.startswith("compose"))
    # The slot role's .env would have named the app's stack too (the check above can fail).
    assert _env_file(multi, "blue", "uat-blue").get("DB_PUBLISH") != "1"
    # Green runs blue's commit: started again as it was.
    assert any("compose -p demo-uat-green-web start" in line for line in multi["green"].docker())
    for slot in ("blue", "green", "data"):
        inst = await _get(Instance, seeded.ids[slot])
        assert inst.status == "running" and not (inst.slot_state or {}).get("stale")
    assert (multi["data"].folder("uat-data") / "state" / "db").read_text().startswith("MIGRATED blue")


@pytest.mark.parametrize("before", ["stopped", "stale"])
async def test_restore_on_the_owner_leaves_a_stopped_or_stale_green_as_it_was(multi, submitted, before):
    """Test 35's "statuses restored": only a slot that was running is started again. A stopped green that runs
    blue's commit stays stopped without a mark; a stale green keeps its mark (and its reason) and stays stopped."""
    seeded = await _live_env(multi)
    mark = {"reason": "Stopped when uat's data was reset; deploy to it before activating it",
            "at": "2026-11-01T00:00:00+00:00", "deployment_id": uuid.uuid4().hex}
    await _set(Instance, seeded.ids["green"], status="stopped",
               slot_state={"stale": mark} if before == "stale" else None)
    dep = await _restore_on_owner(multi, seeded)
    assert dep.options["slots_were"] == {"blue": "running", "green": "stopped"} and dep.options["lead"] == "blue"
    assert multi["blue"].calls()[-1].startswith("up ")  # the lead, with its live start
    assert not any(c.startswith("up ") for c in multi["green"].calls())
    assert not any(line.endswith(" start") for line in multi["green"].docker() if "compose" in line)
    green = await _get(Instance, seeded.ids["green"])
    assert green.status == "stopped"
    assert (green.slot_state or {}).get("stale") == (mark if before == "stale" else None)
    for slot in ("blue", "data"):
        assert (await _get(Instance, seeded.ids[slot])).status == "running", slot
    assert "green stays stopped, as before the restore" in _note(dep, "start_slots")


async def test_a_lead_slot_that_doesnt_start_fails_the_restore_and_holds_the_data(multi, submitted, tmp_path):
    seeded = await _live_env(multi)
    backup = await _owner_job(multi, seeded, "backup")
    [row] = [b for b in await _backups(seeded) if b.deployment_id == backup.id]
    flag = tmp_path / "fail-blue"
    flag.write_text("")
    multi["blue"].env["FAIL_FLAG"] = str(flag)
    dep = await _owner_job(multi, seeded, "restore", restore_backup_id=row.id)
    assert dep.status == "failed" and _steps(dep)["start_slots"] == "failed" and _steps(dep)["finish"] == "pending"
    assert "blue didn't start again after the restore (migration failed); Blue and Green are stopped" in dep.error
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.data_dirty["hold"] is True and owner.data_dirty["last"]["slots_stopped"] == ["blue", "green"]
    assert owner.app_state.get("went_live") != dep.id.hex
    async with get_sessionmaker()() as db:
        text = await data.hold_text(db, await db.get(Instance, seeded.ids["blue"]))
    assert "blue didn't start again after the restore (migration failed); Blue and Green are stopped." in text
    for slot in ("blue", "green"):
        assert (await _get(Instance, seeded.ids[slot])).status == "stopped"


async def _cancelled_at(multi: MultiRemote, dep_id: uuid.UUID, monkeypatch, name: str) -> Deployment:
    """Run the job and cancel it (Slipway shutting down) once the deployer reaches ``deployer.<name>``."""
    reached = asyncio.Event()

    async def hang(*_args, **_kwargs):
        reached.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(deployer, name, hang)
    task = asyncio.create_task(deployer.run_deployment(dep_id, connect=multi.connect, github=EnvGitHub))
    await asyncio.wait_for(reached.wait(), 30)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    return await _get(Deployment, dep_id)


async def test_slipway_cancelled_during_start_slots_leaves_the_restore_held(multi, submitted, monkeypatch):
    """Test 62's second half: a shutdown while the slots start again doesn't end the restore as succeeded."""
    seeded = await _live_env(multi)
    backup = await _owner_job(multi, seeded, "backup")
    [row] = [b for b in await _backups(seeded) if b.deployment_id == backup.id]
    owner = await _get(Instance, seeded.ids["data"])
    dep_id = await queue(seeded, "data", kind="restore", commit_sha=owner.app_state["live"]["sha"],
                         restore_backup_id=row.id)
    dep = await _cancelled_at(multi, dep_id, monkeypatch, "_start_slots")
    assert dep.status == "cancelled" and _steps(dep)["finish"] == "pending"
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.data_dirty["hold"] is True and owner.data_dirty["last"]["slots_stopped"] == ["blue", "green"]
    assert owner.app_state.get("went_live") != dep.id.hex
    async with get_sessionmaker()() as db:
        text = await data.hold_text(db, await db.get(Instance, seeded.ids["blue"]))
    assert text.endswith(" Blue and Green are stopped.")
    assert submitted == []  # nothing is chained from a job that didn't succeed


async def test_a_restore_with_nothing_active_starts_the_slot_deployed_last(multi, submitted):
    seeded = await _live_env(multi, active=None)
    assert (await _get(Environment, seeded.env_id)).traffic_state["last_slot_deploy"]["slot"] == "green"
    backup = await _owner_job(multi, seeded, "backup")
    [row] = [b for b in await _backups(seeded) if b.deployment_id == backup.id]
    multi.clear()
    _containers(multi, "blue", "green")
    dep = await _owner_job(multi, seeded, "restore", restore_backup_id=row.id)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert dep.options["lead"] == "green" and multi["green"].calls()[-1].startswith("up ")
    assert not any(c.startswith("up ") for c in multi["blue"].calls())  # started as it was (same commit)
    assert any("compose -p demo-uat-blue-web start" in line for line in multi["blue"].docker())


async def test_a_restore_before_any_slot_is_deployed_checks_and_starts_nothing(multi, submitted):
    seeded = await seed_env(multi)
    assert (await _deploy(multi, seeded, "data")).status == "succeeded"
    (multi["data"].folder("uat-data") / "state" / "db").write_text("DATA\n")
    backup = await _owner_job(multi, seeded, "backup")
    assert backup.status == "succeeded", backup.error
    [row] = await _backups(seeded)
    dep = await _owner_job(multi, seeded, "restore", restore_backup_id=row.id)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert _steps(dep)["stop_slots"] == _steps(dep)["start_slots"] == "skipped"
    assert _note(dep, "start_slots") == "No app slot has been deployed yet"
    assert "nothing checks the backup's revision" in dep.log or "has no revision" in dep.log


async def test_backups_on_the_data_server_carry_the_environments_identity(multi, submitted):
    seeded = await _live_env(multi)
    assert _env_file(multi, "data", "uat-data")["APP_KEY"] == ""  # blank on the data server (D18)
    backup = await _owner_job(multi, seeded, "backup")
    assert backup.status == "succeeded", backup.error
    [row] = [b for b in await _backups(seeded) if b.deployment_id == backup.id]
    assert row.identity == {"APP_KEY": SECRETS["APP_KEY"]}
    dep = await _owner_job(multi, seeded, "restore", restore_backup_id=row.id)
    assert dep.status == "succeeded", dep.error  # _identity_problem compares the environment's values


# ------------------------------------------------------------------------ test 41: runner keys


async def test_runner_keys_keep_an_owner_backup_and_a_slot_deploy_apart(monkeypatch):
    env_id = uuid.uuid4()
    started: list[str] = []
    gate = asyncio.Event()

    async def slow(deployment_id):
        started.append(deployment_id)
        await gate.wait()

    monkeypatch.setattr(deployer, "run_deployment", slow)
    runner = deployer.DeployRunner()
    runner.submit("backup", data.env_keys(env_id, "backup"))
    runner.submit("deploy-green", data.env_keys(env_id, "deploy"))
    runner.submit("activate", data.env_keys(env_id, "activate"))
    await asyncio.sleep(0.05)
    # The activate runs beside the Back up now at once; the deploy waits for the data key (D8).
    assert started == ["backup", "activate"]
    assert runner.busy(data.env_keys(env_id, "deploy")) and runner.busy(((env_id, "traffic"),))
    with pytest.raises(deployer.RunnerBusy):
        async with runner.exclusive(data.env_keys(env_id, None)):
            pass
    gate.set()
    await asyncio.gather(*runner._tasks)
    assert started == ["backup", "activate", "deploy-green"]
    assert not runner.busy(data.env_keys(env_id, None))
    # A standalone instance keeps its one key, its id.
    inst = uuid.uuid4()
    assert deployer._keys(inst) == (inst,) and deployer._keys((inst,)) == (inst,)
    assert deployer._keys((env_id, "data")) == ((env_id, "data"),)


async def test_control_of_blue_during_greens_deploy_answers_409(admin_client, multi, monkeypatch):
    seeded = await _live_env(multi)
    gate = asyncio.Event()

    async def slow(deployment_id):
        await gate.wait()

    monkeypatch.setattr(deployer, "run_deployment", slow)
    dep_id = await queue(seeded, "green", options={"slot": "green"})
    deployer.runner.submit(dep_id, data.env_keys(seeded.env_id, "deploy"))
    try:
        r = await admin_client.post(f"/api/v1/instances/{seeded.ids['blue']}/actions/stop")
        assert r.status_code == 409, r.text
    finally:
        gate.set()
        await asyncio.gather(*deployer.runner._tasks)


# ------------------------------------------------------------------------- test 42: recovery


async def test_a_start_left_running_keeps_the_mark_in_the_owners_lock(multi, submitted):
    seeded = await _live_env(multi)
    multi["green"].remote.timeout_on = "deploy/app up"
    try:
        dep = await _deploy(multi, seeded, "green")
    finally:
        with contextlib.suppress(Exception):
            multi["green"].remote.stop_timed_out()
        multi["green"].remote.timeout_on = None
    assert dep.status == "failed" and _steps(dep)["start"] == "failed"
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.data_dirty["first"]["deployment_id"] == dep.id.hex
    lock = (multi["data"].folder("uat-data") / ".slipway-lock").read_text().split()
    assert lock[0] == str(dep.id) and lock[3:] == ["start", "d"]
    # The owner's next Back up now meets it, as phase 2 does a data command left running.
    backup = await _owner_job(multi, seeded, "backup")
    assert backup.status == "failed" and "is still running on data-host" in backup.error
    with contextlib.suppress(ProcessLookupError):
        os.kill(int(lock[2]), 9)  # the holder Slipway left on the data host


async def test_recovery_marks_the_owner_and_keeps_the_slots_stopped(multi, submitted):
    seeded = await _live_env(multi)
    green_steps = [{"key": k, "name": k, "status": s} for k, s in (
        ("resolve", "succeeded"), ("backup", "succeeded"), ("start", "running"), ("finish", "pending"))]
    green = await queue(seeded, "green", status="running", steps=green_steps, options={"slot": "green"})
    await deployer.runner.recover_interrupted()
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.data_dirty["first"]["deployment_id"] == green.hex and not owner.data_dirty["hold"]
    assert (await _get(Instance, seeded.ids["green"])).data_dirty is None

    await _set(Instance, seeded.ids["data"], data_dirty=None)
    for slot in ("blue", "green"):
        await _set(Instance, seeded.ids[slot], status="stopped")
    restore_steps = [{"key": k, "name": k, "status": s} for k, s in (
        ("release", "succeeded"), ("check", "succeeded"), ("backup", "succeeded"), ("stop_slots", "succeeded"),
        ("stop", "succeeded"), ("restore", "running"), ("start", "pending"), ("start_slots", "pending"),
        ("finish", "pending"))]
    await queue(seeded, "data", kind="restore", status="running", steps=restore_steps,
                options={"slots_were": {"blue": "running", "green": "running"}, "lead": "blue"})
    await deployer.runner.recover_interrupted()
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.data_dirty["hold"] is True and owner.data_dirty["last"]["slots_stopped"] == ["blue", "green"]
    for slot in ("blue", "green"):
        assert (await _get(Instance, seeded.ids[slot])).status == "stopped"
    async with get_sessionmaker()() as db:
        text = await data.hold_text(db, await db.get(Instance, seeded.ids["green"]))
    assert text.endswith("Blue and Green are stopped.")


async def test_a_chained_job_recovered_as_succeeded_leaves_the_notice(multi, submitted):
    seeded = await seed_env(multi, slots=("blue",))
    data_dep = await _deploy(multi, seeded, "data", options={"chain": True})
    assert data_dep.status == "succeeded"
    submitted.clear()
    # A second data server deploy that a restart cut off after its finish (app_state.went_live names it).
    rows = [{"key": "finish", "name": "finish", "status": "succeeded"}, {"key": "traffic", "name": "t",
                                                                          "status": "running"}]
    async with get_sessionmaker()() as db:  # the blue deploy it chained never ran
        await db.execute(update(Deployment).where(Deployment.status == "queued").values(status="failed"))
        await db.commit()
    lost = await queue(seeded, "data", status="running", steps=rows, options={"chain": True, "slot": "data"},
                       commit_sha=data_dep.commit_sha)
    owner = await _get(Instance, seeded.ids["data"])
    await _set(Instance, seeded.ids["data"], app_state={**owner.app_state, "went_live": lost.hex})
    await deployer.runner.recover_interrupted()
    assert (await _get(Deployment, lost)).status == "succeeded"
    env = await _get(Environment, seeded.env_id)
    assert env.notice["text"] == "Slipway restarted after Update the data server succeeded, before it started Deploy to blue"
    assert env.notice["next"] == {"kind": "deploy", "slot": "blue"}
    assert submitted == []  # nothing queued


# --------------------------------------------------------------------- test 69: _finish


async def test_finish_records_an_environment_level_job_and_owner_fields(multi, submitted):
    seeded = await seed_env(multi, slots=("blue",))
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=None, environment_id=seeded.env_id, kind="publish", branch="main", log="",
                         status="running", steps=[{"key": "check", "name": "Check uat", "status": "pending"}])
        db.add(dep)
        await db.commit()
    await deployer._finish(dep.id, "failed", error="Switchyard said no")
    found = await _get(Deployment, dep.id)
    assert found.status == "failed" and found.error == "Switchyard said no" and found.finished_at is not None
    blue_dep = await queue(seeded, "blue", status="running")
    await deployer._finish(blue_dep, "succeeded", status="running", owner_id=seeded.ids["data"],
                           owner_fields={"fresh_data": "empty", "live_identity": {"APP_KEY": "x" * 44}})
    assert (await _get(Instance, seeded.ids["blue"])).status == "running"
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.fresh_data == "empty" and owner.live_identity == {"APP_KEY": "x" * 44}
    # An environment-level job goes to env_jobs (S8b): this one is refused in its check step.
    async with get_sessionmaker()() as db:
        later = Deployment(instance_id=None, environment_id=seeded.env_id, kind="publish", branch="main", log="",
                           steps=[{"key": "check", "name": "Check uat", "status": "pending"}])
        db.add(later)
        await db.commit()
    assert (await _run(multi, later.id)).error == "uat publishes no names"


# --------------------------------------------------------------- test 43: a single slot (mode slot)


async def test_a_single_slot_environment_runs_phase_2s_data_jobs_with_traffic(multi, submitted, monkeypatch):
    sy = fake_switchyard.install(monkeypatch)
    await fake_switchyard.configure()
    seeded = await seed_env(multi, mode="slot", slots=("blue",), traffic={"switch": "switchyard", "dns": None})
    first = await _deploy(multi, seeded, "blue", options={"go_live": True})
    assert first.status == "succeeded", (first.error, first.log)
    assert list(_steps(first)) == ["resolve", "source", "upload", "manifest", "ports", "settings", "build", "backup",
                                   "start", "finish", "smoke", "traffic"]
    env = _env_file(multi, "blue", "uat-blue")
    assert "APP_EXTERNAL" not in env and env["APP_KEY"] == SECRETS["APP_KEY"] and env["APP_FILES_PORT"]
    blue = await _get(Instance, seeded.ids["blue"])
    assert blue.live_identity == {"APP_KEY": SECRETS["APP_KEY"]} and blue.app_secrets is None
    assert sy.hosts == {}  # not active yet: nothing published
    await _activate(seeded, "blue")
    again = await _deploy(multi, seeded, "blue")
    assert again.status == "succeeded", again.error
    # In place: a sync of every name to the new ports (the check through Switchyard needs its traffic address).
    assert _steps(again)["traffic"] == "warning" and "traffic address" in _note(again, "traffic"), _note(again, "traffic")
    assert sorted(d for h in sy.hosts.values() for d in h["domains"]) == ["files.uat.example.com",
                                                                          "www.uat.example.com"]
    assert all("environment uat" in h["notes"] for h in sy.hosts.values())
    # Phase 2's Back up now, restore and reset, with traffic in place of proxy.
    backup = await _run(multi, await queue(seeded, "blue", kind="backup", commit_sha=again.commit_sha))
    assert backup.status == "succeeded", backup.error
    [row] = [b for b in await _backups_of(seeded.ids["blue"]) if b.deployment_id == backup.id]
    restore = await _run(multi, await queue(seeded, "blue", kind="restore", restore_backup_id=row.id,
                                            commit_sha=again.commit_sha))
    assert restore.status == "succeeded", (restore.error, restore.log)
    assert list(_steps(restore)) == ["release", "manifest", "settings", "build", "check", "backup", "stop", "restore",
                                     "start", "finish", "traffic"]
    rollback_steps = deployer.steps_for(blue, "rollback", environment=await _get(Environment, seeded.env_id),
                                        members={"blue": blue})
    assert [r["key"] for r in rollback_steps][-1] == "traffic"


async def test_a_single_slot_environment_rolls_back_and_resets_as_phase_2_does(multi, submitted, monkeypatch,
                                                                              tmp_path):
    """Test 43's roll back and reset: phase 2's jobs on blue, the data owner of a mode slot environment, run as
    they do for a standalone instance, with ``traffic`` in place of ``proxy`` and no slot stopped or started."""
    fake_switchyard.install(monkeypatch)
    await fake_switchyard.configure()
    seeded = await seed_env(multi, mode="slot", slots=("blue",), traffic={"switch": "switchyard", "dns": None})
    first = await _deploy(multi, seeded, "blue")
    assert first.status == "succeeded", (first.error, first.log)
    await _activate(seeded, "blue")
    # From here blue's database lives in its volume, which the reset deletes.
    volumes = multi["blue"].tmp / "volumes"
    volumes.write_text("demo-uat-blue-db_data demo-uat-blue-db\n")
    multi["blue"].env["FAKE_VOLUME_FILE"] = str(volumes)
    state = multi["blue"].folder("uat-blue") / "state"
    (state / "rev").write_text("rev-1\n")
    (state / "db").write_text("MIGRATED blue\nUSERS\n")

    # Roll back a deploy that failed at start: the backup from before it comes back, with blue's old release.
    flag = tmp_path / "fail-blue"
    flag.write_text("")
    multi["blue"].env["FAIL_FLAG"] = str(flag)
    failed = await _deploy(multi, seeded, "blue", commit_sha="f" * 40)
    assert failed.status == "failed" and _steps(failed)["start"] == "failed", failed.error
    flag.unlink()
    blue = await _get(Instance, seeded.ids["blue"])
    assert blue.data_dirty["first"]["deployment_id"] == failed.id.hex
    async with get_sessionmaker()() as db:
        rollback = await data.rollback_state(db, await db.get(Deployment, failed.id))
    assert rollback.available, rollback.reason
    multi.clear()
    dep = await _run(multi, await queue(seeded, "blue", kind="rollback", restore_backup_id=rollback.backup.id,
                                        commit_sha=blue.app_state["live"]["sha"],
                                        options={"rollback_of": failed.id.hex}))
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert list(_steps(dep)) == ["release", "manifest", "settings", "build", "check", "backup", "stop", "restore",
                                 "start", "finish", "traffic"]
    assert [c.split()[0] for c in multi["blue"].calls()] == [
        "accepts", "has-data", "data", "revision", "pgdump", "verify-dump", "down", "data", "restore", "up"]
    assert (state / "db").read_text() == "MIGRATED blue\nUSERS\nMIGRATED blue\n"
    blue = await _get(Instance, seeded.ids["blue"])
    assert blue.data_dirty is None and blue.status == "running" and not (blue.slot_state or {}).get("stale")
    assert blue.app_state["live"]["sha"] == first.commit_sha
    assert (await _get(Environment, seeded.env_id)).active_slot_id == seeded.ids["blue"]

    # Reset to empty: blue stops, its volume goes after the down, then its start and seed run.
    multi.clear()
    dep = await _run(multi, await queue(seeded, "blue", kind="reset", commit_sha=blue.app_state["live"]["sha"],
                                        options={"seed": True}))
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert list(_steps(dep)) == ["release", "manifest", "settings", "build", "backup", "stop", "reset", "start",
                                 "finish", "seed", "traffic"]
    docker = multi["blue"].docker()
    assert docker.index("volume rm -- demo-uat-blue-db_data") > docker.index(
        "compose -p demo-uat-blue-web down --remove-orphans")
    assert volumes.read_text() == ""  # the data is gone (this fake's up doesn't make the volume again)
    calls = [c.split()[0] for c in multi["blue"].calls()]
    assert [c for c in calls[calls.index("down"):] if c != "has-data"] == ["down", "up", "seed"], calls
    blue = await _get(Instance, seeded.ids["blue"])
    assert blue.data_dirty is None and blue.status == "running"
    assert {"pre_deploy", "pre_rollback", "pre_reset"} <= {b.reason for b in await _backups_of(seeded.ids["blue"])}


async def _backups_of(instance_id: uuid.UUID) -> list[Backup]:
    async with get_sessionmaker()() as db:
        return list((await db.scalars(select(Backup).where(Backup.instance_id == instance_id))).all())


# ------------------------------------------------------------ test 40: update the data server


async def test_updating_the_data_server_syncs_only_its_names_and_checks_the_active_slot(multi, submitted, monkeypatch):
    sy = fake_switchyard.install(monkeypatch)
    await fake_switchyard.configure()
    seeded = await _live_env(multi, traffic={"switch": "switchyard", "dns": None})
    (multi["data"].folder("uat-data") / "state" / "db").write_text("DATA\n")
    multi["blue"].env["FAKE_HTTP_CODES"] = "www.uat.example.com=502"
    dep = await _deploy(multi, seeded, "data")
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert list(_steps(dep)) == ["resolve", "source", "upload", "manifest", "ports", "settings", "build", "backup",
                                 "start", "finish", "traffic", "smoke"]
    assert _steps(dep)["backup"] == "succeeded" and [b for b in await _backups(seeded) if b.deployment_id == dep.id]
    assert [d for h in sy.hosts.values() for d in h["domains"]] == ["files.uat.example.com"]  # no app name
    assert _steps(dep)["smoke"] == "warning" and "after the data server restarted" in _note(dep, "smoke")
    assert not any(c.startswith(("down", "up")) for c in multi["blue"].calls())
    assert not any("stop" in line for line in multi["blue"].docker())
    # A port the slots' settings name may not move. Another instance on the data host takes the database's
    # port, so the real port check (_plan_ports, with _reserved_ports) would move it: refused in ports, before
    # anything is stored or started, and the data server's port rows stay as they were.
    owner = await _get(Instance, seeded.ids["data"])
    live_db = owner.app_state["live"]["host_ports"]["db"]
    published, overrides = owner.published_ports, owner.port_overrides
    assert any(p["service"] == "db" and p["host"] == live_db for p in published), published
    async with get_sessionmaker()() as db:
        squatter = Instance(name="squatter", slug="squatter", branch="main", host_id=owner.host_id,
                            repository_id=owner.repository_id, env={}, ports=[], volumes=[], build_source="app",
                            status="running", published_ports=[{"service": "db", "container": 5432,
                                                                "protocol": "tcp", "host": live_db}])
        db.add(squatter)
        await db.commit()
    multi.clear()
    moved = await _deploy(multi, seeded, "data")
    assert moved.status == "failed" and _steps(moved)["ports"] == "failed" and _steps(moved)["start"] == "pending"
    assert moved.error.startswith(f"The data server's ports would move (db {live_db} → "), moved.error
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.published_ports == published and owner.port_overrides == overrides
    assert owner.app_state["live"]["host_ports"]["db"] == live_db
    assert not any(c.startswith(("down", "data-start")) for c in multi["data"].calls())
    # Once the port is free again (as the message says), the next update keeps the port.
    async with get_sessionmaker()() as db:
        await db.delete(await db.get(Instance, squatter.id))
        await db.commit()
    again = await _deploy(multi, seeded, "data")
    assert again.status == "succeeded", (again.error, again.log)
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.app_state["live"]["host_ports"]["db"] == live_db and owner.port_overrides == overrides


# ------------------------------------------------- tests 36, 64: restoring other identity keys


async def test_restoring_other_identity_keys_writes_the_environment_and_the_owner(multi, submitted):
    seeded = await _live_env(multi)
    backup = await _owner_job(multi, seeded, "backup")
    [row] = [b for b in await _backups(seeded) if b.deployment_id == backup.id]
    other = "z" * 43 + "="
    env = await _get(Environment, seeded.env_id)
    await _set(Environment, seeded.env_id, app_secrets={**env.app_secrets, "APP_KEY": other})
    await _set(Instance, seeded.ids["data"], live_identity={"APP_KEY": other})
    version = (await _get(Environment, seeded.env_id)).secrets_version
    _containers(multi, "blue", "green")
    dep = await _owner_job(multi, seeded, "restore", restore_backup_id=row.id, options={"restore_identity": True})
    assert dep.status == "succeeded", (dep.error, dep.log)
    env = await _get(Environment, seeded.env_id)
    assert env.app_secrets["APP_KEY"] == SECRETS["APP_KEY"] and env.secrets_version == version + 1
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.live_identity == {"APP_KEY": SECRETS["APP_KEY"]} and owner.app_secrets is None
    assert _env_file(multi, "data", "uat-data")["APP_KEY"] == ""  # still blank on the data server
    # Blue was rendered again with the restored key before its start; green stays stopped and stale.
    assert (multi["blue"].folder("uat-blue") / "keys").read_text().strip() == SECRETS["APP_KEY"]
    green = await _get(Instance, seeded.ids["green"])
    assert green.status == "stopped" and green.slot_state["stale"]
    assert SECRETS["APP_KEY"] not in dep.log and other not in dep.log


# ---------------------------------------------------------------- test 37: reset in mode server


async def test_a_reset_on_the_owner_starts_blue_then_creates_the_first_admin_there(multi, submitted):
    seeded = await _live_env(multi, active="blue", seed_content=True)
    async with get_sessionmaker()() as db:
        db.add(FirstAdmin(instance_id=seeded.ids["data"], fields={"email": "ada@example.com", "name": "Ada"},
                          mode="password", password="correct-horse-9"))
        await db.commit()
    _containers(multi, "blue", "green")
    volumes = multi["data"].tmp / "volumes"
    volumes.write_text("demo-uat-data-db_data demo-uat-data-db\n")
    multi["data"].env["FAKE_VOLUME_FILE"] = str(volumes)
    dep = await _owner_job(multi, seeded, "reset", options={"seed": True})
    assert dep.status == "succeeded", (dep.error, dep.log)
    keys = list(_steps(dep))
    assert keys == ["release", "manifest", "settings", "build", "backup", "stop_slots", "stop", "reset", "start",
                    "start_slots", "finish", "first_admin", "seed", "traffic"]
    assert _steps(dep)["first_admin"] == "succeeded" and _steps(dep)["seed"] == "succeeded"
    assert multi["blue"].log("ADMIN_LOG") and not multi["data"].log("ADMIN_LOG")
    assert any(c.startswith("seed ") for c in multi["blue"].calls())
    assert "volume rm -- demo-uat-data-db_data" in multi["data"].docker()
    # The empty database was migrated by blue's start, then seeded on blue.
    assert (multi["data"].folder("uat-data") / "state" / "db").read_text() == "MIGRATED blue\nSEEDED\n"


# An app with a slot-local volume (data.volumes minus data.server.volumes), as ServerSherpa's status page has.
SLOT_LOCAL_YML = ENV_YML.replace(
    '    - {name: "demo-{APP_ENV}-db_data", holds: database}\n',
    '    - {name: "demo-{APP_ENV}-db_data", holds: database}\n    - {name: "demo-{APP_ENV}-web_cache", holds: other}\n', 1)


async def _slot_local_env(multi: MultiRemote, labels: dict[str, str]) -> tuple[Seeded, type]:
    """Blue active and green deployed on blue's commit, each slot's host holding its slot-local volume with the
    Compose label ``labels`` gives, the data host its database volume."""
    gh = github(SLOT_LOCAL_YML)
    seeded = await seed_env(multi)
    for slot in ("data", "blue", "green"):
        dep = await _deploy(multi, seeded, slot, gh=gh)
        assert dep.status == "succeeded", (slot, dep.error, dep.log[-3000:])
    await _activate(seeded, "blue")
    multi.clear()
    _containers(multi, "blue", "green")
    for host, line in (("data", "demo-uat-data-db_data demo-uat-data-db"),
                       *((slot, f"demo-uat-{slot}-web_cache {label}") for slot, label in labels.items())):
        volumes = multi[host].tmp / "volumes"
        volumes.write_text(line + "\n")
        multi[host].env["FAKE_VOLUME_FILE"] = str(volumes)
    return seeded, gh


async def test_a_reset_on_the_owner_deletes_each_slots_own_volumes(multi, submitted):
    seeded, gh = await _slot_local_env(multi, {"blue": "demo-uat-blue-web", "green": "demo-uat-green-web"})
    owner = await _get(Instance, seeded.ids["data"])
    dep = await _run(multi, await queue(seeded, "data", kind="reset", commit_sha=owner.app_state["live"]["sha"]), gh)
    assert dep.status == "succeeded", (dep.error, dep.log)
    for slot in ("blue", "green"):
        log = multi[slot].docker()
        assert f"compose -p demo-uat-{slot}-web down --remove-orphans" in log, log
        assert f"volume rm -- demo-uat-{slot}-web_cache" in log, log
        assert (multi[slot].tmp / "volumes").read_text() == ""
    assert "volume rm -- demo-uat-data-db_data" in multi["data"].docker()
    # Blue (the lead) started with its live start; green's containers are gone, so it stays stopped and stale.
    assert not any(c.endswith(" start") for c in multi["green"].docker())
    green = await _get(Instance, seeded.ids["green"])
    assert (green.slot_state or {}).get("stale") and green.status == "stopped"
    assert (await _get(Instance, seeded.ids["blue"])).status == "running"


async def test_a_foreign_label_on_a_slots_volume_refuses_the_reset_before_the_slots_stop(multi, submitted):
    seeded, gh = await _slot_local_env(multi, {"blue": "demo-uat-blue-web", "green": "someone-else"})
    owner = await _get(Instance, seeded.ids["data"])
    dep = await _run(multi, await queue(seeded, "data", kind="reset", commit_sha=owner.app_state["live"]["sha"]), gh)
    assert dep.status == "failed" and _steps(dep)["backup"] == "failed", (dep.error, dep.log)
    assert _steps(dep)["stop_slots"] == "pending"
    assert dep.error.startswith("The volume demo-uat-green-web_cache belongs to the Compose project someone-else")
    for host in ("data", "blue", "green"):
        assert not any("volume rm" in c or c.endswith(" stop") for c in multi[host].docker()), host


# ---------------------------------------------------------------- test 38: a snapshot that stops the app


async def test_a_snapshot_with_stop_app_stops_both_slots_and_starts_them_before_store(multi, submitted):
    seeded = await _live_env(multi)
    async with get_sessionmaker()() as db:
        snap = Snapshot(name="uat-1", status="pending", origin="instance", app="demo", source="uat",
                        source_instance_id=seeded.ids["data"])
        db.add(snap)
        await db.commit()
    _containers(multi, "blue", "green")
    dep = await _owner_job(multi, seeded, "snapshot", snapshot_id=snap.id, options={"stop_app": True})
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert list(_steps(dep)) == ["release", "stop_slots", "export", "start_slots", "store"]
    for slot in ("blue", "green"):
        docker = multi[slot].docker()
        stop = docker.index(f"compose -p demo-uat-{slot}-web stop")
        assert docker.index(f"compose -p demo-uat-{slot}-web start") > stop
        assert (await _get(Instance, seeded.ids[slot])).status == "running"
    assert any(c.startswith("pgdump ") for c in multi["data"].calls())
    row = await _get(Snapshot, snap.id)
    assert row.status == "ready" and row.identity_keys == ["APP_KEY"]


# ---------------------------------------------------------------- test 39: a seeded environment


async def test_a_seeded_environment_restores_the_snapshot_on_the_data_server(multi, submitted):
    from tests.test_data_jobs import _make_snapshot
    other = "s" * 43 + "="
    sid = await _make_snapshot(db_text="DB:\nFROM-SNAP\n", identity={"APP_KEY": other})
    seeded = await seed_env(multi, slots=("blue",), seed_snapshot_id=sid)
    first = await _deploy(multi, seeded, "data", options={"chain": True})
    assert first.status == "succeeded", (first.error, first.log)
    assert list(_steps(first))[6:] == ["build", "check", "backup", "stop", "restore", "files", "after_import", "start",
                                       "finish", "traffic"]
    assert first.snapshot_id == sid
    assert (multi["data"].folder("uat-data") / "state" / "db").read_text() == "FROM-SNAP\n"
    env = await _get(Environment, seeded.env_id)
    assert env.app_secrets["APP_KEY"] == other  # the snapshot's identity keys became the environment's
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.live_identity == {"APP_KEY": other} and owner.seed_snapshot_id is None
    blue = await _run(multi, submitted[0][0])
    assert blue.status == "succeeded", (blue.error, blue.log)
    assert not {"check", "restore", "files", "after_import", "first_admin"} & set(_steps(blue))
    assert _env_file(multi, "blue", "uat-blue")["APP_KEY"] == other
