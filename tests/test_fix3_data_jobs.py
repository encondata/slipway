"""Phase 3 review fixes: the data owner's jobs in mode ``server`` (restore, roll back, reset, snapshot, Start over,
Create it now, Add starter content) and a slot deploy whose backup is skipped.

Each test is a reviewer's reproducer turned around: it fails before the fix and passes after. They run through
the real deployer on the fake hosts of tests/fake_hosts.py, as tests/test_env_pipeline.py does.
"""

from __future__ import annotations

from sqlalchemy import select

from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Environment, FirstAdmin, Host, Instance, Snapshot
from slipway.services import data, deployer
from tests.fake_hosts import ENV_YML, github, queue, seed_env
from tests.test_env_pipeline import (  # noqa: F401
    SLOT_LOCAL_YML,
    _activate,
    _backups,
    _containers,
    _deploy,
    _failed_green,
    _get,
    _live_env,
    _note,
    _owner_job,
    _run,
    _set,
    _steps,
    multi,
    no_waits,
    submitted,
)

STALE = {"reason": "Its deploy abcd1234 failed and was discarded", "at": "2026-11-01T00:00:00+00:00",
         "deployment_id": "ab" * 16}


async def _snapshot_row(seeded) -> Snapshot:
    async with get_sessionmaker()() as db:
        snap = Snapshot(name="uat-1", status="pending", origin="instance", app="demo", source="uat",
                        source_instance_id=seeded.ids["data"])
        db.add(snap)
        await db.commit()
        return snap


def _compose(multi, slot: str, action: str) -> bool:
    return f"compose -p demo-uat-{slot}-web {action}" in multi[slot].docker()


# ------------------------------------------------- F3, F13, F21: start_slots starts only what was running


async def test_a_snapshot_leaves_a_discarded_stale_slot_stopped(multi, submitted):
    seeded = await _live_env(multi)
    await _set(Instance, seeded.ids["green"], status="stopped", slot_state={"stale": STALE})
    snap = await _snapshot_row(seeded)
    _containers(multi, "blue", "green")
    dep = await _owner_job(multi, seeded, "snapshot", snapshot_id=snap.id, options={"stop_app": True})
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert dep.options["slots_were"] == {"blue": "running", "green": "stopped"}
    assert _compose(multi, "blue", "start") and not _compose(multi, "green", "start")
    green = await _get(Instance, seeded.ids["green"])
    assert green.status == "stopped" and green.slot_state["stale"] == STALE
    assert (await _get(Instance, seeded.ids["blue"])).status == "running"
    assert _note(dep, "start_slots") == "Green stays stopped, as before the snapshot"


async def test_a_snapshot_leaves_a_slot_that_was_stopped_stopped(multi, submitted):
    seeded = await _live_env(multi)
    await _set(Instance, seeded.ids["green"], status="stopped")
    snap = await _snapshot_row(seeded)
    _containers(multi, "blue", "green")
    dep = await _owner_job(multi, seeded, "snapshot", snapshot_id=snap.id, options={"stop_app": True})
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert not _compose(multi, "green", "start")
    assert (await _get(Instance, seeded.ids["green"])).status == "stopped"


async def test_a_restore_leaves_a_slot_that_was_stopped_stopped_and_not_stale(multi, submitted):
    seeded = await _live_env(multi)
    backup = await _owner_job(multi, seeded, "backup")
    assert backup.status == "succeeded", backup.error
    await _set(Instance, seeded.ids["green"], status="stopped")
    multi.clear()
    _containers(multi, "blue", "green")
    dep = await _owner_job(multi, seeded, "restore", restore_backup_id=backup.backup_id)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert dep.options["slots_were"] == {"blue": "running", "green": "stopped"}
    assert not _compose(multi, "green", "start")
    green = await _get(Instance, seeded.ids["green"])
    # Green runs blue's commit, so it could run on the restored data: it stays as the operator left it.
    assert green.status == "stopped" and not (green.slot_state or {}).get("stale")
    assert (await _get(Instance, seeded.ids["blue"])).status == "running"
    assert _note(dep, "start_slots") == "green stays stopped, as before the restore"


async def test_a_restore_keeps_a_stale_slot_stopped_with_its_mark(multi, submitted):
    seeded = await _live_env(multi)
    backup = await _owner_job(multi, seeded, "backup")
    await _set(Instance, seeded.ids["green"], status="stopped", slot_state={"stale": STALE})
    multi.clear()
    _containers(multi, "blue", "green")
    dep = await _owner_job(multi, seeded, "restore", restore_backup_id=backup.backup_id)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert not _compose(multi, "green", "start")
    green = await _get(Instance, seeded.ids["green"])
    assert green.status == "stopped" and green.slot_state["stale"] == STALE


async def test_a_restore_after_greens_failed_deploy_marks_green_stale(multi, submitted, tmp_path):
    seeded = await _live_env(multi)
    (multi["data"].folder("uat-data") / "state" / "rev").write_text("rev-1\n")
    backup = await _owner_job(multi, seeded, "backup")
    await _failed_green(multi, seeded, tmp_path)
    multi.clear()
    _containers(multi, "blue", "green")
    dep = await _owner_job(multi, seeded, "restore", restore_backup_id=backup.backup_id)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert dep.options["slots_were"]["green"] == "failed"
    assert not _compose(multi, "green", "start")  # its containers may be the failed release
    green = await _get(Instance, seeded.ids["green"])
    assert green.status == "stopped" and green.slot_state["stale"]["reason"].startswith(
        "Stopped when uat's data was restored")


async def test_a_retry_of_a_held_restore_starts_the_slots_the_first_attempt_stopped(multi, submitted, tmp_path):
    """The slots a failed restore left stopped count as running for the next one (data_dirty.last.slots_stopped)."""
    seeded = await _live_env(multi)
    backup = await _owner_job(multi, seeded, "backup")
    flag = tmp_path / "fail-blue"
    flag.write_text("")
    multi["blue"].env["FAIL_FLAG"] = str(flag)
    first = await _owner_job(multi, seeded, "restore", restore_backup_id=backup.backup_id)
    assert first.status == "failed" and _steps(first)["start_slots"] == "failed"
    flag.unlink()
    async with get_sessionmaker()() as db:
        values = await deployer.retry_values(db, await db.get(Deployment, first.id))
    multi.clear()
    _containers(multi, "blue", "green")
    retry = await _run(multi, await queue(seeded, "data", retry_of_id=first.id,
                                          **{**values, "options": {**values["options"], "override_hold": True}}))
    assert retry.status == "succeeded", (retry.error, retry.log)
    assert retry.options["slots_were"] == {"blue": "running", "green": "running"}
    assert retry.options["lead"] == "blue" and retry.options["slots_started"] == ["blue", "green"]
    for slot in ("blue", "green"):
        assert (await _get(Instance, seeded.ids[slot])).status == "running"
    assert (await _get(Instance, seeded.ids["data"])).data_dirty is None


async def test_a_restore_with_no_slot_running_starts_none_and_marks_them_stale(multi, submitted):
    seeded = await _live_env(multi)
    backup = await _owner_job(multi, seeded, "backup")
    for slot in ("blue", "green"):
        await _set(Instance, seeded.ids[slot], status="stopped")
    multi.clear()
    _containers(multi, "blue", "green")
    dep = await _owner_job(multi, seeded, "restore", restore_backup_id=backup.backup_id)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert dep.options["lead"] is None
    assert not any(c.startswith("up ") for c in multi["blue"].calls() + multi["green"].calls())
    assert "No app slot was running before the restore, so none was started" in _note(dep, "start_slots")
    for slot in ("blue", "green"):
        inst = await _get(Instance, seeded.ids[slot])
        assert inst.status == "stopped" and inst.slot_state["stale"]


# ---------------------------------------------------- F19: stop_slots stops a slot whose first deploy failed


async def test_a_roll_back_of_greens_failed_first_deploy_stops_green_and_marks_it_stale(multi, submitted, tmp_path):
    seeded = await seed_env(multi)
    for slot in ("data", "blue"):
        dep = await _deploy(multi, seeded, slot)
        assert dep.status == "succeeded", dep.error
    await _activate(seeded, "blue")
    (multi["data"].folder("uat-data") / "state" / "db").write_text("MIGRATED blue\nUSERS\n")
    flag = tmp_path / "fail-green"
    flag.write_text("")
    multi["green"].env["FAIL_FLAG"] = str(flag)
    failed = await _deploy(multi, seeded, "green")
    assert failed.status == "failed" and _steps(failed)["start"] == "failed"
    flag.unlink()
    async with get_sessionmaker()() as db:
        state = await data.rollback_state(db, await db.get(Deployment, failed.id))
    assert state.available, state.reason
    multi.clear()
    _containers(multi, "blue", "green")
    dep = await _owner_job(multi, seeded, "rollback", restore_backup_id=state.backup.id,
                           options={"rollback_of": failed.id.hex})
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert dep.options["slots_were"] == {"blue": "running", "green": "failed"}
    assert _compose(multi, "green", "stop") and not _compose(multi, "green", "start")
    green = await _get(Instance, seeded.ids["green"])
    assert green.status == "stopped" and green.slot_state["stale"]


# ------------------------------------------- F17: a stop_slots that fails part-way starts the slots again


async def test_a_restore_whose_stop_slots_fails_halfway_starts_blue_again(multi, submitted):
    seeded = await _live_env(multi)
    (multi["data"].folder("uat-data") / "state" / "rev").write_text("rev-1\n")
    backup = await _owner_job(multi, seeded, "backup")
    multi.clear()
    _containers(multi, "blue", "green")
    multi["green"].env["FAKE_PS_FAILS"] = "1"  # green's docker ps fails: its stop fails after blue's stopped
    dep = await _owner_job(multi, seeded, "restore", restore_backup_id=backup.backup_id)
    assert dep.status == "failed" and _steps(dep)["stop_slots"] == "failed"
    assert _steps(dep)["stop"] == "pending"
    docker = multi["blue"].docker()
    assert docker.index("compose -p demo-uat-blue-web start") > docker.index("compose -p demo-uat-blue-web stop")
    assert (await _get(Instance, seeded.ids["blue"])).status == "running"
    assert "Slipway started Blue again; nothing was changed" in dep.error
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.status == "running" and owner.data_dirty is None


def test_a_data_job_lost_in_stop_slots_names_the_slots_it_left_stopped():
    rows = [{"key": "stop_slots", "status": "running"}, {"key": "stop", "status": "pending"}]
    dep = Deployment(kind="restore", steps=rows,
                     options={"slots_were": {"blue": "running", "green": "stopped"}, "slots_started": []})
    assert data.slots_left_stopped(dep) == ["blue"]
    assert not data.change_began(dep)
    dep.options = {**dep.options, "slots_started": ["blue"]}
    assert data.slots_left_stopped(dep) == []
    assert data.slots_left_stopped(Deployment(kind="snapshot", steps=[{"key": "stop_slots", "status": "pending"}],
                                              options={"slots_were": {"blue": "running"}})) == []


# ------------------------------------------------ F4: the lead slot's render is checked before anything stops


async def test_a_reset_refuses_the_lead_slots_render_before_anything_stops(multi, submitted):
    seeded = await _live_env(multi, active="blue")
    # blue's host was given another LAN address since the data server's last deploy (it isn't let in yet).
    await _set(Host, seeded.host_ids["blue"], lan_address="10.0.0.99")
    _containers(multi, "blue", "green")
    volumes = multi["data"].tmp / "volumes"
    volumes.write_text("demo-uat-data-db_data demo-uat-data-db\n")
    multi["data"].env["FAKE_VOLUME_FILE"] = str(volumes)
    dep = await _owner_job(multi, seeded, "reset", options={"seed": False})
    assert dep.status == "failed"
    assert _steps(dep)["stop_slots"] == "failed" and _steps(dep)["reset"] == "pending"
    assert dep.error.startswith("blue couldn't start again after the reset (")
    assert dep.error.endswith("Nothing was changed.")
    assert not any("volume rm" in c for c in multi["data"].docker())
    assert not _compose(multi, "blue", "stop") and not _compose(multi, "green", "stop")
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.data_dirty is None and owner.status == "running"
    assert (await _get(Instance, seeded.ids["blue"])).status == "running"


# ------------------------------------------- F2: Retry without the backup still runs the D7 lag check


async def test_a_retry_without_the_backup_still_runs_the_lag_check(multi, submitted):
    seeded = await _live_env(multi)
    (multi["data"].folder("uat-data") / "state" / "rev").write_text("rev-9\n")
    multi["blue"].env["UNKNOWN_REVS"] = "rev-9"
    dep = await _deploy(multi, seeded, "green")
    assert dep.status == "failed" and "already runs on a database migrated past it" in dep.error
    async with get_sessionmaker()() as db:
        values = await deployer.retry_values(db, await db.get(Deployment, dep.id))
    values["options"] = {**values["options"], "skip_backup": True}
    multi.clear()
    retry = await _run(multi, await queue(seeded, "green", retry_of_id=dep.id, **values))
    assert retry.status == "failed" and _steps(retry)["backup"] == "failed", (retry.error, _steps(retry))
    assert "already runs on a database migrated past it" in retry.error
    assert not any(c.startswith("up ") for c in multi["green"].calls())  # green never migrated the database
    assert not any(c.startswith("pgdump ") for c in multi["data"].calls())  # still no backup


async def test_a_retry_without_the_backup_runs_when_the_active_slot_accepts(multi, submitted):
    seeded = await _live_env(multi)
    (multi["data"].folder("uat-data") / "state" / "rev").write_text("rev-9\n")
    multi["blue"].env["UNKNOWN_REVS"] = "rev-9"
    dep = await _deploy(multi, seeded, "green")
    assert dep.status == "failed"
    multi["blue"].env["UNKNOWN_REVS"] = ""
    async with get_sessionmaker()() as db:
        values = await deployer.retry_values(db, await db.get(Deployment, dep.id))
    values["options"] = {**values["options"], "skip_backup": True}
    retry = await _run(multi, await queue(seeded, "green", retry_of_id=dep.id, **values))
    assert retry.status == "succeeded", (retry.error, retry.log)
    assert _steps(retry)["backup"] == "warning"
    assert "can run the data at revision rev-9 too" in retry.log


# ------------------------------------ F5: Create it now and Add starter content run on the active slot


async def _pending_admin(seeded) -> None:
    async with get_sessionmaker()() as db:
        db.add(FirstAdmin(instance_id=seeded.ids["data"], fields={"email": "ada@example.com", "name": "Ada"},
                          mode="password", password="correct-horse-9"))
        await db.commit()


async def test_create_it_now_on_the_data_owner_runs_on_the_active_slot(multi, submitted):
    seeded = await _live_env(multi, active="green")
    await _pending_admin(seeded)
    dep = await _owner_job(multi, seeded, "admin")
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert _steps(dep)["first_admin"] == "succeeded", _note(dep, "first_admin")
    assert multi["green"].log("ADMIN_LOG") and not multi["blue"].log("ADMIN_LOG")
    assert not multi["data"].log("ADMIN_LOG")
    async with get_sessionmaker()() as db:
        row = await db.scalar(select(FirstAdmin).where(FirstAdmin.instance_id == seeded.ids["data"]))
    assert row.status == "done"


async def test_add_starter_content_on_the_data_owner_runs_on_the_active_slot(multi, submitted):
    seeded = await _live_env(multi)
    await _set(Instance, seeded.ids["data"], content_pending=True)
    dep = await _owner_job(multi, seeded, "content")
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert _steps(dep)["seed"] == "succeeded", _note(dep, "seed")
    assert any(c.startswith("seed ") for c in multi["blue"].calls())
    assert (multi["data"].folder("uat-data") / "state" / "db").read_text().endswith("SEEDED\n")
    assert (await _get(Instance, seeded.ids["data"])).content_pending is False


async def test_create_it_now_skips_a_stopped_active_slot(multi, submitted):
    seeded = await _live_env(multi)
    await _pending_admin(seeded)
    await _set(Instance, seeded.ids["blue"], status="stopped")
    dep = await _owner_job(multi, seeded, "admin")
    assert _steps(dep)["first_admin"] == "warning"
    assert _note(dep, "first_admin") == "blue isn't running: start it, then try again"
    assert not multi["blue"].log("ADMIN_LOG")


async def test_create_it_now_and_add_starter_content_asked_on_a_slot_queue_the_owners_job(
        admin_client, multi, submitted):
    seeded = await _live_env(multi)
    await _pending_admin(seeded)
    await _set(Instance, seeded.ids["data"], content_pending=True)
    r = await admin_client.post(f"/api/v1/instances/{seeded.ids['blue']}/first-admin/run")
    assert r.status_code == 202, r.text
    assert r.json()["kind"] == "admin" and r.json()["instance_id"] == str(seeded.ids["data"])
    await _set(Deployment, __import__("uuid").UUID(r.json()["id"]), status="succeeded")
    r = await admin_client.post(f"/api/v1/instances/{seeded.ids['green']}/content/run")
    assert r.status_code == 202, r.text
    assert r.json()["kind"] == "content" and r.json()["instance_id"] == str(seeded.ids["data"])


async def test_create_it_now_is_refused_while_the_active_slot_is_stopped(admin_client, multi, submitted):
    seeded = await _live_env(multi)
    await _pending_admin(seeded)
    await _set(Instance, seeded.ids["blue"], status="stopped")
    r = await admin_client.post(f"/api/v1/instances/{seeded.ids['data']}/first-admin/run")
    assert r.status_code == 409 and r.json()["detail"] == "uat blue isn't running: start it, then create the first admin"


# ------------------------------------- F8: a backup restore is pinned by the environment's variables


async def test_a_backup_restore_is_refused_when_an_environment_variable_pins_the_key(multi, submitted):
    seeded = await _live_env(multi)
    backup = await _owner_job(multi, seeded, "backup")
    [row] = [b for b in await _backups(seeded) if b.deployment_id == backup.id]
    await _set(Environment, seeded.env_id, env={"APP_KEY": "Q" * 43 + "="})
    # The data is made with the variable's value now. (A data server deploy no longer records it over the
    # recorded one, F35 in test_fix3_member_finish; a restore of other keys would.)
    await _set(Instance, seeded.ids["data"], live_identity={"APP_KEY": "Q" * 43 + "="})
    owner = await _get(Instance, seeded.ids["data"])
    rule = data.restorable(owner, row)
    assert not rule.ok and rule.reason == data.env_pin_message("APP_KEY")
    multi.clear()
    _containers(multi, "blue", "green")
    dep = await _owner_job(multi, seeded, "restore", restore_backup_id=row.id, options={"restore_identity": True})
    assert dep.status == "failed" and _steps(dep)["check"] == "failed"
    assert data.env_pin_message("APP_KEY").rstrip(".") in dep.error
    assert not _compose(multi, "blue", "stop")


# ------------------------------------------- F32, F55, K1: Start over on the data server


async def _never_live_env(multi, tmp_path, yml: str = ENV_YML):
    """The data server deployed (live), then blue's first deploy failed in start: no app slot ever went live."""
    gh = github(yml)
    seeded = await seed_env(multi)
    dep = await _deploy(multi, seeded, "data", gh=gh)
    assert dep.status == "succeeded", dep.error
    flag = tmp_path / "fail-blue"
    flag.write_text("")
    multi["blue"].env["FAIL_FLAG"] = str(flag)
    failed = await _deploy(multi, seeded, "blue", gh=gh)
    assert failed.status == "failed" and _steps(failed)["start"] == "failed"
    flag.unlink()
    return seeded, gh


async def test_start_over_is_allowed_on_a_live_data_server_until_an_app_slot_goes_live(multi, submitted, tmp_path):
    seeded, gh = await _never_live_env(multi, tmp_path)
    async with get_sessionmaker()() as db:
        owner = await db.get(Instance, seeded.ids["data"])
        assert owner.current_commit_sha
        assert await data.require_data_job(db, owner, "reset", start_over=True) == {}
    dep = await _deploy(multi, seeded, "blue", gh=gh)
    assert dep.status == "succeeded", dep.error
    async with get_sessionmaker()() as db:
        owner = await db.get(Instance, seeded.ids["data"])
        assert await data.start_over_refusal(db, owner) == "An app slot of uat has gone live; use Reset data"


async def test_start_over_on_the_data_server_renders_its_server_role_and_deletes_the_slots_volumes(
        multi, submitted, tmp_path):
    seeded, gh = await _never_live_env(multi, tmp_path, SLOT_LOCAL_YML)
    blue = await _get(Instance, seeded.ids["blue"])
    assert [v["name"] for v in blue.app_state["starting_volumes"]] == ["demo-uat-blue-web_cache"]
    _containers(multi, "blue")
    for host, line in (("data", "demo-uat-data-db_data demo-uat-data-db"),
                       ("blue", "demo-uat-blue-web_cache demo-uat-blue-web")):
        volumes = multi[host].tmp / "volumes"
        volumes.write_text(line + "\n")
        multi[host].env["FAKE_VOLUME_FILE"] = str(volumes)
    owner = await _get(Instance, seeded.ids["data"])
    multi.clear()
    dep = await _run(multi, await queue(seeded, "data", kind="reset", options={"start_over": True},
                                        commit_sha=owner.current_commit_sha), gh)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert list(_steps(dep)) == ["release", "backup", "stop_slots", "stop", "reset"]
    env_file = (multi["data"].folder("uat-data") / "shared" / ".env").read_text()
    assert "DB_PUBLISH=1" in env_file and "APP_KEY=\n" in env_file  # the server role (D18)
    assert "volume rm -- demo-uat-data-db_data" in multi["data"].docker()
    assert _compose(multi, "blue", "stop")
    assert "volume rm -- demo-uat-blue-web_cache" in multi["blue"].docker()
    assert (multi["blue"].tmp / "volumes").read_text() == ""
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.status == "stopped" and owner.fresh_data == "empty" and owner.data_dirty is None


async def test_a_restore_lost_in_stop_slots_says_which_slots_it_left_stopped(multi, submitted):
    seeded = await _live_env(multi)
    await _set(Instance, seeded.ids["blue"], status="stopped")
    steps = [{"key": k, "name": k, "status": s} for k, s in (
        ("release", "succeeded"), ("check", "succeeded"), ("backup", "succeeded"), ("stop_slots", "running"),
        ("stop", "pending"), ("restore", "pending"), ("start", "pending"), ("start_slots", "pending"),
        ("finish", "pending"))]
    dep_id = await queue(seeded, "data", kind="restore", status="running", steps=steps,
                         options={"slots_were": {"blue": "running", "green": "running"}, "lead": "blue",
                                  "slots_started": [], "prev_status": "running"})
    await deployer.runner.recover_interrupted()
    dep = await _get(Deployment, dep_id)
    assert dep.error.endswith("Slipway stopped Blue and Green for the restore and didn't start them again: start "
                              "them on the instance page; nothing else was changed")
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.data_dirty is None and owner.status == "running"


async def test_a_snapshot_lost_with_the_slots_stopped_says_so_and_leaves_the_data_server_running(multi, submitted):
    seeded = await _live_env(multi)
    snap = await _snapshot_row(seeded)
    steps = [{"key": k, "name": k, "status": s} for k, s in (
        ("release", "succeeded"), ("stop_slots", "succeeded"), ("export", "running"), ("start_slots", "pending"),
        ("store", "pending"))]
    dep_id = await queue(seeded, "data", kind="snapshot", status="running", steps=steps, snapshot_id=snap.id,
                         options={"stop_app": True, "slots_were": {"blue": "running"}, "slots_started": []})
    await deployer.runner.recover_interrupted()
    dep = await _get(Deployment, dep_id)
    assert dep.error.endswith("Slipway stopped Blue for the snapshot and didn't start it again: start it on the "
                              "instance page")
    assert (await _get(Instance, seeded.ids["data"])).status == "running"
