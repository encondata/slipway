"""Phase 3 review fixes, data rules: the runner keys of an owner backup in mode slot (F22), Roll back after an
Update the data server (F38), Discard after a later failure on the data server (F46), and the dirty snapshot
text naming the environment (K6)."""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Environment, Instance, User
from slipway.services import data, deployer, environments, jobs
from tests.fake_hosts import ENV_YML, github, seed_env
from tests.test_env_jobs import SWITCHYARD, _job, sites, sy  # noqa: F401
from tests.test_env_pipeline import (  # noqa: F401
    _deploy, _failed_green, _get, _live_env, _run, _steps, multi, no_waits, submitted,
)

FAILING_SERVER = ENV_YML.replace(
    'start: [sh, deploy/app, data-start, "{slipway.env_dir}"]', 'start: [sh, -c, "exit 7"]')


# ----------------------------------------------------------------------------- F22: runner keys


async def test_an_owner_backup_on_an_app_slot_takes_both_keys(multi):
    solo = await seed_env(multi, mode="slot", slots=("blue",), name="solo")
    async with get_sessionmaker()() as db:
        blue = await db.get(Instance, solo.ids["blue"])
        sboth = ((solo.env_id, "data"), (solo.env_id, "traffic"))
        # Mode slot: the owner is blue itself, which an activate starts and switches to.
        assert data.runner_keys(blue, "backup") == sboth
        assert data.runner_keys(blue, "snapshot", {"stop_app": False}) == sboth
        assert data.keys_meet(data.runner_keys(blue, "backup"), data.env_keys(solo.env_id, "activate"))


async def test_a_data_server_backup_that_restops_takes_both_keys(multi):
    shared = await seed_env(multi, name="uat")
    async with get_sessionmaker()() as db:
        server = await db.get(Instance, shared.ids["data"])
        both = ((shared.env_id, "data"), (shared.env_id, "traffic"))
        # Mode server: the data server's backup still runs beside an activate (D8)...
        assert data.runner_keys(server, "backup") == ((shared.env_id, "data"),)
        assert data.runner_keys(server, "snapshot", {"stop_app": False}) == ((shared.env_id, "data"),)
        # ...unless it stops the data server again at its end.
        assert data.runner_keys(server, "backup", {"restop": True}) == both
        assert data.runner_keys(server, "snapshot", {"stop_app": False, "restop": True}) == both
        assert data.env_keys(shared.env_id, "backup", {"restop": False}) == ((shared.env_id, "data"),)


async def test_slot_mode_activate_is_refused_beside_the_owners_backup(multi, submitted):
    """The reproducer: the activate of blue used to queue beside blue's own Back up now and fail at smoke on the
    backup's lock line, telling the user to kill the healthy dump."""
    seeded = await seed_env(multi, mode="slot", slots=("blue",))
    first = await _deploy(multi, seeded, "blue", options={"go_live": False})
    assert first.status == "succeeded", first.error
    submitted.clear()
    async with get_sessionmaker()() as db:
        user = await db.get(User, seeded.user_id)
        blue = await db.get(Instance, seeded.ids["blue"])
        backup = await jobs.queue_job(db, instance=blue, user=user, kind="backup", options={"files": False})
        backup.status = "running"
        await db.commit()
        backup_id = backup.id
        lock = deployer.paths_for(blue).lock
        assert data.job_keys(backup, blue) == ((seeded.env_id, "data"), (seeded.env_id, "traffic"))
    with open(lock, "w") as fh:
        fh.write(f"{backup_id} - {os.getpid()} dump d\n")
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, seeded.env_id)
        user = await db.get(User, seeded.user_id)
        with pytest.raises(jobs.JobRefused) as refused:
            await jobs.queue_job(db, environment=env, user=user, kind="activate", options={"slot": "blue"})
    assert refused.value.status == 409
    assert refused.value.text == "A job is already running for uat (Back up on blue); wait for it to finish"
    async with get_sessionmaker()() as db:
        acts = (await db.scalars(select(Deployment).where(Deployment.environment_id == seeded.env_id,
                                                          Deployment.kind == "activate"))).all()
    assert acts == []


async def test_slot_mode_backup_is_refused_beside_a_running_activate(multi, submitted):
    seeded = await seed_env(multi, mode="slot", slots=("blue",))
    first = await _deploy(multi, seeded, "blue", options={"go_live": False})
    assert first.status == "succeeded", first.error
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, seeded.env_id)
        user = await db.get(User, seeded.user_id)
        act = await jobs.queue_job(db, environment=env, user=user, kind="activate", options={"slot": "blue"})
        await db.commit()
        assert act.status == "queued"
    async with get_sessionmaker()() as db:
        user = await db.get(User, seeded.user_id)
        blue = await db.get(Instance, seeded.ids["blue"])
        with pytest.raises(jobs.JobRefused) as refused:
            await jobs.queue_job(db, instance=blue, user=user, kind="backup", options={"files": False})
    assert refused.value.status == 409 and "(Activate on blue)" in refused.value.text


# ----------------------------------------------------------- F38: Roll back after Update the data server


async def test_update_the_data_server_keeps_roll_back_and_the_retrys_inheritance(multi, submitted, tmp_path):
    seeded = await _live_env(multi)
    (multi["data"].folder("uat-data") / "state" / "db").write_text("MIGRATED blue\nUSERS\n")
    failed = await _failed_green(multi, seeded, tmp_path)
    async with get_sessionmaker()() as db:
        before = await data.rollback_state(db, await db.get(Deployment, failed.id))
        inherited = await data.retry_inheritance(db, await db.get(Deployment, failed.id))
    assert before.available, before.reason
    assert inherited.inherit and inherited.backup_id == failed.backup_id

    upd = await _deploy(multi, seeded, "data")
    assert upd.status == "succeeded", upd.error
    async with get_sessionmaker()() as db:
        after = await data.rollback_state(db, await db.get(Deployment, failed.id))
        inherited = await data.retry_inheritance(db, await db.get(Deployment, failed.id))
        env = await db.get(Environment, seeded.env_id)
        # What the environment page offers reads the same rule.
        user = await db.get(User, seeded.user_id)
        offered = await environments.actions(db, env, SimpleNamespace(user=user, can=user.can))
    assert after.available, after.reason
    assert after.backup is not None and after.backup.id == failed.backup_id and after.needs_reset
    assert inherited.inherit and inherited.backup_id == failed.backup_id
    assert offered["rollback"]["available"], offered["rollback"]
    # The latest changing job itself is still the data server's deploy (D10 elsewhere is unchanged).
    async with get_sessionmaker()() as db:
        latest = await data.latest_changing_job(db, await db.get(Instance, seeded.ids["green"]))
    assert latest.id == upd.id


async def test_a_data_server_deploy_that_replaced_data_still_takes_roll_back_away(multi, submitted, tmp_path):
    seeded = await _live_env(multi)
    failed = await _failed_green(multi, seeded, tmp_path)
    async with get_sessionmaker()() as db:
        seeding = Deployment(instance_id=seeded.ids["data"], environment_id=seeded.env_id, kind="deploy",
                             branch="main", log="", status="succeeded",
                             steps=[{"key": "start", "status": "succeeded"},
                                    {"key": "restore", "status": "succeeded"}])
        db.add(seeding)
        await db.commit()
        state = await data.rollback_state(db, await db.get(Deployment, failed.id))
    assert not state.available
    assert state.reason == f"Deployment {seeding.id.hex[:8]} ran after this deployment; restore a backup instead"


async def test_a_later_slot_job_still_takes_roll_back_away(multi, submitted, tmp_path):
    seeded = await _live_env(multi)
    failed = await _failed_green(multi, seeded, tmp_path)
    async with get_sessionmaker()() as db:
        later = Deployment(instance_id=seeded.ids["data"], environment_id=seeded.env_id, kind="restore",
                           branch="main", log="", status="succeeded", steps=[])
        db.add(later)
        await db.commit()
        state = await data.rollback_state(db, await db.get(Deployment, failed.id))
    assert not state.available and "ran after this deployment" in (state.reason or "")


# --------------------------------------------------------- F46: Discard after a later data server failure


async def test_discard_is_refused_while_a_later_data_server_failure_stands(multi, submitted, sy, tmp_path):
    seeded = await _live_env(multi, active="blue", traffic=SWITCHYARD)
    failed = await _failed_green(multi, seeded, tmp_path)
    upd = await _deploy(multi, seeded, "data", gh=github(FAILING_SERVER))
    assert upd.status == "failed" and _steps(upd)["start"] == "failed", upd.error
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.data_dirty["first"]["deployment_id"] == failed.id.hex
    assert owner.data_dirty["last"]["deployment_id"] == upd.id.hex and not owner.data_dirty["hold"]
    text = (f"Update the data server {upd.id.hex[:8]} failed after green's deploy and left uat's data "
            "half-changed too: retry it first")

    async with get_sessionmaker()() as db:
        state = await data.discard_state(db, await db.get(Environment, seeded.env_id), "green")
    assert not state.available and state.reason == text
    with pytest.raises(jobs.JobRefused) as refused:
        await _job(multi, seeded, "discard", slot="green")
    assert refused.value.text == text
    # A job queued before the failure meets the same check at run time, and wipes nothing.
    dep = await _job(multi, seeded, "discard", raw=True, slot="green")
    assert dep.status == "failed" and _steps(dep)["check"] == "failed" and dep.error == text
    assert (await _get(Instance, seeded.ids["data"])).data_dirty["last"]["deployment_id"] == upd.id.hex

    # Once the data server's deploy succeeds again, Discard green is the way past green's deploy again.
    fixed = await _deploy(multi, seeded, "data")
    assert fixed.status == "succeeded", fixed.error
    async with get_sessionmaker()() as db:
        state = await data.discard_state(db, await db.get(Environment, seeded.env_id), "green")
    assert state.available, state.reason
    dep = await _job(multi, seeded, "discard", slot="green")
    assert dep.status == "succeeded", dep.error
    assert (await _get(Instance, seeded.ids["data"])).data_dirty is None


async def test_discard_still_settles_a_retry_of_the_slot_that_failed_again(multi, submitted, sy, tmp_path):
    seeded = await _live_env(multi, active="blue", traffic=SWITCHYARD)
    failed = await _failed_green(multi, seeded, tmp_path)
    again = await _failed_green(multi, seeded, tmp_path)
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.data_dirty["first"]["deployment_id"] == failed.id.hex
    assert owner.data_dirty["last"]["deployment_id"] == again.id.hex
    async with get_sessionmaker()() as db:
        state = await data.discard_state(db, await db.get(Environment, seeded.env_id), "green")
    assert state.available, state.reason


# ------------------------------------------------------------- K6: the dirty snapshot text


async def test_the_dirty_snapshot_text_names_the_environment_even_when_it_isnt_loaded(multi, submitted, tmp_path):
    seeded = await _live_env(multi)
    failed = await _failed_green(multi, seeded, tmp_path)
    text = (f"uat's data was left half-changed by deployment {failed.id.hex[:8]}; a snapshot of it would seed "
            "others with that. Retry, restore or roll back first.")
    async with get_sessionmaker()() as db:
        owner = await db.get(Instance, seeded.ids["data"])
        assert data.dirty_snapshot_text(owner) == text  # loaded with the instance (selectin)
        db.expire(owner, ["environment"])  # as an instance whose environment wasn't loaded with it
        assert data.loaded_environment(owner) is None
        with pytest.raises(HTTPException) as refused:
            await data.require_data_job(db, owner, "snapshot")
        assert refused.value.detail == text
        snap = Deployment(instance_id=owner.id, environment_id=seeded.env_id, kind="snapshot", branch="main",
                          log="", status="failed")
        assert await data.retry_refusal(db, owner, snap) == text
    # A standalone instance keeps its own name.
    assert data.dirty_snapshot_text(Instance(name="shop", data_dirty={"first": {"kind": "deploy"}})).startswith(
        "shop's data was left half-changed")
