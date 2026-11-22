"""Phase 3 review fixes: job queueing, retries and chained follow-ups (kinds, one-shot options, permissions).

A retry is checked as the kind it retries; a retry never re-arms a snapshot's teardown or keeps a stale go_live;
a chained follow-up needs its own permission of the user it runs as; the retry route asks an environment-level
job only for its kind's permission; and the environment page and the queue agree on what is refused.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy import select

from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Environment, Instance, User
from slipway.services import data, deployer, environments, jobs
from tests.conftest import make_user
from tests.test_data_api import client_with, clients
from tests.test_env_api import (  # noqa: F401  (autouse fixtures)
    _backup,
    _get,
    _update,
    cf,
    github,
    no_public_checks,
    storage,
    submitted,
    sy,
)
from tests.test_env_rules import SHA, T0, Ctx, Who, _failed_green, _job, _load, _world

UNRESOLVED = {"unresolved": {"deployment_id": "ab" * 16, "message": "Slipway restarted during the switch"}}


async def _add(*rows) -> None:
    async with get_sessionmaker()() as db:
        db.add_all(rows)
        await db.commit()


# ------------------------------------------------------------------ F6 / F12: a retried snapshot never deletes


async def test_retry_of_a_snapshot_before_delete_doesnt_tear_the_environment_down(make_client):
    c = await clients(make_client)
    ids = await _world()
    r = await c["maintainer"].request("DELETE", f"/api/v1/environments/{ids['env']}",
                                      json={"confirm": "uat", "snapshot": {"name": "uat-before"}})
    assert r.status_code == 202, r.text
    snap_job = uuid.UUID(r.json()["id"])
    assert r.json()["options"]["then"] == "teardown"
    await _update(Deployment, snap_job, status="failed")
    # A developer may not delete uat, but may retry the snapshot: the retry only takes the snapshot.
    r = await c["developer"].request("DELETE", f"/api/v1/environments/{ids['env']}", json={"confirm": "uat"})
    assert r.status_code == 403
    r = await c["developer"].post(f"/api/v1/deployments/{snap_job}/retry", json={})
    assert r.status_code == 202, r.text
    retry_id = uuid.UUID(r.json()["id"])
    assert "then" not in (await _get(Deployment, retry_id)).options
    await _update(Deployment, retry_id, status="succeeded")
    assert await environments.after_job(retry_id, submit=lambda *a: None) is None
    assert (await _get(Environment, ids["env"])).status == "live"


# ------------------------------------------------------------------ F45: a follow-up's own permission


async def test_a_chained_follow_up_needs_an_active_user_with_its_permission():
    ids = await _world()
    admin = await make_user("admin@example.com")  # the first user is an admin
    developer = await make_user("developer@example.com", roles=["developer"])  # no environments:delete
    green_deploy = _job(ids["green"], ids["env"], "deploy", "succeeded", at=T0 + timedelta(hours=1),
                        commit_sha=SHA, options={"slot": "green", "go_live": True}, triggered_by_id=admin.id)
    await _add(green_deploy)
    # The user was deactivated while the deploy ran: Activate isn't queued, the notice says why.
    await _update(User, admin.id, is_active=False)
    assert await environments.after_job(green_deploy.id, submit=lambda *a: None) is None
    env = await _get(Environment, ids["env"])
    assert env.notice["text"] == ("Activate green didn't start after Deploy to green succeeded: the user who "
                                  "started it was deactivated")
    assert env.notice["next"] == {"kind": "activate", "slot": "green"}
    async with get_sessionmaker()() as db:
        assert (await db.scalars(select(Deployment).where(Deployment.kind == "activate"))).first() is None

    # A snapshot-then-teardown by a user without environments:delete stops before the teardown.
    snap = _job(ids["data"], ids["env"], "snapshot", "succeeded", at=T0 + timedelta(hours=2),
                options={"then": "teardown"}, triggered_by_id=developer.id)
    await _add(snap)
    assert await environments.after_job(snap.id, submit=lambda *a: None) is None
    env = await _get(Environment, ids["env"])
    assert env.status == "live"
    assert env.notice["text"].endswith("the user who started it no longer has the environments:delete permission")

    # A follow-up whose user was deleted isn't queued either.
    orphan = _job(ids["data"], ids["env"], "snapshot", "succeeded", at=T0 + timedelta(hours=3),
                  options={"then": "teardown"})
    await _add(orphan)
    assert await environments.after_job(orphan.id, submit=lambda *a: None) is None
    env = await _get(Environment, ids["env"])
    assert env.status == "live" and env.notice["text"].endswith("the user who started it no longer exists")

    # The same Activate is queued for an active user who holds traffic:switch.
    await _update(User, admin.id, is_active=True)
    queued = await environments.after_job(green_deploy.id, submit=lambda *a: None)
    assert queued is not None and (await _get(Deployment, queued)).kind == "activate"


# ------------------------------------------------------------------ F7 / F39: a retry is checked as its kind


async def test_retry_of_a_restore_meets_the_unresolved_switch_fence(make_client):
    c = await clients(make_client)
    ids = await _world()
    bid = await _backup(ids["data"])
    failed = _job(ids["data"], ids["env"], "restore", "failed", at=T0 + timedelta(hours=1), restore_backup_id=bid,
                  steps=[{"key": "release", "status": "failed", "name": "Release"}])
    await _add(failed)
    await _update(Environment, ids["env"], traffic_state=UNRESOLVED)
    unresolved = environments.unresolved_text(await _get(Environment, ids["env"]))
    r = await c["admin"].post(f"/api/v1/instances/{ids['data']}/data/restore",
                              json={"backup_id": str(bid), "confirm": "uat"})
    assert (r.status_code, r.json()["detail"]) == (409, unresolved)
    r = await c["admin"].post(f"/api/v1/deployments/{failed.id}/retry", json={"confirm": "uat"})
    assert (r.status_code, r.json()["detail"]) == (409, unresolved)


async def test_retry_of_a_restore_is_allowed_under_anothers_hold(make_client):
    c = await clients(make_client)
    ids = await _world()
    bid = await _backup(ids["data"])
    held_by = _job(ids["data"], ids["env"], "restore", "failed", at=T0 + timedelta(hours=1), restore_backup_id=bid,
                   steps=[{"key": "restore", "name": "Restore", "status": "failed"}])
    await _add(held_by)
    await _update(Instance, ids["data"], data_dirty=data.mark_dirty(None, held_by, step="restore",
                                                                  at=T0 + timedelta(hours=1)))
    r = await c["admin"].post(f"/api/v1/instances/{ids['data']}/data/restore",
                              json={"backup_id": str(bid), "confirm": "uat"})
    assert r.status_code == 202, r.text  # a restore is allowed under the hold (§7.5)
    second = uuid.UUID(r.json()["id"])
    await _update(Deployment, second, status="failed", finished_at=T0 + timedelta(hours=2),
                  steps=[{"key": "release", "name": "Release", "status": "failed"}])
    r = await c["admin"].post(f"/api/v1/deployments/{second}/retry", json={"confirm": "uat"})
    assert r.status_code == 202, r.text
    assert r.json()["kind"] == "restore"
    assert "slot" not in r.json()["options"] and "go_live" not in r.json()["options"]  # no deploy defaults


async def test_retry_of_a_data_job_gets_no_deploy_defaults():
    ids = await _world(mode="slot", slots=("blue",), live=("blue",), active=None)
    admin = await make_user("admin@example.com")
    failed = _job(ids["blue"], ids["env"], "backup", "failed", at=T0 + timedelta(hours=1),
                  steps=[{"key": "backup", "name": "Back up", "status": "failed"}])
    await _add(failed)
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, ids)
        user = await db.get(User, admin.id)
        retry = await jobs.queue_job(db, instance=mem["blue"], environment=env, user=user, retry_of=failed)
        assert retry.kind == "backup"
        assert "go_live" not in retry.options and "slot" not in retry.options


# ------------------------------------------------------------------ F25: go_live is decided again


async def test_retry_of_a_slot_deploy_decides_go_live_again():
    ids = await _world(auto_activate=False)
    admin = await make_user("admin@example.com")
    failed = _job(ids["green"], ids["env"], "deploy", "failed", at=T0 + timedelta(hours=1), commit_sha=SHA,
                  options={"slot": "green", "go_live": True}, steps=[{"key": "build", "name": "Build", "status": "failed"}])
    # A chained deploy of a slot just added (§9.8) didn't go live, and its retry doesn't either.
    added = _job(ids["green"], ids["env"], "deploy", "failed", at=T0 + timedelta(hours=2), commit_sha=SHA,
                 options={"slot": "green", "go_live": False, "chain": True},
                 steps=[{"key": "build", "name": "Build", "status": "failed"}])
    await _add(failed, added)
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, ids)
        user = await db.get(User, admin.id)
        assert environments.goes_live(env, "green", mem) is False
        retry = await jobs.queue_job(db, instance=mem["green"], environment=env, user=user, retry_of=failed)
        assert retry.options["go_live"] is False
        retry.status = "succeeded"
        await db.commit()
        assert await environments.next_job(db, retry) is None
    await _update(Environment, ids["env"], auto_activate=True)
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, ids)
        user = await db.get(User, admin.id)
        again = await jobs.queue_job(db, instance=mem["green"], environment=env, user=user, retry_of=failed)
        assert again.options["go_live"] is True  # the rule as it stands now (auto_activate, two slots)
        await db.rollback()
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, ids)
        user = await db.get(User, admin.id)
        chained = await jobs.queue_job(db, instance=mem["green"], environment=env, user=user, retry_of=added)
        assert chained.options["go_live"] is False and chained.options["chain"] is True


# ------------------------------------------------------------------ F56: the unresolved fence on data jobs


async def test_an_unresolved_switch_refuses_data_jobs_that_stop_or_run_on_a_slot():
    ids = await _world(traffic_state=UNRESOLVED)
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, ids)
        text = environments.unresolved_text(env)

        async def refusal(kind, **options):
            found = await jobs.job_refusal(db, instance=mem["data"], environment=env, user=Who(), kind=kind,
                                           options=options, members=mem)
            return (found.status, found.text) if found is not None else None

        assert await refusal("snapshot", stop_app=True) == (409, text)
        assert await refusal("admin") == (409, text)
        assert await refusal("content") == (409, text)
        assert await refusal("snapshot", stop_app=False) is None
        assert await refusal("backup") is None


# ------------------------------------------------------------------ F48: a new environment's deploy goes live


async def test_the_first_deploy_of_a_server_environment_needs_traffic_switch_up_front():
    ids = await _world(slots=("blue", "green", "data"), live=(), active=None, status="new")
    no_switch = Who(perms={"deployments:create", "environments:read"})
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, ids)
        found = await jobs.job_refusal(db, instance=mem["data"], environment=env, user=no_switch,
                                       options={"slot": "data", "chain": True}, members=mem)
        assert (found.status, found.text) == (403, "Deploying uat makes blue live, which needs the traffic:switch "
                                                   "permission")
        # Without the chain (update the data server) or with the permission, nothing refuses.
        assert await jobs.job_refusal(db, instance=mem["data"], environment=env, user=no_switch,
                                      options={"slot": "data"}, members=mem) is None
        assert await jobs.job_refusal(db, instance=mem["data"], environment=env, user=Who(),
                                      options={"slot": "data", "chain": True}, members=mem) is None
        out = await environments.actions(db, env, Ctx(no_switch))
        assert out["deploy"]["slot"] == "data" and out["deploy"]["needs_traffic_switch"] is True
        assert out["deploy"]["available"] is False and "traffic:switch" in out["deploy"]["reason"]
        assert (await environments.actions(db, env, Ctx()))["deploy"]["available"] is True


# ------------------------------------------------------------------ F28: a retried roll back on shared data


async def test_retry_of_a_roll_back_on_shared_data_needs_data_reset(make_client):
    c = await clients(make_client)
    ids = await _world()
    async with get_sessionmaker()() as db:
        failed = await _failed_green(db, ids)
    r = await c["maintainer"].post(f"/api/v1/deployments/{failed.id}/rollback", json={"confirm": "uat"})
    assert r.status_code == 202, r.text
    rollback = uuid.UUID(r.json()["id"])
    await _update(Deployment, rollback, status="failed")
    r = await c["developer"].post(f"/api/v1/deployments/{rollback}/retry", json={"confirm": "uat"})
    assert (r.status_code, r.json()["detail"]) == (403, "Missing permission: data:reset")
    r = await c["maintainer"].post(f"/api/v1/deployments/{rollback}/retry", json={"confirm": "uat"})
    assert r.status_code == 202, r.text
    assert r.json()["kind"] == "rollback"


# ------------------------------------------------------------------ F49: the retry route's permissions


async def test_retry_of_an_environment_job_needs_only_its_kinds_permission(make_client):
    await make_user("first@example.com")
    ids = await _world()
    publish = _job(None, ids["env"], "publish", "failed", at=T0 + timedelta(hours=3),
                   steps=[{"key": "check", "name": "Check", "status": "failed"}])
    teardown = _job(None, ids["env"], "teardown", "failed", at=T0 + timedelta(hours=3), options={"confirmed": True},
                    steps=[{"key": "check", "name": "Check", "status": "succeeded"},
                           {"key": "slots", "name": "Slots", "status": "failed"}])
    await _add(publish, teardown)
    switcher = await client_with(make_client, "sw@example.com",
                                 ["environments:read", "deployments:read", "traffic:switch"])
    r = await switcher.post(f"/api/v1/deployments/{publish.id}/retry", json={})
    assert r.status_code == 202, r.text
    await _update(Deployment, uuid.UUID(r.json()["id"]), status="cancelled")
    deleter = await client_with(make_client, "del@example.com",
                                ["environments:read", "deployments:read", "environments:delete"])
    await _update(Environment, ids["env"], status="deleting")
    r = await deleter.post(f"/api/v1/deployments/{teardown.id}/retry", json={"confirm": "uat"})
    assert r.status_code == 202, r.text
    # An instance job's retry still needs deployments:create.
    failed = _job(ids["data"], ids["env"], "backup", "failed", at=T0 + timedelta(hours=4))
    await _add(failed)
    backupper = await client_with(make_client, "bk@example.com", ["instances:read", "deployments:read", "data:backup"])
    r = await backupper.post(f"/api/v1/deployments/{failed.id}/retry", json={})
    assert (r.status_code, r.json()["detail"]) == (403, "Missing permission: deployments:create")


# ------------------------------------------------------------------ F54: Delete while deleting


async def test_delete_is_off_while_a_failed_teardown_leaves_the_environment_deleting():
    ids = await _world()
    await _add(_job(None, ids["env"], "teardown", "failed", at=T0 + timedelta(hours=3), options={"confirmed": True}))
    await _update(Environment, ids["env"], status="deleting")
    async with get_sessionmaker()() as db:
        env, _ = await _load(db, ids)
        out = await environments.actions(db, env, Ctx())
        assert out["delete"] == {"available": False,
                                 "reason": "uat is being deleted: retry its teardown from the job's page"}


# ------------------------------------------------------------------ K2 / K3


async def test_a_queued_member_job_shows_its_environments_steps():
    ids = await _world()
    admin = await make_user("admin@example.com")
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, ids)
        user = await db.get(User, admin.id)
        dep = await jobs.queue_job(db, instance=mem["green"], environment=env, user=user)
        assert dep.steps == deployer.steps_for(mem["green"], environment=env, members=mem)
        assert dep.steps != deployer.new_steps(mem["green"])  # not phase 2's list
        await db.rollback()
        env, mem = await _load(db, ids)
        user = await db.get(User, admin.id)
        backup = await jobs.queue_job(db, instance=mem["data"], environment=env, user=user, kind="backup")
        assert backup.steps == deployer.steps_for(mem["data"], "backup", environment=env, members=mem)


async def test_a_retried_activate_carries_no_switch_record():
    ids = await _world()
    admin = await make_user("admin@example.com")
    failed = _job(None, ids["env"], "activate", "failed", at=T0 + timedelta(hours=1),
                  options={"slot": "green", "from_slot": "blue", "switch": {"changed": ["api"], "applied": True}})
    await _add(failed)
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, ids)
        user = await db.get(User, admin.id)
        retry = await jobs.queue_job(db, environment=env, user=user, kind="activate", retry_of=failed)
        assert "switch" not in retry.options and retry.options["slot"] == "green"
