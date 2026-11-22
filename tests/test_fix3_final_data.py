"""Final review fixes (phase 3), data jobs in mode server: a snapshot after a reset whose start failed (F3/F13/F21),
Start over on a data server that went live (F55), and identity values while no app has run on the data (F9/F35).

The jobs run through the real pipeline on tests/fake_hosts.py's hosts (nothing leaves the machine).
"""

from __future__ import annotations

import uuid

from slipway.db.session import get_sessionmaker
from slipway.models import Environment, Instance, Snapshot, User
from slipway.services import data, environments, jobs
from tests.fake_hosts import queue, seed_env
from tests.test_env_pipeline import (  # noqa: F401  (fixtures)
    _containers,
    _deploy,
    _get,
    _live_env,
    _owner_job,
    _run,
    _set,
    _steps,
    multi,
    no_waits,
    submitted,
)
from tests.test_fix3_data_jobs import _never_live_env

OTHER = "Q" * 43 + "="
THIRD = "R" * 43 + "="


async def _refusal(seeded, slot: str, **kw):
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, seeded.env_id)
        instance = await db.get(Instance, seeded.ids[slot])
        user = await db.get(User, seeded.user_id)
        found = await jobs.job_refusal(db, instance=instance, environment=env, user=user, **kw)
        return found.text if found is not None else None


# --------------------------------------------------- F3/F13/F21: a snapshot after a reset whose start failed


async def test_a_snapshot_never_starts_the_slots_a_failed_reset_left_stopped(multi, submitted):
    """A reset whose data server ``start`` failed has replaced the data and sets no hold; it records the slots it
    stopped. A later snapshot with stop_app must not compose-start their old containers on the new data (no
    migration runs): only a restore, roll back or reset starts them again, with the lead's live ``start``."""
    seeded = await _live_env(multi)
    fake = uuid.uuid4().hex
    dirty = {"first": {"deployment_id": fake, "kind": "reset", "backup_id": None, "at": "x"},
             "last": {"deployment_id": fake, "kind": "reset", "step": "start", "backup_id": None, "at": "x",
                      "step_text": "step 6/9: Start", "slots_stopped": ["blue", "green"]}, "hold": False}
    await _set(Instance, seeded.ids["data"], data_dirty=dirty)
    for slot in ("blue", "green"):
        await _set(Instance, seeded.ids[slot], status="stopped")
    async with get_sessionmaker()() as db:
        snap = Snapshot(name="uat-1", status="pending", origin="instance", app="demo", source="uat",
                        source_instance_id=seeded.ids["data"])
        db.add(snap)
        await db.commit()
    _containers(multi, "blue", "green")
    dep = await _owner_job(multi, seeded, "snapshot", snapshot_id=snap.id, options={"stop_app": True})
    assert dep.status == "succeeded", dep.error
    assert dep.options["slots_were"] == {"blue": "stopped", "green": "stopped"}
    for slot in ("blue", "green"):
        assert not [line for line in multi[slot].docker() if line.endswith(" start")], multi[slot].docker()
        assert (await _get(Instance, seeded.ids[slot])).status == "stopped"


# ------------------------------------------------------------ F55: Start over on a data server that went live


async def test_start_over_leaves_the_data_server_as_never_deployed(multi, submitted, tmp_path):
    """Start over deletes a live data server's database and stops it. It then counts as never deployed: a slot
    deploy is refused until the data server is updated, and the environment's Deploy goes to the data server."""
    seeded, gh = await _never_live_env(multi, tmp_path)
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.current_commit_sha and owner.live_identity
    _containers(multi, "blue")
    dep = await _run(multi, await queue(seeded, "data", kind="reset", options={"start_over": True},
                                        commit_sha=owner.current_commit_sha), gh)
    assert dep.status == "succeeded", dep.error
    assert "deploy uat next, which updates the data server first" in dep.log
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.status == "stopped"
    assert owner.current_commit_sha is None and data.live_state(owner) is None and owner.live_identity is None

    assert await _refusal(seeded, "blue", kind="deploy", options={"slot": "blue"}) == \
        environments.no_server_text(await _get(Environment, seeded.env_id))
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, seeded.env_id)
        user = await db.get(User, seeded.user_id)

        class Ctx:
            def __init__(self, u):
                self.user = u

            def can(self, perm):
                return True

        actions = await environments.actions(db, env, Ctx(user))
    assert actions["deploy"]["slot"] == "data" and actions["deploy"]["available"], actions["deploy"]

    again = await _deploy(multi, seeded, "data", gh=gh)  # Update the data server: a fresh, empty database
    assert again.status == "succeeded", again.error
    blue = await _deploy(multi, seeded, "blue", gh=gh)
    assert blue.status == "succeeded", blue.error


async def test_start_over_with_a_changed_identity_variable_starts_afresh(multi, submitted, tmp_path):
    seeded, gh = await _never_live_env(multi, tmp_path)
    await _set(Environment, seeded.env_id, env={"APP_KEY": OTHER})
    owner = await _get(Instance, seeded.ids["data"])
    dep = await _run(multi, await queue(seeded, "data", kind="reset", options={"start_over": True},
                                        commit_sha=owner.current_commit_sha), gh)
    assert dep.status == "succeeded", dep.error
    assert (await _get(Instance, seeded.ids["data"])).live_identity is None
    assert (await _deploy(multi, seeded, "data", gh=gh)).status == "succeeded"
    blue = await _deploy(multi, seeded, "blue", gh=gh)
    assert blue.status == "succeeded", blue.error
    assert (await _get(Instance, seeded.ids["data"])).live_identity == {"APP_KEY": OTHER}


# ------------------------------------------------------------- F9/F35: identity while no app ran on the data


async def test_the_first_slot_deploy_on_fresh_data_records_its_identity(multi, submitted):
    """The data server's first deploy records an identity but runs no app: until an app slot goes live on the
    data, an identity variable may still change, and the first slot deploy's value becomes the data's. Once an
    app ran on it, a change is refused as before."""
    seeded = await seed_env(multi, slots=("blue", "green"))
    assert (await _deploy(multi, seeded, "data")).status == "succeeded"
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.live_identity and owner.live_identity["APP_KEY"] != OTHER and owner.fresh_data == "empty"
    await _set(Environment, seeded.env_id, env={"APP_KEY": OTHER})
    assert await _refusal(seeded, "blue", kind="deploy", options={"slot": "blue"}) is None
    blue = await _deploy(multi, seeded, "blue")
    assert blue.status == "succeeded", blue.error
    assert (await _get(Instance, seeded.ids["data"])).live_identity == {"APP_KEY": OTHER}
    # A data server deploy keeps it (F35).
    assert (await _deploy(multi, seeded, "data")).status == "succeeded"
    assert (await _get(Instance, seeded.ids["data"])).live_identity == {"APP_KEY": OTHER}

    # An app has run on the data now: another value is refused, with the mode server text.
    await _set(Environment, seeded.env_id, env={"APP_KEY": THIRD})
    refused = await _refusal(seeded, "green", kind="deploy", options={"slot": "green"})
    assert refused and "Only a restore on the data server changes the data's APP_KEY" in refused
    backup = await _owner_job(multi, seeded, "backup")
    assert backup.status == "failed"
    assert "APP_KEY differs" in backup.error and "or deploy" not in backup.error, backup.error
    assert "put the variable back" in backup.error


# ------------------------------------------------------------- F50: Deploy again, confirming pins its commit


async def test_a_pinned_deploy_resolves_that_commit_and_no_other(multi, submitted):
    from tests.test_deployer import SHA, FakeGitHub

    seeded = await _live_env(multi)
    FakeGitHub.calls.clear()
    dep = await _deploy(multi, seeded, "green", options={"pin_commit": SHA, "behind_ok": True})
    assert any(call.endswith(f"@{SHA}") for call in FakeGitHub.calls), FakeGitHub.calls
    assert "(the commit the refused deploy was of)" in dep.log
    assert dep.commit_sha == SHA
    other = "f" * 40
    dep = await _deploy(multi, seeded, "green", options={"pin_commit": other, "behind_ok": True})
    assert dep.status == "failed" and dep.error == "GitHub returned another commit than the one asked for"
    assert _steps(dep)["resolve"] == "failed"
