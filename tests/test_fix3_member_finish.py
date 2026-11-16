"""Phase 3 review fixes: how a member's deploy finishes and is recovered, its identity values, the data server's
ports, and the environment's secrets when they can't be decrypted (F9, F18, F20, F27, F34, F35, F40).

Built on the reviewers' reproducers: the same fake hosts and the real deployer as tests/test_env_pipeline.py.
"""

from __future__ import annotations

import argparse

import pytest
from sqlalchemy import text

from slipway import cli
from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Environment, Instance, User
from slipway.models.environment import SECRETS_LOST
from slipway.services import deployer, jobs
from tests.fake_hosts import SECRETS, EnvGitHub, queue
from tests.test_env_pipeline import (  # noqa: F401  (fixtures)
    _backups,
    _deploy,
    _env_file,
    _failed_green,
    _get,
    _live_env,
    _owner_job,
    _set,
    _steps,
    multi,
    no_waits,
    submitted,
)
from tests.test_env_rules import EVERYONE, _load, _world

OTHER_KEY = "Q" * 43 + "="


# ------------------------------------------- F9: an app slot can't change the shared data's identity


async def test_a_slot_deploy_is_refused_when_a_variable_changes_an_identity_value(multi, submitted):
    seeded = await _live_env(multi)
    await _set(Environment, seeded.env_id, env={"APP_KEY": OTHER_KEY})
    dep = await _deploy(multi, seeded, "green")
    assert dep.status == "failed"
    assert "APP_KEY differs from the value uat data's data was made with: a variable of uat changed it" in dep.error
    assert "put the variable back" in dep.error
    # Nothing changed: green still runs with the data's key, the owner and the environment keep it.
    assert _env_file(multi, "green", "uat-green")["APP_KEY"] == SECRETS["APP_KEY"]
    assert not multi["green"].calls()
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.live_identity == {"APP_KEY": SECRETS["APP_KEY"]}
    assert (await _get(Environment, seeded.env_id)).app_secrets["APP_KEY"] == SECRETS["APP_KEY"]
    assert (await _get(Instance, seeded.ids["green"])).status == "running"
    # And the owner's backups still work.
    await _set(Environment, seeded.env_id, env={})
    backup = await _owner_job(multi, seeded, "backup")
    assert backup.status == "succeeded", backup.error


async def test_queue_job_refuses_the_slot_deploy_first(multi, submitted):
    seeded = await _live_env(multi)
    await _set(Environment, seeded.env_id, env={"APP_KEY": OTHER_KEY})
    async with get_sessionmaker()() as db:
        green = await db.get(Instance, seeded.ids["green"])
        user = await db.get(User, seeded.user_id)
        with pytest.raises(jobs.JobRefused) as refused:
            await jobs.queue_job(db, instance=green, user=user, kind="deploy")
    assert refused.value.status == 409 and refused.value.text.startswith("APP_KEY differs from the value")
    # The same value as the data's is fine, and so is the data server's own deploy.
    await _set(Environment, seeded.env_id, env={"APP_KEY": SECRETS["APP_KEY"]})
    async with get_sessionmaker()() as db:
        green = await db.get(Instance, seeded.ids["green"])
        user = await db.get(User, seeded.user_id)
        assert await jobs.job_refusal(db, instance=green, user=user, kind="deploy",
                                      options={"slot": "green", "go_live": False}) is None


async def test_the_rendered_identity_is_checked_when_the_release_is_read(multi, submitted):
    """No variable sets it, so queue_job can't see it: the stored secret no longer matches what the data was
    made with. The manifest step refuses it before anything is written."""
    seeded = await _live_env(multi)
    await _set(Environment, seeded.env_id, app_secrets={**SECRETS, "APP_KEY": OTHER_KEY})
    dep = await _deploy(multi, seeded, "green")
    assert dep.status == "failed" and _steps(dep)["manifest"] == "failed" and _steps(dep)["settings"] == "pending"
    assert dep.error.startswith("APP_KEY differs from the value uat data's data was made with")
    assert _env_file(multi, "green", "uat-green")["APP_KEY"] == SECRETS["APP_KEY"]
    assert (await _get(Instance, seeded.ids["data"])).live_identity == {"APP_KEY": SECRETS["APP_KEY"]}


async def test_a_slot_deploy_keeps_a_variable_that_sets_the_datas_value_as_the_secret(multi, submitted):
    """The data is made with the variable's value and the stored secret is another one: at finish the variable
    becomes the environment's secret, as on the data owner, while a ready backup holds the stored one."""
    seeded = await _live_env(multi)
    held = [b for b in await _backups(seeded) if b.status == "ready" and (b.identity or {}).get("APP_KEY")
            == SECRETS["APP_KEY"]]
    assert held  # green's pre-deploy backup in _live_env
    await _set(Instance, seeded.ids["data"], live_identity={"APP_KEY": OTHER_KEY})
    await _set(Environment, seeded.env_id, env={"APP_KEY": OTHER_KEY})
    version = (await _get(Environment, seeded.env_id)).secrets_version
    dep = await _deploy(multi, seeded, "green")
    assert dep.status == "succeeded", dep.error
    assert _env_file(multi, "green", "uat-green")["APP_KEY"] == OTHER_KEY
    assert "Kept APP_KEY from uat's variables as the app's secrets: the data is made with them now" in dep.log
    env = await _get(Environment, seeded.env_id)
    assert env.app_secrets["APP_KEY"] == OTHER_KEY and env.secrets_version == version + 1


# ------------------------------------------- F35: a data server deploy never overwrites live_identity


async def test_a_data_server_deploy_keeps_the_recorded_identity(multi, submitted):
    seeded = await _live_env(multi)
    await _set(Instance, seeded.ids["data"], live_identity={"APP_KEY": "the-key-the-data-was-made-with"})
    await _set(Environment, seeded.env_id, env={"APP_KEY": OTHER_KEY})
    dep = await _deploy(multi, seeded, "data")
    assert dep.status == "succeeded", dep.error
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.live_identity == {"APP_KEY": "the-key-the-data-was-made-with"}
    assert "Warning: APP_KEY of uat's variables differs from the value uat data's data was made with" in dep.log
    assert (await _get(Environment, seeded.env_id)).app_secrets["APP_KEY"] == SECRETS["APP_KEY"]


async def test_a_data_server_deploy_records_the_identity_when_there_is_none(multi, submitted):
    seeded = await _live_env(multi)
    await _set(Instance, seeded.ids["data"], live_identity=None)
    dep = await _deploy(multi, seeded, "data")
    assert dep.status == "succeeded", dep.error
    assert (await _get(Instance, seeded.ids["data"])).live_identity == {"APP_KEY": SECRETS["APP_KEY"]}


async def test_the_first_slot_deploy_records_the_owners_identity_with_went_live(multi, submitted, monkeypatch):
    """A restart right after finish saved went_live can't leave the owner with no identity recorded."""
    seeded = await _live_env(multi)
    await _set(Instance, seeded.ids["data"], live_identity=None)

    class Killed(BaseException):
        """The process dies: nothing after this point runs, not even _end_after_live."""

    async def cut_off(job, instance, state):
        raise Killed

    monkeypatch.setattr(deployer, "_member_went_live", cut_off)
    # No pre-deploy backup (it would record the owner's identity on its own).
    dep_id = await queue(seeded, "green", options={"slot": "green", "skip_backup": True})
    with pytest.raises(Killed):
        await deployer.run_deployment(dep_id, connect=multi.connect, github=EnvGitHub)
    assert (await _get(Instance, seeded.ids["green"])).app_state.get("went_live") == dep_id.hex
    assert (await _get(Instance, seeded.ids["data"])).live_identity == {"APP_KEY": SECRETS["APP_KEY"]}


# ------------------------------------------- F18, F27: recovery mirrors the in-process success


async def test_recovering_a_live_data_server_deploy_keeps_the_dirty_state_and_fresh_data(multi, submitted, tmp_path):
    seeded = await _live_env(multi)
    failed = await _failed_green(multi, seeded, tmp_path)
    dep = await _deploy(multi, seeded, "data")
    assert dep.status == "succeeded", dep.error
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.data_dirty["first"]["deployment_id"] == failed.id.hex  # in process: kept (§7.5)
    await _set(Instance, owner.id, app_state={**owner.app_state, "went_live": dep.id.hex}, fresh_data="empty")
    rows = [dict(r, status="pending") if r["key"] == "traffic" else r for r in dep.steps]
    await _set(Deployment, dep.id, status="running", steps=rows)
    await deployer.DeployRunner().recover_interrupted()
    assert (await _get(Deployment, dep.id)).status == "succeeded"
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.data_dirty["first"]["deployment_id"] == failed.id.hex
    assert owner.fresh_data == "empty"
    assert owner.seed_snapshot_id is None


async def test_recovering_a_live_retry_of_the_failed_slot_settles_the_owner(multi, submitted, tmp_path):
    seeded = await _live_env(multi)
    failed = await _failed_green(multi, seeded, tmp_path)
    green = await _get(Instance, seeded.ids["green"])
    steps = [{"key": k, "name": k, "status": "succeeded"} for k in
             ("resolve", "source", "upload", "manifest", "ports", "settings", "build", "backup", "start", "finish")]
    steps += [{"key": "smoke", "name": "smoke", "status": "running"}, {"key": "traffic", "name": "t", "status": "pending"}]
    retry_id = await queue(seeded, "green", status="running", commit_sha=green.current_commit_sha,
                           retry_of_id=failed.id, steps=steps, options={"slot": "green", "go_live": False})
    await _set(Instance, green.id, app_state={**(green.app_state or {}), "went_live": retry_id.hex})
    await deployer.DeployRunner().recover_interrupted()
    assert (await _get(Deployment, retry_id)).status == "succeeded"
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.data_dirty is None
    assert owner.live_identity == {"APP_KEY": SECRETS["APP_KEY"]}


async def test_recovering_a_live_deploy_of_the_other_slot_leaves_the_owner_dirty(multi, submitted, tmp_path):
    seeded = await _live_env(multi)
    failed = await _failed_green(multi, seeded, tmp_path)
    blue = await _get(Instance, seeded.ids["blue"])
    steps = [{"key": "finish", "name": "finish", "status": "succeeded"},
             {"key": "smoke", "name": "smoke", "status": "running"}]
    dep_id = await queue(seeded, "blue", status="running", commit_sha=blue.current_commit_sha, steps=steps,
                         options={"slot": "blue"})
    await _set(Instance, blue.id, app_state={**(blue.app_state or {}), "went_live": dep_id.hex})
    await deployer.DeployRunner().recover_interrupted()
    assert (await _get(Deployment, dep_id)).status == "succeeded"
    assert (await _get(Instance, seeded.ids["data"])).data_dirty["first"]["deployment_id"] == failed.id.hex


# ------------------------------------------- F20: the fences again when a member's job starts


async def test_a_deploy_queued_beside_an_activate_is_refused_when_it_starts():
    ids = await _world()  # blue active, green idle and deployed
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, ids)
        dep = await jobs.queue_job(db, instance=mem["green"], user=EVERYONE, kind="deploy")
        await db.commit()
        dep_id = dep.id
    # Meanwhile an activate queued at the same moment made green live.
    await _set(Environment, ids["env"], active_slot_id=ids["green"])
    with pytest.raises(deployer.DeployError, match="green serves traffic: deploy to blue, then activate it"):
        await deployer._start(dep_id)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "queued" and dep.started_at is None  # nothing changed; run_deployment fails it
    assert (await _get(Instance, ids["green"])).status == "running"


async def test_a_member_job_meets_the_hold_and_the_unresolved_switch_when_it_starts(multi, submitted):
    seeded = await _live_env(multi)
    await _set(Environment, seeded.env_id,
               traffic_state={"unresolved": {"deployment_id": "ab" * 16, "message": "Switchyard didn't answer"}})
    dep = await _deploy(multi, seeded, "green")
    assert dep.status == "failed" and "Traffic of uat may be split between its slots" in dep.error
    assert not multi["green"].calls()
    assert (await _get(Instance, seeded.ids["green"])).status == "running"

    await _set(Environment, seeded.env_id, traffic_state={})
    await _set(Instance, seeded.ids["data"], data_dirty={
        "first": {"deployment_id": "cd" * 16, "kind": "restore", "at": "2026-11-16T00:00:00+00:00"},
        "last": {"deployment_id": "cd" * 16, "kind": "restore", "step": "restore", "at": "2026-11-16T00:00:00+00:00"},
        "hold": True})
    dep = await _deploy(multi, seeded, "green")
    assert dep.status == "failed" and dep.error.startswith("Could not start the deployment: ")
    assert "Start, Restart and Deploy are off until then" in dep.error
    assert not multi["green"].calls()


# ------------------------------------------- F34: a refused port move is never stored


async def test_a_refused_port_move_of_the_data_server_is_not_saved(multi, submitted, monkeypatch):
    seeded = await _live_env(multi)
    owner = await _get(Instance, seeded.ids["data"])
    live_db = owner.app_state["live"]["host_ports"]["db"]
    published, overrides = owner.published_ports, owner.port_overrides
    real = deployer._reserved_ports
    squat = {"on": True}

    async def reserved(instance):
        found = list(await real(instance))
        if instance.slot == "data" and squat["on"]:
            found.append((live_db, "tcp", "a squatter"))
        return found

    monkeypatch.setattr(deployer, "_reserved_ports", reserved)
    dep = await _deploy(multi, seeded, "data")
    assert dep.status == "failed" and _steps(dep)["ports"] == "failed" and _steps(dep)["settings"] == "pending"
    assert dep.error.startswith(f"The data server's ports would move (db {live_db} → ")
    owner = await _get(Instance, seeded.ids["data"])
    assert owner.published_ports == published and owner.port_overrides == overrides
    squat["on"] = False  # the operator freed the port, as the message says
    dep = await _deploy(multi, seeded, "data")
    assert dep.status == "succeeded", dep.error
    assert (await _get(Instance, seeded.ids["data"])).app_state["live"]["host_ports"]["db"] == live_db


# ------------------------------------------- F40: the environment's secrets after --clear-unreadable


async def _lose_the_secrets() -> None:
    """What ``slipway rotate-encryption-key --clear-unreadable`` leaves after the key changed: an encrypted
    null, which reads as None."""
    async with get_sessionmaker()() as db:
        await db.execute(text("UPDATE environments SET app_secrets = 'not-a-fernet-token'"))
        await db.commit()
    async with get_sessionmaker()() as db:
        await cli._rotate_secrets(db, clear_unreadable=True)
        await db.commit()


async def test_a_deploy_takes_the_lost_secrets_from_the_environments_variables(multi, submitted):
    seeded = await _live_env(multi)
    await _lose_the_secrets()
    env = await _get(Environment, seeded.env_id)
    assert env.app_secrets is None
    version = env.secrets_version
    # Until then every member job refuses, and says how to get out of it.
    backup = await _owner_job(multi, seeded, "backup")
    assert backup.status == "failed" and backup.error == SECRETS_LOST.format(env="uat")
    assert "or set each secret as a variable of uat with its old value and deploy" in backup.error

    await _set(Environment, seeded.env_id, env=dict(SECRETS))
    dep = await _deploy(multi, seeded, "green")
    assert dep.status == "succeeded", dep.error
    assert "uat's stored secrets can't be decrypted; its variables set every one" in dep.log
    env = await _get(Environment, seeded.env_id)
    assert env.app_secrets == SECRETS and env.secrets_version == version + 1
    assert _env_file(multi, "green", "uat-green")["APP_KEY"] == SECRETS["APP_KEY"]
    # The environment's other jobs run again, and the variables can go.
    await _set(Environment, seeded.env_id, env={})
    backup = await _owner_job(multi, seeded, "backup")
    assert backup.status == "succeeded", backup.error


async def test_a_deploy_without_every_lost_secret_names_the_missing_ones(multi, submitted):
    seeded = await _live_env(multi)
    await _lose_the_secrets()
    await _set(Environment, seeded.env_id, env={"APP_KEY": SECRETS["APP_KEY"]})
    dep = await _deploy(multi, seeded, "data")
    assert dep.status == "failed" and _steps(dep)["manifest"] == "failed"
    assert dep.error == ("Slipway lost uat's secrets (SLIPWAY_ENCRYPTION_KEY changed): put the old key back first in "
                         "the list and run slipway rotate-encryption-key, or set each of them as a variable of uat: "
                         "APP_SECRET, DB_PASSWORD (their old values, or the app's existing data won't open)")
    assert (await _get(Environment, seeded.env_id)).app_secrets is None  # nothing generated (D5)


async def test_unreadable_variables_of_a_member_point_at_the_environment(multi, submitted):
    seeded = await _live_env(multi)
    async with get_sessionmaker()() as db:
        await db.execute(text("UPDATE environments SET env = 'not-a-fernet-token'"))
        await db.commit()
    for dep in (await _deploy(multi, seeded, "green"), await _owner_job(multi, seeded, "backup")):
        assert dep.status == "failed"
        assert dep.error == deployer.ENV_UNREADABLE_MEMBER.format(env="uat")
        assert "re-enter them in the environment's settings" in dep.error


def test_rotate_encryption_key_says_how_an_environment_gets_its_secrets_back(monkeypatch, capsys):
    async def done(action, args):
        return 0, ["environments.app_secrets (id 1)"], []

    monkeypatch.setattr(cli, "_with_db", done)
    cli.rotate_encryption_key(argparse.Namespace(clear_unreadable=True))
    out = capsys.readouterr().out
    assert "until each secret is set as a variable" in out and "of the environment (its old value)" in out
    assert "the next deploy in it then keeps them as its secrets" in out

    async def instance_only(action, args):
        return 0, ["instances.app_secrets (id 1)"], []

    monkeypatch.setattr(cli, "_with_db", instance_only)
    cli.rotate_encryption_key(argparse.Namespace(clear_unreadable=True))
    assert "Environments listed here" not in capsys.readouterr().out
