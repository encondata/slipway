"""Review 45, the deployer's managed-data and DigitalOcean steps and the job fences: findings F4, F5, F7, F9, F15
and K3, each as the case that failed before its fix.

- F4, F5: Reset on managed data checks the database's doadmin password and the bucket side (the team, a
  temporary Spaces key that can be made) in ``backup``, before the slots stop, so a refusal stops nothing and
  holds nothing; ``wipe`` empties the bucket before it drops the database, and never says that Slipway changed
  nothing once something was.
- F7: the ``database`` step sets the role's password from the secret the release renders, generating or
  adopting one the release adds, as ``settings`` would.
- F9: a load balancer made again at a new address moves the environment's DNS records in the same deploy.
- F15: after a D28 rebuild of the active slot's droplet failed, the slot serves nothing, so its retry or another
  deploy may run.
- K3: an activate onto a VM that isn't made is refused at queue time with the VM's text (P5 §10.4); covered in
  tests/test_provider_pipeline.py test_41.

Everything outside Slipway is a fake (tests/test_do_managed_data.py's and tests/test_do_pipeline.py's worlds).
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, update

from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Environment, Instance, Resource, User
from slipway.services import cloudflare, data, jobs
from tests import do_fixtures as dof
from tests import test_do_managed_data as md
from tests import test_do_pipeline as dp
from tests.test_provider_pipeline import built_droplet, loaded

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")


@pytest.fixture
def mdw(tmp_path, monkeypatch) -> md.World:
    return md.World(tmp_path, monkeypatch)


@pytest.fixture
def dpw(tmp_path, monkeypatch) -> dp.World:
    return dp.World(tmp_path, monkeypatch)


async def _slot_statuses(env: dof.DoEnv) -> dict[str, str]:
    return {slot: (await md.get(Instance, env.ids[slot])).status for slot in ("blue", "green")}


# ------------------------------------------------------------------------- F5: doadmin's password


async def test_f5_reset_with_an_unreadable_doadmin_password_is_refused_before_the_slots_stop(mdw):
    env = await mdw.setup()
    await mdw.live()
    before = await _slot_statuses(env)
    async with get_sessionmaker()() as db:  # what rotate-encryption-key --clear-unreadable leaves
        await db.execute(update(Resource).where(Resource.kind == "database").values(credentials=None))
        await db.commit()
    dep = await mdw.owner_job("reset")
    assert dep.status == "failed"
    assert md.statuses(dep)["backup"] == "failed"
    assert md.statuses(dep)["stop_slots"] == "pending" and md.statuses(dep)["wipe"] == "pending"
    assert "can't read doadmin's password for slipway-shop-db" in dep.error
    assert "deploy to a slot, whose database step reads it from DigitalOcean again" in dep.error
    assert "isn't set up yet" not in dep.error
    # Nothing stopped and nothing held: a deploy to a slot, the way out the text names, stays allowed.
    assert await _slot_statuses(env) == before
    owner = await md.get(Instance, env.ids["data"])
    assert not (owner.data_dirty or {}).get("hold")
    assert not mdw.multi["blue"].sql() and mdw.db_text()


# ----------------------------------------------------------------------------- F4: the bucket side


async def test_f4_a_token_that_cant_make_spaces_keys_refuses_the_reset_before_anything_stops(mdw):
    env = await mdw.setup()
    await mdw.live()
    before = await _slot_statuses(env)
    mdw.cloud.spaces.put(mdw.bucket, "uploads/a.png", b"A")
    held = mdw.db_text()
    assert held
    mdw.cloud.do.forbid.add("spaces_keys")
    dep = await mdw.owner_job("reset")
    assert dep.status == "failed" and md.statuses(dep)["backup"] == "failed"
    assert md.statuses(dep)["stop_slots"] == "pending" and md.statuses(dep)["wipe"] == "pending"
    assert dep.error.endswith("Slipway changed nothing: give the token that scope, then retry")
    # True: the database and the bucket are untouched, no SQL ran, the slots run, nothing is held.
    assert mdw.db_text() == held and not mdw.multi["blue"].sql()
    assert set(mdw.cloud.spaces.buckets[mdw.bucket]) == {"uploads/a.png"}
    assert await _slot_statuses(env) == before
    owner = await md.get(Instance, env.ids["data"])
    assert not (owner.data_dirty or {}).get("hold")


async def test_f4_a_bucket_failure_in_the_wipe_leaves_the_database_as_it_was_and_says_so(mdw):
    await mdw.setup()
    await mdw.live()
    mdw.cloud.spaces.put(mdw.bucket, "uploads/a.png", b"A")
    held = mdw.db_text()
    mdw.cloud.spaces.undeletable.add("uploads/a.png")  # the check's key reads the bucket; the delete fails
    dep = await mdw.owner_job("reset")
    assert dep.status == "failed" and md.statuses(dep)["wipe"] == "failed", (dep.error, md.statuses(dep))
    assert "Spaces couldn't delete 1 object" in dep.error
    assert "changed nothing" not in dep.error
    # The bucket goes first: the database was never dropped.
    assert mdw.db_text() == held and not mdw.multi["blue"].sql()
    # The temporary keys (the check's and the wipe's) are both deleted again.
    assert {k["name"] for k in mdw.cloud.do.spaces_keys.values()} == {f"{mdw.bucket}-rw"}


async def test_f4_a_key_refused_in_the_wipe_names_the_data_as_it_was_not_changed_nothing(mdw, monkeypatch):
    """A refusal the check didn't meet (the token lost its scope between the two) comes before the drop."""
    from slipway.services import do_provision

    await mdw.setup()
    await mdw.live()
    held = mdw.db_text()
    real = do_provision.wipe_check

    async def check_then_forbid(ctx, man):
        await real(ctx, man)
        mdw.cloud.do.forbid.add("spaces_keys")
    monkeypatch.setattr(do_provision, "wipe_check", check_then_forbid)
    dep = await mdw.owner_job("reset")
    assert dep.status == "failed" and md.statuses(dep)["wipe"] == "failed"
    assert "changed nothing" not in dep.error
    assert "The database and the bucket are as they were" in dep.error
    assert mdw.db_text() == held and not mdw.multi["blue"].sql()


async def test_f4_the_wipe_empties_the_bucket_before_it_drops_the_database(mdw):
    await mdw.setup()
    await mdw.live()
    mdw.cloud.spaces.put(mdw.bucket, "uploads/a.png", b"A")
    dep = await mdw.owner_job("reset")
    assert dep.status == "succeeded", (dep.error, dep.log[-4000:])
    assert dep.log.index("Emptied the bucket (1 file deleted)") < dep.log.index("Emptying database demo as doadmin")
    assert mdw.cloud.spaces.buckets[mdw.bucket] == {}
    [sql] = mdw.multi["blue"].sql()
    assert sql.startswith('DROP DATABASE IF EXISTS "demo" WITH (FORCE);')
    # The check's key and the wipe's key: each made once and deleted.
    made = [r for r in mdw.cloud.do.requests if r["method"] == "POST" and r["path"] == "/spaces/keys"]
    gone = [r for r in mdw.cloud.do.requests if r["method"] == "DELETE" and r["path"].startswith("/spaces/keys/")]
    assert len(made) == len(gone) == 2
    assert md.ADMIN_PASSWORD not in dep.log


# ---------------------------------------------------------------- F7: the role's password secret


PG_YML = dp.DO_YML.replace("  POSTGRES_PASSWORD: hex\n", "  POSTGRES_PASSWORD: hex\n  PG_PASS: hex\n").replace(
    'user: serversherpa, password: "{secret.POSTGRES_PASSWORD}"}\n    objects: {cors',
    'user: serversherpa, password: "{secret.PG_PASS}"}\n    objects: {cors')


def _database_url_password(values: dict[str, str]) -> str:
    return values["SS_DATABASE_URL"].split("://", 1)[1].split("@", 1)[0].split(":", 1)[1]


async def test_f7_a_release_that_adds_the_role_password_secret_deploys(dpw):
    assert PG_YML.count("PG_PASS") == 2
    await dp.chain(dpw)
    dpw.gh.texts = {**dpw.gh.texts, "slipway.yml": PG_YML}
    green = await dpw.run(await dpw.queue(slot="green"))
    dp.ok(green)
    env, _mem = await dpw.members()
    secret = env.app_secrets["PG_PASS"]
    # Blue is live and connects with POSTGRES_PASSWORD: the renamed secret keeps the role's password (final review).
    assert secret and secret == env.app_secrets["POSTGRES_PASSWORD"]
    assert "Kept PG_PASS with the value of POSTGRES_PASSWORD" in green.log
    assert dp.steps(green)["database"] == "succeeded"
    # The role got that password, and the release renders the same one.
    (sql,) = dpw.host("green").sql()
    assert 'ALTER ROLE "serversherpa"' in sql or 'CREATE ROLE "serversherpa"' in sql
    assert _database_url_password(dp.env_file(dpw, "green")) == secret
    assert secret not in green.log
    await dp.no_secret_in_audits(dpw)


async def test_f7_the_role_password_comes_from_the_environments_variable_when_one_sets_it(dpw):
    await dp.chain(dpw)
    env, _mem = await dpw.members()
    value = env.app_secrets["POSTGRES_PASSWORD"]  # blue is live: another value is refused (test_review45_final)
    await dp.set_rows(Environment, dpw.env_id, env={"PG_PASS": value})
    dpw.gh.texts = {**dpw.gh.texts, "slipway.yml": PG_YML}
    green = await dpw.run(await dpw.queue(slot="green"))
    dp.ok(green)
    env, _mem = await dpw.members()
    assert env.app_secrets["PG_PASS"] == value
    assert "Kept PG_PASS from shop's variables as the app's secret" in green.log
    assert _database_url_password(dp.env_file(dpw, "green")) == value
    assert value not in green.log


# ------------------------------------------------------------------- F9: a load balancer made again


async def _record_contents() -> set[str]:
    async with get_sessionmaker()() as db:
        rows = await db.scalars(select(Resource).where(Resource.provider == cloudflare.PROVIDER,
                                                       Resource.kind == cloudflare.KIND))
        return {str((r.details or {}).get("content")) for r in rows}


async def test_f9_a_remade_load_balancer_moves_the_dns_records_in_the_same_deploy(dpw):
    await dp.chain(dpw, slots=1)
    old_ip = dpw.lb()["ip"]
    assert {r["content"] for r in dpw.cf.records.values()} == {old_ip}
    dpw.do.load_balancers.clear()  # deleted by hand; DigitalOcean releases its address
    dep = await dpw.run(await dpw.queue(slot="blue"))
    dp.ok(dep)
    new_ip = dpw.lb()["ip"]
    assert new_ip != old_ip
    order = dp.keys(dep)
    assert order[order.index("edge") + 1] == "dns" and dp.steps(dep)["dns"] == "succeeded"
    assert {r["content"] for r in dpw.cf.records.values()} == {new_ip}
    assert await _record_contents() == {new_ip}
    assert dpw.lb()["droplet_ids"] == [dpw.droplet("blue")["id"]]
    # The next deploy finds the records at the address: no dns step.
    again = await dpw.run(await dpw.queue(slot="blue"))
    dp.ok(again)
    assert "dns" not in dp.keys(again)


async def test_f9_the_records_move_even_when_the_deploy_stops_after_the_edge(dpw):
    await dp.chain(dpw, slots=1)
    old_ip = dpw.lb()["ip"]
    dpw.do.load_balancers.clear()
    dpw.gh.fail_source = True
    failed = await dpw.run(await dpw.queue(slot="blue"))
    dpw.gh.fail_source = False
    assert failed.status == "failed" and dp.steps(failed)["source"] == "failed"
    assert dp.steps(failed)["dns"] == "succeeded"
    new_ip = dpw.lb()["ip"]
    assert new_ip != old_ip and {r["content"] for r in dpw.cf.records.values()} == {new_ip}


async def test_f9_a_dns_failure_after_the_edge_is_a_warning_that_names_publish(dpw):
    await dp.chain(dpw, slots=1)
    dpw.do.load_balancers.clear()
    dpw.cf.deny = {"PATCH"}  # the record updates are refused
    dep = await dpw.run(await dpw.queue(slot="blue"))
    dp.ok(dep)  # the deploy goes on: the active slot is back on the new load balancer
    assert dp.steps(dep)["dns"] == "warning"
    assert dp.notes(dep)["dns"].startswith(
        f"The DNS records still name the old address: run Publish to move them to {dpw.lb()['ip']} (")
    dpw.cf.deny = False
    publish = await dpw.run(await dpw.queue(kind="publish"))
    dp.ok(publish)
    assert {r["content"] for r in dpw.cf.records.values()} == {dpw.lb()["ip"]}


# --------------------------------------------------------------- F15: a failed D28 rebuild deploy


async def test_f15_the_fence_lets_the_active_slot_deploy_once_its_release_went_with_its_droplet():
    env = await dof.make_do_env()
    await built_droplet(env, "blue")
    await built_droplet(env, "green")
    await dp.set_rows(Environment, env.env_id, active_slot_id=env.ids["blue"], status="live")
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, env.ids["blue"])
        inst.app_state = {"gone_live": {"release": "abc", "sha": "0" * 40}}
        await db.commit()
    db, instance, row, mem = await loaded(env.ids["blue"])
    try:
        assert data.live_state(instance) is None and jobs.release_gone(instance)
        assert await jobs.environment_fence(db, row, mem, instance=instance, kind="deploy") is None
    finally:
        await db.close()
    # Once a release is live on it again, it serves traffic: the fence is back.
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, env.ids["blue"])
        inst.app_state = {"gone_live": {"release": "abc"}, "live": {"release": "def", "sha": "1" * 40}}
        await db.commit()
    db, instance, row, mem = await loaded(env.ids["blue"])
    try:
        got = await jobs.environment_fence(db, row, mem, instance=instance, kind="deploy")
        assert got is not None and got.text == "blue serves traffic: deploy to green, then activate it"
    finally:
        await db.close()


async def test_f15_a_failed_rebuild_of_the_active_droplet_can_be_retried(dpw):
    await dp.blue_gone_then_green(dpw)
    env, mem = await dpw.members()
    assert env.active_slot_id == mem["blue"].id
    dpw.gh.fail_source = True
    failed = await dpw.run(await dpw.queue(slot="blue"))
    dpw.gh.fail_source = False
    assert failed.status == "failed" and dp.steps(failed)["prepare"] == "succeeded"
    assert dp.steps(failed)["source"] == "failed"
    _env, mem = await dpw.members()
    assert (await dp.host_of(dpw, "blue")).provider_state["phase"] == "ready"
    assert data.live_state(mem["blue"]) is None
    # The retry is queued (before: "blue serves traffic: deploy to green, then activate it") and finishes.
    async with get_sessionmaker()() as db:
        first = await db.get(Deployment, failed.id)
        user = await db.get(User, dpw.user_id)
        env = await db.get(Environment, dpw.env_id)
        mem = await jobs.environments.members(db, env)
        retry = await jobs.queue_job(db, instance=mem["blue"], environment=env, user=user, retry_of=first)
        await db.commit()
        retry_id = retry.id
    dpw.multi.clear()
    done = await dpw.run(retry_id)
    dp.ok(done)
    assert dp.steps(done)["traffic"] == "succeeded"
    assert dpw.lb()["droplet_ids"] == [dpw.droplet("blue")["id"]]
    # Blue serves again: the fence is back for the next deploy.
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, dpw.env_id)
        mem = await jobs.environments.members(db, env)
        got = await jobs.environment_fence(db, env, mem, instance=mem["blue"], kind="deploy")
    assert got is not None and got.text == "blue serves traffic: deploy to green, then activate it"
