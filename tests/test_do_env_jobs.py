"""The environment jobs of a DigitalOcean environment (phase 4 §9.3, §11.6, §13, §14.1-§14.3, §15.4-§15.13), and
the shared rule that a host an environment made is removed without SSH (Decision 15).

Numbered tests of §20.2: 60 (the certificate job's half), 61 (the Deactivate half of recovery), 90 (Resolve through
the load balancer), plus Publish, Activate, Remove slot and the teardown on DigitalOcean.

Two worlds, both fakes only:

* ``world`` (tests/test_do_lb.py): environment ``uat`` as its first deploys leave it, a droplet per slot on a fake
  host at its address, a certificate and a load balancer with no targets. The public check talks to FakeSites.
* ``cloud`` (tests/do_fixtures.py, tests/test_do_cloud.py): environment ``shop`` built by the real provisioner
  against FakeDigitalOcean, FakeSpaces, FakeAcme and FakeCloudflare, its droplets on the address-keyed MultiRemote.

Every job runs through ``deployer.run_deployment`` and ``env_jobs``; nothing here mocks them.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select, update

from slipway.db.session import get_sessionmaker
from slipway.models import AuditEvent, Deployment, Environment, Host, Instance, Resource, User
from slipway.services import (
    backup_store,
    deployer,
    do_lb,
    do_provision,
    do_rules,
    env_jobs,
    environments,
    jobs,
    switchyard,
)
from slipway.services.digitalocean import DigitalOceanError
from tests import do_fixtures as dof
from tests.test_do_cloud import NAMES as SHOP_NAMES
from tests.test_do_cloud import (  # noqa: F401  (fixtures)
    built,
    cloud,
    edge_fakes,
    nothing_left,
    prepared,
    set_routes,
)
from tests.test_do_lb import (  # noqa: F401  (fixtures)
    NAMES,
    World,
    _set_active,
    _world,
    do,
    settles,
    sites,
    waits,
)

SHA = "0123456789abcdef0123456789abcdef01234567"


@pytest.fixture
def submitted(monkeypatch) -> list[tuple[uuid.UUID, tuple]]:
    """Jobs a chain queues are recorded, not run."""
    found: list[tuple[uuid.UUID, tuple]] = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, keys: found.append((dep_id, keys)))
    return found


@pytest.fixture
async def world(do, sites, waits, settles, tmp_path, submitted) -> World:  # noqa: F811
    w = await _world(do, tmp_path)
    # Each droplet's deploy root is a folder of the test's, so the member sessions' commands run for real.
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, w.env_id)
        for inst in (await environments.members(db, env)).values():
            host = await db.get(Host, inst.host_id)
            root = tmp_path / "roots" / str(inst.slot)
            (root / inst.slug).mkdir(parents=True, exist_ok=True)
            host.deploy_root = str(root)
        await db.commit()
    return w


# ------------------------------------------------------------------------------------------------ helpers


async def _get(model, row_id):
    async with get_sessionmaker()() as db:
        return await db.get(model, row_id)


async def _set(model, row_id, **values) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(update(model).where(model.id == row_id).values(**values))
        await db.commit()


async def _members(env_id: uuid.UUID) -> tuple[Environment, dict[str, Instance]]:
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        return env, await environments.members(db, env)


async def _queue(env_id: uuid.UUID, kind: str, *, raw: bool = False, user_id: uuid.UUID | None = None,
                 retry_of: uuid.UUID | None = None, **options: Any) -> uuid.UUID:
    """An environment-level job: through ``jobs.queue_job``, or ``raw`` as a row with its steps, so the job's own
    ``check`` meets what the queue would have refused."""
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        user = await db.get(User, user_id) if user_id is not None else None
        if raw:
            mem = await environments.members(db, env)
            dep = Deployment(instance_id=None, environment_id=env.id, kind=kind, branch=env.branch or "main",
                             options=options, triggered_by_id=user_id, log="", retry_of_id=retry_of,
                             steps=environments.env_steps_for(env, kind, options, mem))
            db.add(dep)
        else:
            parent = await db.get(Deployment, retry_of) if retry_of is not None else None
            dep = await jobs.queue_job(db, environment=env, user=user, kind=kind, options=options, retry_of=parent)
        await db.commit()
        return dep.id


async def _run(dep_id: uuid.UUID, connect) -> Deployment:
    await deployer.run_deployment(dep_id, connect=connect)
    return await _get(Deployment, dep_id)


def _steps(dep: Deployment) -> dict[str, str]:
    return {r["key"]: r["status"] for r in dep.steps or []}


def _names(dep: Deployment) -> dict[str, str]:
    return {r["key"]: r["name"] for r in dep.steps or []}


def _note(dep: Deployment, key: str) -> str | None:
    return next((r.get("note") for r in dep.steps or [] if r["key"] == key), None)


async def _audits(action: str) -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        return list(await db.scalars(select(AuditEvent).where(AuditEvent.action == action)
                                     .order_by(AuditEvent.created_at)))


async def _deployed(env_id: uuid.UUID, slot: str) -> None:
    """``slot`` has a live release: a succeeded deploy, a commit, running."""
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        inst = (await environments.members(db, env))[slot]
        inst.current_commit_sha, inst.status = SHA, "running"
        db.add(Deployment(instance_id=inst.id, environment_id=env_id, kind="deploy", branch="main", commit_sha=SHA,
                          status="succeeded", log="", options={"slot": slot}))
        await db.commit()


async def _set_cloud(env_id: uuid.UUID, **changes: Any) -> None:
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        env.cloud = {**(env.cloud or {}), **changes}
        await db.commit()


def _served(names: list[str], days: int) -> dict[str, Any]:
    when = (datetime.now(UTC) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"id": "c1", "name": "slipway-uat-202611160000", "not_after": when, "names": sorted(names)}


async def _unresolved(env_id: uuid.UUID, to_slot: str | None = "green") -> None:
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        env.traffic_state = {**(env.traffic_state or {}), "unresolved": {
            "deployment_id": uuid.uuid4().hex, "from_slot": "blue", "to_slot": to_slot, "message": "test",
            "at": "2026-11-16T10:00:00+00:00"}}
        await db.commit()


async def _stored_text() -> str:
    out: list[str] = []
    async with get_sessionmaker()() as db:
        for row in await db.scalars(select(AuditEvent)):
            out.append(json.dumps([row.summary, row.details], default=str))
        for row in await db.scalars(select(Deployment)):
            out.append(json.dumps([row.options, row.log, row.error, row.steps], default=str))
    return "\n".join(out)


# ------------------------------------------------------------------------------------ step lists and names


async def test_step_lists_and_names_of_a_digitalocean_environment(world):
    env, mem = await _members(world.env_id)
    names = {k: [r["name"] for r in environments.env_steps_for(env, k, o, mem)] for k, o in (
        ("certificate", {}), ("teardown", {}), ("remove_slot", {"slot": "green"}), ("publish", {}))}
    assert names["certificate"] == ["Check uat", "Renew the certificate"]
    assert names["teardown"] == ["Check uat", "Remove the DNS records", "Remove Blue and Green",
                                 "Remove the data server", "Remove the DigitalOcean objects", "Forget uat"]
    assert names["remove_slot"] == ["Check uat", "Remove green"]
    assert names["publish"] == ["Check uat", "Update the load balancer"]
    await _set_active(world, "blue")
    env, mem = await _members(world.env_id)
    deactivate = environments.env_steps_for(env, "deactivate", {}, mem)
    assert [(r["key"], r["name"]) for r in deactivate] == [("check", "Check uat"), ("switch", "Take traffic off blue")]
    assert environments.ENV_STEP_TIMEOUTS["certificate"] == 45 * 60
    assert environments.ENV_STEP_TIMEOUTS["cloud"] == 75 * 60
    assert "do_lb" in environments.SWITCHES


async def test_activate_lists_the_certificate_step_only_when_it_is_needed(world):
    env, mem = await _members(world.env_id)
    keys = lambda: [r["key"] for r in environments.env_steps_for(env, "activate", {"slot": "green"}, mem)]  # noqa: E731
    assert "certificate" in keys()  # no served certificate recorded yet
    env.cloud = {**env.cloud, "certificate": _served(NAMES, 60)}
    assert keys() == ["check", "smoke", "switch"]
    env.cloud = {**env.cloud, "certificate": _served(NAMES, 30)}
    assert keys() == ["check", "smoke", "certificate", "switch"]
    env.cloud = {**env.cloud, "certificate": _served(NAMES[1:], 60)}  # green's names aren't all covered
    assert keys() == ["check", "smoke", "certificate", "switch"]
    env.cloud = {**env.cloud, "certificate": _served(["*.uat.example.com", "uat.example.com"], 60)}
    assert keys() == ["check", "smoke", "switch"]
    # A Switchyard environment never lists it.
    env.traffic = {"switch": "switchyard", "dns": None}
    env.cloud = {}
    assert "certificate" not in keys()


async def test_managed_environments_attach_nothing_and_have_no_data_values(world):
    env, mem = await _members(world.env_id)
    assert environments.attach_problem(env, None, mem["blue"]) is None
    owner = Instance(name="uat data", slug="uat-data", slot="data", environment_id=env.id, host_id=None)
    with pytest.raises(environments.DataValuesError, match="managed by DigitalOcean"):
        environments.data_values(env, owner, None)  # type: ignore[arg-type]
    with pytest.raises(environments.DataValuesError):
        environments.owner_builtins(env, owner, {"release": "r1"})
    assert await environments.two_slot_traffic_problem(None, env) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------------------- Activate (§15.4)


async def test_activate_through_the_load_balancer(world, sites):
    for slot in ("blue", "green"):
        await _deployed(world.env_id, slot)
    await _set_cloud(world.env_id, certificate=_served(NAMES, 60))
    dep = await _run(await _queue(world.env_id, "activate", slot="blue"), world.multi.connect)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert list(_steps(dep)) == ["check", "smoke", "switch"]
    assert world.targets() == [world.droplets["blue"]]
    env = await _get(Environment, world.env_id)
    assert env.active_slot_id is not None and env.status == "live"
    assert (dep.options or {}).get("switch", {}).get("backend") == "do_lb"
    # Switch to green: joined, checked through the load balancer, the old droplet dropped.
    dep = await _run(await _queue(world.env_id, "activate", slot="green"), world.multi.connect)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert world.lb_puts()[-2:] == [[world.droplets["blue"], world.droplets["green"]], [world.droplets["green"]]]
    assert world.health_calls("green")


async def test_activate_refuses_a_host_that_isnt_built_and_a_load_balancer_blocker(world):
    await _deployed(world.env_id, "blue")
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, world.env_id)
        blue = (await environments.members(db, env))["blue"]
        host = await db.get(Host, blue.host_id)
        host.provider_state = {"phase": "planned"}
        await db.commit()
    dep = await _run(await _queue(world.env_id, "activate", raw=True, slot="blue"), world.multi.connect)
    assert dep.status == "failed" and dep.error == "blue's server isn't built yet: deploy to blue first"
    await _set(Host, host.id, provider_state={"phase": "ready"})
    # The load balancer's plan is read before anything changes.
    world.fake.droplets[world.droplets["blue"]]["tags"] = []
    await _set_cloud(world.env_id, certificate=_served(NAMES, 60))
    dep = await _run(await _queue(world.env_id, "activate", raw=True, slot="blue"), world.multi.connect)
    assert dep.status == "failed"
    assert dep.error == "blue's droplet slipway-uat-blue no longer carries Slipway's tags for uat: Slipway changed " \
                        "nothing"
    assert world.lb_puts() == [] and _steps(dep)["smoke"] == "pending"


# -------------------------------------------------------------------------------------- Publish (§14.3)


async def test_publish_names_puts_the_live_slot_back_on_the_load_balancer(world, sites):
    await _set_active(world, "blue")  # recorded live, but the load balancer has no targets
    dep = await _run(await _queue(world.env_id, "publish"), world.multi.connect)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert _names(dep)["traffic"] == "Update the load balancer"
    assert world.lb_puts() == [[world.droplets["blue"]]]
    assert world.health_calls("blue")
    # Up to date: no write, the names checked once.
    before = len(sites.requests)
    dep = await _run(await _queue(world.env_id, "publish"), world.multi.connect)
    assert dep.status == "succeeded" and world.lb_puts() == [[world.droplets["blue"]]]
    assert len(sites.requests) > before


async def test_publish_never_moves_traffic_to_the_other_slot(world):
    await _set_active(world, "blue")
    world.set_targets("green")
    dep = await _run(await _queue(world.env_id, "publish"), world.multi.connect)
    assert dep.status == "succeeded" and _steps(dep)["traffic"] == "warning"
    assert "but blue is the live slot: activate one of them" in _note(dep, "traffic")
    assert world.lb_puts() == []


# -------------------------------------------------------------------------------------- test 90: Resolve


async def test_90_resolve_through_the_load_balancer(world):
    await _set_active(world, "blue")
    await _unresolved(world.env_id)
    world.set_targets("blue", "green")
    with pytest.raises(env_jobs.ResolveRefused) as err:
        await env_jobs.resolve(world.env_id)
    assert err.value.status == 409
    assert err.value.text == "The load balancer sends traffic to blue and green: activate one of them"
    world.set_targets()
    with pytest.raises(env_jobs.ResolveRefused) as err:
        await env_jobs.resolve(world.env_id)
    assert err.value.text == "The load balancer sends uat's traffic to no slot: activate one of them"
    stranger = world.fake.add_droplet(name="someone-else")
    world.set_targets(stranger["id"])
    with pytest.raises(env_jobs.ResolveRefused) as err:
        await env_jobs.resolve(world.env_id)
    assert err.value.text == f"DigitalOcean: The load balancer sends traffic to droplet {stranger['id']}, which " \
                             "isn't uat's"
    # DigitalOcean can't be read: its error goes to the caller (the API answers 502); nothing is written.
    world.set_targets("green")
    world.fake.fail[("GET", f"/load_balancers/{world.lb_id}")] = [500]
    with pytest.raises(DigitalOceanError):
        await env_jobs.resolve(world.env_id)
    assert (await _get(Environment, world.env_id)).traffic_state["unresolved"] is not None

    seen: list[bool] = []
    real = do_lb.DoLbBackend.who_is_live

    async def watched(self, ctx):
        seen.append(do_lb.lock_for(world.env_id).locked())
        return await real(self, ctx)

    mp = pytest.MonkeyPatch()
    mp.setattr(do_lb.DoLbBackend, "who_is_live", watched)
    try:
        assert await env_jobs.resolve(world.env_id) == "green"
    finally:
        mp.undo()
    assert seen == [True]  # read under the backend's lock
    env, mem = await _members(world.env_id)
    assert env.active_slot_id == mem["green"].id and env.traffic_state["unresolved"] is None
    [row] = await _audits("environment.resolve")
    assert row.details["slot"] == "green"
    with pytest.raises(env_jobs.ResolveRefused, match="isn't split"):
        await env_jobs.resolve(world.env_id)


# --------------------------------------------------------------------------- Deactivate (§13, test 61)


async def _retiring(w: World) -> None:
    await _set(Environment, w.env_id, production=True, retiring_at=datetime.now(UTC), auto_activate=False)


async def test_deactivate_takes_traffic_off_without_a_public_check(world, sites):
    await _set_active(world, "blue")
    world.set_targets("blue")
    dep = await _run(await _queue(world.env_id, "deactivate", raw=True), world.multi.connect)
    assert dep.status == "failed"
    assert dep.error == "Only a retiring production environment is taken off the air: retire uat first"
    assert world.lb_puts() == []

    await _retiring(world)
    dep = await _run(await _queue(world.env_id, "deactivate"), world.multi.connect)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert _names(dep) == {"check": "Check uat", "switch": "Take traffic off blue"}
    assert world.lb_puts() == [[]] and world.targets() == []
    assert sites.requests == []  # the names answer 503 by design: never checked
    env = await _get(Environment, world.env_id)
    assert env.active_slot_id is None and env.traffic_state["deactivated"]["deployment_id"] == str(dep.id)
    assert env.traffic_state["deactivated"]["from_slot"] == "blue"
    assert (dep.options or {})["switch"]["backend"] == "do_lb"
    # Nothing is live any more: a second one is refused before anything changes.
    again = await _run(await _queue(world.env_id, "deactivate", raw=True), world.multi.connect)
    assert again.status == "failed" and again.error == "uat has no live slot: there is no traffic to take off"


async def test_a_failed_deactivate_puts_the_targets_back(world):
    await _retiring(world)
    await _set_active(world, "blue")
    world.set_targets("blue")
    real = do_lb.DoLbBackend.verify

    async def other_writer(self, ctx, plan):
        world.set_targets("green")  # something else put a droplet back meanwhile
        return await real(self, ctx, plan)

    mp = pytest.MonkeyPatch()
    mp.setattr(do_lb.DoLbBackend, "verify", other_writer)
    try:
        dep = await _run(await _queue(world.env_id, "deactivate"), world.multi.connect)
    finally:
        mp.undo()
    assert dep.status == "failed" and "still sends traffic to green" in dep.error
    assert "Traffic stays on blue" in dep.error
    assert world.targets() == [world.droplets["blue"]]
    env, mem = await _members(world.env_id)
    assert env.active_slot_id == mem["blue"].id and not (env.traffic_state or {}).get("deactivated")


async def test_61_an_interrupted_deactivate_is_unresolved_and_switchyard_is_left_alone(world, monkeypatch):
    held: list[str] = []

    async def hold_in(db, env_id):
        held.append(env_id)

    monkeypatch.setattr(switchyard, "hold_in", hold_in)
    await _retiring(world)
    await _set_active(world, "blue")
    steps = [{"key": "check", "name": "Check uat", "status": "succeeded"},
             {"key": "switch", "name": "Take traffic off blue", "status": "running", "started_at": "2026-11-16T10:00"}]
    async with get_sessionmaker()() as db:
        cut = Deployment(instance_id=None, environment_id=world.env_id, kind="deactivate", branch="main", log="",
                         status="running", steps=steps, options={"switch": {
                             "backend": "do_lb", "from_slot": "blue", "to_slot": None,
                             "changed": [{"hostname": "slipway-uat-lb", "id": world.lb_id, "droplet_ids": []}]}})
        db.add(cut)
        await db.commit()
    await deployer.runner.recover_interrupted()
    found = await _get(Deployment, cut.id)
    assert found.status == "failed"
    env = await _get(Environment, world.env_id)
    unresolved = env.traffic_state["unresolved"]
    assert unresolved["deployment_id"] == str(cut.id) and unresolved["to_slot"] is None
    assert unresolved["message"] == env_jobs.RESTARTED
    assert "once the load balancer is right" in environments.unresolved_text(env)
    assert held == []  # a do_lb switch stages nothing in Switchyard
    [row] = await _audits("environment.unresolved")
    assert row.details["slot"] is None

    # One whose empty targets were recorded before the restart succeeded.
    async with get_sessionmaker()() as db:
        done = Deployment(instance_id=None, environment_id=world.env_id, kind="deactivate", branch="main", log="",
                          status="running", steps=steps, options={"switch": {"backend": "do_lb", "changed": []}})
        db.add(done)
        await db.commit()
    await _set(Environment, world.env_id, traffic_state={"deactivated": {"deployment_id": str(done.id)}})
    await deployer.runner.recover_interrupted()
    found = await _get(Deployment, done.id)
    assert found.status == "succeeded" and _steps(found)["switch"] == "succeeded"
    assert not (await _get(Environment, world.env_id)).traffic_state.get("unresolved")

    # An interrupted activate of a do_lb environment doesn't hold Switchyard either.
    async with get_sessionmaker()() as db:
        act = Deployment(instance_id=None, environment_id=world.env_id, kind="activate", branch="main", log="",
                         status="running", options={"slot": "green", "switch": {
                             "backend": "do_lb", "from_slot": "blue", "to_slot": "green", "changed": [{"id": "x"}]}},
                         steps=[{"key": "switch", "name": "Switch traffic to green", "status": "running",
                                 "started_at": "x"}])
        db.add(act)
        await db.commit()
    await deployer.runner.recover_interrupted()
    env = await _get(Environment, world.env_id)
    assert env.traffic_state["unresolved"]["to_slot"] == "green" and held == []


# ---------------------------------------------------------------------------- the certificate job (test 60)


async def _shop_live(cloud: dof.Cloud) -> dof.DoEnv:  # noqa: F811
    """``shop`` built by blue's first deploy (prepare, database, edge), with blue's live routes."""
    env = await dof.make_do_env()
    await built(cloud, env)
    await set_routes(env, "blue", dof.routes("shop"))
    return env


async def test_60_the_certificate_job_renews_swaps_and_deletes_the_old_one(cloud, edge_fakes, submitted):  # noqa: F811
    env = await _shop_live(cloud)
    (first,) = cloud.do.certificates.values()
    cloud.do.certificates[first["id"]]["not_after"] = (datetime.now(UTC) + timedelta(days=20)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    held: list[bool] = []
    real = do_provision.DigitalOceanClient.update_load_balancer

    async def watched(self, lb_id, body):
        held.append(do_lb.lock_for(env.env_id).locked())
        return await real(self, lb_id, body)

    mp = pytest.MonkeyPatch()
    mp.setattr(do_provision.DigitalOceanClient, "update_load_balancer", watched)
    try:
        dep = await _run(await _queue(env.env_id, "certificate", user_id=env.user_id), cloud.connect)
    finally:
        mp.undo()
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert _names(dep) == {"check": "Check shop", "certificate": "Renew the certificate"}
    assert _note(dep, "certificate").startswith("Renewed: slipway-shop-")
    (lb,) = cloud.do.load_balancers.values()
    (cert,) = cloud.do.certificates.values()  # the old one deleted
    assert do_rules.https_certificate(lb) == cert["id"] != first["id"]
    assert held == [True]  # the HTTPS rule PUT ran under do_lb's lock
    row = await dof.env_row(env)
    assert row.cloud["certificate"]["id"] == cert["id"]
    assert sorted(row.cloud["certificate"]["names"]) == SHOP_NAMES
    assert dof.TOKEN not in await _stored_text()
    # Nothing due: the next one keeps ours.
    dep = await _run(await _queue(env.env_id, "certificate", user_id=env.user_id), cloud.connect)
    assert dep.status == "succeeded" and _note(dep, "certificate").endswith("nothing to renew")
    assert list(cloud.do.certificates) == [cert["id"]]


async def test_the_certificate_job_checks_before_it_orders(cloud, edge_fakes, submitted):  # noqa: F811
    env = await _shop_live(cloud)
    orders = dict(edge_fakes.acme.orders)
    await _unresolved(env.env_id)
    dep = await _run(await _queue(env.env_id, "certificate", raw=True), cloud.connect)
    assert dep.status == "failed" and dep.error.startswith("Traffic of shop may be split between its slots")
    await _set(Environment, env.env_id, traffic_state={})
    # Another team behind the token: refused in check.
    await _set(Environment, env.env_id, provider_team="another-team")
    dep = await _run(await _queue(env.env_id, "certificate", raw=True), cloud.connect)
    assert dep.status == "failed" and "not the team shop was built in: Slipway changed nothing" in dep.error
    assert _steps(dep)["certificate"] == "pending"
    assert dict(edge_fakes.acme.orders) == orders


async def test_a_certificate_job_without_a_load_balancer_refuses(world):
    async with get_sessionmaker()() as db:
        await db.execute(Resource.__table__.delete().where(Resource.kind == "load_balancer"))
        await db.commit()
    dep = await _run(await _queue(world.env_id, "certificate", raw=True), world.multi.connect)
    assert dep.status == "failed" and dep.error == "uat has no load balancer yet: deploy it first"


async def test_activate_renews_a_due_certificate_before_the_switch(cloud, edge_fakes, sites, waits, settles,  # noqa: F811
                                                                   submitted, tmp_path):
    env = await _shop_live(cloud)
    await _deployed(env.env_id, "blue")
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, env.ids["blue"])
        host = await db.get(Host, inst.host_id)
        host.deploy_root = str(tmp_path / "root")
        (tmp_path / "root" / inst.slug).mkdir(parents=True)
        inst.published_ports = [{"service": r["service"], "container": r["container"], "protocol": "tcp",
                                 "host": 18000 + i} for i, r in enumerate(dof.routes("shop"))]
        await db.commit()
    (first,) = cloud.do.certificates.values()
    first["not_after"] = (datetime.now(UTC) + timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    await _set_cloud(env.env_id, certificate={**(await dof.env_row(env)).cloud["certificate"],
                                              "not_after": first["not_after"]})
    dep = await _run(await _queue(env.env_id, "activate", user_id=env.user_id, slot="blue"), cloud.connect)
    assert dep.status == "succeeded", (dep.error, dep.log)
    keys = list(_steps(dep))
    assert keys.index("smoke") < keys.index("certificate") < keys.index("switch")
    assert _note(dep, "certificate").startswith("Renewed: slipway-shop-")
    (lb,) = cloud.do.load_balancers.values()
    assert do_rules.https_certificate(lb) != first["id"]
    blue = next(r for r in await dof.rows(env, "droplet") if r.name == "slipway-shop-blue")
    assert lb["droplet_ids"] == [int(blue.provider_id)]


# ------------------------------------------------------------------------------- Remove slot (§9.3, §14.3)


async def _two_slots(cloud: dof.Cloud) -> dof.DoEnv:  # noqa: F811
    env = await _shop_live(cloud)
    green = await prepared(cloud, env, "green")
    await do_provision.database(green)
    return env


async def test_remove_slot_deletes_the_droplet_without_ssh_and_retries(cloud, edge_fakes, submitted):  # noqa: F811
    env = await _two_slots(cloud)
    green_id = next(r.provider_id for r in await dof.rows(env, "droplet") if r.name == "slipway-shop-green")
    green_host = await dof.host_row(env, "green")
    sessions = len(cloud.sent)
    cloud.do.fail[("DELETE", f"/droplets/{green_id}")] = [500]
    dep = await _run(await _queue(env.env_id, "remove_slot", user_id=env.user_id, slot="green"), cloud.connect)
    assert dep.status == "failed" and _names(dep) == {"check": "Check shop", "slot": "Remove green"}
    assert await _get(Instance, env.ids["green"]) is not None
    assert await _get(Host, env.host_ids["green"]) is not None
    assert (await dof.env_row(env)).cloud["plan"]["droplets"] == 2

    retry = await _run(await _queue(env.env_id, "remove_slot", user_id=env.user_id, retry_of=dep.id, slot="green"),
                       cloud.connect)
    assert retry.status == "succeeded", (retry.error, retry.log)
    assert int(green_id) not in cloud.do.droplets
    assert await _get(Instance, env.ids["green"]) is None and await _get(Host, env.host_ids["green"]) is None
    row = await dof.env_row(env)
    assert row.cloud["plan"]["droplets"] == 1 and "one droplet" in _note(retry, "slot")
    assert not [t for t in cloud.sent[sessions:] if t.hostname == green_host.hostname]  # no SSH to the droplet
    [removed] = await _audits("environment.slot_remove")
    assert removed.details["slot"] == "green" and removed.details["host"] == "slipway-shop-green"
    assert [a.details["to"] for a in await _audits("environment.resize")] == [{"droplets": 1}]
    # Nothing left: a retry says so.
    again = await _run(await _queue(env.env_id, "remove_slot", raw=True, retry_of=retry.id, slot="green"),
                       cloud.connect)
    assert again.status == "succeeded" and _note(again, "check") == "green was already removed"
    assert _note(again, "slot") == "Already removed"


async def test_a_remove_slot_retry_goes_on_while_the_host_row_is_left(cloud, edge_fakes, submitted):  # noqa: F811
    env = await _two_slots(cloud)
    first = await _queue(env.env_id, "remove_slot", raw=True, slot="green")
    # A first attempt stopped after the instance row went: the droplet and its host row are still there.
    from sqlalchemy import delete
    async with get_sessionmaker()() as db:
        await db.execute(delete(Instance).where(Instance.id == env.ids["green"]))
        await db.commit()
    await _set(Deployment, first, status="failed")
    retry = await _run(await _queue(env.env_id, "remove_slot", raw=True, retry_of=first, slot="green"), cloud.connect)
    assert retry.status == "succeeded", (retry.error, retry.log)
    assert "isn't removed yet" in _note(retry, "check")
    assert await _get(Host, env.host_ids["green"]) is None
    assert not [r for r in await dof.rows(env, "droplet") if r.name == "slipway-shop-green"]
    assert (await dof.env_row(env)).cloud["plan"]["droplets"] == 1


# ---------------------------------------------------------------------------------- Teardown (§15.11)


async def _deleting(env: dof.DoEnv) -> uuid.UUID:
    return await _queue(env.env_id, "teardown", user_id=env.user_id, confirmed=True)


async def test_teardown_removes_every_object_without_ssh(cloud, edge_fakes, submitted):  # noqa: F811
    env = await _two_slots(cloud)
    owner = await _get(Instance, env.ids["data"])
    stored = backup_store.owner_dir(owner.id)
    stored.mkdir(parents=True, exist_ok=True)
    (stored / "b1.db.sbc").write_bytes(b"sealed")
    sessions = len(cloud.sent)
    dep = await _run(await _deleting(env), cloud.connect)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert list(_steps(dep)) == ["check", "undns", "slots", "data_server", "cloud", "forget"]
    assert _note(dep, "cloud") == "Nothing of shop is left on DigitalOcean."
    assert cloud.sent[sessions:] == []  # no SSH to any droplet
    nothing_left(cloud)
    assert await dof.rows(env) == []
    async with get_sessionmaker()() as db:
        assert list(await db.scalars(select(Host).where(Host.owner_environment_id == env.env_id))) == []
        assert list(await db.scalars(select(Instance).where(Instance.environment_id == env.env_id))) == []
    row = await dof.env_row(env)
    assert row.status == "deleted"
    kept = [p for p in (backup_store.root().parent / backup_store.KEPT_FOLDER).iterdir() if p.name.startswith("shop-")]
    assert kept and (kept[0] / "b1.db.sbc").read_bytes() == b"sealed"
    deleted = [a.details for a in await _audits("instance.delete")]
    assert {d["slot"] for d in deleted} == {"blue", "green", "data"}
    assert all(d.get("owned") for d in deleted if d["slot"] != "data")
    assert dof.TOKEN not in await _stored_text()


async def test_teardown_checks_the_marks_before_it_changes_anything(cloud, edge_fakes, submitted):  # noqa: F811
    env = await _two_slots(cloud)
    (lb,) = cloud.do.load_balancers.values()
    lb["name"] = "renamed-by-hand"
    mark = len(cloud.do.writes())
    dep = await _run(await _deleting(env), cloud.connect)
    assert dep.status == "failed" and "no longer looks like Slipway's slipway-shop-lb" in dep.error
    assert _steps(dep)["slots"] == "pending"
    assert cloud.do.writes()[mark:] == []
    async with get_sessionmaker()() as db:
        assert len(list(await db.scalars(select(Instance).where(Instance.environment_id == env.env_id)))) == 3
    # Put right by hand, the retry goes all the way.
    lb["name"] = "slipway-shop-lb"
    retry = await _run(await _queue(env.env_id, "teardown", user_id=env.user_id, retry_of=dep.id), cloud.connect)
    assert retry.status == "succeeded", (retry.error, retry.log)
    nothing_left(cloud)


async def test_a_production_teardown_reads_the_production_rules_again_at_run_time(cloud, edge_fakes,  # noqa: F811
                                                                                   submitted):  # noqa: F811
    env = await _two_slots(cloud)
    # Queued past the queue's fences (raw): a production environment not retired, still taking traffic.
    await _set(Environment, env.env_id, production=True, status="deleting", retiring_at=None)
    mark = len(cloud.do.writes())
    dep = await _run(await _queue(env.env_id, "teardown", raw=True, confirmed=True), cloud.connect)
    assert dep.status == "failed" and "Retire shop first" in dep.error, dep.error
    assert _steps(dep)["check"] == "failed" and _steps(dep)["slots"] == "pending"
    assert cloud.do.writes()[mark:] == []
    async with get_sessionmaker()() as db:
        assert len(list(await db.scalars(select(Instance).where(Instance.environment_id == env.env_id)))) == 3


async def test_teardown_of_an_environment_never_built(cloud, submitted):  # noqa: F811
    env = await dof.make_do_env()
    dep = await _run(await _deleting(env), cloud.connect)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert cloud.do.writes() == []
    async with get_sessionmaker()() as db:
        assert list(await db.scalars(select(Host).where(Host.owner_environment_id == env.env_id))) == []
    assert (await dof.env_row(env)).status == "deleted"


# ----------------------------------------------------------------------- owned hosts in general (Decision 15)


async def test_an_owned_host_in_any_phase_is_removed_without_ssh(world):
    """Remove slot on a droplet host that isn't built yet: allowed, and nothing is run on it."""
    env, mem = await _members(world.env_id)
    await _set(Host, mem["green"].host_id, provider_state={"phase": "creating"}, host_key=None)
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, world.env_id)
        mem = await environments.members(db, env)
        problem = await env_jobs._fence(db, types_run("remove_slot"), env, mem, mem["green"])
        assert problem is None
        problem = await env_jobs._fence(db, types_run("activate"), env, mem, mem["green"])
        assert problem == "green's server isn't built yet: deploy to green first"


def types_run(kind: str) -> Any:
    """The parts of a running job ``_fence`` reads."""
    import types
    return types.SimpleNamespace(kind=kind, options={}, dep_id=uuid.uuid4())


# ------------------------------------------------------------------------------------------------ texts


async def test_unresolved_text_names_the_backend(world):
    env = await _get(Environment, world.env_id)
    env.traffic_state = {"unresolved": {"deployment_id": "ab" * 16, "message": "test"}}
    assert environments.unresolved_text(env).endswith("use Resolve once the load balancer is right")
    env.traffic = {"switch": "switchyard"}
    assert environments.unresolved_text(env).endswith("use Resolve once Switchyard is right")

