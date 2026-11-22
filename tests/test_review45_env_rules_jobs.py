"""Review 45, cluster "Environment rules and env jobs": the run-time halves, through the real job engine against
FakeDigitalOcean (tests/test_do_env_jobs.py's ``world``): a retiring production's activate fails its check, or its
switch when Retire lands meanwhile (F17), and Resolve after a cut-off Deactivate records it dark (F33).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Environment
from slipway.services import env_jobs, environments, traffic
from tests.test_do_env_jobs import (  # noqa: F401  (fixtures)
    _audits,
    _deployed,
    _get,
    _members,
    _queue,
    _run,
    _served,
    _set,
    _set_cloud,
    _steps,
    do,
    settles,
    sites,
    submitted,
    waits,
    world,
)
from tests.test_do_lb import NAMES, _set_active

RETIRING = "uat is retiring: it only goes dark"


async def _production_ready(world) -> None:  # noqa: F811
    for slot in ("blue", "green"):
        await _deployed(world.env_id, slot)
    await _set_cloud(world.env_id, certificate=_served(NAMES, 60))
    await _set_active(world, "blue")
    world.set_targets("blue")
    await _set(Environment, world.env_id, production=True, auto_activate=False, status="live")


# ------------------------------------------------------------- F17: a retiring production only goes dark


async def test_f17_an_activate_queued_before_retire_fails_its_check(world):  # noqa: F811
    await _production_ready(world)
    dep_id = await _queue(world.env_id, "activate", slot="green", confirm="uat")  # queued while not retiring
    await _set(Environment, world.env_id, retiring_at=datetime.now(UTC))
    dep = await _run(dep_id, world.multi.connect)
    assert dep.status == "failed" and dep.error == RETIRING
    assert _steps(dep)["check"] == "failed" and _steps(dep)["switch"] == "pending"
    assert world.lb_puts() == [] and world.targets() == [world.droplets["blue"]]
    env, mem = await _members(world.env_id)
    assert env.active_slot_id == mem["blue"].id


async def test_f17_retire_during_the_smoke_step_stops_the_switch_before_its_first_write(world, monkeypatch):  # noqa: F811
    await _production_ready(world)
    real = traffic.save_last_check

    async def retire_meanwhile(*args, **kwargs):
        await real(*args, **kwargs)
        await _set(Environment, world.env_id, retiring_at=datetime.now(UTC))  # Retire lands after check

    monkeypatch.setattr(traffic, "save_last_check", retire_meanwhile)
    dep = await _run(await _queue(world.env_id, "activate", slot="green", confirm="uat"), world.multi.connect)
    assert dep.status == "failed"
    assert dep.error == f"{RETIRING}; Slipway changed nothing"
    assert _steps(dep)["check"] == "succeeded" and _steps(dep)["smoke"] == "succeeded"
    assert _steps(dep)["switch"] == "failed"
    assert world.lb_puts() == [] and world.targets() == [world.droplets["blue"]]
    env, mem = await _members(world.env_id)
    assert env.active_slot_id == mem["blue"].id and not (env.traffic_state or {}).get("unresolved")


async def test_f17_a_production_that_isnt_retiring_still_switches(world, sites):  # noqa: F811
    await _production_ready(world)
    dep = await _run(await _queue(world.env_id, "activate", slot="green", confirm="uat"), world.multi.connect)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert world.targets() == [world.droplets["green"]]


# --------------------------------------------------------------- F33: Resolve after a cut-off Deactivate


async def _cut_deactivate(world) -> Deployment:  # noqa: F811
    """A Deactivate whose empty targets went out, cut off before its closing write: recovery's unresolved."""
    await _production_ready(world)
    await _set(Environment, world.env_id, retiring_at=datetime.now(UTC))
    async with get_sessionmaker()() as db:
        cut = Deployment(instance_id=None, environment_id=world.env_id, kind="deactivate", branch="main", log="",
                         status="failed", steps=[], options={"switch": {"backend": "do_lb", "from_slot": "blue",
                                                                        "to_slot": None}})
        db.add(cut)
        await db.flush()
        env = await db.get(Environment, world.env_id)
        env.traffic_state = {**(env.traffic_state or {}), "unresolved": {
            "deployment_id": str(cut.id), "from_slot": "blue", "to_slot": None, "message": env_jobs.RESTARTED,
            "at": "2026-11-16T10:00:00+00:00"}}
        await db.commit()
    world.set_targets()  # the PUT [] landed
    return cut


async def test_f33_resolve_records_a_cut_off_deactivate_as_taken_off_the_air(world):  # noqa: F811
    cut = await _cut_deactivate(world)
    assert await env_jobs.resolve(world.env_id) is None
    env, mem = await _members(world.env_id)
    assert env.active_slot_id is None
    assert env.traffic_state["unresolved"] is None
    assert env.traffic_state["deactivated"]["deployment_id"] == str(cut.id)
    assert env.traffic_state["deactivated"]["from_slot"] == "blue"
    [row] = await _audits("environment.resolve")
    assert row.details["slot"] is None
    assert world.lb_puts() == []  # Resolve reads; it writes nothing to DigitalOcean
    # The teardown's "Deactivate first" no longer holds it back, and a second Resolve has nothing to settle.
    assert environments.unresolved_text(env) is None
    with pytest.raises(env_jobs.ResolveRefused, match="isn't split"):
        await env_jobs.resolve(world.env_id)


async def test_f33_a_cut_off_deactivate_whose_targets_came_back_resolves_to_that_slot(world):  # noqa: F811
    await _cut_deactivate(world)
    world.set_targets("blue")  # its put-back landed
    assert await env_jobs.resolve(world.env_id) == "blue"
    env, mem = await _members(world.env_id)
    assert env.active_slot_id == mem["blue"].id and not env.traffic_state.get("deactivated")


async def test_f33_no_target_after_an_activate_is_still_refused(world):  # noqa: F811
    await _production_ready(world)
    async with get_sessionmaker()() as db:
        act = Deployment(instance_id=None, environment_id=world.env_id, kind="activate", branch="main", log="",
                         status="failed", steps=[], options={"slot": "green"})
        db.add(act)
        await db.flush()
        env = await db.get(Environment, world.env_id)
        env.traffic_state = {**(env.traffic_state or {}), "unresolved": {
            "deployment_id": str(act.id), "from_slot": "blue", "to_slot": None, "message": "x", "at": "x"}}
        await db.commit()
    world.set_targets()
    with pytest.raises(env_jobs.ResolveRefused) as err:
        await env_jobs.resolve(world.env_id)
    assert err.value.text == "The load balancer sends uat's traffic to no slot: activate one of them"
    env = await _get(Environment, world.env_id)
    assert env.active_slot_id is not None and env.traffic_state["unresolved"] is not None
