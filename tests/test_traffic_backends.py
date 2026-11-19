"""The traffic backend interface phase 4 adds to phase 3's traffic code (P4 §11.6 "What S05 changes", test 31).

A stub backend, registered with ``traffic.register``, shows what ``switch``, ``sync`` and the shielded
put-back ask of a backend: its own lock (taken and released around plan and apply, handed to the put-back,
free during verify), ``put_back_locked`` and ``repair`` on the protocol, mode ``deactivate`` through
``context()`` and ``switch()``, and failure texts naming the backend. The Switchyard backend is checked for
the parts it keeps (``switchyard.lock``, the deactivate refusal) and for ``who_is_live``. Switchyard is
tests/fake_switchyard.py; the public check talks to ``FakeSites`` through ``traffic.transport_factory``.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from sqlalchemy import update

from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Environment
from slipway.services import switchyard, traffic
from tests.test_traffic import (  # noqa: F401  (fixtures)
    ADDRESS,
    APP_ROUTES,
    PORT_BASE,
    _activate,
    _ctx,
    _deployment,
    _env,
    _set_active,
    configured,
    fake,
    sites,
    waits,
)


class StubError(Exception):
    pass


class Stub:
    """A backend that records each call and whether its lock (and Switchyard's) was held at the time."""

    name = "stub"
    label = "Stubyard"
    via = "the stub balancer"
    errors = (StubError,)

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self.events: list[tuple] = []
        self.blockers: list[str] = []
        self.plan_error: Exception | None = None
        self.apply_error: BaseException | None = None
        self.verify_error: BaseException | None = None
        self.verifying: asyncio.Event | None = None  # set while verify waits on ``hold``
        self.hold: asyncio.Event | None = None
        self.put_back_fails = False
        self.has_writes = True
        self.repaired: traffic.SyncResult | None = None
        self.why_not: str | None = None
        self.live: list[str] = []

    def held(self) -> tuple[bool, bool]:
        return self._lock.locked(), switchyard.lock.locked()

    def lock(self, ctx):
        return self._lock

    async def configured(self, db):
        return self.why_not

    async def plan(self, ctx):
        self.events.append(("plan", ctx.mode, *self.held()))
        if self.plan_error is not None:
            raise self.plan_error
        after = [] if ctx.mode == "deactivate" else [ctx.to_slot.slot if ctx.to_slot else "?"]
        plan = traffic.Plan(self.name, blockers=list(self.blockers))
        plan.changes.append(traffic.Change("stub-lb", "update", "lb-1", None, {"targets": [ctx.from_slot]},
                                           {"targets": after}, f"stub-lb → {after}"))
        return plan

    async def apply(self, ctx, plan):
        self.events.append(("apply", ctx.mode, *self.held()))
        applied = ctx.applied = traffic.Applied(changes=list(plan.writes))
        if self.apply_error is not None:
            raise self.apply_error
        return applied

    async def verify(self, ctx, plan):
        self.events.append(("verify", ctx.mode, *self.held()))
        if self.hold is not None:
            self.verifying.set()
            await self.hold.wait()
        if self.verify_error is not None:
            raise self.verify_error
        return traffic.CheckResult(ok=True)

    async def put_back(self, ctx, plan, applied):
        self.events.append(("put_back", ctx.mode, *self.held()))
        async with self.lock(ctx):
            return await self.put_back_locked(ctx, plan, applied)

    async def put_back_locked(self, ctx, plan, applied):
        self.events.append(("put_back_locked", ctx.mode, *self.held()))
        pb = traffic.PutBack(total=len(applied.changes))
        names = [c.hostname for c in applied.changes]
        if self.put_back_fails:
            pb.failed = names
        else:
            pb.done = names
        return pb

    async def remove(self, ctx):
        return traffic.Plan(self.name)

    async def who_is_live(self, ctx):
        return list(self.live)

    def pending(self, plan):
        return self.has_writes

    async def check_sync(self, ctx, result):
        self.events.append(("check_sync", ctx.mode, *self.held()))

    async def repair(self, ctx):
        self.events.append(("repair", ctx.mode, *self.held()))
        return self.repaired

    def calls(self) -> list[str]:
        return [e[0] for e in self.events]


@pytest.fixture
def stub(monkeypatch) -> Stub:
    monkeypatch.setattr(traffic, "BACKENDS", dict(traffic.BACKENDS))
    return traffic.register(Stub())


async def _stub_env(*, active: str | None = "blue") -> uuid.UUID:
    env_id = await _env(switch="stub")
    if active:
        await _set_active(env_id, active)
    return env_id


async def _options(dep_id) -> dict:
    async with get_sessionmaker()() as db:
        return (await db.get(Deployment, dep_id)).options or {}


async def _env_row(env_id) -> Environment:
    async with get_sessionmaker()() as db:
        return await db.get(Environment, env_id)


# ------------------------------------------------------------------------- register


async def test_register_adds_a_backend_that_backend_for_finds(stub):
    assert traffic.BACKENDS["stub"] is stub
    assert isinstance(traffic.BACKENDS["switchyard"], traffic.SwitchyardBackend)
    env = await _env_row(await _stub_env())
    assert traffic.backend_for(env) is stub
    again = Stub()
    assert traffic.register(again) is again and traffic.BACKENDS["stub"] is again  # a second register replaces


async def test_switchyards_lock_is_switchyard_lock(fake):
    env_id = await _env()
    ctx = await _ctx(env_id, "sync")
    backend = traffic.BACKENDS["switchyard"]
    assert backend.lock(ctx) is switchyard.lock and backend.lock(ctx) is switchyard._lock
    assert (backend.label, backend.via, backend.errors) == ("Switchyard", "Switchyard", (switchyard.SwitchyardError,))
    assert await backend.repair(ctx) is None


async def test_a_switchyard_switch_still_plans_and_applies_under_switchyard_lock(configured, monkeypatch):
    backend = traffic.BACKENDS["switchyard"]
    seen: list[tuple[str, bool]] = []
    plan, apply, verify = backend.plan, backend.apply, backend.verify

    async def watched_plan(ctx):
        seen.append(("plan", switchyard.lock.locked()))
        return await plan(ctx)

    async def watched_apply(ctx, p):
        seen.append(("apply", switchyard.lock.locked()))
        return await apply(ctx, p)

    async def watched_verify(ctx, p):
        seen.append(("verify", switchyard.lock.locked()))
        return await verify(ctx, p)

    monkeypatch.setattr(backend, "plan", watched_plan)
    monkeypatch.setattr(backend, "apply", watched_apply)
    monkeypatch.setattr(backend, "verify", watched_verify)
    env_id = await _env()
    await _activate(env_id, "blue")
    assert seen == [("plan", True), ("apply", True), ("verify", False)]
    assert not switchyard.lock.locked()


# ---------------------------------------------------------------- the backend's lock


async def test_switch_takes_the_backends_lock_and_frees_it_for_verify(stub, sites):
    env_id = await _stub_env()
    dep_id = await _deployment(env_id)
    lines: list[str] = []
    result = await traffic.switch(await _ctx(env_id, "activate", "green", deployment_id=dep_id, lines=lines))
    assert stub.events == [("plan", "activate", True, False), ("apply", "activate", True, False),
                           ("verify", "activate", False, False)]
    assert not stub._lock.locked() and not switchyard.lock.locked()
    assert result.plan.backend == "stub" and result.applied.changes[0].hostname == "stub-lb"
    assert "Plan for uat → green:" in lines and "Checking the names through the stub balancer" in lines
    record = (await _options(dep_id))["switch"]
    assert (record["backend"], record["from_slot"], record["to_slot"]) == ("stub", "blue", "green")
    assert sites.requests == []  # the public check is the backend's business


async def test_a_failed_apply_hands_the_lock_to_the_put_back_which_releases_it(stub):
    env_id = await _stub_env()
    stub.apply_error = StubError("the stub balancer refused the change")
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(env_id, "activate", "green"))
    assert str(err.value) == "the stub balancer refused the change. Traffic stays on blue"
    assert stub.calls() == ["plan", "apply", "put_back_locked"]
    assert stub.events[-1] == ("put_back_locked", "activate", True, False)  # still held: no writer in between
    assert not stub._lock.locked()
    assert not err.value.unresolved and (await _env_row(env_id)).traffic_state.get("unresolved") is None


async def test_a_failed_first_activation_says_nothing_was_live(stub):
    env_id = await _stub_env(active=None)
    stub.apply_error = StubError("the PUT was refused")
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(env_id, "activate", "green"))
    assert str(err.value) == "the PUT was refused. Nothing was live before; Slipway put back what it had written"


async def test_an_unknown_error_in_apply_is_named_by_its_type(stub):
    env_id = await _stub_env()
    stub.apply_error = KeyError("targets")
    with pytest.raises(traffic.SwitchFailed, match=r"^KeyError: 'targets'\. Traffic stays on blue$"):
        await traffic.switch(await _ctx(env_id, "activate", "green"))
    assert not stub._lock.locked()


async def test_a_put_back_that_cant_finish_names_the_backend_and_marks_unresolved(stub):
    env_id = await _stub_env()
    stub.verify_error = traffic.SwitchFailed("2 of 5 names didn't answer through the stub balancer")
    stub.put_back_fails = True
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(env_id, "activate", "green"))
    assert str(err.value) == ("2 of 5 names didn't answer through the stub balancer. Slipway couldn't put 1 of 1 "
                              "back: stub-lb. Check them in Stubyard, then use Resolve on the environment page")
    assert err.value.unresolved
    # The verify phase held no lock, so the put-back took it itself.
    assert stub.events[-2:] == [("put_back", "activate", False, False), ("put_back_locked", "activate", True, False)]
    assert not stub._lock.locked()
    state = (await _env_row(env_id)).traffic_state
    assert (state["unresolved"]["from_slot"], state["unresolved"]["to_slot"]) == ("blue", "green")


async def test_a_cancel_during_verify_still_puts_back_and_frees_the_lock(stub):
    env_id = await _stub_env()
    stub.verifying, stub.hold = asyncio.Event(), asyncio.Event()
    task = asyncio.create_task(traffic.switch(await _ctx(env_id, "activate", "green")))
    await asyncio.wait_for(stub.verifying.wait(), 5)
    assert not stub._lock.locked()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert stub.calls() == ["plan", "apply", "verify", "put_back", "put_back_locked"]
    assert not stub._lock.locked()


async def test_a_cancel_during_apply_puts_back_under_the_lock(stub):
    env_id = await _stub_env()
    stub.apply_error = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await traffic.switch(await _ctx(env_id, "activate", "green"))
    assert stub.calls() == ["plan", "apply", "put_back_locked"] and not stub._lock.locked()


async def test_a_plan_the_backend_cant_read_refuses_and_frees_the_lock(stub):
    env_id = await _stub_env()
    stub.plan_error = StubError("Stubyard couldn't be reached")
    with pytest.raises(traffic.SwitchRefused, match=r"^Stubyard couldn't be reached; Slipway changed nothing$"):
        await traffic.switch(await _ctx(env_id, "activate", "green"))
    assert stub.calls() == ["plan"] and not stub._lock.locked()


# ------------------------------------------------------------------------ deactivate


async def test_context_builds_a_deactivate_with_the_active_slots_names(stub):
    env_id = await _stub_env()
    ctx = await _ctx(env_id, "deactivate")
    assert ctx.mode == "deactivate" and ctx.to_slot is None and ctx.from_slot == "blue"
    assert ctx.from_instance is not None and ctx.from_instance.slot == "blue"
    assert ctx.scope == (traffic.ACTIVE,)
    assert sorted(r.hostname for r in ctx.routes) == sorted(h for h, *_ in APP_ROUTES)  # not the data server's
    assert {r.follows for r in ctx.routes} == {traffic.ACTIVE}
    async with get_sessionmaker()() as db:
        await db.execute(update(Environment).where(Environment.id == env_id).values(active_slot_id=None))
        await db.commit()
    nothing_live = await _ctx(env_id, "deactivate")
    assert nothing_live.routes == [] and nothing_live.from_slot is None
    with pytest.raises(ValueError, match="unknown traffic mode 'pause'"):
        await _ctx(env_id, "pause")


async def test_deactivate_runs_through_switch_with_the_backends_verify(stub, sites):
    env_id = await _stub_env()
    dep_id = await _deployment(env_id)
    lines: list[str] = []
    result = await traffic.switch(await _ctx(env_id, "deactivate", deployment_id=dep_id, lines=lines))
    assert stub.events == [("plan", "deactivate", True, False), ("apply", "deactivate", True, False),
                           ("verify", "deactivate", False, False)]
    assert result.plan.changes[0].after == {"targets": []}
    assert "Plan to take uat's traffic off blue:" in lines
    assert "Checking that the stub balancer sends no traffic to blue" in lines
    record = (await _options(dep_id))["switch"]
    assert (record["backend"], record["from_slot"], record["to_slot"]) == ("stub", "blue", None)
    assert sites.requests == []  # no public check: the names answer 503 by design
    env = await _env_row(env_id)
    assert env.active_slot_id is not None  # the caller (env_jobs) clears it, not switch


async def test_deactivate_refuses_on_blockers_and_writes_nothing(stub):
    env_id = await _stub_env()
    dep_id = await _deployment(env_id)
    stub.blockers = ["The load balancer is applying a change; try again in a minute"]
    with pytest.raises(traffic.SwitchRefused) as err:
        await traffic.switch(await _ctx(env_id, "deactivate", deployment_id=dep_id))
    assert str(err.value) == ("The load balancer is applying a change; try again in a minute; "
                              "Slipway changed nothing")
    assert stub.calls() == ["plan"] and not stub._lock.locked()
    assert "switch" not in await _options(dep_id)


async def test_a_failed_deactivate_says_traffic_stays_on_the_slot(stub):
    env_id = await _stub_env()
    stub.verify_error = traffic.SwitchFailed("The stub balancer still sends traffic to blue")
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(env_id, "deactivate"))
    assert str(err.value) == "The stub balancer still sends traffic to blue. Traffic stays on blue"
    assert stub.calls()[-2:] == ["put_back", "put_back_locked"]


async def test_a_deactivate_that_cant_be_put_back_is_unresolved_with_no_target_slot(stub):
    env_id = await _stub_env()
    stub.apply_error = StubError("the PUT timed out")
    stub.put_back_fails = True
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(env_id, "deactivate"))
    assert str(err.value) == ("the PUT timed out. Slipway couldn't put 1 of 1 back: stub-lb. Check them in "
                              "Stubyard, then use Resolve on the environment page")
    unresolved = (await _env_row(env_id)).traffic_state["unresolved"]
    assert (unresolved["from_slot"], unresolved["to_slot"]) == ("blue", None)


async def test_switch_accepts_only_activate_and_deactivate(stub):
    env_id = await _stub_env()
    with pytest.raises(ValueError, match="an activate or a deactivate"):
        await traffic.switch(await _ctx(env_id, "sync", include_active=True))
    assert stub.events == []


async def test_switchyard_refuses_a_deactivate_without_asking_switchyard(configured):
    fake = configured
    env_id = await _env()
    await _activate(env_id, "blue")
    before = len(fake.api_calls())
    dep_id = await _deployment(env_id)
    with pytest.raises(traffic.SwitchRefused) as err:
        await traffic.switch(await _ctx(env_id, "deactivate", deployment_id=dep_id))
    assert str(err.value) == "uat uses Switchyard; take its names off in Switchyard instead; Slipway changed nothing"
    assert len(fake.api_calls()) == before and "switch" not in await _options(dep_id)
    assert not switchyard.lock.locked()


# ------------------------------------------------------------------------------ sync


async def test_sync_takes_the_lock_for_plan_and_apply_then_checks_and_repairs_without_it(stub):
    env_id = await _stub_env()
    lines: list[str] = []
    result = await traffic.sync(await _ctx(env_id, "sync", include_active=True, lines=lines))
    assert stub.events == [("plan", "sync", True, False), ("apply", "sync", True, False),
                           ("check_sync", "sync", False, False), ("repair", "sync", False, False)]
    assert "Stubyard plan:" in lines
    assert result.applied is not None and result.warnings == []


async def test_sync_with_nothing_to_write_is_up_to_date_and_still_repairs(stub):
    env_id = await _stub_env()
    stub.has_writes = False
    lines: list[str] = []
    await traffic.sync(await _ctx(env_id, "sync", include_active=True, lines=lines))
    assert stub.calls() == ["plan", "repair"] and "Stubyard: up to date" in lines


async def test_sync_adds_what_the_repair_did(stub):
    env_id = await _stub_env()
    stub.has_writes = False
    repair_plan = traffic.Plan("stub", notes=["put blue back"])
    stub.repaired = traffic.SyncResult(repair_plan, traffic.Applied(), traffic.CheckResult(ok=False),
                                       warnings=["uat.example.com answered 502 on / (1 rounds) through the stub "
                                                 "balancer"])
    result = await traffic.sync(await _ctx(env_id, "sync", include_active=True))
    assert result.plan is repair_plan and result.check is stub.repaired.check
    assert result.warnings == stub.repaired.warnings


async def test_sync_doesnt_repair_while_a_switch_is_unresolved(stub):
    env_id = await _stub_env()
    async with get_sessionmaker()() as db:
        await db.execute(update(Environment).where(Environment.id == env_id).values(
            traffic_state={"unresolved": {"message": "split", "from_slot": "blue", "to_slot": "green"}}))
        await db.commit()
    await traffic.sync(await _ctx(env_id, "sync", include_active=True))
    assert "repair" not in stub.calls()


async def test_a_failed_sync_apply_is_put_back_under_the_lock(stub):
    env_id = await _stub_env()
    stub.apply_error = StubError("the PUT was refused")
    result = await traffic.sync(await _ctx(env_id, "sync", include_active=True))
    assert result.warnings == ["Stubyard: the PUT was refused; put back"]
    assert stub.calls() == ["plan", "apply", "put_back_locked", "repair"]
    assert stub.events[2] == ("put_back_locked", "sync", True, False) and not stub._lock.locked()


async def test_a_sync_plan_the_backend_cant_read_is_a_warning(stub):
    env_id = await _stub_env()
    stub.plan_error = StubError("Stubyard couldn't be reached")
    result = await traffic.sync(await _ctx(env_id, "sync", include_active=True))
    assert result.warnings == ["Stubyard: Stubyard couldn't be reached; nothing was changed"]
    assert not stub._lock.locked()


async def test_sync_blockers_are_warnings_under_the_backends_label(stub):
    env_id = await _stub_env()
    stub.blockers = ["The load balancer is applying a change; try again in a minute"]
    lines: list[str] = []
    result = await traffic.sync(await _ctx(env_id, "sync", include_active=True, lines=lines))
    assert result.warnings == stub.blockers and "Stubyard: nothing was changed" in lines
    assert "apply" not in stub.calls()


async def test_sync_without_a_backend_keeps_phase_3s_text(stub):
    env_id = await _env(switch=None)
    result = await traffic.sync(await _ctx(env_id, "sync", include_active=True))
    assert result.skipped == "uat doesn't publish its names through Switchyard" and stub.events == []


# --------------------------------------------------------------------------- plan_for


async def test_plan_for_asks_for_switchyards_settings_only_for_switchyard(stub):
    env_id = await _stub_env()
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        out = await traffic.plan_for(env, "green", db)
    assert out["switch"]["backend"] == "stub" and out["switch"]["blockers"] == []  # Switchyard isn't set up
    assert stub.calls() == ["plan"]
    stub.why_not = "Add a DigitalOcean token to the account first"
    async with get_sessionmaker()() as db:
        out = await traffic.plan_for(await db.get(Environment, env_id), "green", db)
    assert out["switch"] == {"backend": "stub", "changes": [], "blockers": [stub.why_not], "notes": [], "warnings": []}


async def test_plan_for_switchyard_still_asks_for_its_settings(fake):
    env_id = await _env()
    async with get_sessionmaker()() as db:
        out = await traffic.plan_for(await db.get(Environment, env_id), "blue", db)
    assert out["switch"]["backend"] == "switchyard" and out["switch"]["blockers"] == [traffic.SWITCHYARD_MISSING]


# ----------------------------------------------------------------------- public check


async def test_public_check_takes_an_address_insecure_and_via(sites, waits):
    planned = [traffic.Route("api.uat.example.com", "api", 8000, "active", "auto", "/healthz"),
               traffic.Route("int.uat.example.com", "api", 8000, "active", "internal", "/")]
    sites.codes = {"api.uat.example.com": [503, 200]}
    lines: list[str] = []

    async def say(line):
        lines.append(line)

    result = await traffic.public_check(planned, "203.0.113.7:443", say=say, rounds=2, insecure=True,
                                        via="the load balancer")
    assert result.ok and result.failures == []
    # The load balancer's "<ip>:443" (httpx drops the default port from the URL it shows).
    assert {r["url"] for r in sites.requests} == {"https://203.0.113.7/healthz", "https://203.0.113.7/"}
    assert all(r["verify"] is False for r in sites.requests)  # staging certificates: nothing is verified
    assert all(r["sni"] == r["host"] for r in sites.requests)
    assert lines[0] == "Certificates aren't verified in this check: they are Let's Encrypt staging certificates"
    assert "api.uat.example.com answered 200 on /healthz through the load balancer" in lines
    assert not any("Switchyard" in line for line in lines)


async def test_public_check_names_its_path_and_verifies_by_default(sites, waits):
    planned = [traffic.Route("api.uat.example.com", "api", 8000, "active", "auto", "/healthz"),
               traffic.Route("int.uat.example.com", "api", 8000, "active", "internal", "/")]
    lines: list[str] = []

    async def say(line):
        lines.append(line)

    await traffic.public_check(planned, "203.0.113.7:443", say=say, rounds=1, via="the load balancer")
    by = {r["host"]: r for r in sites.requests}
    assert by["api.uat.example.com"]["verify"] is True and by["int.uat.example.com"]["verify"] is False
    assert "int.uat.example.com uses the load balancer's internal certificate, so it isn't verified" in lines
    # The defaults keep phase 3's texts.
    lines.clear()
    await traffic.public_check(planned[:1], "10.0.0.2", say=say, rounds=1)
    assert lines == ["api.uat.example.com answered 200 on /healthz through Switchyard"]


async def test_public_check_without_an_address_names_the_path(sites):
    lines: list[str] = []

    async def say(line):
        lines.append(line)

    route = traffic.Route("api.uat.example.com", "api", 8000, "active", "auto", "/healthz")
    result = await traffic.public_check([route], "", say=say, via="the load balancer")
    assert result.ok
    assert result.skipped == "Slipway has no address for the load balancer, so the names weren't checked through it"
    assert lines == [result.skipped] and sites.requests == []
    assert (await traffic.public_check([route], "")).skipped == traffic.NO_TRAFFIC_ADDRESS
    assert traffic.no_address("Switchyard") == traffic.NO_TRAFFIC_ADDRESS


# ------------------------------------------------------------------------ who is live


async def test_who_is_live_on_switchyard_with_no_one_and_two_slots(configured):
    fake = configured
    env_id = await _env()
    backend = traffic.BACKENDS["switchyard"]
    assert await backend.who_is_live(await _ctx(env_id, "sync")) == []  # nothing recorded yet

    await _activate(env_id, "blue")
    assert await backend.who_is_live(await _ctx(env_id, "sync")) == ["blue"]

    # Someone points one name at green in Switchyard: the traffic is split between the slots.
    api = fake.hosts_by_domain()["api.uat.example.com"]
    index = [h for h, *_ in APP_ROUTES].index("api.uat.example.com")
    api["upstreams"] = [dict(api["upstreams"][0], host=ADDRESS["green"], port=PORT_BASE["green"] + index)]
    assert await backend.who_is_live(await _ctx(env_id, "sync")) == ["blue", "green"]

    # Only green now: every name moved.
    await _activate(env_id, "green")
    assert await backend.who_is_live(await _ctx(env_id, "sync")) == ["green"]

    # A host that no longer carries the environment's marker doesn't count, nor one pointing elsewhere.
    for host in fake.hosts.values():
        if host["domains"] != ["spaces.uat.example.com"]:
            host["notes"] = "someone else's"
    assert await backend.who_is_live(await _ctx(env_id, "sync")) == []
    assert not switchyard.lock.locked()


async def test_who_is_live_ignores_the_data_servers_names(configured):
    fake = configured
    env_id = await _env()
    await _activate(env_id, "blue")
    spaces = fake.hosts_by_domain()["spaces.uat.example.com"]
    # The server-following name points at the data server; even pointed at green it says nothing of the slots.
    spaces["upstreams"] = [dict(spaces["upstreams"][0], host=ADDRESS["green"], port=PORT_BASE["green"])]
    assert await traffic.BACKENDS["switchyard"].who_is_live(await _ctx(env_id, "sync")) == ["blue"]
