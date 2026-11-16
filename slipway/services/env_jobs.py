"""Jobs of a whole environment (phase 3 §9.5-9.14): activate, publish, discard, remove_slot and teardown.

They are ``Deployment`` rows with ``environment_id`` set and no instance (D9); ``deployer.run_deployment`` hands
them to ``run`` and calls the chain hook afterwards. Each job checks its refusals again in its first step,
``check``, before it changes anything (I5), because the environment may have moved on since it was queued. The
commands they run on the slots' hosts go through the deployer's member sessions (§7.1 Members), so every
command holds that host's lock as any other job's does.

Also here, because they belong with these jobs: what recovery after a restart does to an interrupted one
(``recover``, §9.13), Resolve of an unresolved switch (``resolve``, §9.12) and the rule a retry of an activate
must meet (``retry_refusal``, §9.5 Retry).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, null, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from slipway.db.base import utcnow
from slipway.db.session import session_scope
from slipway.models import (
    Backup,
    DataMode,
    Deployment,
    DeploymentKind,
    DeploymentStatus,
    Environment,
    EnvironmentStatus,
    Instance,
    InstanceStatus,
    Resource,
    User,
)
from slipway.models.environment import SECRETS_LOST
from slipway.services import audit, cloudflare, data, deployer, environments, jobs, ssh, switchyard, traffic
from slipway.services.deployer import DeployError

log = logging.getLogger(__name__)

APP_SLOTS = environments.APP_SLOTS
DATA_SLOT = environments.DATA_SLOT
RESTARTED = "Slipway restarted during the switch"
# Every slot's folder goes in this order (green first, so blue, the one most likely to serve, goes last).
REMOVE_ORDER = ("green", "blue")


class _Nobody:
    """The job's own run stands for no instance: every command goes through a member's session."""

    slot = None
    name = ""


@dataclass
class _EnvRun:
    """An environment-level job while it runs: what it was queued with, its log and steps, and the sessions to
    the members' hosts it opens on demand (``member``)."""

    dep_id: uuid.UUID
    kind: str
    options: dict[str, Any]
    env: Environment
    members: dict[str, Instance]
    owner: Instance | None
    user: User | None
    retry_of: uuid.UUID | None
    label: str
    job: deployer._Job
    sink: deployer.LogSink
    steps: deployer.Steps
    run: deployer._AppRun
    connect: Any
    live: bool = False  # activate: traffic moved and was recorded; nothing after it can fail the job
    switch_ctx: Any = None  # activate: the switch's traffic.SwitchContext once built (what it wrote, for a timeout)

    @property
    def slot(self) -> str | None:
        return self.options.get("slot")

    async def member(self, slot: str) -> deployer._AppRun:
        """A session to ``slot``'s host (its lock taken), opened once per job."""
        m = await self.run.member(slot)
        m.instance = self.members.get(slot, m.instance)
        return m

    async def say(self, line: str) -> None:
        await self.sink.line(line)


Body = Callable[[], Awaitable[tuple[str, str | None]]]


async def _step(er: _EnvRun, key: str, body: Body, *, never_fail: bool = False) -> None:
    """Run one listed step; ``body`` answers ``(status, note)``. A step the job's list doesn't have is skipped.

    A step with a limit in ``environments.ENV_STEP_TIMEOUTS`` (§13) is stopped when it runs past it, as a
    cancellation: the switch's put-back is shielded from it and still runs to its end."""
    if not er.steps.listed(key):
        return
    limit = environments.ENV_STEP_TIMEOUTS.get(key)
    if not limit:
        await deployer._outcome_step(er.run, key, body, never_fail=never_fail)
        return

    async def timed() -> tuple[str, str | None]:
        try:
            async with asyncio.timeout(limit) as cm:
                return await body()
        except TimeoutError:
            if not cm.expired():
                raise
            if er.live:  # the limit came after traffic moved and was recorded: the activation stands
                return "warning", f"It took longer than {_minutes(limit)}, after traffic had moved"
            raise DeployError(await _timed_out(er, key, limit)) from None

    await deployer._outcome_step(er.run, key, timed, never_fail=never_fail)


def _minutes(seconds: float) -> str:
    if seconds >= 60 and seconds % 60 == 0:
        n = int(seconds // 60)
        return f"{n} minute{'s' if n != 1 else ''}"
    return f"{seconds:g} seconds"


async def _timed_out(er: _EnvRun, key: str, limit: float) -> str:
    """The note a step stopped at its time limit fails with; a switch also says where traffic stands."""
    text = f"It took longer than {_minutes(limit)} and was stopped"
    if key != "switch":
        return text
    with contextlib.suppress(Exception):
        async with session_scope() as db:
            env = await db.get(Environment, er.env.id)
            unresolved = environments.unresolved_text(env) if env is not None else None
        if unresolved:
            return f"{text}. {unresolved}"
    applied = getattr(er.switch_ctx, "applied", None)
    if applied is None or not (applied.changes or applied.did_apply):
        # Stopped while it waited for Switchyard's lock or read the plan: nothing was written.
        return f"{text}; Slipway changed nothing"
    return f"{text}; Slipway put back what the switch had written"


async def _env_now(er: _EnvRun) -> tuple[Environment, dict[str, Instance]]:
    """The environment and its members as they are now (another job may have changed them since this began)."""
    async with session_scope() as db:
        env = await db.get(Environment, er.env.id)
        assert env is not None
        mem = await environments.members(db, env)
    er.env, er.members = env, mem
    er.owner = environments.owner_in(env, mem)
    er.job.environment, er.job.members, er.job.owner = env, mem, er.owner
    return env, mem


# --------------------------------------------------------------------------- running a job


async def _begin(deployment_id: uuid.UUID, connect: Any) -> _EnvRun | None:
    """Mark the job running and gather what it needs; None when it isn't a queued environment-level job."""
    async with session_scope() as db:
        dep = await db.get(Deployment, deployment_id)
        if dep is None or dep.status != DeploymentStatus.QUEUED or dep.instance_id is not None:
            return None
        env = await db.get(Environment, dep.environment_id) if dep.environment_id else None
        if env is None:
            dep.status, dep.error = DeploymentStatus.FAILED, "Its environment is gone"
            dep.started_at = dep.finished_at = utcnow()
            return None
        mem = await environments.members(db, env)
        owner = environments.owner_in(env, mem)
        secrets = env.app_secrets
        if secrets is None:
            stored = await db.scalar(select(Environment.app_secrets.is_not(None)).where(Environment.id == env.id))
            secrets = None if stored else {}
        variables = env.env
        if variables is None:
            stored = await db.scalar(select(Environment.env.is_not(None)).where(Environment.id == env.id))
            variables = None if stored else {}
        options = dict(dep.options or {})
        kind = str(dep.kind)
        label = data.job_label(kind, slot=options.get("slot"), back=bool(options.get("back")))
        target = mem.get(options.get("slot")) if options.get("slot") else None
        job = deployer._Job(
            instance=target or owner or _Nobody(), branch=dep.branch, user=dep.triggered_by, env=variables,
            secrets=secrets, steps=list(dep.steps or []), deployment_id=dep.id, kind=kind, options=options,
            environment=env, owner=owner, members=mem,
            settings={str(k): str(v) for k, v in (env.app_settings or {}).items()},
            services=list(env.app_services) if env.app_services is not None else None,
            secrets_version=int(env.secrets_version or 0), connect=connect,
        )
        dep.status = DeploymentStatus.RUNNING
        dep.started_at = utcnow()
        user, retry_of = dep.triggered_by, dep.retry_of_id
    for value in (secrets or {}).values():
        job.hide.add(str(value))
    for value in (variables or {}).values():
        job.hide.add(str(value))
    if owner is not None:
        for value in (owner.live_identity or {}).values():
            job.hide.add(str(value))
    sink = deployer.LogSink(deployment_id, hide=job.hide)
    steps = deployer.Steps(deployment_id, job.steps, sink)
    root = deployer._AppRun(remote=None, instance=_Nobody(), job=job, sink=sink, steps=steps,  # type: ignore[arg-type]
                            paths=deployer.InstancePaths.of("/"))
    return _EnvRun(dep_id=deployment_id, kind=kind, options=options, env=env, members=mem, owner=owner, user=user,
                   retry_of=retry_of, label=label, job=job, sink=sink, steps=steps, run=root, connect=connect)


async def _close(er: _EnvRun) -> None:
    with contextlib.suppress(Exception):
        await er.run.close_members()


async def run(deployment_id: uuid.UUID, *, connect: Any = ssh.open_session, github: Any = None) -> None:
    """Run the environment-level job ``deployment_id`` to its end (the runner holds its keys)."""
    er = await _begin(deployment_id, connect)
    if er is None:
        return
    handler = _HANDLERS.get(er.kind)
    try:
        if handler is None:
            raise DeployError(f"Slipway can't run a {er.kind} job of an environment")
        await handler(er)
    except asyncio.CancelledError:
        await _close(er)
        if er.live:  # traffic already moved and was recorded: the activation stands (as P2 D12)
            await _end_live(er, "Slipway is shutting down")
            raise
        await er.say(f"{er.label} interrupted: Slipway is shutting down")
        await er.steps.close()
        await er.sink.close()
        await deployer._finish(deployment_id, DeploymentStatus.CANCELLED, error="Interrupted", short=True)
        raise
    except Exception as exc:
        await _close(er)
        log.info("Job %s of environment %s failed: %s", deployment_id, er.env.name, er.sink.scrub(str(exc)))
        await er.say(f"{er.label} failed: {exc}")
        await er.steps.close()
        await er.sink.close()
        await deployer._finish(deployment_id, DeploymentStatus.FAILED, error=str(exc) or type(exc).__name__,
                               scrub=er.sink.scrub)
        return
    await _close(er)
    await er.say(f"{er.label} succeeded")
    await er.steps.close()
    await er.sink.close()
    await deployer._finish(deployment_id, DeploymentStatus.SUCCEEDED)


async def _end_live(er: _EnvRun, why: str) -> None:
    """An activate cut off after its switch was recorded still succeeded: the step it was in becomes a warning,
    the ones it never reached are skipped, and starter content it didn't add is left pending (as P2)."""
    er.steps._current = None
    missed = False
    after = False
    for row in er.steps.rows:
        after = after or row.get("key") == "switch"
        if row.get("key") == "switch":
            continue
        if after and row.get("status") in ("running", "failed"):
            row.update(status="warning", note=f"Interrupted: {why}")
        elif after and row.get("status") == "pending":
            row.update(status="skipped", note=f"Not run: {why}")
        missed = missed or (row.get("key") == "seed" and row.get("status") in ("warning", "skipped"))
    await er.say(f"{er.label} cut off after traffic moved ({why}); it still counts as succeeded")
    await er.steps.close()
    await er.sink.close()
    if missed and er.owner is not None:
        with contextlib.suppress(Exception):
            await deployer._save_instance(er.owner, content_pending=True)
    await deployer._finish(er.dep_id, DeploymentStatus.SUCCEEDED, short=True)


# ------------------------------------------------------------------------- shared checks


async def _fence(db: AsyncSession, er: _EnvRun, env: Environment, mem: dict[str, Instance],
                 target: Instance | None) -> str | None:
    """``jobs.job_refusal``'s environment fences, run again at run time, without counting this job as the one
    that is running: deleting, a job whose runner keys meet this one's, an unverified host, the data owner's
    hold or (for an activate) dirty state, and an unresolved switch (§7.5, §8.2, §10.6)."""
    kind = er.kind
    gone = environments.deleting_text(env)
    if gone and not (kind == DeploymentKind.TEARDOWN and env.status == EnvironmentStatus.DELETING):
        return gone
    busy = await jobs.busy_job(db, env, data.env_keys(env.id, kind, er.options), exclude=er.dep_id)
    if busy is not None:
        return environments.busy_text(env, busy)
    if target is not None and kind in (DeploymentKind.ACTIVATE, DeploymentKind.DISCARD, DeploymentKind.REMOVE_SLOT) \
            and not target.host.is_pinned:
        return jobs.UNPINNED.format(host=target.host.name)
    owner = environments.owner_in(env, mem)
    dirty = (owner.data_dirty if owner is not None else None) or {}
    if dirty.get("hold") and kind in jobs.HOLD_REFUSES and owner is not None:
        held = await data.hold_text(db, owner)
        if held:
            return held
    unresolved = environments.unresolved_text(env)
    if kind == DeploymentKind.ACTIVATE and dirty and owner is not None:
        recorded = target is not None and env.active_slot_id == target.id
        if not (unresolved and recorded):
            return environments.dirty_activate_text(env, owner, str(er.slot))
    if unresolved and kind in (DeploymentKind.REMOVE_SLOT, DeploymentKind.DISCARD):
        return unresolved
    return None


def _stays(from_slot: str | None) -> str:
    return f"Traffic stays on {from_slot}" if from_slot else "Nothing was live before, and Slipway moved no traffic"


async def retry_refusal(db: AsyncSession, parent: Deployment) -> str | None:
    """Why a retry of ``parent`` (an environment-level job) can't be queued, or None (§9.5 Retry): an activate
    may be retried only while the slot it moved traffic from is still the active one, or a switch is
    unresolved; otherwise traffic moved since, and a new activate is the honest way."""
    if parent.kind != DeploymentKind.ACTIVATE or parent.environment_id is None:
        return None
    env = await db.get(Environment, parent.environment_id)
    if env is None:
        return None
    mem = await environments.members(db, env)
    if environments.unresolved_text(env):
        return None
    active = environments.active_member(env, mem)
    now = str(active.slot) if active is not None else None
    if ((parent.options or {}).get("from_slot") or None) != now:
        return "Traffic moved since: activate again instead"
    return None


# ------------------------------------------------------------------------------- activate


async def _activate(er: _EnvRun) -> None:
    """Activate (§9.5): ``check, [start_slot], smoke, [dns], switch, [seed]``. Nothing changes before ``smoke``
    passed and, when a record has to be created, ``dns`` succeeded; ``active_slot_id`` is written only once the
    switch's check through Switchyard passed."""
    slot = str(er.slot or "")
    if er.job.secrets is None:
        raise DeployError(SECRETS_LOST.format(env=er.env.name))

    async def check() -> tuple[str, str | None]:
        async with session_scope() as db:
            env = await db.get(Environment, er.env.id)
            assert env is not None
            mem = await environments.members(db, env)
            target = mem.get(slot)
            problem = await _fence(db, er, env, mem, target)
            if problem is None and er.retry_of is not None:
                parent = await db.get(Deployment, er.retry_of)
                problem = await retry_refusal(db, parent) if parent is not None else None
            problem = problem or await environments.activate_problem(db, env, slot, mem)
            ctx = None
            if problem is None and traffic.backend_for(env) is not None:
                ctx = await traffic.context(db, env, "activate", slot=slot)
        if problem:
            raise DeployError(problem)
        await _env_now(er)
        target = er.members[slot]
        if ctx is not None:
            # The switch's plan, read only: a blocker refuses before the slot is started or a record written.
            try:
                plan = await traffic.backend_for(er.env).plan(ctx)
            except (switchyard.SwitchyardError, traffic.TrafficError) as exc:
                raise DeployError(f"Switchyard: {exc}; Slipway changed nothing") from None
            if plan.blockers:
                raise DeployError("; ".join(plan.blockers) + "; Slipway changed nothing")
        if target.status == InstanceStatus.STOPPED and not er.steps.listed("start_slot"):
            at = next(i for i, r in enumerate(er.steps.rows) if r["key"] == "smoke")
            er.steps.rows.insert(at, {"key": "start_slot", "name": f"Start {slot}", "status": "pending"})
            await er.steps._save()
        return "succeeded", None

    async def start_slot() -> tuple[str, str | None]:
        target = er.members[slot]
        if target.status != InstanceStatus.STOPPED:
            return "skipped", f"{slot} is already running"
        m = await er.member(slot)
        await deployer._compose_start(er.run, m)
        return "succeeded", None

    async def smoke() -> tuple[str, str | None]:
        env, mem = await _env_now(er)
        target = mem[slot]
        m = await er.member(slot)
        check_result = await traffic.smoke(m.remote, target, traffic.routes(env, target, er.owner), say=er.say)
        await traffic.save_last_check(target.id, check_result, er.dep_id)
        if not check_result.ok:
            raise DeployError(f"{check_result.message}. Nothing has changed")
        return "succeeded", None

    async def dns() -> tuple[str, str | None]:
        env, mem = await _env_now(er)
        active = environments.active_member(env, mem)
        stays = _stays(str(active.slot) if active is not None else None)
        if not (env.traffic or {}).get("dns"):
            return "skipped", f"{env.name} publishes no DNS records"
        creates = await _dns_creates(env)
        try:
            await traffic.publish_dns(env, er.say, actor=er.user)
        except (cloudflare.CloudflareError, traffic.TrafficError) as exc:
            if creates:
                # Caddy can't get a certificate for a name with no record: switching now would serve errors.
                raise DeployError(f"{exc}. {stays}") from None
            return "warning", f"{exc}; every record was already there, so the switch goes ahead"
        return "succeeded", None

    async def switch() -> tuple[str, str | None]:
        env, mem = await _env_now(er)
        target = mem[slot]
        active = environments.active_member(env, mem)
        from_slot = str(active.slot) if active is not None else None
        back = bool(er.options.get("back"))
        if traffic.backend_for(env) is None:
            await _record_switched(er, target, from_slot, back, None)
            return "succeeded", f"{env.name} doesn't publish its names through Switchyard; {slot} is now its live slot"
        async with session_scope() as db:
            ctx = await traffic.context(db, env, "activate", slot=slot, deployment_id=er.dep_id, say=er.say,
                                        connect=er.connect)
        er.switch_ctx = ctx
        result = await traffic.switch(ctx)  # SwitchRefused / SwitchFailed carry the text the step fails with
        await _record_switched(er, target, ctx.from_slot, back, ctx)
        if result.warnings:
            return "warning", "; ".join(result.warnings)
        return "succeeded", None

    async def seed() -> tuple[str, str | None]:
        async with session_scope() as db:
            env = await db.get(Environment, er.env.id)
            owner = await environments.owner_of(db, env) if env is not None else None
            why = await _seed_skip(db, env, owner)
        if why:
            return "skipped", why
        er.job.owner = owner
        try:
            m = await er.member(slot)
            m.new = await deployer._live_plan(m, write=False)
            return await deployer._seed(m)
        except Exception as exc:
            # The seed didn't run, or didn't finish: the starter content stays pending (§9.5 step 7), so Add
            # starter content can run it again.
            with contextlib.suppress(Exception):
                await deployer._save_instance(owner, content_pending=True)
            return "warning", (f"The starter content wasn't added: {exc}. Add starter content to try again.")

    await _step(er, "check", check)
    await _step(er, "start_slot", start_slot)
    await _step(er, "smoke", smoke)
    await _step(er, "dns", dns)
    await _step(er, "switch", switch)
    await _step(er, "seed", seed, never_fail=True)


async def _dns_creates(env: Environment) -> bool:
    """Whether a name has no usable A record yet (§9.5 step 4), whatever the plan's status for it: one to
    create, and one held up by a conflict or a record Slipway may not use (``traffic._unpublished``). When the
    plan can't be read, any name without a recorded row counts as one."""
    try:
        async with session_scope() as db:
            plan = await traffic.dns_plan(env, db)
        return bool(plan.creates) or bool(plan.meta.get("unpublished"))
    except traffic.DnsRefused as exc:
        if exc.plan.changes:
            return bool(exc.plan.creates) or bool(exc.plan.meta.get("unpublished"))
    except Exception:  # the plan couldn't be read; the rows answer below
        pass
    # The plan couldn't be read (Cloudflare unset or down, no address): go by the recorded rows.
    async with session_scope() as db:
        rows = {r.name for r in await _rows(db, env.id, cloudflare.PROVIDER, cloudflare.KIND)}
    return any(str(h.get("hostname") or "").lower() not in rows for h in env.hostnames or [])


async def _seed_skip(db: AsyncSession, env: Environment | None, owner: Instance | None) -> str | None:
    """Why the first activation adds no starter content (D24), or None: it is added only to data that started
    empty, never to a snapshot's or to data a host already had."""
    if env is None or owner is None:
        return "The environment has no data owner"
    if not owner.seed_content:
        return f"Starter content is off for {env.name}"
    deploys = (await db.scalars(select(Deployment).options(defer(Deployment.log)).where(
        Deployment.instance_id == owner.id, Deployment.kind == DeploymentKind.DEPLOY))).all()
    if any(d.snapshot_id is not None for d in deploys):
        return f"{env.name}'s data came from a snapshot: starter content is only added after an empty start"
    if not any((d.options or {}).get("started_empty") for d in deploys):
        return "The app already had data: starter content is only added after an empty start"
    return None


async def _record_switched(er: _EnvRun, target: Instance, from_slot: str | None, back: bool,
                           ctx: traffic.SwitchContext | None) -> None:
    """Record the switch (``_record_active``) even when the job is cancelled meanwhile: traffic has moved. Once
    it is recorded the activation stands (``er.live``). When it can't be recorded, the switch is unresolved:
    Switchyard sends the names to ``target`` while Slipway still names the old slot."""
    task = asyncio.ensure_future(_record_active(er, target, from_slot, back))
    try:
        await asyncio.shield(task)
    except asyncio.CancelledError:
        await asyncio.wait({task})
        er.live = not task.cancelled() and task.exception() is None
        raise
    except Exception as exc:
        if ctx is not None:
            await traffic._mark_unresolved(ctx, f"Traffic moved to {target.slot}, but Slipway couldn't record it "
                                                f"({exc})")
        raise
    er.live = True


async def _record_active(er: _EnvRun, target: Instance, from_slot: str | None, back: bool) -> None:
    """§9.5 step 6, after the switch's check passed, in one transaction: the active slot, the last switch, no
    unresolved switch, status ``live``, and the audit row."""
    async with session_scope() as db:
        env = await db.get(Environment, er.env.id, with_for_update=True)
        assert env is not None
        env.active_slot_id = target.id
        state = dict(env.traffic_state or {})
        state["last"] = {"deployment_id": str(er.dep_id), "from_slot": from_slot, "to_slot": target.slot,
                         "back": back, "at": utcnow().isoformat()}
        state["unresolved"] = None
        env.traffic_state = state
        if env.status == EnvironmentStatus.NEW:
            env.status = EnvironmentStatus.LIVE
        audit.record(db, "environment.activate", actor=er.user, target=env,
                     summary=f"{er.label}: {env.name}'s traffic moved to {target.slot}"
                             + (f" from {from_slot}" if from_slot else ""),
                     details={"from": from_slot, "to": target.slot, "back": back, "deployment": er.dep_id.hex})
    await er.say(f"{target.slot} now takes {er.env.name}'s traffic")


# -------------------------------------------------------------------------------- publish


async def _publish(er: _EnvRun) -> None:
    """Publish names (§9.11): ``check, [traffic], [dns]``. Each step's blockers fail it with the list before it
    writes anything; it never moves a name to another slot (I6)."""

    async def check() -> tuple[str, str | None]:
        async with session_scope() as db:
            env = await db.get(Environment, er.env.id)
            assert env is not None
            mem = await environments.members(db, env)
            problem = await _fence(db, er, env, mem, None) or await environments.publish_problem(db, env)
        if problem:
            raise DeployError(problem)
        return "succeeded", None

    async def sync() -> tuple[str, str | None]:
        env, _ = await _env_now(er)
        backend = traffic.backend_for(env)
        if backend is None:
            return "skipped", f"{env.name} doesn't publish its names through Switchyard"
        async with session_scope() as db:
            ctx = await traffic.context(db, env, "sync", include_active=True, deployment_id=er.dep_id, say=er.say,
                                        connect=er.connect)
        plan = await backend.plan(ctx)  # reads only: a blocker fails the step before any write
        if plan.blockers:
            raise DeployError("; ".join(plan.blockers) + "; Slipway changed nothing")
        result = await traffic.sync(ctx)
        notes = list(ctx.notes)
        if result.skipped:
            return "skipped", result.skipped
        split = traffic.SPLIT in notes
        if result.warnings or split:
            return "warning", "; ".join([*notes, *result.warnings])
        return "succeeded", "; ".join(notes) or None

    async def dns() -> tuple[str, str | None]:
        env, _ = await _env_now(er)
        if not (env.traffic or {}).get("dns"):
            return "skipped", f"{env.name} publishes no DNS records"
        await traffic.publish_dns(env, er.say, actor=er.user)
        return "succeeded", None

    await _step(er, "check", check)
    await _step(er, "traffic", sync)
    await _step(er, "dns", dns)


# -------------------------------------------------------------------------------- discard


async def _discard(er: _EnvRun) -> None:
    """Discard a failed deploy to the idle slot (§9.14, D17): ``check, stop_slot, smoke, settle``. Nothing is
    restored: the failed slot is stopped and marked stale, the active slot is checked on the data as it is, and
    the owner's dirty state clears."""
    slot = str(er.slot or "")
    if er.job.secrets is None:
        raise DeployError(SECRETS_LOST.format(env=er.env.name))
    facts: dict[str, Any] = {}

    async def check() -> tuple[str, str | None]:
        async with session_scope() as db:
            env = await db.get(Environment, er.env.id)
            assert env is not None
            mem = await environments.members(db, env)
            problem = await _fence(db, er, env, mem, mem.get(slot))
            if problem is None:
                state = await data.discard_state(db, env, slot)
                if not state.available:
                    me = await db.get(Deployment, er.dep_id)
                    # discard_state counts this job as the one running; every other refusal stands.
                    if me is None or state.reason != environments.busy_text(env, me):
                        problem = state.reason or "Nothing to discard"
                facts["failed"] = state.deployment_id
            owner = environments.owner_in(env, mem)
            first = ((owner.data_dirty if owner is not None else None) or {}).get("first") or {}
            backup = await db.get(Backup, data._uuid(first.get("backup_id"))) if first.get("backup_id") else None
            facts["time"] = deployer._utc_text(backup.taken_at) if backup is not None else "before the failed deploy"
        if problem:
            raise DeployError(problem)
        env, mem = await _env_now(er)
        active = environments.active_member(env, mem)
        assert active is not None and er.owner is not None
        facts["active"] = active
        # The data as the failed deploy left it must be something the active slot can run (expand/contract
        # says it is; the active release's own accepts has the last word), before anything stops.
        owner_run = await er.member(environments.owner_slot(env))
        side = await deployer._live_plan(owner_run, write=False)
        job_dir = data.job_dir(owner_run.paths.base, er.dep_id)
        await owner_run.remote.run(f"umask 077 && mkdir -p -- {deployer.q(job_dir)}", timeout=60)
        try:
            revision = await deployer._read_revision(owner_run, side, job_dir)
        finally:
            with contextlib.suppress(Exception):
                await owner_run.remote.run(f"rm -f -- {deployer.q(job_dir + '/revision.out')}; "
                                           f"rmdir -- {deployer.q(job_dir)} 2>/dev/null; true", check=False, timeout=60)
        if not revision:
            return "succeeded", "The database's revision couldn't be read, so it wasn't checked against " \
                                f"{active.slot}'s release"
        active_run = await er.member(str(active.slot))
        active_side = await deployer._live_plan(active_run, write=False)
        if "accepts" not in active_side.plan.commands:
            return "succeeded", f"{active.slot}'s slipway.yml has no accepts command, so the revision wasn't checked"
        code, _ = await deployer._accepts(active_run, active_side, revision)
        short = data.revision_short(revision) or "?"
        if code == 3:
            raise DeployError(f"{active.slot} ({active_side.sha7}) can't run the database at revision {short} that "
                              f"{slot}'s deploy left: roll back to the backup from {facts['time']} instead")
        if code != 0:
            raise DeployError(f"The revision check of {active.slot} failed (commands.accepts exited {code}). "
                              "Nothing was changed")
        await er.say(f"{active.slot} ({active_side.sha7}) can run the data at revision {short}")
        return "succeeded", None

    async def stop_slot() -> tuple[str, str | None]:
        m = await er.member(slot)
        command = deployer._app_projects_command(m.instance, "stop")
        await er.say(f"$ {command}")
        await m.remote.run(command, on_line=er.say, scrub=er.sink.scrub, timeout=600)
        d8 = str(facts.get("failed") or "")[:8]
        await deployer._save_instance(m.instance, status=InstanceStatus.STOPPED)
        await deployer._mark_stale(m.instance, f"Its deploy {d8} failed and was discarded", er.job)
        await er.say(f"Stopped {slot} on {m.instance.host.name}")
        return "succeeded", None

    async def smoke() -> tuple[str, str | None]:
        env, mem = await _env_now(er)
        active = mem[str(facts["active"].slot)]
        m = await er.member(str(active.slot))
        result = await traffic.smoke(m.remote, active, traffic.routes(env, active, er.owner), say=er.say)
        await traffic.save_last_check(active.id, result, er.dep_id)
        if not result.ok:
            raise DeployError(f"{active.slot} fails its check on the current data too ({result.message}): roll back "
                              f"to the backup from {facts['time']} instead")
        return "succeeded", None

    async def settle() -> tuple[str, str | None]:
        active = facts["active"]
        async with session_scope() as db:
            env = await db.get(Environment, er.env.id)
            owner = await environments.owner_of(db, env) if env is not None else None
            assert env is not None and owner is not None
            first = ((owner.data_dirty or {}).get("first") or {})
            if str(first.get("deployment_id") or "") != str(facts.get("failed") or ""):
                raise DeployError(f"{env.name}'s data state changed while this job ran; look at the environment page")
            await db.execute(update(Instance).where(Instance.id == owner.id).values(data_dirty=null()))
            audit.record(db, "environment.discard", actor=er.user, target=env,
                         summary=f"Discarded {slot}'s failed deploy on {env.name}; {active.slot} keeps serving",
                         details={"slot": slot, "deployment": facts.get("failed"), "checked": active.slot})
        return "succeeded", None

    await _step(er, "check", check)
    await _step(er, "stop_slot", stop_slot)
    await _step(er, "smoke", smoke)
    await _step(er, "settle", settle)


# ---------------------------------------------------------------------------- remove a slot


async def _remove_instance(er: _EnvRun, instance_id: uuid.UUID, *, action: str) -> tuple[bool, str | None]:
    """``deployer.destroy`` of a member (its containers and folder; volumes stay, backups move to
    ``.slipway-kept``), then its row in a transaction of its own; its deployments go with it. ``(removed,
    warning)``; ``removed`` is False when the row was already gone. Leftover containers raise and keep the row."""
    async with session_scope() as db:
        inst = await db.get(Instance, instance_id)
        if inst is None:
            return False, None
        started = inst.status != InstanceStatus.CREATED or await db.scalar(
            select(Deployment.id).where(Deployment.instance_id == inst.id, Deployment.started_at.is_not(None))
            .limit(1)) is not None
    warning: str | None = None
    report: dict[str, Any] = {}
    if started:
        await er.say(f"Removing {inst.name}'s containers and folder from {inst.host.name}; its volumes stay")
        warning = await deployer.destroy(inst, connect=er.connect, report=report)
        if warning:
            await er.say(warning)
    async with session_scope() as db:
        env = await db.get(Environment, er.env.id, with_for_update=True)
        await db.execute(delete(Instance).where(Instance.id == instance_id))
        if env is not None:
            state = dict(env.traffic_state or {})
            if (state.get("last_slot_deploy") or {}).get("slot") == inst.slot:
                state["last_slot_deploy"] = None
                env.traffic_state = state
        details: dict[str, Any] = {"slot": inst.slot, "host": inst.host.name}
        if warning:
            details["warning"] = warning
        if report.get("backups"):
            details.update(kept_backups=report["backups"], kept_backups_folder=report.get("kept_backups"))
        audit.record(db, action, actor=er.user, target=env if action.startswith("environment.") else inst,
                     summary=f"Removed {inst.name} from {inst.host.name}" + (f". {warning}" if warning else ""),
                     details=details)
    await er.say(f"Removed {inst.name}")
    return True, warning


async def _remove_slot(er: _EnvRun) -> None:
    """Remove a slot (§9.9): ``check, slot``. The data server and its data aren't touched."""
    slot = str(er.slot or "")

    async def check() -> tuple[str, str | None]:
        async with session_scope() as db:
            env = await db.get(Environment, er.env.id)
            assert env is not None
            mem = await environments.members(db, env)
            if slot in APP_SLOTS and slot not in mem and er.retry_of is not None:
                return "succeeded", f"{slot} was already removed"
            problem = await _fence(db, er, env, mem, mem.get(slot)) \
                or await environments.remove_slot_problem(db, env, slot, mem)
        if problem:
            raise DeployError(problem)
        return "succeeded", None

    async def remove() -> tuple[str, str | None]:
        env, mem = await _env_now(er)
        target = mem.get(slot)
        if target is None:
            return "succeeded", "Already removed"
        host = target.host.name
        _, warning = await _remove_instance(er, target.id, action="environment.slot_remove")
        notes = [warning] if warning else []
        if env.data_mode == DataMode.SERVER:
            notes.append(f"{env.name}'s data server still lets {host} in: update it to stop that")
        return "succeeded", " ".join(notes) or None

    await _step(er, "check", check)
    await _step(er, "slot", remove)


# ----------------------------------------------------------------------------- teardown


async def _rows(db: AsyncSession, env_id: uuid.UUID, provider: str | None = None,
                kind: str | None = None) -> list[Resource]:
    stmt = select(Resource).where(Resource.environment_id == env_id)
    if provider is not None:
        stmt = stmt.where(Resource.provider == provider, Resource.kind == kind)
    return list((await db.scalars(stmt.order_by(Resource.provider, Resource.name))).all())


async def _teardown(er: _EnvRun) -> None:
    """Delete the environment (§9.10): ``check, unroute, undns, slots, data_server, forget``. Every step can run
    again: a retry skips what is already gone. Volumes and backups stay on the data host; claimed DNS records and
    whatever Slipway didn't make stay where they are."""
    forget_traffic = bool(er.options.get("forget_traffic"))

    async def check() -> tuple[str, str | None]:
        async with session_scope() as db:
            env = await db.get(Environment, er.env.id)
            assert env is not None
            mem = await environments.members(db, env)
            problem = await _fence(db, er, env, mem, None)
            if problem is None and env.status != EnvironmentStatus.DELETING:
                problem = f"{env.name} isn't being deleted: use Delete on the environment page"
        if problem:
            raise DeployError(problem)
        return "succeeded", None

    async def unroute() -> tuple[str, str | None]:
        env, _ = await _env_now(er)
        async with session_scope() as db:
            rows = await _rows(db, env.id, traffic.PROVIDER, traffic.KIND)
            if not rows and (env.traffic or {}).get("switch", "none") == "none":
                return "skipped", f"{env.name} has no Switchyard hosts"
            ctx = await traffic.context(db, env, "remove", deployment_id=er.dep_id, say=er.say, connect=er.connect)
        if not rows:
            return "succeeded", "Slipway records no Switchyard host for it"
        try:
            plan = await traffic.remove(ctx)
        except (switchyard.SwitchyardError, traffic.TrafficError) as exc:
            if not forget_traffic:
                raise DeployError(f"Switchyard: {exc}. Retry, or retry forgetting the Switchyard hosts and DNS records "
                                  "to leave them for you to delete there") from None
            n = await traffic.forget_all(env.id, traffic.PROVIDER, traffic.KIND, actor=er.user)
            return "warning", (f"Switchyard: {exc}. Slipway forgot its {n} host(s) there: delete them in Switchyard "
                               "if they are still there")
        if plan.warnings:
            return "warning", "; ".join(plan.warnings)
        return "succeeded", None

    async def undns() -> tuple[str, str | None]:
        env, _ = await _env_now(er)
        async with session_scope() as db:
            rows = await _rows(db, env.id, cloudflare.PROVIDER, cloudflare.KIND)
        if not rows:
            return "skipped", f"{env.name} has no DNS records Slipway keeps"
        try:
            await traffic.remove_dns(env, er.say, actor=er.user)
        except (cloudflare.CloudflareError, traffic.TrafficError) as exc:
            if not forget_traffic:
                raise DeployError(f"{exc}. Retry, or retry forgetting the Switchyard hosts and DNS records to leave "
                                  "them for you to delete in Cloudflare") from None
            n = await traffic.forget_all(env.id, cloudflare.PROVIDER, cloudflare.KIND, actor=er.user)
            return "warning", f"{exc}. Slipway forgot its {n} record(s): delete them in Cloudflare if they are still there"
        return "succeeded", None

    async def slots() -> tuple[str, str | None]:
        _, mem = await _env_now(er)
        notes: list[str] = []
        removed = 0
        for slot in REMOVE_ORDER:
            inst = mem.get(slot)
            if inst is None:
                continue
            done, warning = await _remove_instance(er, inst.id, action="instance.delete")
            removed += int(done)
            if warning:
                notes.append(warning)
        if not removed:
            return "succeeded", "Already removed"
        return "succeeded", " ".join(notes) or None

    async def data_server() -> tuple[str, str | None]:
        env, mem = await _env_now(er)
        inst = mem.get(DATA_SLOT)
        if inst is None:
            return ("skipped", f"{env.name} keeps its data in its slot") if env.data_mode == DataMode.SLOT \
                else ("succeeded", "Already removed")
        _, warning = await _remove_instance(er, inst.id, action="instance.delete")
        return "succeeded", warning

    async def forget() -> tuple[str, str | None]:
        async with session_scope() as db:
            env = await db.get(Environment, er.env.id, with_for_update=True)
            assert env is not None
            rows = await _rows(db, env.id)
            if rows:
                listed = ", ".join(f"{r.provider} {r.kind.replace('_', ' ')} {r.name}" for r in rows[:10])
                raise DeployError(f"Slipway still records {len(rows)} object(s) of {env.name}: {listed}. Retry, or "
                                  "retry forgetting the Switchyard hosts and DNS records")
            left = await db.scalar(select(Instance.name).where(Instance.environment_id == env.id).limit(1))
            if left is not None:
                raise DeployError(f"{left} is still part of {env.name}; retry")
            env.status = EnvironmentStatus.DELETED
            env.deleted_at = utcnow()
            env.deleted_by_id = er.user.id if er.user is not None else None
            env.active_slot_id = None
            env.notice = None
            audit.record(db, "environment.delete", actor=er.user, target=env, summary=f"Deleted environment {env.name}",
                         details={"snapshot": er.options.get("snapshot"), "forget_traffic": forget_traffic})
        return "succeeded", None

    await _step(er, "check", check)
    await _step(er, "unroute", unroute)
    await _step(er, "undns", undns)
    await _step(er, "slots", slots)
    await _step(er, "data_server", data_server)
    await _step(er, "forget", forget)


_HANDLERS: dict[str, Callable[[_EnvRun], Awaitable[None]]] = {
    DeploymentKind.ACTIVATE: _activate,
    DeploymentKind.PUBLISH: _publish,
    DeploymentKind.DISCARD: _discard,
    DeploymentKind.REMOVE_SLOT: _remove_slot,
    DeploymentKind.TEARDOWN: _teardown,
}


# ----------------------------------------------------------------------------- recovery (§9.13)


def _switch_began(dep: Deployment) -> bool:
    """An activate whose ``switch`` step had begun, or whose switch record lists a write."""
    record = (dep.options or {}).get("switch") or {}
    if any(record.get(k) for k in ("changed", "created", "deleted")):
        return True
    row = next((r for r in dep.steps or [] if r.get("key") == "switch"), None)
    return bool(row and row.get("started_at"))


async def recover(db: AsyncSession, dep: Deployment) -> None:
    """What an environment-level job interrupted by a restart leaves (``recover_interrupted`` has marked it
    failed in ``db`` already; this runs in the same transaction).

    * An activate that was switching: traffic may be split, so the switch is unresolved (Resolve or another
      activate settles it). One whose switch was already recorded as the active slot did move traffic and
      succeeded; starter content it didn't add is left pending.
    * A teardown: the environment stays ``deleting``; only its retry runs.
    * Publish, discard, remove_slot: nothing beyond the failed status (discard writes the owner's dirty state
      last, in ``settle``).
    """
    if dep.instance_id is not None or dep.environment_id is None or dep.kind != DeploymentKind.ACTIVATE:
        return
    env = await db.get(Environment, dep.environment_id, with_for_update=True)
    if env is None or not _switch_began(dep):
        return
    state = dict(env.traffic_state or {})
    last = state.get("last") or {}
    if data._uuid(last.get("deployment_id")) == dep.id:
        # The switch passed its check and was recorded: the activation stands.
        rows = []
        missed = False
        for row in dep.steps or []:
            row = dict(row)
            if row.get("key") == "seed" and row.get("status") in ("pending", "running", "failed"):
                row.update(status="warning" if row.get("status") != "pending" else "skipped",
                           note="Interrupted by a Slipway restart")
                missed = True
            elif row.get("key") == "switch" and row.get("status") == "failed":
                row.update(status="succeeded", note=None)
            rows.append(row)
        dep.steps, dep.status, dep.error = rows, DeploymentStatus.SUCCEEDED, None
        if missed:
            owner = await environments.owner_of(db, env)
            if owner is not None:
                owner.content_pending = True
        return
    record = (dep.options or {}).get("switch") or {}
    state["unresolved"] = {"deployment_id": str(dep.id), "from_slot": record.get("from_slot"),
                           "to_slot": record.get("to_slot") or (dep.options or {}).get("slot"),
                           "message": RESTARTED, "at": utcnow().isoformat()}
    env.traffic_state = state
    # What the cut-off switch wrote may still be staged in Switchyard: no other apply may take it live (I6).
    await switchyard.hold_in(db, str(env.id))
    audit.record(db, "environment.unresolved", target=env, summary=f"Traffic of {env.name} may be split",
                 details={"slot": state["unresolved"]["to_slot"], "message": RESTARTED})


# ------------------------------------------------------------------------------- Resolve (§9.12)


class ResolveRefused(Exception):
    """Resolve couldn't tell which slot takes the traffic; the HTTP status and the text."""

    def __init__(self, status: int, text: str) -> None:
        super().__init__(text)
        self.status, self.text = status, text


async def resolve(env_id: uuid.UUID, *, actor: User | None = None, request: Any = None) -> str:
    """Settle an unresolved switch by reading Switchyard (§9.12): when every active-following host the
    environment owns sends traffic to one app slot, that slot becomes the active one and the switch is
    resolved (audit ``environment.resolve``). Returns the slot. Raises ResolveRefused (409) otherwise,
    ``deployer.RunnerBusy`` while a job holds the environment's keys, and SwitchyardError when Switchyard
    can't be read. The typed confirmation is the caller's."""
    async with deployer.runner.exclusive(data.env_keys(env_id, None)):
        async with session_scope() as db:
            env = await db.get(Environment, env_id)
            if env is None or env.is_deleted:
                raise ResolveRefused(404, "No such environment")
            if environments.unresolved_text(env) is None:
                raise ResolveRefused(409, f"Traffic of {env.name} isn't split: there is nothing to resolve")
            mem = await environments.members(db, env)
            owner = environments.owner_in(env, mem)
            config = await switchyard.load_config(db)
            rows = await _rows(db, env.id, traffic.PROVIDER, traffic.KIND)
        if config is None:
            raise ResolveRefused(409, environments.SET_UP_SWITCHYARD)
        async with switchyard.SwitchyardClient(config) as sy:
            preview = await sy.preview()
            hosts = await sy.list_hosts()
        why = switchyard.blocker(preview, 0)
        if why:
            raise ResolveRefused(409, f"Switchyard: {why}, so what it serves may not be what its hosts say. Settle "
                                      "that in Switchyard first")
        marker = switchyard.Owner.of(env)
        by_id = {str(h.get("id")): h for h in hosts}
        apps = environments.app_members(mem)
        where: dict[str, str | None] = {}
        for row in rows:
            if traffic._row_follows(row, env) != traffic.ACTIVE:
                continue
            host = by_id.get(row.provider_id)
            if host is None or not switchyard.owned_by(host, marker):
                where[row.name] = None
                continue
            upstream = traffic._upstream_of(host)
            found = None
            for slot in apps:
                route = next((r for r in traffic.routes(env, slot, owner) if r.hostname == row.name), None)
                tgt = traffic.target(route, slot) if route is not None else None
                if tgt is not None and not tgt.problem and tgt.upstream == upstream:
                    found = str(slot.slot)
            where[row.name] = found
        if not where:
            raise ResolveRefused(409, f"Switchyard has no host of {env.name}'s that follows the active slot: activate "
                                      "one of them")
        slots = set(where.values())
        if len(slots) != 1 or None in slots:
            parts = [f"{name} to {slot or 'neither slot'}" for name, slot in sorted(where.items())]
            raise ResolveRefused(409, f"Switchyard sends {' and '.join(parts)}: activate one of them")
        chosen = slots.pop()
        assert chosen is not None
        # Every name the chosen slot serves must reach it, not only those Slipway still records: a host the
        # failed switch deleted (its row went with it) and couldn't make again leaves its name with none.
        missing = []
        for route in traffic.routes(env, mem[chosen], owner):
            if route.follows != traffic.ACTIVE:
                continue
            tgt = traffic.target(route, mem[chosen])
            host = next((h for h in hosts if route.hostname in (h.get("domains") or [])
                         and switchyard.owned_by(h, marker)), None)
            if tgt.problem or host is None or traffic._upstream_of(host) != tgt.upstream:
                missing.append(route.hostname)
        if missing:
            raise ResolveRefused(409, f"Switchyard has no host of {env.name}'s sending {', '.join(missing)} to "
                                      f"{chosen}: activate {chosen} to put {'them' if len(missing) > 1 else 'it'} "
                                      "back")
        async with session_scope() as db:
            env = await db.get(Environment, env_id, with_for_update=True)
            assert env is not None
            state = dict(env.traffic_state or {})
            message = (state.get("unresolved") or {}).get("message")
            state["unresolved"] = None
            env.traffic_state = state
            env.active_slot_id = mem[chosen].id
            if env.status == EnvironmentStatus.NEW:
                env.status = EnvironmentStatus.LIVE
            audit.record(db, "environment.resolve", actor=actor, target=env, request=request,
                         summary=f"Resolved {env.name}'s traffic: {chosen} takes it",
                         details={"slot": chosen, "message": message})
        async with switchyard.lock:
            await switchyard.release_edits(str(env_id))
        return chosen
