"""The ``do_lb`` traffic backend: a DigitalOcean environment's load balancer (phase 4 §11.6, D10, D11, D28).

A DigitalOcean environment's names all resolve to its load balancer's IP (``traffic.dns.address``, written by
the ``edge`` step), so DNS never moves on a switch. What moves is the load balancer's target list,
``droplet_ids``: the live slot's droplet, and nothing else.

* **Activate** (and Switch back) joins the new slot's droplet, checks its health over its own SSH session,
  waits the load balancer's settle time, checks the names through the load balancer, drops the old droplet,
  waits again and proves the switch by reading the load balancer back. The old droplet serves until the new
  one has answered through the real path, so there is no gap.
* **Deactivate** empties the targets and proves they are empty. The names then answer 503 by design, so
  its check is a read of the targets, never the public check.
* **Sync** writes nothing of its own. Its ``repair`` puts the recorded active slot's current droplet back on
  the load balancer when the load balancer lost it (a rebuilt droplet, a remade load balancer). It never adds
  another slot's droplet, so traffic never moves between slots (P3 I6).

The load balancer is made with no targets (D11): only this backend writes ``droplet_ids``. Every write is a
full-body ``PUT`` made from the live body (``do_rules.lb_update_body``), sent only while the load balancer is
``active`` (DigitalOcean refuses a PUT mid-change). Plans only read.

Importing this module registers the backend (``traffic.register``).
"""

from __future__ import annotations

import asyncio
import dataclasses
import math
import re
import uuid
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, ClassVar

from sqlalchemy.ext.asyncio import AsyncSession

from slipway.db.session import session_scope
from slipway.models import Environment, Host, ProviderAccount, Resource
from slipway.services import digitalocean, do_rules, environments, provider_accounts, resources, ssh, traffic
from slipway.services.digitalocean import DigitalOceanClient, DigitalOceanError
from slipway.services.traffic import (
    Applied,
    Change,
    CheckResult,
    Plan,
    PutBack,
    SwitchContext,
    SwitchFailed,
    SyncResult,
)

PROVIDER = "digitalocean"
LB_KIND, DROPLET_KIND, CERT_KIND = "load_balancer", "droplet", "certificate"

# Waits (seconds). The load balancer applies each PUT before it takes another (SD/do_provision.py:1162-1168).
ACTIVE_WAIT = 180
HEALTH_EVERY = 10  # the slot's own health check over SSH: every 10 s for up to 5 minutes
HEALTH_TRIES = 30
HEALTH_COMMAND_TIMEOUT = 30
HEALTH_HOST = "slipway-health.invalid"  # a Host outside the app's names reaches its health route
VERIFY_ROUNDS = traffic.CHECK_ROUNDS
SYNC_ROUNDS = 1

LABEL = "DigitalOcean"
VIA = "the load balancer"
NO_LB = "This environment has no load balancer yet: deploy it first"
LB_BUSY = "The load balancer is applying a change; try again in a minute"
GOES_WITH_CLOUD = "The load balancer goes with the DigitalOcean objects"

# Test seam: the settle time and the health check's waits.
sleep: Callable[[float], Awaitable[None]] = asyncio.sleep

# One writer per environment's load balancer (an environment has one). The certificate job's HTTPS rule
# PUT takes the same lock (``lock_for``); the environment's runner key already serialises them.
_locks: dict[uuid.UUID, asyncio.Lock] = {}


def lock_for(env_id: uuid.UUID) -> asyncio.Lock:
    """The lock every write of this environment's load balancer holds."""
    return _locks.setdefault(env_id, asyncio.Lock())


# ------------------------------------------------------------------------ reading


@dataclass
class _State:
    """What Slipway recorded for the environment: its account, load balancer, droplets and certificates."""

    env: Environment
    account: ProviderAccount | None
    lb: Resource | None
    droplets: dict[str, Resource] = field(default_factory=dict)  # slot -> its droplet row
    slot_of: dict[int, str] = field(default_factory=dict)  # recorded droplet id -> slot
    certs: dict[str, Resource] = field(default_factory=dict)  # certificate id -> row
    hosts: dict[str, Host] = field(default_factory=dict)  # slot -> its host

    @property
    def token(self) -> str | None:
        if self.account is None or self.account.is_removed:
            return None
        return self.account.secret or None


def _droplet_id(row: Resource) -> int | None:
    try:
        return int(row.provider_id)
    except (TypeError, ValueError):
        return None


async def _read_state(db: AsyncSession, env_id: uuid.UUID) -> _State:
    env = await db.get(Environment, env_id)
    if env is None:
        raise traffic.TrafficError("The environment is gone")
    account = await db.get(ProviderAccount, env.provider_account_id) if env.provider_account_id else None
    lbs = await resources.owned(db, env.id, PROVIDER, LB_KIND)
    mem = await environments.members(db, env)
    slot_by_instance = {inst.id: slot for slot, inst in mem.items()}
    state = _State(env=env, account=account, lb=lbs[0] if lbs else None)
    for row in await resources.owned(db, env.id, PROVIDER, DROPLET_KIND):
        slot = (row.details or {}).get("slot") or slot_by_instance.get(row.instance_id)
        droplet_id = _droplet_id(row)
        if not slot or droplet_id is None:
            continue
        state.droplets[str(slot)] = row
        state.slot_of[droplet_id] = str(slot)
    for row in await resources.owned(db, env.id, PROVIDER, CERT_KIND):
        state.certs[row.provider_id] = row
    for slot, inst in mem.items():
        if inst.host_id is not None:
            host = await db.get(Host, inst.host_id)
            if host is not None:
                state.hosts[slot] = host
    return state


async def _state(env_id: uuid.UUID) -> _State:
    async with session_scope() as db:
        return await _read_state(db, env_id)


def _client(state: _State) -> DigitalOceanClient:
    token = state.token
    if token is None:
        raise traffic.TrafficError(_no_token(state))
    return DigitalOceanClient(token)


def _no_token(state: _State) -> str:
    name = state.account.name if state.account is not None else "Its DigitalOcean account"
    if state.account is not None and state.account.is_removed:
        return f"{name} was removed, so Slipway can't reach {state.env.name}'s load balancer"
    return f"{name} has no API token: set it in Settings → Integrations"


def _ids(lb: dict[str, Any] | None) -> list[int]:
    return do_rules.lb_targets(lb or {})


def _describe(ids: Iterable[int], slot_of: dict[int, str]) -> str:
    """``blue (3001)``, ``blue (3001) and green (3002)``, or ``no droplet``."""
    parts = [f"{slot_of[i]} ({i})" if i in slot_of else f"droplet {i}" for i in ids]
    return " and ".join(parts) if parts else "no droplet"


def _ids_text(ids: Iterable[int]) -> str:
    ids = list(ids)
    return ", ".join(str(i) for i in ids) if ids else "none"


def _covers(names: Iterable[str], hostname: str) -> bool:
    for name in names:
        name = str(name).lower()
        if name == hostname:
            return True
        if name.startswith("*.") and "." in hostname and hostname.split(".", 1)[1] == name[2:]:
            return True
    return False


def _edge(state: _State, live: dict[str, Any]) -> tuple[int, str]:
    """The port and health path the load balancer checks: the frozen ``cloud.edge``, else its own check."""
    edge = (state.env.cloud or {}).get("edge") or {}
    check = live.get("health_check") or {}
    port = int(edge.get("port") or check.get("port") or 80)
    path = str(edge.get("health") or check.get("path") or "/")
    return port, path


async def _wait_active(do: DigitalOceanClient, lb_id: str, name: str) -> dict[str, Any]:
    return await digitalocean.poll(lambda: do.load_balancer(lb_id), lambda lb: lb.get("status") == "active",
                                   ACTIVE_WAIT, f"Load balancer {name}")


def _lb_routes(ctx: SwitchContext) -> list[traffic.Route]:
    """The routes as the public check through the load balancer asks them: HTTPS with the certificate verified.

    The load balancer's listener is HTTPS on 443 with a certificate Slipway issued, so a route's Switchyard
    TLS mode (``env.route_tls``, Switchyard's default) doesn't apply: ``off`` would send plain HTTP to 443 and
    ``internal`` would skip the certificate check. Staging certificates are the one exception, through
    ``insecure``.
    """
    return [dataclasses.replace(r, tls_mode="auto") for r in ctx.routes]


def _put_back_worst() -> float:
    """How long ``traffic.switch`` waits for a put-back: two waits for ``active`` around a PUT, each DigitalOcean
    request (the waits' last reads and the PUT) at its own timeout with one 429 retry, and a minute for the
    database. A DigitalOcean request can take longer than that (``_call`` retries a 502 and a 429 again), so
    ``put_back_locked`` ends itself within ``_put_back_budget`` of it: the switch never stops waiting before the
    put-back has ended."""
    request = 2 * digitalocean.TIMEOUT + digitalocean.MAX_RETRY_AFTER
    return 2 * ACTIVE_WAIT + 3 * request + 60


def _put_back_budget() -> float:
    """What ``put_back_locked`` gives the load balancer's calls: the switch's wait less a margin (30 s, or a tenth
    of a shorter wait) for writing what it couldn't do."""
    wait = _put_back_worst()
    return wait - min(30.0, wait / 10)


# ------------------------------------------------------------------------ backend


class DoLbBackend:
    """Point a DigitalOcean environment's load balancer at a slot's droplet (§11.6).

    ``plan`` and ``apply`` expect the caller (``traffic.switch``) to hold ``lock(ctx)``; ``put_back``,
    ``repair`` and ``remove`` take it themselves; ``verify`` and ``who_is_live`` hold no lock.
    """

    name: ClassVar[str] = "do_lb"
    label: ClassVar[str] = LABEL
    via: ClassVar[str] = VIA
    errors: ClassVar[tuple[type[Exception], ...]] = (DigitalOceanError,)

    @property
    def put_back_timeout(self) -> float:
        """How long ``traffic.switch`` waits for the put-back: longer than P3's 120 s, since it can wait for the
        load balancer to be ``active`` twice (3 minutes each)."""
        return _put_back_worst()

    def lock(self, ctx: SwitchContext) -> asyncio.Lock:
        return lock_for(ctx.env.id)

    async def configured(self, db: AsyncSession) -> str | None:
        """Nothing install-wide: each environment's account and team are checked by its plan."""
        return None

    # -- plan

    async def plan(self, ctx: SwitchContext) -> Plan:
        """Reads only. Activate: ``previous`` -> the target slot's droplet; Deactivate: ``previous`` -> none.
        Sync: nothing of its own (``repair`` does the load balancer's part after it)."""
        if ctx.mode == "sync":
            notes = list(ctx.notes)
            if ctx.to_slot is not None and traffic.ACTIVE in ctx.scope:
                notes.append(f"Slipway checks that the load balancer sends traffic to {ctx.to_slot.slot}'s droplet "
                             "after the sync")
            return Plan(self.name, notes=notes)
        if ctx.mode == "remove":
            return Plan(self.name, notes=[GOES_WITH_CLOUD])
        if ctx.mode == "activate":
            if ctx.to_slot is None:
                raise traffic.TrafficError("Only an app slot can take traffic")
            return await self._plan(ctx, str(ctx.to_slot.slot))
        if ctx.mode == "deactivate":
            return await self._plan(ctx, None)
        raise ValueError(f"unknown traffic mode {ctx.mode!r}")

    async def _plan(self, ctx: SwitchContext, slot: str | None, *, repair: bool = False) -> Plan:
        """The load balancer's change for ``slot`` (None: take every droplet off), or why it can't be made."""
        plan = Plan(self.name, notes=list(ctx.notes))
        state = await _state(ctx.env.id)
        env = state.env
        if state.token is None:
            plan.blockers.append(_no_token(state))
            return plan
        if state.lb is None:
            plan.blockers.append(NO_LB)
            return plan
        lb_name = do_rules.lb_name(env.name)
        async with _client(state) as do:
            team = await self._team_problem(do, state)
            if team:
                plan.blockers.append(team)
                return plan
            live = await do.load_balancer(state.lb.provider_id)
            if live is None:
                plan.blockers.append(f"The load balancer {state.lb.name} is gone: deploy again to make it")
                return plan
            if live.get("name") != state.lb.name:
                plan.blockers.append(f"The load balancer Slipway made for {env.name} is no longer named "
                                     f"{state.lb.name} (it is {live.get('name')} now): Slipway changed nothing")
                return plan
            if live.get("status") != "active":
                plan.blockers.append(LB_BUSY)
            previous: list[int] = []
            for droplet_id in _ids(live):
                if droplet_id in state.slot_of:
                    if await do.droplet(droplet_id) is not None:
                        previous.append(droplet_id)
                    continue
                if await do.droplet(droplet_id) is not None:
                    plan.blockers.append(f"The load balancer sends traffic to droplet {droplet_id}, which isn't "
                                         f"{env.name}'s: Slipway changed nothing")
            new: int | None = None
            if slot is not None:
                new = await self._target_problem(do, state, slot, plan)
                cert_id = do_rules.https_certificate(live)
                cert = state.certs.get(cert_id or "")
                if cert is None:
                    plan.blockers.append(f"The load balancer serves a certificate Slipway didn't record for "
                                         f"{env.name}: Renew the certificate first")
                else:
                    names = (cert.details or {}).get("dns_names")
                    if names is None:
                        names = ((await do.certificate(cert.provider_id)) or {}).get("dns_names") or []
                    missing = [r.hostname for r in ctx.routes if not _covers(names, r.hostname)]
                    if missing:
                        plan.blockers.append(f"The certificate doesn't cover {', '.join(missing)}: Renew the "
                                             "certificate first")
                if repair and new is not None:
                    others = [i for i in previous if i != new]
                    if others:
                        plan.blockers.append(f"The load balancer sends traffic to {_describe(others, state.slot_of)}, "
                                             f"but {slot} is the live slot: activate one of them")
        after = [new] if new is not None else []
        action = "none" if sorted(previous) == sorted(after) else "update"
        was = _describe(previous, state.slot_of)
        if slot is None:
            summary = f"{lb_name} → no droplet, was {was}"
        else:
            summary = f"{lb_name} → {slot} (droplet {new if new is not None else '?'}), was {was}"
        plan.changes.append(Change(lb_name, action, state.lb.provider_id, state.lb.id,
                                   before={"droplet_ids": previous}, after={"droplet_ids": after}, summary=summary))
        port, health = _edge(state, live)
        ip = str(live.get("ip") or (env.cloud or {}).get("lb_ip") or "")
        plan.meta.update(
            lb_id=state.lb.provider_id, lb_name=lb_name, previous=previous, new=new, slot=slot,
            slot_of=dict(state.slot_of), certs=set(state.certs), port=port, health=health,
            address=f"{ip}:443" if ip else "", insecure=bool((env.cloud or {}).get("acme_staging")),
            settle=do_rules.settle_seconds(live),
        )
        return plan

    async def _team_problem(self, do: DigitalOceanClient, state: _State) -> str | None:
        """D3: the token must still answer for the team the environment was built in."""
        frozen = state.env.provider_team
        if not frozen:
            return None
        team = provider_accounts.team_of(await do.account())
        if team["id"] == frozen:
            return None
        account = state.account.name if state.account is not None else "The account"
        return (f"{account}'s token answers for team {team['name']}, not the team {state.env.name} was built in: "
                "Slipway changed nothing")

    async def _target_problem(self, do: DigitalOceanClient, state: _State, slot: str, plan: Plan) -> int | None:
        """The slot's recorded droplet id when it is live, tagged and built; else a blocker and None."""
        row = state.droplets.get(slot)
        if row is None:
            plan.blockers.append(f"{slot} has no droplet yet: deploy to {slot} first")
            return None
        droplet_id = _droplet_id(row)
        droplet = await do.droplet(droplet_id) if droplet_id is not None else None
        if droplet is None:
            plan.blockers.append(f"{slot}'s droplet {row.name} is gone: deploy to {slot} to make it again")
            return None
        if not do_rules.has_both_tags(droplet, state.env.id):
            plan.blockers.append(f"{slot}'s droplet {row.name} no longer carries Slipway's tags for "
                                 f"{state.env.name}: Slipway changed nothing")
            return None
        host = state.hosts.get(slot)
        if host is None or not ssh.host_is_built(host):
            plan.blockers.append(f"{slot}'s server isn't built yet: deploy to {slot} first")
            return None
        return droplet_id

    # -- apply

    async def apply(self, ctx: SwitchContext, plan: Plan) -> Applied:
        """Activate: join, health, settle, public check, drop, settle, prove. Deactivate: empty, prove."""
        change = plan.changes[0] if plan.changes else None
        if change is None or change.action == "none":
            await ctx.say(f"{LABEL}: {plan.meta.get('lb_name', 'the load balancer')} already sends traffic where "
                          "it should; nothing to write")
            return Applied()
        meta = plan.meta
        applied = ctx.applied = Applied(changes=[change])
        state = await _state(ctx.env.id)
        async with _client(state) as do:
            if ctx.mode == "deactivate":
                await self._put(ctx, do, meta, [])
                applied.did_apply = True
                await self._prove(ctx, do, meta, [], need_cert=False)
                return applied
            new = meta["new"]
            join = list(meta["previous"]) if new in meta["previous"] else [*meta["previous"], new]
            live = await self._put(ctx, do, meta, join)
            applied.did_apply = True
            why = await self._health(ctx, state, meta)
            if why:
                raise SwitchFailed(why)
            await self._settle(ctx, live)
            check = await self._public_check(ctx, meta, rounds=self._rounds(live))
            if not check.ok:
                raise SwitchFailed(_failed_text(check, ctx))
            if join != [new]:
                live = await self._put(ctx, do, meta, [new])
                await self._settle(ctx, live)
            await self._prove(ctx, do, meta, [new], need_cert=True)
        return applied

    async def _put(self, ctx: SwitchContext, do: DigitalOceanClient, meta: dict[str, Any],
                   ids: list[int]) -> dict[str, Any]:
        """Wait for ``active``, PUT the whole body with ``ids`` as the targets, record it, wait for ``active``."""
        lb_id, name = meta["lb_id"], meta["lb_name"]
        live = await _wait_active(do, lb_id, name)
        body = do_rules.lb_update_body(live, droplet_ids=ids)
        try:
            await do.update_load_balancer(lb_id, body)
        except digitalocean.Unreachable:
            await self._note(ctx, meta, ids)  # it may have landed
            raise
        await self._note(ctx, meta, ids)
        await ctx.say(f"{LABEL}: {name} now sends traffic to {_describe(ids, meta['slot_of'])}")
        return await _wait_active(do, lb_id, name)

    async def _note(self, ctx: SwitchContext, meta: dict[str, Any], ids: list[int]) -> None:
        entry = {"hostname": meta["lb_name"], "id": meta["lb_id"], "droplet_ids": list(ids)}
        await traffic._save_switch(ctx, lambda r: r.setdefault("changed", []).append(entry))

    async def _health(self, ctx: SwitchContext, state: _State, meta: dict[str, Any]) -> str | None:
        """The slot's own health route over its SSH session, every 10 s for up to 5 minutes; None when it passed."""
        slot = meta["slot"]
        host = state.hosts.get(slot)
        port, path = meta["port"], meta["health"]
        command = health_command(port, path)
        await ctx.say(f"Checking {slot}'s health on its droplet ({path} on port {port})")
        last = "it didn't answer"
        connect = ctx.connect or ssh.open_session
        for attempt in range(1, HEALTH_TRIES + 1):
            if attempt > 1:
                await sleep(HEALTH_EVERY)
            try:
                if host is None:
                    raise ssh.SSHError(f"{slot} has no server")
                async with connect(ssh.SSHTarget.from_host(host)) as remote:
                    _status, output = await remote.run(command, check=False, timeout=HEALTH_COMMAND_TIMEOUT)
            except (ssh.SSHError, ssh.HostNotBuilt) as exc:
                last = str(exc).splitlines()[0][:200] if str(exc) else type(exc).__name__
                continue
            code = _code(output)
            if traffic.passes(code):
                await ctx.say(f"{slot} answered {code} on {path} on its droplet")
                return None
            last = f"it answered {code}" if code is not None else (output.strip().splitlines() or ["no answer"])[-1][:200]
        return (f"{slot}'s droplet didn't pass its health check ({path} on port {port}) in "
                f"{_span(HEALTH_TRIES * HEALTH_EVERY)}: {last}")

    def _rounds(self, live: dict[str, Any]) -> int:
        """Enough public-check rounds to outlast the settle time."""
        return max(traffic.CHECK_ROUNDS, math.ceil(do_rules.settle_seconds(live) / traffic.CHECK_DELAY) + 1)

    async def _settle(self, ctx: SwitchContext, live: dict[str, Any]) -> None:
        seconds = do_rules.settle_seconds(live)
        await ctx.say(f"Waiting {seconds} s for the load balancer to settle")
        await sleep(seconds)

    async def _public_check(self, ctx: SwitchContext, meta: dict[str, Any], *, rounds: int) -> CheckResult:
        await ctx.say(f"Checking the names through {VIA}")
        return await traffic.public_check(_lb_routes(ctx), meta["address"], say=ctx.say, rounds=rounds,
                                          insecure=meta["insecure"], via=VIA)

    async def _prove(self, ctx: SwitchContext, do: DigitalOceanClient, meta: dict[str, Any], want: list[int], *,
                     need_cert: bool) -> dict[str, Any]:
        """Read the load balancer back: its targets must be exactly ``want``, its certificate one Slipway recorded."""
        live = await do.load_balancer(meta["lb_id"])
        if live is None:
            raise SwitchFailed(f"The load balancer {meta['lb_name']} disappeared from DigitalOcean during the switch")
        now = _ids(live)
        if sorted(now) != sorted(want):
            raise SwitchFailed(f"The load balancer's targets changed during the switch (now {_ids_text(now)}): "
                               "something else updated it")
        if need_cert and do_rules.https_certificate(live) not in meta["certs"]:
            raise SwitchFailed("The load balancer's certificate changed during the switch: something else "
                               "updated it")
        return live

    # -- verify

    async def verify(self, ctx: SwitchContext, plan: Plan) -> CheckResult:
        """Activate: the names through the load balancer once more. Deactivate: a read that finds no targets
        (the names answer 503 by design, so the public check isn't run)."""
        meta = plan.meta
        if ctx.mode == "deactivate":
            state = await _state(ctx.env.id)
            async with _client(state) as do:
                live = await do.load_balancer(meta["lb_id"])
            now = _ids(live)
            if live is None or now:
                what = "is gone" if live is None else f"still sends traffic to {_describe(now, meta['slot_of'])}"
                raise SwitchFailed(f"The load balancer {meta['lb_name']} {what}")
            await ctx.say(f"{meta['lb_name']} sends traffic to no droplet")
            return CheckResult(ok=True)
        result = await traffic.public_check(_lb_routes(ctx), meta.get("address", ""), say=ctx.say,
                                            rounds=VERIFY_ROUNDS, insecure=bool(meta.get("insecure")), via=VIA)
        if not result.ok:
            raise SwitchFailed(_failed_text(result, ctx))
        return result

    # -- put back

    async def put_back(self, ctx: SwitchContext, plan: Plan, applied: Applied) -> PutBack:
        async with self.lock(ctx):
            return await self.put_back_locked(ctx, plan, applied)

    async def put_back_locked(self, ctx: SwitchContext, plan: Plan, applied: Applied) -> PutBack:
        """Put the targets back to ``previous`` (the caller holds ``lock(ctx)``). Never raises.

        A sync repair whose ``previous`` was empty has nothing to put back: nothing answered before either.
        """
        pb = PutBack(total=len(applied.changes))
        if not applied.changes:
            return pb
        meta = plan.meta
        name = meta.get("lb_name", "the load balancer")
        previous = list(meta.get("previous") or [])
        if ctx.mode == "sync" and not previous:
            pb.done.append(name)
            return pb
        budget = _put_back_budget()
        try:
            async with asyncio.timeout(budget):  # ends before the switch's own wait does (F32)
                state = await _state(ctx.env.id)
                async with _client(state) as do:
                    live = await _wait_active(do, meta["lb_id"], name)
                    if sorted(_ids(live)) != sorted(previous):
                        await do.update_load_balancer(meta["lb_id"],
                                                      do_rules.lb_update_body(live, droplet_ids=previous))
                        await self._note(ctx, meta, previous)
                        live = await _wait_active(do, meta["lb_id"], name)
            if sorted(_ids(live)) != sorted(previous):
                raise traffic.TrafficError("the targets didn't take")
        except Exception as exc:  # noqa: BLE001 - a put-back never raises
            pb.failed.append(_by_hand(name, previous, meta.get("slot_of") or {}))
            pb.not_applied = (f"DigitalOcean took longer than {budget:g} s" if isinstance(exc, TimeoutError)
                              else str(exc)[:300] or type(exc).__name__)
            await ctx.say(f"{LABEL}: couldn't put {name} back: {pb.not_applied}")
            return pb
        pb.done.append(name)
        await ctx.say(f"{LABEL}: put {name} back to {_describe(previous, meta.get('slot_of') or {})}")
        return pb

    # -- remove

    async def remove(self, ctx: SwitchContext) -> Plan:
        """Teardown: nothing here; the ``cloud`` step deletes the load balancer with the other objects."""
        return Plan(self.name, notes=[GOES_WITH_CLOUD])

    # -- who is live (Resolve)

    async def who_is_live(self, ctx: SwitchContext) -> list[str]:
        """The app slots whose recorded droplets are the load balancer's targets now, sorted. Reads only, without
        the lock. Raises TrafficError when a target is a live droplet that isn't the environment's, and
        DigitalOceanError when DigitalOcean can't be read."""
        state = await _state(ctx.env.id)
        if state.lb is None:
            return []
        live_slots: set[str] = set()
        async with _client(state) as do:
            live = await do.load_balancer(state.lb.provider_id)
            for droplet_id in _ids(live):
                if droplet_id in state.slot_of:
                    live_slots.add(state.slot_of[droplet_id])
                elif await do.droplet(droplet_id) is not None:
                    raise traffic.TrafficError(f"The load balancer sends traffic to droplet {droplet_id}, which isn't "
                                               f"{state.env.name}'s")
        return sorted(live_slots)

    # -- sync

    def pending(self, plan: Plan) -> bool:
        """A sync's own plan never writes: the repair does the load balancer's part."""
        return False

    async def check_sync(self, ctx: SwitchContext, result: SyncResult) -> None:
        return None

    async def repair(self, ctx: SwitchContext) -> SyncResult | None:
        """Put the recorded active slot's current droplet back on the load balancer when it isn't its only target.

        Only while the sync covers the active slot (``ctx.to_slot``) and no switch is unresolved. With that
        droplet already the only target nothing is written and the names are checked once (a warning). Else:
        PUT [the active droplet], its health over SSH, settle, the public check, prove. A failing health or
        public check is a warning (nothing answered before either); a failing prove raises SwitchFailed.
        """
        if traffic.unresolved(ctx.env) or ctx.to_slot is None or traffic.ACTIVE not in ctx.scope:
            return None
        slot = str(ctx.to_slot.slot)
        result = SyncResult(None)

        async def warn(text: str) -> None:
            result.warnings.append(text)
            await ctx.say(text)

        async with self.lock(ctx):
            try:
                plan = await self._plan(ctx, slot, repair=True)
            except (DigitalOceanError, traffic.TrafficError) as exc:
                await warn(f"{LABEL}: {exc}; nothing was changed")
                return result
            result.plan = plan
            await ctx.say(f"{LABEL}: the load balancer for {slot}:")
            await traffic._log_plan(ctx.say, plan)
            if plan.blockers:
                result.warnings += plan.blockers
                await ctx.say(f"{LABEL}: nothing was changed")
                return result
            meta = plan.meta
            change = plan.changes[0]
            if change.action == "none":
                await ctx.say(f"{LABEL}: {meta['lb_name']} sends traffic to {slot}'s droplet only")
                await ctx.say(f"Checking the names through {VIA}")
                result.check = await traffic.public_check(_lb_routes(ctx), meta["address"], say=ctx.say,
                                                          rounds=SYNC_ROUNDS, insecure=meta["insecure"], via=VIA)
                if result.check.skipped:
                    result.warnings.append(result.check.skipped)
                elif not result.check.ok:
                    result.warnings.append(_failed_text(result.check, ctx))
                return result
            applied = ctx.applied = Applied(changes=[change])
            result.applied = applied
            state = await _state(ctx.env.id)
            try:
                async with _client(state) as do:
                    live = await self._put(ctx, do, meta, [meta["new"]])
                    applied.did_apply = True
                    why = await self._health(ctx, state, meta)
                    if why:
                        await warn(why)
                    await self._settle(ctx, live)
                    result.check = await self._public_check(ctx, meta, rounds=self._rounds(live))
                    if result.check.skipped:
                        result.warnings.append(result.check.skipped)
                    elif not result.check.ok:
                        await warn(_failed_text(result.check, ctx))
                    await self._prove(ctx, do, meta, [meta["new"]], need_cert=True)
            except DigitalOceanError as exc:
                await warn(f"{LABEL}: {exc}; nothing was live before, so nothing was put back")
        return result


def health_command(port: int, path: str) -> str:
    """The slot's health check on its own droplet: the code its health route answers to a Host outside its names."""
    path = path if path.startswith("/") else "/" + path
    url = f"http://127.0.0.1:{int(port)}{path}"
    return (f"curl -sS -o /dev/null -w '%{{http_code}}' --max-time 5 -H 'Host: {HEALTH_HOST}' "
            f"'{url.replace(chr(39), '')}'")


def _span(seconds: int) -> str:
    if seconds % 60 == 0:
        minutes = seconds // 60
        return f"{minutes} minute" + ("" if minutes == 1 else "s")
    return f"{seconds} seconds"


def _code(output: str) -> int | None:
    match = re.search(r"([0-9]{3})\s*$", output or "")
    return int(match.group(1)) if match else None


def _failed_text(check: CheckResult, ctx: SwitchContext) -> str:
    failed = [r["hostname"] for r in check.results if not traffic.passes(r.get("code"))]
    total = len(list(ctx.routes))
    return f"{len(failed)} of {total} names didn't answer through the load balancer: {', '.join(failed)}"


def _by_hand(name: str, previous: list[int], slot_of: dict[int, str]) -> str:
    """What a person does in DigitalOcean when a put-back couldn't finish."""
    if not previous:
        return f"take every droplet off load balancer {name}"
    where = " and ".join(f"{slot_of[i]} (droplet {i})" if i in slot_of else f"droplet {i}" for i in previous)
    return f"point load balancer {name} at {where}"


traffic.register(DoLbBackend())
