"""Traffic for environments: which slot an environment's public names reach, and their DNS records.

An environment's **routes** are its public hostnames (phase 3 §10.1). Those of the app's data services
(``data.server.services``) follow the data server; the rest follow the **active** slot. Two things keep
them published:

* a **traffic backend** points each name at a slot. Phase 3 has one, ``switchyard``: one Switchyard proxy
  host per name, marked as the environment's (``switchyard.marker``). Phase 4 adds ``do_lb``, which
  registers itself with ``register``. ``switch`` is the whole of Activate's ``switch`` step (and of
  Deactivate's): plan (reads only), write and apply, check the names through the backend, and put back
  what it wrote when anything fails. ``sync`` brings hosts up to date without moving any name to another
  slot (an in-place deploy, the data server's deploy, Publish names), then lets the backend repair what
  it serves for the recorded active slot. Each backend gives the lock its writers share
  (``backend.lock(ctx)``); Switchyard's is ``switchyard.lock``.
* **DNS publishing** (``publish_dns``) keeps one Cloudflare A record per name at a fixed address. DNS
  never moves on a switch.

Every Switchyard host and DNS record Slipway manages is a ``resources`` row, written the moment the
provider answers. Slipway changes or deletes only objects a row names whose live object still carries
its marker (I7); anything else in the way is a blocker, and a plan with a blocker writes nothing (I5).

Also here, because Activate, the deploys and Discard all use them: the slot smoke test (a ``curl`` on
the slot's host), the public check (from the Slipway server through the backend's address), and
the database probe a slot's ``settings`` step runs against the data server.
"""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import logging
import re
import shlex
import uuid
from collections.abc import Awaitable, Callable, Iterable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
from typing import Any, ClassVar, Protocol

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.db.base import utcnow
from slipway.db.session import session_scope
from slipway.models import Deployment, Environment, Instance, Resource, User
from slipway.services import audit, cloudflare, environments, resources, ssh, switchyard
from slipway.services.switchyard import Owner, SwitchyardClient, SwitchyardError, Target

log = logging.getLogger(__name__)

Log = switchyard.Log
ConnectFactory = Callable[[ssh.SSHTarget], AbstractAsyncContextManager[ssh.RemoteSession]]

PROVIDER = "switchyard"
KIND = "proxy_host"
ACTIVE, SERVER = "active", "server"  # what a route follows
MAX_ROUTES = 50
PUT_BACK_TIMEOUT = 120  # seconds the put-back may take before the switch gives up waiting for it

# Slot smoke test (§10.8): tries per failing name and the wait between them; the SSH command's timeout.
SMOKE_TRIES = 5
SMOKE_DELAY = 10
SMOKE_COMMAND_TIMEOUT = 60
# Public check: rounds and the wait between them (more when Caddy is getting a certificate), per request.
CHECK_ROUNDS = 6
CHECK_ROUNDS_CREATED = 12
CHECK_DELAY = 10
CHECK_TIMEOUT = 10
# Database probe (§6).
PROBE_IMAGE = "postgres:16-alpine"
PROBE_COMMAND_TIMEOUT = 120  # the image may have to be pulled

NO_TRAFFIC_ADDRESS = ("Set Switchyard's traffic address in Settings → Integrations so Slipway can check "
                      "the names through it")
SWITCHYARD_MISSING = "Set up Switchyard in Settings → Integrations first"
CLOUDFLARE_MISSING = "Set up Cloudflare in Settings → Integrations first"
SPLIT = "Traffic may be split between the slots; resolve it first"

# Test seams: the public check's transport (given whether the certificate is verified) and the waits.
Transport = httpx.AsyncBaseTransport | None
transport_factory: Callable[[bool], Transport] = lambda verify: None  # noqa: E731
sleep: Callable[[float], Awaitable[None]] = asyncio.sleep


async def _quiet(_line: str) -> None:
    return None


class TrafficError(RuntimeError):
    pass


class SwitchRefused(TrafficError):
    """The switch's plan had a blocker (or Switchyard couldn't be read): nothing was written."""

    def __init__(self, message: str, plan: Plan | None = None) -> None:
        super().__init__(message)
        self.plan = plan


class SwitchFailed(TrafficError):
    """Something failed after the first write. ``unresolved``: the put-back couldn't finish."""

    def __init__(self, message: str, *, unresolved: bool = False, put_back: PutBack | None = None) -> None:
        super().__init__(message)
        self.unresolved = unresolved
        self.put_back = put_back


class DnsRefused(TrafficError):
    """The DNS plan had blockers: no record was written."""

    def __init__(self, message: str, plan: Plan) -> None:
        super().__init__(message)
        self.plan = plan


# ---------------------------------------------------------------------------- types


@dataclass(frozen=True)
class Route:
    hostname: str
    service: str
    container: int
    follows: str  # active | server
    tls_mode: str
    health: str

    def to_json(self) -> dict[str, Any]:
        return {"hostname": self.hostname, "service": self.service, "container": self.container,
                "follows": self.follows, "tls_mode": self.tls_mode, "health": self.health}


@dataclass
class Change:
    hostname: str
    action: str  # create | update | delete | none | forget (forget: a row whose object is gone or no longer ours)
    external_id: str | None  # Switchyard host id, Cloudflare record id
    resource_id: uuid.UUID | None
    before: dict[str, Any] | None  # the object as read (for put-back)
    after: dict[str, Any] | None  # the body Slipway will write
    summary: str  # "api.uat.example.com → 10.0.0.12:8000 (was 10.0.0.11:8000)"
    follows: str = ""
    upstream: str = ""  # where the name will go, "address:port"
    status: str = ""  # DNS: plan_dns's status (ok, update, create, covered, claimable, adopt, conflict, delete, forget)
    stale_row: uuid.UUID | None = None  # a row to forget before this change (its object is gone or not ours)
    adopt: bool = False  # a host carrying this environment's marker that no row names: record it first
    unconfirmed: bool = False  # a create whose answer Switchyard never gave: the host may exist (found by name)
    target: Target | None = field(default=None, repr=False, compare=False)
    written: dict[str, Any] | None = field(default=None, repr=False, compare=False)  # as Switchyard stored it
    # An Activate planned while the environment's earlier switch is unresolved (its writes may still be
    # staged): what a put-back makes the host. "target": ``put_back_to`` (the recorded active slot's, what
    # Caddy last served); "delete": nothing was live before; "unknown": Slipway can't tell (§10.3, I6).
    put_back_mode: str = field(default="", repr=False, compare=False)
    put_back_to: Target | None = field(default=None, repr=False, compare=False)

    def to_json(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname, "action": self.action, "external_id": self.external_id,
            "resource_id": str(self.resource_id) if self.resource_id else None, "before": self.before,
            "after": self.after, "summary": self.summary, "follows": self.follows, "upstream": self.upstream,
            "status": self.status,
        }


@dataclass
class Plan:
    backend: str
    changes: list[Change] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)  # any one: nothing is written
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)  # what the step should end with as a warning
    meta: dict[str, Any] = field(default_factory=dict, repr=False)  # the backend's own (preview version, edits)

    @property
    def writes(self) -> list[Change]:
        return [c for c in self.changes if c.action in ("create", "update", "delete")]

    @property
    def creates(self) -> list[Change]:
        return [c for c in self.changes if c.action == "create"]

    def to_json(self) -> dict[str, Any]:
        return {"backend": self.backend, "changes": [c.to_json() for c in self.changes],
                "blockers": list(self.blockers), "notes": list(self.notes), "warnings": list(self.warnings)}


@dataclass
class Applied:
    changes: list[Change] = field(default_factory=list)  # what was written, in order, with the external ids
    apply_n: int | None = None  # Switchyard's last_applied.n after Slipway's apply, or None (no apply)
    did_apply: bool = False

    @property
    def created(self) -> bool:
        return any(c.action == "create" for c in self.changes)


@dataclass
class PutBack:
    total: int = 0
    done: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    not_applied: str | None = None  # why the put-back couldn't be applied
    interrupted: bool = False  # Slipway was cancelled while it waited for the put-back

    @property
    def ok(self) -> bool:
        return not self.failed


@dataclass
class SwitchContext:
    env: Environment
    # activate: the target slot; sync: the recorded active slot when included; deactivate and remove: None
    to_slot: Instance | None
    owner: Instance | None  # the data owner (data server in mode server, the only slot in mode slot)
    routes: list[Route]  # deactivate: the active slot's names, the ones traffic is taken off
    mode: str  # activate | deactivate | sync | remove
    deployment_id: uuid.UUID | None = None
    say: Log = _quiet
    connect: ConnectFactory | None = None
    from_slot: str | None = None  # the slot active when the context was built
    from_instance: Instance | None = None  # that slot's instance
    config: switchyard.SwitchyardConfig | None = None
    scope: tuple[str, ...] = (ACTIVE, SERVER)  # which rows a plan may delete (what it follows)
    applied: Applied | None = None  # set by the backend's apply as it goes, for a put-back after a failure
    record_switch: bool = False  # keep options.switch on the deployment up to date (Activate)
    notes: list[str] = field(default_factory=list)  # for the plan: why some names were left out


@dataclass
class CheckResult:
    ok: bool
    results: list[dict[str, Any]] = field(default_factory=list)  # [{hostname, code} | {hostname, error}]
    failures: list[str] = field(default_factory=list)
    skipped: str | None = None  # why nothing was checked (a warning)

    @property
    def message(self) -> str:
        return "; ".join(self.failures)


@dataclass
class SwitchResult:
    plan: Plan
    applied: Applied
    check: CheckResult | None
    warnings: list[str] = field(default_factory=list)


@dataclass
class SyncResult:
    plan: Plan | None
    applied: Applied | None = None
    check: CheckResult | None = None
    warnings: list[str] = field(default_factory=list)
    skipped: str | None = None


# --------------------------------------------------------------------------- routes


def _health(hostname: str, service: str, instance: Instance | None, env: Environment) -> str:
    """The path smoke tests request: the release's ``services.<name>.health``, else what env.hostnames has, else /."""
    services = (((instance.app_state or {}).get("manifest") or {}).get("services") or []) if instance else []
    found = next((s.get("health") for s in services if s.get("name") == service and s.get("health")), None)
    if found:
        return found
    listed = next((h.get("health") for h in env.hostnames or [] if h.get("hostname") == hostname), None)
    return listed or "/"


def routes(env: Environment, slot_instance: Instance | None, owner: Instance | None, *,
           default_tls: str = "auto") -> list[Route]:
    """The environment's routes (§10.1): the target slot's names follow it, the data server's follow it.

    Active-following: what ``slot_instance``'s release serves (``app_state.routes``, slot role, so without
    ``data.server.services``), or before it deployed, ``env.hostnames`` that follow the active slot.
    Server-following (mode ``server``): the data server's ``app_state.routes``, or ``env.hostnames``
    that follow the server before it deployed.
    """
    tls = env.route_tls or {}
    out: dict[str, Route] = {}

    def add(raw: dict[str, Any], follows: str, instance: Instance | None) -> None:
        hostname = str(raw["hostname"]).lower()
        if hostname in out:
            return
        service = raw.get("service") or ""
        out[hostname] = Route(hostname, service, int(raw["container"]), follows,
                              tls.get(hostname) or default_tls, _health(hostname, service, instance, env))

    listed = list(env.hostnames or [])
    server_mode = env.data_mode == "server" and owner is not None and owner.slot == "data"
    if server_mode:
        served = (owner.app_state or {}).get("routes")
        for raw in served if served else [h for h in listed if h.get("follows") == SERVER]:
            add(raw, SERVER, owner)
    served = (slot_instance.app_state or {}).get("routes") if slot_instance is not None else None
    if served:
        server_names = {h.get("hostname") for h in listed if h.get("follows") == SERVER}
        for raw in served:
            if raw.get("hostname") not in server_names or not server_mode:
                add(raw, ACTIVE, slot_instance)
    else:
        for raw in listed:
            if raw.get("follows", ACTIVE) == ACTIVE or not server_mode:
                add(raw, ACTIVE, slot_instance)
    return sorted(out.values(), key=lambda r: r.hostname)


def _host_name(instance: Instance) -> str:
    """The instance's host in a sentence; a managed environment's data owner has none (P4 §3.4)."""
    return instance.host.name if instance.host is not None else "its managed database"


def _port_name(route: Route) -> str:
    return f"{route.service} container port {route.container}" if route.service else f"container port {route.container}"


def target(route: Route, instance: Instance | None) -> Target:
    """Where ``route`` should send traffic on ``instance`` (as ``switchyard.route_targets``), or why it can't."""
    if instance is None:
        return Target(route.hostname, route.tls_mode, problem="its slot doesn't exist")
    if instance.host is None:  # a managed environment's data owner runs nothing that serves a name (P4 §3.4)
        return Target(route.hostname, route.tls_mode, problem=f"{instance.name} has no server of its own")
    published = [p for p in instance.published_ports or [] if p.get("protocol", "tcp") == "tcp"]
    match = next((p for p in published if int(p["container"]) == route.container
                  and (p.get("service") or "") == route.service), None)
    if match is None:
        why = (f"is not published on {instance.host.name}" if instance.app_state
               else f"isn't running yet ({instance.name} hasn't been deployed)")
        return Target(route.hostname, route.tls_mode, problem=f"{_port_name(route)} {why}")
    return Target(route.hostname, route.tls_mode, instance.host.upstream_address, int(match["host"]))


def target_for(route: Route, ctx: SwitchContext) -> Target:
    return target(route, ctx.owner if route.follows == SERVER else ctx.to_slot)


# The environment's members by slot name, and its data owner among them (D3): one definition, in environments.
members = environments.members
owner_in = environments.owner_in


def active_in(env: Environment, slots: dict[str, Instance]) -> Instance | None:
    return next((i for i in slots.values() if env.active_slot_id and i.id == env.active_slot_id), None)


def unresolved(env: Environment) -> dict[str, Any] | None:
    return (env.traffic_state or {}).get("unresolved") or None


def sync_scope(env: Environment, active: Instance | None, *,
               include_active: bool) -> tuple[tuple[str, ...], str | None]:
    """What a sync may plan (§10.1, I6): ``(follows, note)``.

    Server-following routes always; active-following ones only when the caller asks, a slot is recorded
    as active, and no switch is unresolved. ``note`` says why active-following routes were left out.
    """
    if not include_active:
        return (SERVER,), None
    if unresolved(env):
        return (SERVER,), SPLIT
    if active is None:
        return (SERVER,), "Nothing is live yet, so no app name was published"
    return (ACTIVE, SERVER), None


async def context(
    db: AsyncSession, env: Environment, mode: str, *, slot: str | None = None, include_active: bool = False,
    deployment_id: uuid.UUID | None = None, say: Log = _quiet, connect: ConnectFactory | None = None,
) -> SwitchContext:
    """A SwitchContext for ``mode``: ``activate`` (of ``slot``), ``deactivate`` (take traffic off the
    recorded active slot: ``to_slot`` None, ``routes`` that slot's names), ``sync`` or ``remove``."""
    slots = await members(db, env)
    owner = owner_in(env, slots)
    active = active_in(env, slots)
    config = await switchyard.load_config(db)
    default_tls = config.default_tls_mode if config else await switchyard.default_tls_mode(db)
    notes: list[str] = []
    if mode == "activate":
        if slot not in slots or slot == "data":
            raise TrafficError("Only an app slot can take traffic")
        to_slot, scope = slots[slot], (ACTIVE, SERVER)
        planned = routes(env, to_slot, owner, default_tls=default_tls)
    elif mode == "deactivate":
        to_slot, scope = None, (ACTIVE,)
        planned = ([r for r in routes(env, active, owner, default_tls=default_tls) if r.follows == ACTIVE]
                   if active is not None else [])
    elif mode == "sync":
        scope, note = sync_scope(env, active, include_active=include_active)
        if note and include_active:
            notes.append(note)
        to_slot = active if ACTIVE in scope else None
        planned = [r for r in routes(env, to_slot or active, owner, default_tls=default_tls) if r.follows in scope]
    elif mode == "remove":
        to_slot, scope, planned = None, (ACTIVE, SERVER), []
    else:
        raise ValueError(f"unknown traffic mode {mode!r}")
    ctx = SwitchContext(env=env, to_slot=to_slot, owner=owner, routes=planned, mode=mode,
                        deployment_id=deployment_id, say=say, connect=connect,
                        from_slot=active.slot if active else None, from_instance=active, config=config,
                        scope=scope, notes=notes)
    return ctx


# ------------------------------------------------------------------------- backend


class TrafficBackend(Protocol):
    """What ``switch``, ``sync``, ``remove`` and Resolve need from a backend (registered with ``register``).

    ``switch`` and ``sync`` hold ``lock(ctx)`` around ``plan`` and ``apply``, and hand it to the put-back
    task (``put_back_locked``) when ``apply`` fails, which releases it; ``verify`` runs without it.
    ``put_back`` and ``remove`` take it themselves. ``repair`` runs after a sync, without the lock (it takes
    it itself if it writes), only while no switch is unresolved, and never moves traffic to another slot.
    A backend whose put-back can outlast PUT_BACK_TIMEOUT gives its own ``put_back_timeout`` (seconds).
    """

    name: ClassVar[str]  # switchyard | do_lb (phase 4)
    label: ClassVar[str]  # what its log lines and warnings start with, and where to check by hand
    via: ClassVar[str]  # the path the public check takes, in "through <via>" texts
    errors: ClassVar[tuple[type[Exception], ...]]  # what it raises when its service can't be read or written

    def lock(self, ctx: SwitchContext) -> asyncio.Lock: ...  # one writer at a time; the same lock for one ctx
    async def configured(self, db: AsyncSession) -> str | None: ...  # why it can't be used, or None
    async def plan(self, ctx: SwitchContext) -> Plan: ...  # reads only
    async def apply(self, ctx: SwitchContext, plan: Plan) -> Applied: ...  # writes; records as it goes
    async def verify(self, ctx: SwitchContext, plan: Plan) -> CheckResult: ...  # raises SwitchFailed; no lock
    async def put_back(self, ctx: SwitchContext, plan: Plan, applied: Applied) -> PutBack: ...  # never raises
    async def put_back_locked(self, ctx: SwitchContext, plan: Plan,
                              applied: Applied) -> PutBack: ...  # the caller holds lock(ctx); never raises
    async def remove(self, ctx: SwitchContext) -> Plan: ...  # teardown: plan of deletes, then applied
    async def who_is_live(self, ctx: SwitchContext) -> list[str]: ...  # the app slots it serves now, sorted
    def pending(self, plan: Plan) -> bool: ...  # sync: whether the plan leaves anything to write or apply
    async def check_sync(self, ctx: SwitchContext, result: SyncResult) -> None: ...  # sync: after apply
    async def repair(self, ctx: SwitchContext) -> SyncResult | None: ...  # sync: None when it has nothing to do


def _strip(host: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in host.items() if k not in ("id", "created_at", "updated_at")}


def _upstream_of(host: dict[str, Any] | None) -> str:
    ups = (host or {}).get("upstreams") or []
    return f"{ups[0].get('host')}:{ups[0].get('port')}" if ups else "nowhere"


def _row_follows(row: Resource, env: Environment) -> str:
    follows = (row.details or {}).get("follows")
    if follows:
        return follows
    return next((h.get("follows") for h in env.hostnames or [] if h.get("hostname") == row.name), ACTIVE)


async def _config(ctx: SwitchContext) -> switchyard.SwitchyardConfig:
    if ctx.config is None:
        async with session_scope() as db:
            ctx.config = await switchyard.load_config(db)
    if ctx.config is None:
        raise SwitchRefused(SWITCHYARD_MISSING)
    return ctx.config


UNKNOWN_BEFORE = "Slipway can't tell what Switchyard served for it before the unresolved switch"


def _tainted(ctx: SwitchContext, state: dict[str, Any]) -> bool:
    """Whether an Activate is planned while the environment's earlier switch is unresolved: what Switchyard
    has staged may then be that switch's half-written state, not what Caddy serves, so a put-back mustn't
    put the hosts back to it."""
    return ctx.mode == "activate" and bool(unresolved(ctx.env) or (state.get("held") or {}).get(str(ctx.env.id)))


def _put_back_plan(change: Change, route: Route | None, ctx: SwitchContext) -> None:
    """Set where a tainted Activate's put-back takes ``change``'s host (see ``Change.put_back_mode``)."""
    if route is None:  # a delete of a name the slot no longer serves: was it live before? Slipway can't tell
        change.put_back_mode = "unknown"
        return
    if route.follows == SERVER:
        tgt = target(route, ctx.owner)
    elif ctx.from_slot is None:
        change.put_back_mode = "delete"
        return
    else:
        tgt = target(route, ctx.from_instance)
    if tgt.problem:
        change.put_back_mode = "unknown"
        return
    change.put_back_mode, change.put_back_to = "target", tgt


def _holder(ctx: SwitchContext) -> str | None:
    """Whose held edits (``switchyard.hold``) this operation may apply: the environment's own in an Activate,
    which checks every name afterwards, and in a teardown, which deletes its hosts; nobody's in a sync (I6)."""
    return str(ctx.env.id) if ctx.mode in ("activate", "remove") else None


async def _rows(env_id: uuid.UUID) -> dict[str, Resource]:
    async with session_scope() as db:
        return {r.name: r for r in await resources.owned(db, env_id, PROVIDER, KIND)}


async def _save_switch(ctx: SwitchContext, change: Callable[[dict[str, Any]], None]) -> None:
    """Update ``options.switch`` on the deployment in its own transaction (Activate only)."""
    if not ctx.record_switch or ctx.deployment_id is None:
        return
    async with session_scope() as db:
        dep = await db.get(Deployment, ctx.deployment_id, with_for_update=True)
        if dep is None:
            return
        # A deep copy: changing the stored lists in place would hide the change from the session.
        options = copy.deepcopy(dict(dep.options or {}))
        record = options.get("switch") or {}
        change(record)
        options["switch"] = record
        dep.options = options


async def _note_write(ctx: SwitchContext, what: str, change: Change) -> None:
    entry = {"hostname": change.hostname, "id": change.external_id}
    await _save_switch(ctx, lambda r: r.setdefault(what, []).append(entry))


async def _landed(sy: SwitchyardClient, change: Change, owner: Owner) -> dict[str, Any] | None:
    """The host a create whose answer was lost made, if it made one: the host serving ``change.hostname``
    that carries ``owner``'s marker. Raises SwitchyardError when Switchyard can't be read."""
    return next((h for h in await sy.list_hosts()
                 if change.hostname in (h.get("domains") or []) and switchyard.owned_by(h, owner)), None)


class SwitchyardBackend:
    """Repoint the environment's Switchyard proxy hosts (§10.3).

    ``plan`` and ``apply`` expect the caller (``switch``, ``sync``) to hold ``switchyard.lock``;
    ``put_back`` and ``remove`` take it themselves; ``verify`` holds no lock. Deactivate isn't designed for
    Switchyard: its plan refuses.
    """

    name: ClassVar[str] = "switchyard"
    label: ClassVar[str] = "Switchyard"
    via: ClassVar[str] = "Switchyard"
    errors: ClassVar[tuple[type[Exception], ...]] = (SwitchyardError,)

    def lock(self, ctx: SwitchContext) -> asyncio.Lock:
        """The one Switchyard writer lock, shared with every instance's sync (``switchyard.lock``)."""
        return switchyard.lock

    async def configured(self, db: AsyncSession) -> str | None:
        return None if await switchyard.load_config(db) is not None else SWITCHYARD_MISSING

    # -- plan

    async def plan(self, ctx: SwitchContext) -> Plan:
        if ctx.mode == "deactivate":
            return Plan(self.name, notes=list(ctx.notes), blockers=[
                f"{ctx.env.name} uses Switchyard; take its names off in Switchyard instead"])
        config = await _config(ctx)
        async with SwitchyardClient(config) as sy:
            preview = await sy.preview()
            hosts = await sy.list_hosts()
        state = await switchyard.own_edits(preview)
        plan = Plan(self.name, notes=list(ctx.notes))
        plan.meta = {"version": (preview.get("last_applied") or {}).get("n"), "edits": dict(state)}
        tainted = _tainted(ctx, state)
        if tainted:
            plan.meta["tainted"] = True
        why = switchyard.blocked(preview, state, holder=_holder(ctx))
        if why and ctx.mode != "remove":
            plan.blockers.append(f"Switchyard: {why}")
        elif why:
            plan.meta["blocked"] = why
        if len(ctx.routes) > MAX_ROUTES:
            plan.blockers.append(f"Too many public names ({len(ctx.routes)}); Slipway manages at most "
                                 f"{MAX_ROUTES} per environment")

        owner = Owner.of(ctx.env)
        by_id = {int(h["id"]): h for h in hosts if str(h.get("id", "")).isdigit()}
        by_domain = {d: h for h in hosts for d in h.get("domains") or []}
        rows = await _rows(ctx.env.id)

        def recorded_host(row: Resource) -> dict[str, Any] | None:
            host = by_id.get(int(row.provider_id)) if row.provider_id.isdigit() else None
            return host if host is not None and switchyard.owned_by(host, owner) else None

        for route in ctx.routes:
            tgt = target_for(route, ctx)
            if tgt.problem:
                plan.blockers.append(f"{route.hostname}: {tgt.problem}")
                continue
            row = rows.get(route.hostname)
            host = recorded_host(row) if row is not None else None
            stale = row.id if row is not None and host is None else None
            if host is None:
                row = None
            change = Change(route.hostname, "none", None, row.id if row else None, None, None, "",
                            follows=route.follows, upstream=tgt.upstream, stale_row=stale, target=tgt)
            if host is None:
                found = by_domain.get(route.hostname)
                if found is not None:
                    others = [d for d in found.get("domains") or [] if d != route.hostname]
                    if others:
                        plan.blockers.append(f"Switchyard host #{found.get('id')} serves {route.hostname} together "
                                             f"with {', '.join(others)}; give it a host of its own")
                        continue
                    if not switchyard.owned_by(found, owner):
                        plan.blockers.append(f"{route.hostname} is used by Switchyard host #{found.get('id')}, "
                                             f"which belongs to {switchyard.describe_owner(found)}")
                        continue
                    host, change.adopt = found, True  # ours, but its row was lost: record it, then use it
            if host is None:
                change.action = "create"
                change.after = switchyard.desired(None, tgt, owner)
                change.summary = f"{route.hostname} → {tgt.upstream} (new)"
            else:
                change.external_id = str(host["id"])
                change.before = _strip(host)
                body = switchyard.desired(host, tgt, owner)
                if switchyard.differs(host, body):
                    change.action, change.after = "update", body
                    was = _upstream_of(host)
                    if host.get("tls_mode") != tgt.tls_mode:
                        was += f", TLS {host.get('tls_mode')}"
                        change.summary = f"{route.hostname} → {tgt.upstream}, TLS {tgt.tls_mode} (was {was})"
                    else:
                        change.summary = f"{route.hostname} → {tgt.upstream} (was {was})"
                else:
                    change.summary = f"{route.hostname} → {tgt.upstream} (no change)"
            if tainted:
                _put_back_plan(change, route, ctx)
            plan.changes.append(change)

        # Rows for names this operation no longer routes (only those it may touch: a sync without the active
        # slot leaves the active-following hosts alone).
        routed = {r.hostname for r in ctx.routes}
        for name, row in sorted(rows.items()):
            if name in routed or _row_follows(row, ctx.env) not in ctx.scope:
                continue
            host = recorded_host(row)
            if host is not None:
                gone = Change(name, "delete", str(host["id"]), row.id, _strip(host), None,
                              f"{name}: remove Switchyard host #{host['id']}",
                              follows=_row_follows(row, ctx.env), upstream=_upstream_of(host))
                if tainted:
                    _put_back_plan(gone, None, ctx)
                plan.changes.append(gone)
            else:
                plan.changes.append(Change(name, "forget", row.provider_id, row.id, None, None,
                                           f"{name}: forget Switchyard host #{row.provider_id} (it is gone or no "
                                           "longer carries Slipway's marker)", follows=_row_follows(row, ctx.env)))
        plan.changes.sort(key=lambda c: c.hostname)
        return plan

    # -- apply

    async def _record(self, ctx: SwitchContext, change: Change, host_id: str, config: switchyard.SwitchyardConfig,
                      origin: str = "created") -> uuid.UUID:
        tls = change.target.tls_mode if change.target else (change.before or {}).get("tls_mode")
        details = {"follows": change.follows, "upstream": change.upstream, "tls_mode": tls, "url": config.url}
        args = (ctx.env.id, PROVIDER, KIND, host_id, change.hostname, origin, details)
        try:
            return await resources.record(*args)
        except resources.ResourceTaken:
            # Switchyard reuses ids: another environment's row may still name an id whose host it lost.
            # The live host is ours (it carries this environment's marker), so that row is stale.
            async with session_scope() as db:
                held = await db.scalar(select(Resource).where(
                    Resource.provider == PROVIDER, Resource.kind == KIND, Resource.provider_id == host_id,
                    Resource.environment_id != ctx.env.id))
            if held is None:
                raise
            await resources.forget(held.id)
            return await resources.record(*args)

    async def apply(self, ctx: SwitchContext, plan: Plan) -> Applied:
        config = await _config(ctx)
        owner = Owner.of(ctx.env)
        applied = ctx.applied = Applied()
        state = dict(plan.meta.get("edits") or {"version": plan.meta.get("version"), "edits": 0})
        version = plan.meta.get("version")

        async def edited() -> None:
            state["edits"] = int(state.get("edits") or 0) + 1
            await switchyard.save_edits(state)

        async with SwitchyardClient(config) as sy:
            for change in plan.changes:
                if change.stale_row is not None:
                    await resources.forget(change.stale_row)
                    change.stale_row = None
                if change.action == "forget":
                    if change.resource_id is not None:
                        await resources.forget(change.resource_id)
                    await ctx.say(f"Switchyard: forgot {change.hostname} (host #{change.external_id} is gone or "
                                  "no longer Slipway's)")
                elif change.action == "create":
                    # Listed before the write, as updates are: when Switchyard's answer is lost (a timeout, a
                    # gateway error after it made the host), the put-back looks for the host by its name.
                    change.unconfirmed = True
                    applied.changes.append(change)
                    try:
                        host = await sy.create_host(change.after)
                    except SwitchyardError as exc:
                        if exc.status_code is not None and exc.status_code < 500:  # refused: nothing was made
                            applied.changes.remove(change)
                            change.unconfirmed = False
                            raise
                        found = await _landed(sy, change, owner)  # if this fails too, the put-back looks again
                        if found is None:
                            applied.changes.remove(change)
                            change.unconfirmed = False
                            raise
                        host = found
                        await ctx.say(f"Switchyard answered the create of {change.hostname} with an error ({exc}), "
                                      f"but it made the host (#{host['id']})")
                    change.unconfirmed = False
                    change.external_id, change.written = str(host["id"]), _strip(host)
                    await edited()
                    await _note_write(ctx, "created", change)
                    change.resource_id = await self._record(ctx, change, change.external_id, config)
                    await ctx.say(f"Switchyard: created {change.hostname} → {change.upstream} (host #{host['id']})")
                elif change.action in ("update", "delete") or change.adopt:
                    host = await sy.get_host(int(change.external_id))
                    if host is None or not switchyard.owned_by(host, owner):
                        raise SwitchFailed(f"Switchyard host #{change.external_id} ({change.hostname}) changed "
                                           "during the switch: it no longer carries Slipway's marker")
                    change.before = _strip(host)
                    if change.adopt:
                        change.resource_id = await self._record(ctx, change, change.external_id, config)
                        await ctx.say(f"Switchyard: recorded host #{change.external_id} ({change.hostname}), "
                                      "which carries this environment's marker")
                    if change.action == "update" or (change.action == "none" and change.adopt):
                        body = switchyard.desired(host, change.target, owner)
                        if not switchyard.differs(host, body):
                            continue
                        change.action, change.after = "update", body
                        applied.changes.append(change)  # before the write: a put-back re-reads it either way
                        stored = await sy.update_host(int(change.external_id), body)
                        change.written = _strip(stored) if stored else None
                        await edited()
                        await _note_write(ctx, "changed", change)
                        if change.resource_id is not None:
                            await resources.update_details(change.resource_id, follows=change.follows,
                                                           upstream=change.upstream, tls_mode=change.target.tls_mode)
                        await ctx.say(f"Switchyard: {change.summary}")
                    else:  # delete
                        applied.changes.append(change)
                        await sy.delete_host(int(change.external_id))
                        await edited()
                        await _note_write(ctx, "deleted", change)
                        if change.resource_id is not None:
                            await resources.forget(change.resource_id, deleted=True)
                        await ctx.say(f"Switchyard: removed {change.hostname} (host #{change.external_id})")

            if not switchyard.own_count(state, holder=_holder(ctx)):
                return applied  # nothing of Slipway's that it may apply is waiting: no apply
            preview = await sy.preview()
            now = (preview.get("last_applied") or {}).get("n")
            why = switchyard.blocked(preview, state, holder=_holder(ctx))
            if now != version or why:
                raise SwitchFailed("Someone changed Switchyard during the switch"
                                   + (f" ({why})" if why and now == version else ""))
            note = (f"Slipway: {ctx.env.name} → {ctx.to_slot.slot}" if ctx.mode == "activate" and ctx.to_slot
                    else f"Slipway: {ctx.env.name}")
            try:
                answer = await sy.apply(note)
            except SwitchyardError as exc:
                raise SwitchFailed(f"Switchyard could not apply: {exc}") from exc
            applied.did_apply = True
            applied.apply_n = (answer or {}).get("n")
            await switchyard.save_edits(switchyard.applied_edits(answer, version))
            await _save_switch(ctx, lambda r: r.update(applied=True, apply_n=applied.apply_n))
            await ctx.say(f"Switchyard: applied #{applied.apply_n}")
        return applied

    # -- verify

    async def verify(self, ctx: SwitchContext, plan: Plan, *, rounds: int | None = None) -> CheckResult:
        config = await _config(ctx)
        created = bool(ctx.applied and ctx.applied.created)
        rounds = rounds or (CHECK_ROUNDS_CREATED if created else CHECK_ROUNDS)
        result = await public_check(ctx.routes, config.traffic_address, say=ctx.say, rounds=rounds)
        if not result.ok:
            raise SwitchFailed(f"{result.message} through Switchyard")
        return result

    # -- put back

    async def put_back(self, ctx: SwitchContext, plan: Plan, applied: Applied) -> PutBack:
        async with self.lock(ctx):
            return await self.put_back_locked(ctx, plan, applied)

    async def put_back_locked(self, ctx: SwitchContext, plan: Plan, applied: Applied) -> PutBack:
        """Undo ``applied`` (the caller holds ``switchyard.lock``). Never raises.

        The put-back is applied only when some of the writes may be live: Slipway applied them, or someone
        applied in Switchyard during the switch (that apply took whatever was staged then live with it).
        When nothing went live and an undo failed, nothing is applied: Caddy still serves what it did
        before, and an apply would take what couldn't be put back live (§10.3, I6). A put-back that can't
        finish (an Activate's) leaves what Slipway staged held (``switchyard.hold``) for the environment,
        so no other apply takes it live before Activate or Resolve settles the switch.
        """
        pb = PutBack(total=len(applied.changes))
        if not applied.changes and not applied.did_apply:
            return pb
        names = [c.hostname for c in applied.changes]
        try:
            config = await _config(ctx)
            owner = Owner.of(ctx.env)
            async with SwitchyardClient(config) as sy:
                preview = await sy.preview()
                version = (preview.get("last_applied") or {}).get("n")
                went_live = applied.did_apply or version != plan.meta.get("version")
                # At a new version the count starts again from 0. After someone else's apply in the middle of
                # the switch, Slipway can't tell which of its writes came after it, so it counts none of them:
                # it may then refuse an apply it could have made, but never makes one that takes someone
                # else's change live.
                state = await switchyard.own_edits(preview)
                # An Activate planned over an unresolved switch's staged writes: once anything went live, the
                # hosts it found already moved (and left alone) went live too, so they are put back as well.
                written = {id(c) for c in applied.changes}
                held = [c for c in plan.changes if went_live and plan.meta.get("tainted") and c.put_back_mode
                        and c.action == "none" and c.external_id and id(c) not in written]
                pb.total += len(held)
                names += [c.hostname for c in held]
                if applied.did_apply:
                    await ctx.say(f"Switchyard applied #{applied.apply_n} for the switch; putting back on #{version}")
                elif went_live:
                    await ctx.say(f"Someone applied in Switchyard during the switch (#{version}); putting back "
                                  f"{len(applied.changes)} Switchyard host(s)")
                else:
                    await ctx.say(f"Putting back {len(applied.changes)} Switchyard host(s) (nothing was applied)")
                for change in reversed(applied.changes):
                    try:
                        made = await self._undo(sy, ctx, change, owner, config)
                        if made:
                            state["edits"] = int(state.get("edits") or 0) + made
                            await switchyard.save_edits(state)
                        pb.done.append(change.hostname)
                    except Exception as exc:  # each its own try: one failure doesn't stop the rest
                        pb.failed.append(change.hostname)
                        await ctx.say(f"Switchyard: couldn't put {change.hostname} back: {exc}")
                for change in held:
                    try:
                        host = await sy.get_host(int(change.external_id))
                        if host is None:
                            raise SwitchFailed("it is gone")
                        if switchyard.differs(host, change.before):
                            raise SwitchFailed("someone changed it after the switch")
                        made = await self._restore(sy, ctx, change, host, owner)
                        if made:
                            state["edits"] = int(state.get("edits") or 0) + made
                            await switchyard.save_edits(state)
                        pb.done.append(change.hostname)
                    except Exception as exc:
                        pb.failed.append(change.hostname)
                        await ctx.say(f"Switchyard: couldn't put {change.hostname} back: {exc}")
                if pb.failed and not went_live:
                    pb.not_applied = "nothing had gone live, and applying would take what wasn't put back live"
                    await ctx.say("Switchyard: not applied: the switch had not gone live, and an apply would take "
                                  f"{', '.join(sorted(pb.failed))} live as the switch left them")
                elif went_live or switchyard.own_count(state):
                    preview = await sy.preview()
                    why = switchyard.blocked(preview, state)
                    if why and went_live:
                        pb.not_applied = why
                        pb.failed = names  # back in Switchyard, but not live
                        await ctx.say(f"Switchyard: put back but not applied, because {why}")
                    elif why:
                        # The switch never went live, so Caddy still serves what it did before; Slipway's
                        # writes and their undoing stay staged until the next apply.
                        await ctx.say(f"Switchyard: not applied, because {why}; the switch had not gone live")
                    else:
                        try:
                            answer = await sy.apply(f"Slipway: put back {ctx.env.name}")
                        except SwitchyardError as exc:
                            if went_live:
                                raise
                            # Nothing had gone live: the writes and their undoing stay staged, which is no split.
                            await ctx.say(f"Switchyard: not applied ({exc}); the switch had not gone live")
                        else:
                            await switchyard.save_edits(switchyard.applied_edits(answer, version))
                            await ctx.say(f"Switchyard: applied #{(answer or {}).get('n')} (put back)")
        except Exception as exc:
            pb.failed = names
            pb.not_applied = pb.not_applied or str(exc)
            await ctx.say(f"Switchyard: the put-back failed: {exc}")
        if pb.failed and ctx.mode == "activate":
            try:
                await switchyard.hold_edits(str(ctx.env.id))
            except Exception as exc:  # the database is gone too: recovery holds them after a restart
                log.warning("Couldn't hold the Switchyard edits of %s's switch: %s", ctx.env.name, exc)
        return pb

    async def _undo(self, sy: SwitchyardClient, ctx: SwitchContext, change: Change, owner: Owner,
                    config: switchyard.SwitchyardConfig) -> int:
        """Put one change back; the number of edits it made. Raises when it can't."""
        counted = 0
        if change.action == "create" and change.unconfirmed:
            # Switchyard never answered the create: it may have made the host anyway. Look for it by its name.
            found = await _landed(sy, change, owner)
            if found is None:
                return 0
            change.external_id, change.unconfirmed = str(found["id"]), False
            counted = 1  # its create was never counted
        host_id = int(change.external_id)
        host = await sy.get_host(host_id)
        wrote = change.written or change.after  # compared as Switchyard stored it, when it answered
        if change.action == "update":
            landed = host is not None and not (switchyard.differs(host, wrote) and switchyard.differs(host, change.after))
            if change.put_back_mode and host is not None and (landed or not switchyard.differs(host, change.before)):
                return await self._restore(sy, ctx, change, host, owner)
            if landed:
                await sy.update_host(host_id, change.before)
                await ctx.say(f"Switchyard: put {change.hostname} back to {_upstream_of(change.before)}")
                return 1
            if host is not None and not switchyard.differs(host, change.before):
                return 0  # the write never landed
            raise SwitchFailed("someone changed it after the switch" if host is not None else "it is gone")
        if change.action == "create":
            if host is None:
                if change.resource_id is not None:
                    await resources.forget(change.resource_id)
                return counted
            if not switchyard.owned_by(host, owner) or (switchyard.differs(host, wrote)
                                                         and switchyard.differs(host, change.after)):
                raise SwitchFailed("someone changed it after the switch")
            await sy.delete_host(host_id)
            if change.resource_id is not None:
                await resources.forget(change.resource_id, deleted=True)
            await ctx.say(f"Switchyard: removed {change.hostname} again (host #{host_id})")
            return 1 + counted
        # delete: make it again (Switchyard gives it a new id)
        if host is not None and switchyard.owned_by(host, owner) and not switchyard.differs(host, change.before):
            return 0  # the delete never landed
        if change.put_back_mode == "unknown":
            raise SwitchFailed(UNKNOWN_BEFORE)
        made = await sy.create_host(change.before)
        change.external_id = str(made["id"])
        await self._record(ctx, change, change.external_id, config)
        await ctx.say(f"Switchyard: made {change.hostname} again (host #{made['id']})")
        return 1

    async def _restore(self, sy: SwitchyardClient, ctx: SwitchContext, change: Change, host: dict[str, Any],
                       owner: Owner) -> int:
        """Put ``host`` where a tainted Activate's put-back takes it (``change.put_back_mode``): the recorded
        active slot's target, what Caddy last served, never the unresolved switch's staged state. The number
        of edits it made. Raises when Slipway can't tell where that is."""
        if not switchyard.owned_by(host, owner):
            raise SwitchFailed("it no longer carries Slipway's marker")
        if change.put_back_mode == "unknown":
            raise SwitchFailed(UNKNOWN_BEFORE)
        host_id = int(host["id"])
        if change.put_back_mode == "delete":
            await sy.delete_host(host_id)
            if change.resource_id is not None:
                await resources.forget(change.resource_id, deleted=True)
            await ctx.say(f"Switchyard: removed {change.hostname} (host #{host_id}): nothing was live before")
            return 1
        body = switchyard.desired(host, change.put_back_to, owner)
        if not switchyard.differs(host, body):
            return 0
        await sy.update_host(host_id, body)
        await ctx.say(f"Switchyard: put {change.hostname} back to {change.put_back_to.upstream}")
        return 1

    # -- remove

    async def remove(self, ctx: SwitchContext) -> Plan:
        """Delete every host the environment recorded that still carries its marker; forget the rest.

        One apply afterwards, skipped with a warning when other changes are waiting (the deletes stay
        staged). Raises SwitchyardError when Switchyard can't be reached.
        """
        ctx.routes, ctx.mode, ctx.scope = [], "remove", (ACTIVE, SERVER)
        async with self.lock(ctx):
            plan = await self.plan(ctx)
            config = await _config(ctx)
            owner = Owner.of(ctx.env)
            state = dict(plan.meta["edits"])
            async with SwitchyardClient(config) as sy:
                for change in plan.changes:
                    if change.action == "delete":
                        host = await sy.get_host(int(change.external_id))
                        if host is not None and switchyard.owned_by(host, owner):
                            await sy.delete_host(int(change.external_id))
                            state["edits"] = int(state.get("edits") or 0) + 1
                            await switchyard.save_edits(state)
                            await resources.forget(change.resource_id, deleted=True)
                            await ctx.say(f"Switchyard: removed {change.hostname} (host #{change.external_id})")
                            continue
                        change.action = "forget"
                    if change.resource_id is not None:
                        await resources.forget(change.resource_id)
                        await ctx.say(f"Switchyard: forgot {change.hostname}")
                if switchyard.own_count(state, holder=_holder(ctx)):
                    preview = await sy.preview()
                    why = switchyard.blocked(preview, state, holder=_holder(ctx))
                    if why:
                        plan.warnings.append(f"Applied nothing: {why}; apply there")
                        await ctx.say(f"Switchyard: applied nothing: {why}; apply there")
                    else:
                        answer = await sy.apply(f"Slipway: remove {ctx.env.name}")
                        await switchyard.save_edits(switchyard.applied_edits(answer, plan.meta.get("version")))
                        await ctx.say(f"Switchyard: applied #{(answer or {}).get('n')}")
        return plan

    # -- who is live (Resolve)

    async def who_is_live(self, ctx: SwitchContext) -> list[str]:
        """The app slots Switchyard sends the environment's active-following names to now, sorted.

        Read from the hosts Slipway recorded for the environment: one that still carries its marker counts
        for the slot whose published port it points at. Two slots: the traffic is split; none: no recorded
        host reaches a slot. Reads only, without the lock. Raises SwitchyardError when Switchyard can't be
        read, SwitchRefused when it isn't set up.
        """
        config = await _config(ctx)
        async with SwitchyardClient(config) as sy:
            hosts = await sy.list_hosts()
        async with session_scope() as db:
            mem = await members(db, ctx.env)
        owner = owner_in(ctx.env, mem)
        marker = Owner.of(ctx.env)
        by_id = {str(h.get("id")): h for h in hosts}
        apps = environments.app_members(mem)
        live: set[str] = set()
        for row in (await _rows(ctx.env.id)).values():
            if _row_follows(row, ctx.env) != ACTIVE:
                continue
            host = by_id.get(row.provider_id)
            if host is None or not switchyard.owned_by(host, marker):
                continue
            upstream = _upstream_of(host)
            for slot in apps:
                route = next((r for r in routes(ctx.env, slot, owner) if r.hostname == row.name), None)
                tgt = target(route, slot) if route is not None else None
                if tgt is not None and not tgt.problem and tgt.upstream == upstream:
                    live.add(str(slot.slot))
        return sorted(live)

    # -- sync

    def pending(self, plan: Plan) -> bool:
        """Whether a sync's plan writes, records or forgets a host, or leaves Slipway's own edits to apply."""
        return bool(plan.writes or [c for c in plan.changes if c.adopt or c.stale_row or c.action == "forget"]
                    or switchyard.own_count(plan.meta.get("edits") or {}))

    async def check_sync(self, ctx: SwitchContext, result: SyncResult) -> None:
        """After a sync's apply: the names through Switchyard's traffic address, once (more rounds when a
        host was made, since Caddy gets a certificate). A failure is a warning."""
        if not (result.applied and result.applied.did_apply and ctx.routes):
            return
        rounds = CHECK_ROUNDS_CREATED if result.applied.created else 1
        config = await _config(ctx)
        await ctx.say("Checking the names through Switchyard")
        result.check = await public_check(ctx.routes, config.traffic_address, say=ctx.say, rounds=rounds)
        if result.check.skipped:
            result.warnings.append(result.check.skipped)
        elif not result.check.ok:
            result.warnings.append(f"{result.check.message} through Switchyard")

    async def repair(self, ctx: SwitchContext) -> SyncResult | None:
        """Nothing: a sync already brings every Switchyard host it may touch up to date."""
        return None


BACKENDS: dict[str, TrafficBackend] = {"switchyard": SwitchyardBackend()}


def register(backend: TrafficBackend) -> TrafficBackend:
    """Add (or replace) the backend for ``traffic.switch = <backend.name>``; returns it."""
    BACKENDS[backend.name] = backend
    return backend


def backend_for(env: Environment) -> TrafficBackend | None:
    return BACKENDS.get((env.traffic or {}).get("switch") or "none")


# ------------------------------------------------------------------------- switching


async def _log_plan(say: Log, plan: Plan) -> None:
    for change in plan.changes:
        await say(f"  {change.summary}")
    for note in plan.notes:
        await say(f"  Note: {note}")
    for blocker in plan.blockers:
        await say(f"  Blocked: {blocker}")


_put_backs: set[asyncio.Task[PutBack]] = set()  # strong references, so a put-back is never collected mid-way


async def _shielded_put_back(backend: TrafficBackend, ctx: SwitchContext, plan: Plan, applied: Applied, *,
                             held: asyncio.Lock | None) -> PutBack:
    """Run the put-back as its own task and wait for it, even if we're cancelled.

    The wait is the backend's ``put_back_timeout`` when it has one (``do_lb``'s can wait for its load
    balancer twice), else PUT_BACK_TIMEOUT.

    ``held`` is the backend's lock (``backend.lock(ctx)``) when the caller holds it: the task runs
    ``put_back_locked`` and releases it when it ends, so no other writer gets in between a failed apply and
    its put-back. Without it the task runs ``put_back``, which takes the lock itself.
    """

    async def run() -> PutBack:
        if held is not None:
            try:
                return await backend.put_back_locked(ctx, plan, applied)
            finally:
                held.release()
        return await backend.put_back(ctx, plan, applied)

    task = asyncio.ensure_future(run())
    _put_backs.add(task)
    task.add_done_callback(_put_backs.discard)
    loop = asyncio.get_running_loop()
    timeout = getattr(backend, "put_back_timeout", None) or PUT_BACK_TIMEOUT
    deadline = loop.time() + timeout
    interrupted = False
    while not task.done() and loop.time() < deadline:
        try:
            await asyncio.wait({task}, timeout=max(deadline - loop.time(), 0))
        except asyncio.CancelledError:
            interrupted = True  # keep waiting: the put-back must not be cut off
    if not task.done():
        pb = PutBack(total=len(applied.changes), failed=[c.hostname for c in applied.changes],
                     not_applied=f"the put-back took longer than {timeout:g} s")
    else:
        pb = task.result()
    pb.interrupted = interrupted
    return pb


async def _mark_unresolved(ctx: SwitchContext, message: str) -> None:
    """Record ``traffic_state.unresolved`` (§10.6) and its audit row."""
    async with session_scope() as db:
        env = await db.get(Environment, ctx.env.id, with_for_update=True)
        if env is None:
            return
        state = dict(env.traffic_state or {})
        state["unresolved"] = {
            "deployment_id": str(ctx.deployment_id) if ctx.deployment_id else None,
            "from_slot": ctx.from_slot, "to_slot": ctx.to_slot.slot if ctx.to_slot else None,
            "message": message[:500], "at": utcnow().isoformat(),
        }
        env.traffic_state = state
        audit.record(db, "environment.unresolved", target=env, summary=f"Traffic of {env.name} may be split",
                     details={"slot": ctx.to_slot.slot if ctx.to_slot else None, "message": message[:500]})
    ctx.env.traffic_state = state


def _failure_text(ctx: SwitchContext, reason: str, pb: PutBack, backend: TrafficBackend) -> str:
    if pb.failed:
        names = ", ".join(sorted(pb.failed))
        return (f"{reason}. Slipway couldn't put {len(pb.failed)} of {pb.total} back: {names}. Check them in "
                f"{backend.label}, then use Resolve on the environment page")
    if ctx.from_slot:
        return f"{reason}. Traffic stays on {ctx.from_slot}"
    if isinstance(backend, SwitchyardBackend):
        return f"{reason}. Nothing was live before; Slipway removed the hosts it had made"
    return f"{reason}. Nothing was live before; Slipway put back what it had written"


SWITCH_MODES = ("activate", "deactivate")


async def _retiring_text(env_id: uuid.UUID) -> str | None:
    """P4 §13's ``<env> is retiring: it only goes dark``, read again under the backend's lock just before an
    activate's first write: Retire may have landed while the activate's smoke or certificate step ran."""
    async with session_scope() as db:
        env = await db.get(Environment, env_id)
        if env is None or not env.production or env.retiring_at is None:
            return None
        return f"{env.name} is retiring: it only goes dark"


async def switch(ctx: SwitchContext) -> SwitchResult:
    """Activate's ``switch`` step (§10.2), and Deactivate's: plan, write and apply, check through the
    backend, put back.

    ``ctx.mode`` is ``activate`` (traffic moves to ``ctx.to_slot``) or ``deactivate`` (traffic comes off
    the active slot, ``to_slot`` None; ``verify`` is the backend's own check for that mode). Raises
    SwitchRefused (nothing written) or SwitchFailed (put back, or ``unresolved``). It doesn't write
    ``active_slot_id``: the caller does that once this returns.
    """
    backend = backend_for(ctx.env)
    if backend is None:
        raise SwitchRefused(f"{ctx.env.name} doesn't publish its names through Switchyard")
    if ctx.mode not in SWITCH_MODES:
        raise ValueError(f"a switch is an activate or a deactivate, not {ctx.mode!r}")
    ctx.record_switch = True
    deactivate = ctx.mode == "deactivate"
    to = ctx.to_slot.slot if ctx.to_slot else ("" if deactivate else "?")
    lock = backend.lock(ctx)
    await lock.acquire()
    lock_ours = True
    try:
        if not deactivate:
            retiring = await _retiring_text(ctx.env.id)
            if retiring:
                raise SwitchRefused(f"{retiring}; Slipway changed nothing")
        try:
            plan = await backend.plan(ctx)
        except backend.errors as exc:
            raise SwitchRefused(f"{exc}; Slipway changed nothing") from exc
        if deactivate:
            await ctx.say(f"Plan to take {ctx.env.name}'s traffic off {ctx.from_slot or 'every slot'}:")
        else:
            await ctx.say(f"Plan for {ctx.env.name} → {to}:")
        await _log_plan(ctx.say, plan)
        if plan.blockers:
            raise SwitchRefused("; ".join(plan.blockers) + "; Slipway changed nothing", plan)
        # The switch record exists before the first write, for recovery and Resolve.
        before = {c.hostname: c.before for c in plan.changes if c.before is not None}
        await _save_switch(ctx, lambda r: (r.clear(), r.update(
            backend=backend.name, from_slot=ctx.from_slot, to_slot=to or None, before=before,
            created=[], deleted=[], changed=[], applied=False, apply_n=None)))
        try:
            applied = await backend.apply(ctx, plan)
        except BaseException as exc:
            applied = ctx.applied or Applied()
            lock_ours = False  # the put-back task holds it now and releases it
            pb = await _shielded_put_back(backend, ctx, plan, applied, held=lock)
            await _after_failed(ctx, exc, pb, backend)
            raise AssertionError("unreachable")  # pragma: no cover
    finally:
        if lock_ours:
            lock.release()

    # The verify phase holds no lock: other syncs run meanwhile (they touch other hosts).
    if deactivate:
        await ctx.say(f"Checking that {backend.via} sends no traffic to {ctx.from_slot or 'any slot'}")
    else:
        await ctx.say(f"Checking the names through {backend.via}")
    try:
        check = await backend.verify(ctx, plan)
    except BaseException as exc:
        pb = await _shielded_put_back(backend, ctx, plan, applied, held=None)
        await _after_failed(ctx, exc, pb, backend)
        raise AssertionError("unreachable")  # pragma: no cover
    warnings = [check.skipped] if check.skipped else []
    return SwitchResult(plan, applied, check, warnings)


async def _after_failed(ctx: SwitchContext, exc: BaseException, pb: PutBack, backend: TrafficBackend) -> None:
    """Raise the right error after a put-back: SwitchFailed, or the cancellation that interrupted us."""
    if not isinstance(exc, Exception):
        reason = "Slipway was stopped during the switch"
    else:
        known = (TrafficError, SwitchyardError, *backend.errors)
        reason = str(exc) if isinstance(exc, known) else f"{type(exc).__name__}: {exc}"
    text = _failure_text(ctx, reason.rstrip("."), pb, backend)
    if pb.failed:
        await _mark_unresolved(ctx, text)
    if pb.interrupted:
        raise asyncio.CancelledError
    if not isinstance(exc, Exception):
        raise exc
    raise SwitchFailed(text, unresolved=bool(pb.failed), put_back=pb) from exc


async def sync(ctx: SwitchContext) -> SyncResult:
    """Bring the hosts in ``ctx.routes`` up to date (mode ``sync``, §10.3). Never raises for Switchyard problems.

    It never moves a name to another slot: ``context(..., "sync")`` targets only the recorded active slot
    and the data server. Blockers and failures come back as warnings; a failed apply is put back. After
    a successful apply the backend checks the names (``check_sync``). Then, while no switch is unresolved,
    the backend's ``repair`` may put the recorded active slot back where it lost it (``do_lb``); what it
    did is added to the result.
    """
    ctx.mode = "sync"
    backend = backend_for(ctx.env)
    if backend is None:
        return SyncResult(None, skipped=f"{ctx.env.name} doesn't publish its names through Switchyard")
    result = await _sync_writes(backend, ctx)
    if unresolved(ctx.env) is None:
        _merge(result, await backend.repair(ctx))
    return result


async def _sync_writes(backend: TrafficBackend, ctx: SwitchContext) -> SyncResult:
    """The plan and apply of a sync under the backend's lock, then the backend's check of the names."""
    label = backend.label
    result = SyncResult(None)
    lock = backend.lock(ctx)
    await lock.acquire()
    lock_ours = True
    try:
        try:
            plan = await backend.plan(ctx)
        except (*backend.errors, SwitchRefused) as exc:
            result.warnings.append(f"{label}: {exc}; nothing was changed")
            await ctx.say(result.warnings[-1])
            return result
        result.plan = plan
        await ctx.say(f"{label} plan:")
        await _log_plan(ctx.say, plan)
        if plan.blockers:
            result.warnings += plan.blockers
            await ctx.say(f"{label}: nothing was changed")
            return result
        if not backend.pending(plan):
            await ctx.say(f"{label}: up to date")
            return result
        try:
            result.applied = await backend.apply(ctx, plan)
        except BaseException as exc:
            applied = ctx.applied or Applied()
            lock_ours = False
            pb = await _shielded_put_back(backend, ctx, plan, applied, held=lock)
            if pb.interrupted:
                raise asyncio.CancelledError from exc
            if isinstance(exc, asyncio.CancelledError) or not isinstance(exc, Exception):
                raise
            back = "put back" if pb.ok else f"couldn't put {len(pb.failed)} of {pb.total} back: {', '.join(pb.failed)}"
            result.warnings.append(f"{label}: {exc}; {back}")
            result.applied = applied
            return result
    finally:
        if lock_ours:
            lock.release()

    await backend.check_sync(ctx, result)
    return result


def _merge(result: SyncResult, repaired: SyncResult | None) -> None:
    """Add a repair's plan, writes, check and warnings to the sync's result (the repair's win where both have one)."""
    if repaired is None:
        return
    result.plan = repaired.plan or result.plan
    result.applied = repaired.applied or result.applied
    result.check = repaired.check or result.check
    result.warnings += [w for w in repaired.warnings if w not in result.warnings]
    if repaired.skipped and not result.skipped:
        result.skipped = repaired.skipped


async def remove(ctx: SwitchContext) -> Plan:
    """Teardown's ``unroute``: delete the environment's hosts (``TrafficBackend.remove``)."""
    backend = backend_for(ctx.env) or BACKENDS["switchyard"]
    return await backend.remove(ctx)


async def forget_all(env_id: uuid.UUID, provider: str, kind: str, *, actor: User | None = None) -> int:
    """Forget every row of one provider and kind (teardown's retry with ``forget_traffic``). Writes no provider."""
    async with session_scope() as db:
        ids = [r.id for r in await resources.owned(db, env_id, provider, kind)]
    for row_id in ids:
        await resources.forget(row_id, actor=actor)
    return len(ids)


# ------------------------------------------------------------------------------ DNS


ADOPT = cloudflare.ADOPT  # a record Slipway made for this environment and never recorded
# Statuses whose name already has an A record Slipway may count on (§9.5 step 4: no record has to be made).
_PUBLISHED = {cloudflare.OK, cloudflare.UPDATE, cloudflare.COVERED, ADOPT}


def _dns_change(c: cloudflare.DnsChange) -> Change:
    action = {"update": "update", "create": "create", "delete": "delete", "forget": "forget",
              ADOPT: "adopt"}.get(c.status, "none")
    return Change(c.name, action, c.record_id, c.row_id, c.before, c.after, c.message, status=c.status,
                  stale_row=c.row_id if c.forget_row else None)


async def _dns_inputs(db: AsyncSession, env: Environment, *, remove: bool = False,
                      ) -> tuple[cloudflare.CloudflareConfig, dict[str, dict], list, dict]:
    config = await cloudflare.load_config(db)
    if config is None:
        raise DnsRefused(CLOUDFLARE_MISSING, Plan("cloudflare", blockers=[CLOUDFLARE_MISSING]))
    dns = (env.traffic or {}).get("dns") or {}
    # A DigitalOcean environment's records point only at its load balancer, whose IP ``edge`` writes (P4 §11.6):
    # never at the install's public IP, which is another host's (Switchyard's).
    cloud = environments.is_digitalocean(env)
    address = dns.get("address") or (None if cloud else config.public_ip)
    proxied = dns.get("proxied")
    proxied = config.proxied if proxied is None else bool(proxied)
    # Every name a member's live release serves, the idle slot's included, and env.hostnames (§10.5): a
    # deploy to the idle slot never takes a record from the live one, and switching back finds its own.
    names = [] if remove else sorted(environments.served_names(env, (await members(db, env)).values()))
    wanted = {n: {"content": address, "proxied": proxied} for n in names} if address else {}
    rows = list(await db.scalars(select(Resource).where(Resource.provider == cloudflare.PROVIDER,
                                                        Resource.kind == cloudflare.KIND)))
    env_ids = {r.environment_id for r in rows}
    env_names = {e.id: e.name for e in await db.scalars(select(Environment).where(Environment.id.in_(env_ids)))} \
        if env_ids else {}
    if remove:
        return config, {}, rows, env_names
    if not address and names and cloud:
        problem = environments.NO_LB_YET.format(env=env.name)
        raise DnsRefused(problem, Plan("cloudflare", blockers=[problem]))
    if not address and names:
        problem = (f"Set Cloudflare's public IP in Settings → Integrations, or an address for {env.name}'s DNS "
                   "records, so Slipway knows where they point")
        raise DnsRefused(problem, Plan("cloudflare", blockers=[problem]))
    return config, wanted, rows, env_names


async def _dns_plan(env: Environment, cf: cloudflare.CloudflareClient, zone_id: str, config, wanted, rows,
                    env_names) -> Plan:
    mine = [r for r in rows if r.environment_id == env.id]
    by_name, wildcards = await cloudflare.read_state(cf, zone_id, config.zone, wanted, mine)
    planned = cloudflare.plan_dns(wanted, by_name, wildcards, rows, env.id, zone=config.zone, env_names=env_names)
    plan = Plan("cloudflare", [_dns_change(c) for c in planned.changes], list(planned.blockers))
    plan.meta = {"zone_id": zone_id, "unpublished": _unpublished(planned, by_name, wanted)}
    return plan


def _unpublished(planned: cloudflare.DnsPlan, by_name: dict[str, list], wanted: dict[str, dict]) -> list[str]:
    """The wanted names with no usable A record, whatever the plan says about them: a create, and a name
    held up by a conflict (a recorded record renamed elsewhere, an AAAA, CNAME or NS record, several
    records) or claimable, unless an A record at the name already points at the address. Caddy can't get a
    certificate for any of them, so Activate's ``dns`` step fails on them before the switch (§9.5)."""
    out = []
    for change in planned.changes:
        want = wanted.get(change.name)
        if want is None or change.status in _PUBLISHED:
            continue
        if change.status != cloudflare.CREATE:
            here = [r for n, recs in by_name.items() if n.lower().rstrip(".") == change.name for r in recs
                    if r.get("type") == "A"]
            if any(r.get("content") == want["content"] for r in here):
                continue
        out.append(change.name)
    return out


async def dns_plan(env: Environment, db: AsyncSession, *, remove: bool = False) -> Plan:
    """The DNS plan for every name of the environment (or, with ``remove``, for none). Reads only."""
    config, wanted, rows, env_names = await _dns_inputs(db, env, remove=remove)
    async with cloudflare.CloudflareClient(config.token) as cf:
        zone_id = config.zone_id or await cf.zone_id(config.zone)
        return await _dns_plan(env, cf, zone_id, config, wanted, rows, env_names)


async def publish_dns(env: Environment, say: Log = _quiet, *, actor: User | None = None,
                      remove: bool = False) -> Plan:
    """The ``dns`` step (§10.5): every name's A record at the fixed address, recorded as it's written.

    Blockers raise DnsRefused before any write. Then stale rows are deleted (or forgotten), updates and
    creates follow, each recorded at once. ``remove`` (teardown's ``undns``) wants no name at all.
    Raises CloudflareError when Cloudflare fails part-way; what was written is already recorded.
    """
    async with session_scope() as db:
        config, wanted, rows, env_names = await _dns_inputs(db, env, remove=remove)
    async with cloudflare.CloudflareClient(config.token) as cf:
        zone_id = config.zone_id or await cf.zone_id(config.zone)
        plan = await _dns_plan(env, cf, zone_id, config, wanted, rows, env_names)
        await say("DNS plan:")
        await _log_plan(say, plan)
        if plan.blockers:
            raise DnsRefused("; ".join(plan.blockers) + "; Slipway changed no DNS record", plan)
        comment = cloudflare.comment_for(env.name, env.id)
        # A recorded record is changed and deleted in the zone its row names; new records go to the zone now set.
        zones = {r.id: cloudflare.zone_of(r, zone_id) for r in rows}
        order = {"delete": 0, "forget": 0, "adopt": 1, "update": 1, "create": 2}
        for change in sorted(plan.changes, key=lambda c: (order.get(c.action, 3), c.hostname)):
            if change.stale_row is not None:
                # A row whose record is gone (or not ours): forgotten whatever the name's plan, a covered
                # name's included, so no row keeps naming a record that no longer exists.
                await resources.forget(change.stale_row, actor=actor)
                if change.resource_id == change.stale_row:
                    change.resource_id = None
                change.stale_row = None
            if change.action == "delete":
                gone = await cf.delete_record(zones.get(change.resource_id, zone_id), change.external_id)
                await resources.forget(change.resource_id, deleted=gone, actor=actor)
                await say(f"DNS: removed {change.hostname}" if gone else f"DNS: {change.hostname} was already gone")
            elif change.action == "forget":
                await resources.forget(change.resource_id, actor=actor)
                await say(f"DNS: forgot {change.hostname}")
            elif change.action == "update":
                claimed = next((r.origin for r in rows if r.id == change.resource_id), "created") == "claimed"
                keep = ((change.before or {}).get("comment") or "") if claimed else comment
                in_zone = zones.get(change.resource_id, zone_id)
                record = await cf.update_a(in_zone, change.external_id, change.after["content"],
                                           change.after["proxied"], keep)
                await resources.update_details(change.resource_id, zone_id=in_zone, type="A",
                                               content=record.get("content", change.after["content"]),
                                               proxied=bool(record.get("proxied", change.after["proxied"])))
                await say(f"DNS: {change.summary}")
            elif change.action == "adopt":
                # Slipway made this record (it carries this environment's comment) but never recorded it: record
                # it first, as a record it created, then bring it up to date.
                details = {"zone_id": zone_id, "type": "A", "content": (change.before or {}).get("content"),
                           "proxied": bool((change.before or {}).get("proxied"))}
                change.resource_id = await resources.record(
                    env.id, cloudflare.PROVIDER, cloudflare.KIND, change.external_id, change.hostname, "created",
                    details, actor=actor)
                if change.after:
                    record = await cf.update_a(zone_id, change.external_id, change.after["content"],
                                               change.after["proxied"], comment)
                    await resources.update_details(change.resource_id, content=record.get("content",
                                                   change.after["content"]),
                                                   proxied=bool(record.get("proxied", change.after["proxied"])))
                await say(f"DNS: {change.summary}")
            elif change.action == "create":
                record = await cf.create_a(zone_id, change.hostname, change.after["content"],
                                           change.after["proxied"], comment)
                change.external_id = str(record["id"])
                change.resource_id = await resources.record(
                    env.id, cloudflare.PROVIDER, cloudflare.KIND, change.external_id, change.hostname, "created",
                    {"zone_id": zone_id, "type": "A", "content": change.after["content"],
                     "proxied": change.after["proxied"]}, actor=actor)
                await say(f"DNS: {change.summary}")
        if not plan.writes:
            await say("DNS: up to date")
    return plan


async def forget_lost_zone(env: Environment, *, actor: User | None = None) -> list[str]:
    """Forget, without deleting anything, the environment's DNS rows whose recorded zone Cloudflare doesn't
    know (or this token can't see): a zone deleted and added again, or moved to another account, keeps its
    name but takes its records with it, so nothing is left to delete. The names forgotten, each audited.

    Asked for explicitly (turning DNS off with ``forget_lost_zone``). Raises CloudflareError when Cloudflare
    can't be asked, or answers anything but that the zone is unknown."""
    async with session_scope() as db:
        config = await cloudflare.load_config(db)
        rows = await resources.owned(db, env.id, cloudflare.PROVIDER, cloudflare.KIND)
    if config is None or not rows:
        return []
    lost: dict[str, bool] = {}
    forgotten: list[str] = []
    async with cloudflare.CloudflareClient(config.token) as cf:
        for row in rows:
            zone_id = (row.details or {}).get("zone_id") or config.zone_id
            if not zone_id:
                continue
            if zone_id not in lost:
                try:
                    await cf.can_read_records(zone_id)
                    lost[zone_id] = False
                except cloudflare.CloudflareError as exc:
                    if exc.status_code != 404 or not set(exc.codes) & cloudflare.ZONE_CODES:
                        raise
                    lost[zone_id] = True
            if lost[zone_id]:
                await resources.forget(row.id, actor=actor)
                forgotten.append(row.name)
    if forgotten:
        async with session_scope() as db:
            target = await db.get(Environment, env.id)
            audit.record(db, "environment.dns_forgotten", actor=actor, target=target,
                         summary=f"Forgot {len(forgotten)} DNS record(s) of {env.name} whose Cloudflare zone is gone "
                                 "(nothing was deleted)", details={"names": sorted(forgotten)})
    return sorted(forgotten)


async def remove_dns(env: Environment, say: Log = _quiet, *, actor: User | None = None) -> Plan:
    """Teardown's ``undns``: delete the records Slipway created that still carry its comment; forget the rest."""
    return await publish_dns(env, say, actor=actor, remove=True)


# ------------------------------------------------------------------------- dry runs


async def plan_for(env: Environment, slot: str | None, db: AsyncSession) -> dict[str, Any]:
    """``GET …/traffic/plan`` (§10.7), with no write: ``{switch, dns, routes}`` as JSON.

    With ``slot``: Activate's plan for that slot; without: the sync plan (server-following names, and the
    recorded active slot's). Switchyard and Cloudflare errors are raised (the API answers 502), and so are
    the errors of any other backend. Switchyard's settings are asked for only when the backend is
    Switchyard; another backend says itself why it can't be used (``configured``).
    """
    mode = "activate" if slot else "sync"
    ctx = await context(db, env, mode, slot=slot, include_active=True)
    switch_plan: Plan | None = None
    backend = backend_for(env)
    if backend is not None:
        if isinstance(backend, SwitchyardBackend):
            why = SWITCHYARD_MISSING if ctx.config is None else None
        else:
            why = await backend.configured(db)
        if why:
            switch_plan = Plan(backend.name, blockers=[why])
        else:
            switch_plan = await backend.plan(ctx)
    dns: Plan | None = None
    if (env.traffic or {}).get("dns"):
        try:
            dns = await dns_plan(env, db)
        except DnsRefused as exc:
            dns = exc.plan
    return {"switch": switch_plan.to_json() if switch_plan else None, "dns": dns.to_json() if dns else None,
            "routes": [r.to_json() for r in ctx.routes]}


# --------------------------------------------------------------------- smoke test


@dataclass(frozen=True)
class SmokeTarget:
    hostname: str
    port: int | None
    bind: str
    health: str
    problem: str | None = None


def _bind(host_ip: str | None) -> str:
    """The published port's address when it is a specific one, else 127.0.0.1."""
    value = (host_ip or "").strip().strip("[]")
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "127.0.0.1"
    return "127.0.0.1" if ip.is_unspecified else str(ip)


def smoke_targets(instance: Instance, planned: Iterable[Route]) -> list[SmokeTarget]:
    """What a slot's smoke test requests: every route that follows the slot, on the port it's published on."""
    out = []
    published = [p for p in instance.published_ports or [] if p.get("protocol", "tcp") == "tcp"]
    for route in planned:
        if route.follows != ACTIVE:
            continue  # the data server's names aren't part of a slot's check
        match = next((p for p in published if int(p["container"]) == route.container
                      and (p.get("service") or "") == route.service), None)
        if match is None:
            out.append(SmokeTarget(route.hostname, None, "", route.health,
                                   problem=f"{_port_name(route)} is not published on {_host_name(instance)}"))
        else:
            out.append(SmokeTarget(route.hostname, int(match["host"]), _bind(match.get("host_ip")), route.health))
    return out


def _url(scheme: str, address: str, port: int | None, path: str) -> str:
    """``address`` is a host, an IP, or (the traffic address) either with ``:port``; a bare IPv6 gets brackets."""
    try:
        if ipaddress.ip_address(address).version == 6:
            address = f"[{address}]"
    except ValueError:
        pass
    path = path if path.startswith("/") else "/" + path
    return f"{scheme}://{address}{f':{port}' if port else ''}{path}"


TOOL_PROBE = ("if command -v curl >/dev/null 2>&1; then echo curl; "
              "elif command -v wget >/dev/null 2>&1; then echo wget; fi")


def smoke_command(tool: str, t: SmokeTarget) -> str:
    """One request to ``t`` on the slot's host, printing the HTTP status (redirects are not followed)."""
    q = shlex.quote
    url = _url("http", t.bind, t.port, t.health)
    if tool == "curl":
        return (f"curl -sS -o /dev/null -w '%{{http_code}}' --max-time 10 -H {q('Host: ' + t.hostname)} "
                f"-H 'X-Forwarded-Proto: https' {q(url)}")
    # wget follows redirects and can't be told not to everywhere (busybox), so the first status line counts.
    return (f"wget -q -S -O /dev/null -T 10 --header {q('Host: ' + t.hostname)} --header 'X-Forwarded-Proto: https' "
            f"{q(url)} 2>&1 | awk '/^  HTTP/{{if (!c) c=$2}} END{{print c}}'")


_CODE_RE = re.compile(r"^(\d{3})(?!\d)|(?<![\d.])(\d{3})$")


def _code(output: str) -> tuple[int | None, str]:
    """The status a smoke command printed (None when none came back) and the rest of its output.

    curl prints the three digits with no newline, and its error (when it couldn't connect) is mixed in
    before or after them, so the code is three digits at the start or end of a line.
    """
    code, rest = None, []
    for line in output.strip().splitlines():
        line = line.strip()
        found = _CODE_RE.search(line) if code is None else None
        if found:
            code = int(found.group(1) or found.group(2))
            line = (line[: found.start()] + line[found.end():]).strip()
        if line:
            rest.append(line)
    return (None if code == 0 else code), " ".join(rest)


def passes(code: int | None) -> bool:
    return code is not None and 200 <= code <= 399


async def smoke(remote: Any, instance: Instance, planned: Iterable[Route], *, say: Log = _quiet,
                tries: int = SMOKE_TRIES, delay: float = SMOKE_DELAY) -> CheckResult:
    """The slot smoke test (§10.8) over ``remote`` (an SSH session to the slot's host).

    Each failing name is tried again ``tries`` times in all, ``delay`` seconds apart; names that passed
    aren't asked again. Raises TrafficError when the host has neither curl nor wget.
    """
    targets = smoke_targets(instance, planned)
    host = _host_name(instance)
    result = CheckResult(ok=True)
    answers: dict[str, dict[str, Any]] = {}
    for t in targets:
        if t.problem:
            answers[t.hostname] = {"hostname": t.hostname, "error": t.problem}
    waiting = [t for t in targets if not t.problem]
    tool = ""
    if waiting:
        _, found = await remote.run(TOOL_PROBE, check=False, timeout=SMOKE_COMMAND_TIMEOUT)
        tool = found.strip().splitlines()[-1].strip() if found.strip() else ""
        if tool not in ("curl", "wget"):
            raise TrafficError(f"Neither curl nor wget is on {host}; install one")
    for attempt in range(1, tries + 1):
        if not waiting:
            break
        if attempt > 1:
            await sleep(delay)
        still = []
        for t in waiting:
            try:
                _, output = await remote.run(smoke_command(tool, t), check=False, timeout=SMOKE_COMMAND_TIMEOUT)
                code, rest = _code(output)
            except ssh.SSHError as exc:
                code, rest = None, str(exc)
            if passes(code):
                answers[t.hostname] = {"hostname": t.hostname, "code": code}
                await say(f"{t.hostname} answered {code} on {t.health}")
                continue
            answers[t.hostname] = ({"hostname": t.hostname, "code": code} if code is not None
                                   else {"hostname": t.hostname, "error": (rest or "no answer")[:300]})
            still.append(t)
        waiting = still
    for t in targets:
        answer = answers[t.hostname]
        result.results.append(answer)
        if t.problem:
            result.failures.append(f"{t.hostname}: {t.problem}")
        elif "error" in answer:
            result.failures.append(f"{t.hostname} didn't answer on {t.health} ({tries} tries): {answer['error']}")
        elif not passes(answer["code"]):
            result.failures.append(f"{t.hostname} answered {answer['code']} on {t.health} ({tries} tries)")
    result.ok = not result.failures
    return result


async def save_last_check(instance_id: uuid.UUID, check: CheckResult, deployment_id: uuid.UUID | None) -> None:
    """Keep a smoke test's results in ``slot_state.last_check`` (its own transaction)."""
    async with session_scope() as db:
        inst = await db.get(Instance, instance_id, with_for_update=True)
        if inst is None:
            return
        state = dict(inst.slot_state or {})
        state["last_check"] = {"ok": check.ok, "at": utcnow().isoformat(),
                               "deployment_id": str(deployment_id) if deployment_id else None,
                               "results": check.results}
        inst.slot_state = state


# -------------------------------------------------------------------- public check


def no_address(via: str) -> str:
    """Why the public check was skipped: there is no address to send the requests to."""
    if via == "Switchyard":
        return NO_TRAFFIC_ADDRESS
    return f"Slipway has no address for {via}, so the names weren't checked through it"


async def _ask(route: Route, address: str, *, insecure: bool = False) -> dict[str, Any]:
    """One request for ``route`` through the traffic path at ``address``, on a connection of its own."""
    verify = not insecure and route.tls_mode not in ("internal", "off")
    url = _url("http" if route.tls_mode == "off" else "https", address, None, route.health)
    try:
        async with httpx.AsyncClient(verify=verify, timeout=CHECK_TIMEOUT, follow_redirects=False,
                                     transport=transport_factory(verify)) as client:
            resp = await client.get(url, headers={"Host": route.hostname},
                                    extensions={"sni_hostname": route.hostname})
        return {"hostname": route.hostname, "code": resp.status_code}
    except httpx.HTTPError as exc:
        return {"hostname": route.hostname, "error": f"{type(exc).__name__}: {exc}"[:300]}


async def public_check(planned: Iterable[Route], address: str, *, say: Log = _quiet,
                       rounds: int = CHECK_ROUNDS, delay: float = CHECK_DELAY, insecure: bool = False,
                       via: str = "Switchyard") -> CheckResult:
    """Ask for every name at ``address`` (§10.8), as a visitor would; only failures are asked again.

    ``address`` is where the names are served: Switchyard's traffic address, or a load balancer's
    ``<ip>:443``. ``via`` names that path in the log and the skip text. ``insecure`` skips every
    certificate check (Let's Encrypt staging certificates), and says so. Skipped, with ``skipped`` set (a
    warning), when there is no address.
    """
    planned = list(planned)
    if not address:
        text = no_address(via)
        await say(text)
        return CheckResult(ok=True, skipped=text)
    if insecure:
        await say("Certificates aren't verified in this check: they are Let's Encrypt staging certificates")
    else:
        for route in planned:
            if route.tls_mode == "internal":
                await say(f"{route.hostname} uses {via}'s internal certificate, so it isn't verified")
    answers: dict[str, dict[str, Any]] = {}
    waiting = planned
    for n in range(1, rounds + 1):
        if not waiting:
            break
        if n > 1:
            await sleep(delay)
        still = []
        for route in waiting:
            answer = answers[route.hostname] = await _ask(route, address, insecure=insecure)
            if passes(answer.get("code")):
                await say(f"{route.hostname} answered {answer['code']} on {route.health} through {via}")
            else:
                still.append(route)
        waiting = still
    result = CheckResult(ok=not waiting, results=[answers[r.hostname] for r in planned])
    for route in waiting:
        answer = answers[route.hostname]
        if "error" in answer:
            result.failures.append(f"{route.hostname} didn't answer on {route.health} ({rounds} rounds): "
                                   f"{answer['error']}")
        else:
            result.failures.append(f"{route.hostname} answered {answer['code']} on {route.health} ({rounds} rounds)")
    return result


# ------------------------------------------------------------------ database probe


def _conninfo_value(value: Any) -> str:
    """A libpq connection-string value, quoted when it has to be."""
    text = str(value)
    if text and not re.search(r"[\s'\\]", text):
        return text
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


def probe_command(*, host: str, port: int, database: str, user: str, sslmode: str = "disable") -> str:
    """Sign in to the data server's database from the slot's host, the way the app's containers would.

    The password arrives on stdin (one line) and reaches docker through the environment, never argv.
    It uses Docker's default bridge, so the connection leaves the host as the app's does.
    """
    q = shlex.quote
    conninfo = " ".join(f"{k}={_conninfo_value(v)}" for k, v in (
        ("host", host), ("port", int(port)), ("dbname", database), ("user", user), ("sslmode", sslmode),
        ("connect_timeout", 10)))
    run = f"docker run --rm -e PGPASSWORD {PROBE_IMAGE} psql {q(conninfo)} -tAc 'select 1'"
    # Exit 97: nothing arrived on stdin. PGPASSWORD is set only in this shell, which execs docker.
    return f"{{ IFS= read -r PGPASSWORD || exit 97; export PGPASSWORD; exec {run}; }}"


_PG_HBA_RE = re.compile(r'no pg_hba\.conf entry for host "([^"]+)"')


def probe_problem(output: str, *, slot: Instance, env_name: str, host: str, port: int,
                  managed: bool = False) -> str:
    """The step's error when the probe failed: psql's last line and, for pg_hba, the LAN address to set. On a
    managed database (P4 §10.2) there is no pg_hba.conf or LAN address to set: its trusted sources let the slot's
    droplet in, so the text says to deploy the slot again (its ``database`` step puts them right)."""
    lines = [line.strip() for line in (output or "").splitlines() if line.strip()]
    last = lines[-1] if lines else "no answer"
    name = _host_name(slot)
    text = (f"{slot.name} on {name} can't sign in to {env_name}'s database at {host}:{port} "
            f"({last[:300]}).")
    if managed:
        return (text + f" The managed database lets in only the droplets in its trusted sources: deploy to "
                f"{slot.slot or slot.name} again, which sets them before anything uses the database")
    found = _PG_HBA_RE.search(output or "")
    if found:
        return (text + f' It says "no pg_hba.conf entry for host {found.group(1)}": set host {name}\'s '
                f"LAN address to {found.group(1)} and update the data server")
    return (text + ' If it says "no pg_hba.conf entry for host <address>", set host '
            f"{name}'s LAN address to that address and update the data server")


async def probe_database(remote: Any, slot: Instance, *, env_name: str, host: str, port: int, database: str,
                         user: str, password: str, sslmode: str = "disable",
                         scrub: Callable[[str], str] | None = None, managed: bool = False) -> str | None:
    """Run the probe on the slot's host; None when it signed in, else the step's error text. ``managed``: the
    database is a managed one (P4 §10.2, probed with ``sslmode=require``), whose failure text names no LAN
    address."""
    command = probe_command(host=host, port=port, database=database, user=user, sslmode=sslmode)
    try:
        status, output = await remote.run(command, check=False, timeout=PROBE_COMMAND_TIMEOUT,
                                          input=password + "\n", scrub=scrub)
    except ssh.SSHError as exc:
        status, output = -1, str(exc)
    if password:
        output = output.replace(password, "<hidden>")
    if status == 0 and output.strip().splitlines()[-1:] == ["1"]:
        return None
    return probe_problem(output, slot=slot, env_name=env_name, host=host, port=port, managed=managed)
