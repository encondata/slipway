"""The machines core (phase 5 §6): everything a VM provider (Proxmox, ESXi) plugs into.

A VM Slipway makes is an ordinary host (D1) with a ``machines`` row for what only the hypervisor needs. This
module plans that pair at create (``plan``), drives a deploy's ``prepare`` step (``prepare``: the provider makes,
continues or checks the VM, then the core pins its key, sets up Docker and marks it ready), applies a stored
resize in the deploy's own ``resize`` step (``resize_step``), keeps the address registry (``addresses_in_use``),
waits for hypervisor tasks it didn't start (``tasks.wait_idle``), records hypervisor ids so a retry finds them
(``reserve_vmid``, ``record_vm``) and removes or forgets a VM (``blockers``, ``remove``).

The host-level contract it plugs into is shared with phase 4's droplets (P4 §3.3): every stage change writes
``hosts.provider_state.phase`` in the same transaction (``set_stage``); ``SSHTarget.from_host`` and
``hosts.check_host`` are called with ``building=True`` only from ``prepare``; the owned-host and address-holder
checks are ``hosts.owned_host_refusal`` and ``hosts.address_holder``.

Writes that must outlive a failed step (a stage, an id, a task Slipway started, a pin) each commit in their own
session, before Slipway waits on the hypervisor (M5). ``plan`` is the exception: it writes in the caller's
transaction, so environment create and Add slot commit the host, its address claim and the machine together.

``tcp_open`` and ``resolve`` are the module's only network reaches outside SSH; the test guard replaces them by
these names, so call them through the module.
"""

from __future__ import annotations

import asyncio
import dataclasses
import ipaddress
import math
import re
import shlex
import socket
import uuid
from collections.abc import Awaitable, Callable
from contextlib import AbstractAsyncContextManager, suppress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar, Protocol
from urllib.parse import urlsplit

import asyncssh
from sqlalchemy import delete, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.core.config import get_settings
from slipway.db.base import utcnow
from slipway.db.session import get_sessionmaker, session_scope
from slipway.models import (
    AddressClaim,
    AppSetting,
    Deployment,
    Environment,
    Host,
    Instance,
    InstanceStatus,
    Machine,
    MachineSnapshot,
    MachineStage,
    ProviderAccount,
    Resource,
    TerraformState,
    User,
)
from slipway.services import audit, cloudinit, hosts, resources, ssh, terraform_store, vmnet
from slipway.services.providers import label as provider_label
from slipway.services.providers import provider_for
from slipway.services.vmtypes import Blocker, MachineError

Log = Callable[[str], Awaitable[None]]
ConnectFactory = Callable[[ssh.SSHTarget], AbstractAsyncContextManager[ssh.RemoteSession]]

# The port Slipway pins a VM's key on. Phase 5 test 18 points it at a real SSH server on 127.0.0.1.
SSH_PORT = 22
# The TCP probe before a new VM takes an address (§6.6) always asks the SSH port itself.
PROBE_PORT = 22
PROBE_TIMEOUT = 3.0
RESOLVE_TIMEOUT = 2.0

VM_KIND = "vm"  # resources.kind of a VM
RESERVE_TRIES = 20

# machines.stage -> hosts.provider_state.phase (§3.6): written together, in one transaction.
STAGE_PHASES = {
    MachineStage.PLANNED.value: hosts.PHASE_PLANNED,
    MachineStage.CREATING.value: hosts.PHASE_CREATING,
    MachineStage.BOOTING.value: hosts.PHASE_CREATING,
    MachineStage.READY.value: hosts.PHASE_READY,
    MachineStage.DESTROYING.value: hosts.PHASE_GONE,
}
_PHASE_STAGES = {hosts.PHASE_PLANNED: "planned", hosts.PHASE_CREATING: "creating", hosts.PHASE_READY: "ready",
                 hosts.PHASE_GONE: "destroying"}
SIZE_KEYS = ("cores", "memory_mb", "disk_gb")

# Each part of prepare and resize has its own time limit, in seconds (§14); the step's error names the part
# that ran out. Tests lower them.
PART_LIMITS: dict[str, float] = {
    "pin": 300, "sudo": 30, "cloud_init": 600, "docker": 1500, "service": 120, "group": 60, "folder": 30,
    "check": 60, "check_resize": 600, "start_release": 120,
}
PIN_POLL = 5.0  # seconds between SSH tries while pinning
PIN_TRIES = 60  # five minutes of tries
TASK_WAIT_LIMIT = 600.0  # waiting for a hypervisor task Slipway didn't start (D24)
TASK_POLL = 5.0

# Bootstrap (§6.5): every root command through sudo -n, naming the slipway user (cloudinit.GUEST_USER).
APT_LOCK = "-o DPkg::Lock::Timeout=600"
DOCKER_INSTALL = (
    "docker compose version >/dev/null 2>&1 || "
    f"{{ sudo -n apt-get {APT_LOCK} update -q && "
    f"sudo -n env DEBIAN_FRONTEND=noninteractive apt-get {APT_LOCK} install -y -q docker.io docker-compose-v2; }}"
)
DOCKER_SERVICE = "sudo -n systemctl enable --now docker"
DOCKER_CHECK = "docker info --format '{{.ServerVersion}}'"
LOCK_TEXT = "Could not get lock"


def group_command(user: str = cloudinit.GUEST_USER) -> str:
    return f"id -nG {user} | grep -qw docker || sudo -n usermod -aG docker {user}"


def folder_command(deploy_root: str, user: str = cloudinit.GUEST_USER) -> str:
    return f"sudo -n install -d -o {user} -g {user} -m 0755 {shlex.quote(deploy_root)}"


# ---------------------------------------------------------------------------------------------- types


class PlanProblem(ValueError):
    """``plan`` refuses a VM for a create or an Add slot: ``text`` for the person, ``field`` the body field."""

    def __init__(self, text: str, field: str) -> None:
        super().__init__(text)
        self.text = text
        self.field = field


@dataclass
class MachineContext:
    """What a provider gets for one VM in one job. ``machine`` and ``host`` are kept up to date by the core's
    writes (``set_stage``, ``write``, ``pin``); the provider never writes them itself."""

    machine: Machine
    host: Host
    account: ProviderAccount
    env: Environment
    deployment_id: uuid.UUID | None
    user_id: uuid.UUID | None
    say: Log
    hide: ssh.Redactor
    connect: ConnectFactory
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    now: Callable[[], datetime] = utcnow
    # Called once (then cleared) when the provider is about to change the VM: its ``tasks.wait_idle`` found the VM
    # idle, the last check before it starts a task, or at the latest a task it started was recorded. A VM revert
    # sets it to tell a revert that refused (and changed nothing) from one that may have moved the disk (§9.12).
    before_change: Callable[[], Awaitable[None]] | None = None

    @property
    def vm(self) -> str:
        return self.machine.name

    @property
    def label(self) -> str:
        return provider_label(self.machine.provider)

    @property
    def provider(self) -> MachineProvider:
        return provider_for(self.machine.provider)


@dataclass
class Ensured:
    address: str  # where the VM answers
    expected_key: str  # the OpenSSH public host key to pin
    how: str  # "read through the Proxmox guest agent" | "generated by Slipway"
    reread_key: Callable[[], Awaitable[str]] | None = None  # Proxmox while booting: read the key again (§6.4)
    warnings: list[str] = field(default_factory=list)


@dataclass
class ResizePlan:
    """What ``check_resize`` found; ``resize`` applies exactly this."""

    to: dict[str, Any]
    snapshot_first: bool = False
    drop_snapshots: list[str] = field(default_factory=list)
    changes: list[str] = field(default_factory=list)


@dataclass
class SnapshotView:
    name: str
    id: str | None = None
    created: datetime | None = None
    ours: bool = False  # recorded in machine_snapshots
    newest: bool = False


@dataclass
class MachineState:
    """A read-only view of the VM, for pages and refusals."""

    exists: bool
    ours: bool
    why_not_ours: str | None = None
    hidden: bool = False  # Proxmox: the recorded id is used but not visible (D25)
    power: str | None = None  # running | stopped | suspended
    busy: str | None = None  # a running task: "snapshot (started 10:02)" (D24)
    addresses: list[str] = field(default_factory=list)
    applied: dict[str, Any] | None = None
    snapshot_mode: str | None = None  # D23
    snapshots: list[SnapshotView] = field(default_factory=list)
    error: str | None = None  # "busy" or why the account couldn't be read


@dataclass(frozen=True)
class Busy:
    """A hypervisor task running on a VM (D24), or a lock no task holds any more (``task_id`` None)."""

    kind: str  # the task's type: clone, snapshot, rollback, shutdown...
    where: str  # what it runs on, for the texts: "VM 106", "slipway-uat-blue"
    started_at: datetime | None = None
    task_id: str | None = None
    lock: str | None = None
    vmid: int | None = None  # Proxmox: for the qm unlock hint

    @property
    def stale(self) -> bool:
        return self.task_id is None and self.lock is not None


class MachineProvider(Protocol):
    """One hypervisor's half of the machines core (§6.1). Every error is a ``MachineError`` with Slipway's own
    sentence; ``unreachable`` is set when the hypervisor couldn't be reached at all."""

    name: ClassVar[str]  # proxmox | esxi
    label: ClassVar[str]  # Proxmox | ESXi

    def clean_config(self, config: dict[str, Any], secret: str | None) -> dict[str, Any]: ...
    async def test(self, account: ProviderAccount) -> list[Any]: ...  # not used for accounts (Decision 34)
    def freeze(self, account: ProviderAccount, network: dict[str, Any]) -> dict[str, Any]: ...  # machines.spec
    async def ensure(self, ctx: MachineContext) -> Ensured: ...  # make, continue, start; never resizes
    async def after_pin(self, ctx: MachineContext) -> None: ...  # ESXi: scrub the user-data; Proxmox: nothing
    async def describe(self, ctx: MachineContext) -> MachineState: ...  # reads only
    async def running(self, ctx: MachineContext) -> list[Busy]: ...  # the VM's running tasks, for wait_idle
    async def check_resize(self, ctx: MachineContext) -> ResizePlan: ...  # reads only
    async def resize(self, ctx: MachineContext, plan: ResizePlan) -> dict[str, Any]: ...  # leaves the VM running
    async def snapshot(self, ctx: MachineContext, row: MachineSnapshot) -> bool: ...
    async def revert(self, ctx: MachineContext, row: MachineSnapshot) -> None: ...
    async def drop_snapshot(self, ctx: MachineContext, row: MachineSnapshot) -> None: ...
    async def stop(self, ctx: MachineContext, *, timeout: int) -> None: ...
    async def destroy_blockers(self, ctx: MachineContext) -> list[Blocker]: ...  # reads only
    async def destroy(self, ctx: MachineContext) -> list[str]: ...  # idempotent; what it did, for the log


# -------------------------------------------------------------------------------------------- helpers


def _duration(seconds: float) -> str:
    if seconds < 60:
        n = f"{seconds:g}"
        return f"{n} second" if n == "1" else f"{n} seconds"
    minutes = seconds / 60
    n = f"{minutes:g}" if minutes != int(minutes) else str(int(minutes))
    return f"{n} minute" if n == "1" else f"{n} minutes"


def _same_key(a: str | None, b: str | None) -> bool:
    """Two OpenSSH public key lines name the same key (the comment doesn't count)."""
    return bool(a and b) and a.split()[:2] == b.split()[:2]


def _sizes(value: dict[str, Any] | None) -> dict[str, int] | None:
    if not value:
        return None
    try:
        return {key: int(value[key]) for key in SIZE_KEYS}
    except (KeyError, TypeError, ValueError):
        return None


def size_differs(machine: Machine) -> bool:
    """The wanted size isn't the applied one (a pending resize)."""
    return _sizes(machine.size) != _sizes(machine.applied)


async def _actor(db: AsyncSession, user_id: uuid.UUID | None) -> User | None:
    return await db.get(User, user_id) if user_id else None


def _copy_columns(source: Any, target: Any) -> None:
    """Copy every column value of ``source`` onto ``target`` (the caller's copy of the same row)."""
    if target is None or source is target:
        return
    for column in type(source).__table__.columns:
        setattr(target, column.key, getattr(source, column.key))


def phase_for(stage: str) -> str:
    return STAGE_PHASES[str(stage)]


def stage_of(host: Host) -> str | None:
    """The machine stage of a VM host (from its ``provider_state``), or None for a host that isn't a VM."""
    if (host.provider or "ssh") not in vmnet.PROVIDERS:
        return None
    state = host.provider_state or {}
    return state.get("stage") or _PHASE_STAGES.get(state.get("phase") or hosts.PHASE_PLANNED)


def account_problem(account: ProviderAccount | None) -> str | None:
    """Why ``account`` can't be used now (no URL, no readable secret, no trusted certificate, removed), or None."""
    if account is None:
        return "it is gone"
    if account.removed_at is not None:
        return "it was removed"
    if not (account.config or {}).get("url"):
        return "it has no URL"
    if not account.secret:
        what = "API token" if account.provider == "proxmox" else "password"
        return f"its {what} is missing or can't be read with SLIPWAY_ENCRYPTION_KEY"
    if not (account.tls or {}).get("pem"):
        return "no certificate is trusted for it yet"
    return None


def account_refusal(account: ProviderAccount, why: str) -> str:
    return (f"{provider_label(account.provider)} account {account.name} can't be used: {why}. "
            "Fix it in Settings → Integrations, then retry.")


def lost_text(machine: Machine, *, env: Environment | None = None) -> str:
    """What a step answers for a ready VM the hypervisor doesn't have any more (M3), with the way out."""
    account = machine.account.name if machine.account is not None else "its account"
    env_name = env.name if env is not None else "the environment"
    holds_data = machine.slot == "data" or (env is not None and env.data_mode == "slot")
    if holds_data:
        return (f"{machine.name} is gone from {account}, and {env_name}'s data was on it. Slipway can't make it again "
                "without that data: delete the environment, and create it again from a snapshot if you have one")
    return (f"{machine.name} is gone from {account}. Slipway never makes a ready VM again by itself: use Forget "
            f"the VM on {env_name}, then deploy to {machine.slot} to make a new one")


# -------------------------------------------------------------------------------------------- writes


async def write(
    ctx: MachineContext, *, stage: str | None = None, audit_action: str | None = None, summary: str = "",
    details: dict[str, Any] | None = None, phase_fields: dict[str, Any] | None = None, **fields: Any,
) -> Machine:
    """Write machine columns (and, with ``stage``, the stage and the host's phase) in one transaction of their
    own, committed before this returns. ``phase_fields`` go into the host's ``provider_state`` beside the phase.
    ``ctx.machine`` and ``ctx.host`` are updated to match."""
    async with session_scope() as db:
        machine = await db.get(Machine, ctx.machine.id, with_for_update=True, populate_existing=True)
        if machine is None:
            raise MachineError(f"{ctx.vm} was removed meanwhile; Slipway changed nothing")
        host = await db.get(Host, machine.host_id, with_for_update=True, populate_existing=True)
        for key, value in fields.items():
            setattr(machine, key, value)
        if stage is not None:
            stage = MachineStage(stage).value
            machine.stage = stage
            if host is not None:
                hosts.set_phase(host, phase_for(stage), **{**(phase_fields or {}), "stage": stage})
        if audit_action:
            audit.record(db, audit_action, actor=await _actor(db, ctx.user_id), target=machine, summary=summary,
                         details=details)
    _copy_columns(machine, ctx.machine)
    if host is not None:
        _copy_columns(host, ctx.host)
    return machine


async def set_stage(ctx: MachineContext, stage: str, **fields: Any) -> Machine:
    """Move the machine to ``stage`` (with ``hosts.provider_state.phase`` in the same transaction, §3.6)."""
    return await write(ctx, stage=stage, **fields)


async def set_notice(env_id: uuid.UUID, text: str, *, deployment_id: uuid.UUID | None) -> bool:
    """Write a VM notice on the environment (P3's dict shape), unless its notice carries a chain follow-up
    (``next``): that one is never replaced (Decision 23). Returns whether it was written."""
    async with session_scope() as db:
        env = await db.get(Environment, env_id, with_for_update=True)
        if env is None:
            return False
        if (env.notice or {}).get("next"):
            return False
        env.notice = {"text": text, "at": utcnow().isoformat(),
                      "deployment_id": deployment_id.hex if deployment_id else None, "next": None}
        return True


class _Tasks:
    """Hypervisor tasks on a VM (§6.8): wait for one that runs, and record the ones Slipway starts (M5)."""

    async def wait_idle(
        self, ctx: MachineContext, *, read: Callable[[], Awaitable[list[Busy]]] | None = None,
        limit: float | None = None, poll: float | None = None,
    ) -> None:
        """Return once no task runs on the VM; wait up to ``limit`` seconds, then refuse. A lock no task holds
        refuses at once. ``read`` lists the running tasks (the provider's ``running`` by default). ``limit`` and
        ``poll`` default to ``TASK_WAIT_LIMIT`` and ``TASK_POLL`` as they are when called, so tests can lower
        them."""
        limit = TASK_WAIT_LIMIT if limit is None else limit
        poll = TASK_POLL if poll is None else poll
        reader = read or (lambda: ctx.provider.running(ctx))
        label = ctx.label
        waited = 0.0
        logged: set[tuple[str, str | None]] = set()
        while True:
            busy = await reader()
            if not busy:
                await self._before_change(ctx)
                return
            for task in busy:
                if task.stale:
                    hint = f' and run "qm unlock {task.vmid}"' if task.vmid is not None and label == "Proxmox" else ""
                    raise MachineError(f"{task.where} is locked ({task.lock}) with no task running; check it in "
                                       f"{label}{hint}, then retry")
            task = busy[0]
            when = task.started_at.strftime("%H:%M") if task.started_at else "earlier"
            if waited >= limit:
                if task.kind in ("clone", "qmclone"):
                    raise MachineError(f"{label} is still cloning {task.where}; Slipway changed nothing. "
                                       "Retry when it has finished")
                raise MachineError(f"{label} is still running {task.kind} on {task.where} (since {when}); Slipway "
                                   f"changed nothing. Wait for it to finish, or stop it in {label}, then retry")
            if (task.kind, task.task_id) not in logged:
                logged.add((task.kind, task.task_id))
                await ctx.say(f"Waiting for {label}'s {task.kind} task on {task.where} (started {when})")
            await ctx.sleep(poll)
            waited += poll

    async def started(self, ctx: MachineContext, task_id: str, kind: str) -> None:
        """Record a task Slipway just started, before it waits on it."""
        await self._before_change(ctx)
        await write(ctx, last_task={"id": task_id, "kind": kind, "started_at": ctx.now().isoformat(),
                                    "deployment_id": ctx.deployment_id.hex if ctx.deployment_id else None})

    async def _before_change(self, ctx: MachineContext) -> None:
        hook, ctx.before_change = ctx.before_change, None
        if hook is not None:
            await hook()

    async def ended(self, ctx: MachineContext) -> None:
        await write(ctx, last_task=None)


tasks = _Tasks()


# ----------------------------------------------------------------------------------- address registry


async def resolve(name: str) -> list[str]:
    """The IPv4 addresses ``name`` resolves to within 2 seconds; none when it doesn't resolve."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(name, None, family=socket.AF_INET, type=socket.SOCK_STREAM), RESOLVE_TIMEOUT
        )
    except (OSError, TimeoutError, UnicodeError):
        return []
    return sorted({str(info[4][0]) for info in infos})


async def tcp_open(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> bool:
    """Whether something accepts a TCP connection at ``host:port`` within ``timeout`` seconds."""
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, TimeoutError):
        return False
    writer.close()
    with suppress(Exception):
        await writer.wait_closed()
    return True


def _host_part(value: str | None) -> str | None:
    """A host name or address from a hostname, ``host:port`` or URL value."""
    text = (value or "").strip()
    if not text:
        return None
    if "://" in text:
        return urlsplit(text).hostname
    if text.startswith("["):
        return text[1:].split("]", 1)[0]
    if text.count(":") == 1:
        text = text.split(":", 1)[0]
    return text or None


async def _addresses_of(value: str | None, cache: dict[str, list[str]]) -> list[str]:
    """The IPv4 addresses a host field stands for: the literal itself, or what the name resolves to."""
    name = _host_part(value)
    if not name:
        return []
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        return [str(ip)] if ip.version == 4 else []
    if name.endswith(".invalid"):  # a droplet's placeholder: it never resolves
        return []
    if name not in cache:
        cache[name] = list(await resolve(name))
    return cache[name]


async def addresses_in_use(
    db: AsyncSession, *, network: dict[str, Any] | None = None, except_host_id: uuid.UUID | None = None,
) -> dict[str, str]:
    """Every address in use (§6.6), with what holds it as the end of a sentence (``is used by host pve1``).

    Claims; every host's ``hostname``, ``proxy_address`` and ``lan_address`` (names resolved); each Proxmox and
    ESXi account's API host; Switchyard's URL and traffic address; and ``network``'s gateway and DNS servers.
    Read under no lock: the claim's primary key is the lock. ``except_host_id`` leaves out a host's own claim and
    row (a VM checking its own address again).
    """
    held: dict[str, str] = {}

    def put(address: str, phrase: str) -> None:
        held.setdefault(address, phrase)

    claims = (await db.execute(
        select(AddressClaim.address, AddressClaim.host_id, Host.name, Machine.slot, Environment.name.label("env"))
        .join(Host, Host.id == AddressClaim.host_id)
        .outerjoin(Machine, Machine.host_id == Host.id)
        .outerjoin(Environment, Environment.id == Machine.environment_id)
    )).all()
    for row in claims:
        if row.host_id == except_host_id:
            continue
        put(row.address, f"is reserved for {row.env}'s {row.slot} VM" if row.slot else f"is reserved for host {row.name}")

    cache: dict[str, list[str]] = {}
    rows = (await db.execute(
        select(Host.id, Host.name, Host.hostname, Host.proxy_address, Host.lan_address).order_by(Host.name)
    )).all()
    for row in rows:
        if row.id == except_host_id:
            continue
        for value in (row.hostname, row.proxy_address, row.lan_address):
            for address in await _addresses_of(value, cache):
                put(address, f"is used by host {row.name}")

    accounts = await db.scalars(
        select(ProviderAccount).where(ProviderAccount.provider.in_(vmnet.PROVIDERS), ProviderAccount.removed_at.is_(None))
    )
    for account in accounts:
        for address in await _addresses_of((account.config or {}).get("url"), cache):
            put(address, f"is the {provider_label(account.provider)} API's address")

    setting = await db.scalar(select(AppSetting).where(AppSetting.key == "switchyard"))
    value = (setting.value if setting is not None else None) or {}
    for address in await _addresses_of(value.get("traffic_address"), cache):
        put(address, "is Switchyard's traffic address")
    for address in await _addresses_of(value.get("url"), cache):
        put(address, "is Switchyard's address")

    if network:
        if network.get("gateway"):
            put(network["gateway"], "is the network's gateway")
        for server in network.get("dns_servers") or []:
            put(server, "is one of the network's DNS servers")
    return held


async def address_problem(
    db: AsyncSession, address: str, *, network: dict[str, Any] | None = None, except_host_id: uuid.UUID | None = None,
) -> str | None:
    """``<address> is used by host <name>`` (or another holder), or None when the address is free."""
    phrase = (await addresses_in_use(db, network=network, except_host_id=except_host_id)).get(address)
    return f"{address} {phrase}" if phrase else None


def claim(db: AsyncSession, host: Host, address: str) -> AddressClaim:
    """Claim ``address`` for ``host`` in the caller's transaction (the primary key is the lock)."""
    row = AddressClaim(address=address, host_id=host.id)
    db.add(row)
    return row


async def check_address_free(ctx: MachineContext, *, probe: bool = True) -> None:
    """Before a new VM boots (§6.6, §7.4 C1): the registry once more (leaving out this VM's own claim and host),
    then the TCP probe of ``<address>:22`` unless ``probe`` is off (the VM there is the machine's own)."""
    address = ctx.machine.network["address"]
    async with get_sessionmaker()() as db:
        problem = await address_problem(db, address, network=ctx.machine.network, except_host_id=ctx.host.id)
    if problem:
        raise MachineError(f"{problem}, so Slipway won't give it to {ctx.vm}. Slipway changed nothing")
    if probe:
        await probe_address(ctx)


async def probe_address(ctx: MachineContext) -> None:
    """The TCP probe of ``<address>:22`` before a new VM takes its address (§6.6), when ``vm_address_probe`` is
    on. ESXi runs it after its guest-IP check (§8.2 E4); ``check_address_free`` runs it after the registry."""
    address = ctx.machine.network["address"]
    if get_settings().vm_address_probe and await tcp_open(address, PROBE_PORT, PROBE_TIMEOUT):
        raise MachineError(f"Something already answers SSH at {address}, so Slipway won't give that address to a new "
                           "VM. Free it, or recreate the environment with another address")


async def unpin(ctx: MachineContext, why: str) -> None:
    """Forget the host's pinned key (own transaction, audited ``host.key_reset``): a VM Slipway makes again gets
    a new key, which ``pin`` pins only by its compare-and-set on an empty or equal key."""
    async with session_scope() as db:
        host = await db.get(Host, ctx.host.id, with_for_update=True, populate_existing=True)
        if host is None or not host.host_key:
            return
        old = host.host_key_fingerprint or ssh.fingerprint(host.host_key)
        host.host_key = None
        host.host_key_fingerprint = None
        audit.record(db, "host.key_reset", actor=await _actor(db, ctx.user_id), target=host,
                     summary=f"Reset pinned key {old} for {host.name}: {why}",
                     details={"fingerprint": old, "why": why})
    ctx.host.host_key = None
    ctx.host.host_key_fingerprint = None


# -------------------------------------------------------------------------------------------- planning


def _host_key_pair(name: str) -> tuple[str, str]:
    """An ed25519 host key pair for an ESXi VM (§6.2 step 3): (private, public)."""
    key = asyncssh.generate_private_key("ssh-ed25519", comment=f"root@{name}")
    return key.export_private_key("openssh").decode(), key.export_public_key("openssh").decode().strip()


async def plan(
    db: AsyncSession, env: Environment, slot: str, account: ProviderAccount, network: dict[str, Any] | str,
    address: str | None, size: dict[str, Any] | None, user: User | None, *,
    provider: MachineProvider | None = None, deploy_root: str | None = None, keep_vm_snapshots: int | None = None,
) -> tuple[Host, Machine]:
    """Plan ``env``'s ``slot`` VM (§6.2) in the caller's transaction: the planned host, its address claim and the
    machine row (``planned``, with the spec, network and size frozen). Touches no hypervisor.

    ``network`` is one of the account's network profiles or its name; ``address`` a typed address or ``auto``
    (the lowest free pool address). Raises ``PlanProblem`` naming the body field. Nothing is flushed here, so a
    claim taken by another environment meanwhile surfaces as an ``IntegrityError`` at the caller's commit.
    """
    base = f"hosts.{slot}.machine"
    if account.provider not in vmnet.PROVIDERS:
        raise PlanProblem(f"{account.name} is a {provider_label(account.provider)} account, not a Proxmox or ESXi "
                          "one", field=f"{base}.account")
    if account.removed_at is not None:
        raise PlanProblem(f"{account.name} was removed: add the account again first", field=f"{base}.account")
    if slot not in vmnet.SLOTS:
        raise PlanProblem(f"{slot!r} isn't a slot: use blue, green or data", field=f"hosts.{slot}")
    profile = network if isinstance(network, dict) else vmnet.find_network((account.config or {}).get("networks") or [],
                                                                         network)
    if profile is None:
        raise PlanProblem(f"{account.name} has no network named {network}", field=f"{base}.network")
    try:
        name = vmnet.vm_name(env.name, slot)
    except ValueError as exc:
        raise PlanProblem(str(exc), field="name") from None
    clash = await hosts.name_clash(db, name)
    if clash:
        raise PlanProblem(clash, field=f"hosts.{slot}")

    held = await addresses_in_use(db, network=profile)
    try:
        if address in (None, "", "auto"):
            address = vmnet.allocate(profile, held.__contains__)
        else:
            address = vmnet.check_address(address, profile)
    except ValueError as exc:
        raise PlanProblem(str(exc), field=f"{base}.address") from None
    if address in held:
        raise PlanProblem(f"{address} {held[address]}", field=f"{base}.address")
    try:
        wanted = vmnet.check_size(size)
        keep = vmnet.check_keep_vm_snapshots(
            keep_vm_snapshots if keep_vm_snapshots is not None else vmnet.DEFAULT_KEEP_VM_SNAPSHOTS
        )
    except ValueError as exc:
        raise PlanProblem(str(exc), field=f"{base}.size") from None
    provider = provider or provider_for(account.provider)
    spec = provider.freeze(account, profile)

    if env.id is None:
        await db.flush()
    host = hosts.planned_host(
        env.name, slot, provider=account.provider, hostname=address, deploy_root=deploy_root,
        description=f"VM Slipway made for {env.name}'s {slot} slot on {account.name}",
    )
    host.id = uuid.uuid4()  # set now, so nothing needs a flush before the caller's commit
    host.owner_environment_id = env.id
    host.created_by_id = user.id if user is not None else None
    hosts.set_phase(host, hosts.PHASE_PLANNED, stage=MachineStage.PLANNED.value)
    machine = Machine(
        id=uuid.uuid4(), environment_id=env.id, host_id=host.id, account_id=account.id, provider=account.provider,
        slot=slot, name=name, stage=MachineStage.PLANNED.value, spec=spec,
        network=vmnet.frozen_network(profile, address), size=wanted, applied=None, ids={},
        keep_vm_snapshots=keep, created_by_id=user.id if user is not None else None,
    )
    if account.provider == "esxi":
        machine.host_key_private, machine.host_key_public = _host_key_pair(name)
    db.add(host)
    claim(db, host, address)
    db.add(machine)
    audit.record(
        db, "machine.plan", actor=user, target=machine,
        summary=f"Planned {name} for {env.name}'s {slot} slot at {address} on {account.name}",
        details={"environment": env.name, "slot": slot, "account": account.name, "network": profile.get("name"),
                 "address": address, "size": wanted},
    )
    return host, machine


# ------------------------------------------------------------------------------------------------- pin


async def pin(
    host: Host, *, address: str, expected_key: str, how: str, connect: ConnectFactory,
    tries: int = PIN_TRIES, poll: float = PIN_POLL, sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    reread_key: Callable[[], Awaitable[str]] | None = None, machine: Machine | None = None,
    user_id: uuid.UUID | None = None, vm: str | None = None,
) -> str:
    """Pin ``host``'s key only after an SSH connection to ``address`` that presents ``expected_key`` (§6.4, M4).

    Refused at another host row's address. A refused or timed-out connection (or a failed sign-in while
    cloud-init may still be making the user) is tried again every ``poll`` seconds, ``tries`` times. Another key
    fails at once, unless ``reread_key`` is given (a Proxmox VM still booting): then the key is read again and
    the loop goes on. The pin is a compare-and-set on the host's address and key. Returns the pinned key.
    """
    vm = vm or host.name
    async with get_sessionmaker()() as db:
        holder = await hosts.address_holder(db, address, except_host_id=host.id)
    if holder is not None:
        raise MachineError(f"{address} is the address of host {holder.name}; Slipway won't pin a VM's key there")
    mismatch = f"The VM at {address} answered SSH with a key that isn't the one {how}. Slipway pinned nothing."
    try:
        ssh.fingerprint(expected_key)
    except Exception:
        raise MachineError(f"The host key Slipway expects for {vm} isn't a key it can use. Slipway pinned nothing.") from None

    mismatched = False
    for attempt in range(max(1, tries)):
        target = dataclasses.replace(
            ssh.SSHTarget.from_host(host, building=True), hostname=address, port=SSH_PORT, pinned_host_key=expected_key
        )
        try:
            async with connect(target) as session:
                await session.run("true", timeout=30)
        except ssh.HostKeyMismatch:
            if reread_key is None:
                raise MachineError(mismatch) from None
            mismatched = True
            fresh = await reread_key()
            if fresh and not _same_key(fresh, expected_key):
                ssh.fingerprint(fresh)  # a key Slipway can use, or this raises
                expected_key = fresh
                if machine is not None:
                    await _write_machine(machine, host_key_public=fresh)
        except (ssh.SSHError, OSError, TimeoutError):
            pass
        else:
            break
        if attempt + 1 < tries:
            await sleep(poll)
    else:
        if mismatched:
            raise MachineError(mismatch)
        minutes = max(1, math.ceil(tries * poll / 60))
        raise MachineError(f"{vm} didn't answer SSH at {address} in {minutes} minute{'s' if minutes != 1 else ''}")

    fingerprint = ssh.fingerprint(expected_key)
    async with session_scope() as db:
        result = await db.execute(
            update(Host)
            .where(Host.id == host.id, Host.hostname == address, Host.port == host.port,
                   or_(Host.host_key.is_(None), Host.host_key == expected_key))
            .values(host_key=expected_key, host_key_fingerprint=fingerprint)
        )
        if result.rowcount != 1:
            raise MachineError(f"{host.name} changed while Slipway was pinning it; Slipway pinned nothing")
        audit.record(
            db, "host.key_pinned", actor=await _actor(db, user_id), target=host,
            summary=f"Pinned host key {fingerprint} for {host.name}",
            details={"how": how, "fingerprint": fingerprint, "address": address},
        )
    host.host_key, host.host_key_fingerprint = expected_key, fingerprint
    return expected_key


async def _write_machine(machine: Machine, **fields: Any) -> None:
    """Write machine columns in their own transaction (outside a job's context) and update ``machine``."""
    async with session_scope() as db:
        row = await db.get(Machine, machine.id, with_for_update=True, populate_existing=True)
        if row is None:
            return
        for key, value in fields.items():
            setattr(row, key, value)
    for key, value in fields.items():
        setattr(machine, key, value)


# ------------------------------------------------------------------------------------------- bootstrap


def _last_line(output: str) -> str:
    lines = [line.strip() for line in (output or "").splitlines() if line.strip()]
    return ssh.clip(lines[-1], 300) if lines else "no output"


async def _run_part(
    ctx: MachineContext, session: ssh.RemoteSession, part: str, command: str, *, what: str,
    timeout_text: str | None = None, stream: bool = False,
) -> tuple[int, str]:
    """Run one bootstrap command within its part's limit; a limit that runs out raises its own text."""
    limit = PART_LIMITS[part]
    text = timeout_text or f"Timed out after {_duration(limit)} {what} on {ctx.vm}"
    try:
        async with asyncio.timeout(limit):
            return await session.run(command, check=False, timeout=limit, scrub=ctx.hide.scrub,
                                     on_line=ctx.say if stream else None)
    except TimeoutError:
        raise MachineError(text) from None
    except ssh.SSHError as exc:
        if "timed out" in str(exc):
            raise MachineError(text) from None
        raise MachineError(f"Slipway lost its SSH connection to {ctx.vm} while {what}: {exc}") from None


async def bootstrap(ctx: MachineContext) -> str:
    """Set up a new VM for Slipway over SSH with its pinned key (§6.5): sudo, cloud-init, Docker from Ubuntu's
    archive, the service, the slipway user in the docker group, the deploy root, then Docker checked in a new
    session. Every part is safe to run again. Returns Docker's version."""
    vm, user = ctx.vm, cloudinit.GUEST_USER
    target = ssh.SSHTarget.from_host(ctx.host, building=True)
    try:
        async with ctx.connect(target) as session:
            await ctx.say(f"Setting up {vm}: sudo, cloud-init, Docker")
            code, _ = await _run_part(ctx, session, "sudo", "sudo -n true", what="checking sudo")
            if code != 0:
                raise MachineError(f"{vm}'s {user} user can't use sudo without a password; check the template's "
                                   "cloud-init")
            code, out = await _run_part(
                ctx, session, "cloud_init", "cloud-init status --wait", what="waiting for cloud-init",
                timeout_text=f"cloud-init didn't finish on {vm} in {_duration(PART_LIMITS['cloud_init'])}",
            )
            if code not in (0, 2):
                raise MachineError(f"cloud-init reported an error on {vm}: {_last_line(out)}")
            code, out = await _run_part(ctx, session, "docker", DOCKER_INSTALL, what="installing Docker", stream=True)
            if code != 0:
                if LOCK_TEXT in out:
                    raise MachineError(f"Something on {vm} (usually unattended-upgrades) held the package lock for "
                                       "10 minutes; retry the deploy")
                raise MachineError(f"Couldn't install Docker on {vm}: {_last_line(out)}")
            code, out = await _run_part(ctx, session, "service", DOCKER_SERVICE, what="starting Docker")
            if code != 0:
                raise MachineError(f"Couldn't start Docker on {vm}: {_last_line(out)}")
            code, out = await _run_part(ctx, session, "group", group_command(user),
                                        what=f"adding the {user} user to the docker group")
            if code != 0:
                raise MachineError(f"Couldn't add the {user} user to the docker group on {vm}: {_last_line(out)}")
        # A new session, so the slipway user's docker group counts.
        async with ctx.connect(target) as session:
            code, out = await _run_part(ctx, session, "folder", folder_command(ctx.host.deploy_root, user),
                                        what=f"creating {ctx.host.deploy_root}")
            if code != 0:
                raise MachineError(f"Couldn't create {ctx.host.deploy_root} on {vm}: {_last_line(out)}")
            code, out = await _run_part(ctx, session, "check", DOCKER_CHECK, what="checking Docker")
            version = _last_line(out) if code == 0 else ""
            if code != 0 or not version or version == "no output":
                raise MachineError(f"Docker on {vm} doesn't answer for the {user} user")
    except ssh.SSHError as exc:
        raise MachineError(f"Slipway couldn't reach {vm} over SSH to set it up: {exc}") from None
    await ctx.say(f"Docker {version} is ready on {vm}")
    return version


# --------------------------------------------------------------------------------------------- prepare


async def _failed(ctx: MachineContext, text: str, *, unreachable: bool = False) -> MachineError:
    """Keep ``text`` as the machine's ``last_error`` (own transaction) and return the error to raise."""
    with suppress(MachineError):
        await write(ctx, last_error=ssh.clip(text, 500))
    return MachineError(text, unreachable=unreachable)


async def shielded[T](coro: Awaitable[T]) -> T:
    """Run ``coro`` to its end even when the caller is cancelled meanwhile (P3's shielded cancel), then
    re-raise that cancel. Used for what must follow a cut-off change: starting a VM again after its shutdown,
    and recording what a cut-off resize or snapshot left."""
    task = asyncio.ensure_future(coro)
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            if not task.done():
                cancelled = True
        except BaseException:  # the task's own failure: read below
            break
    if cancelled:
        raise asyncio.CancelledError
    return task.result()


async def _check_host(ctx: MachineContext) -> None:
    """``hosts.check_host(..., building=True)`` (Decision 6): Docker's version, the OS and metrics, after the pin
    and the bootstrap, before the stage is ready. It never pins a provider host."""
    async with get_sessionmaker()() as db:
        host = await db.get(Host, ctx.host.id, populate_existing=True)
        if host is None:
            raise MachineError(f"{ctx.vm}'s host was removed meanwhile; Slipway changed nothing")
        checked = await hosts.check_host(db, host, building=True)
    if checked is not None:
        _copy_columns(checked, ctx.host)


async def prepare(ctx: MachineContext, *, resize: bool = False) -> tuple[str, str | None]:
    """The ``prepare`` step of a deploy to a VM member (§6.3), right after ``resolve``.

    The provider makes, continues or checks the VM; the core pins its key, bootstraps a new VM, fills the host's
    facts and marks it ready. It never stops a made VM and never resizes; ``resize`` (the job lists a ``resize``
    step) runs the provider's read-only resize checks. Returns ``(status, note)``: ``succeeded``, or ``warning``
    for a ready VM whose hypervisor couldn't be checked (the deploy goes on over SSH). Raises ``MachineError``;
    its text is kept as ``last_error``.
    """
    machine = ctx.machine
    vm, label, account = ctx.vm, ctx.label, ctx.account.name
    if machine.stage == MachineStage.DESTROYING:
        raise MachineError(f"{vm} is being removed; only the retry of that removal can run")
    ready = machine.stage == MachineStage.READY
    pending = resize and ready and size_differs(machine)

    why = account_problem(ctx.account)
    if why:
        if ready and not pending:
            note = f"Couldn't check {vm} on {account} ({why}); carrying on over SSH"
            await ctx.say(note)
            return "warning", note
        raise await _failed(ctx, account_refusal(ctx.account, why))

    provider = ctx.provider
    try:
        ensured = await provider.ensure(ctx)
    except MachineError as exc:
        if exc.unreachable and ready:
            if pending:
                raise await _failed(ctx, f"Slipway can't reach {account} to resize {vm}", unreachable=True) from None
            note = f"Couldn't reach {label} to check {vm}; carrying on over SSH"
            await ctx.say(note)
            return "warning", note
        raise await _failed(ctx, exc.text, unreachable=exc.unreachable) from None

    try:
        notes: list[str] = []
        if not ctx.host.host_key or not _same_key(ensured.expected_key, ctx.host.host_key):
            try:
                async with asyncio.timeout(PART_LIMITS["pin"]):
                    await pin(ctx.host, address=ensured.address, expected_key=ensured.expected_key, how=ensured.how,
                              connect=ctx.connect, sleep=ctx.sleep, reread_key=ensured.reread_key,
                              machine=ctx.machine, user_id=ctx.user_id, vm=vm)
            except TimeoutError:
                raise MachineError(f"Timed out after {_duration(PART_LIMITS['pin'])} pinning {vm}'s host key") from None
            await ctx.say(f"Pinned {vm}'s host key ({ensured.how})")
            await provider.after_pin(ctx)

        if ctx.machine.stage != MachineStage.READY:
            await bootstrap(ctx)
            await _check_host(ctx)
            state = await provider.describe(ctx)
            applied = {**(_sizes(state.applied) or _sizes(ctx.machine.size) or {}), "at": ctx.now().isoformat(),
                       "deployment_id": ctx.deployment_id.hex if ctx.deployment_id else None}
            await set_stage(
                ctx, MachineStage.READY.value, ready_at=ctx.now(), applied=applied, snapshot_mode=state.snapshot_mode,
                last_error=None, audit_action="machine.ready",
                summary=f"{vm} is ready at {ensured.address}",
                details={"name": vm, "address": ensured.address, "applied": _sizes(applied)},
            )
            notes.append(f"{vm} is ready at {ensured.address}")
        elif ctx.machine.last_error:
            await write(ctx, last_error=None)

        if pending:
            try:
                async with asyncio.timeout(PART_LIMITS["check_resize"]):
                    await provider.check_resize(ctx)
            except TimeoutError:
                raise MachineError(f"Timed out after {_duration(PART_LIMITS['check_resize'])} checking the resize "
                                   f"of {vm}") from None
            except MachineError as exc:
                before = vmnet.size_text(_sizes(ctx.machine.applied) or ctx.machine.size)
                raise MachineError(f"{exc.text.rstrip('.')}. To deploy without the resize, set {vm}'s size back to "
                                   f"{before} on the environment page", unreachable=exc.unreachable) from None
            notes.append(f"{vm} is resized to {vmnet.size_text(ctx.machine.size)} after the backup")
    except MachineError as exc:
        raise await _failed(ctx, exc.text, unreachable=exc.unreachable) from None
    except ssh.SSHError as exc:
        raise await _failed(ctx, f"Slipway lost its SSH connection to {vm}: {exc}") from None

    if ensured.warnings:
        return "warning", " ".join([*notes, *ensured.warnings])
    return "succeeded", " ".join(notes) or None


# ----------------------------------------------------------------------------- shared provider helpers


async def snapshots_allowed(ctx: MachineContext) -> bool:
    """D11: VM snapshots exist only for one app slot, in data mode ``slot``, on a VM (never the data VM)."""
    if ctx.machine.slot == "data" or ctx.env.data_mode != "slot":
        return False
    async with get_sessionmaker()() as db:
        slots = set(await db.scalars(select(Instance.slot).where(Instance.environment_id == ctx.env.id)))
    return len(slots & {"blue", "green"}) <= 1


async def pre_resize_row(ctx: MachineContext) -> MachineSnapshot:
    """The ``pre_resize`` VM snapshot's row, committed ``pending`` before its task starts (M5), for both providers:
    ``vm_jobs.new_row``'s, so it holds the slot instance's commit, app state and fresh data, the data owner's
    identity values and their fingerprint, its ready backups and the size before the resize. A revert to it then
    keeps the identity guard of the data on the VM (§9.7)."""
    from slipway.services import vm_jobs  # vm_jobs imports this module

    return await vm_jobs.new_row(ctx, reason="pre_resize", note="Before a resize")


GROWPART_SLACK = 2  # GB a root file system may be under ``disk_gb - 2`` before the warning
DF_COMMAND = "df -BG --output=size / | tail -1"


async def growpart_warning(ctx: MachineContext, disk_gb: int) -> str | None:
    """After a disk grow (§7.5 step 5, §8.3 step 5): the warning when the root file system didn't grow with
    the disk, or None. Never raises: a VM that can't be read is no reason to fail a finished resize."""
    try:
        async with ctx.connect(ssh.SSHTarget.from_host(ctx.host)) as session:
            code, out = await session.run(DF_COMMAND, check=False, timeout=30, scrub=ctx.hide.scrub)
    except (ssh.SSHError, OSError, TimeoutError):
        return None
    lines = (out or "").strip().splitlines()
    match = re.fullmatch(r"\s*(\d+)G\s*", lines[-1]) if code == 0 and lines else None
    if match is None or int(match.group(1)) >= disk_gb - 2 - GROWPART_SLACK:
        return None
    return (f"{ctx.vm}'s disk grew to {disk_gb} GB but its root file system is {match.group(1)} GB: cloud-init's "
            "growpart didn't run; run \"sudo growpart /dev/sda 1 && sudo resize2fs /dev/sda1\" on it")


# ---------------------------------------------------------------------------------------------- resize


async def _slot_instance(db: AsyncSession, machine: Machine) -> Instance | None:
    return await db.scalar(
        select(Instance).where(Instance.environment_id == machine.environment_id, Instance.slot == machine.slot)
    )


async def resize_rule(db: AsyncSession, machine: Machine) -> str | None:
    """Why a stored resize can't apply to ``machine`` now (§9.4, M8), or None when it may.

    The data server's VM keeps its size once ready; the active slot of two waits until it is idle.
    """
    if machine.slot == "data":
        return ("The data server's VM keeps its size: both slots' data is on it. docs/machines.md shows how to grow "
                "it by hand")
    env = await db.get(Environment, machine.environment_id)
    instance = await _slot_instance(db, machine)
    if env is None or instance is None or env.active_slot_id != instance.id:
        return None
    apps = await db.scalars(
        select(Instance.slot).where(Instance.environment_id == env.id, Instance.slot.in_(("blue", "green")))
    )
    if len(list(apps)) >= 2:
        return f"{machine.slot} takes the traffic now; the resize waits"
    return None


async def resize_due(db: AsyncSession, machine: Machine) -> bool:
    """Whether a deploy of ``machine``'s slot lists the ``resize`` step (§9.4's rule at queue time)."""
    return machine.stage == MachineStage.READY and size_differs(machine) and await resize_rule(db, machine) is None


async def left_off(ctx: MachineContext, why: str) -> None:
    """A resize may have left the VM off (§6.7, §9.12): the environment's notice says so (Decision 23's rule),
    ``last_error`` keeps why, and ``machine.left_off`` is audited."""
    text = f"{ctx.vm} was left off during a resize: deploy to {ctx.machine.slot} again to finish it"
    await set_notice(ctx.env.id, text, deployment_id=ctx.deployment_id)
    await write(ctx, last_error=ssh.clip(why, 500), audit_action="machine.left_off", summary=text,
                details={"name": ctx.vm, "why": ssh.clip(why, 300)})


RESIZED_SSH_WAIT = 300.0  # seconds a resized VM's sshd is given to answer with the pinned key (§7.5, §8.3)


async def check_resized(ctx: MachineContext, *, limit: float | None = None, poll: float = PIN_POLL) -> None:
    """A resized VM answers SSH with its pinned key: tried every ``poll`` seconds for ``limit`` (the agent or
    VMware Tools can report the address before sshd listens). A different key fails at once."""
    vm = ctx.vm
    tries = max(1, math.ceil((RESIZED_SSH_WAIT if limit is None else limit) / poll)) if poll > 0 else 1
    for attempt in range(tries):
        try:
            async with ctx.connect(ssh.SSHTarget.from_host(ctx.host)) as session:  # the same pinned key
                await session.run("true", timeout=30)
            return
        except ssh.HostKeyMismatch as exc:
            raise MachineError(f"{vm} is resized, but Slipway couldn't reach it over SSH with its pinned key: "
                               f"{exc}") from None
        except (ssh.SSHError, OSError, TimeoutError) as exc:
            if attempt + 1 >= tries:
                raise MachineError(f"{vm} is resized, but Slipway couldn't reach it over SSH with its pinned key: "
                                   f"{exc}") from None
        await ctx.sleep(poll)


async def _cut_pre_resize(ctx: MachineContext) -> None:
    """A resize cut off while its ``pre_resize`` VM snapshot was being taken: that row is failed, not left
    ``pending``, as ``vm_jobs._VmRun.take`` does for a VM job (§6.7). Delete and Revert then don't refuse it as
    still being taken, prune counts it, and the next VM job's settle makes it ready if the snapshot is there.
    Never raises."""
    with suppress(Exception):
        async with session_scope() as db:
            await db.execute(
                update(MachineSnapshot)
                .where(MachineSnapshot.machine_id == ctx.machine.id, MachineSnapshot.reason == "pre_resize",
                       MachineSnapshot.status == "pending",
                       MachineSnapshot.deployment_id == ctx.deployment_id if ctx.deployment_id is not None
                       else MachineSnapshot.deployment_id.is_(None))
                .values(status="failed"))


async def _after_failed_resize(ctx: MachineContext, before: dict[str, int] | None, why: str, *,
                               cut_off: bool = False) -> None:
    """What a failed or cut-off resize left, read from the hypervisor (§6.7): ``applied`` takes the size the VM
    has now when the change went through part or all of the way (so the next deploy doesn't power it off for a
    plan with nothing left to change), and a VM that isn't running is left off (the notice, ``machine.left_off``).
    A cut-off resize also keeps ``why`` as ``last_error``. Never raises: the resize's own failure is reported."""
    state = None
    with suppress(Exception):
        state = await ctx.provider.describe(ctx)
    now = _sizes(state.applied) if state is not None and state.exists and state.ours else None
    with suppress(Exception):
        if now is not None and now != before:
            await write(ctx, applied={**now, "at": ctx.now().isoformat(),
                                      "deployment_id": ctx.deployment_id.hex if ctx.deployment_id else None})
        if state is None or state.power != "running":
            await left_off(ctx, why)
        elif cut_off:
            await write(ctx, last_error=ssh.clip(why, 500))


async def _start_live_release(ctx: MachineContext, instance: Instance) -> None:
    """Start the live release's projects again (the control action), so the old release runs until ``start``."""
    from slipway.services import deployer  # the deployer imports this module

    command = deployer.control_command(instance, "start")
    await ctx.say(f"$ {command}")
    async with ctx.connect(ssh.SSHTarget.from_host(ctx.host)) as session:
        async with asyncio.timeout(PART_LIMITS["start_release"]):
            await session.run(command, timeout=PART_LIMITS["start_release"], scrub=ctx.hide.scrub, on_line=ctx.say)


async def resize_step(
    ctx: MachineContext, *, instance: Instance | None = None,
    start_release: Callable[[Instance], Awaitable[None]] | None = None,
) -> tuple[str, str | None]:
    """The ``resize`` step of a deploy (§6.7), after ``backup``: apply the stored size, then start the live
    release again when the instance runs. ``start_release`` starts it (by default the control action over SSH;
    the deployer passes one that holds the instance's lock). Returns ``(status, note)``."""
    async with get_sessionmaker()() as db:
        machine = await db.get(Machine, ctx.machine.id, populate_existing=True)
        if machine is None:
            raise MachineError(f"{ctx.vm} was removed meanwhile; Slipway changed nothing")
        waits = await resize_rule(db, machine)
        if instance is None:
            instance = await _slot_instance(db, machine)
    _copy_columns(machine, ctx.machine)
    vm = ctx.vm
    if machine.stage != MachineStage.READY:
        return "skipped", f"{vm} isn't made yet; it is made at its size"
    if waits:
        return "skipped", waits
    if not size_differs(machine):
        return "skipped", f"{vm} already has {vmnet.size_text(machine.size)}"

    provider = ctx.provider
    before = _sizes(machine.applied)
    try:
        await tasks.wait_idle(ctx)
        plan_ = await provider.check_resize(ctx)
    except MachineError as exc:
        raise await _failed(ctx, exc.text, unreachable=exc.unreachable) from None
    try:
        result = await provider.resize(ctx, plan_)
    except MachineError as exc:
        await _after_failed_resize(ctx, before, exc.text)
        raise await _failed(ctx, exc.text, unreachable=exc.unreachable) from None
    except BaseException:  # the step's time limit, or Slipway stopping: cancelled part way
        text = f"The resize of {vm} was cut off before it finished"

        async def cut_off() -> None:
            await _cut_pre_resize(ctx)
            await _after_failed_resize(ctx, before, text, cut_off=True)

        await shielded(cut_off())
        raise

    after = _sizes(result) or _sizes(plan_.to) or _sizes(machine.size)
    applied = {**(after or {}), "at": ctx.now().isoformat(),
               "deployment_id": ctx.deployment_id.hex if ctx.deployment_id else None}
    await write(ctx, applied=applied, last_error=None, audit_action="machine.resize",
                summary=f"Resized {vm} to {vmnet.size_text(after)}",
                details={"name": vm, "from": before, "to": after,
                         "deployment_id": str(ctx.deployment_id) if ctx.deployment_id else None})
    if ctx.deployment_id is not None:
        async with session_scope() as db:
            dep = await db.get(Deployment, ctx.deployment_id, with_for_update=True)
            if dep is not None:
                dep.options = {**(dep.options or {}), "resize": {"from": before, "to": after}}

    if instance is not None and instance.status == InstanceStatus.RUNNING:
        try:
            await (start_release or (lambda inst: _start_live_release(ctx, inst)))(instance)
        except (MachineError, ssh.SSHError, TimeoutError, ssh.HostNotBuilt) as exc:
            text = f"{vm} is resized, but {instance.slot}'s live release didn't start: {getattr(exc, 'text', None) or exc}"
            raise await _failed(ctx, text) from None
    note = f"Resized to {vmnet.size_text(after)}"
    warnings = [str(w) for w in (result.get("warnings") or []) if w] if isinstance(result, dict) else []
    if warnings:  # the provider resized the VM but saw something to fix by hand (growpart, §7.5 step 5)
        return "warning", " ".join([f"{note}.", *warnings])
    return "succeeded", note


# ------------------------------------------------------------------------------------- hypervisor ids


def _vm_rows_stmt(provider: str, account_id: uuid.UUID) -> Any:
    return select(Resource).where(
        Resource.provider == provider, Resource.kind == VM_KIND, Resource.provider_id.startswith(f"{account_id}:")
    )


def _machine_of(row: Resource) -> str | None:
    value = (row.details or {}).get("machine_id")
    return str(value) if value else None


async def _set_ids(machine: Machine, ids: dict[str, Any], *, user_id: uuid.UUID | None, audit_text: str | None,
                   details: dict[str, Any] | None = None) -> None:
    async with session_scope() as db:
        row = await db.get(Machine, machine.id, with_for_update=True, populate_existing=True)
        if row is None:
            raise MachineError(f"{machine.name} was removed meanwhile; Slipway changed nothing")
        row.ids = {**(row.ids or {}), **ids}
        if audit_text:
            audit.record(db, "machine.reserve", actor=await _actor(db, user_id), target=row, summary=audit_text,
                         details={"name": row.name, **(details or {})})
    machine.ids = dict(row.ids)


async def reserve_vmid(
    machine: Machine, account: ProviderAccount, *, api: Any, user_id: uuid.UUID | None = None,
) -> int:
    """Reserve a Proxmox VM id for ``machine`` before Terraform runs (§6.9, D10, M13): a ``vm`` resource row,
    then ``machines.ids.vmid``, each committed on its own. ``api`` is the account's ``ProxmoxClient``.

    A row of this machine already there gives its id back (a crash between the two writes). Otherwise an id is
    taken when any ``vm`` row names it for another machine (whatever its environment: green never takes blue's
    reserved, unbuilt id) or another machine's ``ids.vmid`` holds it. Up to 20 tries.
    """
    prefix = f"{account.id}:"
    async with get_sessionmaker()() as db:
        rows = list(await db.scalars(_vm_rows_stmt(account.provider, account.id)))
        instance = await _slot_instance(db, machine)
    for row in rows:
        if _machine_of(row) == str(machine.id):
            vmid = int(row.provider_id[len(prefix):])
            if (machine.ids or {}).get("vmid") != vmid:
                await _set_ids(machine, {"vmid": vmid}, user_id=user_id, audit_text=None)
            return vmid

    async def taken(candidate: int) -> bool:
        async with get_sessionmaker()() as db:
            row = await db.scalar(select(Resource).where(
                Resource.provider == account.provider, Resource.kind == VM_KIND,
                Resource.provider_id == f"{prefix}{candidate}"))
            if row is not None and _machine_of(row) != str(machine.id):
                return True
            others = await db.scalars(select(Machine).where(Machine.account_id == account.id, Machine.id != machine.id))
            return any((other.ids or {}).get("vmid") == candidate for other in others)

    first = candidate = int(await api.next_vmid())
    for attempt in range(RESERVE_TRIES):
        if attempt:
            candidate += 1
            if not await api.vmid_free(candidate):
                continue
        if await taken(candidate):
            continue
        try:
            await resources.record(
                machine.environment_id, account.provider, VM_KIND, f"{prefix}{candidate}", machine.name, "created",
                details={"machine_id": str(machine.id), "node": (machine.spec or {}).get("node")},
                instance_id=instance.id if instance is not None else None,
                actor=await _user(user_id),
            )
        except resources.ResourceTaken:
            continue
        await _set_ids(machine, {"vmid": candidate}, user_id=user_id,
                       audit_text=f"Reserved VM id {candidate} for {machine.name}", details={"vmid": candidate})
        return candidate
    raise MachineError(f"Slipway couldn't find a free VM id in {RESERVE_TRIES} tries (from {first}): other machines "
                       "hold the next ones reserved")


async def _user(user_id: uuid.UUID | None) -> User | None:
    if user_id is None:
        return None
    async with get_sessionmaker()() as db:
        return await db.get(User, user_id)


async def record_vm(
    machine: Machine, provider_id: str, details: dict[str, Any] | None = None, *, ids: dict[str, Any] | None = None,
    user_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """Record the hypervisor id of ``machine``'s VM (ESXi's instance UUID, §6.9), then its ``ids``.

    ``provider_id`` is ``<account id>:<id>`` (the account prefix is added when missing). A ``vm`` row of this
    machine with another id is forgotten first (audited ``machine.rebuild``); a row of another machine with this id
    refuses. Each write commits on its own.
    """
    prefix = f"{machine.account_id}:"
    if not provider_id.startswith(prefix):
        provider_id = f"{prefix}{provider_id}"
    async with get_sessionmaker()() as db:
        rows = list(await db.scalars(_vm_rows_stmt(machine.provider, machine.account_id)))
        instance = await _slot_instance(db, machine)
        others = {str(m.id): m.name for m in await db.scalars(select(Machine).where(Machine.account_id == machine.account_id))}
    for row in rows:
        if row.provider_id == provider_id and _machine_of(row) != str(machine.id):
            other = others.get(_machine_of(row) or "", row.name)
            raise MachineError(f"{provider_id} is recorded for {other}; Slipway changed nothing")
    actor = await _user(user_id)
    for row in rows:
        if _machine_of(row) == str(machine.id) and row.provider_id != provider_id:
            await resources.forget(row.id, actor=actor)
            async with session_scope() as db:
                audit.record(db, "machine.rebuild", actor=actor, target=machine,
                             summary=f"Forgot {row.provider_id}, the earlier VM of {machine.name}",
                             details={"name": machine.name, "old": row.provider_id, "new": provider_id})
    row_id = await resources.record(
        machine.environment_id, machine.provider, VM_KIND, provider_id, machine.name, "created",
        details={"machine_id": str(machine.id), **(details or {})},
        instance_id=instance.id if instance is not None else None, actor=actor,
    )
    if ids:
        await _set_ids(machine, ids, user_id=user_id, audit_text=f"Recorded {provider_id} for {machine.name}",
                       details={k: v for k, v in ids.items() if k in ("instance_uuid", "moref", "vmid")})
    return row_id


# ----------------------------------------------------------------------------------------------- remove


def ids_text(machine: Machine) -> str:
    ids = machine.ids or {}
    if ids.get("vmid") is not None:
        return f"VM {ids['vmid']}"
    if ids.get("instance_uuid"):
        return str(ids["instance_uuid"])
    return "no id recorded"


async def blockers(ctx: MachineContext) -> list[Blocker]:
    """Why the VM can't be removed now (D26), checked before anything changes; [] when it may go.

    A machine still ``planned`` holds nothing on the hypervisor. An account that can't be used or reached is a
    forgettable blocker, so a retry with ``forget_vms`` can get past it.
    """
    machine = ctx.machine
    if machine.stage == MachineStage.PLANNED and not machine.ids:
        return []
    reach = f"Slipway can't reach {ctx.account.name}, so it can't remove {ctx.vm}: retry when it answers"
    why = account_problem(ctx.account)
    if why:
        return [Blocker(f"{ctx.account.name} can't be used ({why}), so Slipway can't remove {ctx.vm}: fix the account, "
                        "then retry", True)]
    try:
        return list(await ctx.provider.destroy_blockers(ctx))
    except MachineError as exc:
        return [Blocker(reach if exc.unreachable else exc.text, exc.unreachable)]


async def remove(ctx: MachineContext, *, forget: bool = False) -> list[str]:
    """Remove the VM and every row of it (§9.5, §9.9): its blockers once more, the stage ``destroying`` (own
    transaction), the provider's destroy, then in one transaction the Terraform state, the VM snapshots, the
    ``vm`` resource rows, the machine, the host and its claim. With ``forget`` (a retry's ``forget_vms``), a
    machine whose only blockers are forgettable is forgotten instead: the same rows go, the hypervisor isn't
    called, and the environment's notice names it for removal by hand. Returns what was done, for the log.
    """
    async with get_sessionmaker()() as db:
        machine = await db.get(Machine, ctx.machine.id, populate_existing=True)
        if machine is None:
            return [f"{ctx.vm} is already removed"]
        held = await db.scalar(select(Instance.slot).where(Instance.host_id == machine.host_id).limit(1))
    _copy_columns(machine, ctx.machine)
    if held is not None:
        raise MachineError(f"{ctx.vm} still runs the {held} slot's instance; Slipway removes the VM after the slot")

    found = await blockers(ctx)
    forgetting = False
    if found:
        if forget and all(b.forgettable for b in found):
            forgetting = True
        else:
            stuck = next((b for b in found if not b.forgettable), found[0])
            raise await _failed(ctx, stuck.text)

    done: list[str] = []
    if forgetting:
        done.append(f"Forgot {ctx.vm} without removing it: {found[0].text}")
    else:
        from_stage = (ctx.host.provider_state or {}).get("from_stage")
        if ctx.machine.stage != MachineStage.DESTROYING:
            from_stage = ctx.machine.stage
            await write(ctx, stage=MachineStage.DESTROYING.value, phase_fields={"from_stage": from_stage})
        if from_stage == MachineStage.PLANNED and not ctx.machine.ids:
            done.append(f"{ctx.vm} was never made")
        else:
            done.extend(await ctx.provider.destroy(ctx))

    machine = ctx.machine
    async with session_scope() as db:
        actor = await _actor(db, ctx.user_id)
        rows = [row for row in await db.scalars(_vm_rows_stmt(machine.provider, machine.account_id))
                if _machine_of(row) == str(machine.id)]
        for row in rows:
            audit.record(
                db, "resource.forget" if forgetting else "resource.delete", actor=actor, target=row,
                summary=f"{'Forgot' if forgetting else 'Deleted'} {machine.provider} vm {row.provider_id} ({row.name})",
                details={"provider": row.provider, "kind": row.kind, "name": row.name, "provider_id": row.provider_id,
                         "environment_id": str(row.environment_id)},
            )
            await db.delete(row)
        await db.execute(delete(TerraformState).where(TerraformState.machine_id == machine.id))
        await db.execute(delete(MachineSnapshot).where(MachineSnapshot.machine_id == machine.id))
        await db.execute(delete(Machine).where(Machine.id == machine.id))
        await db.execute(delete(AddressClaim).where(AddressClaim.host_id == machine.host_id))
        await db.execute(delete(Host).where(Host.id == machine.host_id))
        if forgetting:
            audit.record(db, "machine.forget", actor=actor, target=machine,
                         summary=f"Forgot {machine.name} ({ids_text(machine)} on {ctx.account.name}) without removing it",
                         details={"name": machine.name, "ids": dict(machine.ids or {}), "why": "forget_vms",
                                  "blocker": found[0].text})
        else:
            audit.record(db, "machine.destroy", actor=actor, target=machine, summary=f"Removed {machine.name}",
                         details={"name": machine.name, "ids": dict(machine.ids or {})})
    if machine.provider == "proxmox":
        from slipway.services import terraform

        terraform.Workdir(terraform.TerraformSettings.from_config(get_settings()).dir, machine.id).remove()
    if forgetting:
        await set_notice(
            ctx.env.id,
            f"Slipway forgot {machine.name} ({ids_text(machine)} on {ctx.account.name}) without removing it: "
            f"{found[0].text}. Remove it by hand.",
            deployment_id=ctx.deployment_id,
        )
    return done


# --------------------------------------------------------------------------------------------- recovery


async def recover_prepare(db: AsyncSession, deployment: Deployment) -> Machine | None:
    """A job interrupted in ``prepare`` (§9.12), in the caller's transaction: the machine keeps its stage and
    ``last_task`` and gets ``last_error``; the deployment's Terraform locks are released. Returns the machine."""
    await terraform_store.clear_lock(deployment.id, db)
    if deployment.instance_id is None:
        return None
    host_id = await db.scalar(select(Instance.host_id).where(Instance.id == deployment.instance_id))
    if host_id is None:
        return None
    machine = await db.scalar(select(Machine).where(Machine.host_id == host_id))
    if machine is not None:
        machine.last_error = ssh.clip(f"Slipway restarted while preparing {machine.name}", 500)
    return machine


async def load_context(
    db: AsyncSession, *, machine_id: uuid.UUID | None = None, host_id: uuid.UUID | None = None,
    deployment_id: uuid.UUID | None = None, user_id: uuid.UUID | None = None, say: Log, hide: ssh.Redactor,
    connect: ConnectFactory = ssh.open_session, sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    now: Callable[[], datetime] = utcnow,
) -> MachineContext | None:
    """The ``MachineContext`` of a machine (by its id or its host's), or None when the host isn't a VM."""
    if machine_id is not None:
        machine = await db.get(Machine, machine_id)
    else:
        machine = await db.scalar(select(Machine).where(Machine.host_id == host_id))
    if machine is None:
        return None
    env = await db.get(Environment, machine.environment_id)
    host = machine.host or await db.get(Host, machine.host_id)
    account = machine.account or await db.get(ProviderAccount, machine.account_id)
    return MachineContext(machine=machine, host=host, account=account, env=env, deployment_id=deployment_id,
                          user_id=user_id, say=say, hide=hide, connect=connect, sleep=sleep, now=now)
