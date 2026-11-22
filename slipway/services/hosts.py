"""Host health checks, the optional background poller, and the host contract phases 4 and 5 share.

The contract (P4 §3.3, P5 §3.6): a host a provider makes (a droplet, a VM) carries ``provider_state`` with a
``phase`` (planned, creating, ready, gone) that ``set_phase`` writes; ``Host.is_built`` reads it, and
``ssh.SSHTarget.from_host`` refuses a host that isn't built. Such a host belongs to the environment that made
it (``owner_environment_id``): ``owned_by`` is the one predicate for that, ``owned_host_refusal`` gives every
answer for the paths that would put something else on it or change what the environment set, and
``address_holder`` is the one check that no other host row already holds an address. ``planned_host`` builds
the unsaved row a provider starts from.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from fastapi import Request
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.core.config import get_settings
from slipway.db.base import utcnow
from slipway.db.session import session_scope
from slipway.models import Environment, Host, HostAuthMethod, HostStatus, Instance, InstanceStatus, Machine, User
from slipway.services import audit, cloudinit, host_metrics, ssh

log = logging.getLogger(__name__)

CPU_WARN = 85.0
MEM_WARN = 90.0

# provider_state["phase"] of a host a provider makes. A VM's follows its machines.stage (planned -> planned,
# creating and booting -> creating, ready -> ready, destroying -> gone), written in the same transaction.
PHASE_PLANNED = "planned"
PHASE_CREATING = "creating"
PHASE_READY = "ready"
PHASE_GONE = "gone"
PHASES = (PHASE_PLANNED, PHASE_CREATING, PHASE_READY, PHASE_GONE)
NO_PROVIDER_PIN = "{host} has no pinned host key. Slipway pins it itself when it builds the machine: deploy again"


def status_from_probe(result: ssh.ProbeResult) -> HostStatus:
    if result.docker_version is None:
        return HostStatus.WARNING
    if result.cpu_percent >= CPU_WARN or result.mem_percent >= MEM_WARN:
        return HostStatus.WARNING
    return HostStatus.HEALTHY


async def check_host(
    db: AsyncSession, host: Host, *, actor: User | None = None, request: Request | None = None,
    building: bool = False,
) -> Host | None:
    """Probe a host over SSH and store the result. Pins the host key on first contact.

    No database connection is held while SSH runs. Returns None if the host was deleted meanwhile;
    a result is discarded if the host's address or pinned key changed during the probe.

    A host a provider makes is never pinned here (no trust on first use): its key is written only by its
    provider's ``prepare``, and a provider host with no pinned key isn't probed at all. One that isn't
    built yet raises ``ssh.HostNotBuilt`` before anything is written, unless ``building`` (only the
    providers' ``prepare`` drivers pass it, to fill in Docker's version, the OS and metrics).
    """
    target = ssh.SSHTarget.from_host(host, building=building)
    host.last_checked_at = utcnow()
    if (host.provider or "ssh") != "ssh" and not target.pinned_host_key:
        host.status, host.last_error = HostStatus.ERROR, NO_PROVIDER_PIN.format(host=host.name)
        await db.commit()
        return host
    await db.commit()
    result: ssh.ProbeResult | None = None
    try:
        result = await ssh.probe(target)
    except ssh.HostKeyMismatch as exc:
        status, error = HostStatus.ERROR, str(exc)
    except ssh.SSHError as exc:
        status, error = HostStatus.UNREACHABLE, str(exc)
    else:
        status, error = status_from_probe(result), result.docker_error

    current = await db.get(Host, host.id, populate_existing=True)
    if current is None:
        return None
    if (current.hostname, current.port, current.host_key) != (target.hostname, target.port, target.pinned_host_key):
        return current
    # Another request can still move the host or change its key between the read above and the write
    # below. This compare-and-set UPDATE only matches while the row has the address and key that were
    # probed, and it locks the row until the commit, so a concurrent edit waits for this check
    # (PostgreSQL re-checks the condition after waiting for a concurrent writer's lock).
    same_key = Host.host_key.is_(None) if target.pinned_host_key is None else Host.host_key == target.pinned_host_key
    claimed = await db.execute(
        update(Host)
        .where(Host.id == host.id, Host.hostname == target.hostname, Host.port == target.port, same_key)
        .values(last_checked_at=utcnow())
    )
    if claimed.rowcount != 1:  # moved, re-keyed or deleted meanwhile: discard the result
        await db.commit()
        return await db.get(Host, host.id, populate_existing=True)
    current.status = status
    current.last_error = ssh.clip(error, 2000) if error else None
    if result is not None:
        if not current.host_key and (current.provider or "ssh") == "ssh":
            current.host_key = result.host_key
            current.host_key_fingerprint = result.fingerprint
            audit.record(
                db, "host.key_pinned", actor=actor, target=current,
                summary=f"Pinned host key {result.fingerprint} for {current.name}", request=request,
            )
        current.docker_version = ssh.clip(result.docker_version, 64) if result.docker_version else None
        current.os_info = ssh.clip(result.os_info, 255)
        current.metrics = result.metrics
        host_metrics.record_sample(db, current.id, result.metrics)
        await _unraid_deploy_root(db, current, actor=actor, request=request)
    await db.commit()
    return current


DEFAULT_DEPLOY_ROOT = "/opt/slipway"
UNRAID_DEPLOY_ROOT = "/mnt/user/appdata"


async def _unraid_deploy_root(db: AsyncSession, host: Host, *, actor: User | None, request: Request | None) -> None:
    """On Unraid, swap the untouched default deploy root (in RAM, cleared at restart) for /mnt/user/appdata.

    Only while no instance has files there; otherwise the host page warns and the root can be moved.
    """
    if not (host.os_info or "").startswith("Unraid") or host.deploy_root != DEFAULT_DEPLOY_ROOT:
        return
    used = await db.scalar(
        select(Instance.id).where(
            Instance.host_id == host.id, Instance.deploy_dir.is_(None),
            or_(Instance.status != InstanceStatus.CREATED, Instance.last_deployed_at.is_not(None)),
        ).limit(1)
    )
    if used is not None:
        return
    host.deploy_root = UNRAID_DEPLOY_ROOT
    audit.record(
        db, "host.update", actor=actor, target=host, request=request,
        summary=f"{host.name} runs Unraid, which clears {DEFAULT_DEPLOY_ROOT} when it restarts: "
                f"deploy root set to {UNRAID_DEPLOY_ROOT}",
    )


async def _check_by_id(host_id: uuid.UUID) -> None:
    async with session_scope() as db:
        host = await db.get(Host, host_id)
        if host is not None and host.is_pinned and ssh.host_is_built(host) and not host.setup_running:
            await check_host(db, host)


def _built(provider: str, provider_state: dict[str, Any] | None) -> bool:
    """``Host.is_built`` from the two columns, without loading the row."""
    return provider == "ssh" or (provider_state or {}).get("phase") == PHASE_READY


async def poll_once() -> None:
    """Check every pinned host that is built. Each host gets its own session, so one failure cannot affect
    the others. A host a provider is still making (or has lost) is left to its provider."""
    async with session_scope() as db:
        rows = (await db.execute(
            select(Host.id, Host.provider, Host.provider_state).where(Host.host_key.is_not(None)).order_by(Host.name)
        )).all()
    ids = [row.id for row in rows if _built(row.provider, row.provider_state)]
    for host_id in ids:
        try:
            await _check_by_id(host_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Health check failed for host %s", host_id)


async def poll_hosts_forever() -> None:
    interval = get_settings().host_poll_interval
    if interval <= 0:
        return
    while True:
        await asyncio.sleep(interval)
        try:
            await poll_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # keep polling whatever happens
            log.exception("Host health poll failed")


# ------------------------------------------------------------------ the host contract (P4 §3.3, P5 §3.6)


def set_phase(host: Host, phase: str, **fields: Any) -> dict[str, Any]:
    """Write ``provider_state['phase']`` (and any provider fields) as a new dict, so the change is seen.

    The caller commits, in the same transaction as the provider's own change (a VM's stage). Returns the
    new state. A field given as None is removed.
    """
    if phase not in PHASES:
        raise ValueError(f"{phase!r} isn't a host phase: use one of {', '.join(PHASES)}")
    state = {**(host.provider_state or {}), **fields, "phase": phase}
    host.provider_state = {key: value for key, value in state.items() if value is not None}
    return host.provider_state


def phase_of(host: Host) -> str | None:
    """The host's phase, or None for a host added by hand."""
    if (host.provider or "ssh") == "ssh":
        return None
    return (host.provider_state or {}).get("phase") or PHASE_PLANNED


def owned_by(env: Environment | uuid.UUID, host: Host | None) -> bool:
    """True when ``host`` is one ``env`` made (a droplet or a VM), so it goes with the environment.

    The one predicate by which Remove slot and teardown delete instance rows without SSH.
    """
    if host is None or host.owner_environment_id is None:
        return False
    env_id = env if isinstance(env, uuid.UUID) else env.id
    return host.owner_environment_id == env_id


# What owned_host_refusal answers for. The PATCH fields of api/v1/hosts.py map onto the first group; label
# and description stay editable.
EDIT_ACTIONS = {
    "hostname": "address", "proxy_address": "address", "lan_address": "address", "address": "address",
    "port": "port", "username": "username", "deploy_root": "deploy_root",
    "credentials": "credentials", "auth_method": "credentials", "private_key": "credentials",
    "key_passphrase": "credentials", "password": "credentials",
}
ALLOWED_ACTIONS = frozenset({"label", "description"})
# Paths that would run something else on the host: POST /instances, a placement change, another
# environment's hosts.<slot>, Add slot with host_id, and the unmanaged-instance claim.
PLACING_ACTIONS = frozenset({"instance", "placement", "environment", "add_slot", "claim"})
OTHER_ACTIONS = frozenset({"delete", "reset_key", "move_root", "check"})
ACTIONS = frozenset(EDIT_ACTIONS) | ALLOWED_ACTIONS | PLACING_ACTIONS | OTHER_ACTIONS

_KINDS = {"digitalocean": "droplet", "proxmox": "VM", "esxi": "VM"}


def kind_of(host: Host) -> str:
    """``droplet`` or ``VM``: what the host is, in the owned-host texts."""
    return _KINDS.get(host.provider, "machine")


def _slot_from_name(host: Host) -> str | None:
    name = host.name or ""
    if name.startswith("slipway-") and "-" in name[len("slipway-"):]:
        return name.rsplit("-", 1)[1]
    return None


def owned_host_refusal(
    host: Host, *, action: str, owner: str | None = None, slot: str | None = None, account: str | None = None,
) -> str | None:
    """Why ``action`` isn't allowed on ``host``, a host an environment made; None when it is (or the host
    was added by hand).

    ``action`` is a PATCH field (``hostname``, ``proxy_address``, ``lan_address``, ``port``, ``username``,
    ``deploy_root``, a credential field, or ``label``/``description``, which stay editable) or one of
    ``delete``, ``reset_key``, ``move_root`` (the deploy-root move), ``check`` (refused only while the host
    isn't built), ``instance`` (POST /instances), ``placement`` (a placement change onto it), ``environment``
    (another environment's ``hosts.<slot>``), ``add_slot`` (Add slot with ``host_id``) and ``claim`` (the
    unmanaged-instance claim). ``owner``, ``slot`` and ``account`` name the owning environment, the host's
    slot and (for a VM) its account; ``owned_host_problem`` reads them. The texts say a droplet or a VM.
    """
    if action not in ACTIONS:
        raise ValueError(f"{action!r} isn't an owned-host action")
    if host.owner_environment_id is None or action in ALLOWED_ACTIONS:
        return None
    kind = kind_of(host)
    env = owner or host.label or "its environment"
    slot = slot or _slot_from_name(host) or "its slot"
    name = host.name
    if action in EDIT_ACTIONS:
        return f"{name} is a {kind} Slipway made for {env}; change it on the environment"
    if action in PLACING_ACTIONS:
        return f"{name} is a {kind} of environment {env}; only its slots run there"
    if action == "delete":
        if slot == "data":
            return f"{name} goes when {env} is deleted"
        return f"{name} goes when {env} removes its {slot} slot"
    if action == "move_root":
        return f"{name} is a {kind} Slipway made for {env}; its deploy root stays where Slipway set it"
    if action == "check":
        if ssh.host_is_built(host):
            return None
        return f"Slipway pins {name}'s key itself when it makes the {kind}: deploy to {slot}"
    # reset_key
    if kind == "VM":
        source = account or "its account"
        return (f"{name}'s key was pinned from {source}. If the VM was rebuilt by hand, "
                f"use Forget the VM on {env}")
    return (f"{name}'s key was made by Slipway with the {kind} for {env}; "
            f"Slipway changes it only when it builds the {kind} again")


def edit_refusal(host: Host, fields: set[str] | list[str], **names: Any) -> str | None:
    """The first refusal for a PATCH that sets ``fields`` (field names of the hosts API), or None.

    Fields outside the host contract (anything not in ``EDIT_ACTIONS``) are left to the caller.
    """
    for field in sorted(fields):
        if field in EDIT_ACTIONS:
            problem = owned_host_refusal(host, action=field, **names)
            if problem:
                return problem
    return None


async def owned_host_problem(db: AsyncSession, host: Host, *, action: str) -> str | None:
    """``owned_host_refusal`` with the owning environment's name, the host's slot and its account read from
    the database."""
    if host.owner_environment_id is None:
        return owned_host_refusal(host, action=action)
    owner = await db.scalar(select(Environment.name).where(Environment.id == host.owner_environment_id))
    machine = await db.scalar(select(Machine).where(Machine.host_id == host.id)) if host.id else None
    slot = machine.slot if machine is not None else None
    account = machine.account.name if machine is not None and machine.account is not None else None
    if slot is None and host.id is not None:
        slot = await db.scalar(
            select(Instance.slot).where(
                Instance.host_id == host.id, Instance.environment_id == host.owner_environment_id
            ).limit(1)
        )
    return owned_host_refusal(host, action=action, owner=owner, slot=slot, account=account)


async def address_holder(
    db: AsyncSession, address: str, *, except_host_id: uuid.UUID | None = None,
    except_environment_id: uuid.UUID | None = None,
) -> Host | None:
    """Another host row whose ``hostname``, ``proxy_address`` or ``lan_address`` is ``address``, or None.

    ``except_host_id`` leaves out the host being built; ``except_environment_id`` also leaves out the hosts
    that environment made (a droplet's own environment, P4 §9.2 step 5). The address is compared as given
    and in lower case (host names aren't case-sensitive).
    """
    wanted = {address, address.lower()}
    stmt = select(Host).where(
        or_(Host.hostname.in_(wanted), Host.proxy_address.in_(wanted), Host.lan_address.in_(wanted))
    )
    if except_host_id is not None:
        stmt = stmt.where(Host.id != except_host_id)
    if except_environment_id is not None:
        stmt = stmt.where(or_(Host.owner_environment_id.is_(None), Host.owner_environment_id != except_environment_id))
    return await db.scalar(stmt.order_by(Host.name).limit(1))


HOST_NAME_MAX = 64  # hosts.name


def planned_name(env_name: str, slot: str) -> str:
    """``slipway-<env>-<slot>``: the host row's name, equal to the droplet's and the VM's name."""
    name = f"slipway-{env_name}-{slot}"
    if not env_name or not slot or len(name) > HOST_NAME_MAX:
        raise ValueError(f"{name!r} can't be a host name: it must be 1 to {HOST_NAME_MAX} characters")
    return name


async def name_clash(db: AsyncSession, name: str) -> str | None:
    """The refusal when a host row already has ``name``, or None."""
    if await db.scalar(select(Host.id).where(Host.name == name).limit(1)) is None:
        return None
    return f"A host named {name} already exists: rename it, or pick another environment name"


def planned_host(
    env_name: str, slot: str, *, provider: str, hostname: str | None = None, description: str = "",
    deploy_root: str | None = None,
) -> Host:
    """An unsaved host row for ``env_name``'s ``slot`` that ``provider`` will make (Decision 9).

    Named ``slipway-<env>-<slot>``, user ``slipway`` (``cloudinit.GUEST_USER``), label the environment, port
    22, a key pair Slipway generated (comment ``slipway@<name>``), no pinned key and phase ``planned``.
    ``hostname`` defaults to ``<name>.invalid``, a placeholder that never resolves (a droplet's until it is
    built; a VM passes its static address). The caller sets ``owner_environment_id`` once the environment
    row exists.
    """
    if provider == "ssh":
        raise ValueError("a planned host belongs to a provider, not ssh")
    name = planned_name(env_name, slot)
    private_key, public_key = ssh.generate_keypair(f"slipway@{name}")
    return Host(
        name=name, hostname=hostname or f"{name}.invalid", port=22, username=cloudinit.GUEST_USER,
        label=env_name[:32], description=description[:255],
        deploy_root=deploy_root or get_settings().default_deploy_root or DEFAULT_DEPLOY_ROOT,
        provider=provider, auth_method=HostAuthMethod.KEY.value, private_key=private_key, public_key=public_key,
        host_key=None, host_key_fingerprint=None, status=HostStatus.UNKNOWN.value, metrics={},
        provider_state={"phase": PHASE_PLANNED},
    )
