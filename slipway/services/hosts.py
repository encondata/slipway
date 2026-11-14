"""Host health checks and the optional background poller."""

from __future__ import annotations

import asyncio
import logging
import uuid

from fastapi import Request
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.core.config import get_settings
from slipway.db.base import utcnow
from slipway.db.session import session_scope
from slipway.models import Host, HostStatus, Instance, InstanceStatus, User
from slipway.services import audit, ssh

log = logging.getLogger(__name__)

CPU_WARN = 85.0
MEM_WARN = 90.0


def status_from_probe(result: ssh.ProbeResult) -> HostStatus:
    if result.docker_version is None:
        return HostStatus.WARNING
    if result.cpu_percent >= CPU_WARN or result.mem_percent >= MEM_WARN:
        return HostStatus.WARNING
    return HostStatus.HEALTHY


async def check_host(
    db: AsyncSession, host: Host, *, actor: User | None = None, request: Request | None = None
) -> Host | None:
    """Probe a host over SSH and store the result. Pins the host key on first contact.

    No database connection is held while SSH runs. Returns None if the host was deleted meanwhile;
    a result is discarded if the host's address or pinned key changed during the probe.
    """
    host.last_checked_at = utcnow()
    target = ssh.SSHTarget.from_host(host)
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
        if not current.host_key:
            current.host_key = result.host_key
            current.host_key_fingerprint = result.fingerprint
            audit.record(
                db, "host.key_pinned", actor=actor, target=current,
                summary=f"Pinned host key {result.fingerprint} for {current.name}", request=request,
            )
        current.docker_version = ssh.clip(result.docker_version, 64) if result.docker_version else None
        current.os_info = ssh.clip(result.os_info, 255)
        current.metrics = result.metrics
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
        if host is not None and host.is_pinned:
            await check_host(db, host)


async def poll_once() -> None:
    """Check every pinned host. Each host gets its own session, so one failure cannot affect the others."""
    async with session_scope() as db:
        ids = (await db.scalars(select(Host.id).where(Host.host_key.is_not(None)).order_by(Host.name))).all()
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
