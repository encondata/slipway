"""Docker hosts reached over SSH."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm.attributes import flag_modified

from slipway.api.deps import DB, Auth, not_found, require
from slipway.core.permissions import Perm
from slipway.models import Host, HostAuthMethod, HostStatus, Instance, InstanceStatus
from slipway.schemas import HostCreate, HostOut, HostUpdate, host_out
from slipway.services import audit, ssh
from slipway.services.auth import AuthContext
from slipway.services.hosts import check_host

router = APIRouter(prefix="/hosts", tags=["hosts"])

Reader = Annotated[AuthContext, require(Perm.HOSTS_READ)]
Writer = Annotated[AuthContext, require(Perm.HOSTS_WRITE)]


def _apply_credentials(host: Host, body: HostCreate | HostUpdate) -> None:
    method = body.auth_method
    if method is None:
        # Update without changing method: allow replacing the key / password in place.
        if body.private_key and host.auth_method == HostAuthMethod.KEY:
            method = "key"
        elif body.password and host.auth_method == HostAuthMethod.PASSWORD:
            method = "password"
        else:
            return
    if method == "generate":
        host.private_key, host.public_key = ssh.generate_keypair(comment=f"slipway@{host.name}")
        host.key_passphrase = None
        host.password = None
        host.auth_method = HostAuthMethod.KEY
    elif method == "key":
        if not body.private_key:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Paste the private key Slipway should use")
        try:
            host.public_key = ssh.public_key_from_private(body.private_key, body.key_passphrase)
        except ssh.SSHError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        host.private_key = body.private_key.strip() + "\n"
        host.key_passphrase = body.key_passphrase or None
        host.password = None
        host.auth_method = HostAuthMethod.KEY
    elif method == "password":
        if not body.password:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "A password is required")
        host.password = body.password
        host.private_key = host.key_passphrase = host.public_key = None
        host.auth_method = HostAuthMethod.PASSWORD


async def _get(db: DB, host_id: uuid.UUID) -> Host:
    host = await db.get(Host, host_id)
    if host is None:
        raise not_found("Host")
    return host


def _forget_host_key(host: Host) -> None:
    """Clear the pinned key and health status, so the host must be verified again.

    The columns are always written, even when this session loaded them as already empty: a check that
    pinned a key after they were loaded must not keep that key.
    """
    host.host_key = host.host_key_fingerprint = None
    host.status = HostStatus.UNKNOWN
    host.last_error = None
    for column in ("host_key", "host_key_fingerprint", "status", "last_error"):
        flag_modified(host, column)


async def _stored_fingerprint(db: DB, host: Host) -> str | None:
    """The pinned key's fingerprint as stored now, read with a row lock, before ``_forget_host_key``.

    A check may have pinned a key since ``host`` was loaded, and that is the key being cleared. On PostgreSQL
    the lock also makes this wait for a check that is writing its result, or a later check wait for this
    request (its compare-and-set then no longer matches and the result is discarded).
    """
    return await db.scalar(select(Host.host_key_fingerprint).where(Host.id == host.id).with_for_update())


@router.get("")
async def list_hosts(ctx: Reader, db: DB) -> list[HostOut]:
    return [host_out(h) for h in (await db.scalars(select(Host).order_by(Host.name))).all()]


@router.post("", status_code=201)
async def create_host(body: HostCreate, ctx: Writer, request: Request, db: DB) -> HostOut:
    if await db.scalar(select(Host).where(Host.name == body.name)):
        raise HTTPException(status.HTTP_409_CONFLICT, "A host with this name already exists")
    host = Host(
        name=body.name,
        hostname=body.hostname,
        port=body.port,
        username=body.username,
        environment=body.environment or "",
        description=body.description or "",
        deploy_root=body.deploy_root or "/opt/slipway",
        proxy_address=body.proxy_address or None,
        metrics={},
        created_by_id=ctx.user.id,
    )
    _apply_credentials(host, body)
    db.add(host)
    await db.flush()
    audit.record(db, "host.create", actor=ctx.user, target=host, summary=f"Added host {host.name} ({host.address})", request=request)
    await db.commit()
    return host_out(host)


@router.get("/{host_id}")
async def get_host(host_id: uuid.UUID, ctx: Reader, db: DB) -> HostOut:
    return host_out(await _get(db, host_id))


async def _deployed_instances(db: DB, host: Host) -> int:
    """Instances on the host that have ever been deployed (they have files under its deploy root)."""
    ever_deployed = or_(
        Instance.status != InstanceStatus.CREATED,
        Instance.current_commit_sha.is_not(None),
        Instance.last_deployed_at.is_not(None),
    )
    stmt = select(func.count()).select_from(Instance).where(Instance.host_id == host.id, ever_deployed)
    return await db.scalar(stmt) or 0


@router.patch("/{host_id}")
async def update_host(host_id: uuid.UUID, body: HostUpdate, ctx: Writer, request: Request, db: DB) -> HostOut:
    host = await _get(db, host_id)
    if body.deploy_root is not None and body.deploy_root != host.deploy_root:
        if deployed := await _deployed_instances(db, host):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"{deployed} instance(s) on this host have been deployed; destroy them before changing the deploy root",
            )
    if body.name and body.name != host.name:
        if await db.scalar(select(Host).where(Host.name == body.name)):
            raise HTTPException(status.HTTP_409_CONFLICT, "A host with this name already exists")
        host.name = body.name
    moved = (body.hostname and body.hostname != host.hostname) or (body.port and body.port != host.port)
    old_address = host.address
    old_fingerprint = await _stored_fingerprint(db, host) if moved else None
    for field in ("hostname", "port", "username", "environment", "description", "deploy_root"):
        value = getattr(body, field)
        if value is not None:
            setattr(host, field, value)
    if body.proxy_address is not None:
        host.proxy_address = body.proxy_address or None
    _apply_credentials(host, body)
    summary = f"Updated host {host.name}"
    if moved:  # possibly a different machine: forget the pinned host key and re-verify
        _forget_host_key(host)
        summary += f" (address {old_address} -> {host.address})"
    audit.record(db, "host.update", actor=ctx.user, target=host, summary=summary, request=request)
    if moved and old_fingerprint:
        audit.record(
            db, "host.key_reset", actor=ctx.user, target=host, request=request,
            summary=f"Cleared pinned key {old_fingerprint} for {host.name}: address changed to {host.address}",
        )
    await db.commit()
    return host_out(host)


@router.delete("/{host_id}", status_code=204)
async def delete_host(host_id: uuid.UUID, ctx: Writer, request: Request, db: DB) -> None:
    host = await _get(db, host_id)
    in_use = await db.scalar(select(func.count()).select_from(Instance).where(Instance.host_id == host.id))
    if in_use:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{in_use} instance(s) still run on this host; remove them first")
    audit.record(db, "host.delete", actor=ctx.user, target=host, summary=f"Removed host {host.name}", request=request)
    await db.delete(host)
    await db.commit()


@router.post("/{host_id}/check")
async def check(host_id: uuid.UUID, ctx: Auth, request: Request, db: DB) -> HostOut:
    """Probe the host. The first successful check pins its SSH host key, which needs hosts:write."""
    host = await _get(db, host_id)
    needed = Perm.HOSTS_READ if host.is_pinned else Perm.HOSTS_WRITE
    if not ctx.can(needed):
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {needed}")
    checked = await check_host(db, host, actor=ctx.user, request=request)
    if checked is None:
        raise not_found("Host")
    return host_out(checked)


@router.post("/{host_id}/reset-host-key")
async def reset_host_key(host_id: uuid.UUID, ctx: Writer, request: Request, db: DB) -> HostOut:
    host = await _get(db, host_id)
    old = await _stored_fingerprint(db, host)
    _forget_host_key(host)
    audit.record(db, "host.key_reset", actor=ctx.user, target=host, summary=f"Reset pinned key {old} for {host.name}", request=request)
    await db.commit()
    return host_out(host)
