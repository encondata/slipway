"""Docker hosts reached over SSH.

A host an environment made (a droplet or a VM, ``owner_environment_id`` set) belongs to that environment:
``hosts.owned_host_refusal`` answers 409 for every change of how Slipway reaches it (its address, port, user,
credentials, deploy root, name), for DELETE and for reset-host-key, while its label and description stay
editable (phase 4 §3.3, phase 5 D18). A host a provider hasn't built yet has nothing to check: 409 with
``HostNotBuilt``'s text. ``HostOut.machine`` ({stage, account}) names the VM a Proxmox or ESXi host is (P5 §11).
"""

from __future__ import annotations

import uuid
from contextlib import AsyncExitStack
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm.attributes import flag_modified

from slipway.api.deps import DB, Auth, not_found, require
from slipway.core.permissions import Perm
from slipway.models import (
    Deployment,
    DeploymentStatus,
    Environment,
    Host,
    HostAuthMethod,
    HostStatus,
    Instance,
    InstanceStatus,
    Machine,
    ProviderAccount,
)
from slipway.schemas import HostCreate, HostOut, HostSetupIn, HostSetupOut, HostUpdate, host_out
from slipway.services import audit, data, deployer, hosts, provisioning, ssh
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


async def owned_by_of(db: DB, found: list[Host]) -> dict[uuid.UUID, dict[str, Any]]:
    """``HostOut.owned_by`` ({id, name, slot}) of each host an environment made, in two queries."""
    owned = [h for h in found if h.owner_environment_id is not None]
    if not owned:
        return {}
    env_ids = {h.owner_environment_id for h in owned}
    names = dict((await db.execute(select(Environment.id, Environment.name).where(Environment.id.in_(env_ids)))).all())
    ids = [h.id for h in owned]
    slots = {host_id: slot for host_id, slot in (await db.execute(
        select(Machine.host_id, Machine.slot).where(Machine.host_id.in_(ids)))).all()}
    for host_id, env_id, slot in (await db.execute(
            select(Instance.host_id, Instance.environment_id, Instance.slot).where(Instance.host_id.in_(ids)))).all():
        if env_id is not None and slots.get(host_id) is None:
            slots[host_id] = slot
    return {h.id: {"id": h.owner_environment_id, "name": names.get(h.owner_environment_id), "slot": slots.get(h.id)}
            for h in owned}


async def machines_of(db: DB, found: list[Host]) -> dict[uuid.UUID, dict[str, Any]]:
    """``HostOut.machine`` ({stage, account: {id, name, provider}}) of each host that is a VM Slipway made."""
    ids = [h.id for h in found if h.owner_environment_id is not None]
    if not ids:
        return {}
    rows = (await db.execute(
        select(Machine.host_id, Machine.stage, ProviderAccount.id, ProviderAccount.name, ProviderAccount.provider)
        .join(ProviderAccount, ProviderAccount.id == Machine.account_id).where(Machine.host_id.in_(ids)))).all()
    return {host_id: {"stage": stage, "account": {"id": account_id, "name": name, "provider": provider}}
            for host_id, stage, account_id, name, provider in rows}


async def _out(db: DB, host: Host) -> HostOut:
    return host_out(host, owned_by=(await owned_by_of(db, [host])).get(host.id),
                    machine=(await machines_of(db, [host])).get(host.id))


async def _refuse_owned(db: DB, host: Host, action: str) -> None:
    """409 with ``hosts.owned_host_refusal``'s text when ``action`` isn't allowed on a host an environment made."""
    problem = await hosts.owned_host_problem(db, host, action=action)
    if problem:
        raise HTTPException(status.HTTP_409_CONFLICT, problem)


# PATCH fields that change how Slipway reaches a host. An owned host refuses each one that would change.
_REACH_FIELDS = ("name", "hostname", "port", "username", "proxy_address", "lan_address", "deploy_root")
_CREDENTIAL_FIELDS = ("auth_method", "private_key", "key_passphrase", "password")


def _changed_fields(host: Host, body: HostUpdate) -> set[str]:
    """The reach and credential fields a PATCH would change (a field sent with its current value doesn't)."""
    changed = {f for f in _CREDENTIAL_FIELDS if getattr(body, f) is not None}
    for field in _REACH_FIELDS:
        value = getattr(body, field)
        if value is None:
            continue
        current = getattr(host, field)
        if field in ("proxy_address", "lan_address"):
            value, current = value or None, current or None
        if value != current:
            changed.add(field)
    return changed


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
    found = list((await db.scalars(select(Host).order_by(Host.name))).all())
    owned = await owned_by_of(db, found)
    vms = await machines_of(db, found)
    return [host_out(h, owned_by=owned.get(h.id), machine=vms.get(h.id)) for h in found]


def _not_while_setting_up(host: Host) -> None:
    if host.setup_running or provisioning.runner.running(host.id):
        raise HTTPException(status.HTTP_409_CONFLICT, f"Slipway is setting up {host.name}; try again when it finishes")


def _admin_login(username: str | None, password: str | None, ssh_user: str) -> provisioning.AdminLogin:
    if not password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Enter the admin password Slipway should use once to set up the server")
    if ssh_user == "root":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Pick a separate SSH user for Slipway to create, such as deploy, rather than root"
        )
    return provisioning.AdminLogin(username or "root", password)


def _start_setup(host: Host, admin: provisioning.AdminLogin, ctx: AuthContext) -> None:
    try:
        provisioning.runner.start(host.id, admin, ctx.user.id)
    except provisioning.SetupError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc


@router.post("", status_code=201)
async def create_host(body: HostCreate, ctx: Writer, request: Request, db: DB) -> HostOut:
    """Add a host. With ``setup: "new"`` Slipway also sets the server up, in the background, with the
    one-time admin login (follow it with GET /hosts/{id}/setup)."""
    if await db.scalar(select(Host).where(Host.name == body.name)):
        raise HTTPException(status.HTTP_409_CONFLICT, "A host with this name already exists")
    admin = _admin_login(body.admin_username, body.admin_password, body.username) if body.setup == "new" else None
    if admin is not None:
        body = body.model_copy(update={"auth_method": "generate"})  # Slipway installs its own key
    host = Host(
        name=body.name,
        hostname=body.hostname,
        port=body.port,
        username=body.username,
        label=body.label or "",
        description=body.description or "",
        deploy_root=body.deploy_root or "/opt/slipway",
        proxy_address=body.proxy_address or None,
        lan_address=body.lan_address or None,
        os_type=body.os_type,
        metrics={},
        created_by_id=ctx.user.id,
    )
    _apply_credentials(host, body)
    if admin is not None:
        provisioning.begin(host)
    db.add(host)
    await db.flush()
    audit.record(db, "host.create", actor=ctx.user, target=host, summary=f"Added host {host.name} ({host.address})", request=request)
    if admin is not None:
        audit.record(
            db, "host.setup_started", actor=ctx.user, target=host, request=request,
            summary=f"Started setting up {host.name} as {admin.username}: user {host.username}, SSH key and Docker",
        )
    await db.commit()
    if admin is not None:
        _start_setup(host, admin, ctx)
    return host_out(host)


@router.get("/{host_id}/setup")
async def get_setup(host_id: uuid.UUID, ctx: Reader, db: DB) -> HostSetupOut:
    host = await _get(db, host_id)
    return HostSetupOut(status=host.setup_status, step=host.setup_step, error=host.setup_error, log=host.setup_log or "")


@router.post("/{host_id}/setup", status_code=202)
async def start_setup(host_id: uuid.UUID, body: HostSetupIn, ctx: Writer, request: Request, db: DB) -> HostOut:
    """Set the host up (again) with a one-time admin login: user, Slipway's key, Docker and the deploy root."""
    host = await _get(db, host_id)
    _not_while_setting_up(host)
    if (host.provider or "ssh") != "ssh" or host.owner_environment_id is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{host.name} was made by Slipway, which sets it up itself")
    if host.auth_method != HostAuthMethod.KEY or not host.public_key:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Slipway can only set up a host it signs in to with a key: switch it to a generated key first"
        )
    if host.os_type not in (None, *provisioning.OS_LABELS):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Slipway can only set up Ubuntu servers")
    admin = _admin_login(body.admin_username, body.admin_password, host.username)
    provisioning.begin(host)
    audit.record(
        db, "host.setup_started", actor=ctx.user, target=host, request=request,
        summary=f"Started setting up {host.name} as {admin.username}: user {host.username}, SSH key and Docker",
    )
    await db.commit()
    _start_setup(host, admin, ctx)
    return host_out(host)


@router.get("/{host_id}")
async def get_host(host_id: uuid.UUID, ctx: Reader, db: DB) -> HostOut:
    return await _out(db, await _get(db, host_id))


async def _deployed_instances(db: DB, host: Host) -> list[Instance]:
    """Instances on the host that have ever been deployed (they have files under its deploy root)."""
    ever_deployed = or_(
        Instance.status != InstanceStatus.CREATED,
        Instance.current_commit_sha.is_not(None),
        Instance.last_deployed_at.is_not(None),
    )
    # Instances given a folder of their own don't live under the deploy root and stay where they are.
    stmt = select(Instance).where(Instance.host_id == host.id, ever_deployed, Instance.deploy_dir.is_(None))
    return list(await db.scalars(stmt.order_by(Instance.name)))


async def _deploying(db: DB, instances: list[Instance]) -> bool:
    if any(inst.status == InstanceStatus.DEPLOYING for inst in instances):
        return True
    active = select(func.count()).select_from(Deployment).where(
        Deployment.instance_id.in_([inst.id for inst in instances]),
        Deployment.status.in_([DeploymentStatus.QUEUED, DeploymentStatus.RUNNING]),
    )
    return bool(await db.scalar(active))


@router.patch("/{host_id}")
async def update_host(host_id: uuid.UUID, body: HostUpdate, ctx: Writer, request: Request, db: DB) -> HostOut:
    """Update the host. A new deploy root moves the files of instances deployed on it over SSH.

    Answers the host, with a ``warning`` when the move left something for the user to do.
    """
    host = await _get(db, host_id)
    _not_while_setting_up(host)
    old_root = host.deploy_root
    to_move: list[Instance] = []
    if body.deploy_root is not None and body.deploy_root != old_root:
        to_move = await _deployed_instances(db, host)
    if host.owner_environment_id is not None:
        # A host an environment made: only its label and description change here (phase 4 §3.3, P5 D18).
        changed = _changed_fields(host, body)
        if "deploy_root" in changed and to_move:
            await _refuse_owned(db, host, "move_root")
        for field in sorted(changed):
            await _refuse_owned(db, host, "address" if field == "name" else field)
    if body.name and body.name != host.name:
        if await db.scalar(select(Host).where(Host.name == body.name)):
            raise HTTPException(status.HTTP_409_CONFLICT, "A host with this name already exists")
    if to_move:
        reconnects = (
            (body.hostname and body.hostname != host.hostname)
            or (body.port and body.port != host.port)
            or (body.username and body.username != host.username)
            or body.auth_method
            or body.private_key
            or body.password
        )
        if reconnects:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "Change the deploy root on its own: Slipway moves the instances' files over the current connection. "
                "Save the address or sign-in change separately.",
            )

    async def save() -> None:
        if body.name and body.name != host.name:
            host.name = body.name
        moved = (body.hostname and body.hostname != host.hostname) or (body.port and body.port != host.port)
        old_address = host.address
        old_fingerprint = await _stored_fingerprint(db, host) if moved else None
        for field in ("hostname", "port", "username", "label", "description", "deploy_root"):
            value = getattr(body, field)
            if value is not None:
                setattr(host, field, value)
        if body.proxy_address is not None:
            host.proxy_address = body.proxy_address or None
        if body.lan_address is not None:
            host.lan_address = body.lan_address or None
        _apply_credentials(host, body)
        summary = f"Updated host {host.name}"
        if moved:  # possibly a different machine: forget the pinned host key and re-verify
            _forget_host_key(host)
            summary += f" (address {old_address} -> {host.address})"
        if to_move:
            summary += f" (moved {', '.join(i.name for i in to_move)} from {old_root} to {host.deploy_root})"
        audit.record(db, "host.update", actor=ctx.user, target=host, summary=summary, request=request)
        if moved and old_fingerprint:
            audit.record(
                db, "host.key_reset", actor=ctx.user, target=host, request=request,
                summary=f"Cleared pinned key {old_fingerprint} for {host.name}: address changed to {host.address}",
            )
        await db.commit()

    if not to_move:
        await save()
        return await _out(db, host)

    notes: list[str] = []
    try:
        async with AsyncExitStack() as stack:
            # Every runner key of the instances on the host: members of one environment share theirs (§8.2).
            keys = {k for inst in to_move for k in data.runner_keys(inst)}
            await stack.enter_async_context(deployer.runner.exclusive(tuple(keys)))
            if await _deploying(db, to_move):
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    "A deployment is in progress on this host; change the deploy root when it finishes",
                )
            await db.commit()  # release the DB connection during SSH
            notes = await deployer.move_deploy_root(host, to_move, body.deploy_root, save=save)
    except deployer.RunnerBusy as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except deployer.DeployError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except ssh.SSHError as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, f"Could not move the files on {host.name}: {exc}. Nothing was changed."
        ) from exc
    if notes:
        audit.record(
            db, "host.deploy_root_notes", actor=ctx.user, target=host, request=request,
            summary=f"Moving {host.name}'s deploy root to {host.deploy_root}: {' '.join(notes)}",
            details={"warning": " ".join(notes)},
        )
        await db.commit()
        return JSONResponse({**(await _out(db, host)).model_dump(mode="json"), "warning": " ".join(notes)})
    return await _out(db, host)


@router.delete("/{host_id}", status_code=204)
async def delete_host(host_id: uuid.UUID, ctx: Writer, request: Request, db: DB) -> None:
    host = await _get(db, host_id)
    _not_while_setting_up(host)
    await _refuse_owned(db, host, "delete")
    in_use = await db.scalar(select(func.count()).select_from(Instance).where(Instance.host_id == host.id))
    if in_use:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{in_use} instance(s) still run on this host; remove them first")
    audit.record(db, "host.delete", actor=ctx.user, target=host, summary=f"Removed host {host.name}", request=request)
    await db.delete(host)
    await db.commit()


@router.post("/{host_id}/check")
async def check(host_id: uuid.UUID, ctx: Auth, request: Request, db: DB) -> HostOut:
    """Probe the host. The first successful check pins its SSH host key, which needs hosts:write. A host a
    provider makes pins its own key and is checked with hosts:read once built; before that, 409."""
    host = await _get(db, host_id)
    _not_while_setting_up(host)
    owned = (host.provider or "ssh") != "ssh"
    needed = Perm.HOSTS_READ if host.is_pinned or owned else Perm.HOSTS_WRITE
    if not ctx.can(needed):
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {needed}")
    await _refuse_owned(db, host, "check")
    try:
        checked = await check_host(db, host, actor=ctx.user, request=request)
    except ssh.HostNotBuilt as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    if checked is None:
        raise not_found("Host")
    return await _out(db, checked)


@router.post("/{host_id}/reset-host-key")
async def reset_host_key(host_id: uuid.UUID, ctx: Writer, request: Request, db: DB) -> HostOut:
    host = await _get(db, host_id)
    _not_while_setting_up(host)
    await _refuse_owned(db, host, "reset_key")
    old = await _stored_fingerprint(db, host)
    _forget_host_key(host)
    audit.record(db, "host.key_reset", actor=ctx.user, target=host, summary=f"Reset pinned key {old} for {host.name}", request=request)
    await db.commit()
    return await _out(db, host)
