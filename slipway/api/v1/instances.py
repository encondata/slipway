"""Instances: a repository + branch running on a host. Create, configure, deploy, operate."""

from __future__ import annotations

import asyncio
import json
import re
import shlex
import uuid
from collections.abc import Sequence
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.api.deps import DB, Auth, not_found, require
from slipway.core.config import get_settings
from slipway.core.permissions import Perm
from slipway.db.base import utcnow
from slipway.models import (
    Backup,
    BackupStatus,
    BuildSource,
    DataMode,
    Deployment,
    DeploymentKind,
    DeploymentStatus,
    FirstAdmin,
    FirstAdminStatus,
    Host,
    Instance,
    InstanceStatus,
    Repository,
    Snapshot,
    SnapshotOrigin,
    SnapshotStatus,
    User,
)
from slipway.schemas import (
    BRANCH_MAX,
    ActionOut,
    BackupCreate,
    BackupOut,
    ConfirmIn,
    ControlIn,
    DeployIn,
    DeploymentOut,
    FirstAdminIn,
    FirstAdminOut,
    InstanceCreate,
    InstanceOut,
    InstanceUpdate,
    ResetIn,
    RestoreIn,
    SnapshotOut,
    SnapshotTake,
    deployment_out,
    deployment_outs,
    instance_outs,
    seeding_needs_download,
)
from slipway.services import (
    audit,
    backup_store,
    data,
    deployer,
    environments,
    hosts,
    jobs,
    manifest,
    snapshots,
    ssh,
    switchyard,
)
from slipway.services.auth import AuthContext
from slipway.services.github import GitHubClient, GitHubError
from slipway.services.repos import github_token_for

router = APIRouter(prefix="/instances", tags=["instances"])

Reader = Annotated[AuthContext, require(Perm.INSTANCES_READ)]
Writer = Annotated[AuthContext, require(Perm.INSTANCES_WRITE)]
Operator = Annotated[AuthContext, require(Perm.INSTANCES_OPERATE)]
Deployer = Annotated[AuthContext, require(Perm.DEPLOYMENTS_CREATE)]
LogReader = Annotated[AuthContext, require(Perm.INSTANCES_READ, Perm.LOGS_READ)]
DataReader = Annotated[AuthContext, require(Perm.INSTANCES_READ, Perm.DATA_READ)]
Backupper = Annotated[AuthContext, require(Perm.DATA_BACKUP)]
Restorer = Annotated[AuthContext, require(Perm.DATA_RESTORE)]
Resetter = Annotated[AuthContext, require(Perm.DATA_RESET)]

open_session = ssh.open_session  # replaced in tests

# Settings that decide where and how an instance runs; fixed once anything was deployed.
_PLACEMENT_FIELDS = ("host_id", "build_source", "compose_file", "dockerfile_path", "build_context", "manifest_file")
# A claimed instance runs on its host from the start, but its paths in the repository can still be
# corrected until Slipway first deploys it.
CLAIM_EDITABLE_FIELDS = frozenset({"compose_file", "dockerfile_path", "build_context"})
IN_PROGRESS = "A deployment is in progress for this instance; wait for it to finish"
ENV_UNREADABLE = (
    "The stored environment variables can't be decrypted with the configured SLIPWAY_ENCRYPTION_KEY. "
    "Add the old key after the new one (comma-separated) and run `slipway rotate-encryption-key` to recover them, "
    "or re-enter them on the instance, or clear them"
)
UNPROCESSABLE = 422  # a request that is well formed but can't be done as asked
ONLY_APPS = "Only app instances (slipway.yml) can back up, restore or reset their data"
ALREADY_CREATED = "The first admin was already created; change their password in the app"


def confirmed(instance: Instance, confirm: str | None) -> None:
    """Typed confirmation (§13): the instance's name exactly, case and spaces included. Checked first.

    For a member of an environment it is the environment's name (phase 3 D20), the name people see on the
    environment page (``data.confirm_name``)."""
    name = data.confirm_name(instance)
    if confirm != name:
        what = "environment's" if instance.environment_id is not None else "instance's"
        raise HTTPException(UNPROCESSABLE, f"Type the {what} name, {name}, exactly to confirm")


def _env_name(instance: Instance) -> str:
    """The name of the environment ``instance`` is a member of (its selectin-loaded row)."""
    env = data.loaded_environment(instance)
    return env.name if env is not None else "its environment"


def member_text(instance: Instance) -> str:
    """Why a member's own settings can't change on the instance (phase 3 §11)."""
    return (f"{instance.name} is the {instance.slot} slot of environment {_env_name(instance)}: change it on the "
            "environment")


async def _refuse_shared_data(db: AsyncSession, instance: Instance) -> None:
    """An app slot in mode ``server`` has no data of its own: its environment's lives on the data server (§7.3).
    409 with ``data_shared_reason``. The data owner, mode ``slot`` slots and standalone instances pass."""
    if instance.environment_id is None:
        return
    env = await environments.environment_of(db, instance)
    if not data.is_shared_slot(instance, env):
        return
    owner = await environments.owner_of(db, instance)
    raise HTTPException(status.HTTP_409_CONFLICT,
                        data.data_shared_reason(instance, environment=env,
                                                owner=owner if owner is not instance else None))


async def _app_job_owner(db: AsyncSession, instance: Instance) -> tuple[Instance, Instance]:
    """Create it now and Add starter content: (the instance the job is queued on, the instance the app runs in).
    In mode ``server`` the job is the data owner's whether it is asked on an app slot or on the data server, and
    the app runs on the active slot, or with none on the lead slot (phase 3 §7.3, deployer ``_on_lead``); 409
    when no app slot has been deployed. Elsewhere both are the instance itself."""
    env = await environments.environment_of(db, instance) if instance.environment_id is not None else None
    if env is None or env.data_mode == DataMode.SLOT:
        return instance, instance
    members = await environments.members(db, env)
    owner = environments.owner_in(env, members)
    if owner is None:
        await _refuse_shared_data(db, instance)
        return instance, instance
    lead = environments.lead_slot(env, members)
    if lead is None or lead.slot not in environments.APP_SLOTS or not lead.current_commit_sha:
        raise HTTPException(status.HTTP_409_CONFLICT, f"No app slot of {env.name} has been deployed yet: deploy one first")
    if environments.stale_of(lead):
        raise HTTPException(status.HTTP_409_CONFLICT, f"Deploy to {lead.slot} first: it was stopped when the data was "
                                                      "restored")
    return owner, lead


def need(ctx: AuthContext, *permissions: str, message: str | None = None) -> None:
    """403 unless the user holds every one of ``permissions`` (for permissions that depend on the request)."""
    missing = [p for p in permissions if not ctx.can(p)]
    if missing:
        raise HTTPException(status.HTTP_403_FORBIDDEN, message or f"Missing permission: {', '.join(missing)}")


def _snapshots_error(exc: snapshots.SnapshotsError) -> HTTPException:
    return HTTPException(exc.status, exc.message)


async def _check_hostnames(db: AsyncSession, routes: list[Any] | None, instance_id: uuid.UUID | None) -> None:
    """Answer 409 when another instance, or a live environment (phase 3 §11), already has one of these
    hostnames."""
    wanted = {r.hostname for r in routes or []}
    if not wanted:
        return
    others = (await db.execute(select(Instance.name, Instance.routes).where(Instance.id != instance_id))).all()
    for name, other_routes in others:
        taken = wanted & {r.get("hostname") for r in other_routes or []}
        if taken:
            raise HTTPException(status.HTTP_409_CONFLICT, f"{sorted(taken)[0]} is already a hostname of instance {name}")
    held = await environments.environment_with_hostname(db, wanted)
    if held:
        raise HTTPException(status.HTTP_409_CONFLICT, held)


async def _check_slug_free(db: AsyncSession, slug: str) -> None:
    """``<env>-blue``, ``-green`` and ``-data`` are reserved for every live environment (§3.2)."""
    reserved = await environments.reserved_slug(db, slug)
    if reserved is not None:
        env, slot = reserved
        raise HTTPException(status.HTTP_409_CONFLICT, environments.reserved_text(slug, env, slot))


async def _check_folder(db: AsyncSession, host: Host, folder: str, instance_id: uuid.UUID | None) -> None:
    """Answer 409 when ``folder`` is, holds or is inside another instance's folder on the same host."""
    others = (await db.scalars(select(Instance).where(Instance.host_id == host.id, Instance.id != instance_id))).all()
    for other in others:
        try:
            theirs = deployer.instance_dir(other)
        except deployer.DeployError:
            continue
        if folder == theirs or folder.startswith(theirs + "/") or theirs.startswith(folder + "/"):
            raise HTTPException(status.HTTP_409_CONFLICT, f"{folder} overlaps {theirs}, the folder of instance {other.name}")


def _folder_of(host: Host, slug: str, deploy_dir: str | None) -> str:
    return deploy_dir or f"{deployer.clean_deploy_root(host.deploy_root)}/{slug}"


async def _get(db: DB, instance_id: uuid.UUID) -> Instance:
    instance = await db.get(Instance, instance_id)
    if instance is None:
        raise not_found("Instance")
    return instance


async def env_unreadable(db: AsyncSession, instance: Instance) -> bool:
    """True when variables are stored but can't be decrypted: they load as None while the column is set.

    The same test as ``deployer._start``; ``IS NOT NULL`` does not decrypt anything.
    """
    if instance.env is not None:
        return False
    return bool(await db.scalar(select(Instance.env.is_not(None)).where(Instance.id == instance.id)))


async def unreadable_env_ids(db: AsyncSession, instances: Sequence[Instance]) -> set[uuid.UUID]:
    """``env_unreadable`` for many instances in one query."""
    ids = [i.id for i in instances if i.env is None]
    if not ids:
        return set()
    return set((await db.scalars(select(Instance.id).where(Instance.id.in_(ids), Instance.env.is_not(None)))).all())


async def instance_out(db: AsyncSession, instance: Instance) -> InstanceOut:
    unreadable = {instance.id} if await env_unreadable(db, instance) else set()
    return (await instance_outs(db, [instance], unreadable=unreadable))[0]


async def _active_deployment(db: DB, instance_id: uuid.UUID) -> uuid.UUID | None:
    return await db.scalar(
        select(Deployment.id)
        .where(
            Deployment.instance_id == instance_id,
            Deployment.status.in_([DeploymentStatus.QUEUED, DeploymentStatus.RUNNING]),
        )
        .limit(1)
    )


async def deployment_started(db: AsyncSession, instance: Instance) -> bool:
    started = await db.scalar(
        select(Deployment.id).where(Deployment.instance_id == instance.id, Deployment.started_at.is_not(None)).limit(1)
    )
    return started is not None


async def _ever_deployed(db: DB, instance: Instance) -> bool:
    """True once something may exist on the host: any status but CREATED, or a deployment that started."""
    if instance.status != InstanceStatus.CREATED:
        return True
    return await deployment_started(db, instance)


async def claim_paths_editable(db: AsyncSession, instance: Instance) -> bool:
    """A claimed instance that no deployment has started on yet: its repository paths may change."""
    return instance.claim_pending and not await deployment_started(db, instance)


BUSY = "A job is already running for this instance; wait for it to finish"
# What a change that isn't a job holds in the runner (phase 3 §8.2): the instance's id, or both keys of its
# environment. A module name, because some handlers have a local ``data``.
_runner_keys = data.runner_keys


async def queue_deployment(
    db: DB, instance: Instance, user: User, *, kind: str = DeploymentKind.DEPLOY, retry_of: Deployment | None = None,
    options: dict[str, Any] | None = None, **refs: Any,
) -> Deployment:
    """Add a queued job for ``instance`` (the caller audits, commits and submits it).

    ``refs`` are the rows the job points at (``backup_id``, ``restore_backup_id``, ``snapshot_id``). A retry
    takes its kind, options, references and commit from the job it retries (``deployer.retry_values``), with
    ``options`` added on top. Jobs that run the live release copy the live release's commit.

    ``jobs.queue_job`` (phase 3 §8.5) does the work: a standalone instance meets exactly the checks it met
    before; an environment member also meets its environment's fences. Its refusal becomes the HTTP answer.
    """
    try:
        return await jobs.queue_job(db, instance=instance, user=user, kind=kind, retry_of=retry_of,
                                    options=options, **refs)
    except jobs.JobRefused as exc:
        raise HTTPException(exc.status, exc.text) from exc


async def _submit(db: AsyncSession, dep: Deployment, instance: Instance) -> DeploymentOut:
    """Commit the queued job (with its audit record), start it, and answer with it."""
    await db.commit()
    await db.refresh(dep)
    deployer.runner.submit(dep.id, data.job_keys(dep, instance))
    return await deployment_out(db, dep)


def _ssh_error(exc: ssh.SSHError) -> HTTPException:
    return HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))


def _not_built(exc: ssh.HostNotBuilt) -> HTTPException:
    """A host a provider hasn't built yet (P4 §3.3): nothing to connect to, so 409 with its text. Not an
    SSHError, so it never becomes ``_ssh_error``'s 502."""
    return HTTPException(status.HTTP_409_CONFLICT, str(exc))


def _require_host(instance: Instance) -> Host:
    """409 for a managed environment's data owner, which has no host (P4 §3.4); else its host."""
    if instance.host is None:
        raise HTTPException(status.HTTP_409_CONFLICT, data.hostless_text(instance))
    return instance.host


async def _refuse_owned(db: AsyncSession, host: Host, action: str) -> None:
    """409 when ``host`` is one an environment made (a droplet or a VM): only that environment's slots run there
    (``hosts.owned_host_refusal``, phase 4 §3.3, phase 5 §10.4)."""
    problem = await hosts.owned_host_problem(db, host, action=action)
    if problem:
        raise HTTPException(status.HTTP_409_CONFLICT, problem)


def _require_built(instance: Instance) -> None:
    """409 with ``HostNotBuilt``'s text while the instance's host isn't built (a planned or gone droplet, a VM
    not made yet; P4 §3.3, test 63). Phase 3's hosts are always built."""
    host = _require_host(instance)
    if not ssh.host_is_built(host):
        try:
            ssh.SSHTarget.from_host(host)
        except ssh.HostNotBuilt as exc:
            raise _not_built(exc) from exc


@router.get("")
async def list_instances(ctx: Reader, db: DB, host_id: uuid.UUID | None = None, repository_id: uuid.UUID | None = None) -> list[InstanceOut]:
    # A managed environment's data owner has no host (P4 §3.4): it is shown on its environment, not here.
    stmt = select(Instance).where(Instance.host_id.is_not(None)).order_by(Instance.name)
    if host_id:
        stmt = stmt.where(Instance.host_id == host_id)
    if repository_id:
        stmt = stmt.where(Instance.repository_id == repository_id)
    instances = list((await db.scalars(stmt)).all())
    return await instance_outs(db, instances, unreadable=await unreadable_env_ids(db, instances))


@router.post("", status_code=201)
async def create_instance(body: InstanceCreate, ctx: Writer, request: Request, db: DB) -> InstanceOut:
    if body.deploy and not ctx.can(Perm.DEPLOYMENTS_CREATE):
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {Perm.DEPLOYMENTS_CREATE}")
    if body.seed_snapshot_id is not None:
        need(ctx, Perm.DATA_RESET, message="Starting from a snapshot needs the data:reset permission")
    if (body.seed_snapshot_id is not None or body.first_admin is not None) and body.build_source != BuildSource.APP:
        raise HTTPException(UNPROCESSABLE,
                            "Only app instances (slipway.yml) can start from a snapshot or have a first admin")
    repo = await db.get(Repository, body.repository_id)
    host = await db.get(Host, body.host_id)
    if repo is None or host is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown repository or host")
    await _refuse_owned(db, host, "instance")
    try:
        slug = deployer.slugify(body.name)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if await db.scalar(select(Instance).where(Instance.slug == slug)):
        raise HTTPException(status.HTTP_409_CONFLICT, f"An instance named '{slug}' already exists")
    await _check_slug_free(db, slug)
    await _check_hostnames(db, body.routes, None)
    await _check_folder(db, host, _folder_of(host, slug, body.deploy_dir or None), None)
    if not body.branch and not repo.default_branch_usable:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Slipway could not store the default branch of {repo.full_name} (its name is longer than "
            f"{BRANCH_MAX} characters); specify a branch",
        )
    branch = body.branch or repo.default_branch
    seed: Snapshot | None = None
    if body.seed_snapshot_id is not None or body.first_admin is not None:
        # Checked against the branch's slipway.yml, as the form showed it (§10.7, §11.1); again when it runs.
        path = body.manifest_file or manifest.DEFAULT_FILE
        branch_man = await branch_manifest(ctx, repo, branch, path)
        where = f"{path} on {branch}"
        if body.seed_snapshot_id is not None:
            seed = await db.get(Snapshot, body.seed_snapshot_id)
            if seed is None:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown snapshot")
            check_seed(ctx, seed, name=body.name.strip(), repository=repo.full_name, man=branch_man,
                       env=body.env or {}, where=where)
        if body.first_admin is not None:
            check_first_admin(branch_man, body.first_admin, where=where)

    instance = Instance(
        name=body.name.strip(),
        slug=slug,
        repository=repo,
        host=host,
        branch=body.branch or repo.default_branch,
        build_source=body.build_source,
        dockerfile_path=body.dockerfile_path or "Dockerfile",
        build_context=body.build_context or ".",
        compose_file=body.compose_file or repo.compose_file or "docker-compose.yml",
        deploy_dir=body.deploy_dir or None,
        manifest_file=body.manifest_file or manifest.DEFAULT_FILE,
        app_settings=body.app_settings or {},
        app_services=body.app_services,
        env=body.env or {},
        ports=[p.model_dump() for p in body.ports or []],
        volumes=[v.model_dump() for v in body.volumes or []],
        auto_ports=True if body.auto_ports is None else body.auto_ports,
        port_overrides=[o.model_dump() for o in body.port_overrides or []],
        routes=[r.model_dump() for r in body.routes or []],
        status=InstanceStatus.CREATED,
        created_by_id=ctx.user.id,
        keep_backups=body.keep_backups or 5,
        seed_content=True if body.seed_content is None else body.seed_content,
        seed_snapshot_id=seed.id if seed is not None else None,
    )
    db.add(instance)
    await db.flush()
    details: dict[str, Any] = {}
    if seed is not None:
        details["seed_snapshot"] = seed.name
    if body.first_admin is not None:
        details["first_admin"] = _admin_summary(body.first_admin)
        db.add(_new_first_admin(instance, body.first_admin, body.first_admin.password, ctx.user))
    audit.record(
        db, "instance.create", actor=ctx.user, target=instance, details=details or None,
        summary=f"Created instance {instance.name} ({repo.full_name}@{instance.branch} on {host.name})", request=request,
    )
    dep = await queue_deployment(db, instance, ctx.user) if body.deploy else None
    await db.commit()
    if dep is not None:
        deployer.runner.submit(dep.id, data.job_keys(dep, instance))
    return await instance_out(db, instance)  # a new instance's env was just set, so it is readable


@router.get("/{instance_id}")
async def get_instance(instance_id: uuid.UUID, ctx: Reader, db: DB) -> InstanceOut:
    instance = await _get(db, instance_id)
    return await instance_out(db, instance)  # the host-less owner's host and host_id are null


@router.get("/{instance_id}/env")
async def get_env(instance_id: uuid.UUID, ctx: Writer, db: DB) -> dict[str, str]:
    """Environment variable values are only visible to people who can edit the instance.

    Answers 409 when the stored values can't be decrypted, so a read-modify-write can't erase them.
    """
    instance = await _get(db, instance_id)
    if await env_unreadable(db, instance):
        raise HTTPException(status.HTTP_409_CONFLICT, ENV_UNREADABLE)
    return instance.env or {}


@router.patch("/{instance_id}")
async def update_instance(instance_id: uuid.UUID, body: InstanceUpdate, ctx: Writer, request: Request, db: DB) -> InstanceOut:
    instance = await _get(db, instance_id)
    data = body.model_dump(exclude_unset=True)
    if instance.environment_id is not None:
        # A member's settings, secrets, data and names belong to its environment (§11): only its name and
        # whether Slipway may pick free ports stay editable here.
        if any(k not in ("name", "auto_ports") for k in data):
            raise HTTPException(status.HTTP_409_CONFLICT, member_text(instance))
    await _check_seed_update(db, ctx, instance, data)
    changing = {f for f in _PLACEMENT_FIELDS if data.get(f) is not None and data[f] != getattr(instance, f)}
    if "host_id" in changing:
        target = await db.get(Host, data["host_id"])
        if target is not None:
            await _refuse_owned(db, target, "placement")
    if body.deploy_dir is not None and (body.deploy_dir or None) != instance.deploy_dir:
        if changing:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Change the folder on its own, without the host or build settings")
        return await _change_folder(db, instance, body, data, ctx, request)
    if not changing:
        return await _apply_update(db, instance, body, data, ctx, request)
    # Hold the instance's deploy lock until the commit, so no deployment starts in between.
    try:
        async with deployer.runner.exclusive(_runner_keys(instance)):
            if await _active_deployment(db, instance.id) is not None:
                raise HTTPException(status.HTTP_409_CONFLICT, IN_PROGRESS)
            if await _ever_deployed(db, instance) and not (
                changing <= CLAIM_EDITABLE_FIELDS and await claim_paths_editable(db, instance)
            ):
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    "The host and build settings can't change once an instance has been deployed. "
                    "Delete it (removing it from the host) and create it again.",
                )
            return await _apply_update(db, instance, body, data, ctx, request)
    except deployer.RunnerBusy as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc


async def _change_folder(
    db: DB, instance: Instance, body: InstanceUpdate, data: dict[str, Any], ctx: AuthContext, request: Request
) -> Response | InstanceOut:
    """Give the instance another folder. Once it has been deployed, its files move there over SSH first."""
    host = _require_host(instance)
    old = deployer.instance_dir(instance)
    new = _folder_of(host, instance.slug, body.deploy_dir or None)
    await _check_folder(db, host, new, instance.id)
    result: list[InstanceOut] = []

    async def save() -> None:
        result.append(await _apply_update(db, instance, body, data, ctx, request))

    try:
        async with deployer.runner.exclusive(_runner_keys(instance)):
            if await _active_deployment(db, instance.id) is not None:
                raise HTTPException(status.HTTP_409_CONFLICT, IN_PROGRESS)
            if new == old or not await _ever_deployed(db, instance):
                await save()
                return result[0]
            await db.commit()  # release the DB connection during SSH
            notes = await deployer.move_instance_dir(instance, new, save=save)
    except deployer.RunnerBusy as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except deployer.DeployError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except ssh.HostNotBuilt as exc:
        raise _not_built(exc) from exc
    except ssh.SSHError as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, f"Could not move the files on {host.name}: {exc}. Nothing was changed."
        ) from exc
    audit.record(db, "instance.move", actor=ctx.user, target=instance, request=request,
                 summary=f"Moved {instance.name}'s folder from {old} to {new}" + (f": {' '.join(notes)}" if notes else ""),
                 details={"from": old, "to": new, **({"warning": " ".join(notes)} if notes else {})})
    await db.commit()
    if notes:
        return JSONResponse({**result[0].model_dump(mode="json"), "warning": " ".join(notes)})
    return result[0]


async def _apply_update(
    db: DB, instance: Instance, body: InstanceUpdate, data: dict[str, Any], ctx: AuthContext, request: Request
) -> InstanceOut:
    unreadable = await env_unreadable(db, instance)
    if data.get("host_id") is not None and data["host_id"] != instance.host_id:
        host = await db.get(Host, data["host_id"])
        if host is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown host")
        instance.host = host
    if body.deploy_dir is not None:
        instance.deploy_dir = body.deploy_dir or None
    for field in ("name", "branch", "build_source", "dockerfile_path", "build_context", "compose_file", "manifest_file"):
        if data.get(field) is not None:
            setattr(instance, field, data[field])
    if body.app_settings is not None:
        instance.app_settings = body.app_settings
    if "app_services" in data:
        instance.app_services = body.app_services
    if body.ports is not None:
        instance.ports = [p.model_dump() for p in body.ports]
    if body.volumes is not None:
        instance.volumes = [v.model_dump() for v in body.volumes]
    if body.auto_ports is not None:
        instance.auto_ports = body.auto_ports
    if body.port_overrides is not None:
        instance.port_overrides = [o.model_dump() for o in body.port_overrides]
    if body.routes is not None:
        await _check_hostnames(db, body.routes, instance.id)
        instance.routes = [r.model_dump() for r in body.routes]
    if body.keep_backups is not None:
        instance.keep_backups = body.keep_backups
    if body.seed_content is not None:
        instance.seed_content = body.seed_content
    if "seed_snapshot_id" in data:
        instance.seed_snapshot_id = body.seed_snapshot_id  # checked by _check_seed_update
    changed = sorted(k for k in data if k not in ("env", "clear_env"))
    # Stored values that can't be decrypted are kept, since the old key may still recover them, and the
    # deploy guard keeps refusing to run without them. Only re-entered variables (a non-empty env) or
    # clear_env replace them; an empty env, which is what saving the edit form sends, does not.
    replaced = body.clear_env or bool(body.env) or (body.env is not None and not unreadable)
    if replaced:
        instance.env = body.env or {}  # clear_env on purpose also erases values that can't be decrypted
        changed.append("env (cleared)" if body.clear_env and not body.env else "env")
    details = None
    if unreadable and (body.env is not None or body.clear_env):
        details = {"env_unreadable": True, "env_replaced": replaced}
    if "seed_snapshot_id" in data:
        seed = await db.get(Snapshot, body.seed_snapshot_id) if body.seed_snapshot_id else None
        details = {**(details or {}), "seed_snapshot": seed.name if seed is not None else None}
    audit.record(
        db, "instance.update", actor=ctx.user, target=instance, details=details,
        summary=f"Updated {instance.name}: {', '.join(changed) or 'no changes'}", request=request,
    )
    await db.commit()
    return await instance_out(db, instance)


@router.delete("/{instance_id}", status_code=204)
async def delete_instance(instance_id: uuid.UUID, ctx: Writer, request: Request, db: DB, purge: bool = True) -> Response:
    """Delete the instance. With ``purge`` (default) its containers and files are removed from the host.
    Without it, only the ``<name>.identity.env`` files of backups taken with other identity keys than the data's
    are written next to their dumps (the rows that hold those keys go with the instance).

    Answers 204, or 200 with ``{"ok": true, "warning": "..."}`` when files had to be left on the host.
    """
    instance = await _get(db, instance_id)
    if instance.environment_id is not None:
        env = _env_name(instance)
        raise HTTPException(status.HTTP_409_CONFLICT, f"Delete {env} instead" if instance.slot == "data"
                            else f"Remove the slot from {env} instead")
    warning: str | None = None
    report: dict[str, Any] = {}  # the backups kept on the host (names and SHA-256s) and their folder
    try:
        async with deployer.runner.exclusive(_runner_keys(instance), deleting=True):
            if instance.status == InstanceStatus.DEPLOYING or await _active_deployment(db, instance.id) is not None:
                raise HTTPException(status.HTTP_409_CONFLICT, IN_PROGRESS)
            if purge and await _ever_deployed(db, instance):
                await db.commit()  # release the DB connection during SSH
                try:
                    warning = await deployer.destroy(instance, report=report)
                except ssh.HostNotBuilt as exc:
                    raise _not_built(exc) from exc
                except (ssh.SSHError, deployer.DeployError) as exc:
                    raise HTTPException(
                        status.HTTP_502_BAD_GATEWAY, f"{exc}. Retry, or delete with purge=false to keep the host untouched."
                    ) from exc
            elif not purge:
                # The rows that hold its backups' identity values go with it: those the keys in its .env don't
                # open are written next to the dumps first (data-loss 16).
                await db.commit()  # release the DB connection during SSH
                warning = await deployer.keep_identity_files(instance, connect=open_session)
            if instance.proxy_entries:
                warning = " ".join(filter(None, [warning, await _remove_proxy_entries(instance)])) or None
            summary = f"Deleted instance {instance.name}" + (f". {warning}" if warning else "")
            details: dict[str, Any] = {"warning": warning} if warning else {}
            if report.get("backups"):
                details.update(kept_backups=report["backups"], kept_backups_folder=report.get("kept_backups"))
            audit.record(
                db, "instance.delete", actor=ctx.user, target=instance, summary=summary,
                details=details or None, request=request,
            )
            await db.delete(instance)
            await db.commit()
    except deployer.RunnerBusy as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    if warning:
        return JSONResponse({"ok": True, "warning": warning})
    return Response(status_code=status.HTTP_204_NO_CONTENT)


async def _remove_proxy_entries(instance: Instance) -> str | None:
    """Remove the instance's hostnames from Switchyard; a warning when that did not fully work."""
    problems: list[str] = []

    async def say(line: str) -> None:
        if "removed" not in line and "applied" not in line:
            problems.append(line.removeprefix("Proxy: "))

    try:
        left = await switchyard.sync(instance, say=say, remove_all=True)
    except Exception as exc:  # never block deleting the instance on the proxy
        return f"Its hostnames could not be removed from Switchyard ({exc}); remove them there"
    problems += [f"{e['hostname']}: {e['message']}" for e in left if e.get("state") == "error"]
    if not problems:
        return None
    return "Switchyard: " + "; ".join(dict.fromkeys(problems))


@router.post("/{instance_id}/proxy/sync")
async def sync_proxy(instance_id: uuid.UUID, ctx: Writer, request: Request, db: DB) -> dict[str, Any]:
    """Publish the instance's hostnames in Switchyard now, as a deploy does at its end."""
    instance = await _get(db, instance_id)
    if instance.environment_id is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{_env_name(instance)}'s names are published by the environment")
    if instance.status == InstanceStatus.CREATED and not instance.proxy_entries:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Deploy the instance first: its ports are not published yet")
    await db.commit()  # release the DB connection during the HTTP calls
    lines: list[str] = []

    async def say(line: str) -> None:
        lines.append(line)

    entries = await switchyard.sync_and_store(instance, say=say)
    audit.record(db, "instance.proxy_sync", actor=ctx.user, target=instance,
                 summary=f"Synced hostnames of {instance.name} with Switchyard", details={"log": lines[:50]}, request=request)
    await db.commit()
    out: dict[str, Any] = {"ok": all(e["state"] != "error" for e in entries), "entries": entries, "log": lines}
    problems = [f"{e['hostname']}: {e['message']}" for e in entries if e["state"] != "live"]
    if problems:
        out["warning"] = "; ".join(problems)
    return out


@router.post("/{instance_id}/deploy", status_code=202)
async def deploy(
    instance_id: uuid.UUID, ctx: Deployer, request: Request, db: DB, body: DeployIn | None = None
) -> DeploymentOut:
    """Deploy the instance's branch. The optional flags each need their permission and the typed name:
    ``override_hold`` and ``take_over_lock`` (data:reset), ``skip_revision_check`` (data:restore)."""
    body = body or DeployIn()
    instance = await _get(db, instance_id)
    if instance.environment_id is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Deploy {_env_name(instance)} from its page: Slipway picks the slot")
    if body.override_hold or body.take_over_lock:
        need(ctx, Perm.DATA_RESET)
    if body.skip_revision_check:
        need(ctx, Perm.DATA_RESTORE)
    flags = {k: True for k in ("override_hold", "take_over_lock", "skip_revision_check") if getattr(body, k)}
    if flags:
        confirmed(instance, body.confirm)
    held = await data.hold_text(db, instance)
    if held and not body.override_hold:
        raise HTTPException(status.HTTP_409_CONFLICT, held)
    dep = await queue_deployment(db, instance, ctx.user, options=flags)
    if held:
        audit.record(db, "instance.hold_override", actor=ctx.user, target=instance, request=request,
                     summary=f"Deployed {instance.name} while its data was held",
                     details={"hold": instance.data_dirty, "deployment": str(dep.id)})
    audit.record(db, "deployment.create", actor=ctx.user, target=dep, summary=f"Deploy {instance.name}@{instance.branch}",
                 details=flags or None, request=request)
    return await _submit(db, dep, instance)


@router.post("/{instance_id}/actions/{action}")
async def control(
    instance_id: uuid.UUID, action: Literal["start", "stop", "restart"], ctx: Operator, request: Request, db: DB,
    body: ControlIn | None = None,
) -> ActionOut:
    """Start, stop or restart the instance's containers. Runs inside the instance's runner lock, so it never
    overlaps a job (a backup or a snapshot leaves the status as it is). Start and restart are refused while a
    data hold stands, unless ``override_hold`` (data:reset and the typed name)."""
    body = body or ControlIn()
    instance = await _get(db, instance_id)
    if body.override_hold:
        need(ctx, Perm.DATA_RESET)
        confirmed(instance, body.confirm)
    # Before the status check: a planned slot's instance is CREATED, and its answer is that the host isn't built.
    _require_built(instance)
    if instance.status in (InstanceStatus.CREATED, InstanceStatus.DEPLOYING):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Instance is {instance.status}")
    env = await environments.environment_of(db, instance)
    if env is not None and action in ("start", "restart") and instance.slot in environments.APP_SLOTS \
            and environments.stale_of(instance):
        # A slot a data job left stopped can't run the data as it is now (D16): deploy to it instead.
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"Deploy to {instance.slot} first: it was stopped when the data was restored")
    try:
        async with deployer.runner.exclusive(_runner_keys(instance)):
            running = await data.active_job(db, instance.id)
            if running is not None:
                raise HTTPException(status.HTTP_409_CONFLICT, _running_text(running))
            if env is not None:
                busy = await jobs.busy_job(db, env, data.env_keys(env.id, None))
                if busy is not None:
                    raise HTTPException(status.HTTP_409_CONFLICT, environments.busy_text(env, busy))
            # The data's fields are the data owner's (phase 3 D3): its hold and the time of the last start.
            owner = await environments.owner_of(db, instance) if env is not None else instance
            owner = owner if owner is not None else instance
            if action in ("start", "restart"):
                held = await data.hold_text(db, instance)
                if held and not body.override_hold:
                    raise HTTPException(status.HTTP_409_CONFLICT, held)
                if held:
                    # The hold goes at once; the dirty state (and its roll back point) stays (§8.4).
                    audit.record(db, "instance.hold_override", actor=ctx.user, target=instance, request=request,
                                 summary=f"{action.title()} {instance.name} while its data was held",
                                 details={"hold": owner.data_dirty, "action": action})
                    owner.data_dirty = {**(owner.data_dirty or {}), "hold": False}
            command = deployer.control_command(instance, action)
            owner_id = owner.id
            await db.commit()  # release the DB connection during SSH
            try:
                output = await deployer.run_on_instance(instance, command)
            except ssh.HostNotBuilt as exc:
                raise _not_built(exc) from exc
            except ssh.SSHError as exc:
                raise _ssh_error(exc) from exc
            values: dict[str, Any] = {"status": InstanceStatus.STOPPED if action == "stop" else InstanceStatus.RUNNING}
            if action in ("start", "restart") and owner_id == instance.id:
                values["last_control_at"] = utcnow()  # a retry backs up what was written since (§8.1)
            # A deployment may have started meanwhile; it records the status itself.
            await db.execute(
                update(Instance).where(Instance.id == instance.id, Instance.status != InstanceStatus.DEPLOYING)
                .values(**values)
            )
            if action in ("start", "restart") and owner_id != instance.id:
                # A start of any app slot counts for the data owner's retry rule (§7.5).
                await db.execute(update(Instance).where(Instance.id == owner_id).values(last_control_at=utcnow()))
            audit.record(db, f"instance.{action}", actor=ctx.user, target=instance,
                         summary=f"{action.title()} {instance.name}", request=request)
            await db.commit()
    except deployer.RunnerBusy as exc:
        running = await data.active_job(db, instance.id)
        raise HTTPException(status.HTTP_409_CONFLICT, _running_text(running) if running else str(exc)) from exc
    return ActionOut(ok=True, output=output)


def _running_text(job: Deployment) -> str:
    return f"A job is running for this instance ({data.kind_label(job.kind)}); wait for it to finish"


@router.get("/{instance_id}/containers")
async def containers(instance_id: uuid.UUID, ctx: Reader, db: DB) -> list[dict[str, str]]:
    instance = await _get(db, instance_id)
    _require_host(instance)
    if instance.status == InstanceStatus.CREATED:
        return []
    await db.commit()  # release the DB connection during SSH
    try:
        output = await deployer.run_on_instance(instance, deployer.status_command(instance))
    except ssh.HostNotBuilt as exc:
        raise _not_built(exc) from exc
    except ssh.SSHError as exc:
        raise _ssh_error(exc) from exc
    rows = []
    for line in output.splitlines():
        try:
            data = json.loads(line)
        except ValueError:
            continue
        rows.append({k: str(data.get(k, "")) for k in ("Names", "Image", "State", "Status", "Ports", "RunningFor")})
    return rows


@router.get("/{instance_id}/logs")
async def logs(
    instance_id: uuid.UUID, ctx: LogReader, db: DB, tail: Annotated[int, Query(ge=1, le=10000)] = 200
) -> ActionOut:
    instance = await _get(db, instance_id)
    _require_host(instance)
    if instance.status == InstanceStatus.CREATED:
        return ActionOut(ok=True, output="")
    await db.commit()  # release the DB connection during SSH
    try:
        output = await deployer.run_on_instance(instance, deployer.logs_command(instance, tail), check=False)
    except ssh.HostNotBuilt as exc:
        raise _not_built(exc) from exc
    except ssh.SSHError as exc:
        raise _ssh_error(exc) from exc
    return ActionOut(ok=True, output=output)


@router.get("/{instance_id}/deployments")
async def instance_deployments(
    instance_id: uuid.UUID, ctx: Auth, db: DB, limit: Annotated[int, Query(ge=1, le=100)] = 20
) -> list[DeploymentOut]:
    if not ctx.can(Perm.DEPLOYMENTS_READ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {Perm.DEPLOYMENTS_READ}")
    deps = await db.scalars(
        select(Deployment)
        .where(Deployment.instance_id == instance_id)
        .order_by(Deployment.created_at.desc())
        .limit(limit)
    )
    return await deployment_outs(db, list(deps))


# =========================================================================== data (§13)
#
# Every data job is a Deployment with a kind (D1): build the row, audit it, commit, submit, answer 202. Record
# ids are always loaded filtered by their instance (security 11), and the typed name is checked before any
# other state check (§13).


def _require_app(instance: Instance) -> None:
    if instance.build_source != BuildSource.APP:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, ONLY_APPS)


async def branch_manifest(ctx: AuthContext, repo: Repository, branch: str, path: str) -> dict[str, Any]:
    """The repository's slipway.yml on ``branch`` (as ``Manifest.to_json``), read from GitHub."""
    token, _ = github_token_for(ctx.user)
    try:
        async with GitHubClient(token) as gh:
            text = await gh.get_file(repo.github_id, path, branch)
    except GitHubError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                            f"Could not read {path} on {branch} of {repo.full_name}: {exc}") from exc
    if text is None:
        raise HTTPException(UNPROCESSABLE, f"{repo.full_name} has no {path} on branch {branch}")
    try:
        return manifest.parse(text).to_json()
    except manifest.ManifestError as exc:
        raise HTTPException(UNPROCESSABLE, str(exc)) from exc


async def known_manifest(ctx: AuthContext, instance: Instance) -> tuple[dict[str, Any], str]:
    """What a first admin is checked against (§11.1): the live release's slipway.yml once the instance has gone
    live, otherwise its branch's. Returns the manifest and how to name it in a message."""
    man = data.live_manifest(instance)
    if instance.current_commit_sha and man:
        return man, f"release {data.live_sha7(instance)}'s slipway.yml"
    path = instance.manifest_file or manifest.DEFAULT_FILE
    return await branch_manifest(ctx, instance.repository, instance.branch, path), f"{path} on {instance.branch}"


def _first_admin_spec(man: dict[str, Any]) -> manifest.FirstAdmin | None:
    """The manifest's ``first_admin`` back from its stored JSON (only what the checks need)."""
    fa = man.get("first_admin")
    if not isinstance(fa, dict):
        return None
    fields = tuple(
        manifest.AdminField(name=str(f.get("name")), label=str(f.get("label") or f.get("name")),
                            kind=str(f.get("kind") or "text"), help=str(f.get("help") or ""),
                            max=int(f.get("max") or 200))
        for f in fa.get("fields") or [] if isinstance(f, dict)
    )
    pw, inv = fa.get("password"), fa.get("invite")
    return manifest.FirstAdmin(
        command=(), fields=fields,
        password=manifest.AdminPassword(min_length=int(pw.get("min_length") or 8)) if isinstance(pw, dict) else None,
        invite=manifest.AdminInvite(label=str(inv.get("label") or "")) if isinstance(inv, dict) else None,
    )


def check_first_admin(man: dict[str, Any], body: FirstAdminIn, *, where: str, password: str | None = None) -> None:
    """422 unless the first admin fits the manifest's ``first_admin`` (§11.1). ``password`` defaults to the
    body's (a change that keeps the stored password passes that one)."""
    spec = _first_admin_spec(man)
    if spec is None:
        raise HTTPException(UNPROCESSABLE, f"{where} declares no first_admin")
    if body.mode == "invite" and body.password:
        raise HTTPException(UNPROCESSABLE, "A first admin invited by email has no password")
    problem = deployer.first_admin_problem(spec, dict(body.fields), body.mode,
                                           body.password if password is None else password)
    if problem:
        raise HTTPException(UNPROCESSABLE, f"The first admin doesn't fit {where}: {problem}")


_EMAIL_LIKE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s.]{2,}$")


def _admin_summary(body: FirstAdminIn | FirstAdmin) -> dict[str, Any]:
    """What the audit log keeps of a first admin: its email-like fields and mode, never a password."""
    fields = body.fields or {}
    return {"emails": {k: v for k, v in fields.items() if isinstance(v, str) and _EMAIL_LIKE.match(v)},
            "mode": body.mode}


def _admin_email(body: FirstAdminIn | None) -> str | None:
    emails = list(_admin_summary(body)["emails"].values()) if body is not None else []
    return emails[0] if emails else None


def _new_first_admin(instance: Instance, body: FirstAdminIn, password: str | None, user: User) -> FirstAdmin:
    return FirstAdmin(instance_id=instance.id, fields=dict(body.fields), mode=body.mode,
                      password=password if body.mode == "password" else None, status=FirstAdminStatus.PENDING,
                      existed=False, created_by_id=user.id)


async def _first_admin_row(db: AsyncSession, instance: Instance) -> FirstAdmin | None:
    return await db.scalar(select(FirstAdmin).where(FirstAdmin.instance_id == instance.id))


async def _set_first_admin(db: AsyncSession, instance: Instance, body: FirstAdminIn, password: str | None,
                           user: User) -> str:
    """Store ``body`` as the instance's pending first admin. Returns "set" or "changed"."""
    row = await _first_admin_row(db, instance)
    if row is None:
        db.add(_new_first_admin(instance, body, password, user))
        return "set"
    row.fields, row.mode = dict(body.fields), body.mode
    row.password = password if body.mode == "password" else None
    row.status, row.existed, row.done_at, row.deployment_id, row.last_error = (
        FirstAdminStatus.PENDING, False, None, None, None)
    row.created_by_id = user.id
    return "changed"


def check_seed(ctx: AuthContext, snap: Snapshot, *, name: str, repository: str, man: dict[str, Any],
               env: dict[str, str] | None, where: str) -> None:
    """Whether an instance (``name``, of ``repository``) may start from ``snap`` (§10.7, D16). The caller has
    checked data:reset. The app id is a guard against mistakes, checked again when the job runs."""
    if snap.status != SnapshotStatus.READY:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Snapshot {snap.name} isn't ready ({snap.status})")
    if seeding_needs_download(snap, repository):
        need(ctx, Perm.SNAPSHOTS_DOWNLOAD,
             message=f"Snapshot {snap.name} was made from {snap.repository or 'an unknown repository'}; seeding "
                     f"{name} ({repository}) from it needs the snapshots:download permission")
    app = (man.get("data") or {}).get("app")
    if not app:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{where} declares no data, so {name} can't start from a snapshot")
    if snap.app != app:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"This snapshot is of app {snap.app} ({snap.app_name or snap.app}); {name} runs {app}")
    carried = set(data.release_identity_keys(man)) & set(snap.identity_keys or [])
    pinned = sorted(k for k in carried if k in (env or {}))
    if pinned:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"The snapshot brings the {pinned[0]} its data was made with, and the instance's environment "
                            f"variable {pinned[0]} would replace it: remove the variable, then try again")


async def _check_seed_update(db: AsyncSession, ctx: AuthContext, instance: Instance, fields: dict[str, Any]) -> None:
    """PATCH rules for a seeded instance (§10.7): while it starts from a snapshot and has never gone live,
    changing what code receives it (branch, slipway.yml or the snapshot) needs data:reset."""
    never_live = instance.current_commit_sha is None
    changing_seed = "seed_snapshot_id" in fields and fields["seed_snapshot_id"] != instance.seed_snapshot_id
    if instance.seed_snapshot_id is not None and never_live and not ctx.can(Perm.DATA_RESET):
        code = any(fields.get(f) is not None and fields[f] != getattr(instance, f) for f in ("branch", "manifest_file"))
        if code or changing_seed:
            snap = await db.get(Snapshot, instance.seed_snapshot_id)
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f"{instance.name} starts from snapshot {snap.name if snap else '(deleted)'}; changing "
                                "what code receives it needs data:reset")
    if not changing_seed:
        return
    need(ctx, Perm.DATA_RESET, message="Starting from a snapshot needs the data:reset permission")
    if not never_live:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"{instance.name} has gone live; use Reset data to start it from a snapshot")
    if fields["seed_snapshot_id"] is None:
        return
    if (fields.get("build_source") or instance.build_source) != BuildSource.APP:
        raise HTTPException(UNPROCESSABLE, "Only app instances (slipway.yml) can start from a snapshot")
    snap = await db.get(Snapshot, fields["seed_snapshot_id"])
    if snap is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown snapshot")
    branch = fields.get("branch") or instance.branch
    path = fields.get("manifest_file") or instance.manifest_file or manifest.DEFAULT_FILE
    man = await branch_manifest(ctx, instance.repository, branch, path)
    env = fields["env"] if fields.get("env") else instance.env
    check_seed(ctx, snap, name=instance.name, repository=instance.repository.full_name, man=man, env=env,
               where=f"{path} on {branch}")


# ----------------------------------------------------------------------- backups

LS_MARK = "slipway-ls:"


def _listing_command(backups: str) -> str:
    """Lists ``backups/`` (for the "N other files" footer). A missing folder prints ``slipway-bk: nodir``."""
    return (f"cd {shlex.quote(backups)} 2>/dev/null || {{ echo '{data.BK_MARK} nodir'; exit 0; }}; "
            f"ls -A1 | sed 's/^/{LS_MARK} /'")


def _other_files(output: str, names: set[str]) -> int | None:
    """How many entries of ``backups/`` aren't the files of a backup Slipway recorded (or its work area)."""
    lines = output.splitlines()
    if f"{data.BK_MARK} nodir" in lines:
        return 0
    count = 0
    for line in lines:
        if not line.startswith(LS_MARK):
            continue
        entry = line[len(LS_MARK):].strip()
        match = data.FILE_RE.match(entry)
        if not entry or entry == data.INCOMING_DIR or (match and match.group(1) in names):
            continue
        count += 1
    return count


def _backups_folder(instance: Instance) -> str | None:
    try:
        return deployer.paths_for(instance).backups
    except deployer.DeployError:
        return None


async def _check_on_host(db: AsyncSession, instance: Instance, rows: list[Backup],
                         backups: str) -> tuple[str | None, int | None]:
    """``?check=true`` (§4.4): check the files on the host without waiting for a job. Returns a warning (the
    stored rows are shown as they are) and the number of other files in the folder."""
    host = data.host_label(instance)
    busy = f"A job is running for {instance.name}; showing what Slipway recorded"
    try:
        async with deployer.runner.exclusive(_runner_keys(instance)):
            if await data.active_job(db, instance.id) is not None:
                return busy, None
            await db.commit()  # release the DB connection during SSH
            async with open_session(ssh.SSHTarget.from_host(deployer.host_of(instance))) as remote:
                _, listing = await remote.run(_listing_command(backups), check=False, timeout=data.PROBE_TIMEOUT)
                result = await data.check_backups(remote, db, rows, backups, host)
            await db.commit()
    except deployer.RunnerBusy:
        return busy, None
    except (ssh.SSHError, ssh.HostNotBuilt, deployer.DeployError) as exc:
        return f"Couldn't check the backups on {host} ({exc}); showing what Slipway recorded", None
    if result.warning:
        return result.warning, None
    return None, _other_files(listing, {r.name for r in rows})


async def _check_on_slipway(db: AsyncSession, instance: Instance, rows: list[Backup]) -> str | None:
    """``?check=true`` for a managed environment's data owner (P4 §10.5): its backups are kept on Slipway, so
    they are checked in Slipway's storage with no SSH. A warning when a job is running."""
    busy = f"A job is running for {data.confirm_name(instance)}; showing what Slipway recorded"
    try:
        async with deployer.runner.exclusive(_runner_keys(instance)):
            if await data.active_job(db, instance.id) is not None:
                return busy
            result = await data.check_backups(None, db, rows, None, None)
            await db.commit()
    except deployer.RunnerBusy:
        return busy
    for row in rows:
        await db.refresh(row)
    return result.warning


@router.get("/{instance_id}/backups")
async def list_backups(instance_id: uuid.UUID, ctx: DataReader, db: DB, check: bool = False) -> dict[str, Any]:
    """The instance's backups, newest first, with whether each can be restored and why not.

    ``check=true`` checks their files on the host first (when no job is running).
    """
    instance = await _get(db, instance_id)
    await _refuse_shared_data(db, instance)
    _require_app(instance)
    rows = list((await db.scalars(
        select(Backup).where(Backup.instance_id == instance.id).order_by(Backup.taken_at.desc())
    )).all())
    folder = _backups_folder(instance)
    warning: str | None = None
    other: int | None = None
    if check and folder:
        warning, other = await _check_on_host(db, instance, rows, folder)
    elif check and instance.host is None:
        warning = await _check_on_slipway(db, instance, rows)
    views = await data.backup_views(db, instance, rows)
    users = {u.id: u.display_name for u in (await db.scalars(
        select(User).where(User.id.in_({r.created_by_id for r in rows if r.created_by_id})))).all()} \
        if any(r.created_by_id for r in rows) else {}
    # "Back up now" keeps its note in the job's options (the job's backup step writes the row).
    job_ids = {r.deployment_id for r in rows if r.deployment_id and r.note is None}
    notes = {d: (o or {}).get("note") for d, o in (await db.execute(
        select(Deployment.id, Deployment.options).where(Deployment.id.in_(job_ids)))).all()} if job_ids else {}
    out: dict[str, Any] = {
        "backups": [BackupOut.of(v, created_by=users.get(v.row.created_by_id) if v.row.created_by_id else None,
                                 note=notes.get(v.row.deployment_id) if v.row.deployment_id else None) for v in views],
        "keep": instance.keep_backups,
        "manual_max": get_settings().manual_backups_max,
        "folder": folder,
        "other_files": other,
        "ram_backed": bool(folder) and deployer.ram_backed(instance.host, folder),
        "data_elsewhere": data.data_shared_reason(instance),
    }
    if warning:
        out["warning"] = warning
    return out


@router.post("/{instance_id}/backups", status_code=202)
async def back_up_now(
    instance_id: uuid.UUID, ctx: Backupper, request: Request, db: DB, body: BackupCreate | None = None
) -> DeploymentOut:
    """Back up now (kind ``backup``): a manual backup, kept until deleted by hand."""
    body = body or BackupCreate()
    instance = await _get(db, instance_id)
    await _refuse_shared_data(db, instance)
    await data.require_data_job(db, instance, DeploymentKind.BACKUP)
    if body.files and "files" not in data.capabilities(instance):
        raise HTTPException(status.HTTP_409_CONFLICT, f"{data.live_sha7(instance)}'s slipway.yml has no export_files "
                                                      f"command, so Slipway can't back up {instance.name}'s files")
    capped = await data.manual_cap_text(db, instance)
    if capped:
        raise HTTPException(status.HTTP_409_CONFLICT, capped)
    options: dict[str, Any] = {"files": body.files, "restop": instance.status == InstanceStatus.STOPPED}
    if body.note:
        options["note"] = body.note
    dep = await queue_deployment(db, instance, ctx.user, kind=DeploymentKind.BACKUP, options=options)
    audit.record(db, "backup.create", actor=ctx.user, target=dep, summary=f"Back up {instance.name}",
                 details={"files": body.files, "note": body.note}, request=request)
    return await _submit(db, dep, instance)


async def _backup(db: AsyncSession, instance: Instance, backup_id: uuid.UUID) -> Backup:
    row = await db.scalar(select(Backup).where(Backup.id == backup_id, Backup.instance_id == instance.id))
    if row is None:
        raise not_found("Backup")
    return row


@router.delete("/{instance_id}/backups/{backup_id}", status_code=204)
async def delete_backup(
    instance_id: uuid.UUID, backup_id: uuid.UUID, ctx: Resetter, request: Request, db: DB
) -> Response:
    """Delete a backup: its files on the host (only once this session confirmed them, I5), then its row. A
    backup that isn't on the host any more is just forgotten. Answers 204, or 200 with a warning when its
    files changed on the host and were left there."""
    instance = await _get(db, instance_id)
    await _refuse_shared_data(db, instance)
    _require_app(instance)
    row = await _backup(db, instance, backup_id)
    if data.on_slipway(row):
        return await _delete_stored_backup(db, instance, row, ctx, request)
    host = _require_host(instance).name
    left: str | None = None
    forgotten = False
    try:
        async with deployer.runner.exclusive(_runner_keys(instance)):
            running = await data.active_job(db, instance.id)
            if running is not None:
                raise HTTPException(status.HTTP_409_CONFLICT, _running_text(running))
            pinned = await data.pinned_backups(db, instance)
            if row.id in pinned:
                raise HTTPException(status.HTTP_409_CONFLICT, f"This backup is pinned: {pinned[row.id]}")
            if row.status == BackupStatus.PENDING:
                raise HTTPException(status.HTTP_409_CONFLICT, "This backup is still being taken")
            folder = _backups_folder(instance)
            if row.status == BackupStatus.MISSING or not folder or not data.NAME_RE.match(row.name or ""):
                forgotten = True
            else:
                name = row.name
                files = {f"{name}.dump": row.db_bytes, **({f"{name}.files": row.files_bytes} if row.has_files else {})}
                await db.commit()  # release the DB connection during SSH
                try:
                    async with open_session(ssh.SSHTarget.from_host(instance.host)) as remote:
                        code, output = await remote.run(data.file_check_command(folder, list(files)), check=False,
                                                        timeout=data.PROBE_TIMEOUT)
                        found = data.parse_file_check(output)
                        if not found.nodir and code != 0 and not found.sizes:
                            raise ssh.SSHError(f"the check exited {code}")
                        present = {f: found.sizes.get(f) for f in files if found.sizes.get(f) is not None}
                        if found.nodir or not present:
                            forgotten = True
                        elif any(size is not None and present.get(f, size) != size for f, size in files.items()):
                            left = (f"The files of backup {name} on {host} changed since Slipway took them, so Slipway "
                                    f"left them in {folder}; Slipway forgot the backup")
                        else:
                            await remote.run(data.remove_backup_command(folder, [name]), timeout=data.PROBE_TIMEOUT)
                except ssh.HostNotBuilt as exc:
                    raise _not_built(exc) from exc
                except ssh.SSHError as exc:
                    raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                                        f"Could not delete backup {name} on {host}: {exc}. Nothing was changed.") from exc
            details: dict[str, Any] = {"name": row.name, "reason": row.reason}
            details.update({"forgotten": True} if forgotten else {"sha256": row.db_sha256})
            if left:
                details["left_on_host"] = True
            audit.record(db, "backup.delete", actor=ctx.user, target=row, request=request, details=details,
                         summary=f"{'Forgot' if forgotten or left else 'Deleted'} backup {row.name} of {instance.name}")
            await db.execute(delete(Backup).where(Backup.id == row.id).execution_options(synchronize_session=False))
            await db.commit()
    except deployer.RunnerBusy as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    if left:
        return JSONResponse({"ok": True, "warning": left})
    return Response(status_code=status.HTTP_204_NO_CONTENT)


async def _delete_stored_backup(db: AsyncSession, instance: Instance, row: Backup, ctx: AuthContext,
                                request: Request) -> Response:
    """Delete a backup kept on Slipway (P4 §10.5, a managed environment's owner): its files in Slipway's storage,
    then its row, with no SSH. P2's refusals stay: a running job, a pinned backup, one still being taken. A
    backup whose key can't be read any more is deleted the same way."""
    try:
        async with deployer.runner.exclusive(_runner_keys(instance)):
            running = await data.active_job(db, instance.id)
            if running is not None:
                raise HTTPException(status.HTTP_409_CONFLICT, _running_text(running))
            pinned = await data.pinned_backups(db, instance)
            if row.id in pinned:
                raise HTTPException(status.HTTP_409_CONFLICT, f"This backup is pinned: {pinned[row.id]}")
            if row.status == BackupStatus.PENDING:
                raise HTTPException(status.HTTP_409_CONFLICT, "This backup is still being taken")
            try:
                removed = await asyncio.to_thread(backup_store.delete, instance.id, row)
            except (OSError, data.DataError) as exc:
                raise HTTPException(status.HTTP_409_CONFLICT,
                                    f"Could not delete backup {row.name} from Slipway's storage ({type(exc).__name__}). "
                                    "Nothing was changed.") from exc
            forgotten = removed == 0
            audit.record(db, "backup.delete", actor=ctx.user, target=row, request=request,
                         details={"name": row.name, "reason": row.reason, "location": row.location,
                                  **({"forgotten": True} if forgotten else {"sha256": row.db_sha256})},
                         summary=f"{'Forgot' if forgotten else 'Deleted'} backup {row.name} of "
                                 f"{data.confirm_name(instance)} (kept on Slipway)")
            await db.execute(delete(Backup).where(Backup.id == row.id).execution_options(synchronize_session=False))
            await db.commit()
    except deployer.RunnerBusy as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------- restore and reset


def _identity_needed(instance: Instance) -> str:
    label = data.identity_label(instance)
    return (f"This backup was made with other {label}; restoring it puts them back. Restore it again with "
            f"\"Put back its {label}\" (needs data:reset).")


@router.post("/{instance_id}/data/restore", status_code=202)
async def restore_backup(
    instance_id: uuid.UUID, body: RestoreIn, ctx: Restorer, request: Request, db: DB
) -> DeploymentOut:
    """Restore a backup into the live release (kind ``restore``). ``restore_identity`` (data:reset) puts back
    the identity keys the backup was made with."""
    instance = await _get(db, instance_id)
    if body.restore_identity:
        need(ctx, Perm.DATA_RESET)
    confirmed(instance, body.confirm)
    await _refuse_shared_data(db, instance)
    await data.require_data_job(db, instance, DeploymentKind.RESTORE)
    row = await _backup(db, instance, body.backup_id)
    if body.files and not row.has_files:
        raise HTTPException(UNPROCESSABLE, f"Backup {row.name} has no files to put back")
    rule = data.restorable(instance, row)
    if not rule.ok:
        raise HTTPException(status.HTTP_409_CONFLICT, rule.reason or "This backup can't be restored")
    if rule.override and not body.restore_identity:
        raise HTTPException(status.HTTP_409_CONFLICT, _identity_needed(instance))
    options: dict[str, Any] = {"files": body.files, "restore_identity": bool(rule.override) and body.restore_identity}
    latest = await data.latest_changing_job(db, instance)
    if latest is not None and latest.kind in (DeploymentKind.RESTORE, DeploymentKind.RESET) \
            and latest.backup_id == row.id:
        options["undo_of"] = latest.id.hex  # the copy taken before that job: this undoes it (§8.3)
    dep = await queue_deployment(db, instance, ctx.user, kind=DeploymentKind.RESTORE, restore_backup_id=row.id,
                                 options=options)
    audit.record(db, "instance.restore", actor=ctx.user, target=instance, request=request,
                 summary=f"Restore {instance.name} from backup {row.name}",
                 details={"backup": row.name, "taken_at": row.taken_at.isoformat(), "files": body.files,
                          "identity_restored": options["restore_identity"], "deployment": str(dep.id),
                          **({"undo_of": options["undo_of"]} if "undo_of" in options else {})})
    return await _submit(db, dep, instance)


@router.post("/{instance_id}/data/reset", status_code=202)
async def reset_data(instance_id: uuid.UUID, body: ResetIn, ctx: Resetter, request: Request, db: DB) -> DeploymentOut:
    """Reset the data (kind ``reset``): back it up, delete the app's volumes and start the live release again,
    empty (with an optional first admin and starter content) or from a snapshot."""
    instance = await _get(db, instance_id)
    confirmed(instance, body.confirm)
    await _refuse_shared_data(db, instance)
    await data.require_data_job(db, instance, DeploymentKind.RESET)
    man = data.live_manifest(instance)
    where = f"release {data.live_sha7(instance)}'s slipway.yml"
    snap: Snapshot | None = None
    if body.snapshot_id is not None:
        snap = await db.get(Snapshot, body.snapshot_id)
        if snap is None:
            raise not_found("Snapshot")
        env_row = data.loaded_environment(instance)
        check_seed(ctx, snap, name=data.confirm_name(instance), repository=instance.repository.full_name, man=man,
                   env=env_row.env if env_row is not None else instance.env, where=where)
    elif man.get("first_admin") and body.first_admin is None:
        row = await _first_admin_row(db, instance)
        if row is None or row.status != FirstAdminStatus.PENDING:
            raise HTTPException(UNPROCESSABLE,
                                "After the reset the app has no accounts: give a first admin so someone can sign in")
    if body.first_admin is not None:
        check_first_admin(man, body.first_admin, where=where)
        await _set_first_admin(db, instance, body.first_admin, body.first_admin.password, ctx.user)
    seed = snap is None and "starter_content" in data.capabilities(instance) and (
        instance.seed_content if body.seed is None else body.seed)
    dep = await queue_deployment(db, instance, ctx.user, kind=DeploymentKind.RESET,
                                 snapshot_id=snap.id if snap is not None else None, options={"seed": bool(seed)})
    audit.record(db, "instance.reset", actor=ctx.user, target=instance, request=request,
                 summary=f"Reset {instance.name}'s data " + (f"from snapshot {snap.name}" if snap else "to empty"),
                 details={"to": snap.name if snap else "empty", "seed": bool(seed),
                          "first_admin": _admin_email(body.first_admin), "deployment": str(dep.id)})
    return await _submit(db, dep, instance)


@router.post("/{instance_id}/data/start-over", status_code=202)
async def start_over(instance_id: uuid.UUID, body: ConfirmIn, ctx: Resetter, request: Request, db: DB) -> DeploymentOut:
    """Start over (a reset of a never-live instance): back up, then delete what its failed first deploys made."""
    instance = await _get(db, instance_id)
    confirmed(instance, body.confirm)
    await _refuse_shared_data(db, instance)
    await data.require_data_job(db, instance, DeploymentKind.RESET, start_over=True)
    release = await db.scalar(select(Deployment.id).where(
        Deployment.instance_id == instance.id, Deployment.kind == DeploymentKind.DEPLOY,
        Deployment.release.is_not(None)).limit(1))
    if release is None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"Slipway has no release of {instance.name} on {data.host_label(instance)} to back up its data "
                            "with; deploy once more, or remove the volumes by hand")
    dep = await queue_deployment(db, instance, ctx.user, kind=DeploymentKind.RESET, options={"start_over": True})
    state = instance.app_state or {}
    volumes = [v.get("name") for v in (state.get("live") or {}).get("volumes") or state.get("volumes") or []
               if isinstance(v, dict)]
    audit.record(db, "instance.start_over", actor=ctx.user, target=instance, request=request,
                 summary=f"Start {instance.name} over", details={"volumes": volumes, "deployment": str(dep.id)})
    return await _submit(db, dep, instance)


# ------------------------------------------------------------------------ snapshots


@router.post("/{instance_id}/snapshots", status_code=202)
async def take_snapshot(
    instance_id: uuid.UUID, body: SnapshotTake, ctx: Backupper, request: Request, db: DB
) -> dict[str, Any]:
    """Take a snapshot (kind ``snapshot``): the database, files and identity keys, kept encrypted on Slipway.
    ``stop_app`` (instances:operate too) stops the app while the data is exported."""
    instance = await _get(db, instance_id)
    await _refuse_shared_data(db, instance)
    if body.stop_app:
        need(ctx, Perm.INSTANCES_OPERATE)
    try:
        name = snapshots.check_name(body.name)
        notes = snapshots.check_notes(body.notes)
    except snapshots.SnapshotsError as exc:
        raise _snapshots_error(exc) from exc
    if await db.scalar(select(Snapshot.id).where(Snapshot.name == name)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"There is already a snapshot named {name}")
    await data.require_data_job(db, instance, DeploymentKind.SNAPSHOT)
    try:
        snapshots.require_storage()
    except snapshots.SnapshotsError as exc:
        raise _snapshots_error(exc) from exc
    man = data.live_manifest(instance)
    snap = Snapshot(id=uuid.uuid4(), name=name, notes=notes, status=SnapshotStatus.PENDING,
                    origin=SnapshotOrigin.INSTANCE, app=(man.get("data") or {}).get("app"),
                    app_name=(str(man.get("name"))[:100] if man.get("name") else None),
                    repository=instance.repository.full_name[:200], source=instance.name[:100],
                    source_instance_id=instance.id, created_by_id=ctx.user.id)
    db.add(snap)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, f"There is already a snapshot named {name}") from exc
    dep = await queue_deployment(db, instance, ctx.user, kind=DeploymentKind.SNAPSHOT, snapshot_id=snap.id,
                                 options={"stop_app": body.stop_app, "restop": instance.status == InstanceStatus.STOPPED})
    snap.deployment_id = dep.id
    audit.record(db, "snapshot.take", actor=ctx.user, target=snap, request=request,
                 summary=f"Take snapshot {name} of {instance.name}",
                 details={"name": name, "app": snap.app, "repository": snap.repository, "origin": snap.origin,
                          "stop_app": body.stop_app, "deployment": str(dep.id)})
    out = await _submit(db, dep, instance)
    return {"snapshot": SnapshotOut.of(snap).model_dump(mode="json"), "deployment": out.model_dump(mode="json")}


# ----------------------------------------------------------------------- first admin


@router.get("/{instance_id}/first-admin")
async def get_first_admin(instance_id: uuid.UUID, ctx: Reader, db: DB) -> FirstAdminOut:
    instance = await _get(db, instance_id)
    await _refuse_shared_data(db, instance)
    row = await _first_admin_row(db, instance)
    if row is None:
        raise not_found("First admin")
    return FirstAdminOut.of(row)


async def _exclusively(instance: Instance, db: AsyncSession) -> None:
    """Inside ``runner.exclusive``: 409 while a job is queued or running for the instance."""
    running = await data.active_job(db, instance.id)
    if running is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, _running_text(running))


@router.put("/{instance_id}/first-admin")
async def put_first_admin(
    instance_id: uuid.UUID, body: FirstAdminIn, ctx: Auth, request: Request, db: DB
) -> FirstAdminOut:
    """Set or change the first admin (§11.1). Before the app goes live, or while one is pending after a reset,
    this needs instances:write. On a live app with none pending it creates another account: data:reset and the
    typed name."""
    instance = await _get(db, instance_id)
    await _refuse_shared_data(db, instance)
    if instance.build_source != BuildSource.APP:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Only app instances (slipway.yml) have a first admin")
    row = await _first_admin_row(db, instance)
    live = instance.current_commit_sha is not None
    pending = row is not None and row.status == FirstAdminStatus.PENDING
    on_live = live and not pending
    if on_live:
        if row is not None and not ctx.can(Perm.DATA_RESET):
            raise HTTPException(status.HTTP_409_CONFLICT, ALREADY_CREATED)
        need(ctx, Perm.DATA_RESET)
        confirmed(instance, body.confirm)
    else:
        need(ctx, Perm.INSTANCES_WRITE)
    man, where = await known_manifest(ctx, instance)
    password = body.password
    if body.mode == "password" and password is None and pending and row is not None and row.mode == "password":
        password = row.password  # a change of the fields keeps the stored password
    check_first_admin(man, body, where=where, password=password)
    try:
        async with deployer.runner.exclusive(_runner_keys(instance)):
            await _exclusively(instance, db)
            action = await _set_first_admin(db, instance, body, password, ctx.user)
            audit.record(db, "instance.first_admin", actor=ctx.user, target=instance, request=request,
                         summary=f"{action.title()} the first admin of {instance.name}",
                         details={"action": action, **_admin_summary(body), "live": on_live})
            await db.commit()
    except deployer.RunnerBusy as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    row = await _first_admin_row(db, instance)
    assert row is not None
    return FirstAdminOut.of(row)


@router.delete("/{instance_id}/first-admin", status_code=204)
async def delete_first_admin(instance_id: uuid.UUID, ctx: Writer, request: Request, db: DB) -> Response:
    """Drop a first admin that hasn't been created yet."""
    instance = await _get(db, instance_id)
    await _refuse_shared_data(db, instance)
    row = await _first_admin_row(db, instance)
    if row is None:
        raise not_found("First admin")
    if row.status != FirstAdminStatus.PENDING:
        raise HTTPException(status.HTTP_409_CONFLICT, ALREADY_CREATED)
    try:
        async with deployer.runner.exclusive(_runner_keys(instance)):
            await _exclusively(instance, db)
            audit.record(db, "instance.first_admin", actor=ctx.user, target=instance, request=request,
                         summary=f"Dropped the first admin of {instance.name}",
                         details={"action": "dropped", **_admin_summary(row)})
            await db.delete(row)
            await db.commit()
    except deployer.RunnerBusy as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{instance_id}/first-admin/run", status_code=202)
async def create_first_admin_now(instance_id: uuid.UUID, ctx: Deployer, request: Request, db: DB) -> DeploymentOut:
    """Create it now (kind ``admin``): run the first_admin command for the pending first admin. In mode
    ``server`` the job is the data owner's, asked from it or from an app slot (phase 3 §7.3): it runs on the
    active slot, or with none on the lead slot."""
    instance, runs_on = await _app_job_owner(db, await _get(db, instance_id))
    await data.require_data_job(db, instance, DeploymentKind.ADMIN)
    row = await _first_admin_row(db, instance)
    if row is None or row.status != FirstAdminStatus.PENDING:
        raise HTTPException(status.HTTP_409_CONFLICT, f"No first admin is waiting to be created in {instance.name}")
    if runs_on.status != InstanceStatus.RUNNING:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{runs_on.name} isn't running: start it, then create the first admin")
    dep = await queue_deployment(db, instance, ctx.user, kind=DeploymentKind.ADMIN)
    audit.record(db, "instance.first_admin_run", actor=ctx.user, target=instance, request=request,
                 summary=f"Create the first admin of {instance.name}", details={"deployment": str(dep.id)})
    return await _submit(db, dep, instance)


@router.post("/{instance_id}/content/run", status_code=202)
async def add_starter_content(instance_id: uuid.UUID, ctx: Deployer, request: Request, db: DB) -> DeploymentOut:
    """Add starter content (kind ``content``) after a seed step ended in a warning. In mode ``server`` the job is
    the data owner's, as for Create it now."""
    instance, runs_on = await _app_job_owner(db, await _get(db, instance_id))
    await data.require_data_job(db, instance, DeploymentKind.CONTENT)
    if runs_on.status != InstanceStatus.RUNNING:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{runs_on.name} isn't running: start it, then add the starter content")
    if not instance.content_pending:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{instance.name} has no starter content waiting to be added")
    dep = await queue_deployment(db, instance, ctx.user, kind=DeploymentKind.CONTENT)
    audit.record(db, "instance.content_run", actor=ctx.user, target=instance, request=request,
                 summary=f"Add starter content to {instance.name}", details={"deployment": str(dep.id)})
    return await _submit(db, dep, instance)
