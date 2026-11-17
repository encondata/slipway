"""Deployment history and build output, and what a finished job offers next: retry and roll back.

Phase 3: a job of a whole environment (activate, publish, discard, remove_slot, teardown) has no instance; its
retry needs its kind's permission and goes through ``jobs.queue_job`` with the environment's fences. A failed
deploy to an app slot rolls back on the environment's data owner, where its backup is.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from slipway.api.deps import DB, Auth, not_found, require
from slipway.core.permissions import Perm
from slipway.models import DataMode, Deployment, DeploymentKind, DeploymentStatus, Environment, Instance
from slipway.schemas import ConfirmIn, DeploymentDetail, DeploymentOut, RetryIn, deployment_out, deployment_outs
from slipway.services import audit, data, deployer, environments, jobs
from slipway.services.auth import AuthContext

UNPROCESSABLE = 422

router = APIRouter(prefix="/deployments", tags=["deployments"])

Reader = Annotated[AuthContext, require(Perm.DEPLOYMENTS_READ)]
RollBacker = Annotated[AuthContext, require(Perm.DEPLOYMENTS_CREATE, Perm.DATA_RESTORE)]


@router.get("")
async def list_deployments(
    ctx: Reader,
    db: DB,
    instance_id: uuid.UUID | None = None,
    environment: uuid.UUID | None = None,
    status: Annotated[str | None, Query(max_length=16)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[DeploymentOut]:
    """``environment`` lists every job of an environment: its members' and its own (phase 3)."""
    stmt = select(Deployment).options(defer(Deployment.log, raiseload=True)).order_by(Deployment.created_at.desc()).limit(limit)
    if instance_id:
        stmt = stmt.where(Deployment.instance_id == instance_id)
    if environment:
        stmt = stmt.where(Deployment.environment_id == environment)
    if status:
        stmt = stmt.where(Deployment.status == status)
    return await deployment_outs(db, list((await db.scalars(stmt)).all()))


@router.get("/{deployment_id}")
async def get_deployment(
    deployment_id: uuid.UUID, ctx: Reader, db: DB, log_offset: Annotated[int, Query(ge=0)] = 0
) -> DeploymentDetail:
    """``log_offset`` lets the UI poll for only the new part of the build log. ``actions`` says whether the job
    can be retried, rolled back or undone, and why not."""
    dep = await db.get(Deployment, deployment_id, populate_existing=True)
    if dep is None:
        raise not_found("Deployment")
    log = dep.log or ""
    offset = max(0, min(log_offset, len(log)))
    out = await deployment_out(db, dep)
    if dep.instance_id is None:
        actions = await env_job_actions(db, dep)
    else:
        actions = _member_retry_extras(dep, await data.job_actions(db, dep))
    return DeploymentDetail(**out.model_dump(), log=log[offset:], log_offset=len(log), actions=actions)


# Environment-level kinds whose retry needs the environment's name typed (they remove things, §12.5; Deactivate
# takes a production environment off the air, phase 4 §4.1).
CONFIRMED_KINDS = (DeploymentKind.REMOVE_SLOT, DeploymentKind.TEARDOWN, DeploymentKind.DEACTIVATE)
# The steps of a teardown that a retry with forget_traffic gets past (§9.10).
TRAFFIC_STEPS = ("unroute", "undns")
# Kinds whose retry may forget VMs (phase 5 §9.5, §9.9) or let the data's only home go (Decision 26).
FORGET_VMS_KINDS = (DeploymentKind.REMOVE_SLOT, DeploymentKind.TEARDOWN)
# Member jobs whose retry asks the instance's name typed again (Decision 37): a VM revert puts the data back.
CONFIRMED_MEMBER_KINDS = (DeploymentKind.VM_REVERT,)
# Kinds that are VM jobs on a member (phase 5 §9.6-9.8): their refusals are vm_jobs', not data.require_data_job's.
VM_KINDS = (DeploymentKind.VM_SNAPSHOT, DeploymentKind.VM_REVERT, DeploymentKind.VM_DROP)


def _member_retry_extras(dep: Deployment, actions: dict[str, Any]) -> dict[str, Any]:
    """Decision 37 on the member path: ``also_needs`` lists ``data.RETRY_EXTRA`` too, and a VM revert asks the
    name typed again."""
    retry = actions.get("retry")
    if not isinstance(retry, dict):
        return actions
    extra = list(data.RETRY_EXTRA.get(dep.kind or "", ()))
    if extra:
        retry["also_needs"] = sorted(set(retry.get("also_needs") or []) | set(extra))
    if dep.kind in CONFIRMED_MEMBER_KINDS:
        retry["needs_confirm"] = True
    return actions


def _offers_forget_traffic(dep: Deployment) -> bool:
    return dep.kind == DeploymentKind.TEARDOWN and any(
        r.get("key") in TRAFFIC_STEPS and r.get("status") == "failed" for r in dep.steps or [])


async def _env_of(db: AsyncSession, dep: Deployment) -> Environment:
    env = await db.get(Environment, dep.environment_id) if dep.environment_id is not None else None
    if env is None:
        raise not_found("Environment")
    return env


async def env_retry_refusal(db: AsyncSession, dep: Deployment, user: Any = None) -> str | None:
    """Why a failed environment-level job can't be retried now, or None (phase 3 §9)."""
    from slipway.services import env_jobs

    if dep.status not in (DeploymentStatus.FAILED, DeploymentStatus.CANCELLED):
        return "Only a failed or interrupted deployment can be retried"
    env = await db.get(Environment, dep.environment_id) if dep.environment_id is not None else None
    if env is None or env.is_deleted:
        return "Its environment was deleted"
    refused = await env_jobs.retry_refusal(db, dep)
    if refused:
        return refused
    found = await jobs.job_refusal(db, environment=env, user=user, kind=dep.kind, options=_carried(dep),
                                   retry_of=dep)
    return found.text if found is not None else None


def _carried(dep: Deployment) -> dict[str, Any]:
    """The options a retry of ``dep`` carries (``queue_job`` copies all but ``ENV_ONE_SHOT``)."""
    return {k: v for k, v in (dep.options or {}).items() if k not in jobs.ENV_ONE_SHOT}


def _needs_name(env: Environment | None, dep: Deployment) -> bool:
    """Whether the retry asks the environment's name typed: the kinds that remove things, and an Activate or
    Switch back of a production environment (Decision 39, ``jobs.confirm_refusal``; a chained activate while
    nothing is live asks none)."""
    if dep.kind in CONFIRMED_KINDS:
        return True
    if env is None or dep.kind != DeploymentKind.ACTIVATE:
        return False
    return jobs.confirm_refusal(env, DeploymentKind.ACTIVATE, {**_carried(dep), "confirm": None}) is not None


async def _data_goes(db: AsyncSession, env: Environment, dep: Deployment) -> str | None:
    """Decision 26 on a teardown's retry, as ``environments.delete_problem`` on Delete: the data's only home (a
    managed database, a data VM) that the teardown destroys with no snapshot taken first, or None. An owner that
    never held data (P4 §13, for the environments phases 4 and 5 make) loses nothing."""
    if dep.kind != DeploymentKind.TEARDOWN or (dep.options or {}).get("snapshot_first"):
        return None
    mem = await environments.members(db, env)
    home = environments.data_home(env, mem)
    if home is None and not (dep.options or {}).get("no_snapshot"):
        return None
    made_here = bool(env.production) or environments.is_digitalocean(env) \
        or any(environments.is_vm_host(m.host) for m in mem.values())
    if made_here and await environments.never_held_data(db, env, mem):
        return None
    return home or "its managed database"


async def env_job_actions(db: AsyncSession, dep: Deployment) -> dict[str, Any]:
    """``DeploymentDetail.actions`` of an environment-level job: only Retry (there is no data to roll back).
    A page read: no hypervisor is read (``environments.page_view``); the retry's queue still checks the VM."""
    with environments.page_view():
        reason = await env_retry_refusal(db, dep)
    env = await db.get(Environment, dep.environment_id) if dep.environment_id is not None else None
    opts = dep.options or {}
    # The phrases a production teardown's retry asks again (phase 4 §13), and the VM and data choices it offers.
    phrases: list[str] = []
    if env is not None and env.production and dep.kind == DeploymentKind.TEARDOWN:
        phrases.append("confirm_production")
        if opts.get("no_snapshot"):
            phrases.append("confirm_no_snapshot")
    return {
        "retry": {"available": reason is None, "reason": reason, "needs_confirm": _needs_name(env, dep),
                  "offers_skip_backup": False, "inherits": False,
                  "offers_forget_traffic": _offers_forget_traffic(dep),
                  "offers_forget_vms": dep.kind in FORGET_VMS_KINDS,
                  "needs_phrases": phrases,
                  "permission": data.RETRY_PERMISSION.get(dep.kind, Perm.DEPLOYMENTS_CREATE),
                  "also_needs": list(data.RETRY_EXTRA.get(dep.kind, ()))},
        "rollback": {"available": False, "reason": "Only a failed deploy can be rolled back", "also_undoes": False,
                     "backup_id": None},
        "undo": {"available": False, "backup_id": None, "files": False, "reason": None},
    }


async def _retry_env_job(db: DB, dep: Deployment, ctx: AuthContext, request: Request, body: RetryIn) -> DeploymentOut:
    """Retry an activate, publish, discard, remove_slot or teardown (phase 3 §9): only its kind's permission
    (§4.1), the environment's name typed for the kinds that remove things and for ``forget_traffic``."""
    from slipway.api.v1.instances import need

    kind = dep.kind
    need(ctx, data.RETRY_PERMISSION.get(kind, Perm.DEPLOYMENTS_CREATE), *data.RETRY_EXTRA.get(kind, ()))
    if body.skip_backup or body.take_over_lock:
        raise HTTPException(UNPROCESSABLE, f"A {data.kind_label(kind).lower()} job takes no backup and no lock")
    if body.rebuild_data:
        raise HTTPException(UNPROCESSABLE, "Only a deploy can make a gone database cluster or bucket again")
    if body.forget_traffic and kind != DeploymentKind.TEARDOWN:
        raise HTTPException(UNPROCESSABLE, "Only a teardown can forget its Switchyard hosts and DNS records")
    if body.forget_vms and kind not in FORGET_VMS_KINDS:
        raise HTTPException(UNPROCESSABLE, "Only removing a slot or deleting the environment can forget its VMs")
    if body.drop_data and kind != DeploymentKind.TEARDOWN:
        raise HTTPException(UNPROCESSABLE, "Only deleting the environment can let its data go with it")
    env = await _env_of(db, dep)
    if _needs_name(env, dep) or body.forget_traffic or body.forget_vms:
        if body.confirm != env.name:
            raise HTTPException(UNPROCESSABLE, f"Type the environment's name, {env.name}, exactly to confirm")
    if body.forget_vms:
        need(ctx, Perm.MACHINES_WRITE, Perm.ENVIRONMENTS_DELETE)  # phase 5 §4.1
    if body.drop_data:
        need(ctx, Perm.DATA_RESET, message=f"Deleting {env.name}'s data with it needs the {Perm.DATA_RESET} permission")
    reason = await env_retry_refusal(db, dep, ctx.user)
    if reason:
        raise HTTPException(status.HTTP_409_CONFLICT, reason)
    if not body.drop_data:
        # Decision 26, asked again on every retry (ENV_ONE_SHOT): the data's only home goes without a snapshot.
        home = await _data_goes(db, env, dep)
        if home is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, environments.only_home_text(env, home))
    options: dict[str, Any] = {"forget_traffic": True} if body.forget_traffic else {}
    if kind == DeploymentKind.ACTIVATE and body.confirm is not None:
        options["confirm"] = body.confirm  # a production activate's name (Decision 39), never carried
    # Asked again on every retry (ENV_ONE_SHOT): the production phrases, forget_vms, drop_data (phase 4 §13, P5 §9.9).
    for key in ("confirm_production", "confirm_no_snapshot"):
        if getattr(body, key) is not None:
            options[key] = getattr(body, key)
    for key in ("forget_vms", "drop_data"):
        if getattr(body, key):
            options[key] = True
    try:
        new = await jobs.queue_job(db, environment=env, user=ctx.user, kind=kind, retry_of=dep, options=options)
    except jobs.JobRefused as exc:
        raise HTTPException(exc.status, exc.text) from exc
    label = data.dep_label(dep)
    audit.record(db, "deployment.retry", actor=ctx.user, target=new, request=request,
                 summary=f"Retry {label.lower()} of {env.name} (deployment {dep.id.hex[:8]})",
                 details={"kind": kind, "of": str(dep.id), "environment": env.name,
                          "slot": (dep.options or {}).get("slot"), "forget_traffic": body.forget_traffic,
                          **({"forget_vms": True} if body.forget_vms else {}),
                          **({"drop_data": True} if body.drop_data else {})})
    await db.commit()
    await db.refresh(new)
    deployer.runner.submit(new.id, data.job_keys(new))
    return await deployment_out(db, new)


async def _instance(db: DB, dep: Deployment) -> Instance:
    instance = await db.get(Instance, dep.instance_id)
    if instance is None:
        raise not_found("Instance")
    return instance


@router.post("/{deployment_id}/retry", status_code=202)
async def retry_deployment(
    deployment_id: uuid.UUID, ctx: Auth, request: Request, db: DB, body: RetryIn | None = None
) -> DeploymentOut:
    """Run a failed job again (§8.1). A deploy reuses its release and build when they are still on the host;
    a restore, roll back or reset runs the live release again and needs the typed name.

    An instance job's retry needs deployments:create and its kind's permission; an environment-level job's only
    its kind's (phase 3 §4.1). ``skip_backup`` (only when the backup step failed) and ``take_over_lock`` need
    data:reset and the typed name, and so does a roll back on an environment's shared data (D17).
    """
    from slipway.api.v1.instances import _submit, confirmed, need, queue_deployment  # instances imports schemas

    body = body or RetryIn()
    dep = await db.get(Deployment, deployment_id)
    if dep is None:
        raise not_found("Deployment")
    if dep.instance_id is None:
        return await _retry_env_job(db, dep, ctx, request, body)
    if body.forget_traffic:
        raise HTTPException(UNPROCESSABLE, "Only a teardown can forget its Switchyard hosts and DNS records")
    if body.forget_vms:
        raise HTTPException(UNPROCESSABLE, "Only removing a slot or deleting the environment can forget its VMs")
    if body.drop_data or body.confirm_production or body.confirm_no_snapshot:
        raise HTTPException(UNPROCESSABLE, "Only deleting the environment takes those confirmations")
    kind = dep.kind or DeploymentKind.DEPLOY
    if body.rebuild_data and kind != DeploymentKind.DEPLOY:
        raise HTTPException(UNPROCESSABLE, "Only a deploy can make a gone database cluster or bucket again")
    # The kind's own permission, so a retry never does more than the user could start (§8.1), and what it also
    # needs (``RETRY_EXTRA``, Decision 37: a VM revert data:reset).
    need(ctx, Perm.DEPLOYMENTS_CREATE, data.RETRY_PERMISSION.get(kind, Perm.DEPLOYMENTS_CREATE),
         *data.RETRY_EXTRA.get(kind, ()))
    if (dep.options or {}).get("restore_identity") or body.skip_backup or body.take_over_lock or body.rebuild_data:
        need(ctx, Perm.DATA_RESET)
    if (dep.options or {}).get("stop_app"):
        need(ctx, Perm.INSTANCES_OPERATE)  # stopping the app for a snapshot needs it, as when first taken (§10.4)
    instance = await _instance(db, dep)
    if kind == DeploymentKind.ROLLBACK and instance.environment_id is not None:
        env = await environments.environment_of(db, instance)
        if env is not None and env.data_mode != DataMode.SLOT:
            # On shared data a roll back loses what the active slot wrote since the backup (D17, §4.1).
            need(ctx, Perm.DATA_RESET)
    if kind in data.RESTORE_KINDS or kind in CONFIRMED_MEMBER_KINDS or body.skip_backup or body.take_over_lock \
            or body.rebuild_data:
        confirmed(instance, body.confirm)
    if dep.status not in (DeploymentStatus.FAILED, DeploymentStatus.CANCELLED):
        raise HTTPException(status.HTTP_409_CONFLICT, "Only a failed or interrupted deployment can be retried")
    if kind == DeploymentKind.DEPLOY:
        if not dep.commit_sha:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                "This deployment failed before it resolved a commit: deploy again instead")
        if dep.branch != instance.branch:
            # Changing what an instance deploys takes instances:write; a retry must not get around that.
            raise HTTPException(status.HTTP_409_CONFLICT,
                                f"This deployment was of branch {dep.branch}, and the instance now deploys {instance.branch}: "
                                "deploy the instance instead")
    state = await data.retry_state(db, dep)
    if not state["available"]:
        raise HTTPException(status.HTTP_409_CONFLICT, state["reason"] or "This job can't be retried")
    if body.skip_backup and not state["offers_skip_backup"]:
        raise HTTPException(status.HTTP_409_CONFLICT, "Retry without the backup is only for a job whose backup failed")
    if kind != DeploymentKind.DEPLOY and kind not in VM_KINDS:
        # The checks the job had when it was first started, against today's live release (no dump or restore
        # command any more, data elsewhere, the hold for snapshot, admin and content...). retry_state has
        # already refused what the endpoint that started it refuses (the hold for deploy, the manual cap,
        # nothing pending, another seed).
        await data.require_data_job(db, instance, kind, start_over=bool((dep.options or {}).get("start_over")))
    if kind == DeploymentKind.SNAPSHOT:
        from slipway.services import snapshots

        try:
            snapshots.require_storage()
        except snapshots.SnapshotsError as exc:
            raise HTTPException(exc.status, exc.message) from exc
    extra = {k: True for k in ("skip_backup", "take_over_lock", "rebuild_data") if getattr(body, k)}
    new = await queue_deployment(db, instance, ctx.user, kind=kind, retry_of=dep, options=extra)
    sha = f"@{dep.commit_sha[:7]}" if dep.commit_sha else ""
    details: dict[str, Any] = {"kind": kind, "of": str(dep.id), "skip_backup": body.skip_backup,
                               "take_over_lock": body.take_over_lock,
                               **({"rebuild_data": True} if body.rebuild_data else {}),
                               "inherits": bool((new.options or {}).get("inherit"))}
    if instance.environment_id is not None:
        details.update(environment=data.confirm_name(instance), slot=instance.slot,
                       go_live=bool((new.options or {}).get("go_live")))
    audit.record(db, "deployment.retry", actor=ctx.user, target=new, request=request,
                 summary=f"Retry {data.kind_label(kind).lower()} of {instance.name}{sha} (deployment {dep.id.hex[:8]})",
                 details=details)
    return await _submit(db, new, instance)


@router.post("/{deployment_id}/rollback", status_code=202)
async def rollback_deployment(
    deployment_id: uuid.UUID, body: ConfirmIn, ctx: RollBacker, request: Request, db: DB
) -> DeploymentOut:
    """Roll back a failed deploy (§8.2, kind ``rollback``): put the database back as it was before the first
    failed deploy since the instance was last clean, and start the live release again."""
    from slipway.api.v1.instances import _submit, confirmed, need, queue_deployment

    dep = await db.get(Deployment, deployment_id)
    if dep is None:
        raise not_found("Deployment")
    if dep.instance_id is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Roll back isn't available: only a failed deploy can be rolled back")
    instance = await _instance(db, dep)
    confirmed(instance, body.confirm)
    state = await data.rollback_state(db, dep)
    if state.needs_reset:
        # On shared data a roll back loses what the active slot wrote since the backup (D17, §4.1).
        need(ctx, Perm.DATA_RESET)
    if not state.available or state.backup is None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Roll back isn't available: {state.reason}")
    # The backup and the dirty state are the data owner's, so the roll back runs there (phase 3 D3).
    owner = await environments.owner_of(db, instance) or instance
    await data.require_data_job(db, owner, DeploymentKind.ROLLBACK)
    backup = state.backup
    new = await queue_deployment(db, owner, ctx.user, kind=DeploymentKind.ROLLBACK, restore_backup_id=backup.id,
                                 options={"rollback_of": dep.id.hex})
    name = data.confirm_name(owner)
    details: dict[str, Any] = {"deployment": str(dep.id), "backup": backup.name, "job": str(new.id),
                               "also_undoes": state.first_deployment_id if state.also_undoes else None}
    if owner.environment_id is not None:
        details.update(environment=name, slot=instance.slot)
    audit.record(db, "instance.rollback", actor=ctx.user, target=owner, request=request,
                 summary=f"Roll back {name} to backup {backup.name} (failed deployment {dep.id.hex[:8]})",
                 details=details)
    return await _submit(db, new, owner)
