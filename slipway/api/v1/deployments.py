"""Deployment history and build output, and what a finished job offers next: retry and roll back."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import defer

from slipway.api.deps import DB, not_found, require
from slipway.core.permissions import Perm
from slipway.models import Deployment, DeploymentKind, DeploymentStatus, Instance
from slipway.schemas import ConfirmIn, DeploymentDetail, DeploymentOut, RetryIn, deployment_out, deployment_outs
from slipway.services import audit, data
from slipway.services.auth import AuthContext

router = APIRouter(prefix="/deployments", tags=["deployments"])

Reader = Annotated[AuthContext, require(Perm.DEPLOYMENTS_READ)]
Deployer = Annotated[AuthContext, require(Perm.DEPLOYMENTS_CREATE)]
RollBacker = Annotated[AuthContext, require(Perm.DEPLOYMENTS_CREATE, Perm.DATA_RESTORE)]


@router.get("")
async def list_deployments(
    ctx: Reader,
    db: DB,
    instance_id: uuid.UUID | None = None,
    status: Annotated[str | None, Query(max_length=16)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[DeploymentOut]:
    stmt = select(Deployment).options(defer(Deployment.log, raiseload=True)).order_by(Deployment.created_at.desc()).limit(limit)
    if instance_id:
        stmt = stmt.where(Deployment.instance_id == instance_id)
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
    actions = await data.job_actions(db, dep)
    return DeploymentDetail(**out.model_dump(), log=log[offset:], log_offset=len(log), actions=actions)


async def _instance(db: DB, dep: Deployment) -> Instance:
    instance = await db.get(Instance, dep.instance_id)
    if instance is None:
        raise not_found("Instance")
    return instance


@router.post("/{deployment_id}/retry", status_code=202)
async def retry_deployment(
    deployment_id: uuid.UUID, ctx: Deployer, request: Request, db: DB, body: RetryIn | None = None
) -> DeploymentOut:
    """Run a failed job again (§8.1). A deploy reuses its release and build when they are still on the host;
    a restore, roll back or reset runs the live release again and needs the typed name.

    ``skip_backup`` (only when the backup step failed) and ``take_over_lock`` need data:reset and the typed name.
    """
    from slipway.api.v1.instances import _submit, confirmed, need, queue_deployment  # instances imports schemas

    body = body or RetryIn()
    dep = await db.get(Deployment, deployment_id)
    if dep is None:
        raise not_found("Deployment")
    kind = dep.kind or DeploymentKind.DEPLOY
    # The kind's own permission, so a retry never does more than the user could start (§8.1).
    need(ctx, data.RETRY_PERMISSION.get(kind, Perm.DEPLOYMENTS_CREATE))
    if (dep.options or {}).get("restore_identity") or body.skip_backup or body.take_over_lock:
        need(ctx, Perm.DATA_RESET)
    if (dep.options or {}).get("stop_app"):
        need(ctx, Perm.INSTANCES_OPERATE)  # stopping the app for a snapshot needs it, as when first taken (§10.4)
    instance = await _instance(db, dep)
    if kind in data.RESTORE_KINDS or body.skip_backup or body.take_over_lock:
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
    if kind != DeploymentKind.DEPLOY:
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
    extra = {k: True for k in ("skip_backup", "take_over_lock") if getattr(body, k)}
    new = await queue_deployment(db, instance, ctx.user, retry_of=dep, options=extra)
    sha = f"@{dep.commit_sha[:7]}" if dep.commit_sha else ""
    audit.record(db, "deployment.retry", actor=ctx.user, target=new, request=request,
                 summary=f"Retry {data.kind_label(kind).lower()} of {instance.name}{sha} (deployment {dep.id.hex[:8]})",
                 details={"kind": kind, "of": str(dep.id), "skip_backup": body.skip_backup,
                          "take_over_lock": body.take_over_lock, "inherits": bool((new.options or {}).get("inherit"))})
    return await _submit(db, new, instance)


@router.post("/{deployment_id}/rollback", status_code=202)
async def rollback_deployment(
    deployment_id: uuid.UUID, body: ConfirmIn, ctx: RollBacker, request: Request, db: DB
) -> DeploymentOut:
    """Roll back a failed deploy (§8.2, kind ``rollback``): put the database back as it was before the first
    failed deploy since the instance was last clean, and start the live release again."""
    from slipway.api.v1.instances import _submit, confirmed, queue_deployment

    dep = await db.get(Deployment, deployment_id)
    if dep is None:
        raise not_found("Deployment")
    instance = await _instance(db, dep)
    confirmed(instance, body.confirm)
    state = await data.rollback_state(db, dep)
    if not state.available or state.backup is None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Roll back isn't available: {state.reason}")
    await data.require_data_job(db, instance, DeploymentKind.ROLLBACK)
    backup = state.backup
    new = await queue_deployment(db, instance, ctx.user, kind=DeploymentKind.ROLLBACK, restore_backup_id=backup.id,
                                 options={"rollback_of": dep.id.hex})
    audit.record(db, "instance.rollback", actor=ctx.user, target=instance, request=request,
                 summary=f"Roll back {instance.name} to backup {backup.name} (failed deployment {dep.id.hex[:8]})",
                 details={"deployment": str(dep.id), "backup": backup.name, "also_undoes": state.first_deployment_id
                          if state.also_undoes else None, "job": str(new.id)})
    return await _submit(db, new, instance)
