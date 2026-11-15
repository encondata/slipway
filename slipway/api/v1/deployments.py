"""Deployment history and build output."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import defer

from slipway.api.deps import DB, not_found, require
from slipway.core.permissions import Perm
from slipway.models import Deployment, DeploymentStatus
from slipway.schemas import DeploymentDetail, DeploymentOut
from slipway.services import audit, deployer
from slipway.services.auth import AuthContext

router = APIRouter(prefix="/deployments", tags=["deployments"])

Reader = Annotated[AuthContext, require(Perm.DEPLOYMENTS_READ)]
Deployer = Annotated[AuthContext, require(Perm.DEPLOYMENTS_CREATE)]


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
    return [DeploymentOut.of(d) for d in (await db.scalars(stmt)).all()]


@router.get("/{deployment_id}")
async def get_deployment(
    deployment_id: uuid.UUID, ctx: Reader, db: DB, log_offset: Annotated[int, Query(ge=0)] = 0
) -> DeploymentDetail:
    """``log_offset`` lets the UI poll for only the new part of the build log."""
    dep = await db.get(Deployment, deployment_id, populate_existing=True)
    if dep is None:
        raise not_found("Deployment")
    log = dep.log or ""
    offset = max(0, min(log_offset, len(log)))
    return DeploymentDetail(**DeploymentOut.of(dep).model_dump(), log=log[offset:], log_offset=len(log))


@router.post("/{deployment_id}/retry", status_code=202)
async def retry_deployment(deployment_id: uuid.UUID, ctx: Deployer, request: Request, db: DB) -> DeploymentOut:
    """Run a failed deployment's commit again, reusing its release and build when they are still on the host."""
    from slipway.api.v1.instances import queue_deployment  # instances imports this module's schemas

    dep = await db.get(Deployment, deployment_id)
    if dep is None:
        raise not_found("Deployment")
    if dep.status not in (DeploymentStatus.FAILED, DeploymentStatus.CANCELLED):
        raise HTTPException(status.HTTP_409_CONFLICT, "Only a failed or interrupted deployment can be retried")
    if not dep.commit_sha:
        raise HTTPException(status.HTTP_409_CONFLICT, "This deployment failed before it resolved a commit: deploy again instead")
    instance = dep.instance
    if dep.branch != instance.branch:
        # Changing what an instance deploys takes instances:write; a retry must not get around that.
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"This deployment was of branch {dep.branch}, and the instance now deploys {instance.branch}: "
                            "deploy the instance instead")
    new = await queue_deployment(db, instance, ctx.user, retry_of=dep)
    audit.record(db, "deployment.retry", actor=ctx.user, target=new,
                 summary=f"Retry {instance.name}@{dep.commit_sha[:7]} (deployment {dep.id.hex[:8]})", request=request)
    await db.commit()
    await db.refresh(new)
    deployer.runner.submit(new.id, instance.id)
    return DeploymentOut.of(new)
