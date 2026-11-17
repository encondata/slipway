"""Ops analytics: deploy outcomes and host resource trends."""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query

from slipway.api.deps import DB, require
from slipway.core.permissions import Perm
from slipway.services import analytics, host_metrics
from slipway.services.auth import AuthContext

router = APIRouter(prefix="/analytics", tags=["analytics"])

DeployReader = Annotated[AuthContext, require(Perm.DEPLOYMENTS_READ, Perm.ANALYTICS_READ)]
HostReader = Annotated[AuthContext, require(Perm.HOSTS_READ, Perm.ANALYTICS_READ)]


def _days(days: int) -> int:
    if days not in analytics.ALLOWED_DAYS:
        allowed = ", ".join(str(d) for d in analytics.ALLOWED_DAYS)
        raise HTTPException(422, f"days must be one of {allowed}")
    return days


def jsonable(value: Any) -> Any:
    """Datetimes as ISO 8601 UTC with a Z, dates as YYYY-MM-DD, UUIDs as strings."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    return value


@router.get("/deploys")
async def deploys(ctx: DeployReader, db: DB, days: Annotated[int, Query()] = 30) -> dict[str, Any]:
    """Deploy analytics. ``repository`` and ``host`` of each instance are null without repos:read and
    hosts:read."""
    return jsonable(analytics.hide_names(
        await analytics.deploy_stats(db, days=_days(days)),
        repositories=ctx.can(Perm.REPOS_READ), hosts=ctx.can(Perm.HOSTS_READ),
    ))


@router.get("/hosts")
async def hosts(ctx: HostReader, db: DB, days: Annotated[int, Query()] = 7) -> list[dict[str, Any]]:
    return jsonable(await host_metrics.host_trends(db, days=_days(days)))
