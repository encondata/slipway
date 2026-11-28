"""Deploy analytics, built from the deployments Slipway already records.

Counts by status, instance and person are computed in SQL. Day buckets, durations, percentiles and recovery
times are computed in Python, so they behave the same on SQLite and PostgreSQL.

The window is whole UTC days: with ``days=30`` it starts at midnight UTC 29 days before ``now`` and ends at
``now``, so ``by_day`` has exactly ``days`` entries. The previous window is just as long and ends where this
one starts, so a steady rate of deploys gives no change between them.

Every count is of finished deploys (succeeded, failed, cancelled), the same ones ``by_day`` draws, so its
counts add up to ``totals.deploys``. Deploys still queued or running are in ``totals.queued`` and
``totals.running``.
"""

from __future__ import annotations

import math
import statistics
import uuid
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.models import Deployment, DeploymentKind, DeploymentStatus, Host, Instance, Repository, User

ALLOWED_DAYS = (7, 30, 90)
# A deployment with no trigger: every deploy is started by a person today, so the person was deleted since.
DELETED_USER = "Deleted user"
# recover_interrupted's error for deploys a restart cut off: their finish time is when Slipway came back,
# not when the deploy stopped, so their durations say nothing.
RESTART_ERROR = "Interrupted by a Slipway restart"
RECENT_FAILURES = 10
ERROR_CLIP = 200

_FINISHED = (DeploymentStatus.SUCCEEDED, DeploymentStatus.FAILED, DeploymentStatus.CANCELLED)
# Outcomes that say whether an instance works. A cancelled deploy says neither.
_OUTCOMES = (DeploymentStatus.SUCCEEDED, DeploymentStatus.FAILED)


def window(days: int, now: datetime) -> tuple[datetime, datetime, datetime]:
    """(previous start, start, end) of the window ending at ``now``. The previous window is as long as this
    one (``days - 1`` days plus the part of today that has passed) and ends where it starts."""
    end = now.astimezone(UTC)
    start = datetime.combine(end.date() - timedelta(days=days - 1), datetime.min.time(), tzinfo=UTC)
    return start - (end - start), start, end


def percentile(values: list[float], q: float) -> float | None:
    """The ``q`` quantile (0..1) with linear interpolation between closest ranks; None for no values."""
    if not values:
        return None
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    low, high = math.floor(pos), math.ceil(pos)
    return ordered[low] + (ordered[high] - ordered[low]) * (pos - low)


def _rate(succeeded: int, failed: int) -> float | None:
    return succeeded / (succeeded + failed) if succeeded + failed else None


def _first_line(text: str | None, limit: int = ERROR_CLIP) -> str:
    line = next((ln.strip() for ln in (text or "").splitlines() if ln.strip()), "")
    return line if len(line) <= limit else line[: limit - 1] + "…"


def _aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value


def _count_where(condition):
    return func.count(case((condition, 1)))


# Only deploys count: the deployments table also holds data jobs (backup, restore...) and environment jobs.
_DEPLOYS = Deployment.kind == DeploymentKind.DEPLOY


def _in(start: datetime, end: datetime):
    return and_(_DEPLOYS, Deployment.created_at >= start, Deployment.created_at <= end)


async def _status_counts(db: AsyncSession, start: datetime, end: datetime) -> dict[str, int]:
    rows = await db.execute(
        select(Deployment.status, func.count())
        .where(_in(start, end), Deployment.status.in_(_FINISHED))
        .group_by(Deployment.status)
    )
    return {status: count for status, count in rows.all()}


async def _durations(db: AsyncSession, start: datetime, end: datetime) -> list[tuple[uuid.UUID, float]]:
    rows = await db.execute(
        select(Deployment.instance_id, Deployment.started_at, Deployment.finished_at).where(
            _in(start, end),
            Deployment.status.in_(_FINISHED),
            Deployment.started_at.is_not(None),
            Deployment.finished_at.is_not(None),
            or_(Deployment.error.is_(None), Deployment.error != RESTART_ERROR),
        )
    )
    return [(iid, max(0.0, (fin - sta).total_seconds())) for iid, sta, fin in rows.all()]


async def _recovery_rows(db: AsyncSession, prev_start: datetime, end: datetime) -> list[tuple]:
    """(instance id, status, created_at, finished_at) of the outcomes a recovery in [prev_start, end] can use.

    Only instances with a success created in the windows, and for each only its rows from its last success
    created before ``prev_start`` on (all of them when there is none): that keeps the run of failures still
    open at ``prev_start`` and leaves the older history out.
    """
    recovered = (
        select(Deployment.instance_id)
        .where(Deployment.status == DeploymentStatus.SUCCEEDED, _in(prev_start, end))
        .distinct()
    )
    anchor = (
        select(Deployment.instance_id, func.max(Deployment.created_at).label("at"))
        .where(_DEPLOYS, Deployment.status == DeploymentStatus.SUCCEEDED, Deployment.created_at < prev_start)
        .group_by(Deployment.instance_id)
        .subquery()
    )
    rows = await db.execute(
        select(Deployment.instance_id, Deployment.status, Deployment.created_at, Deployment.finished_at)
        .outerjoin(anchor, anchor.c.instance_id == Deployment.instance_id)
        .where(
            _DEPLOYS,
            Deployment.instance_id.in_(recovered),
            Deployment.status.in_(_OUTCOMES),
            Deployment.created_at <= end,
            or_(anchor.c.at.is_(None), Deployment.created_at >= anchor.c.at),
        )
        .order_by(Deployment.instance_id, Deployment.created_at)
    )
    return [tuple(row) for row in rows.all()]


async def _recoveries(db: AsyncSession, prev_start: datetime, end: datetime) -> list[tuple[datetime, float]]:
    """(success created_at, seconds to recover) for every recovery whose success was created in
    [prev_start, end], the same key every other number of the window uses.

    A recovery runs from the first failure of a run of failures to the success that ends it.
    """
    out: list[tuple[datetime, float]] = []
    run_start: dict[uuid.UUID, datetime] = {}
    for iid, status, created, finished in await _recovery_rows(db, prev_start, end):
        created = _aware(created)
        finished = _aware(finished) or created
        if status == DeploymentStatus.FAILED:
            run_start.setdefault(iid, finished)
        elif iid in run_start:
            began = run_start.pop(iid)
            if prev_start <= created <= end:
                out.append((created, max(0.0, (finished - began).total_seconds())))
    return out


def _mttr(recoveries: list[tuple[datetime, float]], start: datetime, end: datetime) -> float | None:
    times = [secs for at, secs in recoveries if start <= at <= end]
    return statistics.fmean(times) if times else None


def _totals(counts: dict[str, int], durations: list[float], mttr: float | None) -> dict[str, Any]:
    succeeded = counts.get(DeploymentStatus.SUCCEEDED, 0)
    failed = counts.get(DeploymentStatus.FAILED, 0)
    return {
        "deploys": sum(counts.values()),
        "succeeded": succeeded,
        "failed": failed,
        "cancelled": counts.get(DeploymentStatus.CANCELLED, 0),
        "success_rate": _rate(succeeded, failed),
        "median_seconds": statistics.median(durations) if durations else None,
        "p90_seconds": percentile(durations, 0.9),
        "mttr_seconds": mttr,
    }


async def _by_day(db: AsyncSession, days: int, start: datetime, end: datetime) -> list[dict[str, Any]]:
    buckets: dict[date, dict[str, Any]] = {}
    for i in range(days):
        day = start.date() + timedelta(days=i)
        buckets[day] = {"date": day, "succeeded": 0, "failed": 0, "cancelled": 0}
    rows = await db.execute(
        select(Deployment.created_at, Deployment.status).where(_in(start, end), Deployment.status.in_(_FINISHED))
    )
    for created, status in rows.all():
        bucket = buckets.get(_aware(created).astimezone(UTC).date())
        if bucket is not None:
            bucket[status] += 1
    return list(buckets.values())


async def _latest(db: AsyncSession, ids: list[uuid.UUID], statuses=None) -> dict[uuid.UUID, tuple]:
    """(id, status, created_at, finished_at) of each instance's latest deployment, optionally among ``statuses``."""
    if not ids:
        return {}
    conditions = [_DEPLOYS, Deployment.instance_id.in_(ids)]
    if statuses:
        conditions.append(Deployment.status.in_(statuses))
    newest = (
        select(Deployment.instance_id, func.max(Deployment.created_at).label("at"))
        .where(*conditions)
        .group_by(Deployment.instance_id)
        .subquery()
    )
    rows = await db.execute(
        select(Deployment.instance_id, Deployment.id, Deployment.status, Deployment.created_at, Deployment.finished_at)
        .join(newest, and_(Deployment.instance_id == newest.c.instance_id, Deployment.created_at == newest.c.at))
        .where(*conditions)
    )
    return {iid: (dep_id, status, created, finished) for iid, dep_id, status, created, finished in rows.all()}


async def _by_instance(
    db: AsyncSession, start: datetime, end: datetime, durations: list[tuple[uuid.UUID, float]]
) -> list[dict[str, Any]]:
    failed_count = _count_where(Deployment.status == DeploymentStatus.FAILED)
    succeeded_count = _count_where(Deployment.status == DeploymentStatus.SUCCEEDED)
    # Finished deploys only, like the totals; an instance whose only deploy is still running is listed with 0.
    finished_count = _count_where(Deployment.status.in_(_FINISHED))
    source = func.coalesce(Repository.full_name, Instance.image)
    rows = (
        await db.execute(
            select(
                Instance.id, Instance.name, Instance.slug, source, Host.name,
                finished_count, succeeded_count, failed_count,
            )
            .join(Deployment, Deployment.instance_id == Instance.id)
            # An instance of a container image has no repository: its image stands in for the name.
            .outerjoin(Repository, Repository.id == Instance.repository_id)
            .join(Host, Host.id == Instance.host_id)
            .where(_in(start, end))
            .group_by(Instance.id, Instance.name, Instance.slug, Repository.full_name, Instance.image, Host.name)
        )
    ).all()
    ids = [row[0] for row in rows]
    latest = await _latest(db, ids)
    latest_outcome = await _latest(db, ids, _OUTCOMES)
    per_instance: dict[uuid.UUID, list[float]] = defaultdict(list)
    for iid, secs in durations:
        per_instance[iid].append(secs)

    out = []
    for iid, name, slug, repo, host, deploys, succeeded, failed in rows:
        last = latest.get(iid)
        outcome = latest_outcome.get(iid)
        secs = per_instance.get(iid)
        out.append({
            "id": iid,
            "name": name,
            "slug": slug,
            "repository": repo,
            "host": host,
            "deploys": deploys,
            "failed": failed,
            "success_rate": _rate(succeeded, failed),
            "median_seconds": statistics.median(secs) if secs else None,
            "last_deploy": (
                {"id": last[0], "status": last[1], "at": _aware(last[3]) or _aware(last[2])} if last else None
            ),
            "recovering": bool(outcome and outcome[1] == DeploymentStatus.FAILED),
        })
    out.sort(key=lambda r: (-r["deploys"], r["name"].lower(), r["slug"]))
    return out


async def _by_person(db: AsyncSession, start: datetime, end: datetime) -> list[dict[str, Any]]:
    failed_count = _count_where(Deployment.status == DeploymentStatus.FAILED)
    rows = await db.execute(
        select(Deployment.triggered_by_id, User.full_name, User.email, func.count(), failed_count)
        .outerjoin(User, User.id == Deployment.triggered_by_id)
        .where(_in(start, end), Deployment.status.in_(_FINISHED))
        .group_by(Deployment.triggered_by_id, User.full_name, User.email)
    )
    out = []
    for uid, full_name, email, deploys, failed in rows.all():
        if uid is None:
            name = DELETED_USER
        else:
            name = full_name or (email or "").split("@", 1)[0]
        out.append({"id": uid, "name": name, "deploys": deploys, "failed": failed})
    out.sort(key=lambda r: (-r["deploys"], r["id"] is None, r["name"].lower()))
    return out


async def _recent_failures(db: AsyncSession, start: datetime, end: datetime) -> list[dict[str, Any]]:
    rows = await db.execute(
        select(
            Deployment.id, Deployment.created_at, Deployment.finished_at, Deployment.error,
            Deployment.commit_sha, Deployment.commit_message, Instance.id, Instance.name, Instance.slug,
        )
        .join(Instance, Instance.id == Deployment.instance_id)
        .where(_in(start, end), Deployment.status == DeploymentStatus.FAILED)
        .order_by(Deployment.created_at.desc())
        .limit(RECENT_FAILURES)
    )
    return [
        {
            "id": dep_id,
            "instance": {"id": iid, "name": name, "slug": slug},
            "at": _aware(finished) or _aware(created),
            "error": _first_line(error),
            "commit_sha": (sha or "")[:7] or None,
            "commit_message": _first_line(message) or None,
        }
        for dep_id, created, finished, error, sha, message, iid, name, slug in rows.all()
    ]


def hide_names(stats: dict[str, Any], *, repositories: bool, hosts: bool) -> dict[str, Any]:
    """Blank (None) each instance's repository name unless ``repositories``, and its host name unless
    ``hosts``: the rest of the app shows them only with repos:read and hosts:read."""
    for row in stats["by_instance"]:
        if not repositories:
            row["repository"] = None
        if not hosts:
            row["host"] = None
    return stats


async def deploy_stats(db: AsyncSession, *, days: int, now: datetime | None = None) -> dict[str, Any]:
    """Deploy analytics for the last ``days`` whole UTC days (7, 30 or 90) ending at ``now``.

    Datetimes in the result are timezone-aware UTC, days are ``date`` objects and ids are UUIDs.
    ``success_rate`` is a fraction between 0 and 1 (None when nothing succeeded or failed).
    """
    if days not in ALLOWED_DAYS:
        raise ValueError(f"days must be one of {ALLOWED_DAYS}")
    now = _aware(now) or datetime.now(UTC)
    prev_start, start, end = window(days, now)
    # The previous window ends just before this one starts.
    prev_end = start - timedelta(microseconds=1)

    durations = await _durations(db, start, end)
    prev_durations = await _durations(db, prev_start, prev_end)
    recoveries = await _recoveries(db, prev_start, end)

    totals = _totals(await _status_counts(db, start, end), [s for _, s in durations], _mttr(recoveries, start, end))
    active = dict(
        (
            await db.execute(
                select(Deployment.status, func.count())
                .where(_DEPLOYS, Deployment.status.in_((DeploymentStatus.QUEUED, DeploymentStatus.RUNNING)))
                .group_by(Deployment.status)
            )
        ).all()
    )
    totals["running"] = active.get(DeploymentStatus.RUNNING, 0)
    totals["queued"] = active.get(DeploymentStatus.QUEUED, 0)
    totals["previous"] = _totals(
        await _status_counts(db, prev_start, prev_end),
        [s for _, s in prev_durations],
        _mttr(recoveries, prev_start, prev_end),
    )

    return {
        "days": days,
        "start": start,
        "end": end,
        "previous_start": prev_start,
        "totals": totals,
        "by_day": await _by_day(db, days, start, end),
        "by_instance": await _by_instance(db, start, end, durations),
        "by_person": await _by_person(db, start, end),
        "recent_failures": await _recent_failures(db, start, end),
    }
