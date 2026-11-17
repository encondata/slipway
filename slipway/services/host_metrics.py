"""Host history: a sample per successful health check, hourly rollups, retention and trends.

Raw samples are kept for ``RAW_RETENTION`` (8 days) and back the 7 day view. Every complete hour is
rolled up into ``host_samples_hourly`` (average and maximum), kept for ``HOURLY_RETENTION`` (400 days),
which backs the longer views.
"""

from __future__ import annotations

import asyncio
import logging
import math
import uuid
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.core.config import get_settings
from slipway.db.base import utcnow
from slipway.db.session import session_scope
from slipway.models import Host, HostSample, HostSampleHourly

log = logging.getLogger(__name__)

RAW_RETENTION = timedelta(days=8)
HOURLY_RETENTION = timedelta(days=400)
# An hour is rolled up once it ended at least this long ago, so late writes still land in it.
ROLLUP_DELAY = timedelta(hours=1)
# Up to this many days the trends use raw samples; beyond, hourly rows.
RAW_MAX_DAYS = 7
HOUR = timedelta(hours=1)
# The retention loop's first run comes this soon after start (or after the interval, if shorter), so a
# process that never lives a whole interval still rolls up and prunes.
FIRST_RUN_DELAY = 300


def floor_hour(at: datetime) -> datetime:
    return at.replace(minute=0, second=0, microsecond=0)


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def record_sample(
    db: AsyncSession, host_id: uuid.UUID, metrics: Mapping[str, Any], *, at: datetime | None = None
) -> HostSample:
    """Add one sample from a probe's metrics to the session (the caller commits)."""
    containers = metrics.get("containers_running")
    sample = HostSample(
        host_id=host_id,
        at=at or utcnow(),
        cpu_percent=_number(metrics.get("cpu_percent")) or 0.0,
        mem_percent=_number(metrics.get("mem_percent")) or 0.0,
        disk_percent=_number(metrics.get("disk_percent")),
        containers_running=containers if isinstance(containers, int) and not isinstance(containers, bool) else None,
    )
    db.add(sample)
    return sample


# ------------------------------------------------------------------ rollup


@dataclass
class _Bucket:
    cpu: list[float] = field(default_factory=list)
    mem: list[float] = field(default_factory=list)
    disk: list[float] = field(default_factory=list)

    def add(self, cpu: float, mem: float, disk: float | None) -> None:
        self.cpu.append(cpu)
        self.mem.append(mem)
        if disk is not None:
            self.disk.append(disk)


def _bucket(rows: Iterable[tuple[uuid.UUID, datetime, float, float, float | None]]) -> dict[tuple[uuid.UUID, datetime], _Bucket]:
    buckets: dict[tuple[uuid.UUID, datetime], _Bucket] = defaultdict(_Bucket)
    for host_id, at, cpu, mem, disk in rows:
        buckets[host_id, floor_hour(at)].add(cpu, mem, disk)
    return buckets


def _hourly_row(host_id: uuid.UUID, hour: datetime, bucket: _Bucket) -> HostSampleHourly:
    return HostSampleHourly(
        host_id=host_id,
        hour=hour,
        cpu_avg=sum(bucket.cpu) / len(bucket.cpu),
        cpu_max=max(bucket.cpu),
        mem_avg=sum(bucket.mem) / len(bucket.mem),
        mem_max=max(bucket.mem),
        disk_max=max(bucket.disk) if bucket.disk else None,
        samples=len(bucket.cpu),
    )


_RAW_COLUMNS = (HostSample.host_id, HostSample.at, HostSample.cpu_percent, HostSample.mem_percent, HostSample.disk_percent)


async def rollup(db: AsyncSession, *, now: datetime | None = None) -> int:
    """Roll up every complete hour that ended over an hour ago and has no hourly row yet. Returns rows added.

    Every raw sample is read, however old: prune deletes raw samples over 8 days old right after, so an hour
    left out here (retention was off, or never ran for over 8 days) would be lost for good. Raw samples are
    only about 8 days in normal running, so the read stays small. The new rows are flushed here, for hosts
    that still exist, so a host deleted meanwhile is skipped instead of failing the whole run.
    """
    now = now or utcnow()
    cutoff = floor_hour(now - ROLLUP_DELAY)  # hours ending at or before this are complete and settled
    rows = [tuple(row) for row in await db.execute(select(*_RAW_COLUMNS).where(HostSample.at < cutoff))]
    if not rows:
        return 0
    since = floor_hour(min(row[1] for row in rows))
    done = {
        (host_id, hour)
        for host_id, hour in await db.execute(
            select(HostSampleHourly.host_id, HostSampleHourly.hour).where(
                HostSampleHourly.hour >= since, HostSampleHourly.hour < cutoff
            )
        )
    }
    pending = [
        (host_id, hour, bucket)
        for (host_id, hour), bucket in sorted(_bucket(rows).items(), key=lambda item: item[0][1])
        if (host_id, hour) not in done
    ]
    if not pending:
        return 0
    hosts = set(await db.scalars(select(Host.id).where(Host.id.in_({host_id for host_id, _, _ in pending}))))
    added = 0
    for host_id, hour, bucket in pending:
        if host_id in hosts:  # deleted since the read: its samples go with it
            db.add(_hourly_row(host_id, hour, bucket))
            added += 1
    await db.flush()
    return added


async def prune(db: AsyncSession, *, now: datetime | None = None) -> None:
    """Delete raw samples older than 8 days and hourly rows older than 400 days."""
    now = now or utcnow()
    await db.execute(delete(HostSample).where(HostSample.at < now - RAW_RETENTION))
    await db.execute(delete(HostSampleHourly).where(HostSampleHourly.hour < now - HOURLY_RETENTION))


async def retention_once(db: AsyncSession, *, now: datetime | None = None) -> int:
    """Roll up, then prune, in one transaction. Safe to run any number of times."""
    now = now or utcnow()
    added = await rollup(db, now=now)
    await prune(db, now=now)
    await db.commit()
    return added


async def retention_forever() -> None:
    interval = get_settings().metrics_retention_interval
    if interval <= 0:
        return
    await asyncio.sleep(min(FIRST_RUN_DELAY, interval))
    while True:
        try:
            async with session_scope() as db:
                await retention_once(db)
        except asyncio.CancelledError:
            raise
        except Exception:  # keep going whatever happens
            log.exception("Host history rollup failed")
        await asyncio.sleep(interval)


# ------------------------------------------------------------------ trends


def _stats(values: list[float], *, peaks: list[float] | None = None, weights: list[int] | None = None,
           latest: float | None = None) -> dict[str, float] | None:
    if not values:
        return None
    weights = weights or [1] * len(values)
    avg = sum(v * w for v, w in zip(values, weights, strict=True)) / sum(weights)
    return {
        "min": round(min(values), 1),
        "avg": round(avg, 1),
        "max": round(max(peaks or values), 1),
        "latest": round(values[-1] if latest is None else latest, 1),
    }


def _raw_series(samples: list[tuple[datetime, float, float, float | None]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    series = [
        {"at": at, "cpu": round(cpu, 1), "mem": round(mem, 1), "disk": None if disk is None else round(disk, 1)}
        for at, cpu, mem, disk in samples
    ]
    disks = [disk for _, _, _, disk in samples if disk is not None]
    return series, {
        "cpu": _stats([cpu for _, cpu, _, _ in samples]),
        "mem": _stats([mem for _, _, mem, _ in samples]),
        "disk": _stats(disks),
    }


def _hourly_series(rows: list[HostSampleHourly], latest: tuple[float, float, float | None] | None
                   ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    series = [
        {
            "at": row.hour, "cpu": round(row.cpu_avg, 1), "mem": round(row.mem_avg, 1),
            "disk": None if row.disk_max is None else round(row.disk_max, 1),
            "cpu_max": round(row.cpu_max, 1), "mem_max": round(row.mem_max, 1), "samples": row.samples,
        }
        for row in rows
    ]
    weights = [row.samples for row in rows]
    disk_rows = [row for row in rows if row.disk_max is not None]
    latest_cpu, latest_mem, latest_disk = latest if latest else (None, None, None)
    return series, {
        "cpu": _stats([r.cpu_avg for r in rows], peaks=[r.cpu_max for r in rows], weights=weights, latest=latest_cpu),
        "mem": _stats([r.mem_avg for r in rows], peaks=[r.mem_max for r in rows], weights=weights, latest=latest_mem),
        "disk": _stats([r.disk_max for r in disk_rows], latest=latest_disk),  # type: ignore[misc]
    }


async def host_trends(db: AsyncSession, *, days: int, now: datetime | None = None) -> list[dict[str, Any]]:
    """History of every pinned host over the last ``days`` days, ordered by host name.

    Each entry: ``id``, ``name``, ``cpus``, ``mem_total_mb``, ``metrics`` (the latest probe),
    ``last_checked_at``, ``resolution`` ("raw" up to 7 days, else "hour"), ``series`` (oldest first, each
    point ``{at, cpu, mem, disk}``; hourly points are averages, with ``cpu_max``, ``mem_max`` and
    ``samples`` too, and ``disk`` is the hour's maximum) and ``stats`` (``cpu``, ``mem``, ``disk``: each
    ``{min, avg, max, latest}`` or None without data). Hours not rolled up yet are computed from raw samples.
    """
    now = now or utcnow()
    since = now - timedelta(days=days)
    hosts = (await db.scalars(select(Host).where(Host.host_key.is_not(None)).order_by(Host.name))).all()
    if not hosts:
        return []
    ids = [host.id for host in hosts]
    raw_since = since if days <= RAW_MAX_DAYS else max(floor_hour(since), now - RAW_RETENTION)
    raw: dict[uuid.UUID, list[tuple[datetime, float, float, float | None]]] = defaultdict(list)
    for host_id, at, cpu, mem, disk in (await db.execute(
        select(*_RAW_COLUMNS).where(HostSample.host_id.in_(ids), HostSample.at >= raw_since, HostSample.at <= now)
        .order_by(HostSample.at)
    )):
        raw[host_id].append((at, cpu, mem, disk))

    hourly: dict[uuid.UUID, list[HostSampleHourly]] = defaultdict(list)
    if days > RAW_MAX_DAYS:
        stored = (await db.scalars(
            select(HostSampleHourly).where(
                HostSampleHourly.host_id.in_(ids), HostSampleHourly.hour >= floor_hour(since),
                HostSampleHourly.hour <= now,
            )
        )).all()
        have = {(row.host_id, row.hour) for row in stored}
        for row in stored:
            hourly[row.host_id].append(row)
        pending = _bucket((host_id, at, cpu, mem, disk) for host_id, samples in raw.items() for at, cpu, mem, disk in samples)
        for (host_id, hour), bucket in pending.items():
            if (host_id, hour) not in have:  # not rolled up yet: computed now, never stored here
                hourly[host_id].append(_hourly_row(host_id, hour, bucket))
        for rows in hourly.values():
            rows.sort(key=lambda row: row.hour)

    result = []
    for host in hosts:
        metrics = host.metrics or {}
        if days > RAW_MAX_DAYS:
            last = raw[host.id][-1][1:] if raw[host.id] else None
            series, stats = _hourly_series(hourly[host.id], last)
            resolution = "hour"
        else:
            series, stats = _raw_series(raw[host.id])
            resolution = "raw"
        result.append({
            "id": host.id,
            "name": host.name,
            "cpus": metrics.get("cpus"),
            "mem_total_mb": metrics.get("mem_total_mb"),
            "metrics": metrics,
            "last_checked_at": host.last_checked_at,
            "resolution": resolution,
            "series": series,
            "stats": stats,
        })
    return result
