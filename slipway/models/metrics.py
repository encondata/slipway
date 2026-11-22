"""Host history: one row per successful health check, rolled up into hourly rows for long ranges."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from slipway.db.base import Base, UUIDPrimaryKey


class HostSample(UUIDPrimaryKey, Base):
    __tablename__ = "host_samples"
    __table_args__ = (Index("ix_host_samples_host_id_at", "host_id", "at"),)

    host_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"))
    at: Mapped[datetime]
    cpu_percent: Mapped[float]
    mem_percent: Mapped[float]
    disk_percent: Mapped[float | None]
    containers_running: Mapped[int | None]


class HostSampleHourly(UUIDPrimaryKey, Base):
    __tablename__ = "host_samples_hourly"
    __table_args__ = (UniqueConstraint("host_id", "hour", name="uq_host_samples_hourly_host_id_hour"),)

    host_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"))
    hour: Mapped[datetime]  # start of the hour, UTC
    cpu_avg: Mapped[float]
    cpu_max: Mapped[float]
    mem_avg: Mapped[float]
    mem_max: Mapped[float]
    disk_max: Mapped[float | None]
    samples: Mapped[int]
