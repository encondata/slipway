"""Instances (a repository running on a host) and their deployments."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import ForeignKey, String, Text, text, true
from sqlalchemy.orm import Mapped, mapped_column, relationship

from slipway.core.crypto import EncryptedJSON
from slipway.db.base import Base, Timestamps, UUIDPrimaryKey
from slipway.models.host import Host
from slipway.models.repository import Repository
from slipway.models.user import User


class BuildSource(StrEnum):
    DOCKERFILE = "dockerfile"
    COMPOSE = "compose"


class InstanceStatus(StrEnum):
    CREATED = "created"  # configured, never deployed
    DEPLOYING = "deploying"
    RUNNING = "running"
    STOPPED = "stopped"
    FAILED = "failed"


class DeploymentStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_active(self) -> bool:
        return self in (DeploymentStatus.QUEUED, DeploymentStatus.RUNNING)


class Instance(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "instances"

    name: Mapped[str] = mapped_column(String(100))
    slug: Mapped[str] = mapped_column(String(63), unique=True)
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id", ondelete="RESTRICT"))
    host_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("hosts.id", ondelete="RESTRICT"))
    branch: Mapped[str] = mapped_column(String(255))

    build_source: Mapped[str] = mapped_column(String(16), default=BuildSource.DOCKERFILE)
    dockerfile_path: Mapped[str] = mapped_column(String(255), default="Dockerfile")
    build_context: Mapped[str] = mapped_column(String(255), default=".")
    compose_file: Mapped[str] = mapped_column(String(255), default="docker-compose.yml")

    env: Mapped[dict[str, str] | None] = mapped_column(EncryptedJSON)
    ports: Mapped[list[dict[str, Any]]] = mapped_column(default=list)  # [{host, container, protocol}]
    volumes: Mapped[list[dict[str, Any]]] = mapped_column(default=list)  # [{source, target}]
    # When a host port is taken at deploy time, use the next free one (else the deploy fails before it starts).
    auto_ports: Mapped[bool] = mapped_column(default=True, server_default=true())
    # Compose mode: host ports to use instead of the compose file's, [{service, container, protocol, host, auto?}].
    # Ports Slipway moved are stored here too (auto: true), so they stay the same on later deploys.
    port_overrides: Mapped[list[dict[str, Any]]] = mapped_column(default=list, server_default=text("'[]'"))
    # Host ports the last deployment published, [{service, container, protocol, host, host_ip?, declared?}].
    published_ports: Mapped[list[dict[str, Any]]] = mapped_column(default=list, server_default=text("'[]'"))

    # Compose project name of a claimed compose project. Compose prefixes named volumes and networks
    # with the project name, so a claimed project keeps its own name on every deploy (None: slipway-<slug>).
    compose_project_name: Mapped[str | None] = mapped_column(String(255))
    # Set on instances claimed from containers Slipway did not deploy: {kind: "compose" | "container",
    # name, container_id?, container_name?, working_dir?, config_files?, claimed_at, replaced}. Until the
    # first successful deploy (``replaced``), a claimed standalone container is reached by its id.
    claim: Mapped[dict[str, Any] | None] = mapped_column()

    status: Mapped[str] = mapped_column(String(16), default=InstanceStatus.CREATED)
    current_commit_sha: Mapped[str | None] = mapped_column(String(40))
    last_deployed_at: Mapped[datetime | None]
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    repository: Mapped[Repository] = relationship(lazy="selectin")
    host: Mapped[Host] = relationship(lazy="selectin")

    @property
    def container_name(self) -> str:
        return f"slipway-{self.slug}"

    @property
    def compose_project(self) -> str:
        return self.compose_project_name or f"slipway-{self.slug}"

    @property
    def claim_pending(self) -> bool:
        """Claimed, and no Slipway deployment has replaced the claimed containers yet."""
        return bool(self.claim) and not self.claim.get("replaced")

    @property
    def claimed_container(self) -> str | None:
        """Id of the claimed standalone container the first deployment still has to replace."""
        if self.claim_pending and self.claim.get("kind") == "container":
            return self.claim.get("container_id") or None
        return None

    @property
    def running_container_name(self) -> str:
        """The container's name on the host: the claimed one until the first deploy replaces it."""
        if self.claimed_container:
            return self.claim.get("container_name") or self.claimed_container[:12]
        return self.container_name


class Deployment(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "deployments"

    instance_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("instances.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(16), default=DeploymentStatus.QUEUED, index=True)
    branch: Mapped[str] = mapped_column(String(255))
    commit_sha: Mapped[str | None] = mapped_column(String(40))
    commit_message: Mapped[str | None] = mapped_column(String(500))
    commit_author: Mapped[str | None] = mapped_column(String(100))
    triggered_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    error: Mapped[str | None] = mapped_column(Text)
    log: Mapped[str] = mapped_column(Text, default="")

    instance: Mapped[Instance] = relationship(lazy="selectin")
    triggered_by: Mapped[User | None] = relationship(lazy="selectin")

    @property
    def is_active(self) -> bool:
        return DeploymentStatus(self.status).is_active

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    @property
    def short_sha(self) -> str:
        return (self.commit_sha or "")[:7]
