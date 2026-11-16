"""Instances (a repository running on a host) and their deployments."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import ForeignKey, Index, String, Text, false, text, true
from sqlalchemy.orm import Mapped, mapped_column, relationship

from slipway.core.crypto import EncryptedJSON
from slipway.db.base import Base, Timestamps, UUIDPrimaryKey
from slipway.models.host import Host
from slipway.models.repository import Repository
from slipway.models.user import User


class BuildSource(StrEnum):
    DOCKERFILE = "dockerfile"
    COMPOSE = "compose"
    APP = "app"  # the repository's slipway.yml says how (see services.manifest)


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


class DeploymentKind(StrEnum):
    """What a job does. Every data job is a Deployment with a kind (D1)."""

    DEPLOY = "deploy"
    RESTORE = "restore"
    ROLLBACK = "rollback"
    RESET = "reset"
    BACKUP = "backup"
    SNAPSHOT = "snapshot"
    ADMIN = "admin"
    CONTENT = "content"


class FreshData(StrEnum):
    """Data that only Slipway's own never-live attempts created (instances.fresh_data)."""

    EMPTY = "empty"
    SNAPSHOT = "snapshot"


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
    # The instance's own folder on the host (releases, shared settings, ``current``). None: a folder
    # named after the slug in the host's deploy root, which moves with that root.
    deploy_dir: Mapped[str | None] = mapped_column(String(255))

    # App mode (BuildSource.APP): the manifest's path in the repository, the values of its settings,
    # the optional services that run (None: each one's default), the secrets Slipway generated for it
    # (kept for good: changing one can lock the app out of its own data), and what the last deploy read
    # and rendered: {manifest, routes: [{hostname, service, container}], projects, commands, release}.
    manifest_file: Mapped[str] = mapped_column(String(255), default="slipway.yml", server_default="slipway.yml")
    app_settings: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default=text("'{}'"))
    app_services: Mapped[list[str] | None] = mapped_column()
    app_secrets: Mapped[dict[str, str] | None] = mapped_column(EncryptedJSON)
    app_state: Mapped[dict[str, Any] | None] = mapped_column()

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

    # Hostnames the reverse proxy (Switchyard) sends to this instance:
    # [{hostname, service (compose; None in Dockerfile mode), container, tls_mode}].
    routes: Mapped[list[dict[str, Any]]] = mapped_column(default=list, server_default=text("'[]'"))
    # What the last proxy sync left in Switchyard, one per hostname:
    # [{hostname, switchyard_id, upstream, state: "live" | "staged" | "error", message, synced_at}].
    proxy_entries: Mapped[list[dict[str, Any]]] = mapped_column(default=list, server_default=text("'[]'"))

    status: Mapped[str] = mapped_column(String(16), default=InstanceStatus.CREATED)
    current_commit_sha: Mapped[str | None] = mapped_column(String(40))
    last_deployed_at: Mapped[datetime | None]
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    # Data safety (app instances whose slipway.yml declares data). How many automatic backups to keep (1-100).
    keep_backups: Mapped[int] = mapped_column(default=5, server_default=text("5"))
    # A snapshot the first deploy restores; cleared when that job succeeds. Instances and snapshots point
    # at each other (snapshots.source_instance_id), hence use_alter.
    seed_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("snapshots.id", ondelete="SET NULL", use_alter=True)
    )
    # Run the app's seed command on an empty first deploy; content_pending: a seed step ended in a warning.
    seed_content: Mapped[bool] = mapped_column(default=True, server_default=true())
    content_pending: Mapped[bool] = mapped_column(default=False, server_default=false())
    # The identity secret values the data now carries (set at finish and by the restore step), when they
    # last changed and where they came from (such as "snapshot uat-2026-11-15").
    live_identity: Mapped[dict[str, str] | None] = mapped_column(EncryptedJSON)
    identity_changed_at: Mapped[datetime | None]
    identity_source: Mapped[str | None] = mapped_column(String(300))
    # The first job since the last success that began changing data and then failed, with its
    # pre-change backup and whether the data is held (see services.data).
    data_dirty: Mapped[dict[str, Any] | None] = mapped_column()
    fresh_data: Mapped[str | None] = mapped_column(String(8))  # FreshData
    last_control_at: Mapped[datetime | None]  # the last start or restart from the instance page

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
    __table_args__ = (
        # At most one queued or running job per instance.
        Index(
            "ux_deployments_one_active",
            "instance_id",
            unique=True,
            postgresql_where=text("status IN ('queued', 'running')"),
            sqlite_where=text("status IN ('queued', 'running')"),
        ),
    )

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
    # The numbered steps, in order: [{key, name, status, started_at?, finished_at?, offset?, note?}];
    # ``offset`` is where the step's part of ``log`` begins.
    steps: Mapped[list[dict[str, Any]]] = mapped_column(default=list, server_default=text("'[]'"))
    # The release folder on the host (kept after a failure once the build succeeded, for a retry).
    release: Mapped[str | None] = mapped_column(Text)  # a folder of up to 255 characters, plus the release
    # A retry runs the same commit again and skips the steps the earlier run finished that it can reuse.
    retry_of_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("deployments.id", ondelete="SET NULL"))
    # What the job does (DeploymentKind) and its options, such as skip_backup or files.
    kind: Mapped[str] = mapped_column(String(16), default=DeploymentKind.DEPLOY, server_default="deploy", index=True)
    options: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default=text("'{}'"))
    previous_sha: Mapped[str | None] = mapped_column(String(40))  # the instance's live commit when queued
    # The chain's pre-change backup (taken or inherited), what a restore or roll back puts back, and the
    # snapshot restored or taken.
    backup_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("backups.id", ondelete="SET NULL"))
    restore_backup_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("backups.id", ondelete="SET NULL"))
    snapshot_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("snapshots.id", ondelete="SET NULL"))

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
