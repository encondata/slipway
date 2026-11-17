"""Environments (one app with its settings, secrets, slots and traffic) and the outside objects they own.

An environment's slots are ordinary instances with ``environment_id`` and ``slot`` set (``blue``,
``green``, or ``data`` for the data server); there is no slot table. Environments are never hard-deleted:
Delete sets ``status = deleted`` and ``deleted_at``, so the teardown job, its log and the audit trail stay
readable, and the name becomes free for a new environment.

Every Switchyard host and DNS record an environment manages is a ``resources`` row, written the moment
the provider answers, so Slipway only ever changes or deletes objects it recorded (phase 3 §3.4).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, UniqueConstraint, false, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from slipway.core.crypto import EncryptedJSON
from slipway.db.base import Base, Timestamps, UUIDPrimaryKey
from slipway.models.repository import Repository

# An environment's name: 2-26 characters, so "<name>-green" fits the 32 characters an app's own names
# often allow (ServerSherpa's STACK_ENV) and the instance slug's 63.
ENVIRONMENT_NAME_RE = r"^[a-z][a-z0-9-]{0,24}[a-z0-9]$"
ENVIRONMENT_NAME_MAX = 26

# What a member job answers when ``app_secrets`` is stored but reads as nothing (rotate-encryption-key
# --clear-unreadable left an encrypted null): Slipway never regenerates an environment's secrets (D5).
SECRETS_LOST = (
    "Slipway lost {env}'s secrets (SLIPWAY_ENCRYPTION_KEY changed): put the old key back first in the list "
    "and run slipway rotate-encryption-key, or set each secret as a variable of {env} with its old value and "
    "deploy (the deploy keeps them as {env}'s secrets)"
)


class EnvironmentStatus(StrEnum):
    NEW = "new"  # created; nothing activated yet
    LIVE = "live"  # the first activate succeeded
    DELETING = "deleting"  # teardown queued (a failed teardown stays here until its retry finishes)
    DELETED = "deleted"


class DataMode(StrEnum):
    SLOT = "slot"  # the only app slot holds its own data, exactly as a phase 2 instance
    SERVER = "server"  # a separate data server instance; one or two app slots attach to it
    MANAGED = "managed"  # phase 4: managed database and object store


class SlotName(StrEnum):
    BLUE = "blue"
    GREEN = "green"
    DATA = "data"  # the data server

    @property
    def is_app(self) -> bool:
        return self is not SlotName.DATA


class ResourceOrigin(StrEnum):
    CREATED = "created"  # Slipway made it and may delete it
    CLAIMED = "claimed"  # it existed; Slipway keeps it current and never deletes it


# The production environments ux_environments_one_production allows one of per app.
ONE_PRODUCTION = "production AND retiring_at IS NULL AND deleted_at IS NULL"


def _default_traffic() -> dict[str, Any]:
    return {"switch": "none", "dns": None}


class Environment(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "environments"
    __table_args__ = (
        # The name is unique among live environments only (deleted ones keep theirs for the record).
        Index(
            "ux_environments_name_live",
            "name",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
            sqlite_where=text("deleted_at IS NULL"),
        ),
        CheckConstraint("(status = 'deleted') = (deleted_at IS NOT NULL)", name="deleted"),
        CheckConstraint("data_mode IN ('slot', 'server', 'managed')", name="data_mode"),
        # Phase 4: a DigitalOcean environment always names its account, and only it does (a VM environment is
        # placement ssh: its accounts are on its machines). DigitalOcean data is always managed.
        CheckConstraint("(provider = 'digitalocean') = (provider_account_id IS NOT NULL)", name="provider_account"),
        CheckConstraint("provider <> 'digitalocean' OR data_mode = 'managed'", name="do_managed"),
        CheckConstraint("NOT production OR provider = 'digitalocean'", name="production_do"),
        CheckConstraint("retiring_at IS NULL OR production", name="retiring"),
        CheckConstraint("NOT production OR NOT auto_activate", name="production_auto"),
        # One production environment per app (repository and manifest) that isn't being retired.
        Index(
            "ux_environments_one_production",
            "repository_id",
            "manifest_file",
            unique=True,
            postgresql_where=text(ONE_PRODUCTION),
            sqlite_where=text(ONE_PRODUCTION),
        ),
    )

    name: Mapped[str] = mapped_column(String(ENVIRONMENT_NAME_MAX))
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id", ondelete="RESTRICT"))
    branch: Mapped[str] = mapped_column(String(255))
    manifest_file: Mapped[str] = mapped_column(String(255), default="slipway.yml", server_default="slipway.yml")
    data_mode: Mapped[str] = mapped_column(String(8))  # DataMode

    # Settings, services, variables and secrets belong to the environment and are written into every
    # member's .env; the slots' own columns stay empty (D5).
    app_settings: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default=text("'{}'"))
    app_services: Mapped[list[str] | None] = mapped_column()  # None: each optional service's default
    app_secrets: Mapped[dict[str, str] | None] = mapped_column(EncryptedJSON)
    # Bumped by every write of app_secrets. Fernet encrypts the same value differently each time, so a
    # compare-and-set compares this, never the ciphertext.
    secrets_version: Mapped[int] = mapped_column(default=0, server_default=text("0"))
    env: Mapped[dict[str, str] | None] = mapped_column(EncryptedJSON)

    # {hostname: tls_mode} overrides of Switchyard's default_tls_mode.
    route_tls: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default=text("'{}'"))
    # The routes last planned: [{hostname, service, container, follows, health}].
    hostnames: Mapped[list[dict[str, Any]]] = mapped_column(default=list, server_default=text("'[]'"))
    auto_activate: Mapped[bool] = mapped_column(default=False, server_default=false())
    # {switch: "none" | "switchyard", dns: None | {provider: "cloudflare", address, proxied}}
    traffic: Mapped[dict[str, Any]] = mapped_column(
        default=_default_traffic, server_default=text("""'{"switch": "none", "dns": null}'""")
    )
    # {unresolved: {...} | None, last: {...} | None, last_slot_deploy: {...} | None}
    traffic_state: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default=text("'{}'"))
    # The app slot that receives traffic (None: nothing is live). Instances and environments point at
    # each other, hence use_alter.
    active_slot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("instances.id", ondelete="SET NULL", use_alter=True)
    )

    status: Mapped[str] = mapped_column(String(16), default=EnvironmentStatus.NEW, server_default="new")
    # Why a chained job didn't start: {text, at, deployment_id}.
    notice: Mapped[dict[str, Any] | None] = mapped_column()
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    deleted_at: Mapped[datetime | None]
    deleted_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    # Phase 4. The placement: ``ssh`` (hosts added by hand, or VMs Slipway makes) or ``digitalocean``.
    provider: Mapped[str] = mapped_column(String(16), default="ssh", server_default="ssh")
    # RESTRICT: an account can't be dropped while an environment row (deleted ones included) points at it.
    provider_account_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("provider_accounts.id", ondelete="RESTRICT")
    )
    provider_team: Mapped[str | None] = mapped_column(String(80))  # frozen by the first DigitalOcean step
    # DigitalOcean: {region, droplet_size, droplet_image, db_size, db_nodes, db_version, acme_staging, vpc_range,
    # lb_ip, edge, slipway_addresses, certificate, plan, cost} (phase 4 §3.2).
    cloud: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default=text("'{}'"))
    production: Mapped[bool] = mapped_column(default=False, server_default=false())
    retiring_at: Mapped[datetime | None]
    retired_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    repository: Mapped[Repository] = relationship(lazy="selectin")

    @property
    def is_deleted(self) -> bool:
        return self.status == EnvironmentStatus.DELETED

    def slot_slug(self, slot: str) -> str:
        """The slug of this environment's instance in ``slot`` (reserved whether or not it exists yet)."""
        return f"{self.name}-{slot}"


class Resource(UUIDPrimaryKey, Timestamps, Base):
    """An outside object an environment manages: a Switchyard proxy host, a DNS record (phase 4: droplets,
    databases, buckets, load balancers...). Deleted when the object is deleted or forgotten."""

    __tablename__ = "resources"
    __table_args__ = (
        # One owner per outside object.
        UniqueConstraint("provider", "kind", "provider_id", name="uq_resources_provider_kind_provider_id"),
        UniqueConstraint("environment_id", "kind", "name", name="uq_resources_environment_id_kind_name"),
    )

    # RESTRICT: an environment row can't go while it still lists objects Slipway made.
    environment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("environments.id", ondelete="RESTRICT"), index=True
    )
    # The slot it belongs to, when it belongs to one (phase 4 droplets).
    instance_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("instances.id", ondelete="SET NULL"))
    provider: Mapped[str] = mapped_column(String(16))  # switchyard, cloudflare
    kind: Mapped[str] = mapped_column(String(32))  # proxy_host, dns_record
    provider_id: Mapped[str] = mapped_column(String(200))  # Switchyard host id, Cloudflare record id
    name: Mapped[str] = mapped_column(String(255))  # the hostname (or the provider-side name)
    origin: Mapped[str] = mapped_column(String(8))  # ResourceOrigin
    # proxy_host: {follows, upstream, tls_mode, url}; dns_record: {zone_id, type, content, proxied}
    details: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default=text("'{}'"))
    tags: Mapped[list[str]] = mapped_column(default=list, server_default=text("'[]'"))
    credentials: Mapped[dict[str, Any] | None] = mapped_column(EncryptedJSON)  # phase 4
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
