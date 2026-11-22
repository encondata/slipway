"""Provider accounts: the DigitalOcean, Proxmox and ESXi accounts Slipway makes machines with.

One table for all three providers. What only one provider needs lives in ``config`` (DigitalOcean
``{region, ssh_sources, monthly_limit_cents, prices, team}``; Proxmox ``{url, node, pool, storage,
template_vmid, token_id, networks}``; ESXi ``{url, user, datastore, resource_pool, source_vm, networks}``),
so the columns are the ones every provider shares. ``secret`` is write-only: the DigitalOcean token, the
whole Proxmox API token (``user@realm!tokenid=<uuid>``) or the ESXi password. NULL means not set.

An account that something still points at is never deleted: Remove clears its secret and config, keeps
its name and sets ``removed_at`` (the tombstone), so a deleted environment's log can still name it.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, String, false, text
from sqlalchemy.orm import Mapped, mapped_column

from slipway.core.crypto import EncryptedText
from slipway.db.base import Base, Timestamps, UUIDPrimaryKey

# An account's name, shown everywhere (checked by the accounts service, not by the database).
ACCOUNT_NAME_RE = r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$"


class ProviderKind(StrEnum):
    """Who makes a machine. Hosts added by hand are ``ssh``, which is not a provider account."""

    DIGITALOCEAN = "digitalocean"
    PROXMOX = "proxmox"
    ESXI = "esxi"

    @property
    def is_hypervisor(self) -> bool:
        return self is not ProviderKind.DIGITALOCEAN


class AccountStatus(StrEnum):
    """The result of an account's last Test."""

    UNKNOWN = "unknown"
    OK = "ok"
    WARNING = "warning"
    ERROR = "error"


class ProviderAccount(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "provider_accounts"
    __table_args__ = (
        CheckConstraint("provider IN ('digitalocean', 'proxmox', 'esxi')", name="provider"),
        # Production safeguards are DigitalOcean's alone (phase 4 §13).
        CheckConstraint("NOT production OR provider = 'digitalocean'", name="production_do"),
    )

    provider: Mapped[str] = mapped_column(String(16))  # ProviderKind
    name: Mapped[str] = mapped_column(String(64), unique=True)
    production: Mapped[bool] = mapped_column(default=False, server_default=false())
    secret: Mapped[str | None] = mapped_column(EncryptedText)
    # The secret's last few characters, so a person can tell which one is stored ('' when none is).
    secret_hint: Mapped[str] = mapped_column(String(16), default="", server_default="")
    config: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default=text("'{}'"))
    # Proxmox and ESXi: the pinned TLS certificate {pem, fingerprint_sha256, subject, issuer, not_after, sans,
    # trusted_at, trusted_by}; NULL until a person trusts one. Always NULL for DigitalOcean.
    tls: Mapped[dict[str, Any] | None] = mapped_column()
    status: Mapped[str] = mapped_column(String(16), default=AccountStatus.UNKNOWN, server_default="unknown")
    # The last Test's checks, [{name, ok, level, text}] (vmtypes.Check.to_dict), and what it read.
    checks: Mapped[list[dict[str, Any]]] = mapped_column(default=list, server_default=text("'[]'"))
    facts: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default=text("'{}'"))
    last_checked_at: Mapped[datetime | None]
    removed_at: Mapped[datetime | None]
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    @property
    def has_secret(self) -> bool:
        return bool(self.secret)

    @property
    def is_removed(self) -> bool:
        return self.removed_at is not None
