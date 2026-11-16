"""An app instance's data: backups on its host, snapshot bundles stored by Slipway, and the first admin.

Backups are dump files in the instance folder's ``backups/`` on the host; a row records what Slipway
took and checked (the file itself never passes through Slipway). Snapshots are ``.sbx`` files in
Slipway's own storage (``SLIPWAY_STORAGE_DIR``), always encrypted under a per-snapshot key held in
``data_key``. The first admin is the account an app's ``first_admin`` command creates after a deploy.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, Index, String, Text, UniqueConstraint, false, text
from sqlalchemy.orm import Mapped, mapped_column

from slipway.core.crypto import EncryptedJSON, EncryptedText
from slipway.db.base import Base, Timestamps, UUIDPrimaryKey

# The longest revision text a backup or snapshot keeps (an opaque value the app prints, D6).
REVISION_MAX_BYTES = 16 * 1024


class BackupReason(StrEnum):
    PRE_DEPLOY = "pre_deploy"
    PRE_RETRY = "pre_retry"  # the app was started by hand since the failed run's backup
    PRE_RESTORE = "pre_restore"
    PRE_RESET = "pre_reset"
    PRE_ROLLBACK = "pre_rollback"
    MANUAL = "manual"  # "Back up now": deleted by hand only


class BackupStatus(StrEnum):
    PENDING = "pending"  # the dump is being written
    UNVERIFIED = "unverified"  # written, but the checks didn't finish
    READY = "ready"  # written and checked
    MISSING = "missing"  # a host check didn't find the file
    CHANGED = "changed"  # a host check found another size or checksum


class Backup(UUIDPrimaryKey, Timestamps, Base):
    """A dump of an instance's data, taken on its host by a job (or by "Back up now")."""

    __tablename__ = "backups"
    __table_args__ = (
        UniqueConstraint("instance_id", "name"),
        Index("ix_backups_instance_id_taken_at", "instance_id", "taken_at"),
        CheckConstraint("status <> 'ready' OR db_bytes IS NOT NULL", name="ready_has_db_bytes"),
        CheckConstraint("NOT has_files OR status <> 'ready' OR files_bytes IS NOT NULL", name="ready_has_files_bytes"),
    )

    instance_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("instances.id", ondelete="CASCADE"), index=True)
    # The job that took it. Backups and deployments point at each other, hence use_alter.
    deployment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("deployments.id", ondelete="SET NULL", use_alter=True)
    )
    name: Mapped[str] = mapped_column(String(32))  # the file name stem on the host (checked against NAME_RE)
    reason: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default=BackupStatus.PENDING, server_default="pending")
    format: Mapped[str] = mapped_column(String(40))  # data.format of the release whose dump ran
    db_bytes: Mapped[int | None] = mapped_column(BigInteger)
    db_sha256: Mapped[str | None] = mapped_column(String(64))
    has_files: Mapped[bool] = mapped_column(default=False, server_default=false())
    files_format: Mapped[str | None] = mapped_column(String(40))
    files_bytes: Mapped[int | None] = mapped_column(BigInteger)
    files_sha256: Mapped[str | None] = mapped_column(String(64))
    revision: Mapped[str | None] = mapped_column(Text)  # up to REVISION_MAX_BYTES
    commit_sha: Mapped[str | None] = mapped_column(String(40))  # the instance's live commit when taken
    release: Mapped[str | None] = mapped_column(String(64))  # folder of the release whose dump ran
    # Taken while the instance was dirty: the first failed job that began changing the data (§8.4).
    dirty_of: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("deployments.id", ondelete="SET NULL", use_alter=True)
    )
    # The identity secrets the data was made with: their names, their values (from live_identity) and
    # a fingerprint of the values, so a restore can tell whether the keys match.
    identity_keys: Mapped[list[str]] = mapped_column(default=list, server_default=text("'[]'"))
    identity: Mapped[dict[str, str] | None] = mapped_column(EncryptedJSON)
    identity_fp: Mapped[str] = mapped_column(String(64))
    note: Mapped[str | None] = mapped_column(String(300))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    taken_at: Mapped[datetime]
    finished_at: Mapped[datetime | None]
    checked_at: Mapped[datetime | None]  # last time a host check confirmed the file


class SnapshotStatus(StrEnum):
    PENDING = "pending"  # being taken or uploaded
    LOCKED = "locked"  # an encrypted import waiting for its passphrase
    CHECKING = "checking"  # being validated in the background
    READY = "ready"
    FAILED = "failed"


class SnapshotOrigin(StrEnum):
    INSTANCE = "instance"  # taken from an instance
    UPLOAD = "upload"  # a plain bundle uploaded
    IMPORT = "import"  # a passphrase-encrypted file uploaded


class Snapshot(UUIDPrimaryKey, Timestamps, Base):
    """A named copy of an app's data (database, optional files, identity keys) kept by Slipway."""

    __tablename__ = "snapshots"
    __table_args__ = (
        CheckConstraint(
            # data_key is left out on purpose: rotate-encryption-key --clear-unreadable must be able to clear it.
            "status <> 'ready' OR (file_sha256 IS NOT NULL AND db_sha256 IS NOT NULL AND app IS NOT NULL)",
            name="ready_is_complete",
        ),
    )

    name: Mapped[str] = mapped_column(String(64), unique=True)
    notes: Mapped[str] = mapped_column(Text, default="", server_default="")
    status: Mapped[str] = mapped_column(String(16))
    origin: Mapped[str] = mapped_column(String(16))
    # What the bundle says about itself. repository is owner/name.
    app: Mapped[str | None] = mapped_column(String(64))
    app_name: Mapped[str | None] = mapped_column(String(100))
    repository: Mapped[str | None] = mapped_column(String(200))
    source: Mapped[str | None] = mapped_column(String(100))
    source_instance_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("instances.id", ondelete="SET NULL"))
    commit_sha: Mapped[str | None] = mapped_column(String(40))
    source_created_at: Mapped[datetime | None]
    db_format: Mapped[str | None] = mapped_column(String(40))
    db_revision: Mapped[str | None] = mapped_column(Text)
    db_bytes: Mapped[int | None] = mapped_column(BigInteger)
    db_sha256: Mapped[str | None] = mapped_column(String(64))
    # All three are None when the snapshot has no files.
    files_format: Mapped[str | None] = mapped_column(String(40))
    files_bytes: Mapped[int | None] = mapped_column(BigInteger)
    files_sha256: Mapped[str | None] = mapped_column(String(64))
    identity_keys: Mapped[list[str]] = mapped_column(default=list, server_default=text("'[]'"))  # names only
    data_key: Mapped[str | None] = mapped_column(EncryptedText)  # base64 of the 32-byte key the .sbx is under
    # The passphrase key block of a locked import, until it is unlocked (then None).
    import_keyblock: Mapped[dict[str, Any] | None] = mapped_column()
    expires_at: Mapped[datetime | None]  # a locked import is deleted after this
    # The stored .sbx file.
    file_bytes: Mapped[int | None] = mapped_column(BigInteger)
    file_sha256: Mapped[str | None] = mapped_column(String(64))
    deployment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("deployments.id", ondelete="SET NULL", use_alter=True)
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    error: Mapped[str | None] = mapped_column(String(500))


class FirstAdminMode(StrEnum):
    PASSWORD = "password"
    INVITE = "invite"


class FirstAdminStatus(StrEnum):
    PENDING = "pending"
    DONE = "done"


class FirstAdmin(UUIDPrimaryKey, Timestamps, Base):
    """The first admin account of an app instance, created by the first_admin step after a deploy."""

    __tablename__ = "first_admins"
    __table_args__ = (
        CheckConstraint("mode = 'password' OR password IS NULL", name="password_only_in_password_mode"),
        # The password is dropped once the account exists.
        CheckConstraint("status = 'pending' OR password IS NULL", name="password_only_while_pending"),
    )

    instance_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("instances.id", ondelete="CASCADE"), unique=True)
    fields: Mapped[dict[str, Any]] = mapped_column()  # {field: value} from the manifest's admin fields; no secrets
    mode: Mapped[str] = mapped_column(String(8))
    password: Mapped[str | None] = mapped_column(EncryptedText)
    status: Mapped[str] = mapped_column(String(8), default=FirstAdminStatus.PENDING)
    existed: Mapped[bool] = mapped_column(default=False, server_default=false())  # the app already had the account
    done_at: Mapped[datetime | None]
    deployment_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("deployments.id", ondelete="SET NULL"))
    last_error: Mapped[str | None] = mapped_column(String(300))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
