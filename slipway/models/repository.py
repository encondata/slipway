"""GitHub repositories synced into Slipway."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from slipway.db.base import Base, Timestamps, UUIDPrimaryKey

# Set in detected_config when GitHub's default branch name is too long to store (see repos.sync_repositories).
DEFAULT_BRANCH_TOO_LONG = "default_branch_too_long"


class Repository(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "repositories"

    github_id: Mapped[int] = mapped_column(BigInteger, unique=True)
    full_name: Mapped[str] = mapped_column(String(200), index=True)
    owner: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(Text, default="")
    visibility: Mapped[str] = mapped_column(String(16), default="public")  # public/private/internal
    default_branch: Mapped[str] = mapped_column(String(255), default="main")
    html_url: Mapped[str] = mapped_column(String(300))
    language: Mapped[str | None] = mapped_column(String(50))
    archived: Mapped[bool] = mapped_column(default=False)
    pushed_at: Mapped[datetime | None]

    # {"dockerfile": bool, "compose_file": str | None, "files": [...]}, plus DEFAULT_BRANCH_TOO_LONG: True if set
    detected_config: Mapped[dict[str, Any]] = mapped_column(default=dict)
    detected_at: Mapped[datetime | None]

    synced_at: Mapped[datetime | None]
    synced_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    @property
    def is_private(self) -> bool:
        return self.visibility != "public"

    @property
    def has_dockerfile(self) -> bool:
        return bool(self.detected_config.get("dockerfile"))

    @property
    def compose_file(self) -> str | None:
        return self.detected_config.get("compose_file")

    @property
    def has_manifest(self) -> bool:
        """A slipway.yml at the root: deployed as an app (see services.manifest)."""
        return bool(self.detected_config.get("manifest"))

    @property
    def default_source(self) -> str:
        if self.has_manifest:
            return "app"
        return "compose" if self.compose_file and not self.has_dockerfile else "dockerfile"

    @property
    def deployable(self) -> bool:
        return self.has_dockerfile or bool(self.compose_file) or self.has_manifest

    @property
    def default_branch_usable(self) -> bool:
        """False when GitHub's default branch could not be stored; ``default_branch`` is then not it."""
        return not (self.detected_config or {}).get(DEFAULT_BRANCH_TOO_LONG)
