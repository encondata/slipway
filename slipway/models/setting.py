"""Slipway-wide settings that are kept in the database, such as the Switchyard connection."""

from __future__ import annotations

from typing import Any

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from slipway.core.crypto import EncryptedText
from slipway.db.base import Base, Timestamps, UUIDPrimaryKey


class AppSetting(UUIDPrimaryKey, Timestamps, Base):
    """One group of settings: plain values in ``value``, a secret (an API key, say) encrypted in ``secret``."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), unique=True)
    value: Mapped[dict[str, Any]] = mapped_column(default=dict)
    secret: Mapped[str | None] = mapped_column(EncryptedText)
