"""Where the certificate code keeps its ACME account keys and puts its challenge records (phase 4 §3.8, §11.2).

``certs.issue`` takes two small protocols so it needs neither a database nor Cloudflare. This module gives the
real ones:

* ``AccountKeys``: one ACME account key per directory, on the ``acme`` row of ``app_settings``
  (``value = {accounts: {<directory>: {kid}}}``, ``secret`` = JSON ``{<directory>: <ES256 key PEM>}``,
  encrypted). Migration 0011 inserts the row empty; the store inserts it too when it is missing (a database
  built without the migration, as the tests' is), swallowing a racing insert's IntegrityError on the key, then
  takes ``SELECT ... FOR UPDATE`` of it. A new key is stored only when the directory has none yet, so two first
  uses at once keep one key and both use it (Decision 40). Storing one drops the directory's old ``kid``.
* ``TxtRecords``: the ACME challenge records, TXT records in the Cloudflare zone carrying Slipway's comment
  (``Managed by Slipway: ACME challenge``), through ``CloudflareClient.create_txt``, ``txt_records`` and
  ``delete_record``.

Nothing here logs or audits a key.
"""

from __future__ import annotations

import asyncio
import json
import weakref
from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from slipway.db.session import get_sessionmaker
from slipway.models import AppSetting
from slipway.services import certs
from slipway.services.certs import AccountKey, TxtRecord
from slipway.services.cloudflare import CloudflareClient

SETTING_KEY = "acme"

# SQLite has no row locks (``FOR UPDATE`` is ignored there), so writers in one process also take this lock.
# On PostgreSQL the row lock is what keeps two Slipway processes from storing two keys. One lock per event loop.
_locks: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = weakref.WeakKeyDictionary()


def _lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    lock = _locks.get(loop)
    if lock is None:
        lock = _locks[loop] = asyncio.Lock()
    return lock


def _keys_of(row: AppSetting | None) -> dict[str, str]:
    """The stored ``{directory: pem}``; an empty or unreadable secret is no keys (a key change cleared it)."""
    if row is None or not row.secret:
        return {}
    try:
        value = json.loads(row.secret)
    except (TypeError, ValueError):
        return {}
    return {str(k): str(v) for k, v in value.items() if isinstance(v, str)} if isinstance(value, dict) else {}


def _kid_of(row: AppSetting | None, directory: str) -> str | None:
    accounts = ((row.value if row is not None else None) or {}).get("accounts") or {}
    entry = accounts.get(directory) if isinstance(accounts, dict) else None
    kid = entry.get("kid") if isinstance(entry, dict) else None
    return str(kid) if kid else None


class AccountKeys:
    """``certs.AccountKeys`` on the ``acme`` row of ``app_settings``."""

    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession] | None = None) -> None:
        self._sessionmaker = sessionmaker

    def _db(self) -> AsyncSession:
        return (self._sessionmaker or get_sessionmaker())()

    async def _row(self, db: AsyncSession, *, lock: bool = False) -> AppSetting | None:
        stmt = select(AppSetting).where(AppSetting.key == SETTING_KEY)
        if lock:
            stmt = stmt.with_for_update()
        return await db.scalar(stmt)

    async def _ensure_row(self) -> None:
        """Insert the empty row when it is missing; another writer's insert of the same key is no error."""
        async with self._db() as db:
            if await self._row(db) is not None:
                return
            db.add(AppSetting(key=SETTING_KEY, value={}, secret=None))
            try:
                await db.commit()
            except IntegrityError:
                await db.rollback()

    async def get(self, directory: str) -> AccountKey | None:
        async with self._db() as db:
            row = await self._row(db)
            pem = _keys_of(row).get(directory)
            return AccountKey(directory, pem, _kid_of(row, directory)) if pem else None

    async def put_if_absent(self, directory: str, pem: str) -> AccountKey:
        """Store ``pem`` for ``directory`` only when it has no key yet; returns the key stored afterwards.

        A new key drops the directory's remembered ``kid`` in the same transaction: that account URL belonged
        to a key that is gone (a key change cleared an unreadable secret), so the next order registers the
        new key instead of signing with the old account's URL.
        """
        await self._ensure_row()
        async with _lock(), self._db() as db:
            row = await self._row(db, lock=True)
            assert row is not None
            keys = _keys_of(row)
            if directory not in keys:
                keys[directory] = pem
                row.secret = json.dumps(keys, sort_keys=True)
                if _kid_of(row, directory) is not None:
                    value: dict[str, Any] = dict(row.value or {})
                    accounts = dict(value.get("accounts") or {})
                    accounts.pop(directory, None)
                    value["accounts"] = accounts
                    row.value = value
            stored = keys[directory]
            kid = _kid_of(row, directory)
            await db.commit()
            return AccountKey(directory, stored, kid)

    async def remember_kid(self, directory: str, kid: str) -> None:
        """Keep the account URL of ``directory`` (``value.accounts[<directory>].kid``)."""
        await self._ensure_row()
        async with _lock(), self._db() as db:
            row = await self._row(db, lock=True)
            assert row is not None
            value: dict[str, Any] = dict(row.value or {})
            accounts = dict(value.get("accounts") or {}) if isinstance(value.get("accounts"), dict) else {}
            accounts[directory] = {**(accounts.get(directory) or {}), "kid": str(kid)}
            value["accounts"] = accounts
            row.value = value
            await db.commit()


class TxtRecords:
    """``certs.TxtRecords`` in one Cloudflare zone, through an open ``CloudflareClient``."""

    def __init__(self, client: CloudflareClient, zone_id: str) -> None:
        self.client = client
        self.zone_id = zone_id

    async def create(self, name: str, content: str, comment: str) -> str:
        record = await self.client.create_txt(self.zone_id, name, content, comment)
        return str(record["id"])

    async def list(self, comment: str) -> Sequence[TxtRecord]:
        """The zone's TXT records carrying exactly ``comment`` (one page of 100; a later sweep takes the rest)."""
        return [TxtRecord(id=str(r["id"]), name=str(r.get("name") or ""), content=str(r.get("content") or ""),
                          comment=r.get("comment"))
                for r in await self.client.txt_records(self.zone_id, comment)]

    async def delete(self, record_id: str) -> None:
        await self.client.delete_record(self.zone_id, record_id)


CHALLENGE_COMMENT = certs.CHALLENGE_COMMENT
