"""Migration 0016 (Sign in with HackSpaceLabs): the new user_sessions columns, existing sessions reading as
local ones, the downgrade ending HackSpaceLabs sessions, and at head ``alembic check``.

Runs on SQLite, and also on PostgreSQL when SLIPWAY_TEST_DATABASE_URL names one (a throwaway database).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import create_async_engine

from tests.test_migration_0009 import _insert, _inspect, _ok, _rows, migration_url  # noqa: F401

NOW = datetime(2026, 11, 24, 9, 0, tzinfo=UTC)
NEW = {"auth_source", "idp_sid", "idp_tokens", "idp_checked_at", "auth_time"}


async def _session(engine, user: uuid.UUID, **extra) -> uuid.UUID:
    sid = uuid.uuid4()
    await _insert(engine, "user_sessions", id=sid, user_id=user, token_hash=uuid.uuid4().hex * 2, csrf_token="c",
                  expires_at=NOW + timedelta(hours=96), last_seen_at=NOW, **extra)
    return sid


async def test_migration_0016_round_trip(migration_url):  # noqa: F811
    url = migration_url
    _ok(url, "upgrade", "0015")
    engine = create_async_engine(url)
    try:
        user = uuid.uuid4()
        await _insert(engine, "users", id=user, email="a@example.com", full_name="A", is_active=True)
        await _session(engine, user)
        _ok(url, "upgrade", "0016")
        columns = await _inspect(engine, lambda i: {c["name"] for c in i.get_columns("user_sessions")})
        assert NEW <= columns
        assert [r[0] for r in await _rows(engine, "SELECT auth_source FROM user_sessions")] == ["local"]

        await _session(engine, user, auth_source="oidc", idp_sid="kc-session")
        _ok(url, "downgrade", "0015")
        assert not NEW & await _inspect(engine, lambda i: {c["name"] for c in i.get_columns("user_sessions")})
        assert len(await _rows(engine, "SELECT id FROM user_sessions")) == 1  # the HackSpaceLabs session ended

        _ok(url, "upgrade", "head")
        _ok(url, "check")
    finally:
        await engine.dispose()
