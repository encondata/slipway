"""Migration 0010 (phase 4 test 20, phase 5 test 1): provider_accounts and hosts.provider_state, the
round trip, and the downgrade's refusal while an account or a provider's host is recorded.

Runs on SQLite, and also on PostgreSQL when SLIPWAY_TEST_DATABASE_URL names one (a throwaway database).
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from tests.test_migration_0009 import _alembic, _insert, _inspect, _ok, _rows, _seed_0008, migration_url  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = ROOT / "alembic" / "versions"
REFUSED = "Remove the DigitalOcean, Proxmox and ESXi accounts first"


async def _version(engine: AsyncEngine) -> list[str]:
    return [r[0] for r in await _rows(engine, "SELECT version_num FROM alembic_version")]


async def _check_names(engine: AsyncEngine, table: str) -> set[str]:
    return {c["name"] for c in await _inspect(engine, lambda i: i.get_check_constraints(table))}


async def test_migration_0010_round_trip(migration_url):  # noqa: F811
    url = migration_url
    _ok(url, "upgrade", "0008")
    engine = create_async_engine(url)
    try:
        ids = await _seed_0008(engine)
        _ok(url, "upgrade", "0010")
        assert await _version(engine) == ["0010"]

        # The existing host is an SSH host with an empty provider state.
        assert [tuple(r) for r in await _rows(engine, "SELECT provider, provider_state FROM hosts")] in (
            [("ssh", "{}")], [("ssh", {})])
        columns = await _inspect(engine, lambda i: {c["name"]: c for c in i.get_columns("provider_accounts")})
        assert set(columns) == {
            "id", "created_at", "updated_at", "provider", "name", "production", "secret", "secret_hint", "config",
            "tls", "status", "checks", "facts", "last_checked_at", "removed_at", "created_by_id", "updated_by_id",
        }
        assert columns["secret"]["nullable"] and columns["tls"]["nullable"] and not columns["config"]["nullable"]
        assert await _check_names(engine, "provider_accounts") == {
            "ck_provider_accounts_provider", "ck_provider_accounts_production_do"}
        uniques = await _inspect(engine, lambda i: i.get_unique_constraints("provider_accounts"))
        assert [(u["name"], u["column_names"]) for u in uniques] == [("uq_provider_accounts_name", ["name"])]
        fks = await _inspect(engine, lambda i: {fk["name"]: fk for fk in i.get_foreign_keys("provider_accounts")})
        assert {name: fk["options"]["ondelete"].upper() for name, fk in fks.items()} == {
            "fk_provider_accounts_created_by_id_users": "SET NULL",
            "fk_provider_accounts_updated_by_id_users": "SET NULL",
        }

        # Defaults and checks as written by the migration.
        account = uuid.uuid4()
        await _insert(engine, "provider_accounts", id=account, provider="proxmox", name="Lab")
        assert [tuple(r) for r in await _rows(
            engine, "SELECT status, secret_hint, production, secret FROM provider_accounts")] in (
            [("unknown", "", False, None)], [("unknown", "", 0, None)])
        for bad in ({"provider": "aws", "name": "x1"}, {"provider": "esxi", "name": "x2", "production": True},
                    {"provider": "esxi", "name": "Lab"}):
            with pytest.raises(IntegrityError):
                await _insert(engine, "provider_accounts", id=uuid.uuid4(), **bad)

        # The downgrade refuses while an account is recorded, and changes nothing...
        refused = _alembic(url, "downgrade", "0009")
        assert refused.returncode != 0 and REFUSED in refused.stderr
        assert await _version(engine) == ["0010"]
        async with engine.begin() as conn:
            await conn.execute(text("DELETE FROM provider_accounts"))
            # ...or while a host a provider made is.
            await conn.execute(text("UPDATE hosts SET provider = 'esxi'"))
        refused = _alembic(url, "downgrade", "0009")
        assert refused.returncode != 0 and REFUSED in refused.stderr
        assert await _version(engine) == ["0010"]
        async with engine.begin() as conn:
            await conn.execute(text("UPDATE hosts SET provider = 'ssh'"))

        _ok(url, "downgrade", "0009")
        assert not await _inspect(engine, lambda i: i.has_table("provider_accounts"))
        assert "provider_state" not in await _inspect(engine, lambda i: {c["name"] for c in i.get_columns("hosts")})
        assert [tuple(r) for r in await _rows(engine, "SELECT name, label FROM hosts")] == [("h", "prod")]

        _ok(url, "upgrade", "0010")
        assert len(await _rows(engine, "SELECT id FROM hosts")) == 1 and ids
    finally:
        await engine.dispose()


def test_provider_migrations_are_unconditional_and_linear():
    """None of the three inspects the database to decide what to create; they form one line from 0009."""
    files = {rev: next(VERSIONS.glob(f"20261118_{rev}_*.py")) for rev in ("0010", "0011", "0012")}
    assert [p.name for p in files.values()] == [
        "20261118_0010_provider_accounts.py", "20261118_0011_digitalocean.py", "20261118_0012_machines.py"]
    for rev, path in files.items():
        source = path.read_text()
        for needle in ("inspect(", "has_table", "get_columns", "IF NOT EXISTS", "IF EXISTS"):
            assert needle not in source, (path.name, needle)
        assert f"revision: str = '{rev}'" in source
    assert "down_revision: str | None = '0009'" in files["0010"].read_text()
    assert "down_revision: str | None = '0010'" in files["0011"].read_text()
    assert "down_revision: str | None = '0011'" in files["0012"].read_text()
    heads = _alembic("sqlite+aiosqlite:///:memory:", "heads")
    assert heads.returncode == 0 and heads.stdout.split() == ["0012", "(head)"], heads.stdout
