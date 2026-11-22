"""Migration 0011 (phase 4 test 20): the environment placement and production columns, host-less data
owners, backups stored on Slipway and the ``acme`` row; the round trip, and each downgrade refusal
(a live DigitalOcean environment, a DigitalOcean resource, a Slipway-stored backup, a host-less instance).

Runs on SQLite, and also on PostgreSQL when SLIPWAY_TEST_DATABASE_URL names one (a throwaway database).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from tests.test_migration_0009 import (  # noqa: F401
    _alembic,
    _insert,
    _inspect,
    _ok,
    _rows,
    _seed_0008,
    _table,
    _where,
    migration_url,
)

NOW = datetime(2026, 11, 18, 9, 0, tzinfo=UTC)
ENV_CHECKS = {f"ck_environments_{n}" for n in (
    "deleted", "data_mode", "provider_account", "do_managed", "production_do", "retiring", "production_auto")}


async def _version(engine: AsyncEngine) -> list[str]:
    return [r[0] for r in await _rows(engine, "SELECT version_num FROM alembic_version")]


async def _exec(engine: AsyncEngine, sql: str) -> None:
    async with engine.begin() as conn:
        await conn.execute(text(sql))


async def _acme(engine: AsyncEngine) -> list[tuple]:
    return [tuple(r) for r in await _rows(engine, "SELECT key, value, secret FROM app_settings WHERE key = 'acme'")]


def _refused(url: str, needle: str) -> None:
    done = _alembic(url, "downgrade", "0010")
    assert done.returncode != 0 and needle in done.stderr, done.stderr


async def test_migration_0011_round_trip(migration_url):  # noqa: F811
    url = migration_url
    _ok(url, "upgrade", "0008")
    engine = create_async_engine(url)
    try:
        ids = await _seed_0008(engine)
        backup = uuid.uuid4()
        await _insert(engine, "backups", id=backup, instance_id=ids["inst"], name="b1", reason="manual",
                      status="ready", format="pg_dump", db_bytes=10, identity_fp="x", taken_at=NOW)
        _ok(url, "upgrade", "0009")
        env = uuid.uuid4()
        await _insert(engine, "environments", id=env, name="uat", repository_id=ids["repo"], branch="main",
                      data_mode="server")
        _ok(url, "upgrade", "0011")
        assert await _version(engine) == ["0011"]

        # Existing rows: an SSH environment, a backup on its host, the acme row inserted empty.
        rows = await _rows(engine, "SELECT provider, provider_account_id, production, retiring_at FROM environments")
        assert [(r[0], r[1], bool(r[2]), r[3]) for r in rows] == [("ssh", None, False, None)]
        assert [tuple(r) for r in await _rows(engine, "SELECT location, data_key, stored_bytes FROM backups")] == [
            ("host", None, None)]
        assert await _acme(engine) in ([("acme", {}, None)], [("acme", "{}", None)])

        assert ENV_CHECKS <= {c["name"] for c in await _inspect(engine, lambda i: i.get_check_constraints("environments"))}
        assert "ck_instances_host" in {c["name"] for c in await _inspect(
            engine, lambda i: i.get_check_constraints("instances"))}
        assert "ck_backups_slipway_key" in {c["name"] for c in await _inspect(
            engine, lambda i: i.get_check_constraints("backups"))}
        indexes = await _inspect(engine, lambda i: {ix["name"]: ix for ix in i.get_indexes("environments")})
        one = indexes["ux_environments_one_production"]
        assert one["unique"] and one["column_names"] == ["repository_id", "manifest_file"]
        assert "production" in _where(one) and "retiring_at IS NULL" in _where(one)
        assert "deleted_at IS NULL" in _where(indexes["ux_environments_name_live"])  # kept through the batch
        columns = await _inspect(engine, lambda i: {c["name"]: c for c in i.get_columns("instances")})
        assert columns["host_id"]["nullable"]
        fks = await _inspect(engine, lambda i: {fk["name"]: fk for fk in i.get_foreign_keys("environments")})
        assert fks["fk_environments_provider_account_id_provider_accounts"]["options"]["ondelete"].upper() == "RESTRICT"
        assert fks["fk_environments_retired_by_id_users"]["options"]["ondelete"].upper() == "SET NULL"

        # The checks hold on the migrated tables.
        with pytest.raises(IntegrityError):
            await _insert(engine, "environments", id=uuid.uuid4(), name="x1", repository_id=ids["repo"],
                          branch="main", data_mode="managed", provider="digitalocean")
        with pytest.raises(IntegrityError):
            await _insert(engine, "environments", id=uuid.uuid4(), name="x2", repository_id=ids["repo"],
                          branch="main", data_mode="server", production=True)
        with pytest.raises(IntegrityError):
            await _insert(engine, "instances", id=uuid.uuid4(), name="x", slug="x", repository_id=ids["repo"],
                          branch="main", build_source="app", dockerfile_path="Dockerfile", build_context=".",
                          compose_file="docker-compose.yml", ports=[], volumes=[], status="created")
        with pytest.raises(IntegrityError):
            await _exec(engine, "UPDATE backups SET location = 'slipway'")

        # A DigitalOcean account and a live environment on it: the downgrade refuses, changing nothing.
        account, cloud = uuid.uuid4(), uuid.uuid4()
        await _insert(engine, "provider_accounts", id=account, provider="digitalocean", name="DO")
        await _insert(engine, "environments", id=cloud, name="cloud", repository_id=ids["repo"], branch="main",
                      data_mode="managed", provider="digitalocean", provider_account_id=account, production=True)
        objects = "Slipway still manages DigitalOcean objects for {}: delete those environments first"
        _refused(url, objects.format("cloud"))
        assert await _version(engine) == ["0011"]

        # Deleted, it still names its environment while a DigitalOcean resource is recorded.
        envs = _table("environments", id=cloud, status="deleted", deleted_at=NOW)
        async with engine.begin() as conn:
            await conn.execute(envs.update().where(envs.c.id == cloud).values(status="deleted", deleted_at=NOW))
        await _insert(engine, "resources", id=uuid.uuid4(), environment_id=cloud, provider="digitalocean",
                      kind="droplet", provider_id="101", name="slipway-cloud-blue", origin="created", details={},
                      tags=[])
        _refused(url, objects.format("cloud"))
        await _exec(engine, "DELETE FROM resources")

        # A backup stored on this Slipway server.
        await _exec(engine, "UPDATE backups SET location = 'slipway', status = 'pending'")
        _refused(url, "1 backups are stored on this Slipway server; delete them first")
        await _exec(engine, "UPDATE backups SET location = 'host', status = 'ready'")

        # A data owner without a host.
        owner = uuid.uuid4()
        await _insert(engine, "instances", id=owner, name="uat data", slug="uat-data", repository_id=ids["repo"],
                      branch="main", build_source="app", dockerfile_path="Dockerfile", build_context=".",
                      compose_file="docker-compose.yml", ports=[], volumes=[], status="created", environment_id=env,
                      slot="data")
        _refused(url, objects.format("uat"))
        assert await _version(engine) == ["0011"]
        await _exec(engine, "DELETE FROM instances WHERE host_id IS NULL")

        # Jobs of the new kinds go with the revision; others stay.
        cert, retry = uuid.uuid4(), uuid.uuid4()
        await _insert(engine, "deployments", id=cert, environment_id=cloud, status="succeeded", branch="main",
                      log="", steps=[], kind="certificate", options={})
        await _insert(engine, "deployments", id=retry, environment_id=cloud, status="failed", branch="main",
                      log="", steps=[], kind="teardown", options={}, retry_of_id=cert)

        _ok(url, "downgrade", "0010")
        assert await _acme(engine) == []
        env_columns = await _inspect(engine, lambda i: {c["name"] for c in i.get_columns("environments")})
        assert not {"provider", "provider_account_id", "provider_team", "cloud", "production", "retiring_at",
                    "retired_by_id"} & env_columns
        assert not {"location", "data_key", "stored_bytes"} & await _inspect(
            engine, lambda i: {c["name"] for c in i.get_columns("backups")})
        columns = await _inspect(engine, lambda i: {c["name"]: c for c in i.get_columns("instances")})
        assert not columns["host_id"]["nullable"]
        assert "ux_environments_one_production" not in await _inspect(
            engine, lambda i: {ix["name"] for ix in i.get_indexes("environments")})
        kinds = sorted(r[0] for r in await _rows(engine, "SELECT kind FROM deployments"))
        assert kinds == ["deploy", "teardown"]
        assert [r[0] for r in await _rows(engine, "SELECT retry_of_id FROM deployments WHERE kind = 'teardown'")] == [
            None]

        # An acme row already there (put back by hand, say) is kept as it is on the way up.
        await _insert(engine, "app_settings", id=uuid.uuid4(), key="acme", value={"accounts": {"x": {"kid": "k"}}})
        _ok(url, "upgrade", "0011")
        assert await _acme(engine) in ([("acme", {"accounts": {"x": {"kid": "k"}}}, None)],
                                       [("acme", '{"accounts": {"x": {"kid": "k"}}}', None)])
    finally:
        await engine.dispose()
