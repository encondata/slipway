"""Migration 0012 (phase 5 test 1): machines, address_claims, terraform_states and machine_snapshots with
their NAMING_CONVENTION names; the round trip; the downgrade's refusal while a VM is recorded; and, at
head, ``alembic check``: the models equal the migrations.

Runs on SQLite, and also on PostgreSQL when SLIPWAY_TEST_DATABASE_URL names one (a throwaway database).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from tests.test_migration_0009 import _alembic, _insert, _inspect, _ok, _rows, _seed_0008, migration_url  # noqa: F401

NOW = datetime(2026, 11, 18, 9, 0, tzinfo=UTC)
TABLES = ("machines", "address_claims", "terraform_states", "machine_snapshots")


async def _version(engine: AsyncEngine) -> list[str]:
    return [r[0] for r in await _rows(engine, "SELECT version_num FROM alembic_version")]


async def _exec(engine: AsyncEngine, sql: str) -> None:
    async with engine.begin() as conn:
        await conn.execute(text(sql))


async def _names(engine: AsyncEngine, table: str) -> dict[str, set]:
    def read(i):
        return {
            "pk": {i.get_pk_constraint(table)["name"]},
            "uq": {(u["name"], tuple(u["column_names"])) for u in i.get_unique_constraints(table)},
            "ck": {c["name"] for c in i.get_check_constraints(table)},
            "fk": {(fk["name"], fk["options"].get("ondelete", "").upper()) for fk in i.get_foreign_keys(table)},
            "ix": {ix["name"] for ix in i.get_indexes(table) if not ix.get("unique")},
        }
    return await _inspect(engine, read)


async def test_migration_0012_round_trip_and_models_match(migration_url):  # noqa: F811
    url = migration_url
    _ok(url, "upgrade", "0008")
    engine = create_async_engine(url)
    try:
        ids = await _seed_0008(engine)
        _ok(url, "upgrade", "head")
        assert await _version(engine) == ["0012"]
        _ok(url, "check")  # the migrations, 0001 to 0012, match the models exactly

        machines = await _names(engine, "machines")
        assert machines["pk"] == {"pk_machines"}
        assert machines["uq"] == {("uq_machines_host_id", ("host_id",)),
                                  ("uq_machines_account_id", ("account_id", "name")),
                                  ("uq_machines_environment_id", ("environment_id", "slot"))}
        assert machines["ck"] == {"ck_machines_provider", "ck_machines_stage", "ck_machines_ready_at",
                                  "ck_machines_snapshot_mode"}
        assert machines["fk"] == {("fk_machines_environment_id_environments", "RESTRICT"),
                                  ("fk_machines_host_id_hosts", "RESTRICT"),
                                  ("fk_machines_account_id_provider_accounts", "RESTRICT"),
                                  ("fk_machines_created_by_id_users", "SET NULL")}
        assert machines["ix"] == {"ix_machines_environment_id"}
        claims = await _names(engine, "address_claims")
        assert claims["pk"] == {"pk_address_claims"}
        assert claims["uq"] == {("uq_address_claims_host_id", ("host_id",))}
        assert claims["fk"] == {("fk_address_claims_host_id_hosts", "CASCADE")}
        states = await _names(engine, "terraform_states")
        assert states["pk"] == {"pk_terraform_states"}
        assert states["fk"] == {("fk_terraform_states_machine_id_machines", "RESTRICT")}
        snaps = await _names(engine, "machine_snapshots")
        assert snaps["uq"] == {("uq_machine_snapshots_machine_id", ("machine_id", "name"))}
        assert snaps["fk"] == {("fk_machine_snapshots_machine_id_machines", "CASCADE"),
                               ("fk_machine_snapshots_deployment_id_deployments", "SET NULL"),
                               ("fk_machine_snapshots_created_by_id_users", "SET NULL")}
        assert snaps["ix"] == {"ix_machine_snapshots_machine_id"}

        # A Proxmox VM for an environment's blue slot.
        env, account, host, machine = (uuid.uuid4() for _ in range(4))
        await _insert(engine, "environments", id=env, name="lab", repository_id=ids["repo"], branch="main",
                      data_mode="slot")
        await _insert(engine, "provider_accounts", id=account, provider="proxmox", name="Lab")
        await _insert(engine, "hosts", id=host, name="slipway-lab-blue", hostname="192.168.1.50", port=22,
                      username="slipway", label="lab", description="", deploy_root="/opt/slipway", auth_method="key",
                      status="unknown", metrics={}, provider="proxmox", owner_environment_id=env,
                      provider_state={"phase": "planned"})
        values = dict(environment_id=env, host_id=host, account_id=account, provider="proxmox", slot="blue",
                      name="slipway-lab-blue", spec={"node": "pve1"}, network={"address": "192.168.1.50"},
                      size={"cores": 2, "memory_mb": 2048, "disk_gb": 20})
        with pytest.raises(IntegrityError):
            await _insert(engine, "machines", id=uuid.uuid4(), **{**values, "provider": "digitalocean"})
        await _insert(engine, "machines", id=machine, **values)
        await _insert(engine, "address_claims", address="192.168.1.50", host_id=host)
        with pytest.raises(IntegrityError):
            await _insert(engine, "address_claims", address="192.168.1.50", host_id=ids["host"])
        assert [tuple(r) for r in await _rows(engine, "SELECT stage, keep_vm_snapshots FROM machines")] == [
            ("planned", 3)]

        # The downgrade refuses while a VM is recorded, and changes nothing.
        done = _alembic(url, "downgrade", "0011")
        assert done.returncode != 0
        assert "Delete the environments with Proxmox or ESXi VMs first (still here: lab)" in done.stderr
        assert await _version(engine) == ["0012"]

        # Gone: the VM kinds' jobs go with the revision; others stay.
        await _exec(engine, "DELETE FROM address_claims")
        await _exec(engine, "DELETE FROM machines")
        snap_job, retry = uuid.uuid4(), uuid.uuid4()
        await _insert(engine, "deployments", id=snap_job, instance_id=ids["inst"], status="succeeded", branch="main",
                      log="", steps=[], kind="vm_snapshot", options={})
        await _insert(engine, "deployments", id=retry, instance_id=ids["inst"], status="failed", branch="main",
                      log="", steps=[], kind="deploy", options={}, retry_of_id=snap_job)
        _ok(url, "downgrade", "0011")
        assert not any([await _inspect(engine, lambda i, t=t: i.has_table(t)) for t in TABLES])
        assert sorted(r[0] for r in await _rows(engine, "SELECT kind FROM deployments")) == ["deploy", "deploy"]
        assert all(r[0] is None for r in await _rows(engine, "SELECT retry_of_id FROM deployments"))

        _ok(url, "upgrade", "head")
        _ok(url, "check")
    finally:
        await engine.dispose()


async def test_full_downgrade_to_0009_and_back(migration_url):  # noqa: F811
    """With nothing recorded, the three revisions go down and come back up in one run each way."""
    url = migration_url
    _ok(url, "upgrade", "0008")
    engine = create_async_engine(url)
    try:
        await _seed_0008(engine)
        _ok(url, "upgrade", "head")
        _ok(url, "downgrade", "0009")
        assert await _version(engine) == ["0009"]
        assert not await _inspect(engine, lambda i: i.has_table("provider_accounts"))
        _ok(url, "upgrade", "head")
        _ok(url, "check")
        assert len(await _rows(engine, "SELECT key FROM app_settings WHERE key = 'acme'")) == 1
    finally:
        await engine.dispose()
