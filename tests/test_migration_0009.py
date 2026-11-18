"""Phase 3 schema (tests 6, 7, 9, 10 and 11): migration 0009, the environment constraints, the new
permissions, host labels and LAN addresses, and rotate-encryption-key over environment secrets.

Test 6 runs on SQLite, and also on PostgreSQL when SLIPWAY_TEST_DATABASE_URL names one: it then makes a
throwaway database next to the test database and drops it afterwards.
"""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import sqlalchemy as sa
from cryptography.fernet import Fernet
from sqlalchemy import select, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from slipway import cli
from slipway.core.config import get_settings
from slipway.core.crypto import reset_crypto_cache
from slipway.core.permissions import SYSTEM_ROLES, has_permission
from slipway.db.session import get_sessionmaker
from slipway.models import (
    Deployment,
    DeploymentKind,
    DeploymentStatus,
    Environment,
    EnvironmentStatus,
    Host,
    Instance,
    Repository,
    Resource,
    Role,
)
from slipway.services.users import bootstrap

ROOT = Path(__file__).resolve().parents[1]
JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


# ------------------------------------------------------------------ test 6: migration 0009


def _alembic(url: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "SLIPWAY_DATABASE_URL": url, "SLIPWAY_ENV_FILE": "", "PYTHONPATH": str(ROOT)}
    return subprocess.run([sys.executable, "-m", "alembic", *args], cwd=ROOT, env=env, capture_output=True, text=True)


def _ok(url: str, *args: str) -> None:
    done = _alembic(url, *args)
    assert done.returncode == 0, (args, done.stderr)


def _pg_url() -> str | None:
    url = os.environ.get("SLIPWAY_TEST_DATABASE_URL", "")
    return url if url.startswith("postgresql") else None


@pytest.fixture(params=["sqlite", "postgresql"])
async def migration_url(request, tmp_path) -> AsyncIterator[str]:
    """An empty database for alembic to build: a SQLite file, or a throwaway PostgreSQL database."""
    if request.param == "sqlite":
        yield f"sqlite+aiosqlite:///{tmp_path}/m.db"
        return
    base = _pg_url()
    if base is None:
        pytest.skip("SLIPWAY_TEST_DATABASE_URL does not name a PostgreSQL database")
    name = f"slipway_m9_{uuid.uuid4().hex[:12]}"
    admin = create_async_engine(base, isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text(f'CREATE DATABASE "{name}"'))
    try:
        yield make_url(base).set(database=name).render_as_string(hide_password=False)
    finally:
        async with admin.connect() as conn:
            await conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        await admin.dispose()


def _table(table: str, **values: object) -> sa.TableClause:
    """A lightweight table for the columns in ``values``, typed so UUIDs, JSON and times bind on both backends."""
    def kind(value: object) -> sa.types.TypeEngine:
        if isinstance(value, uuid.UUID):
            return sa.Uuid()
        if isinstance(value, dict | list):
            return JSON
        if isinstance(value, datetime):
            return sa.DateTime(timezone=True)
        if isinstance(value, bool):
            return sa.Boolean()
        if isinstance(value, int):
            return sa.Integer()
        return sa.String()

    return sa.table(table, *(sa.column(k, kind(v)) for k, v in values.items()))


async def _insert(engine: AsyncEngine, table: str, **values: object) -> None:
    async with engine.begin() as conn:
        await conn.execute(_table(table, **values).insert().values(**values))


async def _rows(engine: AsyncEngine, sql: str) -> list[sa.Row]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql))).all())


async def _seed_0008(engine: AsyncEngine) -> dict[str, uuid.UUID]:
    """A labelled host, a repository, an instance and a finished job, as stored at revision 0008."""
    ids = {k: uuid.uuid4() for k in ("host", "repo", "inst", "job")}
    await _insert(engine, "hosts", id=ids["host"], name="h", hostname="10.0.0.1", port=22, username="deploy",
                  environment="prod", description="", deploy_root="/opt/slipway", auth_method="key",
                  status="healthy", metrics={})
    await _insert(engine, "repositories", id=ids["repo"], github_id=1, full_name="acme/web", owner="acme", name="web",
                  description="", visibility="private", default_branch="main", html_url="https://github.com/acme/web",
                  archived=False, detected_config={})
    await _insert(engine, "instances", id=ids["inst"], name="web", slug="web", repository_id=ids["repo"],
                  host_id=ids["host"], branch="main", build_source="app", dockerfile_path="Dockerfile",
                  build_context=".", compose_file="docker-compose.yml", ports=[], volumes=[], status="running")
    await _insert(engine, "deployments", id=ids["job"], instance_id=ids["inst"], status="succeeded", branch="main",
                  log="", steps=[])
    return ids


def _where(index: dict) -> str:
    options = index.get("dialect_options", {})
    clause = options.get("postgresql_where", options.get("sqlite_where"))
    return str(clause) if clause is not None else ""


async def _inspect(engine: AsyncEngine, fn):
    async with engine.connect() as conn:
        return await conn.run_sync(lambda sync: fn(sa.inspect(sync)))


async def test_migration_0009_upgrade_downgrade_round_trip(migration_url):
    url = migration_url
    _ok(url, "upgrade", "0008")
    engine = create_async_engine(url)
    try:
        ids = await _seed_0008(engine)
        _ok(url, "upgrade", "head")

        # Host labels carry over; every existing host is an SSH host.
        assert [tuple(r) for r in await _rows(engine, "SELECT label, provider, lan_address FROM hosts")] == [
            ("prod", "ssh", None)
        ]
        host_columns = await _inspect(engine, lambda i: {c["name"] for c in i.get_columns("hosts")})
        assert "environment" not in host_columns
        assert {"label", "provider", "provider_id", "lan_address", "owner_environment_id"} <= host_columns
        assert await _inspect(engine, lambda i: i.has_table("environments") and i.has_table("resources"))

        # The partial unique indexes: both new ones, and phase 2's keeps its WHERE.
        indexes = await _inspect(engine, lambda i: {ix["name"]: ix for ix in i.get_indexes("deployments")})
        for name, column, needle in (
            ("ux_deployments_one_active", "instance_id", "queued"),
            ("ux_deployments_one_active_env", "environment_id", "<> 'activate'"),
            ("ux_deployments_one_active_activate", "environment_id", "= 'activate'"),
        ):
            assert indexes[name]["unique"] and indexes[name]["column_names"] == [column], name
            assert needle in _where(indexes[name]) and "running" in _where(indexes[name]), name
        # instance_id is nullable now and its foreign key still cascades.
        columns = await _inspect(engine, lambda i: {c["name"]: c for c in i.get_columns("deployments")})
        assert columns["instance_id"]["nullable"] and columns["environment_id"]["nullable"]
        fks = await _inspect(engine, lambda i: {fk["name"]: fk for fk in i.get_foreign_keys("deployments")})
        assert fks["fk_deployments_instance_id_instances"]["options"]["ondelete"].upper() == "CASCADE"
        assert fks["fk_deployments_environment_id_environments"]["options"]["ondelete"].upper() == "SET NULL"
        _ok(url, "check")  # the migration matches the models exactly

        # The downgrade refuses while an environment is live, and changes nothing.
        env_id, env_job, retry = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        await _insert(engine, "environments", id=env_id, name="uat", repository_id=ids["repo"], branch="main",
                      data_mode="server")
        refused = _alembic(url, "downgrade", "0008")
        assert refused.returncode != 0
        assert "Delete every environment before downgrading below 0009 (still here: uat)" in refused.stderr
        assert [r[0] for r in await _rows(engine, "SELECT version_num FROM alembic_version")] == ["0009"]

        # Deleted, with an environment-level job (and a job that retried it) and a member job.
        now = datetime.now(UTC)
        environments = _table("environments", id=env_id, status="deleted", deleted_at=now)
        async with engine.begin() as conn:
            await conn.execute(environments.update().where(environments.c.id == env_id)
                               .values(status="deleted", deleted_at=now))
        await _insert(engine, "deployments", id=env_job, environment_id=env_id, status="succeeded", branch="main",
                      log="", steps=[], kind="teardown", options={})
        await _insert(engine, "deployments", id=retry, instance_id=ids["inst"], environment_id=env_id,
                      retry_of_id=env_job, status="failed", branch="main", log="", steps=[], kind="deploy", options={})
        await _insert(engine, "resources", id=uuid.uuid4(), environment_id=env_id, provider="switchyard",
                      kind="proxy_host", provider_id="12", name="uat.example.com", origin="created", details={},
                      tags=[])
        refused = _alembic(url, "downgrade", "0008")
        assert refused.returncode != 0
        assert "resources still lists 1 objects Slipway made; delete their environments first" in refused.stderr
        async with engine.begin() as conn:
            await conn.execute(text("DELETE FROM resources"))

        _ok(url, "downgrade", "0008")
        assert not await _inspect(engine, lambda i: i.has_table("environments") or i.has_table("resources"))
        assert [tuple(r) for r in await _rows(engine, "SELECT environment FROM hosts")] == [("prod",)]
        deps = {r[0] if isinstance(r[0], uuid.UUID) else uuid.UUID(r[0]): r[1]
                for r in await _rows(engine, "SELECT id, retry_of_id FROM deployments")}
        assert deps == {ids["job"]: None, retry: None}  # the environment-level job went, the member job stayed
        columns = await _inspect(engine, lambda i: {c["name"]: c for c in i.get_columns("deployments")})
        assert not columns["instance_id"]["nullable"] and "environment_id" not in columns
        assert not {"environment_id", "slot", "slot_state"} & await _inspect(
            engine, lambda i: {c["name"] for c in i.get_columns("instances")}
        )
        indexes = await _inspect(engine, lambda i: {ix["name"]: ix for ix in i.get_indexes("deployments")})
        assert "queued" in _where(indexes["ux_deployments_one_active"])
        assert not {"ux_deployments_one_active_env", "ux_deployments_one_active_activate"} & set(indexes)

        _ok(url, "upgrade", "head")
        _ok(url, "check")
        assert [tuple(r) for r in await _rows(engine, "SELECT label FROM hosts")] == [("prod",)]
    finally:
        await engine.dispose()


# ------------------------------------------------------------------ test 7: constraints


async def _base() -> dict[str, uuid.UUID]:
    async with get_sessionmaker()() as db:
        host = Host(name="h", hostname="10.0.0.11", username="deploy")
        repo = Repository(github_id=1, full_name="acme/web", owner="acme", name="web", html_url="https://github.com/acme/web")
        db.add_all([host, repo])
        await db.flush()
        env = Environment(name="uat", repository_id=repo.id, branch="main", data_mode="server")
        db.add(env)
        await db.flush()
        alone = Instance(name="web", slug="web", repository_id=repo.id, host_id=host.id, branch="main")
        blue = Instance(name="uat blue", slug="uat-blue", repository_id=repo.id, host_id=host.id, branch="main",
                        build_source="app", environment_id=env.id, slot="blue")
        db.add_all([alone, blue])
        await db.commit()
        return {"host": host.id, "repo": repo.id, "env": env.id, "alone": alone.id, "blue": blue.id}


async def _fails(*rows) -> None:
    async with get_sessionmaker()() as db:
        db.add_all(rows)
        with pytest.raises(IntegrityError):
            await db.commit()


async def _adds(*rows) -> None:
    async with get_sessionmaker()() as db:
        db.add_all(rows)
        await db.commit()


def _job(**kw) -> Deployment:
    return Deployment(branch="main", **{"status": DeploymentStatus.QUEUED, **kw})


async def test_environment_constraints():
    ids = await _base()

    def inst(slug: str, **kw) -> Instance:
        return Instance(name=slug, slug=slug, repository_id=ids["repo"], host_id=ids["host"], branch="main", **kw)

    # ck_instances_slot_pair: a slot only inside an environment, and an environment member always has one.
    await _fails(inst("x1", environment_id=ids["env"]))
    await _fails(inst("x2", slot="green"))
    # uq_instances_environment_id_slot: one instance per slot.
    await _fails(inst("uat-blue-2", environment_id=ids["env"], slot="blue"))
    await _adds(inst("uat-green", environment_id=ids["env"], slot="green"))
    # ck_deployments_subject: a job is about an instance, an environment or both.
    await _fails(_job(status=DeploymentStatus.SUCCEEDED))

    # One job at a time per environment besides activate, and one activate.
    await _adds(_job(instance_id=ids["blue"], environment_id=ids["env"]))
    await _fails(_job(environment_id=ids["env"], kind=DeploymentKind.PUBLISH))
    await _fails(_job(environment_id=ids["env"], kind=DeploymentKind.TEARDOWN, status=DeploymentStatus.RUNNING))
    await _adds(_job(environment_id=ids["env"], kind=DeploymentKind.ACTIVATE))
    await _fails(_job(environment_id=ids["env"], kind=DeploymentKind.ACTIVATE, status=DeploymentStatus.RUNNING))
    # Finished jobs never count.
    await _adds(*(_job(environment_id=ids["env"], kind=k, status=DeploymentStatus.SUCCEEDED)
                  for k in (DeploymentKind.ACTIVATE, DeploymentKind.PUBLISH, DeploymentKind.ACTIVATE)))

    # A standalone instance's jobs carry no environment, so the environment indexes never see them;
    # phase 2's one-job-per-instance index still holds.
    await _adds(_job(instance_id=ids["alone"]))
    await _fails(_job(instance_id=ids["alone"], kind=DeploymentKind.BACKUP))
    async with get_sessionmaker()() as db:
        other = inst("other")
        db.add(other)
        await db.flush()
        db.add(_job(instance_id=other.id))
        await db.commit()
        active = await db.scalar(select(sa.func.count()).select_from(Deployment).where(
            Deployment.status.in_([DeploymentStatus.QUEUED, DeploymentStatus.RUNNING]),
            Deployment.environment_id.is_(None),
        ))
        assert active == 2

    # An environment-level job loads with no instance; a member's job sees its environment.
    async with get_sessionmaker()() as db:
        env_job = await db.scalar(select(Deployment).where(Deployment.kind == DeploymentKind.ACTIVATE,
                                                           Deployment.status == DeploymentStatus.QUEUED))
        assert env_job.instance is None and env_job.environment.name == "uat"
        blue = await db.get(Instance, ids["blue"])
        assert blue.environment.name == "uat" and blue.slot_state == {}
        assert (await db.get(Instance, ids["alone"])).environment is None
        env = await db.get(Environment, ids["env"])
        assert (env.status, env.traffic, env.secrets_version, env.manifest_file) == (
            EnvironmentStatus.NEW, {"switch": "none", "dns": None}, 0, "slipway.yml")

    # ck_environments_deleted and the live-name index: a deleted environment frees its name.
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, ids["env"])
        env.status = EnvironmentStatus.DELETED
        with pytest.raises(IntegrityError):
            await db.commit()
    await _fails(Environment(name="uat", repository_id=ids["repo"], branch="main", data_mode="slot"))
    await _fails(Environment(name="odd", repository_id=ids["repo"], branch="main", data_mode="cloud"))
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, ids["env"])
        env.status, env.deleted_at = EnvironmentStatus.DELETED, datetime.now(UTC)
        await db.commit()
    await _adds(Environment(name="uat", repository_id=ids["repo"], branch="main", data_mode="slot"))


# ------------------------------------------------------------------ test 9: roles


ENV_PERMS = ["environments:read", "environments:write", "environments:delete", "traffic:switch"]
EXPECTED = {
    "viewer": ["environments:read"],
    "developer": ["environments:read", "traffic:switch"],
    "maintainer": ENV_PERMS,
    "admin": ENV_PERMS,
}


async def _granted() -> dict[str, list[str]]:
    async with get_sessionmaker()() as db:
        roles = {r.name: set(r.permissions) for r in (await db.scalars(select(Role))).all()}
    return {name: [p for p in ENV_PERMS if has_permission(roles[name], p)] for name in EXPECTED}


async def test_roles_hold_the_environment_permissions_fresh_and_after_a_resync():
    assert {name: [p for p in ENV_PERMS if has_permission({str(x) for x in SYSTEM_ROLES[name]["permissions"]}, p)]
            for name in EXPECTED} == EXPECTED
    assert await _granted() == EXPECTED  # a fresh install (conftest bootstraps)

    # An install bootstrapped before phase 3: its roles lack the new permissions until the next start.
    async with get_sessionmaker()() as db:
        for role in (await db.scalars(select(Role))).all():
            if role.name != "admin":
                role.permissions = [p for p in role.permissions if p not in ENV_PERMS]
        await db.commit()
    assert (await _granted())["developer"] == []
    async with get_sessionmaker()() as db:
        await bootstrap(db)
        await db.commit()
    assert await _granted() == EXPECTED


# ------------------------------------------------------------------ test 10: hosts API


async def test_hosts_api_label_alias_and_lan_address(admin_client):
    base = {"hostname": "10.0.0.11", "username": "deploy"}
    by_label = await admin_client.post("/api/v1/hosts", json={**base, "name": "a", "label": "prod"})
    by_env = await admin_client.post("/api/v1/hosts", json={**base, "name": "b", "environment": "staging"})
    assert by_label.status_code == by_env.status_code == 201, (by_label.text, by_env.text)
    assert (by_label.json()["label"], by_label.json()["environment"]) == ("prod", "prod")
    assert (by_env.json()["label"], by_env.json()["environment"]) == ("staging", "staging")
    assert by_label.json()["provider"] == "ssh" and by_label.json()["provider_id"] is None
    assert by_label.json()["lan_address"] is None and by_label.json()["owner_environment_id"] is None

    url = f"/api/v1/hosts/{by_label.json()['id']}"
    r = await admin_client.patch(url, json={"environment": "dev"})
    assert r.status_code == 200 and (r.json()["label"], r.json()["environment"]) == ("dev", "dev")
    r = await admin_client.patch(url, json={"label": "qa", "environment": "qa"})
    assert r.status_code == 200 and r.json()["label"] == "qa"
    r = await admin_client.patch(url, json={"label": "qa", "environment": "prod"})
    assert r.status_code == 422 and "not both" in r.text

    # lan_address: an IP literal (normalised), "" clears it.
    for bad in ("lan.example.com", "10.0.0", "10.0.0.300", "10.0.0.1/24"):
        r = await admin_client.patch(url, json={"lan_address": bad})
        assert r.status_code == 422 and "Enter an IP address" in r.text, bad
    r = await admin_client.post("/api/v1/hosts", json={**base, "name": "c", "lan_address": "nope"})
    assert r.status_code == 422
    r = await admin_client.patch(url, json={"lan_address": "192.168.1.20"})
    assert r.status_code == 200 and r.json()["lan_address"] == "192.168.1.20"
    r = await admin_client.patch(url, json={"lan_address": "FD00::0001"})
    assert r.status_code == 200 and r.json()["lan_address"] == "fd00::1"
    async with get_sessionmaker()() as db:
        host = await db.get(Host, uuid.UUID(r.json()["id"]))
        assert host.label == "qa" and host.client_address == "fd00::1"
    r = await admin_client.patch(url, json={"lan_address": ""})
    assert r.status_code == 200 and r.json()["lan_address"] is None

    # client_address is lan_address or upstream_address (the proxy address, else the hostname).
    host = Host(name="x", hostname="h.example.com", username="deploy")
    assert host.client_address == "h.example.com"
    host.proxy_address = "10.0.0.5"
    assert host.client_address == "10.0.0.5"
    host.lan_address = "10.1.0.5"
    assert (host.client_address, host.upstream_address) == ("10.1.0.5", "10.0.0.5")

    # The pages show the label and the LAN address field.
    page = (await admin_client.get("/hosts")).text
    assert "<th>Label</th>" in page and '<span class="chip">qa</span>' in page
    detail = (await admin_client.get(url.replace("/api/v1", ""))).text
    assert 'name="label"' in detail and 'name="lan_address"' in detail and 'name="environment"' not in detail


# ------------------------------------------------------------------ test 11: rotate-encryption-key


K1, K2, K3 = (Fernet.generate_key().decode() for _ in range(3))


@pytest.fixture
def encryption_key():
    saved = os.environ.get("SLIPWAY_ENCRYPTION_KEY")

    def apply(value: str) -> None:
        os.environ["SLIPWAY_ENCRYPTION_KEY"] = value
        get_settings.cache_clear()
        reset_crypto_cache()

    yield apply
    if saved is None:
        os.environ.pop("SLIPWAY_ENCRYPTION_KEY", None)
    else:
        os.environ["SLIPWAY_ENCRYPTION_KEY"] = saved
    get_settings.cache_clear()
    reset_crypto_cache()


async def _raw(sql: str) -> str | None:
    async with get_sessionmaker()() as db:
        return await db.scalar(text(sql))


async def test_rotate_reencrypts_environment_secrets_and_resource_credentials(encryption_key):
    encryption_key(K1)
    ids = await _base()
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, ids["env"])
        env.app_secrets, env.env = {"SS_JWT_SECRET": "jwt-1"}, {"APP_MODE": "uat"}
        db.add(Resource(environment_id=env.id, provider="digitalocean", kind="spaces_key", provider_id="k1",
                        name="uat-spaces", origin="created", credentials={"secret": "s3-1"}))
        await db.commit()

    encryption_key(f"{K2},{K1}")
    async with get_sessionmaker()() as db:
        rotated, unreadable = await cli._rotate_secrets(db)
        await db.commit()
    assert rotated == 3 and unreadable == []
    encryption_key(K2)  # the old key is gone: everything reads under the new one alone
    for column, plain in (("app_secrets", b'{"SS_JWT_SECRET": "jwt-1"}'), ("env", b'{"APP_MODE": "uat"}')):
        raw = await _raw(f"SELECT {column} FROM environments")
        assert Fernet(K2.encode()).decrypt(raw.encode()) == plain
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, ids["env"])
        assert (env.app_secrets, env.env) == ({"SS_JWT_SECRET": "jwt-1"}, {"APP_MODE": "uat"})
        assert (await db.scalar(select(Resource))).credentials == {"secret": "s3-1"}

    # A key nobody has any more: --clear-unreadable leaves an encrypted null for the environment's secrets
    # and variables (they read as None, but the column isn't empty), and clears the resource credentials.
    encryption_key(K3)
    async with get_sessionmaker()() as db:
        rotated, unreadable = await cli._rotate_secrets(db, clear_unreadable=True)
        await db.commit()
    assert rotated == 0
    assert sorted(u.split(" ")[0] for u in unreadable) == [
        "environments.app_secrets", "environments.env", "resources.credentials",
    ]
    for column in ("app_secrets", "env"):
        raw = await _raw(f"SELECT {column} FROM environments")
        assert raw is not None and Fernet(K3.encode()).decrypt(raw.encode()) == b"null"
    assert await _raw("SELECT credentials FROM resources") is None
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, ids["env"])
        assert env.app_secrets is None and env.env is None
        secrets_cleared = await db.scalar(
            select(Environment.__table__.c.app_secrets.is_not(None)).where(Environment.id == env.id)
        )
        assert secrets_cleared  # what tells a member job the secrets were lost, not never made
