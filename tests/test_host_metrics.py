"""Host history: disk use in the probe, samples on health checks, hourly rollup, retention and trends."""

from __future__ import annotations

import asyncio
import os
import sqlite3
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import asyncpg
import asyncssh
import pytest
from sqlalchemy import func, select
from sqlalchemy.engine import make_url

from slipway.db.session import get_sessionmaker
from slipway.models import Host, HostSample, HostSampleHourly
from slipway.services import host_metrics, hosts, ssh

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 17, 12, 30, tzinfo=UTC)
KEY = asyncssh.generate_private_key("ssh-ed25519").export_public_key("openssh").decode().strip()


def _probe_output(df: str | None = "/dev/sda1   102400000  45000000  57400000   44%  /var/lib/docker") -> str:
    parts = ["Ubuntu 24.04 LTS", "4", "1.00 0.50 0.25 1/200 1234",
             "MemTotal:        8000000 kB\nMemAvailable:    6000000 kB", "27.3.1\nrc=0", "3"]
    if df is not None:
        parts.append(df)
    return "\n::slipway::\n".join(parts) + "\n"


def _result(**kw) -> ssh.ProbeResult:
    fields = dict(host_key=KEY, fingerprint=ssh.fingerprint(KEY), os_info="Debian 13", cpus=2, cpu_percent=10,
                  mem_total_mb=4096, mem_percent=40, docker_version="27.0", docker_error=None, containers_running=2,
                  disk_percent=55.0)
    fields.update(kw)
    return ssh.ProbeResult(**fields)


async def _add_host(name: str, *, pinned: bool = True, metrics: dict | None = None) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        host = Host(name=name, hostname=f"{name}.example", username="deploy", deploy_root="/opt/slipway",
                    metrics=metrics or {"cpus": 4, "mem_total_mb": 8192, "cpu_percent": 5.0, "mem_percent": 20.0},
                    auth_method="password", password="pw", host_key=KEY if pinned else None,
                    host_key_fingerprint=ssh.fingerprint(KEY) if pinned else None)
        db.add(host)
        await db.commit()
        return host.id


async def _add_samples(host_id: uuid.UUID, samples: list[tuple[datetime, float, float, float | None]]) -> None:
    async with get_sessionmaker()() as db:
        for at, cpu, mem, disk in samples:
            host_metrics.record_sample(db, host_id, {"cpu_percent": cpu, "mem_percent": mem, "disk_percent": disk,
                                                     "containers_running": 1}, at=at)
        await db.commit()


async def _count(model) -> int:
    async with get_sessionmaker()() as db:
        return await db.scalar(select(func.count()).select_from(model))


async def _hourly() -> list[HostSampleHourly]:
    async with get_sessionmaker()() as db:
        return list((await db.scalars(select(HostSampleHourly).order_by(HostSampleHourly.hour))).all())


# ------------------------------------------------------------------ probe


def test_probe_reads_disk_use_of_the_docker_data_root():
    assert "DockerRootDir" in ssh.PROBE_COMMAND and "df -P" in ssh.PROBE_COMMAND
    result = ssh.parse_probe(_probe_output(), KEY)
    assert result.disk_percent == 44.0
    assert result.metrics["disk_percent"] == 44.0
    assert result.containers_running == 3 and result.cpus == 4  # the earlier fields are unchanged


@pytest.mark.parametrize("df", [
    None,  # an older probe without the disk part
    "",
    "df: /var/lib/docker: Permission denied",
    "Filesystem 1024-blocks Used Available Capacity Mounted on",
    "overlay 0 0 0 - /",
    "/dev/sda1 1 1 1 250% /",
    "x" * 5000,
])
def test_unreadable_disk_use_gives_none(df):
    result = ssh.parse_probe(_probe_output(df), KEY)
    assert result.disk_percent is None
    assert "disk_percent" not in result.metrics
    assert result.docker_version == "27.3.1"


def test_disk_use_with_spaces_in_the_mount_point():
    assert ssh.parse_probe(_probe_output("/dev/sdb1 100 7 93 7% /mnt/user/app data"), KEY).disk_percent == 7.0


def test_probe_result_without_disk_keeps_the_old_metrics():
    assert ssh.ProbeResult(host_key=KEY, fingerprint="x", os_info="", cpus=1, cpu_percent=0, mem_total_mb=0,
                           mem_percent=0, docker_version=None, docker_error=None, containers_running=0).metrics == {
        "cpus": 1, "cpu_percent": 0, "mem_total_mb": 0, "mem_percent": 0, "containers_running": 0,
    }


# ------------------------------------------------------------------ samples from health checks


async def test_manual_check_writes_a_sample(admin_client, monkeypatch):
    host = (await admin_client.post("/api/v1/hosts", json={"name": "a", "hostname": "10.0.0.5", "username": "deploy"})).json()

    async def probe(target):
        return _result(cpu_percent=12.34, mem_percent=56.78)

    monkeypatch.setattr(hosts.ssh, "probe", probe)
    assert (await admin_client.post(f"/api/v1/hosts/{host['id']}/check")).json()["status"] == "healthy"
    async with get_sessionmaker()() as db:
        sample = (await db.scalars(select(HostSample))).one()
    assert str(sample.host_id) == host["id"]
    assert (sample.cpu_percent, sample.mem_percent, sample.disk_percent, sample.containers_running) == (12.3, 56.8, 55.0, 2)
    assert sample.at.tzinfo is not None


async def test_failed_check_writes_no_sample(monkeypatch):
    host_id = await _add_host("a")

    async def probe(target):
        raise ssh.SSHError("Connection refused")

    monkeypatch.setattr(hosts.ssh, "probe", probe)
    await hosts.poll_once()
    async with get_sessionmaker()() as db:
        assert (await db.get(Host, host_id)).status == "unreachable"
    assert await _count(HostSample) == 0

    monkeypatch.setattr(hosts.ssh, "probe", lambda target: asyncio.sleep(0, _result(disk_percent=None)))
    await hosts.poll_once()
    async with get_sessionmaker()() as db:
        sample = (await db.scalars(select(HostSample))).one()
    assert sample.disk_percent is None


def test_record_sample_tolerates_odd_metrics():
    class FakeSession:
        def add(self, obj):
            self.added = obj

    db = FakeSession()
    sample = host_metrics.record_sample(db, uuid.uuid4(), {"cpu_percent": float("nan"), "mem_percent": "9",
                                                            "disk_percent": True, "containers_running": "3"})
    assert db.added is sample
    assert (sample.cpu_percent, sample.mem_percent, sample.disk_percent, sample.containers_running) == (0.0, 0.0, None, None)


async def test_deleting_a_host_deletes_its_history():
    host_id = await _add_host("a")
    await _add_samples(host_id, [(NOW - timedelta(hours=3), 10, 20, 30)])
    async with get_sessionmaker()() as db:
        await host_metrics.retention_once(db, now=NOW)
        await db.delete(await db.get(Host, host_id))
        await db.commit()
    assert await _count(HostSample) == 0 and await _count(HostSampleHourly) == 0


# ------------------------------------------------------------------ rollup and retention


async def test_rollup_averages_complete_hours_and_keeps_the_max():
    a, b = await _add_host("a"), await _add_host("b")
    await _add_samples(a, [
        (datetime(2026, 11, 17, 9, 5, tzinfo=UTC), 10, 40, 50),
        (datetime(2026, 11, 17, 9, 35, tzinfo=UTC), 30, 60, None),
        (datetime(2026, 11, 17, 9, 55, tzinfo=UTC), 20, 50, 52),
        (datetime(2026, 11, 17, 10, 10, tzinfo=UTC), 90, 90, 90),  # 10:00-11:00 ends 11:00, 1.5 hours ago
        (datetime(2026, 11, 17, 11, 10, tzinfo=UTC), 80, 80, 80),  # ended 30 minutes ago: not yet
        (datetime(2026, 11, 17, 12, 10, tzinfo=UTC), 70, 70, 70),  # the current hour: not yet
    ])
    await _add_samples(b, [(datetime(2026, 11, 17, 9, 15, tzinfo=UTC), 5, 6, None)])

    async with get_sessionmaker()() as db:
        assert await host_metrics.retention_once(db, now=NOW) == 3
    rows = await _hourly()
    by_key = {(row.host_id, row.hour.hour): row for row in rows}
    assert set(by_key) == {(a, 9), (a, 10), (b, 9)}
    nine = by_key[a, 9]
    assert (nine.cpu_avg, nine.cpu_max, nine.mem_avg, nine.mem_max, nine.disk_max, nine.samples) == (20, 30, 50, 60, 52, 3)
    assert nine.hour == datetime(2026, 11, 17, 9, tzinfo=UTC)
    assert by_key[b, 9].disk_max is None and by_key[b, 9].samples == 1
    assert await _count(HostSample) == 7  # nothing raw is old enough to delete

    async with get_sessionmaker()() as db:  # idempotent
        assert await host_metrics.retention_once(db, now=NOW) == 0
    assert len(await _hourly()) == 3

    async with get_sessionmaker()() as db:  # an hour later, 11:00-12:00 is due
        assert await host_metrics.retention_once(db, now=NOW + timedelta(hours=1)) == 1
    assert [row.hour.hour for row in await _hourly() if row.host_id == a] == [9, 10, 11]


async def test_rollup_never_rewrites_an_existing_hour():
    a = await _add_host("a")
    hour = datetime(2026, 11, 17, 8, tzinfo=UTC)
    async with get_sessionmaker()() as db:
        db.add(HostSampleHourly(host_id=a, hour=hour, cpu_avg=1, cpu_max=2, mem_avg=3, mem_max=4, disk_max=None, samples=9))
        await db.commit()
    await _add_samples(a, [(hour + timedelta(minutes=5), 50, 50, 50)])
    async with get_sessionmaker()() as db:
        assert await host_metrics.retention_once(db, now=NOW) == 0
    (row,) = await _hourly()
    assert (row.cpu_avg, row.samples) == (1, 9)


async def test_retention_deletes_old_rows():
    a = await _add_host("a")
    await _add_samples(a, [
        (NOW - timedelta(days=8, minutes=1), 10, 10, None),
        (NOW - timedelta(days=7, hours=23), 20, 20, None),
        (NOW - timedelta(hours=3), 30, 30, None),
    ])
    async with get_sessionmaker()() as db:
        for hour in (datetime(2025, 10, 1, tzinfo=UTC), NOW - timedelta(days=399)):
            db.add(HostSampleHourly(host_id=a, hour=floor(hour), cpu_avg=1, cpu_max=1, mem_avg=1, mem_max=1, samples=1))
        await db.commit()
    async with get_sessionmaker()() as db:
        await host_metrics.retention_once(db, now=NOW)
    async with get_sessionmaker()() as db:
        raw = sorted(s.cpu_percent for s in (await db.scalars(select(HostSample))).all())
    assert raw == [20, 30]
    hours = [row.hour for row in await _hourly()]
    assert datetime(2025, 10, 1, tzinfo=UTC) not in hours
    assert floor(NOW - timedelta(days=399)) in hours
    # The sample deleted for being over 8 days old was rolled up first.
    assert floor(NOW - timedelta(days=8, minutes=1)) in hours
    assert len(hours) == 4


def floor(at: datetime) -> datetime:
    return host_metrics.floor_hour(at)


async def test_retention_loop_is_off_when_the_interval_is_zero():
    await asyncio.wait_for(host_metrics.retention_forever(), timeout=1)


async def test_retention_loop_runs_and_survives_errors(monkeypatch):
    calls: list[int] = []

    async def once(db, now=None):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("boom")
        if len(calls) == 3:
            raise asyncio.CancelledError

    real_sleep = asyncio.sleep
    monkeypatch.setattr(host_metrics, "get_settings", lambda: type("S", (), {"metrics_retention_interval": 3600})())
    monkeypatch.setattr(host_metrics.asyncio, "sleep", lambda seconds: real_sleep(0))
    monkeypatch.setattr(host_metrics, "retention_once", once)
    monkeypatch.setattr(host_metrics.log, "exception", lambda *args, **kw: None)
    with pytest.raises(asyncio.CancelledError):
        await host_metrics.retention_forever()
    assert len(calls) == 3


# ------------------------------------------------------------------ trends


async def test_trends_use_raw_samples_up_to_seven_days():
    a = await _add_host("b-host")
    first = await _add_host("a-host")
    await _add_host("unpinned", pinned=False)
    await _add_samples(a, [
        (NOW - timedelta(days=8), 99, 99, 99),  # outside the window
        (NOW - timedelta(days=2), 10, 40, None),
        (NOW - timedelta(hours=5), 30, 20, 60),
        (NOW - timedelta(minutes=5), 20, 30, 62),
    ])
    async with get_sessionmaker()() as db:
        trends = await host_metrics.host_trends(db, days=7, now=NOW)
    assert [t["name"] for t in trends] == ["a-host", "b-host"]
    empty, host = trends
    assert empty["id"] == first and empty["series"] == [] and empty["stats"] == {"cpu": None, "mem": None, "disk": None}
    assert host["resolution"] == "raw" and host["cpus"] == 4 and host["mem_total_mb"] == 8192
    assert host["metrics"]["cpu_percent"] == 5.0
    assert [(p["cpu"], p["mem"], p["disk"]) for p in host["series"]] == [(10, 40, None), (30, 20, 60), (20, 30, 62)]
    assert host["series"][0]["at"] == NOW - timedelta(days=2)
    assert host["stats"]["cpu"] == {"min": 10, "avg": 20, "max": 30, "latest": 20}
    assert host["stats"]["mem"] == {"min": 20, "avg": 30, "max": 40, "latest": 30}
    assert host["stats"]["disk"] == {"min": 60, "avg": 61, "max": 62, "latest": 62}


async def test_trends_use_hourly_rows_beyond_seven_days():
    a = await _add_host("a")
    old_hour = floor(NOW - timedelta(days=20))
    async with get_sessionmaker()() as db:
        db.add(HostSampleHourly(host_id=a, hour=old_hour, cpu_avg=10, cpu_max=80, mem_avg=50, mem_max=55,
                                disk_max=40, samples=12))
        db.add(HostSampleHourly(host_id=a, hour=floor(NOW - timedelta(days=40)), cpu_avg=1, cpu_max=1, mem_avg=1,
                                mem_max=1, samples=1))  # outside the 30 day window
        await db.commit()
    # Recent hours not rolled up yet still show, computed from raw samples.
    await _add_samples(a, [
        (datetime(2026, 11, 17, 12, 5, tzinfo=UTC), 20, 60, 41),
        (datetime(2026, 11, 17, 12, 25, tzinfo=UTC), 40, 70, 42),
    ])
    async with get_sessionmaker()() as db:
        (host,) = await host_metrics.host_trends(db, days=30, now=NOW)
    assert host["resolution"] == "hour"
    first, last = host["series"]
    assert first == {"at": old_hour, "cpu": 10, "mem": 50, "disk": 40, "cpu_max": 80, "mem_max": 55, "samples": 12}
    assert last == {"at": datetime(2026, 11, 17, 12, tzinfo=UTC), "cpu": 30, "mem": 65, "disk": 42, "cpu_max": 40,
                    "mem_max": 70, "samples": 2}
    # avg weighs hours by their samples, max keeps the peak, latest is the newest raw sample.
    assert host["stats"]["cpu"] == {"min": 10, "avg": round((10 * 12 + 30 * 2) / 14, 1), "max": 80, "latest": 40}
    assert host["stats"]["mem"]["max"] == 70 and host["stats"]["mem"]["latest"] == 70
    assert host["stats"]["disk"] == {"min": 40, "avg": 41, "max": 42, "latest": 42}
    assert await _count(HostSampleHourly) == 2  # reading never writes rollups


async def test_trends_without_pinned_hosts():
    await _add_host("a", pinned=False)
    async with get_sessionmaker()() as db:
        assert await host_metrics.host_trends(db, days=90, now=NOW) == []


# ------------------------------------------------------------------ migration


def _alembic(url: str, *args: str) -> None:
    env = {**os.environ, "SLIPWAY_DATABASE_URL": url, "SLIPWAY_ENV_FILE": "", "PYTHONPATH": str(ROOT)}
    done = subprocess.run([sys.executable, "-m", "alembic", *args], cwd=ROOT, env=env, capture_output=True, text=True)
    assert done.returncode == 0, (args, done.stderr)


def test_migration_0006b_on_sqlite(tmp_path):
    url = f"sqlite+aiosqlite:///{tmp_path}/m.db"
    _alembic(url, "upgrade", "head")
    with sqlite3.connect(tmp_path / "m.db") as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"host_samples", "host_samples_hourly"} <= tables
        indexes = {row[1] for row in conn.execute("PRAGMA index_list(host_samples)")}
        assert "ix_host_samples_host_id_at" in indexes
        fks = {(row[2], row[6]) for row in conn.execute("PRAGMA foreign_key_list(host_samples_hourly)")}
        assert fks == {("hosts", "CASCADE")}
    _alembic(url, "check")
    _alembic(url, "downgrade", "0006")
    with sqlite3.connect(tmp_path / "m.db") as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert not tables & {"host_samples", "host_samples_hourly"}
        assert conn.execute("SELECT version_num FROM alembic_version").fetchone() == ("0006",)
    _alembic(url, "upgrade", "head")
    _alembic(url, "check")


@pytest.mark.skipif(not os.environ.get("SLIPWAY_TEST_DATABASE_URL", "").startswith("postgresql"),
                    reason="needs SLIPWAY_TEST_DATABASE_URL pointing at PostgreSQL")
async def test_migration_0006b_on_postgresql():
    base = make_url(os.environ["SLIPWAY_TEST_DATABASE_URL"])
    name = f"slipway_migration_{uuid.uuid4().hex[:12]}"
    admin_dsn = base.set(drivername="postgresql").render_as_string(hide_password=False)
    conn = await asyncpg.connect(admin_dsn)
    try:
        await conn.execute(f'CREATE DATABASE "{name}"')
    except asyncpg.InsufficientPrivilegeError:
        await conn.close()
        pytest.skip("the test database user cannot create databases")
    try:
        url = base.set(database=name).render_as_string(hide_password=False)
        for args in (["upgrade", "head"], ["check"], ["downgrade", "0006"], ["upgrade", "head"], ["check"]):
            await asyncio.to_thread(_alembic, url, *args)
    finally:
        await conn.execute(f'DROP DATABASE IF EXISTS "{name}"')
        await conn.close()
