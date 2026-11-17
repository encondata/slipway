"""The certificate renewal loop and the app lifespan (phase 4 §15.12, §15.13; D12).

Numbered tests of §20.2: 60 (the loop's half: one job queued when due; none after a failure within 24 hours,
while a job runs, or for an environment that isn't live; the stored date when DigitalOcean can't be read), 86
(the system actor: no ``triggered_by``, ``options.by = 'renewals'``, no permission check; refused, logged and
audited once by a running job, an unresolved switch and a deleting environment, but not by the owner's hold)
and 61's sweep half (a backup cut mid-stream by a restart leaves a ``.part`` that start-up removes before
recovery runs). Also: a renewal leaves a stopped chain's notice and its Continue follow-up (Decision 23), and
the lifespan starts and stops the loop and registers the do_lb backend.

Fakes only: FakeDigitalOcean (tests/fake_digitalocean.py) through tests/do_fixtures.py, and a local shell for
the backup store's runner. The runner never runs a job here: ``submit`` is recorded.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
import pytest
from sqlalchemy import select, update

from slipway.core.config import get_settings
from slipway.core.crypto import reset_crypto_cache
from slipway.db.session import get_sessionmaker
from slipway.models import AuditEvent, Deployment, Environment, Instance, ProviderAccount, Resource
from slipway.services import backup_store, data, deployer, do_rules, renewals, snapshots
from tests import do_fixtures as dof
from tests import fake_digitalocean as fdo
from tests.test_backup_store import OWNER, _backup
from tests.test_final_remote import ShellRemote

ROOT = Path(__file__).resolve().parents[1]
NAMES = sorted(r["hostname"] for r in dof.routes("shop"))


@pytest.fixture
def do(monkeypatch) -> fdo.FakeDigitalOcean:
    return fdo.use_fake(monkeypatch, fdo.FakeDigitalOcean())


@pytest.fixture
def submitted(monkeypatch) -> list[tuple[uuid.UUID, tuple]]:
    """Jobs the loop hands to the runner are recorded, not run."""
    found: list[tuple[uuid.UUID, tuple]] = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, keys: found.append((dep_id, keys)))
    return found


@pytest.fixture
def storage(tmp_path) -> Path:
    """The Slipway storage folder (snapshots and the backup store) in this test's temp folder."""
    root = tmp_path / "storage"
    old = os.environ.get("SLIPWAY_STORAGE_DIR")
    os.environ["SLIPWAY_STORAGE_DIR"] = str(root)
    get_settings.cache_clear()
    reset_crypto_cache()
    snapshots.reset_state()
    yield root
    os.environ["SLIPWAY_STORAGE_DIR"] = old or ""
    get_settings.cache_clear()
    reset_crypto_cache()
    snapshots.reset_state()


def _iso(when: datetime) -> str:
    return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


async def _live(do: fdo.FakeDigitalOcean, *, days: int = 20, stored_days: int | None = None, name: str = "shop",
                status: str = "live") -> dof.DoEnv:
    """A DigitalOcean environment behind its load balancer, serving a certificate with ``days`` left. The
    stored ``cloud.certificate`` says ``stored_days`` (the served one's date unless given)."""
    async with get_sessionmaker()() as db:
        account_id = await db.scalar(select(ProviderAccount.id).where(ProviderAccount.name == "do-main"))
    env = await dof.make_do_env(name=name, status=status, account_id=account_id or await dof.make_account())
    names = sorted(r["hostname"] for r in dof.routes(name))
    vpc = do.add_vpc(name=f"slipway-{name}")
    served = datetime.now(UTC) + timedelta(days=days)
    cert = do.add_certificate(f"slipway-{name}-202611010000", names, served)
    lb = do.add_load_balancer(**do_rules.lb_body(name, region="nyc3", vpc_uuid=vpc["id"], port=80,
                                                 health="/healthz", certificate_id=cert["id"]))
    stored_at = served if stored_days is None else datetime.now(UTC) + timedelta(days=stored_days)
    async with get_sessionmaker()() as db:
        db.add(Resource(environment_id=env.env_id, provider="digitalocean", kind="load_balancer",
                        provider_id=lb["id"], name=lb["name"], origin="created", details={"ip": lb["ip"]}))
        row = await db.get(Environment, env.env_id)
        row.cloud = {**row.cloud, "lb_ip": lb["ip"], "certificate": {
            "id": cert["id"], "name": cert["name"], "not_after": _iso(stored_at), "names": names}}
        await db.commit()
    do.requests.clear()
    return env


async def _set(model, row_id, **values) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(update(model).where(model.id == row_id).values(**values))
        await db.commit()


async def _jobs(env: dof.DoEnv, kind: str = "certificate") -> list[Deployment]:
    async with get_sessionmaker()() as db:
        return list(await db.scalars(select(Deployment).where(Deployment.environment_id == env.env_id,
                                                              Deployment.kind == kind)
                                     .order_by(Deployment.created_at)))


async def _audits(action: str) -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        return list(await db.scalars(select(AuditEvent).where(AuditEvent.action == action)
                                     .order_by(AuditEvent.created_at)))


async def _add_job(env: dof.DoEnv, kind: str, status: str, *, finished_ago: timedelta | None = None,
                   instance_id: uuid.UUID | None = None) -> uuid.UUID:
    finished = datetime.now(UTC) - finished_ago if finished_ago is not None else None
    async with get_sessionmaker()() as db:
        dep = Deployment(environment_id=env.env_id, instance_id=instance_id, kind=kind, branch="main",
                         status=status, log="", options={}, finished_at=finished,
                         created_at=finished - timedelta(minutes=5) if finished else datetime.now(UTC))
        db.add(dep)
        await db.commit()
        return dep.id


def _outcome(outcomes: list[renewals.Outcome], env: dof.DoEnv) -> renewals.Outcome:
    (found,) = [o for o in outcomes if o.environment_id == env.env_id]
    return found


# ------------------------------------------------------------------------------- test 60: the loop's half


async def test_60_a_due_certificate_queues_one_renewal(do, submitted):
    env = await _live(do, days=20)
    fresh = await _live(do, days=80, name="calm")
    outcomes = await renewals.run_once()
    assert _outcome(outcomes, fresh).result == renewals.NOT_DUE
    got = _outcome(outcomes, env)
    assert got.result == renewals.QUEUED and got.served.source == renewals.FROM_DIGITALOCEAN
    (job,) = await _jobs(env)
    assert got.deployment_id == job.id and job.status == "queued"
    assert [s["key"] for s in job.steps] == ["check", "certificate"]
    assert submitted == [(job.id, data.job_keys(job))]
    assert await _jobs(fresh) == []
    # Read from DigitalOcean: the load balancer, then the certificate it serves; nothing written.
    assert {r["method"] for r in do.requests} == {"GET"}
    # The next pass finds the job and queues nothing more.
    again = _outcome(await renewals.run_once(), env)
    assert again.result == renewals.SKIPPED and again.reason == "a job is running"
    assert len(await _jobs(env)) == 1 and len(submitted) == 1


async def test_60_thirty_days_is_due_and_thirty_one_is_not(do, submitted):
    due = await _live(do, days=30, name="due")
    later = await _live(do, days=31, name="later")
    outcomes = await renewals.run_once()
    assert _outcome(outcomes, due).result == renewals.QUEUED
    assert _outcome(outcomes, later).result == renewals.NOT_DUE


async def test_60_a_renewal_that_failed_within_a_day_isnt_tried_again(do, submitted):
    env = await _live(do, days=10)
    await _add_job(env, "certificate", "failed", finished_ago=timedelta(hours=23))
    got = _outcome(await renewals.run_once(), env)
    assert got.result == renewals.SKIPPED and got.reason.startswith("the last renewal failed at ")
    assert len(await _jobs(env)) == 1 and submitted == []
    assert do.requests == []  # skipped before DigitalOcean is read
    # A day on, it is tried again.
    assert (await renewals.check_environment(env.env_id, at=datetime.now(UTC) + timedelta(hours=2))).result \
        == renewals.QUEUED


async def test_60_only_the_latest_renewal_counts(do, submitted):
    env = await _live(do, days=10)
    await _add_job(env, "certificate", "failed", finished_ago=timedelta(hours=3))
    await _add_job(env, "certificate", "succeeded", finished_ago=timedelta(hours=1))
    assert _outcome(await renewals.run_once(), env).result == renewals.QUEUED


async def test_60_a_running_job_or_an_environment_that_isnt_live_queues_nothing(do, submitted):
    busy = await _live(do, days=5, name="busy")
    await _add_job(busy, "deploy", "running", instance_id=busy.ids["blue"])
    new = await _live(do, days=5, name="fresh", status="new")
    deleting = await _live(do, days=5, name="going", status="deleting")
    outcomes = await renewals.run_once()
    assert _outcome(outcomes, busy).reason == "a job is running"
    assert [o.environment_id for o in outcomes] == [busy.env_id]  # the others aren't looked at
    for env in (busy, new, deleting):
        assert await _jobs(env) == []
    assert submitted == [] and await _audits(renewals.REFUSED_ACTION) == []


async def test_60_an_environment_not_behind_a_load_balancer_is_not_looked_at(do, submitted):
    env = await _live(do, days=5)
    await _set(Environment, env.env_id, traffic={"switch": "switchyard", "dns": None})
    assert await renewals.run_once() == []
    assert await _jobs(env) == []


async def test_60_digitalocean_unreadable_falls_back_to_the_stored_date(do, submitted, caplog):
    due = await _live(do, days=80, stored_days=12, name="due")
    calm = await _live(do, days=10, stored_days=60, name="calm")
    do.down = True
    caplog.set_level(logging.WARNING, logger="slipway.services.renewals")
    outcomes = await renewals.run_once()
    got = _outcome(outcomes, due)
    assert got.result == renewals.QUEUED and got.served.source == renewals.FROM_STORED
    assert _outcome(outcomes, calm).result == renewals.NOT_DUE
    lines = [r.getMessage() for r in caplog.records if r.name == "slipway.services.renewals"]
    assert any("Couldn't read due's certificate from DigitalOcean (Unreachable); using the stored date"
               in line for line in lines), lines
    assert not any("down (fake)" in line or "sensitive" in line or fdo.TOKEN in line for line in lines)
    (event,) = await _audits(renewals.QUEUED_ACTION)
    assert event.details["read_from"] == "stored"


async def test_60_a_load_balancer_the_fake_answers_wrongly_falls_back_too(do, submitted, caplog):
    env = await _live(do, days=80, stored_days=3)
    do.fail[("GET", f"/load_balancers/{(await _lb_id(env))}")] = {"status": 500, "message": "sensitive detail"}
    caplog.set_level(logging.WARNING, logger="slipway.services.renewals")
    got = _outcome(await renewals.run_once(), env)
    assert got.result == renewals.QUEUED and got.served.source == renewals.FROM_STORED
    assert not any("sensitive" in r.getMessage() for r in caplog.records)


async def test_60_no_load_balancer_yet_is_skipped(do, submitted):
    env = await _live(do, days=5)
    async with get_sessionmaker()() as db:
        await db.execute(Resource.__table__.delete().where(Resource.kind == "load_balancer"))
        await db.commit()
    got = _outcome(await renewals.run_once(), env)
    assert got.result == renewals.SKIPPED and got.reason == "it has no load balancer yet"
    assert await _jobs(env) == []


async def _lb_id(env: dof.DoEnv) -> str:
    async with get_sessionmaker()() as db:
        return await db.scalar(select(Resource.provider_id).where(Resource.environment_id == env.env_id,
                                                                  Resource.kind == "load_balancer"))


async def test_one_environment_failing_doesnt_stop_the_others(do, submitted, monkeypatch, caplog):
    first = await _live(do, days=5, name="aaa")
    second = await _live(do, days=5, name="bbb")
    real = renewals.check_environment

    async def flaky(env_id, *, at=None):
        if env_id == first.env_id:
            from sqlalchemy.exc import OperationalError
            raise OperationalError("SELECT", {}, Exception("database is locked"))
        return await real(env_id, at=at)

    monkeypatch.setattr(renewals, "check_environment", flaky)
    caplog.set_level(logging.WARNING, logger="slipway.services.renewals")
    outcomes = await renewals.run_once()
    assert [o.environment_id for o in outcomes] == [second.env_id] and outcomes[0].result == renewals.QUEUED
    lines = [r.getMessage() for r in caplog.records]
    assert "Couldn't check aaa's certificate: a database error (OperationalError); trying again next pass" in lines
    assert not any("database is locked" in line for line in lines)


# ------------------------------------------------------------------------------ test 86: the system actor


async def test_86_the_system_actor_queues_with_no_user(do, submitted):
    env = await _live(do, days=5)
    outcome = _outcome(await renewals.run_once(), env)
    (job,) = await _jobs(env)
    assert job.triggered_by_id is None and job.options == {"by": "renewals"} and job.instance_id is None
    (event,) = await _audits(renewals.QUEUED_ACTION)
    assert event.actor_id is None and event.target_type == "environment" and event.target_id == str(env.env_id)
    assert event.details["by"] == "renewals" and event.details["deployment_id"] == str(job.id)
    assert event.details["names"] == NAMES and event.details["staging"] is False
    assert renewals.certs.parse_time(event.details["not_after"]) == outcome.served.not_after
    assert fdo.TOKEN not in str(event.details) and fdo.TOKEN not in event.summary
    assert event.summary == "Slipway queued a renewal of shop's certificate"


async def test_86_the_owners_hold_doesnt_refuse_a_renewal(do, submitted):
    env = await _live(do, days=5)
    await _set(Instance, env.ids["data"], data_dirty={"hold": True, "first": {"deployment_id": uuid.uuid4().hex}})
    assert _outcome(await renewals.run_once(), env).result == renewals.QUEUED
    assert len(await _jobs(env)) == 1


async def test_86_an_unresolved_switch_refuses_and_is_audited_once(do, submitted, caplog):
    env = await _live(do, days=5)
    await _set(Environment, env.env_id, traffic_state={"unresolved": {
        "deployment_id": uuid.uuid4().hex, "from_slot": "blue", "to_slot": "green", "message": "test",
        "at": "2026-11-16T10:00:00+00:00"}})
    caplog.set_level(logging.INFO, logger="slipway.services.renewals")
    first = _outcome(await renewals.run_once(), env)
    second = _outcome(await renewals.run_once(), env)
    for got in (first, second):
        assert got.result == renewals.REFUSED and got.reason.startswith("Traffic of shop may be split")
    assert await _jobs(env) == [] and submitted == []
    (event,) = await _audits(renewals.REFUSED_ACTION)  # once, though refused twice
    assert event.actor_id is None and event.target_id == str(env.env_id)
    assert event.details == {"by": "renewals", "reason": first.reason}
    logged = [r.getMessage() for r in caplog.records if r.getMessage().startswith("Didn't queue a renewal of shop")]
    assert len(logged) == 2
    # A day later it is audited again.
    third = await renewals.queue_renewal(env.env_id, at=datetime.now(UTC) + timedelta(days=1, minutes=1))
    assert third.result == renewals.REFUSED and len(await _audits(renewals.REFUSED_ACTION)) == 2


async def test_86_a_running_job_refuses_at_queue_time(do, submitted):
    """A job that started between the loop's look and its queue: queue_job's busy fence."""
    env = await _live(do, days=5)
    await _add_job(env, "activate", "running")
    got = await renewals.queue_renewal(env.env_id)
    assert got.result == renewals.REFUSED
    assert got.reason.startswith("A job is already running for shop (") and got.reason.endswith("wait for it to finish")
    assert await _jobs(env) == [] and submitted == []
    (event,) = await _audits(renewals.REFUSED_ACTION)
    assert event.details["reason"] == got.reason


async def test_86_a_deleting_environment_refuses_at_queue_time(do, submitted):
    env = await _live(do, days=5)
    await _set(Environment, env.env_id, status="deleting")
    got = await renewals.queue_renewal(env.env_id)
    assert got.result == renewals.REFUSED and got.reason == "shop is being deleted: only its teardown's retry can run"
    assert await _jobs(env) == [] and len(await _audits(renewals.REFUSED_ACTION)) == 1


# ------------------------------------------------------------------- Decision 23: the chain's notice stays


async def test_a_renewal_leaves_a_stopped_chains_notice(do, submitted):
    env = await _live(do, days=5)
    notice = {"text": "The data server deployed, but blue's deploy couldn't start", "at": "2026-11-16T09:00:00+00:00",
              "deployment_id": uuid.uuid4().hex, "next": {"kind": "deploy", "slot": "blue"}}
    await _set(Environment, env.env_id, notice=notice)
    assert _outcome(await renewals.run_once(), env).result == renewals.QUEUED
    async with get_sessionmaker()() as db:
        assert (await db.get(Environment, env.env_id)).notice == notice


# ------------------------------------------------------------------------------------------- the schedule


async def test_the_loop_is_off_at_zero_and_paced_otherwise(monkeypatch):
    waits: list[float] = []
    passes: list[int] = []

    async def fake_sleep(seconds: float) -> None:
        waits.append(seconds)
        if len(waits) == 3:
            raise asyncio.CancelledError

    async def fake_pass(*, at=None):
        passes.append(1)
        if len(passes) == 1:
            raise RuntimeError("boom")  # a failed pass doesn't end the loop
        return []

    monkeypatch.setattr(renewals, "sleep", fake_sleep)
    monkeypatch.setattr(renewals, "run_once", fake_pass)
    await renewals.run_forever()  # SLIPWAY_CERT_RENEW_INTERVAL=0 in the tests: returns at once
    assert waits == [] and passes == []
    monkeypatch.setenv("SLIPWAY_CERT_RENEW_INTERVAL", "3600")
    get_settings.cache_clear()
    try:
        with pytest.raises(asyncio.CancelledError):
            await renewals.run_forever()
    finally:
        monkeypatch.setenv("SLIPWAY_CERT_RENEW_INTERVAL", "0")
        get_settings.cache_clear()
    assert waits == [renewals.FIRST_RUN_DELAY, 3600, 3600] and len(passes) == 2


# ------------------------------------------------------------------ the lifespan, and test 61's sweep half


def _keep_engine(monkeypatch) -> None:
    from slipway import main

    monkeypatch.setattr(main, "init_engine", lambda *a, **kw: None)  # keep the tests' engine

    async def keep() -> None:
        return None

    monkeypatch.setattr(main, "dispose_engine", keep)


async def test_61_a_half_streamed_backup_is_swept_before_recovery(app, monkeypatch, storage, tmp_path):
    from slipway import main

    _keep_engine(monkeypatch)
    incoming = tmp_path / "runner" / "backups" / ".incoming"
    incoming.mkdir(parents=True)
    remote = ShellRemote("sh", dict(os.environ))
    backup, sources = _backup(incoming, files=False)
    streaming, never = asyncio.Event(), asyncio.Event()

    async def stalls(path, chunk=None):
        yield b"x" * 4096
        streaming.set()
        await never.wait()

    remote.read_stream = stalls
    pull = asyncio.create_task(backup_store.pull(remote, OWNER, backup, sources=sources))
    await asyncio.wait_for(streaming.wait(), 10)
    part = backup_store.stored_path(OWNER, backup.name, "dump").with_name(
        backup_store.stored_path(OWNER, backup.name, "dump").name + backup_store.PART)
    assert part.is_file()
    # A restart ends the process here, so pull's own clean-up never runs: stand that in by keeping the file.
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(backup_store, "_remove_quietly", lambda path: False)
        pull.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await pull
    assert part.is_file()

    seen_at_recovery: list[bool] = []
    real_recover = main.runner.recover_interrupted

    async def recover() -> None:
        seen_at_recovery.append(part.exists())
        await real_recover()

    monkeypatch.setattr(main.runner, "recover_interrupted", recover)
    async with main.lifespan(app):
        assert seen_at_recovery == [False]  # swept before recovery ran
        assert not part.exists()
        stored = sorted(p.name for p in (storage / "backups").rglob("*") if p.is_file())
        assert stored == []  # no .sbc either
        assert [p.name for p in incoming.iterdir()] == [f"{backup.name}.dump"]  # the runner's copy is kept
    await snapshots.shutdown()


async def test_the_lifespan_starts_and_stops_the_renewal_loop(app, monkeypatch, storage):
    from slipway import main

    _keep_engine(monkeypatch)
    started, stopped = asyncio.Event(), asyncio.Event()

    async def loop() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    monkeypatch.setattr(main.renewals, "run_forever", loop)
    async with main.lifespan(app):
        await asyncio.wait_for(started.wait(), 10)
        assert not stopped.is_set()
    assert stopped.is_set()
    await snapshots.shutdown()


def test_the_app_registers_the_load_balancer_backend():
    """Importing the app registers do_lb (a fresh interpreter: other tests may have imported do_lb already)."""
    code = ("import slipway.main\nimport sys\nfrom slipway.services import traffic\n"
            "print('do_lb' in traffic.BACKENDS)")
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=120,
                         env={**os.environ, "SLIPWAY_ENV_FILE": ""}, check=True)
    assert out.stdout.strip().splitlines()[-1] == "True"
