"""The certificate renewal loop (phase 4 §15.12, D12): Slipway renews each load balancer's certificate itself.

Started in the app's lifespan (``run_forever``). The first pass runs five minutes after start, then one every
``SLIPWAY_CERT_RENEW_INTERVAL`` seconds; 0 turns the loop off (the tests set it so). Each pass looks at every
live DigitalOcean environment whose traffic goes through ``do_lb`` and:

* skips it while any of its jobs is queued or running, or when its latest ``certificate`` job failed within
  24 hours (a failed renewal backs off a day);
* reads the certificate the load balancer serves from DigitalOcean. Any failure there falls back to the date
  stored in ``cloud.certificate``, and only the error's type is logged, never its text;
* when 30 days or fewer are left (``certs.is_due``), queues one ``certificate`` job as the system actor
  (``jobs.queue_job(..., user=None, system='renewals')``: no permission check, no ``triggered_by``,
  ``options.by = 'renewals'``, the environment's notice left as it is), audits ``certificate.renew_queued``
  and hands the job to the runner.

A refused queue (a job that started meanwhile, an unresolved switch, an environment being deleted) is logged
each time and audited once a day per environment (``certificate.renew_refused``); it is never raised. A
database hiccup is logged by its type and the loop goes on with the next environment.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from slipway.core.config import get_settings
from slipway.db.session import get_sessionmaker
from slipway.models import AuditEvent, Deployment, Environment, ProviderAccount
from slipway.models.environment import EnvironmentStatus
from slipway.models.instance import DeploymentKind, DeploymentStatus
from slipway.services import audit, certs, data, do_rules, jobs, resources
from slipway.services.digitalocean import DigitalOceanClient

log = logging.getLogger(__name__)

SYSTEM = "renewals"
PROVIDER = "digitalocean"
SWITCH = "do_lb"
FIRST_RUN_DELAY = 300.0  # seconds after start before the first pass
FAILED_BACKOFF = timedelta(hours=24)  # a failed renewal isn't tried again for a day (D12)
REFUSAL_AUDIT_EVERY = timedelta(days=1)  # a refused queue is audited once a day per environment
QUEUED_ACTION = "certificate.renew_queued"
REFUSED_ACTION = "certificate.renew_refused"

# Outcomes of one environment's look.
QUEUED, NOT_DUE, SKIPPED, REFUSED = "queued", "not_due", "skipped", "refused"
# Where the expiry came from.
FROM_DIGITALOCEAN, FROM_STORED = "digitalocean", "stored"

# Tests swap these: the wait between passes, and the clock.
sleep: Callable[[float], Awaitable[None]] = asyncio.sleep


def now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class Served:
    """The certificate the load balancer serves: its expiry and names, and where they were read."""

    not_after: datetime | None
    names: list[str] = field(default_factory=list)
    source: str = FROM_STORED


@dataclass(frozen=True)
class Outcome:
    """What one pass did for one environment (for the log and the tests)."""

    environment_id: uuid.UUID
    result: str
    reason: str = ""
    deployment_id: uuid.UUID | None = None
    served: Served | None = None


# ------------------------------------------------------------------------------------------------ the loop


async def run_forever() -> None:
    """The lifespan's task: a pass five minutes after start, then one every ``cert_renew_interval`` seconds."""
    interval = get_settings().cert_renew_interval
    if interval <= 0:
        return
    await sleep(FIRST_RUN_DELAY)
    while True:
        try:
            await run_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # keep renewing whatever happens; the type only, never the text
            log.error("The certificate renewal pass failed (%s); it runs again in %s seconds",
                      type(exc).__name__, interval)
        await sleep(interval)


async def run_once(*, at: datetime | None = None) -> list[Outcome]:
    """One pass over every live DigitalOcean environment. Returns what it did for each."""
    async with get_sessionmaker()() as db:
        candidates = list(await db.execute(
            select(Environment.id, Environment.name, Environment.traffic)
            .where(Environment.status == EnvironmentStatus.LIVE, Environment.provider == PROVIDER)
            .order_by(Environment.name)
        ))
    outcomes: list[Outcome] = []
    for env_id, name, traffic in candidates:
        if (traffic or {}).get("switch") != SWITCH:
            continue
        try:
            outcomes.append(await check_environment(env_id, at=at))
        except asyncio.CancelledError:
            raise
        except SQLAlchemyError as exc:
            log.warning("Couldn't check %s's certificate: a database error (%s); trying again next pass",
                        name, type(exc).__name__)
        except Exception as exc:
            log.error("Couldn't check %s's certificate (%s); trying again next pass", name, type(exc).__name__)
    return outcomes


# ------------------------------------------------------------------------------------------ one environment


async def check_environment(env_id: uuid.UUID, *, at: datetime | None = None) -> Outcome:
    """Look at one environment, and queue its renewal when the served certificate is due."""
    when = at or now()
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        if env is None or env.status != EnvironmentStatus.LIVE or (env.traffic or {}).get("switch") != SWITCH:
            return Outcome(env_id, SKIPPED, "it isn't live behind a load balancer")
        if await data.active_env_jobs(db, env.id):
            return Outcome(env_id, SKIPPED, "a job is running")
        failed = await recent_failure(db, env.id, when)
        if failed is not None:
            return Outcome(env_id, SKIPPED, f"the last renewal failed at {failed:%Y-%m-%d %H:%M} UTC")
        lbs = await resources.owned(db, env.id, PROVIDER, "load_balancer")
        if not lbs:
            return Outcome(env_id, SKIPPED, "it has no load balancer yet")
        account = await db.get(ProviderAccount, env.provider_account_id) if env.provider_account_id else None
        token = (account.secret if account is not None else None) or ""
        stored = dict((env.cloud or {}).get("certificate") or {})
        name, lb_id = env.name, lbs[0].provider_id
    served = await read_served(name, token, lb_id, stored)
    if not certs.is_due(served.not_after, when):
        return Outcome(env_id, NOT_DUE, served=served)
    return await queue_renewal(env_id, served, at=when)


async def recent_failure(db: Any, env_id: uuid.UUID, at: datetime) -> datetime | None:
    """When the environment's latest ``certificate`` job failed, if that was within 24 hours of ``at``."""
    latest = (await db.execute(
        select(Deployment.status, Deployment.finished_at, Deployment.created_at)
        .where(Deployment.environment_id == env_id, Deployment.kind == DeploymentKind.CERTIFICATE)
        .order_by(Deployment.created_at.desc(), Deployment.id.desc()).limit(1)
    )).first()
    if latest is None or latest.status != DeploymentStatus.FAILED:
        return None
    ended = latest.finished_at or latest.created_at
    if ended is not None and ended.tzinfo is None:
        ended = ended.replace(tzinfo=UTC)
    return ended if ended is not None and at - ended < FAILED_BACKOFF else None


def _stored(stored: dict[str, Any]) -> Served:
    names = stored.get("names") or stored.get("dns_names") or []
    return Served(certs.parse_time(stored.get("not_after")), sorted(str(n) for n in names), FROM_STORED)


async def read_served(env_name: str, token: str, lb_id: str, stored: dict[str, Any]) -> Served:
    """The certificate the load balancer serves, read from DigitalOcean; on any failure the date stored in
    ``cloud.certificate``. A load balancer that serves no certificate reads as one with no expiry (due)."""
    if not token:
        log.warning("Couldn't read %s's certificate from DigitalOcean: its account has no token; "
                    "using the stored date", env_name)
        return _stored(stored)
    try:
        async with DigitalOceanClient(token) as client:
            lb = await client.load_balancer(lb_id)
            if lb is None:
                raise LookupError("load balancer not found")
            cert_id = do_rules.https_certificate(lb)
            if not cert_id:
                return Served(None, [], FROM_DIGITALOCEAN)
            cert = await client.certificate(cert_id)
            if cert is None:
                raise LookupError("certificate not found")
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # never the error's text (§15.12)
        log.warning("Couldn't read %s's certificate from DigitalOcean (%s); using the stored date",
                    env_name, type(exc).__name__)
        return _stored(stored)
    return Served(certs.not_after(cert), certs.dns_names(cert), FROM_DIGITALOCEAN)


def _when(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat() if value is not None else None


async def queue_renewal(env_id: uuid.UUID, served: Served | None = None, *, at: datetime | None = None) -> Outcome:
    """Queue one ``certificate`` job as the system actor, audit it and hand it to the runner. A refusal is
    logged, audited once a day (``refused``) and answered as an Outcome, never raised."""
    from slipway.services.deployer import runner  # the deployer imports most services; loaded when first needed

    when = at or now()
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        if env is None:
            return Outcome(env_id, SKIPPED, "it is gone")
        name = env.name
        try:
            dep = await jobs.queue_job(db, environment=env, user=None, kind=DeploymentKind.CERTIFICATE,
                                       system=SYSTEM)
        except jobs.JobRefused as refused:
            await db.rollback()
            reason = refused.text
        else:
            details: dict[str, Any] = {"by": SYSTEM, "deployment_id": str(dep.id),
                                       "staging": bool((env.cloud or {}).get("acme_staging"))}
            if served is not None:
                details.update(names=list(served.names), not_after=_when(served.not_after), read_from=served.source)
            audit.record(db, QUEUED_ACTION, actor=None, target=env,
                         summary=f"Slipway queued a renewal of {name}'s certificate", details=details)
            await db.commit()
            keys = data.job_keys(dep)
            runner.submit(dep.id, keys)
            log.info("Queued a renewal of %s's certificate (%s)", name, dep.id)
            return Outcome(env_id, QUEUED, deployment_id=dep.id, served=served)
    log.info("Didn't queue a renewal of %s's certificate: %s", name, reason)
    await _audit_refusal(env_id, name, reason, when)
    return Outcome(env_id, REFUSED, reason, served=served)


async def _audit_refusal(env_id: uuid.UUID, name: str, reason: str, at: datetime) -> None:
    """Audit a refused renewal, at most once a day per environment."""
    async with get_sessionmaker()() as db:
        recent = await db.scalar(
            select(AuditEvent.id).where(AuditEvent.action == REFUSED_ACTION, AuditEvent.target_id == str(env_id),
                                        AuditEvent.created_at > at - REFUSAL_AUDIT_EVERY).limit(1))
        if recent is not None:
            return
        audit.record(db, REFUSED_ACTION, actor=None, target=env_id, target_type="environment",
                     summary=f"Slipway couldn't queue a renewal of {name}'s certificate",
                     details={"by": SYSTEM, "reason": reason})
        await db.commit()
