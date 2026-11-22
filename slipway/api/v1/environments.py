"""Environments (phase 3 §11): one app from one branch in one or two slots, with its data and its names.

Every job follows the existing pattern: ``jobs.queue_job`` builds the row (its refusals become the HTTP answer),
the endpoint audits it, commits and submits it to the runner with its keys, and answers 202 with the
``DeploymentOut``. What the page offers, and why not, is ``environments.actions``, shared with the pages.

Environment ids are loaded live (``deleted_at IS NULL``) except on GET, where a deleted environment still shows.
Typed names are the environment's and are checked before anything else (422).

Phases 4 and 5: the rules of create, Add slot, grow, retire and Delete are service helpers in
``services/environments.py`` (Decision 25); this module maps them to HTTP. ``DigitalOceanError`` answers 502
with its text, ``HostNotBuilt`` 409 with its text, and an address claim another create took at the commit 409
with Decision 43's text.
"""

from __future__ import annotations

import asyncio
import uuid
from collections import Counter
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, or_, select
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from slipway.api.deps import DB, not_found, require
from slipway.core.permissions import Perm
from slipway.models import (
    Backup,
    BackupStatus,
    DataMode,
    Deployment,
    DeploymentKind,
    Environment,
    EnvironmentStatus,
    FirstAdmin,
    Instance,
    InstanceStatus,
    Machine,
    MachineSnapshot,
    MachineStage,
    ResourceOrigin,
    Snapshot,
    SnapshotMode,
    SnapshotOrigin,
    SnapshotStatus,
    User,
)
from slipway.schemas import (
    ActivateIn,
    ChangeCheckOut,
    ConfirmIn,
    DeploymentOut,
    EnvDeployIn,
    EnvironmentCreate,
    EnvironmentDelete,
    EnvironmentOut,
    EnvironmentSummary,
    EnvironmentUpdate,
    FirstAdminOut,
    HostnameIn,
    MachineOut,
    MachineResizeIn,
    MachineStateOut,
    RemoveSlotIn,
    RetireIn,
    SlotAdd,
    SlotAdded,
    SlotIn,
    SlotOut,
    VmRevertIn,
    VmSnapshotIn,
    VmSnapshotOut,
    VmSnapshotsOut,
    deployment_out,
    deployment_outs,
)
from slipway.services import (
    audit,
    cloudflare,
    data,
    deployer,
    environments,
    jobs,
    machines,
    manifest,
    resources,
    snapshots,
    ssh,
    switchyard,
    traffic,
    vm_jobs,
)
from slipway.services.auth import AuthContext
from slipway.services.digitalocean import DigitalOceanError
from slipway.services.environments import APP_SLOTS, DATA_SLOT, CreateRefused

router = APIRouter(prefix="/environments", tags=["environments"])

Reader = Annotated[AuthContext, require(Perm.ENVIRONMENTS_READ)]
Writer = Annotated[AuthContext, require(Perm.ENVIRONMENTS_WRITE)]
Deleter = Annotated[AuthContext, require(Perm.ENVIRONMENTS_DELETE)]
Deployer = Annotated[AuthContext, require(Perm.DEPLOYMENTS_CREATE)]
Switcher = Annotated[AuthContext, require(Perm.TRAFFIC_SWITCH)]
Discarder = Annotated[AuthContext, require(Perm.DEPLOYMENTS_CREATE, Perm.TRAFFIC_SWITCH)]
Darkener = Annotated[AuthContext, require(Perm.TRAFFIC_SWITCH, Perm.ENVIRONMENTS_DELETE)]
MachineWriter = Annotated[AuthContext, require(Perm.MACHINES_WRITE)]
UNPROCESSABLE = 422
ENV_UNREADABLE = (
    "The environment's stored variables can't be decrypted with the configured SLIPWAY_ENCRYPTION_KEY. Add the old "
    "key after the new one (comma-separated) and run `slipway rotate-encryption-key` to recover them, or re-enter them"
)


# ----------------------------------------------------------------------------- helpers


def need(ctx: AuthContext, *permissions: str, message: str | None = None) -> None:
    missing = [p for p in permissions if not ctx.can(p)]
    if missing:
        raise HTTPException(status.HTTP_403_FORBIDDEN, message or f"Missing permission: {', '.join(missing)}")


def refused(exc: jobs.JobRefused) -> HTTPException:
    return HTTPException(exc.status, exc.text)


def field_answer(exc: CreateRefused) -> JSONResponse:
    """``{detail, field}``, so the flow and edit pages can move to the step that holds the field (§9.1)."""
    return JSONResponse(exc.body(), status_code=exc.status)


def _claimed_vms(planned: dict[str, dict[str, Any]] | None) -> dict[str, str]:
    """slot -> address of each new VM a create or Add slot plans (their address claims)."""
    return {slot: str(m["address"]) for slot, m in (planned or {}).items()
            if m.get("provider") != environments.DIGITALOCEAN and m.get("address")}


async def claim_taken(db: AsyncSession, exc: IntegrityError, vms: dict[str, str]) -> JSONResponse | None:
    """Decision 43: an ``address_claims`` conflict (another create took the address) answers 409 with the
    address and its field; anything else is None, for the caller to raise. Called after the rollback: which
    address was taken is ``environments.claim_conflict``'s (PostgreSQL's detail, else the claims read again)."""
    taken = await environments.claim_conflict(db, exc, vms)
    return field_answer(taken) if taken is not None else None


def not_built(exc: ssh.HostNotBuilt) -> HTTPException:
    """A host a provider hasn't built yet (phase 4 §3.3): 409 with its text, never a 500 or a 502."""
    return HTTPException(status.HTTP_409_CONFLICT, str(exc))


def do_error(exc: DigitalOceanError) -> HTTPException:
    """DigitalOcean couldn't be read or refused (phase 4 §16): 502 with the client's text (never a token)."""
    return HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))


def check_confirm(env: Environment, confirm: str | None) -> None:
    """Typed confirmation (D20): the environment's name exactly. Checked before any other refusal."""
    if confirm != env.name:
        raise HTTPException(UNPROCESSABLE, f"Type the environment's name, {env.name}, exactly to confirm")


async def _get(db: AsyncSession, env_id: uuid.UUID, *, deleted: bool = False) -> Environment:
    """The environment, live only unless ``deleted`` (GET shows deleted ones too)."""
    env = await db.get(Environment, env_id, populate_existing=True)
    if env is None or (env.deleted_at is not None and not deleted):
        raise not_found("Environment")
    return env


async def env_unreadable(db: AsyncSession, env: Environment) -> bool:
    """Variables are stored but load as None (the key changed): ``IS NOT NULL`` decrypts nothing."""
    if env.env is not None:
        return False
    return bool(await db.scalar(select(Environment.env.is_not(None)).where(Environment.id == env.id)))


async def _last_job(db: AsyncSession, env: Environment, member_ids: list[uuid.UUID]) -> Deployment | None:
    cond = Deployment.environment_id == env.id
    if member_ids:
        cond = or_(cond, Deployment.instance_id.in_(member_ids))
    return await db.scalar(select(Deployment).options(defer(Deployment.log)).where(cond)
                           .order_by(Deployment.created_at.desc(), Deployment.id.desc()).limit(1))


async def environment_out(db: AsyncSession, env: Environment, ctx: AuthContext, *,
                          warnings: list[str] | None = None) -> EnvironmentOut:
    mem = await environments.members(db, env)
    owner = environments.owner_in(env, mem)
    last = await _last_job(db, env, [m.id for m in mem.values()])
    running = await data.active_env_jobs(db, env.id)
    seed = await db.get(Snapshot, owner.seed_snapshot_id) if owner is not None and owner.seed_snapshot_id else None
    admin = await db.scalar(select(FirstAdmin).where(FirstAdmin.instance_id == owner.id)) if owner else None
    creator = await db.get(User, env.created_by_id) if env.created_by_id else None
    order = {"blue": 0, "green": 1, "data": 2}
    slots = sorted(mem.values(), key=lambda m: order.get(str(m.slot), 3))
    parts = EnvironmentSummary.parts(env, mem, last)
    pending = await environments.pending_resizes(db, env, mem)
    parts["slots"] = [SlotOut.of(env, m, resize_pending=pending.get(str(m.slot))) for m in slots]
    vms = await machine_outs(db, env, mem)
    actions = await environments.actions(db, env, ctx)
    if isinstance(actions.get("vm_snapshots"), dict):
        # P5 §11: the VM snapshots card words a refusal by the storage's snapshot mode (ZFS, none).
        target = _snapshot_slot(mem)
        vm = next((m for m in vms if target is not None and m.slot == target.slot), None)
        actions["vm_snapshots"] = {**actions["vm_snapshots"], "snapshot_mode": vm.snapshot_mode if vm else None,
                                   "vm": vm.name if vm else None}
    return EnvironmentOut(
        **parts,
        manifest_file=env.manifest_file, auto_activate=bool(env.auto_activate), traffic=dict(env.traffic or {}),
        traffic_state=dict(env.traffic_state or {}), route_tls=dict(env.route_tls or {}),
        hostnames=list(env.hostnames or []), settings=dict(env.app_settings or {}), services=env.app_services,
        secrets=sorted((env.app_secrets or {}).keys()), env_keys=sorted((env.env or {}).keys()),
        env_unreadable=await env_unreadable(db, env),
        data_owner_id=owner.id if owner is not None else None,
        data={
            "keep_backups": owner.keep_backups if owner is not None else None,
            "seed_snapshot": {"id": seed.id, "name": seed.name, "status": seed.status} if seed is not None else None,
            "seed_content": bool(owner.seed_content) if owner is not None else None,
            "content_pending": bool(owner.content_pending) if owner is not None else False,
            "first_admin": FirstAdminOut.of(admin).model_dump(mode="json") if admin is not None else None,
            "data_dirty": (owner.data_dirty or None) if owner is not None else None,
            "capabilities": sorted(data.capabilities(owner)) if owner is not None else [],
            "clients": list((data.live_state(owner) or {}).get("clients") or []) if owner is not None else [],
        },
        active_job=(await deployment_out(db, running[0])) if running else None,
        notice=env.notice if isinstance(env.notice, dict) else None,
        created_by=creator.display_name if creator is not None else None,
        created_at=env.created_at, deleted_at=env.deleted_at,
        actions=actions,
        warnings=list(warnings or []),
        provider=str(env.provider or "ssh"), production=bool(env.production), retiring_at=env.retiring_at,
        cloud=await cloud_summary(db, env, pending),
        machines=vms,
    )


def _days_left(not_after: Any) -> int | None:
    from slipway.services import certs

    when = certs.parse_time(not_after)
    if when is None:
        return None
    return (when - datetime.now(UTC)).days


async def cloud_summary(db: AsyncSession, env: Environment, pending: dict[str, str]) -> dict[str, Any] | None:
    """``EnvironmentOut.cloud`` (phase 4 §16): what Slipway recorded of a DigitalOcean environment, read from the
    database only (``GET /environments/{id}/cloud`` reads DigitalOcean). ``billing_open`` is §12.4's Billing
    callout: a never-live environment that already has DigitalOcean objects (pending creates included)."""
    if not environments.is_digitalocean(env):
        return None
    from slipway.models import ProviderAccount, Resource

    stored = dict(env.cloud or {})
    account = await db.get(ProviderAccount, env.provider_account_id) if env.provider_account_id else None
    cert = stored.get("certificate") if isinstance(stored.get("certificate"), dict) else None
    objects = int(await db.scalar(select(func.count()).select_from(Resource).where(
        Resource.environment_id == env.id, Resource.provider == environments.DIGITALOCEAN)) or 0)
    return {
        "account": {"id": account.id, "name": account.name} if account is not None else None,
        "team": env.provider_team,
        "region": stored.get("region"),
        "sizes": {"droplet_size": stored.get("droplet_size"), "db_size": stored.get("db_size"),
                  "db_nodes": stored.get("db_nodes"), "db_version": stored.get("db_version"),
                  "droplets": (stored.get("plan") or {}).get("droplets")},
        "lb_ip": stored.get("lb_ip"),
        "certificate": ({"name": cert.get("name"), "not_after": cert.get("not_after"),
                         "days_left": _days_left(cert.get("not_after"))} if cert is not None else None),
        "cost": stored.get("cost"),
        "objects": objects,
        "billing_open": env.status == EnvironmentStatus.NEW and objects > 0,
        "pending_resizes": dict(pending),
    }


async def _submit(db: AsyncSession, dep: Deployment, instance: Instance | None = None) -> DeploymentOut:
    """Commit the queued job (with its audit row), start it, and answer with it."""
    await db.commit()
    await db.refresh(dep)
    deployer.runner.submit(dep.id, data.job_keys(dep, instance))
    return await deployment_out(db, dep)


async def _queue(db: AsyncSession, **kw: Any) -> Deployment:
    try:
        return await jobs.queue_job(db, **kw)
    except jobs.JobRefused as exc:
        raise refused(exc) from exc


def _audit_job(db: AsyncSession, ctx: AuthContext, request: Request, env: Environment, dep: Deployment,
               **extra: Any) -> None:
    opts = dep.options or {}
    slot = opts.get("slot")
    audit.record(db, "deployment.create", actor=ctx.user, target=dep, request=request,
                 summary=f"{data.job_label(dep.kind, slot=slot, back=bool(opts.get('back')))} of {env.name}",
                 details={"environment": env.name, "kind": dep.kind, "slot": slot,
                          "go_live": bool(opts.get("go_live")), **extra})


# ---------------------------------------------------------------------------- list, read


@router.get("")
async def list_environments(ctx: Reader, db: DB, include_deleted: bool = False) -> list[EnvironmentSummary]:
    stmt = select(Environment).order_by(Environment.name, Environment.created_at)
    if not include_deleted:
        stmt = stmt.where(Environment.deleted_at.is_(None))
    out = []
    for env in (await db.scalars(stmt)).all():
        mem = await environments.members(db, env)
        out.append(EnvironmentSummary.of(env, mem, await _last_job(db, env, [m.id for m in mem.values()])))
    return out


@router.get("/{env_id}")
async def get_environment(env_id: uuid.UUID, ctx: Reader, db: DB) -> EnvironmentOut:
    return await environment_out(db, await _get(db, env_id, deleted=True), ctx)


@router.get("/{env_id}/env")
async def get_env(env_id: uuid.UUID, ctx: Writer, db: DB) -> dict[str, dict[str, str]]:
    """The environment's own variables (secrets are never returned). 409 when they can't be decrypted, so a
    read-modify-write can't erase them."""
    env = await _get(db, env_id, deleted=True)
    if await env_unreadable(db, env):
        raise HTTPException(status.HTTP_409_CONFLICT, ENV_UNREADABLE)
    return {"env": dict(env.env or {})}


@router.get("/{env_id}/deployments")
async def environment_deployments(
    env_id: uuid.UUID, ctx: Reader, db: DB, limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[DeploymentOut]:
    """Every job of the environment: its members' and its own, newest first."""
    need(ctx, Perm.DEPLOYMENTS_READ)
    env = await _get(db, env_id, deleted=True)
    ids = list((await db.scalars(select(Instance.id).where(Instance.environment_id == env.id))).all())
    cond = Deployment.environment_id == env.id
    if ids:
        cond = or_(cond, Deployment.instance_id.in_(ids))
    deps = await db.scalars(select(Deployment).options(defer(Deployment.log, raiseload=True)).where(cond)
                            .order_by(Deployment.created_at.desc()).limit(limit))
    return await deployment_outs(db, list(deps))


# ------------------------------------------------------------------------------- create


@router.post("", status_code=201, response_model=EnvironmentOut)
async def create_environment(body: EnvironmentCreate, ctx: Writer, request: Request, db: DB,
                             check: bool = False) -> Any:
    """Create an environment (§9.1): its slots' instances, its secrets and its names; no host is touched.
    ``?check=true`` runs every refusal and answers the plan, writing nothing. Refusals answer
    ``{detail, field}``. A seed snapshot needs data:reset (and snapshots:download for another repository's).

    Placement ``digitalocean`` (phase 4 §15.1) needs providers:spend and the typed monthly total
    (``confirm_cost``: 422 when it isn't the estimate, 409 when the estimate moved since it was shown);
    ``?check=true`` answers the cost at the top level. New VMs (phase 5 §9.2) under ``hosts.<slot>.machine``:
    an address another create took at the commit answers 409 (Decision 43). ``DigitalOceanError`` is 502."""
    try:
        plan = await environments.validate_create(db, body, ctx)
    except CreateRefused as exc:
        return field_answer(exc)
    except DigitalOceanError as exc:
        raise do_error(exc) from exc
    if check:
        return JSONResponse(plan.to_json(), status_code=200)
    vms = _claimed_vms(plan.planned)
    try:
        env = await environments.create(db, plan, ctx, request=request)
        env_id = env.id
        await db.commit()
    except CreateRefused as exc:
        return field_answer(exc)
    except IntegrityError as exc:
        await db.rollback()
        answer = await claim_taken(db, exc, vms)
        if answer is None:
            raise
        return answer
    return await environment_out(db, await _get(db, env_id), ctx, warnings=plan.warnings)


# -------------------------------------------------------------------------------- update


async def _branch_manifest(ctx: AuthContext, env: Environment) -> tuple[manifest.Manifest, str | None]:
    """The environment's slipway.yml (and its env_file) at the branch head, as create read them."""
    from slipway.services.github import GitHubError

    read = environments.github_reader(ctx.user)
    repo, branch, path = env.repository, env.branch, env.manifest_file or manifest.DEFAULT_FILE
    try:
        text = await read(repo, branch, path)
    except GitHubError as exc:
        raise CreateRefused(502, f"Could not read {path} on {branch} of {repo.full_name}: {exc}", "branch") from exc
    if text is None:
        raise CreateRefused(409, f"{repo.full_name} has no {path} at {branch}", "manifest_file")
    try:
        man = manifest.parse(text)
    except manifest.ManifestError as exc:
        raise CreateRefused(409, str(exc), "manifest_file") from exc
    template = None
    if man.env_file:
        try:
            template = await read(repo, branch, man.env_file)
        except GitHubError as exc:
            raise CreateRefused(502, f"Could not read {man.env_file} on {branch} of {repo.full_name}: {exc}",
                                "branch") from exc
        if template is None:
            raise CreateRefused(409, f"{repo.full_name} has no {man.env_file} at {branch} (slipway.yml's env_file)",
                                "manifest_file")
    return man, template


async def _replan(db: AsyncSession, env: Environment, mem: dict[str, Instance], ctx: AuthContext, *,
                  settings: dict[str, str], services: list[str] | None,
                  env_vars: dict[str, str]) -> list[dict[str, Any]]:
    """Check new settings, services and variables the way create does (§9.1 rules 5-6) and return the names
    they give (``env.hostnames``); raise CreateRefused. Plans with placeholder ports, as create does."""
    man, template = await _branch_manifest(ctx, env)
    known = {s.name for s in man.optional_services}
    if services is not None:
        wrong = sorted(set(services) - known)
        if wrong:
            raise CreateRefused(422, f"{wrong[0]} isn't an optional service of {env.manifest_file}", "services")
    secrets = {**manifest.new_secrets(man, dict(env.app_secrets or {})), **dict(env.app_secrets or {})}
    apps = environments.app_members(mem)
    if not apps:
        return list(env.hostnames or [])
    app = apps[0]
    data_member = mem.get(DATA_SLOT)
    managed = env.data_mode == DataMode.MANAGED
    if managed:
        roles = ["slot"]  # the data is a managed database: the slots' role only, as create checks it (P4 §15.1)
    else:
        roles = ["app"] if env.data_mode == DataMode.SLOT or data_member is None else ["server", "slot"]
    plans: dict[str, manifest.AppPlan] = {}
    for role in roles:
        try:
            manifest.check_instance_env(man, env_vars, role, managed=managed, edge=managed)
        except manifest.ManifestError as exc:
            raise CreateRefused(422, str(exc).replace("the instance's environment variables",
                                                      "the environment's variables"), "env") from exc
        member = data_member if role == "server" else app
        assert member is not None and member.host is not None
        extra: dict[str, Any] = {}
        if managed:
            extra = {"data_values": environments.managed_placeholders(man), "managed": True,
                     "edge_values": dict(environments.EDGE_PLACEHOLDERS)}
        elif role == "slot":
            extra = {"data_values": plans["server"].provides}
        elif role == "server":
            extra = {"server_values": {"host": member.host.upstream_address,
                                       "clients": [m.host.client_address for m in apps if m.host is not None]}}
        try:
            plans[role] = manifest.plan(
                man, template=template,
                builtins=environments._placeholder_builtins(env.name, str(member.slot), member.host),
                settings=settings, chosen=services, host_ports={}, secrets=secrets, env=env_vars, role=role,
                **extra,
            )
        except manifest.ManifestError as exc:
            raise CreateRefused(422, str(exc).replace("of the instance", "of the environment"), "settings") from exc
    hostnames = environments.routes_of(plans.get("app") or plans["slot"], man, "active")
    if "server" in plans:
        hostnames += environments.routes_of(plans["server"], man, "server")
    taken = await environments.hostname_conflict(db, [h["hostname"] for h in hostnames], environment_id=env.id)
    if taken:
        raise CreateRefused(409, taken, "hostnames")
    return hostnames


# Traffic follows placement (phase 4 §3.2, Decision 24): a DigitalOcean environment's names go through its load
# balancer and its records point at the load balancer's address, which its edge step writes.
DO_SWITCH_FIXED = ("{env}'s traffic goes through its load balancer: a DigitalOcean environment keeps the "
                   "DigitalOcean load balancer")
DO_ADDRESS_FIXED = "{env}'s records point at its load balancer, whose address Slipway sets: leave the address out"
DO_DNS_ALWAYS = "A DigitalOcean environment always publishes its names in Cloudflare: DNS stays on"


async def _traffic_of(db: AsyncSession, env: Environment, wanted: dict[str, Any], *, two: bool,
                      names: set[str]) -> dict[str, Any]:
    """§9.1 rule 7 for a changed ``traffic``; raise CreateRefused. Phase 4 §3.2: on a DigitalOcean environment
    the switch stays ``do_lb``, DNS stays on and its address stays the load balancer's (only ``proxied``
    changes); ``do_lb`` is refused on an SSH environment.

    ``wanted`` holds only the keys the PATCH sent. On a DigitalOcean environment a missing ``switch`` is its
    stored one, and a missing ``dns`` keeps the stored records as they are (the Settings page sends neither unless
    ``proxied`` is shown); an SSH environment keeps phase 3's reading of a missing switch as ``none``. The
    records' address is the load balancer's, written by the edge step, so it may still be empty before the first
    deploy: the public IP isn't asked for (as at create)."""
    on_do = environments.is_digitalocean(env)
    stored_switch = (env.traffic or {}).get("switch")
    switch = str(wanted.get("switch") or (stored_switch if on_do and "switch" not in wanted else None) or "none")
    current_dns = (env.traffic or {}).get("dns") if isinstance((env.traffic or {}).get("dns"), dict) else None
    if on_do and switch == environments.DO_LB and "dns" not in wanted:
        if current_dns is not None:  # the stored records stand, so the names must still be in the zone (rule 7)
            config = await cloudflare.load_config(db)
            if config is None:
                raise CreateRefused(409, environments.SET_UP_CLOUDFLARE, "traffic.dns")
            outside = sorted(n for n in names if not cloudflare.in_zone(n, config.zone))
            if outside:
                raise CreateRefused(409, f"{outside[0]} isn't in the Cloudflare zone {config.zone}", "traffic.dns")
        return {"switch": switch, "dns": dict(current_dns) if current_dns is not None else None}
    if on_do and switch != environments.DO_LB:
        raise CreateRefused(409, DO_SWITCH_FIXED.format(env=env.name), "traffic.switch")
    if not on_do and switch == environments.DO_LB:
        raise CreateRefused(409, environments.LB_NEEDS_DO, "traffic.switch")
    dns_in = wanted.get("dns")
    if on_do:
        if not isinstance(dns_in, dict):
            raise CreateRefused(409, DO_DNS_ALWAYS, "traffic.dns")
        typed = dns_in.get("address")
        stored = (current_dns or {}).get("address")
        if typed not in (None, "") and str(typed).strip() != str(stored or ""):
            raise CreateRefused(409, DO_ADDRESS_FIXED.format(env=env.name), "traffic.dns.address")
        dns_in = {**dns_in, "address": stored}
    if switch == "switchyard" and await switchyard.load_config(db) is None:
        raise CreateRefused(409, environments.SET_UP_SWITCHYARD, "traffic")
    if two and switch not in ("switchyard", environments.DO_LB):
        raise CreateRefused(409, environments.BLUE_GREEN_SWITCH, "traffic")
    dns = None
    if isinstance(dns_in, dict):
        config = await cloudflare.load_config(db)
        if config is None:
            raise CreateRefused(409, environments.SET_UP_CLOUDFLARE, "traffic.dns")
        try:
            address = cloudflare.clean_public_ip(dns_in.get("address"))
        except ValueError as exc:
            raise CreateRefused(422, str(exc), "traffic.dns") from exc
        if address is None and not config.public_ip and not on_do:
            raise CreateRefused(409, "Give the records an address, or set the public IP in Settings → Integrations",
                                "traffic.dns")
        outside = sorted(n for n in names if not cloudflare.in_zone(n, config.zone))
        if outside:
            raise CreateRefused(409, f"{outside[0]} isn't in the Cloudflare zone {config.zone}", "traffic.dns")
        proxied = dns_in.get("proxied")
        dns = {"provider": "cloudflare", "address": address,
               "proxied": config.proxied if proxied is None else bool(proxied)}
    return {"switch": switch, "dns": dns}


@router.patch("/{env_id}", response_model=EnvironmentOut)
async def update_environment(env_id: uuid.UUID, body: EnvironmentUpdate, ctx: Writer, request: Request,
                             db: DB, check: bool = False) -> Any:
    """Change the settings, services, variables, TLS modes, traffic or data options. Each slot uses them from its
    next deploy (§6 Settings edits). Refused while a job of the environment is queued or running. ``cloud`` grows
    a DigitalOcean environment's sizes (providers:spend, the typed total ``confirm_cost``; P4 §15.7).

    ``?check=true`` is for a grow only (``cloud``, and nothing else but ``confirm_cost``): it runs every refusal
    of the grow but the typed total and answers ``ChangeCheckOut`` (``from``, ``to``, the new estimate with its
    ``delta``), writing nothing."""
    env = await _get(db, env_id)
    gone = environments.deleting_text(env)
    if gone:
        raise HTTPException(status.HTTP_409_CONFLICT, gone)
    sent = body.model_dump(exclude_unset=True)
    if check:
        others = sorted(k for k in sent if k not in ("cloud", "confirm_cost"))
        if body.cloud is None or others:
            return field_answer(CreateRefused(422, "A check prices a change of sizes only: send cloud and nothing "
                                                   "else", others[0] if others else "cloud"))
        try:
            grown = await environments.grow_plan(db, env, body.cloud, ctx)
        except CreateRefused as exc:
            await db.rollback()
            return field_answer(exc)
        except DigitalOceanError as exc:
            raise do_error(exc) from exc
        answer = _check_answer(grown.to_json())
        await db.rollback()
        return answer
    try:
        async with deployer.runner.exclusive(data.env_keys(env.id, None)):
            busy = await jobs.busy_job(db, env, data.env_keys(env.id, None))
            if busy is not None:
                raise HTTPException(status.HTTP_409_CONFLICT, environments.busy_text(env, busy))
            try:
                # Growing a DigitalOcean environment's sizes (P4 §15.7): checked against the catalog read here,
                # before any row is locked, then written with the rest (``grow`` locks the account row).
                grown = (await environments.grow_plan(db, env, body.cloud, ctx, confirm_cost=body.confirm_cost)
                         if body.cloud is not None else None)
                changed = await _apply_update(db, env, body, sent, ctx)
                if grown is not None:
                    await environments.grow(db, grown, ctx, request=request)
                    changed.append("sizes")
            except CreateRefused as exc:
                await db.rollback()
                return field_answer(exc)
            except DigitalOceanError as exc:
                raise do_error(exc) from exc
            others = [c for c in changed if c != "sizes"]
            if others or grown is None:
                audit.record(db, "environment.update", actor=ctx.user, target=env, request=request,
                             summary=f"Updated environment {env.name}: {', '.join(others) or 'no changes'}",
                             details={"changed": others})
            await db.commit()
    except deployer.RunnerBusy as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return await environment_out(db, await _get(db, env.id), ctx)


async def _remove_records(db: AsyncSession, env: Environment, ctx: AuthContext, *,
                          forget_lost_zone: bool = False) -> str | None:
    """Turning DNS off removes the records Slipway keeps for the environment first (teardown's ``undns``:
    delete what it made and still carries its comment, forget what it claimed), so none is left behind with
    no environment publishing it. Raise CreateRefused, with DNS left on, when Cloudflare can't be used.

    With ``forget_lost_zone``, records whose Cloudflare zone is gone (Cloudflare doesn't know the zone they
    were made in) are forgotten first, without deleting anything."""
    rows = await resources.owned(db, env.id, cloudflare.PROVIDER, cloudflare.KIND)
    if not rows:
        return None
    await db.commit()  # nothing is written yet; publish_dns records in its own sessions
    lost: list[str] = []
    try:
        if forget_lost_zone:
            lost = await traffic.forget_lost_zone(env, actor=ctx.user)
            rows = await resources.owned(db, env.id, cloudflare.PROVIDER, cloudflare.KIND)
            await db.commit()
        plan = await traffic.remove_dns(env, actor=ctx.user) if rows else None
    except traffic.DnsRefused as exc:
        raise CreateRefused(409, f"{exc}. Slipway keeps {len(rows)} DNS record(s) for {env.name} in Cloudflare and "
                            "removes them when DNS is turned off", "traffic.dns") from exc
    except (cloudflare.CloudflareError, traffic.TrafficError) as exc:
        zone_gone = isinstance(exc, cloudflare.CloudflareError) and exc.status_code == 404 \
            and bool(set(exc.codes) & cloudflare.ZONE_CODES)
        hint = (" If that zone was deleted or moved to another account, its records went with it: turn DNS off "
                "with 'Forget the records whose zone is gone'.") if zone_gone and not forget_lost_zone else ""
        raise CreateRefused(502, f"{exc}. DNS stays on for {env.name}: Slipway removes its records when DNS is "
                            f"turned off, so try again once Cloudflare answers.{hint}", "traffic.dns") from exc
    deleted = sum(1 for c in plan.changes if c.action == "delete") if plan else 0
    forgot = sum(1 for c in plan.changes if c.action == "forget") if plan else 0
    text = f"DNS records removed ({deleted} deleted, {forgot} left in Cloudflare and forgotten"
    if lost:
        text += f", {len(lost)} forgotten because their Cloudflare zone is gone"
    return text + ")"


async def _apply_update(db: AsyncSession, env: Environment, body: EnvironmentUpdate, sent: dict[str, Any],
                        ctx: AuthContext) -> list[str]:
    """Check and write a PATCH; the names of what changed (only the names of variables, never values)."""
    mem = await environments.members(db, env)
    apps = environments.app_members(mem)
    owner = environments.owner_in(env, mem)
    changed: list[str] = []
    settings = dict(env.app_settings or {}) if body.settings is None else dict(body.settings)
    services = env.app_services if "services" not in sent else body.services
    env_vars = dict(env.env or {}) if body.env is None else dict(body.env)
    hostnames = list(env.hostnames or [])
    if body.settings is not None or "services" in sent or body.env is not None:
        planned = await _replan(db, env, mem, ctx, settings=settings, services=services, env_vars=env_vars)
        # The names a slot's live release serves stay until a deploy drops them everywhere: the new settings
        # only apply from each slot's next deploy, so the names live now keep their DNS records.
        hostnames = environments.refreshed_hostnames(
            env.hostnames or [], planned, follows=("active", "server"), held=environments.held_names(mem.values()))
        if hostnames == sorted(env.hostnames or [], key=lambda h: str(h.get("hostname"))):
            hostnames = list(env.hostnames or [])  # the same names: no change to record
    names = {str(h.get("hostname")) for h in hostnames if h.get("hostname")}
    route_tls = dict(env.route_tls or {}) if body.route_tls is None else dict(body.route_tls)
    for hostname in route_tls:
        if hostname not in names:
            raise CreateRefused(422, f"{hostname} isn't one of {env.name}'s names", "route_tls")
    traffic_now = dict(env.traffic or {})
    if body.traffic is not None:
        traffic_now = await _traffic_of(db, env, body.traffic.model_dump(exclude_unset=True), two=len(apps) == 2,
                                        names=names)
    elif (traffic_now.get("dns") and hostnames != list(env.hostnames or [])):
        # New names must still be inside the zone their records go to.
        traffic_now = await _traffic_of(db, env, {"switch": traffic_now.get("switch"),
                                                  "dns": {"address": traffic_now["dns"].get("address"),
                                                          "proxied": traffic_now["dns"].get("proxied")}},
                                        two=len(apps) == 2, names=names)
    if body.auto_activate and len(apps) != 2:
        raise CreateRefused(422, "Activate automatically needs two slots", "auto_activate")
    if body.auto_activate and env.production:  # as create (ck_environments_production_auto)
        raise CreateRefused(409, "A production environment waits for Activate: turn Activate automatically off",
                            "auto_activate")
    if body.keep_backups is not None and not 1 <= body.keep_backups <= 100:
        raise CreateRefused(422, "Keep 1 to 100 backups", "keep_backups")
    removed = None
    # A DigitalOcean environment's DNS never goes off by a PATCH (``_traffic_of``), so it removes no records.
    if body.traffic is not None and not traffic_now.get("dns") and not environments.is_digitalocean(env):
        removed = await _remove_records(db, env, ctx, forget_lost_zone=body.traffic.forget_lost_zone)

    if body.settings is not None and settings != (env.app_settings or {}):
        env.app_settings = settings
        changed.append("settings")
    if "services" in sent and services != env.app_services:
        env.app_services = services
        changed.append("services")
    if body.env is not None:
        old = dict(env.env or {})
        if env_vars != old or await env_unreadable(db, env):
            env.env = env_vars
            keys = sorted(set(old) ^ set(env_vars) | {k for k in env_vars if old.get(k) != env_vars[k]})
            changed.append("variables" + (f" ({', '.join(keys)})" if keys else ""))
    if hostnames != list(env.hostnames or []):
        env.hostnames = hostnames
        changed.append("names")
    if body.route_tls is not None and route_tls != (env.route_tls or {}):
        env.route_tls = route_tls
        changed.append("TLS modes")
    if body.traffic is not None and traffic_now != (env.traffic or {}):
        env.traffic = traffic_now
        changed.append("traffic")
    if removed:
        changed.append(removed)
    if body.auto_activate is not None and bool(body.auto_activate) != bool(env.auto_activate):
        env.auto_activate = bool(body.auto_activate)
        changed.append("auto activate")
    if owner is not None:
        if body.keep_backups is not None and body.keep_backups != owner.keep_backups:
            owner.keep_backups = body.keep_backups
            changed.append("backups kept")
        if body.seed_content is not None and bool(body.seed_content) != bool(owner.seed_content):
            owner.seed_content = bool(body.seed_content)
            changed.append("starter content")
    return changed


# -------------------------------------------------------------------------------- deploy


@router.post("/{env_id}/deploy", status_code=202)
async def deploy_environment(env_id: uuid.UUID, ctx: Deployer, request: Request, db: DB,
                             body: EnvDeployIn | None = None) -> DeploymentOut:
    """Deploy the branch (§9.2, §9.3, §9.7): to the idle slot (Slipway picks it unless ``slot`` is given), or to
    the data server with ``target: data``. A new environment with a data server starts with the data server; the
    chain then deploys the first slot and activates it. A deploy that goes live by itself needs traffic:switch."""
    body = body or EnvDeployIn()
    env = await _get(db, env_id)
    mem = await environments.members(db, env)
    owner = environments.owner_in(env, mem)
    options: dict[str, Any] = {}
    # Only a data server is deployed first; a managed environment never deploys its data owner (Decision 21).
    server_first = (env.data_mode == DataMode.SERVER and owner is not None and owner.slot == DATA_SLOT
                    and data.live_state(owner) is None and body.slot is None)
    if body.target == "data" or server_first:
        if env.data_mode == DataMode.MANAGED:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                f"{env.name}'s data is in its managed database: it has no data server to deploy")
        if env.data_mode == DataMode.SLOT or DATA_SLOT not in mem:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                f"{env.name} keeps its data in {environments.owner_slot(env)}: it has no data server")
        instance = mem[DATA_SLOT]
        if not any(m.current_commit_sha for m in environments.app_members(mem)):
            options["chain"] = True  # the hook then deploys the first slot (§8.5 rule 1)
    else:
        slot = body.slot or environments.target_slot(env, mem)
        found = mem.get(slot)
        if found is None:
            raise HTTPException(status.HTTP_409_CONFLICT, f"{env.name} has no slot {slot}")
        instance = found
        if env.status == EnvironmentStatus.NEW:
            options["chain"] = True
    if body.acknowledge_schema:
        options["behind_ok"] = True  # past the lag check (§7.6)
    if body.commit_sha:
        # Deploy again, confirming (§7.6): the refused deploy's own commit, so the acknowledgement covers the
        # release it was given for. Only with it, only to an app slot, and only a commit that slot was deployed at.
        if not body.acknowledge_schema or instance.slot not in environments.APP_SLOTS:
            raise HTTPException(422,
                                "A commit is chosen only to deploy an app slot again, confirming")
        known = await db.scalar(select(Deployment.id).where(
            Deployment.instance_id == instance.id, Deployment.kind == DeploymentKind.DEPLOY,
            Deployment.commit_sha == body.commit_sha).limit(1))
        if known is None:
            raise HTTPException(status.HTTP_409_CONFLICT, f"No deploy of {instance.slot} was of commit "
                                f"{body.commit_sha[:7]}: Slipway deploys the newest commit of {env.branch}")
        options["pin_commit"] = body.commit_sha
    dep = await _queue(db, instance=instance, environment=env, user=ctx.user, kind=DeploymentKind.DEPLOY,
                       options=options)
    _audit_job(db, ctx, request, env, dep, behind_ok=bool(body.acknowledge_schema))
    return await _submit(db, dep, instance)


# ----------------------------------------------------------------------------- traffic


async def _cert_renewed(db: AsyncSession, env: Environment, slot: str,
                        blockers: list[str]) -> tuple[list[str], list[str]]:
    """``(blockers, renewed)``: as the job's own check (env_jobs._activate), when Activate lists its certificate
    step, that step renews before the switch, so a certificate that doesn't cover the names yet doesn't refuse
    it; those blockers are ``renewed``. Used by POST /activate and the dialog's plan (GET /traffic/plan)."""
    from slipway.services.env_jobs import CERT_NOT_COVERING

    if not any(b.startswith(CERT_NOT_COVERING) for b in blockers):
        return blockers, []
    mem = await environments.members(db, env)
    if not environments.certificate_due(env, mem.get(slot), mem):
        return blockers, []
    return ([b for b in blockers if not b.startswith(CERT_NOT_COVERING)],
            [b for b in blockers if b.startswith(CERT_NOT_COVERING)])


async def _plan_blockers(db: AsyncSession, env: Environment, slot: str) -> None:
    """§9.5 refusal 6: the switch's plan, read only; a blocker refuses before anything is queued."""
    backend = traffic.backend_for(env)
    if backend is None:
        return
    try:
        ctx = await traffic.context(db, env, "activate", slot=slot)
        # Switchyard's settings only for Switchyard; another backend says itself why it can't be used (as plan_for).
        if isinstance(backend, traffic.SwitchyardBackend):
            if ctx.config is None:
                raise HTTPException(status.HTTP_409_CONFLICT, environments.SET_UP_SWITCHYARD)
        else:
            why = await backend.configured(db)
            if why:
                raise HTTPException(status.HTTP_409_CONFLICT, why)
        plan = await backend.plan(ctx)
    except traffic.TrafficError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except ssh.HostNotBuilt as exc:
        raise not_built(exc) from exc
    except (switchyard.SwitchyardError, DigitalOceanError) as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    blockers, _renewed = await _cert_renewed(db, env, slot, list(plan.blockers))
    if blockers:
        raise HTTPException(status.HTTP_409_CONFLICT, "; ".join(blockers) + "; Slipway changed nothing")


@router.post("/{env_id}/activate", status_code=202)
async def activate(env_id: uuid.UUID, body: ActivateIn, ctx: Switcher, request: Request, db: DB) -> DeploymentOut:
    """Activate a slot (§9.5), or switch back to the one that was live before (§9.6): its smoke test, DNS, then
    one switch in Switchyard (or the load balancer) that is checked and put back on any failure. A production
    environment needs its name typed (``confirm``, P4 §13, Decision 39: 422 without it)."""
    env = await _get(db, env_id)
    mem = await environments.members(db, env)
    active = environments.active_member(env, mem)
    last = (env.traffic_state or {}).get("last")
    back = (isinstance(last, dict) and last.get("from_slot") == body.slot and active is not None
            and active.slot != body.slot)
    options: dict[str, Any] = {"slot": body.slot, **({"back": True} if back else {})}
    typed = jobs.confirm_refusal(env, DeploymentKind.ACTIVATE, {**options, "confirm": body.confirm})
    if typed is not None:
        raise refused(typed)  # typed text first (422), before any other refusal
    if body.confirm is not None:
        options["confirm"] = body.confirm
    found = await jobs.job_refusal(db, environment=env, user=ctx.user, kind=DeploymentKind.ACTIVATE,
                                   options=options, members=mem)
    if found is not None:
        raise refused(found)
    await _plan_blockers(db, env, body.slot)
    dep = await _queue(db, environment=env, user=ctx.user, kind=DeploymentKind.ACTIVATE, options=options)
    _audit_job(db, ctx, request, env, dep, back=back)
    return await _submit(db, dep)


@router.post("/{env_id}/publish", status_code=202)
async def publish(env_id: uuid.UUID, ctx: Switcher, request: Request, db: DB) -> DeploymentOut:
    """Publish names (§9.11): bring Switchyard and DNS up to date for what is live, without a deploy."""
    env = await _get(db, env_id)
    dep = await _queue(db, environment=env, user=ctx.user, kind=DeploymentKind.PUBLISH)
    _audit_job(db, ctx, request, env, dep)
    return await _submit(db, dep)


@router.post("/{env_id}/discard", status_code=202)
async def discard(env_id: uuid.UUID, body: SlotIn, ctx: Discarder, request: Request, db: DB) -> DeploymentOut:
    """Discard a failed deploy to the idle slot (§9.14): stop it, check the active slot on the data as it is,
    and mark the data as checked. Nothing is restored."""
    env = await _get(db, env_id)
    dep = await _queue(db, environment=env, user=ctx.user, kind=DeploymentKind.DISCARD, options={"slot": body.slot})
    _audit_job(db, ctx, request, env, dep)
    return await _submit(db, dep)


# The permission each follow-up of the chain needs when started by hand (§8.5).
FOLLOW_UP_PERMISSION = {DeploymentKind.ACTIVATE: Perm.TRAFFIC_SWITCH, DeploymentKind.TEARDOWN: Perm.ENVIRONMENTS_DELETE,
                        DeploymentKind.DEPLOY: Perm.DEPLOYMENTS_CREATE}


@router.post("/{env_id}/notice/continue", status_code=202)
async def continue_chain(env_id: uuid.UUID, ctx: Reader, request: Request, db: DB,
                         body: ConfirmIn | None = None) -> DeploymentOut:
    """Start the job the chain didn't start (the notice's button, D12), with that job's own permission. An
    Activate of a production environment while a slot is live needs its name typed (``confirm``, Decision 39:
    422 without it)."""
    env = await _get(db, env_id)
    notice = env.notice if isinstance(env.notice, dict) else None
    nxt_in = (notice or {}).get("next")
    if not isinstance(nxt_in, dict) or not nxt_in.get("kind"):
        raise HTTPException(status.HTTP_409_CONFLICT, f"{env.name} has no stopped chain to continue")
    finished = await db.get(Deployment, data._uuid(notice.get("deployment_id"))) if notice else None
    nxt = await environments.next_job(db, finished) if finished is not None else None
    if nxt is None:
        kind, slot = str(nxt_in["kind"]), nxt_in.get("slot")
        opts: dict[str, Any] = {"confirmed": True} if kind == DeploymentKind.TEARDOWN else {"slot": slot}
        nxt = environments.NextJob(kind, slot, opts)
    need(ctx, FOLLOW_UP_PERMISSION.get(nxt.kind, Perm.DEPLOYMENTS_CREATE))
    options = dict(nxt.options)
    if nxt.kind == DeploymentKind.ACTIVATE and body is not None and body.confirm is not None:
        options["confirm"] = body.confirm  # queue_job's confirm_refusal checks it first
    if finished is not None:
        if await environments._already_queued(db, env.id, finished.id) is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, f"{nxt.label()} was already started")
        options["after"] = finished.id.hex
    mem = await environments.members(db, env)
    instance = mem.get(str(nxt.slot)) if nxt.kind == DeploymentKind.DEPLOY else None
    if nxt.kind == DeploymentKind.DEPLOY and instance is None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{env.name} has no slot {nxt.slot}")
    dep = await _queue(db, instance=instance, environment=env, user=ctx.user, kind=nxt.kind, options=options)
    _audit_job(db, ctx, request, env, dep, continued=True)
    return await _submit(db, dep, instance)


@router.get("/{env_id}/traffic/plan")
async def traffic_plan(env_id: uuid.UUID, ctx: Reader, db: DB, slot: str | None = None) -> dict[str, Any]:
    """The dry run (§10.7): Switchyard's and DNS's plans with no write. Without ``slot`` the sync plan (what
    Publish names would do), with ``slot`` what activating it would do."""
    env = await _get(db, env_id, deleted=True)
    if env.is_deleted:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{env.name} was deleted")
    if slot is not None:
        mem = await environments.members(db, env)
        if slot not in APP_SLOTS or slot not in mem:
            raise HTTPException(UNPROCESSABLE, "Only an app slot can take traffic")
    try:
        answer = await traffic.plan_for(env, slot, db)
        switch = answer.get("switch")
        if slot is not None and switch:
            # The Activate dialog enables only with no blockers: one its certificate step renews is a note (F31).
            switch["blockers"], renewed = await _cert_renewed(db, env, slot, list(switch.get("blockers") or []))
            switch["notes"] = [*(switch.get("notes") or []),
                               *(f"{b.split(':', 1)[0]}: Activate's certificate step renews it before the switch"
                                 for b in renewed)]
        return answer
    except (switchyard.SwitchyardError, cloudflare.CloudflareError, DigitalOceanError) as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    except traffic.TrafficError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except ssh.HostNotBuilt as exc:
        raise not_built(exc) from exc


@router.post("/{env_id}/traffic/resolve", response_model=EnvironmentOut)
async def resolve(env_id: uuid.UUID, body: ConfirmIn, ctx: Switcher, request: Request, db: DB) -> Any:
    """Settle an unresolved switch (§9.12): read Switchyard and, when every name points at one slot, record that
    slot as live."""
    from slipway.services import env_jobs

    env = await _get(db, env_id)
    check_confirm(env, body.confirm)
    await db.commit()  # release the DB connection: resolve reads Switchyard and writes in its own session
    try:
        await env_jobs.resolve(env.id, actor=ctx.user, request=request)
    except env_jobs.ResolveRefused as exc:
        raise HTTPException(exc.status, exc.text) from exc
    except deployer.RunnerBusy as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except (switchyard.SwitchyardError, DigitalOceanError) as exc:  # do_lb reads DigitalOcean (P4 §11.6)
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    return await environment_out(db, await _get(db, env.id), ctx)


# ------------------------------------------------------- production: retire, deactivate, certificate (P4 §13)


@router.post("/{env_id}/retire", response_model=EnvironmentOut)
async def retire(env_id: uuid.UUID, body: RetireIn, ctx: Deleter, request: Request, db: DB) -> Any:
    """Retire a production environment (P4 §13): it keeps serving, but no slot can be activated any more; then
    it can be taken off the air and deleted. Its name typed (422)."""
    env = await _get(db, env_id)
    try:
        await environments.retire(db, env, ctx, body.confirm, request=request)
    except CreateRefused as exc:
        await db.rollback()
        return field_answer(exc)
    await db.commit()
    return await environment_out(db, await _get(db, env_id), ctx)


@router.delete("/{env_id}/retire", response_model=EnvironmentOut)
async def unretire(env_id: uuid.UUID, ctx: Deleter, request: Request, db: DB, body: RetireIn | None = None) -> Any:
    """Un-retire (Decision 38): refused while another production environment of the same app isn't retiring.
    Its name typed (422)."""
    env = await _get(db, env_id)
    try:
        await environments.unretire(db, env, ctx, (body or RetireIn()).confirm, request=request)
    except CreateRefused as exc:
        await db.rollback()
        return field_answer(exc)
    await db.commit()
    return await environment_out(db, await _get(db, env_id), ctx)


@router.post("/{env_id}/deactivate", status_code=202)
async def deactivate(env_id: uuid.UUID, body: ConfirmIn, ctx: Darkener, request: Request, db: DB) -> DeploymentOut:
    """Take a retiring production environment off the air (P4 §13, kind ``deactivate``): the load balancer stops
    sending traffic to the active slot, and its names answer 503 until their records are moved or removed. Its
    name typed (422); traffic:switch and environments:delete. Audit ``environment.deactivate``."""
    env = await _get(db, env_id)
    check_confirm(env, body.confirm)
    mem = await environments.members(db, env)
    active = environments.active_member(env, mem)
    dep = await _queue(db, environment=env, user=ctx.user, kind=DeploymentKind.DEACTIVATE,
                       options={"confirmed": True})
    _audit_job(db, ctx, request, env, dep)
    audit.record(db, "environment.deactivate", actor=ctx.user, target=env, request=request,
                 summary=f"Take {env.name} off the air" + (f" (traffic off {active.slot})" if active else ""),
                 details={"name": env.name, "by": ctx.user.display_name if ctx.user else None,
                          "slot": active.slot if active is not None else None, "deployment": str(dep.id)})
    return await _submit(db, dep)


@router.post("/{env_id}/certificate", status_code=202)
async def renew_certificate(env_id: uuid.UUID, ctx: Switcher, request: Request, db: DB) -> DeploymentOut:
    """Renew the load balancer's certificate now (P4 §15.8, kind ``certificate``): the same job the renewal loop
    queues. A failed renewal leaves the old certificate serving."""
    env = await _get(db, env_id)
    if (env.traffic or {}).get("switch") != environments.DO_LB:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"{env.name} has no load balancer, so Slipway serves no certificate for it")
    if not await resources.owned(db, env.id, environments.DIGITALOCEAN, "load_balancer"):
        raise HTTPException(status.HTTP_409_CONFLICT, f"{env.name} has no load balancer yet: deploy it first")
    dep = await _queue(db, environment=env, user=ctx.user, kind=DeploymentKind.CERTIFICATE)
    _audit_job(db, ctx, request, env, dep)
    return await _submit(db, dep)


# ----------------------------------------------------------------------- the cloud (P4 §16)


@router.get("/{env_id}/cloud")
async def cloud_objects(env_id: uuid.UUID, ctx: Reader, db: DB) -> dict[str, Any]:
    """What a DigitalOcean environment has on DigitalOcean (P4 §16, §17.3's DigitalOcean card): every recorded
    object read live, ``ok``, ``gone`` (DigitalOcean doesn't have it) or ``changed`` (it no longer carries
    Slipway's marks), with its monthly price from the confirmed estimate, and each droplet's power. Nothing is
    written to DigitalOcean. A recorded droplet whose GET answered 404 marks its slot's host ``gone``, by
    ``do_provision._other_gone``'s rule (``mark_gone``), so the page and the fences see it (audit ``host.gone``);
    not while a job of the environment is queued or running, whose own steps read it. 502 with the client's text
    when DigitalOcean can't be read."""
    from slipway.models import ProviderAccount

    env = await _get(db, env_id, deleted=True)
    if not environments.is_digitalocean(env):
        raise HTTPException(status.HTTP_409_CONFLICT, f"{env.name} isn't on DigitalOcean")
    account = await db.get(ProviderAccount, env.provider_account_id) if env.provider_account_id else None
    if account is None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{env.name}'s DigitalOcean account was removed")
    token = account.secret
    rows = await _do_rows(db, env)
    stored = dict(env.cloud or {})
    out: dict[str, Any] = {
        "account": {"id": account.id, "name": account.name}, "team": env.provider_team,
        "region": stored.get("region"), "plan": stored.get("plan"), "cost": stored.get("cost"),
        "lb_ip": stored.get("lb_ip"), "certificate": stored.get("certificate"), "objects": [], "pending": [],
        "notes": [],
    }
    if not token:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"Slipway can't read {account.name}'s token any more: enter it again")
    await db.commit()  # release the DB connection while DigitalOcean is read
    try:
        out["objects"], out["pending"], out["notes"] = await _read_objects(env, token, rows)
    except DigitalOceanError as exc:
        raise do_error(exc) from exc
    out["notes"] += await _mark_gone_droplets(db, env, ctx, rows, out["objects"])
    return out


async def _mark_gone_droplets(db: AsyncSession, env: Environment, ctx: AuthContext, rows: list[Any],
                              objects: list[dict[str, Any]]) -> list[str]:
    """The hosts of the recorded droplets this read found gone (a 404 on their own GET, J13), marked ``gone``
    with ``do_provision.mark_gone``: each committed and audited on its own; the texts for ``notes``."""
    from slipway.models import Host, Resource
    from slipway.services import do_provision

    gone = {str(o["provider_id"]) for o in objects if o["kind"] == "droplet" and o["status"] == "gone"}
    if not gone or env.is_deleted:
        return []
    # Plain values first: each commit or rollback below expires the rows read before it.
    env_id, picked = env.id, [(r.id, str(r.provider_id)) for r in rows
                              if r.kind == "droplet" and str(r.provider_id) in gone]
    if await jobs.busy_job(db, env, data.env_keys(env_id, None)) is not None:
        await db.rollback()
        return []
    name = env.name
    # The user without a load (the request's session was committed before DigitalOcean was read).
    user_id = sa_inspect(ctx.user).identity[0] if ctx.user is not None else None
    texts: list[str] = []
    for row_id, droplet_id in picked:
        fresh = await db.get(Resource, row_id, populate_existing=True)  # still recorded, for the same droplet
        if fresh is None or str(fresh.provider_id) != droplet_id:
            continue
        inst = await do_provision.mark_gone(db, env_id, fresh)
        if inst is None:
            await db.rollback()
            continue
        host = await db.get(Host, inst.host_id)
        text = do_provision.gone_text(fresh.name, str(inst.slot))
        actor = await db.get(User, user_id) if user_id is not None else None
        audit.record(db, "host.gone", actor=actor, target=host, summary=text,
                     details={"environment": name, "slot": inst.slot, "droplet": fresh.name,
                              "droplet_id": droplet_id})
        await db.commit()
        texts.append(text)
    await db.rollback()
    return texts


async def _do_rows(db: AsyncSession, env: Environment) -> list[Any]:
    from slipway.models import Resource

    return list(await db.scalars(select(Resource).where(
        Resource.environment_id == env.id, Resource.provider == environments.DIGITALOCEAN)
        .order_by(Resource.kind, Resource.name)))


# What each kind costs a month, from the confirmed estimate's lines (``cloud.cost.lines``, P4 §12.1).
_COST_OBJECT = {"droplet": "droplet", "database": "database", "load_balancer": "load_balancer", "bucket": "spaces"}


def _monthly(env: Environment, kind: str) -> int | None:
    wanted = _COST_OBJECT.get(kind)
    if wanted is None:
        return 0
    for line in ((env.cloud or {}).get("cost") or {}).get("lines") or []:
        if isinstance(line, dict) and line.get("object") == wanted:
            unit = line.get("unit_cents", line.get("cents"))
            return int(unit) if unit is not None else None
    return None


async def _read_objects(env: Environment, token: str,
                        rows: list[Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Each recorded DigitalOcean object read live (one GET each; Spaces keys in one list): ``ok``, ``gone`` or
    ``changed`` by the marks the teardown's check reads (P4 §15.11 step 3). Pending creates are listed apart.
    The bucket isn't read here (it is on Spaces, not the API): it shows as recorded."""
    from slipway.services import certs, digitalocean, do_rules
    from slipway.services.digitalocean import DigitalOceanClient

    objects: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    notes: list[str] = []
    vpc_ids = {r.provider_id for r in rows if r.kind == "vpc" and not resources.is_pending(r)}
    async with DigitalOceanClient(token) as client:
        keys: dict[str, Any] | None = None
        for row in rows:
            if resources.is_pending(row):
                pending.append({"kind": row.kind, "name": row.name,
                                "sent_at": (row.details or {}).get("sent_at")})
                continue
            item: dict[str, Any] = {"kind": row.kind, "name": row.name, "provider_id": row.provider_id,
                                    "status": "ok", "detail": None, "monthly_cents": _monthly(env, row.kind)}
            live: dict[str, Any] | None = None
            ok = True
            if row.kind == "droplet":
                live = await client.droplet(row.provider_id)
                ok = live is None or do_rules.tagged_matches(live, row.name, env.id)
                if live is not None:
                    item["power"] = live.get("status")
                    size = live.get("size_slug") or (live.get("size") or {}).get("slug")
                    public, _private = digitalocean.droplet_ips(live)
                    item["detail"] = " · ".join(str(p) for p in (size, public) if p) or None
                    if live.get("status") == "off":
                        notes.append(f"{row.name} is powered off")
            elif row.kind == "database":
                live = await client.database(row.provider_id)
                ok = live is None or do_rules.tagged_matches(live, do_rules.database_name(env.name), env.id)
                if live is not None:
                    item["detail"] = f"{live.get('size')} × {live.get('num_nodes')}, {live.get('status')}"
            elif row.kind == "vpc":
                live = await client.vpc(row.provider_id)
                ok = live is None or (live.get("name") == do_rules.vpc_name(env.name)
                                      and do_rules.vpc_is_marked(live, env.id))
                if live is not None:
                    item["detail"] = live.get("ip_range")
            elif row.kind == "load_balancer":
                live = await client.load_balancer(row.provider_id)
                ok = live is None or (live.get("name") == do_rules.lb_name(env.name)
                                      and (not vpc_ids or live.get("vpc_uuid") in vpc_ids))
                if live is not None:
                    item["detail"] = " · ".join(str(p) for p in (live.get("ip"), live.get("status")) if p) or None
            elif row.kind == "firewall":
                live = await client.firewall(row.provider_id)
                ok = live is None or live.get("name") == do_rules.firewall_name(env.name)
            elif row.kind == "certificate":
                live = await client.certificate(row.provider_id)
                ok = live is None or bool(certs.name_pattern(env.name).match(str(live.get("name") or "")))
                if live is not None:
                    item["detail"] = f"valid until {live.get('not_after')}" if live.get("not_after") else None
            elif row.kind == "spaces_key":
                if keys is None:
                    keys = {str(k.get("access_key")): k for k in await client.spaces_keys()}
                live = keys.get(row.provider_id)
                ok = live is None or live.get("name") == row.name
            else:  # the bucket: recorded, not read here
                live = {"name": row.name}
                item["detail"] = "Recorded; Slipway reads it at teardown"
            if live is None:
                item["status"] = "gone"
            elif not ok:
                item["status"] = "changed"
                item["detail"] = f"It no longer looks like Slipway's {row.name}"
            objects.append(item)
    return objects, pending, notes


# --------------------------------------------------------------------------------- DNS


async def _dns_plan(db: AsyncSession, env: Environment) -> tuple[cloudflare.CloudflareConfig, traffic.Plan]:
    config = await cloudflare.load_config(db)
    if config is None:
        raise HTTPException(status.HTTP_409_CONFLICT, environments.SET_UP_CLOUDFLARE)
    try:
        plan = await traffic.dns_plan(env, db)
    except traffic.DnsRefused as exc:
        plan = exc.plan
    except cloudflare.CloudflareError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    return config, plan


@router.get("/{env_id}/dns")
async def dns_records(env_id: uuid.UUID, ctx: Reader, db: DB) -> dict[str, Any]:
    """Each name's DNS record as Cloudflare has it and what publishing would do (read only)."""
    env = await _get(db, env_id, deleted=True)
    if env.is_deleted or not (env.traffic or {}).get("dns"):
        return {"zone": None, "records": [], "blockers": []}
    config, plan = await _dns_plan(db, env)
    rows = {r.id: r for r in await resources.owned(db, env.id, cloudflare.PROVIDER, cloudflare.KIND)}
    records = []
    for change in plan.changes:
        record = change.after or change.before or {}
        row = rows.get(change.resource_id) if change.resource_id else None
        records.append({"hostname": change.hostname, "status": change.status or change.action,
                        "content": record.get("content"), "proxied": bool(record.get("proxied")),
                        "origin": row.origin if row is not None else None, "record_id": change.external_id,
                        "summary": change.summary})
    return {"zone": config.zone, "records": records, "blockers": list(plan.blockers)}


@router.post("/{env_id}/dns/claim")
async def claim_record(env_id: uuid.UUID, body: HostnameIn, ctx: Switcher, db: DB) -> dict[str, Any]:
    """Claim a name's A record that Slipway didn't make (§9.11): Slipway keeps it current from now on and never
    deletes it. Only for a name whose status is ``claimable``."""
    env = await _get(db, env_id)
    if not (env.traffic or {}).get("dns"):
        raise HTTPException(status.HTTP_409_CONFLICT, f"{env.name} doesn't publish DNS records")
    try:
        async with deployer.runner.exclusive(data.env_keys(env.id, DeploymentKind.ACTIVATE)):
            _, plan = await _dns_plan(db, env)
            change = next((c for c in plan.changes if c.hostname == body.hostname), None)
            if change is None:
                raise HTTPException(status.HTTP_409_CONFLICT, f"{body.hostname} isn't one of {env.name}'s names")
            if change.status != cloudflare.CLAIMABLE or not change.external_id:
                raise HTTPException(status.HTTP_409_CONFLICT,
                                    f"{body.hostname} can't be claimed ({change.status}): {change.summary}")
            record = change.before or {}
            details = {"zone_id": plan.meta.get("zone_id"), "type": "A", "content": record.get("content"),
                       "proxied": bool(record.get("proxied"))}
            await db.commit()  # resources.record writes in its own session
            try:
                row_id = await resources.record(env.id, cloudflare.PROVIDER, cloudflare.KIND, change.external_id,
                                                body.hostname, ResourceOrigin.CLAIMED, details, actor=ctx.user)
            except resources.ResourceTaken as exc:
                raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except deployer.RunnerBusy as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return {"ok": True, "hostname": body.hostname, "record_id": change.external_id, "resource_id": str(row_id),
            "origin": ResourceOrigin.CLAIMED}


# --------------------------------------------------------------------------- VMs (phase 5 §11)

# A page's read of one VM gives up after this (P5 §7.1, §10.5): Proxmox's page timeout; ESXi's read pool waits
# 5 seconds for a session, and the sign-in and reads then get the rest.
LIVE_LIMIT = {"proxmox": 5.0, "esxi": 15.0}
BUSY_TEXT = "{account} is busy with other work; try again in a minute"


async def _quiet(_line: str) -> None:
    return None


def _read_busy(exc: Exception) -> bool:
    """ESXi's read pool had no free session within its 5 seconds (``esxi.session(purpose='read')``)."""
    return "is busy with" in str(getattr(exc, "text", exc))


async def _contexts(db: AsyncSession, found: list[Any]) -> list[Any]:
    """A ``MachineContext`` per machine, for reads made for a page (no deployment: ESXi's read pool)."""
    out = []
    for machine in found:
        ctx = await machines.load_context(db, machine_id=machine.id, say=_quiet, hide=ssh.Redactor())
        if ctx is not None:
            out.append(ctx)
    return out


async def _describe(ctx: Any) -> tuple[Any, MachineStateOut | None]:
    """``(MachineState, None)``, or ``(None, the error as a MachineStateOut)``: a page read never raises, and
    never waits more than ``LIVE_LIMIT``. Nothing is read for a VM the hypervisor was never asked to make."""
    from slipway.services.vmtypes import MachineError

    account = ctx.account
    name = account.name if account is not None else "its account"
    why = machines.account_problem(account)
    if why:
        detail = machines.account_refusal(account, why) if account is not None else f"Its account {why}"
        return None, MachineStateOut(error=why, detail=detail)
    limit = LIVE_LIMIT.get(ctx.machine.provider, 5.0)
    try:
        return await asyncio.wait_for(ctx.provider.describe(ctx), limit), None
    except TimeoutError:
        text = f"{ctx.label} didn't answer in {int(limit)} seconds"
    except MachineError as exc:
        if _read_busy(exc):
            return None, MachineStateOut(error="busy", detail=BUSY_TEXT.format(account=name))
        text = exc.text
    return None, MachineStateOut(error=text, detail=f"Slipway can't read {ctx.vm} on {name} now: {text}")


def _state_out(ctx: Any, state: Any) -> MachineStateOut:
    ready = ctx.machine.stage == MachineStage.READY
    return MachineStateOut(
        exists=state.exists, ours=state.ours, why_not_ours=state.why_not_ours, hidden=state.hidden,
        lost=ready and not state.exists and not state.hidden, power=state.power, busy=state.busy,
        addresses=list(state.addresses or []), applied=state.applied, snapshot_mode=state.snapshot_mode,
        error=state.error, detail=state.error,
    )


async def _live(ctx: Any) -> MachineStateOut | None:
    if not (ctx.machine.ids or {}):
        return None  # planned: nothing on the hypervisor to read yet
    state, error = await _describe(ctx)
    return error if state is None else _state_out(ctx, state)


def _active_of_two(env: Environment, mem: dict[str, Instance], slot: str) -> bool:
    inst = mem.get(slot)
    return inst is not None and env.active_slot_id == inst.id and len(environments.app_members(mem)) == 2


async def machine_outs(db: AsyncSession, env: Environment, mem: dict[str, Instance]) -> list[MachineOut]:
    """``EnvironmentOut.machines``: the environment's VMs from Slipway's records only."""
    found = await environments.env_machines(db, env)
    order = {"blue": 0, "green": 1, "data": 2}
    return [MachineOut.of(m, active=_active_of_two(env, mem, m.slot))
            for m in sorted(found, key=lambda m: order.get(m.slot, 3))]


async def _machine(db: AsyncSession, env: Environment, slot: str) -> Machine:
    if slot not in environments.SLOTS:
        raise not_found("Slot")
    found = await environments.env_machines(db, env, [slot])
    if not found:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{env.name}'s {slot} slot has no VM Slipway made")
    return found[0]


async def _blockers(ctx: Any) -> list[Any] | None:
    """What stops Remove slot and Delete removing the VM now, as their check reads it (``machines.blockers``),
    within ``LIVE_LIMIT``; None when the read didn't answer in time. Reads only."""
    limit = LIVE_LIMIT.get(ctx.machine.provider, 5.0)
    try:
        return await asyncio.wait_for(machines.blockers(ctx), limit)
    except TimeoutError:
        return None


@router.get("/{env_id}/machines")
async def list_machines(env_id: uuid.UUID, ctx: Reader, db: DB, blockers: bool = False) -> list[MachineOut]:
    """The environment's VMs with what the hypervisor shows of each now (``live``): power, a running task,
    hidden or lost. An account that can't be read gives ``live.error`` (``busy`` when ESXi's page reads are all
    taken), never a failed answer. Reads only, each within ``LIVE_LIMIT``; no job's ESXi session is waited for.

    With ``blockers=true`` (the Remove slot, Delete and retry dialogs, when they open) each VM's removal
    blockers are read too, as the jobs' check reads them, with ``forgettable`` saying whether ``forget_vms``
    gets past them (P5 §9.5, §9.9, §12.4)."""
    env = await _get(db, env_id, deleted=True)
    mem = await environments.members(db, env)
    found = await environments.env_machines(db, env)
    contexts = await _contexts(db, found)
    await db.commit()  # no transaction stays open while the hypervisors answer
    lives = await asyncio.gather(*(_live(c) for c in contexts))
    live_of = {c.machine.id: live for c, live in zip(contexts, lives, strict=True)}
    blocked_of: dict[uuid.UUID, list[Any] | None] = {}
    if blockers:
        # After the live reads, not beside them: ESXi's sessions per account are few.
        read = await asyncio.gather(*(_blockers(c) for c in contexts))
        blocked_of = {c.machine.id: b for c, b in zip(contexts, read, strict=True)}
    order = {"blue": 0, "green": 1, "data": 2}
    return [MachineOut.of(m, active=_active_of_two(env, mem, m.slot), live=live_of.get(m.id),
                          blockers=blocked_of.get(m.id))
            for m in sorted(found, key=lambda m: order.get(m.slot, 3))]


@router.patch("/{env_id}/machines/{slot}")
async def resize_machine(env_id: uuid.UUID, slot: str, body: MachineResizeIn, ctx: MachineWriter,
                         request: Request, db: DB) -> Any:
    """Store a VM's new size, or how many automatic VM snapshots it keeps (P5 §9.4,
    ``environments.resize_plan``). Nothing reaches the hypervisor: the slot's next deploy applies the size."""
    env = await _get(db, env_id)
    if slot not in environments.SLOTS:
        raise not_found("Slot")
    try:
        machine = await environments.resize_plan(db, env, slot, body, ctx, request=request)
    except CreateRefused as exc:
        await db.rollback()
        return field_answer(exc)
    await db.commit()
    mem = await environments.members(db, env)
    return MachineOut.of(machine, active=_active_of_two(env, mem, slot))


@router.post("/{env_id}/machines/{slot}/forget")
async def forget_machine(env_id: uuid.UUID, slot: str, body: ConfirmIn, ctx: Reader, request: Request,
                         db: DB) -> MachineOut:
    """Forget a lost VM (P5 §9.10): the name typed (422) first, then machines:write and environments:delete
    (403), then ``env_jobs.forget_vm``'s refusals (409; 502 when the account can't be checked). The slot's
    next deploy makes a new VM at the same address."""
    from slipway.services import env_jobs

    env = await _get(db, env_id)
    check_confirm(env, body.confirm)
    need(ctx, Perm.MACHINES_WRITE, Perm.ENVIRONMENTS_DELETE)
    machine = await _machine(db, env, slot)
    machine_id = machine.id
    await db.commit()  # forget_vm writes in its own transaction
    try:
        text = await env_jobs.forget_vm(env.id, slot, actor=ctx.user, request=request)
    except jobs.JobRefused as exc:
        raise refused(exc) from exc
    except deployer.RunnerBusy as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    forgotten = await db.get(Machine, machine_id, populate_existing=True)
    assert forgotten is not None
    return MachineOut.of(forgotten, note=text)


# ---------------------------------------------------------------------- VM snapshots (P5 §9.6-9.8)


def _snapshot_slot(mem: dict[str, Instance]) -> Instance | None:
    """The instance VM snapshots are of: the one app slot (D11's shape is checked by the jobs' refusals)."""
    apps = environments.app_members(mem)
    return apps[0] if len(apps) == 1 else mem.get("blue")


async def _snapshot_target(db: AsyncSession, env: Environment) -> tuple[Instance, Machine]:
    mem = await environments.members(db, env)
    target = _snapshot_slot(mem)
    machine = await vm_jobs.machine_of(db, target) if target is not None else None
    if target is None or machine is None:
        raise HTTPException(status.HTTP_409_CONFLICT, vm_jobs.SHAPE_TEXT)
    return target, machine


async def _vm_refusal(db: AsyncSession, env: Environment, ctx: AuthContext, target: Instance | None, kind: str,
                      options: dict[str, Any] | None = None) -> str | None:
    gone = environments.deleting_text(env)
    if gone:
        return gone
    if target is None:
        return vm_jobs.SHAPE_TEXT
    found = await jobs.job_refusal(db, instance=target, user=ctx.user, kind=kind, options=options or {})
    return found.text if found is not None else None


def _settle(rows: list[MachineSnapshot], names: dict[str, int]) -> bool:
    """A page's read settles what the hypervisor accounts for (P5 §9.12, the rules of ``vm_jobs``' check): a
    pending, failed or missing row whose name is there once is ready, a pending one that isn't there failed, a
    ready one gone missing. Called only while no job of the environment runs, so no row is a running job's.
    True when anything changed."""
    changed = False
    for row in rows:
        count = names.get(row.name, 0)
        if row.status in ("pending", "failed", "missing") and count == 1:
            row.status, changed = "ready", True
        elif row.status == "pending" and count == 0:
            row.status, changed = "failed", True
        elif row.status == "ready" and count == 0:
            row.status, changed = "missing", True
    return changed


@router.get("/{env_id}/vm-snapshots")
async def list_vm_snapshots(env_id: uuid.UUID, ctx: Reader, db: DB) -> VmSnapshotsOut:
    """The VM snapshots of the environment's one app slot's VM: Slipway's records joined with the hypervisor's
    list (``on_hypervisor``; ``newest``), what Revert and Delete would answer for each, and the backups each
    revert loses. The live read is a page read (``LIVE_LIMIT``); when it fails, ``error`` says why and the
    records are answered as they are."""
    env = await _get(db, env_id, deleted=True)
    mem = await environments.members(db, env)
    target = _snapshot_slot(mem)
    machine = await vm_jobs.machine_of(db, target) if target is not None else None
    if target is None or machine is None:
        return VmSnapshotsOut(take={"available": False, "reason": vm_jobs.SHAPE_TEXT})
    take = await _vm_refusal(db, env, ctx, target, DeploymentKind.VM_SNAPSHOT)
    owner = environments.owner_in(env, mem)
    backups = list((await db.execute(
        select(Backup.name, Backup.taken_at).where(Backup.instance_id == owner.id, Backup.status == BackupStatus.READY)
        .order_by(Backup.taken_at))).all()) if owner is not None else []
    running = bool(await data.active_env_jobs(db, env.id))
    contexts = await _contexts(db, [machine])
    await db.commit()  # no transaction stays open while the hypervisor answers
    state, error = (await _describe(contexts[0])) if contexts and machine.ids else (None, None)
    rows = list((await db.scalars(select(MachineSnapshot).where(MachineSnapshot.machine_id == machine.id)
                                  .order_by(MachineSnapshot.taken_at.desc())
                                  .execution_options(populate_existing=True))).all())
    views = {v.name: v for v in (state.snapshots if state is not None else [])}
    names = Counter(v.name for v in (state.snapshots if state is not None else []))
    if state is not None and state.exists and state.ours and not running and _settle(rows, names):
        await db.commit()
    mode = (state.snapshot_mode if state is not None else None) or machine.snapshot_mode
    account = machine.account.name if machine.account is not None else "its account"
    newest_live = next((v for v in views.values() if v.newest), None)
    newest_row = next((r for r in rows if r.status == "ready"), None)
    out = []
    for row in rows:
        options = {"vm_snapshot_id": row.id.hex}
        on = (names.get(row.name, 0) > 0) if state is not None and state.exists else None
        revert = await _vm_refusal(db, env, ctx, target, DeploymentKind.VM_REVERT, options)
        if revert is None and on is False:
            revert = f"The VM snapshot {row.name} is gone from {account}"
        if revert is None and names.get(row.name, 0) > 1:
            revert = f"{account} has {names[row.name]} VM snapshots named {row.name}; Slipway won't pick one"
        if revert is None and mode == SnapshotMode.NEWEST_ONLY.value and newest_live is not None \
                and newest_live.name != row.name:
            mine = views.get(row.name)
            newer = [v.name for v in views.values() if v.name != row.name and mine is not None
                     and mine.created is not None and v.created is not None and v.created > mine.created]
            revert = vm_jobs.zfs_text(newer or [newest_live.name], newest_live.name)
        drop = await _vm_refusal(db, env, ctx, target, DeploymentKind.VM_DROP, options)
        out.append(VmSnapshotOut(
            id=row.id, name=row.name, reason=row.reason, status=row.status, taken_at=row.taken_at,
            commit_sha=row.commit_sha, note=row.note, quiesced=row.quiesced, sizes=dict(row.sizes or {}),
            on_hypervisor=on,
            newest=(views[row.name].newest if row.name in views else False) if state is not None and state.exists
            else (newest_row is not None and row.id == newest_row.id),
            revert={"available": revert is None, "reason": revert}, drop={"available": drop is None, "reason": drop},
            backups_after=[name for name, at in backups if at is not None and row.taken_at is not None
                           and _aware(at) > _aware(row.taken_at)],
        ))
    return VmSnapshotsOut(slot=str(target.slot), vm=machine.name, snapshot_mode=mode,
                          error=error.error if error is not None else None,
                          detail=error.detail if error is not None else None,
                          take={"available": take is None, "reason": take}, snapshots=out)


def _aware(at: datetime) -> datetime:
    return at if at.tzinfo is not None else at.replace(tzinfo=UTC)


async def _queue_vm_job(db: AsyncSession, env: Environment, ctx: AuthContext, request: Request, kind: str,
                        options: dict[str, Any], **extra: Any) -> DeploymentOut:
    """Queue a VM snapshot job on the slot instance, list its steps with the VM's and the snapshot's names
    (``vm_jobs.job_steps``), audit it and start it."""
    target, _machine_row = await _snapshot_target(db, env)
    dep = await _queue(db, instance=target, environment=env, user=ctx.user, kind=kind, options=options)
    dep.steps = await vm_jobs.job_steps(db, target, kind, dep.options, deployer.STEP_NAMES)
    _audit_job(db, ctx, request, env, dep, **extra)
    return await _submit(db, dep, target)


@router.post("/{env_id}/vm-snapshots", status_code=202)
async def take_vm_snapshot(env_id: uuid.UUID, ctx: MachineWriter, request: Request, db: DB,
                           body: VmSnapshotIn | None = None) -> DeploymentOut:
    """Take a VM snapshot of the one app slot's VM (P5 §9.6); its refusals are the job's (``vm_jobs``)."""
    env = await _get(db, env_id)
    note = (body.note if body is not None else None) or None
    return await _queue_vm_job(db, env, ctx, request, DeploymentKind.VM_SNAPSHOT,
                               {"note": note} if note else {})


async def _snapshot_row(db: AsyncSession, env: Environment, sid: uuid.UUID) -> MachineSnapshot:
    row = await db.get(MachineSnapshot, sid)
    machine = await db.get(Machine, row.machine_id) if row is not None else None
    if row is None or machine is None or machine.environment_id != env.id:
        raise not_found("VM snapshot")
    return row


@router.post("/{env_id}/vm-snapshots/{sid}/revert", status_code=202)
async def revert_vm_snapshot(env_id: uuid.UUID, sid: uuid.UUID, body: VmRevertIn, ctx: Reader, request: Request,
                             db: DB) -> DeploymentOut:
    """Revert the VM to a VM snapshot (P5 §9.7): the name typed (422), then machines:write and data:reset (403),
    then the job's refusals. Writes since the snapshot are lost, backups on the VM included."""
    env = await _get(db, env_id)
    problem = vm_jobs.revert_request_problem(env, body.confirm, ctx.user)
    if problem is not None:
        raise refused(problem)
    row = await _snapshot_row(db, env, sid)
    options: dict[str, Any] = {"vm_snapshot_id": row.id.hex}
    if body.skip_pre_revert:
        options["skip_pre_revert"] = True
    return await _queue_vm_job(db, env, ctx, request, DeploymentKind.VM_REVERT, options, snapshot=row.name)


@router.delete("/{env_id}/vm-snapshots/{sid}", status_code=202)
async def delete_vm_snapshot(env_id: uuid.UUID, sid: uuid.UUID, ctx: MachineWriter, request: Request,
                             db: DB) -> DeploymentOut:
    """Delete a VM snapshot (P5 §9.8), on the hypervisor and in Slipway's records."""
    env = await _get(db, env_id)
    row = await _snapshot_row(db, env, sid)
    return await _queue_vm_job(db, env, ctx, request, DeploymentKind.VM_DROP, {"vm_snapshot_id": row.id.hex},
                               snapshot=row.name)


# ------------------------------------------------------------------------------- slots


def _check_answer(plan: dict[str, Any]) -> JSONResponse:
    """``ChangeCheckOut``: the plan, with its ``cost`` (a DigitalOcean change's) at the top level."""
    cost = plan.pop("cost", None)
    return JSONResponse(ChangeCheckOut(plan=plan, cost=cost).model_dump(mode="json"), status_code=200)


@router.post("/{env_id}/slots", status_code=201, response_model=SlotAdded,
             responses={200: {"model": ChangeCheckOut, "description": "The dry run (?check=true)"}})
async def add_slot(env_id: uuid.UUID, body: SlotAdd, ctx: Writer, request: Request, db: DB,
                   check: bool = False) -> Any:
    """Add the second app slot (§9.8). On SSH placement exactly one of ``host_id`` (a host added by hand, never one
    another environment made) and ``machine`` (a new VM on the account and network of the environment's other
    VMs, P5 §9.5); on DigitalOcean neither, with providers:spend and the new monthly total typed
    (``confirm_cost``, P4 §15.5). With ``update_data_server`` (deployments:create too) the data server is updated
    so it lets the new host in, and the chain then deploys the new slot. The rules are
    ``environments.add_slot_plan``; a refusal answers ``{detail, field}``.

    ``?check=true`` runs every refusal but the typed total and answers ``ChangeCheckOut`` (the slot, and on
    DigitalOcean the new estimate with its ``delta``), writing nothing."""
    env = await _get(db, env_id)
    gone = environments.deleting_text(env)
    if gone:
        raise HTTPException(status.HTTP_409_CONFLICT, gone)
    if body.update_data_server:
        need(ctx, Perm.DEPLOYMENTS_CREATE)
    try:
        plan = await environments.add_slot_plan(db, env, body, ctx)
    except CreateRefused as exc:
        return field_answer(exc)
    except DigitalOceanError as exc:
        raise do_error(exc) from exc
    if check:
        answer = _check_answer(plan.to_json())
        await db.rollback()  # the plan's stand-in host is never saved
        return answer
    slot, host_name = plan.slot, plan.host.name
    vms = _claimed_vms({slot: plan.planned} if plan.planned else None)
    mem = await environments.members(db, env)
    data_member = mem.get(DATA_SLOT) if env.data_mode == DataMode.SERVER else None
    try:
        async with deployer.runner.exclusive(data.env_keys(env.id, None)):
            busy = await jobs.busy_job(db, env, data.env_keys(env.id, None))
            if busy is not None:
                raise HTTPException(status.HTTP_409_CONFLICT, environments.busy_text(env, busy))
            try:
                inst = await environments.add_slot(db, plan, ctx, request=request)
            except CreateRefused as exc:
                await db.rollback()
                return field_answer(exc)
            dep = None
            if body.update_data_server and data_member is not None:
                dep = await _queue(db, instance=data_member, environment=env, user=ctx.user,
                                   kind=DeploymentKind.DEPLOY, options={"chain": True})
                _audit_job(db, ctx, request, env, dep, slot_added=slot)
            inst_id, dep_id = inst.id, dep.id if dep is not None else None
            await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        answer = await claim_taken(db, exc, vms)
        if answer is None:
            raise
        return answer
    except deployer.RunnerBusy as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    dep_out = None
    if dep_id is not None:
        queued = await db.get(Deployment, dep_id)
        assert queued is not None and data_member is not None
        deployer.runner.submit(queued.id, data.job_keys(queued, data_member))
        dep_out = await deployment_out(db, queued)
    added = await db.get(Instance, inst_id, populate_existing=True)
    env = await _get(db, env.id)
    assert added is not None
    notes = []
    if dep_out is None and env.data_mode == DataMode.SERVER:
        notes.append(f"Update the data server so it lets {host_name} in, then deploy to {slot}")
    elif dep_out is None:
        notes.append(f"Deploy to {slot} to build it" if plan.planned else f"Deploy to {slot}")
    if plan.shared is not None:
        notes.append(f"{plan.shared.slot} and {slot} both run on {host_name}: a problem with that host stops both, "
                     "and Switch back can't help with it")
    pending = await environments.pending_resizes(db, env)
    return SlotAdded(**SlotOut.of(env, added, resize_pending=pending.get(slot)).model_dump(), deployment=dep_out,
                     note=". ".join(notes) or None)


@router.delete("/{env_id}/slots/{slot}", status_code=202)
async def remove_slot(env_id: uuid.UUID, slot: str, ctx: Deleter, request: Request, db: DB,
                      body: RemoveSlotIn | None = None) -> DeploymentOut:
    """Remove an app slot (§9.9): its containers and folder go; the environment's data isn't touched. A slot on
    a VM Slipway made loses its VM too (P5 §9.5); ``forget_vms`` (machines:write and environments:delete, the
    name typed) lets forgettable VM blockers pass, and the VM is then forgotten rather than removed."""
    body = body or RemoveSlotIn()
    env = await _get(db, env_id)
    check_confirm(env, body.confirm)
    if slot not in environments.SLOTS:
        raise not_found("Slot")
    options: dict[str, Any] = {"slot": slot}
    if body.forget_vms:
        need(ctx, Perm.MACHINES_WRITE, Perm.ENVIRONMENTS_DELETE,
             message=f"Forgetting a VM needs the {Perm.MACHINES_WRITE} and {Perm.ENVIRONMENTS_DELETE} permissions")
        options["forget_vms"] = True
    dep = await _queue(db, environment=env, user=ctx.user, kind=DeploymentKind.REMOVE_SLOT, options=options)
    _audit_job(db, ctx, request, env, dep, **({"forget_vms": True} if body.forget_vms else {}))
    return await _submit(db, dep)


# ------------------------------------------------------------------------------ delete


@router.delete("/{env_id}", status_code=202)
async def delete_environment(env_id: uuid.UUID, ctx: Deleter, request: Request, db: DB,
                             body: EnvironmentDelete | None = None) -> Any:
    """Delete the environment (§9.10): the teardown job removes the Switchyard hosts and DNS records Slipway
    made, then every slot and the data server; data volumes and backups stay on the data host. With
    ``snapshot`` (data:backup) a snapshot of the data is taken first, and the teardown follows it.

    Phases 4 and 5 (``environments.delete_problem``): a production environment needs ``confirm_production``,
    retiring, off the air and a snapshot (P4 §13); when Delete destroys the data's only home (a managed cluster,
    a data VM) a snapshot is taken unless ``drop_data`` (data:reset, Decision 26); ``forget_vms`` lets
    forgettable VM blockers pass (P5 §9.9). A delete that goes without a snapshot of data it held audits
    ``environment.delete_without_snapshot``."""
    body = body or EnvironmentDelete()
    env = await _get(db, env_id, deleted=True)
    check_confirm(env, body.confirm)
    if env.is_deleted:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{env.name} was deleted")
    try:
        plan = await environments.delete_problem(db, env, body, ctx)
    except CreateRefused as exc:
        await db.rollback()
        return field_answer(exc)
    except DigitalOceanError as exc:
        raise do_error(exc) from exc
    if not plan.snapshot:
        dep = await _queue(db, environment=env, user=ctx.user, kind=DeploymentKind.TEARDOWN, options=plan.options)
        _audit_job(db, ctx, request, env, dep, **({"drop_data": True} if plan.options.get("drop_data") else {}))
        if plan.without_snapshot:
            audit.record(db, "environment.delete_without_snapshot", actor=ctx.user, target=env, request=request,
                         summary=f"Delete {env.name} without a snapshot: {plan.why}",
                         details={"name": env.name, "by": ctx.user.display_name if ctx.user else None,
                                  "why": plan.why, "deployment": str(dep.id)})
        return await _answer(await _submit(db, dep), plan.note)
    assert body.snapshot is not None
    owner = await environments.owner_of(db, env)
    if owner is None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{env.name} has no data to take a snapshot of")
    try:
        name = snapshots.check_name(body.snapshot.name)
        notes = snapshots.check_notes(body.snapshot.notes)
    except snapshots.SnapshotsError as exc:
        raise HTTPException(exc.status, exc.message) from exc
    if await db.scalar(select(Snapshot.id).where(Snapshot.name == name)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"There is already a snapshot named {name}")
    await data.require_data_job(db, owner, DeploymentKind.SNAPSHOT)
    try:
        snapshots.require_storage()
    except snapshots.SnapshotsError as exc:
        raise HTTPException(exc.status, exc.message) from exc
    man = data.live_manifest(owner)
    snap = Snapshot(id=uuid.uuid4(), name=name, notes=notes, status=SnapshotStatus.PENDING,
                    origin=SnapshotOrigin.INSTANCE, app=(man.get("data") or {}).get("app"),
                    app_name=(str(man.get("name"))[:100] if man.get("name") else None),
                    repository=env.repository.full_name[:200], source=env.name[:100],
                    source_instance_id=owner.id, created_by_id=ctx.user.id)
    db.add(snap)
    await db.flush()
    dep = await _queue(db, instance=owner, environment=env, user=ctx.user, kind=DeploymentKind.SNAPSHOT,
                       snapshot_id=snap.id, options={"stop_app": False, **plan.snapshot_options(),
                                                     "restop": owner.status == InstanceStatus.STOPPED})
    snap.deployment_id = dep.id
    audit.record(db, "snapshot.take", actor=ctx.user, target=snap, request=request,
                 summary=f"Take snapshot {name} of {env.name} before deleting it",
                 details={"name": name, "app": snap.app, "repository": snap.repository, "origin": snap.origin,
                          "stop_app": False, "deployment": str(dep.id), "then": "teardown"})
    _audit_job(db, ctx, request, env, dep, then="teardown", snapshot=name)
    return await _answer(await _submit(db, dep, owner), plan.note)


async def _answer(out: DeploymentOut, note: str | None) -> Any:
    """The queued job, with Delete's note when it has one (``<env> never held data, ...``)."""
    if not note:
        return out
    return JSONResponse({**out.model_dump(mode="json"), "note": note}, status_code=202)
