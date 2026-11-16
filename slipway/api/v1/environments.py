"""Environments (phase 3 §11): one app from one branch in one or two slots, with its data and its names.

Every job follows the existing pattern: ``jobs.queue_job`` builds the row (its refusals become the HTTP answer),
the endpoint audits it, commits and submits it to the runner with its keys, and answers 202 with the
``DeploymentOut``. What the page offers, and why not, is ``environments.actions``, shared with the pages.

Environment ids are loaded live (``deleted_at IS NULL``) except on GET, where a deleted environment still shows.
Typed names are the environment's and are checked before anything else (422).
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from slipway.api.deps import DB, not_found, require
from slipway.core.permissions import Perm
from slipway.models import (
    BuildSource,
    DataMode,
    Deployment,
    DeploymentKind,
    Environment,
    EnvironmentStatus,
    FirstAdmin,
    Host,
    Instance,
    InstanceStatus,
    ResourceOrigin,
    Snapshot,
    SnapshotOrigin,
    SnapshotStatus,
    User,
)
from slipway.schemas import (
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
    SlotAdd,
    SlotAdded,
    SlotIn,
    SlotOut,
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
    manifest,
    resources,
    snapshots,
    switchyard,
    traffic,
)
from slipway.services.auth import AuthContext
from slipway.services.environments import APP_SLOTS, DATA_SLOT, CreateRefused

router = APIRouter(prefix="/environments", tags=["environments"])

Reader = Annotated[AuthContext, require(Perm.ENVIRONMENTS_READ)]
Writer = Annotated[AuthContext, require(Perm.ENVIRONMENTS_WRITE)]
Deleter = Annotated[AuthContext, require(Perm.ENVIRONMENTS_DELETE)]
Deployer = Annotated[AuthContext, require(Perm.DEPLOYMENTS_CREATE)]
Switcher = Annotated[AuthContext, require(Perm.TRAFFIC_SWITCH)]
Discarder = Annotated[AuthContext, require(Perm.DEPLOYMENTS_CREATE, Perm.TRAFFIC_SWITCH)]
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
    parts["slots"] = [SlotOut.of(env, m) for m in slots]
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
        actions=await environments.actions(db, env, ctx),
        warnings=list(warnings or []),
    )


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
    ``{detail, field}``. A seed snapshot needs data:reset (and snapshots:download for another repository's)."""
    try:
        plan = await environments.validate_create(db, body, ctx)
    except CreateRefused as exc:
        return field_answer(exc)
    if check:
        return JSONResponse(plan.to_json(), status_code=200)
    try:
        env = await environments.create(db, plan, ctx, request=request)
    except CreateRefused as exc:
        return field_answer(exc)
    await db.commit()
    return await environment_out(db, await _get(db, env.id), ctx, warnings=plan.warnings)


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
    roles = ["app"] if env.data_mode == DataMode.SLOT or data_member is None else ["server", "slot"]
    plans: dict[str, manifest.AppPlan] = {}
    for role in roles:
        try:
            manifest.check_instance_env(man, env_vars, role)
        except manifest.ManifestError as exc:
            raise CreateRefused(422, str(exc).replace("the instance's environment variables",
                                                      "the environment's variables"), "env") from exc
        member = data_member if role == "server" else app
        assert member is not None
        try:
            plans[role] = manifest.plan(
                man, template=template,
                builtins=environments._placeholder_builtins(env.name, str(member.slot), member.host),
                settings=settings, chosen=services, host_ports={}, secrets=secrets, env=env_vars, role=role,
                data_values=plans["server"].provides if role == "slot" else None,
                server_values={"host": member.host.upstream_address,
                               "clients": [m.host.client_address for m in apps]} if role == "server" else None,
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


async def _traffic_of(db: AsyncSession, env: Environment, wanted: dict[str, Any], *, two: bool,
                      names: set[str]) -> dict[str, Any]:
    """§9.1 rule 7 for a changed ``traffic``; raise CreateRefused."""
    switch = str(wanted.get("switch") or "none")
    if switch == "switchyard" and await switchyard.load_config(db) is None:
        raise CreateRefused(409, environments.SET_UP_SWITCHYARD, "traffic")
    if two and switch != "switchyard":
        raise CreateRefused(409, environments.BLUE_GREEN_SWITCH, "traffic")
    dns_in = wanted.get("dns")
    dns = None
    if isinstance(dns_in, dict):
        config = await cloudflare.load_config(db)
        if config is None:
            raise CreateRefused(409, environments.SET_UP_CLOUDFLARE, "traffic.dns")
        try:
            address = cloudflare.clean_public_ip(dns_in.get("address"))
        except ValueError as exc:
            raise CreateRefused(422, str(exc), "traffic.dns") from exc
        if address is None and not config.public_ip:
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
                             db: DB) -> Any:
    """Change the settings, services, variables, TLS modes, traffic or data options. Each slot uses them from its
    next deploy (§6 Settings edits). Refused while a job of the environment is queued or running."""
    env = await _get(db, env_id)
    gone = environments.deleting_text(env)
    if gone:
        raise HTTPException(status.HTTP_409_CONFLICT, gone)
    sent = body.model_dump(exclude_unset=True)
    try:
        async with deployer.runner.exclusive(data.env_keys(env.id, None)):
            busy = await jobs.busy_job(db, env, data.env_keys(env.id, None))
            if busy is not None:
                raise HTTPException(status.HTTP_409_CONFLICT, environments.busy_text(env, busy))
            try:
                changed = await _apply_update(db, env, body, sent, ctx)
            except CreateRefused as exc:
                return field_answer(exc)
            audit.record(db, "environment.update", actor=ctx.user, target=env, request=request,
                         summary=f"Updated environment {env.name}: {', '.join(changed) or 'no changes'}",
                         details={"changed": changed})
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
        traffic_now = await _traffic_of(db, env, body.traffic.model_dump(), two=len(apps) == 2, names=names)
    elif (traffic_now.get("dns") and hostnames != list(env.hostnames or [])):
        # New names must still be inside the zone their records go to.
        traffic_now = await _traffic_of(db, env, {"switch": traffic_now.get("switch"),
                                                  "dns": {"address": traffic_now["dns"].get("address"),
                                                          "proxied": traffic_now["dns"].get("proxied")}},
                                        two=len(apps) == 2, names=names)
    if body.auto_activate and len(apps) != 2:
        raise CreateRefused(422, "Activate automatically needs two slots", "auto_activate")
    if body.keep_backups is not None and not 1 <= body.keep_backups <= 100:
        raise CreateRefused(422, "Keep 1 to 100 backups", "keep_backups")
    removed = None
    if body.traffic is not None and not traffic_now.get("dns"):
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
    server_first = (env.data_mode != DataMode.SLOT and owner is not None and owner.slot == DATA_SLOT
                    and data.live_state(owner) is None and body.slot is None)
    if body.target == "data" or server_first:
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


async def _plan_blockers(db: AsyncSession, env: Environment, slot: str) -> None:
    """§9.5 refusal 6: the switch's plan, read only; a blocker refuses before anything is queued."""
    backend = traffic.backend_for(env)
    if backend is None:
        return
    try:
        ctx = await traffic.context(db, env, "activate", slot=slot)
        if ctx.config is None:
            raise HTTPException(status.HTTP_409_CONFLICT, environments.SET_UP_SWITCHYARD)
        plan = await backend.plan(ctx)
    except traffic.TrafficError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except switchyard.SwitchyardError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    if plan.blockers:
        raise HTTPException(status.HTTP_409_CONFLICT, "; ".join(plan.blockers) + "; Slipway changed nothing")


@router.post("/{env_id}/activate", status_code=202)
async def activate(env_id: uuid.UUID, body: SlotIn, ctx: Switcher, request: Request, db: DB) -> DeploymentOut:
    """Activate a slot (§9.5), or switch back to the one that was live before (§9.6): its smoke test, DNS, then
    one switch in Switchyard that is checked through Switchyard and put back on any failure."""
    env = await _get(db, env_id)
    mem = await environments.members(db, env)
    active = environments.active_member(env, mem)
    last = (env.traffic_state or {}).get("last")
    back = (isinstance(last, dict) and last.get("from_slot") == body.slot and active is not None
            and active.slot != body.slot)
    options: dict[str, Any] = {"slot": body.slot, **({"back": True} if back else {})}
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
async def continue_chain(env_id: uuid.UUID, ctx: Reader, request: Request, db: DB) -> DeploymentOut:
    """Start the job the chain didn't start (the notice's button, D12), with that job's own permission."""
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
        return await traffic.plan_for(env, slot, db)
    except (switchyard.SwitchyardError, cloudflare.CloudflareError) as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    except traffic.TrafficError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc


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
    except switchyard.SwitchyardError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    return await environment_out(db, await _get(db, env.id), ctx)


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


# ------------------------------------------------------------------------------- slots


@router.post("/{env_id}/slots", status_code=201, response_model=SlotAdded)
async def add_slot(env_id: uuid.UUID, body: SlotAdd, ctx: Writer, request: Request, db: DB) -> Any:
    """Add the second app slot (§9.8) on ``host_id``. With ``update_data_server`` (deployments:create too) the data
    server is updated so it lets the new host in, and the chain then deploys the new slot. Two slots need the
    traffic switched by Switchyard (§9.1 rule 7), and the slot's folder must be free on the host: a folder
    clash answers ``{detail, field}``."""
    env = await _get(db, env_id)
    gone = environments.deleting_text(env)
    if gone:
        raise HTTPException(status.HTTP_409_CONFLICT, gone)
    if body.update_data_server:
        need(ctx, Perm.DEPLOYMENTS_CREATE)
    mem = await environments.members(db, env)
    apps = environments.app_members(mem)
    if env.data_mode == DataMode.SLOT:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"{env.name} keeps its data on {apps[0].slot if apps else 'blue'}; a second slot needs a "
                            "data server")
    if len(apps) >= 2:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{env.name} already has two slots")
    problem = await environments.two_slot_traffic_problem(db, env)
    if problem:
        raise HTTPException(status.HTTP_409_CONFLICT, problem)
    slot = next(s for s in APP_SLOTS if s not in mem)
    host = await db.get(Host, body.host_id)
    if host is None:
        raise HTTPException(UNPROCESSABLE, "Unknown host")
    if not host.is_pinned:
        raise HTTPException(status.HTTP_409_CONFLICT, environments.UNPINNED.format(host=host.name))
    problem = environments.address_problem(env, host)
    if problem:
        raise HTTPException(status.HTTP_409_CONFLICT, problem)
    data_member = mem.get(DATA_SLOT)
    if data_member is not None and data_member.host_id == host.id:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"The data server needs a host of its own: a container on {host.name} reaches its "
                            f"database from a Docker address, which {env.name}'s data server can't let in by host "
                            "address")
    slug = env.slot_slug(slot)
    holder = await db.scalar(select(Instance.name).where(Instance.slug == slug))
    if holder is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Instance {holder} already uses the slug {slug}")
    problem = await environments.slot_folder_problem(db, env.name, slot, host)
    if problem:
        return field_answer(CreateRefused(409, problem, f"hosts.{slot}"))
    busy = await jobs.busy_job(db, env, data.env_keys(env.id, None))
    if busy is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, environments.busy_text(env, busy))
    try:
        man, _ = await _branch_manifest(ctx, env)
    except CreateRefused as exc:
        raise HTTPException(exc.status, exc.detail) from exc
    caps = set(man.capabilities())
    if "bluegreen" not in caps:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"{env.repository.full_name}'s slipway.yml at {env.branch} doesn't declare data.migrations: "
                            f"expand_contract. With two slots, {apps[0].slot if apps else 'blue'} keeps running on the "
                            f"database {slot} migrates, so its migrations must add before they remove.")
    shared = next((m for m in apps if m.host_id == host.id), None)
    try:
        async with deployer.runner.exclusive(data.env_keys(env.id, None)):
            inst = Instance(
                name=f"{env.name} {slot}", slug=slug, repository_id=env.repository_id, host_id=host.id,
                branch=env.branch, build_source=BuildSource.APP, manifest_file=env.manifest_file, deploy_dir=None,
                environment_id=env.id, slot=slot, slot_state={}, status=InstanceStatus.CREATED,
                created_by_id=ctx.user.id,
            )
            db.add(inst)
            await db.flush()
            audit.record(db, "environment.slot_add", actor=ctx.user, target=env, request=request,
                         summary=f"Added {slot} to {env.name} on {host.name}",
                         details={"slot": slot, "host": host.name, "update_data_server": body.update_data_server})
            dep = None
            if body.update_data_server and data_member is not None:
                dep = await _queue(db, instance=data_member, environment=env, user=ctx.user,
                                   kind=DeploymentKind.DEPLOY, options={"chain": True})
                _audit_job(db, ctx, request, env, dep, slot_added=slot)
            await db.commit()
            inst_id, dep_id = inst.id, dep.id if dep is not None else None
    except deployer.RunnerBusy as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    dep_out = None
    if dep_id is not None:
        queued = await db.get(Deployment, dep_id)
        assert queued is not None and data_member is not None
        deployer.runner.submit(queued.id, data.job_keys(queued, data_member))
        dep_out = await deployment_out(db, queued)
    inst = await db.get(Instance, inst_id, populate_existing=True)
    env = await _get(db, env.id)
    assert inst is not None
    notes = []
    if dep_out is None:
        notes.append(f"Update the data server so it lets {host.name} in, then deploy to {slot}")
    if shared is not None:
        notes.append(f"{shared.slot} and {slot} both run on {host.name}: a problem with that host stops both, and "
                     "Switch back can't help with it")
    return SlotAdded(**SlotOut.of(env, inst).model_dump(), deployment=dep_out, note=". ".join(notes) or None)


@router.delete("/{env_id}/slots/{slot}", status_code=202)
async def remove_slot(env_id: uuid.UUID, slot: str, ctx: Deleter, request: Request, db: DB,
                      body: ConfirmIn | None = None) -> DeploymentOut:
    """Remove an app slot (§9.9): its containers and folder go; the environment's data isn't touched."""
    env = await _get(db, env_id)
    check_confirm(env, (body or ConfirmIn()).confirm)
    if slot not in environments.SLOTS:
        raise not_found("Slot")
    dep = await _queue(db, environment=env, user=ctx.user, kind=DeploymentKind.REMOVE_SLOT, options={"slot": slot})
    _audit_job(db, ctx, request, env, dep)
    return await _submit(db, dep)


# ------------------------------------------------------------------------------ delete


@router.delete("/{env_id}", status_code=202)
async def delete_environment(env_id: uuid.UUID, ctx: Deleter, request: Request, db: DB,
                             body: EnvironmentDelete | None = None) -> DeploymentOut:
    """Delete the environment (§9.10): the teardown job removes the Switchyard hosts and DNS records Slipway
    made, then every slot and the data server; data volumes and backups stay on the data host. With
    ``snapshot`` (data:backup) a snapshot of the data is taken first, and the teardown follows it."""
    body = body or EnvironmentDelete()
    env = await _get(db, env_id, deleted=True)
    check_confirm(env, body.confirm)
    if env.is_deleted:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{env.name} was deleted")
    if body.snapshot is None:
        dep = await _queue(db, environment=env, user=ctx.user, kind=DeploymentKind.TEARDOWN,
                           options={"confirmed": True})
        _audit_job(db, ctx, request, env, dep)
        return await _submit(db, dep)
    need(ctx, Perm.DATA_BACKUP, message="Taking a snapshot first needs the data:backup permission")
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
                       snapshot_id=snap.id, options={"stop_app": False, "then": "teardown",
                                                     "restop": owner.status == InstanceStatus.STOPPED})
    snap.deployment_id = dep.id
    audit.record(db, "snapshot.take", actor=ctx.user, target=snap, request=request,
                 summary=f"Take snapshot {name} of {env.name} before deleting it",
                 details={"name": name, "app": snap.app, "repository": snap.repository, "origin": snap.origin,
                          "stop_app": False, "deployment": str(dep.id), "then": "teardown"})
    _audit_job(db, ctx, request, env, dep, then="teardown", snapshot=name)
    return await _submit(db, dep, owner)
