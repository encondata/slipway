"""Server-rendered pages. All writes go through the JSON API (see static/js/slipway.js)."""

from __future__ import annotations

import re
import shlex
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_, select
from sqlalchemy.orm import defer

from slipway import __version__
from slipway.api.deps import DB, OptionalAuth
from slipway.core.config import get_settings
from slipway.core.permissions import PERMISSION_DESCRIPTIONS, Perm, has_permission
from slipway.db.base import utcnow
from slipway.models import (
    ApiToken,
    AppSetting,
    AuditEvent,
    Deployment,
    DeploymentStatus,
    Host,
    HostStatus,
    Instance,
    InstanceStatus,
    Repository,
    Role,
    User,
)
from slipway.services import switchyard
from slipway.services.auth import AuthContext
from slipway.services.users import user_count
from slipway.web.oauth import safe_next

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
# List pages never show build logs; don't load up to 1 MB per row (raise if a template ever reads it).
NO_LOG = defer(Deployment.log, raiseload=True)


# ----------------------------------------------------------------------- filters


def timeago(value: datetime | None) -> str:
    if value is None:
        return "never"
    seconds = int((utcnow() - value).total_seconds())
    if seconds < 0:
        return "just now"
    for unit, size in (("day", 86400), ("hour", 3600), ("min", 60)):
        if seconds >= size:
            n = seconds // size
            return f"{n} {unit}{'s' if n != 1 and unit != 'min' else ''} ago"
    return "just now"


def fmt_dt(value: datetime | None) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC") if value else "—"


def fmt_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s:02d}s" if m else f"{s}s"


templates.env.filters.update(timeago=timeago, dt=fmt_dt, duration=fmt_duration, shquote=shlex.quote)
templates.env.globals.update(Perm=Perm, version=__version__)


# ------------------------------------------------------------- OAuth errors

GITHUB_LOGIN = re.compile(r"[A-Za-z0-9-]{1,39}")
SIGN_IN_FAILED = "Sign-in failed. Please try again."
# The ?error=<code> values slipway.web.oauth redirects with. Only these fixed texts are shown.
OAUTH_ERRORS: dict[str, str] = {
    "cancelled": "GitHub sign-in was cancelled.",
    "state": "GitHub sign-in expired or was tampered with. Please try again.",
    "session_expired": "Your Slipway session expired. Sign in and try again.",
    "already_linked": "{who} is already linked to another Slipway account.",
    "unlink_first": "Unlink your current GitHub account first.",
    "deactivated": "This account has been deactivated.",
    "not_allowed": "{who} is not allowed to sign in to Slipway. Ask an admin to invite you.",
    "no_verified_email": "Your GitHub account needs a verified primary email address.",
    "email_in_use": "A Slipway account already uses your GitHub email. Sign in with your password, then link GitHub from Settings.",
    "config": "GitHub sign-in is misconfigured on this Slipway. Ask an admin.",
    "failed": "GitHub sign-in failed. Please try again.",
}


def oauth_error(code: str, login: str = "") -> str:
    """Message for an OAuth ``?error=`` code. Query text is never echoed, apart from a valid GitHub login."""
    if not code:
        return ""
    who = f"@{login}" if GITHUB_LOGIN.fullmatch(login) else "This GitHub account"
    return OAUTH_ERRORS.get(code, SIGN_IN_FAILED).format(who=who)


def permission_choices() -> dict[str, str]:
    """Everything a role can hold: ``*``, then each resource's wildcard followed by its actions."""
    choices = {"*": "All permissions, including ones added later"}
    for name, desc in PERMISSION_DESCRIPTIONS.items():
        resource = str(name).split(":", 1)[0]
        choices.setdefault(f"{resource}:*", f"Every {resource} permission")
        choices[str(name)] = desc
    return choices


# --------------------------------------------------------------- auth plumbing


class LoginRequired(Exception):
    def __init__(self, next_url: str) -> None:
        self.next_url = next_url


class PageForbidden(Exception):
    def __init__(self, permission: str) -> None:
        self.permission = permission


async def page_auth(request: Request, ctx: OptionalAuth) -> AuthContext:
    if ctx is None:
        target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        raise LoginRequired(target)
    return ctx


PageAuth = Annotated[AuthContext, Depends(page_auth)]


def need(ctx: AuthContext, *perms: str) -> None:
    for perm in perms:
        if not ctx.can(perm):
            raise PageForbidden(perm)


def _uuid(value: str) -> uuid.UUID | None:
    """Lenient UUID parsing for optional query parameters on pages."""
    try:
        return uuid.UUID(value) if value else None
    except ValueError:
        return None


async def render(request: Request, db: DB, name: str, ctx: AuthContext | None, *, status_code: int = 200, **context: Any) -> HTMLResponse:
    settings = get_settings()
    last_sync = await db.scalar(select(func.max(Repository.synced_at))) if ctx else None
    return templates.TemplateResponse(
        request,
        name,
        {
            "auth": ctx,
            "user": ctx.user if ctx else None,
            "csrf_token": ctx.csrf_token if ctx else "",
            "settings": settings,
            "last_sync": last_sync,
            "path": request.url.path,
            **context,
        },
        status_code=status_code,
    )


def instance_summary(instances: list[Instance]) -> dict[str, Any]:
    """Roll up instance state for one repository (used for the Status column)."""
    if not instances:
        return {"state": "unconfigured", "last": None, "sha": None, "count": 0}
    states = {i.status for i in instances}
    state = (
        "deploying" if InstanceStatus.DEPLOYING in states
        else "failed" if InstanceStatus.FAILED in states
        else "running" if InstanceStatus.RUNNING in states
        else "stopped" if InstanceStatus.STOPPED in states
        else "created"
    )
    deployed = [i for i in instances if i.last_deployed_at]
    latest = max(deployed, key=lambda i: i.last_deployed_at) if deployed else None
    return {
        "state": state,
        "last": latest.last_deployed_at if latest else None,
        "sha": (latest.current_commit_sha or "")[:7] if latest else None,
        "count": len(instances),
    }


async def env_unreadable(db: DB, instance: Instance) -> bool:
    """True when variables are stored but the configured SLIPWAY_ENCRYPTION_KEY can't decrypt them (they load as None).

    Same check as the deployer's ENV_UNREADABLE guard; IS NOT NULL is evaluated without decrypting.
    """
    if instance.env is not None:
        return False
    return bool(await db.scalar(select(Instance.env.is_not(None)).where(Instance.id == instance.id)))


def no_summaries() -> dict[uuid.UUID, dict[str, Any]]:
    return defaultdict(lambda: instance_summary([]))


async def repo_summaries(db: DB) -> dict[uuid.UUID, dict[str, Any]]:
    grouped: dict[uuid.UUID, list[Instance]] = defaultdict(list)
    for inst in (await db.scalars(select(Instance))).all():
        grouped[inst.repository_id].append(inst)
    summaries = no_summaries()
    summaries.update({k: instance_summary(v) for k, v in grouped.items()})
    return summaries


# ------------------------------------------------------------------------- pages


@router.get("/login")
async def login_page(
    request: Request, db: DB, ctx: OptionalAuth, next: str = "/", error: str = "", login: str = ""
) -> Response:
    next = safe_next(next)
    if ctx is not None:
        return RedirectResponse(next, 302)
    return await render(
        request, db, "login.html", None, next=next, error=oauth_error(error, login), no_users=await user_count(db) == 0
    )


@router.post("/js-required")
async def js_required(request: Request, db: DB, ctx: OptionalAuth) -> HTMLResponse:
    """Native target of API-backed forms submitted before slipway.js has loaded. The body is never read."""
    return await render(
        request, db, "error.html", ctx, status_code=400, code=400, heading="JavaScript required",
        message="This form needs JavaScript. Reload the page and try again.",
    )


@router.get("/")
async def overview(request: Request, db: DB, ctx: PageAuth) -> HTMLResponse:
    # Each section only loads what the viewer may read; overview.html hides the rest.
    can_repos, can_hosts = ctx.can(Perm.REPOS_READ), ctx.can(Perm.HOSTS_READ)
    can_instances, can_deps = ctx.can(Perm.INSTANCES_READ), ctx.can(Perm.DEPLOYMENTS_READ)
    today = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    repos = (
        (await db.scalars(select(Repository).order_by(Repository.pushed_at.desc().nulls_last()))).all() if can_repos else []
    )
    hosts = (await db.scalars(select(Host).order_by(Host.name))).all() if can_hosts else []
    instances = (await db.scalars(select(Instance))).all() if can_instances else []
    recent = (
        (await db.scalars(select(Deployment).options(NO_LOG).order_by(Deployment.created_at.desc()).limit(6))).all() if can_deps else []
    )
    today_deps = (await db.scalars(select(Deployment).options(NO_LOG).where(Deployment.created_at >= today))).all() if can_deps else []
    summaries = await repo_summaries(db) if can_instances else no_summaries()

    steps = [("Link your GitHub account", bool(ctx.user.github), "/settings")]
    if can_repos:
        steps.append(("Sync repositories", bool(repos), "/repositories"))
    if can_hosts:
        steps.append(("Add a Docker host", bool(hosts), "/hosts"))
        steps.append(("Verify the host's SSH key", any(h.is_pinned for h in hosts), "/hosts"))
    # /instances/new needs instances:write; without instances:read the step could never be ticked off.
    if can_instances and ctx.can(Perm.INSTANCES_WRITE):
        steps.append(("Create your first instance", bool(instances), "/instances/new"))
    stats = {
        "repos": len(repos),
        "deployable": sum(1 for r in repos if r.deployable),
        "running": sum(1 for i in instances if i.status == InstanceStatus.RUNNING),
        "instances": len(instances),
        "hosts": len(hosts),
        "healthy": sum(1 for h in hosts if h.status == HostStatus.HEALTHY),
        "warning": sum(1 for h in hosts if h.status in (HostStatus.WARNING, HostStatus.UNREACHABLE, HostStatus.ERROR)),
        "today": len(today_deps),
        "today_failed": sum(1 for d in today_deps if d.status == DeploymentStatus.FAILED),
    }
    hour = datetime.now().hour
    greeting = "Good morning" if hour < 12 else "Good afternoon" if hour < 18 else "Good evening"
    return await render(
        request, db, "overview.html", ctx,
        stats=stats, repos=repos[:5], hosts=hosts[:5], recent=recent, summaries=summaries,
        steps=steps, setup_done=all(done for _, done, _ in steps), greeting=greeting,
    )


@router.get("/search")
async def search(request: Request, db: DB, ctx: PageAuth, q: str = "") -> HTMLResponse:
    results: dict[str, list[Any]] = {"repos": [], "instances": [], "hosts": []}
    if q.strip():
        like = f"%{q.strip().lower()}%"
        if ctx.can(Perm.REPOS_READ):
            results["repos"] = (await db.scalars(
                select(Repository).where(or_(Repository.full_name.ilike(like), Repository.description.ilike(like))).limit(25)
            )).all()
        if ctx.can(Perm.INSTANCES_READ):
            results["instances"] = (await db.scalars(
                select(Instance).where(or_(Instance.name.ilike(like), Instance.slug.ilike(like))).limit(25)
            )).all()
        if ctx.can(Perm.HOSTS_READ):
            results["hosts"] = (await db.scalars(
                select(Host).where(or_(Host.name.ilike(like), Host.hostname.ilike(like))).limit(25)
            )).all()
    return await render(request, db, "search.html", ctx, q=q, results=results)


@router.get("/repositories")
async def repositories(request: Request, db: DB, ctx: PageAuth, q: str = "", show: str = "all", repo: str = "") -> HTMLResponse:
    repo_id = _uuid(repo)
    need(ctx, Perm.REPOS_READ)
    can_instances = ctx.can(Perm.INSTANCES_READ)
    if not can_instances and show in ("deployed", "unconfigured"):
        show = "all"
    all_repos = (await db.scalars(select(Repository).order_by(Repository.pushed_at.desc().nulls_last()))).all()
    summaries = await repo_summaries(db) if can_instances else no_summaries()
    rows = list(all_repos)
    if q:
        rows = [r for r in rows if q.lower() in r.full_name.lower() or q.lower() in (r.description or "").lower()]
    if show == "deployable":
        rows = [r for r in rows if r.deployable]
    elif show == "deployed":
        rows = [r for r in rows if summaries[r.id]["count"]]
    elif show == "unconfigured":
        rows = [r for r in rows if not summaries[r.id]["count"]]
    selected = next((r for r in all_repos if r.id == repo_id), None) if repo_id else None
    selected_instances = (
        (await db.scalars(select(Instance).where(Instance.repository_id == selected.id))).all()
        if selected and can_instances else []
    )
    stats = {
        "total": len(all_repos),
        "deployable": sum(1 for r in all_repos if r.deployable),
        "deployed": sum(1 for r in all_repos if summaries[r.id]["count"]),
        "unconfigured": sum(1 for r in all_repos if not r.deployable),
    }
    return await render(
        request, db, "repositories.html", ctx, repos=rows, summaries=summaries, stats=stats,
        q=q, show=show, selected=selected, selected_instances=selected_instances,
    )


@router.get("/hosts")
async def hosts_page(request: Request, db: DB, ctx: PageAuth) -> HTMLResponse:
    need(ctx, Perm.HOSTS_READ)
    hosts = (await db.scalars(select(Host).order_by(Host.name))).all()
    counts = (
        dict((await db.execute(select(Instance.host_id, func.count()).group_by(Instance.host_id))).all())
        if ctx.can(Perm.INSTANCES_READ) else {}
    )
    return await render(request, db, "hosts.html", ctx, hosts=hosts, counts=counts)


@router.get("/hosts/{host_id}")
async def host_detail(request: Request, db: DB, ctx: PageAuth, host_id: uuid.UUID) -> HTMLResponse:
    need(ctx, Perm.HOSTS_READ)
    host = await db.get(Host, host_id)
    if host is None:
        return await not_found_page(request, db, ctx)
    instances = (
        (await db.scalars(select(Instance).where(Instance.host_id == host.id).order_by(Instance.name))).all()
        if ctx.can(Perm.INSTANCES_READ) else []
    )
    # Repositories to pick from when claiming an unmanaged container (the same list as the instance form).
    claim_repos = (
        (await _form_context(db))["repos"] if ctx.can(Perm.INSTANCES_WRITE) and ctx.can(Perm.INSTANCES_READ) else []
    )
    return await render(request, db, "host_detail.html", ctx, host=host, instances=instances, claim_repos=claim_repos)


@router.get("/instances")
async def instances_page(request: Request, db: DB, ctx: PageAuth) -> HTMLResponse:
    need(ctx, Perm.INSTANCES_READ)
    instances = (await db.scalars(select(Instance).order_by(Instance.name))).all()
    return await render(request, db, "instances.html", ctx, instances=instances)


async def _form_context(db: DB) -> dict[str, Any]:
    repos = (await db.scalars(select(Repository).where(Repository.archived.is_(False)).order_by(Repository.full_name))).all()
    hosts = (await db.scalars(select(Host).order_by(Host.name))).all()
    return {
        "repos": repos, "hosts": hosts,
        "switchyard_configured": await switchyard.load_config(db) is not None,
        "default_tls": await switchyard.default_tls_mode(db),
    }


@router.get("/instances/new")
async def new_instance(request: Request, db: DB, ctx: PageAuth, repo: str = "") -> HTMLResponse:
    repo_id = _uuid(repo)
    need(ctx, Perm.INSTANCES_WRITE)
    context = await _form_context(db)
    selected = next((r for r in context["repos"] if r.id == repo_id), None) or (context["repos"][0] if context["repos"] else None)
    return await render(request, db, "instance_form.html", ctx, instance=None, env={}, selected_repo=selected, **context)


@router.get("/instances/{instance_id}")
async def instance_detail(request: Request, db: DB, ctx: PageAuth, instance_id: uuid.UUID) -> HTMLResponse:
    need(ctx, Perm.INSTANCES_READ)
    instance = await db.get(Instance, instance_id)
    if instance is None:
        return await not_found_page(request, db, ctx)
    deployments = (await db.scalars(
        select(Deployment).options(NO_LOG).where(Deployment.instance_id == instance.id).order_by(Deployment.created_at.desc()).limit(10)
    )).all() if ctx.can(Perm.DEPLOYMENTS_READ) else []
    return await render(
        request, db, "instance_detail.html", ctx, instance=instance, deployments=deployments,
        env_unreadable=await env_unreadable(db, instance),
    )


@router.get("/instances/{instance_id}/edit")
async def edit_instance(request: Request, db: DB, ctx: PageAuth, instance_id: uuid.UUID) -> HTMLResponse:
    need(ctx, Perm.INSTANCES_WRITE)
    instance = await db.get(Instance, instance_id)
    if instance is None:
        return await not_found_page(request, db, ctx)
    context = await _form_context(db)
    # The repository is fixed once an instance exists, and may since have been archived.
    context["repos"] = [instance.repository]
    # Same rule as PATCH /api/v1/instances/{id}: placement and build settings freeze once anything ran on the host.
    started = await db.scalar(
        select(Deployment.id).where(Deployment.instance_id == instance.id, Deployment.started_at.is_not(None)).limit(1)
    )
    locked = instance.status != InstanceStatus.CREATED or started is not None
    # A claimed instance's repository paths stay editable until Slipway first deploys it.
    paths_locked = locked and not (instance.claim_pending and started is None)
    # An unreadable env renders as one blank row; PATCH keeps the stored values unless new ones are entered.
    return await render(
        request, db, "instance_form.html", ctx, instance=instance, env=instance.env or {},
        env_unreadable=await env_unreadable(db, instance), selected_repo=instance.repository, locked=locked,
        paths_locked=paths_locked, **context,
    )


@router.get("/deployments")
async def deployments_page(request: Request, db: DB, ctx: PageAuth, status: str = "") -> HTMLResponse:
    need(ctx, Perm.DEPLOYMENTS_READ)
    stmt = select(Deployment).options(NO_LOG).order_by(Deployment.created_at.desc()).limit(100)
    if status:
        stmt = stmt.where(Deployment.status == status)
    deployments = (await db.scalars(stmt)).all()
    return await render(request, db, "deployments.html", ctx, deployments=deployments, status=status)


@router.get("/deployments/{deployment_id}")
async def deployment_detail(request: Request, db: DB, ctx: PageAuth, deployment_id: uuid.UUID) -> HTMLResponse:
    need(ctx, Perm.DEPLOYMENTS_READ)
    dep = await db.get(Deployment, deployment_id)
    if dep is None:
        return await not_found_page(request, db, ctx)
    return await render(request, db, "deployment_detail.html", ctx, dep=dep)


@router.get("/analytics")
async def analytics(request: Request, db: DB, ctx: PageAuth) -> HTMLResponse:
    need(ctx, Perm.ANALYTICS_READ)
    return await render(request, db, "coming_soon.html", ctx, page="analytics")


@router.get("/logs")
async def logs(request: Request, db: DB, ctx: PageAuth) -> HTMLResponse:
    need(ctx, Perm.LOGS_READ)
    return await render(request, db, "coming_soon.html", ctx, page="logs")


# ---------------------------------------------------------------------- settings


@router.get("/settings")
async def settings_profile(
    request: Request, db: DB, ctx: PageAuth, error: str = "", login: str = "", linked: str = ""
) -> HTMLResponse:
    return await render(
        request, db, "settings/profile.html", ctx, tab="profile", error=oauth_error(error, login), linked=bool(linked)
    )


@router.get("/settings/tokens")
async def settings_tokens(request: Request, db: DB, ctx: PageAuth) -> HTMLResponse:
    tokens = (await db.scalars(
        select(ApiToken).where(ApiToken.user_id == ctx.user.id).order_by(ApiToken.created_at.desc())
    )).all()
    return await render(request, db, "settings/tokens.html", ctx, tab="tokens", tokens=tokens)


@router.get("/settings/users")
async def settings_users(request: Request, db: DB, ctx: PageAuth) -> HTMLResponse:
    need(ctx, Perm.USERS_READ)
    users = (await db.scalars(select(User).order_by(User.created_at))).all()
    roles = (await db.scalars(select(Role).order_by(Role.is_system.desc(), Role.name))).all()
    # users:write only reaches users whose every permission the viewer also holds (the API enforces this).
    mine = ctx.user.permissions
    manageable = {u.id for u in users if all(has_permission(mine, p) for p in u.permissions)}
    # Likewise you can only grant a role whose every permission you hold.
    grantable = {r.name for r in roles if all(has_permission(mine, p) for p in r.permissions)}
    new_user_roles = next(([name] for name in ("viewer", get_settings().default_role) if name in grantable), [])
    return await render(
        request, db, "settings/users.html", ctx, tab="users", users=users, roles=roles, manageable=manageable,
        grantable=grantable, new_user_roles=new_user_roles,
    )


@router.get("/settings/roles")
async def settings_roles(request: Request, db: DB, ctx: PageAuth) -> HTMLResponse:
    need(ctx, Perm.ROLES_READ)
    roles = (await db.scalars(select(Role).order_by(Role.is_system.desc(), Role.name))).all()
    choices = permission_choices()
    return await render(
        request, db, "settings/roles.html", ctx, tab="roles", roles=roles, catalog=PERMISSION_DESCRIPTIONS,
        choices=choices, grantable={p for p in choices if has_permission(ctx.user.permissions, p)},
    )


@router.get("/settings/integrations")
async def settings_integrations(request: Request, db: DB, ctx: PageAuth) -> HTMLResponse:
    need(ctx, Perm.SETTINGS_WRITE)
    row = await db.scalar(select(AppSetting).where(AppSetting.key == switchyard.SETTING_KEY))
    return await render(
        request, db, "settings/integrations.html", ctx, tab="integrations",
        sy=(row.value if row else None) or {}, sy_has_key=bool(row and row.secret),
        required_operations=switchyard.REQUIRED_OPERATIONS,
    )


@router.get("/settings/audit")
async def settings_audit(request: Request, db: DB, ctx: PageAuth) -> HTMLResponse:
    need(ctx, Perm.AUDIT_READ)
    since = utcnow() - timedelta(days=90)
    events = (await db.scalars(
        select(AuditEvent).where(AuditEvent.created_at >= since).order_by(AuditEvent.created_at.desc()).limit(200)
    )).all()
    return await render(request, db, "settings/audit.html", ctx, tab="audit", events=events)


async def not_found_page(request: Request, db: DB, ctx: AuthContext | None) -> HTMLResponse:
    return await render(request, db, "error.html", ctx, status_code=404, code=404, message="We couldn't find that page.")
