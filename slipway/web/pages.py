"""Server-rendered pages. All writes go through the JSON API (see static/js/slipway.js)."""

from __future__ import annotations

import hashlib
import re
import shlex
import time
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlencode

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
from slipway.services import deployer, switchyard, updates
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


def from_iso(value: object) -> datetime | None:
    """An ISO 8601 time from stored JSON (``...Z`` or with an offset) as a datetime, or None."""
    if not isinstance(value, str) or not value or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


templates.env.filters.update(
    timeago=timeago, dt=fmt_dt, duration=fmt_duration, shquote=shlex.quote, from_iso=from_iso,
)
STATIC_DIR = Path(__file__).resolve().parent / "static"


_asset_stamp: tuple[float, str] = (0.0, "")


def asset_version() -> str:
    """The ``?v=`` of the stylesheet, scripts and favicon: changes whenever one of the static files does,
    so browsers fetch the new ones after an update instead of keeping what they cached. Rechecked at
    most every 10 seconds."""
    global _asset_stamp
    now = time.monotonic()
    if _asset_stamp[1] and now - _asset_stamp[0] < 10:
        return _asset_stamp[1]
    stamp = hashlib.sha256(__version__.encode())
    try:
        paths = sorted(STATIC_DIR.rglob("*"))
    except OSError:
        paths = []
    for path in paths:
        try:  # a file replaced during an update can vanish between the listing and here
            if not path.is_file():
                continue
            st = path.stat()
        except OSError:
            continue
        stamp.update(f"{path.relative_to(STATIC_DIR)}:{st.st_size}:{st.st_mtime_ns}".encode())
    _asset_stamp = (now, stamp.hexdigest()[:12])
    return _asset_stamp[1]


templates.env.globals.update(Perm=Perm, version=__version__, asset_version=asset_version)
# Links to GitHub, built only from a validated owner/repo and a 40-hex sha (None otherwise).
templates.env.globals.update(commit_url=updates.commit_url)


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
    updates_ahead = await updates_badge(db) if ctx and ctx.can(Perm.UPDATES_RUN) else 0
    return templates.TemplateResponse(
        request,
        name,
        {
            "auth": ctx,
            "user": ctx.user if ctx else None,
            "csrf_token": ctx.csrf_token if ctx else "",
            "settings": settings,
            "last_sync": last_sync,
            "updates_ahead": updates_ahead,
            "path": request.url.path,
            **context,
        },
        status_code=status_code,
    )


async def updates_badge(db: DB) -> int:
    """New commits on the followed branch from the last check (the sidebar badge); 0 when the check is stale.

    Reads the stored setting only: no SSH.
    """
    state = await updates.load_state(db)
    check = state["last_check"]
    if not check or not check.get("descends") or check.get("branch") != state["branch"]:
        return 0
    running = updates.running_version()
    if running["commit"] and check.get("from") != running["commit"]:
        return 0  # Slipway changed since: those commits may be running now
    ahead = check.get("ahead")
    return ahead if isinstance(ahead, int) and ahead > 0 else 0


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
    return await render(
        request, db, "overview.html", ctx,
        stats=stats, repos=repos[:5], hosts=hosts[:5], recent=recent, summaries=summaries,
        steps=steps, setup_done=all(done for _, done, _ in steps),
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
    # ?repo= opens that repository's details on load; the others open in place when clicked.
    selected = next((r for r in all_repos if r.id == repo_id), None) if repo_id else None
    if selected and selected not in rows:  # a link to a repository the filter hides still shows it
        rows.insert(0, selected)
    repo_instances: dict[uuid.UUID, list[Instance]] = defaultdict(list)
    if can_instances:
        for inst in (await db.scalars(select(Instance).order_by(Instance.name))).all():
            repo_instances[inst.repository_id].append(inst)
    stats = {
        "total": len(all_repos),
        "deployable": sum(1 for r in all_repos if r.deployable),
        "deployed": sum(1 for r in all_repos if summaries[r.id]["count"]),
        "unconfigured": sum(1 for r in all_repos if not r.deployable),
    }
    return await render(
        request, db, "repositories.html", ctx, repos=rows, summaries=summaries, stats=stats,
        q=q, show=show, selected=selected, repo_instances=repo_instances,
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
    return await render(
        request, db, "host_detail.html", ctx, host=host, instances=instances, claim_repos=claim_repos,
        root_in_ram=deployer.ram_backed(host, host.deploy_root),
    )


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
    folder = _folder(instance)
    return await render(
        request, db, "instance_detail.html", ctx, instance=instance, deployments=deployments,
        env_unreadable=await env_unreadable(db, instance),
        folder=folder, folder_in_ram=bool(folder) and deployer.ram_backed(instance.host, folder),
    )


def _folder(instance: Instance) -> str:
    try:
        return deployer.instance_dir(instance)
    except deployer.DeployError:
        return ""


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
        paths_locked=paths_locked, folder=_folder(instance), **context,
    )


GROUP_EARLIER = 5  # earlier deployments folded under each instance on /deployments; the rest are in History
HISTORY_PAGE_SIZE = 50
ACTIVE_DEPLOYMENTS = (DeploymentStatus.QUEUED, DeploymentStatus.RUNNING)


@router.get("/deployments")
async def deployments_page(request: Request, db: DB, ctx: PageAuth) -> HTMLResponse:
    """One row per instance: its latest deployment, anything else still queued or building, and a few earlier ones."""
    need(ctx, Perm.DEPLOYMENTS_READ)
    rank = func.row_number().over(
        partition_by=Deployment.instance_id, order_by=(Deployment.created_at.desc(), Deployment.id.desc())
    ).label("rank")
    ranked = select(Deployment.id, rank).subquery()
    rows = (await db.execute(
        select(Deployment, ranked.c.rank).options(NO_LOG).join(ranked, ranked.c.id == Deployment.id)
        .where(or_(ranked.c.rank <= 1 + GROUP_EARLIER, Deployment.status.in_(ACTIVE_DEPLOYMENTS)))
        .order_by(Deployment.instance_id, ranked.c.rank)
    )).all()
    totals = dict((await db.execute(
        select(Deployment.instance_id, func.count()).group_by(Deployment.instance_id)
    )).all())
    groups: dict[uuid.UUID, dict[str, Any]] = {}
    for dep, n in rows:
        group = groups.setdefault(dep.instance_id, {
            "instance": dep.instance, "latest": dep, "active": [], "earlier": [], "total": totals.get(dep.instance_id, 0),
        })
        if n == 1:
            continue
        if dep.is_active:
            group["active"].append(dep)
        elif n <= 1 + GROUP_EARLIER:
            group["earlier"].append(dep)
    for group in groups.values():
        group["more"] = group["total"] - 1 - len(group["active"]) - len(group["earlier"])
        group["busy"] = group["latest"].is_active or bool(group["active"])

    def attention(group: dict[str, Any]) -> int:
        return 0 if group["busy"] else 1 if group["latest"].status == DeploymentStatus.FAILED else 2

    # Newest first, then anything building or queued on top, then failures.
    ordered = sorted(groups.values(), key=lambda g: g["latest"].created_at, reverse=True)
    ordered.sort(key=attention)
    return await render(request, db, "deployment_groups.html", ctx, groups=ordered)


@router.get("/deployments/history")
async def deployment_history(
    request: Request, db: DB, ctx: PageAuth, status: str = "", instance: str = "", page: str = "1",
) -> HTMLResponse:
    """Every deployment, newest first, a page at a time; filter by status and by instance."""
    need(ctx, Perm.DEPLOYMENTS_READ)
    where = []
    if status:
        where.append(Deployment.status == status)
    selected = None
    if instance:
        try:
            selected = await db.get(Instance, uuid.UUID(instance))
        except ValueError:
            selected = None
        if selected is None:
            instance = ""
        else:
            where.append(Deployment.instance_id == selected.id)
    total = await db.scalar(select(func.count()).select_from(Deployment).where(*where)) or 0
    pages = max(1, -(-total // HISTORY_PAGE_SIZE))
    page_no = min(max(1, int(page) if page.isdigit() else 1), pages)
    deployments = (await db.scalars(
        select(Deployment).options(NO_LOG).where(*where)
        .order_by(Deployment.created_at.desc(), Deployment.id.desc())
        .offset((page_no - 1) * HISTORY_PAGE_SIZE).limit(HISTORY_PAGE_SIZE)
    )).all()

    def url(**changes: Any) -> str:
        params = {"status": status, "instance": instance, "page": 1} | changes
        query = {k: v for k, v in params.items() if v and not (k == "page" and v == 1)}
        return "/deployments/history" + (f"?{urlencode(query)}" if query else "")

    return await render(
        request, db, "deployments.html", ctx, deployments=deployments, status=status, instance=selected,
        page=page_no, pages=pages, total=total, first=(page_no - 1) * HISTORY_PAGE_SIZE + 1 if total else 0, url=url,
    )


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


# ----------------------------------------------------------------------- updates

# What each step of the upgrade script does, in the words the page uses.
UPDATE_STEPS: dict[str, str] = {
    "preflight": "Check the server",
    "fetch": "Fetch the new version",
    "build": "Build it while this version keeps running",
    "backup": "Stop Slipway and back up the database",
    "switch": "Start the new version",
    "health": "Check that it started",
    "rollback": "Roll back to the old version",
    "cleanup": "Clean up",
}
# The reasons ``updates.overview`` gives that are about the followed branch only: switching to another
# branch is still possible then.
_FOLLOWED_ONLY = ("Slipway is up to date",)


def switch_reason(ov: dict[str, Any]) -> str | None:
    """Why no other branch can be switched to now, or None. The last two of overview's reasons (up to date,
    and the followed branch not descending) only concern the followed branch."""
    reason = ov.get("reason")
    if reason is None or reason in _FOLLOWED_ONLY or reason.endswith("Slipway can't move back or sideways"):
        return None
    return reason


@router.get("/updates")
async def updates_page(request: Request, db: DB, ctx: PageAuth, run: str = "") -> HTMLResponse:
    need(ctx, Perm.UPDATES_RUN)
    ov = await updates.overview(db)
    hosts = [h for h in (await db.scalars(select(Host).order_by(Host.name))).all() if h.is_pinned]
    # ?run=<id> opens that run; otherwise a run that is still going opens by itself.
    run_id = run if updates.valid_id(run) else None
    if run_id is None and ov["run"] and ov["run"].get("status") == "running":
        run_id = ov["run"]["id"]
    selected = next((r for r in ov["runs"] if r["id"] == run_id), None)
    steps = [(name, UPDATE_STEPS.get(name, name)) for name in ov["steps"]]
    # Branch to follow: what Slipway saw last (the page then reads GitHub's list live), the followed one first.
    followed = (ov["config"] or {}).get("branch")
    known = [b["name"] for b in ov["branches"] if b.get("valid", True) and updates.valid_branch(b["name"])]
    branch_names = updates.order_branches([*([followed] if followed else []), *known], followed)
    return await render(
        request, db, "updates.html", ctx, ov=ov, hosts=hosts, run_id=run_id, selected_run=selected,
        steps=steps, switch_reason=switch_reason(ov), branch_names=branch_names,
    )


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
        sy_key_prefix=(row.secret or "")[: switchyard.KEY_PREFIX_LEN] if row else "",
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
