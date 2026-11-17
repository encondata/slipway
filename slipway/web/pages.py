"""Server-rendered pages. All writes go through the JSON API (see static/js/slipway.js)."""

from __future__ import annotations

import hashlib
import math
import re
import shlex
import time
import uuid
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
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
from slipway.services import analytics as deploy_analytics
from slipway.services import deployer, host_metrics, switchyard, updates
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


# --------------------------------------------------------------------- analytics
# The page draws its charts itself (templates/_charts.html). The helpers below turn the analytics services'
# numbers into chart models: plain numbers and fixed labels, never text from the database.

ANALYTICS_DEFAULT_DAYS = 30


def fmt_span(seconds: float | None) -> str:
    """A length of time for people: 45s, 4m 05s, 2h 05m, 3d 4h."""
    if seconds is None:
        return "—"
    s = int(round(seconds))
    if s < 3600:
        return fmt_duration(s)
    if s < 86400:
        h, rest = divmod(s, 3600)
        return f"{h}h {rest // 60:02d}m"
    d, rest = divmod(s, 86400)
    return f"{d}d {rest // 3600}h"


def fmt_pct(value: float | None) -> str:
    """A percentage (0-100): one decimal under 10, whole numbers above. The page's script does the same."""
    if value is None:
        return "—"
    return f"{value:.1f}%" if value < 10 else f"{round(value)}%"


def fmt_rate(rate: float | None) -> str:
    """A success rate (0-1) as a percentage, with one decimal unless it is whole. 100% means nothing failed and
    0% nothing succeeded: anything in between stays between 0.1% and 99.9%, so one failure in 2000 never
    shows as 100%."""
    if rate is None:
        return "—"
    if rate >= 1:
        return "100%"
    if rate <= 0:
        return "0%"
    pct = rate * 100
    if abs(pct - round(pct)) < 1e-9:
        return f"{round(pct)}%"
    return f"{min(99.9, max(0.1, pct)):.1f}%"


templates.env.filters.update(span=fmt_span, pct=fmt_pct, rate=fmt_rate)


def _day_label(day: date) -> str:
    return f"{day:%a} {day.day} {day:%b}"


def _short_day(day: date) -> str:
    return f"{day.day} {day:%b}"


def _count_axis(top_value: int) -> tuple[int, list[int]]:
    """A round top for a count axis, and its ticks from 0 (at most 5)."""
    if top_value <= 0:
        return 1, [0, 1]
    magnitude = 10 ** max(0, math.floor(math.log10(top_value / 4))) if top_value >= 4 else 1
    step = magnitude
    for m in (1, 2, 5, 10):
        step = m * magnitude
        if math.ceil(top_value / step) <= 4:
            break
    top = math.ceil(top_value / step) * step
    return top, list(range(0, top + 1, step))


def _edge(pos: float) -> str:
    """How an axis label at ``pos`` (0..1) is anchored, so labels at the ends stay inside the chart."""
    return "start" if pos < 0.06 else "end" if pos > 0.94 else ""


def _delta(cur: float | None, prev: float | None, *, days: int, higher_is_better: bool, points: bool = False,
           nothing: str, nothing_now: str = "") -> dict[str, Any]:
    """The change of a stat tile against the previous window: text, direction and whether that is good.

    ``nothing`` says why there is no change to show when the previous window has no value, ``nothing_now``
    when this one has none."""
    better = "Higher is better" if higher_is_better else "Lower is better"
    if cur is None:
        return {"note": nothing_now, "better": better}
    if prev is None or (not points and prev == 0):
        return {"note": nothing, "better": better}
    if points:
        change = (cur - prev) * 100
        text = f"{change:+.0f} pts"
    else:
        change = (cur - prev) / prev * 100
        text = f"{change:+.0f}%"
    if round(change) == 0:
        return {"text": "No change", "dir": "flat", "tone": "", "days": days, "better": better}
    up = change > 0
    return {"text": text, "dir": "up" if up else "down", "tone": "good" if up == higher_is_better else "bad",
            "days": days, "better": better}


def _deploy_tiles(totals: dict[str, Any], days: int) -> dict[str, Any]:
    prev = totals["previous"]
    return {
        "deploys": _delta(totals["deploys"], prev["deploys"], days=days, higher_is_better=True,
                          nothing=f"No deploys in the previous {days} days"),
        # Cancelled deploys count for neither side of the rate, so say which deploys it needs.
        "rate": _delta(totals["success_rate"], prev["success_rate"], days=days, higher_is_better=True, points=True,
                       nothing=f"No deploys succeeded or failed in the previous {days} days",
                       nothing_now=f"No deploys succeeded or failed in the last {days} days"),
        "median": _delta(totals["median_seconds"], prev["median_seconds"], days=days, higher_is_better=False,
                         nothing=f"Nothing finished in the previous {days} days",
                         nothing_now="No deploys have finished yet"),
        "mttr": _delta(totals["mttr_seconds"], prev["mttr_seconds"], days=days, higher_is_better=False,
                       nothing=f"No recoveries in the previous {days} days",
                       nothing_now=f"No recoveries in the last {days} days"),
    }


DEPLOY_SERIES = [
    {"key": "ok", "name": "Succeeded"},
    {"key": "fail", "name": "Failed"},
    {"key": "cancel", "name": "Cancelled"},
]


def _deploy_chart(by_day: list[dict[str, Any]]) -> dict[str, Any]:
    """The stacked bars of deploys per day: one slot per day, succeeded at the bottom."""
    rows = [
        {"date": r["date"], "label": _day_label(r["date"]), "values": [r["succeeded"], r["failed"], r["cancelled"]]}
        for r in by_day
    ]
    n = len(rows)
    top, ticks = _count_axis(max((sum(r["values"]) for r in rows), default=0))
    step = 1 if n <= 7 else 7 if n <= 30 else 14
    xlabels = []
    for k, i in enumerate(range(n - 1, -1, -step)):  # counted back from today, so today always has a label
        pos = (i + 0.5) / n
        # Every other label goes on a narrow chart: 7 days of labels, or 90 days' fortnightly ones, would touch.
        xlabels.append({"pos": pos, "text": _short_day(rows[i]["date"]), "edge": _edge(pos),
                        "minor": (n <= 7 or n > 30) and k % 2 == 1})
    return {
        "n": n, "top": top, "ticks": ticks, "rows": rows, "series": DEPLOY_SERIES, "xlabels": xlabels,
        "data": {"kind": "bars", "series": DEPLOY_SERIES, "rows": [{"label": r["label"], "values": r["values"]} for r in rows]},
    }


HOST_SERIES = [("cpu", "CPU load"), ("mem", "Memory"), ("disk", "Disk")]


def _time_axis(start: datetime, end: datetime, days: int) -> list[dict[str, Any]]:
    """Labels at UTC midnights, every day for 7 days, every week for 30 and every two weeks for 90."""
    span = (end - start).total_seconds()
    step = 1 if days <= 7 else 7 if days <= 30 else 14
    first = datetime.combine(end.date(), datetime.min.time(), tzinfo=UTC)
    labels = []
    k = 0
    at = first
    while at > start:
        pos = (at - start).total_seconds() / span
        if 0.04 < pos < 0.96:
            labels.append({"pos": pos, "text": _short_day(at.date()), "edge": "",
                           "minor": (days <= 7 or days > 30) and k % 2 == 1})
        k += 1
        at -= timedelta(days=step)
    return labels[::-1]


PLOT_COLUMNS = 360


def _thin(run: list[tuple[float, float]]) -> list[tuple[float, float]]:
    """The points of a run worth drawing: the lowest and highest of each of PLOT_COLUMNS columns, plus both
    ends, in time order. A week of 5-minute checks is more points than the chart has pixels, and this keeps
    every peak. The hover layer still has every point."""
    if len(run) <= 2 * PLOT_COLUMNS:
        return run
    keep = {0, len(run) - 1}
    column: list[int] = []
    for i, (x, _) in enumerate(run):
        if column and int(x * PLOT_COLUMNS) != int(run[column[0]][0] * PLOT_COLUMNS):
            keep.update((min(column, key=lambda j: run[j][1]), max(column, key=lambda j: run[j][1])))
            column = []
        column.append(i)
    keep.update((min(column, key=lambda j: run[j][1]), max(column, key=lambda j: run[j][1])))
    return [run[i] for i in sorted(keep)]


def _host_points(trend: dict[str, Any], *, start: datetime, span: float) -> dict[str, Any]:
    """Every point of a host's series for the hover layer, shared by the host's charts: seconds since
    ``start`` and the values (None where a check had no disk figure); hourly points add their peaks."""
    series = trend["series"]
    hourly = trend["resolution"] == "hour"
    points: dict[str, Any] = {
        "start": round(start.timestamp(), 3), "span": round(span), "hourly": hourly,
        "t": [round((p["at"] - start).total_seconds()) for p in series],
        "cpu": [p["cpu"] for p in series], "mem": [p["mem"] for p in series],
    }
    if any(p.get("disk") is not None for p in series):
        points["disk"] = [p.get("disk") for p in series]
    if hourly:  # an hour's disk point is its peak already
        points["cpu_peak"] = [p.get("cpu_max", p["cpu"]) for p in series]
        points["mem_peak"] = [p.get("mem_max", p["mem"]) for p in series]
    return points


def _line_chart(trend: dict[str, Any], key: str, name: str, *, points: dict[str, Any], points_id: str, days: int,
                gap: float, xlabels: list[dict[str, Any]]) -> dict[str, Any] | None:
    """One host series on a 0-100% axis, split into runs wherever checks are missing (the gaps stay visible)."""
    span = points["span"]
    pairs = [(t, max(0.0, min(100.0, float(v)))) for t, v in zip(points["t"], points.get(key) or [], strict=False)
             if v is not None]
    if not pairs:
        return None
    runs: list[list[tuple[float, float]]] = []
    for i, (t, v) in enumerate(pairs):
        if not runs or t - pairs[i - 1][0] > gap:
            runs.append([])
        runs[-1].append((t / span, v))
    hourly = points["hourly"]
    # Hourly lines plot each hour's average (disk: its peak), so the headline maximum is a peak above the line.
    value_name = name if not hourly else f"{name}, peak" if key == "disk" else f"{name}, average"
    return {
        "key": key, "name": name, "stats": trend["stats"].get(key), "runs": [_thin(run) for run in runs],
        "xlabels": xlabels, "last": runs[-1][-1], "hourly": hourly,
        "note": ("Hourly peaks" if key == "disk" else "Hourly averages") if hourly else "",
        "max_label": "Peak" if hourly else "Max",
        "data": {"kind": "line", "key": key, "name": name, "value_name": value_name, "points": points_id},
        "label": f"{name} on {trend['name']}, last {days} days, 0 to 100%. The values are in the table below.",
    }


def _host_table(trend: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """The table view of a host's charts: hourly rows for raw samples, daily rows for hourly ones, newest first."""
    hourly = trend["resolution"] == "hour"
    groups: dict[datetime, list[dict[str, Any]]] = defaultdict(list)
    for point in trend["series"]:
        at = point["at"].astimezone(UTC)
        key = at.replace(minute=0, second=0, microsecond=0) if not hourly else at.replace(hour=0, minute=0, second=0, microsecond=0)
        groups[key].append(point)
    rows = []
    for at in sorted(groups, reverse=True):
        points = groups[at]
        weights = [p.get("samples", 1) for p in points]
        row: dict[str, Any] = {"at": at, "label": _day_label(at.date()) + ("" if hourly else f", {at:%H}:00")}
        for key in ("cpu", "mem"):
            row[f"{key}_avg"] = sum(p[key] * w for p, w in zip(points, weights, strict=True)) / sum(weights)
            row[f"{key}_max"] = max(p.get(f"{key}_max", p[key]) for p in points)
        disks = [p["disk"] for p in points if p.get("disk") is not None]
        row["disk_max"] = max(disks) if disks else None
        rows.append(row)
    return ("Daily" if hourly else "Hourly"), rows


def _check_interval(seconds: int) -> str:
    if seconds % 60 == 0:
        minutes = seconds // 60
        return "every minute" if minutes == 1 else f"every {minutes} minutes"
    return f"every {seconds} seconds"


def _host_cards(trends: list[dict[str, Any]], *, now: datetime, days: int) -> list[dict[str, Any]]:
    start = now - timedelta(days=days)
    span = (now - start).total_seconds()
    poll = get_settings().host_poll_interval or 300
    xlabels = _time_axis(start, now, days)
    cards = []
    for trend in trends:
        # Longer than this between two points is a gap: checks failed or Slipway was down.
        gap = 1.5 * 3600 if trend["resolution"] == "hour" else max(2.5 * poll, poll + 60)
        points = _host_points(trend, start=start, span=span)
        points_id = f"points-{trend['id']}"
        charts = [
            chart for key, name in HOST_SERIES
            if (chart := _line_chart(trend, key, name, points=points, points_id=points_id, days=days, gap=gap,
                                     xlabels=xlabels))
        ]
        caption, rows = _host_table(trend)
        cards.append({**trend, "charts": charts, "points": points, "points_id": points_id, "table_caption": caption,
                      "table": rows, "has_disk": any(r["disk_max"] is not None for r in rows)})
    return cards


@router.get("/analytics")
async def analytics(request: Request, db: DB, ctx: PageAuth, days: str = "") -> HTMLResponse:
    need(ctx, Perm.ANALYTICS_READ)
    try:
        n = int(days)
    except ValueError:
        n = ANALYTICS_DEFAULT_DAYS
    if n not in deploy_analytics.ALLOWED_DAYS:
        n = ANALYTICS_DEFAULT_DAYS
    now = utcnow()
    deploys = tiles = deploy_chart = None
    if ctx.can(Perm.DEPLOYMENTS_READ):
        deploys = deploy_analytics.hide_names(
            await deploy_analytics.deploy_stats(db, days=n, now=now),
            repositories=ctx.can(Perm.REPOS_READ), hosts=ctx.can(Perm.HOSTS_READ),
        )
        tiles = _deploy_tiles(deploys["totals"], n)
        deploy_chart = _deploy_chart(deploys["by_day"])
    hosts = None
    if ctx.can(Perm.HOSTS_READ):
        hosts = _host_cards(await host_metrics.host_trends(db, days=n, now=now), now=now, days=n)
    poll = get_settings().host_poll_interval
    return await render(
        request, db, "analytics.html", ctx, days=n, ranges=deploy_analytics.ALLOWED_DAYS, deploys=deploys,
        tiles=tiles, deploy_chart=deploy_chart, hosts=hosts,
        check_every=_check_interval(poll) if poll > 0 else None,
    )


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
