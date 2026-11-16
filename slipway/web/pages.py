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
    Backup,
    BuildSource,
    Deployment,
    DeploymentKind,
    DeploymentStatus,
    Environment,
    EnvironmentStatus,
    FirstAdmin,
    FirstAdminStatus,
    Host,
    HostStatus,
    Instance,
    InstanceStatus,
    Repository,
    Resource,
    ResourceOrigin,
    Role,
    Snapshot,
    SnapshotStatus,
    User,
)
from slipway.schemas import BackupOut, SnapshotOut, seeding_needs_download
from slipway.services import cloudflare, data, deployer, environments, snapshots, switchyard
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


templates.env.filters.update(
    timeago=timeago, dt=fmt_dt, duration=fmt_duration, shquote=shlex.quote,
    bytes=data.human_bytes, kind_label=data.kind_label, kind_noun=data.kind_noun, dep_label=data.dep_label,
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
    # The environments with a slot on this host (phase 3 §12.5).
    env_slots: list[tuple[Environment, str, Instance]] = []
    if ctx.can(Perm.ENVIRONMENTS_READ):
        rows = (await db.execute(select(Environment, Instance).join(Instance, Instance.environment_id == Environment.id)
                                 .where(Instance.host_id == host.id).order_by(Environment.name))).all()
        env_slots = sorted(((e, str(i.slot), i) for e, i in rows),
                           key=lambda r: (r[0].name, SLOT_ORDER.get(r[1], 3)))
    # Repositories to pick from when claiming an unmanaged container (the same list as the instance form).
    claim_repos = (
        (await _form_context(db))["repos"] if ctx.can(Perm.INSTANCES_WRITE) and ctx.can(Perm.INSTANCES_READ) else []
    )
    return await render(
        request, db, "host_detail.html", ctx, host=host, instances=instances, claim_repos=claim_repos, env_slots=env_slots,
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
    return await render(request, db, "instance_form.html", ctx, instance=None, env={}, selected_repo=selected,
                        seed_snapshots=await _seed_snapshots(db, ctx), **context)


async def _seed_snapshots(db: DB, ctx: AuthContext, saved: uuid.UUID | None = None) -> list[dict[str, Any]]:
    """Ready snapshots the instance form can start a new instance from (only offered to data:reset, §10.7).

    ``saved`` is the instance's own seed snapshot on the edit page: it is always listed (read-only without
    data:reset, as the overview names it), so the form shows what the first deploy restores."""
    rows: list[Snapshot] = []
    if ctx.can(Perm.DATA_RESET):
        rows = list((await db.scalars(select(Snapshot).where(Snapshot.status == SnapshotStatus.READY)
                                      .order_by(Snapshot.created_at.desc()))).all())
    if saved is not None and all(s.id != saved for s in rows):
        own = await db.get(Snapshot, saved)
        if own is not None:
            rows.insert(0, own)
    # Its details are what the Snapshots page shows, which needs data:read; anyone else only sees its name,
    # as the instance's overview does.
    full = ctx.can(Perm.DATA_READ) or ctx.can(Perm.DATA_RESET)
    out: list[dict[str, Any]] = []
    for s in rows:
        row: dict[str, Any] = {"id": str(s.id), "name": s.name, "app": s.app, "status": s.status}
        if full:
            row.update(repository=s.repository, source=s.source, origin=s.origin,
                       identity_keys=list(s.identity_keys or []),
                       has_files=s.files_format is not None or s.files_bytes is not None)
        else:
            row["brief"] = True
        out.append(row)
    return out


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
    # A slot of an environment (phase 3 §12.5): its settings, secrets, data and names are the environment's, so
    # the page shows the banner instead of them, and keeps status, containers, logs and the control buttons.
    member = None
    if instance.environment_id is not None and instance.environment is not None:
        env = instance.environment
        member = {
            "env": env, "slot": instance.slot, "live": env.active_slot_id == instance.id,
            "hold": await data.hold_text(db, instance),
            "stale": stale_sentence(str(instance.slot), (instance.slot_state or {}).get("stale")),
        }
    return await render(
        request, db, "instance_detail.html", ctx, instance=instance, deployments=deployments,
        env_unreadable=await env_unreadable(db, instance),
        folder=folder, folder_in_ram=bool(folder) and deployer.ram_backed(instance.host, folder),
        active_job=await data.active_job(db, instance.id),
        d=None if member else await data_view(db, ctx, instance), member=member,
    )


# ------------------------------------------------------------------ data safety (§15)

# The Why column of the Backups card (the JS renderer in slipway.js says the same).
BACKUP_WHY = {
    "pre_deploy": "Before deploy", "pre_retry": "Before retry", "pre_restore": "Before restore",
    "pre_reset": "Before reset", "pre_rollback": "Before roll back (for diagnosis)", "manual": "Back up now",
}
ON_HOST = {
    "pending": ("Being taken", "warning spin"), "missing": ("Missing", "error"), "changed": ("Changed", "error"),
    "unverified": ("Unverified", "warning"),
}
BACKUPS_SHOWN = 50


def _sha7(sha: str | None) -> str:
    return (sha or "")[:7]


def data_labels(man: dict[str, Any]) -> dict[str, str]:
    """What the app calls its identity keys and its files (slipway.yml ``data``), with Slipway's defaults."""
    spec = man.get("data") or {}
    return {
        "identity": spec.get("identity_label") or "identity keys",
        "identity_help": spec.get("identity_help") or "",
        "files": ((spec.get("files") or {}).get("label")) or "Files",
    }


def rebuild_note(man: dict[str, Any], sha7: str) -> str | None:
    """The Restore and Roll back dialogs' note when the live release is rebuilt first (§7.4 image freshness)."""
    images = man.get("images") or []
    if "build" not in (man.get("commands") or {}):
        return None
    if deployer.images_per_release(images, man.get("vars") or {}):
        return None
    minutes = (man.get("timeouts") or {}).get("build") or 60
    limit = f"{minutes // 60} hour{'s' if minutes >= 120 else ''}" if minutes % 60 == 0 else f"{minutes} minutes"
    return f"Slipway rebuilds {sha7} first (up to {limit})."


def backup_present(b: dict[str, Any], *, labels: dict[str, str], job_shas: dict[str, str], can_reset: bool,
                   busy: bool, revision_check: bool) -> dict[str, Any]:
    """How one ``BackupOut`` shows on the Backups card, and the Restore dialog's fill. ``renderers.backups`` in
    slipway.js builds the same rows from the API, so a change here belongs there too."""
    why = BACKUP_WHY.get(b["reason"], b["reason"])
    job = str(b.get("deployment_id") or "")
    if b["reason"] == "pre_deploy" and job_shas.get(job):
        why += " " + job_shas[job]
    if b["reason"] == "manual" and b.get("created_by"):
        why += " · " + b["created_by"]
    chips: list[tuple[str, str]] = []
    if b["has_files"]:
        chips.append(("with files", labels["files"]))
    pinned = b.get("pinned_reason") or ""
    if "roll back point" in pinned:
        chips.append(("Roll back point", pinned))
    elif "kept for undoing" in pinned:
        chips.append(("Kept for undo", pinned))
    if b.get("dirty_note"):
        chips.append((re.sub(r" \(.*\)$", "", b["dirty_note"].replace("Holds data changed by failed ", "after failed ")),
                      b["dirty_note"]))
    size = data.human_bytes(b["db_bytes"]) if b["db_bytes"] is not None else "—"
    if b["has_files"] and b.get("files_bytes") is not None:
        size += f" + {data.human_bytes(b['files_bytes'])} {labels['files'].lower()}"
    if b["status"] == "ready":
        on_host = ("On host", "success") if b.get("checked_at") else ("Not checked", "")
    else:
        on_host = ON_HOST.get(b["status"], (b["status"].title(), ""))
    restore_off = None
    if b["needs_reset_perm"] and not can_reset:
        restore_off = f"Restoring it puts back old {labels['identity']}; that needs data:reset"
    elif busy:
        restore_off = "A job is running for this instance; wait for it to finish"
    delete_off = None
    if b.get("pinned"):
        delete_off = f"This backup is pinned: {pinned}"
    elif b["status"] == "pending" or busy:
        delete_off = "Wait for the running job to finish"
    taken = b["taken_at"]
    taken_dt = datetime.fromisoformat(taken) if isinstance(taken, str) else taken
    fill = {
        "backup_id": str(b["id"]), "name": b["name"], "taken": fmt_dt(taken_dt), "why": why,
        "release": _sha7(b.get("commit_sha")) or "—", "revision": b.get("revision_short") or "—", "size": size,
        "has_files": bool(b["has_files"]), "files": False, "identity_note": b.get("identity_note") or "",
        "needs_identity": bool(b["needs_reset_perm"]), "restore_identity": False,
        "dirty_note": b.get("dirty_note") or "", "no_revision_check": not (revision_check and b.get("revision_short")),
    }
    return {
        "b": b, "taken": fmt_dt(taken_dt), "taken_iso": taken_dt.isoformat(), "why": why, "chips": chips,
        "data": " · ".join(x for x in (_sha7(b.get("commit_sha")), b.get("revision_short") or "") if x) or "—",
        "size": size, "on_host": on_host, "restore_off": restore_off, "delete_off": delete_off,
        "delete_label": "Forget" if b["status"] == "missing" else "Delete", "fill": fill,
    }


async def _backup_outs(db: DB, instance: Instance, rows: list[Backup]) -> list[dict[str, Any]]:
    """``BackupOut`` (as JSON) for rows of one instance, as ``GET /instances/{id}/backups`` gives them."""
    views = await data.backup_views(db, instance, rows)
    creators = {r.created_by_id for r in rows if r.created_by_id}
    users = {u.id: u.display_name for u in (await db.scalars(select(User).where(User.id.in_(creators)))).all()} \
        if creators else {}
    # "Back up now" keeps its note in the job's options until the row has one (as the API does).
    job_ids = {r.deployment_id for r in rows if r.deployment_id and r.note is None}
    notes = {d: (o or {}).get("note") for d, o in (await db.execute(
        select(Deployment.id, Deployment.options).where(Deployment.id.in_(job_ids)))).all()} if job_ids else {}
    return [BackupOut.of(v, created_by=users.get(v.row.created_by_id) if v.row.created_by_id else None,
                         note=notes.get(v.row.deployment_id) if v.row.deployment_id else None).model_dump(mode="json")
            for v in views]


async def _job_shas(db: DB, outs: list[dict[str, Any]]) -> dict[str, str]:
    """The commit each backup's job deployed (``Before deploy <sha7>``), by job id."""
    ids = {uuid.UUID(o["deployment_id"]) for o in outs if o.get("deployment_id")}
    if not ids:
        return {}
    rows = (await db.execute(select(Deployment.id, Deployment.commit_sha).where(Deployment.id.in_(ids)))).all()
    return {str(i): _sha7(sha) for i, sha in rows if sha}


def _admin_email(row: FirstAdmin | None) -> str:
    fields = (row.fields or {}) if row else {}
    return str(fields.get("email") or next((v for v in fields.values() if "@" in str(v)), "") or
               next(iter(fields.values()), ""))


async def data_view(db: DB, ctx: AuthContext, instance: Instance) -> dict[str, Any] | None:
    """Everything the instance page's data parts need (§15.1), or None for Dockerfile and compose instances."""
    if instance.build_source != BuildSource.APP:
        return None
    man = data.live_manifest(instance)
    live = data.live_state(instance)
    caps = data.capabilities(instance)
    labels = data_labels(man)
    active = await data.active_job(db, instance.id)
    busy = active is not None
    can_reset = ctx.can(Perm.DATA_RESET)
    folder = _folder(instance)
    sha7 = data.live_sha7(instance)
    out: dict[str, Any] = {
        "man": man, "live": live, "caps": caps, "labels": labels, "busy": busy, "sha7": sha7,
        "folder": folder, "ram_backed": bool(folder) and deployer.ram_backed(instance.host, folder),
        "elsewhere": data.data_shared_reason(instance), "keep": instance.keep_backups,
        # Who the data is (the environment, for its data owner) and the name its dialogs ask to be typed (D20).
        "who": data.confirm_name(instance), "confirm": data.confirm_name(instance),
        # The data owner of an environment whose app slots share a data server: its data jobs stop the slots.
        "shared": instance.environment_id is not None and instance.environment is not None
        and instance.environment.data_mode != "slot",
        "manual_max": get_settings().manual_backups_max, "rebuild_note": rebuild_note(man, sha7),
    }

    # Backups (newest first) and the Restore dialog's fill for each.
    backups: list[dict[str, Any]] = []
    if ctx.can(Perm.DATA_READ):
        rows = list((await db.scalars(select(Backup).where(Backup.instance_id == instance.id)
                                      .order_by(Backup.taken_at.desc()).limit(BACKUPS_SHOWN))).all())
        outs = await _backup_outs(db, instance, rows)
        shas = await _job_shas(db, outs)
        out["job_shas"] = shas
        backups = [backup_present(o, labels=labels, job_shas=shas, can_reset=can_reset, busy=busy,
                                  revision_check="revision_check" in caps) for o in outs]
    out["backups"] = backups

    # The dirty state and its hold (§8.4).
    dirty = instance.data_dirty or None
    out["dirty"] = dirty
    out["hold_text"] = await data.hold_text(db, instance)
    out["hold_backup"] = None
    out["rollback_job"] = None
    if dirty:
        first, last = dirty.get("first") or {}, dirty.get("last") or {}
        out["first_d8"] = str(first.get("deployment_id") or "")[:8]
        first_job = await _job_by_hex(db, instance, first.get("deployment_id"))
        out["first_job"] = first_job
        out["last_job"] = await _job_by_hex(db, instance, last.get("deployment_id"))
        if out["hold_text"] and ctx.can(Perm.DATA_READ) and last.get("backup_id"):
            row = await db.scalar(select(Backup).where(Backup.id == _uuid(str(last["backup_id"])),
                                                       Backup.instance_id == instance.id))
            if row is not None:
                o = (await _backup_outs(db, instance, [row]))[0]
                out["hold_backup"] = backup_present(o, labels=labels, job_shas=out.get("job_shas", {}),
                                                    can_reset=can_reset, busy=busy,
                                                    revision_check="revision_check" in caps)
        if not out["hold_text"]:
            latest = await data.latest_changing_job(db, instance)
            if latest is not None and latest.kind == DeploymentKind.DEPLOY:
                state = await data.rollback_state(db, latest)
                if state.available:
                    out["rollback_job"] = latest

    # First admin, starter content and the seed snapshot.
    out["first_admin"] = await db.scalar(select(FirstAdmin).where(FirstAdmin.instance_id == instance.id))
    out["admin_email"] = _admin_email(out["first_admin"])
    out["seed_snapshot"] = await db.get(Snapshot, instance.seed_snapshot_id) if instance.seed_snapshot_id else None

    # Reset data: the volumes it deletes, which of them no backup holds, and the snapshots it can start from.
    volumes = [v for v in ((live or {}).get("volumes") or (instance.app_state or {}).get("volumes") or [])
               if isinstance(v, dict) and v.get("name")]
    out["volumes"] = [v["name"] for v in volumes]
    out["unbacked"] = [v["name"] for v in volumes
                       if v.get("holds") == "other" or (v.get("holds") == "files" and "files" not in caps)]
    out["ready_snapshots"] = []
    app_id = (man.get("data") or {}).get("app")
    if can_reset and app_id and "reset" in caps:
        snaps = (await db.scalars(select(Snapshot).where(Snapshot.status == SnapshotStatus.READY, Snapshot.app == app_id)
                                  .order_by(Snapshot.created_at.desc()))).all()
        can_download = ctx.can(Perm.SNAPSHOTS_DOWNLOAD)
        out["ready_snapshots"] = [
            {"snap": s, "needs_download": (need := seeding_needs_download(s, instance.repository.full_name)),
             "off": need and not can_download} for s in snaps]
    # "From a snapshot" is offered only when one of them is usable: a select of disabled options has no value,
    # and a reset without a snapshot_id starts empty (§15.2).
    out["usable_snapshots"] = sum(not s["off"] for s in out["ready_snapshots"])
    # Start over: never live, and a release of a failed first deploy is on the host to back up with (§7.5). On the
    # data server of a mode server environment, "never live" is the environment's: no app slot went live (§7.3).
    out["start_over"] = False
    env = instance.environment if instance.environment_id is not None else None
    if await data.start_over_refusal(db, instance, environment=env) is None:
        out["start_over"] = await db.scalar(select(Deployment.id).where(
            Deployment.instance_id == instance.id, Deployment.kind == DeploymentKind.DEPLOY,
            Deployment.release.is_not(None)).limit(1)) is not None
    # Start over on a mode server data server that went live (no app slot did): its dialog says what that job
    # does instead of phase 2's (the data server's data, the slots' own volumes, the data server stopped).
    out["start_over_server"] = None
    if out["start_over"] and env is not None and instance.slot == environments.DATA_SLOT \
            and env.data_mode != "slot" and (instance.current_commit_sha or live):
        mem = await environments.members(db, env)
        out["start_over_server"] = {
            "env": env.name,
            # The slots whose failed deploys recorded volumes of their own (deployer._slot_local_volumes).
            "slots": [str(m.slot) for m in environments.app_members(mem) if (m.app_state or {}).get("starting_volumes")],
        }
    out["reset_off"] = (
        f"slipway.yml at {sha7} declares no data volumes and restore command, so Slipway can't reset it"
        if live and "reset" not in caps else
        out["elsewhere"] if out["elsewhere"] else
        "A job is running for this instance; wait for it to finish" if busy else
        None if live else data.not_live_text(instance)
    )
    out["snapshot_off"] = (
        data.dirty_snapshot_text(instance) or out["hold_text"] or
        ("A job is running for this instance; wait for it to finish" if busy else None)
    )
    out["default_snapshot_name"] = f"{instance.slug}-{utcnow():%Y-%m-%d-%H%M}"
    return out


async def _job_by_hex(db: DB, instance: Instance, value: Any) -> Deployment | None:
    job_id = _uuid(str(value or ""))
    if job_id is None:
        return None
    return await db.scalar(select(Deployment).options(NO_LOG)
                           .where(Deployment.id == job_id, Deployment.instance_id == instance.id))


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
        paths_locked=paths_locked, folder=_folder(instance),
        seed_snapshots=await _seed_snapshots(db, ctx, instance.seed_snapshot_id), **context,
    )


# ------------------------------------------------------------------ environments (phase 3 §12)

SLOT_ORDER = {"blue": 0, "green": 1, "data": 2}
STEP_NAMES = ("Environment", "Servers", "Hosts", "Settings", "Traffic", "Data", "Review & Deploy")


def check_view(last: dict[str, Any] | None) -> dict[str, Any] | None:
    """A slot's ``slot_state.last_check`` for the pages: OK or Failed, when, and the names that failed (by their
    code or error), which the chip's title lists."""
    if not isinstance(last, dict):
        return None
    failing = []
    for r in last.get("results") or []:
        if not isinstance(r, dict):
            continue
        code = r.get("code")
        if r.get("error") or not isinstance(code, int) or not 200 <= code < 400:
            failing.append(f"{r.get('hostname')}: {r.get('error') or code}")
    at = None
    try:
        at = datetime.fromisoformat(str(last.get("at"))) if last.get("at") else None
    except ValueError:
        at = None
    ok = bool(last.get("ok"))
    title = (f"Checked {fmt_dt(at)}" if at else "Checked") + ("" if ok else ": " + "; ".join(failing))
    return {"ok": ok, "at": at, "failing": failing, "title": title}


def stale_sentence(slot: str, stale: dict[str, Any] | None) -> str | None:
    """``green was stopped when uat's data was restored; deploy to it before activating it``."""
    if not isinstance(stale, dict):
        return None
    reason = str(stale.get("reason") or "Marked stale").strip().rstrip(".")
    if reason.lower().startswith("its "):
        text = f"{slot}'s {reason[4:]}"
    else:
        text = f"{slot} was {reason[:1].lower()}{reason[1:]}"
    if "deploy to it" not in text:
        text += "; deploy to it before activating it"
    return text


async def _env_last_job(db: DB, env: Environment, member_ids: list[uuid.UUID]) -> Deployment | None:
    cond = Deployment.environment_id == env.id
    if member_ids:
        cond = or_(cond, Deployment.instance_id.in_(member_ids))
    return await db.scalar(select(Deployment).options(NO_LOG).where(cond)
                           .order_by(Deployment.created_at.desc(), Deployment.id.desc()).limit(1))


def env_row(env: Environment, members: dict[str, Instance], last: Deployment | None) -> dict[str, Any]:
    """One row of the Environments list: the live and idle slots, where the data is, and the last job."""
    apps = environments.app_members(members)
    active = environments.active_member(env, members)
    idle = next((m for m in apps if active is None or m.id != active.id), None) if len(apps) == 2 or active is None \
        else None
    owner = environments.owner_in(env, members)
    if env.data_mode == "slot":
        where = f"In {owner.slot}" if owner is not None else "In blue"
    else:
        data_member = members.get(environments.DATA_SLOT)
        where = f"On {data_member.host.name}" if data_member is not None else "On its data server"
    return {
        "env": env, "active": active, "idle": idle, "where": where, "last": last,
        "idle_check": check_view((idle.slot_state or {}).get("last_check")) if idle is not None else None,
        "two": len(apps) == 2,
    }


@router.get("/environments")
async def environments_page(request: Request, db: DB, ctx: PageAuth, show: str = "") -> HTMLResponse:
    need(ctx, Perm.ENVIRONMENTS_READ)
    deleted = show == "deleted"
    stmt = select(Environment).order_by(Environment.name, Environment.created_at)
    if not deleted:
        stmt = stmt.where(Environment.deleted_at.is_(None))
    rows = []
    for env in (await db.scalars(stmt)).all():
        mem = await environments.members(db, env)
        rows.append(env_row(env, mem, await _env_last_job(db, env, [m.id for m in mem.values()])))
    deleted_count = int(await db.scalar(select(func.count()).select_from(Environment)
                                        .where(Environment.deleted_at.is_not(None))) or 0)
    return await render(request, db, "environments.html", ctx, rows=rows, show_deleted=deleted,
                        deleted_count=deleted_count)


async def _flow_context(db: DB, ctx: AuthContext) -> dict[str, Any]:
    """What the New environment flow and the settings page offer: repositories with a slipway.yml, hosts (with
    why one can't take a slot), Switchyard's traffic address and the Cloudflare integration's defaults."""
    repos = (await db.scalars(select(Repository).where(Repository.archived.is_(False))
                              .order_by(Repository.full_name))).all()
    hosts = (await db.scalars(select(Host).order_by(Host.name))).all()
    sy = await switchyard.load_config(db)
    cf = await cloudflare.load_config(db)
    return {
        "repos": [r for r in repos if r.has_manifest],
        "hosts": [{"host": h, "pinned": h.is_pinned, "ip": environments.is_ip(h.client_address)} for h in hosts],
        "switchyard_configured": sy is not None, "traffic_address": sy.traffic_address if sy is not None else "",
        "default_tls": await switchyard.default_tls_mode(db),
        "cloudflare": {"zone": cf.zone, "public_ip": cf.public_ip or "", "proxied": cf.proxied} if cf else None,
        "tls_modes": [("auto", "Let's Encrypt"), ("dns", "DNS challenge"), ("internal", "Internal CA"),
                      ("off", "No TLS")],
    }


@router.get("/environments/new")
async def new_environment(request: Request, db: DB, ctx: PageAuth, repo: str = "") -> HTMLResponse:
    need(ctx, Perm.ENVIRONMENTS_WRITE)
    context = await _flow_context(db, ctx)
    repo_id = _uuid(repo)
    selected = next((r for r in context["repos"] if r.id == repo_id), None) or \
        (context["repos"][0] if context["repos"] else None)
    return await render(request, db, "environment_new.html", ctx, selected_repo=selected, steps=STEP_NAMES,
                        seed_snapshots=await _seed_snapshots(db, ctx), **context)


async def _env_or_404(db: DB, env_id: uuid.UUID) -> Environment | None:
    return await db.get(Environment, env_id, populate_existing=True)


def _slot_dialog(env: Environment, slot: Any) -> dict[str, Any]:
    """What the Activate and Switch back dialogs say about ``slot`` (a SlotOut)."""
    live = slot.live or {}
    return {"slot": slot.slot, "sha7": _sha7(live.get("sha")), "host": slot.host.name}


def rollback_off(ctx: AuthContext, state: data.RollbackState) -> str | None:
    """Why this user can't roll back (POST /deployments/{id}/rollback's permissions), or None: deployments:create
    and data:restore, and on shared data data:reset too (D17), as environments.actions()['rollback'] asks."""
    for perm in (Perm.DEPLOYMENTS_CREATE, Perm.DATA_RESTORE, *([Perm.DATA_RESET] if state.needs_reset else [])):
        if not ctx.can(perm):
            return environments.need_text(perm)
    return None


def env_rollback_view(env: Environment, mem: dict[str, Instance], failed: Deployment,
                      state: data.RollbackState) -> dict[str, Any]:
    """What the Roll back dialog of an environment says the job does (phase 3 §7.3, D16): which slot starts again on
    the restored data (the lead), which are stopped while it runs, and what happens to the other app slot.

    ``case``: ``slot`` (mode slot: the owner itself starts its release that was running, phase 2's wording),
    ``idle`` (mode server, a failed idle app slot: it stays stopped and stale) or ``data`` (mode server, a failed
    data server deploy: the data server's release that was running starts again, then the lead slot)."""
    apps = environments.app_members(mem)
    failed_slot = str(failed.instance.slot) if failed.instance is not None and failed.instance.slot else None
    if env.data_mode == "slot":
        lead = mem.get(failed_slot or "") or (apps[0] if apps else None)
        case = "slot"
    else:
        lead = environments.active_member(env, mem)
        case = "data" if failed_slot == environments.DATA_SLOT else "idle"
    lead_slot = str(lead.slot) if lead is not None else None
    lead_sha7 = data.live_sha7(lead) if lead is not None else ""
    # The other app slot of a failed data server deploy starts again only on the lead's commit (D16).
    other = next((m for m in apps if lead is None or m.id != lead.id), None) if case == "data" else None
    other_view = None
    if other is not None:
        other_view = {"slot": str(other.slot), "same": bool(lead_sha7) and data.live_sha7(other) == lead_sha7}
    server = mem.get(environments.DATA_SLOT)
    return {
        "dep": failed, "d8": failed.id.hex[:8], "slot": failed_slot, "case": case,
        "backup_at": state.backup.taken_at if state.backup is not None else None,
        "also_undoes": state.also_undoes,
        "lead": lead_slot, "lead_sha7": lead_sha7,
        "stopped": [str(m.slot) for m in apps] if case != "slot" else [],
        "other": other_view,
        "data_sha7": data.live_sha7(server) if case == "data" and server is not None else "",
    }


@router.get("/environments/{env_id}")
async def environment_detail(request: Request, db: DB, ctx: PageAuth, env_id: uuid.UUID) -> HTMLResponse:
    need(ctx, Perm.ENVIRONMENTS_READ)
    env = await _env_or_404(db, env_id)
    if env is None:
        return await not_found_page(request, db, ctx)
    from slipway.api.v1.environments import environment_out  # the API module imports the web's deps

    out = await environment_out(db, env, ctx)
    mem = await environments.members(db, env)
    owner = environments.owner_in(env, mem)
    slots = {s.slot: s for s in out.slots}
    apps = [s for s in out.slots if s.role == "app"]
    active = next((s for s in apps if s.active), None)
    actions = out.actions

    deployments: list[Deployment] = []
    if ctx.can(Perm.DEPLOYMENTS_READ):
        cond = Deployment.environment_id == env.id
        if mem:
            cond = or_(cond, Deployment.instance_id.in_([m.id for m in mem.values()]))
        deployments = list((await db.scalars(select(Deployment).options(NO_LOG).where(cond)
                                             .order_by(Deployment.created_at.desc()).limit(20))).all())

    # The data owner's phase 2 parts (Backups card, Restore, Reset, snapshots), as on an instance page.
    d = await data_view(db, ctx, owner) if owner is not None else None

    # Roll back after a failed idle-slot deploy (mode server: the second action, D17).
    rollback = None
    if actions["rollback"]["available"] and actions["rollback"]["deployment_id"]:
        failed = await db.get(Deployment, _uuid(actions["rollback"]["deployment_id"]), options=[NO_LOG])
        if failed is not None:
            state = await data.rollback_state(db, failed)
            rollback = env_rollback_view(env, mem, failed, state)

    # The chain notice's button (§8.5).
    cont = actions.get("continue")
    cont_label = None
    if cont:
        cont_label = {"deploy": f"Deploy {cont.get('slot')}", "activate": f"Activate {cont.get('slot')}",
                      "teardown": "Delete environment"}.get(cont["kind"], data.job_label(cont["kind"], slot=cont.get("slot")))

    # What Delete removes and what it leaves (§9.10).
    owned = (await db.execute(select(Resource.provider, Resource.origin, func.count())
                              .where(Resource.environment_id == env.id)
                              .group_by(Resource.provider, Resource.origin))).all()
    counts = {(p, o): n for p, o, n in owned}
    teardown = {
        "hosts": counts.get(("switchyard", ResourceOrigin.CREATED), 0),
        "records": counts.get((cloudflare.PROVIDER, ResourceOrigin.CREATED), 0),
        "claimed": counts.get((cloudflare.PROVIDER, ResourceOrigin.CLAIMED), 0),
    }

    # Hosts a new slot may use: pinned, an IP the data server can let in, and not the data server's.
    data_host = slots["data"].host.id if "data" in slots else None
    add_hosts = []
    if actions["add_slot"]["available"]:
        for h in (await db.scalars(select(Host).order_by(Host.name))).all():
            off = ("Check it first" if not h.is_pinned else
                   "The data server needs a host of its own" if h.id == data_host else
                   "Its address must be an IP for the data server to let it in"
                   if not environments.is_ip(h.client_address) else None)
            add_hosts.append({"host": h, "off": off})

    idle = slots.get(actions["activate"]["slot"]) if actions["activate"]["slot"] else None
    back = slots.get(actions["switch_back"]["slot"]) if actions["switch_back"]["slot"] else None
    names = [h for h in env.hostnames or [] if h.get("follows") != "server"]
    two = len(apps) == 2
    publishes = (env.traffic or {}).get("switch") == "switchyard" or bool((env.traffic or {}).get("dns"))
    return await render(
        request, db, "environment_detail.html", ctx, env=env, out=out, slots=slots, apps=apps, active=active,
        owner=owner, d=d, deployments=deployments, actions=actions, rollback=rollback, cont_label=cont_label,
        teardown=teardown, add_hosts=add_hosts, idle=_slot_dialog(env, idle) if idle else None,
        back=_slot_dialog(env, back) if back else None, active_names=names, two=two, publishes=publishes,
        unresolved=environments.unresolved_text(env),
        checks={s.slot: check_view(s.last_check) for s in out.slots},
        stale={s.slot: stale_sentence(s.slot, s.stale) for s in out.slots if s.stale},
        default_snapshot_name=f"{env.name}-before-delete-{utcnow():%Y-%m-%d-%H%M}",
        poll=out.active_job is not None,
    )


@router.get("/environments/{env_id}/edit")
async def edit_environment(request: Request, db: DB, ctx: PageAuth, env_id: uuid.UUID) -> HTMLResponse:
    """Steps 4-6 of the flow for PATCH (§12.3); read-only without environments:write."""
    need(ctx, Perm.ENVIRONMENTS_READ)
    env = await _env_or_404(db, env_id)
    if env is None:
        return await not_found_page(request, db, ctx)
    mem = await environments.members(db, env)
    owner = environments.owner_in(env, mem)
    can_write = ctx.can(Perm.ENVIRONMENTS_WRITE) and not env.is_deleted
    from slipway.api.v1.environments import env_unreadable as unreadable

    # The manifest as the last deploy saw it, for when GitHub can't be read.
    fallback = next((m.app_state.get("manifest") for m in sorted(mem.values(), key=lambda m: SLOT_ORDER.get(str(m.slot), 3))
                     if isinstance(m.app_state, dict) and m.app_state.get("manifest")), None)
    context = await _flow_context(db, ctx)
    return await render(
        request, db, "environment_edit.html", ctx, env=env, owner=owner, can_write=can_write, fallback=fallback,
        env_unreadable=await unreadable(db, env), env_vars=(env.env or {}) if can_write else {},
        two=len(environments.app_members(mem)) == 2, **context,
    )


@router.get("/deployments")
async def deployments_page(request: Request, db: DB, ctx: PageAuth, status: str = "",
                           environment: str = "") -> HTMLResponse:
    need(ctx, Perm.DEPLOYMENTS_READ)
    stmt = select(Deployment).options(NO_LOG).order_by(Deployment.created_at.desc()).limit(100)
    if status:
        stmt = stmt.where(Deployment.status == status)
    # ?environment=<id>: every job of one environment, its members' and its own (phase 3 §12.5).
    env_id = _uuid(environment)
    env = await db.get(Environment, env_id) if env_id else None
    if env is not None:
        stmt = stmt.where(Deployment.environment_id == env.id)
    deployments = (await db.scalars(stmt)).all()
    return await render(request, db, "deployments.html", ctx, deployments=deployments, status=status,
                        environment=env, any_env=any(d.environment_id for d in deployments))


@router.get("/deployments/{deployment_id}")
async def deployment_detail(request: Request, db: DB, ctx: PageAuth, deployment_id: uuid.UUID) -> HTMLResponse:
    need(ctx, Perm.DEPLOYMENTS_READ)
    dep = await db.get(Deployment, deployment_id)
    if dep is None:
        return await not_found_page(request, db, ctx)
    instance = dep.instance
    if instance is None:
        return await _env_job_detail(request, db, ctx, dep)
    actions = await data.job_actions(db, dep)
    refs = {b.id: b for b in (await db.scalars(select(Backup).where(
        Backup.id.in_({x for x in (dep.backup_id, dep.restore_backup_id) if x is not None})))).all()} \
        if dep.backup_id or dep.restore_backup_id else {}
    d: dict[str, Any] = {
        "actions": actions, "kind": dep.kind or DeploymentKind.DEPLOY,
        "backup": refs.get(dep.backup_id) if dep.backup_id else None,
        "restore_backup": refs.get(dep.restore_backup_id) if dep.restore_backup_id else None,
        "snapshot": await db.get(Snapshot, dep.snapshot_id) if dep.snapshot_id else None,
        "retry_of": await db.get(Deployment, dep.retry_of_id, options=[NO_LOG]) if dep.retry_of_id else None,
        "man": data.live_manifest(instance), "labels": data_labels(data.live_manifest(instance)),
        "sha7": data.live_sha7(instance), "undo": None, "rollback": None,
    }
    d["rebuild_note"] = rebuild_note(d["man"], d["sha7"])
    caps = data.capabilities(instance)
    if actions["rollback"]["available"]:
        state = await data.rollback_state(db, dep)
        first_at = ((instance.data_dirty or {}).get("first") or {}).get("at")
        started = instance.last_control_at
        by_hand = None
        if started and first_at:
            try:
                if started > datetime.fromisoformat(first_at):
                    by_hand = started
            except (TypeError, ValueError):
                by_hand = None
        d["rollback"] = {"state": state, "by_hand": by_hand, "off": rollback_off(ctx, state), "env": None}
        env = instance.environment if instance.environment_id is not None else None
        if env is not None:
            # A member's roll back runs on the data owner and restarts the lead slot: the environment's wording.
            d["rollback"]["env"] = env_rollback_view(env, await environments.members(db, env), dep, state)
    d["again"] = await deploy_again(db, ctx, dep, instance)
    if actions["undo"]["available"] and ctx.can(Perm.DATA_RESTORE):
        row = await db.scalar(select(Backup).where(Backup.id == _uuid(str(actions["undo"]["backup_id"])),
                                                   Backup.instance_id == instance.id))
        if row is not None:
            o = (await _backup_outs(db, instance, [row]))[0]
            # restore_off says why Undo can't run for this user now (other identity keys without data:reset,
            # or another job running), as on the Backups card.
            undo = backup_present(o, labels=d["labels"], job_shas=await _job_shas(db, [o]),
                                  can_reset=ctx.can(Perm.DATA_RESET),
                                  busy=await data.active_job(db, instance.id) is not None,
                                  revision_check="revision_check" in caps)
            undo["fill"]["files"] = bool(row.has_files)  # undo puts the files back too when the backup has them
            d["undo"] = undo
    if instance.environment_id is not None:
        d["confirm"] = data.confirm_name(instance)
    return await render(request, db, "deployment_detail.html", ctx, dep=dep, instance=instance, d=d)


# The lag check's refusal (deployer._lag_check, §7.6), and the step it fails in.
LAG_REFUSAL = "already runs on a database migrated past it"
LAG_STEP = "backup"


def lag_refused(dep: Deployment) -> bool:
    """Whether the lag check refused this slot deploy at run time (§7.6): its ``backup`` step failed with the lag
    check's text, and it wasn't already confirmed past it."""
    if dep.kind != DeploymentKind.DEPLOY or dep.status != DeploymentStatus.FAILED or not dep.error:
        return False
    if (dep.options or {}).get("behind_ok") or LAG_REFUSAL not in dep.error:
        return False
    failed = [st.get("key") for st in dep.steps or [] if isinstance(st, dict) and st.get("status") == "failed"]
    return failed == [LAG_STEP]


async def deploy_again(db: DB, ctx: AuthContext, dep: Deployment, instance: Instance) -> dict[str, Any] | None:
    """What **Deploy again, confirming** offers on a slot deploy the lag check refused (§7.6), or None.

    It is offered while the refusal still stands: this is the slot's newest deploy, no Activate has run since (the
    same slot is idle and the same one takes the traffic), and the environment's Deploy goes to this slot and is
    open to this user. The page's dialog asks for the acknowledgement again, unticked."""
    if instance.environment_id is None or instance.slot not in environments.APP_SLOTS or not lag_refused(dep):
        return None
    env = instance.environment
    if env is None:
        return None
    newer = await db.scalar(select(Deployment.id).where(
        Deployment.instance_id == instance.id, Deployment.kind == DeploymentKind.DEPLOY, Deployment.id != dep.id,
        Deployment.created_at >= dep.created_at).limit(1))
    if newer is not None:
        return None
    switched = await db.scalar(select(Deployment.id).where(
        Deployment.environment_id == env.id, Deployment.kind == DeploymentKind.ACTIVATE,
        Deployment.created_at >= dep.created_at,
        Deployment.status.not_in((DeploymentStatus.FAILED, DeploymentStatus.CANCELLED))).limit(1))
    if switched is not None:
        return None
    deploy = (await environments.actions(db, env, ctx))["deploy"]
    if not deploy["available"] or deploy["slot"] != instance.slot:
        return None
    mem = await environments.members(db, env)
    active = environments.active_member(env, mem)
    if active is None or active.id == instance.id:
        return None
    return {"slot": str(instance.slot), "branch": env.branch, "sha7": dep.short_sha or "",
            "active": str(active.slot), "active_sha7": data.live_sha7(active), "go_live": deploy.get("go_live")}


def switch_text(dep: Deployment) -> str | None:
    """What an Activate did to the names (§12.5): ``Moved 6 names from blue to green``, or after a failure,
    ``Put back: traffic stays on blue``."""
    from slipway.schemas import _switch_summary

    record = _switch_summary((dep.options or {}).get("switch"))
    if not isinstance(record, dict):
        return None
    moved = len(record.get("created") or []) + len(record.get("changed") or [])
    src, dst = record.get("from_slot"), record.get("to_slot") or (dep.options or {}).get("slot")
    if dep.status == DeploymentStatus.SUCCEEDED:
        names = f"{moved} name{'' if moved == 1 else 's'}"
        return f"Moved {names} from {src} to {dst}" if src else f"Pointed {names} at {dst}"
    if dep.status in (DeploymentStatus.FAILED, DeploymentStatus.CANCELLED) and (moved or record.get("deleted")):
        return f"Put back: traffic stays on {src}" if src else \
            "Put back: nothing was live before; Slipway removed the hosts it had made"
    return None


async def _env_job_detail(request: Request, db: DB, ctx: AuthContext, dep: Deployment) -> HTMLResponse:
    """The page of a job of a whole environment (activate, publish, discard, remove_slot, teardown): it has no
    instance, so the breadcrumb and the What card name the environment."""
    from slipway.api.v1.deployments import env_job_actions

    env = dep.environment
    actions = await env_job_actions(db, dep)
    d = {"actions": actions, "kind": dep.kind, "label": data.dep_label(dep), "switch": switch_text(dep),
         "retry_of": await db.get(Deployment, dep.retry_of_id, options=[NO_LOG]) if dep.retry_of_id else None}
    return await render(request, db, "deployment_detail.html", ctx, dep=dep, instance=None, env=env, d=d)


# --------------------------------------------------------------------- snapshots


SNAPSHOT_POLL_STATES = (SnapshotStatus.PENDING, SnapshotStatus.CHECKING)


@router.get("/snapshots")
async def snapshots_page(request: Request, db: DB, ctx: PageAuth) -> HTMLResponse:
    need(ctx, Perm.DATA_READ)
    problem = snapshots.storage_problem()
    if problem is not None:
        return await render(request, db, "error.html", ctx, status_code=503, code=503,
                            heading="Snapshots are unavailable", message=problem)
    rows = (await db.scalars(select(Snapshot).order_by(Snapshot.created_at.desc(), Snapshot.id.desc()))).all()
    sources = {s.source_instance_id for s in rows if s.source_instance_id}
    live_sources = set((await db.scalars(select(Instance.id).where(Instance.id.in_(sources)))).all()) if sources else set()
    return await render(
        request, db, "snapshots.html", ctx, snaps=[SnapshotOut.of(s) for s in rows], live_sources=live_sources,
        usage=await snapshots.usage(db), polling=any(s.status in SNAPSHOT_POLL_STATES for s in rows),
        max_bytes=get_settings().snapshot_max_bytes, locked_days=get_settings().snapshot_locked_days,
    )


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
    from slipway.api.v1.settings import _cloudflare_out, _dns_users

    cf_row = await db.scalar(select(AppSetting).where(AppSetting.key == cloudflare.SETTING_KEY))
    return await render(
        request, db, "settings/integrations.html", ctx, tab="integrations",
        sy=(row.value if row else None) or {}, sy_has_key=bool(row and row.secret),
        sy_key_prefix=(row.secret or "")[: switchyard.KEY_PREFIX_LEN] if row else "",
        required_operations=switchyard.REQUIRED_OPERATIONS,
        cf=_cloudflare_out(cf_row), cf_users=await _dns_users(db),
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
