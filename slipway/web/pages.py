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
from markupsafe import Markup
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
    Machine,
    MachineSnapshot,
    ProviderAccount,
    Repository,
    Resource,
    ResourceOrigin,
    Role,
    Snapshot,
    SnapshotStatus,
    User,
)
from slipway.services import analytics as deploy_analytics
from slipway.schemas import BackupOut, SnapshotOut, provider_account_out, seeding_needs_download
from slipway.services import cloudflare, data, deployer, do_rules, environments, host_metrics, machines, provisioning, snapshots, ssh, switchyard, updates
from slipway.services import hosts as host_rules
from slipway.services import provider_accounts as accounts_service
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
                select(Instance).where(or_(Instance.name.ilike(like), Instance.slug.ilike(like)),
                                       Instance.host_id.is_not(None)).limit(25)
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
        for inst in (await db.scalars(select(Instance).where(Instance.host_id.is_not(None))
                                      .order_by(Instance.name))).all():
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


# ------------------------------------------------------------- hosts a provider made (P4 §17.5, P5 §12.5)

# The provider chip of a host Slipway made, and the build chip of each phase (Decision 33). Lost, Hidden and Off
# are a VM's alone and come from a live read of the hypervisor (``live``); the stored phase gives the rest.
PROVIDER_CHIPS = {"digitalocean": "DigitalOcean droplet", "proxmox": "Proxmox VM", "esxi": "ESXi VM"}
BUILD_CHIPS: dict[str, tuple[str, str]] = {
    "planned": ("Not built yet", ""), "creating": ("Building", "warning spin"), "ready": ("Ready", "success"),
    "gone": ("Gone", "error"), "lost": ("Lost", "error"), "hidden": ("Hidden", "warning"), "off": ("Off", "warning"),
}
BUILD_TITLES = {
    "planned": "Slipway makes it when its slot is first deployed",
    "creating": "Slipway is making it",
    "gone": "It isn't there any more: deploy its slot to build it again",
    "lost": "A ready VM the hypervisor doesn't have any more, or has without Slipway's markers",
    "hidden": "Proxmox says the VM's id is in use, but the token can't see it",
    "off": "The VM is powered off",
}
# The host actions an owned host refuses (hosts.owned_host_refusal), by the page's name for them.
HOST_ACTIONS = {"check": "check", "edit_address": "hostname", "reset_key": "reset_key", "delete": "delete",
                "move_root": "move_root", "claim": "claim", "instance": "instance", "add_slot": "add_slot"}


def resize_pending_text(slot: str | None) -> str:
    """The one pending-size phrase (Decision 33); the environment page adds ``... when <slot> is idle``."""
    return f"Resize pending: applies at {slot or 'its slot'}'s next deploy"


def _slot_of_name(name: str) -> str | None:
    """The slot of ``slipway-<env>-<slot>`` (hosts.planned_name), or None."""
    if name.startswith("slipway-") and "-" in name[len("slipway-"):]:
        tail = name.rsplit("-", 1)[1]
        return tail if tail in SLOT_ORDER else None
    return None


def _live_value(live: Any, key: str) -> Any:
    if live is None:
        return None
    return live.get(key) if isinstance(live, dict) else getattr(live, key, None)


def build_state(host: Host, *, live: Any = None) -> str | None:
    """The build chip's key for ``host``: planned, creating, ready or gone from its phase, and for a ready VM
    lost, hidden or off from ``live`` (a ``machines.MachineState`` or its JSON; None: the stored phase only).
    None for a host added by hand."""
    phase = host_rules.phase_of(host)
    if phase is None:
        return None
    if (host.provider or "ssh") in PROVIDER_CHIPS and host.provider != "digitalocean" and phase == "ready" \
            and live is not None and not _live_value(live, "error"):
        if _live_value(live, "hidden"):
            return "hidden"
        if _live_value(live, "exists") is False or _live_value(live, "ours") is False:
            return "lost"
        if _live_value(live, "power") == "stopped":
            return "off"
    return phase if phase in BUILD_CHIPS else "planned"


def _vm_size(size: dict[str, Any] | None) -> str:
    """``4 vCPU · 8 GB · 64 GB`` for a machine size {cores, memory_mb, disk_gb}."""
    if not isinstance(size, dict):
        return ""
    parts = []
    if size.get("cores"):
        parts.append(f"{size['cores']} vCPU")
    if size.get("memory_mb"):
        parts.append(f"{int(size['memory_mb']) / 1024:g} GB")
    if size.get("disk_gb"):
        parts.append(f"{size['disk_gb']} GB")
    return " · ".join(parts)


def host_view(host: Host, *, env: Environment | None = None, machine: Machine | None = None,
              slot: str | None = None, account: str | None = None, live: Any = None) -> dict[str, Any]:
    """What the pages show about one host (the hosts list and detail, the instance page; the environment pages
    reuse it for their host cells): who made it and for which environment and slot, its build chip, the
    actions an owned host refuses with the reason (``off[action]``), a one-line summary and a pending resize.

    ``env`` is the owning environment, ``machine`` its VM row, ``slot`` the slot it serves, ``account`` the
    account's name (a VM's comes from ``machine``), ``live`` a hypervisor read for the VM-only chips."""
    provider = host.provider or "ssh"
    made = provider in PROVIDER_CHIPS
    owned = host.owner_environment_id is not None
    built = ssh.host_is_built(host)
    if machine is not None:
        slot = machine.slot
        if machine.account is not None:
            account = machine.account.name
    slot = slot or _slot_of_name(host.name or "")
    names = {"owner": env.name if env is not None else None, "slot": slot, "account": account}
    off = {page: host_rules.owned_host_refusal(host, action=action, **names) for page, action in HOST_ACTIONS.items()}
    if not built and off["check"] is None:
        off["check"] = f"{host.name} isn't built yet: deploy {(env.name if env else None) or host.label or host.name} " \
                       "to build it"
    state = build_state(host, live=live)
    chip = BUILD_CHIPS.get(state) if state else None
    pstate = host.provider_state or {}
    summary, size, pending = "", "", None
    if provider == "digitalocean":
        size = str(pstate.get("size") or "")
        summary = " · ".join(x for x in (str(pstate.get("droplet_name") or host.name), size,
                                         str(pstate.get("public_ip") or "")) if x)
        wanted = (env.cloud or {}).get("droplet_size") if env is not None else None
        if built and wanted and pstate.get("size") and pstate.get("size") != wanted:
            pending = resize_pending_text(slot)
    elif machine is not None:
        summary = f"{machine.name} on {account or 'its account'}"
        size = _vm_size(machine.applied or machine.size)
        if size:
            summary += f" · {size}"
        if machine.stage == "ready" and machines.size_differs(machine):
            pending = resize_pending_text(slot)
    return {
        "host": host, "provider": provider, "made": made, "owned": owned, "built": built,
        "kind": PROVIDER_CHIPS.get(provider), "noun": host_rules.kind_of(host) if made else None,
        "env": env, "slot": slot, "account": account, "machine": machine,
        "state": state, "chip": chip, "chip_title": BUILD_TITLES.get(state or "", ""),
        "off": off, "summary": summary, "size": size, "pending_resize": pending,
        "last_error": machine.last_error if machine is not None and machine.stage != "ready" else None,
    }


def provider_chip(view: dict[str, Any], auth: AuthContext | None = None) -> Markup:
    """``DigitalOcean droplet · shop blue``: who made the host, linking its environment (with environments:read).
    Empty for a host added by hand."""
    if not view.get("kind"):
        return Markup("")
    env = view.get("env")
    text = view["kind"]
    if env is not None:
        text += f" · {env.name}" + (f" {view['slot']}" if view.get("slot") else "")
    title = (f"Slipway made it for {env.name}'s {view['slot'] or 'slot'}; it goes with the environment"
             if env is not None else "Slipway made it; the environment it was made for is gone")
    if env is not None and auth is not None and auth.can(Perm.ENVIRONMENTS_READ):
        return Markup('<a class="chip provider-chip" href="/environments/{}" title="{}">{}</a>').format(
            env.id, title, text)
    return Markup('<span class="chip provider-chip" title="{}">{}</span>').format(title, text)


def build_chip(view: dict[str, Any], *, gone_text: str | None = None) -> Markup:
    """The build chip (Decision 33): Not built yet, Building, Ready, Gone, and for VMs Lost, Hidden and Off.
    ``gone_text`` replaces Gone's label (the environment page's ``Gone: deploy to rebuild``)."""
    if not view.get("chip"):
        return Markup("")
    label, cls = view["chip"]
    if view.get("state") == "gone" and gone_text:
        label = gone_text
    return Markup('<span class="badge build-chip {}" title="{}">{}</span>').format(cls, view.get("chip_title") or "",
                                                                                   label)


templates.env.globals.update(provider_chip=provider_chip, build_chip=build_chip)


async def host_views(db: DB, hosts: list[Host]) -> dict[uuid.UUID, dict[str, Any]]:
    """``host_view`` for each host, with the owning environments, VM rows, slots and DigitalOcean account names
    read in one query each."""
    made = [h for h in hosts if (h.provider or "ssh") != "ssh" or h.owner_environment_id is not None]
    env_ids = {h.owner_environment_id for h in made if h.owner_environment_id is not None}
    envs = {e.id: e for e in (await db.scalars(select(Environment).where(Environment.id.in_(env_ids)))).all()} \
        if env_ids else {}
    ids = [h.id for h in made]
    vms = {m.host_id: m for m in (await db.scalars(select(Machine).where(Machine.host_id.in_(ids)))).all()} \
        if ids else {}
    slots: dict[uuid.UUID, str] = {}
    if ids:
        for host_id, env_id, slot in (await db.execute(
                select(Instance.host_id, Instance.environment_id, Instance.slot)
                .where(Instance.host_id.in_(ids), Instance.environment_id.is_not(None)))).all():
            owner = next((h.owner_environment_id for h in made if h.id == host_id), None)
            if slot and (owner is None or owner == env_id):
                slots[host_id] = str(slot)
    account_ids = {e.provider_account_id for e in envs.values() if e.provider_account_id is not None}
    account_names = dict((await db.execute(select(ProviderAccount.id, ProviderAccount.name)
                                           .where(ProviderAccount.id.in_(account_ids)))).all()) if account_ids else {}
    out = {}
    for h in hosts:
        env = envs.get(h.owner_environment_id) if h.owner_environment_id is not None else None
        out[h.id] = host_view(h, env=env, machine=vms.get(h.id), slot=slots.get(h.id),
                              account=account_names.get(env.provider_account_id) if env is not None else None)
    return out


@router.get("/hosts")
async def hosts_page(request: Request, db: DB, ctx: PageAuth) -> HTMLResponse:
    need(ctx, Perm.HOSTS_READ)
    hosts = list((await db.scalars(select(Host).order_by(Host.name))).all())
    counts = (
        dict((await db.execute(select(Instance.host_id, func.count()).where(Instance.host_id.is_not(None))
                               .group_by(Instance.host_id))).all())
        if ctx.can(Perm.INSTANCES_READ) else {}
    )
    return await render(request, db, "hosts.html", ctx, hosts=hosts, counts=counts, views=await host_views(db, hosts))


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
    view = (await host_views(db, [host]))[host.id]
    # Repositories to pick from when claiming an unmanaged container (the same list as the instance form). A host
    # an environment made runs only that environment's slots, so nothing is claimed onto it.
    claim_repos = (
        (await _form_context(db))["repos"]
        if ctx.can(Perm.INSTANCES_WRITE) and ctx.can(Perm.INSTANCES_READ) and not view["off"]["claim"] else []
    )
    return await render(
        request, db, "host_detail.html", ctx, host=host, instances=instances, claim_repos=claim_repos, env_slots=env_slots,
        root_in_ram=deployer.ram_backed(host, host.deploy_root), hv=view, setup_steps=provisioning.STEPS,
    )


@router.get("/instances")
async def instances_page(request: Request, db: DB, ctx: PageAuth) -> HTMLResponse:
    need(ctx, Perm.INSTANCES_READ)
    # A managed environment's data owner has no host; it shows on its environment's page only (P4 §3.4).
    instances = (await db.scalars(select(Instance).where(Instance.host_id.is_not(None))
                                  .order_by(Instance.name))).all()
    return await render(request, db, "instances.html", ctx, instances=instances)


async def _form_context(db: DB, *, keep: uuid.UUID | None = None) -> dict[str, Any]:
    """The instance form's choices. A host an environment made isn't offered (it runs only that environment's
    slots), except ``keep``, the instance's own host on its edit page."""
    repos = (await db.scalars(select(Repository).where(Repository.archived.is_(False)).order_by(Repository.full_name))).all()
    hosts = [h for h in (await db.scalars(select(Host).order_by(Host.name))).all()
             if h.owner_environment_id is None or h.id == keep]
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
    # The host Slipway made for this slot (a droplet or a VM), or None for a managed environment's data owner,
    # which has no host (P4 §3.4).
    hv = (await host_views(db, [instance.host]))[instance.host.id] if instance.host is not None else None
    return await render(
        request, db, "instance_detail.html", ctx, instance=instance, deployments=deployments,
        env_unreadable=await env_unreadable(db, instance), hv=hv,
        folder=folder,
        folder_in_ram=bool(folder) and instance.host is not None and deployer.ram_backed(instance.host, folder),
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
        # A managed environment's backups are kept on this Slipway server (P4 §10.5).
        stored = ("On Slipway", "success") if b.get("location") == "slipway" else ("On host", "success")
        on_host = stored if b.get("checked_at") else ("Not checked", "")
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
        "folder": folder,
        "ram_backed": bool(folder) and instance.host is not None and deployer.ram_backed(instance.host, folder),
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
        # A VM revert's hold (P5 §9.12: data_dirty.last.text) is undone by reverting again, never by a P2 restore:
        # the release the records name may not be on the disk any more.
        if out["hold_text"] and ctx.can(Perm.DATA_READ) and last.get("backup_id") and not last.get("text"):
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
    if instance.host is None and not instance.deploy_dir:  # a managed environment's data owner (P4 §3.4)
        return ""
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
    context = await _form_context(db, keep=instance.host_id)
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


def env_row(env: Environment, members: dict[str, Instance], last: Deployment | None, *,
            billing: int = 0) -> dict[str, Any]:
    """One row of the Environments list: the live and idle slots, where the data is, and the last job.
    ``billing`` is how many DigitalOcean objects a never-live environment already has (P4 §12.4's marker)."""
    apps = environments.app_members(members)
    active = environments.active_member(env, members)
    idle = next((m for m in apps if active is None or m.id != active.id), None) if len(apps) == 2 or active is None \
        else None
    owner = environments.owner_in(env, members)
    if env.data_mode == "slot":
        where = f"In {owner.slot}" if owner is not None else "In blue"
    else:
        data_member = members.get(environments.DATA_SLOT)
        if data_member is not None and data_member.host is None:  # a managed environment's data owner
            where = "In a managed database"
        else:
            where = f"On {data_member.host.name}" if data_member is not None else "On its data server"
    if environments.is_digitalocean(env):
        region = (env.cloud or {}).get("region")
        where = "In a managed database on DigitalOcean" + (f" ({region})" if region else "")
    open_bill = billing if env.status == EnvironmentStatus.NEW and environments.is_digitalocean(env) else 0
    return {
        "env": env, "active": active, "idle": idle, "where": where, "last": last,
        "idle_check": check_view((idle.slot_state or {}).get("last_check")) if idle is not None else None,
        "two": len(apps) == 2, "billing": open_bill,
        "billing_title": (f"{open_bill} DigitalOcean object{'' if open_bill == 1 else 's'} already bill for "
                          f"{env.name}: retry its failed deploy, or delete it") if open_bill else "",
        "production": bool(env.production), "retiring": env.retiring_at is not None,
    }


@router.get("/environments")
async def environments_page(request: Request, db: DB, ctx: PageAuth, show: str = "") -> HTMLResponse:
    need(ctx, Perm.ENVIRONMENTS_READ)
    deleted = show == "deleted"
    stmt = select(Environment).order_by(Environment.name, Environment.created_at)
    if not deleted:
        stmt = stmt.where(Environment.deleted_at.is_(None))
    rows = []
    found = list((await db.scalars(stmt)).all())
    # The Billing marker (P4 §12.4): DigitalOcean objects, pending creates included, of each never-live one.
    new_ids = [e.id for e in found if e.status == EnvironmentStatus.NEW and environments.is_digitalocean(e)]
    billed = dict((await db.execute(select(Resource.environment_id, func.count()).where(
        Resource.environment_id.in_(new_ids), Resource.provider == environments.DIGITALOCEAN)
        .group_by(Resource.environment_id))).all()) if new_ids else {}
    for env in found:
        mem = await environments.members(db, env)
        rows.append(env_row(env, mem, await _env_last_job(db, env, [m.id for m in mem.values()]),
                            billing=int(billed.get(env.id) or 0)))
    deleted_count = int(await db.scalar(select(func.count()).select_from(Environment)
                                        .where(Environment.deleted_at.is_not(None))) or 0)
    return await render(request, db, "environments.html", ctx, rows=rows, show_deleted=deleted,
                        deleted_count=deleted_count)


MAKE_VMS_TEXT = f"Making VMs needs the {Perm.MACHINES_WRITE} permission"
# Without providers:read the pages name no account, network or pool (P4 §4.1, P5 §11): the placement says why.
DO_ACCOUNTS_TEXT = f"Choosing a DigitalOcean account needs the {Perm.PROVIDERS_READ} permission"
VM_ACCOUNTS_TEXT = f"New VMs on Proxmox or ESXi need the {Perm.PROVIDERS_READ} permission to choose an account"
VM_PROVIDERS = ("proxmox", "esxi")


def _pool_text(network: dict[str, Any]) -> str:
    pool = network.get("pool") or None
    return f"{pool.get('first')} to {pool.get('last')}" if isinstance(pool, dict) and pool.get("first") else ""


def vm_account_view(account: ProviderAccount, *, off: str | None = None,
                    only_network: str | None = None) -> dict[str, Any]:
    """A Proxmox or ESXi account as the host selects offer it (P5 §12.2): ``New VM on <account>``, its networks
    (only ``only_network`` when the environment's VMs already use one) and why it can't be chosen, never a
    secret. ``off`` is a reason that comes first (a missing permission)."""
    problem = environments.vm_account_refusal(account, "hosts")
    networks = [{"name": str(n.get("name") or ""), "subnet": str(n.get("subnet") or ""), "pool": _pool_text(n)}
                for n in (account.config or {}).get("networks") or [] if isinstance(n, dict) and n.get("name")]
    if only_network is not None:
        networks = [n for n in networks if n["name"] == only_network]
    if off is None and problem is not None:
        off = problem.detail
    if off is None and not networks:
        off = f"{account.name} has no network Slipway can use: add one in Settings › Integrations"
    return {"id": str(account.id), "name": account.name, "provider": account.provider,
            "label": f"New VM on {account.name}", "off": off, "networks": networks}


async def vm_accounts(db: DB, ctx: AuthContext, *, account_id: uuid.UUID | None = None,
                      network: str | None = None) -> list[dict[str, Any]]:
    """The Proxmox and ESXi accounts a slot's host select offers a new VM on (P5 §12.2, §12.4): every account
    not removed, or only ``account_id`` with only ``network`` (an environment whose VMs share them, P5 §9.5).
    Without machines:write each is offered disabled with the reason; without providers:read none is (the
    accounts' names, networks and pools are that permission's, P5 §11)."""
    if not ctx.can(Perm.PROVIDERS_READ):
        return []
    stmt = select(ProviderAccount).where(ProviderAccount.provider.in_(VM_PROVIDERS),
                                         ProviderAccount.removed_at.is_(None)).order_by(ProviderAccount.name)
    if account_id is not None:
        stmt = stmt.where(ProviderAccount.id == account_id)
    off = None if ctx.can(Perm.MACHINES_WRITE) else MAKE_VMS_TEXT
    return [vm_account_view(a, off=off, only_network=network) for a in (await db.scalars(stmt)).all()]


async def _flow_context(db: DB, ctx: AuthContext) -> dict[str, Any]:
    """What the New environment flow and the settings page offer: repositories with a slipway.yml, hosts (with
    why one can't take a slot), Switchyard's traffic address and the Cloudflare integration's defaults."""
    repos = (await db.scalars(select(Repository).where(Repository.archived.is_(False))
                              .order_by(Repository.full_name))).all()
    # A host another environment made runs only that environment's slots (Decision 7), so it isn't offered.
    hosts = (await db.scalars(select(Host).where(Host.owner_environment_id.is_(None)).order_by(Host.name))).all()
    sy = await switchyard.load_config(db)
    cf = await cloudflare.load_config(db)
    # DigitalOcean placement (P4 §17.2): the accounts an environment can use, never a secret, and only to a user
    # who may list them (providers:read); without it the placement is disabled with the reason.
    see_accounts = ctx.can(Perm.PROVIDERS_READ)
    do_accounts = [{"id": str(a.id), "name": a.name, "region": (a.config or {}).get("region") or "",
                    "production": bool(a.production), "usable": bool(a.secret) and a.status != "error"}
                   for a in (await db.scalars(select(ProviderAccount).where(
                       ProviderAccount.provider == environments.DIGITALOCEAN, ProviderAccount.removed_at.is_(None))
                       .order_by(ProviderAccount.name))).all()] if see_accounts else []
    # Whether a Proxmox or ESXi account exists, so the Hosts step can say why it offers no new VM.
    vm_off = None if see_accounts or not await db.scalar(select(ProviderAccount.id).where(
        ProviderAccount.provider.in_(VM_PROVIDERS), ProviderAccount.removed_at.is_(None)).limit(1)) \
        else VM_ACCOUNTS_TEXT
    # Whether any provider account exists, whoever looks: with no SSH host the flow still renders (with the
    # placements disabled and their reasons) rather than "No hosts yet" (F48).
    any_account = bool(await db.scalar(select(ProviderAccount.id).where(
        ProviderAccount.provider.in_((environments.DIGITALOCEAN, *VM_PROVIDERS)),
        ProviderAccount.removed_at.is_(None)).limit(1)))
    if not ctx.can(Perm.PROVIDERS_SPEND):
        do_off = f"Creating a DigitalOcean environment needs the {Perm.PROVIDERS_SPEND} permission"
    elif not see_accounts:
        do_off = DO_ACCOUNTS_TEXT
    elif not do_accounts:
        do_off = "Add a DigitalOcean account in Settings › Integrations first"
    elif cf is None:
        do_off = "A DigitalOcean environment publishes its names in Cloudflare: set it up in Settings › Integrations first"
    else:
        do_off = None
    return {
        "do_accounts": do_accounts, "do_off": do_off, "do_production": any(a["production"] for a in do_accounts),
        "vm_accounts": await vm_accounts(db, ctx), "vm_off": vm_off, "has_provider_accounts": any_account,
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
    return {"slot": slot.slot, "sha7": _sha7(live.get("sha")), "host": slot.host.name if slot.host else ""}


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


# ------------------------------------------------- DigitalOcean environments (phase 4 §12.4, §17.2-17.5)

PENDING_OLD = timedelta(minutes=10)  # a create that hasn't shown up after this is called out (§17.3)
CERT_WARN_DAYS = 14  # a certificate this close to its end, with a failed renewal, is called out (§17.3)
OPEN_SSH = "0.0.0.0/0"
# What each DigitalOcean object is called in a sentence, and in the Delete dialog's list.
DO_KINDS = {"droplet": "droplet", "database": "database cluster", "load_balancer": "load balancer", "vpc": "VPC",
            "firewall": "cloud firewall", "certificate": "certificate", "bucket": "bucket",
            "spaces_key": "Spaces key"}
# The cost line (``cloud.cost.lines[].object``) each kind of object is priced by.
DO_COST_OBJECT = {"droplet": "droplet", "database": "database", "load_balancer": "load_balancer",
                  "bucket": "spaces"}
ADDRESS_HELD = "which Slipway lists separately"  # do_provision's address-check refusal (§9.2 step 5)
ADDRESS_HOLDER = re.compile(r"is still the address of host (\S+), which Slipway lists separately")
DO_DELETE_GOES = "Deleting removes every DigitalOcean object Slipway made for {env} and the DNS records it made."


def cost_figure(cents: int | None) -> str:
    """``84.00``: the figure a person types to confirm a cost (``do_rules.dollars``)."""
    return do_rules.dollars(int(cents or 0))


def first_line(text: str | None, limit: int = 300) -> str:
    """A job's error as one short sentence for a callout."""
    line = next((ln.strip() for ln in (text or "").splitlines() if ln.strip()), "")
    return line if len(line) <= limit else line[: limit - 1] + "…"


def _unit_cents(env: Environment, kind: str) -> int | None:
    """What one object of ``kind`` costs a month by the confirmed estimate (0 for the free kinds)."""
    wanted = DO_COST_OBJECT.get(kind)
    if wanted is None:
        return 0
    for line in ((env.cloud or {}).get("cost") or {}).get("lines") or []:
        if isinstance(line, dict) and line.get("object") == wanted:
            unit = line.get("unit_cents", line.get("cents"))
            return int(unit) if unit is not None else None
    return None


def resize_phrase(env: Environment, slot: str, text: str | None, *, active: bool, two: bool) -> str | None:
    """The one pending-size phrase (Decision 33), with ``when <slot> is idle`` for the active one of two: a deploy
    never resizes the droplet that takes the traffic."""
    if not text:
        return None
    return f"{text} when {slot} is idle" if active and two else text


async def _latest_cert_job(db: DB, env: Environment) -> Deployment | None:
    return await db.scalar(select(Deployment).options(NO_LOG).where(
        Deployment.environment_id == env.id, Deployment.kind == DeploymentKind.CERTIFICATE)
        .order_by(Deployment.created_at.desc(), Deployment.id.desc()).limit(1))


async def _address_problem(db: DB, env: Environment, mem: dict[str, Instance]) -> dict[str, Any] | None:
    """A host that holds an address DigitalOcean gave one of the droplets (§9.2 step 5): the newest deploy of an
    app slot failed with the address check's refusal. It names the host to fix."""
    for inst in environments.app_members(mem):
        last = await db.scalar(select(Deployment).options(NO_LOG).where(
            Deployment.instance_id == inst.id, Deployment.kind == DeploymentKind.DEPLOY)
            .order_by(Deployment.created_at.desc(), Deployment.id.desc()).limit(1))
        if last is None or last.status != DeploymentStatus.FAILED or ADDRESS_HELD not in (last.error or ""):
            continue
        found = ADDRESS_HOLDER.search(last.error or "")
        holder = await db.scalar(select(Host).where(Host.name == found.group(1))) if found else None
        return {"text": first_line(last.error), "host": holder, "deployment": last, "slot": str(inst.slot)}
    return None


async def do_view(db: DB, ctx: AuthContext, env: Environment, out: Any, mem: dict[str, Instance],
                  views: dict[uuid.UUID, dict[str, Any]]) -> dict[str, Any] | None:
    """What the environment page shows of a DigitalOcean environment (§17.3), from what Slipway recorded (no
    DigitalOcean read: the DigitalOcean card loads ``GET /environments/{id}/cloud`` itself): the header chips,
    the callouts in §17.3's order, the card's recorded half, the renewal line and the Delete dialog's lists."""
    if not environments.is_digitalocean(env):
        return None
    cloud = out.cloud or {}
    stored = dict(env.cloud or {})
    account = await db.get(ProviderAccount, env.provider_account_id) if env.provider_account_id else None
    sources = list(((account.config or {}).get("ssh_sources") or []) if account is not None else [])
    cost = stored.get("cost") or {}
    total = int(cost.get("total_cents") or 0)
    rows = list((await db.scalars(select(Resource).where(
        Resource.environment_id == env.id, Resource.provider == environments.DIGITALOCEAN)
        .order_by(Resource.kind, Resource.name))).all())
    from slipway.services import resources as resource_rules

    callouts: list[dict[str, Any]] = []
    # Billing (§12.4): a never-live environment that already has DigitalOcean objects, pending ones included.
    if cloud.get("billing_open"):
        n = int(cloud.get("objects") or len(rows))
        callouts.append({"key": "billing", "level": "warning",
                         "text": f"{n} DigitalOcean object{'' if n == 1 else 's'} exist{'s' if n == 1 else ''} for "
                                 f"{env.name} and cost about ${cost_figure(total)} a month: retry the failed deploy, "
                                 "or delete the environment to remove them."})
    if OPEN_SSH in sources and account is not None:
        callouts.append({"key": "open_ssh", "level": "warning",
                         "text": f"SSH to {env.name}'s droplets is open to the internet",
                         "link": ("/settings/integrations", f"Change {account.name}'s SSH sources")
                         if can_see_integrations(ctx) else None})
    # A gone (or never rebuilt) droplet of the active slot (§6.3): nothing answers through the load balancer.
    # Shown once the host is marked gone, by the DigitalOcean card's GET /cloud (K1) or a deploy's prepare;
    # until then the card's live read gives the same callout (slipway.js cloudCallouts).
    apps = environments.app_members(mem)
    active = environments.active_member(env, mem)
    if active is not None and active.host is not None and not ssh.host_is_built(active.host) \
            and env.status == EnvironmentStatus.LIVE:
        other = next((m for m in apps if m.id != active.id), None)
        text = (f"{active.slot}'s droplet is gone, so nothing answers through the load balancer: deploy to "
                f"{active.slot} to build it again")
        if other is not None and other.current_commit_sha and not environments.stale_of(other):
            text += f", or activate {other.slot}"
        callouts.append({"key": f"gone-{active.slot}", "level": "error", "text": text, "deploy_slot": str(active.slot)})
    now = utcnow()
    for row in rows:
        if not resource_rules.is_pending(row):
            continue
        sent = ((row.details or {}).get("pending") or {}).get("sent_at")
        try:
            at = datetime.fromisoformat(str(sent)) if sent else None
        except ValueError:
            at = None
        if at is not None and at.tzinfo is None:
            at = at.replace(tzinfo=UTC)
        if at is not None and now - at > PENDING_OLD:
            callouts.append({"key": f"pending-{row.id}", "level": "warning",
                             "text": f"A {DO_KINDS.get(row.kind, row.kind)} create from {fmt_dt(at)} hasn't shown "
                                     "up in DigitalOcean yet; the next deploy looks again"})
    holder = await _address_problem(db, env, mem)
    if holder is not None:
        callouts.append({"key": "address", "level": "error", "text": holder["text"], "host": holder["host"],
                         "deployment": holder["deployment"]})
    renewal = await _latest_cert_job(db, env)
    failed_renewal = renewal if renewal is not None and renewal.status == DeploymentStatus.FAILED else None
    cert = cloud.get("certificate") or None
    renew_text = None
    if failed_renewal is not None:
        renew_text = (f"Renews on its own; the last try failed {timeago(failed_renewal.finished_at or failed_renewal.created_at)}: "
                      f"{first_line(failed_renewal.error) or 'see the job'}")
    elif cert is not None:
        renew_text = "Renews on its own 30 days before it runs out"
    days = cert.get("days_left") if cert else None
    if cert is not None and days is not None and days <= CERT_WARN_DAYS and failed_renewal is not None:
        when = certs_date(cert.get("not_after"))
        callouts.append({"key": "certificate", "level": "error",
                         "text": f"{env.name}'s certificate runs out {when} (in {max(days, 0)} day{'' if days == 1 else 's'}), "
                                 f"and its last renewal failed: {first_line(failed_renewal.error) or 'see the job'}",
                         "renew": True, "deployment": failed_renewal})
    deactivated = (env.traffic_state or {}).get("deactivated")
    if isinstance(deactivated, dict) and env.active_slot_id is None and env.status == EnvironmentStatus.LIVE:
        callouts.append({"key": "deactivated", "level": "primary",
                         "text": f"{env.name} was taken off the air {timeago(_iso(deactivated.get('at')))}: its names "
                                 "answer 503 from the load balancer until their DNS records are moved or removed"})
    # The Delete dialog's lists (§15.10): every recorded object with its monthly price.
    objects = []
    for row in rows:
        unit = _unit_cents(env, row.kind)
        objects.append({"kind": DO_KINDS.get(row.kind, row.kind), "name": row.name,
                        "pending": resource_rules.is_pending(row),
                        "monthly": (f"${cost_figure(unit)} a month" if unit else "No charge") if unit is not None
                        else "Price not known"})
    sizes = cloud.get("sizes") or {}
    nodes = int(sizes.get("db_nodes") or 1)
    # The team the first DigitalOcean step froze (its id), by the name the account's last Test read.
    known = ((account.config or {}).get("team") or {}) if account is not None else {}
    team_name = (known.get("name") if isinstance(known, dict) and env.provider_team
                 and known.get("id") == env.provider_team else None) or env.provider_team
    region = cloud.get("region") or stored.get("region") or ""
    return {
        "account": account, "region": region, "team": team_name,
        "chip": f"DigitalOcean · {region}" if region else "DigitalOcean",
        "callouts": callouts, "cloud": cloud, "cert": cert, "cert_date": certs_date(cert.get("not_after")) if cert else None,
        "renew_text": renew_text, "renewal": renewal, "failed_renewal": failed_renewal,
        "total_cents": total, "total": cost_figure(total), "as_of": cost.get("as_of"),
        "sizes": sizes, "db_text": (f"{sizes.get('db_size')} × {nodes} node{'' if nodes == 1 else 's'}"
                                    + (f", PostgreSQL {sizes.get('db_version')}" if sizes.get("db_version") else "")
                                    + (" (with a standby)" if nodes == 2 else "")) if sizes.get("db_size") else "",
        "droplet_cents": _unit_cents(env, "droplet"), "droplet_figure": cost_figure(_unit_cents(env, "droplet")),
        "objects": objects, "ssh_open": OPEN_SSH in sources,
        "active_droplet": str(active.host.name) if active is not None and active.host is not None else "",
        # The slot the managed data's commands run on now (P4 §10.4), or None while no slot can run them.
        "runner": str(runner.slot) if (runner := data.runner_choice(env, mem).instance) is not None else None,
    }


def _iso(value: Any) -> datetime | None:
    try:
        at = datetime.fromisoformat(str(value)) if value else None
    except ValueError:
        return None
    return at.replace(tzinfo=UTC) if at is not None and at.tzinfo is None else at


def certs_date(value: Any) -> str:
    """A certificate's end as a date (``Dec 14, 2026``)."""
    at = _iso(value)
    return at.strftime("%b %d, %Y").replace(" 0", " ") if at is not None else str(value or "")


def delete_view(env: Environment, actions: dict[str, Any], ctx: AuthContext, mem: dict[str, Instance]) -> dict[str, Any]:
    """The Delete dialog's snapshot box and data choices (P4 §13, §17.4; Decision 26), from
    ``actions.delete_data``: ``snapshot`` is ``forced`` (production that holds data and can run its commands),
    ``ticked`` (it holds data, a slot can run its commands), ``unticked`` (it never held data: the note) or
    ``disabled`` (no slot can run the data commands)."""
    info = actions.get("delete_data") or {}
    held, can_snap, home = bool(info.get("holds_data", True)), bool(info.get("can_snapshot", True)), info.get("data_home")
    production = bool(info.get("production"))
    runner = data.runner_slot(env, mem) if env.data_mode == "managed" else "blue"
    if not held:
        state = "unticked"
    elif not can_snap:
        state = "disabled"
    elif production:
        state = "forced"
    else:
        state = "ticked"
    return {
        "state": state, "held": held, "home": home, "production": production, "runner": runner,
        "never_held": f"{env.name} never held data, so there is nothing to snapshot",
        "no_runner": f"No slot can run the data commands: deploy to {runner} first",
        "gone_text": (f"The database cluster and the bucket are destroyed with {env.name}. Without a snapshot the data "
                      "is gone for good.") if home == "its managed database" else
                     (f"{home} is destroyed with {env.name}. Without a snapshot the data is gone for good." if home else ""),
        "can_drop": ctx.can(Perm.DATA_RESET),
        "phrase": environments.production_phrase(env), "no_snapshot_phrase": environments.no_snapshot_phrase(env),
    }


def _vm_sentence_size(size: dict[str, Any] | None) -> str:
    """``8 vCPU, 16 GB, 128 GB`` (the Deploy dialog's resize sentence, P5 §9.4)."""
    return _vm_size(size).replace(" · ", ", ")


VM_NONE_TEXT = "{storage} ({kind}) can't take VM snapshots, so {vm} has none. Backups (above) still work."


async def vm_view(db: DB, ctx: AuthContext, env: Environment, mem: dict[str, Instance], actions: dict[str, Any],
                  two: bool) -> dict[str, Any] | None:
    """What the environment page shows of its VMs (P5 §12.3, §12.4), from Slipway's records only (the Slots card
    reads ``GET /environments/{id}/machines`` itself for power, Lost, Hidden and Off): per slot the VM, its account,
    address and sizes, Resize and Forget, and the Deploy dialog's sentences; the VM snapshots card's shape; and
    the Delete dialog's lists. None for an environment without a VM Slipway made."""
    found = await environments.env_machines(db, env)
    if not found:
        return None
    active = environments.active_member(env, mem)
    resize, forget = actions.get("resize") or {}, actions.get("forget") or {}
    slots: dict[str, dict[str, Any]] = {}
    for m in found:
        account = m.account
        account_name = account.name if account is not None else "its account"
        network = dict(m.network or {})
        snaps = [r.name for r in (await db.scalars(select(MachineSnapshot).where(
            MachineSnapshot.machine_id == m.id, MachineSnapshot.status == "ready")
            .order_by(MachineSnapshot.taken_at))).all()]
        size, applied = dict(m.size or {}), dict(m.applied or {})
        is_active = two and active is not None and active.slot == m.slot
        deploy: list[str] = []
        if m.stage != "ready":
            deploy.append(f"Slipway makes {m.name} first (several minutes).")
        elif m.slot != environments.DATA_SLOT and machines.size_differs(m) and not is_active:
            text = f"{m.name} is resized to {_vm_sentence_size(size)} after the backup: it shuts down for a minute or two."
            if not two:
                text += f" {env.name} is down meanwhile."
            deploy.append(text)
            grows = int(size.get("disk_gb") or 0) > int(applied.get("disk_gb") or 0)
            if m.provider == "esxi" and grows and snaps:
                deploy.append(f"ESXi can't keep VM snapshots across a disk grow: {', '.join(snaps)} "
                              f"{'is' if len(snaps) == 1 else 'are'} deleted.")
            if m.snapshot_mode == "none":
                spec = m.spec or {}
                storage = spec.get("storage") or spec.get("datastore") or "Its storage"
                deploy.append(f"No VM snapshot is taken first: {storage} can't take one.")
        problem = machines.account_problem(account)
        slots[m.slot] = {
            "machine": m, "name": m.name, "account": account_name, "provider": m.provider,
            "kind": PROVIDER_CHIPS.get(m.provider), "address": network.get("address") or "",
            "network": network.get("name") or "", "size": size, "applied": applied, "ready": m.stage == "ready",
            "min_disk": int(applied.get("disk_gb") or 0) or 20, "memory_gb": round(int(size.get("memory_mb") or 8192) / 1024, 2),
            "keep": m.keep_vm_snapshots, "active": is_active, "deploy": deploy, "snapshots": snaps,
            "resize": resize.get(m.slot) or {"available": False, "reason": None},
            "forget": forget.get(m.slot) or {"available": False, "reason": None},
            # Remove and Delete offer forget_vms when the account can't be used (no read needed for that); the
            # Slots card's live read adds a hidden or moved VM (slipway.js renderers.vm_live).
            "forgettable": problem is not None,
            "last_error": m.last_error,
        }
    # The VM snapshots card (P5 §12.3): an environment of one app slot in mode slot on a VM Slipway made.
    apps = environments.app_members(mem)
    card = None
    target = apps[0] if len(apps) == 1 else None
    vm = slots.get(str(target.slot)) if target is not None else None
    if env.data_mode == "slot" and vm is not None:
        m = vm["machine"]
        spec = m.spec or {}
        card = {"slot": str(target.slot), "vm": m.name, "account": vm["account"], "mode": m.snapshot_mode,
                "keep": m.keep_vm_snapshots, "action": actions.get("vm_snapshots") or {},
                "none_text": VM_NONE_TEXT.format(storage=spec.get("storage") or spec.get("datastore") or "Its storage",
                                                 kind=spec.get("storage_type") or "unknown", vm=m.name)}
    accounts = sorted({s["account"] for s in slots.values()})
    return {
        "slots": slots, "card": card, "accounts": accounts,
        "names": [s["name"] for s in (slots.get(k) for k in ("blue", "green", "data")) if s],
        "forgettable": any(s["forgettable"] for s in slots.values()),
        "can_forget": ctx.can(Perm.MACHINES_WRITE) and ctx.can(Perm.ENVIRONMENTS_DELETE),
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
    data_host = slots["data"].host.id if "data" in slots and slots["data"].host else None
    add_hosts = []
    if actions["add_slot"]["available"]:
        for h in (await db.scalars(select(Host).order_by(Host.name))).all():
            # A host another environment made runs only that environment's slots (Decision 7).
            off = host_rules.owned_host_refusal(h, action="add_slot") or (
                "Check it first" if not h.is_pinned else
                "The data server needs a host of its own" if h.id == data_host else
                "Its address must be an IP for the data server to let it in"
                if not environments.is_ip(h.client_address) else None)
            add_hosts.append({"host": h, "off": off})

    # A new VM for the second slot (P5 §9.5): on the account and network the environment's VMs share, if any.
    add_vms: list[dict[str, Any]] = []
    if actions["add_slot"]["available"] and not environments.is_digitalocean(env):
        own = next(iter(await environments.env_machines(db, env)), None)
        add_vms = await vm_accounts(db, ctx, account_id=own.account_id if own is not None else None,
                                    network=(own.network or {}).get("name") if own is not None else None)

    idle = slots.get(actions["activate"]["slot"]) if actions["activate"]["slot"] else None
    back = slots.get(actions["switch_back"]["slot"]) if actions["switch_back"]["slot"] else None
    names = [h for h in env.hostnames or [] if h.get("follows") != "server"]
    two = len(apps) == 2
    publishes = (env.traffic or {}).get("switch") in ("switchyard", environments.DO_LB) \
        or bool((env.traffic or {}).get("dns"))

    # The Slots card's host cells (one macro for every placement, S24b adds the VM cells): host_view per host.
    slot_hosts = [m.host for m in mem.values() if m.host is not None]
    views = await host_views(db, slot_hosts) if slot_hosts else {}
    host_cells = {}
    for s in out.slots:
        member = mem.get(s.slot)
        view = views.get(member.host.id) if member is not None and member.host is not None else None
        # The data server's VM keeps its size (P5 §9.4): only an app slot's pending resize is shown.
        own = (view or {}).get("pending_resize") if s.slot != environments.DATA_SLOT else None
        host_cells[s.slot] = {"view": view, "pending": resize_phrase(env, s.slot, s.resize_pending or own,
                                                                     active=s.active, two=two)}
    do = await do_view(db, ctx, env, out, mem, views)
    vms = await vm_view(db, ctx, env, mem, actions, two)
    lb = (env.traffic or {}).get("switch") == environments.DO_LB
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
        host_cells=host_cells, doenv=do, vmenv=vms, add_vms=add_vms, lb=lb, deleting=delete_view(env, actions, ctx, mem),
        production=bool(env.production), retiring=env.retiring_at is not None,
        active_name_count=len(names),
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
    d["by"] = started_by(dep)
    d["rebuild"] = rebuild_offer(dep, instance)
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
         "retry_of": await db.get(Deployment, dep.retry_of_id, options=[NO_LOG]) if dep.retry_of_id else None,
         "by": started_by(dep), "phrases": retry_phrases(env, actions["retry"]),
         "offers_drop_data": dep.kind == DeploymentKind.TEARDOWN and bool((dep.options or {}).get("drop_data")),
         "offers_forget_vms": offers_forget_vms(dep, actions["retry"])}
    return await render(request, db, "deployment_detail.html", ctx, dep=dep, instance=None, env=env, d=d)


# The steps of a Remove slot or a teardown whose failure a VM blocker explains (P5 §12.5).
VM_BLOCKER_STEPS = ("check", "machine", "machines")


def offers_forget_vms(dep: Deployment, retry: dict[str, Any]) -> bool:
    """Whether the retry offers ``forget_vms`` (P5 §12.5): a failed Remove slot or teardown of an environment with
    VMs (its list has a ``machine`` or ``machines`` step) that stopped in ``check`` or in that step."""
    if not retry.get("offers_forget_vms") or dep.status not in (DeploymentStatus.FAILED, DeploymentStatus.CANCELLED):
        return False
    steps = [st for st in dep.steps or [] if isinstance(st, dict)]
    if not any(st.get("key") in ("machine", "machines") for st in steps):
        return False
    return any(st.get("status") == "failed" and st.get("key") in VM_BLOCKER_STEPS for st in steps)


# Who a job with no user was started by (P4 §15.12): the renewal loop says so.
SYSTEM_STARTERS = {"renewals": "Slipway (certificate renewal)"}
# do_provision's refusal to make a gone cluster or bucket again by itself (P4 §10.1, open question 7).
GONE_DATA = "Slipway won't make an empty one by itself"


def started_by(dep: Deployment) -> str:
    """``Started by`` on a job's page: its user, or what in Slipway started it."""
    if dep.triggered_by is not None:
        return dep.triggered_by.display_name
    return SYSTEM_STARTERS.get(str((dep.options or {}).get("by") or ""), "Slipway")


def retry_phrases(env: Environment | None, retry: dict[str, Any]) -> list[dict[str, str]]:
    """The phrases a production teardown's retry asks again (P4 §13): ``needs_phrases`` as fields."""
    if env is None:
        return []
    texts = {"confirm_production": environments.production_phrase(env),
             "confirm_no_snapshot": environments.no_snapshot_phrase(env)}
    return [{"name": p, "phrase": texts[p]} for p in retry.get("needs_phrases") or [] if p in texts]


def rebuild_offer(dep: Deployment, instance: Instance) -> dict[str, Any] | None:
    """**Make it again, empty** on a slot deploy that failed because its environment's cluster or bucket is gone
    with the data (P4 §10.1): the retry with ``rebuild_data`` (data:reset and the name typed)."""
    if dep.kind != DeploymentKind.DEPLOY or dep.status not in (DeploymentStatus.FAILED, DeploymentStatus.CANCELLED):
        return None
    if instance.environment_id is None or GONE_DATA not in (dep.error or ""):
        return None
    what = "bucket" if "bucket" in (dep.error or "").split(GONE_DATA)[0] else "database cluster"
    return {"what": what, "name": data.confirm_name(instance)}


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


def can_see_integrations(ctx: AuthContext) -> bool:
    """The Integrations tab and page: the account cards need providers:read, the Switchyard and Cloudflare cards
    settings:write; either shows the page (P4 §17.1, P5 §12.1)."""
    return ctx.can(Perm.PROVIDERS_READ) or ctx.can(Perm.SETTINGS_WRITE)


templates.env.globals.update(can_see_integrations=can_see_integrations)

# The account cards, in the order the page shows them, and what each calls its secret.
ACCOUNT_CARDS = (
    ("digitalocean", "DigitalOcean", "Droplets, a managed database, a load balancer and Spaces for environments "
                                     "Slipway places on DigitalOcean."),
    ("proxmox", "Proxmox", "Proxmox VE clusters Slipway makes VMs on for environments' slots."),
    ("esxi", "VMware ESXi", "Standalone ESXi hosts Slipway makes VMs on for environments' slots."),
)
ACCOUNT_STATUS = {"unknown": ("Not tested", ""), "ok": ("OK", "success"), "warning": ("Warning", "warning"),
                  "error": ("Failed", "error")}
CHECK_LEVELS = {"ok": ("OK", "success"), "note": ("Note", "plain"), "warning": ("Warning", "warning"),
                "error": ("Failed", "error")}


def dollars(cents: int | None) -> str:
    """``$47`` or ``$12.50`` for a sum in cents."""
    if cents is None:
        return ""
    whole, part = divmod(int(cents), 100)
    return f"${whole:,}" if not part else f"${whole:,}.{part:02d}"


def limit_field(cents: int | None) -> str:
    """The Monthly limit field's value for a sum in cents, exact (``150``, ``1234567.89``), so that a dialog saved
    without touching it sends the same cents back; ``""`` for no limit."""
    if cents is None:
        return ""
    whole, part = divmod(int(cents), 100)
    return f"{whole}" if not part else f"{whole}.{part:02d}"


def account_view(out: dict[str, Any]) -> dict[str, Any]:
    """One account card row from its ``ProviderAccountOut`` (as JSON): the chips and texts, and ``edit``, what the
    account dialog is filled with (never a secret: only whether one is set and its hint)."""
    status = ACCOUNT_STATUS.get(out["status"], (out["status"].title(), ""))
    checked = out.get("last_checked_at")
    checked_at = datetime.fromisoformat(checked) if isinstance(checked, str) else checked
    edit = {k: v for k, v in out.items() if k not in ("checks", "facts", "used_by", "created_at", "updated_at",
                                                        "last_checked_at", "removed_at")}
    if out["provider"] == "digitalocean":
        edit["monthly_limit"] = limit_field(out.get("monthly_limit_cents"))
    removed = out.get("removed_at")
    view = {
        "a": out, "edit": edit, "status": status, "checked_at": checked_at,
        "removed_at": datetime.fromisoformat(removed) if isinstance(removed, str) else removed,
        "status_title": f"Tested {fmt_dt(checked_at)}" if checked_at else "Not tested yet",
        "checks": [{**c, "badge": CHECK_LEVELS.get(str(c.get("level")), (str(c.get("level")), ""))}
                   for c in out.get("checks") or [] if isinstance(c, dict)],
        "envs": sorted({u["environment"] for u in out.get("used_by") or []}),
        "vms": [u for u in out.get("used_by") or [] if u.get("name")],
        "untrusted": out["provider"] != "digitalocean" and not out.get("tls") and not out.get("removed"),
    }
    if out["provider"] == "digitalocean":
        view["estimate"] = dollars(out.get("estimate_cents") or 0)
        view["limit"] = dollars(out.get("monthly_limit_cents")) if out.get("monthly_limit_cents") is not None else ""
    else:
        view["networks"] = [str(n.get("name")) for n in out.get("networks") or [] if isinstance(n, dict)]
    return view


async def account_cards(db: DB) -> list[dict[str, Any]]:
    """The three account cards of the Integrations page, each with its accounts (removed ones last)."""
    by_provider: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for account in await accounts_service.list_accounts(db):
        estimate = await accounts_service.estimate_cents(db, account.id) if account.provider == "digitalocean" else 0
        out = provider_account_out(account, used_by=await accounts_service.used_by(db, account),
                                   estimate_cents=estimate).model_dump(mode="json")
        by_provider[account.provider].append(account_view(out))
    return [{"provider": p, "title": t, "lede": lede,
             "accounts": sorted(by_provider.get(p, []), key=lambda v: (v["a"]["removed"], v["a"]["name"].lower()))}
            for p, t, lede in ACCOUNT_CARDS]


@router.get("/settings/integrations")
async def settings_integrations(request: Request, db: DB, ctx: PageAuth) -> HTMLResponse:
    if not can_see_integrations(ctx):
        raise PageForbidden(Perm.PROVIDERS_READ)
    context: dict[str, Any] = {"can_settings": ctx.can(Perm.SETTINGS_WRITE), "can_accounts": ctx.can(Perm.PROVIDERS_READ)}
    if context["can_settings"]:
        row = await db.scalar(select(AppSetting).where(AppSetting.key == switchyard.SETTING_KEY))
        from slipway.api.v1.settings import _cloudflare_out, _dns_users

        cf_row = await db.scalar(select(AppSetting).where(AppSetting.key == cloudflare.SETTING_KEY))
        context.update(
            sy=(row.value if row else None) or {}, sy_has_key=bool(row and row.secret),
            sy_key_prefix=(row.secret or "")[: switchyard.KEY_PREFIX_LEN] if row else "",
            required_operations=switchyard.REQUIRED_OPERATIONS,
            cf=_cloudflare_out(cf_row), cf_users=await _dns_users(db),
        )
    if context["can_accounts"]:
        context.update(cards=await account_cards(db), do_regions=sorted(do_rules.SPACES_REGIONS))
    return await render(request, db, "settings/integrations.html", ctx, tab="integrations", **context)


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
