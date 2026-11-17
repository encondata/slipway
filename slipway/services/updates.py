"""Slipway's own version, and upgrades of it started from the UI.

An upgrade recreates the Slipway container, so it cannot run inside it. Slipway SSHes to the server it runs on (a
host registered in Slipway, with a pinned key), writes the upgrade script (``slipway/updates/upgrade.sh``, the
RUNNING Slipway's copy) into ``<install folder>/.slipway-updates/`` and starts it detached. The script writes its
status to ``<id>.json`` and its output to ``<id>.log`` there; that folder on the server is the source of truth,
and the ``updates`` setting only keeps what Slipway last read from it.

Everything read back from the server is treated as untrusted: it is size-limited, validated against fixed
patterns and enums, and clipped before it is stored or audited. Every value placed in a remote command is a
validated id, sha or branch, quoted with ``shlex.quote``, and git revisions follow ``--end-of-options``.
"""

from __future__ import annotations

import asyncio
import copy
import importlib.metadata
import importlib.resources
import json
import logging
import os
import posixpath
import re
import secrets
import shlex
import socket
import uuid
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from slipway import __version__
from slipway.core.permissions import Perm, has_permission
from slipway.db.base import utcnow
from slipway.db.session import session_scope
from slipway.models import AppSetting, AuditEvent, Deployment, DeploymentStatus, Host, Role, User
from slipway.services import audit, ssh

log = logging.getLogger(__name__)

SETTING_KEY = "updates"
WORK_DIR = ".slipway-updates"
LOCK_FILE = "/tmp/slipway-upgrade.lock"  # the script's lock; outside the share, cleared on reboot
BOOT_ID_FILE = "/proc/sys/kernel/random/boot_id"
MAX_RUNS = 20
MAX_BRANCHES = 200
MAX_COMMITS = 100
MAX_STATUS_BYTES = 64 * 1024
LOG_TAIL_BYTES = 64 * 1024
PRIVILEGED_FILES = ("docker-compose.yml", "Dockerfile", ".dockerignore", "install.sh", "slipway/updates/upgrade.sh")

# Statuses the script writes, plus two of Slipway's own: ``interrupted`` (the script died without finishing)
# and ``unknown`` (the status file is missing or doesn't validate).
SCRIPT_STATUSES = ("running", "succeeded", "failed", "rolled_back", "rollback_failed")
STATUSES = (*SCRIPT_STATUSES, "interrupted", "unknown")
FINAL_STATUSES = frozenset({"succeeded", "failed", "rolled_back", "rollback_failed", "interrupted"})
# In the order the script runs them (``rollback`` only on a failure after the switch, ``cleanup`` on success).
STEPS = ("preflight", "fetch", "build", "backup", "switch", "health", "rollback", "cleanup")

ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,100}$")
CONTAINER_RE = re.compile(r"^[0-9a-f]{12,64}$")
IMAGE_ID_RE = re.compile(r"^[0-9a-f]{64}$")
GITHUB_PART_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
BOOT_ID_RE = re.compile(r"^[0-9a-f-]{8,64}$")
_GITHUB_URLS = (
    re.compile(r"^https://(?:[^/@\s]+@)?github\.com/([^/\s]+)/([^/\s]+?)(?:\.git)?/?$"),
    re.compile(r"^(?:ssh://)?git@github\.com[:/]([^/\s]+)/([^/\s]+?)(?:\.git)?/?$"),
)
_CREDENTIALS = re.compile(r"://[^/@\s]+@")
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

# Timeouts for remote commands, in seconds.
QUICK_TIMEOUT = 30
FETCH_TIMEOUT = 300
# After starting the script: how long the request waits for its status file, and how often it looks. A
# script that is slower than that (a spun-down disk) is left running and read later; it counts as failed only
# when its process is gone without a status file, or no status file shows up within LAUNCH_GRACE.
LAUNCH_WAIT = 10.0
LAUNCH_POLL = 1.0
LAUNCH_GRACE = 600
# The overview reconciles running runs over SSH, but never holds up the page longer than this.
OVERVIEW_TIMEOUT = 10.0
FIRST_CHECK_DELAY = 300

MSG_NOT_IN_DOCKER = "Slipway isn't running in Docker here, so it can't upgrade itself; run install.sh"
MSG_NOT_CONFIGURED = "Choose the host Slipway runs on first"
MSG_COMMIT_UNKNOWN = "Slipway can't tell which commit it runs"
MSG_COMMIT_UNSURE = (
    "Slipway can't tell which commit it runs: this image doesn't record it and the last upgrade didn't finish "
    "cleanly, so the checkout may be ahead of it. Run install.sh once on the server"
)
MSG_UPGRADING = "Slipway is being upgraded. Try again when the upgrade finishes."
MSG_LAUNCH_PENDING = "The upgrade was started. Slipway is waiting for it to write its first status."
MSG_RUN_RUNNING = "Another upgrade is running"
MSG_CHECK_SKIPPED = "An upgrade is running"
MSG_DEPLOYMENT_RUNNING = "A deployment is running. Try again when it finishes."
MSG_TOKEN = "Upgrades can only be started from the web UI"
MSG_DIRTY = "Local changes in the install folder"
MSG_INTERRUPTED = (
    "The upgrade stopped before it finished (the server restarted or the script was killed). Check docs/updates.md."
)


class UpdateError(Exception):
    """A refusal with an HTTP status, shown to the user as ``detail`` (``field`` names the input at fault)."""

    def __init__(self, status: int, detail: str, field: str | None = None) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.field = field
        self.recorded = False  # True once the run was recorded and audited as started


class Remote(Protocol):
    async def run(self, command: str, *, check: bool = ..., on_line: Any = ..., timeout: float | None = ...) -> tuple[int, str]: ...
    async def write_text(self, remote: str, content: str, mode: int = ...) -> None: ...


def connect(target: ssh.SSHTarget) -> AbstractAsyncContextManager[Remote]:
    """Open an SSH session (tests replace this, like ``deployer.connect``)."""
    return ssh.open_session(target)


# ------------------------------------------------------------------------ validators
# Applied at every entry point: request bodies, path parameters, settings read back, and every value the
# server sends.


def valid_sha(value: object) -> bool:
    return isinstance(value, str) and bool(SHA_RE.fullmatch(value))


def valid_id(value: object) -> bool:
    return isinstance(value, str) and bool(ID_RE.fullmatch(value))


def valid_branch(value: object) -> bool:
    """The script's rule, plus git's: no ``..``, no leading ``-`` or ``/``, no trailing ``/`` or ``.lock``."""
    if not isinstance(value, str) or not BRANCH_RE.fullmatch(value):
        return False
    if ".." in value or value.startswith(("-", "/")) or value.endswith(("/", ".lock", ".")):
        return False
    return all(part and not part.startswith(".") and not part.endswith(".lock") for part in value.split("/"))


def valid_dir(value: object) -> bool:
    """An absolute, normalised folder path without control characters, at most 1024 characters."""
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 1024 or value == "/":
        return False
    if _CONTROL.search(value) or "\n" in value or "\t" in value:
        return False
    return posixpath.normpath(value) == value and ".." not in value.split("/") and not value.startswith("//")


def new_run_id() -> str:
    return utcnow().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)


def clean_text(value: object, limit: int) -> str:
    """Remote text made storable and displayable: no NUL or control characters, clipped."""
    if not isinstance(value, str):
        return ""
    return _CONTROL.sub("", _ANSI.sub("", value))[:limit]


def redact(text: str) -> str:
    """Credentials in URLs (``https://user:token@host``) replaced, ANSI escapes and control characters removed."""
    text = _ANSI.sub("", text.replace("\x00", ""))
    text = _CREDENTIALS.sub("://***@", text)
    return _CONTROL.sub("", text)


def _iso(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.isoformat()


def _now() -> str:
    return utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _sep() -> str:
    """A section separator for one remote command; random, so remote text cannot forge it."""
    return f"::slipway-{secrets.token_hex(8)}::"


def _sections(output: str, sep: str, count: int) -> list[str]:
    parts = output.split(sep, count - 1)
    parts += [""] * (count - len(parts))
    return [p.strip("\n") for p in parts]


def short(sha: str | None) -> str:
    return (sha or "")[:7]


# ------------------------------------------------------------------------- GitHub links


def parse_github(url: str) -> dict[str, str] | None:
    """``{owner, repo}`` from a github.com origin URL (https or ssh), or None. Credentials are never kept."""
    url = url.strip()
    for pattern in _GITHUB_URLS:
        if m := pattern.fullmatch(url):
            owner, repo = m.group(1), m.group(2)
            if all(GITHUB_PART_RE.fullmatch(p) and p not in (".", "..") for p in (owner, repo)):
                return {"owner": owner, "repo": repo}
    return None


def _valid_github(github: object) -> dict[str, str] | None:
    if not isinstance(github, dict):
        return None
    owner, repo = github.get("owner"), github.get("repo")
    if all(isinstance(p, str) and GITHUB_PART_RE.fullmatch(p) and p not in (".", "..") for p in (owner, repo)):
        return {"owner": owner, "repo": repo}  # type: ignore[dict-item]
    return None


def commit_url(github: object, sha: object) -> str | None:
    gh = _valid_github(github)
    if gh is None or not valid_sha(sha):
        return None
    return f"https://github.com/{gh['owner']}/{gh['repo']}/commit/{sha}"


def compare_url(github: object, base: object, head: object) -> str | None:
    gh = _valid_github(github)
    if gh is None or not valid_sha(base) or not valid_sha(head):
        return None
    return f"https://github.com/{gh['owner']}/{gh['repo']}/compare/{base}...{head}"


# ------------------------------------------------------------------- running version


def in_docker() -> bool:
    return Path("/.dockerenv").exists()


def container_id() -> str:
    return socket.gethostname()


def package_version() -> str:
    try:
        return importlib.metadata.version("slipway")
    except importlib.metadata.PackageNotFoundError:
        return __version__


def script_text() -> str:
    """The RUNNING Slipway's upgrade script (package data), never the checkout's."""
    try:
        return (importlib.resources.files("slipway.updates") / "upgrade.sh").read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError) as exc:
        raise UpdateError(500, "The upgrade script is missing from this Slipway build") from exc


def running_version() -> dict[str, Any]:
    raw = os.environ.get("SLIPWAY_COMMIT", "").strip()
    branch = os.environ.get("SLIPWAY_BRANCH", "").strip()
    return {
        "version": package_version(),
        "commit": raw if valid_sha(raw) else None,
        # Set but not a full sha: Slipway can't tell what it runs, so it doesn't fall back to the checkout.
        "commit_invalid": bool(raw) and not valid_sha(raw),
        "short": short(raw) if valid_sha(raw) else "",
        "branch": branch if valid_branch(branch) else None,
        "built_at": _iso(os.environ.get("SLIPWAY_BUILT_AT", "").strip()),
    }


def _from_commit(head: str | None, state: dict[str, Any] | None = None) -> str:
    """The commit Slipway runs: the image's stamp, else the checkout's HEAD. Raises 409 when neither is valid.

    HEAD stands in only while it can be trusted: not when the newest run on this install was cut off
    (``interrupted``, ``rollback_failed``) or left HEAD at its target without succeeding, since the checkout
    may then be ahead of the unstamped image that runs.
    """
    running = running_version()
    if running["commit"]:
        return running["commit"]
    if running["commit_invalid"] or not valid_sha(head):
        raise UpdateError(409, MSG_COMMIT_UNKNOWN)
    if state is not None:
        last = next((r for r in state["runs"] if r.get("host_id") == state.get("host_id") and r.get("dir") == state.get("dir")), None)
        if last is not None and (
            last.get("status") in ("interrupted", "rollback_failed")
            or (last.get("to") == head and last.get("status") != "succeeded")
        ):
            raise UpdateError(409, MSG_COMMIT_UNSURE)
    return head  # type: ignore[return-value]


# ------------------------------------------------------------------------ the setting

# Serialises read-modify-writes of the ``updates`` row in this process (SQLite ignores FOR UPDATE); the row is
# also selected FOR UPDATE, which serialises them across processes on PostgreSQL.
_state_lock = asyncio.Lock()
# Held while a run is being validated, recorded and started, so a second click is refused at once.
_start_lock = asyncio.Lock()


def _normalise(value: dict[str, Any] | None) -> dict[str, Any]:
    value = dict(value or {})
    state: dict[str, Any] = {
        "host_id": value.get("host_id"),
        "host_name": value.get("host_name"),
        "hostname": value.get("hostname"),
        "port": value.get("port"),
        "username": value.get("username"),
        "host_fingerprint": value.get("host_fingerprint"),
        "dir": value.get("dir") if valid_dir(value.get("dir")) else None,
        "branch": value.get("branch") if valid_branch(value.get("branch")) else None,
        "last_check": value.get("last_check") if isinstance(value.get("last_check"), dict) else None,
        "branches": value.get("branches") if isinstance(value.get("branches"), list) else [],
        "runs": [r for r in value.get("runs") or [] if isinstance(r, dict) and valid_id(r.get("id"))],
    }
    return state


async def load_state(db: AsyncSession) -> dict[str, Any]:
    row = await db.scalar(select(AppSetting).where(AppSetting.key == SETTING_KEY))
    return _normalise(copy.deepcopy(row.value) if row else None)


@asynccontextmanager
async def edit_state(db: AsyncSession) -> AsyncIterator[dict[str, Any]]:
    """Read-modify-write of the ``updates`` row, committed on exit with whatever else the caller added.

    The caller's open transaction is committed first, so nothing waits for the lock while holding a read
    transaction open (SQLite would then refuse the writer).
    """
    await db.commit()
    async with _state_lock:
        try:
            row = await db.scalar(
                select(AppSetting).where(AppSetting.key == SETTING_KEY).with_for_update()
                .execution_options(populate_existing=True)
            )
            if row is None:
                row = AppSetting(key=SETTING_KEY, value={})
                db.add(row)
            state = _normalise(copy.deepcopy(row.value))
            yield state
            row.value = copy.deepcopy(state)
            await db.commit()
        except BaseException:
            await db.rollback()
            raise


def configured(state: dict[str, Any]) -> bool:
    return bool(state.get("host_id") and state.get("dir") and state.get("branch"))


def _identity(source: dict[str, Any]) -> dict[str, Any]:
    keys = ("host_id", "host_name", "hostname", "port", "username", "host_fingerprint", "dir")
    return {k: source.get(k) for k in keys}


def _same_server(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """Same host (address, user, pinned key) and folder; the host's display name doesn't count."""
    keys = ("host_id", "hostname", "port", "username", "host_fingerprint", "dir")
    return all(a.get(k) == b.get(k) for k in keys)


def _host_matches(ident: dict[str, Any], host: Host | None) -> bool:
    return bool(
        host is not None and host.is_pinned
        and ident.get("host_fingerprint") == host.host_key_fingerprint
        and ident.get("hostname") == host.hostname
        and ident.get("port") == host.port
        and ident.get("username") == host.username
    )


def _host_changed_message(ident: dict[str, Any]) -> str:
    return f"{ident.get('host_name') or 'The host'} changed since updates were set up: save it on the Updates page again"


async def _get_host(db: AsyncSession, host_id: object) -> Host | None:
    try:
        return await db.get(Host, uuid.UUID(str(host_id)))
    except (ValueError, TypeError):
        return None


async def verified_host(
    db: AsyncSession, ident: dict[str, Any], *, actor: User | None = None, request: Request | None = None
) -> Host:
    """The Host row, when it still has the address, user and pinned key recorded with ``ident``.

    Anyone with hosts:write can edit a host's address or reset its key, so a difference is refused (and
    audited) until an admin saves the updates host again.
    """
    host = await _get_host(db, ident.get("host_id"))
    if _host_matches(ident, host):
        assert host is not None
        return host
    message = _host_changed_message(ident)
    audit.record(
        db, "updates.host_changed", actor=actor, request=request, summary=message,
        details={"host_id": ident.get("host_id"), "host_name": ident.get("host_name"), "deleted": host is None},
    )
    await db.commit()
    raise UpdateError(409, message, "host_id")


async def upgrade_running(db: AsyncSession) -> bool:
    """Whether a Slipway upgrade is (as last read) running: deployments wait until it ends."""
    return any(r.get("status") == "running" for r in (await load_state(db))["runs"])


async def deployment_active(db: AsyncSession) -> bool:
    active = (DeploymentStatus.QUEUED.value, DeploymentStatus.RUNNING.value)
    return await db.scalar(select(Deployment.id).where(Deployment.status.in_(active)).limit(1)) is not None


async def exposed_roles(db: AsyncSession) -> list[str]:
    """Roles that can create or deploy instances: on Slipway's own server, that is root on Slipway."""
    roles = (await db.scalars(select(Role).order_by(Role.name))).all()
    out = []
    for role in roles:
        granted = frozenset(role.permissions or [])
        if has_permission(granted, Perm.INSTANCES_WRITE) or has_permission(granted, Perm.DEPLOYMENTS_CREATE):
            out.append(role.name)
    return out


# ------------------------------------------------------------------------ self check

_INSPECT_FORMAT = "{{println .Id}}{{json .Config.Labels}}"


async def self_check(remote: Remote, host: Host) -> str:
    """Find this Slipway's container on ``host`` and return its install folder (compose working_dir)."""
    cid = container_id()
    if not CONTAINER_RE.fullmatch(cid):
        raise UpdateError(409, "Slipway can't tell which container it runs in (its hostname isn't a container id)", "host_id")
    status, out = await remote.run(
        f"docker inspect --format {shlex.quote(_INSPECT_FORMAT)} {cid}", check=False, timeout=QUICK_TIMEOUT
    )
    if status != 0:
        if "no such" in out.lower():
            raise UpdateError(409, f"{host.name} doesn't run this Slipway: no container {cid} there", "host_id")
        raise UpdateError(502, f"docker inspect failed on {host.name}: {redact(ssh.clip(out, 500))}")
    lines = [line.strip() for line in out.strip().splitlines() if line.strip()]
    ids = [line for line in lines if IMAGE_ID_RE.fullmatch(line)]
    try:
        labels = json.loads(lines[-1]) if lines else None
    except ValueError:
        labels = None
    if not ids or not ids[0].startswith(cid) or not isinstance(labels, dict):
        raise UpdateError(409, f"{host.name} doesn't run this Slipway: no container {cid} there", "host_id")
    if labels.get("com.docker.compose.project") != "slipway" or labels.get("com.docker.compose.service") != "slipway":
        raise UpdateError(409, f"Container {cid} on {host.name} isn't the slipway service of the slipway compose project", "host_id")
    folder = labels.get("com.docker.compose.project.working_dir")
    if not valid_dir(folder):
        raise UpdateError(409, f"Slipway's install folder on {host.name} has an unusable path", "host_id")
    q = shlex.quote
    status, _ = await remote.run(
        f"test -f {q(folder + '/docker-compose.yml')} && test -d {q(folder + '/.git')}", check=False, timeout=QUICK_TIMEOUT
    )
    if status != 0:
        raise UpdateError(409, f"{folder} on {host.name} isn't a Slipway install folder (no docker-compose.yml or .git). Run install.sh.", "host_id")
    return folder


# ---------------------------------------------------------------------- configuration


async def configure(
    db: AsyncSession, *, host_id: uuid.UUID, branch: str | None, actor: User, request: Request | None = None
) -> dict[str, Any]:
    if branch is not None and not valid_branch(branch):
        raise UpdateError(422, "That branch name isn't allowed", "branch")
    if not in_docker():
        raise UpdateError(409, MSG_NOT_IN_DOCKER, "host_id")
    host = await db.get(Host, host_id)
    if host is None:
        raise UpdateError(404, "Host not found", "host_id")
    if not host.is_pinned:
        raise UpdateError(409, f"Check {host.name} first so Slipway pins its SSH key", "host_id")
    target = ssh.SSHTarget.from_host(host)
    ident = {"host_id": str(host.id), "host_name": host.name, "hostname": host.hostname, "port": host.port,
             "username": host.username, "host_fingerprint": host.host_key_fingerprint}
    await db.commit()
    async with connect(target) as remote:
        folder = await self_check(remote, host)
        if branch is None:
            _, out = await remote.run(
                f"cd -- {shlex.quote(folder)} && git symbolic-ref --short -q HEAD", check=False, timeout=QUICK_TIMEOUT
            )
            found = out.strip().splitlines()[-1].strip() if out.strip() else ""
            branch = found if valid_branch(found) else "main"
    async with edit_state(db) as state:
        old = {"host_id": state["host_id"], "dir": state["dir"], "branch": state["branch"]}
        if (old["host_id"], old["dir"], old["branch"]) != (ident["host_id"], folder, branch):
            state["last_check"] = None
            state["branches"] = []
        state.update(ident, dir=folder, branch=branch)
        # Runs still going on this install were recorded with the host's old address, user or key; saving it
        # is the trust decision their reads wait for, so they follow the host from now on.
        for run in state["runs"]:
            if run.get("status") in ("running", "unknown") and run.get("host_id") == ident["host_id"] and run.get("dir") == folder:
                run.update(ident)
        audit.record(
            db, "updates.configured", actor=actor, request=request,
            summary=f"Set Slipway's updates to {host.name}:{folder}, following {branch}",
            details={"old_host_id": old["host_id"], "host_id": ident["host_id"], "host_name": host.name,
                     "old_dir": old["dir"], "dir": folder, "old_branch": old["branch"], "branch": branch},
        )
    return await overview(db, remote=False)


# ------------------------------------------------------------------------------ check

_REF_FORMAT = "%(objectname)%1f%(refname)%1f%(committerdate:iso-strict)%1f%(authorname)%1f%(subject)"
_LOG_FORMAT = "%H%x1f%h%x1f%cI%x1f%an%x1f%s"
_ORIGIN_PREFIX = "refs/remotes/origin/"


def _locked(inner: str) -> str:
    """Run ``inner`` under the upgrade script's lock: exit 1 means an upgrade holds it.

    ``inner`` itself only exits 0, 3 or 4. The script falls back to a lock folder (``<lock>.d/owner`` holding
    "pid boot_id") when flock is missing or fails for any reason other than the lock being held, so the same
    happens here: any other flock exit means flock didn't work, and the lock folder counts while its pid is
    alive. A folder without an owner counts for its first minute (its holder may still be writing the file);
    after that the script takes it over, so it doesn't count here either.
    """
    q = shlex.quote
    lock_dir = f"{LOCK_FILE}.d"
    return (
        f"if command -v flock >/dev/null 2>&1; then flock -n {LOCK_FILE} sh -c {q(inner)}; rc=$?; "
        f"case $rc in 0|1|3|4) exit $rc;; esac; fi; "
        f"if [ -d {lock_dir} ]; then "
        f"if read -r p b 2>/dev/null < {lock_dir}/owner && [ -n \"$p\" ]; then kill -0 \"$p\" 2>/dev/null && exit 1; "
        f"elif [ -n \"$(find {lock_dir} -maxdepth 0 -mmin -1 2>/dev/null)\" ]; then exit 1; fi; fi; "
        f"sh -c {q(inner)}"
    )


def _git_fetch(branch: str | None) -> str:
    refspec = f"+refs/heads/{branch}:refs/remotes/origin/{branch}" if branch else "+refs/heads/*:refs/remotes/origin/*"
    prune = "" if branch else " --prune"
    return (
        "export GIT_TERMINAL_PROMPT=0; "
        "if [ \"$(git rev-parse --is-shallow-repository 2>/dev/null)\" = true ]; then "
        "git fetch --quiet --unshallow origin </dev/null 2>&1 || exit 4; fi; "
        f"git fetch --quiet{prune} origin {shlex.quote(refspec)} </dev/null 2>&1 || exit 4"
    )


def _read_command(folder: str, branch: str, sep: str, *, all_branches: bool) -> str:
    """Fetch (under the lock), then the checkout's HEAD, local changes, origin URL and branch heads."""
    q = shlex.quote
    parts = [
        f"cd -- {q(folder)} || exit 3",
        _git_fetch(None if all_branches else branch),
        f"echo {sep}", "git rev-parse --verify -q HEAD",
        f"echo {sep}", "git status --porcelain --untracked-files=no 2>/dev/null | head -n 50",
        f"echo {sep}", "git remote get-url origin 2>/dev/null",
        f"echo {sep}", f"git for-each-ref --format={q(_REF_FORMAT)} {q(_ORIGIN_PREFIX + branch)}",
    ]
    if all_branches:
        parts += [f"echo {sep}",
                  f"git for-each-ref --count={MAX_BRANCHES + 1} --sort=-committerdate --format={q(_REF_FORMAT)} refs/remotes/origin"]
    parts.append("exit 0")
    return _locked("\n".join(parts))


def _parse_ref(line: str) -> dict[str, Any] | None:
    parts = line.split("\x1f", 4)
    if len(parts) != 5 or not parts[1].startswith(_ORIGIN_PREFIX):
        return None
    sha, ref, date, author, subject = parts
    name = ref[len(_ORIGIN_PREFIX):]
    if not valid_sha(sha) or name == "HEAD":
        return None
    return {"name": name if valid_branch(name) else clean_text(name, 100), "valid": valid_branch(name), "sha": sha,
            "short": short(sha), "date": _iso(date), "author": clean_text(author, 200), "subject": clean_text(subject, 200)}


def _parse_commit(line: str) -> dict[str, Any] | None:
    parts = line.split("\x1f", 4)
    if len(parts) != 5:
        return None
    sha, abbrev, date, author, subject = parts
    if not valid_sha(sha) or not re.fullmatch(r"[0-9a-f]{4,40}", abbrev):
        return None
    return {"sha": sha, "short": short(sha), "date": _iso(date), "author": clean_text(author, 200),
            "subject": clean_text(subject, 200)}


def _fetch_failed(status: int, output: str, host: Host, folder: str) -> UpdateError:
    tail = redact(ssh.clip("\n".join(output.strip().splitlines()[-ssh.TAIL_LINES:]), 1000))
    if status == 3:
        return UpdateError(502, f"Can't open {folder} on {host.name}")
    if status == 4:
        return UpdateError(502, f"git fetch failed in {folder} on {host.name}: {tail}")
    return UpdateError(502, f"Reading the install folder on {host.name} failed (exit {status}): {tail}")


async def _read_checkout(
    remote: Remote, host: Host, folder: str, branch: str, *, all_branches: bool
) -> dict[str, Any]:
    sep = _sep()
    status, out = await remote.run(
        _read_command(folder, branch, sep, all_branches=all_branches), check=False, timeout=FETCH_TIMEOUT
    )
    if status == 1:
        raise UpdateError(409, MSG_CHECK_SKIPPED if all_branches else MSG_RUN_RUNNING)
    if status != 0:
        raise _fetch_failed(status, out, host, folder)
    _, head, dirty, origin, followed, others = _sections(out, sep, 6)
    head = head.strip().splitlines()[-1].strip() if head.strip() else ""
    dirty_lines = [clean_text(line, 200) for line in dirty.splitlines() if line.strip()]
    origin_lines = origin.strip().splitlines()
    github = parse_github(origin_lines[-1]) if origin_lines else None
    followed_head = next((r for r in map(_parse_ref, followed.splitlines()) if r and r["name"] == branch), None)
    branches = [r for r in map(_parse_ref, others.splitlines()) if r][:MAX_BRANCHES]
    return {"head": head if valid_sha(head) else None, "dirty": dirty_lines, "github": github,
            "followed": followed_head, "branches": branches}


async def _compare(remote: Remote, folder: str, base: str, head: str, others: list[str]) -> dict[str, Any]:
    """Commits, migrations and privileged changes from ``base`` to ``head``, and which ``others`` descend."""
    q = shlex.quote
    sep = _sep()
    eoo = "--end-of-options"
    priv = " ".join(q(p) for p in PRIVILEGED_FILES)
    shas = sorted({head, *others})
    command = "\n".join([
        f"cd -- {q(folder)} || exit 3",
        f"git log --max-count={MAX_COMMITS} --format={q(_LOG_FORMAT)} {eoo} {base}..{head} --; echo \"rc=$?\"",
        f"echo {sep}", f"git rev-list --count {eoo} {base}..{head} --",
        f"echo {sep}", f"git diff --name-only --diff-filter=A {eoo} {base} {head} -- alembic/versions",
        f"echo {sep}",
        f"for s in {' '.join(shas)}; do "
        f"if git merge-base --is-ancestor {eoo} {base} \"$s\" 2>/dev/null; then echo \"$s yes\"; "
        f"git diff --name-only {eoo} {base} \"$s\" -- {priv} | sed \"s/^/$s f /\"; "
        f"else echo \"$s no\"; fi; done",
        "exit 0",
    ])
    status, out = await remote.run(command, check=False, timeout=FETCH_TIMEOUT)
    if status != 0:
        raise UpdateError(502, f"Reading the install folder failed (exit {status})")
    log_part, count, migrations, ancestry = _sections(out, sep, 4)
    log_lines = log_part.strip().splitlines()
    if not log_lines or log_lines[-1].strip() != "rc=0":
        raise UpdateError(409, f"The running commit {short(base)} isn't in the install folder's git history")
    commits = [c for c in map(_parse_commit, log_lines[:-1]) if c][:MAX_COMMITS]
    count = count.strip().splitlines()[-1].strip() if count.strip() else ""
    ahead = int(count) if count.isdigit() and len(count) <= 9 else len(commits)
    added = [clean_text(p, 200) for p in migrations.splitlines()
             if p.startswith("alembic/versions/") and p.endswith(".py")][:100]
    descends: dict[str, bool] = {}
    privileged: dict[str, list[str]] = {}
    for line in ancestry.splitlines():
        parts = line.strip().split(" ", 2)
        if len(parts) == 2 and valid_sha(parts[0]) and parts[1] in ("yes", "no"):
            descends[parts[0]] = parts[1] == "yes"
        elif len(parts) == 3 and valid_sha(parts[0]) and parts[1] == "f" and parts[2] in PRIVILEGED_FILES:
            privileged.setdefault(parts[0], []).append(parts[2])
    return {"commits": commits, "ahead": ahead, "migrations": added, "descends": descends, "privileged": privileged}


def _ls_remote_command(folder: str) -> str:
    """The branch heads on origin (GitHub), read live: ``git ls-remote`` changes nothing in the checkout, so it
    doesn't take the upgrade lock."""
    return (f"cd -- {shlex.quote(folder)} || exit 3; export GIT_TERMINAL_PROMPT=0; "
            "git ls-remote --heads origin </dev/null 2>&1 || exit 4")


MAX_LISTED_BRANCHES = 1000


def parse_ls_remote(output: str, followed: str | None) -> dict[str, Any]:
    """``{branches, hidden, truncated}``: the valid branch names in ``git ls-remote --heads`` output, the followed
    branch first, then main, then the rest by name (at most MAX_LISTED_BRANCHES); ``hidden`` counts names Slipway
    won't use, ``truncated`` the valid ones past the cap."""
    names: set[str] = set()
    hidden = 0
    for line in output.splitlines():
        parts = line.strip().split("\t")
        if len(parts) != 2 or not valid_sha(parts[0]) or not parts[1].startswith("refs/heads/"):
            continue
        name = parts[1][len("refs/heads/"):]
        if valid_branch(name):
            names.add(name)
        else:
            hidden += 1
    ordered = order_branches(names, followed)
    return {"branches": ordered[:MAX_LISTED_BRANCHES], "hidden": hidden,
            "truncated": max(0, len(ordered) - MAX_LISTED_BRANCHES)}


def order_branches(names: Any, followed: str | None) -> list[str]:
    """Valid branch names without repeats: the followed branch first, then main, then the rest by name."""
    unique = {n for n in names if isinstance(n, str) and valid_branch(n)}
    return sorted(unique, key=lambda n: (n != followed, n != "main", n.lower(), n))


async def remote_branches(db: AsyncSession, *, actor: User | None = None, request: Request | None = None) -> dict[str, Any]:
    """The branches on the install's origin (GitHub), for the Branch to follow list: ``{branches, followed,
    hidden}``. Read over SSH from the configured host; nothing is stored."""
    state = await load_state(db)
    if not in_docker():
        raise UpdateError(409, MSG_NOT_IN_DOCKER)
    if not configured(state):
        raise UpdateError(409, MSG_NOT_CONFIGURED)
    host = await verified_host(db, _identity(state), actor=actor, request=request)
    folder = state["dir"]
    target = ssh.SSHTarget.from_host(host)
    await db.commit()
    async with connect(target) as remote:
        status, out = await remote.run(_ls_remote_command(folder), check=False, timeout=QUICK_TIMEOUT * 2)
    if status == 3:
        raise UpdateError(502, f"Can't open {folder} on {host.name}")
    if status != 0:
        tail = redact(ssh.clip("\n".join(out.strip().splitlines()[-ssh.TAIL_LINES:]), 1000))
        raise UpdateError(502, f"Couldn't list the branches on origin from {host.name}: {tail}")
    return {**parse_ls_remote(out, state["branch"]), "followed": state["branch"]}


async def check(
    db: AsyncSession, *, actor: User | None = None, request: Request | None = None, manual: bool = True
) -> dict[str, Any]:
    """Fetch and compare the followed branch (and every other) with the running commit; store ``last_check``.

    Returns ``{...last_check, branches}``. Raises UpdateError; SSH errors are stored in ``last_check.error``
    and re-raised.
    """
    state = await load_state(db)
    if not in_docker():
        raise UpdateError(409, MSG_NOT_IN_DOCKER)
    if not configured(state):
        raise UpdateError(409, MSG_NOT_CONFIGURED)
    running = running_version()
    if running["commit_invalid"]:
        raise UpdateError(409, MSG_COMMIT_UNKNOWN)
    ident = _identity(state)
    host = await verified_host(db, ident, actor=actor, request=request)
    folder, branch = state["dir"], state["branch"]
    target = ssh.SSHTarget.from_host(host)
    await db.commit()
    if _start_lock.locked():
        raise UpdateError(409, MSG_CHECK_SKIPPED)
    try:
        async with connect(target) as remote:
            # An upgrade being started takes the script's lock moments later: a fetch holding it then would
            # make the script give up with "Another upgrade is running".
            if _start_lock.locked():
                raise UpdateError(409, MSG_CHECK_SKIPPED)
            read = await _read_checkout(remote, host, folder, branch, all_branches=True)
            base = _from_commit(read["head"], state)
            head = read["followed"]
            if head is None:
                raise UpdateError(409, f"origin has no branch {branch}")
            others = [b["sha"] for b in read["branches"] if b["valid"]]
            cmp = await _compare(remote, folder, base, head["sha"], others)
    except ssh.SSHError as exc:
        await _store_check_error(db, branch, redact(ssh.clip(str(exc), 1000)))
        raise
    except UpdateError as exc:
        if exc.status == 502:
            await _store_check_error(db, branch, exc.detail)
        raise
    github = read["github"]
    branches = []
    for b in read["branches"]:
        descends = b["valid"] and cmp["descends"].get(b["sha"], False)
        branches.append({
            **{k: b[k] for k in ("name", "sha", "short", "date", "author", "subject", "valid")},
            "followed": b["name"] == branch, "descends": descends, "can_switch": bool(descends and b["sha"] != base),
            "privileged_changes": cmp["privileged"].get(b["sha"], []) if descends else [],
            "compare_url": compare_url(github, base, b["sha"]) if descends else None,
        })
    descends = cmp["descends"].get(head["sha"], False)
    last_check = {
        "at": _now(), "branch": branch, "from": base,
        "head": {k: head[k] for k in ("sha", "short", "date", "author", "subject")},
        "ahead": cmp["ahead"] if descends else 0,
        "descends": descends, "commits": cmp["commits"] if descends else [],
        "migrations": cmp["migrations"] if descends else [],
        "privileged_changes": cmp["privileged"].get(head["sha"], []) if descends else [],
        "dirty": bool(read["dirty"]), "dirty_files": read["dirty"][:20],
        "github": github, "compare_url": compare_url(github, base, head["sha"]) if descends else None,
        "error": None,
    }
    async with edit_state(db) as state:
        if (state["dir"], state["branch"]) == (folder, branch):
            state["last_check"] = last_check
            state["branches"] = branches
        if manual:
            audit.record(
                db, "updates.checked", actor=actor, request=request,
                summary=f"Checked {branch} for updates: {last_check['ahead']} new",
                details={"branch": branch, "head": head["sha"], "ahead": last_check["ahead"]},
            )
    return {**last_check, "branches": branches}


async def _store_check_error(db: AsyncSession, branch: str, message: str) -> None:
    async with edit_state(db) as state:
        previous = state["last_check"] or {"branch": branch}
        state["last_check"] = {**previous, "error": message, "error_at": _now()}
        if not previous.get("at"):
            state["last_check"]["at"] = None


# ------------------------------------------------------------------------------- runs


def parse_status(raw: str, run_id: str) -> dict[str, Any]:
    """Validate ``<id>.json`` from the server. Anything off makes the status ``unknown`` (shown, not audited)."""

    def unknown(why: str) -> dict[str, Any]:
        return {"id": run_id, "status": "unknown", "step": None, "message": why, "valid": False}

    if not raw.strip():
        return unknown("The run's status file is missing.")
    if len(raw.encode("utf-8", "replace")) > MAX_STATUS_BYTES:
        return unknown("The run's status file is too large.")
    try:
        data = json.loads(raw)
    except ValueError:
        return unknown("The run's status file can't be read.")
    if not isinstance(data, dict) or data.get("id") != run_id:
        return unknown("The run's status file is for another run.")
    status, step = data.get("status"), data.get("step")
    frm, to, branch = data.get("from"), data.get("to"), data.get("branch")
    backup, db_changed, pid, boot_id = data.get("backup"), data.get("db_changed"), data.get("pid"), data.get("boot_id")
    failed_step = data.get("failed_step")
    ok = (
        status in SCRIPT_STATUSES
        and (step is None or step in STEPS)
        and (failed_step in (None, "") or failed_step in STEPS)
        and (frm in (None, "") or valid_sha(frm))
        and valid_sha(to)
        and (branch is None or valid_branch(branch))
        and backup in (None, "", f"{WORK_DIR}/{run_id}-before.dump")
        and (db_changed is None or isinstance(db_changed, bool))
        and (pid is None or (isinstance(pid, int) and not isinstance(pid, bool) and 0 < pid < 2**31))
        and (boot_id in (None, "") or (isinstance(boot_id, str) and bool(BOOT_ID_RE.fullmatch(boot_id))))
        and all(data.get(k) in (None, "") or _iso(data.get(k)) for k in ("started_at", "finished_at", "heartbeat_at"))
    )
    if not ok:
        return unknown("The run's status file doesn't validate.")
    return {
        "id": run_id, "status": status, "step": step, "from": frm or None, "to": to, "branch": branch,
        "started_at": _iso(data.get("started_at")), "finished_at": _iso(data.get("finished_at")),
        "heartbeat_at": _iso(data.get("heartbeat_at")), "message": ssh.clip(clean_text(data.get("message"), 500), 500),
        "backup": backup or None, "db_changed": bool(db_changed), "failed_step": failed_step or None, "pid": pid,
        "boot_id": boot_id or None, "valid": True,
    }


def _read_run_command(folder: str, run_id: str, sep: str, *, with_log: bool) -> str:
    q = shlex.quote
    base = f"{WORK_DIR}/{run_id}"
    lines = [
        f"cd -- {q(folder)} || exit 3",
        f"if [ -f {base}.json ]; then head -c {MAX_STATUS_BYTES + 1} {base}.json; fi",
        "echo", f"echo {sep}",
        f"tr -cd '0-9a-f-' 2>/dev/null < {BOOT_ID_FILE}", "echo",
    ]
    if with_log:
        lines += [f"echo {sep}", f"tail -c {LOG_TAIL_BYTES} {base}.log 2>/dev/null"]
    lines.append("exit 0")
    return "\n".join(lines)


def _alive_command(folder: str, run_id: str, pid: int, sep: str) -> str:
    base = f"{WORK_DIR}/{run_id}"
    return "\n".join([
        f"cd -- {shlex.quote(folder)} || exit 3",
        f"if kill -0 {pid} 2>/dev/null && {{ [ ! -r /proc/{pid}/cmdline ] || "
        f"tr '\\000' ' ' < /proc/{pid}/cmdline | grep -q -F upgrade-{run_id}.sh; }}; then echo alive; "
        f"else echo dead; echo {sep}; head -c {MAX_STATUS_BYTES + 1} {base}.json 2>/dev/null; echo; fi",
        "exit 0",
    ])


def _valid_pid(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value < 2**31


async def _alive(remote: Remote, folder: str, run_id: str, pid: int) -> tuple[str, dict[str, Any]]:
    """``("alive", {})``, ``("dead", <status file read right after>)`` or ``("unsure", {})``.

    Only an explicit answer counts: a failed command, a lost exit status or odd output is ``unsure``, so a
    hiccup on one of the many polls of a run never ends it."""
    sep = _sep()
    status, out = await remote.run(_alive_command(folder, run_id, pid, sep), check=False, timeout=QUICK_TIMEOUT)
    verdict, again = _sections(out, sep, 2)
    first = verdict.strip().splitlines()[:1]
    if status == 0 and first == ["alive"]:
        return "alive", {}
    if status == 0 and first == ["dead"]:
        return "dead", parse_status(again.strip(), run_id)
    log.warning("Could not tell whether upgrade %s is still running (exit %s)", run_id, status)
    return "unsure", {}


async def read_run(
    remote: Remote, folder: str, run_id: str, *, with_log: bool = False, launch_pid: object = None
) -> dict[str, Any]:
    """The run's status as the server has it, with ``interrupted`` for a script that died while running.

    ``launch_pid`` is the process Slipway started for a run that hasn't written its status file yet: when
    that process is gone and there is still no file, ``launch_dead`` is set."""
    if not valid_id(run_id) or not valid_dir(folder):
        raise UpdateError(404, "Unknown id")
    sep = _sep()
    status, out = await remote.run(_read_run_command(folder, run_id, sep, with_log=with_log), check=False, timeout=QUICK_TIMEOUT)
    if status != 0:
        raise UpdateError(502, f"Can't open {folder} on the server")
    raw, boot_id, log_text = _sections(out, sep, 3)
    parsed = parse_status(raw.strip(), run_id)
    parsed["exists"] = bool(raw.strip())
    if with_log:
        parsed["log"] = redact(log_text)[-LOG_TAIL_BYTES:]
    keep_log = {"log": parsed["log"]} if with_log else {}
    if not parsed["exists"] and _valid_pid(launch_pid):
        verdict, latest = await _alive(remote, folder, run_id, launch_pid)  # type: ignore[arg-type]
        if verdict == "dead":
            if latest.get("valid"):  # it wrote its file after all, then ended
                latest = {**latest, "exists": True, **keep_log}
                return _interrupted(latest) if latest["status"] == "running" else latest
            parsed["launch_dead"] = True
        return parsed
    if parsed["status"] != "running":
        return parsed
    boot_id = boot_id.strip()
    if parsed.get("boot_id") and BOOT_ID_RE.fullmatch(boot_id) and boot_id != parsed["boot_id"]:
        return _interrupted(parsed)
    if parsed.get("pid"):
        verdict, latest = await _alive(remote, folder, run_id, parsed["pid"])
        if verdict == "dead":
            # It may have finished between the two reads: its last word wins.
            if latest["status"] in FINAL_STATUSES:
                return {**latest, "exists": True, **keep_log}
            return _interrupted(parsed)
    return parsed


def _interrupted(parsed: dict[str, Any]) -> dict[str, Any]:
    return {**parsed, "status": "interrupted", "message": MSG_INTERRUPTED, "finished_at": parsed.get("finished_at")}


def _summary(run: dict[str, Any]) -> dict[str, Any]:
    keys = ("id", "host_id", "host_name", "dir", "branch", "from", "to", "by", "by_name", "started_at", "status", "step",
            "failed_step", "finished_at", "message", "db_changed", "backup", "heartbeat_at", "launch_log")
    return {k: run.get(k) for k in keys}


async def _finished_audited(db: AsyncSession, run_id: str) -> bool:
    found = await db.scalar(
        select(AuditEvent.id).where(AuditEvent.action == "updates.finished", AuditEvent.target_id == run_id).limit(1)
    )
    return found is not None


def _audit_finished(db: AsyncSession, run: dict[str, Any]) -> None:
    status = run["status"]
    audit.record(
        db, "updates.finished", actor=None, target=run["id"], target_type="update_run",
        summary=f"Slipway upgrade {run['id']} to {short(run.get('to'))} on {run.get('branch')}: {status.replace('_', ' ')}",
        details={"run_id": run["id"], "status": status, "step": run.get("step"), "db_changed": bool(run.get("db_changed")),
                 "backup": run.get("backup"), "by": run.get("by"), "by_name": run.get("by_name")},
    )


async def _apply(db: AsyncSession, state: dict[str, Any], parsed: dict[str, Any], ident: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Store what was read for one run (inside ``edit_state``). Adds the run when it isn't stored and the file
    validated. Writes ``updates.finished`` once, when the stored status first becomes final."""
    run_id = parsed["id"]
    run = next((r for r in state["runs"] if r.get("id") == run_id), None)
    if run is None:
        if not parsed.get("valid") or ident is None:
            return None
        run = {**_identity(ident), "id": run_id, "branch": parsed.get("branch"), "from": parsed.get("from"),
               "to": parsed.get("to"), "by": None, "by_name": None, "started_at": parsed.get("started_at"),
               "status": "unknown"}
        state["runs"].append(run)
        state["runs"].sort(key=lambda r: r["id"], reverse=True)
        del state["runs"][MAX_RUNS:]
        if run not in state["runs"]:
            return None
    old = run.get("status")
    if old not in FINAL_STATUSES:
        parsed = _settle_launch(run, parsed)
    new = parsed["status"]
    if old in FINAL_STATUSES:
        new = old  # final is final; a later read can't reopen it
    else:
        run["status"] = new
        for key in ("step", "failed_step", "message", "finished_at", "heartbeat_at", "backup", "db_changed"):
            if key in parsed and (parsed.get("valid") or key == "message"):
                run[key] = parsed[key]
        if parsed.get("valid") and parsed.get("from") and not run.get("from"):
            run["from"] = parsed["from"]
        if new == "interrupted" and not run.get("finished_at"):
            run["finished_at"] = _now()
    if run["status"] in FINAL_STATUSES and not await _finished_audited(db, run_id):
        _audit_finished(db, run)
    return run


def _settle_launch(run: dict[str, Any], parsed: dict[str, Any]) -> dict[str, Any]:
    """For a run Slipway started that hasn't written its status file yet: still ``running`` while it may be
    starting, ``failed`` once its process is gone without a file or LAUNCH_GRACE has passed."""
    deadline = run.get("launch_deadline")
    if not deadline:
        return parsed
    if parsed.get("exists") or parsed["status"] != "unknown":
        run.pop("launch_deadline", None)
        run.pop("launch_pid", None)
        return parsed
    expired = (until := _iso(deadline)) is None or datetime.fromisoformat(until) <= utcnow()
    if not parsed.get("launch_dead") and not expired:
        return {**parsed, "status": "running", "message": MSG_LAUNCH_PENDING}
    run.pop("launch_deadline", None)
    run.pop("launch_pid", None)
    why = "Its process ended without writing a status file." if parsed.get("launch_dead") else (
        f"It didn't write a status file within {LAUNCH_GRACE // 60} minutes.")
    return {"id": run["id"], "status": "failed", "step": None, "valid": False,
            "message": f"The upgrade didn't start. {why} Check the run's log on the server."}


async def reconcile_runs(
    db: AsyncSession, *, remote: Remote | None = None, ident: dict[str, Any] | None = None
) -> None:
    """Read the status of every stored run that is ``running`` (or ``unknown``) and store it.

    With ``remote`` (an open session to the server ``ident`` names), only that server's runs are read.
    """
    state = await load_state(db)
    pending = [r for r in state["runs"] if r.get("status") in ("running", "unknown")]
    if remote is not None:
        pending = [r for r in pending if ident is not None and _same_server(_identity(r), ident)]
    if not pending:
        return
    groups: list[list[dict[str, Any]]] = []
    for run in pending:
        group = next((g for g in groups if _same_server(_identity(g[0]), _identity(run))), None)
        if group is None:
            groups.append([run])
        else:
            group.append(run)
    for runs in groups:
        ident = _identity(runs[0])
        if not valid_dir(ident.get("dir")):
            continue
        if remote is not None:
            results = [await read_run(remote, ident["dir"], r["id"], launch_pid=r.get("launch_pid")) for r in runs]
        else:
            host = await _get_host(db, ident.get("host_id"))
            if not _host_matches(ident, host):
                continue  # refused (and audited) where a person asked; the loop just leaves it
            assert host is not None
            target = ssh.SSHTarget.from_host(host)
            await db.commit()
            async with connect(target) as session:
                results = [await read_run(session, ident["dir"], r["id"], launch_pid=r.get("launch_pid")) for r in runs]
        async with edit_state(db) as state:
            for parsed in results:
                await _apply(db, state, parsed)


async def _list_remote_ids(remote: Remote, folder: str) -> list[str]:
    command = (
        f"cd -- {shlex.quote(folder)} || exit 3\n"
        f"ls -1t {WORK_DIR} 2>/dev/null | grep -E '^[0-9]{{8}}-[0-9]{{6}}-[0-9a-f]{{6}}\\.json$' | head -n {MAX_RUNS}\n"
        "exit 0"
    )
    _, out = await remote.run(command, check=False, timeout=QUICK_TIMEOUT)
    ids = [line.strip()[:-5] for line in out.splitlines() if line.strip().endswith(".json")]
    return [i for i in ids if valid_id(i)][:MAX_RUNS]


async def merge_remote_runs(db: AsyncSession, remote: Remote, ident: dict[str, Any]) -> None:
    """Add runs that have a status file on the server but are missing from the setting (newest 20)."""
    state = await load_state(db)
    known = {r["id"] for r in state["runs"]}
    missing = [i for i in await _list_remote_ids(remote, ident["dir"]) if i not in known]
    if not missing:
        return
    results = [await read_run(remote, ident["dir"], run_id) for run_id in missing]
    async with edit_state(db) as state:
        for parsed in results:
            await _apply(db, state, parsed, ident)


async def list_runs(db: AsyncSession) -> list[dict[str, Any]]:
    """The stored runs, after merging in status files found on the configured server."""
    state = await load_state(db)
    if configured(state) and in_docker():
        ident = _identity(state)
        host = await _get_host(db, ident.get("host_id"))
        if _host_matches(ident, host):
            assert host is not None
            target = ssh.SSHTarget.from_host(host)
            await db.commit()
            try:
                async with connect(target) as remote:
                    await merge_remote_runs(db, remote, ident)
                    await reconcile_runs(db, remote=remote, ident=ident)
            except (ssh.SSHError, UpdateError) as exc:
                log.warning("Could not read upgrade runs from %s: %s", ident.get("host_name"), exc)
    return [_summary(r) for r in (await load_state(db))["runs"]]


async def get_run(db: AsyncSession, run_id: str, *, actor: User | None = None, request: Request | None = None) -> dict[str, Any]:
    """One run as the server has it, with the last 64 KB of its log. GET: it only reconciles the stored status."""
    if not valid_id(run_id):
        raise UpdateError(404, "Unknown id")
    state = await load_state(db)
    stored = next((r for r in state["runs"] if r["id"] == run_id), None)
    if stored is not None:
        ident = _identity(stored)
    elif configured(state):
        ident = _identity(state)  # the server is the source of truth: a run lost from the setting is re-added
    else:
        raise UpdateError(404, "Unknown id")
    if not valid_dir(ident.get("dir")):
        raise UpdateError(404, "Unknown id")
    host = await verified_host(db, ident, actor=actor, request=request)
    target = ssh.SSHTarget.from_host(host)
    await db.commit()
    async with connect(target) as remote:
        parsed = await read_run(remote, ident["dir"], run_id, with_log=True,
                                launch_pid=stored.get("launch_pid") if stored else None)
    if stored is None and not (parsed.get("exists") and parsed.get("valid")):
        raise UpdateError(404, "Unknown id")
    async with edit_state(db) as state:
        run = await _apply(db, state, parsed, ident)
    run = run or stored or {}
    out = {k: v for k, v in parsed.items() if k not in ("valid", "exists", "pid", "boot_id", "launch_dead")}
    out["status"] = run.get("status", parsed["status"])
    if out["status"] != parsed["status"] and run.get("message"):
        out["message"] = run["message"]
    out["run"] = _summary(run) if run else None
    out["steps"] = list(STEPS)
    out["final"] = out["status"] in FINAL_STATUSES
    return out


async def _refuse(
    db: AsyncSession, exc: UpdateError, *, branch: str, sha: str, actor_id: uuid.UUID, request: Request | None,
    action: str = "updates.refused",
) -> UpdateError:
    await db.rollback()
    actor = await db.get(User, actor_id)  # the rollback expired the loaded user
    verb = "Refused" if action == "updates.refused" else "Could not start"
    audit.record(
        db, action, actor=actor, request=request, summary=f"{verb} a Slipway upgrade: {exc.detail}",
        details={"reason": exc.detail, "branch": branch, "sha": sha},
    )
    await db.commit()
    return exc


def launch_command(folder: str, run_id: str, sha: str, branch: str, base: str | None) -> str:
    """Start the script detached, with a private umask, its output going to ``<id>.log``. Prints
    ``started <pid>``: without job control the background job isn't a process group leader, so ``setsid``
    doesn't fork and ``nohup`` execs, and ``$!`` is the script's own pid."""
    q = shlex.quote
    args = f"--id {q(run_id)} --target {q(sha)} --branch {q(branch)}" + (f" --from {q(base)}" if base else "")
    job = f"bash {WORK_DIR}/upgrade-{run_id}.sh {args} > {WORK_DIR}/{run_id}.log 2>&1 < /dev/null &"
    return (
        f"cd -- {q(folder)} && umask 077 && "
        f"if command -v setsid >/dev/null 2>&1; then (setsid nohup {job} echo \"started $!\"); "
        f"else (nohup {job} echo \"started $!\"); fi"
    )


_STARTED_RE = re.compile(r"^started ([0-9]{1,10})$")


async def start_run(
    db: AsyncSession, *, branch: str, sha: str, ctx_via: str, actor: User, request: Request | None = None
) -> str:
    """Validate, record (committed before anything starts), then start the upgrade script. Returns the run id.

    Every attempt leaves an audit row: ``updates.refused`` for a refusal, ``updates.start_failed`` when the
    server couldn't be read before the run was recorded, ``updates.started`` (and later ``updates.finished``)
    once it was recorded."""
    actor_id = actor.id
    if ctx_via != "session":
        raise await _refuse(db, UpdateError(403, MSG_TOKEN), branch=branch, sha=sha, actor_id=actor_id, request=request)
    if not valid_branch(branch) or not valid_sha(sha):
        raise await _refuse(db, UpdateError(422, "Give a branch name and a full 40-character commit sha"),
                            branch=clean_text(branch, 100), sha=clean_text(sha, 40), actor_id=actor_id, request=request)
    if _start_lock.locked():
        raise await _refuse(db, UpdateError(409, MSG_RUN_RUNNING), branch=branch, sha=sha, actor_id=actor_id, request=request)
    async with _start_lock:
        try:
            return await _start_run(db, branch=branch, sha=sha, actor=actor, request=request)
        except UpdateError as exc:
            if exc.recorded:
                raise
            action = "updates.start_failed" if exc.status == 502 else "updates.refused"
            raise await _refuse(db, exc, branch=branch, sha=sha, actor_id=actor_id, request=request, action=action) from None
        except ssh.SSHError as exc:
            await _refuse(db, UpdateError(502, redact(ssh.clip(str(exc), 1000))), branch=branch, sha=sha,
                          actor_id=actor_id, request=request, action="updates.start_failed")
            raise


async def _start_run(db: AsyncSession, *, branch: str, sha: str, actor: User, request: Request | None) -> str:
    if not in_docker():
        raise UpdateError(409, MSG_NOT_IN_DOCKER)
    state = await load_state(db)
    if not configured(state):
        raise UpdateError(409, MSG_NOT_CONFIGURED)
    running = running_version()
    if running["commit_invalid"]:
        raise UpdateError(409, MSG_COMMIT_UNKNOWN)
    ident = _identity(state)
    host = await verified_host(db, ident, actor=actor, request=request)
    if await deployment_active(db):
        raise UpdateError(409, MSG_DEPLOYMENT_RUNNING)
    folder = state["dir"]
    target = ssh.SSHTarget.from_host(host)
    await db.commit()
    async with connect(target) as remote:
        await reconcile_runs(db, remote=remote, ident=ident)
        if any(r.get("status") == "running" for r in (await load_state(db))["runs"]):
            raise UpdateError(409, MSG_RUN_RUNNING)
        if (found := await self_check(remote, host)) != folder:
            raise UpdateError(409, f"Slipway now runs from {found} on {host.name}: save it on the Updates page again", "host_id")
        read = await _read_checkout(remote, host, folder, branch, all_branches=False)
        base = _from_commit(read["head"], await load_state(db))
        if read["dirty"]:
            raise UpdateError(409, MSG_DIRTY)
        head = read["followed"]
        if head is None or head["sha"] != sha:
            raise UpdateError(409, f"{branch} has moved on: check again")
        if sha == base:
            raise UpdateError(409, f"Slipway already runs {short(sha)}")
        cmp = await _compare(remote, folder, base, sha, [])
        if not cmp["descends"].get(sha):
            raise UpdateError(409, f"{short(sha)} doesn't come after the running version {short(base)}: Slipway can't move back or sideways")
        q = shlex.quote
        await remote.run(
            f"cd -- {q(folder)} && umask 077 && mkdir -p {WORK_DIR} && chmod 700 {WORK_DIR}", timeout=QUICK_TIMEOUT
        )
        run_id = new_run_id()
        script = f"{folder}/{WORK_DIR}/upgrade-{run_id}.sh"
        try:  # SFTP has no timeout of its own: a hung share would hold _start_lock for good
            await asyncio.wait_for(remote.write_text(script, script_text(), mode=0o700), QUICK_TIMEOUT)
        except TimeoutError as exc:
            raise ssh.SSHError(f"Writing {script} timed out after {QUICK_TIMEOUT}s") from exc

        # Record the run and its audit BEFORE starting it: the script's backup then holds them, so a restore
        # keeps them, and nothing else can start a run meanwhile.
        async with edit_state(db) as state:
            if any(r.get("status") == "running" for r in state["runs"]):
                raise UpdateError(409, MSG_RUN_RUNNING)
            if await deployment_active(db):
                raise UpdateError(409, MSG_DEPLOYMENT_RUNNING)
            grace = datetime.fromtimestamp(utcnow().timestamp() + LAUNCH_GRACE, UTC)
            run = {**ident, "id": run_id, "branch": branch, "from": base, "to": sha, "by": str(actor.id),
                   "by_name": actor.display_name, "started_at": _now(), "status": "running", "step": None,
                   "finished_at": None, "message": None, "db_changed": False, "backup": None,
                   "launch_deadline": grace.strftime("%Y-%m-%dT%H:%M:%SZ")}
            state["runs"].insert(0, run)
            del state["runs"][MAX_RUNS:]
            audit.record(
                db, "updates.started", actor=actor, request=request, target=run_id, target_type="update_run",
                summary=f"Started upgrading Slipway from {short(base)} to {short(sha)} on {branch}",
                details={"run_id": run_id, "host_id": ident["host_id"], "host_name": ident["host_name"], "dir": folder,
                         "branch": branch, "from": base, "to": sha, "migrations": len(cmp["migrations"]),
                         "privileged_changes": cmp["privileged"].get(sha, [])},
            )
        await _launch(db, remote, folder, run_id, sha, branch, running["commit"])
    return run_id


async def _launch(
    db: AsyncSession, remote: Remote, folder: str, run_id: str, sha: str, branch: str, base: str | None
) -> None:
    """Start the recorded run. A run that clearly didn't start is stored ``failed`` (502). When Slipway can't
    tell (the connection dropped after the command went out, or the script is slow to write its status), the
    run stays ``running`` and later reads settle it from its status file and process."""
    try:
        status, out = await remote.run(launch_command(folder, run_id, sha, branch, base), check=False, timeout=QUICK_TIMEOUT)
    except ssh.SSHError as exc:
        log.warning("Lost the connection while starting upgrade %s; reading its status later: %s", run_id, exc)
        return
    lines = out.strip().splitlines()
    started = _STARTED_RE.fullmatch(lines[-1].strip()) if lines else None
    if status != 0 or started is None:
        await _launch_failed(db, run_id, f"The upgrade script didn't start: {redact(ssh.clip(out, 500))}", remote, folder)
    pid = int(started.group(1))  # type: ignore[union-attr]
    async with edit_state(db) as state:
        run = next((r for r in state["runs"] if r.get("id") == run_id), None)
        if run is not None and run.get("status") == "running":
            run["launch_pid"] = pid
    try:
        await _wait_for_start(db, remote, folder, run_id, pid)
    except ssh.SSHError as exc:
        log.warning("Could not read upgrade %s right after starting it; reading it later: %s", run_id, exc)
    except UpdateError as exc:
        if exc.recorded:
            raise
        log.warning("Could not read upgrade %s right after starting it; reading it later: %s", run_id, exc.detail)


async def _wait_for_start(db: AsyncSession, remote: Remote, folder: str, run_id: str, pid: int) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + LAUNCH_WAIT
    while True:
        parsed = await read_run(remote, folder, run_id, launch_pid=pid)
        if parsed.get("launch_dead"):
            await _launch_failed(db, run_id, "Its process ended without writing a status file.", remote, folder)
        if (parsed.get("valid") and (parsed.get("pid") or parsed["status"] in FINAL_STATUSES)) or loop.time() >= deadline:
            # Past the deadline the run stays running ("waiting for its first status") until a read settles it.
            async with edit_state(db) as state:
                await _apply(db, state, parsed)
            return
        await asyncio.sleep(LAUNCH_POLL)


async def _launch_failed(db: AsyncSession, run_id: str, why: str, remote: Remote, folder: str) -> None:
    """Store the run as ``failed`` with the end of its log, then raise the 502 for the request."""
    tail = ""
    try:
        _, tail = await remote.run(
            f"cd -- {shlex.quote(folder)} && tail -n 20 {WORK_DIR}/{run_id}.log 2>/dev/null; exit 0",
            check=False, timeout=QUICK_TIMEOUT,
        )
    except ssh.SSHError:
        pass
    async with edit_state(db) as state:
        parsed = {"id": run_id, "status": "failed", "step": None, "valid": False,
                  "message": ssh.clip(f"The upgrade didn't start. {why}", 500)}
        run = await _apply(db, state, parsed)
        if run is not None:
            run["finished_at"] = run.get("finished_at") or _now()
            run["launch_log"] = redact(ssh.clip(tail, 4000))
    exc = UpdateError(502, f"The upgrade didn't start. {why}")
    exc.recorded = True
    raise exc
# --------------------------------------------------------------------------- overview


def _reason(state: dict[str, Any], running: dict[str, Any], *, host_ok: bool, deploying: bool) -> str | None:
    """Why the page can't offer an upgrade now, or None when it can."""
    if not in_docker():
        return MSG_NOT_IN_DOCKER
    if not configured(state):
        return MSG_NOT_CONFIGURED
    if not host_ok:
        return _host_changed_message(state)
    if running["commit_invalid"]:
        return MSG_COMMIT_UNKNOWN
    if any(r.get("status") == "running" for r in state["runs"]):
        return MSG_RUN_RUNNING
    if deploying:
        return MSG_DEPLOYMENT_RUNNING
    check = state["last_check"]
    if not check or not check.get("at"):
        return "Check for updates first"
    if check.get("error"):
        return "The last check failed: check again"
    if check.get("branch") != state["branch"]:
        return "Check for updates first"
    if running["commit"] and check.get("from") != running["commit"]:
        return "Slipway's version changed since the last check: check again"
    if check.get("dirty"):
        return MSG_DIRTY
    head = check.get("head") or {}
    if not check.get("descends"):
        return f"{state['branch']} doesn't come after the running version: Slipway can't move back or sideways"
    if not check.get("ahead") or head.get("sha") == check.get("from"):
        return "Slipway is up to date"
    return None


async def overview(db: AsyncSession, *, remote: bool = True) -> dict[str, Any]:
    """The body of GET /api/v1/updates, also used by the page. With ``remote``, runs still ``running`` are read
    from the server first (never for longer than OVERVIEW_TIMEOUT); otherwise no SSH."""
    state = await load_state(db)
    remote_error = None
    if remote and in_docker() and any(r.get("status") == "running" for r in state["runs"]):
        try:
            await asyncio.wait_for(reconcile_runs(db), OVERVIEW_TIMEOUT)
        except (ssh.SSHError, UpdateError, TimeoutError) as exc:
            remote_error = redact(ssh.clip(str(exc) or "Timed out reading the running upgrade", 500))
        except Exception:  # the page must still render
            log.exception("Reading the running upgrade failed")
            remote_error = "Reading the running upgrade failed"
        state = await load_state(db)
    running = running_version()
    running["container"] = container_id()
    config = None
    host_ok = False
    if configured(state):
        host = await _get_host(db, state["host_id"])
        host_ok = _host_matches(_identity(state), host)
        config = {"host_id": state["host_id"], "host_name": host.name if host else state["host_name"],
                  "dir": state["dir"], "branch": state["branch"], "host_changed": not host_ok,
                  "exposed_roles": await exposed_roles(db)}
    last_check = state["last_check"]
    github = (last_check or {}).get("github")
    running["commit_url"] = commit_url(github, running["commit"])
    deploying = await deployment_active(db)
    reason = _reason(state, running, host_ok=host_ok, deploying=deploying)
    runs = [_summary(r) for r in state["runs"]]
    return {
        "in_docker": in_docker(),
        "running": running,
        "config": config,
        "last_check": last_check,
        "branches": state["branches"] if last_check else [],
        "run": runs[0] if runs else None,
        "runs": runs,
        "steps": list(STEPS),
        "final_statuses": sorted(FINAL_STATUSES),
        "deploying": deploying,
        "can_upgrade": reason is None,
        "reason": reason,
        "remote_error": remote_error,
    }


# ------------------------------------------------------------------------- background


def _interval(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    return int(raw) if raw.lstrip("-").isdigit() else default


async def background_check() -> None:
    """One scheduled check: only when configured and in Docker, never while a run is being started."""
    if not in_docker() or _start_lock.locked():
        return
    async with session_scope() as db:
        state = await load_state(db)
        if not configured(state):
            return
        try:
            await check(db, manual=False)
        except UpdateError as exc:
            if exc.detail == MSG_CHECK_SKIPPED:
                log.info("Skipped the update check: an upgrade is running")
                return
            log.warning("Update check failed: %s", exc.detail)
            if exc.status != 502:  # 502s are stored by check() itself
                await _store_check_error(db, state["branch"], exc.detail)
        except ssh.SSHError as exc:
            log.warning("Update check failed: %s", exc)


async def check_forever() -> None:
    """Check for updates every 6 hours (first after 5 minutes). SLIPWAY_UPDATE_CHECK_INTERVAL=0 disables it."""
    interval = _interval("SLIPWAY_UPDATE_CHECK_INTERVAL", 6 * 3600)
    if interval <= 0:
        return
    await asyncio.sleep(min(FIRST_CHECK_DELAY, interval))
    while True:
        try:
            await background_check()
        except asyncio.CancelledError:
            raise
        except Exception:  # keep checking whatever happens
            log.exception("Update check failed")
        await asyncio.sleep(interval)


async def reconcile_forever() -> None:
    """While a run is ``running``, read its status every minute, so ``updates.finished`` is written even when
    nobody has the page open. SLIPWAY_UPDATE_RECONCILE_INTERVAL=0 disables it."""
    interval = _interval("SLIPWAY_UPDATE_RECONCILE_INTERVAL", 60)
    if interval <= 0:
        return
    while True:
        await asyncio.sleep(interval)
        try:
            async with session_scope() as db:
                state = await load_state(db)
                if any(r.get("status") == "running" for r in state["runs"]):
                    await reconcile_runs(db)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Reading the running upgrade failed")
