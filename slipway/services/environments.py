"""Environment rules (phase 3): who owns the data, which slot a deploy goes to and whether it goes live, the
values an app slot attaches to its data with, creating an environment, the environment-level step lists, what
the environment page offers, and the chain of jobs a first deploy starts.

An environment's slots are ordinary instances with ``environment_id`` and ``slot`` set (D1). The **data owner**
is the data server (mode ``server``) or the only app slot (mode ``slot``) and holds every phase 2 data field
(D3). The API, the pages and the job engine all ask this module, so they always agree; it never touches a host.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from slipway.core.permissions import Perm
from slipway.db.base import utcnow
from slipway.db.session import session_scope
from slipway.models import (
    BuildSource,
    DataMode,
    Deployment,
    DeploymentKind,
    DeploymentStatus,
    Environment,
    EnvironmentStatus,
    FirstAdmin,
    FirstAdminStatus,
    Host,
    Instance,
    InstanceStatus,
    Repository,
    Snapshot,
    SnapshotStatus,
    User,
)
from slipway.models.environment import ENVIRONMENT_NAME_RE
from slipway.services import audit, data, manifest

APP_SLOTS = ("blue", "green")
SLOTS = ("blue", "green", "data")
DATA_SLOT = "data"
NAME_RE = re.compile(ENVIRONMENT_NAME_RE)
LIVE_STATUSES = (EnvironmentStatus.NEW, EnvironmentStatus.LIVE, EnvironmentStatus.DELETING)
SWITCHES = ("none", "switchyard")

# The texts more than one place answers with.
NAME_RULE = "Use 2-26 lowercase letters, digits and hyphens, starting with a letter"
SET_UP_SWITCHYARD = "Set up Switchyard in Settings → Integrations first"
SET_UP_CLOUDFLARE = "Set up Cloudflare in Settings → Integrations first"
UNPINNED = "Check host {host} first: Slipway hasn't verified its key"
BLUE_GREEN_SWITCH = "Blue/Green moves its names in Switchyard when a slot goes live: choose Switchyard"


class DataValuesError(RuntimeError):
    """An app slot can't be given its data server's address, ports and keys; the message is for the user."""


# --------------------------------------------------------------------- members


async def members(db: AsyncSession, env: Environment) -> dict[str, Instance]:
    """The environment's instances by slot name (``blue``, ``green``, ``data``)."""
    rows = (await db.scalars(select(Instance).where(Instance.environment_id == env.id))).all()
    return {str(r.slot): r for r in rows if r.slot}


def app_members(members: dict[str, Instance]) -> list[Instance]:
    """The app slots, blue first."""
    return [members[s] for s in APP_SLOTS if s in members]


def owner_slot(env: Environment) -> str:
    """The data owner's slot (D3): the data server, or in mode ``slot`` the only app slot."""
    return "blue" if env.data_mode == DataMode.SLOT else DATA_SLOT


def owner_in(env: Environment, members: dict[str, Instance]) -> Instance | None:
    return members.get(owner_slot(env))


async def environment_of(db: AsyncSession, instance: Instance) -> Environment | None:
    if instance.environment_id is None:
        return None
    return data.loaded_environment(instance) or await db.get(Environment, instance.environment_id)


async def owner_of(db: AsyncSession, subject: Instance | Environment) -> Instance | None:
    """The data owner of an environment, or of the environment ``subject`` is a member of (D3). A standalone
    instance is its own owner. None only when the owner's row is missing (an environment being torn down)."""
    if isinstance(subject, Instance):
        if subject.environment_id is None:
            return subject
        env = await environment_of(db, subject)
        if env is None:
            return subject
        if subject.slot == owner_slot(env):
            return subject
    else:
        env = subject
    return await db.scalar(select(Instance).where(Instance.environment_id == env.id,
                                                  Instance.slot == owner_slot(env)))


def active_member(env: Environment, members: dict[str, Instance]) -> Instance | None:
    return next((m for m in members.values() if m.id == env.active_slot_id), None)


def target_slot(env: Environment, members: dict[str, Instance]) -> str:
    """The app slot a deploy goes to (D11, §8.5): with one app slot, that slot (in place); with two, the one
    that isn't active; with nothing active, blue."""
    apps = app_members(members)
    if len(apps) == 1:
        return str(apps[0].slot)
    active = active_member(env, members)
    if active is None or active.slot not in APP_SLOTS:
        return "blue"
    return "green" if active.slot == "blue" else "blue"


def goes_live(env: Environment, slot: str, members: dict[str, Instance]) -> bool:
    """Whether a deploy of ``slot`` goes live by itself (a chained activate, D11): when nothing is active, or
    with two app slots and ``auto_activate``. With one app slot, a deploy after the first is in place."""
    if slot not in APP_SLOTS:
        return False
    if env.active_slot_id is None:
        return True
    return bool(env.auto_activate) and len(app_members(members)) == 2


def last_slot_deploy(env: Environment) -> dict[str, Any] | None:
    found = (env.traffic_state or {}).get("last_slot_deploy")
    return found if isinstance(found, dict) else None


def lead_slot(env: Environment, members: dict[str, Instance]) -> Instance | None:
    """The slot a data job starts with its live ``start`` (D16): the active one, or with none, the app slot whose
    deploy finished last."""
    active = active_member(env, members)
    if active is not None:
        return active
    last = last_slot_deploy(env)
    if last and last.get("slot") in members:
        return members[last["slot"]]
    deployed = [m for m in app_members(members) if m.current_commit_sha]
    return max(deployed, key=lambda m: m.last_deployed_at or utcnow()) if deployed else None


def stale_of(instance: Instance) -> dict[str, Any] | None:
    found = (instance.slot_state or {}).get("stale")
    return found if isinstance(found, dict) else None


# ---------------------------------------------------------------- shared texts


def unresolved_text(env: Environment) -> str | None:
    """The refusal while a switch is unresolved (§10.6), or None."""
    found = (env.traffic_state or {}).get("unresolved")
    if not isinstance(found, dict):
        return None
    d8 = str(found.get("deployment_id") or "")[:8]
    since = f" since deployment {d8}" if d8 else ""
    why = f" ({found['message']})" if found.get("message") else ""
    return (f"Traffic of {env.name} may be split between its slots{since}{why}. Activate a slot, or use Resolve "
            "once Switchyard is right")


def busy_text(env: Environment, job: Deployment) -> str:
    """``A job is already running for uat (Deploy on green); wait for it to finish``."""
    slot = (job.instance.slot if job.instance_id is not None and job.instance is not None else None) \
        or (job.options or {}).get("slot")
    what = data.kind_label(job.kind) + (f" on {data.slot_text(slot)}" if slot else "")
    return f"A job is already running for {env.name} ({what}); wait for it to finish"


def dirty_activate_text(env: Environment, owner: Instance, slot: str) -> str:
    first = (owner.data_dirty or {}).get("first") or {}
    d8 = str(first.get("deployment_id") or "")[:8]
    return (f"{env.name}'s data may not be what {slot} expects since deployment {d8} failed: discard or retry it "
            "first")


def deleting_text(env: Environment) -> str | None:
    if env.status == EnvironmentStatus.DELETED:
        return f"{env.name} was deleted"
    if env.status == EnvironmentStatus.DELETING:
        return f"{env.name} is being deleted"
    return None


def need_text(permission: str) -> str:
    return f"You need the {permission} permission"


# --------------------------------------------------------------- data values (§6)


def is_ip(value: str | None) -> bool:
    try:
        ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return True


def address_problem(env: Environment, host: Host) -> str | None:
    """An app slot's host must be named by an IP address, since the data server lets clients in by address (D18)."""
    address = host.client_address
    if is_ip(address):
        return None
    return (f"Host {host.name}'s address is {address}; {env.name}'s data server lets clients in by IP address: set "
            "the host's LAN address (or proxy address) to its IP")


def no_server_text(env: Environment) -> str:
    return f"Deploy {env.name}'s data server first: the app slots need its address and ports"


def attach_problem(env: Environment, owner: Instance | None, slot: Instance) -> str | None:
    """Why an app slot in mode ``server`` can't be deployed on its data server yet (§6), checked when the job is
    queued and again in its ``settings`` step. None in mode ``slot`` and for the data server itself."""
    if env.data_mode == DataMode.SLOT or slot.slot not in APP_SLOTS:
        return None
    live = data.live_state(owner) if owner is not None else None
    if live is None:
        return no_server_text(env)
    problem = address_problem(env, slot.host)
    if problem:
        return problem
    clients = live.get("clients") or []
    if isinstance(clients, str):
        clients = clients.split(",")
    if slot.host.client_address not in {str(c).strip() for c in clients}:
        return (f"{env.name}'s data server doesn't let {slot.host.name} ({slot.host.client_address}) in yet: update "
                "the data server first (Deploy → Data server)")
    return None


def owner_builtins(env: Environment, owner: Instance, live: dict[str, Any]) -> dict[str, str]:
    """The ``{slipway.*}`` values of the data owner's live release, as its own live render uses them."""
    from slipway.services import deployer  # the deployer imports this module

    release = f"{deployer.paths_for(owner).releases}/{live.get('release')}"
    dep = data._uuid(live.get("deployment")) or uuid.UUID(int=0)
    out = deployer.app_builtins(owner, release, str(live.get("sha") or ""), dep)
    out.update(environment=env.name, slot=str(owner.slot or ""))
    return out


def data_values(env: Environment, owner: Instance, man: manifest.Manifest, *, template: str | None = None,
                builtins: dict[str, str] | None = None) -> dict[str, dict[str, str]]:
    """What an app slot attaches to: ``data.server.provides`` rendered with the data owner's live render (its
    ``app_state.live`` settings, services and host ports), ``{server.host}`` its host's proxy address,
    ``{server.port.*}`` its live host ports, and ``{secret.*}`` the environment's secrets (§6).

    ``man`` and ``template`` are the owner's live release's slipway.yml and env_file (the deployer reads them on
    the data host); ``builtins`` the live release's ``{slipway.*}`` values (default: ``owner_builtins``).
    Raises DataValuesError when the data server has no live release or can't be rendered.
    """
    live = data.live_state(owner)
    if live is None:
        raise DataValuesError(no_server_text(env))
    try:
        plan = manifest.plan(
            man, template=template, builtins=builtins if builtins is not None else owner_builtins(env, owner, live),
            settings={str(k): str(v) for k, v in (live.get("settings") or {}).items()},
            chosen=live.get("services"),
            host_ports={str(k): int(v) for k, v in (live.get("host_ports") or {}).items()},
            secrets=dict(env.app_secrets or {}), env=dict(env.env or {}), role="server",
            server_values={"host": owner.host.upstream_address, "clients": live.get("clients") or []},
        )
    except manifest.ManifestError as exc:
        raise DataValuesError(f"{env.name}'s data server can't be rendered again: {exc}") from exc
    except KeyError as exc:
        raise DataValuesError(f"{env.name}'s data server needs the secret {exc.args[0]}, which Slipway doesn't "
                              "have") from exc
    return plan.provides


# ------------------------------------------------------------ names and slugs


async def reserved_slug(db: AsyncSession, slug: str) -> tuple[Environment, str] | None:
    """``(environment, slot)`` when ``slug`` is ``<env>-blue``, ``-green`` or ``-data`` of a live environment
    (reserved whether or not the slot exists yet, §3.2), else None."""
    name, _, slot = (slug or "").rpartition("-")
    if slot not in SLOTS or not NAME_RE.match(name):
        return None
    env = await db.scalar(select(Environment).where(Environment.name == name, Environment.deleted_at.is_(None)))
    return (env, slot) if env is not None else None


def reserved_text(slug: str, env: Environment, slot: str) -> str:
    return f"{slug} is reserved for environment {env.name}'s {slot} slot"


def folders_overlap(folder: str, theirs: str) -> bool:
    """``folder`` is, holds or is inside ``theirs``."""
    return folder == theirs or folder.startswith(theirs + "/") or theirs.startswith(folder + "/")


async def folder_problem(db: AsyncSession, host: Host, folder: str, *,
                         instance_id: uuid.UUID | None = None) -> str | None:
    """The 409 text when ``folder`` is, holds or is inside another instance's folder on ``host`` (the rule
    ``POST /instances`` applies), else None."""
    from slipway.services import deployer  # the deployer imports this module

    query = select(Instance).where(Instance.host_id == host.id)
    if instance_id is not None:
        query = query.where(Instance.id != instance_id)
    for other in (await db.scalars(query)).all():
        try:
            theirs = deployer.instance_dir(other)
        except deployer.DeployError:
            continue
        if folders_overlap(folder, theirs):
            return f"{folder} overlaps {theirs}, the folder of instance {other.name}"
    return None


async def slot_folder_problem(db: AsyncSession, env_name: str, slot: str, host: Host) -> str | None:
    """``folder_problem`` for the folder a new slot gets, ``<host deploy root>/<env>-<slot>`` (its deploy_dir
    is always None)."""
    from slipway.services import deployer

    try:
        root = deployer.clean_deploy_root(host.deploy_root)
    except ValueError:
        return f"Fix {host.name}'s deploy root first: it must be an absolute path such as /opt/slipway"
    return await folder_problem(db, host, f"{root}/{env_name}-{slot}")


async def two_slot_traffic_problem(db: AsyncSession, env: Environment) -> str | None:
    """Why ``env`` can't run two app slots with its traffic settings (§9.1 rule 7), else None: Blue/Green moves
    its names in Switchyard, so the switch must be Switchyard and Switchyard set up."""
    from slipway.services import switchyard

    if (env.traffic or {}).get("switch") != "switchyard":
        return BLUE_GREEN_SWITCH
    if await switchyard.load_config(db) is None:
        return SET_UP_SWITCHYARD
    return None


def _route_names(routes: Iterable[Any]) -> set[str]:
    return {str(r.get("hostname")).lower() for r in routes or [] if isinstance(r, dict) and r.get("hostname")}


def held_names(members: Iterable[Instance], *, besides: uuid.UUID | None = None) -> set[str] | None:
    """The names the live releases of ``members`` serve (their ``app_state.routes``), leaving out the
    instance ``besides``. None when a member that went live recorded no routes, so its names aren't known."""
    names: set[str] = set()
    for inst in members:
        if besides is not None and inst.id == besides:
            continue
        state = inst.app_state or {}
        if "routes" in state:
            names |= _route_names(state.get("routes"))
        elif state.get("went_live") or inst.current_commit_sha:
            return None
    return names


def served_names(env: Environment, members: Iterable[Instance]) -> set[str]:
    """Every name the environment holds: ``env.hostnames`` and what each member's live release serves, the
    idle slot's and the data server's included. DNS publishes them and other instances and environments can't
    take them, so a deploy to the idle slot (or a PATCH) never takes a name away from the live slot, and
    switching back finds every name of the slot it goes back to (§10.1, §10.5)."""
    names = _route_names(env.hostnames)
    for inst in members:
        names |= _route_names((inst.app_state or {}).get("routes"))
    return names


def refreshed_hostnames(current: Iterable[dict[str, Any]], fresh: Iterable[dict[str, Any]], *,
                        follows: Iterable[str], held: set[str] | None) -> list[dict[str, Any]]:
    """``env.hostnames`` with the entries that follow ``follows`` refreshed from ``fresh`` (§9.3, §11 PATCH).
    A fresh entry wins. An old entry of those ``follows`` stays while a member's live release still serves its
    name (``held``; None keeps every old entry): a name leaves only once nothing live serves it."""
    fresh = [dict(h) for h in fresh]
    fresh_names = _route_names(fresh)
    follows = set(follows)
    keep = []
    for h in current or []:
        name = str(h.get("hostname") or "").lower()
        if not name or name in fresh_names:
            continue
        if h.get("follows", "active") not in follows or held is None or name in held:
            keep.append(dict(h))
    return sorted([*keep, *fresh], key=lambda h: str(h.get("hostname")))


async def _environment_names(db: AsyncSession, *, besides: uuid.UUID | None = None) -> list[tuple[str, set[str]]]:
    """Each live environment's name and the names it holds (``served_names``), by environment name."""
    stmt = select(Environment).where(Environment.deleted_at.is_(None)).order_by(Environment.name)
    if besides is not None:
        stmt = stmt.where(Environment.id != besides)
    envs = list(await db.scalars(stmt))
    if not envs:
        return []
    states: dict[uuid.UUID, list[Any]] = {}
    rows = (await db.execute(select(Instance.environment_id, Instance.app_state)
                             .where(Instance.environment_id.in_([e.id for e in envs])))).all()
    for env_id, state in rows:
        states.setdefault(env_id, []).append((state or {}).get("routes"))
    out = []
    for env in envs:
        names = _route_names(env.hostnames)
        for routes in states.get(env.id, []):
            names |= _route_names(routes)
        out.append((env.name, names))
    return out


async def hostname_conflict(db: AsyncSession, hostnames: Iterable[str], *,
                            environment_id: uuid.UUID | None = None) -> str | None:
    """Why an environment can't use ``hostnames`` (§9.1 rule 6): one is a hostname of a standalone instance (its
    ``routes`` or what its last deploy published, ``app_state.routes``) or of another live environment (its
    ``hostnames`` or what one of its slots' releases serves). None when they are free. ``environment_id`` is
    the environment asking (its own names don't count)."""
    wanted = {h.lower() for h in hostnames if h}
    if not wanted:
        return None
    rows = (await db.execute(select(Instance.name, Instance.routes, Instance.app_state)
                             .where(Instance.environment_id.is_(None)).order_by(Instance.name))).all()
    for name, routes, state in rows:
        taken = wanted & (_route_names(routes) | _route_names((state or {}).get("routes")))
        if taken:
            return f"{sorted(taken)[0]} is already a hostname of instance {name}"
    for name, names in await _environment_names(db, besides=environment_id):
        taken = wanted & names
        if taken:
            return f"{sorted(taken)[0]} is already a hostname of environment {name}"
    return None


async def environment_with_hostname(db: AsyncSession, hostnames: Iterable[str]) -> str | None:
    """For a standalone instance's routes (§11): ``<hostname> is a hostname of environment <env>``, or None."""
    wanted = {h.lower() for h in hostnames if h}
    if not wanted:
        return None
    for name, names in await _environment_names(db):
        taken = wanted & names
        if taken:
            return f"{sorted(taken)[0]} is a hostname of environment {name}"
    return None


def routes_of(plan: manifest.AppPlan, man: manifest.Manifest, follows: str) -> list[dict[str, Any]]:
    """``env.hostnames`` entries from a plan's routes (§10.1): ``{hostname, service, container, follows, health}``."""
    return [{"hostname": r["hostname"], "service": r["service"], "container": r["container"], "follows": follows,
             "health": man.health_path(str(r["service"]))} for r in plan.routes]


# ---------------------------------------------------------------- create (§9.1)


class CreateRefused(Exception):
    """A refusal of ``validate_create``: the HTTP status, the text and the request field it is about, so the flow
    page can move to the step that holds the field (§9.1, §12.3)."""

    def __init__(self, status: int, detail: str, field: str | None = None) -> None:
        super().__init__(detail)
        self.status, self.detail, self.field = status, detail, field

    def body(self) -> dict[str, Any]:
        return {"detail": self.detail, "field": self.field}


@dataclass
class NewEnvironment:
    """What ``POST /environments`` asks for (``EnvironmentCreate``, §11), as plain values."""

    name: str
    repository_id: uuid.UUID
    data_mode: str
    hosts: dict[str, uuid.UUID]
    branch: str | None = None
    manifest_file: str | None = None
    settings: dict[str, str] = field(default_factory=dict)
    services: list[str] | None = None
    env: dict[str, str] = field(default_factory=dict)
    route_tls: dict[str, str] = field(default_factory=dict)
    auto_activate: bool = False
    traffic: dict[str, Any] = field(default_factory=lambda: {"switch": "none", "dns": None})
    keep_backups: int | None = None
    seed_snapshot_id: uuid.UUID | None = None
    seed_content: bool | None = None
    first_admin: Any = None  # schemas.FirstAdminIn (or the same as a dict)

    @classmethod
    def of(cls, value: Any) -> NewEnvironment:
        """From an ``EnvironmentCreate`` model, a dict, or one of these."""
        if isinstance(value, cls):
            return value
        raw = value.model_dump() if hasattr(value, "model_dump") else dict(value)
        if hasattr(value, "first_admin"):
            raw["first_admin"] = value.first_admin  # keep the model (it carries the password)
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in raw.items() if k in known and v is not None})


@dataclass
class CreatePlan:
    """What ``validate_create`` checked, ready for ``create`` (and the ``?check=true`` answer)."""

    request: NewEnvironment
    repo: Repository
    branch: str
    path: str
    man: manifest.Manifest
    template: str | None
    hosts: dict[str, Host]
    secrets: dict[str, str]
    hostnames: list[dict[str, Any]]
    traffic: dict[str, Any]
    route_tls: dict[str, str]
    warnings: list[str] = field(default_factory=list)
    seed: Snapshot | None = None

    def to_json(self) -> dict[str, Any]:
        """``200 {ok, warnings, plan: {slots, hostnames, secrets, traffic}}`` (secret names only)."""
        slots = {slot: {"host_id": str(h.id), "host": h.name, "role": "data" if slot == DATA_SLOT else "app",
                        "slug": f"{self.request.name}-{slot}"} for slot, h in self.hosts.items()}
        return {"ok": True, "warnings": list(self.warnings),
                "plan": {"slots": slots, "hostnames": self.hostnames, "secrets": sorted(self.secrets),
                         "traffic": self.traffic}}


ReadFile = Callable[[Repository, str, str], Awaitable[str | None]]


def github_reader(user: User | None) -> ReadFile:
    """Read a file at a branch from GitHub, as ``GET /repositories/{id}/manifest`` does (repositories.py:90)."""
    from slipway.services.github import GitHubClient
    from slipway.services.repos import github_token_for

    async def read(repo: Repository, branch: str, path: str) -> str | None:
        token, _ = github_token_for(user)
        async with GitHubClient(token) as gh:
            text = await gh.get_file(repo.github_id, path, branch)
            if text is None:
                # GitHub answers 404 for a branch this token can't see too: only call the file missing when the
                # branch is there (else this raises).
                await gh.get_commit(repo.github_id, branch)
        return text

    return read


def _placeholder_builtins(name: str, slot: str, host: Host) -> dict[str, str]:
    """``{slipway.*}`` for planning before anything is deployed: the slot's real names, placeholder paths."""
    from slipway.services import deployer

    base = f"{deployer.clean_deploy_root(host.deploy_root)}/{name}-{slot}"
    sha = "0" * 40
    return {"slug": f"{name}-{slot}", "name": f"{name} {slot}", "release": f"{base}/releases/{sha[:12]}-plan",
            "env_dir": f"{base}/shared", "sha": sha, "sha12": sha[:12], "host": host.address,
            "deployment": "00000000", "environment": name, "slot": slot}


async def validate_create(db: AsyncSession, request: Any, ctx: Any, *, read_file: ReadFile | None = None) -> CreatePlan:
    """Check a new environment against §9.1's refusals, in its order, before anything is written; raise
    CreateRefused with the first one. ``ctx`` is the caller's AuthContext (``can``, ``user``). ``read_file``
    reads a file of the repository at a branch (tests pass a fake; default GitHub). Writes nothing."""
    from slipway.services import cloudflare, deployer, switchyard

    req = NewEnvironment.of(request)
    read = read_file or github_reader(getattr(ctx, "user", None))

    def no(status: int, detail: str, where: str | None) -> CreateRefused:
        return CreateRefused(status, detail, where)

    # 1. The name, and the slugs it reserves.
    name = (req.name or "").strip()
    if not NAME_RE.match(name):
        raise no(422, NAME_RULE, "name")
    if await db.scalar(select(Environment.id).where(Environment.name == name, Environment.deleted_at.is_(None))):
        raise no(409, f"An environment named {name} already exists", "name")
    for slot in SLOTS:
        holder = await db.scalar(select(Instance.name).where(Instance.slug == f"{name}-{slot}"))
        if holder is not None:
            raise no(409, f"Instance {holder} already uses the slug {name}-{slot}; pick another name", "name")

    # 2. The repository and its slipway.yml at the branch.
    repo = await db.get(Repository, req.repository_id)
    if repo is None:
        raise no(422, "Unknown repository", "repository_id")
    if not req.branch and not repo.default_branch_usable:
        raise no(422, f"Slipway could not store the default branch of {repo.full_name}; choose a branch", "branch")
    branch = req.branch or repo.default_branch
    try:
        path = manifest.clean_manifest_file(deployer.clean_relative_path(req.manifest_file or manifest.DEFAULT_FILE))
    except ValueError as exc:
        raise no(422, str(exc), "manifest_file") from exc
    from slipway.services.github import GitHubError

    try:
        text = await read(repo, branch, path)
    except GitHubError as exc:
        raise no(502, f"Could not read {path} on {branch} of {repo.full_name}: {exc}", "branch") from exc
    if text is None:
        raise no(409, f"{repo.full_name} has no {path} at {branch}", "manifest_file")
    try:
        man = manifest.parse(text)
    except manifest.ManifestError as exc:
        raise no(409, str(exc), "manifest_file") from exc
    template = None
    if man.env_file:
        try:
            template = await read(repo, branch, man.env_file)
        except GitHubError as exc:
            raise no(502, f"Could not read {man.env_file} on {branch} of {repo.full_name}: {exc}", "branch") from exc
        if template is None:
            raise no(409, f"{repo.full_name} has no {man.env_file} at {branch} (slipway.yml's env_file)", "manifest_file")

    # 3. The shape: two app slots need a data server and expand/contract migrations (D7); mode server a data server.
    caps = set(man.capabilities())
    if req.data_mode not in (DataMode.SLOT, DataMode.SERVER):
        raise no(422, "Choose where the data is kept: in the slot, or on a server of its own", "data_mode")
    hosts_in = {str(k): v for k, v in (req.hosts or {}).items() if v}
    unknown = sorted(set(hosts_in) - set(SLOTS))
    if unknown:
        raise no(422, f"There is no slot {unknown[0]}: the slots are blue, green and data", "hosts")
    two = "green" in hosts_in
    if two and req.data_mode == DataMode.SLOT:
        raise no(409, f"{name} would keep its data on blue; a second slot needs a data server", "data_mode")
    if (two or req.data_mode == DataMode.SERVER) and "server" not in caps:
        raise no(409, f"{repo.full_name}'s slipway.yml doesn't describe a data server (data.server), so Slipway can't "
                      "run two slots on one set of data" if two else
                 f"{repo.full_name}'s slipway.yml doesn't describe a data server (data.server), so Slipway can't keep "
                 "its data on a server of its own", "data_mode")
    if two and "bluegreen" not in caps:
        raise no(409, f"{repo.full_name}'s slipway.yml at {branch} doesn't declare data.migrations: expand_contract. "
                      "With two slots, blue keeps running on the database green migrates, so its migrations must add "
                      "before they remove.", "data_mode")

    # 4. The hosts.
    if "blue" not in hosts_in:
        raise no(422, "Choose a host for blue", "hosts.blue")
    if req.data_mode == DataMode.SERVER and DATA_SLOT not in hosts_in:
        raise no(422, "Choose a host for the data server", "hosts.data")
    if req.data_mode == DataMode.SLOT and DATA_SLOT in hosts_in:
        raise no(422, f"{name} keeps its data in blue, so it has no data server", "hosts.data")
    hosts: dict[str, Host] = {}
    for slot in SLOTS:
        if slot not in hosts_in:
            continue
        host = await db.get(Host, hosts_in[slot])
        if host is None:
            raise no(422, "Unknown host", f"hosts.{slot}")
        if not host.is_pinned:
            raise no(409, UNPINNED.format(host=host.name), f"hosts.{slot}")
        problem = await slot_folder_problem(db, name, slot, host)
        if problem:
            raise no(409, problem, f"hosts.{slot}")
        hosts[slot] = host
    probe = Environment(name=name, data_mode=req.data_mode)
    if req.data_mode == DataMode.SERVER:
        for slot in APP_SLOTS:
            if slot in hosts:
                problem = address_problem(probe, hosts[slot])
                if problem:
                    raise no(409, problem, f"hosts.{slot}")
        if any(hosts[DATA_SLOT].id == hosts[s].id for s in APP_SLOTS if s in hosts):
            raise no(409, f"The data server needs a host of its own: a container on {hosts[DATA_SLOT].name} reaches its "
                          f"database from a Docker address, which {name}'s data server can't let in by host address",
                     "hosts.data")
    warnings = []
    if two and hosts["blue"].id == hosts["green"].id:
        warnings.append(f"Blue and green both run on {hosts['blue'].name}: a problem with that host stops both, and "
                        "Switch back can't help with it")

    # 5. Settings: plan in each role with placeholder ports (this also catches clashing variables).
    env_vars = {str(k): str(v) for k, v in (req.env or {}).items()}
    settings = {str(k): str(v) for k, v in (req.settings or {}).items()}
    known = {s.name for s in man.optional_services}
    if req.services is not None:
        wrong = sorted(set(req.services) - known)
        if wrong:
            raise no(422, f"{wrong[0]} isn't an optional service of {path}", "services")
    secrets = manifest.new_secrets(man, {})
    roles = ["app"] if req.data_mode == DataMode.SLOT else ["server", "slot"]
    plans: dict[str, manifest.AppPlan] = {}
    for role in roles:
        try:
            manifest.check_instance_env(man, env_vars, role)
        except manifest.ManifestError as exc:
            raise no(422, str(exc).replace("the instance's environment variables", "the environment's variables"),
                     "env") from exc
        slot = DATA_SLOT if role == "server" else "blue"
        try:
            plans[role] = manifest.plan(
                man, template=template, builtins=_placeholder_builtins(name, slot, hosts[slot]), settings=settings,
                chosen=req.services, host_ports={}, secrets=secrets, env=env_vars, role=role,
                data_values=plans["server"].provides if role == "slot" else None,
                server_values={"host": hosts[DATA_SLOT].upstream_address,
                               "clients": [hosts[s].client_address for s in APP_SLOTS if s in hosts]}
                if role == "server" else None,
            )
        except manifest.ManifestError as exc:
            raise no(422, str(exc).replace("of the instance", "of the environment"), "settings") from exc
    app_plan = plans.get("app") or plans["slot"]
    hostnames = routes_of(app_plan, man, "active")
    if "server" in plans:
        hostnames += routes_of(plans["server"], man, "server")

    # 6. The names must be free.
    taken = await hostname_conflict(db, [h["hostname"] for h in hostnames])
    if taken:
        raise no(409, taken, "hostnames")
    names = {h["hostname"] for h in hostnames}
    route_tls = {str(k).lower(): str(v) for k, v in (req.route_tls or {}).items()}
    for hostname, mode in route_tls.items():
        if hostname not in names:
            raise no(422, f"{hostname} isn't one of {name}'s names", "route_tls")
        if mode not in switchyard.TLS_MODES:
            raise no(422, f"{mode} isn't a TLS mode (use {', '.join(switchyard.TLS_MODES)})", "route_tls")

    # 7. Traffic.
    wanted = dict(req.traffic or {})
    switch = str(wanted.get("switch") or "none")
    if switch not in SWITCHES:
        raise no(422, f"{switch} isn't a way to switch traffic (use none or switchyard)", "traffic")
    if switch == "switchyard" and await switchyard.load_config(db) is None:
        raise no(409, SET_UP_SWITCHYARD, "traffic")
    if two and switch != "switchyard":
        raise no(409, BLUE_GREEN_SWITCH, "traffic")
    dns_in = wanted.get("dns")
    dns = None
    if isinstance(dns_in, dict):  # {} turns DNS publishing on with the integration's defaults
        config = await cloudflare.load_config(db)
        if config is None:
            raise no(409, SET_UP_CLOUDFLARE, "traffic.dns")
        try:
            address = cloudflare.clean_public_ip((dns_in or {}).get("address"))
        except ValueError as exc:
            raise no(422, str(exc), "traffic.dns") from exc
        if address is None and not config.public_ip:
            raise no(409, "Give the records an address, or set the public IP in Settings → Integrations",
                     "traffic.dns")
        outside = sorted(n for n in names if not cloudflare.in_zone(n, config.zone))
        if outside:
            raise no(409, f"{outside[0]} isn't in the Cloudflare zone {config.zone}", "traffic.dns")
        proxied = dns_in.get("proxied")
        dns = {"provider": "cloudflare", "address": address,
               "proxied": config.proxied if proxied is None else bool(proxied)}
    traffic = {"switch": switch, "dns": dns}
    if req.auto_activate and not two:
        raise no(422, "Activate automatically needs two slots", "auto_activate")
    if req.keep_backups is not None and not 1 <= int(req.keep_backups) <= 100:
        raise no(422, "Keep 1 to 100 backups", "keep_backups")

    # 8. The seed snapshot and the first admin.
    seed = None
    where = f"{path} on {branch}"
    if req.seed_snapshot_id is not None:
        if not ctx.can(Perm.DATA_RESET):
            raise no(403, "Starting from a snapshot needs the data:reset permission", "seed_snapshot_id")
        seed = await db.get(Snapshot, req.seed_snapshot_id)
        if seed is None:
            raise no(422, "Unknown snapshot", "seed_snapshot_id")
        if seed.status != SnapshotStatus.READY:
            raise no(409, f"Snapshot {seed.name} isn't ready ({seed.status})", "seed_snapshot_id")
        if not seed.repository or seed.repository != repo.full_name:
            if not ctx.can(Perm.SNAPSHOTS_DOWNLOAD):
                raise no(403, f"Snapshot {seed.name} was made from {seed.repository or 'an unknown repository'}; "
                              f"seeding {name} ({repo.full_name}) from it needs the snapshots:download permission",
                         "seed_snapshot_id")
        if not man.data.app:
            raise no(409, f"{where} declares no data, so {name} can't start from a snapshot", "seed_snapshot_id")
        if seed.app != man.data.app:
            raise no(409, f"This snapshot is of app {seed.app} ({seed.app_name or seed.app}); {name} runs "
                          f"{man.data.app}", "seed_snapshot_id")
        pinned = sorted(k for k in set(man.identity_keys()) & set(seed.identity_keys or []) if k in env_vars)
        if pinned:
            raise no(409, f"The snapshot brings the {pinned[0]} its data was made with, and the environment's variable "
                          f"{pinned[0]} would replace it: remove the variable, then try again", "env")
    admin = req.first_admin
    if isinstance(admin, dict):
        from slipway.schemas import FirstAdminIn

        admin = FirstAdminIn(**admin)
    if admin is not None:
        if man.first_admin is None:
            raise no(422, f"{where} declares no first_admin", "first_admin")
        if admin.mode == "invite" and admin.password:
            raise no(422, "A first admin invited by email has no password", "first_admin")
        problem = deployer.first_admin_problem(man.first_admin, dict(admin.fields), admin.mode, admin.password)
        if problem:
            raise no(422, f"The first admin doesn't fit {where}: {problem}", "first_admin")
    elif seed is None and man.first_admin is not None:
        raise no(422, "Enter the first admin", "first_admin")
    req.first_admin = admin
    return CreatePlan(request=req, repo=repo, branch=branch, path=path, man=man, template=template, hosts=hosts,
                      secrets=secrets, hostnames=hostnames, traffic=traffic, route_tls=route_tls, warnings=warnings,
                      seed=seed)


async def create(db: AsyncSession, plan: CreatePlan, ctx: Any, *, request: Any = None) -> Environment:
    """Write what ``validate_create`` checked, in the caller's transaction (it commits): the environment (status
    ``new``, its secrets, its names), its instances (status CREATED), the data owner's phase 2 fields and
    ``FirstAdmin`` row, and the audit row (never a secret). No host is touched (§9.1)."""
    req, user = plan.request, ctx.user
    name = req.name.strip()
    env = Environment(
        id=uuid.uuid4(), name=name, repository_id=plan.repo.id, branch=plan.branch, manifest_file=plan.path,
        data_mode=req.data_mode, app_settings=dict(req.settings or {}), app_services=req.services,
        app_secrets=dict(plan.secrets), secrets_version=0, env=dict(req.env or {}), route_tls=dict(plan.route_tls),
        hostnames=list(plan.hostnames), auto_activate=bool(req.auto_activate), traffic=dict(plan.traffic),
        traffic_state={}, status=EnvironmentStatus.NEW, created_by_id=user.id if user else None,
    )
    db.add(env)
    try:
        await db.flush()
    except IntegrityError as exc:  # ux_environments_name_live: another request took the name
        await db.rollback()
        raise CreateRefused(409, f"An environment named {name} already exists", "name") from exc
    slots: dict[str, Instance] = {}
    for slot, host in plan.hosts.items():
        inst = Instance(
            name=f"{name} {slot}", slug=f"{name}-{slot}", repository_id=plan.repo.id, host_id=host.id,
            branch=plan.branch, build_source=BuildSource.APP, manifest_file=plan.path, deploy_dir=None,
            environment_id=env.id, slot=slot, slot_state={}, status=InstanceStatus.CREATED,
            created_by_id=user.id if user else None,
        )
        slots[slot] = inst
        db.add(inst)
    owner = slots[owner_slot(env)]
    owner.keep_backups = req.keep_backups or 5
    owner.seed_snapshot_id = plan.seed.id if plan.seed is not None else None
    owner.seed_content = True if req.seed_content is None else bool(req.seed_content)
    await db.flush()
    admin = req.first_admin
    if admin is not None:
        db.add(FirstAdmin(instance_id=owner.id, fields=dict(admin.fields), mode=admin.mode,
                          password=admin.password if admin.mode == "password" else None,
                          status=FirstAdminStatus.PENDING, existed=False, created_by_id=user.id if user else None))
    emails = [v for v in dict(admin.fields).values() if isinstance(v, str) and "@" in v] if admin is not None else []
    audit.record(
        db, "environment.create", actor=user, target=env, request=request,
        summary=f"Created environment {name} ({plan.repo.full_name}@{plan.branch})",
        details={"name": name, "repository": plan.repo.full_name, "branch": plan.branch, "data_mode": req.data_mode,
                 "slots": {s: h.name for s, h in plan.hosts.items()}, "traffic": plan.traffic,
                 "seed_snapshot": plan.seed.name if plan.seed is not None else None,
                 "first_admin": emails[0] if emails else None, "secrets": sorted(plan.secrets)},
    )
    await db.flush()
    return env


# ------------------------------------------------------- environment-level steps (§8.4)

ENV_STEP_NAMES = {
    "check": "Check {env}",
    "start_slot": "Start {slot}",
    "stop_slot": "Stop {slot}",
    "smoke": "Check {slot} on {host}",
    "dns": "Update DNS records",
    "switch": "Switch traffic to {slot}",
    "seed": "Add starter content",
    "traffic": "Update Switchyard",
    "settle": "Mark the data as checked",
    "slot": "Remove {slot}",
    "unroute": "Remove the Switchyard hosts",
    "undns": "Remove the DNS records",
    "slots": "Remove Blue and Green",
    "data_server": "Remove the data server",
    "forget": "Forget {env}",
}
# Seconds each environment-level step may take (§13); ``seed`` takes the manifest's own timeout.
ENV_STEP_TIMEOUTS = {"check": 120, "switch": 1200, "dns": 600, "stop_slot": 600, "settle": 60, "unroute": 600,
                     "undns": 600, "slot": 1800, "slots": 1800, "data_server": 1800, "start_slot": 600,
                     "smoke": 600, "traffic": 600, "forget": 60}


def env_steps_for(env: Environment, kind: str, options: dict[str, Any] | None,
                  members: dict[str, Instance]) -> list[dict[str, Any]]:
    """The numbered steps of an environment-level job (§8.1, §8.4), with ⟨…⟩ steps listed only when their
    condition holds when the job is queued: ``start_slot`` when the target slot is stopped, ``dns`` when the
    environment publishes DNS records, ``seed`` in the first activation when starter content is wanted,
    ``traffic`` when it publishes through Switchyard."""
    opts = options or {}
    slot = opts.get("slot")
    target = members.get(slot) if slot else None
    owner = owner_in(env, members)
    dns = bool((env.traffic or {}).get("dns"))
    if kind == DeploymentKind.ACTIVATE:
        keys = ["check", *(["start_slot"] if target is not None and target.status == InstanceStatus.STOPPED else []),
                "smoke", *(["dns"] if dns else []), "switch",
                *(["seed"] if env.status == EnvironmentStatus.NEW and owner is not None and owner.seed_content else [])]
    elif kind == DeploymentKind.PUBLISH:
        keys = ["check", *(["traffic"] if (env.traffic or {}).get("switch", "none") != "none" else []),
                *(["dns"] if dns else [])]
    elif kind == DeploymentKind.DISCARD:
        keys = ["check", "stop_slot", "smoke", "settle"]
        # The smoke test of a discard checks the active slot on the current data, not the discarded one.
        target = active_member(env, members) or target
    elif kind == DeploymentKind.REMOVE_SLOT:
        keys = ["check", "slot"]
    elif kind == DeploymentKind.TEARDOWN:
        keys = ["check", "unroute", "undns", "slots", "data_server", "forget"]
    else:
        raise ValueError(f"{kind!r} isn't an environment-level job")
    values = {"env": env.name, "slot": slot or "", "host": target.host.name if target is not None else ""}
    if kind == DeploymentKind.DISCARD:
        values["checked"] = target.slot if target is not None else ""
    names = dict(ENV_STEP_NAMES)
    if kind == DeploymentKind.DISCARD:
        names["smoke"] = "Check {checked} on {host}"
    if kind == DeploymentKind.TEARDOWN and len(app_members(members)) == 1:
        names["slots"] = "Remove Blue"
    return [{"key": k, "name": names[k].format(**values), "status": "pending"} for k in keys]


# ---------------------------------------------------------------- refusals by action


async def latest_deploy(db: AsyncSession, instance: Instance) -> Deployment | None:
    return await db.scalar(select(Deployment).options(defer(Deployment.log))
                           .where(Deployment.instance_id == instance.id, Deployment.kind == DeploymentKind.DEPLOY)
                           .order_by(Deployment.created_at.desc(), Deployment.id.desc()).limit(1))


def stale_text(slot: str, stale: dict[str, Any]) -> str:
    """``green was stopped when uat's data was restored; deploy to it first``."""
    reason = str(stale.get("reason") or "marked stale").split(";")[0].strip()
    if reason.lower().startswith("its "):
        return f"{slot}'s {reason[4:]}; deploy to it first"
    return f"{slot} was {reason[:1].lower()}{reason[1:]}; deploy to it first"


async def activate_problem(db: AsyncSession, env: Environment, slot: str | None,
                           members: dict[str, Instance] | None = None) -> str | None:
    """§9.5's refusals 1-3 and 5 for an activate of ``slot`` (the host, the data owner's state and the running
    jobs, refusal 4, are ``jobs.job_refusal``'s fences; the plan's blockers, 6, need Switchyard)."""
    from slipway.services import switchyard

    mem = members if members is not None else await members_of(db, env)
    target = mem.get(slot) if slot else None
    if target is None or slot not in APP_SLOTS:
        return "Only an app slot can take traffic"
    if env.active_slot_id == target.id and unresolved_text(env) is None:
        return f"{slot} already takes the traffic"
    latest = await latest_deploy(db, target)
    if latest is None or not target.current_commit_sha:
        return f"Deploy to {slot} first"
    if latest.status != DeploymentStatus.SUCCEEDED and not DeploymentStatus(latest.status).is_active:
        return f"{slot}'s latest deploy ({latest.id.hex[:8]}) failed: retry it, deploy again or discard it"
    stale = stale_of(target)
    if stale:
        return stale_text(slot, stale)
    if target.status not in (InstanceStatus.RUNNING, InstanceStatus.STOPPED):
        return f"{slot} is {target.status}"
    if (env.traffic or {}).get("switch") == "switchyard" and await switchyard.load_config(db) is None:
        return SET_UP_SWITCHYARD
    return None


members_of = members  # an alias for the parameter name it would shadow


def dirty_names(owner: Instance | None, slot_instance: Instance, deployments: dict[str, Deployment]) -> bool:
    """Whether the owner's dirty state names a job of ``slot_instance`` (``deployments`` by id hex)."""
    dirty = (owner.data_dirty if owner is not None else None) or {}
    for part in ("first", "last"):
        dep = deployments.get(str((dirty.get(part) or {}).get("deployment_id") or ""))
        if dep is not None and dep.instance_id == slot_instance.id:
            return True
    return False


async def remove_slot_problem(db: AsyncSession, env: Environment, slot: str | None,
                              members: dict[str, Instance] | None = None) -> str | None:
    """§9.9's refusals that are about the slot (the running job and an unresolved switch are fences)."""
    mem = members if members is not None else await members_of(db, env)
    if slot == DATA_SLOT:
        return "The data server goes with the environment"
    target = mem.get(slot) if slot else None
    if target is None:
        return f"{env.name} has no slot {slot}"
    if env.active_slot_id == target.id:
        other = next((s for s in APP_SLOTS if s != slot), "the other slot")
        return f"{slot} takes the traffic: activate {other} first"
    if len(app_members(mem)) < 2:
        return f"{slot} is {env.name}'s only slot: delete the environment instead"
    owner = owner_in(env, mem)
    ids = [str((((owner.data_dirty if owner else None) or {}).get(p) or {}).get("deployment_id") or "")
           for p in ("first", "last")]
    found = {d.id.hex: d for d in (await db.scalars(select(Deployment).options(defer(Deployment.log)).where(
        Deployment.id.in_([u for u in (data._uuid(i) for i in ids) if u])))).all()} if any(ids) else {}
    if dirty_names(owner, target, found):
        return f"Discard {slot} or roll back first"
    return None


async def publish_problem(db: AsyncSession, env: Environment) -> str | None:
    """§9.11's refusals that don't need a plan."""
    from slipway.services import cloudflare, switchyard

    traffic = env.traffic or {}
    if traffic.get("switch", "none") == "none" and not traffic.get("dns"):
        return f"{env.name} publishes no names"
    if traffic.get("switch") == "switchyard" and await switchyard.load_config(db) is None:
        return SET_UP_SWITCHYARD
    if traffic.get("dns") and await cloudflare.load_config(db) is None:
        return SET_UP_CLOUDFLARE
    return None


# ---------------------------------------------------------------- actions (§11)


def _no(reason: str | None, **extra: Any) -> dict[str, Any]:
    return {"available": reason is None, "reason": reason, **extra}


def behind(env: Environment, slot: str) -> bool:
    """The lag check's hint (§7.6): the last activate was a switch back, and no deploy to ``slot`` (the idle
    slot) has succeeded since."""
    last = (env.traffic_state or {}).get("last")
    if not isinstance(last, dict) or not last.get("back"):
        return False
    deployed = last_slot_deploy(env)
    return not (deployed and deployed.get("slot") == slot and str(deployed.get("at") or "") > str(last.get("at") or ""))


async def actions(db: AsyncSession, env: Environment, ctx: Any) -> dict[str, Any]:
    """``EnvironmentOut.actions``: what the environment page offers, and why not (§11). The API and the page
    share it, and each queued job is checked again by ``jobs.queue_job``."""
    from slipway.services import jobs  # jobs imports this module

    user = getattr(ctx, "user", None)
    mem = await members(db, env)
    apps = app_members(mem)
    owner = owner_in(env, mem)
    can = ctx.can
    gone = deleting_text(env)

    async def refusal(instance: Instance | None, kind: str, options: dict[str, Any] | None = None) -> str | None:
        found = await jobs.job_refusal(db, instance=instance, environment=env, user=user, kind=kind,
                                       options=options, members=mem)
        return found.text if found is not None else None

    # Deploy: the data server first in a new mode server environment, then the target slot.
    server_new = env.data_mode != DataMode.SLOT and owner is not None and data.live_state(owner) is None
    slot = DATA_SLOT if server_new else target_slot(env, mem)
    target = mem.get(slot)
    go_live = goes_live(env, slot, mem)
    needs_ts = go_live and (len(apps) == 2 or env.active_slot_id is None)
    if server_new and not any(m.current_commit_sha for m in apps):
        needs_ts = True  # the chain's first slot deploy goes live (jobs.job_refusal asks it up front)
    reason = gone or (None if can(Perm.DEPLOYMENTS_CREATE) else need_text(Perm.DEPLOYMENTS_CREATE))
    if reason is None:
        reason = f"{env.name} has no slot {slot}" if target is None else await refusal(
            target, DeploymentKind.DEPLOY, {"slot": slot, "go_live": go_live, "chain": server_new or None})
    stale = stale_of(target) if target is not None else None
    out: dict[str, Any] = {"deploy": _no(reason, slot=slot, go_live=go_live, needs_traffic_switch=needs_ts,
                                         behind=len(apps) == 2 and behind(env, slot), stale=stale)}

    # Discard and roll back, after a failed deploy that left the owner dirty.
    disc = await data.discard_state(db, env)
    if disc.available and not (can(Perm.DEPLOYMENTS_CREATE) and can(Perm.TRAFFIC_SWITCH)):
        disc.available, disc.reason = False, need_text(Perm.TRAFFIC_SWITCH)
    out["discard"] = _no(None if disc.available else disc.reason, slot=disc.slot)
    first = ((owner.data_dirty if owner is not None else None) or {}).get("first") or {}
    first_id = data._uuid(first.get("deployment_id"))
    failed = await db.get(Deployment, first_id) if first_id is not None else None
    if failed is None:
        out["rollback"] = _no("Nothing to roll back", deployment_id=None)
    else:
        roll = await data.rollback_state(db, failed)
        reason = roll.reason
        if roll.available:
            for perm in (Perm.DEPLOYMENTS_CREATE, Perm.DATA_RESTORE, *([Perm.DATA_RESET] if roll.needs_reset else [])):
                if not can(perm):
                    reason = need_text(perm)
                    break
        out["rollback"] = _no(reason, deployment_id=failed.id.hex)

    # Update the data server (mode server).
    data_member = mem.get(DATA_SLOT)
    if env.data_mode == DataMode.SLOT or data_member is None:
        reason = f"{env.name} keeps its data in {apps[0].slot if apps else 'blue'}"
    else:
        # With the options POST /environments/{id}/deploy (target data) queues: a chain to the first slot while
        # no app slot has deployed, which goes live and so needs traffic:switch (jobs.job_refusal).
        chain = True if not any(m.current_commit_sha for m in apps) else None
        reason = gone or (None if can(Perm.DEPLOYMENTS_CREATE) else need_text(Perm.DEPLOYMENTS_CREATE)) \
            or await refusal(data_member, DeploymentKind.DEPLOY, {"slot": DATA_SLOT, "chain": chain})
    out["update_data_server"] = _no(reason)

    # Activate the idle slot, or switch back to the one that was live before.
    active = active_member(env, mem)
    if len(apps) == 2 and active is not None and active.slot in APP_SLOTS:
        idle = "green" if active.slot == "blue" else "blue"
    else:
        last = last_slot_deploy(env)
        idle = last["slot"] if last and last.get("slot") in APP_SLOTS and last["slot"] in mem else "blue"
    last = (env.traffic_state or {}).get("last") or {}
    back_slot = last.get("from_slot") if isinstance(last, dict) else None
    reason = gone or (None if can(Perm.TRAFFIC_SWITCH) else need_text(Perm.TRAFFIC_SWITCH)) \
        or await refusal(None, DeploymentKind.ACTIVATE, {"slot": idle})
    out["activate"] = _no(reason, slot=idle)
    if back_slot in APP_SLOTS and back_slot in mem and (active is None or active.slot != back_slot):
        reason = gone or (None if can(Perm.TRAFFIC_SWITCH) else need_text(Perm.TRAFFIC_SWITCH)) \
            or await refusal(None, DeploymentKind.ACTIVATE, {"slot": back_slot, "back": True})
        if reason is None and mem[back_slot].status != InstanceStatus.RUNNING:
            reason = f"{back_slot} isn't running"
        out["switch_back"] = _no(reason, slot=back_slot)
    else:
        out["switch_back"] = _no("Nothing was live before", slot=None)

    reason = gone or (None if can(Perm.TRAFFIC_SWITCH) else need_text(Perm.TRAFFIC_SWITCH)) \
        or await refusal(None, DeploymentKind.PUBLISH)
    out["publish"] = _no(reason)

    # The chain notice's button: the follow-up job, with its own permission (§8.5).
    notice = env.notice if isinstance(env.notice, dict) else None
    nxt = (notice or {}).get("next")
    if isinstance(nxt, dict) and nxt.get("kind"):
        kind, nslot = str(nxt["kind"]), nxt.get("slot")
        perm = FOLLOW_UP_PERMISSION.get(kind, Perm.DEPLOYMENTS_CREATE)
        reason = None if can(perm) else need_text(perm)
        if reason is None:
            inst = mem.get(nslot) if kind == DeploymentKind.DEPLOY and nslot else None
            opts: dict[str, Any] = {"slot": nslot}
            if inst is not None:
                opts["go_live"] = goes_live(env, str(nslot), mem)
            if kind == DeploymentKind.TEARDOWN:
                opts = {"confirmed": True}
            reason = await refusal(inst, kind, opts)
        out["continue"] = _no(reason, kind=kind, slot=nslot)
    else:
        out["continue"] = None

    # Add a slot (mode server, one app slot).
    if gone:
        reason = gone
    elif env.data_mode == DataMode.SLOT:
        reason = f"{env.name} keeps its data on {apps[0].slot if apps else 'blue'}; a second slot needs a data server"
    elif len(apps) >= 2:
        reason = f"{env.name} already has two slots"
    elif not can(Perm.ENVIRONMENTS_WRITE):
        reason = need_text(Perm.ENVIRONMENTS_WRITE)
    else:
        caps = data.capabilities(owner) if owner is not None else set()
        reason = await two_slot_traffic_problem(db, env)
        if reason is None and caps and "bluegreen" not in caps:
            reason = f"{env.name}'s slipway.yml doesn't declare data.migrations: expand_contract, which two slots need"
        if reason is None:
            busy = await jobs.busy_job(db, env, data.env_keys(env.id, None))
            reason = busy_text(env, busy) if busy is not None else None
    out["add_slot"] = _no(reason)

    # Delete. While the environment is deleting, only its teardown's retry is accepted (§3).
    if env.status == EnvironmentStatus.DELETED:
        reason = f"{env.name} was deleted"
    elif not can(Perm.ENVIRONMENTS_DELETE):
        reason = need_text(Perm.ENVIRONMENTS_DELETE)
    else:
        busy = await jobs.busy_job(db, env, data.env_keys(env.id, DeploymentKind.TEARDOWN))
        reason = busy_text(env, busy) if busy is not None else None
        if reason is None and env.status == EnvironmentStatus.DELETING:
            reason = f"{deleting_text(env)}: retry its teardown from the job's page"
    out["delete"] = _no(reason)
    return out


# ---------------------------------------------------------------- the chain (§8.5)

# The permission a chained follow-up needs of the user it runs as (§4.1); any other kind needs
# deployments:create, and a slot deploy that goes live traffic:switch as well (jobs.job_refusal).
FOLLOW_UP_PERMISSION = {DeploymentKind.ACTIVATE: Perm.TRAFFIC_SWITCH, DeploymentKind.TEARDOWN: Perm.ENVIRONMENTS_DELETE}


@dataclass
class NextJob:
    """What a chain rule queues after a job succeeded."""

    kind: str
    slot: str | None
    options: dict[str, Any]

    def label(self) -> str:
        return data.job_label(self.kind, slot=self.slot)

    def to_json(self) -> dict[str, Any]:
        return {"kind": self.kind, "slot": self.slot}


async def next_job(db: AsyncSession, dep: Deployment) -> NextJob | None:
    """The job §8.5's chain rules queue after ``dep`` succeeded, or None:

    1. a data server deploy with ``options.chain``: when no app slot has finished a deploy, a deploy of
       ``target_slot`` that goes live; otherwise a deploy of an app slot that has never been deployed (a slot just
       added with "update the data server", §9.8), which doesn't;
    2. an app slot deploy with ``options.go_live``: an activate of that slot;
    3. a snapshot with ``options.then == "teardown"``: the teardown, its typed name already checked.
    """
    if dep.environment_id is None or dep.status != DeploymentStatus.SUCCEEDED:
        return None
    env = await db.get(Environment, dep.environment_id)
    if env is None or env.is_deleted:
        return None
    mem = await members(db, env)
    opts = dep.options or {}
    inst = next((m for m in mem.values() if m.id == dep.instance_id), None)
    if dep.kind == DeploymentKind.DEPLOY and inst is not None and inst.slot == DATA_SLOT and opts.get("chain"):
        apps = app_members(mem)
        if not any(m.current_commit_sha for m in apps):
            slot = target_slot(env, mem)
            return NextJob(DeploymentKind.DEPLOY, slot, {"chain": True, "go_live": True, "slot": slot})
        new = next((m for m in apps if not m.current_commit_sha), None)
        if new is not None:
            return NextJob(DeploymentKind.DEPLOY, str(new.slot), {"chain": True, "go_live": False, "slot": new.slot})
        return None
    if dep.kind == DeploymentKind.DEPLOY and inst is not None and inst.slot in APP_SLOTS and opts.get("go_live"):
        return NextJob(DeploymentKind.ACTIVATE, str(inst.slot), {"chain": True, "slot": inst.slot})
    if dep.kind == DeploymentKind.SNAPSHOT and opts.get("then") == "teardown":
        snap = await db.get(Snapshot, dep.snapshot_id) if dep.snapshot_id is not None else None
        return NextJob(DeploymentKind.TEARDOWN, None,
                       {"confirmed": True, **({"snapshot": snap.name} if snap is not None else {})})
    return None


async def _already_queued(db: AsyncSession, env_id: uuid.UUID, after: uuid.UUID) -> Deployment | None:
    rows = (await db.scalars(select(Deployment).options(defer(Deployment.log))
                             .where(Deployment.environment_id == env_id, Deployment.created_at.is_not(None))
                             .order_by(Deployment.created_at.desc()))).all()
    return next((d for d in rows if (d.options or {}).get("after") == after.hex), None)


async def _write_notice(db: AsyncSession, env: Environment, finished: uuid.UUID, nxt: NextJob, text: str,
                        why: str) -> None:
    env.notice = {"text": text, "at": utcnow().isoformat(), "deployment_id": finished.hex, "next": nxt.to_json()}
    audit.record(db, "environment.chain_stopped", target=env, summary=text,
                 details={"finished": finished.hex, "next": nxt.to_json(), "why": why})


Submit = Callable[[uuid.UUID, tuple[Any, ...]], Any]


async def after_job(deployment_id: uuid.UUID, *, submit: Submit | None = None) -> uuid.UUID | None:
    """Queue the next job of the chain after ``deployment_id`` succeeded (§8.5), in its own session and under no
    runner lock; it only queues. Called at the end of ``run_deployment`` and ``env_jobs.run`` for any job with
    ``environment_id`` (never from ``_finish``, which also records successes during shutdown).

    The new job is triggered by the finished job's user and carries ``options.after``; calling this twice for
    one job queues once. A refusal (busy, the hold, an unpinned host, a permission the user no longer has) is
    written to ``environments.notice`` and audited (``environment.chain_stopped``). ``submit(id, keys)`` starts
    the job (default the deployer's runner). Returns the queued (or already queued) job's id.
    """
    from slipway.services import jobs

    queued: Deployment | None = None
    keys: tuple[Any, ...] = ()
    async with session_scope() as db:
        dep = await db.get(Deployment, deployment_id)
        if dep is None or dep.environment_id is None or dep.status != DeploymentStatus.SUCCEEDED:
            return None
        nxt = await next_job(db, dep)
        if nxt is None:
            return None
        found = await _already_queued(db, dep.environment_id, dep.id)
        if found is not None:
            return found.id
        env = await db.get(Environment, dep.environment_id)
        assert env is not None
        mem = await members(db, env)
        user = await db.get(User, dep.triggered_by_id) if dep.triggered_by_id else None
        instance = mem.get(nxt.slot) if nxt.kind == DeploymentKind.DEPLOY and nxt.slot else None
        env_id, finished, label = env.id, dep.id, data.dep_label(dep)  # a refusal may roll the session back
        try:
            if nxt.kind == DeploymentKind.DEPLOY and instance is None:
                raise jobs.JobRefused(409, f"{env.name} has no slot {nxt.slot}")
            # The follow-up runs as the finished job's user, who must still exist, be active and hold its
            # permission (checked after the queue's other refusals).
            needs = (FOLLOW_UP_PERMISSION.get(nxt.kind, Perm.DEPLOYMENTS_CREATE),)
            queued = await jobs.queue_job(db, instance=instance, environment=env, user=user, kind=nxt.kind,
                                          options={**nxt.options, "after": finished.hex}, needs=needs)
        except jobs.JobRefused as exc:
            env = await db.get(Environment, env_id, populate_existing=True)
            assert env is not None
            text = f"{nxt.label()} didn't start after {label} succeeded: {exc.text}"
            await _write_notice(db, env, finished, nxt, text, "refused")
            return None
        audit.record(db, "deployment.create", actor=user, target=queued,
                     summary=f"Queued {nxt.label()} of {env.name} after {label}",
                     details={"environment": env.name, "slot": nxt.slot, "kind": nxt.kind,
                              "go_live": bool(nxt.options.get("go_live")), "after": finished.hex})
        keys = data.job_keys(queued, instance)
        queued_id = queued.id
    if submit is None:
        from slipway.services import deployer  # the deployer imports this module

        submit = deployer.runner.submit
    submit(queued_id, keys)
    return queued_id


async def chain_notice(deployment_id: uuid.UUID, *, why: str = "shutdown") -> bool:
    """When a job of an environment was recorded as succeeded without its chain hook running (Slipway shutting
    down, ``why="shutdown"``, or recovery after a restart marking it succeeded, ``why="restart"``), write the
    notice whose button starts the follow-up by hand (§8.5). Returns whether a follow-up was due."""
    if why not in ("shutdown", "restart"):
        raise ValueError(why)
    async with session_scope() as db:
        dep = await db.get(Deployment, deployment_id)
        if dep is None or dep.environment_id is None:
            return False
        nxt = await next_job(db, dep)
        if nxt is None or await _already_queued(db, dep.environment_id, dep.id) is not None:
            return False
        env = await db.get(Environment, dep.environment_id)
        assert env is not None
        verb = "stopped" if why == "shutdown" else "restarted"
        text = f"Slipway {verb} after {data.dep_label(dep)} succeeded, before it started {nxt.label()}"
        await _write_notice(db, env, dep.id, nxt, text, why)
    return True
