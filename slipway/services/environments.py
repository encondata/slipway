"""Environment rules (phase 3): who owns the data, which slot a deploy goes to and whether it goes live, the
values an app slot attaches to its data with, creating an environment, the environment-level step lists, what
the environment page offers, and the chain of jobs a first deploy starts.

An environment's slots are ordinary instances with ``environment_id`` and ``slot`` set (D1). The **data owner**
is the data server (mode ``server``) or the only app slot (mode ``slot``) and holds every phase 2 data field
(D3). The API, the pages and the job engine all ask this module, so they always agree; it never touches a host.
"""

from __future__ import annotations

import contextlib
import contextvars
import ipaddress
import re
import uuid
from collections.abc import Awaitable, Callable, Iterable, Iterator
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
    Machine,
    MachineStage,
    ProviderAccount,
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
# ``do_lb`` is a DigitalOcean environment's load balancer (phase 4 §11.6); placement pairs it (Decision 24).
SWITCHES = ("none", "switchyard", "do_lb")
DO_LB = "do_lb"
DIGITALOCEAN = "digitalocean"  # the placement (environments.provider) and the droplets' host provider
DO_NEEDS_LB = ("A DigitalOcean environment's traffic goes through its load balancer: choose the DigitalOcean load "
               "balancer")
LB_NEEDS_DO = "A load balancer comes only with DigitalOcean placement: choose Switchyard or none"
CLAIM_TAKEN = "{address} was just taken by another environment: pick another address"  # Decision 43

# The texts more than one place answers with.
NAME_RULE = "Use 2-26 lowercase letters, digits and hyphens, starting with a letter"
SET_UP_SWITCHYARD = "Set up Switchyard in Settings → Integrations first"
SET_UP_CLOUDFLARE = "Set up Cloudflare in Settings → Integrations first"
UNPINNED = "Check host {host} first: Slipway hasn't verified its key"
BLUE_GREEN_SWITCH = "Blue/Green moves its names in Switchyard when a slot goes live: choose Switchyard"
# Phase 5 §10.4: Activate of a slot whose VM isn't made yet, or is off after a resize left it off.
VM_NOT_MADE = "{slot}'s VM isn't made yet: deploy to {slot} first"
VM_OFF = "{slot}'s VM {vm} is off: deploy to {slot} again to finish its resize"
# The order VMs go in, in Delete (phase 5 §9.9): the app VMs first, the data VM last.
VM_REMOVE_ORDER = ("green", "blue", "data")


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
    where = "the load balancer" if (env.traffic or {}).get("switch") == DO_LB else "Switchyard"
    return (f"Traffic of {env.name} may be split between its slots{since}{why}. Activate a slot, or use Resolve "
            f"once {where} is right")


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


def no_host_text(env: Environment) -> str:
    """A host-less data owner (a managed environment's, phase 4 §3.4) has no data server to attach to."""
    return f"{env.name}'s data is managed by DigitalOcean: it has no data server to attach to"


def attach_problem(env: Environment, owner: Instance | None, slot: Instance) -> str | None:
    """Why an app slot in mode ``server`` can't be deployed on its data server yet (§6), checked when the job is
    queued and again in its ``settings`` step. None outside mode ``server`` (mode ``slot``, and a managed
    environment's slots, whose values come from the provider) and for the data server itself."""
    if env.data_mode != DataMode.SERVER or slot.slot not in APP_SLOTS or slot.host is None:
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

    if owner.host is None:
        raise DataValuesError(no_host_text(env))
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
    Raises DataValuesError when the data server has no live release or can't be rendered, and for a host-less
    owner (a managed environment has no data server).
    """
    if owner.host is None:
        raise DataValuesError(no_host_text(env))
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
    its names in Switchyard, so the switch must be Switchyard and Switchyard set up. A DigitalOcean environment's
    load balancer (``do_lb``) moves them itself."""
    from slipway.services import switchyard

    if (env.traffic or {}).get("switch") == DO_LB:
        return None
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
    hosts: dict[str, Any]  # a host id, or {machine: {...}} for a new VM (phase 5 §9.2)
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
    placement: dict[str, Any] | None = None  # phase 4 §15.1: {provider: digitalocean, account_id, region, ...}
    production: bool = False
    confirm_cost: str | None = None

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
    # The hosts a provider makes, by slot (Decision 24): ``{provider, name}`` for a droplet, and for a VM also
    # ``account_id, account, network, profile, address, size``. Their ``hosts`` entries are unsaved stand-ins.
    planned: dict[str, dict[str, Any]] = field(default_factory=dict)
    do: Any = None  # DoChoice: a DigitalOcean create's account, sizes, plan and estimate

    def to_json(self) -> dict[str, Any]:
        """``200 {ok, warnings, plan: {slots, hostnames, secrets, traffic}}`` (secret names only). A slot a
        provider makes gives ``{host_id: null, host, planned: <provider>}``; DigitalOcean adds ``cost`` at the top
        level and ``plan.cloud``, new VMs ``plan.machines`` (Decision 24)."""
        slots: dict[str, Any] = {}
        for slot, h in self.hosts.items():
            made = self.planned.get(slot)
            slots[slot] = {"host_id": None if made else str(h.id), "host": h.name,
                           "role": "data" if slot == DATA_SLOT else "app", "slug": f"{self.request.name}-{slot}"}
            if made:
                slots[slot]["planned"] = made["provider"]
        if self.do is not None:
            slots[DATA_SLOT] = {"host_id": None, "host": None, "role": "data", "slug": f"{self.request.name}-data",
                                "managed": True}
        out: dict[str, Any] = {"ok": True, "warnings": list(self.warnings),
                               "plan": {"slots": slots, "hostnames": self.hostnames, "secrets": sorted(self.secrets),
                                        "traffic": self.traffic}}
        vms = [{"slot": slot, "name": m["name"], "account": m["account"], "network": m["network"],
                "address": m["address"], "size": m["size"]}
               for slot, m in self.planned.items() if m["provider"] != DIGITALOCEAN]
        if vms:
            out["plan"]["machines"] = vms
        if self.do is not None:
            out["cost"] = self.do.cost.to_json()
            out["plan"]["cloud"] = self.do.to_json(self.request.name.strip())
        return out


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


def _host_rules() -> Any:
    from slipway.services import hosts  # the name ``hosts`` is a local everywhere in this module

    return hosts


def _provider_accounts() -> Any:
    from slipway.services import provider_accounts  # imports the provider clients, which import this module

    return provider_accounts


def _stand_in(env_name: str, slot: str, provider: str, *, description: str, hostname: str | None = None) -> Host:
    """An unsaved host for a slot a provider will make (Decision 24), with an id of its own so the rules that
    compare hosts tell the slots apart. A droplet's is written as it is by ``create``; a VM's comes from
    ``machines.plan``."""
    host = _host_rules().planned_host(env_name, slot, provider=provider, hostname=hostname, description=description)
    host.id = uuid.uuid4()
    return host


def machine_spec(value: Any) -> dict[str, Any] | None:
    """The VM a ``hosts.<slot>`` value asks for (``{machine: {account_id, network, address, sizes}}``), as
    ``{account_id, network, address, size}``, or None for a host id."""
    if hasattr(value, "model_dump"):
        value = value.model_dump()
    if not isinstance(value, dict) or "machine" not in value:
        return None
    spec = value["machine"]
    if hasattr(spec, "model_dump"):
        spec = spec.model_dump()
    spec = dict(spec or {})
    size = {k: spec[k] for k in ("cores", "memory_mb", "disk_gb") if spec.get(k) is not None}
    if isinstance(spec.get("size"), dict):
        size.update(spec["size"])
    return {"account_id": spec.get("account_id"), "network": spec.get("network"),
            "address": spec.get("address") or "auto", "size": size}


def _host_id(value: Any) -> uuid.UUID | None:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except ValueError:
        return None


async def _owned_problem(db: AsyncSession, host: Host, action: str) -> str | None:
    """Phase 5 refusal 0 (D18), for droplets too (Decision 7): a host an environment made runs only its slots."""
    if host.owner_environment_id is None:
        return None
    return await _host_rules().owned_host_problem(db, host, action=action)


def _secret_word(provider: str) -> str:
    return {"proxmox": "API token", "esxi": "password"}.get(provider, "token")


def vm_account_refusal(account: ProviderAccount | None, base: str) -> CreateRefused | None:
    """Phase 5 §9.2 refusal 2: the account of a new VM is a Proxmox or ESXi account that can be used, has been
    tested and didn't fail its last test."""
    from slipway.services import vmnet

    if account is None:
        return CreateRefused(422, "Unknown account", f"{base}.account_id")
    if account.provider not in vmnet.PROVIDERS:
        return CreateRefused(409, f"{account.name} is a DigitalOcean account: choose DigitalOcean under Where",
                             f"{base}.account_id")
    if account.removed_at is not None:
        return CreateRefused(409, f"{account.name} was removed: add the account again first", f"{base}.account_id")
    if not (account.config or {}).get("url"):
        return CreateRefused(409, f"{account.name} has no URL: set it in Settings → Integrations", f"{base}.account_id")
    if not account.secret:
        return CreateRefused(409, f"Slipway can't read {account.name}'s {_secret_word(account.provider)} any more: "
                                  "enter it again in Settings → Integrations", f"{base}.account_id")
    if not (account.tls or {}).get("pem"):
        return CreateRefused(409, f"Trust {account.name}'s certificate in Settings → Integrations first",
                             f"{base}.account_id")
    if account.provider == "proxmox" and not (account.facts or {}).get("storage_type"):
        return CreateRefused(409, f"Test {account.name} first: Slipway needs to know its storage type",
                             f"{base}.account_id")
    if account.status == "error":
        failed = next((c for c in account.checks or [] if isinstance(c, dict) and c.get("level") == "error"), None)
        what = str((failed or {}).get("text") or (failed or {}).get("name") or "a check failed").rstrip(".")
        return CreateRefused(409, f"{account.name}'s last test failed: {what}. Test it again in Settings → "
                                  "Integrations", f"{base}.account_id")
    return None


async def plan_vms(db: AsyncSession, env_name: str, wanted: dict[str, dict[str, Any]], ctx: Any, *,
                   existing: Iterable[Machine] = ()) -> dict[str, dict[str, Any]]:
    """Phase 5 §9.2 refusals 1-5 for the new VMs ``wanted`` (slot to ``machine_spec``), in order; raise
    CreateRefused with the first. Reads no hypervisor. ``existing`` are the environment's VMs already planned (Add
    slot): the new one must use their account and network.

    Returns, per slot in slot order: ``{provider, account_id, account, network, profile, address, size, name,
    host}``, where ``host`` is the unsaved stand-in at the VM's address and ``address`` is the typed one, or the
    lowest free pool address in slot order for ``auto``."""
    from slipway.services import machines, vmnet

    order = [s for s in SLOTS if s in wanted]
    if not ctx.can(Perm.MACHINES_WRITE):
        raise CreateRefused(403, f"Making a VM needs the {Perm.MACHINES_WRITE} permission", f"hosts.{order[0]}")
    accounts: dict[str, ProviderAccount] = {}
    for slot in order:
        account = await db.get(ProviderAccount, _host_id(wanted[slot].get("account_id")))
        problem = vm_account_refusal(account, f"hosts.{slot}.machine")
        if problem is not None:
            raise problem
        accounts[slot] = account
    # 3. One account and one network for all the environment's VMs (D4).
    seen = [(str(m.account_id), str((m.network or {}).get("name") or "")) for m in existing]
    for slot in order:
        pair = (str(accounts[slot].id), str(wanted[slot].get("network") or ""))
        if seen and pair != seen[0]:
            raise CreateRefused(409, f"{env_name}'s VMs share one account and one network", f"hosts.{slot}.machine")
        seen.append(pair)
    account = accounts[order[0]]
    network = str(wanted[order[0]].get("network") or "")
    profile = vmnet.find_network((account.config or {}).get("networks") or [], network)
    if profile is None:
        raise CreateRefused(409, f"{account.name} has no network named {network}", f"hosts.{order[0]}.machine.network")
    # 4. The addresses: typed ones first, then the pool's lowest free ones in slot order.
    held = await machines.addresses_in_use(db, network=profile)
    given: dict[str, str] = {}
    addresses: dict[str, str] = {}
    for slot in order:
        typed = str(wanted[slot].get("address") or "auto").strip()
        if typed == "auto":
            continue
        field_name = f"hosts.{slot}.machine.address"
        try:
            address = vmnet.check_address(typed, profile)
        except ValueError as exc:
            raise CreateRefused(422, str(exc), field_name) from None
        if address in held:
            raise CreateRefused(409, f"{address} {held[address]}", field_name)
        if address in given:
            raise CreateRefused(409, f"{address} is given to both {given[address]} and {slot}: give each VM its own "
                                     "address", field_name)
        given[address], addresses[slot] = slot, address
    for slot in order:
        if slot in addresses:
            continue
        field_name = f"hosts.{slot}.machine.address"
        if not profile.get("pool"):
            raise CreateRefused(409, f"{network} has no address pool: type an address", field_name)
        try:
            address = vmnet.allocate(profile, lambda a: a in held or a in given)
        except ValueError:
            raise CreateRefused(409, f"{network} has no free address left in its pool", field_name) from None
        given[address], addresses[slot] = slot, address
    # 5. Sizes, and the names.
    out: dict[str, dict[str, Any]] = {}
    for slot in order:
        base = f"hosts.{slot}.machine"
        try:
            size = vmnet.check_size(wanted[slot].get("size") or {})
        except ValueError as exc:
            raise CreateRefused(422, str(exc), f"{base}.size") from None
        try:
            name = vmnet.check_vm_name(vmnet.vm_name(env_name, slot))
        except ValueError as exc:
            raise CreateRefused(422, str(exc), "name") from None
        clash = await _host_rules().name_clash(db, name)
        if clash:
            raise CreateRefused(409, clash, f"hosts.{slot}")
        acct = accounts[slot]
        host = _stand_in(env_name, slot, acct.provider, hostname=addresses[slot],
                         description=f"VM Slipway made for {env_name}'s {slot} slot on {acct.name}")
        out[slot] = {"provider": acct.provider, "account_id": acct.id, "account": acct.name, "account_row": acct,
                     "network": network, "profile": profile, "address": addresses[slot], "size": size, "name": name,
                     "host": host}
    return out


TESTED_WITHIN = 24 * 3600  # seconds: an older Test is named in the create's warnings


def vm_warnings(vms: Iterable[dict[str, Any]]) -> list[str]:
    """``?check=true``'s warnings for new VMs (P5 §9.2), from each account's last Test: an old (or no) Test, and
    less free storage than the new disks need. Never a refusal."""
    out: list[str] = []
    by_account: dict[uuid.UUID, tuple[ProviderAccount, int]] = {}
    for vm in vms:
        account = vm["account_row"]
        disk = int((vm.get("size") or {}).get("disk_gb") or 0)
        found = by_account.get(account.id)
        by_account[account.id] = (account, (found[1] if found else 0) + disk)
    now = utcnow()
    for account, disks in by_account.values():
        checked = account.last_checked_at
        if checked is not None and checked.tzinfo is None:
            checked = checked.replace(tzinfo=now.tzinfo)
        if checked is None:
            out.append(f"{account.name} hasn't been tested yet")
        elif (now - checked).total_seconds() > TESTED_WITHIN:
            out.append(f"{account.name} hasn't been tested since {checked:%Y-%m-%d %H:%M} UTC")
        free = (account.facts or {}).get("free_gb")
        storage = (account.config or {}).get("storage") or (account.config or {}).get("datastore") or "Its storage"
        if isinstance(free, (int, float)) and not isinstance(free, bool) and free < disks:
            out.append(f"{storage} has {free:g} GB free; the new disks need {disks} GB")
    return out


# What a DigitalOcean slot's plan is checked with before anything is made (P4 §15.1): placeholders for the managed
# objects' values and the load balancer's (the real ones come from do_provision.slot_values).
PLACEHOLDER_VALUE = "planned"
EDGE_PLACEHOLDERS = {"address": "192.0.2.1", "trusted": "10.10.0.0/16"}
_PLACEHOLDERS = {("postgres", "host"): "managed-database.invalid", ("postgres", "port"): "25060",
                 ("postgres", "tls"): "require", ("s3", "endpoint"): "https://spaces.invalid",
                 ("s3", "path_style"): "false"}


def managed_placeholders(man: manifest.Manifest) -> dict[str, dict[str, str]]:
    """``data_values`` for a create's check of a DigitalOcean slot: every field of every ``data.attach`` need."""
    attach = man.data.attach
    if attach is None:
        return {}
    return {need: {f: _PLACEHOLDERS.get((kind, f), PLACEHOLDER_VALUE) for f in manifest.ENDPOINT_FIELDS[kind]}
            for need, kind in attach.needs.items()}


@dataclass
class DoChoice:
    """What a DigitalOcean create (or Add slot, or grow) chose and was priced at (P4 §12): the account, the region
    and sizes, ``cloud.plan``, the fresh estimate and, when a figure was typed, the estimate the page showed (read
    from the catalog cache before the fresh read, so a moved price is told apart from a typing slip)."""

    account: ProviderAccount
    region: str
    droplet_size: str
    db_size: str
    db_nodes: int
    db_version: str
    acme_staging: bool
    slots: int
    plan: dict[str, Any]
    cost: Any  # do_rules.Cost
    shown: Any = None  # do_rules.Cost | None
    catalog: dict[str, Any] = field(default_factory=dict)

    def confirm_problem(self, typed: Any) -> CreateRefused | None:
        """§12.2: the typed figure must be the fresh total (422 otherwise); a figure that was the shown total
        when prices have moved since answers 409."""
        from slipway.services import do_rules

        figure = do_rules.parse_confirm(typed)
        if figure is not None and figure == self.cost.total:
            return None
        if figure is not None and self.shown is not None and figure == self.shown.total != self.cost.total:
            return CreateRefused(409, f"The estimate changed to ${self.cost.total} a month (DigitalOcean's prices "
                                      "moved): check it again", "confirm_cost")
        return CreateRefused(422, do_rules.confirm_problem(typed, self.cost) or "Type the total to confirm",
                             "confirm_cost")

    def cloud(self, user: User | None, *, base: dict[str, Any] | None = None) -> dict[str, Any]:
        """``environments.cloud`` with these sizes, the plan and the confirmed cost (§3.2)."""
        from slipway.services import do_rules

        stored = {"region": self.region, "droplet_image": do_rules.DROPLET_IMAGE, "acme_staging": self.acme_staging,
                  "vpc_range": None, "lb_ip": None, "edge": None, "slipway_addresses": [], "certificate": None,
                  **dict(base or {})}
        stored.update(droplet_size=self.droplet_size, db_size=self.db_size, db_nodes=self.db_nodes,
                      db_version=self.db_version, plan=dict(self.plan), cost=cost_record(self.cost, user))
        return stored

    def to_json(self, env_name: str) -> dict[str, Any]:
        """``plan.cloud`` of the ``?check=true`` answer (P4 §15.1): every object that will exist."""
        from slipway.services import do_rules

        sizes = {s["slug"]: s for s in self.catalog.get("sizes") or [] if s.get("slug")}
        droplet = sizes.get(self.droplet_size) or {}
        return {
            "account": {"id": str(self.account.id), "name": self.account.name}, "region": self.region,
            "plan": dict(self.plan),
            "droplets": [{"slot": s, "name": do_rules.droplet_name(env_name, s), "size": self.droplet_size,
                          "vcpus": droplet.get("vcpus"), "memory": droplet.get("memory"), "disk": droplet.get("disk")}
                         for s in APP_SLOTS[:self.slots]],
            "database": {"name": do_rules.database_name(env_name), "size": self.db_size, "nodes": self.db_nodes,
                         "version": self.db_version},
            "load_balancer": do_rules.lb_name(env_name), "vpc": do_rules.vpc_name(env_name),
            "firewall": do_rules.firewall_name(env_name), "bucket": True, "certificate": True,
            "acme_staging": self.acme_staging,
        }


def cost_record(cost: Any, user: User | None) -> dict[str, Any]:
    """``cloud.cost`` (§3.2): the confirmed estimate and who confirmed it."""
    return {"total_cents": cost.total_cents, "lines": [line.to_json() for line in cost.lines], "as_of": cost.as_of,
            "confirmed_by_id": str(user.id) if user is not None else None, "confirmed_at": utcnow().isoformat()}


async def _catalog(account: ProviderAccount, region: str, *, fresh: bool) -> dict[str, Any]:
    """The account's catalog; a refusal of the account or DigitalOcean's error answer as CreateRefused (502)."""
    from slipway.services import digitalocean

    pa = _provider_accounts()
    try:
        return await pa.catalog(account, region, fresh=fresh)
    except pa.AccountRefused as exc:
        raise CreateRefused(exc.status, exc.text, "placement.account_id") from exc
    except digitalocean.DigitalOceanError as exc:
        raise CreateRefused(502, f"Slipway couldn't read DigitalOcean's catalog for {account.name}: {exc}",
                            "placement") from exc


async def catalogs(account: ProviderAccount, region: str, *, typed: Any = None) -> tuple[dict[str, Any], Any]:
    """``(fresh catalog, cached catalog or None)`` (§12.2), read before any transaction locks a row. With a figure
    ``typed``, the catalog cache (what the page was shown) is read first, so a moved price can be told apart."""
    cached = None
    if typed is not None:
        try:
            cached = await _catalog(account, region, fresh=False)
        except CreateRefused:
            cached = None
    return await _catalog(account, region, fresh=True), cached


def estimate(account: ProviderAccount, plan: dict[str, Any], catalog: dict[str, Any] | None) -> Any:
    """``do_rules.cost`` of ``plan`` with the account's price layers (Decision 41); None for no catalog."""
    from slipway.services import do_rules

    if catalog is None:
        return None
    try:
        return do_rules.cost(plan, catalog, do_rules.price_layers((account.config or {}).get("prices"), None))
    except do_rules.DoRuleError as exc:
        raise CreateRefused(409, str(exc), "placement") from exc


def _shown(account: ProviderAccount, plan: dict[str, Any], cached: dict[str, Any] | None) -> Any:
    try:
        return estimate(account, plan, cached)
    except CreateRefused:
        return None


async def _limit_problem(db: AsyncSession, account: ProviderAccount, total_cents: int, *,
                         except_environment: uuid.UUID | None = None) -> None:
    """§12.2: the account's monthly limit against the stored totals of the environments using it."""
    from slipway.services import do_rules

    limit = (account.config or {}).get("monthly_limit_cents")
    if limit is None:
        return
    others = await _provider_accounts().estimate_cents(db, account.id, except_environment=except_environment)
    if others + total_cents > int(limit):
        raise CreateRefused(409, f"This would bring {account.name}'s estimate to ${do_rules.dollars(others + total_cents)} "
                                 f"a month, over its limit of ${do_rules.dollars(int(limit))}", "confirm_cost")


def _audit_cost(db: AsyncSession, env: Environment, cost: Any, user: User | None, *, typed: Any, request: Any,
                summary: str, deployment_id: uuid.UUID | None = None, **extra: Any) -> None:
    """``environment.cost_confirmed`` (P4 §4.2): the plan's lines and total, the figure typed, the deployment."""
    audit.record(db, "environment.cost_confirmed", actor=user, target=env, request=request, summary=summary,
                 details={"lines": [line.to_json() for line in cost.lines], "total": cost.total,
                          "total_cents": cost.total_cents, "as_of": cost.as_of, "typed": str(typed or ""),
                          "deployment": deployment_id.hex if deployment_id else None, **extra})


async def _production_holder(db: AsyncSession, repository_id: uuid.UUID, manifest_file: str, *,
                             besides: uuid.UUID | None = None) -> Environment | None:
    """The non-retiring production environment of an app (repository and manifest), if any (D20)."""
    stmt = select(Environment).where(Environment.repository_id == repository_id,
                                     Environment.manifest_file == manifest_file, Environment.production.is_(True),
                                     Environment.retiring_at.is_(None), Environment.deleted_at.is_(None))
    if besides is not None:
        stmt = stmt.where(Environment.id != besides)
    return await db.scalar(stmt.limit(1))


def production_taken_text(repo: str, path: str, other: str) -> str:
    return f"{repo}'s {path} already has a production environment, {other}; retire it first"


async def _do_choice(db: AsyncSession, req: NewEnvironment, placement: dict[str, Any], ctx: Any, *, repo: Repository,
                     branch: str, path: str, man: manifest.Manifest, caps: set[str], name: str,
                     hosts_in: dict[str, Any]) -> DoChoice:
    """Phase 4 §15.1 refusals 1-4 and §13's production rules, then the estimate (§12.2)."""
    from slipway.services import certs, do_provision, do_rules

    def no(status: int, detail: str, where: str | None) -> CreateRefused:
        return CreateRefused(status, detail, where)

    # 1. Spending money.
    if not ctx.can(Perm.PROVIDERS_SPEND):
        raise no(403, f"Creating a DigitalOcean environment needs the {Perm.PROVIDERS_SPEND} permission", "placement")
    if hosts_in:
        raise no(422, "A DigitalOcean environment makes its droplets: leave hosts out", "hosts")
    slots = int(placement.get("slots") or 1)
    production = bool(req.production)
    staging = bool(placement.get("acme_staging"))
    # 2. The account, and the production rules (§13).
    account = await _provider_accounts().get(db, _host_id(placement.get("account_id")))
    where = "placement.account_id"
    if account is None:
        raise no(422, "Unknown account", where)
    if account.provider != DIGITALOCEAN:
        label = _provider_accounts().label(account.provider)
        raise no(409, f"{account.name} is a {label} account: choose Hosts under Where", where)
    if account.removed_at is not None:
        raise no(409, f"{account.name} was removed: add the account again first", where)
    if not account.secret:
        raise no(409, f"Slipway can't read {account.name}'s token any more: enter it again", where)
    if not (account.config or {}).get("ssh_sources"):
        raise no(409, f"{account.name} has no SSH sources: set the addresses Slipway connects from on the account "
                      "first", where)
    if production and not account.production:
        raise no(409, f"{account.name} isn't a production account: a production environment needs one", where)
    if not production and account.production:
        raise no(409, f"{account.name} is for production environments", where)
    if production and slots != 2:
        raise no(409, "Production runs Blue and Green", "placement.slots")
    try:
        certs.check_staging(production, staging)
    except certs.CertError as exc:
        raise no(409, str(exc), "placement.acme_staging") from exc
    if production:
        other = await _production_holder(db, repo.id, path)
        if other is not None:
            raise no(409, production_taken_text(repo.full_name, path, other.name), "production")
    # 3. The manifest says how it runs there.
    if "digitalocean" not in caps:
        raise no(409, f"{repo.full_name}'s slipway.yml at {branch} doesn't say how it runs on managed data behind a "
                      "load balancer (data.managed and edge)", "placement")
    if slots == 2 and "bluegreen" not in caps:
        raise no(409, f"{repo.full_name}'s slipway.yml at {branch} doesn't declare data.migrations: expand_contract. "
                      "With two slots, blue keeps running on the database green migrates, so its migrations must add "
                      "before they remove.", "placement.slots")
    need = do_provision.postgres_need(man)
    if need is None or man.data.managed is None:
        raise no(409, f"{repo.full_name}'s slipway.yml at {branch} has no managed PostgreSQL database "
                      "(data.managed), which a DigitalOcean environment's cluster is", "placement")
    version = str(man.data.managed.needs[need].get("version") or "")
    # 4. The catalog, read live (uncached) before anything is locked.
    region = str(placement.get("region") or (account.config or {}).get("region") or "")
    if not region:
        raise no(422, "Choose a region", "placement.region")
    nodes = 2 if placement.get("db_standby") else 1
    droplet_size, db_size = str(placement.get("droplet_size") or ""), str(placement.get("db_size") or "")
    try:
        plan = do_rules.make_plan(droplets=slots, droplet_size=droplet_size, db_size=db_size, db_nodes=nodes,
                                  db_version=version)
    except do_rules.DoRuleError as exc:
        raise no(422, str(exc), "placement") from exc
    catalog, cached = await catalogs(account, region, typed=req.confirm_cost)
    for problem, where in ((do_rules.region_problem(catalog), "placement.region"),
                           (do_rules.droplet_size_problem(droplet_size, catalog), "placement.droplet_size"),
                           (do_rules.database_size_problem(db_size, nodes, catalog), "placement.db_size"),
                           (do_rules.db_version_problem(version, catalog), "placement")):
        if problem:
            raise no(409, problem, where)
    cost, shown = estimate(account, plan, catalog), _shown(account, plan, cached)
    return DoChoice(account=account, region=region, droplet_size=droplet_size, db_size=db_size, db_nodes=nodes,
                    db_version=version, acme_staging=staging, slots=slots, plan=plan, cost=cost, shown=shown,
                    catalog=catalog)


async def validate_create(db: AsyncSession, request: Any, ctx: Any, *, read_file: ReadFile | None = None) -> CreatePlan:
    """Check a new environment against §9.1's refusals, in its order, before anything is written; raise
    CreateRefused with the first one. ``ctx`` is the caller's AuthContext (``can``, ``user``). ``read_file``
    reads a file of the repository at a branch (tests pass a fake; default GitHub). Writes nothing.

    Placement ``digitalocean`` (phase 4 §15.1) adds its refusals 1-8 after the name and the repository, and reads
    the account's catalog uncached (no row is locked meanwhile; ``create`` locks the account and compares only
    stored values). A ``machine`` under ``hosts.<slot>`` (phase 5 §9.2) adds refusals 0-5 at the hosts step.
    Both validate on unsaved stand-in hosts from ``hosts.planned_host`` (Decision 24)."""
    from slipway.services import cloudflare, deployer, switchyard

    req = NewEnvironment.of(request)
    read = read_file or github_reader(getattr(ctx, "user", None))
    placement = dict(req.placement or {})
    on_do = placement.get("provider") == DIGITALOCEAN

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

    caps = set(man.capabilities())
    hosts_in = {str(k): v for k, v in (req.hosts or {}).items() if v}
    unknown = sorted(set(hosts_in) - set(SLOTS))
    if unknown:
        raise no(422, f"There is no slot {unknown[0]}: the slots are blue, green and data", "hosts")
    if placement and not on_do:
        raise no(422, "Choose where the environment runs: on hosts, or on DigitalOcean", "placement")
    if req.production and not on_do:
        raise no(409, "Only a DigitalOcean environment can be a production environment", "production")
    hosts: dict[str, Host] = {}
    planned: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    do: DoChoice | None = None
    if on_do:
        # Phase 4 §15.1 refusals 1-4 (the account, the manifest's capability, the catalog), and §13's
        # production rules. The data is always managed (D21).
        do = await _do_choice(db, req, placement, ctx, repo=repo, branch=branch, path=path, man=man, caps=caps,
                              name=name, hosts_in=hosts_in)
        data_mode = DataMode.MANAGED
        two = do.slots == 2
        for slot in APP_SLOTS[:do.slots]:
            host = _stand_in(name, slot, DIGITALOCEAN, description=f"Droplet Slipway makes for {name}'s {slot} slot")
            hosts[slot] = host
            planned[slot] = {"provider": DIGITALOCEAN, "name": host.name}
    else:
        # 3. The shape: two app slots need a data server and expand/contract migrations (D7); mode server a data
        # server.
        data_mode = req.data_mode
        if data_mode == DataMode.MANAGED:
            raise no(422, "Managed data comes only with DigitalOcean placement: choose DigitalOcean under Where",
                     "data_mode")
        if data_mode not in (DataMode.SLOT, DataMode.SERVER):
            raise no(422, "Choose where the data is kept: in the slot, or on a server of its own", "data_mode")
        two = "green" in hosts_in
        if two and data_mode == DataMode.SLOT:
            raise no(409, f"{name} would keep its data on blue; a second slot needs a data server", "data_mode")
        if (two or data_mode == DataMode.SERVER) and "server" not in caps:
            raise no(409, f"{repo.full_name}'s slipway.yml doesn't describe a data server (data.server), so Slipway "
                          "can't run two slots on one set of data" if two else
                     f"{repo.full_name}'s slipway.yml doesn't describe a data server (data.server), so Slipway can't "
                     "keep its data on a server of its own", "data_mode")
        if two and "bluegreen" not in caps:
            raise no(409, f"{repo.full_name}'s slipway.yml at {branch} doesn't declare data.migrations: "
                          "expand_contract. With two slots, blue keeps running on the database green migrates, so "
                          "its migrations must add before they remove.", "data_mode")

        # 4. The hosts: a host id (P3's rules, and phase 5's refusal 0), or a new VM (phase 5 §9.2).
        if "blue" not in hosts_in:
            raise no(422, "Choose a host for blue", "hosts.blue")
        if data_mode == DataMode.SERVER and DATA_SLOT not in hosts_in:
            raise no(422, "Choose a host for the data server", "hosts.data")
        if data_mode == DataMode.SLOT and DATA_SLOT in hosts_in:
            raise no(422, f"{name} keeps its data in blue, so it has no data server", "hosts.data")
        wanted_vms: dict[str, dict[str, Any]] = {}
        for slot in SLOTS:
            if slot not in hosts_in:
                continue
            spec = machine_spec(hosts_in[slot])
            if spec is not None:
                wanted_vms[slot] = spec
                continue
            host = await db.get(Host, _host_id(hosts_in[slot]))
            if host is None:
                raise no(422, "Unknown host", f"hosts.{slot}")
            problem = await _owned_problem(db, host, "environment")
            if problem:
                raise no(409, problem, f"hosts.{slot}")
            if not host.is_pinned:
                raise no(409, UNPINNED.format(host=host.name), f"hosts.{slot}")
            problem = await slot_folder_problem(db, name, slot, host)
            if problem:
                raise no(409, problem, f"hosts.{slot}")
            hosts[slot] = host
        if wanted_vms:
            vms = await plan_vms(db, name, wanted_vms, ctx)
            for slot, vm in vms.items():
                hosts[slot] = vm.pop("host")
                planned[slot] = vm
            warnings += vm_warnings(vms.values())
        hosts = {slot: hosts[slot] for slot in SLOTS if slot in hosts}
        probe = Environment(name=name, data_mode=data_mode)
        if data_mode == DataMode.SERVER:
            for slot in APP_SLOTS:
                if slot in hosts:
                    problem = address_problem(probe, hosts[slot])
                    if problem:
                        raise no(409, problem, f"hosts.{slot}")
            if any(hosts[DATA_SLOT] is hosts[s] or (hosts[DATA_SLOT].id == hosts[s].id) for s in APP_SLOTS if s in hosts):
                raise no(409, f"The data server needs a host of its own: a container on {hosts[DATA_SLOT].name} reaches "
                              f"its database from a Docker address, which {name}'s data server can't let in by host "
                              "address", "hosts.data")
        if two and hosts["blue"].id == hosts["green"].id:
            warnings.append(f"Blue and green both run on {hosts['blue'].name}: a problem with that host stops both, "
                            "and Switch back can't help with it")

    # 5. Settings: plan in each role with placeholder ports (this also catches clashing variables).
    env_vars = {str(k): str(v) for k, v in (req.env or {}).items()}
    settings = {str(k): str(v) for k, v in (req.settings or {}).items()}
    known = {s.name for s in man.optional_services}
    if req.services is not None:
        wrong = sorted(set(req.services) - known)
        if wrong:
            raise no(422, f"{wrong[0]} isn't an optional service of {path}", "services")
    secrets = manifest.new_secrets(man, {})
    if on_do:
        roles = ["slot"]
    else:
        roles = ["app"] if data_mode == DataMode.SLOT else ["server", "slot"]
    plans: dict[str, manifest.AppPlan] = {}
    for role in roles:
        try:
            manifest.check_instance_env(man, env_vars, role, managed=on_do, edge=on_do)
        except manifest.ManifestError as exc:
            raise no(422, str(exc).replace("the instance's environment variables", "the environment's variables"),
                     "env") from exc
        slot = DATA_SLOT if role == "server" else "blue"
        extra: dict[str, Any] = {}
        if on_do:
            extra = {"data_values": managed_placeholders(man), "managed": True, "edge_values": dict(EDGE_PLACEHOLDERS)}
        elif role == "slot":
            extra = {"data_values": plans["server"].provides}
        elif role == "server":
            extra = {"server_values": {"host": hosts[DATA_SLOT].upstream_address,
                                       "clients": [hosts[s].client_address for s in APP_SLOTS if s in hosts]}}
        try:
            plans[role] = manifest.plan(
                man, template=template, builtins=_placeholder_builtins(name, slot, hosts[slot]), settings=settings,
                chosen=req.services, host_ports={}, secrets=secrets, env=env_vars, role=role, **extra)
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

    # 7. Traffic. It follows placement (Decision 24): do_lb only with placement digitalocean, and placement
    # digitalocean only with do_lb, which always publishes its names through Cloudflare (P4 D21).
    wanted = dict(req.traffic or {})
    switch = str(wanted.get("switch") or "none")
    if switch not in SWITCHES:
        raise no(422, f"{switch} isn't a way to switch traffic (use none, switchyard or do_lb)", "traffic")
    if on_do and switch != DO_LB:
        raise no(409, DO_NEEDS_LB, "traffic.switch")
    if switch == DO_LB and not on_do:
        raise no(409, LB_NEEDS_DO, "traffic.switch")
    if switch == "switchyard" and await switchyard.load_config(db) is None:
        raise no(409, SET_UP_SWITCHYARD, "traffic")
    if two and switch not in ("switchyard", DO_LB):
        raise no(409, BLUE_GREEN_SWITCH, "traffic")
    dns_in = wanted.get("dns")
    if on_do and not isinstance(dns_in, dict):
        dns_in = {}
    dns = None
    if isinstance(dns_in, dict):  # {} turns DNS publishing on with the integration's defaults
        config = await cloudflare.load_config(db)
        if config is None:
            raise no(409, SET_UP_CLOUDFLARE, "traffic.dns")
        try:
            address = cloudflare.clean_public_ip((dns_in or {}).get("address"))
        except ValueError as exc:
            raise no(422, str(exc), "traffic.dns") from exc
        if on_do and address is not None:
            raise no(422, "A DigitalOcean environment's records point at its load balancer, whose address Slipway "
                          "writes: leave the address empty", "traffic.dns")
        if address is None and not config.public_ip and not on_do:
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
    if req.auto_activate and req.production:
        raise no(409, "A production environment waits for Activate: turn Activate automatically off", "auto_activate")
    if req.keep_backups is not None and not 1 <= int(req.keep_backups) <= 100:
        raise no(422, "Keep 1 to 100 backups", "keep_backups")

    # Phase 4 §15.1 refusals 6 and 8: the droplets' host names, then the cost and the account's limit.
    if do is not None:
        for slot in APP_SLOTS[:do.slots]:
            clash = await _host_rules().name_clash(db, hosts[slot].name)
            if clash:
                raise no(409, clash, "name")
        await _limit_problem(db, do.account, do.cost.total_cents)

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
    req.data_mode = data_mode
    return CreatePlan(request=req, repo=repo, branch=branch, path=path, man=man, template=template, hosts=hosts,
                      secrets=secrets, hostnames=hostnames, traffic=traffic, route_tls=route_tls, warnings=warnings,
                      seed=seed, planned=planned, do=do)


async def create(db: AsyncSession, plan: CreatePlan, ctx: Any, *, request: Any = None) -> Environment:
    """Write what ``validate_create`` checked, in the caller's transaction (it commits): the environment (status
    ``new``, its secrets, its names), its instances (status CREATED), the data owner's phase 2 fields and
    ``FirstAdmin`` row, and the audit row (never a secret). No host is touched (§9.1).

    Placement ``digitalocean`` (P4 §15.1): first the typed cost (422, or 409 when the estimate moved since it was
    shown), then the account row ``FOR UPDATE`` and its limit against the stored totals (no HTTP call here); the
    environment with its ``cloud`` (sizes, plan, cost), the planned droplet hosts, the slot instances on them and
    the host-less data owner (the only writer of one, and only for ``managed``); audit ``environment.create`` and
    ``environment.cost_confirmed``. New VMs (P5 §9.2): ``machines.plan`` per VM in the same transaction. A
    claim another create took meanwhile fails the flush: the transaction is rolled back, nothing is written, and
    CreateRefused 409 names the address (Decision 43)."""
    from slipway.services import machines

    req, user = plan.request, ctx.user
    name = req.name.strip()
    do = plan.do
    if do is not None:
        problem = do.confirm_problem(req.confirm_cost)
        if problem is not None:
            raise problem
        account = await _provider_accounts().get(db, do.account.id, lock=True)
        if account is None or account.removed_at is not None:
            raise CreateRefused(409, f"{do.account.name} was removed", "placement.account_id")
        await _limit_problem(db, account, do.cost.total_cents)
    env = Environment(
        id=uuid.uuid4(), name=name, repository_id=plan.repo.id, branch=plan.branch, manifest_file=plan.path,
        data_mode=req.data_mode, app_settings=dict(req.settings or {}), app_services=req.services,
        app_secrets=dict(plan.secrets), secrets_version=0, env=dict(req.env or {}), route_tls=dict(plan.route_tls),
        hostnames=list(plan.hostnames), auto_activate=bool(req.auto_activate), traffic=dict(plan.traffic),
        traffic_state={}, status=EnvironmentStatus.NEW, created_by_id=user.id if user else None,
    )
    if do is not None:
        env.provider, env.provider_account_id, env.production = DIGITALOCEAN, do.account.id, bool(req.production)
        env.cloud = do.cloud(user)
    db.add(env)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        if "one_production" in str(exc.orig):  # ux_environments_one_production: another production took the app
            raise CreateRefused(409, f"{plan.repo.full_name}'s {plan.path} already has a production environment; "
                                     "retire it first", "production") from exc
        raise CreateRefused(409, f"An environment named {name} already exists", "name") from exc  # ux_..._name_live
    slots: dict[str, Instance] = {}
    vms: dict[str, dict[str, Any]] = {}
    for slot, host in plan.hosts.items():
        made = plan.planned.get(slot)
        host_id = host.id
        if made is not None and made["provider"] == DIGITALOCEAN:
            host.owner_environment_id = env.id
            host.created_by_id = user.id if user else None
            db.add(host)
        elif made is not None:
            account = await db.get(ProviderAccount, made["account_id"])
            try:
                row, _machine = await machines.plan(db, env, slot, account, made["network"], made["address"],
                                                    made["size"], user)
            except machines.PlanProblem as exc:
                await db.rollback()
                raise CreateRefused(409, exc.text, exc.field) from exc
            host_id = row.id
            vms[slot] = {"account": made["account"], "network": made["network"], "address": made["address"],
                         "size": made["size"]}
        inst = Instance(
            name=f"{name} {slot}", slug=f"{name}-{slot}", repository_id=plan.repo.id, host_id=host_id,
            branch=plan.branch, build_source=BuildSource.APP, manifest_file=plan.path, deploy_dir=None,
            environment_id=env.id, slot=slot, slot_state={}, status=InstanceStatus.CREATED,
            created_by_id=user.id if user else None,
        )
        slots[slot] = inst
        db.add(inst)
    if do is not None:
        # The managed data owner has no host (P4 §3.4): its commands run on the data runner.
        slots[DATA_SLOT] = Instance(
            name=f"{name} data", slug=f"{name}-data", repository_id=plan.repo.id, host_id=None, branch=plan.branch,
            build_source=BuildSource.APP, manifest_file=plan.path, deploy_dir=None, environment_id=env.id,
            slot=DATA_SLOT, slot_state={}, status=InstanceStatus.CREATED, created_by_id=user.id if user else None,
        )
        db.add(slots[DATA_SLOT])
    owner = slots[owner_slot(env)]
    owner.keep_backups = req.keep_backups or 5
    owner.seed_snapshot_id = plan.seed.id if plan.seed is not None else None
    owner.seed_content = True if req.seed_content is None else bool(req.seed_content)
    await _flush_claims(db, vms)
    admin = req.first_admin
    if admin is not None:
        db.add(FirstAdmin(instance_id=owner.id, fields=dict(admin.fields), mode=admin.mode,
                          password=admin.password if admin.mode == "password" else None,
                          status=FirstAdminStatus.PENDING, existed=False, created_by_id=user.id if user else None))
    emails = [v for v in dict(admin.fields).values() if isinstance(v, str) and "@" in v] if admin is not None else []
    details: dict[str, Any] = {
        "name": name, "repository": plan.repo.full_name, "branch": plan.branch, "data_mode": req.data_mode,
        "slots": {s: h.name for s, h in plan.hosts.items()}, "traffic": plan.traffic,
        "seed_snapshot": plan.seed.name if plan.seed is not None else None,
        "first_admin": emails[0] if emails else None, "secrets": sorted(plan.secrets),
    }
    if vms:
        details["machines"] = vms
    if do is not None:
        details.update(provider=DIGITALOCEAN, account=do.account.name, production=bool(req.production),
                       cloud={"region": do.region, "droplet_size": do.droplet_size, "db_size": do.db_size,
                              "db_nodes": do.db_nodes, "db_version": do.db_version, "acme_staging": do.acme_staging})
    audit.record(
        db, "environment.create", actor=user, target=env, request=request,
        summary=f"Created environment {name} ({plan.repo.full_name}@{plan.branch})", details=details,
    )
    if do is not None:
        _audit_cost(db, env, do.cost, user, typed=req.confirm_cost, request=request,
                    summary=f"Confirmed about ${do.cost.total} a month for {name} on {do.account.name}")
    await db.flush()
    return env


async def _flush_claims(db: AsyncSession, vms: dict[str, dict[str, Any]]) -> None:
    """Flush the new rows; an address claim another create took meanwhile (the claim's primary key) rolls the
    transaction back and answers 409 naming it (Decision 43). Every other database error is the caller's."""
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        taken = await claim_conflict(db, exc, {s: str(v["address"]) for s, v in vms.items()})
        if taken is not None:
            raise taken from exc
        raise


_CLAIM_KEY = re.compile(r"Key \(address\)=\(([^)]*)\)")


async def claim_conflict(db: AsyncSession, exc: IntegrityError,
                         vms: dict[str, str]) -> CreateRefused | None:
    """Decision 43's 409 for an ``address_claims`` conflict, naming the planned address that was taken and its
    field, or None when the error is something else. Call it after the rollback. PostgreSQL's detail names the
    address (``Key (address)=(10.0.0.12)``), matched exactly; when it doesn't (SQLite names only the column),
    the claims are read again, and the first planned address another environment now holds is the one. asyncpg
    keeps the detail apart from the message (``exc.orig.detail``), so both are read."""
    text = f"{exc.orig}\n{getattr(exc.orig, 'detail', None) or ''}"
    if not vms or "address_claims" not in text:
        return None
    found = _CLAIM_KEY.search(text)
    named = found.group(1).strip() if found else None
    slot = next((s for s, a in vms.items() if a == named), None)
    if slot is None:
        from slipway.models import AddressClaim

        held = set(await db.scalars(select(AddressClaim.address).where(AddressClaim.address.in_(list(vms.values())))))
        slot = next((s for s, a in vms.items() if a in held), next(iter(vms)))
    return CreateRefused(409, CLAIM_TAKEN.format(address=vms[slot]), f"hosts.{slot}.machine.address")


# ------------------------------------------------------- Add slot (P3 §9.8, P4 §15.5, P5 §9.5)


@dataclass
class SlotPlan:
    """What ``add_slot_plan`` checked, ready for ``add_slot``: the new slot, its host (a host added by hand, or an
    unsaved stand-in for a droplet or a VM Slipway makes), and on DigitalOcean the new plan and its estimate."""

    env: Environment
    slot: str
    host: Host
    planned: dict[str, Any] | None = None  # the droplet's or the VM's, as validate_create's ``planned``
    do: DoChoice | None = None
    old_cents: int = 0
    shared: Instance | None = None  # the app slot already on the same host
    update_data_server: bool = False
    confirm_cost: Any = None

    def to_json(self) -> dict[str, Any]:
        from slipway.services import do_rules

        out: dict[str, Any] = {"slot": self.slot, "host_id": None if self.planned else str(self.host.id),
                               "host": self.host.name, "planned": (self.planned or {}).get("provider")}
        if self.planned and self.planned.get("provider") != DIGITALOCEAN:
            out["machine"] = {k: self.planned[k] for k in ("name", "account", "network", "address", "size")}
        if self.do is not None:
            out["cost"] = {**self.do.cost.to_json(), "delta": do_rules.delta_text(self.old_cents,
                                                                                  self.do.cost.total_cents)}
        return out


def _cloud(env: Environment) -> dict[str, Any]:
    return dict(env.cloud or {})


async def _env_account(db: AsyncSession, env: Environment, where: str) -> ProviderAccount:
    account = await _provider_accounts().get(db, env.provider_account_id) if env.provider_account_id else None
    if account is None or account.removed_at is not None:
        raise CreateRefused(409, f"{env.name}'s DigitalOcean account was removed", where)
    if not account.secret:
        raise CreateRefused(409, f"Slipway can't read {account.name}'s token any more: enter it again", where)
    return account


def _resize_choice(env: Environment, account: ProviderAccount, *, droplets: int | None = None,
                   droplet_size: str | None = None, db_size: str | None = None,
                   db_nodes: int | None = None) -> DoChoice:
    """The environment's stored choice with some of it changed (Add slot, grow), unpriced."""
    from slipway.services import do_rules

    cloud = _cloud(env)
    plan = dict(cloud.get("plan") or {})
    sizes = {"droplets": droplets or int(plan.get("droplets") or 1),
             "droplet_size": droplet_size or str(cloud.get("droplet_size") or plan.get("droplet_size") or ""),
             "db_size": db_size or str(cloud.get("db_size") or plan.get("db_size") or ""),
             "db_nodes": db_nodes or int(cloud.get("db_nodes") or plan.get("db_nodes") or 1),
             "db_version": str(cloud.get("db_version") or plan.get("db_version") or "")}
    try:
        new_plan = do_rules.make_plan(**sizes)
    except do_rules.DoRuleError as exc:
        raise CreateRefused(422, str(exc), "cloud") from exc
    return DoChoice(account=account, region=str(cloud.get("region") or ""), droplet_size=sizes["droplet_size"],
                    db_size=sizes["db_size"], db_nodes=sizes["db_nodes"], db_version=sizes["db_version"],
                    acme_staging=bool(cloud.get("acme_staging")), slots=sizes["droplets"], plan=new_plan,
                    cost=None)


async def add_slot_plan(db: AsyncSession, env: Environment, body: Any, ctx: Any, *,
                        read_file: ReadFile | None = None) -> SlotPlan:
    """Check Add slot (Decision 25) for every placement; raise CreateRefused with the first refusal, before
    anything is written. ``body`` is ``SlotAdd`` (or a dict): on SSH placement exactly one of ``host_id`` (P3
    §9.8, and phase 5 refusal 0: no host another environment, or this one, made) and ``machine`` (P5 §9.5: the
    account and network of the environment's other VMs); on DigitalOcean neither, ``providers:spend`` and the new
    total, priced from the catalog read here, before any transaction locks a row (P4 §15.5, §12.2).
    ``read_file`` reads slipway.yml at the branch (default GitHub)."""
    from slipway.services import jobs  # jobs imports this module

    raw = body.model_dump() if hasattr(body, "model_dump") else dict(body or {})
    host_id, machine = raw.get("host_id"), raw.get("machine")

    def no(status: int, detail: str, where: str | None = None) -> CreateRefused:
        return CreateRefused(status, detail, where)

    gone = deleting_text(env)
    if gone:
        raise no(409, gone)
    mem = await members(db, env)
    apps = app_members(mem)
    if env.data_mode == DataMode.SLOT:
        raise no(409, f"{env.name} keeps its data on {apps[0].slot if apps else 'blue'}; a second slot needs a data "
                      "server")
    if len(apps) >= 2:
        raise no(409, f"{env.name} already has two slots")
    problem = await two_slot_traffic_problem(db, env)
    if problem:
        raise no(409, problem)
    slot = next(s for s in APP_SLOTS if s not in mem)
    on_do = is_digitalocean(env)
    planned: dict[str, Any] | None = None
    host: Host | None = None
    if on_do:
        if not ctx.can(Perm.PROVIDERS_SPEND):
            raise no(403, f"Adding a droplet needs the {Perm.PROVIDERS_SPEND} permission")
        if host_id or machine:
            raise no(422, f"A DigitalOcean environment makes its droplets: leave out the host for {slot}", "host_id")
        host = _stand_in(env.name, slot, DIGITALOCEAN, description=f"Droplet Slipway makes for {env.name}'s {slot} slot")
        clash = await _host_rules().name_clash(db, host.name)
        if clash:
            raise no(409, clash, f"hosts.{slot}")
        planned = {"provider": DIGITALOCEAN, "name": host.name}
    else:
        if bool(host_id) == bool(machine):
            raise no(422, f"Choose a host for {slot}, or a new VM", "host_id")
        if machine:
            spec = machine_spec({"machine": machine})
            assert spec is not None
            vms = await plan_vms(db, env.name, {slot: spec}, ctx, existing=await env_machines(db, env))
            planned = vms[slot]
            host = planned.pop("host")
        else:
            host = await db.get(Host, _host_id(host_id))
            if host is None:
                raise no(422, "Unknown host", "host_id")
            problem = await _owned_problem(db, host, "add_slot")
            if problem:
                raise no(409, problem, "host_id")
            if not host.is_pinned:
                raise no(409, UNPINNED.format(host=host.name), "host_id")
    assert host is not None
    if env.data_mode == DataMode.SERVER:
        problem = address_problem(env, host)
        if problem:
            raise no(409, problem, f"hosts.{slot}")
        data_member = mem.get(DATA_SLOT)
        if data_member is not None and data_member.host_id is not None and data_member.host_id == host.id:
            raise no(409, f"The data server needs a host of its own: a container on {host.name} reaches its database "
                          f"from a Docker address, which {env.name}'s data server can't let in by host address",
                     f"hosts.{slot}")
    slug = env.slot_slug(slot)
    holder = await db.scalar(select(Instance.name).where(Instance.slug == slug))
    if holder is not None:
        raise no(409, f"Instance {holder} already uses the slug {slug}")
    if planned is None:
        problem = await slot_folder_problem(db, env.name, slot, host)
        if problem:
            raise no(409, problem, f"hosts.{slot}")
    busy = await jobs.busy_job(db, env, data.env_keys(env.id, None))
    if busy is not None:
        raise no(409, busy_text(env, busy))
    man = await _branch_manifest(env, read_file or github_reader(getattr(ctx, "user", None)))
    if "bluegreen" not in set(man.capabilities()):
        raise no(409, f"{env.repository.full_name}'s slipway.yml at {env.branch} doesn't declare data.migrations: "
                      f"expand_contract. With two slots, {apps[0].slot if apps else 'blue'} keeps running on the "
                      f"database {slot} migrates, so its migrations must add before they remove.")
    out = SlotPlan(env=env, slot=slot, host=host, planned=planned,
                   shared=next((m for m in apps if planned is None and m.host_id == host.id), None),
                   update_data_server=bool(raw.get("update_data_server")), confirm_cost=raw.get("confirm_cost"))
    if on_do:
        account = await _env_account(db, env, "confirm_cost")
        choice = _resize_choice(env, account, droplets=2)
        catalog, cached = await catalogs(account, choice.region, typed=out.confirm_cost)
        choice.cost, choice.shown, choice.catalog = estimate(account, choice.plan, catalog), \
            _shown(account, choice.plan, cached), catalog
        out.do, out.old_cents = choice, int((_cloud(env).get("cost") or {}).get("total_cents") or 0)
        await _limit_problem(db, account, choice.cost.total_cents, except_environment=env.id)
    return out


async def _branch_manifest(env: Environment, read: ReadFile) -> manifest.Manifest:
    from slipway.services.github import GitHubError

    repo, branch, path = env.repository, env.branch, env.manifest_file or manifest.DEFAULT_FILE
    try:
        text = await read(repo, branch, path)
    except GitHubError as exc:
        raise CreateRefused(502, f"Could not read {path} on {branch} of {repo.full_name}: {exc}", "branch") from exc
    if text is None:
        raise CreateRefused(409, f"{repo.full_name} has no {path} at {branch}", "manifest_file")
    try:
        return manifest.parse(text)
    except manifest.ManifestError as exc:
        raise CreateRefused(409, str(exc), "manifest_file") from exc


async def add_slot(db: AsyncSession, plan: SlotPlan, ctx: Any, *, request: Any = None) -> Instance:
    """Write what ``add_slot_plan`` checked, in the caller's transaction (the API holds the environment's runner
    keys and commits): the slot instance on its host. On DigitalOcean first the typed total (422, or 409 when the
    estimate moved) and the account's limit under ``FOR UPDATE``, then the planned droplet host, ``plan.droplets
    = 2`` and the new cost (audit ``environment.cost_confirmed``); a new VM through ``machines.plan``. Audit
    ``environment.slot_add``."""
    from slipway.services import machines

    env, slot, user = plan.env, plan.slot, ctx.user
    host_id = plan.host.id
    vms: dict[str, dict[str, Any]] = {}
    if plan.do is not None:
        problem = plan.do.confirm_problem(plan.confirm_cost)
        if problem is not None:
            raise problem
        account = await _provider_accounts().get(db, plan.do.account.id, lock=True)
        if account is None or account.removed_at is not None:
            raise CreateRefused(409, f"{plan.do.account.name} was removed", "confirm_cost")
        await _limit_problem(db, account, plan.do.cost.total_cents, except_environment=env.id)
        plan.host.owner_environment_id = env.id
        plan.host.created_by_id = user.id if user else None
        db.add(plan.host)
        env.cloud = plan.do.cloud(user, base=_cloud(env))
    elif plan.planned is not None:
        account = await db.get(ProviderAccount, plan.planned["account_id"])
        try:
            row, _machine = await machines.plan(db, env, slot, account, plan.planned["network"],
                                                plan.planned["address"], plan.planned["size"], user)
        except machines.PlanProblem as exc:
            await db.rollback()
            raise CreateRefused(409, exc.text, exc.field) from exc
        host_id = row.id
        vms[slot] = {k: plan.planned[k] for k in ("account", "network", "address", "size")}
    inst = Instance(
        name=f"{env.name} {slot}", slug=env.slot_slug(slot), repository_id=env.repository_id, host_id=host_id,
        branch=env.branch, build_source=BuildSource.APP, manifest_file=env.manifest_file, deploy_dir=None,
        environment_id=env.id, slot=slot, slot_state={}, status=InstanceStatus.CREATED,
        created_by_id=user.id if user else None,
    )
    db.add(inst)
    await _flush_claims(db, vms)
    details: dict[str, Any] = {"slot": slot, "host": plan.host.name, "update_data_server": plan.update_data_server}
    if vms:
        details["machine"] = vms[slot]
    if plan.do is not None:
        details["droplet"] = plan.host.name
    audit.record(db, "environment.slot_add", actor=user, target=env, request=request,
                 summary=f"Added {slot} to {env.name} on {plan.host.name}", details=details)
    if plan.do is not None:
        from slipway.services import do_rules

        _audit_cost(db, env, plan.do.cost, user, typed=plan.confirm_cost, request=request,
                    summary=f"Confirmed about ${plan.do.cost.total} a month for {env.name} with {slot}",
                    delta=do_rules.delta_text(plan.old_cents, plan.do.cost.total_cents))
    await db.flush()
    return inst


# -------------------------------------------------------------- grow sizes (P4 §15.7)

RESIZE_PENDING = "Resize pending: applies at {slot}'s next deploy"


@dataclass
class GrowPlan:
    """A confirmed-to-be grow of a DigitalOcean environment's sizes: the old and new sizes and estimates."""

    env: Environment
    old: dict[str, Any]
    new: dict[str, Any]
    do: DoChoice
    old_cents: int
    confirm_cost: Any = None

    def to_json(self) -> dict[str, Any]:
        from slipway.services import do_rules

        return {"from": self.old, "to": self.new,
                "cost": {**self.do.cost.to_json(), "delta": do_rules.delta_text(self.old_cents,
                                                                                self.do.cost.total_cents)}}


def _sizes_of(cloud: dict[str, Any]) -> dict[str, Any]:
    return {"droplet_size": cloud.get("droplet_size"), "db_size": cloud.get("db_size"),
            "db_nodes": int(cloud.get("db_nodes") or 1)}


async def grow_plan(db: AsyncSession, env: Environment, sizes: Any, ctx: Any, *,
                    confirm_cost: Any = None) -> GrowPlan:
    """P4 §15.7: check a grow of a DigitalOcean environment's sizes (``CloudSizesIn`` or a dict of
    ``droplet_size``, ``db_size``, ``db_standby``) against the catalog read live here, before any row is locked;
    raise CreateRefused. Sizes only grow and a standby is only added; refused while a job runs or the environment
    retires."""
    from slipway.services import do_rules, jobs

    raw = sizes.model_dump() if hasattr(sizes, "model_dump") else dict(sizes or {})
    if not is_digitalocean(env):
        raise CreateRefused(409, f"{env.name} isn't on DigitalOcean: its sizes are its hosts'", "cloud")
    gone = deleting_text(env)
    if gone:
        raise CreateRefused(409, gone, "cloud")
    if not ctx.can(Perm.PROVIDERS_SPEND):
        raise CreateRefused(403, f"Growing {env.name}'s sizes needs the {Perm.PROVIDERS_SPEND} permission", "cloud")
    if env.retiring_at is not None:
        raise CreateRefused(409, f"{env.name} is retiring: its sizes stay as they are", "cloud")
    busy = await jobs.busy_job(db, env, data.env_keys(env.id, None))
    if busy is not None:
        raise CreateRefused(409, busy_text(env, busy), "cloud")
    cloud = _cloud(env)
    old = _sizes_of(cloud)
    nodes = old["db_nodes"] if raw.get("db_standby") is None else (2 if raw["db_standby"] else 1)
    new = {"droplet_size": raw.get("droplet_size") or old["droplet_size"], "db_size": raw.get("db_size") or old["db_size"],
           "db_nodes": nodes}
    if new == old:
        raise CreateRefused(422, "Choose a larger size, or add a standby node", "cloud")
    account = await _env_account(db, env, "cloud")
    choice = _resize_choice(env, account, droplet_size=new["droplet_size"], db_size=new["db_size"],
                            db_nodes=new["db_nodes"])
    catalog, cached = await catalogs(account, choice.region, typed=confirm_cost)
    problem = do_rules.droplet_grow_problem(str(old["droplet_size"]), str(new["droplet_size"]), catalog)
    if problem:
        raise CreateRefused(409, problem, "cloud.droplet_size")
    problem = do_rules.database_grow_problem(str(old["db_size"]), old["db_nodes"], str(new["db_size"]),
                                             new["db_nodes"], catalog)
    if problem:
        raise CreateRefused(409, problem, "cloud.db_standby" if "standby" in problem else "cloud.db_size")
    choice.cost, choice.shown, choice.catalog = estimate(account, choice.plan, catalog), \
        _shown(account, choice.plan, cached), catalog
    await _limit_problem(db, account, choice.cost.total_cents, except_environment=env.id)
    return GrowPlan(env=env, old=old, new=new, do=choice, old_cents=int((cloud.get("cost") or {}).get("total_cents") or 0),
                    confirm_cost=confirm_cost)


async def grow(db: AsyncSession, plan: GrowPlan, ctx: Any, *, request: Any = None) -> Environment:
    """Write a checked grow in the caller's transaction: the typed total first (422, or 409 when the estimate
    moved), the limit under the account's ``FOR UPDATE``, then ``cloud.droplet_size``, ``db_size``, ``db_nodes``,
    ``plan`` and ``cost`` together (there is no unconfirmed stored size). Each slot's next deploy applies the new
    droplet size in its ``resize`` step, the next ``database`` step the cluster's. Audit ``environment.resize``
    and ``environment.cost_confirmed``."""
    from slipway.services import do_rules

    env, user = plan.env, ctx.user
    problem = plan.do.confirm_problem(plan.confirm_cost)
    if problem is not None:
        raise problem
    account = await _provider_accounts().get(db, plan.do.account.id, lock=True)
    if account is None or account.removed_at is not None:
        raise CreateRefused(409, f"{plan.do.account.name} was removed", "cloud")
    await _limit_problem(db, account, plan.do.cost.total_cents, except_environment=env.id)
    env.cloud = plan.do.cloud(user, base=_cloud(env))
    delta = do_rules.delta_text(plan.old_cents, plan.do.cost.total_cents)
    changed = ", ".join(f"{k} {plan.old[k]} → {plan.new[k]}" for k in plan.new if plan.new[k] != plan.old[k])
    audit.record(db, "environment.resize", actor=user, target=env, request=request,
                 summary=f"Grew {env.name}: {changed} ({delta})",
                 details={"from": plan.old, "to": plan.new, "delta": delta,
                          "delta_cents": plan.do.cost.total_cents - plan.old_cents})
    _audit_cost(db, env, plan.do.cost, user, typed=plan.confirm_cost, request=request,
                summary=f"Confirmed about ${plan.do.cost.total} a month for {env.name}'s new sizes", delta=delta)
    await db.flush()
    return env


def resize_pending(env: Environment, slot: str, host: Host | None, machine: Machine | None = None) -> str | None:
    """``Resize pending: applies at <slot>'s next deploy`` (Decision 33) for a slot whose droplet is behind the
    confirmed size (its host's ``provider_state.size`` differs from ``cloud.droplet_size``), or whose ready app VM's
    size differs from what it has; None otherwise (a droplet or VM not made yet is made at its size, and the data
    server's VM is never resized by a deploy)."""
    from slipway.services import machines

    if machine is not None:  # the data server's VM keeps its size (P5 §9.4)
        if slot != DATA_SLOT and machine.stage == MachineStage.READY and machines.size_differs(machine):
            return RESIZE_PENDING.format(slot=slot)
        return None
    if host is None or (host.provider or "ssh") != DIGITALOCEAN:
        return None
    size = (host.provider_state or {}).get("size")
    wanted = _cloud(env).get("droplet_size")
    if size and wanted and size != wanted:
        return RESIZE_PENDING.format(slot=slot)
    return None


async def pending_resizes(db: AsyncSession, env: Environment,
                          members: dict[str, Instance] | None = None) -> dict[str, str]:
    """Each slot whose resize is pending, with the phrase (for ``EnvironmentOut`` and the Slots card)."""
    mem = members if members is not None else await members_of(db, env)
    vms = {m.slot: m for m in await env_machines(db, env)}
    out: dict[str, str] = {}
    for slot, inst in mem.items():
        text = resize_pending(env, slot, inst.host, vms.get(slot))
        if text:
            out[slot] = text
    return out


async def resize_plan(db: AsyncSession, env: Environment, slot: str, body: Any, ctx: Any, *,
                      request: Any = None) -> Machine:
    """P5 §9.4 (``PATCH /environments/{id}/machines/{slot}``): store a VM's new size (and how many automatic VM
    snapshots it keeps); nothing touches the hypervisor, the slot's next deploy applies it. Raise CreateRefused:
    machines:write (403), the environment deleting, a slot whose host Slipway didn't make, a size out of range or
    a disk smaller than it is (422), the data server's VM once it is made. Audit ``environment.update``."""
    from slipway.services import vmnet

    raw = body.model_dump() if hasattr(body, "model_dump") else dict(body or {})
    if not ctx.can(Perm.MACHINES_WRITE):
        raise CreateRefused(403, f"Resizing a VM needs the {Perm.MACHINES_WRITE} permission")
    gone = deleting_text(env)
    if gone:
        raise CreateRefused(409, gone)
    found = await env_machines(db, env, [slot])
    if not found:
        inst = (await members_of(db, env)).get(slot)
        if inst is None:
            raise CreateRefused(409, f"{env.name} has no slot {slot}")
        where = inst.host.name if inst.host is not None else "no host"
        raise CreateRefused(409, f"{slot} runs on host {where}, which Slipway didn't make")
    machine = found[0]
    size = dict(machine.size or {})
    wanted = {**size, **{k: raw[k] for k in vmnet.SIZE_LIMITS if raw.get(k) is not None}}
    applied = machine.applied or {}
    if raw.get("disk_gb") is not None and applied.get("disk_gb") is not None \
            and int(raw["disk_gb"]) < int(applied["disk_gb"]):
        raise CreateRefused(422, f"Disks only grow: {machine.name} has {int(applied['disk_gb'])} GB", "disk_gb")
    try:
        wanted = vmnet.check_size(wanted)
        keep = (vmnet.check_keep_vm_snapshots(raw["keep_vm_snapshots"]) if raw.get("keep_vm_snapshots") is not None
                else machine.keep_vm_snapshots)
    except ValueError as exc:
        raise CreateRefused(422, str(exc), "size") from None
    if slot == DATA_SLOT and machine.stage == MachineStage.READY and wanted != size:
        raise CreateRefused(409, "The data server's VM keeps its size: both slots' data is on it. docs/machines.md "
                                 "shows how to grow it by hand")
    changes: dict[str, str] = {}
    if wanted != size:
        changes[f"machine.{slot}"] = f"{vmnet.size_text(size) if size else 'none'} → {vmnet.size_text(wanted)}"
    if keep != machine.keep_vm_snapshots:
        changes[f"machine.{slot}.keep_vm_snapshots"] = f"{machine.keep_vm_snapshots} → {keep}"
    if changes:
        machine.size, machine.keep_vm_snapshots = wanted, keep
        audit.record(db, "environment.update", actor=ctx.user, target=env, request=request,
                     summary=f"Changed {machine.name}'s size: {'; '.join(changes.values())}",
                     details={"changed": changes})
        await db.flush()
    return machine


# ------------------------------------------------------------ retire and un-retire (P4 §13, §15.9)


def _typed_name(env: Environment, confirm: Any) -> None:
    if confirm != env.name:
        raise CreateRefused(422, f"Type the environment's name, {env.name}, exactly to confirm", "confirm")


async def _locked(db: AsyncSession, env: Environment) -> Environment:
    """The environment row again, ``FOR UPDATE`` (a no-op on SQLite), so Retire, Un-retire and Delete can't race."""
    found = await db.scalar(select(Environment).where(Environment.id == env.id).with_for_update()
                            .execution_options(populate_existing=True))
    return found if found is not None else env


async def _refuse_while_busy(db: AsyncSession, env: Environment) -> None:
    """Retire and Un-retire wait for every queued or running job of the environment (as Grow does): an activate
    queued before Retire would otherwise switch a retiring production, and a deactivate or teardown queued
    before Un-retire would run on one that no longer retires."""
    from slipway.services import jobs  # jobs imports this module

    busy = await jobs.busy_job(db, env, data.env_keys(env.id, None))
    if busy is not None:
        raise CreateRefused(409, busy_text(env, busy))


async def retire(db: AsyncSession, env: Environment, ctx: Any, confirm: Any, *, request: Any = None) -> Environment:
    """Retire a production environment (``POST /environments/{id}/retire {confirm}``): it keeps serving, no slot
    can be activated any more, and it can then be taken off the air and deleted. Refused while a job of the
    environment is queued or running. Audit ``environment.retire``."""
    _typed_name(env, confirm)
    env = await _locked(db, env)
    gone = deleting_text(env)
    if gone:
        raise CreateRefused(409, gone)
    if not env.production:
        raise CreateRefused(409, f"Only a production environment is retired: delete {env.name} instead")
    if env.retiring_at is not None:
        raise CreateRefused(409, f"{env.name} is already retiring")
    await _refuse_while_busy(db, env)
    user = ctx.user
    env.retiring_at, env.retired_by_id = utcnow(), user.id if user else None
    audit.record(db, "environment.retire", actor=user, target=env, request=request,
                 summary=f"Retired {env.name}: it keeps serving, but no slot can be activated", details={"name": env.name})
    await db.flush()
    return env


async def unretire(db: AsyncSession, env: Environment, ctx: Any, confirm: Any, *, request: Any = None) -> Environment:
    """Un-retire (``DELETE /environments/{id}/retire {confirm}``, Decision 38): refused while another production
    environment of the same app isn't retiring (the unique index answers a lost race the same way). Audit
    ``environment.unretire``."""
    _typed_name(env, confirm)
    env = await _locked(db, env)
    gone = deleting_text(env)
    if gone:
        raise CreateRefused(409, gone)
    if env.retiring_at is None:
        raise CreateRefused(409, f"{env.name} isn't retiring")
    await _refuse_while_busy(db, env)
    found = await db.get(Repository, env.repository_id)
    repo = found.full_name if found is not None else "This app"
    path = env.manifest_file or manifest.DEFAULT_FILE
    other = await _production_holder(db, env.repository_id, path, besides=env.id)
    if other is not None:
        raise CreateRefused(409, production_taken_text(repo, path, other.name))
    env.retiring_at, env.retired_by_id = None, None
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise CreateRefused(409, f"{repo}'s {path} already has a production environment; retire it first") from exc
    audit.record(db, "environment.unretire", actor=ctx.user, target=env, request=request,
                 summary=f"Un-retired {env.name}", details={"name": env.name})
    await db.flush()
    return env


# ----------------------------------------------------------------- Delete (P4 §13, §15.10; P5 §9.9)


def production_phrase(env: Environment) -> str:
    return f"delete production {env.name}"


def no_snapshot_phrase(env: Environment) -> str:
    return f"delete production {env.name} without a snapshot"


async def never_held_data(db: AsyncSession, env: Environment, members: dict[str, Instance] | None = None) -> bool:
    """P4 §13: the data owner never held data. Its data is empty or never made (a first deploy that failed
    before its backup step, in ``prepare``, ``database`` or ``edge``), no backup of it reached ``ready``, and no
    deploy of an app slot began its ``start`` step."""
    from slipway.models import Backup, BackupStatus, FreshData

    mem = members if members is not None else await members_of(db, env)
    owner = owner_in(env, mem)
    if owner is None:
        return True
    if owner.fresh_data not in (None, FreshData.EMPTY) or owner.data_dirty:
        return False
    if owner.fresh_data is None and (data.live_state(owner) is not None
                                     or any(m.current_commit_sha for m in mem.values())):
        return False
    reached = await db.scalar(select(Backup.id).where(
        Backup.instance_id == owner.id,
        Backup.status.in_([BackupStatus.READY, BackupStatus.MISSING, BackupStatus.CHANGED])).limit(1))
    if reached is not None:
        return False
    ids = [m.id for m in app_members(mem)] or [owner.id]
    deploys = (await db.scalars(select(Deployment).options(defer(Deployment.log)).where(
        Deployment.instance_id.in_(ids), Deployment.kind == DeploymentKind.DEPLOY))).all()
    return not any(step.get("key") == "start" and step.get("status") not in (None, "pending", "skipped")
                   for dep in deploys for step in dep.steps or [])


@dataclass
class DeletePlan:
    """How a Delete goes (``delete_problem``): with a snapshot first or not, the teardown's options (the typed
    phrases each retry asks again, ``drop_data``, ``forget_vms``), whether the data goes without a snapshot
    (``environment.delete_without_snapshot``, with ``why``), and a note for the answer."""

    snapshot: bool
    options: dict[str, Any]
    without_snapshot: bool = False
    why: str | None = None
    note: str | None = None

    def snapshot_options(self) -> dict[str, Any]:
        """What the snapshot taken first carries for the teardown its chain queues (``next_job``)."""
        return {"then": "teardown",
                "then_options": {k: v for k, v in self.options.items() if k in THEN_OPTIONS}}


def data_home(env: Environment, members: dict[str, Instance]) -> str | None:
    """Where the data lives when Delete destroys its only home (Decision 26): ``its managed database`` for a
    managed environment, the data VM's name when the owner's host is a VM Slipway made; else None."""
    if env.data_mode == DataMode.MANAGED:
        return "its managed database"
    owner = owner_in(env, members)
    if owner is not None and is_vm_host(owner.host):
        return owner.host.name
    return None


async def delete_problem(db: AsyncSession, env: Environment, body: Any, ctx: Any, *,
                         read_vms: bool = True) -> DeletePlan:
    """The rules of ``DELETE /environments/{id}`` (``EnvironmentDelete``), read with the environment row ``FOR
    UPDATE``; raise CreateRefused (typed text 422 first, a missing permission 403, else 409) before anything is
    queued. Phase 4 §13: a production environment is deleted only once retiring, off the air, with the phrase and
    a snapshot, unless it never held data or no slot can run its data commands (then the second phrase, and
    ``drop_data``). Decision 26: when Delete destroys the data's only home (a managed cluster, a data VM) a
    snapshot is taken unless ``drop_data`` (data:reset). Phase 5 §9.9: every VM must be removable
    (``machines.blockers``, unless ``read_vms`` is False); ``forget_vms`` lets forgettable blockers pass."""
    raw = body.model_dump() if hasattr(body, "model_dump") else dict(body or {})
    snapshot_in = raw.get("snapshot")
    drop = bool(raw.get("drop_data"))
    forget = bool(raw.get("forget_vms"))
    _typed_name(env, raw.get("confirm"))
    production = bool(env.production)
    if production and raw.get("confirm_production") != production_phrase(env):
        raise CreateRefused(422, f"Type {production_phrase(env)} to confirm", "confirm_production")
    env = await _locked(db, env)
    if env.status == EnvironmentStatus.DELETED:
        raise CreateRefused(409, f"{env.name} was deleted")
    if drop and not ctx.can(Perm.DATA_RESET):
        raise CreateRefused(403, f"Deleting {env.name}'s data with it needs the {Perm.DATA_RESET} permission",
                            "drop_data")
    if forget:
        for permission in (Perm.MACHINES_WRITE, Perm.ENVIRONMENTS_DELETE):
            if not ctx.can(permission):
                raise CreateRefused(403, f"Forgetting a VM needs the {permission} permission", "forget_vms")
    mem = await members_of(db, env)
    if production:
        if env.retiring_at is None:
            raise CreateRefused(409, f"Retire {env.name} first: a production environment is deleted only after it "
                                     "is retired")
        if env.active_slot_id is not None:
            raise CreateRefused(409, f"Deactivate {env.name} first: it still takes traffic")
    # P4 §13's never-held rule is for the environments phases 4 and 5 make. A phase 3 environment on SSH hosts
    # keeps phase 3's answer: a snapshot asked for goes through the snapshot's own checks.
    made_here = production or is_digitalocean(env) or any(is_vm_host(m.host) for m in mem.values())
    held = not made_here or not await never_held_data(db, env, mem)
    home = data_home(env, mem)
    runner = data.runner_choice(env, mem).instance if env.data_mode == DataMode.MANAGED else None
    no_runner = env.data_mode == DataMode.MANAGED and runner is None
    options: dict[str, Any] = {"confirmed": True}
    if production:
        options["confirm_production"] = raw.get("confirm_production")
    if drop:
        options["drop_data"] = True
    if forget:
        options["forget_vms"] = True
    out = DeletePlan(snapshot=False, options=options)
    if not held:
        out.note = f"{env.name} never held data, so there is nothing to snapshot"
    elif snapshot_in is not None:
        if not ctx.can(Perm.DATA_BACKUP):
            raise CreateRefused(403, "Taking a snapshot first needs the data:backup permission", "snapshot")
        if no_runner:
            raise CreateRefused(409, f"No slot can run the data commands: deploy to {data.runner_slot(env, mem)} "
                                     "first", "snapshot")
        out.snapshot = True
    elif production:
        if not no_runner:
            raise CreateRefused(422, "A production environment is deleted only after a snapshot", "snapshot")
        # It holds data, but nothing can run the data commands: the second phrase, and the data goes (§13).
        if raw.get("confirm_no_snapshot") != no_snapshot_phrase(env):
            raise CreateRefused(422, f"Type {no_snapshot_phrase(env)} to confirm", "confirm_no_snapshot")
        if not ctx.can(Perm.ENVIRONMENTS_DELETE):
            raise CreateRefused(403, f"Deleting without a snapshot needs the {Perm.ENVIRONMENTS_DELETE} permission",
                                "confirm_no_snapshot")
        if not drop:
            raise CreateRefused(409, only_home_text(env, home or "its managed database"), "drop_data")
        options.update(no_snapshot=True, confirm_no_snapshot=raw.get("confirm_no_snapshot"))
        out.without_snapshot, out.why = True, data.no_runner_text(env, mem)
    elif home is not None:
        if not drop:
            raise CreateRefused(409, only_home_text(env, home), "drop_data")
        out.without_snapshot = True
        out.why = "drop_data: " + (data.no_runner_text(env, mem) if no_runner else "the data goes with the environment")
    if read_vms and await env_machines(db, env):
        found = await vm_blockers(db, env)
        if stopping_blocker(found, forget_vms=forget) is not None:
            machine, blocker = next(((m, b) for m, b in found if not b.forgettable), found[0])
            raise CreateRefused(409, f"Slipway can't remove {machine.name}: {str(blocker.text).rstrip('.')}. Nothing "
                                     "was changed")
    return out


def only_home_text(env: Environment, home: str) -> str:
    """Decision 26's refusal: the data's only home goes with the environment."""
    if home == "its managed database":
        return (f"{env.name}'s data is in its managed database, which Delete destroys: take a snapshot first, or "
                "confirm that the data goes with it")
    return (f"{env.name}'s data is on {home}, which Delete destroys: take a snapshot first, or confirm that the data "
            "goes with it")


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
    # Phase 4 (§14.2): the certificate renewal, teardown's DigitalOcean objects, and Deactivate's switch.
    "certificate": "Renew the certificate",
    "cloud": "Remove the DigitalOcean objects",
    # Phase 5 (§10.2): Remove slot's VM, and Delete's VMs.
    "machine": "Remove the VM {vm}",
    "machines": "Remove the VMs",
}
# Names that depend on the job's kind or the environment's backend (phase 4 §14.2, Decision 13).
DEACTIVATE_SWITCH = "Take traffic off {from_slot}"
DO_LB_TRAFFIC = "Update the load balancer"
# Seconds each environment-level step may take (§13); ``seed`` takes the manifest's own timeout.
ENV_STEP_TIMEOUTS = {"check": 120, "switch": 1200, "dns": 600, "stop_slot": 600, "settle": 60, "unroute": 600,
                     "undns": 600, "slot": 1800, "slots": 1800, "data_server": 1800, "start_slot": 600,
                     "smoke": 600, "traffic": 600, "forget": 60, "certificate": 2700, "cloud": 4500,
                     "machine": 1800, "machines": 3600}


def is_digitalocean(env: Environment) -> bool:
    """Placement ``digitalocean`` (phase 4 §3.2): droplets, managed data and a load balancer."""
    return (env.provider or "ssh") == "digitalocean"


def is_vm_host(host: Host | None) -> bool:
    """A host that is a VM Slipway makes on Proxmox or ESXi (phase 5), planned or made."""
    from slipway.services import vmnet

    return host is not None and (host.provider or "ssh") in vmnet.PROVIDERS


def vm_name(env: Environment, slot: str) -> str:
    """The name of ``slot``'s VM, and of its host row (Decision 9)."""
    return f"slipway-{env.name}-{slot}"


async def env_machines(db: AsyncSession, env: Environment, slots: Iterable[str] | None = None) -> list[Machine]:
    """The environment's VMs (of ``slots`` when given), in the order Delete removes them: green, blue, data."""
    stmt = select(Machine).where(Machine.environment_id == env.id)
    if slots is not None:
        stmt = stmt.where(Machine.slot.in_(list(slots)))
    rows = list((await db.scalars(stmt)).all())
    return sorted(rows, key=lambda m: VM_REMOVE_ORDER.index(m.slot) if m.slot in VM_REMOVE_ORDER else 9)


async def _quiet(_line: str) -> None:
    return None


async def vm_blockers(db: AsyncSession, env: Environment, slots: Iterable[str] | None = None, *,
                      say: Callable[[str], Awaitable[None]] | None = None, hide: Any = None,
                      deployment_id: uuid.UUID | None = None, user_id: uuid.UUID | None = None,
                      connect: Any = None) -> list[tuple[Machine, Any]]:
    """Why the environment's VMs (of ``slots``) can't be removed now (phase 5 D26): ``(machine, Blocker)`` for each
    blocker ``machines.blockers`` finds, reading only. A machine never made has none."""
    from slipway.services import machines, ssh

    found: list[tuple[Machine, Any]] = []
    for machine in await env_machines(db, env, slots):
        kw: dict[str, Any] = {} if connect is None else {"connect": connect}
        ctx = await machines.load_context(db, machine_id=machine.id, deployment_id=deployment_id, user_id=user_id,
                                          say=say or _quiet, hide=hide if hide is not None else ssh.Redactor(), **kw)
        if ctx is None:
            continue
        found.extend((machine, blocker) for blocker in await machines.blockers(ctx))
    return found


def stopping_blocker(found: list[tuple[Machine, Any]], *, forget_vms: bool = False) -> str | None:
    """The text of the blocker that stops a removal, or None: any blocker does, unless ``forget_vms`` is given
    and every one of them is forgettable (D26)."""
    if not found:
        return None
    if forget_vms and all(blocker.forgettable for _, blocker in found):
        return None
    _, blocker = next(((m, b) for m, b in found if not b.forgettable), found[0])
    return str(blocker.text)


def _covers(names: Iterable[str], hostname: str) -> bool:
    hostname = hostname.lower()
    for name in names:
        name = str(name).lower().rstrip(".")
        if name == hostname or (name.startswith("*.") and hostname.split(".", 1)[-1] == name[2:]):
            return True
    return False


def certificate_due(env: Environment, target: Instance | None, members: dict[str, Instance]) -> bool:
    """Activate's ⟨certificate⟩ step (phase 4 §14.3): on a ``do_lb`` environment, when the served certificate
    (``cloud.certificate``) doesn't cover the target slot's names, has 30 days or fewer, or isn't known."""
    from slipway.services import certs, traffic  # traffic imports this module

    if (env.traffic or {}).get("switch") != DO_LB or target is None:
        return False
    served = (env.cloud or {}).get("certificate") or {}
    if not served:
        return True
    if certs.is_due(certs.parse_time(served.get("not_after"))):
        return True
    names = served.get("names") or served.get("dns_names") or []
    wanted = [r.hostname for r in traffic.routes(env, target, owner_in(env, members)) if r.follows == traffic.ACTIVE]
    return any(not _covers(names, hostname) for hostname in wanted)


def env_steps_for(env: Environment, kind: str, options: dict[str, Any] | None,
                  members: dict[str, Instance]) -> list[dict[str, Any]]:
    """The numbered steps of an environment-level job (§8.1, §8.4), with ⟨…⟩ steps listed only when their
    condition holds when the job is queued: ``start_slot`` when the target slot is stopped, ``certificate`` when
    a ``do_lb`` environment's certificate doesn't cover the target or is due (phase 4 §14.3), ``dns`` when the
    environment publishes DNS records, ``seed`` in the first activation when starter content is wanted,
    ``traffic`` when it publishes through a backend.

    Phase 4 adds the certificate renewal (``check, certificate``), Deactivate (``check, switch``) and the
    DigitalOcean teardown (``check, undns, slots, data_server, cloud, forget``: the load balancer goes with the
    other objects in ``cloud``, so there is nothing to unroute). Remove slot keeps ``check, slot``.

    Phase 5 (§10.3): Remove slot is ``check, slot, ⟨machine⟩`` and the teardown ``check, unroute, undns, slots,
    data_server, ⟨machines⟩, forget``, with the VM steps listed when the slot's host (any member's host) is a VM.
    A retry whose slot instance is already gone gets its ``machine`` step from its ``check`` (``env_jobs``)."""
    opts = options or {}
    slot = opts.get("slot")
    target = members.get(slot) if slot else None
    owner = owner_in(env, members)
    dns = bool((env.traffic or {}).get("dns"))
    switch = (env.traffic or {}).get("switch", "none") or "none"
    active = active_member(env, members)
    if kind == DeploymentKind.ACTIVATE:
        keys = ["check", *(["start_slot"] if target is not None and target.status == InstanceStatus.STOPPED else []),
                "smoke", *(["certificate"] if certificate_due(env, target, members) else []),
                *(["dns"] if dns else []), "switch",
                *(["seed"] if env.status == EnvironmentStatus.NEW and owner is not None and owner.seed_content else [])]
    elif kind == DeploymentKind.PUBLISH:
        keys = ["check", *(["traffic"] if switch != "none" else []), *(["dns"] if dns else [])]
    elif kind == DeploymentKind.DISCARD:
        keys = ["check", "stop_slot", "smoke", "settle"]
        # The smoke test of a discard checks the active slot on the current data, not the discarded one.
        target = active or target
    elif kind == DeploymentKind.REMOVE_SLOT:
        keys = ["check", "slot", *(["machine"] if target is not None and is_vm_host(target.host) else [])]
    elif kind == DeploymentKind.TEARDOWN:
        if is_digitalocean(env):
            keys = ["check", "undns", "slots", "data_server", "cloud", "forget"]
        else:
            vms = any(is_vm_host(m.host) for m in members.values())
            keys = ["check", "unroute", "undns", "slots", "data_server", *(["machines"] if vms else []), "forget"]
    elif kind == DeploymentKind.CERTIFICATE:
        keys = ["check", "certificate"]
    elif kind == DeploymentKind.DEACTIVATE:
        keys = ["check", "switch"]
    else:
        raise ValueError(f"{kind!r} isn't an environment-level job")
    host = target.host if target is not None else None
    values = {"env": env.name, "slot": slot or "", "host": host.name if host is not None else "",
              "from_slot": str(active.slot) if active is not None else "every slot",
              "vm": host.name if host is not None else (vm_name(env, slot) if slot else "")}
    if kind == DeploymentKind.DISCARD:
        values["checked"] = target.slot if target is not None else ""
    names = dict(ENV_STEP_NAMES)
    if kind == DeploymentKind.DISCARD:
        names["smoke"] = "Check {checked} on {host}"
    if kind == DeploymentKind.TEARDOWN and len(app_members(members)) == 1:
        names["slots"] = "Remove Blue"
    if kind == DeploymentKind.DEACTIVATE:
        names["switch"] = DEACTIVATE_SWITCH
    if switch == DO_LB:
        names["traffic"] = DO_LB_TRAFFIC
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
    jobs, refusal 4, are ``jobs.job_refusal``'s fences; the plan's blockers, 6, need Switchyard).

    Phase 5 §10.4: a slot whose VM isn't made yet, or whose VM is off (a resize left it off), read through the
    provider's ``describe`` last, after every refusal that needs no hypervisor."""
    from slipway.services import switchyard

    mem = members if members is not None else await members_of(db, env)
    target = mem.get(slot) if slot else None
    if target is None or slot not in APP_SLOTS:
        return "Only an app slot can take traffic"
    if env.active_slot_id == target.id and unresolved_text(env) is None:
        return f"{slot} already takes the traffic"
    if is_vm_host(target.host) and not target.host.is_built:
        return VM_NOT_MADE.format(slot=slot)
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
    return await vm_off_problem(db, target)


async def vm_off_problem(db: AsyncSession, target: Instance) -> str | None:
    """``<slot>'s VM <vm> is off`` when the slot's ready VM isn't running (phase 5 §9.12, §10.4), read through
    ``describe``; None for a host that isn't a VM, a VM that isn't ready, a hypervisor that can't be read
    (the activate's smoke test still checks the slot), and on a page view (``actions``)."""
    from slipway.services import machines, ssh
    from slipway.services.vmtypes import MachineError

    if not is_vm_host(target.host) or _page_view.get():
        return None
    ctx = await machines.load_context(db, host_id=target.host_id, say=_quiet, hide=ssh.Redactor())
    if ctx is None or ctx.machine.stage != MachineStage.READY or machines.account_problem(ctx.account):
        return None
    try:
        state = await ctx.provider.describe(ctx)
    except MachineError:
        return None
    if state.exists and state.power and state.power != "running":
        return VM_OFF.format(slot=target.slot, vm=ctx.vm)
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
                              members: dict[str, Instance] | None = None, *, forget_vms: bool = False,
                              read_vms: bool = True) -> str | None:
    """§9.9's refusals that are about the slot (the running job and an unresolved switch are fences).

    Phase 5 §9.5 (D26): then the slot's VM must be removable (``machines.blockers``, reading the hypervisor
    unless ``read_vms`` is False); a forgettable blocker passes only with ``forget_vms``. A slot whose instance
    is already gone but whose VM is left (a Remove slot stopped after its ``slot`` step) may be removed again."""
    mem = members if members is not None else await members_of(db, env)
    if slot == DATA_SLOT:
        return "The data server goes with the environment"
    target = mem.get(slot) if slot else None
    if target is None:
        if slot in APP_SLOTS and await env_machines(db, env, [slot]):
            if not read_vms:
                return None
            return stopping_blocker(await vm_blockers(db, env, [slot]), forget_vms=forget_vms)
        return f"{env.name} has no slot {slot}"
    if env.active_slot_id == target.id:
        other = next((s for s in APP_SLOTS if s != slot), "the other slot")
        return f"{slot} takes the traffic: activate {other} first"
    if len(app_members(mem)) < 2:
        return f"{slot} is {env.name}'s only slot: delete the environment instead"
    if env.production and env.retiring_at is None:
        # P4 §13 (D20): with one slot every deploy would replace the live release in place, with no Activate.
        return f"Production runs Blue and Green: retire {env.name} first"
    owner = owner_in(env, mem)
    ids = [str((((owner.data_dirty if owner else None) or {}).get(p) or {}).get("deployment_id") or "")
           for p in ("first", "last")]
    found = {d.id.hex: d for d in (await db.scalars(select(Deployment).options(defer(Deployment.log)).where(
        Deployment.id.in_([u for u in (data._uuid(i) for i in ids) if u])))).all()} if any(ids) else {}
    if dirty_names(owner, target, found):
        return f"Discard {slot} or roll back first"
    if read_vms and is_vm_host(target.host):
        return stopping_blocker(await vm_blockers(db, env, [str(slot)]), forget_vms=forget_vms)
    return None


def deactivate_problem(env: Environment, members: dict[str, Instance]) -> str | None:
    """Phase 4 §13's refusals of Deactivate that don't need a plan: only a retiring production environment with
    a live slot (or an unresolved switch) is taken off the air, through its traffic backend."""
    if not (env.production and env.retiring_at is not None):
        return f"Only a retiring production environment is taken off the air: retire {env.name} first"
    if (env.traffic or {}).get("switch", "none") in (None, "none"):
        return f"{env.name} doesn't publish its names, so there is no traffic to take off"
    if active_member(env, members) is None and unresolved_text(env) is None:
        return f"{env.name} has no live slot: there is no traffic to take off"
    return None


async def forget_vm_problem(db: AsyncSession, env: Environment, slot: str,
                            members: dict[str, Instance] | None = None, *, read_vm: bool = True) -> Any:
    """Why Forget the VM (phase 5 §9.10) can't run for ``slot``, as a ``jobs.JobRefused`` (409, or 502 when the
    account can't be checked), or None. The typed name (422) and the permissions (403) are the API's. Reads the
    hypervisor last, through ``describe``: only a VM that is gone may be forgotten. ``read_vm`` False stops
    before that read (the environment page's ``actions``)."""
    from slipway.services import jobs, machines, ssh
    from slipway.services.vmtypes import MachineError

    def no(text: str, status: int = 409) -> Any:
        return jobs.JobRefused(status, text)

    gone = deleting_text(env)
    if gone:
        return no(gone)
    mem = members if members is not None else await members_of(db, env)
    found = await env_machines(db, env, [slot])
    if not found:
        return no(f"{env.name}'s {slot} slot has no VM")
    machine = found[0]
    vm = machine.name
    if machine.stage != MachineStage.READY:
        return no(f"{vm} isn't made yet: deploy to {slot} to finish it")
    if slot == DATA_SLOT or env.data_mode == DataMode.SLOT:
        return no(f"{vm} held {env.name}'s data. Slipway can't make it again without that data: delete the "
                  "environment, and create it again from a snapshot if you have one")
    target = mem.get(slot)
    if target is not None and env.active_slot_id == target.id and len(app_members(mem)) == 2:
        other = next(s for s in APP_SLOTS if s != slot)
        return no(f"{slot} takes the traffic: activate {other} first")
    busy = await jobs.busy_job(db, env, data.env_keys(env.id, None))
    if busy is not None:
        return no(busy_text(env, busy))
    ctx = await machines.load_context(db, machine_id=machine.id, say=_quiet, hide=ssh.Redactor())
    if ctx is None:
        return no(f"{env.name}'s {slot} slot has no VM")
    account = ctx.account.name if ctx.account is not None else "its account"
    why = machines.account_problem(ctx.account)
    if why:
        return no(f"{account} can't be used ({why}), so Slipway won't forget {vm}: fix the account first")
    if not read_vm:
        return None
    try:
        state = await ctx.provider.describe(ctx)
    except MachineError as exc:
        detail = "" if exc.unreachable else f" ({exc.text})"
        return no(f"Slipway can't check {account} now{detail}, so it won't forget {vm}", 502)
    if state.error:
        return no(f"Slipway can't check {account} now ({state.error}), so it won't forget {vm}", 502)
    if state.hidden:
        vmid = (machine.ids or {}).get("vmid")
        pool = (machine.spec or {}).get("pool") or ""
        return no(f"Proxmox still has VM {vmid}, but the token can't see it. Give it back its rights on /pool/{pool}, "
                  "or remove the VM by hand, then try again")
    if state.exists:
        return no(f"Slipway can still see {vm} on {account}: remove the slot instead")
    return None


# A DigitalOcean environment before ``edge`` wrote its load balancer's IP (P4 §11.6): no record has an address.
NO_LB_YET = "{env}'s load balancer isn't made yet: deploy first"


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
    if traffic.get("dns") and is_digitalocean(env) and not traffic["dns"].get("address"):
        return NO_LB_YET.format(env=env.name)
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


# Set while ``actions`` runs: a page view reads no hypervisor, so Activate's VM-off check (``vm_off_problem``,
# a ``describe``) is left to the queue and the job's own check (P5 §10.4).
_page_view: contextvars.ContextVar[bool] = contextvars.ContextVar("slipway_environment_page_view", default=False)


@contextlib.contextmanager
def page_view() -> Iterator[None]:
    """A page's read of what it offers (``actions``, a failed environment job's Retry): no hypervisor is read
    meanwhile, so Activate's VM-off check is left to the queue and the job's own check (P5 §10.4, §19)."""
    token = _page_view.set(True)
    try:
        yield
    finally:
        _page_view.reset(token)


async def actions(db: AsyncSession, env: Environment, ctx: Any) -> dict[str, Any]:
    """``EnvironmentOut.actions``: what the environment page offers, and why not (§11). The API and the page
    share it, and each queued job is checked again by ``jobs.queue_job``. It reads no hypervisor."""
    with page_view():
        return await _actions(db, env, ctx)


async def _actions(db: AsyncSession, env: Environment, ctx: Any) -> dict[str, Any]:
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

    # Deploy: the data server first in a new mode server environment, then the target slot. A managed
    # environment never deploys its data owner (Decision 21).
    server_new = env.data_mode == DataMode.SERVER and owner is not None and data.live_state(owner) is None
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
    if env.data_mode == DataMode.MANAGED:
        reason = f"{env.name}'s data is in its managed database, so it has no data server to update"
    elif env.data_mode == DataMode.SLOT or data_member is None:
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

    # The chain notice's button: the follow-up job, with its own permission (§8.5), checked with the options
    # POST /notice/continue queues: next_job's (a production teardown's carry snapshot_first and the phrase), or
    # the notice's kind and slot when the finished job names none.
    notice = env.notice if isinstance(env.notice, dict) else None
    nxt = (notice or {}).get("next")
    if isinstance(nxt, dict) and nxt.get("kind"):
        kind, nslot = str(nxt["kind"]), nxt.get("slot")
        finished_id = data._uuid((notice or {}).get("deployment_id"))
        finished = await db.get(Deployment, finished_id) if finished_id is not None else None
        found = await next_job(db, finished) if finished is not None else None
        if found is not None:
            kind, nslot = found.kind, found.slot
        perm = FOLLOW_UP_PERMISSION.get(kind, Perm.DEPLOYMENTS_CREATE)
        reason = None if can(perm) else need_text(perm)
        inst = mem.get(str(nslot)) if kind == DeploymentKind.DEPLOY and nslot else None
        if found is not None:
            opts: dict[str, Any] = dict(found.options)
        elif kind == DeploymentKind.TEARDOWN:
            opts = {"confirmed": True}
        else:
            opts = {"slot": nslot}
            if inst is not None:
                opts["go_live"] = goes_live(env, str(nslot), mem)
        if reason is None:
            reason = await refusal(inst, kind, opts)
        # A production Activate while a slot is live takes the name typed (Decision 39): the button opens a
        # dialog that sends it as POST /notice/continue's ``confirm``.
        needs_confirm = kind == DeploymentKind.ACTIVATE and jobs.confirm_refusal(env, kind, opts) is not None
        out["continue"] = _no(reason, kind=kind, slot=nslot, needs_confirm=needs_confirm)
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
    elif is_digitalocean(env) and not can(Perm.PROVIDERS_SPEND):
        reason = need_text(Perm.PROVIDERS_SPEND)
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
        if reason is None and env.production and env.retiring_at is None:
            reason = f"Retire {env.name} first: a production environment is deleted only after it is retired"
        if reason is None and env.production and env.active_slot_id is not None:
            reason = f"Deactivate {env.name} first: it still takes traffic"
    held = not await never_held_data(db, env, mem)
    home = data_home(env, mem)
    can_snapshot = env.data_mode != DataMode.MANAGED or data.runner_choice(env, mem).instance is not None
    out["delete"] = _no(reason)
    # What Delete's dialog offers (P4 §13, P5 §9.9): the snapshot box's state and the data's only home.
    out["delete_data"] = {"holds_data": held, "data_home": home, "can_snapshot": can_snapshot,
                          "production": bool(env.production)}
    out.update(await _later_actions(db, env, ctx, mem, refusal=refusal, gone=gone))
    return out


async def _later_actions(db: AsyncSession, env: Environment, ctx: Any, mem: dict[str, Instance], *,
                         refusal: Callable[..., Awaitable[str | None]], gone: str | None) -> dict[str, Any]:
    """Phase 4's and phase 5's entries of ``actions``: retire, unretire, deactivate, renew_certificate and grow
    (DigitalOcean), resize, forget and vm_snapshots (VMs). Nothing here reads a hypervisor."""
    can = ctx.can
    out: dict[str, Any] = {}

    def needs(*perms: str) -> str | None:
        return next((need_text(p) for p in perms if not can(p)), None)

    # Retire, un-retire and Deactivate: production only (P4 §13).
    if not env.production:
        no_prod = f"Only a production environment is retired and taken off the air: delete {env.name} instead"
        out["retire"] = out["unretire"] = out["deactivate"] = _no(no_prod)
    else:
        from slipway.services import jobs

        busy = await jobs.busy_job(db, env, data.env_keys(env.id, None))
        waits = busy_text(env, busy) if busy is not None else None  # Retire and Un-retire wait for every job
        out["retire"] = _no(gone or needs(Perm.ENVIRONMENTS_DELETE)
                            or (f"{env.name} is already retiring" if env.retiring_at is not None else None) or waits)
        out["unretire"] = _no(gone or needs(Perm.ENVIRONMENTS_DELETE)
                              or (f"{env.name} isn't retiring" if env.retiring_at is None else None) or waits)
        out["deactivate"] = _no(gone or needs(Perm.TRAFFIC_SWITCH, Perm.ENVIRONMENTS_DELETE)
                                or await refusal(None, DeploymentKind.DEACTIVATE))
    # Renew the certificate now, and grow the sizes (DigitalOcean).
    if (env.traffic or {}).get("switch") == DO_LB:
        from slipway.services import resources

        made = await resources.owned(db, env.id, DIGITALOCEAN, "load_balancer")
        out["renew_certificate"] = _no(gone or needs(Perm.TRAFFIC_SWITCH)
                                       or (None if made else f"{env.name} has no load balancer yet: deploy it first")
                                       or await refusal(None, DeploymentKind.CERTIFICATE))
    else:
        out["renew_certificate"] = _no(f"{env.name} has no load balancer, so Slipway serves no certificate for it")
    if is_digitalocean(env):
        from slipway.services import jobs

        reason = gone or needs(Perm.ENVIRONMENTS_WRITE, Perm.PROVIDERS_SPEND)             or (f"{env.name} is retiring: its sizes stay as they are" if env.retiring_at is not None else None)
        if reason is None:
            busy = await jobs.busy_job(db, env, data.env_keys(env.id, None))
            reason = busy_text(env, busy) if busy is not None else None
        out["grow"] = _no(reason, pending=await pending_resizes(db, env, mem))
    else:
        out["grow"] = _no(f"{env.name} isn't on DigitalOcean: its sizes are its hosts'", pending={})
    # The VMs (P5 §11): resize per slot, Forget per app slot, and VM snapshots.
    vms = {m.slot: m for m in await env_machines(db, env)}
    resize: dict[str, Any] = {}
    forget: dict[str, Any] = {}
    for slot, machine in vms.items():
        inst = mem.get(slot)
        reason = gone or needs(Perm.MACHINES_WRITE)
        if reason is None and slot == DATA_SLOT and machine.stage == MachineStage.READY:
            reason = "The data server's VM keeps its size: both slots' data is on it"
        pending = resize_pending(env, slot, inst.host if inst is not None else None, machine)
        resize[slot] = _no(reason, pending=pending is not None,
                           applies_at=f"{slot}'s next deploy" if pending is not None else None)
        if slot in APP_SLOTS:
            reason = gone or needs(Perm.MACHINES_WRITE, Perm.ENVIRONMENTS_DELETE)
            if reason is None:
                found = await forget_vm_problem(db, env, slot, mem, read_vm=False)
                reason = found.text if found is not None else None
            forget[slot] = _no(reason)
    out["resize"], out["forget"] = resize, forget
    target = mem.get("blue")
    if not vms:
        reason = "VM snapshots are for an environment whose one slot runs on a VM Slipway made"
    else:
        reason = gone or needs(Perm.MACHINES_WRITE)
        if reason is None and target is not None:
            reason = await refusal(target, DeploymentKind.VM_SNAPSHOT, {"slot": "blue"})
    out["vm_snapshots"] = _no(reason)
    return out


# ---------------------------------------------------------------- the chain (§8.5)

# The permission a chained follow-up needs of the user it runs as (§4.1); any other kind needs
# deployments:create, and a slot deploy that goes live traffic:switch as well (jobs.job_refusal).
FOLLOW_UP_PERMISSION = {DeploymentKind.ACTIVATE: Perm.TRAFFIC_SWITCH, DeploymentKind.TEARDOWN: Perm.ENVIRONMENTS_DELETE}


# What a Delete's snapshot carries on to the teardown its chain queues (``options.then_options``).
THEN_OPTIONS = ("confirm_production", "drop_data", "forget_vms")


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
        # Delete's own choices ride on the snapshot (``then_options``: the production phrase, drop_data,
        # forget_vms), and the teardown records that a snapshot came first (P4 §13).
        carried = {k: v for k, v in (opts.get("then_options") or {}).items() if k in THEN_OPTIONS}
        return NextJob(DeploymentKind.TEARDOWN, None,
                       {"confirmed": True, "snapshot_first": True, **carried,
                        **({"snapshot": snap.name} if snap is not None else {})})
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
