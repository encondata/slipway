"""Queueing jobs: every refusal a job meets before it is queued, and the queued ``Deployment`` row.

``queue_job`` is ``api/v1/instances.queue_deployment`` moved here and extended for environments (phase 3 §8.5):
a job of a standalone instance meets exactly the checks it met before (I1); a job of an environment member, or
of a whole environment (``instance`` None), also meets the environment's fences: the runner keys of D8, the
data owner's hold and dirty state (§7.5), an unresolved switch (§10.6), the data server's readiness (§6) and
the permission a deploy that goes live needs. The caller audits, commits and submits the job, as before.

Phases 4 and 5 add the not-built rule for hosts a provider makes (a droplet, a VM): a deploy builds its host
(its steps start with ``resolve`` then ``prepare``), Remove slot and the teardown may run on an owned host in any
phase, and every other job waits until the host is built (Decision 28). SSH hosts keep phase 3's unpinned
refusal. Production environments add P4 §13's fences: the typed name or phrases (``confirm_refusal``, asked
first when a job is queued) and the retiring and off-the-air rules (``production_problem``). The system actor (``system='renewals'``) may queue only a certificate renewal (P4 §15.12), and the kinds
of later slices register their own refusals in ``KIND_PROBLEMS`` (Decision 45).
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.core.permissions import Perm
from slipway.models import (
    DataMode,
    Deployment,
    DeploymentKind,
    Environment,
    EnvironmentStatus,
    Instance,
    InstanceStatus,
    Machine,
    MachineStage,
    ProviderAccount,
    User,
)
from slipway.services import data, environments, hosts, machines, ssh

BUSY = "A job is already running for this instance; wait for it to finish"
DELETING = "This instance is being deleted"
UNPINNED = "Host {host} has not been verified yet; run a connection check first"
# The not-built rule (Decision 28) for a host a provider makes, and the VM data server's own text (P5 §10.4).
NOT_BUILT = "{slot}'s server isn't built yet: deploy to {slot} first"
DATA_VM_NOT_MADE = "Deploy {env} first: its data server's VM isn't made yet"
VM_DESTROYING = "{vm} is being removed; only the retry of that removal can run"
# Kinds refused while the data owner's data is held (§7.5): Retry, the restore kinds, Back up now, removing a
# slot and the teardown stay allowed. A VM snapshot of held data would keep the half-changed data (P5 §10.1).
HOLD_REFUSES = (DeploymentKind.DEPLOY, DeploymentKind.ACTIVATE, DeploymentKind.DISCARD, DeploymentKind.SNAPSHOT,
                DeploymentKind.ADMIN, DeploymentKind.CONTENT, DeploymentKind.VM_SNAPSHOT)
# Kinds that run on an owned host whatever its phase: they remove it (Decision 28).
REMOVING_KINDS = (DeploymentKind.REMOVE_SLOT, DeploymentKind.TEARDOWN)
# Who other than a person may queue a job, and the one kind each may queue (P4 §15.12).
SYSTEM_KINDS = {"renewals": DeploymentKind.CERTIFICATE}

# A kind's own refusals, registered by the module that owns the kind (Decision 45: phase 5's vm_jobs registers
# vm_snapshot, vm_revert and vm_drop here, so they need no edit of this file). ``job_refusal`` calls the one of
# the job's kind, for a job of an environment, after the environment's fences; it answers None, a text (409) or
# a JobRefused. Keyword arguments: db, env, instance, members, options, user, retry_of.
KindProblem = Callable[..., Awaitable["JobRefused | str | None"]]
KIND_PROBLEMS: dict[str, KindProblem] = {}


class JobRefused(Exception):
    """A job that can't be queued: the HTTP status and the text for the user. The API turns it into an
    HTTPException; the chain hook writes it into the environment's notice."""

    def __init__(self, status: int, text: str) -> None:
        super().__init__(text)
        self.status, self.text = status, text


def _runner_deleting(keys: tuple[Any, ...]) -> bool:
    """Whether the runner is deleting what one of ``keys`` names. Read off the runner's set directly, so it holds
    both before and after the runner is keyed on runner keys (S8a)."""
    from slipway.services import deployer  # the deployer imports data, which imports environments

    deleting = getattr(deployer.runner, "_deleting", set())
    return any(k in deleting for k in keys)


async def busy_job(db: AsyncSession, env: Environment, keys: tuple[Any, ...], *,
                   exclude: uuid.UUID | None = None) -> Deployment | None:
    """The first queued or running job of ``env`` whose runner keys meet ``keys`` (§8.2), or None."""
    for job in await data.active_env_jobs(db, env.id):
        if job.id != exclude and data.keys_meet(data.job_keys(job), keys):
            return job
    return None


def _go_live_needs_switch(env: Environment, members: dict[str, Instance]) -> bool:
    return len(environments.app_members(members)) == 2 or env.active_slot_id is None


def _chain_goes_live(env: Environment, instance: Instance, opts: dict[str, Any], members: dict[str, Instance]) -> bool:
    """A data server deploy whose chain queues an app slot deploy that goes live (§8.5 rule 1: no app slot has
    finished a deploy yet)."""
    return instance.slot == environments.DATA_SLOT and bool(opts.get("chain")) and not any(
        m.current_commit_sha for m in environments.app_members(members))


async def environment_fence(db: AsyncSession, env: Environment, members: dict[str, Instance], *,
                            instance: Instance | None, kind: str, options: dict[str, Any] | None = None,
                            retry_of: Deployment | None = None) -> JobRefused | None:
    """The environment's fences on a job, or None: the data owner's hold, its dirty state for an activate
    (§7.5), an unresolved switch (§10.6), and a deploy to the app slot that serves traffic while there are
    two (I2). ``job_refusal`` asks them before a job is queued; the deployer asks them again when a member's
    job starts (two requests can both pass the first check before either commits). Writes nothing."""
    opts = options or {}
    slot = instance.slot if instance is not None else opts.get("slot")
    target = instance if instance is not None else (members.get(slot) if slot else None)
    owner = environments.owner_in(env, members)

    # The data owner's hold, and its dirty state for an activate (§7.5).
    dirty = (owner.data_dirty if owner is not None else None) or {}
    dirty_ids = {str((dirty.get(p) or {}).get("deployment_id") or "") for p in ("first", "last")} - {""}
    if dirty.get("hold") and kind in HOLD_REFUSES and not (retry_of is not None and retry_of.id.hex in dirty_ids):
        held = await data.hold_text(db, owner) if owner is not None else None
        if held:
            return JobRefused(409, held)
    unresolved = environments.unresolved_text(env)
    if kind == DeploymentKind.ACTIVATE and dirty:
        recorded = env.active_slot_id is not None and target is not None and target.id == env.active_slot_id
        if not (unresolved and recorded):
            return JobRefused(409, environments.dirty_activate_text(env, owner, str(slot)))

    # An unresolved switch fences off what could move, stop or rebuild a slot that may take traffic (§10.6):
    # of the data jobs only Back up now and a snapshot that doesn't stop the app stay allowed.
    if unresolved:
        app_deploy = kind == DeploymentKind.DEPLOY and slot in environments.APP_SLOTS
        stops_app = kind == DeploymentKind.SNAPSHOT and bool(opts.get("stop_app"))
        # A certificate renewal rewrites the load balancer's HTTPS rule, which a switch left half-done (P4 §14.3).
        if app_deploy or stops_app or kind in (DeploymentKind.REMOVE_SLOT, DeploymentKind.DISCARD,
                                               DeploymentKind.ADMIN, DeploymentKind.CONTENT,
                                               DeploymentKind.CERTIFICATE, *data.RESTORE_KINDS):
            return JobRefused(409, unresolved)

    # A deploy to the app slot that serves traffic. While that slot's host isn't built (a droplet found gone,
    # P4 D28) nothing serves from it, so its deploy builds it again; so too once that deploy rebuilt the host
    # but failed before a release went live on it (its old release went with the old disk), so its retry or
    # another deploy can finish the job.
    if kind == DeploymentKind.DEPLOY and instance is not None and instance.slot in environments.APP_SLOTS \
            and (instance.host is None or ssh.host_is_built(instance.host)) and not release_gone(instance):
        apps = environments.app_members(members)
        if len(apps) == 2 and env.active_slot_id == instance.id:
            other = "green" if instance.slot == "blue" else "blue"
            return JobRefused(409, f"{instance.slot} serves traffic: deploy to {other}, then activate it")
    return None


def release_gone(instance: Instance) -> bool:
    """Whether the slot's live release went with its gone droplet (``app_state.gone_live``, P4 D28) and no
    release has gone live on it since: it serves nothing."""
    return bool((instance.app_state or {}).get("gone_live")) and data.live_state(instance) is None


def identity_text(env: Environment, owner: Instance, key: str) -> str:
    """The refusal of an app slot deploy whose identity value isn't the one the shared data was made with."""
    return (f"{key} differs from the value {owner.name}'s data was made with: a variable of {env.name} changed it. "
            f"An app slot can't change it on the shared data, so put the variable back to the old value "
            f"and deploy again. Only a restore on the data server changes the data's {key}.")


def identity_replaceable(owner: Instance | None, members: dict[str, Instance] | None) -> bool:
    """Whether the shared data's identity values may still be replaced (§7.5): no app has run on it yet. The
    data server's first deploy made it empty and records an identity, but runs no app: until an app slot goes
    live on it (no slot has a live commit, or a failed release whose containers may have run, and nothing marked
    the data dirty), the first app slot deploy's values become the data's."""
    if owner is None or owner.fresh_data != "empty" or owner.data_dirty:
        return False
    return not any(m.current_commit_sha or (m.app_state or {}).get("starting")
                   for m in environments.app_members(members or {}))


def identity_problem(env: Environment, owner: Instance | None, instance: Instance,
                     members: dict[str, Instance] | None = None) -> str | None:
    """An app slot whose data is on another instance (mode ``server``) may not go live with an identity value
    other than the one the shared data was made with (I3, data-loss 4): a variable of the environment that sets
    a recorded identity key to another value refuses its deploy, unless no app has run on the data yet
    (``identity_replaceable``). The deployer checks the release's rendered values too, once it has read
    slipway.yml."""
    if owner is None or owner.id == instance.id or not owner.live_identity:
        return None
    if identity_replaceable(owner, members):
        return None
    variables = env.env or {}  # an unreadable column reads as None: the deploy refuses it on its own
    for key in sorted(owner.live_identity):
        if key in variables and str(variables[key]) != str(owner.live_identity[key]):
            return identity_text(env, owner, key)
    return None


def confirm_refusal(env: Environment, kind: str, options: dict[str, Any] | None) -> JobRefused | None:
    """The typed confirmations a job of a production environment needs (P4 §13), checked first (422) when it is
    queued: the environment's name for an Activate or Switch back (``options.confirm``, Decision 39), and for its
    teardown the phrase ``delete production <name>`` (``options.confirm_production``) and, when it goes without a
    snapshot, ``delete production <name> without a snapshot``. A retry is asked them again, since a retry never
    copies them (``ENV_ONE_SHOT``). A chained activate while nothing is live (the first deploy's) moves no
    traffic away and needs no name. ``job_refusal`` doesn't ask these, so a page can still offer the job."""
    opts = options or {}
    if not env.production:
        return None
    if kind == DeploymentKind.ACTIVATE:
        if opts.get("chain") and env.active_slot_id is None:
            return None
        if opts.get("confirm") != env.name:
            return JobRefused(422, f"Type the environment's name, {env.name}, exactly to confirm")
    if kind == DeploymentKind.TEARDOWN:
        phrase = environments.production_phrase(env)
        if opts.get("confirm_production") != phrase:
            return JobRefused(422, f"Type {phrase} to confirm")
        if opts.get("no_snapshot") and opts.get("confirm_no_snapshot") != environments.no_snapshot_phrase(env):
            return JobRefused(422, f"Type {environments.no_snapshot_phrase(env)} to confirm")
    return None


async def production_problem(db: AsyncSession, env: Environment, kind: str, options: dict[str, Any] | None,
                             members: dict[str, Instance]) -> JobRefused | None:
    """P4 §13's fences that read the environment's state: no slot of a retiring production is activated; only a
    retiring production with a live slot is taken off the air (``deactivate_problem``, for every environment);
    a production teardown needs the environment retiring and off the air, and a snapshot first unless its data
    owner never held data or the delete went without one (``no_snapshot``). The teardown's ``check`` may ask
    this again at run time."""
    opts = options or {}
    if kind == DeploymentKind.DEACTIVATE:
        problem = environments.deactivate_problem(env, members)
        return JobRefused(409, problem) if problem else None
    if not env.production:
        return None
    if kind == DeploymentKind.ACTIVATE and env.retiring_at is not None:
        return JobRefused(409, f"{env.name} is retiring: it only goes dark")
    if kind == DeploymentKind.TEARDOWN:
        if env.retiring_at is None:
            return JobRefused(409, f"Retire {env.name} first: a production environment is deleted only after it is "
                                   "retired")
        if env.active_slot_id is not None:
            return JobRefused(409, f"Deactivate {env.name} first: it still takes traffic")
        if not (opts.get("snapshot_first") or opts.get("no_snapshot")) \
                and not await environments.never_held_data(db, env, members):
            return JobRefused(422, "A production environment is deleted only after a snapshot")
    return None


def _missing_permission(user: User | None, permissions: tuple[str, ...]) -> str | None:
    """Why the user can't be the one a chained follow-up runs as (§8.5), or None."""
    if not permissions:
        return None
    if user is None:
        return "the user who started it no longer exists"
    if not user.is_active:
        return "the user who started it was deactivated"
    for permission in permissions:
        if not user.can(permission):
            return f"the user who started it no longer has the {permission} permission"
    return None


async def job_refusal(db: AsyncSession, *, instance: Instance | None = None, environment: Environment | None = None,
                      user: User | None, kind: str = DeploymentKind.DEPLOY, options: dict[str, Any] | None = None,
                      retry_of: Deployment | None = None, members: dict[str, Instance] | None = None,
                      needs: tuple[str, ...] = ()) -> JobRefused | None:
    """What refuses a job before it is queued, or None. Writes nothing (``actions`` asks it too).

    ``instance`` is the job's instance (None for an environment-level job, whose target slot is
    ``options.slot``). ``options`` are the job's own, ``go_live`` and ``slot`` included for a slot deploy.
    ``kind`` is the job's real kind, a retry's included. ``needs`` are permissions the user must still hold,
    checked last (a chained follow-up's, §8.5).
    """
    opts = options or {}
    env = environment if environment is not None else (
        await environments.environment_of(db, instance) if instance is not None else None)
    if instance is None and env is None:
        raise ValueError("a job needs an instance or an environment")

    if env is None:
        # A standalone instance: exactly phase 2's checks, in phase 2's order (I1).
        assert instance is not None
        if _runner_deleting((instance.id,)):
            return JobRefused(409, DELETING)
        running = await data.active_job(db, instance.id)
        if running is not None:
            return JobRefused(409, data.busy_text(running))
        if not instance.host.is_pinned:
            return JobRefused(400, UNPINNED.format(host=instance.host.name))
        return None

    mem = members if members is not None else await environments.members(db, env)
    keys = data.runner_keys(instance, kind, opts) if instance is not None else data.env_keys(env.id, kind, opts)
    slot = instance.slot if instance is not None else opts.get("slot")
    target = instance if instance is not None else (mem.get(slot) if slot else None)
    owner = environments.owner_in(env, mem)
    if _runner_deleting(keys) or (instance is not None and _runner_deleting((instance.id,))):
        return JobRefused(409, DELETING if instance is not None else f"{env.name} is being deleted")
    if env.status == EnvironmentStatus.DELETED:
        return JobRefused(409, f"{env.name} was deleted")
    if env.status == EnvironmentStatus.DELETING and not (
            kind == DeploymentKind.TEARDOWN and retry_of is not None and retry_of.kind == DeploymentKind.TEARDOWN):
        return JobRefused(409, f"{env.name} is being deleted: only its teardown's retry can run")
    busy = await busy_job(db, env, keys)
    if busy is not None:
        return JobRefused(409, environments.busy_text(env, busy))
    if instance is not None:
        running = await data.active_job(db, instance.id)
        if running is not None:
            return JobRefused(409, environments.busy_text(env, running))
    # Production's state fences (P4 §13), before the target's host: a retiring production only goes dark.
    fenced = await production_problem(db, env, kind, opts, mem)
    if fenced is not None:
        return fenced
    target_host = target.host if target is not None else None
    if target_host is not None and not _ssh_host(target_host):
        problem = await not_built_problem(db, env, target, kind, retry_of=retry_of)
        if problem is not None:
            return problem
    elif target_host is not None and kind not in (DeploymentKind.TEARDOWN, DeploymentKind.PUBLISH) \
            and not target_host.is_pinned:
        return JobRefused(400, UNPINNED.format(host=target_host.name))
    if opts.get("forget_vms"):
        problem = _forget_vms_problem(user, kind)
        if problem is not None:
            return problem

    fenced = await environment_fence(db, env, mem, instance=instance, kind=kind, options=opts, retry_of=retry_of)
    if fenced is not None:
        return fenced

    # A deploy to an app slot.
    if kind == DeploymentKind.DEPLOY and instance is not None and instance.slot in environments.APP_SLOTS:
        problem = identity_problem(env, owner, instance, mem)
        if problem:
            return JobRefused(409, problem)
        problem = environments.attach_problem(env, owner, instance)
        if problem:
            return JobRefused(409, problem)
        if opts.get("go_live") and _go_live_needs_switch(env, mem) and not (user and user.can(Perm.TRAFFIC_SWITCH)):
            return JobRefused(403, f"Deploying {instance.slot} makes it live, which needs the traffic:switch "
                                   "permission")
    if kind == DeploymentKind.DEPLOY and instance is not None and instance.slot == environments.DATA_SLOT \
            and env.data_mode == DataMode.SLOT:
        return JobRefused(409, f"{env.name} keeps its data in its slot")
    if kind == DeploymentKind.DEPLOY and instance is not None and _chain_goes_live(env, instance, opts, mem) \
            and _go_live_needs_switch(env, mem) and not (user and user.can(Perm.TRAFFIC_SWITCH)):
        # The chain's slot deploy will go live: refused before the data server changes anything (I5).
        first = environments.target_slot(env, mem)
        return JobRefused(403, f"Deploying {env.name} makes {first} live, which needs the traffic:switch permission")

    # The environment-level kinds' own refusals.
    if kind == DeploymentKind.ACTIVATE:
        problem = await environments.activate_problem(db, env, slot, mem)
        if problem:
            return JobRefused(409, problem)
    elif kind == DeploymentKind.DISCARD:
        state = await data.discard_state(db, env, slot)
        if not state.available:
            return JobRefused(409, state.reason or "Nothing to discard")
    elif kind == DeploymentKind.REMOVE_SLOT:
        # forget_vms lets a forgettable VM blocker pass (P5 §9.5); its permissions were checked above.
        problem = await environments.remove_slot_problem(db, env, slot, mem, forget_vms=bool(opts.get("forget_vms")))
        if problem:
            return JobRefused(409, problem)
    elif kind == DeploymentKind.PUBLISH:
        problem = await environments.publish_problem(db, env)
        if problem:
            return JobRefused(409, problem)
    own = KIND_PROBLEMS.get(str(kind))
    if own is not None:
        found = await own(db=db, env=env, instance=instance, members=mem, options=opts, user=user, retry_of=retry_of)
        if isinstance(found, JobRefused):
            return found
        if found:
            return JobRefused(409, str(found))
    missing = _missing_permission(user, needs)
    if missing:
        return JobRefused(403, missing)
    return None


def _ssh_host(host: Any) -> bool:
    return (getattr(host, "provider", None) or "ssh") == "ssh"


async def _machine_of(db: AsyncSession, host: Any) -> Machine | None:
    if (host.provider or "ssh") not in ("proxmox", "esxi") or host.id is None:
        return None
    return await db.scalar(select(Machine).where(Machine.host_id == host.id))


async def not_built_problem(db: AsyncSession, env: Environment, target: Instance, kind: str, *,
                            retry_of: Deployment | None = None) -> JobRefused | None:
    """The not-built rule for a job whose target's host a provider makes (Decision 28; P4 §3.3, P5 §10.4), or
    None. A VM being removed takes only the retry of the job removing it. A deploy is allowed whatever the
    host's phase: its ``prepare`` step builds the host (and a VM's account must then be usable). Remove slot and
    the teardown are allowed on a host the environment owns in any phase. Every other kind waits until the host
    is built."""
    host = target.host
    machine = await _machine_of(db, host)
    if machine is not None and machine.stage == MachineStage.DESTROYING:
        removing = retry_of is not None and retry_of.kind in REMOVING_KINDS and kind == retry_of.kind
        if not removing:
            return JobRefused(409, VM_DESTROYING.format(vm=machine.name))
        return None
    if kind in REMOVING_KINDS and hosts.owned_by(env, host):
        return None
    if kind == DeploymentKind.DEPLOY:
        if machine is not None and machine.stage != MachineStage.READY:
            account = await db.get(ProviderAccount, machine.account_id)
            why = machines.account_problem(account)
            if why:
                name = account.name if account is not None else "Its account"
                return JobRefused(409, f"{name} can't be used: {why}")
        return None
    if ssh.host_is_built(host):
        return None
    if target.slot == environments.DATA_SLOT and machine is not None:
        return JobRefused(409, DATA_VM_NOT_MADE.format(env=env.name))
    if kind == DeploymentKind.ACTIVATE and environments.is_vm_host(host):
        # As the activate's own check words it (env_jobs._host_problem, P5 §10.4).
        return JobRefused(409, environments.VM_NOT_MADE.format(slot=target.slot or target.name))
    return JobRefused(409, NOT_BUILT.format(slot=target.slot or target.name))


def _forget_vms_problem(user: User | None, kind: str) -> JobRefused | None:
    """``forget_vms`` (P5 §9.5, §9.9): only on Remove slot or the teardown, by someone who may write VMs and
    delete environments. The environment's typed name is the API's to check, as for every removing job."""
    if kind not in REMOVING_KINDS:
        return JobRefused(409, "Only removing a slot or deleting the environment can forget its VMs")
    for permission in (Perm.MACHINES_WRITE, Perm.ENVIRONMENTS_DELETE):
        if user is None or not user.can(permission):
            return JobRefused(403, f"Forgetting a VM needs the {permission} permission")
    return None


async def control_refusal(db: AsyncSession, instance: Instance, action: str) -> str | None:
    """Why ``POST /instances/{id}/actions/{action}`` is refused for an environment member (§11), or None: start
    and restart of a stale app slot, and of any app slot while the data owner's data is held. Standalone
    instances keep their own checks (None here)."""
    if instance.environment_id is None or action not in ("start", "restart"):
        return None
    env = await environments.environment_of(db, instance)
    stale = environments.stale_of(instance)
    if stale and instance.slot in environments.APP_SLOTS:
        return f"Deploy to {instance.slot} first: it was stopped when the data was restored"
    if env is not None:
        held = await data.hold_text(db, instance)
        if held:
            return held
    return None


# Options a retry never copies, of any job of an environment (deployer.ONE_SHOT_OPTIONS as well for instance
# jobs). ``switch`` is an activate's record of its own writes (§10.2 step 2); a retry starts its own. ``then``
# is a snapshot's "delete the environment afterwards": a retried snapshot never deletes it, since the teardown
# needs environments:delete and the typed name of whoever asks for it. ``go_live`` is decided again (D11).
# Phases 4 and 5 add the typed confirmations of production and of a delete without a snapshot, the retry's own
# choices (``rebuild_data``: make a gone cluster again, empty; ``forget_vms``; ``drop_data``), each asked again.
ENV_ONE_SHOT = frozenset({"confirm", "forget_traffic", "after", "switch", "then", "go_live", "confirm_production",
                          "confirm_no_snapshot", "rebuild_data", "forget_vms", "drop_data", "then_options"})


def _retry_go_live(env: Environment, instance: Instance, parent: Deployment, members: dict[str, Instance]) -> bool:
    """Whether a retried app slot deploy goes live: by the rule as it stands now (D11), not as it stood when the
    first attempt was queued. A chained deploy that wasn't to go live (a slot just added, §9.8) still doesn't."""
    now = environments.goes_live(env, str(instance.slot), members)
    opts = parent.options or {}
    if opts.get("chain") and not opts.get("go_live"):
        return False
    return now


async def queue_job(db: AsyncSession, *, instance: Instance | None = None, environment: Environment | None = None,
                    user: User | None, kind: str = DeploymentKind.DEPLOY, retry_of: Deployment | None = None,
                    options: dict[str, Any] | None = None, needs: tuple[str, ...] = (), system: str | None = None,
                    **refs: Any) -> Deployment:
    """Add a queued job (the caller audits, commits and submits it); raise JobRefused.

    ``refs`` are the rows the job points at (``backup_id``, ``restore_backup_id``, ``snapshot_id``). A retry
    takes its kind, options, references and commit from the job it retries (``deployer.retry_values``), with
    ``options`` added on top, and is checked as its own kind. Jobs that run the live release copy the live
    release's commit. ``needs`` are permissions the user must still hold (``job_refusal``).

    For a member of an environment the row gets ``environment_id``; a slot deploy records ``options.slot`` and
    ``options.go_live`` (``environments.goes_live`` unless given). An environment-level job (``instance`` None,
    ``options.slot`` its target slot) gets its steps from ``environments.env_steps_for``. Queueing any job of an
    environment clears its chain notice, and queueing its teardown marks it ``deleting``.

    ``system`` names a queue that no person asked for: ``renewals`` (P4 §15.12) may queue only a ``certificate``
    job of an environment, with ``user`` None. It skips the permission checks, records no ``triggered_by`` and
    ``options.by = 'renewals'``, and leaves the environment's notice as it is (Decision 23). The environment's
    fences still apply.
    """
    from slipway.services import deployer  # the deployer imports data, which imports environments

    if system is not None:
        if system not in SYSTEM_KINDS:
            raise ValueError(f"{system!r} can't queue jobs")
        if kind != SYSTEM_KINDS[system] or retry_of is not None:
            raise ValueError(f"{system} may queue only a {SYSTEM_KINDS[system]} job")
        if user is not None or instance is not None or environment is None:
            raise ValueError(f"{system} queues an environment's job with no user")
    if instance is None and environment is None:
        raise ValueError("a job needs an instance or an environment")
    env = environment if environment is not None else await environments.environment_of(db, instance)
    if instance is not None and env is not None and instance.environment_id != env.id:
        raise ValueError("the instance isn't a member of that environment")
    if env is not None and env.id is not None:
        # One request at a time per environment between the checks and the insert (I2): the partial indexes
        # can't tell an activate queued beside a deploy. A no-op on SQLite, which runs one writer anyway.
        await db.execute(select(Environment.id).where(Environment.id == env.id).with_for_update())
    mem = await environments.members(db, env) if env is not None else {}
    opts_in = dict(options or {})
    if retry_of is not None:
        # A retry is checked, and queued, as the kind it retries (§8.1).
        kind = retry_of.kind or DeploymentKind.DEPLOY
        # What the retry will carry, for the checks (the queued row below takes them from retry_values).
        carried = {k: v for k, v in (retry_of.options or {}).items()
                   if k not in deployer.ONE_SHOT_OPTIONS and k not in ENV_ONE_SHOT}
        opts_in = {**carried, **opts_in}
    if env is not None and instance is not None and kind == DeploymentKind.DEPLOY:
        opts_in.setdefault("slot", instance.slot)
        if instance.slot in environments.APP_SLOTS and "go_live" not in opts_in:
            opts_in["go_live"] = (_retry_go_live(env, instance, retry_of, mem) if retry_of is not None
                                  else environments.goes_live(env, str(instance.slot), mem))
    if system is not None:
        opts_in["by"] = system
    if env is not None:
        typed = confirm_refusal(env, kind, opts_in)
        if typed is not None:
            raise typed
    refused = await job_refusal(db, instance=instance, environment=env, user=user, kind=kind, options=opts_in,
                                retry_of=retry_of, members=mem, needs=needs)
    if refused is not None:
        raise refused

    if instance is not None:
        values: dict[str, Any] = {"kind": kind, "branch": instance.branch, "previous_sha": instance.current_commit_sha,
                                  **refs}
        if retry_of is not None:
            values.update(await deployer.retry_values(db, retry_of))
            if env is not None:
                values["options"] = {k: v for k, v in (values.get("options") or {}).items() if k not in ENV_ONE_SHOT}
        values["options"] = {**(values.get("options") or {}), **opts_in}
        kind = values["kind"]
        if retry_of is None and kind != DeploymentKind.DEPLOY:
            # A data job runs the live release: it records that release's commit (§6.4).
            live = data.live_state(instance)
            if live and live.get("sha"):
                values["commit_sha"] = str(live["sha"])
                source = await db.get(Deployment, data._uuid(live.get("deployment"))) if live.get("deployment") else None
                if source is not None:
                    values.update(commit_message=source.commit_message, commit_author=source.commit_author)
        opts = values["options"]
        # The job settles the conditional steps itself when it starts; this list is what the page shows meanwhile.
        # A member gets its environment's lists (§8.4), as the deployer gives them when the job starts.
        member = {"environment": env, "members": mem} if env is not None else {}
        if env is not None and kind == DeploymentKind.DEPLOY:
            # A deploy on a provider's host lists prepare, and resize when its rule holds now (Decisions 12, 14).
            member["provider"] = await deployer.provider_steps(db, instance, env, mem)
        server = env is not None and env.data_mode == DataMode.SERVER
        steps = deployer.steps_for(
            instance, kind, snapshot=values.get("snapshot_id") is not None and kind != DeploymentKind.SNAPSHOT,
            files=bool(opts.get("files")),
            stop_app=bool(opts.get("stop_app")) and (instance.status == InstanceStatus.RUNNING or server),
            stopped=bool(opts.get("restop")) and kind in data.DATA_ONLY_KINDS, start_over=bool(opts.get("start_over")),
            rollback_of=data._uuid(opts.get("rollback_of")), seed=bool(opts.get("seed")) and kind == DeploymentKind.RESET,
            **member,
        ) if kind != DeploymentKind.DEPLOY else (
            deployer.steps_for(instance, **member) if member else deployer.new_steps(instance))
        dep = Deployment(instance_id=instance.id, environment_id=env.id if env is not None else None,
                         triggered_by_id=user.id if user else None, log="",
                         retry_of_id=retry_of.id if retry_of else None, steps=steps, **values)
    else:
        assert env is not None
        if kind not in data.ENV_KINDS:
            raise ValueError(f"{kind!r} isn't an environment-level job")
        values = {"branch": env.branch, **refs}
        target = mem.get(opts_in.get("slot")) if opts_in.get("slot") else None
        if kind == DeploymentKind.ACTIVATE and target is not None:
            # An activate records the target slot's live commit, and the slot traffic moves from.
            live = data.live_state(target) or {}
            values["commit_sha"] = str(live.get("sha") or target.current_commit_sha or "") or None
            active = environments.active_member(env, mem)
            opts_in.setdefault("from_slot", active.slot if active is not None else None)
            values["previous_sha"] = active.current_commit_sha if active is not None else None
        if retry_of is not None:
            values.update(commit_sha=retry_of.commit_sha, previous_sha=retry_of.previous_sha)
        dep = Deployment(instance_id=None, environment_id=env.id, kind=kind, options=opts_in,
                         triggered_by_id=user.id if user else None, log="",
                         retry_of_id=retry_of.id if retry_of else None,
                         steps=environments.env_steps_for(env, kind, opts_in, mem), **values)
    db.add(dep)
    if env is not None and system is None:
        # Cleared by any later job of the environment (§8.5), but not by the renewal loop's: a renewal must never
        # erase a stopped chain's notice and its Continue follow-up (Decision 23).
        env.notice = None
        if kind == DeploymentKind.TEARDOWN:
            env.status = EnvironmentStatus.DELETING
    try:
        await db.flush()
    except IntegrityError as exc:
        # ux_deployments_one_active (per instance) or one of the environment indexes: another request queued a
        # job at the same moment.
        await db.rollback()
        if env is not None:
            raise JobRefused(409, f"A job is already running for {env.name}; wait for it to finish") from exc
        raise JobRefused(409, BUSY) from exc
    return dep

