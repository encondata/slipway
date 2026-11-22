"""The VM snapshot jobs (phase 5 §9.6, §9.7, §9.8, §9.12, §10.1): take a VM snapshot, revert to one, delete one.

A VM snapshot is the whole disk of the one app slot's VM (D11): code, data, Docker and Slipway's release folders.
The three kinds run on the slot instance (the data owner in mode ``slot``) and hold both of the environment's
runner keys. Their steps (P5 §10.1):

* ``vm_snapshot``: ``check, vm_snapshot, prune``;
* ``vm_revert``: ``check, ⟨vm_snapshot⟩, vm_revert, wait, vm_settle, restart, traffic`` (``vm_snapshot`` takes a
  ``pre_revert`` snapshot unless ``skip_pre_revert``, which ZFS forces, D13 and D23);
* ``vm_drop``: ``check, vm_drop``.

Every refusal comes in ``check``, before any change (M9): a revert to a snapshot whose identity values can't be
read is refused there too, and deleting the snapshot a revert's hold names is refused. The rows are written before Slipway waits on the
hypervisor (M5): a snapshot's row is committed ``pending`` before its task starts, and the provider writes
``ready`` or ``failed`` itself (§7.6, §8.5). ``vm_settle`` brings Slipway's records back to the snapshot in one
transaction: the instance's app state, fresh data, live commit and identity, the data owner's hold cleared, the
identity secrets put back through phase 3's ``secrets_version`` compare-and-set, the VM's applied size, and the
backups taken since marked missing.

Each kind's queue-time refusals are registered in ``jobs.KIND_PROBLEMS`` when this module is imported (Decision
45; the deployer imports it). The typed name and ``data:reset`` of a revert are the API's (``revert_request_problem``
is the helper it calls, S22) and a retry's (S20). The deployer runs the jobs (``run``), lists their steps
(``step_rows``, ``job_steps``), records a failed revert's hold (``failed_fields``) and recovers an interrupted one
(``recover``).
"""

from __future__ import annotations

import contextlib
import shlex
import uuid
from collections import Counter
from collections.abc import Awaitable, Callable, Mapping
from datetime import datetime
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.core.permissions import Perm
from slipway.db.base import utcnow
from slipway.db.session import get_sessionmaker, session_scope
from slipway.models import (
    Backup,
    BackupStatus,
    DataMode,
    Deployment,
    DeploymentKind,
    Environment,
    Instance,
    InstanceStatus,
    Machine,
    MachineSnapshot,
    MachineStage,
    SnapshotMode,
    SnapshotReason,
    User,
)
from slipway.services import audit, data, environments, jobs, machines, ssh, vmnet
from slipway.services.vmtypes import MachineError

KINDS = (DeploymentKind.VM_SNAPSHOT.value, DeploymentKind.VM_REVERT.value, DeploymentKind.VM_DROP.value)
MANUAL_LIMIT = 10  # VM snapshots a person may keep of one VM (P5 §14)
AUTOMATIC = (SnapshotReason.PRE_RESIZE.value, SnapshotReason.PRE_REVERT.value)
WAIT_POLL = 5.0  # seconds between SSH tries in ``wait``
WAIT_TRIES = 120  # ten minutes of tries; the step's own limit is ten minutes too
# A revert's steps that may leave the VM's disk at the snapshot while Slipway's records still name a later
# release: a failure or a restart in one of them holds the data (§9.12).
REVERTING_STEPS = ("vm_revert", "wait", "vm_settle")
# ``options.revert_started``: False while ``vm_revert`` runs the provider's own refusals, True from the moment the
# provider is about to start the hypervisor's revert task. A ``vm_revert`` that failed or was cut off while it was
# still False changed nothing, so it holds nothing (§9.12). A deployment without the key (one recorded before it
# existed) holds, as it always did.
REVERT_STARTED = "revert_started"

SHAPE_TEXT = "VM snapshots are for an environment whose one slot runs on a VM Slipway made"
LIMIT_TEXT = "{vm} has {n} VM snapshots you took; delete one first"
NOT_FOUND_TEXT = "That VM snapshot isn't one of {env}'s"
IDENTITY_LOST_TEXT = ("{name}'s identity values can't be read any more (SLIPWAY_ENCRYPTION_KEY changed): put the old "
                      "key back or delete it")
IDENTITY_CLEARED_TEXT = "{name}'s identity values were erased when SLIPWAY_ENCRYPTION_KEY changed: delete it"
HELD_TEXT = ("{env}'s data is held until {vm} is reverted to {name} again, so Slipway keeps {name}: revert to it "
             "first")


# ------------------------------------------------------------------------------------------------ names


def step_rows(kind: str, *, vm: str, names: Mapping[str, str], snapshot: str | None = None,
              pre_revert: bool = True) -> list[dict[str, Any]]:
    """The steps of a VM job, named after the VM and the snapshot (P5 §10.1, §10.2). ``names`` is the
    deployer's catalogue (``restart`` and ``traffic`` keep its names). ``snapshot`` None: the name isn't known
    yet (the queued list before the job starts)."""
    which = snapshot or "the VM snapshot"
    own = {
        "check": f"Check {vm} and its VM snapshots",
        "vm_snapshot": (f"Take a VM snapshot of {vm}" if kind == DeploymentKind.VM_SNAPSHOT
                        else "Take a VM snapshot first"),
        "prune": "Delete old VM snapshots",
        "vm_revert": f"Revert {vm} to {which}",
        "wait": f"Wait for {vm} to answer",
        "vm_settle": f"Bring Slipway's records back to {which}",
        "vm_drop": f"Delete the VM snapshot {snapshot}" if snapshot else "Delete the VM snapshot",
    }
    if kind == DeploymentKind.VM_SNAPSHOT:
        keys = ["check", "vm_snapshot", "prune"]
    elif kind == DeploymentKind.VM_REVERT:
        keys = ["check", *(["vm_snapshot"] if pre_revert else []), "vm_revert", "wait", "vm_settle", "restart",
                "traffic"]
    elif kind == DeploymentKind.VM_DROP:
        keys = ["check", "vm_drop"]
    else:
        raise ValueError(f"{kind!r} isn't a VM snapshot job")
    return [{"key": k, "name": own.get(k) or names.get(k, k), "status": "pending"} for k in keys]


def _snapshot_id(options: Mapping[str, Any] | None) -> uuid.UUID | None:
    return data._uuid((options or {}).get("vm_snapshot_id"))


async def machine_of(db: AsyncSession, instance: Instance) -> Machine | None:
    """The machine behind ``instance``'s host, or None when its host isn't a VM Slipway made."""
    if instance.host_id is None:
        return None
    return await db.scalar(select(Machine).where(Machine.host_id == instance.host_id))


def takes_pre_revert(machine: Machine | None, options: Mapping[str, Any] | None) -> bool:
    """A revert takes a ``pre_revert`` snapshot first, unless asked not to or the storage reverts only to its
    newest snapshot (ZFS, where one would be newer than the target and Proxmox would refuse the rollback)."""
    if (options or {}).get("skip_pre_revert"):
        return False
    return not (machine is not None and machine.snapshot_mode == SnapshotMode.NEWEST_ONLY.value)


async def job_steps(db: AsyncSession, instance: Instance, kind: str, options: Mapping[str, Any] | None,
                    names: Mapping[str, str]) -> list[dict[str, Any]]:
    """A VM job's steps with the VM's and the snapshot's names, as the job lists them when it starts (and as the
    API may list them when it queues one)."""
    machine = await machine_of(db, instance)
    vm = machine.name if machine is not None else data.host_label(instance)
    row_id = _snapshot_id(options)
    row = await db.get(MachineSnapshot, row_id) if row_id is not None else None
    return step_rows(kind, vm=vm, names=names, snapshot=row.name if row is not None else None,
                     pre_revert=takes_pre_revert(machine, options))


# --------------------------------------------------------------------------------- queue-time refusals


def _permission_refusal(user: User | None, what: str, *permissions: str) -> jobs.JobRefused | None:
    for permission in permissions:
        if user is None or not user.can(permission):
            return jobs.JobRefused(403, f"{what} needs the {permission} permission")
    return None


def shape_problem(env: Environment, instance: Instance | None, members: Mapping[str, Instance],
                  machine: Machine | None) -> str | None:
    """D11's shape rule: one app slot, in data mode ``slot``, on a ready VM of this environment (never the data
    VM). The refusal text, or None."""
    apps = environments.app_members(dict(members))
    if (instance is None or machine is None or env.data_mode != DataMode.SLOT
            or instance.slot not in environments.APP_SLOTS or len(apps) != 1 or machine.slot == environments.DATA_SLOT
            or machine.environment_id != env.id or machine.stage != MachineStage.READY):
        return SHAPE_TEXT
    return None


def storage_text(machine: Machine) -> str:
    """``<storage> (<type>) can't take VM snapshots of <vm>`` (D23)."""
    spec = machine.spec or {}
    storage = spec.get("storage") or spec.get("datastore") or "Its storage"
    return f"{storage} ({spec.get('storage_type') or 'unknown'}) can't take VM snapshots of {machine.name}"


async def _manual_count(db: AsyncSession, machine: Machine) -> int:
    rows = await db.scalars(select(MachineSnapshot.id).where(
        MachineSnapshot.machine_id == machine.id, MachineSnapshot.reason == SnapshotReason.MANUAL.value,
        MachineSnapshot.status.in_(("pending", "ready"))))
    return len(list(rows))


def _account_refusal(machine: Machine) -> str | None:
    why = machines.account_problem(machine.account)
    if why:
        return machines.account_refusal(machine.account, why)
    return None


async def snapshot_problem(*, db: AsyncSession, env: Environment, instance: Instance | None,
                           members: Mapping[str, Instance], options: Mapping[str, Any], user: User | None,
                           retry_of: Deployment | None) -> jobs.JobRefused | str | None:
    """§9.6's refusals of Take a VM snapshot (a job running and the owner's hold are ``job_refusal``'s)."""
    refused = _permission_refusal(user, "Taking a VM snapshot", Perm.MACHINES_WRITE)
    if refused is not None:
        return refused
    machine = await machine_of(db, instance) if instance is not None else None
    problem = shape_problem(env, instance, members, machine)
    if problem:
        return problem
    assert machine is not None
    if machine.snapshot_mode == SnapshotMode.NONE.value:
        return storage_text(machine)
    count = await _manual_count(db, machine)
    if count >= MANUAL_LIMIT:
        return LIMIT_TEXT.format(vm=machine.name, n=count)
    return _account_refusal(machine)


async def _target_row(db: AsyncSession, env: Environment, machine: Machine | None,
                      options: Mapping[str, Any]) -> MachineSnapshot | str:
    """The VM snapshot a revert or a delete names, when it is this environment's machine's; else the refusal."""
    row_id = _snapshot_id(options)
    row = await db.get(MachineSnapshot, row_id) if row_id is not None else None
    if row is None or machine is None or row.machine_id != machine.id:
        return NOT_FOUND_TEXT.format(env=env.name)
    return row


def identity_unreadable(row: MachineSnapshot) -> bool:
    """The row recorded identity values (its fingerprint isn't the one of no keys) that read as None now: no
    configured key decrypts them, or ``rotate-encryption-key --clear-unreadable`` erased them."""
    return row.identity is None and row.identity_fp != data.identity_fp(row.id, [], None)


async def identity_problem(db: AsyncSession, row: MachineSnapshot) -> str | None:
    """Why a revert to ``row`` is refused for its identity values, or None (§9.7). Its data was made with them,
    and without them Slipway could neither put the secrets back nor keep ``live_identity`` true."""
    if not identity_unreadable(row):
        return None
    erased = await db.scalar(select(MachineSnapshot.id).where(MachineSnapshot.id == row.id,
                                                              MachineSnapshot.identity.is_(None)))
    return (IDENTITY_CLEARED_TEXT if erased is not None else IDENTITY_LOST_TEXT).format(name=row.name)


async def held_for(db: AsyncSession, env: Environment, instance: Instance, machine: Machine,
                   row: MachineSnapshot) -> str | None:
    """The refusal of deleting ``row`` while the data owner's hold is a revert's to it (§9.8, §9.12): that hold
    asks for a revert to ``row`` again, which needs the snapshot. None otherwise."""
    owner = await data.owner_for(db, instance)
    dirty = owner.data_dirty or {}
    last = dirty.get("last") or {}
    if not dirty.get("hold") or last.get("kind") != DeploymentKind.VM_REVERT.value:
        return None
    dep_id = data._uuid(last.get("deployment_id"))
    dep = await db.get(Deployment, dep_id) if dep_id is not None else None
    if dep is None or _snapshot_id(dep.options) != row.id:
        return None
    return HELD_TEXT.format(env=env.name, vm=machine.name, name=row.name)


async def newer_rows(db: AsyncSession, row: MachineSnapshot) -> list[MachineSnapshot]:
    """Slipway's own ready VM snapshots of the machine taken after ``row``."""
    return list(await db.scalars(
        select(MachineSnapshot).where(MachineSnapshot.machine_id == row.machine_id, MachineSnapshot.id != row.id,
                                      MachineSnapshot.status == "ready", MachineSnapshot.taken_at > row.taken_at)
        .order_by(MachineSnapshot.taken_at)))


def zfs_text(newer: list[str], newest: str) -> str:
    return (f"Proxmox can roll ZFS back only to the newest VM snapshot; {', '.join(newer)} "
            f"{'is' if len(newer) == 1 else 'are'} newer. Delete {'it' if len(newer) == 1 else 'them'} first, "
            f"or revert to {newest}")


async def revert_problem(*, db: AsyncSession, env: Environment, instance: Instance | None,
                         members: Mapping[str, Instance], options: Mapping[str, Any], user: User | None,
                         retry_of: Deployment | None) -> jobs.JobRefused | str | None:
    """§9.7's refusals of Revert to a VM snapshot, as Slipway's records show them (the hypervisor is read in
    ``check``). The owner's hold doesn't refuse it: a revert is one way out of a hold."""
    refused = _permission_refusal(user, "Reverting to a VM snapshot", Perm.MACHINES_WRITE, Perm.DATA_RESET)
    if refused is not None:
        return refused
    machine = await machine_of(db, instance) if instance is not None else None
    row = await _target_row(db, env, machine, options)
    if isinstance(row, str):
        return row
    lost = await identity_problem(db, row)
    if lost:
        return lost
    if row.status != "ready":
        return f"The VM snapshot {row.name} isn't ready ({row.status})"
    problem = shape_problem(env, instance, members, machine)
    if problem:
        return problem
    assert machine is not None
    if machine.snapshot_mode == SnapshotMode.NEWEST_ONLY.value:
        newer = await newer_rows(db, row)
        if newer:
            return zfs_text([r.name for r in newer], newer[-1].name)
    return _account_refusal(machine)


async def drop_problem(*, db: AsyncSession, env: Environment, instance: Instance | None,
                       members: Mapping[str, Instance], options: Mapping[str, Any], user: User | None,
                       retry_of: Deployment | None) -> jobs.JobRefused | str | None:
    """§9.8's refusals of Delete a VM snapshot."""
    refused = _permission_refusal(user, "Deleting a VM snapshot", Perm.MACHINES_WRITE)
    if refused is not None:
        return refused
    machine = await machine_of(db, instance) if instance is not None else None
    row = await _target_row(db, env, machine, options)
    if isinstance(row, str):
        return row
    if row.status == "pending":
        return f"The VM snapshot {row.name} is still being taken; wait for it to finish"
    assert instance is not None and machine is not None
    return await held_for(db, env, instance, machine, row)


def revert_request_problem(env: Environment, confirm: str | None, user: User | None) -> jobs.JobRefused | None:
    """What ``POST /environments/{id}/vm-snapshots/{sid}/revert`` checks first, in P5 test 47's order: the typed
    name (422), then ``machines:write`` and ``data:reset`` (403). For the API (S22) and a revert's retry (S20)."""
    if (confirm or "") != env.name:
        return jobs.JobRefused(422, f"Type the environment's name, {env.name}, exactly to confirm")
    return _permission_refusal(user, "Reverting to a VM snapshot", Perm.MACHINES_WRITE, Perm.DATA_RESET)


jobs.KIND_PROBLEMS[DeploymentKind.VM_SNAPSHOT.value] = snapshot_problem
jobs.KIND_PROBLEMS[DeploymentKind.VM_REVERT.value] = revert_problem
jobs.KIND_PROBLEMS[DeploymentKind.VM_DROP.value] = drop_problem


# ------------------------------------------------------------------------------------------- the rows


def _sizes(value: Mapping[str, Any] | None) -> dict[str, int] | None:
    try:
        return {k: int(value[k]) for k in machines.SIZE_KEYS} if value else None
    except (KeyError, TypeError, ValueError):
        return None


async def new_row(mctx: machines.MachineContext, *, reason: str, note: str | None = None) -> MachineSnapshot:
    """A VM snapshot's row, committed ``pending`` before its task starts (M5): the slot instance's app state,
    live commit and fresh data, the data owner's identity values and their fingerprint, the names of its ready
    backups, and the VM's applied size (§9.6 step 2). One builder for ``manual``, ``pre_revert`` and (through
    ``machines.pre_resize_row``, both providers) ``pre_resize`` rows, so a revert to any of them brings back the
    identity the VM's data was made with."""
    async with session_scope() as db:
        machine = await db.get(Machine, mctx.machine.id)
        if machine is None:
            raise MachineError(f"{mctx.vm} was removed meanwhile; Slipway changed nothing")
        instance = await db.scalar(select(Instance).where(Instance.host_id == machine.host_id))
        if instance is None:
            instance = await db.scalar(select(Instance).where(Instance.environment_id == machine.environment_id,
                                                              Instance.slot == machine.slot))
        owner = await data.owner_for(db, instance) if instance is not None else None
        taken = set(await db.scalars(select(MachineSnapshot.name).where(MachineSnapshot.machine_id == machine.id)))
        backups = list(await db.scalars(
            select(Backup.name).where(Backup.instance_id == owner.id, Backup.status == BackupStatus.READY)
            .order_by(Backup.taken_at))) if owner is not None else []
        identity = dict(owner.live_identity or {}) if owner is not None else {}
        row_id = uuid.uuid4()
        now = mctx.now()
        row = MachineSnapshot(
            id=row_id, machine_id=machine.id, name=vmnet.next_snapshot_name(now, taken), reason=reason,
            status="pending", deployment_id=mctx.deployment_id,
            commit_sha=instance.current_commit_sha if instance is not None else None,
            app_state=dict(instance.app_state) if instance is not None and instance.app_state else None,
            fresh_data=instance.fresh_data if instance is not None else None,
            identity=identity or None, identity_fp=data.identity_fp(row_id, sorted(identity), identity),
            backups=backups, sizes=_sizes(machine.applied) or dict(machine.size),
            note=ssh.clip(note, 300) if note else None, taken_at=now, created_by_id=mctx.user_id,
        )
        db.add(row)
    return row


async def _row(row_id: uuid.UUID) -> MachineSnapshot | None:
    async with get_sessionmaker()() as db:
        return await db.get(MachineSnapshot, row_id)


# ---------------------------------------------------------------------------------------------- the jobs


class _VmRun:
    """One VM job: its machine, its steps and (in a revert, from ``wait`` on) its SSH session to the VM."""

    def __init__(self, job: Any, sink: Any, steps: Any, connect: Any, mctx: machines.MachineContext) -> None:
        self.job, self.sink, self.steps, self.connect, self.mctx = job, sink, steps, connect, mctx
        self.row: MachineSnapshot | None = None  # the snapshot a revert or a delete names
        self.names: Counter[str] = Counter()  # the names on the hypervisor, as ``check`` read them
        self.remote: ssh.RemoteSession | None = None
        self.lost: list[str] = []  # backups vm_settle found gone
        self.quiesced: bool | None = None  # ESXi: whether the last snapshot this job took was quiesced

    @property
    def vm(self) -> str:
        return self.mctx.vm

    @property
    def instance(self) -> Instance:
        return self.job.instance

    async def step(self, key: str, body: Callable[[], Awaitable[tuple[str, str | None]]]) -> None:
        from slipway.services import deployer  # the deployer imports this module

        async def guarded() -> tuple[str, str | None]:
            try:
                return await body()
            except MachineError as exc:
                raise deployer.DeployError(exc.text) from None

        await deployer._timed_step(self.steps, self.sink, key, self.job.provider, guarded)

    async def save_options(self, **values: Any) -> None:
        from slipway.services import deployer

        await deployer._save_options(self.job, **values)

    # ---------------------------------------------------------------------------- shared checks

    async def load_target(self) -> MachineSnapshot:
        row_id = _snapshot_id(self.job.options)
        row = await _row(row_id) if row_id is not None else None
        if row is None or row.machine_id != self.mctx.machine.id:
            raise MachineError(NOT_FOUND_TEXT.format(env=self.mctx.env.name))
        self.row = row
        return row

    async def shape(self) -> None:
        """The run-time half of the queue's refusals: D11's shape and a usable account."""
        async with get_sessionmaker()() as db:
            env = await db.get(Environment, self.mctx.env.id)
            machine = await db.get(Machine, self.mctx.machine.id)
            instance = await db.get(Instance, self.instance.id)
            mem = await environments.members(db, env) if env is not None else {}
        if env is None or machine is None:
            raise MachineError(f"{self.vm} was removed meanwhile; Slipway changed nothing")
        problem = shape_problem(env, instance, mem, machine) or _account_refusal(machine)
        if problem:
            raise MachineError(problem)

    async def describe(self) -> machines.MachineState:
        """The VM as the hypervisor has it, which must be Slipway's (M2); its snapshot names are kept."""
        mctx = self.mctx
        state = await mctx.provider.describe(mctx)
        if state.error:
            raise MachineError(f"Slipway can't read {self.vm} on {mctx.account.name}: {state.error}")
        if not state.exists:
            if state.hidden:
                raise MachineError(f"{state.why_not_ours}; Slipway changed nothing")
            raise MachineError(machines.lost_text(mctx.machine, env=mctx.env))
        if not state.ours:
            why = state.why_not_ours or f"{self.vm} doesn't carry Slipway's markers any more"
            raise MachineError(f"{why}; Slipway changed nothing")
        self.names = Counter(s.name for s in state.snapshots)
        return state

    async def settle(self) -> list[str]:
        """Rows the hypervisor now accounts for (§9.6 Retry, §9.12): a ``pending`` or ``failed`` row whose name
        is there once becomes ``ready``; a ``pending`` one that isn't there ``failed``; a ``ready`` one gone
        ``missing``. Rows of this job are left to it. Returns the log lines."""
        lines: list[str] = []
        label = self.mctx.label
        async with session_scope() as db:
            rows = await db.scalars(select(MachineSnapshot).where(MachineSnapshot.machine_id == self.mctx.machine.id))
            for row in rows:
                if row.deployment_id == self.job.deployment_id:
                    continue
                count = self.names.get(row.name, 0)
                if row.status == "failed" and identity_unreadable(row):
                    continue  # rotate-encryption-key marked it: it can't be reverted to, whatever the hypervisor has
                if row.status in ("pending", "failed", "missing") and count == 1:
                    row.status = "ready"
                    lines.append(f"The VM snapshot {row.name} is on {label} after all: it is ready")
                elif row.status == "pending" and count == 0:
                    row.status = "failed"
                    lines.append(f"The VM snapshot {row.name} isn't on {label}: it failed")
                elif row.status == "ready" and count == 0:
                    row.status = "missing"
                    lines.append(f"The VM snapshot {row.name} is gone from {label}")
        for line in lines:
            await self.sink.line(line)
        return lines

    async def wait_idle(self) -> None:
        await machines.tasks.wait_idle(self.mctx)

    # ------------------------------------------------------------------------------------- snapshot

    async def take(self, reason: str, note: str | None = None) -> MachineSnapshot:
        """Take a VM snapshot: the row first, then the provider's task, then ``machine.snapshot``."""
        mctx = self.mctx
        row = await new_row(mctx, reason=reason, note=note)
        if reason == SnapshotReason.PRE_REVERT.value:
            await self.save_options(vm_snapshot_pre=row.id.hex)
        else:
            await self.save_options(vm_snapshot_taken=row.id.hex)
        await self.sink.line(f"Taking the VM snapshot {row.name} of {self.vm}")
        try:
            quiesced = await mctx.provider.snapshot(mctx, row)
        except MachineError:
            await self._give_up(row)
            raise
        except BaseException:
            # Cut off (the step's limit, Slipway stopping): the row is failed, not left pending, so the cap and
            # Delete don't count it as still being taken. A snapshot that appears later is there once, and the
            # next VM job's settle makes the row ready (§9.6 Retry).
            async def cut_off() -> None:
                async with session_scope() as db:
                    await db.execute(update(MachineSnapshot).where(MachineSnapshot.id == row.id,
                                                                   MachineSnapshot.status == "pending")
                                     .values(status="failed"))

            with contextlib.suppress(Exception):
                await machines.shielded(cut_off())
            raise
        async with session_scope() as db:
            stored = await db.get(MachineSnapshot, row.id)
            if stored is not None and stored.status == "pending":
                stored.status = "ready"  # a provider that returned has taken it
            machine = await db.get(Machine, mctx.machine.id)
            audit.record(db, "machine.snapshot", actor=self.job.user, target=machine,
                         summary=f"Took the VM snapshot {row.name} of {self.vm}",
                         details={"name": self.vm, "snapshot": row.name, "reason": reason,
                                  "quiesced": quiesced if mctx.machine.provider == "esxi" else None})
        row.status = "ready"
        self.quiesced = quiesced
        return row

    async def _give_up(self, row: MachineSnapshot) -> None:
        """A snapshot whose provider call failed before its task started is ``failed``; one whose task Slipway
        started stays as the provider left it (a task that outlived the wait may still finish, D24)."""
        last = self.mctx.machine.last_task or {}
        started = last.get("deployment_id") == (self.job.deployment_id.hex if self.job.deployment_id else None)
        if started:
            return
        async with session_scope() as db:
            await db.execute(update(MachineSnapshot).where(MachineSnapshot.id == row.id,
                                                           MachineSnapshot.status == "pending")
                             .values(status="failed"))

    def taken_note(self, row: MachineSnapshot) -> str:
        note = f"Took {row.name}"
        if row.note == "The task ended late":
            note += ". The task ended late"
        if self.mctx.machine.provider == "esxi" and self.quiesced is False:
            note += ". VMware Tools couldn't quiesce the file systems, so it is crash-consistent"
        return note

    async def snapshot_job(self) -> None:
        async def check() -> tuple[str, str | None]:
            await self.shape()
            machine = self.mctx.machine
            if machine.snapshot_mode == SnapshotMode.NONE.value:
                raise MachineError(storage_text(machine))
            await self.describe()
            await self.settle()
            async with get_sessionmaker()() as db:
                count = await _manual_count(db, machine)
            if count >= MANUAL_LIMIT:
                raise MachineError(LIMIT_TEXT.format(vm=self.vm, n=count))
            await self.wait_idle()
            return "succeeded", f"{self.vm} is Slipway's; {sum(self.names.values())} VM snapshots on it"

        async def take() -> tuple[str, str | None]:
            note = self.job.options.get("note")
            row = await self.take(SnapshotReason.MANUAL.value, str(note) if note else None)
            return "succeeded", self.taken_note(row)

        await self.step("check", check)
        await self.step("vm_snapshot", take)
        await self.prune_step()

    # ---------------------------------------------------------------------------------------- prune

    async def prune_step(self) -> None:
        """Delete the oldest ``pre_resize`` and ``pre_revert`` snapshots beyond ``keep_vm_snapshots`` (§9.6 step
        3). Never a ``manual`` one, never a name that appears twice on the hypervisor. The snapshot the job took
        stands whatever happens here, so a failure only warns."""
        from slipway.services import deployer

        mctx = self.mctx
        kept_text = "Nothing to delete"

        async def body() -> tuple[str, str | None]:
            async with get_sessionmaker()() as db:
                machine = await db.get(Machine, mctx.machine.id)
                keep = int(machine.keep_vm_snapshots or vmnet.DEFAULT_KEEP_VM_SNAPSHOTS)
                rows = list(await db.scalars(
                    select(MachineSnapshot).where(MachineSnapshot.machine_id == machine.id,
                                                  MachineSnapshot.reason.in_(AUTOMATIC),
                                                  MachineSnapshot.status != "pending")
                    .order_by(MachineSnapshot.taken_at.desc())))
            ready = [r for r in rows if r.status == "ready"]
            old = ready[keep:] + [r for r in rows if r.status in ("failed", "missing")]
            if not old:
                return "skipped", kept_text
            try:
                await self.describe()
            except MachineError as exc:
                return "warning", f"Slipway didn't delete old VM snapshots: {exc.text}"
            deleted, left = [], []
            for row in sorted(old, key=lambda r: r.taken_at):
                count = self.names.get(row.name, 0)
                if count > 1:
                    await self.sink.line(f"{mctx.account.name} has {count} VM snapshots named {row.name}; Slipway "
                                         "won't pick one, so it keeps them")
                    left.append(row.name)
                    continue
                try:
                    if count == 1:
                        await mctx.provider.drop_snapshot(mctx, row)
                except MachineError as exc:
                    return "warning", f"Slipway couldn't delete the VM snapshot {row.name}: {exc.text}"
                await self._forget_row(row, why="prune")
                deleted.append(row.name)
            if left and not deleted:
                return "warning", f"Kept {', '.join(left)}: each name appears more than once"
            note = f"Deleted {', '.join(deleted)}" if deleted else kept_text
            if left:
                return "warning", f"{note}. Kept {', '.join(left)}: each name appears more than once"
            return "succeeded", note

        async def guarded() -> tuple[str, str | None]:
            try:
                return await body()
            except (MachineError, deployer.DeployError) as exc:
                return "warning", getattr(exc, "text", None) or str(exc)

        await deployer._timed_step(self.steps, self.sink, "prune", self.job.provider, guarded)

    async def _forget_row(self, row: MachineSnapshot, *, why: str) -> None:
        """Delete a VM snapshot's row and audit ``machine.snapshot_delete`` (the shape ESXi's resize writes)."""
        async with session_scope() as db:
            await db.execute(delete(MachineSnapshot).where(MachineSnapshot.id == row.id))
            machine = await db.get(Machine, self.mctx.machine.id)
            audit.record(db, "machine.snapshot_delete", actor=self.job.user, target=machine,
                         summary=f"Deleted the VM snapshot {row.name} of {self.vm}",
                         details={"name": self.vm, "snapshot": row.name, "reason": row.reason, "why": why})

    # ------------------------------------------------------------------------------------------ drop

    async def drop_job(self) -> None:
        mctx = self.mctx

        async def check() -> tuple[str, str | None]:
            row = await self.load_target()
            if row.status == "pending":
                raise MachineError(f"The VM snapshot {row.name} is still being taken; wait for it to finish")
            async with get_sessionmaker()() as db:
                instance = await db.get(Instance, self.instance.id)
                held = await held_for(db, mctx.env, instance, mctx.machine, row) if instance is not None else None
            if held:
                raise MachineError(held)
            why = machines.account_problem(mctx.account)
            if why:
                raise MachineError(machines.account_refusal(mctx.account, why))
            state = await mctx.provider.describe(mctx)
            if state.error:
                raise MachineError(f"Slipway can't read {self.vm} on {mctx.account.name}: {state.error}")
            if not state.exists and state.hidden:
                raise MachineError(f"{state.why_not_ours}; Slipway changed nothing")
            if state.exists and not state.ours:
                raise MachineError(f"{state.why_not_ours}; Slipway changed nothing")
            self.names = Counter(s.name for s in state.snapshots)
            count = self.names.get(row.name, 0)
            if count > 1:
                raise MachineError(f"{mctx.account.name} has {count} VM snapshots named {row.name}; Slipway won't "
                                   "pick one")
            if count == 1:
                await self.wait_idle()
                return "succeeded", f"{row.name} is on {mctx.label}"
            return "succeeded", f"{row.name} is gone from {mctx.account.name}"

        async def drop() -> tuple[str, str | None]:
            row = self.row
            assert row is not None
            if self.names.get(row.name, 0) == 1:
                await self.sink.line(f"Deleting the VM snapshot {row.name} of {self.vm}")
                await mctx.provider.drop_snapshot(mctx, row)
                note = f"Deleted {row.name}"
            else:
                note = f"{row.name} was already gone from {mctx.account.name}; Slipway forgot it"
            await self._forget_row(row, why="deleted")
            return "succeeded", note

        await self.step("check", check)
        await self.step("vm_drop", drop)

    # ---------------------------------------------------------------------------------------- revert

    async def revert_job(self, stack: contextlib.AsyncExitStack) -> None:
        mctx = self.mctx

        async def check() -> tuple[str, str | None]:
            await self.shape()
            row = await self.load_target()
            async with get_sessionmaker()() as db:
                lost = await identity_problem(db, row)
            if lost:
                raise MachineError(lost)
            if row.status not in ("ready", "missing"):
                raise MachineError(f"The VM snapshot {row.name} isn't ready ({row.status})")
            state = await self.describe()
            await self.settle()
            count = self.names.get(row.name, 0)
            if count == 0:
                raise MachineError(f"The VM snapshot {row.name} is gone from {mctx.account.name}")
            if count > 1:
                raise MachineError(f"{mctx.account.name} has {count} VM snapshots named {row.name}; Slipway won't "
                                   "pick one")
            if (state.snapshot_mode or mctx.machine.snapshot_mode) == SnapshotMode.NEWEST_ONLY.value:
                newest = next((s for s in state.snapshots if s.newest), None)
                if newest is not None and newest.name != row.name:
                    target = next((s for s in state.snapshots if s.name == row.name), None)
                    newer = [s.name for s in state.snapshots
                             if s.name != row.name and target is not None and target.created is not None
                             and s.created is not None and s.created > target.created] or [newest.name]
                    raise MachineError(zfs_text(newer, newest.name))
            await self.wait_idle()
            return "succeeded", f"{row.name} is on {mctx.label} once"

        async def pre() -> tuple[str, str | None]:
            first = data._uuid(self.job.options.get("vm_snapshot_pre"))
            kept = await _row(first) if first is not None else None
            if kept is not None and kept.machine_id == mctx.machine.id and kept.status == "ready":
                return "skipped", f"Kept {kept.name}, which the first attempt took"
            row = await self.take(SnapshotReason.PRE_REVERT.value, f"Before reverting to {self.row.name}")
            return "succeeded", self.taken_note(row)

        async def revert() -> tuple[str, str | None]:
            row = self.row
            assert row is not None
            await self.sink.line(f"Reverting {self.vm} to {row.name}: its disk goes back to {_when(row.taken_at)}")
            # The provider's own refusals (the snapshot gone or twice, a task still running, the account, the VM
            # not Slipway's) change nothing; only once it is about to start the revert task may the disk move.
            await self.save_options(**{REVERT_STARTED: False})

            async def reached() -> None:
                await self.save_options(**{REVERT_STARTED: True})

            mctx.before_change = reached
            try:
                await mctx.provider.revert(mctx, row)
            finally:
                mctx.before_change = None
            return "succeeded", f"{self.vm} is back at {row.name}"

        async def wait() -> tuple[str, str | None]:
            self.remote = await self._answer(stack)
            return "succeeded", f"{self.vm} answers SSH with its pinned key"

        async def settle() -> tuple[str, str | None]:
            return await self._settle_records()

        await self.step("check", check)
        if self.steps.listed("vm_snapshot"):
            await self.step("vm_snapshot", pre)
        await self.step("vm_revert", revert)
        await self.step("wait", wait)
        await self.step("vm_settle", settle)
        await self.step("restart", self._restart)
        await self._traffic()

    async def _answer(self, stack: contextlib.AsyncExitStack) -> ssh.RemoteSession:
        """``wait``: an SSH session with the pinned key (the snapshot was taken after the first boot, so the key
        is the same; another key fails, and nothing is pinned)."""
        from slipway.services import deployer

        await deployer._refresh_host(self.mctx.host)
        host = self.mctx.host
        target = ssh.SSHTarget.from_host(host)
        address = host.address
        for attempt in range(WAIT_TRIES):
            try:
                async with self.connect(target) as probe:
                    await probe.run("true", timeout=30)
            except ssh.HostKeyMismatch:
                raise MachineError(f"{self.vm} answered SSH at {address} with a key that isn't the one Slipway pinned; "
                                   "Slipway pinned nothing") from None
            except (ssh.SSHError, OSError, TimeoutError):
                if attempt + 1 < WAIT_TRIES:
                    await self.mctx.sleep(WAIT_POLL)
                continue
            return await stack.enter_async_context(self.connect(target))
        raise MachineError(f"{self.vm} didn't answer SSH at {address} in 10 minutes")

    async def _settle_records(self) -> tuple[str, str | None]:
        """``vm_settle`` (§9.7 step 5): the host lock emptied over SSH, then Slipway's records back to the
        snapshot in one transaction."""
        from slipway.services import deployer

        job, row, remote = self.job, self.row, self.remote
        assert row is not None and remote is not None
        instance = self.instance
        paths = deployer.paths_for(instance)
        # Every line there is stale: this job holds both runner keys and the VM's memory wasn't in the snapshot.
        await self.sink.line(f"$ : > {paths.lock}")
        lock = shlex.quote(paths.lock)
        await remote.run(f"[ ! -e {lock} ] || : > {lock}", timeout=60)

        env = job.environment
        restored: list[str] = []
        lost: list[str] = []
        async with session_scope() as db:
            stored = await db.get(MachineSnapshot, row.id)
            if stored is None:
                raise MachineError(f"The VM snapshot {row.name} was deleted meanwhile")
            # A row that recorded no identity values (or whose values can't be read; ``check`` refuses those)
            # leaves ``live_identity`` as it is: clearing it would drop the identity guard of the data on the VM.
            recorded = stored.identity is not None
            identity = dict(stored.identity or {})
            keys = sorted(identity)
            fresh_env = await db.get(Environment, env.id)
            secrets = dict((fresh_env.app_secrets if fresh_env is not None else None) or job.secrets or {})
            now_values = {k: secrets[k] for k in keys if k in secrets}
            if keys and data.identity_fp(stored.id, keys, now_values) != stored.identity_fp:
                restored = [k for k in keys if secrets.get(k) != identity[k]]
                result = await db.execute(
                    update(Environment).where(Environment.id == env.id,
                                              Environment.secrets_version == job.secrets_version)
                    .values(app_secrets={**secrets, **identity}, secrets_version=Environment.secrets_version + 1)
                    .execution_options(synchronize_session=False))
                if result.rowcount != 1:
                    raise MachineError(f"{env.name}'s secrets changed while this job ran; retry it")
            inst = await db.get(Instance, instance.id)
            owner = await data.owner_for(db, inst)
            inst.app_state = dict(stored.app_state) if stored.app_state else None
            inst.fresh_data = stored.fresh_data
            inst.current_commit_sha = stored.commit_sha
            owner.data_dirty = None
            if recorded:
                owner.live_identity = identity or None
            if restored:
                owner.identity_changed_at = utcnow()
                owner.identity_source = ssh.clip(f"VM snapshot {stored.name}", 300)
            machine = await db.get(Machine, self.mctx.machine.id)
            machine.applied = {**(_sizes(stored.sizes) or dict(stored.sizes or {})), "at": utcnow().isoformat(),
                               "deployment_id": job.deployment_id.hex}
            backups = list(await db.scalars(select(Backup).where(Backup.instance_id == owner.id)))
            check = await data.check_backups(remote, db, backups, paths.backups, data.host_label(instance))
            if check.warning:
                await self.sink.line(f"Warning: {check.warning}")
            lost = sorted(b.name for b in backups if check.statuses.get(b.id) == BackupStatus.MISSING
                          and b.name not in (stored.backups or []))
            dep = await db.get(Deployment, job.deployment_id)
            if dep is not None:
                dep.options = {**(dep.options or {}), "settled": True}
            audit.record(db, "machine.revert", actor=job.user, target=machine,
                         summary=f"Reverted {self.vm} to {stored.name}",
                         details={"name": self.vm, "snapshot": stored.name, "taken_at": stored.taken_at.isoformat(),
                                  "commit_sha": stored.commit_sha, "identity_restored": bool(restored)})
            app_state, fresh, sha = inst.app_state, inst.fresh_data, inst.current_commit_sha
        job.options["settled"] = True
        if restored:
            job.secrets_version += 1
            job.secrets = {**(job.secrets or {}), **identity}
            env.app_secrets = job.secrets
        # The job's own copy of the instance follows, so restart starts the snapshot's projects.
        instance.app_state, instance.fresh_data, instance.current_commit_sha = app_state, fresh, sha
        instance.data_dirty = None
        self.mctx.machine.applied = machine.applied
        self.lost = lost
        text = f"Reverted to {row.name} ({_when(row.taken_at)}, {(row.commit_sha or 'no release')[:7]})."
        if lost:
            text += f" Backups taken after it were on the VM and are gone: {', '.join(lost)}."
        text += " Settings changed since then apply at the next deploy."
        await machines.set_notice(env.id, text, deployment_id=job.deployment_id)
        parts = ["Slipway's records name the release, data and identity of the snapshot again"]
        if restored:
            parts.append(f"{', '.join(restored)} came back from {row.name}")
        if lost:
            parts.append(f"backups gone with the revert: {', '.join(lost)}")
        return "succeeded", "; ".join(parts)

    async def _restart(self) -> tuple[str, str | None]:
        """``restart`` (§9.7 step 6): the live release's projects started, as the control action. A failure fails
        the job with the records already matching the VM."""
        from slipway.services import deployer

        job, instance, remote, row = self.job, self.instance, self.remote, self.row
        assert remote is not None and row is not None
        if data.live_state(instance) is None:
            await _status(instance, InstanceStatus.STOPPED if instance.current_commit_sha else InstanceStatus.CREATED)
            return "skipped", f"Nothing of {job.environment.name} was live when {row.name} was taken"
        command = deployer.control_command(instance, "start")
        try:
            await deployer._acquire_lock(remote, instance, job, self.sink)
            try:
                await self.sink.line(f"$ {command}")
                await remote.run(command, on_line=self.sink.line, scrub=self.sink.scrub, timeout=600)
            finally:
                await deployer._release_lock(remote, instance, job, self.sink)
        except (ssh.SSHError, deployer.DeployError, TimeoutError) as exc:
            await _status(instance, InstanceStatus.STOPPED)
            raise MachineError(f"{self.vm} is back at {row.name}, but {job.environment.name} didn't start: "
                               f"{getattr(exc, 'text', None) or exc}. Start it from the instance page") from None
        await _status(instance, InstanceStatus.RUNNING)
        return "succeeded", None

    async def _traffic(self) -> None:
        """``traffic``: phase 3's in-place sync for the single slot, warning only (the restored ports may
        differ)."""
        from slipway.services import deployer

        assert self.remote is not None
        c = deployer._AppRun(remote=self.remote, instance=self.instance, job=self.job, sink=self.sink,
                             steps=self.steps, paths=deployer.paths_for(self.instance))
        await deployer._traffic_step(c)


def _when(at: datetime | None) -> str:
    return at.strftime("%Y-%m-%d %H:%M UTC") if at is not None else "an unknown time"


async def _status(instance: Instance, status: str) -> None:
    async with session_scope() as db:
        await db.execute(update(Instance).where(Instance.id == instance.id).values(status=status))
    instance.status = status


async def run(job: Any, sink: Any, steps: Any, connect: Any) -> None:
    """Run a VM job (the deployer's ``run_deployment`` calls it for the three kinds). Raises to fail it."""
    from slipway.services import deployer

    if job.instance.environment_id is None or job.environment is None:
        raise deployer.DeployError(SHAPE_TEXT)
    mctx = await deployer._machine_context(job, sink, connect)
    vm_run = _VmRun(job, sink, steps, connect, mctx)
    async with contextlib.AsyncExitStack() as stack:
        if job.kind == DeploymentKind.VM_SNAPSHOT:
            await vm_run.snapshot_job()
        elif job.kind == DeploymentKind.VM_REVERT:
            await vm_run.revert_job(stack)
        elif job.kind == DeploymentKind.VM_DROP:
            await vm_run.drop_job()
        else:
            raise deployer.DeployError(f"Slipway can't run {data.kind_label(job.kind)} jobs this way")


# ------------------------------------------------------------------------------- holds and recovery


def hold_text(vm: str, snapshot: str, *, restarted: bool) -> str:
    """The data owner's hold after a revert that may have left the disk at the snapshot (§9.12)."""
    first = (f"Slipway restarted while reverting {vm} to {snapshot}." if restarted
             else f"Slipway couldn't finish reverting {vm} to {snapshot}.")
    return (f"{first} The VM's disk may already be back at {snapshot} while Slipway's records name a later release: "
            f"revert to {snapshot} again")


def _reverting(dep: Deployment) -> str | None:
    """The revert step a failed or interrupted ``vm_revert`` ended in, when its disk may have moved and its
    records hadn't followed yet; None otherwise."""
    if dep.kind != DeploymentKind.VM_REVERT or (dep.options or {}).get("settled"):
        return None
    step = next((r.get("key") for r in dep.steps or [] if r.get("key") in REVERTING_STEPS
                 and r.get("status") in ("running", "failed")), None)
    return None if step is not None and not _may_have_moved(dep, step) else step


def _may_have_moved(dep: Deployment, step: str | None) -> bool:
    """Whether the VM's disk may have left where it was when ``step`` ended: always after ``vm_revert``; in it,
    unless the provider refused before it was about to start the revert task (``REVERT_STARTED`` False)."""
    return step != "vm_revert" or (dep.options or {}).get(REVERT_STARTED) is not False


def _held(old: dict[str, Any] | None, dep: Deployment, step: str, text: str) -> dict[str, Any]:
    dirty = data.mark_dirty(old, dep, step=step)
    dirty["hold"] = True
    dirty["last"] = {**(dirty.get("last") or {}), "text": text}
    return dirty


async def _names(db: AsyncSession, dep: Deployment, instance: Instance | None) -> tuple[str, str]:
    row_id = _snapshot_id(dep.options)
    row = await db.get(MachineSnapshot, row_id) if row_id is not None else None
    machine = await machine_of(db, instance) if instance is not None else None
    vm = machine.name if machine is not None else (data.host_label(instance) if instance is not None else "the VM")
    return vm, row.name if row is not None else "the VM snapshot"


async def failed_fields(deployment_id: uuid.UUID, job: Any) -> dict[str, Any]:
    """The instance fields a failed VM job leaves: none, except a revert that failed between ``vm_revert`` and the
    end of ``vm_settle``, which holds the data owner's data with §9.12's text (the disk may be at the snapshot
    while Slipway's records name a later release). A ``vm_revert`` the provider refused before it was about to
    start the revert task changed nothing and holds nothing."""
    if job.kind != DeploymentKind.VM_REVERT:
        return {}
    async with session_scope() as db:
        dep = await db.get(Deployment, deployment_id)
        if dep is None:
            return {}
        step = _reverting(dep)
        if step is None:
            return {}
        inst = await db.get(Instance, job.instance.id)
        owner = await data.owner_for(db, inst)
        vm, snapshot = await _names(db, dep, inst)
        dirty = _held(owner.data_dirty, dep, step, hold_text(vm, snapshot, restarted=False))
    if owner.id == job.instance.id:
        return {"data_dirty": dirty}
    return {"owner_id": owner.id, "owner_fields": {"data_dirty": dirty}}


async def recover(db: AsyncSession, dep: Deployment, cut: str | None) -> None:
    """What a restart leaves of a VM job (§9.12), in the recovery's transaction: its ``pending`` VM snapshot rows
    become ``failed`` (the next ``describe`` makes one ``ready`` if the hypervisor has it), and a revert cut off
    between ``vm_revert`` and the end of ``vm_settle`` holds the data owner's data with §9.12's text, unless it was
    cut off in ``vm_revert`` before the provider was about to start the revert task."""
    rows = await db.scalars(select(MachineSnapshot).where(MachineSnapshot.deployment_id == dep.id,
                                                          MachineSnapshot.status == "pending"))
    for row in rows:
        row.status = "failed"
        row.note = "Slipway restarted while taking it"
    if (dep.kind != DeploymentKind.VM_REVERT or cut not in REVERTING_STEPS or (dep.options or {}).get("settled")
            or not _may_have_moved(dep, cut)):
        return
    instance = await db.get(Instance, dep.instance_id) if dep.instance_id is not None else None
    if instance is None:
        return
    owner = await data.owner_for(db, instance)
    vm, snapshot = await _names(db, dep, instance)
    text = hold_text(vm, snapshot, restarted=True)
    owner.data_dirty = _held(owner.data_dirty, dep, cut, text)
    dep.error = f"{dep.error or 'Interrupted by a Slipway restart'}. {text}"
