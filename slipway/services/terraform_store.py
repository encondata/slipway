"""The database ``StateStore`` for Terraform (phase 5 §3.4, §7.3): one ``terraform_states`` row per Proxmox VM.

``terraform.session`` takes a store with ``lock``, ``unlock``, ``load`` and ``save``. This module is that store:
pass the module itself (``store=terraform_store``) or ``STORE``. Every function opens its own session and commits
at once, so what it writes survives the caller's rollback (a step that fails after Terraform saved its state
still leaves the state in the database, M5).

The lock is a compare-and-set on ``lock_id``: it is taken when it is free, already this deployment's, or held by
a deployment that is no longer queued or running, or no longer exists (a slot's deployments go with its
instance when Remove slot deletes it). ``lock_id`` has no foreign key for that reason. The row is inserted
first when it is missing, with a NULL lineage: a first apply whose save never ran then counts as older than
whatever the working folder holds (§7.3 step 3). ``clear_lock`` is the recovery of §9.12.
"""

from __future__ import annotations

import uuid

from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.db.base import utcnow
from slipway.db.session import get_sessionmaker, session_scope
from slipway.models import Deployment, DeploymentStatus, TerraformState
from slipway.services.terraform import LockResult, StoredState

ACTIVE = (DeploymentStatus.QUEUED.value, DeploymentStatus.RUNNING.value)


async def _ensure_row(machine_id: uuid.UUID) -> None:
    """Insert the machine's row when it is missing; a racing insert of the same row is fine."""
    async with get_sessionmaker()() as db:
        if await db.scalar(select(TerraformState.machine_id).where(TerraformState.machine_id == machine_id)):
            return
        try:
            await db.execute(insert(TerraformState).values(machine_id=machine_id, serial=0))
            await db.commit()
        except IntegrityError:
            await db.rollback()  # another session inserted it first (or the machine is gone: the update finds nothing)


async def lock(machine_id: uuid.UUID, deployment_id: uuid.UUID) -> LockResult:
    """Take the state's lock for ``deployment_id`` (§7.3 step 1); refused while another live deployment holds it."""
    await _ensure_row(machine_id)
    async with session_scope() as db:
        held = await db.scalar(select(TerraformState.lock_id).where(TerraformState.machine_id == machine_id))
        live = select(Deployment.id).where(Deployment.status.in_(ACTIVE))
        result = await db.execute(
            update(TerraformState)
            .where(
                TerraformState.machine_id == machine_id,
                TerraformState.lock_id.is_(None)
                | (TerraformState.lock_id == deployment_id)
                | TerraformState.lock_id.not_in(live),
            )
            .values(lock_id=deployment_id, locked_at=utcnow())
        )
        if result.rowcount == 1:
            taken = held if held is not None and held != deployment_id else None
            return LockResult(ok=True, taken_over=taken)
        holder = await db.scalar(select(TerraformState.lock_id).where(TerraformState.machine_id == machine_id))
        return LockResult(ok=False, holder=holder)


async def unlock(machine_id: uuid.UUID, deployment_id: uuid.UUID) -> None:
    """Release the lock when this deployment holds it."""
    async with session_scope() as db:
        await db.execute(
            update(TerraformState)
            .where(TerraformState.machine_id == machine_id, TerraformState.lock_id == deployment_id)
            .values(lock_id=None, locked_at=None)
        )


async def load(machine_id: uuid.UUID) -> StoredState:
    """The stored state, or an empty one when there is no row or no state (or it can't be decrypted)."""
    async with get_sessionmaker()() as db:
        row = await db.get(TerraformState, machine_id)
        if row is None or row.state is None or row.lineage is None:
            return StoredState()
        return StoredState(lineage=row.lineage, serial=row.serial, sha256=row.sha256, state=row.state)


async def save(
    machine_id: uuid.UUID, state: StoredState, *, module_sha: str | None, terraform_version: str | None,
) -> None:
    """Store ``state`` in its own transaction. ``module_sha`` and ``terraform_version`` are kept as they were
    unless given (only an apply or destroy in the session gives them)."""
    await _ensure_row(machine_id)
    values: dict[str, object] = {
        "lineage": state.lineage, "serial": state.serial, "sha256": state.sha256, "state": state.state,
    }
    if module_sha is not None:
        values["module_sha"] = module_sha
    if terraform_version is not None:
        values["terraform_version"] = terraform_version[:16]
    async with session_scope() as db:
        row = await db.get(TerraformState, machine_id, with_for_update=True)
        if row is None:  # the machine went meanwhile: nothing to keep the state for
            return
        for key, value in values.items():
            setattr(row, key, value)


async def clear_lock(deployment_id: uuid.UUID, db: AsyncSession | None = None) -> int:
    """Recovery after a restart (§9.12): release every lock ``deployment_id`` holds. In ``db`` when given (the
    caller commits), else in its own transaction. Returns how many were released."""
    stmt = (
        update(TerraformState).where(TerraformState.lock_id == deployment_id).values(lock_id=None, locked_at=None)
    )
    if db is not None:
        return (await db.execute(stmt)).rowcount or 0
    async with session_scope() as own:
        return (await own.execute(stmt)).rowcount or 0


async def forget(db: AsyncSession, machine_id: uuid.UUID) -> None:
    """Delete the machine's row in the caller's transaction (Remove, once the VM is gone or forgotten)."""
    await db.execute(delete(TerraformState).where(TerraformState.machine_id == machine_id))


class DatabaseStateStore:
    """The same store as an object, for callers that want one (``terraform.StateStore``)."""

    lock = staticmethod(lock)
    unlock = staticmethod(unlock)
    load = staticmethod(load)
    save = staticmethod(save)


STORE = DatabaseStateStore()
