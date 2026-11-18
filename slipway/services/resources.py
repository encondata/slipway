"""The outside objects an environment manages (Switchyard proxy hosts, DNS records; phase 4 droplets...).

A row is written the moment the provider answers, in its own transaction, so a failure later in the same
job still knows the object exists and can put it back or delete it (phase 3 D15). ``record``,
``update_details`` and ``forget`` therefore each open their own session and commit at once: a caller's
rollback never takes a row with it. Slipway changes or deletes only objects a row names (I7); the
callers also check the live object still carries Slipway's marker before they touch it.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.db.session import session_scope
from slipway.models import Environment, Resource, ResourceOrigin, User
from slipway.services import audit


class ResourceError(Exception):
    pass


class ResourceTaken(ResourceError):
    """The outside object (or the environment's name for one of this kind) is already recorded elsewhere."""


def _describe(provider: str, kind: str, provider_id: str, name: str) -> str:
    return f"{provider} {kind.replace('_', ' ')} {provider_id} ({name})"


async def _env_name(db: AsyncSession, env_id: uuid.UUID) -> str:
    return await db.scalar(select(Environment.name).where(Environment.id == env_id)) or str(env_id)


async def _clash(
    db: AsyncSession, env_id: uuid.UUID, provider: str, kind: str, provider_id: str, name: str
) -> tuple[Resource | None, str | None]:
    """The row already recording this object for ``env_id`` (to update), or why it can't be recorded."""
    held = await db.scalar(
        select(Resource).where(
            Resource.provider == provider, Resource.kind == kind, Resource.provider_id == provider_id
        )
    )
    if held is not None and held.environment_id != env_id:
        other = await _env_name(db, held.environment_id)
        return None, f"{_describe(provider, kind, provider_id, held.name)} already belongs to environment {other}"
    same_name = await db.scalar(
        select(Resource).where(Resource.environment_id == env_id, Resource.kind == kind, Resource.name == name)
    )
    if same_name is not None and same_name is not held:
        mine = await _env_name(db, env_id)
        return None, (
            f"Environment {mine} already records {name} as "
            f"{_describe(same_name.provider, kind, same_name.provider_id, name)}; forget that one first"
        )
    return held, None


async def record(
    env_id: uuid.UUID,
    provider: str,
    kind: str,
    provider_id: str,
    name: str,
    origin: str,
    details: dict[str, Any] | None = None,
    instance_id: uuid.UUID | None = None,
    *,
    actor: User | None = None,
) -> uuid.UUID:
    """Record an object the provider just made (``created``) or one Slipway now keeps current (``claimed``).

    Committed at once. Recording the same object for the same environment again updates the row (a retry).
    Raises ``ResourceTaken`` when another environment holds the object, or this one already records the
    name under another object of the same kind.
    """
    origin = ResourceOrigin(origin).value
    provider_id = str(provider_id)
    for attempt in (1, 2):
        try:
            async with session_scope() as db:
                row, problem = await _clash(db, env_id, provider, kind, provider_id, name)
                if problem:
                    raise ResourceTaken(problem)
                if row is None:
                    row = Resource(
                        environment_id=env_id, instance_id=instance_id, provider=provider, kind=kind,
                        provider_id=provider_id, name=name, origin=origin, details=dict(details or {}),
                        created_by_id=actor.id if actor else None,
                    )
                    db.add(row)
                else:
                    row.name, row.origin, row.details = name, origin, dict(details or {})
                    if instance_id is not None:
                        row.instance_id = instance_id
                await db.flush()
                action = "resource.claim" if origin == ResourceOrigin.CLAIMED else "resource.create"
                verb = "Claimed" if origin == ResourceOrigin.CLAIMED else "Recorded"
                audit.record(
                    db, action, actor=actor, target=row,
                    summary=f"{verb} {_describe(provider, kind, provider_id, name)}",
                    details={"provider": provider, "kind": kind, "name": name, "provider_id": provider_id,
                             "environment_id": str(env_id)},
                )
                return row.id
        except IntegrityError:
            # Someone recorded it between our check and the insert: look again, once.
            if attempt == 2:
                raise
    raise AssertionError("unreachable")  # pragma: no cover


async def update_details(row_id: uuid.UUID, **details: Any) -> bool:
    """Merge ``details`` into a row's details, committed at once. False when the row is gone."""
    async with session_scope() as db:
        row = await db.get(Resource, row_id, with_for_update=True)
        if row is None:
            return False
        row.details = {**(row.details or {}), **details}
        return True


async def forget(row_id: uuid.UUID, *, deleted: bool = False, actor: User | None = None) -> bool:
    """Drop a row, committed at once: the object was deleted (``deleted``) or Slipway no longer manages it.

    False when the row was already gone.
    """
    async with session_scope() as db:
        row = await db.get(Resource, row_id)
        if row is None:
            return False
        action, verb = ("resource.delete", "Deleted") if deleted else ("resource.forget", "Forgot")
        audit.record(
            db, action, actor=actor, target=row,
            summary=f"{verb} {_describe(row.provider, row.kind, row.provider_id, row.name)}",
            details={"provider": row.provider, "kind": row.kind, "name": row.name, "provider_id": row.provider_id,
                     "environment_id": str(row.environment_id)},
        )
        await db.delete(row)
        return True


async def owned(db: AsyncSession, env_id: uuid.UUID, provider: str, kind: str) -> list[Resource]:
    """The environment's rows of one provider and kind, by name (read in the caller's session)."""
    stmt = select(Resource).where(
        Resource.environment_id == env_id, Resource.provider == provider, Resource.kind == kind
    )
    return list(await db.scalars(stmt.order_by(Resource.name)))
