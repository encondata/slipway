"""The outside objects an environment manages (Switchyard proxy hosts, DNS records; phase 4 droplets...).

A row is written the moment the provider answers, in its own transaction, so a failure later in the same
job still knows the object exists and can put it back or delete it (phase 3 D15). ``record``,
``record_pending``, ``update_details``, ``looked``, ``set_credentials`` and ``forget`` therefore each open
their own session and commit at once: a caller's rollback never takes a row with it. Slipway changes or
deletes only objects a row names (I7); the callers also check the live object still carries Slipway's
marker before they touch it.

Phase 4 adds intent rows (P4 §6.4): before a create is sent, ``record_pending`` commits a row whose
``provider_id`` is ``pending:<nonce>``, named as the object will be, with ``details.pending`` holding the
nonce, when it was sent, a hash of the body and the times it was looked for. The answer turns it into the
real row (``record(..., replaces=<pending row>)``) in one transaction. Credentials (a Spaces secret, the
doadmin password) and tags are written in the row's own commit, so a secret is never between two commits.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.db.base import utcnow
from slipway.db.session import session_scope
from slipway.models import Environment, Resource, ResourceOrigin, User
from slipway.services import audit


class ResourceError(Exception):
    pass


class ResourceTaken(ResourceError):
    """The outside object (or the environment's name for one of this kind) is already recorded elsewhere."""


PENDING_PREFIX = "pending:"
NONCE_RE = re.compile(r"^[0-9a-f]{16}\Z")
AUDIT_ACTIONS = ("resource.create", "resource.adopt", "resource.rebuild", "resource.claim")


def is_pending(row: Resource) -> bool:
    """True for an intent row: a create was sent (or is about to be) and its answer isn't recorded yet."""
    return row.provider_id.startswith(PENDING_PREFIX)


def nonce_of(row: Resource) -> str | None:
    return row.provider_id[len(PENDING_PREFIX):] if is_pending(row) else None


def _describe(provider: str, kind: str, provider_id: str, name: str) -> str:
    return f"{provider} {kind.replace('_', ' ')} {provider_id} ({name})"


def _audit_details(row: Resource, **extra: Any) -> dict[str, Any]:
    """What a resource audit row says: never credentials."""
    return {"provider": row.provider, "kind": row.kind, "name": row.name, "provider_id": row.provider_id,
            "environment_id": str(row.environment_id), **{k: v for k, v in extra.items() if v is not None}}


async def _env_name(db: AsyncSession, env_id: uuid.UUID) -> str:
    return await db.scalar(select(Environment.name).where(Environment.id == env_id)) or str(env_id)


async def _clash(
    db: AsyncSession, env_id: uuid.UUID, provider: str, kind: str, provider_id: str, name: str,
    *, replacing: Resource | None = None,
) -> tuple[Resource | None, str | None]:
    """The row already recording this object for ``env_id`` (to update), or why it can't be recorded.

    ``replacing`` is a pending row the real one takes over: the name rule treats it as the row itself.
    """
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
    if same_name is not None and replacing is not None and same_name.id == replacing.id:
        same_name = None
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
    credentials: dict[str, Any] | None = None,
    tags: list[str] | None = None,
    audit_action: str | None = None,
    replaces: uuid.UUID | None = None,
    rule: str | None = None,
) -> uuid.UUID:
    """Record an object the provider just made (``created``) or one Slipway now keeps current (``claimed``).

    Committed at once, with ``credentials`` and ``tags`` in the same commit. Recording the same object for
    the same environment again updates the row (a retry); credentials and tags given as None are then left
    as they are. Raises ``ResourceTaken`` when another environment holds the object, or this one already
    records the name under another object of the same kind.

    ``replaces`` names a pending row of this environment, kind and name (``record_pending``): the real row
    takes it over in the same transaction, so there is never a moment with both or neither. Its credentials
    become ``credentials`` (a certificate's are kept only while pending). A pending row that is already gone,
    or that already became this very object (a retry), is no obstacle. ``audit_action`` is ``resource.adopt`` (a lost answer found, ``rule`` naming what
    matched) or ``resource.rebuild`` in place of ``resource.create``; ``rule`` goes to the audit only.
    """
    origin = ResourceOrigin(origin).value
    provider_id = str(provider_id)
    if provider_id.startswith(PENDING_PREFIX):
        raise ResourceError("A pending id is written by record_pending, not record")
    if audit_action is None:
        audit_action = "resource.claim" if origin == ResourceOrigin.CLAIMED else "resource.create"
    if audit_action not in AUDIT_ACTIONS:
        raise ValueError(f"{audit_action!r} isn't a resource audit action for record")
    for attempt in (1, 2):
        try:
            async with session_scope() as db:
                pending_row = await db.get(Resource, replaces) if replaces is not None else None
                if pending_row is not None and not is_pending(pending_row) and (
                        pending_row.environment_id, pending_row.provider, pending_row.kind,
                        pending_row.provider_id) == (env_id, provider, kind, provider_id):
                    pending_row = None  # it took the pending row over already (a retry): update it as usual
                if pending_row is not None:
                    if not is_pending(pending_row) or (pending_row.environment_id, pending_row.provider,
                                                       pending_row.kind, pending_row.name) != (
                            env_id, provider, kind, name):
                        raise ResourceError(
                            f"{_describe(pending_row.provider, pending_row.kind, pending_row.provider_id, pending_row.name)}"
                            f" isn't the pending create of {kind.replace('_', ' ')} {name}"
                        )
                row, problem = await _clash(db, env_id, provider, kind, provider_id, name, replacing=pending_row)
                if problem:
                    raise ResourceTaken(problem)
                pending_nonce = nonce_of(pending_row) if pending_row is not None else None
                if row is None and pending_row is not None:
                    row = pending_row  # the intent row becomes the real one: same id, one commit
                    row.provider_id, row.origin = provider_id, origin
                    row.details, row.credentials = dict(details or {}), credentials
                    row.tags = list(tags or [])
                    if instance_id is not None:
                        row.instance_id = instance_id
                elif row is None:
                    row = Resource(
                        environment_id=env_id, instance_id=instance_id, provider=provider, kind=kind,
                        provider_id=provider_id, name=name, origin=origin, details=dict(details or {}),
                        credentials=credentials, tags=list(tags or []), created_by_id=actor.id if actor else None,
                    )
                    db.add(row)
                else:
                    if pending_row is not None:  # recorded already (a retry): the intent row just goes
                        await db.delete(pending_row)
                        await db.flush()
                    row.name, row.origin, row.details = name, origin, dict(details or {})
                    if credentials is not None or pending_row is not None:
                        row.credentials = credentials
                    if tags is not None:
                        row.tags = list(tags)
                    if instance_id is not None:
                        row.instance_id = instance_id
                await db.flush()
                verbs = {"resource.claim": "Claimed", "resource.create": "Recorded", "resource.adopt": "Adopted",
                         "resource.rebuild": "Recorded the rebuilt"}
                audit.record(
                    db, audit_action, actor=actor, target=row,
                    summary=f"{verbs[audit_action]} {_describe(provider, kind, provider_id, name)}",
                    details=_audit_details(row, rule=rule, replaces=pending_nonce),
                )
                return row.id
        except IntegrityError:
            # Someone recorded it between our check and the insert: look again, once.
            if attempt == 2:
                raise
    raise AssertionError("unreachable")  # pragma: no cover


async def record_pending(
    env_id: uuid.UUID,
    provider: str,
    kind: str,
    name: str,
    *,
    nonce: str,
    body_hash: str,
    instance_id: uuid.UUID | None = None,
    credentials: dict[str, Any] | None = None,
    actor: User | None = None,
) -> uuid.UUID:
    """Commit an intent row before a create is sent (P4 §6.4 step 4): ``provider_id = pending:<nonce>``, the
    name the object will have, ``details.pending = {nonce, sent_at, body_hash, looked: []}``.

    Raises ``ResourceTaken`` when this environment already has a row of this kind and name, recorded or
    pending, so there is at most one pending create per name.
    """
    if not isinstance(nonce, str) or not NONCE_RE.match(nonce):
        raise ValueError("a nonce is 16 hex characters (secrets.token_hex(8))")
    provider_id = f"{PENDING_PREFIX}{nonce}"
    for attempt in (1, 2):
        try:
            async with session_scope() as db:
                same_name = await db.scalar(
                    select(Resource).where(Resource.environment_id == env_id, Resource.kind == kind,
                                           Resource.name == name)
                )
                if same_name is not None:
                    mine = await _env_name(db, env_id)
                    if is_pending(same_name):
                        raise ResourceTaken(
                            f"Environment {mine} is still waiting to learn whether its {kind.replace('_', ' ')} "
                            f"{name} was made (request {nonce_of(same_name)})"
                        )
                    raise ResourceTaken(
                        f"Environment {mine} already records {name} as "
                        f"{_describe(same_name.provider, kind, same_name.provider_id, name)}"
                    )
                row = Resource(
                    environment_id=env_id, instance_id=instance_id, provider=provider, kind=kind,
                    provider_id=provider_id, name=name, origin=ResourceOrigin.CREATED.value,
                    details={"pending": {"nonce": nonce, "sent_at": utcnow().isoformat(), "body_hash": body_hash,
                                         "looked": []}},
                    credentials=credentials, tags=[], created_by_id=actor.id if actor else None,
                )
                db.add(row)
                await db.flush()
                audit.record(
                    db, "resource.pending", actor=actor, target=row,
                    summary=f"About to create {provider} {kind.replace('_', ' ')} {name} (request {nonce})",
                    details=_audit_details(row, nonce=nonce),
                )
                return row.id
        except IntegrityError:
            if attempt == 2:
                raise ResourceTaken(f"Another job is recording {kind.replace('_', ' ')} {name} right now") from None
    raise AssertionError("unreachable")  # pragma: no cover


async def pending(db: AsyncSession, env_id: uuid.UUID, provider: str, kind: str) -> list[Resource]:
    """The environment's pending rows of one provider and kind, by name (read in the caller's session)."""
    stmt = select(Resource).where(
        Resource.environment_id == env_id, Resource.provider == provider, Resource.kind == kind,
        Resource.provider_id.startswith(PENDING_PREFIX),
    )
    return list(await db.scalars(stmt.order_by(Resource.name)))


async def looked(row_id: uuid.UUID, at: datetime | None = None) -> bool:
    """Note that a pending row's object was looked for and not found, committed at once. False when the row
    is gone or isn't pending."""
    async with session_scope() as db:
        row = await db.get(Resource, row_id, with_for_update=True)
        if row is None or not is_pending(row):
            return False
        info = dict((row.details or {}).get("pending") or {})
        info["looked"] = [*info.get("looked", []), (at or utcnow()).isoformat()]
        row.details = {**(row.details or {}), "pending": info}
        return True


async def set_credentials(row_id: uuid.UUID, value: dict[str, Any] | None) -> bool:
    """Set (or, with None, clear) a row's credentials, committed at once. False when the row is gone."""
    async with session_scope() as db:
        row = await db.get(Resource, row_id, with_for_update=True)
        if row is None:
            return False
        row.credentials = value
        return True


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
            details=_audit_details(row),
        )
        await db.delete(row)
        return True


async def owned(
    db: AsyncSession, env_id: uuid.UUID, provider: str, kind: str, *, include_pending: bool = False
) -> list[Resource]:
    """The environment's rows of one provider and kind, by name (read in the caller's session). Pending rows
    are left out unless ``include_pending``."""
    stmt = select(Resource).where(
        Resource.environment_id == env_id, Resource.provider == provider, Resource.kind == kind
    )
    if not include_pending:
        stmt = stmt.where(~Resource.provider_id.startswith(PENDING_PREFIX))
    return list(await db.scalars(stmt.order_by(Resource.name)))
