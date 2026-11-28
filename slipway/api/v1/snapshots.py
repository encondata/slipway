"""Snapshots kept on this Slipway server: list, upload, unlock, rename, delete and download (§10).

Taking one from an instance is ``POST /instances/{id}/snapshots`` (instances.py). The storage, checks and
transfers live in ``services.snapshots``; this module turns its ``SnapshotsError`` into responses. Passphrases
are passed through once and never stored, logged or audited.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from slipway.api.deps import DB, not_found, require
from slipway.core.permissions import Perm
from slipway.models import Instance, Snapshot
from slipway.schemas import PassphraseIn, SnapshotOut, SnapshotUpdate, seeding_needs_download
from slipway.services import snapshots
from slipway.services.auth import AuthContext

router = APIRouter(tags=["snapshots"])

Reader = Annotated[AuthContext, require(Perm.DATA_READ)]
Uploader = Annotated[AuthContext, require(Perm.SNAPSHOTS_UPLOAD)]
Keeper = Annotated[AuthContext, require(Perm.DATA_BACKUP)]
Deleter = Annotated[AuthContext, require(Perm.DATA_RESET)]
Downloader = Annotated[AuthContext, require(Perm.SNAPSHOTS_DOWNLOAD)]


def _error(exc: snapshots.SnapshotsError) -> HTTPException:
    return HTTPException(exc.status, exc.message)


def _storage() -> None:
    """503 while SLIPWAY_STORAGE_DIR isn't usable (deploys are unaffected, §5)."""
    try:
        snapshots.require_storage()
    except snapshots.SnapshotsError as exc:
        raise _error(exc) from exc


async def _get(db: DB, snapshot_id: uuid.UUID) -> Snapshot:
    snap = await db.get(Snapshot, snapshot_id, populate_existing=True)
    if snap is None:
        raise not_found("Snapshot")
    return snap


@router.get("/snapshots")
async def list_snapshots(
    ctx: Reader, db: DB, instance_id: uuid.UUID | None = None, app: Annotated[str | None, Query(max_length=64)] = None,
) -> list[SnapshotOut]:
    """Every snapshot, newest first. With ``instance_id``, each says whether seeding that instance from it
    needs snapshots:download (it is of another repository, or of an unknown one)."""
    _storage()
    stmt = select(Snapshot).order_by(Snapshot.created_at.desc(), Snapshot.id.desc())
    if app:
        stmt = stmt.where(Snapshot.app == app)
    rows = (await db.scalars(stmt)).all()
    repository = None
    if instance_id is not None:
        instance = await db.get(Instance, instance_id)
        if instance is None:
            raise not_found("Instance")
        repository = instance.repository.full_name if instance.repository is not None else None
    return [SnapshotOut.of(s, seeding_needs_download=seeding_needs_download(s, repository)
                           if instance_id is not None else None) for s in rows]


@router.get("/snapshots/usage")
async def snapshot_usage(ctx: Reader, db: DB) -> dict[str, Any]:
    """How much of the quota (SLIPWAY_SNAPSHOT_TOTAL_BYTES) the stored snapshots use."""
    _storage()
    return await snapshots.usage(db)


@router.get("/snapshots/{snapshot_id}")
async def get_snapshot(snapshot_id: uuid.UUID, ctx: Reader, db: DB) -> SnapshotOut:
    _storage()
    return SnapshotOut.of(await _get(db, snapshot_id))


@router.post("/snapshots/upload", status_code=201)
async def upload_snapshot(
    request: Request, ctx: Uploader, db: DB,
    name: Annotated[str, Query(max_length=64)],
    notes: Annotated[str | None, Query(max_length=2000)] = None,
) -> SnapshotOut:
    """Upload a snapshot file as the raw request body (``application/octet-stream``, with Content-Length):
    a passphrase-encrypted ``.slipway-snapshot`` (kept ``locked`` until unlocked) or a plain ``.tar`` /
    ``.tar.gz`` made with ``slipway snapshot pack`` (checked while it arrives, then ``ready``)."""
    try:
        snap = await snapshots.receive_upload(
            db, name=name, notes=notes, content_length=request.headers.get("content-length"),
            body=request.stream(), user=ctx.user, request=request,
        )
    except snapshots.SnapshotsError as exc:
        raise _error(exc) from exc
    return SnapshotOut.of(snap)


@router.post("/snapshots/{snapshot_id}/unlock", status_code=202)
async def unlock_snapshot(
    snapshot_id: uuid.UUID, body: PassphraseIn, ctx: Uploader, request: Request, db: DB
) -> SnapshotOut:
    """Unlock an imported file with its passphrase; it is then checked in the background."""
    _storage()
    await _get(db, snapshot_id)
    try:
        snap = await snapshots.unlock(db, snapshot_id, body.passphrase, user=ctx.user, request=request)
    except snapshots.SnapshotsError as exc:
        raise _error(exc) from exc
    return SnapshotOut.of(snap)


@router.patch("/snapshots/{snapshot_id}")
async def update_snapshot(
    snapshot_id: uuid.UUID, body: SnapshotUpdate, ctx: Keeper, request: Request, db: DB
) -> SnapshotOut:
    """Rename a snapshot or change its notes."""
    _storage()
    await _get(db, snapshot_id)
    try:
        snap = await snapshots.update_snapshot(db, snapshot_id, name=body.name, notes=body.notes, user=ctx.user,
                                               request=request)
    except snapshots.SnapshotsError as exc:
        raise _error(exc) from exc
    return SnapshotOut.of(snap)


@router.delete("/snapshots/{snapshot_id}", status_code=204)
async def delete_snapshot(snapshot_id: uuid.UUID, ctx: Deleter, request: Request, db: DB) -> Response:
    """Delete a snapshot and its stored file, unless a job or an instance still needs it (409)."""
    _storage()
    await _get(db, snapshot_id)
    try:
        await snapshots.delete_snapshot(db, snapshot_id, user=ctx.user, request=request)
    except snapshots.SnapshotsError as exc:
        raise _error(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/snapshots/{snapshot_id}/exports", status_code=201)
async def export_snapshot(
    snapshot_id: uuid.UUID, body: PassphraseIn, ctx: Downloader, request: Request, db: DB
) -> dict[str, Any]:
    """Prepare a download encrypted with a passphrase you choose: a single-use link for 10 minutes."""
    _storage()
    await _get(db, snapshot_id)
    try:
        ticket = await snapshots.create_export(db, snapshot_id, body.passphrase, user=ctx.user, request=request)
    except snapshots.SnapshotsError as exc:
        raise _error(exc) from exc
    return {"url": ticket.url, "expires_at": ticket.expires_at, "bytes": ticket.bytes}


@router.get("/snapshot-exports/{token}")
async def download_snapshot(token: str, ctx: Downloader, db: DB) -> StreamingResponse:
    """The download a ticket allows: once, by the user who prepared it, while they still hold
    snapshots:download."""
    _storage()
    if len(token) > 200:
        raise HTTPException(status.HTTP_404_NOT_FOUND, snapshots.EXPORT_GONE)
    try:
        stream = await snapshots.open_export(db, token, user=ctx.user)
    except snapshots.SnapshotsError as exc:
        raise _error(exc) from exc
    await db.commit()  # don't hold a transaction while the file streams
    return StreamingResponse(
        stream.body, media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{stream.filename}"',
                 "Content-Length": str(stream.content_length), "Cache-Control": "no-store"},
    )
