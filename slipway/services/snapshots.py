"""Snapshot storage on the Slipway server (spec §5 and §10).

Every stored snapshot is one ``.sbx`` file, ``<storage>/bundles/<snapshot id>.sbx``, encrypted under its own
data key (``snapshots.data_key``) with a ``kdf: none`` key block (D15). Files in flight (uploads, takes) are
written to ``<storage>/incoming/<uuid>.partial`` and moved into ``bundles/`` only when complete. Plaintext
never touches this disk: plain uploads are encrypted as they arrive, and a passphrase-locked import is kept
exactly as its ciphertext until somebody unlocks it.

This module holds:

- the folders, their checks (503 when Slipway can't write them) and ``prepare_storage`` at startup;
- free space and the quota over all stored files (507 and 409), with in-process reservations;
- the transfer semaphore (takes, uploads, checks, downloads) and the KDF semaphore (unlock, export);
- upload (plain or passphrase-encrypted), unlock and the background check of a stored file;
- export tickets and the download stream;
- rename and the delete rules;
- ``sweep_forever``, which deletes locked imports nobody unlocked in time.

Every failure the person can act on is a ``SnapshotsError`` carrying an HTTP status and plain text; the API
turns it into the response. Passphrases, data keys and identity values are never logged or audited.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hashlib
import logging
import os
import queue
import re
import secrets
import shutil
import threading
import uuid
from collections.abc import AsyncIterable, AsyncIterator, Awaitable, Callable, Iterable, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, BinaryIO

from fastapi import Request
from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import ClientDisconnect

from slipway.core.config import get_settings
from slipway.core.ratelimit import RateLimiter
from slipway.db.base import utcnow
from slipway.db.session import session_scope
from slipway.models import Deployment, DeploymentStatus, Instance, User
from slipway.models.data import Snapshot, SnapshotOrigin, SnapshotStatus
from slipway.services import audit, data, snapfile
from slipway.services.snapfile import SnapshotError

log = logging.getLogger(__name__)

KiB = 1024
MiB = 1024 * KiB
GiB = 1024 * MiB

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
NOTES_MAX = 2000
FREE_MARGIN = 2 * GiB  # free space Slipway's disk keeps beyond what a snapshot needs (§5)
SPACE_RECHECK = GiB  # free space is checked again after every GiB written
PIPE_DEPTH = 8  # pieces of PIECE bytes between the request and the worker thread
PIECE = MiB
SNIFF_PLAIN = 262  # enough to see "ustar" at offset 257
EXPORT_TTL = timedelta(minutes=10)
EXPORTS_PER_USER = 3
SWEEP_INTERVAL = 3600  # seconds
SPACE_SLACK = 64 * KiB  # container preamble and the last tag, on top of the per-MiB tags

STORED_STATUSES = (SnapshotStatus.LOCKED, SnapshotStatus.CHECKING, SnapshotStatus.READY)  # have a file

BAD_NAME = "A snapshot name is 1-64 letters, digits, '.', '_' or '-', starting with a letter or digit"
NOT_A_BUNDLE = (
    "Choose a Slipway snapshot: a .slipway-snapshot file downloaded from a Slipway, or a .tar or .tar.gz "
    "made with slipway snapshot pack"
)
UPLOAD_STOPPED = "The upload stopped before the end of the file"
EXPORT_GONE = "This download link was used or has expired; start the download again"
KEY_LOST = "The snapshot's key can't be decrypted with SLIPWAY_ENCRYPTION_KEY"
TOO_MANY_TRIES = "Too many passphrase attempts; wait 10 minutes and try again"


class SnapshotsError(RuntimeError):
    """A refusal with an HTTP status. ``str(exc)`` is plain English, safe to show, and holds no secret."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


# Sizes read the same on the Snapshots page as on the Backups card.
human_bytes = data.human_bytes


def check_name(name: Any) -> str:
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise SnapshotsError(422, BAD_NAME)
    return name


def check_notes(notes: Any) -> str:
    if notes is None:
        return ""
    if not isinstance(notes, str) or len(notes) > NOTES_MAX or "\x00" in notes:
        raise SnapshotsError(422, f"Notes are at most {NOTES_MAX} characters")
    return notes


# --- folders -------------------------------------------------------------------------------------------------


def storage_root() -> Path:
    return Path(get_settings().storage_dir).absolute()


def bundles_dir() -> Path:
    return storage_root() / "bundles"


def incoming_dir() -> Path:
    return storage_root() / "incoming"


def bundle_path(snapshot_id: uuid.UUID) -> Path:
    """The stored file of a snapshot. Built from the row's id only, never from anything a file says (I5)."""
    return bundles_dir() / f"{uuid.UUID(str(snapshot_id))}.sbx"


def unwritable_message() -> str:
    folder = storage_root()
    uid = os.getuid() if hasattr(os, "getuid") else 10001
    return (
        f"SLIPWAY_STORAGE_DIR ({folder}) isn't writable by Slipway (uid {uid}): on the server, run "
        f"chown {uid} {folder} && chmod 700 {folder}"
    )


def _ensure_folders() -> None:
    """Create the storage folders (0700) and check Slipway can write them. Raises OSError."""
    root = storage_root()
    for folder in (root, root / "bundles", root / "incoming"):
        folder.mkdir(mode=0o700, parents=folder is root, exist_ok=True)
        # The root may be a symlink an operator set up; the two folders Slipway made itself may not.
        if not folder.is_dir() or (folder is not root and folder.is_symlink()):
            raise NotADirectoryError(str(folder))
        if not os.access(folder, os.W_OK | os.X_OK):
            raise PermissionError(str(folder))
    with contextlib.suppress(OSError):  # tighten what we own; someone else's folder is checked above
        if root.stat().st_mode & 0o077:
            root.chmod(0o700)


def storage_problem() -> str | None:
    """None when snapshots can be stored, otherwise the 503 text."""
    try:
        _ensure_folders()
    except OSError:
        return unwritable_message()
    return None


def require_storage() -> None:
    """Raise the 503 when the storage folder isn't usable. Snapshot endpoints and the Snapshots page call it."""
    problem = storage_problem()
    if problem is not None:
        raise SnapshotsError(503, problem)


def _remove_quietly(path: Path) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        log.warning("Could not remove %s: %s", path, exc)


def remove_bundle(snapshot_id: uuid.UUID) -> None:
    _remove_quietly(bundle_path(snapshot_id))


class NewBundle:
    """A file being written to ``incoming/<stem>.partial`` (0600, ``O_CREAT|O_EXCL|O_NOFOLLOW``).

    ``write`` hashes and counts what it writes (``bytes``, ``sha256``). ``encrypting(data_key)`` gives a
    ``ContainerWriter`` that writes the stored form (key block ``kdf: none``) through it. ``install`` moves
    the finished file to ``bundles/<snapshot id>.sbx``, never replacing a file there; ``discard`` removes the
    partial. Use it from one thread at a time.
    """

    def __init__(self, stem: str | None = None) -> None:
        name = stem or uuid.uuid4().hex
        if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", name):
            raise ValueError("a partial's name is letters, digits and '-'")
        self.path = incoming_dir() / f"{name}.partial"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        self._f: BinaryIO = os.fdopen(os.open(self.path, flags, 0o600), "wb")
        self._hash = hashlib.sha256()
        self.bytes = 0
        self.installed: Path | None = None

    def write(self, data: bytes | bytearray | memoryview) -> int:
        self._f.write(data)
        self._hash.update(data)
        self.bytes += len(data)
        return len(data)

    @property
    def sha256(self) -> str:
        return self._hash.hexdigest()

    def encrypting(self, data_key: bytes) -> snapfile.ContainerWriter:
        return snapfile.ContainerWriter(self, data_key)

    def close(self) -> None:
        if not self._f.closed:
            self._f.flush()
            os.fsync(self._f.fileno())
            self._f.close()

    def install(self, snapshot_id: uuid.UUID) -> Path:
        self.close()
        final = bundle_path(snapshot_id)
        try:
            os.link(self.path, final)  # refuses to replace a file already there
        except FileExistsError:
            raise
        except OSError:  # a filesystem without hard links
            if os.path.lexists(final):
                raise FileExistsError(str(final)) from None
            os.rename(self.path, final)
        else:
            os.unlink(self.path)
        self.installed = final
        return final

    def discard(self) -> None:
        with contextlib.suppress(OSError):
            self._f.close()
        if self.installed is None:
            _remove_quietly(self.path)


def _clear_incoming() -> int:
    """Remove everything in ``incoming/`` (files left by a crash). Returns how many entries went."""
    removed = 0
    with os.scandir(incoming_dir()) as entries:
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    shutil.rmtree(entry.path)
                else:
                    os.unlink(entry.path)
                removed += 1
            except OSError as exc:
                log.warning("Could not remove %s from Slipway's storage: %s", entry.path, exc)
    return removed


# --- free space and quota ------------------------------------------------------------------------------------


def disk_free(path: Path) -> int:
    """Free bytes on the disk that holds ``path`` (one place, so tests can stand in a small disk)."""
    return shutil.disk_usage(path).free


def stored_size(plaintext_or_upload_bytes: int) -> int:
    """About how many bytes a stored ``.sbx`` of this many plaintext (or uploaded) bytes takes."""
    return plaintext_or_upload_bytes + snapfile.TAG * (plaintext_or_upload_bytes // MiB + 1) + SPACE_SLACK


_reservations: dict[int, int] = {}  # in-flight uploads and takes: id -> expected bytes
_quota_lock: asyncio.Lock | None = None  # one quota check at a time (see reserve)


def _quota_check_lock() -> asyncio.Lock:
    global _quota_lock
    if _quota_lock is None:
        _quota_lock = asyncio.Lock()
    return _quota_lock


async def stored_total(db: AsyncSession) -> int:
    """Bytes of every stored file (locked, checking and ready rows), without what is in flight."""
    total = await db.scalar(
        select(func.coalesce(func.sum(Snapshot.file_bytes), 0)).where(Snapshot.status.in_(STORED_STATUSES))
    )
    return int(total or 0)


async def usage(db: AsyncSession) -> dict[str, int]:
    """For the Snapshots page footer: ``<used> of <quota> used``."""
    return {"used": await stored_total(db), "quota": get_settings().snapshot_total_bytes}


def _check_free(need: int) -> None:
    free = disk_free(storage_root())
    if free < need + FREE_MARGIN:
        raise SnapshotsError(
            507, f"Slipway's storage has {human_bytes(free)} free; this snapshot needs about {human_bytes(need + FREE_MARGIN)}"
        )


class SpaceGuard:
    """Re-checks free space after every GiB written (§5). ``wrote(n)`` raises the 507."""

    def __init__(self, expected: int) -> None:
        self.expected = expected
        self.written = 0
        self._next = SPACE_RECHECK

    def wrote(self, n: int) -> None:
        self.written += n
        if self.written >= self._next:
            self._next = self.written + SPACE_RECHECK
            _check_free(max(self.expected - self.written, 0))


@asynccontextmanager
async def reserve(db: AsyncSession, expected: int) -> AsyncIterator[SpaceGuard]:
    """Check space and quota for ``expected`` new stored bytes and hold them until the block ends.

    Used before an upload and by the take's ``store`` step. The quota counts stored files plus every
    reservation in flight, so two uploads at once can't both squeeze under it. Raises the 507 or the 409.

    An upload commits its row and only then drops its reservation, so its bytes are always in one of the two
    numbers provided the reservations are summed *before* the stored total is read (read after, an upload
    that commits and ends during the read is in neither). Both may count a file that has just been
    committed, which only errs on the safe side. The lock keeps two checks from passing each other while one
    awaits the database.
    """
    require_storage()
    _check_free(expected)
    async with _quota_check_lock():
        in_flight = sum(_reservations.values())
        used = await stored_total(db)
        quota = get_settings().snapshot_total_bytes
        if used + in_flight + expected > quota:
            raise SnapshotsError(
                409,
                f"Snapshots on this Slipway already use {human_bytes(used + in_flight)} of {human_bytes(quota)} "
                "(SLIPWAY_SNAPSHOT_TOTAL_BYTES); delete some first",
            )
        key = id(object())
        while key in _reservations:  # pragma: no cover - ids of dead objects can repeat
            key += 1
        _reservations[key] = expected
    try:
        yield SpaceGuard(expected)
    finally:
        _reservations.pop(key, None)


# --- semaphores ----------------------------------------------------------------------------------------------

_transfer_sem: asyncio.Semaphore | None = None
_kdf_sem: asyncio.Semaphore | None = None


def _transfers() -> asyncio.Semaphore:
    global _transfer_sem
    if _transfer_sem is None:
        _transfer_sem = asyncio.Semaphore(get_settings().snapshot_transfers)
    return _transfer_sem


def _kdfs() -> asyncio.Semaphore:
    global _kdf_sem
    if _kdf_sem is None:
        _kdf_sem = asyncio.Semaphore(get_settings().snapshot_kdf_slots)
    return _kdf_sem


@asynccontextmanager
async def transfer(on_wait: Callable[[], Awaitable[Any]] | None = None) -> AsyncIterator[None]:
    """One of ``snapshot_transfers`` slots: takes and stores, staging, uploads, checks and downloads.

    ``on_wait`` runs first when every slot is taken (a job logs `Waiting for another snapshot transfer to
    finish`).
    """
    sem = _transfers()
    if sem.locked() and on_wait is not None:
        await on_wait()
    async with sem:
        yield


async def derive(fn: Callable[..., Any], *args: Any) -> Any:
    """Run a key derivation (scrypt) in a thread, inside the KDF semaphore."""
    async with _kdfs():
        return await asyncio.to_thread(fn, *args)


# --- rows ----------------------------------------------------------------------------------------------------


def _created_at(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def apply_manifest(snap: Snapshot, manifest: dict[str, Any]) -> None:
    """Fill a row's metadata from a checked ``slipway-snapshot.json``. Identity values are never stored in
    the row: only their names (the values stay inside the encrypted file)."""
    database = manifest["database"]
    files = manifest.get("files")
    identity = manifest.get("identity")
    snap.app = manifest["app"]
    snap.app_name = manifest["app_name"]
    snap.repository = manifest.get("repository")
    snap.source = manifest["source"]
    snap.commit_sha = manifest.get("commit")
    snap.source_created_at = _created_at(manifest["created_at"])
    snap.db_format = database["format"]
    snap.db_revision = database["revision"]
    snap.db_bytes = database["bytes"]
    snap.db_sha256 = database["sha256"]
    snap.files_format = files["format"] if files else None
    snap.files_bytes = files["bytes"] if files else None
    snap.files_sha256 = files["sha256"] if files else None
    snap.identity_keys = list(identity["keys"]) if identity else []
    if not snap.notes and manifest.get("notes"):
        snap.notes = manifest["notes"]


def encode_key(data_key: bytes) -> str:
    return base64.b64encode(data_key).decode("ascii")


def data_key(snap: Snapshot) -> bytes:
    """The snapshot's data key, or the 409 when it can't be read (SLIPWAY_ENCRYPTION_KEY changed)."""
    if not snap.data_key:
        raise SnapshotsError(409, KEY_LOST)
    try:
        raw = base64.b64decode(snap.data_key, validate=True)
    except (binascii.Error, ValueError):
        raise SnapshotsError(409, KEY_LOST) from None
    if len(raw) != 32:
        raise SnapshotsError(409, KEY_LOST)
    return raw


def _details(snap: Snapshot, **extra: Any) -> dict[str, Any]:
    """Audit details: name, app, repository, origin, sizes and checksum. Never keys or values."""
    details: dict[str, Any] = {
        "name": snap.name, "app": snap.app, "repository": snap.repository, "origin": snap.origin,
        "db_bytes": snap.db_bytes, "files_bytes": snap.files_bytes, "file_bytes": snap.file_bytes,
        "sha256": snap.file_sha256,
    }
    details.update(extra)
    return details


async def _name_taken(db: AsyncSession, name: str, *, other_than: uuid.UUID | None = None) -> bool:
    query = select(Snapshot.id).where(Snapshot.name == name)
    if other_than is not None:
        query = query.where(Snapshot.id != other_than)
    return await db.scalar(query.limit(1)) is not None


def _taken(name: str) -> SnapshotsError:
    return SnapshotsError(409, f"There is already a snapshot named {name}")


async def _load(db: AsyncSession, snapshot_id: uuid.UUID, *, lock: bool = False) -> Snapshot:
    query = select(Snapshot).where(Snapshot.id == snapshot_id).execution_options(populate_existing=True)
    if lock:
        query = query.with_for_update()
    snap = await db.scalar(query)
    if snap is None:
        raise SnapshotsError(404, "Snapshot not found")
    return snap


# --- upload --------------------------------------------------------------------------------------------------


class _Aborted(Exception):
    """The request side gave up; the worker thread stops quietly."""


class _Pipe:
    """Hands byte pieces from the event loop to one worker thread through a bounded queue.

    ``put`` (run with ``asyncio.to_thread``) blocks while the queue is full and returns False once the worker
    has stopped, so a worker that refused the file early never leaves the request side waiting.
    """

    _END = object()

    def __init__(self, depth: int = PIPE_DEPTH) -> None:
        self._q: queue.Queue[Any] = queue.Queue(depth)
        self._stopped = threading.Event()  # the worker ended (or must end)
        self._aborted = threading.Event()

    def put(self, piece: bytes) -> bool:
        while not self._stopped.is_set():
            try:
                self._q.put(piece, timeout=0.1)
                return True
            except queue.Full:
                continue
        return False

    def close(self) -> bool:
        return self.put(self._END)  # type: ignore[arg-type]

    def abort(self) -> None:
        self._aborted.set()
        self._stopped.set()

    def stop(self) -> None:
        self._stopped.set()

    def __iter__(self) -> Iterator[bytes]:
        while True:
            if self._aborted.is_set():
                raise _Aborted
            try:
                item = self._q.get(timeout=0.1)
            except queue.Empty:
                continue
            if item is self._END:
                return
            yield item


def _import_worker(pipe: _Pipe, bundle: NewBundle, preamble: snapfile.Preamble) -> int:
    """Write a passphrase-locked upload in its stored form: the same header, a ``kdf: none`` key block and
    the unchanged body. Returns the body's size."""
    try:
        bundle.write(preamble.stored_prefix())
        body = 0
        for piece in pipe:
            bundle.write(piece)
            body += len(piece)
        bundle.close()
        return body
    finally:
        pipe.stop()


@dataclass
class _PlainResult:
    contents: snapfile.SnapshotContents
    data_key: bytes


def _plain_worker(pipe: _Pipe, bundle: NewBundle, max_bytes: int) -> _PlainResult:
    """Encrypt a plain upload into the partial and validate it in the same pass (§10.5)."""
    try:
        key = snapfile.new_data_key()
        writer = bundle.encrypting(key)

        def plaintext() -> Iterator[bytes]:
            for piece in pipe:
                writer.write(piece)
                yield piece

        stream = plaintext()
        contents = snapfile.validate(stream, max_bytes=max_bytes)
        for _ in stream:  # validation reads to the end; anything left would be data after the end
            raise SnapshotError(snapfile.AFTER_END)
        writer.close()
        bundle.close()
        return _PlainResult(contents, key)
    finally:
        pipe.stop()


def _sniff(head: bytes, *, final: bool) -> tuple[str, snapfile.Preamble | None] | None:
    """What an upload is, from its first bytes: ("import", preamble) or ("plain", None). None while
    undecided (more bytes needed); ``final`` means no more bytes come."""
    magic = snapfile.MAGIC
    seen = min(len(head), len(magic))
    if seen and head[:seen] == magic[:seen]:
        if len(head) < len(magic):
            if final:
                raise SnapshotsError(422, NOT_A_BUNDLE)
            return None
        try:
            preamble = snapfile.parse_preamble(head)
        except SnapshotError as exc:
            raise SnapshotsError(422, str(exc)) from None
        if preamble is None:
            if final:
                raise SnapshotsError(422, snapfile.INCOMPLETE)
            return None
        if not preamble.locked:
            raise SnapshotsError(
                422,
                "This file has no passphrase, so it can't be opened here; download it again from its Slipway "
                "(it asks for a passphrase)",
            )
        return "import", preamble
    if head[:2] == b"\x1f\x8b":
        return "plain", None
    if len(head) >= SNIFF_PLAIN:
        if head[257:262] == b"ustar":
            return "plain", None
        raise SnapshotsError(422, NOT_A_BUNDLE)
    if final:
        raise SnapshotsError(422, NOT_A_BUNDLE)
    return None  # a gzip magic or "ustar" may still come


def _content_length(value: str | int | None) -> int:
    if value is None or value == "":
        raise SnapshotsError(411, "Send the file with a Content-Length header (curl: --data-binary @file)")
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise SnapshotsError(400, "The Content-Length header isn't a number") from None
    if n < 0:
        raise SnapshotsError(400, "The Content-Length header isn't a number")
    return n


async def receive_upload(
    db: AsyncSession,
    *,
    name: str,
    notes: str | None,
    content_length: str | int | None,
    body: AsyncIterable[bytes],
    user: User,
    request: Request | None = None,
) -> Snapshot:
    """Store an uploaded snapshot file (§10.5) and return its row.

    A passphrase-encrypted file (``SLWSNAP1``) is kept as it came, with a ``kdf: none`` key block in front of
    the unchanged body, and its row is ``locked`` until ``unlock``. A plain tar or tar.gz is encrypted under a
    new data key and validated in one streaming pass, and its row is ``ready``. Anything else is refused.
    The partial is always removed. Commits ``db``.
    """
    settings = get_settings()
    check_name(name)
    notes = check_notes(notes)
    require_storage()
    if await _name_taken(db, name):
        raise _taken(name)
    declared = _content_length(content_length)
    cap = settings.snapshot_max_bytes
    if declared > cap:
        raise SnapshotsError(
            413, f"The file is larger than this Slipway accepts ({human_bytes(cap)}, SLIPWAY_SNAPSHOT_MAX_BYTES)"
        )
    user_id = user.id

    async with reserve(db, stored_size(declared)) as guard:
        # End the read transaction before a long upload (expire_on_commit is off, so user stays loaded).
        await db.commit()
        async with transfer():
            bundle = await asyncio.to_thread(NewBundle)
            pipe = _Pipe()
            worker: asyncio.Future[Any] | None = None
            mode: str | None = None
            preamble: snapfile.Preamble | None = None
            head = bytearray()
            buffer = bytearray()
            received = 0

            async def send(data: bytes | bytearray) -> bool:
                return await asyncio.to_thread(pipe.put, bytes(data))

            def start(kind: str, pre: snapfile.Preamble | None) -> asyncio.Future[Any]:
                if kind == "import":
                    assert pre is not None
                    return asyncio.ensure_future(asyncio.to_thread(_import_worker, pipe, bundle, pre))
                return asyncio.ensure_future(asyncio.to_thread(_plain_worker, pipe, bundle, cap))

            try:
                try:
                    async for chunk in body:
                        if not chunk:
                            continue
                        received += len(chunk)
                        if received > declared:
                            raise SnapshotsError(
                                413, f"The upload is longer than its Content-Length ({declared} bytes)"
                            )
                        guard.wrote(len(chunk))
                        if mode is None:
                            head += chunk
                            sniffed = _sniff(bytes(head), final=False)
                            if sniffed is None:
                                continue
                            mode, preamble = sniffed
                            worker = start(mode, preamble)
                            rest = bytes(head[preamble.length:]) if preamble is not None else bytes(head)
                            buffer += rest
                        else:
                            buffer += chunk
                        if len(buffer) >= PIECE:
                            if not await send(buffer):
                                break  # the worker refused the file; its error is raised below
                            buffer = bytearray()
                except ClientDisconnect:
                    raise SnapshotsError(400, UPLOAD_STOPPED) from None
                if worker is None or not worker.done():
                    if received < declared:
                        raise SnapshotsError(400, UPLOAD_STOPPED)
                if mode is None:
                    sniffed = _sniff(bytes(head), final=True)
                    assert sniffed is not None  # final=True decides or raises
                    mode, preamble = sniffed
                    worker = start(mode, preamble)
                    buffer += bytes(head[preamble.length:]) if preamble is not None else bytes(head)
                assert worker is not None
                if buffer and not worker.done():
                    await send(buffer)
                if not worker.done():
                    await asyncio.to_thread(pipe.close)
                try:
                    result = await worker
                except SnapshotError as exc:
                    raise SnapshotsError(422, str(exc)) from None

                if mode == "import":
                    assert preamble is not None
                    if result < snapfile.TAG:
                        raise SnapshotsError(422, snapfile.INCOMPLETE)
                    snap = Snapshot(
                        id=uuid.uuid4(), name=name, notes=notes, status=SnapshotStatus.LOCKED,
                        origin=SnapshotOrigin.IMPORT, import_keyblock=dict(preamble.keyblock),
                        expires_at=utcnow() + timedelta(days=settings.snapshot_locked_days),
                        file_bytes=bundle.bytes, file_sha256=bundle.sha256, created_by_id=user_id,
                    )
                else:
                    plain: _PlainResult = result
                    snap = Snapshot(
                        id=uuid.uuid4(), name=name, notes=notes, status=SnapshotStatus.READY,
                        origin=SnapshotOrigin.UPLOAD, data_key=encode_key(plain.data_key),
                        file_bytes=bundle.bytes, file_sha256=bundle.sha256, created_by_id=user_id,
                    )
                    apply_manifest(snap, plain.contents.manifest)
                return await _insert_with_file(db, snap, bundle, user, request, encrypted=mode == "import")
            except BaseException:
                pipe.abort()
                if worker is not None:
                    with contextlib.suppress(BaseException):
                        await worker
                raise
            finally:
                await asyncio.to_thread(bundle.discard)


async def _insert_with_file(
    db: AsyncSession, snap: Snapshot, bundle: NewBundle, user: User, request: Request | None, *, encrypted: bool
) -> Snapshot:
    """Move the finished partial to ``bundles/<id>.sbx`` and commit the row; on any failure neither stays."""
    await asyncio.to_thread(bundle.install, snap.id)
    try:
        db.add(snap)
        audit.record(
            db, "snapshot.upload", actor=user, target=snap,
            summary=f"Uploaded snapshot {snap.name}",
            details=_details(snap, encrypted=encrypted, status=snap.status),
            request=request,
        )
        await db.commit()
    except IntegrityError:
        await db.rollback()
        remove_bundle(snap.id)
        raise _taken(snap.name) from None
    except BaseException:
        with contextlib.suppress(Exception):
            await db.rollback()
        remove_bundle(snap.id)
        raise
    log.info("Stored snapshot %s (%s, %s)", snap.name, snap.status, human_bytes(snap.file_bytes or 0))
    return snap


# --- unlock and the background check -------------------------------------------------------------------------

unlock_limiter = RateLimiter(limit=5, window_seconds=600)


def _read_preamble(path: Path) -> snapfile.Preamble:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        return snapfile.read_preamble(f)


async def unlock(
    db: AsyncSession, snapshot_id: uuid.UUID, passphrase: str, *, user: User, request: Request | None = None
) -> Snapshot:
    """Unlock an imported file with its passphrase (§10.5 step 4): keep its data key, then check the file in
    the background (``checking`` -> ``ready`` or ``failed``). Commits ``db``.

    A wrong passphrase is a 422 and the row stays locked. Each user may try 5 times in 10 minutes (429).
    """
    snap = await _load(db, snapshot_id)
    if snap.status != SnapshotStatus.LOCKED or not snap.import_keyblock:
        raise SnapshotsError(409, f"Snapshot {snap.name} isn't waiting for a passphrase")
    keyblock = dict(snap.import_keyblock)
    limiter_key = str(user.id)
    await db.commit()  # don't hold a transaction across the key derivation
    if not unlock_limiter.acquire(limiter_key):
        raise SnapshotsError(429, TOO_MANY_TRIES)
    try:
        preamble = await asyncio.to_thread(_read_preamble, bundle_path(snapshot_id))
    except (OSError, SnapshotError):
        unlock_limiter.undo(limiter_key)
        raise SnapshotsError(409, f"Slipway can't read the stored file of snapshot {snap.name}; delete it") from None
    try:
        key = await derive(snapfile.unwrap_key, keyblock, passphrase, preamble.header_hash)
    except SnapshotError as exc:
        raise SnapshotsError(422, str(exc)) from None

    unlock_limiter.undo(limiter_key)  # the right passphrase doesn't count against the user
    snap = await _load(db, snapshot_id, lock=True)
    if snap.status != SnapshotStatus.LOCKED:
        raise SnapshotsError(409, f"Snapshot {snap.name} isn't waiting for a passphrase")
    snap.data_key = encode_key(key)
    snap.import_keyblock = None
    snap.expires_at = None
    snap.status = SnapshotStatus.CHECKING
    snap.error = None
    audit.record(db, "snapshot.unlock", actor=user, target=snap, summary=f"Unlocked snapshot {snap.name}",
                 details=_details(snap), request=request)
    await db.commit()
    schedule_validation(snap.id)
    return snap


_tasks: dict[uuid.UUID, asyncio.Task[None]] = {}


def schedule_validation(snapshot_id: uuid.UUID) -> None:
    """Check a ``checking`` row's stored file in the background (at most one task per snapshot)."""
    task = _tasks.get(snapshot_id)
    if task is not None and not task.done():
        return
    task = asyncio.create_task(validate_stored(snapshot_id), name=f"snapshot-check-{snapshot_id}")
    _tasks[snapshot_id] = task
    task.add_done_callback(lambda t, sid=snapshot_id: _tasks.pop(sid, None) if _tasks.get(sid) is t else None)


async def wait_for_validations() -> None:
    """Wait until every background check has finished (tests; and a calm shutdown)."""
    while _tasks:
        await asyncio.gather(*list(_tasks.values()), return_exceptions=True)


class _HashingReader:
    def __init__(self, f: BinaryIO) -> None:
        self._f = f
        self.digest = hashlib.sha256()
        self.count = 0

    def read(self, n: int = -1, /) -> bytes:
        data = self._f.read(n)
        self.digest.update(data)
        self.count += len(data)
        return data


def _check_file(path: Path, key: bytes, max_bytes: int) -> tuple[snapfile.SnapshotContents, int, str]:
    """Decrypt and validate a stored file (§10.3), hashing every byte of it."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        reader = _HashingReader(f)
        contents = snapfile.validate_container(reader, key, max_bytes=max_bytes)
        if reader.read(1):  # pragma: no cover - validate_container reads to the end
            raise SnapshotError(snapfile.AFTER_END)
        return contents, reader.count, reader.digest.hexdigest()


CHECK_FAILED = "The check failed"
FILE_MISSING = "The stored file is missing"


async def validate_stored(snapshot_id: uuid.UUID) -> None:
    """The background check: the row becomes ``ready`` (metadata filled) or ``failed`` (the file deleted).

    Whatever goes wrong, the row leaves ``checking`` (a ``checking`` row can't be deleted, §10.8), with one
    exception: when Slipway can't read its storage folder or the file (permissions, a disk error), the row
    and its data key stay as they are and the check runs again at the next start, so fixing the folder
    brings the snapshot back.
    """
    async with transfer():
        async with session_scope() as db:
            snap = await db.get(Snapshot, snapshot_id)
            if snap is None or snap.status != SnapshotStatus.CHECKING:
                return
            expected = (snap.file_bytes, snap.file_sha256)
            try:
                key: bytes | None = data_key(snap)
            except SnapshotsError:
                key = None
        error: str | None = None
        manifest: dict[str, Any] | None = None
        if key is None:
            error = KEY_LOST
        else:
            try:
                contents, size, sha = await asyncio.to_thread(
                    _check_file, bundle_path(snapshot_id), key, get_settings().snapshot_max_bytes
                )
            except SnapshotError as exc:
                error = str(exc)
            except FileNotFoundError as exc:
                if storage_problem() is not None:
                    log.warning("Snapshot %s is checked again at the next start: %s (%s)",
                                snapshot_id, unwritable_message(), exc)
                    return
                error = FILE_MISSING
            except OSError as exc:
                # Not the file's fault: keep the row and its key, and check again at the next start.
                log.warning("Could not read snapshot file %s; it is checked again at the next start: %s",
                            snapshot_id, exc)
                return
            except Exception:
                log.exception("The check of snapshot %s failed", snapshot_id)
                error = CHECK_FAILED
            else:
                if expected[1] is not None and (sha != expected[1] or size != expected[0]):
                    error = "The stored file changed since it was uploaded"
                manifest = contents.manifest

    if error is None and manifest is not None:
        try:
            await _finish_check(snapshot_id, None, manifest)
            return
        except Exception:
            # What the file says can't be stored (the database refused a value): the check fails instead.
            log.exception("Could not save the check of snapshot %s", snapshot_id)
            error = CHECK_FAILED
    try:
        failed = await _finish_check(snapshot_id, error or CHECK_FAILED, None)
    except Exception:
        log.exception("Could not mark snapshot %s as failed; it is checked again at the next start", snapshot_id)
        return
    if failed:
        remove_bundle(snapshot_id)
        log.info("Snapshot %s failed its check: %s", snapshot_id, error)


async def _finish_check(snapshot_id: uuid.UUID, error: str | None, manifest: dict[str, Any] | None) -> bool:
    """Move a ``checking`` row to ``ready`` (no error) or ``failed``, in its own transaction. Returns False
    when the row is gone or no longer ``checking``."""
    async with session_scope() as db:
        snap = await db.get(Snapshot, snapshot_id, with_for_update=True)
        if snap is None or snap.status != SnapshotStatus.CHECKING:
            return False
        if error is None and manifest is not None:
            apply_manifest(snap, manifest)
            snap.status = SnapshotStatus.READY
            snap.error = None
            audit.record(db, "snapshot.ready", target=snap, summary=f"Snapshot {snap.name} is ready",
                         details=_details(snap))
        else:
            snap.status = SnapshotStatus.FAILED
            snap.error = (error or CHECK_FAILED)[:500]
            if error != FILE_MISSING:
                # A missing file may only be on a volume that isn't mounted: with its key kept, the next
                # start checks it again once the file is back (prepare_storage).
                snap.data_key = None
            audit.record(db, "snapshot.failed", target=snap, summary=f"Snapshot {snap.name} failed its check",
                         details=_details(snap, error=snap.error))
    return True


# --- export tickets and the download -------------------------------------------------------------------------


@dataclass
class _Ticket:
    user_id: uuid.UUID
    snapshot_id: uuid.UUID
    keyblock: dict[str, Any]
    expires_at: datetime
    bytes: int
    created: datetime = field(default_factory=utcnow)


_tickets: dict[str, _Ticket] = {}  # sha256(token) -> ticket


@dataclass(frozen=True)
class ExportTicket:
    """What ``POST /snapshots/{id}/exports`` answers. ``token`` appears only in ``url``."""

    token: str
    url: str
    expires_at: datetime
    bytes: int


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8", "surrogatepass")).hexdigest()


def _prune_tickets(now: datetime) -> None:
    for key in [k for k, t in _tickets.items() if t.expires_at <= now]:
        del _tickets[key]


async def create_export(
    db: AsyncSession, snapshot_id: uuid.UUID, passphrase: str, *, user: User, request: Request | None = None
) -> ExportTicket:
    """Lock a ready snapshot's data key with a passphrase for one download (§10.6 step 1). Commits ``db``.

    The passphrase is used for one key derivation and then forgotten. The ticket holds only the new key
    block; the token is kept hashed, for 10 minutes, at most 3 per user (the oldest goes).
    """
    try:
        snapfile.check_passphrase(passphrase)
    except SnapshotError as exc:
        raise SnapshotsError(422, str(exc)) from None
    require_storage()
    snap = await _load(db, snapshot_id)
    if snap.status != SnapshotStatus.READY:
        raise SnapshotsError(409, f"Snapshot {snap.name} isn't ready")
    key = data_key(snap)
    try:
        preamble = await asyncio.to_thread(_read_preamble, bundle_path(snap.id))
    except (OSError, SnapshotError):
        raise SnapshotsError(409, f"Slipway can't read the stored file of snapshot {snap.name}") from None
    keyblock = await derive(snapfile.wrap_key, key, passphrase, preamble.header_hash)
    del passphrase, key
    size = (snap.file_bytes or 0) - preamble.length + len(preamble.prefix(keyblock))

    now = utcnow()
    _prune_tickets(now)
    mine = sorted((t.created, k) for k, t in _tickets.items() if t.user_id == user.id)
    for _, k in mine[: max(0, len(mine) - EXPORTS_PER_USER + 1)]:
        del _tickets[k]
    token = secrets.token_urlsafe(32)
    ticket = _Ticket(user.id, snap.id, keyblock, now + EXPORT_TTL, size)
    _tickets[_token_hash(token)] = ticket
    audit.record(db, "snapshot.export", actor=user, target=snap, summary=f"Prepared a download of snapshot {snap.name}",
                 details={"name": snap.name, "bytes": size}, request=request)
    await db.commit()
    return ExportTicket(token, f"/api/v1/snapshot-exports/{token}", ticket.expires_at, size)


def take_export(token: str, user_id: uuid.UUID, *, now: datetime | None = None) -> _Ticket:
    """Pop a ticket for its own user (single use). Another user's token, or a used or expired one, is a 404
    (another user's attempt leaves the ticket for its owner)."""
    now = now or utcnow()
    key = _token_hash(token)
    ticket = _tickets.get(key)
    if ticket is None or ticket.user_id != user_id:
        raise SnapshotsError(404, EXPORT_GONE)
    del _tickets[key]
    if ticket.expires_at <= now:
        raise SnapshotsError(404, EXPORT_GONE)
    return ticket


@dataclass
class ExportStream:
    """A download: headers to send and the body. The body takes a transfer slot while it runs."""

    filename: str
    content_length: int
    body: AsyncIterator[bytes]


async def open_export(db: AsyncSession, token: str, *, user: User) -> ExportStream:
    """Start the download a ticket allows (§10.6 step 2). The caller checks that ``user`` still holds
    ``snapshots:download``.

    The body is the stored file with the ticket's key block in place of ``kdf: none``. The stored file is
    hashed while it streams and its last part (the final chunk) is held back until the hash equals
    ``file_sha256``; a mismatch ends the stream early, so the receiver sees `The file is incomplete`.
    """
    ticket = take_export(token, user.id)
    snap = await db.get(Snapshot, ticket.snapshot_id)
    if snap is None or snap.status != SnapshotStatus.READY or not snap.file_sha256:
        raise SnapshotsError(404, "The snapshot was deleted")
    path = bundle_path(snap.id)
    try:
        fd = await asyncio.to_thread(os.open, path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise SnapshotsError(404, "The snapshot's stored file is missing") from None
    f = os.fdopen(fd, "rb")
    try:
        preamble = await asyncio.to_thread(snapfile.read_preamble, f)
    except (OSError, SnapshotError):
        f.close()
        raise SnapshotsError(409, f"Slipway can't read the stored file of snapshot {snap.name}") from None
    head = preamble.prefix(ticket.keyblock)
    expected_sha, expected_bytes = snap.file_sha256, snap.file_bytes or 0
    hold = (1 << preamble.chunk_log2) + snapfile.TAG
    name, snap_id, user_id = snap.name, snap.id, user.id
    size = expected_bytes - preamble.length + len(head)

    async def body() -> AsyncIterator[bytes]:
        sent = 0
        complete = False
        try:
            async with transfer():
                digest = hashlib.sha256(preamble.prefix())
                total = preamble.length
                yield head
                sent += len(head)
                pending = bytearray()
                while True:
                    block = await asyncio.to_thread(f.read, PIECE)
                    if not block:
                        break
                    digest.update(block)
                    total += len(block)
                    pending += block
                    if len(pending) > hold:
                        out = bytes(pending[:-hold])
                        del pending[:-hold]
                        yield out
                        sent += len(out)
                if digest.hexdigest() != expected_sha or total != expected_bytes:
                    log.error("The stored file of snapshot %s changed on disk; the download was stopped", name)
                    raise SnapshotsError(409, f"The stored file of snapshot {name} has changed; Slipway stopped the download")
                yield bytes(pending)
                sent += len(pending)
                complete = True
        finally:
            f.close()
            with contextlib.suppress(Exception):
                async with session_scope() as adb:
                    actor = await adb.get(User, user_id)
                    audit.record(adb, "snapshot.download", actor=actor, target_type="snapshot", target=snap_id,
                                 summary=f"Downloaded snapshot {name}" if complete else f"Download of snapshot {name} stopped",
                                 details={"name": name, "bytes_sent": sent, "complete": complete})

    return ExportStream(f"{name}.slipway-snapshot", size, body())


# --- rename and delete ---------------------------------------------------------------------------------------


async def update_snapshot(
    db: AsyncSession,
    snapshot_id: uuid.UUID,
    *,
    name: str | None = None,
    notes: str | None = None,
    user: User,
    request: Request | None = None,
) -> Snapshot:
    """Rename a snapshot or change its notes (``PATCH /snapshots/{id}``). Commits ``db``."""
    if name is not None:
        check_name(name)
    if notes is not None:
        notes = check_notes(notes)
    snap = await _load(db, snapshot_id, lock=True)
    changed: dict[str, Any] = {}
    if name is not None and name != snap.name:
        if await _name_taken(db, name, other_than=snap.id):
            raise _taken(name)
        changed["name"] = {"from": snap.name, "to": name}
        snap.name = name
    if notes is not None and notes != snap.notes:
        changed["notes"] = True
        snap.notes = notes
    if not changed:
        return snap
    audit.record(db, "snapshot.update", actor=user, target=snap, summary=f"Updated snapshot {snap.name}",
                 details=_details(snap, changed=changed), request=request)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise _taken(name or "") from None
    return snap


def _restore_done(dep: Deployment) -> bool:
    """True when the job's ``restore`` step succeeded, here or in an earlier attempt (``done_by``)."""
    for row in dep.steps or []:
        if row.get("key") == "restore":
            return row.get("status") == "succeeded" or bool(row.get("done_by"))
    return False


async def in_use_reason(db: AsyncSession, snap: Snapshot) -> str | None:
    """Why a snapshot can't be deleted now (§10.8), or None."""
    if snap.status == SnapshotStatus.PENDING:
        return "it is still being taken"
    if snap.status == SnapshotStatus.CHECKING:
        return "it is still being checked"
    active = await db.scalar(
        select(Deployment)
        .where(Deployment.snapshot_id == snap.id,
               Deployment.status.in_([DeploymentStatus.QUEUED, DeploymentStatus.RUNNING]))
        .limit(1)
    )
    if active is not None:
        inst = await db.get(Instance, active.instance_id)
        where = inst.name if inst is not None else "an instance"
        return f"a {active.kind} job of {where} ({active.id.hex[:8]}) uses it"
    seeding = await db.scalar(
        select(Instance).where(Instance.seed_snapshot_id == snap.id, Instance.current_commit_sha.is_(None)).limit(1)
    )
    if seeding is not None:
        return f"{seeding.name} starts from it when it is first deployed"
    failed = (await db.scalars(
        select(Deployment).where(
            Deployment.snapshot_id == snap.id,
            Deployment.status.in_([DeploymentStatus.FAILED, DeploymentStatus.CANCELLED]),
        )
    )).all()
    for dep in failed:
        latest = await data.latest_changing_job(db, dep.instance_id)
        if latest is not None and latest.id == dep.id and not _restore_done(dep):
            inst = await db.get(Instance, dep.instance_id)
            where = inst.name if inst is not None else "an instance"
            return f"the last {dep.kind} of {where} ({dep.id.hex[:8]}) failed before it restored it; a retry needs it"
    return None


async def delete_snapshot(
    db: AsyncSession, snapshot_id: uuid.UUID, *, user: User, request: Request | None = None
) -> None:
    """Delete a snapshot and its stored file (§10.8), unless it is in use (409). Commits ``db``."""
    snap = await _load(db, snapshot_id, lock=True)
    reason = await in_use_reason(db, snap)
    if reason is not None:
        raise SnapshotsError(409, f"Snapshot {snap.name} is in use: {reason}")
    details = _details(snap, status=snap.status)
    audit.record(db, "snapshot.delete", actor=user, target=snap, summary=f"Deleted snapshot {snap.name}",
                 details=details, request=request)
    await db.delete(snap)
    await db.commit()
    remove_bundle(snapshot_id)


# --- startup and the sweep -----------------------------------------------------------------------------------


def _stored_bundles() -> dict[uuid.UUID, Path]:
    """The ``bundles/<uuid>.sbx`` files on disk, by id. Anything else in the folder is left alone."""
    found: dict[uuid.UUID, Path] = {}
    with os.scandir(bundles_dir()) as entries:
        for entry in entries:
            stem, dot, ext = entry.name.rpartition(".")
            if not dot or ext != "sbx" or not entry.is_file(follow_symlinks=False):
                continue
            try:
                snapshot_id = uuid.UUID(stem)
            except ValueError:
                continue
            if str(snapshot_id) == stem:
                found[snapshot_id] = Path(entry.path)
    return found


def _remove_files(ids: Iterable[uuid.UUID], found: dict[uuid.UUID, Path]) -> int:
    removed = 0
    for snapshot_id in ids:
        if snapshot_id in found:
            _remove_quietly(found[snapshot_id])
            removed += 1
    return removed


async def prepare_storage() -> bool:
    """At startup (after ``recover_interrupted``): create and check the folders, remove what a crash left in
    ``incoming/``, and check ``checking`` rows again. Never raises: when the folder isn't usable it logs the
    503 text and returns False (deploys are unaffected).

    A stored file is removed only when its row says it shouldn't be there: a take that crashed between
    moving its file into ``bundles/`` and committing READY is ``failed`` (or still ``pending``), and its Retry
    must be able to put its file there again. A file with no row at all is left alone and logged: Slipway may
    have started against another database, and its snapshots would be lost. A file that was missing when it
    was checked (an unmounted volume) and is back is checked again. Only for startup: while an upload or a
    take saves its row, its file looks the same."""
    try:
        await asyncio.to_thread(_ensure_folders)
        removed = await asyncio.to_thread(_clear_incoming)
    except OSError as exc:
        log.error("%s (%s)", unwritable_message(), exc)
        return False
    if removed:
        log.info("Removed %d unfinished file(s) from %s", removed, incoming_dir())
    try:
        found = await asyncio.to_thread(_stored_bundles)
    except OSError as exc:
        log.warning("Could not list the stored files in %s: %s", bundles_dir(), exc)
        found = {}
    revived: list[uuid.UUID] = []
    try:
        async with session_scope() as db:
            rows = (await db.execute(
                select(Snapshot.id, Snapshot.status, Snapshot.error, Snapshot.data_key.is_not(None).label("keyed"))
                .where(or_(Snapshot.status == SnapshotStatus.CHECKING, Snapshot.id.in_(list(found))))
            )).all()
            known = {row.id for row in rows}
            stale = [row.id for row in rows if row.id in found and row.status not in STORED_STATUSES
                     and not (row.status == SnapshotStatus.FAILED and row.error == FILE_MISSING and row.keyed)]
            revived = [row.id for row in rows if row.id in found and row.status == SnapshotStatus.FAILED
                       and row.error == FILE_MISSING and row.keyed]
            if revived:
                await db.execute(update(Snapshot).where(Snapshot.id.in_(revived), Snapshot.status == SnapshotStatus.FAILED)
                                 .values(status=SnapshotStatus.CHECKING, error=None))
            checking = [row.id for row in rows if row.status == SnapshotStatus.CHECKING]
    except Exception:
        log.exception("Could not list the stored snapshots")
        return True
    unknown = [i for i in found if i not in known]
    if unknown:
        log.warning("%d stored file(s) in %s have no snapshot in this database; they are left alone",
                    len(unknown), bundles_dir())
    try:
        gone = await asyncio.to_thread(_remove_files, stale, found)
    except OSError as exc:
        log.warning("Could not remove stored files of failed snapshots in %s: %s", bundles_dir(), exc)
    else:
        if gone:
            log.info("Removed %d stored file(s) of failed snapshots from %s", gone, bundles_dir())
    for snapshot_id in revived:
        log.info("The stored file of snapshot %s is back; it is checked again", snapshot_id)
    for snapshot_id in [*checking, *revived]:
        schedule_validation(snapshot_id)
    return True


async def sweep_once(*, now: datetime | None = None) -> list[str]:
    """Delete locked imports past ``expires_at`` with their files, and forget expired export tickets.
    Returns the names deleted."""
    now = now or utcnow()
    _prune_tickets(now)
    async with session_scope() as db:
        expired = (await db.scalars(
            select(Snapshot)
            .where(Snapshot.status == SnapshotStatus.LOCKED, Snapshot.expires_at.is_not(None),
                   Snapshot.expires_at <= now)
            .with_for_update()
        )).all()
        gone = [(s.id, s.name) for s in expired]
        for snap in expired:
            audit.record(db, "snapshot.expired", target=snap,
                         summary=f"Deleted snapshot {snap.name}: nobody unlocked it in time",
                         details=_details(snap, expires_at=snap.expires_at.isoformat() if snap.expires_at else None))
            await db.delete(snap)
    for snapshot_id, name in gone:
        remove_bundle(snapshot_id)
        log.info("Deleted locked snapshot %s: nobody unlocked it before it expired", name)
    return [name for _, name in gone]


async def sweep_forever(interval: float = SWEEP_INTERVAL) -> None:
    """Run ``sweep_once`` now and then every hour; started with the host poller and cancelled with it."""
    while True:
        try:
            await sweep_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # keep sweeping whatever happens
            log.exception("Snapshot sweep failed")
        await asyncio.sleep(interval)


async def shutdown() -> None:
    """Cancel background checks; their rows stay ``checking`` and are checked again at the next start."""
    tasks = list(_tasks.values())
    for task in tasks:
        task.cancel()
    for task in tasks:
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task
    _tasks.clear()


def reset_state() -> None:
    """Forget in-process state: tickets, reservations, the unlock limiter and the semaphores (tests)."""
    global _transfer_sem, _kdf_sem, _quota_lock
    _tickets.clear()
    _reservations.clear()
    unlock_limiter.clear()
    _transfer_sem = None
    _kdf_sem = None
    _quota_lock = None
