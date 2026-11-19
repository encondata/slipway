"""Backups Slipway keeps on its own server (P4 §10.5): a managed environment's data owner has no host.

The owner's dump is written on the runner's machine as phase 2 writes it, then ``pull`` streams it through
``snapfile.ContainerWriter`` under a fresh per-backup key into ``<storage_dir>/backups/<owner id>/<name>.db.sbc``
(and ``<name>.files.sbc``), hashing the plaintext on the way. Each file is first written as ``<file>.part``,
fsynced, checked against the host's hash, and only then renamed; the folder is fsynced, and only after that is
the host's copy removed. So a ``.sbc`` file always holds a whole, checked container, and a cut stream leaves
only a ``.part`` that ``sweep`` removes at start-up.

``push`` is the other way (restore, roll back, a seeding reset): it decrypts into a file on the runner, checks
the hash there, and removes the copy in a ``finally``. ``check`` answers ok, missing or changed as phase 2's
host check does; ``delete`` removes the files; ``keep`` moves an owner's files aside at teardown. A backup
whose ``data_key`` can't be read (SLIPWAY_ENCRYPTION_KEY changed) can only be deleted.

The caller writes the row: ``apply`` sets ``location``, ``data_key`` and ``stored_bytes`` from what ``pull``
returns. Data keys are never logged or audited.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hashlib
import logging
import os
import shlex
import shutil
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO, Protocol

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.core.config import get_settings
from slipway.db.base import utcnow
from slipway.db.session import session_scope
from slipway.models import Backup, BackupLocation, BackupStatus
from slipway.services import snapfile
from slipway.services.snapfile import SnapshotError

log = logging.getLogger(__name__)

MiB = 1024 * 1024
FOLDER = "backups"
KEPT_FOLDER = "kept"
PART = ".part"
# The host's file of each part (data.BACKUP_PARTS) and the stored file it becomes.
SUFFIXES = {"dump": "db.sbc", "files": "files.sbc"}
SPACE_SLACK = 64 * 1024  # each container's preamble and last tag, on top of the per-MiB tags

KEY_LOST = "Slipway can't open this backup any more (SLIPWAY_ENCRYPTION_KEY changed)"
CHANGED_ON_THE_WAY = "The backup changed on its way to Slipway"

Say = Callable[[str], Awaitable[None]]


class BackupStoreError(RuntimeError):
    """A refusal or failure of the store; the message is meant for the user."""


class Remote(Protocol):
    async def run(self, command: str, *, check: bool = True, on_line: Any = None,
                  timeout: float | None = None) -> tuple[int, str]: ...

    def read_stream(self, path: str, chunk: int | None = None) -> AsyncIterator[bytes]: ...

    async def write_stream(self, path: str, chunks: Any, mode: int = 0o600) -> int: ...


@dataclass(frozen=True)
class Stored:
    """What ``pull`` wrote: the encoded data key, the bytes the files take, and the plaintext sizes."""

    data_key: str
    stored_bytes: int
    db_bytes: int
    files_bytes: int | None

    def __repr__(self) -> str:  # never show the key
        return f"Stored(stored_bytes={self.stored_bytes}, db_bytes={self.db_bytes}, files_bytes={self.files_bytes})"


@dataclass(frozen=True)
class Checked:
    """``check``'s answer: ``ok``, ``missing`` or ``changed`` (the backup statuses phase 2 uses), and why."""

    status: str
    text: str | None = None


def _data() -> Any:
    from slipway.services import data  # data.py calls this module too; imported when first needed

    return data


# --- where the files are -------------------------------------------------------------------------------------


def root() -> Path:
    """``<storage_dir>/backups``."""
    return Path(get_settings().storage_dir) / FOLDER


def _owner_id(owner: Any) -> uuid.UUID:
    return owner if isinstance(owner, uuid.UUID) else owner.id


def owner_dir(owner: Any) -> Path:
    """The folder of one data owner's backups: ``backups/<owner id>``."""
    return root() / _owner_id(owner).hex


def stored_path(owner: Any, name: str, part: str) -> Path:
    """``backups/<owner id>/<name>.db.sbc`` (part ``dump``) or ``<name>.files.sbc`` (part ``files``)."""
    if part not in SUFFIXES:
        raise ValueError(part)
    return owner_dir(owner) / f"{_data().check_name(name)}.{SUFFIXES[part]}"


def _parts(backup: Backup) -> list[str]:
    return ["dump", "files"] if backup.has_files else ["dump"]


def _expected(backup: Backup, part: str) -> str | None:
    return backup.db_sha256 if part == "dump" else backup.files_sha256


def _size(backup: Backup, part: str) -> int | None:
    return backup.db_bytes if part == "dump" else backup.files_bytes


def encode_key(key: bytes) -> str:
    return base64.b64encode(key).decode("ascii")


def key_of(backup: Backup) -> bytes | None:
    """The backup's data key, or None when it can't be read (cleared after SLIPWAY_ENCRYPTION_KEY changed)."""
    if not backup.data_key:
        return None
    try:
        raw = base64.b64decode(backup.data_key, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if len(raw) == 32 else None


def usable(backup: Backup) -> str | None:
    """Why a Slipway-stored backup can only be deleted, or None when it can be used."""
    return KEY_LOST if key_of(backup) is None else None


def apply(backup: Backup, stored: Stored) -> None:
    """Write what ``pull`` stored onto the row (the caller commits)."""
    backup.location = BackupLocation.SLIPWAY.value
    backup.data_key = stored.data_key
    backup.stored_bytes = stored.stored_bytes


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _remove_quietly(path: Path) -> bool:
    try:
        os.unlink(path)
    except FileNotFoundError:
        return False
    except OSError as exc:
        log.warning("Could not remove %s: %s", path, exc)
        return False
    return True


def _open_new(path: Path) -> BinaryIO:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    return os.fdopen(os.open(path, flags, 0o600), "wb")


def _open_read(path: Path) -> BinaryIO:
    return os.fdopen(os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)), "rb")


# --- space ---------------------------------------------------------------------------------------------------


def disk_free(path: Path) -> int:
    """Free bytes on the disk that holds ``path`` (one place, so tests can stand in a small disk)."""
    return shutil.disk_usage(path).free


def _existing(path: Path) -> Path:
    while not path.exists() and path != path.parent:
        path = path.parent
    return path


def stored_size(plaintext_bytes: int) -> int:
    """About how many bytes the stored container of this many plaintext bytes takes."""
    return plaintext_bytes + snapfile.TAG * (plaintext_bytes // MiB + 1) + SPACE_SLACK


async def used_bytes(db: AsyncSession) -> int:
    """What every backup kept on Slipway takes, added up."""
    total = await db.scalar(
        select(func.coalesce(func.sum(Backup.stored_bytes), 0)).where(Backup.location == BackupLocation.SLIPWAY.value)
    )
    return int(total or 0)


def _row_need(db_bytes: int | None, files_bytes: int | None, has_files: bool | None) -> int:
    need = stored_size(int(db_bytes)) if db_bytes is not None else 0
    if has_files and files_bytes is not None:
        need += stored_size(int(files_bytes))
    return need


async def in_flight_bytes(db: AsyncSession, *, exclude: uuid.UUID | None = None) -> tuple[int, int]:
    """What the Slipway backups not yet recorded as stored will take: ``(pending, pending and unverified)``.

    A backup being copied has a ``pending`` row whose sizes were committed before its copy began, and no
    ``stored_bytes`` until ``apply``; one a restart cut has the same row ``unverified`` until it is settled,
    and its files may be on disk. Each counts as ``stored_size`` of its recorded sizes, so two backups copied
    at the same time can't both fit in room that only one has. ``exclude`` is the backup asking.
    """
    query = select(Backup.id, Backup.status, Backup.db_bytes, Backup.files_bytes, Backup.has_files).where(
        Backup.location == BackupLocation.SLIPWAY.value, Backup.stored_bytes.is_(None),
        Backup.status.in_([BackupStatus.PENDING.value, BackupStatus.UNVERIFIED.value]),
    )
    pending = every = 0
    for row_id, status, db_bytes, files_bytes, has_files in (await db.execute(query)).all():
        if exclude is not None and row_id == exclude:
            continue
        need = _row_need(db_bytes, files_bytes, has_files)
        every += need
        if status == BackupStatus.PENDING.value:
            pending += need
    return pending, every


def _part_bytes() -> int:
    """The bytes already written to ``.part`` files under the store (copies in progress)."""
    base = root()
    if not base.is_dir():
        return 0
    total = 0
    for dirpath, _dirs, files in os.walk(base, followlinks=False):
        for file in files:
            if file.endswith(PART):
                with contextlib.suppress(OSError):
                    total += (Path(dirpath) / file).lstat().st_size
    return total


async def space_problem(need: int, *, db: AsyncSession | None = None,
                        exclude: uuid.UUID | None = None) -> str | None:
    """The refusal when Slipway can't keep ``need`` more bytes of backups, or None.

    Two limits: SLIPWAY_BACKUP_TOTAL_BYTES over every stored backup and every one still being copied (or cut
    by a restart and not yet settled), and the free space of the disk less what the copies in progress have
    still to write (and less SLIPWAY_BACKUP_FREE_MARGIN_MB, the margin a host keeps too). Run before the dump,
    and again by ``pull`` with ``exclude`` = the backup being copied, whose own pending row is ``need``.
    """
    settings = get_settings()
    human = _data().human_bytes
    if db is None:
        async with session_scope() as own:
            used = await used_bytes(own)
            pending, in_flight = await in_flight_bytes(own, exclude=exclude)
    else:
        used = await used_bytes(db)
        pending, in_flight = await in_flight_bytes(db, exclude=exclude)
    used += in_flight
    limit = settings.backup_total_bytes
    if used + need > limit:
        return (f"Slipway's backup storage is full ({human(used)} of {human(limit)}): "
                "delete old backups or raise SLIPWAY_BACKUP_TOTAL_BYTES")
    to_come = max(0, pending - await asyncio.to_thread(_part_bytes)) if pending else 0
    want = need + to_come + settings.backup_free_margin_mb * MiB
    free = disk_free(_existing(root()))
    if free < want:
        return (f"Only {human(free)} is free in Slipway's backup storage; the backup needs about {human(want)}. "
                "Delete old backups and retry. Nothing was changed.")
    return None


# --- pull: the runner's dump into the store ------------------------------------------------------------------


async def _quiet(say: Say | None, line: str) -> None:
    if say is not None:
        await say(line)


async def _pull_part(remote: Remote, source: str, part_file: Path, key: bytes, expected: str,
                     size: int) -> tuple[int, int]:
    """Stream ``source`` into ``part_file`` encrypted; fsync it; check the plaintext hash. Returns
    (plaintext bytes, file bytes). A stream longer than the ``size`` measured on the runner is a file that
    changed: it is cut off there, before it takes more room than the space check allowed."""
    hasher = hashlib.sha256()
    seen = 0
    out = await asyncio.to_thread(_open_new, part_file)
    try:
        writer = snapfile.ContainerWriter(out, key)
        stream = remote.read_stream(source)
        async with contextlib.aclosing(stream):
            async for chunk in stream:
                seen += len(chunk)
                if seen > size:
                    raise BackupStoreError(CHANGED_ON_THE_WAY)
                hasher.update(chunk)
                await asyncio.to_thread(writer.write, chunk)
        writer.close()
        out.flush()
        await asyncio.to_thread(os.fsync, out.fileno())
    finally:
        out.close()
    if hasher.hexdigest() != expected:
        raise BackupStoreError(CHANGED_ON_THE_WAY)
    return writer.plaintext_bytes, writer.file_bytes


async def pull(
    remote: Remote, owner: Any, backup: Backup, *, sources: dict[str, str], say: Say | None = None,
) -> Stored:
    """Copy a backup from the runner into Slipway's store and remove the runner's copy.

    ``sources`` maps each part (``dump``, and ``files`` when the backup has files) to its path on the runner;
    ``backup`` carries the id of its pending row, the name, and the host-side sizes and hashes (``db_bytes``,
    ``db_sha256``, ``files_bytes``, ``files_sha256``). Raises ``BackupStoreError`` for a full store (counting
    the other copies in progress), a hash that differs, a stream longer than its recorded size, or a file
    already stored; any failure removes the ``.part`` files and leaves the runner's copy where it is.
    """
    name = _data().check_name(backup.name)
    parts = _parts(backup)
    for part in parts:
        if part not in sources:
            raise BackupStoreError(f"Backup {name} has no {part} file to copy")
        if not _expected(backup, part):
            raise BackupStoreError(f"Backup {name} has no checksum for its {part} file, so Slipway can't check it")
        if _size(backup, part) is None:
            raise BackupStoreError(f"Backup {name} has no recorded size for its {part} file, so Slipway can't check it")
    need = _row_need(backup.db_bytes, backup.files_bytes, backup.has_files)
    problem = await space_problem(need, exclude=backup.id)
    if problem:
        raise BackupStoreError(problem)
    folder = owner_dir(owner)
    await asyncio.to_thread(folder.mkdir, mode=0o700, parents=True, exist_ok=True)
    finals = {part: stored_path(owner, name, part) for part in parts}
    for final in finals.values():
        if os.path.lexists(final):
            raise BackupStoreError(f"Backup {name} is already stored on Slipway")
    key = snapfile.new_data_key()
    partials = {part: final.with_name(final.name + PART) for part, final in finals.items()}
    sizes: dict[str, tuple[int, int]] = {}
    renamed: list[Path] = []
    try:
        for part in parts:
            _remove_quietly(partials[part])  # left by a run this process gave up on
            sizes[part] = await _pull_part(remote, sources[part], partials[part], key, str(_expected(backup, part)),
                                         int(_size(backup, part) or 0))
        for part in parts:
            os.rename(partials[part], finals[part])
            renamed.append(finals[part])
        await asyncio.to_thread(_fsync_dir, folder)
    except BaseException:
        for path in [*partials.values(), *renamed]:
            _remove_quietly(path)
        raise
    # Only now, with every file renamed and the folder synced, does the runner's copy go.
    paths = " ".join(shlex.quote(sources[part]) for part in parts)
    try:
        await remote.run(f"rm -f -- {paths}", check=True)
    except Exception as exc:  # the files are safe on Slipway; the runner's work folder is emptied by its next job
        log.warning("Could not remove the runner's copy of backup %s: %s", name, exc)
        await _quiet(say, f"Couldn't remove the copy of {name} on the runner; its next job clears that folder")
    stored = sum(file_bytes for _, file_bytes in sizes.values())
    files_bytes = sizes["files"][0] if "files" in sizes else None
    await _quiet(say, f"Kept backup {name} on Slipway ({_data().human_bytes(stored)}, encrypted)")
    return Stored(data_key=encode_key(key), stored_bytes=stored, db_bytes=sizes["dump"][0], files_bytes=files_bytes)


# --- push: a stored backup onto the runner -------------------------------------------------------------------


def _plaintext_chunks(path: Path, key: bytes) -> Iterator[bytes]:
    with _open_read(path) as f:
        yield from snapfile.iter_plaintext(f, key)


async def _decrypting(path: Path, key: bytes, hasher: Any) -> AsyncIterator[bytes]:
    chunks = _plaintext_chunks(path, key)
    try:
        while (chunk := await asyncio.to_thread(next, chunks, None)) is not None:
            hasher.update(chunk)
            yield chunk
    finally:
        await asyncio.to_thread(chunks.close)


@asynccontextmanager
async def push(
    remote: Remote, owner: Any, backup: Backup, *, targets: dict[str, str], say: Say | None = None,
) -> AsyncIterator[dict[str, str]]:
    """Decrypt a stored backup into files on the runner for the length of the ``async with`` block.

    ``targets`` maps each part to the runner path to write (a new file: nothing may be there). Each copy is
    hashed on the way and again on the runner; the copies are removed in a ``finally``, whatever the block
    does. Raises ``BackupStoreError`` when the key can't be read, a file is missing or a hash differs.
    """
    data = _data()
    name = data.check_name(backup.name)
    key = key_of(backup)
    if key is None:
        raise BackupStoreError(KEY_LOST)
    parts = _parts(backup)
    for part in parts:
        if part not in targets:
            raise BackupStoreError(f"Backup {name} needs a place on the runner for its {part} file")
        if not stored_path(owner, name, part).is_file():
            raise BackupStoreError(f"Backup {name} isn't in Slipway's storage any more")
    host = getattr(remote, "host", None) or "the runner"
    written: list[str] = []
    try:
        for part in parts:
            hasher = hashlib.sha256()
            written.append(targets[part])
            try:
                await remote.write_stream(targets[part], _decrypting(stored_path(owner, name, part), key, hasher), 0o600)
            except SnapshotError:
                raise BackupStoreError(f"Backup {name} on Slipway doesn't match what was recorded") from None
            if hasher.hexdigest() != _expected(backup, part):
                raise BackupStoreError(f"Backup {name} on Slipway doesn't match what was recorded")
            _, output = await remote.run(data.sha_command(targets[part]), check=False)
            there = data.parse_sha(output)
            if there is None:
                await _quiet(say, data.no_hash_tool_message(host))
            elif there != hasher.hexdigest():
                raise BackupStoreError(f"The backup changed on its way to {host}")
        await _quiet(say, f"Copied backup {name} from Slipway to {host}")
        yield {part: targets[part] for part in parts}
    finally:
        if written:
            paths = " ".join(shlex.quote(p) for p in written)
            with contextlib.suppress(Exception):
                await asyncio.shield(remote.run(f"rm -f -- {paths}", check=False))


# --- check, delete, sweep, keep ------------------------------------------------------------------------------


def _check_sync(owner: Any, backup: Backup, key: bytes) -> Checked:
    name = _data().check_name(backup.name)
    total = 0
    for part in _parts(backup):
        path = stored_path(owner, name, part)
        if not path.is_file() or path.is_symlink():
            return Checked("missing", f"Backup {name} isn't in Slipway's storage any more")
        total += path.stat().st_size
        hasher = hashlib.sha256()
        try:
            for chunk in _plaintext_chunks(path, key):
                hasher.update(chunk)
        except (SnapshotError, OSError):
            return Checked("changed", f"Backup {name} on Slipway doesn't match what was recorded")
        if hasher.hexdigest() != _expected(backup, part):
            return Checked("changed", f"Backup {name} on Slipway doesn't match what was recorded")
    if backup.stored_bytes is not None and total != backup.stored_bytes:
        return Checked("changed", f"Backup {name} on Slipway doesn't match what was recorded")
    return Checked("ok")


async def check(owner: Any, backup: Backup) -> Checked:
    """Whether a Slipway-stored backup's files are there, decrypt and hash to the recorded values."""
    key = key_of(backup)
    if key is None:
        return Checked("changed", KEY_LOST)
    return await asyncio.to_thread(_check_sync, owner, backup, key)


def delete(owner: Any, backup: Backup) -> int:
    """Remove a backup's stored files (and any ``.part`` left of them). Returns how many files went.

    Works whether or not the data key can still be read.
    """
    name = _data().check_name(backup.name)
    removed = 0
    for part in SUFFIXES:
        final = stored_path(owner, name, part)
        removed += _remove_quietly(final)
        _remove_quietly(final.with_name(final.name + PART))
    with contextlib.suppress(OSError):
        owner_dir(owner).rmdir()  # only when empty
    return removed


def sweep() -> int:
    """Remove every ``*.part`` under the store (left by a restart mid-copy). Run before the job runner
    starts. Returns how many went."""
    base = root()
    if not base.is_dir():
        return 0
    removed = 0
    for dirpath, _dirs, files in os.walk(base, followlinks=False):
        for file in files:
            if file.endswith(PART):
                removed += _remove_quietly(Path(dirpath) / file)
    return removed


def keep(owner: Any, *, env_name: str, env_id: uuid.UUID, at: datetime | None = None) -> Path | None:
    """At teardown, move an owner's stored backups to ``<storage_dir>/kept/<env>-<env id hex[:8]>/`` with a
    README naming the environment and the date. None when there was nothing to keep. Nothing counts these
    files afterwards; they are removed by hand."""
    folder = owner_dir(owner)
    if not folder.is_dir() or not any(folder.iterdir()):
        with contextlib.suppress(OSError):
            folder.rmdir()
        return None
    kept_root = Path(get_settings().storage_dir) / KEPT_FOLDER
    kept_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    dest = kept_root / f"{env_name}-{env_id.hex[:8]}"
    n = 1
    while dest.exists():
        n += 1
        dest = kept_root / f"{env_name}-{env_id.hex[:8]}-{n}"
    os.rename(folder, dest)
    when = (at or utcnow()).strftime("%Y-%m-%d")
    (dest / "README.txt").write_text(
        f"Backups of environment {env_name}, kept when it was deleted on {when}.\n"
        "Each .sbc file is encrypted. Slipway no longer lists them; remove this folder by hand when you no "
        "longer need it.\n"
    )
    for part in dest.glob(f"*{PART}"):
        _remove_quietly(part)
    return dest
