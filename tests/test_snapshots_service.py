"""Snapshot storage on the Slipway server (spec §5, §10.5-10.8): uploads, unlock and the background check,
export tickets and the download, the delete rules, the quota, prepare_storage and the sweep.

These are the service-level parts of test 26; the endpoints themselves are tested with the API (S7a).
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import io
import json
import os
import stat
import struct
import tarfile
import uuid
from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select
from starlette.requests import ClientDisconnect

from slipway.core.config import get_settings
from slipway.core.crypto import reset_crypto_cache
from slipway.db.base import utcnow
from slipway.db.session import get_sessionmaker
from slipway.models import AuditEvent, Deployment, Host, Instance, Repository, User
from slipway.models.data import Snapshot
from slipway.services import snapfile, snapshots
from slipway.services.snapshots import SnapshotsError
from tests.conftest import make_user

PASSPHRASE = "correct horse battery staple"
IDENTITY_VALUE = "identity-value-that-must-stay-secret-7d1f"
DB_MARK = b"DB:plaintext-rows-that-must-stay-encrypted:"


# --- fixtures and helpers ------------------------------------------------------------------------------------


@pytest.fixture
def env():
    """Set SLIPWAY_* settings for one test; everything is put back afterwards."""
    saved: dict[str, str | None] = {}

    def apply(**values: str) -> None:
        for key, value in values.items():
            name = f"SLIPWAY_{key.upper()}"
            saved.setdefault(name, os.environ.get(name))
            os.environ[name] = value
        get_settings.cache_clear()
        reset_crypto_cache()

    yield apply
    for name, value in saved.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value
    get_settings.cache_clear()
    reset_crypto_cache()


@pytest.fixture(autouse=True)
async def storage(tmp_path, env) -> AsyncIterator[Path]:
    root = tmp_path / "storage"
    env(storage_dir=str(root))
    snapshots.reset_state()
    yield root
    await snapshots.shutdown()
    snapshots.reset_state()


@pytest.fixture
async def user() -> User:
    return await make_user("admin@example.com")


@pytest.fixture
async def other_user() -> User:
    return await make_user("other@example.com")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _plain(database: bytes = DB_MARK * 64, *, files: bytes | None = b"OBJECTS" * 50, identity: bool = True,
           repository: str | None = "encondata/BaseCampV3") -> bytes:
    values = {"APP_KEY": IDENTITY_VALUE} if identity else None
    manifest = snapfile.build_manifest(
        app="serversherpa", app_name="ServerSherpa", source="uat", repository=repository, commit="0" * 40,
        notes="from the manifest",
        database={"format": "pg-custom", "revision": "0090", "bytes": len(database), "sha256": _sha(database)},
        files=None if files is None else {"format": "serversherpa-objects-v1", "bytes": len(files), "sha256": _sha(files)},
        identity=values, producer="slipway test",
    )
    out = io.BytesIO()
    snapfile.write_tar(out, manifest, identity=values, database=io.BytesIO(database),
                       files=None if files is None else io.BytesIO(files))
    return out.getvalue()


def _encrypted(plain: bytes, passphrase: str = PASSPHRASE) -> bytes:
    out = io.BytesIO()
    writer = snapfile.ContainerWriter(out, snapfile.new_data_key(), passphrase=passphrase)
    writer.write(plain)
    writer.close()
    return out.getvalue()


async def _chunks(data: bytes, size: int = 7000, *, then: BaseException | None = None) -> AsyncIterator[bytes]:
    for i in range(0, len(data), size):
        yield data[i : i + size]
    if then is not None:
        raise then


async def _upload(data: bytes, name: str, user: User, *, length: int | str | None = "auto", body=None,
                  notes: str | None = None) -> Snapshot:
    async with get_sessionmaker()() as db:
        return await snapshots.receive_upload(
            db, name=name, notes=notes, content_length=len(data) if length == "auto" else length,
            body=body if body is not None else _chunks(data), user=user,
        )


async def _row(name: str) -> Snapshot | None:
    async with get_sessionmaker()() as db:
        return await db.scalar(select(Snapshot).where(Snapshot.name == name))


async def _actions() -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        return list((await db.scalars(select(AuditEvent).order_by(AuditEvent.created_at))).all())


def _all_stored_bytes(root: Path) -> bytes:
    return b"".join(p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file())


def _incoming(root: Path) -> list[str]:
    folder = root / "incoming"
    return sorted(os.listdir(folder)) if folder.exists() else []


def _stored_contents(snap: Snapshot) -> snapfile.SnapshotContents:
    with open(snapshots.bundle_path(snap.id), "rb") as f:
        return snapfile.validate_container(f, snapshots.data_key(snap))


async def _download(token: str, user: User) -> bytes:
    async with get_sessionmaker()() as db:
        stream = await snapshots.open_export(db, token, user=user)
    data = b"".join([piece async for piece in stream.body])
    assert len(data) == stream.content_length
    return data


# --- uploads -------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("compress", [False, True], ids=["tar", "tar.gz"])
async def test_plain_tar_and_tar_gz_become_ready_inline(compress, user, storage):
    plain = _plain()
    data = gzip.compress(plain) if compress else plain
    snap = await _upload(data, "uat-2026-11-15", user)

    assert (snap.status, snap.origin) == ("ready", "upload")
    assert (snap.app, snap.app_name, snap.repository, snap.source) == (
        "serversherpa", "ServerSherpa", "encondata/BaseCampV3", "uat")
    assert (snap.db_format, snap.db_revision, snap.db_bytes) == ("pg-custom", "0090", len(DB_MARK * 64))
    assert (snap.files_format, snap.files_bytes) == ("serversherpa-objects-v1", 350)
    assert snap.identity_keys == ["APP_KEY"] and snap.notes == "from the manifest"
    assert snap.import_keyblock is None and snap.expires_at is None

    path = snapshots.bundle_path(snap.id)
    stored = path.read_bytes()
    assert (len(stored), _sha(stored)) == (snap.file_bytes, snap.file_sha256)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with open(path, "rb") as f:
        assert snapfile.read_preamble(f).keyblock == {"kdf": "none"}
    contents = _stored_contents(snap)
    assert contents.identity == {"APP_KEY": IDENTITY_VALUE} and contents.compressed is compress

    # Plaintext never touches Slipway's disk: not the identity value, not the database, not the manifest.
    everything = _all_stored_bytes(storage)
    assert IDENTITY_VALUE.encode() not in everything and DB_MARK not in everything
    assert b"serversherpa" not in everything
    assert _incoming(storage) == []
    upload = [e for e in await _actions() if e.action == "snapshot.upload"]
    assert len(upload) == 1 and upload[0].details["encrypted"] is False
    assert IDENTITY_VALUE not in json.dumps(upload[0].details)


async def test_upload_refusals_and_the_partial_is_always_removed(user, storage, env, monkeypatch):
    plain = _plain()

    async def refused(status: int, data: bytes = plain, name: str = "s1", **kw) -> str:
        with pytest.raises(SnapshotsError) as caught:
            await _upload(data, name, user, **kw)
        assert caught.value.status == status, caught.value.message
        assert _incoming(storage) == []
        return caught.value.message

    assert "1-64 letters" in await refused(422, name="-bad")
    assert await refused(422, notes="x" * 2001) == "Notes are at most 2000 characters"
    assert "Content-Length" in await refused(411, length=None)
    assert await refused(422, b"junk" * 100) == snapshots.NOT_A_BUNDLE
    assert await refused(422, b"") == snapshots.NOT_A_BUNDLE
    # A plain bundle that fails validation (a member's checksum) is refused and nothing is kept.
    broken = plain.replace(DB_MARK, DB_MARK.upper(), 1)
    assert "doesn't match its SHA-256" in await refused(422, broken)
    # Streamed past the declared length.
    assert "longer than its Content-Length" in await refused(413, length=100)
    # A disconnect, and a body that ends before Content-Length.
    assert await refused(400, body=_chunks(plain[:5000], then=ClientDisconnect())) == snapshots.UPLOAD_STOPPED
    assert await refused(400, body=_chunks(plain[:5000]), length=len(plain)) == snapshots.UPLOAD_STOPPED

    # Encrypted files: no passphrase, refused key-derivation settings, cut short.
    stored_form = io.BytesIO()
    writer = snapfile.ContainerWriter(stored_form, snapfile.new_data_key())
    writer.write(plain)
    writer.close()
    assert "has no passphrase" in await refused(422, stored_form.getvalue())
    header = snapfile.new_header()
    weak = json.dumps({"kdf": "scrypt", "log2_n": 16, "r": 8, "p": 1, "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
                       "nonce": "AAAAAAAAAAAAAAAA", "wrapped": "A" * 64}).encode()
    weak_file = snapfile.MAGIC + struct.pack(">I", len(header)) + header + struct.pack(">I", len(weak)) + weak
    assert await refused(422, weak_file + b"x" * 100) == snapfile.BAD_KDF
    encrypted = _encrypted(plain)
    assert await refused(422, encrypted[:30]) == snapfile.INCOMPLETE

    # The declared size over the cap, before a byte is read.
    env(snapshot_max_bytes=str(len(plain) - 1))
    message = await refused(413)
    assert message == (f"The file is larger than this Slipway accepts ({snapshots.human_bytes(len(plain) - 1)}, "
                       "SLIPWAY_SNAPSHOT_MAX_BYTES)")
    env(snapshot_max_bytes=str(20 * 1024**3))

    # A low disk: 507 before anything is written.
    monkeypatch.setattr(snapshots, "disk_free", lambda path: 1024**3)
    assert (await refused(507)).startswith("Slipway's storage has 1 GiB free; this snapshot needs about 2")
    monkeypatch.undo()

    # A name in use, and the quota.
    await _upload(plain, "taken", user)
    assert await refused(409, name="taken") == "There is already a snapshot named taken"
    env(snapshot_total_bytes=str(len(plain) + 1000))
    assert "SLIPWAY_SNAPSHOT_TOTAL_BYTES); delete some first" in await refused(409, name="over-quota")
    async with get_sessionmaker()() as db:
        assert [s.name for s in (await db.scalars(select(Snapshot))).all()] == ["taken"]
    assert sorted(p.name for p in (storage / "bundles").iterdir()) == [f"{(await _row('taken')).id}.sbx"]


async def test_free_space_is_checked_again_while_streaming(user, storage, monkeypatch):
    free = iter([10 * 1024**3, 1024**3])  # enough at the start, then the disk fills up
    monkeypatch.setattr(snapshots, "disk_free", lambda path: next(free))
    monkeypatch.setattr(snapshots, "SPACE_RECHECK", 4096)
    with pytest.raises(SnapshotsError) as caught:
        await _upload(_plain(), "s1", user)
    assert caught.value.status == 507
    assert _incoming(storage) == [] and await _row("s1") is None


async def test_reservations_count_towards_the_quota(env):
    env(snapshot_total_bytes="1000")
    async with get_sessionmaker()() as db:
        async with snapshots.reserve(db, 900):
            with pytest.raises(SnapshotsError) as caught:
                async with snapshots.reserve(db, 200):
                    pass
            assert caught.value.status == 409
            assert caught.value.message.startswith("Snapshots on this Slipway already use 900 bytes of 1000 bytes")
        async with snapshots.reserve(db, 200):  # released when the first one ended
            pass
        assert await snapshots.usage(db) == {"used": 0, "quota": 1000}


# --- export, import, unlock ----------------------------------------------------------------------------------


async def test_export_then_import_on_another_slipway(user, storage, env, tmp_path):
    plain = _plain()
    first = await _upload(plain, "uat-2026-11-15", user)

    async with get_sessionmaker()() as db:
        with pytest.raises(SnapshotsError) as caught:
            await snapshots.create_export(db, first.id, "short", user=user)
        assert caught.value.status == 422
        ticket = await snapshots.create_export(db, first.id, PASSPHRASE, user=user)
    assert ticket.url == f"/api/v1/snapshot-exports/{ticket.token}"
    exported = await _download(ticket.token, user)
    assert len(exported) == ticket.bytes
    stored = snapshots.bundle_path(first.id).read_bytes()
    with io.BytesIO(exported) as f:
        out = snapfile.read_preamble(f)
        exported_body = f.read()
    with io.BytesIO(stored) as f:
        stored_pre = snapfile.read_preamble(f)
        stored_body = f.read()
    assert out.keyblock["kdf"] == "scrypt" and out.header_bytes == stored_pre.header_bytes
    assert exported_body == stored_body  # re-wrapping leaves the body as it is
    assert PASSPHRASE not in json.dumps([e.details for e in await _actions()])
    assert {"snapshot.export", "snapshot.download"} <= {e.action for e in await _actions()}

    # A second Slipway: its own storage folder and its own SLIPWAY_ENCRYPTION_KEY.
    second = tmp_path / "second-storage"
    env(storage_dir=str(second), encryption_key=Fernet.generate_key().decode())
    snap = await _upload(exported, "imported", user)
    assert (snap.status, snap.origin) == ("locked", "import")
    assert snap.import_keyblock == out.keyblock and snap.data_key is None and snap.app is None
    assert timedelta(days=6, hours=23) < snap.expires_at - utcnow() <= timedelta(days=7)
    path = snapshots.bundle_path(snap.id)
    assert path.parent.parent == second
    with open(path, "rb") as f:
        kept = snapfile.read_preamble(f)
        assert kept.keyblock == {"kdf": "none"} and f.read() == exported_body
    assert (path.stat().st_size, _sha(path.read_bytes())) == (snap.file_bytes, snap.file_sha256)

    async with get_sessionmaker()() as db:
        with pytest.raises(SnapshotsError) as caught:
            await snapshots.unlock(db, snap.id, "the wrong passphrase", user=user)
        assert (caught.value.status, caught.value.message) == (422, snapfile.WRONG_PASSPHRASE)
    assert (await _row("imported")).status == "locked"

    async with get_sessionmaker()() as db:
        unlocked = await snapshots.unlock(db, snap.id, PASSPHRASE, user=user)
        assert unlocked.status == "checking" and unlocked.import_keyblock is None and unlocked.expires_at is None
    await snapshots.wait_for_validations()
    ready = await _row("imported")
    assert ready.status == "ready" and ready.error is None
    assert (ready.app, ready.repository, ready.db_revision, ready.identity_keys) == (
        "serversherpa", "encondata/BaseCampV3", "0090", ["APP_KEY"])
    # What seeding reads: the stored file opens with the new data key and carries the identity values.
    assert _stored_contents(ready).identity == {"APP_KEY": IDENTITY_VALUE}
    assert IDENTITY_VALUE.encode() not in _all_stored_bytes(second)
    actions = [e.action for e in await _actions()]
    assert actions.count("snapshot.unlock") == 1 and "snapshot.ready" in actions

    async with get_sessionmaker()() as db:  # not locked any more
        with pytest.raises(SnapshotsError) as caught:
            await snapshots.unlock(db, snap.id, PASSPHRASE, user=user)
        assert caught.value.status == 409


async def test_unlock_attempts_are_limited_per_user(user, other_user):
    snap = await _upload(_encrypted(_plain()), "locked", user)
    async with get_sessionmaker()() as db:
        for _ in range(5):
            with pytest.raises(SnapshotsError) as caught:
                await snapshots.unlock(db, snap.id, "not the passphrase", user=user)
            assert caught.value.status == 422
        with pytest.raises(SnapshotsError) as caught:
            await snapshots.unlock(db, snap.id, PASSPHRASE, user=user)
        assert (caught.value.status, caught.value.message) == (429, snapshots.TOO_MANY_TRIES)
        # Another user still may, and the right passphrase works.
        assert (await snapshots.unlock(db, snap.id, PASSPHRASE, user=other_user)).status == "checking"
    await snapshots.wait_for_validations()
    assert (await _row("locked")).status == "ready"


async def test_a_damaged_import_fails_its_check_and_its_file_is_deleted(user, storage):
    snap = await _upload(_encrypted(_plain()), "damaged", user)
    path = snapshots.bundle_path(snap.id)
    data = bytearray(path.read_bytes())
    data[-40] ^= 0x01  # inside the final chunk
    path.write_bytes(bytes(data))
    async with get_sessionmaker()() as db:
        await snapshots.unlock(db, snap.id, PASSPHRASE, user=user)  # the key block is still intact
    await snapshots.wait_for_validations()
    failed = await _row("damaged")
    assert failed.status == "failed" and failed.data_key is None
    assert failed.error == "The file is damaged (part 1 doesn't decrypt)"
    assert not path.exists()
    assert "snapshot.failed" in [e.action for e in await _actions()]


async def test_a_locked_import_past_its_expiry_is_swept(user, storage):
    snap = await _upload(_encrypted(_plain()), "forgotten", user)
    assert await snapshots.sweep_once() == []
    assert (await _row("forgotten")).status == "locked"
    assert await snapshots.sweep_once(now=utcnow() + timedelta(days=8)) == ["forgotten"]
    assert await _row("forgotten") is None
    assert not snapshots.bundle_path(snap.id).exists()
    expired = [e for e in await _actions() if e.action == "snapshot.expired"]
    assert len(expired) == 1 and expired[0].details["name"] == "forgotten"


# --- export tickets and the download -------------------------------------------------------------------------


async def test_export_tickets_are_single_use_expire_and_belong_to_one_user(user, other_user):
    snap = await _upload(_plain(), "s1", user)
    async with get_sessionmaker()() as db:
        ticket = await snapshots.create_export(db, snap.id, PASSPHRASE, user=user)
        with pytest.raises(SnapshotsError) as caught:
            await snapshots.open_export(db, ticket.token, user=other_user)
        assert (caught.value.status, caught.value.message) == (404, snapshots.EXPORT_GONE)
    assert len(await _download(ticket.token, user)) == ticket.bytes  # another user's try left it in place
    async with get_sessionmaker()() as db:
        with pytest.raises(SnapshotsError) as caught:
            await snapshots.open_export(db, ticket.token, user=user)
        assert caught.value.status == 404

        late = await snapshots.create_export(db, snap.id, PASSPHRASE, user=user)
    with pytest.raises(SnapshotsError) as caught:
        snapshots.take_export(late.token, user.id, now=late.expires_at + timedelta(seconds=1))
    assert caught.value.status == 404
    with pytest.raises(SnapshotsError):  # an expired ticket is gone for good
        snapshots.take_export(late.token, user.id)

    async with get_sessionmaker()() as db:
        tickets = [await snapshots.create_export(db, snap.id, PASSPHRASE, user=user) for _ in range(4)]
    with pytest.raises(SnapshotsError):  # at most 3 per user: the oldest went
        snapshots.take_export(tickets[0].token, user.id)
    for t in tickets[1:]:
        snapshots.take_export(t.token, user.id)


async def test_a_stored_file_altered_on_disk_stops_the_download_before_its_final_chunk(user):
    database = DB_MARK + os.urandom(3 * 1024 * 1024)  # four chunks of 1 MiB
    snap = await _upload(_plain(database, files=None), "big", user)
    path = snapshots.bundle_path(snap.id)
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0x01  # same size, another checksum
    path.write_bytes(bytes(data))

    async with get_sessionmaker()() as db:
        ticket = await snapshots.create_export(db, snap.id, PASSPHRASE, user=user)
        stream = await snapshots.open_export(db, ticket.token, user=user)
    received = bytearray()
    with pytest.raises(SnapshotsError) as caught:
        async for piece in stream.body:
            received += piece
    assert "has changed" in caught.value.message
    hold = (1 << snapfile.CHUNK_LOG2) + snapfile.TAG
    assert len(received) <= stream.content_length - hold
    with pytest.raises(snapfile.SnapshotError):  # the receiver can't open what it got
        for _ in snapfile.iter_plaintext(io.BytesIO(bytes(received)), snapshots.data_key(snap)):
            pass
    download = [e for e in await _actions() if e.action == "snapshot.download"]
    assert len(download) == 1 and download[0].details["complete"] is False


async def test_exports_need_a_ready_snapshot_with_a_readable_key(user, env):
    snap = await _upload(_plain(), "s1", user)
    env(encryption_key=Fernet.generate_key().decode())  # the stored data key no longer decrypts
    async with get_sessionmaker()() as db:
        with pytest.raises(SnapshotsError) as caught:
            await snapshots.create_export(db, snap.id, PASSPHRASE, user=user)
        assert (caught.value.status, caught.value.message) == (409, snapshots.KEY_LOST)


# --- rename and delete ---------------------------------------------------------------------------------------


async def test_rename_and_notes(user):
    a = await _upload(_plain(), "a", user)
    await _upload(_plain(), "b", user)
    async with get_sessionmaker()() as db:
        with pytest.raises(SnapshotsError) as caught:
            await snapshots.update_snapshot(db, a.id, name="b", user=user)
        assert caught.value.status == 409
        with pytest.raises(SnapshotsError) as caught:
            await snapshots.update_snapshot(db, a.id, name="no spaces", user=user)
        assert caught.value.status == 422
    async with get_sessionmaker()() as db:
        renamed = await snapshots.update_snapshot(db, a.id, name="a2", notes="kept for UAT", user=user)
    assert (renamed.name, renamed.notes) == ("a2", "kept for UAT")
    assert "snapshot.update" in [e.action for e in await _actions()]


async def _instance(db, name: str, *, live: bool, seed: uuid.UUID | None = None) -> Instance:
    host = Host(name=f"h-{name}", hostname="10.0.0.1", username="deploy", password="pw")
    repo = Repository(github_id=uuid.uuid4().int % 10**9, full_name=f"encondata/{name}", owner="encondata",
                      name=name, html_url=f"https://github.com/encondata/{name}")
    inst = Instance(name=name, slug=name, repository=repo, host=host, branch="main", seed_snapshot_id=seed,
                    current_commit_sha="a" * 40 if live else None)
    db.add_all([host, repo, inst])
    await db.flush()
    return inst


def _job(inst: Instance, kind: str, status: str, *, snap: Snapshot | None, at: int, restore: str | None = None,
         done_by: bool = False) -> Deployment:
    steps = [{"key": "check", "name": "Check the snapshot", "status": "succeeded"}]
    if restore is not None:
        row = {"key": "restore", "name": "Restore", "status": restore}
        if done_by:
            row["done_by"] = "1234abcd"
        steps.append(row)
    return Deployment(instance_id=inst.id, branch="main", kind=kind, status=status, log="", steps=steps,
                      snapshot_id=snap.id if snap else None, created_at=utcnow() + timedelta(seconds=at))


async def _delete(snap_id: uuid.UUID, user: User) -> str | None:
    async with get_sessionmaker()() as db:
        try:
            await snapshots.delete_snapshot(db, snap_id, user=user)
        except SnapshotsError as exc:
            assert exc.status == 409
            return exc.message
    return None


async def test_delete_is_refused_while_the_snapshot_is_in_use(user, storage):
    snap = await _upload(_plain(), "seed", user)
    async with get_sessionmaker()() as db:
        for status in ("pending", "checking"):
            row = await db.get(Snapshot, snap.id)
            row.status = status
            await db.commit()
            assert await _delete(snap.id, user) == f"Snapshot seed is in use: it is still being {'taken' if status == 'pending' else 'checked'}"
        row = await db.get(Snapshot, snap.id)
        row.status = "ready"
        await db.commit()

    # A never-live instance starts from it.
    async with get_sessionmaker()() as db:
        fresh = await _instance(db, "fresh", live=False, seed=snap.id)
        await db.commit()
    assert await _delete(snap.id, user) == "Snapshot seed is in use: fresh starts from it when it is first deployed"
    async with get_sessionmaker()() as db:
        (await db.get(Instance, fresh.id)).current_commit_sha = "b" * 40  # it went live
        await db.commit()

    # An active job uses it.
    async with get_sessionmaker()() as db:
        uat = await _instance(db, "uat", live=True)
        running = _job(uat, "reset", "running", snap=snap, at=1)
        db.add(running)
        await db.commit()
    assert "a reset job of uat" in await _delete(snap.id, user)

    # The latest changing job failed before its restore: a retry needs the snapshot.
    async with get_sessionmaker()() as db:
        (await db.get(Deployment, running.id)).status = "failed"
        await db.commit()
    assert "the last reset of uat" in await _delete(snap.id, user)
    async with get_sessionmaker()() as db:  # a Back up now after it doesn't move "latest" (D10)
        db.add(_job(uat, "backup", "succeeded", snap=None, at=2))
        await db.commit()
    assert "the last reset of uat" in await _delete(snap.id, user)
    async with get_sessionmaker()() as db:  # restore done by an earlier attempt: no longer needed
        (await db.get(Deployment, running.id)).steps = [{"key": "restore", "status": "skipped", "done_by": "ab12cd34"}]
        await db.commit()
    assert await _delete(snap.id, user) is None

    snap2 = await _upload(_plain(), "seed2", user)
    async with get_sessionmaker()() as db:
        failed = _job(uat, "reset", "failed", snap=snap2, at=3, restore="failed")
        db.add(failed)
        await db.commit()
    assert "the last reset of uat" in await _delete(snap2.id, user)
    async with get_sessionmaker()() as db:  # a newer changing job ran after it
        db.add(_job(uat, "deploy", "succeeded", snap=None, at=4))
        await db.commit()
    assert await _delete(snap2.id, user) is None
    assert await _row("seed2") is None and not snapshots.bundle_path(snap2.id).exists()
    assert await _row("seed") is None
    deletes = [e for e in await _actions() if e.action == "snapshot.delete"]
    assert sorted(e.details["name"] for e in deletes) == ["seed", "seed2"]


# --- startup, semaphores -------------------------------------------------------------------------------------


async def test_prepare_storage_creates_cleans_and_checks_again(user, storage):
    assert await snapshots.prepare_storage()
    for folder in (storage, storage / "bundles", storage / "incoming"):
        assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    snap = await _upload(_plain(), "s1", user)
    (storage / "incoming" / "left-by-a-crash.partial").write_bytes(b"ciphertext")
    async with get_sessionmaker()() as db:
        (await db.get(Snapshot, snap.id)).status = "checking"
        await db.commit()
    assert await snapshots.prepare_storage()
    await snapshots.wait_for_validations()
    assert _incoming(storage) == []
    assert (await _row("s1")).status == "ready"


async def test_an_unwritable_storage_folder_answers_503_and_startup_goes_on(tmp_path, env, user):
    blocker = tmp_path / "not-a-folder"
    blocker.write_text("a file where the folder should be")
    env(storage_dir=str(blocker))
    assert await snapshots.prepare_storage() is False
    with pytest.raises(SnapshotsError) as caught:
        snapshots.require_storage()
    assert caught.value.status == 503
    assert caught.value.message.startswith(f"SLIPWAY_STORAGE_DIR ({blocker}) isn't writable by Slipway (uid ")
    assert f"chmod 700 {blocker}" in caught.value.message
    with pytest.raises(SnapshotsError) as caught:
        await _upload(_plain(), "s1", user)
    assert caught.value.status == 503


async def test_a_waiting_transfer_says_so(env):
    env(snapshot_transfers="1")
    snapshots.reset_state()
    waited: list[str] = []

    async def note() -> None:
        waited.append("Waiting for another snapshot transfer to finish")

    async def second() -> None:
        async with snapshots.transfer(on_wait=note):
            waited.append("got the slot")

    async with snapshots.transfer(on_wait=note):
        assert waited == []  # a free slot: no waiting line
        task = asyncio.create_task(second())
        await asyncio.sleep(0.01)
        assert waited == ["Waiting for another snapshot transfer to finish"]
    await task
    assert waited[-1] == "got the slot"


def test_human_bytes():
    assert snapshots.human_bytes(20 * 1024**3) == "20 GiB"
    assert snapshots.human_bytes(1536) == "1.5 KiB"
    assert snapshots.human_bytes(512) == "512 bytes"


# --- the check always settles; the quota; files left by a crash ----------------------------------------------


def _pax_size_tar() -> bytes:
    """A tar whose first PAX header gives a size of "²": str.isdigit() says yes, int() refuses it."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.PAX_FORMAT) as tf:
        info = tarfile.TarInfo(snapfile.MANIFEST)
        info.size = 2
        info.pax_headers = {"size": "²"}
        tf.addfile(info, io.BytesIO(b"{}"))
    return out.getvalue()


async def _unlocked(data: bytes, name: str, user: User) -> Snapshot:
    snap = await _upload(_encrypted(data), name, user)
    async with get_sessionmaker()() as db:
        await snapshots.unlock(db, snap.id, PASSPHRASE, user=user)
    await snapshots.wait_for_validations()
    return snap


async def test_a_file_the_reader_didnt_foresee_is_refused_not_stuck_checking(user, storage):
    """Review findings 17 and 32: a PAX size of "²" was a raw ValueError: a 500 for a plain upload, and an
    import that stayed `checking` for good (undeletable, counted in the quota)."""
    with pytest.raises(SnapshotsError) as caught:
        await _upload(_pax_size_tar(), "plain", user)
    assert caught.value.status == 422 and "PAX size is damaged" in caught.value.message
    assert _incoming(storage) == [] and await _row("plain") is None

    snap = await _unlocked(_pax_size_tar(), "evil", user)
    row = await _row("evil")
    assert row.status == "failed" and "PAX size is damaged" in row.error and row.data_key is None
    assert not snapshots.bundle_path(snap.id).exists()
    assert await _delete(snap.id, user) is None


async def test_any_error_in_the_check_or_its_save_fails_the_snapshot(user, storage, monkeypatch):
    """Review finding 17: an exception other than SnapshotError/OSError, in the check or while saving what it
    found (the database refusing a value), left the row `checking`."""
    real_validate = snapfile.validate_container

    def crash(*args, **kwargs):
        raise RuntimeError("an unforeseen bug")

    monkeypatch.setattr(snapfile, "validate_container", crash)
    first = await _unlocked(_plain(), "crashed", user)
    row = await _row("crashed")
    assert (row.status, row.error, row.data_key) == ("failed", snapshots.CHECK_FAILED, None)
    assert not snapshots.bundle_path(first.id).exists()
    monkeypatch.setattr(snapfile, "validate_container", real_validate)

    def refused(snap, manifest):
        raise UnicodeEncodeError("utf-8", "x", 0, 1, "surrogates not allowed")

    monkeypatch.setattr(snapshots, "apply_manifest", refused)
    second = await _unlocked(_plain(), "unsaveable", user)
    row = await _row("unsaveable")
    assert (row.status, row.error, row.data_key, row.app) == ("failed", snapshots.CHECK_FAILED, None, None)
    assert not snapshots.bundle_path(second.id).exists()
    assert [e.action for e in await _actions()].count("snapshot.failed") == 2
    assert await _delete(second.id, user) is None


async def test_an_unreadable_stored_file_keeps_the_key_and_is_checked_again(user, storage, monkeypatch):
    """Review finding 25: an OSError while reading (permissions, a disk error, the folder not usable yet)
    failed the import and erased its data key, so fixing the folder couldn't bring it back."""
    real_check = snapshots._check_file

    def denied(path, key, max_bytes):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(snapshots, "_check_file", denied)
    snap = await _unlocked(_plain(), "imported", user)
    row = await _row("imported")
    assert row.status == "checking" and row.data_key is not None and row.error is None
    assert snapshots.bundle_path(snap.id).exists()

    # The storage folder isn't usable (a file where it should be): the file looks missing, but isn't gone.
    monkeypatch.setattr(snapshots, "_check_file", real_check)
    moved = storage.parent / "storage-moved"
    storage.rename(moved)
    storage.write_text("not a folder")
    await snapshots.validate_stored(snap.id)
    assert (await _row("imported")).status == "checking"

    # The operator fixes it; the next start checks it again.
    storage.unlink()
    moved.rename(storage)
    assert await snapshots.prepare_storage()
    await snapshots.wait_for_validations()
    assert (await _row("imported")).status == "ready"

    # With a usable folder, a file that is really gone fails the check.
    lost = await _upload(_encrypted(_plain()), "lost", user)
    async with get_sessionmaker()() as db:
        await snapshots.unlock(db, lost.id, PASSPHRASE, user=user)
        snapshots.bundle_path(lost.id).unlink()
    await snapshots.wait_for_validations()
    row = await _row("lost")
    assert (row.status, row.error) == ("failed", snapshots.FILE_MISSING)


async def test_the_quota_counts_an_upload_that_commits_while_another_checks(env, monkeypatch):
    """Review finding 37: B read the stored total before A committed and summed the reservations after A
    dropped its own, so A's bytes were in neither number."""
    env(snapshot_total_bytes="1000")
    real_total = snapshots.stored_total
    calls = 0
    b_read, a_done = asyncio.Event(), asyncio.Event()

    async def slow_total(db):
        nonlocal calls
        calls += 1
        value = await real_total(db)
        if calls == 2:  # B's check: its read happens before A's commit, and returns after A finished
            b_read.set()
            await a_done.wait()
        return value

    monkeypatch.setattr(snapshots, "stored_total", slow_total)

    async def upload_a() -> None:
        async with get_sessionmaker()() as db:
            async with snapshots.reserve(db, 600):
                await b_read.wait()
                db.add(Snapshot(name="a", status="locked", origin="import", file_bytes=600))
                await db.commit()
        a_done.set()

    async def upload_b() -> None:
        async with get_sessionmaker()() as db:
            async with snapshots.reserve(db, 600):
                pass

    task_a = asyncio.create_task(upload_a())
    await asyncio.sleep(0)  # A holds its reservation first
    with pytest.raises(SnapshotsError) as caught:
        await asyncio.wait_for(upload_b(), 5)
    assert caught.value.status == 409
    await task_a
    async with get_sessionmaker()() as db:
        assert await real_total(db) == 600


async def test_startup_removes_stored_files_no_snapshot_owns(user, storage):
    """Review finding 38: a crash between moving a file into bundles/ and committing its row left a file
    no row counts in the quota, and the retried take couldn't put its own file there (File exists)."""
    kept = await _upload(_plain(), "kept", user)
    locked = await _upload(_encrypted(_plain()), "locked", user)
    bundles = storage / "bundles"
    unowned = bundles / f"{uuid.uuid4()}.sbx"  # no row in this database: maybe another database's, left alone
    unowned.write_bytes(b"ciphertext")
    taken = await _upload(_plain(), "taken", user)
    async with get_sessionmaker()() as db:  # a take that crashed before its READY commit: failed at restart
        row = await db.get(Snapshot, taken.id)
        row.status, row.error = "failed", "Slipway restarted while this snapshot was being taken; take it again"
        await db.commit()
    other = bundles / "notes.txt"  # not a stored snapshot file: left alone
    other.write_text("hello")

    assert await snapshots.prepare_storage()
    assert unowned.exists() and not snapshots.bundle_path(taken.id).exists()
    assert snapshots.bundle_path(kept.id).exists() and snapshots.bundle_path(locked.id).exists()
    assert other.exists()

    # The retry of the take can now install its file under the same id.
    def retry() -> None:
        bundle = snapshots.NewBundle(stem=str(taken.id))
        bundle.write(b"the retried take")
        bundle.install(taken.id)

    await asyncio.to_thread(retry)
    assert snapshots.bundle_path(taken.id).read_bytes() == b"the retried take"


async def test_a_start_against_another_database_leaves_the_stored_files_alone(user, storage):
    """A wrong SLIPWAY_DATABASE_URL for one start used to delete every stored snapshot file."""
    snap = await _upload(_plain(), "keepme", user)
    path = snapshots.bundle_path(snap.id)
    async with get_sessionmaker()() as db:  # the database Slipway starts against doesn't have the row
        await db.delete(await db.get(Snapshot, snap.id))
        await db.commit()
    assert await snapshots.prepare_storage()
    assert path.exists()


async def test_a_file_missing_while_its_volume_was_unmounted_is_checked_again_once_back(user, storage, monkeypatch):
    """The storage folder is writable but empty (the volume isn't mounted): the import fails as missing, but
    keeps its key, and the next start with the file back checks it again."""
    snap = await _upload(_encrypted(_plain()), "mnt", user)
    monkeypatch.setattr(snapshots, "schedule_validation", lambda snapshot_id: None)
    async with get_sessionmaker()() as db:
        await snapshots.unlock(db, snap.id, PASSPHRASE, user=user)
    monkeypatch.undo()
    path = snapshots.bundle_path(snap.id)
    hidden = path.with_suffix(".hidden")
    path.rename(hidden)
    assert await snapshots.prepare_storage()
    await snapshots.wait_for_validations()
    row = await _row("mnt")
    assert (row.status, row.error) == ("failed", snapshots.FILE_MISSING) and row.data_key is not None
    hidden.rename(path)  # mounted again
    assert await snapshots.prepare_storage()
    await snapshots.wait_for_validations()
    row = await _row("mnt")
    assert row.status == "ready" and row.error is None and path.exists()


def test_names_and_variable_names_ending_in_a_newline_are_refused():
    """``$`` also matches before a final newline: a name like that would reach a Content-Disposition header,
    a variable name like that a .env line."""
    from slipway.services import data, manifest

    assert snapshots.check_name("uat-1") == "uat-1"
    with pytest.raises(SnapshotsError) as caught:
        snapshots.check_name("uat-1\n")
    assert caught.value.status == 422
    assert manifest.ENV_KEY_RE.match("APP_KEY") and not manifest.ENV_KEY_RE.match("APP_KEY\n")
    assert not data.NAME_RE.match("20261115T101500Z-0a1b2c3d\n")
    assert manifest.format_value("abc\n") == "'abc\n'"  # never written raw
