"""Backups kept on the Slipway server (P4 §10.5): P4 test 51 and the service half of test 52.

``pull`` writes an encrypted container to ``.part``, fsyncs and renames it, checks the plaintext hash against
the host's, and removes the runner's copy only after the rename; a mismatch or a cut stream leaves no ``.sbc``
and the runner's copy where it was. ``sweep`` removes every ``.part``. ``push`` writes, checks and removes in a
``finally``. The quota and free-space refusals. ``check`` answers ok, missing and changed; ``delete`` removes
the files; an unreadable data key leaves a backup that can only be deleted. The runner here is
``ShellRemote`` (commands in a real shell, files on this machine).
"""

from __future__ import annotations

import hashlib
import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from slipway.core.config import get_settings
from slipway.core.crypto import reset_crypto_cache
from slipway.db.session import get_sessionmaker
from slipway.models import Backup, Host, Instance, Repository
from slipway.services import backup_store, snapfile, ssh
from slipway.services.backup_store import BackupStoreError
from tests.test_final_remote import ShellRemote

NAME = "20261118T090000Z-1a2b3c4d"
MARK = b"ROWS-THAT-MUST-STAY-ENCRYPTED:"
OWNER = uuid.UUID("11111111-2222-3333-4444-555555555555")


@pytest.fixture
def settings_env() -> Iterator:
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
def storage(tmp_path, settings_env) -> Path:
    root = tmp_path / "storage"
    settings_env(storage_dir=str(root))
    return root


@pytest.fixture
def runner(tmp_path) -> tuple[ShellRemote, Path]:
    incoming = tmp_path / "runner" / "backups" / ".incoming"
    incoming.mkdir(parents=True)
    return ShellRemote("sh", dict(os.environ)), incoming


def _write(path: Path, size: int, seed: bytes) -> str:
    """Write ``size`` bytes (the mark, then pseudo-random data); return their sha256."""
    data = bytearray(MARK)
    block = seed
    while len(data) < size:
        block = hashlib.sha256(block).digest()
        data += block * 64
    path.write_bytes(bytes(data[:size]))
    return hashlib.sha256(bytes(data[:size])).hexdigest()


def _backup(incoming: Path, *, files: bool = True, db_size: int = 2 * 1024 * 1024 + 123) -> tuple[Backup, dict]:
    db_sha = _write(incoming / f"{NAME}.dump", db_size, b"db")
    sources = {"dump": str(incoming / f"{NAME}.dump")}
    backup = Backup(name=NAME, has_files=files, db_sha256=db_sha, db_bytes=db_size, format="pg-custom")
    if files:
        backup.files_sha256 = _write(incoming / f"{NAME}.files", 300_000, b"files")
        backup.files_bytes = 300_000
        sources["files"] = str(incoming / f"{NAME}.files")
    return backup, sources


def _stored(storage: Path) -> list[str]:
    base = storage / "backups"
    return sorted(str(p.relative_to(base)) for p in base.rglob("*") if p.is_file()) if base.exists() else []


async def _pulled(runner, **kw) -> tuple[Backup, backup_store.Stored]:
    remote, incoming = runner
    backup, sources = _backup(incoming, **kw)
    stored = await backup_store.pull(remote, OWNER, backup, sources=sources)
    backup_store.apply(backup, stored)
    return backup, stored


# ------------------------------------------------------------------ pull (test 51)


async def test_pull_stores_an_encrypted_checked_copy_and_then_removes_the_runners(runner, storage):
    remote, incoming = runner
    backup, sources = _backup(incoming)
    said: list[str] = []

    async def say(line: str) -> None:
        said.append(line)

    finals = [storage / "backups" / OWNER.hex / f"{NAME}.db.sbc", storage / "backups" / OWNER.hex / f"{NAME}.files.sbc"]
    seen_at_rm: list[bool] = []
    real_run = remote.run

    async def run(command, **kw):
        if command.startswith("rm -f -- "):
            seen_at_rm.append(all(p.is_file() for p in finals) and not any(p.with_name(p.name + ".part").exists()
                                                                          for p in finals))
        return await real_run(command, **kw)

    remote.run = run
    stored = await backup_store.pull(remote, OWNER, backup, sources=sources, say=say)

    assert seen_at_rm == [True]  # the runner's copy went only after both renames
    assert not any(incoming.iterdir())
    assert _stored(storage) == [f"{OWNER.hex}/{NAME}.db.sbc", f"{OWNER.hex}/{NAME}.files.sbc"]
    assert stored.stored_bytes == sum(p.stat().st_size for p in finals)
    assert (stored.db_bytes, stored.files_bytes) == (backup.db_bytes, 300_000)
    assert "data_key" not in repr(stored) and stored.data_key not in repr(stored)
    for path, expected in zip(finals, (backup.db_sha256, backup.files_sha256), strict=True):
        raw = path.read_bytes()
        assert MARK not in raw  # plaintext never touches Slipway's disk
        assert oct(path.stat().st_mode & 0o777) == "0o600"
        with open(path, "rb") as f:
            assert snapfile.read_preamble(f).keyblock == {"kdf": "none"}
        key = backup_store.key_of(Backup(data_key=stored.data_key))
        plain = b"".join(snapfile.open_container(path, key))
        assert hashlib.sha256(plain).hexdigest() == expected
    assert said == [f"Kept backup {NAME} on Slipway (2.3 MiB, encrypted)"]

    backup_store.apply(backup, stored)
    assert (backup.location, backup.data_key, backup.stored_bytes) == ("slipway", stored.data_key, stored.stored_bytes)

    # The same backup can't be stored twice.
    again, sources = _backup(incoming)
    with pytest.raises(BackupStoreError, match="already stored on Slipway"):
        await backup_store.pull(remote, OWNER, again, sources=sources)


async def test_a_hash_that_differs_leaves_nothing_stored(runner, storage):
    remote, incoming = runner
    backup, sources = _backup(incoming)
    backup.files_sha256 = "0" * 64
    with pytest.raises(BackupStoreError) as caught:
        await backup_store.pull(remote, OWNER, backup, sources=sources)
    assert str(caught.value) == "The backup changed on its way to Slipway"
    assert _stored(storage) == []  # no .part, no .sbc
    assert sorted(p.name for p in incoming.iterdir()) == [f"{NAME}.dump", f"{NAME}.files"]


async def test_a_stream_cut_mid_way_leaves_no_sbc(runner, storage):
    remote, incoming = runner
    backup, sources = _backup(incoming, files=False)
    parts_seen: list[list[str]] = []

    async def cut(path, chunk=None):
        yield b"x" * 1024
        parts_seen.append(_stored(storage))
        raise ssh.SSHError(f"Could not read {path}: connection lost")

    remote.read_stream = cut
    with pytest.raises(ssh.SSHError, match="connection lost"):
        await backup_store.pull(remote, OWNER, backup, sources=sources)
    assert parts_seen == [[f"{OWNER.hex}/{NAME}.db.sbc.part"]]  # it was writing the .part
    assert _stored(storage) == []
    assert [p.name for p in incoming.iterdir()] == [f"{NAME}.dump"]


async def test_sweep_removes_every_part_file(runner, storage):
    await _pulled(runner)
    other = storage / "backups" / uuid.uuid4().hex
    other.mkdir(parents=True)
    (other / f"{NAME}.db.sbc.part").write_bytes(b"half")
    (storage / "backups" / OWNER.hex / "20261118T100000Z-00000000.files.sbc.part").write_bytes(b"half")
    assert backup_store.sweep() == 2
    assert _stored(storage) == [f"{OWNER.hex}/{NAME}.db.sbc", f"{OWNER.hex}/{NAME}.files.sbc"]
    assert backup_store.sweep() == 0


async def test_a_backup_without_a_checksum_is_refused(runner):
    remote, incoming = runner
    backup, sources = _backup(incoming, files=False)
    backup.db_sha256 = None
    with pytest.raises(BackupStoreError, match="has no checksum for its dump file"):
        await backup_store.pull(remote, OWNER, backup, sources=sources)
    backup, _ = _backup(incoming, files=True)
    with pytest.raises(BackupStoreError, match="has no files file to copy"):
        await backup_store.pull(remote, OWNER, backup, sources={"dump": str(incoming / f"{NAME}.dump")})


# ------------------------------------------------------------------ space (test 51)


async def _stored_rows(*sizes: int) -> None:
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=1, full_name="acme/web", owner="acme", name="web",
                          html_url="https://github.com/acme/web")
        host = Host(name="h", hostname="10.0.0.1", username="deploy")
        db.add_all([repo, host])
        await db.flush()
        inst = Instance(name="web", slug="web", branch="main", host_id=host.id, repository_id=repo.id, env={},
                        ports=[], volumes=[])
        db.add(inst)
        await db.flush()
        for i, size in enumerate(sizes):
            db.add(Backup(instance_id=inst.id, name=f"20261118T09000{i}Z-0000000{i}", reason="manual",
                          format="pg-custom", identity_fp="x", taken_at=datetime(2026, 11, 18, tzinfo=UTC),
                          location="slipway", stored_bytes=size))
        db.add(Backup(instance_id=inst.id, name="20261118T080000Z-00000009", reason="manual", format="pg-custom",
                      identity_fp="x", taken_at=datetime(2026, 11, 18, tzinfo=UTC), location="host",
                      stored_bytes=10**12))  # a host backup counts in nothing here
        await db.commit()


async def test_the_quota_and_the_free_space_refusals(runner, storage, settings_env, monkeypatch):
    remote, incoming = runner
    await _stored_rows(40 * 1024 * 1024, 50 * 1024 * 1024)
    async with get_sessionmaker()() as db:
        assert await backup_store.used_bytes(db) == 90 * 1024 * 1024
    assert await backup_store.space_problem(1024) is None

    settings_env(backup_total_bytes=str(91 * 1024 * 1024))
    backup, sources = _backup(incoming)
    expected = ("Slipway's backup storage is full (90 MiB of 91 MiB): delete old backups or raise "
                "SLIPWAY_BACKUP_TOTAL_BYTES")
    assert await backup_store.space_problem(2 * 1024 * 1024) == expected
    with pytest.raises(BackupStoreError) as caught:
        await backup_store.pull(remote, OWNER, backup, sources=sources)
    assert str(caught.value) == expected
    assert _stored(storage) == [] and len(list(incoming.iterdir())) == 2

    settings_env(backup_total_bytes=str(10 * 1024**3), backup_free_margin_mb="100")
    monkeypatch.setattr(backup_store, "disk_free", lambda path: 50 * 1024 * 1024)
    with pytest.raises(BackupStoreError) as caught:
        await backup_store.pull(remote, OWNER, backup, sources=sources)
    assert str(caught.value).startswith("Only 50 MiB is free in Slipway's backup storage; the backup needs about ")
    assert str(caught.value).endswith("Delete old backups and retry. Nothing was changed.")
    assert _stored(storage) == [] and len(list(incoming.iterdir())) == 2


# ------------------------------------------------------------------ push (test 51)


async def test_push_writes_checks_and_removes_in_a_finally(runner, storage):
    remote, incoming = runner
    backup, _ = await _pulled(runner)
    targets = {"dump": str(incoming / f"{NAME}.dump"), "files": str(incoming / f"{NAME}.files")}
    said: list[str] = []

    async def say(line: str) -> None:
        said.append(line)

    async with backup_store.push(remote, OWNER, backup, targets=targets, say=say) as paths:
        assert paths == targets
        for part, path in targets.items():
            digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
            assert digest == (backup.db_sha256 if part == "dump" else backup.files_sha256)
            assert oct(Path(path).stat().st_mode & 0o777) == "0o600"
    assert not any(incoming.iterdir())
    assert said == [f"Copied backup {NAME} from Slipway to the runner"]

    with pytest.raises(RuntimeError, match="the restore failed"):
        async with backup_store.push(remote, OWNER, backup, targets=targets):
            assert len(list(incoming.iterdir())) == 2
            raise RuntimeError("the restore failed")
    assert not any(incoming.iterdir())


async def test_push_refuses_a_lost_key_a_missing_file_and_a_damaged_one(runner, storage):
    remote, incoming = runner
    backup, _ = await _pulled(runner, files=False)
    targets = {"dump": str(incoming / f"{NAME}.dump")}

    lost = Backup(name=NAME, has_files=False, db_sha256=backup.db_sha256, data_key=None)
    with pytest.raises(BackupStoreError, match=r"Slipway can't open this backup any more \(SLIPWAY_ENCRYPTION_KEY"):
        async with backup_store.push(remote, OWNER, lost, targets=targets):
            pass

    stored = storage / "backups" / OWNER.hex / f"{NAME}.db.sbc"
    raw = bytearray(stored.read_bytes())
    raw[-40] ^= 1
    stored.write_bytes(bytes(raw))
    with pytest.raises(BackupStoreError, match="doesn't match what was recorded"):
        async with backup_store.push(remote, OWNER, backup, targets=targets):
            pass
    assert not any(incoming.iterdir())  # the half-written copy went in the finally

    stored.unlink()
    with pytest.raises(BackupStoreError, match="isn't in Slipway's storage any more"):
        async with backup_store.push(remote, OWNER, backup, targets=targets):
            pass


async def test_push_compares_the_hash_on_the_runner(runner, storage):
    remote, incoming = runner
    backup, _ = await _pulled(runner, files=False)
    real_run = remote.run

    async def run(command, **kw):
        if "sha256" in command:
            return 0, "slipway-sha: " + "f" * 64
        return await real_run(command, **kw)

    remote.run = run
    with pytest.raises(BackupStoreError, match="The backup changed on its way to the runner"):
        async with backup_store.push(remote, OWNER, backup, targets={"dump": str(incoming / f"{NAME}.dump")}):
            pass
    assert not any(incoming.iterdir())


# ------------------------------------------------------------------ check and delete (test 52, service half)


async def test_check_answers_ok_missing_and_changed(runner, storage):
    backup, _ = await _pulled(runner)
    assert await backup_store.check(OWNER, backup) == backup_store.Checked("ok")
    assert backup_store.usable(backup) is None

    files = storage / "backups" / OWNER.hex / f"{NAME}.files.sbc"
    raw = bytearray(files.read_bytes())
    raw[200] ^= 1
    files.write_bytes(bytes(raw))
    assert await backup_store.check(OWNER, backup) == backup_store.Checked(
        "changed", f"Backup {NAME} on Slipway doesn't match what was recorded")

    files.unlink()
    assert await backup_store.check(OWNER, backup) == backup_store.Checked(
        "missing", f"Backup {NAME} isn't in Slipway's storage any more")


async def test_an_unreadable_key_leaves_a_backup_that_can_only_be_deleted(runner, storage):
    backup, _ = await _pulled(runner)
    backup.data_key = None  # what --clear-unreadable leaves after SLIPWAY_ENCRYPTION_KEY changed
    text = "Slipway can't open this backup any more (SLIPWAY_ENCRYPTION_KEY changed)"
    assert backup_store.usable(backup) == text
    assert await backup_store.check(OWNER, backup) == backup_store.Checked("changed", text)
    backup.data_key = "not base64!"
    assert backup_store.usable(backup) == text
    assert backup_store.delete(OWNER, backup) == 2
    assert _stored(storage) == [] and not (storage / "backups" / OWNER.hex).exists()
    assert backup_store.delete(OWNER, backup) == 0


async def test_a_changed_stored_size_counts_as_changed(runner):
    backup, _ = await _pulled(runner, files=False)
    backup.stored_bytes += 1
    assert (await backup_store.check(OWNER, backup)).status == "changed"


async def test_keep_moves_an_owners_backups_aside(runner, storage):
    await _pulled(runner)
    env_id = uuid.UUID("abcdef01-0000-0000-0000-000000000000")
    dest = backup_store.keep(OWNER, env_name="prod", env_id=env_id, at=datetime(2026, 11, 18, tzinfo=UTC))
    assert dest == storage / "kept" / "prod-abcdef01"
    assert sorted(p.name for p in dest.iterdir()) == [f"{NAME}.db.sbc", f"{NAME}.files.sbc", "README.txt"]
    assert "environment prod" in (dest / "README.txt").read_text() and "2026-11-18" in (dest / "README.txt").read_text()
    assert _stored(storage) == []
    assert backup_store.keep(OWNER, env_name="prod", env_id=env_id) is None
