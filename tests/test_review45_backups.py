"""Review fixes for backups kept on the Slipway server (P4 §10.5): F29, F30 and K7.

F29: checking a managed owner's backups (``?check=true``) leaves a row a restart left ``unverified`` alone, so a
copy cut before its key was recorded is never shown as "key changed" and the owner's next settle still forgets it
and removes its files.

F30: the store's quota and free-space checks count the other backups being copied (their pending rows carry
the sizes measured on the runner), so two backups copied at the same time can't overrun
SLIPWAY_BACKUP_TOTAL_BYTES; and a stream longer than its recorded size is cut off.

K7: no route serves a Slipway-kept backup's files.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select

from slipway.core.config import get_settings
from slipway.core.crypto import reset_crypto_cache
from slipway.db.session import get_sessionmaker
from slipway.models import Backup, Host, Instance, Repository
from slipway.services import backup_store, data
from slipway.services.backup_store import BackupStoreError
from tests.test_backup_store import _backup
from tests.test_do_managed_data import _name, _stored_row, get, stored_files, world  # noqa: F401
from tests.test_final_remote import ShellRemote

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")

MiB = 1024 * 1024


# ------------------------------------------------------------------ F29: check leaves unverified rows to settle


async def _keyless_unverified(env, name: str) -> Backup:
    """What a restart between pull's rename and ``apply``'s commit leaves: the files whole on Slipway, the row
    ``unverified`` (recovery's rule) with no data key and no ``stored_bytes``."""
    row = await _stored_row(env, name, status="unverified", key=False, at=7)
    async with get_sessionmaker()() as db:
        fresh = await db.get(Backup, row.id)
        fresh.stored_bytes = None
        await db.commit()
    return row


async def test_f29_check_leaves_an_unverified_slipway_row_for_settle_to_forget(world):
    env = await world.setup()
    ready = await _stored_row(env, _name(1), at=1)
    cut = await _keyless_unverified(env, _name(7))
    assert f"{cut.name}.db.sbc" in stored_files(env)
    async with get_sessionmaker()() as db:
        rows = list(await db.scalars(select(Backup).where(Backup.instance_id == env.ids["data"])))
        found = await data.check_backups(None, db, rows, None, None)
        await db.commit()
    assert found.warning is None
    assert found.statuses == {ready.id: "ready", cut.id: "unverified"}
    after = await get(Backup, cut.id)
    assert after.status == "unverified" and after.checked_at is None  # not "changed", not "key lost"
    async with get_sessionmaker()() as db:
        row = await db.get(Backup, cut.id)
        assert await data.confirm_backup(None, db, row, None, None) == f"The backup {cut.name} isn't ready (unverified)"
    # The owner's next job settles it: the files go and the row is forgotten.
    async with get_sessionmaker()() as db:
        owner = await db.get(Instance, env.ids["data"])
        lines = await data.settle_unverified(None, db, owner, None)
        await db.commit()
    assert lines == [f"Backup {cut.name} never finished before Slipway restarted; forgot it"]
    assert await get(Backup, cut.id) is None
    assert stored_files(env) == [f"{ready.name}.db.sbc"]
    assert not world.multi.opened


async def test_f29_the_api_check_on_the_owner_keeps_the_row_settleable(world, admin_client):
    env = await world.setup()
    await world.live()
    cut = await _keyless_unverified(env, _name(8))
    resp = await admin_client.get(f"/api/v1/instances/{env.ids['data']}/backups", params={"check": "true"})
    assert resp.status_code == 200, resp.text
    assert backup_store.KEY_LOST not in resp.text and "SLIPWAY_ENCRYPTION_KEY" not in resp.text
    assert "Not checked since Slipway restarted" in resp.text
    assert (await get(Backup, cut.id)).status == "unverified"
    async with get_sessionmaker()() as db:
        owner = await db.get(Instance, env.ids["data"])
        await data.settle_unverified(None, db, owner, None)
        await db.commit()
    assert await get(Backup, cut.id) is None
    assert f"{cut.name}.db.sbc" not in stored_files(env)


# ------------------------------------------------------------------ F30: the quota counts copies in progress


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


@pytest.fixture
def storage(tmp_path, settings_env) -> Path:
    root = tmp_path / "storage"
    settings_env(storage_dir=str(root))
    return root


@pytest.fixture
def runner(tmp_path) -> tuple[ShellRemote, Path]:
    incoming = tmp_path / "runner" / "backups" / ".incoming"
    incoming.mkdir(parents=True)
    return ShellRemote("sh", dict(os.environ)), incoming


async def _instance(name: str) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=abs(hash(name)) % 10**6, full_name=f"acme/{name}", owner="acme", name=name,
                          html_url=f"https://github.com/acme/{name}")
        host = Host(name=f"h-{name}", hostname="10.0.0.1", username="deploy")
        db.add_all([repo, host])
        await db.flush()
        inst = Instance(name=name, slug=name, branch="main", host_id=host.id, repository_id=repo.id, env={},
                        ports=[], volumes=[])
        db.add(inst)
        await db.commit()
        return inst.id


async def _row(instance_id: uuid.UUID, name: str, **values) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        row = Backup(instance_id=instance_id, name=name, reason="manual", format="pg-custom", identity_fp="x",
                     taken_at=datetime(2026, 11, 18, tzinfo=UTC), location="slipway", **values)
        db.add(row)
        await db.commit()
        return row.id


async def _pending_for(instance_id: uuid.UUID, backup: Backup) -> Backup:
    """The pending row ``_keep_on_slipway`` commits before it pulls (sizes measured), and the view it pulls with."""
    row_id = await _row(instance_id, backup.name, status="pending", has_files=backup.has_files,
                        db_bytes=backup.db_bytes, db_sha256=backup.db_sha256, files_bytes=backup.files_bytes,
                        files_sha256=backup.files_sha256)
    return Backup(id=row_id, name=backup.name, has_files=backup.has_files, db_bytes=backup.db_bytes,
                  db_sha256=backup.db_sha256, files_bytes=backup.files_bytes, files_sha256=backup.files_sha256)


async def test_f30_another_environments_copy_in_progress_counts_against_the_quota(runner, storage, settings_env):
    remote, incoming = runner
    other = await _instance("other")
    mine = await _instance("mine")
    await _row(other, "20261118T090000Z-00000001", status="ready", stored_bytes=40 * MiB, data_key="x",
               db_bytes=40 * MiB, db_sha256="0" * 64)
    # The other environment's backup is being copied: its pending row has its sizes and no stored_bytes yet.
    await _row(other, "20261118T090100Z-00000002", status="pending", db_bytes=45 * MiB, has_files=False)
    backup, sources = _backup(incoming, files=False)
    view = await _pending_for(mine, backup)
    settings_env(backup_total_bytes=str(86 * MiB))
    async with get_sessionmaker()() as db:
        assert await backup_store.used_bytes(db) == 40 * MiB
        pending, every = await backup_store.in_flight_bytes(db, exclude=view.id)
    assert pending == every == backup_store.stored_size(45 * MiB)  # this backup's own row is not counted twice
    with pytest.raises(BackupStoreError) as caught:
        await backup_store.pull(remote, mine, view, sources=sources)
    assert str(caught.value).startswith("Slipway's backup storage is full (85.1 MiB of 86 MiB)")
    assert not (storage / "backups" / mine.hex).exists() or not any((storage / "backups" / mine.hex).iterdir())
    assert len(list(incoming.iterdir())) == 1  # the runner's copy stays

    # Room for both: the pull goes ahead, its own pending row not counted against it.
    settings_env(backup_total_bytes=str(100 * MiB))
    stored = await backup_store.pull(remote, mine, view, sources=sources)
    assert stored.db_bytes == backup.db_bytes


async def test_f30_two_copies_at_the_same_time_cannot_both_fit_in_room_for_one(runner, storage, settings_env,
                                                                               tmp_path):
    """Environment A's copy is mid-stream when environment B's pull checks the store: B is refused."""
    remote, incoming = runner
    a_owner, b_owner = await _instance("env-a"), await _instance("env-b")
    a_backup, a_sources = _backup(incoming, files=False, db_size=3 * MiB)
    a_view = await _pending_for(a_owner, a_backup)
    b_incoming = tmp_path / "runner-b"
    b_incoming.mkdir()
    b_backup, b_sources = _backup(b_incoming, files=False, db_size=3 * MiB)
    b_backup.name = "20261118T100000Z-0b0b0b0b"
    settings_env(backup_total_bytes=str(5 * MiB))  # room for one 3 MiB copy, not two

    streaming, go_on = asyncio.Event(), asyncio.Event()
    real = remote.read_stream

    async def slow(path, chunk=None):
        first = True
        async for piece in real(path, chunk):
            yield piece
            if first:
                first = False
                streaming.set()
                await go_on.wait()

    a_remote = ShellRemote("sh", dict(os.environ))
    a_remote.read_stream = slow
    a_pull = asyncio.create_task(backup_store.pull(a_remote, a_owner, a_view, sources=a_sources))
    try:
        await asyncio.wait_for(streaming.wait(), 10)
        b_view = await _pending_for(b_owner, b_backup)  # B's dump finished while A's copy was streaming
        with pytest.raises(BackupStoreError, match="^Slipway's backup storage is full"):
            await backup_store.pull(remote, b_owner, b_view, sources=b_sources)
    finally:
        go_on.set()
    stored = await asyncio.wait_for(a_pull, 30)
    assert stored.db_bytes == 3 * MiB


async def test_f30_free_space_counts_what_a_copy_in_progress_has_still_to_write(runner, storage, settings_env,
                                                                               monkeypatch):
    remote, incoming = runner
    other, mine = await _instance("busy"), await _instance("next")
    await _row(other, "20261118T090100Z-00000002", status="pending", db_bytes=80 * MiB, has_files=False)
    backup, sources = _backup(incoming, files=False)
    view = await _pending_for(mine, backup)
    settings_env(backup_total_bytes=str(10 * 1024**3), backup_free_margin_mb="10")
    monkeypatch.setattr(backup_store, "disk_free", lambda path: 60 * MiB)
    with pytest.raises(BackupStoreError, match="^Only 60 MiB is free in Slipway's backup storage"):
        await backup_store.pull(remote, mine, view, sources=sources)
    # Once most of the other copy is on disk (its .part), only the rest of it is set aside.
    folder = storage / "backups" / other.hex
    folder.mkdir(parents=True)
    with open(folder / "20261118T090100Z-00000002.db.sbc.part", "wb") as f:
        f.truncate(79 * MiB)
    stored = await backup_store.pull(remote, mine, view, sources=sources)
    assert stored.db_bytes == backup.db_bytes


async def test_f30_a_stream_longer_than_its_recorded_size_is_cut_off(runner, storage):
    remote, incoming = runner
    backup, sources = _backup(incoming, files=False, db_size=2 * MiB)
    sent: list[int] = []

    async def grows(path, chunk=None):
        while True:  # a file that kept growing after it was measured
            sent.append(MiB)
            yield b"y" * MiB
            if len(sent) > 64:
                raise AssertionError("the stream was never cut off")

    remote.read_stream = grows
    with pytest.raises(BackupStoreError, match=f"^{backup_store.CHANGED_ON_THE_WAY}$"):
        await backup_store.pull(remote, uuid.uuid4(), backup, sources=sources)
    assert len(sent) == 3  # stopped at the first chunk past 2 MiB, before writing it
    base = storage / "backups"
    assert not base.exists() or not [p for p in base.rglob("*") if p.is_file()]
    assert len(list(incoming.iterdir())) == 1


async def test_f30_a_backup_with_no_recorded_size_is_refused_before_anything_is_written(runner, storage):
    remote, incoming = runner
    backup, sources = _backup(incoming, files=False)
    backup.db_bytes = None
    with pytest.raises(BackupStoreError, match="has no recorded size for its dump file"):
        await backup_store.pull(remote, uuid.uuid4(), backup, sources=sources)
    assert not (storage / "backups").exists() or not list((storage / "backups").rglob("*.sbc*"))


# ------------------------------------------------------------------ K7: nothing serves a Slipway backup's files


def _routes(app) -> list[tuple[str, set[str], object]]:
    from fastapi.routing import _IncludedRouter
    from starlette.routing import Mount, Route, WebSocketRoute

    found: list[tuple[str, set[str], object]] = []

    def walk(routes, prefix: str) -> None:
        for route in routes:
            if isinstance(route, _IncludedRouter):
                walk(route.original_router.routes, prefix + route.include_context.prefix)
            elif isinstance(route, Mount):
                found.append((prefix + route.path, {"MOUNT"}, route.app))
                walk(route.routes or [], prefix + route.path)
            elif isinstance(route, (Route, WebSocketRoute)):
                found.append((prefix + route.path, set(getattr(route, "methods", None) or {"WS"}), route.endpoint))
            else:
                raise AssertionError(f"a route of an unknown kind: {route!r}")

    walk(app.routes, "")
    return found


def test_k7_no_route_serves_a_slipway_kept_backups_files(app):
    routes = _routes(app)
    assert len(routes) > 50  # the walk reached the included routers
    backup_routes = {(path, frozenset(methods - {"HEAD"})) for path, methods, _ in routes if "backup" in path.lower()}
    # The list (JSON views), Back up now and Delete: no download. A new route here must refuse a
    # location = slipway row with P4 §10.5's text before this list is widened.
    assert backup_routes == {
        ("/api/v1/instances/{instance_id}/backups", frozenset({"GET"})),
        ("/api/v1/instances/{instance_id}/backups", frozenset({"POST"})),
        ("/api/v1/instances/{instance_id}/backups/{backup_id}", frozenset({"DELETE"})),
    }
    storage = Path(get_settings().storage_dir).resolve()
    for path, methods, target in routes:
        directory = getattr(target, "directory", None)
        if "MOUNT" in methods and directory is not None:
            served = Path(directory).resolve()
            assert storage != served and storage not in served.parents and served not in storage.parents, path
        # No endpoint reads the store's files: only the job's push (onto a runner) does.
        if callable(target) and "MOUNT" not in methods:
            with contextlib.suppress(OSError, TypeError):
                source = inspect.getsource(target)
                for name in ("stored_path", "owner_dir", "backup_store.root", "backup_store.push",
                             "_plaintext_chunks"):
                    assert name not in source, (path, name)


async def test_k7_asking_for_a_backups_file_finds_no_route(admin_client):
    owner, backup = uuid.uuid4(), uuid.uuid4()
    for url in (f"/api/v1/instances/{owner}/backups/{backup}", f"/api/v1/instances/{owner}/backups/{backup}/download",
                f"/api/v1/instances/{owner}/backups/{backup}/file"):
        resp = await admin_client.get(url)
        assert resp.status_code in (404, 405), (url, resp.status_code)
        assert resp.headers.get("content-type", "").startswith("application/json")
