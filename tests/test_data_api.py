"""The data API (spec §13, §14.2): backups, restore, reset, start over, roll back, retry, snapshots, the first
admin and starter content, the hold, typed confirmation, cross-instance ids, concurrency and audit records.

Jobs are queued but not run (``runner.submit`` is replaced); the host side of ``?check=true`` and backup
deletion runs in a real shell on this machine, in the instance's folder under the test's temp folder.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import json
import os
import subprocess
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select

from slipway.api.v1 import instances as instances_api
from slipway.core.config import get_settings
from slipway.core.crypto import reset_crypto_cache
from slipway.db.base import utcnow
from slipway.db.session import get_sessionmaker
from slipway.models import AuditEvent, Backup, Deployment, FirstAdmin, Host, Instance, Repository, Snapshot
from slipway.services import data, deployer, manifest, snapfile, snapshots, ssh
from slipway.services.github import GitHubClient
from tests.conftest import login, make_user

SHA = "0123456789abcdef0123456789abcdef01234567"
SHA2 = "fedcba9876543210fedcba9876543210fedcba98"
KEY_A = Fernet.generate_key().decode()  # the identity key the live data was made with
KEY_B = Fernet.generate_key().decode()  # another one (an older backup's)
PASSWORD = "first-admin-password-9f3k"
PASSPHRASE = "correct horse battery staple"
T0 = datetime(2026, 11, 15, 10, 15, 0, tzinfo=UTC)

SHOP_YML = """\
version: 1
name: Acme shop
projects: ["shop-{slipway.slug}"]
vars: {COMPOSE_PROJECT_NAME: "shop-{slipway.slug}"}
data:
  app: acme-shop
  format: pg-custom
  volumes: [{name: "shop-{slipway.slug}_pgdata", holds: database}]
  identity_label: field encryption key
secrets:
  FIELD_ENCRYPTION_KEY: {kind: fernet, identity: true}
commands:
  start:    [docker, compose, -p, "shop-{slipway.slug}", up, -d, --wait]
  stop:     [docker, compose, -p, "shop-{slipway.slug}", down]
  data_up:  [docker, compose, -p, "shop-{slipway.slug}", up, -d, --wait, db]
  dump:     {run: [docker, compose, -p, "shop-{slipway.slug}", exec, -T, db, pg_dump, -Fc, -U, shop, shop], stdout: true}
  restore:  {run: [docker, compose, -p, "shop-{slipway.slug}", exec, -T, db, pg_restore, -U, shop, -d, shop], stdin: true}
  seed:     [docker, compose, -p, "shop-{slipway.slug}", run, --rm, web, python, manage.py, loaddata, starter]
first_admin:
  command: [docker, compose, -p, "shop-{slipway.slug}", run, --rm, -T, -e, DJANGO_SUPERUSER_PASSWORD, web, python,
            manage.py, createsuperuser, --noinput, --username, "{admin.username}", --email, "{admin.email}"]
  fields: {username: {label: Username, max: 150}, email: {label: Email, kind: email}}
  password: {min_length: 10, env: DJANGO_SUPERUSER_PASSWORD}
"""
MANIFEST = manifest.parse(SHOP_YML).to_json()
ADMIN = {"fields": {"username": "ada", "email": "ada@example.com"}, "mode": "password", "password": PASSWORD}


# ------------------------------------------------------------------------------------------- fixtures


@pytest.fixture(autouse=True)
async def storage(tmp_path) -> AsyncIterator[Path]:
    """Snapshot storage in this test's temp folder."""
    root = tmp_path / "storage"
    old = os.environ.get("SLIPWAY_STORAGE_DIR")
    os.environ["SLIPWAY_STORAGE_DIR"] = str(root)
    get_settings.cache_clear()
    reset_crypto_cache()
    snapshots.reset_state()
    yield root
    await snapshots.shutdown()
    snapshots.reset_state()
    os.environ["SLIPWAY_STORAGE_DIR"] = old or ""
    get_settings.cache_clear()
    reset_crypto_cache()


@pytest.fixture(autouse=True)
def submitted(monkeypatch) -> list[uuid.UUID]:
    """Jobs are queued but never run here."""
    jobs: list[uuid.UUID] = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, keys: jobs.append(dep_id))
    return jobs


class Shell:
    """A RemoteSession stand-in that runs each command in sh on this machine, as sshd would."""

    def __init__(self) -> None:
        self.commands: list[str] = []

    async def run(self, command, *, check=True, on_line=None, timeout=None, **kw):
        self.commands.append(command)
        result = await asyncio.to_thread(subprocess.run, ["sh", "-c", command], capture_output=True, text=True,
                                         stdin=subprocess.DEVNULL, timeout=60)
        output = result.stdout + result.stderr
        if check and result.returncode:
            raise ssh.CommandFailed(command, result.returncode, output)
        return result.returncode, output

    async def write_text(self, remote, content, mode=0o600):
        self.commands.append(f"write {remote}")
        Path(remote).write_text(content)
        os.chmod(remote, mode)


def connect_to(remote):
    @contextlib.asynccontextmanager
    async def connect(target, **kw):
        yield remote
    return connect


@pytest.fixture
def shell(monkeypatch) -> Shell:
    remote = Shell()
    monkeypatch.setattr(instances_api, "open_session", connect_to(remote))
    return remote


def github_serving(monkeypatch, files: dict[str, str]) -> None:
    """The branch's slipway.yml (and other files) as GitHub would serve them."""
    def handler(request: httpx.Request) -> httpx.Response:
        name = request.url.path.split("/contents/", 1)[-1]
        if name in files:
            return httpx.Response(200, text=files[name])
        return httpx.Response(404, json={"message": "Not Found"})

    monkeypatch.setattr(instances_api, "GitHubClient",
                        lambda token: GitHubClient(token, transport=httpx.MockTransport(handler)))


async def clients(make_client) -> dict[str, httpx.AsyncClient]:
    """Signed-in clients for the four built-in roles (admin first: the first user becomes admin)."""
    out = {}
    for role in ("admin", "viewer", "developer", "maintainer"):
        await make_user(f"{role}@example.com", roles=None if role == "admin" else [role])
        c = make_client()
        await login(c, f"{role}@example.com")
        out[role] = c
    return out


async def client_with(make_client, email: str, permissions: list[str]) -> httpx.AsyncClient:
    """A client whose only role holds exactly ``permissions``."""
    async with get_sessionmaker()() as db:
        from slipway.models import Role
        db.add(Role(name=email.split("@")[0], description="", permissions=permissions, is_system=False))
        await db.commit()
    await make_user(email, roles=[email.split("@")[0]])
    c = make_client()
    await login(c, email)
    return c


async def seed(tmp_path: Path | None = None, *, name: str = "shop", repo: str = "acme/shop", live: bool = True,
               **fields) -> uuid.UUID:
    """A live app instance (its release went live with SHA), whose folder is under ``tmp_path``."""
    async with get_sessionmaker()() as db:
        host = await db.scalar(select(Host).where(Host.name == "prod-01"))
        if host is None:
            host = Host(name="prod-01", hostname="10.0.0.1", username="deploy", host_key="ssh-ed25519 AAAA",
                        metrics={})
        repository = await db.scalar(select(Repository).where(Repository.full_name == repo))
        if repository is None:
            owner, short = repo.split("/")
            repository = Repository(github_id=abs(hash(repo)) % 10**8, full_name=repo, owner=owner, name=short,
                                    html_url=f"https://github.com/{repo}", detected_config={})
        live_dep = uuid.uuid4()
        values = dict(
            name=name, slug=name, branch="main", host=host, repository=repository, build_source="app",
            status="running" if live else "failed", current_commit_sha=SHA if live else None, env={},
            app_secrets={"FIELD_ENCRYPTION_KEY": KEY_A}, live_identity={"FIELD_ENCRYPTION_KEY": KEY_A} if live else None,
            deploy_dir=str(tmp_path / name) if tmp_path else None,
            app_state={"manifest": MANIFEST, "live": {
                "release": f"{SHA[:12]}-{live_dep.hex[:8]}", "deployment": live_dep.hex, "sha": SHA,
                "projects": [f"shop-{name}"], "volumes": [{"name": f"shop-{name}_pgdata", "holds": "database"}],
                "settings": {}, "services": None, "host_ports": {}}} if live else None,
        )
        values.update(fields)
        inst = Instance(**values)
        db.add(inst)
        await db.flush()
        if live:
            db.add(Deployment(id=live_dep, instance_id=inst.id, kind="deploy", status="succeeded", branch="main",
                              commit_sha=SHA, commit_message="Live", created_at=T0 - timedelta(days=1),
                              release=f"/x/releases/{SHA[:12]}-{live_dep.hex[:8]}"))
        await db.commit()
        return inst.id


def backup_row(instance_id: uuid.UUID, *, at: datetime = T0, reason: str = "pre_deploy", status: str = "ready",
               identity: dict[str, str] | None = None, size: int = 10, **kw) -> Backup:
    bid = uuid.uuid4()
    identity = {"FIELD_ENCRYPTION_KEY": KEY_A} if identity is None else identity
    return Backup(id=bid, instance_id=instance_id, name=data.backup_name(bid, at), reason=reason, status=status,
                  format=kw.pop("format", "pg-custom"), db_bytes=size, identity_keys=sorted(identity),
                  identity=identity, identity_fp=data.identity_fp(bid, identity, identity), taken_at=at, **kw)


async def add(*rows) -> None:
    async with get_sessionmaker()() as db:
        db.add_all(rows)
        await db.commit()


async def load(model, row_id):
    async with get_sessionmaker()() as db:
        return await db.get(model, row_id, populate_existing=True)


async def job(instance_id, kind="deploy", status="failed", *, at=T0, steps=None, **kw) -> Deployment:
    dep = Deployment(id=kw.pop("id", uuid.uuid4()), instance_id=instance_id, kind=kind, status=status, branch="main",
                     commit_sha=kw.pop("commit_sha", SHA2), created_at=at, finished_at=at + timedelta(minutes=1),
                     steps=steps or [], **kw)
    await add(dep)
    return dep


def steps(**status) -> list[dict]:
    return [{"key": k, "name": k.title(), "status": s} for k, s in status.items()]


async def actions() -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        return list((await db.scalars(select(AuditEvent).order_by(AuditEvent.created_at))).all())


def plain_snapshot(*, app: str = "acme-shop", repository: str | None = "acme/shop") -> bytes:
    database = b"DB rows " * 100
    identity = {"FIELD_ENCRYPTION_KEY": KEY_B}
    man = snapfile.build_manifest(
        app=app, app_name="Acme shop", source="uat", repository=repository, commit=SHA, notes="",
        database={"format": "pg-custom", "revision": "0042", "bytes": len(database),
                  "sha256": hashlib.sha256(database).hexdigest()},
        files=None, identity=identity, producer="slipway test",
    )
    out = io.BytesIO()
    snapfile.write_tar(out, man, identity=identity, database=io.BytesIO(database), files=None)
    return out.getvalue()


def encrypted(plain: bytes) -> bytes:
    out = io.BytesIO()
    writer = snapfile.ContainerWriter(out, snapfile.new_data_key(), passphrase=PASSPHRASE)
    writer.write(plain)
    writer.close()
    return out.getvalue()


async def upload(client, body: bytes, name: str) -> httpx.Response:
    return await client.post(f"/api/v1/snapshots/upload?name={name}", content=body,
                             headers={"Content-Type": "application/octet-stream"})


async def ready_snapshot(admin, name: str = "uat-1", **kw) -> uuid.UUID:
    r = await upload(admin, plain_snapshot(**kw), name)
    assert r.status_code == 201 and r.json()["status"] == "ready", r.text
    return uuid.UUID(r.json()["id"])


# ------------------------------------------------------------------- backups: list, check, back up, delete


async def test_back_up_now_queues_a_backup_job_with_its_note(admin_client, submitted):
    iid = await seed()
    r = await admin_client.post(f"/api/v1/instances/{iid}/backups", json={"note": "before the migration"})
    assert r.status_code == 202, r.text
    out = r.json()
    assert out["kind"] == "backup" and out["commit_sha"] == SHA and out["commit_message"] == "Live"
    assert out["options"] == {"files": False, "restop": False, "note": "before the migration"}
    assert [s["key"] for s in out["steps"]] == ["release", "backup"]
    assert submitted == [uuid.UUID(out["id"])]
    # The job's backup row shows the note (the job keeps it in its options).
    await add(backup_row(iid, reason="manual", deployment_id=uuid.UUID(out["id"])))
    listed = (await admin_client.get(f"/api/v1/instances/{iid}/backups")).json()
    assert listed["backups"][0]["note"] == "before the migration" and listed["keep"] == 5 and listed["manual_max"] == 10
    # Busy: one job at a time, named in the answer.
    r = await admin_client.post(f"/api/v1/instances/{iid}/backups")
    assert r.status_code == 409 and r.json()["detail"] == (
        "A job is already running for this instance (Back up); wait for it to finish")
    assert [e.action for e in await actions()].count("backup.create") == 1


async def test_back_up_now_refusals(admin_client, monkeypatch):
    plain = await seed(name="plain", build_source="dockerfile", app_state=None)
    r = await admin_client.post(f"/api/v1/instances/{plain}/backups")
    assert r.status_code == 400 and r.json()["detail"] == instances_api.ONLY_APPS
    never = await seed(name="never", live=False)
    r = await admin_client.post(f"/api/v1/instances/{never}/backups")
    assert r.status_code == 409 and "doesn't know never's data commands yet" in r.json()["detail"]
    iid = await seed()
    r = await admin_client.post(f"/api/v1/instances/{iid}/backups", json={"files": True})
    assert r.status_code == 409 and "has no export_files command" in r.json()["detail"]
    monkeypatch.setenv("SLIPWAY_MANUAL_BACKUPS_MAX", "1")
    get_settings.cache_clear()
    await add(backup_row(iid, reason="manual"))
    r = await admin_client.post(f"/api/v1/instances/{iid}/backups")
    assert r.status_code == 409 and r.json()["detail"] == "shop already has 1 backups you took yourself; delete one first"
    r = await admin_client.post(f"/api/v1/instances/{iid}/backups", json={"note": "x" * 201})
    assert r.status_code == 422


async def test_check_true_reports_what_the_host_has(admin_client, shell, tmp_path):
    iid = await seed(tmp_path)
    ok = backup_row(iid, at=T0)
    back = backup_row(iid, at=T0 + timedelta(hours=1), status="missing")
    resized = backup_row(iid, at=T0 + timedelta(hours=2))
    await add(ok, back, resized)
    url = f"/api/v1/instances/{iid}/backups?check=true"

    # No backups folder: a warning, and no row changes.
    r = (await admin_client.get(url)).json()
    assert r["warning"] == f"{tmp_path}/shop/backups isn't on prod-01; showing what Slipway recorded"
    assert [b["status"] for b in r["backups"]] == ["ready", "missing", "ready"]

    folder = tmp_path / "shop" / "backups"
    (folder / ".incoming").mkdir(parents=True)
    for row in (ok, back):
        (folder / f"{row.name}.dump").write_bytes(b"x" * 10)
        (folder / f"{row.name}.json").write_text("{}")
    (folder / f"{resized.name}.dump").write_bytes(b"x" * 11)
    (folder / "notes.txt").write_text("mine")
    r = (await admin_client.get(url)).json()
    assert "warning" not in r and r["other_files"] == 1 and r["folder"] == str(folder)
    by_name = {b["name"]: b for b in r["backups"]}
    assert by_name[back.name]["status"] == "ready"  # it came back, so it can be restored again
    assert by_name[resized.name]["status"] == "changed" and not by_name[resized.name]["restorable"]
    assert by_name[ok.name]["restorable"] and by_name[ok.name]["checked_at"]
    assert (await load(Backup, back.id)).status == "ready"


async def test_check_true_while_busy_or_unreachable_shows_the_stored_rows(admin_client, monkeypatch, tmp_path):
    iid = await seed(tmp_path)
    await add(backup_row(iid))

    @contextlib.asynccontextmanager
    async def unreachable(target, **kw):
        raise ssh.SSHError("Connection refused")
        yield

    monkeypatch.setattr(instances_api, "open_session", unreachable)
    r = (await admin_client.get(f"/api/v1/instances/{iid}/backups?check=true")).json()
    assert r["warning"] == "Couldn't check the backups on prod-01 (Connection refused); showing what Slipway recorded"
    assert [b["status"] for b in r["backups"]] == ["ready"]
    await job(iid, "backup", "running")
    r = (await admin_client.get(f"/api/v1/instances/{iid}/backups?check=true")).json()
    assert r["warning"] == "A job is running for shop; showing what Slipway recorded"
    assert len(r["backups"]) == 1


async def test_delete_backup_removes_confirmed_files_forgets_missing_and_keeps_changed(admin_client, shell, tmp_path):
    iid = await seed(tmp_path)
    folder = tmp_path / "shop" / "backups"
    folder.mkdir(parents=True)
    ready = backup_row(iid, at=T0, reason="manual")
    missing = backup_row(iid, at=T0 + timedelta(hours=1), reason="manual", status="missing")
    changed = backup_row(iid, at=T0 + timedelta(hours=2), reason="manual")
    pinned = backup_row(iid, at=T0 + timedelta(hours=3))
    await add(ready, missing, changed, pinned)
    await job(iid, "deploy", "failed", at=T0 + timedelta(hours=4), backup_id=pinned.id)  # the latest changing job
    for row, size in ((ready, 10), (changed, 12)):
        (folder / f"{row.name}.dump").write_bytes(b"x" * size)
        (folder / f"{row.name}.json").write_text("{}")

    r = await admin_client.delete(f"/api/v1/instances/{iid}/backups/{pinned.id}")
    assert r.status_code == 409 and r.json()["detail"].startswith("This backup is pinned: it was taken before deployment")
    assert (await admin_client.delete(f"/api/v1/instances/{iid}/backups/{ready.id}")).status_code == 204
    assert not (folder / f"{ready.name}.dump").exists() and not (folder / f"{ready.name}.json").exists()
    shell.commands.clear()
    assert (await admin_client.delete(f"/api/v1/instances/{iid}/backups/{missing.id}")).status_code == 204
    assert shell.commands == []  # forgotten without touching the host
    r = await admin_client.delete(f"/api/v1/instances/{iid}/backups/{changed.id}")
    assert r.status_code == 200 and "changed since Slipway took them" in r.json()["warning"]
    assert (folder / f"{changed.name}.dump").exists()  # never removed unconfirmed (I5)
    async with get_sessionmaker()() as db:
        left = {b.id for b in (await db.scalars(select(Backup))).all()}
    assert left == {pinned.id}
    deleted = [e.details for e in await actions() if e.action == "backup.delete"]
    assert deleted[0] == {"name": ready.name, "reason": "manual", "sha256": None}
    assert deleted[1]["forgotten"] is True


async def test_removing_from_slipway_only_writes_the_keys_only_slipway_holds(admin_client, shell, tmp_path, monkeypatch):
    """purge=false: the backup rows go with the instance, so a dump taken with other identity keys than the ones
    in its .env gets its <name>.identity.env next to it (data-loss 16). Nothing else on the host is touched."""
    plain = await seed(tmp_path, name="plain")
    await add(backup_row(plain))  # made with the live key: the .env on the host opens it
    assert (await admin_client.delete(f"/api/v1/instances/{plain}?purge=false")).status_code == 204
    assert shell.commands == []

    iid = await seed(tmp_path)
    folder = tmp_path / "shop" / "backups"
    folder.mkdir(parents=True)
    same = backup_row(iid, at=T0, reason="manual")
    older = backup_row(iid, at=T0 - timedelta(days=3), reason="manual", identity={"FIELD_ENCRYPTION_KEY": KEY_B})
    await add(same, older)
    for row in (same, older):
        (folder / f"{row.name}.dump").write_bytes(b"x" * 10)
    r = await admin_client.delete(f"/api/v1/instances/{iid}?purge=false")
    assert r.status_code == 204, r.text
    assert (folder / f"{older.name}.identity.env").read_text() == f"FIELD_ENCRYPTION_KEY={KEY_B}\n"
    assert oct((folder / f"{older.name}.identity.env").stat().st_mode & 0o777) == "0o600"
    assert sorted(p.name for p in folder.iterdir()) == sorted(
        [f"{same.name}.dump", f"{same.name}.identity.env", f"{older.name}.dump", f"{older.name}.identity.env"])
    assert not any("docker" in c or "rm " in c for c in shell.commands)
    assert await load(Instance, iid) is None

    # The host can't be reached: the instance is still removed, and the answer says which keys are gone.
    iid = await seed(tmp_path, name="gone")
    lost = backup_row(iid, reason="manual", identity={"FIELD_ENCRYPTION_KEY": KEY_B})
    await add(lost)

    @contextlib.asynccontextmanager
    async def unreachable(target, **kw):
        raise ssh.SSHError("Could not connect to 10.0.0.1: timed out")
        yield

    monkeypatch.setattr(instances_api, "open_session", unreachable)
    r = await admin_client.delete(f"/api/v1/instances/{iid}?purge=false")
    assert r.status_code == 200
    assert r.json()["warning"] == (f"The field encryption key of backup {lost.name} could not be written next to it "
                                   "on prod-01 (Could not connect to 10.0.0.1: timed out); Slipway no longer has a copy")
    assert await load(Instance, iid) is None
    event = [e for e in await actions() if e.action == "instance.delete"][-1]
    assert lost.name in event.summary and KEY_B not in json.dumps([event.summary, event.details])


async def test_record_ids_are_loaded_by_their_instance(admin_client, shell, tmp_path):
    a = await seed(tmp_path, name="shop-a")
    b = await seed(tmp_path, name="shop-b")
    theirs = backup_row(b)
    await add(theirs)
    assert (await admin_client.delete(f"/api/v1/instances/{a}/backups/{theirs.id}")).status_code == 404
    r = await admin_client.post(f"/api/v1/instances/{a}/data/restore",
                                json={"backup_id": str(theirs.id), "confirm": "shop-a"})
    assert r.status_code == 404 and r.json()["detail"] == "Backup not found"
    assert (await load(Backup, theirs.id)) is not None


# ----------------------------------------------------------------------------------- restore and reset


async def test_restore_queues_the_live_release_with_the_backup(admin_client, submitted):
    iid = await seed()
    row = backup_row(iid, has_files=False)
    await add(row)
    r = await admin_client.post(f"/api/v1/instances/{iid}/data/restore",
                                json={"backup_id": str(row.id), "confirm": "shop", "files": True})
    assert r.status_code == 422 and "has no files to put back" in r.json()["detail"]
    r = await admin_client.post(f"/api/v1/instances/{iid}/data/restore", json={"backup_id": str(row.id), "confirm": "shop"})
    assert r.status_code == 202, r.text
    out = r.json()
    assert out["kind"] == "restore" and out["restore_backup"]["name"] == row.name and out["previous_sha"] == SHA
    assert out["options"] == {"files": False, "restore_identity": False}
    assert [s["key"] for s in out["steps"]][:4] == ["release", "manifest", "settings", "build"]
    event = next(e for e in await actions() if e.action == "instance.restore")
    assert event.details["backup"] == row.name and event.details["identity_restored"] is False
    # Undo: restoring the copy taken before the latest restore records the link.
    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, uuid.UUID(out["id"]))
        before = backup_row(iid, at=T0 + timedelta(hours=1), reason="pre_restore")
        db.add(before)
        dep.status, dep.backup_id = "succeeded", before.id
        await db.commit()
    r = await admin_client.post(f"/api/v1/instances/{iid}/data/restore", json={"backup_id": str(before.id), "confirm": "shop"})
    assert r.status_code == 202 and r.json()["options"]["undo_of"] == out["id"].replace("-", "")


async def test_restoring_other_identity_keys_needs_the_tick_and_data_reset(make_client):
    c = await clients(make_client)
    iid = await seed()
    old = backup_row(iid, identity={"FIELD_ENCRYPTION_KEY": KEY_B})
    await add(old)
    body = {"backup_id": str(old.id), "confirm": "shop"}
    r = await c["developer"].post(f"/api/v1/instances/{iid}/data/restore", json=body)
    assert r.status_code == 409 and r.json()["detail"] == (
        "This backup was made with other field encryption key; restoring it puts them back. Restore it again with "
        "\"Put back its field encryption key\" (needs data:reset).")
    r = await c["developer"].post(f"/api/v1/instances/{iid}/data/restore", json={**body, "restore_identity": True})
    assert r.status_code == 403 and "data:reset" in r.json()["detail"]
    listed = (await c["developer"].get(f"/api/v1/instances/{iid}/backups")).json()["backups"][0]
    assert listed["needs_reset_perm"] and "puts back the field encryption key" in listed["identity_note"]
    r = await c["maintainer"].post(f"/api/v1/instances/{iid}/data/restore", json={**body, "restore_identity": True})
    assert r.status_code == 202 and r.json()["options"]["restore_identity"] is True
    # An instance variable that pins the key refuses it (§9.2 rule 5).
    other = await seed(name="pinned", env={"FIELD_ENCRYPTION_KEY": KEY_A})
    row = backup_row(other, identity={"FIELD_ENCRYPTION_KEY": KEY_B})
    await add(row)
    r = await c["maintainer"].post(f"/api/v1/instances/{other}/data/restore",
                                   json={"backup_id": str(row.id), "confirm": "pinned", "restore_identity": True})
    assert r.status_code == 409 and "the instance's environment variable FIELD_ENCRYPTION_KEY sets this one" in r.json()["detail"]


async def test_reset_empty_needs_a_first_admin_and_keeps_it_pending(admin_client):
    iid = await seed()
    r = await admin_client.post(f"/api/v1/instances/{iid}/data/reset", json={"confirm": "shop"})
    assert r.status_code == 422 and r.json()["detail"] == (
        "After the reset the app has no accounts: give a first admin so someone can sign in")
    r = await admin_client.post(f"/api/v1/instances/{iid}/data/reset",
                                json={"confirm": "shop", "first_admin": {**ADMIN, "password": "short"}})
    assert r.status_code == 422 and "the password must be 10 to 1024 characters" in r.json()["detail"]
    r = await admin_client.post(f"/api/v1/instances/{iid}/data/reset", json={"confirm": "shop", "first_admin": ADMIN})
    assert r.status_code == 202, r.text
    out = r.json()
    assert out["kind"] == "reset" and out["options"] == {"seed": True} and out["snapshot"] is None
    assert "reset" in [s["key"] for s in out["steps"]] and "seed" in [s["key"] for s in out["steps"]]
    async with get_sessionmaker()() as db:
        admin = await db.scalar(select(FirstAdmin).where(FirstAdmin.instance_id == iid))
    assert admin.status == "pending" and admin.password == PASSWORD and admin.fields["email"] == "ada@example.com"
    event = next(e for e in await actions() if e.action == "instance.reset")
    assert event.details["to"] == "empty" and event.details["first_admin"] == "ada@example.com"


async def test_reset_from_a_snapshot_follows_the_seeding_rules(make_client):
    c = await clients(make_client)
    iid = await seed()
    same = await ready_snapshot(c["admin"], "same-repo")
    elsewhere = await ready_snapshot(c["admin"], "other-repo", repository="acme/other")
    unknown = await ready_snapshot(c["admin"], "no-repo", repository=None)
    wrong_app = await ready_snapshot(c["admin"], "other-app", app="blog")
    url = f"/api/v1/instances/{iid}/data/reset"
    r = await c["maintainer"].post(url, json={"confirm": "shop", "snapshot_id": str(elsewhere)})
    assert r.status_code == 403 and r.json()["detail"] == (
        "Snapshot other-repo was made from acme/other; seeding shop (acme/shop) from it needs the snapshots:download "
        "permission")
    r = await c["maintainer"].post(url, json={"confirm": "shop", "snapshot_id": str(unknown)})
    assert r.status_code == 403 and "made from an unknown repository" in r.json()["detail"]
    r = await c["maintainer"].post(url, json={"confirm": "shop", "snapshot_id": str(wrong_app)})
    assert r.status_code == 409 and r.json()["detail"] == "This snapshot is of app blog (Acme shop); shop runs acme-shop"
    async with get_sessionmaker()() as db:
        snap = await db.get(Snapshot, same)
        snap.status = "checking"
        await db.commit()
    r = await c["maintainer"].post(url, json={"confirm": "shop", "snapshot_id": str(same)})
    assert r.status_code == 409 and r.json()["detail"] == "Snapshot same-repo isn't ready (checking)"
    pinned = await seed(name="pinned", env={"FIELD_ENCRYPTION_KEY": KEY_A})
    r = await c["admin"].post(f"/api/v1/instances/{pinned}/data/reset",
                              json={"confirm": "pinned", "snapshot_id": str(elsewhere)})
    assert r.status_code == 409 and "environment variable FIELD_ENCRYPTION_KEY would replace it" in r.json()["detail"]
    # The admin holds snapshots:download; no first admin is needed with a snapshot.
    r = await c["admin"].post(url, json={"confirm": "shop", "snapshot_id": str(elsewhere)})
    assert r.status_code == 202, r.text
    out = r.json()
    assert out["snapshot"]["name"] == "other-repo" and out["options"] == {"seed": False}
    assert [s["key"] for s in out["steps"]].index("check") < [s["key"] for s in out["steps"]].index("reset")


async def test_start_over_is_for_never_live_instances_with_a_release(admin_client):
    live = await seed()
    r = await admin_client.post(f"/api/v1/instances/{live}/data/start-over", json={"confirm": "shop"})
    assert r.status_code == 409 and r.json()["detail"] == "shop has gone live; use Reset data"
    never = await seed(name="fresh", live=False)
    r = await admin_client.post(f"/api/v1/instances/{never}/data/start-over", json={"confirm": "fresh"})
    assert r.status_code == 409 and r.json()["detail"] == (
        "Slipway has no release of fresh on prod-01 to back up its data with; deploy once more, or remove the volumes "
        "by hand")
    await job(never, "deploy", "failed", release=f"/x/releases/{SHA2[:12]}-0000aaaa")
    r = await admin_client.post(f"/api/v1/instances/{never}/data/start-over", json={"confirm": "fresh"})
    assert r.status_code == 202, r.text
    assert r.json()["options"] == {"start_over": True}
    assert [s["key"] for s in r.json()["steps"]] == ["release", "backup", "stop", "reset"]


# ------------------------------------------------------------------------------- roll back and retry


async def _failed_deploy(iid) -> tuple[Deployment, Backup]:
    point = backup_row(iid, at=T0)
    await add(point)
    dep = await job(iid, "deploy", "failed", at=T0 + timedelta(minutes=1), backup_id=point.id,
                    steps=steps(backup="succeeded", start="failed"))
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, iid)
        inst.data_dirty = data.mark_dirty(None, dep, step="start")
        inst.status = "failed"
        await db.commit()
    return dep, point


async def test_roll_back_a_failed_deploy(admin_client, submitted):
    iid = await seed()
    dep, point = await _failed_deploy(iid)
    detail = (await admin_client.get(f"/api/v1/deployments/{dep.id}")).json()
    assert detail["actions"]["rollback"]["available"] is True and detail["backup"]["name"] == point.name
    assert detail["actions"]["retry"]["available"] is True and detail["kind"] == "deploy"
    r = await admin_client.post(f"/api/v1/deployments/{dep.id}/rollback", json={"confirm": "Shop"})
    assert r.status_code == 422
    r = await admin_client.post(f"/api/v1/deployments/{dep.id}/rollback", json={"confirm": "shop"})
    assert r.status_code == 202, r.text
    out = r.json()
    assert out["kind"] == "rollback" and out["restore_backup"]["id"] == str(point.id)
    assert out["options"] == {"rollback_of": dep.id.hex} and out["commit_sha"] == SHA
    names = {s["key"]: s["name"] for s in out["steps"]}
    assert names["restore"] == f"Restore the backup from before deployment {dep.id.hex[:8]}"
    # It is now the latest changing job: rolling back again is refused with the reason.
    r = await admin_client.post(f"/api/v1/deployments/{dep.id}/rollback", json={"confirm": "shop"})
    assert r.status_code == 409 and r.json()["detail"].startswith("Roll back isn't available: Roll back ")
    event = next(e for e in await actions() if e.action == "instance.rollback")
    assert event.details["backup"] == point.name and event.details["deployment"] == str(dep.id)


async def test_retry_needs_the_kind_s_permission_and_the_typed_name(make_client):
    c = await clients(make_client)
    iid = await seed()
    row = backup_row(iid)
    await add(row)
    restore = await job(iid, "restore", "failed", restore_backup_id=row.id, backup_id=row.id,
                        options={"files": False, "prev_status": "running"},
                        steps=steps(release="succeeded", check="succeeded", backup="failed"))
    url = f"/api/v1/deployments/{restore.id}/retry"
    assert (await c["viewer"].post(url, json={"confirm": "shop"})).status_code == 403
    r = await c["developer"].post(url)
    assert r.status_code == 422 and r.json()["detail"] == "Type the instance's name, shop, exactly to confirm"
    r = await c["developer"].post(url, json={"confirm": "shop", "skip_backup": True})
    assert r.status_code == 403  # skipping the backup needs data:reset
    r = await c["maintainer"].post(url, json={"confirm": "shop", "skip_backup": True})
    assert r.status_code == 202, r.text
    out = r.json()
    assert out["kind"] == "restore" and out["retry_of_id"] == str(restore.id)
    assert out["options"]["skip_backup"] is True and "prev_status" not in out["options"]
    event = next(e for e in await actions() if e.action == "deployment.retry")
    assert event.details["kind"] == "restore" and event.details["skip_backup"] is True
    # skip_backup only when the backup step failed.
    async with get_sessionmaker()() as db:
        (await db.get(Deployment, uuid.UUID(out["id"]))).status = "failed"
        await db.commit()
    r = await c["maintainer"].post(f"/api/v1/deployments/{out['id']}/retry", json={"confirm": "shop", "skip_backup": True})
    assert r.status_code == 409 and r.json()["detail"] == "Retry without the backup is only for a job whose backup failed"
    # A reset's retry needs data:reset; one that puts back identity keys does too.
    reset = await job(iid, "reset", "failed", at=T0 + timedelta(hours=2), steps=steps(release="failed"))
    assert (await c["developer"].post(f"/api/v1/deployments/{reset.id}/retry", json={"confirm": "shop"})).status_code == 403
    keys = await job(iid, "restore", "failed", at=T0 + timedelta(hours=3), options={"restore_identity": True},
                     restore_backup_id=row.id, steps=steps(release="failed"))
    assert (await c["developer"].post(f"/api/v1/deployments/{keys.id}/retry", json={"confirm": "shop"})).status_code == 403
    # Only the latest changing job of a restore kind can be retried.
    r = await c["maintainer"].post(f"/api/v1/deployments/{reset.id}/retry", json={"confirm": "shop"})
    assert r.status_code == 409 and r.json()["detail"].startswith("Only the most recent job of shop can be retried")


# --------------------------------------------------------------------------------- hold and control


async def _held(iid) -> Backup:
    before = backup_row(iid, reason="pre_restore")
    await add(before)
    dep = await job(iid, "restore", "failed", backup_id=before.id,
                    steps=steps(release="succeeded", check="succeeded", backup="succeeded", stop="succeeded",
                                restore="failed"))
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, iid)
        inst.data_dirty = data.mark_dirty(None, dep, step="restore")
        inst.status = "failed"
        await db.commit()
    return before


async def test_a_hold_refuses_deploy_and_start_until_overridden(make_client, monkeypatch):
    c = await clients(make_client)
    iid = await seed()
    before = await _held(iid)
    r = await c["developer"].post(f"/api/v1/instances/{iid}/deploy")
    assert r.status_code == 409 and r.json()["detail"] == (
        "shop's last restore stopped part-way (step 5/5: Restore), so its database may be empty or half-restored. "
        f"Retry it, or restore the backup taken just before it ({before.name}). Start, Restart and Deploy are off until then.")
    assert (await c["developer"].post(f"/api/v1/instances/{iid}/deploy",
                                      json={"override_hold": True, "confirm": "shop"})).status_code == 403
    assert (await c["maintainer"].post(f"/api/v1/instances/{iid}/deploy",
                                       json={"override_hold": True})).status_code == 422
    for path in ("snapshots", "first-admin/run"):
        r = await c["maintainer"].post(f"/api/v1/instances/{iid}/{path}", json={"name": "held-1"})
        assert r.status_code == 409 and "stopped part-way" in r.json()["detail"], path

    ran = []

    async def fake_run(instance, command, **kw):
        ran.append(command)
        return "started"

    monkeypatch.setattr(deployer, "run_on_instance", fake_run)
    r = await c["developer"].post(f"/api/v1/instances/{iid}/actions/start")
    assert r.status_code == 409 and "stopped part-way" in r.json()["detail"] and not ran
    assert (await c["developer"].post(f"/api/v1/instances/{iid}/actions/stop")).status_code == 200  # stop is allowed
    r = await c["maintainer"].post(f"/api/v1/instances/{iid}/actions/start", json={"override_hold": True, "confirm": "shop"})
    assert r.status_code == 200, r.text
    inst = await load(Instance, iid)
    assert inst.data_dirty["hold"] is False and inst.data_dirty["first"]["kind"] == "restore"  # dirty stays
    assert inst.status == "running" and inst.last_control_at is not None
    assert (await c["developer"].post(f"/api/v1/instances/{iid}/deploy")).status_code == 202
    assert [e.action for e in await actions()].count("instance.hold_override") == 1


async def test_a_hold_refuses_retrying_an_older_deploy(make_client):
    """Review findings 3, 7 and 9: a retried deploy is a deploy, so the hold refuses it; the held job's retry stays."""
    c = await clients(make_client)
    iid = await seed()
    old = await job(iid, "deploy", "failed", at=T0 - timedelta(hours=5), steps=steps(release="failed"))
    await _held(iid)
    held = (await c["developer"].post(f"/api/v1/instances/{iid}/deploy")).json()["detail"]
    assert "stopped part-way" in held
    r = await c["developer"].post(f"/api/v1/deployments/{old.id}/retry")
    assert r.status_code == 409 and r.json()["detail"] == held
    detail = (await c["developer"].get(f"/api/v1/deployments/{old.id}")).json()
    assert detail["actions"]["retry"] == {**detail["actions"]["retry"], "available": False, "reason": held}
    assert (await c["maintainer"].post(f"/api/v1/deployments/{old.id}/retry")).status_code == 409
    # Retrying the held restore itself is the way out the hold text names.
    async with get_sessionmaker()() as db:
        restore = await data.latest_changing_job(db, iid)
    assert restore.kind == "restore"
    r = await c["maintainer"].post(f"/api/v1/deployments/{restore.id}/retry", json={"confirm": "shop"})
    assert r.status_code == 202, r.text
    assert "instance.hold_override" not in [e.action for e in await actions()]


async def test_a_retry_is_refused_what_starting_the_job_again_would_be(make_client, monkeypatch):
    """Review findings 21, 22 and 36: the manual-backup cap, nothing pending, and stop_app's permission."""
    c = await clients(make_client)
    iid = await seed(content_pending=False)
    # Back up now: the cap on backups taken by hand.
    monkeypatch.setenv("SLIPWAY_MANUAL_BACKUPS_MAX", "1")
    get_settings.cache_clear()
    backup = await job(iid, "backup", "failed", steps=steps(release="succeeded", backup="failed"))
    await add(backup_row(iid, reason="manual"))
    r = await c["developer"].post(f"/api/v1/deployments/{backup.id}/retry")
    assert r.status_code == 409 and r.json()["detail"] == "shop already has 1 backups you took yourself; delete one first"
    detail = (await c["developer"].get(f"/api/v1/deployments/{backup.id}")).json()
    assert detail["actions"]["retry"]["available"] is False
    monkeypatch.setenv("SLIPWAY_MANUAL_BACKUPS_MAX", "2")
    get_settings.cache_clear()
    assert (await c["developer"].post(f"/api/v1/deployments/{backup.id}/retry")).status_code == 202
    async with get_sessionmaker()() as db:
        for dep in (await db.scalars(select(Deployment).where(Deployment.retry_of_id.is_not(None)))).all():
            dep.status = "succeeded"
        await db.commit()
    # Add starter content: only while some is waiting.
    content = await job(iid, "content", "failed", at=T0 + timedelta(hours=1), steps=steps(release="failed", seed="pending"))
    r = await c["developer"].post(f"/api/v1/deployments/{content.id}/retry")
    assert r.status_code == 409 and r.json()["detail"] == "shop has no starter content waiting to be added"
    # Create the first admin: only while one is waiting, on a running app.
    admin = await job(iid, "admin", "failed", at=T0 + timedelta(hours=2), steps=steps(release="failed"))
    r = await c["developer"].post(f"/api/v1/deployments/{admin.id}/retry")
    assert r.status_code == 409 and r.json()["detail"] == "No first admin is waiting to be created in shop"
    # Take a snapshot that stops the app: instances:operate too.
    snap = Snapshot(id=uuid.uuid4(), name="s1", notes="", status="failed", origin="instance", app="acme-shop",
                    repository="acme/shop", source="shop", source_instance_id=iid)
    await add(snap)
    taken = await job(iid, "snapshot", "failed", snapshot_id=snap.id, options={"stop_app": True, "restop": False},
                      steps=steps(release="failed"))
    backer = await client_with(make_client, "bk@example.com", ["deployments:create", "data:backup", "instances:read"])
    assert (await backer.post(f"/api/v1/instances/{iid}/snapshots", json={"name": "s2", "stop_app": True})).status_code == 403
    r = await backer.post(f"/api/v1/deployments/{taken.id}/retry")
    assert r.status_code == 403 and r.json()["detail"] == "Missing permission: instances:operate"
    r = await c["maintainer"].post(f"/api/v1/deployments/{taken.id}/retry")
    assert r.status_code == 202, r.text
    assert r.json()["options"]["stop_app"] is True


async def test_retrying_a_seeding_deploy_follows_todays_seed(make_client):
    """Review finding 20: changing the seed needs data:reset, and Retry doesn't get around it."""
    c = await clients(make_client)
    kw = dict(notes="", status="ready", origin="instance", app="acme-shop", repository="acme/shop",
              file_sha256="a" * 64, db_sha256="b" * 64)
    s1, s2 = Snapshot(id=uuid.uuid4(), name="bad-s1", **kw), Snapshot(id=uuid.uuid4(), name="good-s2", **kw)
    await add(s1, s2)
    iid = await seed(live=False, seed_snapshot_id=s1.id)
    d1 = await job(iid, "deploy", "failed", snapshot_id=s1.id,
                   steps=steps(release="succeeded", build="succeeded", check="failed", restore="pending"))
    url = f"/api/v1/deployments/{d1.id}/retry"
    for seed_id, now in ((s2.id, "from snapshot good-s2"), (None, "empty")):
        async with get_sessionmaker()() as db:
            (await db.get(Instance, iid)).seed_snapshot_id = seed_id
            await db.commit()
        r = await c["developer"].post(url)
        assert r.status_code == 409 and r.json()["detail"] == (
            f"This deployment started shop from snapshot bad-s1, and shop now starts {now}: deploy the instance instead")
    async with get_sessionmaker()() as db:
        (await db.get(Instance, iid)).seed_snapshot_id = s1.id
        await db.commit()
    r = await c["developer"].post(url)
    assert r.status_code == 202 and r.json()["snapshot"]["name"] == "bad-s1"


async def test_retrying_a_seeding_deploy_after_its_snapshot_and_seed_went_stays_empty(make_client):
    """The seed was cleared, then the restored snapshot deleted: the retry must not go live on its data."""
    c = await clients(make_client)
    iid = await seed(live=False)
    d1 = await job(iid, "deploy", "failed", snapshot_id=None,
                   steps=steps(release="succeeded", build="succeeded", check="succeeded", restore="succeeded",
                               files="skipped", after_import="succeeded", start="failed"))
    r = await c["developer"].post(f"/api/v1/deployments/{d1.id}/retry")
    assert r.status_code == 409 and r.json()["detail"] == (
        "This deployment started shop from a snapshot that was deleted, and shop now starts empty: "
        "deploy the instance instead")


async def test_control_waits_for_no_job(admin_client, monkeypatch):
    iid = await seed()
    monkeypatch.setattr(deployer, "run_on_instance", lambda *a, **kw: pytest.fail("ran during a job"))
    assert (await admin_client.post(f"/api/v1/instances/{iid}/backups")).status_code == 202
    r = await admin_client.post(f"/api/v1/instances/{iid}/actions/stop")
    assert r.status_code == 409 and r.json()["detail"] == (
        "A job is running for this instance (Back up); wait for it to finish")


# ------------------------------------------------------------------------------------ concurrency


async def test_two_restores_at_once_give_one_job(admin_client):
    iid = await seed()
    row = backup_row(iid)
    await add(row)
    body = {"backup_id": str(row.id), "confirm": "shop"}
    url = f"/api/v1/instances/{iid}/data/restore"
    codes = sorted(r.status_code for r in await asyncio.gather(admin_client.post(url, json=body),
                                                               admin_client.post(url, json=body)))
    assert codes == [202, 409]
    async with get_sessionmaker()() as db:
        assert len((await db.scalars(select(Deployment).where(Deployment.kind == "restore"))).all()) == 1


async def test_the_one_active_job_index_answers_409(admin_client, monkeypatch):
    iid = await seed()
    row = backup_row(iid)
    await add(row)
    await job(iid, "backup", "running")

    async def nothing_running(db, instance_id):
        return None  # as if the other request's job wasn't visible yet: the partial unique index decides

    monkeypatch.setattr(data, "active_job", nothing_running)
    r = await admin_client.post(f"/api/v1/instances/{iid}/data/restore", json={"backup_id": str(row.id), "confirm": "shop"})
    assert r.status_code == 409 and r.json()["detail"] == instances_api.BUSY


# ---------------------------------------------------------------------------- typed confirmation


async def test_every_gated_action_wants_the_exact_name(admin_client, monkeypatch):
    iid = await seed()
    row = backup_row(iid)
    await add(row)
    dep, _ = await _failed_deploy(await seed(name="dirty"))
    restore = await job(iid, "restore", "failed", restore_backup_id=row.id, steps=steps(release="failed"))
    requests = [
        ("post", f"/api/v1/instances/{iid}/data/restore", {"backup_id": str(row.id)}),
        ("post", f"/api/v1/instances/{iid}/data/restore", {"backup_id": str(uuid.uuid4())}),  # missing: 422 first
        ("post", f"/api/v1/instances/{iid}/data/reset", {"first_admin": ADMIN}),
        ("post", f"/api/v1/instances/{iid}/data/start-over", {}),
        ("post", f"/api/v1/deployments/{dep.id}/rollback", {}),
        ("post", f"/api/v1/deployments/{restore.id}/retry", {}),
        ("post", f"/api/v1/deployments/{dep.id}/retry", {"skip_backup": True}),
        ("post", f"/api/v1/instances/{iid}/deploy", {"override_hold": True}),
        ("post", f"/api/v1/instances/{iid}/deploy", {"take_over_lock": True}),
        ("post", f"/api/v1/instances/{iid}/deploy", {"skip_revision_check": True}),
        ("post", f"/api/v1/instances/{iid}/actions/start", {"override_hold": True}),
        ("put", f"/api/v1/instances/{iid}/first-admin", {"fields": ADMIN["fields"], "mode": "password",
                                                       "password": PASSWORD}),
    ]
    for method, url, body in requests:
        for typed in (None, "Shop", "shop ", "SHOP", ""):
            payload = {**body, **({"confirm": typed} if typed is not None else {})}
            r = await getattr(admin_client, method)(url, json=payload)
            name = "dirty" if "/deployments/" in url and str(dep.id) in url else "shop"
            assert r.status_code == 422 and r.json()["detail"] == (
                f"Type the instance's name, {name}, exactly to confirm"), (url, typed, r.text)


# ------------------------------------------------------------------------------------------ snapshots


async def test_take_a_snapshot(make_client):
    c = await clients(make_client)
    iid = await seed()
    r = await c["developer"].post(f"/api/v1/instances/{iid}/snapshots", json={"name": "bad name!"})
    assert r.status_code == 422 and r.json()["detail"] == snapshots.BAD_NAME
    r = await c["developer"].post(f"/api/v1/instances/{iid}/snapshots", json={"name": "shop-1", "notes": "Before go-live"})
    assert r.status_code == 202, r.text
    snap, dep = r.json()["snapshot"], r.json()["deployment"]
    assert snap["status"] == "pending" and snap["origin"] == "instance" and snap["app"] == "acme-shop"
    assert snap["repository"] == "acme/shop" and snap["source"] == "shop" and snap["deployment_id"] == dep["id"]
    assert dep["kind"] == "snapshot" and dep["snapshot"]["name"] == "shop-1"
    assert [s["key"] for s in dep["steps"]] == ["release", "export", "store"]
    r = await c["developer"].post(f"/api/v1/instances/{iid}/snapshots", json={"name": "shop-1"})
    assert r.status_code == 409 and r.json()["detail"] == "There is already a snapshot named shop-1"
    # Stopping the app needs instances:operate too.
    taker = await client_with(make_client, "taker@example.com", ["data:backup"])
    other = await seed(name="other")
    r = await taker.post(f"/api/v1/instances/{other}/snapshots", json={"name": "other-1", "stop_app": True})
    assert r.status_code == 403 and "instances:operate" in r.json()["detail"]
    r = await taker.post(f"/api/v1/instances/{other}/snapshots", json={"name": "other-1"})
    assert r.status_code == 202
    # Half-changed data isn't snapshotted.
    dirty = await seed(name="dirty")
    await _failed_deploy(dirty)
    r = await c["developer"].post(f"/api/v1/instances/{dirty}/snapshots", json={"name": "dirty-1"})
    assert r.status_code == 409 and "was left half-changed by deployment" in r.json()["detail"]


async def test_upload_unlock_rename_export_and_download(make_client, storage):
    c = await clients(make_client)
    iid = await seed()
    r = await upload(c["developer"], plain_snapshot(), "uat-1")
    assert r.status_code == 403
    sid = await ready_snapshot(c["maintainer"], "uat-1")
    other = await ready_snapshot(c["maintainer"], "elsewhere", repository="acme/other")
    listed = (await c["viewer"].get(f"/api/v1/snapshots?instance_id={iid}")).json()
    assert [s["name"] for s in listed] == ["elsewhere", "uat-1"]
    assert {s["name"]: s["seeding_needs_download"] for s in listed} == {"elsewhere": True, "uat-1": False}
    assert all("data_key" not in s and "import_keyblock" not in s for s in listed)
    assert listed[1]["revision_short"] == "0042" and listed[1]["identity_keys"] == ["FIELD_ENCRYPTION_KEY"]
    r = await c["developer"].patch(f"/api/v1/snapshots/{other}", json={"name": "uat-1"})
    assert r.status_code == 409
    r = await c["developer"].patch(f"/api/v1/snapshots/{other}", json={"name": "renamed", "notes": "kept"})
    assert r.status_code == 200 and r.json()["name"] == "renamed"
    usage = (await c["viewer"].get("/api/v1/snapshots/usage")).json()
    assert usage["used"] > 0

    # Download: only snapshots:download (the admin), with a passphrase, once.
    r = await c["maintainer"].post(f"/api/v1/snapshots/{sid}/exports", json={"passphrase": PASSPHRASE})
    assert r.status_code == 403
    r = await c["admin"].post(f"/api/v1/snapshots/{sid}/exports", json={"passphrase": "short"})
    assert r.status_code == 422
    r = await c["admin"].post(f"/api/v1/snapshots/{sid}/exports", json={"passphrase": PASSPHRASE})
    assert r.status_code == 201, r.text
    ticket = r.json()
    assert ticket["url"].startswith("/api/v1/snapshot-exports/") and ticket["bytes"] > 0
    another = make_client()
    await make_user("admin2@example.com", roles=["admin"])
    await login(another, "admin2@example.com")
    assert (await another.get(ticket["url"])).status_code == 404  # another user's link
    r = await c["admin"].get(ticket["url"])
    assert r.status_code == 200 and r.content[:8] == b"SLWSNAP1" and len(r.content) == ticket["bytes"]
    assert r.headers["content-disposition"] == 'attachment; filename="uat-1.slipway-snapshot"'
    assert r.headers["cache-control"] == "no-store"
    assert (await c["admin"].get(ticket["url"])).status_code == 404  # single use

    # The downloaded file imports here as a locked snapshot, opened with the passphrase.
    r = await upload(c["maintainer"], r.content, "imported")
    assert r.status_code == 201 and r.json()["status"] == "locked" and r.json()["expires_at"]
    imported = r.json()["id"]
    r = await c["maintainer"].post(f"/api/v1/snapshots/{imported}/unlock", json={"passphrase": "wrong passphrase!"})
    assert r.status_code == 422 and r.json()["detail"] == "That passphrase doesn't open this file"
    r = await c["maintainer"].post(f"/api/v1/snapshots/{imported}/unlock", json={"passphrase": PASSPHRASE})
    assert r.status_code == 202 and r.json()["status"] == "checking"
    await snapshots.wait_for_validations()
    got = (await c["viewer"].get(f"/api/v1/snapshots/{imported}")).json()
    assert got["status"] == "ready" and got["app"] == "acme-shop" and got["db_sha256"]
    r = await upload(c["maintainer"], b"not a snapshot at all" * 20, "junk")
    assert r.status_code == 422 and "Choose a Slipway snapshot" in r.json()["detail"]


async def test_snapshot_delete_is_refused_while_in_use(admin_client, storage):
    iid = await seed()
    sid = await ready_snapshot(admin_client, "in-use")
    never = await seed(name="fresh", live=False, seed_snapshot_id=sid)
    r = await admin_client.delete(f"/api/v1/snapshots/{sid}")
    assert r.status_code == 409 and r.json()["detail"] == "Snapshot in-use is in use: fresh starts from it when it is first deployed"
    async with get_sessionmaker()() as db:
        (await db.get(Instance, never)).seed_snapshot_id = None
        await db.commit()
    running = await job(iid, "reset", "running", snapshot_id=sid)
    r = await admin_client.delete(f"/api/v1/snapshots/{sid}")
    assert r.status_code == 409 and f"a reset job of shop ({running.id.hex[:8]}) uses it" in r.json()["detail"]
    async with get_sessionmaker()() as db:
        (await db.get(Deployment, running.id)).status = "failed"  # failed before it restored it: a retry needs it
        await db.commit()
    r = await admin_client.delete(f"/api/v1/snapshots/{sid}")
    assert r.status_code == 409 and "failed before it restored it" in r.json()["detail"]
    async with get_sessionmaker()() as db:
        (await db.get(Snapshot, sid)).status = "pending"
        await db.commit()
    r = await admin_client.delete(f"/api/v1/snapshots/{sid}")
    assert r.status_code == 409 and "it is still being taken" in r.json()["detail"]
    async with get_sessionmaker()() as db:
        (await db.get(Snapshot, sid)).status = "ready"
        (await db.get(Deployment, running.id)).steps = steps(restore="succeeded")
        await db.commit()
    assert (await admin_client.delete(f"/api/v1/snapshots/{sid}")).status_code == 204
    assert not snapshots.bundle_path(sid).exists()
    assert (await admin_client.get(f"/api/v1/snapshots/{sid}")).status_code == 404


async def test_snapshot_endpoints_answer_503_when_storage_is_unusable(admin_client, storage):
    storage.parent.mkdir(parents=True, exist_ok=True)
    storage.write_text("a file, not a folder")
    r = await admin_client.get("/api/v1/snapshots")
    assert r.status_code == 503 and r.json()["detail"].startswith("SLIPWAY_STORAGE_DIR (")
    iid = await seed()
    r = await admin_client.post(f"/api/v1/instances/{iid}/snapshots", json={"name": "x-1"})
    assert r.status_code == 503
    assert (await admin_client.post(f"/api/v1/instances/{iid}/backups")).status_code == 202  # backups don't need it


# -------------------------------------------------------------------------------------- first admin


async def test_first_admin_before_and_after_going_live(make_client, monkeypatch):
    c = await clients(make_client)
    writer = await client_with(make_client, "writer@example.com", ["instances:read", "instances:write"])
    github_serving(monkeypatch, {"slipway.yml": SHOP_YML})
    never = await seed(name="fresh", live=False)
    url = f"/api/v1/instances/{never}/first-admin"
    assert (await writer.get(url)).status_code == 404
    r = await writer.put(url, json={**ADMIN, "mode": "invite", "password": None})
    assert r.status_code == 422 and "it can't invite by email" in r.json()["detail"]
    r = await writer.put(url, json={**ADMIN, "mode": "invite"})
    assert r.status_code == 422 and r.json()["detail"] == "A first admin invited by email has no password"
    r = await writer.put(url, json={**ADMIN, "fields": {"email": "ada@example.com"}})
    assert r.status_code == 422 and "it needs username" in r.json()["detail"]
    r = await writer.put(url, json=ADMIN)  # checked against the branch's slipway.yml
    assert r.status_code == 200, r.text
    assert r.json() == {"fields": ADMIN["fields"], "mode": "password", "status": "pending", "existed": False,
                        "done_at": None, "last_error": None, "has_password": True}
    # Changing the fields keeps the stored password.
    r = await writer.put(url, json={"fields": {"username": "ada2", "email": "ada@example.com"}, "mode": "password"})
    assert r.status_code == 200 and r.json()["fields"]["username"] == "ada2" and r.json()["has_password"]
    got = await writer.get(url)
    assert PASSWORD not in got.text and "password" not in got.json()
    inst = (await writer.get(f"/api/v1/instances/{never}")).json()
    assert inst["first_admin"]["status"] == "pending" and PASSWORD not in json.dumps(inst)
    # While a job runs: 409.
    await job(never, "deploy", "running")
    r = await writer.put(url, json=ADMIN)
    assert r.status_code == 409 and "A job is running for this instance (Deploy)" in r.json()["detail"]
    assert (await writer.delete(url)).status_code == 409

    # Live, and the first admin was created: 409, except the data:reset path with the typed name.
    live = await seed()
    await add(FirstAdmin(instance_id=live, fields=ADMIN["fields"], mode="password", status="done", done_at=T0))
    url = f"/api/v1/instances/{live}/first-admin"
    r = await writer.put(url, json=ADMIN)
    assert r.status_code == 409 and r.json()["detail"] == instances_api.ALREADY_CREATED
    assert (await c["maintainer"].put(url, json=ADMIN)).status_code == 422  # no typed name
    r = await c["maintainer"].put(url, json={**ADMIN, "confirm": "shop"})
    assert r.status_code == 200 and r.json()["status"] == "pending"
    event = [e for e in await actions() if e.action == "instance.first_admin"][-1]
    assert event.details == {"action": "changed", "emails": {"email": "ada@example.com"}, "mode": "password", "live": True}
    # Create it now: only while it is pending and the instance runs.
    r = await c["developer"].post(f"{url}/run")
    assert r.status_code == 202 and r.json()["kind"] == "admin"
    # Live with none at all: data:reset and the name.
    bare = await seed(name="bare")
    assert (await writer.put(f"/api/v1/instances/{bare}/first-admin", json=ADMIN)).status_code == 403


@pytest.mark.parametrize("fields", [
    {"username": "ada", "email": "a\x1b[31m@example.com"},
    {"username": "\n\x1c ada\x1f\n", "email": "ada@example.com"},
])
async def test_first_admin_fields_with_control_characters_are_refused(admin_client, monkeypatch, fields):
    github_serving(monkeypatch, {"slipway.yml": SHOP_YML})
    never = await seed(name="fresh", live=False)
    r = await admin_client.put(f"/api/v1/instances/{never}/first-admin", json={**ADMIN, "fields": fields})
    assert r.status_code == 422 and r.json()["detail"].startswith("The first admin doesn't fit "), r.text


async def test_starter_content_runs_only_while_pending(admin_client):
    iid = await seed()
    r = await admin_client.post(f"/api/v1/instances/{iid}/content/run")
    assert r.status_code == 409 and r.json()["detail"] == "shop has no starter content waiting to be added"
    async with get_sessionmaker()() as db:
        (await db.get(Instance, iid)).content_pending = True
        await db.commit()
    r = await admin_client.post(f"/api/v1/instances/{iid}/content/run")
    assert r.status_code == 202 and r.json()["kind"] == "content" and [s["key"] for s in r.json()["steps"]] == [
        "release", "seed"]
    assert "instance.content_run" in [e.action for e in await actions()]


# ------------------------------------------------------------------------------- create and edit


async def test_create_an_instance_from_a_snapshot_with_a_first_admin(make_client, monkeypatch):
    c = await clients(make_client)
    github_serving(monkeypatch, {"slipway.yml": SHOP_YML})
    await seed()  # makes the host and repository
    async with get_sessionmaker()() as db:
        host = await db.scalar(select(Host))
        repo = await db.scalar(select(Repository))
    sid = await ready_snapshot(c["admin"], "uat-1")
    other = await ready_snapshot(c["admin"], "other", repository="acme/other")
    body = {"name": "UAT two", "repository_id": str(repo.id), "host_id": str(host.id), "build_source": "app",
            "deploy": False, "seed_snapshot_id": str(sid), "first_admin": ADMIN, "keep_backups": 7}
    writer = await client_with(make_client, "writer@example.com", ["instances:read", "instances:write"])
    r = await writer.post("/api/v1/instances", json=body)
    assert r.status_code == 403 and r.json()["detail"] == "Starting from a snapshot needs the data:reset permission"
    r = await c["maintainer"].post("/api/v1/instances", json={**body, "seed_snapshot_id": str(other)})
    assert r.status_code == 403 and "needs the snapshots:download permission" in r.json()["detail"]
    r = await c["maintainer"].post("/api/v1/instances", json={**body, "env": {"FIELD_ENCRYPTION_KEY": KEY_A}})
    assert r.status_code == 409 and "would replace it" in r.json()["detail"]
    r = await c["maintainer"].post("/api/v1/instances", json={**body, "build_source": "compose"})
    assert r.status_code == 422
    r = await c["maintainer"].post("/api/v1/instances", json=body)
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["seed_snapshot"]["name"] == "uat-1" and out["keep_backups"] == 7 and out["seed_content"] is True
    assert out["first_admin"]["status"] == "pending" and PASSWORD not in r.text
    event = next(e for e in await actions() if e.action == "instance.create" and e.target_id == out["id"])
    assert event.details == {"seed_snapshot": "uat-1", "first_admin": {"emails": {"email": "ada@example.com"},
                                                                         "mode": "password"}}
    # While it starts from the snapshot, changing its branch or the snapshot needs data:reset.
    r = await writer.patch(f"/api/v1/instances/{out['id']}", json={"branch": "next"})
    assert r.status_code == 403 and r.json()["detail"] == (
        "UAT two starts from snapshot uat-1; changing what code receives it needs data:reset")
    assert (await writer.patch(f"/api/v1/instances/{out['id']}", json={"keep_backups": 3})).status_code == 200
    r = await c["maintainer"].patch(f"/api/v1/instances/{out['id']}", json={"seed_snapshot_id": None})
    assert r.status_code == 200 and r.json()["seed_snapshot"] is None
    # Once live, a snapshot is for Reset data.
    live = await seed(name="live")
    r = await c["maintainer"].patch(f"/api/v1/instances/{live}", json={"seed_snapshot_id": str(sid)})
    assert r.status_code == 409 and r.json()["detail"] == "live has gone live; use Reset data to start it from a snapshot"


# ------------------------------------------------------------------------------------------- audit


async def test_audit_records_hold_no_secret(make_client, monkeypatch, storage):
    c = await clients(make_client)
    github_serving(monkeypatch, {"slipway.yml": SHOP_YML})
    iid = await seed()
    old = backup_row(iid, identity={"FIELD_ENCRYPTION_KEY": KEY_B})
    await add(old)
    never = await seed(name="fresh", live=False)
    assert (await c["admin"].put(f"/api/v1/instances/{never}/first-admin", json=ADMIN)).status_code == 200
    r = await c["admin"].post(f"/api/v1/instances/{iid}/data/restore",
                              json={"backup_id": str(old.id), "confirm": "shop", "restore_identity": True})
    assert r.status_code == 202
    sid = await ready_snapshot(c["admin"], "uat-1")
    ticket = (await c["admin"].post(f"/api/v1/snapshots/{sid}/exports", json={"passphrase": PASSPHRASE})).json()
    exported = (await c["admin"].get(ticket["url"])).content
    locked = (await upload(c["admin"], exported, "again")).json()["id"]
    await c["admin"].post(f"/api/v1/snapshots/{locked}/unlock", json={"passphrase": "a wrong one, long enough"})
    await c["admin"].post(f"/api/v1/snapshots/{locked}/unlock", json={"passphrase": PASSPHRASE})
    await snapshots.wait_for_validations()
    await asyncio.sleep(0.05)  # the download's own audit record is written as its stream ends
    events = await actions()
    assert {"instance.first_admin", "instance.restore", "snapshot.upload", "snapshot.export", "snapshot.unlock",
            "snapshot.download"} <= {e.action for e in events}
    text = json.dumps([[e.summary, e.details] for e in events])
    for secret in (PASSWORD, PASSPHRASE, KEY_A, KEY_B, "a wrong one"):
        assert secret not in text


# -------------------------------------------------------------------------------------------- startup


async def test_startup_prepares_storage_and_sweeps_expired_imports(app, monkeypatch, storage):
    from slipway import main

    monkeypatch.setattr(main, "init_engine", lambda *a, **kw: None)  # keep the tests' engine

    async def keep_engine() -> None:
        return None

    monkeypatch.setattr(main, "dispose_engine", keep_engine)
    (storage / "incoming").mkdir(parents=True)
    (storage / "incoming" / "left-by-a-crash.partial").write_bytes(b"x")
    expired = Snapshot(name="never-unlocked", status="locked", origin="import", notes="",
                       expires_at=utcnow() - timedelta(days=1), import_keyblock={"kdf": "scrypt"})
    await add(expired)
    (storage / "bundles").mkdir()
    snapshots.bundle_path(expired.id).write_bytes(b"SLWSNAP1")
    async with main.lifespan(app):
        for _ in range(100):
            if await load(Snapshot, expired.id) is None:
                break
            await asyncio.sleep(0.02)
        assert not (storage / "incoming" / "left-by-a-crash.partial").exists()
        assert await load(Snapshot, expired.id) is None and not snapshots.bundle_path(expired.id).exists()
