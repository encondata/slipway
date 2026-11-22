"""Phase 2 end to end: each data job queued through the API (spec §13) and then run by the real deployer (§7).

test_data_api.py queues jobs without running them, and test_data_jobs.py runs jobs it builds itself. Here the job
the API queued (its kind, options, references and pre-built steps) is the one the deployer runs, so the options
the API writes and the ones the deployer reads must agree. The app and its host are test_data_jobs.py's: a shell
script whose database is a file, run through ShellRemote with the fake docker.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from sqlalchemy import select

from slipway.api.v1 import instances as instances_api
from slipway.core.config import get_settings
from slipway.core.crypto import reset_crypto_cache
from slipway.db.session import get_sessionmaker
from slipway.models import Backup, Deployment, FirstAdmin, Snapshot
from slipway.services import deployer, snapfile, snapshots
from tests.conftest import login, make_user
from tests.test_data_api import connect_to, github_serving
from tests.test_data_jobs import DF_SHIM, App, DataGitHub, _fernet, _get, _steps
from tests.test_deployer import SHA
from tests.test_final_remote import _local, docker_shim  # noqa: F401

NAME = "web"  # the instance App.seed creates, and the typed confirmation


@pytest.fixture(autouse=True)
async def storage(tmp_path) -> AsyncIterator[Path]:
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


@pytest.fixture
def host(tmp_path, docker_shim, monkeypatch):  # noqa: F811
    env, _ = docker_shim
    df = Path(env["PATH"].split(":")[0]) / "df"
    df.write_text(DF_SHIM)
    df.chmod(0o755)
    app = App(tmp_path, env)
    app.env["FAKE_VOLUME_FILE"] = str(tmp_path / "volumes")  # the database lives in a labelled volume
    # GET /backups?check=true and backup deletion reach the same "host".
    monkeypatch.setattr(instances_api, "open_session", connect_to(app.remote))
    return app


@pytest.fixture
def queued(monkeypatch) -> list[uuid.UUID]:
    jobs: list[uuid.UUID] = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, inst_id: jobs.append(dep_id))
    return jobs


async def _run(host: App, queued: list[uuid.UUID], resp) -> Deployment:
    """Run the job the API just queued with the real deployer, and return it finished."""
    assert resp.status_code in (201, 202), resp.text
    dep_id = queued.pop()
    body = resp.json()
    assert uuid.UUID((body.get("deployment") or body)["id"]) == dep_id
    await deployer.run_deployment(dep_id, connect=_local(host.remote), github=DataGitHub)
    return await _get(Deployment, dep_id)


async def test_every_data_job_runs_as_the_api_queued_it(make_client, host, queued, tmp_path):
    await make_user("admin@example.com")  # the first user is the admin
    client = make_client()
    await login(client, "admin@example.com")
    await host.seed()
    iid = host.instance_id
    api = f"/api/v1/instances/{iid}"

    first = await host.deploy()
    assert first.status == "succeeded", (first.error, first.log)
    (host.state / "rev").write_text("rev-1\n")

    # Back up now, with its note on the backup row.
    dep = await _run(host, queued, await client.post(f"{api}/backups", json={"note": "before the e2e run"}))
    assert dep.kind == "backup" and dep.status == "succeeded", (dep.error, dep.log)
    [manual] = await host.backups_rows()
    assert manual.reason == "manual" and manual.status == "ready" and manual.note == "before the e2e run"
    listed = (await client.get(f"{api}/backups?check=true")).json()
    [out] = listed["backups"]
    assert out["id"] == str(manual.id) and out["restorable"] is True and out["note"] == "before the e2e run"
    assert out["checked_at"] is not None

    # Restore it over changed data.
    (host.state / "db").write_text("CHANGED\n")
    dep = await _run(host, queued, await client.post(f"{api}/data/restore",
                                                     json={"backup_id": str(manual.id), "confirm": NAME}))
    assert dep.kind == "restore" and dep.status == "succeeded", (dep.error, dep.log)
    assert (host.state / "db").read_text().startswith("MIGRATED\n")
    assert "CHANGED" not in (host.state / "db").read_text()
    detail = (await client.get(f"/api/v1/deployments/{dep.id}")).json()
    assert detail["actions"]["undo"]["available"] is True

    # A failed deploy, then Roll back from its page.
    flag = tmp_path / "fail"
    flag.write_text("")
    host.env["FAIL_FLAG"] = str(flag)
    failed = await _run(host, queued, await client.post(f"{api}/deploy"))
    assert failed.status == "failed" and _steps(failed)["backup"] == "succeeded"
    flag.unlink()
    detail = (await client.get(f"/api/v1/deployments/{failed.id}")).json()
    assert detail["actions"]["rollback"]["available"] is True, detail["actions"]
    dep = await _run(host, queued, await client.post(f"/api/v1/deployments/{failed.id}/rollback",
                                                     json={"confirm": NAME}))
    assert dep.kind == "rollback" and dep.status == "succeeded", (dep.error, dep.log)
    assert dep.restore_backup_id == failed.backup_id
    assert (await host.instance()).data_dirty is None

    # A restore that fails part-way holds the data; Deploy is refused; the retry inherits its backup and finishes.
    host.env["RESTORE_FAIL"] = "1"
    held = await _run(host, queued, await client.post(f"{api}/data/restore",
                                                      json={"backup_id": str(manual.id), "confirm": NAME}))
    assert held.status == "failed" and (await host.instance()).data_dirty["hold"] is True
    resp = await client.post(f"{api}/deploy")
    assert resp.status_code == 409 and "stopped part-way" in resp.json()["detail"]
    host.env.pop("RESTORE_FAIL")
    assert (await client.post(f"/api/v1/deployments/{held.id}/retry", json={})).status_code == 422  # typed name
    dep = await _run(host, queued, await client.post(f"/api/v1/deployments/{held.id}/retry", json={"confirm": NAME}))
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert dep.kind == "restore" and dep.options.get("inherit") is True and dep.backup_id == held.backup_id
    assert _steps(dep)["backup"] == "skipped"
    assert (await host.instance()).data_dirty is None

    # Take a snapshot; it ends ready on this Slipway.
    resp = await client.post(f"{api}/snapshots", json={"name": "e2e-snap"})
    dep = await _run(host, queued, resp)
    assert dep.kind == "snapshot" and dep.status == "succeeded", (dep.error, dep.log)
    snap = await _get(Snapshot, uuid.UUID(resp.json()["snapshot"]["id"]))
    assert snap.status == "ready" and snap.repository == "acme/web" and snapshots.bundle_path(snap.id).is_file()

    # Reset from that snapshot, then reset to empty with a first admin.
    (host.state / "db").write_text("LATER\n")
    dep = await _run(host, queued, await client.post(f"{api}/data/reset",
                                                     json={"confirm": NAME, "snapshot_id": str(snap.id)}))
    assert dep.kind == "reset" and dep.status == "succeeded", (dep.error, dep.log)
    assert dep.snapshot_id == snap.id and "LATER" not in (host.state / "db").read_text()
    admin = {"fields": {"email": "ada@example.com", "name": "Ada Lovelace"}, "mode": "password",
             "password": "correct-horse-9"}
    dep = await _run(host, queued, await client.post(f"{api}/data/reset",
                                                     json={"confirm": NAME, "first_admin": admin, "seed": True}))
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert _steps(dep)["first_admin"] == "succeeded" and _steps(dep)["seed"] == "succeeded"
    assert (host.state / "db").read_text() == "MIGRATED\nSEEDED\n"
    async with get_sessionmaker()() as db:
        row = await db.scalar(select(FirstAdmin).where(FirstAdmin.instance_id == iid))
        reasons = [b.reason for b in (await db.scalars(select(Backup).where(Backup.instance_id == iid))).all()]
    assert row.status == "done" and row.password is None
    assert "correct-horse-9" not in dep.log
    assert {"manual", "pre_restore", "pre_deploy", "pre_rollback", "pre_reset"} <= set(reasons)
    assert (await host.instance()).status == "running"
    # The pages render what these jobs left.
    for page in (f"/instances/{iid}", f"/deployments/{dep.id}", f"/deployments/{failed.id}", f"/deployments/{held.id}",
                 "/snapshots", "/deployments", "/"):
        resp = await client.get(page)
        assert resp.status_code == 200, (page, resp.text[:500])
    page = (await client.get(f"/instances/{iid}")).text
    assert "Back up now" in page and "before the e2e run" in page and "e2e-snap" in page
    listing = (await client.get("/deployments")).text
    assert "Reset data" in listing and "Roll back" in listing


def _plain_snapshot(identity: dict[str, str]) -> bytes:
    """A snapshot file as `slipway snapshot pack` writes it unencrypted: the demo app's database and its key."""
    database = b"DB:\nFROM-SNAP\n"
    man = snapfile.build_manifest(
        app="demo", app_name="Demo", source="uat", repository="acme/web", commit=SHA, notes="",
        database={"format": "demo-v1", "revision": None, "bytes": len(database),
                  "sha256": hashlib.sha256(database).hexdigest()},
        files=None, identity=identity, producer="slipway test")
    out = io.BytesIO()
    snapfile.write_tar(out, man, identity=identity, database=io.BytesIO(database), files=None)
    return out.getvalue()


async def test_a_new_instance_starts_from_an_uploaded_snapshot_after_a_start_over(make_client, host, queued, tmp_path,
                                                                                  monkeypatch):
    await make_user("admin@example.com")
    client = make_client()
    await login(client, "admin@example.com")
    github_serving(monkeypatch, DataGitHub.files)  # the never-live instance's checks read the branch's slipway.yml
    await host.seed()
    iid = host.instance_id
    api = f"/api/v1/instances/{iid}"

    key = _fernet()
    resp = await client.post("/api/v1/snapshots/upload?name=uat-1", content=_plain_snapshot({"APP_KEY": key}),
                             headers={"Content-Type": "application/octet-stream"})
    assert resp.status_code == 201 and resp.json()["status"] == "ready", resp.text
    sid = resp.json()["id"]
    resp = await client.patch(api, json={"seed_snapshot_id": sid})
    assert resp.status_code == 200 and resp.json()["seed_snapshot"]["name"] == "uat-1", resp.text
    admin = {"fields": {"email": "ada@example.com", "name": "Ada Lovelace"}, "mode": "password",
             "password": "correct-horse-9"}
    assert (await client.put(f"{api}/first-admin", json=admin)).status_code == 200

    # The first deploy fails part-way, after the snapshot was restored.
    flag = tmp_path / "fail"
    flag.write_text("")
    host.env["FAIL_FLAG"] = str(flag)
    failed = await _run(host, queued, await client.post(f"{api}/deploy"))
    assert failed.status == "failed" and failed.snapshot_id == uuid.UUID(sid), (failed.error, failed.log)
    assert _steps(failed)["restore"] == "succeeded"

    # Start over removes what it left, after backing it up; the next deploy starts from the snapshot again.
    dep = await _run(host, queued, await client.post(f"{api}/data/start-over", json={"confirm": NAME}))
    assert dep.kind == "reset" and dep.status == "succeeded", (dep.error, dep.log)
    assert dep.options.get("start_over") is True and list(_steps(dep)) == ["release", "backup", "stop", "reset"]
    flag.unlink()
    assert (await client.put(f"{api}/first-admin", json=admin)).status_code == 200  # its password again
    dep = await _run(host, queued, await client.post(f"{api}/deploy"))
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert dep.snapshot_id == uuid.UUID(sid) and _steps(dep)["restore"] == "succeeded"
    assert (host.state / "db").read_text().startswith("FROM-SNAP\n")
    assert (host.state / "keys").read_text().strip() == key and key not in dep.log
    inst = await host.instance()
    assert inst.live_identity == {"APP_KEY": key} and inst.seed_snapshot_id is None and inst.status == "running"
    out = (await client.get(f"{api}/first-admin")).json()
    assert out["status"] == "done" and "correct-horse-9" not in json.dumps(out)
    # Nothing is pending now: Create it now and Add starter content are refused.
    assert (await client.post(f"{api}/first-admin/run")).status_code == 409
    assert (await client.post(f"{api}/content/run")).status_code == 409
    # The snapshot is in use as this instance's seed no more, so it can be deleted.
    assert (await client.delete(f"/api/v1/snapshots/{sid}")).status_code == 204
