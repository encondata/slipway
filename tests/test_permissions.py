from tests.conftest import login, make_user

HOST = {"name": "prod-01", "hostname": "10.0.1.12", "username": "deploy"}


async def test_viewer_is_read_only(make_client):
    await make_user("admin@example.com")
    await make_user("viewer@example.com", roles=["viewer"])
    viewer = make_client()
    await login(viewer, "viewer@example.com")
    assert (await viewer.get("/api/v1/hosts")).status_code == 200
    r = await viewer.post("/api/v1/hosts", json=HOST)
    assert r.status_code == 403 and "hosts:write" in r.json()["detail"]
    assert (await viewer.get("/api/v1/users")).status_code == 403


async def test_maintainer_manages_hosts_not_users(make_client):
    await make_user("admin@example.com")
    await make_user("m@example.com", roles=["maintainer"])
    m = make_client()
    await login(m, "m@example.com")
    assert (await m.post("/api/v1/hosts", json=HOST)).status_code == 201
    assert (await m.get("/api/v1/users")).status_code == 200  # users:read
    r = await m.post("/api/v1/users", json={"email": "x@example.com", "password": "long-enough-pw"})
    assert r.status_code == 403


async def test_cannot_grant_roles_beyond_own_permissions(admin_client, make_client):
    # A custom role that can manage users but holds nothing else.
    r = await admin_client.post(
        "/api/v1/roles", json={"name": "user-manager", "permissions": ["users:read", "users:write", "roles:read"]}
    )
    assert r.status_code == 201
    await make_user("um@example.com", roles=["user-manager"])
    um = make_client()
    await login(um, "um@example.com")

    r = await um.post("/api/v1/users", json={"email": "evil@example.com", "password": "long-enough-pw", "roles": ["admin"]})
    assert r.status_code == 403
    r = await um.post("/api/v1/users", json={"email": "ok@example.com", "password": "long-enough-pw", "roles": ["user-manager"]})
    assert r.status_code == 201


async def test_last_admin_is_protected(admin_client):
    me = (await admin_client.get("/api/v1/auth/me")).json()["user"]
    r = await admin_client.patch(f"/api/v1/users/{me['id']}", json={"roles": ["viewer"]})
    assert r.status_code == 400 and "last active admin" in r.json()["detail"]
    r = await admin_client.patch(f"/api/v1/users/{me['id']}", json={"is_active": False})
    assert r.status_code == 400


async def test_deactivated_user_is_signed_out(admin_client, make_client):
    user = await make_user("dev@example.com", roles=["developer"])
    dev = make_client()
    await login(dev, "dev@example.com")
    r = await admin_client.patch(f"/api/v1/users/{user.id}", json={"is_active": False})
    assert r.status_code == 200
    assert (await dev.get("/api/v1/auth/me")).status_code == 401
    r = await dev.post("/api/v1/auth/login", json={"email": "dev@example.com", "password": "correct-horse-battery"})
    assert r.status_code == 401


async def test_builtin_roles_are_read_only(admin_client):
    roles = (await admin_client.get("/api/v1/roles")).json()
    admin = next(r for r in roles if r["name"] == "admin")
    assert (await admin_client.patch(f"/api/v1/roles/{admin['id']}", json={"permissions": []})).status_code == 400
    assert (await admin_client.delete(f"/api/v1/roles/{admin['id']}")).status_code == 400


async def test_unknown_permission_rejected(admin_client):
    r = await admin_client.post("/api/v1/roles", json={"name": "bad", "permissions": ["hosts:destroy"]})
    assert r.status_code == 422


async def test_audit_log_records_actions(admin_client):
    await admin_client.post("/api/v1/hosts", json=HOST)
    events = (await admin_client.get("/api/v1/audit")).json()
    actions = [e["action"] for e in events]
    assert "host.create" in actions and "auth.login" in actions


# ------------------------------------------------------------------------- data endpoints (spec §13, §14.1)

from tests.test_data_api import (  # noqa: E402
    ADMIN,
    PASSPHRASE,
    KEY_B,
    Shell,
    add,
    backup_row,
    clients,
    connect_to,
    job,
    plain_snapshot,
    ready_snapshot,
    seed,
    steps,
    storage,  # noqa: F401  (autouse: snapshots in this test's temp folder)
    submitted,  # noqa: F401  (autouse: jobs are queued, never run)
    upload,
)

ROLES = ("viewer", "developer", "maintainer", "admin")
V, D, M, A = ROLES


async def test_data_endpoints_by_role(make_client, monkeypatch, tmp_path):
    """Every data endpoint against the four built-in roles: 403 for a role without the permission, anything
    else (the request then runs, or is refused for another reason) for a role with it."""
    import uuid

    from slipway.api.v1 import instances as instances_api
    from slipway.services import deployer

    c = await clients(make_client)
    monkeypatch.setattr(instances_api, "open_session", connect_to(Shell()))

    async def fake_run(instance, command, **kw):
        return ""

    monkeypatch.setattr(deployer, "run_on_instance", fake_run)
    iid = await seed(tmp_path)
    never = await seed(tmp_path, name="fresh", live=False)
    row = backup_row(iid)
    await add(row)
    failed = await job(iid, "deploy", "failed", steps=steps(start="failed"))
    restore = await job(iid, "restore", "failed", restore_backup_id=row.id, steps=steps(release="failed"))
    reset = await job(iid, "reset", "failed", steps=steps(release="failed"))
    sid = await ready_snapshot(c["admin"], "matrix-1")
    i, s = f"/api/v1/instances/{iid}", f"/api/v1/snapshots/{sid}"
    endpoints = [
        ("get", f"{i}/backups", None, {V, D, M, A}),
        ("get", f"{i}/backups?check=true", None, {V, D, M, A}),
        ("post", f"{i}/backups", {}, {D, M, A}),
        ("delete", f"{i}/backups/{uuid.uuid4()}", None, {M, A}),
        ("post", f"{i}/data/restore", {"backup_id": str(row.id), "confirm": "shop"}, {D, M, A}),
        ("post", f"{i}/data/restore", {"backup_id": str(row.id), "confirm": "shop", "restore_identity": True}, {M, A}),
        ("post", f"{i}/data/reset", {"confirm": "shop", "first_admin": ADMIN}, {M, A}),
        ("post", f"/api/v1/instances/{never}/data/start-over", {"confirm": "fresh"}, {M, A}),
        ("post", f"{i}/snapshots", {"name": "x-1"}, {D, M, A}),
        ("post", f"{i}/snapshots", {"name": "x-2", "stop_app": True}, {D, M, A}),  # developers may operate
        ("get", f"{i}/first-admin", None, {V, D, M, A}),
        ("put", f"/api/v1/instances/{never}/first-admin", ADMIN, {M, A}),  # never live: instances:write
        ("put", f"{i}/first-admin", {**ADMIN, "confirm": "shop"}, {M, A}),  # live: data:reset
        ("delete", f"/api/v1/instances/{never}/first-admin", None, {M, A}),
        ("post", f"{i}/first-admin/run", None, {D, M, A}),
        ("post", f"{i}/content/run", None, {D, M, A}),
        ("post", f"{i}/deploy", None, {D, M, A}),
        ("post", f"{i}/deploy", {"override_hold": True, "confirm": "shop"}, {M, A}),
        ("post", f"{i}/deploy", {"take_over_lock": True, "confirm": "shop"}, {M, A}),
        ("post", f"{i}/deploy", {"skip_revision_check": True, "confirm": "shop"}, {D, M, A}),
        ("post", f"{i}/actions/restart", None, {D, M, A}),
        ("post", f"{i}/actions/restart", {"override_hold": True, "confirm": "shop"}, {M, A}),
        ("patch", f"{i}", {"keep_backups": 4}, {M, A}),
        ("post", f"/api/v1/deployments/{failed.id}/retry", None, {D, M, A}),
        ("post", f"/api/v1/deployments/{failed.id}/retry", {"take_over_lock": True, "confirm": "shop"}, {M, A}),
        ("post", f"/api/v1/deployments/{restore.id}/retry", {"confirm": "shop"}, {D, M, A}),
        ("post", f"/api/v1/deployments/{reset.id}/retry", {"confirm": "shop"}, {M, A}),
        ("post", f"/api/v1/deployments/{failed.id}/rollback", {"confirm": "shop"}, {D, M, A}),
        ("get", f"/api/v1/deployments/{failed.id}", None, {V, D, M, A}),
        ("get", "/api/v1/snapshots", None, {V, D, M, A}),
        ("get", s, None, {V, D, M, A}),
        ("post", f"{s}/unlock", {"passphrase": PASSPHRASE}, {M, A}),
        ("patch", s, {"notes": "n"}, {D, M, A}),
        ("post", f"{s}/exports", {"passphrase": PASSPHRASE}, {A}),
        ("get", "/api/v1/snapshot-exports/not-a-token", None, {A}),
        ("delete", f"/api/v1/snapshots/{uuid.uuid4()}", None, {M, A}),
    ]
    for role in ROLES:
        for method, url, body, allowed in endpoints:
            kw = {"json": body} if body is not None else {}
            r = await getattr(c[role], method)(url, **kw)
            if role in allowed:
                assert r.status_code != 403, (role, method, url, r.text)
            else:
                assert r.status_code == 403, (role, method, url, r.status_code, r.text)
        r = await upload(c[role], plain_snapshot(), f"up-{role}")
        assert (r.status_code == 403) == (role not in (M, A)), (role, r.text)


async def test_conditional_data_permissions(make_client):
    """Permissions a request needs because of what it asks for (§13): putting back identity keys, seeding
    from another repository, a first admin on a live app and stopping the app for a snapshot."""
    from slipway.models import Role
    from slipway.db.session import get_sessionmaker

    c = await clients(make_client)
    async with get_sessionmaker()() as db:
        db.add(Role(name="backupper", description="", permissions=["instances:read", "data:backup"], is_system=False))
        await db.commit()
    await make_user("backupper@example.com", roles=["backupper"])
    c["backupper"] = make_client()
    await login(c["backupper"], "backupper@example.com")
    other = await ready_snapshot(c["admin"], "other-repo", repository="acme/other")
    for role, expected in (("developer", 403), ("maintainer", 202)):
        iid = await seed(name=f"keys-{role}")
        old = backup_row(iid, identity={"FIELD_ENCRYPTION_KEY": KEY_B})
        await add(old)
        r = await c[role].post(f"/api/v1/instances/{iid}/data/restore",
                               json={"backup_id": str(old.id), "confirm": f"keys-{role}", "restore_identity": True})
        assert r.status_code == expected, (role, r.text)
    for role, expected in (("maintainer", 403), ("admin", 202)):
        iid = await seed(name=f"seed-{role}")
        r = await c[role].post(f"/api/v1/instances/{iid}/data/reset",
                               json={"confirm": f"seed-{role}", "snapshot_id": str(other)})
        assert r.status_code == expected, (role, r.text)
    for role, expected in (("developer", 403), ("maintainer", 200)):
        iid = await seed(name=f"admin-{role}")
        r = await c[role].put(f"/api/v1/instances/{iid}/first-admin", json={**ADMIN, "confirm": f"admin-{role}"})
        assert r.status_code == expected, (role, r.text)
    iid = await seed(name="snap")
    r = await c["backupper"].post(f"/api/v1/instances/{iid}/snapshots", json={"name": "snap-1", "stop_app": True})
    assert r.status_code == 403 and "instances:operate" in r.json()["detail"]
    r = await c["developer"].post(f"/api/v1/instances/{iid}/snapshots", json={"name": "snap-1", "stop_app": True})
    assert r.status_code == 202 and r.json()["deployment"]["options"]["stop_app"] is True
    # Its retry stops the app too, so it needs instances:operate as well (review finding 36).
    import uuid

    from slipway.models import Deployment

    taken = r.json()["deployment"]["id"]
    async with get_sessionmaker()() as db:
        (await db.get(Deployment, uuid.UUID(taken))).status = "failed"
        db.add(Role(name="snapshotter", description="", is_system=False,
                    permissions=["instances:read", "deployments:create", "data:backup"]))
        await db.commit()
    await make_user("snapshotter@example.com", roles=["snapshotter"])
    snapshotter = make_client()
    await login(snapshotter, "snapshotter@example.com")
    r = await snapshotter.post(f"/api/v1/deployments/{taken}/retry")
    assert r.status_code == 403 and "instances:operate" in r.json()["detail"]
    r = await c["developer"].post(f"/api/v1/deployments/{taken}/retry")
    assert r.status_code == 202 and r.json()["options"]["stop_app"] is True
