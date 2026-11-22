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

    import httpx

    from slipway.api.v1 import instances as instances_api
    from slipway.services import deployer, github

    c = await clients(make_client)
    monkeypatch.setattr(instances_api, "open_session", connect_to(Shell()))
    # A first admin for an instance that never went live is checked against its branch's slipway.yml: a fake
    # GitHub that has none answers it, so the matrix never reaches api.github.com.
    asked: list[str] = []

    def no_such_file(request: httpx.Request) -> httpx.Response:
        asked.append(request.url.path)
        return httpx.Response(404, json={"message": "Not Found"})

    monkeypatch.setattr(github, "transport_factory", lambda: httpx.MockTransport(no_such_file))

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
    assert asked and all(path.endswith("/contents/slipway.yml") for path in asked), asked


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


# ------------------------------------------------------------- environments (phase 3 §11, test 52)

import pytest  # noqa: E402

from tests.test_env_api import (  # noqa: E402
    HOSTNAMES,
    _create_body,
    _fake_key,
    _update,
    cf,  # noqa: F401  (autouse: a FakeCloudflare)
    github,  # noqa: F401  (autouse: the repository's files)
    no_public_checks,  # noqa: F401  (autouse)
    sy,  # noqa: F401  (autouse: a FakeSwitchyard)
)
from tests.test_env_rules import T0, _failed_green, _job, _world  # noqa: E402


async def _settle(env_id) -> None:
    """Undo what an allowed request queued, so the next request meets the same environment."""
    from sqlalchemy import update

    from slipway.db.session import get_sessionmaker
    from slipway.models import Deployment, Environment

    async with get_sessionmaker()() as db:
        await db.execute(update(Deployment).where(Deployment.status.in_(["queued", "running"]))
                         .values(status="cancelled", finished_at=T0))
        await db.execute(update(Environment).where(Environment.id == env_id).values(status="live", deleted_at=None))
        await db.commit()


@pytest.mark.parametrize("role", ROLES)
async def test_environment_endpoints_by_role(make_client, role):
    """Every §11 endpoint against one built-in role: 403 for a role without the permission, anything else
    (the request runs, or is refused for another reason) for a role with it. One role per run, so each meets a
    fresh database."""
    from datetime import timedelta

    from slipway.db.session import get_sessionmaker
    from slipway.models import Environment

    c = await clients(make_client)
    ids = await _world()
    await _fake_key()
    await _update(Environment, ids["env"], hostnames=HOSTNAMES)
    async with get_sessionmaker()() as db:
        failed = await _failed_green(db, ids)
        activate = _job(None, ids["env"], "activate", "failed", at=T0 + timedelta(hours=2),
                        options={"slot": "green", "from_slot": "blue"})
        remove = _job(None, ids["env"], "remove_slot", "failed", at=T0 + timedelta(hours=2), options={"slot": "green"})
        teardown = _job(None, ids["env"], "teardown", "failed", at=T0 + timedelta(hours=2), options={"confirmed": True})
        done = _job(ids["green"], ids["env"], "deploy", "succeeded", at=T0 + timedelta(minutes=30),
                    options={"slot": "green"})
        db.add_all([activate, remove, teardown, done])
        await db.commit()
    e = f"/api/v1/environments/{ids['env']}"
    notice = {"text": "stopped", "at": T0.isoformat(), "deployment_id": done.id.hex,
              "next": {"kind": "activate", "slot": "green"}}
    endpoints = [
        # Roll back first: it needs the failed deploy to be the latest changing job, and data:reset on shared data.
        ("post", f"/api/v1/deployments/{failed.id}/rollback", {"confirm": "uat"}, {M, A}),
        ("get", "/api/v1/environments", None, {V, D, M, A}),
        ("post", "/api/v1/environments?check=true", _create_body(ids), {M, A}),
        ("post", "/api/v1/environments", _create_body(ids, name="uat"), {M, A}),
        ("get", e, None, {V, D, M, A}),
        ("patch", e, {"keep_backups": 4}, {M, A}),
        ("get", f"{e}/env", None, {M, A}),
        ("post", f"{e}/deploy", None, {D, M, A}),
        ("post", f"{e}/deploy", {"target": "data"}, {D, M, A}),
        ("post", f"{e}/activate", {"slot": "green"}, {D, M, A}),
        ("post", f"{e}/publish", None, {D, M, A}),
        ("post", f"{e}/discard", {"slot": "green"}, {D, M, A}),
        ("post", f"{e}/notice/continue", None, {D, M, A}),
        ("get", f"{e}/traffic/plan", None, {V, D, M, A}),
        ("get", f"{e}/traffic/plan?slot=green", None, {V, D, M, A}),
        ("post", f"{e}/traffic/resolve", {"confirm": "uat"}, {D, M, A}),
        ("get", f"{e}/dns", None, {V, D, M, A}),
        ("post", f"{e}/dns/claim", {"hostname": "api.uat.example.com"}, {D, M, A}),
        ("post", f"{e}/slots", {"host_id": str(ids["host_green"])}, {M, A}),
        ("delete", f"{e}/slots/green", {"confirm": "uat"}, {M, A}),
        ("delete", e, {"confirm": "uat"}, {M, A}),
        ("delete", e, {"confirm": "uat", "snapshot": {"name": "matrix-snap"}}, {M, A}),
        ("get", f"{e}/deployments", None, {V, D, M, A}),
        ("get", "/api/v1/settings/cloudflare", None, {A}),
        ("put", "/api/v1/settings/cloudflare", {"zone": "example.com"}, {A}),
        ("post", "/api/v1/settings/cloudflare/test", None, {A}),
        ("put", "/api/v1/settings/switchyard", {"url": "https://sy.example.test", "traffic_address": "10.0.0.2"}, {A}),
        ("post", f"/api/v1/deployments/{activate.id}/retry", None, {D, M, A}),
        ("post", f"/api/v1/deployments/{remove.id}/retry", {"confirm": "uat"}, {M, A}),
        ("post", f"/api/v1/deployments/{teardown.id}/retry", {"confirm": "uat"}, {M, A}),
        ("get", f"/api/v1/deployments?environment={ids['env']}", None, {V, D, M, A}),
        ("get", f"/api/v1/deployments/{activate.id}", None, {V, D, M, A}),
    ]
    for method, url, body, allowed in endpoints:
        await _update(Environment, ids["env"], notice=notice)
        kw = {"json": body} if body is not None else {}
        r = await c[role].request(method.upper(), url, **kw)
        if role in allowed:
            assert r.status_code != 403, (role, method, url, r.text)
        else:
            assert r.status_code == 403, (role, method, url, r.status_code, r.text)
        await _settle(ids["env"])


async def test_environment_conditional_permissions(make_client):
    """Permissions an environment request needs because of what it asks for (§4.1): a deploy that goes live by
    itself (traffic:switch), a seed snapshot (data:reset), another repository's snapshot (snapshots:download),
    a delete that takes a snapshot first (data:backup) and Add a slot that updates the data server
    (deployments:create)."""
    import uuid

    from slipway.db.session import get_sessionmaker
    from slipway.models import Environment, Snapshot
    from tests.test_data_api import client_with
    from tests.test_env_rules import MAN

    c = await clients(make_client)
    ids = await _world(active=None, status="new")
    e = f"/api/v1/environments/{ids['env']}"
    deployer_only = await client_with(make_client, "deployer@example.com",
                                      ["environments:read", "deployments:create"])
    # Nothing is live: the deploy goes live by itself, which takes traffic:switch.
    r = await deployer_only.post(f"{e}/deploy")
    assert r.status_code == 403 and "traffic:switch" in r.json()["detail"]
    r = await c["developer"].post(f"{e}/deploy")
    assert r.status_code == 202 and r.json()["options"]["go_live"] is True, r.text
    await _settle(ids["env"])
    await _update(Environment, ids["env"], status="new")

    async with get_sessionmaker()() as db:
        same = Snapshot(id=uuid.uuid4(), name="same-repo", status="ready", origin="instance", app=MAN.data.app,
                        repository="acme/serversherpa", file_sha256="a" * 64, db_sha256="b" * 64)
        other = Snapshot(id=uuid.uuid4(), name="other-repo", status="ready", origin="instance", app=MAN.data.app,
                         repository="acme/other", file_sha256="c" * 64, db_sha256="d" * 64)
        db.add_all([same, other])
        await db.commit()
    writer = await client_with(make_client, "writer@example.com", ["environments:read", "environments:write"])
    body = _create_body(ids, first_admin=None, seed_snapshot_id=str(same.id))
    r = await writer.post("/api/v1/environments?check=true", json=body)
    assert r.status_code == 403
    assert r.json() == {"detail": "Starting from a snapshot needs the data:reset permission", "field": "seed_snapshot_id"}
    r = await c["maintainer"].post("/api/v1/environments?check=true", json=body)
    assert r.status_code == 200, r.text
    body = _create_body(ids, first_admin=None, seed_snapshot_id=str(other.id))
    r = await c["maintainer"].post("/api/v1/environments?check=true", json=body)
    assert r.status_code == 403 and "snapshots:download" in r.json()["detail"]
    r = await c["admin"].post("/api/v1/environments?check=true", json=body)
    assert r.status_code == 200, r.text

    deleter = await client_with(make_client, "deleter@example.com", ["environments:read", "environments:delete"])
    r = await deleter.request("DELETE", e, json={"confirm": "uat", "snapshot": {"name": "before"}})
    assert r.status_code == 403 and "data:backup" in r.json()["detail"]
    r = await deleter.request("DELETE", e, json={"confirm": "uat"})
    assert r.status_code == 202 and r.json()["kind"] == "teardown"
    await _settle(ids["env"])

    adder = await client_with(make_client, "adder@example.com", ["environments:read", "environments:write"])
    r = await adder.post(f"{e}/slots", json={"host_id": str(ids["host_green"]), "update_data_server": True})
    assert r.status_code == 403 and "deployments:create" in r.json()["detail"]


# ------------------------------------------------------------------ phase 4 test 22, phase 5 §4.1: providers and machines


PROVIDER_PERMS = ["providers:read", "providers:write", "providers:spend", "machines:write"]
PROVIDER_ROLES = {
    "viewer": [],
    "developer": ["providers:read"],
    "maintainer": ["providers:read", "providers:spend", "machines:write"],
    "admin": PROVIDER_PERMS,
}


async def _provider_grants() -> dict[str, list[str]]:
    from sqlalchemy import select

    from slipway.core.permissions import has_permission
    from slipway.db.session import get_sessionmaker
    from slipway.models import Role

    async with get_sessionmaker()() as db:
        roles = {r.name: set(r.permissions) for r in (await db.scalars(select(Role))).all()}
    return {name: [p for p in PROVIDER_PERMS if has_permission(roles[name], p)] for name in PROVIDER_ROLES}


async def test_roles_hold_the_provider_and_machine_permissions():
    from sqlalchemy import select

    from slipway.core.permissions import ALL_PERMISSIONS, PERMISSION_DESCRIPTIONS, SYSTEM_ROLES, Perm
    from slipway.db.session import get_sessionmaker
    from slipway.models import Role
    from slipway.services.users import bootstrap

    assert set(PROVIDER_PERMS) <= set(ALL_PERMISSIONS)
    assert set(PERMISSION_DESCRIPTIONS) == set(Perm)  # every permission, the new ones included, says what it allows
    assert "never tokens" in PERMISSION_DESCRIPTIONS[Perm.PROVIDERS_READ]
    # Only admin writes accounts; viewers see none of it.
    for name, spec in SYSTEM_ROLES.items():
        held = {str(p) for p in spec["permissions"]}
        assert ("providers:write" in held) is False or name == "admin", name
    assert await _provider_grants() == PROVIDER_ROLES  # a fresh install (conftest bootstraps)

    # An install bootstrapped before phases 4 and 5: the next start gives its roles the new permissions.
    async with get_sessionmaker()() as db:
        for role in (await db.scalars(select(Role))).all():
            if role.name != "admin":
                role.permissions = [p for p in role.permissions if p not in PROVIDER_PERMS]
        await db.commit()
    assert (await _provider_grants())["maintainer"] == []
    async with get_sessionmaker()() as db:
        await bootstrap(db)
        await db.commit()
    assert await _provider_grants() == PROVIDER_ROLES
