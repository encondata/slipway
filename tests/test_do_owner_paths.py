"""The host-less owner and the not-built instance answers (S14a): P4 test 80's instance and recovery half and
P4 test 63's control-action half.

A DigitalOcean environment (``tests/do_fixtures.make_do_env``) has a planned droplet host per app slot and a
data owner with no host (``instances.host_id`` NULL, P4 §3.4). Every instance API on that owner answers 409 or a
skip, recovery and the poller pass over it, and a start, stop or restart of a slot whose droplet isn't built
answers 409 with ``HostNotBuilt``'s text. Nothing raises AttributeError, and nothing answers 500.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest
from sqlalchemy import select, update

from slipway.db.session import get_sessionmaker
from slipway.models import Backup, Deployment, Environment, Host, Instance
from slipway.services import data, deployer, environments, hosts, ssh, traffic
from tests import do_fixtures as dof

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")

NO_RUNNER = "shop has no slot that can run its data commands: deploy to blue first"
HOSTLESS = "shop's data is in its managed database, so it has no server of its own: manage it from shop's page"
NOT_BUILT = "slipway-shop-blue isn't built yet: deploy shop to build it"
BACKUP_NAME = "20261116T090000Z-0a1b2c3d"


async def owner_backup(env: dof.DoEnv, *, status: str = "ready") -> uuid.UUID:
    """A backup row of the owner, as S14b's data runner will leave one on Slipway."""
    async with get_sessionmaker()() as db:
        row = Backup(instance_id=env.ids["data"], name=BACKUP_NAME, reason="manual", status=status,
                     format="pg-custom", db_bytes=10 if status == "ready" else None, identity_fp="x" * 64,
                     taken_at=dt.datetime(2026, 11, 16, 9, tzinfo=dt.UTC), location="slipway", data_key="k" * 44)
        db.add(row)
        await db.commit()
        return row.id


async def loaded(instance_id: uuid.UUID) -> tuple[Any, Instance, Environment, dict[str, Instance]]:
    db = get_sessionmaker()()
    instance = await db.get(Instance, instance_id)
    env = await db.get(Environment, instance.environment_id)
    mem = await environments.members(db, env)
    return db, instance, env, mem


def route_of(follows: str) -> traffic.Route:
    return traffic.Route(hostname="api.shop.example.com", service="api", container=8000, follows=follows,
                         tls_mode="auto", health="/healthz")


async def set_rows(model: Any, ident: uuid.UUID, **values: Any) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(update(model).where(model.id == ident).values(**values))
        await db.commit()


async def built(env: dof.DoEnv, slot: str) -> None:
    """The slot's droplet host as prepare leaves it: built and pinned."""
    async with get_sessionmaker()() as db:
        host = await db.get(Host, env.host_ids[slot])
        _private, public = ssh.generate_keypair("root@droplet")
        host.host_key = public
        host.hostname = "203.0.113.10"
        hosts.set_phase(host, hosts.PHASE_READY, size="s-1vcpu-1gb", droplet_name=host.name)
        await db.commit()


# ------------------------------------------------------------------------------- the instance API (test 80)


async def test_80_lists_leave_out_the_host_less_owner(admin_client):
    env = await dof.make_do_env()
    resp = await admin_client.get("/api/v1/instances")
    assert resp.status_code == 200, resp.text
    ids = {row["id"] for row in resp.json()}
    assert str(env.ids["blue"]) in ids and str(env.ids["green"]) in ids
    assert str(env.ids["data"]) not in ids
    async with get_sessionmaker()() as db:
        repo_id = (await db.get(Instance, env.ids["blue"])).repository_id
    resp = await admin_client.get("/api/v1/instances", params={"repository_id": str(repo_id)})
    assert {row["id"] for row in resp.json()} == {str(env.ids["blue"]), str(env.ids["green"])}


# (method, path under the owner, body, expected status, expected detail or None). GET, PATCH and the delete of
# a Slipway-kept backup answer on the owner since S20: test_80_get_patch_and_backup_delete_answer_on_the_owner.
OWNER_CALLS: list[tuple[str, str, dict[str, Any] | None, int, str | None]] = [
    ("DELETE", "", None, 409, "Delete shop instead"),
    ("POST", "/proxy/sync", None, 409, "shop's names are published by the environment"),
    ("POST", "/deploy", None, 409, "Deploy shop from its page: Slipway picks the slot"),
    ("POST", "/actions/start", None, 409, HOSTLESS),
    ("POST", "/actions/stop", None, 409, HOSTLESS),
    ("POST", "/actions/restart", None, 409, HOSTLESS),
    ("GET", "/containers", None, 409, HOSTLESS),
    ("GET", "/logs", None, 409, HOSTLESS),
    ("POST", "/backups", None, 409, NO_RUNNER),
    ("POST", "/data/restore", {"backup_id": "{backup}", "confirm": "shop"}, 409, NO_RUNNER),
    ("POST", "/data/reset", {"confirm": "shop"}, 409, NO_RUNNER),
    ("POST", "/data/start-over", {"confirm": "shop"}, 409, NO_RUNNER),
    ("POST", "/snapshots", {"name": "shop-before"}, 409, NO_RUNNER),
    ("POST", "/first-admin/run", None, 409, "No app slot of shop has been deployed yet: deploy one first"),
    ("POST", "/content/run", None, 409, "No app slot of shop has been deployed yet: deploy one first"),
]


@pytest.mark.parametrize(("method", "path", "body", "code", "detail"), OWNER_CALLS,
                         ids=[f"{m} {p or '/'}" for m, p, *_ in OWNER_CALLS])
async def test_80_every_instance_api_on_the_owner_answers_409(admin_client, method, path, body, code, detail):
    env = await dof.make_do_env()
    backup = await owner_backup(env)
    url = f"/api/v1/instances/{env.ids['data']}{path}".replace("{backup}", str(backup))
    if body is not None:
        body = {k: (str(backup) if v == "{backup}" else v) for k, v in body.items()}
    resp = await admin_client.request(method, url, json=body)
    assert resp.status_code == code, resp.text
    if detail is not None:
        assert resp.json()["detail"] == detail
    # Nothing was queued, and the backup is still recorded.
    async with get_sessionmaker()() as db:
        assert (await db.scalars(select(Deployment.id))).all() == []
        assert await db.get(Backup, backup) is not None


async def test_80_get_patch_and_backup_delete_answer_on_the_owner(admin_client):
    env = await dof.make_do_env()
    backup = await owner_backup(env)
    owner = f"/api/v1/instances/{env.ids['data']}"
    resp = await admin_client.get(owner)
    assert resp.status_code == 200, resp.text
    assert resp.json()["host"] is None and resp.json()["host_id"] is None
    resp = await admin_client.patch(owner, json={"name": "shop data"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["name"] == "shop data" and resp.json()["host"] is None
    # A backup kept on Slipway is deleted with its files and its row, with no SSH.
    resp = await admin_client.delete(f"{owner}/backups/{backup}")
    assert resp.status_code == 204, resp.text
    async with get_sessionmaker()() as db:
        assert (await db.scalars(select(Deployment.id))).all() == []
        assert await db.get(Backup, backup) is None


async def test_80_reads_that_need_no_host_answer_on_the_owner(admin_client):
    env = await dof.make_do_env()
    await owner_backup(env)
    owner = f"/api/v1/instances/{env.ids['data']}"
    assert (await admin_client.get(f"{owner}/env")).json() == {}
    assert (await admin_client.get(f"{owner}/deployments")).json() == []
    assert (await admin_client.get(f"{owner}/first-admin")).status_code == 404
    assert (await admin_client.delete(f"{owner}/first-admin")).status_code == 404
    for params in ({}, {"check": "true"}):
        resp = await admin_client.get(f"{owner}/backups", params=params)
        assert resp.status_code == 200, resp.text
        out = resp.json()
        assert out["folder"] is None and out["ram_backed"] is False and out["other_files"] is None
        assert [b["name"] for b in out["backups"]] == [BACKUP_NAME]
        assert out["backups"][0]["restorable"] is False
        assert out["backups"][0]["reason_text"] == "Deploy the instance first"
    # An app slot of a managed environment shares the owner's data: its data endpoints say where it lives.
    resp = await admin_client.get(f"/api/v1/instances/{env.ids['blue']}/backups")
    assert resp.status_code == 409
    assert resp.json()["detail"] == ("shop's data is shared by its slots and lives in its managed database: back "
                                     "it up, restore or reset it from the environment page")


# -------------------------------------------------------------------------- not built (test 63, control half)


@pytest.mark.parametrize("action", ["start", "stop", "restart"])
async def test_63_control_on_a_planned_slot_answers_409_with_the_not_built_text(admin_client, action):
    env = await dof.make_do_env()  # blue's instance is CREATED: the not-built answer comes before that 400
    resp = await admin_client.post(f"/api/v1/instances/{env.ids['blue']}/actions/{action}")
    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"] == NOT_BUILT
    # A gone droplet under a running slot answers the same way, before any SSH.
    await set_rows(Instance, env.ids["blue"], status="running")
    async with get_sessionmaker()() as db:
        host = await db.get(Host, env.host_ids["blue"])
        hosts.set_phase(host, hosts.PHASE_GONE)
        await db.commit()
    resp = await admin_client.post(f"/api/v1/instances/{env.ids['blue']}/actions/{action}")
    assert (resp.status_code, resp.json()["detail"]) == (409, NOT_BUILT)


async def test_63_host_not_built_from_run_on_instance_answers_409_not_500(admin_client, monkeypatch):
    env = await dof.make_do_env()
    await built(env, "blue")
    await set_rows(Instance, env.ids["blue"], status="running")

    async def gone(instance: Instance, command: str, **_kw: Any) -> str:
        raise ssh.HostNotBuilt(NOT_BUILT)  # the droplet went while the request was on its way

    monkeypatch.setattr(deployer, "run_on_instance", gone)
    blue = f"/api/v1/instances/{env.ids['blue']}"
    for method, path in (("POST", "/actions/stop"), ("POST", "/actions/restart"), ("GET", "/containers"),
                         ("GET", "/logs")):
        resp = await admin_client.request(method, f"{blue}{path}")
        assert (resp.status_code, resp.json()["detail"]) == (409, NOT_BUILT), (path, resp.text)
    async with get_sessionmaker()() as db:
        assert (await db.get(Instance, env.ids["blue"])).status == "running"


async def test_63_containers_and_logs_of_a_planned_slot_skip_before_its_first_deploy(admin_client):
    env = await dof.make_do_env()
    blue = f"/api/v1/instances/{env.ids['blue']}"
    assert (await admin_client.get(f"{blue}/containers")).json() == []
    assert (await admin_client.get(f"{blue}/logs")).json()["output"] == ""


async def test_63_run_on_instance_raises_host_not_built_without_connecting():
    env = await dof.make_do_env()
    db, blue, _env, _mem = await loaded(env.ids["blue"])
    try:
        def connect(_target: ssh.SSHTarget) -> Any:
            raise AssertionError("no SSH to a host that isn't built")

        with pytest.raises(ssh.HostNotBuilt, match="isn't built yet"):
            await deployer.run_on_instance(blue, "true", connect=connect)
    finally:
        await db.close()


# ------------------------------------------------------------------------------------- jobs on the owner


async def queue_raw(env: dof.DoEnv, slot: str, kind: str, *, status: str = "queued",
                    steps: list[dict[str, Any]] | None = None) -> uuid.UUID:
    """A job row inserted directly (``jobs.queue_job`` is the API's way; this is the runner's view)."""
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=env.ids[slot], environment_id=env.env_id, kind=kind, branch="main", log="",
                         status=status, triggered_by_id=env.user_id, steps=steps or [], options={})
        db.add(dep)
        await db.commit()
        return dep.id


@pytest.mark.parametrize("kind", ["backup", "snapshot", "restore", "reset", "admin", "content"])
async def test_80_an_owner_job_that_reaches_the_runner_fails_with_rule_4s_text(kind):
    env = await dof.make_do_env()
    dep_id = await queue_raw(env, "data", kind)
    await deployer.run_deployment(dep_id)
    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, dep_id)
        owner = await db.get(Instance, env.ids["data"])
    assert dep.status == "failed"
    assert dep.error == f"Could not start the deployment: {NO_RUNNER}"
    assert owner.status == "created"  # nothing changed on the owner


async def test_80_a_deploy_of_the_owner_never_runs():
    env = await dof.make_do_env()
    dep_id = await queue_raw(env, "data", "deploy")
    await deployer.run_deployment(dep_id)
    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, dep_id)
    assert dep.status == "failed"
    assert dep.error == ("Could not start the deployment: shop's data is in its managed database, so there is no "
                         "data server to deploy: deploy to blue instead")


async def test_80_rule_4_names_the_active_slot_when_there_is_one():
    env = await dof.make_do_env()
    await set_rows(Environment, env.env_id, active_slot_id=env.ids["green"])
    db, owner, row, mem = await loaded(env.ids["data"])
    try:
        assert await data.hostless_refusal(db, owner) == ("shop has no slot that can run its data commands: deploy "
                                                          "to green first")
        assert data.no_runner_text(row, mem).endswith("deploy to green first")
        blue = mem["blue"]
        assert await data.hostless_refusal(db, blue) is None
    finally:
        await db.close()


async def test_80_a_member_run_never_opens_the_owner():
    """A slot job that asks for the data member (``_AppRun.member``) is refused with rule 4's text, before any
    connection (the data runner is S14b's)."""
    env = await dof.make_do_env()
    db, blue, row, mem = await loaded(env.ids["blue"])
    try:
        job = deployer._Job(instance=blue, branch="main", user=None, env={}, secrets={}, steps=[], retry=None,
                            deployment_id=uuid.uuid4(), kind="deploy", options={}, never_live=True)
        job.environment, job.members = row, mem

        def connect(_target: ssh.SSHTarget) -> Any:
            raise AssertionError("nothing to connect to")

        job.connect = connect
        sink = deployer.LogSink(job.deployment_id)
        run = deployer._AppRun(remote=None, instance=blue, job=job, sink=sink,  # type: ignore[arg-type]
                               steps=deployer.Steps(job.deployment_id, [], sink), paths=deployer.InstancePaths.of("/x"))
        with pytest.raises(deployer.DeployError, match="no slot that can run its data commands"):
            await run.member("data")
    finally:
        await db.close()


# ----------------------------------------------------------------------------- recovery and the poller (80)


async def test_80_recover_interrupted_passes_over_the_owner_and_the_unbuilt_hosts():
    env = await dof.make_do_env()
    backup = await owner_backup(env, status="pending")
    running = [{"key": "release", "name": "Use the live release", "status": "running"},
               {"key": "backup", "name": "Back up the data", "status": "pending"}]
    on_owner = await queue_raw(env, "data", "backup", status="running", steps=running)
    deploy_rows = [{"key": "resolve", "name": "Find the commit", "status": "succeeded"},
                   {"key": "prepare", "name": "Prepare DigitalOcean", "status": "pending"},
                   {"key": "source", "name": "Download the source", "status": "pending"}]
    other = await dof.make_do_env(name="cart", account_id=env.account_id)  # one active job per environment
    queued_blue = await queue_raw(other, "blue", "deploy", steps=deploy_rows)
    await deployer.runner.recover_interrupted()
    async with get_sessionmaker()() as db:
        for dep_id in (on_owner, queued_blue):
            dep = await db.get(Deployment, dep_id)
            assert dep.status == "failed" and dep.error == "Interrupted by a Slipway restart"
        assert (await db.get(Backup, backup)).status == "unverified"
        assert (await db.get(Instance, env.ids["data"])).status == "created"
        assert (await db.get(Host, other.host_ids["blue"])).provider_state["phase"] == "planned"


async def test_80_the_poller_checks_only_built_hosts(monkeypatch):
    env = await dof.make_do_env()
    async with get_sessionmaker()() as db:
        host = await db.get(Host, env.host_ids["green"])  # creating: host_key holds the key sent with the create
        _private, public = ssh.generate_keypair("root@droplet")
        host.host_key = public
        hosts.set_phase(host, hosts.PHASE_CREATING)
        await db.commit()
    await built(env, "blue")
    checked: list[uuid.UUID] = []

    async def check(host_id: uuid.UUID) -> None:
        checked.append(host_id)

    monkeypatch.setattr(hosts, "_check_by_id", check)
    await hosts.poll_once()
    assert checked == [env.host_ids["blue"]]


# ----------------------------------------------------------------------------- the service helpers (80)


async def test_80_service_helpers_are_none_safe_for_the_owner():
    env = await dof.make_do_env()
    backup_id = await owner_backup(env)
    db, owner, row, mem = await loaded(env.ids["data"])
    try:
        backup = await db.get(Backup, backup_id)
        assert data.host_label(owner) == "its managed database"
        assert data.hostless(owner) and not data.hostless(mem["blue"])
        assert data.restorable(owner, backup).reason == "Deploy the instance first"
        assert data.data_shared_reason(owner) is None
        assert data.data_shared_reason(mem["blue"], environment=row, owner=owner).endswith(
            "lives in its managed database: back it up, restore or reset it from the environment page")
        with pytest.raises(deployer.DeployError, match="no server of its own"):
            deployer.instance_dir(owner)
        with pytest.raises(deployer.DeployError, match="no server of its own"):
            await deployer.run_on_instance(owner, "true")
        with pytest.raises(deployer.DeployError, match="no server of its own"):
            await deployer.destroy(owner)
        assert deployer.ram_backed(None, "/opt/slipway/x") is False
        # Every kind's steps for the owner name no host; the snapshot export says where the data is.
        for kind in ("backup", "snapshot", "restore", "reset", "admin", "content"):
            rows = deployer.steps_for(owner, kind, environment=row, members=mem)
            assert rows and all(r["name"] for r in rows)
        snap = deployer.steps_for(owner, "snapshot", environment=row, members=mem)
        assert {r["key"]: r["name"] for r in snap}["export"] == "Export the data on its managed database"
        # Traffic: the owner serves no name; its smoke targets and probe texts name no host.
        route = route_of("server")
        assert traffic.target(route, owner).problem == "shop data has no server of its own"
        found = traffic.smoke_targets(owner, [route_of("active")])
        assert found[0].problem == "api container port 8000 is not published on its managed database"
        assert "on its managed database can't sign in" in traffic.probe_problem(
            "", slot=owner, env_name="shop", host="db", port=25060)
        # The SchemaOut folder of the owner is empty, not an error.
        from slipway.schemas import _folder
        assert _folder(owner) == ""
    finally:
        await db.close()


async def test_80_answers_for_instances_with_a_host_are_unchanged():
    env = await dof.make_do_env()
    await built(env, "blue")
    db, blue, row, mem = await loaded(env.ids["blue"])
    try:
        assert data.host_label(blue) == "slipway-shop-blue"
        assert deployer.instance_dir(blue) == "/opt/slipway/shop-blue"
        route = route_of("active")
        assert traffic.target(route, blue).problem.endswith("isn't running yet (shop blue hasn't been deployed)")
    finally:
        await db.close()
