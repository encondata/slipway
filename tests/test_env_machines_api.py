"""The VM API (phase 5 §11, S22): the machines of an environment, Resize, Forget the VM, VM snapshots, an account's
free addresses, ``HostOut.machine`` and ``forget_vms`` on Remove slot.

Numbered tests of P5 §16.2: 38 (the addresses half), 47 (the API half), 55 (the API half), 56 (the route), 57, 58
(the VM half), 59 and 60. Proxmox is ``tests/fake_proxmox.py`` (the Proxmox provider tests' World), ESXi
``tests/fake_esxi.py``; the VMs are ``tests/fake_vm_hosts.py``. Jobs a route queues are recorded, not started; a
test that needs one to run runs it through ``deployer.run_deployment``.
"""

from __future__ import annotations

import datetime as dt
import time
import uuid
from typing import Any

import httpx
import pytest
from sqlalchemy import select, update

from slipway.db.base import utcnow
from slipway.db.session import get_sessionmaker
from slipway.models import (
    AuditEvent,
    Backup,
    Deployment,
    Environment,
    Host,
    Instance,
    Machine,
    MachineSnapshot,
    ProviderAccount,
    Repository,
)
from slipway.services import deployer, environments, esxi, vm_jobs
from slipway.services.providers import proxmox as pxp
from tests import vm_fixtures as vf
from tests.test_data_api import client_with, clients, storage  # noqa: F401  (storage: autouse)
from tests.test_env_machines import GONE, KEPT, all_ready, pve_env, ready, rows_of, unreachable
from tests.test_owned_hosts_api import FILES, vm_body
from tests.test_provider_esxi import World as EsxiWorld
from tests.test_provider_esxi import made as esxi_made
from tests.test_provider_proxmox import World, a_world, net, world  # noqa: F401  (fixtures)
from tests.test_vm_jobs import add_row, idle, pve_ready, snap_name

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")

ROLES = ("viewer", "developer", "maintainer", "admin")


@pytest.fixture(autouse=True)
def submitted(monkeypatch) -> list[uuid.UUID]:
    found: list[uuid.UUID] = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, keys: found.append(dep_id))
    return found


@pytest.fixture
async def c(make_client) -> dict[str, httpx.AsyncClient]:
    return await clients(make_client)


# ------------------------------------------------------------------------------------------------ helpers


async def get(model: Any, ident: uuid.UUID) -> Any:
    async with get_sessionmaker()() as db:
        return await db.get(model, ident)


async def set_rows(model: Any, ident: uuid.UUID, **values: Any) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(update(model).where(model.id == ident).values(**values))
        await db.commit()


async def audits(action: str) -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        return list(await db.scalars(select(AuditEvent).where(AuditEvent.action == action)
                                     .order_by(AuditEvent.created_at)))


async def run(dep_id: uuid.UUID | str, w: Any) -> Deployment:
    dep_id = uuid.UUID(str(dep_id))
    await deployer.run_deployment(dep_id, connect=w.vms.connect)
    return await get(Deployment, dep_id)


def steps(dep: Deployment) -> dict[str, str]:
    return {r["key"]: r["status"] for r in dep.steps or []}


def stopped(w: World, vmid: int) -> None:
    with w.fake.edit() as state:
        state["vms"][str(vmid)]["status"] = "stopped"


async def backup(instance_id: uuid.UUID, name: str, minutes_ago: int) -> None:
    async with get_sessionmaker()() as db:
        at = utcnow() - dt.timedelta(minutes=minutes_ago)
        db.add(Backup(instance_id=instance_id, name=name, reason="manual", status="ready", format="pg-dump-v1",
                      db_bytes=10, db_sha256="0" * 64, identity_fp="0" * 64, taken_at=at, finished_at=at))
        await db.commit()


async def failed_job(env: vf.VmEnv, kind: str, **options: Any) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, env.instances["blue"])
        dep = Deployment(instance_id=inst.id, environment_id=env.env_id, kind=kind, branch="main", options=options,
                         triggered_by_id=env.user_id, log="", status="failed", finished_at=utcnow(),
                         steps=deployer.steps_for(inst, kind))
        db.add(dep)
        await db.commit()
        return dep.id


# --------------------------------------------------------- test 38's addresses half: free and held addresses


async def test_38_addresses_lists_free_pool_addresses_and_who_holds_the_others(c, net):
    account = await vf.proxmox_account()
    await vf.vm_env(account, addresses={"blue": "10.0.0.100"})
    async with get_sessionmaker()() as db:
        db.add(Host(name="box", hostname="10.0.0.101", username="deploy", created_by_id=None))
        await db.commit()
    url = f"/api/v1/provider-accounts/{account.id}/addresses"
    resp = await c["developer"].get(url, params={"network": "lan", "count": 3})
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["network"] == "lan" and out["subnet"] == "10.0.0.0/24"
    assert out["free"] == ["10.0.0.102", "10.0.0.103", "10.0.0.104"]
    assert {r["address"]: r["by"] for r in out["in_use"]} == {
        "10.0.0.1": "the network's gateway",
        "10.0.0.2": "the Proxmox API's address",
        "10.0.0.53": "one of the network's DNS servers",
        "10.0.0.100": "uat's blue VM",
        "10.0.0.101": "host box",
    }
    assert [r["address"] for r in out["in_use"]] == ["10.0.0.1", "10.0.0.2", "10.0.0.53", "10.0.0.100", "10.0.0.101"]
    assert out["in_use"][3]["text"] == "10.0.0.100 is reserved for uat's blue VM"
    assert net.probed == []  # from Slipway's records: nothing is probed
    # The account's only network is the default; the count defaults to ten.
    assert len((await c["admin"].get(url)).json()["free"]) == 10
    resp = await c["admin"].get(url, params={"network": "wan"})
    assert (resp.status_code, resp.json()) == (422, {"detail": "lab has no network named wan", "field": "network"})
    assert (await c["admin"].get(url, params={"count": 0})).status_code == 422
    assert (await c["viewer"].get(url)).status_code == 403  # providers:read
    # A DigitalOcean account has no address pools.
    from tests import do_fixtures as dof  # noqa: PLC0415

    do = await dof.make_account()
    resp = await c["admin"].get(f"/api/v1/provider-accounts/{do}/addresses")
    assert resp.status_code == 409 and "DigitalOcean account" in resp.json()["detail"]


# ------------------------------------------------------------------------- test 58's VM half: HostOut.machine


async def test_58_hostout_names_the_vm_a_host_is(c, net):
    account = await vf.proxmox_account()
    env = await vf.vm_env(account, addresses={"blue": "10.0.0.100"})
    async with get_sessionmaker()() as db:
        db.add(Host(name="box", hostname="10.0.0.101", username="deploy"))
        await db.commit()
    out = (await c["viewer"].get(f"/api/v1/hosts/{env.hosts['blue']}")).json()
    assert out["machine"] == {"stage": "planned",
                              "account": {"id": str(account.id), "name": "lab", "provider": "proxmox"}}
    assert out["owned_by"] == {"id": str(env.env_id), "name": "uat", "slot": "blue"}
    assert out["built"] is False and out["provider_state"]["phase"] == "planned" and out["provider"] == "proxmox"
    listed = {h["name"]: h for h in (await c["viewer"].get("/api/v1/hosts")).json()}
    assert listed["slipway-uat-blue"]["machine"]["stage"] == "planned"
    assert listed["box"]["machine"] is None and listed["box"]["owned_by"] is None
    resp = await c["admin"].patch(f"/api/v1/hosts/{env.hosts['blue']}", json={"hostname": "10.0.0.120"})
    assert (resp.status_code, resp.json()["detail"]) == (
        409, "slipway-uat-blue is a VM Slipway made for uat; change it on the environment")
    resp = await c["admin"].patch(f"/api/v1/hosts/{env.hosts['blue']}", json={"label": "uat VM"})
    assert resp.status_code == 200 and resp.json()["machine"]["account"]["name"] == "lab"


# ------------------------------------------------------------------------------- test 60: the Resize PATCH


async def test_60_resize_stores_the_sizes_only(c, world):
    env = await pve_ready(world)
    url = f"/api/v1/environments/{env.env_id}/machines/blue"
    mark = len(world.fake.requests)
    resp = await c["maintainer"].patch(url, json={"cores": 8, "memory_mb": 16384, "keep_vm_snapshots": 5})
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["size"] == {"cores": 8, "memory_mb": 16384, "disk_gb": 64} and out["keep_vm_snapshots"] == 5
    assert out["applied"]["cores"] == 4
    assert out["pending_resize"] is True and out["applies_at"] == "next deploy"
    machine = await get(Machine, env.machines["blue"])
    assert machine.size["cores"] == 8 and machine.keep_vm_snapshots == 5
    (row,) = await audits("environment.update")
    assert row.details == {"changed": {"machine.blue": "4 vCPU, 8 GB, 64 GB → 8 vCPU, 16 GB, 64 GB",
                                       "machine.blue.keep_vm_snapshots": "3 → 5"}}
    assert len(world.fake.requests) == mark  # nothing reached Proxmox

    resp = await c["maintainer"].patch(url, json={"disk_gb": 32})
    assert (resp.status_code, resp.json()) == (422, {"detail": "Disks only grow: slipway-uat-blue has 64 GB",
                                                     "field": "disk_gb"})
    resp = await c["maintainer"].patch(url, json={"cores": 0})
    assert resp.status_code == 422 and resp.json()["field"] == "size"
    assert (await c["developer"].patch(url, json={"cores": 2})).status_code == 403  # machines:write
    assert (await c["maintainer"].patch(f"/api/v1/environments/{env.env_id}/machines/purple",
                                        json={"cores": 2})).status_code == 404
    assert (await get(Machine, env.machines["blue"])).size["cores"] == 8
    assert len(world.fake.requests) == mark


async def test_60_the_ready_data_servers_vm_keeps_its_size(c, net):
    account = await vf.proxmox_account()
    env = await vf.vm_env(account, mode="server", slots=("blue",))
    async with get_sessionmaker()() as db:
        row = await db.get(Machine, env.machines["data"])
        row.stage, row.applied, row.ready_at = "ready", dict(row.size), utcnow()
        await db.commit()
    resp = await c["maintainer"].patch(f"/api/v1/environments/{env.env_id}/machines/data", json={"cores": 8})
    assert (resp.status_code, resp.json()["detail"]) == (
        409, "The data server's VM keeps its size: both slots' data is on it. docs/machines.md shows how to grow it "
             "by hand")
    # Its snapshot count can still change.
    resp = await c["maintainer"].patch(f"/api/v1/environments/{env.env_id}/machines/data",
                                       json={"keep_vm_snapshots": 1})
    assert resp.status_code == 200 and resp.json()["keep_vm_snapshots"] == 1


# ----------------------------------------------------------------- test 59: machines, actions and snapshots


async def test_59_environment_out_lists_the_vms_and_their_actions(c, world):
    env = await pve_env(world)
    await all_ready(world, env)
    await set_rows(Environment, env.env_id, active_slot_id=env.instances["blue"], status="live")
    async with get_sessionmaker()() as db:
        for slot in ("blue", "green"):
            (await db.get(Machine, env.machines[slot])).size = {"cores": 8, "memory_mb": 8192, "disk_gb": 64}
        await db.commit()
    out = (await c["maintainer"].get(f"/api/v1/environments/{env.env_id}")).json()
    vms = {m["slot"]: m for m in out["machines"]}
    assert list(vms) == ["blue", "green", "data"]
    assert vms["blue"]["name"] == "slipway-uat-blue" and vms["blue"]["address"] == "10.0.0.100"
    assert vms["blue"]["account"]["name"] == "lab" and vms["blue"]["network"] == "lan"
    assert vms["blue"]["live"] is None  # records only: GET .../machines reads them live
    assert (vms["blue"]["pending_resize"], vms["blue"]["applies_at"]) == (True, "when idle")  # active of two
    assert (vms["green"]["pending_resize"], vms["green"]["applies_at"]) == (True, "next deploy")
    assert (vms["data"]["pending_resize"], vms["data"]["applies_at"]) == (False, None)
    actions = out["actions"]
    assert actions["resize"]["green"]["pending"] is True
    assert actions["resize"]["green"]["applies_at"] == "green's next deploy"
    assert actions["resize"]["data"]["available"] is False
    assert actions["forget"]["blue"] == {"available": False, "reason": "blue takes the traffic: activate green first"}
    assert actions["forget"]["green"]["available"] is True
    assert actions["vm_snapshots"]["available"] is False
    assert actions["vm_snapshots"]["reason"] == vm_jobs.SHAPE_TEXT
    slots = {s["slot"]: s for s in out["slots"]}
    assert slots["green"]["resize_pending"] == "Resize pending: applies at green's next deploy"
    # A viewer sees the same records, and no action.
    viewer = (await c["viewer"].get(f"/api/v1/environments/{env.env_id}")).json()
    assert len(viewer["machines"]) == 3 and viewer["actions"]["forget"]["green"]["available"] is False


async def test_59_vm_snapshots_action_gives_the_snapshot_mode(c, world):
    env = await pve_ready(world)
    out = (await c["maintainer"].get(f"/api/v1/environments/{env.env_id}")).json()
    assert out["actions"]["vm_snapshots"] == {"available": True, "reason": None, "snapshot_mode": "any",
                                              "vm": "slipway-uat-blue"}
    assert out["machines"][0]["snapshot_mode"] == "any"


async def test_59_machines_reads_power_busy_hidden_and_lost(c, world):
    env = await pve_env(world)
    ids = await all_ready(world, env)
    stopped(world, ids["green"])
    world.fake.run_task(ids["blue"], "vzdump", polls=None)
    url = f"/api/v1/environments/{env.env_id}/machines"
    mark = len(world.fake.requests)
    out = {m["slot"]: m for m in (await c["viewer"].get(url)).json()}
    assert out["blue"]["live"]["power"] == "running" and out["blue"]["live"]["busy"].startswith("vzdump (started ")
    assert out["blue"]["live"]["ours"] is True and out["blue"]["live"]["addresses"] == ["10.0.0.100"]
    assert out["blue"]["live"]["snapshot_mode"] == "any" and out["blue"]["live"]["error"] is None
    assert out["green"]["live"]["power"] == "stopped" and out["green"]["live"]["busy"] is None

    world.fake.remove_vm(ids["green"])
    world.fake.hidden(ids["green"])
    world.fake.remove_vm(ids["data"])
    out = {m["slot"]: m for m in (await c["viewer"].get(url)).json()}
    assert out["green"]["live"]["hidden"] is True and out["green"]["live"]["lost"] is False
    assert out["green"]["live"]["exists"] is False
    assert out["data"]["live"]["lost"] is True and out["data"]["live"]["hidden"] is False
    assert out["data"]["live"]["why_not_ours"] == f"VM {ids['data']} is gone from lab"
    # Nothing but reads reached Proxmox.
    assert {r["method"] for r in world.fake.requests[mark:]} == {"GET"}


async def test_59_machines_with_the_account_down_gives_live_error(c, world, monkeypatch):
    env = await pve_env(world, slots=("blue",))
    await all_ready(world, env)
    unreachable(monkeypatch)
    resp = await c["viewer"].get(f"/api/v1/environments/{env.env_id}/machines")
    assert resp.status_code == 200, resp.text
    live = {m["slot"]: m["live"] for m in resp.json()}
    assert live["blue"]["error"] and live["blue"]["power"] is None
    assert live["blue"]["detail"].startswith("Slipway can't read slipway-uat-blue on lab now: ")
    # An account that can't be used is said without a read; a VM never made isn't read at all.
    await set_rows(ProviderAccount, env.account_id, removed_at=utcnow())
    await set_rows(Machine, env.machines["data"], ids={}, stage="planned")
    live = {m["slot"]: m["live"] for m in (await c["viewer"].get(f"/api/v1/environments/{env.env_id}/machines")).json()}
    assert live["blue"]["error"] == "it was removed"
    assert live["blue"]["detail"] == ("Proxmox account lab can't be used: it was removed. Fix it in Settings → "
                                      "Integrations, then retry.")
    assert live["data"] is None


@pytest.fixture
def esxi_world(tmp_path, monkeypatch, net) -> EsxiWorld:
    """The ESXi World, with the real ``esxi.session`` (its two session pools) signing in to the fake."""
    real = esxi.session
    w = EsxiWorld(tmp_path, monkeypatch, net)

    class Api:
        def __getattr__(self, name: str) -> Any:
            return getattr(w.fake, name)

        async def close(self) -> None:
            return None

    monkeypatch.setattr(esxi, "_smart_connect", lambda *args: object())
    monkeypatch.setattr(esxi, "PyvmomiEsxi", lambda si, **kw: Api())
    monkeypatch.setattr(esxi, "session", real)
    return w


async def test_59_esxi_page_reads_never_wait_for_the_jobs_sessions(c, esxi_world, monkeypatch):
    w = esxi_world
    env, _ctx, _log = await esxi_made(w)
    await idle(env)
    key = str(env.account_id)
    url = f"/api/v1/environments/{env.env_id}/machines"
    for _ in range(esxi.SESSIONS_PER_ACCOUNT):  # a job holds both job sessions (a 30-minute disk copy, say)
        await esxi.job_sessions[key].acquire()
    try:
        started = time.monotonic()
        resp = await c["viewer"].get(url)
        assert time.monotonic() - started < 5
        (vm,) = resp.json()
        assert vm["live"]["power"] == "running" and vm["live"]["error"] is None and vm["live"]["ours"] is True
    finally:
        for _ in range(esxi.SESSIONS_PER_ACCOUNT):
            esxi.job_sessions[key].release()
    # Every page read is taken: the read gives up after its wait and says the account is busy.
    monkeypatch.setattr(esxi, "READ_WAIT", 0.05)
    for _ in range(esxi.SESSIONS_PER_ACCOUNT):
        await esxi.read_sessions[key].acquire()
    try:
        (vm,) = (await c["viewer"].get(url)).json()
    finally:
        for _ in range(esxi.SESSIONS_PER_ACCOUNT):
            esxi.read_sessions[key].release()
    assert vm["live"]["error"] == "busy"
    assert vm["live"]["detail"] == "esx-01 is busy with other work; try again in a minute"


async def test_59_vm_snapshots_join_the_records_with_the_hypervisor(c, world):
    env = await pve_ready(world)
    old = await add_row(env, snap_name(180), minutes_ago=180, world=world)
    gone = await add_row(env, snap_name(120), minutes_ago=120)  # recorded, not on Proxmox
    late = await add_row(env, snap_name(60), status="pending", world=world)  # its job was cut off
    await backup(env.instances["blue"], "b-before", 200)
    await backup(env.instances["blue"], "b-middle", 90)
    await backup(env.instances["blue"], "b-after", 30)
    resp = await c["maintainer"].get(f"/api/v1/environments/{env.env_id}/vm-snapshots")
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert (out["slot"], out["vm"], out["snapshot_mode"], out["error"]) == ("blue", "slipway-uat-blue", "any", None)
    assert out["take"] == {"available": True, "reason": None}
    rows = {r["name"]: r for r in out["snapshots"]}
    assert [r["name"] for r in out["snapshots"]] == [late.name, gone.name, old.name]  # newest first
    assert rows[old.name]["on_hypervisor"] is True and rows[gone.name]["on_hypervisor"] is False
    assert rows[late.name]["newest"] is True and rows[old.name]["newest"] is False
    # The page's read settles them: the late one is there (ready), the gone one is missing.
    assert rows[late.name]["status"] == "ready" and rows[gone.name]["status"] == "missing"
    assert (await get(MachineSnapshot, late.id)).status == "ready"
    assert (await get(MachineSnapshot, gone.id)).status == "missing"
    assert rows[old.name]["revert"] == {"available": True, "reason": None}
    assert rows[gone.name]["revert"]["available"] is False
    assert rows[old.name]["backups_after"] == ["b-middle", "b-after"]
    assert rows[late.name]["backups_after"] == ["b-after"]
    assert rows[old.name]["drop"] == {"available": True, "reason": None}
    # A developer may look, not act.
    dev = (await c["developer"].get(f"/api/v1/environments/{env.env_id}/vm-snapshots")).json()
    assert dev["take"]["reason"] == "Taking a VM snapshot needs the machines:write permission"
    assert {r["name"]: r["revert"]["reason"] for r in dev["snapshots"]}[old.name] == (
        "Reverting to a VM snapshot needs the machines:write permission")
    # The hypervisor can't be read: the records as they are, with the error.
    world.fake.remove_vm(100)
    world.fake.hidden(100)
    out = (await c["maintainer"].get(f"/api/v1/environments/{env.env_id}/vm-snapshots")).json()
    assert {r["on_hypervisor"] for r in out["snapshots"]} == {None}
    assert {r["name"]: r["newest"] for r in out["snapshots"]}[late.name] is True  # the newest ready row
    assert (await get(MachineSnapshot, old.id)).status == "ready"  # nothing settled from a read that failed


async def test_59_vm_snapshots_of_an_environment_without_a_vm(c, net):
    account = await vf.proxmox_account()
    env = await vf.vm_env(account, mode="server", slots=("blue", "green"))
    out = (await c["viewer"].get(f"/api/v1/environments/{env.env_id}/vm-snapshots")).json()
    assert out["vm"] == "slipway-uat-blue" and out["take"]["available"] is False and out["snapshots"] == []
    assert out["error"] is None  # a VM never made isn't read


async def test_59_on_zfs_revert_names_the_newer_snapshots(c, tmp_path, monkeypatch, net):
    world = a_world(tmp_path, monkeypatch, net, storage_type="zfspool")
    env = await pve_ready(world, storage_type="zfspool")
    old = await add_row(env, snap_name(60), world=world)
    world.fake.add_snapshot(100, "by-hand")  # someone else's, newer than Slipway's
    out = (await c["maintainer"].get(f"/api/v1/environments/{env.env_id}/vm-snapshots")).json()
    assert out["snapshot_mode"] == "newest_only"
    (row,) = out["snapshots"]
    assert row["name"] == old.name and row["newest"] is False
    assert row["revert"] == {"available": False, "reason": "Proxmox can roll ZFS back only to the newest VM snapshot; "
                                                           "by-hand is newer. Delete it first, or revert to by-hand"}
    new = await add_row(env, snap_name(1), minutes_ago=1, world=world)
    rows = {r["name"]: r for r in
            (await c["maintainer"].get(f"/api/v1/environments/{env.env_id}/vm-snapshots")).json()["snapshots"]}
    assert rows[new.name]["newest"] is True and rows[new.name]["revert"]["available"] is True
    assert rows[old.name]["revert"]["reason"].startswith("Proxmox can roll ZFS back only to the newest VM snapshot; ")


async def test_59_take_on_storage_that_cant_snapshot_is_409(c, tmp_path, monkeypatch, net):
    world = a_world(tmp_path, monkeypatch, net)
    world.fake.set_storage(type="lvm")
    env = await pve_ready(world, storage_type="lvm")
    assert (await get(Machine, env.machines["blue"])).snapshot_mode == "none"
    resp = await c["maintainer"].post(f"/api/v1/environments/{env.env_id}/vm-snapshots", json={})
    assert (resp.status_code, resp.json()["detail"]) == (
        409, "local-lvm (lvm) can't take VM snapshots of slipway-uat-blue")
    out = (await c["maintainer"].get(f"/api/v1/environments/{env.env_id}")).json()
    assert out["actions"]["vm_snapshots"]["snapshot_mode"] == "none"
    assert out["actions"]["vm_snapshots"]["reason"] == "local-lvm (lvm) can't take VM snapshots of slipway-uat-blue"


# --------------------------------------------------------- test 47's API half, and the other snapshot routes


async def test_47_revert_checks_the_typed_name_then_the_permissions_then_queues(c, world, make_client, submitted):
    env = await pve_ready(world)
    row = await add_row(env, snap_name(60), world=world)
    url = f"/api/v1/environments/{env.env_id}/vm-snapshots/{row.id}/revert"
    resp = await c["viewer"].post(url, json={"confirm": "nope"})
    assert (resp.status_code, resp.json()["detail"]) == (422, "Type the environment's name, uat, exactly to confirm")
    resp = await c["developer"].post(url, json={"confirm": "uat"})
    assert (resp.status_code, resp.json()["detail"]) == (
        403, "Reverting to a VM snapshot needs the machines:write permission")
    writer = await client_with(make_client, "vmwriter@example.com",
                               ["environments:read", "deployments:create", "machines:write"])
    resp = await writer.post(url, json={"confirm": "uat"})
    assert (resp.status_code, resp.json()["detail"]) == (
        403, "Reverting to a VM snapshot needs the data:reset permission")
    assert submitted == []

    resp = await c["maintainer"].post(url, json={"confirm": "uat"})
    assert resp.status_code == 202, resp.text
    dep = resp.json()
    assert dep["kind"] == "vm_revert" and submitted == [uuid.UUID(dep["id"])]
    assert [(s["key"], s["name"]) for s in dep["steps"]] == [
        ("check", "Check slipway-uat-blue and its VM snapshots"), ("vm_snapshot", "Take a VM snapshot first"),
        ("vm_revert", f"Revert slipway-uat-blue to {row.name}"), ("wait", "Wait for slipway-uat-blue to answer"),
        ("vm_settle", f"Bring Slipway's records back to {row.name}"), ("restart", deployer.STEP_NAMES["restart"]),
        ("traffic", deployer.STEP_NAMES["traffic"])]
    stored = await get(Deployment, uuid.UUID(dep["id"]))
    assert stored.options["vm_snapshot_id"] == row.id.hex and stored.instance_id == env.instances["blue"]
    (audit_row,) = await audits("deployment.create")
    assert audit_row.details["kind"] == "vm_revert" and audit_row.details["snapshot"] == row.name

    # One job at a time; then skip_pre_revert drops the snapshot step.
    resp = await c["maintainer"].post(url, json={"confirm": "uat"})
    assert resp.status_code == 409
    await idle(env)
    resp = await c["maintainer"].post(url, json={"confirm": "uat", "skip_pre_revert": True})
    assert resp.status_code == 202, resp.text
    assert "vm_snapshot" not in [s["key"] for s in resp.json()["steps"]]
    assert (await get(Deployment, uuid.UUID(resp.json()["id"]))).options["skip_pre_revert"] is True
    await idle(env)
    # A snapshot of another environment (or none) is not found.
    resp = await c["maintainer"].post(f"/api/v1/environments/{env.env_id}/vm-snapshots/{uuid.uuid4()}/revert",
                                      json={"confirm": "uat"})
    assert resp.status_code == 404


async def test_take_and_delete_a_vm_snapshot_queue_their_jobs(c, world, submitted):
    env = await pve_ready(world)
    base = f"/api/v1/environments/{env.env_id}/vm-snapshots"
    resp = await c["maintainer"].post(base, json={"note": "before the upgrade"})
    assert resp.status_code == 202, resp.text
    dep = resp.json()
    assert dep["kind"] == "vm_snapshot"
    assert [(s["key"], s["name"]) for s in dep["steps"]] == [
        ("check", "Check slipway-uat-blue and its VM snapshots"), ("vm_snapshot", "Take a VM snapshot of slipway-uat-blue"),
        ("prune", "Delete old VM snapshots")]
    assert (await get(Deployment, uuid.UUID(dep["id"]))).options["note"] == "before the upgrade"
    # The job runs: the row is taken on Proxmox, and the page then lists it.
    done = await run(dep["id"], world)
    assert done.status == "succeeded", (done.error, done.log[-2000:])
    (row,) = (await c["viewer"].get(base)).json()["snapshots"]
    assert row["status"] == "ready" and row["on_hypervisor"] is True and row["note"] == "before the upgrade"

    resp = await c["maintainer"].delete(f"{base}/{row['id']}")
    assert resp.status_code == 202, resp.text
    assert [(s["key"], s["name"]) for s in resp.json()["steps"]] == [
        ("check", "Check slipway-uat-blue and its VM snapshots"), ("vm_drop", f"Delete the VM snapshot {row['name']}")]
    done = await run(resp.json()["id"], world)
    assert done.status == "succeeded", (done.error, done.log[-2000:])
    assert (await c["viewer"].get(base)).json()["snapshots"] == []
    assert [a.details["kind"] for a in await audits("deployment.create")] == ["vm_snapshot", "vm_drop"]
    assert (await c["developer"].post(base, json={})).status_code == 403
    assert (await c["maintainer"].delete(f"{base}/{uuid.uuid4()}")).status_code == 404


# ---------------------------------------------------- test 55's API half: VM blockers and forget_vms


async def test_55_a_vm_blocker_refuses_removing_the_slot_and_deleting_the_environment(c, world, make_client):
    env = await pve_env(world)
    ids = await all_ready(world, env)
    world.fake.remove_vm(ids["green"])
    world.fake.hidden(ids["green"])
    slot_url = f"/api/v1/environments/{env.env_id}/slots/green"
    resp = await c["maintainer"].request("DELETE", slot_url, json={"confirm": "uat"})
    assert resp.status_code == 409
    assert resp.json()["detail"].startswith(f"Slipway can't see VM {ids['green']}")
    resp = await c["maintainer"].request("DELETE", f"/api/v1/environments/{env.env_id}",
                                         json={"confirm": "uat", "drop_data": True})
    assert resp.status_code == 409
    assert resp.json()["detail"].startswith(f"Slipway can't remove slipway-uat-green: Slipway can't see VM {ids['green']}")
    assert resp.json()["detail"].endswith("Nothing was changed")
    assert (await get(Environment, env.env_id)).status != "deleting"

    # forget_vms: the name typed (422) first, then machines:write and environments:delete (403).
    resp = await c["maintainer"].request("DELETE", slot_url, json={"confirm": "nope", "forget_vms": True})
    assert resp.status_code == 422
    deleter = await client_with(make_client, "deleter@example.com", ["environments:read", "environments:delete"])
    resp = await deleter.request("DELETE", slot_url, json={"confirm": "uat", "forget_vms": True})
    assert (resp.status_code, resp.json()["detail"]) == (
        403, "Forgetting a VM needs the machines:write and environments:delete permissions")

    resp = await c["maintainer"].request("DELETE", slot_url, json={"confirm": "uat", "forget_vms": True})
    assert resp.status_code == 202, resp.text
    stored = await get(Deployment, uuid.UUID(resp.json()["id"]))
    assert stored.options["forget_vms"] is True and stored.kind == "remove_slot"
    assert [s["key"] for s in resp.json()["steps"]] == ["check", "slot", "machine"]
    (queued,) = [a for a in await audits("deployment.create") if a.details["kind"] == "remove_slot"]
    assert queued.details["forget_vms"] is True
    done = await run(stored.id, world)
    assert done.status == "succeeded", (done.error, done.log[-2000:])
    assert await rows_of(env, "green") == GONE
    assert await rows_of(env, "blue") == KEPT
    (forgot,) = await audits("machine.forget")
    assert forgot.details["why"] == "forget_vms" and forgot.details["name"] == "slipway-uat-green"
    assert world.fake.vm(ids["green"]) is not None  # hidden: someone else's to remove


async def test_55_delete_with_forget_vms_for_an_account_that_is_gone(c, world, make_client):
    env = await pve_env(world)
    await all_ready(world, env)
    await set_rows(ProviderAccount, env.account_id, removed_at=utcnow())
    url = f"/api/v1/environments/{env.env_id}"
    resp = await c["maintainer"].request("DELETE", url, json={"confirm": "uat", "drop_data": True})
    assert resp.status_code == 409 and resp.json()["detail"].startswith("Slipway can't remove slipway-uat-green: ")
    resp = await c["maintainer"].request("DELETE", url, json={"confirm": "nope", "drop_data": True, "forget_vms": True})
    assert resp.status_code == 422
    writer = await client_with(make_client, "deleter2@example.com",
                               ["environments:read", "environments:delete", "data:reset"])
    resp = await writer.request("DELETE", url, json={"confirm": "uat", "drop_data": True, "forget_vms": True})
    assert (resp.status_code, resp.json()["field"]) == (403, "forget_vms")

    resp = await c["maintainer"].request("DELETE", url, json={"confirm": "uat", "drop_data": True, "forget_vms": True})
    assert resp.status_code == 202, resp.text
    dep = await get(Deployment, uuid.UUID(resp.json()["id"]))
    assert dep.kind == "teardown" and dep.options["forget_vms"] is True
    done = await run(dep.id, world)
    assert done.status == "succeeded", (done.error, done.log[-2000:])
    assert (await get(Environment, env.env_id)).status == "deleted"
    for slot in ("blue", "green", "data"):
        assert await rows_of(env, slot) == GONE
    assert sorted(a.details["name"] for a in await audits("machine.forget")) == [
        "slipway-uat-blue", "slipway-uat-data", "slipway-uat-green"]
    assert {a.details["why"] for a in await audits("machine.forget")} == {"forget_vms"}


# -------------------------------------------------------------------------- test 56's route: Forget the VM


async def test_56_forget_the_vm_route(c, world, monkeypatch):
    env = await pve_env(world)
    ids = await all_ready(world, env)
    url = f"/api/v1/environments/{env.env_id}/machines/green/forget"
    resp = await c["maintainer"].post(url, json={"confirm": "uat"})
    assert (resp.status_code, resp.json()["detail"]) == (
        409, "Slipway can still see slipway-uat-green on lab: remove the slot instead")
    resp = await c["maintainer"].post(f"/api/v1/environments/{env.env_id}/machines/data/forget",
                                      json={"confirm": "uat"})
    assert resp.status_code == 409 and resp.json()["detail"].startswith("slipway-uat-data held uat's data.")
    world.fake.remove_vm(ids["green"])  # deleted by hand: the id is free
    resp = await c["maintainer"].post(url, json={"confirm": "UAT"})
    assert (resp.status_code, resp.json()["detail"]) == (422, "Type the environment's name, uat, exactly to confirm")
    resp = await c["developer"].post(url, json={"confirm": "uat"})
    assert (resp.status_code, resp.json()["detail"]) == (403, "Missing permission: machines:write, environments:delete")
    # The account can't be checked: 502, and nothing is forgotten.
    with monkeypatch.context() as m:
        unreachable(m)
        resp = await c["maintainer"].post(url, json={"confirm": "uat"})
        assert (resp.status_code, resp.json()["detail"]) == (
            502, "Slipway can't check lab now, so it won't forget slipway-uat-green")
    assert (await get(Machine, env.machines["green"])).stage == "ready"

    resp = await c["maintainer"].post(url, json={"confirm": "uat"})
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["stage"] == "planned" and out["slot"] == "green" and out["address"] == "10.0.0.101"
    assert out["note"] == "Slipway forgot slipway-uat-green; the next deploy to green makes a new VM at 10.0.0.101"
    (forgot,) = await audits("machine.forget")
    assert forgot.details["why"] == "lost" and forgot.details["slot"] == "green"
    host = await get(Host, env.hosts["green"])
    assert host.host_key is None and host.provider_state["phase"] == "planned"
    inst = await get(Instance, env.instances["green"])
    assert inst.status == "created" and inst.slot_state["stale"]
    resp = await c["maintainer"].post(url, json={"confirm": "uat"})
    assert (resp.status_code, resp.json()["detail"]) == (
        409, "slipway-uat-green isn't made yet: deploy to green to finish it")
    resp = await c["maintainer"].post(f"/api/v1/environments/{env.env_id}/machines/purple/forget",
                                      json={"confirm": "uat"})
    assert resp.status_code == 404


# --------------------------------------------------------------------------- test 57: the permission matrix


async def test_57_the_permission_matrix(c, world, monkeypatch):
    uat = await pve_env(world)
    await all_ready(world, uat)
    qa_account = await vf.proxmox_account(name="lab2")
    if "10.0.0.110" not in world.vms.by_address:
        world.vms.add_vm("qa-blue", "10.0.0.110")
    qa = await vf.vm_env(qa_account, name="qa", addresses={"blue": "10.0.0.110"}, provider=pxp.ProxmoxProvider())
    await ready(world, qa, "blue")
    async with get_sessionmaker()() as db:
        (await db.get(Machine, qa.machines["blue"])).snapshot_mode = "any"
        await db.commit()
    await idle(qa)
    vmid = (await get(Machine, qa.machines["blue"])).ids["vmid"]
    row = await add_row(qa, snap_name(60))
    world.fake.add_snapshot(vmid, row.name)
    retries = {kind: await failed_job(qa, kind, **({"vm_snapshot_id": row.id.hex} if kind != "vm_snapshot" else {}))
               for kind in ("vm_snapshot", "vm_revert", "vm_drop")}
    # A create with a machine needs slipway.yml (read from GitHub, faked) and a repository.
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=4343, full_name="acme/demo", owner="acme", name="demo",
                          html_url="https://github.com/acme/demo", detected_config={})
        db.add(repo)
        await db.commit()

    async def read(repo, branch, path):
        return FILES.get(path)

    monkeypatch.setattr(environments, "github_reader", lambda user: read)
    create = vm_body({"repo_id": repo.id, "pve": qa_account}, "new", "10.0.0.120")

    u, q, acct = uat.env_id, qa.env_id, qa_account.id
    everyone, readers, makers, admins = set(ROLES), {"developer", "maintainer", "admin"}, {"maintainer", "admin"}, {
        "admin"}
    calls: list[tuple[str, str, Any, set[str]]] = [
        ("GET", "/api/v1/provider-accounts", None, readers),
        ("GET", f"/api/v1/provider-accounts/{acct}", None, readers),
        ("GET", f"/api/v1/provider-accounts/{acct}/addresses?network=lan", None, readers),
        ("POST", "/api/v1/provider-accounts", {"provider": "proxmox", "name": "lab3", "url": "ftp://nope",
                                               "node": "pve1", "pool": "slipway", "storage": "local-lvm",
                                               "template_vmid": 9000, "networks": []}, admins),
        ("PATCH", f"/api/v1/provider-accounts/{acct}", {"node": "not a node!"}, admins),
        ("POST", f"/api/v1/provider-accounts/{acct}/test", None, admins | {"skip"}),
        ("POST", f"/api/v1/provider-accounts/{acct}/trust", {"fingerprint": "00" * 32}, admins | {"skip"}),
        ("DELETE", f"/api/v1/provider-accounts/{acct}", {"confirm": "wrong"}, admins),
        ("GET", f"/api/v1/environments/{u}", None, everyone),
        ("GET", f"/api/v1/environments/{u}/machines", None, everyone),
        ("PATCH", f"/api/v1/environments/{u}/machines/blue", {"keep_vm_snapshots": 4}, makers),
        ("POST", f"/api/v1/environments/{u}/machines/green/forget", {"confirm": "uat"}, makers),
        ("GET", f"/api/v1/environments/{q}/vm-snapshots", None, everyone),
        ("POST", f"/api/v1/environments/{q}/vm-snapshots", {}, makers),
        ("POST", f"/api/v1/environments/{q}/vm-snapshots/{row.id}/revert", {"confirm": "qa"}, makers),
        ("DELETE", f"/api/v1/environments/{q}/vm-snapshots/{row.id}", None, makers),
        ("POST", f"/api/v1/deployments/{retries['vm_snapshot']}/retry", {}, makers),
        ("POST", f"/api/v1/deployments/{retries['vm_revert']}/retry", {"confirm": "qa"}, makers),
        ("POST", f"/api/v1/deployments/{retries['vm_drop']}/retry", {}, makers),
        ("POST", "/api/v1/environments?check=true", create, makers),
        ("DELETE", f"/api/v1/environments/{u}/slots/green", {"confirm": "uat", "forget_vms": True}, makers),
        ("DELETE", f"/api/v1/environments/{u}", {"confirm": "uat", "drop_data": True}, makers),
    ]
    seen: dict[tuple[str, str], dict[str, int]] = {}
    for method, url, body, allowed in calls:
        for role in ROLES:
            if role == "admin" and "skip" in allowed:
                continue  # Test and Trust would read the account's live certificate
            resp = await c[role].request(method, url, json=body)
            seen.setdefault((method, url), {})[role] = resp.status_code
            if role in allowed:
                assert resp.status_code != 403, (method, url, role, resp.text)
            else:
                assert resp.status_code == 403, (method, url, role, resp.status_code, resp.text)
    # The allowed calls were answered, not refused for something else by mistake.
    assert seen[("GET", f"/api/v1/environments/{u}/machines")] == dict.fromkeys(ROLES, 200)
    assert seen[("POST", "/api/v1/provider-accounts")]["admin"] == 422
    assert seen[("POST", "/api/v1/environments?check=true")]["maintainer"] == 200
    assert seen[("POST", f"/api/v1/environments/{q}/vm-snapshots")]["maintainer"] == 202
    assert seen[("POST", f"/api/v1/environments/{u}/machines/green/forget")]["maintainer"] == 409
