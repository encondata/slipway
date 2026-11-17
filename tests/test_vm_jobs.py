"""The VM snapshot jobs (phase 5 §9.6, §9.7, §9.8, §9.12, §10.1, §10.2, §14): Take a VM snapshot, Revert to one,
Delete one, their refusals, their recovery after a restart and their step timeouts.

Numbered tests of P5 §16.2: 43 (the ESXi half), 46, 47 (the job half), 48 and 49 (the revert half), plus the
audits ``machine.snapshot``, ``machine.snapshot_delete`` and ``machine.revert``. Proxmox is
``tests/fake_proxmox.py`` (the Proxmox provider tests' World, with ``tests/bin/fake-terraform`` for a real deploy);
ESXi is ``tests/fake_esxi.py`` (the ESXi provider tests' World); the VMs are ``tests/fake_vm_hosts.py``. Every job
runs through ``jobs.queue_job`` and ``deployer.run_deployment``; the providers and the machines core are the real
ones. The HTTP halves (the routes, the API's 409s) are S22's.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import select, update

from slipway.db.base import utcnow
from slipway.db.session import get_sessionmaker
from slipway.models import (
    AuditEvent,
    Backup,
    Deployment,
    Environment,
    Instance,
    Machine,
    MachineSnapshot,
    User,
)
from slipway.services import data, deployer, jobs, machines, traffic, vm_jobs
from slipway.services.providers import proxmox as pxp
from tests import vm_fixtures as vf
from tests.conftest import make_user
from tests.test_provider_esxi import World as EsxiWorld
from tests.test_provider_esxi import blue_env as esxi_blue_env
from tests.test_provider_pipeline import live, run_vm, vm_world_env
from tests.test_provider_proxmox import BLUE, VM, World, ready_vm
from tests.test_provider_proxmox import blue_env as pve_blue_env

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")


@pytest.fixture(autouse=True)
def net(monkeypatch) -> vf.Network:
    return vf.quiet_network(monkeypatch)


@pytest.fixture(autouse=True)
def quiet(monkeypatch) -> list[uuid.UUID]:
    """Chained jobs are recorded, not run; traffic checks don't sleep."""
    found: list[uuid.UUID] = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, keys: found.append(dep_id))
    monkeypatch.setattr(traffic, "sleep", vf.no_sleep)
    return found


@pytest.fixture
def world(tmp_path, monkeypatch, net) -> World:
    return World(tmp_path, monkeypatch, net)


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


async def maintainer() -> User:
    return await make_user(f"maintainer-{uuid.uuid4().hex[:6]}@example.com", roles=["maintainer"])


async def developer() -> User:
    return await make_user(f"developer-{uuid.uuid4().hex[:6]}@example.com", roles=["developer"])


async def idle(env: vf.VmEnv) -> None:
    """Every job of the environment has ended (the provider tests' helpers leave one running)."""
    async with get_sessionmaker()() as db:
        await db.execute(update(Deployment).where(Deployment.environment_id == env.env_id,
                                                  Deployment.status.in_(("queued", "running")))
                         .values(status="succeeded", finished_at=utcnow()))
        await db.commit()


async def refusal(env: vf.VmEnv, kind: str, *, user: User | None = None, slot: str = "blue",
                  **options: Any) -> jobs.JobRefused | None:
    async with get_sessionmaker()() as db:
        instance = await db.get(Instance, env.instances[slot])
        who = await db.get(User, (user or await maintainer()).id)
        return await jobs.job_refusal(db, instance=instance, user=who, kind=kind, options=options)


async def queue(env: vf.VmEnv, kind: str, *, user: User | None = None, retry_of: uuid.UUID | None = None,
                **options: Any) -> uuid.UUID:
    """A VM job through ``jobs.queue_job`` (the API's queue)."""
    async with get_sessionmaker()() as db:
        instance = await db.get(Instance, env.instances["blue"])
        who = await db.get(User, (user or await maintainer()).id)
        parent = await db.get(Deployment, retry_of) if retry_of is not None else None
        dep = await jobs.queue_job(db, instance=instance, user=who, kind=kind, options=options, retry_of=parent)
        await db.commit()
        return dep.id


async def raw(env: vf.VmEnv, kind: str, **options: Any) -> uuid.UUID:
    """A VM job written as a queued row (one queued before something changed, so its own check meets it)."""
    async with get_sessionmaker()() as db:
        instance = await db.get(Instance, env.instances["blue"])
        who = await maintainer()
        dep = Deployment(instance_id=instance.id, environment_id=env.env_id, kind=kind, branch="main",
                         options=options, triggered_by_id=who.id, log="", status="queued",
                         steps=deployer.steps_for(instance, kind))
        db.add(dep)
        await db.commit()
        return dep.id


async def run(dep_id: uuid.UUID, w: Any) -> Deployment:
    await deployer.run_deployment(dep_id, connect=w.vms.connect)
    return await get(Deployment, dep_id)


def statuses(dep: Deployment) -> dict[str, str]:
    return {r["key"]: r["status"] for r in dep.steps or []}


def note(dep: Deployment, key: str) -> str | None:
    return next((r.get("note") for r in dep.steps or [] if r["key"] == key), None)


def names(dep: Deployment) -> dict[str, str]:
    return {r["key"]: r["name"] for r in dep.steps or []}


async def rows(env: vf.VmEnv) -> list[MachineSnapshot]:
    async with get_sessionmaker()() as db:
        return list(await db.scalars(select(MachineSnapshot).where(MachineSnapshot.machine_id == env.machines["blue"])
                                     .order_by(MachineSnapshot.taken_at)))


async def add_row(env: vf.VmEnv, name: str, *, reason: str = "manual", status: str = "ready",
                  minutes_ago: int = 60, world: Any = None, vmid: int = 100, **fields: Any) -> MachineSnapshot:
    """A VM snapshot row Slipway recorded (and, with ``world``, the snapshot on Proxmox)."""
    row_id = uuid.uuid4()
    row = MachineSnapshot(id=row_id, machine_id=env.machines["blue"], name=name, reason=reason, status=status,
                          identity_fp=data.identity_fp(row_id, [], None), backups=[],
                          sizes={"cores": 4, "memory_mb": 8192, "disk_gb": 64},
                          taken_at=utcnow() - dt.timedelta(minutes=minutes_ago), **fields)
    async with get_sessionmaker()() as db:
        db.add(row)
        await db.commit()
    if world is not None:
        world.fake.add_snapshot(vmid, name)
    return row


def snap_name(minutes_ago: int) -> str:
    return (utcnow() - dt.timedelta(minutes=minutes_ago)).strftime("slipway-%Y%m%dT%H%M%SZ")


async def pve_ready(world: World, *, storage_type: str = "lvmthin") -> vf.VmEnv:
    """A ready Proxmox VM at id 100 (no deploy yet), its environment idle."""
    env, _ctx = await ready_vm(world, storage_type=storage_type)
    await idle(env)
    return env


async def pve_deployed(world: World) -> vf.VmEnv:
    """A Proxmox VM made and deployed end to end (fake Terraform, the deploy on the VM's fake shell), live."""
    env = await pve_blue_env(world)
    dep = await run_vm(world, env)
    assert dep.status == "succeeded", (dep.error, dep.log[-3000:])
    await live(env)
    return env


def pve_writes(world: World, since: int) -> list[dict[str, Any]]:
    return [r for r in world.fake.requests[since:] if r["method"] != "GET"]


# ------------------------------------------------------------------------------- the step lists and names


def test_the_vm_kinds_steps_and_their_timeouts():
    """P5 §10.1, §10.2 and §14: the lists, the names and each step's limit (prune chosen equal to vm_snapshot)."""
    rows_ = vm_jobs.step_rows("vm_snapshot", vm=VM, names=deployer.STEP_NAMES)
    assert [(r["key"], r["name"]) for r in rows_] == [
        ("check", f"Check {VM} and its VM snapshots"), ("vm_snapshot", f"Take a VM snapshot of {VM}"),
        ("prune", "Delete old VM snapshots")]
    name = "slipway-20261116T090000Z"
    rows_ = vm_jobs.step_rows("vm_revert", vm=VM, names=deployer.STEP_NAMES, snapshot=name)
    assert [(r["key"], r["name"]) for r in rows_] == [
        ("check", f"Check {VM} and its VM snapshots"), ("vm_snapshot", "Take a VM snapshot first"),
        ("vm_revert", f"Revert {VM} to {name}"), ("wait", f"Wait for {VM} to answer"),
        ("vm_settle", f"Bring Slipway's records back to {name}"), ("restart", "Start the app again"),
        ("traffic", "Update Switchyard")]
    no_pre = vm_jobs.step_rows("vm_revert", vm=VM, names=deployer.STEP_NAMES, snapshot=name, pre_revert=False)
    assert "vm_snapshot" not in [r["key"] for r in no_pre]
    rows_ = vm_jobs.step_rows("vm_drop", vm=VM, names=deployer.STEP_NAMES, snapshot=name)
    assert [(r["key"], r["name"]) for r in rows_] == [
        ("check", f"Check {VM} and its VM snapshots"), ("vm_drop", f"Delete the VM snapshot {name}")]
    minutes = {key: deployer.step_timeout(key, provider) / 60
               for key in ("vm_snapshot", "prune", "vm_revert", "vm_drop", "wait", "vm_settle")
               for provider in ("proxmox", "esxi")}
    assert minutes == {"vm_snapshot": 35, "prune": 45, "vm_revert": 30, "vm_drop": 25, "wait": 10, "vm_settle": 2}
    assert deployer.step_timeout("check", "proxmox") is None
    for kind in vm_jobs.KINDS:
        assert jobs.KIND_PROBLEMS[kind] is not None


async def test_a_queued_job_lists_the_vms_steps_and_its_start_names_the_snapshot(world):
    env = await pve_ready(world)
    row = await add_row(env, snap_name(30), world=world)
    dep_id = await queue(env, "vm_drop", vm_snapshot_id=row.id.hex)
    queued = await get(Deployment, dep_id)
    assert names(queued) == {"check": f"Check {VM} and its VM snapshots", "vm_drop": "Delete the VM snapshot"}
    dep = await run(dep_id, world)
    assert dep.status == "succeeded", (dep.error, dep.log[-2000:])
    assert names(dep) == {"check": f"Check {VM} and its VM snapshots", "vm_drop": f"Delete the VM snapshot {row.name}"}


async def test_a_vm_steps_timeout_fails_the_step_with_its_limit(world, monkeypatch):
    env = await pve_ready(world)
    row = await add_row(env, snap_name(30), world=world)
    monkeypatch.setitem(deployer.STEP_TIMEOUTS, "vm_drop", 0.05)

    async def hangs(self, ctx, row):
        await asyncio.sleep(3600)

    monkeypatch.setattr(pxp.ProxmoxProvider, "drop_snapshot", hangs)
    dep = await run(await queue(env, "vm_drop", vm_snapshot_id=row.id.hex), world)
    assert dep.status == "failed"
    assert statuses(dep)["vm_drop"] == "failed"
    assert dep.error == f"Delete the VM snapshot {row.name} timed out after 0.05 seconds"
    assert len(await rows(env)) == 1  # nothing was forgotten


# ------------------------------------------------------------------------------- P5 test 46: vm_snapshot


async def test_46_each_refusal_of_take_a_vm_snapshot():
    env = await vm_world_env(ready=True)
    other = await vm_world_env(mode="server", slots=("blue", "green"), ready=True, name="two")
    dev = await developer()

    got = await refusal(env, "vm_snapshot", user=dev)
    assert (got.status, got.text) == (403, "Taking a VM snapshot needs the machines:write permission")
    got = await refusal(other, "vm_snapshot")
    assert (got.status, got.text) == (409, vm_jobs.SHAPE_TEXT)
    got = await refusal(other, "vm_snapshot", slot="data")
    assert (got.status, got.text) == (409, vm_jobs.SHAPE_TEXT)
    assert await refusal(env, "vm_snapshot") is None

    await set_rows(Machine, env.machines["blue"], snapshot_mode="none")
    got = await refusal(env, "vm_snapshot")
    assert (got.status, got.text) == (409, "local-lvm (lvmthin) can't take VM snapshots of slipway-uat-blue")
    await set_rows(Machine, env.machines["blue"], snapshot_mode="any")

    for i in range(vm_jobs.MANUAL_LIMIT):
        await add_row(env, snap_name(100 + i))
    await add_row(env, snap_name(10), reason="pre_resize")  # automatic ones don't count
    got = await refusal(env, "vm_snapshot")
    assert (got.status, got.text) == (409, "slipway-uat-blue has 10 VM snapshots you took; delete one first")
    async with get_sessionmaker()() as db:
        first = (await db.scalars(select(MachineSnapshot).where(MachineSnapshot.reason == "manual"))).first()
        await db.delete(first)
        await db.commit()
    assert await refusal(env, "vm_snapshot") is None

    # The owner's hold (P3's text) and a job running.
    async with get_sessionmaker()() as db:
        failed = Deployment(instance_id=env.instances["blue"], environment_id=env.env_id, kind="restore",
                            branch="main", log="", status="failed", steps=[{"key": "restore", "status": "failed"}])
        db.add(failed)
        await db.flush()
        await db.execute(update(Instance).where(Instance.id == env.instances["blue"]).values(
            data_dirty={"hold": True, "first": {"deployment_id": failed.id.hex, "kind": "restore"},
                        "last": {"deployment_id": failed.id.hex, "kind": "restore", "step": "restore"}}))
        await db.commit()
    got = await refusal(env, "vm_snapshot")
    assert got.status == 409 and "stopped part-way" in got.text
    await set_rows(Instance, env.instances["blue"], data_dirty=None)
    async with get_sessionmaker()() as db:
        db.add(Deployment(instance_id=env.instances["blue"], environment_id=env.env_id, kind="backup", branch="main",
                          log="", status="running", steps=[]))
        await db.commit()
    got = await refusal(env, "vm_snapshot")
    assert got.status == 409 and "running" in got.text
    await idle(env)

    async with get_sessionmaker()() as db:
        account = await db.get(Machine, env.machines["blue"])
        await db.execute(update(type(account.account)).where(type(account.account).id == account.account_id)
                         .values(secret=None))
        await db.commit()
    got = await refusal(env, "vm_snapshot")
    assert got.status == 409 and got.text.startswith("Proxmox account lab can't be used: its API token is missing")


async def test_46_the_row_is_committed_before_the_task_then_prune_keeps_the_newest_automatic(world, monkeypatch):
    env = await pve_deployed(world)
    instance = await get(Instance, env.instances["blue"])
    assert instance.live_identity and instance.app_state
    vmid = (await get(Machine, env.machines["blue"])).ids["vmid"]
    await set_rows(Machine, env.machines["blue"], keep_vm_snapshots=2)
    # A ready backup of the slot, a manual snapshot and four automatic ones (two too many), oldest first.
    backup_id = uuid.uuid4()
    async with get_sessionmaker()() as db:
        db.add(Backup(id=backup_id, instance_id=instance.id, name=data.backup_name(backup_id, utcnow()),
                      reason="manual", status="ready", format="demo-v1", identity_fp="x", taken_at=utcnow(),
                      db_bytes=5))
        await db.commit()
    manual = await add_row(env, snap_name(500), world=world, vmid=vmid)
    autos = [await add_row(env, snap_name(400 - 10 * i), reason=reason, world=world, vmid=vmid)
             for i, reason in enumerate(("pre_resize", "pre_revert", "pre_resize", "pre_revert"))]
    seen: list[MachineSnapshot] = []
    real = pxp.ProxmoxProvider.snapshot

    async def spy(self, ctx, row):
        seen.append(await get(MachineSnapshot, row.id))  # what the database holds when the task starts
        return await real(self, ctx, row)

    monkeypatch.setattr(pxp.ProxmoxProvider, "snapshot", spy)
    dep = await run(await queue(env, "vm_snapshot", note="Before the upgrade"), world)
    assert dep.status == "succeeded", (dep.error, dep.log[-3000:])
    assert list(statuses(dep).items()) == [("check", "succeeded"), ("vm_snapshot", "succeeded"),
                                           ("prune", "succeeded")]

    stored = seen[0]
    assert stored.status == "pending" and stored.reason == "manual" and stored.note == "Before the upgrade"
    assert stored.app_state == instance.app_state and stored.commit_sha == instance.current_commit_sha
    assert stored.fresh_data == instance.fresh_data
    assert stored.identity == instance.live_identity
    assert stored.identity_fp == data.identity_fp(stored.id, sorted(instance.live_identity), instance.live_identity)
    assert stored.backups == [data.backup_name(backup_id, (await get(Backup, backup_id)).taken_at)]
    machine = await get(Machine, env.machines["blue"])
    assert stored.sizes == {k: machine.applied[k] for k in ("cores", "memory_mb", "disk_gb")}
    taken = await get(MachineSnapshot, stored.id)
    assert taken.status == "ready" and taken.deployment_id == dep.id
    assert taken.name in [s["name"] for s in world.fake.vm(vmid)["snapshots"]]

    # Prune: the two oldest automatic ones go (row and hypervisor), the manual one and the newest two stay.
    left = {r.name for r in await rows(env)}
    assert left == {manual.name, autos[2].name, autos[3].name, taken.name}
    on_pve = {s["name"] for s in world.fake.vm(vmid)["snapshots"]}
    assert autos[0].name not in on_pve and autos[1].name not in on_pve and manual.name in on_pve
    assert note(dep, "prune") == f"Deleted {autos[0].name}, {autos[1].name}"

    shot = await audits("machine.snapshot")
    assert [(a.details["snapshot"], a.details["reason"]) for a in shot] == [(taken.name, "manual")]
    deleted = await audits("machine.snapshot_delete")
    assert [a.details for a in deleted] == [
        {"name": VM, "snapshot": autos[0].name, "reason": "pre_resize", "why": "prune"},
        {"name": VM, "snapshot": autos[1].name, "reason": "pre_revert", "why": "prune"}]
    secret = next(iter(instance.live_identity.values()))
    for row in [*shot, *deleted]:
        assert secret not in json.dumps(row.details) and secret not in (row.summary or "")


async def test_46_a_retry_settles_the_failed_attempts_pending_rows_first(world):
    env = await pve_ready(world)
    there = await add_row(env, snap_name(20), status="pending", world=world)
    gone = await add_row(env, snap_name(15), status="pending")
    lost = await add_row(env, snap_name(10), status="ready")
    dep = await run(await queue(env, "vm_snapshot"), world)
    assert dep.status == "succeeded", (dep.error, dep.log[-2000:])
    assert (await get(MachineSnapshot, there.id)).status == "ready"
    assert (await get(MachineSnapshot, gone.id)).status == "failed"
    assert (await get(MachineSnapshot, lost.id)).status == "missing"
    assert f"The VM snapshot {there.name} is on Proxmox after all: it is ready" in dep.log


async def test_46_check_refuses_at_run_time_what_changed_since_the_queue(world):
    env = await pve_ready(world)
    # snapshot_mode none (P5 test 47's last case): vm_snapshot's check refuses.
    dep_id = await raw(env, "vm_snapshot")
    await set_rows(Machine, env.machines["blue"], snapshot_mode="none")
    mark = len(world.fake.requests)
    dep = await run(dep_id, world)
    assert dep.status == "failed" and statuses(dep)["check"] == "failed"
    assert dep.error == "local-lvm (lvmthin) can't take VM snapshots of slipway-uat-blue"
    assert not pve_writes(world, mark) and not await rows(env)
    # The VM gone from Proxmox: the lost text (M3).
    await set_rows(Machine, env.machines["blue"], snapshot_mode="any")
    world.fake.remove_vm(100)
    dep = await run(await raw(env, "vm_snapshot"), world)
    assert dep.status == "failed"
    assert dep.error.startswith("slipway-uat-blue is gone from lab, and uat's data was on it")
    assert not await rows(env)


async def test_46_a_snapshot_that_fails_before_its_task_is_failed_and_one_that_ends_late_is_ready(world, monkeypatch):
    env = await pve_ready(world)
    world.fake.snapshot_task_late()
    monkeypatch.setattr(pxp, "LATE_GRACE", 0)
    monkeypatch.setattr(pxp, "TASK_TIMEOUTS", {**pxp.TASK_TIMEOUTS, "snapshot": 0.05})
    dep = await run(await queue(env, "vm_snapshot"), world)
    assert dep.status == "succeeded", (dep.error, dep.log[-2000:])
    (row,) = await rows(env)
    assert row.status == "ready" and row.note == "The task ended late"
    assert note(dep, "vm_snapshot").endswith("The task ended late")


async def test_46_prune_never_deletes_an_esxi_duplicate(tmp_path, monkeypatch, net):
    w = EsxiWorld(tmp_path, monkeypatch, net)
    env = await esxi_blue_env(w)
    ctx = await vf.context(env.machines["blue"], connect=w.vms.connect, deployment_id=await _running(env),
                           user_id=env.user_id)
    assert (await machines.prepare(ctx))[0] == "succeeded"
    await idle(env)
    await set_rows(Machine, env.machines["blue"], keep_vm_snapshots=1)
    vm = w.vm()
    twice = snap_name(300)
    for _ in range(2):
        w.fake._snapshot(vm, twice, "", quiesced=False)
    await add_row(env, twice, reason="pre_resize", minutes_ago=300)
    newer = await add_row(env, snap_name(200), reason="pre_revert", minutes_ago=200)
    w.fake._snapshot(vm, newer.name, "", quiesced=False)
    dep = await run(await queue(env, "vm_snapshot"), w)
    assert dep.status == "succeeded", (dep.error, dep.log[-2000:])
    assert statuses(dep)["prune"] == "warning"
    assert note(dep, "prune") == f"Kept {twice}: each name appears more than once"
    assert f"esx-01 has 2 VM snapshots named {twice}; Slipway won't pick one, so it keeps them" in dep.log
    assert [s.name for s in vm.snaps].count(twice) == 2
    assert twice in {r.name for r in await rows(env)}
    assert not w.calls("delete_snapshot")
    taken = next(r for r in await rows(env) if r.reason == "manual")
    assert taken.status == "ready" and taken.quiesced is True


async def _running(env: vf.VmEnv) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=env.instances["blue"], environment_id=env.env_id, kind="deploy",
                         triggered_by_id=env.user_id, branch="main", log="", status="running")
        db.add(dep)
        await db.commit()
        return dep.id


# ----------------------------------------------------------------------- P5 test 43: the ESXi half


async def test_43_a_deploy_to_a_ready_esxi_vm_never_shuts_it_down(tmp_path, monkeypatch, net):
    w = EsxiWorld(tmp_path, monkeypatch, net)
    env = await esxi_blue_env(w)
    first = await run_vm(w, env)
    assert first.status == "succeeded", (first.error, first.log[-3000:])
    assert (await get(Machine, env.machines["blue"])).stage == "ready"
    await live(env)
    mark = len(w.fake.calls)
    again = await run_vm(w, env)
    assert again.status == "succeeded", (again.error, again.log[-3000:])
    assert "resize" not in statuses(again)
    called = [c[0] for c in w.fake.calls[mark:]]
    assert not {"shutdown_guest", "power_off", "set_size", "grow_disk", "destroy"} & set(called)


# --------------------------------------------------------------------- P5 test 47: vm_revert


def test_47_the_typed_name_comes_first_then_data_reset():
    env = SimpleNamespace(name="uat")
    nobody = SimpleNamespace(can=lambda permission: False)
    got = vm_jobs.revert_request_problem(env, "UAT", nobody)
    assert (got.status, got.text) == (422, "Type the environment's name, uat, exactly to confirm")
    machines_only = SimpleNamespace(can=lambda permission: permission == "machines:write")
    got = vm_jobs.revert_request_problem(env, "uat", machines_only)
    assert (got.status, got.text) == (403, "Reverting to a VM snapshot needs the data:reset permission")
    got = vm_jobs.revert_request_problem(env, "uat", nobody)
    assert (got.status, got.text) == (403, "Reverting to a VM snapshot needs the machines:write permission")
    assert vm_jobs.revert_request_problem(env, "uat", SimpleNamespace(can=lambda permission: True)) is None


async def test_47_each_refusal_of_a_revert_at_the_queue():
    env = await vm_world_env(ready=True)
    other = await vm_world_env(ready=True, name="qa")
    row = await add_row(env, snap_name(60))
    theirs = MachineSnapshot(machine_id=other.machines["blue"], name=snap_name(60), reason="manual", status="ready",
                             identity_fp="x", backups=[], sizes={}, taken_at=utcnow())
    async with get_sessionmaker()() as db:
        db.add(theirs)
        await db.commit()
    got = await refusal(env, "vm_revert", user=await developer(), vm_snapshot_id=row.id.hex)
    assert (got.status, got.text) == (403, "Reverting to a VM snapshot needs the machines:write permission")
    got = await refusal(env, "vm_revert", vm_snapshot_id=theirs.id.hex)
    assert (got.status, got.text) == (409, "That VM snapshot isn't one of uat's")
    pending = await add_row(env, snap_name(5), status="pending")
    got = await refusal(env, "vm_revert", vm_snapshot_id=pending.id.hex)
    assert (got.status, got.text) == (409, f"The VM snapshot {pending.name} isn't ready (pending)")
    assert await refusal(env, "vm_revert", vm_snapshot_id=row.id.hex) is None
    # The owner's hold doesn't refuse a revert (it is one way out); it refuses a snapshot.
    await set_rows(Instance, env.instances["blue"], data_dirty={"hold": True, "first": {}, "last": {}})
    assert await refusal(env, "vm_revert", vm_snapshot_id=row.id.hex) is None
    assert (await refusal(env, "vm_snapshot")).status == 409
    await set_rows(Instance, env.instances["blue"], data_dirty=None)
    # ZFS: a newer snapshot Slipway took refuses a revert to an older one.
    await set_rows(Machine, env.machines["blue"], snapshot_mode="newest_only")
    newer = await add_row(env, snap_name(30))
    got = await refusal(env, "vm_revert", vm_snapshot_id=row.id.hex)
    assert (got.status, got.text) == (409, f"Proxmox can roll ZFS back only to the newest VM snapshot; {newer.name} "
                                           f"is newer. Delete it first, or revert to {newer.name}")
    assert await refusal(env, "vm_revert", vm_snapshot_id=newer.id.hex) is None


async def lock_file(env: vf.VmEnv) -> Path:
    instance = await get(Instance, env.instances["blue"])
    return Path(deployer.paths_for(instance).lock)


async def host_backup(env: vf.VmEnv, minutes_ago: int) -> Backup:
    """A ready backup whose dump is on the VM's fake host."""
    instance = await get(Instance, env.instances["blue"])
    backup_id = uuid.uuid4()
    at = utcnow() - dt.timedelta(minutes=minutes_ago)
    row = Backup(id=backup_id, instance_id=instance.id, name=data.backup_name(backup_id, at), reason="manual",
                 status="ready", format="demo-v1", identity_fp="x", taken_at=at, db_bytes=5)
    folder = Path(deployer.paths_for(instance).backups)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{row.name}.dump").write_bytes(b"dump\n")
    async with get_sessionmaker()() as db:
        db.add(row)
        await db.commit()
    return row


REAL_REVERT = pxp.ProxmoxProvider.revert


def disk_goes_back(monkeypatch: Any, env: vf.VmEnv, *, after: Any = None) -> list[str]:
    """The fake revert takes the VM's disk back: the backups taken after the snapshot leave the fake host."""
    seen: list[str] = []
    async def revert(self, ctx, row):
        await REAL_REVERT(self, ctx, row)
        seen.append(row.name)
        instance = await get(Instance, env.instances["blue"])
        folder = Path(deployer.paths_for(instance).backups)
        for file in folder.glob("*.dump"):
            if file.name.split(".")[0] not in (row.backups or []):
                file.unlink()
        if after is not None:
            after()

    monkeypatch.setattr(pxp.ProxmoxProvider, "revert", revert)
    return seen


async def test_47_a_revert_puts_the_vm_and_slipways_records_back(world, monkeypatch):
    env = await pve_deployed(world)
    before_backup = await host_backup(env, 120)
    taken = await run(await queue(env, "vm_snapshot"), world)
    assert taken.status == "succeeded", (taken.error, taken.log[-2000:])
    (row,) = [r for r in await rows(env) if r.reason == "manual"]
    assert row.backups == [before_backup.name] and row.identity
    after_backup = await host_backup(env, 0)
    # Everything moves on after the snapshot: another release, other identity values, a hold, a stale lock line.
    instance = await get(Instance, env.instances["blue"])
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, instance.id)
        inst.app_state = {**(inst.app_state or {}), "later": True}
        inst.current_commit_sha = "f" * 40
        inst.fresh_data = None
        inst.live_identity = {"APP_KEY": "a-later-key"}
        inst.data_dirty = {"hold": True, "first": {}, "last": {}}
        env_row = await db.get(Environment, env.env_id)
        env_row.app_secrets = {**(env_row.app_secrets or {}), "APP_KEY": "a-later-key"}
        version = env_row.secrets_version
        await db.execute(update(Machine).where(Machine.id == env.machines["blue"])
                         .values(applied={"cores": 8, "memory_mb": 8192, "disk_gb": 64}))
        await db.commit()
    lock = await lock_file(env)
    lock.write_text("stale-job 4242 deploy 1\n")
    reverted = disk_goes_back(monkeypatch, env)
    docker_before = len(world.vms["blue"].docker())

    dep = await run(await queue(env, "vm_revert", vm_snapshot_id=row.id.hex), world)
    assert dep.status == "succeeded", (dep.error, dep.log[-3000:])
    assert list(statuses(dep)) == ["check", "vm_snapshot", "vm_revert", "wait", "vm_settle", "restart", "traffic"]
    assert statuses(dep)["traffic"] in ("skipped", "succeeded", "warning")
    assert reverted == [row.name]
    pre = next(r for r in await rows(env) if r.reason == "pre_revert")
    assert pre.status == "ready" and dep.options["vm_snapshot_pre"] == pre.id.hex
    assert any(r["path"].endswith(f"/snapshot/{row.name}/rollback") for r in world.fake.requests)

    assert not lock.exists() or "stale-job" not in lock.read_text()
    assert f"$ : > {lock}" in dep.log
    inst = await get(Instance, instance.id)
    assert inst.app_state == row.app_state and inst.current_commit_sha == row.commit_sha
    assert inst.fresh_data == row.fresh_data and inst.live_identity == row.identity
    assert inst.data_dirty is None and inst.status == "running"
    env_row = await get(Environment, env.env_id)
    assert env_row.app_secrets["APP_KEY"] == row.identity["APP_KEY"]
    assert env_row.secrets_version == version + 1
    machine = await get(Machine, env.machines["blue"])
    assert {k: machine.applied[k] for k in ("cores", "memory_mb", "disk_gb")} == row.sizes
    assert (await get(Backup, after_backup.id)).status == "missing"
    assert (await get(Backup, before_backup.id)).status == "ready"
    restart = dep.log[dep.log.index("Start the app again"):]
    assert "docker compose -p demo-uat-blue-web start" in restart
    assert "ps -aq --filter label=com.docker.compose.project=demo-uat-blue-web" in \
        world.vms["blue"].docker()[docker_before:]
    notice = env_row.notice
    assert notice["text"].startswith(f"Reverted to {row.name} (")
    assert f"Backups taken after it were on the VM and are gone: {after_backup.name}." in notice["text"]
    assert notice["text"].endswith("Settings changed since then apply at the next deploy.")
    assert notice["deployment_id"] == dep.id.hex and notice["next"] is None
    (audit_row,) = await audits("machine.revert")
    assert audit_row.details == {"name": VM, "snapshot": row.name, "taken_at": row.taken_at.isoformat(),
                                 "commit_sha": row.commit_sha, "identity_restored": True}
    for a in [audit_row, *await audits("machine.snapshot")]:
        assert row.identity["APP_KEY"] not in json.dumps(a.details) and "a-later-key" not in json.dumps(a.details)
    assert row.identity["APP_KEY"] not in dep.log


async def test_47_traffic_is_warning_only(world, monkeypatch):
    env = await pve_deployed(world)
    await run(await queue(env, "vm_snapshot"), world)
    (row,) = [r for r in await rows(env) if r.reason == "manual"]

    async def down(c):
        raise RuntimeError("Switchyard is down")

    monkeypatch.setattr(deployer, "_traffic", down)
    dep = await run(await queue(env, "vm_revert", vm_snapshot_id=row.id.hex, skip_pre_revert=True), world)
    assert dep.status == "succeeded", (dep.error, dep.log[-2000:])
    assert "vm_snapshot" not in statuses(dep)
    assert (statuses(dep)["traffic"], note(dep, "traffic")) == ("warning", "Switchyard is down")


async def test_47_a_failed_wait_holds_the_data_and_the_retry_keeps_the_first_pre_revert(world, monkeypatch):
    env = await pve_ready(world)
    row = await add_row(env, snap_name(60), world=world)
    monkeypatch.setattr(vm_jobs, "WAIT_TRIES", 3)
    disk_goes_back(monkeypatch, env, after=lambda: world.vms.booting(BLUE, 100))
    first = await run(await queue(env, "vm_revert", vm_snapshot_id=row.id.hex), world)
    assert first.status == "failed" and statuses(first)["wait"] == "failed"
    assert first.error == f"{VM} didn't answer SSH at {BLUE} in 10 minutes"
    dirty = (await get(Instance, env.instances["blue"])).data_dirty
    assert dirty["hold"] is True and dirty["last"]["step"] == "wait"
    assert dirty["last"]["text"] == (f"Slipway couldn't finish reverting {VM} to {row.name}. The VM's disk may "
                                     f"already be back at {row.name} while Slipway's records name a later release: "
                                     f"revert to {row.name} again")
    pre = next(r for r in await rows(env) if r.reason == "pre_revert")
    assert pre.status == "ready"

    world.vms["blue"].refuse = 0
    monkeypatch.setattr(pxp.ProxmoxProvider, "revert", REAL_REVERT)  # undo the booting hook
    disk_goes_back(monkeypatch, env)
    retry = await run(await queue(env, "vm_revert", retry_of=first.id), world)
    assert retry.status == "succeeded", (retry.error, retry.log[-2000:])
    assert (statuses(retry)["vm_snapshot"], note(retry, "vm_snapshot")) == \
        ("skipped", f"Kept {pre.name}, which the first attempt took")
    assert [r.reason for r in await rows(env)].count("pre_revert") == 1
    assert (await get(Instance, env.instances["blue"])).data_dirty is None


async def test_47_wait_with_another_key_fails_and_pins_nothing(world, monkeypatch):
    env = await pve_ready(world)
    row = await add_row(env, snap_name(60), world=world)
    pinned = (await get(Instance, env.instances["blue"])).host.host_key
    disk_goes_back(monkeypatch, env, after=lambda: world.vms.new_key(BLUE))
    dep = await run(await queue(env, "vm_revert", vm_snapshot_id=row.id.hex, skip_pre_revert=True), world)
    assert dep.status == "failed" and statuses(dep)["wait"] == "failed"
    assert dep.error == (f"{VM} answered SSH at {BLUE} with a key that isn't the one Slipway pinned; Slipway pinned "
                         "nothing")
    assert (await get(Instance, env.instances["blue"])).host.host_key == pinned


async def test_47_a_restart_that_fails_leaves_records_matching_the_vm(world, monkeypatch):
    env = await pve_deployed(world)
    await run(await queue(env, "vm_snapshot"), world)
    (row,) = [r for r in await rows(env) if r.reason == "manual"]
    await set_rows(Instance, env.instances["blue"], current_commit_sha="f" * 40)
    disk_goes_back(monkeypatch, env)
    monkeypatch.setattr(deployer, "control_command", lambda instance, action: "echo 'no such project' >&2; exit 3")
    dep = await run(await queue(env, "vm_revert", vm_snapshot_id=row.id.hex, skip_pre_revert=True), world)
    assert dep.status == "failed" and statuses(dep)["restart"] == "failed"
    assert statuses(dep)["vm_settle"] == "succeeded"
    assert dep.error.startswith(f"{VM} is back at {row.name}, but uat didn't start: ")
    assert dep.error.endswith("Start it from the instance page")
    inst = await get(Instance, env.instances["blue"])
    assert inst.current_commit_sha == row.commit_sha and inst.app_state == row.app_state
    assert inst.status == "stopped" and not (inst.data_dirty or {}).get("hold")
    assert dep.options["settled"] is True
    async with get_sessionmaker()() as db:
        retry = await deployer.retry_values(db, await db.get(Deployment, dep.id))
    assert "settled" not in retry["options"]  # a retry that fails while reverting holds the data again
    assert retry["options"]["vm_snapshot_id"] == row.id.hex


async def test_47_on_zfs_a_revert_past_a_newer_snapshot_is_refused_in_check_and_the_newest_takes_no_pre_revert(
        tmp_path, monkeypatch, net):
    from tests.test_provider_proxmox import a_world  # noqa: PLC0415

    world = a_world(tmp_path, monkeypatch, net, storage_type="zfspool")
    env = await pve_ready(world, storage_type="zfspool")
    assert (await get(Machine, env.machines["blue"])).snapshot_mode == "newest_only"
    old = await add_row(env, snap_name(60), world=world)
    world.fake.add_snapshot(100, "by-hand")  # someone else's, newer: Slipway's records can't see it
    mark = len(world.fake.requests)
    dep = await run(await queue(env, "vm_revert", vm_snapshot_id=old.id.hex), world)
    assert "vm_snapshot" not in statuses(dep)  # never a pre_revert on ZFS
    assert dep.status == "failed" and statuses(dep)["check"] == "failed"
    assert dep.error == ("Proxmox can roll ZFS back only to the newest VM snapshot; by-hand is newer. Delete it "
                         f"first, or revert to by-hand")
    assert not pve_writes(world, mark)

    world.fake.add_snapshot(100, (newest := snap_name(1)))
    row = await add_row(env, newest, minutes_ago=1)
    disk_goes_back(monkeypatch, env)
    dep = await run(await queue(env, "vm_revert", vm_snapshot_id=row.id.hex), world)
    assert dep.status == "succeeded", (dep.error, dep.log[-2000:])
    assert "vm_snapshot" not in statuses(dep)
    assert not [r for r in await rows(env) if r.reason == "pre_revert"]
    assert any(r["path"].endswith(f"/snapshot/{newest}/rollback") for r in world.fake.requests)


async def test_47_check_refuses_a_name_gone_from_the_hypervisor(world):
    env = await pve_ready(world)
    row = await add_row(env, snap_name(60))  # recorded, not on Proxmox
    mark = len(world.fake.requests)
    dep = await run(await queue(env, "vm_revert", vm_snapshot_id=row.id.hex), world)
    assert dep.status == "failed" and dep.error == f"The VM snapshot {row.name} is gone from lab"
    assert not pve_writes(world, mark)
    assert (await get(MachineSnapshot, row.id)).status == "missing"
    assert not (await get(Instance, env.instances["blue"])).data_dirty


# --------------------------------------------------------------------------- P5 test 48: vm_drop


async def test_48_vm_drop_deletes_on_the_hypervisor_and_the_row(world):
    env = await pve_ready(world)
    row = await add_row(env, snap_name(60), world=world)
    dep = await run(await queue(env, "vm_drop", vm_snapshot_id=row.id.hex), world)
    assert dep.status == "succeeded", (dep.error, dep.log[-2000:])
    assert note(dep, "vm_drop") == f"Deleted {row.name}"
    assert row.name not in {s["name"] for s in world.fake.vm(100)["snapshots"]}
    assert await rows(env) == []
    (a,) = await audits("machine.snapshot_delete")
    assert a.details == {"name": VM, "snapshot": row.name, "reason": "manual", "why": "deleted"}


async def test_48_a_name_gone_from_the_hypervisor_just_deletes_the_row(world):
    env = await pve_ready(world)
    row = await add_row(env, snap_name(60))
    mark = len(world.fake.requests)
    dep = await run(await queue(env, "vm_drop", vm_snapshot_id=row.id.hex), world)
    assert dep.status == "succeeded", (dep.error, dep.log[-2000:])
    assert note(dep, "vm_drop") == f"{row.name} was already gone from lab; Slipway forgot it"
    assert not pve_writes(world, mark) and await rows(env) == []


async def test_48_a_pending_row_refuses(world):
    env = await pve_ready(world)
    row = await add_row(env, snap_name(5), status="pending", world=world)
    got = await refusal(env, "vm_drop", vm_snapshot_id=row.id.hex)
    assert (got.status, got.text) == (409, f"The VM snapshot {row.name} is still being taken; wait for it to finish")
    dep = await run(await raw(env, "vm_drop", vm_snapshot_id=row.id.hex), world)
    assert dep.status == "failed" and dep.error == got.text
    assert len(await rows(env)) == 1
    got = await refusal(env, "vm_drop", user=await developer(), vm_snapshot_id=row.id.hex)
    assert (got.status, got.text) == (403, "Deleting a VM snapshot needs the machines:write permission")


# ------------------------------------------------------------ P5 test 49: recovery (the revert half)


async def interrupted(env: vf.VmEnv, kind: str, cut: str, **options: Any) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        instance = await db.get(Instance, env.instances["blue"])
        rows_ = deployer.steps_for(instance, kind)
        seen = False
        for r in rows_:
            if r["key"] == cut:
                r["status"], seen = "running", True
            elif not seen:
                r["status"] = "succeeded"
        dep = Deployment(instance_id=instance.id, environment_id=env.env_id, kind=kind, branch="main", log="",
                         status="running", options=options, steps=rows_)
        db.add(dep)
        await db.commit()
        return dep.id


async def test_49_an_interrupted_revert_holds_the_data_and_offers_only_reverting_again(world):
    env = await pve_ready(world)
    row = await add_row(env, snap_name(60), world=world)
    dep_id = await interrupted(env, "vm_revert", "vm_revert", vm_snapshot_id=row.id.hex)
    await deployer.runner.recover_interrupted()
    text = (f"Slipway restarted while reverting {VM} to {row.name}. The VM's disk may already be back at {row.name} "
            f"while Slipway's records name a later release: revert to {row.name} again")
    dirty = (await get(Instance, env.instances["blue"])).data_dirty
    assert dirty["hold"] is True and dirty["last"]["text"] == text and dirty["last"]["step"] == "vm_revert"
    dep = await get(Deployment, dep_id)
    assert dep.status == "failed" and dep.error == f"Interrupted by a Slipway restart. {text}"
    # Reverting again is accepted, a retry too; the hold refuses a VM snapshot and a deploy.
    assert await refusal(env, "vm_revert", vm_snapshot_id=row.id.hex) is None
    async with get_sessionmaker()() as db:
        instance = await db.get(Instance, env.instances["blue"])
        who = await db.get(User, (await maintainer()).id)
        assert await jobs.job_refusal(db, instance=instance, user=who, kind="vm_revert", retry_of=dep,
                                      options={"vm_snapshot_id": row.id.hex}) is None
    assert (await refusal(env, "vm_snapshot")).status == 409
    assert (await refusal(env, "deploy")).status == 409
    # The hold's refusal shows §9.12's text, not P2's offer of a restore.
    async with get_sessionmaker()() as db:
        held = await data.hold_text(db, await db.get(Instance, env.instances["blue"]))
    assert held == f"{text}. Start, Restart and Deploy are off until then."
    assert "restore" not in held


async def test_49_a_revert_cut_off_after_its_records_settled_holds_nothing(world):
    env = await pve_ready(world)
    row = await add_row(env, snap_name(60), world=world)
    await interrupted(env, "vm_revert", "restart", vm_snapshot_id=row.id.hex, settled=True)
    await deployer.runner.recover_interrupted()
    assert not (await get(Instance, env.instances["blue"])).data_dirty


async def test_49_a_pending_snapshot_of_an_interrupted_job_fails_then_is_ready_when_found(world):
    env = await pve_ready(world)
    dep_id = await interrupted(env, "vm_snapshot", "vm_snapshot")
    row = await add_row(env, snap_name(3), status="pending", deployment_id=dep_id, world=world)
    await deployer.runner.recover_interrupted()
    stored = await get(MachineSnapshot, row.id)
    assert stored.status == "failed" and stored.note == "Slipway restarted while taking it"
    assert (await get(Instance, env.instances["blue"])).status != "failed"
    dep = await run(await queue(env, "vm_snapshot"), world)  # the next check reads the hypervisor
    assert dep.status == "succeeded", (dep.error, dep.log[-2000:])
    assert (await get(MachineSnapshot, row.id)).status == "ready"


async def test_a_vm_job_never_marks_the_instance_deploying_or_failed(world, monkeypatch):
    env = await pve_ready(world)
    await set_rows(Instance, env.instances["blue"], status="running")
    seen: list[str] = []
    real = pxp.ProxmoxProvider.snapshot

    async def spy(self, ctx, row):
        seen.append((await get(Instance, env.instances["blue"])).status)
        raise vm_jobs.MachineError("Proxmox didn't take it")

    monkeypatch.setattr(pxp.ProxmoxProvider, "snapshot", spy)
    dep = await run(await queue(env, "vm_snapshot"), world)
    assert dep.status == "failed" and dep.error == "Proxmox didn't take it"
    assert seen == ["running"]
    assert (await get(Instance, env.instances["blue"])).status == "running"
    (row,) = await rows(env)
    assert row.status == "failed"  # no task was started for it
    monkeypatch.setattr(pxp.ProxmoxProvider, "snapshot", real)
