"""The environment jobs of an environment on VMs (phase 5 §9.5, §9.9, §9.10, §10.3, §10.4, D26): Remove slot,
Delete, Forget the VM and Activate's VM checks.

Numbered tests of P5 §16.2: 40b, 54 (the remove half), 55 (the job half), 56 and 65, plus the ``machine.forget``
audit. Proxmox is ``tests/fake_proxmox.py`` with ``tests/bin/fake-terraform`` (the Proxmox provider tests' World);
ESXi is ``tests/fake_esxi.py`` (the ESXi provider tests' World); the VMs are ``tests/fake_vm_hosts.py``. Every
job runs through ``deployer.run_deployment`` and ``env_jobs``; the machines core and the providers are the real
ones. The HTTP halves (typed names, 422s, the routes) are S20's and S22's.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx
import pytest
from sqlalchemy import select, update

from slipway.db.base import utcnow
from slipway.db.session import get_sessionmaker
from slipway.models import (
    AddressClaim,
    AuditEvent,
    Backup,
    Deployment,
    Environment,
    Host,
    Instance,
    Machine,
    MachineSnapshot,
    ProviderAccount,
    Resource,
    TerraformState,
    User,
)
from slipway.services import deployer, env_jobs, environments, hosts, jobs, machines, proxmox, ssh, terraform
from slipway.services.providers import esxi as exp
from slipway.services.providers import proxmox as pxp
from slipway.services.vmtypes import MachineError
from tests import fake_switchyard
from tests import vm_fixtures as vf
from tests.conftest import make_user
from tests.test_provider_esxi import World as EsxiWorld
from tests.test_provider_proxmox import World, net, world  # noqa: F401  (fixtures)

BLUE, GREEN, DATA = "10.0.0.100", "10.0.0.101", "10.0.0.102"
ADDRESSES = {"blue": BLUE, "green": GREEN, "data": DATA}
SHA = "0123456789abcdef0123456789abcdef01234567"


@pytest.fixture
def submitted(monkeypatch) -> list[tuple[uuid.UUID, tuple]]:
    """Jobs a chain queues are recorded, not run."""
    found: list[tuple[uuid.UUID, tuple]] = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, keys: found.append((dep_id, keys)))
    return found


@pytest.fixture
def quick_tasks(monkeypatch) -> None:
    """A task another hand runs on a VM outlives Slipway's wait at once (the wait counts real sleeps)."""
    monkeypatch.setattr(machines, "TASK_WAIT_LIMIT", 0.03)
    monkeypatch.setattr(machines, "TASK_POLL", 0.01)


# ------------------------------------------------------------------------------------------------ helpers


async def _get(model, row_id):
    async with get_sessionmaker()() as db:
        return await db.get(model, row_id)


async def _set(model, row_id, **values) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(update(model).where(model.id == row_id).values(**values))
        await db.commit()


async def _all(model, *where) -> list[Any]:
    async with get_sessionmaker()() as db:
        return list(await db.scalars(select(model).where(*where)))


async def _audits(action: str) -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        return list(await db.scalars(select(AuditEvent).where(AuditEvent.action == action)
                                     .order_by(AuditEvent.created_at)))


async def pve_env(w: World, *, slots: tuple[str, ...] = ("blue", "green"), mode: str = "server", name: str = "uat",
                  addresses: dict[str, str] | None = None, account: ProviderAccount | None = None) -> vf.VmEnv:
    """An environment of Proxmox VMs planned at fixed addresses, a fake VM host at each."""
    addresses = addresses or ADDRESSES
    wanted = [*slots, *(["data"] if mode == "server" else [])]
    account = account or await vf.proxmox_account()
    for slot in wanted:
        if addresses[slot] not in w.vms.by_address:
            w.vms.add_vm(f"{name}-{slot}", addresses[slot])
    return await vf.vm_env(account, name=name, mode=mode, slots=slots,
                           addresses={s: addresses[s] for s in wanted}, provider=pxp.ProxmoxProvider())


async def ready(w: World, env: vf.VmEnv, slot: str, *, status: str = "running") -> int:
    """Make ``slot``'s VM as a finished prepare leaves it: a reserved id (its ``vm`` row), the VM on Proxmox with
    Slipway's tags at its address, the machine ready and its host pinned. Returns the VM id."""
    ctx = await vf.context(env.machines[slot], connect=w.vms.connect, user_id=env.user_id)
    async with proxmox.ProxmoxClient.for_account(ctx.account, sleep=vf.no_sleep) as api:
        vmid = await machines.reserve_vmid(ctx.machine, ctx.account, api=api, user_id=env.user_id)
    address = env.addresses[slot]
    key = w.vms.pinned_key(address)
    w.fake.add_vm(vmid, ctx.vm, tags=terraform.vm_tags(env.env_id), address=address, host_key=key, status=status,
                  description=terraform.vm_description(env.name, env.env_id, slot))
    async with get_sessionmaker()() as db:
        row = await db.get(Machine, env.machines[slot])
        h = await db.get(Host, row.host_id)
        row.stage, row.ready_at = "ready", utcnow()
        row.applied = {**row.size, "at": utcnow().isoformat(), "deployment_id": None}
        row.host_key_public = key
        hosts.set_phase(h, "ready", stage="ready")
        h.host_key, h.host_key_fingerprint = key, ssh.fingerprint(key)
        await db.commit()
    return vmid


async def all_ready(w: World, env: vf.VmEnv) -> dict[str, int]:
    return {slot: await ready(w, env, slot) for slot in env.machines}


async def deployed(env: vf.VmEnv, slot: str, *, status: str = "succeeded") -> uuid.UUID:
    """A finished deploy of ``slot``: the slot runs commit SHA."""
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=env.instances[slot], environment_id=env.env_id, kind="deploy", status=status,
                         triggered_by_id=env.user_id, branch="main", log="", commit_sha=SHA,
                         started_at=utcnow(), finished_at=utcnow())
        db.add(dep)
        await db.execute(update(Instance).where(Instance.id == env.instances[slot])
                         .values(status="running", current_commit_sha=SHA, last_deployed_at=utcnow()))
        await db.commit()
        return dep.id


async def queue(env: vf.VmEnv, kind: str, *, raw: bool = False, user_id: uuid.UUID | None = None,
                retry_of: uuid.UUID | None = None, **options: Any) -> uuid.UUID:
    """An environment-level job through ``jobs.queue_job``, or ``raw`` as a row with its steps (a job queued
    before something changed, so its own ``check`` meets what the queue would have refused)."""
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        user = await db.get(User, user_id or env.user_id)
        if raw:
            mem = await environments.members(db, row)
            dep = Deployment(instance_id=None, environment_id=row.id, kind=kind, branch="main", options=options,
                             triggered_by_id=user.id, log="", retry_of_id=retry_of,
                             steps=environments.env_steps_for(row, kind, options, mem))
            db.add(dep)
            if kind == "teardown":
                row.status = "deleting"
        else:
            parent = await db.get(Deployment, retry_of) if retry_of is not None else None
            dep = await jobs.queue_job(db, environment=row, user=user, kind=kind, options=options, retry_of=parent)
        await db.commit()
        return dep.id


async def refusal(env: vf.VmEnv, kind: str, *, user_id: uuid.UUID | None = None,
                  **options: Any) -> jobs.JobRefused | None:
    """What ``jobs.queue_job`` (the API's queue) answers for the job, without queueing it."""
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        user = await db.get(User, user_id or env.user_id)
        return await jobs.job_refusal(db, environment=row, user=user, kind=kind, options=options)


async def run(dep_id: uuid.UUID, w: Any) -> Deployment:
    await deployer.run_deployment(dep_id, connect=w.vms.connect)
    return await _get(Deployment, dep_id)


def steps(dep: Deployment) -> dict[str, str]:
    return {r["key"]: r["status"] for r in dep.steps or []}


def note(dep: Deployment, key: str) -> str | None:
    return next((r.get("note") for r in dep.steps or [] if r["key"] == key), None)


def opened_to(w: Any, since: int, addresses: set[str]) -> list[str]:
    """The SSH sessions opened to one of ``addresses`` since the ``since``-th connect."""
    return [t.hostname for t in w.vms.targets[since:] if t.hostname in addresses]


async def rows_of(env: vf.VmEnv, slot: str) -> dict[str, int]:
    """What Slipway still records of ``slot``'s VM."""
    machine_id, host_id = env.machines[slot], env.hosts[slot]
    vm_rows = [r for r in await _all(Resource, Resource.kind == "vm")
               if (r.details or {}).get("machine_id") == str(machine_id)]
    return {
        "machine": len(await _all(Machine, Machine.id == machine_id)),
        "host": len(await _all(Host, Host.id == host_id)),
        "claim": len(await _all(AddressClaim, AddressClaim.host_id == host_id)),
        "state": len(await _all(TerraformState, TerraformState.machine_id == machine_id)),
        "vm rows": len(vm_rows),
    }


GONE = {"machine": 0, "host": 0, "claim": 0, "state": 0, "vm rows": 0}
KEPT = {"machine": 1, "host": 1, "claim": 1, "state": 0, "vm rows": 1}


def unreachable(monkeypatch) -> None:
    def refuse(pem=None):
        def handler(request):
            raise httpx.ConnectError("refused")

        return httpx.MockTransport(handler)

    monkeypatch.setattr(proxmox, "transport_factory", refuse)


# ---------------------------------------------------------------------------------- test 40b: step lists


def _member(slot: str, provider: str) -> Instance:
    host = Host(name=f"slipway-uat-{slot}" if provider != "ssh" else f"box-{slot}", hostname="h", username="u",
                provider=provider, provider_state={"phase": "ready"} if provider != "ssh" else {})
    return Instance(name=f"uat {slot}", slug=f"uat-{slot}", slot=slot, host=host, status="running")


def test_40b_remove_slot_and_teardown_list_the_vm_steps_only_with_a_vm():
    env = Environment(name="uat", data_mode="server", traffic={"switch": "none", "dns": None}, status="live")
    on_vms = {s: _member(s, "proxmox") for s in ("blue", "green", "data")}
    on_ssh = {s: _member(s, "ssh") for s in ("blue", "green", "data")}
    mixed = {"blue": _member("blue", "ssh"), "green": _member("green", "esxi"), "data": _member("data", "esxi")}

    removal = environments.env_steps_for(env, "remove_slot", {"slot": "green"}, on_vms)
    assert [(r["key"], r["name"]) for r in removal] == [
        ("check", "Check uat"), ("slot", "Remove green"), ("machine", "Remove the VM slipway-uat-green")]
    teardown = environments.env_steps_for(env, "teardown", {"confirmed": True}, on_vms)
    assert [r["key"] for r in teardown] == ["check", "unroute", "undns", "slots", "data_server", "machines", "forget"]
    assert {r["key"]: r["name"] for r in teardown}["machines"] == "Remove the VMs"

    # Members on hosts added by hand: phase 3's lists, unchanged.
    assert [r["key"] for r in environments.env_steps_for(env, "remove_slot", {"slot": "green"}, on_ssh)] == [
        "check", "slot"]
    assert [r["key"] for r in environments.env_steps_for(env, "teardown", {}, on_ssh)] == [
        "check", "unroute", "undns", "slots", "data_server", "forget"]
    # Mixed: blue on an SSH host loses no VM step of its own; the teardown removes the VMs the others are on.
    assert [r["key"] for r in environments.env_steps_for(env, "remove_slot", {"slot": "blue"}, mixed)] == [
        "check", "slot"]
    assert "machines" in [r["key"] for r in environments.env_steps_for(env, "teardown", {}, mixed)]
    # A DigitalOcean environment keeps phase 4's lists (Decision 15).
    env.provider = "digitalocean"
    assert [r["key"] for r in environments.env_steps_for(env, "teardown", {}, on_vms)] == [
        "check", "undns", "slots", "data_server", "cloud", "forget"]
    assert environments.ENV_STEP_TIMEOUTS["machine"] == 1800 and environments.ENV_STEP_TIMEOUTS["machines"] == 3600


# ------------------------------------------------------------------------ test 54: Remove slot on a VM


async def test_54_remove_slot_removes_the_vm_without_ssh(world, submitted):
    env = await pve_env(world)
    ids = await all_ready(world, env)
    await deployed(env, "green")
    since = len(world.vms.targets)
    dep = await run(await queue(env, "remove_slot", slot="green"), world)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert steps(dep) == {"check": "succeeded", "slot": "succeeded", "machine": "succeeded"}
    assert [r["name"] for r in dep.steps] == ["Check uat", "Remove green", "Remove the VM slipway-uat-green"]
    assert note(dep, "slot").startswith("slipway-uat-green goes in the next step")
    assert note(dep, "machine") == "Removed slipway-uat-green (VM 101) through the Proxmox API"
    assert opened_to(world, since, {GREEN}) == []  # nothing ran on the VM
    assert await _get(Instance, env.instances["green"]) is None
    assert await rows_of(env, "green") == GONE
    assert world.fake.vm(ids["green"]) is None
    # Blue, the data server and their VMs are untouched.
    for slot in ("blue", "data"):
        assert await _get(Instance, env.instances[slot]) is not None
        assert (await rows_of(env, slot))["machine"] == 1
        assert world.fake.vm(ids[slot]) is not None
    (removed,) = await _audits("environment.slot_remove")
    assert removed.details["slot"] == "green" and removed.details["owned"] is True
    (destroyed,) = await _audits("machine.destroy")
    assert destroyed.details == {"name": "slipway-uat-green", "ids": {"vmid": ids["green"]}}
    assert [a.details["provider_id"] for a in await _audits("resource.delete")] == [
        f"{env.account_id}:{ids['green']}"]


async def test_54_a_vm_never_made_is_removed_with_its_rows(world, submitted):
    env = await pve_env(world)
    await ready(world, env, "blue")
    dep = await run(await queue(env, "remove_slot", slot="green"), world)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert note(dep, "machine") == "slipway-uat-green was never made"
    assert await rows_of(env, "green") == {**GONE}


async def test_54_a_retry_after_slot_goes_on_with_the_vm(world, submitted, monkeypatch):
    env = await pve_env(world)
    ids = await all_ready(world, env)
    real = pxp.ProxmoxProvider.destroy
    calls: list[str] = []

    async def fails_once(self, ctx):
        calls.append(ctx.vm)
        if len(calls) == 1:
            raise MachineError("Proxmox couldn't delete VM 101 (a test's failure)")
        return await real(self, ctx)

    monkeypatch.setattr(pxp.ProxmoxProvider, "destroy", fails_once)
    dep = await run(await queue(env, "remove_slot", slot="green"), world)
    assert dep.status == "failed" and dep.error == "Proxmox couldn't delete VM 101 (a test's failure)"
    assert steps(dep) == {"check": "succeeded", "slot": "succeeded", "machine": "failed"}
    assert await _get(Instance, env.instances["green"]) is None
    assert (await _get(Machine, env.machines["green"])).stage == "destroying"

    # The retry is queued although the slot's instance is gone, and its check lists the VM's step again.
    retry = await run(await queue(env, "remove_slot", retry_of=dep.id, slot="green"), world)
    assert retry.status == "succeeded", (retry.error, retry.log)
    assert note(retry, "check") == ("green's VM slipway-uat-green isn't removed yet; Slipway goes on from where it "
                                    "stopped")
    assert note(retry, "slot") == "Already removed"
    assert steps(retry)["machine"] == "succeeded"
    assert await rows_of(env, "green") == GONE and world.fake.vm(ids["green"]) is None

    # Nothing left: a further retry says so.
    again = await run(await queue(env, "remove_slot", raw=True, retry_of=retry.id, slot="green"), world)
    assert again.status == "succeeded" and note(again, "check") == "green was already removed"


BLOCKERS = {
    "marker": (lambda w, vmid, mp: w.fake.untag(vmid), "VM 101 isn't slipway-uat-green any more", True),
    "node": (lambda w, vmid, mp: w.fake.move_node(vmid),
             "VM 101 (slipway-uat-green) is on node pve2 now, not pve1. Slipway changed nothing: move it back, or fix "
             "it by hand, then retry", True),
    "hidden": (lambda w, vmid, mp: (w.fake.remove_vm(vmid), w.fake.hidden(vmid)),
               "Slipway can't see VM 101 (check the token's rights on /pool/slipway); nothing was removed", True),
    "unreachable": (lambda w, vmid, mp: unreachable(mp),
                    "Slipway can't reach lab, so it can't remove slipway-uat-green: retry when it answers", True),
    "task": (lambda w, vmid, mp: w.fake.run_task(vmid, "vzdump", polls=None),
             "Proxmox is still running vzdump on VM 101 (since ", False),
}


@pytest.mark.parametrize("blocker", list(BLOCKERS))
async def test_54_each_blocker_refuses_the_queue_and_fails_check(world, submitted, quick_tasks, monkeypatch, blocker):
    env = await pve_env(world)
    ids = await all_ready(world, env)
    green_deploy = await deployed(env, "green")
    make, text, forgettable = BLOCKERS[blocker]
    make(world, ids["green"], monkeypatch)
    writes = len(world.writes())

    # The API's queue refuses it (409) before any job exists.
    refused = await refusal(env, "remove_slot", slot="green")
    assert refused is not None and refused.status == 409 and refused.text.startswith(text), refused

    # Queued before the blocker appeared: check fails, and nothing has gone.
    dep = await run(await queue(env, "remove_slot", raw=True, slot="green"), world)
    assert dep.status == "failed" and dep.error.startswith(text), dep.error
    assert steps(dep) == {"check": "failed", "slot": "pending", "machine": "pending"}
    assert await _get(Instance, env.instances["green"]) is not None
    assert await _get(Deployment, green_deploy) is not None
    machine = await _get(Machine, env.machines["green"])
    assert machine.stage == "ready" and machine.ids == {"vmid": ids["green"]}
    assert await rows_of(env, "green") == KEPT
    assert world.writes(writes) == []

    # forget_vms gets past a forgettable blocker only (the queue's half of it: S18 passes the option).
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        passed = await environments.remove_slot_problem(db, row, "green", forget_vms=True)
    assert (passed is None) == forgettable


async def test_54_forget_vms_forgets_a_hidden_vm_and_still_fails_on_a_task(world, submitted, quick_tasks):
    env = await pve_env(world)
    ids = await all_ready(world, env)
    world.fake.run_task(ids["green"], "vzdump", polls=None)
    dep = await run(await queue(env, "remove_slot", raw=True, slot="green"), world)
    assert dep.status == "failed" and dep.error.startswith("Proxmox is still running vzdump on VM 101")
    retry = await run(await queue(env, "remove_slot", raw=True, retry_of=dep.id, slot="green", forget_vms=True),
                      world)
    assert retry.status == "failed" and retry.error.startswith("Proxmox is still running vzdump on VM 101")
    assert await rows_of(env, "green") == KEPT

    # Gone from the token's view: hidden. forget_vms forgets it after one more read; the VM itself stays.
    with world.fake.edit() as state:
        state["tasks"] = {}
    world.fake.remove_vm(ids["green"])
    world.fake.hidden(ids["green"])
    last = await run(await queue(env, "remove_slot", raw=True, retry_of=retry.id, slot="green", forget_vms=True),
                     world)
    assert last.status == "succeeded", (last.error, last.log)
    assert steps(last) == {"check": "succeeded", "slot": "succeeded", "machine": "warning"}
    assert note(last, "machine").startswith("Forgot slipway-uat-green without removing it: Slipway can't see VM 101")
    assert await rows_of(env, "green") == GONE
    assert world.fake.vm(ids["green"]) is not None  # someone else's to remove
    (forgot,) = await _audits("machine.forget")
    assert forgot.details["why"] == "forget_vms" and forgot.details["name"] == "slipway-uat-green"
    assert forgot.details["ids"] == {"vmid": ids["green"]}
    notice = (await _get(Environment, env.env_id)).notice
    assert notice["text"] == ("Slipway forgot slipway-uat-green (VM 101 on lab) without removing it: Slipway can't see "
                              "VM 101 (check the token's rights on /pool/slipway); nothing was removed. Remove it by "
                              "hand.")
    assert notice["deployment_id"] == last.id.hex and notice["next"] is None


async def test_54_remove_slot_on_esxi_refuses_a_foreign_disk(tmp_path, monkeypatch, submitted):
    net = vf.quiet_network(monkeypatch)
    w = EsxiWorld(tmp_path, monkeypatch, net)
    account = await vf.esxi_account()
    env = await vf.vm_env(account, mode="server", slots=("blue", "green"), addresses=ADDRESSES,
                          provider=exp.EsxiProvider(),
                          deploy_roots={"green": str(tmp_path / "vms" / "host-green" / "root")})
    w.fake.addresses["slipway-uat-green"] = GREEN
    dep_id = await _job(env, "green")
    ctx = await vf.context(env.machines["green"], connect=w.vms.connect, deployment_id=dep_id, user_id=env.user_id)
    assert (await machines.prepare(ctx))[0] == "succeeded"
    await _set(Deployment, dep_id, status="succeeded")
    vm = w.fake.vm_named("slipway-uat-green")
    folder = vm.disks[0].chain[0].rsplit("/", 1)[0]
    w.fake.add_file(f"{folder}/extra.vmdk", 5)
    vm.disks.append(type(vm.disks[0])(2001, [f"{folder}/extra.vmdk"], 5))
    text = "slipway-uat-green has a disk Slipway didn't put there"

    refused = await refusal(env, "remove_slot", slot="green")
    assert refused is not None and refused.status == 409 and refused.text == text
    dep = await run(await queue(env, "remove_slot", raw=True, slot="green"), w)
    assert dep.status == "failed" and dep.error == text
    assert await _get(Instance, env.instances["green"]) is not None
    assert (await _get(Machine, env.machines["green"])).stage == "ready"
    assert not w.calls("power_off", "destroy")


async def _job(env: vf.VmEnv, slot: str) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=env.instances[slot], environment_id=env.env_id, kind="deploy", branch="main",
                         triggered_by_id=env.user_id, log="", status="running")
        db.add(dep)
        await db.commit()
        return dep.id


# ------------------------------------------------------------------------------ test 55: Delete with VMs


async def _backup(env: vf.VmEnv) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        row = Backup(instance_id=env.instances["data"], name="b-20261116-0900", reason="manual", status="ready",
                     db_bytes=10, db_sha256="0" * 64, format="demo-v1", identity_keys=[], identity_fp="x",
                     taken_at=utcnow())
        db.add(row)
        await db.commit()
        return row.id


async def test_55_teardown_removes_the_vms_green_blue_data_without_ssh(world, submitted):
    env = await pve_env(world)
    ids = await all_ready(world, env)
    since = len(world.vms.targets)
    dep = await run(await queue(env, "teardown", confirmed=True), world)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert list(steps(dep)) == ["check", "unroute", "undns", "slots", "data_server", "machines", "forget"]
    assert note(dep, "slots") == "slipway-uat-green and slipway-uat-blue go in Remove the VMs"
    assert note(dep, "data_server") == "slipway-uat-data goes in Remove the VMs"
    assert opened_to(world, since, set(ADDRESSES.values())) == []
    assert [a.details["name"] for a in await _audits("machine.destroy")] == [
        "slipway-uat-green", "slipway-uat-blue", "slipway-uat-data"]
    for slot in ("blue", "green", "data"):
        assert await rows_of(env, slot) == GONE
        assert world.fake.vm(ids[slot]) is None
    row = await _get(Environment, env.env_id)
    assert row.status == "deleted"
    assert await _all(Resource, Resource.environment_id == env.env_id) == []  # forget found nothing left


async def test_55_an_app_vm_that_fails_after_check_keeps_the_data_vm(world, submitted, monkeypatch):
    env = await pve_env(world)
    ids = await all_ready(world, env)
    real = pxp.ProxmoxProvider.destroy
    failed: list[str] = []

    async def green_fails_once(self, ctx):
        if ctx.vm == "slipway-uat-green" and not failed:
            failed.append(ctx.vm)
            raise MachineError("VM 101 is still there after Slipway deleted it. Remove it by hand in Proxmox, then "
                               "retry")
        return await real(self, ctx)

    monkeypatch.setattr(pxp.ProxmoxProvider, "destroy", green_fails_once)
    dep = await run(await queue(env, "teardown", confirmed=True), world)
    assert dep.status == "failed"
    assert dep.error == ("Slipway couldn't remove slipway-uat-green: VM 101 is still there after Slipway deleted it. "
                         "Remove it by hand in Proxmox, then retry. slipway-uat-data was kept; retry once that is "
                         "fixed")
    assert steps(dep)["machines"] == "failed" and steps(dep)["forget"] == "pending"
    assert (await rows_of(env, "data"))["machine"] == 1 and world.fake.vm(ids["data"]) is not None
    assert (await rows_of(env, "blue"))["machine"] == 1  # blue comes after green
    assert (await _get(Environment, env.env_id)).status == "deleting"

    retry = await run(await queue(env, "teardown", retry_of=dep.id), world)
    assert retry.status == "succeeded", (retry.error, retry.log)
    for slot in ("blue", "green", "data"):
        assert await rows_of(env, slot) == GONE
    assert (await _get(Environment, env.env_id)).status == "deleted"


async def test_55_a_data_vm_deleted_by_hand_is_already_gone(world, submitted):
    env = await pve_env(world)
    ids = await all_ready(world, env)
    world.fake.remove_vm(ids["data"])
    dep = await run(await queue(env, "teardown", confirmed=True), world)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert note(dep, "machines").endswith(f"VM {ids['data']} is already gone")
    assert (await _get(Environment, env.env_id)).status == "deleted"


async def test_55_a_blocker_fails_check_with_everything_still_there(world, submitted):
    env = await pve_env(world)
    ids = await all_ready(world, env)
    backup = await _backup(env)
    world.fake.untag(ids["blue"])
    dep = await run(await queue(env, "teardown", confirmed=True), world)
    assert dep.status == "failed" and dep.error == "VM 100 isn't slipway-uat-blue any more"
    assert steps(dep)["check"] == "failed" and steps(dep)["unroute"] == "pending"
    for slot in ("blue", "green", "data"):
        assert await _get(Instance, env.instances[slot]) is not None
        assert (await rows_of(env, slot))["machine"] == 1
    assert await _get(Backup, backup) is not None


async def test_55_a_hidden_data_vm_blocks_until_a_retry_with_forget_vms(world, submitted):
    env = await pve_env(world)
    ids = await all_ready(world, env)
    world.fake.remove_vm(ids["data"])
    world.fake.hidden(ids["data"])
    dep = await run(await queue(env, "teardown", confirmed=True), world)
    assert dep.status == "failed" and dep.error.startswith(f"Slipway can't see VM {ids['data']}")
    for slot in ("blue", "green", "data"):
        assert await _get(Instance, env.instances[slot]) is not None

    # forget_vms needs machines:write and environments:delete (the typed name is the API's).
    developer = await make_user("dev@example.com", roles=["developer"])
    with pytest.raises(jobs.JobRefused) as caught:
        await queue(env, "teardown", retry_of=dep.id, user_id=developer.id, forget_vms=True)
    assert caught.value.status == 403

    retry = await run(await queue(env, "teardown", retry_of=dep.id, forget_vms=True), world)
    assert retry.status == "succeeded", (retry.error, retry.log)
    assert steps(retry)["machines"] == "warning"
    row = await _get(Environment, env.env_id)
    assert row.status == "deleted"
    assert row.notice["text"].startswith(f"Slipway forgot slipway-uat-data (VM {ids['data']} on lab) without removing "
                                         "it: ")
    assert [a.details["name"] for a in await _audits("machine.destroy")] == ["slipway-uat-green", "slipway-uat-blue"]
    (forgot,) = await _audits("machine.forget")
    assert forgot.details["why"] == "forget_vms"
    assert world.fake.vm(ids["data"]) is not None


async def test_55_an_account_gone_for_good_is_forgotten_with_forget_vms(world, submitted):
    env = await pve_env(world)
    await all_ready(world, env)
    await _set(ProviderAccount, env.account_id, removed_at=utcnow())
    dep = await run(await queue(env, "teardown", confirmed=True), world)
    assert dep.status == "failed" and dep.error.startswith("lab can't be used (it was removed)")
    retry = await run(await queue(env, "teardown", retry_of=dep.id, forget_vms=True), world)
    assert retry.status == "succeeded", (retry.error, retry.log)
    assert len(await _audits("machine.forget")) == 3 and await _audits("machine.destroy") == []
    assert (await _get(Environment, env.env_id)).status == "deleted"


# ------------------------------------------------------------------------------ test 56: Forget the VM


async def forget_problem(env: vf.VmEnv, slot: str) -> jobs.JobRefused | None:
    async with get_sessionmaker()() as db:
        return await environments.forget_vm_problem(db, await db.get(Environment, env.env_id), slot)


async def test_56_forget_refuses(world, monkeypatch):
    env = await pve_env(world)
    await ready(world, env, "blue")
    await ready(world, env, "data")
    actor = await _get(User, env.user_id)

    found = await forget_problem(env, "green")
    assert (found.status, found.text) == (409, "slipway-uat-green isn't made yet: deploy to green to finish it")
    found = await forget_problem(env, "data")
    assert found.text == ("slipway-uat-data held uat's data. Slipway can't make it again without that data: delete "
                          "the environment, and create it again from a snapshot if you have one")
    found = await forget_problem(env, "blue")
    assert (found.status, found.text) == (409, "Slipway can still see slipway-uat-blue on lab: remove the slot instead")

    green_id = await ready(world, env, "green")
    await _set(Environment, env.env_id, active_slot_id=env.instances["green"])
    world.fake.remove_vm(green_id)
    found = await forget_problem(env, "green")
    assert found.text == "green takes the traffic: activate blue first"
    await _set(Environment, env.env_id, active_slot_id=env.instances["blue"])

    world.fake.hidden(green_id)
    found = await forget_problem(env, "green")
    assert found.text == (f"Proxmox still has VM {green_id}, but the token can't see it. Give it back its rights on "
                          "/pool/slipway, or remove the VM by hand, then try again")
    with world.fake.edit() as state:
        state["vms"].pop(str(green_id), None)

    job = await queue(env, "publish", raw=True)
    await _set(Deployment, job, status="running")
    found = await forget_problem(env, "green")
    assert (found.status, found.text) == (409, "A job is already running for uat (Publish names); wait for it to "
                                               "finish")
    await _set(Deployment, job, status="failed")

    unreachable(monkeypatch)
    found = await forget_problem(env, "green")
    assert (found.status, found.text) == (502, "Slipway can't check lab now, so it won't forget slipway-uat-green")
    with pytest.raises(jobs.JobRefused) as caught:
        await env_jobs.forget_vm(env.env_id, "green", actor=actor)
    assert caught.value.status == 502
    assert (await _get(Machine, env.machines["green"])).stage == "ready"
    assert await _audits("machine.forget") == []


async def test_56_forget_refuses_the_vm_of_a_mode_slot_environment(world):
    env = await pve_env(world, slots=("blue",), mode="slot", name="qa", addresses={"blue": "10.0.0.110"})
    vmid = await ready(world, env, "blue")
    world.fake.remove_vm(vmid)
    found = await forget_problem(env, "blue")
    assert found.text.startswith("slipway-qa-blue held qa's data. Slipway can't make it again without that data")


async def test_56_forget_a_lost_vm_then_the_next_deploy_makes_a_new_one(world):
    from tests.test_provider_proxmox import blue_env

    env = await blue_env(world, mode="server")
    dep = await _job(env, "blue")
    ctx = await vf.context(env.machines["blue"], connect=world.vms.connect, deployment_id=dep, user_id=env.user_id)
    assert (await machines.prepare(ctx))[0] == "succeeded"
    await _set(Deployment, dep, status="succeeded")
    before = await _get(Machine, env.machines["blue"])
    old_key = before.host_key_public
    vmid = before.ids["vmid"]
    async with get_sessionmaker()() as db:
        db.add(MachineSnapshot(machine_id=before.id, name="slipway-20261116T090000Z", reason="manual", status="ready",
                               identity_fp="0" * 64, sizes={"cores": 4}, taken_at=utcnow()))
        await db.commit()
    await _set(Instance, env.instances["blue"], status="running", app_state={"live": {"release": "r1"}})
    world.fake.remove_vm(vmid)  # deleted by hand on Proxmox: the id is free
    actor = await _get(User, env.user_id)

    text = await env_jobs.forget_vm(env.env_id, "blue", actor=actor)
    assert text == "Slipway forgot slipway-uat-blue; the next deploy to blue makes a new VM at 10.0.0.100"
    machine = await _get(Machine, env.machines["blue"])
    assert machine.stage == "planned" and machine.ids == {} and machine.applied is None
    assert machine.ready_at is None and machine.host_key_public is None
    host = await _get(Host, env.hosts["blue"])
    assert host.host_key is None and host.host_key_fingerprint is None and host.status == "unknown"
    assert host.provider_state["phase"] == "planned" and host.provider_state["stage"] == "planned"
    inst = await _get(Instance, env.instances["blue"])
    assert inst.status == "created" and inst.app_state is None
    assert inst.slot_state["stale"]["reason"] == "Its VM was lost; the next deploy makes a new one"
    assert await _all(Resource, Resource.kind == "vm", Resource.environment_id == env.env_id) == []
    assert await _all(TerraformState, TerraformState.machine_id == machine.id) == []
    assert await _all(MachineSnapshot, MachineSnapshot.machine_id == machine.id) == []
    assert len(await _all(AddressClaim, AddressClaim.host_id == host.id)) == 1  # the address stays the slot's
    (forgot,) = await _audits("machine.forget")
    assert forgot.details == {"name": "slipway-uat-blue", "ids": {"vmid": vmid}, "why": "lost", "environment": "uat",
                              "slot": "blue"}
    assert fp_token_free(forgot)

    # The next deploy's prepare makes a new VM at the same address and pins its new key.
    new_key = world.vms.new_key(BLUE)
    world.knobs(host_key=new_key)
    dep = await _job(env, "blue")
    ctx = await vf.context(env.machines["blue"], connect=world.vms.connect, deployment_id=dep, user_id=env.user_id)
    assert (await machines.prepare(ctx))[0] == "succeeded"
    machine = await _get(Machine, env.machines["blue"])
    assert machine.stage == "ready" and machine.network["address"] == BLUE
    assert machine.host_key_public.split()[:2] == new_key.split()[:2] != old_key.split()[:2]
    host = await _get(Host, env.hosts["blue"])
    assert host.host_key.split()[:2] == new_key.split()[:2]


def fp_token_free(event: AuditEvent) -> bool:
    from tests import fake_proxmox as fp

    blob = json.dumps([event.summary, event.details], default=str)
    return fp.TOKEN not in blob and fp.TOKEN_SECRET not in blob


async def test_56_forget_on_esxi_makes_a_new_host_key_pair(tmp_path, monkeypatch):
    net = vf.quiet_network(monkeypatch)
    w = EsxiWorld(tmp_path, monkeypatch, net)
    account = await vf.esxi_account()
    env = await vf.vm_env(account, mode="server", slots=("blue",), addresses=ADDRESSES,
                          provider=exp.EsxiProvider(),
                          deploy_roots={"blue": str(tmp_path / "vms" / "host-blue" / "root")})
    w.fake.addresses["slipway-uat-blue"] = BLUE
    dep = await _job(env, "blue")
    ctx = await vf.context(env.machines["blue"], connect=w.vms.connect, deployment_id=dep, user_id=env.user_id)
    assert (await machines.prepare(ctx))[0] == "succeeded"
    await _set(Deployment, dep, status="succeeded")
    old = await _get(Machine, env.machines["blue"])
    assert old.host_key_private is None  # scrubbed once pinned
    vm = w.fake.vm_named("slipway-uat-blue")
    vm.power = "poweredOff"
    await w.fake.destroy(vm.uuid)
    await env_jobs.forget_vm(env.env_id, "blue", actor=await _get(User, env.user_id))
    machine = await _get(Machine, env.machines["blue"])
    assert machine.stage == "planned" and machine.ids == {}
    assert machine.host_key_private and machine.host_key_public
    assert machine.host_key_public.split()[:2] != old.host_key_public.split()[:2]
    (forgot,) = await _audits("machine.forget")
    assert machine.host_key_private not in json.dumps([forgot.summary, forgot.details], default=str)


# ------------------------------------------------------------------------------ test 65: Activate on VMs


async def test_65_activate_refuses_a_vm_that_is_off_or_not_made(world, submitted, monkeypatch):
    sy = fake_switchyard.install(monkeypatch)
    await fake_switchyard.configure()
    env = await pve_env(world)
    await _set(Environment, env.env_id, traffic={"switch": "switchyard", "dns": None})
    await ready(world, env, "blue")
    await ready(world, env, "data")
    await deployed(env, "blue")
    await _set(Environment, env.env_id, active_slot_id=env.instances["blue"], status="live")

    # Green's VM isn't made yet.
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        found = await environments.activate_problem(db, row, "green")
    assert found == "green's VM isn't made yet: deploy to green first"
    refused = await refusal(env, "activate", slot="green")
    assert refused is not None and refused.status == 409  # the queue's not-built fence answers first (jobs.py)
    dep = await run(await queue(env, "activate", raw=True, slot="green"), world)
    assert dep.status == "failed" and dep.error == "green's VM isn't made yet: deploy to green first"

    # Made and deployed, but left off by a resize.
    green_id = await ready(world, env, "green", status="stopped")
    await deployed(env, "green")
    off = "green's VM slipway-uat-green is off: deploy to green again to finish its resize"
    refused = await refusal(env, "activate", slot="green")
    assert refused is not None and (refused.status, refused.text) == (409, off)
    dep = await run(await queue(env, "activate", raw=True, slot="green"), world)
    assert dep.status == "failed" and dep.error == off
    assert steps(dep)["check"] == "failed" and steps(dep)["switch"] == "pending"
    row = await _get(Environment, env.env_id)
    assert row.active_slot_id == env.instances["blue"]
    assert sy.api_calls() == []  # nothing asked of Switchyard, let alone changed

    # Running again, it may be activated (as far as the VM goes).
    with world.fake.edit() as state:
        state["vms"][str(green_id)]["status"] = "running"
    assert await refusal(env, "activate", slot="green") is None
    # An account that can't be read doesn't refuse: the activate's smoke test checks the slot.
    unreachable(monkeypatch)
    assert await refusal(env, "activate", slot="green") is None
