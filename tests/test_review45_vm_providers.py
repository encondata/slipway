"""Review fixes for the VM providers, the machines core and the ESXi session (phases 4 and 5 review).

- F11/K2: a Proxmox VM made again before it was ready gets its new key pinned (the old pin is cleared first).
- F12: a size stored while a VM isn't ready leaves prepare to finish it; the resize step applies it once ready.
- F13: a resized VM's sshd is given time to answer; a resize that went through records ``applied`` even when a
  later check fails, and a plan with nothing left to change shuts nothing down.
- F14: a resize cut off after the shutdown (the step's limit, Slipway stopping) starts a Proxmox VM again and
  leaves an ESXi one off with the notice and ``machine.left_off``.
- F35: an ESXi sign-in cut off by its limit or a cancel signs its late session out, and holds its pool place
  until the sign-in thread has finished.
- F36: the VM job step limits hold the waits inside them; a cut-off snapshot's row is failed, not left pending.

Proxmox is ``tests/fake_proxmox.py`` with ``tests/bin/fake-terraform``; ESXi is ``tests/fake_esxi.py``; the VMs
are ``tests/fake_vm_hosts.py``. Fakes only.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import delete, select

from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Environment, Instance, Machine, MachineSnapshot, TerraformState, User
from slipway.services import deployer, esxi, jobs, machines, traffic
from slipway.services.providers import esxi as exp
from slipway.services.providers import proxmox as pxp
from slipway.services.vmtypes import MachineError
from tests import test_provider_esxi as te
from tests import test_provider_proxmox as tp
from tests import vm_fixtures as vf
from tests.test_provider_pipeline import VmGitHub

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")


@pytest.fixture(autouse=True)
def net(monkeypatch) -> vf.Network:
    return vf.quiet_network(monkeypatch)


@pytest.fixture(autouse=True)
def quiet(monkeypatch) -> None:
    """Chained jobs are recorded, not run; traffic checks don't sleep."""
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, keys: None)
    monkeypatch.setattr(traffic, "sleep", vf.no_sleep)


@pytest.fixture
def pve(tmp_path, monkeypatch, net) -> tp.World:
    return tp.World(tmp_path, monkeypatch, net)


@pytest.fixture
def ex(tmp_path, monkeypatch, net) -> te.World:
    return te.World(tmp_path, monkeypatch, net)


async def get(model: Any, ident: uuid.UUID) -> Any:
    async with get_sessionmaker()() as db:
        return await db.get(model, ident)


def shutdowns(world: tp.World) -> list[dict[str, Any]]:
    return tp.calls(world, "POST", "/nodes/pve1/qemu/100/status/shutdown")


async def run_deploy(world: tp.World, env: vf.VmEnv) -> Deployment:
    async with get_sessionmaker()() as db:
        instance = await db.get(Instance, env.instances["blue"])
        user = await db.get(User, env.user_id)
        dep = await jobs.queue_job(db, instance=instance, user=user)
        await db.commit()
        dep_id = dep.id
    await deployer.run_deployment(dep_id, connect=world.vms.connect, github=VmGitHub)
    return await get(Deployment, dep_id)


async def finish_jobs(env: vf.VmEnv) -> None:
    from sqlalchemy import update  # noqa: PLC0415

    async with get_sessionmaker()() as db:
        await db.execute(update(Deployment).where(Deployment.environment_id == env.env_id,
                                                  Deployment.status.in_(("queued", "running")))
                         .values(status="succeeded"))
        await db.commit()


# ------------------------------------------------------------------- F11/K2: a Proxmox VM made again


async def _pinned_while_booting(world: tp.World) -> tuple[vf.VmEnv, str]:
    """The VM is made and its key pinned, then the bootstrap fails: stage booting, host pinned."""
    env = await tp.blue_env(world)
    world.vms.no_sudo("blue")
    with pytest.raises(MachineError, match="can't use sudo"):
        await machines.prepare(await tp.reload(world, env))
    row, host = await tp.machine(env), await tp.host(env)
    assert row.stage == "booting" and host.host_key
    world.vms.no_sudo("blue", False)
    return env, host.host_key


async def _pinned_to_the_new_key(world: tp.World, env: vf.VmEnv, old: str, new: str) -> None:
    host = await tp.host(env)
    assert machines._same_key(host.host_key, new) and not machines._same_key(host.host_key, old)
    assert (await tp.machine(env)).stage == "ready"
    (reset,) = await tp.audits("host.key_reset")
    assert reset.details["why"] == f"{tp.VM} is made again with a new host key"


async def test_f11_a_pinned_vm_gone_before_it_was_ready_is_made_again_and_its_new_key_pinned(pve):
    env, old = await _pinned_while_booting(pve)
    pve.fake.remove_vm(100)  # deleted by hand, or lost
    new = pve.vms.new_key(tp.BLUE)
    pve.knobs()  # the new VM presents the new key
    assert (await machines.prepare(await tp.reload(pve, env)))[0] == "succeeded"
    assert "state rm" in pve.commands()
    await _pinned_to_the_new_key(pve, env, old, new)


async def test_f11_a_pinned_half_made_vm_deleted_and_made_again_has_its_new_key_pinned(pve):
    env, old = await _pinned_while_booting(pve)
    # Terraform's state lost the VM (no resource), so the VM there is a half-made one: deleted and made again.
    async with get_sessionmaker()() as db:
        await db.execute(delete(TerraformState).where(TerraformState.machine_id == env.machines["blue"]))
        await db.commit()
    pve.workdir(env.machines["blue"]).state_path.unlink(missing_ok=True)
    new = pve.vms.new_key(tp.BLUE)
    pve.knobs()
    assert (await machines.prepare(await tp.reload(pve, env)))[0] == "succeeded"
    assert tp.calls(pve, "DELETE", "/nodes/pve1/qemu/100")  # the half-made VM went first
    await _pinned_to_the_new_key(pve, env, old, new)


async def test_f11_a_refused_plan_changes_no_pin(pve, monkeypatch):
    """The unpin is a change: a plan that does more than make the VM refuses before it."""
    env, old = await _pinned_while_booting(pve)
    pve.fake.remove_vm(100)
    pve.knobs(plan_extra="delete")
    with pytest.raises(MachineError, match="does more than make it"):
        await machines.prepare(await tp.reload(pve, env))
    assert (await tp.host(env)).host_key == old and await tp.audits("host.key_reset") == []


# ------------------------------------------------------------------ F12: a size stored while not ready


async def test_f12_a_size_stored_while_booting_lets_prepare_finish_and_the_resize_step_applies_it(pve, monkeypatch):
    env = await tp._booting_with_state(pve, monkeypatch)  # made by Terraform; prepare failed while booting
    await tp.grow(env, cores=6)  # PATCH .../machines/blue is allowed for a VM that isn't ready
    runs = len(pve.runs())
    assert (await machines.prepare(await tp.reload(pve, env)))[0] == "succeeded"
    assert "apply" not in pve.commands()[runs:]  # planned at the size it was made at: nothing to apply
    row = await tp.machine(env)
    assert row.stage == "ready" and row.applied["cores"] == 4 and machines.size_differs(row)
    assert pve.fake.vm(100)["config"]["cores"] == 4
    async with get_sessionmaker()() as db:
        assert await machines.resize_due(db, await db.get(Machine, env.machines["blue"]))  # the next deploy's
    assert (await machines.resize_step(await tp.reload(pve, env)))[0] == "succeeded"
    assert pve.fake.vm(100)["config"]["cores"] == 6 and (await tp.machine(env)).applied["cores"] == 6


async def test_f12_a_vm_gone_while_booting_is_made_again_at_the_size_stored_meanwhile(pve, monkeypatch):
    env = await tp._booting_with_state(pve, monkeypatch)
    await tp.grow(env, cores=6)
    pve.fake.remove_vm(100)
    assert (await machines.prepare(await tp.reload(pve, env)))[0] == "succeeded"
    assert "state rm" in pve.commands()
    assert pve.fake.vm(100)["config"]["cores"] == 6
    row = await tp.machine(env)
    assert row.applied["cores"] == 6 and not machines.size_differs(row)


# --------------------------------------------------------------- F13: the SSH check after a resize


async def test_f13_a_resized_vm_whose_sshd_is_late_is_waited_for(pve):
    env, _ctx, _ = await tp.made(pve)
    await tp.grow(env, cores=6)
    pve.vms.booting(tp.BLUE, 2)  # sshd isn't listening yet when the agent reports the address
    assert await machines.resize_step(await tp.reload(pve, env)) == ("succeeded", "Resized to 6 vCPU, 8 GB, 64 GB")
    assert (await tp.machine(env)).applied["cores"] == 6


async def test_f13_a_resize_that_went_through_records_applied_even_when_ssh_never_answers(pve, monkeypatch):
    env, _ctx, _ = await tp.made(pve)
    await tp.grow(env, cores=6)
    monkeypatch.setattr(machines, "RESIZED_SSH_WAIT", 15.0)
    pve.vms.booting(tp.BLUE, 1000)
    with pytest.raises(MachineError, match=f"^{tp.VM} is resized, but Slipway couldn't reach it over SSH with its "
                                           "pinned key: "):
        await machines.resize_step(await tp.reload(pve, env))
    assert pve.fake.vm(100)["config"]["cores"] == 6
    row = await tp.machine(env)
    assert row.applied["cores"] == 6 and not machines.size_differs(row)
    assert "couldn't reach it over SSH" in row.last_error
    assert await tp.audits("machine.left_off") == []  # it runs

    # The next deploy has nothing to resize: no second shutdown.
    pve.vms.booting(tp.BLUE, 0)
    before = len(shutdowns(pve))
    assert (await machines.resize_step(await tp.reload(pve, env)))[0] == "skipped"
    assert len(shutdowns(pve)) == before


async def test_f13_a_stale_applied_with_nothing_to_change_shuts_nothing_down(pve, monkeypatch):
    """A resize whose record was cut off (a restart): the plan has no change, so the VM keeps running."""
    env, _ctx, _ = await tp.made(pve)
    await tp.grow(env, cores=6)
    assert (await machines.resize_step(await tp.reload(pve, env)))[0] == "succeeded"
    async with get_sessionmaker()() as db:
        row = await db.get(Machine, env.machines["blue"])
        row.applied = {**row.applied, "cores": 4}  # the record of the resize never landed
        await db.commit()
    before, snaps = len(shutdowns(pve)), len(tp.calls(pve, "POST", "/nodes/pve1/qemu/100/snapshot"))
    status, _note = await machines.resize_step(await tp.reload(pve, env))
    assert status == "succeeded"
    assert len(shutdowns(pve)) == before  # no shutdown of the running VM
    assert len(tp.calls(pve, "POST", "/nodes/pve1/qemu/100/snapshot")) == snaps  # and no pre_resize snapshot
    assert (await tp.machine(env)).applied["cores"] == 6


async def test_f13_esxi_waits_for_a_late_sshd_and_skips_a_resize_with_nothing_to_change(ex):
    env, _, _ = await te.made(ex)
    await te.set_size(env, cores=8)
    ex.vms.booting(te.BLUE, 2)
    assert (await machines.resize_step(await te.again(ex, env)))[0] == "succeeded"
    assert (await te.machine(env)).applied["cores"] == 8
    async with get_sessionmaker()() as db:
        row = await db.get(Machine, env.machines["blue"])
        row.applied = {**row.applied, "cores": 4}
        await db.commit()
    ex.fake.calls.clear()
    assert (await machines.resize_step(await te.again(ex, env)))[0] == "succeeded"
    assert "shutdown_guest" not in ex.names() and "take_snapshot" not in ex.names()
    assert (await te.machine(env)).applied["cores"] == 8


# ------------------------------------------------------------- F14: a resize cut off after the shutdown


def _slow_apply(monkeypatch) -> None:
    real = pxp.ProxmoxProvider._session

    @contextlib.asynccontextmanager
    async def slow(self, ctx, vmid, size):
        async with real(self, ctx, vmid, size) as tf:
            async def apply(*a, **k):
                await asyncio.sleep(30)  # Terraform's apply outlasts the step's limit

            tf.apply = apply
            yield tf

    monkeypatch.setattr(pxp.ProxmoxProvider, "_session", slow)


async def test_f14_a_proxmox_resize_past_its_limit_starts_the_vm_again(pve, monkeypatch):
    env = await tp.blue_env(pve)
    first = await run_deploy(pve, env)
    assert first.status == "succeeded", (first.error, first.log[-3000:])
    await finish_jobs(env)
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        row.active_slot_id, row.status = env.instances["blue"], "live"
        await db.commit()
    await tp.grow(env, cores=6)
    _slow_apply(monkeypatch)
    monkeypatch.setitem(deployer.PROVIDER_STEP_TIMEOUTS["proxmox"], "resize", 1.0)
    dep = await run_deploy(pve, env)
    assert dep.status == "failed" and "timed out" in dep.error
    vm = pve.fake.vm(100)
    assert len(shutdowns(pve)) == 1
    assert vm["status"] == "running" and vm["config"]["cores"] == 4  # started again at its old size
    m = await get(Machine, env.machines["blue"])
    assert m.last_error == f"The resize of {tp.VM} was cut off before it finished"
    assert m.applied["cores"] == 4  # nothing changed


async def test_f14_a_cut_off_resize_that_leaves_the_vm_off_sets_the_notice_and_audits_left_off(pve, monkeypatch):
    env, _ctx, _ = await tp.made(pve)
    await tp.grow(env, cores=6)
    _slow_apply(monkeypatch)

    async def cannot_start(self, ctx, api, vmid):
        return None  # Proxmox refuses the start meanwhile

    monkeypatch.setattr(pxp.ProxmoxProvider, "_start_again", cannot_start)
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(machines.resize_step(await tp.reload(pve, env)), 2.0)
    assert pve.fake.vm(100)["status"] == "stopped"
    notice = (await get(Environment, env.env_id)).notice
    assert notice["text"] == f"{tp.VM} was left off during a resize: deploy to blue again to finish it"
    (left,) = await tp.audits("machine.left_off")
    assert left.details["why"] == f"The resize of {tp.VM} was cut off before it finished"


async def test_f14_an_esxi_resize_cancelled_while_off_leaves_it_off_with_the_notice(ex, monkeypatch):
    env, _, _ = await te.made(ex)
    await te.set_size(env, cores=8)
    real = ex.fake.set_size

    async def hangs(uuid_, cores, memory_mb, *, on_task=None):
        await asyncio.sleep(3600)
        return await real(uuid_, cores, memory_mb, on_task=on_task)

    monkeypatch.setattr(ex.fake, "set_size", hangs)
    task = asyncio.ensure_future(machines.resize_step(await te.again(ex, env)))
    for _ in range(200):
        if ex.vm().power == "poweredOff":
            break
        await asyncio.sleep(0.01)
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert ex.vm().power == "poweredOff" and ex.vm().cores == 4  # ESXi: left off (§8.3 step 3)
    async with get_sessionmaker()() as db:
        notice = (await db.get(Environment, env.env_id)).notice
    assert notice["text"] == f"{te.VM} was left off during a resize: deploy to blue again to finish it"
    (left,) = await te.audits("machine.left_off")
    assert left.details["why"] == f"The resize of {te.VM} was cut off before it finished"
    assert (await te.machine(env)).last_error == f"The resize of {te.VM} was cut off before it finished"


# ------------------------------------------------------------------ F35: a cut-off ESXi sign-in


def _account(ident: str) -> SimpleNamespace:
    return SimpleNamespace(id=ident, name="lab", config={"url": "https://esxi.lan", "user": "slipway"},
                           secret="pw-123", tls={"pem": "pem", "fingerprint_sha256": "AA:BB"}, facts={})


def _slow_sign_in(monkeypatch) -> tuple[threading.Event, object, list[Any]]:
    go, si, signed_out = threading.Event(), object(), []

    def slow(*args):
        go.wait(10)
        return si

    monkeypatch.setattr(esxi, "_smart_connect", slow)
    monkeypatch.setattr(esxi, "_disconnect", signed_out.append)
    return go, si, signed_out


async def _until(check, tries: int = 300) -> None:
    for _ in range(tries):
        if check():
            return
        await asyncio.sleep(0.01)


async def test_f35_a_sign_in_past_its_limit_signs_the_late_session_out_and_holds_the_pool_until_then(monkeypatch):
    go, si, signed_out = _slow_sign_in(monkeypatch)
    monkeypatch.setattr(esxi, "SIGNIN_TIMEOUT", 0.05)
    gate = esxi.read_sessions["acct-late-limit"]
    with pytest.raises(MachineError, match="didn't answer the sign-in"):
        async with esxi.session(_account("acct-late-limit"), purpose="read"):
            pass
    assert gate._value == esxi.SESSIONS_PER_ACCOUNT - 1  # the thread still signs in: its place stays taken
    go.set()
    await _until(lambda: gate._value == esxi.SESSIONS_PER_ACCOUNT)
    assert signed_out == [si] and gate._value == esxi.SESSIONS_PER_ACCOUNT


async def test_f35_a_sign_in_cancelled_by_its_caller_signs_the_late_session_out(monkeypatch):
    go, si, signed_out = _slow_sign_in(monkeypatch)
    gate = esxi.job_sessions["acct-late-cancel"]

    async def enter() -> None:
        async with esxi.session(_account("acct-late-cancel")):
            pass

    with pytest.raises(TimeoutError):
        await asyncio.wait_for(enter(), 0.05)  # a page read's 15-second limit, shorter than the sign-in's
    assert gate._value == esxi.SESSIONS_PER_ACCOUNT - 1
    go.set()
    await _until(lambda: gate._value == esxi.SESSIONS_PER_ACCOUNT)
    assert signed_out == [si] and gate._value == esxi.SESSIONS_PER_ACCOUNT


async def test_f35_a_failed_sign_in_gives_its_place_back_at_once(monkeypatch):
    def refuse(*args):
        raise MachineError("ESXi refused the sign-in")

    monkeypatch.setattr(esxi, "_smart_connect", refuse)
    gate = esxi.read_sessions["acct-refused"]
    with pytest.raises(MachineError, match="refused the sign-in"):
        async with esxi.session(_account("acct-refused"), purpose="read"):
            pass
    assert gate._value == esxi.SESSIONS_PER_ACCOUNT


# --------------------------------------------------------------------- F36: VM job step limits


def test_f36_the_vm_job_step_limits_hold_the_waits_inside_them():
    wait, sign_in = machines.TASK_WAIT_LIMIT, esxi.SIGNIN_TIMEOUT + 2 * esxi.CALL_TIMEOUT
    esxi_take = wait + 2 * esxi.TASK_LIMIT + exp.LATE_GRACE + sign_in  # quiesced, then crash-consistent
    pve_take = wait + pxp.TASK_TIMEOUTS["snapshot"] + pxp.LATE_GRACE
    esxi_drop = wait + esxi.TASK_LIMIT + sign_in
    pve_drop = wait + pxp.TASK_TIMEOUTS["delsnapshot"]
    for provider in ("proxmox", "esxi"):
        assert deployer.step_timeout("vm_snapshot", provider) > max(esxi_take, pve_take)
        assert deployer.step_timeout("vm_drop", provider) > max(esxi_drop, pve_drop)
        assert deployer.step_timeout("prune", provider) > 2 * max(esxi_drop, pve_drop)


async def test_f36_a_snapshot_cut_off_by_its_limit_fails_its_row_instead_of_leaving_it_pending(pve, monkeypatch):
    env, _ctx = await tp.ready_vm(pve)
    await finish_jobs(env)
    monkeypatch.setitem(deployer.STEP_TIMEOUTS, "vm_snapshot", 0.05)

    async def hangs(self, ctx, row):
        await asyncio.sleep(3600)

    monkeypatch.setattr(pxp.ProxmoxProvider, "snapshot", hangs)
    async with get_sessionmaker()() as db:
        instance = await db.get(Instance, env.instances["blue"])
        user = await db.get(User, env.user_id)
        dep = await jobs.queue_job(db, instance=instance, user=user, kind="vm_snapshot", options={})
        await db.commit()
        dep_id = dep.id
    await deployer.run_deployment(dep_id, connect=pve.vms.connect)
    dep = await get(Deployment, dep_id)
    assert dep.status == "failed" and "timed out" in dep.error
    async with get_sessionmaker()() as db:
        (row,) = await db.scalars(select(MachineSnapshot).where(MachineSnapshot.machine_id == env.machines["blue"]))
    assert row.status == "failed"
