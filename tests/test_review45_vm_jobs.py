"""Review 45, the VM jobs cluster: snapshot identity, revert holds and cleared keys.

* F1: a ``pre_resize`` row is ``vm_jobs.new_row``'s (identity values, fingerprint, backups), and a revert to a row
  that recorded no identity keeps the data owner's ``live_identity``.
* F19, F24: a VM snapshot whose identity values can't be read (another key, or erased by ``--clear-unreadable``) is
  refused at the queue and in ``check``; ``--clear-unreadable`` marks it failed; a later ``describe`` keeps it so.
* F34: a ``vm_revert`` the provider refused before its task changed nothing and holds nothing; one that reached
  the hypervisor still holds; deleting the snapshot a revert's hold names is refused.
* F20: ``--clear-unreadable`` refuses to erase the SSH key of a host an environment made; the connect error for
  such a host no longer points at the host page.
"""

from __future__ import annotations

import argparse
import uuid
from typing import Any

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select, text, update

from slipway import cli
from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Environment, Host, Instance, MachineSnapshot, TerraformState
from slipway.services import data, deployer, machines, ssh, vm_jobs
from slipway.services.providers import esxi as exp
from slipway.services.providers import proxmox as pxp
from slipway.services.vmtypes import MachineError
from tests import vm_fixtures as vf
from tests.test_migration_0009 import K1, K3, encryption_key  # noqa: F401  (fixture)
from tests.test_provider_esxi import World as EsxiWorld
from tests.test_provider_esxi import blue_env as esxi_blue_env
from tests.test_rotate_provider_secrets import STATE
from tests.test_rotate_provider_secrets import _seed as rotation_seed
from tests.test_vm_jobs import (  # noqa: F401  (net, quiet and world are fixtures)
    REAL_REVERT,
    _running,
    add_row,
    disk_goes_back,
    get,
    host_backup,
    idle,
    interrupted,
    net,
    pve_deployed,
    pve_ready,
    queue,
    quiet,
    raw,
    refusal,
    rows,
    run,
    snap_name,
    statuses,
    world,
)
from tests.test_provider_proxmox import VM
from tests.test_provider_proxmox import grow as pve_grow
from tests.test_provider_proxmox import made as pve_made
from tests.test_provider_proxmox import reload as pve_reload

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")


def _id(value: uuid.UUID, db: Any) -> Any:
    return value.hex if db.bind.dialect.name == "sqlite" else value


async def _raw_identity(row_id: uuid.UUID, token: str | None) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(text("UPDATE machine_snapshots SET identity = :t WHERE id = :i"),
                         {"t": token, "i": _id(row_id, db)})
        await db.commit()


async def _later_identity(env: vf.VmEnv) -> None:
    """The environment moves on to another APP_KEY after the snapshot."""
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, env.instances["blue"])
        inst.live_identity = {"APP_KEY": "a-later-key"}
        env_row = await db.get(Environment, env.env_id)
        env_row.app_secrets = {**(env_row.app_secrets or {}), "APP_KEY": "a-later-key"}
        await db.commit()


async def _manual_snapshot(env: vf.VmEnv, w: Any) -> MachineSnapshot:
    taken = await run(await queue(env, "vm_snapshot"), w)
    assert taken.status == "succeeded", (taken.error, taken.log[-2000:])
    (row,) = [r for r in await rows(env) if r.reason == "manual"]
    assert row.identity
    return row


# ---------------------------------------------------------------------------------- F1: pre_resize rows


async def test_f1_a_pre_resize_row_records_the_identity_and_a_revert_to_it_keeps_the_guard(world, monkeypatch):
    env = await pve_deployed(world)
    backup = await host_backup(env, 120)
    inst = await get(Instance, env.instances["blue"])
    identity = dict(inst.live_identity)
    assert identity
    ctx = await vf.context(env.machines["blue"], connect=world.vms.connect, user_id=env.user_id)
    row = await machines.pre_resize_row(ctx)
    stored = await get(MachineSnapshot, row.id)
    assert (stored.reason, stored.status, stored.note) == ("pre_resize", "pending", "Before a resize")
    assert stored.identity == identity
    assert stored.identity_fp == data.identity_fp(row.id, sorted(identity), identity)
    assert stored.backups == [backup.name]
    await vm_jobs_ready(row.id)
    world.fake.add_snapshot(100, row.name)

    disk_goes_back(monkeypatch, env)
    dep = await run(await queue(env, "vm_revert", vm_snapshot_id=row.id.hex, skip_pre_revert=True), world)
    assert dep.status == "succeeded", (dep.error, dep.log[-2000:])
    assert (await get(Instance, env.instances["blue"])).live_identity == identity
    assert (await get(Deployment, dep.id)).options.get("revert_started") is True


async def vm_jobs_ready(row_id: uuid.UUID) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(update(MachineSnapshot).where(MachineSnapshot.id == row_id).values(status="ready"))
        await db.commit()


async def test_f1_a_proxmox_resize_records_the_identity_on_its_pre_resize_row(world):
    env, _ctx, _ = await pve_made(world)
    identity = {"APP_KEY": "made-with-this"}
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, env.instances["blue"])
        inst.live_identity = identity
        await db.commit()
    await pve_grow(env, cores=6)
    ctx = await pve_reload(world, env)
    assert (await machines.resize_step(ctx))[0] == "succeeded"
    async with get_sessionmaker()() as db:
        snap = await db.scalar(select(MachineSnapshot))
    assert (snap.reason, snap.status) == ("pre_resize", "ready")
    assert snap.identity == identity
    assert snap.identity_fp == data.identity_fp(snap.id, ["APP_KEY"], identity)


async def test_f1_a_revert_to_a_row_that_recorded_no_identity_keeps_live_identity(world, monkeypatch):
    env = await pve_deployed(world)
    identity = dict((await get(Instance, env.instances["blue"])).live_identity)
    # A row as the old pre_resize builders wrote it: no identity values, the fingerprint of no keys.
    row = await add_row(env, snap_name(30), reason="pre_resize", world=world)
    disk_goes_back(monkeypatch, env)
    dep = await run(await queue(env, "vm_revert", vm_snapshot_id=row.id.hex, skip_pre_revert=True), world)
    assert dep.status == "succeeded", (dep.error, dep.log[-2000:])
    assert (await get(Instance, env.instances["blue"])).live_identity == identity


# --------------------------------------------------------------------- F19, F24: unreadable identity


async def test_f19_a_snapshot_whose_identity_was_erased_is_refused_at_the_queue_and_in_check(world, monkeypatch):
    env = await pve_deployed(world)
    row = await _manual_snapshot(env, world)
    await _later_identity(env)
    await _raw_identity(row.id, None)  # what --clear-unreadable leaves
    text_ = f"{row.name}'s identity values were erased when SLIPWAY_ENCRYPTION_KEY changed: delete it"

    refused = await refusal(env, "vm_revert", vm_snapshot_id=row.id.hex)
    assert refused is not None and refused.text == text_

    seen = disk_goes_back(monkeypatch, env)
    dep = await run(await raw(env, "vm_revert", vm_snapshot_id=row.id.hex), world)  # queued before the change
    assert dep.status == "failed" and dep.error == text_
    assert statuses(dep)["check"] == "failed" and seen == []
    inst = await get(Instance, env.instances["blue"])
    assert inst.live_identity == {"APP_KEY": "a-later-key"} and not inst.data_dirty
    assert (await get(Environment, env.env_id)).app_secrets["APP_KEY"] == "a-later-key"


async def test_f24_a_snapshot_whose_identity_another_key_wrote_is_refused(world, monkeypatch):
    env = await pve_deployed(world)
    row = await _manual_snapshot(env, world)
    await _later_identity(env)
    other = Fernet(Fernet.generate_key()).encrypt(b'{"APP_KEY": "old"}').decode()
    await _raw_identity(row.id, other)
    text_ = (f"{row.name}'s identity values can't be read any more (SLIPWAY_ENCRYPTION_KEY changed): put the old key "
             "back or delete it")
    assert (await refusal(env, "vm_revert", vm_snapshot_id=row.id.hex)).text == text_
    seen = disk_goes_back(monkeypatch, env)
    dep = await run(await raw(env, "vm_revert", vm_snapshot_id=row.id.hex), world)
    assert dep.status == "failed" and dep.error == text_ and seen == []
    assert (await get(Instance, env.instances["blue"])).live_identity == {"APP_KEY": "a-later-key"}
    # Deleting it is still allowed.
    assert await refusal(env, "vm_drop", vm_snapshot_id=row.id.hex) is None


async def test_f24_a_failed_row_with_lost_identity_stays_failed_when_the_hypervisor_has_it(world):
    env = await pve_ready(world)
    row = await add_row(env, snap_name(60), world=world, status="failed")
    async with get_sessionmaker()() as db:  # it recorded identity values, which were erased since
        await db.execute(update(MachineSnapshot).where(MachineSnapshot.id == row.id).values(identity_fp="f" * 64))
        await db.commit()
    other = await add_row(env, snap_name(50), world=world, status="failed")
    dep = await run(await queue(env, "vm_snapshot"), world)
    assert dep.status == "succeeded", (dep.error, dep.log[-2000:])
    assert (await get(MachineSnapshot, row.id)).status == "failed"
    assert (await get(MachineSnapshot, other.id)).status == "ready"  # a failed row the hypervisor has, revived


async def test_f19_clear_unreadable_marks_vm_snapshots_with_lost_identity_failed(encryption_key):  # noqa: F811
    encryption_key(K1)
    ids = await rotation_seed()
    encryption_key(K3)
    async with get_sessionmaker()() as db:
        (await db.get(TerraformState, ids["green"])).state = STATE  # only the other secrets are lost
        await db.commit()
    async with get_sessionmaker()() as db:
        _, _, fixed = await cli._rotate_all(db, argparse.Namespace(clear_unreadable=True))
        await db.commit()
    async with get_sessionmaker()() as db:
        snap = await db.scalar(select(MachineSnapshot))
        assert snap.status == "failed" and snap.identity is None
        assert await vm_jobs.identity_problem(db, snap) == (
            f"{snap.name}'s identity values were erased when SLIPWAY_ENCRYPTION_KEY changed: delete it")
    joined = "\n".join(fixed)
    assert "Marked 1 VM snapshot(s) failed; their identity values were lost" in joined
    assert f"  {snap.name}" in fixed and "jwt-1" not in joined


# ----------------------------------------------------------------------------------- F34: revert holds


ESXI_REVERT = exp.EsxiProvider.revert


async def _esxi_ready(tmp_path, monkeypatch, net):  # noqa: F811
    w = EsxiWorld(tmp_path, monkeypatch, net)
    env = await esxi_blue_env(w)
    ctx = await vf.context(env.machines["blue"], connect=w.vms.connect, deployment_id=await _running(env),
                           user_id=env.user_id)
    assert (await machines.prepare(ctx))[0] == "succeeded"
    await idle(env)
    return w, env


async def test_f34_a_revert_the_provider_refused_before_its_task_holds_nothing(tmp_path, monkeypatch, net):  # noqa: F811
    w, env = await _esxi_ready(tmp_path, monkeypatch, net)
    vm = w.vm()
    row = await add_row(env, snap_name(60))
    w.fake._snapshot(vm, row.name, "", quiesced=True)

    async def revert(self, ctx, r):
        vm.snaps[:] = [s for s in vm.snaps if s.name != r.name]  # deleted in the Host Client after check
        await ESXI_REVERT(self, ctx, r)

    monkeypatch.setattr(exp.EsxiProvider, "revert", revert)
    dep = await run(await queue(env, "vm_revert", vm_snapshot_id=row.id.hex, skip_pre_revert=True), w)
    assert dep.status == "failed" and "Slipway changed nothing" in dep.error
    assert not w.calls("revert_snapshot")
    assert dep.options.get("revert_started") is False
    assert not (await get(Instance, env.instances["blue"])).data_dirty
    deploy = await refusal(env, "deploy")
    assert deploy is None or "reverting" not in (deploy.text or "")


async def test_f34_a_proxmox_revert_refused_by_a_running_task_holds_nothing(world, monkeypatch):
    env = await pve_ready(world)
    row = await add_row(env, snap_name(60), world=world)

    async def revert(self, ctx, r):
        world.fake.run_task(100, "vzdump")  # someone's backup starts after check
        monkeypatch.setattr(machines, "TASK_WAIT_LIMIT", 0.0)
        await REAL_REVERT(self, ctx, r)

    monkeypatch.setattr(pxp.ProxmoxProvider, "revert", revert)
    dep = await run(await queue(env, "vm_revert", vm_snapshot_id=row.id.hex, skip_pre_revert=True), world)
    assert dep.status == "failed" and "Slipway changed nothing" in dep.error, dep.error
    assert not any(r["path"].endswith("/rollback") for r in world.fake.requests)
    assert not (await get(Instance, env.instances["blue"])).data_dirty


async def test_f34_a_revert_whose_task_started_and_failed_still_holds(world, monkeypatch):
    env = await pve_ready(world)
    row = await add_row(env, snap_name(60), world=world)

    async def revert(self, ctx, r):
        await machines.tasks.wait_idle(ctx, read=_nothing)
        await machines.tasks.started(ctx, "UPID:pve1:rollback", "rollback")
        raise MachineError("Proxmox's rollback failed")

    monkeypatch.setattr(pxp.ProxmoxProvider, "revert", revert)
    dep = await run(await queue(env, "vm_revert", vm_snapshot_id=row.id.hex, skip_pre_revert=True), world)
    assert dep.status == "failed" and dep.options.get("revert_started") is True
    dirty = (await get(Instance, env.instances["blue"])).data_dirty
    assert dirty["hold"] is True and dirty["last"]["step"] == "vm_revert"


async def _nothing() -> list[Any]:
    return []


async def test_f34_recovery_holds_only_a_revert_that_reached_the_hypervisor(world):
    env = await pve_ready(world)
    row = await add_row(env, snap_name(60), world=world)
    await interrupted(env, "vm_revert", "vm_revert", vm_snapshot_id=row.id.hex, revert_started=False)
    await deployer.runner.recover_interrupted()
    assert not (await get(Instance, env.instances["blue"])).data_dirty

    await interrupted(env, "vm_revert", "vm_revert", vm_snapshot_id=row.id.hex, revert_started=True)
    await deployer.runner.recover_interrupted()
    dirty = (await get(Instance, env.instances["blue"])).data_dirty
    assert dirty and dirty["hold"] is True


async def test_f34_deleting_the_snapshot_a_revert_hold_names_is_refused(world):
    env = await pve_ready(world)
    row = await add_row(env, snap_name(60), world=world)
    other = await add_row(env, snap_name(50), world=world)
    await interrupted(env, "vm_revert", "wait", vm_snapshot_id=row.id.hex)
    await deployer.runner.recover_interrupted()
    assert (await get(Instance, env.instances["blue"])).data_dirty["hold"] is True
    env_name = (await get(Environment, env.env_id)).name
    text_ = (f"{env_name}'s data is held until {VM} is reverted to {row.name} again, so Slipway keeps {row.name}: "
             "revert to it first")
    refused = await refusal(env, "vm_drop", vm_snapshot_id=row.id.hex)
    assert refused is not None and refused.text == text_
    assert await refusal(env, "vm_drop", vm_snapshot_id=other.id.hex) is None
    # Queued before the hold, its own check refuses it too.
    dep = await run(await raw(env, "vm_drop", vm_snapshot_id=row.id.hex), world)
    assert dep.status == "failed" and dep.error == text_
    assert (await get(MachineSnapshot, row.id)) is not None
    assert world.fake.vm(100)["snapshots"]


# ---------------------------------------------------------------------------------- F20: cleared keys


async def _owned_host_with_key(env_id: uuid.UUID | None, name: str) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        host = Host(name=name, hostname="10.0.0.9", username="slipway", provider="proxmox" if env_id else "ssh",
                    owner_environment_id=env_id, private_key="-----BEGIN OPENSSH PRIVATE KEY-----client")
        db.add(host)
        await db.commit()
        return host.id


async def test_f20_clear_unreadable_keeps_the_key_of_a_host_slipway_made(encryption_key):  # noqa: F811
    """The key is kept as it is (the old key can still read it) and the host listed; the rest of the rotation
    goes ahead, so a lost owned host key doesn't block --clear-unreadable for the whole install (final review)."""
    encryption_key(K1)
    ids = await rotation_seed()
    async with get_sessionmaker()() as db:
        env_id = await db.scalar(select(Environment.id))
    await _owned_host_with_key(env_id, "slipway-lab-made")
    encryption_key(K3)
    async with get_sessionmaker()() as db:
        (await db.get(TerraformState, ids["green"])).state = STATE
        await db.commit()
    async with get_sessionmaker()() as db:
        before = await db.scalar(text("SELECT private_key FROM hosts WHERE name = 'slipway-lab-made'"))
        _, unreadable, fixed = await cli._rotate_all(db, argparse.Namespace(clear_unreadable=True))
        await db.commit()
    assert fixed[:2] == [
        "Kept the SSH key of 1 host(s) Slipway made, which no configured key can read: Slipway made them, so the "
        "key can't be entered again by hand. Put the old key back after the new one in SLIPWAY_ENCRYPTION_KEY and "
        "run this again to re-encrypt it; until then Slipway can't reach them:",
        "  slipway-lab-made",
    ]
    assert not any(u.startswith("hosts.private_key") for u in unreadable)
    async with get_sessionmaker()() as db:
        assert await db.scalar(text("SELECT private_key FROM hosts WHERE name = 'slipway-lab-made'")) == before
        # The rest went ahead: the provider account's unreadable token was cleared.
        assert await db.scalar(text("SELECT secret FROM provider_accounts WHERE name = 'DO'")) is None
    # With the old key back, the next rotation re-encrypts it.
    encryption_key(f"{K3},{K1}")
    async with get_sessionmaker()() as db:
        _, unreadable, fixed = await cli._rotate_all(db, argparse.Namespace(clear_unreadable=True))
        await db.commit()
    assert not any(line.startswith("Kept the SSH key") for line in fixed)
    async with get_sessionmaker()() as db:
        assert await db.scalar(text("SELECT private_key FROM hosts WHERE name = 'slipway-lab-made'")) != before


async def test_f20_a_hand_added_hosts_unreadable_key_is_still_cleared(encryption_key):  # noqa: F811
    encryption_key(K1)
    ids = await rotation_seed()
    await _owned_host_with_key(None, "by-hand")
    encryption_key(K3)
    async with get_sessionmaker()() as db:
        (await db.get(TerraformState, ids["green"])).state = STATE
        await db.commit()
    async with get_sessionmaker()() as db:
        _, unreadable, _ = await cli._rotate_all(db, argparse.Namespace(clear_unreadable=True))
        await db.commit()
    assert any(u.startswith("hosts.private_key") for u in unreadable)
    async with get_sessionmaker()() as db:
        assert await db.scalar(text("SELECT private_key FROM hosts WHERE name = 'by-hand'")) is None


async def test_f20_the_connect_error_for_a_made_host_names_the_fix_that_works():
    made = ssh.SSHTarget.from_host(Host(name="vm", hostname="10.0.0.9", username="slipway", port=22, provider="ssh",
                                        auth_method="key", owner_environment_id=uuid.uuid4()))
    assert made.owned is True
    with pytest.raises(ssh.SSHError) as caught:
        await ssh.connect(made)
    assert str(caught.value) == ssh.OWNED_KEY_UNREADABLE
    assert "host page" not in str(caught.value) and "SLIPWAY_ENCRYPTION_KEY" in str(caught.value)

    by_hand = ssh.SSHTarget.from_host(Host(name="h", hostname="10.0.0.8", username="deploy", port=22, provider="ssh",
                                           auth_method="key"))
    assert by_hand.owned is False
    with pytest.raises(ssh.SSHError) as caught:
        await ssh.connect(by_hand)
    assert str(caught.value) == ssh.CREDENTIALS_UNREADABLE  # phase 3's text, unchanged
