"""Phase 5 tests 15-17: the ESXi client (``slipway.services.esxi``) and its fakes.

15. ``FakeEsxi`` behaves as ESXi in each respect Slipway depends on.
16. ``PyvmomiEsxi`` over ``fake_vim``: task states and fault mapping, ``QuiesceFailed``, guest
    addresses, markers, the new VM's config, ``_smart_connect``'s arguments, the one-thread executor.
17. The account's Test and ``clean_config``; on a timeout or cancel only a cancelable disk copy is
    cancelled.
"""

from __future__ import annotations

import asyncio
import ssl
import threading
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from slipway.services import esxi, tls_pin
from slipway.services.esxi import (
    COPY_KIND,
    QuiesceFailed,
    TaskFailed,
    TaskRef,
    TaskTimedOut,
    VmGone,
    VmSpec,
)
from slipway.services.vmtypes import AccountInvalid, MachineError

from tests.fake_esxi import FakeEsxi
from tests.hypervisor_guard import no_real_hypervisors  # noqa: F401  (the fixture)

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")

MACHINE_ID = "7f8f2b1e-0000-4000-8000-000000000001"
ENV_ID = "7f8f2b1e-0000-4000-8000-0000000000e1"
UPSTREAM = "UPSTREAM-TEXT /vmfs/volumes/secret-path root@host"


def needs_pyvmomi() -> Any:
    return pytest.importorskip("pyVmomi")


def spec(name: str = "slipway-shop-blue", **kw: Any) -> VmSpec:
    values = dict(name=name, datastore="datastore1", resource_pool="Resources", port_group="VM Network", cores=2,
                  memory_mb=4096, annotation="VM Slipway made for shop's blue slot",
                  owner=esxi.owner_keys(MACHINE_ID, ENV_ID),
                  guestinfo={"guestinfo.metadata": "bWV0YQ==", "guestinfo.metadata.encoding": "base64",
                             "guestinfo.userdata": "UFJJVkFURS1LRVk=", "guestinfo.userdata.encoding": "base64"})
    values.update(kw)
    return VmSpec(**values)


def host_with_seed(**seed: Any) -> FakeEsxi:
    fake = FakeEsxi()
    fake.add_datastore("datastore1")
    fake.add_network("VM Network")
    fake.add_vm("ubuntu-2404-seed", **seed)
    return fake


SEED_DISK = "[datastore1] ubuntu-2404-seed/ubuntu-2404-seed.vmdk"


async def make_vm(fake: FakeEsxi, name: str = "slipway-shop-blue", disk_gb: int | None = None) -> esxi.VmInfo:
    vm = await fake.create_vm(spec(name))
    path = f"{vm.folder}/{name}-disk0.vmdk"
    await fake.copy_disk(SEED_DISK, path)
    await fake.attach_disk(vm.uuid, path)
    if disk_gb:
        await fake.grow_disk(vm.uuid, disk_gb)
    return await fake.find_vm(vm.uuid)


# ============================================================ 15. FakeEsxi behaves as ESXi


async def test_fake_names_are_unique_and_a_taken_folder_gives_name_1():
    fake = host_with_seed()
    first = await fake.create_vm(spec())
    assert first.path == "[datastore1] slipway-shop-blue/slipway-shop-blue.vmx"
    assert first.owner == MACHINE_ID and first.environment == ENV_ID
    with pytest.raises(TaskFailed, match="already has a VM with that name"):
        await fake.create_vm(spec())
    # Leftover files of an earlier attempt keep their folder: ESXi puts the new VM in <name>_1/.
    fake.add_file("[datastore1] slipway-shop-green/slipway-shop-green-disk0.vmdk", 10)
    second = await fake.create_vm(spec("slipway-shop-green"))
    assert second.folder == "[datastore1] slipway-shop-green_1"


async def test_fake_copy_attach_and_grow():
    fake = host_with_seed(disk_gb=10)
    vm = await make_vm(fake, disk_gb=64)
    assert [d.base for d in vm.disks] == ["[datastore1] slipway-shop-blue/slipway-shop-blue-disk0.vmdk"]
    assert vm.disks[0].size_gb == 64
    assert fake.folder_files(vm.folder) == [
        "[datastore1] slipway-shop-blue/slipway-shop-blue-disk0-flat.vmdk",
        "[datastore1] slipway-shop-blue/slipway-shop-blue-disk0.vmdk",
        "[datastore1] slipway-shop-blue/slipway-shop-blue.vmx",
    ]
    with pytest.raises(TaskFailed, match="a file is already where"):
        await fake.copy_disk(SEED_DISK, vm.disks[0].base)
    with pytest.raises(MachineError, match="never shrinks"):
        await fake.grow_disk(vm.uuid, 20)
    assert await fake.disk_users(vm.disks[0].base) == ["slipway-shop-blue"]


async def test_fake_grow_is_refused_while_the_vm_has_snapshots():
    fake = host_with_seed()
    vm = await make_vm(fake)
    await fake.take_snapshot(vm.uuid, "slipway-20261115T100000Z", quiesce=False)
    with pytest.raises(TaskFailed, match="couldn't grow"):
        await fake.grow_disk(vm.uuid, 80)


async def test_fake_size_changes_only_while_off_and_revert_leaves_the_vm_off():
    fake = host_with_seed()
    vm = await make_vm(fake)
    await fake.power_on(vm.uuid)
    with pytest.raises(TaskFailed, match="power state"):
        await fake.set_size(vm.uuid, 4, 8192)
    await fake.take_snapshot(vm.uuid, "slipway-20261115T100000Z")
    snap = (await fake.snapshots(vm.uuid))[0]
    assert snap.quiesced and snap.current
    await fake.revert_snapshot(vm.uuid, snap.id)
    assert (await fake.find_vm(vm.uuid)).power == "poweredOff"
    await fake.set_size(vm.uuid, 4, 8192)
    after = await fake.find_vm(vm.uuid)
    assert (after.cores, after.memory_mb) == (4, 8192)


async def test_fake_destroy_is_refused_while_on_and_leaves_unattached_files():
    fake = host_with_seed()
    vm = await make_vm(fake)
    await fake.power_on(vm.uuid)
    with pytest.raises(TaskFailed, match="power state"):
        await fake.destroy(vm.uuid)
    await fake.power_off(vm.uuid)
    fake.add_file(f"{vm.folder}/stray-disk.vmdk", 5)  # a file no VM has attached
    await fake.destroy(vm.uuid)
    assert await fake.find_vm(vm.uuid) is None
    assert await fake.list_folder(vm.folder) == ["stray-disk.vmdk"]
    # An unattached copy is never deleted by destroy: ESXi leaks it, so Slipway deletes it first (§8.5).
    fake2 = host_with_seed()
    vm2 = await fake2.create_vm(spec())
    await fake2.copy_disk(SEED_DISK, f"{vm2.folder}/slipway-shop-blue-disk0.vmdk")
    await fake2.destroy(vm2.uuid)
    assert await fake2.list_folder(vm2.folder) == ["slipway-shop-blue-disk0-flat.vmdk", "slipway-shop-blue-disk0.vmdk"]
    # With every file gone, the folder goes too.
    await fake2.delete_disk(f"{vm2.folder}/slipway-shop-blue-disk0.vmdk")
    assert await fake2.list_folder(vm2.folder) is None


async def test_fake_tools_addresses_and_extra_config():
    fake = host_with_seed()
    vm = await make_vm(fake)
    fake.boot_ips("slipway-shop-blue", ["10.0.0.12"])
    assert (await fake.guest(vm.uuid)).ipv4 == ()
    await fake.power_on(vm.uuid)
    assert (await fake.guest(vm.uuid)).ipv4 == ("10.0.0.12",)
    assert await fake.guest_ips() == {"slipway-shop-blue": ["10.0.0.12"]}
    assert "guestinfo.userdata" in vm.guestinfo_keys
    await fake.set_extra_config(vm.uuid, {"guestinfo.userdata": "", "guestinfo.userdata.encoding": ""})
    after = await fake.find_vm(vm.uuid)
    assert after.guestinfo_keys == ("guestinfo.metadata", "guestinfo.metadata.encoding")
    assert after.owner == MACHINE_ID  # the markers stay
    assert "PRIVATE" not in repr(after) and "UFJJVkFURS1LRVk" not in repr(after)


async def test_fake_snapshot_deltas_and_consolidation():
    fake = host_with_seed()
    vm = await make_vm(fake)
    await fake.take_snapshot(vm.uuid, "a", quiesce=False)
    await fake.take_snapshot(vm.uuid, "b", quiesce=False)
    disk = (await fake.find_vm(vm.uuid)).disks[0]
    assert disk.chain == (
        "[datastore1] slipway-shop-blue/slipway-shop-blue-disk0.vmdk",
        "[datastore1] slipway-shop-blue/slipway-shop-blue-disk0-000001.vmdk",
        "[datastore1] slipway-shop-blue/slipway-shop-blue-disk0-000002.vmdk",
    )
    assert disk.base == disk.chain[0] and disk.path == disk.chain[-1]
    snaps = await fake.snapshots(vm.uuid)
    assert [s.name for s in snaps] == ["a", "b"] and snaps[1].parent_id == snaps[0].id
    await fake.delete_snapshot(vm.uuid, snaps[1].id)
    assert len((await fake.find_vm(vm.uuid)).disks[0].chain) == 2
    assert [s.current for s in await fake.snapshots(vm.uuid)] == [True]


async def test_fake_browser_and_recent_tasks():
    fake = host_with_seed()
    assert await fake.list_folder("[datastore1] nothing-here") is None
    assert await fake.file_exists(SEED_DISK)
    vm = await make_vm(fake)
    started: list[TaskRef] = []

    async def record(ref: TaskRef) -> None:
        started.append(ref)
        # While ESXi runs it, the task is in recentTask.
        assert [r.id for r in await fake.running_tasks(vm.uuid)] == [ref.id]

    await fake.power_on(vm.uuid, on_task=record)
    assert [r.kind for r in started] == ["power_on"] and started[0].ours
    other = fake.task_running("snapshot", 2, uuid=vm.uuid)
    assert await fake.running_tasks(vm.uuid) == [other]
    assert await fake.running_tasks() == [other]  # host-wide
    assert await fake.running_tasks(vm.uuid) == []  # finished after two polls


async def test_fake_knobs_quiesce_timeout_late_snapshot():
    fake = host_with_seed()
    vm = await make_vm(fake)
    await fake.power_on(vm.uuid)
    fake.quiesce_fails()
    with pytest.raises(QuiesceFailed):
        await fake.take_snapshot(vm.uuid, "q")
    await fake.take_snapshot(vm.uuid, "q", quiesce=False)  # crash-consistent goes
    fake.snapshot_task_late()
    with pytest.raises(TaskFailed):
        await fake.take_snapshot(vm.uuid, "late", quiesce=False)
    assert "late" in [s.name for s in await fake.snapshots(vm.uuid)]  # it appeared anyway
    fake.task_times_out("revert", polls=2)
    snap = (await fake.snapshots(vm.uuid))[0]
    with pytest.raises(TaskTimedOut) as caught:
        await fake.revert_snapshot(vm.uuid, snap.id)
    assert caught.value.task in await fake.running_tasks(vm.uuid)  # left running (D24)
    assert await fake.cancel_task(caught.value.task) is False  # and never cancelled
    assert await fake.running_tasks(vm.uuid) == [caught.value.task]
    assert await fake.running_tasks(vm.uuid) == []  # it finished on its own
    assert (await fake.find_vm(vm.uuid)).power == "poweredOn"  # the revert never happened


async def test_fake_api_type_and_licence_knobs():
    assert (await FakeEsxi(api_type="VirtualCenter").about()).api_type == "VirtualCenter"
    assert await FakeEsxi(editions=["esxBasic"]).license_editions() == ["esxBasic"]


@pytest.mark.parametrize("cancelable", [True, False])
async def test_fake_copy_cut_leaves_a_partial_file(cancelable):
    fake = host_with_seed()
    vm = await fake.create_vm(spec())
    fake.copy_cancelable(cancelable)
    fake.copy_cut(3)
    seen: list[TaskRef] = []

    async def record(ref: TaskRef) -> None:
        seen.append(ref)

    dest = f"{vm.folder}/slipway-shop-blue-disk0.vmdk"
    with pytest.raises(TaskTimedOut) as caught:
        await fake.copy_disk(SEED_DISK, dest, on_task=record)
    assert seen and seen[0].kind == COPY_KIND
    assert caught.value.cancelled is cancelable
    assert await fake.file_exists(dest)  # partial: E5 deletes it before copying again
    running = await fake.running_tasks()
    if cancelable:
        assert running == []
    else:
        assert [r.id for r in running] == [seen[0].id]
        assert await fake.cancel_task(running[0]) is False


async def test_fake_cancel_task_stops_a_cancelable_copy_only():
    fake = FakeEsxi()
    copy = fake.task_running(COPY_KIND, 5)
    snapshot = fake.task_running("snapshot", 5)
    assert await fake.cancel_task(snapshot) is False
    assert await fake.cancel_task(copy) is True
    assert [r.id for r in await fake.running_tasks()] == [snapshot.id]


# ======================================================== 16. PyvmomiEsxi over fake_vim


@pytest.fixture
def vim_host():
    needs_pyvmomi()
    from tests.fake_vim import FakeServiceInstance

    si = FakeServiceInstance()
    si.add_datastore("datastore1", folders={"[datastore1] slipway-shop-blue": ["slipway-shop-blue.vmx"]})
    si.add_network("VM Network")
    api = esxi.PyvmomiEsxi(si, host="esxi.lan", poll=0)
    yield si, api
    api.executor.shutdown(wait=True)


def _vm_with_disk(si: Any, name: str = "slipway-shop-blue", **kw: Any) -> Any:
    from tests.fake_vim import disk, scsi_controller

    devices = [scsi_controller(), disk(f"[datastore1] {name}/{name}-disk0.vmdk", 64)]
    extra = {**esxi.owner_keys(MACHINE_ID, ENV_ID), "guestinfo.userdata": "UFJJVkFURS1LRVk=",
             "disk.EnableUUID": "TRUE"}
    return si.add_vm(name, devices=devices, extra=extra, **kw)


async def test_task_states_and_on_task_before_the_wait(vim_host):
    si, api = vim_host
    vm = _vm_with_disk(si)
    si.world.script("PowerOnVM_Task", states=["queued", "running", "running", "success"])
    order: list[str] = []

    async def record(ref: TaskRef) -> None:
        order.append(f"on_task {ref.kind} {ref.state}")
        si.world.note("on_task")

    await api.power_on(vm.config.instanceUuid, on_task=record)
    assert vm.runtime.powerState == "poweredOn"
    names = [c for c in (c for c, _ in si.world.calls) if c != "FindByUuid"]
    # Started, read once for the report, reported, then polled through running, running and success.
    assert names == ["PowerOnVM_Task", "Task.info PowerOnVM_Task", "on_task"] + ["Task.info PowerOnVM_Task"] * 3
    assert order == ["on_task power_on queued"]
    # Already on: no new task.
    await api.power_on(vm.config.instanceUuid)
    assert names.count("PowerOnVM_Task") == 1


async def test_a_task_error_is_slipways_text_never_esxis(vim_host):
    from pyVmomi import vim

    si, api = vim_host
    vm = _vm_with_disk(si)
    si.world.script("PowerOnVM_Task", error=vim.fault.InvalidPowerState(msg=UPSTREAM))
    with pytest.raises(TaskFailed) as caught:
        await api.power_on(vm.config.instanceUuid)
    assert caught.value.text == "ESXi couldn't power on the VM: the VM's power state doesn't allow it"
    assert caught.value.task is not None and caught.value.task.kind == "power_on"
    assert UPSTREAM not in str(caught.value) and caught.value.__cause__ is None


def _fault_cases() -> list[tuple[Any, type, str, bool]]:
    from pyVmomi import Security, vim, vmodl

    return [
        (vim.fault.InvalidLogin(msg=UPSTREAM), MachineError, esxi.LOGIN_TEXT, False),
        (vim.fault.RestrictedVersion(msg=UPSTREAM), MachineError, esxi.LICENCE_TEXT, False),
        (vim.fault.NoPermission(msg=UPSTREAM), TaskFailed, "doesn't allow the account's user to do it", False),
        (vim.fault.FileNotFound(msg=UPSTREAM), esxi.FileMissing, "isn't on the datastore", False),
        (vim.fault.FileAlreadyExists(msg=UPSTREAM), TaskFailed, "a file is already where", False),
        (vim.fault.TaskInProgress(msg=UPSTREAM), TaskFailed, "another task is running", False),
        (vim.fault.InsufficientResourcesFault(msg=UPSTREAM), TaskFailed, "hasn't room", False),
        (vmodl.fault.ManagedObjectNotFound(msg=UPSTREAM), TaskFailed, "gone from ESXi", False),
        (vim.fault.NotAuthenticated(msg=UPSTREAM), MachineError, "ended Slipway's session", True),
        (vim.fault.GuestOperationsFault(msg=UPSTREAM), TaskFailed, "(GuestOperationsFault)", False),
        (Security.ThumbprintMismatchException("aa", "bb"), esxi.CertificateChanged, "isn't the one Slipway trusts", True),
        (ssl.SSLCertVerificationError(UPSTREAM), esxi.CertificateChanged, "isn't the one Slipway trusts", True),
        (ConnectionRefusedError(UPSTREAM), MachineError, "can't reach ESXi at esxi.lan", True),
        (TimeoutError(UPSTREAM), MachineError, "didn't answer in time", True),
        (RuntimeError(UPSTREAM), TaskFailed, "Something went wrong", False),
    ]


def test_fault_mapping():
    needs_pyvmomi()
    for fault, cls, text, unreachable in _fault_cases():
        err = esxi.map_fault(fault, doing="do it", host="esxi.lan")
        assert isinstance(err, cls), (fault, err)
        assert text in err.text, (fault, err.text)
        assert err.unreachable is unreachable, fault
        assert UPSTREAM not in err.text and "secret-path" not in err.text


async def test_quiesce_failed(vim_host):
    from pyVmomi import vim

    si, api = vim_host
    vm = _vm_with_disk(si, power="poweredOn")
    uuid = vm.config.instanceUuid
    si.world.script("CreateSnapshot_Task", error=vim.fault.ApplicationQuiesceFault(msg=UPSTREAM))
    with pytest.raises(QuiesceFailed):
        await api.take_snapshot(uuid, "slipway-20261115T100000Z")
    # The same fault without quiescing asked for is an ordinary failure.
    si.world.script("CreateSnapshot_Task", error=vim.fault.ApplicationQuiesceFault(msg=UPSTREAM))
    with pytest.raises(TaskFailed) as caught:
        await api.take_snapshot(uuid, "slipway-20261115T100000Z", quiesce=False)
    assert not isinstance(caught.value, QuiesceFailed)
    # A generic snapshot fault whose message names quiescing is QuiesceFailed too.
    si.world.script("CreateSnapshot_Task", error=vim.fault.SnapshotFault(msg="An error occurred while quiescing"))
    with pytest.raises(QuiesceFailed):
        await api.take_snapshot(uuid, "slipway-20261115T100000Z")
    assert "CreateSnapshot_Task quiesce=True memory=False" in [c for c, _ in si.world.calls]


def test_guest_ipv4_keeps_real_vnics_only():
    needs_pyvmomi()
    from tests.fake_vim import nic

    guest = SimpleNamespace(net=[
        nic(4000, "10.0.0.12", "fe80::250:56ff:fe00:1", "169.254.3.4"),
        nic(-1, "172.17.0.1"),  # docker0: not a vNIC of the VM
        nic(4001, "127.0.0.1", "10.0.1.5", "10.0.0.12"),
    ])
    assert esxi.guest_ipv4(guest) == ["10.0.0.12", "10.0.1.5"]
    no_config = SimpleNamespace(net=[SimpleNamespace(deviceConfigId=4000, ipConfig=None, ipAddress=["10.0.0.9"])])
    assert esxi.guest_ipv4(no_config) == ["10.0.0.9"]
    assert esxi.guest_ipv4(SimpleNamespace(net=None)) == []


async def test_owner_of_and_vm_info(vim_host):
    si, api = vim_host
    vm = _vm_with_disk(si)
    assert esxi.owner_of(vm) == MACHINE_ID
    assert esxi.owner_of(SimpleNamespace(config=None)) is None
    assert esxi.owner_of(si.add_vm("someone-else")) is None
    info = await api.find_vm(vm.config.instanceUuid)
    assert info.owner == MACHINE_ID and info.environment == ENV_ID
    assert info.extra == esxi.owner_keys(MACHINE_ID, ENV_ID)
    assert info.guestinfo_keys == ("guestinfo.userdata",)
    assert "UFJJVkFURS1LRVk" not in repr(info)
    assert info.disks[0].base == "[datastore1] slipway-shop-blue/slipway-shop-blue-disk0.vmdk"
    assert info.disks[0].size_gb == 64
    assert info.folder == "[datastore1] slipway-shop-blue"
    assert (await api.find_vm_by_name("slipway-shop-blue")).uuid == info.uuid
    assert await api.find_vm("no-such-uuid") is None
    with pytest.raises(VmGone):
        await api.guest("no-such-uuid")


def test_create_config():
    needs_pyvmomi()
    from pyVmomi import vim

    config = esxi.create_config(spec())
    assert config.name == "slipway-shop-blue" and config.guestId == "ubuntu64Guest"
    assert (config.numCPUs, config.memoryMB) == (2, 4096)
    assert config.files.vmPathName == "[datastore1]"
    assert config.annotation == "VM Slipway made for shop's blue slot"
    devices = [c.device for c in config.deviceChange]
    assert all(c.operation == "add" for c in config.deviceChange)
    assert [type(d) for d in devices] == [vim.vm.device.ParaVirtualSCSIController, vim.vm.device.VirtualVmxnet3]
    assert devices[1].backing.deviceName == "VM Network" and devices[1].connectable.startConnected
    extra = {o.key: o.value for o in config.extraConfig}
    assert extra["disk.EnableUUID"] == "TRUE"
    assert extra["slipway.machine"] == MACHINE_ID and extra["slipway.environment"] == ENV_ID
    assert {k for k in extra if k.startswith("guestinfo.")} == {
        "guestinfo.metadata", "guestinfo.metadata.encoding", "guestinfo.userdata", "guestinfo.userdata.encoding"}
    with pytest.raises(ValueError, match="both of Slipway's markers"):
        esxi.create_config(spec(owner={"slipway.machine": MACHINE_ID}))
    with pytest.raises(ValueError, match="guestinfo"):
        esxi.create_config(spec(guestinfo={"slipway.machine": "x"}))
    with pytest.raises(ValueError):
        esxi.create_config(spec(name="not-a-slipway-vm"))
    assert "UFJJVkFURS1LRVk" not in repr(spec())


async def test_create_attach_grow_and_extra_config_specs(vim_host):
    si, api = vim_host
    reported: list[TaskRef] = []

    async def record(ref: TaskRef) -> None:
        reported.append(ref)

    info = await api.create_vm(spec(), on_task=record)
    assert [r.kind for r in reported] == ["create_vm"]
    config, pool = si.folder.created[0]
    assert pool.name == "Resources" and config.name == "slipway-shop-blue"
    vm = next(o for o in si.world.of("VirtualMachine") if o.name == "slipway-shop-blue")
    assert info.uuid == vm.config.instanceUuid and info.owner == MACHINE_ID

    path = "[datastore1] slipway-shop-blue/slipway-shop-blue-disk0.vmdk"
    await api.copy_disk("[datastore1] ubuntu-2404-seed/ubuntu-2404-seed.vmdk", path, on_task=record)
    copy = si.disks.copies[0]
    assert copy["dest"] == path and copy["spec"].diskType == "thin" and copy["force"] is False
    assert reported[-1].kind == COPY_KIND and reported[-1].is_copy

    await api.attach_disk(info.uuid, path)
    added = vm.reconfigs[-1].deviceChange[0]
    assert added.operation == "add" and added.device.backing.fileName == path
    assert added.device.controllerKey == esxi.SCSI_KEY and added.device.unitNumber == 0
    assert added.device.backing.diskMode == "persistent"

    await api.grow_disk(info.uuid, 64)
    edit = vm.reconfigs[-1].deviceChange[0]
    assert edit.operation == "edit" and edit.device.capacityInKB == 64 * 1024 * 1024
    count = len(vm.reconfigs)
    await api.grow_disk(info.uuid, 64)  # already that size: nothing
    assert len(vm.reconfigs) == count
    with pytest.raises(MachineError, match="never shrinks"):
        await api.grow_disk(info.uuid, 20)

    await api.set_extra_config(info.uuid, {"guestinfo.userdata": "", "guestinfo.userdata.encoding": ""})
    assert "guestinfo.userdata" not in vm.extra() and vm.extra()["slipway.machine"] == MACHINE_ID
    await api.set_size(info.uuid, 4, 8192)
    assert (vm.config.hardware.numCPU, vm.config.hardware.memoryMB) == (4, 8192)


async def test_snapshots_tree_revert_and_delete(vim_host):
    from tests.fake_vim import SnapshotNode

    si, api = vim_host
    vm = _vm_with_disk(si, power="poweredOn")
    b = SnapshotNode(2, "slipway-20261115T110000Z", quiesced=True)
    a = SnapshotNode(1, "slipway-20261115T100000Z", childSnapshotList=[b])
    vm.set_snapshots([a], current=2)
    snaps = await api.snapshots(vm.config.instanceUuid)
    assert [(s.id, s.name, s.parent_id, s.current, s.quiesced) for s in snaps] == [
        (1, "slipway-20261115T100000Z", None, False, False),
        (2, "slipway-20261115T110000Z", 1, True, True),
    ]
    assert snaps[0].created.tzinfo is not None
    await api.revert_snapshot(vm.config.instanceUuid, 1)
    assert vm.runtime.powerState == "poweredOff"
    await api.delete_snapshot(vm.config.instanceUuid, 2)
    assert vm.removed_snapshots == [2]
    with pytest.raises(MachineError, match="no snapshot with the id 9"):
        await api.delete_snapshot(vm.config.instanceUuid, 9)


async def test_browser_disk_users_guest_ips_and_tasks(vim_host):
    from tests.fake_vim import nic

    si, api = vim_host
    vm = _vm_with_disk(si, net=[nic(4000, "10.0.0.12")])
    assert await api.list_folder("[datastore1] slipway-shop-blue") == ["slipway-shop-blue.vmx"]
    assert await api.list_folder("[datastore1] gone") is None
    assert await api.file_exists("[datastore1] slipway-shop-blue/slipway-shop-blue.vmx")
    assert not await api.file_exists("[datastore1] slipway-shop-blue/other.vmdk")
    assert await api.disk_users("[datastore1]  slipway-shop-blue/slipway-shop-blue-disk0.vmdk") == ["slipway-shop-blue"]
    assert await api.guest_ips() == {"slipway-shop-blue": ["10.0.0.12"]}

    si.world.script("CopyVirtualDisk_Task", states=["running"], cancelable=True)
    copy = si.disks.CopyVirtualDisk_Task("a", destName="b")
    si.world.script("CreateSnapshot_Task", states=["running"])
    snap = vm.CreateSnapshot_Task("x", "", False, False)
    host_wide = await api.running_tasks()
    assert {r.id: r.kind for r in host_wide} == {copy._moId: COPY_KIND, snap._moId: "snapshot"}
    on_vm = await api.running_tasks(vm.config.instanceUuid)
    assert [r.id for r in on_vm] == [snap._moId] and on_vm[0].entity == "slipway-shop-blue"
    assert on_vm[0].started_at == datetime(2026, 11, 15, 10, 2, tzinfo=UTC)
    assert await api.cancel_task(on_vm[0]) is False and snap.cancel_calls == 0
    copy_ref = next(r for r in host_wide if r.is_copy)
    assert await api.cancel_task(copy_ref) is True and copy.cancel_calls == 1


async def test_every_call_runs_on_the_one_executor_thread(vim_host):
    si, api = vim_host
    vm = _vm_with_disk(si)
    await api.about()
    await api.find_vm(vm.config.instanceUuid)
    await api.power_on(vm.config.instanceUuid)
    await api.snapshots(vm.config.instanceUuid)
    threads = {name for _, name in si.world.calls}
    assert len(threads) == 1
    (name,) = threads
    assert name.startswith("slipway-esxi") and name != threading.current_thread().name


def _certificate() -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost.localdomain")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return pem, tls_pin.fingerprint(cert)


def test_smart_connect_arguments(monkeypatch):
    needs_pyvmomi()
    from pyVim import connect

    seen: dict[str, Any] = {}
    monkeypatch.setattr(connect, "SmartConnect", lambda **kw: seen.update(kw) or "si")
    pem, fp = _certificate()
    original = getattr(esxi._smart_connect, "__wrapped__", esxi._smart_connect)  # under the guard's wrapper
    assert original("esxi.lan", 443, "slipway", "pw-123", pem, fp) == "si"
    assert seen["host"] == "esxi.lan" and seen["port"] == 443 and seen["user"] == "slipway"
    assert seen["thumbprint"] == fp
    assert seen["httpConnectionTimeout"] == 30
    ctx = seen["sslContext"]
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.check_hostname is False and ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.cert_store_stats()["x509"] == 1  # the pinned certificate and nothing else


def _account(**config: Any) -> SimpleNamespace:
    pem, fp = _certificate()
    base = {"url": "https://esxi.lan", "user": "slipway", "datastore": "datastore1", "resource_pool": "Resources",
            "source_vm": "ubuntu-2404-seed",
            "networks": [{"name": "lan", "port_group": "VM Network", "subnet": "10.0.0.0/24", "gateway": "10.0.0.1",
                          "dns_servers": [], "pool": None}]}
    base.update(config)
    return SimpleNamespace(id="acct-1", name="lab", config=base, secret="pw-123",
                           tls={"pem": pem, "fingerprint_sha256": fp}, facts={})


async def test_session_signs_in_on_the_executor_and_always_signs_out(monkeypatch):
    needs_pyvmomi()
    from tests.fake_vim import FakeServiceInstance

    si = FakeServiceInstance()
    args: dict[str, Any] = {}

    def fake_connect(host, port, user, password, pem, fingerprint):
        args.update(host=host, port=port, user=user, thread=threading.current_thread().name)
        return si

    monkeypatch.setattr(esxi, "_smart_connect", fake_connect)
    account = _account(url="https://esxi.lan:8443")
    with pytest.raises(RuntimeError):
        async with esxi.session(account) as api:
            assert (await api.about()).api_type == "HostAgent"
            raise RuntimeError("the caller failed")
    assert args["host"] == "esxi.lan" and args["port"] == 8443 and args["thread"].startswith("slipway-esxi")
    assert si.world.logged_out and si.world.dropped
    threads = {name for _, name in si.world.calls}
    assert len(threads) == 1 and threads == {args["thread"]}


async def test_session_refuses_an_account_it_cant_use(monkeypatch):
    account = _account()
    account.secret = None
    with pytest.raises(MachineError, match="has no password"):
        async with esxi.session(account):
            pass
    account = _account()
    account.tls = None
    with pytest.raises(MachineError, match="no certificate is trusted"):
        async with esxi.session(account):
            pass


async def test_a_sign_in_failure_is_mapped(monkeypatch):
    needs_pyvmomi()
    from pyVmomi import vim

    def refuse(*args):
        raise vim.fault.InvalidLogin(msg=UPSTREAM)

    monkeypatch.setattr(esxi, "_smart_connect", refuse)
    with pytest.raises(MachineError) as caught:
        async with esxi.session(_account()):
            pass
    assert caught.value.text == esxi.LOGIN_TEXT


async def test_read_sessions_give_up_after_a_short_wait(monkeypatch):
    monkeypatch.setattr(esxi, "READ_WAIT", 0.01)
    gate = esxi.read_sessions["acct-busy"]
    for _ in range(esxi.SESSIONS_PER_ACCOUNT):
        await gate.acquire()
    account = _account()
    account.id = "acct-busy"
    try:
        with pytest.raises(MachineError, match="busy"):
            async with esxi.session(account, purpose="read"):
                pass
    finally:
        for _ in range(esxi.SESSIONS_PER_ACCOUNT):
            gate.release()


# ====================================================== 17. Test, clean_config, cancelling


def _good_host() -> FakeEsxi:
    fake = FakeEsxi()
    fake.add_datastore("datastore1", free_gb=412.5, capacity_gb=1000)
    fake.add_network("VM Network")
    fake.add_vm("ubuntu-2404-seed", disk_gb=10)
    return fake


async def _run(fake: FakeEsxi, account: SimpleNamespace | None = None) -> tuple[dict[str, Any], SimpleNamespace]:
    account = account or _account()
    checks = await esxi.run_test(account, open_session=fake.session_factory())
    return {c.name: c for c in checks}, account


async def test_run_test_passes_and_records_facts():
    checks, account = await _run(_good_host())
    assert all(c.ok for c in checks.values()), checks
    assert list(checks) == ["api", "licence", "datastore", "network:lan", "resource_pool", "seed"]
    assert checks["api"].text == "ESXi 8.0.3 (build 24022510)"
    assert checks["datastore"].text == "datastore1: 412.5 GB free of 1000 GB"
    assert account.facts == {"version": "8.0.3", "free_gb": 412.5}


async def test_run_test_refuses_vcenter_and_free_esxi():
    fake = _good_host()
    fake.api_type = "VirtualCenter"
    checks, _ = await _run(fake)
    assert list(checks) == ["api"] and checks["api"].level == "error"
    assert checks["api"].text == "Slipway works with a standalone ESXi host, not vCenter"
    fake = _good_host()
    fake.editions = ["esxBasic"]
    checks, _ = await _run(fake)
    assert checks["licence"].level == "error" and "free ESXi is read-only" in checks["licence"].text
    assert "datastore" not in checks


async def test_run_test_names_whats_missing():
    fake = FakeEsxi()
    checks, _ = await _run(fake)
    assert checks["datastore"].text == "ESXi has no datastore named datastore1"
    assert checks["network:lan"].text == "ESXi has no port group named VM Network (network lan)"
    assert checks["seed"].text == "ESXi has no VM named ubuntu-2404-seed to copy the disk from"
    checks, _ = await _run(_good_host(), _account(resource_pool="Slipway"))
    assert checks["resource_pool"].text == "ESXi has no resource pool named Slipway"
    checks, _ = await _run(_good_host(), _account(networks=[]))
    assert checks["networks"].level == "warning"
    fake = _good_host()
    fake.add_datastore("datastore1", accessible=False)
    checks, _ = await _run(fake)
    assert checks["datastore"].level == "error" and "isn't accessible" in checks["datastore"].text


@pytest.mark.parametrize(("seed", "text"), [
    ({"power": "poweredOn"}, "ubuntu-2404-seed is running; Slipway copies its disk only while it is off: shut it down"),
    ({"disks": 2}, "ubuntu-2404-seed has 2 disks; the seed VM must have exactly one"),
    ({"disks": 0}, "ubuntu-2404-seed has 0 disks; the seed VM must have exactly one"),
    ({"snapshots": 1}, "ubuntu-2404-seed has VM snapshots; delete them so Slipway copies one whole disk"),
])
async def test_run_test_seed_rules(seed, text):
    fake = FakeEsxi()
    fake.add_datastore("datastore1")
    fake.add_network("VM Network")
    fake.add_vm("ubuntu-2404-seed", **seed)
    checks, _ = await _run(fake)
    assert checks["seed"].level == "error" and checks["seed"].text == text


async def test_run_test_reports_a_connection_failure_as_one_check():
    fake = _good_host()
    fake.fail("about", "Slipway can't reach ESXi at esxi.lan")
    checks, account = await _run(fake)
    assert list(checks) == ["connect"] and checks["connect"].text == "Slipway can't reach ESXi at esxi.lan"
    assert account.facts == {}


GOOD = {"url": "https://ESXi.lan/", "user": "slipway", "datastore": "datastore1", "source_vm": "ubuntu-2404-seed",
        "networks": [{"name": "lan", "port_group": "VM Network", "subnet": "10.0.0.0/24", "gateway": "10.0.0.1"}]}


def test_clean_config_accepts_and_normalises():
    out = esxi.clean_config(dict(GOOD), "Hunter2-secret")
    assert out["url"] == "https://esxi.lan"
    assert out["resource_pool"] == "Resources"
    assert out["networks"][0]["port_group"] == "VM Network"
    assert "secret" not in out and "Hunter2" not in repr(out)
    assert esxi.clean_config({**GOOD, "url": "https://10.0.0.5:8443/sdk"}, None)["url"] == "https://10.0.0.5:8443"
    assert esxi.clean_config({**GOOD, "url": "https://[fd00::5]"}, None)["url"] == "https://[fd00::5]"
    assert esxi.clean_config({**GOOD, "url": "https://esxi.lan:443"}, None)["url"] == "https://esxi.lan"


@pytest.mark.parametrize(("change", "secret", "field"), [
    ({"url": "http://esxi.lan"}, None, "url"),
    ({"url": "https://root:pw@esxi.lan"}, None, "url"),
    ({"url": "https://esxi.lan/ui/#/host"}, None, "url"),
    ({"url": "https://esxi.lan:99999"}, None, "url"),
    ({"url": "https://bad_host!"}, None, "url"),
    ({"url": None}, None, "url"),
    ({"user": ""}, None, "user"),
    ({"user": "root; rm"}, None, "user"),
    ({"datastore": "[ds1]"}, None, "datastore"),
    ({"datastore": ""}, None, "datastore"),
    ({"resource_pool": "pool/child"}, None, "resource_pool"),
    ({"source_vm": None}, None, "source_vm"),
    ({"networks": [{"name": "lan", "bridge": "vmbr0", "subnet": "10.0.0.0/24", "gateway": "10.0.0.1"}]}, None,
     "networks.0.bridge"),
    ({"networks": [{"name": "lan", "port_group": "VM Network", "subnet": "10.0.0.0/24", "gateway": "10.0.1.1"}]},
     None, "networks.0.gateway"),
    ({"networks": [GOOD["networks"][0], GOOD["networks"][0]]}, None, "networks.1.name"),
    ({"token_id": "x"}, None, "token_id"),
    ({}, "", "secret"),
    ({}, "pw\nwith newline", "secret"),
    ({}, "x" * 300, "secret"),
])
def test_clean_config_refusals(change, secret, field):
    with pytest.raises(AccountInvalid) as caught:
        esxi.clean_config({**GOOD, **change}, secret)
    assert caught.value.field == field


def test_clean_config_refuses_a_non_dict():
    with pytest.raises(AccountInvalid) as caught:
        esxi.clean_config(["https://esxi.lan"], None)
    assert caught.value.field == "config"


@pytest.fixture
def slow_host():
    """A ``PyvmomiEsxi`` whose task limits are a few milliseconds, over fake_vim."""
    needs_pyvmomi()
    from tests.fake_vim import FakeServiceInstance

    si = FakeServiceInstance()
    si.add_datastore("datastore1")
    api = esxi.PyvmomiEsxi(si, host="esxi.lan", poll=0.001, task_limit=0.05, copy_limit=0.05)
    yield si, api
    api.executor.shutdown(wait=True)


@pytest.mark.parametrize("cancelable", [True, False])
async def test_a_timed_out_copy_is_cancelled_when_esxi_allows_it(slow_host, cancelable):
    si, api = slow_host
    si.world.script("CopyVirtualDisk_Task", states=["running"], cancelable=cancelable)
    with pytest.raises(TaskTimedOut) as caught:
        await api.copy_disk("[datastore1] seed/seed.vmdk", "[datastore1] vm/vm-disk0.vmdk")
    task = si.world.tasks[-1]
    assert task.cancel_calls == (1 if cancelable else 0)
    assert caught.value.cancelled is cancelable
    assert ("Slipway cancelled the copy" in caught.value.text) is cancelable


async def test_a_timed_out_snapshot_is_left_running(slow_host):
    si, api = slow_host
    vm = _vm_with_disk(si)
    si.world.script("CreateSnapshot_Task", states=["running"], cancelable=True)
    with pytest.raises(TaskTimedOut) as caught:
        await api.take_snapshot(vm.config.instanceUuid, "slipway-20261115T100000Z")
    assert si.world.tasks[-1].cancel_calls == 0
    assert "left it running" in caught.value.text and caught.value.task.kind == "snapshot"


@pytest.mark.parametrize(("method", "kind", "cancels"), [
    ("CopyVirtualDisk_Task", COPY_KIND, 1),
    ("CreateSnapshot_Task", "snapshot", 0),
    ("RevertToSnapshot_Task", "revert", 0),
    ("Destroy_Task", "destroy", 0),
])
async def test_a_cancelled_job_stops_only_a_copy(slow_host, method, kind, cancels):
    from tests.fake_vim import SnapshotNode

    si, api = slow_host
    api.task_limit = api.copy_limit = 60
    vm = _vm_with_disk(si)
    vm.set_snapshots([SnapshotNode(1, "slipway-20261115T100000Z")], current=1)
    uuid = vm.config.instanceUuid
    si.world.script(method, states=["running"], cancelable=True)
    reported = asyncio.Event()

    async def record(ref: TaskRef) -> None:
        assert ref.kind == kind
        reported.set()

    calls = {
        "CopyVirtualDisk_Task": lambda: api.copy_disk("[datastore1] a/a.vmdk", "[datastore1] b/b.vmdk", on_task=record),
        "CreateSnapshot_Task": lambda: api.take_snapshot(uuid, "s", on_task=record),
        "RevertToSnapshot_Task": lambda: api.revert_snapshot(uuid, 1, on_task=record),
        "Destroy_Task": lambda: api.destroy(uuid, on_task=record),
    }
    job = asyncio.create_task(calls[method]())
    await asyncio.wait_for(reported.wait(), 5)
    await asyncio.sleep(0.01)
    job.cancel()
    with pytest.raises(asyncio.CancelledError):
        await job
    assert si.world.tasks[-1].cancel_calls == cancels


async def test_cancel_task_refuses_anything_but_a_copy(slow_host):
    _, api = slow_host
    ref = TaskRef(id="haTask-9", kind="snapshot", description_id="VirtualMachine.createSnapshot", started_at=None,
                  state="running", cancelable=True)
    assert await api.cancel_task(ref) is False
