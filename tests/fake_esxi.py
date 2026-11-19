"""``FakeEsxi``: an in-memory ``EsxiApi`` that behaves like a standalone ESXi host where Slipway depends on it.

Phase 5 §16.1 lists the behaviours, each checked by ``test_esxi_client.py`` (test 15):

* VM names are unique; a VM created where a folder of its name already exists goes in
  ``<name>_1/`` (then ``_2``…), as ESXi does.
* ``copy_disk`` writes the descriptor and its ``-flat`` file, refusing a destination that exists;
  ``attach_disk`` attaches an existing file; ``grow_disk`` refuses while the VM has snapshots, and
  never shrinks.
* Cores and memory change only while the VM is off. A revert leaves the VM off.
* ``destroy`` is refused while the VM is on, and deletes the VMX, the log and the attached disks
  only: an unattached file stays in the folder (so does the folder, then).
* VMware Tools reports the addresses set with ``boot_ips`` once the VM is on.
* extraConfig: an empty value deletes a key.
* A snapshot puts a delta on top of each disk's chain; deleting one consolidates the newest delta.
* ``list_folder`` is the datastore browser (None for a folder that isn't there).
* ``running_tasks`` is ``recentTask`` (a VM's, or the host's with ``uuid=None``).

Knobs: ``quiesce_fails(n)``, ``task_times_out(kind)``, ``snapshot_task_late()``, ``api_type``,
``editions``, ``task_running(kind, n, uuid=None)``, ``copy_cut(n)``, ``copy_cancelable(bool)``,
``boot_ips(name, ips)``, ``ignore_shutdown(name)`` and ``fail(method, text)``.

Every call is written to ``calls`` (method name and first argument) and every task Slipway starts to
``started`` (the ``TaskRef`` handed to ``on_task``), so a test can check the order.
"""

from __future__ import annotations

import itertools
import uuid as uuidlib
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any

from slipway.services.esxi import (
    COPY_KIND,
    OWNER_KEYS,
    About,
    DatastoreInfo,
    DiskInfo,
    FileMissing,
    GuestView,
    OnTask,
    QuiesceFailed,
    SnapshotInfo,
    TaskFailed,
    TaskRef,
    TaskTimedOut,
    VmGone,
    VmInfo,
    VmSpec,
    normalize_path,
    split_path,
)
from slipway.services.vmtypes import MachineError

T0 = datetime(2026, 11, 15, 10, 0, tzinfo=UTC)


@dataclass
class FakeFile:
    size_gb: int = 0


@dataclass
class FakeDisk:
    key: int
    chain: list[str]  # base first
    size_gb: int


@dataclass
class FakeSnap:
    id: int
    name: str
    description: str
    created: datetime
    quiesced: bool
    parent_id: int | None


@dataclass
class FakeVm:
    moref: str
    uuid: str
    name: str
    datastore: str
    folder: str  # relative folder name on the datastore
    cores: int
    memory_mb: int
    annotation: str = ""
    power: str = "poweredOff"
    extra: dict[str, str] = field(default_factory=dict)
    disks: list[FakeDisk] = field(default_factory=list)
    snaps: list[FakeSnap] = field(default_factory=list)
    current: int | None = None
    ips: list[str] = field(default_factory=list)
    tools: bool = False

    @property
    def vmx(self) -> str:
        return f"[{self.datastore}] {self.folder}/{self.name}.vmx"

    @property
    def folder_path(self) -> str:
        return f"[{self.datastore}] {self.folder}"


@dataclass
class FakeTaskState:
    ref: TaskRef
    uuid: str | None
    polls_left: int  # how many more running_tasks calls still see it, once Slipway stopped waiting
    live: bool = False  # Slipway's own call is still inside it


def _flat(path: str) -> str:
    return path[:-5] + "-flat.vmdk" if path.endswith(".vmdk") else path + "-flat"


def _delta(base: str, n: int) -> str:
    return f"{base[:-5]}-{n:06d}.vmdk"


class FakeEsxi:
    """See the module's notes. Build the host with ``add_datastore``, ``add_network`` and ``add_vm``."""

    def __init__(self, *, api_type: str = "HostAgent", editions: list[str] | None = None,
                 version: str = "8.0.3") -> None:
        self.api_type = api_type
        self.editions = list(editions if editions is not None else ["esx.enterprisePlus.cpuPackage"])
        self.version = version
        self.datastores: dict[str, dict[str, Any]] = {}
        self.networks: list[str] = []
        self.pools: list[str] = ["Resources"]
        self.files: dict[str, FakeFile] = {}  # normalized path -> file
        self.dirs: set[str] = set()  # "[ds] folder"
        self.vms: dict[str, FakeVm] = {}
        self.tasks: list[FakeTaskState] = []
        self.calls: list[tuple[str, Any]] = []
        self.started: list[TaskRef] = []
        self.cancelled: list[str] = []
        self._ids = itertools.count(1)
        self._boot_ips: dict[str, list[str]] = {}
        self._ignore_shutdown: set[str] = set()
        self._quiesce_fails = 0
        self._times_out: dict[str, int] = {}
        self._late_snapshot = False
        self._copy_cut: int | None = None
        self._copy_cancelable = True
        self._fail: dict[str, str] = {}

    # -------------------------------------------------------------- building

    def add_datastore(self, name: str = "datastore1", *, free_gb: float = 500, capacity_gb: float = 1000,
                      accessible: bool = True) -> None:
        self.datastores[name] = {"free_gb": free_gb, "capacity_gb": capacity_gb, "accessible": accessible}

    def add_network(self, name: str) -> None:
        self.networks.append(name)

    def add_file(self, path: str, size_gb: int = 0) -> None:
        path = normalize_path(path)
        self.files[path] = FakeFile(size_gb)
        self.dirs.add(path.rsplit("/", 1)[0])

    def add_vm(self, name: str, *, datastore: str = "datastore1", disks: int = 1, disk_gb: int = 10,
               power: str = "poweredOff", snapshots: int = 0, extra: dict[str, str] | None = None,
               cores: int = 2, memory_mb: int = 4096) -> VmInfo:
        """A VM made outside Slipway (a seed, or someone else's), with its files on the datastore."""
        vm = self._new_vm(name, datastore, cores, memory_mb, "", dict(extra or {}))
        vm.power = power
        for i in range(disks):
            path = f"{vm.folder_path}/{name}{'' if i == 0 else f'_{i}'}.vmdk"
            self.add_file(path, disk_gb)
            self.add_file(_flat(path))
            vm.disks.append(FakeDisk(2000 + i, [path], disk_gb))
        for _ in range(snapshots):
            self._snapshot(vm, f"outside-{next(self._ids)}", "", quiesced=False)
        return self._info(vm)

    # ----------------------------------------------------------------- knobs

    def boot_ips(self, name: str, ips: list[str]) -> None:
        """What VMware Tools reports for ``name`` once it is on."""
        self._boot_ips[name] = list(ips)
        for vm in self.vms.values():
            if vm.name == name and vm.power == "poweredOn":
                vm.ips = list(ips)

    def ignore_shutdown(self, name: str) -> None:
        self._ignore_shutdown.add(name)

    def quiesce_fails(self, times: int = 1) -> None:
        self._quiesce_fails = times

    def task_times_out(self, kind: str, polls: int = 3) -> None:
        """The next task of ``kind`` outlives Slipway's wait: ``TaskTimedOut``, its change not made, and
        the task still running for ``polls`` calls of ``running_tasks``."""
        self._times_out[kind] = polls

    def snapshot_task_late(self) -> None:
        """The next snapshot task reports an error, but the snapshot is there afterwards."""
        self._late_snapshot = True

    def task_running(self, kind: str, polls: int, uuid: str | None = None) -> TaskRef:
        """A task someone else started, seen by ``running_tasks`` for ``polls`` calls."""
        ref = TaskRef(id=f"haTask-{next(self._ids)}", kind=kind, description_id=None,
                      started_at=T0, state="running", cancelable=kind == COPY_KIND,
                      entity=self.vms[uuid].name if uuid in self.vms else None)
        self.tasks.append(FakeTaskState(ref, uuid, polls))
        return ref

    def copy_cut(self, polls: int = 1) -> None:
        """The next copy is cut off: a partial file is left, the call fails as a timeout, and unless it
        can be cancelled the copy task stays running for ``polls`` calls of ``running_tasks``."""
        self._copy_cut = polls

    def copy_cancelable(self, value: bool) -> None:
        self._copy_cancelable = value

    def fail(self, method: str, text: str) -> None:
        """The next call of ``method`` raises ``MachineError(text)`` before it changes anything."""
        self._fail[method] = text

    # -------------------------------------------------------------- plumbing

    def _note(self, method: str, arg: Any = None) -> None:
        self.calls.append((method, arg))
        text = self._fail.pop(method, None)
        if text is not None:
            raise MachineError(text)

    def _vm(self, uuid: str) -> FakeVm:
        vm = self.vms.get(uuid)
        if vm is None:
            raise VmGone(f"ESXi has no VM with the instance UUID {uuid}")
        return vm

    async def _start(self, kind: str, uuid: str | None, on_task: OnTask | None) -> FakeTaskState:
        ref = TaskRef(id=f"haTask-{next(self._ids)}", kind=kind, description_id=None, started_at=T0,
                      state="running", cancelable=kind == COPY_KIND and self._copy_cancelable,
                      entity=self.vms[uuid].name if uuid in self.vms else None, ours=True)
        state = FakeTaskState(ref, uuid, 0, live=True)
        self.tasks.append(state)
        self.started.append(ref)
        if on_task is not None:
            await on_task(ref)
        if kind in self._times_out:
            state.live = False
            state.polls_left = self._times_out.pop(kind)
            raise TaskTimedOut(f"ESXi's {ref.words} task {ref.id} didn't finish in 10 minutes; Slipway left it "
                               "running, and the next change waits for it", ref)
        return state

    def _end(self, state: FakeTaskState, ok: bool = True) -> None:
        state.ref = replace(state.ref, state="success" if ok else "error")
        state.polls_left = 0
        state.live = False

    def _new_vm(self, name: str, datastore: str, cores: int, memory_mb: int, annotation: str,
                extra: dict[str, str]) -> FakeVm:
        if any(v.name == name for v in self.vms.values()):
            raise TaskFailed(f"ESXi couldn't create the VM {name}: it already has a VM with that name")
        if datastore not in self.datastores:
            raise TaskFailed(f"ESXi couldn't create the VM {name}: a file it needed isn't on the datastore")
        folder, n = name, 0
        while f"[{datastore}] {folder}" in self.dirs:  # ESXi never reuses a folder: it makes <name>_1
            n += 1
            folder = f"{name}_{n}"
        n = next(self._ids)
        vm = FakeVm(moref=str(n), uuid=str(uuidlib.UUID(int=n)), name=name, datastore=datastore, folder=folder,
                    cores=cores, memory_mb=memory_mb, annotation=annotation, extra=extra)
        self.dirs.add(vm.folder_path)
        self.files[vm.vmx] = FakeFile()
        self.vms[vm.uuid] = vm
        return vm

    def _info(self, vm: FakeVm) -> VmInfo:
        return VmInfo(
            moref=vm.moref, uuid=vm.uuid, name=vm.name, power=vm.power, path=vm.vmx, annotation=vm.annotation,
            cores=vm.cores, memory_mb=vm.memory_mb,
            disks=tuple(DiskInfo(key=d.key, path=d.chain[-1], base=d.chain[0], chain=tuple(d.chain),
                                 size_gb=d.size_gb, controller_key=1000, unit=i) for i, d in enumerate(vm.disks)),
            extra={k: v for k, v in vm.extra.items() if k.startswith("slipway.")},
            guestinfo_keys=tuple(sorted(k for k in vm.extra if k.startswith("guestinfo."))),
            tools_running=vm.tools,
        )

    def _users(self, path: str) -> list[str]:
        return sorted(vm.name for vm in self.vms.values() if any(path in d.chain for d in vm.disks))

    def _snapshot(self, vm: FakeVm, name: str, description: str, *, quiesced: bool) -> FakeSnap:
        snap = FakeSnap(id=next(self._ids), name=name, description=description,
                        created=T0 + timedelta(minutes=len(vm.snaps)), quiesced=quiesced, parent_id=vm.current)
        vm.snaps.append(snap)
        vm.current = snap.id
        for d in vm.disks:  # the running disk becomes a delta on top of the chain
            top = _delta(d.chain[0], len(d.chain))
            self.add_file(top)
            self.add_file(top[:-5] + "-sesparse.vmdk")
            d.chain.append(top)
        return snap

    def _remove_files(self, path: str) -> None:
        for p in (path, _flat(path), path[:-5] + "-sesparse.vmdk"):
            self.files.pop(p, None)

    def _tidy(self, folder: str) -> None:
        if not any(p.startswith(folder + "/") for p in self.files):
            self.dirs.discard(folder)

    # ------------------------------------------------------------------ reads

    async def about(self) -> About:
        self._note("about")
        return About(api_type=self.api_type, version=self.version, build="24022510",
                     full_name=f"VMware ESXi {self.version}")

    async def license_editions(self) -> list[str]:
        self._note("license_editions")
        return list(self.editions)

    async def datastore(self, name: str) -> DatastoreInfo | None:
        self._note("datastore", name)
        ds = self.datastores.get(name)
        return None if ds is None else DatastoreInfo(name=name, free_gb=ds["free_gb"], capacity_gb=ds["capacity_gb"],
                                                     accessible=ds["accessible"])

    async def network_names(self) -> list[str]:
        self._note("network_names")
        return sorted(self.networks)

    async def resource_pool_names(self) -> list[str]:
        self._note("resource_pool_names")
        return sorted(self.pools)

    async def find_vm(self, uuid: str) -> VmInfo | None:
        self._note("find_vm", uuid)
        vm = self.vms.get(uuid)
        return None if vm is None else self._info(vm)

    async def find_vm_by_name(self, name: str) -> VmInfo | None:
        self._note("find_vm_by_name", name)
        for vm in self.vms.values():
            if vm.name == name:
                return self._info(vm)
        return None

    async def guest_ips(self) -> dict[str, list[str]]:
        self._note("guest_ips")
        return {vm.name: list(vm.ips) for vm in self.vms.values() if vm.ips}

    async def disk_users(self, path: str) -> list[str]:
        self._note("disk_users", path)
        return self._users(normalize_path(path))

    async def guest(self, uuid: str) -> GuestView:
        self._note("guest", uuid)
        vm = self._vm(uuid)
        return GuestView(tools_running=vm.tools, ipv4=tuple(vm.ips), hostname=vm.name if vm.tools else None)

    async def snapshots(self, uuid: str) -> list[SnapshotInfo]:
        self._note("snapshots", uuid)
        vm = self._vm(uuid)
        return [SnapshotInfo(id=s.id, name=s.name, description=s.description, created=s.created,
                             quiesced=s.quiesced, current=s.id == vm.current, parent_id=s.parent_id)
                for s in vm.snaps]

    async def file_exists(self, path: str) -> bool:
        self._note("file_exists", path)
        return normalize_path(path) in self.files

    async def list_folder(self, path: str) -> list[str] | None:
        self._note("list_folder", path)
        folder = normalize_path(path)
        if folder not in self.dirs:
            return None
        return sorted(p[len(folder) + 1:] for p in self.files if p.startswith(folder + "/"))

    async def running_tasks(self, uuid: str | None = None) -> list[TaskRef]:
        self._note("running_tasks", uuid)
        out = []
        for state in self.tasks:
            if state.ref.state not in ("queued", "running") or not (state.live or state.polls_left > 0):
                continue
            if uuid is not None and state.uuid != uuid:
                continue
            out.append(state.ref)
            if state.live:
                continue
            state.polls_left -= 1
            if state.polls_left == 0:
                state.ref = replace(state.ref, state="success")
        return out

    async def cancel_task(self, task: TaskRef) -> bool:
        self._note("cancel_task", task.id)
        if not task.is_copy:
            return False  # D24: only a disk copy is ever cancelled
        for state in self.tasks:
            if state.ref.id == task.id and state.ref.state in ("queued", "running") and (state.live or state.polls_left > 0):
                if not state.ref.cancelable:
                    return False
                state.ref = replace(state.ref, state="error")
                state.polls_left = 0
                state.live = False
                self.cancelled.append(task.id)
                return True
        return False

    # ---------------------------------------------------------------- changes

    async def create_vm(self, spec: VmSpec, *, on_task: OnTask | None = None) -> VmInfo:
        self._note("create_vm", spec.name)
        if set(spec.owner) != set(OWNER_KEYS):
            raise ValueError("A VM needs both of Slipway's markers")
        if spec.port_group not in self.networks:
            raise TaskFailed(f"ESXi couldn't create the VM {spec.name} (InvalidDeviceSpec)")
        if (spec.resource_pool or "Resources") not in self.pools:
            raise MachineError(f"ESXi has no resource pool named {spec.resource_pool}")
        state = await self._start("create_vm", None, on_task)
        extra = {"disk.EnableUUID": "TRUE", **spec.owner, **spec.guestinfo}
        vm = self._new_vm(spec.name, spec.datastore, spec.cores, spec.memory_mb, spec.annotation, extra)
        state.uuid = vm.uuid
        self._end(state)
        return self._info(vm)

    async def copy_disk(self, source: str, dest: str, *, on_task: OnTask | None = None) -> None:
        self._note("copy_disk", dest)
        source, dest = normalize_path(source), normalize_path(dest)
        if source not in self.files:
            raise FileMissing("ESXi couldn't copy the seed VM's disk: a file it needed isn't on the datastore")
        if dest in self.files:
            raise TaskFailed("ESXi couldn't copy the seed VM's disk: a file is already where Slipway wanted to write one")
        if dest.rsplit("/", 1)[0] not in self.dirs:
            raise FileMissing("ESXi couldn't copy the seed VM's disk: a file it needed isn't on the datastore")
        state = await self._start(COPY_KIND, None, on_task)
        if self._copy_cut is not None:
            polls, self._copy_cut = self._copy_cut, None
            self.add_file(dest, self.files[source].size_gb)  # the descriptor, then a part of the data
            self.add_file(_flat(dest))
            if state.ref.cancelable:
                self._end(state, ok=False)
                self.cancelled.append(state.ref.id)
                raise TaskTimedOut("ESXi didn't finish copying the disk in 30 minutes; Slipway cancelled the copy",
                                   state.ref, cancelled=True)
            state.live = False
            state.polls_left = polls
            raise TaskTimedOut("ESXi didn't finish copying the disk in 30 minutes; ESXi couldn't cancel it, so it "
                               "may still be running; the next attempt waits for it", state.ref)
        self.add_file(dest, self.files[source].size_gb)
        self.add_file(_flat(dest))
        self._end(state)

    async def delete_disk(self, path: str, *, on_task: OnTask | None = None) -> None:
        self._note("delete_disk", path)
        path = normalize_path(path)
        if path not in self.files:
            raise FileMissing(f"ESXi couldn't delete {path}: a file it needed isn't on the datastore")
        if self._users(path):
            raise TaskFailed(f"ESXi couldn't delete {path}: a file it needs is in use by another VM")
        state = await self._start("delete_disk", None, on_task)
        self._remove_files(path)
        self._tidy(path.rsplit("/", 1)[0])
        self._end(state)

    async def attach_disk(self, uuid: str, path: str, *, on_task: OnTask | None = None) -> None:
        self._note("attach_disk", path)
        vm, path = self._vm(uuid), normalize_path(path)
        if path not in self.files:
            raise FileMissing("ESXi couldn't attach the copied disk: a file it needed isn't on the datastore")
        if self._users(path):
            raise TaskFailed("ESXi couldn't attach the copied disk: a file it needs is in use by another VM")
        state = await self._start("attach_disk", uuid, on_task)
        vm.disks.append(FakeDisk(2000 + len(vm.disks), [path], self.files[path].size_gb))
        self._end(state)

    async def grow_disk(self, uuid: str, size_gb: int, *, on_task: OnTask | None = None) -> None:
        self._note("grow_disk", size_gb)
        vm = self._vm(uuid)
        if len(vm.disks) != 1:
            raise MachineError(f"{vm.name} has {len(vm.disks)} disks; Slipway grows a VM with exactly one")
        disk = vm.disks[0]
        if size_gb < disk.size_gb:
            raise MachineError(f"{vm.name}'s disk is {disk.size_gb} GB; Slipway never shrinks a disk")
        if size_gb == disk.size_gb:
            return
        if vm.snaps:  # ESXi can't extend a disk that has snapshot deltas on top
            raise TaskFailed(f"ESXi couldn't grow {vm.name}'s disk to {size_gb} GB (InvalidDeviceOperation)")
        state = await self._start("grow_disk", uuid, on_task)
        disk.size_gb = size_gb
        self.files[disk.chain[0]].size_gb = size_gb
        self._end(state)

    async def set_size(self, uuid: str, cores: int, memory_mb: int, *, on_task: OnTask | None = None) -> None:
        self._note("set_size", (cores, memory_mb))
        vm = self._vm(uuid)
        if vm.power != "poweredOff":  # no CPU or memory hot-add on Slipway's VMs
            raise TaskFailed(f"ESXi couldn't set the VM to {cores} vCPU and {memory_mb} MB: the VM's power state "
                             "doesn't allow it")
        state = await self._start("set_size", uuid, on_task)
        vm.cores, vm.memory_mb = int(cores), int(memory_mb)
        self._end(state)

    async def set_extra_config(self, uuid: str, values: dict[str, str], *, on_task: OnTask | None = None) -> None:
        self._note("set_extra_config", sorted(values))
        vm = self._vm(uuid)
        state = await self._start("set_extra_config", uuid, on_task)
        for key, value in values.items():
            if value in ("", None):
                vm.extra.pop(key, None)
            else:
                vm.extra[key] = value
        self._end(state)

    async def power_on(self, uuid: str, *, on_task: OnTask | None = None) -> None:
        self._note("power_on", uuid)
        vm = self._vm(uuid)
        if vm.power == "poweredOn":
            return
        if not vm.disks:
            raise TaskFailed("ESXi couldn't power on the VM (it has no disk to boot from)")
        state = await self._start("power_on", uuid, on_task)
        vm.power = "poweredOn"
        vm.tools = True
        vm.ips = list(self._boot_ips.get(vm.name, []))
        self.add_file(f"{vm.folder_path}/vmware.log")
        self._end(state)

    async def shutdown_guest(self, uuid: str) -> None:
        self._note("shutdown_guest", uuid)
        vm = self._vm(uuid)
        if vm.power == "poweredOff":
            return
        if not vm.tools:
            raise TaskFailed("ESXi couldn't shut the VM down: VMware Tools isn't running in the VM")
        if vm.name in self._ignore_shutdown:
            return
        vm.power, vm.tools, vm.ips = "poweredOff", False, []

    async def power_off(self, uuid: str, *, on_task: OnTask | None = None) -> None:
        self._note("power_off", uuid)
        vm = self._vm(uuid)
        if vm.power == "poweredOff":
            return
        state = await self._start("power_off", uuid, on_task)
        vm.power, vm.tools, vm.ips = "poweredOff", False, []
        self._end(state)

    async def take_snapshot(self, uuid: str, name: str, description: str = "", *, memory: bool = False,
                            quiesce: bool = True, on_task: OnTask | None = None) -> None:
        self._note("take_snapshot", (name, quiesce))
        vm = self._vm(uuid)
        state = await self._start("snapshot", uuid, on_task)
        if quiesce and (self._quiesce_fails > 0 or not vm.tools):
            self._quiesce_fails = max(0, self._quiesce_fails - 1)
            self._end(state, ok=False)
            raise QuiesceFailed("VMware Tools couldn't quiesce the file systems", state.ref)
        self._snapshot(vm, name, description, quiesced=quiesce)
        if self._late_snapshot:
            self._late_snapshot = False
            self._end(state, ok=False)
            raise TaskFailed(f"ESXi couldn't take the VM snapshot {name} (Timedout)", state.ref)
        self._end(state)

    def _snap(self, vm: FakeVm, snapshot_id: int) -> FakeSnap:
        found = [s for s in vm.snaps if s.id == snapshot_id]
        if len(found) != 1:
            raise MachineError(f"The VM has no snapshot with the id {snapshot_id}")
        return found[0]

    async def revert_snapshot(self, uuid: str, snapshot_id: int, *, on_task: OnTask | None = None) -> None:
        self._note("revert_snapshot", snapshot_id)
        vm = self._vm(uuid)
        snap = self._snap(vm, snapshot_id)
        state = await self._start("revert", uuid, on_task)
        vm.current = snap.id
        vm.power, vm.tools, vm.ips = "poweredOff", False, []  # a disk-only snapshot reverts to a VM that is off
        self._end(state)

    async def delete_snapshot(self, uuid: str, snapshot_id: int, *, on_task: OnTask | None = None) -> None:
        self._note("delete_snapshot", snapshot_id)
        vm = self._vm(uuid)
        snap = self._snap(vm, snapshot_id)
        state = await self._start("delete_snapshot", uuid, on_task)
        vm.snaps.remove(snap)
        for other in vm.snaps:
            if other.parent_id == snap.id:
                other.parent_id = snap.parent_id
        if vm.current == snap.id:
            vm.current = snap.parent_id
        for d in vm.disks:  # consolidation folds the newest delta into its parent
            if len(d.chain) > 1:
                self._remove_files(d.chain.pop())
        self._end(state)

    async def destroy(self, uuid: str, *, on_task: OnTask | None = None) -> None:
        self._note("destroy", uuid)
        vm = self._vm(uuid)
        if vm.power != "poweredOff":
            raise TaskFailed("ESXi couldn't delete the VM: the VM's power state doesn't allow it")
        state = await self._start("destroy", uuid, on_task)
        for d in vm.disks:  # only attached disks go; any other file stays in the folder
            for path in d.chain:
                self._remove_files(path)
        for name in (vm.vmx, f"{vm.folder_path}/vmware.log"):
            self.files.pop(name, None)
        self._tidy(vm.folder_path)
        del self.vms[uuid]
        self._end(state)

    # ----------------------------------------------------------- test helpers

    def vm_named(self, name: str) -> FakeVm:
        return next(vm for vm in self.vms.values() if vm.name == name)

    def folder_files(self, folder: str) -> list[str]:
        folder = normalize_path(folder)
        return sorted(p for p in self.files if p.startswith(folder + "/"))

    def session_factory(self) -> Any:
        """A stand-in for ``esxi.session``: ``factory(account)`` yields this fake."""
        @asynccontextmanager
        async def factory(account: Any) -> Any:
            yield self
        return factory


def datastore_of(path: str) -> str:
    return split_path(path)[0]
