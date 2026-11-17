"""Just enough pyvmomi stand-ins for ``PyvmomiEsxi``'s unit tests (phase 5 §16.1).

Managed objects (``Task``, ``VirtualMachine``, the datastore, the ``ServiceInstance`` and its
``content``) are fakes; data objects (devices, backings, ``OptionValue``, guest NIC info, faults) are
pyvmomi's own, so ``PyvmomiEsxi`` sees the real types it checks with ``isinstance``. This module
therefore needs pyvmomi; test modules import it after ``pytest.importorskip("pyVmomi")``.

Every method call and every ``Task.info`` read is written to ``World.calls`` with the thread it ran
on, so a test can check that all of them ran on the session's one executor thread.

Tasks follow a script: ``World.script(method, states=[...], error=fault, result=...)`` sets what the
next task started by ``method`` does; each read of ``task.info`` moves it one state on, and the last
state stays. Without a script a task goes ``running`` then ``success``.
"""

from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from pyVmomi import vim, vmodl

GIB_KB = 1024 * 1024


@dataclass
class Script:
    states: list[str]
    error: Any = None
    result: Any = None
    cancelable: bool = False


class World:
    """Everything one fake ESXi host holds, and the record of what was called."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.objects: list[Any] = []
        self.tasks: list[FakeTask] = []
        self.scripts: dict[str, list[Script]] = {}
        self.ids = itertools.count(1)
        self.logged_out = False
        self.dropped = False

    def note(self, what: str) -> None:
        self.calls.append((what, threading.current_thread().name))

    def script(self, method: str, *, states: list[str] | None = None, error: Any = None, result: Any = None,
               cancelable: bool = False) -> None:
        self.scripts.setdefault(method, []).append(
            Script(states=list(states or (["running", "error"] if error is not None else ["running", "success"])),
                   error=error, result=result, cancelable=cancelable))

    def task(self, method: str, *, description_id: str, entity: Any = None, result: Any = None,
             on_success: Any = None) -> FakeTask:
        script = (self.scripts.get(method) or [None]).pop(0) if self.scripts.get(method) else None
        if script is None:
            script = Script(states=["running", "success"])
        task = FakeTask(self, f"haTask-{next(self.ids)}", name=method, description_id=description_id,
                        states=script.states, error=script.error,
                        result=script.result if script.result is not None else result,
                        cancelable=script.cancelable, entity=entity, on_success=on_success)
        self.tasks.append(task)
        if entity is not None and hasattr(entity, "recentTask"):
            entity.recentTask.append(task)
        return task

    def of(self, wsdl: str) -> list[Any]:
        return [o for o in self.objects if getattr(o, "_wsdl", None) == wsdl]


class FakeTask:
    _wsdl = "Task"

    def __init__(self, world: World, moid: str, *, name: str, description_id: str, states: list[str], error: Any,
                 result: Any, cancelable: bool, entity: Any, on_success: Any) -> None:
        self._world = world
        self._moId = moid
        self._states = states
        self._at = 0
        self._name = name
        self._description_id = description_id
        self._error = error
        self._result = result
        self._cancelable = cancelable
        self._entity = entity
        self._on_success = on_success
        self._done = False
        self.cancel_calls = 0
        self.reads = 0
        self.started = datetime(2026, 11, 15, 10, 2, tzinfo=UTC)

    @property
    def state(self) -> str:
        return self._states[min(self._at, len(self._states) - 1)]

    @property
    def info(self) -> Any:
        self._world.note(f"Task.info {self._name}")
        self.reads += 1
        state = self.state
        if self._at < len(self._states) - 1:
            self._at += 1
        if state == "success" and not self._done:
            self._done = True
            if self._on_success is not None:
                self._on_success()
        return SimpleNamespace(
            key=self._moId, name=self._name, descriptionId=self._description_id, state=state,
            error=self._error if state == "error" else None,
            result=self._result if state == "success" else None,
            cancelable=self._cancelable and state in ("queued", "running"),
            startTime=self.started, queueTime=self.started,
            entityName=getattr(self._entity, "name", None),
        )

    def CancelTask(self) -> None:  # noqa: N802 (pyvmomi's name)
        self._world.note(f"CancelTask {self._name}")
        self.cancel_calls += 1
        self._states = ["error"]
        self._at = 0
        self._error = vmodl.fault.RequestCanceled()


# ---------------------------------------------------------------------- VMs


def scsi_controller(key: int = 1000) -> Any:
    return vim.vm.device.ParaVirtualSCSIController(key=key, busNumber=0, sharedBus="noSharing")


def disk(path: str, size_gb: int, *, key: int = 2000, parents: tuple[str, ...] = (), controller: int = 1000,
         unit: int = 0) -> Any:
    """A real ``VirtualDisk`` whose backing chain is ``parents`` (base first) then ``path`` on top."""
    backing = None
    for name in (*parents, path):
        backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo(fileName=name, diskMode="persistent", parent=backing)
    return vim.vm.device.VirtualDisk(key=key, controllerKey=controller, unitNumber=unit,
                                     capacityInKB=size_gb * GIB_KB, backing=backing)


def nic(device_id: int, *ips: str) -> Any:
    """A guest NIC as VMware Tools reports it (``device_id`` -1 for an interface that isn't a vNIC)."""
    return vim.vm.GuestInfo.NicInfo(
        deviceConfigId=device_id, ipAddress=list(ips),
        ipConfig=vim.net.IpConfigInfo(ipAddress=[vim.net.IpConfigInfo.IpAddress(ipAddress=ip, prefixLength=24)
                                                 for ip in ips]))


class FakeSnapshotRef:
    _wsdl = "VirtualMachineSnapshot"

    def __init__(self, world: World, vm: FakeVirtualMachine, node: SnapshotNode) -> None:
        self._world = world
        self._vm = vm
        self._node = node
        self._moId = f"snapshot-{node.id}"

    def RevertToSnapshot_Task(self) -> FakeTask:  # noqa: N802
        self._world.note("RevertToSnapshot_Task")

        def done() -> None:
            self._vm.runtime.powerState = "poweredOff"
        return self._world.task("RevertToSnapshot_Task", description_id="vm.Snapshot.revert", entity=self._vm,
                                on_success=done)

    def RemoveSnapshot_Task(self, removeChildren: bool, consolidate: bool = True) -> FakeTask:  # noqa: N802, N803
        self._world.note("RemoveSnapshot_Task")
        self._vm.removed_snapshots.append(self._node.id)
        return self._world.task("RemoveSnapshot_Task", description_id="vm.Snapshot.remove", entity=self._vm)


@dataclass
class SnapshotNode:
    id: int
    name: str
    description: str = ""
    createTime: datetime = field(default_factory=lambda: datetime(2026, 11, 1, 9, 0))  # naive, as pyvmomi may give
    quiesced: bool = False
    childSnapshotList: list[SnapshotNode] = field(default_factory=list)
    snapshot: Any = None


class FakeVirtualMachine:
    _wsdl = "VirtualMachine"

    def __init__(self, world: World, name: str, *, uuid: str, datastore: str = "datastore1", folder: str | None = None,
                 power: str = "poweredOff", cores: int = 2, memory_mb: int = 4096,
                 extra: dict[str, str] | None = None, devices: list[Any] | None = None, net: list[Any] | None = None,
                 tools: str = "guestToolsNotRunning", annotation: str = "") -> None:
        self._world = world
        self._moId = str(next(world.ids))
        self.name = name
        self.config = SimpleNamespace(
            name=name, instanceUuid=uuid, annotation=annotation,
            files=SimpleNamespace(vmPathName=f"[{datastore}] {folder or name}/{name}.vmx"),
            extraConfig=[vim.option.OptionValue(key=k, value=v) for k, v in (extra or {}).items()],
            hardware=SimpleNamespace(numCPU=cores, memoryMB=memory_mb,
                                     device=list(devices if devices is not None else [scsi_controller()])),
        )
        self.runtime = SimpleNamespace(powerState=power)
        self.guest = SimpleNamespace(toolsRunningStatus=tools, net=list(net or []), hostName=None)
        self.snapshot: Any = None
        self.recentTask: list[FakeTask] = []
        self.reconfigs: list[Any] = []
        self.removed_snapshots: list[int] = []
        self.shutdown_calls = 0
        self.destroyed = False

    def set_snapshots(self, roots: list[SnapshotNode], current: int | None = None) -> None:
        def wire(node: SnapshotNode) -> None:
            node.snapshot = FakeSnapshotRef(self._world, self, node)
            for child in node.childSnapshotList:
                wire(child)
        for root in roots:
            wire(root)
        flat = []
        stack = list(roots)
        while stack:
            node = stack.pop()
            flat.append(node)
            stack.extend(node.childSnapshotList)
        cur = next((n.snapshot for n in flat if n.id == current), None)
        self.snapshot = SimpleNamespace(rootSnapshotList=roots, currentSnapshot=cur) if roots else None

    def extra(self) -> dict[str, str]:
        return {o.key: o.value for o in self.config.extraConfig}

    def PowerOnVM_Task(self) -> FakeTask:  # noqa: N802
        self._world.note("PowerOnVM_Task")

        def done() -> None:
            self.runtime.powerState = "poweredOn"
        return self._world.task("PowerOnVM_Task", description_id="VirtualMachine.powerOn", entity=self, on_success=done)

    def PowerOffVM_Task(self) -> FakeTask:  # noqa: N802
        self._world.note("PowerOffVM_Task")

        def done() -> None:
            self.runtime.powerState = "poweredOff"
        return self._world.task("PowerOffVM_Task", description_id="VirtualMachine.powerOff", entity=self,
                                on_success=done)

    def ShutdownGuest(self) -> None:  # noqa: N802
        self._world.note("ShutdownGuest")
        self.shutdown_calls += 1
        if self.guest.toolsRunningStatus != "guestToolsRunning":
            raise vim.fault.ToolsUnavailable(msg="upstream: tools not running on vm")
        self.runtime.powerState = "poweredOff"

    def ReconfigVM_Task(self, spec: Any) -> FakeTask:  # noqa: N802
        self._world.note("ReconfigVM_Task")
        self.reconfigs.append(spec)

        def done() -> None:
            hw = self.config.hardware
            if spec.numCPUs:
                hw.numCPU = spec.numCPUs
            if spec.memoryMB:
                hw.memoryMB = spec.memoryMB
            for change in spec.deviceChange or []:
                if change.operation == "add":
                    hw.device.append(change.device)
                elif change.operation == "edit":
                    hw.device = [change.device if d.key == change.device.key else d for d in hw.device]
            options = {o.key: o.value for o in self.config.extraConfig}
            for option in spec.extraConfig or []:
                if option.value in ("", None):
                    options.pop(option.key, None)
                else:
                    options[option.key] = option.value
            self.config.extraConfig = [vim.option.OptionValue(key=k, value=v) for k, v in options.items()]
        return self._world.task("ReconfigVM_Task", description_id="VirtualMachine.reconfigure", entity=self,
                                on_success=done)

    def CreateSnapshot_Task(self, name: str, description: str, memory: bool, quiesce: bool) -> FakeTask:  # noqa: N802
        self._world.note(f"CreateSnapshot_Task quiesce={quiesce} memory={memory}")
        return self._world.task("CreateSnapshot_Task", description_id="VirtualMachine.createSnapshot", entity=self)

    def Destroy_Task(self) -> FakeTask:  # noqa: N802
        self._world.note("Destroy_Task")

        def done() -> None:
            self.destroyed = True
            if self in self._world.objects:
                self._world.objects.remove(self)
        return self._world.task("Destroy_Task", description_id="VirtualMachine.destroy", entity=self, on_success=done)


# -------------------------------------------------------------- the rest of the host


class FakeDatastore:
    _wsdl = "Datastore"

    def __init__(self, world: World, name: str, *, free_gb: float = 500, capacity_gb: float = 1000,
                 accessible: bool = True, folders: dict[str, list[str]] | None = None) -> None:
        self._world = world
        self._moId = f"datastore-{next(world.ids)}"
        self.name = name
        self.summary = SimpleNamespace(name=name, freeSpace=int(free_gb * 2**30), capacity=int(capacity_gb * 2**30),
                                       accessible=accessible)
        self.folders = dict(folders or {})  # "[ds] folder" -> file names
        self.browser = SimpleNamespace(SearchDatastore_Task=self._search)
        self.searches: list[tuple[str, Any]] = []

    def _search(self, datastorePath: str, searchSpec: Any) -> FakeTask:  # noqa: N803
        self._world.note("SearchDatastore_Task")
        self.searches.append((datastorePath, searchSpec))
        if datastorePath not in self.folders:
            self._world.script("SearchDatastore_Task", error=vim.fault.FileNotFound(file=datastorePath))
            return self._world.task("SearchDatastore_Task", description_id="HostDatastoreBrowser.search")
        files = [SimpleNamespace(path=name) for name in self.folders[datastorePath]]
        return self._world.task("SearchDatastore_Task", description_id="HostDatastoreBrowser.search",
                                result=SimpleNamespace(folderPath=datastorePath, file=files))


class FakeNamed:
    def __init__(self, world: World, wsdl: str, name: str) -> None:
        self._wsdl = wsdl
        self._moId = f"{wsdl.lower()}-{next(world.ids)}"
        self.name = name


class FakeFolder:
    _wsdl = "Folder"

    def __init__(self, world: World) -> None:
        self._world = world
        self._moId = "ha-folder-vm"
        self.created: list[tuple[Any, Any]] = []

    def CreateVM_Task(self, config: Any, pool: Any, host: Any = None) -> FakeTask:  # noqa: N802
        self._world.note("CreateVM_Task")
        self.created.append((config, pool))
        ds = config.files.vmPathName.strip("[]").split("]")[0]
        vm = FakeVirtualMachine(self._world, config.name, uuid=f"5000-{next(self._world.ids):04d}", datastore=ds,
                                cores=config.numCPUs, memory_mb=config.memoryMB, annotation=config.annotation,
                                extra={o.key: o.value for o in config.extraConfig},
                                devices=[c.device for c in config.deviceChange])

        def done() -> None:
            self._world.objects.append(vm)
        return self._world.task("CreateVM_Task", description_id="Folder.createVm", result=vm, on_success=done)


class FakeDiskManager:
    def __init__(self, world: World) -> None:
        self._world = world
        self.copies: list[dict[str, Any]] = []
        self.deletes: list[str] = []

    def CopyVirtualDisk_Task(self, sourceName: str, sourceDatacenter: Any = None, destName: str | None = None,  # noqa: N802, N803
                             destDatacenter: Any = None, destSpec: Any = None, force: bool = False) -> FakeTask:  # noqa: N803
        self._world.note("CopyVirtualDisk_Task")
        self.copies.append({"source": sourceName, "dest": destName, "spec": destSpec, "force": force})
        return self._world.task("CopyVirtualDisk_Task", description_id="VirtualDiskManager.copyVirtualDisk")

    def DeleteVirtualDisk_Task(self, name: str, datacenter: Any = None) -> FakeTask:  # noqa: N802
        self._world.note("DeleteVirtualDisk_Task")
        self.deletes.append(name)
        return self._world.task("DeleteVirtualDisk_Task", description_id="VirtualDiskManager.deleteVirtualDisk")


class FakeServiceInstance:
    """A ``ServiceInstance`` over one ``World``: a standalone host with one datacenter."""

    def __init__(self, world: World | None = None, *, api_type: str = "HostAgent", version: str = "8.0.3",
                 editions: tuple[str, ...] = ("esx.enterprisePlus.cpuPackage",)) -> None:
        self.world = world or World()
        w = self.world
        self.folder = FakeFolder(w)
        self.datacenter = SimpleNamespace(_wsdl="Datacenter", _moId="ha-datacenter", name="ha-datacenter",
                                          vmFolder=self.folder)
        w.objects.append(self.datacenter)
        w.objects.append(FakeNamed(w, "ResourcePool", "Resources"))
        self.disks = FakeDiskManager(w)
        self.content = SimpleNamespace(
            about=SimpleNamespace(apiType=api_type, version=version, build="24022510",
                                  fullName=f"VMware ESXi {version} build-24022510"),
            licenseManager=SimpleNamespace(licenses=[SimpleNamespace(editionKey=e, name=e) for e in editions]),
            rootFolder=SimpleNamespace(_moId="ha-folder-root"),
            searchIndex=SimpleNamespace(FindByUuid=self._find_by_uuid),
            viewManager=SimpleNamespace(CreateContainerView=self._view),
            virtualDiskManager=self.disks,
            taskManager=SimpleNamespace(recentTask=w.tasks),
            sessionManager=SimpleNamespace(Logout=self._logout),
        )
        self._stub = SimpleNamespace(DropConnections=self._drop)

    def RetrieveContent(self) -> Any:  # noqa: N802
        return self.content

    def _logout(self) -> None:
        self.world.note("Logout")
        self.world.logged_out = True

    def _drop(self) -> None:
        self.world.dropped = True

    def _find_by_uuid(self, datacenter: Any, uuid: str, vmSearch: bool, instanceUuid: bool) -> Any:  # noqa: N803
        self.world.note("FindByUuid")
        assert vmSearch and instanceUuid, "Slipway finds VMs by instance UUID"
        for vm in self.world.of("VirtualMachine"):
            if vm.config.instanceUuid == uuid:
                return vm
        return None

    def _view(self, container: Any, types: list[Any], recursive: bool) -> Any:
        self.world.note("CreateContainerView")
        wanted = {t._wsdlName for t in types}
        objects = [o for o in self.world.objects if getattr(o, "_wsdl", None) in wanted]
        view = SimpleNamespace(view=objects, destroyed=False)

        def destroy() -> None:
            view.destroyed = True
        view.Destroy = destroy
        return view

    # ---- building the host

    def add_vm(self, name: str, **kw: Any) -> FakeVirtualMachine:
        vm = FakeVirtualMachine(self.world, name, uuid=kw.pop("uuid", f"5000-{next(self.world.ids):04d}"), **kw)
        self.world.objects.append(vm)
        return vm

    def add_datastore(self, name: str = "datastore1", **kw: Any) -> FakeDatastore:
        ds = FakeDatastore(self.world, name, **kw)
        self.world.objects.append(ds)
        return ds

    def add_network(self, name: str) -> None:
        self.world.objects.append(FakeNamed(self.world, "Network", name))
