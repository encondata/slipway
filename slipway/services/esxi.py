"""VMware ESXi: the client Slipway uses to make and look after VMs on a standalone ESXi host.

Phase 5 makes an environment's VMs on ESXi as Sirdar did: an empty VM carrying Slipway's markers
and guestinfo cloud-init, the seed VM's single disk copied in thin, attached and grown, then powered
on. This module is the part that talks to ESXi; the provider (``providers/esxi.py``) decides what
to do with it.

* ``EsxiApi`` is the protocol everything above this module uses. ``PyvmomiEsxi`` implements it over
  one pyvmomi ``ServiceInstance``; ``tests/fake_esxi.py`` implements it in memory.
* pyvmomi objects aren't thread-safe and every call blocks, so a ``PyvmomiEsxi`` runs each call on
  its own one-thread executor, and the event loop never waits on ESXi directly.
* Every task Slipway starts is reported to the caller (``on_task``, which records it in
  ``machines.last_task``) before it is waited on. On a timeout or a cancel only a disk copy is
  stopped (``CancelTask``, when ESXi says it can be); a snapshot, revert, delete or any other task
  is left to finish, because stopping one half-way leaves a VM only a person can repair (D24).
* Every failure is a ``MachineError`` carrying Slipway's own sentence. ESXi's own message is never
  passed on: it is rarely something a person can act on, and it can hold paths and user names.
* ``clean_config`` and ``run_test`` are the account rules and the account's Test, so the accounts
  service needs only this module.
* ``_smart_connect`` is the only call that opens a real session; the test guard patches it.

pyvmomi is optional: it is imported only inside this module, and only when a session is opened or a
pyvmomi object is built, so Slipway runs without it until someone adds an ESXi account.

The password stays inside Slipway's process (D17): it goes to ESXi's sign-in and nowhere else, and
nothing here logs it. ``VmSpec`` and ``VmInfo`` never show guestinfo values (the user-data holds the
VM's host private key until the pin scrubs it).
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import ipaddress
import re
from collections import defaultdict
from collections.abc import AsyncIterator, Awaitable, Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import urlsplit

from slipway.services import vmnet
from slipway.services.vmtypes import AccountInvalid, Check, MachineError

PROVIDER = "esxi"

# The markers (D20). They are extraConfig keys outside ``guestinfo.*``, so the guest can't change
# them; ``slipway.machine`` is what ``VmInfo.owner`` reads.
OWNER_KEY = "slipway.machine"
ENVIRONMENT_KEY = "slipway.environment"
OWNER_KEYS = (OWNER_KEY, ENVIRONMENT_KEY)

GUESTINFO_PREFIX = "guestinfo."
GUEST_ID = "ubuntu64Guest"
SCSI_KEY = 1000  # the PVSCSI controller's device key in a new VM
NIC_KEY = -101  # a new device's key only needs to be negative and unique within the spec

CALL_TIMEOUT = 30.0  # seconds, every call (§14)
SIGNIN_TIMEOUT = 35.0  # seconds, the sign-in
COPY_LIMIT = 30 * 60  # a disk copy
TASK_LIMIT = 10 * 60  # every other task
POLL = 1.0  # seconds between task polls
READ_WAIT = 5.0  # a page read waits this long for a free session, then gives up (§10.5)
SESSIONS_PER_ACCOUNT = 2

LICENCE_BASIC = "esxBasic"  # the edition key of the free ESXi licence
API_HOST_AGENT = "HostAgent"
API_VCENTER = "VirtualCenter"

# What ESXi calls a disk copy. A copy is the one task Slipway may cancel.
COPY_KIND = "copy_disk"
COPY_DESCRIPTION_IDS = frozenset({"VirtualDiskManager.copyVirtualDisk"})
COPY_TASK_NAMES = frozenset({"CopyVirtualDisk_Task", "CopyVirtualDisk"})

# Slipway's label for each task ESXi might be running, by ESXi's description id.
KIND_BY_DESCRIPTION = {
    "VirtualDiskManager.copyVirtualDisk": COPY_KIND,
    "VirtualDiskManager.deleteVirtualDisk": "delete_disk",
    "Folder.createVm": "create_vm",
    "VirtualMachine.powerOn": "power_on",
    "VirtualMachine.powerOff": "power_off",
    "VirtualMachine.reconfigure": "reconfigure",
    "VirtualMachine.createSnapshot": "snapshot",
    "vm.Snapshot.revert": "revert",
    "vm.Snapshot.remove": "delete_snapshot",
    "VirtualMachine.revertToCurrentSnapshot": "revert",
    "VirtualMachine.removeAllSnapshots": "delete_snapshot",
    "VirtualMachine.destroy": "destroy",
    "Destroy": "destroy",
    "HostDatastoreBrowser.search": "browse",
}

TASK_WORDS = {
    COPY_KIND: "disk copy",
    "delete_disk": "disk delete",
    "create_vm": "create",
    "attach_disk": "disk attach",
    "grow_disk": "disk grow",
    "set_size": "size change",
    "set_extra_config": "settings change",
    "reconfigure": "settings change",
    "power_on": "power-on",
    "power_off": "power-off",
    "snapshot": "VM snapshot",
    "revert": "VM snapshot revert",
    "delete_snapshot": "VM snapshot delete",
    "destroy": "delete",
    "browse": "datastore browse",
}

NO_PYVMOMI = ("Slipway was installed without ESXi support (the pyvmomi package). "
              "Install it (pip install pyvmomi) to use ESXi accounts.")
VCENTER_TEXT = "Slipway works with a standalone ESXi host, not vCenter"
LICENCE_TEXT = ("ESXi's licence doesn't allow changes through its API (free ESXi is read-only); "
                "Slipway needs a paid licence")
CERT_TEXT = ("ESXi's certificate isn't the one Slipway trusts. If it was renewed on purpose, "
             "trust the new one in Settings → Integrations.")
LOGIN_TEXT = "ESXi refused the user name or password. Check them in Settings → Integrations."

URL_HOST_RE = re.compile(r"^(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
# A local ESXi user, or user@domain for a host joined to a directory.
USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._@-]{0,63}$")
SECRET_MAX = 256
CONFIG_KEYS = ("url", "user", "datastore", "resource_pool", "source_vm", "networks")
DEFAULT_RESOURCE_POOL = "Resources"  # the root pool's name on a standalone host
_SAFE_WORD = re.compile(r"[^A-Za-z0-9 ._()-]")

OnTask = Callable[["TaskRef"], Awaitable[None]]


# ------------------------------------------------------------------------- errors


class TaskFailed(MachineError):
    """A task ESXi ran ended in an error. ``task`` is the task, as it was reported to ``on_task``."""

    def __init__(self, text: str, task: TaskRef | None = None, *, unreachable: bool = False) -> None:
        super().__init__(text, unreachable=unreachable)
        self.task = task


class QuiesceFailed(TaskFailed):
    """VMware Tools couldn't quiesce the guest's file systems for a snapshot; retry without quiescing."""


class TaskTimedOut(TaskFailed):
    """Slipway stopped waiting for a task. ``cancelled`` says whether it was a copy Slipway cancelled."""

    def __init__(self, text: str, task: TaskRef | None = None, *, cancelled: bool = False) -> None:
        super().__init__(text, task)
        self.cancelled = cancelled


class FileMissing(TaskFailed):
    """A file or folder the task needed isn't on the datastore."""


class VmGone(MachineError):
    """The VM isn't on ESXi (any more)."""


class CertificateChanged(MachineError):
    """ESXi presented a certificate other than the pinned one."""


# -------------------------------------------------------------------------- shapes


@dataclass(frozen=True)
class About:
    api_type: str  # HostAgent (ESXi) or VirtualCenter
    version: str
    build: str
    full_name: str


@dataclass(frozen=True)
class DatastoreInfo:
    name: str
    free_gb: float
    capacity_gb: float
    accessible: bool


@dataclass(frozen=True)
class DiskInfo:
    key: int
    path: str  # the file the VM writes to now: the newest snapshot delta, or the base disk
    base: str  # the disk at the bottom of the chain: the one Slipway copied
    chain: tuple[str, ...]  # base first, then each snapshot delta
    size_gb: int
    controller_key: int | None = None
    unit: int | None = None


@dataclass(frozen=True)
class VmInfo:
    moref: str
    uuid: str  # the instance UUID, what Slipway records and finds the VM by
    name: str
    power: str  # poweredOn | poweredOff | suspended
    path: str  # the VMX file, "[datastore] folder/name.vmx"
    annotation: str = ""
    cores: int | None = None
    memory_mb: int | None = None
    disks: tuple[DiskInfo, ...] = ()
    extra: dict[str, str] = field(default_factory=dict)  # slipway.* keys only
    guestinfo_keys: tuple[str, ...] = ()  # names only: the values may hold the host private key
    tools_running: bool = False

    @property
    def owner(self) -> str | None:
        return self.extra.get(OWNER_KEY) or None

    @property
    def environment(self) -> str | None:
        return self.extra.get(ENVIRONMENT_KEY) or None

    @property
    def folder(self) -> str:
        """``[datastore] folder`` of the VMX file (ESXi may have made it ``<name>_1``)."""
        return self.path.rsplit("/", 1)[0] if "/" in self.path else self.path


@dataclass(frozen=True)
class SnapshotInfo:
    id: int  # ESXi's id within the VM
    name: str
    description: str
    created: datetime | None
    quiesced: bool
    current: bool  # the snapshot the VM runs on top of
    parent_id: int | None = None


@dataclass(frozen=True)
class GuestView:
    tools_running: bool
    ipv4: tuple[str, ...]
    hostname: str | None = None


@dataclass(frozen=True)
class TaskRef:
    id: str  # the task's moref, such as haTask-12-vim.VirtualDiskManager.copyVirtualDisk-123
    kind: str  # Slipway's label (KIND_BY_DESCRIPTION), or ESXi's description id when unknown
    description_id: str | None
    started_at: datetime | None
    state: str  # queued | running | success | error
    cancelable: bool
    entity: str | None = None  # the VM's name, when the task is on a VM
    ours: bool = False  # started by this client

    @property
    def is_copy(self) -> bool:
        return self.kind == COPY_KIND or (self.description_id or "") in COPY_DESCRIPTION_IDS

    @property
    def words(self) -> str:
        return TASK_WORDS.get(self.kind, "ESXi")

    def to_dict(self) -> dict[str, Any]:
        """What ``machines.last_task`` keeps (the caller adds ``deployment_id``)."""
        return {"id": self.id, "kind": self.kind,
                "started_at": self.started_at.isoformat() if self.started_at else None}


@dataclass(frozen=True)
class VmSpec:
    """What ``create_vm`` makes: an empty VM, without its disk."""

    name: str
    datastore: str
    resource_pool: str
    port_group: str
    cores: int
    memory_mb: int
    annotation: str
    owner: dict[str, str]  # exactly OWNER_KEYS: {slipway.machine, slipway.environment}
    guestinfo: dict[str, str]  # guestinfo.metadata/.userdata and their encodings (cloudinit.guestinfo)

    def __repr__(self) -> str:  # the user-data holds the host private key: keep it out of logs
        return (f"VmSpec(name={self.name!r}, datastore={self.datastore!r}, resource_pool={self.resource_pool!r}, "
                f"port_group={self.port_group!r}, cores={self.cores}, memory_mb={self.memory_mb}, "
                f"owner={self.owner!r}, guestinfo=<{len(self.guestinfo)} keys hidden>)")


def owner_keys(machine_id: Any, environment_id: Any) -> dict[str, str]:
    """The marker values for one machine (D20)."""
    return {OWNER_KEY: str(machine_id), ENVIRONMENT_KEY: str(environment_id)}


# --------------------------------------------------------------------------- paths


def vm_folder(datastore: str, name: str) -> str:
    """Where ESXi puts a new VM's files when no folder of that name exists yet."""
    return f"[{datastore}] {name}"


def disk_file(name: str) -> str:
    return f"{name}-disk0.vmdk"


def disk_path(datastore: str, name: str) -> str:
    """The fixed path of the disk Slipway copies for a VM (E5, M5)."""
    return f"{vm_folder(datastore, name)}/{disk_file(name)}"


_PATH_RE = re.compile(r"^\[(?P<ds>[^\]]+)\]\s*(?P<rel>.*)$")


def split_path(path: str) -> tuple[str, str]:
    """``("datastore", "folder/file")`` from ``"[datastore] folder/file"``."""
    match = _PATH_RE.match((path or "").strip())
    if not match:
        raise ValueError(f"{path!r} isn't a datastore path such as [datastore1] folder/file.vmdk")
    return match["ds"], match["rel"].strip("/")


def normalize_path(path: str) -> str:
    """One spelling of a datastore path, so two can be compared."""
    ds, rel = split_path(path)
    return f"[{ds}] {rel}" if rel else f"[{ds}]"


# ------------------------------------------------------------------------ pyvmomi


def _pyvmomi() -> tuple[Any, Any]:
    """pyvmomi's ``vim`` and ``vmodl``, imported only when they are needed."""
    try:
        from pyVmomi import vim, vmodl  # noqa: PLC0415 (optional dependency, imported lazily)
    except ImportError:
        raise MachineError(NO_PYVMOMI) from None
    return vim, vmodl


def available() -> bool:
    """Whether pyvmomi is installed, so ESXi accounts can be used."""
    try:
        _pyvmomi()
    except MachineError:
        return False
    return True


def _wsdl_name(exc: BaseException) -> str:
    name = getattr(type(exc), "_wsdlName", None) or type(exc).__name__
    return _SAFE_WORD.sub("", str(name))[:60]


def _is_thumbprint_mismatch(exc: BaseException) -> bool:
    return type(exc).__name__ == "ThumbprintMismatchException"


def _fault_mentions(exc: BaseException, word: str) -> bool:
    """Whether a fault's own message mentions ``word``. Used to classify a fault, never shown."""
    texts = [getattr(exc, "msg", None) or ""]
    for item in getattr(exc, "faultMessage", None) or []:
        texts.append(getattr(item, "key", "") or "")
        texts.append(getattr(item, "message", "") or "")
    return any(word in str(t).lower() for t in texts)


def map_fault(exc: BaseException, *, doing: str, host: str, quiesce: bool = False,
              task: TaskRef | None = None) -> MachineError:
    """Slipway's error for anything pyvmomi raised (or a task's ``info.error``) while ``doing``.

    ``doing`` is a verb phrase (``"power on slipway-shop-blue"``). The result never carries ESXi's
    own message; the fault's type name is kept where nothing better fits, so a person can search it.
    """
    from slipway.services import tls_pin  # noqa: PLC0415 (keeps this module importable on its own)

    if isinstance(exc, MachineError):
        return exc
    if tls_pin.pin_refused(exc) or _is_thumbprint_mismatch(exc):
        return CertificateChanged(CERT_TEXT, unreachable=True)
    try:
        vim, vmodl = _pyvmomi()
    except MachineError:
        vim = vmodl = None

    def failed(text: str, cls: type[MachineError] = TaskFailed, **kw: Any) -> MachineError:
        if issubclass(cls, TaskFailed):
            return cls(text, task, **kw)
        return cls(text, **kw)

    if vim is not None and isinstance(exc, vmodl.MethodFault):
        if isinstance(exc, vim.fault.InvalidLogin):
            return MachineError(LOGIN_TEXT)
        if isinstance(exc, vim.fault.NotAuthenticated):
            return MachineError("ESXi ended Slipway's session; retry", unreachable=True)
        if isinstance(exc, vim.fault.RestrictedVersion):
            return MachineError(LICENCE_TEXT)
        if isinstance(exc, vim.fault.NoPermission | vmodl.fault.SecurityError):
            return failed(f"ESXi doesn't allow the account's user to {doing}: give it the Administrator role")
        if quiesce and (isinstance(exc, vim.fault.ApplicationQuiesceFault | vim.fault.ToolsUnavailable)
                        or _fault_mentions(exc, "quiesc")):
            return failed("VMware Tools couldn't quiesce the file systems", QuiesceFailed)
        if isinstance(exc, vmodl.fault.ManagedObjectNotFound):
            return failed(f"ESXi couldn't {doing}: the VM or file is gone from ESXi")
        if isinstance(exc, vim.fault.DuplicateName):
            return failed(f"ESXi couldn't {doing}: it already has a VM with that name")
        if isinstance(exc, vim.fault.FileAlreadyExists):
            return failed(f"ESXi couldn't {doing}: a file is already where Slipway wanted to write one")
        if isinstance(exc, vim.fault.FileLocked):
            return failed(f"ESXi couldn't {doing}: a file it needs is in use by another VM")
        if isinstance(exc, vim.fault.FileNotFound):
            return failed(f"ESXi couldn't {doing}: a file it needed isn't on the datastore", FileMissing)
        if isinstance(exc, vim.fault.InvalidPowerState):
            return failed(f"ESXi couldn't {doing}: the VM's power state doesn't allow it")
        if isinstance(exc, vim.fault.TaskInProgress):
            return failed(f"ESXi couldn't {doing}: another task is running on the VM; retry when it has finished")
        if isinstance(exc, vim.fault.ToolsUnavailable):
            return failed(f"ESXi couldn't {doing}: VMware Tools isn't running in the VM")
        if isinstance(exc, vim.fault.InsufficientResourcesFault | vim.fault.NoDiskSpace):
            return failed(f"ESXi couldn't {doing}: the host or datastore hasn't room for it")
        if isinstance(exc, vmodl.fault.RequestCanceled):
            return failed(f"ESXi's task to {doing} was cancelled")
        return failed(f"ESXi couldn't {doing} ({_wsdl_name(exc)})")
    if isinstance(exc, TimeoutError):
        return MachineError(f"ESXi at {host} didn't answer in time while Slipway tried to {doing}", unreachable=True)
    if isinstance(exc, OSError | ConnectionError) or type(exc).__module__.startswith("http.client"):
        return MachineError(f"Slipway can't reach ESXi at {host}", unreachable=True)
    return failed(f"Something went wrong while Slipway asked ESXi to {doing} ({_wsdl_name(exc)})")


def _extra_of(config: Any) -> dict[str, str]:
    return {str(o.key): "" if o.value is None else str(o.value) for o in (getattr(config, "extraConfig", None) or [])}


def owner_of(vm: Any) -> str | None:
    """The ``slipway.machine`` marker of a pyvmomi VM, or None."""
    config = getattr(vm, "config", None)
    if config is None:
        return None
    return _extra_of(config).get(OWNER_KEY) or None


def _usable_ipv4(text: Any) -> str | None:
    try:
        ip = ipaddress.ip_address(str(text).split("%", 1)[0])
    except ValueError:
        return None
    if ip.version != 4 or ip.is_link_local or ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        return None
    return str(ip)


def guest_ipv4(guest: Any) -> list[str]:
    """The IPv4 addresses VMware Tools reports on the VM's real vNICs.

    Interfaces that aren't a virtual NIC of the VM (``deviceConfigId`` -1: Docker's bridges, veths,
    loopback) are skipped, as are link-local and loopback addresses.
    """
    out: list[str] = []
    for nic in getattr(guest, "net", None) or []:
        if getattr(nic, "deviceConfigId", -1) is None or getattr(nic, "deviceConfigId", -1) < 0:
            continue
        candidates: list[Any] = []
        ip_config = getattr(nic, "ipConfig", None)
        if ip_config is not None and getattr(ip_config, "ipAddress", None):
            candidates = [getattr(a, "ipAddress", None) for a in ip_config.ipAddress]
        else:
            candidates = list(getattr(nic, "ipAddress", None) or [])
        for value in candidates:
            ip = _usable_ipv4(value)
            if ip and ip not in out:
                out.append(ip)
    return out


def create_config(spec: VmSpec) -> Any:
    """The ``vim.vm.ConfigSpec`` of a new, empty VM (Sirdar's ``esxi.py:331-352``, Slipway's markers).

    ``ubuntu64Guest``, a PVSCSI controller, one vmxnet3 NIC on the port group, ``disk.EnableUUID``
    (so the guest sees stable disk ids), both markers, the annotation, and the guestinfo keys.
    ``vmPathName`` names only the datastore, so ESXi makes the VM's folder.
    """
    vim, _ = _pyvmomi()
    vmnet.check_vm_name(spec.name)
    if set(spec.owner) != set(OWNER_KEYS) or not all(spec.owner.values()):
        raise ValueError("A VM needs both of Slipway's markers")
    if any(not key.startswith(GUESTINFO_PREFIX) for key in spec.guestinfo):
        raise ValueError("Only guestinfo.* keys can be handed to cloud-init")
    device = vim.vm.device
    scsi = device.VirtualDeviceSpec(
        operation=device.VirtualDeviceSpec.Operation.add,
        device=device.ParaVirtualSCSIController(key=SCSI_KEY, busNumber=0, sharedBus="noSharing"),
    )
    nic = device.VirtualDeviceSpec(
        operation=device.VirtualDeviceSpec.Operation.add,
        device=device.VirtualVmxnet3(
            key=NIC_KEY,
            addressType="generated",
            backing=device.VirtualEthernetCard.NetworkBackingInfo(deviceName=spec.port_group),
            connectable=device.VirtualDevice.ConnectInfo(startConnected=True, allowGuestControl=True, connected=True),
        ),
    )
    extra = {"disk.EnableUUID": "TRUE", **spec.owner, **spec.guestinfo}
    return vim.vm.ConfigSpec(
        name=spec.name,
        guestId=GUEST_ID,
        numCPUs=int(spec.cores),
        memoryMB=int(spec.memory_mb),
        annotation=spec.annotation,
        files=vim.vm.FileInfo(vmPathName=f"[{spec.datastore}]"),
        deviceChange=[scsi, nic],
        extraConfig=[vim.option.OptionValue(key=k, value=v) for k, v in extra.items()],
    )


# ------------------------------------------------------------------------ protocol


class EsxiApi(Protocol):
    """What Slipway asks of ESXi. Every method raises ``MachineError`` with Slipway's text.

    A method that starts a task takes ``on_task``, awaited with the task before Slipway waits on it.
    """

    async def about(self) -> About: ...
    async def license_editions(self) -> list[str]: ...
    async def datastore(self, name: str) -> DatastoreInfo | None: ...
    async def network_names(self) -> list[str]: ...
    async def resource_pool_names(self) -> list[str]: ...
    async def find_vm(self, uuid: str) -> VmInfo | None: ...
    async def find_vm_by_name(self, name: str) -> VmInfo | None: ...
    async def guest_ips(self) -> dict[str, list[str]]: ...
    async def disk_users(self, path: str) -> list[str]: ...
    async def create_vm(self, spec: VmSpec, *, on_task: OnTask | None = None) -> VmInfo: ...
    async def file_exists(self, path: str) -> bool: ...
    async def list_folder(self, path: str) -> list[str] | None: ...
    async def copy_disk(self, source: str, dest: str, *, on_task: OnTask | None = None) -> None: ...
    async def delete_disk(self, path: str, *, on_task: OnTask | None = None) -> None: ...
    async def attach_disk(self, uuid: str, path: str, *, on_task: OnTask | None = None) -> None: ...
    async def grow_disk(self, uuid: str, size_gb: int, *, on_task: OnTask | None = None) -> None: ...
    async def set_size(self, uuid: str, cores: int, memory_mb: int, *, on_task: OnTask | None = None) -> None: ...
    async def set_extra_config(self, uuid: str, values: dict[str, str], *, on_task: OnTask | None = None) -> None: ...
    async def power_on(self, uuid: str, *, on_task: OnTask | None = None) -> None: ...
    async def shutdown_guest(self, uuid: str) -> None: ...
    async def power_off(self, uuid: str, *, on_task: OnTask | None = None) -> None: ...
    async def guest(self, uuid: str) -> GuestView: ...
    async def snapshots(self, uuid: str) -> list[SnapshotInfo]: ...
    async def take_snapshot(self, uuid: str, name: str, description: str = "", *, memory: bool = False,
                            quiesce: bool = True, on_task: OnTask | None = None) -> None: ...
    async def revert_snapshot(self, uuid: str, snapshot_id: int, *, on_task: OnTask | None = None) -> None: ...
    async def delete_snapshot(self, uuid: str, snapshot_id: int, *, on_task: OnTask | None = None) -> None: ...
    async def destroy(self, uuid: str, *, on_task: OnTask | None = None) -> None: ...
    async def running_tasks(self, uuid: str | None = None) -> list[TaskRef]: ...
    async def cancel_task(self, task: TaskRef) -> bool: ...


# ------------------------------------------------------------------------- pyvmomi


def _disconnect(si: Any) -> None:
    """Signs a pyvmomi ``ServiceInstance`` out (blocking: on the session's thread)."""
    try:
        from pyVim import connect  # noqa: PLC0415
    except ImportError:
        return
    connect.Disconnect(si)


def _executor() -> ThreadPoolExecutor:
    return ThreadPoolExecutor(max_workers=1, thread_name_prefix="slipway-esxi")


def _gb(kb: Any) -> int:
    """Whole GiB from KiB, rounded up (a 10 GiB disk reads 10, never 9.99)."""
    kb = int(kb or 0)
    return -(-kb // (1024 * 1024))


def _aware(value: Any) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


class PyvmomiEsxi:
    """``EsxiApi`` over one pyvmomi ``ServiceInstance``, each call on the one-thread executor."""

    def __init__(self, si: Any, *, host: str, executor: ThreadPoolExecutor | None = None,
                 poll: float = POLL, call_timeout: float = CALL_TIMEOUT,
                 task_limit: float = TASK_LIMIT, copy_limit: float = COPY_LIMIT) -> None:
        self._si = si
        self.host = host
        self.executor = executor or _executor()
        self.poll = poll
        self.call_timeout = call_timeout
        self.task_limit = task_limit
        self.copy_limit = copy_limit
        self._tasks: dict[str, Any] = {}  # task moref -> pyvmomi task, for cancel_task

    # ------------------------------------------------------------------ plumbing

    async def _call(self, fn: Callable[..., Any], *args: Any, doing: str, quiesce: bool = False) -> Any:
        loop = asyncio.get_running_loop()
        future = loop.run_in_executor(self.executor, functools.partial(fn, *args))
        try:
            return await asyncio.wait_for(future, self.call_timeout)
        except MachineError:
            raise
        except TimeoutError:
            raise MachineError(f"ESXi at {self.host} didn't answer in {int(self.call_timeout)} seconds "
                               f"while Slipway tried to {doing}", unreachable=True) from None
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 (every pyvmomi failure becomes Slipway's text)
            raise map_fault(exc, doing=doing, host=self.host, quiesce=quiesce) from None

    async def close(self) -> None:
        """Signs out (bounded) and stops the executor. Never raises."""
        try:
            await asyncio.wait_for(asyncio.get_running_loop().run_in_executor(self.executor, self._t_disconnect), 10)
        except Exception:  # noqa: BLE001, S110 (signing out is best effort)
            pass
        self.executor.shutdown(wait=False)

    def _t_disconnect(self) -> None:
        _disconnect(self._si)

    @property
    def _content(self) -> Any:
        return self._si.content

    def _t_view(self, *type_names: str) -> list[Any]:
        vim, _ = _pyvmomi()
        content = self._content
        view = content.viewManager.CreateContainerView(content.rootFolder, [getattr(vim, n) for n in type_names], True)
        try:
            return list(view.view)
        finally:
            view.Destroy()

    def _t_datacenter(self) -> Any:
        found = self._t_view("Datacenter")
        if not found:
            raise MachineError("ESXi shows no datacenter, which a standalone host always has")
        return found[0]

    def _t_vm(self, uuid: str) -> Any:
        vm = self._content.searchIndex.FindByUuid(None, uuid, True, True)
        if vm is None:
            raise VmGone(f"ESXi has no VM with the instance UUID {uuid}")
        return vm

    def _t_datastore(self, name: str) -> Any:
        for ds in self._t_view("Datastore"):
            if ds.name == name:
                return ds
        raise MachineError(f"ESXi has no datastore named {name}")

    def _t_disks(self, config: Any) -> tuple[DiskInfo, ...]:
        vim, _ = _pyvmomi()
        out = []
        for dev in getattr(getattr(config, "hardware", None), "device", None) or []:
            if not isinstance(dev, vim.vm.device.VirtualDisk):
                continue
            chain: list[str] = []
            backing = dev.backing
            while backing is not None:
                name = getattr(backing, "fileName", None)
                if name:
                    chain.insert(0, normalize_path(name))
                backing = getattr(backing, "parent", None)
            if not chain:
                continue
            out.append(DiskInfo(key=dev.key, path=chain[-1], base=chain[0], chain=tuple(chain),
                                size_gb=_gb(dev.capacityInKB), controller_key=dev.controllerKey, unit=dev.unitNumber))
        return tuple(out)

    def _t_info(self, vm: Any) -> VmInfo:
        config = vm.config
        runtime = vm.runtime
        guest = vm.guest
        extra = _extra_of(config) if config is not None else {}
        return VmInfo(
            moref=str(vm._moId),
            uuid=str(getattr(config, "instanceUuid", "") or ""),
            name=str(getattr(config, "name", None) or vm.name),
            power=str(getattr(runtime, "powerState", "") or ""),
            path=normalize_path(config.files.vmPathName) if config is not None else "",
            annotation=str(getattr(config, "annotation", "") or ""),
            cores=getattr(getattr(config, "hardware", None), "numCPU", None),
            memory_mb=getattr(getattr(config, "hardware", None), "memoryMB", None),
            disks=self._t_disks(config) if config is not None else (),
            extra={k: v for k, v in extra.items() if k.startswith("slipway.")},
            guestinfo_keys=tuple(sorted(k for k in extra if k.startswith(GUESTINFO_PREFIX))),
            tools_running=getattr(guest, "toolsRunningStatus", None) == "guestToolsRunning",
        )

    def _t_ref(self, task: Any, kind: str | None = None, *, ours: bool = False) -> TaskRef:
        info = task.info
        description_id = getattr(info, "descriptionId", None)
        name = getattr(info, "name", None)
        if kind is None:
            kind = KIND_BY_DESCRIPTION.get(description_id or "")
            if kind is None and name in COPY_TASK_NAMES:
                kind = COPY_KIND
            kind = kind or str(description_id or name or "unknown")
        return TaskRef(
            id=str(task._moId),
            kind=kind,
            description_id=description_id,
            started_at=_aware(getattr(info, "startTime", None) or getattr(info, "queueTime", None)),
            state=str(getattr(info, "state", "") or ""),
            cancelable=bool(getattr(info, "cancelable", False)),
            entity=getattr(info, "entityName", None),
            ours=ours,
        )

    def _t_poll(self, task: Any) -> tuple[str, Any, Any]:
        info = task.info  # read once: each attribute of a live task is another round trip
        return str(info.state), info.error, info.result

    async def _task(self, start: Callable[[], Any], *, kind: str, doing: str, on_task: OnTask | None,
                    quiesce: bool = False) -> Any:
        """Starts a task, reports it, then waits for it (see the module's notes on stopping tasks)."""
        task = await self._call(start, doing=doing, quiesce=quiesce)
        ref = await self._call(functools.partial(self._t_ref, task, kind, ours=True), doing=doing)
        self._tasks[ref.id] = task
        if on_task is not None:
            await on_task(ref)  # recorded before Slipway waits (M5)
        limit = self.copy_limit if ref.is_copy else self.task_limit
        try:
            result = await asyncio.wait_for(self._wait(task, ref, doing, quiesce), limit)
        except TimeoutError:
            cancelled = await self._stop_copy(task, ref)
            minutes = max(1, round(limit / 60))
            if ref.is_copy:
                tail = ("Slipway cancelled the copy" if cancelled
                        else "ESXi couldn't cancel it, so it may still be running; the next attempt waits for it")
                raise TaskTimedOut(f"ESXi didn't finish copying the disk in {minutes} minutes; {tail}", ref,
                                   cancelled=cancelled) from None
            raise TaskTimedOut(f"ESXi's {ref.words} task {ref.id} didn't finish in {minutes} minutes; Slipway "
                               "left it running, and the next change waits for it", ref) from None
        except asyncio.CancelledError:
            # A cancelled job stops only a disk copy; shielded so a second cancel can't cut it short.
            await asyncio.shield(self._stop_copy(task, ref))
            raise
        self._tasks.pop(ref.id, None)
        return result

    async def _wait(self, task: Any, ref: TaskRef, doing: str, quiesce: bool) -> Any:
        while True:
            state, error, result = await self._call(self._t_poll, task, doing=doing)
            if state == "success":
                return result
            if state == "error":
                err = map_fault(error, doing=doing, host=self.host, quiesce=quiesce, task=ref) if error is not None \
                    else TaskFailed(f"ESXi couldn't {doing}", ref)
                if isinstance(err, TaskFailed) and err.task is None:
                    err.task = ref
                raise err
            await asyncio.sleep(self.poll)

    async def _stop_copy(self, task: Any, ref: TaskRef) -> bool:
        """Cancels ``task`` when it is a disk copy ESXi says can be cancelled; leaves any other task alone."""
        if not ref.is_copy:
            return False
        try:
            return bool(await self._call(self._t_cancel, task, doing="cancel the disk copy"))
        except MachineError:
            return False

    def _t_cancel(self, task: Any) -> bool:
        info = task.info
        if str(info.state) not in ("queued", "running") or not info.cancelable:
            return False
        task.CancelTask()
        return True

    # ------------------------------------------------------------------- reads

    async def about(self) -> About:
        def read() -> About:
            a = self._content.about
            return About(api_type=str(a.apiType or ""), version=str(a.version or ""), build=str(a.build or ""),
                         full_name=str(a.fullName or ""))
        return await self._call(read, doing="read its version")

    async def license_editions(self) -> list[str]:
        def read() -> list[str]:
            manager = self._content.licenseManager
            return [str(lic.editionKey) for lic in (getattr(manager, "licenses", None) or []) if lic.editionKey]
        return await self._call(read, doing="read its licence")

    async def datastore(self, name: str) -> DatastoreInfo | None:
        def read() -> DatastoreInfo | None:
            for ds in self._t_view("Datastore"):
                summary = ds.summary
                if summary.name == name:
                    return DatastoreInfo(name=name, free_gb=round(int(summary.freeSpace or 0) / 2**30, 1),
                                         capacity_gb=round(int(summary.capacity or 0) / 2**30, 1),
                                         accessible=bool(summary.accessible))
            return None
        return await self._call(read, doing=f"read the datastore {name}")

    async def network_names(self) -> list[str]:
        return await self._call(lambda: sorted({str(n.name) for n in self._t_view("Network")}),
                                doing="list its port groups")

    async def resource_pool_names(self) -> list[str]:
        return await self._call(lambda: sorted({str(p.name) for p in self._t_view("ResourcePool")}),
                                doing="list its resource pools")

    async def find_vm(self, uuid: str) -> VmInfo | None:
        def read() -> VmInfo | None:
            vm = self._content.searchIndex.FindByUuid(None, uuid, True, True)
            return None if vm is None else self._t_info(vm)
        return await self._call(read, doing="look up a VM")

    async def find_vm_by_name(self, name: str) -> VmInfo | None:
        def read() -> VmInfo | None:
            for vm in self._t_view("VirtualMachine"):
                if vm.name == name:  # a standalone host keeps VM names unique in its one VM folder
                    return self._t_info(vm)
            return None
        return await self._call(read, doing=f"look up the VM {name}")

    async def guest_ips(self) -> dict[str, list[str]]:
        def read() -> dict[str, list[str]]:
            out: dict[str, list[str]] = {}
            for vm in self._t_view("VirtualMachine"):
                ips = guest_ipv4(vm.guest)
                if ips:
                    out[str(vm.name)] = ips
            return out
        return await self._call(read, doing="read the addresses its VMs report")

    async def disk_users(self, path: str) -> list[str]:
        wanted = normalize_path(path)

        def read() -> list[str]:
            users = []
            for vm in self._t_view("VirtualMachine"):
                if vm.config is not None and any(wanted in d.chain for d in self._t_disks(vm.config)):
                    users.append(str(vm.name))
            return sorted(users)
        return await self._call(read, doing="find which VMs use a disk")

    async def guest(self, uuid: str) -> GuestView:
        def read() -> GuestView:
            g = self._t_vm(uuid).guest
            return GuestView(tools_running=getattr(g, "toolsRunningStatus", None) == "guestToolsRunning",
                             ipv4=tuple(guest_ipv4(g)), hostname=getattr(g, "hostName", None))
        return await self._call(read, doing="read what VMware Tools reports")

    def _t_tree(self, vm: Any) -> list[tuple[Any, int | None]]:
        info = vm.snapshot
        if info is None:
            return []
        out: list[tuple[Any, int | None]] = []
        stack = [(node, None) for node in reversed(info.rootSnapshotList or [])]
        while stack:
            node, parent = stack.pop()
            out.append((node, parent))
            stack.extend((child, node.id) for child in reversed(node.childSnapshotList or []))
        return out

    async def snapshots(self, uuid: str) -> list[SnapshotInfo]:
        def read() -> list[SnapshotInfo]:
            vm = self._t_vm(uuid)
            current = getattr(getattr(vm, "snapshot", None), "currentSnapshot", None)
            current_id = getattr(current, "_moId", None)
            return [SnapshotInfo(id=int(node.id), name=str(node.name), description=str(node.description or ""),
                                 created=_aware(node.createTime), quiesced=bool(node.quiesced),
                                 current=current_id is not None and getattr(node.snapshot, "_moId", None) == current_id,
                                 parent_id=parent)
                    for node, parent in self._t_tree(vm)]
        return await self._call(read, doing="list the VM's snapshots")

    async def list_folder(self, path: str) -> list[str] | None:
        """The names of the files in ``[datastore] folder``, or None when the folder isn't there."""
        vim, _ = _pyvmomi()
        ds_name, _rel = split_path(path)
        folder = normalize_path(path)
        ds = await self._call(self._t_datastore, ds_name, doing=f"read the datastore {ds_name}")

        def start() -> Any:
            spec = vim.host.DatastoreBrowser.SearchSpec(matchPattern=["*"])
            return ds.browser.SearchDatastore_Task(datastorePath=folder, searchSpec=spec)
        try:
            result = await self._task(start, kind="browse", doing=f"list {folder}", on_task=None)
        except FileMissing:  # no such folder
            return None
        return sorted(str(f.path) for f in (getattr(result, "file", None) or []))

    async def file_exists(self, path: str) -> bool:
        ds, rel = split_path(path)
        if "/" not in rel:
            folder, name = f"[{ds}]", rel
        else:
            parent, name = rel.rsplit("/", 1)
            folder = f"[{ds}] {parent}"
        names = await self.list_folder(folder)
        return names is not None and name in names

    async def running_tasks(self, uuid: str | None = None) -> list[TaskRef]:
        """Tasks queued or running on the VM, or on the whole host with ``uuid=None`` (a disk copy is
        on no VM, so only the host-wide list shows one)."""
        def read() -> list[TaskRef]:
            tasks = self._t_vm(uuid).recentTask if uuid else self._content.taskManager.recentTask
            out = []
            for task in tasks or []:
                ref = self._t_ref(task, ours=str(task._moId) in self._tasks)
                if ref.state in ("queued", "running"):
                    self._tasks.setdefault(ref.id, task)
                    out.append(ref)
            return out
        return await self._call(read, doing="list its running tasks")

    async def cancel_task(self, task: TaskRef) -> bool:
        """Cancels a disk copy that ESXi says can be cancelled. Any other task is left alone (D24)."""
        if not task.is_copy:
            return False
        live = self._tasks.get(task.id)
        if live is None:
            return False
        return await self._stop_copy(live, task)

    # ------------------------------------------------------------------ changes

    async def create_vm(self, spec: VmSpec, *, on_task: OnTask | None = None) -> VmInfo:
        config = create_config(spec)

        def start() -> Any:
            dc = self._t_datacenter()
            pools = [p for p in self._t_view("ResourcePool") if p.name == (spec.resource_pool or DEFAULT_RESOURCE_POOL)]
            if not pools:
                raise MachineError(f"ESXi has no resource pool named {spec.resource_pool}")
            return dc.vmFolder.CreateVM_Task(config=config, pool=pools[0])
        vm = await self._task(start, kind="create_vm", doing=f"create the VM {spec.name}", on_task=on_task)
        return await self._call(self._t_info, vm, doing=f"read the new VM {spec.name}")

    async def copy_disk(self, source: str, dest: str, *, on_task: OnTask | None = None) -> None:
        vim, _ = _pyvmomi()
        source, dest = normalize_path(source), normalize_path(dest)

        def start() -> Any:
            dc = self._t_datacenter()
            spec = vim.VirtualDiskManager.VirtualDiskSpec(diskType="thin", adapterType="lsiLogic")
            return self._content.virtualDiskManager.CopyVirtualDisk_Task(
                sourceName=source, sourceDatacenter=dc, destName=dest, destDatacenter=dc, destSpec=spec, force=False)
        await self._task(start, kind=COPY_KIND, doing="copy the seed VM's disk", on_task=on_task)

    async def delete_disk(self, path: str, *, on_task: OnTask | None = None) -> None:
        path = normalize_path(path)

        def start() -> Any:
            return self._content.virtualDiskManager.DeleteVirtualDisk_Task(name=path, datacenter=self._t_datacenter())
        await self._task(start, kind="delete_disk", doing=f"delete {path}", on_task=on_task)

    async def _reconfigure(self, uuid: str, build: Callable[[Any], Any], *, kind: str, doing: str,
                           on_task: OnTask | None) -> None:
        def start() -> Any:
            vm = self._t_vm(uuid)
            return vm.ReconfigVM_Task(spec=build(vm))
        await self._task(start, kind=kind, doing=doing, on_task=on_task)

    async def attach_disk(self, uuid: str, path: str, *, on_task: OnTask | None = None) -> None:
        vim, _ = _pyvmomi()
        path = normalize_path(path)

        def build(vm: Any) -> Any:
            devices = vm.config.hardware.device
            controllers = [d for d in devices if isinstance(d, vim.vm.device.ParaVirtualSCSIController)]
            if not controllers:
                raise MachineError(f"{vm.name} has no PVSCSI controller to attach its disk to")
            key = controllers[0].key
            used = {d.unitNumber for d in devices if getattr(d, "controllerKey", None) == key}
            unit = next(u for u in range(16) if u != 7 and u not in used)  # 7 is the controller itself
            disk = vim.vm.device.VirtualDisk(
                key=-1, controllerKey=key, unitNumber=unit,
                backing=vim.vm.device.VirtualDisk.FlatVer2BackingInfo(fileName=path, diskMode="persistent"))
            change = vim.vm.device.VirtualDeviceSpec(operation=vim.vm.device.VirtualDeviceSpec.Operation.add, device=disk)
            return vim.vm.ConfigSpec(deviceChange=[change])
        await self._reconfigure(uuid, build, kind="attach_disk", doing="attach the copied disk", on_task=on_task)

    async def grow_disk(self, uuid: str, size_gb: int, *, on_task: OnTask | None = None) -> None:
        """Grows the VM's one disk to ``size_gb``. Disks never shrink; the same size changes nothing."""
        vim, _ = _pyvmomi()
        size_gb = int(size_gb)
        info = await self._call(lambda: self._t_info(self._t_vm(uuid)), doing="read the VM")
        if len(info.disks) != 1:
            raise MachineError(f"{info.name} has {len(info.disks)} disks; Slipway grows a VM with exactly one")
        if size_gb < info.disks[0].size_gb:
            raise MachineError(f"{info.name}'s disk is {info.disks[0].size_gb} GB; Slipway never shrinks a disk")
        if size_gb == info.disks[0].size_gb:
            return
        key = info.disks[0].key

        def build(vm: Any) -> Any:
            disk = next(d for d in vm.config.hardware.device if getattr(d, "key", None) == key)
            disk.capacityInKB = size_gb * 1024 * 1024
            disk.capacityInBytes = size_gb * 2**30
            change = vim.vm.device.VirtualDeviceSpec(operation=vim.vm.device.VirtualDeviceSpec.Operation.edit, device=disk)
            return vim.vm.ConfigSpec(deviceChange=[change])
        await self._reconfigure(uuid, build, kind="grow_disk", doing=f"grow {info.name}'s disk to {size_gb} GB",
                                on_task=on_task)

    async def set_size(self, uuid: str, cores: int, memory_mb: int, *, on_task: OnTask | None = None) -> None:
        vim, _ = _pyvmomi()
        await self._reconfigure(uuid, lambda vm: vim.vm.ConfigSpec(numCPUs=int(cores), memoryMB=int(memory_mb)),
                                kind="set_size", doing=f"set the VM to {cores} vCPU and {memory_mb} MB",
                                on_task=on_task)

    async def set_extra_config(self, uuid: str, values: dict[str, str], *, on_task: OnTask | None = None) -> None:
        """Sets extraConfig keys; an empty value deletes the key."""
        vim, _ = _pyvmomi()
        options = [vim.option.OptionValue(key=k, value=v) for k, v in values.items()]
        await self._reconfigure(uuid, lambda vm: vim.vm.ConfigSpec(extraConfig=options), kind="set_extra_config",
                                doing="change the VM's settings", on_task=on_task)

    def _t_power(self, uuid: str) -> str:
        return str(self._t_vm(uuid).runtime.powerState)

    async def power_on(self, uuid: str, *, on_task: OnTask | None = None) -> None:
        if await self._call(self._t_power, uuid, doing="read the VM's power state") == "poweredOn":
            return
        await self._task(lambda: self._t_vm(uuid).PowerOnVM_Task(), kind="power_on", doing="power on the VM",
                         on_task=on_task)

    async def shutdown_guest(self, uuid: str) -> None:
        """Asks the guest to shut down through VMware Tools (no task: poll ``find_vm`` for ``poweredOff``)."""
        def run() -> None:
            vm = self._t_vm(uuid)
            if str(vm.runtime.powerState) != "poweredOff":
                vm.ShutdownGuest()
        await self._call(run, doing="shut the VM down")

    async def power_off(self, uuid: str, *, on_task: OnTask | None = None) -> None:
        if await self._call(self._t_power, uuid, doing="read the VM's power state") == "poweredOff":
            return
        await self._task(lambda: self._t_vm(uuid).PowerOffVM_Task(), kind="power_off", doing="power off the VM",
                         on_task=on_task)

    def _t_snapshot_node(self, uuid: str, snapshot_id: int) -> Any:
        matches = [node for node, _ in self._t_tree(self._t_vm(uuid)) if int(node.id) == int(snapshot_id)]
        if len(matches) != 1:
            raise MachineError(f"The VM has no snapshot with the id {snapshot_id}")
        return matches[0].snapshot

    async def take_snapshot(self, uuid: str, name: str, description: str = "", *, memory: bool = False,
                            quiesce: bool = True, on_task: OnTask | None = None) -> None:
        def start() -> Any:
            return self._t_vm(uuid).CreateSnapshot_Task(name=name, description=description, memory=memory,
                                                         quiesce=quiesce)
        await self._task(start, kind="snapshot", doing=f"take the VM snapshot {name}", on_task=on_task,
                         quiesce=quiesce)

    async def revert_snapshot(self, uuid: str, snapshot_id: int, *, on_task: OnTask | None = None) -> None:
        await self._task(lambda: self._t_snapshot_node(uuid, snapshot_id).RevertToSnapshot_Task(), kind="revert",
                         doing="revert the VM to its snapshot", on_task=on_task)

    async def delete_snapshot(self, uuid: str, snapshot_id: int, *, on_task: OnTask | None = None) -> None:
        def start() -> Any:
            return self._t_snapshot_node(uuid, snapshot_id).RemoveSnapshot_Task(removeChildren=False, consolidate=True)
        await self._task(start, kind="delete_snapshot", doing="delete the VM snapshot", on_task=on_task)

    async def destroy(self, uuid: str, *, on_task: OnTask | None = None) -> None:
        await self._task(lambda: self._t_vm(uuid).Destroy_Task(), kind="destroy", doing="delete the VM",
                         on_task=on_task)


# ------------------------------------------------------------------------ sessions


def _smart_connect(host: str, port: int, user: str, password: str, pem: str, fingerprint: str) -> Any:
    """Signs in to ESXi. The only call that opens a real connection (the test guard patches it).

    The context trusts the pinned certificate alone, without host-name checking (ESXi's default
    certificate names ``localhost.localdomain``), and pyvmomi checks the thumbprint on top (D16).
    """
    _pyvmomi()
    from pyVim import connect  # noqa: PLC0415

    from slipway.services import tls_pin  # noqa: PLC0415

    return connect.SmartConnect(
        host=host,
        port=port,
        user=user,
        pwd=password,
        sslContext=tls_pin.pinned_context(pem, check_hostname=False),
        thumbprint=fingerprint,
        httpConnectionTimeout=int(CALL_TIMEOUT),
    )


# Two sessions per account for jobs and two for page reads; the pools never wait on each other (§10.5).
job_sessions: defaultdict[str, asyncio.Semaphore] = defaultdict(lambda: asyncio.Semaphore(SESSIONS_PER_ACCOUNT))
read_sessions: defaultdict[str, asyncio.Semaphore] = defaultdict(lambda: asyncio.Semaphore(SESSIONS_PER_ACCOUNT))


def _account_name(account: Any) -> str:
    return str(getattr(account, "name", None) or "ESXi")


def connection_of(account: Any) -> tuple[str, int, str, str, str, str]:
    """``(host, port, user, password, pem, fingerprint)`` of an account, or ``MachineError`` saying what's missing."""
    config = getattr(account, "config", None) or {}
    name = _account_name(account)
    try:
        host, port = _url_host_port(config.get("url", ""))
    except AccountInvalid as exc:
        raise MachineError(f"ESXi account {name} can't be used: {exc.text}. "
                           "Fix it in Settings → Integrations, then retry.") from None
    user = str(config.get("user") or "")
    secret = getattr(account, "secret", None)
    tls = getattr(account, "tls", None) or {}
    if not secret:
        raise MachineError(f"ESXi account {name} can't be used: it has no password. "
                           "Fix it in Settings → Integrations, then retry.")
    if not tls.get("pem") or not tls.get("fingerprint_sha256"):
        raise MachineError(f"ESXi account {name} can't be used: no certificate is trusted for it. "
                           "Fix it in Settings → Integrations, then retry.")
    return host, port, user, str(secret), str(tls["pem"]), str(tls["fingerprint_sha256"])


@contextlib.asynccontextmanager
async def session(account: Any, *, purpose: str = "job", poll: float = POLL) -> AsyncIterator[PyvmomiEsxi]:
    """Signs in to the account's ESXi host, yields a ``PyvmomiEsxi``, and always signs out.

    ``purpose`` picks the pool: ``job`` waits for a free session, ``read`` (a page) waits at most
    5 seconds and then fails, so a page never hangs behind a long job.
    """
    if purpose not in ("job", "read"):
        raise ValueError(f"Unknown session purpose {purpose!r}")
    host, port, user, password, pem, fingerprint = connection_of(account)
    key = str(getattr(account, "id", None) or host)
    gate = (job_sessions if purpose == "job" else read_sessions)[key]
    if purpose == "read":
        try:
            await asyncio.wait_for(gate.acquire(), READ_WAIT)
        except TimeoutError:
            raise MachineError(f"ESXi account {_account_name(account)} is busy with Slipway's jobs; "
                               "try again in a moment") from None
    else:
        await gate.acquire()
    executor = _executor()
    release = True
    try:
        loop = asyncio.get_running_loop()
        signin = executor.submit(_smart_connect, host, port, user, password, pem, fingerprint)
        try:
            si = await asyncio.wait_for(asyncio.wrap_future(signin), SIGNIN_TIMEOUT)
        except BaseException as exc:
            if _late(signin):
                # Cut off (its time limit or a cancel) while the thread still signs in: a session it opens
                # later is signed out on that thread, and the pool's place is given back only then.
                executor.submit(_sign_out_late, signin, loop, gate)
                release = False
            if isinstance(exc, TimeoutError):
                raise MachineError(f"ESXi at {host} didn't answer the sign-in in {int(SIGNIN_TIMEOUT)} seconds",
                                   unreachable=True) from None
            if isinstance(exc, MachineError) or not isinstance(exc, Exception):
                raise
            raise map_fault(exc, doing="sign in", host=host) from None
        api = PyvmomiEsxi(si, host=host, executor=executor, poll=poll)
        try:
            yield api
        finally:
            await api.close()
    finally:
        executor.shutdown(wait=False)
        if release:
            gate.release()


def _late(signin: Future[Any]) -> bool:
    """The sign-in thread still runs, or ended with a session nobody took."""
    if signin.cancelled():
        return False
    return not signin.done() or signin.exception() is None


def _sign_out_late(signin: Future[Any], loop: asyncio.AbstractEventLoop, gate: asyncio.Semaphore) -> None:
    """On the session's one thread, after a cut-off sign-in ended: sign its session out, then free the pool."""
    try:
        if not signin.cancelled() and signin.exception() is None:
            _disconnect(signin.result())
    except Exception:  # noqa: BLE001, S110 (signing out is best effort)
        pass
    finally:
        with contextlib.suppress(RuntimeError):  # the loop has closed meanwhile
            loop.call_soon_threadsafe(gate.release)


SessionFactory = Callable[[Any], contextlib.AbstractAsyncContextManager[EsxiApi]]


# -------------------------------------------------------------------- the account


def _url_host_port(url: Any) -> tuple[str, int]:
    """Host and port of a cleaned account URL; ``AccountInvalid('url')`` when it isn't one."""
    cleaned = _clean_url(url)
    parts = urlsplit(cleaned)
    return str(parts.hostname), parts.port or 443


def _clean_url(value: Any) -> str:
    text = value.strip() if isinstance(value, str) else ""
    example = "such as https://esxi.example.lan"
    parts = urlsplit(text)
    if parts.scheme.lower() != "https" or not parts.netloc:
        raise AccountInvalid("url", f"The URL must start with https://, {example}")
    if parts.username or parts.password or "@" in parts.netloc:
        raise AccountInvalid("url", "Leave the user name and password out of the URL")
    if parts.query or parts.fragment or parts.path.rstrip("/") not in ("", "/sdk", "/ui"):
        raise AccountInvalid("url", f"Give only the host's address, {example}")
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        raise AccountInvalid("url", "The URL's port must be a number between 1 and 65535") from None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is None and not URL_HOST_RE.fullmatch(host):
        raise AccountInvalid("url", f"{host or 'That'} isn't a host name or IP address, {example}")
    shown = f"[{host}]" if ip is not None and ip.version == 6 else host
    return f"https://{shown}" + (f":{port}" if port and port != 443 else "")


def _esxi_name(config: dict[str, Any], key: str, what: str, example: str, default: str | None = None) -> str:
    value = config.get(key)
    if default is not None and (value is None or (isinstance(value, str) and not value.strip())):
        return default
    try:
        return vmnet.check_esxi_name(value, what, example)
    except ValueError as exc:
        raise AccountInvalid(key, str(exc)) from None


def clean_secret(secret: Any) -> str:
    if not isinstance(secret, str) or not secret.strip():
        raise AccountInvalid("secret", "Give the ESXi user's password")
    if len(secret) > SECRET_MAX:
        raise AccountInvalid("secret", f"The password is longer than {SECRET_MAX} characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in secret):
        raise AccountInvalid("secret", "The password can't contain control characters")
    return secret


def clean_config(config: Any, secret: str | None) -> dict[str, Any]:
    """An ESXi account's ``config``, cleaned; ``AccountInvalid(field, text)`` on the first bad field.

    ``secret`` is checked when given (None keeps the stored one); it is never part of the result.
    """
    if not isinstance(config, dict):
        raise AccountInvalid("config", "An ESXi account is {url, user, datastore, resource_pool, source_vm, networks}")
    unknown = sorted(set(config) - set(CONFIG_KEYS))
    if unknown:
        raise AccountInvalid(unknown[0], f"An ESXi account has no {unknown[0]} setting")
    out: dict[str, Any] = {"url": _clean_url(config.get("url"))}
    user = config.get("user")
    user = user.strip() if isinstance(user, str) else ""
    if not USER_RE.fullmatch(user):
        raise AccountInvalid("user", "Give the ESXi user's name: letters, digits, '.', '_', '-' or '@' (such as slipway)")
    out["user"] = user
    out["datastore"] = _esxi_name(config, "datastore", "datastore name", "datastore1")
    out["resource_pool"] = _esxi_name(config, "resource_pool", "resource pool name", DEFAULT_RESOURCE_POOL,
                                      default=DEFAULT_RESOURCE_POOL)
    out["source_vm"] = _esxi_name(config, "source_vm", "seed VM name", "ubuntu-2404-seed")
    out["networks"] = vmnet.check_networks(config.get("networks") or [], provider=PROVIDER)
    if secret is not None:
        clean_secret(secret)
    return out


def _word(value: Any, limit: int = 40) -> str:
    """A short value ESXi reported, made safe to show (version and build strings)."""
    return _SAFE_WORD.sub("", str(value or ""))[:limit]


async def run_test(account: Any, *, open_session: SessionFactory | None = None) -> list[Check]:
    """The account's Test: what ESXi is, its licence, and everything the account names.

    Returns the checks in order and sets ``account.facts`` to ``{version, free_gb}`` (what was read);
    the accounts service stores both. A failure to sign in is one failed ``connect`` check.
    """
    config = getattr(account, "config", None) or {}
    opener = open_session or session
    checks: list[Check] = []
    facts: dict[str, Any] = {}
    try:
        async with opener(account) as api:
            await _test_with(api, config, checks, facts)
    except MachineError as exc:
        checks.append(Check.failed("connect", exc.text))
    with contextlib.suppress(AttributeError, TypeError):
        account.facts = facts
    return checks


async def _test_with(api: EsxiApi, config: dict[str, Any], checks: list[Check], facts: dict[str, Any]) -> None:
    about = await api.about()
    if about.api_type == API_VCENTER:
        checks.append(Check.failed("api", VCENTER_TEXT))
        return
    if about.api_type != API_HOST_AGENT:
        checks.append(Check.failed("api", "That address doesn't answer as an ESXi host's API"))
        return
    facts["version"] = _word(about.version, 20)
    checks.append(Check.passed("api", f"ESXi {_word(about.version, 20)} (build {_word(about.build, 20)})"))

    editions = await api.license_editions()
    if LICENCE_BASIC in editions:
        checks.append(Check.failed("licence", LICENCE_TEXT))
        return  # free ESXi refuses every change, so nothing else here matters yet
    checks.append(Check.passed("licence", "The licence allows changes through the API"))

    ds_name = config.get("datastore", "")
    ds = await api.datastore(ds_name)
    if ds is None:
        checks.append(Check.failed("datastore", f"ESXi has no datastore named {ds_name}"))
    elif not ds.accessible:
        checks.append(Check.failed("datastore", f"The datastore {ds_name} isn't accessible on ESXi right now"))
    else:
        facts["free_gb"] = ds.free_gb
        checks.append(Check.passed("datastore", f"{ds_name}: {ds.free_gb:g} GB free of {ds.capacity_gb:g} GB"))

    networks = config.get("networks") or []
    if not networks:
        checks.append(Check.warning("networks", "The account has no networks yet: add one so environments can "
                                                "give their VMs addresses"))
    else:
        port_groups = set(await api.network_names())
        for net in networks:
            group = net.get("port_group", "")
            if group in port_groups:
                checks.append(Check.passed(f"network:{net.get('name')}", f"Port group {group} is there"))
            else:
                checks.append(Check.failed(f"network:{net.get('name')}",
                                           f"ESXi has no port group named {group} (network {net.get('name')})"))

    pool = config.get("resource_pool") or DEFAULT_RESOURCE_POOL
    if pool in set(await api.resource_pool_names()):
        checks.append(Check.passed("resource_pool", f"Resource pool {pool} is there"))
    else:
        checks.append(Check.failed("resource_pool", f"ESXi has no resource pool named {pool}"))

    checks.append(await _seed_check(api, config.get("source_vm", "")))


async def _seed_check(api: EsxiApi, name: str) -> Check:
    """The seed VM exists, is off, has exactly one disk and no snapshots (Sirdar's ``esxi.py:802-820``)."""
    seed = await api.find_vm_by_name(name)
    if seed is None:
        return Check.failed("seed", f"ESXi has no VM named {name} to copy the disk from")
    if seed.power != "poweredOff":
        return Check.failed("seed", f"{name} is running; Slipway copies its disk only while it is off: shut it down")
    if len(seed.disks) != 1:
        return Check.failed("seed", f"{name} has {len(seed.disks)} disks; the seed VM must have exactly one")
    if len(seed.disks[0].chain) > 1 or await api.snapshots(seed.uuid):
        return Check.failed("seed", f"{name} has VM snapshots; delete them so Slipway copies one whole disk")
    return Check.passed("seed", f"{name}: off, one {seed.disks[0].size_gb} GB disk, no snapshots")
