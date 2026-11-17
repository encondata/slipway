"""``FakeProxmox``: a Proxmox VE API for tests, as an httpx ``MockTransport`` handler (spec §16.1).

Its state is a JSON file, so the fake Terraform (another process, ``tests/bin/fake-terraform``) and
this fake API see the same VMs. Every change happens under an exclusive ``flock`` on
``<state>.lock``: read the file, change it, write it back. The module-level helpers (``locked``,
``load``, ``save``, ``clone_vm``, ``finish_clone``, ``destroy_vm``, ``set_config``) are what the fake
Terraform uses to make its two writes (the clone, then the tags), as ``bpg/proxmox`` 0.115.0 does.

It behaves as Proxmox where Slipway's design depends on it:

* ``Authorization: PVEAPIToken=<token>`` is checked on every request (401 otherwise);
* tags are stored sorted and ``;``-joined;
* ``/cluster/resources`` lists only VMs in the token's pool, while ``/cluster/nextid?vmid=`` answers
  for every VM (400 when the id is taken), and a VM outside the pool answers 403;
* a VM asked for on a node that doesn't hold it answers 500, as Proxmox's "Configuration file
  does not exist" does;
* the storage's type (``lvmthin``, ``zfspool``, ``lvm``, ``dir`` with a ``file_format``) drives
  ``…/feature?feature=snapshot``; on ``zfspool`` a rollback to any snapshot but the newest ends
  with Proxmox's "is not most recent snapshot" text;
* the clone call (``POST /nodes/{node}/qemu/{template}/clone``) takes ``name``, ``description`` and
  ``pool`` but no tags, and the clone has ``lock: clone`` while its task runs; the tags come in a
  later ``POST …/config``, refused while the VM is locked;
* error answers carry upstream-looking text (``UPSTREAM_MARK``) so tests can check Slipway never
  passes it on.

Tasks. Each task has a UPID and ``polls`` left. A request about a VM (its config, status, tasks,
agent, snapshots) or about the task first ticks that VM's running tasks; a task whose polls reach 0
ends (``OK``, or an error with ``task_fails``), and its effect is applied then. By default a task
ends at the first such request. ``task_hangs(kind)`` makes a kind never end.

Kinds are Proxmox's task types (``qmstart``, ``qmshutdown``, ``qmstop``, ``qmsnapshot``,
``qmrollback``, ``qmdelsnapshot``, ``qmdestroy``, ``qmclone``); the short names ``start``,
``shutdown``, ``stop``, ``snapshot``, ``rollback``, ``delsnapshot``, ``destroy`` and ``clone`` work too.
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import json
import os
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote

import httpx

TOKEN = "slipway@pve!slipway=0b3c2f6e-1a2b-4c3d-8e9f-0123456789ab"
TOKEN_SECRET = TOKEN.split("=", 1)[1]
URL = "https://pve.test:8006"
NODES = ("pve1", "pve2")
POOL = "slipway"
STORAGE = "local-lvm"
TEMPLATE_VMID = 9000
TEMPLATE_NAME = "ubuntu-2404-cloud"
TEMPLATE_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOldTemplateKeyFromTheImageXXXXXXXXXXXXXXX template"
HOST_KEY_PATH = "/etc/ssh/ssh_host_ed25519_key.pub"
BOOT_FINISHED = "/var/lib/cloud/instance/boot-finished"
UPSTREAM_MARK = "UPSTREAM-PROXMOX-TEXT"
NOT_NEWEST_TEXT = "can't rollback, '{name}' is not most recent snapshot"

# The role of spec §13.3 (Proxmox 9 names), what the token has on /pool/<pool> by default.
FULL_ROLE = [
    "VM.Allocate", "VM.Clone", "VM.Audit", "VM.PowerMgmt", "VM.Config.CDROM", "VM.Config.CPU",
    "VM.Config.Cloudinit", "VM.Config.Disk", "VM.Config.HWType", "VM.Config.Memory",
    "VM.Config.Network", "VM.Config.Options", "VM.Snapshot", "VM.Snapshot.Rollback",
    "VM.GuestAgent.Audit", "VM.GuestAgent.FileRead", "Datastore.AllocateSpace", "Datastore.Audit",
    "SDN.Use", "Pool.Audit", "Sys.Audit",
]

KINDS = {
    "start": "qmstart", "shutdown": "qmshutdown", "stop": "qmstop", "snapshot": "qmsnapshot",
    "rollback": "qmrollback", "delsnapshot": "qmdelsnapshot", "destroy": "qmdestroy", "clone": "qmclone",
}
# The lock Proxmox holds on a VM while a task of that kind runs.
LOCKS = {"qmsnapshot": "snapshot", "qmrollback": "rollback", "qmdelsnapshot": "snapshot-delete",
         "qmclone": "clone", "qmdestroy": "destroyed"}
FILE_STORAGES = ("dir", "nfs", "cifs", "glusterfs")


def kind_of(kind: str) -> str:
    return KINDS.get(kind, kind)


# ------------------------------------------------------------------------ the state file


def initial_state(*, token: str = TOKEN, nodes: tuple[str, ...] = NODES, pool: str = POOL,
                  storage: str = STORAGE, storage_type: str = "lvmthin", file_format: str | None = None,
                  version: str = "9.0.3") -> dict[str, Any]:
    template = {
        "vmid": TEMPLATE_VMID, "name": TEMPLATE_NAME, "node": nodes[0], "pool": pool, "template": True,
        "tags": [], "status": "stopped", "lock": None, "description": "Ubuntu 24.04 cloud image",
        "config": {"agent": "enabled=1", "ciupgrade": 0, "cores": 2, "memory": 2048,
                   "scsi0": f"{storage}:base-{TEMPLATE_VMID}-disk-0,size=3584M"},
        "address": None, "files": {}, "snapshots": [],
    }
    return {
        "token": token, "version": version, "nodes": list(nodes), "pool": pool,
        "storages": {storage: {"type": storage_type, "content": "images,rootdir", "active": 1, "enabled": 1,
                               "avail": 500 * 1024 ** 3, "total": 1000 * 1024 ** 3, "file_format": file_format}},
        "bridges": {node: {"vmbr0": {"type": "bridge"}, "vmbr1": {"type": "OVSBridge"}, "eno1": {"type": "eth"}}
                    for node in nodes},
        "privileges": {f"/pool/{pool}": list(FULL_ROLE)},
        "vms": {str(TEMPLATE_VMID): template},
        "tasks": {},
        "seq": 0,
        "first_free": 100,
        "knobs": {
            "deny": [], "task_fails": [], "task_hangs": [], "task_outlives_cancel": {}, "snapshot_task_late": False,
            "agent_late": 0, "agent_wrong_address": False, "stale_template_key": 0, "clone_lock_outlives": 0,
            "resize_refused_with_snapshots": False, "slow": 0.0,
        },
    }


@contextlib.contextmanager
def locked(path: str | os.PathLike) -> Iterator[dict[str, Any]]:
    """The state, under an exclusive lock; written back when the block ends without an error."""
    lock_path = f"{os.fspath(path)}.lock"
    with open(lock_path, "a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            state = load(path)
            yield state
            save(path, state)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def load(path: str | os.PathLike) -> dict[str, Any]:
    return json.loads(Path(path).read_text())


def save(path: str | os.PathLike, state: dict[str, Any]) -> None:
    tmp = f"{os.fspath(path)}.tmp"
    Path(tmp).write_text(json.dumps(state, indent=1, sort_keys=True))
    os.replace(tmp, path)


def sorted_tags(tags: Any) -> list[str]:
    if isinstance(tags, str):
        items = tags.replace(",", ";").replace(" ", ";").split(";")
    else:
        items = list(tags or [])
    return sorted({str(t).strip() for t in items if str(t).strip()})


def new_upid(state: dict[str, Any], node: str, kind: str, vmid: int | str, *, user: str | None = None) -> str:
    state["seq"] += 1
    start = int(time.time())
    who = user or state["token"].split("=", 1)[0]
    return f"UPID:{node}:{state['seq']:08X}:{state['seq']:08X}:{start:08X}:{kind}:{vmid}:{who}:"


def start_task(state: dict[str, Any], node: str, kind: str, vmid: int | str, effect: dict[str, Any] | None = None,
               *, polls: int | None = 1, user: str | None = None) -> str:
    """A running task; ``polls`` None never ends. The VM takes the kind's lock while it runs."""
    kind = kind_of(kind)
    knobs = state["knobs"]
    if kind in knobs["task_hangs"]:
        polls = None
    elif kind in knobs["task_outlives_cancel"]:
        polls = int(knobs["task_outlives_cancel"][kind])
    upid = new_upid(state, node, kind, vmid, user=user)
    state["tasks"][upid] = {
        "upid": upid, "node": node, "type": kind, "vmid": int(vmid), "status": "running", "exitstatus": None,
        "polls": polls, "effect": effect or {}, "starttime": int(time.time()), "late": False,
        "user": user or state["token"].split("=", 1)[0],
    }
    vm = state["vms"].get(str(vmid))
    if vm is not None and kind in LOCKS:
        vm["lock"] = LOCKS[kind]
    return upid


def _finish(state: dict[str, Any], task: dict[str, Any]) -> None:
    """Ends a task: its effect applied, or its error when its kind fails or the effect refuses."""
    task["status"] = "stopped"
    vm = state["vms"].get(str(task["vmid"]))
    if vm is not None and vm.get("lock") == LOCKS.get(task["type"]):
        vm["lock"] = None
    if task["type"] in state["knobs"]["task_fails"]:
        task["exitstatus"] = f"{UPSTREAM_MARK}: command '/usr/bin/kvm -id {task['vmid']}' failed: exit code 1"
        return
    error = _apply(state, task)
    task["exitstatus"] = error or "OK"


def _apply(state: dict[str, Any], task: dict[str, Any]) -> str | None:
    vm = state["vms"].get(str(task["vmid"]))
    kind, effect = task["type"], task["effect"]
    if vm is None and kind != "qmclone":
        return f"{UPSTREAM_MARK}: VM {task['vmid']} not found"
    if kind == "qmstart":
        vm["status"] = "running"
    elif kind in ("qmshutdown", "qmstop"):
        vm["status"] = "stopped"
    elif kind == "qmsnapshot":
        if not any(s["name"] == effect["name"] for s in vm["snapshots"]):
            _add_snapshot(vm, effect["name"], effect.get("description", ""))
    elif kind == "qmrollback":
        names = [s["name"] for s in vm["snapshots"]]
        if effect["name"] not in names:
            return f"{UPSTREAM_MARK}: snapshot '{effect['name']}' does not exist"
        storage = state["storages"].get(vm.get("storage") or "", {})
        newest = max(vm["snapshots"], key=lambda s: s["snaptime"])["name"]
        if storage.get("type") == "zfspool" and effect["name"] != newest:
            return NOT_NEWEST_TEXT.format(name=effect["name"])
        vm["status"] = "stopped"
        vm["current_parent"] = effect["name"]
    elif kind == "qmdelsnapshot":
        vm["snapshots"] = [s for s in vm["snapshots"] if s["name"] != effect["name"]]
    elif kind == "qmdestroy":
        state["vms"].pop(str(task["vmid"]), None)
    return None


def _add_snapshot(vm: dict[str, Any], name: str, description: str) -> None:
    parent = vm.get("current_parent")
    stamp = max([int(time.time())] + [s["snaptime"] + 1 for s in vm["snapshots"]])
    vm["snapshots"].append({"name": name, "description": description, "snaptime": stamp, "parent": parent})
    vm["current_parent"] = name


def tick(state: dict[str, Any], vmid: int | str | None = None, upid: str | None = None) -> None:
    """One poll for the VM's running tasks (or one task)."""
    for task in list(state["tasks"].values()):
        if task["status"] != "running":
            continue
        if upid is not None and task["upid"] != upid:
            continue
        if upid is None and (vmid is None or task["vmid"] != int(vmid)):
            continue
        if task["polls"] is None:
            continue
        task["polls"] -= 1
        if task["polls"] <= 0:
            _finish(state, task)


def make_vm(state: dict[str, Any], vmid: int, name: str, *, node: str | None = None, pool: str | None = "",
            tags: Any = (), status: str = "running", address: str | None = None, host_key: str | None = None,
            description: str = "", storage: str | None = None, cores: int = 4, memory_mb: int = 8192,
            disk_gb: int = 64, boot_finished: bool = True, lock: str | None = None) -> dict[str, Any]:
    """A VM as it would be after a finished clone and first boot (or as a test wants it)."""
    storage = storage or next(iter(state["storages"]))
    files = {}
    if host_key:
        files[HOST_KEY_PATH] = host_key + "\n"
    if boot_finished:
        files[BOOT_FINISHED] = "2026-11-15T10:00:00+00:00 - v. 24.4\n"
    vm = {
        "vmid": int(vmid), "name": name, "node": node or state["nodes"][0],
        "pool": state["pool"] if pool == "" else pool, "template": False, "tags": sorted_tags(tags),
        "status": status, "lock": lock, "description": description, "storage": storage,
        "config": {"agent": "enabled=1", "cores": cores, "memory": memory_mb,
                   "scsi0": f"{storage}:vm-{vmid}-disk-0,size={disk_gb}G",
                   **({"ipconfig0": f"ip={address}/24"} if address else {})},
        "address": address, "files": files, "snapshots": [], "current_parent": None,
    }
    state["vms"][str(vmid)] = vm
    return vm


def clone_vm(state: dict[str, Any], template: int, newid: int, *, node: str, name: str | None = None,
             description: str | None = None, pool: str | None = None, storage: str | None = None,
             polls: int | None = None) -> str:
    """The first of ``bpg/proxmox``'s two writes: the clone call, with name, description and pool but
    no tags. The clone is locked (``clone``) while its task runs (``clone_lock_outlives`` polls, at least 1)."""
    if str(newid) in state["vms"]:
        raise ValueError(f"VM {newid} already exists")
    if str(template) not in state["vms"]:
        raise ValueError(f"template {template} doesn't exist")
    vm = make_vm(state, newid, name or f"Copy-of-VM-{template}", node=node, pool=pool, tags=(), status="stopped",
                 description=description or "", storage=storage, boot_finished=False)
    vm["files"] = {}
    vm["lock"] = "clone"
    if polls is None:
        polls = max(1, int(state["knobs"].get("clone_lock_outlives") or 0))
    upid = start_task(state, node, "qmclone", newid, polls=polls)
    vm["lock"] = "clone"
    return upid


def finish_clone(state: dict[str, Any], vmid: int, *, tags: Any, address: str | None = None,
                 host_key: str | None = None, start: bool = True, **config: Any) -> None:
    """The second write (``UpdateVM``): tags and settings, then the VM started and booted."""
    vm = state["vms"][str(vmid)]
    for task in state["tasks"].values():
        if task["vmid"] == int(vmid) and task["type"] == "qmclone" and task["status"] == "running":
            _finish(state, task)
    vm["lock"] = None
    vm["tags"] = sorted_tags(tags)
    vm["config"].update(config)
    if address:
        vm["address"] = address
        vm["config"]["ipconfig0"] = f"ip={address}/24"
    if host_key:
        vm["files"][HOST_KEY_PATH] = host_key + "\n"
    vm["files"][BOOT_FINISHED] = "2026-11-15T10:00:00+00:00 - v. 24.4\n"
    if start:
        vm["status"] = "running"


def destroy_vm(state: dict[str, Any], vmid: int) -> None:
    state["vms"].pop(str(vmid), None)


def set_config(state: dict[str, Any], vmid: int, **config: Any) -> None:
    state["vms"][str(vmid)]["config"].update(config)


# ----------------------------------------------------------------------------- the fake


class ProxmoxAnswer(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class FakeProxmox:
    """The handler and its knobs. ``install(monkeypatch)`` points ``proxmox.transport_factory`` at it."""

    def __init__(self, state_path: str | os.PathLike | None = None, **initial: Any) -> None:
        if state_path is None:
            state_path = Path(tempfile.mkdtemp(prefix="fake-pve-")) / "pve.json"
        self.path = Path(state_path)
        if not self.path.exists():
            save(self.path, initial_state(**initial))
        self.requests: list[dict[str, Any]] = []
        self.pems: list[str] = []   # the pinned certificate each transport was made for

    # ------------------------------------------------------------------ plumbing

    @property
    def state(self) -> dict[str, Any]:
        return load(self.path)

    @contextlib.contextmanager
    def edit(self) -> Iterator[dict[str, Any]]:
        with locked(self.path) as state:
            yield state

    def transport(self, pem: str | None = None) -> httpx.MockTransport:
        if pem is not None:
            self.pems.append(pem)
        return httpx.MockTransport(self.handle)

    def install(self, monkeypatch: Any) -> FakeProxmox:
        from slipway.services import proxmox

        monkeypatch.setattr(proxmox, "transport_factory", self.transport)
        return self

    def calls(self, method: str | None = None, path: str | None = None) -> list[dict[str, Any]]:
        return [r for r in self.requests
                if (method is None or r["method"] == method) and (path is None or r["path"] == path)]

    # --------------------------------------------------------------------- knobs

    def _knob(self, key: str, value: Any) -> None:
        with self.edit() as state:
            state["knobs"][key] = value

    def deny(self, path: str) -> None:
        """403 for every request whose path (after /api2/json) starts with ``path``."""
        with self.edit() as state:
            state["knobs"]["deny"].append(path)

    def task_fails(self, kind: str) -> None:
        with self.edit() as state:
            state["knobs"]["task_fails"].append(kind_of(kind))

    def task_hangs(self, kind: str) -> None:
        """Tasks of this kind never end."""
        with self.edit() as state:
            state["knobs"]["task_hangs"].append(kind_of(kind))

    def task_outlives_cancel(self, kind: str, n: int) -> None:
        """A task of this kind keeps running for ``n`` polls (longer than Slipway's wait in the test)."""
        with self.edit() as state:
            state["knobs"]["task_outlives_cancel"][kind_of(kind)] = int(n)

    def snapshot_task_late(self) -> None:
        """A snapshot task answers ``running`` to every status poll, so the wait times out; the
        snapshot is there at once, and the task ends at the next other request about the VM."""
        self._knob("snapshot_task_late", True)

    def agent_late(self, n: int) -> None:
        """The guest agent answers 500 for the next ``n`` agent requests."""
        self._knob("agent_late", int(n))

    def agent_wrong_address(self) -> None:
        self._knob("agent_wrong_address", True)

    def stale_template_key(self, n: int) -> None:
        """For ``n`` reads of the key file or boot-finished, the key file holds the template's key
        and boot-finished is missing."""
        self._knob("stale_template_key", int(n))

    def clone_lock_outlives(self, n: int) -> None:
        """The clone task (and its lock) stays for ``n`` polls after the clone call."""
        self._knob("clone_lock_outlives", int(n))

    def resize_refused_with_snapshots(self) -> None:
        """Growing a qcow2 disk of a VM with snapshots fails, as Proxmox does (fake Terraform reads it too)."""
        self._knob("resize_refused_with_snapshots", True)

    def slow(self, seconds: float) -> None:
        """Every answer comes after ``seconds`` (for the page-read timeout)."""
        self._knob("slow", float(seconds))

    def template_ciupgrade(self, on: bool | None) -> None:
        """``None`` leaves the option unset (Proxmox 8.1+ then upgrades)."""
        with self.edit() as state:
            config = state["vms"][str(TEMPLATE_VMID)]["config"]
            if on is None:
                config.pop("ciupgrade", None)
            else:
                config["ciupgrade"] = 1 if on else 0

    def add_vm(self, vmid: int, name: str, **kwargs: Any) -> None:
        with self.edit() as state:
            make_vm(state, vmid, name, **kwargs)

    def hidden(self, vmid: int, name: str = "someone-elses-vm") -> None:
        """A VM outside the token's pool at that id: invisible, but its id is taken."""
        with self.edit() as state:
            make_vm(state, vmid, name, pool=None, tags=("prod",))

    def reuse_vmid(self, vmid: int, name: str) -> None:
        """Someone else's VM (in the pool, no Slipway tags) now holds the id."""
        with self.edit() as state:
            state["vms"].pop(str(vmid), None)
            make_vm(state, vmid, name, tags=("web",), description="Not Slipway's")

    def remove_vm(self, vmid: int) -> None:
        with self.edit() as state:
            destroy_vm(state, vmid)

    def move_node(self, vmid: int, node: str | None = None) -> None:
        with self.edit() as state:
            vm = state["vms"][str(vmid)]
            vm["node"] = node or next(n for n in state["nodes"] if n != vm["node"])

    def untag(self, vmid: int) -> None:
        with self.edit() as state:
            state["vms"][str(vmid)]["tags"] = []

    def stale_lock(self, vmid: int, lock: str) -> None:
        """A lock with no task running (a task that died)."""
        with self.edit() as state:
            state["vms"][str(vmid)]["lock"] = lock

    def set_storage(self, **fields: Any) -> None:
        with self.edit() as state:
            next(iter(state["storages"].values())).update(fields)

    def set_privileges(self, path: str, privileges: list[str]) -> None:
        with self.edit() as state:
            state["privileges"][path] = list(privileges)

    def add_snapshot(self, vmid: int, name: str, description: str = "") -> None:
        with self.edit() as state:
            _add_snapshot(state["vms"][str(vmid)], name, description)

    def run_task(self, vmid: int, kind: str, *, polls: int | None = None, user: str = "root@pam") -> str:
        """Someone else's task running on the VM (``polls`` None: until the test ends it)."""
        with self.edit() as state:
            vm = state["vms"][str(vmid)]
            return start_task(state, vm["node"], kind, vmid, polls=polls, user=user)

    def vm(self, vmid: int) -> dict[str, Any] | None:
        return self.state["vms"].get(str(vmid))

    def task(self, upid: str) -> dict[str, Any]:
        return self.state["tasks"][upid]

    # ------------------------------------------------------------------- handler

    async def handle(self, request: httpx.Request) -> httpx.Response:
        state_now = self.state
        delay = float(state_now["knobs"].get("slow") or 0)
        if delay:
            await asyncio.sleep(delay)
        path = request.url.path
        prefix = "/api2/json"
        params = {k: v for k, v in request.url.params.items()}
        data = {k: v[-1] for k, v in parse_qs(request.content.decode() if request.content else "").items()}
        self.requests.append({"method": request.method, "path": path[len(prefix):] if path.startswith(prefix) else path,
                              "params": params, "data": data, "auth": request.headers.get("authorization")})
        if not path.startswith(prefix):
            return self._error(404, "no such path")
        rel = path[len(prefix):]
        # An error answer still keeps what the request changed (a tick, a knob counted down).
        with self.edit() as state:
            try:
                if request.headers.get("authorization") != f"PVEAPIToken={state['token']}":
                    raise ProxmoxAnswer(401, "authentication failure")
                for denied in state["knobs"]["deny"]:
                    if rel.startswith(denied):
                        raise ProxmoxAnswer(403, f"Permission check failed ({rel}, {UPSTREAM_MARK})")
                result = self._route(state, request.method, rel, params, data)
            except ProxmoxAnswer as answer:
                return self._error(answer.status, answer.message)
        return httpx.Response(200, json={"data": result})

    @staticmethod
    def _error(status: int, message: str) -> httpx.Response:
        # Proxmox puts its message in the status line and sometimes in "errors".
        return httpx.Response(status, json={"data": None, "message": f"{message} [{UPSTREAM_MARK}]",
                                            "errors": {"detail": UPSTREAM_MARK}})

    # ------------------------------------------------------------------- routes

    def _route(self, state: dict[str, Any], method: str, rel: str, params: dict, data: dict) -> Any:
        parts = [unquote(p) for p in rel.strip("/").split("/")]
        if method == "GET" and parts == ["version"]:
            return {"version": state["version"], "release": state["version"].rsplit(".", 1)[0], "repoid": "abc"}
        if method == "GET" and parts == ["nodes"]:
            return [{"node": n, "status": "online"} for n in state["nodes"]]
        if method == "GET" and parts == ["cluster", "nextid"]:
            return self._nextid(state, params)
        if method == "GET" and parts == ["cluster", "resources"]:
            return self._resources(state, params)
        if method == "GET" and parts[:1] == ["pools"]:
            return self._pools(state, parts, params)
        if method == "GET" and parts == ["access", "permissions"]:
            wanted = params.get("path")
            privs = state["privileges"]
            if wanted:
                return {wanted: {p: 1 for p in privs.get(wanted, [])}}
            return {path: {p: 1 for p in ps} for path, ps in privs.items()}
        if len(parts) >= 2 and parts[0] == "nodes":
            node = parts[1]
            if node not in state["nodes"]:
                raise ProxmoxAnswer(595, f"no such cluster node '{node}'")
            return self._node(state, method, node, parts[2:], params, data)
        raise ProxmoxAnswer(501, f"Method '{method} /{rel}' not implemented")

    def _nextid(self, state: dict[str, Any], params: dict) -> Any:
        if "vmid" in params:
            vmid = int(params["vmid"])
            if str(vmid) in state["vms"]:
                raise ProxmoxAnswer(400, f"Parameter verification failed. vmid: VM {vmid} already exists")
            return str(vmid)
        vmid = int(state["first_free"])
        while str(vmid) in state["vms"]:
            vmid += 1
        return str(vmid)

    def _visible(self, state: dict[str, Any], vm: dict[str, Any]) -> bool:
        return vm.get("pool") == state["pool"]

    def _resources(self, state: dict[str, Any], params: dict) -> list[dict[str, Any]]:
        if params.get("type") not in (None, "vm"):
            return []
        out = []
        for vm in state["vms"].values():
            if not self._visible(state, vm):
                continue
            entry = {"id": f"qemu/{vm['vmid']}", "type": "qemu", "vmid": vm["vmid"], "name": vm["name"],
                     "node": vm["node"], "status": vm["status"], "pool": vm["pool"],
                     "template": 1 if vm["template"] else 0, "maxmem": vm["config"].get("memory", 0) * 1024 ** 2}
            if vm["tags"]:
                entry["tags"] = ";".join(vm["tags"])
            if vm.get("lock"):
                entry["lock"] = vm["lock"]
            out.append(entry)
        return out

    def _pools(self, state: dict[str, Any], parts: list[str], params: dict) -> Any:
        members = [{"id": f"qemu/{vm['vmid']}", "type": "qemu", "vmid": vm["vmid"], "name": vm["name"]}
                   for vm in state["vms"].values() if vm.get("pool") == state["pool"]]
        members.append({"id": f"storage/{state['nodes'][0]}/{STORAGE}", "type": "storage", "storage": STORAGE})
        if len(parts) == 1:
            wanted = params.get("poolid")
            pools = [{"poolid": state["pool"], "members": members}]
            return [p for p in pools if wanted in (None, p["poolid"])]
        if parts[1] != state["pool"]:
            raise ProxmoxAnswer(500, f"pool '{parts[1]}' does not exist")
        return {"members": members}

    def _vm(self, state: dict[str, Any], node: str, vmid: str) -> dict[str, Any]:
        vm = state["vms"].get(str(int(vmid)))
        if vm is not None and not self._visible(state, vm):
            raise ProxmoxAnswer(403, f"Permission check failed (/vms/{vmid}, VM.Audit)")
        if vm is None or vm["node"] != node:
            raise ProxmoxAnswer(500, f"Configuration file 'nodes/{node}/qemu-server/{vmid}.conf' does not exist")
        return vm

    def _node(self, state: dict[str, Any], method: str, node: str, rest: list[str], params: dict, data: dict) -> Any:
        if method == "GET" and rest == ["storage"]:
            wanted = params.get("storage")
            return [{"storage": name, "type": s["type"], "content": s["content"], "active": s["active"],
                     "enabled": s["enabled"], "avail": s["avail"], "total": s["total"],
                     "used": s["total"] - s["avail"], "shared": 0}
                    for name, s in state["storages"].items() if wanted in (None, name)]
        if method == "GET" and len(rest) == 2 and rest[0] == "network":
            iface = state["bridges"].get(node, {}).get(rest[1])
            if iface is None:
                raise ProxmoxAnswer(400, f"interface '{rest[1]}' does not exist")
            return {"iface": rest[1], **iface, "active": 1}
        if method == "GET" and rest == ["tasks"]:
            vmid = params.get("vmid")
            if vmid is not None:
                tick(state, vmid)
            out = []
            for t in state["tasks"].values():
                if t["node"] != node or (vmid is not None and t["vmid"] != int(vmid)):
                    continue
                if params.get("source") == "active" and t["status"] != "running":
                    continue
                out.append({"upid": t["upid"], "type": t["type"], "id": str(t["vmid"]), "user": t["user"],
                            "starttime": t["starttime"], "node": t["node"],
                            **({"status": "running"} if t["status"] == "running" else
                               {"status": t["exitstatus"], "endtime": t["starttime"] + 1})})
            return out
        if method == "GET" and len(rest) == 3 and rest[0] == "tasks" and rest[2] == "status":
            task = state["tasks"].get(rest[1])
            if task is None or task["node"] != node:
                raise ProxmoxAnswer(500, f"no such task '{rest[1]}'")
            if not task.get("late"):
                tick(state, upid=task["upid"])
            out = {"upid": task["upid"], "status": task["status"], "type": task["type"], "node": node,
                   "id": str(task["vmid"]), "starttime": task["starttime"]}
            if task["status"] == "stopped":
                out["exitstatus"] = task["exitstatus"]
            return out
        if len(rest) >= 2 and rest[0] == "qemu":
            return self._qemu(state, method, node, rest[1], rest[2:], params, data)
        raise ProxmoxAnswer(501, f"Method '{method} /nodes/{node}/{'/'.join(rest)}' not implemented")

    def _qemu(self, state: dict[str, Any], method: str, node: str, vmid: str, rest: list[str],
              params: dict, data: dict) -> Any:
        if method == "POST" and rest == ["clone"]:
            template = self._vm(state, node, vmid)
            newid = int(data["newid"])
            if str(newid) in state["vms"]:
                raise ProxmoxAnswer(500, f"unable to create VM {newid}: config file already exists")
            if data.get("pool") not in (None, state["pool"]):
                raise ProxmoxAnswer(403, "Permission check failed (/pool, VM.Allocate)")
            return clone_vm(state, template["vmid"], newid, node=data.get("target") or node, name=data.get("name"),
                            description=data.get("description"), pool=data.get("pool"), storage=data.get("storage"))
        vm = self._vm(state, node, vmid)
        late = [t for t in state["tasks"].values() if t["vmid"] == vm["vmid"] and t.get("late") and t["status"] == "running"]
        if late and rest not in (["status", "current"],):
            for t in late:   # the late snapshot task ends at the next other request about the VM
                _finish(state, t)
        tick(state, vm["vmid"])
        vm = state["vms"].get(str(vm["vmid"]))
        if vm is None:
            raise ProxmoxAnswer(500, f"Configuration file 'nodes/{node}/qemu-server/{vmid}.conf' does not exist")
        if method == "DELETE" and rest == []:
            self._unlocked(vm)
            if vm["status"] == "running":
                raise ProxmoxAnswer(500, f"VM {vmid} is running - destroy failed")
            if params.get("purge") not in ("1", 1):
                raise ProxmoxAnswer(400, "fake: Slipway always purges")
            return start_task(state, node, "qmdestroy", vm["vmid"])
        if method == "GET" and rest == ["config"]:
            config = dict(vm["config"])
            if vm["template"]:
                config["template"] = 1
            config["name"] = vm["name"]
            if vm["description"]:
                config["description"] = vm["description"]
            if vm["tags"]:
                config["tags"] = ";".join(vm["tags"])
            if vm.get("lock"):
                config["lock"] = vm["lock"]
            config["digest"] = "0" * 40
            return config
        if method in ("POST", "PUT") and rest == ["config"]:
            self._unlocked(vm)
            if "tags" in data:
                vm["tags"] = sorted_tags(data.pop("tags"))
            if "description" in data:
                vm["description"] = data.pop("description")
            vm["config"].update(data)
            return None
        if method == "PUT" and rest == ["resize"]:
            self._unlocked(vm)
            storage = state["storages"].get(vm.get("storage") or "", {})
            qcow2 = storage.get("type") in FILE_STORAGES and storage.get("file_format") == "qcow2"
            if vm["snapshots"] and qcow2 and state["knobs"]["resize_refused_with_snapshots"]:
                raise ProxmoxAnswer(500, "can't resize volume: disk has snapshots")
            vm["config"]["scsi0"] = vm["config"]["scsi0"].rsplit("size=", 1)[0] + f"size={data.get('size')}"
            return None
        if method == "GET" and rest == ["status", "current"]:
            return {"vmid": vm["vmid"], "status": vm["status"], "name": vm["name"],
                    "qmpstatus": vm["status"], **({"lock": vm["lock"]} if vm.get("lock") else {})}
        if method == "POST" and len(rest) == 2 and rest[0] == "status":
            action = rest[1]
            if action not in ("start", "shutdown", "stop", "reboot"):
                raise ProxmoxAnswer(501, "no such action")
            self._unlocked(vm)
            if action == "start" and vm["template"]:
                raise ProxmoxAnswer(500, "you can't start a vm if it's a template")
            return start_task(state, node, f"qm{action}", vm["vmid"])
        if method == "GET" and rest == ["feature"]:
            storage = state["storages"].get(vm.get("storage") or "", {})
            kind = storage.get("type")
            if kind == "lvm":
                has = False
            elif kind in FILE_STORAGES:
                has = storage.get("file_format") == "qcow2"
            else:
                has = True
            return {"hasFeature": 1 if has else 0, "nodes": [node] if has else []}
        if rest[:1] == ["agent"]:
            return self._agent(state, vm, rest[1:], params)
        if rest[:1] == ["snapshot"]:
            return self._snapshot(state, node, vm, method, rest[1:], data)
        raise ProxmoxAnswer(501, f"Method '{method} …/qemu/{vmid}/{'/'.join(rest)}' not implemented")

    @staticmethod
    def _unlocked(vm: dict[str, Any]) -> None:
        if vm.get("lock"):
            raise ProxmoxAnswer(500, f"VM is locked ({vm['lock']})")

    def _agent(self, state: dict[str, Any], vm: dict[str, Any], rest: list[str], params: dict) -> Any:
        knobs = state["knobs"]
        if vm["status"] != "running" or not str(vm["config"].get("agent", "")).startswith(("1", "enabled=1")):
            raise ProxmoxAnswer(500, "QEMU guest agent is not running")
        if knobs["agent_late"] > 0:
            knobs["agent_late"] -= 1
            raise ProxmoxAnswer(500, "QEMU guest agent is not running")
        if rest == ["network-get-interfaces"]:
            address = vm.get("address")
            if address and knobs["agent_wrong_address"]:
                address = "10.99.99.99"
            ifaces = [
                {"name": "lo", "hardware-address": "00:00:00:00:00:00",
                 "ip-addresses": [{"ip-address-type": "ipv4", "ip-address": "127.0.0.1", "prefix": 8},
                                  {"ip-address-type": "ipv6", "ip-address": "::1", "prefix": 128}]},
                {"name": "eth0", "hardware-address": "bc:24:11:00:00:01",
                 "ip-addresses": ([{"ip-address-type": "ipv4", "ip-address": address, "prefix": 24}] if address else [])
                 + [{"ip-address-type": "ipv6", "ip-address": "fe80::be24:11ff:fe00:1", "prefix": 64},
                    {"ip-address-type": "ipv4", "ip-address": "169.254.10.20", "prefix": 16}]},
                {"name": "docker0", "ip-addresses": [{"ip-address-type": "ipv4", "ip-address": "172.17.0.1", "prefix": 16}]},
                {"name": "br-1a2b3c", "ip-addresses": [{"ip-address-type": "ipv4", "ip-address": "172.18.0.1", "prefix": 16}]},
                {"name": "veth12ab", "ip-addresses": [{"ip-address-type": "ipv4", "ip-address": "172.18.0.5", "prefix": 16}]},
            ]
            return {"result": ifaces}
        if rest == ["file-read"]:
            path = params.get("file", "")
            if path in (HOST_KEY_PATH, BOOT_FINISHED) and knobs["stale_template_key"] > 0:
                knobs["stale_template_key"] -= 1
                if path == HOST_KEY_PATH:
                    return {"content": TEMPLATE_KEY + "\n", "bytes": len(TEMPLATE_KEY) + 1}
                raise ProxmoxAnswer(500, f"guest-file-open: Failed to open file '{path}': No such file or directory")
            if path not in vm["files"]:
                raise ProxmoxAnswer(500, f"guest-file-open: Failed to open file '{path}': No such file or directory")
            content = vm["files"][path]
            return {"content": content, "bytes": len(content)}
        raise ProxmoxAnswer(501, "no such agent command")

    def _snapshot(self, state: dict[str, Any], node: str, vm: dict[str, Any], method: str,
                  rest: list[str], data: dict) -> Any:
        if method == "GET" and rest == []:
            out = [{"name": s["name"], "description": s["description"], "snaptime": s["snaptime"],
                    **({"parent": s["parent"]} if s.get("parent") else {}), "vmstate": 0}
                   for s in vm["snapshots"]]
            current = {"name": "current", "description": "You are here!", "running": 1 if vm["status"] == "running" else 0}
            if vm.get("current_parent"):
                current["parent"] = vm["current_parent"]
            return out + [current]
        if method == "POST" and rest == []:
            self._unlocked(vm)
            name = data.get("snapname", "")
            if any(s["name"] == name for s in vm["snapshots"]):
                raise ProxmoxAnswer(500, f"snapshot name '{name}' already used")
            if str(data.get("vmstate", "0")) not in ("0", ""):
                raise ProxmoxAnswer(400, "fake: Slipway takes disk-only snapshots")
            upid = start_task(state, node, "qmsnapshot", vm["vmid"],
                              {"name": name, "description": data.get("description", "")})
            if state["knobs"]["snapshot_task_late"]:
                task = state["tasks"][upid]
                task["late"] = True
                task["polls"] = None
                _add_snapshot(vm, name, data.get("description", ""))
            return upid
        if method == "POST" and len(rest) == 2 and rest[1] == "rollback":
            self._unlocked(vm)
            return start_task(state, node, "qmrollback", vm["vmid"], {"name": rest[0]})
        if method == "DELETE" and len(rest) == 1:
            self._unlocked(vm)
            if not any(s["name"] == rest[0] for s in vm["snapshots"]):
                raise ProxmoxAnswer(500, f"snapshot '{rest[0]}' does not exist")
            return start_task(state, node, "qmdelsnapshot", vm["vmid"], {"name": rest[0]})
        raise ProxmoxAnswer(501, "no such snapshot call")
