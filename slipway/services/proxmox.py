"""The Proxmox VE API client, ported from Sirdar's ``deploy/proxmox.py``.

Terraform makes and destroys Slipway's Proxmox VMs (``terraform.py``); everything else Slipway
reads or does on Proxmox goes through this module: VM ids, finding a VM and checking its markers,
power, the guest agent (the VM's address and SSH host key), VM snapshots, running tasks, the
storage's snapshot ability, and the account's Test.

Rules every call keeps:

* Every request carries ``Authorization: PVEAPIToken=<token>`` and goes through a transport that
  trusts the account's pinned certificate and nothing else, with host names checked
  (``tls_pin.pinned_context``). Tests swap ``transport_factory`` for an ``httpx.MockTransport``, as
  ``switchyard.py`` does; the hypervisor guard makes the real one fail in tests.
* Every failure is a ``ProxmoxError`` (a ``MachineError``) carrying Slipway's own sentence. Proxmox's
  own error text is never passed on: it can hold paths and task logs, and it is rarely something a
  person can act on. The token is never put in an error or a log line.
* Calls that start a Proxmox task (start, shutdown, delete, snapshot, rollback) return the task's
  UPID without waiting, so the caller can record it before it waits (M5); ``wait`` follows it.
* Methods about one VM take the node explicitly: an existing machine uses the node frozen in its
  ``spec``, never the account's current one.

``clean_config`` (the account form's rules) and ``run_test`` (the account's Test) live here too, so
the accounts service needs only this module.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, TypeVar
from urllib.parse import quote, urlsplit

import httpx

from slipway.services import tls_pin, vmnet
from slipway.services.vmtypes import AccountInvalid, Check, MachineError, status_of

DEFAULT_PORT = 8006
TIMEOUT = 30.0          # seconds per call (§14)
PAGE_TIMEOUT = 5.0      # a read made for a page gives up after this, overall (§7.1)
TASK_POLL = 2.0         # seconds between task status reads
TASK_TIMEOUT = 600      # other tasks 10 minutes (§14); the clone runs inside Terraform's apply

TLS_CHANGED = (
    "Proxmox's certificate isn't the one Slipway trusts. If it was renewed on purpose, "
    "trust the new one in Settings → Integrations."
)
MALFORMED = "Proxmox answered in a way Slipway doesn't understand."
NOT_NEWEST = "Proxmox can roll back only to the newest VM snapshot on this storage (ZFS)."

# Interfaces whose addresses aren't the VM's own: loopback and Docker's bridges and veth pairs.
_SKIPPED_IFACES = ("docker", "br-", "veth")
_BRIDGE_TYPES = ("bridge", "OVSBridge")
_GB = 1024 ** 3

# What the token needs on /pool/<pool> (§13.3's role). Proxmox 9 split VM.Monitor into the two
# VM.GuestAgent privileges; Proxmox 8 has only VM.Monitor. Sys.Audit (reading the node's network)
# is optional: without it the bridge check is a warning.
_ROLE_COMMON = (
    "VM.Allocate", "VM.Clone", "VM.Audit", "VM.PowerMgmt", "VM.Config.CDROM", "VM.Config.CPU",
    "VM.Config.Cloudinit", "VM.Config.Disk", "VM.Config.HWType", "VM.Config.Memory",
    "VM.Config.Network", "VM.Config.Options", "VM.Snapshot", "VM.Snapshot.Rollback",
    "Datastore.AllocateSpace", "Datastore.Audit", "SDN.Use", "Pool.Audit",
)
ROLE_PVE9 = _ROLE_COMMON + ("VM.GuestAgent.Audit", "VM.GuestAgent.FileRead")
ROLE_PVE8 = _ROLE_COMMON + ("VM.Monitor",)

# What bpg/proxmox 0.115.0's clone call (vmCreateClone → POST /nodes/{node}/qemu/{template}/clone)
# carries of a VM's markers: name, description and pool, each only when set. Tags are not in it;
# they come in the UpdateVM call after the clone's lock is released. So a Terraform killed between
# the two leaves a clone with the name, description and pool but no tags, which the provider's
# _our_clone recognises (§7.4). Test 7 pins this.
CLONE_CALL_CARRIES = ("name", "description", "pool")

# Storage types whose disks Slipway writes as qcow2, so they can take VM snapshots (§7.2).
FILE_STORAGES = ("dir", "nfs", "cifs", "glusterfs")

T = TypeVar("T")


class ProxmoxError(MachineError):
    """A Proxmox call failed. ``text`` is Slipway's sentence; ``status`` the HTTP status, if any."""

    def __init__(self, text: str, status: int | None = None, *, unreachable: bool = False) -> None:
        super().__init__(text, unreachable=unreachable)
        self.status = status


class AgentNotReady(ProxmoxError):
    """The VM's guest agent didn't answer (still booting, VM off, or the agent isn't installed)."""


class TaskTimeout(ProxmoxError):
    """A task was still running when ``wait`` gave up. It may still finish (D24): don't assume it failed."""

    def __init__(self, text: str, upid: str) -> None:
        super().__init__(text)
        self.upid = upid


class TaskFailed(ProxmoxError):
    """A task ended with an error."""

    def __init__(self, text: str, upid: str) -> None:
        super().__init__(text)
        self.upid = upid


# ------------------------------------------------------------------------ transport


def pinned_transport(pem: str) -> httpx.AsyncBaseTransport:
    """A transport that trusts only the pinned certificate, host names checked (D16)."""
    return httpx.AsyncHTTPTransport(verify=tls_pin.pinned_context(pem))


# Tests swap this for one returning an httpx.MockTransport; the guard makes the real one raise.
transport_factory: Callable[[str], httpx.AsyncBaseTransport] = pinned_transport


# ---------------------------------------------------------------------------- helpers


def split_url(url: str) -> tuple[str, int]:
    parts = urlsplit(url)
    return parts.hostname or "", parts.port or DEFAULT_PORT


def parse_upid(upid: str) -> dict[str, str]:
    """``UPID:<node>:<pid>:<pstart>:<starttime>:<type>:<id>:<user>:`` → its parts.

    ``starttime`` is hex seconds since the epoch. Raises ValueError for anything else.
    """
    parts = str(upid).split(":")
    if len(parts) < 8 or parts[0] != "UPID" or not parts[1]:
        raise ValueError("not a UPID")
    return {"node": parts[1], "pid": parts[2], "pstart": parts[3], "starttime": parts[4],
            "type": parts[5], "id": parts[6], "user": parts[7]}


def _tags(value: Any) -> tuple[str, ...]:
    """Proxmox's tag string (``;``, ``,`` or space separated) as a sorted tuple, as Proxmox stores them."""
    if isinstance(value, (list, tuple)):
        items = [str(t) for t in value]
    else:
        items = re.split(r"[;, ]+", str(value or ""))
    return tuple(sorted({t.strip() for t in items if t and t.strip()}))


def _list(data: Any) -> list:
    if data is None:
        return []
    if not isinstance(data, list):
        raise TypeError("expected a list")
    return data


def _dict(data: Any) -> dict:
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise TypeError("expected an object")
    return data


def _duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 120:
        return f"{seconds} second{'' if seconds == 1 else 's'}"
    return f"{seconds // 60} minutes"


def _reason(status: int, what: str) -> str:
    if status == 401:
        return "Proxmox refused the API token. Check it in Settings → Integrations."
    if status == 403:
        return f"The API token isn't allowed to {what}. Check its privileges (see docs/machines.md)."
    if status == 404:
        return f"Proxmox couldn't {what}: it doesn't have what Slipway asked for (HTTP 404)."
    return f"Proxmox couldn't {what} (HTTP {status})."


def _version_tuple(version: str) -> tuple[int, int]:
    match = re.match(r"(\d+)(?:\.(\d+))?", str(version or ""))
    if not match:
        return (0, 0)
    return int(match.group(1)), int(match.group(2) or 0)


def _flag(value: Any) -> bool:
    """A Proxmox boolean option (``1``, ``"1"``, ``"enabled=1,fstrim_cloned_disks=1"``…)."""
    text = str(value if value is not None else "").strip()
    if not text:
        return False
    first = text.split(",", 1)[0]
    if "=" in first:
        return bool(re.search(r"(?:^|,)enabled=1(?:,|$)", text))
    return first in ("1", "true", "on", "yes")


# ----------------------------------------------------------------------------- client


class ProxmoxClient:
    """One account's API. Use as ``async with ProxmoxClient.for_account(account) as api:``."""

    def __init__(self, url: str, token: str, pem: str, *, timeout: float = TIMEOUT,
                 transport: httpx.AsyncBaseTransport | None = None,
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
                 task_poll: float = TASK_POLL, task_timeout: float = TASK_TIMEOUT) -> None:
        self.url = endpoint(url)
        host, port = split_url(self.url)
        self._where = f"{host}:{port}"
        self._sleep = sleep
        self._poll = task_poll
        self._task_timeout = task_timeout
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            base_url=f"{self.url}/api2/json",
            headers={"Authorization": f"PVEAPIToken={token}", "User-Agent": "Slipway"},
            timeout=httpx.Timeout(timeout, connect=min(10.0, timeout)),
            transport=transport if transport is not None else transport_factory(pem),
            follow_redirects=False,
        )

    @classmethod
    def for_account(cls, account: Any, *, page: bool = False, **kwargs: Any) -> ProxmoxClient:
        """The client for a ``provider_accounts`` row (anything with ``name``, ``config``, ``secret``, ``tls``).

        ``page=True`` gives the 5-second timeout reads made for a page use. Refuses an account with
        no token or no pinned certificate (§6.3 step 1).
        """
        name = getattr(account, "name", None) or "the Proxmox account"
        config = getattr(account, "config", None) or {}
        token = getattr(account, "secret", None)
        pem = (getattr(account, "tls", None) or {}).get("pem")
        why = None
        if not config.get("url"):
            why = "it has no URL"
        elif not token:
            why = "its API token is missing or can't be read with SLIPWAY_ENCRYPTION_KEY"
        elif not pem:
            why = "no certificate is trusted for it yet"
        if why:
            raise ProxmoxError(f"Proxmox account {name} can't be used: {why}. "
                               "Fix it in Settings → Integrations, then retry.")
        if page:
            kwargs.setdefault("timeout", PAGE_TIMEOUT)
        return cls(config["url"], token, pem, **kwargs)

    async def __aenter__(self) -> ProxmoxClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    # ---------------------------------------------------------------- plumbing

    async def _call(self, method: str, path: str, what: str, *, params: dict | None = None,
                    data: dict | None = None, agent: bool = False) -> Any:
        try:
            resp = await self._client.request(method, path, params=params, data=data)
        except httpx.TimeoutException:
            raise ProxmoxError(f"Proxmox at {self._where} didn't answer in {_duration(self.timeout)} "
                               f"(trying to {what}).", unreachable=True) from None
        except httpx.HTTPError as exc:
            if tls_pin.pin_refused(exc):
                raise ProxmoxError(TLS_CHANGED, unreachable=True) from None
            raise ProxmoxError(f"Slipway couldn't reach Proxmox at {self._where}.", unreachable=True) from None
        if resp.status_code >= 400:
            # The guest agent answers 500 while the VM boots, is off, or has no agent.
            if agent and resp.status_code == 500:
                raise AgentNotReady("The VM's guest agent isn't answering yet.", 500)
            raise ProxmoxError(_reason(resp.status_code, what), resp.status_code)
        try:
            return resp.json()["data"]
        except (ValueError, KeyError, TypeError):
            raise ProxmoxError(MALFORMED) from None

    async def _read(self, read: Callable[[], Awaitable[T]]) -> T:
        """Runs a read and turns a payload of the wrong shape into MALFORMED, never a crash."""
        try:
            return await read()
        except ProxmoxError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError):
            raise ProxmoxError(MALFORMED) from None

    @staticmethod
    def _vm(node: str, vmid: int) -> str:
        return f"/nodes/{quote(str(node), safe='')}/qemu/{int(vmid)}"

    @staticmethod
    def _node(node: str) -> str:
        return f"/nodes/{quote(str(node), safe='')}"

    @staticmethod
    def _upid(value: Any, what: str) -> str:
        if not isinstance(value, str) or not value.startswith("UPID:"):
            raise ProxmoxError(f"Proxmox didn't return a task id (trying to {what}), so Slipway can't follow it.")
        return value

    # ------------------------------------------------------------------- reads

    async def version(self) -> str:
        async def read() -> str:
            data = await self._call("GET", "/version", "read its version")
            return str(_dict(data).get("version", ""))
        return await self._read(read)

    async def nodes(self) -> list[str]:
        async def read() -> list[str]:
            data = await self._call("GET", "/nodes", "list the nodes")
            return [str(n["node"]) for n in _list(data)]
        return await self._read(read)

    async def next_vmid(self) -> int:
        async def read() -> int:
            return int(await self._call("GET", "/cluster/nextid", "find a free VM id"))
        return await self._read(read)

    async def vmid_free(self, vmid: int) -> bool:
        """Whether no VM or container anywhere in the cluster has id ``vmid`` (D25).

        ``GET /cluster/nextid?vmid=`` answers for every id, whatever the token can see: the id back
        when it is free, 400 when it is taken.
        """
        async def read() -> bool:
            try:
                data = await self._call("GET", "/cluster/nextid", "check a VM id", params={"vmid": int(vmid)})
            except ProxmoxError as exc:
                if exc.status == 400:
                    return False
                raise
            return int(data) == int(vmid)
        return await self._read(read)

    async def pool_members(self, pool: str) -> set[int]:
        """The VM ids in ``pool``. ``GET /pools?poolid=`` (Proxmox 8.1+), else the older ``/pools/{id}``."""
        async def read() -> set[int]:
            try:
                data = await self._call("GET", "/pools", "read the pool", params={"poolid": pool})
                found = [p for p in _list(data) if p.get("poolid") == pool]
                if not found:
                    raise ProxmoxError(f"Proxmox has no pool named {pool} that the token can see.", 404)
                members = found[0].get("members") or []
            except ProxmoxError as exc:
                if exc.status not in (400, 501):
                    raise
                data = await self._call("GET", f"/pools/{quote(pool, safe='')}", "read the pool")
                members = _dict(data).get("members") or []
            return {int(m["vmid"]) for m in _list(members) if m.get("vmid") is not None}
        return await self._read(read)

    async def find_vm(self, vmid: int) -> dict[str, Any] | None:
        """VM ``vmid`` on whichever node holds it, or None when the token can't see one there.

        ``GET /cluster/resources?type=vm`` lists only VMs the token may audit (its pool): a None
        here isn't proof the id is free, ``vmid_free`` tells (D25). The answer is
        ``{vmid, name, node, status, tags, pool, template, lock}``, tags sorted as Proxmox stores them.
        """
        async def read() -> dict[str, Any] | None:
            data = await self._call("GET", "/cluster/resources", "list the cluster's VMs", params={"type": "vm"})
            for v in _list(data):
                if v.get("type", "qemu") != "qemu" or v.get("vmid") is None or int(v["vmid"]) != int(vmid):
                    continue
                return {
                    "vmid": int(v["vmid"]),
                    "name": str(v.get("name") or ""),
                    "node": str(v.get("node") or ""),
                    "status": str(v.get("status") or ""),
                    "tags": _tags(v.get("tags")),
                    "pool": str(v.get("pool") or "") or None,
                    "template": bool(v.get("template")),
                    "lock": str(v.get("lock") or "") or None,
                }
            return None
        return await self._read(read)

    async def vm_config(self, node: str, vmid: int) -> dict[str, Any]:
        """The VM's settings as Proxmox keeps them (``lock``, ``description``, ``tags``, ``ciupgrade``…)."""
        async def read() -> dict[str, Any]:
            return _dict(await self._call("GET", f"{self._vm(node, vmid)}/config", "read the VM's settings"))
        return await self._read(read)

    async def status(self, node: str, vmid: int) -> str:
        """``running``, ``stopped`` (Proxmox's word for off) or ``suspended``… as Proxmox says."""
        async def read() -> str:
            data = await self._call("GET", f"{self._vm(node, vmid)}/status/current", "read the VM's state")
            return str(_dict(data).get("status", ""))
        return await self._read(read)

    async def storage_info(self, node: str, storage: str) -> dict[str, Any] | None:
        """The storage as ``node`` sees it, or None when the token can't see one by that name.

        ``GET /nodes/{node}/storage?storage=`` needs only Datastore.Audit, unlike ``GET /storage/{id}``.
        """
        async def read() -> dict[str, Any] | None:
            data = await self._call("GET", f"{self._node(node)}/storage", "read the storage",
                                    params={"storage": storage})
            for s in _list(data):
                if str(s.get("storage")) == storage:
                    return {
                        "storage": storage,
                        "type": str(s.get("type") or ""),
                        "content": sorted(c for c in str(s.get("content") or "").split(",") if c),
                        "active": bool(s.get("active", 1)),
                        "enabled": bool(s.get("enabled", 1)),
                        "avail": int(s.get("avail") or 0),
                        "total": int(s.get("total") or 0),
                    }
            return None
        return await self._read(read)

    async def bridge(self, node: str, name: str) -> dict[str, Any]:
        async def read() -> dict[str, Any]:
            path = f"{self._node(node)}/network/{quote(name, safe='')}"
            return _dict(await self._call("GET", path, "read the node's network bridge"))
        return await self._read(read)

    async def permissions(self, path: str) -> set[str]:
        """The token's privileges on ``path`` (its effective ones: with privilege separation, the
        intersection of the user's and the token's)."""
        async def read() -> set[str]:
            data = _dict(await self._call("GET", "/access/permissions", "read its own privileges",
                                          params={"path": path}))
            privs = _dict(data.get(path))
            return {str(k) for k, v in privs.items() if v}
        return await self._read(read)

    async def vm_tasks(self, node: str, vmid: int) -> list[dict[str, Any]]:
        """Tasks still running on the VM, anyone's (D24): ``[{upid, type, user, starttime}]``."""
        async def read() -> list[dict[str, Any]]:
            data = await self._call("GET", f"{self._node(node)}/tasks", "list the node's running tasks",
                                    params={"vmid": int(vmid), "source": "active"})
            found = []
            for t in _list(data):
                # source=active lists running tasks; an entry with an end time has just finished.
                if t.get("endtime") or (t.get("status") and t.get("status") != "running"):
                    continue
                found.append({"upid": str(t.get("upid") or ""), "type": str(t.get("type") or ""),
                              "user": str(t.get("user") or ""), "starttime": int(t.get("starttime") or 0)})
            return found
        return await self._read(read)

    async def snapshot_feature(self, node: str, vmid: int) -> bool:
        """Whether the VM's disks can take snapshots (D23), as Proxmox's own feature check says."""
        async def read() -> bool:
            data = await self._call("GET", f"{self._vm(node, vmid)}/feature", "check the VM's snapshot support",
                                    params={"feature": "snapshot"})
            return bool(int(_dict(data).get("hasFeature") or 0))
        return await self._read(read)

    async def snapshots(self, node: str, vmid: int) -> list[dict[str, Any]]:
        """The VM's snapshots, without Proxmox's ``current`` entry: ``[{name, parent, description, snaptime, newest}]``.

        ``newest`` marks the most recent one (by its time; without times, the one ``current`` grows
        from). ZFS rolls back only to that one (D23).
        """
        async def read() -> list[dict[str, Any]]:
            data = _list(await self._call("GET", f"{self._vm(node, vmid)}/snapshot", "list the VM snapshots"))
            current_parent = None
            found: list[dict[str, Any]] = []
            for s in data:
                name = str(s["name"])
                if name == "current":
                    current_parent = str(s.get("parent") or "") or None
                    continue
                found.append({"name": name, "parent": str(s.get("parent") or "") or None,
                              "description": str(s.get("description") or ""),
                              "snaptime": int(s["snaptime"]) if s.get("snaptime") is not None else None,
                              "newest": False})
            if found:
                timed = [s for s in found if s["snaptime"] is not None]
                if timed:
                    newest = max(timed, key=lambda s: s["snaptime"])
                else:
                    newest = next((s for s in found if s["name"] == current_parent), found[-1])
                newest["newest"] = True
            return found
        return await self._read(read)

    async def agent_ipv4(self, node: str, vmid: int) -> list[str]:
        """The VM's IPv4 addresses in the agent's order, without loopback, Docker's own interfaces
        (``docker*``, ``br-*``, ``veth*``) and link-local addresses."""
        async def read() -> list[str]:
            data = await self._call("GET", f"{self._vm(node, vmid)}/agent/network-get-interfaces",
                                    "ask the guest agent for the VM's addresses", agent=True)
            found: list[str] = []
            for iface in _list(_dict(data).get("result") or []):
                name = str(iface.get("name", ""))
                if name == "lo" or name.startswith(_SKIPPED_IFACES):
                    continue
                for addr in _list(iface.get("ip-addresses") or []):
                    if addr.get("ip-address-type") != "ipv4":
                        continue
                    try:
                        ip = ipaddress.IPv4Address(str(addr.get("ip-address", "")))
                    except ValueError:
                        continue
                    if ip.is_link_local or ip.is_loopback or str(ip) in found:
                        continue
                    found.append(str(ip))
            return found
        return await self._read(read)

    async def agent_file(self, node: str, vmid: int, path: str) -> str:
        """A file's text read through the guest agent (``file-read``). AgentNotReady while it can't."""
        async def read() -> str:
            data = await self._call("GET", f"{self._vm(node, vmid)}/agent/file-read",
                                    "read a file through the guest agent", params={"file": path}, agent=True)
            return str(_dict(data)["content"])
        return await self._read(read)

    # ------------------------------------------------------------- task starts

    async def start(self, node: str, vmid: int) -> str:
        return self._upid(await self._call("POST", f"{self._vm(node, vmid)}/status/start", "start the VM"),
                          "start the VM")

    async def shutdown(self, node: str, vmid: int, *, timeout: int = 300) -> str:
        """A clean shutdown through ACPI or the agent; Proxmox gives up after ``timeout`` seconds."""
        upid = await self._call("POST", f"{self._vm(node, vmid)}/status/shutdown", "shut the VM down",
                                data={"timeout": int(timeout)})
        return self._upid(upid, "shut the VM down")

    async def delete_vm(self, node: str, vmid: int) -> str:
        """Deletes the VM with its disks, and drops it from the pool, backup jobs and replication."""
        upid = await self._call("DELETE", self._vm(node, vmid), "delete the VM",
                                params={"purge": 1, "destroy-unreferenced-disks": 1})
        return self._upid(upid, "delete the VM")

    async def take_snapshot(self, node: str, vmid: int, name: str, description: str = "") -> str:
        """A disk-only snapshot (``vmstate=0``: no RAM, so a revert boots the VM afresh)."""
        upid = await self._call("POST", f"{self._vm(node, vmid)}/snapshot", "take a VM snapshot",
                                data={"snapname": name, "description": description, "vmstate": 0})
        return self._upid(upid, "take a VM snapshot")

    async def rollback(self, node: str, vmid: int, name: str) -> str:
        path = f"{self._vm(node, vmid)}/snapshot/{quote(name, safe='')}/rollback"
        return self._upid(await self._call("POST", path, "revert to the VM snapshot"), "revert to the VM snapshot")

    async def delete_snapshot(self, node: str, vmid: int, name: str) -> str:
        path = f"{self._vm(node, vmid)}/snapshot/{quote(name, safe='')}"
        return self._upid(await self._call("DELETE", path, "delete a VM snapshot"), "delete a VM snapshot")

    async def task_status(self, upid: str) -> dict[str, Any]:
        """``{status: running|stopped, exitstatus}`` of one task."""
        async def read() -> dict[str, Any]:
            node = parse_upid(upid)["node"]
            path = f"{self._node(node)}/tasks/{quote(upid, safe='')}/status"
            return _dict(await self._call("GET", path, "follow a task"))
        return await self._read(read)

    async def wait(self, upid: str, what: str, *, timeout: float | None = None) -> None:
        """Until task ``upid`` stops. Exit status ``OK`` or ``WARNINGS: n`` passes; anything else is
        TaskFailed, and still running after ``timeout`` is TaskTimeout (the task may yet finish)."""
        try:
            parse_upid(upid)
        except ValueError:
            raise ProxmoxError(f"Proxmox didn't return a task id (trying to {what}), so Slipway can't follow it.") from None
        limit = self._task_timeout if timeout is None else timeout
        deadline = time.monotonic() + limit
        while True:
            data = await self.task_status(upid)
            if data.get("status") == "stopped":
                exit_status = str(data.get("exitstatus") or "")
                if exit_status == "OK" or exit_status.startswith("WARNINGS"):
                    return
                if "is not most recent snapshot" in exit_status:
                    raise TaskFailed(NOT_NEWEST, upid)
                raise TaskFailed(f"Proxmox couldn't {what}: its task ended with an error. "
                                 f"See task {upid} in Proxmox's task log.", upid)
            if time.monotonic() >= deadline:
                raise TaskTimeout(f"Proxmox didn't finish ({what}) in {_duration(limit)}; "
                                  f"task {upid} may still be running.", upid)
            await self._sleep(self._poll)


# ------------------------------------------------------------------------ page reads


@dataclass
class PageRead:
    value: Any = None
    error: str | None = None   # MachineState.error / live.error when the read failed


async def page_read(read: Callable[[], Awaitable[T]], *, limit: float | None = None) -> PageRead:
    """Runs a read for a page under an overall limit (5 s), answering the error text instead of raising.

    The client's own 5-second timeout bounds each request; this bounds the whole read, which may
    make several.
    """
    limit = PAGE_TIMEOUT if limit is None else limit
    try:
        return PageRead(value=await asyncio.wait_for(read(), limit))
    except TimeoutError:
        return PageRead(error=f"Proxmox didn't answer in {_duration(limit)}.")
    except MachineError as exc:
        return PageRead(error=exc.text)


# ------------------------------------------------------------------------- config


_URL_RE = re.compile(r"https://([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\])(?::([0-9]{1,5}))?")
_NODE_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_POOL_RE = re.compile(r"[A-Za-z0-9_.-]{1,40}")
_STORAGE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,62}")
# user@realm!tokenid=<uuid>. The user is anything Proxmox allows (printable, no ':', '/', '!', '@'
# and here no '='), the realm [A-Za-z0-9._-], the token id starts with a letter. The uuid is the secret.
_TOKEN_RE = re.compile(
    r"((?:(?![:/!@=])[!-~]){1,64}@[A-Za-z0-9._-]{1,32}![A-Za-z][A-Za-z0-9._-]{0,63})="
    r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
)


def token_parts(token: str) -> tuple[str, str]:
    """``(token id, secret)`` of ``user@realm!tokenid=<uuid>``; ValueError for anything else."""
    match = _TOKEN_RE.fullmatch(str(token or "").strip())
    if not match:
        raise ValueError("not a Proxmox API token")
    return match.group(1), match.group(2)


def clean_url(value: Any) -> str:
    """``https://host:port``; a URL without a port gets Proxmox's own, 8006.

    The port is written into the stored URL so the certificate Slipway shows and pins, the API client and
    Terraform's endpoint all name the same port (a bare ``https://host`` would otherwise be pinned on :8006
    but called on :443).
    """
    url = str(value or "").strip().rstrip("/")
    match = _URL_RE.fullmatch(url)
    if not match or (match.group(2) is not None and not 1 <= int(match.group(2)) <= 65535):
        raise AccountInvalid("url", "The URL must be https://host or https://host:port, such as "
                                    "https://pve.example.lan:8006, with no path.")
    if match.group(2) is None:
        url = f"{url}:{DEFAULT_PORT}"
    return url


def endpoint(value: Any) -> str:
    """The URL Slipway calls: ``clean_url``'s, so a row stored as ``https://host`` before the port was written in
    is called on 8006, where its certificate was pinned (F41); a URL ``clean_url`` refuses is used as it is."""
    try:
        return clean_url(value)
    except AccountInvalid:
        return str(value or "").strip().rstrip("/")


def _text(config: dict, key: str, regex: re.Pattern, label: str) -> str:
    value = str(config.get(key) or "").strip()
    if not regex.fullmatch(value):
        raise AccountInvalid(key, f"{label} isn't a name Proxmox allows.")
    return value


def _int_in(value: Any, low: int, high: int) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    if not isinstance(value, int) or not low <= value <= high:
        return None
    return value


def clean_config(config: Any, secret: str | None) -> dict[str, Any]:
    """The account form's Proxmox fields, checked and tidied; AccountInvalid(field, text) for the first bad one.

    Keeps ``url``, ``node``, ``pool``, ``storage``, ``template_vmid`` and ``networks`` (1-20, names
    unique, each by ``vmnet.check_network_profile``); other keys are dropped. ``secret`` is the whole
    token when one was typed: its format is checked and its id part becomes ``token_id``. With no secret (the stored one kept) ``token_id`` is left out, for the
    accounts service to carry over; whether a secret is required is the accounts service's rule.
    """
    if not isinstance(config, dict):
        raise AccountInvalid("config", "The Proxmox settings must be an object.")
    out: dict[str, Any] = {
        "url": clean_url(config.get("url")),
        "node": _text(config, "node", _NODE_RE, "The node"),
        "pool": _text(config, "pool", _POOL_RE, "The pool"),
        "storage": _text(config, "storage", _STORAGE_RE, "The storage"),
    }
    template = _int_in(config.get("template_vmid"), 100, 999_999_999)
    if template is None:
        raise AccountInvalid("template_vmid", "The template's VM id must be a number from 100 to 999999999.")
    out["template_vmid"] = template
    networks = config.get("networks")
    if not isinstance(networks, list) or not networks:
        raise AccountInvalid("networks", "Add at least one network for Slipway's VMs.")
    # §3.1's rules for each network (subnet, gateway, DNS, pool, bridge and VLAN), names unique.
    out["networks"] = vmnet.check_networks(networks, provider="proxmox")
    if secret not in (None, ""):
        try:
            out["token_id"] = token_parts(str(secret))[0]
        except ValueError:
            raise AccountInvalid("secret", "The API token must look like user@realm!tokenid=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx "
                                           "(Datacenter → Permissions → API Tokens shows the secret once).") from None
    return out


def redactions(secret: str | None) -> list[str]:
    """What a job's redactor hides for this account: the whole token and its secret part (D17)."""
    if not secret:
        return []
    out = [secret]
    try:
        out.append(token_parts(secret)[1])
    except ValueError:
        pass
    return out


# --------------------------------------------------------------------------- Test


@dataclass
class TestResult:
    """An account's Test: its checks, the facts it read (``provider_accounts.facts``) and the status."""

    checks: list[Check]
    facts: dict[str, Any] = field(default_factory=dict)

    __test__ = False  # not a pytest class, despite the name

    @property
    def status(self) -> str:
        return status_of(self.checks)


def _bridges(networks: Iterable[dict]) -> list[tuple[str, list[int]]]:
    found: dict[str, list[int]] = {}
    for n in networks or []:
        name = str(n.get("bridge") or "")
        if not name:
            continue
        vlans = found.setdefault(name, [])
        if n.get("vlan_tag") and int(n["vlan_tag"]) not in vlans:
            vlans.append(int(n["vlan_tag"]))
    return list(found.items())


async def run_test(account: Any, *, client: ProxmoxClient | None = None) -> TestResult:
    """Reads only: the version, then one check each for the node, the pool, the template, the storage,
    each network's bridge and the token's privileges (§7.1). A check that can't be read fails alone;
    an API that can't be reached at all is one failed check."""
    config = getattr(account, "config", None) or {}
    node = str(config.get("node") or "")
    pool = str(config.get("pool") or "")
    storage = str(config.get("storage") or "")
    template_vmid = int(config.get("template_vmid") or 0)
    checks: list[Check] = []
    facts: dict[str, Any] = {}
    try:
        api = client or ProxmoxClient.for_account(account)
    except MachineError as exc:
        return TestResult([Check.failed("Proxmox", exc.text)])
    async with api:
        try:
            version = await api.version()
        except MachineError as exc:
            return TestResult([Check.failed("Proxmox", exc.text)])
        facts["version"] = version
        checks.append(Check.passed("Proxmox", f"Proxmox VE {version}"))
        major_minor = _version_tuple(version)

        async def node_check() -> Check:
            names = await api.nodes()
            if node in names:
                return Check.passed("Node", node)
            return Check.failed("Node", f"No node named {node} (Proxmox has {', '.join(names) or 'none the token can see'}).")

        async def pool_check() -> Check:
            members = await api.pool_members(pool)
            return Check.passed("Pool", f"{pool} · {len(members)} VM{'' if len(members) == 1 else 's'}")

        async def template_check() -> list[Check]:
            found = await api.find_vm(template_vmid)
            if found is None:
                return [Check.failed("Template", f"VM {template_vmid} isn't visible to the token. Is it in the {pool} pool?")]
            label = f"{found['name'] or 'VM'} ({template_vmid})"
            if not found["template"]:
                return [Check.failed("Template", f"VM {template_vmid} ({found['name']}) isn't a template. "
                                                 "Convert it with \"qm template\" first.")]
            cfg = await api.vm_config(found["node"], template_vmid)
            out: list[Check] = []
            if _flag(cfg.get("agent")):
                out.append(Check.passed("Template", label))
            else:
                out.append(Check.warning("Template", f"{label}: its guest agent option is off. Slipway turns it on "
                                                     "in each VM, but the template should have it on too."))
            # Proxmox 8.1 added ciupgrade, on unless set to 0; older versions never upgrade at first boot.
            raw = cfg.get("ciupgrade")
            upgrades = _flag(raw) if raw is not None else major_minor >= (8, 1)
            facts["template_ciupgrade"] = upgrades
            if upgrades:
                out.append(Check.warning(
                    "Template upgrades",
                    f"The template upgrades every package at first boot (ciupgrade 1); set "
                    f"\"qm set {template_vmid} --ciupgrade 0\" so a new VM's first boot takes a predictable time"))
            return out

        async def storage_check() -> Check:
            info = await api.storage_info(node, storage)
            if info is None:
                return Check.failed("Storage", f"Node {node} has no storage named {storage} that the token can see.")
            facts["storage_type"] = info["type"]
            facts["storage_content"] = info["content"]
            facts["free_gb"] = round(info["avail"] / _GB, 1)
            if not info["active"] or not info["enabled"]:
                return Check.failed("Storage", f"{storage} isn't active on {node}.")
            if "images" not in info["content"]:
                return Check.failed("Storage", f"{storage} can't hold VM disks (its content doesn't include Disk image).")
            summary = f"{storage} ({info['type']}) · {facts['free_gb']:.0f} GB free"
            if info["type"] == "lvm":
                return Check.warning("Storage", f"{storage} is thick LVM: Slipway's VMs there can't have VM snapshots")
            if info["type"] == "zfspool":
                return Check.note("Storage", f"{summary}. ZFS rolls back only to the newest VM snapshot")
            return Check.passed("Storage", summary)

        async def bridge_check(name: str, vlans: list[int]) -> Check:
            label = f"Bridge {name}"
            try:
                iface = await api.bridge(node, name)
            except ProxmoxError as exc:
                if exc.status == 403:
                    return Check.warning(label, f"{name}: Slipway can't check it (the token has no Sys.Audit on "
                                                f"/nodes/{node}, which is optional).")
                if exc.status in (400, 404, 500):
                    return Check.failed(label, f"Node {node} has no bridge named {name}.")
                raise
            if iface.get("type") not in _BRIDGE_TYPES:
                return Check.failed(label, f"{name} on {node} isn't a bridge.")
            suffix = f" · VLAN {', '.join(str(v) for v in vlans)}" if vlans else ""
            return Check.passed(label, f"{name}{suffix}")

        async def privileges_check() -> Check:
            role = ROLE_PVE9 if major_minor >= (9, 0) else ROLE_PVE8
            have = await api.permissions(f"/pool/{pool}")
            missing = [p for p in role if p not in have]
            if missing:
                return Check.failed("Privileges", f"The token lacks {', '.join(missing)} on /pool/{pool}. "
                                                  "Give it the role in docs/machines.md.")
            return Check.passed("Privileges", f"The token has the role's privileges on /pool/{pool}")

        steps: list[tuple[str, Callable[[], Awaitable[Check | list[Check]]]]] = [
            ("Node", node_check), ("Pool", pool_check), ("Template", template_check), ("Storage", storage_check),
        ]
        for name, vlans in _bridges(config.get("networks") or []):
            steps.append((f"Bridge {name}", lambda name=name, vlans=vlans: bridge_check(name, vlans)))
        steps.append(("Privileges", privileges_check))
        for label, step in steps:
            try:
                result = await step()
            except MachineError as exc:
                result = Check.failed(label, exc.text)
            except (KeyError, TypeError, ValueError, AttributeError):
                result = Check.failed(label, MALFORMED)
            checks.extend(result if isinstance(result, list) else [result])
    return TestResult(checks, facts)


run_test.__test__ = False  # type: ignore[attr-defined]
