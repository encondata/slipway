"""The Proxmox provider of the machines core (phase 5 §7.4-§7.7, §9.11).

``ProxmoxProvider`` makes, checks, resizes, snapshots and removes Slipway's Proxmox VMs. Terraform (the bundled
``proxmox-vm`` module, ``terraform.session``) makes, resizes and destroys a VM; everything else goes through the
API client (``proxmox.ProxmoxClient``): finding a VM and checking its markers, power, the guest agent (the VM's
address and SSH host key), VM snapshots and running tasks. The machines core (``machines.py``) drives it: it pins
the key the provider read, sets up Docker and marks the VM ready.

Rules every method keeps:

* A VM is Slipway's only when its name is the machine's, its tags hold ``slipway`` and ``env-<environment id>``
  and it is on the node frozen in ``machines.spec`` (D20, M2). A half-made clone without its tags yet is
  recognised by its name, node, pool and description (``_our_clone``), only before the VM is ready.
* Every id Slipway uses is recorded before Terraform runs (``machines.reserve_vmid``), and every task Slipway
  starts is in ``machines.last_task`` before Slipway waits on it (M5). A task someone else runs on the VM is
  waited for (``machines.tasks.wait_idle``), never stopped (D24).
* A ready VM is never made again (M3): a gone one answers the lost text. ``nextid?vmid=`` tells a gone id from
  one the token can't see (D25).
* Terraform deletes only Slipway's own half-made VM, or in Remove (M6).
* Every stage change goes through ``machines.set_stage``, so the host's phase moves in the same transaction
  (Decision 6). Errors are ``MachineError`` with Slipway's own sentence, never Proxmox's text or the token.

``MODULE_DIR`` and the wait limits below are module attributes so tests can point them elsewhere.
"""

from __future__ import annotations

import math
import re
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from typing import Any, ClassVar

import asyncssh
from sqlalchemy import select

from slipway.core.config import get_settings
from slipway.db.session import get_sessionmaker, session_scope
from slipway.models import (
    Deployment,
    DeploymentStatus,
    Instance,
    MachineSnapshot,
    MachineStage,
    ProviderAccount,
    Resource,
    SnapshotMode,
    TerraformState,
)
from slipway.services import machines, proxmox, resources, ssh, terraform, terraform_store, vmnet
from slipway.services.machines import Busy, Ensured, MachineContext, MachineState, ResizePlan, SnapshotView
from slipway.services.vmtypes import Blocker, Check, MachineError

# The bundled module Terraform runs (tests point this at a copy with a fake-mirror lock file, Decision 36).
MODULE_DIR = terraform.MODULE_DIR

HOW = "read through the Proxmox guest agent"
BOOT_FINISHED = "/var/lib/cloud/instance/boot-finished"
HOST_KEY_FILE = "/etc/ssh/ssh_host_ed25519_key.pub"

# Waits, in seconds; each is counted in polls of ``ctx.sleep``, so a test with a no-op sleep doesn't wait.
POLL = 5.0
ADDRESS_WAIT = 300.0  # the guest agent reports the static address (§7.4 C6, PR3)
BOOT_WAIT = 600.0  # cloud-init's boot-finished can be read (C7)
KEY_WAIT = 300.0  # the VM's own host key can be read (C8)
SHUTDOWN_SECONDS = 300  # what Proxmox's shutdown is given (§7.5 step 2)
LATE_GRACE = 15.0  # after a snapshot task timed out or failed, before the snapshots are listed (§7.6)
# How long Slipway follows each kind of task it starts (Proxmox's own wait is in the client; §14: 10 minutes).
TASK_TIMEOUTS: dict[str, float] = {
    "start": 600.0, "shutdown": SHUTDOWN_SECONDS + 60.0, "delete": 600.0, "snapshot": 600.0, "rollback": 600.0,
    "delsnapshot": 600.0,
}
# The attributes a resize plan may change (§7.5 step 1); ``started`` because the VM may be off.
SIZE_ATTRIBUTES = frozenset({"cpu", "memory", "disk", "started"})
GROWPART_SLACK = 2  # GB a root file system may be under ``disk_gb - 2`` before the warning
DF_COMMAND = "df -BG --output=size / | tail -1"


def _minutes(seconds: float) -> str:
    minutes = max(1, math.ceil(seconds / 60))
    return f"{minutes} minute" if minutes == 1 else f"{minutes} minutes"


def _polls(limit: float) -> int:
    return max(1, math.ceil(limit / POLL)) if POLL > 0 else max(1, int(limit))


def _disk_gb(spec: str | None) -> int | None:
    """The size of a Proxmox disk line (``local-lvm:vm-105-disk-0,size=64G``) in GB."""
    match = re.search(r"size=(\d+(?:\.\d+)?)([KMGT]?)", spec or "")
    if not match:
        return None
    value, unit = float(match.group(1)), match.group(2) or "G"
    factor = {"K": 1 / 1024 ** 2, "M": 1 / 1024, "G": 1, "T": 1024}[unit]
    return int(round(value * factor))


def applied_of(config: dict[str, Any]) -> dict[str, int] | None:
    """``{cores, memory_mb, disk_gb}`` from the VM's Proxmox settings, or None when they can't be read."""
    try:
        disk = _disk_gb(str(config.get("scsi0") or ""))
        if disk is None:
            return None
        return {"cores": int(config["cores"]), "memory_mb": int(config["memory"]), "disk_gb": disk}
    except (KeyError, TypeError, ValueError):
        return None


def snapshot_mode_of(has_feature: bool, storage_type: str | None) -> str:
    """D23: no snapshot feature, ``none``; ZFS rolls back only to the newest; anything else, ``any``."""
    if not has_feature:
        return SnapshotMode.NONE.value
    if storage_type == "zfspool":
        return SnapshotMode.NEWEST_ONLY.value
    return SnapshotMode.ANY.value


def _when(epoch: int | None) -> datetime | None:
    if not epoch:
        return None
    try:
        return datetime.fromtimestamp(int(epoch), tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


class ProxmoxProvider:
    """The ``MachineProvider`` for Proxmox VE (§6.1)."""

    name: ClassVar[str] = "proxmox"
    label: ClassVar[str] = "Proxmox"

    # ------------------------------------------------------------------------------------ account side

    def clean_config(self, config: dict[str, Any], secret: str | None) -> dict[str, Any]:
        return proxmox.clean_config(config, secret)

    async def test(self, account: ProviderAccount) -> list[Check]:
        """Not used for accounts (Decision 34): the accounts service calls ``proxmox.run_test`` itself."""
        return (await proxmox.run_test(account)).checks

    def freeze(self, account: ProviderAccount, network: dict[str, Any]) -> dict[str, Any]:
        """``machines.spec`` at create: where the VM goes, frozen from the account and its network (§3.2)."""
        config = account.config or {}
        storage_type = (account.facts or {}).get("storage_type") or None
        return {
            "node": config.get("node"), "pool": config.get("pool"), "storage": config.get("storage"),
            "storage_type": storage_type, "file_format": terraform.file_format_for(storage_type),
            "template_vmid": config.get("template_vmid"), "bridge": network.get("bridge"),
            "vlan_tag": network.get("vlan_tag"),
        }

    # ------------------------------------------------------------------------------------------ plumbing

    def _client(self, ctx: MachineContext) -> proxmox.ProxmoxClient:
        for value in proxmox.redactions(ctx.account.secret):
            ctx.hide.add(value)
        return proxmox.ProxmoxClient.for_account(ctx.account, sleep=ctx.sleep)

    @staticmethod
    def _vmid(ctx: MachineContext) -> int | None:
        value = (ctx.machine.ids or {}).get("vmid")
        return int(value) if value is not None else None

    @staticmethod
    def _node(ctx: MachineContext) -> str:
        return str((ctx.machine.spec or {}).get("node") or "")

    @staticmethod
    def _pool(ctx: MachineContext) -> str:
        return str((ctx.machine.spec or {}).get("pool") or "")

    @staticmethod
    def _tags(ctx: MachineContext) -> tuple[str, ...]:
        return tuple(terraform.vm_tags(ctx.env.id))

    def _verdict(self, ctx: MachineContext, found: dict[str, Any]) -> str:
        """``ours`` (name, both tags, the frozen node), ``moved`` (ours on another node) or ``foreign``."""
        if found.get("name") != ctx.machine.name or not set(self._tags(ctx)) <= set(found.get("tags") or ()):
            return "foreign"
        return "ours" if found.get("node") == self._node(ctx) else "moved"

    def _moved_text(self, ctx: MachineContext, found: dict[str, Any]) -> str:
        return (f"VM {found['vmid']} ({found.get('name')}) is on node {found.get('node')} now, not {self._node(ctx)}. "
                "Slipway changed nothing: move it back, or fix it by hand, then retry")

    async def _our_clone(self, ctx: MachineContext, api: proxmox.ProxmoxClient, found: dict[str, Any]) -> bool:
        """Slipway's own half-made clone, which may not have its tags yet (§7.4): the name, the node, the pool,
        the tags none or exactly Slipway's, the description empty or naming this environment's id."""
        if found.get("name") != ctx.machine.name or found.get("node") != self._node(ctx):
            return False
        if (found.get("pool") or "") != self._pool(ctx):
            return False
        if tuple(found.get("tags") or ()) not in ((), self._tags(ctx)):
            return False
        try:
            config = await api.vm_config(found["node"], found["vmid"])
        except proxmox.ProxmoxError as exc:
            if exc.unreachable:
                raise
            return False
        description = str(config.get("description") or "")
        return not description.strip() or str(ctx.env.id) in description

    async def _running(self, ctx: MachineContext, api: proxmox.ProxmoxClient, vmid: int | None = None) -> list[Busy]:
        """The tasks running on the VM, anyone's, and its lock (§6.8). A lock with no task is a dead task's."""
        vmid = vmid if vmid is not None else self._vmid(ctx)
        node = self._node(ctx)
        if vmid is None or not node:
            return []
        where = f"VM {vmid}"

        def busy_of(items: list[dict[str, Any]]) -> list[Busy]:
            return [Busy(kind=t["type"] or "a task", where=where, started_at=_when(t.get("starttime")),
                         task_id=t["upid"], vmid=vmid) for t in items]

        busy = busy_of(await api.vm_tasks(node, vmid))
        lock = None
        try:
            lock = (await api.vm_config(node, vmid)).get("lock") or None
        except proxmox.ProxmoxError as exc:
            if exc.unreachable or exc.status not in (403, 404, 500):
                raise
        if lock and not busy:
            busy = busy_of(await api.vm_tasks(node, vmid))  # a task that started meanwhile holds the lock
            if not busy:
                busy = [Busy(kind=str(lock), where=where, lock=str(lock), vmid=vmid)]
        return busy

    async def running(self, ctx: MachineContext) -> list[Busy]:
        async with self._client(ctx) as api:
            return await self._running(ctx, api)

    async def _wait_idle(self, ctx: MachineContext, api: proxmox.ProxmoxClient, vmid: int | None = None) -> None:
        await machines.tasks.wait_idle(ctx, read=lambda: self._running(ctx, api, vmid), limit=machines.TASK_WAIT_LIMIT,
                                       poll=machines.TASK_POLL)

    async def _task(self, ctx: MachineContext, api: proxmox.ProxmoxClient, kind: str, what: str,
                    start: Callable[[], Awaitable[str]]) -> None:
        """Start a task, record it in ``last_task`` (its own transaction), then wait for it (M5). A task that
        outlives the wait stays in ``last_task``, so the next change waits for it (D24)."""
        upid = await start()
        await machines.tasks.started(ctx, upid, kind)
        try:
            await api.wait(upid, what, timeout=TASK_TIMEOUTS.get(kind, proxmox.TASK_TIMEOUT))
        except proxmox.TaskTimeout:
            raise
        except proxmox.TaskFailed:
            await machines.tasks.ended(ctx)
            raise
        await machines.tasks.ended(ctx)

    async def _start(self, ctx: MachineContext, api: proxmox.ProxmoxClient, vmid: int) -> None:
        await self._wait_idle(ctx, api, vmid)
        await ctx.say(f"Starting {ctx.vm} (VM {vmid})")
        await self._task(ctx, api, "start", f"start {ctx.vm}", lambda: api.start(self._node(ctx), vmid))

    @asynccontextmanager
    async def _session(
        self, ctx: MachineContext, vmid: int, size: dict[str, Any],
    ) -> AsyncIterator[terraform.Terraform]:
        if ctx.deployment_id is None:
            raise MachineError(f"Slipway runs Terraform for {ctx.vm} only inside a job; it changed nothing")
        machine, account = ctx.machine, ctx.account
        variables = terraform.tfvars(
            endpoint=proxmox.endpoint((account.config or {}).get("url")), name=machine.name, environment_id=ctx.env.id,
            environment_name=ctx.env.name, slot=machine.slot, spec=machine.spec, network=machine.network,
            size=size, vmid=vmid, ssh_public_key=ctx.host.public_key or "",
        )
        async with terraform.session(
            machine_id=machine.id, vm_name=machine.name, deployment_id=ctx.deployment_id, store=terraform_store,
            settings=terraform.TerraformSettings.from_config(get_settings()), variables=variables,
            ca_pem=(account.tls or {}).get("pem") or "", token=account.secret or "", say=ctx.say, hide=ctx.hide,
            module_dir=MODULE_DIR,
        ) as tf:
            yield tf

    @staticmethod
    def _made_size(resource: terraform.StateResource | None) -> dict[str, int] | None:
        """The size a VM the state holds (and Terraform made, not a tainted create) was made at, or None."""
        if resource is None or resource.tainted:
            return None
        attrs = resource.attributes or {}
        try:
            return {"cores": int(attrs["cpu"][0]["cores"]), "memory_mb": int(attrs["memory"][0]["dedicated"]),
                    "disk_gb": int(attrs["disk"][0]["size"])}
        except (KeyError, IndexError, TypeError, ValueError):
            return None

    async def _stored_resource(self, ctx: MachineContext) -> terraform.StateResource | None:
        """The VM as the database's Terraform state holds it (read only, no session)."""
        stored = await terraform_store.load(ctx.machine.id)
        return terraform.state_resource(stored.state)

    # ------------------------------------------------------------------------------------- ready checks

    async def _made_vm(self, ctx: MachineContext, api: proxmox.ProxmoxClient) -> dict[str, Any]:
        """The made VM, checked (§7.4 PR1): visible, Slipway's, on its node. Raises with nothing changed."""
        vmid = self._vmid(ctx)
        if vmid is None:
            raise MachineError(f"Slipway never made {ctx.vm}")
        found = await api.find_vm(vmid)
        if found is None:
            if await api.vmid_free(vmid):
                raise MachineError(machines.lost_text(ctx.machine, env=ctx.env))
            raise MachineError(
                f"Slipway can't see VM {vmid} on {ctx.account.name}: the token may have lost its rights on "
                f"/pool/{self._pool(ctx)}, or the VM was moved out of the pool. Slipway changed nothing"
            )
        verdict = self._verdict(ctx, found)
        if verdict == "moved":
            raise MachineError(self._moved_text(ctx, found))
        if verdict != "ours":
            raise MachineError(f"VM {vmid} on Proxmox isn't {ctx.vm} any more; Slipway changed nothing")
        return found

    async def _wait_address(self, ctx: MachineContext, api: proxmox.ProxmoxClient, vmid: int, *,
                            made: bool) -> str | None:
        """Wait until the guest agent reports the VM's static address (PR3, C6). Another address only is the
        cloud-init text. An agent that never answers is a warning for a made VM (SSH is the real check), and an
        error for a new one, whose key comes through the agent. Returns the warning, if any."""
        address = ctx.machine.network["address"]
        seen: list[str] = []
        answered = False
        for attempt in range(_polls(ADDRESS_WAIT)):
            try:
                found = await api.agent_ipv4(self._node(ctx), vmid)
            except proxmox.AgentNotReady:
                found = None
            if found is not None:
                answered = True
                if address in found:
                    return None
                seen = found
            if attempt + 1 < _polls(ADDRESS_WAIT):
                await ctx.sleep(POLL)
        if answered:
            raise MachineError(f"{ctx.vm} came up at {', '.join(seen) or 'no address'}, not {address}. Check the "
                               "template's cloud-init settings")
        if made:
            note = f"{ctx.vm}'s guest agent didn't answer in {_minutes(ADDRESS_WAIT)}; carrying on over SSH"
            await ctx.say(note)
            return note
        raise MachineError(f"{ctx.vm}'s guest agent didn't report an address in {_minutes(ADDRESS_WAIT)}. Check that "
                           "the template has qemu-guest-agent installed and its agent option on")

    # --------------------------------------------------------------------------------------------- ensure

    async def ensure(self, ctx: MachineContext) -> Ensured:
        """Make, continue or check the VM (§7.4); never resizes and never stops a made VM."""
        async with self._client(ctx) as api:
            if ctx.machine.stage == MachineStage.READY:
                return await self._ensure_ready(ctx, api)
            return await self._ensure_new(ctx, api)

    async def _ensure_ready(self, ctx: MachineContext, api: proxmox.ProxmoxClient) -> Ensured:
        found = await self._made_vm(ctx, api)  # PR1
        vmid = int(found["vmid"])
        if found.get("status") != "running":  # PR2
            await self._start(ctx, api, vmid)
        warnings = []
        warning = await self._wait_address(ctx, api, vmid, made=True)  # PR3
        if warning:
            warnings.append(warning)
        expected = ctx.host.host_key or ctx.machine.host_key_public or ""
        return Ensured(address=ctx.machine.network["address"], expected_key=expected, how=HOW, reread_key=None,
                       warnings=warnings)

    async def _forget_vmid(self, ctx: MachineContext, vmid: int, *, why: str, audit_text: str | None) -> None:
        """Forget the reserved id (its ``vm`` row and ``ids.vmid``), so ``reserve_vmid`` takes another (C3)."""
        provider_id = f"{ctx.account.id}:{vmid}"
        async with get_sessionmaker()() as db:
            rows = list(await db.scalars(select(Resource).where(
                Resource.provider == ctx.machine.provider, Resource.kind == machines.VM_KIND,
                Resource.provider_id == provider_id,
            )))
        actor = await machines._user(ctx.user_id)
        for row in rows:
            if (row.details or {}).get("machine_id") == str(ctx.machine.id):
                await resources.forget(row.id, actor=actor)
        ids = {k: v for k, v in (ctx.machine.ids or {}).items() if k != "vmid"}
        if audit_text:
            await machines.write(ctx, ids=ids, audit_action="machine.rebuild", summary=audit_text,
                                 details={"name": ctx.vm, "vmid": vmid, "why": why})
        else:
            await machines.write(ctx, ids=ids)

    async def _ensure_new(self, ctx: MachineContext, api: proxmox.ProxmoxClient) -> Ensured:
        """Stage planned, creating or booting: C1-C9."""
        # C1: the address, unless the VM there is already this machine's own.
        own = False
        vmid = self._vmid(ctx)
        if vmid is not None:
            found = await api.find_vm(vmid)
            own = found is not None and (self._verdict(ctx, found) == "ours" or await self._our_clone(ctx, api, found))
        await machines.check_address_free(ctx, probe=not own)

        for _round in range(machines.RESERVE_TRIES):
            vmid = self._vmid(ctx)
            if vmid is None:  # C2
                vmid = await machines.reserve_vmid(ctx.machine, ctx.account, api=api, user_id=ctx.user_id)
                await ctx.say(f"Reserved VM id {vmid} for {ctx.vm}")
            # A VM Terraform made already is planned at the size it was made at, so the plan is no change and a
            # size stored meanwhile waits for the resize step once the VM is ready (§7.4 C4).
            size = self._made_size(await self._stored_resource(ctx)) or ctx.machine.size
            async with self._session(ctx, vmid, size) as tf:  # C3: lock, PID check, reconcile
                outcome = await self._identify(ctx, api, tf, vmid)
                if outcome == "again":
                    continue
                if (self._made_size(tf.resource()) or machines._sizes(ctx.machine.size)) != machines._sizes(size):
                    continue  # the state changed under the session's size (dropped, or saved by an earlier run)
                await self._make(ctx, tf, vmid, replace_ok=outcome == "tainted")  # C4, C5
            break
        else:
            raise MachineError(f"Slipway couldn't find a VM id for {ctx.vm} that no other VM uses; it changed nothing")

        if ctx.machine.stage != MachineStage.BOOTING:  # C6
            await machines.set_stage(ctx, MachineStage.BOOTING.value)
        found = await api.find_vm(vmid)
        if found is not None and found.get("status") != "running":
            await self._start(ctx, api, vmid)
        await self._wait_address(ctx, api, vmid, made=False)
        await self._wait_boot_finished(ctx, api, vmid)  # C7
        key = await self._wait_key(ctx, api, vmid)  # C8
        if key != ctx.machine.host_key_public:
            await machines.write(ctx, host_key_public=key)

        async def reread() -> str:
            return await self._reread_key(ctx, vmid)

        return Ensured(address=ctx.machine.network["address"], expected_key=key, how=HOW, reread_key=reread)  # C9

    async def _identify(self, ctx: MachineContext, api: proxmox.ProxmoxClient, tf: terraform.Terraform,
                        vmid: int) -> str:
        """C3: whose VM the reserved id names, against whether the state holds the resource. Returns ``make``,
        ``tainted`` (the state's resource is our failed create: the replace is allowed) or ``again`` (the id was
        forgotten: reserve another). Refusals change nothing."""
        await self._wait_idle(ctx, api, vmid)  # a clone outlives a killed Terraform (D24)
        found = await api.find_vm(vmid)
        resource = tf.resource()
        if resource is not None:
            if found is not None:
                verdict = self._verdict(ctx, found)
                if verdict == "moved":
                    raise MachineError(self._moved_text(ctx, found))
                if verdict == "ours" or (resource.tainted and await self._our_clone(ctx, api, found)):
                    if resource.tainted:
                        await machines.write(
                            ctx, audit_action="machine.rebuild",
                            summary=(f"Replacing the half-made {ctx.vm} (VM {vmid}) that an earlier create left "
                                     "unfinished"),
                            details={"name": ctx.vm, "vmid": vmid, "why": "Terraform's earlier create failed part way"},
                        )
                        return "tainted"
                    if found.get("status") != "running":  # made, not yet booted: start it
                        await self._start(ctx, api, vmid)
                    return "make"
                raise MachineError(f"VM {vmid} on Proxmox isn't the {ctx.vm} Slipway made. Slipway changed nothing: "
                                   "remove or rename that VM, or delete this environment")
            if await api.vmid_free(vmid):
                await ctx.say(f"VM {vmid} is gone from Proxmox; Slipway makes {ctx.vm} again")
                await tf.state_rm()
                await machines.write(ctx, audit_action="machine.rebuild",
                                     summary=f"{ctx.vm} (VM {vmid}) was gone before it was ready; making it again",
                                     details={"name": ctx.vm, "vmid": vmid, "why": "gone before it was ready"})
                return "make"
            raise MachineError(f"Slipway can't see VM {vmid} (check the token's rights on /pool/{self._pool(ctx)}); "
                               "Slipway changed nothing")

        if found is not None:
            verdict = self._verdict(ctx, found)
            if verdict == "moved":
                raise MachineError(self._moved_text(ctx, found))
            if verdict == "ours" or await self._our_clone(ctx, api, found):
                text = f"Removed the half-made {ctx.vm} (VM {vmid}) from an earlier attempt"
                await self._delete_vm(ctx, api, vmid, found)
                await machines.write(ctx, audit_action="machine.rebuild", summary=text,
                                     details={"name": ctx.vm, "vmid": vmid,
                                              "why": "a half-made VM Terraform's state doesn't hold"})
                await ctx.say(text)
                return "make"
            text = f"VM {vmid} is someone else's now; reserving another id"
            await ctx.say(text)
            await self._forget_vmid(ctx, vmid, why="someone else's VM holds the id", audit_text=text)
            return "again"
        if await api.vmid_free(vmid):
            return "make"
        await ctx.say(f"VM id {vmid} is used by a VM Slipway can't see; reserving another")
        await self._forget_vmid(ctx, vmid, why="a VM Slipway can't see holds the id", audit_text=None)
        return "again"

    async def _make(self, ctx: MachineContext, tf: terraform.Terraform, vmid: int, *, replace_ok: bool) -> None:
        """C4 and C5: the plan must only make the VM (or replace our failed create), then apply it."""
        changes = await tf.plan()
        if not changes:  # made already (an earlier apply whose stage change never ran)
            return
        change = changes[0]
        allowed = len(changes) == 1 and change.address == terraform.VM_ADDRESS and (
            change.is_create or (replace_ok and change.is_replace)
        )
        if not allowed:
            actions = ", ".join(f"{c.address}: {'+'.join(c.actions)}" for c in changes)
            raise MachineError(f"Terraform's plan for {ctx.vm} does more than make it ({actions}), so Slipway applied "
                               "nothing")
        if ctx.machine.stage != MachineStage.CREATING:
            await machines.set_stage(ctx, MachineStage.CREATING.value)
        if ctx.host.host_key:  # pinned to a VM made earlier (gone, half-made or re-reserved): this one has a new key
            await machines.unpin(ctx, f"{ctx.vm} is made again with a new host key")
        await ctx.say(f"Making {ctx.vm} (VM {vmid}) on {ctx.account.name}")
        try:
            await tf.apply()
        except terraform.TerraformFailed:
            raise MachineError(f"Terraform couldn't make {ctx.vm}. See the log above.") from None
        await machines.write(ctx, audit_action="machine.create",
                             summary=f"Made {ctx.vm} (VM {vmid}) on {ctx.account.name}",
                             details={"name": ctx.vm, "ids": {"vmid": vmid}, "node": self._node(ctx)})

    async def _wait_boot_finished(self, ctx: MachineContext, api: proxmox.ProxmoxClient, vmid: int) -> None:
        """C7: cloud-init's ``cc_ssh`` makes the host keys after the address is set, so the key is read only once
        ``boot-finished`` can be read."""
        tries = _polls(BOOT_WAIT)
        for attempt in range(tries):
            try:
                await api.agent_file(self._node(ctx), vmid, BOOT_FINISHED)
                return
            except proxmox.AgentNotReady:
                pass
            if attempt + 1 < tries:
                await ctx.sleep(POLL)
        raise MachineError(f"cloud-init didn't finish on {ctx.vm} in {_minutes(BOOT_WAIT)} (read through the guest "
                           "agent)")

    @staticmethod
    def _parse_key(text: str) -> str:
        try:
            key = asyncssh.import_public_key(text.strip())
        except (asyncssh.KeyImportError, ValueError, TypeError):
            raise MachineError(
                "The VM's SSH host key, read through its guest agent, isn't a key Slipway can use"
            ) from None
        return key.export_public_key("openssh").decode().strip()

    async def _wait_key(self, ctx: MachineContext, api: proxmox.ProxmoxClient, vmid: int) -> str:
        """C8: the VM's own ed25519 host key, read through the guest agent."""
        tries = _polls(KEY_WAIT)
        for attempt in range(tries):
            try:
                return self._parse_key(await api.agent_file(self._node(ctx), vmid, HOST_KEY_FILE))
            except proxmox.AgentNotReady:
                pass
            if attempt + 1 < tries:
                await ctx.sleep(POLL)
        raise MachineError(f"Slipway couldn't read {ctx.vm}'s SSH host key through its guest agent in "
                           f"{_minutes(KEY_WAIT)}")

    async def _reread_key(self, ctx: MachineContext, vmid: int) -> str:
        """The key read once more while pinning (§6.4): a template's old key cloud-init hadn't replaced yet."""
        async with self._client(ctx) as api:
            try:
                return self._parse_key(await api.agent_file(self._node(ctx), vmid, HOST_KEY_FILE))
            except proxmox.AgentNotReady:
                return ctx.machine.host_key_public or ""

    async def _delete_vm(
        self, ctx: MachineContext, api: proxmox.ProxmoxClient, vmid: int, found: dict[str, Any],
    ) -> None:
        """Delete Slipway's own VM through the API (a half-made clone, or a VM not in the state): a clean shutdown
        first when it runs, then the delete, each after the VM's tasks are done."""
        node = self._node(ctx)
        await self._wait_idle(ctx, api, vmid)
        if found.get("status") == "running" or await api.status(node, vmid) == "running":
            await self._task(ctx, api, "shutdown", f"shut {ctx.vm} down",
                             lambda: api.shutdown(node, vmid, timeout=SHUTDOWN_SECONDS))
            await self._wait_idle(ctx, api, vmid)
        await self._task(ctx, api, "delete", f"delete VM {vmid}", lambda: api.delete_vm(node, vmid))

    async def after_pin(self, ctx: MachineContext) -> None:
        """Nothing on Proxmox: the key was read, not generated, so there is nothing to scrub."""

    # ------------------------------------------------------------------------------------------- describe

    async def describe(self, ctx: MachineContext) -> MachineState:
        """What Proxmox has for the VM now (reads only)."""
        vmid = self._vmid(ctx)
        if vmid is None:
            return MachineState(exists=False, ours=False, why_not_ours=f"Slipway never made {ctx.vm}")
        async with self._client(ctx) as api:
            found = await api.find_vm(vmid)
            if found is None:
                hidden = not await api.vmid_free(vmid)
                why = (f"Slipway can't see VM {vmid} (check the token's rights on /pool/{self._pool(ctx)})" if hidden
                       else f"VM {vmid} is gone from {ctx.account.name}")
                return MachineState(exists=False, ours=False, why_not_ours=why, hidden=hidden)
            verdict = self._verdict(ctx, found)
            if verdict != "ours":
                why = (self._moved_text(ctx, found) if verdict == "moved"
                       else f"VM {vmid} on Proxmox isn't {ctx.vm} any more")
                return MachineState(exists=True, ours=False, why_not_ours=why, power=found.get("status") or None)
            node = self._node(ctx)
            config = await api.vm_config(node, vmid)
            busy = await self._running(ctx, api, vmid)
            storage_type = (ctx.machine.spec or {}).get("storage_type")
            mode = snapshot_mode_of(await api.snapshot_feature(node, vmid), storage_type)
            listed = await api.snapshots(node, vmid)
            addresses: list[str] = []
            if found.get("status") == "running":
                with suppress(proxmox.AgentNotReady):
                    addresses = await api.agent_ipv4(node, vmid)
        async with get_sessionmaker()() as db:
            recorded = set(await db.scalars(
                select(MachineSnapshot.name).where(MachineSnapshot.machine_id == ctx.machine.id)
            ))
        snapshots = [SnapshotView(name=s["name"], id=s["name"], created=_when(s.get("snaptime")),
                                  ours=s["name"] in recorded, newest=bool(s.get("newest"))) for s in listed]
        task = busy[0] if busy else None
        busy_text = None
        if task is not None:
            when = task.started_at.strftime("%H:%M") if task.started_at else "earlier"
            busy_text = f"{task.kind} (started {when})" if task.task_id else f"locked ({task.lock})"
        return MachineState(
            exists=True, ours=True, power=found.get("status") or None, busy=busy_text, addresses=addresses,
            applied=applied_of(config), snapshot_mode=mode, snapshots=snapshots,
        )

    # --------------------------------------------------------------------------------------------- resize

    @staticmethod
    def _size_attributes(changes: list[terraform.Change]) -> tuple[list[str], list[str]]:
        """(the size attributes the plan changes, everything else it does) for §7.5's 'only sizes' rule."""
        sizes: list[str] = []
        other: list[str] = []
        for change in changes:
            if change.address != terraform.VM_ADDRESS or not change.is_update:
                other.append(f"{change.address}: {'+'.join(change.actions)}")
                continue
            for attr in terraform.changed_attributes(change):
                (sizes if attr in SIZE_ATTRIBUTES else other).append(attr)
        return sorted(a for a in sizes if a != "started"), other

    async def _plan_resize(self, ctx: MachineContext, vmid: int) -> list[str]:
        """A resize plan (session, plan, show) that may change only the VM's sizes; returns those attributes."""
        async with self._session(ctx, vmid, ctx.machine.size) as tf:
            sizes, other = self._size_attributes(await tf.plan())
        if other:
            raise MachineError(f"Terraform's plan for {ctx.vm} would change more than its size ({', '.join(other)}); "
                               "Slipway applied nothing")
        return sizes

    async def _snapshots_allowed(self, ctx: MachineContext) -> bool:
        """D11: VM snapshots exist only for one app slot in data mode ``slot`` on a VM."""
        if ctx.machine.slot == "data" or ctx.env.data_mode != "slot":
            return False
        async with get_sessionmaker()() as db:
            slots = set(await db.scalars(select(Instance.slot).where(Instance.environment_id == ctx.env.id)))
        return len(slots & {"blue", "green"}) <= 1

    async def check_resize(self, ctx: MachineContext) -> ResizePlan:
        """§7.5's read-only checks: disks only grow, the VM is Slipway's, the plan changes only sizes, and a
        qcow2 disk with VM snapshots isn't grown."""
        size = vmnet.check_size(ctx.machine.size)
        applied = machines._sizes(ctx.machine.applied) or size
        if size["disk_gb"] < applied["disk_gb"]:
            raise MachineError(f"{ctx.vm}'s disk can't shrink from {applied['disk_gb']} GB to {size['disk_gb']} GB")
        async with self._client(ctx) as api:
            found = await self._made_vm(ctx, api)
            vmid = int(found["vmid"])
            sizes = await self._plan_resize(ctx, vmid)
            grows = size["disk_gb"] > applied["disk_gb"]
            spec = ctx.machine.spec or {}
            qcow2 = (spec.get("file_format") or terraform.file_format_for(spec.get("storage_type"))) == "qcow2"
            if grows and qcow2:
                names = [s["name"] for s in await api.snapshots(self._node(ctx), vmid)]
                if names:
                    raise MachineError(f"Proxmox can't grow {ctx.vm}'s qcow2 disk while it has VM snapshots "
                                       f"({', '.join(names)}); delete them first")
        mode = ctx.machine.snapshot_mode
        snapshot_first = (mode not in (None, SnapshotMode.NONE.value) and not (grows and qcow2)
                          and await self._snapshots_allowed(ctx))
        return ResizePlan(to=dict(size), snapshot_first=snapshot_first, drop_snapshots=[], changes=sizes)

    async def _start_again(self, ctx: MachineContext, api: proxmox.ProxmoxClient, vmid: int) -> None:
        with suppress(MachineError):
            if await api.status(self._node(ctx), vmid) != "running":
                await self._start(ctx, api, vmid)

    async def _root_gb(self, ctx: MachineContext) -> int | None:
        async with ctx.connect(ssh.SSHTarget.from_host(ctx.host)) as session:
            code, out = await session.run(DF_COMMAND, check=False, timeout=30, scrub=ctx.hide.scrub)
        if code != 0:
            return None
        match = re.fullmatch(r"\s*(\d+)G\s*", (out or "").strip().splitlines()[-1] if (out or "").strip() else "")
        return int(match.group(1)) if match else None

    async def resize(self, ctx: MachineContext, plan: ResizePlan) -> dict[str, Any]:
        """§7.5: the ``pre_resize`` snapshot, a clean shutdown, a second plan equal to the first, the apply (which
        starts the VM), the address and the pinned key checked. A failure starts the VM again where it can."""
        vm = ctx.vm
        async with self._client(ctx) as api:
            found = await self._made_vm(ctx, api)
            vmid, node = int(found["vmid"]), self._node(ctx)
            if not plan.changes:  # the VM has the size already (an earlier resize whose record was cut off)
                now = applied_of(await api.vm_config(node, vmid))
                if now is not None:
                    await ctx.say(f"{vm} already has {vmnet.size_text(now)}; nothing to resize")
                    return now
            if plan.snapshot_first:
                row = await machines.pre_resize_row(ctx)  # vm_jobs.new_row's shape, with the identity
                await ctx.say(f"Taking the VM snapshot {row.name} of {vm} before the resize")
                await self.snapshot(ctx, row)

            await self._wait_idle(ctx, api, vmid)
            await ctx.say(f"Shutting {vm} down for the resize")
            try:
                try:
                    await self._task(ctx, api, "shutdown", f"shut {vm} down",
                                     lambda: api.shutdown(node, vmid, timeout=SHUTDOWN_SECONDS))
                except (proxmox.TaskTimeout, proxmox.TaskFailed):
                    pass
                if await api.status(node, vmid) != "stopped":
                    raise MachineError(f"{vm} didn't shut down in {_minutes(SHUTDOWN_SECONDS)}; Slipway left it "
                                       "running at its old size")
                async with self._session(ctx, vmid, ctx.machine.size) as tf:
                    sizes, other = self._size_attributes(await tf.plan())
                    if other or sizes != list(plan.changes):
                        what = ", ".join(other) or ", ".join(sizes) or "nothing"
                        raise MachineError(f"Terraform's plan for {vm} changed while it was off ({what}); Slipway "
                                           "started it again at its old size and applied nothing")
                    await ctx.say(f"Resizing {vm} to {vmnet.size_text(plan.to)}")
                    try:
                        await tf.apply()
                    except terraform.TerraformFailed:
                        await self._start_again(ctx, api, vmid)
                        now = applied_of(await api.vm_config(node, vmid))
                        size_now = vmnet.size_text(now) if now else "a size Slipway can't read"
                        raise MachineError(f"Terraform couldn't resize {vm}; it is running at {size_now}") from None
            except BaseException:
                # Once it is off, it is started again whatever stopped the resize: a failure, the step's time
                # limit or Slipway stopping (shielded from the cancel), at whatever size Proxmox has.
                with suppress(Exception):
                    await machines.shielded(self._start_again(ctx, api, vmid))
                raise

            await self._start_again(ctx, api, vmid)  # the apply's started = true starts it; make sure
            await self._wait_address(ctx, api, vmid, made=True)
            applied = applied_of(await api.vm_config(node, vmid)) or dict(plan.to)
        await machines.check_resized(ctx)

        warnings: list[str] = []
        with suppress(ssh.SSHError, MachineError):
            root = await self._root_gb(ctx)
            if root is not None and root < applied["disk_gb"] - 2 - GROWPART_SLACK:
                warning = (f"{vm}'s disk grew to {applied['disk_gb']} GB but its root file system is {root} GB: "
                           "cloud-init's growpart didn't run; run \"sudo growpart /dev/sda 1 && sudo resize2fs "
                           "/dev/sda1\" on it")
                await ctx.say(warning)
                warnings.append(warning)
        return {**applied, "warnings": warnings} if warnings else applied

    # ------------------------------------------------------------------------------------------ snapshots

    async def _named_once(self, ctx: MachineContext, api: proxmox.ProxmoxClient, vmid: int,
                          row: MachineSnapshot) -> list[dict[str, Any]]:
        """The id rule (§7.6): the snapshot is recorded on this machine and on the VM exactly once."""
        if row.machine_id != ctx.machine.id:
            raise MachineError(f"The VM snapshot {row.name} isn't {ctx.vm}'s; Slipway changed nothing")
        listed = await api.snapshots(self._node(ctx), vmid)
        if sum(1 for s in listed if s["name"] == row.name) != 1:
            raise MachineError(f"{ctx.vm} has no VM snapshot named {row.name} on Proxmox; Slipway changed nothing")
        return listed

    async def _set_row(self, row: MachineSnapshot, **fields: Any) -> None:
        async with session_scope() as db:
            stored = await db.get(MachineSnapshot, row.id, with_for_update=True)
            if stored is not None:
                for key, value in fields.items():
                    setattr(stored, key, value)
        for key, value in fields.items():
            setattr(row, key, value)

    async def snapshot(self, ctx: MachineContext, row: MachineSnapshot) -> bool:
        """Take the VM snapshot ``row`` names (already committed ``pending``): its task in ``last_task`` before
        the wait. A task that times out or fails is given 15 seconds, then the snapshot list decides: there, the
        row is ``ready`` (``The task ended late``); not there, ``failed``. Proxmox doesn't quiesce: False."""
        mode = ctx.machine.snapshot_mode
        spec = ctx.machine.spec or {}
        if mode == SnapshotMode.NONE.value:
            raise MachineError(f"{spec.get('storage')} ({spec.get('storage_type') or 'unknown'}) can't take VM "
                               f"snapshots of {ctx.vm}")
        async with self._client(ctx) as api:
            found = await self._made_vm(ctx, api)
            vmid, node = int(found["vmid"]), self._node(ctx)
            await self._wait_idle(ctx, api, vmid)
            description = f"Slipway {row.reason} snapshot of {ctx.vm}"
            try:
                await self._task(ctx, api, "snapshot", f"take the VM snapshot {row.name}",
                                 lambda: api.take_snapshot(node, vmid, row.name, description))
            except (proxmox.TaskTimeout, proxmox.TaskFailed) as exc:
                await ctx.say(f"{exc.text} Slipway checks again in {int(LATE_GRACE)} seconds")
                await ctx.sleep(LATE_GRACE)
                names = [s["name"] for s in await api.snapshots(node, vmid)]
                if row.name in names:
                    await self._set_row(row, status="ready", note="The task ended late")
                    return False
                await self._set_row(row, status="failed")
                raise MachineError(f"Proxmox didn't take the VM snapshot {row.name} of {ctx.vm}") from None
        await self._set_row(row, status="ready")
        return False

    async def revert(self, ctx: MachineContext, row: MachineSnapshot) -> None:
        """Roll the VM back to ``row`` (it stops: no RAM was saved), start it, and check its address (§7.6)."""
        async with self._client(ctx) as api:
            found = await self._made_vm(ctx, api)
            vmid, node = int(found["vmid"]), self._node(ctx)
            listed = await self._named_once(ctx, api, vmid, row)
            newest = next((s["name"] for s in listed if s.get("newest")), None)
            if ctx.machine.snapshot_mode == SnapshotMode.NEWEST_ONLY.value and newest != row.name:
                raise MachineError(f"{ctx.vm}'s storage reverts only to its newest VM snapshot ({newest}), not "
                                   f"{row.name}; Slipway changed nothing")
            await self._wait_idle(ctx, api, vmid)
            await ctx.say(f"Reverting {ctx.vm} to {row.name}")
            await self._task(ctx, api, "rollback", f"revert {ctx.vm} to {row.name}",
                             lambda: api.rollback(node, vmid, row.name))
            await self._start(ctx, api, vmid)
            await self._wait_address(ctx, api, vmid, made=True)

    async def drop_snapshot(self, ctx: MachineContext, row: MachineSnapshot) -> None:
        async with self._client(ctx) as api:
            found = await self._made_vm(ctx, api)
            vmid, node = int(found["vmid"]), self._node(ctx)
            await self._named_once(ctx, api, vmid, row)
            await self._wait_idle(ctx, api, vmid)
            await self._task(ctx, api, "delsnapshot", f"delete the VM snapshot {row.name}",
                             lambda: api.delete_snapshot(node, vmid, row.name))

    async def stop(self, ctx: MachineContext, *, timeout: int) -> None:
        """A clean shutdown, or MachineError when the VM is still running after ``timeout`` seconds."""
        async with self._client(ctx) as api:
            found = await self._made_vm(ctx, api)
            vmid, node = int(found["vmid"]), self._node(ctx)
            if found.get("status") == "stopped":
                return
            await self._wait_idle(ctx, api, vmid)
            with suppress(proxmox.TaskTimeout, proxmox.TaskFailed):
                await self._task(ctx, api, "shutdown", f"shut {ctx.vm} down",
                                 lambda: api.shutdown(node, vmid, timeout=timeout))
            if await api.status(node, vmid) != "stopped":
                raise MachineError(f"{ctx.vm} didn't shut down in {_minutes(timeout)}")

    # -------------------------------------------------------------------------------------------- destroy

    async def _state_lock_holder(self, ctx: MachineContext) -> str | None:
        """Why Terraform's state of the VM is held by a live run (a blocker that isn't forgettable), or None."""
        async with get_sessionmaker()() as db:
            row = await db.get(TerraformState, ctx.machine.id)
            if row is not None and row.lock_id is not None and row.lock_id != ctx.deployment_id:
                status = await db.scalar(select(Deployment.status).where(Deployment.id == row.lock_id))
                if status in (DeploymentStatus.QUEUED.value, DeploymentStatus.RUNNING.value):
                    return (f"Terraform state of {ctx.vm} is in use by deployment {str(row.lock_id)[:8]}; wait for it "
                            "to finish, then retry")
        settings = terraform.TerraformSettings.from_config(get_settings())
        run = terraform.Workdir(settings.dir, ctx.machine.id).read_json(terraform.RUN_FILE)
        if isinstance(run, dict) and isinstance(run.get("pid"), int):
            with suppress(terraform.TerraformError):
                if terraform._is_terraform(run["pid"], terraform.resolve_binary(settings.binary)):
                    return (f"Terraform is still running for {ctx.vm} (pid {run['pid']}): wait for it to finish, then "
                            "retry")
        return None

    async def destroy_blockers(self, ctx: MachineContext) -> list[Blocker]:
        """Why the VM can't be removed now (§7.7, D26), reading only; [] when ``destroy`` may go."""
        vmid = self._vmid(ctx)
        if vmid is None:
            return []
        ever_ready = ctx.machine.ready_at is not None
        async with self._client(ctx) as api:
            found = await api.find_vm(vmid)
            if found is None:
                if await api.vmid_free(vmid):
                    return []
                if ever_ready or await self._stored_resource(ctx) is not None:
                    return [Blocker(f"Slipway can't see VM {vmid} (check the token's rights on "
                                    f"/pool/{self._pool(ctx)}); nothing was removed", True)]
                return []
            verdict = self._verdict(ctx, found)
            if verdict == "moved":
                return [Blocker(self._moved_text(ctx, found), True)]
            if verdict != "ours" and not (not ever_ready and await self._our_clone(ctx, api, found)):
                return [Blocker(f"VM {vmid} isn't {ctx.vm} any more", True)] if ever_ready else []
            try:
                await self._wait_idle(ctx, api, vmid)
            except MachineError as exc:
                if exc.unreachable:
                    raise
                return [Blocker(exc.text, False)]
        held = await self._state_lock_holder(ctx)
        return [Blocker(held, False)] if held else []

    async def destroy(self, ctx: MachineContext) -> list[str]:
        """Remove the VM (§7.7): through Terraform when its state holds it, through the API when only Slipway's
        half-made VM is there; an id that names nothing of Slipway's is only forgotten. The rows, the state and
        the working folder go in ``machines.remove`` afterwards. Idempotent."""
        vm = ctx.vm
        vmid = self._vmid(ctx)
        if vmid is None:
            return [f"Slipway never made {vm}"]
        ever_ready = ctx.machine.ready_at is not None
        resource = await self._stored_resource(ctx)
        forgotten = f"VM {vmid} was never made by Slipway, or is gone; forgetting the id"
        async with self._client(ctx) as api:
            found = await api.find_vm(vmid)
            if found is None:
                if await api.vmid_free(vmid):
                    return [f"VM {vmid} is already gone" if ever_ready or resource is not None else forgotten]
                if ever_ready or resource is not None:
                    raise MachineError(f"Slipway can't see VM {vmid} (check the token's rights on "
                                       f"/pool/{self._pool(ctx)}); nothing was removed")
                return [forgotten]
            verdict = self._verdict(ctx, found)
            if verdict == "moved":
                raise MachineError(self._moved_text(ctx, found))
            ours = verdict == "ours" or (not ever_ready and await self._our_clone(ctx, api, found))
            if not ours:
                if ever_ready:
                    raise MachineError(f"VM {vmid} isn't {vm} any more")
                return [forgotten]

            await self._wait_idle(ctx, api, vmid)
            if resource is not None:
                size = machines._sizes(ctx.machine.applied) or vmnet.check_size(ctx.machine.size)
                await ctx.say(f"Removing {vm} (VM {vmid}) with Terraform")
                async with self._session(ctx, vmid, size) as tf:
                    if tf.resource() is not None:
                        await tf.destroy()
                done = f"Removed {vm} (VM {vmid}) with Terraform"
            else:
                await ctx.say(f"Removing the half-made {vm} (VM {vmid}) through the Proxmox API")
                await self._delete_vm(ctx, api, vmid, found)
                done = f"Removed {vm} (VM {vmid}) through the Proxmox API"
            if await api.find_vm(vmid) is not None or not await api.vmid_free(vmid):
                raise MachineError(f"VM {vmid} is still there after Terraform's destroy. Remove it by hand in "
                                   "Proxmox, then retry" if resource is not None else
                                   f"VM {vmid} is still there after Slipway deleted it. Remove it by hand in Proxmox, "
                                   "then retry")
        return [done]
