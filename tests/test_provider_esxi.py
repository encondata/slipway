"""The ESXi provider (phase 5 §8.2-§8.5, §9.11): tests 21 (the ESXi half), 30, 31, 31b, 32, 33 and 66 (the ESXi
part), and the audit actions it writes.

ESXi is ``tests/fake_esxi.py`` (an in-memory ``EsxiApi``), handed to the provider in place of ``esxi.session``; the
VMs are ``tests/fake_vm_hosts.py``. A fake VM's first power-on presents the host key its guestinfo user-data
carries, as cloud-init installs it (``boot_esxi_vm``). Every run goes through the machines core
(``machines.prepare``, ``resize_step``, ``remove``), so the stage transactions, the pin and the bootstrap are the
real ones. FakeEsxi is pure Python, so these tests don't need pyvmomi.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
import yaml
from sqlalchemy import delete, select, text, update

from slipway.db.session import get_sessionmaker
from slipway.models import (
    AuditEvent,
    Deployment,
    Environment,
    Host,
    Instance,
    Machine,
    MachineSnapshot,
    ProviderAccount,
    Resource,
)
from slipway.services import esxi, hosts, machines
from slipway.services.providers import esxi as exp
from slipway.services.providers import provider_for
from slipway.services.vmtypes import Blocker, MachineError
from tests import vm_fixtures as vf
from tests.fake_esxi import FakeEsxi
from tests.fake_vm_hosts import VmRemote, boot_esxi_vm, guestinfo_host_key, probe_through

VM = "slipway-uat-blue"
BLUE = "10.0.0.100"
DS = "datastore1"
SEED = "ubuntu-2404-seed"
FOLDER = f"[{DS}] {VM}"
DISK = f"{FOLDER}/{VM}-disk0.vmdk"


# ------------------------------------------------------------------------------------------- the world


class BootingEsxi(FakeEsxi):
    """FakeEsxi whose VMs boot: on power-on, the fake VM host at the VM's address presents the key in its
    user-data (as cloud-init installs it) and VMware Tools reports the address (unless ``tools_quiet``)."""

    def __init__(self, world: World, **kw: Any) -> None:
        super().__init__(**kw)
        self.world = world
        self.addresses: dict[str, str] = {}  # VM name -> the address it comes up at
        self.tools_quiet = False
        self.events: list[str] = []
        self.on_start: Any = None  # awaited with each TaskRef Slipway starts, after on_task

    async def _start(self, kind, uuid, on_task):
        state = await super()._start(kind, uuid, on_task)
        if self.on_start is not None:
            await self.on_start(state.ref)
        return state

    async def power_on(self, uuid: str, *, on_task=None) -> None:
        vm = self._vm(uuid)
        if vm.name in self.addresses and not self.tools_quiet:
            self.boot_ips(vm.name, [self.addresses[vm.name]])
        await super().power_on(uuid, on_task=on_task)
        address = self.addresses.get(vm.name)
        if address and vm.power == "poweredOn":
            boot_esxi_vm(self.world.vms, vm.name.rsplit("-", 1)[-1], address, vm.extra)


class World:
    """One test's ESXi host, VM hosts and session seam."""

    def __init__(self, root: Path, monkeypatch: pytest.MonkeyPatch, net: vf.Network) -> None:
        self.root = root
        self.net = net
        (root / "vms").mkdir()
        self.vms = VmRemote(root / "vms")
        self.fake = BootingEsxi(self)
        self.fake.add_datastore(DS)
        self.fake.add_network("VM Network")
        self.seed = self.fake.add_vm(SEED, disk_gb=10)
        self.fake.addresses[VM] = BLUE
        self.purposes: list[str] = []
        self.down = False

        @asynccontextmanager
        async def session(account: Any, *, purpose: str = "job", poll: float = esxi.POLL):
            if self.down:
                raise MachineError(f"Slipway can't reach ESXi at {exp.EsxiProvider._host_of(account.config['url'])}",
                                   unreachable=True)
            self.purposes.append(purpose)
            yield self.fake

        monkeypatch.setattr(esxi, "session", session)
        self.probe = probe_through(self.vms)
        monkeypatch.setattr(hosts.ssh, "probe", self.probe)

    def calls(self, *methods: str) -> list[tuple[str, Any]]:
        return [c for c in self.fake.calls if not methods or c[0] in methods]

    def names(self) -> list[str]:
        return [c[0] for c in self.fake.calls]

    def vm(self, name: str = VM):
        return self.fake.vm_named(name)


@pytest.fixture
def net(monkeypatch) -> vf.Network:
    return vf.quiet_network(monkeypatch)


@pytest.fixture
def world(tmp_path, monkeypatch, net) -> World:
    return World(tmp_path, monkeypatch, net)


async def blue_env(world: World, *, size: dict | None = None, mode: str = "slot") -> vf.VmEnv:
    """An environment ``uat`` with one ESXi VM planned for blue at 10.0.0.100."""
    account = await vf.esxi_account()
    return await vf.vm_env(account, mode=mode, addresses={"blue": BLUE}, size=size, provider=exp.EsxiProvider(),
                           deploy_roots={"blue": str(world.root / "vms" / "host-blue" / "root")})


async def deployment(env: vf.VmEnv, slot: str | None = "blue", *, kind: str = "deploy") -> uuid.UUID:
    async with get_sessionmaker()() as db:
        await db.execute(update(Deployment).where(Deployment.environment_id == env.env_id,
                                                  Deployment.status.in_(("queued", "running")))
                         .values(status="failed"))
        dep = Deployment(instance_id=env.instances[slot] if slot else None, environment_id=env.env_id, kind=kind,
                         triggered_by_id=env.user_id, branch="main", log="", status="running")
        db.add(dep)
        await db.commit()
        return dep.id


async def ctx_for(world: World, env: vf.VmEnv, *, log: vf.Lines | None = None,
                  job: str | None = "blue") -> machines.MachineContext:
    dep = await deployment(env, job)
    return await vf.context(env.machines["blue"], connect=world.vms.connect, deployment_id=dep, user_id=env.user_id,
                            say=log if log is not None else vf.Lines())


async def machine(env: vf.VmEnv) -> Machine:
    async with get_sessionmaker()() as db:
        return await db.get(Machine, env.machines["blue"])


async def host(env: vf.VmEnv) -> Host:
    async with get_sessionmaker()() as db:
        return await db.get(Host, env.hosts["blue"])


async def audits(action: str | None = None) -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        stmt = select(AuditEvent).order_by(AuditEvent.created_at)
        if action:
            stmt = stmt.where(AuditEvent.action == action)
        return list(await db.scalars(stmt))


async def vm_rows(env: vf.VmEnv) -> list[Resource]:
    async with get_sessionmaker()() as db:
        return list(await db.scalars(select(Resource).where(Resource.environment_id == env.env_id,
                                                            Resource.kind == "vm")))


async def made(world: World, **kw: Any) -> tuple[vf.VmEnv, machines.MachineContext, vf.Lines]:
    """A ready VM, made end to end (the path test 30 checks)."""
    env = await blue_env(world, **kw)
    log = vf.Lines()
    ctx = await ctx_for(world, env, log=log)
    assert (await machines.prepare(ctx))[0] == "succeeded"
    return env, ctx, log


async def again(world: World, env: vf.VmEnv, log: vf.Lines | None = None, job: str | None = "blue"):
    return await ctx_for(world, env, log=log, job=job)


async def unreadable_host_key(env: vf.VmEnv) -> None:
    """The private host key can't be read with the current SLIPWAY_ENCRYPTION_KEY (§3.9): it reads as None."""
    async with get_sessionmaker()() as db:
        await db.execute(text("UPDATE machines SET host_key_private = 'not-a-fernet-token' WHERE id = :id"),
                         {"id": env.machines["blue"].hex if db.bind.dialect.name == "sqlite" else env.machines["blue"]})
        await db.commit()
    assert (await machine(env)).host_key_private is None


async def no_secret_anywhere(env: vf.VmEnv, log: list[str], *, private: str | None = None,
                             client_key: str | None = None) -> None:
    """The ESXi password, the host's client key and the VM's private host key are in no audit row or log line."""
    blob = json.dumps([[a.summary, a.details] for a in await audits()], default=str)
    secrets = [vf.ESXI_PASSWORD, client_key or (await host(env)).private_key]
    if private:
        secrets.append(private)
    for secret in secrets:
        assert secret not in blob
        assert not any(secret in line for line in log)


def userdata_of(extra: dict[str, str]) -> dict[str, Any]:
    return yaml.safe_load(base64.b64decode(extra["guestinfo.userdata"]).decode())


def metadata_of(extra: dict[str, str]) -> dict[str, Any]:
    return yaml.safe_load(base64.b64decode(extra["guestinfo.metadata"]).decode())


# ------------------------------------------------------------------ test 30: a new VM, end to end


async def test_30_a_new_vm_end_to_end(world, monkeypatch):
    env = await blue_env(world)
    planned = await machine(env)
    private = planned.host_key_private
    events: list[str] = []

    async def tcp_open(address, port, timeout=machines.PROBE_TIMEOUT):
        events.append(f"probe {address}:{port}")
        return False

    real_guest_ips = world.fake.guest_ips

    async def guest_ips():
        events.append("guest ips")
        return await real_guest_ips()

    real_addresses = machines.addresses_in_use

    async def addresses_in_use(db, **kw):
        events.append("registry")
        return await real_addresses(db, **kw)

    real_record = machines.record_vm

    async def record_vm(m, provider_id, *args, **kw):
        events.append("record")
        return await real_record(m, provider_id, *args, **kw)

    real_write = machines.write

    async def write(ctx, **fields):
        result = await real_write(ctx, **fields)
        if fields.get("stage"):
            events.append(f"stage {fields['stage']}")
        return result

    real_check = hosts.check_host

    async def check_host(db, h, **kw):
        events.append(f"check_host building={kw.get('building')} docker={world.vms.docker_installed(BLUE)}")
        return await real_check(db, h, **kw)

    monkeypatch.setattr(machines, "tcp_open", tcp_open)
    monkeypatch.setattr(world.fake, "guest_ips", guest_ips)
    monkeypatch.setattr(machines, "addresses_in_use", addresses_in_use)
    monkeypatch.setattr(machines, "record_vm", record_vm)
    monkeypatch.setattr(machines, "write", write)
    monkeypatch.setattr(hosts, "check_host", check_host)

    async def on_start(ref):
        events.append(f"task {ref.kind}")
        if ref.kind == "copy_disk":  # the ids and the vm row are recorded before the disk is copied
            row = await machine(env)
            assert row.ids["instance_uuid"] and len(await vm_rows(env)) == 1

    world.fake.on_start = on_start

    log = vf.Lines()
    ctx = await ctx_for(world, env, log=log)
    status, note = await machines.prepare(ctx)
    assert (status, note) == ("succeeded", f"{VM} is ready at {BLUE}")

    # The API-host check passed; the registry, the guest IPs and the probe before anything was made.
    assert events[:3] == ["registry", "guest ips", f"probe {BLUE}:22"]
    order = [e for e in events if e.startswith(("stage", "task", "record", "check_host"))]
    assert order[:4] == ["stage creating", "task create_vm", "record", "task copy_disk"]
    assert order.index("task copy_disk") < order.index("task attach_disk") < order.index("task grow_disk")
    assert order.index("task grow_disk") < order.index("stage booting") < order.index("task power_on")
    assert order.index("task power_on") < order.index("task set_extra_config")  # the scrub, after the pin
    assert "check_host building=True docker=True" in events  # after the bootstrap
    assert events[-1] == "stage ready"

    # create_vm: both markers and guestinfo, the size, the port group; the folder is the VM's own.
    vm = world.vm()
    assert vm.extra["slipway.machine"] == str(env.machines["blue"])
    assert vm.extra["slipway.environment"] == str(env.env_id)
    assert vm.extra["disk.EnableUUID"] == "TRUE" and vm.folder == VM
    assert "guestinfo.metadata" in vm.extra and "guestinfo.userdata" not in vm.extra  # scrubbed (E9)
    meta = metadata_of(vm.extra)
    assert meta["local-hostname"] == VM and meta["network"]["ethernets"]["primary"]["addresses"] == [f"{BLUE}/24"]
    assert meta["network"]["ethernets"]["primary"]["nameservers"]["addresses"] == ["10.0.0.53"]
    assert (vm.cores, vm.memory_mb) == (4, 8192)
    assert [d.chain[0] for d in vm.disks] == [DISK] and vm.disks[0].size_gb == 64
    assert vm.power == "poweredOn"
    assert ("copy_disk", DISK) in world.calls("copy_disk")
    assert not world.calls("shutdown_guest", "power_off")  # prepare never shuts a VM down (test 21)

    # Ids and the resource; pinned with the generated key; the private half gone; bootstrapped; ready.
    row, h = await machine(env), await host(env)
    assert row.stage == "ready" and row.snapshot_mode == "any" and row.last_error is None
    assert set(row.ids) == {"instance_uuid", "moref", "vm_path"} and row.ids["instance_uuid"] == vm.uuid
    assert row.ids["vm_path"] == f"{FOLDER}/{VM}.vmx"
    assert row.applied["cores"] == 4 and row.applied["disk_gb"] == 64
    assert row.host_key_private is None and row.host_key_public == planned.host_key_public
    assert h.host_key == planned.host_key_public and h.is_built and h.docker_version == "26.1.3"
    assert h.provider_state["phase"] == "ready"
    (resource,) = await vm_rows(env)
    assert resource.provider == "esxi" and resource.provider_id == f"{row.account_id}:{vm.uuid}"
    assert resource.details["machine_id"] == str(row.id) and resource.details["moref"] == vm.moref
    assert world.vms.docker_installed(BLUE) and world.vms.in_docker_group(BLUE)
    assert set(world.purposes) == {"job"}

    (pinned,) = await audits("host.key_pinned")
    assert pinned.details["how"] == "generated by Slipway" and pinned.details["address"] == BLUE
    (reserved,) = await audits("machine.reserve")
    assert reserved.details == {"name": VM, "instance_uuid": vm.uuid, "moref": vm.moref}
    (created,) = await audits("machine.create")
    assert created.details == {"name": VM, "ids": {"instance_uuid": vm.uuid, "moref": vm.moref}, "datastore": DS}
    assert created.actor_id == env.user_id
    assert await audits("machine.rebuild") == [] and await audits("machine.adopt") == []
    (ready,) = await audits("machine.ready")
    assert ready.details["address"] == BLUE
    await no_secret_anywhere(env, log, private=private)


async def test_30_the_user_data_has_the_slipway_user_with_sudo_and_the_generated_pair(world, monkeypatch):
    env = await blue_env(world)
    planned = await machine(env)
    seen: dict[str, Any] = {}
    real = world.fake.create_vm

    async def create_vm(spec, *, on_task=None):
        seen["spec"] = spec
        return await real(spec, on_task=on_task)

    monkeypatch.setattr(world.fake, "create_vm", create_vm)
    ctx = await ctx_for(world, env)
    await machines.prepare(ctx)
    spec = seen["spec"]
    assert "hidden" in repr(spec) and planned.host_key_private not in repr(spec)
    assert spec.owner == {"slipway.machine": str(env.machines["blue"]), "slipway.environment": str(env.env_id)}
    assert spec.datastore == DS and spec.resource_pool == "Resources" and spec.port_group == "VM Network"
    user = userdata_of(spec.guestinfo)
    (account,) = user["users"]
    assert account["name"] == "slipway" and account["sudo"] == "ALL=(ALL) NOPASSWD:ALL" and account["lock_passwd"]
    assert account["ssh_authorized_keys"] == [(await host(env)).public_key]
    assert user["ssh_keys"]["ed25519_public"] == planned.host_key_public
    assert user["ssh_deletekeys"] is True and user["ssh_genkeytypes"] == []
    assert guestinfo_host_key(spec.guestinfo) == planned.host_key_public


async def test_30_the_provider_is_found_lazily_and_freezes_the_spec(world):
    provider = provider_for("esxi")
    assert isinstance(provider, exp.EsxiProvider) and provider.label == "ESXi" and provider.name == "esxi"
    account = await vf.esxi_account()
    assert provider.freeze(account, vf.LAN_ESXI) == {
        "api_host": "esxi.test", "datastore": DS, "resource_pool": "Resources", "source_vm": SEED,
        "port_group": "VM Network",
    }
    assert provider.freeze(account, vf.LAN_ESXI) == vf.SimpleFreeze().freeze(account, vf.LAN_ESXI)
    assert provider.clean_config(dict(account.config), None)["url"] == vf.ESXI_URL


async def test_30_an_account_now_pointing_at_another_host_changes_nothing(world):
    env = await blue_env(world)
    async with get_sessionmaker()() as db:
        account = await db.get(ProviderAccount, env.account_id)
        account.config = {**account.config, "url": "https://esxi-2.test"}
        await db.commit()
    ctx = await ctx_for(world, env)
    with pytest.raises(MachineError) as caught:
        await machines.prepare(ctx)
    assert caught.value.text == (f"{VM} was made on esxi.test, but the account now points at esxi-2.test; Slipway "
                                 "changed nothing")
    assert world.fake.calls == [] and (await machine(env)).stage == "planned"
    assert (await machine(env)).last_error == caught.value.text


@pytest.mark.parametrize("holder", ["guest", "probe"])
async def test_30_an_address_another_vm_reports_or_that_answers_ssh_is_refused(world, net, holder):
    env = await blue_env(world)
    if holder == "guest":
        world.fake.add_vm("someone-else", power="poweredOn")
        world.fake.vm_named("someone-else").ips = [BLUE]
        want = (f"someone-else on ESXi already reports {BLUE}, so Slipway won't give that address to {VM}. Slipway "
                "changed nothing")
    else:
        net.open.add(BLUE)
        want = (f"Something already answers SSH at {BLUE}, so Slipway won't give that address to a new VM. Free it, "
                "or recreate the environment with another address")
    ctx = await ctx_for(world, env)
    with pytest.raises(MachineError) as caught:
        await machines.prepare(ctx)
    assert caught.value.text == want
    assert not world.calls("create_vm") and (await machine(env)).stage == "planned"


async def test_30_tools_reporting_another_address_fails_the_new_vm(world):
    env = await blue_env(world)
    world.fake.addresses[VM] = "10.0.0.99"
    ctx = await ctx_for(world, env)
    with pytest.raises(MachineError) as caught:
        await machines.prepare(ctx)
    assert caught.value.text.startswith(f"{VM} came up at 10.0.0.99, not {BLUE}.")
    assert (await machine(env)).stage == "booting"


# ---------------------------------------------------------------- test 21: the driver, the ESXi half


async def test_21_a_ready_vm_is_only_read_powered_on_when_off_and_never_shut_down(world):
    env, ctx, _ = await made(world)
    world.fake.calls.clear()
    log = vf.Lines()
    assert await machines.prepare(await again(world, env, log)) == ("succeeded", None)
    assert set(world.names()) <= {"find_vm", "guest", "running_tasks"}

    vm = world.vm()
    vm.power, vm.tools, vm.ips = "poweredOff", False, []
    world.fake.calls.clear()
    assert (await machines.prepare(await again(world, env, log)))[0] == "succeeded"
    assert "power_on" in world.names() and not world.calls("shutdown_guest", "power_off", "create_vm", "copy_disk")
    assert world.vm().power == "poweredOn"


async def test_21_tools_quiet_on_a_ready_vm_is_a_warning(world):
    env, _, _ = await made(world)
    world.vm().ips = []
    status, note = await machines.prepare(await again(world, env))
    assert (status, note) == ("warning", f"VMware Tools on {VM} didn't answer in 5 minutes; carrying on over SSH")


async def test_21_a_ready_vm_with_the_api_down_is_a_warning_and_with_a_resize_fails(world):
    env, _, _ = await made(world)
    world.down = True
    status, note = await machines.prepare(await again(world, env))
    assert (status, note) == ("warning", f"Couldn't reach ESXi to check {VM}; carrying on over SSH")
    async with get_sessionmaker()() as db:
        row = await db.get(Machine, env.machines["blue"])
        row.size = {**row.size, "cores": 8}
        await db.commit()
    with pytest.raises(MachineError) as caught:
        await machines.prepare(await again(world, env), resize=True)
    assert caught.value.text == f"Slipway can't reach esx-01 to resize {VM}"


async def test_21_check_resize_runs_reading_only_and_its_refusal_names_the_size_to_set_back(world):
    env, _, _ = await made(world)
    await world.fake.take_snapshot(world.vm().uuid, "by-hand", quiesce=False)
    async with get_sessionmaker()() as db:
        row = await db.get(Machine, env.machines["blue"])
        row.size = {**row.size, "disk_gb": 80}
        await db.commit()
    world.fake.calls.clear()
    with pytest.raises(MachineError) as caught:
        await machines.prepare(await again(world, env), resize=True)
    assert caught.value.text == (
        "ESXi can't grow a disk that has VM snapshots, and by-hand aren't Slipway's; delete them in ESXi first. To "
        f"deploy without the resize, set {VM}'s size back to 4 vCPU, 8 GB, 64 GB on the environment page")
    assert set(world.names()) <= {"find_vm", "guest", "running_tasks", "snapshots"}
    assert (await machine(env)).last_error == caught.value.text


async def test_21_the_stage_and_the_hosts_phase_move_together(world, monkeypatch):
    env = await blue_env(world)
    seen: list[tuple[str, str]] = []
    real_write = machines.write

    async def write(ctx, **fields):
        result = await real_write(ctx, **fields)
        if fields.get("stage"):
            async with get_sessionmaker()() as db:
                m = await db.get(Machine, env.machines["blue"])
                h = await db.get(Host, m.host_id)
                seen.append((m.stage, h.provider_state["phase"]))
        return result

    monkeypatch.setattr(machines, "write", write)
    await machines.prepare(await ctx_for(world, env))
    assert seen == [("creating", "creating"), ("booting", "creating"), ("ready", "ready")]


# ------------------------------------------------------------------------------ test 31: half-made VMs


async def test_31_a_lost_record_is_adopted_by_its_marker(world, monkeypatch):
    env = await blue_env(world)
    real = machines.record_vm
    calls = {"n": 0}

    async def record_vm(*args, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise MachineError("Slipway stopped here")  # made, but the UUID never reached the database
        return await real(*args, **kw)

    monkeypatch.setattr(machines, "record_vm", record_vm)
    with pytest.raises(MachineError):
        await machines.prepare(await ctx_for(world, env))
    assert (await machine(env)).ids == {} and (await machine(env)).stage == "creating"
    first = world.vm().uuid

    log = vf.Lines()
    assert (await machines.prepare(await again(world, env, log)))[0] == "succeeded"
    assert len(world.calls("create_vm")) == 1 and world.vm().uuid == first
    assert (await machine(env)).ids["instance_uuid"] == first
    (adopt,) = await audits("machine.adopt")
    assert adopt.summary == f"Found {VM} from an earlier attempt"
    assert adopt.details == {"name": VM, "ids": {"instance_uuid": first, "moref": world.vm().moref}}
    assert f"Found {VM} from an earlier attempt" in log


async def test_31_the_same_name_with_another_owner_is_refused(world):
    env = await blue_env(world)
    world.fake.add_vm(VM, extra={"slipway.machine": str(uuid.uuid4()), "slipway.environment": str(uuid.uuid4())})
    with pytest.raises(MachineError) as caught:
        await machines.prepare(await ctx_for(world, env))
    assert caught.value.text == (f"ESXi already has a VM named {VM} that isn't this environment's. Slipway changed "
                                 "nothing: rename or remove it, or recreate the environment")
    assert not world.calls("create_vm", "copy_disk", "delete_disk", "destroy")


async def test_31_a_half_copied_disk_is_deleted_after_the_running_copy_is_waited_for(world):
    env = await blue_env(world)
    world.fake.copy_cancelable(False)
    world.fake.copy_cut(polls=2)
    with pytest.raises(MachineError) as caught:
        await machines.prepare(await ctx_for(world, env))
    assert "ESXi couldn't cancel it, so it may still be running" in caught.value.text
    row = await machine(env)
    assert row.stage == "creating" and row.last_task["kind"] == "copy_disk"  # kept: the copy may still run (D24)
    assert DISK in world.fake.files and not world.vm().disks

    log = vf.Lines()
    assert (await machines.prepare(await again(world, env, log)))[0] == "succeeded"
    assert any(line.startswith("Waiting for ESXi's disk copy task") for line in log)
    assert f"Deleted {DISK}, left by an earlier attempt" in log
    names = world.names()
    last_copy = len(names) - 1 - names[::-1].index("copy_disk")
    assert names.count("copy_disk") == 2 and names.index("delete_disk") < last_copy
    assert [d.chain[0] for d in world.vm().disks] == [DISK]
    assert (await machine(env)).last_task is None


async def test_31_a_half_copied_disk_another_vm_has_attached_is_refused(world):
    env = await blue_env(world)
    world.fake.copy_cut(polls=0)
    with pytest.raises(MachineError):
        await machines.prepare(await ctx_for(world, env))
    other = world.fake.add_vm("thief")
    world.fake.vm_named("thief").disks.clear()
    await world.fake.attach_disk(other.uuid, DISK)
    with pytest.raises(MachineError) as caught:
        await machines.prepare(await again(world, env))
    assert caught.value.text == f"{DISK} is attached to thief, so Slipway won't delete it"
    assert DISK in world.fake.files and not world.calls("delete_disk")


async def test_31_a_recorded_vm_gone_while_creating_is_made_again(world):
    env = await blue_env(world)
    world.fake.fail("copy_disk", "ESXi couldn't copy the seed VM's disk (NoDiskSpace)")
    with pytest.raises(MachineError):
        await machines.prepare(await ctx_for(world, env))
    gone = (await machine(env)).ids["instance_uuid"]
    await world.fake.destroy(gone)
    (old_row,) = await vm_rows(env)

    log = vf.Lines()
    assert (await machines.prepare(await again(world, env, log)))[0] == "succeeded"
    assert f"The half-made {VM} is gone from ESXi; making it again" in log
    row = await machine(env)
    assert row.ids["instance_uuid"] != gone and row.ids["instance_uuid"] == world.vm().uuid
    (new_row,) = await vm_rows(env)
    assert new_row.id != old_row.id and new_row.provider_id.endswith(row.ids["instance_uuid"])
    (rebuild,) = await audits("machine.rebuild")
    assert rebuild.details == {"name": VM, "old": gone, "why": "gone before it was ready"}
    assert [a.details["provider_id"] for a in await audits("resource.forget")] == [old_row.provider_id]


async def test_31_a_folder_holding_only_slipways_disk_is_cleaned_before_create(world):
    env = await blue_env(world)
    world.fake.add_file(DISK, 10)
    world.fake.add_file(DISK[:-5] + "-flat.vmdk")
    assert (await machines.prepare(await ctx_for(world, env)))[0] == "succeeded"
    names = world.names()
    assert names.index("delete_disk") < names.index("create_vm")
    assert world.vm().folder == VM and not any(d.endswith(f"{VM}_1") for d in world.fake.dirs)


async def test_31_a_folder_holding_other_files_is_refused_before_create(world):
    env = await blue_env(world)
    world.fake.add_file(f"{FOLDER}/notes.txt")
    with pytest.raises(MachineError) as caught:
        await machines.prepare(await ctx_for(world, env))
    assert caught.value.text == (f"{FOLDER}/ already holds files no VM uses (notes.txt). Slipway changed nothing: "
                                 "remove them in the ESXi Host Client, then retry")
    assert not world.calls("create_vm", "delete_disk")


async def test_31_ready_and_gone_answers_the_lost_text(world):
    env, _, _ = await made(world)
    vm = world.vm()
    vm.power = "poweredOff"
    await world.fake.destroy(vm.uuid)
    world.fake.calls.clear()
    with pytest.raises(MachineError) as caught:
        await machines.prepare(await again(world, env))
    assert caught.value.text == (f"{VM} is gone from esx-01, and uat's data was on it. Slipway can't make it again "
                                 "without that data: delete the environment, and create it again from a snapshot if "
                                 "you have one")
    assert set(world.names()) <= {"find_vm", "find_vm_by_name"}


async def test_31_ready_and_gone_with_a_marked_vm_of_its_name_says_so(world):
    env, _, _ = await made(world)
    vm = world.vm()
    vm.power = "poweredOff"
    await world.fake.destroy(vm.uuid)
    world.fake.add_vm(VM, extra={"slipway.machine": str(env.machines["blue"]), "slipway.environment": str(env.env_id)})
    with pytest.raises(MachineError) as caught:
        await machines.prepare(await again(world, env))
    assert caught.value.text.endswith(f". {VM} carries this environment's marker but isn't the VM Slipway recorded; "
                                      "remove it by hand")


async def test_31_a_foreign_disk_or_a_changed_marker_is_refused(world):
    env, _, _ = await made(world)
    world.fake.calls.clear()
    world.fake.add_file(f"{FOLDER}/extra.vmdk", 5)
    world.vm().disks.append(type(world.vm().disks[0])(2001, [f"{FOLDER}/extra.vmdk"], 5))
    with pytest.raises(MachineError) as caught:
        await machines.prepare(await again(world, env))
    assert caught.value.text == f"{VM} has a disk Slipway didn't put there; Slipway changed nothing"

    world.vm().disks.pop()
    world.vm().extra["slipway.environment"] = str(uuid.uuid4())
    with pytest.raises(MachineError) as caught:
        await machines.prepare(await again(world, env))
    assert caught.value.text == ("The VM Slipway recorded for uat isn't slipway-uat-blue with its marker any more; "
                                 "Slipway changed nothing")
    assert set(world.names()) <= {"find_vm"}  # refused with only reads


# ------------------------------------------------------------ test 31b: host key regeneration (E1)


async def test_31b_no_vm_gets_a_new_pair(world):
    env = await blue_env(world)
    old = (await machine(env)).host_key_public
    await unreadable_host_key(env)
    log = vf.Lines()
    assert (await machines.prepare(await ctx_for(world, env, log=log)))[0] == "succeeded"
    row = await machine(env)
    assert row.host_key_public != old and (await host(env)).host_key == row.host_key_public
    assert f"Made a new host key for {VM}" in log
    assert await audits("machine.rebuild") == []


async def test_31b_a_vm_in_creating_gets_a_new_pair_written_before_its_power_on(world):
    env = await blue_env(world)
    old = (await machine(env)).host_key_public
    world.fake.fail("copy_disk", "ESXi couldn't copy the seed VM's disk (NoDiskSpace)")
    with pytest.raises(MachineError):
        await machines.prepare(await ctx_for(world, env))
    assert (await machine(env)).stage == "creating"
    await unreadable_host_key(env)
    world.fake.calls.clear()

    log = vf.Lines()
    assert (await machines.prepare(await again(world, env, log)))[0] == "succeeded"
    names = world.names()
    assert names.index("set_extra_config") < names.index("power_on")
    row = await machine(env)
    assert row.host_key_public != old and (await host(env)).host_key == row.host_key_public
    assert f"Made a new host key for {VM} and wrote it into its cloud-init settings" in log
    assert len(world.calls("create_vm")) == 0 and await audits("machine.rebuild") == []


async def test_31b_a_vm_in_booting_is_made_again_with_a_new_pair(world):
    env = await blue_env(world)
    old = (await machine(env)).host_key_public
    world.fake.fail("guest", "VMware Tools didn't answer")
    with pytest.raises(MachineError):
        await machines.prepare(await ctx_for(world, env))
    first = await machine(env)
    assert first.stage == "booting"
    await unreadable_host_key(env)

    assert (await machines.prepare(await again(world, env)))[0] == "succeeded"
    row = await machine(env)
    assert row.ids["instance_uuid"] != first.ids["instance_uuid"] and first.ids["instance_uuid"] not in world.fake.vms
    assert row.host_key_public != old and (await host(env)).host_key == row.host_key_public
    assert len(world.calls("create_vm")) == 2 and world.calls("power_off", "destroy")
    (rebuild,) = await audits("machine.rebuild")
    assert rebuild.details["old"] == first.ids["instance_uuid"]
    assert rebuild.details["why"] == "its host key couldn't be read after it may have booted"


async def test_31b_a_readable_pair_is_never_replaced(world):
    env = await blue_env(world)
    old = (await machine(env)).host_key_public
    world.fake.fail("guest", "VMware Tools didn't answer")
    with pytest.raises(MachineError):
        await machines.prepare(await ctx_for(world, env))
    assert (await machines.prepare(await again(world, env)))[0] == "succeeded"
    assert (await machine(env)).host_key_public == old == (await host(env)).host_key
    assert len(world.calls("create_vm")) == 1


async def test_31b_a_vm_pinned_before_its_scrub_is_scrubbed_on_the_retry(world, monkeypatch):
    env = await blue_env(world)
    provider = provider_for("esxi")
    real = provider.after_pin
    calls = {"n": 0}

    async def after_pin(ctx):
        calls["n"] += 1
        if calls["n"] == 1:
            raise MachineError("Slipway can't reach ESXi at esxi.test", unreachable=True)
        await real(ctx)

    monkeypatch.setattr(provider, "after_pin", after_pin)
    with pytest.raises(MachineError):
        await machines.prepare(await ctx_for(world, env))
    assert (await host(env)).host_key and "guestinfo.userdata" in world.vm().extra
    assert (await machines.prepare(await again(world, env)))[0] == "succeeded"
    assert "guestinfo.userdata" not in world.vm().extra and (await machine(env)).host_key_private is None
    assert calls["n"] == 1 and len(world.calls("create_vm")) == 1


# ------------------------------------------------------------------- test 32: check_resize and resize


async def set_size(env: vf.VmEnv, **size: int) -> None:
    async with get_sessionmaker()() as db:
        row = await db.get(Machine, env.machines["blue"])
        row.size = {**row.size, **size}
        await db.commit()


async def snapshot_row(env: vf.VmEnv, name: str, *, status: str = "ready") -> MachineSnapshot:
    async with get_sessionmaker()() as db:
        row = MachineSnapshot(machine_id=env.machines["blue"], name=name, reason="manual", status=status,
                              identity_fp="x" * 64, sizes={"cores": 4, "memory_mb": 8192, "disk_gb": 64},
                              taken_at=machines.utcnow())
        db.add(row)
        await db.commit()
        return row


async def test_32_cores_and_memory_take_a_pre_resize_snapshot(world):
    env, _, _ = await made(world)
    await set_size(env, cores=8, memory_mb=16384)
    ctx = await again(world, env)
    plan = await provider_for("esxi").check_resize(ctx)
    assert plan.snapshot_first and plan.drop_snapshots == [] and plan.changes == ["cores", "memory_mb"]
    world.fake.calls.clear()
    assert await machines.resize_step(ctx) == ("succeeded", "Resized to 8 vCPU, 16 GB, 64 GB")
    names = world.names()
    assert names.index("take_snapshot") < names.index("shutdown_guest") < names.index("set_size")
    assert names.index("set_size") < names.index("power_on") and "grow_disk" not in names
    vm = world.vm()
    assert (vm.cores, vm.memory_mb, vm.power) == (8, 16384, "poweredOn")
    async with get_sessionmaker()() as db:
        (snap,) = await db.scalars(select(MachineSnapshot))
        assert snap.reason == "pre_resize" and snap.status == "ready" and snap.quiesced is True
    row = await machine(env)
    assert row.applied["cores"] == 8 and row.applied["memory_mb"] == 16384
    (resized,) = await audits("machine.resize")
    assert resized.details["to"] == {"cores": 8, "memory_mb": 16384, "disk_gb": 64}


async def test_32_a_grow_with_a_foreign_or_duplicate_snapshot_is_refused_in_check_resize(world):
    env, _, _ = await made(world)
    await set_size(env, disk_gb=80)
    uuid_ = world.vm().uuid
    await world.fake.take_snapshot(uuid_, "by-hand", quiesce=False)
    ctx = await again(world, env)
    with pytest.raises(MachineError) as caught:
        await provider_for("esxi").check_resize(ctx)
    assert caught.value.text == ("ESXi can't grow a disk that has VM snapshots, and by-hand aren't Slipway's; delete "
                                 "them in ESXi first")

    snap = world.vm().snaps[0]
    await world.fake.delete_snapshot(uuid_, snap.id)
    await snapshot_row(env, "slipway-20261115T100000Z")
    await world.fake.take_snapshot(uuid_, "slipway-20261115T100000Z", quiesce=False)
    await world.fake.take_snapshot(uuid_, "slipway-20261115T100000Z", quiesce=False)
    world.fake.calls.clear()
    with pytest.raises(MachineError) as caught:
        await provider_for("esxi").check_resize(ctx)
    assert "and slipway-20261115T100000Z aren't Slipway's" in caught.value.text
    assert set(world.names()) <= {"find_vm", "snapshots"}  # check_resize reads only


async def test_32_a_grow_deletes_slipways_snapshots_and_marks_them_missing(world):
    env, _, _ = await made(world)
    await snapshot_row(env, "slipway-20261115T100000Z")
    await world.fake.take_snapshot(world.vm().uuid, "slipway-20261115T100000Z", quiesce=True)
    await set_size(env, disk_gb=80)
    ctx = await again(world, env)
    plan = await provider_for("esxi").check_resize(ctx)
    assert plan.drop_snapshots == ["slipway-20261115T100000Z"] and not plan.snapshot_first
    world.fake.calls.clear()
    assert (await machines.resize_step(ctx))[0] == "succeeded"
    vm = world.vm()
    assert vm.snaps == [] and vm.disks[0].size_gb == 80 and vm.power == "poweredOn"
    names = world.names()
    assert names.index("shutdown_guest") < names.index("delete_snapshot") < names.index("grow_disk")
    assert "take_snapshot" not in names  # a grow takes no snapshot first (D13)
    async with get_sessionmaker()() as db:
        (snap,) = await db.scalars(select(MachineSnapshot))
        assert snap.status == "missing"
    (dropped,) = await audits("machine.snapshot_delete")
    assert dropped.details == {"name": VM, "snapshot": "slipway-20261115T100000Z", "why": "resize"}
    assert (await machine(env)).applied["disk_gb"] == 80


async def test_32_a_shutdown_timeout_leaves_it_running_at_its_old_size(world):
    env, _, _ = await made(world)
    await set_size(env, cores=8)
    world.fake.ignore_shutdown(VM)
    with pytest.raises(MachineError) as caught:
        await machines.resize_step(await again(world, env))
    assert caught.value.text == f"{VM} didn't shut down in 5 minutes; Slipway left it running at its old size"
    vm = world.vm()
    assert (vm.power, vm.cores) == ("poweredOn", 4) and not world.calls("set_size")
    async with get_sessionmaker()() as db:
        assert (await db.get(Environment, env.env_id)).notice is None
    assert await audits("machine.left_off") == []


async def test_32_a_failure_while_off_leaves_it_off_with_the_retry_text_and_the_notice(world):
    env, _, _ = await made(world)
    await set_size(env, cores=8)
    world.fake.fail("set_size", "ESXi couldn't set the VM's size (InvalidState)")
    with pytest.raises(MachineError) as caught:
        await machines.resize_step(await again(world, env))
    assert caught.value.text == (f"Slipway left {VM} off at 4 vCPU, 8 GB, 64 GB; retry the deploy to finish the "
                                 "resize")
    assert world.vm().power == "poweredOff"
    async with get_sessionmaker()() as db:
        notice = (await db.get(Environment, env.env_id)).notice
    assert notice["text"] == f"{VM} was left off during a resize: deploy to blue again to finish it"
    (left,) = await audits("machine.left_off")
    assert left.details["why"] == caught.value.text
    assert (await machine(env)).applied["cores"] == 4

    # The next deploy's prepare powers it on, and its resize finishes the change.
    assert (await machines.prepare(await again(world, env), resize=True))[0] == "succeeded"
    assert world.vm().power == "poweredOn"
    assert (await machines.resize_step(await again(world, env)))[0] == "succeeded"
    assert world.vm().cores == 8


async def test_32_the_growpart_warning_ends_the_resize_step_as_a_warning(world):
    env, _, _ = await made(world)
    shim = world.root / "df-bin"
    shim.mkdir()
    (shim / "df").write_text("#!/bin/sh\necho ' Size'\necho '  30G'\n")
    (shim / "df").chmod(0o755)
    blue = world.vms[BLUE]
    blue.env["PATH"] = f"{shim}:{blue.env['PATH']}"
    await set_size(env, disk_gb=80)
    log = vf.Lines()
    status, note = await machines.resize_step(await again(world, env, log))
    warning = (f"{VM}'s disk grew to 80 GB but its root file system is 30 GB: cloud-init's growpart didn't run; run "
               "\"sudo growpart /dev/sda 1 && sudo resize2fs /dev/sda1\" on it")
    assert (status, note) == ("warning", f"Resized to 4 vCPU, 8 GB, 80 GB. {warning}")
    assert warning in log and (await machine(env)).applied["disk_gb"] == 80

    # A root file system that grew with the disk gives no warning.
    (shim / "df").write_text("#!/bin/sh\necho ' Size'\necho '  99G'\n")
    await set_size(env, disk_gb=100)
    assert await machines.resize_step(await again(world, env)) == ("succeeded", "Resized to 4 vCPU, 8 GB, 100 GB")


# ------------------------------------------------------------ test 33: snapshots, revert and destroy


async def pending_row(env: vf.VmEnv, name: str = "slipway-20261116T090000Z") -> MachineSnapshot:
    return await snapshot_row(env, name, status="pending")


async def test_33_a_snapshot_is_quiesced_and_falls_back_to_crash_consistent(world):
    env, ctx, _ = await made(world)
    provider = provider_for("esxi")
    row = await pending_row(env)
    assert await provider.snapshot(ctx, row) is True
    assert row.status == "ready" and row.quiesced is True and world.vm().snaps[-1].quiesced

    world.fake.quiesce_fails(1)
    log = vf.Lines()
    ctx = await again(world, env, log)
    second = await pending_row(env, "slipway-20261116T090100Z")
    assert await provider.snapshot(ctx, second) is False
    assert second.status == "ready" and second.quiesced is False
    assert ("VMware Tools couldn't quiesce the file systems; taking a crash-consistent snapshot instead") in log
    assert [c[1] for c in world.calls("take_snapshot")][-2:] == [("slipway-20261116T090100Z", True),
                                                                ("slipway-20261116T090100Z", False)]
    async with get_sessionmaker()() as db:
        stored = await db.get(MachineSnapshot, second.id)
        assert stored.status == "ready" and stored.quiesced is False


async def test_33_a_late_task_ends_ready_and_a_missing_one_failed(world, monkeypatch):
    env, ctx, _ = await made(world)
    provider = provider_for("esxi")
    world.fake.snapshot_task_late()
    row = await pending_row(env)
    await provider.snapshot(ctx, row)
    assert row.status == "ready" and row.note == "The task ended late"

    world.fake.fail("take_snapshot", "ESXi couldn't take the VM snapshot")
    lost = await pending_row(env, "slipway-20261116T090200Z")
    with pytest.raises(MachineError) as caught:
        await provider.snapshot(await again(world, env), lost)
    assert caught.value.text == f"ESXi didn't take the VM snapshot slipway-20261116T090200Z of {VM}"
    async with get_sessionmaker()() as db:
        assert (await db.get(MachineSnapshot, lost.id)).status == "failed"


async def test_33_revert_powers_on_after_and_drop_deletes(world):
    env, ctx, _ = await made(world)
    provider = provider_for("esxi")
    row = await pending_row(env)
    await provider.snapshot(ctx, row)
    world.fake.calls.clear()
    await provider.revert(await again(world, env), row)
    names = world.names()
    assert names.index("revert_snapshot") < names.index("power_on") < names.index("guest")
    assert world.vm().power == "poweredOn"
    await provider.drop_snapshot(await again(world, env), row)
    assert world.vm().snaps == []


async def test_33_a_duplicate_name_is_never_picked(world):
    env, ctx, _ = await made(world)
    provider = provider_for("esxi")
    row = await pending_row(env)
    await world.fake.take_snapshot(world.vm().uuid, row.name, quiesce=False)
    await world.fake.take_snapshot(world.vm().uuid, row.name, quiesce=False)
    world.fake.calls.clear()
    for call in (provider.revert, provider.drop_snapshot):
        with pytest.raises(MachineError) as caught:
            await call(await again(world, env), row)
        assert caught.value.text == (f"{VM} has 2 VM snapshots named {row.name} on ESXi, so Slipway won't pick one; "
                                     "Slipway changed nothing")
    assert not world.calls("revert_snapshot", "delete_snapshot")


async def blockers_of(world: World, env: vf.VmEnv) -> list[Blocker]:
    return await machines.blockers(await again(world, env, job=None))


async def test_33_destroy_blockers_each_forgettable_or_not(world, monkeypatch):
    env, _, _ = await made(world)
    assert await blockers_of(world, env) == []

    world.fake.add_file(f"{FOLDER}/extra.vmdk", 5)
    world.vm().disks.append(type(world.vm().disks[0])(2001, [f"{FOLDER}/extra.vmdk"], 5))
    assert await blockers_of(world, env) == [Blocker(f"{VM} has a disk Slipway didn't put there", True)]
    world.vm().disks.pop()

    world.vm().extra["slipway.machine"] = str(uuid.uuid4())
    assert await blockers_of(world, env) == [Blocker(
        f"The VM Slipway recorded for uat isn't {VM} with its marker any more; Slipway changed nothing", True)]
    world.vm().extra["slipway.machine"] = str(env.machines["blue"])

    world.fake.task_running("snapshot", 1000, uuid=world.vm().uuid)
    monkeypatch.setattr(machines, "TASK_WAIT_LIMIT", 10.0)
    (busy,) = await blockers_of(world, env)
    assert not busy.forgettable and busy.text.startswith(f"ESXi is still running VM snapshot on {VM} (since 10:00)")
    world.fake.tasks.clear()

    async with get_sessionmaker()() as db:
        account = await db.get(ProviderAccount, env.account_id)
        account.config = {**account.config, "url": "https://esxi-2.test"}
        await db.commit()
    assert await blockers_of(world, env) == [Blocker(
        f"{VM} was made on esxi.test, but the account now points at esxi-2.test; Slipway changed nothing", True)]


async def test_33_destroy_blocker_for_a_marked_vm_under_another_uuid(world):
    env, _, _ = await made(world)
    vm = world.vm()
    vm.power = "poweredOff"
    await world.fake.destroy(vm.uuid)
    world.fake.add_vm(VM, extra={"slipway.machine": str(env.machines["blue"]), "slipway.environment": str(env.env_id)})
    assert await blockers_of(world, env) == [Blocker(
        f"{VM} carries this environment's marker but isn't the VM Slipway recorded; remove it by hand", True)]


async def drop_instance(env: vf.VmEnv) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(delete(Instance).where(Instance.id == env.instances["blue"]))
        await db.commit()


async def test_33_remove_a_ready_vm_powers_it_off_destroys_it_and_checks_the_folder(world):
    env, _, _ = await made(world)
    world.fake.add_file(f"{FOLDER}/notes.log")
    await drop_instance(env)
    world.fake.calls.clear()
    done = await machines.remove(await again(world, env, job=None))
    assert await vm_rows(env) == []
    names = world.names()
    assert names.index("power_off") < names.index("destroy")
    assert {v.name for v in world.fake.vms.values()} == {SEED}
    assert done[0].startswith(f"Removed {VM} (") and done[0].endswith(") from ESXi")
    assert done[-1] == (f"ESXi left notes.log in {FOLDER}; Slipway no longer records them: delete them in the ESXi "
                        "Host Client")
    async with get_sessionmaker()() as db:
        assert await db.get(Machine, env.machines["blue"]) is None
        assert await db.get(Host, env.hosts["blue"]) is None
    (destroyed,) = await audits("machine.destroy")
    assert destroyed.details["name"] == VM


async def test_33_remove_an_unfinished_vm_deletes_its_unattached_disk_first(world):
    env = await blue_env(world)
    world.fake.fail("attach_disk", "ESXi couldn't attach the copied disk")
    with pytest.raises(MachineError):
        await machines.prepare(await ctx_for(world, env))
    assert DISK in world.fake.files and not world.vm().disks
    await drop_instance(env)
    world.fake.calls.clear()
    done = await machines.remove(await again(world, env, job=None))
    names = world.names()
    assert names.index("delete_disk") < names.index("destroy")
    assert DISK not in world.fake.files and FOLDER not in world.fake.dirs
    assert done[0] == f"Deleted {DISK}, which no VM had attached" and done[1].startswith(f"Removed {VM} (")
    assert len(done) == 2


async def test_33_remove_finds_an_unrecorded_vm_by_its_markers(world, monkeypatch):
    env = await blue_env(world)
    real = machines.record_vm

    async def record_vm(*args, **kw):
        raise MachineError("Slipway stopped here")

    monkeypatch.setattr(machines, "record_vm", record_vm)
    with pytest.raises(MachineError):
        await machines.prepare(await ctx_for(world, env))
    monkeypatch.setattr(machines, "record_vm", real)
    await drop_instance(env)
    done = await machines.remove(await again(world, env, job=None))
    assert done[0].startswith(f"Removed {VM} (") and VM not in {v.name for v in world.fake.vms.values()}


async def test_33_a_vm_still_there_after_destroy_is_refused(world, monkeypatch):
    env, _, _ = await made(world)
    await drop_instance(env)
    real = world.fake.destroy

    async def destroy(uuid_, *, on_task=None):  # ESXi answers, but the VM stays
        state = await world.fake._start("destroy", uuid_, on_task)
        world.fake._end(state)

    monkeypatch.setattr(world.fake, "destroy", destroy)
    with pytest.raises(MachineError) as caught:
        await machines.remove(await again(world, env, job=None))
    assert caught.value.text == (f"{VM} is still there after destroy. Remove it by hand in the ESXi Host Client, "
                                 "then retry")
    async with get_sessionmaker()() as db:  # nothing of it was forgotten
        assert (await db.get(Machine, env.machines["blue"])).stage == "destroying"
    assert len(await vm_rows(env)) == 1
    monkeypatch.setattr(world.fake, "destroy", real)
    done = await machines.remove(await again(world, env, job=None))  # the retry finishes it
    assert done[0].startswith(f"Removed {VM} (") and await vm_rows(env) == []


async def test_33_remove_with_nothing_made_says_so(world):
    env = await blue_env(world)
    await drop_instance(env)
    async with get_sessionmaker()() as db:  # an id-less machine past planned: the folder rule alone
        row = await db.get(Machine, env.machines["blue"])
        h = await db.get(Host, row.host_id)
        row.stage = "creating"
        hosts.set_phase(h, "creating", stage="creating")
        await db.commit()
    done = await machines.remove(await again(world, env, job=None))
    assert done == [f"Slipway never made {VM}"]


async def test_33_destroy_cancels_slipways_own_running_copy(world):
    env = await blue_env(world)
    world.fake.copy_cancelable(False)  # ESXi couldn't cancel it when the job's wait ran out
    world.fake.copy_cut(polls=50)
    with pytest.raises(MachineError):
        await machines.prepare(await ctx_for(world, env))
    last = (await machine(env)).last_task["id"]
    state = next(t for t in world.fake.tasks if t.ref.id == last)
    state.ref = dataclasses.replace(state.ref, cancelable=True)  # it can be cancelled now
    await drop_instance(env)
    log = vf.Lines()
    ctx = await again(world, env, log, job=None)
    assert await machines.blockers(ctx) == []  # Slipway's own copy doesn't block: it is cancelled
    await machines.remove(ctx)
    assert world.fake.cancelled == [last]
    assert f"Cancelled the disk copy {last} Slipway had started for {VM}" in log


# ------------------------------------------------------------------------------- test 66: ESXi tasks


async def test_66_a_running_task_is_waited_for_then_the_change_runs(world):
    env, _, _ = await made(world)
    world.fake.task_running("snapshot", 2, uuid=world.vm().uuid)
    log = vf.Lines()
    row = await pending_row(env)
    await provider_for("esxi").snapshot(await again(world, env, log), row)
    assert any(line.startswith(f"Waiting for ESXi's VM snapshot task on {VM} (started 10:00)") for line in log)
    assert row.status == "ready"


async def test_66_a_task_outliving_the_limit_refuses_with_nothing_changed(world, monkeypatch):
    env, _, _ = await made(world)
    world.fake.task_running("revert", 1000, uuid=world.vm().uuid)
    monkeypatch.setattr(machines, "TASK_WAIT_LIMIT", 15.0)
    world.fake.calls.clear()
    with pytest.raises(MachineError) as caught:
        await provider_for("esxi").stop(await again(world, env), timeout=60)
    assert caught.value.text == (f"ESXi is still running VM snapshot revert on {VM} (since 10:00); Slipway changed "
                                 "nothing. Wait for it to finish, or stop it in ESXi, then retry")
    assert not world.calls("shutdown_guest", "power_off")


async def test_66_every_task_is_in_last_task_before_its_wait_and_cleared_after(world):
    env = await blue_env(world)
    checked: list[str] = []

    async def on_start(ref):
        row = await machine(env)
        assert row.last_task is not None and row.last_task["id"] == ref.id and row.last_task["kind"] == ref.kind
        checked.append(ref.kind)

    world.fake.on_start = on_start
    await machines.prepare(await ctx_for(world, env))
    assert checked == ["create_vm", "copy_disk", "attach_disk", "grow_disk", "power_on", "set_extra_config"]
    assert (await machine(env)).last_task is None


async def test_66_a_task_that_times_out_stays_in_last_task_and_the_next_change_waits(world):
    env, ctx, _ = await made(world)
    world.fake.task_times_out("snapshot", polls=2)
    row = await pending_row(env)
    with pytest.raises(MachineError):
        await provider_for("esxi").snapshot(ctx, row)
    stuck = (await machine(env)).last_task
    assert stuck is not None and stuck["kind"] == "snapshot"
    assert row.status == "failed"
    log = vf.Lines()
    await provider_for("esxi").stop(await again(world, env, log), timeout=60)
    assert any(line.startswith("Waiting for ESXi's VM snapshot task") for line in log)
    assert not world.calls("cancel_task")  # D24: only a disk copy is ever cancelled


# -------------------------------------------------------------------------------------- the rest


async def test_no_secret_reaches_a_log_line_or_an_audit_row_across_a_build_and_a_remove(world):
    env = await blue_env(world)
    private = (await machine(env)).host_key_private
    client_key = (await host(env)).private_key
    log = vf.Lines()
    ctx = await ctx_for(world, env, log=log)
    await machines.prepare(ctx)
    assert vf.ESXI_PASSWORD not in ctx.hide.scrub(f"password {vf.ESXI_PASSWORD}")  # the job's redactor hides it
    await drop_instance(env)
    await machines.remove(await again(world, env, log, job=None))
    await no_secret_anywhere(env, log, private=private, client_key=client_key)


async def test_describe_reports_power_size_mode_and_snapshots(world):
    env, ctx, _ = await made(world)
    await snapshot_row(env, "slipway-20261115T100000Z")
    await world.fake.take_snapshot(world.vm().uuid, "slipway-20261115T100000Z", quiesce=True)
    await world.fake.take_snapshot(world.vm().uuid, "by-hand", quiesce=False)
    page = await vf.context(env.machines["blue"], connect=world.vms.connect)  # no job: a page read
    state = await provider_for("esxi").describe(page)
    assert state.exists and state.ours and state.power == "running" and state.snapshot_mode == "any"
    assert state.applied == {"cores": 4, "memory_mb": 8192, "disk_gb": 64} and state.addresses == [BLUE]
    assert [(s.name, s.ours, s.newest) for s in state.snapshots] == [
        ("slipway-20261115T100000Z", True, False), ("by-hand", False, True)]
    assert world.purposes[-1] == "read"


def test_applied_sizes_need_exactly_one_disk():
    disk = esxi.DiskInfo(key=1, path="[d] a/a.vmdk", base="[d] a/a.vmdk", chain=("[d] a/a.vmdk",), size_gb=64)
    info = esxi.VmInfo(moref="1", uuid="u", name="a", power="poweredOn", path="[d] a/a.vmx", cores=2, memory_mb=4096,
                       disks=(disk,))
    assert exp.applied_of(info) == {"cores": 2, "memory_mb": 4096, "disk_gb": 64}
    assert exp.applied_of(esxi.VmInfo(moref="1", uuid="u", name="a", power="x", path="p")) is None
    assert exp.applied_of(esxi.VmInfo(moref="1", uuid="u", name="a", power="x", path="p", cores=2, memory_mb=4096,
                                      disks=(disk, disk))) is None
