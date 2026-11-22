"""The machines core (phase 5 §6): tests 18, 19, 20, 21 (the core half, against a stub provider), 22, 24, 24b and 34.

Test 18 pins against a real asyncssh server on 127.0.0.1 (``vmnet.ALLOW_LOOPBACK``); everything else reaches VMs
through ``tests/fake_vm_hosts.py``. ``reserve_vmid`` asks FakeProxmox for ``nextid``. The provider is a stub
written here, so the driver's own rules are tested apart from Proxmox and ESXi (S11b and S13 run the real ones).
Also the audit actions the core writes (machine.plan, machine.ready, machine.reserve, machine.resize,
machine.left_off, machine.destroy, machine.forget, machine.rebuild, host.key_pinned with ``how``), none of which
may carry a key or a token.
"""

from __future__ import annotations

import asyncio
import json
import socket
import uuid
from typing import Any

import asyncssh
import pytest
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import IntegrityError

from slipway.db.base import utcnow
from slipway.db.session import get_sessionmaker
from slipway.models import (
    AddressClaim,
    AppSetting,
    AuditEvent,
    Deployment,
    Environment,
    Host,
    Instance,
    Machine,
    MachineSnapshot,
    Repository,
    Resource,
    TerraformState,
)
from slipway.services import hosts, machines, providers, proxmox, resources, ssh, terraform_store, vmnet
from slipway.services.terraform import StoredState
from slipway.services.vmtypes import Blocker, MachineError
from tests import fake_proxmox as fp
from tests import vm_fixtures as vf
from tests.fake_vm_hosts import VmRemote, probe_through

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")


# ------------------------------------------------------------------------------------------- the stub


async def committed(machine_id: uuid.UUID) -> tuple[str, str]:
    """(machines.stage, hosts.provider_state.phase) as another session sees them now."""
    async with get_sessionmaker()() as db:
        machine = await db.get(Machine, machine_id)
        host = await db.get(Host, machine.host_id)
        return machine.stage, host.provider_state["phase"]


class Stub:
    """A MachineProvider whose every answer the test sets."""

    name = "proxmox"
    label = "Proxmox"

    def __init__(self, multi: VmRemote | None = None) -> None:
        self.multi = multi
        self.calls: list[str] = []
        self.seen: list[tuple[str, str]] = []
        self.ensure_error: MachineError | None = None
        self.check_error: MachineError | None = None
        self.resize_error: MachineError | None = None
        self.describe_error: MachineError | None = None
        self.warnings: list[str] = []
        self.key: str | None = None
        self.power = "running"
        self.running_tasks: list[list[machines.Busy]] = []
        self.destroy_blockers_: list[Blocker] = []

    def freeze(self, account, network):
        return vf.SimpleFreeze().freeze(account, network)

    async def ensure(self, ctx):
        self.calls.append("ensure")
        if self.ensure_error is not None:
            raise self.ensure_error
        if ctx.machine.stage != "ready":
            await machines.set_stage(ctx, "creating")
            self.seen.append(await committed(ctx.machine.id))
            await machines.set_stage(ctx, "booting")
            self.seen.append(await committed(ctx.machine.id))
        address = ctx.machine.network["address"]
        key = self.key or (self.multi.pinned_key(address) if self.multi else None) or ctx.host.host_key
        return machines.Ensured(address=address, expected_key=key, how="read by the stub", warnings=list(self.warnings))

    async def after_pin(self, ctx):
        self.calls.append("after_pin")

    async def describe(self, ctx):
        self.calls.append("describe")
        if self.describe_error is not None:
            raise self.describe_error
        return machines.MachineState(exists=True, ours=True, power=self.power,
                                     applied=dict(ctx.machine.applied or ctx.machine.size), snapshot_mode="any")

    async def running(self, ctx):
        self.calls.append("running")
        return self.running_tasks.pop(0) if self.running_tasks else []

    async def check_resize(self, ctx):
        self.calls.append("check_resize")
        if self.check_error is not None:
            raise self.check_error
        return machines.ResizePlan(to=dict(ctx.machine.size), changes=["cores"])

    async def resize(self, ctx, plan):
        self.calls.append("resize")
        if self.resize_error is not None:
            raise self.resize_error
        return dict(plan.to)

    async def stop(self, ctx, *, timeout):
        self.calls.append("stop")

    async def destroy_blockers(self, ctx):
        self.calls.append("destroy_blockers")
        return list(self.destroy_blockers_)

    async def destroy(self, ctx):
        self.calls.append("destroy")
        return [f"Deleted {ctx.vm}"]


@pytest.fixture
def vms(tmp_path) -> VmRemote:
    return VmRemote(tmp_path)


@pytest.fixture
def net(monkeypatch) -> vf.Network:
    return vf.quiet_network(monkeypatch)


@pytest.fixture
def stub(monkeypatch, vms) -> Stub:
    s = Stub(vms)
    monkeypatch.setitem(providers.PROVIDERS, "proxmox", s)
    monkeypatch.setitem(providers.PROVIDERS, "esxi", s)
    return s


@pytest.fixture
def fast(monkeypatch):
    """Short part limits, so a time limit test takes a second."""
    monkeypatch.setitem(machines.PART_LIMITS, "cloud_init", 0.4)
    return machines.PART_LIMITS


async def audits(action: str | None = None) -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        stmt = select(AuditEvent).order_by(AuditEvent.created_at)
        if action:
            stmt = stmt.where(AuditEvent.action == action)
        return list(await db.scalars(stmt))


async def no_secret_in_audit(*secrets: str) -> None:
    blob = json.dumps([[a.summary, a.details] for a in await audits()], default=str)
    for secret in secrets:
        if secret:
            assert secret not in blob


async def blue_env(vms: VmRemote, *, docker: bool = False, mode: str = "slot", slots=("blue",), **kw: Any) -> vf.VmEnv:
    """An environment whose VMs are fake VMs at 10.0.0.100 (blue), .101 (green), .102 (data)."""
    account = await vf.proxmox_account()
    where = {"blue": "10.0.0.100", "green": "10.0.0.101", "data": "10.0.0.102"}
    wanted = [*slots, *(["data"] if mode == "server" else [])]
    for slot in wanted:
        vms.add_vm(slot, where[slot], docker=docker)
    return await vf.vm_env(account, mode=mode, slots=slots, addresses={s: where[s] for s in wanted},
                           deploy_roots={s: str(vms[s].tmp / "root") for s in wanted}, **kw)


async def deployment(env: vf.VmEnv, slot: str = "blue", *, status: str = "running") -> uuid.UUID:
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=env.instances[slot], environment_id=env.env_id, triggered_by_id=env.user_id,
                         branch="main", log="", status=status)
        db.add(dep)
        await db.commit()
        return dep.id


async def make_ready(env: vf.VmEnv, vms: VmRemote, slot: str = "blue", **fields: Any) -> None:
    """Mark a machine ready as a finished prepare leaves it (pinned, phase ready, applied = size)."""
    address = env.addresses[slot]
    key = vms.pinned_key(address)
    async with get_sessionmaker()() as db:
        machine = await db.get(Machine, env.machines[slot])
        host = await db.get(Host, machine.host_id)
        machine.stage, machine.ready_at = "ready", utcnow()
        machine.applied = {**machine.size, "at": utcnow().isoformat(), "deployment_id": None}
        machine.snapshot_mode = "any"
        for key_, value in fields.items():
            setattr(machine, key_, value)
        hosts.set_phase(host, "ready", stage="ready")
        host.host_key, host.host_key_fingerprint = key, ssh.fingerprint(key)
        await db.commit()


# ------------------------------------------------------------------------------------- test 18: pin


class _Server(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        return True


async def _exit_ok(process: asyncssh.SSHServerProcess) -> None:
    process.exit(0)


def _keypair() -> tuple[asyncssh.SSHKey, str]:
    key = asyncssh.generate_private_key("ssh-ed25519")
    return key, key.export_public_key().decode().strip()


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


LOOP = {"name": "loop", "bridge": "vmbr0", "subnet": "127.0.0.0/24", "gateway": "127.0.0.254", "dns_servers": [],
        "pool": None}


@pytest.fixture
async def loop_vm(monkeypatch, net):
    """A planned VM host at 127.0.0.1 and a real SSH server there presenting ``key``."""
    monkeypatch.setattr(vmnet, "ALLOW_LOOPBACK", True)
    key, public = _keypair()
    server = await asyncssh.create_server(_Server, "127.0.0.1", 0, server_host_keys=[key], process_factory=_exit_ok)
    monkeypatch.setattr(machines, "SSH_PORT", server.sockets[0].getsockname()[1])
    account = await vf.proxmox_account(networks=[LOOP])
    env = await vf.vm_env(account, network="loop", addresses={"blue": "127.0.0.1"})
    async with get_sessionmaker()() as db:
        host = await db.get(Host, env.hosts["blue"])
        machine = await db.get(Machine, env.machines["blue"])
    try:
        yield env, host, machine, public
    finally:
        server.close()
        await server.wait_closed()


async def _pinned(host_id: uuid.UUID) -> str | None:
    async with get_sessionmaker()() as db:
        return (await db.get(Host, host_id)).host_key


async def test_18_pin_after_a_real_ssh_connection_presenting_the_key(loop_vm):
    env, host, _machine, public = loop_vm
    sleeps: list[float] = []

    async def sleep(seconds):
        sleeps.append(seconds)

    pinned = await machines.pin(host, address="127.0.0.1", expected_key=public, how="read through the Proxmox guest agent",
                                connect=ssh.open_session, tries=3, poll=0.01, sleep=sleep, user_id=env.user_id)
    assert pinned == public and sleeps == []
    assert await _pinned(host.id) == public
    async with get_sessionmaker()() as db:
        row = await db.get(Host, host.id)
        assert row.host_key_fingerprint == ssh.fingerprint(public)
        assert row.provider_state["phase"] == "planned"  # pinning builds nothing by itself
    (event,) = await audits("host.key_pinned")
    assert event.details["how"] == "read through the Proxmox guest agent"
    assert event.details["fingerprint"] == ssh.fingerprint(public) and event.target_id == str(host.id)
    await no_secret_in_audit(host.private_key)


async def test_18_another_key_pins_nothing(loop_vm):
    _env, host, _machine, _public = loop_vm
    _, other = _keypair()
    with pytest.raises(MachineError, match="isn't the one read through the Proxmox guest agent. Slipway pinned nothing"):
        await machines.pin(host, address="127.0.0.1", expected_key=other, how="read through the Proxmox guest agent",
                           connect=ssh.open_session, tries=3, poll=0, sleep=vf.no_sleep)
    assert await _pinned(host.id) is None
    assert await audits("host.key_pinned") == []


async def test_18_a_reread_key_pins_once_it_matches(loop_vm):
    _env, host, machine, public = loop_vm
    _, stale = _keypair()
    reads = [stale, public]

    async def reread():
        return reads.pop(0)

    pinned = await machines.pin(host, address="127.0.0.1", expected_key=stale, how="read through the Proxmox guest agent",
                                connect=ssh.open_session, tries=5, poll=0, sleep=vf.no_sleep, reread_key=reread,
                                machine=machine)
    assert pinned == public and await _pinned(host.id) == public
    assert (await vf.machine_row(machine.id)).host_key_public == public  # the key read again is kept


async def test_18_a_reread_key_that_never_matches_pins_nothing(loop_vm):
    _env, host, machine, _public = loop_vm
    _, stale = _keypair()

    async def reread():
        return stale

    with pytest.raises(MachineError, match="Slipway pinned nothing"):
        await machines.pin(host, address="127.0.0.1", expected_key=stale, how="read through the Proxmox guest agent",
                           connect=ssh.open_session, tries=3, poll=0, sleep=vf.no_sleep, reread_key=reread,
                           machine=machine)
    assert await _pinned(host.id) is None


async def test_18_retries_while_the_port_refuses(loop_vm, monkeypatch):
    _env, host, _machine, public = loop_vm
    attempts: list[int] = []
    closed = _closed_port()

    def connect(target):
        attempts.append(target.port)
        if len(attempts) <= 2:
            target = ssh.SSHTarget(**{**target.__dict__, "port": closed})
        return ssh.open_session(target)

    sleeps: list[float] = []

    async def sleep(seconds):
        sleeps.append(seconds)

    await machines.pin(host, address="127.0.0.1", expected_key=public, how="generated by Slipway", connect=connect,
                       tries=5, poll=0.5, sleep=sleep)
    assert len(attempts) == 3 and sleeps == [0.5, 0.5]
    assert await _pinned(host.id) == public


async def test_18_a_port_that_never_answers_names_the_wait(loop_vm, monkeypatch):
    _env, host, _machine, public = loop_vm
    monkeypatch.setattr(machines, "SSH_PORT", _closed_port())
    with pytest.raises(MachineError, match=r"slipway-uat-blue didn't answer SSH at 127.0.0.1 in 1 minute$"):
        await machines.pin(host, address="127.0.0.1", expected_key=public, how="generated by Slipway",
                           connect=ssh.open_session, tries=2, poll=1, sleep=vf.no_sleep, vm="slipway-uat-blue")
    assert await _pinned(host.id) is None


async def test_18_refused_at_another_hosts_address(loop_vm):
    _env, host, _machine, public = loop_vm
    async with get_sessionmaker()() as db:
        db.add(Host(name="nas", hostname="nas.lan", lan_address="127.0.0.1", username="root", metrics={}))
        await db.commit()
    calls: list[Any] = []
    with pytest.raises(MachineError, match="127.0.0.1 is the address of host nas; Slipway won't pin a VM's key there"):
        await machines.pin(host, address="127.0.0.1", expected_key=public, how="generated by Slipway",
                           connect=lambda t: calls.append(t), tries=1, poll=0, sleep=vf.no_sleep)
    assert calls == [] and await _pinned(host.id) is None


async def test_18_an_address_change_meanwhile_writes_nothing(loop_vm):
    _env, host, _machine, public = loop_vm

    def connect(target):
        async def move():
            async with get_sessionmaker()() as db:
                await db.execute(update(Host).where(Host.id == host.id).values(hostname="127.0.0.2"))
                await db.commit()

        class Moving:
            async def __aenter__(self):
                await move()
                self.inner = ssh.open_session(target)
                return await self.inner.__aenter__()

            async def __aexit__(self, *exc):
                return await self.inner.__aexit__(*exc)

        return Moving()

    with pytest.raises(MachineError, match="slipway-uat-blue changed while Slipway was pinning it; Slipway pinned nothing"):
        await machines.pin(host, address="127.0.0.1", expected_key=public, how="generated by Slipway", connect=connect,
                           tries=1, poll=0, sleep=vf.no_sleep)
    assert await _pinned(host.id) is None
    assert await audits("host.key_pinned") == []


# --------------------------------------------------------------------------------- test 19: registry


async def test_19_the_registry_names_every_holder(net):
    net.names.update({"proxy.lan": ["10.0.0.21"], "sw.lan": ["10.0.0.30"], "gone.lan": []})
    account = await vf.proxmox_account()
    planned = await vf.vm_env(account, name="uat", addresses={"blue": "10.0.0.101"})
    async with get_sessionmaker()() as db:
        db.add_all([
            Host(name="web1", hostname="10.0.0.20", proxy_address="proxy.lan", lan_address="10.0.0.22", username="root",
                 metrics={}),
            Host(name="old", hostname="gone.lan", username="root", metrics={}),
            AppSetting(key="switchyard", value={"url": "https://sw.lan:8443", "traffic_address": "10.0.0.31:443"},
                       secret="sw-key"),
        ])
        await db.commit()
        held = await machines.addresses_in_use(db, network=vf.LAN_PVE)
        assert held == {
            "10.0.0.101": "is reserved for uat's blue VM",
            "10.0.0.20": "is used by host web1",
            "10.0.0.21": "is used by host web1",
            "10.0.0.22": "is used by host web1",
            "10.0.0.2": "is the Proxmox API's address",
            "10.0.0.31": "is Switchyard's traffic address",
            "10.0.0.30": "is Switchyard's address",
            "10.0.0.1": "is the network's gateway",
            "10.0.0.53": "is one of the network's DNS servers",
        }
        assert "gone.lan" in net.resolved and "proxy.lan" in net.resolved  # names go through the resolver
        assert await machines.address_problem(db, "10.0.0.21") == "10.0.0.21 is used by host web1"
        assert await machines.address_problem(db, "10.0.0.130", network=vf.LAN_PVE) is None
        # A VM checking its own address again leaves out its own claim and host row.
        assert "10.0.0.101" not in await machines.addresses_in_use(db, except_host_id=planned.hosts["blue"])

        env = await db.get(Environment, planned.env_id)
        acct = await db.get(type(account), account.id)
        for address, text_ in (("10.0.0.20", "10.0.0.20 is used by host web1"),
                               ("10.0.0.101", "10.0.0.101 is reserved for uat's blue VM"),
                               ("10.0.0.2", "10.0.0.2 is the Proxmox API's address"),
                               ("10.0.0.31", "10.0.0.31 is Switchyard's traffic address"),
                               ("10.0.0.53", "10.0.0.53 is one of the network's DNS servers")):
            with pytest.raises(machines.PlanProblem) as caught:
                await machines.plan(db, env, "green", acct, "lan", address, None, None, provider=vf.SimpleFreeze())
            assert caught.value.text == text_ and caught.value.field == "hosts.green.machine.address"
        with pytest.raises(machines.PlanProblem, match="10.0.0.1 is network lan's gateway"):
            await machines.plan(db, env, "green", acct, "lan", "10.0.0.1", None, None, provider=vf.SimpleFreeze())
        # auto skips every held address: the pool starts at .100, .101 is blue's.
        _host, machine = await machines.plan(db, env, "green", acct, "lan", "auto", None, None, provider=vf.SimpleFreeze())
        assert machine.network["address"] == "10.0.0.100"
        await db.rollback()


async def test_19_the_live_probe_before_a_new_vm_boots(net, stub, vms):
    env = await blue_env(vms)
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)
    await machines.check_address_free(ctx)
    assert net.probed == [("10.0.0.100", 22)]
    net.open.add("10.0.0.100")
    with pytest.raises(MachineError, match="Something already answers SSH at 10.0.0.100, so Slipway won't give"):
        await machines.check_address_free(ctx)
    await machines.check_address_free(ctx, probe=False)  # the VM there is the machine's own
    async with get_sessionmaker()() as db:
        db.add(Host(name="nas", hostname="10.0.0.100", username="root", metrics={}))
        await db.commit()
    with pytest.raises(MachineError, match="10.0.0.100 is used by host nas, so Slipway won't give it to slipway-uat-blue"):
        await machines.check_address_free(ctx, probe=False)


# ------------------------------------------------------------------------------------- test 20: plan


async def test_20_plan_writes_the_host_the_claim_and_the_machine(net):
    account = await vf.proxmox_account()
    env = await vf.vm_env(account, mode="server", slots=("blue", "green"),
                          addresses={"blue": "10.0.0.110", "green": "auto"}, size={"cores": 2, "disk_gb": 80})
    async with get_sessionmaker()() as db:
        blue = await db.get(Host, env.hosts["blue"])
        assert (blue.name, blue.hostname, blue.port, blue.username, blue.label) == (
            "slipway-uat-blue", "10.0.0.110", 22, "slipway", "uat")
        assert blue.description == "VM Slipway made for uat's blue slot on lab"
        assert blue.provider == "proxmox" and blue.owner_environment_id == env.env_id
        assert blue.host_key is None and blue.host_key_fingerprint is None
        assert blue.provider_state == {"phase": "planned", "stage": "planned"} and not blue.is_built
        assert blue.private_key.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
        assert blue.public_key == ssh.public_key_from_private(blue.private_key)
        assert blue.public_key.endswith("slipway@slipway-uat-blue") and blue.auth_method == "key"
        claims = {c.address: c.host_id for c in await db.scalars(select(AddressClaim))}
        assert claims == {"10.0.0.110": env.hosts["blue"], "10.0.0.100": env.hosts["green"],
                          "10.0.0.101": env.hosts["data"]}
        machine = await db.get(Machine, env.machines["blue"])
        assert (machine.stage, machine.slot, machine.name, machine.provider, machine.account_id) == (
            "planned", "blue", "slipway-uat-blue", "proxmox", account.id)
        assert machine.spec == {"node": "pve1", "pool": "slipway", "storage": "local-lvm", "storage_type": "lvmthin",
                                "file_format": None, "template_vmid": 9000, "bridge": "vmbr0", "vlan_tag": None}
        assert machine.network == {"name": "lan", "address": "10.0.0.110", "prefix": 24, "gateway": "10.0.0.1",
                                   "dns_servers": ["10.0.0.53"]}
        assert machine.size == {"cores": 2, "memory_mb": 8192, "disk_gb": 80}
        assert machine.applied is None and machine.ids == {} and machine.host_key_public is None
        assert machine.keep_vm_snapshots == 3 and machine.host_key_private is None
        assert machines.stage_of(blue) == "planned"
    (first, *_rest) = await audits("machine.plan")
    assert first.details == {"environment": "uat", "slot": "blue", "account": "lab", "network": "lan",
                             "address": "10.0.0.110", "size": {"cores": 2, "memory_mb": 8192, "disk_gb": 80}}
    assert len(await audits("machine.plan")) == 3


async def test_20_esxi_gets_an_encrypted_host_key_pair(net):
    account = await vf.esxi_account()
    env = await vf.vm_env(account)
    async with get_sessionmaker()() as db:
        machine = await db.get(Machine, env.machines["blue"])
        public = machine.host_key_public
        assert public.startswith("ssh-ed25519 ") and ssh.fingerprint(public)
        private = machine.host_key_private
        assert private.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
        assert asyncssh.import_private_key(private).export_public_key().decode().split()[:2] == public.split()[:2]
        raw = await db.scalar(text("SELECT host_key_private FROM machines WHERE id = :id"),
                              {"id": machine.id.hex if db.bind.dialect.name == "sqlite" else machine.id})
        assert raw and raw != private and "PRIVATE KEY" not in raw  # stored encrypted
        assert machine.spec["api_host"] == "esxi.test" and machine.spec["port_group"] == "VM Network"
    await no_secret_in_audit(private)


async def test_20_a_taken_host_name_and_other_refusals(net):
    account = await vf.proxmox_account()
    env = await vf.vm_env(account)
    async with get_sessionmaker()() as db:
        db.add(Host(name="slipway-uat-green", hostname="10.0.0.9", username="root", metrics={}))
        await db.commit()
        env_row = await db.get(Environment, env.env_id)
        acct = await db.get(type(account), account.id)
        with pytest.raises(machines.PlanProblem) as caught:
            await machines.plan(db, env_row, "green", acct, "lan", "auto", None, None, provider=vf.SimpleFreeze())
        assert caught.value.text == ("A host named slipway-uat-green already exists: rename it, or pick another "
                                     "environment name") and caught.value.field == "hosts.green"
        with pytest.raises(machines.PlanProblem, match="lab has no network named wan"):
            await machines.plan(db, env_row, "data", acct, "wan", "auto", None, None, provider=vf.SimpleFreeze())
        with pytest.raises(machines.PlanProblem, match="Memory must be between"):
            await machines.plan(db, env_row, "data", acct, "lan", "auto", {"memory_mb": 1024}, None,
                                provider=vf.SimpleFreeze())
        with pytest.raises(machines.PlanProblem, match="isn't in network lan's subnet"):
            await machines.plan(db, env_row, "data", acct, "lan", "192.168.1.5", None, None, provider=vf.SimpleFreeze())
        await db.rollback()


async def test_20_a_claim_conflict_at_commit_writes_nothing(net):
    account = await vf.proxmox_account()
    user = await vf.a_user()
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=7, full_name="acme/web", owner="acme", name="web", html_url="https://github.com/acme/web")
        db.add(repo)
        for name in ("one", "two"):
            db.add(Environment(name=name, repository=repo, branch="main", data_mode="slot", app_settings={},
                               traffic={"switch": "none", "dns": None}, hostnames=[]))
        await db.commit()

    async def planned(db, name):
        env = await db.scalar(select(Environment).where(Environment.name == name))
        acct = await db.get(type(account), account.id)
        return await machines.plan(db, env, "blue", acct, "lan", "10.0.0.120", None, user, provider=vf.SimpleFreeze())

    first, second = get_sessionmaker()(), get_sessionmaker()()
    try:
        await planned(first, "one")
        await planned(second, "two")  # both checked the registry before either committed
        await first.commit()
        with pytest.raises(IntegrityError):
            await second.commit()
        await second.rollback()
    finally:
        await first.close()
        await second.close()
    async with get_sessionmaker()() as db:
        assert [h.name for h in await db.scalars(select(Host).order_by(Host.name))] == ["slipway-one-blue"]
        assert [m.name for m in await db.scalars(select(Machine))] == ["slipway-one-blue"]
        assert [(c.address) for c in await db.scalars(select(AddressClaim))] == ["10.0.0.120"]
        assert await db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "machine.plan")) == 1


# ----------------------------------------------------------------------------------- test 21: prepare


async def test_21_a_new_vm_is_made_pinned_bootstrapped_and_ready(net, stub, vms, monkeypatch):
    env = await blue_env(vms)
    dep = await deployment(env)
    probe = probe_through(vms)
    phases_at_probe: list[str] = []

    async def probe_and_look(target):
        async with get_sessionmaker()() as db:
            phases_at_probe.append((await db.get(Host, env.hosts["blue"])).provider_state["phase"])
        return await probe(target)

    monkeypatch.setattr(hosts.ssh, "probe", probe_and_look)
    log = vf.Lines()
    ctx = await vf.context(env.machines["blue"], connect=vms.connect, deployment_id=dep, user_id=env.user_id, say=log)
    status, note = await machines.prepare(ctx)
    assert (status, note) == ("succeeded", "slipway-uat-blue is ready at 10.0.0.100")
    # Each stage change committed on its own, with the host's phase in the same transaction.
    assert stub.seen == [("creating", "creating"), ("booting", "creating")]
    assert await committed(env.machines["blue"]) == ("ready", "ready")
    assert stub.calls == ["ensure", "after_pin", "describe"]
    # check_host ran with building=True after the bootstrap, while the host wasn't built yet, and filled Docker's version.
    assert phases_at_probe == ["creating"] and len(probe.seen) == 1
    async with get_sessionmaker()() as db:
        machine = await db.get(Machine, env.machines["blue"])
        host = await db.get(Host, env.hosts["blue"])
        assert machine.ready_at is not None and machine.last_error is None and machine.snapshot_mode == "any"
        assert machine.applied == {"cores": 4, "memory_mb": 8192, "disk_gb": 64, "at": machine.applied["at"],
                                   "deployment_id": dep.hex}
        assert host.docker_version == "26.1.3" and host.status == "healthy" and host.is_built
        assert host.host_key == vms.pinned_key("10.0.0.100")
        assert host.provider_state == {"phase": "ready", "stage": "ready"}
    (ready,) = await audits("machine.ready")
    assert ready.details == {"name": "slipway-uat-blue", "address": "10.0.0.100",
                             "applied": {"cores": 4, "memory_mb": 8192, "disk_gb": 64}}
    assert ready.actor_id == env.user_id
    (pinned,) = await audits("host.key_pinned")
    assert pinned.details["how"] == "read by the stub"
    assert "Pinned slipway-uat-blue's host key (read by the stub)" in log
    async with get_sessionmaker()() as db:
        host = await db.get(Host, env.hosts["blue"])
    await no_secret_in_audit(host.private_key)


async def test_21_a_ready_vm_with_the_api_down_is_a_warning_and_nothing_else_runs(net, stub, vms):
    env = await blue_env(vms, docker=True)
    await make_ready(env, vms)
    stub.ensure_error = proxmox.ProxmoxError("Slipway couldn't reach Proxmox at pve.test:8006", unreachable=True)
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)
    status, note = await machines.prepare(ctx)
    assert (status, note) == ("warning", "Couldn't reach Proxmox to check slipway-uat-blue; carrying on over SSH")
    assert stub.calls == ["ensure"] and vms.targets == []
    assert await committed(env.machines["blue"]) == ("ready", "ready")


async def test_21_an_unusable_account_is_a_warning_only_for_a_ready_vm_without_a_resize(net, stub, vms):
    env = await blue_env(vms, docker=True, slots=("blue", "green"), mode="slot")
    await make_ready(env, vms, "blue")
    async with get_sessionmaker()() as db:
        acct = await db.get(type((await vf.machine_row(env.machines["blue"])).account), env.account_id)
        acct.secret = None
        await db.commit()
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)
    status, note = await machines.prepare(ctx)
    assert status == "warning" and "its API token is missing" in note and note.endswith("carrying on over SSH")
    assert stub.calls == []
    green = await vf.context(env.machines["green"], connect=vms.connect)
    with pytest.raises(MachineError, match=r"^Proxmox account lab can't be used: its API token is missing or can't be "
                                           r"read with SLIPWAY_ENCRYPTION_KEY. Fix it in Settings → Integrations"):
        await machines.prepare(green)
    assert (await vf.machine_row(env.machines["green"])).last_error.startswith("Proxmox account lab can't be used")


async def test_21_a_resize_to_apply_with_the_api_down_fails(net, stub, vms):
    env = await blue_env(vms, docker=True)
    await make_ready(env, vms, size={"cores": 8, "memory_mb": 8192, "disk_gb": 64})
    stub.ensure_error = MachineError("down", unreachable=True)
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)
    with pytest.raises(MachineError, match="^Slipway can't reach lab to resize slipway-uat-blue$"):
        await machines.prepare(ctx, resize=True)
    assert (await vf.machine_row(env.machines["blue"])).last_error == "Slipway can't reach lab to resize slipway-uat-blue"


async def test_21_check_resize_reads_only_and_its_refusal_fails_prepare(net, stub, vms):
    env = await blue_env(vms, docker=True)
    await make_ready(env, vms, size={"cores": 8, "memory_mb": 16384, "disk_gb": 128})
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)
    status, note = await machines.prepare(ctx, resize=True)
    assert status == "succeeded"
    assert note == "slipway-uat-blue is resized to 8 vCPU, 16 GB, 128 GB after the backup"
    assert stub.calls == ["ensure", "check_resize"]  # never stop or resize: prepare doesn't shut a ready VM down
    assert vms.targets == []  # the pinned key is unchanged, so prepare opens no SSH session

    stub.calls.clear()
    stub.check_error = MachineError("ESXi can't grow a disk that has snapshots Slipway didn't take.")
    with pytest.raises(MachineError) as caught:
        await machines.prepare(ctx, resize=True)
    assert caught.value.text == ("ESXi can't grow a disk that has snapshots Slipway didn't take. To deploy without the "
                                 "resize, set slipway-uat-blue's size back to 4 vCPU, 8 GB, 64 GB on the environment page")
    assert "stop" not in stub.calls and "resize" not in stub.calls
    # Without a resize step in the job, the stored size isn't checked at all.
    stub.calls.clear()
    assert await machines.prepare(ctx) == ("succeeded", None)
    assert stub.calls == ["ensure"]


async def test_21_a_part_that_runs_out_of_time_is_named(net, stub, vms, monkeypatch, fast):
    env = await blue_env(vms)
    monkeypatch.setattr(hosts.ssh, "probe", probe_through(vms))
    vms.cloud_init("10.0.0.100", "running", sleep=2)
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)
    with pytest.raises(MachineError, match=r"^cloud-init didn't finish on slipway-uat-blue in 0.4 seconds$"):
        await machines.prepare(ctx)
    machine = await vf.machine_row(env.machines["blue"])
    assert machine.stage == "booting" and machine.last_error == "cloud-init didn't finish on slipway-uat-blue in 0.4 seconds"
    monkeypatch.setitem(machines.PART_LIMITS, "docker", 0.4)
    vms.cloud_init("10.0.0.100", "done")
    (vms.vm_bin / "apt-get").write_text("#!/bin/sh\nsleep 2\n")
    with pytest.raises(MachineError, match=r"^Timed out after 0.4 seconds installing Docker on slipway-uat-blue$"):
        await machines.prepare(ctx)


async def test_21_any_other_failure_keeps_last_error_and_the_stage(net, stub, vms, monkeypatch):
    env = await blue_env(vms)
    monkeypatch.setattr(hosts.ssh, "probe", probe_through(vms))  # the retry's check_host probes the fake VM
    stub.ensure_error = MachineError("Terraform couldn't make slipway-uat-blue. See the log above.")
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)
    with pytest.raises(MachineError, match="Terraform couldn't make"):
        await machines.prepare(ctx)
    machine = await vf.machine_row(env.machines["blue"])
    assert machine.stage == "planned" and machine.last_error == "Terraform couldn't make slipway-uat-blue. See the log above."
    # A retry that succeeds clears it.
    stub.ensure_error = None
    await machines.prepare(ctx)
    assert (await vf.machine_row(env.machines["blue"])).last_error is None


async def test_21_a_mismatched_key_fails_the_pin_and_keeps_the_stage(net, stub, vms):
    env = await blue_env(vms)
    _, stub.key = _keypair()
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)
    with pytest.raises(MachineError, match="isn't the one read by the stub. Slipway pinned nothing"):
        await machines.prepare(ctx)
    machine = await vf.machine_row(env.machines["blue"])
    assert machine.stage == "booting" and "Slipway pinned nothing" in machine.last_error
    assert await _pinned(env.hosts["blue"]) is None


async def test_21_provider_warnings_make_the_step_a_warning(net, stub, vms, monkeypatch):
    env = await blue_env(vms)
    monkeypatch.setattr(hosts.ssh, "probe", probe_through(vms))
    stub.warnings = ["The guest agent never answered; SSH works, so Slipway carried on"]
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)
    status, note = await machines.prepare(ctx)
    assert status == "warning" and note.endswith("SSH works, so Slipway carried on")


async def test_21_a_vm_being_removed_is_refused(net, stub, vms):
    env = await blue_env(vms)
    async with get_sessionmaker()() as db:
        machine = await db.get(Machine, env.machines["blue"])
        machine.stage = "destroying"
        await db.commit()
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)
    with pytest.raises(MachineError, match="is being removed"):
        await machines.prepare(ctx)
    assert stub.calls == []


# ---------------------------------------------------------------------------------- test 22: bootstrap


def _after(log: list[str], wanted: list[str]) -> bool:
    """Each of ``wanted`` appears in ``log``, in this order."""
    at = 0
    for line in log:
        if at < len(wanted) and line == wanted[at]:
            at += 1
    return at == len(wanted)


async def test_22_bootstrap_runs_its_commands_in_order_through_sudo(net, stub, vms):
    env = await blue_env(vms)
    await make_ready(env, vms)  # pinned; the stage doesn't matter to bootstrap
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)
    root = str(vms["blue"].tmp / "root")
    version = await machines.bootstrap(ctx)
    assert version == "26.1.3"
    log = vms.vm_log("10.0.0.100")
    lock = "-o DPkg::Lock::Timeout=600"
    assert _after(log, [
        "sudo -n true",
        "docker compose version",
        f"sudo -n apt-get {lock} update -q",
        f"apt-get {lock} update -q",
        f"sudo -n env DEBIAN_FRONTEND=noninteractive apt-get {lock} install -y -q docker.io docker-compose-v2",
        f"apt-get {lock} install -y -q docker.io docker-compose-v2",
        "sudo -n systemctl enable --now docker",
        "systemctl enable --now docker",
        "id -nG slipway",
        "sudo -n usermod -aG docker slipway",
        "usermod -aG docker slipway",
        f"sudo -n install -d -o slipway -g slipway -m 0755 {root}",
        f"install -d -o slipway -g slipway -m 0755 {root}",
        "docker info --format {{.ServerVersion}}",
    ]), log
    assert [line for line in log if line.startswith("apt-get")] == [
        f"apt-get {lock} update -q", f"apt-get {lock} install -y -q docker.io docker-compose-v2"]
    assert vms["blue"].cloud_init() == ["status --wait"]
    # A new session after usermod: the check ran in a session that has the docker group.
    assert vms.sessions == [("10.0.0.100", "slipway sudo"), ("10.0.0.100", "slipway sudo docker")]
    assert (vms["blue"].tmp / "root").is_dir()
    # Every remote command names the slipway user, and every root command goes through sudo -n.
    commands = vms["blue"].remote.commands
    assert commands[0] == "sudo -n true"
    assert any("usermod -aG docker slipway" in c for c in commands) and all("deploy" not in c for c in commands)


async def test_22_running_it_twice_changes_nothing(net, stub, vms):
    env = await blue_env(vms)
    await make_ready(env, vms)
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)
    await machines.bootstrap(ctx)
    before = len(vms.vm_log("10.0.0.100"))
    await machines.bootstrap(ctx)
    again = vms.vm_log("10.0.0.100")[before:]
    assert not any(line.startswith(("apt-get", "usermod", "sudo -n apt-get", "sudo -n usermod")) for line in again)
    assert "docker compose version" in again and "id -nG slipway" in again


async def test_22_docker_already_in_the_template_is_not_installed(net, stub, vms):
    env = await blue_env(vms, docker=True)
    await make_ready(env, vms)
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)
    await machines.bootstrap(ctx)
    log = vms.vm_log("10.0.0.100")
    assert not any("apt-get" in line for line in log) and not any("usermod" in line for line in log)


async def test_22_the_package_lock_is_waited_for_and_beyond_the_timeout_refused(net, stub, vms):
    env = await blue_env(vms)
    await make_ready(env, vms)
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)
    vms.dpkg_locked("10.0.0.100", 30)
    await machines.bootstrap(ctx)
    assert "Waited 30s for the dpkg lock held by unattended-upgr" in vms.vm_log("10.0.0.100")
    assert vms.docker_installed("10.0.0.100")

    vms.add_vm("green", "10.0.0.120")
    env2 = await vf.vm_env(await vf.proxmox_account(name="lab2"), name="two", addresses={"blue": "10.0.0.120"},
                           deploy_roots={"blue": str(vms["green"].tmp / "root")})
    await make_ready(env2, vms)
    ctx2 = await vf.context(env2.machines["blue"], connect=vms.connect)
    vms.dpkg_locked("10.0.0.120", 601)
    with pytest.raises(MachineError) as caught:
        await machines.bootstrap(ctx2)
    assert caught.value.text == ("Something on slipway-two-blue (usually unattended-upgrades) held the package lock for "
                                 "10 minutes; retry the deploy")


async def test_22_the_fake_apt_without_the_lock_option_fails_at_once(vms):
    vm = vms.add_vm("blue", "10.0.0.100")
    vms.dpkg_locked("10.0.0.100", 5)
    async with vms.connect(ssh.SSHTarget(hostname="10.0.0.100", port=22, username="slipway",
                                         pinned_host_key=vms.pinned_key("10.0.0.100"))) as session:
        code, out = await session.run("sudo -n apt-get update -q", check=False)
        assert code == 100 and "Could not get lock /var/lib/dpkg/lock-frontend" in out
        code, _ = await session.run("apt-get -o DPkg::Lock::Timeout=600 update -q", check=False)
        assert code == 1  # not root without sudo
    assert vm.name == "blue"


@pytest.mark.parametrize("knob, text_", [
    ("no_sudo", "slipway-uat-blue's slipway user can't use sudo without a password; check the template's cloud-init"),
    ("cloud_init_error", "cloud-init reported an error on slipway-uat-blue: errors: Failed to run module scripts-user"),
    ("apt_fails", "Couldn't install Docker on slipway-uat-blue: E: Unable to locate package docker-compose-v2"),
])
async def test_22_each_refusal_text(net, stub, vms, knob, text_):
    env = await blue_env(vms)
    await make_ready(env, vms)
    if knob == "no_sudo":
        vms.no_sudo("10.0.0.100")
    elif knob == "cloud_init_error":
        vms.cloud_init("10.0.0.100", "error")
    else:
        vms.apt_fails("10.0.0.100")
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)
    with pytest.raises(MachineError) as caught:
        await machines.bootstrap(ctx)
    assert caught.value.text == text_


async def test_22_cloud_init_timeout_text(net, stub, vms, fast):
    env = await blue_env(vms)
    await make_ready(env, vms)
    vms.cloud_init("10.0.0.100", "running", sleep=2)
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)
    with pytest.raises(MachineError, match="^cloud-init didn't finish on slipway-uat-blue in 0.4 seconds$"):
        await machines.bootstrap(ctx)


# ------------------------------------------------------------------------------- tests 24 and 24b: ids


@pytest.fixture
def pve(monkeypatch, tmp_path) -> fp.FakeProxmox:
    return fp.FakeProxmox(tmp_path / "pve.json").install(monkeypatch)


async def _machine(machine_id: uuid.UUID) -> Machine:
    async with get_sessionmaker()() as db:
        return await db.get(Machine, machine_id)


async def _vm_rows() -> list[Resource]:
    async with get_sessionmaker()() as db:
        return list(await db.scalars(select(Resource).where(Resource.kind == "vm").order_by(Resource.provider_id)))


async def test_24_an_id_race_between_environments(net, pve):
    account = await vf.proxmox_account()
    one = await vf.vm_env(account, name="one", addresses={"blue": "10.0.0.110"})
    two = await vf.vm_env(account, name="two", addresses={"blue": "10.0.0.111"})
    async with proxmox.ProxmoxClient.for_account(account) as api:
        first = await machines.reserve_vmid(await _machine(one.machines["blue"]), account, api=api, user_id=one.user_id)
        second = await machines.reserve_vmid(await _machine(two.machines["blue"]), account, api=api)
    assert (first, second) == (100, 101)  # both got nextid 100; the second counted it taken
    assert (await _machine(one.machines["blue"])).ids == {"vmid": 100}
    assert (await _machine(two.machines["blue"])).ids == {"vmid": 101}
    rows = await _vm_rows()
    assert [(r.provider_id, r.name, r.details["machine_id"], r.environment_id, r.instance_id) for r in rows] == [
        (f"{account.id}:100", "slipway-one-blue", str(one.machines["blue"]), one.env_id, one.instances["blue"]),
        (f"{account.id}:101", "slipway-two-blue", str(two.machines["blue"]), two.env_id, two.instances["blue"]),
    ]
    assert all(r.details["node"] == "pve1" for r in rows)
    reserved = await audits("machine.reserve")
    assert [e.details for e in reserved] == [{"name": "slipway-one-blue", "vmid": 100},
                                             {"name": "slipway-two-blue", "vmid": 101}]
    assert reserved[0].actor_id == one.user_id
    await no_secret_in_audit(fp.TOKEN, fp.TOKEN_SECRET)


async def test_24_twenty_taken_ids_give_the_text(net, pve):
    account = await vf.proxmox_account()
    one = await vf.vm_env(account, name="one", addresses={"blue": "10.0.0.110"})
    two = await vf.vm_env(account, name="two", addresses={"blue": "10.0.0.111"})
    async with get_sessionmaker()() as db:
        for vmid in range(100, 125):
            db.add(Resource(environment_id=one.env_id, provider="proxmox", kind="vm", provider_id=f"{account.id}:{vmid}",
                            name=f"held-{vmid}", origin="created", details={"machine_id": str(uuid.uuid4())}))
        await db.commit()
    async with proxmox.ProxmoxClient.for_account(account) as api:
        with pytest.raises(MachineError, match=r"^Slipway couldn't find a free VM id in 20 tries \(from 100\): other "
                                               r"machines hold the next ones reserved$"):
            await machines.reserve_vmid(await _machine(two.machines["blue"]), account, api=api)
    assert (await _machine(two.machines["blue"])).ids == {}


async def test_24_a_crash_between_the_row_and_the_ids_gives_the_id_back(net, pve):
    account = await vf.proxmox_account()
    env = await vf.vm_env(account)
    machine = await _machine(env.machines["blue"])
    await resources.record(env.env_id, "proxmox", "vm", f"{account.id}:104", machine.name, "created",
                           details={"machine_id": str(machine.id), "node": "pve1"})
    async with proxmox.ProxmoxClient.for_account(account) as api:
        assert await machines.reserve_vmid(machine, account, api=api) == 104
    assert (await _machine(machine.id)).ids == {"vmid": 104}
    assert pve.calls("GET", "/cluster/nextid") == []  # nothing new was asked for
    assert len(await _vm_rows()) == 1


async def test_24b_a_slot_never_takes_another_slots_reserved_id(net, pve):
    with pve.edit() as state:
        state["first_free"] = 106
    account = await vf.proxmox_account()
    env = await vf.vm_env(account, mode="server", slots=("blue", "green"))
    other = await vf.vm_env(account, name="other", addresses={"blue": "10.0.0.140"})
    async with get_sessionmaker()() as db:  # another environment's machine holds 108 only in its ids
        row = await db.get(Machine, other.machines["blue"])
        row.ids = {"vmid": 108}
        await db.commit()
    async with proxmox.ProxmoxClient.for_account(account) as api:
        blue = await machines.reserve_vmid(await _machine(env.machines["blue"]), account, api=api)
        # blue fails before its clone: nothing is made, so Proxmox's nextid still answers 106
        green = await machines.reserve_vmid(await _machine(env.machines["green"]), account, api=api)
        data = await machines.reserve_vmid(await _machine(env.machines["data"]), account, api=api)
    assert (blue, green, data) == (106, 107, 109)
    rows = {r.provider_id: r for r in await _vm_rows()}
    assert rows[f"{account.id}:106"].details["machine_id"] == str(env.machines["blue"])
    assert rows[f"{account.id}:106"].name == "slipway-uat-blue"
    assert rows[f"{account.id}:107"].details["machine_id"] == str(env.machines["green"])
    assert rows[f"{account.id}:109"].details["machine_id"] == str(env.machines["data"])
    assert f"{account.id}:108" not in rows
    # Asked again, each machine gets its own id back and no row changes hands.
    async with proxmox.ProxmoxClient.for_account(account) as api:
        assert await machines.reserve_vmid(await _machine(env.machines["green"]), account, api=api) == 107
        assert await machines.reserve_vmid(await _machine(env.machines["blue"]), account, api=api) == 106
    after = {r.provider_id: r.details["machine_id"] for r in await _vm_rows()}
    assert after == {pid: r.details["machine_id"] for pid, r in rows.items()}


async def test_record_vm_forgets_the_machines_old_row_and_refuses_another_machines_id(net):
    account = await vf.esxi_account()
    env = await vf.vm_env(account, mode="server", slots=("blue",))
    blue = await _machine(env.machines["blue"])
    await machines.record_vm(blue, "4211-aaaa", {"moref": "vm-1"}, ids={"instance_uuid": "4211-aaaa", "moref": "vm-1"},
                             user_id=env.user_id)
    assert (await _machine(blue.id)).ids == {"instance_uuid": "4211-aaaa", "moref": "vm-1"}
    await machines.record_vm(blue, f"{account.id}:4211-bbbb", {"moref": "vm-2"},
                             ids={"instance_uuid": "4211-bbbb", "moref": "vm-2"})
    rows = await _vm_rows()
    assert [r.provider_id for r in rows] == [f"{account.id}:4211-bbbb"]
    (rebuild,) = await audits("machine.rebuild")
    assert rebuild.details["old"] == f"{account.id}:4211-aaaa"
    data = await _machine(env.machines["data"])
    with pytest.raises(MachineError, match=f"{account.id}:4211-bbbb is recorded for slipway-uat-blue; Slipway changed nothing"):
        await machines.record_vm(data, "4211-bbbb", {})


# ------------------------------------------------------------------------------- test 34: StateStore


async def test_34_saves_survive_the_callers_rollback(net):
    env = await vf.vm_env(await vf.proxmox_account())
    machine_id = env.machines["blue"]
    state = '{"version": 4, "lineage": "lin-1", "serial": 3, "resources": []}'
    stored = StoredState(lineage="lin-1", serial=3, sha256="ab" * 32, state=state)
    async with get_sessionmaker()() as db:
        await db.scalar(select(Machine.stage).where(Machine.id == machine_id))
        db.add(Host(name="scratch", hostname="10.9.9.9", username="root", metrics={}))
        if db.bind.dialect.name != "sqlite":  # SQLite allows one writer: there the caller's write stays pending
            await db.flush()
        await terraform_store.save(machine_id, stored, module_sha="m" * 64, terraform_version="1.16.5")
        await db.rollback()
        assert await db.scalar(select(Host).where(Host.name == "scratch")) is None
    assert await terraform_store.load(machine_id) == stored
    # A later save without an apply keeps the module and version it had.
    await terraform_store.save(machine_id, StoredState(lineage="lin-1", serial=4, sha256="cd" * 32, state=state),
                               module_sha=None, terraform_version=None)
    async with get_sessionmaker()() as db:
        row = await db.get(TerraformState, machine_id)
        assert (row.serial, row.module_sha, row.terraform_version) == (4, "m" * 64, "1.16.5")
        raw = await db.scalar(text("SELECT state FROM terraform_states"))
        assert raw and "lin-1" not in raw  # encrypted


async def test_34_a_new_row_has_a_null_lineage_and_loads_empty(net):
    env = await vf.vm_env(await vf.proxmox_account())
    dep = await deployment(env)
    assert (await terraform_store.lock(env.machines["blue"], dep)).ok
    async with get_sessionmaker()() as db:
        row = await db.get(TerraformState, env.machines["blue"])
        assert row.lineage is None and row.state is None and row.lock_id == dep
    assert (await terraform_store.load(env.machines["blue"])).empty
    assert (await terraform_store.load(uuid.uuid4())).empty


async def test_34_the_lock_is_a_compare_and_set_with_takeover(net):
    env = await vf.vm_env(await vf.proxmox_account())
    machine_id = env.machines["blue"]
    first, second = await deployment(env), await deployment(env, status="succeeded")
    got = await terraform_store.lock(machine_id, first)
    assert got.ok and got.taken_over is None
    assert (await terraform_store.lock(machine_id, first)).ok  # ours already
    refused = await terraform_store.lock(machine_id, second)
    assert not refused.ok and refused.holder == first
    async with get_sessionmaker()() as db:
        await db.execute(update(Deployment).where(Deployment.id == first).values(status="failed"))
        await db.commit()
    taken = await terraform_store.lock(machine_id, second)
    assert taken.ok and taken.taken_over == first
    await terraform_store.unlock(machine_id, first)  # not its lock any more: nothing changes
    async with get_sessionmaker()() as db:
        assert (await db.get(TerraformState, machine_id)).lock_id == second
    # A lock whose deployment row is gone is taken over too.
    async with get_sessionmaker()() as db:
        await db.execute(update(TerraformState).values(lock_id=uuid.uuid4()))
        await db.commit()
    third = await deployment(env, status="succeeded")
    assert (await terraform_store.lock(machine_id, third)).ok
    await terraform_store.unlock(machine_id, third)
    async with get_sessionmaker()() as db:
        row = await db.get(TerraformState, machine_id)
        assert row.lock_id is None and row.locked_at is None


async def test_34_two_locks_at_once_one_wins(net):
    env = await vf.vm_env(await vf.proxmox_account(), mode="server", slots=("blue", "green"))
    deps = []
    async with get_sessionmaker()() as db:
        for slot in ("blue", "green", "data"):  # one running job per instance, so all three hold a live lock
            dep = Deployment(instance_id=env.instances[slot], triggered_by_id=env.user_id, branch="main", log="",
                             status="running")
            db.add(dep)
            await db.flush()
            deps.append(dep.id)
        await db.commit()
    results = await asyncio.gather(*(terraform_store.lock(env.machines["blue"], d) for d in deps))
    assert sum(r.ok for r in results) == 1


async def test_34_recovery_clears_the_lock_of_an_interrupted_deployment(net):
    env = await vf.vm_env(await vf.proxmox_account())
    dep = await deployment(env)
    assert (await terraform_store.lock(env.machines["blue"], dep)).ok
    async with get_sessionmaker()() as db:
        row = await db.get(Deployment, dep)
        machine = await machines.recover_prepare(db, row)
        await db.commit()
    assert machine is not None and machine.id == env.machines["blue"]
    async with get_sessionmaker()() as db:
        assert (await db.get(TerraformState, env.machines["blue"])).lock_id is None
        machine = await db.get(Machine, env.machines["blue"])
        assert machine.stage == "planned" and machine.last_error == "Slipway restarted while preparing slipway-uat-blue"
    assert await terraform_store.clear_lock(dep) == 0


async def test_34_the_store_is_terraform_sessions_store(net):
    from slipway.services import terraform

    for name in ("lock", "unlock", "load", "save"):
        assert callable(getattr(terraform_store, name)) and callable(getattr(terraform_store.STORE, name))
    assert isinstance(terraform_store.STORE, terraform_store.DatabaseStateStore)
    assert terraform.StateStore  # the protocol the module satisfies


# ------------------------------------------------------------------------------- wait_idle and tasks


async def test_wait_idle_waits_for_a_running_task_then_refuses_after_the_limit(net, stub, vms):
    env = await blue_env(vms)
    log = vf.Lines()
    ctx = await vf.context(env.machines["blue"], connect=vms.connect, say=log)
    started = utcnow()
    task = machines.Busy(kind="snapshot", where="VM 106", started_at=started, task_id="UPID:pve1:1")
    stub.running_tasks = [[task], [task], []]
    await machines.tasks.wait_idle(ctx, limit=60, poll=5)
    assert log == [f"Waiting for Proxmox's snapshot task on VM 106 (started {started:%H:%M})"]
    stub.running_tasks = [[task]] * 5
    with pytest.raises(MachineError, match=r"^Proxmox is still running snapshot on VM 106 \(since \d\d:\d\d\); Slipway "
                                           r"changed nothing. Wait for it to finish, or stop it in Proxmox, then retry$"):
        await machines.tasks.wait_idle(ctx, limit=10, poll=5)
    clone = machines.Busy(kind="clone", where="VM 106", task_id="UPID:pve1:2")
    with pytest.raises(MachineError, match="^Proxmox is still cloning VM 106; Slipway changed nothing. Retry when"):
        await machines.tasks.wait_idle(ctx, read=lambda: _gives([clone]), limit=0, poll=5)
    stale = machines.Busy(kind="snapshot", where="VM 106", lock="snapshot", vmid=106)
    with pytest.raises(MachineError, match=r'^VM 106 is locked \(snapshot\) with no task running; check it in Proxmox '
                                           r'and run "qm unlock 106", then retry$'):
        await machines.tasks.wait_idle(ctx, read=lambda: _gives([stale]))


async def _gives(value):
    return value


async def test_tasks_are_recorded_before_the_wait_and_cleared(net, stub, vms):
    env = await blue_env(vms)
    dep = await deployment(env)
    ctx = await vf.context(env.machines["blue"], connect=vms.connect, deployment_id=dep)
    await machines.tasks.started(ctx, "UPID:pve1:00001:qmstart", "start")
    task = (await vf.machine_row(env.machines["blue"])).last_task
    assert task["id"] == "UPID:pve1:00001:qmstart" and task["kind"] == "start" and task["deployment_id"] == dep.hex
    await machines.tasks.ended(ctx)
    assert (await vf.machine_row(env.machines["blue"])).last_task is None


# ------------------------------------------------------------------------------------------ resize step


async def test_resize_step_applies_the_size_and_starts_the_live_release(net, stub, vms):
    env = await blue_env(vms, docker=True)
    await make_ready(env, vms, size={"cores": 8, "memory_mb": 16384, "disk_gb": 128})
    dep = await deployment(env)
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, env.instances["blue"])
        inst.status = "running"
        await db.commit()
    started: list[str] = []

    async def start_release(instance):
        started.append(instance.slot)

    ctx = await vf.context(env.machines["blue"], connect=vms.connect, deployment_id=dep, user_id=env.user_id)
    status, note = await machines.resize_step(ctx, start_release=start_release)
    assert (status, note) == ("succeeded", "Resized to 8 vCPU, 16 GB, 128 GB")
    assert stub.calls == ["running", "check_resize", "resize"] and started == ["blue"]
    machine = await vf.machine_row(env.machines["blue"])
    assert {k: machine.applied[k] for k in machines.SIZE_KEYS} == {"cores": 8, "memory_mb": 16384, "disk_gb": 128}
    assert machine.applied["deployment_id"] == dep.hex
    async with get_sessionmaker()() as db:
        assert (await db.get(Deployment, dep)).options["resize"] == {
            "from": {"cores": 4, "memory_mb": 8192, "disk_gb": 64}, "to": {"cores": 8, "memory_mb": 16384, "disk_gb": 128}}
    (event,) = await audits("machine.resize")
    assert event.details == {"name": "slipway-uat-blue", "from": {"cores": 4, "memory_mb": 8192, "disk_gb": 64},
                             "to": {"cores": 8, "memory_mb": 16384, "disk_gb": 128}, "deployment_id": str(dep)}
    # Nothing left to apply: the step is skipped.
    assert (await machines.resize_step(ctx, start_release=start_release))[0] == "skipped"


async def test_resize_waits_while_the_slot_takes_the_traffic_of_two(net, stub, vms):
    env = await blue_env(vms, docker=True, mode="server", slots=("blue", "green"))
    await make_ready(env, vms, "blue", size={"cores": 8, "memory_mb": 8192, "disk_gb": 64})
    await make_ready(env, vms, "data", size={"cores": 8, "memory_mb": 8192, "disk_gb": 64})
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        row.active_slot_id = env.instances["blue"]
        await db.commit()
        assert not await machines.resize_due(db, await db.get(Machine, env.machines["blue"]))
        assert not await machines.resize_due(db, await db.get(Machine, env.machines["data"]))
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)
    assert await machines.resize_step(ctx) == ("skipped", "blue takes the traffic now; the resize waits")
    data = await vf.context(env.machines["data"], connect=vms.connect)
    status, note = await machines.resize_step(data)
    assert status == "skipped" and note.startswith("The data server's VM keeps its size")
    assert stub.calls == []
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        row.active_slot_id = env.instances["green"]
        await db.commit()
        assert await machines.resize_due(db, await db.get(Machine, env.machines["blue"]))


async def test_a_failed_resize_that_leaves_the_vm_off_says_so(net, stub, vms):
    env = await blue_env(vms, docker=True)
    await make_ready(env, vms, size={"cores": 8, "memory_mb": 8192, "disk_gb": 64})
    stub.resize_error = MachineError("ESXi couldn't change slipway-uat-blue's size")
    stub.power = "stopped"
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)
    with pytest.raises(MachineError, match="couldn't change"):
        await machines.resize_step(ctx)
    async with get_sessionmaker()() as db:
        notice = (await db.get(Environment, env.env_id)).notice
    assert notice["text"] == "slipway-uat-blue was left off during a resize: deploy to blue again to finish it"
    assert notice["next"] is None
    (event,) = await audits("machine.left_off")
    assert event.details["name"] == "slipway-uat-blue"
    # A notice with a chain follow-up is never replaced (Decision 23).
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        row.notice = {"text": "Deploy stopped", "at": "x", "deployment_id": None, "next": {"kind": "deploy"}}
        await db.commit()
    with pytest.raises(MachineError):
        await machines.resize_step(ctx)
    async with get_sessionmaker()() as db:
        assert (await db.get(Environment, env.env_id)).notice["text"] == "Deploy stopped"
    assert (await vf.machine_row(env.machines["blue"])).last_error == "ESXi couldn't change slipway-uat-blue's size"


# --------------------------------------------------------------------------------------- remove, forget


async def _drop_instance(env: vf.VmEnv, slot: str) -> None:
    async with get_sessionmaker()() as db:
        await db.delete(await db.get(Instance, env.instances[slot]))
        await db.commit()


async def test_remove_a_planned_vm_deletes_every_row_without_the_hypervisor(net, stub, vms):
    env = await blue_env(vms)
    ctx = await vf.context(env.machines["blue"], connect=vms.connect, user_id=env.user_id)
    with pytest.raises(MachineError, match="still runs the blue slot's instance"):
        await machines.remove(ctx)
    await _drop_instance(env, "blue")
    assert await machines.blockers(ctx) == []
    done = await machines.remove(ctx)
    assert done == ["slipway-uat-blue was never made"] and "destroy" not in stub.calls
    async with get_sessionmaker()() as db:
        assert await db.get(Machine, env.machines["blue"]) is None
        assert await db.get(Host, env.hosts["blue"]) is None
        assert await db.scalar(select(func.count()).select_from(AddressClaim)) == 0
    (event,) = await audits("machine.destroy")
    assert event.details == {"name": "slipway-uat-blue", "ids": {}}
    assert await machines.remove(ctx) == ["slipway-uat-blue is already removed"]


async def test_remove_a_made_vm_destroys_it_and_its_rows(net, stub, vms):
    env = await blue_env(vms, docker=True)
    await make_ready(env, vms, ids={"vmid": 106})
    account_id = env.account_id
    await resources.record(env.env_id, "proxmox", "vm", f"{account_id}:106", "slipway-uat-blue", "created",
                           details={"machine_id": str(env.machines["blue"]), "node": "pve1"})
    async with get_sessionmaker()() as db:
        db.add(TerraformState(machine_id=env.machines["blue"], serial=1))
        db.add(MachineSnapshot(machine_id=env.machines["blue"], name="slipway-20261116T100000Z", reason="manual",
                               identity_fp="x", sizes={}, taken_at=utcnow()))
        await db.commit()
    await _drop_instance(env, "blue")
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)
    assert await machines.remove(ctx) == ["Deleted slipway-uat-blue"]
    assert stub.calls == ["destroy_blockers", "destroy"]
    async with get_sessionmaker()() as db:
        for model in (Machine, MachineSnapshot, TerraformState, Resource, AddressClaim):
            assert await db.scalar(select(func.count()).select_from(model)) == 0
    assert [e.details["provider_id"] for e in await audits("resource.delete")] == [f"{account_id}:106"]
    assert (await audits("machine.destroy"))[0].details["ids"] == {"vmid": 106}


async def test_blockers_refuse_and_forget_vms_gets_past_only_forgettable_ones(net, stub, vms):
    env = await blue_env(vms, docker=True)
    await make_ready(env, vms, ids={"vmid": 106})
    await _drop_instance(env, "blue")
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)
    stub.destroy_blockers_ = [Blocker("Proxmox is still running snapshot on VM 106", False)]
    with pytest.raises(MachineError, match="still running snapshot"):
        await machines.remove(ctx, forget=True)
    assert (await vf.machine_row(env.machines["blue"])).stage == "ready"  # nothing changed
    hidden = "Slipway can't see VM 106 on lab: the token may have lost its rights on /pool/slipway"
    stub.destroy_blockers_ = [Blocker(hidden, True)]
    with pytest.raises(MachineError, match="can't see VM 106"):
        await machines.remove(ctx)
    done = await machines.remove(ctx, forget=True)
    assert done == [f"Forgot slipway-uat-blue without removing it: {hidden}"] and "destroy" not in stub.calls
    assert await vf.machine_row(env.machines["blue"]) is None
    (event,) = await audits("machine.forget")
    assert event.details == {"name": "slipway-uat-blue", "ids": {"vmid": 106}, "why": "forget_vms", "blocker": hidden}
    async with get_sessionmaker()() as db:
        notice = (await db.get(Environment, env.env_id)).notice
    assert notice["text"] == (f"Slipway forgot slipway-uat-blue (VM 106 on lab) without removing it: {hidden}. "
                              "Remove it by hand.")


async def test_an_unreachable_or_unusable_account_is_a_forgettable_blocker(net, stub, vms):
    env = await blue_env(vms, docker=True)
    await make_ready(env, vms, ids={"vmid": 106})
    ctx = await vf.context(env.machines["blue"], connect=vms.connect)

    async def down(ctx_):
        raise MachineError("x", unreachable=True)

    stub.destroy_blockers = down  # type: ignore[method-assign]
    assert await machines.blockers(ctx) == [
        Blocker("Slipway can't reach lab, so it can't remove slipway-uat-blue: retry when it answers", True)]
    ctx.account.tls = None
    (blocker,) = await machines.blockers(ctx)
    assert blocker.forgettable and "no certificate is trusted for it yet" in blocker.text


# ------------------------------------------------------------------------------------------- the rest


async def test_provider_for_resolves_lazily_and_names_a_missing_provider(monkeypatch):
    monkeypatch.setattr(providers, "PROVIDERS", {})
    monkeypatch.setitem(providers.PATHS, "proxmox", ("slipway.services.providers.not_built_yet", "ProxmoxProvider"))
    with pytest.raises(MachineError, match="^This Slipway has no Proxmox provider yet$"):
        providers.provider_for("proxmox")
    with pytest.raises(MachineError, match="isn't a VM provider"):
        providers.provider_for("digitalocean")
    sentinel = Stub()
    providers.PROVIDERS["esxi"] = sentinel
    assert providers.provider_for("esxi") is sentinel
    assert providers.label("esxi") == "ESXi" and providers.label("proxmox") == "Proxmox"


async def test_set_notice_never_replaces_a_chain_follow_up(net):
    env = await vf.vm_env(await vf.proxmox_account())
    assert await machines.set_notice(env.env_id, "first", deployment_id=None)
    async with get_sessionmaker()() as db:
        assert (await db.get(Environment, env.env_id)).notice["text"] == "first"
        row = await db.get(Environment, env.env_id)
        row.notice = {"text": "stopped", "at": "x", "deployment_id": None, "next": {"kind": "deploy", "slot": "green"}}
        await db.commit()
    assert not await machines.set_notice(env.env_id, "second", deployment_id=None)
    async with get_sessionmaker()() as db:
        assert (await db.get(Environment, env.env_id)).notice["text"] == "stopped"


async def test_stage_of_and_lost_text(net):
    account = await vf.proxmox_account()
    env = await vf.vm_env(account, mode="server", slots=("blue",))
    async with get_sessionmaker()() as db:
        blue = await db.get(Machine, env.machines["blue"])
        data = await db.get(Machine, env.machines["data"])
        env_row = await db.get(Environment, env.env_id)
        assert machines.stage_of(blue.host) == "planned"
        assert machines.stage_of(Host(name="x", hostname="x", username="x", provider="ssh")) is None
        assert machines.stage_of(Host(name="d", hostname="d", username="x", provider="digitalocean",
                                      provider_state={"phase": "ready"})) is None
        assert machines.lost_text(blue, env=env_row) == (
            "slipway-uat-blue is gone from lab. Slipway never makes a ready VM again by itself: use Forget the VM on "
            "uat, then deploy to blue to make a new one")
        assert machines.lost_text(data, env=env_row).startswith(
            "slipway-uat-data is gone from lab, and uat's data was on it. Slipway can't make it again without that data")
