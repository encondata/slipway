"""The Proxmox provider (phase 5 §7.4-§7.7, §9.11): tests 23, 25, 26, 27, 28, 29, 66 (the Proxmox part) and 67.

Proxmox is ``tests/fake_proxmox.py``; Terraform is ``tests/bin/fake-terraform`` (through a wrapper named
``fake-terraform``, against a copy of the bundled module with a lock file in the fake mirror's format, as test 13
does, since the real lock file's hashes are for the registry's zips, not the fake mirror's); the VMs are
``tests/fake_vm_hosts.py``.
Every run goes through the machines core (``machines.prepare``, ``resize_step``, ``remove``), so the stage
transactions, the pin and the bootstrap are the real ones. Also the audit actions the provider writes
(machine.create, machine.rebuild, and host.key_pinned with ``how: read through the Proxmox guest agent``), none of
which may carry the token or a key.
"""

from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import delete, select, update

from slipway.core.config import get_settings
from slipway.db.base import utcnow
from slipway.db.session import get_sessionmaker
from slipway.models import (
    AuditEvent,
    Deployment,
    Environment,
    Host,
    Instance,
    Machine,
    MachineSnapshot,
    Resource,
    TerraformState,
)
from slipway.services import hosts, machines, proxmox, ssh, terraform, vmnet
from slipway.services.providers import proxmox as pxp
from slipway.services.providers import provider_for
from slipway.services.vmtypes import MachineError
from tests import fake_proxmox as fp
from tests.python_shim import python_header
from tests import vm_fixtures as vf
from tests.fake_vm_hosts import VmRemote, probe_through
from tests.test_terraform import lock_file

FAKE_TF = Path(__file__).parent / "bin" / "fake-terraform"
SECRET_PART = fp.TOKEN.split("=", 1)[1]
VM = "slipway-uat-blue"
BLUE = "10.0.0.100"


# ------------------------------------------------------------------------------------------- the world


class World:
    """One test's Proxmox, Terraform, VM hosts and settings."""

    def __init__(self, root: Path, monkeypatch: pytest.MonkeyPatch, net: vf.Network, **pve: Any) -> None:
        self.root = root
        self.net = net
        self.monkeypatch = monkeypatch
        self.fake = fp.FakeProxmox(root / "pve.json", **pve).install(monkeypatch)
        (root / "vms").mkdir()
        self.vms = VmRemote(root / "vms")
        self.script = root / "tf-script.json"
        self.log = root / "tf-log.jsonl"
        self.bin = root / "bin" / "fake-terraform"
        self.bin.parent.mkdir()
        config = {"pve_state": str(self.fake.path), "script": str(self.script), "log": str(self.log)}
        self.bin.write_text(
            python_header() +
            "import runpy\n"
            f"runpy.run_path({str(FAKE_TF)!r}, init_globals={{'FAKE_CONFIG': {config!r}}}, run_name='__main__')\n"
        )
        self.bin.chmod(0o755)
        cli_config = root / "terraformrc"
        cli_config.write_text('provider_installation {\n  filesystem_mirror { path = "/nowhere" }\n}\n')
        module = root / "module"
        module.mkdir()
        for name in terraform.MODULE_FILES:
            shutil.copy(terraform.MODULE_DIR / name, module / name)
        (module / terraform.LOCK_FILE).write_text(lock_file(terraform.PROVIDER_VERSION))
        settings = get_settings()
        monkeypatch.setattr(settings, "terraform_binary", str(self.bin))
        monkeypatch.setattr(settings, "terraform_cli_config", str(cli_config))
        monkeypatch.setattr(settings, "terraform_dir", str(root / "terraform"))
        monkeypatch.setattr(pxp, "MODULE_DIR", module)
        monkeypatch.setattr(terraform, "_semaphores", {})
        self.probe = probe_through(self.vms)
        monkeypatch.setattr(hosts.ssh, "probe", self.probe)
        self.knobs()

    def knobs(self, **values: Any) -> None:
        """fake-terraform's knobs; the VM it makes always presents the fake blue VM's key unless told otherwise."""
        if "blue" in self.vms and "host_key" not in values:
            values["host_key"] = self.vms.pinned_key(BLUE)
        self.script.write_text(json.dumps(values))

    def runs(self) -> list[dict[str, Any]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def commands(self) -> list[str]:
        return [" ".join(run["argv"][:2]) if run["argv"][:1] == ["state"] else run["argv"][0] for run in self.runs()]

    def writes(self, since: int = 0) -> list[dict[str, Any]]:
        return [r for r in self.fake.requests[since:] if r["method"] != "GET"]

    def workdir(self, machine_id: uuid.UUID) -> terraform.Workdir:
        return terraform.Workdir(str(self.root / "terraform"), machine_id)


@pytest.fixture
def net(monkeypatch) -> vf.Network:
    return vf.quiet_network(monkeypatch)


@pytest.fixture
def world(tmp_path, monkeypatch, net) -> World:
    return World(tmp_path, monkeypatch, net)


def a_world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, net: vf.Network, **pve: Any) -> World:
    return World(tmp_path, monkeypatch, net, **pve)


async def blue_env(world: World, *, storage_type: str = "lvmthin", size: dict | None = None,
                   mode: str = "slot") -> vf.VmEnv:
    """An environment ``uat`` with one Proxmox VM planned for blue at 10.0.0.100 (a fake VM host there)."""
    account = await vf.proxmox_account(storage_type=storage_type)
    if "blue" not in world.vms:
        world.vms.add_vm("blue", BLUE)
    world.knobs()
    return await vf.vm_env(account, mode=mode, addresses={"blue": BLUE}, size=size,
                           provider=pxp.ProxmoxProvider(), deploy_roots={"blue": str(world.vms["blue"].tmp / "root")})


async def deployment(env: vf.VmEnv, slot: str | None = "blue", *, kind: str = "deploy") -> uuid.UUID:
    """A running job of ``slot`` (None: an environment-level job, as Remove slot is); the environment's earlier
    job has finished (one job at a time per environment)."""
    async with get_sessionmaker()() as db:
        if kind != "activate":
            await db.execute(update(Deployment).where(Deployment.environment_id == env.env_id,
                                                      Deployment.kind != "activate",
                                                      Deployment.status.in_(("queued", "running")))
                             .values(status="failed"))
        dep = Deployment(instance_id=env.instances[slot] if slot else None, environment_id=env.env_id, kind=kind,
                         triggered_by_id=env.user_id, branch="main", log="", status="running")
        db.add(dep)
        await db.commit()
        return dep.id


async def ctx_for(world: World, env: vf.VmEnv, *, dep: uuid.UUID | None = None, log: vf.Lines | None = None,
                  slot: str = "blue", job: str | None = "blue") -> machines.MachineContext:
    dep = dep or await deployment(env, job)
    return await vf.context(env.machines[slot], connect=world.vms.connect, deployment_id=dep, user_id=env.user_id,
                            say=log if log is not None else vf.Lines())


async def machine(env: vf.VmEnv, slot: str = "blue") -> Machine:
    async with get_sessionmaker()() as db:
        return await db.get(Machine, env.machines[slot])


async def host(env: vf.VmEnv, slot: str = "blue") -> Host:
    async with get_sessionmaker()() as db:
        return await db.get(Host, env.hosts[slot])


async def audits(action: str | None = None) -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        stmt = select(AuditEvent).order_by(AuditEvent.created_at)
        if action:
            stmt = stmt.where(AuditEvent.action == action)
        return list(await db.scalars(stmt))


async def no_secret_anywhere(world: World, env: vf.VmEnv, log: list[str]) -> None:
    """The token (and its secret part) and the host's private key are in no audit row, log line, argv or file."""
    blob = json.dumps([[a.summary, a.details] for a in await audits()], default=str)
    private = (await host(env)).private_key
    for secret in (fp.TOKEN, SECRET_PART, private):
        assert secret not in blob
        assert not any(secret in line for line in log)
    for run in world.runs():
        assert not any(SECRET_PART in arg for arg in run["argv"])
        assert "PROXMOX_VE_API_TOKEN" in run["env"] or run["argv"][0] == "version"
    for path in (world.root / "terraform").rglob("*"):
        if path.is_file():
            text = path.read_text(errors="replace")
            assert SECRET_PART not in text and fp.TOKEN not in text


async def made(world: World, **kw: Any) -> tuple[vf.VmEnv, machines.MachineContext, vf.Lines]:
    """A ready VM, made end to end (the path test 23 checks)."""
    env = await blue_env(world, **kw)
    log = vf.Lines()
    ctx = await ctx_for(world, env, log=log)
    assert (await machines.prepare(ctx))[0] == "succeeded"
    return env, ctx, log


async def reload(world: World, env: vf.VmEnv, log: vf.Lines | None = None, slot: str = "blue",
                 job: str | None = "blue") -> machines.MachineContext:
    return await ctx_for(world, env, log=log, slot=slot, job=job)


async def set_stage(env: vf.VmEnv, stage: str, slot: str = "blue") -> None:
    async with get_sessionmaker()() as db:
        row = await db.get(Machine, env.machines[slot])
        h = await db.get(Host, row.host_id)
        row.stage = stage
        hosts.set_phase(h, machines.phase_for(stage), stage=stage)
        await db.commit()


async def reserve(world: World, env: vf.VmEnv) -> int:
    ctx = await reload(world, env)
    async with proxmox.ProxmoxClient.for_account(ctx.account, sleep=vf.no_sleep) as api:
        return await machines.reserve_vmid(ctx.machine, ctx.account, api=api, user_id=env.user_id)


def calls(world: World, method: str, suffix: str) -> list[dict[str, Any]]:
    return [r for r in world.fake.requests if r["method"] == method and r["path"].endswith(suffix)]


# ------------------------------------------------------------------- test 23: a new VM, end to end


async def test_23_a_new_vm_end_to_end(world, monkeypatch):
    env = await blue_env(world)
    dep = await deployment(env)
    events: list[str] = []

    async def tcp_open(address, port, timeout=machines.PROBE_TIMEOUT):
        events.append(f"probe {address}:{port}")
        return False

    real_reserve = machines.reserve_vmid

    async def reserve_vmid(*args, **kw):
        vmid = await real_reserve(*args, **kw)
        events.append(f"reserved {vmid}")
        return vmid

    real_spawn = terraform._spawn

    async def spawn(argv, **kw):
        async with get_sessionmaker()() as db:
            rows = list(await db.scalars(select(Resource).where(Resource.kind == "vm")))
            stage = (await db.get(Machine, env.machines["blue"])).stage
        events.append(f"terraform {argv[1]} (vm rows {len(rows)}, {stage})")
        return await real_spawn(argv, **kw)

    real_write = machines.write

    async def write(ctx, **fields):
        result = await real_write(ctx, **fields)
        if fields.get("stage"):
            events.append(f"stage {fields['stage']}")
        return result

    monkeypatch.setattr(machines, "tcp_open", tcp_open)
    monkeypatch.setattr(machines, "reserve_vmid", reserve_vmid)
    monkeypatch.setattr(terraform, "_spawn", spawn)
    monkeypatch.setattr(machines, "write", write)

    log = vf.Lines()
    ctx = await ctx_for(world, env, dep=dep, log=log)
    status, note = await machines.prepare(ctx)
    assert (status, note) == ("succeeded", f"{VM} is ready at {BLUE}")

    # Registry, probe, then the id and its row committed before the first Terraform run; creating before apply.
    assert events[:2] == [f"probe {BLUE}:22", "reserved 100"]
    tf = [e for e in events if e.startswith("terraform")]
    assert tf[0] == "terraform version (vm rows 1, planned)"
    assert [e.split(" (")[0] for e in tf] == ["terraform version", "terraform init", "terraform plan",
                                            "terraform show", "terraform apply"]
    assert events.index("stage creating") < events.index("terraform apply (vm rows 1, creating)")
    assert events.index("terraform apply (vm rows 1, creating)") < events.index("stage booting")
    assert events[-1] == "stage ready"

    # The state was saved to terraform_states; the agent was asked for the address, then boot-finished, then the key.
    async with get_sessionmaker()() as db:
        state = await db.get(TerraformState, env.machines["blue"])
        assert state.lineage and state.serial >= 1 and state.lock_id is None
        assert '"vm_id": 100' in state.state
    paths = [(r["path"], r["params"].get("file")) for r in world.fake.requests if "/agent/" in r["path"]]
    address_at = paths.index(("/nodes/pve1/qemu/100/agent/network-get-interfaces", None))
    boot_at = paths.index(("/nodes/pve1/qemu/100/agent/file-read", pxp.BOOT_FINISHED))
    key_at = paths.index(("/nodes/pve1/qemu/100/agent/file-read", pxp.HOST_KEY_FILE))
    assert address_at < boot_at < key_at

    # Pinned the key read through the agent, bootstrapped (check_host with building=True), ready with snapshot_mode.
    row, h = await machine(env), await host(env)
    assert row.stage == "ready" and row.snapshot_mode == "any" and row.ids == {"vmid": 100}
    assert row.applied["cores"] == 4 and row.applied["disk_gb"] == 64 and row.last_error is None
    assert row.host_key_public.split()[:2] == world.vms.pinned_key(BLUE).split()[:2]
    assert h.host_key == row.host_key_public and h.is_built and h.docker_version == "26.1.3"
    assert len(world.probe.seen) == 1
    assert not calls(world, "POST", "/status/shutdown")  # prepare never shuts a VM down (test 21)
    vm = world.fake.vm(100)
    assert vm["tags"] == sorted(["slipway", f"env-{env.env_id}"]) and vm["status"] == "running"

    (pinned,) = await audits("host.key_pinned")
    assert pinned.details["how"] == "read through the Proxmox guest agent"
    (reserved,) = await audits("machine.reserve")
    assert reserved.details == {"name": VM, "vmid": 100}
    (created,) = await audits("machine.create")
    assert created.details == {"name": VM, "ids": {"vmid": 100}, "node": "pve1"}
    assert created.actor_id == env.user_id
    assert await audits("machine.rebuild") == []
    await no_secret_anywhere(world, env, log)


async def test_23_the_provider_is_found_lazily_and_freezes_the_spec(world):
    provider = provider_for("proxmox")
    assert isinstance(provider, pxp.ProxmoxProvider) and provider.label == "Proxmox"
    account = await vf.proxmox_account(storage_type="dir")
    assert provider.freeze(account, vf.LAN_PVE) == {
        "node": "pve1", "pool": "slipway", "storage": "local-lvm", "storage_type": "dir", "file_format": "qcow2",
        "template_vmid": 9000, "bridge": "vmbr0", "vlan_tag": None,
    }
    assert provider.clean_config(dict(account.config), None)["url"] == fp.URL


# ------------------------------------------------------------------------ test 25: half-made VMs


async def test_25_tainted_after_a_failed_create_is_replaced_after_the_identity_check(world):
    env = await blue_env(world)
    world.knobs(fail_after_clone=True)
    ctx = await reload(world, env)
    with pytest.raises(MachineError, match=f"^Terraform couldn't make {VM}. See the log above.$"):
        await machines.prepare(ctx)
    row = await machine(env)
    assert row.stage == "creating" and row.last_error == f"Terraform couldn't make {VM}. See the log above."
    async with get_sessionmaker()() as db:
        state = await db.get(TerraformState, env.machines["blue"])
    assert terraform.state_resource(state.state).tainted
    assert world.fake.vm(100)["tags"] == []  # the clone, without its tags

    world.knobs()
    ctx = await reload(world, env)
    assert (await machines.prepare(ctx))[0] == "succeeded"
    assert world.fake.vm(100)["tags"] == sorted(["slipway", f"env-{env.env_id}"])
    rebuilt = await audits("machine.rebuild")
    assert [a.details["why"] for a in rebuilt] == ["Terraform's earlier create failed part way"]
    assert (await machine(env)).stage == "ready"


async def test_25_a_clone_left_by_a_killed_terraform_is_waited_for_deleted_and_made_again(world):
    env = await blue_env(world)
    world.knobs(die_after_clone=True, clone_lock_outlives=3)
    with pytest.raises(MachineError, match="Terraform couldn't make"):
        await machines.prepare(await reload(world, env))
    vm = world.fake.vm(100)
    assert vm["lock"] == "clone" and vm["tags"] == [] and vm["description"]

    world.knobs()
    log = vf.Lines()
    assert (await machines.prepare(await reload(world, env, log)))[0] == "succeeded"
    assert any(line.startswith("Waiting for Proxmox's qmclone task on VM 100") for line in log)
    assert calls(world, "DELETE", "/nodes/pve1/qemu/100")
    (rebuilt,) = await audits("machine.rebuild")
    assert rebuilt.summary == f"Removed the half-made {VM} (VM 100) from an earlier attempt"
    assert rebuilt.details == {"name": VM, "vmid": 100, "why": "a half-made VM Terraform's state doesn't hold"}
    assert world.fake.vm(100)["tags"] == sorted(["slipway", f"env-{env.env_id}"])


async def test_25_a_clone_lock_that_outlives_the_wait_deletes_nothing(world, monkeypatch):
    env = await blue_env(world)
    world.knobs(die_after_clone=True, clone_lock_outlives=1000)
    with pytest.raises(MachineError):
        await machines.prepare(await reload(world, env))
    world.knobs()
    monkeypatch.setattr(machines, "TASK_WAIT_LIMIT", 10.0)
    with pytest.raises(MachineError, match="^Proxmox is still cloning VM 100; Slipway changed nothing. Retry when it "
                                           "has finished$"):
        await machines.prepare(await reload(world, env))
    assert not calls(world, "DELETE", "/nodes/pve1/qemu/100")
    assert world.fake.vm(100) is not None and await audits("machine.rebuild") == []


@pytest.mark.parametrize("stage", ["planned", "creating", "booting"])
async def test_25_a_foreign_vm_at_the_reserved_id_with_the_state_empty_is_re_reserved(world, stage):
    env = await blue_env(world)
    assert await reserve(world, env) == 100
    await set_stage(env, stage)
    world.fake.reuse_vmid(100, "web-1")
    log = vf.Lines()
    assert (await machines.prepare(await reload(world, env, log)))[0] == "succeeded"
    assert (await machine(env)).ids == {"vmid": 101}
    assert "VM 100 is someone else's now; reserving another id" in log
    (rebuilt,) = await audits("machine.rebuild")
    assert rebuilt.details == {"name": VM, "vmid": 100, "why": "someone else's VM holds the id"}
    async with get_sessionmaker()() as db:
        ids = [r.provider_id.split(":")[1] for r in await db.scalars(select(Resource).where(Resource.kind == "vm"))]
    assert ids == ["101"]
    assert world.fake.vm(100)["name"] == "web-1"  # someone else's VM is left alone


async def _booting_with_state(world: World, monkeypatch) -> vf.VmEnv:
    """A VM made by Terraform (the state has it) whose prepare failed while booting (the agent's wrong address)."""
    env = await blue_env(world)
    monkeypatch.setattr(pxp, "ADDRESS_WAIT", 10.0)
    world.fake.agent_wrong_address()
    with pytest.raises(MachineError, match=f"^{VM} came up at 10.99.99.99, not {BLUE}"):
        await machines.prepare(await reload(world, env))
    assert (await machine(env)).stage == "booting"
    world.fake._knob("agent_wrong_address", False)
    return env


async def test_25_a_foreign_vm_while_the_state_has_the_resource_is_refused(world, monkeypatch):
    env = await _booting_with_state(world, monkeypatch)
    world.fake.reuse_vmid(100, "web-1")
    since, tf_runs = len(world.fake.requests), len(world.runs())
    with pytest.raises(MachineError, match=f"^VM 100 on Proxmox isn't the {VM} Slipway made. Slipway changed nothing: "
                                           "remove or rename that VM, or delete this environment$"):
        await machines.prepare(await reload(world, env))
    assert world.writes(since) == [] and "apply" not in world.commands()[tf_runs:]


async def test_25_an_id_used_by_a_hidden_vm_with_the_state_empty_is_re_reserved(world):
    env = await blue_env(world)
    assert await reserve(world, env) == 100
    world.fake.hidden(100)
    log = vf.Lines()
    assert (await machines.prepare(await reload(world, env, log)))[0] == "succeeded"
    assert "VM id 100 is used by a VM Slipway can't see; reserving another" in log
    assert (await machine(env)).ids == {"vmid": 101}


async def test_25_an_id_used_by_a_hidden_vm_with_the_state_holding_it_is_refused(world, monkeypatch):
    env = await _booting_with_state(world, monkeypatch)
    world.fake.remove_vm(100)
    world.fake.hidden(100)
    since = len(world.fake.requests)
    with pytest.raises(MachineError, match=r"^Slipway can't see VM 100 \(check the token's rights on /pool/slipway\); "
                                           "Slipway changed nothing$"):
        await machines.prepare(await reload(world, env))
    assert world.writes(since) == []


async def test_25_gone_while_booting_is_dropped_from_the_state_and_made_again(world, monkeypatch):
    env = await _booting_with_state(world, monkeypatch)
    world.fake.remove_vm(100)
    assert (await machines.prepare(await reload(world, env)))[0] == "succeeded"
    assert "state rm" in world.commands()
    assert world.fake.vm(100)["status"] == "running" and (await machine(env)).stage == "ready"
    (rebuilt,) = await audits("machine.rebuild")
    assert rebuilt.details["why"] == "gone before it was ready"


async def test_25_a_made_vm_whose_stage_never_moved_is_started_and_not_made_again(world, monkeypatch):
    env = await _booting_with_state(world, monkeypatch)
    with world.fake.edit() as state:
        state["vms"]["100"]["status"] = "stopped"
    runs = len(world.runs())
    assert (await machines.prepare(await reload(world, env)))[0] == "succeeded"
    assert "apply" not in world.commands()[runs:]
    assert calls(world, "POST", "/nodes/pve1/qemu/100/status/start")


# ----------------------------------------------------------------------------- test 26: a ready VM


async def test_26_a_ready_vm_runs_no_terraform_and_is_started_when_stopped(world):
    env, _ctx, _log = await made(world)
    runs = len(world.runs())
    assert await machines.prepare(await reload(world, env)) == ("succeeded", None)
    assert len(world.runs()) == runs
    with world.fake.edit() as state:
        state["vms"]["100"]["status"] = "stopped"
    assert (await machines.prepare(await reload(world, env)))[0] == "succeeded"
    assert len(world.runs()) == runs and world.fake.vm(100)["status"] == "running"
    assert calls(world, "POST", "/nodes/pve1/qemu/100/status/start")


async def test_26_gone_answers_the_lost_text(world):
    env, ctx, _ = await made(world)
    world.fake.remove_vm(100)
    since = len(world.fake.requests)
    with pytest.raises(MachineError) as caught:
        await machines.prepare(await reload(world, env))
    ctx = await reload(world, env)
    assert caught.value.text == machines.lost_text(ctx.machine, env=ctx.env)
    assert world.writes(since) == []


async def test_26_hidden_answers_the_pool_rights_text(world):
    env, _ctx, _ = await made(world)
    world.fake.remove_vm(100)
    world.fake.hidden(100)
    since = len(world.fake.requests)
    with pytest.raises(MachineError, match="^Slipway can't see VM 100 on lab: the token may have lost its rights on "
                                           "/pool/slipway, or the VM was moved out of the pool. Slipway changed "
                                           "nothing$"):
        await machines.prepare(await reload(world, env))
    assert world.writes(since) == []


@pytest.mark.parametrize("change", ["untag", "rename", "move"])
async def test_26_untagged_renamed_or_moved_is_refused_with_only_reads(world, change):
    env, _ctx, _ = await made(world)
    if change == "untag":
        world.fake.untag(100)
        text = f"^VM 100 on Proxmox isn't {VM} any more; Slipway changed nothing$"
    elif change == "rename":
        with world.fake.edit() as state:
            state["vms"]["100"]["name"] = "renamed"
        text = f"^VM 100 on Proxmox isn't {VM} any more; Slipway changed nothing$"
    else:
        world.fake.move_node(100)
        text = (rf"^VM 100 \({VM}\) is on node pve2 now, not pve1. Slipway changed nothing: move it back, or fix it by "
                "hand, then retry$")
    since, runs = len(world.fake.requests), len(world.runs())
    with pytest.raises(MachineError, match=text):
        await machines.prepare(await reload(world, env))
    assert world.writes(since) == [] and len(world.runs()) == runs


async def test_26_an_agent_that_never_answers_on_a_ready_vm_is_a_warning(world, monkeypatch):
    env, _ctx, _ = await made(world)
    monkeypatch.setattr(pxp, "ADDRESS_WAIT", 10.0)
    world.fake.agent_late(100)
    status, note = await machines.prepare(await reload(world, env))
    assert status == "warning" and note == f"{VM}'s guest agent didn't answer in 1 minute; carrying on over SSH"


async def test_26_the_api_down_on_a_ready_vm_is_the_cores_warning(world, monkeypatch):
    env, _ctx, _ = await made(world)

    def unreachable(pem=None):
        import httpx

        def refuse(request):
            raise httpx.ConnectError("refused")

        return httpx.MockTransport(refuse)

    monkeypatch.setattr(proxmox, "transport_factory", unreachable)
    status, note = await machines.prepare(await reload(world, env))
    assert (status, note) == ("warning", f"Couldn't reach Proxmox to check {VM}; carrying on over SSH")


# --------------------------------------------------------------------------------- test 27: resize


async def grow(env: vf.VmEnv, **size: int) -> None:
    async with get_sessionmaker()() as db:
        row = await db.get(Machine, env.machines["blue"])
        row.size = {**row.size, **size}
        await db.commit()


async def test_27_check_resize_then_resize(world, monkeypatch):
    env, _ctx, _ = await made(world)
    await grow(env, cores=6, memory_mb=12288, disk_gb=80)
    log = vf.Lines()
    ctx = await reload(world, env, log)
    provider = ctx.provider
    since = len(world.fake.requests)
    plan = await provider.check_resize(ctx)
    assert plan.to == {"cores": 6, "memory_mb": 12288, "disk_gb": 80}
    assert plan.changes == ["cpu", "disk", "memory"]  # no tag change: tags are written sorted
    assert plan.snapshot_first is True  # one slot in mode slot, on storage that takes snapshots
    assert world.writes(since) == []  # reads only

    seen: list[tuple[str, str]] = []
    real = proxmox.ProxmoxClient.take_snapshot

    async def take_snapshot(self, node, vmid, name, description=""):
        async with get_sessionmaker()() as db:
            row = await db.scalar(select(MachineSnapshot).where(MachineSnapshot.name == name))
        seen.append((row.status, row.reason))
        return await real(self, node, vmid, name, description)

    monkeypatch.setattr(proxmox.ProxmoxClient, "take_snapshot", take_snapshot)
    key = (await host(env)).host_key
    assert await machines.resize_step(ctx) == ("succeeded", "Resized to 6 vCPU, 12 GB, 80 GB")
    assert seen == [("pending", "pre_resize")]  # the row was committed before its task
    shutdown = calls(world, "POST", "/nodes/pve1/qemu/100/status/shutdown")
    assert len(shutdown) == 1
    # The create's; check_resize here and again in the step (the read-only checks run again, §6.7); the second
    # plan, from the stopped VM.
    assert world.commands().count("plan") == 4
    vm = world.fake.vm(100)
    assert vm["status"] == "running" and vm["config"]["cores"] == 6 and vm["config"]["memory"] == 12288
    assert pxp._disk_gb(vm["config"]["scsi0"]) == 80
    row = await machine(env)
    assert row.applied["cores"] == 6 and row.applied["disk_gb"] == 80
    assert (await host(env)).host_key == key  # the same pinned key answered afterwards
    async with get_sessionmaker()() as db:
        snap = await db.scalar(select(MachineSnapshot))
    assert snap.status == "ready" and snap.reason == "pre_resize" and snap.sizes["cores"] == 4
    (resized,) = await audits("machine.resize")
    assert resized.details["to"] == {"cores": 6, "memory_mb": 12288, "disk_gb": 80}


async def test_27_no_pre_resize_snapshot_on_storage_without_snapshots(tmp_path, monkeypatch, net):
    world = a_world(tmp_path, monkeypatch, net, storage_type="lvm")
    env, _ctx, _ = await made(world, storage_type="lvm")
    assert (await machine(env)).snapshot_mode == "none"
    await grow(env, cores=6)
    ctx = await reload(world, env)
    assert (await ctx.provider.check_resize(ctx)).snapshot_first is False
    assert (await machines.resize_step(ctx))[0] == "succeeded"
    assert not calls(world, "POST", "/nodes/pve1/qemu/100/snapshot")


@pytest.mark.parametrize("how", ["delete", "attribute"])
async def test_27_a_plan_doing_more_than_sizes_refuses_in_check_resize(world, how):
    env, _ctx, _ = await made(world)
    await grow(env, cores=6)
    if how == "delete":
        world.knobs(plan_extra="delete")
        text = r"\(proxmox_virtual_environment_vm.other: delete\)"
    else:
        with world.fake.edit() as state:
            state["vms"]["100"]["config"]["net0"] = "virtio,bridge=vmbr1"
        text = r"\(network_device\)"
    ctx = await reload(world, env)
    since = len(world.fake.requests)
    with pytest.raises(MachineError, match=f"^Terraform's plan for {VM} would change more than its size {text}; "
                                           "Slipway applied nothing$"):
        await ctx.provider.check_resize(ctx)
    assert world.writes(since) == []


async def test_27_a_qcow2_grow_with_snapshots_refuses_in_check_resize(tmp_path, monkeypatch, net):
    world = a_world(tmp_path, monkeypatch, net, storage_type="dir", file_format="qcow2")
    env, _ctx, _ = await made(world, storage_type="dir")
    world.fake.add_snapshot(100, "slipway-20261115T100000Z")
    await grow(env, disk_gb=80)
    ctx = await reload(world, env)
    with pytest.raises(MachineError, match=rf"^Proxmox can't grow {VM}'s qcow2 disk while it has VM snapshots "
                                           r"\(slipway-20261115T100000Z\); delete them first$"):
        await ctx.provider.check_resize(ctx)
    # Through prepare (the job lists a resize), the refusal names the way out.
    with pytest.raises(MachineError, match="To deploy without the resize, set slipway-uat-blue's size back to 4 vCPU, "
                                           "8 GB, 64 GB on the environment page$"):
        await machines.prepare(await reload(world, env), resize=True)


async def test_27_a_shutdown_timeout_leaves_the_vm_running_at_its_old_size(world, monkeypatch):
    env, _ctx, _ = await made(world)
    await grow(env, cores=6)
    world.fake.task_hangs("shutdown")
    monkeypatch.setitem(pxp.TASK_TIMEOUTS, "shutdown", 0.05)
    ctx = await reload(world, env)
    with pytest.raises(MachineError, match=f"^{VM} didn't shut down in 5 minutes; Slipway left it running at its old "
                                           "size$"):
        await machines.resize_step(ctx)
    vm = world.fake.vm(100)
    assert vm["status"] == "running" and vm["config"]["cores"] == 4
    assert (await machine(env)).last_task["kind"] == "shutdown"  # still running: the next change waits for it
    assert await audits("machine.left_off") == []


async def test_27_a_failed_apply_starts_the_vm_again_and_reads_its_size(world):
    env, _ctx, _ = await made(world)
    world.fake.add_snapshot(100, "slipway-20261115T100000Z")
    world.fake.resize_refused_with_snapshots()
    await grow(env, disk_gb=80)
    ctx = await reload(world, env)
    with pytest.raises(MachineError, match=f"^Terraform couldn't resize {VM}; it is running at 4 vCPU, 8 GB, 64 GB$"):
        await machines.resize_step(ctx)
    assert world.fake.vm(100)["status"] == "running"
    assert await audits("machine.left_off") == []  # it runs: not left off


async def test_27_the_growpart_warning(world):
    env, _ctx, _ = await made(world)
    shim = world.root / "df-bin"
    shim.mkdir()
    (shim / "df").write_text("#!/bin/sh\necho ' Size'\necho '  30G'\n")
    (shim / "df").chmod(0o755)
    blue = world.vms["blue"]
    blue.env["PATH"] = f"{shim}:{blue.env['PATH']}"
    await grow(env, disk_gb=80)
    log = vf.Lines()
    ctx = await reload(world, env, log)
    plan = await ctx.provider.check_resize(ctx)
    applied = await ctx.provider.resize(ctx, plan)
    warning = (f"{VM}'s disk grew to 80 GB but its root file system is 30 GB: cloud-init's growpart didn't run; run "
               "\"sudo growpart /dev/sda 1 && sudo resize2fs /dev/sda1\" on it")
    assert applied["warnings"] == [warning] and warning in log
    assert {k: applied[k] for k in ("cores", "memory_mb", "disk_gb")} == {"cores": 4, "memory_mb": 8192, "disk_gb": 80}


# ------------------------------------------------------------------------------ test 28: snapshots


async def ready_vm(world: World, *, storage_type: str = "lvmthin") -> tuple[vf.VmEnv, machines.MachineContext]:
    """A ready VM without Terraform: the fake VM added with Slipway's markers at id 100 (for snapshots and tasks)."""
    env = await blue_env(world, storage_type=storage_type)
    key = world.vms.pinned_key(BLUE)
    world.fake.add_vm(100, VM, tags=terraform.vm_tags(env.env_id), address=BLUE, host_key=key,
                      description=terraform.vm_description("uat", env.env_id, "blue"))
    async with get_sessionmaker()() as db:
        row = await db.get(Machine, env.machines["blue"])
        h = await db.get(Host, row.host_id)
        row.ids, row.stage, row.ready_at = {"vmid": 100}, "ready", utcnow()
        row.applied = {**row.size, "at": utcnow().isoformat(), "deployment_id": None}
        row.host_key_public = key
        hosts.set_phase(h, "ready", stage="ready")
        h.host_key, h.host_key_fingerprint = key, ssh.fingerprint(key)
        await db.commit()
    ctx = await reload(world, env)
    mode = (await ctx.provider.describe(ctx)).snapshot_mode
    async with get_sessionmaker()() as db:
        (await db.get(Machine, env.machines["blue"])).snapshot_mode = mode
        await db.commit()
    return env, await reload(world, env)


async def snapshot_row(env: vf.VmEnv, name: str = "slipway-20261116T090000Z",
                       reason: str = "manual") -> MachineSnapshot:
    async with get_sessionmaker()() as db:
        row = MachineSnapshot(machine_id=env.machines["blue"], name=name, reason=reason, status="pending",
                              identity_fp="0" * 64, sizes={"cores": 4}, taken_at=utcnow())
        db.add(row)
        await db.commit()
        return row


@pytest.mark.parametrize("storage_type, file_format, mode", [
    ("lvmthin", None, "any"), ("zfspool", None, "newest_only"), ("lvm", None, "none"), ("dir", "qcow2", "any"),
    ("dir", "raw", "none"),
])
async def test_28_snapshot_mode_from_the_storage_and_the_feature_check(tmp_path, monkeypatch, net, storage_type,
                                                                     file_format, mode):
    world = a_world(tmp_path, monkeypatch, net, storage_type=storage_type, file_format=file_format)
    _env, ctx = await ready_vm(world, storage_type=storage_type)
    assert ctx.machine.snapshot_mode == mode
    assert pxp.snapshot_mode_of(mode != "none", storage_type) == mode


async def test_28_a_snapshot_is_pending_with_its_task_recorded_before_the_wait(world, monkeypatch):
    env, ctx = await ready_vm(world)
    row = await snapshot_row(env)
    seen: list[Any] = []
    real = proxmox.ProxmoxClient.wait

    async def wait(self, upid, what, *, timeout=None):
        async with get_sessionmaker()() as db:
            snap = await db.get(MachineSnapshot, row.id)
            m = await db.get(Machine, env.machines["blue"])
        seen.append((snap.status, (m.last_task or {}).get("id") == upid, (m.last_task or {}).get("kind")))
        return await real(self, upid, what, timeout=timeout)

    monkeypatch.setattr(proxmox.ProxmoxClient, "wait", wait)
    assert await ctx.provider.snapshot(ctx, row) is False
    assert seen == [("pending", True, "snapshot")]
    async with get_sessionmaker()() as db:
        assert (await db.get(MachineSnapshot, row.id)).status == "ready"
        assert (await db.get(Machine, env.machines["blue"])).last_task is None
    assert [s["name"] for s in world.fake.vm(100)["snapshots"]] == [row.name]
    describe = await ctx.provider.describe(ctx)
    assert [(s.name, s.ours, s.newest) for s in describe.snapshots] == [(row.name, True, True)]


async def test_28_a_late_task_ends_ready_after_the_grace(world, monkeypatch):
    env, ctx = await ready_vm(world)
    world.fake.snapshot_task_late()
    monkeypatch.setitem(pxp.TASK_TIMEOUTS, "snapshot", 0.05)
    row = await snapshot_row(env)
    await ctx.provider.snapshot(ctx, row)
    async with get_sessionmaker()() as db:
        stored = await db.get(MachineSnapshot, row.id)
    assert (stored.status, stored.note) == ("ready", "The task ended late")


async def test_28_a_failed_task_leaves_the_row_failed(world):
    env, ctx = await ready_vm(world)
    world.fake.task_fails("snapshot")
    row = await snapshot_row(env)
    with pytest.raises(MachineError, match=f"^Proxmox didn't take the VM snapshot {row.name} of {VM}$"):
        await ctx.provider.snapshot(ctx, row)
    async with get_sessionmaker()() as db:
        assert (await db.get(MachineSnapshot, row.id)).status == "failed"


async def test_28_no_snapshot_on_storage_without_them(tmp_path, monkeypatch, net):
    world = a_world(tmp_path, monkeypatch, net, storage_type="lvm")
    env, ctx = await ready_vm(world, storage_type="lvm")
    row = await snapshot_row(env)
    with pytest.raises(MachineError, match=f"^local-lvm \\(lvm\\) can't take VM snapshots of {VM}$"):
        await ctx.provider.snapshot(ctx, row)
    assert world.writes() == []


async def test_28_revert_starts_the_vm_and_checks_the_address_then_drop(world):
    env, ctx = await ready_vm(world)
    first = await snapshot_row(env, "slipway-20261116T090000Z")
    await ctx.provider.snapshot(ctx, first)
    second = await snapshot_row(env, "slipway-20261116T100000Z")
    await ctx.provider.snapshot(ctx, second)
    since = len(world.fake.requests)
    await ctx.provider.revert(ctx, first)
    writes = [r["path"] for r in world.writes(since)]
    assert writes == ["/nodes/pve1/qemu/100/snapshot/slipway-20261116T090000Z/rollback",
                      "/nodes/pve1/qemu/100/status/start"]
    assert world.fake.vm(100)["status"] == "running"
    assert any("network-get-interfaces" in r["path"] for r in world.fake.requests[since:])
    await ctx.provider.drop_snapshot(ctx, second)
    assert [s["name"] for s in world.fake.vm(100)["snapshots"]] == [first.name]
    with pytest.raises(MachineError, match="has no VM snapshot named slipway-20261116T100000Z"):
        await ctx.provider.drop_snapshot(ctx, second)


async def test_28_on_zfs_proxmox_refuses_an_older_rollback_and_slipway_refuses_first(tmp_path, monkeypatch, net):
    world = a_world(tmp_path, monkeypatch, net, storage_type="zfspool")
    env, ctx = await ready_vm(world, storage_type="zfspool")
    assert ctx.machine.snapshot_mode == "newest_only"
    older = await snapshot_row(env, "slipway-20261116T090000Z")
    await ctx.provider.snapshot(ctx, older)
    newer = await snapshot_row(env, "slipway-20261116T100000Z")
    await ctx.provider.snapshot(ctx, newer)
    since = len(world.fake.requests)
    with pytest.raises(MachineError, match="reverts only to its newest VM snapshot"):
        await ctx.provider.revert(ctx, older)
    assert world.writes(since) == []
    # What Proxmox itself answers, which the refusal above keeps Slipway from reaching.
    async with proxmox.ProxmoxClient.for_account(ctx.account, sleep=vf.no_sleep) as api:
        upid = await api.rollback("pve1", 100, older.name)
        with pytest.raises(proxmox.TaskFailed) as caught:
            await api.wait(upid, "revert")
    assert caught.value.text == proxmox.NOT_NEWEST


# ---------------------------------------------------------------------------- test 29: destroy


async def drop_instance(env: vf.VmEnv, slot: str = "blue") -> None:
    """Remove slot deletes the slot's instance (its jobs go with it) before the VM."""
    async with get_sessionmaker()() as db:
        await db.execute(delete(Instance).where(Instance.id == env.instances[slot]))
        await db.commit()


async def rows_left(env: vf.VmEnv) -> dict[str, int]:
    async with get_sessionmaker()() as db:
        return {
            "machine": len(list(await db.scalars(select(Machine)))),
            "state": len(list(await db.scalars(select(TerraformState)))),
            "vm rows": len(list(await db.scalars(select(Resource).where(Resource.kind == "vm")))),
            "host": len(list(await db.scalars(select(Host).where(Host.id == env.hosts["blue"])))),
        }


async def test_29_never_made(world):
    env = await blue_env(world)
    ctx = await reload(world, env)
    assert await ctx.provider.destroy_blockers(ctx) == []
    assert await ctx.provider.destroy(ctx) == [f"Slipway never made {VM}"]


async def test_29_reserved_and_never_ours_is_released(world):
    env = await blue_env(world)
    await reserve(world, env)
    await set_stage(env, "creating")
    world.fake.reuse_vmid(100, "web-1")
    await drop_instance(env)
    ctx = await reload(world, env, job=None)
    assert await ctx.provider.destroy_blockers(ctx) == []
    assert await machines.remove(ctx) == ["VM 100 was never made by Slipway, or is gone; forgetting the id"]
    assert await rows_left(env) == {"machine": 0, "state": 0, "vm rows": 0, "host": 0}
    assert world.fake.vm(100)["name"] == "web-1"


async def test_29_ready_and_gone_is_already_gone_and_every_row_goes(world):
    env, ctx, _ = await made(world)
    workdir = world.workdir(env.machines["blue"])
    assert workdir.exists()
    world.fake.remove_vm(100)
    await drop_instance(env)
    ctx = await reload(world, env, job=None)
    assert await ctx.provider.destroy_blockers(ctx) == []
    assert await machines.remove(ctx) == ["VM 100 is already gone"]
    assert await rows_left(env) == {"machine": 0, "state": 0, "vm rows": 0, "host": 0}
    assert not workdir.exists()


async def test_29_ready_and_hidden_is_a_forgettable_blocker_and_nothing_goes(world):
    env, ctx, _ = await made(world)
    world.fake.remove_vm(100)
    world.fake.hidden(100)
    await drop_instance(env)
    ctx = await reload(world, env, job=None)
    (blocker,) = await ctx.provider.destroy_blockers(ctx)
    assert blocker.forgettable and blocker.text == ("Slipway can't see VM 100 (check the token's rights on "
                                                    "/pool/slipway); nothing was removed")
    with pytest.raises(MachineError, match="nothing was removed"):
        await machines.remove(ctx)
    assert await rows_left(env) == {"machine": 1, "state": 1, "vm rows": 1, "host": 1}


async def test_29_ours_in_the_state_goes_through_terraform_destroy(world):
    env, ctx, log = await made(world)
    await drop_instance(env)
    ctx = await reload(world, env, job=None)
    assert await machines.remove(ctx) == [f"Removed {VM} (VM 100) with Terraform"]
    assert "destroy" in world.commands() and world.fake.vm(100) is None
    assert await rows_left(env) == {"machine": 0, "state": 0, "vm rows": 0, "host": 0}
    (destroyed,) = await audits("machine.destroy")
    assert destroyed.details == {"name": VM, "ids": {"vmid": 100}}


async def test_29_an_untagged_clone_not_in_the_state_is_deleted_through_the_api_after_the_lock(world):
    env = await blue_env(world)
    world.knobs(die_after_clone=True, clone_lock_outlives=3)
    with pytest.raises(MachineError):
        await machines.prepare(await reload(world, env))
    await drop_instance(env)
    log = vf.Lines()
    ctx = await reload(world, env, log, job=None)
    assert await machines.remove(ctx) == [f"Removed {VM} (VM 100) through the Proxmox API"]
    assert any(line.startswith("Waiting for Proxmox's qmclone task on VM 100") for line in log)
    assert world.fake.vm(100) is None and "destroy" not in world.commands()


async def test_29_a_tagged_vm_not_in_the_state_is_shut_down_and_deleted_through_the_api(world):
    env = await blue_env(world)
    await reserve(world, env)
    await set_stage(env, "booting")
    world.fake.add_vm(100, VM, tags=terraform.vm_tags(env.env_id), address=BLUE)
    await drop_instance(env)
    ctx = await reload(world, env, job=None)
    assert await machines.remove(ctx) == [f"Removed {VM} (VM 100) through the Proxmox API"]
    assert [r["path"] for r in world.writes()] == ["/nodes/pve1/qemu/100/status/shutdown", "/nodes/pve1/qemu/100"]


async def test_29_still_there_afterwards_is_refused(world, monkeypatch):
    env, ctx, _ = await made(world)
    await drop_instance(env)
    real = terraform.Terraform.destroy

    async def destroy_that_leaves_it(self):
        await real(self)
        world.fake.add_vm(100, VM, tags=terraform.vm_tags(env.env_id), address=BLUE)

    monkeypatch.setattr(terraform.Terraform, "destroy", destroy_that_leaves_it)
    ctx = await reload(world, env, job=None)
    with pytest.raises(MachineError, match="^VM 100 is still there after Terraform's destroy. Remove it by hand in "
                                           "Proxmox, then retry$"):
        await machines.remove(ctx)
    assert (await rows_left(env))["machine"] == 1


async def test_29_a_running_task_is_a_blocker_that_isnt_forgettable(world, monkeypatch):
    env, ctx, _ = await made(world)
    world.fake.run_task(100, "vzdump", polls=None)
    monkeypatch.setattr(machines, "TASK_WAIT_LIMIT", 10.0)
    ctx = await reload(world, env)
    (blocker,) = await ctx.provider.destroy_blockers(ctx)
    assert not blocker.forgettable and blocker.text.startswith("Proxmox is still running vzdump on VM 100 (since ")


async def test_29_a_terraform_lock_held_by_a_live_job_is_a_blocker(world):
    env, ctx, _ = await made(world)
    other = await deployment(env, None, kind="activate")  # a live job that holds the lock
    async with get_sessionmaker()() as db:
        (await db.get(TerraformState, env.machines["blue"])).lock_id = other
        await db.commit()
    ctx = await reload(world, env)
    (blocker,) = await ctx.provider.destroy_blockers(ctx)
    assert not blocker.forgettable and blocker.text.startswith(f"Terraform state of {VM} is in use by deployment ")


# -------------------------------------------------------------------- test 66: tasks.wait_idle


async def test_66_a_lock_with_a_running_task_is_waited_for_then_the_change_runs(world, monkeypatch):
    _env, ctx = await ready_vm(world)
    monkeypatch.setitem(fp.LOCKS, "vzdump", "backup")  # a backup holds the VM's lock while it runs
    world.fake.run_task(100, "vzdump", polls=3)
    assert world.fake.vm(100)["lock"] == "backup"
    await ctx.provider.stop(ctx, timeout=60)
    assert any(line.startswith("Waiting for Proxmox's vzdump task on VM 100") for line in ctx.say)
    assert world.fake.vm(100)["status"] == "stopped"


async def test_66_a_task_outliving_the_limit_refuses_with_nothing_changed(world, monkeypatch):
    _env, ctx = await ready_vm(world)
    world.fake.run_task(100, "vzdump", polls=None)
    monkeypatch.setattr(machines, "TASK_WAIT_LIMIT", 10.0)
    with pytest.raises(MachineError, match=r"^Proxmox is still running vzdump on VM 100 \(since \d\d:\d\d\); "
                                           "Slipway changed nothing. Wait for it to finish, or stop it in Proxmox, "
                                           "then retry$"):
        await ctx.provider.stop(ctx, timeout=60)
    assert world.writes() == [] and world.fake.vm(100)["status"] == "running"


async def test_66_a_lock_with_no_task_refuses_with_the_qm_unlock_text(world):
    _env, ctx = await ready_vm(world)
    world.fake.stale_lock(100, "backup")
    with pytest.raises(MachineError, match='^VM 100 is locked \\(backup\\) with no task running; check it in '
                                           'Proxmox and run "qm unlock 100", then retry$'):
        await ctx.provider.stop(ctx, timeout=60)
    assert world.writes() == []


async def test_66_every_task_is_in_last_task_before_its_wait_and_cleared_after(world, monkeypatch):
    env, ctx = await ready_vm(world)
    seen: list[tuple[bool, str | None]] = []
    real = proxmox.ProxmoxClient.wait

    async def wait(self, upid, what, *, timeout=None):
        async with get_sessionmaker()() as db:
            m = await db.get(Machine, env.machines["blue"])
        seen.append(((m.last_task or {}).get("id") == upid, (m.last_task or {}).get("kind")))
        return await real(self, upid, what, timeout=timeout)

    monkeypatch.setattr(proxmox.ProxmoxClient, "wait", wait)
    await ctx.provider.stop(ctx, timeout=60)
    await machines.prepare(await reload(world, env))  # starts it again
    assert seen == [(True, "shutdown"), (True, "start")]
    assert (await machine(env)).last_task is None
    assert not [r for r in world.fake.requests if r["method"] == "DELETE" and "/tasks/" in r["path"]]


# -------------------------------------------------------------------- test 67: a stale template key


async def test_67_boot_finished_is_waited_for_and_the_vms_own_key_read(world):
    env = await blue_env(world)
    world.fake.stale_template_key(3)
    assert (await machines.prepare(await reload(world, env)))[0] == "succeeded"
    boot_reads = [r for r in world.fake.requests if r["params"].get("file") == pxp.BOOT_FINISHED]
    assert len(boot_reads) == 4  # three missing, then there
    assert (await host(env)).host_key.split()[:2] == world.vms.pinned_key(BLUE).split()[:2]
    assert fp.TEMPLATE_KEY.split()[1] not in (await machine(env)).host_key_public


async def test_67_a_key_still_stale_after_boot_finished_is_read_again_while_pinning(world, monkeypatch):
    env = await blue_env(world)
    _old_private, old = ssh.generate_keypair("root@template")
    world.knobs(host_key=old)
    right = world.vms.pinned_key(BLUE)
    real = proxmox.ProxmoxClient.agent_file
    reads: list[str] = []

    async def agent_file(self, node, vmid, path):
        text = await real(self, node, vmid, path)
        if path == pxp.HOST_KEY_FILE:
            reads.append(text)
            if len(reads) == 1:  # cloud-init replaces the template's key after Slipway read it once
                with world.fake.edit() as state:
                    state["vms"][str(vmid)]["files"][path] = right + "\n"
        return text

    monkeypatch.setattr(proxmox.ProxmoxClient, "agent_file", agent_file)
    assert (await machines.prepare(await reload(world, env)))[0] == "succeeded"
    assert len(reads) == 2 and reads[0].split()[1] == old.split()[1]
    h, row = await host(env), await machine(env)
    assert h.host_key.split()[:2] == right.split()[:2] and row.host_key_public.split()[:2] == right.split()[:2]


async def test_67_a_key_that_never_matches_pins_nothing(world):
    env = await blue_env(world)
    _old_private, old = ssh.generate_keypair("root@template")
    world.knobs(host_key=old)
    with pytest.raises(MachineError, match=f"^The VM at {BLUE} answered SSH with a key that isn't the one read through "
                                           "the Proxmox guest agent. Slipway pinned nothing.$"):
        await machines.prepare(await reload(world, env))
    h, row = await host(env), await machine(env)
    assert h.host_key is None and row.stage == "booting"
    assert await audits("host.key_pinned") == []


# ------------------------------------------------------------------------------------------- texts


def test_disk_sizes_and_applied_sizes_are_read_from_proxmox_settings():
    assert pxp._disk_gb("local-lvm:vm-100-disk-0,size=64G") == 64
    assert pxp._disk_gb("local:100/vm-100-disk-0.qcow2,size=3584M") == 4
    assert pxp._disk_gb("local-lvm:vm-100-disk-0,size=1T") == 1024
    assert pxp._disk_gb("local-lvm:vm-100-disk-0") is None
    assert pxp.applied_of({"cores": 2, "memory": "4096", "scsi0": "x:y,size=32G"}) == {
        "cores": 2, "memory_mb": 4096, "disk_gb": 32}
    assert pxp.applied_of({"cores": 2}) is None


async def test_no_environment_row_is_changed_by_the_provider(world):
    env, _ctx, _ = await made(world)
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
    assert row.notice is None
    assert vmnet.vm_name("uat", "blue") == VM
