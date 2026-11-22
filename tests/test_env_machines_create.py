"""Create and Add slot with new VMs (S18, phase 5 §9.2 and §9.5, the service half): P5 tests 52 (every refusal of
§9.2 with its field, nothing written; ``?check=true`` lists the planned VMs and warnings and calls no
hypervisor), 53 (create writes the environment, instances, hosts, claims and machines in one transaction; a claim
taken at the commit leaves nothing written), 54 (Add slot's half: a new VM on the account and network of the
others; a host id of another environment's VM is refused), the VM PATCH rules (§9.4), and the chains 44
(Blue/Green on three new Proxmox VMs) and 45 (blue on an SSH host, green and the data server on new ESXi VMs),
run for real from ``environments.create`` through each deploy that makes a VM and the chained activate.

The HTTP half of 53 (two creates racing) is S20's.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

import pytest
from sqlalchemy import func, select, update

from slipway.db.session import get_sessionmaker
from slipway.models import (
    AddressClaim,
    AppSetting,
    AuditEvent,
    Environment,
    Host,
    Instance,
    Machine,
    ProviderAccount,
    Repository,
)
from slipway.services import environments, machines, manifest, switchyard
from slipway.services.environments import CreateRefused, NewEnvironment
from tests import fake_proxmox as fp
from tests import vm_fixtures as vf
from tests.conftest import make_user
from tests.fake_hosts import ENV_EXAMPLE, ENV_YML

FILES = {"slipway.yml": ENV_YML, "deploy/env.example": ENV_EXAMPLE}
ADMIN = {"fields": {"email": "ada@example.com", "name": "Ada"}, "mode": "password", "password": "correct-horse-9"}
MAN = manifest.parse(ENV_YML)

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")


@dataclass
class Ctx:
    user: Any = None
    perms: set[str] = field(default_factory=lambda: {"*"})

    def can(self, permission: str) -> bool:
        return "*" in self.perms or permission in self.perms


@dataclass
class World:
    repo_id: uuid.UUID
    user: Any
    pve: ProviderAccount
    net: vf.Network

    def ctx(self, *perms: str) -> Ctx:
        return Ctx(self.user, set(perms) if perms else {"*"})


def reader(files: dict[str, str] | None = None):
    files = FILES if files is None else files

    async def read(repo, branch, path):
        return files.get(path)

    return read


@pytest.fixture
async def world(monkeypatch) -> World:
    net = vf.quiet_network(monkeypatch)
    user = await make_user(f"admin-{uuid.uuid4().hex[:6]}@example.com", roles=["admin"])
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=4343, full_name="acme/demo", owner="acme", name="demo",
                          html_url="https://github.com/acme/demo", detected_config={})
        db.add(repo)
        db.add(AppSetting(key=switchyard.SETTING_KEY, value={"url": "https://sy.example.test",
                                                             "default_tls_mode": "auto"}, secret="sy_" + "k" * 30))
        await db.commit()
    return World(repo_id=repo.id, user=user, pve=await vf.proxmox_account(), net=net)


def vm(account: ProviderAccount, address: str | None = "auto", network: str = "lan", **size: Any) -> dict[str, Any]:
    return {"machine": {"account_id": account.id, "network": network, "address": address, **size}}


def body(w: World, hosts: dict[str, Any] | None = None, **kw: Any) -> NewEnvironment:
    values: dict[str, Any] = dict(
        name="prod", repository_id=w.repo_id, data_mode="server",
        hosts=hosts if hosts is not None else {"blue": vm(w.pve, "10.0.0.101"), "green": vm(w.pve, "10.0.0.102"),
                                               "data": vm(w.pve, "10.0.0.103")},
        settings={"APP_DOMAIN": "prod.example.com"}, traffic={"switch": "switchyard", "dns": None}, first_admin=ADMIN)
    values.update(kw)
    return NewEnvironment(**values)


async def refused(w: World, request: NewEnvironment, ctx: Ctx | None = None) -> CreateRefused:
    async with get_sessionmaker()() as db:
        with pytest.raises(CreateRefused) as err:
            await environments.validate_create(db, request, ctx or w.ctx(), read_file=reader())
    return err.value


async def counts() -> tuple[int, ...]:
    async with get_sessionmaker()() as db:
        return tuple([await db.scalar(select(func.count()).select_from(m))
                      for m in (Environment, Instance, Host, Machine, AddressClaim)])


async def create(w: World, request: NewEnvironment) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        plan = await environments.validate_create(db, request, w.ctx(), read_file=reader())
        env = await environments.create(db, plan, w.ctx())
        await db.commit()
        return env.id


async def set_row(model: Any, ident: uuid.UUID, **values: Any) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(update(model).where(model.id == ident).values(**values))
        await db.commit()


# ------------------------------------------------------------------------------------------ test 52


async def test_52_every_refusal_of_create_with_vms_with_its_field_and_nothing_written(world):
    w = world
    before = await counts()

    async def no(request, status, detail, where, ctx=None):
        err = await refused(w, request, ctx)
        assert (err.status, err.detail, err.field) == (status, detail, where), err.detail

    # 1. machines:write.
    await no(body(w), 403, "Making a VM needs the machines:write permission", "hosts.blue",
             w.ctx("environments:write"))
    # 2. The account: a DigitalOcean one, untrusted, never tested, failing.
    async with get_sessionmaker()() as db:
        do = ProviderAccount(provider="digitalocean", name="do-main", secret="dop_v1_x", config={"region": "nyc3"})
        db.add(do)
        await db.commit()
    await no(body(w, {"blue": vm(do)}, data_mode="slot", traffic={"switch": "none", "dns": None}), 409,
             "do-main is a DigitalOcean account: choose DigitalOcean under Where", "hosts.blue.machine.account_id")
    untrusted = await vf.proxmox_account(name="lab2", pem=None)
    await no(body(w, {"blue": vm(untrusted)}, data_mode="slot", traffic={"switch": "none", "dns": None}), 409,
             "Trust lab2's certificate in Settings → Integrations first", "hosts.blue.machine.account_id")
    untested = await vf.proxmox_account(name="lab3")
    await set_row(ProviderAccount, untested.id, facts={})
    await no(body(w, {"blue": vm(untested)}, data_mode="slot", traffic={"switch": "none", "dns": None}), 409,
             "Test lab3 first: Slipway needs to know its storage type", "hosts.blue.machine.account_id")
    await set_row(ProviderAccount, untested.id, facts={"storage_type": "lvmthin"}, status="error",
                  checks=[{"name": "token", "ok": False, "level": "error", "text": "The token was refused."}])
    await no(body(w, {"blue": vm(untested)}, data_mode="slot", traffic={"switch": "none", "dns": None}), 409,
             "lab3's last test failed: The token was refused. Test it again in Settings → Integrations",
             "hosts.blue.machine.account_id")
    # 3. One account and one network; the network must exist.
    other = await vf.proxmox_account(name="lab4")
    await no(body(w, {"blue": vm(w.pve), "green": vm(other), "data": vm(w.pve)}), 409,
             "prod's VMs share one account and one network", "hosts.green.machine")
    await no(body(w, {"blue": vm(w.pve, network="wan")}, data_mode="slot", traffic={"switch": "none", "dns": None}),
             409, "lab has no network named wan", "hosts.blue.machine.network")
    # 4. The addresses: outside the subnet, the gateway, in use by a host, claimed, twice, an empty pool.
    one = {"data_mode": "slot", "traffic": {"switch": "none", "dns": None}}
    err = await refused(w, body(w, {"blue": vm(w.pve, "192.168.1.5")}, **one))
    assert (err.status, err.field) == (422, "hosts.blue.machine.address") and "10.0.0.0/24" in err.detail
    err = await refused(w, body(w, {"blue": vm(w.pve, "10.0.0.1")}, **one))
    assert (err.status, err.field) == (422, "hosts.blue.machine.address")
    async with get_sessionmaker()() as db:
        db.add(Host(name="pve1", hostname="10.0.0.120", username="root", metrics={}))
        await db.commit()
    await no(body(w, {"blue": vm(w.pve, "10.0.0.120")}, **one), 409, "10.0.0.120 is used by host pve1",
             "hosts.blue.machine.address")
    taken = await vf.vm_env(w.pve, name="uat", addresses={"blue": "10.0.0.130"})
    await no(body(w, {"blue": vm(w.pve, "10.0.0.130")}, **one), 409, "10.0.0.130 is reserved for uat's blue VM",
             "hosts.blue.machine.address")
    await no(body(w, {"blue": vm(w.pve, "10.0.0.140"), "green": vm(w.pve, "10.0.0.140"), "data": vm(w.pve)}), 409,
             "10.0.0.140 is given to both blue and green: give each VM its own address", "hosts.green.machine.address")
    nopool = await vf.proxmox_account(name="lab5", networks=[{**vf.LAN_PVE, "pool": None}])
    await no(body(w, {"blue": vm(nopool)}, **one), 409, "lan has no address pool: type an address",
             "hosts.blue.machine.address")
    # 5. Sizes, and the host name.
    err = await refused(w, body(w, {"blue": vm(w.pve, cores=99)}, **one))
    assert (err.status, err.field) == (422, "hosts.blue.machine.size") and "between 1 and 64" in err.detail
    async with get_sessionmaker()() as db:
        db.add(Host(name="slipway-prod-blue", hostname="10.0.0.99", username="root", metrics={}))
        await db.commit()
    await no(body(w, {"blue": vm(w.pve)}, **one), 409,
             "A host named slipway-prod-blue already exists: rename it, or pick another environment name", "hosts.blue")
    # 0. A host id that is another environment's VM.
    await no(body(w, {"blue": taken.hosts["blue"]}, **one), 409,
             "slipway-uat-blue is a VM of environment uat; only its slots run there", "hosts.blue")
    after = await counts()
    assert after[0] == before[0] + 1 and after[3] == before[3] + 1  # only vm_env's own rows were added


async def test_52_check_lists_the_planned_vms_and_warnings_and_calls_no_hypervisor(world, monkeypatch):
    w = world
    calls: list[str] = []
    monkeypatch.setattr(fp.FakeProxmox, "install", lambda *a, **k: calls.append("install"))
    await set_row(ProviderAccount, w.pve.id, facts={"storage_type": "lvmthin", "free_gb": 100})
    before = await counts()
    async with get_sessionmaker()() as db:
        plan = await environments.validate_create(db, body(w, {"blue": vm(w.pve), "green": vm(w.pve),
                                                               "data": vm(w.pve, disk_gb=80)}),
                                                  w.ctx(), read_file=reader())
    out = plan.to_json()
    assert [(m["slot"], m["name"], m["address"]) for m in out["plan"]["machines"]] == [
        ("blue", "slipway-prod-blue", "10.0.0.100"), ("green", "slipway-prod-green", "10.0.0.101"),
        ("data", "slipway-prod-data", "10.0.0.102")]
    assert out["plan"]["machines"][2]["size"] == {"cores": 4, "memory_mb": 8192, "disk_gb": 80}
    assert out["plan"]["slots"]["green"] == {"host_id": None, "host": "slipway-prod-green", "role": "app",
                                             "slug": "prod-green", "planned": "proxmox"}
    assert "cost" not in out and "cloud" not in out["plan"]
    assert out["warnings"] == ["lab hasn't been tested yet", "local-lvm has 100 GB free; the new disks need 208 GB"]
    assert await counts() == before and calls == []
    # The data server's clients are the app VMs' planned addresses (D4): the server role rendered with them.
    assert plan.hosts["blue"].client_address == "10.0.0.100" and plan.hosts["data"].upstream_address == "10.0.0.102"


# ------------------------------------------------------------------------------------------ test 53


async def test_53_create_writes_hosts_claims_and_machines_in_one_transaction(world):
    w = world
    env_id = await create(w, body(w, {"blue": vm(w.pve), "green": vm(w.pve, "10.0.0.110"), "data": vm(w.pve)}))
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        mem = await environments.members(db, env)
        rows = {m.slot: m for m in await db.scalars(select(Machine).where(Machine.environment_id == env_id))}
        assert env.provider == "ssh" and env.data_mode == "server" and env.provider_account_id is None
        assert {s: r.network["address"] for s, r in rows.items()} == {"blue": "10.0.0.100", "green": "10.0.0.110",
                                                                      "data": "10.0.0.101"}
        for slot, inst in mem.items():
            host = inst.host
            assert host.id == rows[slot].host_id and host.owner_environment_id == env_id
            assert host.hostname == rows[slot].network["address"] and host.provider == "proxmox"
            assert rows[slot].stage == "planned" and rows[slot].size == vf_default()
        claims = {c.address: c.host_id for c in await db.scalars(select(AddressClaim))}
        assert claims == {r.network["address"]: r.host_id for r in rows.values()}
        events = {e.action: e for e in await db.scalars(select(AuditEvent))}
        assert events["environment.create"].details["machines"]["green"] == {
            "account": "lab", "network": "lan", "address": "10.0.0.110", "size": vf_default()}
        plans = (await db.scalars(select(AuditEvent).where(AuditEvent.action == "machine.plan"))).all()
        assert len(plans) == 3
        assert fp.TOKEN not in str([e.details for e in await db.scalars(select(AuditEvent))])


def vf_default() -> dict[str, int]:
    return {"cores": 4, "memory_mb": 8192, "disk_gb": 64}


async def test_53_a_claim_taken_at_the_commit_leaves_nothing_written(world, monkeypatch):
    w = world
    async with get_sessionmaker()() as db:
        plan = await environments.validate_create(db, body(w, {"blue": vm(w.pve, "10.0.0.120")}, data_mode="slot",
                                                           traffic={"switch": "none", "dns": None}),
                                                  w.ctx(), read_file=reader())
    # Another create takes 10.0.0.120 meanwhile; this one's registry read doesn't see it any more (the race).
    async with get_sessionmaker()() as db:
        rival = Host(name="rival", hostname="10.9.9.9", username="root", metrics={})
        db.add(rival)
        await db.flush()
        db.add(AddressClaim(address="10.0.0.120", host_id=rival.id))
        await db.commit()
    real = machines.addresses_in_use

    async def blind(db, **kw):
        found = await real(db, **kw)
        found.pop("10.0.0.120", None)
        return found

    monkeypatch.setattr(machines, "addresses_in_use", blind)
    before = await counts()
    async with get_sessionmaker()() as db:
        with pytest.raises(CreateRefused) as err:
            await environments.create(db, plan, w.ctx())
    assert (err.value.status, err.value.detail, err.value.field) == (
        409, "10.0.0.120 was just taken by another environment: pick another address", "hosts.blue.machine.address")
    assert await counts() == before
    async with get_sessionmaker()() as db:
        assert await db.scalar(select(Environment.id).where(Environment.name == "prod")) is None


# ------------------------------------------------------------------------------------------ test 54


async def test_54_add_a_slot_on_a_new_vm_of_the_same_account_and_network(world):
    w = world
    env_id = await create(w, body(w, {"blue": vm(w.pve), "data": vm(w.pve)}))
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        other = await vf.proxmox_account(name="lab9")
        with pytest.raises(CreateRefused) as err:
            await environments.add_slot_plan(db, env, {"machine": vm(other)["machine"]}, w.ctx(), read_file=reader())
        assert (err.value.status, err.value.detail) == (409, "prod's VMs share one account and one network")
        with pytest.raises(CreateRefused) as err:
            await environments.add_slot_plan(db, env, {"machine": vm(w.pve)["machine"], "host_id": uuid.uuid4()},
                                             w.ctx(), read_file=reader())
        assert (err.value.status, err.value.field) == (422, "host_id")
        uat = await vf.vm_env(w.pve, name="uat", addresses={"blue": "10.0.0.140"})
        with pytest.raises(CreateRefused) as err:
            await environments.add_slot_plan(db, env, {"host_id": uat.hosts["blue"]}, w.ctx(), read_file=reader())
        assert (err.value.status, err.value.detail) == (
            409, "slipway-uat-blue is a VM of environment uat; only its slots run there")
        own = (await environments.members(db, env))["data"].host_id
        with pytest.raises(CreateRefused) as err:
            await environments.add_slot_plan(db, env, {"host_id": own}, w.ctx(), read_file=reader())
        assert err.value.detail == "slipway-prod-data is a VM of environment prod; only its slots run there"
        with pytest.raises(CreateRefused) as err:
            await environments.add_slot_plan(db, env, {"machine": vm(w.pve)["machine"]}, w.ctx("environments:write"),
                                             read_file=reader())
        assert err.value.status == 403
        plan = await environments.add_slot_plan(db, env, {"machine": vm(w.pve)["machine"]}, w.ctx(),
                                                read_file=reader())
        assert plan.to_json()["machine"]["address"] == "10.0.0.102" and plan.to_json()["planned"] == "proxmox"
        inst = await environments.add_slot(db, plan, w.ctx())
        await db.commit()
        green = await db.scalar(select(Machine).where(Machine.environment_id == env_id, Machine.slot == "green"))
        assert inst.slot == "green" and inst.host_id == green.host_id and green.network["address"] == "10.0.0.102"
        claim = await db.get(AddressClaim, "10.0.0.102")
        assert claim is not None and claim.host_id == green.host_id
        event = await db.scalar(select(AuditEvent).where(AuditEvent.action == "environment.slot_add"))
        assert event.details["machine"]["address"] == "10.0.0.102"


# -------------------------------------------------------------------------------- tests 44 and 45 (create)


async def test_44_blue_green_on_three_new_proxmox_vms_plans_the_data_servers_clients(world):
    w = world
    env_id = await create(w, body(w, {"blue": vm(w.pve), "green": vm(w.pve), "data": vm(w.pve)}))
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        mem = await environments.members(db, env)
        # The data server's {server.clients} names the app VMs' planned addresses from the start (D4).
        clients = [mem[s].host.client_address for s in ("blue", "green")]
        assert clients == ["10.0.0.100", "10.0.0.101"] and mem["data"].host.upstream_address == "10.0.0.102"
        rendered = manifest.plan(
            MAN, template=ENV_EXAMPLE, builtins=environments._placeholder_builtins("prod", "data", mem["data"].host),
            settings=env.app_settings, chosen=None, host_ports={}, secrets=env.app_secrets, env={}, role="server",
            server_values={"host": mem["data"].host.upstream_address, "clients": clients})
        assert rendered.env["DB_ALLOW"] == "10.0.0.100,10.0.0.101"
        # The first deploy is the data server's, which makes the data VM first (P3's order).
        acts = await environments.actions(db, env, w.ctx())
        assert acts["deploy"]["slot"] == "data" and acts["resize"]["data"]["available"]
        assert set(acts["forget"]) == {"blue", "green"}
        assert acts["forget"]["blue"]["reason"] == "slipway-prod-blue isn't made yet: deploy to blue to finish it"
        # Switchyard's upstreams are the VMs' addresses.
        assert [mem[s].host.upstream_address for s in ("blue", "green")] == clients
        # No audit row carries a token, password, key or identity value.
        text = str([(e.action, e.details) for e in await db.scalars(select(AuditEvent))])
        machines_rows = list(await db.scalars(select(Machine).where(Machine.environment_id == env_id)))
        hosts_rows = [m.host for m in mem.values()]
    for secret in (fp.TOKEN, fp.TOKEN.split("=", 1)[1], ADMIN["password"], *env.app_secrets.values(),
                   *(h.private_key for h in hosts_rows),
                   *(m.host_key_private for m in machines_rows if m.host_key_private)):
        assert secret not in text


async def test_45_mixed_blue_on_an_ssh_host_green_and_the_data_server_on_new_esxi_vms(world):
    w = world
    esx = await vf.esxi_account()
    async with get_sessionmaker()() as db:
        ssh_host = Host(name="h-blue", hostname="10.0.0.11", username="deploy", host_key="ssh-ed25519 AAAA",
                        metrics={})
        db.add(ssh_host)
        await db.commit()
    env_id = await create(w, body(w, {"blue": ssh_host.id, "green": vm(esx), "data": vm(esx)}))
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        mem = await environments.members(db, env)
        assert mem["blue"].host_id == ssh_host.id and mem["blue"].host.owner_environment_id is None
        rows = {m.slot: m for m in await db.scalars(select(Machine).where(Machine.environment_id == env_id))}
        assert set(rows) == {"green", "data"} and {m.provider for m in rows.values()} == {"esxi"}
        assert all(m.host_key_private and m.host_key_public for m in rows.values())  # ESXi keys at plan time
        assert mem["green"].host.provider == "esxi" and mem["green"].host.hostname == rows["green"].network["address"]
        # Blue's host is untouched; a Remove slot of green lists the VM step, of blue doesn't.
        host = await db.get(Host, ssh_host.id)
        assert host.provider == "ssh" and host.host_key == "ssh-ed25519 AAAA"
        steps = environments.env_steps_for(env, "remove_slot", {"slot": "green"}, mem)
        assert [s["key"] for s in steps] == ["check", "slot", "machine"]
        steps = environments.env_steps_for(env, "remove_slot", {"slot": "blue"}, mem)
        assert [s["key"] for s in steps] == ["check", "slot"]
        # The environment never held data, so Delete needs no snapshot.
        plan = await environments.delete_problem(db, env, {"confirm": "prod"}, w.ctx(), read_vms=False)
        assert plan.note == "prod never held data, so there is nothing to snapshot" and not plan.snapshot
    # Once it holds data on the data VM: a snapshot, or drop_data with data:reset (D19, Decision 26).
    await set_row(Instance, mem["blue"].id, current_commit_sha="0" * 40)
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        with pytest.raises(CreateRefused) as err:
            await environments.delete_problem(db, env, {"confirm": "prod"}, w.ctx(), read_vms=False)
        assert (err.value.status, err.value.detail, err.value.field) == (
            409, "prod's data is on slipway-prod-data, which Delete destroys: take a snapshot first, or confirm that "
                 "the data goes with it", "drop_data")
        await db.rollback()
        env = await db.get(Environment, env_id)
        with pytest.raises(CreateRefused) as err:
            await environments.delete_problem(db, env, {"confirm": "prod", "drop_data": True},
                                              w.ctx("environments:delete"), read_vms=False)
        assert err.value.status == 403
        await db.rollback()
        env = await db.get(Environment, env_id)
        plan = await environments.delete_problem(db, env, {"confirm": "prod", "drop_data": True}, w.ctx(),
                                                 read_vms=False)
        assert plan.without_snapshot and plan.options["drop_data"] is True


async def test_resize_plan_stores_the_size_and_refuses_shrinks_and_the_ready_data_server(world):
    w = world
    env_id = await create(w, body(w, {"blue": vm(w.pve), "data": vm(w.pve)}))
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        machine = await environments.resize_plan(db, env, "blue", {"cores": 8, "keep_vm_snapshots": 5}, w.ctx())
        await db.commit()
        assert machine.size == {"cores": 8, "memory_mb": 8192, "disk_gb": 64} and machine.keep_vm_snapshots == 5
        event = await db.scalar(select(AuditEvent).where(AuditEvent.action == "environment.update"))
        assert event.details["changed"]["machine.blue"] == "4 vCPU, 8 GB, 64 GB → 8 vCPU, 8 GB, 64 GB" \
            or "machine.blue" in event.details["changed"]
        await db.execute(update(Machine).where(Machine.id == machine.id)
                         .values(stage="ready", applied={"cores": 4, "memory_mb": 8192, "disk_gb": 64},
                                 ready_at=func.now()))
        await db.commit()
        env = await db.get(Environment, env_id)
        with pytest.raises(CreateRefused) as err:
            await environments.resize_plan(db, env, "blue", {"disk_gb": 32}, w.ctx())
        assert (err.value.status, err.value.detail) == (422, "Disks only grow: slipway-prod-blue has 64 GB")
        with pytest.raises(CreateRefused) as err:
            await environments.resize_plan(db, env, "blue", {"cores": 999}, w.ctx())
        assert err.value.status == 422
        with pytest.raises(CreateRefused) as err:
            await environments.resize_plan(db, env, "blue", {"cores": 2}, w.ctx("environments:write"))
        assert err.value.status == 403
        data_vm = await db.scalar(select(Machine).where(Machine.environment_id == env_id, Machine.slot == "data"))
        await db.execute(update(Machine).where(Machine.id == data_vm.id).values(stage="ready", ready_at=func.now()))
        await db.commit()
        env = await db.get(Environment, env_id)
        with pytest.raises(CreateRefused) as err:
            await environments.resize_plan(db, env, "data", {"cores": 8}, w.ctx())
        assert err.value.status == 409 and err.value.detail.startswith("The data server's VM keeps its size")
        # Blue's VM is ready and behind its stored size: its resize is pending until its next deploy.
        mem = await environments.members(db, env)
        assert await environments.pending_resizes(db, env, mem) == {"blue": "Resize pending: applies at blue's next "
                                                                            "deploy"}


# ------------------------------------------------------------------- test 44: the chain, run for real


async def test_44_the_first_chain_makes_the_data_vm_then_blues_vm_then_activates(tmp_path, monkeypatch):
    """P3-30's chain on three new Proxmox VMs: FakeProxmox, tests/bin/fake-terraform and the VM fake hosts make
    each VM in its own deploy; the data server's .env names the planned app addresses as its clients; the chained
    activate makes blue live through FakeSwitchyard, whose upstreams are the VMs' addresses."""
    from slipway.models import Deployment, User
    from slipway.services import deployer, env_jobs, jobs, traffic
    from tests import fake_switchyard
    from tests.test_env_jobs import Sites
    from tests.test_provider_pipeline import VmGitHub
    from tests.test_provider_proxmox import World as PveWorld

    net = vf.quiet_network(monkeypatch)
    pve_world = PveWorld(tmp_path, monkeypatch, net)
    monkeypatch.setattr(traffic, "sleep", vf.no_sleep)
    sites = Sites()
    monkeypatch.setattr(traffic, "transport_factory", sites.factory)
    sy = fake_switchyard.install(monkeypatch)
    await fake_switchyard.configure(traffic_address="10.0.0.2")
    queued: list[uuid.UUID] = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, keys: queued.append(dep_id))
    user = await make_user(f"admin-{uuid.uuid4().hex[:6]}@example.com", roles=["admin"])
    account = await vf.proxmox_account()
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=42, full_name="acme/web", owner="acme", name="web",
                          html_url="https://github.com/acme/web", detected_config={})
        db.add(repo)
        await db.commit()
    w = World(repo_id=repo.id, user=user, pve=account, net=net)
    env_id = await create(w, body(w, {"blue": vm(account), "green": vm(account), "data": vm(account)},
                                  name="uat", settings={"APP_DOMAIN": "uat.example.com"}))
    addresses = {"blue": "10.0.0.100", "green": "10.0.0.101", "data": "10.0.0.102"}
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        mem = await environments.members(db, env)
        ids = {slot: inst.id for slot, inst in mem.items()}
        for slot, address in addresses.items():
            assert mem[slot].host.hostname == address
            pve_world.vms.add_vm(slot, address)
            await db.execute(update(Host).where(Host.id == mem[slot].host_id)
                             .values(deploy_root=str(pve_world.vms[slot].tmp / "root")))
        await db.commit()

    async def run(dep_id: uuid.UUID, slot: str) -> Deployment:
        pve_world.knobs(host_key=pve_world.vms.pinned_key(addresses[slot]))
        await deployer.run_deployment(dep_id, connect=pve_world.vms.connect, github=VmGitHub)
        async with get_sessionmaker()() as db:
            return await db.get(Deployment, dep_id)

    # The data server's deploy makes the data VM first.
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        data_inst = await db.get(Instance, ids["data"])
        first = await jobs.queue_job(db, instance=data_inst, environment=env, user=await db.get(User, user.id),
                                     options={"chain": True})
        await db.commit()
    dep = await run(first.id, "data")
    assert dep.status == "succeeded", (dep.error, dep.log[-3000:])
    assert [s["key"] for s in dep.steps][:3] == ["resolve", "prepare", "source"]
    env_file = (pve_world.vms["data"].folder("uat-data") / "shared" / ".env").read_text()
    assert "DB_ALLOW=10.0.0.100,10.0.0.101" in env_file.splitlines()
    async with get_sessionmaker()() as db:
        stages = {m.slot: m.stage for m in await db.scalars(select(Machine).where(Machine.environment_id == env_id))}
    assert stages == {"data": "ready", "blue": "planned", "green": "planned"}
    # The chain queued blue's deploy, which makes blue's VM and goes live.
    blue_id = queued.pop(0)
    dep = await run(blue_id, "blue")
    assert dep.status == "succeeded", (dep.error, dep.log[-3000:])
    env_file = (pve_world.vms["blue"].folder("uat-blue") / "shared" / ".env").read_text()
    assert "DB_HOST=10.0.0.102" in env_file.splitlines()
    # Then the chained activate makes the environment live.
    activate_id = queued.pop(0)
    async with get_sessionmaker()() as db:
        activate = await db.get(Deployment, activate_id)
        assert activate.kind == "activate" and activate.options["slot"] == "blue"
    await env_jobs.run(activate_id, connect=pve_world.vms.connect)
    async with get_sessionmaker()() as db:
        activate = await db.get(Deployment, activate_id)
        assert activate.status == "succeeded", (activate.error, activate.log[-3000:])
        env = await db.get(Environment, env_id)
        assert env.status == "live" and env.active_slot_id == ids["blue"]
        stages = {m.slot: m.stage for m in await db.scalars(select(Machine).where(Machine.environment_id == env_id))}
        assert stages == {"data": "ready", "blue": "ready", "green": "planned"}
        upstreams = {h["domains"][0]: [u["host"] for u in h["upstreams"]] for h in sy.hosts.values()}
        assert upstreams["www.uat.example.com"] == ["10.0.0.100"]
        assert upstreams["files.uat.example.com"] == ["10.0.0.102"]
        text = str([(e.action, e.details) for e in await db.scalars(select(AuditEvent))])
        keys = [m.host_key_private for m in await db.scalars(select(Machine)) if m.host_key_private]
        private = [h.private_key for h in await db.scalars(select(Host)) if h.private_key]
    for secret in (fp.TOKEN, fp.TOKEN.split("=", 1)[1], ADMIN["password"], *env.app_secrets.values(), *keys,
                   *private):
        assert secret not in text


# ------------------------------------------------------------------- test 45: the mixed chain, run for real


async def test_45_blue_on_an_ssh_host_green_and_the_data_server_on_new_esxi_vms(tmp_path, monkeypatch):
    """Blue on a host added by hand, green and the data server on new ESXi VMs (FakeEsxi and the VM fake hosts):
    the data server's deploy makes its VM, blue goes live on its own host, green's deploy makes green's VM, and
    the activate of green changes nothing about blue's host."""
    from slipway.models import Deployment, User
    from slipway.services import deployer, env_jobs, jobs, traffic
    from tests import fake_switchyard
    from tests.test_env_jobs import Sites
    from tests.test_provider_esxi import World as EsxiWorld
    from tests.test_provider_pipeline import VmGitHub

    net = vf.quiet_network(monkeypatch)
    esx_world = EsxiWorld(tmp_path, monkeypatch, net)
    monkeypatch.setattr(traffic, "sleep", vf.no_sleep)
    sites = Sites()
    monkeypatch.setattr(traffic, "transport_factory", sites.factory)
    sy = fake_switchyard.install(monkeypatch)
    await fake_switchyard.configure(traffic_address="10.0.0.2")
    queued: list[uuid.UUID] = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, keys: queued.append(dep_id))
    user = await make_user(f"admin-{uuid.uuid4().hex[:6]}@example.com", roles=["admin"])
    account = await vf.esxi_account()
    blue_fake = esx_world.vms.add_vm("blue", "10.0.0.11", docker=True)
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=42, full_name="acme/web", owner="acme", name="web",
                          html_url="https://github.com/acme/web", detected_config={})
        db.add(repo)
        blue_host = Host(name="h-blue", hostname="10.0.0.11", username="deploy", metrics={},
                         host_key=esx_world.vms.pinned_key("10.0.0.11"), deploy_root=str(blue_fake.root))
        db.add(blue_host)
        await db.commit()
    blue_before = {c: getattr(blue_host, c) for c in ("hostname", "host_key", "deploy_root", "owner_environment_id")}
    w = World(repo_id=repo.id, user=user, pve=account, net=net)
    env_id = await create(w, body(w, {"blue": blue_host.id, "green": vm(account), "data": vm(account)},
                                  name="uat", settings={"APP_DOMAIN": "uat.example.com"}))
    addresses = {"green": "10.0.0.100", "data": "10.0.0.101"}
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        mem = await environments.members(db, env)
        ids = {slot: inst.id for slot, inst in mem.items()}
        for slot, address in addresses.items():
            assert mem[slot].host.hostname == address and mem[slot].host.provider == "esxi"
            esx_world.fake.addresses[f"slipway-uat-{slot}"] = address
            await db.execute(update(Host).where(Host.id == mem[slot].host_id)
                             .values(deploy_root=str(tmp_path / "vms" / f"host-{slot}" / "root")))
        await db.commit()

    async def run(dep_id: uuid.UUID) -> Deployment:
        await deployer.run_deployment(dep_id, connect=esx_world.vms.connect, github=VmGitHub)
        async with get_sessionmaker()() as db:
            return await db.get(Deployment, dep_id)

    async def activate(dep_id: uuid.UUID) -> Deployment:
        await env_jobs.run(dep_id, connect=esx_world.vms.connect)
        async with get_sessionmaker()() as db:
            return await db.get(Deployment, dep_id)

    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        first = await jobs.queue_job(db, instance=await db.get(Instance, ids["data"]), environment=env,
                                     user=await db.get(User, user.id), options={"chain": True})
        await db.commit()
    dep = await run(first.id)
    assert dep.status == "succeeded", (dep.error, dep.log[-3000:])
    env_file = (esx_world.vms["data"].folder("uat-data") / "shared" / ".env").read_text()
    assert "DB_ALLOW=10.0.0.100,10.0.0.11" in env_file.splitlines()
    dep = await run(queued.pop(0))  # blue's deploy, on its own host: no prepare
    assert dep.status == "succeeded", (dep.error, dep.log[-3000:])
    assert "prepare" not in [s["key"] for s in dep.steps]
    dep = await activate(queued.pop(0))
    assert dep.status == "succeeded", (dep.error, dep.log[-3000:])
    # Green's deploy makes its VM; then green is activated.
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        green = await jobs.queue_job(db, instance=await db.get(Instance, ids["green"]), environment=env,
                                     user=await db.get(User, user.id))
        await db.commit()
    dep = await run(green.id)
    assert dep.status == "succeeded", (dep.error, dep.log[-3000:])
    assert [s["key"] for s in dep.steps][:2] == ["resolve", "prepare"]
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        switch = await jobs.queue_job(db, environment=env, user=await db.get(User, user.id), kind="activate",
                                      options={"slot": "green"})
        await db.commit()
    dep = await activate(switch.id)
    assert dep.status == "succeeded", (dep.error, dep.log[-3000:])
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        assert env.active_slot_id == ids["green"]
        stages = {m.slot: m.stage for m in await db.scalars(select(Machine).where(Machine.environment_id == env_id))}
        assert stages == {"green": "ready", "data": "ready"}
        host = await db.get(Host, blue_host.id)
        assert {c: getattr(host, c) for c in blue_before} == blue_before and host.provider == "ssh"
        upstreams = {h["domains"][0]: [u["host"] for u in h["upstreams"]] for h in sy.hosts.values()}
        assert upstreams["www.uat.example.com"] == ["10.0.0.100"]
