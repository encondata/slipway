"""Provider accounts, the DigitalOcean columns and the machines tables, at the model level (phase 4 tests 21
and 24, phase 5 test 2): every CHECK, unique key, partial index and RESTRICT, the defaults, and
``Host.is_built``. The schema here is ``Base.metadata.create_all`` (tests/conftest.py); the migrations'
own tests are test_migration_0010.py to 0012.py.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError

import slipway.models as models
from slipway.db.base import Base
from slipway.db.session import get_sessionmaker
from slipway.models import (
    AddressClaim,
    Backup,
    BackupLocation,
    DeploymentKind,
    Environment,
    Host,
    Instance,
    Machine,
    MachineSnapshot,
    MachineStage,
    ProviderAccount,
    ProviderKind,
    Repository,
    SnapshotMode,
    SnapshotReason,
    TerraformState,
)

NOW = datetime(2026, 11, 18, 9, 0, tzinfo=UTC)


async def _adds(*rows) -> None:
    async with get_sessionmaker()() as db:
        db.add_all(rows)
        await db.commit()


async def _fails(*rows) -> None:
    async with get_sessionmaker()() as db:
        db.add_all(rows)
        with pytest.raises(IntegrityError):
            await db.commit()


async def _base() -> dict[str, uuid.UUID]:
    """A repository, an SSH host, a DigitalOcean account and a Proxmox account."""
    repo = Repository(github_id=1, full_name="acme/web", owner="acme", name="web", html_url="https://github.com/acme/web")
    host = Host(name="h", hostname="10.0.0.11", username="deploy")
    do = ProviderAccount(provider=ProviderKind.DIGITALOCEAN, name="DO main", secret="dop_v1_token")
    pve = ProviderAccount(provider=ProviderKind.PROXMOX, name="Lab", secret="slipway@pve!slipway=uuid")
    await _adds(repo, host, do, pve)
    return {"repo": repo.id, "host": host.id, "do": do.id, "pve": pve.id}


def _env(ids: dict[str, uuid.UUID], name: str, **kw) -> Environment:
    return Environment(name=name, repository_id=ids["repo"], branch="main", **{"data_mode": "server", **kw})


def _do_env(ids: dict[str, uuid.UUID], name: str, **kw) -> Environment:
    return _env(ids, name, provider="digitalocean", provider_account_id=ids["do"], data_mode="managed", **kw)


# ------------------------------------------------------------------ provider accounts


async def test_provider_account_defaults_and_constraints():
    ids = await _base()
    async with get_sessionmaker()() as db:
        account = await db.get(ProviderAccount, ids["pve"])
        assert (account.status, account.checks, account.facts, account.config, account.secret_hint) == (
            "unknown", [], {}, {}, "")
        assert (account.production, account.tls, account.removed_at, account.last_checked_at) == (
            False, None, None, None)
        assert account.has_secret and not account.is_removed
        assert account.secret == "slipway@pve!slipway=uuid"
    assert [k.value for k in ProviderKind] == ["digitalocean", "proxmox", "esxi"]
    assert not ProviderKind.DIGITALOCEAN.is_hypervisor and ProviderKind.ESXI.is_hypervisor

    # The provider CHECK, production only on DigitalOcean, and one name across every provider.
    await _fails(ProviderAccount(provider="aws", name="Other"))
    await _fails(ProviderAccount(provider=ProviderKind.PROXMOX, name="Prod lab", production=True))
    await _fails(ProviderAccount(provider=ProviderKind.ESXI, name="Lab"))
    await _adds(ProviderAccount(provider=ProviderKind.DIGITALOCEAN, name="DO prod", production=True),
                ProviderAccount(provider=ProviderKind.ESXI, name="esx-01", secret=None))


async def test_no_model_is_called_machine_provider():
    """ProviderKind is the enum; MachineProvider is only the services' protocol (phase 5 test 1)."""
    assert not hasattr(models, "MachineProvider")
    assert "MachineProvider" not in {m.class_.__name__ for m in Base.registry.mappers}
    assert {"provider_accounts", "machines", "machine_snapshots", "terraform_states", "address_claims"} <= set(
        Base.metadata.tables)


# ------------------------------------------------------------------ environments (phase 4 test 21)


async def test_environment_provider_and_production_checks():
    ids = await _base()
    await _adds(_env(ids, "plain"))
    async with get_sessionmaker()() as db:
        env = (await db.execute(Environment.__table__.select().where(Environment.name == "plain"))).one()
    assert (env.provider, env.provider_account_id, env.provider_team, env.cloud, env.production, env.retiring_at) == (
        "ssh", None, None, {}, False, None)

    # ck_environments_provider_account: a DigitalOcean environment names its account, and only it does.
    await _fails(_env(ids, "a1", provider="digitalocean", data_mode="managed"))
    await _fails(_env(ids, "a2", provider_account_id=ids["do"]))
    # ck_environments_do_managed: DigitalOcean data is always managed.
    await _fails(_env(ids, "a3", provider="digitalocean", provider_account_id=ids["do"], data_mode="server"))
    await _adds(_do_env(ids, "cloud"))
    # ck_environments_production_do, ck_environments_retiring, ck_environments_production_auto.
    await _fails(_env(ids, "a4", production=True))
    await _fails(_do_env(ids, "a5", retiring_at=NOW))
    await _fails(_do_env(ids, "a6", production=True, auto_activate=True))
    # A VM environment is placement ssh with no account of its own (its accounts are on its machines).
    await _adds(_env(ids, "vms", data_mode="slot"))


async def test_one_production_environment_per_app():
    ids = await _base()
    await _adds(_do_env(ids, "prod", production=True))
    # A second production environment of the same repository and manifest is refused...
    await _fails(_do_env(ids, "prod2", production=True))
    # ...but another manifest of the same repository is another app, and a non-production one is fine.
    await _adds(_do_env(ids, "prod-api", production=True, manifest_file="api/slipway.yml"),
                _do_env(ids, "uat"))
    # A retiring production environment doesn't block its successor.
    async with get_sessionmaker()() as db:
        old = (await db.execute(Environment.__table__.select().where(Environment.name == "prod"))).one()
        env = await db.get(Environment, old.id)
        env.retiring_at = NOW
        await db.commit()
    await _adds(_do_env(ids, "prod2", production=True))
    # Nor does a deleted one.
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, (await db.execute(
            Environment.__table__.select().where(Environment.name == "prod2"))).one().id)
        env.status, env.deleted_at = "deleted", NOW
        await db.commit()
    await _adds(_do_env(ids, "prod3", production=True))
    await _fails(_do_env(ids, "prod4", production=True))


# ------------------------------------------------------------------ instances and backups (phase 4 test 21)


async def test_only_a_managed_data_owner_has_no_host():
    ids = await _base()
    env, managed = _env(ids, "uat"), _do_env(ids, "cloud")
    await _adds(env, managed)

    def inst(slug: str, **kw) -> Instance:
        return Instance(name=slug, slug=slug, repository_id=ids["repo"], branch="main", **kw)

    await _fails(inst("alone"))  # a standalone instance always has a host
    await _fails(inst("cloud-blue", environment_id=managed.id, slot="blue"))  # so does an app slot
    owner = inst("cloud-data", environment_id=managed.id, slot="data")
    await _adds(owner, inst("uat-blue", environment_id=env.id, slot="blue", host_id=ids["host"]))
    async with get_sessionmaker()() as db:
        loaded = await db.get(Instance, owner.id)
        assert loaded.host_id is None and loaded.host is None


async def test_backups_on_slipway_need_their_key_when_ready():
    ids = await _base()
    inst = Instance(name="web", slug="web", repository_id=ids["repo"], host_id=ids["host"], branch="main")
    await _adds(inst)

    def backup(name: str, **kw) -> Backup:
        return Backup(instance_id=inst.id, name=name, reason="manual", format="pg_dump", identity_fp="x",
                      taken_at=NOW, **kw)

    host_backup = backup("b1", status="ready", db_bytes=10)
    await _adds(host_backup)
    async with get_sessionmaker()() as db:
        loaded = await db.get(Backup, host_backup.id)
        assert (loaded.location, loaded.data_key, loaded.stored_bytes) == (BackupLocation.HOST, None, None)
    # ck_backups_slipway_key: a ready backup on the Slipway server has its key; a pending one may not yet.
    await _fails(backup("b2", status="ready", db_bytes=10, location="slipway"))
    await _adds(backup("b3", status="pending", location="slipway"),
                backup("b4", status="ready", db_bytes=10, location="slipway", data_key="a2V5", stored_bytes=99))
    async with get_sessionmaker()() as db:
        raw = await db.scalar(text("SELECT data_key FROM backups WHERE name = 'b4'"))
        assert raw and "a2V5" not in raw  # stored encrypted
        assert (await db.scalar(select(Backup).where(Backup.name == "b4"))).data_key == "a2V5"


def test_new_job_kinds_fit_the_kind_column():
    new = [DeploymentKind.CERTIFICATE, DeploymentKind.DEACTIVATE, DeploymentKind.VM_SNAPSHOT,
           DeploymentKind.VM_REVERT, DeploymentKind.VM_DROP]
    assert [k.value for k in new] == ["certificate", "deactivate", "vm_snapshot", "vm_revert", "vm_drop"]
    assert all(len(k.value) <= 16 for k in DeploymentKind)


# ------------------------------------------------------------------ hosts (phase 4 test 24)


def test_host_is_built():
    def host(provider: str, state: dict | None) -> Host:
        return Host(name="x", hostname="x.invalid", username="slipway", provider=provider, provider_state=state)

    assert host("ssh", {}).is_built and host("ssh", None).is_built
    assert host("ssh", {"phase": "planned"}).is_built  # a host added by hand is always built
    for provider in ("digitalocean", "proxmox", "esxi"):
        assert [phase for phase in ("planned", "creating", "ready", "gone") if host(provider, {"phase": phase}).is_built
                ] == ["ready"], provider
        assert not host(provider, {}).is_built and not host(provider, None).is_built


async def test_host_provider_state_defaults_to_empty():
    ids = await _base()
    async with get_sessionmaker()() as db:
        host = await db.get(Host, ids["host"])
        assert host.provider_state == {} and host.is_built


# ------------------------------------------------------------------ machines (phase 5 test 2)


def _vm_host(name: str, address: str) -> Host:
    return Host(name=name, hostname=address, username="slipway", provider="proxmox", provider_state={"phase": "planned"})


def _machine(env: Environment, host: Host, account_id: uuid.UUID, slot: str, **kw) -> Machine:
    values = {"provider": "proxmox", "name": f"slipway-{env.name}-{slot}", "spec": {"node": "pve1"},
              "network": {"name": "lan", "address": host.hostname}, "size": {"cores": 2, "memory_mb": 2048,
                                                                            "disk_gb": 20}, **kw}
    return Machine(environment_id=env.id, host_id=host.id, account_id=account_id, slot=slot, **values)


async def _vm_base() -> tuple[dict[str, uuid.UUID], Environment, Host, Host]:
    ids = await _base()
    env = _env(ids, "lab", data_mode="slot")
    blue, green = _vm_host("slipway-lab-blue", "192.168.1.50"), _vm_host("slipway-lab-green", "192.168.1.51")
    await _adds(env, blue, green)
    return ids, env, blue, green


async def test_machine_defaults_and_relationships():
    ids, env, blue, _ = await _vm_base()
    machine = _machine(env, blue, ids["pve"], "blue")
    await _adds(machine)
    async with get_sessionmaker()() as db:
        loaded = await db.get(Machine, machine.id)
        assert (loaded.stage, loaded.ids, loaded.keep_vm_snapshots, loaded.applied, loaded.snapshot_mode) == (
            MachineStage.PLANNED, {}, 3, None, None)
        assert loaded.host.name == "slipway-lab-blue" and loaded.account.name == "Lab"
        assert not loaded.is_ready
    assert [s.value for s in MachineStage] == ["planned", "creating", "booting", "ready", "destroying"]
    assert [m.value for m in SnapshotMode] == ["any", "newest_only", "none"]
    assert [r.value for r in SnapshotReason] == ["manual", "pre_resize", "pre_revert"]


async def test_machine_constraints():
    ids, env, blue, green = await _vm_base()
    other = _env(ids, "lab2", data_mode="slot")
    third = _vm_host("slipway-lab2-blue", "192.168.1.52")
    await _adds(other, third, _machine(env, blue, ids["pve"], "blue"))

    # Two machines on one host; one slot of an environment twice; one VM name twice in an account.
    await _fails(_machine(other, blue, ids["pve"], "blue"))
    await _fails(_machine(env, green, ids["pve"], "blue", name="slipway-lab-blue-2"))
    await _fails(_machine(other, third, ids["pve"], "blue", name="slipway-lab-blue"))
    # The same name in another account is another VM.
    esx = ProviderAccount(provider=ProviderKind.ESXI, name="esx")
    await _adds(esx)
    await _adds(_machine(other, third, esx.id, "blue", provider="esxi", name="slipway-lab-blue"))

    # The provider, stage, ready_at and snapshot_mode CHECKs.
    for bad in ({"provider": "digitalocean"}, {"stage": "booted"}, {"stage": "ready"},
                {"snapshot_mode": "some"}):
        await _fails(_machine(env, green, ids["pve"], "green", **bad))
    await _adds(_machine(env, green, ids["pve"], "green", stage="ready", ready_at=NOW, snapshot_mode="newest_only"))


async def test_address_claims():
    ids, env, blue, green = await _vm_base()
    await _adds(AddressClaim(address="192.168.1.50", host_id=blue.id))
    # The address is the key: a second claim of it fails, whoever makes it.
    await _fails(AddressClaim(address="192.168.1.50", host_id=green.id))
    # A host holds one claim.
    await _fails(AddressClaim(address="192.168.1.60", host_id=blue.id))
    await _adds(AddressClaim(address="192.168.1.51", host_id=green.id))
    async with get_sessionmaker()() as db:
        claim = await db.get(AddressClaim, "192.168.1.51")
        assert claim.created_at is not None
        # A claim goes with its host.
        await db.execute(delete(Host).where(Host.id == green.id))
        await db.commit()
    async with get_sessionmaker()() as db:
        assert await db.get(AddressClaim, "192.168.1.51") is None


async def test_restrict_keeps_states_accounts_and_hosts_of_machines():
    ids, env, blue, _ = await _vm_base()
    machine = _machine(env, blue, ids["pve"], "blue")
    await _adds(machine)
    await _adds(TerraformState(machine_id=machine.id, state='{"version": 4}'))
    async with get_sessionmaker()() as db:
        state = await db.get(TerraformState, machine.id)
        assert (state.serial, state.lineage, state.lock_id, state.state) == (0, None, None, '{"version": 4}')

    async def refused(statement) -> None:
        async with get_sessionmaker()() as db:
            with pytest.raises(IntegrityError):
                await db.execute(statement)
                await db.commit()

    # RESTRICT: the machine row goes only after its state; an account or host goes only after its machines.
    await refused(delete(Machine).where(Machine.id == machine.id))
    await refused(delete(ProviderAccount).where(ProviderAccount.id == ids["pve"]))
    await refused(delete(Host).where(Host.id == blue.id))
    await refused(delete(Environment).where(Environment.id == env.id))
    async with get_sessionmaker()() as db:
        await db.execute(delete(TerraformState).where(TerraformState.machine_id == machine.id))
        await db.execute(delete(Machine).where(Machine.id == machine.id))
        await db.commit()
    # An environment's account is RESTRICT too, deleted environments included.
    cloud = _do_env(ids, "cloud", status="deleted", deleted_at=NOW)
    await _adds(cloud)
    await refused(delete(ProviderAccount).where(ProviderAccount.id == ids["do"]))


async def test_machine_snapshots():
    ids, env, blue, _ = await _vm_base()
    machine = _machine(env, blue, ids["pve"], "blue")
    await _adds(machine)

    def snap(name: str, **kw) -> MachineSnapshot:
        return MachineSnapshot(machine_id=machine.id, name=name, reason=SnapshotReason.MANUAL, identity_fp="fp",
                               sizes={"cores": 2}, taken_at=NOW, **kw)

    first = snap("slipway-20261118T090000Z", identity={"SS_JWT_SECRET": "jwt-1"})
    await _adds(first)
    await _fails(snap("slipway-20261118T090000Z"))
    async with get_sessionmaker()() as db:
        loaded = await db.get(MachineSnapshot, first.id)
        assert (loaded.status, loaded.backups, loaded.quiesced, loaded.identity) == (
            "pending", [], None, {"SS_JWT_SECRET": "jwt-1"})
        raw = await db.scalar(text("SELECT identity FROM machine_snapshots"))
        assert raw and "jwt-1" not in raw  # stored encrypted
        # CASCADE: a machine's snapshots go with it.
        await db.execute(delete(Machine).where(Machine.id == machine.id))
        await db.commit()
    async with get_sessionmaker()() as db:
        assert await db.get(MachineSnapshot, first.id) is None
