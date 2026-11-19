"""Provider steps in the deploy pipeline (S12): P5 tests 40, 41, 42, 43 (Proxmox), 49 (prepare and resize), 51
and 64; P4 tests 63 (the job half), 61 (the prepare-recovery half), 76 (the member-step timeout) and 83 (the
manifest-hash half).

The VM pipeline runs for real: FakeProxmox, ``tests/bin/fake-terraform`` and the VM fake hosts (the Proxmox
provider tests' ``World``), then phase 3's deploy on the VM's fake shell. A DigitalOcean slot's full deploy needs
the managed data owner (S14b), so its tests stub ``do_provision`` where a run would reach the data runner, and
call the real ``resize_droplet`` against FakeDigitalOcean for the step timeout.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import uuid
from typing import Any

import pytest
from sqlalchemy import select, update

from slipway.db.session import get_sessionmaker
from slipway.models import (
    AuditEvent,
    Deployment,
    Environment,
    Host,
    Instance,
    Machine,
    ProviderAccount,
    User,
)
from slipway.services import data, deployer, do_provision, environments, hosts, jobs, machines, ssh, traffic
from slipway.services.vmtypes import MachineError
from tests import do_fixtures as dof
from tests import vm_fixtures as vf
from tests.conftest import make_user
from tests.fake_hosts import ENV_EXAMPLE, ENV_SCRIPT, ENV_YML, EnvGitHub, MultiRemote, seed_env
from tests.test_deployer import FakeGitHub
from tests.test_provider_proxmox import BLUE, VM, World, blue_env

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")


# ------------------------------------------------------------------------------------------------ helpers


def keys(rows: list[dict[str, Any]]) -> list[str]:
    return [r["key"] for r in rows]


def names(rows: list[dict[str, Any]]) -> dict[str, str]:
    return {r["key"]: r["name"] for r in rows}


async def loaded(instance_id: uuid.UUID) -> tuple[Any, Instance, Environment, dict[str, Instance]]:
    """A session, the instance (its host loaded), its environment and the environment's members."""
    db = get_sessionmaker()()
    instance = await db.get(Instance, instance_id)
    env = await db.get(Environment, instance.environment_id)
    mem = await environments.members(db, env)
    return db, instance, env, mem


async def deploy_steps(instance_id: uuid.UUID) -> list[dict[str, Any]]:
    """The steps a deploy of the instance lists when it is queued now (queue_job's own computation)."""
    db, instance, env, mem = await loaded(instance_id)
    try:
        provider = await deployer.provider_steps(db, instance, env, mem)
        return deployer.steps_for(instance, environment=env, members=mem, provider=provider)
    finally:
        await db.close()


async def set_rows(model: Any, ident: uuid.UUID, **values: Any) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(update(model).where(model.id == ident).values(**values))
        await db.commit()


async def get(model: Any, ident: uuid.UUID) -> Any:
    async with get_sessionmaker()() as db:
        return await db.get(model, ident)


async def built_droplet(env: dof.DoEnv, slot: str, size: str = "s-1vcpu-1gb") -> None:
    """The slot's droplet host as prepare leaves it: built, pinned, at ``size``."""
    async with get_sessionmaker()() as db:
        host = await db.get(Host, env.host_ids[slot])
        _private, public = ssh.generate_keypair("root@droplet")
        host.host_key = public
        host.hostname = "203.0.113.10" if slot == "blue" else "203.0.113.11"
        hosts.set_phase(host, hosts.PHASE_READY, size=size, droplet_name=host.name)
        await db.commit()


async def machine_state(env: vf.VmEnv, slot: str = "blue", **fields: Any) -> None:
    async with get_sessionmaker()() as db:
        row = await db.get(Machine, env.machines[slot])
        host = await db.get(Host, row.host_id)
        for key, value in fields.items():
            setattr(row, key, value)
        if "stage" in fields:
            hosts.set_phase(host, machines.phase_for(fields["stage"]), stage=fields["stage"])
            if fields["stage"] == "ready":
                row.ready_at = row.ready_at or deployer.utcnow()
                if not host.host_key:
                    host.host_key = ssh.generate_keypair("root@vm")[1]
        await db.commit()


SIZE = {"cores": 2, "memory_mb": 4096, "disk_gb": 32}
BIGGER = {"cores": 4, "memory_mb": 8192, "disk_gb": 64}


@pytest.fixture(autouse=True)
def net(monkeypatch) -> vf.Network:
    """Names resolve as the VM fixtures say and nothing answers the TCP probe (the guard refuses real ones)."""
    return vf.quiet_network(monkeypatch)


async def vm_world_env(mode: str = "slot", slots: tuple[str, ...] = ("blue",), *, ready: bool = False,
                       size: dict | None = None, applied: dict | None = None, name: str = "uat") -> vf.VmEnv:
    """An environment of planned Proxmox VMs on account ``lab`` (no hypervisor behind them), optionally marked
    ready. A test that makes several names each one."""
    async with get_sessionmaker()() as db:
        account = await db.scalar(select(ProviderAccount).where(ProviderAccount.name == "lab"))
    account = account or await vf.proxmox_account()
    env = await vf.vm_env(account, name=name, mode=mode, slots=slots, size=size or SIZE)
    if ready:
        for slot in env.machines:
            await machine_state(env, slot, stage="ready", applied=dict(applied or size or SIZE))
    return env


# ------------------------------------------------------------------------- P5 test 40: steps_for


async def test_40_a_vm_slot_deploy_starts_with_resolve_then_prepare():
    env = await vm_world_env()
    rows = await deploy_steps(env.instances["blue"])
    assert keys(rows) == ["resolve", "prepare", "source", "upload", "manifest", "ports", "settings", "build",
                          "backup", "start", "finish", "smoke", "traffic"]
    assert names(rows)["prepare"] == f"Prepare the VM {VM} on lab"


async def test_40_resize_is_listed_after_backup_only_when_its_rule_holds():
    # A planned VM is made at its size: no resize.
    env = await vm_world_env(size=BIGGER)
    assert "resize" not in keys(await deploy_steps(env.instances["blue"]))
    # A ready VM whose stored size differs from the applied one.
    env = await vm_world_env(ready=True, size=BIGGER, applied=SIZE, name="qa")
    rows = await deploy_steps(env.instances["blue"])
    assert keys(rows)[keys(rows).index("backup") + 1] == "resize"
    assert keys(rows).index("resize") < keys(rows).index("start")
    assert names(rows)["resize"] == "Resize slipway-qa-blue to 4 vCPU, 8 GB, 64 GB"
    # The same size: nothing to resize.
    env = await vm_world_env(ready=True, size=SIZE, applied=SIZE, name="demo")
    assert "resize" not in keys(await deploy_steps(env.instances["blue"]))


async def test_40_mode_slot_resize_comes_before_the_snapshot_steps():
    env = await vm_world_env(ready=True, size=BIGGER, applied=SIZE)
    db, instance, row, mem = await loaded(env.instances["blue"])
    try:
        provider = await deployer.provider_steps(db, instance, row, mem)
        rows = deployer.steps_for(instance, snapshot=True, environment=row, members=mem, provider=provider)
    finally:
        await db.close()
    assert keys(rows)[keys(rows).index("backup"):keys(rows).index("start")] == [
        "backup", "resize", "stop", "restore", "files", "after_import"]


async def test_40_never_for_the_data_server_or_the_active_slot_of_two():
    env = await vm_world_env(mode="server", slots=("blue", "green"), ready=True, size=BIGGER, applied=SIZE)
    data_rows = await deploy_steps(env.instances["data"])
    assert keys(data_rows)[:3] == ["resolve", "prepare", "source"]
    assert "resize" not in keys(data_rows)
    assert "resize" in keys(await deploy_steps(env.instances["green"]))
    await set_rows(Environment, env.env_id, active_slot_id=env.instances["blue"])
    assert "resize" not in keys(await deploy_steps(env.instances["blue"]))  # the active one of two
    assert "resize" in keys(await deploy_steps(env.instances["green"]))  # the idle one


async def test_40_members_on_ssh_hosts_and_data_kinds_keep_phase_3s_lists(tmp_path):
    multi = MultiRemote(tmp_path)
    seeded = await seed_env(multi, mode="server", slots=("blue", "green"))
    for slot in ("data", "blue", "green"):
        db, instance, env, mem = await loaded(seeded.ids[slot])
        try:
            assert await deployer.provider_steps(db, instance, env, mem) is None
            assert deployer.steps_for(instance, environment=env, members=mem, provider=None) == \
                deployer.steps_for(instance, environment=env, members=mem)
        finally:
            await db.close()
    # A data kind on a VM's member lists no prepare (the not-built rule fences it instead).
    env = await vm_world_env(ready=True, name="qa")
    db, instance, row, mem = await loaded(env.instances["blue"])
    try:
        rows = deployer.steps_for(instance, data.DeploymentKind.BACKUP, environment=row, members=mem)
    finally:
        await db.close()
    assert "prepare" not in keys(rows) and "resize" not in keys(rows)


async def test_40_a_digitalocean_slot_lists_prepare_database_and_edge():
    env = await dof.make_do_env()
    rows = await deploy_steps(env.ids["blue"])
    assert keys(rows) == ["resolve", "prepare", "database", "edge", "source", "upload", "manifest", "ports",
                          "settings", "build", "backup", "start", "finish", "smoke", "traffic"]
    assert names(rows)["prepare"] == "Prepare DigitalOcean"
    assert names(rows)["database"] == "Set up the database"
    assert names(rows)["edge"] == "Set up the load balancer"
    assert names(rows)["traffic"] == "Update the load balancer"
    # A built droplet whose size is behind cloud.droplet_size gets the resize step after backup.
    await built_droplet(env, "blue", "s-1vcpu-1gb")
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        row.cloud = {**row.cloud, "droplet_size": "s-1vcpu-2gb"}
        await db.commit()
    rows = await deploy_steps(env.ids["blue"])
    assert keys(rows)[keys(rows).index("backup") + 1] == "resize"
    assert names(rows)["resize"] == "Resize slipway-shop-blue to s-1vcpu-2gb"
    # ... but not while blue is the active one of two.
    await set_rows(Environment, env.env_id, active_slot_id=env.ids["blue"])
    assert "resize" not in keys(await deploy_steps(env.ids["blue"]))


async def test_40_the_job_keeps_the_resize_decided_when_it_was_queued():
    env = await vm_world_env(ready=True, size=BIGGER, applied=SIZE)
    rows = await deploy_steps(env.instances["blue"])
    assert "resize" in keys(rows)
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=env.instances["blue"], environment_id=env.env_id, kind="deploy",
                         triggered_by_id=env.user_id, branch="main", log="", steps=rows, options={"slot": "blue"})
        db.add(dep)
        await db.commit()
    await machine_state(env, applied=dict(BIGGER))  # the rule no longer holds when the job starts
    job = await deployer._start(dep.id)
    assert job is not None and "resize" in keys(job.steps)
    assert job.provider == "proxmox" and job.status_before == "created"


# ------------------------------------------------------------------- P5 test 41, P4 test 63: fences


async def refusal(instance_id: uuid.UUID, kind: str = "deploy", *, user: Any = None, retry_of: Any = None,
                  options: dict | None = None, env_level: bool = False) -> jobs.JobRefused | None:
    db, instance, env, mem = await loaded(instance_id)
    try:
        if env_level:
            return await jobs.job_refusal(db, environment=env, user=user, kind=kind,
                                          options={"slot": instance.slot, **(options or {})}, retry_of=retry_of,
                                          members=mem)
        return await jobs.job_refusal(db, instance=instance, user=user, kind=kind, options=options,
                                      retry_of=retry_of, members=mem)
    finally:
        await db.close()


async def test_41_a_deploy_is_queued_on_a_machine_that_isnt_ready():
    env = await vm_world_env()
    user = await get(User, env.user_id)  # the environment's creator, the test's first user: an admin
    async with get_sessionmaker()() as db:
        instance = await db.get(Instance, env.instances["blue"])
        dep = await jobs.queue_job(db, instance=instance, user=user)
        await db.commit()
    assert keys(dep.steps)[:3] == ["resolve", "prepare", "source"]


async def test_41_other_kinds_wait_until_the_host_is_built():
    env = await vm_world_env(mode="server", slots=("blue",))
    user = await vf.a_user()
    got = await refusal(env.instances["blue"], "activate", user=user, env_level=True)
    # An activate onto a VM that isn't made says so at queue time, as its own check does (P5 §10.4).
    assert (got.status, got.text) == (409, "blue's VM isn't made yet: deploy to blue first")
    got = await refusal(env.instances["data"], "backup", user=user)
    assert (got.status, got.text) == (409, "Deploy uat first: its data server's VM isn't made yet")
    got = await refusal(env.instances["data"], "restore", user=user)
    assert got.text == "Deploy uat first: its data server's VM isn't made yet"


async def test_41_remove_slot_and_teardown_run_on_an_owned_host_in_any_phase():
    env = await vm_world_env()
    for stage in ("planned", "creating", "booting", "ready"):
        await machine_state(env, stage=stage)
        db, instance, row, _mem = await loaded(env.instances["blue"])
        try:
            for kind in ("remove_slot", "teardown"):
                assert await jobs.not_built_problem(db, row, instance, kind) is None
            got = await jobs.not_built_problem(db, row, instance, "backup")
            assert (got is None) == (stage == "ready")
        finally:
            await db.close()


async def test_41_ssh_hosts_keep_phase_3s_unpinned_refusal(tmp_path):
    multi = MultiRemote(tmp_path)
    seeded = await seed_env(multi, mode="slot", slots=("blue",))
    await set_rows(Host, seeded.host_ids["blue"], host_key=None)
    got = await refusal(seeded.ids["blue"], "backup", user=await vf.a_user())
    assert (got.status, got.text) == (400, "Host blue-host has not been verified yet; run a connection check first")


async def test_41_a_destroying_machine_takes_only_the_retry_of_its_removal():
    env = await vm_world_env(ready=True)
    await machine_state(env, stage="destroying")
    db, instance, row, _mem = await loaded(env.instances["blue"])
    try:
        got = await jobs.not_built_problem(db, row, instance, "deploy")
        assert got.text == f"{VM} is being removed; only the retry of that removal can run"
        assert (await jobs.not_built_problem(db, row, instance, "remove_slot")).text == got.text
        first = Deployment(id=uuid.uuid4(), kind="remove_slot", environment_id=env.env_id)
        assert await jobs.not_built_problem(db, row, instance, "remove_slot", retry_of=first) is None
        other = Deployment(id=uuid.uuid4(), kind="teardown", environment_id=env.env_id)
        assert (await jobs.not_built_problem(db, row, instance, "remove_slot", retry_of=other)).text == got.text
    finally:
        await db.close()


async def test_41_an_unusable_account_refuses_the_deploy_of_a_machine_not_ready():
    env = await vm_world_env()
    await set_rows(ProviderAccount, env.account_id, secret=None)
    admin = await get(User, env.user_id)
    got = await refusal(env.instances["blue"], "deploy", user=admin)
    assert got.status == 409
    assert got.text == "lab can't be used: its API token is missing or can't be read with SLIPWAY_ENCRYPTION_KEY"
    # A ready machine's deploy goes ahead: prepare warns and the deploy carries on over SSH (§6.3).
    await machine_state(env, stage="ready", applied=dict(SIZE))
    assert await refusal(env.instances["blue"], "deploy", user=admin) is None


async def test_41_forget_vms_only_on_removal_and_with_both_permissions():
    env = await vm_world_env(ready=True)
    admin = await get(User, env.user_id)  # the test's first user: an admin
    developer = await make_user(f"dev-{uuid.uuid4().hex[:6]}@example.com", roles=["developer"])
    got = await refusal(env.instances["blue"], "backup", user=admin, options={"forget_vms": True})
    assert (got.status, got.text) == (409, "Only removing a slot or deleting the environment can forget its VMs")
    got = jobs._forget_vms_problem(developer, "remove_slot")
    assert got.status == 403 and "machines:write" in got.text
    assert jobs._forget_vms_problem(admin, "remove_slot") is None
    assert jobs._forget_vms_problem(admin, "teardown") is None
    assert jobs._forget_vms_problem(None, "teardown").status == 403


async def test_63_a_job_on_a_planned_droplet_host_is_refused_unless_it_builds_or_removes_it():
    env = await dof.make_do_env()
    user = await vf.a_user()
    got = await refusal(env.ids["blue"], "activate", user=user, env_level=True)
    assert (got.status, got.text) == (409, "blue's server isn't built yet: deploy to blue first")
    got = await refusal(env.ids["green"], "discard", user=user, env_level=True)
    assert got.text == "green's server isn't built yet: deploy to green first"
    db, instance, row, _mem = await loaded(env.ids["blue"])
    try:
        assert await jobs.not_built_problem(db, row, instance, "deploy") is None
        assert await jobs.not_built_problem(db, row, instance, "remove_slot") is None
        assert await jobs.not_built_problem(db, row, instance, "teardown") is None
    finally:
        await db.close()
    # The deploy that builds it lists resolve, then prepare.
    assert keys(await deploy_steps(env.ids["blue"]))[:2] == ["resolve", "prepare"]


async def test_63_d28_a_deploy_to_the_active_slot_whose_droplet_is_gone():
    env = await dof.make_do_env()
    await built_droplet(env, "blue")
    await built_droplet(env, "green")
    await set_rows(Environment, env.env_id, active_slot_id=env.ids["blue"], status="live")
    db, instance, row, mem = await loaded(env.ids["blue"])
    try:
        got = await jobs.environment_fence(db, row, mem, instance=instance, kind="deploy")
        assert got.text == "blue serves traffic: deploy to green, then activate it"
    finally:
        await db.close()
    async with get_sessionmaker()() as db:
        host = await db.get(Host, env.host_ids["blue"])
        hosts.set_phase(host, hosts.PHASE_GONE)
        await db.commit()
    db, instance, row, mem = await loaded(env.ids["blue"])
    try:
        assert await jobs.environment_fence(db, row, mem, instance=instance, kind="deploy") is None
    finally:
        await db.close()


async def test_41_kind_problems_registry_is_consulted():
    env = await vm_world_env(ready=True)
    seen: list[dict[str, Any]] = []

    async def problem(**kw: Any) -> str | None:
        seen.append(kw)
        return "Not this VM snapshot"

    jobs.KIND_PROBLEMS["backup"] = problem
    try:
        got = await refusal(env.instances["blue"], "backup", user=await vf.a_user())
    finally:
        del jobs.KIND_PROBLEMS["backup"]
    assert (got.status, got.text) == (409, "Not this VM snapshot")
    assert set(seen[0]) == {"db", "env", "instance", "members", "options", "user", "retry_of"}


# --------------------------------------------------------------------- the system actor (P4 §15.12)


async def test_the_renewals_actor_queues_nothing_but_a_certificate_job():
    env = await dof.make_do_env()
    person = await vf.a_user()
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        for kind in ("deploy", "activate", "publish", "discard", "remove_slot", "teardown", "deactivate", "backup",
                     "restore", "vm_snapshot"):
            with pytest.raises(ValueError, match="renewals may queue only a certificate job"):
                await jobs.queue_job(db, environment=row, user=None, kind=kind, system="renewals")
        with pytest.raises(ValueError, match="can't queue jobs"):
            await jobs.queue_job(db, environment=row, user=None, kind="certificate", system="someone")
        with pytest.raises(ValueError, match="no user"):
            await jobs.queue_job(db, environment=row, user=person, kind="certificate", system="renewals")


async def test_the_renewals_actor_keeps_the_notice_and_records_who(monkeypatch):
    """The certificate job's steps are S15's (env_steps_for); stood in for here."""
    real = environments.env_steps_for

    def steps(env: Any, kind: str, options: Any, members: Any) -> list[dict[str, Any]]:
        if kind == "certificate":
            return [{"key": "check", "name": "Check", "status": "pending"},
                    {"key": "certificate", "name": "Renew the certificate", "status": "pending"}]
        return real(env, kind, options, members)

    monkeypatch.setattr(environments, "env_steps_for", steps)
    env = await dof.make_do_env(status="live")
    person = await vf.a_user()
    notice = {"text": "blue's deploy stopped", "at": "2026-11-16T00:00:00+00:00", "deployment_id": None,
              "next": {"kind": "activate", "slot": "blue"}}
    await set_rows(Environment, env.env_id, notice=notice)
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        dep = await jobs.queue_job(db, environment=row, user=None, kind="certificate", system="renewals")
        await db.commit()
    assert dep.triggered_by_id is None and dep.options["by"] == "renewals"
    assert data.job_keys(dep) == ((env.env_id, "traffic"),)
    assert (await get(Environment, env.env_id)).notice == notice  # a renewal never clears it (Decision 23)
    # A person's job clears it, as before.
    async with get_sessionmaker()() as db:
        await db.execute(update(Deployment).where(Deployment.id == dep.id).values(status="succeeded"))
        row = await db.get(Environment, env.env_id)
        await jobs.queue_job(db, environment=row, user=person, kind="certificate")
        await db.commit()
    assert (await get(Environment, env.env_id)).notice is None


async def test_an_unresolved_switch_refuses_a_renewal():
    env = await dof.make_do_env(status="live")
    await set_rows(Environment, env.env_id,
                   traffic_state={"unresolved": {"deployment_id": uuid.uuid4().hex, "message": "split"}})
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        text = environments.unresolved_text(row)
        assert text
        got = await jobs.job_refusal(db, environment=row, user=None, kind="certificate")
    assert got is not None and got.text == text


# -------------------------------------------------------------------- P5 test 51: kinds and keys


def test_51_kinds_labels_keys_and_retry_rows():
    assert "vm_revert" in data.CHANGING_KINDS
    assert {"certificate", "deactivate"} <= set(data.ENV_KINDS)
    for kind in ("certificate", "deactivate", "vm_snapshot", "vm_revert", "vm_drop"):
        assert data.KIND_LABELS[kind] and data.KIND_NOUNS[kind]
    env_id = uuid.uuid4()
    both = ((env_id, "data"), (env_id, "traffic"))
    assert data.env_keys(env_id, "certificate") == ((env_id, "traffic"),)
    assert data.env_keys(env_id, "deactivate") == both
    for kind in ("vm_snapshot", "vm_revert", "vm_drop"):
        assert data.env_keys(env_id, kind) == both
        assert data.env_keys(env_id, kind, on_app_slot=True) == both
    assert data.RETRY_PERMISSION["certificate"] == data.RETRY_PERMISSION["deactivate"] == "traffic:switch"
    assert data.RETRY_PERMISSION["vm_snapshot"] == data.RETRY_PERMISSION["vm_drop"] == "machines:write"
    assert data.RETRY_PERMISSION["vm_revert"] == "machines:write"
    assert data.RETRY_EXTRA["deactivate"] == ("environments:delete",)
    assert data.RETRY_EXTRA["vm_revert"] == ("data:reset",)
    assert "vm_snapshot" in jobs.HOLD_REFUSES
    assert {"confirm_production", "confirm_no_snapshot", "rebuild_data", "forget_vms", "drop_data"} <= jobs.ENV_ONE_SHOT
    for key in ("prepare", "resize", "database", "edge", "wipe", "vm_snapshot", "prune", "vm_revert", "wait",
                "vm_settle", "vm_drop"):
        assert deployer.STEP_NAMES[key]
    assert deployer.PRE_START_STEPS.index("resize") == deployer.PRE_START_STEPS.index("backup") + 1


async def test_51_an_older_failed_deploys_retry_backs_up_afresh_after_a_revert():
    env = await vm_world_env(ready=True)
    later = deployer.utcnow()
    async with get_sessionmaker()() as db:
        failed = Deployment(instance_id=env.instances["blue"], environment_id=env.env_id, kind="deploy",
                            branch="main", log="", status="failed", steps=[{"key": "start", "status": "failed"}])
        db.add(failed)
        await db.commit()
        assert (await data.latest_changing_job(db, env.instances["blue"])).id == failed.id
        reverted = Deployment(instance_id=env.instances["blue"], environment_id=env.env_id, kind="vm_revert",
                              branch="main", log="", status="succeeded", steps=[],
                              created_at=later + dt.timedelta(seconds=5))
        db.add(reverted)
        await db.commit()
        assert (await data.latest_changing_job(db, env.instances["blue"])).id == reverted.id
        assert not (await data.retry_inheritance(db, failed)).inherit


# ------------------------------------------------------------------------- the member-step timeouts


def test_step_timeouts_per_provider():
    assert deployer.step_timeout("prepare", "digitalocean") == 50 * 60
    assert deployer.step_timeout("prepare", "proxmox") == deployer.step_timeout("prepare", "esxi") == 120 * 60
    assert deployer.step_timeout("resize", "digitalocean") == 60 * 60
    assert deployer.step_timeout("resize", "proxmox") == 90 * 60
    assert deployer.step_timeout("database", "digitalocean") == 65 * 60
    assert deployer.step_timeout("edge", "digitalocean") == 40 * 60
    assert deployer.step_timeout("wipe", "digitalocean") == 45 * 60
    assert deployer.step_timeout("build") is None and deployer.step_timeout("start", "proxmox") is None


async def a_deployment(env_id: uuid.UUID, instance_id: uuid.UUID, steps: list[dict[str, Any]]) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=instance_id, environment_id=env_id, kind="deploy", branch="main", log="",
                         status="running", steps=steps)
        db.add(dep)
        await db.commit()
        return dep.id


async def test_a_member_step_timeout_cancels_the_step_and_fails_it(monkeypatch):
    env = await dof.make_do_env()
    dep_id = await a_deployment(env.env_id, env.ids["blue"],
                                [{"key": "prepare", "name": "Prepare DigitalOcean", "status": "pending"}])
    monkeypatch.setitem(deployer.PROVIDER_STEP_TIMEOUTS["digitalocean"], "prepare", 0.05)
    sink = deployer.LogSink(dep_id)
    steps = deployer.Steps(dep_id, [{"key": "prepare", "name": "Prepare DigitalOcean", "status": "pending"}], sink)
    shielded_done: list[str] = []

    async def finishes() -> None:
        await asyncio.sleep(0.2)
        shielded_done.append("done")

    async def body() -> tuple[str, str | None]:
        await do_provision._shielded(finishes())
        return "succeeded", None

    with pytest.raises(deployer.DeployError, match="^Prepare DigitalOcean timed out after 0.05 seconds$"):
        await deployer._timed_step(steps, sink, "prepare", "digitalocean", body)
    assert shielded_done == ["done"]  # the shielded part finished before the step failed
    assert steps.rows[0]["status"] == "failed"
    assert steps.rows[0]["note"] == "Prepare DigitalOcean timed out after 0.05 seconds"
    await sink.close()


async def test_76_resize_droplet_hitting_the_member_step_timeout_ends_active(tmp_path, monkeypatch):
    from tests.test_do_provision import _grow, _yielding_sleep, run_prepare  # noqa: PLC0415

    cloud = dof.Cloud(tmp_path, monkeypatch)
    env = await dof.make_do_env()
    got = await run_prepare(cloud, env)
    await _grow(env)
    cloud.do.action_polls = 20
    _yielding_sleep(cloud, monkeypatch, pause=0.01)
    monkeypatch.setitem(deployer.PROVIDER_STEP_TIMEOUTS["digitalocean"], "resize", 0.3)
    rows = [{"key": "resize", "name": "Resize slipway-shop-blue to s-1vcpu-2gb", "status": "pending"}]
    dep_id = await a_deployment(env.env_id, env.ids["blue"], rows)
    sink = deployer.LogSink(dep_id)
    steps = deployer.Steps(dep_id, rows, sink)

    async def body() -> tuple[str, str | None]:
        note = await do_provision.resize_droplet(cloud.context(env, deployment_id=dep_id))
        return ("skipped", note) if note else ("succeeded", None)

    with pytest.raises(deployer.DeployError, match="timed out after 0.3 seconds"):
        await deployer._timed_step(steps, sink, "resize", "digitalocean", body)
    assert cloud.do.droplets[int(got.droplet_id)]["status"] == "active"
    assert [a["type"] for a in cloud.do.actions.values()] == ["power_off", "resize", "power_on"]
    assert steps.rows[0]["status"] == "failed"
    await sink.close()


# ----------------------------------------------------------- P4 test 83 and the DigitalOcean pipeline


class DoGitHub(EnvGitHub):
    """The phase 3 test app, with ``get_file`` for prepare's read at the resolved commit."""

    files = {"slipway.yml": ENV_YML, "deploy/env.example": ENV_EXAMPLE, "deploy/app": ENV_SCRIPT}
    read: list[str] = []

    async def get_file(self, repo_id: Any, path: str, ref: str, **_kw: Any) -> str | None:
        DoGitHub.read.append(f"{path}@{ref}")
        return self.files.get(path)


class DoStubs:
    """``do_provision`` stood in for: what each step was called with, in order. ``prepare`` builds the slot's
    host as the real one would (ready, pinned with the key the fake host presents, at its address)."""

    def __init__(self, monkeypatch: Any, multi: MultiRemote, env: dof.DoEnv, *, digest: str | None = None) -> None:
        self.calls: list[str] = []
        self.multi, self.env, self.digest = multi, env, digest
        self.fail: dict[str, str] = {}
        monkeypatch.setattr(do_provision, "prepare", self.prepare)
        monkeypatch.setattr(do_provision, "database", self.database)
        monkeypatch.setattr(do_provision, "edge", self.edge)

    async def prepare(self, ctx: do_provision.ProvisionContext, *, read_manifest: Any) -> do_provision.Prepared:
        self.calls.append("prepare")
        text = await read_manifest()
        if "prepare" in self.fail:
            raise do_provision.ProvisionError(self.fail["prepare"])
        digest = self.digest or hashlib.sha256(text.encode()).hexdigest()
        ctx.manifest_sha256 = digest
        await do_provision._set_options(ctx, manifest_sha256=digest)
        async with get_sessionmaker()() as db:
            inst = await db.get(Instance, ctx.instance_id)
            host = await db.get(Host, inst.host_id)
            fake = self.multi[str(inst.slot)]
            host.hostname = fake.address
            host.deploy_root = str(fake.root)
            host.host_key = self.multi.new_key(str(inst.slot))
            hosts.set_phase(host, hosts.PHASE_READY, size="s-1vcpu-1gb")
            await db.commit()
        return do_provision.Prepared(host_id=host.id, droplet_id="1", public_ip=fake.address, private_ip="10.1.0.2",
                                     notes=["Resize pending: none"])

    async def database(self, ctx: do_provision.ProvisionContext) -> None:
        self.calls.append("database")
        return None

    async def edge(self, ctx: do_provision.ProvisionContext) -> do_provision.Edged:
        self.calls.append("edge")
        if "edge" in self.fail:
            raise do_provision.ProvisionError(self.fail["edge"])
        return do_provision.Edged(lb_id="lb", lb_ip="203.0.113.50", certificate={})


async def run_do(multi: MultiRemote, env: dof.DoEnv, slot: str = "blue") -> Deployment:
    rows = await deploy_steps(env.ids[slot])
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=env.ids[slot], environment_id=env.env_id, kind="deploy", branch="main", log="",
                         triggered_by_id=env.user_id, steps=rows, options={"slot": slot, "go_live": True})
        db.add(dep)
        await db.commit()
    DoGitHub.read = []
    await deployer.run_deployment(dep.id, connect=multi.connect, github=DoGitHub)
    return await get(Deployment, dep.id)


def statuses(dep: Deployment) -> dict[str, str]:
    return {r["key"]: r["status"] for r in dep.steps}


async def test_42_digitalocean_resolve_then_prepare_database_edge_before_source(tmp_path, monkeypatch):
    multi = MultiRemote(tmp_path)
    env = await dof.make_do_env()
    stubs = DoStubs(monkeypatch, multi, env)
    stubs.fail["edge"] = "The load balancer isn't active"
    dep = await run_do(multi, env)
    assert dep.status == "failed" and dep.error == "The load balancer isn't active"
    assert stubs.calls == ["prepare", "database", "edge"]
    assert DoGitHub.read == [f"slipway.yml@{dep.commit_sha}"]  # read at the resolved commit
    got = statuses(dep)
    assert got["resolve"] == "succeeded" and got["prepare"] == "succeeded"
    assert got["database"] == "skipped" and got["edge"] == "failed"
    assert all(got[k] == "pending" for k in ("source", "upload", "manifest", "start"))
    assert not multi.opened  # nothing reached the droplet
    note = next(r.get("note") for r in dep.steps if r["key"] == "prepare")
    assert note == "Resize pending: none"
    assert dep.options["manifest_sha256"]


async def test_42_a_prepare_failure_fails_the_job_and_nothing_after_it_runs(tmp_path, monkeypatch):
    multi = MultiRemote(tmp_path)
    env = await dof.make_do_env()
    stubs = DoStubs(monkeypatch, multi, env)
    stubs.fail["prepare"] = "slipway-shop-blue answered SSH with a host key Slipway didn't generate for it"
    mark = len(FakeGitHub.calls)
    dep = await run_do(multi, env)
    assert dep.status == "failed" and dep.error.startswith("slipway-shop-blue answered SSH")
    assert stubs.calls == ["prepare"]
    got = statuses(dep)
    assert got["prepare"] == "failed"
    assert [k for k, v in got.items() if v != "pending"] == ["resolve", "prepare"]
    assert not any(c.startswith("tarball") for c in FakeGitHub.calls[mark:])


async def test_83_an_uploaded_slipway_yml_other_than_the_provisioning_one_fails_manifest(tmp_path, monkeypatch):
    multi = MultiRemote(tmp_path)
    env = await dof.make_do_env()
    stubs = DoStubs(monkeypatch, multi, env, digest="0" * 64)
    dep = await run_do(multi, env)
    assert dep.status == "failed"
    assert dep.error == "The slipway.yml on slipway-shop-blue isn't the one Slipway provisioned from"
    got = statuses(dep)
    assert got["manifest"] == "failed" and got["start"] == "pending"
    assert stubs.calls == ["prepare", "database", "edge"]
    # The deployer's SSH target carried the pin prepare wrote (the fake host checks it).
    assert multi.opened and set(multi.opened) == {multi["blue"].address}


async def test_83_the_same_slipway_yml_passes_manifest(tmp_path, monkeypatch):
    """With the hash matching, the job goes on past manifest (the managed render itself is S14b's)."""
    multi = MultiRemote(tmp_path)
    env = await dof.make_do_env()
    DoStubs(monkeypatch, multi, env)
    dep = await run_do(multi, env)
    manifest_row = next(r for r in dep.steps if r["key"] == "manifest")
    assert manifest_row["status"] != "pending"
    assert "isn't the one Slipway provisioned from" not in (dep.error or "")


# ------------------------------------------------------------- P5 tests 42 and 43: a VM deploy, for real


class VmGitHub(EnvGitHub):
    files = {"slipway.yml": ENV_YML, "deploy/env.example": ENV_EXAMPLE, "deploy/app": ENV_SCRIPT}


@pytest.fixture
def world(tmp_path, monkeypatch, net) -> World:
    return World(tmp_path, monkeypatch, net)


async def queue_vm(env: vf.VmEnv, slot: str = "blue") -> uuid.UUID:
    async with get_sessionmaker()() as db:
        instance = await db.get(Instance, env.instances[slot])
        user = await db.get(User, env.user_id)
        dep = await jobs.queue_job(db, instance=instance, user=user)
        await db.commit()
        return dep.id


async def run_vm(world: World, env: vf.VmEnv, slot: str = "blue", gh: Any = VmGitHub) -> Deployment:
    dep_id = await queue_vm(env, slot)
    await deployer.run_deployment(dep_id, connect=world.vms.connect, github=gh)
    return await get(Deployment, dep_id)


async def live(env: vf.VmEnv, slot: str = "blue") -> None:
    """What the chained Activate records once it passed (the activate itself is phase 3's, tested there)."""
    async with get_sessionmaker()() as db:
        await db.execute(update(Deployment).where(Deployment.environment_id == env.env_id,
                                                  Deployment.status.in_(("queued", "running")))
                         .values(status="succeeded"))
        await db.execute(update(Environment).where(Environment.id == env.env_id)
                         .values(active_slot_id=env.instances[slot], status="live"))
        await db.commit()


@pytest.fixture(autouse=True)
def no_chain(monkeypatch) -> list[uuid.UUID]:
    """Jobs the chain queues are recorded, not run."""
    found: list[uuid.UUID] = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, keys: found.append(dep_id))
    return found


def shutdowns(world: World) -> list[dict[str, Any]]:
    return [r for r in world.fake.requests if r["method"] == "POST" and r["path"].endswith("/status/shutdown")]


async def test_42_a_vm_deploy_makes_the_vm_then_deploys_on_it(world, monkeypatch):
    monkeypatch.setattr(traffic, "sleep", vf.no_sleep)
    env = await blue_env(world)
    dep = await run_vm(world, env)
    assert dep.status == "succeeded", (dep.error, dep.log[-3000:])
    assert keys(dep.steps)[:3] == ["resolve", "prepare", "source"]
    started = {r["key"]: r.get("started_at") for r in dep.steps}
    assert started["resolve"] < started["prepare"] < started["source"]
    row = await get(Machine, env.machines["blue"])
    host = await get(Host, env.hosts["blue"])
    assert row.stage == "ready" and host.provider_state["phase"] == "ready"
    # After prepare the deployer's SSH target carried the new pin: the VM's fake host checks it.
    assert host.host_key and ssh.host_is_built(host)
    assert BLUE in world.vms.opened
    note = next(r.get("note") for r in dep.steps if r["key"] == "prepare")
    assert note == f"{VM} is ready at {BLUE}"
    assert fp_token_hidden(dep.log)


def fp_token_hidden(log: str) -> bool:
    from tests import fake_proxmox as fp  # noqa: PLC0415

    return fp.TOKEN not in log and fp.TOKEN.split("=", 1)[1] not in log


async def test_42_a_cut_off_in_prepare_ends_cancelled_with_the_stage_as_it_was(world, monkeypatch):
    env = await blue_env(world)
    entered = asyncio.Event()

    async def hangs(ctx: machines.MachineContext, *, resize: bool = False) -> tuple[str, str | None]:
        entered.set()
        await asyncio.sleep(3600)
        return "succeeded", None

    monkeypatch.setattr(machines, "prepare", hangs)
    dep_id = await queue_vm(env)
    task = asyncio.create_task(deployer.run_deployment(dep_id, connect=world.vms.connect, github=VmGitHub))
    await asyncio.wait_for(entered.wait(), 10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    dep = await get(Deployment, dep_id)
    assert dep.status == "cancelled"
    assert statuses(dep)["prepare"] == "failed" and statuses(dep)["source"] == "pending"
    assert (await get(Machine, env.machines["blue"])).stage == "planned"


async def test_42_a_failing_vm_prepare_fails_the_job_before_source(world, monkeypatch):
    env = await blue_env(world)

    async def fails(ctx: machines.MachineContext, *, resize: bool = False) -> tuple[str, str | None]:
        raise MachineError(f"Timed out after 25 minutes installing Docker on {ctx.vm}")

    monkeypatch.setattr(machines, "prepare", fails)
    mark = len(FakeGitHub.calls)
    dep = await run_vm(world, env)
    assert dep.status == "failed" and dep.error == f"Timed out after 25 minutes installing Docker on {VM}"
    assert [k for k, v in statuses(dep).items() if v != "pending"] == ["resolve", "prepare"]
    assert not any(c.startswith("tarball") for c in FakeGitHub.calls[mark:])
    assert any(c.startswith("commit ") for c in FakeGitHub.calls[mark:])  # resolve did run
    assert not world.vms.opened


async def grow_vm(env: vf.VmEnv, **size: int) -> None:
    async with get_sessionmaker()() as db:
        row = await db.get(Machine, env.machines["blue"])
        row.size = {**row.size, **size}
        await db.commit()


async def test_43_a_pending_resize_is_applied_after_backup_and_the_live_release_started(world, monkeypatch):
    monkeypatch.setattr(traffic, "sleep", vf.no_sleep)
    env = await blue_env(world)
    first = await run_vm(world, env)
    assert first.status == "succeeded", (first.error, first.log[-3000:])
    await live(env)
    assert (await get(Instance, env.instances["blue"])).status == "running"
    assert not shutdowns(world)
    await grow_vm(env, cores=6)
    docker_before = len(world.vms["blue"].docker())
    dep = await run_vm(world, env)
    assert dep.status == "succeeded", (dep.error, dep.log[-3000:])
    order = keys(dep.steps)
    assert order[order.index("backup") + 1] == "resize"
    row = next(r for r in dep.steps if r["key"] == "resize")
    assert row["status"] == "succeeded" and row["note"].startswith("Resized to 6 vCPU")
    assert len(shutdowns(world)) == 1
    assert world.fake.vm(100)["config"]["cores"] == 6
    assert (await get(Machine, env.machines["blue"])).applied["cores"] == 6
    # The live release's projects were started again after the resize (the control action), on a session opened
    # again once the VM was back.
    start = dep.log.index(f"Resize {VM} to 6 vCPU")
    section = dep.log[start:dep.log.index("── Step", start)]
    assert "docker compose -p demo-uat-blue-web start" in section
    assert section.index("Resizing slipway-uat-blue") < section.index("docker compose -p demo-uat-blue-web start")
    assert "ps -aq --filter label=com.docker.compose.project=demo-uat-blue-web" in \
        world.vms["blue"].docker()[docker_before:]
    assert any(a.action == "machine.resize" for a in await audit_rows())


async def audit_rows() -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        return list(await db.scalars(select(AuditEvent).order_by(AuditEvent.created_at)))


async def test_43_a_deploy_failing_at_manifest_never_shuts_the_vm_down(world, monkeypatch):
    monkeypatch.setattr(traffic, "sleep", vf.no_sleep)
    env = await blue_env(world)
    first = await run_vm(world, env)
    assert first.status == "succeeded", (first.error, first.log[-3000:])
    await live(env)
    await grow_vm(env, cores=6)

    class Broken(VmGitHub):
        files = {**VmGitHub.files, "slipway.yml": "name: [broken"}

    dep = await run_vm(world, env, gh=Broken)
    assert dep.status == "failed" and statuses(dep)["manifest"] == "failed"
    assert statuses(dep)["resize"] == "pending"
    assert not shutdowns(world)
    assert world.fake.vm(100)["config"]["cores"] == 4


async def test_43_resize_skipped_when_the_slot_became_active_of_two_after_queueing(world, monkeypatch):
    """machines.resize_step says it waits; the deployer ends the step skipped with that text, no shutdown."""
    monkeypatch.setattr(traffic, "sleep", vf.no_sleep)
    env = await blue_env(world)
    first = await run_vm(world, env)
    assert first.status == "succeeded", (first.error, first.log[-3000:])
    await live(env)
    await grow_vm(env, cores=6)
    text = "blue takes the traffic now; the resize waits"
    real = machines.resize_rule

    async def rule(db: Any, machine: Machine) -> str | None:
        return text

    dep_id = await queue_vm(env)
    assert "resize" in keys((await get(Deployment, dep_id)).steps)
    monkeypatch.setattr(machines, "resize_rule", rule)
    await deployer.run_deployment(dep_id, connect=world.vms.connect, github=VmGitHub)
    monkeypatch.setattr(machines, "resize_rule", real)
    dep = await get(Deployment, dep_id)
    assert dep.status == "succeeded", (dep.error, dep.log[-3000:])
    row = next(r for r in dep.steps if r["key"] == "resize")
    assert (row["status"], row["note"]) == ("skipped", text)
    assert not shutdowns(world)


# --------------------------------------------------------- P5 test 49, P4 test 61: recovery after a restart


async def interrupted(instance_id: uuid.UUID, env_id: uuid.UUID, step: str) -> uuid.UUID:
    rows = [{"key": "resolve", "name": "Resolve", "status": "succeeded"},
            {"key": "prepare", "name": "Prepare", "status": "running" if step == "prepare" else "succeeded"},
            {"key": "backup", "name": "Back up", "status": "succeeded"},
            {"key": "resize", "name": "Resize", "status": "running" if step == "resize" else "pending"},
            {"key": "start", "name": "Start", "status": "pending"}]
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=instance_id, environment_id=env_id, kind="deploy", branch="main", log="",
                         status="running", steps=rows)
        db.add(dep)
        await db.commit()
        return dep.id


async def test_49_an_interrupted_prepare_keeps_the_stage_and_clears_the_terraform_lock():
    env = await vm_world_env()
    await machine_state(env, stage="creating", last_task={"id": "UPID:pve1:1", "kind": "qmclone"})
    dep_id = await interrupted(env.instances["blue"], env.env_id, "prepare")
    from slipway.models import TerraformState  # noqa: PLC0415

    async with get_sessionmaker()() as db:
        db.add(TerraformState(machine_id=env.machines["blue"], state="{}", serial=1, lock_id=dep_id))
        await db.commit()
    await deployer.DeployRunner().recover_interrupted()
    row = await get(Machine, env.machines["blue"])
    assert row.stage == "creating" and row.last_error == f"Slipway restarted while preparing {VM}"
    assert row.last_task == {"id": "UPID:pve1:1", "kind": "qmclone"}
    async with get_sessionmaker()() as db:
        state = await db.get(TerraformState, env.machines["blue"])
    assert state.lock_id is None
    dep = await get(Deployment, dep_id)
    assert dep.status == "failed" and f"{VM} keeps its stage (creating)" in dep.log


async def test_49_an_interrupted_resize_sets_the_notice_last_error_and_left_off():
    env = await vm_world_env(ready=True, size=BIGGER, applied=SIZE)
    dep_id = await interrupted(env.instances["blue"], env.env_id, "resize")
    await deployer.DeployRunner().recover_interrupted()
    row = await get(Environment, env.env_id)
    text = f"{VM} was left off during a resize: deploy to blue again to finish it"
    assert row.notice["text"] == text and row.notice["next"] is None
    assert row.notice["deployment_id"] == dep_id.hex
    machine = await get(Machine, env.machines["blue"])
    assert machine.last_error == f"Slipway restarted while resizing {VM}"
    (left,) = [a for a in await audit_rows() if a.action == "machine.left_off"]
    assert left.details["name"] == VM


async def test_49_an_interrupted_resize_never_replaces_a_notice_with_a_next():
    env = await vm_world_env(ready=True, size=BIGGER, applied=SIZE)
    chained = {"text": "Deploying blue stopped", "at": "2026-11-16T00:00:00+00:00", "deployment_id": None,
               "next": {"kind": "activate", "slot": "blue"}}
    await set_rows(Environment, env.env_id, notice=chained)
    await interrupted(env.instances["blue"], env.env_id, "resize")
    await deployer.DeployRunner().recover_interrupted()
    assert (await get(Environment, env.env_id)).notice == chained
    assert (await get(Machine, env.machines["blue"])).last_error  # it lives in last_error instead


async def test_61_an_interrupted_droplet_prepare_leaves_the_host_building_then_the_next_adopts(tmp_path,
                                                                                               monkeypatch):
    """The create went out and its answer was lost, then Slipway restarted inside prepare: recovery clears
    nothing, and the next prepare adopts the droplet and pins it with the key written before the POST."""
    from tests.test_do_provision import run_prepare  # noqa: PLC0415

    cloud = dof.Cloud(tmp_path, monkeypatch)
    env = await dof.make_do_env()
    cloud.do.lose_answer[("POST", "/droplets")] = 1
    cloud.do.lost_visible_after = 30
    dep_id = await interrupted(env.ids["blue"], env.env_id, "prepare")
    with pytest.raises(do_provision.ProvisionError):
        await run_prepare(cloud, env, deployment_id=dep_id)
    sent_key = (await get(Host, env.host_ids["blue"])).host_key
    assert sent_key
    await deployer.DeployRunner().recover_interrupted()
    host = await get(Host, env.host_ids["blue"])
    assert host.provider_state["phase"] == "creating" and host.host_key == sent_key
    dep = await get(Deployment, dep_id)
    assert dep.status == "failed"
    assert "slipway-shop-blue stays building with its host key" in dep.log
    got = await run_prepare(cloud, env)
    assert cloud.writes().count(("POST", "/droplets")) == 1  # adopted, never made twice
    host = await get(Host, env.host_ids["blue"])
    assert host.host_key == sent_key == cloud.do.host_keys[int(got.droplet_id)]
    assert host.provider_state["phase"] == "ready"


async def test_an_interrupted_droplet_resize_writes_the_powered_off_notice():
    env = await dof.make_do_env()
    await built_droplet(env, "blue")
    dep_id = await interrupted(env.ids["blue"], env.env_id, "resize")
    await deployer.DeployRunner().recover_interrupted()
    notice = (await get(Environment, env.env_id)).notice
    assert notice["text"] == "blue's droplet may be powered off: deploy to blue again"
    assert notice["deployment_id"] == dep_id.hex and notice["next"] is None
