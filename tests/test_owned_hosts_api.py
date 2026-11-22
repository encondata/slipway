"""Hosts an environment made, over the API (S20): P4 test 66 and P5 test 58's generic half, P4 test 80's
unmanaged-claim and deploy-root-move cases with a managed owner around, P5 test 53's HTTP half (two creates
racing for one address) and P5 test 61 (Delete's body rules when the data is on a VM).

Every refusal is ``hosts.owned_host_refusal``'s text, for a droplet or a VM in its own words. The label and the
description stay editable. Nothing here connects anywhere: the probe is a stand-in, and the hypervisors are
never called (the VMs are only planned).
"""

from __future__ import annotations

import uuid
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select, update

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
    Repository,
)
from slipway.services import deployer, environments, machines, ssh, switchyard
from tests import do_fixtures as dof
from tests import vm_fixtures as vf
from tests.fake_hosts import ENV_EXAMPLE, ENV_YML
from tests.test_data_api import clients, storage  # noqa: F401  (storage: autouse)

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")

DROPLET_EDIT = "slipway-shop-blue is a droplet Slipway made for shop; change it on the environment"
DROPLET_PLACE = "slipway-shop-blue is a droplet of environment shop; only its slots run there"


@pytest.fixture(autouse=True)
def submitted(monkeypatch) -> list[uuid.UUID]:
    found: list[uuid.UUID] = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, keys: found.append(dep_id))
    return found


@pytest.fixture
async def c(make_client) -> dict[str, httpx.AsyncClient]:
    return await clients(make_client)


async def set_rows(model: Any, ident: uuid.UUID, **values: Any) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(update(model).where(model.id == ident).values(**values))
        await db.commit()


async def get_row(model: Any, ident: uuid.UUID) -> Any:
    async with get_sessionmaker()() as db:
        return await db.get(model, ident)


def probe_ok(monkeypatch) -> list[str]:
    """``ssh.probe`` answers as a healthy host would, and records whom it probed."""
    probed: list[str] = []

    async def probe(target):
        probed.append(target.hostname)
        return ssh.ProbeResult(host_key=target.pinned_host_key or "ssh-ed25519 AAAA", fingerprint="SHA256:x",
                               os_info="Ubuntu 24.04", cpus=2, cpu_percent=5.0, mem_total_mb=2048, mem_percent=20.0,
                               docker_version="27.1", docker_error=None, containers_running=0)

    monkeypatch.setattr(ssh, "probe", probe)
    return probed


# ------------------------------------------------------- tests 66 and 58: the hosts API on an owned host


async def test_66_an_owned_droplet_refuses_every_change_of_how_slipway_reaches_it(c, monkeypatch):
    env = await dof.make_do_env()
    admin = c["admin"]
    url = f"/api/v1/hosts/{env.host_ids['blue']}"
    out = (await admin.get(url)).json()
    assert out["owned_by"] == {"id": str(env.env_id), "name": "shop", "slot": "blue"}
    assert out["built"] is False and out["provider_state"] == {"phase": "planned"} and out["provider"] == "digitalocean"
    for patch in ({"hostname": "203.0.113.99"}, {"proxy_address": "10.1.1.1"}, {"lan_address": "10.1.1.2"},
                  {"port": 2222}, {"username": "root"}, {"password": "hunter22", "auth_method": "password"},
                  {"auth_method": "generate"}, {"deploy_root": "/srv/apps"}, {"name": "renamed"}):
        resp = await admin.patch(url, json=patch)
        assert (resp.status_code, resp.json()["detail"]) == (409, DROPLET_EDIT), patch
    # The fields sent with their current values change nothing, and the label and description stay editable.
    resp = await admin.patch(url, json={"label": "shop prod", "description": "Blue's droplet",
                                        "hostname": out["hostname"], "port": out["port"]})
    assert resp.status_code == 200, resp.text
    assert (resp.json()["label"], resp.json()["description"]) == ("shop prod", "Blue's droplet")
    resp = await admin.delete(url)
    assert (resp.status_code, resp.json()["detail"]) == (409, "slipway-shop-blue goes when shop removes its blue slot")
    resp = await admin.post(f"{url}/reset-host-key")
    assert (resp.status_code, resp.json()["detail"]) == (
        409, "slipway-shop-blue's key was made by Slipway with the droplet for shop; Slipway changes it only when it "
             "builds the droplet again")
    # Check: 409 while it isn't built, allowed once it is (and it never pins a key there).
    probed = probe_ok(monkeypatch)
    resp = await admin.post(f"{url}/check")
    assert (resp.status_code, resp.json()["detail"]) == (
        409, "Slipway pins slipway-shop-blue's key itself when it makes the droplet: deploy to blue")
    assert probed == []
    await set_rows(Host, env.host_ids["blue"], provider_state={"phase": "ready", "size": "s-1vcpu-1gb"},
                   host_key="ssh-ed25519 AAAAdroplet", hostname="203.0.113.10")
    resp = await c["viewer"].post(f"{url}/check")  # a provider host's check pins nothing: hosts:read is enough
    assert resp.status_code == 200, resp.text
    assert resp.json()["built"] is True and probed == ["203.0.113.10"]
    host = await get_row(Host, env.host_ids["blue"])
    assert host.host_key == "ssh-ed25519 AAAAdroplet" and host.status == "healthy"
    listed = {h["id"]: h for h in (await admin.get("/api/v1/hosts")).json()}
    assert listed[str(env.host_ids["green"])]["owned_by"]["slot"] == "green"


async def test_58_an_owned_vm_says_vm_and_names_its_account(c, monkeypatch):
    vf.quiet_network(monkeypatch)
    account = await vf.proxmox_account()
    made = await vf.vm_env(account, name="uat", addresses={"blue": "10.0.0.120"})
    host_id = made.hosts["blue"]
    await set_rows(Host, host_id, provider_state={"phase": "ready"}, host_key="ssh-ed25519 AAAAvm")
    admin = c["admin"]
    url = f"/api/v1/hosts/{host_id}"
    resp = await admin.patch(url, json={"hostname": "10.0.0.121"})
    assert (resp.status_code, resp.json()["detail"]) == (
        409, "slipway-uat-blue is a VM Slipway made for uat; change it on the environment")
    resp = await admin.post(f"{url}/reset-host-key")
    assert (resp.status_code, resp.json()["detail"]) == (
        409, "slipway-uat-blue's key was pinned from lab. If the VM was rebuilt by hand, use Forget the VM on uat")
    resp = await admin.delete(url)
    assert (resp.status_code, resp.json()["detail"]) == (409, "slipway-uat-blue goes when uat removes its blue slot")
    out = (await admin.get(url)).json()
    assert out["owned_by"] == {"id": str(made.env_id), "name": "uat", "slot": "blue"} and out["built"] is True
    assert out["provider"] == "proxmox" and out["provider_state"] == {"phase": "ready"}


async def test_66_post_instances_and_a_placement_change_onto_an_owned_host_are_refused(c):
    env = await dof.make_do_env()
    admin = c["admin"]
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=555, full_name="acme/app", owner="acme", name="app",
                          html_url="https://github.com/acme/app", detected_config={}, default_branch="main")
        hand = Host(name="hand-1", hostname="10.0.0.31", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
        db.add_all([repo, hand])
        await db.flush()
        alone = Instance(name="alone", slug="alone", branch="main", host_id=hand.id, repository=repo, env={},
                         ports=[], volumes=[], build_source="compose")
        db.add(alone)
        await db.commit()
    body = {"name": "sneaky", "repository_id": str(repo.id), "host_id": str(env.host_ids["blue"]),
            "build_source": "compose", "deploy": False}
    resp = await admin.post("/api/v1/instances", json=body)
    assert (resp.status_code, resp.json()["detail"]) == (409, DROPLET_PLACE)
    resp = await admin.patch(f"/api/v1/instances/{alone.id}", json={"host_id": str(env.host_ids["blue"])})
    assert (resp.status_code, resp.json()["detail"]) == (409, DROPLET_PLACE)
    assert (await get_row(Instance, alone.id)).host_id == hand.id
    async with get_sessionmaker()() as db:
        assert await db.scalar(select(func.count()).select_from(Instance).where(Instance.name == "sneaky")) == 0


async def test_66_and_80_the_unmanaged_claim_and_the_deploy_root_move_with_a_managed_owner(c):
    env = await dof.make_do_env()  # its data owner has no host
    admin = c["admin"]
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=556, full_name="acme/claimed", owner="acme", name="claimed",
                          html_url="https://github.com/acme/claimed", detected_config={}, default_branch="main")
        db.add(repo)
        await db.commit()
    claim = {"name": "claimed", "repository_id": str(repo.id), "group": {"kind": "compose", "project": "legacy"}}
    blue = f"/api/v1/hosts/{env.host_ids['blue']}"
    resp = await admin.post(f"{blue}/claim", json=claim)
    assert (resp.status_code, resp.json()["detail"]) == (409, DROPLET_PLACE)
    resp = await admin.get(f"{blue}/unmanaged")
    assert (resp.status_code, resp.json()["detail"]) == (
        409, "slipway-shop-blue isn't built yet: deploy shop to build it")
    # The deploy-root move of a droplet with a deployed slot: refused before anything moves.
    await set_rows(Instance, env.ids["blue"], status="running", current_commit_sha=dof.SHA)
    resp = await admin.patch(blue, json={"deploy_root": "/srv/elsewhere"})
    assert (resp.status_code, resp.json()["detail"]) == (
        409, "slipway-shop-blue is a droplet Slipway made for shop; its deploy root stays where Slipway set it")
    # A host added by hand, with the managed owner in the database: the move finds nothing to move, no error.
    async with get_sessionmaker()() as db:
        hand = Host(name="hand-2", hostname="10.0.0.32", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
        db.add(hand)
        await db.commit()
    resp = await admin.patch(f"/api/v1/hosts/{hand.id}", json={"deploy_root": "/srv/apps"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["owned_by"] is None and resp.json()["built"] is True


# ---------------------------------------------------------------- P5 test 53: the HTTP half


FILES = {"slipway.yml": ENV_YML, "deploy/env.example": ENV_EXAMPLE}
ADMIN = {"fields": {"email": "ada@example.com", "name": "Ada"}, "mode": "password", "password": "correct-horse-9"}


@pytest.fixture
async def vms(c, monkeypatch) -> dict[str, Any]:
    vf.quiet_network(monkeypatch)
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=4343, full_name="acme/demo", owner="acme", name="demo",
                          html_url="https://github.com/acme/demo", detected_config={})
        db.add(repo)
        db.add(AppSetting(key=switchyard.SETTING_KEY, value={"url": "https://sy.example.test",
                                                             "default_tls_mode": "auto"}, secret="sy_" + "k" * 30))
        await db.commit()

    async def read(repo, branch, path):
        return FILES.get(path)

    monkeypatch.setattr(environments, "github_reader", lambda user: read)
    return {"repo_id": repo.id, "pve": await vf.proxmox_account()}


def vm_body(vms: dict[str, Any], name: str, address: str, **kw: Any) -> dict[str, Any]:
    body = {"name": name, "repository_id": str(vms["repo_id"]), "data_mode": "slot",
            "hosts": {"blue": {"machine": {"account_id": str(vms["pve"].id), "network": "lan", "address": address}}},
            "settings": {"APP_DOMAIN": f"{name}.example.com"}, "traffic": {"switch": "none", "dns": None},
            "first_admin": ADMIN}
    body.update(kw)
    return body


async def counts() -> tuple[int, ...]:
    async with get_sessionmaker()() as db:
        return tuple([await db.scalar(select(func.count()).select_from(m))
                      for m in (Environment, Instance, Host, Machine, AddressClaim)])


def blind_to(monkeypatch, address: str) -> None:
    """The second create's registry read doesn't see the first's claim yet: the race of P5 test 53."""
    real = machines.addresses_in_use

    async def blind(db, **kw):
        found = await real(db, **kw)
        found.pop(address, None)
        return found

    monkeypatch.setattr(machines, "addresses_in_use", blind)


async def test_53_two_creates_racing_for_one_address_one_201_one_409(c, vms, monkeypatch):
    admin = c["admin"]
    blind_to(monkeypatch, "10.0.0.130")
    resp = await admin.post("/api/v1/environments", json=vm_body(vms, "first", "10.0.0.130"))
    assert resp.status_code == 201, resp.text
    before = await counts()
    resp = await admin.post("/api/v1/environments", json=vm_body(vms, "second", "10.0.0.130"))
    assert (resp.status_code, resp.json()) == (409, {
        "detail": "10.0.0.130 was just taken by another environment: pick another address",
        "field": "hosts.blue.machine.address"})
    assert await counts() == before
    async with get_sessionmaker()() as db:
        assert await db.scalar(select(Environment.id).where(Environment.name == "second")) is None


async def test_53_a_claim_conflict_the_commit_meets_answers_the_same_409(c, vms, monkeypatch):
    """When the service's own flush doesn't meet the conflict (another create committed in between), the API's
    catch around the commit answers it."""
    from sqlalchemy.exc import IntegrityError

    admin = c["admin"]
    real_create = environments.create

    async def create(db, plan, ctx, **kw):
        env = await real_create(db, plan, ctx, **kw)
        real_commit = db.commit

        async def commit():
            db.commit = real_commit
            raise IntegrityError("INSERT INTO address_claims", {},
                                 Exception("UNIQUE constraint failed: address_claims.address"))

        db.commit = commit
        return env

    monkeypatch.setattr(environments, "create", create)
    before = await counts()
    resp = await admin.post("/api/v1/environments", json=vm_body(vms, "second", "10.0.0.131"))
    assert (resp.status_code, resp.json()) == (409, {
        "detail": "10.0.0.131 was just taken by another environment: pick another address",
        "field": "hosts.blue.machine.address"})
    assert await counts() == before


# ---------------------------------------------------------------- P5 test 61: Delete with a data VM


async def test_61_delete_needs_drop_data_when_the_data_is_on_a_vm_or_a_snapshot_first(c, vms, monkeypatch):
    admin = c["admin"]
    body = vm_body(vms, "prod", "10.0.0.140", data_mode="server",
                   hosts={"blue": {"machine": {"account_id": str(vms["pve"].id), "network": "lan",
                                               "address": "10.0.0.140"}},
                          "data": {"machine": {"account_id": str(vms["pve"].id), "network": "lan",
                                               "address": "10.0.0.141"}}},
                   traffic={"switch": "switchyard", "dns": None})
    resp = await admin.post("/api/v1/environments", json=body)
    assert resp.status_code == 201, resp.text
    env_id = uuid.UUID(resp.json()["id"])
    owner_id = uuid.UUID(resp.json()["data_owner_id"])
    # The data server's VM is made, and it held data once.
    await set_rows(Instance, owner_id, fresh_data="seeded", current_commit_sha="0" * 40, status="running",
                   app_state={"live": {"release": "r1", "sha": "0" * 40, "deployment": "22" * 16},
                              "manifest": {"data": {"app": "demo"}}})
    async with get_sessionmaker()() as db:
        data_vm = await db.scalar(select(Machine).where(Machine.environment_id == env_id, Machine.slot == "data"))
        host = await db.get(Host, data_vm.host_id)  # built (its machine stays planned: no hypervisor is read)
        host.provider_state = {"phase": "ready"}
        host.host_key = "ssh-ed25519 AAAAdatavm"
        await db.commit()
    url = f"/api/v1/environments/{env_id}"
    resp = await admin.request("DELETE", url, json={"confirm": "prod"})
    assert (resp.status_code, resp.json()) == (409, {
        "detail": "prod's data is on slipway-prod-data, which Delete destroys: take a snapshot first, or confirm "
                  "that the data goes with it", "field": "drop_data"})
    resp = await c["developer"].request("DELETE", url, json={"confirm": "prod", "drop_data": True})
    assert resp.status_code == 403  # environments:delete, and data:reset for drop_data
    # With a snapshot: P3's chain, the snapshot first and then the teardown, which removes the VMs.
    seen: dict[str, Any] = {}
    real_require = environments.data.require_data_job

    async def runnable(db, instance, kind, **kw):
        seen["kind"] = kind
        return {}

    monkeypatch.setattr(environments.data, "require_data_job", runnable)
    from slipway.services import snapshots

    monkeypatch.setattr(snapshots, "require_storage", lambda: None)
    resp = await admin.request("DELETE", url, json={"confirm": "prod", "snapshot": {"name": "prod-last"}})
    monkeypatch.setattr(environments.data, "require_data_job", real_require)
    assert resp.status_code == 202, resp.text
    assert seen["kind"] == "snapshot" and resp.json()["kind"] == "snapshot"
    async with get_sessionmaker()() as db:
        snap = await db.get(Deployment, uuid.UUID(resp.json()["id"]))
        assert snap.options["then"] == "teardown" and snap.instance_id == owner_id
        snap.status = "succeeded"
        await db.commit()
        nxt = await environments.next_job(db, snap)
        assert nxt is not None and nxt.kind == "teardown" and nxt.options["snapshot_first"] is True
        env = await db.get(Environment, env_id)
        mem = await environments.members(db, env)
        steps = [s["key"] for s in environments.env_steps_for(env, "teardown", nxt.options, mem)]
        assert "machines" in steps and steps.index("machines") < steps.index("forget")
    events = [e.action for e in await _audits()]
    assert "snapshot.take" in events and "environment.delete_without_snapshot" not in events


async def _audits() -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        return list(await db.scalars(select(AuditEvent).order_by(AuditEvent.created_at)))


async def test_61_drop_data_deletes_a_vm_environment_without_a_snapshot_and_audits_why(c, vms):
    admin = c["admin"]
    body = vm_body(vms, "lab", "10.0.0.150", data_mode="server",
                   hosts={"blue": {"machine": {"account_id": str(vms["pve"].id), "network": "lan",
                                               "address": "10.0.0.150"}},
                          "data": {"machine": {"account_id": str(vms["pve"].id), "network": "lan",
                                               "address": "10.0.0.151"}}},
                   traffic={"switch": "switchyard", "dns": None})
    resp = await admin.post("/api/v1/environments", json=body)
    assert resp.status_code == 201, resp.text
    env_id = uuid.UUID(resp.json()["id"])
    await set_rows(Instance, uuid.UUID(resp.json()["data_owner_id"]), fresh_data="seeded")
    resp = await admin.request("DELETE", f"/api/v1/environments/{env_id}", json={"confirm": "lab", "drop_data": True})
    assert resp.status_code == 202, resp.text
    assert resp.json()["kind"] == "teardown"
    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, uuid.UUID(resp.json()["id"]))
        assert dep.options["drop_data"] is True
        event = await db.scalar(select(AuditEvent).where(AuditEvent.action == "environment.delete_without_snapshot"))
        assert event is not None and event.details["why"] == "drop_data: the data goes with the environment"


async def test_58_a_teardown_retry_takes_forget_vms_with_its_permissions_and_the_name(c, vms, make_client):
    from tests.test_data_api import client_with

    made = await vf.vm_env(vms["pve"], name="gone", addresses={"blue": "10.0.0.160"})
    await set_rows(Environment, made.env_id, status="deleting")
    async with get_sessionmaker()() as db:
        dep = Deployment(environment_id=made.env_id, kind="teardown", status="failed", branch="main", steps=[],
                         options={"confirmed": True})
        db.add(dep)
        await db.commit()
    url = f"/api/v1/deployments/{dep.id}/retry"
    deleter = await client_with(make_client, "deleter@example.com", ["environments:delete", "deployments:read"])
    resp = await deleter.post(url, json={"confirm": "gone", "forget_vms": True})
    assert resp.status_code == 403  # machines:write
    resp = await c["admin"].post(url, json={"forget_vms": True})
    assert resp.status_code == 422
    resp = await c["admin"].post(url, json={"forget_vms": True, "confirm": "gone"})
    assert resp.status_code == 202, resp.text
    async with get_sessionmaker()() as db:
        new = await db.get(Deployment, uuid.UUID(resp.json()["id"]))
        assert new.kind == "teardown" and new.options["forget_vms"] is True
