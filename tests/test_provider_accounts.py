"""Provider accounts through ``/api/v1/provider-accounts`` for DigitalOcean, Proxmox and ESXi.

Phase 4 tests 33 (save, the token write-only, one token per account, the team freeze and its race, clear,
``ssh_sources``, the production flag, remove), 34 (Test), 35 (the catalog and its cache) and 87 (new and
deleting environments count, the tombstone, the SSH lock-out guard); phase 5 tests 36 (create and trust),
37 (update and remove) and 38's Test half (the addresses half is the machines API's). Also the permission
split and every audit action, none of which may carry a secret.

Everything outside is a fake: FakeDigitalOcean, FakeProxmox, FakeEsxi, and a stand-in for the one unverified
certificate read. Environment and machine rows are inserted directly to exercise the in-use rules.
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from sqlalchemy import func, select

from slipway.db.session import get_sessionmaker
from slipway.models import AuditEvent, Environment, Host, Machine, ProviderAccount, Repository
from slipway.services import esxi, provider_accounts, tls_pin
from slipway.services.vmtypes import MachineError
from tests import fake_digitalocean as fdo
from tests import fake_proxmox as fp
from tests.conftest import login, make_user
from tests.fake_esxi import FakeEsxi

API = "/api/v1/provider-accounts"
TOKEN_B = "dop_v1_" + "fedcba9876543210" * 4  # another team's token
TOKEN_C = "dop_v1_" + "00112233445566778899aabbccddeeff" * 2  # a second token of the first team
ESXI_PASSWORD = "esx-Secret-pw-42"


def make_pem(cn: str) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=365)).sign(key, hashes.SHA256()))
    return cert.public_bytes(Encoding.PEM).decode()


PVE_PEM = make_pem("pve.test")
ESXI_PEM = make_pem("localhost.localdomain")

NET_PVE = {"name": "lan", "bridge": "vmbr0", "subnet": "10.0.0.0/24", "gateway": "10.0.0.1", "dns_servers": [],
           "pool": {"first": "10.0.0.100", "last": "10.0.0.150"}}
NET_ESXI = {"name": "lan", "port_group": "VM Network", "subnet": "10.0.0.0/24", "gateway": "10.0.0.1"}


# ------------------------------------------------------------------------ fixtures


@pytest.fixture(autouse=True)
def _fresh_catalog():
    provider_accounts.clear_catalog_cache()
    yield
    provider_accounts.clear_catalog_cache()


@pytest.fixture
def do(monkeypatch) -> fdo.FakeDigitalOcean:
    fake = fdo.FakeDigitalOcean()
    fake.add_token(TOKEN_B, "Other Team")
    fake.tokens[TOKEN_C] = dict(fdo.TEAM)
    return fdo.use_fake(monkeypatch, fake)


@pytest.fixture
def pve(monkeypatch, tmp_path) -> fp.FakeProxmox:
    return fp.FakeProxmox(tmp_path / "pve.json").install(monkeypatch)


@pytest.fixture
def esx(monkeypatch) -> FakeEsxi:
    fake = FakeEsxi()
    fake.add_datastore("datastore1", free_gb=412.5, capacity_gb=1000)
    fake.add_network("VM Network")
    fake.add_vm("ubuntu-2404-seed", disk_gb=10)
    monkeypatch.setattr(esxi, "session", fake.session_factory())
    return fake


@pytest.fixture
def live(monkeypatch) -> dict[str, Any]:
    """The certificate each URL presents: what ``tls_pin.read_certificate`` would fetch, unverified."""
    state: dict[str, Any] = {"pems": {("pve.test", 8006): PVE_PEM, ("esxi.lan", 443): ESXI_PEM}, "reads": []}

    async def read_certificate(host: str, port: int, *, timeout: float = 10.0) -> str:
        state["reads"].append((host, port))
        if (host, port) not in state["pems"]:
            raise tls_pin.TlsPinError(f"Slipway couldn't connect to {host}:{port} to read its certificate")
        return state["pems"][(host, port)]

    monkeypatch.setattr(tls_pin, "read_certificate", read_certificate)
    return state


def fingerprint(pem: str) -> str:
    return tls_pin.fingerprint(pem)


def do_body(**kw: Any) -> dict[str, Any]:
    return {"provider": "digitalocean", "name": "DO main", "secret": fdo.TOKEN, "region": "nyc3",
            "ssh_sources": ["198.51.100.0/24"], **kw}


def pve_body(**kw: Any) -> dict[str, Any]:
    return {"provider": "proxmox", "name": "Lab", "secret": fp.TOKEN, "url": fp.URL, "node": "pve1",
            "pool": fp.POOL, "storage": fp.STORAGE, "template_vmid": fp.TEMPLATE_VMID, "networks": [NET_PVE],
            "trust_fingerprint": fingerprint(PVE_PEM), **kw}


def esxi_body(**kw: Any) -> dict[str, Any]:
    return {"provider": "esxi", "name": "esx-01", "secret": ESXI_PASSWORD, "url": "https://esxi.lan",
            "user": "slipway", "datastore": "datastore1", "source_vm": "ubuntu-2404-seed", "networks": [NET_ESXI],
            "trust_fingerprint": fingerprint(ESXI_PEM), **kw}


async def created(client, body: dict[str, Any]) -> dict[str, Any]:
    resp = await client.post(API, json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


async def delete(client, account_id: str, confirm: str | None):
    return await client.request("DELETE", f"{API}/{account_id}", json={"confirm": confirm})


async def row(account_id: str) -> ProviderAccount | None:
    async with get_sessionmaker()() as db:
        return await db.get(ProviderAccount, uuid.UUID(account_id))


async def audits(action: str | None = None) -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        stmt = select(AuditEvent).order_by(AuditEvent.created_at)
        if action:
            stmt = stmt.where(AuditEvent.action == action)
        return list(await db.scalars(stmt))


async def no_secret_in_audit(*secrets: str) -> None:
    for event in await audits():
        text = json.dumps({"summary": event.summary, "details": event.details}, default=str)
        for secret in secrets:
            assert secret not in text, event.action


async def count_accounts() -> int:
    async with get_sessionmaker()() as db:
        return await db.scalar(select(func.count()).select_from(ProviderAccount))


async def repo_id() -> uuid.UUID:
    async with get_sessionmaker()() as db:
        repo = await db.scalar(select(Repository).where(Repository.full_name == "acme/web"))
        if repo is None:
            repo = Repository(github_id=1, full_name="acme/web", owner="acme", name="web",
                              html_url="https://github.com/acme/web")
            db.add(repo)
            await db.commit()
        return repo.id


async def add_env(account_id: str | None, name: str, *, status: str = "live", cost: int | None = None,
                  production: bool = False, team: str | None = None, addresses: list[str] | None = None,
                  manifest: str | None = None) -> uuid.UUID:
    cloud: dict[str, Any] = {}
    if cost is not None:
        cloud["cost"] = {"total_cents": cost}
    if addresses is not None:
        cloud["slipway_addresses"] = addresses
    values: dict[str, Any] = {"name": name, "repository_id": await repo_id(), "branch": "main", "status": status,
                              "manifest_file": manifest or f"{name}.yml"}
    if status == "deleted":
        values["deleted_at"] = dt.datetime.now(dt.UTC)
    if account_id is not None:
        values.update(provider="digitalocean", provider_account_id=uuid.UUID(account_id), data_mode="managed",
                      cloud=cloud, production=production, provider_team=team)
    else:
        values["data_mode"] = "slot"
    async with get_sessionmaker()() as db:
        env = Environment(**values)
        db.add(env)
        await db.commit()
        return env.id


async def add_machine(account_id: str, env_name: str, slot: str = "blue", *, network: str = "lan",
                      provider: str = "proxmox") -> None:
    env_id = await add_env(None, env_name)
    name = f"slipway-{env_name}-{slot}"
    async with get_sessionmaker()() as db:
        host = Host(name=name, hostname="10.0.0.120", username="slipway", provider=provider,
                    provider_state={"phase": "planned"})
        db.add(host)
        await db.flush()
        db.add(Machine(environment_id=env_id, host_id=host.id, account_id=uuid.UUID(account_id), provider=provider,
                       slot=slot, name=name, spec={}, network={"name": network, "address": "10.0.0.120"},
                       size={"cores": 2, "memory_mb": 2048, "disk_gb": 20}))
        await db.commit()


# ------------------------------------------------------------------ permissions


async def test_developers_list_accounts_and_only_admins_change_them(make_client, do):
    await make_user("admin@example.com")
    admin = make_client()
    await login(admin, "admin@example.com")
    account = await created(admin, do_body())
    for role, can_read in (("developer", True), ("maintainer", True), ("viewer", False)):
        await make_user(f"{role}@example.com", roles=[role])
        client = make_client()
        await login(client, f"{role}@example.com")
        assert (await client.get(API)).status_code == (200 if can_read else 403)
        assert (await client.get(f"{API}/{account['id']}")).status_code == (200 if can_read else 403)
        resp = await client.post(API, json=do_body(name="Mine", secret=TOKEN_B))
        assert resp.status_code == 403 and "providers:write" in resp.json()["detail"]
        assert (await client.patch(f"{API}/{account['id']}", json={"name": "Renamed"})).status_code == 403
        assert (await client.post(f"{API}/{account['id']}/test")).status_code == 403
        assert (await client.post(f"{API}/test", json={"secret": fdo.TOKEN})).status_code == 403
        assert (await delete(client, account["id"], "DO main")).status_code == 403
        catalog = await client.get(f"{API}/{account['id']}/catalog")
        assert catalog.status_code == (200 if can_read else 403)


# ------------------------------------------------------------- DigitalOcean (test 33)


async def test_do_save_keeps_the_token_write_only(admin_client, do):
    out = await created(admin_client, do_body(monthly_limit_cents=50000))
    assert out["provider"] == "digitalocean" and out["has_secret"] is True
    assert out["secret_hint"] == fdo.TOKEN[-4:] and "secret" not in out
    assert (out["region"], out["ssh_sources"], out["ssh_open"]) == ("nyc3", ["198.51.100.0/24"], False)
    assert (out["monthly_limit_cents"], out["estimate_cents"], out["team_name"], out["used_by"]) == (50000, 0, None, [])
    assert (out["status"], out["removed"], out["production"]) == ("unknown", False, False)
    listed = (await admin_client.get(API)).json()
    assert [a["name"] for a in listed] == ["DO main"]
    assert fdo.TOKEN not in json.dumps(listed)
    assert (await admin_client.get(API, params={"provider": "proxmox"})).json() == []
    stored = await row(out["id"])
    assert stored.secret == fdo.TOKEN and stored.config["team"] is None
    [event] = await audits("provider_account.create")
    assert (event.target_type, event.target_id) == ("provider_account", out["id"])
    assert event.details == {"name": "DO main", "provider": "digitalocean", "production": False, "region": "nyc3"}

    # A token isn't needed to save; an open SSH source is shown as open.
    other = await created(admin_client, do_body(name="Spare", secret=None, ssh_sources=["0.0.0.0/0", "10.0.0.5"]))
    assert other["has_secret"] is False and other["secret_hint"] == ""
    assert other["ssh_sources"] == ["0.0.0.0/0", "10.0.0.5/32"] and other["ssh_open"] is True
    await no_secret_in_audit(fdo.TOKEN)


async def test_the_same_token_cant_serve_two_accounts(admin_client, do):
    first = await created(admin_client, do_body())
    resp = await admin_client.post(API, json=do_body(name="Second"))
    assert resp.status_code == 409
    assert resp.json() == {"detail": "This token already belongs to account DO main", "field": "secret"}
    second = await created(admin_client, do_body(name="Second", secret=TOKEN_B))
    resp = await admin_client.patch(f"{API}/{second['id']}", json={"secret": fdo.TOKEN})
    assert resp.status_code == 409 and "DO main" in resp.json()["detail"]
    assert (await row(second["id"])).secret == TOKEN_B
    # Saving an account's own token again is no change.
    assert (await admin_client.patch(f"{API}/{first['id']}", json={"secret": fdo.TOKEN})).status_code == 200


@pytest.mark.parametrize(("change", "field"), [
    ({"region": "New York"}, "region"),
    ({"ssh_sources": []}, "ssh_sources"),
    ({"ssh_sources": ["not-an-address"]}, "ssh_sources"),
    ({"ssh_sources": [f"10.0.{i}.0/24" for i in range(11)]}, "ssh_sources"),
    ({"monthly_limit_cents": 0}, "monthly_limit_cents"),
    ({"prices": {"spaces": 500}}, "prices"),
    ({"prices": {"as_of": "2026-11-01", "spaces": -1}}, "prices"),
    ({"secret": "dop v1 with spaces"}, "secret"),
    ({"name": "-bad"}, "name"),
])
async def test_do_fields_are_refused_by_name(admin_client, do, change, field):
    resp = await admin_client.post(API, json=do_body(**change))
    assert resp.status_code == 422 and resp.json()["field"] == field, resp.text
    assert await count_accounts() == 0


async def test_ssh_sources_and_fields_of_other_providers(admin_client, do):
    body = do_body()
    del body["ssh_sources"]
    assert (await admin_client.post(API, json=body)).status_code == 422  # required
    assert (await admin_client.post(API, json=do_body(url="https://x"))).status_code == 422  # not a DO field
    account = await created(admin_client, do_body())
    resp = await admin_client.patch(f"{API}/{account['id']}", json={"node": "pve1"})
    assert resp.status_code == 422 and resp.json() == {"detail": "A DigitalOcean account has no node setting",
                                                       "field": "node"}
    resp = await admin_client.patch(f"{API}/{account['id']}", json={"prices": {"as_of": "2026-11-01", "spaces": 400},
                                                                     "monthly_limit_cents": 90000})
    assert resp.status_code == 200 and resp.json()["prices"] == {"as_of": "2026-11-01", "spaces": 400}
    resp = await admin_client.patch(f"{API}/{account['id']}", json={"prices": None, "monthly_limit_cents": None})
    assert (resp.json()["prices"], resp.json()["monthly_limit_cents"]) == (None, None)
    [*_, event] = await audits("provider_account.update")
    assert event.details["changed"] == ["monthly_limit_cents", "prices"]


async def test_a_token_of_another_team_is_refused_while_environments_use_the_account(admin_client, do, monkeypatch):
    account = await created(admin_client, do_body())
    await admin_client.post(f"{API}/{account['id']}/test")  # learns the team while unused
    await add_env(account["id"], "web", team=fdo.TEAM["uuid"])
    order: list[str] = []
    real_read, real_get = provider_accounts.read_team, provider_accounts.get

    async def read_team(token):
        order.append("team")
        return await real_read(token)

    async def get(db, account_id, *, lock=False):
        if lock:
            order.append("lock")
        return await real_get(db, account_id, lock=lock)

    monkeypatch.setattr(provider_accounts, "read_team", read_team)
    monkeypatch.setattr(provider_accounts, "get", get)
    resp = await admin_client.patch(f"{API}/{account['id']}", json={"secret": TOKEN_B})
    assert resp.status_code == 409
    assert resp.json()["detail"] == ("1 environment was built in team Slipway Team; a token for Other Team can't "
                                     "manage it")
    assert order == ["team", "lock"]  # the team is read before the row is locked
    assert (await row(account["id"])).secret == fdo.TOKEN

    # A token of the same team is taken, and the team stays.
    resp = await admin_client.patch(f"{API}/{account['id']}", json={"secret": TOKEN_C})
    assert resp.status_code == 200 and resp.json()["secret_hint"] == TOKEN_C[-4:]
    assert (await row(account["id"])).config["team"]["id"] == fdo.TEAM["uuid"]
    [event] = await audits("provider_account.update")
    assert event.details["changed"] == ["token replaced"]
    await no_secret_in_audit(fdo.TOKEN, TOKEN_B, TOKEN_C)


async def test_an_environment_starting_to_use_the_account_during_a_save_answers_save_again(admin_client, do,
                                                                                         monkeypatch):
    account = await created(admin_client, do_body())
    real = provider_accounts.environments_using
    calls = {"n": 0}

    async def racing(db, account_id):
        calls["n"] += 1
        if calls["n"] == 1:  # read before the lock: nothing used it yet
            found = await real(db, account_id)
            await add_env(account["id"], "web")  # a create commits meanwhile
            return found
        return await real(db, account_id)

    monkeypatch.setattr(provider_accounts, "environments_using", racing)
    resp = await admin_client.patch(f"{API}/{account['id']}", json={"secret": TOKEN_B})
    assert resp.status_code == 409 and resp.json()["detail"] == "Save again: an environment started using this account"
    assert (await row(account["id"])).secret == fdo.TOKEN


async def test_clearing_the_token_is_refused_while_in_use(admin_client, do):
    used = await created(admin_client, do_body())
    await add_env(used["id"], "web")
    resp = await admin_client.patch(f"{API}/{used['id']}", json={"clear_secret": True})
    assert resp.status_code == 409 and resp.json() == {"detail": "web uses DO main: its token can't be cleared",
                                                       "field": "clear_secret"}
    spare = await created(admin_client, do_body(name="Spare", secret=TOKEN_B))
    resp = await admin_client.patch(f"{API}/{spare['id']}", json={"clear_secret": True})
    assert resp.status_code == 200 and (resp.json()["has_secret"], resp.json()["secret_hint"]) == (False, "")
    assert (await row(spare["id"])).secret is None
    [*_, event] = await audits("provider_account.update")
    assert event.details["changed"] == ["token cleared"]
    resp = await admin_client.patch(f"{API}/{spare['id']}", json={"clear_secret": True, "secret": TOKEN_B})
    assert resp.status_code == 422 and resp.json()["field"] == "secret"


async def test_production_flag_rules(admin_client, do):
    assert (await admin_client.post(API, json=pve_body(production=True))).status_code == 422
    prod = await created(admin_client, do_body(production=True))
    assert prod["production"] is True
    await add_env(prod["id"], "prod", production=True)
    resp = await admin_client.patch(f"{API}/{prod['id']}", json={"production": False})
    assert resp.status_code == 409 and resp.json()["field"] == "production"
    assert resp.json()["detail"] == "prod is a production environment using DO main: it stays a production account"

    plain = await created(admin_client, do_body(name="Plain", secret=TOKEN_B))
    await add_env(plain["id"], "uat")
    resp = await admin_client.patch(f"{API}/{plain['id']}", json={"production": True})
    assert resp.status_code == 409
    assert resp.json()["detail"] == ("uat uses Plain and isn't production: a production account serves only "
                                     "production environments")
    spare = await created(admin_client, do_body(name="Spare", secret=None))
    resp = await admin_client.patch(f"{API}/{spare['id']}", json={"production": True})
    assert resp.status_code == 200 and resp.json()["production"] is True


async def test_remove_is_refused_while_referenced(admin_client, do):
    account = await created(admin_client, do_body())
    await add_env(account["id"], "web")
    await add_env(account["id"], "uat", status="new")
    resp = await delete(admin_client, account["id"], "DO main")
    assert resp.status_code == 409
    assert resp.json()["detail"] == "Environments uat and web use DO main; delete them first"
    resp = await delete(admin_client, account["id"], "do main")
    assert resp.status_code == 422 and resp.json()["detail"] == "Type the account's name, DO main, exactly to confirm"
    assert await row(account["id"]) is not None


# ----------------------------------------------------------------- Test (test 34)


async def test_do_test_passes_each_check_and_remembers_the_team(admin_client, do):
    account = await created(admin_client, do_body())
    resp = await admin_client.post(f"{API}/{account['id']}/test")
    assert resp.status_code == 200, resp.text
    answer = resp.json()
    assert answer["status"] == "ok"
    names = [c["name"] for c in answer["checks"]]
    assert names == ["account", "region", "droplets", "vpcs", "databases", "spaces_keys", "certificates",
                     "load_balancers", "firewalls", "scopes"]
    assert all(c["level"] == "ok" for c in answer["checks"][:-1])
    assert answer["checks"][-1] == {"name": "scopes", "ok": True, "level": "note",
                                    "text": provider_accounts.SCOPES_NOTE}
    assert answer["facts"]["droplet_limit"] == 25 and answer["facts"]["droplet_count"] == 0
    assert answer["facts"]["team"] == {"id": fdo.TEAM["uuid"], "name": "Slipway Team"}
    reads = [r for r in do.requests if r["path"] in ("/vpcs", "/firewalls", "/spaces/keys")]
    assert reads and all(r["params"]["per_page"] == "1" for r in reads)
    assert not do.writes()

    out = (await admin_client.get(f"{API}/{account['id']}")).json()
    assert (out["status"], out["team_name"], out["checks"]) == ("ok", "Slipway Team", answer["checks"])
    assert out["last_checked_at"] is not None
    [event] = await audits("provider_account.test")
    assert event.details["status"] == "ok" and event.details["checks"][0] == {"name": "account", "level": "ok"}
    await no_secret_in_audit(fdo.TOKEN)


async def test_do_test_warns_and_fails(admin_client, do):
    account = await created(admin_client, do_body())
    do.droplet_limit = 2
    do.add_droplet(name="one")
    do.add_droplet(name="two")
    do.forbid.add("firewalls")
    answer = (await admin_client.post(f"{API}/{account['id']}/test")).json()
    checks = {c["name"]: c for c in answer["checks"]}
    assert checks["droplets"]["level"] == "warning"
    assert checks["droplets"]["text"] == ("The account has 2 droplets, at its limit of 2: DigitalOcean would refuse "
                                          "a new one")
    assert checks["firewalls"]["level"] == "error" and "can't read firewalls" in checks["firewalls"]["text"]
    assert answer["status"] == "error" and (await row(account["id"])).status == "error"

    do.forbid.clear()
    do.droplet_limit = 3
    do.regions.append({"slug": "abc1", "name": "ABC1", "available": True})
    await admin_client.patch(f"{API}/{account['id']}", json={"region": "abc1"})
    answer = (await admin_client.post(f"{API}/{account['id']}/test")).json()
    checks = {c["name"]: c for c in answer["checks"]}
    assert checks["droplets"]["level"] == "warning" and "Blue/Green needs two" in checks["droplets"]["text"]
    assert checks["region"]["level"] == "warning" and "no Spaces" in checks["region"]["text"]
    assert answer["status"] == "warning"


async def test_do_test_with_a_refused_token_and_without_one(admin_client, do):
    account = await created(admin_client, do_body())
    del do.tokens[fdo.TOKEN]
    answer = (await admin_client.post(f"{API}/{account['id']}/test")).json()
    assert [(c["name"], c["level"]) for c in answer["checks"]] == [("account", "error")]
    assert answer["checks"][0]["text"] == "DigitalOcean rejected the API token"
    spare = await created(admin_client, do_body(name="Spare", secret=None))
    answer = (await admin_client.post(f"{API}/{spare['id']}/test")).json()
    assert answer["status"] == "error" and answer["checks"][0]["name"] == "token"


async def test_a_used_accounts_test_fails_a_token_of_another_team(admin_client, do):
    account = await created(admin_client, do_body())
    await add_env(account["id"], "web", team="another-team-uuid")
    answer = (await admin_client.post(f"{API}/{account['id']}/test")).json()
    team = next(c for c in answer["checks"] if c["name"] == "team")
    assert team["level"] == "error" and "a token for Slipway Team can't manage it" in team["text"]
    assert (await row(account["id"])).config["team"] is None  # not learned while frozen elsewhere


async def test_the_unsaved_token_test_writes_nothing(admin_client, do):
    before = len(await audits())
    resp = await admin_client.post(f"{API}/test", json={"secret": fdo.TOKEN, "region": "fra1"})
    assert resp.status_code == 200
    answer = resp.json()
    assert set(answer) == {"status", "checks", "facts"} and answer["status"] == "ok"
    assert [c["name"] for c in answer["checks"]][:2] == ["account", "region"]
    assert await count_accounts() == 0 and len(await audits()) == before
    resp = await admin_client.post(f"{API}/test", json={"secret": fdo.TOKEN})
    assert "region" not in [c["name"] for c in resp.json()["checks"]]
    resp = await admin_client.post(f"{API}/test", json={"secret": "  "})
    assert resp.status_code == 422 and resp.json()["field"] == "secret"


async def test_a_new_secret_after_a_key_change_replaces_the_error(admin_client, do):
    account = await created(admin_client, do_body())
    async with get_sessionmaker()() as db:  # what rotate-encryption-key --clear-unreadable leaves
        stored = await db.get(ProviderAccount, uuid.UUID(account["id"]))
        stored.secret, stored.status = None, "error"
        stored.checks = [{"name": "secret", "ok": False, "level": "error",
                          "text": "The token couldn't be read after a key change: enter it again"}]
        await db.commit()
    resp = await admin_client.patch(f"{API}/{account['id']}", json={"secret": fdo.TOKEN})
    assert resp.status_code == 200 and (resp.json()["status"], resp.json()["checks"]) == ("unknown", [])
    assert (await admin_client.post(f"{API}/{account['id']}/test")).json()["status"] == "ok"


# --------------------------------------------------------------- catalog (test 35)


async def test_catalog_in_the_region_with_prices_and_a_ten_minute_cache(admin_client, do, monkeypatch):
    do.sizes[-1]["regions"] = ["sfo3"]  # c-2 isn't offered in nyc3
    account = await created(admin_client, do_body())
    clock = {"now": 1000.0}
    monkeypatch.setattr(provider_accounts, "monotonic", lambda: clock["now"])
    resp = await admin_client.get(f"{API}/{account['id']}/catalog")
    assert resp.status_code == 200, resp.text
    cat = resp.json()
    assert cat["region"] == "nyc3" and cat["region_has_spaces"] is True
    assert [s["slug"] for s in cat["sizes"]] == [s[0] for s in fdo.SIZES[:-1]]
    assert cat["sizes"][0] == {"slug": "s-1vcpu-1gb", "vcpus": 1, "memory": 1024, "disk": 25, "price_monthly": 6.0,
                               "description": "Basic"}
    assert cat["db_sizes"] == {"1": fdo.DB_SIZES, "2": fdo.DB_SIZES[1:], "3": fdo.DB_SIZES[1:]}
    assert cat["db_versions"] == fdo.DB_VERSIONS
    assert "nyc3" in cat["spaces"] and {r["slug"] for r in cat["regions"]} == set(fdo.REGIONS)

    def size_reads() -> int:
        return len([r for r in do.requests if r["path"] == "/sizes"])

    assert size_reads() == 1
    clock["now"] += 599
    await admin_client.get(f"{API}/{account['id']}/catalog")
    assert size_reads() == 1  # cached
    sfo = (await admin_client.get(f"{API}/{account['id']}/catalog", params={"region": "sfo3"})).json()
    assert "c-2" in [s["slug"] for s in sfo["sizes"]] and size_reads() == 2  # per region
    clock["now"] += 2
    await admin_client.get(f"{API}/{account['id']}/catalog")
    assert size_reads() == 3  # ten minutes passed
    async with get_sessionmaker()() as db:
        await provider_accounts.catalog(await db.get(ProviderAccount, uuid.UUID(account["id"])), fresh=True)
    assert size_reads() == 4  # fresh skips the cache

    resp = await admin_client.get(f"{API}/{account['id']}/catalog", params={"region": "Paris"})
    assert resp.status_code == 422 and resp.json()["field"] == "region"
    do.down = True
    resp = await admin_client.get(f"{API}/{account['id']}/catalog", params={"region": "ams3"})
    assert resp.status_code == 502 and "Couldn't reach the DigitalOcean API" in resp.json()["detail"]


async def test_catalog_is_digitalocean_only(admin_client, pve, live):
    account = await created(admin_client, pve_body())
    resp = await admin_client.get(f"{API}/{account['id']}/catalog")
    assert resp.status_code == 409 and "only DigitalOcean has a catalog" in resp.json()["detail"]


# ------------------------------------------------- in use, tombstones, lock-out (test 87)


async def test_new_and_deleting_environments_count_for_the_estimate_and_remove(admin_client, do):
    account = await created(admin_client, do_body())
    await add_env(account["id"], "web", status="new", cost=8400)
    await add_env(account["id"], "uat", status="deleting", cost=5000)
    await add_env(account["id"], "gone", status="deleted", cost=99999)
    out = (await admin_client.get(f"{API}/{account['id']}")).json()
    assert out["estimate_cents"] == 13400
    assert [u["environment"] for u in out["used_by"]] == ["uat", "web"]
    async with get_sessionmaker()() as db:
        assert await provider_accounts.estimate_cents(db, uuid.UUID(account["id"])) == 13400
    resp = await delete(admin_client, account["id"], "DO main")
    assert resp.status_code == 409
    assert resp.json()["detail"] == "Environments uat and web use DO main; delete them first"


async def test_remove_keeps_a_tombstone_when_only_deleted_environments_point_at_it(admin_client, do):
    account = await created(admin_client, do_body(monthly_limit_cents=1000))
    await add_env(account["id"], "old", status="deleted")
    resp = await delete(admin_client, account["id"], "DO main")
    assert resp.status_code == 204
    stored = await row(account["id"])
    assert (stored.secret, stored.secret_hint, stored.config, stored.name) == (None, "", {}, "DO main")
    assert stored.removed_at is not None
    out = (await admin_client.get(f"{API}/{account['id']}")).json()
    assert (out["removed"], out["has_secret"], out["region"], out["ssh_sources"]) == (True, False, None, [])
    [event] = await audits("provider_account.delete")
    assert event.details == {"name": "DO main", "provider": "digitalocean", "tombstone": True}

    resp = await admin_client.patch(f"{API}/{account['id']}", json={"name": "Again"})
    assert resp.status_code == 409 and resp.json()["detail"] == "DO main was removed: add a new account instead"
    assert (await admin_client.post(f"{API}/{account['id']}/test")).status_code == 409
    assert (await delete(admin_client, account["id"], "DO main")).status_code == 409
    resp = await admin_client.post(API, json=do_body(name="do main"))
    assert resp.status_code == 409 and "it was removed" in resp.json()["detail"]
    # The tombstone's token is gone, so the same token can serve a new account.
    await created(admin_client, do_body(name="DO new"))


async def test_remove_deletes_an_account_nothing_points_at(admin_client, do):
    account = await created(admin_client, do_body())
    assert (await delete(admin_client, account["id"], "DO main")).status_code == 204
    assert await row(account["id"]) is None
    assert (await admin_client.get(f"{API}/{account['id']}")).status_code == 404
    [event] = await audits("provider_account.delete")
    assert event.details["tombstone"] is False and event.target_id == account["id"]


async def test_ssh_sources_may_not_lock_slipway_out(admin_client, do):
    account = await created(admin_client, do_body())
    await add_env(account["id"], "web", addresses=["198.51.100.7"])
    resp = await admin_client.patch(f"{API}/{account['id']}", json={"ssh_sources": ["203.0.113.0/24"]})
    assert resp.status_code == 409 and resp.json()["field"] == "ssh_sources"
    assert resp.json()["detail"] == ("Slipway connects to web's droplets from 198.51.100.7, which these SSH sources "
                                     "leave out: Slipway would lose SSH to them, and with it backups, snapshots and "
                                     "Delete")
    resp = await admin_client.patch(f"{API}/{account['id']}", json={"ssh_sources": ["203.0.113.0/24",
                                                                                    "198.51.100.7/32"]})
    assert resp.status_code == 200 and resp.json()["ssh_sources"] == ["203.0.113.0/24", "198.51.100.7/32"]


# --------------------------------------------------- Proxmox and ESXi create (test 36)


async def test_create_without_trust_answers_the_certificate_and_writes_nothing(admin_client, pve, live):
    body = pve_body()
    del body["trust_fingerprint"]
    resp = await admin_client.post(API, json=body)
    assert resp.status_code == 409
    answer = resp.json()
    assert answer["code"] == "tls_untrusted"
    assert answer["certificate"]["fingerprint_sha256"] == fingerprint(PVE_PEM)
    assert set(answer["certificate"]) == {"fingerprint_sha256", "subject", "issuer", "not_before", "not_after", "sans"}
    assert answer["certificate"]["subject"] == "CN=pve.test"
    assert live["reads"] == [("pve.test", 8006)]
    assert await count_accounts() == 0
    assert [e for e in await audits() if e.action.startswith("provider_account.")] == []


async def test_create_with_the_matching_fingerprint_stores_the_pin_and_tests_once(admin_client, pve, live):
    out = await created(admin_client, pve_body())
    assert out["provider"] == "proxmox" and out["has_secret"] is True
    assert out["secret_hint"] == "pway"  # the token id's last 4 (slipway@pve!slipway)
    assert out["tls"]["fingerprint_sha256"] == fingerprint(PVE_PEM) and out["tls"]["subject"] == "CN=pve.test"
    assert (out["url"], out["node"], out["pool"], out["storage"], out["template_vmid"]) == (
        fp.URL, "pve1", fp.POOL, fp.STORAGE, fp.TEMPLATE_VMID)
    assert out["networks"][0]["name"] == "lan" and "secret" not in out
    stored = await row(out["id"])
    assert stored.secret == fp.TOKEN and stored.config["token_id"] == "slipway@pve!slipway"
    assert stored.tls["pem"] == tls_pin.clean_pem(PVE_PEM) and stored.tls["trusted_by"] == "admin@example.com"
    # The Test after the create's answer (phase 5 §9.1).
    assert stored.status in ("ok", "warning") and stored.last_checked_at is not None
    assert stored.facts["version"]
    assert [e.action for e in await audits()][-3:] == ["provider_account.create", "provider_account.trust",
                                                         "provider_account.test"]
    [trusted] = await audits("provider_account.trust")
    assert trusted.details == {"name": "Lab", "provider": "proxmox", "fingerprint": fingerprint(PVE_PEM),
                               "subject": "CN=pve.test", "not_after": stored.tls["not_after"]}
    await no_secret_in_audit(fp.TOKEN, fp.TOKEN_SECRET)


async def test_a_wrong_fingerprint_answers_tls_mismatch(admin_client, pve, live):
    resp = await admin_client.post(API, json=pve_body(trust_fingerprint=fingerprint(ESXI_PEM)))
    assert resp.status_code == 409
    assert resp.json()["code"] == "tls_mismatch" and resp.json()["field"] == "trust_fingerprint"
    assert resp.json()["certificate"]["fingerprint_sha256"] == fingerprint(PVE_PEM)
    resp = await admin_client.post(API, json=pve_body(trust_fingerprint="not hex"))
    assert resp.status_code == 422 and resp.json()["field"] == "trust_fingerprint"
    assert await count_accounts() == 0


async def test_a_certificate_that_cant_be_read_is_a_502(admin_client, pve, live):
    live["pems"].clear()
    resp = await admin_client.post(API, json=pve_body())
    assert resp.status_code == 502 and "couldn't connect to pve.test:8006" in resp.json()["detail"]


async def test_esxi_create_hints_set_and_tests_once(admin_client, esx, live):
    out = await created(admin_client, esxi_body())
    assert (out["provider"], out["secret_hint"], out["user"], out["resource_pool"]) == ("esxi", "set", "slipway",
                                                                                         "Resources")
    stored = await row(out["id"])
    assert stored.secret == ESXI_PASSWORD and stored.status == "ok"
    assert stored.facts == {"version": "8.0.3", "free_gb": 412.5}
    await no_secret_in_audit(ESXI_PASSWORD)


@pytest.mark.parametrize(("change", "field"), [
    ({"name": " "}, "name"),
    ({"url": "http://pve.test:8006"}, "url"),
    ({"url": "https://pve.test:8006/api2"}, "url"),
    ({"node": "pve_1!"}, "node"),
    ({"pool": "a pool"}, "pool"),
    ({"storage": "9local"}, "storage"),
    ({"template_vmid": 5}, "template_vmid"),
    ({"networks": []}, "networks"),
    ({"networks": [{**NET_PVE, "gateway": "10.0.1.1"}]}, "networks.0.gateway"),
    ({"networks": [{**NET_PVE, "vlan_tag": 5000}]}, "networks.0.vlan_tag"),
    ({"networks": [{**NET_PVE, "port_group": "VM Network"}]}, "networks.0.port_group"),
    ({"networks": [NET_PVE, {**NET_PVE, "bridge": "vmbr1"}]}, "networks.1.name"),
    ({"secret": "not-a-token"}, "secret"),
    ({"secret": None}, "secret"),
])
async def test_proxmox_clean_config_rules_answer_their_field(admin_client, pve, live, change, field):
    resp = await admin_client.post(API, json=pve_body(**change))
    assert resp.status_code == 422 and resp.json()["field"] == field, resp.text
    assert live["reads"] == []  # every field is checked before the certificate is fetched
    assert await count_accounts() == 0


@pytest.mark.parametrize(("change", "field"), [
    ({"url": "https://esxi.lan/folder"}, "url"),
    ({"user": "bad user"}, "user"),
    ({"datastore": ""}, "datastore"),
    ({"source_vm": ""}, "source_vm"),
    ({"networks": [{**NET_ESXI, "port_group": ""}]}, "networks.0.port_group"),
    ({"networks": [{**NET_ESXI, "vlan_tag": 10}]}, "networks.0.vlan_tag"),
    ({"secret": None}, "secret"),
])
async def test_esxi_clean_config_rules_answer_their_field(admin_client, esx, live, change, field):
    resp = await admin_client.post(API, json=esxi_body(**change))
    assert resp.status_code == 422 and resp.json()["field"] == field, resp.text
    assert await count_accounts() == 0


async def test_one_name_across_every_provider(admin_client, do, pve, live):
    await created(admin_client, do_body(name="Lab"))
    resp = await admin_client.post(API, json=pve_body())
    assert resp.status_code == 409 and resp.json() == {"detail": "An account named Lab already exists", "field": "name"}


# ------------------------------------------------- Proxmox and ESXi update, remove (test 37)


async def test_the_secret_is_reused_only_with_the_same_url(admin_client, pve, live):
    account = await created(admin_client, pve_body())
    resp = await admin_client.patch(f"{API}/{account['id']}", json={"storage": "local-zfs"})
    assert resp.status_code == 200 and resp.json()["storage"] == "local-zfs"
    stored = await row(account["id"])
    assert stored.secret == fp.TOKEN and stored.config["token_id"] == "slipway@pve!slipway" and stored.tls

    live["pems"][("pve2.test", 8006)] = PVE_PEM
    resp = await admin_client.patch(f"{API}/{account['id']}", json={"url": "https://pve2.test:8006"})
    assert resp.status_code == 422 and resp.json()["field"] == "secret"
    assert resp.json()["detail"] == "Enter the token again: Slipway sends it only to the address it was saved for"

    # With the token again, the URL changes and the pin is forgotten (trust again).
    resp = await admin_client.patch(f"{API}/{account['id']}", json={"url": "https://pve2.test:8006",
                                                                     "secret": fp.TOKEN})
    assert resp.status_code == 200 and resp.json()["tls"] is None and resp.json()["status"] == "unknown"
    [*_, event] = await audits("provider_account.update")
    assert "url" in event.details["changed"] and "certificate forgotten" in event.details["changed"]
    answer = (await admin_client.post(f"{API}/{account['id']}/test")).json()
    assert answer["status"] == "error" and "no certificate is trusted" in answer["checks"][0]["text"]
    resp = await admin_client.post(f"{API}/{account['id']}/trust", json={"fingerprint": fingerprint(PVE_PEM)})
    assert resp.status_code == 200 and resp.json()["tls"]["fingerprint_sha256"] == fingerprint(PVE_PEM)
    assert live["reads"][-1] == ("pve2.test", 8006)
    await no_secret_in_audit(fp.TOKEN, fp.TOKEN_SECRET)


async def test_esxi_password_is_kept_only_with_the_same_user(admin_client, esx, live):
    account = await created(admin_client, esxi_body())
    resp = await admin_client.patch(f"{API}/{account['id']}", json={"user": "root"})
    assert resp.status_code == 422 and resp.json()["field"] == "secret"
    assert "Enter the password again" in resp.json()["detail"]
    resp = await admin_client.patch(f"{API}/{account['id']}", json={"user": "root", "secret": "another-pw"})
    assert resp.status_code == 200 and resp.json()["user"] == "root"
    assert (await row(account["id"])).secret == "another-pw"
    [*_, event] = await audits("provider_account.update")
    assert "password replaced" in event.details["changed"]
    await no_secret_in_audit(ESXI_PASSWORD, "another-pw")


async def test_a_url_change_is_refused_while_a_machine_uses_the_account(admin_client, pve, live):
    account = await created(admin_client, pve_body())
    await add_machine(account["id"], "lab")
    resp = await admin_client.patch(f"{API}/{account['id']}", json={"url": "https://pve2.test:8006",
                                                                     "secret": fp.TOKEN})
    assert resp.status_code == 409 and resp.json()["detail"] == (
        "Lab has VMs (slipway-lab-blue): its URL can't change. Make another account for the new address")
    out = (await admin_client.get(f"{API}/{account['id']}")).json()
    assert out["used_by"][0] | {"environment_id": None} == {"environment": "lab", "environment_id": None,
                                                             "slot": "blue", "name": "slipway-lab-blue"}


async def test_a_used_network_cant_be_removed_or_renamed(admin_client, pve, live):
    office = {**NET_PVE, "name": "office", "bridge": "vmbr1", "subnet": "10.1.0.0/24", "gateway": "10.1.0.1",
              "pool": None}
    account = await created(admin_client, pve_body(networks=[NET_PVE, office]))
    await add_machine(account["id"], "lab")
    for networks in ([office], [{**NET_PVE, "name": "lan2"}, office]):
        resp = await admin_client.patch(f"{API}/{account['id']}", json={"networks": networks})
        assert resp.status_code == 409 and resp.json() == {"detail": "lan is used by slipway-lab-blue",
                                                           "field": "networks"}
    # Its other fields may change (machines keep their frozen copy), and an unused network can go.
    changed = {**NET_PVE, "dns_servers": ["1.1.1.1"]}
    resp = await admin_client.patch(f"{API}/{account['id']}", json={"networks": [changed]})
    assert resp.status_code == 200 and resp.json()["networks"][0]["dns_servers"] == ["1.1.1.1"]


async def test_remove_is_refused_while_a_machine_uses_the_account(admin_client, pve, live):
    account = await created(admin_client, pve_body())
    await add_machine(account["id"], "lab")
    await add_machine(account["id"], "lab2", slot="data")
    resp = await delete(admin_client, account["id"], "Lab")
    assert resp.status_code == 409
    assert resp.json()["detail"] == ("Lab has VMs: slipway-lab-blue and slipway-lab2-data. "
                                     "Delete their environments first")
    other = await created(admin_client, pve_body(name="Spare"))
    assert (await delete(admin_client, other["id"], "Spare")).status_code == 204
    assert await row(other["id"]) is None


async def test_trust_a_renewed_certificate(admin_client, pve, live, do):
    account = await created(admin_client, pve_body())
    renewed = make_pem("pve.test")
    live["pems"][("pve.test", 8006)] = renewed
    resp = await admin_client.post(f"{API}/{account['id']}/trust", json={"fingerprint": fingerprint(PVE_PEM)})
    assert resp.status_code == 409 and resp.json()["code"] == "tls_mismatch"
    assert resp.json()["certificate"]["fingerprint_sha256"] == fingerprint(renewed)
    resp = await admin_client.post(f"{API}/{account['id']}/trust",
                                   json={"fingerprint": fingerprint(renewed).replace(":", "").lower()})
    assert resp.status_code == 200 and resp.json()["tls"]["fingerprint_sha256"] == fingerprint(renewed)
    assert (await row(account["id"])).tls["pem"] == tls_pin.clean_pem(renewed)
    assert len(await audits("provider_account.trust")) == 2

    cloud = await created(admin_client, do_body())
    resp = await admin_client.post(f"{API}/{cloud['id']}/trust", json={"fingerprint": fingerprint(renewed)})
    assert resp.status_code == 409 and "pins no certificate" in resp.json()["detail"]


# ------------------------------------------------------------- Test endpoint (test 38)


async def test_proxmox_test_answers_and_stores_status_checks_and_facts(admin_client, pve, live):
    account = await created(admin_client, pve_body())
    resp = await admin_client.post(f"{API}/{account['id']}/test")
    assert resp.status_code == 200
    answer = resp.json()
    assert set(answer) == {"status", "checks", "facts"}
    assert [c["name"] for c in answer["checks"]][:2] == ["Proxmox", "Node"]
    assert all(set(c) == {"name", "ok", "level", "text"} for c in answer["checks"])
    assert {"version", "storage_type", "free_gb"} <= set(answer["facts"])
    stored = await row(account["id"])
    assert (stored.status, stored.checks, stored.facts) == (answer["status"], answer["checks"], answer["facts"])


async def test_esxi_test_answers_and_stores_its_facts(admin_client, esx, live, monkeypatch):
    account = await created(admin_client, esxi_body())
    answer = (await admin_client.post(f"{API}/{account['id']}/test")).json()
    assert answer["status"] == "ok" and answer["facts"] == {"version": "8.0.3", "free_gb": 412.5}
    assert [c["name"] for c in answer["checks"]] == ["api", "licence", "datastore", "network:lan", "resource_pool",
                                                     "seed"]

    def refused(_account):
        raise MachineError("ESXi refused the user name or password. Check them in Settings → Integrations.")

    monkeypatch.setattr(esxi, "session", refused)
    answer = (await admin_client.post(f"{API}/{account['id']}/test")).json()
    assert answer == {"status": "error", "facts": {}, "checks": [
        {"name": "connect", "ok": False, "level": "error",
         "text": "ESXi refused the user name or password. Check them in Settings → Integrations."}]}
    assert (await row(account["id"])).facts == {}


async def test_redactions_name_every_secret(admin_client, do, pve, live):
    cloud = await row((await created(admin_client, do_body()))["id"])
    lab = await row((await created(admin_client, pve_body()))["id"])
    assert provider_accounts.redactions(cloud) == [fdo.TOKEN]
    assert provider_accounts.redactions(lab) == [fp.TOKEN, fp.TOKEN_SECRET]


async def test_a_name_taken_during_the_save_answers_409(admin_client, do, monkeypatch):
    await created(admin_client, do_body(name="Twin"))

    async def free(db, name, *, except_id=None):
        return None  # the check ran before the other save committed

    monkeypatch.setattr(provider_accounts, "_check_name_free", free)
    resp = await admin_client.post(API, json=do_body(name="Twin", secret=TOKEN_B))
    assert resp.status_code == 409 and resp.json() == {"detail": "An account named Twin already exists",
                                                       "field": "name"}
    assert await count_accounts() == 1
