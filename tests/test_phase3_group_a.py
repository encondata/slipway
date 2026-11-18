"""Phase 3 Group A wiring: the slices built side by side (manifest roles, the environment and resource
models, the Cloudflare client and plan, Switchyard owners) used together with real rows, the way S5 and
S6 will use them. Each slice has its own tests; these check only that their names and shapes fit."""

from __future__ import annotations

import uuid
from pathlib import Path

import httpx
import pytest

from slipway.db.session import get_sessionmaker
from slipway.models import Environment, Host, Repository
from slipway.services import cloudflare, manifest, resources, switchyard
from tests.fake_cloudflare import TOKEN, ZONE, FakeCloudflare

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = (ROOT / "docs/examples/serversherpa.slipway.yml").read_text()


async def _env(name: str = "uat") -> Environment:
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=7, full_name="acme/web", owner="acme", name="web",
                          html_url="https://github.com/acme/web")
        db.add(repo)
        await db.flush()
        env = Environment(name=name, repository_id=repo.id, branch="main", data_mode="server")
        db.add(env)
        await db.commit()
        return env


async def test_an_environment_row_owns_switchyard_hosts():
    env = await _env()
    owner = switchyard.Owner.of(env)
    assert (owner.kind, owner.id, owner.name) == ("environment", env.id, "uat")
    # §10.3's marker, word for word.
    assert switchyard.marker(env) == (
        f"Managed by Slipway: environment uat ({env.id}). "
        "Domains, upstreams and TLS mode are set from Slipway when traffic moves."
    )
    body = switchyard.desired(None, switchyard.Target("uat.example.com", "auto", "10.0.0.11", 18000), env)
    assert switchyard.owned_by(body, env) and switchyard.describe_owner(body) == "environment uat"
    assert not switchyard.owned_by(body, uuid.uuid4())  # no instance owns it
    assert body["upstreams"][0]["host"] == "10.0.0.11" and body["upstreams"][0]["port"] == 18000


@pytest.fixture
def fake_cf(monkeypatch):
    fake = FakeCloudflare()
    monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(fake.handle))
    return fake


async def test_dns_plans_over_recorded_resource_rows(fake_cf):
    env = await _env()
    zid = fake_cf.add_zone()
    comment = cloudflare.comment_for(env.name, env.id)
    ours = fake_cf.add_record(zid, "A", "uat.example.com", "203.0.113.7", comment=comment)
    stale = fake_cf.add_record(zid, "A", "old.example.com", "203.0.113.7", comment=comment)
    for rec in (ours, stale):
        await resources.record(env.id, cloudflare.PROVIDER, cloudflare.KIND, rec["id"], rec["name"], "created",
                               {"zone_id": zid, "type": "A", "content": rec["content"], "proxied": False})
    assert cloudflare.is_ours(comment, env.id)

    wanted = {"uat.example.com": {"content": "203.0.113.7", "proxied": False},
              "spaces.uat.example.com": {"content": "203.0.113.7", "proxied": False}}
    async with get_sessionmaker()() as db:
        rows = await resources.owned(db, env.id, cloudflare.PROVIDER, cloudflare.KIND)
    async with cloudflare.CloudflareClient(TOKEN) as cf:
        assert await cf.zone_id(ZONE) == zid
        by_name, wildcards = await cloudflare.read_state(cf, zid, ZONE, wanted, rows)
    plan = cloudflare.plan_dns(wanted, by_name, wildcards, rows, env.id, zone=ZONE)
    statuses = {c.name: c.status for c in plan.changes}
    assert statuses == {"uat.example.com": "ok", "spaces.uat.example.com": "create", "old.example.com": "delete"}
    assert plan.blockers == [] and fake_cf.writes() == []  # planning only reads
    row_ids = {r.name: r.id for r in rows}
    assert plan.by_name()["uat.example.com"].row_id == row_ids["uat.example.com"]


async def test_the_data_servers_clients_come_from_the_hosts_client_address():
    multi = Host(name="blue", hostname="blue.lan", port=22, username="deploy", proxy_address="10.0.0.11",
                 lan_address="192.168.5.11")
    plain = Host(name="green", hostname="10.0.0.12", port=22, username="deploy")  # upstream: the hostname
    assert (multi.client_address, plain.client_address) == ("192.168.5.11", "10.0.0.12")
    plan = manifest.plan(
        manifest.parse(EXAMPLE), template="SS_SPACES_BUCKET=serversherpa\n", chosen=None,
        settings={"STACK_DOMAIN": "uat.example.com", "STACK_PROXY_IP": "10.0.0.2"},
        host_ports={"spaces": 9000, "db": 5433}, env={}, role="server",
        secrets={k: "x" * 40 for k in ("POSTGRES_PASSWORD", "SPACES_SECRET_KEY", "SS_JWT_SECRET",
                                        "SS_TOTP_ENCRYPTION_KEY", "SS_PASSWORD_PEPPER", "SS_WIKI_SERVICE_TOKEN")},
        builtins=dict(slug="uat-data", name="uat data", release="/srv/r", env_dir="/srv/s", sha="0" * 40,
                      sha12="0" * 12, host="10.0.0.13", deployment="0123abcd", environment="uat", slot="data"),
        server_values={"host": "10.0.0.13", "clients": [multi.client_address, plain.client_address]},
    )
    assert plan.env["STACK_DB_ALLOW"] == "10.0.0.12,192.168.5.11"
