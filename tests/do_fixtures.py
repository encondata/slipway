"""Builders for DigitalOcean tests (phase 4 §20.1): an account row, an environment placed on DigitalOcean with
its planned droplet hosts, slot instances and the host-less managed data owner, all inserted directly (Create
itself is S18's). Also ``Cloud``: FakeDigitalOcean, FakeSpaces over the same Spaces keys, and fake droplets
that appear as hosts of an address-keyed ``MultiRemote`` the moment DigitalOcean gives them an address, each
presenting the host key its user-data delivered.

Import from S09b, S12, S14a, S14b, S15, S18, S19 and S23::

    cloud = do_fixtures.Cloud(tmp_path, monkeypatch)
    env = await do_fixtures.make_do_env()
    ctx = cloud.context(env, "blue")
    await do_provision.prepare(ctx, read_manifest=cloud.read_manifest)
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from slipway.db.session import get_sessionmaker
from slipway.models import Environment, Host, Instance, ProviderAccount, Repository
from slipway.services import digitalocean, do_provision, do_rules, hosts, resources, spaces, ssh
from tests import fake_digitalocean as fdo
from tests.conftest import make_user
from tests.fake_hosts import MultiRemote
from tests.fake_spaces import FakeSpaces

ROOT = Path(__file__).resolve().parents[1]
DO_YML = (ROOT / "docs/examples/serversherpa.slipway.yml").read_text()
TOKEN = fdo.TOKEN
SSH_SOURCES = ["198.51.100.0/24"]  # MultiRemote's Slipway address (198.51.100.7) is inside
SECRETS = {"POSTGRES_PASSWORD": "pg-" + "1" * 61, "SPACES_SECRET_KEY": "sp-" + "2" * 61,
           "SS_JWT_SECRET": "jwt-" + "3" * 60, "SS_TOTP_ENCRYPTION_KEY": "totp-key-" + "A" * 35 + "=",
           "SS_PASSWORD_PEPPER": "pepper-" + "4" * 57, "SS_WIKI_SERVICE_TOKEN": "wiki-" + "5" * 59}
SHA = "0123456789abcdef0123456789abcdef01234567"


async def make_account(name: str = "do-main", *, token: str | None = TOKEN, region: str = "nyc3",
                       ssh_sources: list[str] | None = None, production: bool = False,
                       team: dict[str, str] | None = None, monthly_limit_cents: int | None = None) -> uuid.UUID:
    """A DigitalOcean account row (as provider_accounts.create would leave it, without the API call)."""
    async with get_sessionmaker()() as db:
        row = ProviderAccount(provider="digitalocean", name=name, production=production, secret=token,
                              secret_hint=(token or "")[-4:],
                              config={"region": region, "ssh_sources": list(SSH_SOURCES if ssh_sources is None
                                                                            else ssh_sources),
                                      "monthly_limit_cents": monthly_limit_cents, "prices": None, "team": team},
                              status="ok")
        db.add(row)
        await db.commit()
        return row.id


def routes(name: str, domain: str | None = None) -> list[dict[str, Any]]:
    """``env.hostnames`` for the ServerSherpa example's default services (every route follows the active slot)."""
    domain = domain or f"{name}.example.com"
    out = []
    for service, port, health in (("api", 8000, "/healthz"), ("portal", 8091, "/"), ("kiosk", 8090, "/"),
                                  ("wiki", 8096, "/healthz")):
        out.append({"hostname": f"{service}.{domain}", "service": service, "container": port, "follows": "active",
                    "health": health})
    return out


@dataclass
class DoEnv:
    env_id: uuid.UUID
    name: str
    account_id: uuid.UUID
    user_id: uuid.UUID
    ids: dict[str, uuid.UUID] = field(default_factory=dict)  # slot -> instance id (data: the owner)
    host_ids: dict[str, uuid.UUID] = field(default_factory=dict)  # app slot -> planned host id


async def make_do_env(
    *, name: str = "shop", slots: tuple[str, ...] = ("blue", "green"), account_id: uuid.UUID | None = None,
    region: str = "nyc3", droplet_size: str = "s-1vcpu-1gb", db_size: str = "db-s-1vcpu-1gb", db_nodes: int = 1,
    db_version: str = "16", droplets: int | None = None, status: str = "new", production: bool = False,
    cloud: dict[str, Any] | None = None, manifest_file: str = "slipway.yml",
) -> DoEnv:
    """An environment with placement ``digitalocean`` (data_mode managed, traffic do_lb), its confirmed plan and
    cost, a planned host per app slot (``hosts.planned_host``, owned by the environment), the slot instances on
    them and the host-less data owner."""
    if account_id is None:
        account_id = await make_account()
    user = await make_user(f"admin-{uuid.uuid4().hex[:6]}@example.com")
    plan = do_rules.make_plan(droplets=droplets or len(slots), droplet_size=droplet_size, db_size=db_size,
                              db_nodes=db_nodes, db_version=db_version)
    stored = {"region": region, "droplet_size": droplet_size, "droplet_image": do_rules.DROPLET_IMAGE,
              "db_size": db_size, "db_nodes": db_nodes, "db_version": db_version, "acme_staging": False,
              "vpc_range": None, "lb_ip": None, "edge": None, "slipway_addresses": [], "certificate": None,
              "plan": plan, "cost": {"total_cents": 4700, "lines": [], "as_of": do_rules.PRICES["as_of"],
                                      "confirmed_by_id": str(user.id), "confirmed_at": "2026-11-16T00:00:00+00:00"}}
    stored.update(cloud or {})
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=uuid.uuid4().int % 10**9, full_name=f"acme/serversherpa-{name}", owner="acme",
                          name=f"serversherpa-{name}",
                          html_url="https://github.com/acme/serversherpa", detected_config={})
        env = Environment(name=name, repository=repo, branch="main", data_mode="managed", manifest_file=manifest_file,
                          app_settings={"STACK_DOMAIN": f"{name}.example.com"}, app_secrets=dict(SECRETS), env={},
                          traffic={"switch": "do_lb", "dns": {"provider": "cloudflare", "address": None,
                                                               "proxied": False}},
                          status=status, created_by_id=user.id, hostnames=routes(name), provider="digitalocean",
                          provider_account_id=account_id, cloud=stored, production=production)
        db.add(env)
        await db.flush()
        out = DoEnv(env_id=env.id, name=name, account_id=account_id, user_id=user.id)
        for slot in slots:
            host = hosts.planned_host(name, slot, provider="digitalocean",
                                      description=f"Droplet Slipway makes for {name}'s {slot} slot")
            host.owner_environment_id = env.id
            db.add(host)
            await db.flush()
            inst = Instance(name=f"{name} {slot}", slug=f"{name}-{slot}", branch="main", host_id=host.id,
                            repository=repo, env={}, ports=[], volumes=[], build_source="app",
                            environment_id=env.id, slot=slot, manifest_file=manifest_file)
            db.add(inst)
            await db.flush()
            out.ids[slot], out.host_ids[slot] = inst.id, host.id
        owner = Instance(name=f"{name} data", slug=f"{name}-data", branch="main", host_id=None, repository=repo,
                         env={}, ports=[], volumes=[], build_source="app", environment_id=env.id, slot="data",
                         manifest_file=manifest_file)
        db.add(owner)
        await db.flush()
        out.ids["data"] = owner.id
        await db.commit()
    return out


async def env_row(env: DoEnv) -> Environment:
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        assert row is not None
        return row


async def host_row(env: DoEnv, slot: str) -> Host:
    async with get_sessionmaker()() as db:
        row = await db.get(Host, env.host_ids[slot])
        assert row is not None
        return row


async def rows(env: DoEnv, kind: str | None = None, *, include_pending: bool = True) -> list[Any]:
    from sqlalchemy import select

    from slipway.models import Resource
    async with get_sessionmaker()() as db:
        stmt = select(Resource).where(Resource.environment_id == env.env_id)
        if kind is not None:
            stmt = stmt.where(Resource.kind == kind)
        found = list(await db.scalars(stmt.order_by(Resource.kind, Resource.name)))
    return [r for r in found if include_pending or not resources.is_pending(r)]


class Cloud:
    """The fakes one DigitalOcean test needs, installed: FakeDigitalOcean (its clock drives every wait, the
    pending rows' times included), FakeSpaces reading the same Spaces keys, and the droplets as fake hosts."""

    def __init__(self, tmp_path: Path, monkeypatch: Any, *, fake: fdo.FakeDigitalOcean | None = None) -> None:
        self.tmp, self.monkeypatch = tmp_path, monkeypatch
        self.do = fdo.use_fake(monkeypatch, fake or fdo.FakeDigitalOcean())
        self.spaces = FakeSpaces(self.do.spaces_keys)
        monkeypatch.setattr(spaces, "transport_factory", self.spaces.transport)
        monkeypatch.setattr(spaces, "sleep", self._no_wait)
        # The pending rows' sent_at comes from resources' clock: the fake's, so the 60 s rules run instantly.
        monkeypatch.setattr(resources, "utcnow", lambda: dt.datetime.fromtimestamp(self.do.now, dt.UTC))
        self.multi = MultiRemote(tmp_path, names={})
        marker = tmp_path / "slipway-ready"
        marker.write_text("")
        monkeypatch.setattr(do_provision, "READY_MARKER", str(marker))
        self.marker = marker
        # Per droplet name: presents another key (wrong_key), refuses its first n connects while it boots
        # (booting), drops every connection from Slipway (firewalled), extra environment for its shell (host_env).
        self.wrong_key: set[str] = set()
        self.booting: dict[str, int] = {}
        self.firewalled: set[str] = set()
        self.host_env: dict[str, dict[str, str]] = {}
        self.manifest_text = DO_YML
        self.log: list[str] = []
        self.sent: list[ssh.SSHTarget] = []

    @staticmethod
    async def _no_wait(_seconds: float) -> None:
        return None

    async def say(self, line: str) -> None:
        self.log.append(line)

    async def read_manifest(self) -> str:
        return self.manifest_text

    def droplet_host(self, droplet: dict[str, Any]):
        """The fake host of a droplet, added the first time Slipway connects to its address."""
        public, _private = digitalocean.droplet_ips(droplet)
        assert public
        if public not in self.multi:
            key = self.do.host_keys.get(droplet["id"])
            if droplet["name"] in self.wrong_key or key is None:  # by droplet name
                _priv, key = ssh.generate_keypair("root@impostor")
            host = self.multi.add(f"{droplet['name']}-{droplet['id']}", public, host_key=key)
            host.refuse = self.booting.get(droplet["name"], 0)
            host.firewalled = droplet["name"] in self.firewalled
            host.env.update(self.host_env.get(droplet["name"], {}))
        return self.multi[public]

    def connect(self, target: ssh.SSHTarget):
        """``ProvisionContext.connect``: droplets appear as hosts of the MultiRemote when first reached."""
        self.sent.append(target)
        for droplet in self.do.droplets.values():
            public, _private = digitalocean.droplet_ips(droplet)
            if public and public == target.hostname:
                self.droplet_host(droplet)
        return self.multi.connect(target)

    def context(self, env: DoEnv, slot: str | None = "blue", *, deployment_id: uuid.UUID | None = None,
                **fields: Any) -> do_provision.ProvisionContext:
        return do_provision.ProvisionContext(
            environment_id=env.env_id, instance_id=env.ids[slot] if slot else None, deployment_id=deployment_id,
            say=self.say, connect=self.connect, **fields)

    def writes(self) -> list[tuple[str, str]]:
        return [(r["method"], r["path"]) for r in self.do.writes()]

    def transport(self, handler: Any) -> None:
        """Route the DigitalOcean client through ``handler`` (an async wrapper around the fake's)."""
        self.monkeypatch.setattr(digitalocean, "transport_factory", lambda: httpx.MockTransport(handler))

