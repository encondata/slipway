"""Builders for phase 5's VM tests: accounts, environments with planned VMs, and machine contexts.

* ``proxmox_account`` and ``esxi_account`` write a ``provider_accounts`` row with a trusted certificate (the
  FakeProxmox URL and token; an ESXi URL and password), one network ``lan`` (10.0.0.0/24, pool .100-.150) and
  a passing Test.
* ``vm_env`` writes an environment, its planned VM hosts and machines through ``machines.plan`` (so every row is
  as create writes it) and the slot instances on those hosts.
* ``context`` loads a ``MachineContext`` for one machine, with a log that collects its lines.
* ``quiet_network`` replaces ``machines.resolve`` and ``machines.tcp_open`` (the guard refuses the real ones):
  names resolve as the test says, and only the addresses it lists answer the TCP probe.

S11b, S12, S13, S16, S17, S18 and S22 import these.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from sqlalchemy import select

from slipway.db.session import get_sessionmaker
from slipway.models import Environment, Instance, Machine, ProviderAccount, Repository, User
from slipway.services import machines, ssh, tls_pin
from tests import fake_proxmox as fp

ESXI_URL = "https://esxi.test"
ESXI_PASSWORD = "esx-Secret-pw-42"

LAN_PVE = {"name": "lan", "bridge": "vmbr0", "vlan_tag": None, "subnet": "10.0.0.0/24", "gateway": "10.0.0.1",
           "dns_servers": ["10.0.0.53"], "pool": {"first": "10.0.0.100", "last": "10.0.0.150"}}
LAN_ESXI = {"name": "lan", "port_group": "VM Network", "subnet": "10.0.0.0/24", "gateway": "10.0.0.1",
            "dns_servers": ["10.0.0.53"], "pool": {"first": "10.0.0.100", "last": "10.0.0.150"}}
# What the two account URLs resolve to in quiet_network.
API_ADDRESSES = {"pve.test": ["10.0.0.2"], "esxi.test": ["10.0.0.3"]}


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


def trusted(pem: str) -> dict[str, Any]:
    return {**tls_pin.describe(pem), "trusted_at": dt.datetime.now(dt.UTC).isoformat(), "trusted_by": "admin@example.com"}


async def _add(row: Any) -> Any:
    async with get_sessionmaker()() as db:
        db.add(row)
        await db.commit()
        return row


async def proxmox_account(*, name: str = "lab", networks: list[dict[str, Any]] | None = None,
                          storage_type: str = "lvmthin", secret: str | None = fp.TOKEN, pem: str | None = PVE_PEM,
                          **config: Any) -> ProviderAccount:
    base = {"url": fp.URL, "node": fp.NODES[0], "pool": fp.POOL, "storage": fp.STORAGE,
            "template_vmid": fp.TEMPLATE_VMID, "token_id": fp.TOKEN.split("=", 1)[0],
            "networks": [dict(n) for n in (networks or [LAN_PVE])]}
    return await _add(ProviderAccount(
        provider="proxmox", name=name, secret=secret, secret_hint=(secret or "")[-4:] if secret else "",
        config={**base, **config}, tls=trusted(pem) if pem else None, status="ok", checks=[],
        facts={"version": "9.0.3", "storage_type": storage_type, "storage_content": "images,rootdir", "free_gb": 500,
               "template_ciupgrade": False},
    ))


async def esxi_account(*, name: str = "esx-01", networks: list[dict[str, Any]] | None = None,
                       secret: str | None = ESXI_PASSWORD, pem: str | None = ESXI_PEM, **config: Any) -> ProviderAccount:
    base = {"url": ESXI_URL, "user": "slipway", "datastore": "datastore1", "resource_pool": "Resources",
            "source_vm": "ubuntu-2404-seed", "networks": [dict(n) for n in (networks or [LAN_ESXI])]}
    return await _add(ProviderAccount(
        provider="esxi", name=name, secret=secret, secret_hint="set" if secret else "", config={**base, **config},
        tls=trusted(pem) if pem else None, status="ok", checks=[], facts={"version": "8.0.3", "free_gb": 412.5},
    ))


class SimpleFreeze:
    """A ``freeze`` for tests that plan VMs without the real provider: the spec as each provider writes it."""

    def freeze(self, account: ProviderAccount, network: dict[str, Any]) -> dict[str, Any]:
        config = account.config or {}
        if account.provider == "proxmox":
            return {"node": config.get("node"), "pool": config.get("pool"), "storage": config.get("storage"),
                    "storage_type": (account.facts or {}).get("storage_type"), "file_format": None,
                    "template_vmid": config.get("template_vmid"), "bridge": network.get("bridge"),
                    "vlan_tag": network.get("vlan_tag")}
        return {"api_host": tls_pin.url_host_port(config.get("url") or ESXI_URL)[0],
                "datastore": config.get("datastore"), "resource_pool": config.get("resource_pool"),
                "source_vm": config.get("source_vm"), "port_group": network.get("port_group")}


@dataclass
class VmEnv:
    env_id: uuid.UUID
    user_id: uuid.UUID
    account_id: uuid.UUID
    repo_id: uuid.UUID
    name: str
    machines: dict[str, uuid.UUID] = field(default_factory=dict)  # slot -> machine id
    hosts: dict[str, uuid.UUID] = field(default_factory=dict)  # slot -> host id
    instances: dict[str, uuid.UUID] = field(default_factory=dict)  # slot -> instance id
    addresses: dict[str, str] = field(default_factory=dict)  # slot -> the VM's address


async def a_user(email: str | None = None) -> User:
    from tests.conftest import make_user

    return await make_user(email or f"maintainer-{uuid.uuid4().hex[:6]}@example.com")


async def vm_env(account: ProviderAccount, *, name: str = "uat", mode: str = "slot",
                 slots: tuple[str, ...] = ("blue",), addresses: dict[str, str] | None = None,
                 size: dict[str, Any] | None = None, provider: Any = None, deploy_roots: dict[str, str] | None = None,
                 user: User | None = None, network: str = "lan") -> VmEnv:
    """An environment of ``account``'s VMs: ``slots`` (plus ``data`` when ``mode`` is ``server``), each planned at
    ``addresses[slot]`` (``auto`` when missing) through ``machines.plan``, with its slot instance."""
    user = user or await a_user()
    wanted = [*slots, *(["data"] if mode == "server" and "data" not in slots else [])]
    async with get_sessionmaker()() as db:
        repo = await db.scalar(select(Repository).where(Repository.full_name == "acme/web"))
        if repo is None:
            repo = Repository(github_id=42, full_name="acme/web", owner="acme", name="web",
                              html_url="https://github.com/acme/web", detected_config={})
            db.add(repo)
        env = Environment(name=name, repository=repo, branch="main", data_mode=mode,
                          app_settings={"APP_DOMAIN": f"{name}.example.com"}, app_secrets={}, env={},
                          traffic={"switch": "none", "dns": None}, created_by_id=user.id, hostnames=[])
        db.add(env)
        await db.flush()
        acct = await db.get(ProviderAccount, account.id)
        out = VmEnv(env_id=env.id, user_id=user.id, account_id=account.id, repo_id=repo.id, name=name)
        for slot in wanted:
            host, machine = await machines.plan(
                db, env, slot, acct, network, (addresses or {}).get(slot, "auto"), size, user,
                provider=provider or SimpleFreeze(), deploy_root=(deploy_roots or {}).get(slot),
            )
            inst = Instance(name=f"{name} {slot}", slug=f"{name}-{slot}", branch="main", host_id=host.id,
                            repository=repo, env={}, ports=[], volumes=[], build_source="app",
                            environment_id=env.id, slot=slot)
            db.add(inst)
            await db.flush()
            out.machines[slot], out.hosts[slot], out.instances[slot] = machine.id, host.id, inst.id
            out.addresses[slot] = machine.network["address"]
        await db.commit()
    return out


class Lines(list):
    """A ``say`` that keeps every line."""

    async def __call__(self, line: str) -> None:
        self.append(line)


async def no_sleep(_seconds: float) -> None:
    await asyncio.sleep(0)


async def context(machine_id: uuid.UUID, *, connect: Any, deployment_id: uuid.UUID | None = None,
                  user_id: uuid.UUID | None = None, say: Any = None, sleep: Any = no_sleep) -> machines.MachineContext:
    async with get_sessionmaker()() as db:
        ctx = await machines.load_context(
            db, machine_id=machine_id, deployment_id=deployment_id, user_id=user_id,
            say=say if say is not None else Lines(),
            hide=ssh.Redactor(), connect=connect, sleep=sleep,
        )
    assert ctx is not None
    return ctx


async def machine_row(machine_id: uuid.UUID) -> Machine | None:
    async with get_sessionmaker()() as db:
        return await db.get(Machine, machine_id)


@dataclass
class Network:
    """What ``quiet_network`` answers: names to addresses, and which addresses answer SSH."""

    names: dict[str, list[str]] = field(default_factory=lambda: dict(API_ADDRESSES))
    open: set[str] = field(default_factory=set)
    resolved: list[str] = field(default_factory=list)
    probed: list[tuple[str, int]] = field(default_factory=list)


def quiet_network(monkeypatch: Any, *, names: dict[str, list[str]] | None = None,
                  open_ports: set[str] | None = None) -> Network:
    net = Network(names={**API_ADDRESSES, **(names or {})}, open=set(open_ports or ()))

    async def resolve(name: str) -> list[str]:
        net.resolved.append(name)
        return list(net.names.get(name, []))

    async def tcp_open(host: str, port: int, timeout: float = machines.PROBE_TIMEOUT) -> bool:
        net.probed.append((host, port))
        return host in net.open

    monkeypatch.setattr(machines, "resolve", resolve)
    monkeypatch.setattr(machines, "tcp_open", tcp_open)
    return net
