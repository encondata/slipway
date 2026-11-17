"""The host contract phases 4 and 5 share (P4 §3.3, P5 §3.6, D18, M4; plan Decisions 6-9).

P4 test 23's host half: ``ssh.HostNotBuilt`` from ``SSHTarget.from_host`` for planned and creating hosts (not
with ``building=True``), never an ``SSHError``, and the poller skipping them. P5 test 50's check_host half:
``check_host`` refuses an unbuilt provider host unless called with ``building=True``, and never pins one.
Then ``set_phase``, ``owned_by``, ``owned_host_refusal`` (each action), ``address_holder`` (each column) and
``planned_host``.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from slipway.db.session import get_sessionmaker
from slipway.models import AuditEvent, Environment, Host, Instance, Machine, ProviderAccount, ProviderKind, Repository
from slipway.services import cloudinit, hosts, ssh

READY_KEY = ssh.generate_keypair("host-key")[1]


async def _adds(*rows):
    async with get_sessionmaker()() as db:
        db.add_all(rows)
        await db.commit()
    return rows


async def _repo() -> uuid.UUID:
    (repo,) = await _adds(Repository(github_id=1, full_name="acme/web", owner="acme", name="web",
                                     html_url="https://github.com/acme/web"))
    return repo.id


async def _env(name: str, repo_id: uuid.UUID, **kw) -> Environment:
    (env,) = await _adds(Environment(name=name, repository_id=repo_id, branch="main", **{"data_mode": "slot", **kw}))
    return env


def _provider_host(env: Environment | None, slot: str, provider: str, phase: str, *, host_key: str | None = None,
                   hostname: str | None = None) -> Host:
    host = hosts.planned_host(env.name if env else "lab", slot, provider=provider, hostname=hostname)
    host.owner_environment_id = env.id if env else None
    hosts.set_phase(host, phase)
    if host_key:
        host.host_key, host.host_key_fingerprint = host_key, ssh.fingerprint(host_key)
    return host


async def _get(host_id: uuid.UUID) -> Host:
    async with get_sessionmaker()() as db:
        return await db.get(Host, host_id)


def _probe(calls: list[ssh.SSHTarget], *, presented: str = READY_KEY):
    async def probe(target):
        calls.append(target)
        return ssh.ProbeResult(host_key=presented, fingerprint=ssh.fingerprint(presented), os_info="Ubuntu 24.04",
                               cpus=2, cpu_percent=5.0, mem_total_mb=2048, mem_percent=20.0,
                               docker_version="27.3.1", docker_error=None, containers_running=0)
    return probe


# ------------------------------------------------------------------ HostNotBuilt (P4 test 23)


async def test_from_host_refuses_a_host_that_isnt_built():
    assert not issubclass(ssh.HostNotBuilt, ssh.SSHError) and issubclass(ssh.HostNotBuilt, Exception)
    env = await _env("prod", await _repo(), provider="ssh")
    for phase in ("planned", "creating", "gone"):
        host = _provider_host(env, "blue", "digitalocean", phase, host_key=READY_KEY)
        with pytest.raises(ssh.HostNotBuilt) as caught:
            ssh.SSHTarget.from_host(host)
        assert str(caught.value) == "slipway-prod-blue isn't built yet: deploy prod to build it"
        assert not isinstance(caught.value, ssh.SSHError)
        # Only a provider's prepare passes building=True: then the target is made, with the key pinned.
        target = ssh.SSHTarget.from_host(host, building=True)
        assert (target.hostname, target.username, target.pinned_host_key) == (
            "slipway-prod-blue.invalid", "slipway", READY_KEY)
    vm = _provider_host(env, "green", "proxmox", "ready", host_key=READY_KEY, hostname="192.168.1.51")
    assert ssh.SSHTarget.from_host(vm).hostname == "192.168.1.51"
    # A host added by hand is always built, saved or not (an unsaved row's provider is None until the insert).
    for plain in (Host(name="h", hostname="10.0.0.1", username="deploy"),
                  Host(name="h", hostname="10.0.0.1", username="deploy", provider="ssh", provider_state={})):
        assert ssh.host_is_built(plain) and ssh.SSHTarget.from_host(plain).hostname == "10.0.0.1"


async def test_the_poller_skips_hosts_that_arent_built(monkeypatch):
    env = await _env("prod", await _repo())
    plain = Host(name="a-plain", hostname="10.0.0.1", username="deploy", host_key=READY_KEY)
    unpinned = Host(name="b-unpinned", hostname="10.0.0.2", username="deploy")
    creating = _provider_host(env, "blue", "digitalocean", "creating", host_key=READY_KEY)
    gone = _provider_host(env, "green", "digitalocean", "gone", host_key=READY_KEY)
    planned_vm = _provider_host(env, "data", "proxmox", "planned", hostname="192.168.1.52")
    other = await _env("lab", env.repository_id)
    ready_vm = _provider_host(other, "blue", "proxmox", "ready", host_key=READY_KEY, hostname="192.168.1.50")
    await _adds(plain, unpinned, creating, gone, planned_vm, ready_vm)
    calls: list[ssh.SSHTarget] = []
    monkeypatch.setattr(hosts.ssh, "probe", _probe(calls))
    await hosts.poll_once()
    assert sorted(t.hostname for t in calls) == ["10.0.0.1", "192.168.1.50"]
    for row in (creating, gone, planned_vm):
        assert (await _get(row.id)).last_checked_at is None


# ------------------------------------------------------------------ check_host (P5 test 50)


async def test_check_host_refuses_an_unbuilt_provider_host_and_never_pins_one(monkeypatch):
    env = await _env("lab", await _repo())
    creating = _provider_host(env, "blue", "proxmox", "creating", host_key=READY_KEY, hostname="192.168.1.50")
    unpinned = _provider_host(env, "green", "proxmox", "creating", hostname="192.168.1.51")
    plain = Host(name="tower", hostname="10.0.0.9", username="root")
    await _adds(creating, unpinned, plain)
    calls: list[ssh.SSHTarget] = []
    monkeypatch.setattr(hosts.ssh, "probe", _probe(calls))

    async with get_sessionmaker()() as db:
        host = await db.get(Host, creating.id)
        with pytest.raises(ssh.HostNotBuilt, match="slipway-lab-blue isn't built yet: deploy lab to build it"):
            await hosts.check_host(db, host)
    assert calls == [] and (await _get(creating.id)).last_checked_at is None

    # The machines core's prepare fills Docker's version after bootstrap, before the host is ready.
    async with get_sessionmaker()() as db:
        checked = await hosts.check_host(db, await db.get(Host, creating.id), building=True)
    assert [t.pinned_host_key for t in calls] == [READY_KEY]
    assert (checked.status, checked.docker_version, checked.host_key) == ("healthy", "27.3.1", READY_KEY)

    # A provider host with no pinned key isn't probed at all, let alone pinned on first use.
    async with get_sessionmaker()() as db:
        checked = await hosts.check_host(db, await db.get(Host, unpinned.id), building=True)
    assert len(calls) == 1
    assert (checked.status, checked.host_key) == ("error", None)
    assert checked.last_error == ("slipway-lab-green has no pinned host key. Slipway pins it itself when it "
                                  "builds the machine: deploy again")

    # Once ready, the check runs without building, and the key stays the one prepare pinned.
    async with get_sessionmaker()() as db:
        row = await db.get(Host, creating.id)
        hosts.set_phase(row, "ready")
        await db.commit()
    async with get_sessionmaker()() as db:
        await hosts.check_host(db, await db.get(Host, creating.id))
    assert (await _get(creating.id)).host_key == READY_KEY

    # A host added by hand is still pinned on first contact, as in phase 3.
    async with get_sessionmaker()() as db:
        checked = await hosts.check_host(db, await db.get(Host, plain.id))
    assert checked.host_key == READY_KEY
    async with get_sessionmaker()() as db:
        pinned = list(await db.scalars(select(AuditEvent.target_id).where(AuditEvent.action == "host.key_pinned")))
    assert [str(t) for t in pinned] == [str(plain.id)]


async def test_check_host_on_a_provider_host_never_writes_the_probed_key(monkeypatch):
    """Even if a probe of a provider host came back (a stand-in probe that ignores the pin), its key is not
    written: only the provider's prepare writes a provider host's key."""
    env = await _env("lab", await _repo())
    host = _provider_host(env, "blue", "esxi", "ready", host_key=READY_KEY, hostname="192.168.1.50")
    await _adds(host)
    async with get_sessionmaker()() as db:
        row = await db.get(Host, host.id)
        row.host_key = None  # a hand edit
        await db.commit()
    calls: list[ssh.SSHTarget] = []
    monkeypatch.setattr(hosts.ssh, "probe", _probe(calls))
    async with get_sessionmaker()() as db:
        checked = await hosts.check_host(db, await db.get(Host, host.id))
    assert calls == [] and checked.host_key is None and checked.status == "error"


# ------------------------------------------------------------------ set_phase, owned_by


async def test_set_phase_writes_a_new_dict_that_is_saved():
    env = await _env("prod", await _repo())
    host = _provider_host(env, "blue", "digitalocean", "planned")
    await _adds(host)
    async with get_sessionmaker()() as db:
        row = await db.get(Host, host.id)
        before = row.provider_state
        state = hosts.set_phase(row, "creating", droplet_name="slipway-prod-blue", region="ams3")
        assert state is row.provider_state and state is not before
        await db.commit()
    assert (await _get(host.id)).provider_state == {"phase": "creating", "droplet_name": "slipway-prod-blue",
                                                     "region": "ams3"}
    async with get_sessionmaker()() as db:
        row = await db.get(Host, host.id)
        hosts.set_phase(row, "ready", public_ip="203.0.113.10", region=None)
        await db.commit()
    saved = await _get(host.id)
    assert saved.provider_state == {"phase": "ready", "droplet_name": "slipway-prod-blue", "public_ip": "203.0.113.10"}
    assert saved.is_built and hosts.phase_of(saved) == "ready"
    with pytest.raises(ValueError, match="isn't a host phase"):
        hosts.set_phase(saved, "booting")
    assert hosts.phase_of(Host(name="h", hostname="x", username="u")) is None


async def test_owned_by():
    repo = await _repo()
    prod, uat = await _env("prod", repo), await _env("uat", repo)
    host = _provider_host(prod, "blue", "digitalocean", "ready")
    assert hosts.owned_by(prod, host) and hosts.owned_by(prod.id, host)
    assert not hosts.owned_by(uat, host) and not hosts.owned_by(prod, None)
    assert not hosts.owned_by(prod, Host(name="h", hostname="x", username="u"))


# ------------------------------------------------------------------ owned_host_refusal (D18, Decision 7)


VM_TEXTS = {
    "edit": "slipway-lab-blue is a VM Slipway made for lab; change it on the environment",
    "placing": "slipway-lab-blue is a VM of environment lab; only its slots run there",
    "delete": "slipway-lab-blue goes when lab removes its blue slot",
    "move_root": "slipway-lab-blue is a VM Slipway made for lab; its deploy root stays where Slipway set it",
    "check": "Slipway pins slipway-lab-blue's key itself when it makes the VM: deploy to blue",
    "reset_key": "slipway-lab-blue's key was pinned from Lab. If the VM was rebuilt by hand, use Forget the VM on lab",
}
DROPLET_TEXTS = {
    "edit": "slipway-prod-green is a droplet Slipway made for prod; change it on the environment",
    "placing": "slipway-prod-green is a droplet of environment prod; only its slots run there",
    "delete": "slipway-prod-green goes when prod removes its green slot",
    "move_root": "slipway-prod-green is a droplet Slipway made for prod; its deploy root stays where Slipway set it",
    "check": "Slipway pins slipway-prod-green's key itself when it makes the droplet: deploy to green",
    "reset_key": ("slipway-prod-green's key was made by Slipway with the droplet for prod; "
                  "Slipway changes it only when it builds the droplet again"),
}
EDIT_FIELDS = ("hostname", "proxy_address", "lan_address", "port", "username", "deploy_root", "credentials",
               "auth_method", "private_key", "key_passphrase", "password")


def _expected(action: str, texts: dict[str, str]) -> str:
    if action in EDIT_FIELDS:
        return texts["edit"]
    if action in hosts.PLACING_ACTIONS:
        return texts["placing"]
    return texts[action]


@pytest.mark.parametrize("provider,texts,names", [
    ("proxmox", VM_TEXTS, {"owner": "lab", "slot": "blue", "account": "Lab"}),
    ("digitalocean", DROPLET_TEXTS, {"owner": "prod", "slot": "green"}),
])
def test_owned_host_refusal_answers_every_action(provider, texts, names):
    env = Environment(id=uuid.uuid4(), name=names["owner"])
    host = _provider_host(env, names["slot"], provider, "planned")
    actions = [*EDIT_FIELDS, "instance", "placement", "environment", "add_slot", "claim", "delete", "move_root",
               "check", "reset_key"]
    assert set(actions) | {"label", "description", "address"} == set(hosts.ACTIONS)
    for action in actions:
        assert hosts.owned_host_refusal(host, action=action, **names) == _expected(action, texts), action
    # The label and the description stay editable.
    assert hosts.owned_host_refusal(host, action="label", **names) is None
    assert hosts.owned_host_refusal(host, action="description", **names) is None
    assert hosts.edit_refusal(host, {"label", "description", "name"}, **names) is None
    assert hosts.edit_refusal(host, ["description", "lan_address"], **names) == texts["edit"]
    # Check host is allowed once the host is built.
    hosts.set_phase(host, "ready")
    assert hosts.owned_host_refusal(host, action="check", **names) is None
    # A host added by hand is never refused here, whatever the action.
    plain = Host(name="tower", hostname="10.0.0.9", username="root")
    assert all(hosts.owned_host_refusal(plain, action=a) is None for a in hosts.ACTIONS)
    with pytest.raises(ValueError):
        hosts.owned_host_refusal(host, action="rename")


def test_owned_host_refusal_without_names_reads_the_host_row():
    host = _provider_host(Environment(id=uuid.uuid4(), name="lab"), "data", "esxi", "ready")
    assert hosts.owned_host_refusal(host, action="delete") == "slipway-lab-data goes when lab is deleted"
    assert hosts.owned_host_refusal(host, action="reset_key") == (
        "slipway-lab-data's key was pinned from its account. If the VM was rebuilt by hand, use Forget the VM on lab")


async def test_owned_host_problem_reads_the_environment_slot_and_account():
    repo = await _repo()
    lab = await _env("lab", repo)
    prod = await _env("prod", repo)
    (account,) = await _adds(ProviderAccount(provider=ProviderKind.PROXMOX, name="Lab", secret="slipway@pve!t=u"))
    vm_host = _provider_host(lab, "blue", "proxmox", "ready", host_key=READY_KEY, hostname="192.168.1.50")
    droplet = _provider_host(prod, "green", "digitalocean", "creating")
    droplet.label = "renamed by hand"
    await _adds(vm_host, droplet)
    await _adds(
        Machine(environment_id=lab.id, host_id=vm_host.id, account_id=account.id, slot="blue", provider="proxmox",
                name="slipway-lab-blue", spec={"node": "pve1"}, network={"name": "lan", "address": "192.168.1.50"},
                size={"cores": 2, "memory_mb": 2048, "disk_gb": 20}),
        Instance(name="prod green", slug="prod-green", branch="main", host_id=droplet.id, repository_id=repo,
                 env={}, ports=[], volumes=[], build_source="app", environment_id=prod.id, slot="green"),
    )
    async with get_sessionmaker()() as db:
        vm = await db.get(Host, vm_host.id)
        assert await hosts.owned_host_problem(db, vm, action="reset_key") == VM_TEXTS["reset_key"]
        assert await hosts.owned_host_problem(db, vm, action="label") is None
        row = await db.get(Host, droplet.id)
        assert await hosts.owned_host_problem(db, row, action="hostname") == DROPLET_TEXTS["edit"]
        assert await hosts.owned_host_problem(db, row, action="check") == DROPLET_TEXTS["check"]
        plain = Host(name="tower", hostname="10.0.0.9", username="root")
        assert await hosts.owned_host_problem(db, plain, action="delete") is None


# ------------------------------------------------------------------ address_holder (Decision 8)


async def test_address_holder_checks_every_address_column():
    env = await _env("prod", await _repo())
    by_name = Host(name="by-name", hostname="10.0.0.5", username="u")
    by_proxy = Host(name="by-proxy", hostname="nas.lan", username="u", proxy_address="10.0.0.6")
    by_lan = Host(name="by-lan", hostname="nas2.lan", username="u", lan_address="10.0.0.7")
    mixed = Host(name="mixed", hostname="Tower.LAN", username="u")
    own = _provider_host(env, "blue", "digitalocean", "ready", hostname="203.0.113.10")
    await _adds(by_name, by_proxy, by_lan, mixed, own)
    async with get_sessionmaker()() as db:
        for address, holder in (("10.0.0.5", "by-name"), ("10.0.0.6", "by-proxy"), ("10.0.0.7", "by-lan"),
                                ("Tower.LAN", "mixed"), ("203.0.113.10", own.name)):
            assert (await hosts.address_holder(db, address)).name == holder, address
        assert await hosts.address_holder(db, "10.0.0.8") is None
        assert await hosts.address_holder(db, "10.0.0.5", except_host_id=by_name.id) is None
        assert (await hosts.address_holder(db, "10.0.0.5", except_host_id=own.id)).name == "by-name"
        # A droplet's own environment's hosts don't count against it (P4 §9.2 step 5).
        assert await hosts.address_holder(db, "203.0.113.10", except_environment_id=env.id) is None
        assert (await hosts.address_holder(db, "10.0.0.6", except_environment_id=env.id)).name == "by-proxy"


# ------------------------------------------------------------------ planned_host (Decision 9)


async def test_planned_host_fields():
    host = hosts.planned_host("prod", "blue", provider="digitalocean", description="Blue slot of prod")
    assert (host.name, host.hostname, host.port, host.username, host.label, host.description) == (
        "slipway-prod-blue", "slipway-prod-blue.invalid", 22, cloudinit.GUEST_USER, "prod", "Blue slot of prod")
    assert cloudinit.GUEST_USER == "slipway"
    assert (host.provider, host.provider_state, host.deploy_root, host.auth_method) == (
        "digitalocean", {"phase": "planned"}, "/opt/slipway", "key")
    assert host.host_key is None and host.host_key_fingerprint is None and host.owner_environment_id is None
    assert host.public_key.endswith(" slipway@slipway-prod-blue")
    assert ssh.public_key_from_private(host.private_key) == host.public_key
    assert not host.is_built and host.id is None

    vm = hosts.planned_host("lab", "data", provider="proxmox", hostname="192.168.1.52")
    assert (vm.name, vm.hostname) == ("slipway-lab-data", "192.168.1.52")
    assert vm.private_key != host.private_key

    with pytest.raises(ValueError, match="1 to 64 characters"):
        hosts.planned_name("x" * 60, "blue")
    with pytest.raises(ValueError, match="not ssh"):
        hosts.planned_host("prod", "blue", provider="ssh")

    # Saved, it is an ordinary host row; a second environment of that name clashes by name.
    env = await _env("prod", await _repo())
    host.owner_environment_id = env.id
    await _adds(host)
    async with get_sessionmaker()() as db:
        assert await hosts.name_clash(db, "slipway-prod-blue") == (
            "A host named slipway-prod-blue already exists: rename it, or pick another environment name")
        assert await hosts.name_clash(db, "slipway-prod-green") is None
        saved = await db.get(Host, host.id)
        assert (saved.status, saved.metrics, saved.provider_id, saved.is_pinned) == ("unknown", {}, None, False)
