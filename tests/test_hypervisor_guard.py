"""Phase 5 test 35 and phase 4 §20.1: ``no_real_hypervisors`` blocks every real seam, and it is autouse.

The ``machines`` module comes in a later slice, so the seam tests put stand-ins in ``sys.modules``
under the module names. Tests that install a guard by hand are marked ``own_guard``, so the autouse
guard (tests/conftest.py) doesn't wrap the seams first.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import types
from pathlib import Path

import httpx
import pytest

from slipway.services import acme, cloudflare, digitalocean, github, hsl, spaces, switchyard, tls_pin, traffic

from tests import hypervisor_guard
from tests.hypervisor_guard import Guard, RealHypervisorCall, no_real_hypervisors  # noqa: F401  (the fixture)

REPO = Path(__file__).resolve().parents[1]


def standin(name: str, **attrs):
    """A module called ``name`` whose functions look like its own (``__module__`` is the module)."""
    module = types.ModuleType(name)
    for attr, value in attrs.items():
        if callable(value) and hasattr(value, "__module__"):
            try:
                value.__module__ = name
            except (AttributeError, TypeError):
                pass
        setattr(module, attr, value)
    return module


@pytest.fixture
def standins(monkeypatch):
    calls: list[tuple] = []

    def _spawn(argv, *, cwd=None, env=None):
        calls.append(("spawn", tuple(argv)))
        return "process"

    def _smart_connect(**kwargs):
        calls.append(("esxi", kwargs))

    async def tcp_open(host, port, timeout=3.0):
        calls.append(("tcp", host, port))
        return False

    async def resolve(name, timeout=2.0):
        calls.append(("resolve", name))
        return []

    modules = {
        hypervisor_guard.TERRAFORM: standin(hypervisor_guard.TERRAFORM, _spawn=_spawn),
        hypervisor_guard.ESXI: standin(hypervisor_guard.ESXI, _smart_connect=_smart_connect),
        hypervisor_guard.MACHINES: standin(hypervisor_guard.MACHINES, tcp_open=tcp_open, resolve=resolve),
        hypervisor_guard.PROXMOX: standin(hypervisor_guard.PROXMOX, transport_factory=lambda: None),
    }
    # A lambda defined here belongs to this test module; make it the stand-in's own, as in proxmox.py.
    modules[hypervisor_guard.PROXMOX].transport_factory.__module__ = hypervisor_guard.PROXMOX
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    return types.SimpleNamespace(calls=calls, **{name.rsplit(".", 1)[1]: m for name, m in modules.items()})


# ----------------------------------------------------------------------------- Guard


@pytest.mark.own_guard
async def test_each_seam_is_blocked(standins, monkeypatch):
    guard = Guard().install(monkeypatch)
    assert sorted(guard.installed) == sorted([
        "slipway.services.terraform._spawn", "slipway.services.esxi._smart_connect",
        "slipway.services.machines.tcp_open", "slipway.services.machines.resolve",
        "slipway.services.tls_pin.read_certificate", "slipway.services.proxmox.transport_factory",
        "asyncssh.connect", "asyncssh.get_server_host_key",
        *(f"{name}.transport_factory" for name, _ in hypervisor_guard.CLOUDS),
    ])

    with pytest.raises(RealHypervisorCall, match="only fake-terraform may run"):
        standins.terraform._spawn(["/usr/bin/terraform", "plan"])
    with pytest.raises(RealHypervisorCall, match="ESXi sign-in"):
        standins.esxi._smart_connect(host="esxi.lan")
    with pytest.raises(RealHypervisorCall, match="TCP probe"):
        await standins.machines.tcp_open("10.0.0.12", 22)
    with pytest.raises(RealHypervisorCall, match="name lookup"):
        await standins.machines.resolve("pve.lan")
    with pytest.raises(RealHypervisorCall, match="certificate fetch from 10.0.0.2"):
        await tls_pin.read_certificate("10.0.0.2", 8006)
    with pytest.raises(RealHypervisorCall, match="certificate fetch from pve.lan"):
        await tls_pin.read_certificate(host="pve.lan", port=8006)
    with pytest.raises(RealHypervisorCall, match="Proxmox connection"):
        standins.proxmox.transport_factory()
    # Nothing real ran.
    assert standins.calls == []
    assert len(guard.blocked) == 7

    with pytest.raises(pytest.fail.Exception, match="tried to reach something real") as caught:
        guard.verify()
    assert "fake-terraform" in str(caught.value) and "10.0.0.2" in str(caught.value)
    guard.verify()  # reported once


@pytest.mark.own_guard
async def test_allowed_calls_go_through(standins, monkeypatch, tmp_path):
    guard = Guard().install(monkeypatch)
    fake = tmp_path / "bin" / "fake-terraform"
    assert standins.terraform._spawn([str(fake), "version", "-json"]) == "process"
    assert standins.terraform._spawn(argv=[fake, "init"]) == "process"
    assert standins.calls == [("spawn", (str(fake), "version", "-json")), ("spawn", (fake, "init"))]
    # 127.0.0.1 is reached for real: nothing listens on this port, so tls_pin's own error comes back.
    with pytest.raises(tls_pin.TlsPinError, match="couldn't connect"):
        await tls_pin.read_certificate("127.0.0.1", 9, timeout=2)
    assert guard.blocked == []
    guard.verify()


@pytest.mark.own_guard
async def test_async_spawn_is_guarded(monkeypatch):
    async def _spawn(argv):
        return argv

    monkeypatch.setitem(sys.modules, hypervisor_guard.TERRAFORM, standin(hypervisor_guard.TERRAFORM, _spawn=_spawn))
    guard = Guard().install(monkeypatch)
    module = sys.modules[hypervisor_guard.TERRAFORM]
    assert await module._spawn(["/x/fake-terraform"]) == ["/x/fake-terraform"]
    with pytest.raises(RealHypervisorCall):
        await module._spawn(["terraform"])
    assert len(guard.blocked) == 1
    guard.blocked.clear()


@pytest.mark.own_guard
def test_replaced_seams_are_left_alone(standins, monkeypatch):
    def fake_connect(**kwargs):
        return "fake session"

    async def fake_probe(host, port, timeout=3.0):
        return True

    standins.esxi._smart_connect = fake_connect
    standins.machines.tcp_open = fake_probe
    guard = Guard().install(monkeypatch)
    assert standins.esxi._smart_connect is fake_connect
    assert standins.machines.tcp_open is fake_probe
    assert "slipway.services.esxi._smart_connect" not in guard.installed
    assert "slipway.services.machines.resolve" in guard.installed
    # A second guard doesn't wrap the first one's wrappers again.
    again = Guard().install(monkeypatch)
    assert again.installed == []


@pytest.mark.own_guard
def test_missing_modules_are_skipped(monkeypatch):
    for name in (hypervisor_guard.TERRAFORM, hypervisor_guard.ESXI, hypervisor_guard.MACHINES, hypervisor_guard.PROXMOX,
                 *(cloud for cloud, _ in hypervisor_guard.CLOUDS)):
        monkeypatch.setitem(sys.modules, name, None)  # import of <name> halted: as if it didn't exist
    guard = Guard().install(monkeypatch)
    assert guard.installed == ["slipway.services.tls_pin.read_certificate", "asyncssh.connect",
                               "asyncssh.get_server_host_key"]
    assert hypervisor_guard._module("slipway.services.no_such_module_here") is None


def test_a_module_that_fails_to_import_is_not_skipped(monkeypatch, tmp_path):
    (tmp_path / "guard_broken_module.py").write_text("import a_dependency_that_is_not_installed_xyz\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    with pytest.raises(ModuleNotFoundError, match="a_dependency_that_is_not_installed_xyz"):
        hypervisor_guard._module("guard_broken_module")


# --------------------------------------------------------------------------- fixture


@pytest.mark.own_guard
async def test_fixture_installs_the_guard(standins, no_real_hypervisors):
    assert isinstance(no_real_hypervisors, Guard)
    with pytest.raises(RealHypervisorCall):
        await standins.machines.tcp_open("10.0.0.12", 22)
    assert len(no_real_hypervisors.blocked) == 1
    no_real_hypervisors.blocked.clear()  # so this test's own teardown passes


def test_a_swallowed_blocked_call_fails_the_test_at_teardown(tmp_path):
    """End to end in a separate pytest run: the code under test catches the error, the test still fails."""
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    (tmp_path / "test_inner.py").write_text(textwrap.dedent(f"""\
        import importlib.util
        import sys
        import types

        spec = importlib.util.spec_from_file_location("inner_guard", {str(Path(hypervisor_guard.__file__))!r})
        guard_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard_module)
        no_real_hypervisors = guard_module.no_real_hypervisors

        machines = types.ModuleType("slipway.services.machines")
        def tcp_open(host, port):
            return False
        tcp_open.__module__ = machines.__name__
        machines.tcp_open = tcp_open
        sys.modules[machines.__name__] = machines

        def test_swallows(no_real_hypervisors):
            try:
                machines.tcp_open("10.0.0.12", 22)
            except Exception:
                pass  # the code under test hides the failure

        def test_clean(no_real_hypervisors):
            pass
        """))
    env = {**os.environ, "PYTHONPATH": str(REPO)}
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no:asyncio", "test_inner.py"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120,
    )
    out = result.stdout + result.stderr
    assert result.returncode != 0, out
    assert "2 passed, 1 error" in out, out
    assert "ERROR at teardown of test_swallows" in out, out
    assert "a real TCP probe (machines.tcp_open)" in out, out


# ------------------------------------------------------------------- the cloud seams

CLOUD_MODULES = {
    "slipway.services.digitalocean": (digitalocean, "a real DigitalOcean request"),
    "slipway.services.spaces": (spaces, "a real Spaces request"),
    "slipway.services.acme": (acme, "a real ACME request"),
    "slipway.services.cloudflare": (cloudflare, "a real Cloudflare request"),
    "slipway.services.switchyard": (switchyard, "a real Switchyard request"),
    "slipway.services.traffic": (traffic, "a real public check request"),
    "slipway.services.github": (github, "a real GitHub request"),
    "slipway.services.hsl": (hsl, "a real HackSpaceLabs request"),
}


def test_the_guard_lists_every_cloud_seam():
    assert {name for name, _ in hypervisor_guard.CLOUDS} == set(CLOUD_MODULES)


@pytest.mark.own_guard
@pytest.mark.parametrize("name", sorted(CLOUD_MODULES))
async def test_each_cloud_seam_fails_on_a_request_not_on_building(name, monkeypatch):
    module, what = CLOUD_MODULES[name]
    original = module.transport_factory
    guard = Guard().install(monkeypatch)
    assert f"{name}.transport_factory" in guard.installed
    assert module.transport_factory is not original
    # The traffic seam takes whether the certificate is verified; the others take nothing.
    transport = module.transport_factory(True) if module is traffic else module.transport_factory()
    assert isinstance(transport, httpx.MockTransport)
    assert guard.blocked == []  # making the transport is harmless
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(RealHypervisorCall, match=what):
            await client.get("https://api.example.test/v2/account")
    assert len(guard.blocked) == 1 and "api.example.test" in guard.blocked[0]
    assert f"{name.rsplit('.', 1)[1]}.transport_factory" in guard.blocked[0]
    with pytest.raises(pytest.fail.Exception, match=what):
        guard.verify()


@pytest.mark.own_guard
async def test_building_the_real_clients_does_not_raise(monkeypatch):
    guard = Guard().install(monkeypatch)
    clients = [
        digitalocean.DigitalOceanClient("dop_v1_not-a-real-token"),
        cloudflare.CloudflareClient("not-a-real-token"),
        switchyard.SwitchyardClient(switchyard.SwitchyardConfig(url="https://switchyard.example.test",
                                                                 api_key="not-a-real-key")),
    ]
    for c in clients:
        await c.__aexit__(None, None, None)
    assert guard.blocked == []
    # A request through one of them is what fails.
    async with cloudflare.CloudflareClient("not-a-real-token") as cf:
        with pytest.raises(RealHypervisorCall, match="a real Cloudflare request to api.cloudflare.com"):
            await cf._client.get("/zones")
    guard.blocked.clear()


@pytest.mark.own_guard
def test_a_replaced_cloud_seam_is_left_alone(monkeypatch):
    def fake_factory():
        return httpx.MockTransport(lambda request: httpx.Response(200, json={}))

    monkeypatch.setattr(cloudflare, "transport_factory", fake_factory)
    guard = Guard().install(monkeypatch)
    assert cloudflare.transport_factory is fake_factory
    assert "slipway.services.cloudflare.transport_factory" not in guard.installed
    assert "slipway.services.switchyard.transport_factory" in guard.installed


def test_the_guard_is_on_without_being_asked_for(request):
    """P5 test 35's autouse half: this test names no guard fixture, and every seam is still closed."""
    for name, (module, _) in CLOUD_MODULES.items():
        assert getattr(module.transport_factory, hypervisor_guard.GUARD_MARK, False), name
    from slipway.services import esxi, proxmox, terraform

    for module, attr in ((terraform, "_spawn"), (esxi, "_smart_connect"), (proxmox, "transport_factory"),
                         (tls_pin, "read_certificate")):
        assert getattr(getattr(module, attr), hypervisor_guard.GUARD_MARK, False), (module.__name__, attr)
    # The autouse fixture made the same guard the named fixtures return.
    guard = request.getfixturevalue("no_real_hypervisors")
    assert request.getfixturevalue("no_real_clouds") is guard
    assert f"{hypervisor_guard.PROXMOX}.transport_factory" in guard.installed


async def test_an_unfaked_cloud_call_fails_the_test(request):
    """A request through a client nobody faked raises, and the guard remembers it for teardown."""
    guard = request.getfixturevalue("no_real_hypervisors")
    async with switchyard.SwitchyardClient(switchyard.SwitchyardConfig(url="https://switchyard.example.test",
                                                                        api_key="not-a-real-key")) as client:
        with pytest.raises(RealHypervisorCall, match="a real Switchyard request to switchyard.example.test"):
            await client._client.get("/api/v1/routes")
    assert len(guard.blocked) == 1
    assert "not-a-real-key" not in guard.blocked[0]
    guard.blocked.clear()  # so this test's own teardown passes
