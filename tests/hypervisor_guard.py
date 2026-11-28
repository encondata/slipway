"""The ``no_real_hypervisors`` fixture: no test reaches a real hypervisor, cloud, Terraform, TLS, SSH or TCP endpoint.

Phase 5 talks to Proxmox (httpx), Terraform (a subprocess), ESXi (pyvmomi) and new VMs (TCP probes,
name lookups, certificate fetches). Phase 4 talks to DigitalOcean, Spaces and Let's Encrypt, and
phase 3 to Cloudflare, Switchyard and the public check of a switch. Every one of those has a single
seam, and the guard closes each:

* ``slipway.services.terraform._spawn`` runs only a program named ``fake-terraform``;
* ``slipway.services.esxi._smart_connect``, ``slipway.services.machines.tcp_open`` and
  ``slipway.services.machines.resolve`` fail unless the test replaced them;
* ``slipway.services.tls_pin.read_certificate`` reaches only 127.0.0.1;
* ``slipway.services.proxmox.transport_factory`` raises unless the test replaced it (with an httpx
  ``MockTransport``, as switchyard's tests do);
* the ``transport_factory`` of ``digitalocean``, ``spaces``, ``acme``, ``cloudflare``, ``switchyard``,
  ``traffic`` (the public check), ``github`` and ``registry`` (used when a caller passes no ``transport``) returns an
  ``httpx.MockTransport`` that raises on the first request. Building a client stays harmless; only
  sending something fails;
* ``asyncssh.connect`` and ``asyncssh.get_server_host_key``, which ``slipway.services.ssh`` dials
  through (``ssh.probe`` and ``hosts.check_host`` included), reach only loopback, where the tests' own
  SSH servers listen. A name that can't be encoded never leaves the machine, so it passes too (the
  tests of invalid host names).

Each patch is applied only when its module exists, so the guard works before those modules are
written. A seam a test (or an earlier fixture) already replaced is left alone. A blocked call raises
``RealHypervisorCall`` and is also remembered, and the test fails at teardown even when the code
under test caught the error (Sirdar's ``api/tests/conftest.py`` does the same).

``tests/conftest.py`` makes it autouse, so every test has it without asking. Test modules may still
name it (``pytestmark = pytest.mark.usefixtures("no_real_hypervisors")``); it is the same guard.
``no_real_clouds`` is another name for it. A test marked ``own_guard`` gets no autouse guard (the
guard's own tests, which install one by hand).
"""

from __future__ import annotations

import functools
import importlib
import inspect
import os
from collections.abc import Callable, Iterator
from typing import Any

import asyncssh
import httpx
import pytest

TERRAFORM = "slipway.services.terraform"
ESXI = "slipway.services.esxi"
MACHINES = "slipway.services.machines"
TLS_PIN = "slipway.services.tls_pin"
PROXMOX = "slipway.services.proxmox"
# The client modules whose ``transport_factory`` defaults to a real httpx transport, and what a
# request through each would have been.
CLOUDS = (
    ("slipway.services.digitalocean", "a real DigitalOcean request"),
    ("slipway.services.spaces", "a real Spaces request"),
    ("slipway.services.acme", "a real ACME request"),
    ("slipway.services.cloudflare", "a real Cloudflare request"),
    ("slipway.services.switchyard", "a real Switchyard request"),
    ("slipway.services.traffic", "a real public check request"),
    ("slipway.services.github", "a real GitHub request"),
    ("slipway.services.registry", "a real container registry request"),
)
# What ``slipway.services.ssh`` dials through; each reaches only loopback in tests.
SSH_DIALS = (("connect", "a real SSH connection"), ("get_server_host_key", "a real SSH host key read"))
LOOPBACK = ("127.0.0.1", "::1", "localhost")

FAKE_TERRAFORM = "fake-terraform"
GUARD_MARK = "__slipway_hypervisor_guard__"
LOCAL_HOSTS = ("127.0.0.1",)


class RealHypervisorCall(RuntimeError):
    """A test tried to reach something real; the guard stopped it."""


def _module(name: str) -> Any | None:
    """The module, or None when it doesn't exist (yet). A module that exists but fails to import raises."""
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as exc:
        if exc.name and (exc.name == name or name.startswith(exc.name + ".")):
            return None
        raise


def _is_original(module: Any, attr: str) -> bool:
    """Whether ``module.attr`` is still the module's own (nobody replaced it, and no guard wrapped it).

    Only ``__module__`` is compared: ``transport_factory`` is a lambda in the client modules, and a
    test's replacement is defined in the test's own module.
    """
    value = getattr(module, attr, None)
    if value is None or getattr(value, GUARD_MARK, False):
        return False
    return getattr(value, "__module__", None) == module.__name__


def _program(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    """The program a ``_spawn`` call would start, however its arguments are passed."""
    for key in ("argv", "args", "cmd", "command", "program"):
        if key in kwargs:
            value = kwargs[key]
            break
    else:
        value = args[0] if args else ""
    if isinstance(value, list | tuple):
        value = value[0] if value else ""
    return os.fspath(value) if isinstance(value, str | os.PathLike) else str(value)


def _host(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    return str(kwargs.get("host", args[0] if args else ""))


def _never_leaves(host: str) -> bool:
    """Whether a dial to ``host`` stays on this machine: loopback, or a name the resolver can't even encode."""
    if host in LOOPBACK:
        return True
    try:
        host.encode("idna")
    except UnicodeError:
        return True
    return False


class Guard:
    """The patches and the record of blocked calls; ``no_real_hypervisors`` installs one per test."""

    def __init__(self) -> None:
        self.blocked: list[str] = []
        self.installed: list[str] = []

    def _block(self, what: str) -> RealHypervisorCall:
        self.blocked.append(what)
        return RealHypervisorCall(f"Blocked in tests: {what}. Replace it with a fake.")

    def _wrap(self, original: Callable[..., Any], allowed: Callable[[tuple, dict], str | None]) -> Callable[..., Any]:
        """``original`` when ``allowed`` returns None for the call's arguments, else a blocked call."""
        if inspect.iscoroutinefunction(original):
            @functools.wraps(original)
            async def guarded_async(*args: Any, **kwargs: Any) -> Any:
                refusal = allowed(args, kwargs)
                if refusal:
                    raise self._block(refusal)
                return await original(*args, **kwargs)
            setattr(guarded_async, GUARD_MARK, True)
            return guarded_async

        @functools.wraps(original)
        def guarded(*args: Any, **kwargs: Any) -> Any:
            refusal = allowed(args, kwargs)
            if refusal:
                raise self._block(refusal)
            return original(*args, **kwargs)
        setattr(guarded, GUARD_MARK, True)
        return guarded

    def _deny(self, original: Callable[..., Any], what: str) -> Callable[..., Any]:
        return self._wrap(original, lambda args, kwargs: what)

    def install(self, monkeypatch: pytest.MonkeyPatch) -> Guard:
        terraform = _module(TERRAFORM)
        if terraform is not None and _is_original(terraform, "_spawn"):
            def spawn_allowed(args: tuple, kwargs: dict) -> str | None:
                program = _program(args, kwargs)
                if os.path.basename(program) == FAKE_TERRAFORM:
                    return None
                return f"starting {program or 'a process'} through terraform._spawn (only {FAKE_TERRAFORM} may run)"
            monkeypatch.setattr(terraform, "_spawn", self._wrap(terraform._spawn, spawn_allowed))
            self.installed.append(f"{TERRAFORM}._spawn")

        esxi = _module(ESXI)
        if esxi is not None and _is_original(esxi, "_smart_connect"):
            monkeypatch.setattr(esxi, "_smart_connect", self._deny(esxi._smart_connect, "a real ESXi sign-in (esxi._smart_connect)"))
            self.installed.append(f"{ESXI}._smart_connect")

        machines = _module(MACHINES)
        if machines is not None:
            for attr, what in (("tcp_open", "a real TCP probe (machines.tcp_open)"),
                               ("resolve", "a real name lookup (machines.resolve)")):
                if _is_original(machines, attr):
                    monkeypatch.setattr(machines, attr, self._deny(getattr(machines, attr), what))
                    self.installed.append(f"{MACHINES}.{attr}")

        tls_pin = _module(TLS_PIN)
        if tls_pin is not None and _is_original(tls_pin, "read_certificate"):
            def fetch_allowed(args: tuple, kwargs: dict) -> str | None:
                host = _host(args, kwargs)
                if host in LOCAL_HOSTS:
                    return None
                return f"a certificate fetch from {host} (tls_pin.read_certificate reaches only 127.0.0.1 in tests)"
            monkeypatch.setattr(tls_pin, "read_certificate", self._wrap(tls_pin.read_certificate, fetch_allowed))
            self.installed.append(f"{TLS_PIN}.read_certificate")

        proxmox = _module(PROXMOX)
        if proxmox is not None and _is_original(proxmox, "transport_factory"):
            def no_transport(*args: Any, **kwargs: Any) -> Any:
                raise self._block("a real Proxmox connection (set proxmox.transport_factory to a MockTransport)")
            setattr(no_transport, GUARD_MARK, True)
            monkeypatch.setattr(proxmox, "transport_factory", no_transport)
            self.installed.append(f"{PROXMOX}.transport_factory")

        for attr, what in SSH_DIALS:
            original = getattr(asyncssh, attr)
            if getattr(original, GUARD_MARK, False):
                continue

            def dial_allowed(args: tuple, kwargs: dict, what: str = what) -> str | None:
                host = _host(args, kwargs)
                if _never_leaves(host):
                    return None
                port = kwargs.get("port", args[1] if len(args) > 1 else 22)
                return f"{what} to {host}:{port} (SSH reaches only loopback in tests; patch ssh.probe or use a fake)"
            monkeypatch.setattr(asyncssh, attr, self._wrap(original, dial_allowed))
            self.installed.append(f"asyncssh.{attr}")

        for name, what in CLOUDS:
            module = _module(name)
            if module is not None and _is_original(module, "transport_factory"):
                monkeypatch.setattr(module, "transport_factory", self._failing_transport(name, what))
                self.installed.append(f"{name}.transport_factory")
        return self

    def _failing_transport(self, name: str, what: str) -> Callable[..., httpx.AsyncBaseTransport]:
        """A ``transport_factory`` whose transport raises on a request (the factory itself never does)."""
        short = name.rsplit(".", 1)[1]

        def refuse(request: httpx.Request) -> httpx.Response:
            raise self._block(f"{what} to {request.url.host} (set {short}.transport_factory to a fake)")

        def factory(*args: Any, **kwargs: Any) -> httpx.AsyncBaseTransport:
            return httpx.MockTransport(refuse)

        setattr(factory, GUARD_MARK, True)
        return factory

    def verify(self) -> None:
        """Fail the test when anything was blocked, even if the code under test swallowed the error."""
        if self.blocked:
            blocked, self.blocked = self.blocked, []
            pytest.fail("The test tried to reach something real:\n- " + "\n- ".join(blocked), pytrace=False)


@pytest.fixture
def no_real_hypervisors(monkeypatch: pytest.MonkeyPatch) -> Iterator[Guard]:
    guard = Guard().install(monkeypatch)
    yield guard
    guard.verify()


@pytest.fixture
def no_real_clouds(no_real_hypervisors: Guard) -> Guard:
    """The same guard under the name phase 4's tests use."""
    return no_real_hypervisors
