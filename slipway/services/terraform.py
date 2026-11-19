"""Terraform for Proxmox VMs: the bundled module, the working folder, the state and the runner.

Slipway makes each Proxmox VM with the static root module in ``slipway/terraform/proxmox-vm/``
(design D5), one Terraform state per VM. It writes only ``terraform.tfvars.json`` next to the
module's files, so the module's variables are the whole interface.

**State.** The state that counts is the one in Slipway's database (``terraform_states``, through
a ``StateStore``), encrypted with the rest of Slipway's secrets (D6). Each VM also has a working
folder, ``<terraform_dir>/<machine id>/`` (mode 700), where Terraform runs and keeps its copy.
``session`` reconciles the two by lineage and serial before any command and saves the folder's
state back to the store when a command moved it, whatever happened.

**One writer per state** (M7): the store's lock (a compare-and-set on the deployment id), a check
that no Terraform process named in the folder's ``slipway-run.json`` is still alive, and
Terraform's own lock in the folder.

**Secrets** (D17, M11): the Proxmox API token reaches Terraform only as ``PROXMOX_VE_API_TOKEN``
in an allowlisted environment. It is never in argv, the tfvars file or any other file of the
folder, and every line of Terraform's output goes through the job's redactor, which hides it.

**Stopping.** A timeout or a cancel sends SIGINT to Terraform's process group, so it can save its
state, and SIGKILL after ``SIGINT_GRACE`` seconds. That wait is shielded from a second cancel, so
Slipway's own shutdown still gives Terraform its grace (D27).

``_spawn`` is the one place a process starts; the test guard allows only ``fake-terraform``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import shutil
import signal
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from slipway.services import ssh, tls_pin
from slipway.services.vmtypes import MachineError

log = logging.getLogger(__name__)

Log = Callable[[str], Awaitable[None]]

# The pins of versions.tf, the Dockerfile's build arguments and the image test (test 39) agree.
TERRAFORM_VERSION = "1.16.5"
PROVIDER_SOURCE = "bpg/proxmox"
PROVIDER_ADDRESS = "registry.terraform.io/bpg/proxmox"
PROVIDER_VERSION = "0.115.0"

MODULE_DIR = Path(__file__).resolve().parent.parent / "terraform" / "proxmox-vm"
MODULE_FILES = ("versions.tf", "variables.tf", "main.tf", "outputs.tf")
LOCK_FILE = ".terraform.lock.hcl"
VM_ADDRESS = "proxmox_virtual_environment_vm.vm"

# Whether main.tf sets the first-boot package upgrade (``initialization.upgrade``, Proxmox's ``ciupgrade``).
# bpg/proxmox 0.115.0 has the attribute and a non-root token with VM.Config.Cloudinit may set it, but
# Proxmox before 8.1 has no ciupgrade option, so sending it would fail there. main.tf leaves it out: a clone
# keeps the template's own setting, and Test warns when the template has it on (phase5-machines.md §19.14).
INIT_UPGRADE_SET_BY_MODULE = False

# Storage types whose disks are files: the module writes qcow2 there so they can take snapshots.
FILE_STORAGES = frozenset({"dir", "nfs", "cifs", "glusterfs"})

MAX_STATE_BYTES = 4 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024  # a longer line of Terraform's output is dropped
MAX_CAPTURE_BYTES = 64 * 1024 * 1024  # the most of `show -json` Slipway reads
READ_CHUNK = 64 * 1024

# Seconds per command (design §14). Tests patch these short.
TIMEOUTS: dict[str, float] = {
    "version": 60, "init": 300, "plan": 600, "show": 120, "apply": 2400, "destroy": 1200, "state": 120,
}
SIGINT_GRACE = 30.0  # seconds Terraform gets to save its state after SIGINT, before SIGKILL
KILL_WAIT = 10.0  # seconds to wait for the process to go after SIGKILL

# What Terraform's environment may take from Slipway's; everything else it gets is set here.
INHERITED_ENV = ("PATH", "LANG", "TZ")

STATE_FILE = "terraform.tfstate"
PLAN_FILE = "tfplan"
TFVARS_FILE = "terraform.tfvars.json"
CA_FILE = "proxmox-ca.pem"
RUN_FILE = "slipway-run.json"
INIT_FILE = "slipway-init.json"

PLAN_ACTIONS = frozenset({"no-op", "create", "read", "update", "delete"})


# ------------------------------------------------------------------------ errors


class TerraformError(MachineError):
    """A Terraform step that can't go on, in Slipway's words (the caller adds the VM's context)."""


class PlanUnreadable(TerraformError):
    def __init__(self, detail: str = "") -> None:
        super().__init__("Slipway couldn't read Terraform's plan, so it applied nothing")
        self.detail = detail  # for the server log only; may name the plan's shape, never its values


class TerraformFailed(TerraformError):
    def __init__(self, command: str, returncode: int) -> None:
        super().__init__(f"Terraform's {command} failed (exit code {returncode}). See the log above.")
        self.command = command
        self.returncode = returncode


class TerraformTimeout(TerraformError):
    def __init__(self, command: str, seconds: float) -> None:
        super().__init__(f"Terraform's {command} didn't finish in {_duration(seconds)}; Slipway stopped it")
        self.command = command
        self.seconds = seconds


# ------------------------------------------------------------------------ settings


@dataclass(frozen=True)
class TerraformSettings:
    """What Slipway's configuration says about Terraform (design §3.7)."""

    binary: str = "terraform"  # an absolute path or a name on PATH
    cli_config: str = "/etc/slipway/terraformrc"  # the image's mirror-only CLI config
    dir: str = "data/files/terraform"  # working folders, one per machine
    parallel: int = 2  # Terraform processes at once across Slipway

    @classmethod
    def from_config(cls, settings: Any) -> TerraformSettings:
        """From ``slipway.core.config.Settings``; an empty ``terraform_dir`` means ``<storage_dir>/terraform``."""
        folder = settings.terraform_dir or str(Path(settings.storage_dir) / "terraform")
        return cls(
            binary=settings.terraform_binary, cli_config=settings.terraform_cli_config,
            dir=folder, parallel=settings.terraform_parallel,
        )


_semaphores: dict[int, asyncio.Semaphore] = {}


def _semaphore(parallel: int) -> asyncio.Semaphore:
    # One per configured size; in practice one for the life of the process.
    parallel = max(1, min(int(parallel), 8))
    if parallel not in _semaphores:
        _semaphores[parallel] = asyncio.Semaphore(parallel)
    return _semaphores[parallel]


def resolve_binary(binary: str) -> str:
    path = shutil.which(binary) if not os.path.isabs(binary) else (binary if os.access(binary, os.X_OK) else None)
    if not path:
        raise TerraformError(
            f"Slipway can't find Terraform ({binary}). Install it, or set SLIPWAY_TERRAFORM_BINARY to its path"
        )
    return os.path.abspath(path)


# ------------------------------------------------------------------------ the module


def module_sha(module_dir: Path = MODULE_DIR) -> str:
    """sha256 over the module's files and its lock file, by name, so any change to either changes it."""
    digest = hashlib.sha256()
    for name in sorted((*MODULE_FILES, LOCK_FILE)):
        path = module_dir / name
        digest.update(name.encode() + b"\0")
        digest.update(path.read_bytes() if path.exists() else b"<missing>")
        digest.update(b"\0")
    return digest.hexdigest()


def file_format_for(storage_type: str | None) -> str:
    """qcow2 on a file storage (dir, nfs, cifs, glusterfs), raw on any other (design §7.2)."""
    return "qcow2" if (storage_type or "") in FILE_STORAGES else "raw"


def vm_tags(environment_id: uuid.UUID | str) -> list[str]:
    """Slipway's tags, sorted as Proxmox stores them, so a plan never shows a change from order alone."""
    return sorted(["slipway", f"env-{environment_id}"])


def vm_description(environment_name: str, environment_id: uuid.UUID | str, slot: str) -> str:
    return (
        f"Managed by Slipway: environment {environment_name} ({environment_id}), {slot} slot. "
        "Change or delete it from Slipway, not here."
    )


def tfvars(
    *, endpoint: str, name: str, environment_id: uuid.UUID | str, environment_name: str, slot: str,
    spec: Mapping[str, Any], network: Mapping[str, Any], size: Mapping[str, Any], vmid: int, ssh_public_key: str,
) -> dict[str, Any]:
    """The ``terraform.tfvars.json`` for one machine: exactly the module's variables, no secret.

    ``spec`` is the machine's frozen Proxmox spec (``node``, ``pool``, ``storage``, ``storage_type``,
    optionally ``file_format``, ``template_vmid``, ``bridge``, ``vlan_tag``), ``network`` its frozen
    network (``address``, ``prefix``, ``gateway``, ``dns_servers``) and ``size`` the size to plan for.
    """
    dns = list(network.get("dns_servers") or []) or [network["gateway"]]  # none named: the gateway
    vlan = spec.get("vlan_tag")
    return {
        "endpoint": endpoint,
        "node": spec["node"],
        "vm_id": int(vmid),
        "name": name,
        "pool": spec["pool"],
        "tags": vm_tags(environment_id),
        "description": vm_description(environment_name, environment_id, slot),
        "template_vm_id": int(spec["template_vmid"]),
        "datastore": spec["storage"],
        "file_format": spec.get("file_format") or file_format_for(spec.get("storage_type")),
        "bridge": spec["bridge"],
        "vlan_id": int(vlan) if vlan not in (None, "") else None,
        "cores": int(size["cores"]),
        "memory_mb": int(size["memory_mb"]),
        "disk_gb": int(size["disk_gb"]),
        "address_cidr": f"{network['address']}/{int(network['prefix'])}",
        "gateway": network["gateway"],
        "dns_servers": dns,
        "ssh_public_key": ssh_public_key.strip(),
    }


def one_certificate(pem: str) -> str:
    """The pinned certificate as exactly one PEM certificate, or TerraformError.

    Terraform's SSL_CERT_FILE must trust that certificate alone: an empty or unreadable file would
    let Go fall back to the system's trust, and a second certificate would be trusted too.
    """
    try:
        return tls_pin.clean_pem(pem or "")
    except tls_pin.TlsPinError:
        raise TerraformError(
            "The Proxmox account's pinned certificate isn't exactly one certificate, so Slipway won't run "
            "Terraform with it. Trust the certificate again in Settings → Integrations"
        ) from None


# ------------------------------------------------------------------------ plans


@dataclass(frozen=True)
class Change:
    address: str
    actions: tuple[str, ...]
    before: Any = None
    after: Any = None
    after_unknown: Any = None

    @property
    def is_create(self) -> bool:
        return self.actions == ("create",)

    @property
    def is_update(self) -> bool:
        return self.actions == ("update",)

    @property
    def is_replace(self) -> bool:
        return sorted(self.actions) == ["create", "delete"]

    @property
    def deletes(self) -> bool:
        return "delete" in self.actions


def plan_changes(doc: Any) -> list[Change]:
    """The resource changes of a ``show -json`` plan document, leaving out no-ops.

    Anything that isn't the documented shape raises ``PlanUnreadable``: Slipway applies only a plan
    it has understood.
    """
    if not isinstance(doc, dict) or not isinstance(doc.get("format_version"), str):
        raise PlanUnreadable("not a plan document")
    items = doc.get("resource_changes", [])
    if not isinstance(items, list):
        raise PlanUnreadable("resource_changes isn't a list")
    changes: list[Change] = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("address"), str):
            raise PlanUnreadable("a resource change without an address")
        change = item.get("change")
        actions = change.get("actions") if isinstance(change, dict) else None
        if (
            not isinstance(actions, list) or not actions
            or not all(isinstance(a, str) and a in PLAN_ACTIONS for a in actions)
        ):
            raise PlanUnreadable(f"unknown actions for {item['address']}")
        if actions == ["no-op"]:
            continue
        changes.append(Change(
            address=item["address"], actions=tuple(actions), before=change.get("before"),
            after=change.get("after"), after_unknown=change.get("after_unknown"),
        ))
    return changes


def changed_attributes(change: Change) -> list[str]:
    """Top-level attributes the change sets differently, or leaves to be known after apply."""
    before = change.before if isinstance(change.before, dict) else {}
    after = change.after if isinstance(change.after, dict) else {}
    unknown = change.after_unknown if isinstance(change.after_unknown, dict) else {}
    keys = {k for k in before.keys() | after.keys() if before.get(k) != after.get(k)}
    keys |= {k for k, v in unknown.items() if v not in (False, None, {}, [])}
    return sorted(keys)


# ------------------------------------------------------------------------ state


@dataclass(frozen=True)
class StoredState:
    """A Terraform state as the store holds it. ``state`` is the whole ``terraform.tfstate`` text."""

    lineage: str | None = None
    serial: int = 0
    sha256: str | None = None
    state: str | None = None

    @property
    def empty(self) -> bool:
        return self.lineage is None or self.state is None


@dataclass(frozen=True)
class LockResult:
    ok: bool
    holder: uuid.UUID | None = None  # refused: the deployment holding the lock
    taken_over: uuid.UUID | None = None  # taken: the finished or gone deployment it was taken from


class StateStore(Protocol):
    """Where a machine's Terraform state lives (the database's ``terraform_states``, slice B1).

    Every write is its own committed transaction, so it survives the caller's rollback.
    """

    async def lock(self, machine_id: uuid.UUID, deployment_id: uuid.UUID) -> LockResult:
        """Compare-and-set: take the lock when it is free, ours, or held by a deployment that isn't
        queued or running (or no longer exists). The row is inserted first when absent."""

    async def unlock(self, machine_id: uuid.UUID, deployment_id: uuid.UUID) -> None:
        """Release the lock if this deployment holds it."""

    async def load(self, machine_id: uuid.UUID) -> StoredState: ...

    async def save(
        self, machine_id: uuid.UUID, state: StoredState, *, module_sha: str | None, terraform_version: str | None,
    ) -> None:
        """Store the state; ``module_sha`` and ``terraform_version`` only after an apply or destroy (else None)."""


@dataclass
class _MemoryRow:
    stored: StoredState = field(default_factory=StoredState)
    lock_id: uuid.UUID | None = None
    locked_at: datetime | None = None
    module_sha: str | None = None
    terraform_version: str | None = None


class MemoryStateStore:
    """An in-memory ``StateStore`` for tests and tools. ``active`` holds the deployment ids that are
    queued or running; a lock held by any other id is taken over, as the database store does."""

    def __init__(self, active: set[uuid.UUID] | None = None) -> None:
        self.active: set[uuid.UUID] = active if active is not None else set()
        self.rows: dict[uuid.UUID, _MemoryRow] = {}
        self.saves = 0

    async def lock(self, machine_id: uuid.UUID, deployment_id: uuid.UUID) -> LockResult:
        row = self.rows.setdefault(machine_id, _MemoryRow())
        held = row.lock_id
        if held is not None and held != deployment_id and held in self.active:
            return LockResult(ok=False, holder=held)
        row.lock_id, row.locked_at = deployment_id, datetime.now(UTC)
        return LockResult(ok=True, taken_over=held if held not in (None, deployment_id) else None)

    async def unlock(self, machine_id: uuid.UUID, deployment_id: uuid.UUID) -> None:
        row = self.rows.get(machine_id)
        if row is not None and row.lock_id == deployment_id:
            row.lock_id, row.locked_at = None, None

    async def load(self, machine_id: uuid.UUID) -> StoredState:
        row = self.rows.get(machine_id)
        return row.stored if row is not None else StoredState()

    async def save(
        self, machine_id: uuid.UUID, state: StoredState, *, module_sha: str | None, terraform_version: str | None,
    ) -> None:
        row = self.rows.setdefault(machine_id, _MemoryRow())
        row.stored = state
        if module_sha is not None:
            row.module_sha = module_sha
        if terraform_version is not None:
            row.terraform_version = terraform_version
        self.saves += 1


def parse_state(text: str) -> StoredState:
    """A ``terraform.tfstate`` text as a ``StoredState``; TerraformError when it isn't one."""
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None
    lineage = doc.get("lineage") if isinstance(doc, dict) else None
    serial = doc.get("serial") if isinstance(doc, dict) else None
    if not isinstance(lineage, str) or not lineage or not isinstance(serial, int) or isinstance(serial, bool):
        raise TerraformError("Slipway can't read the Terraform state in the working folder; it changed nothing")
    return StoredState(
        lineage=lineage, serial=serial, sha256=hashlib.sha256(text.encode()).hexdigest(), state=text,
    )


@dataclass(frozen=True)
class StateResource:
    """A resource as the folder's state holds it."""

    address: str
    tainted: bool
    attributes: dict[str, Any]


def state_resource(text: str | None, address: str = VM_ADDRESS) -> StateResource | None:
    if not text:
        return None
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    for res in doc.get("resources", []) if isinstance(doc, dict) else []:
        if not isinstance(res, dict) or res.get("mode") != "managed" or res.get("module"):
            continue
        if f"{res.get('type')}.{res.get('name')}" != address:
            continue
        instances = res.get("instances") or []
        if not instances:
            return None
        inst = instances[0] if isinstance(instances[0], dict) else {}
        attrs = inst.get("attributes") if isinstance(inst.get("attributes"), dict) else {}
        return StateResource(address=address, tainted=inst.get("status") == "tainted", attributes=attrs)
    return None


# ------------------------------------------------------------------------ the working folder


class Workdir:
    """``<terraform_dir>/<machine id>/``, mode 700: the module, tfvars, CA, Terraform's state and plan."""

    def __init__(self, root: str | Path, machine_id: uuid.UUID | str) -> None:
        self.machine_id = uuid.UUID(str(machine_id))  # a UUID, so the name can't leave the root
        self.root = Path(root)
        self.path = self.root / str(self.machine_id)

    def __truediv__(self, name: str) -> Path:
        return self.path / name

    @property
    def state_path(self) -> Path:
        return self.path / STATE_FILE

    def exists(self) -> bool:
        return self.path.is_dir()

    def create(self) -> None:
        for folder in (self.root, self.path):
            folder.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(folder, 0o700)  # mkdir's mode is cut by the umask, and an old folder may be wider
        for sub in ("home", "ca"):
            (self.path / sub).mkdir(mode=0o700, exist_ok=True)

    def read_state(self) -> StoredState | None:
        try:
            text = self.state_path.read_text()
        except FileNotFoundError:
            return None
        if not text.strip():
            return None
        return parse_state(text)

    def write_state(self, text: str) -> None:
        _write_private(self.state_path, text)

    def write_files(self, module_dir: Path, variables: Mapping[str, Any], ca_pem: str) -> None:
        """The module, its lock file, the tfvars and the CA, with what an earlier run left cleared."""
        for name in (*MODULE_FILES, LOCK_FILE):
            _write_private(self.path / name, (module_dir / name).read_text())
        # Terraform reads every *.tf and *.auto.tfvars in the folder: only the bundled ones may be there.
        for old in self.path.iterdir():
            if old.is_file() and old.name not in MODULE_FILES and (
                old.name.endswith((".tf", ".tf.json")) or ".auto.tfvars" in old.name
            ):
                old.unlink()
        _write_private(self.path / TFVARS_FILE, json.dumps(dict(variables), indent=2, sort_keys=True) + "\n")
        _write_private(self.path / CA_FILE, ca_pem)
        ca_dir = self.path / "ca"
        for extra in ca_dir.iterdir():  # SSL_CERT_DIR must hold nothing, so only the CA file is trusted
            shutil.rmtree(extra) if extra.is_dir() else extra.unlink()
        for leftover in ("crash.log", PLAN_FILE):
            (self.path / leftover).unlink(missing_ok=True)

    def read_json(self, name: str) -> Any:
        try:
            return json.loads((self.path / name).read_text())
        except (FileNotFoundError, ValueError):
            return None

    def remove(self) -> None:
        """Delete the folder (Remove, once the VM is confirmed gone)."""
        shutil.rmtree(self.path, ignore_errors=True)


def _write_private(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".slipway-tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


# ------------------------------------------------------------------------ processes


async def _spawn(argv: list[str], *, cwd: str, env: dict[str, str], capture: bool) -> asyncio.subprocess.Process:
    """Start Terraform. The one place a process starts (the test guard replaces it)."""
    return await asyncio.create_subprocess_exec(
        *argv, cwd=cwd, env=env, stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE if capture else asyncio.subprocess.STDOUT,
        # Its own session and process group: SIGINT reaches Terraform and its provider together,
        # and it can outlive a crashed Slipway (the PID check of `session` finds it then).
        start_new_session=True,
    )


def _signal_group(proc: asyncio.subprocess.Process, sig: int) -> None:
    try:
        os.killpg(proc.pid, sig)
    except (ProcessLookupError, PermissionError):
        pass


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _process_command(pid: int) -> list[str] | None:
    """The process's command line, or None when this system doesn't say (no /proc)."""
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except FileNotFoundError:
        return [] if Path("/proc/self").exists() else None  # with /proc: the process is gone
    except OSError:
        return None
    return [part.decode(errors="replace") for part in raw.split(b"\0") if part]


def _is_terraform(pid: int, binary: str) -> bool:
    """Whether ``pid`` is alive and runs ``binary``. Where the command line can't be read, a live
    process counts as Terraform: refusing a retry is safer than running two."""
    if not _pid_alive(pid):
        return False
    command = _process_command(pid)
    if command is None:
        return True
    name = os.path.basename(binary)
    return any(os.path.basename(part) == name for part in command)


async def _finish(awaitable: Awaitable[Any]) -> Any:
    """Await ``awaitable`` to its end even when cancelled meanwhile, then re-raise the cancel."""
    task = asyncio.ensure_future(awaitable)
    cancelled = False
    while True:
        try:
            result = await asyncio.shield(task)
            break
        except asyncio.CancelledError:
            if task.cancelled():
                raise
            cancelled = True
    if cancelled:
        raise asyncio.CancelledError
    return result


def _duration(seconds: float) -> str:
    if seconds >= 60 and seconds % 60 == 0:
        minutes = int(seconds // 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    return f"{seconds:g} seconds"


@dataclass(frozen=True)
class RunResult:
    returncode: int
    stdout: bytes = b""  # captured commands only (`show -json`, `version -json`); never logged


class SubprocessTerraform:
    """Runs Terraform commands in one working folder (Sirdar's runner, SD/deploy/terraform.py:243-311)."""

    def __init__(
        self, *, settings: TerraformSettings, workdir: Workdir, token: str, say: Log, hide: ssh.Redactor,
        deployment_id: uuid.UUID | None = None, binary: str | None = None,
    ) -> None:
        self.settings = settings
        self.workdir = workdir
        self.binary = binary or resolve_binary(settings.binary)
        self.say = say
        self.hide = hide
        self.deployment_id = deployment_id
        self._token = token
        # The whole token and its secret part (after "="), so neither shows in a line printed by Terraform.
        hide.add(token)
        if "=" in token:
            hide.add(token.split("=", 1)[1])

    def env(self) -> dict[str, str]:
        env = {name: os.environ[name] for name in INHERITED_ENV if name in os.environ}
        env.update(
            HOME=str(self.workdir / "home"),
            TF_CLI_CONFIG_FILE=self.settings.cli_config,
            TF_IN_AUTOMATION="1",
            TF_INPUT="0",
            CHECKPOINT_DISABLE="1",
            SSL_CERT_FILE=str(self.workdir / CA_FILE),
            SSL_CERT_DIR=str(self.workdir / "ca"),
            PROXMOX_VE_API_TOKEN=self._token,
        )
        return env

    async def run(self, args: list[str], *, timeout_key: str, capture: bool = False) -> RunResult:
        """Run ``terraform <args>`` in the folder. Output is logged line by line through the redactor,
        except a captured command's standard output, which is returned and never logged."""
        timeout = TIMEOUTS[timeout_key]
        command = args[0] if args else "terraform"
        async with _semaphore(self.settings.parallel):
            proc = await _spawn(
                [self.binary, *args], cwd=str(self.workdir.path), env=self.env(), capture=capture,
            )
            out = bytearray()
            waiter = asyncio.ensure_future(self._drive(proc, out if capture else None))
            try:
                self._write_run_file(proc.pid, args)
                returncode = await asyncio.wait_for(asyncio.shield(waiter), timeout)
            except TimeoutError:
                await _finish(self._stop(proc, waiter))
                raise TerraformTimeout(command, timeout) from None
            except BaseException:  # a cancel (Slipway's shutdown, the step's limit) or a failed read
                await _finish(self._stop(proc, waiter))
                raise
            finally:
                self._clear_run_file(proc)
        if returncode != 0:
            raise TerraformFailed(command, returncode)
        return RunResult(returncode=returncode, stdout=bytes(out))

    async def _drive(self, proc: asyncio.subprocess.Process, out: bytearray | None) -> int:
        assert proc.stdout is not None
        if out is None:
            await self._pump(proc.stdout)
        else:
            assert proc.stderr is not None
            await asyncio.gather(self._collect(proc.stdout, out), self._pump(proc.stderr))
        return await proc.wait()

    async def _pump(self, stream: asyncio.StreamReader) -> None:
        """Log each line as it comes. A line over MAX_LINE_BYTES is dropped and reading goes on."""
        buf = bytearray()
        dropping = False
        while True:
            chunk = await stream.read(READ_CHUNK)
            if not chunk:
                break
            buf += chunk
            while True:
                nl = buf.find(b"\n")
                if nl < 0:
                    break
                line, buf = bytes(buf[:nl]), buf[nl + 1:]
                if dropping:
                    dropping = False  # the end of a dropped line
                    continue
                await self._line(line)
            if len(buf) > MAX_LINE_BYTES:
                if not dropping:
                    await self.say("[Slipway left out a line of Terraform's output longer than 1 MiB]")
                dropping = True
                buf.clear()
        if buf and not dropping:
            await self._line(bytes(buf))

    async def _line(self, raw: bytes) -> None:
        if len(raw) > MAX_LINE_BYTES:
            await self.say("[Slipway left out a line of Terraform's output longer than 1 MiB]")
            return
        text = raw.decode(errors="replace").rstrip("\r")
        await self.say(self.hide.scrub(text))

    async def _collect(self, stream: asyncio.StreamReader, out: bytearray) -> None:
        while True:
            chunk = await stream.read(READ_CHUNK)
            if not chunk:
                return
            if len(out) + len(chunk) > MAX_CAPTURE_BYTES:
                out.clear()
                out += b"\0too large"  # not JSON: the caller's parse refuses it
                while await stream.read(READ_CHUNK):  # keep draining so Terraform isn't blocked
                    pass
                return
            out += chunk

    async def _stop(self, proc: asyncio.subprocess.Process, waiter: asyncio.Future) -> None:
        """SIGINT to the group, so Terraform saves its state; SIGKILL after the grace."""
        if waiter.done():
            return
        _signal_group(proc, signal.SIGINT)
        await self.say("Stopping Terraform; it saves its state first")
        done, _ = await asyncio.wait({waiter}, timeout=SIGINT_GRACE)
        if not done:
            _signal_group(proc, signal.SIGKILL)
            await self.say(f"Terraform didn't stop within {_duration(SIGINT_GRACE)} of being asked; killed it")
            done, _ = await asyncio.wait({waiter}, timeout=KILL_WAIT)
        if done and not waiter.cancelled() and waiter.exception() is not None:
            log.warning("Reading Terraform's output failed while stopping it: %s", waiter.exception())

    def _write_run_file(self, pid: int, args: list[str]) -> None:
        _write_private(self.workdir / RUN_FILE, json.dumps({
            "pid": pid,
            "deployment_id": str(self.deployment_id) if self.deployment_id else None,
            "args": args,  # never holds a secret: the token is only in the environment
            "started_at": datetime.now(UTC).isoformat(timespec="seconds"),
        }))

    def _clear_run_file(self, proc: asyncio.subprocess.Process) -> None:
        # Kept while the process may still be alive, so the next session's check finds it.
        if proc.returncode is not None or not _pid_alive(proc.pid):
            (self.workdir / RUN_FILE).unlink(missing_ok=True)


# ------------------------------------------------------------------------ the session


class Terraform:
    """What ``session`` yields: the commands Slipway runs against one machine's state."""

    def __init__(self, runner: SubprocessTerraform, *, workdir: Workdir, module_sha: str, version: str) -> None:
        self.runner = runner
        self.workdir = workdir
        self.module_sha = module_sha
        self.terraform_version = version
        self.applied = False  # an apply or destroy ran: the save records module_sha and the version
        self._planned = False

    async def init(self) -> None:
        await self.runner.run(["init", "-input=false", "-no-color", "-lockfile=readonly"], timeout_key="init")
        _write_private(self.workdir / INIT_FILE, json.dumps(
            {"module_sha": self.module_sha, "terraform_version": self.terraform_version}, sort_keys=True,
        ))

    def needs_init(self) -> bool:
        if not (self.workdir / ".terraform").is_dir():
            return True
        marker = self.workdir.read_json(INIT_FILE)
        return marker != {"module_sha": self.module_sha, "terraform_version": self.terraform_version}

    async def plan(self) -> list[Change]:
        """``plan -out=tfplan``, then the saved plan read with ``show -json`` (into memory, never logged)."""
        self._planned = False
        await self.runner.run(["plan", "-input=false", "-no-color", f"-out={PLAN_FILE}"], timeout_key="plan")
        result = await self.runner.run(["show", "-json", "-no-color", PLAN_FILE], timeout_key="show", capture=True)
        try:
            doc = json.loads(result.stdout)
        except ValueError:
            raise PlanUnreadable("show -json printed something that isn't JSON") from None
        changes = plan_changes(doc)
        self._planned = True
        return changes

    async def apply(self) -> None:
        """Apply exactly the plan read by ``plan`` in this session."""
        if not self._planned or not (self.workdir / PLAN_FILE).exists():
            raise TerraformError("Slipway applies only a plan it has read, and there is none; it applied nothing")
        self._planned = False
        self.applied = True
        try:
            await self.runner.run(["apply", "-input=false", "-no-color", PLAN_FILE], timeout_key="apply")
        finally:
            (self.workdir / PLAN_FILE).unlink(missing_ok=True)  # a plan is good for one apply

    async def destroy(self) -> None:
        """Only in Remove (design M6)."""
        self._planned = False
        self.applied = True
        await self.runner.run(["destroy", "-auto-approve", "-input=false", "-no-color"], timeout_key="destroy")

    async def state_rm(self, address: str = VM_ADDRESS) -> None:
        self._planned = False
        await self.runner.run(["state", "rm", "-no-color", address], timeout_key="state")

    def resource(self, address: str = VM_ADDRESS) -> StateResource | None:
        """The resource as the folder's state holds it now (None when absent)."""
        try:
            text = self.workdir.state_path.read_text()
        except FileNotFoundError:
            return None
        return state_resource(text, address)


async def terraform_version(runner: SubprocessTerraform) -> str:
    result = await runner.run(["version", "-json"], timeout_key="version", capture=True)
    try:
        version = json.loads(result.stdout).get("terraform_version")
    except (ValueError, AttributeError):
        version = None
    if not isinstance(version, str) or not version:
        raise TerraformError("Slipway couldn't tell which Terraform version it has")
    return version


async def _reconcile(store: StateStore, workdir: Workdir, machine_id: uuid.UUID, vm: str, say: Log) -> StoredState:
    """Make the folder and the store hold the same state; returns the store's state afterwards."""
    stored = await store.load(machine_id)
    folder = workdir.read_state()
    if folder is None:
        if not stored.empty:
            workdir.write_state(stored.state or "")
        return stored
    if stored.empty or (folder.lineage == stored.lineage and folder.serial > stored.serial):
        # A first apply whose save never ran, or a later one: the folder's is the newer state.
        _check_size(folder, vm)
        await store.save(machine_id, folder, module_sha=None, terraform_version=None)
        await say(f"Kept Terraform's state #{folder.serial} from the working folder (Slipway stopped before saving it)")
        return folder
    if folder.lineage != stored.lineage:
        raise TerraformError(
            f"Slipway has two different Terraform states for {vm}; it changed nothing. "
            f"Compare them in {workdir.path} and the database before going on"
        )
    if folder.sha256 != stored.sha256:  # older, or the same serial with other bytes: the store's counts
        workdir.write_state(stored.state or "")
    return stored


def _check_size(state: StoredState, vm: str) -> None:
    if len((state.state or "").encode()) > MAX_STATE_BYTES:
        raise TerraformError(f"Terraform's state for {vm} is larger than Slipway keeps (4 MiB)")


async def _save_back(
    store: StateStore, workdir: Workdir, machine_id: uuid.UUID, vm: str, before: StoredState, tf: Terraform | None,
) -> None:
    folder = workdir.read_state()
    if folder is None or (folder.lineage, folder.serial, folder.sha256) == (before.lineage, before.serial, before.sha256):
        return
    _check_size(folder, vm)
    applied = tf is not None and tf.applied
    await store.save(
        machine_id, folder,
        module_sha=tf.module_sha if applied else None, terraform_version=tf.terraform_version if applied else None,
    )


@asynccontextmanager
async def session(
    *, machine_id: uuid.UUID, vm_name: str, deployment_id: uuid.UUID, store: StateStore,
    settings: TerraformSettings, variables: Mapping[str, Any], ca_pem: str, token: str, say: Log,
    hide: ssh.Redactor, module_dir: Path = MODULE_DIR,
) -> AsyncIterator[Terraform]:
    """Hold one machine's Terraform state for a run of commands (design §7.3).

    Before the first command: the store's lock, no live Terraform process in the folder, the two
    states reconciled, the module, tfvars and CA written, and ``init`` when the folder isn't
    initialised for this module and Terraform. On leaving, always: the folder's state saved to the
    store when it moved, the run file removed once its process is gone, the lock released.
    """
    ca = one_certificate(ca_pem)  # before anything is written
    if not os.path.isfile(settings.cli_config):
        raise TerraformError(
            f"Terraform's settings file {settings.cli_config} is missing, so Slipway won't run Terraform "
            "(without it Terraform would download providers)"
        )
    if not (module_dir / LOCK_FILE).is_file():
        raise TerraformError(
            f"Slipway's bundled Terraform module has no {LOCK_FILE}, so this build of Slipway can't run Terraform"
        )
    binary = resolve_binary(settings.binary)
    workdir = Workdir(settings.dir, machine_id)

    got = await store.lock(machine_id, deployment_id)
    if not got.ok:
        holder = str(got.holder)[:8] if got.holder else "another"
        raise TerraformError(f"Terraform state of {vm_name} is in use by deployment {holder}; wait for it to finish")
    if got.taken_over is not None:
        await say(f"Took over the Terraform lock of {vm_name} from deployment {str(got.taken_over)[:8]}, which isn't running")
        log.info("Terraform lock of machine %s taken over from deployment %s", machine_id, got.taken_over)

    tf: Terraform | None = None
    before: StoredState | None = None
    failed = False
    try:
        workdir.create()
        run = workdir.read_json(RUN_FILE)
        if isinstance(run, dict) and isinstance(run.get("pid"), int) and _is_terraform(run["pid"], binary):
            dep = str(run.get("deployment_id") or "")[:8] or "unknown"
            raise TerraformError(
                f"Terraform is still running for {vm_name} (from deployment {dep}, pid {run['pid']}): "
                "wait for it to finish, then retry"
            )
        (workdir / RUN_FILE).unlink(missing_ok=True)  # a process that is gone holds nothing

        before = await _reconcile(store, workdir, machine_id, vm_name, say)
        workdir.write_files(module_dir, variables, ca)
        runner = SubprocessTerraform(
            settings=settings, workdir=workdir, token=token, say=say, hide=hide,
            deployment_id=deployment_id, binary=binary,
        )
        version = await terraform_version(runner)
        tf = Terraform(runner, workdir=workdir, module_sha=module_sha(module_dir), version=version)
        if tf.needs_init():
            await tf.init()
        yield tf
    except BaseException:
        failed = True
        raise
    finally:
        try:
            if before is not None:
                try:
                    await _finish(_save_back(store, workdir, machine_id, vm_name, before, tf))
                except TerraformError as exc:
                    if not failed:
                        raise
                    await say(str(exc))  # the step already fails with its own error; this one is logged
        finally:
            run = workdir.read_json(RUN_FILE)
            if not (isinstance(run, dict) and isinstance(run.get("pid"), int) and _is_terraform(run["pid"], binary)):
                (workdir / RUN_FILE).unlink(missing_ok=True)
            await _finish(store.unlock(machine_id, deployment_id))
