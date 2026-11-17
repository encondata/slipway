"""Terraform: the runner, the bundled module, plans, the working folder, state and locks (tests 9-14).

Terraform itself is ``bin/fake-terraform``, started through a wrapper named ``fake-terraform``
that runs it with this interpreter; the "Proxmox" it changes is a JSON file. Nothing here
reaches a network.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import os
import re
import shutil
import stat
import sys
import time
import uuid
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from slipway.services import cloudinit, ssh, terraform
from slipway.services.terraform import (
    Change,
    MemoryStateStore,
    PlanUnreadable,
    StoredState,
    TerraformError,
    TerraformFailed,
    TerraformSettings,
    TerraformTimeout,
    changed_attributes,
    plan_changes,
)

from tests.fake_proxmox import FakeProxmox
from tests.hypervisor_guard import no_real_hypervisors  # noqa: F401  (the fixture)

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")

FAKE = Path(__file__).parent / "bin" / "fake-terraform"
TOKEN = "slipway@pve!slipway=0b7c1f9e-5d2a-4a5b-9c8d-abcdef012345"
SECRET_PART = TOKEN.split("=", 1)[1]
ENV_ID = uuid.UUID("11111111-2222-4333-8444-555555555555")
ALLOWED_ENV = {
    "PATH", "LANG", "TZ", "HOME", "TF_CLI_CONFIG_FILE", "TF_IN_AUTOMATION", "TF_INPUT", "CHECKPOINT_DISABLE",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "PROXMOX_VE_API_TOKEN",
}


def provider_hash(version: str) -> str:
    # The fake mirror's rule (bin/fake-terraform `provider_hash`).
    import base64
    import hashlib

    return "h1:" + base64.b64encode(hashlib.sha256(f"fake-bpg-proxmox-{version}".encode()).digest()).decode()


def lock_file(version: str) -> str:
    return (
        "# This file is maintained automatically by \"terraform init\".\n"
        "# Manual edits may be lost in future updates.\n\n"
        f'provider "{terraform.PROVIDER_ADDRESS}" {{\n'
        f'  version     = "{version}"\n'
        f'  constraints = "{version}"\n'
        "  hashes = [\n"
        f'    "{provider_hash(version)}",\n'
        "  ]\n"
        "}\n"
    )


def make_cert(name: str = "pve.lan") -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30)).sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


SPEC = {
    "node": "pve1", "pool": "slipway", "storage": "local-lvm", "storage_type": "lvmthin",
    "template_vmid": 9000, "bridge": "vmbr0", "vlan_tag": None,
}
NETWORK = {"name": "lan", "address": "10.0.0.12", "prefix": 24, "gateway": "10.0.0.1", "dns_servers": []}
SIZE = {"cores": 2, "memory_mb": 4096, "disk_gb": 32}
PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl slipway@slipway-uat-blue"


def make_vars(**size) -> dict:
    return terraform.tfvars(
        endpoint="https://pve.lan:8006/", name="slipway-uat-blue", environment_id=ENV_ID,
        environment_name="uat", slot="blue", spec=SPEC, network=NETWORK, size={**SIZE, **size}, vmid=105,
        ssh_public_key=PUBLIC_KEY,
    )


class FakeTF:
    """One test's fake Terraform, its "Proxmox", its knobs and log, and a session factory."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.pve_state = root / "pve.json"
        self.script = root / "script.json"
        self.log = root / "tf-log.jsonl"
        self.bin = root / "bin" / "fake-terraform"
        self.bin.parent.mkdir()
        config = {"pve_state": str(self.pve_state), "script": str(self.script), "log": str(self.log)}
        self.bin.write_text(
            f"#!{sys.executable}\n"
            "import runpy\n"
            f"runpy.run_path({str(FAKE)!r}, init_globals={{'FAKE_CONFIG': {config!r}}}, run_name='__main__')\n"
        )
        self.bin.chmod(0o755)
        self.cli_config = root / "terraformrc"
        self.cli_config.write_text('provider_installation {\n  filesystem_mirror { path = "/nowhere" }\n}\n')
        self.module = self.make_module(terraform.PROVIDER_VERSION)
        self.settings = TerraformSettings(
            binary=str(self.bin), cli_config=str(self.cli_config), dir=str(root / "terraform"), parallel=2,
        )
        self.proxmox = FakeProxmox(self.pve_state)
        self.store = MemoryStateStore()
        self.machine_id = uuid.uuid4()
        self.deployment_id = uuid.uuid4()
        self.store.active.add(self.deployment_id)
        self.lines: list[str] = []
        self.hide = ssh.Redactor()
        self.ca = make_cert()
        self.knobs()

    def make_module(self, version: str, name: str = "module") -> Path:
        folder = self.root / f"{name}-{version}"
        folder.mkdir()
        for file in terraform.MODULE_FILES:
            shutil.copy(terraform.MODULE_DIR / file, folder / file)
        (folder / terraform.LOCK_FILE).write_text(lock_file(version))
        return folder

    def knobs(self, **values) -> None:
        self.script.write_text(json.dumps(values))

    def runs(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def commands(self) -> list[str]:
        return [run["argv"][0] for run in self.runs()]

    def vms(self) -> dict:
        """FakeProxmox's VMs, the template left out."""
        return {k: v for k, v in self.proxmox.state["vms"].items() if not v.get("template")}

    @property
    def workdir(self) -> terraform.Workdir:
        return terraform.Workdir(self.settings.dir, self.machine_id)

    async def say(self, line: str) -> None:
        self.lines.append(line)

    def session(self, *, variables: dict | None = None, module: Path | None = None, ca: str | None = None,
                deployment_id: uuid.UUID | None = None):
        return terraform.session(
            machine_id=self.machine_id, vm_name="slipway-uat-blue",
            deployment_id=deployment_id or self.deployment_id, store=self.store, settings=self.settings,
            variables=variables or make_vars(), ca_pem=self.ca if ca is None else ca, token=TOKEN,
            say=self.say, hide=self.hide, module_dir=module or self.module,
        )

    def stored(self) -> StoredState:
        row = self.store.rows.get(self.machine_id)
        return row.stored if row else StoredState()

    def lock_id(self):
        row = self.store.rows.get(self.machine_id)
        return row.lock_id if row else None


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeTF:
    monkeypatch.setattr(terraform, "_semaphores", {})
    return FakeTF(tmp_path)


async def make_vm(fake: FakeTF) -> None:
    async with fake.session() as tf:
        changes = await tf.plan()
        assert [c.actions for c in changes] == [("create",)]
        await tf.apply()


def state_doc(lineage: str, serial: int, pad: int = 0) -> str:
    return json.dumps({"version": 4, "serial": serial, "lineage": lineage, "resources": [], "pad": "x" * pad})


# ------------------------------------------------------------------ 9. the runner's environment


async def test_only_the_allowlisted_environment_reaches_terraform(fake, monkeypatch):
    monkeypatch.setenv("SLIPWAY_ENCRYPTION_KEY", "do-not-pass-this-on")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "nor-this")
    monkeypatch.setenv("LANG", "C.UTF-8")
    await make_vm(fake)
    runs = fake.runs()
    assert [r["argv"][0] for r in runs] == ["version", "init", "plan", "show", "apply"]
    wd = fake.workdir
    for run in runs:
        extra = {name for name in run["env"] if not name.startswith("__CF")}  # macOS adds its own
        assert extra <= ALLOWED_ENV, extra - ALLOWED_ENV
        assert "SLIPWAY_ENCRYPTION_KEY" not in run["env"] and "AWS_SECRET_ACCESS_KEY" not in run["env"]
        assert {"PATH", "LANG", "PROXMOX_VE_API_TOKEN"} <= set(run["env"])
        import hashlib

        assert run["token_sha256"] == hashlib.sha256(TOKEN.encode()).hexdigest()
        assert run["env_values"] == {
            "HOME": str(wd / "home"), "SSL_CERT_FILE": str(wd / "proxmox-ca.pem"),
            "SSL_CERT_DIR": str(wd / "ca"), "TF_CLI_CONFIG_FILE": str(fake.cli_config),
            "TF_IN_AUTOMATION": "1", "TF_INPUT": "0", "CHECKPOINT_DISABLE": "1",
        }
        assert run["cwd"] == str(wd.path) or os.path.realpath(run["cwd"]) == os.path.realpath(wd.path)
        assert not any(TOKEN in arg or SECRET_PART in arg for arg in run["argv"])
    # No file of the working folder holds the token or its secret part.
    for path in wd.path.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            assert TOKEN.encode() not in data and SECRET_PART.encode() not in data, path
    assert list((wd / "ca").iterdir()) == []
    assert (wd / "proxmox-ca.pem").read_text() == fake.ca
    assert not any(TOKEN in line or SECRET_PART in line for line in fake.lines)


# ------------------------------------------------------------------ 10. output, timeouts, cancels


async def test_output_goes_through_the_redactor_and_long_lines_are_dropped(fake):
    fake.knobs(print={"plan": [f"token {TOKEN}", f"secret {SECRET_PART} end"]}, big_line={"plan": 2 * 1024 * 1024})
    async with fake.session() as tf:
        await tf.plan()
    text = "\n".join(fake.lines)
    assert TOKEN not in text and SECRET_PART not in text
    assert "token [hidden]" in fake.lines and "secret [hidden] end" in fake.lines
    assert "[Slipway left out a line of Terraform's output longer than 1 MiB]" in fake.lines
    assert "after the big line" in fake.lines  # reading went on
    assert all(len(line) < 1024 * 1024 for line in fake.lines)


def test_each_command_has_its_own_timeout():
    assert terraform.TIMEOUTS["init"] == 5 * 60
    assert terraform.TIMEOUTS["plan"] == 10 * 60
    assert terraform.TIMEOUTS["show"] == 2 * 60
    assert terraform.TIMEOUTS["apply"] == 40 * 60
    assert terraform.TIMEOUTS["destroy"] == 20 * 60
    assert terraform.SIGINT_GRACE == 30


@pytest.mark.parametrize("command", ["plan", "apply", "destroy"])
async def test_a_timeout_sends_sigint_and_terraform_saves_its_state(fake, monkeypatch, command):
    await make_vm(fake)
    before = fake.stored().serial
    fake.knobs(hang=[command])
    others = {k: 60 for k in terraform.TIMEOUTS}
    monkeypatch.setattr(terraform, "TIMEOUTS", {**others, command: 0.5})
    monkeypatch.setattr(terraform, "SIGINT_GRACE", 10)
    with pytest.raises(TerraformTimeout) as err:
        async with fake.session() as tf:
            if command == "plan":
                await tf.plan()
            elif command == "apply":
                fake.knobs()
                await tf.plan()
                fake.knobs(hang=["apply"])
                await tf.apply()
            else:
                await tf.destroy()
    assert err.value.command == command
    assert "Stopping Terraform; it saves its state first" in fake.lines
    assert not any("killed it" in line for line in fake.lines)
    if command != "plan":  # the fake writes its state on SIGINT, as Terraform does
        assert fake.stored().serial == before + 1
    assert fake.lock_id() is None
    assert not (fake.workdir / terraform.RUN_FILE).exists()


async def test_sigkill_after_the_grace_when_sigint_is_ignored(fake, monkeypatch):
    fake.knobs(hang=["plan"], ignore_sigint=True)
    monkeypatch.setitem(terraform.TIMEOUTS, "plan", 0.5)
    monkeypatch.setattr(terraform, "SIGINT_GRACE", 0.5)
    started = time.monotonic()
    with pytest.raises(TerraformTimeout):
        async with fake.session() as tf:
            await tf.plan()
    assert time.monotonic() - started < 15
    assert any("killed it" in line for line in fake.lines)
    pid = [r for r in fake.runs() if r["argv"][0] == "plan"][-1]["pid"]
    assert not terraform._pid_alive(pid)
    assert fake.lock_id() is None


async def _wait_for_command(fake: FakeTF, command: str, count: int = 1) -> None:
    for _ in range(500):
        if fake.commands().count(command) >= count and any("still working" in line for line in fake.lines):
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"{command} never started")


async def test_a_cancel_stops_terraform_saves_the_state_and_re_raises(fake, monkeypatch):
    await make_vm(fake)
    before = fake.stored().serial
    monkeypatch.setattr(terraform, "SIGINT_GRACE", 10)

    async def destroy():
        async with fake.session() as tf:
            await tf.destroy()

    fake.knobs(hang=["destroy"])
    task = asyncio.create_task(destroy())
    await _wait_for_command(fake, "destroy")
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert fake.stored().serial == before + 1
    assert fake.lock_id() is None
    assert not (fake.workdir / terraform.RUN_FILE).exists()


async def test_a_second_cancel_does_not_cut_the_grace_short(fake, monkeypatch):
    await make_vm(fake)
    before = fake.stored().serial
    monkeypatch.setattr(terraform, "SIGINT_GRACE", 10)
    fake.knobs(hang=["destroy"], sigint_delay=1.0)

    async def destroy():
        async with fake.session() as tf:
            await tf.destroy()

    task = asyncio.create_task(destroy())
    await _wait_for_command(fake, "destroy")
    started = time.monotonic()
    task.cancel()
    await asyncio.sleep(0.2)
    task.cancel()  # Slipway's own shutdown cancelling again
    with pytest.raises(asyncio.CancelledError):
        await task
    assert time.monotonic() - started >= 0.9  # it waited for Terraform to save
    assert fake.stored().serial == before + 1
    assert not any("killed it" in line for line in fake.lines)
    assert fake.lock_id() is None


# ------------------------------------------------------------------ 11. plans


def _doc(*changes) -> dict:
    return {"format_version": "1.2", "resource_changes": [
        {"address": address, "change": {"actions": actions, "before": before, "after": after}}
        for address, actions, before, after in changes
    ]}


def test_plan_changes_reads_each_kind_of_change():
    vm = terraform.VM_ADDRESS
    assert plan_changes(_doc((vm, ["create"], None, {"name": "a"}))) == [Change(vm, ("create",), None, {"name": "a"})]
    [update] = plan_changes(_doc((vm, ["update"], {"cpu": [{"cores": 2}], "name": "a"}, {"cpu": [{"cores": 4}], "name": "a"})))
    assert update.is_update and not update.deletes and changed_attributes(update) == ["cpu"]
    [replace] = plan_changes(_doc((vm, ["delete", "create"], {}, {})))
    assert replace.is_replace and replace.deletes
    [replace2] = plan_changes(_doc((vm, ["create", "delete"], {}, {})))
    assert replace2.is_replace and replace2.actions == ("create", "delete")
    [delete] = plan_changes(_doc((vm, ["delete"], {}, None)))
    assert delete.deletes and not delete.is_replace
    assert plan_changes(_doc((vm, ["no-op"], {}, {}))) == []
    assert plan_changes({"format_version": "1.2"}) == []  # nothing to change: no resource_changes at all
    unknown = Change(vm, ("update",), {"a": 1}, {"a": 1}, {"ipv4_addresses": True})
    assert changed_attributes(unknown) == ["ipv4_addresses"]


@pytest.mark.parametrize("doc", [
    None, [], "plan", {}, {"format_version": 1},
    {"format_version": "1.2", "resource_changes": {}},
    {"format_version": "1.2", "resource_changes": ["x"]},
    {"format_version": "1.2", "resource_changes": [{"change": {"actions": ["create"]}}]},
    {"format_version": "1.2", "resource_changes": [{"address": "a.b"}]},
    {"format_version": "1.2", "resource_changes": [{"address": "a.b", "change": {"actions": []}}]},
    {"format_version": "1.2", "resource_changes": [{"address": "a.b", "change": {"actions": ["forget"]}}]},
    {"format_version": "1.2", "resource_changes": [{"address": "a.b", "change": {"actions": "create"}}]},
])
def test_a_malformed_plan_is_unreadable(doc):
    with pytest.raises(PlanUnreadable) as err:
        plan_changes(doc)
    assert str(err.value) == "Slipway couldn't read Terraform's plan, so it applied nothing"


async def test_show_output_is_never_logged(fake):
    async with fake.session() as tf:
        changes = await tf.plan()
    assert changes[0].after["description"].startswith("Managed by Slipway")
    text = "\n".join(fake.lines)
    assert "format_version" not in text and "Managed by Slipway" not in text and "resource_changes" not in text


async def test_a_plan_is_applied_once_and_a_made_vm_then_plans_nothing(fake):
    async with fake.session() as tf:
        with pytest.raises(TerraformError):
            await tf.apply()  # nothing planned in this session
        await tf.plan()
        await tf.apply()
        assert not (fake.workdir / terraform.PLAN_FILE).exists()
        with pytest.raises(TerraformError):
            await tf.apply()
        assert tf.resource() is not None and not tf.resource().tainted
    vm = fake.vms()["105"]
    assert vm["tags"] == [f"env-{ENV_ID}", "slipway"] and vm["status"] == "running" and vm["lock"] is None
    assert (vm["name"], vm["node"], vm["pool"]) == ("slipway-uat-blue", "pve1", "slipway")
    assert vm["config"]["cores"] == 2 and vm["config"]["memory"] == 4096 and "size=32G" in vm["config"]["scsi0"]
    row = fake.store.rows[fake.machine_id]
    assert row.module_sha == terraform.module_sha(fake.module) and row.terraform_version == "1.16.5"
    async with fake.session() as tf:
        assert await tf.plan() == []
        bigger = make_vars(cores=4)
    async with fake.session(variables=bigger) as tf:
        [change] = await tf.plan()
        assert change.is_update and changed_attributes(change) == ["cpu"]


async def test_unsorted_tags_show_as_a_change(fake):
    await make_vm(fake)
    variables = {**make_vars(), "tags": ["slipway", f"env-{ENV_ID}"]}
    async with fake.session(variables=variables) as tf:
        [change] = await tf.plan()
    assert changed_attributes(change) == ["tags"]


# ------------------------------------------------------------------ 12. the module


def _module_text(name: str) -> str:
    return (terraform.MODULE_DIR / name).read_text()


def test_every_module_variable_is_a_tfvars_key_and_back():
    names = set(re.findall(r'^variable\s+"([a-z_]+)"', _module_text("variables.tf"), re.M))
    assert names == set(make_vars())
    assert names == {
        "endpoint", "node", "vm_id", "name", "pool", "tags", "description", "template_vm_id", "datastore",
        "file_format", "bridge", "vlan_id", "cores", "memory_mb", "disk_gb", "address_cidr", "gateway",
        "dns_servers", "ssh_public_key",
    }
    for name in names:  # each has a validation block
        block = re.search(r'variable\s+"' + name + r'"\s*\{(.*?)\n\}', _module_text("variables.tf"), re.S)
        assert block and "validation {" in block.group(1), name


def test_versions_are_pinned_as_the_constants():
    text = _module_text("versions.tf")
    assert re.search(r'required_version\s*=\s*"= ' + re.escape(terraform.TERRAFORM_VERSION) + '"', text)
    assert re.search(r'source\s*=\s*"' + re.escape(terraform.PROVIDER_SOURCE) + '"', text)
    assert re.search(r'version\s*=\s*"= ' + re.escape(terraform.PROVIDER_VERSION) + '"', text)
    assert (terraform.TERRAFORM_VERSION, terraform.PROVIDER_VERSION) == ("1.16.5", "0.115.0")


def test_the_shipped_lock_file_names_the_provider_version():
    path = terraform.MODULE_DIR / terraform.LOCK_FILE
    if not path.exists():
        pytest.skip("The lock file has to be generated with network access (later-A4.md)")
    text = path.read_text()
    assert f'provider "{terraform.PROVIDER_ADDRESS}"' in text
    assert re.search(r'version\s*=\s*"' + re.escape(terraform.PROVIDER_VERSION) + '"', text)
    assert "zh:" in text and "h1:" in text


def test_main_tf_settings():
    text = _module_text("main.tf")
    code = "\n".join(line.split("#", 1)[0] for line in text.splitlines())  # comments left out
    assert re.search(r"reboot_after_update\s*=\s*false", code)
    assert re.search(r"timeout_clone\s*=\s*1800", code)
    assert re.search(r"ignore_changes\s*=\s*\[clone\]", code)
    assert re.search(r"insecure\s*=\s*false", code)
    assert re.search(r"stop_on_destroy\s*=\s*true", code) and re.search(r"purge_on_destroy\s*=\s*true", code)
    assert re.search(r"started\s*=\s*true", code) and re.search(r"on_boot\s*=\s*true", code)
    assert re.search(r"file_format\s*=\s*var\.file_format", code)
    assert "api_token" not in code and "password" not in code  # the token is only in the environment
    has_upgrade = re.search(r"^\s*upgrade\s*=\s*false", code, re.M) is not None
    assert has_upgrade == bool(terraform.INIT_UPGRADE_IN_SCHEMA)
    assert re.search(r'value\s*=\s*proxmox_virtual_environment_vm\.vm\.vm_id', _module_text("outputs.tf"))
    # The VM's Linux user is the one Slipway logs in as everywhere (plan Decision 10).
    assert re.findall(r'^\s*username\s*=\s*"([^"]*)"', code, re.M) == [cloudinit.GUEST_USER]


def test_tfvars_values():
    variables = make_vars()
    assert variables["tags"] == [f"env-{ENV_ID}", "slipway"] == sorted(variables["tags"])
    assert variables["description"] == (
        f"Managed by Slipway: environment uat ({ENV_ID}), blue slot. Change or delete it from Slipway, not here."
    )
    assert variables["dns_servers"] == ["10.0.0.1"]  # none named: the gateway
    assert variables["address_cidr"] == "10.0.0.12/24" and variables["vlan_id"] is None
    assert variables["file_format"] == "raw"
    for kind in ("dir", "nfs", "cifs", "glusterfs"):
        assert terraform.file_format_for(kind) == "qcow2"
    for kind in ("lvmthin", "lvm", "zfspool", "rbd", None, ""):
        assert terraform.file_format_for(kind) == "raw"
    on_dir = terraform.tfvars(
        endpoint="https://pve.lan:8006/", name="slipway-uat-blue", environment_id=ENV_ID, environment_name="uat",
        slot="blue", spec={**SPEC, "storage_type": "nfs", "vlan_tag": 20},
        network={**NETWORK, "dns_servers": ["1.1.1.1", "9.9.9.9"]}, size=SIZE, vmid=105, ssh_public_key=PUBLIC_KEY + "\n",
    )
    assert on_dir["file_format"] == "qcow2" and on_dir["vlan_id"] == 20
    assert on_dir["dns_servers"] == ["1.1.1.1", "9.9.9.9"] and on_dir["ssh_public_key"] == PUBLIC_KEY
    frozen = {**SPEC, "storage_type": "dir", "file_format": "raw"}  # the frozen spec's choice wins
    assert terraform.tfvars(
        endpoint="x", name="n", environment_id=ENV_ID, environment_name="uat", slot="blue", spec=frozen,
        network=NETWORK, size=SIZE, vmid=1, ssh_public_key=PUBLIC_KEY,
    )["file_format"] == "raw"
    dumped = json.dumps(variables)
    assert TOKEN not in dumped and SECRET_PART not in dumped


# ------------------------------------------------------------------ 13. the working folder


async def test_the_working_folder_is_private(fake):
    async with fake.session():
        pass
    wd = fake.workdir
    assert stat.S_IMODE(os.stat(wd.path).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(wd.root).st_mode) == 0o700
    for name in ("terraform.tfvars.json", "proxmox-ca.pem"):
        assert stat.S_IMODE(os.stat(wd / name).st_mode) == 0o600
    assert (wd / terraform.LOCK_FILE).read_text() == (fake.module / terraform.LOCK_FILE).read_text()
    assert json.loads((wd / "terraform.tfvars.json").read_text()) == make_vars()


@pytest.mark.parametrize("ca", ["", "garbage", "two"])
async def test_the_ca_must_be_one_certificate_before_anything_is_written(fake, ca):
    pem = make_cert() + make_cert("other") if ca == "two" else ca
    with pytest.raises(TerraformError) as err:
        async with fake.session(ca=pem):
            pass
    assert "isn't exactly one certificate" in str(err.value)
    assert not Path(fake.settings.dir).exists()
    assert fake.store.rows == {} and fake.runs() == []


async def test_old_files_are_cleared_from_the_folder(fake):
    wd = fake.workdir
    wd.create()
    for name in ("crash.log", "tfplan", "extra.tf", "x.auto.tfvars.json"):
        (wd / name).write_text("old")
    (wd / "ca" / "other.pem").write_text(make_cert())
    async with fake.session():
        pass
    for name in ("crash.log", "extra.tf", "x.auto.tfvars.json"):
        assert not (wd / name).exists()
    assert list((wd / "ca").iterdir()) == []


async def test_a_newer_store_state_is_written_to_the_folder(fake):
    wd = fake.workdir
    wd.create()
    wd.write_state(state_doc("L1", 3))
    await fake.store.save(fake.machine_id, terraform.parse_state(state_doc("L1", 5)), module_sha=None, terraform_version=None)
    async with fake.session():
        assert json.loads(wd.state_path.read_text())["serial"] == 5
    assert fake.stored().serial == 5


async def test_a_newer_folder_state_is_saved_first_and_logged(fake):
    wd = fake.workdir
    wd.create()
    wd.write_state(state_doc("L1", 7))
    await fake.store.save(fake.machine_id, terraform.parse_state(state_doc("L1", 5)), module_sha=None, terraform_version=None)
    saves = fake.store.saves
    async with fake.session():
        assert fake.stored().serial == 7 and fake.store.saves == saves + 1
    assert "Kept Terraform's state #7 from the working folder (Slipway stopped before saving it)" in fake.lines
    assert fake.store.saves == saves + 1  # nothing moved after that: not saved again


async def test_a_store_without_lineage_takes_the_folders_state(fake):
    wd = fake.workdir
    wd.create()
    wd.write_state(state_doc("L9", 1))
    await fake.store.lock(fake.machine_id, uuid.uuid4())  # the row exists, never saved: NULL lineage
    fake.store.rows[fake.machine_id].lock_id = None
    async with fake.session():
        pass
    assert fake.stored().lineage == "L9" and fake.stored().serial == 1


async def test_two_lineages_are_refused(fake):
    wd = fake.workdir
    wd.create()
    wd.write_state(state_doc("L1", 9))
    await fake.store.save(fake.machine_id, terraform.parse_state(state_doc("L2", 3)), module_sha=None, terraform_version=None)
    with pytest.raises(TerraformError) as err:
        async with fake.session():
            pass
    assert str(err.value).startswith("Slipway has two different Terraform states for slipway-uat-blue; it changed nothing.")
    assert str(wd.path) in str(err.value)
    assert json.loads(wd.state_path.read_text())["lineage"] == "L1" and fake.stored().lineage == "L2"
    assert fake.lock_id() is None and fake.runs() == []


async def test_a_state_over_4_mib_is_refused_on_save(fake):
    wd = fake.workdir
    wd.create()
    wd.write_state(state_doc("L1", 2, pad=terraform.MAX_STATE_BYTES))
    with pytest.raises(TerraformError) as err:
        async with fake.session():
            pass
    assert str(err.value) == "Terraform's state for slipway-uat-blue is larger than Slipway keeps (4 MiB)"
    assert fake.stored().empty and fake.lock_id() is None

    # And after a command: the session's own save refuses it.
    wd.write_state(state_doc("L1", 2))
    async with fake.session():
        pass
    with pytest.raises(TerraformError) as err:
        async with fake.session():
            wd.write_state(state_doc("L1", 3, pad=terraform.MAX_STATE_BYTES))
    assert "larger than Slipway keeps (4 MiB)" in str(err.value)
    assert fake.stored().serial == 2 and fake.lock_id() is None


async def test_init_runs_only_when_needed(fake):
    async with fake.session():
        pass
    assert fake.commands().count("init") == 1
    marker = json.loads((fake.workdir / terraform.INIT_FILE).read_text())
    assert marker == {"module_sha": terraform.module_sha(fake.module), "terraform_version": "1.16.5"}
    init = [r for r in fake.runs() if r["argv"][0] == "init"][0]
    assert init["argv"] == ["init", "-input=false", "-no-color", "-lockfile=readonly"]

    async with fake.session():
        pass
    assert fake.commands().count("init") == 1  # initialised for this module and Terraform

    (fake.workdir / terraform.INIT_FILE).write_text(json.dumps({**marker, "module_sha": "0" * 64}))
    async with fake.session():
        pass
    assert fake.commands().count("init") == 2

    (fake.workdir / terraform.INIT_FILE).write_text(json.dumps({**marker, "terraform_version": "1.15.0"}))
    async with fake.session():
        pass
    assert fake.commands().count("init") == 3

    shutil.rmtree(fake.workdir / ".terraform")
    async with fake.session():
        pass
    assert fake.commands().count("init") == 4


async def test_a_lock_file_whose_hash_does_not_match_fails_init(fake):
    (fake.module / terraform.LOCK_FILE).write_text(lock_file("0.115.0").replace(provider_hash("0.115.0"), "h1:bad="))
    with pytest.raises(TerraformFailed) as err:
        async with fake.session():
            pass
    assert err.value.command == "init"
    assert any("doesn't match any of the checksums" in line for line in fake.lines)
    assert fake.lock_id() is None


async def test_a_provider_upgrade_re_initialises(fake):
    await make_vm(fake)
    newer = fake.make_module("0.116.0", name="newer")
    fake.knobs(mirror=["0.115.0", "0.116.0"])

    # Without a new init, a plan with the newer lock file fails as Terraform does.
    wd = fake.workdir
    shutil.copy(newer / terraform.LOCK_FILE, wd / terraform.LOCK_FILE)
    runner = terraform.SubprocessTerraform(settings=fake.settings, workdir=wd, token=TOKEN, say=fake.say, hide=fake.hide)
    with pytest.raises(TerraformFailed):
        await runner.run(["plan", "-input=false", "-no-color", "-out=tfplan"], timeout_key="plan")
    assert any("doesn't match the dependency lock file" in line for line in fake.lines)

    # The session sees another module hash and initialises again; the plan then passes.
    inits = fake.commands().count("init")
    async with fake.session(module=newer) as tf:
        assert await tf.plan() == []
    assert fake.commands().count("init") == inits + 1


async def test_no_lock_file_in_the_module_is_refused(fake):
    (fake.module / terraform.LOCK_FILE).unlink()
    with pytest.raises(TerraformError) as err:
        async with fake.session():
            pass
    assert "has no .terraform.lock.hcl" in str(err.value)
    assert fake.runs() == []


async def test_a_missing_cli_config_is_refused(fake):
    fake.cli_config.unlink()
    with pytest.raises(TerraformError) as err:
        async with fake.session():
            pass
    assert "settings file" in str(err.value) and fake.runs() == []


# ------------------------------------------------------------------ 14. locks


async def test_a_lock_held_by_a_running_deployment_refuses(fake):
    other = uuid.uuid4()
    fake.store.active.add(other)
    await fake.store.lock(fake.machine_id, other)
    with pytest.raises(TerraformError) as err:
        async with fake.session():
            pass
    assert str(err.value) == f"Terraform state of slipway-uat-blue is in use by deployment {str(other)[:8]}; wait for it to finish"
    assert fake.lock_id() == other
    assert not fake.workdir.exists() and fake.runs() == []


@pytest.mark.parametrize("why", ["finished", "row gone"])
async def test_a_lock_of_a_deployment_that_is_not_running_is_taken_over(fake, why):
    other = uuid.uuid4()
    fake.store.active.add(other)
    await fake.store.lock(fake.machine_id, other)
    fake.store.active.discard(other)  # finished, or its row cascaded away: either way not queued or running
    async with fake.session():
        assert fake.lock_id() == fake.deployment_id
    assert f"Took over the Terraform lock of slipway-uat-blue from deployment {str(other)[:8]}, which isn't running" in fake.lines
    assert fake.lock_id() is None


async def test_a_live_terraform_in_the_run_file_refuses(fake, monkeypatch):
    wd = fake.workdir
    wd.create()
    (wd / terraform.RUN_FILE).write_text(json.dumps({"pid": os.getpid(), "deployment_id": str(fake.deployment_id), "args": ["apply"]}))
    monkeypatch.setattr(terraform, "_process_command", lambda pid: ["/usr/bin/python3", str(fake.bin), "apply"])
    with pytest.raises(TerraformError) as err:
        async with fake.session():
            pass
    assert str(err.value) == (
        f"Terraform is still running for slipway-uat-blue (from deployment {str(fake.deployment_id)[:8]}, "
        f"pid {os.getpid()}): wait for it to finish, then retry"
    )
    assert (wd / terraform.RUN_FILE).exists()  # kept for the next check
    assert fake.lock_id() is None and fake.runs() == []

    # The same pid running something else isn't Terraform.
    monkeypatch.setattr(terraform, "_process_command", lambda pid: ["/usr/bin/python3", "-m", "pytest"])
    async with fake.session():
        pass
    assert not (wd / terraform.RUN_FILE).exists()


async def test_a_dead_pid_in_the_run_file_is_ignored(fake):
    proc = await asyncio.create_subprocess_exec(sys.executable, "-c", "pass")
    await proc.wait()
    wd = fake.workdir
    wd.create()
    (wd / terraform.RUN_FILE).write_text(json.dumps({"pid": proc.pid, "deployment_id": None, "args": ["apply"]}))
    async with fake.session() as tf:
        await tf.plan()
    assert not (wd / terraform.RUN_FILE).exists()


async def test_the_run_file_names_the_running_command(fake):
    fake.knobs(hang=["plan"])

    async def plan():
        async with fake.session() as tf:
            await tf.plan()

    task = asyncio.create_task(plan())
    await _wait_for_command(fake, "plan")
    seen = json.loads((fake.workdir / terraform.RUN_FILE).read_text())
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert seen["args"][0] == "plan" and seen["deployment_id"] == str(fake.deployment_id)
    assert seen["pid"] == [r for r in fake.runs() if r["argv"][0] == "plan"][-1]["pid"]
    assert not (fake.workdir / terraform.RUN_FILE).exists()


async def test_after_success_the_state_is_saved_and_the_lock_released(fake):
    await make_vm(fake)
    stored = fake.stored()
    assert stored.serial == 1 and stored.lineage and stored.state == fake.workdir.state_path.read_text()
    assert terraform.state_resource(stored.state).attributes["vm_id"] == 105
    assert fake.lock_id() is None


async def test_after_a_failed_apply_the_tainted_state_is_saved(fake):
    fake.knobs(fail_after_clone=True)
    with pytest.raises(TerraformFailed) as err:
        async with fake.session() as tf:
            await tf.plan()
            await tf.apply()
    assert err.value.command == "apply"
    assert terraform.state_resource(fake.stored().state).tainted
    vm = fake.vms()["105"]
    assert vm["tags"] == [] and vm["lock"] is None  # cloned, never tagged
    assert fake.lock_id() is None
    fake.knobs()
    async with fake.session() as tf:
        [change] = await tf.plan()
        assert change.is_replace and tf.resource().tainted


async def test_a_terraform_killed_after_the_clone_leaves_no_state(fake):
    fake.knobs(die_after_clone=True, clone_lock_outlives=3)
    with pytest.raises(TerraformFailed):
        async with fake.session() as tf:
            await tf.plan()
            await tf.apply()
    vm = fake.vms()["105"]
    assert vm["lock"] == "clone" and vm["tags"] == [] and vm["description"].startswith("Managed by Slipway")
    [task] = [t for t in fake.proxmox.state["tasks"].values() if t["vmid"] == 105]
    assert task["type"] == "qmclone" and task["status"] == "running" and task["polls"] == 3
    assert fake.stored().empty and fake.lock_id() is None


async def test_state_rm_and_destroy(fake):
    await make_vm(fake)
    async with fake.session() as tf:
        await tf.state_rm()
        assert tf.resource() is None
    assert terraform.state_resource(fake.stored().state) is None and fake.stored().serial == 2
    assert "105" in fake.vms()  # state rm forgets, never deletes

    with fake.proxmox.edit() as state:
        state["vms"].pop("105")
    await make_vm(fake)
    async with fake.session() as tf:
        await tf.destroy()
    assert fake.vms() == {} and terraform.state_resource(fake.stored().state) is None
    fake.workdir.remove()
    assert not fake.workdir.exists()


def test_settings_from_config():
    from types import SimpleNamespace

    config = SimpleNamespace(
        terraform_binary="tofu", terraform_cli_config="/etc/x", terraform_dir="", terraform_parallel=3,
        storage_dir="/var/lib/slipway",
    )
    settings = TerraformSettings.from_config(config)
    assert settings == TerraformSettings(binary="tofu", cli_config="/etc/x", dir="/var/lib/slipway/terraform", parallel=3)
    assert TerraformSettings.from_config(SimpleNamespace(**{**vars(config), "terraform_dir": "/t"})).dir == "/t"


def test_a_missing_binary_is_named():
    with pytest.raises(TerraformError) as err:
        terraform.resolve_binary("no-such-terraform-binary")
    assert "SLIPWAY_TERRAFORM_BINARY" in str(err.value)


def test_workdir_names_must_be_uuids(tmp_path):
    with pytest.raises(ValueError):
        terraform.Workdir(tmp_path, "../../etc")


async def test_the_clone_lock_follows_fakeproxmoxs_knob(fake):
    fake.proxmox.clone_lock_outlives(5)
    fake.knobs(die_after_clone=True)
    with pytest.raises(TerraformFailed):
        async with fake.session() as tf:
            await tf.plan()
            await tf.apply()
    [task] = [t for t in fake.proxmox.state["tasks"].values() if t["vmid"] == 105]
    assert task["polls"] == 5 and fake.vms()["105"]["lock"] == "clone"


async def test_a_grow_with_snapshots_fails_when_fakeproxmox_refuses_it(fake):
    await make_vm(fake)
    fake.proxmox.add_snapshot(105, "slipway-20261115T100000Z")
    fake.proxmox.resize_refused_with_snapshots()
    with pytest.raises(TerraformFailed):
        async with fake.session(variables=make_vars(disk_gb=40)) as tf:
            [change] = await tf.plan()
            assert changed_attributes(change) == ["disk"]
            await tf.apply()
    assert "size=32G" in fake.vms()["105"]["config"]["scsi0"]
    assert any("can't resize a disk that has snapshots" in line for line in fake.lines)
