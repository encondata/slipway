"""Phase 5 test 39: the image's Terraform, provider mirror, ESXi packages and stop grace agree with the code.

Everything here reads files. Nothing is built, pulled or downloaded.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
import yaml

from slipway.core.config import Settings
from slipway.services import terraform

REPO = Path(__file__).resolve().parents[1]
DOCKERFILE = REPO / "Dockerfile"
COMPOSE = REPO / "docker-compose.yml"
TERRAFORMRC = REPO / "docker" / "terraformrc"
REQUIREMENTS = REPO / "requirements-esxi.txt"
PYPROJECT = REPO / "pyproject.toml"
LOCK_FILE = terraform.MODULE_DIR / terraform.LOCK_FILE

ARCHITECTURES = ("linux_amd64", "linux_arm64")
SHA256 = re.compile(r"[0-9a-f]{64}")
MIRROR = "/opt/terraform/providers"


def dockerfile() -> str:
    return DOCKERFILE.read_text()


def build_args() -> dict[str, str]:
    """Every ``ARG NAME=value`` of the Dockerfile."""
    return dict(re.findall(r"^ARG (\w+)=(\S+)\s*$", dockerfile(), re.M))


def instructions() -> list[str]:
    """The Dockerfile's instructions, continuation lines joined, comments left out."""
    joined = re.sub(r"\\\n", " ", dockerfile())
    return [line.strip() for line in joined.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def sha_args(kind: str) -> dict[str, str]:
    """``{architecture: value}`` of ``<KIND>_SHA256_LINUX_<ARCH>``."""
    args = build_args()
    return {arch: args.get(f"{kind}_SHA256_{arch.upper()}", "") for arch in ARCHITECTURES}


def pyproject() -> dict:
    return tomllib.loads(PYPROJECT.read_text())


def pyvmomi_pin(requirements: list[str]) -> str:
    pins = [r for r in requirements if r.lower().startswith("pyvmomi")]
    assert len(pins) == 1, requirements
    return pins[0].split("#", 1)[0].strip()


# -------------------------------------------------------------------------- Terraform


def test_the_dockerfile_pins_the_module_versions():
    args = build_args()
    assert args["TERRAFORM_VERSION"] == terraform.TERRAFORM_VERSION
    assert args["PROXMOX_PROVIDER_VERSION"] == terraform.PROVIDER_VERSION
    versions_tf = (terraform.MODULE_DIR / "versions.tf").read_text()
    assert f'required_version = "= {terraform.TERRAFORM_VERSION}"' in versions_tf
    assert f'version = "= {terraform.PROVIDER_VERSION}"' in versions_tf


@pytest.mark.parametrize("kind", ["TERRAFORM", "PROXMOX_PROVIDER"])
def test_each_architecture_has_a_sha256_line(kind):
    for arch, value in sha_args(kind).items():
        assert value, f"no {kind}_SHA256_{arch.upper()} line"
        assert SHA256.fullmatch(value), (arch, value)


def test_every_download_is_checked_before_it_is_used():
    run = next(i for i in instructions() if "releases.hashicorp.com" in i)
    assert run.count("sha256sum -c") == 2
    assert run.index("sha256sum -c") < run.index("unzip")  # Terraform is checked before it is unpacked
    assert "${TERRAFORM_SHA256_LINUX_AMD64}" in run and "${TERRAFORM_SHA256_LINUX_ARM64}" in run
    assert "${PROXMOX_PROVIDER_SHA256_LINUX_AMD64}" in run and "${PROXMOX_PROVIDER_SHA256_LINUX_ARM64}" in run
    # An architecture with no recorded sums stops the build.
    assert "exit 1" in run
    assert f"{MIRROR}/registry.terraform.io/bpg/proxmox" in run
    assert "terraform-provider-proxmox_${PROXMOX_PROVIDER_VERSION}_linux_${TARGETARCH}.zip" in run


def test_the_final_image_has_terraform_the_mirror_and_the_cli_config():
    steps = instructions()
    assert "COPY --from=terraform /usr/local/bin/terraform /usr/local/bin/terraform" in steps
    assert f"COPY --from=terraform {MIRROR} {MIRROR}" in steps
    assert f"COPY docker/terraformrc {Settings.model_fields['terraform_cli_config'].default}" in steps


def test_terraformrc_allows_only_the_mirror():
    text = TERRAFORMRC.read_text()
    body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "disable_checkpoint = true" in body
    assert re.search(r'filesystem_mirror\s*{\s*path\s*=\s*"' + re.escape(MIRROR) + r'"', body)
    assert re.findall(r"include\s*=\s*\[([^\]]*)\]", body) == [f'"{terraform.PROVIDER_ADDRESS}"']
    assert re.search(r'direct\s*{\s*exclude\s*=\s*\["\*/\*"\]\s*}', body)
    assert "network_mirror" not in body
    assert "credentials" not in body


def test_the_lock_file_hashes_equal_the_dockerfile_provider_sums():
    text = LOCK_FILE.read_text()
    block = re.search(r'provider "' + re.escape(terraform.PROVIDER_ADDRESS) + r'"\s*{(.*?)\n}', text, re.S)
    assert block, text
    assert re.search(r'^\s*version\s*=\s*"' + re.escape(terraform.PROVIDER_VERSION) + '"', block.group(1), re.M)
    zh = set(re.findall(r'"zh:([0-9a-f]{64})"', block.group(1)))
    for arch, value in sha_args("PROXMOX_PROVIDER").items():
        assert value in zh, arch


def test_the_package_ships_the_module_and_its_lock_file():
    data = pyproject()["tool"]["setuptools"]["package-data"]["slipway"]
    assert "terraform/**/*" in data
    # setuptools' `*` skips dotfiles, so the lock file needs its own pattern.
    assert "terraform/**/.terraform.lock.hcl" in data


# ------------------------------------------------------------------------------ ESXi


def test_requirements_esxi_pins_the_pyproject_version_with_hashes():
    text = REQUIREMENTS.read_text()
    entries = re.sub(r"\\\n\s*", " ", text)
    pins = {}
    for line in entries.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, rest = line.partition(" ")
        hashes = re.findall(r"--hash=sha256:(\S+)", rest)
        assert hashes and all(SHA256.fullmatch(h) for h in hashes), line
        assert "==" in name, line
        pins[name.split("==")[0].lower()] = name
    extras = pyproject()["project"]["optional-dependencies"]
    assert pins["pyvmomi"] == pyvmomi_pin(extras["esxi"]) == pyvmomi_pin(extras["dev"]) == "pyvmomi==8.0.3.0.1"
    assert set(pins) == {"pyvmomi", "six"}  # pyvmomi's one dependency, since --no-deps installs nothing else


def test_requirements_esxi_is_installed_with_hashes_before_slipway():
    steps = instructions()
    final = steps[max(i for i, s in enumerate(steps) if s.startswith("FROM ")):]
    esxi = final.index("RUN pip install --require-hashes --no-deps -r requirements-esxi.txt")
    assert final.index("COPY requirements-esxi.txt ./") < esxi
    assert esxi < final.index("RUN pip install .")


# ------------------------------------------------------------------------- stop grace


def seconds(value: str | int) -> float:
    if isinstance(value, int):
        return float(value)
    total = 0.0
    for amount, unit in re.findall(r"(\d+(?:\.\d+)?)(h|ms|m|s|us)", value):
        total += float(amount) * {"h": 3600, "m": 60, "s": 1, "ms": 0.001, "us": 0.000001}[unit]
    return total


def test_compose_gives_terraform_time_to_stop():
    compose = yaml.safe_load(COMPOSE.read_text())
    grace = seconds(compose["services"]["slipway"]["stop_grace_period"])
    assert grace >= 60
    assert grace > terraform.SIGINT_GRACE + 15  # Terraform's SIGINT grace plus a margin to shut down
