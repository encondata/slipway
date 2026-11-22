"""Phase 5 test 6: ESXi cloud-init documents (``slipway.services.cloudinit``)."""

from __future__ import annotations

import base64
import textwrap
import uuid

import asyncssh
import pytest
import yaml

from slipway.services import cloudinit

from tests.hypervisor_guard import no_real_hypervisors  # noqa: F401  (the fixture)

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")

MACHINE = uuid.UUID("2b0c3a4e-1111-4222-8333-444455556666")
HOST = "slipway-uat-blue"


@pytest.fixture(scope="module")
def keys():
    host = asyncssh.generate_private_key("ssh-ed25519", comment="slipway@slipway-uat-blue")
    client = asyncssh.generate_private_key("ssh-ed25519", comment="slipway@slipway-uat-blue")
    return {
        "private": host.export_private_key("openssh").decode(),
        "public": host.export_public_key("openssh").decode().strip(),
        "client": client.export_public_key("openssh").decode().strip(),
    }


def test_metadata_exact_yaml():
    meta = cloudinit.metadata(MACHINE, HOST, "10.0.0.12/24", "10.0.0.1", ["10.0.0.53", "1.1.1.1"])
    assert meta == textwrap.dedent("""\
        instance-id: slipway-2b0c3a4e-1111-4222-8333-444455556666
        local-hostname: slipway-uat-blue
        network:
          version: 2
          ethernets:
            primary:
              match:
                driver: vmxnet3
              dhcp4: false
              dhcp6: false
              addresses:
                - 10.0.0.12/24
              routes:
                - to: default
                  via: 10.0.0.1
              nameservers:
                addresses:
                  - 10.0.0.53
                  - 1.1.1.1
        cleanup-guestinfo:
          - userdata
        """)
    assert yaml.safe_load(meta)["network"]["ethernets"]["primary"]["routes"] == [{"to": "default", "via": "10.0.0.1"}]


def test_metadata_without_dns_servers_uses_the_gateway():
    meta = yaml.safe_load(cloudinit.metadata(str(MACHINE), HOST, "10.0.0.12/24", "10.0.0.1", []))
    assert meta["network"]["ethernets"]["primary"]["nameservers"] == {"addresses": ["10.0.0.1"]}
    meta = yaml.safe_load(cloudinit.metadata(str(MACHINE), HOST, "10.0.0.12/24", "10.0.0.1", None))
    assert meta["network"]["ethernets"]["primary"]["nameservers"] == {"addresses": ["10.0.0.1"]}


def test_userdata_exact_yaml(keys):
    user = cloudinit.userdata(HOST, keys["client"], keys["private"], keys["public"])
    private = textwrap.indent(keys["private"].strip(), "    ")
    assert user == (
        "#cloud-config\n"
        "hostname: slipway-uat-blue\n"
        "manage_etc_hosts: true\n"
        "users:\n"
        "  - name: slipway\n"
        "    gecos: Slipway\n"
        "    shell: /bin/bash\n"
        "    sudo: ALL=(ALL) NOPASSWD:ALL\n"
        "    lock_passwd: true\n"
        "    ssh_authorized_keys:\n"
        f"      - {keys['client']}\n"
        "ssh_pwauth: false\n"
        "disable_root: true\n"
        "ssh_deletekeys: true\n"
        "ssh_genkeytypes: []\n"
        "ssh_keys:\n"
        "  ed25519_private: |\n"
        f"{private}\n"
        f"  ed25519_public: {keys['public']}\n"
        "growpart:\n"
        "  mode: auto\n"
        "  devices:\n"
        "    - /\n"
        "resize_rootfs: true\n"
    )
    doc = yaml.safe_load(user)
    assert doc["users"][0]["name"] == cloudinit.GUEST_USER == "slipway"
    assert not hasattr(cloudinit, "DEPLOY_USER")
    assert doc["ssh_keys"]["ed25519_private"] == keys["private"].strip() + "\n"
    assert doc["users"][0]["ssh_authorized_keys"] == [keys["client"]]
    assert doc["ssh_genkeytypes"] == []


def test_guestinfo_and_scrub(keys):
    meta = cloudinit.metadata(MACHINE, HOST, "10.0.0.12/24", "10.0.0.1", [])
    user = cloudinit.userdata(HOST, keys["client"], keys["private"], keys["public"])
    info = cloudinit.guestinfo(meta, user)
    assert list(info) == ["guestinfo.metadata", "guestinfo.metadata.encoding",
                          "guestinfo.userdata", "guestinfo.userdata.encoding"]
    assert info["guestinfo.metadata.encoding"] == info["guestinfo.userdata.encoding"] == "base64"
    assert base64.b64decode(info["guestinfo.metadata"]).decode() == meta
    assert base64.b64decode(info["guestinfo.userdata"]).decode() == user
    # The private key never appears in the clear in what is written to the VM's extraConfig.
    assert "PRIVATE KEY" not in "".join(info.values())
    assert cloudinit.scrub() == {"guestinfo.userdata": "", "guestinfo.userdata.encoding": ""}
    cloudinit.scrub()["guestinfo.userdata"] = "changed"
    assert cloudinit.scrub()["guestinfo.userdata"] == ""


@pytest.mark.parametrize("args, text", [
    ((MACHINE, "Slipway-UAT", "10.0.0.12/24", "10.0.0.1", []), "isn't a host name"),
    ((MACHINE, "uat\nruncmd: [reboot]", "10.0.0.12/24", "10.0.0.1", []), "isn't a host name"),
    ((MACHINE, "slipway-uat-blue\n", "10.0.0.12/24", "10.0.0.1", []), "isn't a host name"),
    ((MACHINE, "x" * 64, "10.0.0.12/24", "10.0.0.1", []), "isn't a host name"),
    ((MACHINE, HOST, "10.0.0.12", "10.0.0.1", []), "with its prefix"),
    ((MACHINE, HOST, "10.0.0.012/24", "10.0.0.1", []), "with its prefix"),
    ((MACHINE, HOST, "10.0.0.0/24", "10.0.0.1", []), "network address"),
    ((MACHINE, HOST, "10.0.0.255/24", "10.0.0.1", []), "broadcast address"),
    ((MACHINE, HOST, "10.0.0.12/31", "10.0.0.13", []), "between /8 and /30"),
    ((MACHINE, HOST, "fd00::12/64", "fd00::1", []), "IPv4"),
    ((MACHINE, HOST, "10.0.0.12/24", "10.0.1.1", []), "isn't a host address"),
    ((MACHINE, HOST, "10.0.0.12/24", "10.0.0.12", []), "VM's own address"),
    ((MACHINE, HOST, "10.0.0.12/24", "10.0.0.1\n", []), "isn't an IPv4 address"),
    ((MACHINE, HOST, "10.0.0.12/24", "10.0.0.1", ["1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4"]), "at most 3"),
    ((MACHINE, HOST, "10.0.0.12/24", "10.0.0.1", ["1.1.1.01"]), "isn.t an IPv4 address"),
    ((MACHINE, HOST, "10.0.0.12/24", "10.0.0.1", ["1.1.1.1\n- 6.6.6.6"]), "isn't an IPv4 address"),
    (("not-a-uuid", HOST, "10.0.0.12/24", "10.0.0.1", []), "badly formed"),
])
def test_metadata_refuses_bad_values(args, text):
    with pytest.raises(ValueError, match=text):
        cloudinit.metadata(*args)


def test_userdata_refuses_bad_values(keys):
    other = asyncssh.generate_private_key("ssh-ed25519")
    rsa = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
    good = (HOST, keys["client"], keys["private"], keys["public"])

    def refused(text, **changes):
        names = ("hostname", "ssh_public_key", "host_key_private", "host_key_public")
        args = dict(zip(names, good))
        args.update(changes)
        with pytest.raises(ValueError, match=text):
            cloudinit.userdata(**args)

    refused("isn't a host name", hostname="bad host")
    refused("one OpenSSH public key line", ssh_public_key=keys["client"] + "\nruncmd: [reboot]")
    refused("isn't an OpenSSH public key", ssh_public_key="ssh-ed25519 not-base64")
    refused("one OpenSSH public key line", ssh_public_key="")
    refused("must be an ed25519 key", host_key_public=rsa.export_public_key("openssh").decode())
    refused("isn't the private half", host_key_private=other.export_private_key("openssh").decode())
    refused("isn't the private half", host_key_private=rsa.export_private_key("openssh").decode(),
            host_key_public=keys["public"])
    refused("must be an OpenSSH private key", host_key_private="")
    refused("can't be read", host_key_private="-----BEGIN OPENSSH PRIVATE KEY-----\nxx\n-----END OPENSSH PRIVATE KEY-----\n")
    locked = asyncssh.import_private_key(keys["private"]).export_private_key("openssh", passphrase="pw").decode()
    refused("can't be read", host_key_private=locked)
