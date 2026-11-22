"""Cloud-init for the VMs Slipway makes on ESXi (phase 5 §8.4), ported from Sirdar's ``cloudinit.py``.

An ESXi VM gets its settings through VMware's guestinfo data source: ``guestinfo.metadata`` (the
instance id, host name and a static netplan configuration) and ``guestinfo.userdata`` (the
``slipway`` user, Slipway's client key and the SSH host key Slipway generated), both base64.
``GUEST_USER`` is the Linux user Slipway logs in as on every machine it makes (droplets too); it is
not the Proxmox API user ``slipway@pve``.

The host key is how Slipway avoids trusting a VM on first use (phase 5 D8): Slipway makes the pair,
cloud-init installs it (deleting any key the seed image had, and generating no others), and Slipway
pins exactly that key once an SSH connection presents it. The private half is then scrubbed from
the VM's guestinfo (``scrub``) and from Slipway's database.

Every value is checked again here before any YAML is written, so nothing a caller got wrong (or a
hostile value) can add keys to the documents; the YAML itself is written by PyYAML's safe dumper.
Droplets have their own user-data (``do_rules.droplet_userdata``, with no sudo); they share only
``GUEST_USER``.
"""

from __future__ import annotations

import base64
import ipaddress
import re
import uuid
from typing import Any

import asyncssh
import yaml

from slipway.services import vmnet

# The Linux user on every machine Slipway makes: the host row's username and the deploy root's owner.
GUEST_USER = "slipway"
# A DNS label: every name ``vmnet.check_vm_name`` accepts, and the host names phase 4 gives droplets.
HOSTNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

# An empty value deletes a guestinfo key (VMware's rule); after the pin the private host key goes.
SCRUB = {"guestinfo.userdata": "", "guestinfo.userdata.encoding": ""}


class _Dumper(yaml.SafeDumper):
    """Block style, list items indented under their key, multi-line strings as ``|`` literals."""

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> Any:
        return super().increase_indent(flow, False)


def _str(dumper: yaml.SafeDumper, value: str) -> yaml.ScalarNode:
    if "\n" in value:
        return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", value)


_Dumper.add_representer(str, _str)


def _dump(doc: dict[str, Any]) -> str:
    return yaml.dump(doc, Dumper=_Dumper, sort_keys=False, default_flow_style=False, width=4096)


# ---------------------------------------------------------------------------- checks


def check_hostname(value: Any) -> str:
    if not isinstance(value, str) or not HOSTNAME_RE.fullmatch(value):
        raise ValueError(f"{value!r} isn't a host name a VM can have (lower-case letters, digits and hyphens, at most 63)")
    return value


def check_address_cidr(value: Any) -> ipaddress.IPv4Interface:
    """A VM's own address with its prefix, such as ``10.0.0.12/24``, written canonically."""
    text = value if isinstance(value, str) else ""
    try:
        iface = ipaddress.ip_interface(text)
    except ValueError:
        raise ValueError(f"{value!r} isn't an address with its prefix, such as 10.0.0.12/24") from None
    if iface.version != 4 or "/" not in text or str(iface) != text:
        raise ValueError(f"{value!r} isn't written as an IPv4 address with its prefix, such as 10.0.0.12/24")
    low, high = vmnet.PREFIX_RANGE
    if not low <= iface.network.prefixlen <= high:
        raise ValueError(f"{value}'s prefix must be between /{low} and /{high}")
    vmnet.check_address(str(iface.ip), {"subnet": str(iface.network)})
    return iface


def _check_gateway(value: Any, iface: ipaddress.IPv4Interface) -> str:
    text = value if isinstance(value, str) else ""
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        raise ValueError(f"The gateway {value!r} isn't an IPv4 address") from None
    if ip.version != 4 or str(ip) != text:
        raise ValueError(f"The gateway {value!r} isn't written as an IPv4 address")
    if ip not in iface.network or ip in (iface.network.network_address, iface.network.broadcast_address):
        raise ValueError(f"The gateway {ip} isn't a host address in {iface.network}")
    if ip == iface.ip:
        raise ValueError(f"The gateway {ip} is the VM's own address")
    return text


def _public_key(value: Any, what: str) -> asyncssh.SSHKey:
    if not isinstance(value, str) or not value.strip() or "\n" in value.strip() or "\r" in value:
        raise ValueError(f"{what} must be one OpenSSH public key line")
    try:
        return asyncssh.import_public_key(value.strip())
    except (asyncssh.KeyImportError, ValueError) as exc:
        raise ValueError(f"{what} isn't an OpenSSH public key") from exc


def _key_data(key: asyncssh.SSHKey) -> bytes:
    return key.public_data


# ---------------------------------------------------------------------------- documents


def metadata(machine_id: uuid.UUID | str, hostname: str, address_cidr: str, gateway: str,
             dns_servers: list[str] | None) -> str:
    """``guestinfo.metadata``: instance id, host name, a static netplan v2 network and the user-data cleanup.

    The network matches the VM's one vmxnet3 NIC by driver, so it doesn't depend on the name the
    guest gives the interface. With no DNS servers the gateway answers DNS.
    """
    instance = f"slipway-{uuid.UUID(str(machine_id))}"
    hostname = check_hostname(hostname)
    iface = check_address_cidr(address_cidr)
    gateway = _check_gateway(gateway, iface)
    servers = vmnet.check_dns_servers(list(dns_servers or [])) or [gateway]
    doc = {
        "instance-id": instance,
        "local-hostname": hostname,
        "network": {
            "version": 2,
            "ethernets": {
                "primary": {
                    "match": {"driver": "vmxnet3"},
                    "dhcp4": False,
                    "dhcp6": False,
                    "addresses": [str(iface)],
                    "routes": [{"to": "default", "via": gateway}],
                    "nameservers": {"addresses": servers},
                },
            },
        },
        # cloud-init clears guestinfo.userdata from inside the guest once it has read it.
        "cleanup-guestinfo": ["userdata"],
    }
    return _dump(doc)


def userdata(hostname: str, ssh_public_key: str, host_key_private: str, host_key_public: str) -> str:
    """``guestinfo.userdata``: the ``slipway`` user and the SSH host key pair Slipway generated.

    ``slipway`` gets passwordless sudo (bootstrap installs Docker through ``sudo -n``), a locked
    password and Slipway's client key only; root and password logins are off. The seed image's host
    keys are deleted and no other types are generated, so the VM can only present Slipway's key.
    """
    hostname = check_hostname(hostname)
    client = _public_key(ssh_public_key, "Slipway's client key")
    public = _public_key(host_key_public, "The host key")
    if public.algorithm != b"ssh-ed25519":
        raise ValueError("The host key must be an ed25519 key")
    if not isinstance(host_key_private, str) or "PRIVATE KEY" not in host_key_private:
        raise ValueError("The private host key must be an OpenSSH private key")
    try:
        private = asyncssh.import_private_key(host_key_private.strip())
    except (asyncssh.KeyImportError, ValueError) as exc:
        raise ValueError("The private host key can't be read (or needs a passphrase)") from exc
    if private.algorithm != b"ssh-ed25519" or _key_data(private) != _key_data(public):
        raise ValueError("The private host key isn't the private half of the host key")
    doc = {
        "hostname": hostname,
        "manage_etc_hosts": True,
        "users": [
            {
                "name": GUEST_USER,
                "gecos": "Slipway",
                "shell": "/bin/bash",
                "sudo": "ALL=(ALL) NOPASSWD:ALL",
                "lock_passwd": True,
                "ssh_authorized_keys": [client.export_public_key("openssh").decode().strip()],
            },
        ],
        "ssh_pwauth": False,
        "disable_root": True,
        "ssh_deletekeys": True,
        "ssh_genkeytypes": [],
        "ssh_keys": {
            "ed25519_private": host_key_private.strip() + "\n",
            "ed25519_public": public.export_public_key("openssh").decode().strip(),
        },
        "growpart": {"mode": "auto", "devices": ["/"]},
        "resize_rootfs": True,
    }
    return "#cloud-config\n" + _dump(doc)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def guestinfo(meta: str, user: str) -> dict[str, str]:
    """The extraConfig keys that carry both documents, base64 with their encodings."""
    return {
        "guestinfo.metadata": _b64(meta),
        "guestinfo.metadata.encoding": "base64",
        "guestinfo.userdata": _b64(user),
        "guestinfo.userdata.encoding": "base64",
    }


def scrub() -> dict[str, str]:
    """The extraConfig change that deletes the user-data (and with it the private host key)."""
    return dict(SCRUB)
