"""Names, sizes, networks and addresses of the VMs Slipway makes (phase 5 §5, §3.1's ``Network``).

Pure rules with no database or network access, shared by the accounts service (a network profile),
environment create (a VM's address and size) and the providers (a VM's name before it reaches
Terraform or cloud-init). Every check returns the canonical value or raises ``ValueError`` with the
sentence a person reads; ``check_network_profile`` raises ``AccountInvalid`` naming the field.

Every VM gets a static IPv4 address (phase 5 D4): a Slipway host is addressed by ``hostname``, and
the data server's clients and Switchyard's upstreams assume it never moves. Which addresses are
already *in use* (claims, other hosts, the hypervisor's API...) is the machines registry's to say;
``allocate`` only picks the lowest pool address that isn't in the set it is given.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Container, Iterable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

from slipway.services.vmtypes import AccountInvalid

# Tests that reach a real SSH server on 127.0.0.1 (phase 5 test 18) turn this on; nothing else may.
ALLOW_LOOPBACK = False

SLOTS = ("blue", "green", "data")
PROVIDERS = ("proxmox", "esxi")

# ``slipway-<env>-<slot>``: the environment name is phase 3's 2-26 characters, so a VM name is at most
# 40 characters and a valid DNS label, usable as the guest's host name.
VM_NAME_RE = re.compile(r"^slipway-[a-z][a-z0-9-]{0,24}[a-z0-9]-(blue|green|data)$")
NETWORK_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$")
# Linux interface names (a Proxmox bridge such as vmbr0) are at most 15 characters.
BRIDGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,14}$")
# ESXi port group names may hold spaces ("VM Network") and are at most 80 characters.
PORT_GROUP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,79}$")
# Proxmox node, storage and pool ids, and ESXi datastore and resource pool names (the clients use these).
PROXMOX_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
ESXI_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,79}$")

# (low, high) per size field, Sirdar's LIMITS; the default is Sirdar's DEFAULTS.
SIZE_LIMITS = {"cores": (1, 64), "memory_mb": (2048, 262144), "disk_gb": (20, 4096)}
DEFAULT_SIZE = {"cores": 4, "memory_mb": 8192, "disk_gb": 64}
KEEP_VM_SNAPSHOTS = (1, 10)
DEFAULT_KEEP_VM_SNAPSHOTS = 3

PREFIX_RANGE = (8, 30)
MAX_DNS_SERVERS = 3
MAX_NETWORKS = 20
MAX_POOL = 4096
VLAN_RANGE = (1, 4094)

SNAPSHOT_PREFIX = "slipway-"
_SNAPSHOT_FORMAT = "%Y%m%dT%H%M%SZ"
SNAPSHOT_NAME_RE = re.compile(r"^slipway-\d{8}T\d{6}Z$")

_ZERO_NET = ipaddress.IPv4Network("0.0.0.0/8")


# ---------------------------------------------------------------------------- names


def vm_name(env_name: str, slot: str) -> str:
    """The VM's name and guest host name for ``<env>``'s ``<slot>``."""
    return check_vm_name(f"slipway-{env_name}-{slot}")


def check_vm_name(name: str) -> str:
    if not isinstance(name, str) or not VM_NAME_RE.fullmatch(name):
        raise ValueError(
            f"{name!r} isn't a VM name Slipway makes: it should be slipway-<environment>-<blue|green|data>, "
            "at most 40 lower-case letters, digits and hyphens"
        )
    return name


def host_row_name(env_name: str, slot: str) -> str:
    """The name of the planned host row for a VM: the VM's own name, ``slipway-<env>-<slot>`` (a droplet's host
    row is named the same way, so ``hosts.planned_name`` gives the same text)."""
    if slot not in SLOTS:
        raise ValueError(f"{slot!r} isn't a slot: use blue, green or data")
    return vm_name(env_name, slot)


def _check_name(value: Any, pattern: re.Pattern[str], what: str, example: str) -> str:
    text = value.strip() if isinstance(value, str) else ""
    if not pattern.fullmatch(text):
        raise ValueError(f"{value!r} isn't a valid {what} (such as {example})")
    return text


def check_bridge(value: Any) -> str:
    return _check_name(value, BRIDGE_RE, "Proxmox bridge name", "vmbr0")


def check_port_group(value: Any) -> str:
    return _check_name(value, PORT_GROUP_RE, "ESXi port group name", "VM Network")


def check_proxmox_id(value: Any, what: str, example: str) -> str:
    """A Proxmox node, storage or pool id."""
    return _check_name(value, PROXMOX_ID_RE, what, example)


def check_esxi_name(value: Any, what: str, example: str) -> str:
    """An ESXi datastore, resource pool or seed VM name."""
    return _check_name(value, ESXI_NAME_RE, what, example)


# ---------------------------------------------------------------------------- sizes


def _int(value: Any, what: str) -> int:
    # bool is an int in Python; "true" is never a size.
    if isinstance(value, bool) or not isinstance(value, int):
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
        raise ValueError(f"{what} must be a whole number")
    return value


_SIZE_WORDS = {"cores": ("vCPU count", ""), "memory_mb": ("Memory", " MB"), "disk_gb": ("Disk", " GB")}


def check_size(size: dict[str, Any] | None, *, applied: dict[str, Any] | None = None) -> dict[str, int]:
    """A wanted VM size ``{cores, memory_mb, disk_gb}``; missing fields take the defaults.

    ``applied`` is what the hypervisor has now: a disk never shrinks.
    """
    if size is not None and not isinstance(size, dict):
        raise ValueError("A VM size is {cores, memory_mb, disk_gb}")
    size = size or {}
    unknown = sorted(set(size) - set(SIZE_LIMITS))
    if unknown:
        raise ValueError(f"A VM size has only cores, memory_mb and disk_gb, not {', '.join(unknown)}")
    out: dict[str, int] = {}
    for key, (low, high) in SIZE_LIMITS.items():
        word, unit = _SIZE_WORDS[key]
        value = _int(size.get(key, DEFAULT_SIZE[key]), word)
        if not low <= value <= high:
            raise ValueError(f"{word} must be between {low}{unit} and {high}{unit}, not {value}{unit}")
        out[key] = value
    if applied and applied.get("disk_gb") is not None and out["disk_gb"] < int(applied["disk_gb"]):
        raise ValueError(
            f"Disks only grow: this VM's disk is {int(applied['disk_gb'])} GB, so its size must be at least that"
        )
    return out


def check_keep_vm_snapshots(value: Any) -> int:
    low, high = KEEP_VM_SNAPSHOTS
    number = _int(value, "Automatic VM snapshots kept")
    if not low <= number <= high:
        raise ValueError(f"Automatic VM snapshots kept must be between {low} and {high}, not {number}")
    return number


def size_text(size: dict[str, Any]) -> str:
    """``4 vCPU, 8 GB, 80 GB`` for logs and notes (memory in GB when it is whole)."""
    memory = int(size["memory_mb"])
    mem = f"{memory // 1024} GB" if memory % 1024 == 0 else f"{memory} MB"
    return f"{int(size['cores'])} vCPU, {mem}, {int(size['disk_gb'])} GB"


# -------------------------------------------------------------------------- addresses


def _ipv4(value: Any, what: str) -> ipaddress.IPv4Address:
    """A canonical IPv4 literal (no leading zeros, no spaces, not IPv6)."""
    text = value if isinstance(value, str) else ""
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        raise ValueError(f"{what} {value!r} isn't an IPv4 address such as 10.0.0.12") from None
    if ip.version != 4:
        raise ValueError(f"{what} {value} is IPv6; Slipway's VMs use IPv4 addresses")
    if str(ip) != text:
        raise ValueError(f"{what} {value!r} must be written as {ip}")
    return ip


def _special(ip: ipaddress.IPv4Address) -> str | None:
    """Why ``ip`` can't be a VM's, gateway's or DNS server's address, regardless of the network."""
    if ip in _ZERO_NET:
        return "is in 0.0.0.0/8, which no host may use"
    if ip.is_loopback and not ALLOW_LOOPBACK:
        return "is a loopback address"
    if ip.is_multicast:
        return "is a multicast address"
    if ip.is_link_local:
        return "is a link-local address"
    if ip == ipaddress.IPv4Address("255.255.255.255"):
        return "is the broadcast address"
    if ip.is_reserved:
        return "is in a reserved range (240.0.0.0/4)"
    return None


def _subnet(value: Any) -> ipaddress.IPv4Network:
    text = value if isinstance(value, str) else ""
    if "/" not in text:
        raise ValueError(f"Subnet {value!r} must be written with its prefix, such as 10.0.0.0/24")
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValueError(f"Subnet {value!r} isn't an IPv4 subnet such as 10.0.0.0/24") from None
    if net.version != 4:
        raise ValueError(f"Subnet {value} is IPv6; Slipway's VMs use IPv4")
    low, high = PREFIX_RANGE
    if not low <= net.prefixlen <= high:
        raise ValueError(f"Subnet {value}'s prefix must be between /{low} and /{high}")
    if str(net) != text:
        raise ValueError(f"Write the subnet as {net}, not {value!r}")
    reason = _special(net.network_address)
    if reason is None and net.overlaps(ipaddress.IPv4Network("224.0.0.0/3")):
        reason = "is in the multicast or reserved ranges"
    if reason is None and net.overlaps(ipaddress.IPv4Network("169.254.0.0/16")):
        reason = "is link-local"
    if reason is None and net.overlaps(ipaddress.IPv4Network("127.0.0.0/8")) and not ALLOW_LOOPBACK:
        reason = "is a loopback range"
    if reason:
        raise ValueError(f"Subnet {net} {reason}")
    return net


def check_address(address: Any, network: dict[str, Any]) -> str:
    """A VM's typed address on ``network`` (a checked profile, or a machine's frozen network).

    It must be inside the subnet, not its network or broadcast address, not the gateway, and not a
    multicast, link-local, reserved, 0/8 or (outside tests) loopback address.
    """
    ip = _ipv4(address, "The address")
    reason = _special(ip)
    if reason:
        raise ValueError(f"{ip} {reason}, so it can't be a VM's address")
    net = network_of(network)
    name = network.get("name") or str(net)
    if ip not in net:
        raise ValueError(f"{ip} isn't in network {name}'s subnet {net}")
    if ip == net.network_address:
        raise ValueError(f"{ip} is the network address of {net}, so it can't be a VM's address")
    if ip == net.broadcast_address:
        raise ValueError(f"{ip} is the broadcast address of {net}, so it can't be a VM's address")
    if network.get("gateway") and ip == ipaddress.IPv4Address(network["gateway"]):
        raise ValueError(f"{ip} is network {name}'s gateway, so it can't be a VM's address")
    return str(ip)


def network_of(network: dict[str, Any]) -> ipaddress.IPv4Network:
    """The subnet of a network profile (``subnet``) or of a machine's frozen network (``address`` + ``prefix``)."""
    if network.get("subnet"):
        return ipaddress.IPv4Network(network["subnet"])
    return ipaddress.IPv4Interface(f"{network['address']}/{int(network['prefix'])}").network


def address_cidr(address: str, network: dict[str, Any]) -> str:
    """``10.0.0.12/24``: the address with the network's prefix, as Terraform and cloud-init take it."""
    return f"{address}/{network_of(network).prefixlen}"


def dns_for(network: dict[str, Any]) -> list[str]:
    """The DNS servers a VM on ``network`` uses: the network's, else its gateway."""
    servers = list(network.get("dns_servers") or [])
    return servers or [network["gateway"]]


def frozen_network(profile: dict[str, Any], address: str) -> dict[str, Any]:
    """``machines.network``: what a VM keeps of its network at create, so later edits don't move it."""
    net = network_of(profile)
    return {
        "name": profile["name"],
        "address": check_address(address, profile),
        "prefix": net.prefixlen,
        "gateway": profile["gateway"],
        "dns_servers": list(profile.get("dns_servers") or []),
    }


def check_dns_servers(values: Any) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise ValueError("DNS servers must be a list of IPv4 addresses")
    if len(values) > MAX_DNS_SERVERS:
        raise ValueError(f"Give at most {MAX_DNS_SERVERS} DNS servers, not {len(values)}")
    out: list[str] = []
    for value in values:
        ip = _ipv4(value, "DNS server")
        reason = _special(ip)
        if reason:
            raise ValueError(f"DNS server {ip} {reason}")
        if str(ip) in out:
            raise ValueError(f"DNS server {ip} is listed twice")
        out.append(str(ip))
    return out


# --------------------------------------------------------------------------- pools


def pool_range(network: dict[str, Any]) -> Iterator[str]:
    """Every address of the network's pool, lowest first (nothing without a pool)."""
    pool = network.get("pool")
    if not pool:
        return iter(())
    first, last = int(ipaddress.IPv4Address(pool["first"])), int(ipaddress.IPv4Address(pool["last"]))
    return (str(ipaddress.IPv4Address(n)) for n in range(first, last + 1))


def allocate(network: dict[str, Any], in_use: Container[str] | Callable[[str], bool]) -> str:
    """The lowest pool address not in ``in_use`` (a set of addresses, or a predicate).

    The gateway and DNS servers are skipped as well, whatever ``in_use`` says. The caller still
    claims the address in the same transaction as the host (the claim's primary key is the lock).
    """
    name = network.get("name") or network.get("subnet")
    pool = network.get("pool")
    if not pool:
        raise ValueError(f"Network {name} has no address pool, so type the VM's address")
    taken = in_use if callable(in_use) else in_use.__contains__
    skip = {network.get("gateway"), *dns_for(network)}
    for address in pool_range(network):
        if address in skip or taken(address):
            continue
        try:
            return check_address(address, network)
        except ValueError:
            continue
    raise ValueError(f"Network {name}'s pool ({pool['first']}-{pool['last']}) has no free address left")


def _check_pool(value: Any, net: ipaddress.IPv4Network, gateway: ipaddress.IPv4Address) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"first", "last"}:
        raise ValueError("An address pool is {first, last}")
    first = _ipv4(value["first"], "The pool's first address")
    last = _ipv4(value["last"], "The pool's last address")
    for ip in (first, last):
        if ip not in net:
            raise ValueError(f"Pool address {ip} isn't in the subnet {net}")
    if first > last:
        raise ValueError(f"The pool's first address {first} comes after its last {last}")
    if first == net.network_address or last == net.broadcast_address:
        raise ValueError(f"The pool must leave out {net}'s network and broadcast addresses")
    if first <= gateway <= last:
        raise ValueError(f"The pool {first}-{last} holds the gateway {gateway}; start or end it beside the gateway")
    count = int(last) - int(first) + 1
    if count > MAX_POOL:
        raise ValueError(f"A pool may hold at most {MAX_POOL} addresses, not {count}")
    for ip in (first, last):
        reason = _special(ip)
        if reason:
            raise ValueError(f"Pool address {ip} {reason}")
    return {"first": str(first), "last": str(last)}


# ---------------------------------------------------------------- network profiles


_PROFILE_KEYS = {
    "proxmox": ("name", "bridge", "vlan_tag", "subnet", "gateway", "dns_servers", "pool"),
    "esxi": ("name", "port_group", "subnet", "gateway", "dns_servers", "pool"),
}


def check_network_profile(profile: Any, *, provider: str, field: str = "network") -> dict[str, Any]:
    """One entry of an account's ``networks``, cleaned; raises ``AccountInvalid`` naming the field.

    ``field`` is the prefix of the field names (``networks.0`` gives ``networks.0.gateway``).
    Keys of the other provider (a port group on Proxmox, a VLAN on ESXi) are refused.
    """
    if provider not in _PROFILE_KEYS:
        raise AccountInvalid("provider", f"{provider!r} isn't proxmox or esxi")
    if not isinstance(profile, dict):
        raise AccountInvalid(field, "A network is {name, subnet, gateway, …}")
    allowed = _PROFILE_KEYS[provider]
    extra = sorted(set(profile) - set(allowed))
    if extra:
        raise AccountInvalid(f"{field}.{extra[0]}", f"A {provider} network has no {extra[0]}")

    def at(key: str, check: Callable[[], Any]) -> Any:
        try:
            return check()
        except AccountInvalid:
            raise
        except (ValueError, TypeError) as exc:
            raise AccountInvalid(f"{field}.{key}", str(exc)) from None

    out: dict[str, Any] = {}
    out["name"] = at("name", lambda: _check_name(profile.get("name"), NETWORK_NAME_RE, "network name", "lan"))
    if provider == "proxmox":
        out["bridge"] = at("bridge", lambda: check_bridge(profile.get("bridge")))
        out["vlan_tag"] = at("vlan_tag", lambda: _check_vlan(profile.get("vlan_tag")))
    else:
        out["port_group"] = at("port_group", lambda: check_port_group(profile.get("port_group")))
    net = at("subnet", lambda: _subnet(profile.get("subnet")))
    out["subnet"] = str(net)

    def gateway() -> ipaddress.IPv4Address:
        ip = _ipv4(profile.get("gateway"), "The gateway")
        if ip not in net:
            raise ValueError(f"The gateway {ip} isn't in the subnet {net}")
        if ip in (net.network_address, net.broadcast_address):
            raise ValueError(f"The gateway {ip} is the network or broadcast address of {net}")
        reason = _special(ip)
        if reason:
            raise ValueError(f"The gateway {ip} {reason}")
        return ip

    gw = at("gateway", gateway)
    out["gateway"] = str(gw)
    out["dns_servers"] = at("dns_servers", lambda: check_dns_servers(profile.get("dns_servers")))
    out["pool"] = at("pool", lambda: _check_pool(profile.get("pool"), net, gw))
    return out


def _check_vlan(value: Any) -> int | None:
    if value is None or value == "":
        return None
    low, high = VLAN_RANGE
    number = _int(value, "The VLAN tag")
    if not low <= number <= high:
        raise ValueError(f"The VLAN tag must be between {low} and {high}, or empty for none")
    return number


def check_networks(networks: Any, *, provider: str, field: str = "networks") -> list[dict[str, Any]]:
    """An account's whole ``networks`` list: each entry checked, names unique (case-blind), at most 20."""
    if not isinstance(networks, list):
        raise AccountInvalid(field, "Networks must be a list")
    if len(networks) > MAX_NETWORKS:
        raise AccountInvalid(field, f"An account may have at most {MAX_NETWORKS} networks")
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for i, profile in enumerate(networks):
        cleaned = check_network_profile(profile, provider=provider, field=f"{field}.{i}")
        key = cleaned["name"].lower()
        if key in seen:
            raise AccountInvalid(f"{field}.{i}.name", f"Two networks are named {cleaned['name']}")
        seen.add(key)
        out.append(cleaned)
    return out


def find_network(networks: Iterable[dict[str, Any]], name: str) -> dict[str, Any] | None:
    for profile in networks:
        if profile.get("name") == name:
            return profile
    return None


# ------------------------------------------------------------------ snapshot names


def snapshot_name(when: datetime) -> str:
    """``slipway-YYYYMMDDTHHMMSSZ`` (UTC): a letter first, at most 40 characters, as Proxmox requires."""
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return SNAPSHOT_PREFIX + when.astimezone(UTC).strftime(_SNAPSHOT_FORMAT)


def parse_snapshot_name(name: str) -> datetime | None:
    """The UTC time in a name ``snapshot_name`` made, or None for any other name."""
    if not isinstance(name, str) or not SNAPSHOT_NAME_RE.fullmatch(name):
        return None
    try:
        return datetime.strptime(name[len(SNAPSHOT_PREFIX):], _SNAPSHOT_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return None


def next_snapshot_name(when: datetime, taken: Container[str]) -> str:
    """``snapshot_name(when)``, a second later each time while that name is already taken on the VM."""
    for step in range(3600):
        name = snapshot_name(when + timedelta(seconds=step))
        if name not in taken:
            return name
    raise ValueError("Slipway couldn't find a free VM snapshot name")
