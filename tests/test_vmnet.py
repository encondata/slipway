"""Phase 5 tests 4 and 5: network profiles, addresses, pools, names, sizes and snapshot names (``vmnet``)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from slipway.services import vmnet
from slipway.services.vmtypes import AccountInvalid

from tests.hypervisor_guard import no_real_hypervisors  # noqa: F401  (the fixture)

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")

LAN = {
    "name": "lan",
    "bridge": "vmbr0",
    "vlan_tag": None,
    "subnet": "10.0.0.0/24",
    "gateway": "10.0.0.1",
    "dns_servers": ["10.0.0.53"],
    "pool": {"first": "10.0.0.100", "last": "10.0.0.110"},
}


def proxmox(**changes):
    return vmnet.check_network_profile({**LAN, **changes}, provider="proxmox")


def esxi(**changes):
    profile = {k: v for k, v in LAN.items() if k not in ("bridge", "vlan_tag")}
    return vmnet.check_network_profile({**profile, "port_group": "VM Network", **changes}, provider="esxi")


# ------------------------------------------------------------------------- profiles


def test_profile_is_cleaned():
    assert proxmox(name=" lan ", vlan_tag=20) == {**LAN, "vlan_tag": 20}
    assert proxmox(dns_servers=None, pool=None)["dns_servers"] == []
    assert esxi() == {
        "name": "lan", "port_group": "VM Network", "subnet": "10.0.0.0/24", "gateway": "10.0.0.1",
        "dns_servers": ["10.0.0.53"], "pool": {"first": "10.0.0.100", "last": "10.0.0.110"},
    }


@pytest.mark.parametrize("changes, field, text", [
    ({"name": ""}, "network.name", "network name"),
    ({"name": "x" * 41}, "network.name", "network name"),
    ({"bridge": "vmbr0; rm -rf /"}, "network.bridge", "bridge"),
    ({"bridge": "a" * 16}, "network.bridge", "bridge"),
    ({"vlan_tag": 0}, "network.vlan_tag", "between 1 and 4094"),
    ({"vlan_tag": 4095}, "network.vlan_tag", "between 1 and 4094"),
    ({"vlan_tag": True}, "network.vlan_tag", "whole number"),
    ({"port_group": "VM Network"}, "network.port_group", "no port_group"),
    # Sirdar's table: prefix 8-30, canonical, IPv4.
    ({"subnet": "10.0.0.0/7"}, "network.subnet", "between /8 and /30"),
    ({"subnet": "10.0.0.0/31"}, "network.subnet", "between /8 and /30"),
    ({"subnet": "10.0.0.5/24"}, "network.subnet", "as 10.0.0.0/24"),
    ({"subnet": "10.0.0.0"}, "network.subnet", "with its prefix"),
    ({"subnet": "fd00::/64"}, "network.subnet", "IPv6"),
    ({"subnet": "nonsense/24"}, "network.subnet", "isn't an IPv4 subnet"),
    ({"subnet": "224.0.0.0/24"}, "network.subnet", "multicast"),
    ({"subnet": "169.254.0.0/16"}, "network.subnet", "link-local"),
    ({"subnet": "127.0.0.0/8"}, "network.subnet", "loopback"),
    ({"subnet": "0.0.0.0/8"}, "network.subnet", "0.0.0.0/8"),
    ({"subnet": "240.0.0.0/8"}, "network.subnet", "reserved"),
    # The gateway: inside, not the network or broadcast address.
    ({"gateway": "10.0.1.1"}, "network.gateway", "isn't in the subnet"),
    ({"gateway": "10.0.0.0"}, "network.gateway", "network or broadcast"),
    ({"gateway": "10.0.0.255"}, "network.gateway", "network or broadcast"),
    ({"gateway": "10.0.0.01"}, "network.gateway", "isn't an IPv4 address"),
    ({"gateway": None}, "network.gateway", "isn't an IPv4 address"),
    # DNS servers: at most three, canonical, no duplicates, nothing special.
    ({"dns_servers": ["1.1.1.1", "8.8.8.8", "9.9.9.9", "10.0.0.53"]}, "network.dns_servers", "at most 3"),
    ({"dns_servers": ["1.1.1.1 "]}, "network.dns_servers", "isn't an IPv4 address"),
    ({"dns_servers": ["1.1.1.1", "1.1.1.1"]}, "network.dns_servers", "twice"),
    ({"dns_servers": ["127.0.0.53"]}, "network.dns_servers", "loopback"),
    ({"dns_servers": ["224.0.0.1"]}, "network.dns_servers", "multicast"),
    ({"dns_servers": "1.1.1.1"}, "network.dns_servers", "must be a list"),
    # Pools: inside, ordered, leaving out the gateway, network and broadcast addresses.
    ({"pool": {"first": "10.0.1.10", "last": "10.0.1.20"}}, "network.pool", "isn't in the subnet"),
    ({"pool": {"first": "10.0.0.20", "last": "10.0.0.10"}}, "network.pool", "comes after"),
    ({"pool": {"first": "10.0.0.0", "last": "10.0.0.10"}}, "network.pool", "network and broadcast"),
    ({"pool": {"first": "10.0.0.200", "last": "10.0.0.255"}}, "network.pool", "network and broadcast"),
    ({"pool": {"first": "10.0.0.1", "last": "10.0.0.10"}}, "network.pool", "holds the gateway"),
    ({"pool": {"first": "10.0.0.2"}}, "network.pool", "first, last"),
    ({"subnet": "10.0.0.0/16", "pool": {"first": "10.0.0.2", "last": "10.0.20.0"}}, "network.pool", "at most 4096"),
    ({"colour": "blue"}, "network.colour", "no colour"),
])
def test_profile_refusals_name_their_field(changes, field, text):
    with pytest.raises(AccountInvalid, match=text) as caught:
        proxmox(**changes)
    assert caught.value.field == field


def test_esxi_profile_needs_a_port_group_and_takes_no_vlan():
    with pytest.raises(AccountInvalid) as caught:
        esxi(port_group="")
    assert caught.value.field == "network.port_group"
    with pytest.raises(AccountInvalid) as caught:
        esxi(vlan_tag=10)
    assert caught.value.field == "network.vlan_tag"


def test_networks_list():
    second = {**LAN, "name": "dmz", "subnet": "10.0.1.0/24", "gateway": "10.0.1.1", "pool": None}
    out = vmnet.check_networks([LAN, second], provider="proxmox")
    assert [n["name"] for n in out] == ["lan", "dmz"]
    with pytest.raises(AccountInvalid) as caught:
        vmnet.check_networks([LAN, {**second, "name": "LAN"}], provider="proxmox")
    assert caught.value.field == "networks.1.name"
    with pytest.raises(AccountInvalid) as caught:
        vmnet.check_networks([LAN, {**second, "gateway": "10.0.9.1"}], provider="proxmox")
    assert caught.value.field == "networks.1.gateway"
    with pytest.raises(AccountInvalid, match="at most 20"):
        vmnet.check_networks([LAN] * 21, provider="proxmox")
    assert vmnet.find_network(out, "dmz") is out[1]
    assert vmnet.find_network(out, "nope") is None


# ------------------------------------------------------------------------ addresses


@pytest.mark.parametrize("address, text", [
    ("10.0.1.5", "isn't in network lan's subnet"),
    ("10.0.0.0", "network address"),
    ("10.0.0.255", "broadcast address"),
    ("10.0.0.1", "gateway"),
    ("224.0.0.5", "multicast"),
    ("169.254.1.1", "link-local"),
    ("240.0.0.1", "reserved"),
    ("255.255.255.255", "broadcast"),
    ("0.1.2.3", "0.0.0.0/8"),
    ("127.0.0.1", "loopback"),
    ("010.0.0.12", "isn't an IPv4 address"),
    ("10.0.0.12 ", "isn't an IPv4 address"),
    ("fd00::12", "IPv6"),
    ("", "isn't an IPv4 address"),
    (None, "isn't an IPv4 address"),
])
def test_check_address_refusals(address, text):
    with pytest.raises(ValueError, match=text):
        vmnet.check_address(address, LAN)


def test_check_address_accepts_and_works_on_frozen_networks():
    assert vmnet.check_address("10.0.0.12", LAN) == "10.0.0.12"
    frozen = vmnet.frozen_network(LAN, "10.0.0.12")
    assert frozen == {"name": "lan", "address": "10.0.0.12", "prefix": 24, "gateway": "10.0.0.1",
                      "dns_servers": ["10.0.0.53"]}
    assert vmnet.check_address("10.0.0.13", frozen) == "10.0.0.13"
    with pytest.raises(ValueError, match="gateway"):
        vmnet.check_address("10.0.0.1", frozen)
    assert vmnet.address_cidr("10.0.0.12", frozen) == "10.0.0.12/24"
    assert vmnet.address_cidr("10.0.0.12", LAN) == "10.0.0.12/24"
    with pytest.raises(ValueError, match="gateway"):
        vmnet.frozen_network(LAN, "10.0.0.1")


def test_loopback_only_with_the_switch(monkeypatch):
    local = {"name": "local", "bridge": "vmbr0", "subnet": "127.0.0.0/8", "gateway": "127.0.0.254"}
    with pytest.raises(AccountInvalid):
        vmnet.check_network_profile(local, provider="proxmox")
    monkeypatch.setattr(vmnet, "ALLOW_LOOPBACK", True)
    profile = vmnet.check_network_profile(local, provider="proxmox")
    assert vmnet.check_address("127.0.0.1", profile) == "127.0.0.1"


def test_dns_for():
    assert vmnet.dns_for(LAN) == ["10.0.0.53"]
    assert vmnet.dns_for({**LAN, "dns_servers": []}) == ["10.0.0.1"]


# ---------------------------------------------------------------------------- pools


def test_allocate_takes_the_lowest_free_address():
    assert vmnet.allocate(LAN, set()) == "10.0.0.100"
    assert vmnet.allocate(LAN, {"10.0.0.100", "10.0.0.101"}) == "10.0.0.102"
    # A predicate works as well as a set (the registry's in-use check).
    assert vmnet.allocate(LAN, lambda a: a.endswith((".100", ".102"))) == "10.0.0.101"
    assert list(vmnet.pool_range(LAN))[:2] == ["10.0.0.100", "10.0.0.101"]
    assert len(list(vmnet.pool_range(LAN))) == 11


def test_allocate_skips_dns_servers_and_reports_an_empty_pool():
    net = {**LAN, "dns_servers": ["10.0.0.100"]}
    assert vmnet.allocate(net, set()) == "10.0.0.101"
    full = {f"10.0.0.{n}" for n in range(100, 111)}
    with pytest.raises(ValueError, match=r"pool \(10.0.0.100-10.0.0.110\) has no free address"):
        vmnet.allocate(LAN, full)
    with pytest.raises(ValueError, match="no address pool"):
        vmnet.allocate({**LAN, "pool": None}, set())
    assert list(vmnet.pool_range({**LAN, "pool": None})) == []


# ---------------------------------------------------------------------------- names


def test_vm_names():
    env = "a" + "b" * 24 + "c"  # P3's longest environment name, 26 characters
    for slot in vmnet.SLOTS:
        name = vmnet.vm_name(env, slot)
        assert name == f"slipway-{env}-{slot}"
        assert len(name) <= 40
    assert vmnet.vm_name("uat", "blue") == "slipway-uat-blue"
    # The host row is named as the VM (Decision 9), the same text hosts.planned_name gives a droplet's row.
    assert vmnet.host_row_name("uat", "data") == "slipway-uat-data"
    from slipway.services import hosts
    for slot in vmnet.SLOTS:
        assert vmnet.host_row_name(env, slot) == vmnet.vm_name(env, slot) == hosts.planned_name(env, slot)
    for bad in ("slipway-uat-purple", "slipway-Uat-blue", "slipway-u-blue", "sirdar-uat-blue",
                "slipway-uat--blue-", "slipway-uat-blue\n", f"slipway-{env}x-blue", "slipway-uat_x-blue", None):
        with pytest.raises(ValueError, match="isn't a VM name"):
            vmnet.check_vm_name(bad)
    with pytest.raises(ValueError):
        vmnet.vm_name("uat-", "blue")
    with pytest.raises(ValueError, match="isn't a slot"):
        vmnet.host_row_name("uat", "purple")


def test_name_rules_for_the_clients():
    assert vmnet.check_bridge("vmbr0") == "vmbr0"
    assert vmnet.check_port_group("VM Network") == "VM Network"
    assert vmnet.check_proxmox_id("local-lvm", "storage", "local-lvm") == "local-lvm"
    assert vmnet.check_esxi_name("datastore1", "datastore", "datastore1") == "datastore1"
    assert vmnet.check_proxmox_id(" slipway\n", "pool", "slipway") == "slipway"
    for bad in ("", "../x", "a\nb", "1pool", None):
        with pytest.raises(ValueError):
            vmnet.check_proxmox_id(bad, "pool", "slipway")
    with pytest.raises(ValueError, match="such as local-lvm"):
        vmnet.check_proxmox_id("local lvm", "storage", "local-lvm")


# ---------------------------------------------------------------------------- sizes


def test_sizes():
    assert vmnet.check_size(None) == vmnet.DEFAULT_SIZE == {"cores": 4, "memory_mb": 8192, "disk_gb": 64}
    assert vmnet.check_size({"cores": 2}) == {"cores": 2, "memory_mb": 8192, "disk_gb": 64}
    assert vmnet.check_size({"cores": 1, "memory_mb": 2048, "disk_gb": 20}) == {"cores": 1, "memory_mb": 2048, "disk_gb": 20}
    assert vmnet.check_size({"cores": 64, "memory_mb": 262144, "disk_gb": 4096})["disk_gb"] == 4096
    assert vmnet.check_size({"cores": "8"})["cores"] == 8
    for bad, text in (({"cores": 0}, "between 1 and 64"), ({"cores": 65}, "between 1 and 64"),
                      ({"memory_mb": 2047}, "between 2048 MB and 262144 MB"),
                      ({"memory_mb": 262145}, "between 2048 MB"),
                      ({"disk_gb": 19}, "between 20 GB and 4096 GB"), ({"disk_gb": 4097}, "between 20 GB"),
                      ({"cores": True}, "whole number"), ({"cores": 2.5}, "whole number"),
                      ({"gpus": 1}, "not gpus"), ([], "A VM size is")):
        with pytest.raises(ValueError, match=text):
            vmnet.check_size(bad)


def test_disks_only_grow():
    applied = {"cores": 4, "memory_mb": 8192, "disk_gb": 80}
    assert vmnet.check_size({"disk_gb": 80}, applied=applied)["disk_gb"] == 80
    assert vmnet.check_size({"disk_gb": 100, "cores": 2}, applied=applied)["cores"] == 2
    with pytest.raises(ValueError, match="Disks only grow: this VM's disk is 80 GB"):
        vmnet.check_size({"disk_gb": 64}, applied=applied)


def test_keep_vm_snapshots():
    assert vmnet.check_keep_vm_snapshots(1) == 1
    assert vmnet.check_keep_vm_snapshots(10) == 10
    for bad in (0, 11, True, "x"):
        with pytest.raises(ValueError):
            vmnet.check_keep_vm_snapshots(bad)


def test_size_text():
    assert vmnet.size_text({"cores": 4, "memory_mb": 8192, "disk_gb": 80}) == "4 vCPU, 8 GB, 80 GB"
    assert vmnet.size_text({"cores": 1, "memory_mb": 3000, "disk_gb": 20}) == "1 vCPU, 3000 MB, 20 GB"


# ------------------------------------------------------------------- snapshot names


def test_snapshot_names_round_trip():
    when = datetime(2026, 11, 15, 22, 5, 9, tzinfo=UTC)
    name = vmnet.snapshot_name(when)
    assert name == "slipway-20261115T220509Z"
    assert len(name) <= 40 and name[0].isalpha()
    assert vmnet.parse_snapshot_name(name) == when
    # Another zone, or a naive UTC time, gives the same UTC name.
    assert vmnet.snapshot_name(when.astimezone(timezone(timedelta(hours=-5)))) == name
    assert vmnet.snapshot_name(when.replace(tzinfo=None)) == name
    for other in ("slipway-20261315T220509Z", "manual-1", "slipway-20261115T220509", "", None):
        assert vmnet.parse_snapshot_name(other) is None


def test_next_snapshot_name_skips_taken_ones():
    when = datetime(2026, 11, 15, 22, 5, 9, tzinfo=UTC)
    taken = {"slipway-20261115T220509Z", "slipway-20261115T220510Z"}
    assert vmnet.next_snapshot_name(when, taken) == "slipway-20261115T220511Z"
    assert vmnet.next_snapshot_name(when, set()) == "slipway-20261115T220509Z"
