"""The Proxmox client, its config rules and its Test, against FakeProxmox (spec §7.1; tests 7 and 8).

Also pins which of a VM's markers bpg/proxmox 0.115.0's clone call carries (§7.4's ``_our_clone``).
No test reaches a real Proxmox: the guard is on, and the one TLS test talks to a server on 127.0.0.1.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import ssl
from types import SimpleNamespace

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from slipway.services import proxmox, tls_pin
from slipway.services.vmtypes import AccountInvalid, MachineError

from tests import fake_proxmox as fp
from tests.hypervisor_guard import no_real_hypervisors  # noqa: F401

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")

NETWORK = {"name": "lan", "bridge": "vmbr0", "vlan_tag": None, "subnet": "10.0.0.0/24", "gateway": "10.0.0.1",
           "dns_servers": [], "pool": {"first": "10.0.0.100", "last": "10.0.0.150"}}


def make_cert(*, cn: str = "pve.test", ip: str | None = None, dns: str | None = None) -> tuple[str, str]:
    """A self-signed certificate and its key, as PEM."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    sans: list[x509.GeneralName] = []
    if ip:
        sans.append(x509.IPAddress(ipaddress.ip_address(ip)))
    if dns:
        sans.append(x509.DNSName(dns))
    now = dt.datetime.now(dt.UTC)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
               .not_valid_after(now + dt.timedelta(days=30))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True))
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    return (cert.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()).decode())


PEM, _ = make_cert()


def account(**config: object) -> SimpleNamespace:
    base = {"url": fp.URL, "node": "pve1", "pool": fp.POOL, "storage": fp.STORAGE,
            "template_vmid": fp.TEMPLATE_VMID, "token_id": fp.TOKEN.split("=")[0], "networks": [NETWORK]}
    base.update(config)
    return SimpleNamespace(name="lab", config=base, secret=fp.TOKEN, tls={"pem": PEM})


async def no_sleep(_seconds: float) -> None:
    await asyncio.sleep(0)


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch, tmp_path) -> fp.FakeProxmox:
    return fp.FakeProxmox(tmp_path / "pve.json").install(monkeypatch)


def client(**kwargs: object) -> proxmox.ProxmoxClient:
    kwargs.setdefault("sleep", no_sleep)
    kwargs.setdefault("task_poll", 0)
    return proxmox.ProxmoxClient.for_account(account(), **kwargs)


def clean(text: str) -> None:
    """Slipway's own sentence: no upstream text, no token."""
    assert fp.UPSTREAM_MARK not in text
    assert fp.TOKEN_SECRET not in text and fp.TOKEN not in text


# ---------------------------------------------------------------- token and transport


async def test_every_request_carries_the_token(fake):
    async with client() as api:
        assert await api.version() == "9.0.3"
        assert await api.nodes() == ["pve1", "pve2"]
    assert fake.requests and all(r["auth"] == f"PVEAPIToken={fp.TOKEN}" for r in fake.requests)
    assert fake.pems == [PEM]  # the transport was made for the account's pinned certificate


async def test_a_wrong_token_is_refused_in_slipways_words(fake):
    acct = account()
    acct.secret = "slipway@pve!slipway=00000000-0000-0000-0000-000000000000"
    async with proxmox.ProxmoxClient.for_account(acct) as api:
        with pytest.raises(proxmox.ProxmoxError) as info:
            await api.version()
    assert info.value.status == 401
    assert info.value.text == "Proxmox refused the API token. Check it in Settings → Integrations."
    assert "00000000-0000" not in info.value.text


def test_an_account_without_token_or_pin_is_refused():
    acct = account()
    acct.secret = None
    with pytest.raises(MachineError, match="lab can't be used: its API token is missing"):
        proxmox.ProxmoxClient.for_account(acct)
    acct = account()
    acct.tls = None
    with pytest.raises(MachineError, match="no certificate is trusted for it yet"):
        proxmox.ProxmoxClient.for_account(acct)


def test_the_real_transport_trusts_only_the_pinned_certificate(monkeypatch):
    seen = []
    real = tls_pin.pinned_context

    def spy(pem, **kwargs):
        seen.append((pem, kwargs))
        return real(pem, **kwargs)

    monkeypatch.setattr(tls_pin, "pinned_context", spy)
    transport = proxmox.pinned_transport(PEM)
    assert isinstance(transport, httpx.AsyncHTTPTransport)
    assert seen == [(PEM, {})]  # host names checked: check_hostname left at its default, True
    ctx = real(PEM)
    assert ctx.check_hostname and ctx.verify_mode == ssl.CERT_REQUIRED
    assert len(ctx.get_ca_certs()) == 1  # the pinned certificate alone, no system store


def test_the_guard_blocks_the_real_transport(no_real_hypervisors):
    with pytest.raises(Exception, match="Blocked in tests"):
        proxmox.ProxmoxClient.for_account(account())
    assert no_real_hypervisors.blocked
    no_real_hypervisors.blocked.clear()  # expected here; don't fail the test at teardown


async def _tls_server(cert_pem: str, key_pem: str, tmp_path) -> tuple[asyncio.Server, int]:
    (tmp_path / "cert.pem").write_text(cert_pem)
    (tmp_path / "key.pem").write_text(key_pem)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(tmp_path / "cert.pem", tmp_path / "key.pem")

    async def serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.readuntil(b"\r\n\r\n")
            body = b'{"data": {"version": "9.0.3"}}'
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n"
                         b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
            await writer.drain()
        except (OSError, asyncio.IncompleteReadError, ssl.SSLError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(serve, "127.0.0.1", 0, ssl=ctx)
    return server, server.sockets[0].getsockname()[1]


async def test_the_pin_decides_over_real_tls(monkeypatch, tmp_path):
    # The guard replaced transport_factory; this test uses the real one against 127.0.0.1 only.
    monkeypatch.setattr(proxmox, "transport_factory", proxmox.pinned_transport)
    served, key = make_cert(cn="pve", ip="127.0.0.1")
    server, port = await _tls_server(served, key, tmp_path)
    url = f"https://127.0.0.1:{port}"
    try:
        async with proxmox.ProxmoxClient(url, fp.TOKEN, served) as api:
            assert await api.version() == "9.0.3"
        other, _ = make_cert(cn="pve", ip="127.0.0.1")
        async with proxmox.ProxmoxClient(url, fp.TOKEN, other) as api:
            with pytest.raises(proxmox.ProxmoxError) as info:
                await api.version()
        assert info.value.text == proxmox.TLS_CHANGED and info.value.unreachable
    finally:
        server.close()
        await server.wait_closed()


async def test_host_names_are_checked(monkeypatch, tmp_path):
    monkeypatch.setattr(proxmox, "transport_factory", proxmox.pinned_transport)
    served, key = make_cert(cn="pve", dns="pve.elsewhere.test")  # the pinned certificate, for another name
    server, port = await _tls_server(served, key, tmp_path)
    try:
        async with proxmox.ProxmoxClient(f"https://127.0.0.1:{port}", fp.TOKEN, served) as api:
            with pytest.raises(proxmox.ProxmoxError) as info:
                await api.version()
        assert info.value.text == proxmox.TLS_CHANGED
    finally:
        server.close()
        await server.wait_closed()


# ---------------------------------------------------------------------- error mapping


async def test_errors_are_slipways_own_text(fake):
    fake.add_vm(101, "slipway-shop-blue", node="pve2", tags=("slipway", "env-1"))
    fake.deny("/nodes/pve2/qemu/101/snapshot")
    async with client() as api:
        with pytest.raises(proxmox.ProxmoxError) as denied:
            await api.snapshots("pve2", 101)
        with pytest.raises(proxmox.ProxmoxError) as wrong_node:
            await api.vm_config("pve1", 101)
        with pytest.raises(proxmox.ProxmoxError) as no_node:
            await api.status("pve9", 101)
    assert denied.value.status == 403
    assert denied.value.text == ("The API token isn't allowed to list the VM snapshots. "
                                 "Check its privileges (see docs/machines.md).")
    assert wrong_node.value.text == "Proxmox couldn't read the VM's settings (HTTP 500)."
    assert no_node.value.text == "Proxmox couldn't read the VM's state (HTTP 595)."
    for exc in (denied.value, wrong_node.value, no_node.value):
        clean(exc.text)
        assert not exc.unreachable


async def test_unreachable_timeout_and_malformed(monkeypatch):
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("[Errno 61] Connection refused to secret-host")

    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out")

    def garbage(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/version"):
            return httpx.Response(200, text="<html>login</html>")
        if request.url.path.endswith("/nodes"):
            return httpx.Response(200, json={"data": {"not": "a list"}})
        return httpx.Response(200, json={"data": [{"no-vmid": 1, "vmid": "abc"}]})

    for handler, text in ((down, "Slipway couldn't reach Proxmox at pve.test:8006."),
                          (slow, "Proxmox at pve.test:8006 didn't answer in 30 seconds (trying to read its version).")):
        monkeypatch.setattr(proxmox, "transport_factory", lambda pem, h=handler: httpx.MockTransport(h))
        async with client() as api:
            with pytest.raises(proxmox.ProxmoxError) as info:
                await api.version()
        assert info.value.text == text and info.value.unreachable
        assert "secret-host" not in info.value.text

    monkeypatch.setattr(proxmox, "transport_factory", lambda pem: httpx.MockTransport(garbage))
    async with client() as api:
        for call in (api.version(), api.nodes(), api.find_vm(5)):
            with pytest.raises(proxmox.ProxmoxError) as info:
                await call
            assert info.value.text == proxmox.MALFORMED


# ----------------------------------------------------------------------------- tasks


async def test_task_waits(fake):
    fake.add_vm(101, "vm", status="stopped")
    async with client(task_timeout=5) as api:
        upid = await api.start("pve1", 101)
        assert proxmox.parse_upid(upid)["type"] == "qmstart"
        await api.wait(upid, "start the VM")
        assert await api.status("pve1", 101) == "running"

        # WARNINGS passes.
        upid = fake.run_task(101, "qmconfig", polls=None)
        with fake.edit() as state:
            state["tasks"][upid].update(status="stopped", exitstatus="WARNINGS: 2")
        await api.wait(upid, "change the VM")

        # An error is Slipway's text, never the task log's.
        fake.task_fails("shutdown")
        upid = await api.shutdown("pve1", 101, timeout=300)
        with pytest.raises(proxmox.TaskFailed) as failed:
            await api.wait(upid, "shut the VM down")
        assert failed.value.upid == upid
        assert failed.value.text.startswith("Proxmox couldn't shut the VM down: its task ended with an error.")
        clean(failed.value.text)

        # A task that never ends: TaskTimeout carries its UPID, for last_task.
        fake.task_hangs("snapshot")
        upid = await api.take_snapshot("pve1", 101, "slipway-20261115T100000Z", "manual")
        with pytest.raises(proxmox.TaskTimeout) as late:
            await api.wait(upid, "take a VM snapshot", timeout=0.05)
        assert late.value.upid == upid and "may still be running" in late.value.text
    shutdown = fake.calls("POST", "/nodes/pve1/qemu/101/status/shutdown")[0]
    assert shutdown["data"] == {"timeout": "300"}
    snap = fake.calls("POST", "/nodes/pve1/qemu/101/snapshot")[0]
    assert snap["data"] == {"snapname": "slipway-20261115T100000Z", "description": "manual", "vmstate": "0"}


async def test_a_bad_task_id_is_refused(fake):
    async with client() as api:
        with pytest.raises(proxmox.ProxmoxError, match="didn't return a task id"):
            await api.wait("not-a-upid", "start the VM")


async def test_a_late_snapshot_task_times_out_then_appears(fake):
    fake.add_vm(101, "vm")
    fake.snapshot_task_late()
    async with client() as api:
        upid = await api.take_snapshot("pve1", 101, "slipway-20261115T100000Z")
        with pytest.raises(proxmox.TaskTimeout):
            await api.wait(upid, "take a VM snapshot", timeout=0.05)
        assert [s["name"] for s in await api.snapshots("pve1", 101)] == ["slipway-20261115T100000Z"]
        assert await api.vm_tasks("pve1", 101) == []


async def test_zfs_rolls_back_only_to_the_newest(monkeypatch, tmp_path):
    fake = fp.FakeProxmox(tmp_path / "pve.json", storage_type="zfspool").install(monkeypatch)
    fake.add_vm(101, "vm")
    fake.add_snapshot(101, "slipway-20261115T090000Z")
    fake.add_snapshot(101, "slipway-20261115T100000Z")
    async with client() as api:
        upid = await api.rollback("pve1", 101, "slipway-20261115T090000Z")
        with pytest.raises(proxmox.TaskFailed) as info:
            await api.wait(upid, "revert to the VM snapshot")
        assert info.value.text == proxmox.NOT_NEWEST
        await api.wait(await api.rollback("pve1", 101, "slipway-20261115T100000Z"), "revert to the VM snapshot")
        assert await api.status("pve1", 101) == "stopped"  # vmstate=0: a revert leaves the VM off


# -------------------------------------------------------------------------- VM reads


async def test_find_vm_across_nodes_and_hidden_ids(fake):
    fake.add_vm(101, "slipway-shop-blue", node="pve2", tags="slipway;env-1234")
    fake.hidden(102)
    async with client() as api:
        found = await api.find_vm(101)
        assert found == {"vmid": 101, "name": "slipway-shop-blue", "node": "pve2", "status": "running",
                         "tags": ("env-1234", "slipway"), "pool": "slipway", "template": False, "lock": None}
        # A VM outside the pool: find_vm can't see it, nextid says its id is used (D25).
        assert await api.find_vm(102) is None
        assert await api.vmid_free(102) is False
        assert await api.vmid_free(103) is True
        fake.remove_vm(101)
        assert await api.find_vm(101) is None and await api.vmid_free(101) is True
        assert (await api.find_vm(fp.TEMPLATE_VMID))["template"] is True


async def test_next_vmid(fake):
    async with client() as api:
        assert await api.next_vmid() == 100
        fake.add_vm(100, "a")
        fake.hidden(101)
        assert await api.next_vmid() == 102


async def test_agent_addresses_skip_loopback_docker_and_link_local(fake):
    fake.add_vm(101, "vm", address="10.0.0.12")
    fake.add_vm(102, "off", address="10.0.0.13", status="stopped")
    fake.agent_late(1)
    async with client() as api:
        with pytest.raises(proxmox.AgentNotReady) as late:
            await api.agent_ipv4("pve1", 101)
        assert late.value.text == "The VM's guest agent isn't answering yet."
        assert await api.agent_ipv4("pve1", 101) == ["10.0.0.12"]
        with pytest.raises(proxmox.AgentNotReady):
            await api.agent_ipv4("pve1", 102)
        fake.agent_wrong_address()
        assert await api.agent_ipv4("pve1", 101) == ["10.99.99.99"]


async def test_agent_file(fake):
    key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFreshVmKeyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX root@vm"
    fake.add_vm(101, "vm", host_key=key)
    fake.stale_template_key(2)
    async with client() as api:
        with pytest.raises(proxmox.AgentNotReady):
            await api.agent_file("pve1", 101, fp.BOOT_FINISHED)
        assert await api.agent_file("pve1", 101, fp.HOST_KEY_PATH) == fp.TEMPLATE_KEY + "\n"
        assert (await api.agent_file("pve1", 101, fp.BOOT_FINISHED)).startswith("2026-")
        assert await api.agent_file("pve1", 101, fp.HOST_KEY_PATH) == key + "\n"
    read = fake.calls("GET", "/nodes/pve1/qemu/101/agent/file-read")[0]
    assert read["params"] == {"file": fp.BOOT_FINISHED}


async def test_snapshots_without_current_with_parents_and_newest(fake):
    fake.add_vm(101, "vm")
    async with client() as api:
        assert await api.snapshots("pve1", 101) == []
        fake.add_snapshot(101, "slipway-20261115T090000Z", "first")
        fake.add_snapshot(101, "slipway-20261115T100000Z", "second")
        snaps = await api.snapshots("pve1", 101)
    assert [(s["name"], s["parent"], s["newest"]) for s in snaps] == [
        ("slipway-20261115T090000Z", None, False),
        ("slipway-20261115T100000Z", "slipway-20261115T090000Z", True),
    ]
    assert snaps[0]["description"] == "first"


async def test_running_tasks_lock_feature_and_storage(fake):
    fake.add_vm(101, "vm")
    upid = fake.run_task(101, "qmsnapshot", user="root@pam")
    async with client() as api:
        tasks = await api.vm_tasks("pve1", 101)
        assert [(t["upid"], t["type"], t["user"]) for t in tasks] == [(upid, "qmsnapshot", "root@pam")]
        assert (await api.vm_config("pve1", 101))["lock"] == "snapshot"
        assert await api.vm_tasks("pve2", 101) == []
        fake.add_vm(102, "locked")
        fake.stale_lock(102, "backup")
        assert (await api.vm_config("pve1", 102))["lock"] == "backup" and await api.vm_tasks("pve1", 102) == []
        assert await api.snapshot_feature("pve1", 101) is True
        info = await api.storage_info("pve1", fp.STORAGE)
        assert info["type"] == "lvmthin" and info["content"] == ["images", "rootdir"] and info["avail"] > 0
        assert await api.storage_info("pve1", "nope") is None
    listed = fake.calls("GET", "/nodes/pve1/tasks")[0]
    assert listed["params"] == {"vmid": "101", "source": "active"}
    assert fake.calls("GET", "/nodes/pve1/qemu/101/feature")[0]["params"] == {"feature": "snapshot"}
    assert fake.calls("GET", "/nodes/pve1/storage")[0]["params"] == {"storage": fp.STORAGE}


@pytest.mark.parametrize(("storage_type", "file_format", "has"), [
    ("lvmthin", None, True), ("zfspool", None, True), ("lvm", None, False),
    ("dir", "raw", False), ("dir", "qcow2", True),
])
async def test_snapshot_feature_follows_the_storage(monkeypatch, tmp_path, storage_type, file_format, has):
    fake = fp.FakeProxmox(tmp_path / "pve.json", storage_type=storage_type, file_format=file_format)
    fake.install(monkeypatch)
    fake.add_vm(101, "vm")
    async with client() as api:
        assert await api.snapshot_feature("pve1", 101) is has
        assert (await api.storage_info("pve1", fp.STORAGE))["type"] == storage_type


async def test_delete_vm_purges_its_disks(fake):
    fake.add_vm(101, "vm", status="stopped")
    async with client() as api:
        await api.wait(await api.delete_vm("pve1", 101), "delete the VM")
        assert await api.find_vm(101) is None
    call = fake.calls("DELETE", "/nodes/pve1/qemu/101")[0]
    assert call["params"] == {"purge": "1", "destroy-unreferenced-disks": "1"}


async def test_snapshot_rollback_and_delete(fake):
    fake.add_vm(101, "vm")
    async with client() as api:
        await api.wait(await api.take_snapshot("pve1", 101, "slipway-20261115T100000Z", "x"), "take a VM snapshot")
        await api.wait(await api.rollback("pve1", 101, "slipway-20261115T100000Z"), "revert")
        await api.wait(await api.start("pve1", 101), "start the VM")
        await api.wait(await api.delete_snapshot("pve1", 101, "slipway-20261115T100000Z"), "delete a VM snapshot")
        assert await api.snapshots("pve1", 101) == []
    assert fake.calls("POST", "/nodes/pve1/qemu/101/snapshot/slipway-20261115T100000Z/rollback")
    assert fake.calls("DELETE", "/nodes/pve1/qemu/101/snapshot/slipway-20261115T100000Z")


# ------------------------------------------------------------------------ page reads


async def test_page_reads_give_up_after_five_seconds(fake):
    assert proxmox.PAGE_TIMEOUT == 5.0
    page = proxmox.ProxmoxClient.for_account(account(), page=True)
    assert page.timeout == 5.0 and page._client.timeout.read == 5.0
    await page.aclose()
    fake.slow(0.5)
    async with client() as api:
        result = await proxmox.page_read(api.version, limit=0.05)
    assert result.value is None and result.error == "Proxmox didn't answer in 0 seconds."
    fake.slow(0)
    fake.deny("/version")
    async with client() as api:
        result = await proxmox.page_read(api.version)
        assert result.error.startswith("The API token isn't allowed to read its version")
        fake.add_vm(101, "vm")
        assert (await proxmox.page_read(lambda: api.status("pve1", 101))).value == "running"


# --------------------------------------------------------------------- the clone call


async def test_the_clone_call_carries_name_description_and_pool_but_no_tags(fake):
    """bpg/proxmox 0.115.0's vmCreateClone, step by step: the clone, then UpdateVM with the tags."""
    assert proxmox.CLONE_CALL_CARRIES == ("name", "description", "pool")
    description = "Managed by Slipway: environment shop (1234), blue slot. Change or delete it from Slipway, not here."
    fake.clone_lock_outlives(5)
    async with client() as api:
        upid = await api._call("POST", f"/nodes/pve1/qemu/{fp.TEMPLATE_VMID}/clone", "clone the template", data={
            "newid": 101, "full": 1, "storage": fp.STORAGE,
            "name": "slipway-shop-blue", "description": description, "pool": fp.POOL})
        # Cut off here, the clone has the name, pool and description, no tags, and its lock.
        found = await api.find_vm(101)
        assert (found["name"], found["pool"], found["tags"], found["lock"]) == ("slipway-shop-blue", "slipway", (), "clone")
        assert (await api.vm_config("pve1", 101))["description"] == description
        with pytest.raises(proxmox.ProxmoxError):  # bpg waits for the lock before UpdateVM
            await api._call("POST", "/nodes/pve1/qemu/101/config", "set tags", data={"tags": "slipway;env-1234"})
        await api.wait(upid, "clone the template")
        await api._call("POST", "/nodes/pve1/qemu/101/config", "set tags", data={"tags": "slipway;env-1234"})
        found = await api.find_vm(101)
    assert found["tags"] == ("env-1234", "slipway") and found["lock"] is None
    clone = fake.calls("POST", f"/nodes/pve1/qemu/{fp.TEMPLATE_VMID}/clone")[0]
    assert {k for k in clone["data"] if k in ("name", "description", "pool", "tags")} == set(proxmox.CLONE_CALL_CARRIES)


async def test_a_clone_lock_outlives_a_killed_terraform(fake):
    fake.clone_lock_outlives(3)
    with fake.edit() as state:  # the fake Terraform's first write, then a SIGKILL
        fp.clone_vm(state, fp.TEMPLATE_VMID, 101, node="pve1", name="slipway-shop-blue", pool=fp.POOL)
    async with client() as api:
        assert [t["type"] for t in await api.vm_tasks("pve1", 101)] == ["qmclone"]
        assert (await api.vm_config("pve1", 101))["lock"] == "clone"
        assert await api.vm_tasks("pve1", 101) == []
        assert "lock" not in await api.vm_config("pve1", 101)


# ---------------------------------------------------------------------- clean_config


def good_config(**changes: object) -> dict:
    config = {"url": "https://pve.example.lan:8006/", "node": "pve1", "pool": "slipway", "storage": "local-lvm",
              "template_vmid": 9000, "networks": [dict(NETWORK)], "extra": "dropped"}
    config.update(changes)
    return config


def test_clean_config_keeps_the_fields_and_the_token_id():
    out = proxmox.clean_config(good_config(), fp.TOKEN)
    assert out["url"] == "https://pve.example.lan:8006"
    assert out["token_id"] == "slipway@pve!slipway"
    assert set(out) == {"url", "node", "pool", "storage", "template_vmid", "networks", "token_id"}
    assert out["networks"][0]["bridge"] == "vmbr0" and out["networks"][0]["subnet"] == "10.0.0.0/24"
    assert fp.TOKEN_SECRET not in repr(out)
    # No secret typed (the stored one kept): no token_id, the accounts service carries it over.
    assert "token_id" not in proxmox.clean_config(good_config(), None)
    assert proxmox.clean_config(good_config(template_vmid="9000"), "")["template_vmid"] == 9000


@pytest.mark.parametrize(("changes", "field"), [
    ({"url": "http://pve:8006"}, "url"),
    ({"url": "https://pve:8006/api2/json"}, "url"),
    ({"url": "https://pve:70000"}, "url"),
    ({"url": ""}, "url"),
    ({"node": "pve 1"}, "node"),
    ({"node": "-pve"}, "node"),
    ({"pool": ""}, "pool"),
    ({"pool": "a/b"}, "pool"),
    ({"storage": "1local"}, "storage"),
    ({"template_vmid": 99}, "template_vmid"),
    ({"template_vmid": 1_000_000_000}, "template_vmid"),
    ({"template_vmid": True}, "template_vmid"),
    ({"networks": []}, "networks"),
    ({"networks": "lan"}, "networks"),
    ({"networks": [dict(NETWORK, gateway="10.0.1.1")]}, "networks.0.gateway"),
    ({"networks": [dict(NETWORK, bridge="vmbr0!")]}, "networks.0.bridge"),
    ({"networks": [dict(NETWORK, vlan_tag=5000)]}, "networks.0.vlan_tag"),
    ({"networks": [dict(NETWORK, port_group="VM Network")]}, "networks.0.port_group"),
    ({"networks": [dict(NETWORK), dict(NETWORK, name="LAN")]}, "networks.1.name"),
    ({"networks": [dict(NETWORK, name=f"n{i}") for i in range(21)]}, "networks"),
])
def test_clean_config_refuses(changes, field):
    with pytest.raises(AccountInvalid) as info:
        proxmox.clean_config(good_config(**changes), fp.TOKEN)
    assert info.value.field == field


@pytest.mark.parametrize("secret", [
    "slipway@pve!slipway",                                     # no secret part
    "slipway@pve=0b3c2f6e-1a2b-4c3d-8e9f-0123456789ab",        # no token id
    "slipway@pve!1tok=0b3c2f6e-1a2b-4c3d-8e9f-0123456789ab",   # token id starts with a digit
    "slipway@pve!slipway=not-a-uuid",
    "slip way@pve!slipway=0b3c2f6e-1a2b-4c3d-8e9f-0123456789ab",
])
def test_clean_config_refuses_a_bad_token_without_echoing_it(secret):
    with pytest.raises(AccountInvalid) as info:
        proxmox.clean_config(good_config(), secret)
    assert info.value.field == "secret"
    assert secret not in info.value.text


def test_redactions_hide_the_token_and_its_secret():
    assert proxmox.redactions(fp.TOKEN) == [fp.TOKEN, fp.TOKEN_SECRET]
    assert proxmox.redactions(None) == []


# ------------------------------------------------------------------------------ Test


def by_name(result: proxmox.TestResult) -> dict[str, tuple[str, str]]:
    return {c.name: (c.level, c.text) for c in result.checks}


async def test_run_test_passes_and_records_facts(fake):
    result = await proxmox.run_test(account())
    checks = by_name(result)
    assert result.status == "ok", checks
    assert list(checks) == ["Proxmox", "Node", "Pool", "Template", "Storage", "Bridge vmbr0", "Privileges"]
    assert checks["Storage"] == ("ok", "local-lvm (lvmthin) · 500 GB free")
    assert result.facts == {"version": "9.0.3", "template_ciupgrade": False, "storage_type": "lvmthin",
                            "storage_content": ["images", "rootdir"], "free_gb": 500.0}
    assert all(c.to_dict()["text"] for c in result.checks)


async def test_run_test_reports_each_problem(fake):
    with fake.edit() as state:
        state["vms"][str(fp.TEMPLATE_VMID)]["config"]["agent"] = "0"
    fake.template_ciupgrade(True)
    fake.set_storage(type="lvm")
    fake.deny("/nodes/pve1/network/vmbr0")
    fake.set_privileges("/pool/slipway", [p for p in fp.FULL_ROLE if p not in ("VM.Snapshot", "VM.GuestAgent.FileRead")])
    acct = account(networks=[NETWORK, dict(NETWORK, name="dmz", bridge="vmbr7", vlan_tag=20)])
    result = await proxmox.run_test(acct)
    checks = by_name(result)
    assert result.status == "error"
    assert checks["Template"][0] == "warning" and "guest agent option is off" in checks["Template"][1]
    assert checks["Template upgrades"] == ("warning", (
        'The template upgrades every package at first boot (ciupgrade 1); set "qm set 9000 --ciupgrade 0" '
        "so a new VM's first boot takes a predictable time"))
    assert checks["Storage"] == ("warning", "local-lvm is thick LVM: Slipway's VMs there can't have VM snapshots")
    assert checks["Bridge vmbr0"][0] == "warning" and "Sys.Audit" in checks["Bridge vmbr0"][1]
    assert checks["Bridge vmbr7"] == ("error", "Node pve1 has no bridge named vmbr7.")
    assert checks["Privileges"][0] == "error"
    assert "VM.Snapshot, VM.GuestAgent.FileRead on /pool/slipway" in checks["Privileges"][1]
    assert result.facts["storage_type"] == "lvm" and result.facts["template_ciupgrade"] is True
    for check in result.checks:
        clean(check.text)


async def test_run_test_node_pool_template_and_zfs(monkeypatch, tmp_path):
    fake = fp.FakeProxmox(tmp_path / "pve.json", storage_type="zfspool").install(monkeypatch)
    with fake.edit() as state:
        state["vms"][str(fp.TEMPLATE_VMID)]["template"] = False
    result = await proxmox.run_test(account(node="pve9"))
    checks = by_name(result)
    assert checks["Node"] == ("error", "No node named pve9 (Proxmox has pve1, pve2).")
    assert checks["Template"] == ("error", 'VM 9000 (ubuntu-2404-cloud) isn\'t a template. Convert it with "qm template" first.')
    assert checks["Storage"][0] == "error"  # pve9 has no storage

    result = await proxmox.run_test(account(template_vmid=9100))
    assert by_name(result)["Template"] == ("error", "VM 9100 isn't visible to the token. Is it in the slipway pool?")
    assert by_name(result)["Storage"] == ("note", "local-lvm (zfspool) · 500 GB free. ZFS rolls back only to the newest VM snapshot")
    assert result.status == "error"

    fake.deny("/pools")
    assert by_name(await proxmox.run_test(account()))["Pool"][0] == "error"


async def test_run_test_on_proxmox_8_wants_vm_monitor(monkeypatch, tmp_path):
    fake = fp.FakeProxmox(tmp_path / "pve.json", version="8.2.4").install(monkeypatch)
    fake.template_ciupgrade(None)  # unset on 8.1+: Proxmox upgrades at first boot
    pve8 = [p for p in fp.FULL_ROLE if not p.startswith("VM.GuestAgent")] + ["VM.Monitor"]
    fake.set_privileges("/pool/slipway", pve8)
    checks = by_name(await proxmox.run_test(account()))
    assert checks["Privileges"][0] == "ok", checks
    assert checks["Template upgrades"][0] == "warning"
    fake.set_privileges("/pool/slipway", [p for p in pve8 if p != "VM.Monitor"])
    assert "VM.Monitor" in by_name(await proxmox.run_test(account()))["Privileges"][1]


async def test_run_test_when_proxmox_cant_be_reached(monkeypatch):
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(proxmox, "transport_factory", lambda pem: httpx.MockTransport(down))
    result = await proxmox.run_test(account())
    assert [(c.name, c.level) for c in result.checks] == [("Proxmox", "error")]
    assert result.status == "error" and result.facts == {}
    acct = account()
    acct.secret = None
    assert "can't be used" in (await proxmox.run_test(acct)).checks[0].text
