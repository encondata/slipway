"""Review of phases 4 and 5, provider accounts and the test guards (findings F41, F42, F50, F51 and F52).

- F41: a Proxmox URL without a port is stored with :8006, so the certificate Slipway pins, the API client and
  Terraform's endpoint name one port;
- F42: a Test whose account changed while the provider answered (another token, address or certificate) keeps
  nothing: the change's own state stays, and the answer is 409 ``test_stale``;
- F50: the phase 3 golden passes whatever the length of pytest's temporary folder;
- F51: the guard stops an SSH dial to anything but loopback;
- F52: the guard stops a real GitHub request.
"""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from pathlib import Path

import httpx
import pytest

from slipway.db.session import get_sessionmaker
from slipway.models import ProviderAccount
from slipway.services import github, provider_accounts, proxmox, ssh, tls_pin
from tests import fake_digitalocean as fdo
from tests import fake_proxmox as fp
from tests.golden import test_phase3_golden as golden
from tests.hypervisor_guard import Guard, RealHypervisorCall
from tests.test_provider_accounts import (  # noqa: F401  (fixtures)
    API, TOKEN_B, _fresh_catalog, created, do, do_body, live, pve, pve_body, row,
)

REPO = Path(__file__).resolve().parents[1]
OTHER_PVE_TOKEN = "slipway@pve!slipway=99999999-1a2b-4c3d-8e9f-0123456789ab"


# ------------------------------------------------------------------- F41: the Proxmox port


@pytest.mark.parametrize(("given", "stored"), [
    ("https://pve.lan", "https://pve.lan:8006"),
    ("https://pve.lan/", "https://pve.lan:8006"),
    ("https://10.0.0.5", "https://10.0.0.5:8006"),
    ("https://[fd00::5]", "https://[fd00::5]:8006"),
    ("https://pve.lan:8006", "https://pve.lan:8006"),
    ("https://pve.lan:443", "https://pve.lan:443"),
])
def test_a_proxmox_url_is_stored_with_its_port(given, stored):
    assert proxmox.clean_url(given) == stored


def test_the_pin_the_client_and_terraform_name_one_port():
    url = proxmox.clean_url("https://pve.lan")
    assert tls_pin.url_host_port(url, proxmox.DEFAULT_PORT) == ("pve.lan", 8006)
    assert provider_accounts._where(url, "proxmox") == "pve.lan:8006"
    client = proxmox.ProxmoxClient(url, fp.TOKEN, "", transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    assert client._client.base_url.port == 8006


async def test_an_account_saved_without_a_port_is_called_where_it_was_trusted(admin_client, pve, live):
    account = await created(admin_client, pve_body(url="https://pve.test"))
    assert account["url"] == fp.URL
    assert live["reads"] == [("pve.test", 8006)]
    assert (await row(account["id"])).config["url"] == fp.URL


async def test_a_url_stored_before_the_port_was_written_in_is_the_same_address(admin_client, pve, live):
    account = await created(admin_client, pve_body())
    async with get_sessionmaker()() as db:
        stored = await db.get(ProviderAccount, uuid.UUID(account["id"]))
        stored.config = {**stored.config, "url": "https://pve.test"}
        await db.commit()
    # Only the name changes: no token asked for again, and the certificate pinned on :8006 is kept.
    resp = await admin_client.patch(f"{API}/{account['id']}", json={"name": "Lab two"})
    assert resp.status_code == 200, resp.text
    after = await row(account["id"])
    assert after.config["url"] == fp.URL and after.tls is not None and after.secret == fp.TOKEN


# -------------------------------------------------------------- F42: a Test that went stale


def _change_while_testing(monkeypatch, fields: dict):
    """Make the next Test's provider call save ``fields`` before it answers; returns the real ``_run_test``."""
    real = provider_accounts._run_test

    async def slow(acct):
        answer = await real(acct)  # the answer about the account as it was
        async with get_sessionmaker()() as db:
            fresh = await provider_accounts.get(db, acct.id)
            await provider_accounts.update(db, fresh, fields, actor=None)
        return answer

    monkeypatch.setattr(provider_accounts, "_run_test", slow)
    return real


async def test_a_token_replaced_during_a_test_keeps_its_own_state(admin_client, do, monkeypatch):
    account = await created(admin_client, do_body())
    real = _change_while_testing(monkeypatch, {"secret": TOKEN_B})
    resp = await admin_client.post(f"{API}/{account['id']}/test")
    assert resp.status_code == 409, resp.text
    assert resp.json()["code"] == "test_stale" and "test again" in resp.json()["detail"]
    stored = await row(account["id"])
    assert stored.secret == TOKEN_B
    assert stored.config["team"] is None  # not the old token's team
    assert stored.status == "unknown" and stored.checks == [] and stored.last_checked_at is None
    # Testing again tests the new token, and keeps its team.
    monkeypatch.setattr(provider_accounts, "_run_test", real)
    resp = await admin_client.post(f"{API}/{account['id']}/test")
    assert resp.status_code == 200, resp.text
    assert (await row(account["id"])).config["team"]["name"] == "Other Team"


async def test_a_proxmox_token_replaced_during_a_test_keeps_its_own_state(admin_client, pve, live, monkeypatch):
    account = await created(admin_client, pve_body())
    _change_while_testing(monkeypatch, {"secret": OTHER_PVE_TOKEN})
    resp = await admin_client.post(f"{API}/{account['id']}/test")
    assert resp.status_code == 409 and resp.json()["code"] == "test_stale", resp.text
    stored = await row(account["id"])
    assert stored.secret == OTHER_PVE_TOKEN and stored.status == "unknown" and stored.facts == {}


async def test_a_test_with_nothing_changed_is_kept(admin_client, do, monkeypatch):
    account = await created(admin_client, do_body())
    _change_while_testing(monkeypatch, {"name": "DO renamed"})  # a rename isn't what the Test was about
    resp = await admin_client.post(f"{API}/{account['id']}/test")
    assert resp.status_code == 200, resp.text
    stored = await row(account["id"])
    assert stored.name == "DO renamed" and stored.status == resp.json()["status"]
    assert stored.config["team"]["name"] == fdo.TEAM["name"]


# ------------------------------------------------------------------- F50: the golden's folder


def test_the_scenario_folder_has_the_recorded_length(tmp_path):
    for base in (tmp_path, tmp_path / ("d" * 120)):
        base.mkdir(exist_ok=True)
        folder = golden.scenario_folder(base)
        assert len(str(folder)) == golden.TMP_LEN and folder.is_dir() and not any(folder.iterdir())
        assert os.path.realpath(folder) == str(folder)


def test_norm_replaces_a_path_the_clip_cut_short(tmp_path):
    norm = golden.Norm(tmp_path)
    tmp = str(tmp_path)
    assert norm.text(f"Kept {tmp}/hosts and Kept {tmp[:12]}") == f"Kept <TMP>/hosts and Kept {golden.CUT_TMP}"
    assert norm.text(f"Kept {tmp[:2]}") == f"Kept {golden.CUT_TMP}"
    assert norm.text("Kept it/") == "Kept it/"  # the end of a word isn't a path
    assert norm.text("Kept /") == "Kept /"  # one character names no machine


@pytest.mark.parametrize("depth", [1, 6])
def test_the_phase_3_golden_passes_under_another_temporary_folder(tmp_path, depth):
    """A --basetemp longer (or shorter) than the one phase3.json was recorded under changes nothing."""
    base = tmp_path.joinpath(*(["deeper-folder"] * depth), "bt")
    base.parent.mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in os.environ.items() if k != "SLIPWAY_WRITE_GOLDEN"}
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--basetemp={base}",
         "tests/golden/test_phase3_golden.py::test_phase_3_behaves_as_recorded[bluegreen]"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-2000:]
    assert "1 passed" in result.stdout


# ------------------------------------------------------------------------ F51: SSH dials


@pytest.mark.own_guard
async def test_the_guard_stops_an_ssh_dial_off_this_machine(monkeypatch):
    guard = Guard().install(monkeypatch)
    assert "asyncssh.connect" in guard.installed and "asyncssh.get_server_host_key" in guard.installed
    target = ssh.SSHTarget(hostname="10.0.0.100", port=22, username="deploy", password="pw")
    with pytest.raises(RealHypervisorCall, match=r"a real SSH connection to 10\.0\.0\.100:22"):
        await ssh.connect(target, allow_unpinned=True)
    # ssh.probe (what hosts.check_host runs) goes through the same dial, even when the caller swallows the error.
    try:
        await ssh.probe(target)
    except RealHypervisorCall:
        pass
    assert len(guard.blocked) == 2
    with pytest.raises(pytest.fail.Exception, match="tried to reach something real"):
        guard.verify()


@pytest.mark.own_guard
async def test_the_guard_lets_loopback_and_unencodable_names_through(monkeypatch):
    guard = Guard().install(monkeypatch)
    with pytest.raises(ssh.SSHError, match="Could not connect to 127.0.0.1:1"):
        await ssh.connect(ssh.SSHTarget(hostname="127.0.0.1", port=1, username="deploy", password="pw"),
                          allow_unpinned=True)
    with pytest.raises(ssh.SSHError, match="Invalid hostname"):
        await ssh.connect(ssh.SSHTarget(hostname="web..example.com", port=22, username="deploy", password="pw"),
                          allow_unpinned=True)
    assert guard.blocked == []


# ---------------------------------------------------------------------------- F52: GitHub


@pytest.mark.own_guard
async def test_the_guard_stops_a_real_github_request(monkeypatch):
    guard = Guard().install(monkeypatch)
    assert "slipway.services.github.transport_factory" in guard.installed
    async with github.GitHubClient(None) as gh:
        with pytest.raises(RealHypervisorCall, match="a real GitHub request to api.github.com"):
            await gh.get_file(7, "slipway.yml", "main")
    with pytest.raises(RealHypervisorCall, match="a real GitHub request"):
        await github.exchange_code("code")
    assert len(guard.blocked) == 2
    with pytest.raises(pytest.fail.Exception, match="tried to reach something real"):
        guard.verify()


async def test_a_client_given_a_transport_uses_it():
    seen: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(404)

    async with github.GitHubClient(None, transport=httpx.MockTransport(handle)) as gh:
        assert await gh.get_file(7, "slipway.yml", "main") is None
    assert seen == ["/repositories/7/contents/slipway.yml"]
