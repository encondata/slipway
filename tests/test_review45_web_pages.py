"""Review findings F47 and F48 on the account and environment pages (P4 §17.1-17.2, P5 §11, §12.2).

F47: the DigitalOcean account dialog is filled with the monthly limit exactly, so saving it after changing only
something else sends no limit. F48: without providers:read, the New environment, Edit and environment pages name no
DigitalOcean, Proxmox or ESXi account, network, subnet or pool; the placement says why instead.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from slipway.db.session import get_sessionmaker
from slipway.models import AppSetting, Host, Repository
from slipway.services import cloudflare
from slipway.web import pages
from tests import do_fixtures as dof
from tests import fake_digitalocean as fdo
from tests import vm_fixtures as vf
from tests.conftest import make_user
from tests.test_accounts_web import PAGE, edit_json, scenario
from tests.test_data_api import client_with
from tests.test_env_machines import all_ready, pve_env
from tests.test_machines_web import _dialog, _live, _switchyard
from tests.test_provider_proxmox import World, a_world, net, world  # noqa: F401  (fixtures)
from tests.test_review_web import run_js

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")


# ------------------------------------------------------------------------------- F47: the limit


def test_f47_limit_field_is_exact():
    assert pages.limit_field(None) == ""
    assert pages.limit_field(0) == "0"
    assert pages.limit_field(15000) == "150"
    assert pages.limit_field(1000001) == "10000.01"
    assert pages.limit_field(1234567) == "12345.67"
    assert pages.limit_field(99999999) == "999999.99"
    assert pages.limit_field(123456789) == "1234567.89"
    assert pages.limit_field(5) == "0.05"


async def test_f47_a_large_limit_survives_an_edit_of_the_name(admin_client, monkeypatch, tmp_path):
    fdo.use_fake(monkeypatch, fdo.FakeDigitalOcean())
    account_id = await dof.make_account("do-main", monthly_limit_cents=123456789)
    page = (await admin_client.get(PAGE)).text
    edit = edit_json(page, str(account_id))
    assert edit["monthly_limit"] == "1234567.89"
    result = run_js(tmp_path, scenario(page, ["account-digitalocean"], """
var form = document.getElementById("account-digitalocean").querySelector("form");
var edit = h("button", { "data-account-open": "digitalocean", "data-account": JSON.stringify(EDIT) });
document.body.appendChild(edit);
await click(edit);
var out = { limit: field(form, "monthly_limit").value };
field(form, "name").value = "do-renamed";
await submit(form);
out.calls = fetchCalls; out.bodies = fetchBodies;
done(out);
""").replace("EDIT", json.dumps(edit)))
    assert result["limit"] == "1234567.89"
    assert result["calls"] == [f"PATCH /api/v1/provider-accounts/{account_id}"]
    assert result["bodies"] == [{"name": "do-renamed"}]
    r = await admin_client.patch(f"/api/v1/provider-accounts/{account_id}", json=result["bodies"][0])
    assert r.status_code == 200 and r.json()["monthly_limit_cents"] == 123456789


# ---------------------------------------------------------------------- F48: providers:read


WRITER = ["environments:read", "environments:write", "hosts:read", "machines:write", "providers:spend"]
# What the accounts below would show: their names, the network's subnet and its pool.
LEAKS = ("New VM on lab", "do-main", "10.0.0.0/24", "10.0.0.100", "10.0.0.150", "nyc3")


async def _accounts() -> dict[str, Any]:
    async with get_sessionmaker()() as db:
        db.add(Repository(github_id=778, full_name="acme/shop", owner="acme", name="shop",
                          html_url="https://github.com/acme/shop", detected_config={"manifest": True}))
        db.add(Host(name="box-1", hostname="10.9.9.9", username="deploy", host_key="ssh-ed25519 AAAA"))
        # Cloudflare set up, so a user who may see the accounts gets the DigitalOcean account select.
        db.add(AppSetting(key=cloudflare.SETTING_KEY, value={"zone": "example.com", "public_ip": None,
                                                             "proxied": False}, secret="c" * 40))
        await db.commit()
    pve = await vf.proxmox_account(name="lab")
    do_id = await dof.make_account("do-main")
    return {"pve": pve, "do": do_id}


async def test_f48_new_environment_without_providers_read_names_no_account(make_client):
    await make_user("admin@example.com")
    w = await _accounts()
    writer = await client_with(make_client, "writer@example.com", WRITER)
    page = (await writer.get("/environments/new")).text
    assert "No hosts yet" not in page and "box-1" in page
    for text in LEAKS:
        assert text not in page, text
    assert str(w["pve"].id) not in page and str(w["do"]) not in page
    assert "data-vm-account" not in page and 'data-vm-form="blue"' not in page and "data-do-fields" not in page
    # The placement says why: DigitalOcean is disabled with the reason, and the Hosts step names the permission.
    assert pages.DO_ACCOUNTS_TEXT in page
    assert 'name="where" value="digitalocean" data-no-send disabled' in page
    assert f"{pages.VM_ACCOUNTS_TEXT}." in page
    # The API refuses this user the same accounts.
    assert (await writer.get("/api/v1/provider-accounts")).status_code == 403

    # With providers:read the same user sees them (the rule is the permission, nothing else).
    reader = await client_with(make_client, "reader@example.com", [*WRITER, "providers:read"])
    page = (await reader.get("/environments/new")).text
    assert "New VM on lab" in page and "do-main" in page and "lan (10.0.0.0/24)" in page and "data-do-fields" in page
    assert pages.DO_ACCOUNTS_TEXT not in page and pages.VM_ACCOUNTS_TEXT not in page


async def test_f48_no_vm_reason_when_there_is_no_vm_account(make_client):
    await make_user("admin@example.com")
    async with get_sessionmaker()() as db:
        db.add(Host(name="box-1", hostname="10.9.9.9", username="deploy", host_key="ssh-ed25519 AAAA"))
        db.add(Repository(github_id=779, full_name="acme/web2", owner="acme", name="web2",
                          html_url="https://github.com/acme/web2", detected_config={"manifest": True}))
        await db.commit()
    writer = await client_with(make_client, "writer@example.com", WRITER)
    page = (await writer.get("/environments/new")).text
    assert pages.VM_ACCOUNTS_TEXT not in page and pages.DO_ACCOUNTS_TEXT in page


async def test_f48_edit_and_add_slot_without_providers_read_name_no_network(make_client, world):  # noqa: F811
    await make_user("admin@example.com")
    env = await pve_env(world, slots=("blue",))
    await all_ready(world, env)
    await _live(env, "blue")
    await _switchyard(env)
    await dof.make_account("do-main")
    writer = await client_with(make_client, "writer@example.com", WRITER)

    edit = (await writer.get(f"/environments/{env.env_id}/edit")).text
    for text in ("New VM on lab", "do-main", "10.0.0.0/24", "10.0.0.150"):
        assert text not in edit, text

    page = (await writer.get(f"/environments/{env.env_id}")).text
    dialog = _dialog(page, "add-slot")
    assert "data-vm-slot-form" not in dialog and "New VM on lab" not in dialog
    assert "10.0.0.0/24" not in dialog and "10.0.0.150" not in dialog and 'data-vm-form="green"' not in dialog

    reader = await client_with(make_client, "reader@example.com", [*WRITER, "providers:read"])
    dialog = _dialog((await reader.get(f"/environments/{env.env_id}")).text, "add-slot")
    assert "data-vm-slot-form" in dialog and "New VM on lab" in dialog and "lan (10.0.0.0/24)" in dialog
