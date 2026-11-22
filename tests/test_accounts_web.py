"""The pages for provider accounts and for hosts Slipway made (phase 4 §17.1, §17.5; phase 5 §12.1, §12.5, §12.6).

Phase 4 test 69's accounts card and read-only owned hosts, test 80's pages half (a host-less managed data owner on
the instance page and lists); phase 5 test 62's Integrations cards, account dialog with networks and trust dialog,
and test 63's account form JS (the networks table, the trust re-submit). The environment pages are S24a's and
S24b's.

Pages are rendered for viewer, developer, maintainer and admin. The JS runs the real slipway.js under the fake DOM
of tests/test_review_web.py, built from the dialogs as the server renders them, and the bodies it sends are posted
to the real API (FakeProxmox and FakeEsxi behind it, and a stand-in for the one unverified certificate read).
"""

from __future__ import annotations

import html
import json
import re
import uuid
from html.parser import HTMLParser
from typing import Any

from slipway.db.session import get_sessionmaker
from slipway.models import Environment, Host, Machine, ProviderAccount
from slipway.services import hosts as host_rules
from slipway.services import provider_accounts
from slipway.web import pages
from tests import do_fixtures as dof
from tests import fake_digitalocean as fdo
from tests import fake_proxmox as fp
from tests import vm_fixtures as vf
from tests.conftest import login, make_user
from tests.test_data_api import client_with
from tests.test_provider_accounts import PVE_PEM, esx, live, pve  # noqa: F401  (fixtures)
from tests.test_review_web import run_js

PAGE = "/settings/integrations"
OPEN = "0.0.0.0/0"


# ------------------------------------------------------------------------ helpers


async def role_clients(make_client) -> dict[str, Any]:
    """Signed-in clients for the four built-in roles (the first user, admin, holds every permission)."""
    out = {}
    for role in ("admin", "viewer", "developer", "maintainer"):
        await make_user(f"{role}@example.com", roles=None if role == "admin" else [role])
        c = make_client()
        await login(c, f"{role}@example.com")
        out[role] = c
    return out


class _Tree(HTMLParser):
    """The element with ``id`` as nested ``[tag, attrs, children]`` (text as strings), for the JS harness."""

    VOID = {"input", "br", "hr", "img", "meta", "link", "source", "wbr"}

    def __init__(self, element_id: str) -> None:
        super().__init__(convert_charrefs=True)
        self.element_id, self.stack, self.root = element_id, [], None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: ("" if v is None else v) for k, v in attrs}
        if tag in ("svg", "use"):
            return
        if not self.stack and a.get("id") != self.element_id:
            return
        node = [tag, a, []]
        if self.stack:
            self.stack[-1][2].append(node)
        else:
            self.root = node
        if tag not in self.VOID:
            self.stack.append(node)

    def handle_endtag(self, tag: str) -> None:
        if tag in ("svg", "use") or not self.stack:
            return
        if self.stack[-1][0] == tag:
            self.stack.pop()

    def handle_data(self, data: str) -> None:
        if self.stack and data.strip():
            self.stack[-1][2].append(data)


def tree(page: str, element_id: str) -> list:
    parser = _Tree(element_id)
    parser.feed(page)
    assert parser.root is not None, element_id
    return parser.root


BUILD = """
function build(node) {
  if (typeof node === "string") return node;
  return h(node[0], node[1], node[2].map(build));
}
var DIALOGS = %s;
DIALOGS.forEach(function (d) { document.body.appendChild(build(d)); });
document.dispatchEvent(new Event("DOMContentLoaded"));
// One answer per call of "METHOD path", used in order; the last one repeats.
var answers = {};
fetch = function (url, opts) {
  fetchCalls.push(opts.method + " " + url);
  fetchBodies.push(opts.body === undefined ? null : JSON.parse(opts.body));
  var key = opts.method + " " + url, list = answers[key] || [{ status: 200, body: {} }];
  var r = list.length > 1 ? list.shift() : list[0];
  return Promise.resolve({ status: r.status, ok: r.status >= 200 && r.status < 300, statusText: "HTTP " + r.status,
    json: function () { return Promise.resolve(JSON.parse(JSON.stringify(r.body))); } });
};
function $(sel, root) { return (root || document).querySelector(sel); }
function field(form, name) { return form.querySelector('[name="' + name + '"]'); }
function net(row, key) { return row.querySelector('[data-net="' + key + '"]'); }
async function click(el) { user("click", el); await settle(); }
async function submit(form) { user("submit", form, { submitter: form.querySelector('[type="submit"]') }); await settle(); }
"""


def scenario(page: str, ids: list[str], body: str) -> str:
    return BUILD % json.dumps([tree(page, i) for i in ids]) + body


def edit_json(page: str, account_id: str) -> dict:
    """The account an Edit button opens its dialog with (data-account, as rendered)."""
    found = re.search(r'data-account-open="\w+" data-account=\'([^\']*)\'', page[page.index(f'data-account-row="{account_id}"'):])
    assert found
    return json.loads(html.unescape(found.group(1)))


async def _ids(env: dof.DoEnv) -> dict[str, str]:
    return {k: str(v) for k, v in env.ids.items()}


# -------------------------------------------------------------- Integrations: who sees what


async def test_integrations_tab_page_cards_and_buttons_by_role(make_client):
    c = await role_clients(make_client)
    await dof.make_account("do-main")
    settings_only = await client_with(make_client, "ops@example.com", ["settings:write"])

    viewer = await c["viewer"].get(PAGE)
    assert viewer.status_code == 403
    assert 'href="/settings/integrations"' not in (await c["viewer"].get("/settings")).text

    for role in ("developer", "maintainer"):
        page = (await c[role].get(PAGE)).text
        assert 'href="/settings/integrations"' in page, role
        assert page.count('class="card account-card"') == 3
        for card in ("digitalocean-accounts", "proxmox-accounts", "esxi-accounts"):
            assert f'id="{card}"' in page
        assert "<h2>DigitalOcean</h2>" in page and "<h2>Proxmox</h2>" in page and "<h2>VMware ESXi</h2>" in page
        assert "do-main" in page
        # Reading accounts isn't changing them, and the Switchyard and Cloudflare cards need settings:write.
        assert "data-account-open" not in page and "data-account-trust" not in page and "/test" not in page
        assert 'id="account-digitalocean"' not in page and 'id="account-trust"' not in page
        assert "<h2>Switchyard</h2>" not in page and 'id="cloudflare-card"' not in page

    admin = (await c["admin"].get(PAGE)).text
    assert "<h2>Switchyard</h2>" in admin and 'id="cloudflare-card"' in admin
    assert admin.count('data-account-open="digitalocean"') == 2  # Add account, and Edit on do-main
    assert 'data-account-open="proxmox"' in admin and 'data-account-open="esxi"' in admin
    for dialog in ("account-digitalocean", "account-proxmox", "account-esxi", "account-trust"):
        assert f'id="{dialog}"' in admin

    ops = await settings_only.get(PAGE)
    assert ops.status_code == 200 and "<h2>Switchyard</h2>" in ops.text and "account-card" not in ops.text
    assert 'href="/settings/integrations"' in ops.text


async def test_account_cards_list_accounts_without_their_secrets(admin_client, monkeypatch):
    vf.quiet_network(monkeypatch)
    do_id = await dof.make_account("do-main", ssh_sources=["198.51.100.0/24", OPEN], monthly_limit_cents=15000,
                                   team={"id": "t1", "name": "Acme"})
    env = await dof.make_do_env(name="shop", account_id=do_id)
    pve_account = await vf.proxmox_account(name="lab")
    await vf.vm_env(pve_account, name="uat")
    esx_account = await vf.esxi_account(name="esx-01", pem=None)
    gone = ProviderAccount(provider="digitalocean", name="old-do", config={}, status="unknown",
                           removed_at=pages.utcnow())
    async with get_sessionmaker()() as db:
        db.add(gone)
        await db.commit()

    page = (await admin_client.get(PAGE)).text
    for secret in (fdo.TOKEN, fp.TOKEN, fp.TOKEN.split("=", 1)[1], vf.ESXI_PASSWORD):
        assert secret not in page

    do_row = page[page.index(f'data-account-row="{do_id}"'):]
    do_row = do_row[:do_row.index("</tr>")]
    assert "nyc3" in do_row and "Acme" in do_row and "About $47 a month" in do_row and "Limit $150" in do_row
    assert "<span class=\"chip\">shop</span>" in do_row and "SSH open to the internet" in do_row
    assert f"(…{fdo.TOKEN[-4:]})" in do_row and 'data-open="remove-account-' in do_row
    assert f'data-api="POST /api/v1/provider-accounts/{do_id}/test"' in do_row
    edit = edit_json(page, str(do_id))
    assert edit["monthly_limit"] == "150" and edit["ssh_sources"] == ["198.51.100.0/24", OPEN]
    assert "secret" not in edit and edit["has_secret"] is True and env.name not in json.dumps(edit)

    pve_row = page[page.index(f'data-account-row="{pve_account.id}"'):]
    pve_row = pve_row[:pve_row.index("</tr>")]
    assert fp.URL in pve_row and '<span class="chip mono">lan</span>' in pve_row
    assert "slipway-uat-blue" in pve_row and ">OK<" in pve_row and "Certificate not trusted" not in pve_row
    esx_row = page[page.index(f'data-account-row="{esx_account.id}"'):]
    esx_row = esx_row[:esx_row.index("</tr>")]
    assert "Certificate not trusted" in esx_row and f'data-account-trust="{esx_account.id}"' in esx_row

    old_row = page[page.index(f'data-account-row="{gone.id}"'):]
    old_row = old_row[:old_row.index("</tr>")]
    assert "Removed" in old_row and "data-account-open" not in old_row and "/test" not in old_row
    assert f'id="remove-account-{gone.id}"' not in page

    # Remove asks for the typed name and says who uses it.
    remove = page[page.index(f'id="remove-account-{pve_account.id}"'):]
    remove = remove[:remove.index("</dialog>")]
    assert 'data-must-equal="lab"' in remove and "It has VMs: slipway-uat-blue." in remove
    assert f'data-form="DELETE /api/v1/provider-accounts/{pve_account.id}"' in remove


async def test_account_dialogs_have_each_providers_fields(admin_client):
    page = (await admin_client.get(PAGE)).text

    def dialog(dialog_id: str) -> str:
        part = page[page.index(f'id="{dialog_id}"'):]
        return part[:part.index("</dialog>")]

    do = dialog("account-digitalocean")
    for name in ("name", "region", "production", "secret", "ssh_sources", "monthly_limit", "prices", "clear_secret"):
        assert f'name="{name}"' in do, name
    assert 'type="password"' in do and "For production environments" in do
    assert "Droplets never receive it." in do and "0.0.0.0/0 lets the whole internet try SSH." in do
    assert '<option value="nyc3" selected>' in do and "data-account-test" in do
    assert "data-form=" not in do  # wireAccountForm saves it, not the generic form handler

    pve_dialog = dialog("account-proxmox")
    for name in ("name", "url", "secret", "node", "pool", "storage", "template_vmid"):
        assert f'name="{name}"' in pve_dialog, name
    assert 'data-networks="proxmox"' in pve_dialog and "<span>Bridge</span><span>VLAN</span>" in pve_dialog
    assert "The API token, user@realm!tokenid=&lt;secret&gt;. Slipway shows it never again." in pve_dialog
    esx_dialog = dialog("account-esxi")
    for name in ("name", "url", "user", "secret", "datastore", "resource_pool", "source_vm"):
        assert f'name="{name}"' in esx_dialog, name
    assert 'data-networks="esxi"' in esx_dialog and "<span>Port group</span>" in esx_dialog
    assert "Slipway's markers are what protect the others." in esx_dialog

    trust = dialog("account-trust")
    assert "Trust this certificate?" in trust and 'data-slot="fingerprint_sha256"' in trust
    for slot in ("subject", "issuer", "not_after", "sans"):
        assert f'data-slot="{slot}"' in trust
    assert "Node › System › Certificates" in trust and "/etc/vmware/ssl/rui.crt" in trust


# ------------------------------------------------------------------- hosts Slipway made


async def test_hosts_list_shows_provider_and_build_chips_and_hides_owned_actions(admin_client, monkeypatch):
    vf.quiet_network(monkeypatch)
    env = await dof.make_do_env(name="shop")
    blue = env.host_ids["blue"]
    async with get_sessionmaker()() as db:
        green = await db.get(Host, env.host_ids["green"])
        host_rules.set_phase(green, "ready", size="s-1vcpu-1gb", public_ip="203.0.113.12", droplet_name=green.name)
        green.host_key, green.hostname = "ssh-ed25519 AAAAgreen", "203.0.113.12"
        await db.commit()
    vm = await vf.vm_env(await vf.proxmox_account(name="lab"), name="uat")
    esx = await vf.vm_env(await vf.esxi_account(name="esx-01"), name="qa")
    by_hand = (await admin_client.post("/api/v1/hosts", json={"name": "lan-01", "hostname": "10.0.9.9",
                                                              "username": "deploy"})).json()

    page = (await admin_client.get("/hosts")).text

    def row(host_id: Any) -> str:
        part = page[page.index(f'href="/hosts/{host_id}"'):]
        return part[:part.index("</tr>")]

    planned = row(blue)
    assert f'<a class="chip provider-chip" href="/environments/{env.env_id}"' in planned
    assert "DigitalOcean droplet · shop blue" in planned and "Not built yet" in planned
    assert f"/api/v1/hosts/{blue}/check" not in planned
    assert "Slipway pins slipway-shop-blue&#39;s key itself when it makes the droplet: deploy to blue" in planned
    assert "address not known yet" in planned and ".invalid" not in planned
    ready = row(env.host_ids["green"])
    assert "Ready" in ready and f"/api/v1/hosts/{env.host_ids['green']}/check" in ready and "Unverified" in ready
    assert "Proxmox VM · uat blue" in row(vm.hosts["blue"]) and "Not built yet" in row(vm.hosts["blue"])
    assert vm.addresses["blue"] in row(vm.hosts["blue"])
    assert "ESXi VM · qa blue" in row(esx.hosts["blue"])
    own = row(by_hand["id"])
    assert "provider-chip" not in own and "build-chip" not in own and f"/api/v1/hosts/{by_hand['id']}/check" in own


async def test_hosts_list_chip_without_environments_read(admin_client, make_client):
    env = await dof.make_do_env(name="shop")
    hosts_only = await client_with(make_client, "hosts@example.com", ["hosts:read"])
    page = (await hosts_only.get("/hosts")).text
    assert '<span class="chip provider-chip"' in page and "DigitalOcean droplet · shop blue" in page
    assert f"/environments/{env.env_id}" not in page


async def test_host_detail_of_an_owned_droplet_is_read_only(admin_client):
    env = await dof.make_do_env(name="shop")
    blue = env.host_ids["blue"]
    page = (await admin_client.get(f"/hosts/{blue}")).text
    assert "DigitalOcean droplet · shop blue" in page and "Not built yet" in page
    assert "Slipway made this droplet for" in page and f'href="/environments/{env.env_id}"' in page
    assert "on do-main" in page
    # Remove, Reset key, the check and the key-setup card are gone, each with its reason.
    assert f'data-api="DELETE /api/v1/hosts/{blue}"' not in page
    assert "slipway-shop-blue goes when shop removes its blue slot" in page
    assert f"/api/v1/hosts/{blue}/check" not in page and "reset-host-key" not in page
    assert "Finish setting up" not in page and "authorized_keys" not in page
    # Edit keeps only what people call it.
    edit = page[page.index('id="edit-host"'):]
    edit = edit[:edit.index("</dialog>")]
    assert 'name="label"' in edit and 'name="description"' in edit
    for name in ("hostname", "port", "username", "deploy_root", "proxy_address", "lan_address", "name"):
        assert f'name="{name}"' not in edit, name
    assert "slipway-shop-blue is a droplet Slipway made for shop; change it on the environment." in edit
    r = await admin_client.patch(f"/api/v1/hosts/{blue}", json={"label": "web", "description": "Shop's blue"})
    assert r.status_code == 200

    # Built: the check comes back, the provider card shows the droplet, a size behind the confirmed one is pending.
    async with get_sessionmaker()() as db:
        host = await db.get(Host, blue)
        host_rules.set_phase(host, "ready", droplet_name=host.name, region="nyc3", size="s-1vcpu-512mb",
                             public_ip="203.0.113.12", private_ip="10.10.0.2")
        host.host_key, host.host_key_fingerprint = "ssh-ed25519 AAAAblue", "SHA256:blue"
        await db.commit()
    page = (await admin_client.get(f"/hosts/{blue}")).text
    assert f"/api/v1/hosts/{blue}/check" in page and "Ready" in page
    assert "203.0.113.12" in page and "10.10.0.2" in page and "s-1vcpu-512mb" in page
    assert "Resize pending: applies at blue&#39;s next deploy" in page
    assert "reset-host-key" not in page
    assert "key was made by Slipway with the droplet for shop" in page
    # Nothing is claimed onto it.
    assert "data-can-claim" not in page and 'id="claim-dialog"' not in page


async def test_host_detail_of_a_vm_shows_its_machine(admin_client, monkeypatch):
    vf.quiet_network(monkeypatch)
    vm = await vf.vm_env(await vf.proxmox_account(name="lab"), name="uat")
    host_id = vm.hosts["blue"]
    page = (await admin_client.get(f"/hosts/{host_id}")).text
    assert "Proxmox VM · uat blue" in page and "Slipway made this VM for" in page and "on lab" in page
    assert vm.addresses["blue"] in page and "4 vCPU · 8 GB · 64 GB" in page
    assert "slipway-uat-blue goes when uat removes its blue slot" in page
    async with get_sessionmaker()() as db:
        machine = await db.get(Machine, vm.machines["blue"])
        machine.stage, machine.ready_at = "ready", pages.utcnow()
        machine.applied = {"cores": 2, "memory_mb": 4096, "disk_gb": 64}
        host_rules.set_phase(machine.host, "ready")
        machine.host.host_key = "ssh-ed25519 AAAAvm"
        await db.commit()
    page = (await admin_client.get(f"/hosts/{host_id}")).text
    assert "2 vCPU · 4 GB · 64 GB" in page and "Resize pending: applies at blue&#39;s next deploy" in page
    assert "key was pinned from lab" in page


def test_build_chips_from_a_live_read():
    host = host_rules.planned_host("uat", "blue", provider="proxmox", hostname="10.0.0.101")
    assert pages.build_state(host) == "planned"
    host_rules.set_phase(host, "creating")
    assert pages.build_state(host) == "creating" and pages.BUILD_CHIPS["creating"][0] == "Building"
    host_rules.set_phase(host, "ready")
    assert pages.build_state(host) == "ready"
    assert pages.build_state(host, live={"exists": True, "ours": True, "hidden": True}) == "hidden"
    assert pages.build_state(host, live={"exists": False, "ours": False}) == "lost"
    assert pages.build_state(host, live={"exists": True, "ours": False}) == "lost"
    assert pages.build_state(host, live={"exists": True, "ours": True, "power": "stopped"}) == "off"
    assert pages.build_state(host, live={"exists": True, "ours": True, "power": "running"}) == "ready"
    assert pages.build_state(host, live={"error": "Proxmox couldn't be reached"}) == "ready"
    host_rules.set_phase(host, "gone")
    view = pages.host_view(host)
    assert view["state"] == "gone" and "Gone: deploy to rebuild" in str(pages.build_chip(view, gone_text="Gone: deploy to rebuild"))
    droplet = host_rules.planned_host("shop", "blue", provider="digitalocean")
    host_rules.set_phase(droplet, "ready")
    assert pages.build_state(droplet, live={"exists": False}) == "ready"  # Lost, Hidden and Off are a VM's
    assert [pages.BUILD_CHIPS[k][0] for k in ("planned", "creating", "ready", "gone", "lost", "hidden", "off")] == \
        ["Not built yet", "Building", "Ready", "Gone", "Lost", "Hidden", "Off"]
    assert pages.host_view(Host(name="h", hostname="10.0.0.1", username="deploy"))["kind"] is None


# ------------------------------------------------- instance page, lists and placement


async def test_host_less_owner_and_owned_slot_on_the_instance_pages(admin_client):
    env = await dof.make_do_env(name="shop")
    ids = await _ids(env)
    page = await admin_client.get(f"/instances/{ids['data']}")
    assert page.status_code == 200
    assert "its data is in a managed database" in page.text and "/hosts/None" not in page.text
    assert "shop's managed database, so it has no host of its own" in page.text
    assert "/containers" not in page.text and "/logs?tail" not in page.text and "Folder on host" not in page.text

    slot = (await admin_client.get(f"/instances/{ids['blue']}")).text
    assert "Its host is the droplet slipway-shop-blue, which Slipway made on do-main." in slot
    assert "Slipway pins slipway-shop-blue&#39;s key itself when it makes the droplet: deploy to blue." in slot
    assert "DigitalOcean droplet · shop blue" in slot

    # The lists leave the host-less owner out; the host counts don't trip on it.
    instances = (await admin_client.get("/instances")).text
    assert "shop blue" in instances and "shop data" not in instances
    assert (await admin_client.get("/hosts")).status_code == 200
    assert "shop data" not in (await admin_client.get("/search?q=shop")).text
    assert "shop data" not in (await admin_client.get("/repositories")).text
    assert "In a managed database" in (await admin_client.get("/environments")).text


async def test_owned_hosts_are_not_offered_for_placement(admin_client):
    env = await dof.make_do_env(name="shop")
    await admin_client.post("/api/v1/hosts", json={"name": "lan-01", "hostname": "10.0.9.9", "username": "deploy"})
    new = (await admin_client.get("/instances/new")).text
    assert "lan-01" in new and "slipway-shop-blue" not in new
    flow = (await admin_client.get("/environments/new")).text
    assert "slipway-shop-blue" not in flow and "slipway-shop-green" not in flow
    # An instance keeps its own host on its edit page; others' owned hosts stay out.
    async with get_sessionmaker()() as db:
        context = await pages._form_context(db, keep=env.host_ids["blue"])
    names = [h.name for h in context["hosts"]]
    assert "slipway-shop-blue" in names and "slipway-shop-green" not in names and "lan-01" in names


def test_host_view_refusals_name_the_environment_slot_and_account():
    host = host_rules.planned_host("uat", "green", provider="esxi", hostname="10.0.0.102")
    host.owner_environment_id = uuid.uuid4()
    env = Environment(name="uat")
    view = pages.host_view(host, env=env, slot="green", account="esx-01")
    assert view["owned"] and view["kind"] == "ESXi VM" and view["noun"] == "VM"
    assert view["off"]["delete"] == "slipway-uat-green goes when uat removes its green slot"
    assert view["off"]["edit_address"] == "slipway-uat-green is a VM Slipway made for uat; change it on the environment"
    assert view["off"]["claim"] == "slipway-uat-green is a VM of environment uat; only its slots run there"
    assert "pinned from esx-01" in view["off"]["reset_key"]
    assert view["off"]["check"] == "Slipway pins slipway-uat-green's key itself when it makes the VM: deploy to green"
    by_hand = pages.host_view(Host(name="lan-01", hostname="10.0.9.9", username="deploy", provider="ssh"))
    assert not any(by_hand["off"].values()) and not by_hand["made"]


# ---------------------------------------------------------------------- the account form JS


def _cert(pem: str) -> dict:
    return provider_accounts.certificate_view(pem)


async def test_js_proxmox_add_networks_table_and_trust_resubmit(admin_client, pve, live, tmp_path):  # noqa: F811
    page = (await admin_client.get(PAGE)).text
    cert = _cert(PVE_PEM)  # what the live fixture's Proxmox presents
    result = run_js(tmp_path, scenario(page, ["account-proxmox", "account-trust"], """
var opener = h("button", { "data-account-open": "proxmox" });
document.body.appendChild(opener);
await click(opener);
var dlg = document.getElementById("account-proxmox"), form = dlg.querySelector("form");
var out = { open: "open" in dlg.attrs, title: dlg.querySelector('[data-slot="account_title"]').textContent,
            rows: form.querySelectorAll("[data-network-row]").length,
            test_hidden: form.querySelector("[data-account-test]").hidden };
field(form, "name").value = "Lab";
field(form, "url").value = "%(url)s";
field(form, "secret").value = "%(token)s";
field(form, "node").value = "pve1"; field(form, "pool").value = "%(pool)s";
field(form, "storage").value = "%(storage)s"; field(form, "template_vmid").value = "%(template)s";
var row = form.querySelector("[data-network-row]");
net(row, "name").value = "lan"; net(row, "bridge").value = "vmbr0"; net(row, "subnet").value = "10.0.0.0/24";
net(row, "gateway").value = "10.0.0.1"; net(row, "dns_servers").value = "10.0.0.1, 1.1.1.1";
net(row, "pool_first").value = "10.0.0.100"; net(row, "pool_last").value = "10.0.0.150";
await click(form.querySelector("[data-network-add]"));
var second = form.querySelectorAll("[data-network-row]")[1];
net(second, "name").value = "dmz"; net(second, "bridge").value = "vmbr1"; net(second, "vlan_tag").value = "20";
net(second, "subnet").value = "10.0.20.0/24"; net(second, "gateway").value = "10.0.20.1";
await click(form.querySelector("[data-network-add]"));  // an empty row isn't sent
out.columns = second.querySelectorAll("[data-net]").map(function (i) { return i.dataset.net; });
answers["POST /api/v1/provider-accounts"] = [
  { status: 409, body: { detail: "Slipway doesn't trust pve.test:8006's certificate yet", code: "tls_untrusted", certificate: CERT } },
  { status: 201, body: { id: "new" } }];
await submit(form);
var trust = document.getElementById("account-trust");
out.trust = { open: "open" in trust.attrs, fp: trust.querySelector('[data-slot="fingerprint_sha256"]').textContent,
              subject: trust.querySelector('[data-slot="subject"]').textContent,
              where: trust.querySelector('[data-slot="where"]').textContent,
              pve_hint: trust.querySelector('[data-trust-hint="proxmox"]').hidden,
              esxi_hint: trust.querySelector('[data-trust-hint="esxi"]').hidden };
await submit(trust.querySelector("form"));
out.calls = fetchCalls; out.bodies = fetchBodies; out.hrefs = hrefs;
done(out);
""" % {"url": fp.URL, "token": fp.TOKEN, "pool": fp.POOL, "storage": fp.STORAGE, "template": fp.TEMPLATE_VMID})
        .replace("CERT", json.dumps(cert)))
    assert result["open"] and result["title"] == "Add a Proxmox account" and result["rows"] == 1
    assert result["test_hidden"] is True  # a new Proxmox account is tested after the save
    assert result["columns"] == ["name", "bridge", "vlan_tag", "subnet", "gateway", "dns_servers", "pool_first",
                                 "pool_last"]
    assert result["trust"] == {"open": True, "fp": cert["fingerprint_sha256"], "subject": cert["subject"],
                               "where": fp.URL, "pve_hint": False, "esxi_hint": True}
    assert result["calls"] == ["POST /api/v1/provider-accounts"] * 2 and result["hrefs"] == ["RELOAD"]
    first, second = result["bodies"]
    assert "trust_fingerprint" not in first and second["trust_fingerprint"] == cert["fingerprint_sha256"]
    assert first["networks"] == [
        {"name": "lan", "bridge": "vmbr0", "vlan_tag": None, "subnet": "10.0.0.0/24", "gateway": "10.0.0.1",
         "dns_servers": ["10.0.0.1", "1.1.1.1"], "pool": {"first": "10.0.0.100", "last": "10.0.0.150"}},
        {"name": "dmz", "bridge": "vmbr1", "vlan_tag": 20, "subnet": "10.0.20.0/24", "gateway": "10.0.20.1",
         "dns_servers": [], "pool": None}]
    assert first["provider"] == "proxmox" and first["template_vmid"] == fp.TEMPLATE_VMID

    # The bodies are what the API takes: the first is refused with the certificate, the second saves the account.
    r = await admin_client.post("/api/v1/provider-accounts", json=first)
    assert r.status_code == 409 and r.json()["code"] == "tls_untrusted"
    assert r.json()["certificate"]["fingerprint_sha256"] == cert["fingerprint_sha256"]
    r = await admin_client.post("/api/v1/provider-accounts", json=second)
    assert r.status_code == 201, r.text
    saved = r.json()
    assert [n["name"] for n in saved["networks"]] == ["lan", "dmz"] and saved["tls"]["fingerprint_sha256"] == \
        cert["fingerprint_sha256"]


async def test_js_esxi_edit_keeps_untouched_fields_and_trusts_a_moved_address(admin_client, esx, live, tmp_path):  # noqa: F811
    account = await vf.esxi_account(name="esx-01", networks=[{**vf.LAN_ESXI}])
    live["pems"][("esxi2.test", 443)] = vf.ESXI_PEM
    page = (await admin_client.get(PAGE)).text
    edit = edit_json(page, str(account.id))
    cert = _cert(vf.ESXI_PEM)
    result = run_js(tmp_path, scenario(page, ["account-esxi", "account-trust"], """
var EDIT = %s;
var opener = h("button", { "data-account-open": "esxi", "data-account": JSON.stringify(EDIT) });
document.body.appendChild(opener);
await click(opener);
var form = document.getElementById("account-esxi").querySelector("form");
var rows = form.querySelectorAll("[data-network-row]");
var out = { title: document.getElementById("account-esxi").querySelector('[data-slot="account_title"]').textContent,
            name: field(form, "name").value, url: field(form, "url").value, rows: rows.length,
            port_group: net(rows[0], "port_group").value, secret: field(form, "secret").value,
            placeholder: field(form, "secret").getAttribute("placeholder"),
            test_hidden: form.querySelector("[data-account-test]").hidden };
// Nothing changed: an empty PATCH.
answers["PATCH /api/v1/provider-accounts/" + EDIT.id] = [{ status: 200, body: {} }];
await submit(form);
// A new address: saved together with trusting its certificate.
field(form, "url").value = "https://esxi2.test";
field(form, "secret").value = "%s";
answers["PATCH /api/v1/provider-accounts/" + EDIT.id] = [
  { status: 409, body: { detail: "That fingerprint isn't the certificate esxi2.test:443 presents now", code: "tls_mismatch", certificate: CERT } },
  { status: 200, body: {} }];
await submit(form);
var trust = document.getElementById("account-trust");
out.note_hidden = trust.querySelector('[data-show-if="note"]').hidden;
out.esxi_hint = trust.querySelector('[data-trust-hint="esxi"]').hidden;
await submit(trust.querySelector("form"));
out.calls = fetchCalls; out.bodies = fetchBodies;
done(out);
""" % (json.dumps(edit), vf.ESXI_PASSWORD)).replace("CERT", json.dumps(cert)))
    assert result["title"] == "Edit esx-01" and result["name"] == "esx-01" and result["url"] == vf.ESXI_URL
    assert result["rows"] == 1 and result["port_group"] == "VM Network" and result["secret"] == ""
    assert result["placeholder"] == "Set; leave it empty to keep it" and result["test_hidden"] is False
    nothing, probe, trusted = result["bodies"]
    assert nothing == {}
    assert probe == {"url": "https://esxi2.test", "secret": vf.ESXI_PASSWORD,
                     "trust_fingerprint": ":".join(["00"] * 32)}
    assert trusted == {"url": "https://esxi2.test", "secret": vf.ESXI_PASSWORD,
                       "trust_fingerprint": cert["fingerprint_sha256"]}
    assert result["note_hidden"] is True and result["esxi_hint"] is False  # the probe's refusal isn't a mistake

    api = f"/api/v1/provider-accounts/{account.id}"
    assert (await admin_client.patch(api, json=nothing)).status_code == 200
    r = await admin_client.patch(api, json=probe)
    assert r.status_code == 409 and r.json()["code"] == "tls_mismatch"
    assert r.json()["certificate"]["fingerprint_sha256"] == cert["fingerprint_sha256"]
    r = await admin_client.patch(api, json=trusted)
    assert r.status_code == 200, r.text
    assert r.json()["url"] == "https://esxi2.test" and r.json()["tls"]["fingerprint_sha256"] == cert["fingerprint_sha256"]


async def test_js_trust_a_renewed_certificate_from_the_card(admin_client, pve, live, tmp_path):  # noqa: F811
    account = await vf.proxmox_account(name="lab", pem=None)
    page = (await admin_client.get(PAGE)).text
    button = re.search(r'<button[^>]*data-account-trust="%s"[^>]*>' % account.id, page).group(0)
    attrs = dict(re.findall(r'([\w-]+)="([^"]*)"', button))
    cert = _cert(PVE_PEM)
    result = run_js(tmp_path, scenario(page, ["account-trust"], """
var btn = h("button", ATTRS);
document.body.appendChild(btn);
answers["POST /api/v1/provider-accounts/%s/trust"] = [
  { status: 409, body: { detail: "That fingerprint isn't the certificate", code: "tls_mismatch", certificate: CERT } },
  { status: 200, body: {} }];
await click(btn);
var trust = document.getElementById("account-trust");
var out = { open: "open" in trust.attrs, where: trust.querySelector('[data-slot="where"]').textContent };
await submit(trust.querySelector("form"));
out.bodies = fetchBodies; out.hrefs = hrefs;
done(out);
""" % account.id).replace("ATTRS", json.dumps({k: html.unescape(v) for k, v in attrs.items()}))
        .replace("CERT", json.dumps(cert)))
    assert result["open"] and result["where"] == fp.URL
    assert result["bodies"] == [{"fingerprint": ":".join(["00"] * 32)}, {"fingerprint": cert["fingerprint_sha256"]}]
    assert result["hrefs"] == ["RELOAD"]
    trust_api = f"/api/v1/provider-accounts/{account.id}/trust"
    r = await admin_client.post(trust_api, json=result["bodies"][0])
    assert r.status_code == 409 and r.json()["certificate"]["fingerprint_sha256"] == cert["fingerprint_sha256"]
    r = await admin_client.post(trust_api, json=result["bodies"][1])
    assert r.status_code == 200 and r.json()["tls"]["fingerprint_sha256"] == cert["fingerprint_sha256"]


async def test_js_digitalocean_test_unsaved_token_and_edit_the_limit(admin_client, monkeypatch, tmp_path):
    fdo.use_fake(monkeypatch, fdo.FakeDigitalOcean())
    account_id = await dof.make_account("do-main", monthly_limit_cents=15000)
    await dof.make_do_env(name="shop", account_id=account_id)
    page = (await admin_client.get(PAGE)).text
    edit = edit_json(page, str(account_id))
    result = run_js(tmp_path, scenario(page, ["account-digitalocean"], """
var add = h("button", { "data-account-open": "digitalocean" });
document.body.appendChild(add);
await click(add);
var form = document.getElementById("account-digitalocean").querySelector("form");
var out = { region: field(form, "region").value, clear_hidden: form.querySelector("[data-clear-secret]").hidden };
// Test without a token says what to do; with one it tests the token as typed.
await click(form.querySelector("[data-account-test]"));
out.no_token = fetchCalls.length;
field(form, "secret").value = "%(token)s";
field(form, "region").value = "fra1";
answers["POST /api/v1/provider-accounts/test"] = [{ status: 200, body: { status: "warning", facts: {}, checks: [
  { name: "account", ok: true, level: "ok", text: "Team Acme, the account is active" },
  { name: "droplets", ok: false, level: "warning", text: "Room for one more" }] } }];
await click(form.querySelector("[data-account-test]"));
var box = form.querySelector("[data-account-test-result]");
out.checks = box.querySelectorAll("li").map(function (li) { return li.textContent; });
out.status = box.querySelector("[data-account-test-status]").textContent;
out.box_hidden = box.hidden;
field(form, "name").value = "do-two";
field(form, "ssh_sources").value = "198.51.100.0/24\\n203.0.113.0/24";
field(form, "monthly_limit").value = "200";
await submit(form);
// Edit: only what changed is sent; an emptied limit is cleared.
var edit = h("button", { "data-account-open": "digitalocean", "data-account": JSON.stringify(EDIT) });
document.body.appendChild(edit);
await click(edit);
out.edit = { name: field(form, "name").value, limit: field(form, "monthly_limit").value,
             sources: field(form, "ssh_sources").value, clear_hidden: form.querySelector("[data-clear-secret]").hidden,
             secret: field(form, "secret").value };
field(form, "monthly_limit").value = "250";
await submit(form);
field(form, "monthly_limit").value = "";
await submit(form);
field(form, "monthly_limit").value = "lots";
await submit(form);
out.calls = fetchCalls; out.bodies = fetchBodies; out.toasts = toasts();
done(out);
""" % {"token": fdo.TOKEN}).replace("EDIT", json.dumps(edit)))
    assert result["region"] == "nyc3" and result["clear_hidden"] is True and result["no_token"] == 0
    assert result["checks"] == ["OKTeam Acme, the account is active", "WarningRoom for one more"]
    assert result["status"] == "It works, with warnings." and result["box_hidden"] is False
    assert result["edit"] == {"name": "do-main", "limit": "150", "sources": "198.51.100.0/24", "clear_hidden": False,
                              "secret": ""}
    test_body, created, raised, cleared = result["bodies"]
    assert test_body == {"secret": fdo.TOKEN, "region": "fra1"}
    assert created == {"provider": "digitalocean", "name": "do-two", "region": "fra1", "production": False,
                       "ssh_sources": ["198.51.100.0/24", "203.0.113.0/24"], "monthly_limit_cents": 20000,
                       "secret": fdo.TOKEN}
    assert raised == {"monthly_limit_cents": 25000} and cleared == {"monthly_limit_cents": None}
    assert result["calls"][-1] == f"PATCH /api/v1/provider-accounts/{account_id}" and len(result["calls"]) == 4
    assert any("number of US dollars" in t for t in result["toasts"])

    # The API takes them: the SSH sources the environment relies on weren't sent again.
    api = f"/api/v1/provider-accounts/{account_id}"
    r = await admin_client.patch(api, json=raised)
    assert r.status_code == 200 and r.json()["monthly_limit_cents"] == 25000
    r = await admin_client.patch(api, json=cleared)
    assert r.status_code == 200 and r.json()["monthly_limit_cents"] is None
    r = await admin_client.post("/api/v1/provider-accounts/test", json=test_body)
    assert r.status_code == 200 and {c["name"] for c in r.json()["checks"]} >= {"account", "region"}


async def test_role_without_providers_write_gets_no_account_buttons_even_with_hosts_write(make_client):
    await make_user("admin@example.com")
    await dof.make_account("do-main")
    c = await client_with(make_client, "reader@example.com", ["providers:read", "hosts:write", "hosts:read"])
    page = (await c.get(PAGE)).text
    assert "do-main" in page and "data-account-open" not in page and "remove-account-" not in page
    assert (await c.get("/api/v1/provider-accounts")).status_code == 200
    assert (await c.post("/api/v1/provider-accounts/test", json={"secret": "x"})).status_code == 403
