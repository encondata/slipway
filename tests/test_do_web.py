"""The environment pages for DigitalOcean (S24a; phase 4 §12.4, §15.13, §17.2-17.5).

Phase 4 test 69's remainder: the New environment flow's DigitalOcean fields for each role (Where, Production, the
account and sizes from the catalog, the load balancer, the Review's cost table and its typed total), the
environment page's DigitalOcean card and each of its callouts (Billing, SSH open to the internet, a gone active
droplet, a droplet powered off, an old pending create, a host holding a droplet's address, a certificate near its
end with a failed renewal), the Slots card's host cell with its chips and the pending-size phrase, the production
danger zone's states (Retire, Un-retire, Take off the air, Delete), the dialogs (Delete with its lists, drop_data and
the production phrases; Activate with the typed name; Grow and Add a slot with the cost confirm; Retire, Un-retire,
Take off the air), the Environments list's Billing marker, and the deployment page (started by the renewal loop,
a production teardown's retry phrases, Make it again, empty).

Pages are rendered as each role sees them; the JS runs the real slipway.js under the fake DOM of
tests/test_review_web.py. FakeDigitalOcean answers every DigitalOcean read (the GET /cloud answer the card's
renderer is fed comes from the real route). Jobs are queued and never run.
"""

from __future__ import annotations

import html
import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import update

from slipway.db.session import get_sessionmaker
from slipway.models import (
    AppSetting,
    Backup,
    Deployment,
    Environment,
    Host,
    Instance,
    ProviderAccount,
    Repository,
    Resource,
)
from slipway.services import cloudflare, do_rules
from slipway.services import hosts as host_rules
from slipway.web import pages
from tests import do_fixtures as dof
from tests.conftest import login, make_user
from tests.test_accounts_web import scenario
from tests.test_data_api import client_with
from tests.test_do_api import API, record, submitted, w  # noqa: F401  (fixtures: jobs never run, the DO world)
from tests.test_review_web import run_js

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")

SPEND = "Creating a DigitalOcean environment needs the providers:spend permission"
NO_ACCOUNT = "Add a DigitalOcean account in Settings › Integrations first"


# ------------------------------------------------------------------------------------ helpers


async def _cloudflare() -> None:
    async with get_sessionmaker()() as db:
        db.add(AppSetting(key=cloudflare.SETTING_KEY, value={"zone": "example.com", "public_ip": None,
                                                             "proxied": False}, secret="c" * 40))
        await db.commit()


async def _repo() -> uuid.UUID:
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=777, full_name="acme/shop", owner="acme", name="shop",
                          html_url="https://github.com/acme/shop", detected_config={"manifest": True})
        db.add(repo)
        await db.commit()
        return repo.id


async def _set(model: Any, row_id: Any, **values: Any) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(update(model).where(model.id == row_id).values(**values))
        await db.commit()


async def _build(env: dof.DoEnv, slot: str, *, size: str = "s-1vcpu-1gb", ip: str = "203.0.113.11") -> None:
    """The slot's droplet as prepare leaves it: ready, with its size and address."""
    async with get_sessionmaker()() as db:
        host = await db.get(Host, env.host_ids[slot])
        host_rules.set_phase(host, "ready", droplet_name=host.name, size=size, public_ip=ip, private_ip="10.10.0.2",
                             region="nyc3")
        host.hostname, host.host_key = ip, f"ssh-ed25519 AAAA{slot}"
        await db.commit()


async def _live(env: dof.DoEnv, slot: str = "blue", sha: str = dof.SHA) -> None:
    """The environment live, ``slot`` active with a release."""
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, env.ids[slot])
        inst.status, inst.current_commit_sha = "running", sha
        manifest = {"capabilities": ["backup", "restore", "bluegreen", "managed", "edge", "digitalocean"]}
        inst.app_state = {"live": {"sha": sha, "release": "r1"}, "manifest": manifest}
        owner = await db.get(Instance, env.ids["data"])  # the owner mirrors its runner's release (S14b)
        owner.app_state = {"live": {"sha": sha, "release": "r1", "runner": slot}, "manifest": manifest}
        await db.execute(update(Environment).where(Environment.id == env.env_id)
                         .values(status="live", active_slot_id=inst.id))
        await db.commit()


async def _job(env: dof.DoEnv, kind: str, *, slot: str | None = None, status: str = "failed", error: str | None = None,
               user: bool = True, **options: Any) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=env.ids[slot] if slot else None, environment_id=env.env_id, kind=kind,
                         status=status, branch="main", steps=[], options=options, error=error,
                         triggered_by_id=env.user_id if user else None, finished_at=datetime.now(UTC),
                         commit_sha=dof.SHA if slot else None)
        db.add(dep)
        await db.commit()
        return dep.id


def _between(page: str, start: str, end: str = "</section>") -> str:
    part = page[page.index(start):]
    return part[:part.index(end)]


def _dialog(page: str, dialog_id: str) -> str:
    return _between(page, f'id="{dialog_id}"', "</dialog>")


def _text(fragment: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", fragment))).strip()


# ------------------------------------------------------------------- 69: the flow, by role


async def test_69_the_flow_offers_digitalocean_with_an_account_and_providers_spend(make_client):
    await make_user("admin@example.com")
    for role in ("maintainer", "developer", "viewer"):
        await make_user(f"{role}@example.com", roles=[role])
    clients = {}
    for role in ("admin", "maintainer", "developer", "viewer"):
        clients[role] = make_client()
        await login(clients[role], f"{role}@example.com")
    writer = await client_with(make_client, "writer@example.com", ["environments:write", "environments:read",
                                                                   "repos:read", "hosts:read"])
    await _repo()
    await _cloudflare()
    async with get_sessionmaker()() as db:
        db.add(Host(name="lan-01", hostname="10.0.0.5", username="deploy"))
        await db.commit()

    # No account yet: DigitalOcean says what to do first.
    page = (await clients["maintainer"].get("/environments/new")).text
    assert NO_ACCOUNT in page
    assert re.search(r'name="where" value="digitalocean" data-no-send\s+disabled', page)
    assert "data-do-fields" not in page and 'name="production"' not in page

    account = await dof.make_account("do-main", region="sfo3")
    for role in ("maintainer", "admin"):
        page = (await clients[role].get("/environments/new")).text
        assert NO_ACCOUNT not in page and SPEND not in page
        assert not re.search(r'value="digitalocean" data-no-send\s+disabled', page)
        assert f'<option value="{account}" data-region="sfo3" data-label="do-main"' in page
        assert "Hosts</strong><small>(servers you added, or new VMs on Proxmox or ESXi)" in page
        for name in ("placement.region", "placement.droplet_size", "placement.db_size", "placement.db_standby",
                     "placement.acme_staging"):
            assert f'name="{name}"' in page, name
        assert "<strong>Through:</strong> DigitalOcean load balancer" in page
        assert 'name="confirm_cost" data-no-send data-flow-cost' in page
        assert 'name="production"' not in page  # no production account
    # Without providers:spend the choice stays off, with the reason; developers and viewers can't create at all.
    page = (await writer.get("/environments/new")).text
    assert SPEND in page and re.search(r'value="digitalocean" data-no-send\s+disabled', page)
    for role in ("developer", "viewer"):
        assert (await clients[role].get("/environments/new")).status_code == 403

    # A production account adds the Production box with its hint.
    prod = await dof.make_account("do-prod", production=True)
    page = (await clients["maintainer"].get("/environments/new")).text
    assert 'name="production" data-no-send' in page
    assert ("Production runs Blue and Green, waits for Activate, and is deleted only after it is retired and "
            "snapshotted.") in page
    assert f'<option value="{prod}" data-region="nyc3" data-label="do-prod" data-production' in page
    assert "do-prod (production)" in page
    # An account whose token can't be used is listed, but off.
    async with get_sessionmaker()() as db:
        await db.execute(update(ProviderAccount).where(ProviderAccount.id == prod).values(status="error"))
        await db.commit()
    page = (await clients["maintainer"].get("/environments/new")).text
    assert "do-prod (production): test it in Settings › Integrations first" in page


# ------------------------------------------------------------- 69: the environment page


async def test_69_cloud_card_slots_host_cells_header_chips_and_billing(make_client, w):  # noqa: F811
    env = await dof.make_do_env(name="shop", account_id=w.account_id)
    await record(env, "vpc", "vpc-1", do_rules.vpc_name("shop"))
    viewer = w.c["viewer"]
    page = (await viewer.get(f"/environments/{env.env_id}")).text
    # Header: the placement chip; not production, not retiring.
    assert '<span class="chip provider-chip" data-chip="placement">DigitalOcean · nyc3</span>' in page
    assert 'data-chip="production"' not in page and 'data-chip="retiring"' not in page
    assert "Blue/Green on managed data" in _between(page, '<p class="lede">', "</p>")
    # Billing (§12.4): a never-live environment with a DigitalOcean object.
    assert ("1 DigitalOcean object exists for shop and cost about $47.00 a month: retry the failed deploy, or "
            "delete the environment to remove them.") in _text(page)
    # The DigitalOcean card: what is recorded, and the objects read live through GET /cloud.
    card = _between(page, 'id="cloud-card"')
    text = _text(card)
    assert "Account and team do-main" in text and "team known after the first deploy" in text
    assert "Region nyc3" in text and "Load balancer IP Known after the first deploy" in text
    assert "Certificate Issued at the first deploy" in text
    assert "Estimate About $47.00 a month · prices as of " + do_rules.PRICES["as_of"] in text
    assert "s-1vcpu-1gb × 2" in text and "db-s-1vcpu-1gb × 1 node, PostgreSQL 16" in text
    assert f'data-load="/api/v1/environments/{env.env_id}/cloud" data-render="cloud_objects"' in card
    assert 'data-active-droplet=""' in card
    # A viewer gets no buttons on it.
    assert "Renew now" not in card and "Grow…" not in card
    assert "<div data-cloud-callouts></div>" in page
    # The Slots card: one host cell per slot, the provider and build chips, the managed data row.
    slots = _between(page, 'id="slots-card"')
    assert slots.count('<span class="chip provider-chip">DigitalOcean droplet</span>') == 2
    assert slots.count("Not built yet") == 2
    assert "Its managed database" in slots and "db-s-1vcpu-1gb × 1 node, PostgreSQL 16" in slots
    assert "Update the data server" not in slots
    # The Backups card speaks of this Slipway server.
    assert "Database dumps stored encrypted on this Slipway server." in page
    assert "DigitalOcean also keeps its own daily backups of the cluster; Slipway doesn&#39;t use them." in page
    # The Environments list marks it.
    listed = (await viewer.get("/environments")).text
    assert "data-billing" in listed and "1 DigitalOcean object already bill for shop" in listed

    # Built and live: the cell shows the droplet, its chips and the pending-size phrase of the active slot.
    await _build(env, "blue")
    await _build(env, "green", size="s-1vcpu-512mb", ip="203.0.113.12")
    await _live(env, "blue")
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        row.cloud = {**row.cloud, "droplet_size": "s-2vcpu-2gb", "lb_ip": "203.0.113.50",
                     "certificate": {"id": "c1", "name": "slipway-shop-1", "names": [],
                                     "not_after": (datetime.now(UTC) + timedelta(days=60)).isoformat()}}
        row.provider_team = "t1"
        acct = await db.get(ProviderAccount, w.account_id)
        acct.config = {**acct.config, "team": {"id": "t1", "name": "Acme"}}
        await db.commit()
    page = (await w.admin.get(f"/environments/{env.env_id}")).text
    slots = _between(page, 'id="slots-card"')
    assert "slipway-shop-blue · s-1vcpu-1gb · 203.0.113.11" in slots
    assert "slipway-shop-green · s-1vcpu-512mb · 203.0.113.12" in slots
    assert slots.count(">Ready</span>") == 2
    assert "Resize pending: applies at blue&#39;s next deploy when blue is idle" in slots
    assert "Resize pending: applies at green&#39;s next deploy</div>" in slots
    assert "Its data commands run on blue" in slots  # the owner's release is its runner's (P4 §10.4)
    # Remove green: its droplet goes, the estimate drops (no price recorded in this estimate: no sentence).
    remove = _dialog(page, "remove-slot")
    assert "'s droplet <span class=\"mono\" data-slot=\"host\"></span> from DigitalOcean" in remove
    assert "data in its managed database isn't touched" in remove and "data server" not in remove
    card = _text(_between(page, 'id="cloud-card"'))
    assert "Account and team do-main · Acme" in card and "Load balancer IP 203.0.113.50" in card
    assert "Valid until" in card and "Renews on its own 30 days before it runs out" in card
    assert "Billing" not in _text(_between(page, "<h1", 'id="cloud-card"'))
    assert 'data-active-droplet="slipway-shop-blue"' in page and 'data-active-slot="blue"' in page
    # The admin's buttons: Renew now (no load balancer yet: off with the reason), Grow.
    assert re.search(r'Renew now</button>', page) and "shop has no load balancer yet: deploy it first" in page
    assert 'data-open="grow-env"' in page
    # The deploy dialog says what the deploy does to the idle slot's droplet.
    deploy = _dialog(page, "deploy-env")
    assert ("The deploy grows green's droplet to <span class=\"mono\">s-2vcpu-2gb</span> after its backup: the "
            "droplet stops for a few minutes, and its disk grows and can't shrink again.") in deploy
    assert 'value="data"' not in deploy  # a managed environment has no data server to deploy
    # The host-less owner's Backups card and Back up now dialog name no host (gate 11).
    backups = _between(page, 'id="backups-card"')
    assert 'data-host="Slipway" data-stored-header="Stored"' in backups
    assert "Checks the files on Slipway" in backups and "On host" not in backups
    backup_now = _text(_dialog(page, "backup-now"))
    assert "database now, while the app keeps running" in backup_now and " on now" not in backup_now


async def test_69_each_callout_of_the_environment_page(w):  # noqa: F811
    env = await dof.make_do_env(name="shop", account_id=w.account_id)
    url = f"/environments/{env.env_id}"
    # SSH open to the internet: the account's sources hold 0.0.0.0/0.
    async with get_sessionmaker()() as db:
        acct = await db.get(ProviderAccount, w.account_id)
        acct.config = {**acct.config, "ssh_sources": ["0.0.0.0/0"]}
        await db.commit()
    page = (await w.admin.get(url)).text
    callout = _between(page, 'data-callout="open_ssh"', "</div></div>")
    assert "SSH to shop&#39;s droplets is open to the internet." in callout
    assert '<a href="/settings/integrations">Change do-main&#39;s SSH sources</a>' in callout
    # A viewer sees it too, without the link to a page it can't open.
    viewer = _between((await w.c["viewer"].get(url)).text, 'data-callout="open_ssh"', "</div></div>")
    assert "open to the internet" in viewer and "/settings/integrations" not in viewer

    # A pending create older than ten minutes; a fresh one isn't called out.
    old = (datetime.now(UTC) - timedelta(minutes=25)).isoformat()
    await record(env, "load_balancer", "pending:aaaaaaaaaaaaaaaa", do_rules.lb_name("shop"),
                 pending={"nonce": "a" * 16, "sent_at": old, "looked": []})
    await record(env, "firewall", "pending:bbbbbbbbbbbbbbbb", do_rules.firewall_name("shop"),
                 pending={"nonce": "b" * 16, "sent_at": datetime.now(UTC).isoformat(), "looked": []})
    page = (await w.admin.get(url)).text
    assert re.search(r"A load balancer create from [^<]+ hasn&#39;t shown up in DigitalOcean yet; the next deploy "
                     r"looks again\.", page)
    assert "A cloud firewall create" not in page

    # A host that holds an address DigitalOcean gave the droplet (§9.2 step 5).
    async with get_sessionmaker()() as db:
        lan = Host(name="lan-01", hostname="203.0.113.11", username="deploy")
        db.add(lan)
        await db.commit()
        lan_id = lan.id
    error = ("203.0.113.11 is still the address of host lan-01, which Slipway lists separately. DigitalOcean gave "
             "that address to slipway-shop-blue, so lan-01 no longer points at the machine it was added for: change "
             "or remove host lan-01, then retry")
    await _job(env, "deploy", slot="blue", error=error)
    page = (await w.admin.get(url)).text
    callout = _between(page, 'data-callout="address"', "</div></div>")
    assert html.escape(error, quote=True).replace("&#x27;", "&#39;") in callout
    assert f'<a href="/hosts/{lan_id}">Open host lan-01</a>' in callout

    # The active slot's droplet gone: nothing answers through the load balancer; Deploy to blue.
    await _live(env, "blue")
    page = (await w.admin.get(url)).text
    callout = _between(page, 'data-callout="gone-blue"', "</div></div>")
    assert ("blue&#39;s droplet is gone, so nothing answers through the load balancer: deploy to blue to build it "
            "again.") in callout
    assert f'data-api="POST /api/v1/environments/{env.env_id}/deploy" data-body=\'{{"slot": "blue"}}\'' in callout
    # ... "or activate green" when green has a live release that isn't stale.
    async with get_sessionmaker()() as db:
        green = await db.get(Instance, env.ids["green"])
        green.current_commit_sha, green.status = dof.SHA, "running"
        await db.commit()
    page = (await w.admin.get(url)).text
    assert "deploy to blue to build it again, or activate green." in page
    # Without deployments:create the callout stays, the button goes.
    assert 'data-callout="gone-blue"' in (await w.c["viewer"].get(url)).text
    assert "Deploy to blue</button>" not in _between((await w.c["viewer"].get(url)).text, 'data-callout="gone-blue"',
                                                     "</div></div>")

    # A certificate within 14 days of its end, and the last renewal failed.
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        row.cloud = {**row.cloud, "certificate": {"id": "c1", "name": "slipway-shop-1", "names": [],
                                                  "not_after": (datetime.now(UTC) + timedelta(days=9, hours=2)).isoformat()}}
        await db.commit()
    async with get_sessionmaker()() as db:  # the load balancer's create was answered after all
        await db.execute(update(Resource).where(Resource.environment_id == env.env_id,
                                                Resource.kind == "load_balancer").values(provider_id="lb-1", details={}))
        await db.commit()
    await _job(env, "certificate", error="Let's Encrypt refused the order: rate limited\nmore detail", user=False,
               by="renewals")
    page = (await w.admin.get(url)).text
    callout = _text(_between(page, 'data-callout="certificate"', "</div></div>"))
    assert re.search(r"> shop's certificate runs out \w+ \d+, \d{4} \(in 9 days\), and its last renewal failed: Let's "
                    r"Encrypt refused the order: rate limited\. Renew now$", callout), callout
    assert "Renews on its own; the last try failed just now: Let&#39;s Encrypt refused the order: rate limited" in page
    # With more than 14 days left, only the card's line says the renewal failed.
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        row.cloud = {**row.cloud, "certificate": {**row.cloud["certificate"],
                                                  "not_after": (datetime.now(UTC) + timedelta(days=40)).isoformat()}}
        await db.commit()
    page = (await w.admin.get(url)).text
    assert 'data-callout="certificate"' not in page and "the last try failed" in page

    # Off the air: a retiring production Deactivate recorded traffic_state.deactivated.
    async with get_sessionmaker()() as db:
        await db.execute(update(Environment).where(Environment.id == env.env_id).values(
            active_slot_id=None, traffic_state={"deactivated": {"deployment_id": "d", "from_slot": "blue",
                                                                "at": datetime.now(UTC).isoformat()}}))
        await db.commit()
    page = (await w.admin.get(url)).text
    assert ("shop was taken off the air just now: its names answer 503 from the load balancer until their DNS "
            "records are moved or removed.") in _text(page)
    assert 'data-callout="gone-blue"' not in page


async def test_69_js_cloud_card_renders_the_live_read_and_its_callouts(w, tmp_path):  # noqa: F811
    env = await dof.make_do_env(name="cl", account_id=w.account_id, status="live")
    tags = [do_rules.BASE_TAG, do_rules.env_tag(env.env_id)]
    blue = w.fake.add_droplet(name="slipway-cl-blue", tags=tags, status="off")
    await record(env, "droplet", str(blue["id"]), "slipway-cl-blue")
    await record(env, "droplet", "99999", "slipway-cl-green")
    await record(env, "bucket", "cl-bucket", "cl-bucket")
    await record(env, "vpc", "pending:0123456789abcdef", do_rules.vpc_name("cl"),
                 pending={"sent_at": datetime.now(UTC).isoformat()})
    answer = (await w.c["viewer"].get(f"{API}/{env.env_id}/cloud")).json()
    result = run_js(tmp_path, """
var data = %s;
var ds = { env: "e1", activeSlot: "green", activeDroplet: "slipway-cl-green", canDeploy: "" };
var table = window.slipway.cloudObjectsHtml(data, ds);
var callouts = window.slipway.cloudCallouts(data, ds);
var empty = window.slipway.cloudObjectsHtml({ objects: [], pending: [] }, {});
// Without deployments:create the gone droplet is called out without a button; an existing callout isn't repeated.
var bare = window.slipway.cloudCallouts(data, { env: "e1", activeSlot: "green", activeDroplet: "slipway-cl-green" });
document.body.appendChild(h("div", { "data-callout": "gone-green" }));
var again = window.slipway.cloudCallouts(data, ds);
done({ table: table, callouts: callouts, empty: empty, bare: bare, again: again });
""" % json.dumps(answer))
    table = result["table"]
    assert '<tr data-object="droplet"><td>Droplet</td><td class="mono">slipway-cl-blue' in table
    assert '<span class="badge success">OK</span> <span class="badge warning">Powered off</span>' in table
    assert re.search(r'slipway-cl-green</td><td><span class="badge error">Gone</span></td>', table)
    assert '<td>Bucket</td><td class="mono">cl-bucket<div class="subtle">Recorded; Slipway reads it at teardown' in table
    assert "Create not answered yet" in table and "<th>Monthly</th>" in table
    assert "Nothing on DigitalOcean yet: the first deploy makes it." in result["empty"]
    off, gone = result["callouts"]
    assert 'data-callout="off-slipway-cl-blue"' in off
    assert "slipway-cl-blue is powered off. The next deploy to its slot powers it on first." in off
    assert ("green's droplet is gone, so nothing answers through the load balancer: deploy to green to build it "
            "again.") in html.unescape(gone)
    assert 'data-api="POST /api/v1/environments/e1/deploy"' in gone and "Deploy to green</button>" in gone
    assert "data-api" not in result["bare"][1]
    assert len(result["again"]) == 1  # the page already says the droplet is gone


# --------------------------------------------------------------- 69: the production danger zone


async def test_69_production_danger_zone_states_and_their_dialogs(w):  # noqa: F811
    prod = await dof.make_account("do-prod", production=True)
    env = await dof.make_do_env(name="prod", account_id=prod, production=True)
    await _build(env, "blue")
    await _live(env, "blue")
    url = f"/environments/{env.env_id}"
    page = (await w.admin.get(url)).text
    assert 'data-chip="production">Production</span>' in page
    zone = _between(page, "<h2>Danger zone</h2>")
    assert "A production environment is retired first, then taken off the air, and deleted only after a snapshot." in zone
    assert 'data-open="retire-env"' in zone and "Un-retire" not in zone and "Take off the air" not in zone
    assert re.search(r'data-open="delete-env" disabled title="Retire prod first: a production environment is '
                     r'deleted only after it is retired"', zone)
    retire = _dialog(page, "retire-env")
    assert f'data-form="POST /api/v1/environments/{env.env_id}/retire"' in retire
    assert ("prod keeps serving. While it retires, no slot can be activated; when the new production is live, take "
            "prod off the air and delete it.") in _text(retire)
    assert 'name="confirm" data-must-equal="prod"' in retire
    # Someone without environments:delete has no danger zone buttons.
    viewer = (await w.c["viewer"].get(url)).text
    assert 'data-open="retire-env"' not in viewer and 'id="retire-env"' not in viewer

    # Retiring, still on the air: Un-retire and Take off the air; Delete waits.
    resp = await w.admin.post(f"{API}/{env.env_id}/retire", json={"confirm": "prod"})
    assert resp.status_code == 200, resp.text
    page = (await w.admin.get(url)).text
    zone = _between(page, "<h2>Danger zone</h2>")
    assert 'data-chip="retiring"' in page
    assert 'data-open="retire-env"' not in zone and 'data-open="unretire-env"' in zone
    assert 'data-open="deactivate-env"' in zone
    assert "Deactivate prod first: it still takes traffic" in zone
    unretire = _dialog(page, "unretire-env")
    assert f'data-form="DELETE /api/v1/environments/{env.env_id}/retire"' in unretire
    off = _dialog(page, "deactivate-env")
    assert f'data-form="POST /api/v1/environments/{env.env_id}/deactivate"' in off
    assert ("The load balancer stops sending traffic to blue. Its 4 names answer 503 until the DNS records are moved "
            "or removed.") in _text(off)
    assert 'name="confirm" data-must-equal="prod"' in off
    # A developer (traffic:switch, no environments:delete) gets none of these.
    dev = (await w.c["developer"].get(url)).text
    assert 'data-open="deactivate-env"' not in dev and 'data-open="unretire-env"' not in dev

    # Off the air: Delete is open, with the production phrase. The owner holds data (a ready backup) and no slot
    # can run its commands (blue's droplet isn't built any more): the second phrase, Deploy to blue first, and
    # drop_data.
    async with get_sessionmaker()() as db:
        await db.execute(update(Environment).where(Environment.id == env.env_id).values(active_slot_id=None))
        host = await db.get(Host, env.host_ids["blue"])
        host_rules.set_phase(host, "planned")
        db.add(Backup(instance_id=env.ids["data"], name="b1", reason="manual", status="missing", format="pg-custom", identity_fp="x" * 64, location="slipway",
                      taken_at=datetime.now(UTC)))
        await db.commit()
    page = (await w.admin.get(url)).text
    zone = _between(page, "<h2>Danger zone</h2>")
    assert re.search(r'data-open="delete-env"\s*>', zone)
    dialog = _dialog(page, "delete-env")
    assert 'data-snapshot-state="disabled"' in dialog
    assert "No slot can run the data commands: deploy to blue first." in _text(dialog)
    assert 'name="confirm_production" data-must-equal="delete production prod"' in dialog
    assert 'name="confirm_no_snapshot" data-must-equal="delete production prod without a snapshot"' in dialog
    assert "Deploy to blue first</button>" in dialog and 'data-body=\'{"slot": "blue"}\'' in dialog
    assert 'name="drop_data" required' in dialog
    assert ("The database cluster and the bucket are destroyed with prod. Without a snapshot the data is gone for "
            "good.") in _text(dialog)
    # The lists: every recorded object with its price, what stays.
    assert "Nothing on DigitalOcean yet" in dialog and "moved to <code>kept/</code>" in dialog
    # The API takes the dialog's body.
    body = {"confirm": "prod", "confirm_production": "delete production prod",
            "confirm_no_snapshot": "delete production prod without a snapshot", "drop_data": True}
    resp = await w.admin.request("DELETE", f"{API}/{env.env_id}", json=body)
    assert resp.status_code == 202, resp.text


async def test_69_delete_dialog_states_for_managed_data(w, make_client):  # noqa: F811
    env = await dof.make_do_env(name="shop", account_id=w.account_id)
    await record(env, "database", "db-1", do_rules.database_name("shop"))
    await record(env, "droplet", "11", "slipway-shop-blue")
    url = f"/environments/{env.env_id}"
    # Never held data: the box is unticked, with the note; no drop_data.
    dialog = _dialog((await w.admin.get(url)).text, "delete-env")
    assert 'data-snapshot-state="unticked"' in dialog and "shop never held data, so there is nothing to snapshot." in dialog
    assert 'name="drop_data"' not in dialog and "confirm_production" not in dialog
    goes = _text(_between(dialog, "data-delete-lists", "</ul>"))
    assert "The database cluster" in goes and "The droplet slipway-shop-blue" in goes
    # Holds data and a slot can run its commands: ticked; unticking shows the warning and the drop_data box.
    await _build(env, "blue")
    await _live(env, "blue")
    async with get_sessionmaker()() as db:
        db.add(Backup(instance_id=env.ids["data"], name="b1", reason="manual", status="missing", format="pg-custom", identity_fp="x" * 64, location="slipway",
                      taken_at=datetime.now(UTC)))
        await db.commit()
    dialog = _dialog((await w.admin.get(url)).text, "delete-env")
    assert 'data-snapshot-state="ticked"' in dialog, _text(dialog)
    assert re.search(r'name="snapshot_first" data-no-send checked>', dialog), _text(dialog)
    assert 'data-show-when="snapshot_first=" hidden data-drop-data' in dialog
    assert 'name="drop_data" required' in dialog
    # Without data:reset the box is there but off, saying why.
    deleter = await client_with(make_client, "deleter@example.com", [
        "environments:read", "environments:delete", "data:read", "data:backup", "instances:read"])
    dialog = _dialog((await deleter.get(url)).text, "delete-env")
    assert 'name="drop_data" disabled' in dialog and "(needs the data:reset permission)" in dialog


async def test_69_activate_grow_and_add_slot_dialogs(w, tmp_path):  # noqa: F811
    env = await dof.make_do_env(name="shop", account_id=w.account_id, slots=("blue",))
    page = (await w.admin.get(f"/environments/{env.env_id}")).text
    # Add a slot (§15.5): no host to choose, the cost priced when it opens.
    add = _dialog(page, "add-slot")
    assert "data-cost-confirm data-cost-auto" in add and 'name="host_id"' not in add
    assert 'name="confirm_cost" data-must-equal="" data-cost-input' in add and "Check the price" in add
    assert "Slipway makes its droplet (<span class=\"mono\">s-1vcpu-1gb</span>) at the slot's first deploy" in add
    # Grow (§15.7): the sizes from the catalog, the cost confirm, the sentence about the droplet stopping.
    grow = _dialog(page, "grow-env")
    assert f'data-load="/api/v1/provider-accounts/{w.account_id}/catalog?region=nyc3" data-render="grow_sizes"' in grow
    assert 'name="cloud.droplet_size"' in grow and 'name="cloud.db_size"' in grow and 'name="cloud.db_standby"' in grow
    assert ("The droplet stops for a few minutes when a deploy resizes it; its disk grows and can't shrink "
            "again. The database stays up while it resizes.") in grow
    assert 'data-old-cents="4700"' in grow

    # The JS: the catalog fills the selects, Check the price reads the dry run's total (?check=true, writing
    # nothing), which must then be typed.
    catalog = (await w.admin.get(f"/api/v1/provider-accounts/{w.account_id}/catalog?region=nyc3")).json()
    priced = await w.admin.patch(f"{API}/{env.env_id}?check=true", json={"cloud": {"droplet_size": "s-2vcpu-2gb"}})
    assert priced.status_code == 200 and priced.json()["ok"] is True, priced.text
    total = priced.json()["cost"]["total"]
    result = run_js(tmp_path, scenario(page, ["grow-env"], """
var dlg = document.getElementById("grow-env"), form = dlg.querySelector("form");
answers["GET /api/v1/provider-accounts/%(account)s/catalog?region=nyc3"] = [{ status: 200, body: %(catalog)s }];
answers["PATCH /api/v1/environments/%(env)s?check=true"] = [{ status: 200, body: %(priced)s }];
answers["PATCH /api/v1/environments/%(env)s"] = [{ status: 200, body: {} }];
var opener = h("button", { "data-open": "grow-env" }); document.body.appendChild(opener);
await click(opener);
var droplet = field(form, "cloud.droplet_size"), submitBtn = form.querySelector('[type="submit"]');
var out = { options: droplet.querySelectorAll("option").map(function (o) { return o.value; }), chosen: droplet.value,
            dbs: field(form, "cloud.db_size").querySelectorAll("option").map(function (o) { return o.value; }),
            boxHidden: form.querySelector("[data-cost-box]").hidden, before: submitBtn.disabled };
droplet.value = "s-2vcpu-2gb";
await click(form.querySelector("[data-cost-price]"));
out.priceBody = fetchBodies[fetchBodies.length - 1];
out.box = [form.querySelector("[data-cost-box]").hidden, form.querySelector("[data-cost-text]").textContent,
           form.querySelector("[data-cost-figure]").textContent, submitBtn.disabled];
var typed = field(form, "confirm_cost");
typed.value = "1.00"; user("input", typed); await settle();
out.wrong = submitBtn.disabled;
typed.value = "%(total)s"; user("input", typed); await settle();
out.right = submitBtn.disabled;
await submit(form);
out.sent = fetchBodies[fetchBodies.length - 1];
// Changing a size asks for the price again.
droplet.value = "s-1vcpu-1gb"; user("change", droplet); await settle();
out.reset = [form.querySelector("[data-cost-box]").hidden, submitBtn.disabled, typed.value];
out.calls = fetchCalls;
done(out);
""" % {"account": w.account_id, "catalog": json.dumps(catalog), "env": env.env_id, "priced": json.dumps(priced.json()),
       "total": total}))
    assert "s-1vcpu-1gb" in result["options"] and "s-2vcpu-2gb" in result["options"]
    assert result["chosen"] == "s-1vcpu-1gb" and "db-s-1vcpu-1gb" in result["dbs"]
    assert result["boxHidden"] is True and result["before"] is True
    assert result["priceBody"] == {"cloud": {"droplet_size": "s-2vcpu-2gb", "db_size": "db-s-1vcpu-1gb",
                                             "db_standby": False}}
    hidden, text, fig, disabled = result["box"]
    old = 4700
    delta = int(round(float(total) * 100)) - old
    assert hidden is False and fig == total and disabled is True
    assert text == f"The new estimate is about ${total} a month (+${do_rules.dollars(delta)} a month)."
    assert result["wrong"] is True and result["right"] is False
    assert result["sent"] == {"cloud": {"droplet_size": "s-2vcpu-2gb", "db_size": "db-s-1vcpu-1gb",
                                        "db_standby": False}, "confirm_cost": total}
    assert result["reset"] == [True, True, ""]
    # The API takes the body the dialog sent.
    resp = await w.admin.patch(f"{API}/{env.env_id}", json=result["sent"])
    assert resp.status_code == 200, resp.text
    assert resp.json()["cloud"]["sizes"]["droplet_size"] == "s-2vcpu-2gb"


async def test_69_activate_dialog_on_the_load_balancer_and_production(w):  # noqa: F811
    from slipway.core.permissions import Perm

    env = await dof.make_do_env(name="prod", production=True, account_id=w.account_id)
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        db.expunge(row)

    class Auth:
        def can(self, perm: str) -> bool:
            return True

    tpl = pages.templates.env.from_string(
        '{% from "_environment_dialogs.html" import activate_dialog with context %}'
        '{{ activate_dialog(env, "activate-slot", s, "blue", names, lb=True, production=True) }}'
        '{{ activate_dialog(env, "switch-back", s, None, names, back=True) }}')
    out = tpl.render(env=row, s={"slot": "green", "sha7": "0123456", "host": "slipway-prod-green"},
                     names=[{"hostname": "api.prod.example.com"}], auth=Auth(), Perm=Perm)
    first, second = out.split('id="switch-back"')
    assert ("Slipway checks green (<span class=\"mono\">0123456</span>) on slipway-prod-green, then points the load "
            "balancer at its droplet and checks 1 name through it.") in first
    assert "If a check fails, the load balancer goes back to blue." in first
    assert 'data-switch-label="Load balancer"' in first and "Reading the load balancer…" in first
    assert 'name="confirm" data-must-equal="prod"' in first
    assert 'name="confirm"' not in second and "in Switchyard" in second


# ---------------------------------------------------------------------------- the deployment page


async def test_69_deployment_page_renewal_retry_phrases_and_make_it_again(w):  # noqa: F811
    env = await dof.make_do_env(name="prod", production=True, status="live", account_id=w.account_id)
    cert = await _job(env, "certificate", status="succeeded", user=False, by="renewals")
    page = (await w.admin.get(f"/deployments/{cert}")).text
    assert "Slipway (certificate renewal)" in page and "Started by Slipway (certificate renewal)." in page
    # A person's renewal says who.
    mine = await _job(env, "certificate", status="succeeded")
    assert "certificate renewal" not in (await w.admin.get(f"/deployments/{mine}")).text

    # A production teardown's retry asks the phrases again, and drop_data when the delete used it.
    teardown = await _job(env, "teardown", confirmed=True, confirm_production="delete production prod",
                          no_snapshot=True, confirm_no_snapshot="delete production prod without a snapshot",
                          drop_data=True)
    await _set(Environment, env.env_id, status="deleting", retiring_at=datetime.now(UTC))
    page = (await w.admin.get(f"/deployments/{teardown}")).text
    assert "retry-env-job" in page, _text(_between(page, "<h1", "Output"))
    dialog = _dialog(page, "retry-env-job")
    assert 'name="confirm_production" data-must-equal="delete production prod"' in dialog
    assert 'name="confirm_no_snapshot" data-must-equal="delete production prod without a snapshot"' in dialog
    assert 'name="drop_data"' in dialog and 'name="confirm" data-must-equal="prod"' in dialog

    # A slot deploy that stopped at a gone cluster offers Make it again, empty (data:reset and the name).
    gone = await _job(env, "deploy", slot="blue", error=(
        "prod's database cluster is gone from DigitalOcean, and its data with it. Slipway won't make an empty one by "
        "itself: retry with \"Make it again, empty\" (the environment's name typed), then restore a backup"))
    await _set(Environment, env.env_id, status="live", retiring_at=None)
    page = (await w.admin.get(f"/deployments/{gone}")).text
    assert 'data-open="retry-rebuild"' in page
    dialog = _dialog(page, "retry-rebuild")
    assert f'data-form="POST /api/v1/deployments/{gone}/retry"' in dialog
    assert 'name="rebuild_data" value="true" data-type="json"' in dialog
    assert "Slipway makes prod's database cluster again, <strong>empty</strong>" in dialog
    assert 'name="confirm" data-must-equal="prod"' in dialog
    # A developer (no data:reset) isn't offered it.
    assert 'data-open="retry-rebuild"' not in (await w.c["developer"].get(f"/deployments/{gone}")).text


def test_js_new_kinds_have_their_running_labels(tmp_path):
    result = run_js(tmp_path, """
var s = window.slipway;
done({ kinds: ["certificate", "deactivate", "vm_snapshot", "vm_revert", "vm_drop"].map(function (k) {
  return s.statusBadge("running", k)[0]; }), done: s.statusBadge("succeeded", "certificate")[0] });
""")
    assert result["kinds"] == ["Renewing", "Taking off the air", "Taking VM snapshot", "Reverting",
                               "Deleting VM snapshot"]
    assert result["done"] == "Done"


def test_server_running_labels_match_the_js_for_the_new_kinds():
    """The first render (_macros.html RUNNING_LABELS) and the live badge (slipway.js RUNNING) agree."""
    from pathlib import Path

    import jinja2

    web = Path(pages.__file__).parent
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(web / "templates")))
    env.globals.update(icon=lambda *a, **k: "")
    macros = env.get_template("_macros.html").module
    for kind, label in {"certificate": "Renewing", "deactivate": "Taking off the air",
                        "vm_snapshot": "Taking VM snapshot", "vm_revert": "Reverting",
                        "vm_drop": "Deleting VM snapshot"}.items():
        assert f">{label}</span>" in str(macros.badge("deployment", "running", job=kind))
        js = (web / "static" / "js" / "slipway.js").read_text()
        assert f'{kind}: "{label}"' in js


# ----------------------------------------------------------- 69: the flow's JS (wireEnvFlow)


async def test_69_js_flow_digitalocean_body_catalog_cost_and_confirm(make_client, w, tmp_path):  # noqa: F811
    repo = await _repo()
    async with get_sessionmaker()() as db:
        db.add(Host(name="lan-01", hostname="10.0.0.5", username="deploy"))
        await db.commit()
    page = (await w.c["maintainer"].get("/environments/new")).text
    catalog = (await w.admin.get(f"/api/v1/provider-accounts/{w.account_id}/catalog?region=nyc3")).json()
    manifest = {"name": "shop", "settings": [], "services": [], "secrets": [], "first_admin": None,
                "capabilities": ["backup", "restore", "bluegreen", "managed", "edge", "digitalocean"],
                "edge": {"port": 8080, "health": "/healthz", "env": ["STACK_PROXY_IP"], "projects": []}}
    cost = {"lines": [{"object": "droplet", "label": "1 × droplet s-1vcpu-1gb (1 vCPU, 1 GB, 25 GB)", "cents": 600},
                      {"object": "database", "label": "Database cluster db-s-1vcpu-1gb × 1 node, PostgreSQL 16",
                       "cents": 1500}],
            "total_cents": 4700, "total": "47.00", "as_of": "2026-11-15", "note": do_rules.COST_NOTE.format(as_of="2026-11-15")}
    moved = dict(cost, total_cents=5300, total="53.00")
    plan = {"hostnames": [{"hostname": "api.shop.example.com", "follows": "active"}], "slots": {}}
    result = run_js(tmp_path, scenario(page, ["env-flow"], """
location.assign = function (u) { hrefs.push("ASSIGN " + u); };
var form = document.getElementById("env-flow");
var CHECK = "POST /api/v1/environments?check=true";
answers["GET /api/v1/repositories/%(repo)s/branches"] = [{ status: 200, body: ["main"] }];
answers["GET /api/v1/repositories/%(repo)s/manifest?branch=main&path=slipway.yml"] = [{ status: 200, body: { manifest: %(manifest)s } }];
answers["GET /api/v1/provider-accounts/%(account)s/catalog?region=nyc3"] = [{ status: 200, body: %(catalog)s }];
answers[CHECK] = [{ status: 200, body: { ok: true, plan: %(plan)s, cost: %(cost)s } }];
var branch = field(form, "branch");
branch.value = "main"; user("change", branch); await settle();
var where = form.querySelector('[name="where"][value="digitalocean"]');
var out = { doDisabled: where.disabled };
where.checked = true; form.querySelector('[name="where"][value="hosts"]').checked = false;
user("change", where); await settle();
var region = field(form, "placement.region"), droplet = field(form, "placement.droplet_size"), db = field(form, "placement.db_size");
out.catalog = [region.value, droplet.querySelectorAll("option").length > 1, db.querySelectorAll("option").map(function (o) { return o.value; })];
out.dataMode = field(form, "data_mode").value;
out.step3 = form.querySelector('[data-step-tab="3"] [data-step-label]').textContent;
field(form, "name").value = "shop";
var next = form.querySelector("[data-flow-next]"), deploy = form.querySelector("[data-flow-deploy]");
await click(next); await click(next);
// Step 3: its own checks first.
droplet.value = ""; await click(next);
out.noSize = [form._flow.current, form.querySelector('[data-step="3"] [data-step-error]').textContent];
droplet.value = "s-1vcpu-1gb"; db.value = "db-s-1vcpu-1gb";
await click(next); await click(next); await click(next); await click(next);
out.review = [form._flow.current, form.querySelector("[data-cost-figure]").textContent, deploy.disabled];
var typed = form.querySelector("[data-flow-cost]");
typed.value = "47"; user("input", typed); await settle();
out.wrong = deploy.disabled;
typed.value = "47.00"; user("input", typed); await settle();
out.right = deploy.disabled;
// The create says the estimate moved: the page prices it again, and the new total must be typed.
answers["POST /api/v1/environments"] = [{ status: 409, body: { detail: "The estimate changed to $53.00 a month (DigitalOcean's prices moved): check it again", field: "confirm_cost" } },
                                        { status: 201, body: { id: "e1", name: "shop" } }];
answers[CHECK] = [{ status: 200, body: { ok: true, plan: %(plan)s, cost: %(moved)s } }];
answers["POST /api/v1/environments/e1/deploy"] = [{ status: 202, body: { id: "d1" } }];
await click(deploy);
out.moved = [form._flow.current, form.querySelector('[data-step="7"] [data-step-error]').textContent,
             form.querySelector("[data-cost-figure]").textContent, typed.value, deploy.disabled];
typed.value = "53.00"; user("input", typed); await settle();
await click(deploy);
out.calls = fetchCalls; out.bodies = fetchBodies; out.hrefs = hrefs;
out.fieldStep = ["placement.account_id", "placement.droplet_size", "placement.slots", "production", "confirm_cost"].map(window.slipway.fieldStep);
done(out);
""" % {"repo": repo, "manifest": json.dumps(manifest), "account": w.account_id, "catalog": json.dumps(catalog),
       "plan": json.dumps(plan), "cost": json.dumps(cost), "moved": json.dumps(moved)}))
    assert result["doDisabled"] is False
    region, has_sizes, dbs = result["catalog"]
    assert region == "nyc3" and has_sizes and "db-s-1vcpu-1gb" in dbs
    assert result["dataMode"] == "managed" and result["step3"] == "DigitalOcean"
    assert result["noSize"] == [3, "Choose a droplet size"]
    assert result["review"] == [7, "47.00", True]
    assert result["wrong"] is True and result["right"] is False
    step, error, fig, typed, disabled = result["moved"]
    assert step == 7 and error.startswith("The estimate changed to $53.00 a month") and fig == "53.00"
    assert typed == "" and disabled is True
    creates = [b for c, b in zip(result["calls"], result["bodies"]) if c == "POST /api/v1/environments"]
    checks = [b for c, b in zip(result["calls"], result["bodies"]) if c == "POST /api/v1/environments?check=true"]
    assert [b.get("confirm_cost") for b in creates] == ["47.00", "53.00"]
    assert all("confirm_cost" not in b for b in checks)
    body = creates[-1]
    assert body["placement"] == {"provider": "digitalocean", "account_id": str(w.account_id), "region": "nyc3",
                                 "droplet_size": "s-1vcpu-1gb", "db_size": "db-s-1vcpu-1gb", "db_standby": False,
                                 "acme_staging": False, "slots": 1}
    assert body["data_mode"] == "managed" and body["hosts"] == {} and body["production"] is False
    assert body["traffic"] == {"switch": "do_lb", "dns": {"proxied": False}} and "route_tls" not in body
    assert result["hrefs"][-1] == "ASSIGN /environments/e1"
    assert result["fieldStep"] == [3, 3, 2, 2, 7]
    # The API takes the body the flow sends (checked, not created: the figure is the fake's estimate's).
    checked = await w.admin.post(f"{API}?check=true", json={**body, "confirm_cost": None, "repository_id": str(repo)})
    assert checked.status_code in (200, 409, 422), checked.text
    assert checked.json().get("field") not in ("placement", "placement.provider", "traffic.switch", "data_mode")


def test_69_js_flow_production_forces_blue_green_and_a_production_account(tmp_path):
    result = run_js(tmp_path, """
var acct = h("select", { name: "placement.account_id", "data-do-account": "" }, [
  h("option", { value: "a1", "data-region": "nyc3", "data-label": "do-main" }, ["do-main"]),
  h("option", { value: "a2", "data-region": "nyc3", "data-label": "do-prod", "data-production": "" }, ["do-prod"])]);
var sections = [1, 2, 3, 4, 5, 6, 7].map(function (n) {
  return h("section", { "data-step": String(n), "data-step-name": "Step" + n }, [h("div", { "data-step-error": "", hidden: "" })]);
});
sections[1].appendChild(h("input", { type: "radio", name: "where", value: "hosts", "data-no-send": "" }));
sections[1].appendChild(h("input", { type: "radio", name: "where", value: "digitalocean", checked: "", "data-no-send": "" }));
sections[1].appendChild(h("input", { type: "checkbox", name: "production", "data-no-send": "" }));
sections[1].appendChild(h("input", { type: "radio", name: "shape", value: "single", checked: "", "data-no-send": "" }));
sections[1].appendChild(h("input", { type: "radio", name: "shape", value: "bluegreen", "data-no-send": "" }));
sections[2].appendChild(acct);
sections[2].appendChild(h("label", { "data-do-staging": "" }, [h("input", { type: "checkbox", name: "placement.acme_staging", checked: "" })]));
sections[4].appendChild(h("input", { type: "checkbox", name: "auto_activate", checked: "" }));
var form = h("form", { "data-env-flow": "" }, sections.concat([
  h("input", { type: "hidden", name: "data_mode", value: "slot", "data-no-send": "" }),
  h("button", { type: "button", "data-flow-next": "" }), h("button", { type: "button", "data-flow-deploy": "", hidden: "" })]));
document.body.appendChild(form);
document.dispatchEvent(new Event("DOMContentLoaded"));
var prod = form.querySelector('[name="production"]');
var before = { a1: acct.querySelectorAll("option")[0].disabled, a2: acct.querySelectorAll("option")[1].disabled, value: acct.value };
prod.checked = true; user("change", prod); await settle();
var body = window.slipway.flowBody(form, false, null);
done({ before: before, after: { a1: acct.querySelectorAll("option")[0].disabled, a2: acct.querySelectorAll("option")[1].disabled,
       value: acct.value }, single: form.querySelector('[value="single"]').disabled,
       bluegreen: form.querySelector('[value="bluegreen"]').checked, staging: form.querySelector("[data-do-staging]").hidden,
       auto: [form.querySelector('[name="auto_activate"]').disabled, form.querySelector('[name="auto_activate"]').checked],
       body: { production: body.production, slots: body.placement.slots, staging: body.placement.acme_staging,
               auto: body.auto_activate, account: body.placement.account_id } });
""")
    assert result["before"] == {"a1": False, "a2": True, "value": "a1"}
    assert result["after"] == {"a1": True, "a2": False, "value": "a2"}
    assert result["single"] is True and result["bluegreen"] is True and result["staging"] is True
    assert result["auto"] == [True, False]
    assert result["body"] == {"production": True, "slots": 2, "staging": False, "auto": False, "account": "a2"}


def test_a_backup_kept_on_slipway_shows_as_on_slipway():
    row = {"id": uuid.uuid4(), "name": "b1", "reason": "manual", "status": "ready", "has_files": False,
           "db_bytes": 1024, "taken_at": "2026-11-16T09:00:00+00:00", "checked_at": "2026-11-16T09:05:00+00:00",
           "needs_reset_perm": False, "location": "slipway"}
    shown = pages.backup_present(row, labels={"files": "Files", "identity": "identity keys"}, job_shas={},
                                 can_reset=True, busy=False, revision_check=False)
    assert shown["on_host"] == ("On Slipway", "success")
    assert pages.backup_present({**row, "location": "host"}, labels={"files": "Files", "identity": "identity keys"},
                                job_shas={}, can_reset=True, busy=False, revision_check=False)["on_host"] == \
        ("On host", "success")


def test_js_backups_card_of_the_hostless_owner_names_no_host(tmp_path):
    """Gate 11: the live renderer heads the column 'Stored' for the host-less owner and names Slipway, not a host."""
    import html as html_lib

    from tests.test_final_ui import BACKUPS_JSON, _backups_html

    rows = [{**b, "location": "slipway"} for b in BACKUPS_JSON["backups"][:1]]
    out = html_lib.unescape(_backups_html(tmp_path, {**BACKUPS_JSON, "backups": rows},
                                          ', "data-stored-header": "Stored", "data-can-reset": ""'))
    assert "<th>Stored</th>" in out and "<th>On host</th>" not in out and ">On Slipway<" in out
    phase3 = html_lib.unescape(_backups_html(tmp_path, BACKUPS_JSON))
    assert "<th>On host</th>" in phase3
