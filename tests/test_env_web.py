"""The environment pages and slipway.js (phase 3 §12; tests 60 and 61 of §16.2).

Test 60 renders every new page and dialog on a seeded environment (``tests.test_env_rules._world``: ``uat`` in mode
server with blue, green and a data server): the nav entry, the list, the environment page's cards, callouts and
dialogs, the pages that show jobs with no instance, the member banner, the Integrations Cloudflare card and the
New environment and settings pages. Test 61 runs the real slipway.js under the fake DOM of tests/test_review_web.py:
the flow's step checks, its FIELD_STEP jumps and its two-call deploy, and ``renderers.traffic_plan``.

Jobs are queued and never run; Switchyard, Cloudflare and GitHub are the fakes (nothing leaves the machine).
"""

from __future__ import annotations

import html
import json
import re
import uuid
from datetime import timedelta
from html.parser import HTMLParser

from sqlalchemy import update

from slipway.db.session import get_sessionmaker
from slipway.models import AppSetting, Deployment, Environment, Instance, Repository
from slipway.services import cloudflare
from tests.fake_cloudflare import TOKEN, ZONE
from tests.test_data_api import client_with, clients
from tests.test_env_api import (  # noqa: F401  (autouse fixtures: jobs never run, fakes for every service)
    HOSTNAMES,
    _backup,
    cf,
    github,
    no_public_checks,
    storage,
    submitted,
    sy,
)
from tests.test_env_rules import SHA, T0, _failed_green, _world
from tests.test_review_web import run_js

# ---------------------------------------------------------------------------------------- helpers


class _Attrs(HTMLParser):
    """Every start tag's attributes, in order, and the id of the <dialog> each one sits in."""

    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None], str | None]] = []
        self.dialog: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "dialog":
            self.dialog = a.get("id")
        self.tags.append((tag, a, self.dialog))

    def handle_endtag(self, tag: str) -> None:
        if tag == "dialog":
            self.dialog = None


def _tags(page: str) -> list[tuple[str, dict[str, str | None], str | None]]:
    parser = _Attrs()
    parser.feed(page)
    return parser.tags


def _must_equal(page: str) -> dict[str, str | None]:
    """``{dialog id: data-must-equal}`` of every typed-name field."""
    return {dlg: a.get("data-must-equal") for _, a, dlg in _tags(page) if "data-must-equal" in a and dlg}


def _text(page: str) -> str:
    """The page's text: tags dropped (inline ones such as <span class="mono"> leave no space), spaces collapsed."""
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", page)))


async def _set(model, row_id, **values) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(update(model).where(model.id == row_id).values(**values))
        await db.commit()


async def _env_job(env_id, kind="activate", status="succeeded", **options) -> uuid.UUID:
    """A job of the whole environment: no instance (D9)."""
    dep_id = uuid.uuid4()
    async with get_sessionmaker()() as db:
        db.add(Deployment(id=dep_id, instance_id=None, environment_id=env_id, kind=kind, status=status, branch="main",
                          commit_sha=SHA, created_at=T0 + timedelta(hours=2), finished_at=T0 + timedelta(hours=2),
                          options=options, steps=[{"key": "check", "name": "Check", "status": "succeeded"}]))
        await db.commit()
    return dep_id


async def _cloudflare_row() -> None:
    async with get_sessionmaker()() as db:
        db.add(AppSetting(key=cloudflare.SETTING_KEY, value={"zone": ZONE, "zone_id": "z1", "public_ip": "203.0.113.10",
                                                             "proxied": False}, secret=TOKEN))
        await db.commit()


# ------------------------------------------------------------------------- 60: pages and dialogs


async def test_nav_entry_and_the_list_need_environments_read(make_client):
    c = await clients(make_client)
    ids = await _world()
    nobody = await client_with(make_client, "nobody@example.com", ["instances:read"])

    page = (await c["viewer"].get("/")).text
    assert 'href="/environments"' in page and "#environments" in page  # the nav entry and its icon
    assert 'href="/environments"' not in (await nobody.get("/")).text
    assert (await nobody.get("/environments")).status_code == 403
    assert (await nobody.get(f"/environments/{ids['env']}")).status_code == 403

    page = (await c["viewer"].get("/environments")).text
    text = _text(page)
    assert "An environment is one app from one branch, in one or two slots. Deploys go to the idle slot; Activate " \
           "moves the traffic." in text
    assert f'href="/environments/{ids["env"]}"' in page and "acme/serversherpa" in text
    assert "Blue · Live" in text and "Green · Idle" in text and "On h-data" in text
    # Only environments:write offers New environment.
    assert 'href="/environments/new"' not in page
    assert 'href="/environments/new"' in (await c["maintainer"].get("/environments")).text
    assert (await c["viewer"].get("/environments/new")).status_code == 403

    # Deleted environments are behind Show deleted; the empty state says what an environment needs.
    await _set(Environment, ids["env"], status="deleted", deleted_at=T0)
    page = (await c["viewer"].get("/environments")).text
    assert "No environments yet A repository whose slipway.yml declares its data can run as one." in _text(page)
    assert 'href="/environments?show=deleted"' in page
    assert f'href="/environments/{ids["env"]}"' in (await c["viewer"].get("/environments?show=deleted")).text


async def test_jobs_with_no_instance_render_on_the_overview_lists_and_their_page(admin_client):
    ids = await _world()
    switch = {"backend": "switchyard", "from_slot": "blue", "to_slot": "green", "applied": True,
              "created": [], "changed": [{"hostname": "api.uat.example.com", "id": 1},
                                         {"hostname": "portal.uat.example.com", "id": 2}], "deleted": []}
    job = await _env_job(ids["env"], "activate", slot="green", switch=switch)

    # The home page, the Deployments list (with its Environment column and ?environment= filter).
    home = _text((await admin_client.get("/")).text)
    assert "uatActivate green: done" in home  # the timeline title is the environment, then the job
    page = (await admin_client.get("/deployments")).text
    assert "<th>Environment</th>" in page and "Activate green" in _text(page)
    only = (await admin_client.get(f"/deployments?environment={ids['env']}")).text
    assert "Deployments of uat" in _text(only) and f"/deployments/{job}" in only

    # The job's page: the environment in the breadcrumb and the What card, and the switch summary.
    page = (await admin_client.get(f"/deployments/{job}")).text
    text = _text(page)
    assert f'href="/environments/{ids["env"]}"' in page
    assert "Activate green · uat" in text and "Moved 2 names from blue to green." in text
    assert "Open environment" in text

    # A failed teardown offers its retry with the environment's name typed (and forget_traffic after unroute).
    failed = uuid.uuid4()
    async with get_sessionmaker()() as db:
        db.add(Deployment(id=failed, instance_id=None, environment_id=ids["env"], kind="teardown", status="failed",
                          branch="main", created_at=T0 + timedelta(hours=3), finished_at=T0 + timedelta(hours=3),
                          options={"confirmed": True},
                          steps=[{"key": "check", "name": "Check", "status": "succeeded"},
                                 {"key": "unroute", "name": "Remove the Switchyard hosts", "status": "failed"}]))
        await db.commit()
    await _set(Environment, ids["env"], status="deleting")
    page = (await admin_client.get(f"/deployments/{failed}")).text
    assert "Delete environment · uat" in _text(page)
    assert _must_equal(page).get("retry-env-job") == "uat"
    assert 'name="forget_traffic"' in page


async def test_environment_page_cards_callouts_and_disabled_reasons(make_client):
    c = await clients(make_client)
    ids = await _world(hostnames=HOSTNAMES)
    await _env_job(ids["env"], "publish")
    page = (await c["admin"].get(f"/environments/{ids['env']}")).text
    text = _text(page)
    # Header and the four cards with their content.
    assert "acme/serversherpa · main · Blue/Green with a data server" in text
    assert 'id="slots-card"' in page and 'id="traffic-card"' in page and 'id="backups-card"' in page
    assert 'id="data-card"' in page and "Publish names" in text
    assert f'data-load="/api/v1/environments/{ids["env"]}/traffic/plan"' in page and 'data-render="traffic_plan"' in page
    assert "Database dumps in" in text and "on h-data. Slipway takes one before every deploy to a slot" in text
    # The Data card names the ports and the clients, and says the ports are open to the LAN.
    assert "spaces on 10.0.0.13:9000" in text and "db on 10.0.0.13:5432" in text
    assert "These ports are reachable from every machine on the LAN; Postgres lets in only 10.0.0.11, 10.0.0.12, " \
           "and the file store needs its key. docs/environments.md shows how to firewall them." in text
    assert "Update the data server…" in text and "Activate green…" in text
    # The Deployments card labels each job.
    assert "Publish names" in text and "Deploy to green" in text

    # A viewer sees the page but no buttons that change anything.
    viewer = (await c["viewer"].get(f"/environments/{ids['env']}")).text
    assert "Deploy…" not in viewer and "Activate green…" not in viewer and 'id="delete-env"' not in viewer

    # Disabled reasons: green is mid-deploy, so Deploy and Activate say why in their title.
    async with get_sessionmaker()() as db:
        db.add(Deployment(instance_id=ids["green"], environment_id=ids["env"], kind="deploy", status="running",
                          branch="main", created_at=T0 + timedelta(hours=4), options={"slot": "green"}))
        await db.commit()
    page = (await c["admin"].get(f"/environments/{ids['env']}")).text
    deploy = next(a for t, a, _ in _tags(page) if t == "button" and a.get("data-open") == "deploy-env")
    assert "disabled" in deploy and "A job is already running for uat (Deploy on green)" in (deploy.get("title") or "")
    assert 'data-poll-reload="5000"' in page


async def test_callouts_unresolved_notice_stale_and_settings(admin_client):
    ids = await _world(hostnames=HOSTNAMES)
    await _set(Environment, ids["env"],
               traffic_state={"unresolved": {"deployment_id": "ab" * 16, "message": "Switchyard didn't answer"}},
               notice={"text": "uat's chain stopped after Slipway restarted: Activate green to continue",
                       "next": {"kind": "activate", "slot": "green"}, "deployment_id": "cd" * 16})
    await _set(Instance, ids["green"], slot_state={"stale": {
        "reason": "Stopped when uat's data was restored; deploy to it before activating it"}})
    live = (await _get_instance(ids["blue"])).app_state
    live["live"] = {**live["live"], "settings": {"STACK_DOMAIN": "old.example.com"}}
    await _set(Instance, ids["blue"], app_state=live)
    page = (await admin_client.get(f"/environments/{ids['env']}")).text
    text = _text(page)
    assert "Traffic of uat may be split between its slots since deployment abababab (Switchyard didn't answer)." in text
    assert 'data-open="resolve-traffic"' in page and _must_equal(page).get("resolve-traffic") == "uat"
    # The chain notice and its button through notice/continue.
    assert "uat's chain stopped after Slipway restarted" in text
    notice = next(a for t, a, _ in _tags(page) if a.get("data-api", "").endswith("/notice/continue"))
    assert notice is not None and "Activate green" in text
    # The stale slot and the settings that differ from a live slot's.
    assert "green was stopped when uat's data was restored; deploy to it before activating it." in text
    assert "blue keeps the settings it was deployed with until you deploy to it." in text  # §6
    # The order of §12.2: unresolved, the owner's state, the notice, a stale slot, settings.
    assert text.index("may be split") < text.index("chain stopped") < text.index("green was stopped") \
        < text.index("keeps the settings")


async def _get_instance(instance_id):
    async with get_sessionmaker()() as db:
        return await db.get(Instance, instance_id)


async def test_discard_first_and_roll_back_second_after_a_failed_idle_deploy(admin_client):
    ids = await _world(hostnames=HOSTNAMES)
    async with get_sessionmaker()() as db:
        dep = await _failed_green(db, ids)
    page = (await admin_client.get(f"/environments/{ids['env']}")).text
    text = _text(page)
    assert "uat's data was changed by failed deployment" in text
    buttons = [a for t, a, _ in _tags(page) if t == "button" and a.get("data-action") in ("discard", "rollback")]
    assert [b["data-action"] for b in buttons] == ["discard", "rollback"]  # Discard is the first action
    assert "btn-primary" in buttons[0]["class"] and "btn-danger" in buttons[1]["class"]
    # Discard names no data to lose and asks for no typed name; Roll back does both.
    assert "Stops green and leaves uat's data as it is: blue (0123456) keeps serving it. Slipway checks blue first; " \
           "deploy to green again when it's fixed." in text
    names = _must_equal(page)
    assert "discard-slot" not in names and names["roll-back-env"] == "uat"
    assert "Writes made through blue since" in text and "are lost." in text
    assert f'data-form="POST /api/v1/deployments/{dep.id}/rollback"' in page


async def test_deploy_dialog_has_the_lag_checkbox_when_the_active_slot_is_behind(admin_client):
    ids = await _world(hostnames=HOSTNAMES)
    page = (await admin_client.get(f"/environments/{ids['env']}")).text
    assert 'name="acknowledge_schema"' not in page
    text = _text(page)
    assert "Deploys main to green on h-green. Traffic stays on blue until you activate green." in text
    assert "Blue keeps serving while green migrates the database." in text
    # After a switch back (no deploy to the idle slot since), the checkbox shows, unticked.
    await _set(Environment, ids["env"], traffic_state={"last": {"slot": "blue", "from_slot": "green", "back": True,
                                                                "at": (T0 + timedelta(hours=1)).isoformat()}})
    page = (await admin_client.get(f"/environments/{ids['env']}")).text
    box = next(a for t, a, _ in _tags(page) if a.get("name") == "acknowledge_schema")
    assert "checked" not in box
    assert "This release removes nothing blue (0123456) uses" in _text(page)


async def test_a_deploy_the_lag_check_refused_offers_deploy_again_confirming(admin_client):
    """§7.6: a refused deploy's error offers Deploy again, confirming (``acknowledge_schema``)."""
    ids = await _world(hostnames=HOSTNAMES)
    lag = ("blue (0123456) already runs on a database migrated past it (revision 0042, by green's 89abcde). A new "
           "release may remove what blue still uses. Activate green again and deploy to blue, or deploy again "
           "confirming that this release removes nothing blue uses.")
    refused, other = uuid.uuid4(), uuid.uuid4()
    async with get_sessionmaker()() as db:
        for dep_id, error, at in ((refused, lag, T0 + timedelta(hours=1)), (other, "The build failed", T0 + timedelta(minutes=30))):
            db.add(Deployment(id=dep_id, instance_id=ids["green"], environment_id=ids["env"], kind="deploy",
                              status="failed", branch="main", commit_sha=SHA, error=error, options={"slot": "green"},
                              created_at=at, finished_at=at,
                              steps=[{"key": "backup", "name": "Back up the data", "status": "failed"}]))
        await db.commit()
    page = (await admin_client.get(f"/deployments/{refused}")).text
    # The button opens a dialog that asks for the acknowledgement again, unticked (tests/test_fix3_web.py, F50).
    assert any(t == "button" and a.get("data-open") == "deploy-again" for t, a, _ in _tags(page))
    form = next(a for t, a, dlg in _tags(page) if t == "form" and dlg == "deploy-again")
    assert form["data-form"] == f"POST /api/v1/environments/{ids['env']}/deploy"
    box = next(a for t, a, dlg in _tags(page) if dlg == "deploy-again" and a.get("name") == "acknowledge_schema")
    assert "checked" not in box
    assert "Deploy again, confirming" in _text(page)
    assert "Deploy again, confirming" not in _text((await admin_client.get(f"/deployments/{other}")).text)


async def test_dialogs_type_the_environments_name_also_in_phase_2_dialogs(admin_client):
    ids = await _world(hostnames=HOSTNAMES)
    await _backup(ids["data"])
    page = (await admin_client.get(f"/environments/{ids['env']}")).text
    names = _must_equal(page)
    # The environment's dialogs, and phase 2's restore and reset dialogs on the data owner, all ask for "uat".
    for dialog in ("remove-slot", "delete-env", "restore-backup", "reset-data"):
        assert names.get(dialog) == "uat", dialog
    assert 'data-form="POST /api/v1/instances/' + str(ids["data"]) + '/data/restore"' in page
    # No typed name for Activate (it is reversible) or Deploy.
    assert "activate-slot" not in names and "deploy-env" not in names
    text = _text(page)
    assert "Blue and Green are stopped while it runs." in text
    assert "Slipway checks green (0123456) on h-green, then points 1 name in Switchyard at it and checks them " \
           "through Switchyard. If a check fails, every name goes back to blue. Blue keeps running: activate it " \
           "again to switch back." in text
    # The plan is read when the Activate dialog opens, and its button waits for it.
    lazy = next(a for t, a, dlg in _tags(page) if dlg == "activate-slot" and "data-lazy" in a)
    assert lazy["data-load"].endswith("/traffic/plan?slot=green")
    submit = next(a for t, a, dlg in _tags(page) if dlg == "activate-slot" and "data-plan-submit" in a)
    assert "disabled" in submit
    # Remove a slot: filled per slot; Delete lists what goes and stays, with a snapshot first.
    removes = {json.loads(a["data-fill"])["slot"]: a for t, a, _ in _tags(page) if a.get("data-open") == "remove-slot"}
    assert "disabled" in removes["blue"] and "takes the traffic" in removes["blue"]["title"]
    assert json.loads(removes["green"]["data-fill"])["action"] == f"DELETE /api/v1/environments/{ids['env']}/slots/green"
    assert "The data volumes and backups on h-data" in text and 'name="snapshot.name"' in page
    assert "This can't be undone." in text

    # The data owner's instance page is the member page: its data dialogs are on the environment page.
    owner_page = (await admin_client.get(f"/instances/{ids['data']}")).text
    assert "restore-backup" not in owner_page


async def test_member_banner_on_the_instance_page(make_client):
    c = await clients(make_client)
    ids = await _world(hostnames=HOSTNAMES)
    page = (await c["admin"].get(f"/instances/{ids['green']}")).text
    text = _text(page)
    assert "This is the green slot of environment uat (idle). Its settings, secrets, data and names belong to the " \
           "environment." in text
    assert f'href="/environments/{ids["env"]}"' in page
    # Hidden: settings, variables, hostnames, backups, Deploy, Configure and the danger zone; containers stay.
    for gone in ("App settings", "Hostnames", "backups-card", "Danger zone", f"/instances/{ids['green']}/deploy",
                 f"/instances/{ids['green']}/edit"):
        assert gone not in page, gone
    assert "Containers" in text and f"/instances/{ids['green']}/actions/stop" in page
    live = _text((await c["admin"].get(f"/instances/{ids['blue']}")).text)
    assert "This is the blue slot of environment uat (live)." in live
    data = _text((await c["admin"].get(f"/instances/{ids['data']}")).text)
    assert "This is the data server of environment uat." in data
    # The Instances list marks members and sends their deploys to the environment.
    listing = (await c["admin"].get("/instances")).text
    assert "uat · green" in _text(listing) and f"/instances/{ids['green']}/deploy" not in listing
    # The host lists the environments with a slot on it.
    host = _text((await c["admin"].get(f"/hosts/{ids['host_green']}")).text)
    assert "Environments on this host" in host and "Green · Idle" in host


async def test_integrations_cloudflare_card_and_traffic_address(admin_client):
    page = (await admin_client.get("/settings/integrations")).text
    text = _text(page)
    assert page.count('id="cloudflare-card"') == 1 and "<title>Integrations · Slipway</title>" in page
    assert "Not set up" in text
    assert "The WAN address published records point at." in text
    assert 'data-form="PUT /api/v1/settings/cloudflare"' in page and 'name="token"' in page
    assert 'name="traffic_address"' in page and "Traffic address" in text
    await _cloudflare_row()
    page = (await admin_client.get("/settings/integrations")).text
    text = _text(page)
    assert "Connected" in text and f"Set (…{TOKEN[-4:]})" in text and TOKEN not in page
    assert 'data-api="POST /api/v1/settings/cloudflare/test"' in page
    remove = next(a for t, a, _ in _tags(page) if t == "button" and a.get("data-body") == '{"clear": true}'
                  and "cloudflare" in (a.get("data-api") or ""))
    assert "Remove the Cloudflare integration?" in remove["data-confirm"]


async def test_the_flow_page_renders_its_steps_and_manifest_driven_fields(make_client):
    c = await clients(make_client)
    ids = await _world(hostnames=HOSTNAMES)
    await _set(Repository, ids["repo"], detected_config={"manifest": True})
    page = (await c["maintainer"].get("/environments/new")).text
    text = _text(page)
    tags = _tags(page)
    steps = [a["data-step"] for t, a, _ in tags if "data-step" in a]
    assert steps == ["1", "2", "3", "4", "5", "6", "7"]
    form = next(a for t, a, _ in tags if t == "form" and "data-env-flow" in a)
    # wireAppForm reads the branch's slipway.yml into steps 4 and 6, as on the instance form.
    assert "data-app-form" in form and form["data-settings-field"] == "settings"
    assert any("data-app-settings" in a for _, a, _ in tags) and any("data-app-data" in a for _, a, _ in tags)
    assert any(a.get("name") == "first_admin" or "data-app-admin" in a for _, a, _ in tags)
    assert "Up to 26 characters: the slots are" in text and "Start over" in text
    # Hosts: every pinned host, the unpinned ones disabled with the reason.
    blue = [a for t, a, _ in tags if t == "option" and a.get("data-label", "").startswith("h-blue")]
    assert blue and "disabled" not in blue[0]
    # Blue/Green starts disabled until the manifest says bluegreen.
    shape = next(a for t, a, _ in tags if a.get("name") == "shape" and a.get("value") == "bluegreen")
    assert "disabled" in shape
    assert "Deploy creates the environment and starts its first deployment, then opens it." in text
    assert "Secrets: generated by Slipway and never shown." in text

    # The settings page: steps 4-6 for PATCH, read-only without environments:write.
    page = (await c["maintainer"].get(f"/environments/{ids['env']}/edit")).text
    assert f'data-form="PATCH /api/v1/environments/{ids["env"]}"' in page
    assert "Saved. The next deploy to each slot uses these settings." in page
    assert 'data-map="route_tls"' in page and "api.uat.example.com" in page
    viewer = (await c["viewer"].get(f"/environments/{ids['env']}/edit")).text
    assert "Read only" in _text(viewer) and 'type="submit"' not in viewer.split('data-form="PATCH')[1].split("</form>")[0]


# ------------------------------------------------------------------------------- 61: slipway.js

FLOW_DOM = """
location.assign = function (u) { hrefs.push("ASSIGN " + u); };
var sections = [1, 2, 3, 4, 5, 6, 7].map(function (n) {
  return h("section", { "data-step": String(n), "data-step-name": "Step" + n }, [h("div", { "data-step-error": "", hidden: "" })]);
});
sections[0].appendChild(h("input", { name: "name", value: "" }));
var repo = h("select", { name: "repository_id" }, [h("option", { value: "r1", selected: "" }, ["acme/app"])]);
sections[0].appendChild(repo);
sections[0].appendChild(h("select", { name: "branch" }, [h("option", { selected: "" }, ["main"])]));
sections[1].appendChild(h("input", { type: "radio", name: "shape", value: "single", checked: "", "data-no-send": "" }));
sections[1].appendChild(h("input", { type: "radio", name: "shape", value: "bluegreen", "data-no-send": "" }));
var blue = h("select", { name: "hosts.blue", "data-host-select": "blue" }, [
  h("option", { value: "" }, ["Choose"]), h("option", { value: "h1", "data-ip": "1", "data-label": "h-one" }, ["h-one"])]);
sections[2].appendChild(blue);
sections[4].appendChild(h("input", { type: "radio", name: "traffic.switch", value: "none", checked: "" }));
var form = h("form", { "data-env-flow": "", "data-traffic-address": "10.0.0.2" }, sections.concat([
  h("input", { type: "hidden", name: "data_mode", value: "slot", "data-no-send": "" }),
  h("p", { "data-flow-live": "" }),
  h("div", { "data-flow-result": "", hidden: "" }, [h("span", { "data-flow-message": "" }), h("a", { "data-flow-open": "", hidden: "" })]),
  h("button", { type: "button", "data-flow-back": "" }), h("button", { type: "button", "data-flow-next": "" }),
  h("button", { type: "button", "data-flow-deploy": "", hidden: "" }), h("button", { type: "button", "data-flow-restart": "" }),
]));
document.body.appendChild(form);
document.dispatchEvent(new Event("DOMContentLoaded"));
var next = form.querySelector("[data-flow-next]"), deploy = form.querySelector("[data-flow-deploy]");
function current() { return form._flow.current; }
function err(n) { var e = sections[n - 1].querySelector("[data-step-error]"); return e.hidden ? "" : e.textContent; }
async function click(b) { user("click", b); await settle(); }
// One answer per call of "METHOD path": a list is used in order; "throw" is an answer that never came.
var answers = {};
fetch = function (url, opts) {  // the harness's fetch, answering per call
  fetchCalls.push(opts.method + " " + url);
  fetchBodies.push(opts.body === undefined ? null : JSON.parse(opts.body));
  var key = opts.method + " " + url, list = answers[key] || [{ status: 200, body: {} }];
  var r = list.length > 1 ? list.shift() : list[0];
  if (r === "throw") return Promise.reject(new TypeError("Failed to fetch"));
  return Promise.resolve({ status: r.status, ok: r.status >= 200 && r.status < 300, statusText: "HTTP " + r.status,
    json: function () { return Promise.resolve(JSON.parse(JSON.stringify(r.body))); } });
};
var CHECK = "POST /api/v1/environments?check=true";
"""


def test_js_flow_step_checks_and_field_step_jumps(tmp_path):
    result = run_js(tmp_path, FLOW_DOM + """
var out = { start: [current(), form.querySelector("[data-flow-live]").textContent] };
// Step 1's own check: the name is checked before Slipway is asked.
form.querySelector('[name="name"]').value = "Bad_Name";
await click(next);
out.badName = [current(), err(1), fetchCalls.length, form.querySelector('[name="name"]').getAttribute("aria-invalid")];
// A refusal of a later step's field lets this step pass.
form.querySelector('[name="name"]').value = "uat";
answers[CHECK] = [{ status: 422, body: { detail: "Choose a host for blue", field: "hosts.blue" } }];
await click(next);
out.step2 = [current(), fetchBodies[0].name, fetchBodies[0].data_mode, JSON.stringify(fetchBodies[0].hosts)];
await click(next);  // step 2 -> 3 (the same later-step refusal)
// Step 3's own check: a host for blue.
await click(next);
out.noHost = [current(), err(3)];
// A refusal for an earlier step's field moves there and marks the field.
blue.value = "h1";
answers[CHECK] = [{ status: 409, body: { detail: "An environment named uat already exists", field: "name" } }];
await click(next);
out.jump = [current(), err(1), form.querySelector('[name="name"]').getAttribute("aria-invalid"),
            form.querySelector("[data-flow-live]").textContent];
// A plan answer moves on, and step 5 then has the plan.
answers[CHECK] = [{ status: 200, body: { ok: true, plan: { hostnames: [{ hostname: "api.uat.example.com", follows: "active" }],
                                                           slots: { blue: { host: "h-one" } } } } }];
form.querySelector('[name="name"]').value = "uat2";
await click(next); await click(next); await click(next); await click(next);
out.step5 = [current(), JSON.stringify(form._flow.plan.hostnames.map(function (h) { return h.hostname; }))];
out.fieldStep = [window.slipway.fieldStep("hosts.data"), window.slipway.fieldStep("traffic.dns"),
                 window.slipway.fieldStep("first_admin"), window.slipway.fieldStep("seed_snapshot_id"),
                 window.slipway.fieldStep("settings"), window.slipway.fieldStep("route_tls"), window.slipway.fieldStep("nope")];
done(out);
""")
    assert result["start"] == [1, "Step 1 of 7: Step1"]
    assert result["badName"][0] == 1 and result["badName"][1].startswith("Use 2-26 lowercase letters")
    assert result["badName"][2] == 0 and result["badName"][3] == "true"  # nothing was sent
    assert result["step2"] == [2, "uat", "slot", "{}"]
    assert result["noHost"] == [3, "Choose a host for blue"]
    assert result["jump"] == [1, "An environment named uat already exists", "true", "Step 1 of 7: Step1"]
    assert result["step5"] == [5, '["api.uat.example.com"]']
    assert result["fieldStep"] == [3, 5, 6, 6, 4, 5, 0]


def test_js_flow_two_call_deploy_unsure_and_locked(tmp_path):
    result = run_js(tmp_path, FLOW_DOM + """
form.querySelector('[name="name"]').value = "uat"; blue.value = "h1";
answers[CHECK] = [{ status: 200, body: { ok: true, plan: { hostnames: [], slots: {} } } }];
for (var i = 0; i < 6; i++) await click(next);
var out = { review: current(), deployShown: !deploy.hidden, nextHidden: next.hidden };
var msg = function () { return form.querySelector("[data-flow-message]").textContent; };
var link = function () { var a = form.querySelector("[data-flow-open]"); return a.hidden ? null : [a.textContent, a.getAttribute("href")]; };

// 1. The create's answer is lost: the name is unsure; the retry's "already exists" says it may exist.
answers["POST /api/v1/environments"] = ["throw", { status: 409, body: { detail: "An environment named uat already exists", field: "name" } }];
await click(deploy);
out.lost = [msg(), form._flow.unsure, link()];
await click(deploy);
out.exists = [msg(), link(), current()];

// 2. Created, but the start failed: locked on Review, and Deploy retries only the start.
form._flow.unsure = false;
var calls = fetchCalls.length;
answers["POST /api/v1/environments"] = [{ status: 201, body: { id: "e1", name: "uat" } }];
answers["POST /api/v1/environments/e1/deploy"] = [{ status: 409, body: { detail: "A job is already running for uat" } },
                                                   { status: 202, body: { id: "d1" } }];
await click(deploy);
out.locked = [msg(), link(), current(), form.querySelector("[data-flow-back]").disabled,
              form.querySelector("[data-flow-restart]").disabled, fetchCalls.slice(calls)];
calls = fetchCalls.length;
await click(next);  // locked: Next does nothing
await click(deploy);
out.retried = [fetchCalls.slice(calls), hrefs.slice(-1)[0]];
out.body = fetchBodies.filter(function (b, i) { return fetchCalls[i] === "POST /api/v1/environments"; }).pop();
done(out);
""")
    assert result["review"] == 7 and result["deployShown"] and result["nextHidden"]
    assert result["lost"][0].startswith("Slipway didn't answer") and result["lost"][1] is True
    assert result["exists"] == ["It may have been created already:", ["open it", "/environments"], 7]
    msg, link, step, back_off, restart_off, calls = result["locked"]
    assert msg == "Created uat, but its first deployment didn't start: A job is already running for uat."
    assert link == ["Open the environment", "/environments/e1"] and step == 7 and back_off and restart_off
    assert calls == ["POST /api/v1/environments", "POST /api/v1/environments/e1/deploy"]
    # Only the start is tried again, then the page opens the environment.
    assert result["retried"] == [["POST /api/v1/environments/e1/deploy"], "ASSIGN /environments/e1"]
    body = result["body"]
    assert body["name"] == "uat" and body["data_mode"] == "slot" and body["hosts"] == {"blue": "h1"}
    assert body["traffic"] == {"switch": "none", "dns": None} and "first_admin" not in body


def test_js_flow_plans_with_a_placeholder_admin_before_the_data_step(tmp_path):
    result = run_js(tmp_path, FLOW_DOM + """
form._flow.manifest = { capabilities: ["backup", "bluegreen", "server"],
  first_admin: { fields: [{ name: "email", kind: "email", max: 254 }, { name: "first_name", kind: "text", max: 50 }],
                 password: { min_length: 12 }, invite: null } };
form.querySelector('[name="name"]').value = "uat"; blue.value = "h1";
var planning = window.slipway.flowBody(form, true, form._flow.manifest);
var real = window.slipway.flowBody(form, false, form._flow.manifest);
done({ planning: planning.first_admin, real: real.first_admin === undefined });
""")
    assert result["planning"] == {"fields": {"email": "admin@example.com", "first_name": "A"}, "mode": "password",
                                  "password": "x" * 12}
    assert result["real"] is True


def test_js_traffic_plan_rows_and_claim_buttons(tmp_path):
    result = run_js(tmp_path, """
var plan = {
  routes: [{ hostname: "api.uat.example.com", follows: "active", tls_mode: "auto" },
           { hostname: "spaces.uat.example.com", follows: "server", tls_mode: "auto" },
           { hostname: "portal.uat.example.com", follows: "active", tls_mode: "off" }],
  switch: { backend: "switchyard", blockers: ["portal.uat.example.com is used by Switchyard host #7, which belongs to environment prod"],
            changes: [{ hostname: "api.uat.example.com", action: "update", summary: "api → 10.0.0.12:8000",
                        before: { upstreams: [{ host: "10.0.0.11", port: 8000 }] } },
                      { hostname: "spaces.uat.example.com", action: "none", before: { upstreams: [{ host: "10.0.0.13", port: 9000 }] } }] },
  dns: { backend: "cloudflare", blockers: ["Switchyard: other changes are waiting"],
         changes: [{ hostname: "api.uat.example.com", status: "ok" }, { hostname: "spaces.uat.example.com", status: "claimable" },
                   { hostname: "portal.uat.example.com", status: "conflict", summary: "a CNAME is there" }] },
};
var sink = function (ds) { return { dataset: ds, html: "", set innerHTML(v) { this.html = v; }, closest: function () { return null; } }; };
var card = sink({ env: "e1", canClaim: "" }), viewer = sink({ env: "e1" });
window.slipway.renderers.traffic_plan(card, plan);
window.slipway.renderers.traffic_plan(viewer, plan);
var submit = h("button", { type: "submit", "data-plan-submit": "" });
var dlg = h("form", {}, [submit]);
var list = { dataset: { mode: "list" }, html: "", set innerHTML(v) { this.html = v; }, closest: function () { return dlg; } };
window.slipway.renderers.traffic_plan(list, plan);
var blocked = submit.disabled, listed = list.html;
window.slipway.renderers.traffic_plan(list, { routes: [], switch: { blockers: [], changes: [{ hostname: "api.uat.example.com", action: "update", summary: "api → green" }] }, dns: null });
done({ card: card.html, viewer: viewer.html, list: listed, blocked: blocked, clear: submit.disabled });
""")
    card = result["card"]
    rows = re.findall(r'<tr data-name="([^"]+)">(.*?)</tr>', card)
    assert [r[0] for r in rows] == ["api.uat.example.com", "spaces.uat.example.com", "portal.uat.example.com"]
    api, spaces, portal = (r[1] for r in rows)
    assert "Live slot" in api and "10.0.0.11:8000" in api and "Will update" in api and "Up to date" in api
    assert "Data server" in spaces and "Not Slipway&#39;s" in spaces and "Claim" in spaces
    claim = re.search(r'data-api="([^"]+)" data-body="([^"]+)"', spaces)
    assert claim.group(1) == "POST /api/v1/environments/e1/dns/claim"
    assert json.loads(html.unescape(claim.group(2))) == {"hostname": "spaces.uat.example.com"}
    assert "Blocked" in portal and "belongs to environment prod" in portal and "a CNAME is there" in portal
    assert 'href="http://portal.uat.example.com"' in portal
    # A blocker that names no route is shown above the table; without traffic:switch there is no Claim.
    assert "other changes are waiting" in card.split("<table")[0]
    assert "Claim</button>" not in result["viewer"]
    # Activate's list: the blockers in red, and the button stays disabled until a plan has none.
    assert "Blocked" in result["list"] and result["blocked"] is True and result["clear"] is False


async def test_the_flow_can_read_the_manifest_with_environments_write_only(make_client):
    """§12.3: the New environment flow reads slipway.yml through GET /repositories/{id}/manifest, which also takes
    environments:write; without either write permission it stays 403 with phase 2's text."""
    await clients(make_client)  # the first user signed in becomes the admin
    ids = await _world()
    async with get_sessionmaker()() as db:
        repo_id = (await db.get(Environment, ids["env"])).repository_id
    url = f"/api/v1/repositories/{repo_id}/manifest?branch=main&path=.env.production"
    builder = await client_with(make_client, "builder@example.com", ["repos:read", "environments:write"])
    r = await builder.get(url)
    assert r.status_code == 400 and "not a .yml or .yaml file" in r.json()["detail"]  # past the permission check
    reader = await client_with(make_client, "reader@example.com", ["repos:read", "environments:read"])
    r = await reader.get(url)
    assert r.status_code == 403 and r.json()["detail"] == "Missing permission: instances:write"
