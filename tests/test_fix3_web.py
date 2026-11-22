"""Phase 3 review fixes for the web pages and dialogs (F33, F50, F51, F52, F53, K4, K5, K8, and the page part of
F55): what the pages offer and say matches what the API allows and what the job does.

Jobs are queued and never run; Switchyard, Cloudflare and GitHub are the fakes (nothing leaves the machine).
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import timedelta

import httpx

from slipway.db.session import get_sessionmaker
from slipway.models import Backup, Deployment, Environment, Instance
from slipway.services import data
from tests.conftest import make_user
from tests.test_data_api import client_with, clients
from tests.test_env_api import (  # noqa: F401  (autouse fixtures: jobs never run, fakes for every service)
    HOSTNAMES,
    cf,
    github,
    no_public_checks,
    storage,
    submitted,
    sy,
)
from tests.test_env_rules import MAN, SHA, T0, _failed_green, _job, _load, _world, _world_slot
from tests.test_env_web import _must_equal, _set, _tags, _text
from tests.test_review_web import run_js

LAG = ("blue (0123456) already runs on a database migrated past it (revision 0042, by green's 89abcde). A new "
       "release may remove what blue still uses. Activate green again and deploy to blue, or deploy again "
       "confirming that this release removes nothing blue uses.")


def _dialog_text(page: str, dialog_id: str) -> str:
    m = re.search(rf'<dialog class="modal" id="{dialog_id}">(.*?)</dialog>', page, re.S)
    assert m, dialog_id
    return _text(m.group(1))


# ------------------------------------------------------------------------------------ F33: the deployment page


async def test_member_deploy_page_offers_roll_back_only_with_data_reset_and_names_the_lead_slot(make_client):
    c = await clients(make_client)
    ids = await _world(hostnames=HOSTNAMES)
    async with get_sessionmaker()() as db:
        dep = await _failed_green(db, ids)
    # The developer has deployments:create and data:restore but not data:reset: no Roll back, and why.
    page = (await c["developer"].get(f"/deployments/{dep.id}")).text
    assert 'data-open="roll-back"' not in page and 'id="roll-back"' not in page
    assert "Roll back isn't available: You need the data:reset permission" in _text(page)
    r = await c["developer"].post(f"/api/v1/deployments/{dep.id}/rollback", json={"confirm": "uat"})
    assert r.status_code == 403  # the page and the API agree
    env_page = (await c["developer"].get(f"/environments/{ids['env']}")).text
    assert 'data-open="roll-back-env"' not in env_page
    # The maintainer gets the environment's wording: blue starts again on the restored data, green stays stopped.
    page = (await c["maintainer"].get(f"/deployments/{dep.id}")).text
    assert 'data-open="roll-back"' in page
    text = _dialog_text(page, "roll-back")
    assert "Puts uat's database back as it was at 2026-11-15 10:00 UTC, before deployment " + dep.id.hex[:8] + \
           ", and starts blue (0123456) again." in text
    assert "Writes made through blue since 2026-11-15 10:00 UTC are lost." in text
    assert "Blue and Green are stopped while it runs; green stays stopped until you deploy to it." in text
    assert "the release that was running" not in text
    assert _must_equal(page)["roll-back"] == "uat"
    assert f'data-form="POST /api/v1/deployments/{dep.id}/rollback"' in page
    assert "and start blue (0123456) again." in _text(page.split('id="roll-back-panel"', 1)[1].split("</section>")[0])


async def test_standalone_deploy_page_keeps_phase_2s_roll_back(admin_client):
    """A standalone instance's Roll back is unchanged: its own release that was running starts again."""
    from tests.test_data_api import seed

    iid = await seed()
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, iid)
        dep = _job(iid, None, "deploy", "failed", at=T0 + timedelta(hours=1),
                   steps=[{"key": "start", "name": "Start", "status": "failed"}])
        db.add(dep)
        await db.flush()
        bid = uuid.uuid4()
        identity = dict(inst.live_identity or {})
        db.add(Backup(id=bid, instance_id=iid, deployment_id=dep.id, name=data.backup_name(bid, T0),
                      reason="pre_deploy", status="ready", format="pg-custom", db_bytes=10,
                      identity_keys=sorted(identity), identity=identity,
                      identity_fp=data.identity_fp(bid, identity, identity), taken_at=T0))
        dep.backup_id = bid
        inst.data_dirty = data.mark_dirty(None, dep, step="start", at=T0)
        await db.commit()
    page = (await admin_client.get(f"/deployments/{dep.id}")).text
    assert 'data-open="roll-back"' in page
    text = _dialog_text(page, "roll-back")
    assert "the release that was running" in text and "Everything written since" in text


# -------------------------------------------------------------------------------- F51: the environment's dialog


async def _failed_deploy_with_backup(ids, slot: str, owner_slot: str) -> Deployment:
    async with get_sessionmaker()() as db:
        env, mem = await _load(db, ids)
        dep = _job(ids[slot], env.id, "deploy", "failed", at=T0 + timedelta(hours=1),
                   steps=[{"key": "start", "name": "Start", "status": "failed"}])
        db.add(dep)
        await db.flush()
        bid = uuid.uuid4()
        owner = mem[owner_slot]
        identity = dict(owner.live_identity or {k: "x" for k in MAN.identity_keys()})
        db.add(Backup(id=bid, instance_id=owner.id, deployment_id=dep.id, name=data.backup_name(bid, T0),
                      reason="pre_deploy", status="ready", format="pg-custom", db_bytes=10,
                      identity_keys=sorted(identity), identity=identity,
                      identity_fp=data.identity_fp(bid, identity, identity), taken_at=T0))
        dep.backup_id = bid
        owner.live_identity = identity
        owner.data_dirty = data.mark_dirty(None, dep, step="start", at=T0)
        await db.commit()
        return dep


async def test_single_slot_roll_back_says_blue_starts_its_release_again(admin_client):
    ids = await _world_slot()
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, ids["env"])
        mem = {"blue": await db.get(Instance, ids["blue"])}
        assert env and mem["blue"]
    dep = await _failed_deploy_with_backup({**ids}, "blue", "blue")
    page = (await admin_client.get(f"/environments/{ids['env']}")).text
    assert 'data-open="roll-back-env"' in page
    text = _dialog_text(page, "roll-back-env")
    assert (f"Puts solo's database back as it was at 2026-11-15 10:00 UTC, before deployment {dep.id.hex[:8]}, and "
            "starts blue (0123456) again, the release that was running.") in text
    assert "Everything written since 2026-11-15 10:00 UTC is lost." in text
    assert "Green" not in text and "stays stopped" not in text and "are stopped" not in text


async def test_failed_data_server_deploy_roll_back_starts_the_data_server_and_blue_again(admin_client):
    ids = await _world(hostnames=HOSTNAMES)
    dep = await _failed_deploy_with_backup(ids, "data", "data")
    page = (await admin_client.get(f"/environments/{ids['env']}")).text
    text = _dialog_text(page, "roll-back-env")
    assert (f"Puts uat's database back as it was at 2026-11-15 10:00 UTC, before deployment {dep.id.hex[:8]}, and "
            "starts the data server (0123456), the release that was running, and blue (0123456) again.") in text
    assert "Writes made through blue since 2026-11-15 10:00 UTC are lost." in text
    assert "Blue and Green are stopped while it runs." in text
    # Green runs blue's commit: it starts again too (D16), so nothing says data or green stays stopped.
    assert "Green runs the same commit, so it starts again too if it was running." in text
    assert "data stays stopped" not in text


async def test_failed_data_server_deploy_with_one_slot_names_only_blue(admin_client):
    ids = await _world(slots=("blue", "data"), live=("blue", "data"), hostnames=HOSTNAMES)
    await _failed_deploy_with_backup(ids, "data", "data")
    text = _dialog_text((await admin_client.get(f"/environments/{ids['env']}")).text, "roll-back-env")
    assert "Blue is stopped while it runs." in text and "Green" not in text


# ------------------------------------------------------------------------------ F50, K5: Deploy again, confirming


async def _refused(ids, *, error: str = LAG, at=None, step: str = "backup") -> uuid.UUID:
    dep_id = uuid.uuid4()
    at = at or T0 + timedelta(hours=1)
    async with get_sessionmaker()() as db:
        db.add(Deployment(id=dep_id, instance_id=ids["green"], environment_id=ids["env"], kind="deploy",
                          status="failed", branch="main", commit_sha=SHA, error=error, options={"slot": "green"},
                          created_at=at, finished_at=at,
                          steps=[{"key": step, "name": "Back up the data", "status": "failed"}]))
        await db.commit()
    return dep_id


async def test_deploy_again_confirming_opens_a_dialog_with_the_acknowledgement_unticked(admin_client):
    """No one-click override (F50): the button opens a dialog that names the commit and asks again, unticked. It
    is offered on a run-time refusal without the Deploy dialog's switch-back hint (K5)."""
    ids = await _world(hostnames=HOSTNAMES)
    refused = await _refused(ids)
    page = (await admin_client.get(f"/deployments/{refused}")).text
    assert not any(a.get("data-api", "").endswith("/deploy") for _, a, _ in _tags(page))
    button = next(a for t, a, _ in _tags(page) if t == "button" and a.get("data-open") == "deploy-again")
    assert "Deploy again, confirming" in _text(page)
    assert button is not None
    form = next(a for t, a, dlg in _tags(page) if t == "form" and dlg == "deploy-again")
    assert form["data-form"] == f"POST /api/v1/environments/{ids['env']}/deploy"
    box = next(a for t, a, dlg in _tags(page) if dlg == "deploy-again" and a.get("name") == "acknowledge_schema")
    assert "checked" not in box and "required" in box
    slot = next(a for t, a, dlg in _tags(page) if dlg == "deploy-again" and a.get("name") == "slot")
    assert slot["value"] == "green"
    text = _dialog_text(page, "deploy-again")
    assert "Deploys commit 0123456 of main to green again" in text
    assert "This release (0123456) removes nothing blue (0123456) uses" in text
    # The API takes what the dialog sends once ticked.
    r = await admin_client.post(f"/api/v1/environments/{ids['env']}/deploy",
                                json={"slot": "green", "acknowledge_schema": True})
    assert r.status_code == 202, r.text


async def test_deploy_again_confirming_goes_once_the_refusal_is_out_of_date(admin_client):
    ids = await _world(hostnames=HOSTNAMES)
    refused = await _refused(ids)
    # Another error is not the lag check.
    other = await _refused(ids, error="The build failed", at=T0 + timedelta(minutes=30))
    assert 'data-open="deploy-again"' not in (await admin_client.get(f"/deployments/{other}")).text
    # A later deploy of green (its retry, or a new one) supersedes the refusal.
    later = uuid.uuid4()
    async with get_sessionmaker()() as db:
        db.add(_job(ids["green"], ids["env"], "deploy", "succeeded", at=T0 + timedelta(hours=2), id=later))
        await db.commit()
    page = (await admin_client.get(f"/deployments/{refused}")).text
    assert 'data-open="deploy-again"' not in page and 'id="deploy-again"' not in page
    async with get_sessionmaker()() as db:
        await db.delete(await db.get(Deployment, later))
        await db.commit()
    assert 'data-open="deploy-again"' in (await admin_client.get(f"/deployments/{refused}")).text
    # An Activate since moved the traffic: the idle slot and the slot that serves aren't the refusal's any more.
    async with get_sessionmaker()() as db:
        db.add(Deployment(instance_id=None, environment_id=ids["env"], kind="activate", status="succeeded",
                          branch="main", created_at=T0 + timedelta(hours=2), finished_at=T0 + timedelta(hours=2),
                          options={"slot": "green"}))
        await db.commit()
    assert 'data-open="deploy-again"' not in (await admin_client.get(f"/deployments/{refused}")).text


async def test_deploy_again_confirming_needs_the_deploy_to_be_open(make_client):
    c = await clients(make_client)
    ids = await _world(hostnames=HOSTNAMES)
    refused = await _refused(ids)
    assert 'data-open="deploy-again"' in (await c["developer"].get(f"/deployments/{refused}")).text
    # While a job runs, Deploy is refused, so the button isn't offered either.
    async with get_sessionmaker()() as db:
        db.add(_job(ids["data"], ids["env"], "backup", "running", at=T0 + timedelta(hours=2)))
        await db.commit()
    assert 'data-open="deploy-again"' not in (await c["developer"].get(f"/deployments/{refused}")).text
    # Without deployments:create there is nothing to offer.
    viewer = (await c["viewer"].get(f"/deployments/{refused}")).text
    assert "deploy-again" not in viewer


# ------------------------------------------------------------------------------------- F52: Add a slot's box


async def test_add_slot_box_is_ticked_only_with_deployments_create(make_client):
    await make_user("first@example.com")
    ids = await _world(slots=("blue", "data"), live=("blue", "data"))
    deployer = await client_with(make_client, "d@example.com", ["environments:read", "environments:write",
                                                                 "hosts:read", "deployments:create"])
    page = (await deployer.get(f"/environments/{ids['env']}")).text
    box = next(a for t, a, dlg in _tags(page) if dlg == "add-slot" and a.get("name") == "update_data_server")
    assert "checked" in box and "disabled" not in box
    writer = await client_with(make_client, "w@example.com", ["environments:read", "environments:write", "hosts:read"])
    page = (await writer.get(f"/environments/{ids['env']}")).text
    box = next(a for t, a, dlg in _tags(page) if dlg == "add-slot" and a.get("name") == "update_data_server")
    assert "checked" not in box and "disabled" in box
    assert "needs the deployments:create permission" in box["title"]
    # What the dialog sends (a disabled box isn't sent) is accepted.
    r = await writer.post(f"/api/v1/environments/{ids['env']}/slots", json={"host_id": str(ids["host_green"])})
    assert r.status_code in (200, 201), r.text


# -------------------------------------------------------------------------------- F53: the Backups card


async def test_env_backups_card_needs_instances_read_for_its_endpoint(make_client):
    await make_user("first@example.com")
    ids = await _world()
    reader = await client_with(make_client, "r@example.com", ["environments:read", "data:read"])
    page = (await reader.get(f"/environments/{ids['env']}")).text
    assert 'id="backups-card"' not in page and 'id="backups"' not in page
    both = await client_with(make_client, "rb@example.com", ["environments:read", "data:read", "instances:read"])
    page = (await both.get(f"/environments/{ids['env']}")).text
    url = re.search(r'id="backups" data-load="([^"]+)"', page).group(1).replace("&amp;", "&")
    r = await both.get(url)
    assert r.status_code != 403, r.text  # what the card loads, this user may read


# -------------------------------------------------------------------- F55 (page part): Start over on a data server


async def test_env_page_offers_start_over_on_a_live_data_server_while_no_slot_went_live(admin_client):
    ids = await _world(slots=("blue", "data"), live=("data",), active=None, status="new")
    async with get_sessionmaker()() as db:
        db.add(_job(ids["data"], ids["env"], "deploy", "succeeded", at=T0 + timedelta(minutes=5),
                    release="/srv/uat-data/releases/0123456789ab-1"))
        await db.commit()
    page = (await admin_client.get(f"/environments/{ids['env']}")).text
    assert 'data-open="start-over"' in page and 'id="start-over"' in page
    # Once an app slot has gone live it is Reset data, as the API says.
    await _set(Instance, ids["blue"], current_commit_sha=SHA)
    page = (await admin_client.get(f"/environments/{ids['env']}")).text
    assert 'data-open="start-over"' not in page


# --------------------------------------------------------------------- K4: the flow with environments:write


async def test_new_environment_flow_reads_branches_and_manifest_with_environments_write_only(make_client,
                                                                                          monkeypatch):
    from slipway.api.v1 import repositories as repos_api
    from slipway.services.github import GitHubClient
    from tests.test_env_api import FILES

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/branches"):
            return httpx.Response(200, json=[{"name": "main"}])
        if "/contents/" in path:
            name = path.split("/contents/", 1)[-1]
            text = FILES.get(name)
            return httpx.Response(200, text=text) if text is not None else httpx.Response(404, json={})
        if "/commits/" in path:
            return httpx.Response(200, json={"sha": SHA, "commit": {"message": "x"}})
        return httpx.Response(404, json={"message": "Not Found"})

    monkeypatch.setattr(repos_api, "GitHubClient", lambda token: GitHubClient(token, transport=httpx.MockTransport(handler)))
    await make_user("first@example.com")
    ids = await _world()
    builder = await client_with(make_client, "b@example.com", ["environments:read", "environments:write",
                                                                "repos:read", "hosts:read"])
    r = await builder.get("/environments/new")
    assert r.status_code == 200
    r = await builder.get(f"/api/v1/repositories/{ids['repo']}/branches")
    assert r.status_code == 200 and r.json() == ["main"], r.text
    r = await builder.get(f"/api/v1/repositories/{ids['repo']}/manifest?branch=main")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["found"] is True and "manifest" in body, body
    assert "bluegreen" in body["manifest"]["capabilities"]


# ------------------------------------------------------------------------------ K8: the Data fieldset in JS


APP_FORM = """
var TREE = __TREE__;
function build(n) { return typeof n === "string" ? n : h(n.tag, n.attrs, n.children.map(build)); }
var form = build(TREE);
document.body.appendChild(form);
routes["GET /api/v1/repositories/__REPO__/branches"] = { status: 200, body: ["main"] };
routes["GET /api/v1/repositories/__REPO__/manifest"] = { status: 200, body: { manifest: __MANIFEST__ } };
document.dispatchEvent(new Event("DOMContentLoaded"));
await settle();
var fs = form.querySelector("[data-app-data]");
var keep = fs.querySelector('[name="keep_backups"]').closest(".field");
done({ hidden: fs.hidden, keep: keep.hidden, body: window.slipway.serialize(form) });
"""


async def test_js_data_fieldset_shows_only_for_capabilities_it_has_fields_for(admin_client, tmp_path):
    from tests.test_data_api import MANIFEST
    from tests.test_final_ui import _add_repo, _form_tree, _host

    repo_id = await _add_repo(93, "attachonly", detected_config={"manifest": True, "files": ["slipway.yml"]})
    await _host(admin_client)
    page = (await admin_client.get(f"/instances/new?repo={repo_id}")).text
    tree = json.dumps(_form_tree(page))
    plain = {**MANIFEST, "data": {**MANIFEST["data"], "volumes": []}, "first_admin": None}
    cases = (
        (["attach"], True, None),  # data.attach alone: nothing to fill in
        (["attach", "server", "bluegreen"], True, None),
        (["attach", "revision_check"], True, None),
        (["attach", "first_admin"], False, True),  # a first admin, but no dump: no Backups to keep
        # A slipway.yml phase 2 could read keeps phase 2's fieldset, Backups to keep included (I1).
        (["revision_check"], False, False),
        (["revision_check", "first_admin"], False, False),
        (["backup", "snapshot"], False, False),
    )
    for caps, hidden, keep_hidden in cases:
        man = {**plain, "capabilities": caps}
        scenario = (APP_FORM.replace("__TREE__", tree).replace("__REPO__", repo_id)
                    .replace("__MANIFEST__", json.dumps(man)))
        result = run_js(tmp_path, scenario)
        assert result["hidden"] is hidden, (caps, result)
        if not hidden:
            assert result["keep"] is keep_hidden, (caps, result)
            assert ("keep_backups" in result["body"]) is (not keep_hidden), (caps, result)
        else:
            assert "keep_backups" not in result["body"], (caps, result)
