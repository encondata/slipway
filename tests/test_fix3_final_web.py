"""Final review fixes (phase 3), pages that must agree with the API: Retry of a roll back on shared data (F28) and
under an unresolved switch (F7), Update the data server's chain (F48), the Start over dialog of a data server that
went live (F55), Deploy again, confirming's commit (F50), and a standalone instance's Roll back text (F33, I1).

Jobs are queued and never run; Switchyard, Cloudflare and GitHub are the fakes.
"""

from __future__ import annotations

import re
import uuid
from datetime import timedelta

from slipway.db.session import get_sessionmaker
from slipway.models import Backup, Deployment, Environment, Instance
from slipway.services import data
from tests.conftest import make_user
from tests.test_data_api import client_with, clients, seed
from tests.test_env_api import (  # noqa: F401  (autouse fixtures: jobs never run, fakes for every service)
    HOSTNAMES,
    _backup,
    _update,
    cf,
    github,
    no_public_checks,
    storage,
    submitted,
    sy,
)
from tests.test_env_rules import SHA, T0, _failed_green, _job, _world
from tests.test_env_web import _tags, _text
from tests.test_fix3_web import _dialog_text, _refused


# ------------------------------------------------------------- F28: Retry of a roll back on shared data


async def test_retry_of_a_roll_back_on_shared_data_is_off_without_data_reset(make_client):
    c = await clients(make_client)
    ids = await _world()
    async with get_sessionmaker()() as db:
        failed = await _failed_green(db, ids)
    r = await c["maintainer"].post(f"/api/v1/deployments/{failed.id}/rollback", json={"confirm": "uat"})
    assert r.status_code == 202, r.text
    rb = uuid.UUID(r.json()["id"])
    await _update(Deployment, rb, status="failed")
    dev = c["developer"]
    retry = (await dev.get(f"/api/v1/deployments/{rb}")).json()["actions"]["retry"]
    assert "data:reset" in retry["also_needs"]
    page = (await dev.get(f"/deployments/{rb}")).text
    assert 'data-open="retry-job"' not in page
    assert "Retrying this roll back needs the data:reset permission" in page
    assert (await dev.post(f"/api/v1/deployments/{rb}/retry", json={"confirm": "uat"})).status_code == 403
    # The maintainer has data:reset: offered, and accepted.
    assert 'data-open="retry-job"' in (await c["maintainer"].get(f"/deployments/{rb}")).text


# ---------------------------------------------------------------- F7: Retry under an unresolved switch


async def test_retry_of_a_member_job_is_off_while_a_switch_is_unresolved(make_client):
    c = await clients(make_client)
    ids = await _world()
    bid = await _backup(ids["data"])
    async with get_sessionmaker()() as db:
        failed = _job(ids["data"], ids["env"], "restore", "failed", at=T0 + timedelta(hours=1),
                      restore_backup_id=bid, steps=[{"key": "release", "status": "failed", "name": "Release"}])
        db.add(failed)
        await db.commit()
    await _update(Environment, ids["env"], traffic_state={
        "unresolved": {"deployment_id": "ab" * 16, "message": "Slipway restarted during the switch"}})
    retry = (await c["admin"].get(f"/api/v1/deployments/{failed.id}")).json()["actions"]["retry"]
    assert not retry["available"] and retry["reason"].startswith("Traffic of uat may be split"), retry
    page = (await c["admin"].get(f"/deployments/{failed.id}")).text
    assert 'data-open="retry-job"' not in page
    r = await c["admin"].post(f"/api/v1/deployments/{failed.id}/retry", json={"confirm": "uat"})
    assert r.status_code == 409


# ------------------------------------------------------------ F48: Update the data server and its chain


async def test_update_the_data_server_asks_traffic_switch_when_its_chain_goes_live(make_client):
    await make_user("first@example.com")
    ids = await _world(live=("data",), active=None)
    u = await client_with(make_client, "dep@example.com",
                          ["environments:read", "deployments:read", "deployments:create", "instances:read"])
    action = (await u.get(f"/api/v1/environments/{ids['env']}")).json()["actions"]["update_data_server"]
    assert not action["available"]
    assert action["reason"] == "Deploying uat makes blue live, which needs the traffic:switch permission"
    r = await u.post(f"/api/v1/environments/{ids['env']}/deploy", json={"target": "data"})
    assert r.status_code == 403 and r.json()["detail"] == action["reason"]


# ------------------------------------------------ F55: the Start over dialog of a data server that went live


async def test_start_over_dialog_of_a_live_data_server_says_what_the_job_does(admin_client):
    ids = await _world(slots=("blue", "data"), live=("data",), active=None, status="new")
    async with get_sessionmaker()() as db:
        db.add(_job(ids["data"], ids["env"], "deploy", "succeeded", at=T0 + timedelta(minutes=5),
                    release="/srv/uat-data/releases/0123456789ab-1"))
        blue = await db.get(Instance, ids["blue"])
        blue.app_state = {**(blue.app_state or {}), "starting_volumes": [{"name": "demo-uat-blue-web_cache"}]}
        await db.commit()
    page = (await admin_client.get(f"/environments/{ids['env']}")).text
    text = _dialog_text(page, "start-over")
    assert "failed first deploys created" not in text
    assert "Deletes uat's data on h-data" in text
    assert "and the app's own volumes on Blue, which its failed deploys left" in text
    assert "The data server is stopped afterwards. uat's next deploy updates it first, and starts empty." in text


# ------------------------------------------------------------- F50: Deploy again, confirming pins its commit


async def test_deploy_again_confirming_sends_the_refused_commit(admin_client):
    ids = await _world(hostnames=HOSTNAMES)
    refused = await _refused(ids)
    page = (await admin_client.get(f"/deployments/{refused}")).text
    sent = next(a for t, a, dlg in _tags(page) if dlg == "deploy-again" and a.get("name") == "commit_sha")
    assert sent["value"] == SHA
    text = _dialog_text(page, "deploy-again")
    assert "Deploys commit 0123456 of main to green again" in text and "newest commit" not in text
    url = f"/api/v1/environments/{ids['env']}/deploy"
    r = await admin_client.post(url, json={"slot": "green", "commit_sha": SHA})
    assert r.status_code == 422  # only with the acknowledgement
    r = await admin_client.post(url, json={"slot": "green", "acknowledge_schema": True, "commit_sha": "e" * 40})
    assert r.status_code == 409 and "No deploy of green was of commit eeeeeee" in r.json()["detail"]
    r = await admin_client.post(url, json={"slot": "green", "acknowledge_schema": True, "commit_sha": SHA})
    assert r.status_code == 202, r.text
    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, uuid.UUID(r.json()["id"]))
    assert dep.options["pin_commit"] == SHA and dep.options["behind_ok"] is True


# --------------------------------------------------- F33 (I1): a standalone instance's Roll back panel


async def test_a_standalone_roll_back_panel_is_phase_2s_for_a_viewer(make_client):
    await make_user("first@example.com")
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
    viewer = await client_with(make_client, "v@example.com", ["deployments:read", "instances:read"])
    page = (await viewer.get(f"/deployments/{dep.id}")).text
    assert not re.search(r'id="roll-back-panel"', page)
    assert "Roll back isn't available" not in page
