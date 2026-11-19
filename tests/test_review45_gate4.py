"""Review of phases 4 and 5, integration gate after fix group 4: regression tests.

K1 (GET /environments/{id}/cloud marks a gone droplet's host gone and adds do_provision.gone_text to its notes)
met F54 (the card's own "<slot>'s droplet is gone" callout): on the view where the read marked the active slot's
host gone, the card showed the note as a warning next to its error callout for the same droplet. The card now
shows only the callout for the active droplet; a gone idle droplet's note still shows.
"""

from __future__ import annotations

import json

import pytest

from slipway.models import Environment, Host
from slipway.services import do_provision
from tests import do_fixtures as dof
from tests.test_do_api import API, built, record, set_rows, w  # noqa: F401
from tests.test_review_web import run_js

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")


async def test_gate4_a_gone_active_droplet_is_called_out_once(w, tmp_path):  # noqa: F811
    env = await dof.make_do_env(name="gd", account_id=w.account_id, slots=("blue", "green"), status="live")
    for slot in ("blue", "green"):
        await built(env, slot)
    await set_rows(Host, env.host_ids["blue"], provider_id="99999")
    await record(env, "droplet", "99999", "slipway-gd-blue", slot="blue")
    await set_rows(Environment, env.env_id, active_slot_id=env.ids["blue"])

    answer = (await w.c["viewer"].get(f"{API}/{env.env_id}/cloud")).json()
    gone = do_provision.gone_text("slipway-gd-blue", "blue")
    assert gone in answer["notes"]  # the read marked blue's host gone
    result = run_js(tmp_path, """
var data = %s;
var ds = { env: "e1", activeSlot: "blue", activeDroplet: "slipway-gd-blue", canDeploy: "" };
var active = window.slipway.cloudCallouts(data, ds);
// The same note for a droplet that isn't the active slot's has no other callout, so it still shows.
var idle = window.slipway.cloudCallouts(
  { notes: [%s], objects: [{ kind: "droplet", name: "slipway-gd-green", status: "gone" }] }, ds);
done({ active: active, idle: idle });
""" % (json.dumps(answer), json.dumps(do_provision.gone_text("slipway-gd-green", "green"))))
    (callout,) = result["active"]
    assert 'data-callout="gone-blue"' in callout
    assert "blue&#39;s droplet is gone" in callout or "blue's droplet is gone" in callout
    assert "is gone from DigitalOcean" not in callout
    (note,) = result["idle"]
    assert 'data-callout="note"' in note and "slipway-gd-green is gone from DigitalOcean" in note
