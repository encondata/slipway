"""Phase 3 review fixes, integration gate after group 1: where two clusters' fixes meet.

Create it now asked on an app slot now queues the data owner's job (F5), and that job meets the unresolved
switch fence (F56). The plan_dns ``adopt`` status (F42) has a label on the traffic plan page.
"""

from __future__ import annotations

import re
from pathlib import Path

from slipway.models import Environment, Instance
from slipway.services import cloudflare, environments
from tests.test_env_pipeline import _get, _live_env, _set, multi, no_waits, submitted  # noqa: F401
from tests.test_fix3_data_jobs import _pending_admin

UNRESOLVED = {"unresolved": {"deployment_id": "ab" * 16, "message": "Slipway restarted during the switch"}}
JS = Path(__file__).resolve().parents[1] / "slipway" / "web" / "static" / "js" / "slipway.js"


async def test_create_it_now_asked_on_a_slot_meets_the_unresolved_switch_fence(admin_client, multi, submitted):
    seeded = await _live_env(multi)
    await _pending_admin(seeded)
    await _set(Instance, seeded.ids["data"], content_pending=True)
    await _set(Environment, seeded.env_id, traffic_state=UNRESOLVED)
    text = environments.unresolved_text(await _get(Environment, seeded.env_id))
    for slot, path in (("blue", "first-admin/run"), ("green", "content/run"), ("data", "first-admin/run")):
        r = await admin_client.post(f"/api/v1/instances/{seeded.ids[slot]}/{path}")
        assert (r.status_code, r.json()["detail"]) == (409, text), (slot, path, r.text)


def test_every_dns_plan_status_has_a_label():
    block = re.search(r"const DNS_STATE = \{(.*?)\};", JS.read_text(), re.S).group(1)
    labelled = set(re.findall(r"(\w+): \[", block))
    statuses = {cloudflare.OK, cloudflare.UPDATE, cloudflare.CREATE, cloudflare.COVERED, cloudflare.CLAIMABLE,
                cloudflare.CONFLICT, cloudflare.DELETE, cloudflare.FORGET, cloudflare.ADOPT}
    assert statuses <= labelled, statuses - labelled
