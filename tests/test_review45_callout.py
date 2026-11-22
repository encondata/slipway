"""Review of phases 4 and 5, cluster "Gone-droplet callout and DigitalOcean doc": regression tests.

F54: a droplet deleted by hand while its slot is active. GET /environments/{id}/cloud (the DigitalOcean card's
read, made on every view of the environment page) marks the slot's host gone, and from then on the page itself
shows the "<slot>'s droplet is gone" callout with Deploy to <slot>, in a Single environment and in Blue/Green.
"""

from __future__ import annotations

import pytest

from slipway.db.session import get_sessionmaker
from slipway.models import Environment, Host
from slipway.services import environments, hosts, jobs
from tests import do_fixtures as dof
from tests.test_do_api import API, built, record, set_rows, w  # noqa: F401

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")


def _callout(page: str, key: str) -> str:
    start = page.find(f'data-callout="{key}"')
    assert start != -1, f"no {key} callout"
    end = page.find("</div></div>", start)
    return page[start:end]


@pytest.mark.parametrize("slots", [("blue",), ("blue", "green")])
async def test_f54_the_page_calls_out_a_gone_active_droplet_once_get_cloud_saw_it(w, slots):  # noqa: F811
    env = await dof.make_do_env(name="gd", account_id=w.account_id, slots=slots, status="live")
    for slot in slots:
        await built(env, slot)
    # blue's droplet was deleted by hand: DigitalOcean answers 404 for the id Slipway recorded.
    await set_rows(Host, env.host_ids["blue"], provider_id="99999")
    await record(env, "droplet", "99999", "slipway-gd-blue", slot="blue")
    await set_rows(Environment, env.env_id, active_slot_id=env.ids["blue"])
    url = f"/environments/{env.env_id}"

    # Before the card's read the host still reads Ready, so the page has no callout of its own: the card's
    # live callout says so instead, once GET /cloud answers.
    page = (await w.admin.get(url)).text
    assert 'data-callout="gone-blue"' not in page
    assert 'data-active-slot="blue"' in page and 'data-active-droplet="slipway-gd-blue"' in page

    resp = await w.c["viewer"].get(f"{API}/{env.env_id}/cloud")
    assert resp.status_code == 200, resp.text
    async with get_sessionmaker()() as db:
        host = await db.get(Host, env.host_ids["blue"])
        assert hosts.phase_of(host) == hosts.PHASE_GONE

    page = (await w.admin.get(url)).text
    callout = _callout(page, "gone-blue")
    text = "blue&#39;s droplet is gone, so nothing answers through the load balancer: deploy to blue to build it again"
    # In Blue/Green, green has a live release: it may be activated instead.
    assert text + (", or activate green." if "green" in slots else ".") in callout
    assert f'data-api="POST /api/v1/environments/{env.env_id}/deploy" data-body=\'{{"slot": "blue"}}\'' in callout
    assert "Deploy to blue</button>" in callout
    # The callout stays on later views; the card's read finds nothing new to mark.
    page = (await w.admin.get(url)).text
    assert page.count('data-callout="gone-blue"') == 1
    # The deploy it offers isn't fenced off: the fence sees the host gone (D28).
    async with get_sessionmaker()() as db:
        env_row = await db.get(Environment, env.env_id)
        assert env_row is not None
        mem = await environments.members(db, env_row)
        assert await jobs.environment_fence(db, env_row, mem, instance=mem["blue"], kind="deploy") is None
