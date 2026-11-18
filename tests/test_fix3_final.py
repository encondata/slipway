"""Final review fixes (phase 3): the problems the checkers found in the earlier fixes.

The traffic-level tests use tests/test_traffic.py's environment (blue live on 10.0.0.11, green on 10.0.0.12)
and tests/fake_switchyard.py, through the helpers of tests/test_fix3_traffic_putback.py.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, update

from slipway.db.session import get_sessionmaker
from slipway.models import AuditEvent, Instance
from slipway.services import cloudflare, environments, resources, switchyard, traffic
from tests.fake_cloudflare import ZONE
from tests.test_data_api import clients
from tests.test_env_jobs import DNS, SWITCHYARD, _job
from tests.test_env_jobs import cf  # noqa: F401  (fixture)
from tests.test_env_pipeline import _live_env, _steps
from tests.test_fix3_traffic_putback import (  # noqa: F401  (fixtures)
    _down_after_second_put,
    _live,
    _on_green,
    configured,
    fake,
    job_sites,
    job_sy,
    multi,
    no_waits,
    submitted,
    tsites,
)
from tests.test_traffic import _blue_live, _ctx, _env, _env_obj, _expected, _slot, _upstreams


# ------------------------------------------- F1/F15: an Activate run over an unresolved switch's staged writes


async def _unresolved_green(fake, monkeypatch):
    """Blue live; an Activate of green ends unresolved after two hosts were staged on green (Switchyard went
    away). Switchyard is then back."""
    env_id = await _blue_live(fake)
    live, state = _down_after_second_put(fake, monkeypatch)
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(env_id, "activate", "green"))
    assert err.value.unresolved
    assert _live(live) == _expected("blue")
    assert len([u for u in _upstreams(fake).values() if u.startswith("10.0.0.12")]) == 2  # staged on green
    assert (await switchyard.load_edits()).get("held")
    state["down"], state["puts"] = False, 100
    return env_id, live


@pytest.mark.parametrize("slot", ["green", "blue"])
async def test_an_activate_over_an_unresolved_switch_puts_back_to_the_active_slot(configured, tsites, monkeypatch,
                                                                                  slot):
    """Activate again (of green, or of blue, the recorded active slot) whose check fails: the put-back takes
    every name back to blue, what Caddy served, never to the first switch's half-written staged state."""
    env_id, live = await _unresolved_green(configured, monkeypatch)
    tsites.codes = {"api.uat.example.com": [502]}
    lines: list[str] = []
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(env_id, "activate", slot, lines=lines))
    assert not err.value.unresolved, (str(err.value), lines)
    assert "Traffic stays on blue" in str(err.value)
    assert _on_green(live) == []
    assert _live(live) == _expected("blue")
    assert _upstreams(configured) == _expected("blue")


async def test_an_activate_over_an_unresolved_switch_that_cant_tell_stays_unresolved(configured, tsites,
                                                                                    monkeypatch):
    """When the recorded active slot doesn't serve a name, Slipway can't tell where to put it back: the switch
    stays unresolved and names it, and never says traffic stays on blue."""
    env_id, live = await _unresolved_green(configured, monkeypatch)
    blue = await _slot(env_id, "blue")
    # blue no longer publishes api's port: where api went before the unresolved switch is unknown.
    async with get_sessionmaker()() as db:
        ports = [p for p in blue.published_ports if int(p["container"]) != 8000]
        await db.execute(update(Instance).where(Instance.id == blue.id).values(published_ports=ports))
        await db.commit()
    tsites.codes = {"api.uat.example.com": [502]}
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(env_id, "activate", "green"))
    assert err.value.unresolved
    assert "api.uat.example.com" in str(err.value) and "Traffic stays on" not in str(err.value)


# ----------------------------------------------------------------- F57: a switch stopped before it wrote


async def test_a_switch_stopped_before_it_wrote_says_nothing_changed(multi, submitted, job_sy, monkeypatch):
    seeded = await _live_env(multi, active="blue", traffic=SWITCHYARD)
    monkeypatch.setitem(environments.ENV_STEP_TIMEOUTS, "switch", 0.3)
    await switchyard.lock.acquire()  # someone else holds Switchyard's lock for the whole limit
    try:
        dep = await _job(multi, seeded, "activate", slot="green")
    finally:
        switchyard.lock.release()
    assert dep.status == "failed" and _steps(dep)["switch"] == "failed", (dep.error, dep.log)
    assert dep.error == "It took longer than 0.3 seconds and was stopped; Slipway changed nothing", dep.error


# ---------------------------------- F24/F31/F43: records in a Cloudflare zone that was deleted and added again


async def test_dns_can_be_turned_off_when_its_zone_was_recreated(make_client, cf):
    """A zone deleted and added again keeps its name but gets a new id, and its records are gone. Turning DNS
    off is still refused by default; with forget_lost_zone the rows are forgotten (nothing deleted), and then
    the settings save and a new publish work."""
    c = await clients(make_client)
    env_id = await _env(mode="slot", slots=("blue",), dns=DNS, switch="none")
    await traffic.publish_dns(await _env_obj(env_id))
    assert len(cf.records) == 6
    cf.zones.clear()
    cf.records.clear()
    cf.add_zone(ZONE)

    r = await c["admin"].put("/api/v1/settings/cloudflare", json={"zone": ZONE, "public_ip": "203.0.113.7"})
    assert r.status_code == 409 and "forgets them when their zone is gone" in r.json()["detail"]
    off = {"traffic": {"switch": "none", "dns": None}}
    r = await c["maintainer"].patch(f"/api/v1/environments/{env_id}", json=off)
    assert r.status_code == 502 and "Forget the records whose zone is gone" in r.json()["detail"], r.json()
    assert len(await _dns_rows(env_id)) == 6  # the default is unchanged: nothing forgotten

    off["traffic"]["forget_lost_zone"] = True
    r = await c["maintainer"].patch(f"/api/v1/environments/{env_id}", json=off)
    assert r.status_code == 200, r.json()
    assert await _dns_rows(env_id) == []
    assert not ((await _env_obj(env_id)).traffic or {}).get("dns")
    async with get_sessionmaker()() as db:
        summaries = [a.summary for a in await db.scalars(select(AuditEvent))]
    assert any("whose Cloudflare zone is gone (nothing was deleted)" in s for s in summaries), summaries
    assert any("6 forgotten because their Cloudflare zone is gone" in s for s in summaries), summaries

    r = await c["admin"].put("/api/v1/settings/cloudflare", json={"zone": ZONE, "public_ip": "203.0.113.7"})
    assert r.status_code == 200, r.json()
    r = await c["maintainer"].patch(f"/api/v1/environments/{env_id}",
                                    json={"traffic": {"switch": "none", "dns": {"proxied": False}}})
    assert r.status_code == 200, r.json()
    await traffic.publish_dns(await _env_obj(env_id))
    assert len(cf.records) == 6


async def test_forget_lost_zone_still_deletes_records_in_a_zone_cloudflare_knows(make_client, cf):
    c = await clients(make_client)
    env_id = await _env(mode="slot", slots=("blue",), dns=DNS, switch="none")
    await traffic.publish_dns(await _env_obj(env_id))
    r = await c["maintainer"].patch(f"/api/v1/environments/{env_id}",
                                    json={"traffic": {"switch": "none", "dns": None, "forget_lost_zone": True}})
    assert r.status_code == 200, r.json()
    assert cf.records == {} and await _dns_rows(env_id) == []


async def _dns_rows(env_id):
    async with get_sessionmaker()() as db:
        return list(await resources.owned(db, env_id, cloudflare.PROVIDER, cloudflare.KIND))
