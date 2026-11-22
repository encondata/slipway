"""Review of phases 4 and 5, cluster "Environments and retry API": regression tests.

F2/F40: a DigitalOcean environment's Settings page saves (its PATCH keeps the load balancer and needs no public
IP before the first deploy). F16/F21: a production Activate's retry and the notice's Continue take the typed
name. F22: a teardown retry asks drop_data again when the data's only home goes. F31: an API Activate isn't
refused for a certificate its own certificate step renews. F39/F44: PATCH auto_activate on production is a 409.
F45: an address claim conflict names the address that was taken. K1: GET /cloud marks a gone droplet's host.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from slipway.db.session import get_sessionmaker
from slipway.models import AddressClaim, AuditEvent, Deployment, Environment, Host, Instance
from slipway.services import do_lb, environments, hosts, traffic
from slipway.services.environments import CreateRefused
from tests import do_fixtures as dof
from tests.test_accounts_web import scenario
from tests.test_data_api import client_with
from tests.test_data_api import storage  # noqa: F401
from tests.test_do_api import API, audits, built, failed, prod, record, set_rows, submitted, w  # noqa: F401
from tests.test_review_web import run_js

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")

RETRY = "/api/v1/deployments/{}/retry"


async def _env(env_id: uuid.UUID) -> Environment:
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env_id)
        assert row is not None
        return row


async def _host(host_id: uuid.UUID) -> Host:
    async with get_sessionmaker()() as db:
        row = await db.get(Host, host_id)
        assert row is not None
        return row


# ------------------------------------------------------------- F2, F40: the Settings page of a DO environment


def _page_patch(tmp_path, page: str, script: str) -> dict[str, Any]:
    """The PATCH body the real slipway.js sends when the edit page's form is submitted after ``script``."""
    page = page.replace('<form class="stack" method="post"', '<form id="edit-form" class="stack" method="post"', 1)
    result = run_js(tmp_path, scenario(page, ["edit-form"], """
var form = document.getElementById("edit-form");
await settle();
""" + script + """
await submit(form);
done({ calls: fetchCalls, bodies: fetchBodies });
"""))
    return [b for c, b in zip(result["calls"], result["bodies"]) if c.startswith("PATCH ")][-1]


@pytest.mark.parametrize("slots", [("blue",), ("blue", "green")])
async def test_f2_the_settings_page_of_a_digitalocean_environment_saves(w, tmp_path, slots):  # noqa: F811
    env = await dof.make_do_env(name="shop", account_id=w.account_id, slots=slots)
    page = (await w.admin.get(f"/environments/{env.env_id}/edit")).text
    # The load balancer is fixed; no Switchyard radio, no DNS address, no untick, no Switchyard TLS select.
    assert '<input type="hidden" name="traffic.switch" value="do_lb">' in page
    assert 'value="switchyard"' not in page and 'name="traffic.dns.address"' not in page
    assert 'name="dns_on"' not in page and "Switchyard's default" not in page
    assert 'name="traffic.forget_lost_zone"' not in page
    patch = _page_patch(tmp_path, page, 'field(form, "keep_backups").value = "7";')
    assert patch["traffic"]["switch"] == "do_lb"
    resp = await w.admin.patch(f"{API}/{env.env_id}", json=patch)
    assert resp.status_code == 200, (json.dumps(patch), resp.text)
    async with get_sessionmaker()() as db:
        owner = await db.get(Instance, env.ids["data"])
        assert owner.keep_backups == 7
    # Ticking Proxied before the first deploy (the load balancer's address isn't known yet, no public IP).
    page = (await w.admin.get(f"/environments/{env.env_id}/edit")).text
    patch = _page_patch(tmp_path, page, 'field(form, "traffic.dns.proxied").checked = true;')
    resp = await w.admin.patch(f"{API}/{env.env_id}", json=patch)
    assert resp.status_code == 200, (json.dumps(patch), resp.text)
    assert resp.json()["traffic"] == {"switch": "do_lb", "dns": {"provider": "cloudflare", "address": None,
                                                                 "proxied": True}}


async def test_f2_f40_patch_of_a_digitalocean_environment_before_and_after_its_first_deploy(w):  # noqa: F811
    env = await dof.make_do_env(name="np", account_id=w.account_id)
    url = f"{API}/{env.env_id}"
    # Before the first deploy: no load balancer address, and Cloudflare has no public IP.
    resp = await w.admin.patch(url, json={"traffic": {"switch": "do_lb", "dns": {"proxied": True}}})
    assert resp.status_code == 200, resp.text
    assert resp.json()["traffic"]["dns"] == {"provider": "cloudflare", "address": None, "proxied": True}
    resp = await w.admin.patch(url, json={"traffic": {"dns": {"proxied": False}}})  # the switch left out
    assert resp.status_code == 200, resp.text
    assert resp.json()["traffic"]["switch"] == "do_lb" and resp.json()["traffic"]["dns"]["proxied"] is False
    resp = await w.admin.patch(url, json={"env": {"FEATURE": "on"}, "traffic": {"forget_lost_zone": False}})
    assert resp.status_code == 200, resp.text
    assert (await _env(env.env_id)).traffic["dns"] == {"provider": "cloudflare", "address": None, "proxied": False}
    # After it: the edge step wrote the load balancer's address, which a PATCH keeps.
    await set_rows(Environment, env.env_id, traffic={"switch": "do_lb", "dns": {
        "provider": "cloudflare", "address": "203.0.113.50", "proxied": False}})
    resp = await w.admin.patch(url, json={"traffic": {"switch": "do_lb", "dns": {"proxied": True}}, "keep_backups": 9})
    assert resp.status_code == 200, resp.text
    assert resp.json()["traffic"]["dns"] == {"provider": "cloudflare", "address": "203.0.113.50", "proxied": True}
    # The rules stay: another switch, a typed address and DNS off are still refused.
    for body, where in (({"switch": "switchyard", "dns": {}}, "traffic.switch"),
                        ({"switch": "do_lb", "dns": {"address": "198.51.100.9"}}, "traffic.dns.address"),
                        ({"switch": "do_lb", "dns": None}, "traffic.dns")):
        resp = await w.admin.patch(url, json={"traffic": body})
        assert (resp.status_code, resp.json()["field"]) == (409, where), resp.text


# ------------------------------------------------------- F39, F44: auto_activate on production by PATCH


async def test_f39_patch_auto_activate_on_production_is_refused_with_its_field(w):  # noqa: F811
    env = await prod(w)
    await built(env, "blue")
    await built(env, "green")
    await set_rows(Environment, env.env_id, active_slot_id=env.ids["blue"], status="live")
    resp = await w.admin.patch(f"{API}/{env.env_id}", json={"auto_activate": True})
    assert (resp.status_code, resp.json()) == (409, {
        "detail": "A production environment waits for Activate: turn Activate automatically off",
        "field": "auto_activate"})
    assert (await _env(env.env_id)).auto_activate is False
    page = (await w.admin.get(f"/environments/{env.env_id}/edit")).text
    assert '<input type="checkbox" name="auto_activate" disabled>' in page


# ------------------------------------------- F16, F21: a production Activate's retry and the notice's Continue


async def _deployed(env: dof.DoEnv, *slots: str, **options: Any) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        last = None
        for slot in slots:
            last = Deployment(instance_id=env.ids[slot], environment_id=env.env_id, kind="deploy",
                              status="succeeded", branch="main", commit_sha=dof.SHA, steps=[],
                              options={"slot": slot, **options}, finished_at=datetime.now(UTC))
            db.add(last)
        await db.commit()
        assert last is not None
        return last.id


async def test_f16_a_production_activate_retry_takes_the_typed_name(w):  # noqa: F811
    env = await prod(w)
    await built(env, "blue")
    await built(env, "green")
    await _deployed(env, "blue", "green")
    await set_rows(Environment, env.env_id, active_slot_id=env.ids["green"], status="live")
    dep = await failed(env, "activate", slot=None, confirm="prod")
    async with get_sessionmaker()() as db:
        await db.execute(update(Deployment).where(Deployment.id == dep).values(options={"slot": "blue",
                                                                                         "confirm": "prod",
                                                                                         "from_slot": "green"}))
        await db.commit()
    detail = (await w.admin.get(f"/api/v1/deployments/{dep}")).json()["actions"]["retry"]
    assert detail["available"] is True and detail["needs_confirm"] is True, detail
    resp = await w.admin.post(RETRY.format(dep), json={})
    assert (resp.status_code, resp.json()["detail"]) == (422, "Type the environment's name, prod, exactly to confirm")
    resp = await w.admin.post(RETRY.format(dep), json={"confirm": "other"})
    assert resp.status_code == 422
    resp = await w.admin.post(RETRY.format(dep), json={"confirm": "prod"})
    assert resp.status_code == 202, resp.text
    async with get_sessionmaker()() as db:
        new = await db.get(Deployment, uuid.UUID(resp.json()["id"]))
        assert new.kind == "activate" and new.options["confirm"] == "prod" and new.options["slot"] == "blue"


async def test_f16_a_non_production_or_first_activate_retry_asks_no_name(w):  # noqa: F811
    env = await dof.make_do_env(name="uat", account_id=w.account_id)
    await built(env, "blue")
    await _deployed(env, "blue")
    dep = await failed(env, "activate", slot=None)
    async with get_sessionmaker()() as db:
        await db.execute(update(Deployment).where(Deployment.id == dep).values(options={"slot": "blue"}))
        await db.commit()
    detail = (await w.admin.get(f"/api/v1/deployments/{dep}")).json()["actions"]["retry"]
    assert detail["needs_confirm"] is False
    resp = await w.admin.post(RETRY.format(dep), json={})
    assert resp.status_code == 202, resp.text
    # A production's chained first activate, while nothing is live, moves no traffic: no name.
    env = await prod(w)
    await built(env, "blue")
    await _deployed(env, "blue")
    dep = await failed(env, "activate", slot=None)
    async with get_sessionmaker()() as db:
        await db.execute(update(Deployment).where(Deployment.id == dep).values(options={"slot": "blue",
                                                                                         "chain": True}))
        await db.commit()
    detail = (await w.admin.get(f"/api/v1/deployments/{dep}")).json()["actions"]["retry"]
    assert detail["needs_confirm"] is False


async def test_f21_continue_of_a_production_activate_takes_the_typed_name(w):  # noqa: F811
    env = await prod(w)
    await built(env, "blue")
    await built(env, "green")
    await _deployed(env, "blue")
    green = await _deployed(env, "green", go_live=True)
    await set_rows(Environment, env.env_id, active_slot_id=env.ids["blue"], status="live", notice={
        "text": "stopped", "deployment_id": green.hex, "next": {"kind": "activate", "slot": "green"}})
    url = f"{API}/{env.env_id}/notice/continue"
    resp = await w.admin.post(url)
    assert (resp.status_code, resp.json()["detail"]) == (422, "Type the environment's name, prod, exactly to confirm")
    resp = await w.admin.post(url, json={"confirm": "prod"})
    assert resp.status_code == 202, resp.text
    async with get_sessionmaker()() as db:
        new = await db.get(Deployment, uuid.UUID(resp.json()["id"]))
        assert new.kind == "activate" and new.options["confirm"] == "prod" and new.options["slot"] == "green"


# ------------------------------------------------------------------- F22: a teardown retry and drop_data


async def _failed_teardown(env: dof.DoEnv, **options: Any) -> uuid.UUID:
    await set_rows(Environment, env.env_id, status="deleting")
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=None, environment_id=env.env_id, kind="teardown", status="failed",
                         branch="main", steps=[{"key": "unroute", "status": "failed"}],
                         options={"confirmed": True, **options}, finished_at=datetime.now(UTC))
        db.add(dep)
        await db.commit()
        return dep.id


async def test_f22_a_teardown_retry_asks_drop_data_and_data_reset_again(w, make_client):  # noqa: F811
    env = await dof.make_do_env(name="td", account_id=w.account_id, status="live")
    await built(env, "blue")
    await set_rows(Instance, env.ids["data"], fresh_data="seeded")
    dep = await _failed_teardown(env, drop_data=True)
    deleter = await client_with(make_client, "del@example.com", ["environments:delete", "environments:read",
                                                                 "deployments:read"])
    resp = await deleter.post(RETRY.format(dep), json={"confirm": "td"})
    assert (resp.status_code, resp.json()["detail"]) == (409, environments.only_home_text(
        await _env(env.env_id), "its managed database"))
    resp = await deleter.post(RETRY.format(dep), json={"confirm": "td", "drop_data": True})
    assert resp.status_code == 403
    resp = await w.admin.post(RETRY.format(dep), json={"confirm": "td"})
    assert resp.status_code == 409
    resp = await w.admin.post(RETRY.format(dep), json={"confirm": "td", "drop_data": True})
    assert resp.status_code == 202, resp.text
    async with get_sessionmaker()() as db:
        new = await db.get(Deployment, uuid.UUID(resp.json()["id"]))
        assert new.options["drop_data"] is True


async def test_f22_a_teardown_retry_after_a_snapshot_or_of_empty_data_needs_no_drop_data(w):  # noqa: F811
    env = await dof.make_do_env(name="ts", account_id=w.account_id, status="live")
    await built(env, "blue")
    await set_rows(Instance, env.ids["data"], fresh_data="seeded")
    dep = await _failed_teardown(env, snapshot_first=True, snapshot="before-delete")
    resp = await w.admin.post(RETRY.format(dep), json={"confirm": "ts"})
    assert resp.status_code == 202, resp.text
    # An owner that never held data loses nothing.
    env = await dof.make_do_env(name="te", account_id=w.account_id, status="new")
    dep = await _failed_teardown(env)
    resp = await w.admin.post(RETRY.format(dep), json={"confirm": "te"})
    assert resp.status_code == 202, resp.text


# ------------------------------------------------- F31: an API Activate and its own certificate step


async def test_f31_an_activate_whose_certificate_step_renews_is_queued(w, monkeypatch):  # noqa: F811
    env = await dof.make_do_env(name="cv", account_id=w.account_id, status="live")
    await built(env, "blue")
    await built(env, "green")
    await _deployed(env, "blue", "green")
    await set_rows(Environment, env.env_id, active_slot_id=env.ids["blue"])
    blockers: list[str] = []

    async def configured(self, db):
        return None

    async def plan(self, ctx):
        return traffic.Plan(backend="do_lb", blockers=list(blockers))

    monkeypatch.setattr(do_lb.DoLbBackend, "configured", configured)
    monkeypatch.setattr(do_lb.DoLbBackend, "plan", plan)
    url = f"{API}/{env.env_id}/activate"
    # No served certificate recorded: the Activate lists its certificate step, which renews before the switch.
    blockers[:] = ["The certificate doesn't cover green.cv.example.com: Renew the certificate first"]
    resp = await w.admin.post(url, json={"slot": "green"})
    assert resp.status_code == 202, resp.text
    assert "certificate" in [s["key"] for s in resp.json()["steps"]]
    # Any other blocker still refuses.
    async with get_sessionmaker()() as db:
        await db.execute(update(Deployment).where(Deployment.id == uuid.UUID(resp.json()["id"]))
                         .values(status="failed", finished_at=datetime.now(UTC)))
        await db.commit()
    blockers[:] = ["The load balancer is applying a change; try again in a minute"]
    resp = await w.admin.post(url, json={"slot": "green"})
    assert resp.status_code == 409 and "applying a change" in resp.json()["detail"]


# ---------------------------------------------------------------- F45: which address claim was taken


def _conflict(text: str) -> IntegrityError:
    return IntegrityError("INSERT INTO address_claims ...", {}, Exception(text))


async def _claim(address: str) -> None:
    async with get_sessionmaker()() as db:
        host = Host(name=f"other-{address}", hostname=address, username="deploy", metrics={})
        db.add(host)
        await db.flush()
        db.add(AddressClaim(address=address, host_id=host.id))
        await db.commit()


async def test_f45_the_claim_named_is_the_address_taken_not_a_prefix_of_it():
    vms = {"blue": "10.0.0.1", "green": "10.0.0.12"}
    pg = _conflict('duplicate key value violates unique constraint "pk_address_claims"\n'
                   "DETAIL:  Key (address)=(10.0.0.12) already exists.")
    async with get_sessionmaker()() as db:
        found = await environments.claim_conflict(db, pg, vms)
    assert found is not None and (found.status, found.field) == (409, "hosts.green.machine.address")
    assert found.detail.startswith("10.0.0.12 was just taken")
    # SQLite names only the column: the claims are read again.
    await _claim("10.0.0.12")
    sqlite = _conflict("UNIQUE constraint failed: address_claims.address")
    async with get_sessionmaker()() as db:
        found = await environments.claim_conflict(db, sqlite, vms)
    assert found is not None and found.field == "hosts.green.machine.address"
    async with get_sessionmaker()() as db:
        assert await environments.claim_conflict(db, _conflict("UNIQUE constraint failed: hosts.name"), vms) is None


async def test_f45_flush_claims_names_the_slot_whose_address_was_taken():
    await _claim("10.0.0.12")
    async with get_sessionmaker()() as db:
        host = Host(name="mine-green", hostname="10.0.0.12", username="deploy", metrics={})
        db.add(host)
        await db.flush()
        db.add(AddressClaim(address="10.0.0.12", host_id=host.id))
        with pytest.raises(CreateRefused) as caught:
            await environments._flush_claims(db, {"blue": {"address": "10.0.0.1"},
                                                  "green": {"address": "10.0.0.12"}})
    assert caught.value.field == "hosts.green.machine.address"
    assert caught.value.detail.startswith("10.0.0.12 was just taken")


# --------------------------------------------------------- K1: GET /cloud and a gone droplet's host


async def test_k1_get_cloud_marks_a_gone_droplets_host_gone(w):  # noqa: F811
    env = await dof.make_do_env(name="gd", account_id=w.account_id, status="live")
    tags = ["slipway", f"slipway-env-{env.env_id}"]
    blue = w.fake.add_droplet(name="slipway-gd-blue", tags=tags)
    await built(env, "blue")
    await built(env, "green")
    await set_rows(Host, env.host_ids["blue"], provider_id=str(blue["id"]))
    await set_rows(Host, env.host_ids["green"], provider_id="99999")
    await set_rows(Environment, env.env_id, active_slot_id=env.ids["green"])
    await record(env, "droplet", str(blue["id"]), "slipway-gd-blue", slot="blue")
    await record(env, "droplet", "99999", "slipway-gd-green", slot="green")
    resp = await w.c["viewer"].get(f"{API}/{env.env_id}/cloud")
    assert resp.status_code == 200, resp.text
    text = "Droplet slipway-gd-green is gone from DigitalOcean: deploy to green to build it again"
    assert text in resp.json()["notes"]
    assert hosts.phase_of(await _host(env.host_ids["green"])) == hosts.PHASE_GONE
    assert hosts.phase_of(await _host(env.host_ids["blue"])) == hosts.PHASE_READY
    [event] = await audits("host.gone")
    assert event.summary == text and event.details["slot"] == "green"
    # A second read marks nothing again.
    resp = await w.c["viewer"].get(f"{API}/{env.env_id}/cloud")
    assert resp.status_code == 200 and text not in resp.json()["notes"]
    assert len(await audits("host.gone")) == 1
    # The fence sees it: a deploy to the gone active slot is allowed (D28).
    resp = await w.admin.post(f"{API}/{env.env_id}/deploy", json={"slot": "green"})
    assert resp.status_code == 202, resp.text


async def test_k1_get_cloud_leaves_a_rebuilt_host_and_a_busy_environment_alone(w):  # noqa: F811
    env = await dof.make_do_env(name="gb", account_id=w.account_id, status="live")
    await built(env, "blue")
    await built(env, "green")
    await set_rows(Host, env.host_ids["green"], provider_id="77777")  # rebuilt since: names a new droplet
    await set_rows(Host, env.host_ids["blue"], provider_id="88888")
    await record(env, "droplet", "99999", "slipway-gb-green", slot="green")
    resp = await w.admin.get(f"{API}/{env.env_id}/cloud")
    assert resp.status_code == 200, resp.text
    assert hosts.phase_of(await _host(env.host_ids["green"])) == hosts.PHASE_READY
    # A job of the environment is running: its own steps read the droplets.
    await record(env, "droplet", "88888", "slipway-gb-blue", slot="blue")
    async with get_sessionmaker()() as db:
        db.add(Deployment(instance_id=env.ids["blue"], environment_id=env.env_id, kind="deploy", status="running",
                          branch="main", steps=[], options={"slot": "blue"}))
        await db.commit()
    resp = await w.admin.get(f"{API}/{env.env_id}/cloud")
    assert resp.status_code == 200, resp.text
    assert hosts.phase_of(await _host(env.host_ids["blue"])) == hosts.PHASE_READY
    async with get_sessionmaker()() as db:
        assert (await db.scalars(select(AuditEvent).where(AuditEvent.action == "host.gone"))).first() is None


async def test_k1_a_droplet_left_alone_doesnt_stop_the_next_one_being_marked(w):  # noqa: F811
    env = await dof.make_do_env(name="g2", account_id=w.account_id, status="live")
    await built(env, "blue")
    await built(env, "green")
    await set_rows(Host, env.host_ids["blue"], provider_id="77777")  # rebuilt since: left alone, rolled back
    await set_rows(Host, env.host_ids["green"], provider_id="99999")
    await record(env, "droplet", "88888", "slipway-g2-blue", slot="blue")
    await record(env, "droplet", "99999", "slipway-g2-green", slot="green")
    resp = await w.c["viewer"].get(f"{API}/{env.env_id}/cloud")
    assert resp.status_code == 200, resp.text
    assert hosts.phase_of(await _host(env.host_ids["blue"])) == hosts.PHASE_READY
    assert hosts.phase_of(await _host(env.host_ids["green"])) == hosts.PHASE_GONE
    [event] = await audits("host.gone")
    assert event.details["droplet"] == "slipway-g2-green" and event.actor_id is not None
