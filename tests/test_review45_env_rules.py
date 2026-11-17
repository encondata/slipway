"""Review 45, cluster "Environment rules and env jobs": the environment rules a DigitalOcean (production) environment
is held to through the API (F8, F17, F18, F38). The job halves are tests/test_review45_env_rules_jobs.py; the VM
page view (K5) is tests/test_review45_env_rules_vm.py. Fakes only.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import select

from slipway.db.session import get_sessionmaker
from slipway.models import AuditEvent, Deployment, Environment, Instance
from slipway.services import cloudflare, environments, traffic
from tests import do_fixtures as dof
from tests.fake_cloudflare import FakeCloudflare
from tests.test_do_api import API, built, prod, set_rows, submitted, w  # noqa: F401  (fixtures)
from tests.test_data_api import storage  # noqa: F401  (autouse)
from tests.test_traffic import _cloudflare, _env_obj


@pytest.fixture
def cf(monkeypatch):
    fake = FakeCloudflare()
    monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(fake.handle))
    return fake


async def _jobs() -> list[Deployment]:
    async with get_sessionmaker()() as db:
        return list(await db.scalars(select(Deployment)))


# ----------------------------------------------------------------------------- F8: no record before edge


async def test_f8_publish_before_the_load_balancer_exists_is_refused_and_plans_no_record(cf):
    await _cloudflare(cf, public_ip="203.0.113.7")  # the install's own public IP (Switchyard's)
    env = await dof.make_do_env(name="shop")
    row = await _env_obj(env.env_id)
    assert row.traffic["switch"] == "do_lb" and row.traffic["dns"]["address"] is None
    text = "shop's load balancer isn't made yet: deploy first"
    async with get_sessionmaker()() as db:
        assert await environments.publish_problem(db, row) == text
        with pytest.raises(traffic.DnsRefused) as err:
            await traffic.dns_plan(row, db)
    assert str(err.value) == text and err.value.plan.blockers == [text]
    with pytest.raises(traffic.DnsRefused):
        await traffic.publish_dns(row)
    assert not [r for r in cf.records.values() if r["type"] == "A"]
    # Teardown's undns still runs: it wants no name at all.
    await traffic.publish_dns(row, remove=True)
    # Once edge has written the load balancer's IP, the records point there, never at the install's IP.
    async with get_sessionmaker()() as db:
        found = await db.get(Environment, env.env_id)
        found.traffic = {**found.traffic, "dns": {**found.traffic["dns"], "address": "198.51.100.9"}}
        await db.commit()
    row = await _env_obj(env.env_id)
    async with get_sessionmaker()() as db:
        assert await environments.publish_problem(db, row) is None
    await traffic.publish_dns(row)
    assert {r["content"] for r in cf.records.values() if r["type"] == "A"} == {"198.51.100.9"}


async def test_f8_the_publish_route_answers_409(w):
    env = await dof.make_do_env(name="shop", account_id=w.account_id)
    resp = await w.admin.post(f"{API}/{env.env_id}/publish")
    assert (resp.status_code, resp.json()["detail"]) == (409, "shop's load balancer isn't made yet: deploy first")
    out = (await w.admin.get(f"{API}/{env.env_id}")).json()
    assert out["actions"]["publish"] == {"available": False,
                                         "reason": "shop's load balancer isn't made yet: deploy first"}
    assert await _jobs() == []


# ------------------------------------------------------------------------ F17: Retire waits for every job


async def _running_activate(env: dof.DoEnv) -> Deployment:
    async with get_sessionmaker()() as db:
        act = Deployment(instance_id=None, environment_id=env.env_id, kind="activate", status="queued",
                         branch="main", steps=[{"key": "check", "status": "pending"},
                                               {"key": "switch", "status": "pending"}],
                         options={"slot": "green", "confirm": "prod", "from_slot": "blue"})
        db.add(act)
        await db.commit()
        return act


async def test_f17_retire_and_unretire_are_refused_while_a_job_is_queued_or_running(w):
    env = await prod(w)
    await built(env, "blue")
    await built(env, "green")
    await set_rows(Environment, env.env_id, active_slot_id=env.ids["blue"], status="live")
    act = await _running_activate(env)
    url = f"{API}/{env.env_id}"
    busy = "A job is already running for prod (Activate on green); wait for it to finish"
    out = (await w.admin.get(url)).json()
    assert out["actions"]["retire"] == {"available": False, "reason": busy}
    resp = await w.admin.post(f"{url}/retire", json={"confirm": "prod"})
    assert (resp.status_code, resp.json()["detail"]) == (409, busy)
    found = await _env_obj(env.env_id)
    assert found.retiring_at is None
    async with get_sessionmaker()() as db:
        assert list(await db.scalars(select(AuditEvent).where(AuditEvent.action == "environment.retire"))) == []
    await set_rows(Deployment, act.id, status="running")
    resp = await w.admin.post(f"{url}/retire", json={"confirm": "prod"})
    assert (resp.status_code, resp.json()["detail"]) == (409, busy)

    # Un-retire waits the same way.
    await set_rows(Deployment, act.id, status="failed")
    resp = await w.admin.post(f"{url}/retire", json={"confirm": "prod"})
    assert resp.status_code == 200, resp.text
    await _running_activate(env)
    out = (await w.admin.get(url)).json()
    assert out["actions"]["unretire"] == {"available": False, "reason": busy}
    resp = await w.admin.request("DELETE", f"{url}/retire", json={"confirm": "prod"})
    assert (resp.status_code, resp.json()["detail"]) == (409, busy)
    assert (await _env_obj(env.env_id)).retiring_at is not None


# ----------------------------------------------------------------- F18: production runs Blue and Green


async def test_f18_remove_slot_of_a_production_that_isnt_retiring_is_refused(w, submitted):  # noqa: F811
    env = await prod(w)
    await built(env, "blue")
    await built(env, "green")
    await set_rows(Environment, env.env_id, active_slot_id=env.ids["blue"], status="live")
    url = f"{API}/{env.env_id}/slots/green"
    resp = await w.admin.request("DELETE", url, json={"confirm": "prod"})
    assert (resp.status_code, resp.json()["detail"]) == (409, "Production runs Blue and Green: retire prod first")
    assert await _jobs() == [] and submitted == []
    # A retiring one may drop its idle slot on the way out.
    await set_rows(Environment, env.env_id, retiring_at=datetime.now(UTC))
    resp = await w.admin.request("DELETE", url, json={"confirm": "prod"})
    assert resp.status_code == 202, resp.text
    assert resp.json()["kind"] == "remove_slot"


# ------------------------------------------------------- F38: Continue of a stopped production Delete chain


async def test_f38_continue_of_a_stopped_production_delete_is_offered(w):
    env = await prod(w)
    await built(env, "blue")
    await built(env, "green")
    await set_rows(Instance, env.ids["data"], fresh_data="seeded")  # it holds data
    await set_rows(Environment, env.env_id, retiring_at=datetime.now(UTC), status="live")
    async with get_sessionmaker()() as db:
        snap = Deployment(instance_id=env.ids["data"], environment_id=env.env_id, kind="snapshot", status="succeeded",
                          branch="main", steps=[], finished_at=datetime.now(UTC),
                          options={"then": "teardown", "then_options": {"confirm_production": "delete production prod"}})
        db.add(snap)
        await db.flush()
        e = await db.get(Environment, env.env_id)
        e.notice = {"text": "Slipway stopped", "at": "x", "deployment_id": snap.id.hex,
                    "next": {"kind": "teardown", "slot": None}}
        await db.commit()
    out = (await w.admin.get(f"{API}/{env.env_id}")).json()
    assert out["actions"]["continue"] == {"available": True, "reason": None, "kind": "teardown", "slot": None,
                                          "needs_confirm": False}
    resp = await w.admin.post(f"{API}/{env.env_id}/notice/continue")
    assert resp.status_code == 202, resp.text
    assert resp.json()["kind"] == "teardown"


async def test_f38_a_notice_whose_job_names_no_follow_up_keeps_the_old_check(w):
    env = await prod(w)
    await built(env, "blue")
    await built(env, "green")
    await set_rows(Instance, env.ids["data"], fresh_data="seeded")
    await set_rows(Environment, env.env_id, retiring_at=datetime.now(UTC), status="live")
    async with get_sessionmaker()() as db:
        e = await db.get(Environment, env.env_id)
        e.notice = {"text": "Slipway stopped", "at": "x", "deployment_id": None,
                    "next": {"kind": "teardown", "slot": None}}
        await db.commit()
    out = (await w.admin.get(f"{API}/{env.env_id}")).json()
    assert out["actions"]["continue"] == {"available": False, "kind": "teardown", "slot": None, "needs_confirm": False,
                                          "reason": "A production environment is deleted only after a snapshot"}
