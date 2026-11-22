"""Review fixes (phase 3, group 1): how Slipway counts its own staged Switchyard edits, and how Activate's
put-back, DNS, seed and Resolve steps behave (findings F1, F15, F16, F36, F37, F41, F44, F47, F57).

The traffic-level tests use tests/test_traffic.py's environment (blue live on 10.0.0.11, green on 10.0.0.12)
and tests/fake_switchyard.py; ``live`` keeps a copy of the hosts as Caddy serves them, taken at each apply.
The job-level tests use tests/test_env_jobs.py's fake hosts.
"""

from __future__ import annotations

import asyncio
import copy

import httpx
import pytest
from sqlalchemy import select, update

from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Environment, Host, Instance, Repository
from slipway.services import cloudflare, deployer, env_jobs, environments, switchyard, traffic
from tests import fake_switchyard
from tests.fake_cloudflare import FakeCloudflare
from tests.fake_hosts import MultiRemote
from tests.test_env_jobs import SWITCHYARD, Sites, _job, _upstream
from tests.test_env_pipeline import _get, _live_env, _steps
from tests.test_traffic import (
    APP_ROUTES,
    DNS,
    TRAFFIC_ADDRESS,
    FakeSites,
    _app_state,
    _blue_live,
    _cloudflare,
    _ctx,
    _env,
    _env_obj,
    _expected,
    _published,
    _rows,
    _slot,
    _state,
    _upstreams,
)

GREEN = "10.0.0.12"


# ----------------------------------------------------------------------------------- fixtures


@pytest.fixture(autouse=True)
def no_waits(monkeypatch):
    async def instantly(_seconds):
        return None
    monkeypatch.setattr(traffic, "sleep", instantly)


@pytest.fixture
def fake(monkeypatch):
    return fake_switchyard.install(monkeypatch)


@pytest.fixture
def tsites(monkeypatch):
    s = FakeSites()
    monkeypatch.setattr(traffic, "transport_factory", s.factory)
    return s


@pytest.fixture
async def configured(fake, tsites):
    await fake_switchyard.configure(traffic_address=TRAFFIC_ADDRESS)
    return fake


@pytest.fixture
def cf(monkeypatch):
    f = FakeCloudflare()
    monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(f.handle))
    return f


@pytest.fixture
def multi(tmp_path):
    return MultiRemote(tmp_path)


@pytest.fixture
def submitted(monkeypatch):
    found: list = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, keys: found.append((dep_id, keys)))
    return found


@pytest.fixture
def job_sites(monkeypatch) -> Sites:
    s = Sites()
    monkeypatch.setattr(traffic, "transport_factory", s.factory)
    return s


@pytest.fixture
async def job_sy(monkeypatch, job_sites):
    f = fake_switchyard.install(monkeypatch)
    await fake_switchyard.configure(traffic_address=TRAFFIC_ADDRESS)
    return f


# ------------------------------------------------------------------------------------ helpers


def _track(fake, monkeypatch, handle=None):
    """Keep ``live``: the hosts as Caddy serves them, copied at each successful apply."""
    live = {"hosts": copy.deepcopy(fake.hosts)}
    inner = handle or fake.handle

    def tracked(request):
        resp = inner(request)
        if request.url.path == "/api/config/apply" and resp.status_code == 200:
            live["hosts"] = copy.deepcopy(fake.hosts)
        return resp

    monkeypatch.setattr(switchyard, "transport_factory", lambda: httpx.MockTransport(tracked))
    return live


def _live(live) -> dict[str, str]:
    return {d: f"{h['upstreams'][0]['host']}:{h['upstreams'][0]['port']}"
            for h in live["hosts"].values() for d in h.get("domains") or []}


def _on_green(live) -> list[str]:
    return sorted(name for name, up in _live(live).items() if up.startswith(GREEN))


async def _quiet(_line):
    return None


async def _shop(name="shop") -> Instance:
    """A standalone instance with one hostname, on the blue host."""
    async with get_sessionmaker()() as db:
        host = await db.scalar(select(Host).where(Host.name == "blue"))
        repo = await db.scalar(select(Repository))
        db.add(Instance(name=name, slug=name, repository_id=repo.id, host_id=host.id, branch="main",
                        ports=[{"host": 8080, "container": 3000, "protocol": "tcp"}],
                        routes=[{"hostname": f"{name}.example.com", "service": None, "container": 3000,
                                 "tls_mode": "auto"}]))
        await db.commit()
    async with get_sessionmaker()() as db:
        return await db.scalar(select(Instance).where(Instance.slug == name))


async def _green_routes(env_id, routes) -> None:
    green = await _slot(env_id, "green")
    async with get_sessionmaker()() as db:
        await db.execute(update(Instance).where(Instance.id == green.id).values(
            app_state=_app_state(routes), published_ports=_published("green", routes)))
        await db.commit()


def _down_after_second_put(fake, monkeypatch):
    """Switchyard answers 503 to everything once the switch's second PUT has landed."""
    state = {"down": False, "puts": 0}

    def handle(request):
        if state["down"]:
            return httpx.Response(503, json={"error": "down", "message": "Switchyard is restarting"})
        resp = fake.handle(request)
        if request.method == "PUT":
            state["puts"] += 1
            if state["puts"] == 2:
                state["down"] = True
        return resp

    return _track(fake, monkeypatch, handle), state


# ------------------------------------------------------------------------- F1: held edits


@pytest.mark.parametrize("who", ["data_server_sync", "standalone_instance"])
async def test_a_half_written_switch_is_never_applied_by_a_later_sync(configured, monkeypatch, who):
    fake = configured
    env_id = await _blue_live(fake)
    live, state = _down_after_second_put(fake, monkeypatch)
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(env_id, "activate", "green"))
    assert err.value.unresolved
    assert _upstreams(fake)["api.uat.example.com"].startswith(GREEN)  # two hosts staged on green
    saved = await switchyard.load_edits()
    assert saved["edits"] == 2 and saved["held"] == {str(env_id): 2}
    state["down"] = False
    applies = list(fake.applies)

    if who == "data_server_sync":
        result = await traffic.sync(await _ctx(env_id, "sync", include_active=False))
        assert any(switchyard.HELD in w for w in result.warnings), result.warnings
    else:
        lines: list[str] = []

        async def say(line):
            lines.append(line)

        entries = await switchyard.sync(await _shop(), say=say)
        assert entries[0]["state"] == "staged" and any(switchyard.HELD in line for line in lines), lines
    assert fake.applies == applies  # nothing was applied
    assert _on_green(live) == [] and _live(live) == _expected("blue")

    # Activate (blue again) may take the held edits live: it rewrites every name and checks them.
    await traffic.switch(await _ctx(env_id, "activate", "blue"))
    assert _live(live)["api.uat.example.com"] == _expected("blue")["api.uat.example.com"]
    assert _on_green(live) == []
    assert "held" not in await switchyard.load_edits()


async def test_recovery_holds_what_a_cut_off_switch_staged(configured, monkeypatch):
    fake = configured
    env_id = await _blue_live(fake)
    live = _track(fake, monkeypatch)
    # A switch cut off by a restart after two writes: both staged, counted as Slipway's.
    api = fake.hosts_by_domain()["api.uat.example.com"]
    auth = fake.hosts_by_domain()["auth.uat.example.com"]
    for host in (api, auth):
        host["upstreams"] = [{**host["upstreams"][0], "host": GREEN}]
        fake.someone_edits()
    await switchyard.save_edits({"version": fake.version, "edits": 2})
    async with get_sessionmaker()() as db:
        dep = Deployment(environment_id=env_id, kind="activate", branch="main", status="running", log="",
                         options={"slot": "green", "switch": {"from_slot": "blue", "to_slot": "green", "changed": [
                             {"hostname": "api.uat.example.com", "id": str(api["id"])}]}},
                         steps=[{"key": "switch", "name": "Switch", "status": "running", "started_at": "x"}])
        db.add(dep)
        await db.commit()
    await deployer.runner.recover_interrupted()
    assert (await _state(env_id))["unresolved"]["message"] == env_jobs.RESTARTED
    assert (await switchyard.load_edits())["held"] == {str(env_id): 2}
    await switchyard.sync(await _shop(), say=_quiet)
    await traffic.sync(await _ctx(env_id, "sync", include_active=False))
    assert _on_green(live) == []


# --------------------------------------------------------- F15: a partial put-back that never went live


async def test_a_partial_put_back_is_not_applied_when_nothing_went_live(configured, monkeypatch):
    fake = configured
    env_id = await _blue_live(fake)
    live = _track(fake, monkeypatch)
    fake.apply_fails_once()
    fake.fail_on = {("PUT", fake.counts.get("PUT", 0) + 6): 500}  # five for the switch, then wiki's undo
    applies = list(fake.applies)
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(env_id, "activate", "green"))
    assert err.value.unresolved and "wiki.uat.example.com" in str(err.value)
    assert fake.applies == applies  # neither the switch's apply nor a put-back apply went through
    assert _live(live) == _expected("blue")  # Caddy still serves blue for every name
    assert (await _state(env_id))["unresolved"] is not None
    assert (await switchyard.load_edits())["held"] == {str(env_id): 9}  # five writes, four undos


async def test_resolve_refuses_a_slot_whose_name_has_no_host(configured):
    """Green drops wiki; the switch deletes wiki's host and making it again fails. Once someone applies in
    Switchyard, Resolve must not settle on blue while blue's wiki has no host."""
    fake = configured
    env_id = await _blue_live(fake)
    await _green_routes(env_id, [r for r in APP_ROUTES if r[0] != "wiki.uat.example.com"])
    fake.apply_fails_once()
    fake.fail_on = {("POST", fake.counts.get("POST", 0) + 2): 500}  # the failing apply, then re-making wiki
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(env_id, "activate", "green"))
    assert err.value.unresolved
    fake.version += 1  # someone applies in Switchyard
    fake.changes = 0
    with pytest.raises(env_jobs.ResolveRefused) as refused:
        await env_jobs.resolve(env_id)
    assert refused.value.status == 409 and "wiki.uat.example.com" in refused.value.text
    assert "activate blue" in refused.value.text
    assert (await _state(env_id))["unresolved"] is not None
    # Activating blue makes wiki's host again; Resolve then has nothing left to settle.
    await traffic.switch(await _ctx(env_id, "activate", "blue"))
    assert _upstreams(fake) == _expected("blue")


# ---------------------------------------------------------------- F16: an apply in Switchyard mid-switch


async def test_an_apply_in_switchyard_mid_switch_leaves_the_switch_unresolved(configured, monkeypatch):
    fake = configured
    env_id = await _blue_live(fake)
    live = _track(fake, monkeypatch)

    def they_apply(f):
        f.version += 1
        f.changes = -1  # someone_edits() adds one back: nothing pending right after their apply
        live["hosts"] = copy.deepcopy(f.hosts)

    fake.someone_edits_after("PUT /api/hosts", they_apply, n=1)
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(env_id, "activate", "green"))
    assert err.value.unresolved, str(err.value)
    assert "Traffic stays on blue" not in str(err.value) and "api.uat.example.com" in str(err.value)
    assert (await _state(env_id))["unresolved"] is not None
    assert _live(live)["api.uat.example.com"].startswith(GREEN)  # their apply took the first write live
    assert _upstreams(fake) == _expected("blue")  # every host is back in Switchyard, waiting for an apply
    # Slipway counts only the undos at the new version (it can't tell which writes came after that apply),
    # all held: no apply of Slipway's takes someone else's change live, or the put-back live unchecked.
    saved = await switchyard.load_edits()
    assert saved["version"] == fake.version and saved["edits"] == 5 and saved["held"] == {str(env_id): 5}
    assert fake.changes > saved["edits"]
    await switchyard.sync(await _shop(), say=_quiet)
    assert _live(live)["api.uat.example.com"].startswith(GREEN) and "shop.example.com" not in _live(live)


async def test_an_apply_in_switchyard_after_the_last_write_is_put_back_and_applied(configured, monkeypatch):
    fake = configured
    env_id = await _blue_live(fake)
    live = _track(fake, monkeypatch)

    def they_apply(f):
        f.version += 1
        f.changes = -1
        live["hosts"] = copy.deepcopy(f.hosts)

    fake.someone_edits_after("PUT /api/hosts", they_apply, n=5)  # after the switch's last write
    with pytest.raises(traffic.SwitchFailed, match="Traffic stays on blue") as err:
        await traffic.switch(await _ctx(env_id, "activate", "green"))
    assert not err.value.unresolved
    assert fake.applies[-1] == "Slipway: put back uat" and _live(live) == _expected("blue")
    assert fake.changes == 0 and (await switchyard.load_edits())["edits"] == 0


# ----------------------------------------------------------- F36: a create whose answer is lost


async def _docs_env(fake):
    env_id = await _blue_live(fake)
    await _green_routes(env_id, APP_ROUTES + [("docs.uat.example.com", "docs", 4000, "/")])
    return env_id


def _post_lands_then_504(fake, *, times=1, list_fails_once=False):
    state = {"left": times, "list_fails": False}

    def handle(request):
        if state["list_fails"] and request.method == "GET" and request.url.path == "/api/hosts":
            state["list_fails"] = False
            return httpx.Response(503, json={"error": "down", "message": "Switchyard is busy"})
        resp = fake.handle(request)
        if request.method == "POST" and request.url.path == "/api/hosts" and state["left"]:
            state["left"] -= 1
            state["list_fails"] = list_fails_once
            return httpx.Response(504, json={"error": "timeout", "message": "Gateway timeout"})
        return resp

    return handle


async def test_a_create_that_lands_but_errors_is_recorded_and_counted(configured, monkeypatch):
    fake = configured
    env_id = await _docs_env(fake)
    _track(fake, monkeypatch, _post_lands_then_504(fake))
    await traffic.switch(await _ctx(env_id, "activate", "green"))
    docs = fake.hosts_by_domain()["docs.uat.example.com"]
    assert (await _rows(env_id))["docs.uat.example.com"].provider_id == str(docs["id"])
    assert fake.applies[-1] == "Slipway: uat → green" and fake.changes == 0


async def test_a_create_that_lands_but_errors_is_put_back(configured, monkeypatch, tsites):
    fake = configured
    env_id = await _docs_env(fake)
    _track(fake, monkeypatch, _post_lands_then_504(fake, times=99))
    tsites.codes = {"api.uat.example.com": [502]}  # the check fails: everything is put back
    with pytest.raises(traffic.SwitchFailed, match="Traffic stays on blue"):
        await traffic.switch(await _ctx(env_id, "activate", "green"))
    assert "docs.uat.example.com" not in fake.hosts_by_domain()
    assert _upstreams(fake) == _expected("blue") and fake.changes == 0
    assert "docs.uat.example.com" not in await _rows(env_id)


async def test_a_create_whose_answer_and_reread_fail_is_found_by_the_put_back(configured, monkeypatch):
    fake = configured
    env_id = await _docs_env(fake)
    _track(fake, monkeypatch, _post_lands_then_504(fake, list_fails_once=True))
    with pytest.raises(traffic.SwitchFailed, match="Traffic stays on blue") as err:
        await traffic.switch(await _ctx(env_id, "activate", "green"))
    assert not err.value.unresolved
    assert "docs.uat.example.com" not in fake.hosts_by_domain()
    assert _upstreams(fake) == _expected("blue")
    # The create and its undoing were both counted, so the put-back could be applied and nothing is left.
    assert fake.applies[-1] == "Slipway: put back uat" and fake.changes == 0
    assert (await switchyard.load_edits())["edits"] == 0


# ------------------------------------------------------------------------------ DNS (F44, F41)


async def test_a_covered_name_forgets_its_stale_row(cf):
    zid = await _cloudflare(cf)
    env_id = await _env(dns=DNS, switch="none")
    await traffic.publish_dns(await _env_obj(env_id))
    (rec,) = cf.named("api.uat.example.com")
    del cf.records[rec["id"]]
    cf.add_record(zid, "A", "*.uat.example.com", "203.0.113.7")
    plan = await traffic.publish_dns(await _env_obj(env_id))
    assert {c.hostname: c for c in plan.changes}["api.uat.example.com"].status == "covered"
    assert "api.uat.example.com" not in await _rows(env_id, cloudflare.PROVIDER, cloudflare.KIND)
    plan = await traffic.publish_dns(await _env_obj(env_id))  # and it stays covered, with no row
    assert {c.hostname: c for c in plan.changes}["api.uat.example.com"].stale_row is None


async def test_a_name_without_a_usable_record_counts_as_one_to_create(cf):
    zid = await _cloudflare(cf)
    env_id = await _env(dns=DNS, switch="none")
    await traffic.publish_dns(await _env_obj(env_id))
    assert await env_jobs._dns_creates(await _env_obj(env_id)) is False
    # A record Slipway recorded renamed in Cloudflare: the name has none (a conflict, not a create).
    (rec,) = cf.named("api.uat.example.com")
    cf.records[rec["id"]]["name"] = "api-old.uat.example.com"
    assert cf.named("api.uat.example.com") == []
    assert await env_jobs._dns_creates(await _env_obj(env_id)) is True
    cf.records[rec["id"]]["name"] = "api.uat.example.com"
    # A second A record next to Slipway's: a conflict, but the name still reaches the address.
    cf.add_record(zid, "A", "api.uat.example.com", "198.51.100.9")
    assert await env_jobs._dns_creates(await _env_obj(env_id)) is False


async def test_a_name_with_only_a_foreign_record_counts_as_one_to_create(cf):
    zid = await _cloudflare(cf)
    env_id = await _env(dns=DNS, switch="none")
    cf.add_record(zid, "A", "learn.uat.example.com", "198.51.100.9")  # claimable, pointing elsewhere
    for name, *_ in APP_ROUTES + [("spaces.uat.example.com",)]:
        if name != "learn.uat.example.com":
            cf.add_record(zid, "A", name, "203.0.113.7")  # claimable, at the address
    async with get_sessionmaker()() as db:
        plan = await traffic.dns_plan(await _env_obj(env_id), db)
    assert plan.creates == [] and plan.meta["unpublished"] == ["learn.uat.example.com"]
    assert await env_jobs._dns_creates(await _env_obj(env_id)) is True


# --------------------------------------------------------------------- F47: the first seed fails


async def test_a_seed_that_raises_leaves_the_starter_content_pending(multi, submitted, job_sy, monkeypatch):
    seeded = await _live_env(multi, active=None, traffic=SWITCHYARD, seed_content=True)

    async def broken(*a, **kw):
        raise deployer.DeployError("The live release on blue-host isn't the one Slipway recorded")

    monkeypatch.setattr(deployer, "_live_plan", broken)
    dep = await _job(multi, seeded, "activate", slot="blue")
    assert dep.status == "succeeded" and _steps(dep)["seed"] == "warning", (dep.error, dep.log)
    assert (await _get(Instance, seeded.ids["data"])).content_pending is True


# ---------------------------------------------------------------------- F57: step time limits


async def test_a_step_past_its_time_limit_fails_the_job(multi, submitted, job_sy, monkeypatch):
    seeded = await _live_env(multi, active="blue", traffic=SWITCHYARD)
    monkeypatch.setitem(environments.ENV_STEP_TIMEOUTS, "smoke", 0.2)

    async def hang(*a, **kw):
        await asyncio.sleep(30)

    monkeypatch.setattr(traffic, "smoke", hang)
    dep = await _job(multi, seeded, "activate", slot="green")
    assert dep.status == "failed" and _steps(dep)["smoke"] == "failed" and _steps(dep)["switch"] == "pending"
    assert dep.error == "It took longer than 0.2 seconds and was stopped"


async def test_a_switch_past_its_time_limit_is_put_back(multi, submitted, job_sy, job_sites, monkeypatch):
    seeded = await _live_env(multi, active="blue", traffic=SWITCHYARD)
    blue = {d: _upstream(job_sy, d) for d in job_sy.hosts_by_domain()}
    monkeypatch.setitem(environments.ENV_STEP_TIMEOUTS, "switch", 0.5)

    async def hang(hostname):
        await asyncio.sleep(30)

    job_sites.hook = hang  # the check through Switchyard never answers
    dep = await _job(multi, seeded, "activate", slot="green")
    assert dep.status == "failed" and _steps(dep)["switch"] == "failed", (dep.error, dep.log)
    assert dep.error.startswith("It took longer than 0.5 seconds and was stopped"), dep.error
    assert {d: _upstream(job_sy, d) for d in job_sy.hosts_by_domain()} == blue  # the put-back ran
    assert job_sy.applies[-1] == "Slipway: put back uat"
    env = await _get(Environment, seeded.env_id)
    assert env.active_slot_id == seeded.ids["blue"] and not (env.traffic_state or {}).get("unresolved")



@pytest.mark.skipif(not hasattr(cloudflare, "ADOPT"), reason="plan_dns plans no adoptable records")
async def test_a_record_slipway_made_but_never_recorded_is_adopted(cf):
    zid = await _cloudflare(cf)
    env_id = await _env(dns=DNS, switch="none")
    comment = cloudflare.comment_for("uat", env_id)
    made = cf.add_record(zid, "A", "api.uat.example.com", "198.51.100.1", comment=comment)
    plan = await traffic.publish_dns(await _env_obj(env_id))
    assert {c.hostname: c for c in plan.changes}["api.uat.example.com"].status == cloudflare.ADOPT
    row = (await _rows(env_id, cloudflare.PROVIDER, cloudflare.KIND))["api.uat.example.com"]
    assert row.provider_id == str(made["id"]) and row.origin == "created"
    assert [r["content"] for r in cf.named("api.uat.example.com")] == ["203.0.113.7"]
    plan = await traffic.publish_dns(await _env_obj(env_id))
    assert {c.hostname: c for c in plan.changes}["api.uat.example.com"].status == "ok"
