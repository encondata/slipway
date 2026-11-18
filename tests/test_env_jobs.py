"""Phase 3 S8b: the jobs of a whole environment through the real deployer and ``env_jobs``: Activate and Switch
back, an unresolved switch and Resolve, Publish names, Discard, Remove a slot, Delete, and recovery after a
restart (tests 45-51, 67, 68).

The data server, blue and green are three fake hosts whose commands run in a real shell (tests/fake_hosts.py).
Switchyard and Cloudflare are their fakes; the check through Switchyard's traffic address talks to ``Sites``.
Nothing here mocks env_jobs or the deployer.
"""

from __future__ import annotations

import asyncio
import uuid

import httpx
import pytest
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from slipway.db.session import get_sessionmaker
from slipway.models import (
    AppSetting,
    AuditEvent,
    Deployment,
    Environment,
    Host,
    Instance,
    Resource,
    Snapshot,
    User,
)
from slipway.services import cloudflare, data, deployer, env_jobs, environments, jobs, resources, switchyard, traffic
from tests import fake_switchyard
from tests.fake_cloudflare import ZONE, FakeCloudflare
from tests.fake_hosts import MultiRemote, Seeded, configure_cloudflare, queue, seed_env
from tests.test_env_pipeline import (
    _backups,
    _containers,
    _deploy,
    _failed_green,
    _get,
    _live_env,
    _note,
    _owner_job,
    _set,
    _steps,
)

TRAFFIC_ADDRESS = "10.0.0.2"
WWW = "www.uat.example.com"
FILES = "files.uat.example.com"


class Sites:
    """What the check through Switchyard's traffic address reaches: a code per hostname (default 200)."""

    def __init__(self) -> None:
        self.codes: dict[str, int] = {}
        self.asked: list[str] = []
        self.hook = None  # async callable(hostname), run before answering

    def factory(self, verify: bool) -> httpx.MockTransport:
        async def handle(request: httpx.Request) -> httpx.Response:
            host = request.headers["host"]
            self.asked.append(host)
            if self.hook is not None:
                await self.hook(host)
            return httpx.Response(self.codes.get(host, 200))

        return httpx.MockTransport(handle)


@pytest.fixture
def multi(tmp_path):
    return MultiRemote(tmp_path)


@pytest.fixture(autouse=True)
def no_waits(monkeypatch):
    async def instantly(_seconds):
        return None
    monkeypatch.setattr(traffic, "sleep", instantly)


@pytest.fixture
def submitted(monkeypatch) -> list[tuple[uuid.UUID, tuple]]:
    """Jobs the chain queues are recorded, not run."""
    found: list[tuple[uuid.UUID, tuple]] = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, keys: found.append((dep_id, keys)))
    return found


@pytest.fixture
def sites(monkeypatch) -> Sites:
    s = Sites()
    monkeypatch.setattr(traffic, "transport_factory", s.factory)
    return s


@pytest.fixture
async def sy(monkeypatch, sites):
    fake = fake_switchyard.install(monkeypatch)
    await fake_switchyard.configure(traffic_address=TRAFFIC_ADDRESS)
    return fake


@pytest.fixture
async def cf(monkeypatch):
    fake = FakeCloudflare()
    fake.add_zone(ZONE)
    monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(fake.handle))
    await configure_cloudflare()
    return fake


SWITCHYARD = {"switch": "switchyard", "dns": None}
DNS = {"provider": "cloudflare", "address": None, "proxied": False}


# ------------------------------------------------------------------------------------ helpers


async def _queue(seeded: Seeded, kind: str, *, raw: bool = False, retry_of: uuid.UUID | None = None,
                 **options) -> uuid.UUID:
    """An environment-level job: through ``jobs.queue_job`` (its refusals), or ``raw`` as a row with its steps,
    so the job's own ``check`` meets what the queue would have refused."""
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, seeded.env_id)
        user = await db.get(User, seeded.user_id)
        if raw:
            mem = await environments.members(db, env)
            dep = Deployment(instance_id=None, environment_id=env.id, kind=kind, branch=env.branch, options=options,
                             triggered_by_id=user.id, log="", retry_of_id=retry_of,
                             steps=environments.env_steps_for(env, kind, options, mem))
            db.add(dep)
        else:
            parent = await db.get(Deployment, retry_of) if retry_of is not None else None
            dep = await jobs.queue_job(db, environment=env, user=user, kind=kind, options=options, retry_of=parent)
        await db.commit()
        return dep.id


async def _run(multi: MultiRemote, dep_id: uuid.UUID) -> Deployment:
    await deployer.run_deployment(dep_id, connect=multi.connect)
    return await _get(Deployment, dep_id)


async def _job(multi: MultiRemote, seeded: Seeded, kind: str, **kw) -> Deployment:
    return await _run(multi, await _queue(seeded, kind, **kw))


def _writes(fake) -> list:
    return [c for c in fake.api_calls() if c.method != "GET"]


async def _audits(action: str) -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        return list((await db.scalars(select(AuditEvent).where(AuditEvent.action == action))).all())


def _upstream(fake, hostname: str) -> str:
    host = fake.hosts_by_domain()[hostname]
    return f"{host['upstreams'][0]['host']}:{host['upstreams'][0]['port']}"


async def _target(seeded: Seeded, slot: str, hostname: str = WWW) -> str:
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, seeded.env_id)
        mem = await environments.members(db, env)
    route = next(r for r in traffic.routes(env, mem[slot], mem.get("data")) if r.hostname == hostname)
    return traffic.target(route, mem[slot]).upstream


# ------------------------------------------------------------------------ test 45: Activate


async def test_activate_refuses_before_anything_changes(multi, submitted, sy):
    seeded = await _live_env(multi, active="blue", traffic=SWITCHYARD)
    green_id, data_id = seeded.ids["green"], seeded.ids["data"]
    green = await _get(Instance, green_id)

    async def failed_deploy():
        async with get_sessionmaker()() as db:
            dep = Deployment(instance_id=green_id, environment_id=seeded.env_id, kind="deploy", branch="main",
                             log="", status="failed", error="boom")
            db.add(dep)
            await db.commit()
        return dep.id

    blocker = {}

    async def foreign_host():
        blocker["host"] = sy.add(domains=[WWW], notes="")["id"]

    async def unconfigured():
        async with get_sessionmaker()() as db:
            await db.execute(delete(AppSetting).where(AppSetting.key == switchyard.SETTING_KEY))
            await db.commit()

    async def queued_deploy():
        blocker["queued"] = await queue(seeded, "green", status="queued", options={"slot": "green"})

    cases = [
        ("data", None, "Only an app slot can take traffic"),
        ("blue", None, "blue already takes the traffic"),
        ("green", lambda: _set(Instance, green_id, current_commit_sha=None), "Deploy to green first"),
        ("green", failed_deploy, "green's latest deploy ("),
        ("green", lambda: _set(Instance, green_id, slot_state={"stale": {
            "reason": "Stopped when uat's data was restored; deploy to it before activating it"}}),
         "green was stopped when uat's data was restored; deploy to it first"),
        ("green", lambda: _set(Instance, data_id, data_dirty={"first": {"deployment_id": "ab12cd34" * 4,
                                                                        "kind": "deploy"}, "hold": False}),
         "uat's data may not be what green expects since deployment ab12cd34 failed: discard or retry it first"),
        ("green", lambda: _set(Instance, data_id, data_dirty={"first": {"kind": "restore"}, "last": {
            "kind": "restore"}, "hold": True}), "uat's last restore stopped part-way"),
        ("green", lambda: _set(Host, seeded.host_ids["green"], host_key=None),
         "Host green-host has not been verified yet; run a connection check first"),
        ("green", queued_deploy, "A job is already running for uat (Deploy on green); wait for it to finish"),
        ("green", unconfigured, "Set up Switchyard in Settings → Integrations first"),
        ("green", foreign_host, f"{WWW} is used by Switchyard host #"),
    ]
    for slot, change, text in cases:
        if change is not None:
            made = await change()
        writes = len(_writes(sy))
        multi.clear()
        dep = await _job(multi, seeded, "activate", raw=True, slot=slot)
        assert dep.status == "failed" and text in dep.error, (slot, text, dep.error)
        assert _steps(dep)["check"] == "failed" and set(list(_steps(dep).values())[1:]) == {"pending"}
        assert len(_writes(sy)) == writes and not multi["green"].docker() and not multi["green"].calls()
        env = await _get(Environment, seeded.env_id)
        assert env.active_slot_id == seeded.ids["blue"]
        # Put things back for the next case.
        await _set(Instance, green_id, current_commit_sha=green.current_commit_sha, slot_state={})
        await _set(Instance, data_id, data_dirty=None)
        await _set(Host, seeded.host_ids["green"], host_key="ssh-ed25519 AAAA")
        if change is failed_deploy:
            async with get_sessionmaker()() as db:
                await db.execute(delete(Deployment).where(Deployment.id == made))
                await db.commit()
        if "queued" in blocker:
            async with get_sessionmaker()() as db:
                await db.execute(delete(Deployment).where(Deployment.id == blocker.pop("queued")))
                await db.commit()
        if "host" in blocker:
            sy.hosts.pop(blocker.pop("host"))
        if change is unconfigured:
            await fake_switchyard.configure(traffic_address=TRAFFIC_ADDRESS)
    assert blocker == {}


async def test_activate_publishes_dns_switches_and_records_the_slot_only_after_the_check(
        multi, submitted, monkeypatch, sy, cf, sites):
    seeded = await _live_env(multi, active=None, traffic=SWITCHYARD, seed_content=True)
    # DNS publishing goes on now, so this activate has both records to create.
    await _set(Environment, seeded.env_id, traffic={**SWITCHYARD, "dns": DNS})
    at_post: list[int] = []

    def handle(request):
        if request.method == "POST" and request.url.path == "/api/hosts":
            at_post.append(len(cf.records))
        return sy.handle(request)

    monkeypatch.setattr(switchyard, "transport_factory", lambda: httpx.MockTransport(handle))
    during: list = []

    async def hook(hostname):
        during.append((await _get(Environment, seeded.env_id)).active_slot_id)

    sites.hook = hook
    dep_id = await _queue(seeded, "activate", slot="blue")
    dep = await _run(multi, dep_id)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert list(_steps(dep)) == ["check", "smoke", "dns", "switch", "seed"]
    assert _steps(dep) == {"check": "succeeded", "smoke": "succeeded", "dns": "succeeded", "switch": "succeeded",
                           "seed": "succeeded"}
    assert dep.log.index("Checking the names through Switchyard") < dep.log.index("blue now takes uat's traffic")
    # dns before switch: both records existed when the app name's host was made.
    assert at_post == [2] and {r["name"] for r in cf.records.values()} == {WWW, FILES}
    # The check ran through Switchyard while the active slot was still unset.
    assert during and set(during) == {None} and WWW in sites.asked
    env = await _get(Environment, seeded.env_id)
    assert env.active_slot_id == seeded.ids["blue"] and env.status == "live"
    assert env.traffic_state["last"]["to_slot"] == "blue" and env.traffic_state["last"]["from_slot"] is None
    assert env.traffic_state["unresolved"] is None
    assert _upstream(sy, WWW) == await _target(seeded, "blue")
    # Starter content after the switch, on blue (the slot that went live), on the shared data.
    assert any(c.startswith("seed ") for c in multi["blue"].calls())
    assert (multi["data"].folder("uat-data") / "state" / "db").read_text().endswith("SEEDED\n")
    assert dep.log.index("blue now takes") < dep.log.rindex("$ cd ")
    [row] = await _audits("environment.activate")
    assert row.details["to"] == "blue" and row.details["deployment"] == dep.id.hex
    assert (await _get(Instance, seeded.ids["blue"])).slot_state["last_check"]["ok"] is True


async def test_a_failing_smoke_changes_nothing(multi, submitted, sy):
    seeded = await _live_env(multi, active="blue", traffic=SWITCHYARD)
    multi["green"].env["FAKE_HTTP_CODES"] = f"{WWW}=502"
    writes = len(_writes(sy))
    dep = await _job(multi, seeded, "activate", slot="green")
    assert dep.status == "failed" and _steps(dep)["smoke"] == "failed"
    assert dep.error == f"{WWW} answered 502 on /healthz (5 tries). Nothing has changed"
    assert multi["green"].log("CURL_LOG").count(WWW) == 5
    assert len(_writes(sy)) == writes
    assert (await _get(Environment, seeded.env_id)).active_slot_id == seeded.ids["blue"]
    assert (await _get(Instance, seeded.ids["green"])).slot_state["last_check"]["ok"] is False


async def test_a_dns_failure_stops_the_switch_only_when_a_record_must_be_made(multi, submitted, sy, cf):
    seeded = await _live_env(multi, active=None, traffic=SWITCHYARD)
    await _set(Environment, seeded.env_id, traffic={**SWITCHYARD, "dns": DNS})
    cf.deny = {"POST"}
    writes = len(_writes(sy))
    dep = await _job(multi, seeded, "activate", slot="blue")
    assert dep.status == "failed" and _steps(dep)["dns"] == "failed" and _steps(dep)["switch"] == "pending"
    assert dep.error.endswith("Nothing was live before, and Slipway moved no traffic"), dep.error
    assert len(_writes(sy)) == writes and (await _get(Environment, seeded.env_id)).active_slot_id is None
    # With every record there, a Cloudflare outage is only a warning: the switch goes ahead.
    cf.deny = False
    await traffic.publish_dns(await _get(Environment, seeded.env_id))
    cf.deny = True
    dep = await _job(multi, seeded, "activate", slot="blue")
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert _steps(dep)["dns"] == "warning" and "every record was already there" in _note(dep, "dns")
    assert (await _get(Environment, seeded.env_id)).active_slot_id == seeded.ids["blue"]


async def test_activate_starts_a_stopped_slot_first(multi, submitted, sy):
    seeded = await _live_env(multi, active="blue", traffic=SWITCHYARD)
    await _set(Instance, seeded.ids["green"], status="stopped")
    _containers(multi, "green")
    dep = await _job(multi, seeded, "activate", slot="green")
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert list(_steps(dep)) == ["check", "start_slot", "smoke", "switch"]
    assert "compose -p demo-uat-green-web start" in multi["green"].docker()
    assert (await _get(Instance, seeded.ids["green"])).status == "running"
    assert _upstream(sy, WWW) == await _target(seeded, "green")
    # Stopped after it was queued: the check adds the step.
    await _set(Instance, seeded.ids["blue"], status="stopped")
    _containers(multi, "blue")
    dep_id = await _queue(seeded, "activate", slot="blue")
    await _set(Instance, seeded.ids["blue"], status="stopped")
    dep = await _run(multi, dep_id)
    assert dep.status == "succeeded" and list(_steps(dep)) == ["check", "start_slot", "smoke", "switch"]


async def test_activate_without_switchyard_records_the_slot(multi, submitted):
    seeded = await seed_env(multi, mode="slot", slots=("blue",))
    first = await _deploy(multi, seeded, "blue", options={"go_live": True})
    assert first.status == "succeeded", first.error
    [(chained, _)] = submitted  # the deploy went live by itself: its chain queued the activate
    dep = await _run(multi, chained)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert "doesn't publish its names through Switchyard" in _note(dep, "switch")
    env = await _get(Environment, seeded.env_id)
    assert env.active_slot_id == seeded.ids["blue"] and env.status == "live"


async def test_a_cancel_during_the_check_puts_traffic_back(multi, submitted, sy, sites):
    seeded = await _live_env(multi, active=None, traffic=SWITCHYARD)
    assert (await _job(multi, seeded, "activate", slot="blue")).status == "succeeded"
    blue_up = _upstream(sy, WWW)
    checking = asyncio.Event()

    async def hook(hostname):
        checking.set()
        await asyncio.sleep(30)

    sites.hook = hook
    dep_id = await _queue(seeded, "activate", slot="green")
    task = asyncio.create_task(deployer.run_deployment(dep_id, connect=multi.connect))
    await asyncio.wait_for(checking.wait(), 30)
    sites.hook = None
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    dep = await _get(Deployment, dep_id)
    assert dep.status == "cancelled" and _steps(dep)["switch"] == "failed"
    assert _upstream(sy, WWW) == blue_up  # the put-back finished
    env = await _get(Environment, seeded.env_id)
    assert env.active_slot_id == seeded.ids["blue"] and not env.traffic_state.get("unresolved")


# ------------------------------------------------------------------------ test 46: Switch back


async def test_switch_back_and_a_retry_after_traffic_moved(multi, submitted, sy, sites):
    seeded = await _live_env(multi, active=None, traffic=SWITCHYARD)
    assert (await _job(multi, seeded, "activate", slot="blue")).status == "succeeded"
    green = await _job(multi, seeded, "activate", slot="green")
    assert green.status == "succeeded" and green.options["from_slot"] == "blue"
    back_id = await _queue(seeded, "activate", slot="blue", back=True)
    async with get_sessionmaker()() as db:
        assert data.dep_label(await db.get(Deployment, back_id)) == "Switch back to blue"
    back = await _run(multi, back_id)
    assert back.status == "succeeded", (back.error, back.log)
    env = await _get(Environment, seeded.env_id)
    assert env.traffic_state["last"] == {**env.traffic_state["last"], "from_slot": "green", "to_slot": "blue",
                                         "back": True}
    assert _upstream(sy, WWW) == await _target(seeded, "blue")
    # An activate of green that failed, then traffic moved: its retry is refused.
    sites.codes[WWW] = 502
    failed = await _job(multi, seeded, "activate", slot="green")
    assert failed.status == "failed" and "Traffic stays on blue" in failed.error
    async with get_sessionmaker()() as db:
        assert await env_jobs.retry_refusal(db, await db.get(Deployment, failed.id)) is None  # still from blue
    sites.codes.clear()
    assert (await _job(multi, seeded, "activate", slot="green")).status == "succeeded"
    async with get_sessionmaker()() as db:
        refused = await env_jobs.retry_refusal(db, await db.get(Deployment, failed.id))
    assert refused == "Traffic moved since: activate again instead"
    retry = await _job(multi, seeded, "activate", raw=True, retry_of=failed.id, slot="green", from_slot="blue")
    assert retry.status == "failed" and retry.error == "Traffic moved since: activate again instead"


# ------------------------------------------------------------- test 47: an unresolved switch


async def test_an_unresolved_switch_fences_slot_deploys_until_resolve_or_activate(multi, submitted, sy, sites):
    seeded = await _live_env(multi, active=None, traffic=SWITCHYARD)
    assert (await _job(multi, seeded, "activate", slot="blue")).status == "succeeded"
    # Green's switch fails its check, and its put-back's PUT fails too.
    sites.codes[WWW] = 502
    sy.fail_on = {("PUT", sy.counts.get("PUT", 0) + 2): 500}
    dep = await _job(multi, seeded, "activate", slot="green")
    assert dep.status == "failed" and "Slipway couldn't put 1 of 1 back: www.uat.example.com" in dep.error
    sites.codes.clear()
    env = await _get(Environment, seeded.env_id)
    assert env.traffic_state["unresolved"]["to_slot"] == "green" and env.active_slot_id == seeded.ids["blue"]
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, seeded.env_id)
        green = await db.get(Instance, seeded.ids["green"])
        refused = await jobs.job_refusal(db, instance=green, environment=env, user=None, kind="deploy",
                                         options={"slot": "green"})
    assert refused.status == 409 and refused.text.startswith("Traffic of uat may be split between its slots")

    # Resolve: a second app name sent to blue makes the answer mixed.
    blue_up, green_up = await _target(seeded, "blue"), await _target(seeded, "green")
    assert _upstream(sy, WWW) == green_up
    admin = "admin.uat.example.com"
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, seeded.env_id)
        env.hostnames = [*env.hostnames, {"hostname": admin, "service": "web", "container": 8080, "follows": "active",
                                          "health": "/"}]
        for slot in ("blue", "green"):
            inst = await db.get(Instance, seeded.ids[slot])
            inst.app_state = {**inst.app_state, "routes": [*inst.app_state["routes"], {
                "hostname": admin, "service": "web", "container": 8080}]}
        await db.commit()
    host_addr, port = blue_up.split(":")
    made = sy.add(domains=[admin], notes=switchyard.marker(env), upstreams=[
        {"scheme": "http", "skip_tls_verify": False, "host": host_addr, "port": int(port)}])
    await resources.record(seeded.env_id, "switchyard", "proxy_host", str(made["id"]), admin, "created",
                           {"follows": "active"})
    with pytest.raises(env_jobs.ResolveRefused) as err:
        await env_jobs.resolve(seeded.env_id)
    assert err.value.status == 409
    assert err.value.text == f"Switchyard sends {admin} to blue and {WWW} to green: activate one of them"
    made["upstreams"][0].update(host="10.9.9.9")
    with pytest.raises(env_jobs.ResolveRefused) as err:
        await env_jobs.resolve(seeded.env_id)
    assert f"{admin} to neither slot" in err.value.text
    made["upstreams"][0].update(host=green_up.split(":")[0], port=int(green_up.split(":")[1]))
    assert await env_jobs.resolve(seeded.env_id) == "green"
    env = await _get(Environment, seeded.env_id)
    assert env.active_slot_id == seeded.ids["green"] and env.traffic_state["unresolved"] is None
    [row] = await _audits("environment.resolve")
    assert row.details["slot"] == "green"

    # A successful activate clears it too.
    await _set(Environment, seeded.env_id, traffic_state={**env.traffic_state, "unresolved": {
        "deployment_id": str(dep.id), "from_slot": "green", "to_slot": "blue", "message": "test", "at": "now"}})
    back = await _job(multi, seeded, "activate", slot="blue")
    assert back.status == "succeeded", (back.error, back.log)
    env = await _get(Environment, seeded.env_id)
    assert env.traffic_state["unresolved"] is None and env.active_slot_id == seeded.ids["blue"]
    assert _upstream(sy, WWW) == blue_up and _upstream(sy, admin) == blue_up


# ------------------------------------------------------------------------- test 48: Publish names


async def test_publish_names_syncs_and_publishes_and_blockers_write_nothing(multi, submitted, sy, cf):
    seeded = await _live_env(multi, active="blue", traffic={**SWITCHYARD, "dns": DNS})
    # The data server's deploy published both records and the files host; nothing published www's host yet.
    assert set(sy.hosts_by_domain()) == {FILES}
    zone_id = cf.zones[0]["id"]
    www = cf.named(WWW)[0]
    del cf.records[www["id"]]  # gone: made again
    cf.named(FILES)[0]["content"] = "198.51.100.1"  # moved: put back
    dep = await _job(multi, seeded, "publish")
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert list(_steps(dep)) == ["check", "traffic", "dns"]
    assert _upstream(sy, WWW) == await _target(seeded, "blue") and FILES in sy.hosts_by_domain()
    assert cf.named(WWW)[0]["content"] == "203.0.113.7" and cf.named(FILES)[0]["content"] == "203.0.113.7"
    async with get_sessionmaker()() as db:
        rows = {r.name for r in await resources.owned(db, seeded.env_id, "cloudflare", "dns_record")}
    assert rows == {WWW, FILES}

    # A blocker in either plan fails its step with the list, writing nothing.
    sy.drift = True
    writes = len(_writes(sy))
    dep = await _job(multi, seeded, "publish")
    assert dep.status == "failed" and _steps(dep)["traffic"] == "failed" and _steps(dep)["dns"] == "pending"
    assert "Caddy's config was changed outside Switchyard; Slipway changed nothing" in dep.error
    assert len(_writes(sy)) == writes
    sy.drift = False
    cf.add_record(zone_id, "CNAME", WWW, "elsewhere.example.net")
    cf_writes = len(cf.writes())
    failed = await _job(multi, seeded, "publish")
    assert failed.status == "failed" and _steps(failed)["dns"] == "failed"
    assert "Slipway changed no DNS record" in failed.error and len(cf.writes()) == cf_writes
    for rec in cf.named(WWW):
        if rec["type"] == "CNAME":
            del cf.records[rec["id"]]
    retry = await _job(multi, seeded, "publish", retry_of=failed.id)
    assert retry.status == "succeeded", retry.error

    # With a switch unresolved only the data server's names are synced.
    env = await _get(Environment, seeded.env_id)
    await _set(Environment, seeded.env_id, traffic_state={**env.traffic_state, "unresolved": {
        "deployment_id": None, "from_slot": "blue", "to_slot": "green", "message": "test", "at": "now"}})
    sy.hosts_by_domain()[WWW]["upstreams"][0]["port"] = 1
    dep = await _job(multi, seeded, "publish")
    assert dep.status == "succeeded" and _steps(dep)["traffic"] == "warning"
    assert traffic.SPLIT in _note(dep, "traffic") and sy.hosts_by_domain()[WWW]["upstreams"][0]["port"] == 1


# ------------------------------------------------------------------------- test 49: Remove a slot


async def test_remove_a_slot(multi, submitted, sy, tmp_path):
    seeded = await _live_env(multi, active="blue", traffic=SWITCHYARD)
    for slot, text in (("blue", "blue takes the traffic: activate green first"),
                       ("data", "The data server goes with the environment")):
        dep = await _job(multi, seeded, "remove_slot", raw=True, slot=slot)
        assert dep.status == "failed" and dep.error == text and _steps(dep)["slot"] == "pending"
    failed = await _failed_green(multi, seeded, tmp_path)
    dep = await _job(multi, seeded, "remove_slot", raw=True, slot="green")
    assert dep.status == "failed" and dep.error == "Discard green or roll back first"
    await _set(Instance, seeded.ids["data"], data_dirty=None)
    assert failed.status == "failed"

    # Containers left behind: the row stays.
    multi.clear()
    multi["green"].env["FAKE_PS"] = "0123456789ab"
    dep = await _job(multi, seeded, "remove_slot", slot="green")
    assert dep.status == "failed" and "Containers of uat green are still on green-host" in dep.error
    assert await _get(Instance, seeded.ids["green"]) is not None
    del multi["green"].env["FAKE_PS"]

    dep = await _job(multi, seeded, "remove_slot", retry_of=dep.id, slot="green")
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert any("compose -p demo-uat-green-web down" in line for line in multi["green"].docker())
    assert not multi["data"].docker() and not multi["data"].calls()  # the data server isn't touched
    assert await _get(Instance, seeded.ids["green"]) is None
    found = await _get(Deployment, dep.id)
    assert found is not None and found.instance_id is None and found.environment_id == seeded.env_id
    assert "uat's data server still lets green-host in: update it to stop that" in _note(dep, "slot")
    [row] = await _audits("environment.slot_remove")
    assert row.details["slot"] == "green" and row.details["host"] == "green-host"
    # A retry finds it gone.
    again = await _job(multi, seeded, "remove_slot", raw=True, retry_of=dep.id, slot="green")
    assert again.status == "succeeded" and _note(again, "slot") == "Already removed"
    # The only slot left can't go.
    only = await _job(multi, seeded, "remove_slot", raw=True, slot="blue")
    assert only.status == "failed" and "blue takes the traffic" in only.error
    await _set(Environment, seeded.env_id, active_slot_id=None)
    only = await _job(multi, seeded, "remove_slot", raw=True, slot="blue")
    assert only.status == "failed" and only.error == "blue is uat's only slot: delete the environment instead"


# ------------------------------------------------------------------------- test 50: Delete


async def test_delete_removes_what_slipway_made_and_keeps_the_data(multi, submitted, sy, cf):
    seeded = await _live_env(multi, active=None, traffic={**SWITCHYARD, "dns": DNS})
    assert (await _job(multi, seeded, "activate", slot="blue")).status == "succeeded"
    backup = await _owner_job(multi, seeded, "backup")
    assert backup.status == "succeeded", backup.error
    zone_id = cf.zones[0]["id"]
    claimed = cf.add_record(zone_id, "A", "claimed.uat.example.com", "203.0.113.7")
    await resources.record(seeded.env_id, "cloudflare", "dns_record", claimed["id"], "claimed.uat.example.com",
                           "claimed", {"zone_id": zone_id})
    assert len(sy.hosts) == 2 and len(cf.records) == 3
    multi.clear()

    # Switchyard is down: unroute fails, nothing after it ran.
    sy.denied = {"GET /api"}
    first_id = await _queue(seeded, "teardown", confirmed=True)
    assert (await _get(Environment, seeded.env_id)).status == "deleting"
    first = await _run(multi, first_id)
    assert first.status == "failed" and _steps(first)["unroute"] == "failed" and _steps(first)["undns"] == "pending"
    assert (await _get(Environment, seeded.env_id)).status == "deleting"
    async with get_sessionmaker()() as db:
        refused = await jobs.job_refusal(db, environment=await db.get(Environment, seeded.env_id), user=None,
                                         kind="teardown", options={"confirmed": True})
    assert refused.text == "uat is being deleted: only its teardown's retry can run"

    # The retry forgets the Switchyard hosts; the data server's containers stay for now.
    multi["data"].env["FAKE_PS"] = "0123456789ab"
    second = await _job(multi, seeded, "teardown", retry_of=first.id, forget_traffic=True)
    assert second.status == "failed" and _steps(second)["data_server"] == "failed", second.error
    assert _steps(second)["unroute"] == "warning" and "Slipway forgot its 2 host(s)" in _note(second, "unroute")
    assert _steps(second)["undns"] == "succeeded" and _steps(second)["slots"] == "succeeded"
    assert len(sy.hosts) == 2  # left in Switchyard, as the person asked
    assert {r["name"] for r in cf.records.values()} == {"claimed.uat.example.com"}  # claimed records stay
    assert await _get(Instance, seeded.ids["blue"]) is None and await _get(Instance, seeded.ids["green"]) is None
    assert any("compose -p demo-uat-green-web down" in line for line in multi["green"].docker())

    # The next retry skips the slots, removes the data server and forgets the environment.
    del multi["data"].env["FAKE_PS"]
    sy.denied = set()
    third = await _job(multi, seeded, "teardown", retry_of=second.id)
    assert third.status == "succeeded", (third.error, third.log)
    assert list(_steps(third)) == ["check", "unroute", "undns", "slots", "data_server", "forget"]
    assert _note(third, "slots") == "Already removed"
    assert await _get(Instance, seeded.ids["data"]) is None
    kept = list((multi["data"].root / ".slipway-kept").iterdir())
    assert any(p.name.endswith(".backups") and any(f.suffix == ".dump" for f in p.iterdir()) for p in kept)
    assert not any("volume rm" in line for line in multi["data"].docker())
    env = await _get(Environment, seeded.env_id)
    assert env.status == "deleted" and env.deleted_at is not None and env.active_slot_id is None
    assert env.deleted_by_id == seeded.user_id
    async with get_sessionmaker()() as db:
        assert not (await db.scalars(select(Resource).where(Resource.environment_id == env.id))).all()
        # The name can be used again.
        db.add(Environment(name="uat", repository_id=env.repository_id, branch="main", data_mode="slot"))
        await db.commit()
    assert [r.details["forget_traffic"] for r in await _audits("environment.delete")] == [False]
    # The jobs of the environment stay readable.
    assert (await _get(Deployment, first.id)).log


async def test_unroute_and_undns_are_skipped_when_there_is_nothing(multi, submitted):
    seeded = await seed_env(multi, mode="slot", slots=("blue",))
    dep = await _job(multi, seeded, "teardown", confirmed=True)
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert _steps(dep) == {"check": "succeeded", "unroute": "skipped", "undns": "skipped", "slots": "succeeded",
                           "data_server": "skipped", "forget": "succeeded"}
    assert not multi.opened  # never deployed: nothing on the host to remove


async def test_a_snapshot_first_then_the_teardown(multi, submitted, sy):
    seeded = await _live_env(multi, active="blue", traffic=SWITCHYARD)
    async with get_sessionmaker()() as db:
        snap = Snapshot(name="uat-last", status="pending", origin="instance", app="demo", source="uat",
                        source_instance_id=seeded.ids["data"])
        db.add(snap)
        await db.commit()
    dep = await _owner_job(multi, seeded, "snapshot", snapshot_id=snap.id, options={"then": "teardown"})
    assert dep.status == "succeeded", (dep.error, dep.log)
    [(teardown_id, keys)] = submitted
    teardown = await _get(Deployment, teardown_id)
    assert teardown.kind == "teardown" and teardown.options["confirmed"] is True
    assert teardown.options["snapshot"] == "uat-last" and teardown.options["after"] == dep.id.hex
    assert (await _get(Environment, seeded.env_id)).status == "deleting"
    done = await _run(multi, teardown_id)
    assert done.status == "succeeded", (done.error, done.log)
    assert (await _get(Environment, seeded.env_id)).status == "deleted"
    assert (await _get(Snapshot, snap.id)).status == "ready"
    assert sy.hosts_by_domain() == {}


# ----------------------------------------------------------------------- test 51: recovery


async def test_recovery_of_environment_jobs(multi, submitted):
    seeded = await seed_env(multi, slots=("blue", "green"))
    async with get_sessionmaker()() as db:
        switching = Deployment(instance_id=None, environment_id=seeded.env_id, kind="activate", branch="main", log="",
                               status="running", options={"slot": "green", "switch": {
                                   "from_slot": "blue", "to_slot": "green", "changed": [{"hostname": WWW, "id": "3"}]}},
                               steps=[{"key": "check", "name": "Check uat", "status": "succeeded"},
                                      {"key": "switch", "name": "Switch traffic to green", "status": "running",
                                       "started_at": "2026-11-16T10:00:00"}])
        db.add(switching)
        await db.commit()
    await deployer.runner.recover_interrupted()
    found = await _get(Deployment, switching.id)
    assert found.status == "failed" and found.error == "Interrupted by a Slipway restart"
    env = await _get(Environment, seeded.env_id)
    assert env.traffic_state["unresolved"]["message"] == "Slipway restarted during the switch"
    assert env.traffic_state["unresolved"]["to_slot"] == "green"
    assert [r.details["slot"] for r in await _audits("environment.unresolved")] == ["green"]

    # An activate whose switch was recorded before the restart moved traffic: it succeeded.
    await _set(Environment, seeded.env_id, traffic_state={})
    async with get_sessionmaker()() as db:
        recorded = Deployment(instance_id=None, environment_id=seeded.env_id, kind="activate", branch="main", log="",
                              status="running", options={"slot": "blue"},
                              steps=[{"key": "switch", "name": "Switch", "status": "succeeded", "started_at": "x"},
                                     {"key": "seed", "name": "Add starter content", "status": "running"}])
        db.add(recorded)
        await db.commit()
    await _set(Environment, seeded.env_id, traffic_state={"last": {"deployment_id": str(recorded.id)}})
    await deployer.runner.recover_interrupted()
    found = await _get(Deployment, recorded.id)
    assert found.status == "succeeded" and _steps(found)["seed"] == "warning"
    assert (await _get(Instance, seeded.ids["data"])).content_pending is True
    assert not (await _get(Environment, seeded.env_id)).traffic_state.get("unresolved")

    # An interrupted teardown stays deleting, and only its retry runs.
    first_id = await _queue(seeded, "teardown", confirmed=True)
    await _set(Deployment, first_id, status="running")
    await deployer.runner.recover_interrupted()
    assert (await _get(Environment, seeded.env_id)).status == "deleting"
    with pytest.raises(jobs.JobRefused):
        await _queue(seeded, "teardown", confirmed=True)
    retry = await _job(multi, seeded, "teardown", retry_of=first_id)
    assert retry.status == "succeeded", (retry.error, retry.log)
    assert (await _get(Environment, seeded.env_id)).status == "deleted"


async def test_a_go_live_deploy_recovered_as_succeeded_leaves_the_activate_button(multi, submitted):
    seeded = await seed_env(multi, mode="slot", slots=("blue",))
    first = await _deploy(multi, seeded, "blue", options={"go_live": True})
    assert first.status == "succeeded"
    submitted.clear()
    lost = await queue(seeded, "blue", status="running", commit_sha=first.commit_sha,
                       options={"slot": "blue", "go_live": True},
                       steps=[{"key": "finish", "name": "Switch", "status": "succeeded"},
                              {"key": "smoke", "name": "Check", "status": "running"}])
    blue = await _get(Instance, seeded.ids["blue"])
    await _set(Instance, blue.id, app_state={**blue.app_state, "went_live": lost.hex})
    await deployer.runner.recover_interrupted()
    assert (await _get(Deployment, lost)).status == "succeeded"
    env = await _get(Environment, seeded.env_id)
    assert env.notice["next"] == {"kind": "activate", "slot": "blue"}
    assert env.notice["text"] == "Slipway restarted after Deploy to blue succeeded, before it started Activate blue"
    assert submitted == []


# ------------------------------------------------------------------------------ test 67: Discard


async def test_discard_a_failed_idle_deploy(multi, submitted, sy, tmp_path):
    seeded = await _live_env(multi, active="blue", traffic=SWITCHYARD)
    (multi["data"].folder("uat-data") / "state" / "rev").write_text("rev-2\n")
    failed = await _failed_green(multi, seeded, tmp_path)
    async with get_sessionmaker()() as db:
        roll = await data.rollback_state(db, await db.get(Deployment, failed.id))
    assert roll.available and roll.needs_reset  # Roll back is the second way, needing data:reset too

    # Blue's release can't run the data as green's deploy left it: refused before green stops.
    multi.clear()
    _containers(multi, "blue", "green")
    multi["blue"].env["UNKNOWN_REVS"] = "rev-2"
    dep = await _job(multi, seeded, "discard", slot="green")
    assert dep.status == "failed" and _steps(dep)["check"] == "failed" and _steps(dep)["stop_slot"] == "pending"
    assert dep.error.startswith("blue (") and "can't run the database at revision rev-2 that green's deploy left" in \
        dep.error and "roll back to the backup from " in dep.error
    assert not any("stop" in line for line in multi["green"].docker())
    del multi["blue"].env["UNKNOWN_REVS"]

    # Blue failing its check: the job fails and the dirty state stays.
    multi["blue"].env["FAKE_HTTP_CODES"] = f"{WWW}=502"
    dep = await _job(multi, seeded, "discard", slot="green")
    assert dep.status == "failed" and _steps(dep)["smoke"] == "failed"
    assert dep.error.startswith(f"blue fails its check on the current data too ({WWW} answered 502")
    assert (await _get(Instance, seeded.ids["data"])).data_dirty["first"]["deployment_id"] == failed.id.hex
    del multi["blue"].env["FAKE_HTTP_CODES"]

    multi.clear()
    dep = await _job(multi, seeded, "discard", slot="green")
    assert dep.status == "succeeded", (dep.error, dep.log)
    assert list(_steps(dep)) == ["check", "stop_slot", "smoke", "settle"]
    assert "compose -p demo-uat-green-web stop" in multi["green"].docker()
    assert [c.split()[0] for c in multi["data"].calls()] == ["revision"]  # nothing restored
    assert any(c.startswith("accepts ") for c in multi["blue"].calls())
    green = await _get(Instance, seeded.ids["green"])
    assert green.status == "stopped"
    assert green.slot_state["stale"]["reason"] == f"Its deploy {failed.id.hex[:8]} failed and was discarded"
    assert (await _get(Instance, seeded.ids["data"])).data_dirty is None
    [row] = await _audits("environment.discard")
    assert row.details == {"slot": "green", "deployment": failed.id.hex, "checked": "blue"}
    assert (await _get(Environment, seeded.env_id)).active_slot_id == seeded.ids["blue"]


async def test_discard_refusals(multi, submitted, sy, tmp_path):
    seeded = await _live_env(multi, active="blue", traffic=SWITCHYARD)
    dep = await _job(multi, seeded, "discard", raw=True, slot="green")
    assert dep.status == "failed" and dep.error == "green has no failed deploy to discard"
    await _failed_green(multi, seeded, tmp_path)
    dep = await _job(multi, seeded, "discard", raw=True, slot="blue")
    assert dep.status == "failed" and dep.error == "blue has no failed deploy to discard"
    owner = await _get(Instance, seeded.ids["data"])
    await _set(Instance, owner.id, data_dirty={**owner.data_dirty, "hold": True, "last": {"kind": "restore"}})
    dep = await _job(multi, seeded, "discard", raw=True, slot="green")
    assert dep.status == "failed" and dep.error.startswith("uat's last restore stopped part-way")


async def test_discard_needs_two_slots(multi, submitted):
    single = await seed_env(multi, slots=("blue",))
    dep = await _job(multi, single, "discard", raw=True, slot="blue")
    assert dep.status == "failed" and dep.error == "Roll back or retry instead: blue is uat's only slot"


# --------------------------------------------- test 68: Activate beside a job that only reads the data


async def test_activate_runs_beside_a_backup_and_waits_for_a_stopping_snapshot(multi, sy, monkeypatch):
    seeded = await _live_env(multi, active="blue", traffic=SWITCHYARD)
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, seeded.env_id)
        user = await db.get(User, seeded.user_id)
        owner = await db.get(Instance, seeded.ids["data"])
        backup = await jobs.queue_job(db, instance=owner, environment=env, user=user, kind="backup")
        activate = await jobs.queue_job(db, environment=env, user=user, kind="activate", options={"slot": "green"})
        await db.commit()
        # Two activates never queue together, and the index stops one a race let through.
        with pytest.raises(jobs.JobRefused) as err:
            await jobs.queue_job(db, environment=env, user=user, kind="activate", options={"slot": "green"})
        assert err.value.status == 409
    async with get_sessionmaker()() as db:
        db.add(Deployment(instance_id=None, environment_id=seeded.env_id, kind="activate", branch="main", log="",
                          options={"slot": "green"}, steps=[]))
        with pytest.raises(IntegrityError):
            await db.commit()

    # Both run through the runner, under their own keys: the backup holds only the data key.
    real = deployer.run_deployment

    async def run_here(dep_id):
        await real(dep_id, connect=multi.connect)

    monkeypatch.setattr(deployer, "run_deployment", run_here)  # the runner calls run_deployment(id)
    if True:
        async with deployer.runner.exclusive(((seeded.env_id, "data"),)):
            # A Back up now running (here: its key held) doesn't keep the activate waiting.
            deployer.runner.submit(activate.id, data.env_keys(seeded.env_id, "activate"))
            for _ in range(400):
                if (await _get(Deployment, activate.id)).status in ("succeeded", "failed"):
                    break
                await asyncio.sleep(0.05)
        done = await _get(Deployment, activate.id)
        assert done.status == "succeeded", (done.error, done.log)
        deployer.runner.submit(backup.id, data.env_keys(seeded.env_id, "backup"))
        for _ in range(400):
            if (await _get(Deployment, backup.id)).status in ("succeeded", "failed"):
                break
            await asyncio.sleep(0.05)
        assert (await _get(Deployment, backup.id)).status == "succeeded"

        # Switch back beside a snapshot that stops the app: refused by the queue, and the runner keeps it waiting.
        async with get_sessionmaker()() as db:
            env = await db.get(Environment, seeded.env_id)
            user = await db.get(User, seeded.user_id)
            owner = await db.get(Instance, seeded.ids["data"])
            snap = await jobs.queue_job(db, instance=owner, environment=env, user=user, kind="snapshot",
                                        options={"stop_app": True})
            await db.commit()
            with pytest.raises(jobs.JobRefused) as err:
                await jobs.queue_job(db, environment=env, user=user, kind="activate",
                                     options={"slot": "blue", "back": True})
            assert err.value.status == 409 and "Take snapshot" in err.value.text
            await db.delete(await db.get(Deployment, snap.id))
            await db.commit()
        back = await _queue(seeded, "activate", slot="blue", back=True)
        keys = data.env_keys(seeded.env_id, "snapshot", {"stop_app": True})
        async with deployer.runner.exclusive(keys):
            deployer.runner.submit(back, data.env_keys(seeded.env_id, "activate"))
            await asyncio.sleep(0.3)
            assert (await _get(Deployment, back)).status == "queued"
        for _ in range(400):
            if (await _get(Deployment, back)).status in ("succeeded", "failed"):
                break
            await asyncio.sleep(0.05)
        assert (await _get(Deployment, back)).status == "succeeded"
