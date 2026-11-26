"""Phase 3 traffic (§10): Switchyard plans, switches and put-backs, sync scope, DNS publishing, the slot
smoke test, the public check and the database probe. Tests 23-29 of §16.2.

Switchyard and Cloudflare are the fakes in tests/fake_switchyard.py and tests/fake_cloudflare.py; the
public check talks to ``FakeSites`` through ``traffic.transport_factory``; the smoke test and the probe
run their commands in a real shell (``ShellRemote``) with ``curl``, ``wget`` and ``docker`` shims.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, update

from slipway.db.session import get_sessionmaker
from slipway.models import AppSetting, Deployment, Environment, Host, Instance, Repository, Resource
from slipway.services import cloudflare, resources, switchyard, traffic
from tests import fake_switchyard
from tests.python_shim import python_header
from tests.fake_cloudflare import TOKEN, ZONE, FakeCloudflare
from tests.test_final_remote import ShellRemote

# name, service, container port, health path
APP_ROUTES = [
    ("uat.example.com", "portal", 80, "/"),
    ("api.uat.example.com", "api", 8000, "/healthz"),
    ("learn.uat.example.com", "learn", 3000, "/"),
    ("wiki.uat.example.com", "wiki", 3001, "/health"),
    ("auth.uat.example.com", "auth", 9100, "/"),
]
SERVER_ROUTES = [("spaces.uat.example.com", "spaces", 9000, "/minio/health/live")]
ADDRESS = {"blue": "10.0.0.11", "green": "10.0.0.12", "data": "10.0.0.13"}
PORT_BASE = {"blue": 18000, "green": 28000, "data": 19000}
TRAFFIC_ADDRESS = "10.0.0.2"


def _app_state(routes):
    return {"routes": [{"hostname": h, "service": s, "container": c} for h, s, c, _ in routes],
            "manifest": {"services": [{"name": s, "health": p if p != "/" else None} for _, s, _, p in routes]}}


def _published(slot, routes, host_ip=None):
    out = []
    for i, (_, service, container, _) in enumerate(routes):
        port = {"service": service, "container": container, "protocol": "tcp", "host": PORT_BASE[slot] + i}
        if host_ip is not None:
            port["host_ip"] = host_ip
        out.append(port)
    return out


async def _env(mode="server", slots=("blue", "green"), *, dns=None, switch="switchyard") -> uuid.UUID:
    """An environment with its slots deployed (published ports and routes), nothing active yet."""
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=7, full_name="acme/web", owner="acme", name="web",
                          html_url="https://github.com/acme/web")
        db.add(repo)
        await db.flush()
        routes = APP_ROUTES + (SERVER_ROUTES if mode == "slot" else [])
        hostnames = [{"hostname": h, "service": s, "container": c, "follows": "active", "health": p}
                     for h, s, c, p in APP_ROUTES]
        hostnames += [{"hostname": h, "service": s, "container": c,
                       "follows": "server" if mode == "server" else "active", "health": p}
                      for h, s, c, p in SERVER_ROUTES]
        env = Environment(name="uat", repository_id=repo.id, branch="main", data_mode=mode, hostnames=hostnames,
                          traffic={"switch": switch, "dns": dns})
        db.add(env)
        await db.flush()
        wanted = list(slots) + (["data"] if mode == "server" else [])
        for slot in wanted:
            host = Host(name=slot, hostname=ADDRESS[slot], username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
            db.add(host)
            await db.flush()
            mine = SERVER_ROUTES if slot == "data" else routes
            db.add(Instance(name=f"uat {slot}", slug=f"uat-{slot}", repository_id=repo.id, host_id=host.id,
                            branch="main", build_source="app", environment_id=env.id, slot=slot,
                            published_ports=_published(slot, mine), app_state=_app_state(mine)))
        await db.commit()
        return env.id


async def _slot(env_id, slot) -> Instance:
    async with get_sessionmaker()() as db:
        return await db.scalar(select(Instance).where(Instance.environment_id == env_id, Instance.slot == slot))


async def _set_active(env_id, slot) -> None:
    inst = await _slot(env_id, slot)
    async with get_sessionmaker()() as db:
        await db.execute(update(Environment).where(Environment.id == env_id).values(active_slot_id=inst.id))
        await db.commit()


async def _deployment(env_id) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        dep = Deployment(environment_id=env_id, kind="activate", branch="main", status="succeeded", options={})
        db.add(dep)
        await db.commit()
        return dep.id


async def _ctx(env_id, mode="activate", slot=None, *, include_active=False, deployment_id=None, lines=None):
    async def say(line):
        if lines is not None:
            lines.append(line)

    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        return await traffic.context(db, env, mode, slot=slot, include_active=include_active,
                                     deployment_id=deployment_id, say=say)


async def _activate(env_id, slot, *, lines=None, deployment_id=None):
    ctx = await _ctx(env_id, "activate", slot, deployment_id=deployment_id, lines=lines)
    result = await traffic.switch(ctx)
    await _set_active(env_id, slot)
    return result


async def _rows(env_id, provider=traffic.PROVIDER, kind=traffic.KIND) -> dict[str, Resource]:
    async with get_sessionmaker()() as db:
        return {r.name: r for r in await resources.owned(db, env_id, provider, kind)}


def _upstreams(fake) -> dict[str, str]:
    return {d: f"{h['upstreams'][0]['host']}:{h['upstreams'][0]['port']}" for d, h in fake.hosts_by_domain().items()}


def _expected(slot, *, server="data") -> dict[str, str]:
    out = {h: f"{ADDRESS[slot]}:{PORT_BASE[slot] + i}" for i, (h, *_) in enumerate(APP_ROUTES)}
    out["spaces.uat.example.com"] = f"{ADDRESS[server]}:{PORT_BASE[server]}"
    return out


class FakeSites:
    """What the public check reaches through Switchyard's traffic address: an answer per hostname."""

    def __init__(self) -> None:
        self.codes: dict[str, list[int]] = {}  # hostname -> answers in turn (the last one repeats)
        self.requests: list[dict] = []
        self.hook = None  # async callable(request), run before answering

    def factory(self, verify: bool) -> httpx.MockTransport:
        async def handle(request: httpx.Request) -> httpx.Response:
            host = request.headers["host"]
            self.requests.append({"url": str(request.url), "host": host, "verify": verify,
                                  "sni": request.extensions.get("sni_hostname")})
            if self.hook is not None:
                await self.hook(request)
            codes = self.codes.get(host, [200])
            code = codes.pop(0) if len(codes) > 1 else codes[0]
            return httpx.Response(code)

        return httpx.MockTransport(handle)

    def asked(self, hostname: str) -> int:
        return sum(1 for r in self.requests if r["host"] == hostname)


@pytest.fixture
def fake(monkeypatch):
    return fake_switchyard.install(monkeypatch)


@pytest.fixture
def sites(monkeypatch):
    s = FakeSites()
    monkeypatch.setattr(traffic, "transport_factory", s.factory)
    return s


@pytest.fixture
def waits(monkeypatch):
    seen: list[float] = []

    async def no_wait(seconds):
        seen.append(seconds)

    monkeypatch.setattr(traffic, "sleep", no_wait)
    return seen


@pytest.fixture
async def configured(fake, sites, waits):
    await fake_switchyard.configure(traffic_address=TRAFFIC_ADDRESS)
    return fake


# ------------------------------------------------------------------------- routes


async def test_routes_follow_the_slot_or_the_data_server():
    env_id = await _env()
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        env.route_tls = {"wiki.uat.example.com": "internal"}
        slots = await traffic.members(db, env)
        planned = traffic.routes(env, slots["green"], slots["data"], default_tls="dns")
    by = {r.hostname: r for r in planned}
    assert {h for h, r in by.items() if r.follows == "server"} == {"spaces.uat.example.com"}
    assert by["api.uat.example.com"].health == "/healthz" and by["uat.example.com"].health == "/"
    assert by["wiki.uat.example.com"].tls_mode == "internal" and by["api.uat.example.com"].tls_mode == "dns"
    assert traffic.target(by["api.uat.example.com"], slots["green"]).upstream == "10.0.0.12:28001"
    # Before the slot deployed, its names come from env.hostnames and have no port yet.
    slots["green"].app_state, slots["green"].published_ports = None, []
    before = {r.hostname: r for r in traffic.routes(env, slots["green"], slots["data"])}
    assert set(before) == {h for h, *_ in APP_ROUTES + SERVER_ROUTES}
    assert "hasn't been deployed" in traffic.target(before["api.uat.example.com"], slots["green"]).problem


# --------------------------------------------------------------------- test 23


async def test_plan_only_reads_and_lists_creates_updates_deletes_and_none(configured):
    fake = configured
    env_id = await _env()
    ctx = await _ctx(env_id, "activate", "blue")
    plan = await traffic.BACKENDS["switchyard"].plan(ctx)
    assert plan.blockers == []
    assert {c.action for c in plan.changes} == {"create"} and len(plan.changes) == 6
    by = {c.hostname: c for c in plan.changes}
    assert by["api.uat.example.com"].summary == "api.uat.example.com → 10.0.0.11:18001 (new)"
    assert by["spaces.uat.example.com"].upstream == "10.0.0.13:19000"
    assert {c.method for c in fake.api_calls()} == {"GET"} and fake.hosts == {}

    await _activate(env_id, "blue")
    # Green's release drops wiki and adds docs.
    green = await _slot(env_id, "green")
    routes = [r for r in APP_ROUTES if r[0] != "wiki.uat.example.com"] + [("docs.uat.example.com", "docs", 4000, "/")]
    async with get_sessionmaker()() as db:
        await db.execute(update(Instance).where(Instance.id == green.id).values(
            app_state=_app_state(routes), published_ports=_published("green", routes)))
        await db.commit()
    calls = len(fake.api_calls())
    plan = await traffic.BACKENDS["switchyard"].plan(await _ctx(env_id, "activate", "green"))
    by = {c.hostname: c for c in plan.changes}
    assert {h: c.action for h, c in by.items()} == {
        "uat.example.com": "update", "api.uat.example.com": "update", "learn.uat.example.com": "update",
        "auth.uat.example.com": "update", "docs.uat.example.com": "create", "wiki.uat.example.com": "delete",
        "spaces.uat.example.com": "none"}
    assert by["api.uat.example.com"].summary == "api.uat.example.com → 10.0.0.12:28001 (was 10.0.0.11:18001)"
    assert by["spaces.uat.example.com"].summary.endswith("(no change)")
    assert by["wiki.uat.example.com"].summary.startswith("wiki.uat.example.com: remove Switchyard host #")
    assert by["api.uat.example.com"].before["upstreams"][0]["host"] == "10.0.0.11"
    assert "id" not in by["api.uat.example.com"].before
    assert {c.method for c in fake.api_calls()[calls:]} == {"GET"}
    assert plan.to_json()["changes"][0]["hostname"] == "api.uat.example.com"


@pytest.mark.parametrize("case, blocker", [
    ("drift", "Switchyard: Caddy's config was changed outside Switchyard"),
    ("never", "Switchyard: Switchyard has not applied a config yet; apply once there"),
    ("pending", "Switchyard: other changes were waiting in Switchyard"),
    ("foreign", "api.uat.example.com is used by Switchyard host #1, which belongs to someone else"),
    ("instance", "api.uat.example.com is used by Switchyard host #1, which belongs to instance shop"),
    ("multi", "Switchyard host #1 serves uat.example.com together with old.example.com; give it a host of its own"),
    ("unpublished", "api.uat.example.com: api container port 8000 is not published on blue"),
])
async def test_plan_blockers(configured, case, blocker):
    fake = configured
    env_id = await _env()
    if case == "drift":
        fake.drift = True
    elif case == "never":
        fake.version = None
    elif case == "pending":
        fake.someone_edits()
    elif case == "foreign":
        fake.add(domains=["api.uat.example.com"])
    elif case == "instance":
        owner = switchyard.Owner("instance", uuid.uuid4(), "shop")
        fake.add(domains=["api.uat.example.com"], notes=switchyard.marker(owner))
    elif case == "multi":
        fake.add(domains=["uat.example.com", "old.example.com"])
    elif case == "unpublished":
        blue = await _slot(env_id, "blue")
        async with get_sessionmaker()() as db:
            await db.execute(update(Instance).where(Instance.id == blue.id).values(
                published_ports=[p for p in blue.published_ports if p["service"] != "api"]))
            await db.commit()
    plan = await traffic.BACKENDS["switchyard"].plan(await _ctx(env_id, "activate", "blue"))
    assert blocker in plan.blockers
    assert {c.method for c in fake.api_calls()} == {"GET"}
    # A switch with that plan writes nothing.
    with pytest.raises(traffic.SwitchRefused, match="Slipway changed nothing"):
        await traffic.switch(await _ctx(env_id, "activate", "blue"))
    assert {c.method for c in fake.api_calls()} == {"GET"}


async def test_too_many_names_is_a_blocker(configured):
    env_id = await _env()
    ctx = await _ctx(env_id, "activate", "blue")
    route = ctx.routes[0]
    ctx.routes = [traffic.Route(f"n{i}.example.com", route.service, route.container, "active", "auto", "/")
                  for i in range(51)]
    plan = await traffic.BACKENDS["switchyard"].plan(ctx)
    assert "Too many public names (51); Slipway manages at most 50 per environment" in plan.blockers


async def test_a_host_with_our_marker_but_no_row_is_adopted(configured):
    fake = configured
    env_id = await _env()
    await _activate(env_id, "blue")
    rows = await _rows(env_id)
    await resources.forget(rows["api.uat.example.com"].id)  # as if the row's write had been lost
    plan = await traffic.BACKENDS["switchyard"].plan(await _ctx(env_id, "activate", "green"))
    api = next(c for c in plan.changes if c.hostname == "api.uat.example.com")
    assert (api.action, api.adopt) == ("update", True)
    await _activate(env_id, "green")
    assert (await _rows(env_id))["api.uat.example.com"].provider_id == api.external_id
    assert _upstreams(fake)["api.uat.example.com"] == "10.0.0.12:28001"


# --------------------------------------------------------------------- test 24


async def test_switch_records_first_and_applies_once(configured, monkeypatch):
    fake = configured
    env_id = await _env()
    dep_id = await _deployment(env_id)
    seen: dict = {}
    backend = traffic.BACKENDS["switchyard"]
    original_apply = backend.apply

    async def watched_apply(ctx, plan):
        async with get_sessionmaker()() as db:
            seen["record"] = dict((await db.get(Deployment, dep_id)).options.get("switch") or {})
        seen["writes_before"] = [c for c in fake.api_calls() if c.method != "GET"]
        return await original_apply(ctx, plan)

    monkeypatch.setattr(backend, "apply", watched_apply)
    original_create = switchyard.SwitchyardClient.create_host
    rows_at_create: list[int] = []

    async def watched_create(self, body):
        rows_at_create.append(len(await _rows(env_id)))
        return await original_create(self, body)

    monkeypatch.setattr(switchyard.SwitchyardClient, "create_host", watched_create)

    lines: list[str] = []
    result = await _activate(env_id, "blue", lines=lines, deployment_id=dep_id)
    # The switch record was saved before the first write, and each created host was recorded at once.
    assert seen["writes_before"] == []
    assert seen["record"]["from_slot"] is None and seen["record"]["to_slot"] == "blue"
    assert seen["record"]["applied"] is False and seen["record"]["created"] == []
    assert rows_at_create == [0, 1, 2, 3, 4, 5]
    rows = await _rows(env_id)
    assert set(rows) == set(_expected("blue"))
    assert rows["spaces.uat.example.com"].details["follows"] == "server"
    assert rows["api.uat.example.com"].details == {
        "follows": "active", "upstream": "10.0.0.11:18001", "tls_mode": "auto", "url": "https://sy.example.test"}
    assert {r.origin for r in rows.values()} == {"created"}
    assert _upstreams(fake) == _expected("blue")
    assert len(fake.applies) == 1 and fake.applies[0] == "Slipway: uat → blue"
    assert result.applied.created and result.check.ok
    # Every name was checked through the traffic address, with the hostname as SNI.
    assert "Checking the names through Switchyard" in lines
    async with get_sessionmaker()() as db:
        record = (await db.get(Deployment, dep_id)).options["switch"]
    assert record["applied"] is True and record["apply_n"] == fake.version
    assert sorted(e["hostname"] for e in record["created"]) == sorted(_expected("blue"))
    for host in fake.hosts.values():
        assert switchyard.owned_by(host, switchyard.Owner("environment", env_id, "uat"))

    # Blue → green: app names move, the data server's name stays; one apply for six hosts.
    dep2 = await _deployment(env_id)
    fake.calls.clear()
    applies = len(fake.applies)
    await _activate(env_id, "green", deployment_id=dep2)
    assert _upstreams(fake) == _expected("green")
    assert len(fake.applies) == applies + 1 and fake.applies[-1] == "Slipway: uat → green"
    api = [c for c in fake.api_calls()]
    previews = [i for i, c in enumerate(api) if c == "GET /api/config/preview"]
    apply_at = api.index("POST /api/config/apply")
    puts = [i for i, c in enumerate(api) if c.method == "PUT"]
    assert len(puts) == 5 and previews[0] < puts[0] and max(puts) < previews[-1] < apply_at
    async with get_sessionmaker()() as db:
        record = (await db.get(Deployment, dep2)).options["switch"]
    assert record["from_slot"] == "blue" and len(record["changed"]) == 5
    assert record["before"]["api.uat.example.com"]["upstreams"][0]["host"] == "10.0.0.11"


# --------------------------------------------------------------------- test 25


async def _blue_live(fake) -> uuid.UUID:
    env_id = await _env()
    await _activate(env_id, "blue")
    return env_id


async def _state(env_id) -> dict:
    async with get_sessionmaker()() as db:
        return (await db.get(Environment, env_id)).traffic_state or {}


async def test_put_back_when_the_second_put_fails(configured):
    fake = configured
    env_id = await _blue_live(fake)
    fake.fail_on = {("PUT", 2): 500}
    with pytest.raises(traffic.SwitchFailed, match="Traffic stays on blue") as err:
        await traffic.switch(await _ctx(env_id, "activate", "green"))
    assert not err.value.unresolved
    assert _upstreams(fake) == _expected("blue")
    assert fake.applies[-1] == "Slipway: put back uat"
    assert (await _state(env_id)).get("unresolved") is None


async def test_put_back_when_someone_edits_before_the_apply(configured):
    fake = configured
    env_id = await _blue_live(fake)
    applies = len(fake.applies)
    fake.someone_edits_after("PUT /api/hosts", n=5)  # after the last of the switch's five PUTs
    with pytest.raises(traffic.SwitchFailed,
                       match="Someone changed Switchyard during the switch.*Traffic stays on blue"):
        await traffic.switch(await _ctx(env_id, "activate", "green"))
    assert _upstreams(fake) == _expected("blue")
    assert len(fake.applies) == applies  # no apply at all: the switch never went live


async def test_put_back_when_the_apply_fails(configured):
    fake = configured
    env_id = await _blue_live(fake)
    fake.apply_fails_once()
    with pytest.raises(traffic.SwitchFailed, match="Switchyard could not apply.*Traffic stays on blue"):
        await traffic.switch(await _ctx(env_id, "activate", "green"))
    assert _upstreams(fake) == _expected("blue") and fake.applies[-1] == "Slipway: put back uat"


async def test_put_back_when_the_public_check_fails(configured, sites, waits):
    fake = configured
    env_id = await _blue_live(fake)
    sites.requests.clear()
    sites.codes = {"api.uat.example.com": [502]}
    lines: list[str] = []
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(env_id, "activate", "green", lines=lines))
    assert str(err.value) == ("api.uat.example.com answered 502 on /healthz (6 rounds) through Switchyard. "
                              "Traffic stays on blue")
    assert _upstreams(fake) == _expected("blue")
    assert sites.asked("api.uat.example.com") == 6 and sites.asked("uat.example.com") == 1  # only failures again
    assert waits.count(traffic.CHECK_DELAY) >= 5
    assert any(line.startswith(f"Switchyard applied #{fake.version - 1} for the switch; putting back on #")
               for line in lines)


async def test_cancel_during_the_check_still_puts_back(configured, sites):
    fake = configured
    env_id = await _blue_live(fake)
    started, never = asyncio.Event(), asyncio.Event()

    async def hang(request):
        started.set()
        await never.wait()

    sites.hook = hang
    task = asyncio.create_task(traffic.switch(await _ctx(env_id, "activate", "green")))
    await asyncio.wait_for(started.wait(), 5)
    assert _upstreams(fake) == _expected("green")  # applied; now in the verify phase
    sites.hook = None
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert _upstreams(fake) == _expected("blue")  # the shielded put-back finished
    assert fake.applies[-1] == "Slipway: put back uat"
    assert not switchyard.lock.locked()


async def test_the_lock_is_free_during_the_check_and_a_sync_in_between_is_not_foreign(configured, sites):
    fake = configured
    env_id = await _blue_live(fake)
    # A standalone instance, published while the switch is checking its names.
    async with get_sessionmaker()() as db:
        host = await db.scalar(select(Host).where(Host.name == "blue"))
        repo = await db.scalar(select(Repository))
        shop = Instance(name="shop", slug="shop", repository_id=repo.id, host_id=host.id, branch="main",
                        ports=[{"host": 8080, "container": 3000, "protocol": "tcp"}],
                        routes=[{"hostname": "shop.example.com", "service": None, "container": 3000,
                                 "tls_mode": "auto"}])
        db.add(shop)
        await db.commit()
    async with get_sessionmaker()() as db:
        shop = await db.scalar(select(Instance).where(Instance.slug == "shop"))
    checking, go_on = asyncio.Event(), asyncio.Event()

    async def wait_for_sync(request):
        checking.set()
        await go_on.wait()

    sites.hook = wait_for_sync
    sites.codes = {"api.uat.example.com": [502]}
    task = asyncio.create_task(traffic.switch(await _ctx(env_id, "activate", "green")))
    await asyncio.wait_for(checking.wait(), 5)
    assert not switchyard.lock.locked()

    async def quiet(line):
        return None

    entries = await asyncio.wait_for(switchyard.sync(shop, say=quiet), 5)  # finishes before the check does
    assert entries[0]["state"] == "live" and fake.applies[-1] == "Slipway: shop"
    sites.hook = None
    go_on.set()
    with pytest.raises(traffic.SwitchFailed, match="Traffic stays on blue") as err:
        await task
    assert not err.value.unresolved  # the sync's apply wasn't taken for a foreign change
    assert _upstreams(fake)["api.uat.example.com"] == "10.0.0.11:18001"
    assert fake.applies[-1] == "Slipway: put back uat"


@pytest.mark.parametrize("they_applied", [False, True])
async def test_a_host_changed_after_the_switch_is_not_overwritten(configured, sites, they_applied):
    fake = configured
    env_id = await _blue_live(fake)
    dep_id = await _deployment(env_id)
    sites.codes = {"api.uat.example.com": [502]}

    async def someone_repoints_wiki(request):
        if request.headers["host"] == "api.uat.example.com" and sites.asked("api.uat.example.com") == 6:
            host = fake.hosts_by_domain()["wiki.uat.example.com"]
            host["upstreams"] = [{**host["upstreams"][0], "port": 9999}]
            if they_applied:  # and applied it in Switchyard
                fake.version, fake.changes = fake.version + 1, 0
            else:
                fake.someone_edits()

    sites.hook = someone_repoints_wiki
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(env_id, "activate", "green", deployment_id=dep_id))
    assert err.value.unresolved
    if they_applied:
        # The other four are back and applied; wiki is theirs now.
        assert "Slipway couldn't put 1 of 5 back: wiki.uat.example.com." in str(err.value)
        assert fake.applies[-1] == "Slipway: put back uat"
    else:
        # Their edit is waiting, so the put-back can't be applied: none of the five is back live.
        assert ("Slipway couldn't put 5 of 5 back: api.uat.example.com, auth.uat.example.com, "
                "learn.uat.example.com, uat.example.com, wiki.uat.example.com") in str(err.value)
    assert _upstreams(fake)["wiki.uat.example.com"] == "10.0.0.12:9999"  # theirs, kept
    assert _upstreams(fake)["api.uat.example.com"] == "10.0.0.11:18001"  # put back in Switchyard
    unresolved = (await _state(env_id))["unresolved"]
    assert unresolved["deployment_id"] == str(dep_id) and unresolved["to_slot"] == "green"
    assert unresolved["from_slot"] == "blue" and "use Resolve" in unresolved["message"]


async def test_a_failing_put_back_reports_n_of_m(configured, sites):
    fake = configured
    env_id = await _blue_live(fake)
    sites.codes = {"api.uat.example.com": [502]}
    fake.fail_on = {("PUT", 6): 500}  # five for the switch, then the put-back's first
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(env_id, "activate", "green"))
    assert err.value.unresolved and err.value.put_back.failed == ["wiki.uat.example.com"]
    assert "Slipway couldn't put 1 of 5 back: wiki.uat.example.com. Check them in Switchyard" in str(err.value)
    assert (await _state(env_id))["unresolved"]["to_slot"] == "green"


async def test_hosts_made_by_a_first_switch_go_when_it_fails(configured, sites):
    fake = configured
    env_id = await _env()
    sites.codes = {"uat.example.com": [503]}
    with pytest.raises(traffic.SwitchFailed, match="Nothing was live before; Slipway removed the hosts it had made"):
        await traffic.switch(await _ctx(env_id, "activate", "blue"))
    assert fake.hosts == {} and await _rows(env_id) == {}
    assert sites.asked("uat.example.com") == traffic.CHECK_ROUNDS_CREATED  # Caddy is getting certificates


# --------------------------------------------------------------------- test 26


async def test_a_recorded_id_reused_by_someone_else_is_forgotten(configured):
    fake = configured
    env_id = await _blue_live(fake)
    api_id = int((await _rows(env_id))["api.uat.example.com"].provider_id)
    fake.delete_id_then_reuse(api_id)
    fake.calls.clear()
    await _activate(env_id, "green")
    assert f"PUT /api/hosts/{api_id}" not in fake.calls and f"DELETE /api/hosts/{api_id}" not in fake.calls
    assert fake.hosts[api_id]["domains"] == [f"other-{api_id}.example.net"]  # theirs, untouched
    row = (await _rows(env_id))["api.uat.example.com"]
    assert row.provider_id != str(api_id) and _upstreams(fake)["api.uat.example.com"] == "10.0.0.12:28001"


async def test_remove_deletes_only_marked_hosts_and_leaves_them_staged_when_blocked(configured):
    fake = configured
    env_id = await _blue_live(fake)
    rows = await _rows(env_id)
    wiki = fake.hosts[int(rows["wiki.uat.example.com"].provider_id)]
    wiki["notes"] = "someone took this one over"
    fake.someone_edits()  # someone else's change is waiting
    applies = len(fake.applies)
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        ctx = await traffic.context(db, env, "remove")
    plan = await traffic.remove(ctx)
    assert plan.warnings == ["Applied nothing: other changes were waiting in Switchyard; apply there"]
    assert len(fake.applies) == applies
    assert list(fake.hosts_by_domain()) == ["wiki.uat.example.com"]  # not ours any more: forgotten, kept
    assert await _rows(env_id) == {}
    assert f"DELETE /api/hosts/{wiki['id']}" not in fake.calls


async def test_remove_applies_when_nothing_else_waits(configured):
    fake = configured
    env_id = await _blue_live(fake)
    async with get_sessionmaker()() as db:
        ctx = await traffic.context(db, await db.get(Environment, env_id), "remove")
    plan = await traffic.remove(ctx)
    assert plan.warnings == [] and fake.hosts == {} and fake.applies[-1] == "Slipway: remove uat"
    assert await traffic.forget_all(env_id, traffic.PROVIDER, traffic.KIND) == 0


# --------------------------------------------------------------------- test 27


@pytest.fixture
def cf(monkeypatch):
    fake_cf = FakeCloudflare()
    monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(fake_cf.handle))
    return fake_cf


async def _cloudflare(fake_cf, *, public_ip="203.0.113.7") -> str:
    zid = fake_cf.add_zone()
    async with get_sessionmaker()() as db:
        db.add(AppSetting(key=cloudflare.SETTING_KEY, value={"zone": ZONE, "zone_id": zid, "public_ip": public_ip,
                                                             "proxied": False}, secret=TOKEN))
        await db.commit()
    return zid


DNS = {"provider": "cloudflare", "address": None, "proxied": False}


async def _env_obj(env_id) -> Environment:
    async with get_sessionmaker()() as db:
        return await db.get(Environment, env_id)


async def test_publish_dns_creates_updates_and_records_at_once(cf, monkeypatch):
    zid = await _cloudflare(cf)
    env_id = await _env(dns=DNS, switch="none")
    env = await _env_obj(env_id)
    comment = cloudflare.comment_for("uat", env_id)
    old = cf.add_record(zid, "A", "api.uat.example.com", "198.51.100.1", comment=comment)
    await resources.record(env_id, cloudflare.PROVIDER, cloudflare.KIND, old["id"], "api.uat.example.com", "created",
                           {"zone_id": zid, "type": "A", "content": "198.51.100.1", "proxied": False})
    rows_at_create: list[int] = []
    original = cloudflare.CloudflareClient.create_a

    async def watched(self, *args, **kw):
        rows_at_create.append(len(await _rows(env_id, cloudflare.PROVIDER, cloudflare.KIND)))
        return await original(self, *args, **kw)

    monkeypatch.setattr(cloudflare.CloudflareClient, "create_a", watched)
    lines: list[str] = []

    async def say(line):
        lines.append(line)

    plan = await traffic.publish_dns(env, say)
    by = {c.hostname: c for c in plan.changes}
    assert by["api.uat.example.com"].action == "update" and by["uat.example.com"].action == "create"
    assert rows_at_create == [1, 2, 3, 4, 5]  # each create recorded before the next
    rows = await _rows(env_id, cloudflare.PROVIDER, cloudflare.KIND)
    assert set(rows) == {h for h, *_ in APP_ROUTES + SERVER_ROUTES}
    assert rows["api.uat.example.com"].details["content"] == "203.0.113.7"
    for name in rows:
        (rec,) = cf.named(name)
        assert (rec["type"], rec["content"], rec["proxied"], rec["comment"]) == ("A", "203.0.113.7", False, comment)
    assert any("api.uat.example.com → A 203.0.113.7 (was A 198.51.100.1)" in line for line in lines)
    # Again: nothing to do.
    writes = len(cf.writes())
    again = await traffic.publish_dns(env)
    assert {c.status for c in again.changes} == {"ok"} and len(cf.writes()) == writes


async def test_a_dns_blocker_stops_every_write(cf):
    zid = await _cloudflare(cf)
    env_id = await _env(dns=DNS, switch="none")
    cf.add_record(zid, "CNAME", "learn.uat.example.com", "elsewhere.example.net")
    with pytest.raises(traffic.DnsRefused, match="learn.uat.example.com has a CNAME record") as err:
        await traffic.publish_dns(await _env_obj(env_id))
    assert cf.writes() == [] and err.value.plan.blockers
    assert await _rows(env_id, cloudflare.PROVIDER, cloudflare.KIND) == {}


async def test_stale_dns_rows_created_are_deleted_and_claimed_forgotten(cf):
    zid = await _cloudflare(cf)
    env_id = await _env(dns=DNS, switch="none")
    comment = cloudflare.comment_for("uat", env_id)
    made = cf.add_record(zid, "A", "old.uat.example.com", "203.0.113.7", comment=comment)
    kept = cf.add_record(zid, "A", "legacy.uat.example.com", "203.0.113.7", comment="theirs")
    await resources.record(env_id, cloudflare.PROVIDER, cloudflare.KIND, made["id"], "old.uat.example.com", "created")
    await resources.record(env_id, cloudflare.PROVIDER, cloudflare.KIND, kept["id"], "legacy.uat.example.com",
                           "claimed")
    plan = await traffic.publish_dns(await _env_obj(env_id))
    by = {c.hostname: c.action for c in plan.changes}
    assert by["old.uat.example.com"] == "delete" and by["legacy.uat.example.com"] == "forget"
    assert made["id"] not in cf.records and kept["id"] in cf.records
    rows = await _rows(env_id, cloudflare.PROVIDER, cloudflare.KIND)
    assert "old.uat.example.com" not in rows and "legacy.uat.example.com" not in rows
    # Teardown's half: every record Slipway made goes.
    await traffic.remove_dns(await _env_obj(env_id))
    assert [r for r in cf.records.values() if r["comment"] == comment] == []
    assert await _rows(env_id, cloudflare.PROVIDER, cloudflare.KIND) == {}


async def test_the_dry_run_only_reads(cf, configured):
    fake = configured
    await _cloudflare(cf)
    env_id = await _env(dns=DNS)
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        dry = await traffic.plan_for(env, "blue", db)
        sync_dry = await traffic.plan_for(env, None, db)
    assert {c["action"] for c in dry["switch"]["changes"]} == {"create"}
    assert {c["status"] for c in dry["dns"]["changes"]} == {"create"}
    assert [r["hostname"] for r in sync_dry["routes"]] == ["spaces.uat.example.com"]  # nothing is active
    assert "Nothing is live yet, so no app name was published" in sync_dry["switch"]["notes"]
    assert len(dry["routes"]) == 6
    assert cf.writes() == [] and {c.method for c in fake.api_calls()} == {"GET"}
    json.dumps(dry)  # JSON as it is


async def test_dns_without_an_address_is_refused(cf):
    await _cloudflare(cf, public_ip=None)
    env_id = await _env(dns=DNS, switch="none")
    with pytest.raises(traffic.DnsRefused, match="Set Cloudflare's public IP"):
        await traffic.publish_dns(await _env_obj(env_id))
    assert cf.calls == []


# --------------------------------------------------------------------- test 28


async def test_sync_scope(configured):
    fake = configured
    env_id = await _env()
    ctx = await _ctx(env_id, "sync", include_active=False)
    assert [r.hostname for r in ctx.routes] == ["spaces.uat.example.com"] and ctx.to_slot is None
    # The data server's deploy: only its own name, before anything is active (D24).
    result = await traffic.sync(ctx)
    assert result.warnings == [] and list(fake.hosts_by_domain()) == ["spaces.uat.example.com"]

    await _activate(env_id, "blue")
    ctx = await _ctx(env_id, "sync", include_active=True)
    assert ctx.to_slot.slot == "blue" and len(ctx.routes) == 6
    assert {traffic.target_for(r, ctx).address for r in ctx.routes if r.follows == "active"} == {"10.0.0.11"}
    plan = await traffic.BACKENDS["switchyard"].plan(ctx)
    assert {c.action for c in plan.changes} == {"none"}  # never another slot, though green is deployed

    # A sync without the active slot leaves the active-following hosts alone (no deletes).
    plan = await traffic.BACKENDS["switchyard"].plan(await _ctx(env_id, "sync", include_active=False))
    assert [(c.hostname, c.action) for c in plan.changes] == [("spaces.uat.example.com", "none")]

    async with get_sessionmaker()() as db:
        await db.execute(update(Environment).where(Environment.id == env_id).values(
            traffic_state={"unresolved": {"message": "x", "to_slot": "green"}}))
        await db.commit()
    ctx = await _ctx(env_id, "sync", include_active=True)
    assert [r.hostname for r in ctx.routes] == ["spaces.uat.example.com"] and ctx.to_slot is None
    assert traffic.SPLIT in ctx.notes


async def test_an_in_place_sync_follows_new_ports(configured):
    fake = configured
    env_id = await _env(mode="slot", slots=("blue",))
    await _activate(env_id, "blue")
    assert _upstreams(fake)["spaces.uat.example.com"] == "10.0.0.11:18005"  # mode slot: it follows blue
    blue = await _slot(env_id, "blue")
    moved = [{**p, "host": p["host"] + 100} for p in blue.published_ports]
    async with get_sessionmaker()() as db:
        await db.execute(update(Instance).where(Instance.id == blue.id).values(published_ports=moved))
        await db.commit()
    result = await traffic.sync(await _ctx(env_id, "sync", include_active=True))
    assert result.warnings == [] and result.applied.did_apply
    assert _upstreams(fake)["api.uat.example.com"] == "10.0.0.11:18101"
    assert result.check.ok and fake.applies[-1] == "Slipway: uat"


async def test_a_blocked_sync_warns_and_writes_nothing(configured):
    fake = configured
    env_id = await _env()
    fake.drift = True
    result = await traffic.sync(await _ctx(env_id, "sync"))
    assert result.warnings == ["Switchyard: Caddy's config was changed outside Switchyard"]
    assert {c.method for c in fake.api_calls()} == {"GET"}


# --------------------------------------------------------------------- test 29


SHIM = r'''{header}import json, os, sys
tool = os.path.basename(sys.argv[0])
args = sys.argv[1:]
with open(os.environ["HTTP_LOG"], "a") as fh:
    fh.write(json.dumps([tool] + args) + "\n")
host = next(a[6:] for a in args if a.startswith("Host: "))
codes = json.loads(os.environ.get("FAKE_HTTP_CODES") or "{{}}").get(host, [200])
count_file = os.path.join(os.environ["HTTP_STATE"], str(abs(hash(host))))
n = int(open(count_file).read()) if os.path.exists(count_file) else 0
open(count_file, "w").write(str(n + 1))
code = codes[min(n, len(codes) - 1)]
if tool == "curl":
    sys.stdout.write(str(code))
    sys.exit(0)
sys.stderr.write("  HTTP/1.1 %d Whatever\n  Server: fake\n" % code)
sys.exit(0 if code < 400 else 8)
'''


def _shims(tmp_path: Path, tools=("curl",), codes=None) -> tuple[dict, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in tools:
        script = bin_dir / tool
        script.write_text(SHIM.format(header=python_header()))
        script.chmod(0o755)
    awk = "/usr/bin/awk" if os.path.exists("/usr/bin/awk") else "/bin/awk"
    (bin_dir / "awk").symlink_to(awk)
    state = tmp_path / "state"
    state.mkdir()
    log = tmp_path / "http.log"
    log.write_text("")
    env = {"PATH": str(bin_dir), "HTTP_LOG": str(log), "HTTP_STATE": str(state), "HOME": str(tmp_path),
           "FAKE_HTTP_CODES": json.dumps(codes or {}), "PYTHONHASHSEED": "0"}
    return env, log


def _calls(log: Path) -> list[list[str]]:
    return [json.loads(line) for line in log.read_text().splitlines()]


def _slot_instance(ports) -> Instance:
    return Instance(name="uat blue", slug="uat-blue", branch="main", build_source="app", slot="blue",
                    published_ports=ports, host=Host(name="blue", hostname="10.0.0.11", username="deploy"))


ROUTE = traffic.Route("api.uat.example.com", "api", 8000, "active", "auto", "/healthz")


def test_smoke_command_quotes_every_value():
    t = traffic.SmokeTarget("o'brien.example.com", 18000, "127.0.0.1", "/x'y z")
    assert traffic.smoke_command("curl", t) == (
        "curl -sS -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: o'\"'\"'brien.example.com' "
        "-H 'X-Forwarded-Proto: https' 'http://127.0.0.1:18000/x'\"'\"'y z'")
    assert traffic.smoke_command("wget", traffic.SmokeTarget("a.example.com", 80, "::1", "/")).startswith(
        "wget -q -S -O /dev/null -T 10 --header 'Host: a.example.com' --header 'X-Forwarded-Proto: https' "
        "'http://[::1]:80/' 2>&1 | awk")


async def test_smoke_runs_curl_with_each_value_as_one_argument(tmp_path, waits):
    env, log = _shims(tmp_path, codes={"o'brien.example.com": [502, 502, 200]})
    remote = ShellRemote("/bin/sh", env)
    ports = [{"service": "api", "container": 8000, "protocol": "tcp", "host": 18000, "host_ip": "10.0.0.11"},
             {"service": "portal", "container": 80, "protocol": "tcp", "host": 18001, "host_ip": "0.0.0.0"}]
    planned = [traffic.Route("o'brien.example.com", "api", 8000, "active", "auto", "/he'alth"),
               traffic.Route("uat.example.com", "portal", 80, "active", "auto", "/"),
               traffic.Route("spaces.uat.example.com", "spaces", 9000, "server", "auto", "/")]
    result = await traffic.smoke(remote, _slot_instance(ports), planned)
    assert result.ok and result.results == [{"hostname": "o'brien.example.com", "code": 200},
                                            {"hostname": "uat.example.com", "code": 200}]
    calls = _calls(log)
    assert [c[0] for c in calls] == ["curl"] * 4  # the failing name three times, the other once
    first = calls[0]
    assert "Host: o'brien.example.com" in first and "http://10.0.0.11:18000/he'alth" in first  # host_ip used
    assert "http://127.0.0.1:18001/" in calls[1]  # 0.0.0.0: ask locally
    assert "X-Forwarded-Proto: https" in first and "--max-time" in first
    assert not any("spaces.uat.example.com" in " ".join(c) for c in calls)  # server names aren't the slot's
    assert waits == [traffic.SMOKE_DELAY, traffic.SMOKE_DELAY]


async def test_smoke_reports_the_codes_after_five_tries(tmp_path, waits):
    env, log = _shims(tmp_path, codes={"api.uat.example.com": [502]})
    ports = [{"service": "api", "container": 8000, "protocol": "tcp", "host": 18000}]
    result = await traffic.smoke(ShellRemote("/bin/sh", env), _slot_instance(ports), [ROUTE])
    assert not result.ok and result.failures == ["api.uat.example.com answered 502 on /healthz (5 tries)"]
    assert len(_calls(log)) == 5


async def test_smoke_falls_back_to_wget(tmp_path, waits):
    env, log = _shims(tmp_path, tools=("wget",), codes={"api.uat.example.com": [503, 301]})
    ports = [{"service": "api", "container": 8000, "protocol": "tcp", "host": 18000}]
    result = await traffic.smoke(ShellRemote("/bin/sh", env), _slot_instance(ports), [ROUTE])
    assert result.ok and result.results == [{"hostname": "api.uat.example.com", "code": 301}]
    calls = _calls(log)
    assert [c[0] for c in calls] == ["wget", "wget"] and "Host: api.uat.example.com" in calls[0]


async def test_smoke_without_curl_or_wget(tmp_path, waits):
    env, _ = _shims(tmp_path, tools=())
    ports = [{"service": "api", "container": 8000, "protocol": "tcp", "host": 18000}]
    with pytest.raises(traffic.TrafficError, match="Neither curl nor wget is on blue; install one"):
        await traffic.smoke(ShellRemote("/bin/sh", env), _slot_instance(ports), [ROUTE])


async def test_smoke_names_an_unpublished_port(tmp_path, waits):
    env, log = _shims(tmp_path)
    result = await traffic.smoke(ShellRemote("/bin/sh", env), _slot_instance([]), [ROUTE])
    assert result.failures == ["api.uat.example.com: api container port 8000 is not published on blue"]
    assert _calls(log) == []


def test_smoke_reads_curls_code_beside_its_error():
    assert traffic._code("000curl: (7) Failed to connect to 127.0.0.1 port 18000 after 0 ms") == (
        None, "curl: (7) Failed to connect to 127.0.0.1 port 18000 after 0 ms")
    assert traffic._code("curl: (28) Operation timed out after 10001 milliseconds\n000")[0] is None
    assert traffic._code("204") == (204, "")


async def test_public_check_sets_sni_verifies_per_tls_mode_and_retries_only_failures(sites, waits):
    planned = [traffic.Route("api.uat.example.com", "api", 8000, "active", "auto", "/healthz"),
               traffic.Route("int.uat.example.com", "api", 8000, "active", "internal", "/"),
               traffic.Route("plain.uat.example.com", "api", 8000, "active", "off", "/")]
    sites.codes = {"api.uat.example.com": [502, 200], "plain.uat.example.com": [404]}
    lines: list[str] = []

    async def say(line):
        lines.append(line)

    result = await traffic.public_check(planned, "10.0.0.2:8443", say=say, rounds=3)
    by = {r["host"]: r for r in sites.requests}
    assert by["api.uat.example.com"]["url"] == "https://10.0.0.2:8443/healthz"
    assert by["api.uat.example.com"]["sni"] == "api.uat.example.com" and by["api.uat.example.com"]["verify"] is True
    assert by["int.uat.example.com"]["verify"] is False
    assert by["plain.uat.example.com"]["url"] == "http://10.0.0.2:8443/"
    assert (sites.asked("api.uat.example.com"), sites.asked("int.uat.example.com"),
            sites.asked("plain.uat.example.com")) == (2, 1, 3)
    assert result.failures == ["plain.uat.example.com answered 404 on / (3 rounds)"]
    assert any("internal certificate" in line for line in lines)
    assert waits == [traffic.CHECK_DELAY, traffic.CHECK_DELAY]


async def test_public_check_is_skipped_without_a_traffic_address(sites):
    result = await traffic.public_check([ROUTE], "")
    assert result.ok and result.skipped == traffic.NO_TRAFFIC_ADDRESS and sites.requests == []


async def test_a_switch_without_a_traffic_address_warns(fake, sites, waits):
    await fake_switchyard.configure()
    env_id = await _env()
    result = await _activate(env_id, "blue")
    assert result.warnings == [traffic.NO_TRAFFIC_ADDRESS] and sites.requests == []
    assert _upstreams(fake) == _expected("blue")


# ------------------------------------------------------------- database probe


DOCKER = r'''{header}import json, os, sys
with open(os.environ["DOCKER_LOG"], "a") as fh:
    fh.write(json.dumps({{"argv": sys.argv[1:], "has_password": bool(os.environ.get("PGPASSWORD")),
                         "password_ok": os.environ.get("PGPASSWORD") == os.environ.get("EXPECT")}}) + "\n")
answer = os.environ.get("FAKE_PSQL") or "1"
print(answer)
sys.exit(0 if answer == "1" else 2)
'''


def _docker(tmp_path, answer="1"):
    bin_dir = tmp_path / "dbin"
    bin_dir.mkdir()
    script = bin_dir / "docker"
    script.write_text(DOCKER.format(header=python_header()))
    script.chmod(0o755)
    log = tmp_path / "docker.log"
    log.write_text("")
    return {"PATH": str(bin_dir), "DOCKER_LOG": str(log), "EXPECT": "s3cr'et pass", "FAKE_PSQL": answer}, log


async def test_the_database_probe_keeps_the_password_out_of_argv(tmp_path):
    env, log = _docker(tmp_path)
    slot = _slot_instance([])
    problem = await traffic.probe_database(ShellRemote("/bin/sh", env), slot, env_name="uat", host="10.0.0.13",
                                           port=5433, database="ss uat", user="ss", password="s3cr'et pass")
    assert problem is None
    (call,) = [json.loads(line) for line in log.read_text().splitlines()]
    assert call["has_password"] and call["password_ok"]
    assert call["argv"][:5] == ["run", "--rm", "-e", "PGPASSWORD", "postgres:16-alpine"]
    assert call["argv"][6] == ("host=10.0.0.13 port=5433 dbname='ss uat' user=ss sslmode=disable "
                               "connect_timeout=10")
    assert "s3cr'et" not in log.read_text().replace('"password_ok"', "")


async def test_the_database_probe_names_the_lan_address_to_set(tmp_path):
    env, _ = _docker(tmp_path, answer='psql: error: FATAL:  no pg_hba.conf entry for host "172.17.0.5", user "ss"')
    problem = await traffic.probe_database(ShellRemote("/bin/sh", env), _slot_instance([]), env_name="uat",
                                           host="10.0.0.13", port=5432, database="ss", user="ss", password="pw")
    assert problem.startswith("uat blue on blue can't sign in to uat's database at 10.0.0.13:5432 (psql: error:")
    assert problem.endswith("set host blue's LAN address to 172.17.0.5 and update the data server")
