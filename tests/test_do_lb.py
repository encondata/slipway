"""The ``do_lb`` traffic backend (phase 4 §11.6, D10, D11, D28; tests 47-50 and 79 of §20.2).

DigitalOcean is tests/fake_digitalocean.py; the droplets are fake hosts (tests/fake_hosts.py ``MultiRemote``) at
the fake's droplet addresses, so the slot's own health check runs the ``curl`` shim on that host. The public
check talks to ``FakeSites`` (tests/test_traffic.py) through ``traffic.transport_factory``. The environment rows
are written here directly, as ``environments.create`` and the provisioner would leave them.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field

import httpx
import pytest
from sqlalchemy import delete, update

from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Environment, Host, Instance, ProviderAccount, Repository, Resource
from slipway.services import digitalocean, do_lb, do_rules, switchyard, traffic
from tests.fake_digitalocean import TEAM, TOKEN, FakeDigitalOcean, use_fake
from tests.fake_hosts import MultiRemote
from tests.test_traffic import (  # noqa: F401  (fixtures)
    APP_ROUTES,
    _app_state,
    _published,
    sites,
    waits,
)

PORT, HEALTH = 8080, "/healthz"
SETTLE = 3 * 10 + 10  # healthy_threshold x check_interval_seconds + 10, from lb_body's health check
NAMES = sorted(h for h, *_ in APP_ROUTES)


@dataclass
class World:
    fake: FakeDigitalOcean
    multi: MultiRemote
    env_id: uuid.UUID
    lb_id: str
    droplets: dict[str, int]
    ips: dict[str, str]
    cert_id: str
    lines: list[str] = field(default_factory=list)

    @property
    def lb(self) -> dict:
        return self.fake.load_balancers[self.lb_id]

    def targets(self) -> list[int]:
        return list(self.lb["droplet_ids"])

    def set_targets(self, *slots_or_ids) -> None:
        self.lb["droplet_ids"] = [self.droplets.get(s, s) if isinstance(s, str) else s for s in slots_or_ids]

    def lb_puts(self) -> list[list[int]]:
        return [r["body"]["droplet_ids"] for r in self.fake.requests
                if r["method"] == "PUT" and r["path"] == f"/load_balancers/{self.lb_id}"]

    def health_calls(self, slot: str) -> list[str]:
        return self.multi[self.ips[slot]].log("CURL_LOG")


@pytest.fixture
def do(monkeypatch):
    return use_fake(monkeypatch, FakeDigitalOcean())


@pytest.fixture
def settles(monkeypatch):
    seen: list[float] = []

    async def no_wait(seconds):
        seen.append(seconds)

    monkeypatch.setattr(do_lb, "sleep", no_wait)
    return seen


@pytest.fixture
async def world(do, sites, waits, settles, tmp_path) -> World:
    return await _world(do, tmp_path)


async def _world(fake: FakeDigitalOcean, tmp_path, *, slots=("blue", "green"), names=None,
                 staging=False, team=TEAM["uuid"]) -> World:
    """A DigitalOcean environment ``uat`` as its first deploys leave it: a droplet per slot (built, pinned, on a
    fake host at its address), a VPC, a certificate, and a load balancer with no targets. Nothing is active."""
    vpc = fake.add_vpc(name="slipway-uat")
    cert = fake.add_certificate("slipway-uat-202611160000", names or NAMES)
    multi = MultiRemote(tmp_path)
    async with get_sessionmaker()() as db:
        account = ProviderAccount(provider="digitalocean", name="DO main", secret=TOKEN, secret_hint=TOKEN[-4:],
                                  config={"region": "nyc3", "ssh_sources": ["198.51.100.0/24"],
                                          "team": {"id": TEAM["uuid"], "name": TEAM["name"]}})
        repo = Repository(github_id=7, full_name="acme/web", owner="acme", name="web",
                          html_url="https://github.com/acme/web")
        db.add_all([account, repo])
        await db.flush()
        hostnames = [{"hostname": h, "service": s, "container": c, "follows": "active", "health": p}
                     for h, s, c, p in APP_ROUTES]
        env = Environment(name="uat", repository_id=repo.id, branch="main", data_mode="managed",
                          hostnames=hostnames, traffic={"switch": "do_lb", "dns": None}, provider="digitalocean",
                          provider_account_id=account.id, provider_team=team,
                          cloud={"region": "nyc3", "edge": {"port": PORT, "health": HEALTH},
                                 "acme_staging": staging})
        db.add(env)
        await db.flush()
        droplets, ips = {}, {}
        for slot in slots:
            name = do_rules.droplet_name("uat", slot)
            droplet = fake.add_droplet(name=name, vpc_uuid=vpc["id"],
                                       tags=do_rules.tags("uat", env.id, nonce=do_rules.new_nonce(), slot=slot))
            ip, _private = digitalocean.droplet_ips(droplet)
            multi.add(name, ip)
            host = Host(name=name, hostname=ip, username="slipway", host_key="ssh-ed25519 AAAA", metrics={},
                        provider="digitalocean", provider_state={"phase": "ready"}, owner_environment_id=env.id)
            db.add(host)
            await db.flush()
            inst = Instance(name=f"uat {slot}", slug=f"uat-{slot}", repository_id=repo.id, host_id=host.id,
                            branch="main", build_source="app", environment_id=env.id, slot=slot,
                            published_ports=_published(slot, APP_ROUTES), app_state=_app_state(APP_ROUTES))
            db.add(inst)
            await db.flush()
            db.add(Resource(environment_id=env.id, instance_id=inst.id, provider="digitalocean", kind="droplet",
                            provider_id=str(droplet["id"]), name=name, origin="created",
                            details={"slot": slot, "host_id": str(host.id), "public_ip": ip}))
            droplets[slot], ips[slot] = droplet["id"], ip
        db.add(Resource(environment_id=env.id, provider="digitalocean", kind="certificate", provider_id=cert["id"],
                        name=cert["name"], origin="created",
                        details={"not_after": cert["not_after"], "dns_names": list(cert["dns_names"])}))
        body = do_rules.lb_body("uat", region="nyc3", vpc_uuid=vpc["id"], port=PORT, health=HEALTH,
                                certificate_id=cert["id"])
        lb = fake.add_load_balancer(**body)
        db.add(Resource(environment_id=env.id, provider="digitalocean", kind="load_balancer", provider_id=lb["id"],
                        name=lb["name"], origin="created", details={"ip": lb["ip"], "vpc_id": vpc["id"]}))
        env.cloud = {**env.cloud, "lb_ip": lb["ip"]}
        await db.commit()
        env_id = env.id
    fake.requests.clear()
    return World(fake, multi, env_id, lb["id"], droplets, ips, cert["id"])


async def _set_active(w: World, slot: str | None) -> None:
    async with get_sessionmaker()() as db:
        inst_id = None
        if slot is not None:
            env = await db.get(Environment, w.env_id)
            inst_id = next(i.id for i in (await traffic.members(db, env)).values() if i.slot == slot)
        await db.execute(update(Environment).where(Environment.id == w.env_id).values(active_slot_id=inst_id))
        await db.commit()


async def _deployment(w: World, kind="activate") -> uuid.UUID:
    async with get_sessionmaker()() as db:
        dep = Deployment(environment_id=w.env_id, kind=kind, branch="main", status="running", options={})
        db.add(dep)
        await db.commit()
        return dep.id


async def _ctx(w: World, mode="activate", slot=None, *, include_active=False, deployment_id=None):
    async def say(line):
        w.lines.append(line)

    async with get_sessionmaker()() as db:
        env = await db.get(Environment, w.env_id)
        return await traffic.context(db, env, mode, slot=slot, include_active=include_active,
                                     deployment_id=deployment_id, say=say, connect=w.multi.connect)


async def _switch_record(dep_id) -> dict:
    async with get_sessionmaker()() as db:
        return dict((await db.get(Deployment, dep_id)).options or {}).get("switch") or {}


async def _env(w: World) -> Environment:
    async with get_sessionmaker()() as db:
        return await db.get(Environment, w.env_id)


async def _live_blue(w: World) -> None:
    """Blue is the live slot: recorded active and the load balancer's only target."""
    w.set_targets("blue")
    await _set_active(w, "blue")


# --------------------------------------------------------------------------- the backend


async def test_registered_at_import_with_its_own_lock(world):
    backend = traffic.BACKENDS["do_lb"]
    assert isinstance(backend, do_lb.DoLbBackend)
    assert backend.label == "DigitalOcean" and backend.via == "the load balancer"
    assert backend.errors == (digitalocean.DigitalOceanError,)
    ctx = await _ctx(world, "activate", "green")
    again = await _ctx(world, "deactivate")
    assert backend.lock(ctx) is backend.lock(again) is do_lb.lock_for(world.env_id)
    assert backend.lock(ctx) is not switchyard.lock
    assert traffic.backend_for(await _env(world)) is backend
    removed = await backend.remove(await _ctx(world, "remove"))
    assert removed.notes == [do_lb.GOES_WITH_CLOUD] and not removed.changes
    assert world.fake.requests == []


# --------------------------------------------------------------------------- test 47: the plan


async def test_plan_only_reads(world):
    await _live_blue(world)
    ctx = await _ctx(world, "activate", "green")
    plan = await traffic.BACKENDS["do_lb"].plan(ctx)
    assert plan.blockers == []
    [change] = plan.changes
    assert change.action == "update" and change.external_id == world.lb_id
    assert change.before == {"droplet_ids": [world.droplets["blue"]]}
    assert change.after == {"droplet_ids": [world.droplets["green"]]}
    assert change.summary == (f"slipway-uat-lb → green (droplet {world.droplets['green']}), "
                              f"was blue ({world.droplets['blue']})")
    assert world.fake.requests and all(r["method"] == "GET" for r in world.fake.requests)
    assert {r["path"] for r in world.fake.requests} >= {"/account", f"/load_balancers/{world.lb_id}"}


@pytest.mark.parametrize("case, blocker", [
    ("no_lb", "This environment has no load balancer yet: deploy it first"),
    ("lb_gone", "The load balancer slipway-uat-lb is gone: deploy again to make it"),
    ("renamed", "The load balancer Slipway made for uat is no longer named slipway-uat-lb (it is old-lb now): "
                "Slipway changed nothing"),
    ("busy", "The load balancer is applying a change; try again in a minute"),
    ("droplet_gone", "green's droplet slipway-uat-green is gone: deploy to green to make it again"),
    ("untagged", "green's droplet slipway-uat-green no longer carries Slipway's tags for uat: Slipway changed "
                 "nothing"),
    ("no_droplet", "green has no droplet yet: deploy to green first"),
    ("not_built", "green's server isn't built yet: deploy to green first"),
    ("cert_short", "The certificate doesn't cover wiki.uat.example.com: Renew the certificate first"),
    ("cert_foreign", "The load balancer serves a certificate Slipway didn't record for uat: Renew the "
                     "certificate first"),
    ("foreign_target", "The load balancer sends traffic to droplet {other}, which isn't uat's: Slipway changed "
                       "nothing"),
    ("team", "DO main's token answers for team Other Team, not the team uat was built in: Slipway changed nothing"),
    ("no_token", "DO main has no API token: set it in Settings → Integrations"),
])
async def test_plan_blockers(world, case, blocker):
    w, fake = world, world.fake
    other = None
    async with get_sessionmaker()() as db:
        if case == "no_lb":
            await db.execute(delete(Resource).where(Resource.kind == "load_balancer"))
        elif case == "no_droplet":
            await db.execute(delete(Resource).where(Resource.name == "slipway-uat-green"))
        elif case == "not_built":
            await db.execute(update(Host).where(Host.name == "slipway-uat-green")
                             .values(provider_state={"phase": "creating"}))
        elif case == "cert_short":
            names = [n for n in NAMES if n != "wiki.uat.example.com"]
            await db.execute(update(Resource).where(Resource.kind == "certificate")
                             .values(details={"dns_names": names}))
        elif case == "cert_foreign":
            await db.execute(delete(Resource).where(Resource.kind == "certificate"))
        elif case == "team":
            fake.tokens[TOKEN] = {"uuid": "0" * 32, "name": "Other Team"}
        elif case == "no_token":
            await db.execute(update(ProviderAccount).values(secret=None))
        await db.commit()
    if case == "lb_gone":
        del fake.load_balancers[w.lb_id]
    elif case == "renamed":
        w.lb["name"] = "old-lb"
    elif case == "busy":
        w.lb["status"] = "new"
        fake._polls[("load_balancer", w.lb_id)] = 5
    elif case == "droplet_gone":
        del fake.droplets[w.droplets["green"]]
    elif case == "untagged":
        fake.droplets[w.droplets["green"]]["tags"] = ["slipway"]
    elif case == "foreign_target":
        other = fake.add_droplet(name="someone-else")["id"]
        w.set_targets(other)
    fake.requests.clear()
    ctx = await _ctx(w, "activate", "green")
    plan = await traffic.BACKENDS["do_lb"].plan(ctx)
    assert blocker.format(other=other) in plan.blockers
    assert all(r["method"] == "GET" for r in fake.requests)

    # A switch with a blocker writes nothing and leaves options.switch unwritten.
    dep = await _deployment(w)
    ctx = await _ctx(w, "activate", "green", deployment_id=dep)
    with pytest.raises(traffic.SwitchRefused) as err:
        await traffic.switch(ctx)
    assert str(err.value).endswith("; Slipway changed nothing")
    assert fake.writes() == []
    assert await _switch_record(dep) == {}


async def test_a_gone_recorded_target_is_left_out_of_previous(world):
    """DigitalOcean drops a deleted droplet from its load balancers; an id that is neither recorded nor live is no
    blocker either (an old droplet id after a rebuild)."""
    world.set_targets(9999)
    plan = await traffic.BACKENDS["do_lb"].plan(await _ctx(world, "activate", "blue"))
    assert plan.blockers == []
    assert plan.changes[0].before == {"droplet_ids": []}


# --------------------------------------------------------------------------- test 48: blue to green


async def test_switch_blue_to_green(world, sites, settles):
    w = world
    await _live_blue(w)
    dep = await _deployment(w)
    seen_by_check: list[list[int]] = []

    async def hook(request):
        seen_by_check.append(w.targets())

    sites.hook = hook
    ctx = await _ctx(w, "activate", "green", deployment_id=dep)
    result = await traffic.switch(ctx)
    blue, green = w.droplets["blue"], w.droplets["green"]

    # Join, then drop: the old droplet serves until the new one answered through the load balancer.
    assert w.lb_puts() == [[blue, green], [green]]
    assert w.targets() == [green]
    # Each PUT is a full body made from the live one, sent while active.
    put = next(r["body"] for r in w.fake.requests if r["method"] == "PUT")
    assert "size" not in put and "tag" not in put and put["region"] == "nyc3"
    assert put["forwarding_rules"][0]["certificate_id"] == w.cert_id
    # Green's own health over its session, with a Host outside the app's names; blue isn't asked.
    assert w.health_calls("green") == [do_lb.HEALTH_HOST]
    assert w.health_calls("blue") == []
    cmd = next(c for c in w.multi[w.ips["green"]].remote.commands if "curl" in c)
    assert f"http://127.0.0.1:{PORT}{HEALTH}" in cmd and "Host: slipway-health.invalid" in cmd
    # The settle sleep from the live body, after each PUT.
    assert settles == [SETTLE, SETTLE]
    # The public check through the load balancer's IP, with SNI, while both droplets were targets; verify again.
    ip = w.lb["ip"]
    urls = [httpx.URL(r["url"]) for r in sites.requests]
    assert {(u.scheme, u.host, u.port or 443) for u in urls} == {("https", ip, 443)}
    assert all(r["sni"] == r["host"] and r["verify"] for r in sites.requests)
    assert {r["host"] for r in sites.requests} == set(NAMES)
    assert seen_by_check[0] == [blue, green] and seen_by_check[-1] == [green]
    assert all(sites.asked(n) == 2 for n in NAMES)  # once in apply, once in verify
    assert result.check is not None and result.check.ok and result.warnings == []
    # options.switch.changed saved after each PUT.
    record = await _switch_record(dep)
    assert record["backend"] == "do_lb" and record["from_slot"] == "blue" and record["to_slot"] == "green"
    assert [c["droplet_ids"] for c in record["changed"]] == [[blue, green], [green]]
    assert {c["hostname"] for c in record["changed"]} == {"slipway-uat-lb"}
    # The prove read came after the second PUT.
    paths = [(r["method"], r["path"]) for r in w.fake.requests]
    last_put = max(i for i, p in enumerate(paths) if p[0] == "PUT")
    assert ("GET", f"/load_balancers/{w.lb_id}") in paths[last_put + 1:]
    assert "Plan for uat → green:" in w.lines
    assert not any(TOKEN in line for line in w.lines)
    assert not do_lb.lock_for(w.env_id).locked() and not switchyard.lock.locked()


async def test_staging_certificates_are_not_verified(do, sites, waits, settles, tmp_path):
    w = await _world(do, tmp_path, staging=True)
    await traffic.switch(await _ctx(w, "activate", "blue"))
    assert sites.requests and not any(r["verify"] for r in sites.requests)
    assert any("Let's Encrypt staging" in line for line in w.lines)


async def test_already_the_only_target_writes_nothing(world, sites):
    await _live_blue(world)
    result = await traffic.switch(await _ctx(world, "activate", "blue"))
    assert world.fake.writes() == []
    assert result.plan.changes[0].action == "none"
    assert result.check.ok and sites.requests  # verify still checks the names


async def test_activate_from_a_split_drops_the_other_droplet(world, settles):
    """Both droplets are targets (a split an earlier switch left): Activate green keeps green on and drops blue."""
    w = world
    w.set_targets("blue", "green")
    await _set_active(w, "blue")
    await traffic.switch(await _ctx(w, "activate", "green"))
    blue, green = w.droplets["blue"], w.droplets["green"]
    assert w.lb_puts() == [[blue, green], [green]]
    assert w.targets() == [green]


# --------------------------------------------------------------------------- test 49: put-back


@pytest.fixture
def quick_health(monkeypatch):
    monkeypatch.setattr(do_lb, "HEALTH_TRIES", 3)


async def test_put_back_when_health_fails(world, quick_health, sites):
    w = world
    await _live_blue(w)
    w.multi[w.ips["green"]].env["FAKE_HTTP_CODES"] = f"{do_lb.HEALTH_HOST}=503"
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(w, "activate", "green"))
    blue, green = w.droplets["blue"], w.droplets["green"]
    assert w.lb_puts() == [[blue, green], [blue]]
    assert w.targets() == [blue]
    assert str(err.value) == ("green's droplet didn't pass its health check (/healthz on port 8080) in 30 seconds: "
                              "it answered 503. Traffic stays on blue")
    assert not err.value.unresolved
    assert sites.requests == []  # the public check never ran


async def test_put_back_when_the_public_check_fails(world, sites):
    w = world
    await _live_blue(w)
    sites.codes["wiki.uat.example.com"] = [503]
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(w, "activate", "green"))
    assert w.targets() == [w.droplets["blue"]]
    assert str(err.value) == ("1 of 5 names didn't answer through the load balancer: wiki.uat.example.com. "
                              "Traffic stays on blue")
    # The check outlasts the settle time.
    assert sites.asked("wiki.uat.example.com") == max(traffic.CHECK_ROUNDS, SETTLE // traffic.CHECK_DELAY + 1)


async def test_put_back_when_the_second_put_fails(world, sites):
    w = world
    await _live_blue(w)
    path = f"/load_balancers/{w.lb_id}"

    async def hook(request):
        w.fake.fail[("PUT", path)] = [{"status": 422, "message": "nope"}]

    sites.hook = hook
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(w, "activate", "green"))
    blue, green = w.droplets["blue"], w.droplets["green"]
    assert w.lb_puts() == [[blue, green], [green], [blue]]  # the second was refused; the put-back landed
    assert w.targets() == [blue]
    assert str(err.value).endswith("Traffic stays on blue")


async def test_put_back_when_the_prove_finds_another_target(world, settles, monkeypatch):
    w = world
    await _live_blue(w)
    other = w.fake.add_droplet(name="someone-else")["id"]
    green = w.droplets["green"]

    async def settle(seconds):
        settles.append(seconds)
        if len(settles) == 2:  # after the second PUT, something else adds a target
            w.set_targets(green, other)

    monkeypatch.setattr(do_lb, "sleep", settle)
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(w, "activate", "green"))
    assert str(err.value) == (f"The load balancer's targets changed during the switch (now {green}, {other}): "
                              "something else updated it. Traffic stays on blue")
    assert w.targets() == [w.droplets["blue"]]


async def test_cancel_during_verify_still_puts_back(world, sites, settles):
    w = world
    await _live_blue(w)
    in_verify = asyncio.Event()

    async def hook(request):
        if len(settles) == 2 and w.targets() == [w.droplets["green"]] and sites.asked(request.headers["host"]) > 1:
            in_verify.set()
            await asyncio.Event().wait()  # hangs until cancelled

    sites.hook = hook
    task = asyncio.create_task(traffic.switch(await _ctx(w, "activate", "green")))
    await asyncio.wait_for(in_verify.wait(), 10)
    assert not do_lb.lock_for(w.env_id).locked()  # verify holds no lock
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert w.targets() == [w.droplets["blue"]]
    assert w.lb_puts()[-1] == [w.droplets["blue"]]


async def test_a_failing_put_back_is_unresolved_with_the_by_hand_text(world, sites):
    w = world
    await _live_blue(w)
    dep = await _deployment(w)
    sites.codes["api.uat.example.com"] = [503]
    path = f"/load_balancers/{w.lb_id}"

    async def hook(request):
        w.fake.fail[("PUT", path)] = 422  # every PUT from now on

    sites.hook = hook
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(w, "activate", "green", deployment_id=dep))
    blue = w.droplets["blue"]
    assert err.value.unresolved
    text = str(err.value)
    assert text == ("1 of 5 names didn't answer through the load balancer: api.uat.example.com. Slipway couldn't "
                    f"put 1 of 1 back: point load balancer slipway-uat-lb at blue (droplet {blue}). Check them in "
                    "DigitalOcean, then use Resolve on the environment page")
    env = await _env(w)
    assert env.traffic_state["unresolved"]["message"] == text
    assert env.traffic_state["unresolved"]["to_slot"] == "green"
    assert TOKEN not in text


# --------------------------------------------------------------------------- test 50: first activation, Deactivate


async def test_first_activation(world, settles, sites):
    w = world
    dep = await _deployment(w)
    result = await traffic.switch(await _ctx(w, "activate", "blue", deployment_id=dep))
    blue = w.droplets["blue"]
    assert w.lb_puts() == [[blue]]  # nothing to drop afterwards
    assert w.targets() == [blue]
    assert w.health_calls("blue") == [do_lb.HEALTH_HOST]
    assert settles == [SETTLE]
    assert result.plan.changes[0].summary == f"slipway-uat-lb → blue (droplet {blue}), was no droplet"
    assert [c["droplet_ids"] for c in (await _switch_record(dep))["changed"]] == [[blue]]


async def test_first_activation_is_put_back_on_failure(world, sites):
    w = world
    sites.codes["uat.example.com"] = [502]
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(w, "activate", "blue"))
    assert w.lb_puts() == [[w.droplets["blue"]], []]
    assert w.targets() == []
    assert str(err.value).endswith("Nothing was live before; Slipway put back what it had written")


async def test_deactivate_empties_the_targets_and_runs_no_public_check(world, sites, settles):
    w = world
    await _live_blue(w)
    dep = await _deployment(w, "deactivate")
    ctx = await _ctx(w, "deactivate", deployment_id=dep)
    assert ctx.to_slot is None and ctx.from_slot == "blue"
    result = await traffic.switch(ctx)
    assert w.lb_puts() == [[]]
    assert w.targets() == []
    assert sites.requests == []  # the names answer 503 by design: never checked
    assert settles == [] and w.health_calls("blue") == []
    assert result.check.ok
    assert result.plan.changes[0].summary == f"slipway-uat-lb → no droplet, was blue ({w.droplets['blue']})"
    record = await _switch_record(dep)
    assert record["to_slot"] is None and [c["droplet_ids"] for c in record["changed"]] == [[]]
    assert "Checking that the load balancer sends no traffic to blue" in w.lines


async def test_deactivate_is_put_back_on_failure(world, sites, monkeypatch):
    w = world
    await _live_blue(w)
    green = w.droplets["green"]
    handler = w.fake.handler

    def intruder(request: httpx.Request) -> httpx.Response:
        resp = handler(request)
        if request.method == "PUT" and not w.targets():  # right after Slipway's PUT, someone adds green
            w.set_targets(green)
        return resp

    monkeypatch.setattr(digitalocean, "transport_factory", lambda: httpx.MockTransport(intruder))
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(w, "deactivate"))
    assert str(err.value) == (f"The load balancer's targets changed during the switch (now {green}): something "
                              "else updated it. Traffic stays on blue")
    assert w.targets() == [w.droplets["blue"]]
    assert sites.requests == []


async def test_deactivate_verify_fails_when_targets_come_back(world, sites, monkeypatch):
    w = world
    await _live_blue(w)
    real = do_lb.DoLbBackend.apply

    async def apply_then_intrude(self, ctx, plan):
        applied = await real(self, ctx, plan)
        w.set_targets("green")
        return applied

    monkeypatch.setattr(do_lb.DoLbBackend, "apply", apply_then_intrude)
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(await _ctx(w, "deactivate"))
    assert str(err.value).startswith(f"The load balancer slipway-uat-lb still sends traffic to green ("
                                     f"{w.droplets['green']})")
    assert w.targets() == [w.droplets["blue"]]
    assert sites.requests == []


@pytest.mark.parametrize("targets, live", [(("blue",), ["blue"]), (("blue", "green"), ["blue", "green"]),
                                           ((), [])])
async def test_who_is_live(world, targets, live):
    world.set_targets(*targets)
    assert await traffic.BACKENDS["do_lb"].who_is_live(await _ctx(world, "sync")) == live
    assert world.fake.writes() == []


async def test_who_is_live_refuses_a_droplet_that_isnt_ours(world):
    other = world.fake.add_droplet(name="someone-else")["id"]
    world.set_targets("blue", other)
    with pytest.raises(traffic.TrafficError, match=f"droplet {other}, which isn't uat's"):
        await traffic.BACKENDS["do_lb"].who_is_live(await _ctx(world, "sync"))


# --------------------------------------------------------------------------- test 79: the sync repair


async def _sync(w: World, *, include_active=True) -> traffic.SyncResult:
    return await traffic.sync(await _ctx(w, "sync", include_active=include_active))


async def test_sync_repair_puts_the_active_slot_back(world, sites, settles):
    w = world
    await _set_active(w, "blue")
    result = await _sync(w)
    blue = w.droplets["blue"]
    assert w.lb_puts() == [[blue]]
    assert w.targets() == [blue]
    assert w.health_calls("blue") == [do_lb.HEALTH_HOST]
    assert settles == [SETTLE]
    assert {r["host"] for r in sites.requests} == set(NAMES)
    assert result.warnings == [] and result.applied.did_apply and result.check.ok
    # The prove read follows the PUT.
    paths = [(r["method"], r["path"]) for r in w.fake.requests]
    assert paths[-1] == ("GET", f"/load_balancers/{w.lb_id}")
    assert not do_lb.lock_for(w.env_id).locked()


async def test_sync_repair_replaces_a_gone_droplet_id(world, sites):
    """The active slot's old droplet id after a rebuild: gone, so the load balancer has no live target."""
    w = world
    await _set_active(w, "blue")
    w.set_targets(9999)
    result = await _sync(w)
    assert w.lb_puts() == [[w.droplets["blue"]]]
    assert result.warnings == []


async def test_sync_with_the_active_slot_the_only_target_writes_nothing(world, sites, settles):
    w = world
    await _live_blue(w)
    result = await _sync(w)
    assert w.fake.writes() == []
    assert settles == [] and w.health_calls("blue") == []
    assert all(sites.asked(n) == 1 for n in NAMES)  # one round
    assert result.warnings == [] and result.check.ok


async def test_sync_never_adds_the_other_slots_droplet(world, sites):
    w = world
    await _set_active(w, "blue")
    w.set_targets("green")
    result = await _sync(w)
    assert w.fake.writes() == []
    assert w.targets() == [w.droplets["green"]]
    assert (f"The load balancer sends traffic to green ({w.droplets['green']}), but blue is the live slot: "
            "activate one of them") in result.warnings


async def test_sync_writes_nothing_with_nothing_active(world, sites):
    result = await _sync(world)
    assert world.fake.requests == []
    assert result.warnings == [] and result.applied is None


async def test_sync_repair_is_skipped_while_a_switch_is_unresolved(world, sites):
    w = world
    await _set_active(w, "blue")
    async with get_sessionmaker()() as db:
        await db.execute(update(Environment).where(Environment.id == w.env_id).values(
            traffic_state={"unresolved": {"message": "split", "from_slot": "blue", "to_slot": "green"}}))
        await db.commit()
    await _sync(w)
    assert w.fake.requests == []
    assert w.targets() == []


async def test_sync_repair_failing_public_check_is_a_warning(world, sites):
    w = world
    await _set_active(w, "blue")
    sites.codes["learn.uat.example.com"] = [503]
    result = await _sync(w)
    assert w.targets() == [w.droplets["blue"]]  # nothing answered before either: nothing is put back
    assert result.warnings == ["1 of 5 names didn't answer through the load balancer: learn.uat.example.com"]


async def test_sync_repair_failing_health_is_a_warning(world, sites, quick_health):
    w = world
    await _set_active(w, "blue")
    w.multi[w.ips["blue"]].env["FAKE_HTTP_CODES"] = f"{do_lb.HEALTH_HOST}=500"
    result = await _sync(w)
    assert w.targets() == [w.droplets["blue"]]
    assert result.warnings == ["blue's droplet didn't pass its health check (/healthz on port 8080) in 30 seconds: "
                               "it answered 500"]


async def test_sync_repair_failing_prove_raises(world, sites, settles, monkeypatch):
    w = world
    await _set_active(w, "blue")

    async def settle(seconds):
        settles.append(seconds)
        w.set_targets("blue", "green")

    monkeypatch.setattr(do_lb, "sleep", settle)
    with pytest.raises(traffic.SwitchFailed, match="targets changed during the switch"):
        await _sync(w)


async def test_sync_repair_blocker_is_a_warning(world, sites):
    w = world
    await _set_active(w, "blue")
    del w.fake.load_balancers[w.lb_id]
    result = await _sync(w)
    assert result.warnings == ["The load balancer slipway-uat-lb is gone: deploy again to make it"]
    assert w.fake.writes() == []


async def test_plan_for_does_not_ask_for_switchyard(world):
    await _live_blue(world)
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, world.env_id)
        dry = await traffic.plan_for(env, "green", db)
        sync = await traffic.plan_for(env, None, db)
    assert dry["switch"]["backend"] == "do_lb" and dry["switch"]["blockers"] == []
    assert dry["switch"]["changes"][0]["after"] == {"droplet_ids": [world.droplets["green"]]}
    assert sync["switch"]["changes"] == [] and sync["switch"]["blockers"] == []
    assert world.fake.writes() == []
