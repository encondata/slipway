"""Review fixes for the traffic backends and the ACME account key (phase 4 §3.8, §11.6).

* F6: a key stored for a directory whose old key was lost (``--clear-unreadable`` set the secret to NULL)
  drops the old ``kid``, so the next order registers the new key instead of signing with the old account.
* F10: ``do_lb``'s public check asks every name over HTTPS with the certificate verified, whatever the
  route's Switchyard TLS mode (``route_tls``, Switchyard's default) says.
* F32: the switch waits for a ``do_lb`` put-back as long as that put-back can take (two waits for the load
  balancer to be active), so a slow but good put-back isn't reported as unresolved.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from sqlalchemy import select, update

from slipway.db.session import get_sessionmaker
from slipway.models import AppSetting, Environment
from slipway.services import acme, acme_store, certs, cloudflare, digitalocean, do_lb, traffic
from slipway.services.cloudflare import CloudflareClient
from tests.fake_acme import FakeAcme, FakeCloudflareTxt
from tests.fake_cloudflare import TOKEN as CF_TOKEN
from tests.fake_cloudflare import FakeCloudflare
from tests.test_do_lb import (  # noqa: F401  (fixtures)
    NAMES,
    _ctx,
    _deployment,
    _env,
    _live_blue,
    do,
    settles,
    sites,
    waits,
    world,
)

# --------------------------------------------------------------------------- F6: the ACME account key

ACME_NAMES = ["api.shop.example.com"]


@pytest.fixture
def cf(monkeypatch):
    fake = FakeCloudflare()
    monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(fake.handle))
    return fake


@pytest.fixture
def acme_world(monkeypatch, cf):
    zone_id = cf.add_zone("example.com")
    server = FakeAcme(FakeCloudflareTxt(cf, zone_id).lookup)
    monkeypatch.setattr(acme, "transport_factory", lambda: httpx.MockTransport(server.handle))

    async def no_wait(_seconds):
        return None

    monkeypatch.setattr(certs, "sleep", no_wait)
    monkeypatch.setattr(acme, "sleep", no_wait)
    return server, zone_id


async def _acme_row() -> AppSetting:
    async with get_sessionmaker()() as db:
        return await db.scalar(select(AppSetting).where(AppSetting.key == acme_store.SETTING_KEY))


async def test_a_regenerated_key_registers_a_new_account_and_issues(acme_world):
    server, zone_id = acme_world
    keys = acme_store.AccountKeys()
    async with CloudflareClient(CF_TOKEN) as client:
        txt = acme_store.TxtRecords(client, zone_id)
        await certs.issue(ACME_NAMES, directory=server.directory_url, keys=keys, txt=txt)
        assert server.registrations == 1
        old_kid = (await _acme_row()).value["accounts"][server.directory_url]["kid"]
        # What rotate-encryption-key --clear-unreadable does to the row: the secret goes, the value stays.
        async with get_sessionmaker()() as db:
            await db.execute(update(AppSetting).where(AppSetting.key == acme_store.SETTING_KEY).values(secret=None))
            await db.commit()
        issued = await certs.issue(ACME_NAMES, directory=server.directory_url, keys=keys, txt=txt)
    assert issued.leaf and issued.dns_names == ACME_NAMES
    assert server.registrations == 2  # the new key got an account of its own
    new_kid = (await _acme_row()).value["accounts"][server.directory_url]["kid"]
    assert new_kid and new_kid != old_kid


async def test_storing_a_key_drops_only_that_directorys_kid():
    keys = acme_store.AccountKeys()
    first = await keys.put_if_absent("https://a.example/dir", "PEM-A")
    await keys.remember_kid("https://a.example/dir", "https://a.example/acct/1")
    await keys.put_if_absent("https://b.example/dir", "PEM-B")
    await keys.remember_kid("https://b.example/dir", "https://b.example/acct/9")
    assert first.kid is None
    # An existing key keeps its kid.
    again = await keys.put_if_absent("https://a.example/dir", "PEM-OTHER")
    assert (again.pem, again.kid) == ("PEM-A", "https://a.example/acct/1")
    # The secret is cleared: a new key for a drops a's kid and leaves b's account entry alone.
    async with get_sessionmaker()() as db:
        await db.execute(update(AppSetting).where(AppSetting.key == acme_store.SETTING_KEY).values(secret=None))
        await db.commit()
    fresh = await keys.put_if_absent("https://a.example/dir", "PEM-NEW")
    assert (fresh.pem, fresh.kid) == ("PEM-NEW", None)
    accounts = (await _acme_row()).value["accounts"]
    assert "https://a.example/dir" not in accounts
    assert accounts["https://b.example/dir"] == {"kid": "https://b.example/acct/9"}


# --------------------------------------------------------------------------- F10: do_lb's public check TLS


async def test_do_lb_checks_https_with_verification_whatever_route_tls_says(world, sites):
    w = world
    await _live_blue(w)
    off, internal = NAMES[0], NAMES[1]
    async with get_sessionmaker()() as db:
        await db.execute(update(Environment).where(Environment.id == w.env_id)
                         .values(route_tls={off: "off", internal: "internal"}))
        await db.commit()
    ctx = await _ctx(w, "activate", "green", deployment_id=await _deployment(w))
    await traffic.switch(ctx)
    asked = list(sites.requests)
    assert {r["host"] for r in asked} == set(NAMES)
    assert all(r["url"].startswith("https://") for r in asked), [r["url"] for r in asked]
    assert all(r["verify"] is True for r in asked)
    assert not any("internal certificate" in line for line in w.lines)


async def test_do_lb_checks_with_verification_when_switchyards_default_is_internal(world, sites):
    w = world
    await _live_blue(w)
    async with get_sessionmaker()() as db:
        db.add(AppSetting(key="switchyard", value={"default_tls_mode": "internal"}, secret=None))
        await db.commit()
    ctx = await _ctx(w, "activate", "green", deployment_id=await _deployment(w))
    assert {r.tls_mode for r in ctx.routes} == {"internal"}  # Switchyard's routes are unchanged
    await traffic.switch(ctx)
    assert sites.requests
    assert all(r["verify"] is True and r["url"].startswith("https://") for r in sites.requests)


async def test_do_lb_sync_check_also_verifies(world, sites):
    w = world
    await _live_blue(w)
    async with get_sessionmaker()() as db:
        await db.execute(update(Environment).where(Environment.id == w.env_id)
                         .values(route_tls={NAMES[0]: "off"}))
        await db.commit()
    result = await traffic.sync(await _ctx(w, "sync", include_active=True))
    assert result.check is not None and result.check.ok
    assert sites.requests and all(r["verify"] is True and r["url"].startswith("https://")
                                  for r in sites.requests)


# --------------------------------------------------------------------------- F32: the put-back wait


def test_do_lb_put_back_timeout_outlasts_two_active_waits():
    backend = traffic.BACKENDS["do_lb"]
    assert backend.put_back_timeout >= 2 * do_lb.ACTIVE_WAIT + 3 * digitalocean.TIMEOUT
    assert backend.put_back_timeout > traffic.PUT_BACK_TIMEOUT
    assert not hasattr(traffic.BACKENDS["switchyard"], "put_back_timeout")  # Switchyard keeps P3's 120 s


async def test_a_slow_good_do_lb_put_back_leaves_the_switch_resolved(world, sites, monkeypatch):
    """The join PUT lands but the load balancer stays busy past 3 minutes, so apply fails; the put-back waits
    for it again and puts blue back. It takes longer than PUT_BACK_TIMEOUT (scaled down here), but finishes."""
    w = world
    await _live_blue(w)
    dep = await _deployment(w)
    monkeypatch.setattr(traffic, "PUT_BACK_TIMEOUT", 0.05)  # stands in for P3's 120 s
    fake_sleep = w.fake.sleep

    async def slow_sleep(seconds):  # each poll also takes a little real time
        await asyncio.sleep(0.02)
        await fake_sleep(seconds)

    monkeypatch.setattr(digitalocean, "sleep", slow_sleep)
    key = ("load_balancer", w.lb_id)
    ctx = await _ctx(w, "activate", "green", deployment_id=dep)
    say = ctx.say
    busy = {"set": False}

    async def watch(line):
        await say(line)
        if not busy["set"] and "now sends traffic to" in line:
            busy["set"] = True
            w.fake._polls[key] = 25  # 19 polls fail apply's 3-minute wait; the put-back's wait gets the rest

    ctx.say = watch
    with pytest.raises(traffic.SwitchFailed) as err:
        await traffic.switch(ctx)
    blue, green = w.droplets["blue"], w.droplets["green"]
    assert w.lb_puts() == [[blue, green], [blue]]
    assert w.targets() == [blue]
    assert not err.value.unresolved
    assert str(err.value).endswith("Traffic stays on blue"), str(err.value)
    env = await _env(w)
    assert not (env.traffic_state or {}).get("unresolved")
