"""Phase 3 fix group 3: the names DNS publishes and other instances can't take, and Cloudflare zone changes.

F10/F11/F14: a deploy to the idle slot (or a PATCH) no longer takes a name away from the live slot: DNS
publishes, and hostname uniqueness reserves, every name a member's live release serves, and switching back
finds the records of the slot it goes back to. F24/F31: the zone can't change under recorded records, each
record is read, changed and deleted in the zone its row names, and a 404 about the zone is never taken to mean
the record is gone. F43: turning DNS off removes the records, and Cloudflare can't be removed while Slipway
keeps records there.

Cloudflare and Switchyard are the fakes; hosts are MultiRemote's shells. Nothing leaves the machine.
"""

from __future__ import annotations

import types
import uuid

import httpx
import pytest
from sqlalchemy import select, update

from slipway.db.session import get_sessionmaker
from slipway.models import AppSetting, AuditEvent, Environment, Instance, Resource
from slipway.services import cloudflare, deployer, environments, resources, traffic
from tests.fake_cloudflare import TOKEN, ZONE
from tests.fake_hosts import ENV_YML, github, seed_env
from tests.test_data_api import clients, storage  # noqa: F401  (storage: autouse)
from tests.test_env_jobs import (  # noqa: F401  (fixtures)
    DNS,
    SWITCHYARD,
    _job,
    cf,
    multi,
    no_waits,
    sites,
    submitted,
    sy,
)
from tests.test_env_pipeline import _deploy, _get
from tests.test_traffic import APP_ROUTES, _env, _env_obj, _rows, _set_active, _slot

WIKI = "wiki.uat.example.com"
ADMIN = "admin.uat.example.com"
WITH_ADMIN = ENV_YML.replace(
    '  files: {port: 9000, port_var: APP_FILES_PORT, hostname: "files.{APP_DOMAIN}"}\n',
    '  files: {port: 9000, port_var: APP_FILES_PORT, hostname: "files.{APP_DOMAIN}"}\n'
    '  admin: {port: 8081, port_var: APP_ADMIN_PORT, hostname: "admin.{APP_DOMAIN}"}\n')


def _routes(*, without: str | None = None) -> list[dict]:
    return [{"hostname": h, "service": s, "container": c} for h, s, c, _ in APP_ROUTES if h != without]


async def _went_live(env_id: uuid.UUID, slot: str, routes: list[dict]) -> None:
    """What a deploy of ``slot`` records at finish: its routes, then ``_member_went_live``."""
    inst = await _slot(env_id, slot)
    async with get_sessionmaker()() as db:
        await db.execute(update(Instance).where(Instance.id == inst.id)
                         .values(app_state={**(inst.app_state or {}), "routes": routes}))
        await db.commit()
    inst = await _slot(env_id, slot)
    job = types.SimpleNamespace(environment=await _env_obj(env_id), data_owner=inst, data_app=False, identity=None,
                                kind="deploy", deployment_id=uuid.uuid4())
    await deployer._member_went_live(job, inst, {"routes": routes, "manifest": {}})


def _names(env: Environment) -> set[str]:
    return {h["hostname"] for h in env.hostnames}


# ------------------------------------------------------------------ F10, F11, F14: wanted names


async def test_an_idle_slot_deploy_keeps_the_live_slots_names_and_records(cf):
    env_id = await _env(dns=DNS, switch="none")
    await _set_active(env_id, "blue")
    await traffic.publish_dns(await _env_obj(env_id))
    assert cf.named(WIKI)
    # green (idle) goes live with a release that no longer routes wiki; blue still serves it.
    await _went_live(env_id, "green", _routes(without=WIKI))
    env = await _env_obj(env_id)
    assert WIKI in _names(env)
    plan = await traffic.publish_dns(env)  # what Publish names and a data server deploy's dns step run
    assert not [c for c in plan.changes if c.action == "delete"]
    assert cf.named(WIKI)


async def test_a_name_nothing_live_serves_still_leaves(cf):
    env_id = await _env(dns=DNS, switch="none")
    await _set_active(env_id, "blue")
    await _went_live(env_id, "blue", _routes(without=WIKI))  # blue's release drops wiki: only green has it
    assert WIKI in _names(await _env_obj(env_id))
    await _went_live(env_id, "green", _routes(without=WIKI))  # and now green's too
    env = await _env_obj(env_id)
    assert WIKI not in _names(env)
    await traffic.publish_dns(env)
    assert cf.named(WIKI) == []
    assert cf.named("api.uat.example.com")


async def test_dns_publishes_what_the_slots_serve_even_when_hostnames_lost_a_name(cf):
    """env.hostnames left wiki out (as an idle deploy used to write it): the name blue serves is still published,
    so a switch back to blue finds its record."""
    env_id = await _env(dns=DNS, switch="none")
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, env_id)
        env.hostnames = [h for h in env.hostnames if h["hostname"] != WIKI]
        await db.commit()
    await _went_live(env_id, "green", _routes(without=WIKI))
    await traffic.publish_dns(await _env_obj(env_id))
    assert cf.named(WIKI), "blue's release serves wiki"


async def test_names_a_slot_serves_stay_reserved(cf):
    env_id = await _env(dns=DNS, switch="none")
    await _set_active(env_id, "blue")
    await _went_live(env_id, "green", _routes(without=WIKI))
    # Even with env.hostnames emptied, what the slots' releases serve stays the environment's.
    async with get_sessionmaker()() as db:
        await db.execute(update(Environment).where(Environment.id == env_id).values(hostnames=[]))
        await db.commit()
    async with get_sessionmaker()() as db:
        assert await environments.environment_with_hostname(db, [WIKI]) == f"{WIKI} is a hostname of environment uat"
        assert await environments.hostname_conflict(db, [WIKI], environment_id=uuid.uuid4()) == \
            f"{WIKI} is already a hostname of environment uat"
        assert await environments.hostname_conflict(db, [WIKI], environment_id=env_id) is None


async def test_an_idle_deploy_then_publish_keeps_the_active_slots_record(multi, submitted, sy, cf):
    seeded = await seed_env(multi, traffic={**SWITCHYARD, "dns": DNS})
    for slot in ("data", "blue"):
        dep = await _deploy(multi, seeded, slot, gh=github(WITH_ADMIN))
        assert dep.status == "succeeded", (slot, dep.error)
    assert (await _job(multi, seeded, "activate", slot="blue")).status == "succeeded"
    assert cf.named(ADMIN) and ADMIN in sy.hosts_by_domain()
    dep = await _deploy(multi, seeded, "green", gh=github(ENV_YML))  # a release without admin, to the idle slot
    assert dep.status == "succeeded", dep.error
    env = await _get(Environment, seeded.env_id)
    assert env.active_slot_id == seeded.ids["blue"] and ADMIN in _names(env)
    pub = await _job(multi, seeded, "publish")
    assert pub.status in ("succeeded", "warning"), pub.error
    assert cf.named(ADMIN), "blue is live and serves admin"
    assert ADMIN in sy.hosts_by_domain()


async def test_activate_and_switch_back_keep_every_record_of_the_slot_that_serves_it(multi, submitted, sy, cf):
    seeded = await seed_env(multi, traffic={**SWITCHYARD, "dns": DNS})
    for slot in ("data", "blue"):
        assert (await _deploy(multi, seeded, slot, gh=github(WITH_ADMIN))).status == "succeeded"
    assert (await _job(multi, seeded, "activate", slot="blue")).status == "succeeded"
    assert (await _deploy(multi, seeded, "green", gh=github(ENV_YML))).status == "succeeded"
    act = await _job(multi, seeded, "activate", slot="green")
    assert act.status == "succeeded", act.error
    assert ADMIN not in sy.hosts_by_domain()
    assert cf.named(ADMIN), "blue, which a switch back goes to, still serves admin"
    back = await _job(multi, seeded, "activate", slot="blue", back=True)
    assert back.status == "succeeded", back.error
    assert ADMIN in sy.hosts_by_domain()
    assert cf.named(ADMIN)


async def test_a_patch_keeps_the_names_a_live_release_serves(make_client, cf, monkeypatch):
    from tests.test_env_rules import FILES, _reader, _world

    monkeypatch.setattr(environments, "github_reader", lambda user: _reader(dict(FILES)))
    c = await clients(make_client)
    ids = await _world()
    async with get_sessionmaker()() as db:
        blue = await db.get(Instance, ids["blue"])
        blue.app_state = {**blue.app_state, "routes": [{"hostname": ADMIN, "service": "api", "container": 8000}]}
        env = await db.get(Environment, ids["env"])  # as blue's deploy wrote them at finish
        env.hostnames = [{"hostname": ADMIN, "service": "api", "container": 8000, "follows": "active",
                          "health": "/"}]
        await db.commit()
    r = await c["maintainer"].patch(f"/api/v1/environments/{ids['env']}",
                                    json={"settings": {"STACK_DOMAIN": "uat2.example.com",
                                                       "STACK_PROXY_IP": "10.0.0.2"}})
    assert r.status_code == 200, r.text
    names = {h["hostname"] for h in r.json()["hostnames"]}
    assert ADMIN in names, "blue's live release still serves it"
    assert "api.uat2.example.com" in names


# -------------------------------------------------------------- F24, F31: the zone of each record


async def test_a_zone_change_is_refused_while_records_are_kept(make_client, cf):
    c = await clients(make_client)
    env_id = await _env(dns=DNS, switch="none")
    await traffic.publish_dns(await _env_obj(env_id))
    assert len(cf.records) == 6
    cf.add_zone("uat.example.com")
    r = await c["admin"].put("/api/v1/settings/cloudflare", json={"zone": "uat.example.com", "token": TOKEN,
                                                                  "public_ip": "203.0.113.7"})
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == ("Environments uat keep DNS records in the Cloudflare zone example.com; turn DNS off "
                                  "on them first (Slipway removes their records, or forgets them when their "
                                  "zone is gone), then change the zone")
    async with get_sessionmaker()() as db:
        assert (await cloudflare.load_config(db)).zone == ZONE
    # The same zone, its public IP changed: fine.
    r = await c["admin"].put("/api/v1/settings/cloudflare", json={"zone": ZONE, "public_ip": "203.0.113.8"})
    assert r.status_code == 200, r.text
    # Once the records are gone, the zone can change.
    await traffic.remove_dns(await _env_obj(env_id))
    r = await c["admin"].put("/api/v1/settings/cloudflare", json={"zone": "uat.example.com", "public_ip": ""})
    assert r.status_code == 200, r.text


async def test_a_token_that_finds_another_zone_is_refused(make_client, cf):
    c = await clients(make_client)
    env_id = await _env(dns=DNS, switch="none")
    await traffic.publish_dns(await _env_obj(env_id))
    async with get_sessionmaker()() as db:  # the records were made in a zone this token doesn't find
        for row in await resources.owned(db, env_id, cloudflare.PROVIDER, cloudflare.KIND):
            row.details = {**row.details, "zone_id": "0" * 32}
        await db.commit()
    r = await c["admin"].put("/api/v1/settings/cloudflare", json={"zone": ZONE, "public_ip": "203.0.113.7"})
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == ("Environments uat keep DNS records in another Cloudflare zone; turn DNS off on them "
                                  "first (Slipway removes their records, or forgets them when their zone is gone), "
                                  "or use a token that sees the zone they are in")


async def test_records_are_deleted_in_the_zone_their_rows_name(cf):
    env_id = await _env(dns=DNS, switch="none")
    await traffic.publish_dns(await _env_obj(env_id))
    assert len(cf.records) == 6
    other = cf.add_zone("example.org")
    async with get_sessionmaker()() as db:  # the setting now names another zone (as a save used to allow)
        row = await db.scalar(select(AppSetting).where(AppSetting.key == cloudflare.SETTING_KEY))
        row.value = {**row.value, "zone": "example.org", "zone_id": other}
        await db.commit()
    plan = await traffic.remove_dns(await _env_obj(env_id))
    assert {c.action for c in plan.changes} == {"delete"}
    assert cf.records == {}
    assert await _rows(env_id, cloudflare.PROVIDER, cloudflare.KIND) == {}


async def test_a_404_about_the_zone_is_not_a_record_that_is_gone(cf):
    zid = cf.zones[0]["id"]
    rec = cf.add_record(zid, "A", "x.example.com", "203.0.113.7")
    async with cloudflare.CloudflareClient(TOKEN) as client:
        assert await client.get_record(zid, "f" * 32) is None  # 81044: the record doesn't exist
        assert await client.delete_record(zid, "f" * 32) is False
        for call in (client.get_record("e" * 32, rec["id"]), client.delete_record("e" * 32, rec["id"])):
            with pytest.raises(cloudflare.CloudflareError) as err:  # 7003: the zone isn't known
                await call
            assert not isinstance(err.value, cloudflare.RecordGone)
            assert "doesn't know that zone" in str(err.value) and TOKEN not in str(err.value)
    assert rec["id"] in cf.records


async def test_teardown_keeps_its_rows_when_the_rows_zone_is_unknown(cf):
    env_id = await _env(dns=DNS, switch="none")
    await traffic.publish_dns(await _env_obj(env_id))
    async with get_sessionmaker()() as db:
        for row in await resources.owned(db, env_id, cloudflare.PROVIDER, cloudflare.KIND):
            row.details = {**row.details, "zone_id": "e" * 32}
        await db.commit()
    with pytest.raises(cloudflare.CloudflareError):
        await traffic.remove_dns(await _env_obj(env_id))
    assert len(await _rows(env_id, cloudflare.PROVIDER, cloudflare.KIND)) == 6
    assert len(cf.records) == 6


# ------------------------------------------------------------------------ F43: turning DNS off


async def test_turning_dns_off_removes_the_records_first(make_client, cf):
    c = await clients(make_client)
    env_id = await _env(mode="slot", slots=("blue",), dns=DNS, switch="none")
    zid = cf.zones[0]["id"]
    theirs = cf.add_record(zid, "A", "old.uat.example.com", "198.51.100.9", comment="ops")
    await traffic.publish_dns(await _env_obj(env_id))
    await resources.record(env_id, cloudflare.PROVIDER, cloudflare.KIND, theirs["id"], "old.uat.example.com",
                           "claimed", {"zone_id": zid, "type": "A", "content": "198.51.100.9", "proxied": False})
    assert len(await _rows(env_id, cloudflare.PROVIDER, cloudflare.KIND)) == 7
    r = await c["maintainer"].patch(f"/api/v1/environments/{env_id}",
                                    json={"traffic": {"switch": "none", "dns": None}})
    assert r.status_code == 200, r.text
    assert r.json()["traffic"]["dns"] is None
    assert await _rows(env_id, cloudflare.PROVIDER, cloudflare.KIND) == {}
    assert list(cf.records) == [theirs["id"]], "the claimed record stays in Cloudflare; the rest are deleted"
    async with get_sessionmaker()() as db:
        event = (await db.scalars(select(AuditEvent).where(AuditEvent.action == "environment.update"))).all()[-1]
    assert "DNS records removed (6 deleted, 1 left in Cloudflare and forgotten)" in event.summary
    # Nothing is kept now, so Cloudflare can be removed.
    r = await c["admin"].put("/api/v1/settings/cloudflare", json={"clear": True})
    assert r.status_code == 200, r.text


async def test_dns_stays_on_when_its_records_cant_be_removed(make_client, cf):
    c = await clients(make_client)
    env_id = await _env(mode="slot", slots=("blue",), dns=DNS, switch="none")
    await traffic.publish_dns(await _env_obj(env_id))
    cf.deny = {"DELETE"}
    r = await c["maintainer"].patch(f"/api/v1/environments/{env_id}",
                                    json={"traffic": {"switch": "none", "dns": None}})
    assert r.status_code == 502, r.text
    assert r.json()["field"] == "traffic.dns" and TOKEN not in r.text
    assert "DNS stays on for uat" in r.json()["detail"]
    assert (await _env_obj(env_id)).traffic["dns"] == DNS
    assert len(await _rows(env_id, cloudflare.PROVIDER, cloudflare.KIND)) == 6


async def test_cloudflare_cant_be_removed_while_records_are_kept(make_client, cf):
    from slipway.api.v1 import settings as st

    c = await clients(make_client)
    env_id = await _env(dns=DNS, switch="none")
    await traffic.publish_dns(await _env_obj(env_id))
    async with get_sessionmaker()() as db:  # DNS turned off some other way: the rows are still there
        await db.execute(update(Environment).where(Environment.id == env_id)
                         .values(traffic={"switch": "none", "dns": None}))
        await db.commit()
    async with get_sessionmaker()() as db:
        assert await st._dns_users(db) == ["uat"]
    r = await c["admin"].put("/api/v1/settings/cloudflare", json={"clear": True})
    assert r.status_code == 409
    assert r.json()["detail"] == "Environments uat publish DNS records through Cloudflare; turn that off on them first"
    async with get_sessionmaker()() as db:
        assert await cloudflare.load_config(db) is not None
        assert len(list(await db.scalars(select(Resource).where(Resource.environment_id == env_id)))) == 6
