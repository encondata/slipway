"""plan_dns checks Slipway's comment (marker) on Cloudflare records (review findings F23, F42).

F23: a record Slipway created and recorded is changed only while it still carries the environment's comment (I7);
a record someone took over in Cloudflare is a blocker, not an update. Claimed records keep being kept current.
F42: a lone A record carrying this environment's comment that no row holds (a create whose answer was lost) is
``adopt``, not ``claimable``, so it no longer blocks every publish.
"""

from __future__ import annotations

import uuid

import httpx
import pytest

from slipway.services import cloudflare, traffic
from slipway.services.cloudflare import plan_dns
from tests.fake_cloudflare import ZONE, FakeCloudflare
from tests.test_traffic import DNS, _cloudflare, _env, _env_obj, _rows

ENV = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER = uuid.UUID("22222222-2222-2222-2222-222222222222")
IP, IP2 = "203.0.113.10", "203.0.113.99"
WANT = {"content": IP, "proxied": False}
MINE = cloudflare.comment_for("uat", ENV)


def rec(name: str, content: str = IP, *, type: str = "A", comment: str | None = None) -> dict:
    return {"id": uuid.uuid4().hex, "type": type, "name": name, "content": content, "proxied": False,
            "comment": comment, "ttl": 1}


def row(name: str, record_id: str, *, env: uuid.UUID = ENV, origin: str = "created") -> dict:
    return {"id": uuid.uuid4(), "environment_id": env, "provider_id": record_id, "name": name, "origin": origin}


def plan(wanted, records=(), *, rows=()):
    by_name: dict[str, list[dict]] = {}
    for r in records:
        by_name.setdefault(r["name"], []).append(r)
    return plan_dns(wanted, by_name, {}, list(rows), ENV, zone=ZONE)


def only(p) -> cloudflare.DnsChange:
    assert len(p.changes) == 1, p.changes
    return p.changes[0]


@pytest.fixture
def cf(monkeypatch):
    fake = FakeCloudflare()
    monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(fake.handle))
    return fake


# ------------------------------------------------------------------------- F23


@pytest.mark.parametrize("comment", ["ops: moved to the new LB", None, cloudflare.comment_for("prod", OTHER)])
def test_created_record_without_our_comment_is_a_blocker(comment):
    taken = rec("api.example.com", IP2, comment=comment)
    r = row("api.example.com", taken["id"])
    p = plan({"api.example.com": WANT}, [taken], rows=[r])
    c = only(p)
    assert c.status == cloudflare.CONFLICT and c.after is None
    assert "someone took this record over in Cloudflare" in c.message
    assert p.blockers == [c.message] and not p.writes
    # Even when it already points where Slipway would point it: it isn't Slipway's to call up to date.
    same = {**taken, "content": IP}
    assert only(plan({"api.example.com": WANT}, [same], rows=[r])).status == cloudflare.CONFLICT


def test_marked_created_record_and_claimed_records_still_update():
    ours = rec("api.example.com", comment=MINE)
    assert only(plan({"api.example.com": WANT}, [ours], rows=[row("api.example.com", ours["id"])])).status == "ok"
    moved = {"api.example.com": {"content": IP2, "proxied": False}}
    assert only(plan(moved, [ours], rows=[row("api.example.com", ours["id"])])).status == "update"
    # A claimed record never carried the comment: it is kept current all the same (I7).
    theirs = rec("api.example.com", comment="made by hand")
    c = only(plan(moved, [theirs], rows=[row("api.example.com", theirs["id"], origin="claimed")]))
    assert c.status == "update" and c.after == {"content": IP2, "proxied": False}


async def test_publish_leaves_a_taken_over_record_alone(cf):
    await _cloudflare(cf)
    env_id = await _env(dns=DNS, switch="none")
    await traffic.publish_dns(await _env_obj(env_id))
    (record,) = cf.named("api.uat.example.com")
    cf.records[record["id"]].update(comment="ops: moved to the new LB, do not touch", content="198.51.100.50")
    writes = len(cf.writes())

    with pytest.raises(traffic.DnsRefused) as err:
        await traffic.publish_dns(await _env_obj(env_id))
    assert "api.uat.example.com: someone took this record over in Cloudflare" in str(err.value)
    assert len(cf.writes()) == writes
    assert cf.records[record["id"]]["content"] == "198.51.100.50"
    assert cf.records[record["id"]]["comment"] == "ops: moved to the new LB, do not touch"
    # Teardown still only forgets it (the stale-row path already checked the comment).
    plan_ = await traffic.remove_dns(await _env_obj(env_id))
    assert {c.hostname: c.action for c in plan_.changes}["api.uat.example.com"] == "forget"
    assert record["id"] in cf.records


# ------------------------------------------------------------------------- F42


def test_lone_record_with_our_comment_is_adopted():
    made = rec("api.example.com", comment=MINE)
    p = plan({"api.example.com": WANT}, [made])
    c = only(p)
    assert (c.status, c.record_id, c.row_id, c.forget_row, c.after) == ("adopt", made["id"], None, False, None)
    assert not p.blockers and "hadn't recorded it" in c.message
    # Pointing somewhere else: adopted and then updated.
    c = only(plan({"api.example.com": {"content": IP2, "proxied": False}}, [made]))
    assert c.status == "adopt" and c.after == {"content": IP2, "proxied": False}
    assert c.before["content"] == IP
    # Our recorded row's record is gone and the one there now is ours too: forget the row, adopt the record.
    r = row("api.example.com", "gone-id")
    c = only(plan({"api.example.com": WANT}, [made], rows=[r]))
    assert (c.status, c.forget_row, c.row_id) == ("adopt", True, r["id"])
    assert c.to_json()["status"] == "adopt"


@pytest.mark.parametrize("records, expect", [
    # Another environment's comment, or none: still not Slipway's to take without a claim.
    (lambda: [rec("api.example.com", comment=cloudflare.comment_for("prod", OTHER))], "claimable"),
    (lambda: [rec("api.example.com", comment="made by hand")], "claimable"),
    # Ours, but beside a second A record or an AAAA: crowded, a conflict as before.
    (lambda: [rec("api.example.com", comment=MINE), rec("api.example.com", IP2)], "conflict"),
    (lambda: [rec("api.example.com", comment=MINE), rec("api.example.com", "2001:db8::1", type="AAAA")],
     "conflict"),
])
def test_only_a_lone_record_with_our_comment_is_adopted(records, expect):
    assert only(plan({"api.example.com": WANT}, records())).status == expect


def test_a_record_held_by_another_row_is_never_adopted():
    # Ours, but recorded for another name (renamed in Cloudflare): the existing conflict.
    moved = rec("api2.example.com", comment=MINE)
    p = plan({"api2.example.com": WANT}, [moved], rows=[row("api.example.com", moved["id"])])
    assert p.by_name()["api2.example.com"].status == "conflict"
    # Carrying our comment but recorded by another environment: theirs.
    copied = rec("api.example.com", comment=MINE)
    c = only(plan({"api.example.com": WANT}, [copied], rows=[row("api.example.com", copied["id"], env=OTHER)]))
    assert c.status == "conflict" and "managed by another Slipway environment" in c.message


async def test_a_create_whose_answer_was_lost_no_longer_blocks(cf, monkeypatch):
    await _cloudflare(cf)
    env_id = await _env(dns=DNS, switch="none")
    handle, posts = cf.handle, []

    def flaky(request: httpx.Request) -> httpx.Response:
        response = handle(request)
        if request.method == "POST":
            posts.append(request)
            if len(posts) == 2:  # Cloudflare made the record, but the answer never arrived
                raise httpx.ReadTimeout("timed out", request=request)
        return response

    monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(flaky))
    with pytest.raises(cloudflare.CloudflareError):
        await traffic.publish_dns(await _env_obj(env_id))
    rows = await _rows(env_id, cloudflare.PROVIDER, cloudflare.KIND)
    (orphan,) = [r for r in cf.records.values() if r["id"] not in {x.provider_id for x in rows.values()}]
    assert cloudflare.is_ours(orphan["comment"], env_id)

    monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(handle))
    plan_ = await traffic.publish_dns(await _env_obj(env_id))  # was DnsRefused: "... that Slipway didn't make"
    adopted = {c.hostname: c for c in plan_.changes}[orphan["name"]]
    assert adopted.status == cloudflare.ADOPT and adopted.external_id == orphan["id"]
    assert len(cf.named(orphan["name"])) == 1  # no second record was made beside it


async def test_an_adopted_record_is_recorded_as_created(cf, monkeypatch):
    zid = await _cloudflare(cf)
    env_id = await _env(dns=DNS, switch="none")
    orphan = cf.add_record(zid, "A", "auth.uat.example.com", "203.0.113.7",
                           comment=cloudflare.comment_for("uat", env_id))
    await traffic.publish_dns(await _env_obj(env_id))
    rows = await _rows(env_id, cloudflare.PROVIDER, cloudflare.KIND)
    assert rows["auth.uat.example.com"].provider_id == orphan["id"]
    assert rows["auth.uat.example.com"].origin == "created"
    await traffic.remove_dns(await _env_obj(env_id))
    assert orphan["id"] not in cf.records
