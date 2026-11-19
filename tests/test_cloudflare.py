"""Cloudflare DNS: the client against FakeCloudflare (test 12), ``plan_dns`` (test 13), settings helpers."""

from __future__ import annotations

import uuid

import httpx
import pytest

from slipway.db.session import get_sessionmaker
from slipway.models import AppSetting
from slipway.services import certs, cloudflare
from slipway.services.cloudflare import CloudflareClient, CloudflareError, RecordGone, plan_dns
from tests.fake_cloudflare import TOKEN, ZONE, FakeCloudflare


@pytest.fixture
def fake_cf(monkeypatch):
    fake = FakeCloudflare()
    monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(fake.handle))
    return fake


@pytest.fixture
def waits(monkeypatch):
    """The waits before a 429 is retried, without waiting."""
    seen: list[float] = []

    async def no_wait(seconds: float) -> None:
        seen.append(seconds)

    monkeypatch.setattr(cloudflare, "sleep", no_wait)
    return seen


# ---------------------------------------------------------------------- 12: client


async def test_verify_token(fake_cf):
    async with CloudflareClient(TOKEN) as cf:
        assert await cf.verify_token() is True
        fake_cf.token_status = "disabled"
        assert await cf.verify_token() is False
    call = fake_cf.calls[0]
    assert (call["method"], call["path"]) == ("GET", "/user/tokens/verify")


async def test_headers(monkeypatch):
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"success": True, "errors": [], "result": {"status": "active"}})

    monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(handle))
    async with CloudflareClient(TOKEN) as cf:
        await cf.verify_token()
    assert str(seen[0].url) == "https://api.cloudflare.com/client/v4/user/tokens/verify"
    assert seen[0].headers["Authorization"] == f"Bearer {TOKEN}"
    assert seen[0].headers["User-Agent"] == "Slipway"


async def test_zone_lookup(fake_cf):
    async with CloudflareClient(TOKEN) as cf:
        with pytest.raises(CloudflareError, match=r"^No active zone example.com for this token$"):
            await cf.zone_id(ZONE)
        fake_cf.add_zone(ZONE, status="pending")  # not active yet: still none
        with pytest.raises(CloudflareError, match="No active zone"):
            await cf.zone_id(ZONE)
        zid = fake_cf.add_zone(ZONE)
        fake_cf.add_zone("other.com")
        assert await cf.zone_id(ZONE) == zid
        fake_cf.add_zone(ZONE)  # a second account's zone of the same name
        with pytest.raises(CloudflareError, match="sees 2 active zones named example.com"):
            await cf.zone_id(ZONE)
    assert fake_cf.calls[0]["params"] == {"name": ZONE, "status": "active"}


async def test_records_by_name_and_get(fake_cf):
    zid = fake_cf.add_zone()
    a = fake_cf.add_record(zid, "A", "api.example.com", "203.0.113.10")
    txt = fake_cf.add_record(zid, "TXT", "api.example.com", "hello")
    fake_cf.add_record(zid, "A", "portal.example.com", "203.0.113.10")
    async with CloudflareClient(TOKEN) as cf:
        got = await cf.records(zid, "api.example.com")
        assert {r["id"] for r in got} == {a["id"], txt["id"]}  # every type, only that name
        assert await cf.records(zid, "nothing.example.com") == []
        assert (await cf.get_record(zid, a["id"]))["content"] == "203.0.113.10"
        assert await cf.get_record(zid, uuid.uuid4().hex) is None  # 404 is None
    assert fake_cf.calls[0]["params"] == {"name": "api.example.com", "per_page": "100"}
    assert fake_cf.calls[0]["path"] == f"/zones/{zid}/dns_records"


async def test_create_patch_delete(fake_cf):
    zid = fake_cf.add_zone()
    comment = cloudflare.comment_for("uat", uuid.uuid4())
    async with CloudflareClient(TOKEN) as cf:
        rec = await cf.create_a(zid, "api.example.com", "203.0.113.10", False, comment)
        assert fake_cf.calls[-1]["method"] == "POST"
        assert fake_cf.calls[-1]["body"] == {"type": "A", "name": "api.example.com", "content": "203.0.113.10",
                                             "ttl": 1, "proxied": False, "comment": comment}
        assert fake_cf.records[rec["id"]]["comment"] == comment

        fake_cf.records[rec["id"]]["ttl"] = 300  # someone set a TTL: the patch puts it back to automatic
        out = await cf.update_a(zid, rec["id"], "203.0.113.20", True, comment)
        assert out["content"] == "203.0.113.20" and out["proxied"] is True and out["ttl"] == 1
        assert fake_cf.calls[-1]["method"] == "PATCH"
        assert fake_cf.calls[-1]["body"] == {"content": "203.0.113.20", "proxied": True, "ttl": 1, "comment": comment}

        assert await cf.delete_record(zid, rec["id"]) is True
        assert rec["id"] not in fake_cf.records
        assert await cf.delete_record(zid, rec["id"]) is False  # already gone is fine
        with pytest.raises(RecordGone) as gone:
            await cf.update_a(zid, rec["id"], "203.0.113.20", True, comment)
        assert gone.value.status_code == 404 and gone.value.codes == [81044]


async def test_create_refused_beside_a_cname(fake_cf):
    zid = fake_cf.add_zone()
    fake_cf.add_record(zid, "CNAME", "api.example.com", "elsewhere.example.net")
    async with CloudflareClient(TOKEN) as cf:
        with pytest.raises(CloudflareError) as err:
            await cf.create_a(zid, "api.example.com", "203.0.113.10", False, "x")
    assert err.value.status_code == 400 and err.value.codes == [81053]
    assert "Cloudflare rejected the request" in str(err.value)
    assert "An A, AAAA, or CNAME record with that host already exists." in str(err.value)


async def test_429_retried_once_after_retry_after(fake_cf, waits):
    zid = fake_cf.add_zone()
    fake_cf.rate_limit_once = True
    async with CloudflareClient(TOKEN) as cf:
        assert await cf.records(zid, "api.example.com") == []
    assert waits == [1.0]
    assert len(fake_cf.calls) == 2


async def test_429_twice_fails_and_wait_is_capped(monkeypatch, waits):
    calls = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(429, headers={"Retry-After": "600"},
                              json={"success": False, "errors": [{"code": 971, "message": "Slow down"}]})

    monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(handle))
    async with CloudflareClient(TOKEN) as cf:
        with pytest.raises(CloudflareError, match="limiting requests") as err:
            await cf.verify_token()
    assert len(calls) == 2  # once, then one retry
    assert waits == [30.0]
    assert err.value.status_code == 429 and err.value.codes == [971]


async def test_403_message(fake_cf):
    zid = fake_cf.add_zone()
    fake_cf.deny = {"POST"}
    async with CloudflareClient(TOKEN) as cf:
        assert await cf.records(zid, "api.example.com") == []  # reads still work
        with pytest.raises(CloudflareError) as err:
            await cf.create_a(zid, "api.example.com", "203.0.113.10", False, "x")
    text = str(err.value)
    assert text.startswith("Cloudflare refused the token (check that it is active and may edit DNS in this zone)")
    assert "HTTP 403, code 9109" in text
    assert "Unauthorized to access requested resource" in text
    assert err.value.status_code == 403 and err.value.codes == [9109]


async def test_no_error_contains_the_token(fake_cf, monkeypatch):
    zid = fake_cf.add_zone()
    fake_cf.echo_token_in_errors = True
    errors: list[str] = []
    fake_cf.deny = True
    async with CloudflareClient(TOKEN) as cf:
        with pytest.raises(CloudflareError) as err:
            await cf.records(zid, "api.example.com")
        errors.append(str(err.value))
    fake_cf.deny = False
    async with CloudflareClient(TOKEN + "x") as cf:  # a wrong token, echoed back by the API
        with pytest.raises(CloudflareError) as err:
            await cf.verify_token()
        errors.append(str(err.value))
        assert err.value.status_code == 401

    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"refused while sending {request.headers['Authorization']}")

    monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(broken))
    async with CloudflareClient(TOKEN) as cf:
        with pytest.raises(CloudflareError, match="Could not reach Cloudflare") as err:
            await cf.verify_token()
        errors.append(str(err.value))
        assert err.value.__cause__ is None and err.value.__suppress_context__  # no chained text with the token
    for text in errors:
        assert TOKEN not in text
    assert "<token>" in errors[0]
    assert TOKEN not in repr(cloudflare.CloudflareConfig(zone=ZONE, token=TOKEN))


async def test_long_messages_are_cut(monkeypatch):
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="<html>" + "x" * 5000 + "</html>")

    monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(handle))
    async with CloudflareClient(TOKEN) as cf:
        with pytest.raises(CloudflareError, match="^Cloudflare had a problem") as err:
            await cf.verify_token()
    assert len(str(err.value)) < 300


async def test_check_connection(fake_cf):
    fake_cf.add_zone()
    config = cloudflare.CloudflareConfig(zone=ZONE, token=TOKEN)
    assert await cloudflare.check_connection(config) == (
        "Connected: zone example.com; the token is active and can read its records. "
        "Slipway can't check that it may edit them without changing one.")
    assert fake_cf.calls[-1]["params"] == {"per_page": "1"}
    assert not fake_cf.writes()
    with pytest.raises(CloudflareError, match="No active zone other.com"):
        await cloudflare.check_connection(cloudflare.CloudflareConfig(zone="other.com", token=TOKEN))


# ------------------------------------------------- phase 4 test 30: TXT records


CHALLENGE = certs.CHALLENGE_COMMENT


async def test_create_txt_lists_it_by_comment_and_deletes_it(fake_cf):
    zid = fake_cf.add_zone()
    async with CloudflareClient(TOKEN) as cf:
        rec = await cf.create_txt(zid, "_acme-challenge.api.example.com", "tok3n-value", CHALLENGE)
        assert fake_cf.calls[-1]["method"] == "POST"
        assert fake_cf.calls[-1]["path"] == f"/zones/{zid}/dns_records"
        assert fake_cf.calls[-1]["body"] == {"type": "TXT", "name": "_acme-challenge.api.example.com",
                                             "content": "tok3n-value", "ttl": cloudflare.TXT_TTL,
                                             "comment": CHALLENGE}
        assert "proxied" not in fake_cf.calls[-1]["body"]
        stored = fake_cf.records[rec["id"]]
        assert (stored["type"], stored["content"], stored["comment"]) == ("TXT", "tok3n-value", CHALLENGE)

        listed = await cf.txt_records(zid, CHALLENGE)
        assert [r["id"] for r in listed] == [rec["id"]]
        assert fake_cf.calls[-1]["params"] == {"type": "TXT", "comment": CHALLENGE, "per_page": "100"}

        assert await cf.delete_record(zid, rec["id"]) is True
        assert rec["id"] not in fake_cf.records
        assert await cf.txt_records(zid, CHALLENGE) == []
        assert await cf.delete_record(zid, rec["id"]) is False  # a second delete finds it gone: no error


async def test_txt_records_match_the_comment_exactly(fake_cf):
    zid = fake_cf.add_zone()
    other_zone = fake_cf.add_zone("example.net")
    ours = fake_cf.add_record(zid, "TXT", "_acme-challenge.uat.example.com", "a", comment=CHALLENGE)
    fake_cf.add_record(zid, "TXT", "_acme-challenge.www.example.com", "b", comment=CHALLENGE + " (old)")
    fake_cf.add_record(zid, "TXT", "_acme-challenge.shop.example.com", "c", comment=None)
    fake_cf.add_record(zid, "TXT", "example.com", "v=spf1 -all", comment="Managed by Slipway: uat (0123456789ab)")
    fake_cf.add_record(zid, "A", "_acme-challenge.uat.example.com", "203.0.113.9", comment=CHALLENGE)
    fake_cf.add_record(other_zone, "TXT", "_acme-challenge.example.net", "d", comment=CHALLENGE)
    async with CloudflareClient(TOKEN) as cf:
        assert [r["id"] for r in await cf.txt_records(zid, CHALLENGE)] == [ours["id"]]
        # Should Cloudflare ignore a filter, the client still returns only exact TXT matches.
        fake_cf.ignore_comment_filter = True
        assert [r["id"] for r in await cf.txt_records(zid, CHALLENGE)] == [ours["id"]]
    assert not fake_cf.writes()


async def test_txt_errors_never_carry_the_token(fake_cf):
    zid = fake_cf.add_zone()
    fake_cf.echo_token_in_errors = True
    fake_cf.deny = {"POST", "DELETE"}
    rec = fake_cf.add_record(zid, "TXT", "_acme-challenge.api.example.com", "x", comment=CHALLENGE)
    errors: list[str] = []
    async with CloudflareClient(TOKEN) as cf:
        with pytest.raises(CloudflareError) as err:
            await cf.create_txt(zid, "_acme-challenge.api.example.com", "y", CHALLENGE)
        assert err.value.status_code == 403
        errors.append(str(err.value))
        with pytest.raises(CloudflareError) as err:
            await cf.delete_record(zid, rec["id"])
        errors.append(str(err.value))
        fake_cf.deny = True
        with pytest.raises(CloudflareError) as err:
            await cf.txt_records(zid, CHALLENGE)
        errors.append(str(err.value))
    async with CloudflareClient(TOKEN + "x") as cf:  # a wrong token, echoed back by the API
        with pytest.raises(CloudflareError) as err:
            await cf.create_txt(zid, "_acme-challenge.api.example.com", "y", CHALLENGE)
        assert err.value.status_code == 401
        errors.append(str(err.value))
    for text in errors:
        assert TOKEN not in text
    assert all("<token>" in text for text in errors[:3])
    assert rec["id"] in fake_cf.records  # the refused delete left it


async def test_read_state(fake_cf):
    zid = fake_cf.add_zone()
    env_id = uuid.uuid4()
    api = fake_cf.add_record(zid, "A", "api.example.com", "203.0.113.10")
    wild = fake_cf.add_record(zid, "A", "*.uat.example.com", "203.0.113.10")
    moved = fake_cf.add_record(zid, "A", "renamed.example.com", "203.0.113.10")
    rows = [
        {"id": uuid.uuid4(), "environment_id": env_id, "provider_id": api["id"], "name": "api.example.com",
         "origin": "created"},
        {"id": uuid.uuid4(), "environment_id": env_id, "provider_id": moved["id"], "name": "old.example.com",
         "origin": "created"},
        {"id": uuid.uuid4(), "environment_id": env_id, "provider_id": "gone", "name": "gone.example.com",
         "origin": "created"},
    ]
    async with CloudflareClient(TOKEN) as cf:
        by_name, wildcards = await cloudflare.read_state(
            cf, zid, ZONE, ["api.example.com", "portal.uat.example.com", "www.elsewhere.net"], rows)
    assert [r["id"] for r in by_name["api.example.com"]] == [api["id"]]
    assert by_name["portal.uat.example.com"] == []
    assert [r["id"] for r in by_name["renamed.example.com"]] == [moved["id"]]
    assert "www.elsewhere.net" not in by_name  # outside the zone: not read
    assert [r["id"] for r in wildcards["*.uat.example.com"]] == [wild["id"]]
    assert set(wildcards) == {"*.uat.example.com", "*.example.com"}
    assert not fake_cf.writes()


# ------------------------------------------------------------------- settings


async def test_load_config():
    async with get_sessionmaker()() as db:
        assert await cloudflare.load_config(db) is None
        db.add(AppSetting(key=cloudflare.SETTING_KEY, value={"zone": ZONE, "zone_id": "z1",
                                                             "public_ip": "203.0.113.10", "proxied": True},
                          secret=TOKEN))
        await db.commit()
    async with get_sessionmaker()() as db:
        config = await cloudflare.load_config(db)
    assert config == cloudflare.CloudflareConfig(zone=ZONE, token=TOKEN, zone_id="z1", public_ip="203.0.113.10",
                                                 proxied=True)
    assert cloudflare.token_hint(config.token) == TOKEN[-4:]
    assert cloudflare.token_hint(None) == ""


def test_clean_values():
    assert cloudflare.clean_zone(" Example.COM. ") == "example.com"
    with pytest.raises(ValueError, match="is not a domain name"):
        cloudflare.clean_zone("https://example.com")
    assert cloudflare.clean_public_ip(" 203.0.113.10 ") == "203.0.113.10"
    assert cloudflare.clean_public_ip("") is None
    with pytest.raises(ValueError, match="IPv4"):
        cloudflare.clean_public_ip("2001:db8::1")
    with pytest.raises(ValueError, match="is not an IP address"):
        cloudflare.clean_public_ip("my.wan.example")
    assert cloudflare.clean_token(f"Bearer {TOKEN} ") == TOKEN
    with pytest.raises(ValueError, match="is not a Cloudflare API token") as err:
        cloudflare.clean_token("hunter2")
    assert "hunter2" not in str(err.value)
    assert cloudflare.in_zone("api.example.com", "example.com")
    assert cloudflare.in_zone("example.com", "example.com")
    assert not cloudflare.in_zone("badexample.com", "example.com")
    assert cloudflare.wildcard_for("api.uat.example.com", ZONE) == "*.uat.example.com"
    assert cloudflare.wildcard_for("example.com", ZONE) is None
    env_id = uuid.uuid4()
    comment = cloudflare.comment_for("uat", env_id)
    assert comment == f"Managed by Slipway: uat ({env_id.hex[:12]})"
    assert len(cloudflare.comment_for("x" * 26, env_id)) <= 100
    assert cloudflare.is_ours(comment, env_id)
    assert cloudflare.is_ours(f"Managed by Slipway: renamed ({env_id.hex[:12]})", env_id)
    assert not cloudflare.is_ours(comment, uuid.uuid4())
    assert not cloudflare.is_ours("hand made", env_id)


# ------------------------------------------------------------------ 13: plan_dns


ENV = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER = uuid.UUID("22222222-2222-2222-2222-222222222222")
IP, IP2 = "203.0.113.10", "203.0.113.99"
WANT = {"content": IP, "proxied": False}


def rec(name: str, type: str = "A", content: str = IP, *, proxied: bool = False, comment: str | None = None,
        id: str | None = None) -> dict:
    return {"id": id or uuid.uuid4().hex, "type": type, "name": name, "content": content, "proxied": proxied,
            "comment": comment, "ttl": 1}


def row(name: str, record_id: str, *, env: uuid.UUID = ENV, origin: str = "created") -> dict:
    return {"id": uuid.uuid4(), "environment_id": env, "provider_id": record_id, "name": name, "origin": origin}


def plan(wanted, records=(), *, wildcards=None, rows=(), names=None):
    by_name: dict[str, list[dict]] = {}
    for r in records:
        by_name.setdefault(r["name"], []).append(r)
    return plan_dns(wanted, by_name, wildcards or {}, list(rows), ENV, zone=ZONE, env_names=names)


def only(p) -> cloudflare.DnsChange:
    assert len(p.changes) == 1, p.changes
    return p.changes[0]


def test_ok_and_update():
    ours = rec("api.example.com", comment=cloudflare.comment_for("uat", ENV))
    r = row("api.example.com", ours["id"])
    c = only(plan({"api.example.com": WANT}, [ours], rows=[r]))
    assert (c.status, c.record_id, c.row_id) == ("ok", ours["id"], r["id"])
    assert not plan({"api.example.com": WANT}, [ours], rows=[r]).blockers

    c = only(plan({"api.example.com": {"content": IP2, "proxied": False}}, [ours], rows=[r]))
    assert c.status == "update" and c.after == {"content": IP2, "proxied": False}
    assert c.before["content"] == IP and c.message == f"api.example.com → A {IP2} (was A {IP})"

    c = only(plan({"api.example.com": {"content": IP, "proxied": True}}, [ours], rows=[r]))
    assert c.status == "update"  # only the proxied flag differs

    # A claimed row is kept current the same way.
    c = only(plan({"api.example.com": {"content": IP2, "proxied": False}}, [ours],
                  rows=[row("api.example.com", ours["id"], origin="claimed")]))
    assert c.status == "update"


def test_create():
    c = only(plan({"api.example.com": WANT}))
    assert (c.status, c.after, c.record_id) == ("create", WANT, None)
    assert c.message == f"api.example.com → A {IP} (new)"
    # A TXT record at the name doesn't stop an A record beside it.
    c = only(plan({"api.example.com": WANT}, [rec("api.example.com", "TXT", "v=spf1 -all")]))
    assert c.status == "create"


def test_wildcards():
    covering = {"*.uat.example.com": [rec("*.uat.example.com")]}
    c = only(plan({"api.uat.example.com": WANT}, wildcards=covering))
    assert c.status == "covered" and c.after is None
    assert "*.uat.example.com" in c.message
    assert not plan({"api.uat.example.com": WANT}, wildcards=covering).writes

    # A wildcard with another address, another proxied flag or of another type doesn't cover: create.
    for wild in ([rec("*.uat.example.com", content=IP2)], [rec("*.uat.example.com", proxied=True)],
                 [rec("*.uat.example.com", "CNAME", "lb.example.net")]):
        c = only(plan({"api.uat.example.com": WANT}, wildcards={"*.uat.example.com": wild}))
        assert c.status == "create", wild
    # A wildcard further up isn't the one that answers for this name.
    c = only(plan({"api.uat.example.com": WANT}, wildcards={"*.example.com": [rec("*.example.com")]}))
    assert c.status == "create"
    # Any record at the name means the wildcard doesn't answer there.
    c = only(plan({"api.uat.example.com": WANT}, [rec("api.uat.example.com", "TXT", "x")], wildcards=covering))
    assert c.status == "create"


def test_claimable():
    theirs = rec("api.example.com", content=IP2, comment="made by hand")
    p = plan({"api.example.com": WANT}, [theirs])
    c = only(p)
    assert (c.status, c.record_id) == ("claimable", theirs["id"])
    assert p.blockers == [c.message]
    assert "claim it on the environment page" in c.message


@pytest.mark.parametrize("records, expect", [
    ([rec("api.example.com", "CNAME", "lb.example.net")], "has a CNAME record"),
    ([rec("api.example.com", "AAAA", "2001:db8::1")], "has a AAAA record"),
    ([rec("api.example.com", "AAAA", "2001:db8::1"), rec("api.example.com")], "has a AAAA record"),
    ([rec("api.example.com"), rec("api.example.com", content=IP2)], "has 2 A records"),
])
def test_conflicts_at_an_unrecorded_name(records, expect):
    p = plan({"api.example.com": WANT}, records)
    c = only(p)
    assert c.status == "conflict" and expect in c.message
    assert p.blockers == [c.message] and not p.writes


def test_outside_the_zone():
    c = only(plan({"api.example.net": WANT}))
    assert c.status == "conflict" and c.message == "api.example.net isn't in the Cloudflare zone example.com"


def test_another_environments_record():
    theirs = rec("api.example.com", comment=cloudflare.comment_for("prod", OTHER))
    c = only(plan({"api.example.com": WANT}, [theirs], rows=[row("api.example.com", theirs["id"], env=OTHER)]))
    assert c.status == "conflict" and c.message == "api.example.com: its A record is managed by another Slipway environment"
    c = only(plan({"api.example.com": WANT}, [theirs], rows=[row("api.example.com", theirs["id"], env=OTHER)],
                  names={OTHER: "prod"}))
    assert c.message == "api.example.com: its A record is managed by environment prod"


def test_renamed_record():
    # Our record for api was renamed to api2 in Cloudflare (read_state found it by id).
    moved = rec("api2.example.com", comment=cloudflare.comment_for("uat", ENV))
    c = only(plan({"api.example.com": WANT}, [moved], rows=[row("api.example.com", moved["id"])]))
    assert c.status == "conflict" and "now named api2.example.com" in c.message
    # The same seen from the name it was renamed to: it is ours, but recorded for another name.
    p = plan({"api.example.com": WANT, "api2.example.com": WANT}, [moved], rows=[row("api.example.com", moved["id"])])
    assert {c.name: c.status for c in p.changes} == {"api.example.com": "conflict", "api2.example.com": "conflict"}
    assert "the one Slipway made for api.example.com" in p.by_name()["api2.example.com"].message


def test_gone_record():
    r = row("api.example.com", "gone-id")
    # Gone and nothing there: create afresh, forgetting the old row.
    c = only(plan({"api.example.com": WANT}, rows=[r]))
    assert (c.status, c.forget_row, c.row_id) == ("create", True, r["id"])
    # Gone, and a foreign A record took the name.
    foreign = rec("api.example.com", content=IP2)
    c = only(plan({"api.example.com": WANT}, [foreign], rows=[r]))
    assert c.status == "conflict" and "the record Slipway made is gone" in c.message
    assert c.record_id == foreign["id"]


def test_recorded_but_crowded():
    ours = rec("api.example.com", comment=cloudflare.comment_for("uat", ENV))
    r = row("api.example.com", ours["id"])
    c = only(plan({"api.example.com": WANT}, [ours, rec("api.example.com", content=IP2)], rows=[r]))
    assert c.status == "conflict" and "has 2 A records" in c.message
    c = only(plan({"api.example.com": WANT}, [ours, rec("api.example.com", "AAAA", "2001:db8::1")], rows=[r]))
    assert c.status == "conflict" and "also has a AAAA record" in c.message
    changed = {**ours, "type": "CNAME", "content": "x.example.net"}
    c = only(plan({"api.example.com": WANT}, [changed], rows=[r]))
    assert c.status == "conflict" and "now a CNAME record" in c.message


def test_stale_rows():
    comment = cloudflare.comment_for("uat", ENV)
    created = rec("old.example.com", comment=comment)
    edited = rec("edited.example.com", comment="someone took this over")
    claimed = rec("claimed.example.com", comment="by hand")
    moved = rec("elsewhere.example.com", comment=comment)
    rows = [
        row("old.example.com", created["id"]),
        row("edited.example.com", edited["id"]),
        row("claimed.example.com", claimed["id"], origin="claimed"),
        row("moved.example.com", moved["id"]),
        row("gone.example.com", "no-such-id"),
    ]
    p = plan({}, [created, edited, claimed, moved], rows=rows)
    got = {c.name: c.status for c in p.changes}
    assert got == {"old.example.com": "delete", "edited.example.com": "forget", "claimed.example.com": "forget",
                   "moved.example.com": "forget", "gone.example.com": "forget"}
    delete = p.changes[[c.name for c in p.changes].index("old.example.com")]
    assert delete.record_id == created["id"] and delete.row_id == rows[0]["id"]
    assert [c.name for c in p.writes] == ["old.example.com"]
    assert not p.blockers
    # Another environment's rows are never stale for this one.
    assert plan({}, [created], rows=[row("old.example.com", created["id"], env=OTHER)]).changes == []
    # A stale row whose record isn't A any more is forgotten, not deleted.
    p = plan({}, [{**created, "type": "TXT"}], rows=[rows[0]])
    assert [c.status for c in p.changes] == ["forget"]


def test_plan_takes_resource_objects_and_serialises():
    class Resource:  # what resources.owned returns has these attributes
        def __init__(self, **kw):
            self.__dict__.update(kw)

    ours = rec("api.example.com", comment=cloudflare.comment_for("uat", ENV))  # a created row's record carries it
    res = Resource(id=uuid.uuid4(), environment_id=ENV, provider_id=ours["id"], name="api.example.com",
                   origin="created", provider="cloudflare", kind="dns_record")
    proxy = Resource(id=uuid.uuid4(), environment_id=OTHER, provider_id=ours["id"], name="api.example.com",
                     origin="created", provider="switchyard", kind="proxy_host")  # not a DNS row: ignored
    p = plan({"API.example.com.": WANT}, [ours], rows=[res, proxy])
    assert only(p).status == "ok" and only(p).name == "api.example.com"
    js = p.to_json()
    assert js["blockers"] == [] and js["changes"][0]["row_id"] == str(res.id)
