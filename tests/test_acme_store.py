"""The ACME store (phase 4 §3.8, §11.2; Decision 40): account keys on the ``acme`` row of ``app_settings`` and the
challenge records in the Cloudflare zone, with P4 test 89.

Runs on SQLite, and on PostgreSQL when SLIPWAY_TEST_DATABASE_URL is set (the conftest points the app there).
Everything outside is a fake: FakeAcme validating DNS-01 through FakeCloudflare's records.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from sqlalchemy import delete, select

from slipway.db.session import get_sessionmaker
from slipway.models import AppSetting, AuditEvent
from slipway.services import acme, acme_store, certs, cloudflare
from slipway.services.cloudflare import CloudflareClient
from tests.fake_acme import FakeAcme, FakeCloudflareTxt
from tests.fake_cloudflare import TOKEN, FakeCloudflare

NAMES = ["api.shop.example.com", "portal.shop.example.com"]


@pytest.fixture
def cf(monkeypatch) -> FakeCloudflare:
    fake = FakeCloudflare()
    monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(fake.handle))
    return fake


@pytest.fixture
def zone_id(cf) -> str:
    return cf.add_zone("example.com")


@pytest.fixture
def server(monkeypatch, cf, zone_id) -> FakeAcme:
    fake = FakeAcme(FakeCloudflareTxt(cf, zone_id).lookup)
    monkeypatch.setattr(acme, "transport_factory", lambda: httpx.MockTransport(fake.handle))

    async def no_wait(_seconds: float) -> None:
        return None
    monkeypatch.setattr(certs, "sleep", no_wait)
    monkeypatch.setattr(acme, "sleep", no_wait)
    return fake


async def acme_row() -> AppSetting | None:
    async with get_sessionmaker()() as db:
        return await db.scalar(select(AppSetting).where(AppSetting.key == acme_store.SETTING_KEY))


async def insert_empty_row() -> None:
    """The row as migration 0011 leaves it: value {} (no accounts key yet) and no secret."""
    async with get_sessionmaker()() as db:
        db.add(AppSetting(key=acme_store.SETTING_KEY, value={}, secret=None))
        await db.commit()


# ------------------------------------------------------------------------------------------------ test 89


async def test_89_left_challenge_records_are_swept_before_an_order_for_its_names_only(cf, zone_id, server):
    crashed = [cf.add_record(zone_id, "TXT", f"_acme-challenge.{n}", "left-by-a-crash", comment=certs.CHALLENGE_COMMENT)
               for n in NAMES]
    elsewhere = cf.add_record(zone_id, "TXT", "_acme-challenge.api.other.example.com", "another env's, in flight",
                              comment=certs.CHALLENGE_COMMENT)
    no_comment = cf.add_record(zone_id, "TXT", f"_acme-challenge.{NAMES[0]}", "someone else's", comment=None)
    async with CloudflareClient(TOKEN) as client:
        issued = await certs.issue(NAMES, directory=server.directory_url, keys=acme_store.AccountKeys(),
                                   txt=acme_store.TxtRecords(client, zone_id))
    assert issued.dns_names == sorted(NAMES)
    for rec in crashed:
        assert rec["id"] not in cf.records
    assert elsewhere["id"] in cf.records and no_comment["id"] in cf.records
    # The order's own records went too, in its finally.
    assert {r["id"] for r in cf.records.values()} == {elsewhere["id"], no_comment["id"]}
    # The challenge records were TXT with Slipway's comment, never proxied.
    posts = [c for c in cf.calls if c["method"] == "POST"]
    assert posts and all(c["body"]["type"] == "TXT" and c["body"]["comment"] == certs.CHALLENGE_COMMENT
                         and "proxied" not in c["body"] for c in posts)


async def test_89_two_first_uses_of_a_directory_store_one_key_with_the_row_missing(server, cf, zone_id):
    assert await acme_row() is None  # tests build the schema without migration 0011
    first, second = acme_store.AccountKeys(get_sessionmaker()), acme_store.AccountKeys(get_sessionmaker())
    async with CloudflareClient(TOKEN) as client:
        txt = acme_store.TxtRecords(client, zone_id)
        a, b = await asyncio.gather(
            certs.issue(NAMES[:1], directory=server.directory_url, keys=first, txt=txt),
            certs.issue(NAMES[1:], directory=server.directory_url, keys=second, txt=txt),
        )
    assert a.dns_names == NAMES[:1] and b.dns_names == NAMES[1:]
    assert len(server.accounts) == 1  # both orders were signed by the one stored key
    row = await acme_row()
    keys = json.loads(row.secret)
    assert list(keys) == [server.directory_url]
    assert row.value["accounts"][server.directory_url]["kid"] in server.accounts


async def test_89_two_put_if_absent_at_once_keep_the_first(monkeypatch):
    await insert_empty_row()
    made = iter(["pem-one", "pem-two"])
    monkeypatch.setattr(acme, "generate_account_key", lambda: next(made))
    one, two = acme_store.AccountKeys(), acme_store.AccountKeys()
    a, b = await asyncio.gather(certs.account_key(one, "https://acme.test/d"),
                                certs.account_key(two, "https://acme.test/d"))
    # Both callers generate a key; whichever stores first wins and the other drops its own. Which one takes the
    # lock first depends on how the two sessions' awaits interleave, so only the agreement is asserted.
    assert a.pem == b.pem and a.pem in ("pem-one", "pem-two")
    assert json.loads((await acme_row()).secret) == {"https://acme.test/d": a.pem}


# ------------------------------------------------------------------------------------------- account keys


async def test_the_row_is_inserted_when_missing_and_found_when_present():
    keys = acme_store.AccountKeys()
    assert await keys.get("https://acme.test/directory") is None
    stored = await keys.put_if_absent("https://acme.test/directory", "pem-a")
    assert stored.pem == "pem-a" and stored.kid is None
    again = await keys.put_if_absent("https://acme.test/directory", "pem-b")
    assert again.pem == "pem-a"
    other = await keys.put_if_absent("https://acme-staging.test/directory", "pem-c")
    assert other.pem == "pem-c"
    async with get_sessionmaker()() as db:
        rows = list(await db.scalars(select(AppSetting).where(AppSetting.key == acme_store.SETTING_KEY)))
    assert len(rows) == 1
    assert json.loads(rows[0].secret) == {"https://acme.test/directory": "pem-a",
                                          "https://acme-staging.test/directory": "pem-c"}


async def test_an_empty_row_from_the_migration_counts_as_no_keys():
    await insert_empty_row()
    keys = acme_store.AccountKeys()
    assert await keys.get("https://acme.test/directory") is None
    assert (await keys.put_if_absent("https://acme.test/directory", "pem-a")).pem == "pem-a"
    assert (await keys.get("https://acme.test/directory")).pem == "pem-a"


async def test_remember_kid_keeps_the_account_url_per_directory():
    keys = acme_store.AccountKeys()
    await keys.put_if_absent("https://acme.test/directory", "pem-a")
    await keys.remember_kid("https://acme.test/directory", "https://acme.test/acct/7")
    found = await keys.get("https://acme.test/directory")
    assert found.kid == "https://acme.test/acct/7" and found.pem == "pem-a"
    row = await acme_row()
    assert row.value == {"accounts": {"https://acme.test/directory": {"kid": "https://acme.test/acct/7"}}}
    assert "pem-a" not in json.dumps(row.value) and "pem-a" not in repr(found)


async def test_a_kid_remembered_before_any_key_and_a_row_deleted_meanwhile():
    keys = acme_store.AccountKeys()
    await keys.remember_kid("https://acme.test/directory", "https://acme.test/acct/1")
    assert await keys.get("https://acme.test/directory") is None  # a kid without a key is no key
    async with get_sessionmaker()() as db:
        await db.execute(delete(AppSetting).where(AppSetting.key == acme_store.SETTING_KEY))
        await db.commit()
    assert (await keys.put_if_absent("https://acme.test/directory", "pem-z")).pem == "pem-z"


async def test_an_unreadable_secret_reads_as_no_keys():
    async with get_sessionmaker()() as db:
        db.add(AppSetting(key=acme_store.SETTING_KEY, value={}, secret="not json"))
        await db.commit()
    keys = acme_store.AccountKeys()
    assert await keys.get("https://acme.test/directory") is None
    assert (await keys.put_if_absent("https://acme.test/directory", "pem-a")).pem == "pem-a"


async def test_issue_through_the_store_registers_once_per_directory(server, cf, zone_id):
    keys = acme_store.AccountKeys()
    async with CloudflareClient(TOKEN) as client:
        txt = acme_store.TxtRecords(client, zone_id)
        await certs.issue(NAMES, directory=server.directory_url, keys=keys, txt=txt)
        await certs.issue(NAMES[:1], directory=server.directory_url, keys=keys, txt=txt)
    assert server.registrations == 1
    async with get_sessionmaker()() as db:
        audited = json.dumps([[a.summary, a.details] for a in await db.scalars(select(AuditEvent))])
    pem = json.loads((await acme_row()).secret)[server.directory_url]
    assert pem.splitlines()[1] not in audited


# ----------------------------------------------------------------------------------------- TXT records


async def test_txt_records_create_list_and_delete_with_the_exact_comment(cf, zone_id):
    async with CloudflareClient(TOKEN) as client:
        txt = acme_store.TxtRecords(client, zone_id)
        rid = await txt.create("_acme-challenge.api.shop.example.com", "token-value", certs.CHALLENGE_COMMENT)
        cf.add_record(zone_id, "TXT", "_acme-challenge.portal.shop.example.com", "x",
                      comment=certs.CHALLENGE_COMMENT + " (copy)")
        cf.add_record(zone_id, "A", "_acme-challenge.kiosk.shop.example.com", "203.0.113.9",
                      comment=certs.CHALLENGE_COMMENT)
        (only,) = await txt.list(certs.CHALLENGE_COMMENT)
        assert only == certs.TxtRecord(rid, "_acme-challenge.api.shop.example.com", "token-value",
                                       certs.CHALLENGE_COMMENT)
        cf.ignore_comment_filter = True  # a server that ignores comment=: still exact
        assert [r.id for r in await txt.list(certs.CHALLENGE_COMMENT)] == [rid]
        await txt.delete(rid)
        assert rid not in cf.records
        await txt.delete(rid)  # already gone: no error
        assert await txt.list(certs.CHALLENGE_COMMENT) == []
    post = next(c for c in cf.calls if c["method"] == "POST")
    assert post["body"]["ttl"] == cloudflare.TXT_TTL and post["body"]["type"] == "TXT"
