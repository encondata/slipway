"""Phase 4 slice F3: ACME and certificates (spec tests 10, 11, 12 and 89), all against fake_acme."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta, timezone

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from slipway.services import acme, certs
from tests.fake_acme import FakeAcme, FakeCloudflareTxt, MemoryAccountKeys, MemoryTxtRecords
from tests.fake_cloudflare import FakeCloudflare

NAMES = ["api.example.com", "portal.example.com", "kiosk.example.com", "wiki.example.com",
         "learn.example.com", "status.example.com"]
NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)


@pytest.fixture
def waits(monkeypatch) -> list[float]:
    """No real waiting: every settle and poll sleep is recorded instead."""
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(certs, "sleep", fake_sleep)
    monkeypatch.setattr(acme, "sleep", fake_sleep)
    return slept


@pytest.fixture
def txt() -> MemoryTxtRecords:
    return MemoryTxtRecords()


@pytest.fixture
def fake(monkeypatch, txt) -> FakeAcme:
    server = FakeAcme(txt.lookup)
    monkeypatch.setattr(acme, "transport_factory", lambda: httpx.MockTransport(server.handle))
    return server


class Lines:
    def __init__(self) -> None:
        self.lines: list[str] = []

    async def __call__(self, line: str) -> None:
        self.lines.append(line)


def _secret_lines(pem: str) -> list[str]:
    return [line for line in pem.splitlines() if line and not line.startswith("-----")]


# ------------------------------------------------------------------------ test 10


async def test_issue_six_names_by_dns01(fake, txt, waits):
    keys = MemoryAccountKeys()
    say = Lines()
    issued = await certs.issue(NAMES, directory=fake.directory_url, keys=keys, txt=txt, say=say)

    assert issued.dns_names == sorted(NAMES)
    assert acme.certificate_names(issued.leaf) == sorted(NAMES)
    assert issued.chain == fake.ca_pem
    assert issued.not_after > datetime.now(UTC) + timedelta(days=80)
    assert fake.orders[FakeAcme.names_key(NAMES)] == 1
    # One challenge record per name, with Slipway's comment, present when the server checked it...
    assert sorted(r.name for r in txt.created) == sorted("_acme-challenge." + n for n in NAMES)
    assert {r.comment for r in txt.created} == {certs.CHALLENGE_COMMENT}
    assert all(len(fake.seen_txt["_acme-challenge." + n]) == 1 for n in NAMES)
    # ...held 15 s before the server was told, and all gone afterwards.
    assert waits[0] == certs.DNS_SETTLE
    assert txt.records == {}
    assert sorted(txt.deleted) == sorted(r.id for r in txt.created)
    # The key matches the leaf and is a usable PEM.
    key = serialization.load_pem_private_key(issued.private_key.encode(), password=None)
    leaf = x509.load_pem_x509_certificate(issued.leaf.encode())
    assert key.public_key().public_numbers() == leaf.public_key().public_numbers()
    assert issued.details()["dns_names"] == sorted(NAMES)
    assert set(issued.credentials()) == {"private_key", "leaf", "chain"}


async def test_account_key_made_once_per_directory_and_kid_remembered(monkeypatch, txt, waits):
    live, staging = FakeAcme(txt.lookup), FakeAcme(txt.lookup, base="https://acme-staging.test")

    def route(request: httpx.Request) -> httpx.Response:
        return (staging if request.url.host == "acme-staging.test" else live).handle(request)

    monkeypatch.setattr(acme, "transport_factory", lambda: httpx.MockTransport(route))
    keys = MemoryAccountKeys()

    await certs.issue(NAMES[:2], directory=live.directory_url, keys=keys, txt=txt)
    first_key = keys.keys[live.directory_url]
    assert keys.kids[live.directory_url] in live.accounts
    await certs.issue(NAMES[2:4], directory=live.directory_url, keys=keys, txt=txt)

    assert keys.keys[live.directory_url] == first_key  # reused, not replaced
    assert live.registrations == 1
    assert live.paths().count("/new-account") == 1  # the second run used the remembered kid
    assert sum(live.orders.values()) == 2

    await certs.issue(NAMES[:2], directory=staging.directory_url, keys=keys, txt=txt)
    assert set(keys.keys) == {live.directory_url, staging.directory_url}
    assert keys.keys[staging.directory_url] != first_key  # one key per directory
    assert keys.puts == 2
    assert staging.registrations == 1


async def test_challenge_records_deleted_when_the_order_fails(fake, txt, waits):
    fake.fail_validation = True
    say = Lines()
    with pytest.raises(acme.AcmeError) as err:
        await certs.issue(NAMES, directory=fake.directory_url, keys=MemoryAccountKeys(), txt=txt, say=say)
    assert "authorization invalid" in str(err.value)
    assert len(txt.created) == len(NAMES)
    assert txt.records == {}  # every one deleted in the finally


async def test_failed_challenge_delete_is_logged_not_raised(fake, txt, waits):
    txt.fail_delete = True
    say = Lines()
    issued = await certs.issue(NAMES[:2], directory=fake.directory_url, keys=MemoryAccountKeys(), txt=txt, say=say)
    assert issued.dns_names == sorted(NAMES[:2])
    assert sum("Couldn't delete the challenge record" in line for line in say.lines) == 2
    assert all("RuntimeError" in line for line in say.lines if "Couldn't delete" in line)

    # The order's own error wins over a failed delete.
    fake.fail_validation = True
    with pytest.raises(acme.AcmeError):
        await certs.issue(NAMES[2:4], directory=fake.directory_url, keys=MemoryAccountKeys(), txt=txt, say=say)


async def test_private_keys_never_in_a_log_line(fake, txt, waits, caplog):
    caplog.set_level(logging.DEBUG)
    keys = MemoryAccountKeys()
    say = Lines()
    issued = await certs.issue(NAMES, directory=fake.directory_url, keys=keys, txt=txt, say=say)
    fake.fail_validation = True
    with pytest.raises(acme.AcmeError) as err:
        await certs.issue(NAMES[:1], directory=fake.directory_url, keys=keys, txt=txt, say=say)

    logged = say.lines + [r.getMessage() for r in caplog.records] + [str(err.value)]
    secrets = _secret_lines(issued.private_key) + _secret_lines(keys.keys[fake.directory_url])
    assert secrets
    for line in logged:
        assert "PRIVATE KEY" not in line
        assert not any(s in line for s in secrets), line
    assert "PRIVATE" not in repr(issued) and issued.private_key not in repr(issued)
    assert keys.keys[fake.directory_url] not in repr(await keys.get(fake.directory_url))
    assert issued.secrets() == [issued.private_key]
    # The key is never sent to the ACME server either: only the CSR.
    assert not any(issued.private_key in str(r["payload"]) for r in fake.requests)


async def test_bad_nonce_is_retried_once(fake, txt, waits):
    fake.bad_nonce_once = True
    issued = await certs.issue(NAMES[:1], directory=fake.directory_url, keys=MemoryAccountKeys(), txt=txt)
    assert issued.dns_names == NAMES[:1]


async def test_sixth_order_for_the_same_names_in_a_week_is_refused(fake, txt, waits):
    keys = MemoryAccountKeys()
    for _ in range(5):
        await certs.issue(NAMES, directory=fake.directory_url, keys=keys, txt=txt)
    with pytest.raises(acme.RateLimited) as err:
        await certs.issue(NAMES, directory=fake.directory_url, keys=keys, txt=txt)
    assert err.value.problem == "rateLimited"
    assert "limiting certificates" in str(err.value)
    assert fake.orders[FakeAcme.names_key(NAMES)] == 5
    assert txt.records == {}
    fake.advance(7 * 86400)
    await certs.issue(NAMES, directory=fake.directory_url, keys=keys, txt=txt)
    assert fake.orders[FakeAcme.names_key(NAMES)] == 6


async def test_issued_names_must_be_the_asked_names(fake, txt, waits):
    fake.issue_other_names = ["api.example.com", "evil.example.org"]
    with pytest.raises(certs.CertError, match="other names"):
        await certs.issue(NAMES[:2], directory=fake.directory_url, keys=MemoryAccountKeys(), txt=txt)


async def test_validates_through_fake_cloudflare_records(monkeypatch, waits):
    cf = FakeCloudflare()
    zone_id = cf.add_zone("example.com")
    adapter = FakeCloudflareTxt(cf, zone_id)
    server = FakeAcme(adapter.lookup)
    monkeypatch.setattr(acme, "transport_factory", lambda: httpx.MockTransport(server.handle))
    issued = await certs.issue(NAMES, directory=server.directory_url, keys=MemoryAccountKeys(), txt=adapter)
    assert issued.dns_names == sorted(NAMES)
    assert not [r for r in cf.records.values() if r["type"] == "TXT"]


# ------------------------------------------------------------------------ test 11


def test_certificate_name_and_exact_pattern():
    assert certs.certificate_name("prod", NOW) == "slipway-prod-202611151200"
    assert certs.certificate_name("prod", datetime(2026, 11, 15, 13, 5, tzinfo=timezone(timedelta(hours=1)))) \
        == "slipway-prod-202611151205"
    pattern = certs.name_pattern("prod")
    assert pattern.match("slipway-prod-202611151200")
    assert not pattern.match("slipway-prod-eu-202611151200")  # prod's rule never takes prod-eu's
    assert not pattern.match("slipway-prod-20261115120")
    assert not pattern.match("slipway-prod-202611151200\n")
    assert not pattern.match("xslipway-prod-202611151200")
    assert certs.name_pattern("prod-eu").match("slipway-prod-eu-202611151200")
    assert not certs.name_pattern("a.b").match("slipway-axb-202611151200")  # escaped


def test_is_ours_needs_the_exact_name_pattern_and_exact_names():
    wanted = ["api.example.com", "portal.example.com"]
    cert = {"id": "c1", "name": "slipway-prod-202611151200", "dns_names": ["portal.example.com", "api.example.com"]}
    assert certs.is_ours(cert, "prod", wanted)
    assert not certs.is_ours({**cert, "name": "slipway-prod-eu-202611151200"}, "prod", wanted)
    assert not certs.is_ours(cert, "prod-eu", wanted)
    assert not certs.is_ours({**cert, "dns_names": ["api.example.com"]}, "prod", wanted)  # a subset
    assert not certs.is_ours({**cert, "dns_names": wanted + ["x.example.com"]}, "prod", wanted)  # a superset
    assert not certs.is_ours({**cert, "name": None}, "prod", wanted)

    hostnames = wanted + ["wiki.example.com"]
    assert certs.ours_for_teardown(cert, "prod", hostnames)
    assert certs.ours_for_teardown({**cert, "dns_names": ["wiki.example.com"]}, "prod", hostnames)
    assert not certs.ours_for_teardown({**cert, "dns_names": ["other.example.com"]}, "prod", hostnames)
    assert not certs.ours_for_teardown({**cert, "dns_names": []}, "prod", hostnames)
    assert not certs.ours_for_teardown({**cert, "name": "slipway-prod-eu-202611151200"}, "prod", hostnames)


def test_not_after_parsing():
    assert certs.not_after({"not_after": "2027-02-08T16:02:37Z"}) == datetime(2027, 2, 8, 16, 2, 37, tzinfo=UTC)
    assert certs.not_after({"not_after": "2027-02-08T17:02:37+01:00"}) == datetime(2027, 2, 8, 16, 2, 37, tzinfo=UTC)
    assert certs.not_after({"not_after": "2027-02-08T16:02:37"}) == datetime(2027, 2, 8, 16, 2, 37, tzinfo=UTC)
    assert certs.not_after({"not_after": datetime(2027, 2, 8)}) == datetime(2027, 2, 8, tzinfo=UTC)
    assert certs.not_after({"not_after": "soon"}) is None
    assert certs.not_after({}) is None


def test_best_is_the_latest_expiry_and_a_tie_goes_to_the_served_one():
    a = {"id": "a", "not_after": "2027-01-01T00:00:00Z"}
    b = {"id": "b", "not_after": "2027-03-01T00:00:00Z"}
    c = {"id": "c", "not_after": "2027-03-01T00:00:00Z"}
    broken = {"id": "x", "not_after": None}
    assert certs.best([]) is None
    assert certs.best([a, b]) is b
    assert certs.best([b, a]) is b
    assert certs.best([b, c], served_id="c") is c
    assert certs.best([c, b], served_id="b") is b
    assert certs.best([b, c]) is b  # no served one: the first stays
    assert certs.best([broken, a]) is a
    assert certs.best([a, broken], served_id="x") is a


def test_due_at_30_days_or_fewer():
    assert certs.is_due(NOW + timedelta(days=30), NOW)
    assert certs.is_due(NOW + timedelta(days=29), NOW)
    assert certs.is_due(NOW - timedelta(days=1), NOW)
    assert not certs.is_due(NOW + timedelta(days=30, minutes=1), NOW)
    assert certs.is_due(None, NOW)

    wanted = ["api.example.com"]
    fresh = {"id": "a", "not_after": (NOW + timedelta(days=60)).isoformat(), "dns_names": wanted}
    assert not certs.needs_new(fresh, wanted, NOW)
    assert certs.needs_new(None, wanted, NOW)
    assert certs.needs_new({**fresh, "not_after": (NOW + timedelta(days=30)).isoformat()}, wanted, NOW)
    assert certs.needs_new(fresh, wanted + ["portal.example.com"], NOW)

    kept = {"not_after": (NOW + timedelta(days=31)).isoformat(), "dns_names": wanted}
    assert certs.kept_usable(kept, wanted, NOW)
    assert not certs.kept_usable({**kept, "not_after": (NOW + timedelta(days=30)).isoformat()}, wanted, NOW)
    assert not certs.kept_usable(kept, wanted + ["portal.example.com"], NOW)


def test_wanted_names_is_the_union_of_live_slots_and_the_deploying_release():
    blue = [{"hostname": "api.example.com", "follows": "active"}, {"hostname": "learn.example.com"}]
    green = [{"hostname": "api.example.com"}, {"hostname": "portal.example.com"}]
    new = [{"hostname": "kiosk.example.com"}, {"hostname": "spaces.example.com", "follows": "server"}]
    assert certs.wanted_names([blue, green]) == ["api.example.com", "learn.example.com", "portal.example.com"]
    # A deploy to green that drops learn keeps it while blue's live release still serves it.
    assert certs.wanted_names([blue, green], new, zone="example.com") == [
        "api.example.com", "kiosk.example.com", "learn.example.com", "portal.example.com"]
    # Only when no slot's live release serves it does a name leave.
    assert "learn.example.com" not in certs.wanted_names([green, green])
    assert certs.wanted_names([["API.Example.com."], None]) == ["api.example.com"]

    with pytest.raises(certs.CertError, match="outside the Cloudflare zone example.com"):
        certs.wanted_names([["api.example.org"]], zone="example.com")
    with pytest.raises(certs.CertError, match="No names"):
        certs.wanted_names([[], []])
    with pytest.raises(certs.CertError, match="at most 100"):
        certs.wanted_names([[f"n{i}.example.com" for i in range(101)]])
    with pytest.raises(certs.CertError, match="aren't hostnames"):
        certs.wanted_names([["*.example.com"]])


# ------------------------------------------------------------------------ test 12


def test_staging_directory_selection_and_production_refuses_staging():
    assert certs.directory_url(staging=False) == certs.LETSENCRYPT_DIRECTORY
    assert certs.directory_url(staging=True) == certs.LETSENCRYPT_STAGING_DIRECTORY
    assert certs.directory_url(staging=False, production=True) == certs.LETSENCRYPT_DIRECTORY

    class Settings:
        acme_directory = "https://acme.internal/directory"
        acme_staging_directory = "https://acme-staging.internal/directory"

    assert certs.directory_url(staging=False, settings=Settings()) == Settings.acme_directory
    assert certs.directory_url(staging=True, settings=Settings()) == Settings.acme_staging_directory

    with pytest.raises(certs.CertError, match="production environment can't use Let's Encrypt staging"):
        certs.directory_url(staging=True, production=True)
    with pytest.raises(certs.CertError):
        certs.check_staging(production=True, staging=True)
    certs.check_staging(production=True, staging=False)
    certs.check_staging(production=False, staging=True)


# ------------------------------------------------------------------------ test 89


async def test_left_challenge_records_are_swept_before_an_order(fake, txt, waits):
    crashed = txt.add("_acme-challenge.api.example.com", "stale-value", certs.CHALLENGE_COMMENT)
    crashed2 = txt.add("_acme-challenge.portal.example.com", "stale-value-2", certs.CHALLENGE_COMMENT)
    theirs = txt.add("_acme-challenge.api.example.com", "someone-elses", None)
    other_comment = txt.add("_acme-challenge.portal.example.com", "x", "Managed by Slipway: uat (0123456789ab)")
    say = Lines()

    await certs.issue(["api.example.com", "portal.example.com"], directory=fake.directory_url,
                      keys=MemoryAccountKeys(), txt=txt, say=say)

    assert crashed.id in txt.deleted and crashed2.id in txt.deleted
    assert txt.deleted.index(crashed.id) < len(txt.deleted) - 2  # swept before the order's own records
    assert set(txt.records) == {theirs.id, other_comment.id}  # without Slipway's challenge comment: left
    assert "Deleted 2 left-over challenge records" in say.lines
    assert fake.orders[("api.example.com", "portal.example.com")] == 1


async def test_sweep_only_touches_the_given_names(txt):
    mine = txt.add("_acme-challenge.api.example.com", "v", certs.CHALLENGE_COMMENT)
    other_env = txt.add("_acme-challenge.shop.example.com", "v", certs.CHALLENGE_COMMENT)
    not_a_challenge = txt.add("api.example.com", "v", certs.CHALLENGE_COMMENT)
    assert await certs.sweep_challenges(txt, ["api.example.com"]) == 1
    assert set(txt.records) == {other_env.id, not_a_challenge.id}
    assert mine.id in txt.deleted


async def test_two_first_uses_of_a_directory_store_one_key(fake, txt, waits):
    keys = MemoryAccountKeys()
    first, second = await asyncio.gather(
        certs.issue(NAMES[:3], directory=fake.directory_url, keys=keys, txt=txt),
        certs.issue(NAMES[3:], directory=fake.directory_url, keys=keys, txt=txt),
    )
    assert keys.puts == 1
    assert len(keys.keys) == 1
    assert len(fake.accounts) == 1  # both orders were signed by the one stored key
    assert fake.registrations == 1
    assert keys.kids[fake.directory_url] in fake.accounts
    assert first.dns_names == sorted(NAMES[:3]) and second.dns_names == sorted(NAMES[3:])
    assert txt.records == {}


async def test_account_key_put_if_absent_keeps_the_first(monkeypatch):
    keys = MemoryAccountKeys()
    made = iter(["pem-one", "pem-two"])
    monkeypatch.setattr(acme, "generate_account_key", lambda: next(made))
    a, b = await asyncio.gather(certs.account_key(keys, "https://x.test/d"), certs.account_key(keys, "https://x.test/d"))
    assert a.pem == b.pem == "pem-one"
    assert keys.keys == {"https://x.test/d": "pem-one"}
