"""Sign in with HackSpaceLabs (PLAN.md work package 4) against a fake Keycloak that signs real RS256 tokens.

The cases follow Switchyard's internal/server/oidc_test.go, plus Slipway's own: linking, the email rules, the
GitHub and password refusals for linked accounts (D16), the owner check of API tokens (D18), re-authentication
for the recent sign-in rule, and the open-redirect cases written for GitHub.
"""

from __future__ import annotations

import logging
import uuid
from datetime import timedelta
from urllib.parse import parse_qs, quote, urlsplit

import pytest
from sqlalchemy import func, select, update

from slipway.core.config import get_settings
from slipway.db.base import utcnow
from slipway.db.session import get_sessionmaker
from slipway.main import _log_hsl_settings
from slipway.models import AuditEvent, OAuthAccount, User, UserSession
from slipway.services import hsl
from slipway.web import hsl as hsl_web
from slipway.web import oauth
from tests.conftest import PASSWORD, login, make_user
from tests.fake_keycloak import CLIENT_SECRET, ISSUER, PORTAL, FakeKeycloak, KcUser

H96 = 96 * 3600


@pytest.fixture
def kc(monkeypatch) -> FakeKeycloak:
    fake = FakeKeycloak()
    settings = get_settings()
    monkeypatch.setattr(settings, "hsl_oidc_issuer", ISSUER)
    monkeypatch.setattr(settings, "hsl_oidc_client_secret", CLIENT_SECRET)
    monkeypatch.setattr(settings, "hsl_portal_internal_url", PORTAL)
    monkeypatch.setattr(hsl, "transport_factory", fake.transport)
    hsl.reset()
    yield fake
    hsl.reset()


@pytest.fixture
async def admin(kc) -> User:
    """The local admin every Slipway keeps (password, no link): the first account."""
    return await make_user("admin@example.com")


def _alice(kc: FakeKeycloak, **kw) -> KcUser:
    return kc.add(KcUser(sub=kw.pop("sub", "sub-alice"), username="alice", email=kw.pop("email", "alice@example.com"),
                         name="Alice Example", roles=kw.pop("roles", ["developer"]), **kw))


async def _start(client, path="/auth/hsl/login?next=/hosts") -> str:
    r = await client.get(path)
    assert r.status_code == 303, (r.status_code, r.text[:300])
    assert r.headers["location"].startswith(f"{ISSUER}/protocol/openid-connect/auth?"), r.headers["location"]
    return r.headers["location"]


async def _sign_in(client, kc, sub="sub-alice", path="/auth/hsl/login?next=/hosts"):
    return await client.get(kc.authorize(await _start(client, path), sub))


def _cookie(response, name: str) -> str:
    return next((c for c in response.headers.get_list("set-cookie") if c.startswith(f"{name}=")), "")


async def _me(client):
    r = await client.get("/api/v1/auth/me")
    return r.status_code, (r.json()["user"] if r.status_code == 200 else None)


async def _count(model) -> int:
    async with get_sessionmaker()() as db:
        return int(await db.scalar(select(func.count()).select_from(model)) or 0)


async def _due() -> None:
    """Make every HackSpaceLabs session due for its recheck."""
    async with get_sessionmaker()() as db:
        await db.execute(update(UserSession).values(idp_checked_at=utcnow() - timedelta(hours=1)))
        await db.commit()


async def _actions() -> list[str]:
    async with get_sessionmaker()() as db:
        return list((await db.scalars(select(AuditEvent.action).order_by(AuditEvent.created_at))).all())


# ------------------------------------------------------------------ sign-in


async def test_sign_in_creates_the_account_and_a_keycloak_length_session(client, kc, admin):
    _alice(kc)
    r = await _sign_in(client, kc)
    assert r.status_code == 303 and r.headers["location"] == "/hosts"
    cookie = _cookie(r, "slipway_session")
    assert f"Max-Age={H96}" in cookie and "HttpOnly" in cookie and "SameSite=lax" in cookie, cookie
    status, me = await _me(client)
    assert status == 200 and me["email"] == "alice@example.com" and me["roles"] == ["developer"]
    assert me["hackspacelabs_login"] == "alice" and me["full_name"] == "Alice Example" and not me["has_password"]
    # PKCE: the code was exchanged with the verifier and the same redirect URI.
    exchange = kc.token_requests[-1]
    assert exchange["grant_type"] == "authorization_code" and exchange["code_verifier"]
    assert exchange["redirect_uri"] == "http://testserver/auth/hsl/callback"
    # Signing in again finds the same account.
    await _sign_in(client, kc)
    assert await _count(User) == 2
    assert "auth.login" in await _actions()


async def test_remember_me_session_lasts_as_long_as_keycloak_says(client, kc, admin):
    _alice(kc)
    kc.session_lifetime = 2592000
    r = await _sign_in(client, kc)
    assert "Max-Age=2592000" in _cookie(r, "slipway_session")
    async with get_sessionmaker()() as db:
        session = await db.scalar(select(UserSession))
        assert timedelta(days=29, hours=23) < session.expires_at - utcnow() <= timedelta(days=30)
        assert session.auth_source == "oidc" and session.idp_sid and session.idp_tokens["sub"] == "sub-alice"


async def test_local_sessions_last_96_hours(client, admin):
    r = await client.post("/api/v1/auth/login", json={"email": "admin@example.com", "password": PASSWORD})
    assert r.status_code == 200 and f"Max-Age={H96}" in _cookie(r, "slipway_session")
    async with get_sessionmaker()() as db:
        session = await db.scalar(select(UserSession))
        assert session.auth_source == "local" and timedelta(hours=95) < session.expires_at - utcnow() <= timedelta(hours=96)


async def test_the_callback_needs_its_own_flow(client, make_client, kc, admin):
    _alice(kc)
    callback = kc.authorize(await _start(client), "sub-alice")
    # Another browser (no flow cookie) can't use the callback address.
    other = make_client()
    r = await other.get(callback)
    assert r.headers["location"] == "/login?error=sso_expired"
    # Tampered state.
    parts = urlsplit(callback)
    query = {k: v[0] for k, v in parse_qs(parts.query).items()}
    r = await client.get(f"/auth/hsl/callback?code={query['code']}&state=not-the-state")
    assert r.headers["location"] == "/login?error=sso_expired"
    # The real one works once; replaying it in this (now signed-in) browser just goes home.
    assert (await client.get(callback)).headers["location"] == "/hosts"
    assert (await client.get(callback)).headers["location"] == "/"
    assert (await make_client().get(callback)).headers["location"] == "/login?error=sso_expired"


async def test_the_flow_cookie_is_per_attempt_and_scoped_to_the_callback(client, kc):
    first = await client.get("/auth/hsl/login?next=/a")
    second = await client.get("/auth/hsl/login?next=/b")
    names = {c.split("=", 1)[0] for r in (first, second) for c in r.headers.get_list("set-cookie")}
    assert len(names) == 2 and all(n.startswith("slipway_hsl_") for n in names)
    cookie = first.headers.get_list("set-cookie")[0]
    assert "Path=/auth/hsl" in cookie and "HttpOnly" in cookie and "Max-Age=600" in cookie and "SameSite=lax" in cookie
    assert "next" not in cookie.split(";")[0]  # the flow is encrypted, not just signed


@pytest.mark.parametrize("switch", ["wrong_issuer", "wrong_audience", "wrong_nonce", "bad_signature"])
async def test_bad_tokens_are_refused(client, kc, admin, switch):
    _alice(kc)
    setattr(kc, switch, True)
    r = await _sign_in(client, kc)
    assert r.headers["location"] == "/login?error=sso_failed"
    assert (await _me(client))[0] == 401 and await _count(User) == 1


async def test_keycloak_errors_and_outages(client, kc):
    url = await _start(client)
    state = parse_qs(urlsplit(url).query)["state"][0]
    r = await client.get(f"/auth/hsl/callback?error=access_denied&state={state}")
    assert r.headers["location"] == "/login?error=sso_cancelled"
    url = await _start(client)
    state = parse_qs(urlsplit(url).query)["state"][0]
    r = await client.get(f"/auth/hsl/callback?error=server_error&state={state}")
    assert r.headers["location"] == "/login?error=sso_failed"
    hsl.reset()
    kc.discovery_down = True
    r = await client.get("/auth/hsl/login?next=/")
    assert r.status_code == 303 and r.headers["location"] == "/login?error=sso_unavailable"


async def test_no_role_no_account(client, kc, admin):
    kc.add(KcUser(sub="sub-cust", username="customer", email="c@example.com"))  # no hsl_roles claim at all
    kc.add(KcUser(sub="sub-other", username="other", roles=["portal-admin"]))
    for sub in ("sub-cust", "sub-other"):
        r = await _sign_in(client, kc, sub)
        assert r.headers["location"] == "/login?error=no_access"
    assert await _count(User) == 1 and await _count(OAuthAccount) == 0
    assert (await _actions()).count("auth.login_refused") == 2
    page = (await client.get("/login?error=no_access")).text
    assert "doesn&#39;t have access to Slipway" in page and 'href="/auth/hsl/switch"' in page


async def test_use_a_different_account_goes_through_keycloak_sign_out(client, kc):
    r = await client.get("/auth/hsl/switch")
    target = urlsplit(r.headers["location"])
    q = parse_qs(target.query)
    assert r.status_code == 303 and r.headers["location"].startswith(f"{ISSUER}/protocol/openid-connect/logout?")
    assert q["client_id"] == ["slipway"] and q["post_logout_redirect_uri"] == ["http://testserver/signed-out"]


async def test_roles_are_exactly_the_claimed_slipway_roles(client, kc, admin):
    _alice(kc, roles=["maintainer", "viewer", "not-a-slipway-role"])
    await _sign_in(client, kc)
    assert (await _me(client))[1]["roles"] == ["maintainer", "viewer"]


# ------------------------------------------------------------------ who it becomes (D9)


async def test_verified_email_links_an_existing_account(client, kc, admin):
    await make_user("alice@example.com", roles=["viewer"])
    _alice(kc, email_verified=True, roles=["developer"])
    await _sign_in(client, kc)
    status, me = await _me(client)
    assert status == 200 and me["email"] == "alice@example.com" and me["roles"] == ["developer"]
    assert me["hackspacelabs_login"] == "alice" and me["has_password"] and await _count(User) == 2


async def test_unverified_email_never_links(client, kc, admin):
    await make_user("alice@example.com", roles=["viewer"])
    _alice(kc)  # email_verified false, as Keycloak has it unless an administrator marks it
    r = await _sign_in(client, kc)
    assert r.headers["location"] == "/login?error=account_exists"
    assert await _count(OAuthAccount) == 0 and await _count(User) == 2


async def test_without_an_email_the_address_is_made_from_the_username(client, kc, admin):
    _alice(kc, email="")
    await _sign_in(client, kc)
    assert (await _me(client))[1]["email"] == "alice@hsl.invalid"


async def test_a_made_up_address_that_is_taken_is_refused_not_varied(client, kc, admin):
    await make_user("alice@hsl.invalid", roles=["viewer"])
    _alice(kc, email="")
    r = await _sign_in(client, kc)
    assert r.headers["location"] == "/login?error=account_exists" and await _count(User) == 2


async def test_no_first_account_through_hackspacelabs(client, kc):
    _alice(kc, roles=["admin"])
    r = await _sign_in(client, kc)
    assert r.headers["location"] == "/login?error=no_admin" and await _count(User) == 0


async def test_a_deactivated_account_is_refused(make_client, admin_client, kc):
    client = make_client()
    _alice(kc)
    await _sign_in(client, kc)
    _, me = await _me(client)
    r = await admin_client.patch(f"/api/v1/users/{me['id']}", json={"is_active": False})
    assert r.status_code == 200
    assert (await _me(client))[0] == 401
    r = await _sign_in(client, kc)
    assert r.headers["location"] == "/login?error=no_access"
    assert await _count(User) == 2  # the link survived deactivation, so no fresh account was made


# ------------------------------------------------------------------ linking


async def test_link_from_settings(client, kc, admin):
    await make_user("bob@example.com", roles=["viewer"])
    await login(client, "bob@example.com")
    kc.add(KcUser(sub="sub-bob", username="bob", email="other@example.com", roles=["developer"]))
    start = await _start(client, "/auth/hsl/link")
    assert parse_qs(urlsplit(start).query)["prompt"] == ["login"]
    r = await client.get(kc.authorize(start, "sub-bob"))
    assert r.headers["location"] == "/settings?linked=hackspacelabs"
    status, me = await _me(client)
    assert status == 200 and me["email"] == "bob@example.com" and me["hackspacelabs_login"] == "bob"
    assert me["roles"] == ["developer"]
    async with get_sessionmaker()() as db:
        assert [s.auth_source for s in (await db.scalars(select(UserSession))).all()] == ["oidc"]
    assert "HackSpaceLabs account linked" in (await client.get("/settings?linked=hackspacelabs")).text
    # D16: the password no longer signs in; a wrong one still says what it always said.
    fresh = await client.post("/api/v1/auth/login", json={"email": "bob@example.com", "password": PASSWORD})
    assert fresh.status_code == 401 and fresh.json()["detail"] == "This account signs in with HackSpaceLabs"
    wrong = await client.post("/api/v1/auth/login", json={"email": "bob@example.com", "password": "nope-nope-nope"})
    assert wrong.status_code == 401 and wrong.json()["detail"] == "Invalid email or password"


async def test_link_needs_a_recent_sign_in_and_its_own_session(client, make_client, kc, admin):
    await make_user("bob@example.com", roles=["viewer"])
    await login(client, "bob@example.com")
    kc.add(KcUser(sub="sub-bob", username="bob", roles=["developer"]))
    start = await _start(client, "/auth/hsl/link")
    # The flow is bound to the session that started it: a different session can't finish it.
    async with get_sessionmaker()() as db:
        await db.execute(update(UserSession).values(token_hash="0" * 64))
        await db.commit()
    await login(client, "bob@example.com")
    r = await client.get(kc.authorize(start, "sub-bob"))
    assert r.headers["location"] == "/settings?error=sso_expired" and await _count(OAuthAccount) == 0
    # An old sign-in gets the sign-in-again page.
    async with get_sessionmaker()() as db:
        await db.execute(update(UserSession).values(created_at=utcnow() - timedelta(hours=1)))
        await db.commit()
    r = await client.get("/auth/hsl/link")
    assert r.status_code == 403 and "Sign in again" in r.text
    # Signed out: to the sign-in page.
    r = await make_client().get("/auth/hsl/link")
    assert r.status_code == 302 and r.headers["location"] == "/login?next=/settings"


async def test_the_last_local_admin_cannot_be_linked(client, kc, admin):
    await login(client, "admin@example.com")
    kc.add(KcUser(sub="sub-adm", username="adm", roles=["admin"]))
    r = await client.get(kc.authorize(await _start(client, "/auth/hsl/link"), "sub-adm"))
    assert r.headers["location"] == "/settings?error=sso_last_admin" and await _count(OAuthAccount) == 0
    # With another local admin it can.
    await make_user("second@example.com", roles=["admin"])
    r = await client.get(kc.authorize(await _start(client, "/auth/hsl/link"), "sub-adm"))
    assert r.headers["location"] == "/settings?linked=hackspacelabs"


async def test_a_hackspacelabs_account_links_to_one_slipway_account(client, make_client, kc, admin):
    _alice(kc)
    await _sign_in(make_client(), kc)  # alice@example.com now exists and is linked
    await make_user("bob@example.com", roles=["viewer"])
    await login(client, "bob@example.com")
    r = await client.get(kc.authorize(await _start(client, "/auth/hsl/link"), "sub-alice"))
    assert r.headers["location"] == "/settings?error=sso_linked_elsewhere"


async def test_github_sign_in_is_refused_for_a_linked_account(client, make_client, kc, admin, monkeypatch):
    from tests.test_github_oauth import FakeGH

    async def exchange(code):
        return "gho_test", "read:user,user:email,repo"

    monkeypatch.setattr(oauth, "exchange_code", exchange)
    monkeypatch.setattr(oauth, "GitHubClient", FakeGH)
    _alice(kc)
    await _sign_in(client, kc)
    # Linking GitHub from a HackSpaceLabs session needs a fresh HackSpaceLabs sign-in first...
    kc.auth_age = 3600
    await _sign_in(client, kc)
    r = await client.get("/auth/github/link")
    assert r.status_code == 302 and r.headers["location"] == "/auth/hsl/login?reauth=1&next=%2Fauth%2Fgithub%2Flink"
    # ...which must really be fresh.
    start = await _start(client, r.headers["location"])
    q = parse_qs(urlsplit(start).query)
    assert q["prompt"] == ["login"] and q["max_age"] == ["0"]
    r = await client.get(kc.authorize(start, "sub-alice"))
    assert r.headers["location"] == "/login?error=sso_reauth"
    kc.auth_age = 0
    r = await client.get(kc.authorize(await _start(client, "/auth/hsl/login?reauth=1&next=%2Fauth%2Fgithub%2Flink"), "sub-alice"))
    assert r.headers["location"] == "/auth/github/link"
    r = await client.get("/auth/github/link")
    state = parse_qs(urlsplit(r.headers["location"]).query)["state"][0]
    r = await client.get(f"/auth/github/callback?code=good-code&state={state}")
    assert r.headers["location"] == "/settings?linked=1"  # linking GitHub (for repositories) still works
    # Signing in with that GitHub account does not.
    fresh = make_client()
    r = await fresh.get("/auth/github/login")
    state = parse_qs(urlsplit(r.headers["location"]).query)["state"][0]
    r = await fresh.get(f"/auth/github/callback?code=good-code&state={state}")
    assert r.headers["location"] == "/login?error=hsl_only"
    assert (await _me(fresh))[0] == 401


# ------------------------------------------------------------------ recheck


async def test_recheck_applies_roles_keeps_through_outages_and_ends_without_a_role(client, kc, admin):
    user = _alice(kc)
    await _sign_in(client, kc)
    user.roles = ["viewer"]
    user.name = "Alice Renamed"
    await _due()
    status, me = await _me(client)
    assert status == 200 and me["roles"] == ["viewer"] and me["full_name"] == "Alice Renamed"

    kc.down = True
    await _due()
    assert (await _me(client))[0] == 200
    async with get_sessionmaker()() as db:  # the next attempt waits a full interval
        assert utcnow() - (await db.scalar(select(UserSession))).idp_checked_at < timedelta(seconds=5)
    kc.down = False

    user.roles = None
    await _due()
    r = await client.get("/api/v1/auth/me")
    assert r.status_code == 401 and 'slipway_session=""' in _cookie(r, "slipway_session")
    assert await _count(UserSession) == 0 and "auth.session_ended" in await _actions()


@pytest.mark.parametrize("what", ["signed out", "disabled"])
async def test_recheck_ends_signed_out_or_disabled_people(client, kc, admin, what):
    user = _alice(kc)
    await _sign_in(client, kc)
    if what == "signed out":
        kc.sign_out("sub-alice")
    else:
        user.disabled = True
    await _due()
    assert (await _me(client))[0] == 401


async def test_recheck_waits_for_its_interval(client, kc, admin):
    _alice(kc)
    await _sign_in(client, kc)
    kc.sign_out("sub-alice")
    for _ in range(3):
        assert (await _me(client))[0] == 200
    assert kc.refresh_requests == 0


async def test_recheck_refuses_an_answer_for_someone_else(client, kc, admin):
    _alice(kc)
    await _sign_in(client, kc)
    async with get_sessionmaker()() as db:
        session = await db.scalar(select(UserSession))
        session.idp_tokens = dict(session.idp_tokens, sub="sub-mallory")
        await db.commit()
    await _due()
    assert (await _me(client))[0] == 401


async def test_the_last_admin_is_not_demoted_but_signed_out(client, kc):
    await make_user("admin@example.com")
    await make_user("second@example.com", roles=["admin"])
    user = _alice(kc, roles=["admin"])
    await _sign_in(client, kc)
    async with get_sessionmaker()() as db:  # alice becomes the only active admin
        await db.execute(update(User).where(User.email != "alice@example.com").values(is_active=False))
        await db.commit()
    user.roles = ["viewer"]
    await _due()
    assert (await _me(client))[0] == 401
    async with get_sessionmaker()() as db:
        alice = await db.scalar(select(User).where(User.email == "alice@example.com"))
        assert alice.role_names == ["admin"]


async def test_sessions_end_when_sign_in_is_turned_off(client, kc, admin, monkeypatch):
    _alice(kc)
    await _sign_in(client, kc)
    monkeypatch.setattr(get_settings(), "hsl_oidc_issuer", "")
    assert (await _me(client))[0] == 401 and await _count(UserSession) == 0


# ------------------------------------------------------------------ sign-out


async def test_sign_out(client, kc, admin):
    _alice(kc)
    await _sign_in(client, kc)
    csrf = (await client.get("/api/v1/auth/me")).json()["csrf_token"]
    r = await client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    target = r.json()["redirect"]
    q = parse_qs(urlsplit(target).query)
    assert target.startswith(f"{ISSUER}/protocol/openid-connect/logout?")
    assert q["client_id"] == ["slipway"] and q["id_token_hint"][0] and q["post_logout_redirect_uri"] == ["http://testserver/signed-out"]
    assert (await _me(client))[0] == 401
    # A local session still answers 204.
    await login(client, "admin@example.com")
    assert (await client.post("/api/v1/auth/logout")).status_code == 204
    page = await client.get("/signed-out")
    assert page.status_code == 200 and "signed out of HackSpaceLabs" in page.text and 'href="/login"' in page.text


# ------------------------------------------------------------------ addresses


async def test_host_and_next(client, kc, admin):
    r = await client.get("http://127.0.0.1/auth/hsl/login?next=%2Fx")
    assert r.status_code == 303 and r.headers["location"] == "http://testserver/auth/hsl/login?next=%2Fx"
    _alice(kc)
    for bad in ("https://evil.example/", "//evil.example", "/\\evil", "/\tx", "javascript:alert(1)"):
        r = await _sign_in(client, kc, path=f"/auth/hsl/login?next={quote(bad, safe='')}")
        assert r.headers["location"] == "/", bad


# ------------------------------------------------------------------ the sign-in page


async def test_sign_in_page(client, kc, monkeypatch):
    page = (await client.get("/login?next=/hosts")).text
    assert 'href="/auth/hsl/login?next=/hosts"' in page and "Sign in with HackSpaceLabs" in page
    assert 'id="login-form"' in page and page.index("HackSpaceLabs") < page.index("Continue with GitHub")
    monkeypatch.setattr(get_settings(), "hsl_oidc_auto_redirect", True)
    r = await client.get("/login?next=/hosts")
    assert r.status_code == 302 and r.headers["location"] == "/auth/hsl/login?next=%2Fhosts"
    assert "Max-Age=30" in _cookie(r, hsl_web.TRY_COOKIE)
    # Back again within 30 seconds: the session cookie didn't stick, so no second bounce.
    r = await client.get("/login?next=/hosts")
    assert r.status_code == 200 and "didn&#39;t work" in r.text and 'id="login-form"' not in r.text
    for path in ("/login?local=1", "/login?error=sso_unavailable"):
        r = await client.get(path)
        assert r.status_code == 200 and 'id="login-form"' in r.text, path
    r = await client.get("/login?error=no_access")
    assert r.status_code == 200 and 'id="login-form"' not in r.text
    assert (await client.get("/signed-out")).status_code == 200


async def test_a_signed_in_page_clears_the_auto_redirect_marker(client, kc, admin, monkeypatch):
    monkeypatch.setattr(get_settings(), "hsl_oidc_auto_redirect", True)
    _alice(kc)
    r = await client.get("/")
    assert r.headers["location"] == "/login?next=/"
    r = await client.get(r.headers["location"])
    assert r.headers["location"] == "/auth/hsl/login?next=%2F"
    r = await client.get(kc.authorize(await _start(client, r.headers["location"]), "sub-alice"))
    assert r.headers["location"] == "/"
    page = await client.get("/")
    assert page.status_code == 200 and f'{hsl_web.TRY_COOKIE}=""' in _cookie(page, hsl_web.TRY_COOKIE)


async def test_without_hackspacelabs_nothing_changes(client):
    page = (await client.get("/login")).text
    assert "HackSpaceLabs" not in page and 'id="login-form"' in page
    assert (await client.get("/auth/hsl/login")).status_code == 404
    assert (await client.get("/auth/hsl/callback?state=x&code=y")).status_code == 404


# ------------------------------------------------------------------ API tokens (D18)


async def _token_for(client) -> str:
    csrf = (await client.get("/api/v1/auth/me")).json()["csrf_token"]
    r = await client.post("/api/v1/tokens", json={"name": "ci"}, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 201, r.text
    return r.json()["token"]


async def test_api_tokens_of_linked_owners_follow_the_portal(client, make_client, kc, admin):
    user = _alice(kc)
    await _sign_in(client, kc)
    token = await _token_for(client)
    api = make_client()
    api.headers["Authorization"] = f"Bearer {token}"
    assert (await api.get("/api/v1/auth/me")).status_code == 200
    assert kc.owner_requests == ["sub-alice"]
    # Asked at most every five minutes.
    user.disabled = True
    assert (await api.get("/api/v1/auth/me")).status_code == 200 and len(kc.owner_requests) == 1
    hsl._owners["sub-alice"] = (0.0, True)  # five minutes later
    assert (await api.get("/api/v1/auth/me")).status_code == 401
    # The portal down: the last answer stands; someone never checked is let through.
    kc.portal_status = 503
    hsl._owners["sub-alice"] = (0.0, False)
    assert (await api.get("/api/v1/auth/me")).status_code == 401
    user.disabled = False
    hsl.reset()
    assert (await api.get("/api/v1/auth/me")).status_code == 200
    # No Slipway role: refused.
    kc.portal_status = 200
    user.roles = []
    hsl.reset()
    assert (await api.get("/api/v1/auth/me")).status_code == 401


async def test_api_tokens_of_unlinked_owners_are_not_checked(admin_client, make_client, kc):
    token = await _token_for(admin_client)
    api = make_client()
    api.headers["Authorization"] = f"Bearer {token}"
    assert (await api.get("/api/v1/auth/me")).status_code == 200 and kc.owner_requests == []


async def test_no_portal_address_no_owner_check(client, make_client, kc, admin, monkeypatch):
    user = _alice(kc)
    await _sign_in(client, kc)
    token = await _token_for(client)
    monkeypatch.setattr(get_settings(), "hsl_portal_internal_url", "")
    user.disabled = True
    api = make_client()
    api.headers["Authorization"] = f"Bearer {token}"
    assert (await api.get("/api/v1/auth/me")).status_code == 200 and kc.owner_requests == []


# ------------------------------------------------------------------ admin reset and deactivation


async def test_a_password_reset_unlinks_hackspacelabs_and_deactivation_does_not(make_client, admin_client, kc):
    client = make_client()
    _alice(kc)
    await _sign_in(client, kc)
    _, me = await _me(client)
    r = await admin_client.patch(f"/api/v1/users/{me['id']}", json={"is_active": False})
    assert r.status_code == 200 and r.json()["hackspacelabs_login"] == "alice"
    # Reactivating needs no password: the HackSpaceLabs link is a way in.
    r = await admin_client.patch(f"/api/v1/users/{me['id']}", json={"is_active": True})
    assert r.status_code == 200, r.text
    r = await admin_client.patch(f"/api/v1/users/{me['id']}", json={"password": "a-brand-new-password"})
    assert r.status_code == 200 and r.json()["hackspacelabs_login"] is None
    assert "user.hackspacelabs_unlinked" in await _actions()
    # Until they link again, a HackSpaceLabs sign-in finds the address taken.
    r = await _sign_in(client, kc)
    assert r.headers["location"] == "/login?error=account_exists"
    assert (await client.post("/api/v1/auth/login", json={"email": "alice@example.com", "password": "a-brand-new-password"})).status_code == 200


async def test_users_page_shows_the_link(make_client, admin_client, kc):
    client = make_client()
    _alice(kc)
    await _sign_in(client, kc)
    page = (await admin_client.get("/settings/users")).text
    assert "HackSpaceLabs alice" in page and "in the HackSpaceLabs portal" in page
    profile = (await client.get("/settings")).text
    assert "HackSpaceLabs account" in profile and "<strong>alice</strong>" in profile


async def test_unlinking_github_is_allowed_with_a_hackspacelabs_link(make_client, admin_client, kc):
    client = make_client()
    _alice(kc)
    await _sign_in(client, kc)
    _, me = await _me(client)
    async with get_sessionmaker()() as db:
        db.add(OAuthAccount(user_id=uuid.UUID(me["id"]), provider="github", provider_user_id="1001", login="octocat"))
        await db.commit()
    assert (await admin_client.delete(f"/api/v1/users/{me['id']}/github")).status_code == 204


# ------------------------------------------------------------------ settings


def test_half_set_up_is_off_with_one_error(monkeypatch, caplog):
    settings = get_settings()
    monkeypatch.setattr(settings, "hsl_oidc_issuer", ISSUER)
    assert not settings.hsl_enabled and settings.hsl_problem() == "HSL_OIDC_CLIENT_SECRET is not set"
    with caplog.at_level(logging.INFO, logger="slipway"):
        _log_hsl_settings()
    assert [r.levelname for r in caplog.records] == ["ERROR"] and "HackSpaceLabs sign-in is off" in caplog.text
    monkeypatch.setattr(settings, "hsl_oidc_client_secret", "s")
    monkeypatch.setattr(settings, "hsl_oidc_internal_url", "http://kc:8080/path")
    assert not settings.hsl_enabled and "HSL_OIDC_INTERNAL_URL" in settings.hsl_problem()
    monkeypatch.setattr(settings, "hsl_oidc_internal_url", "")
    monkeypatch.setattr(settings, "hsl_portal_internal_url", "")
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="slipway"):
        _log_hsl_settings()
    assert settings.hsl_enabled and "API tokens of HackSpaceLabs-linked owners are not checked" in caplog.text


async def test_internal_url_is_used_for_server_calls_only(monkeypatch):
    seen: list[str] = []
    fake = FakeKeycloak()

    def handle(request):
        seen.append(str(request.url))
        public = str(request.url).replace("http://10.0.0.9:8089", "http://kc.test")
        return fake.handle(request.__class__(request.method, public, headers=request.headers, content=request.content))

    import httpx

    monkeypatch.setattr(hsl, "transport_factory", lambda: httpx.MockTransport(handle))
    client = hsl.Client(issuer=ISSUER, client_id="slipway", client_secret=CLIENT_SECRET,
                        redirect_url="http://testserver/auth/hsl/callback", internal_url="http://10.0.0.9:8089")
    flow = hsl.Flow.new()
    url = await client.authorization_url(flow)
    assert url.startswith(f"{ISSUER}/protocol/openid-connect/auth?")  # the browser uses the public address
    fake.add(KcUser(sub="s1", username="u1", roles=["viewer"]))
    tokens = await client.exchange(urlsplit(fake.authorize(url, "s1")).query.split("code=")[1].split("&")[0], flow)
    assert tokens.claims.sub == "s1" and tokens.claims.roles == ["viewer"]
    assert all(u.startswith("http://10.0.0.9:8089/realms/test/") for u in seen), seen
    assert (await client.end_session_url("t", "http://x/signed-out")).startswith(f"{ISSUER}/")


def test_a_missing_role_claim_is_no_roles():
    # Keycloak leaves hsl_roles out for someone with no role: no roles, not an error (PLAN.md 5.5 step 5).
    assert hsl.Claims.of({"sub": "x"}).roles == []


# ------------------------------------------------------------------ the sign-out button


def test_sign_out_follows_the_returned_redirect(tmp_path):
    from tests.test_review_web import run_js

    result = run_js(tmp_path, """
location.pathname = "/instances";
var button = h("button", { type: "button", "data-api": "POST /api/v1/auth/logout", "data-then": "follow:/login" });
document.body.appendChild(button);
routes["POST /api/v1/auth/logout"] = { status: 200, body: { redirect: "http://kc.test/realms/test/protocol/openid-connect/logout?client_id=slipway" } };
user("click", button);
await settle();
routes["POST /api/v1/auth/logout"] = { status: 204 };
user("click", button);
await settle();
done({ hrefs: hrefs });
""")
    assert result["hrefs"][0] == "http://kc.test/realms/test/protocol/openid-connect/logout?client_id=slipway"
    assert result["hrefs"][1].endswith("/login")
