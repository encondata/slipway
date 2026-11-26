"""GitHub OAuth callback flows with GitHub mocked out."""

from __future__ import annotations

import base64
import json
from urllib.parse import parse_qs, urlparse

import pytest

from slipway.core.config import get_settings
from slipway.web import oauth
from tests.conftest import login, make_user

PROFILE = {"id": 1001, "login": "octocat", "name": "Mona Octocat", "avatar_url": "https://avatars.githubusercontent.com/u/1001"}


class FakeGH:
    profile = PROFILE
    email = ("mona@example.com", True)
    orgs: list[dict] = []

    def __init__(self, token):
        assert token == "gho_test"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def get_user(self):
        return self.profile

    async def get_primary_email(self):
        return self.email

    async def get_orgs(self):
        return self.orgs


@pytest.fixture(autouse=True)
def fake_github(monkeypatch):
    async def exchange(code):
        assert code == "good-code"
        return "gho_test", "read:user,user:email,repo"

    monkeypatch.setattr(oauth, "exchange_code", exchange)
    monkeypatch.setattr(oauth, "GitHubClient", FakeGH)
    FakeGH.profile, FakeGH.email, FakeGH.orgs = PROFILE, ("mona@example.com", True), []


async def _start(client, path="/auth/github/login?next=/hosts") -> str:
    r = await client.get(path)
    assert r.status_code == 302
    location = urlparse(r.headers["location"])
    assert location.netloc == "github.com"
    return parse_qs(location.query)["state"][0]


async def test_first_github_user_becomes_admin(client):
    state = await _start(client)
    r = await client.get(f"/auth/github/callback?code=good-code&state={state}")
    assert r.status_code == 302 and r.headers["location"] == "/hosts"
    me = (await client.get("/api/v1/auth/me")).json()["user"]
    assert me["email"] == "mona@example.com" and me["roles"] == ["admin"] and me["github_login"] == "octocat"


async def test_a_github_sign_in_is_a_local_account_with_its_photo(client):
    state = await _start(client)
    await client.get(f"/auth/github/callback?code=good-code&state={state}")
    page = (await client.get("/")).text
    assert 'detail="Admin · Local account"' in page
    assert f'avatar-url="{PROFILE["avatar_url"]}"' in page


async def test_state_mismatch_rejected(client):
    await _start(client)
    r = await client.get("/auth/github/callback?code=good-code&state=forged")
    assert r.status_code == 302 and r.headers["location"].startswith("/login?error=")
    assert (await client.get("/api/v1/auth/me")).status_code == 401


async def test_unknown_user_blocked_once_slipway_has_users(client):
    await make_user("admin@example.com")
    state = await _start(client)
    r = await client.get(f"/auth/github/callback?code=good-code&state={state}")
    assert r.headers["location"] == "/login?error=not_allowed&login=octocat"


async def test_allowlisted_org_can_sign_up(client, monkeypatch):
    await make_user("admin@example.com")
    monkeypatch.setattr(get_settings(), "github_allowed_orgs", ["acme"])
    FakeGH.orgs = [{"id": 77, "login": "Acme"}]
    state = await _start(client)
    await client.get(f"/auth/github/callback?code=good-code&state={state}")
    me = (await client.get("/api/v1/auth/me")).json()["user"]
    assert me["roles"] == ["viewer"]


async def test_email_collision_does_not_auto_link(client, monkeypatch):
    await make_user("admin@example.com")
    await make_user("mona@example.com", roles=["developer"])
    monkeypatch.setattr(get_settings(), "github_allowed_users", ["octocat"])
    state = await _start(client)
    r = await client.get(f"/auth/github/callback?code=good-code&state={state}")
    assert r.headers["location"] == "/login?error=email_in_use"
    assert (await client.get("/api/v1/auth/me")).status_code == 401


async def test_link_then_sign_in_with_github(client, make_client):
    await make_user("admin@example.com")
    await login(client, "admin@example.com")
    state = await _start(client, "/auth/github/link")
    r = await client.get(f"/auth/github/callback?code=good-code&state={state}")
    assert r.headers["location"] == "/settings?linked=1"
    assert (await client.get("/api/v1/auth/me")).json()["user"]["github_login"] == "octocat"

    fresh = make_client()
    state = await _start(fresh, "/auth/github/login")
    await fresh.get(f"/auth/github/callback?code=good-code&state={state}")
    assert (await fresh.get("/api/v1/auth/me")).json()["user"]["email"] == "admin@example.com"


async def test_open_redirect_blocked(client):
    r = await client.get("/auth/github/login?next=//evil.example")
    body = r.cookies[oauth.STATE_COOKIE].partition(".")[0]
    payload = json.loads(base64.urlsafe_b64decode(body))
    assert payload["n"] == "/"
    assert oauth.safe_next("/\\evil.example") == "/"
    assert oauth.safe_next("/instances?x=1") == "/instances?x=1"
