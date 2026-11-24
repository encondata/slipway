"""GitHub OAuth: sign in with GitHub, and link GitHub to an existing Slipway account.

Rules for an unknown GitHub identity signing in:

* Already linked to a Slipway user -> sign in as that user.
* Otherwise an account is created only if self-signup is enabled, or the GitHub user /
  one of its orgs is allow-listed (``SLIPWAY_GITHUB_ALLOWED_USERS`` / ``_ORGS``, by name or as
  ``id:<number>``), or no allowlist is set and Slipway has no users yet (the first account
  becomes admin).
* While ``SLIPWAY_ADMIN_EMAIL`` is set and Slipway has no users, nobody can create the first account
  here: that seat belongs to the configured admin (``?error=config``).
* GitHub is never auto-linked to an existing account by email: sign in with your password
  and link GitHub from Settings instead. This prevents account takeover via email reuse.

The state cookie is signed with ``SLIPWAY_SECRET_KEY``, and a link request's state carries an
HMAC of the session that started it, so a planted cookie cannot link GitHub to another
account. Linking needs a recent sign-in, like setting a first password, so a stolen session
cookie cannot add a GitHub login that outlives it (an older session gets a 403 page saying to
sign in again). Failures redirect with ``?error=<code>`` (plus ``&login=<github login>`` for some).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
from typing import Any
from urllib.parse import urlencode, urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from slipway.api.deps import DB, OptionalAuth
from slipway.core.config import get_settings
from slipway.models import OAuthAccount, User, UserSession
from slipway.services import audit
from slipway.services.auth import create_session, set_session_cookie, sign_in_again, signed_in_recently
from slipway.services.github import GitHubClient, GitHubError, authorize_url, exchange_code
from slipway.services.users import UserError, create_user, get_user_by_email, user_count

log = logging.getLogger(__name__)
router = APIRouter(prefix="/auth/github", include_in_schema=False)

STATE_COOKIE = "slipway_oauth"
GITHUB_LOGIN = re.compile(r"[A-Za-z0-9-]{1,39}")


def safe_next(value: str | None) -> str:
    """Only allow same-site relative redirects."""
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    # Browsers drop tabs and newlines before parsing, so "/\t/evil.example" is "//evil.example".
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        return "/"
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return "/"
    return value


def _sign(*parts: str) -> str:
    message = "|".join(("slipway-oauth", *parts)).encode()
    return hmac.new(get_settings().secret_key.encode(), message, hashlib.sha256).hexdigest()


def _same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def _link_binding(session: UserSession, nonce: str) -> str:
    return _sign("link", session.token_hash, nonce)


def _start(mode: str, next_url: str, session: UserSession | None = None) -> RedirectResponse:
    settings = get_settings()
    if not settings.github_enabled:
        raise HTTPException(404, "GitHub sign-in is not configured")
    nonce = secrets.token_urlsafe(24)
    state = f"{nonce}.{_link_binding(session, nonce)}" if session else nonce
    body = base64.urlsafe_b64encode(json.dumps({"s": state, "m": mode, "n": safe_next(next_url)}).encode()).decode()
    response = RedirectResponse(authorize_url(state), status_code=302)
    response.set_cookie(
        STATE_COOKIE, f"{body}.{_sign('cookie', body)}", max_age=600, httponly=True,
        secure=settings.secure_cookies, samesite="lax", path="/auth/github",
    )
    return response


def _read_state_cookie(request: Request) -> dict[str, Any]:
    """The state cookie's payload, or {} when it is missing, malformed or not signed by us."""
    body, _, signature = request.cookies.get(STATE_COOKIE, "").partition(".")
    try:
        if not signature or not _same(signature, _sign("cookie", body)):
            return {}
        data = json.loads(base64.urlsafe_b64decode(body))
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _fail(code: str, mode: str = "login", login: str | None = None) -> RedirectResponse:
    params = {"error": code}
    if login and GITHUB_LOGIN.fullmatch(login):
        params["login"] = login
    target = "/settings" if mode == "link" else "/login"
    response = RedirectResponse(f"{target}?{urlencode(params)}", status_code=302)
    response.delete_cookie(STATE_COOKIE, path="/auth/github")
    return response


def _avatar(profile: dict[str, Any]) -> str | None:
    url = profile.get("avatar_url")
    return url if isinstance(url, str) and len(url) <= 500 else None


@router.get("/login")
async def github_login(next: str = "/") -> RedirectResponse:
    return _start("login", next)


@router.get("/link")
async def github_link(request: Request, db: DB, ctx: OptionalAuth) -> Response:
    if ctx is None or ctx.session is None:
        return RedirectResponse("/login?next=/settings", status_code=302)
    # Adding (or re-authorizing) a GitHub login is a credential change: it needs a recent sign-in.
    if (ctx.user.password_hash or ctx.user.github or ctx.user.hackspacelabs) and not signed_in_recently(ctx.session):
        if ctx.session.auth_source == "oidc" and get_settings().hsl_enabled:
            # The clock is Keycloak's: confirm with a fresh HackSpaceLabs sign-in, then come straight back here.
            return RedirectResponse("/auth/hsl/login?reauth=1&next=%2Fauth%2Fgithub%2Flink", status_code=302)
        from slipway.web.pages import render  # pages imports this module, so not at the top

        action = "re-authorize GitHub" if ctx.user.github else "link GitHub"
        return await render(
            request, db, "error.html", ctx, status_code=403, code=403, heading="Sign in again to continue",
            message=f"{sign_in_again(action, ctx.session)}.",
        )
    return _start("link", "/settings", ctx.session)


def _allowlisted(entries: list[str], identity: dict[str, Any]) -> bool:
    """Entries are lowercased names (which GitHub lets people change) or ``id:<number>``."""
    ids = {e for e in entries if e.startswith("id:")}
    names = set(entries) - ids
    return f"id:{identity.get('id')}" in ids or str(identity.get("login", "")).lower() in names


async def _signup_allowed(db: DB, gh: GitHubClient, profile: dict[str, Any]) -> bool:
    settings = get_settings()
    users, orgs = settings.github_allowed_users, settings.github_allowed_orgs
    if settings.allow_signup or _allowlisted(users, profile):
        return True
    if orgs:
        try:
            memberships = await gh.get_orgs()
        except GitHubError as exc:
            if exc.transient:  # a hiccup: the callback reports a retryable failure
                raise
            return False
        return any(_allowlisted(orgs, org) for org in memberships)
    # Only with no allowlist configured, and no SLIPWAY_ADMIN_EMAIL reserving it, may anyone claim the
    # first (admin) account.
    return not users and not settings.admin_email and await user_count(db) == 0


@router.get("/callback")
async def github_callback(
    request: Request, db: DB, ctx: OptionalAuth, code: str = "", state: str = "", error: str = ""
) -> RedirectResponse:
    cookie = _read_state_cookie(request)
    mode = "link" if cookie.get("m") == "link" else "login"
    if error:
        if error != "access_denied":
            log.warning("GitHub OAuth returned error %r", error[:100])
        return _fail("cancelled" if error == "access_denied" else "failed", mode)
    expected = cookie.get("s")
    if not code or not isinstance(expected, str) or not state.isascii() or not _same(state, expected):
        return _fail("state", mode)

    # The mode comes from the verified state: only a state minted for this session can link.
    nonce, _, binding = state.partition(".")
    link_user: User | None = None
    if binding:
        if ctx is None or ctx.session is None:
            return _fail("session_expired")
        if not _same(binding, _link_binding(ctx.session, nonce)):
            return _fail("state", "link")
        link_user = ctx.user
    mode = "link" if link_user is not None else "login"

    try:
        token, scopes = await exchange_code(code)
        async with GitHubClient(token) as gh:
            profile = await gh.get_user()
            gh_id, login = str(profile["id"]), str(profile["login"])
            account = await db.scalar(
                select(OAuthAccount)
                .options(joinedload(OAuthAccount.user).selectinload(User.oauth_accounts))
                .where(OAuthAccount.provider == "github", OAuthAccount.provider_user_id == gh_id)
            )

            if link_user is not None:
                user = link_user
                if account is not None and account.user_id != user.id:
                    return _fail("already_linked", mode, login)
                if account is None and user.github is not None:
                    return _fail("unlink_first", mode)
                if account is None:
                    account = OAuthAccount(provider="github", provider_user_id=gh_id, login=login[:100])
                    user.oauth_accounts.append(account)
                audit.record(db, "auth.github_linked", actor=user, target=user, summary=f"Linked @{login}", request=request)

            elif account is not None:
                user = account.user
                if not user.is_active:
                    return _fail("deactivated")
                if user.hackspacelabs is not None:
                    # D16: tied to HackSpaceLabs, so it signs in only there. The GitHub link stays for repositories.
                    audit.record(db, "auth.login_failed", actor=user, target=user, request=request,
                                 summary=f"GitHub sign-in as @{login} refused: this account signs in with HackSpaceLabs")
                    await db.commit()
                    return _fail("hsl_only")

            else:
                admin_email = get_settings().admin_email
                if admin_email and await user_count(db) == 0:
                    log.error(
                        "GitHub sign-up for @%s refused: SLIPWAY_ADMIN_EMAIL reserves the first account, but that "
                        "admin was not created (see the startup log). Fix SLIPWAY_ADMIN_PASSWORD and restart, "
                        "or run `slipway create-admin`.",
                        login,
                    )
                    return _fail("config")
                if not await _signup_allowed(db, gh, profile):
                    return _fail("not_allowed", login=login)
                email, verified = await gh.get_primary_email()
                # An address too long for the column is refused, never cut into a different one.
                if not email or not verified or len(email) > 320:
                    return _fail("no_verified_email")
                if await get_user_by_email(db, email):
                    return _fail("email_in_use")
                try:
                    user = await create_user(
                        db, email=email, full_name=(profile.get("name") or login)[:200], avatar_url=_avatar(profile),
                        allow_first_admin=not admin_email,
                    )
                except UserError as exc:
                    log.error("GitHub sign-up for @%s failed: %s", login, exc)
                    return _fail("config")
                account = OAuthAccount(provider="github", provider_user_id=gh_id, login=login[:100])
                user.oauth_accounts.append(account)
                audit.record(db, "user.register", actor=user, target=user, summary=f"Signed up with GitHub @{login}", request=request)
    except GitHubError as exc:
        log.warning("GitHub OAuth failed: %s", exc)
        return _fail("failed", mode)

    account.login = login[:100]
    account.access_token = token
    account.scopes = scopes[:500]
    if avatar := _avatar(profile):
        user.avatar_url = avatar

    if mode == "link":
        await db.commit()
        response = RedirectResponse("/settings?linked=1", status_code=302)
    else:
        raw, _ = await create_session(db, user, request)
        audit.record(db, "auth.login", actor=user, target=user, summary=f"Signed in with GitHub @{login}", request=request)
        await db.commit()
        response = RedirectResponse(safe_next(cookie.get("n")), status_code=302)
        set_session_cookie(response, raw, request)
    response.delete_cookie(STATE_COOKIE, path="/auth/github")
    return response
