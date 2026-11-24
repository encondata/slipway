"""Sign in with HackSpaceLabs (the HackSpaceLabs Keycloak, OpenID Connect), and linking it to an existing account.

The contract is PLAN.md section 5 in the HSL Suite workspace. ``GET /auth/hsl/login`` starts a sign-in,
``/auth/hsl/callback`` finishes it, ``/auth/hsl/link`` links the signed-in account (from Settings, Profile), and
``/auth/hsl/switch`` signs out of HackSpaceLabs to use a different account.

Who a HackSpaceLabs sign-in becomes (D9), in order:

* the account already linked to that Keycloak user (``oauth_accounts``, provider ``hackspacelabs``, by ``sub``);
* in link mode, the signed-in account that asked to link;
* the account whose email Keycloak marks verified, if it has no HackSpaceLabs link yet;
* otherwise a new account, with the claim's email, or ``<username>@hsl.invalid`` when there is none. If that
  address already belongs to an account the sign-in is refused (``account_exists``): the person signs in the
  old way and links from Settings. No second address is ever made up.

Nobody without a Slipway role in Keycloak gets in, and no account is made for them (``no_access``). Their roles
become exactly the claim's roles that exist in Slipway, on every sign-in and recheck. An account with a link
signs in only with HackSpaceLabs (D16); linking the last admin who can sign in without it is refused.

The flow's state, nonce, PKCE verifier and ``next`` travel in a cookie encrypted with SLIPWAY_ENCRYPTION_KEY,
named after the state so several tabs can sign in at once, and valid for 10 minutes. A link request's flow
carries an HMAC of the session that started it, like the GitHub flow, so a planted cookie cannot link to
another account.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode, urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from slipway.api.deps import DB, OptionalAuth
from slipway.core.config import get_settings
from slipway.core.crypto import DecryptionError, decrypt, encrypt
from slipway.db.base import utcnow
from slipway.models import OAuthAccount, User, UserSession
from slipway.models.user import HACKSPACELABS
from slipway.services import audit, hsl
from slipway.services.auth import (
    RECENT_SIGN_IN_MAX_AGE,
    cookie_secure,
    create_session,
    set_session_cookie,
    sign_in_again,
    signed_in_recently,
)
from slipway.services.users import (
    UserError,
    apply_claimed_roles,
    create_user,
    ensure_not_last_local_admin,
    get_user_by_email,
)
from slipway.web.oauth import safe_next

log = logging.getLogger(__name__)
router = APIRouter(prefix="/auth/hsl", include_in_schema=False)

FLOW_COOKIE = "slipway_hsl_"  # + 8 hex of the state's hash
FLOW_PATH = "/auth/hsl"
FLOW_SECONDS = 600
# Set before the sign-in page sends someone to HackSpaceLabs on its own; while it lasts, it doesn't do that again
# (a session cookie that doesn't stick would otherwise bounce between Slipway and Keycloak forever).
TRY_COOKIE = "slipway_sso_try"
TRY_SECONDS = 30
NO_ADMIN = "no_admin"


def flow_cookie(state: str) -> str:
    return FLOW_COOKIE + hashlib.sha256(state.encode()).hexdigest()[:8]


def _sign(*parts: str) -> str:
    message = "|".join(("slipway-hsl", *parts)).encode()
    return hmac.new(get_settings().secret_key.encode(), message, hashlib.sha256).hexdigest()


def _link_binding(session: UserSession, state: str) -> str:
    return _sign("link", session.token_hash, state)


def _redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def _client() -> hsl.Client:
    client = hsl.client()
    if client is None:
        raise HTTPException(404, "HackSpaceLabs sign-in is not configured")
    return client


def _fail(code: str, mode: str = "login") -> RedirectResponse:
    target = "/settings" if mode == "link" else "/login"
    return _redirect(f"{target}?{urlencode({'error': code})}")


async def _start(
    request: Request, mode: str, next_url: str, *, session: UserSession | None = None, reauth: bool = False
) -> Response:
    client = _client()
    flow = hsl.Flow.new()
    # Link mode shows the Keycloak form even with a Keycloak session in the browser, so the person sees which
    # account they link. Re-authentication also makes Keycloak report a fresh auth_time (PLAN.md WP4).
    prompt = "login" if mode == "link" or reauth else ""
    try:
        target = await client.authorization_url(flow, prompt=prompt, max_age=0 if reauth else None)
    except hsl.HslError as exc:
        log.warning("HackSpaceLabs sign-in unavailable: %s", exc)
        return _fail("sso_unavailable", mode)
    payload = {
        "p": "slipway-hsl-flow", "s": flow.state, "n": flow.nonce, "v": flow.verifier, "m": mode,
        "next": next_url, "r": reauth, "exp": int(time.time()) + FLOW_SECONDS,
        "b": _link_binding(session, flow.state) if session is not None else "",
    }
    response = _redirect(target)
    response.set_cookie(
        flow_cookie(flow.state), encrypt(json.dumps(payload)), max_age=FLOW_SECONDS, httponly=True,
        secure=cookie_secure(request), samesite="lax", path=FLOW_PATH,
    )
    return response


def _wrong_host(request: Request) -> Response | None:
    """PLAN.md 5.4 step 1: the flow cookie must be set on the host Keycloak sends the browser back to. Host names
    only: cookies ignore ports."""
    public = urlsplit(get_settings().base_url)
    if request.url.hostname != public.hostname:
        query = f"?{request.url.query}" if request.url.query else ""
        return _redirect(f"{get_settings().base_url}{request.url.path}{query}")
    return None


@router.get("/login")
async def hsl_login(request: Request, next: str = "/", reauth: str = "") -> Response:
    _client()
    if (moved := _wrong_host(request)) is not None:
        return moved
    return await _start(request, "login", safe_next(next), reauth=bool(reauth))


@router.get("/link")
async def hsl_link(request: Request, db: DB, ctx: OptionalAuth) -> Response:
    _client()
    if (moved := _wrong_host(request)) is not None:
        return moved
    if ctx is None or ctx.session is None:
        return RedirectResponse("/login?next=/settings", status_code=302)
    if ctx.user.hackspacelabs is not None:
        return RedirectResponse("/settings", status_code=302)
    # Linking changes how the account signs in, so like linking GitHub it needs a recent sign-in.
    if not signed_in_recently(ctx.session):
        from slipway.web.pages import render  # pages imports this module, so not at the top

        return await render(
            request, db, "error.html", ctx, status_code=403, code=403, heading="Sign in again to continue",
            message=f"{sign_in_again('link your HackSpaceLabs account', ctx.session)}.",
        )
    return await _start(request, "link", "/settings", session=ctx.session)


@router.get("/switch")
async def hsl_switch() -> Response:
    """"Use a different account" on the no-access page: Keycloak's sign-out (it asks to confirm, as there is no ID
    token to hint with), back to /signed-out, whose button signs in again."""
    client = _client()
    settings = get_settings()
    try:
        target = await client.end_session_url("", f"{settings.base_url}/signed-out")
    except hsl.HslError as exc:
        log.warning("HackSpaceLabs sign-out unavailable: %s", exc)
        return _fail("sso_unavailable")
    return _redirect(target)


def _take_flow(request: Request, state: str) -> dict[str, Any] | None:
    """The flow this browser started for ``state``: None when the cookie is missing, expired or not ours."""
    raw = request.cookies.get(flow_cookie(state)) if state else None
    if not raw:
        return None
    try:
        data = json.loads(decrypt(raw))
    except (DecryptionError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("p") != "slipway-hsl-flow" or not isinstance(data.get("exp"), int):
        return None
    if data["exp"] < time.time() or not isinstance(data.get("s"), str) or not hmac.compare_digest(data["s"], state):
        return None
    return data


async def _refuse(db: DB, request: Request, username: str, why: str, code: str, mode: str = "login") -> Response:
    """Turn a sign-in away: nothing it changed is kept, and the refusal is audited."""
    await db.rollback()
    log.warning("HackSpaceLabs sign-in refused for %r: %s", username[:100], why)
    audit.record(
        db, "auth.login_refused", summary=f"HackSpaceLabs sign-in refused for {username[:100] or 'unknown'}: {why}",
        details={"method": "hackspacelabs", "reason": why, "username": username[:100]}, request=request,
    )
    await db.commit()
    return _fail(code, mode)


@router.get("/callback")
async def hsl_callback(
    request: Request, db: DB, ctx: OptionalAuth, code: str = "", state: str = "", error: str = ""
) -> Response:
    client = _client()
    flow = _take_flow(request, state)
    response = await _finish(request, db, ctx, client, flow, code, error)
    if state:
        response.delete_cookie(flow_cookie(state), path=FLOW_PATH, secure=cookie_secure(request), httponly=True, samesite="lax")
    return response


async def _finish(
    request: Request, db: DB, ctx: OptionalAuth, client: hsl.Client, flow: dict[str, Any] | None, code: str, error: str
) -> Response:
    if flow is None:
        # Another tab may have finished signing in already.
        return _redirect("/") if ctx is not None else _fail("sso_expired")
    mode = "link" if flow.get("m") == "link" else "login"
    if error:
        return _fail("sso_cancelled" if error == "access_denied" else "sso_failed", mode)

    link_user: User | None = None
    if mode == "link":
        # Only a flow minted for this very session can link, so a planted cookie cannot link someone else.
        if ctx is None or ctx.session is None or not hmac.compare_digest(
            str(flow.get("b", "")), _link_binding(ctx.session, str(flow["s"]))
        ):
            return _fail("sso_expired", mode)
        link_user = ctx.user

    try:
        tokens = await client.exchange(code, hsl.Flow(state=str(flow["s"]), nonce=str(flow["n"]), verifier=str(flow["v"])))
    except hsl.Unavailable as exc:
        log.warning("HackSpaceLabs sign-in failed: %s", exc)
        return _fail("sso_unavailable", mode)
    except hsl.HslError as exc:
        log.warning("HackSpaceLabs sign-in failed: %s", exc)
        return _fail("sso_failed", mode)
    claims = tokens.claims
    username = claims.preferred_username or claims.sub
    if len(claims.sub) > 64:  # oauth_accounts.provider_user_id; Keycloak's ids are 36-character UUIDs
        return await _refuse(db, request, username, "the Keycloak user id is too long", "sso_failed", mode)

    if flow.get("r"):
        signed_in = datetime.fromtimestamp(claims.auth_time, UTC) if claims.auth_time else None
        if signed_in is None or utcnow() - signed_in > RECENT_SIGN_IN_MAX_AGE:
            return await _refuse(db, request, username, "no fresh sign-in at HackSpaceLabs", "sso_reauth")

    roles = await hsl.known_roles(db, claims.roles)
    if not roles:
        return await _refuse(db, request, username, "no Slipway role", "no_access", mode)

    account = await db.scalar(
        select(OAuthAccount)
        .options(joinedload(OAuthAccount.user).selectinload(User.oauth_accounts))
        .where(OAuthAccount.provider == HACKSPACELABS, OAuthAccount.provider_user_id == claims.sub)
    )
    user: User | None = None
    if link_user is not None:
        if account is not None and account.user_id != link_user.id:
            return await _refuse(db, request, username, "already linked to another Slipway account", "sso_linked_elsewhere", mode)
        if account is None and link_user.hackspacelabs is not None:
            return await _refuse(db, request, username, "this account is linked to a different one", "sso_already_linked", mode)
        user = link_user
        if account is None:
            try:
                await ensure_not_last_local_admin(db, user)
            except UserError:
                return await _refuse(db, request, username, "last admin able to sign in without HackSpaceLabs", "sso_last_admin", mode)
            account = _link(user, claims)
            audit.record(db, "auth.hackspacelabs_linked", actor=user, target=user,
                         summary=f"Linked HackSpaceLabs account {username[:100]}", request=request)
    elif account is not None:
        user = account.user
    else:
        if claims.email_verified and claims.email:
            existing = await get_user_by_email(db, claims.email)
            if existing is not None and existing.hackspacelabs is None:
                try:
                    await ensure_not_last_local_admin(db, existing)
                except UserError:
                    return await _refuse(db, request, username, "last admin able to sign in without HackSpaceLabs", "sso_last_admin")
                user = existing
                account = _link(user, claims)
                audit.record(db, "auth.hackspacelabs_linked", actor=user, target=user,
                             summary=f"Linked HackSpaceLabs account {username[:100]} by its verified email", request=request)
        if user is None:
            address = claims.email or (f"{claims.preferred_username.lower()}@hsl.invalid" if claims.preferred_username else "")
            if not address or len(address) > 320:
                return await _refuse(db, request, username, "no usable email address", "sso_failed")
            if await get_user_by_email(db, address) is not None:
                return await _refuse(db, request, username, f"{address} already belongs to an account", "account_exists")
            try:
                user = await create_user(
                    db, email=address, full_name=(claims.name or claims.preferred_username)[:200],
                    role_names=[r.name for r in roles], allow_first_admin=False,
                )
            except UserError as exc:
                # The first account (Slipway has none yet) is made with a password: `slipway create-admin`.
                return await _refuse(db, request, username, str(exc), NO_ADMIN)
            account = _link(user, claims)
            audit.record(db, "user.register", actor=user, target=user,
                         summary=f"Signed up with HackSpaceLabs {username[:100]}", request=request)

    if not user.is_active:
        return await _refuse(db, request, username, "account deactivated in Slipway", "no_access", mode)
    try:
        await apply_claimed_roles(db, user, roles)
    except UserError:
        return await _refuse(db, request, username, "it would remove the last active admin", "no_access", mode)
    if claims.name:
        user.full_name = claims.name[:200]
    if claims.preferred_username:
        account.login = claims.preferred_username[:100]

    if mode == "link" and ctx is not None and ctx.session is not None:
        # From now on this account is a HackSpaceLabs one: its old session goes, a rechecked one replaces it.
        await db.delete(ctx.session)
    raw, _ = await create_session(db, user, request, idp=tokens)
    method = "Signed in with HackSpaceLabs" + (" (linked)" if mode == "link" else "")
    audit.record(db, "auth.login", actor=user, target=user, summary=f"{method} as {username[:100]}",
                 details={"method": "hackspacelabs"}, request=request)
    await db.commit()
    target = "/settings?linked=hackspacelabs" if mode == "link" else safe_next(str(flow.get("next") or "/"))
    response = _redirect(target)
    set_session_cookie(response, raw, request, max_age=int(tokens.session_lifetime.total_seconds()))
    return response


def _link(user: User, claims: hsl.Claims) -> OAuthAccount:
    account = OAuthAccount(provider=HACKSPACELABS, provider_user_id=claims.sub[:64],
                           login=(claims.preferred_username or claims.sub)[:100])
    user.oauth_accounts.append(account)
    return account
