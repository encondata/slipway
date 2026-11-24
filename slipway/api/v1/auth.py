"""Email/password login, logout, self-registration and the current user's profile."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from slipway.api.deps import DB, Auth
from slipway.core import ratelimit
from slipway.core.config import get_settings
from slipway.core.ratelimit import (
    LOGIN_PAIR_V6_PREFIX,
    ip_bucket,
    login_email_limiter,
    login_ip_limiter,
    login_pair_limiter,
    password_change_limiter,
    password_change_user_limiter,
    register_limiter,
)
from slipway.core.security import hash_password_async, verify_password_async
from slipway.models import UserSession
from slipway.schemas import LoginIn, PasswordChange, ProfileUpdate, RegisterIn, SessionOut, UserOut
from slipway.services import audit, hsl
from slipway.services.audit import client_ip
from slipway.services.auth import (
    OIDC,
    AuthContext,
    authenticate_password,
    clear_session_cookie,
    create_session,
    revoke_user_sessions,
    set_session_cookie,
    sign_in_again,
    signed_in_recently,
)
from slipway.services.users import FIRST_ADMIN_RESERVED, UserError, check_password_strength, create_user, user_count

router = APIRouter(prefix="/auth", tags=["auth"])
log = logging.getLogger(__name__)

TOO_MANY = "Too many attempts; try again in a few minutes"


def _require_session(ctx: AuthContext) -> UserSession:
    """Credential changes need a browser session, never an API token."""
    if ctx.via != "session" or ctx.session is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This can only be done from the web UI")
    return ctx.session


@router.post("/login")
async def login(body: LoginIn, request: Request, response: Response, db: DB) -> SessionOut:
    email = body.email.strip().lower()
    addr = client_ip(request)
    ip = ip_bucket(addr)
    pair = f"{ip_bucket(addr, LOGIN_PAIR_V6_PREFIX)}|{email}"
    # Count the attempt before any await, so a burst of parallel guesses is limited too.
    if not ratelimit.acquire((login_ip_limiter, ip), (login_pair_limiter, pair), (login_email_limiter, email)):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, TOO_MANY)
    user = await authenticate_password(db, email, body.password)
    if user is not None and user.hackspacelabs is not None:
        # D16: an account tied to HackSpaceLabs signs in only there, or disabling someone in Keycloak would leave
        # their password working. Counted like a wrong password; said only now that the password was right.
        audit.record(db, "auth.login_failed", actor=user, target=user,
                     summary="Password sign-in refused: this account signs in with HackSpaceLabs", request=request)
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "This account signs in with HackSpaceLabs")
    if user is None:
        audit.record(db, "auth.login_failed", summary=f"Failed login for {body.email[:100]}", request=request)
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    # Only failures count against the limits.
    login_pair_limiter.reset(pair)
    login_ip_limiter.undo(ip)
    login_email_limiter.undo(email)
    raw, session = await create_session(db, user, request)
    audit.record(db, "auth.login", actor=user, target=user, summary="Signed in with password", request=request)
    await db.commit()
    set_session_cookie(response, raw, request)
    return SessionOut(user=UserOut.of(user), csrf_token=session.csrf_token)


@router.post(
    "/logout", status_code=204,
    responses={200: {"description": "A HackSpaceLabs session: also sign out at HackSpaceLabs by going to `redirect`"}},
)
async def logout(ctx: Auth, db: DB) -> Response:
    """Ends this session. For a HackSpaceLabs session the answer is 200 with ``{"redirect": url}``, Keycloak's
    sign-out address (which signs the person out of every HackSpaceLabs app); otherwise 204, as always."""
    redirect = None
    if ctx.session is not None:
        if ctx.session.auth_source == OIDC:
            redirect = await _end_session_url(ctx.session.idp_tokens or {})
        await db.delete(ctx.session)
        await db.commit()
    response: Response = JSONResponse({"redirect": redirect}) if redirect else Response(status_code=204)
    clear_session_cookie(response)
    return response


async def _end_session_url(stored: dict[str, str]) -> str:
    """Keycloak's sign-out address for this session, or the signed-out page when it can't be built."""
    client = hsl.client()
    if client is None:
        return "/signed-out"
    try:
        return await client.end_session_url(stored.get("id_token", ""), f"{get_settings().base_url}/signed-out")
    except hsl.HslError as exc:
        log.warning("Couldn't build the HackSpaceLabs sign-out address: %s", exc)
        return "/signed-out"


@router.post("/register", status_code=201)
async def register(body: RegisterIn, request: Request, response: Response, db: DB) -> SessionOut:
    settings = get_settings()
    if not settings.allow_signup:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Self-registration is disabled; ask an admin for an account")
    if not register_limiter.acquire(ip_bucket(client_ip(request))):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, TOO_MANY)
    if settings.admin_email:
        # SLIPWAY_ADMIN_EMAIL reserves the first (admin) account for the configured admin.
        if await user_count(db) == 0:
            raise HTTPException(status.HTTP_403_FORBIDDEN, FIRST_ADMIN_RESERVED)
        await db.commit()  # hand the pooled connection back before create_user queues for argon2
    try:
        user = await create_user(
            db, email=body.email, password=body.password, full_name=body.full_name,
            allow_first_admin=not settings.admin_email,
        )
    except UserError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    raw, session = await create_session(db, user, request)
    audit.record(db, "user.register", actor=user, target=user, summary=f"Registered {user.email}", request=request)
    await db.commit()
    set_session_cookie(response, raw, request)
    return SessionOut(user=UserOut.of(user), csrf_token=session.csrf_token)


@router.get("/me")
async def me(ctx: Auth) -> SessionOut:
    return SessionOut(user=UserOut.of(ctx.user), csrf_token=ctx.csrf_token)


@router.patch("/me")
async def update_me(body: ProfileUpdate, ctx: Auth, db: DB) -> UserOut:
    ctx.user.full_name = body.full_name.strip()
    await db.commit()
    return UserOut.of(ctx.user)


@router.post("/me/password", status_code=204)
async def change_password(body: PasswordChange, ctx: Auth, request: Request, db: DB) -> None:
    session = _require_session(ctx)
    user = ctx.user
    try:
        check_password_strength(body.new_password)
    except UserError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    # Nothing is pending yet: hand the pooled connection back before queuing for argon2.
    await db.commit()
    if user.password_hash:
        attempt = ((password_change_limiter, f"{user.id}:{session.id}"), (password_change_user_limiter, str(user.id)))
        if not ratelimit.acquire(*attempt):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, TOO_MANY)
        if not await verify_password_async(body.current_password or "", user.password_hash):
            audit.record(
                db, "auth.password_change_failed", actor=user, target=user, summary="Wrong current password", request=request
            )
            await db.commit()
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
        for limiter, key in attempt:
            limiter.reset(key)
    elif not signed_in_recently(session):
        raise HTTPException(status.HTTP_403_FORBIDDEN, sign_in_again("set your password", session))
    user.password_hash = await hash_password_async(body.new_password)
    await revoke_user_sessions(db, user, keep=session)
    audit.record(db, "auth.password_changed", actor=user, target=user, request=request)
    await db.commit()


@router.delete("/me/github", status_code=204)
async def unlink_github(ctx: Auth, request: Request, db: DB) -> None:
    session = _require_session(ctx)
    account = ctx.user.github
    if account is None:
        return
    # With a HackSpaceLabs link the account still has a way in without GitHub.
    if ctx.user.password_hash is None and ctx.user.hackspacelabs is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Set a password before unlinking GitHub, or you'll be locked out")
    # A stolen session must not swap the owner's GitHub link for the thief's (unlink, then link another).
    if not signed_in_recently(session):
        raise HTTPException(status.HTTP_403_FORBIDDEN, sign_in_again("unlink GitHub", session))
    ctx.user.oauth_accounts.remove(account)
    audit.record(db, "auth.github_unlinked", actor=ctx.user, target=ctx.user, summary=f"Unlinked @{account.login}", request=request)
    await db.commit()
