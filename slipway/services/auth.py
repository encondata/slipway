"""Login, browser sessions and API-token authentication."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from urllib.parse import urlsplit

from fastapi import Request, Response
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload
from sqlalchemy.orm.exc import StaleDataError

from slipway.core.config import get_settings
from slipway.core.security import (
    API_TOKEN_PREFIX,
    hash_password_async,
    hash_token,
    new_token,
    password_needs_rehash,
    verify_password_async,
)
from slipway.db.base import utcnow
from slipway.models import ApiToken, OAuthAccount, User, UserSession
from slipway.models.user import GITHUB, HACKSPACELABS
from slipway.services import audit, hsl
from slipway.services.audit import client_ip
from slipway.services.users import UserError, apply_claimed_roles

log = logging.getLogger(__name__)

SESSION_COOKIE = "slipway_session"
# UserSession.auth_source of a HackSpaceLabs sign-in; everything else is "local".
OIDC = "oidc"
CSRF_HEADER = "X-CSRF-Token"
_TOUCH_INTERVAL = timedelta(minutes=5)
# Adding or removing a sign-in method (a first password, a GitHub link) needs a sign-in this recent, so a
# stolen session cookie cannot plant a credential that outlives it.
RECENT_SIGN_IN_MAX_AGE = timedelta(minutes=15)


def signed_in_recently(session: UserSession) -> bool:
    """Whether the person behind ``session`` typed their password in the last 15 minutes. A HackSpaceLabs session
    takes the time from Keycloak (``auth_time``): its sign-in may have been silent, from an older Keycloak session."""
    if session.auth_source == OIDC:
        return session.auth_time is not None and utcnow() - session.auth_time <= RECENT_SIGN_IN_MAX_AGE
    return utcnow() - session.created_at <= RECENT_SIGN_IN_MAX_AGE


def sign_in_again(action: str, session: UserSession | None = None) -> str:
    """The refusal shown when ``action`` needs a more recent sign-in."""
    minutes = RECENT_SIGN_IN_MAX_AGE.seconds // 60
    if session is not None and session.auth_source == OIDC:
        return f"Confirm it's you with HackSpaceLabs (Settings, Profile), then {action} within {minutes} minutes"
    return f"Sign out and sign in again, then {action} within {minutes} minutes"


@dataclass
class AuthContext:
    user: User
    via: Literal["session", "token"]
    session: UserSession | None = None
    token: ApiToken | None = None

    def can(self, permission: str) -> bool:
        return self.user.can(permission)

    @property
    def csrf_token(self) -> str:
        return self.session.csrf_token if self.session else ""


async def authenticate_password(db: AsyncSession, email: str, password: str) -> User | None:
    """Check an email/password pair. Commits the (read-only) transaction before hashing."""
    user = await db.scalar(select(User).where(User.email == email.strip().lower()))
    # Hand the pooled connection back while queuing for argon2, so a login burst cannot
    # starve every other request (and the background tasks) of database connections.
    await db.commit()
    ok = await verify_password_async(password, user.password_hash if user else None)
    if not (user and ok and user.is_active):
        return None
    if user.password_hash and password_needs_rehash(user.password_hash):
        user.password_hash = await hash_password_async(password)
    return user


async def create_session(
    db: AsyncSession, user: User, request: Request | None, *, idp: hsl.Tokens | None = None
) -> tuple[str, UserSession]:
    """A browser session. With ``idp`` (a HackSpaceLabs sign-in) it lasts as long as the Keycloak session and keeps
    the tokens to recheck it with; otherwise SLIPWAY_SESSION_TTL_HOURS."""
    raw = new_token()
    now = utcnow()
    session = UserSession(
        user_id=user.id,
        token_hash=hash_token(raw),
        csrf_token=new_token(24),
        expires_at=now + (idp.session_lifetime if idp else timedelta(hours=get_settings().session_ttl_hours)),
        last_seen_at=now,
        ip=client_ip(request),
        user_agent=(request.headers.get("user-agent", "")[:300] if request else None),
    )
    if idp is not None:
        session.auth_source = OIDC
        session.idp_sid = idp.claims.sid[:255] or None
        session.idp_tokens = hsl.sealed(idp)
        session.idp_checked_at = now
        session.auth_time = _timestamp(idp.claims.auth_time)
    db.add(session)
    user.last_login_at = now
    await db.flush()
    return raw, session


def cookie_secure(request: Request) -> bool:
    """Mark the session cookie Secure for requests that arrived over https, or that are addressed to an https
    SLIPWAY_BASE_URL host (through a proxy whose forwarded scheme isn't trusted). A browser drops a Secure cookie
    sent over plain http, so opening Slipway directly (http://<server>:8000) with an https base URL must get a
    plain one, or every sign-in silently fails."""
    if request.url.scheme == "https":
        return True
    settings = get_settings()
    return settings.secure_cookies and request.url.hostname == urlsplit(settings.base_url).hostname


def _timestamp(value: int | None) -> datetime | None:
    try:
        return datetime.fromtimestamp(value, UTC) if value is not None else None
    except (OverflowError, OSError, ValueError):
        return None


def set_session_cookie(response: Response, raw_token: str, request: Request, *, max_age: int | None = None) -> None:
    """``max_age`` in seconds; a HackSpaceLabs session passes its Keycloak session's length (PLAN.md 5.6)."""
    settings = get_settings()
    response.set_cookie(
        SESSION_COOKIE,
        raw_token,
        max_age=max_age if max_age is not None else settings.session_ttl_hours * 3600,
        httponly=True,
        secure=cookie_secure(request),
        samesite="lax",
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


async def session_from_cookie(db: AsyncSession, raw: str) -> UserSession | None:
    session = await db.scalar(select(UserSession).where(UserSession.token_hash == hash_token(raw)))
    if session is None:
        return None
    now = utcnow()
    if session.expires_at <= now or not session.user.is_active:
        await db.delete(session)
        await db.commit()
        return None
    if now - session.last_seen_at > _TOUCH_INTERVAL:
        session.last_seen_at = now
        await db.commit()
    return session


async def token_from_bearer(db: AsyncSession, raw: str) -> ApiToken | None:
    if not raw.startswith(API_TOKEN_PREFIX):
        return None
    token = await db.scalar(
        select(ApiToken).options(joinedload(ApiToken.user).selectinload(User.oauth_accounts))
        .where(ApiToken.token_hash == hash_token(raw))
    )
    if token is None or not token.user.is_active:
        return None
    now = utcnow()
    if token.expires_at and token.expires_at <= now:
        return None
    if token.last_used_at is None or now - token.last_used_at > _TOUCH_INTERVAL:
        token.last_used_at = now
        await db.commit()
    # A token of someone who signs in with HackSpaceLabs stops working once the portal says they were disabled or
    # lost their Slipway role (PLAN.md D18). No Keycloak session is involved, so this is the only check.
    link = token.user.hackspacelabs
    if link is not None and hsl.owner_check_configured():
        await db.commit()  # hand the pooled connection back while the portal answers
        if not await hsl.owner_allowed(db, link.provider_user_id):
            return None
    return token


# Sessions being rechecked in this process right now; another request for one of them carries on without waiting.
_rechecking: set[uuid.UUID] = set()


async def recheck_hsl_session(db: AsyncSession, session: UserSession) -> UserSession | None:
    """PLAN.md 5.7: confirm a HackSpaceLabs session with Keycloak when it is due, and apply the answer.

    Returns the session, or None once it has been ended (deleted here). Keycloak's definite no (signed out,
    disabled, no Slipway role left, a token that fails verification) ends it; Keycloak being unreachable does not.
    """
    user = session.user
    client = hsl.client()
    if client is None:
        # Sign-in was turned off (or misconfigured): nothing can recheck this session any more.
        return await _end_hsl_session(db, session, "HackSpaceLabs sign-in is turned off")
    now = utcnow()
    every = timedelta(seconds=get_settings().hsl_oidc_recheck_seconds)
    if session.idp_checked_at is not None and now - session.idp_checked_at < every:
        return session
    if session.id in _rechecking:
        return session
    _rechecking.add(session.id)
    try:
        stored = session.idp_tokens or {}
        refresh, subject = stored.get("refresh_token"), stored.get("sub")
        if not refresh or not subject:
            return await _end_hsl_session(db, session, "its stored tokens can't be read")
        await db.commit()  # hand the pooled connection back while Keycloak answers
        try:
            tokens = await client.refresh(refresh, subject)
        except (hsl.Refused, hsl.InvalidToken) as exc:
            return await _end_hsl_session(db, session, str(exc))
        except hsl.Unavailable as exc:
            log.warning("Couldn't recheck the HackSpaceLabs session of %s; keeping it (%s)", user.email, exc)
            session.idp_checked_at = utcnow()
            return await _save(db, session)
        roles = await hsl.known_roles(db, tokens.claims.roles)
        if not roles:
            return await _end_hsl_session(db, session, "no Slipway role")
        try:
            await apply_claimed_roles(db, user, roles)
        except UserError:
            # Keycloak took admin away from the last admin: keep the role, but not the person signed in with it.
            return await _end_hsl_session(db, session, "it would remove the last active admin")
        if tokens.claims.name:
            user.full_name = tokens.claims.name[:200]
        if user.hackspacelabs is not None and tokens.claims.preferred_username:
            user.hackspacelabs.login = tokens.claims.preferred_username[:100]
        now = utcnow()
        session.idp_tokens = hsl.sealed(tokens)
        session.idp_sid = tokens.claims.sid[:255] or session.idp_sid
        session.idp_checked_at = now
        session.expires_at = now + tokens.session_lifetime
        return await _save(db, session)
    finally:
        _rechecking.discard(session.id)


async def _save(db: AsyncSession, session: UserSession) -> UserSession | None:
    try:
        await db.commit()
    except StaleDataError:  # signed out by another request meanwhile
        await db.rollback()
        return None
    return session


async def _end_hsl_session(db: AsyncSession, session: UserSession, why: str) -> None:
    user = session.user
    log.info("HackSpaceLabs session of %s ended: %s", user.email, why)
    audit.record(db, "auth.session_ended", actor=user, target=user, summary=f"HackSpaceLabs session ended: {why}"[:300],
                 details={"method": "hackspacelabs", "reason": why[:200]})
    await db.delete(session)
    try:
        await db.commit()
    except StaleDataError:
        await db.rollback()


async def revoke_user_sessions(db: AsyncSession, user: User, *, keep: UserSession | None = None) -> None:
    stmt = delete(UserSession).where(UserSession.user_id == user.id)
    if keep is not None:
        stmt = stmt.where(UserSession.id != keep.id)
    await db.execute(stmt)


async def revoke_user_tokens(db: AsyncSession, user: User) -> None:
    await db.execute(delete(ApiToken).where(ApiToken.user_id == user.id))


async def _unlink(db: AsyncSession, user: User, provider: str) -> list[str]:
    accounts = [a for a in user.oauth_accounts if a.provider == provider]
    for account in accounts:
        user.oauth_accounts.remove(account)
    await db.flush()
    # Also catch a link a concurrent callback committed after ``user`` was loaded.
    await db.execute(delete(OAuthAccount).where(OAuthAccount.user_id == user.id, OAuthAccount.provider == provider))
    return [a.login for a in accounts]


async def revoke_user_github(db: AsyncSession, user: User) -> list[str]:
    """Unlink every GitHub account from ``user``. Returns the logins that were linked."""
    return await _unlink(db, user, GITHUB)


async def revoke_user_hackspacelabs(db: AsyncSession, user: User) -> list[str]:
    """Unlink ``user``'s HackSpaceLabs account. Returns the Keycloak usernames that were linked."""
    return await _unlink(db, user, HACKSPACELABS)


async def revoke_user_credentials(db: AsyncSession, user: User, *, reset: bool) -> list[str]:
    """Sign the user out everywhere, delete their API tokens and unlink GitHub (admin reset, deactivation).

    A GitHub link is a credential too: one planted with a stolen session must not survive a reset. So is a
    HackSpaceLabs link, which a password reset (``reset``) drops as well; deactivation keeps it, or the person's
    next silent HackSpaceLabs sign-in would not find this account and could be given a fresh, active one.
    Returns the HackSpaceLabs usernames unlinked.
    """
    await revoke_user_sessions(db, user)
    await revoke_user_tokens(db, user)
    await revoke_user_github(db, user)
    return await revoke_user_hackspacelabs(db, user) if reset else []
