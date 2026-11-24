"""Authentication, CSRF and permission dependencies shared by the API and web pages."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.core.security import safe_equals
from slipway.db.session import get_db
from slipway.services.auth import (
    CSRF_HEADER,
    OIDC,
    SESSION_COOKIE,
    AuthContext,
    recheck_hsl_session,
    session_from_cookie,
    token_from_bearer,
)

DB = Annotated[AsyncSession, Depends(get_db)]
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


async def get_optional_auth(request: Request, db: DB) -> AuthContext | None:
    authz = request.headers.get("authorization", "")
    ctx: AuthContext | None = None
    if authz[:7].lower() == "bearer ":
        token = await token_from_bearer(db, authz[7:].strip())
        if token is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired API token")
        ctx = AuthContext(user=token.user, via="token", token=token)
    elif raw := request.cookies.get(SESSION_COOKIE):
        session = await session_from_cookie(db, raw)
        if session is not None and session.auth_source == OIDC:
            session = await recheck_hsl_session(db, session)
            if session is None:
                # Ended by Keycloak's answer: main.py clears the cookie on whatever response this request gets.
                request.state.end_session_cookie = True
        if session is not None:
            ctx = AuthContext(user=session.user, via="session", session=session)
    request.state.auth = ctx
    return ctx


OptionalAuth = Annotated[AuthContext | None, Depends(get_optional_auth)]


async def get_auth(request: Request, ctx: OptionalAuth) -> AuthContext:
    if ctx is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    # Cookie-authenticated writes must echo the per-session CSRF token in a header.
    if ctx.via == "session" and request.method not in SAFE_METHODS:
        sent = request.headers.get(CSRF_HEADER, "")
        if not (ctx.session and safe_equals(sent, ctx.session.csrf_token)):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token missing or invalid")
    return ctx


Auth = Annotated[AuthContext, Depends(get_auth)]


def require(*permissions: str):
    """Dependency factory: ``ctx: Annotated[AuthContext, require(Perm.HOSTS_READ)]``."""

    async def checker(ctx: Auth) -> AuthContext:
        missing = [p for p in permissions if not ctx.can(p)]
        if missing:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {', '.join(missing)}")
        return ctx

    return Depends(checker)


def not_found(what: str = "Resource") -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, f"{what} not found")
