"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Text, column, select, table
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import Scope

from slipway import __version__
from slipway.api.v1 import api_router
from slipway.core.config import get_settings
from slipway.core.crypto import DecryptionError, decrypt, encrypted_columns
from slipway.db.base import Base
from slipway.db.session import dispose_engine, get_sessionmaker, init_engine
from slipway.services import snapshots
from slipway.services import updates
from slipway.services.deployer import runner
from slipway.services.hosts import poll_hosts_forever
from slipway.services.users import bootstrap
from slipway.web import oauth, pages

log = logging.getLogger("slipway")
STATIC_DIR = Path(__file__).parent / "web" / "static"

CSP = (
    "default-src 'self'; img-src 'self' data: https://avatars.githubusercontent.com; "
    "style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self' https://github.com"
)
NUL_IN_URL = "The URL contains a NUL character"
# SQLSTATEs PostgreSQL uses for text it cannot store: NUL in a text value (22021), \u0000 in jsonb (22P05).
UNSTORABLE_TEXT = frozenset({"22021", "22P05"})


def has_nul(scope: Scope) -> bool:
    """NUL in the path or query string, raw or percent-encoded (PostgreSQL rejects it in any text value)."""
    raw = scope.get("raw_path") or b""
    query = scope.get("query_string") or b""
    return "\x00" in scope.get("path", "") or any(b"%00" in part.lower() or b"\x00" in part for part in (raw, query))


def sqlstate(exc: DBAPIError) -> str | None:
    """The SQLSTATE of a database error, from the DBAPI exception or the driver error behind it."""
    orig = exc.orig
    for err in (orig, getattr(orig, "__cause__", None)):
        code = getattr(err, "sqlstate", None) or getattr(err, "pgcode", None)
        if code:
            return str(code)
    return None


async def check_encryption_key(db: AsyncSession) -> bool:
    """Try one stored secret per encrypted column so a wrong SLIPWAY_ENCRYPTION_KEY is reported at startup."""
    for source, col in encrypted_columns(Base.metadata):
        raw = table(source.name, column(col.name, Text())).c[col.name]
        token = await db.scalar(select(raw).where(raw.is_not(None)).limit(1))
        if token is None:
            continue
        try:
            decrypt(token)
        except DecryptionError:
            log.error(
                "SLIPWAY_ENCRYPTION_KEY cannot decrypt stored secrets (tried %s.%s), so they read as empty. "
                "Add the old key after the new one (comma-separated) and run `slipway rotate-encryption-key`, "
                "or re-enter the secrets.",
                source.name, col.name,
            )
            return False
    return True


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    init_engine()
    async with get_sessionmaker()() as db:
        await bootstrap(db)
        await check_encryption_key(db)
    await runner.recover_interrupted()
    # Snapshot storage: create and check the folders, drop unfinished files, check the rows left "checking".
    # A folder Slipway can't write is logged and answers 503 on the snapshot endpoints; deploys are unaffected.
    await snapshots.prepare_storage()
    poller = asyncio.create_task(poll_hosts_forever(), name="host-poller")
    sweeper = asyncio.create_task(snapshots.sweep_forever(), name="snapshot-sweeper")  # expired locked imports
    update_checker = asyncio.create_task(updates.check_forever(), name="update-checker")
    update_runs = asyncio.create_task(updates.reconcile_forever(), name="update-runs")
    log.info("Slipway %s started (%s)", __version__, get_settings().env)
    try:
        yield
    finally:
        for task in (poller, sweeper, update_checker, update_runs):
            task.cancel()
        for task in (poller, sweeper, update_checker, update_runs):
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await runner.shutdown()
        await snapshots.shutdown()
        await dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # asyncssh logs every connection and channel at INFO (about 20 lines per host check, and the poller checks
    # every host every few minutes), so keep it to warnings unless SLIPWAY_LOG_LEVEL is DEBUG.
    if settings.log_level != "DEBUG":
        logging.getLogger("asyncssh").setLevel(logging.WARNING)

    app = FastAPI(
        title="Slipway",
        version=__version__,
        description="Deploy GitHub repositories to your own Docker hosts over SSH.",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )

    # Added before security_headers, so that middleware (the outer one) adds headers to this 400 too.
    @app.middleware("http")
    async def reject_nul(request: Request, call_next):  # type: ignore[no-untyped-def]
        if has_nul(request.scope):
            return JSONResponse({"detail": NUL_IN_URL}, status_code=400)
        return await call_next(request)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("X-Frame-Options", "DENY")
        if not request.url.path.startswith("/api/docs"):
            response.headers.setdefault("Content-Security-Policy", CSP)
        if settings.secure_cookies:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        return response

    @app.exception_handler(pages.LoginRequired)
    async def login_required(request: Request, exc: pages.LoginRequired) -> Response:
        return RedirectResponse(f"/login?next={quote(exc.next_url)}", status_code=302)

    @app.exception_handler(pages.PageForbidden)
    async def page_forbidden(request: Request, exc: pages.PageForbidden) -> Response:
        async with get_sessionmaker()() as db:
            return await pages.render(
                request, db, "error.html", getattr(request.state, "auth", None), status_code=403, code=403,
                message=f"You don't have permission to view this page ({exc.permission}). Ask an admin for access.",
            )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> Response:
        # Malformed ids in page URLs get the friendly 404 page; the API keeps FastAPI's 422 detail.
        if not request.url.path.startswith("/api/") and "text/html" in request.headers.get("accept", ""):
            async with get_sessionmaker()() as db:
                return await pages.not_found_page(request, db, getattr(request.state, "auth", None))
        return await request_validation_exception_handler(request, exc)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
        wants_html = "text/html" in request.headers.get("accept", "") and not request.url.path.startswith("/api/")
        if wants_html and exc.status_code in (404, 405):
            async with get_sessionmaker()() as db:
                return await pages.not_found_page(request, db, getattr(request.state, "auth", None))
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))

    @app.exception_handler(DBAPIError)
    async def database_error(request: Request, exc: DBAPIError) -> Response:
        # Backstop for text that reaches PostgreSQL without passing a request model (asyncpg reports
        # it as a plain DBAPIError). Every other database error stays a 500.
        if sqlstate(exc) in UNSTORABLE_TEXT:
            return JSONResponse({"detail": "Input contains characters the database cannot store"}, status_code=400)
        raise exc

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> Response:
        # Browsers still ask for /favicon.ico for responses without <link rel="icon"> (JSON, raw files).
        return RedirectResponse("/static/img/favicon.svg", status_code=301)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(api_router, prefix="/api/v1")
    app.include_router(oauth.router)
    app.include_router(pages.router)
    return app


app = create_app()
