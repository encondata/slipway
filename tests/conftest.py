"""Test fixtures. Tests run against SQLite; set SLIPWAY_TEST_DATABASE_URL to use PostgreSQL."""

from __future__ import annotations

import os
import tempfile
from collections.abc import AsyncIterator, Callable
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix="slipway-tests-"))
os.environ.update(
    SLIPWAY_ENV_FILE="",  # never read the developer's .env
    SLIPWAY_ENV="test",
    SLIPWAY_DATABASE_URL=os.environ.get("SLIPWAY_TEST_DATABASE_URL", f"sqlite+aiosqlite:///{_tmp}/test.db"),
    SLIPWAY_SECRET_KEY="test-secret-key-that-is-long-enough-1234567890",
    SLIPWAY_HOST_POLL_INTERVAL="0",
    SLIPWAY_UPDATE_CHECK_INTERVAL="0",
    SLIPWAY_UPDATE_RECONCILE_INTERVAL="0",
    SLIPWAY_GITHUB_CLIENT_ID="test-client",
    SLIPWAY_GITHUB_CLIENT_SECRET="test-secret",
    SLIPWAY_BASE_URL="http://testserver",
    SLIPWAY_ALLOW_SIGNUP="false",
)

import httpx  # noqa: E402
import pytest  # noqa: E402

from slipway.core import ratelimit  # noqa: E402
from slipway.db.base import Base  # noqa: E402
from slipway.db.session import get_engine, get_sessionmaker, init_engine  # noqa: E402
from slipway.main import create_app  # noqa: E402
from slipway.models import User  # noqa: E402
from slipway.services.users import bootstrap, create_user  # noqa: E402

PASSWORD = "correct-horse-battery"


@pytest.fixture(scope="session")
def app():
    init_engine(os.environ["SLIPWAY_DATABASE_URL"])
    return create_app()


@pytest.fixture(autouse=True)
async def fresh_db(app) -> AsyncIterator[None]:
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with get_sessionmaker()() as db:
        await bootstrap(db)
    ratelimit.reset_all()
    yield


@pytest.fixture
def make_client(app) -> Callable[..., httpx.AsyncClient]:
    clients: list[httpx.AsyncClient] = []

    def factory(ip: str = "127.0.0.1") -> httpx.AsyncClient:
        transport = httpx.ASGITransport(app=app, client=(ip, 123))
        c = httpx.AsyncClient(transport=transport, base_url="http://testserver")
        clients.append(c)
        return c

    yield factory
    # httpx clients over ASGITransport hold no sockets; nothing to close explicitly.


@pytest.fixture
async def client(make_client) -> httpx.AsyncClient:
    return make_client()


async def make_user(email: str, roles: list[str] | None = None, password: str = PASSWORD) -> User:
    async with get_sessionmaker()() as db:
        user = await create_user(db, email=email, password=password, full_name=email.split("@")[0], role_names=roles)
        await db.commit()
        return user


async def login(client: httpx.AsyncClient, email: str, password: str = PASSWORD) -> dict:
    resp = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    client.headers["X-CSRF-Token"] = data["csrf_token"]
    return data


@pytest.fixture
async def admin_client(client) -> httpx.AsyncClient:
    await make_user("admin@example.com")  # first user -> admin
    await login(client, "admin@example.com")
    return client
