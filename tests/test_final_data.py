"""Regression tests for the final data review: unreadable env vars, NUL in input, long branch names,
the host key pinning race, and migration 0008 (data safety)."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path

import asyncpg
import asyncssh
import httpx
import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError
from sqlalchemy import Text, event, select, type_coerce
from sqlalchemy.dialects.postgresql.asyncpg import AsyncAdapt_asyncpg_connection, PGDialect_asyncpg
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.api.deps import DB
from slipway.api.v1 import repositories as repositories_api
from slipway.core.config import Settings, get_settings
from slipway.core.crypto import reset_crypto_cache
from slipway.core.permissions import SYSTEM_ROLES, has_permission
from slipway.db.session import get_engine, get_sessionmaker
from slipway.main import create_app
from slipway.models import AuditEvent, Deployment, Host, Instance, OAuthAccount, Repository, User
from slipway.models.repository import DEFAULT_BRANCH_TOO_LONG
from slipway.services import deployer, hosts, ssh
from slipway.services.github import GitHubClient
from slipway.services.repos import sync_repositories
from slipway.services.users import create_user
from tests.test_deployer import SHA, FakeGitHub, FakeRemote, _connect

ROOT = Path(__file__).resolve().parent.parent
K1, K2 = (Fernet.generate_key().decode() for _ in range(2))
SECRET_ENV = {"DATABASE_URL": "postgres://app:secret@db/app"}


# ------------------------------------------------- env that can't be decrypted (0)


@pytest.fixture
def use_key():
    """Switch SLIPWAY_ENCRYPTION_KEY for one test, rebuilding the cached settings and keys."""
    saved = os.environ.get("SLIPWAY_ENCRYPTION_KEY")

    def apply(value: str) -> None:
        os.environ["SLIPWAY_ENCRYPTION_KEY"] = value
        get_settings.cache_clear()
        reset_crypto_cache()

    yield apply
    if saved is None:
        os.environ.pop("SLIPWAY_ENCRYPTION_KEY", None)
    else:
        os.environ["SLIPWAY_ENCRYPTION_KEY"] = saved
    get_settings.cache_clear()
    reset_crypto_cache()


async def _unreadable_instance(use_key) -> str:
    """A deployed instance whose env was encrypted with K1, while Slipway now only has K2."""
    use_key(K1)
    async with get_sessionmaker()() as db:
        host = Host(name="prod-01", hostname="10.0.0.1", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
        repo = Repository(github_id=42, full_name="acme/web", owner="acme", name="web", html_url="https://github.com/acme/web",
                          detected_config={"dockerfile": True, "compose_file": None, "files": ["Dockerfile"]})
        inst = Instance(name="web", slug="web", branch="main", host=host, repository=repo, env=dict(SECRET_ENV),
                        ports=[], volumes=[], status="running", current_commit_sha=SHA)
        db.add(inst)
        await db.commit()
        instance_id = str(inst.id)
    use_key(K2)
    return instance_id


async def _raw_env(instance_id: str) -> str | None:
    """The stored ciphertext, without decrypting it."""
    async with get_sessionmaker()() as db:
        return await db.scalar(select(type_coerce(Instance.env, Text())).where(Instance.id == uuid.UUID(instance_id)))


async def _env(instance_id: str) -> dict | None:
    async with get_sessionmaker()() as db:
        return await db.scalar(select(Instance.env).where(Instance.id == uuid.UUID(instance_id)))


# What instance_form.html sends after only renaming the instance: the env repeater is always a map.
FORM_SAVE = {"branch": "main", "name": "web-renamed", "env": {}, "ports": [], "volumes": []}


async def test_saving_the_edit_form_keeps_env_that_cannot_be_decrypted(admin_client, use_key):
    instance_id = await _unreadable_instance(use_key)
    raw = await _raw_env(instance_id)
    assert raw is not None

    r = await admin_client.patch(f"/api/v1/instances/{instance_id}", json=FORM_SAVE)
    assert r.status_code == 200, r.text
    assert await _raw_env(instance_id) == raw  # the recoverable ciphertext is untouched
    assert r.json()["name"] == "web-renamed" and r.json()["env_unreadable"] is True

    assert (await admin_client.get(f"/api/v1/instances/{instance_id}")).json()["env_unreadable"] is True
    assert (await admin_client.get("/api/v1/instances")).json()[0]["env_unreadable"] is True
    env = await admin_client.get(f"/api/v1/instances/{instance_id}/env")
    assert env.status_code == 409 and "SLIPWAY_ENCRYPTION_KEY" in env.json()["detail"]

    use_key(f"{K2},{K1}")  # the documented recovery still brings the values back
    assert await _env(instance_id) == SECRET_ENV


async def test_deploy_still_refuses_after_the_edit_form_was_saved(admin_client, use_key):
    instance_id = await _unreadable_instance(use_key)
    assert (await admin_client.patch(f"/api/v1/instances/{instance_id}", json=FORM_SAVE)).status_code == 200
    async with get_sessionmaker()() as db:
        user = await db.scalar(select(User))
        dep = Deployment(instance_id=uuid.UUID(instance_id), branch="main", triggered_by_id=user.id, log="")
        db.add(dep)
        await db.commit()
    remote = FakeRemote()
    await deployer.run_deployment(dep.id, connect=_connect(remote), github=FakeGitHub)
    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, dep.id)
    assert dep.status == "failed" and dep.error == deployer.ENV_UNREADABLE
    assert remote.files == {}


async def test_reentered_env_replaces_values_that_cannot_be_decrypted(admin_client, use_key):
    instance_id = await _unreadable_instance(use_key)
    url = f"/api/v1/instances/{instance_id}"
    r = await admin_client.patch(url, json={**FORM_SAVE, "env": {"DATABASE_URL": "postgres://new"}})
    assert r.status_code == 200 and r.json()["env_unreadable"] is False and r.json()["env_keys"] == ["DATABASE_URL"]
    assert (await admin_client.get(f"{url}/env")).json() == {"DATABASE_URL": "postgres://new"}
    # Once readable, an empty env clears the variables as before.
    assert (await admin_client.patch(url, json={"env": {}})).status_code == 200
    assert (await admin_client.get(f"{url}/env")).json() == {}


async def test_clear_env_erases_values_that_cannot_be_decrypted_and_is_audited(admin_client, use_key):
    instance_id = await _unreadable_instance(use_key)
    r = await admin_client.patch(f"/api/v1/instances/{instance_id}", json={"clear_env": True})
    assert r.status_code == 200 and r.json()["env_unreadable"] is False
    assert (await admin_client.get(f"/api/v1/instances/{instance_id}/env")).json() == {}
    async with get_sessionmaker()() as db:
        event_ = await db.scalar(select(AuditEvent).where(AuditEvent.action == "instance.update"))
    assert "env (cleared)" in event_.summary
    assert event_.details == {"env_unreadable": True, "env_replaced": True}


# ---------------------------------------------------------------- NUL in input (5)


_PG_DBAPI = PGDialect_asyncpg.import_dbapi()


def _asyncpg_error(error: Exception) -> Exception:
    """What SQLAlchemy's asyncpg adapter makes of a driver error (a plain DBAPIError, not DataError)."""
    try:
        AsyncAdapt_asyncpg_connection._handle_exception_no_connection(_PG_DBAPI, error)
    except _PG_DBAPI.Error as translated:
        return translated
    raise AssertionError("not translated")


def _reject_like_postgres(conn, cursor, statement, parameters, context, executemany) -> None:
    """PostgreSQL refuses NUL in any text parameter (22021) and \\u0000 in jsonb (22P05); SQLite stores both."""
    for row in parameters if executemany else [parameters]:
        for value in (row.values() if isinstance(row, dict) else row or ()):
            if not isinstance(value, str):
                continue
            if "\x00" in value:
                error = asyncpg.exceptions.CharacterNotInRepertoireError('invalid byte sequence for encoding "UTF8": 0x00')
            elif "\\u0000" in value:
                error = asyncpg.exceptions.UntranslatableCharacterError("unsupported Unicode escape sequence")
            else:
                continue
            raise DBAPIError.instance(statement, parameters, _asyncpg_error(error), _PG_DBAPI.Error)


@pytest.fixture
def postgres_text():
    engine = get_engine().sync_engine
    event.listen(engine, "before_cursor_execute", _reject_like_postgres)
    yield
    event.remove(engine, "before_cursor_execute", _reject_like_postgres)


async def _seed_repo_and_host() -> tuple[str, str]:
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=7, full_name="acme/web", owner="acme", name="web", html_url="https://github.com/acme/web",
                          detected_config={"dockerfile": True, "compose_file": None, "files": ["Dockerfile"]})
        host = Host(name="h0", hostname="10.0.0.1", username="deploy", metrics={})
        db.add_all([repo, host])
        await db.commit()
        return str(repo.id), str(host.id)


async def test_nul_in_request_bodies_is_a_422(admin_client, make_client, postgres_text):
    repo_id, host_id = await _seed_repo_and_host()
    instance = {"name": "web", "repository_id": repo_id, "host_id": host_id, "deploy": False}
    requests = [
        ("patch", "/api/v1/auth/me", {"full_name": "Al\x00ice"}),
        ("post", "/api/v1/tokens", {"name": "ci\x00"}),
        ("post", "/api/v1/hosts", {"name": "h1", "hostname": "10.0.0.7", "username": "deploy", "description": "d\x00"}),
        ("post", "/api/v1/hosts", {"name": "h2", "hostname": "10.0.0.8", "username": "deploy", "environment": "p\x00"}),
        ("post", "/api/v1/roles", {"name": "ops", "description": "x\x00", "permissions": ["hosts:read"]}),
        ("post", "/api/v1/users", {"email": "new@example.com", "full_name": "N\x00", "roles": ["viewer"]}),
        ("post", "/api/v1/instances", {**instance, "name": "web\x00"}),
        ("post", "/api/v1/instances", {**instance, "volumes": [{"source": "/srv/a\x00b", "target": "/data"}]}),
        ("post", "/api/v1/instances", {**instance, "volumes": [{"source": "/srv/a", "target": "/da\x00ta"}]}),
    ]
    for method, url, body in requests:
        r = await getattr(admin_client, method)(url, json=body)
        assert r.status_code == 422, (url, body, r.status_code)
        assert "NUL" in r.text
    login = await make_client("10.1.1.1").post("/api/v1/auth/login", json={"email": "x\x00@example.com", "password": "whatever-1"})
    assert login.status_code == 422
    assert login.json()["detail"][0]["msg"] == "Value error, must not contain NUL characters"
    # The guard leaves the fields' own limits, patterns and messages alone.
    for url, body, message in [
        ("/api/v1/tokens", {"name": "t" * 101}, "String should have at most 100 characters"),
        (f"/api/v1/hosts/{host_id}", {"description": "d" * 256}, "String should have at most 255 characters"),
        (f"/api/v1/hosts/{host_id}", {"hostname": "10.0.0.3; rm -rf /"}, "String should match pattern"),
    ]:
        r = await (admin_client.post if url.endswith("tokens") else admin_client.patch)(url, json=body)
        assert r.status_code == 422 and r.json()["detail"][0]["msg"].startswith(message), r.text


@pytest.mark.parametrize("url", [
    "/api/v1/repositories?q=a%00",
    "/api/v1/audit?action=a%00",
    "/search?q=a%00",
    f"/api/v1/hosts/{uuid.uuid4()}%00",
    "/api/v1/hosts/%00",
])
async def test_nul_in_the_url_is_a_400(admin_client, postgres_text, url):
    r = await admin_client.get(url)
    assert r.status_code == 400 and r.json()["detail"] == "The URL contains a NUL character"
    assert "Content-Security-Policy" in r.headers


async def test_database_errors_for_unstorable_text_are_a_400(app, postgres_text):
    probe = create_app()

    @probe.post("/_test/nul")
    async def write_nul(db: DB) -> dict:  # text that skipped every request model
        db.add(AuditEvent(action="test", summary="a\x00b", details={}))
        await db.commit()
        return {}

    @probe.post("/_test/jsonb")
    async def write_jsonb(db: DB) -> dict:
        db.add(AuditEvent(action="test", summary="ok", details={"v": "a\x00b"}))
        await db.commit()
        return {}

    @probe.post("/_test/other")
    async def other_error(db: DB) -> dict:
        raise DBAPIError("SELECT 1", None, _asyncpg_error(asyncpg.exceptions.DeadlockDetectedError("deadlock detected")))

    transport = httpx.ASGITransport(app=probe, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        for path in ("/_test/nul", "/_test/jsonb"):
            r = await c.post(path)
            assert r.status_code == 400 and r.json()["detail"] == "Input contains characters the database cannot store"
        assert (await c.post("/_test/other")).status_code == 500
    async with get_sessionmaker()() as db:
        assert await db.scalar(select(AuditEvent).where(AuditEvent.action == "test")) is None


# ------------------------------------------------------------ long branch names (6)


def _repo_json(github_id: int, **extra) -> dict:
    name = f"repo-{github_id}"
    return {
        "id": github_id, "full_name": f"acme/{name}", "owner": {"login": "acme"}, "name": name,
        "html_url": f"https://github.com/acme/{name}", "default_branch": "main",
        "pushed_at": "2026-11-01T10:00:00Z", "visibility": "public", **extra,
    }


class _GitHub:
    """GitHub returning one repository whose default branch can change between syncs."""

    def __init__(self, branch: str) -> None:
        self.branch = branch
        self.refs: list[str | None] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user/repos":
            return httpx.Response(200, json=[_repo_json(9, default_branch=self.branch)])
        self.refs.append(request.url.params.get("ref"))
        return httpx.Response(200, json=[{"name": "Dockerfile", "type": "file"}])

    async def sync(self, db, user) -> Repository:
        async with GitHubClient("gho_x", transport=httpx.MockTransport(self.handler)) as gh:
            await sync_repositories(db, user, client=gh)
        return await db.scalar(select(Repository).execution_options(populate_existing=True))


async def _linked_user(db) -> User:
    user = await create_user(db, email="dev@example.com", full_name="Dev")
    user.oauth_accounts.append(OAuthAccount(provider="github", provider_user_id="1", login="dev", access_token="gho_x"))
    await db.commit()
    return user


async def test_sync_never_cuts_a_default_branch_name(caplog):
    too_long = "release/" + "x" * 300
    github = _GitHub(too_long)
    async with get_sessionmaker()() as db:
        user = await _linked_user(db)
        repo = await github.sync(db, user)
        assert repo.default_branch == "main" and not repo.default_branch_usable  # a new repository
        assert github.refs == [] and not repo.deployable
        assert "longer than 255 characters" in caplog.text

        github.branch = "develop"
        repo = await github.sync(db, user)
        assert repo.default_branch == "develop" and repo.default_branch_usable and repo.deployable
        assert github.refs == ["develop"]

        github.branch = too_long
        repo = await github.sync(db, user)
        assert repo.default_branch == "develop" and not repo.default_branch_usable  # the stored one is kept
        assert github.refs == ["develop"]  # never detected with a cut (or any) name

        long = "release/" + "y" * 240
        github.branch = long
        repo = await github.sync(db, user)
        assert repo.default_branch == long and repo.default_branch_usable
        assert github.refs == ["develop", long]


async def _seed(default_branch: str, detected: dict | None = None) -> tuple[str, str]:
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=7, full_name="acme/web", owner="acme", name="web", html_url="https://github.com/acme/web",
                          default_branch=default_branch,
                          detected_config=detected or {"dockerfile": True, "compose_file": None, "files": ["Dockerfile"]})
        host = Host(name="h0", hostname="10.0.0.1", username="deploy", metrics={})
        db.add_all([repo, host])
        await db.commit()
        return str(repo.id), str(host.id)


async def test_branch_names_up_to_255_characters_are_kept_whole(admin_client):
    long = "release/" + "y" * 240
    repo_id, host_id = await _seed(long)
    body = {"repository_id": repo_id, "host_id": host_id, "deploy": False}
    r = await admin_client.post("/api/v1/instances", json={**body, "name": "web"})
    assert r.status_code == 201 and r.json()["branch"] == long
    explicit = "b" * 255
    r = await admin_client.post("/api/v1/instances", json={**body, "name": "web2", "branch": explicit})
    assert r.status_code == 201 and r.json()["branch"] == explicit
    r = await admin_client.post("/api/v1/instances", json={**body, "name": "web3", "branch": "b" * 256})
    assert r.status_code == 422
    for column in (Repository.default_branch, Instance.branch, Deployment.branch):
        assert column.type.length == 255


async def test_instance_needs_a_branch_when_the_default_could_not_be_stored(admin_client):
    repo_id, host_id = await _seed("main", {"dockerfile": True, DEFAULT_BRANCH_TOO_LONG: True})
    body = {"name": "web", "repository_id": repo_id, "host_id": host_id, "deploy": False}
    r = await admin_client.post("/api/v1/instances", json=body)
    assert r.status_code == 400 and "specify a branch" in r.json()["detail"]
    assert (await admin_client.get(f"/api/v1/repositories/{repo_id}")).json()["default_branch_usable"] is False
    assert (await admin_client.post(f"/api/v1/repositories/{repo_id}/detect")).status_code == 400
    r = await admin_client.post("/api/v1/instances", json={**body, "branch": "develop"})
    assert r.status_code == 201 and r.json()["branch"] == "develop"


async def test_branch_list_only_promotes_a_usable_default_branch(admin_client, monkeypatch):
    repo_id, _ = await _seed("main", {"dockerfile": True, DEFAULT_BRANCH_TOO_LONG: True})
    url = f"/api/v1/repositories/{repo_id}/branches"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/repositories/7/branches"
        return httpx.Response(200, json=[{"name": n} for n in ("zeta", "main", "develop")])

    monkeypatch.setattr(repositories_api, "GitHubClient", lambda token: GitHubClient(token, transport=httpx.MockTransport(handler)))
    assert (await admin_client.get(url)).json() == ["develop", "main", "zeta"]  # "main" is only a placeholder
    async with get_sessionmaker()() as db:
        repo = await db.get(Repository, uuid.UUID(repo_id))
        repo.detected_config = {"dockerfile": True}
        await db.commit()
    assert (await admin_client.get(url)).json() == ["main", "develop", "zeta"]  # a usable default branch comes first


def test_migrations_widen_the_branch_columns(tmp_path):
    env = {**os.environ, "SLIPWAY_DATABASE_URL": f"sqlite+aiosqlite:///{tmp_path}/m.db", "SLIPWAY_ENV_FILE": "", "PYTHONPATH": str(ROOT)}
    for args in (["upgrade", "head"], ["downgrade", "-1"], ["upgrade", "head"], ["check"]):
        done = subprocess.run([sys.executable, "-m", "alembic", *args], cwd=ROOT, env=env, capture_output=True, text=True)
        assert done.returncode == 0, (args, done.stderr)
    with sqlite3.connect(tmp_path / "m.db") as conn:
        types = {
            (table, row[1]): row[2]
            for table in ("repositories", "instances", "deployments")
            for row in conn.execute(f"PRAGMA table_info({table})")
        }
    assert {types["repositories", "default_branch"], types["instances", "branch"], types["deployments", "branch"]} == {"VARCHAR(255)"}


# --------------------------------------------------------- host key pinning race (7)


def _result(host_key: str) -> ssh.ProbeResult:
    return ssh.ProbeResult(host_key=host_key, fingerprint=ssh.fingerprint(host_key), os_info="Debian 13", cpus=2,
                           cpu_percent=10, mem_total_mb=4096, mem_percent=40, docker_version="27.0", docker_error=None,
                           containers_running=0)


@pytest.fixture
async def unpinned_host(admin_client, monkeypatch) -> str:
    host = (await admin_client.post("/api/v1/hosts", json={"name": "a", "hostname": "10.0.0.5", "username": "deploy"})).json()
    key = asyncssh.generate_private_key("ssh-ed25519").export_public_key("openssh").decode().strip()

    async def probe(target):
        assert target.hostname == "10.0.0.5"
        return _result(key)

    monkeypatch.setattr(hosts.ssh, "probe", probe)
    return f"/api/v1/hosts/{host['id']}"


def _run_during_get(monkeypatch, when, action) -> list[bool]:
    """Run ``action`` once, right after the first ``AsyncSession.get`` of a Host for which ``when(kwargs)``."""
    real_get = AsyncSession.get
    fired: list[bool] = []

    async def get(self, entity, ident, **kwargs):
        obj = await real_get(self, entity, ident, **kwargs)
        if entity is Host and when(kwargs) and not fired:
            fired.append(True)
            await action()
        return obj

    monkeypatch.setattr(AsyncSession, "get", get)
    return fired


async def _stored(url: str) -> Host:
    async with get_sessionmaker()() as db:
        return await db.get(Host, uuid.UUID(url.rsplit("/", 1)[1]))


async def test_check_result_is_not_written_after_a_concurrent_address_change(admin_client, unpinned_host, monkeypatch):
    url = unpinned_host

    async def move():  # commits after the check re-read the host, before it writes the result
        assert (await admin_client.patch(url, json={"hostname": "10.0.0.99"})).status_code == 200

    fired = _run_during_get(monkeypatch, lambda kw: kw.get("populate_existing"), move)
    checked = await admin_client.post(f"{url}/check")
    assert fired and checked.status_code == 200
    assert checked.json()["hostname"] == "10.0.0.99" and checked.json()["host_key_fingerprint"] is None
    host = await _stored(url)
    assert (host.hostname, host.host_key, host.host_key_fingerprint, host.status) == ("10.0.0.99", None, None, "unknown")
    assert (await admin_client.get("/api/v1/audit?action=host.key_pinned")).json() == []


@pytest.mark.parametrize(("method", "path", "body"), [
    ("patch", "", {"hostname": "10.0.0.99"}),
    ("post", "/reset-host-key", None),
])
async def test_key_pinned_while_the_host_was_being_edited_is_cleared(admin_client, unpinned_host, monkeypatch, method, path, body):
    url = unpinned_host
    pinned: list[str] = []

    async def check():  # pins the key at the old address after the edit loaded the host, before it saves
        pinned.append((await admin_client.post(f"{url}/check")).json()["host_key_fingerprint"])

    fired = _run_during_get(monkeypatch, lambda kw: not kw, check)
    kwargs = {"json": body} if body is not None else {}
    r = await getattr(admin_client, method)(f"{url}{path}", **kwargs)
    assert fired and pinned[0] and r.status_code == 200 and r.json()["host_key_fingerprint"] is None
    host = await _stored(url)
    assert (host.host_key, host.host_key_fingerprint, host.status) == (None, None, "unknown")
    # The audit trail says which key was cleared, although the edit loaded the host before it was pinned.
    resets = (await admin_client.get("/api/v1/audit?action=host.key_reset")).json()
    assert len(resets) == 1 and pinned[0] in resets[0]["summary"], resets


# ------------------------------------------------------- migration 0008: data safety (test 40)


def _alembic(db: Path, *args: str) -> None:
    env = {**os.environ, "SLIPWAY_DATABASE_URL": f"sqlite+aiosqlite:///{db}", "SLIPWAY_ENV_FILE": "", "PYTHONPATH": str(ROOT)}
    done = subprocess.run([sys.executable, "-m", "alembic", *args], cwd=ROOT, env=env, capture_output=True, text=True)
    assert done.returncode == 0, (args, done.stderr)


def _seed_0007(conn: sqlite3.Connection) -> dict[str, str]:
    """A host, a repository and two instances with jobs left queued and running by a stopped Slipway, as
    stored at revision 0007 (UUIDs as 32 hex digits, JSON as text: what SQLAlchemy writes on SQLite)."""
    ids = {k: uuid.uuid4().hex for k in ("host", "repo", "busy", "idle", "queued", "running", "done", "other")}
    conn.execute("INSERT INTO hosts (id, name, hostname, port, username, environment, description, deploy_root, "
                 "auth_method, status, metrics) VALUES (?, 'h', '10.0.0.1', 22, 'deploy', '', '', '/opt/slipway', "
                 "'key', 'healthy', '{}')", (ids["host"],))
    conn.execute("INSERT INTO repositories (id, github_id, full_name, owner, name, description, visibility, "
                 "default_branch, html_url, archived, detected_config) VALUES (?, 1, 'acme/web', 'acme', 'web', '', "
                 "'private', 'main', 'https://github.com/acme/web', 0, '{}')", (ids["repo"],))
    for key, status in (("busy", "deploying"), ("idle", "running")):
        conn.execute("INSERT INTO instances (id, name, slug, repository_id, host_id, branch, build_source, "
                     "dockerfile_path, build_context, compose_file, ports, volumes, status) VALUES "
                     "(?, ?, ?, ?, ?, 'main', 'app', 'Dockerfile', '.', 'docker-compose.yml', '[]', '[]', ?)",
                     (ids[key], key, key, ids["repo"], ids["host"], status))
    steps = '[{"key": "fetch", "status": "done"}, {"key": "build", "status": "running"}, {"key": "start", "status": "pending"}]'
    # Two active rows for one instance: the new unique index can only be built once they are failed.
    for key, instance, status in (("queued", "busy", "queued"), ("running", "busy", "running"),
                                  ("done", "busy", "succeeded"), ("other", "idle", "queued")):
        conn.execute("INSERT INTO deployments (id, instance_id, status, branch, log, steps) VALUES (?, ?, ?, 'main', '', ?)",
                     (ids[key], ids[instance], status, steps if status == "running" else "[]"))
    return ids


def test_migration_0008_fails_leftover_jobs_adds_the_one_active_index_and_downgrades(tmp_path):
    db = tmp_path / "m.db"
    _alembic(db, "upgrade", "0007")
    with sqlite3.connect(db) as conn:
        ids = _seed_0007(conn)

    _alembic(db, "upgrade", "head")
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        deps = {r["id"]: r for r in conn.execute("SELECT * FROM deployments")}
        for key in ("queued", "running", "other"):
            row = deps[ids[key]]
            assert (row["status"], row["error"]) == ("failed", "Interrupted by a Slipway restart")
            assert row["finished_at"] is not None
        assert deps[ids["done"]]["status"] == "succeeded" and deps[ids["done"]]["error"] is None
        # A step that was running is marked as interrupted, as recover_interrupted does.
        assert json.loads(deps[ids["running"]]["steps"]) == [
            {"key": "fetch", "status": "done"},
            {"key": "build", "status": "failed", "note": "Interrupted"},
            {"key": "start", "status": "pending"},
        ]
        assert {(r["kind"], r["options"], r["backup_id"]) for r in deps.values()} == {("deploy", "{}", None)}
        instances = {r["id"]: r for r in conn.execute("SELECT * FROM instances")}
        # Only an instance left deploying becomes failed; the other one keeps running its old release.
        assert instances[ids["busy"]]["status"] == "failed" and instances[ids["idle"]]["status"] == "running"
        assert {(r["keep_backups"], r["seed_content"], r["content_pending"], r["data_dirty"]) for r in instances.values()} == {
            (5, 1, 0, None)
        }
        assert {"backups", "snapshots", "first_admins"} <= {
            r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }

        # The partial unique index: one queued or running job per instance, any number of finished ones.
        (index_sql,) = conn.execute("SELECT sql FROM sqlite_master WHERE name = 'ux_deployments_one_active'").fetchone()
        assert "UNIQUE" in index_sql and "WHERE status IN ('queued', 'running')" in index_sql
        insert = "INSERT INTO deployments (id, instance_id, status, branch, log, steps) VALUES (?, ?, ?, 'main', '', '[]')"
        conn.execute(insert, (uuid.uuid4().hex, ids["busy"], "failed"))
        conn.execute(insert, (uuid.uuid4().hex, ids["busy"], "queued"))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(insert, (uuid.uuid4().hex, ids["busy"], "running"))
        conn.execute(insert, (uuid.uuid4().hex, ids["idle"], "running"))  # another instance may run its own

    _alembic(db, "downgrade", "0007")
    with sqlite3.connect(db) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert not {"backups", "snapshots", "first_admins"} & tables
        assert conn.execute("SELECT count(*) FROM sqlite_master WHERE name = 'ux_deployments_one_active'").fetchone() == (0,)
        dep_columns = {r[1] for r in conn.execute("PRAGMA table_info(deployments)")}
        inst_columns = {r[1] for r in conn.execute("PRAGMA table_info(instances)")}
        assert not {"kind", "options", "previous_sha", "backup_id", "restore_backup_id", "snapshot_id"} & dep_columns
        assert not {"keep_backups", "seed_snapshot_id", "live_identity", "data_dirty", "fresh_data"} & inst_columns
        assert conn.execute("SELECT count(*) FROM deployments").fetchone() == (7,)  # the rows themselves are kept

    # Upgrading again fails the jobs queued above and matches the models exactly.
    _alembic(db, "upgrade", "head")
    _alembic(db, "check")
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT count(*) FROM deployments WHERE status IN ('queued', 'running')").fetchone() == (0,)


# ------------------------------------------------- data safety permissions and settings


def test_data_permissions_by_role():
    """§14.1: who may read, back up, restore, reset, upload and download data."""
    def granted(role: str) -> set[str]:
        return {str(p) for p in SYSTEM_ROLES[role]["permissions"]}

    data = ["data:read", "data:backup", "data:restore", "data:reset", "snapshots:upload", "snapshots:download"]
    expected = {
        "viewer": ["data:read"],
        "developer": ["data:read", "data:backup", "data:restore"],
        "maintainer": ["data:read", "data:backup", "data:restore", "data:reset", "snapshots:upload"],
        "admin": data,
    }
    for role, perms in expected.items():
        assert [p for p in data if has_permission(granted(role), p)] == perms, role
    # A data wildcard never reaches the privileged snapshot permissions.
    assert not has_permission({"data:*"}, "snapshots:upload") and not has_permission({"data:*"}, "snapshots:download")


def test_snapshot_limits_are_range_checked(monkeypatch):
    settings = Settings()
    assert (settings.snapshot_max_bytes, settings.snapshot_total_bytes) == (20 * 1024**3, 100 * 1024**3)
    assert (settings.snapshot_transfers, settings.snapshot_kdf_slots, settings.manual_backups_max) == (2, 2, 10)
    for name, value in (("SLIPWAY_SNAPSHOT_TRANSFERS", "9"), ("SLIPWAY_SNAPSHOT_KDF_SLOTS", "0")):
        monkeypatch.setenv(name, value)
        with pytest.raises(ValidationError):
            Settings()
        monkeypatch.delenv(name)
