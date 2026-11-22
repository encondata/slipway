"""Regression tests for the follow-ups that spanned several review batches."""

from __future__ import annotations

import re
import uuid

import pytest

from sqlalchemy import select, update

from slipway.api.v1 import users as users_api
from slipway.db.session import get_sessionmaker
from slipway.models import Instance, InstanceStatus, Repository, Role, User
from slipway.services.github import GitHubError
from tests.conftest import login, make_user


async def _role(name: str, permissions: list[str]) -> str:
    async with get_sessionmaker()() as db:
        role = Role(name=name, description="", permissions=permissions, is_system=False)
        db.add(role)
        await db.commit()
        return str(role.id)


async def _client(make_client, email: str, permissions: list[str]):
    await _role(email.split("@")[0], permissions)
    await make_user(email, roles=[email.split("@")[0]])
    c = make_client()
    await login(c, email)
    return c


async def test_role_edit_only_checks_newly_added_permissions(admin_client, make_client):
    role_id = await _role("ops", ["hosts:*"])
    editor = await _client(make_client, "rm@example.com", ["roles:read", "roles:write", "hosts:read", "repos:read"])
    # Keeping a wildcard the editor lacks is fine; adding something they hold is fine.
    r = await editor.patch(f"/api/v1/roles/{role_id}", json={"permissions": ["hosts:*", "repos:read"]})
    assert r.status_code == 200, r.text
    # Adding a permission they don't hold is still refused.
    r = await editor.patch(f"/api/v1/roles/{role_id}", json={"permissions": ["hosts:*", "users:write"]})
    assert r.status_code == 403 and "users:write" in r.text


class _FakeGitHub:
    error: GitHubError | None = None

    def __init__(self, token):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def get_user_by_login(self, login):
        raise self.error


async def test_invite_by_github_login_separates_not_found_from_outage(admin_client, monkeypatch):
    monkeypatch.setattr(users_api, "GitHubClient", _FakeGitHub)
    body = {"email": "new@example.com", "github_login": "someone", "roles": ["viewer"]}
    _FakeGitHub.error = GitHubError("missing", status_code=404)
    r = await admin_client.post("/api/v1/users", json=body)
    assert r.status_code == 400 and "not found" in r.text
    _FakeGitHub.error = GitHubError("network", status_code=None)
    r = await admin_client.post("/api/v1/users", json=body)
    assert r.status_code == 502


async def test_instance_query_params_are_bounded(admin_client):
    some_id = uuid.uuid4()
    assert (await admin_client.get(f"/api/v1/instances/{some_id}/logs?tail=0")).status_code == 422
    assert (await admin_client.get(f"/api/v1/instances/{some_id}/logs?tail=100000")).status_code == 422
    assert (await admin_client.get(f"/api/v1/instances/{some_id}/deployments?limit=-1")).status_code == 422


async def test_users_page_hides_edit_for_users_you_cannot_manage(admin_client, make_client):
    mgr = await _client(make_client, "mgr@example.com", ["users:read", "users:write"])
    async with get_sessionmaker()() as db:
        admin = await db.scalar(select(User).where(User.email == "admin@example.com"))
    page = (await mgr.get("/settings/users")).text
    assert f'data-open="edit-{admin.id}"' not in page
    viewer = await make_user("v@example.com", roles=[])
    page = (await mgr.get("/settings/users")).text
    assert f'data-open="edit-{viewer.id}"' in page


async def test_own_edit_dialog_has_no_password_reset(admin_client):
    page = (await admin_client.get("/settings/users")).text
    dialog = page[page.index('<dialog class="modal" id="edit-'):]
    dialog = dialog[: dialog.index("</dialog>")]
    assert 'name="password"' not in dialog and "/settings" in dialog


async def _instance(admin_client) -> str:
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=7, full_name="acme/app", owner="acme", name="app", html_url="https://github.com/acme/app",
                          detected_config={"dockerfile": True, "compose_file": None, "files": ["Dockerfile"]})
        db.add(repo)
        await db.commit()
        repo_id = str(repo.id)
    host = (await admin_client.post("/api/v1/hosts", json={"name": "h1", "hostname": "10.0.0.5", "username": "deploy"})).json()
    inst = (await admin_client.post("/api/v1/instances", json={
        "name": "app", "repository_id": repo_id, "host_id": host["id"], "branch": "main", "deploy": False,
    })).json()
    return inst["id"]


def _disabled(page: str, name: str) -> bool:
    tag = re.search(rf'<input[^>]*name="{name}"[^>]*>', page).group(0)
    return re.search(r"\sdisabled(\s|>|=)", tag) is not None


async def test_edit_form_locks_placement_once_deployed(admin_client):
    inst_id = await _instance(admin_client)
    page = (await admin_client.get(f"/instances/{inst_id}/edit")).text
    assert not _disabled(page, "dockerfile_path") and not _disabled(page, "host_id")
    async with get_sessionmaker()() as db:
        await db.execute(update(Instance).where(Instance.id == uuid.UUID(inst_id)).values(status=InstanceStatus.RUNNING))
        await db.commit()
    page = (await admin_client.get(f"/instances/{inst_id}/edit")).text
    for name in ("dockerfile_path", "build_context", "compose_file", "host_id", "build_source"):
        assert _disabled(page, name), name
    assert "fixed after the first deployment" in page


async def test_destroy_buttons_disabled_while_deploying(admin_client):
    inst_id = await _instance(admin_client)
    async with get_sessionmaker()() as db:
        await db.execute(update(Instance).where(Instance.id == uuid.UUID(inst_id)).values(status=InstanceStatus.DEPLOYING))
        await db.commit()
    page = (await admin_client.get(f"/instances/{inst_id}")).text
    buttons = re.findall(r'<button[^>]*data-api="DELETE /api/v1/instances/[^"]*"[^>]*>', page)
    assert len(buttons) == 2 and all(" disabled" in b for b in buttons)


async def test_list_pages_render_without_loading_build_logs(admin_client):
    inst_id = await _instance(admin_client)
    from slipway.models import Deployment

    async with get_sessionmaker()() as db:
        db.add(Deployment(instance_id=uuid.UUID(inst_id), status="succeeded", branch="main", commit_sha="a" * 40, log="x" * 1000))
        await db.commit()
    for url in ("/", "/deployments", "/deployments/history", f"/instances/{inst_id}", "/api/v1/deployments"):
        assert (await admin_client.get(url)).status_code == 200, url


# ---------------------------------------------------------- second review round follow-ups

from slipway import cli  # noqa: E402
from slipway.api.v1.instances import env_unreadable  # noqa: E402
from slipway.models.repository import DEFAULT_BRANCH_TOO_LONG  # noqa: E402
from tests.test_review_ops import K1, K2, _store_secrets  # noqa: E402


@pytest.fixture
def key_env():
    """Switch SLIPWAY_ENCRYPTION_KEY for one test, rebuilding the cached settings and keys."""
    import os

    from slipway.core.config import get_settings
    from slipway.core.crypto import reset_crypto_cache

    saved = os.environ.get("SLIPWAY_ENCRYPTION_KEY")

    def apply(key: str) -> None:
        os.environ["SLIPWAY_ENCRYPTION_KEY"] = key
        get_settings.cache_clear()
        reset_crypto_cache()

    yield apply
    if saved is None:
        os.environ.pop("SLIPWAY_ENCRYPTION_KEY", None)
    else:
        os.environ["SLIPWAY_ENCRYPTION_KEY"] = saved
    get_settings.cache_clear()
    reset_crypto_cache()


async def test_clearing_unreadable_env_keeps_the_deploy_guard(key_env):
    key_env(K1)
    await _store_secrets()
    key_env(K2)  # the old key is lost
    async with get_sessionmaker()() as db:
        await cli._rotate_secrets(db, clear_unreadable=True)
        await db.commit()
    async with get_sessionmaker()() as db:
        instance = await db.scalar(select(Instance))
        # Still flagged as needing re-entry (the deployer refuses), rather than silently empty.
        assert instance.env is None and await env_unreadable(db, instance)


async def test_new_instance_form_makes_you_pick_a_branch_when_the_default_is_unusable(admin_client):
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=9, full_name="acme/long", owner="acme", name="long", html_url="https://github.com/acme/long",
                          default_branch="main",
                          detected_config={"dockerfile": True, "compose_file": None, "files": ["Dockerfile"],
                                           DEFAULT_BRANCH_TOO_LONG: True})
        db.add(repo)
        await db.commit()
        repo_id = repo.id
    await admin_client.post("/api/v1/hosts", json={"name": "h1", "hostname": "10.0.0.5", "username": "deploy"})
    page = (await admin_client.get(f"/instances/new?repo={repo_id}")).text
    assert f'<option value="{repo_id}" data-default=""' in page
    branch = re.search(r'<select[^>]*id="branch-select".*?</select>', page, re.S).group(0)
    assert "required" in branch and "Choose a branch" in branch and ">main<" not in branch
