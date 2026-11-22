"""Regression tests for the final UI review batch: unreadable env, locked-form preview, permission-aware links,
grantable role choices and the admin GitHub unlink."""

from __future__ import annotations

import html
import json
import re
import uuid
from html.parser import HTMLParser

import pytest
from sqlalchemy import select, text, update

from slipway.core.config import get_settings
from slipway.core.crypto import reset_crypto_cache
from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Instance, InstanceStatus, OAuthAccount, User
from slipway.services.users import create_user
from tests.conftest import login, make_user
from tests.test_review_web import _add_repo, _client_with, _seed_world, run_js

# ------------------------------------------------------------------- helpers


class _Elements(HTMLParser):
    """Every start tag as (tag, attrs), attribute values unescaped."""

    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, {k: v or "" for k, v in attrs}))


def _elements(page: str) -> list[tuple[str, dict[str, str]]]:
    parser = _Elements()
    parser.feed(page)
    return parser.tags


def _dialog(page: str, dialog_id: str) -> str:
    start = page.index(f'<dialog class="modal" id="{dialog_id}"')
    return page[start: page.index("</dialog>", start)]


def _boxes(fragment: str, name: str) -> dict[str, dict[str, str]]:
    return {a["value"]: a for tag, a in _elements(fragment) if tag == "input" and a.get("name") == name}


def _checked(boxes: dict[str, dict[str, str]]) -> set[str]:
    return {v for v, a in boxes.items() if "checked" in a}


def _disabled(boxes: dict[str, dict[str, str]]) -> set[str]:
    return {v for v, a in boxes.items() if "disabled" in a}


async def _host(admin_client, name: str = "h1") -> str:
    return (await admin_client.post("/api/v1/hosts", json={"name": name, "hostname": "10.0.0.5", "username": "deploy"})).json()["id"]


async def _instance(admin_client, repo_id: str, host_id: str, name: str, **fields) -> str:
    r = await admin_client.post("/api/v1/instances", json={
        "name": name, "repository_id": repo_id, "host_id": host_id, "deploy": False, **fields})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _set_status(instance_id: str, status: InstanceStatus) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(update(Instance).where(Instance.id == uuid.UUID(instance_id)).values(status=status))
        await db.commit()


@pytest.fixture
def crypto_reset():
    yield
    reset_crypto_cache()  # forget the "cannot decrypt" log-once marker this test set


# --------------------------------------------- unreadable env is shown, not hidden (0)


ENV_WARNING = "Stored variables could not be decrypted"


async def test_unreadable_env_is_flagged_on_the_instance_pages(admin_client, crypto_reset):
    inst_id = await _instance(admin_client, await _add_repo(81, "web"), await _host(admin_client), "web",
                              env={"DATABASE_URL": "postgres://secret"})
    detail = (await admin_client.get(f"/instances/{inst_id}")).text
    edit = (await admin_client.get(f"/instances/{inst_id}/edit")).text
    assert "DATABASE_URL" in detail and "DATABASE_URL" in edit
    assert ENV_WARNING not in detail and ENV_WARNING not in edit and "clear_env" not in edit

    # The stored value can't be decrypted with the configured key (as after a wrong SLIPWAY_ENCRYPTION_KEY).
    async with get_sessionmaker()() as db:
        await db.execute(text("UPDATE instances SET env = 'not-a-fernet-token'"))
        await db.commit()

    detail = (await admin_client.get(f"/instances/{inst_id}")).text
    env_row = re.search(r"Environment</dt><dd>(.*?)</dd>", detail, re.S).group(1)
    assert ENV_WARNING in env_row and "SLIPWAY_ENCRYPTION_KEY" in env_row and "None" not in env_row
    assert f'href="/instances/{inst_id}/edit"' in env_row

    edit = (await admin_client.get(f"/instances/{inst_id}/edit")).text
    assert ENV_WARNING in edit and "Enter them again to replace them, or restore the key." in edit
    assert edit.index(ENV_WARNING) < edit.index('data-repeater="env"')  # right above the variables
    clear = [a for tag, a in _elements(edit) if tag == "button" and "data-body" in a]
    assert len(clear) == 1
    assert clear[0]["data-api"] == f"PATCH /api/v1/instances/{inst_id}"
    assert json.loads(clear[0]["data-body"]) == {"clear_env": True}
    assert clear[0]["type"] == "button" and clear[0]["data-confirm"] and clear[0]["data-then"] == "reload"
    assert re.search(r'<div class="repeater-row env">\s*<input class="input mono" data-k value=""', edit)  # room to re-enter

    # Never set at all is not "unreadable".
    async with get_sessionmaker()() as db:
        await db.execute(text("UPDATE instances SET env = NULL"))
        await db.commit()
    for page in (f"/instances/{inst_id}", f"/instances/{inst_id}/edit"):
        assert ENV_WARNING not in (await admin_client.get(page)).text, page


async def test_viewer_sees_the_unreadable_env_warning_without_edit_controls(admin_client, make_client, crypto_reset):
    inst_id = await _instance(admin_client, await _add_repo(82, "web"), await _host(admin_client), "web",
                              env={"SECRET": "x"})
    async with get_sessionmaker()() as db:
        await db.execute(text("UPDATE instances SET env = 'not-a-fernet-token'"))
        await db.commit()
    await make_user("viewer@example.com", roles=["viewer"])
    viewer = make_client()
    await login(viewer, "viewer@example.com")
    page = (await viewer.get(f"/instances/{inst_id}")).text
    assert ENV_WARNING in page and f"/instances/{inst_id}/edit" not in page


# ------------------------------------- the edit-page preview of a locked instance (8)


_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}


class _FormTree(HTMLParser):
    """The element tree of the page's <form data-preview-form>, as {tag, attrs, children}.

    <template> contents are left out, as a browser keeps them out of the document.
    """

    def __init__(self) -> None:
        super().__init__()
        self.root: dict | None = None
        self.stack: list[dict] = []
        self.template_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.template_depth:
            self.template_depth += tag == "template"
            return
        a = {k: v or "" for k, v in attrs}
        if not self.stack and (self.root is not None or tag != "form" or "data-preview-form" not in a):
            return
        node = {"tag": tag, "attrs": a, "children": []}
        if self.stack:
            self.stack[-1]["children"].append(node)
        else:
            self.root = node
        if tag == "template":
            self.template_depth = 1
        elif tag not in _VOID:
            self.stack.append(node)

    def handle_endtag(self, tag: str) -> None:
        if self.template_depth:
            self.template_depth -= tag == "template"
            return
        if tag in _VOID:
            return
        while self.stack and self.stack.pop()["tag"] != tag:
            pass

    def handle_data(self, data: str) -> None:
        if self.stack and not self.template_depth:
            self.stack[-1]["children"].append(data)


def _form_tree(page: str) -> dict:
    parser = _FormTree()
    parser.feed(page)
    assert parser.root is not None
    return parser.root


PREVIEW = """
var TREE = __TREE__;
function build(n) { return typeof n === "string" ? n : h(n.tag, n.attrs, n.children.map(build)); }
var form = build(TREE);
document.body.appendChild(form);
routes["GET /api/v1/repositories/__REPO__/branches"] = { status: 200, body: ["main"] };
document.dispatchEvent(new Event("DOMContentLoaded"));
await settle();
var preview = {};
document.querySelectorAll("[data-preview]").forEach(function (n) { preview[n.getAttribute("data-preview")] = n.textContent; });
done({ preview: preview, body: window.slipway.serialize(form) });
"""


async def _preview(admin_client, tmp_path, inst_id: str, repo_id: str) -> dict:
    page = (await admin_client.get(f"/instances/{inst_id}/edit")).text
    scenario = PREVIEW.replace("__TREE__", json.dumps(_form_tree(page))).replace("__REPO__", repo_id)
    return run_js(tmp_path, scenario)


async def test_js_preview_shows_the_build_settings_of_a_locked_instance(admin_client, tmp_path):
    compose_repo = await _add_repo(83, "web", detected_config={"dockerfile": False, "compose_file": "compose.yaml", "files": ["compose.yaml"]})
    docker_repo = await _add_repo(84, "api")
    host_id = await _host(admin_client)
    compose = await _instance(admin_client, compose_repo, host_id, "web", build_source="compose", compose_file="compose.yaml")
    docker = await _instance(admin_client, docker_repo, host_id, "api", dockerfile_path="docker/Dockerfile.prod",
                             ports=[{"host": 8080, "container": 80}])

    unlocked = await _preview(admin_client, tmp_path, compose, compose_repo)
    assert unlocked["preview"]["source"] == "docker compose (compose.yaml)"

    for inst_id in (compose, docker):
        await _set_status(inst_id, InstanceStatus.RUNNING)
    page = (await admin_client.get(f"/instances/{compose}/edit")).text
    assert re.search(r'<input type="radio" name="build_source" value="compose" checked\s+disabled', page)

    locked = await _preview(admin_client, tmp_path, compose, compose_repo)
    assert locked["preview"]["source"] == "docker compose (compose.yaml)"
    assert locked["preview"]["ports"] == locked["preview"]["volumes"] == "Defined by compose file"
    assert locked["preview"]["host"] == "h1 (10.0.0.5)"
    # The locked fields themselves still stay out of the PATCH body.
    assert not {"build_source", "compose_file", "dockerfile_path", "build_context", "host_id"} & set(locked["body"])
    assert locked["body"]["name"] == "web"

    locked = await _preview(admin_client, tmp_path, docker, docker_repo)
    assert locked["preview"]["source"] == "Dockerfile (docker/Dockerfile.prod)"
    assert locked["preview"]["ports"] == "8080 → 80 (TCP)"
    assert not {"build_source", "dockerfile_path"} & set(locked["body"])


# ------------------------------------------ no links to pages your roles can't open (9, 11)


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.targets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: v or "" for k, v in attrs}
        href = a.get("href", "")
        if tag == "a" and href.startswith("/") and not href.startswith(("/static/", "/api/", "/auth/")):
            self.targets.append(href)
        if a.get("data-then", "").startswith("redirect:"):
            self.targets.append(a["data-then"][len("redirect:"):])


async def _dead_links(c, ids: dict[str, str]) -> list[tuple[str, str]]:
    """(page, target) pairs where a page the user can open links (or redirects after a form) to a 403."""
    pages = [
        "/", "/search?q=payroll", "/repositories", f"/repositories?repo={ids['repo']}", "/hosts", f"/hosts/{ids['host']}",
        "/instances", "/instances/new", f"/instances/{ids['instance']}", f"/instances/{ids['instance']}/edit",
        "/deployments", "/deployments/history", f"/deployments/{ids['dep']}", "/settings", "/settings/tokens",
    ]
    status: dict[str, int] = {}
    dead = []
    for page in pages:
        r = await c.get(page)
        if r.status_code != 200:
            continue
        links = _Links()
        links.feed(r.text)
        for target in links.targets:
            target = target.replace("{id}", ids["dep"] if target.startswith("/deployments/") else ids["instance"])
            if target not in status:
                status[target] = (await c.get(target)).status_code
            if status[target] == 403:
                dead.append((page, target))
    return dead


async def test_pages_only_link_to_what_the_viewer_can_open(admin_client, make_client):
    ids = await _seed_world(admin_client)
    async with get_sessionmaker()() as db:
        ids["dep"] = str(await db.scalar(select(Deployment.id)))
    users = {}
    for role in ("viewer", "developer"):
        await make_user(f"{role}@example.com", roles=[role])
        users[role] = make_client()
        await login(users[role], f"{role}@example.com")
    for perms in (["deployments:read"], ["instances:read"], ["instances:write"], ["hosts:write"],
                  ["instances:read", "instances:write"], ["hosts:read", "hosts:write"],
                  ["instances:read", "deployments:create"]):
        email = "-".join(p.replace(":", "-") for p in perms) + "@example.com"
        users[email] = await _client_with(make_client, email, perms)

    dead = {who: found for who, c in users.items() if (found := await _dead_links(c, ids))}
    assert dead == {}

    # The links are still there for those who can follow them.
    page = (await users["instances-read-instances-write@example.com"].get("/")).text
    assert "Create your first instance" in page
    assert 'href="/hosts?add=1"' in (await users["hosts-read-hosts-write@example.com"].get("/")).text
    assert 'href="/hosts?add=1"' not in (await users["hosts-write@example.com"].get("/")).text
    assert "Create your first instance" not in (await users["viewer"].get("/")).text
    assert "Create your first instance" not in (await users["instances-write@example.com"].get("/")).text


async def test_instance_pages_hide_host_details_without_hosts_read(admin_client, make_client):
    ids = await _seed_world(admin_client)
    reader = await _client_with(make_client, "ireader@example.com", ["instances:read"])
    page = (await reader.get(f"/instances/{ids['instance']}")).text
    assert "/opt/slipway" not in page and "Path on host" not in page and f"/hosts/{ids['host']}" not in page
    assert "/opt/slipway" in (await admin_client.get(f"/instances/{ids['instance']}")).text

    writer = await _client_with(make_client, "iwriter@example.com", ["instances:write"])
    for path in (f"/instances/{ids['instance']}/edit", "/instances/new"):
        form = next(a for tag, a in _elements((await writer.get(path)).text) if tag == "form" and "data-preview-form" in a)
        assert form["data-then"] == "redirect:/", path
    form = next(a for tag, a in _elements((await admin_client.get(f"/instances/{ids['instance']}/edit")).text)
                if tag == "form" and "data-preview-form" in a)
    assert form["data-then"] == "redirect:/instances/{id}"


def _deploy_buttons(page: str) -> list[dict[str, str]]:
    return [a for tag, a in _elements(page) if tag == "button" and a.get("data-api", "").endswith("/deploy")]


async def test_deploy_buttons_open_the_deployment_only_for_deployments_read(admin_client, make_client):
    ids = await _seed_world(admin_client)
    pages = ("/instances", f"/instances/{ids['instance']}")

    # deployments:create alone may deploy, but /deployments/{id} would be a 403: stay and say it was queued.
    deployer = await _client_with(make_client, "deployer@example.com", ["instances:read", "deployments:create"])
    async with get_sessionmaker()() as db:
        dep_id = await db.scalar(select(Deployment.id))
    assert (await deployer.get(f"/deployments/{dep_id}")).status_code == 403
    for path in pages:
        buttons = _deploy_buttons((await deployer.get(path)).text)
        assert len(buttons) == 1, path
        assert buttons[0]["data-then"] == "reload" and buttons[0]["data-success"] == "Deployment queued", path
    r = await deployer.post(f"/api/v1/instances/{ids['instance']}/deploy")
    assert r.status_code != 403, r.text  # (400 here only because the host is unverified)

    watcher = await _client_with(make_client, "watcher@example.com",
                                 ["instances:read", "deployments:create", "deployments:read"])
    for client in (watcher, admin_client):
        for path in pages:
            buttons = _deploy_buttons((await client.get(path)).text)
            assert [b["data-then"] for b in buttons] == ["redirect:/deployments/{id}"], path
            assert "data-success" not in buttons[0], path


# --------------------------------------------- only grantable roles and permissions (10)


async def test_add_user_dialog_only_offers_roles_you_can_grant(admin_client, make_client, monkeypatch):
    mgr = await _client_with(make_client, "usermgr@example.com", ["users:read", "users:write", "hosts:read"])
    target = await make_user("target@example.com", roles=[])

    page = (await mgr.get("/settings/users")).text
    new = _boxes(_dialog(page, "new-user"), "roles")
    assert _checked(new) == set()  # viewer is not grantable, nor is the default role (viewer)
    assert _disabled(new) == {"admin", "maintainer", "developer", "viewer"}
    assert "Needs permissions you don't have." in _dialog(page, "new-user")

    body = {"email": "new@example.com", "password": "a-good-long-password",
            "roles": sorted(_checked(new) - _disabled(new))}
    r = await mgr.post("/api/v1/users", json=body)
    assert r.status_code == 201, r.text
    assert r.json()["roles"] == []

    # Falls back to the configured default role when the viewer can grant that.
    monkeypatch.setattr(get_settings(), "default_role", "usermgr")
    page = (await mgr.get("/settings/users")).text
    new = _boxes(_dialog(page, "new-user"), "roles")
    assert _checked(new) == {"usermgr"} and "usermgr" not in _disabled(new)
    r = await mgr.post("/api/v1/users", json={**body, "email": "new2@example.com", "roles": sorted(_checked(new))})
    assert r.status_code == 201 and r.json()["roles"] == ["usermgr"]

    # Edit dialogs: a box is never both checked and disabled (serialize() would drop it and strip the role).
    async with get_sessionmaker()() as db:
        me = await db.scalar(select(User).where(User.email == "usermgr@example.com"))
    own = _boxes(_dialog(page, f"edit-{me.id}"), "roles")
    assert _checked(own) == {"usermgr"} and not _checked(own) & _disabled(own)
    other = _boxes(_dialog(page, f"edit-{target.id}"), "roles")
    assert _checked(other) == set() and "viewer" in _disabled(other)

    admin_page = (await admin_client.get("/settings/users")).text
    new = _boxes(_dialog(admin_page, "new-user"), "roles")
    assert _checked(new) == {"viewer"} and _disabled(new) == set()


async def test_role_editor_disables_only_unchecked_permissions_you_cannot_grant(admin_client, make_client):
    ops = (await admin_client.post("/api/v1/roles", json={
        "name": "ops", "description": "Ops", "permissions": ["hosts:*", "instances:read"]})).json()
    editor = await _client_with(make_client, "roleeditor@example.com",
                                ["roles:read", "roles:write", "hosts:read", "hosts:write", "instances:read"])
    page = (await editor.get("/settings/roles")).text

    new = _boxes(_dialog(page, "new-role"), "permissions")
    assert {"*", "hosts:*", "users:write", "roles:*"} <= _disabled(new)
    assert not {"hosts:read", "hosts:write", "instances:read", "roles:write"} & _disabled(new)

    edit = _boxes(_dialog(page, f"edit-role-{ops['id']}"), "permissions")
    assert _checked(edit) == {"hosts:*", "instances:read"}
    assert "hosts:*" not in _disabled(edit)  # held by the role but not the editor: stays editable so saves keep it
    assert "users:write" in _disabled(edit) and not _checked(edit) & _disabled(edit)

    admin_page = (await admin_client.get("/settings/roles")).text
    assert _disabled(_boxes(_dialog(admin_page, "new-role"), "permissions")) == set()


# ---------------------------------------------- admin reset text and GitHub unlink (12)


async def test_users_page_offers_to_unlink_github(admin_client):
    linked = await make_user("linked@example.com", roles=["viewer"])
    async with get_sessionmaker()() as db:
        gh_only = await create_user(db, email="ghonly@example.com", password=None, full_name="GH", role_names=["viewer"])
        db.add_all([
            OAuthAccount(user_id=linked.id, provider="github", provider_user_id="101", login="mona"),
            OAuthAccount(user_id=gh_only.id, provider="github", provider_user_id="102", login="hubot"),
        ])
        await db.commit()
        admin = await db.scalar(select(User).where(User.email == "admin@example.com"))
    plain = await make_user("plain@example.com", roles=["viewer"])

    page = (await admin_client.get("/settings/users")).text
    dialog = _dialog(page, f"edit-{linked.id}")
    assert "(optional; also signs them out, deletes their API tokens and unlinks GitHub)" in dialog
    unlink = [a for tag, a in _elements(dialog) if tag == "button" and a.get("data-api", "").endswith("/github")]
    assert len(unlink) == 1
    assert unlink[0]["data-api"] == f"DELETE /api/v1/users/{linked.id}/github"
    assert unlink[0]["type"] == "button" and unlink[0]["data-then"] == "reload"
    assert "@mona" in unlink[0]["data-confirm"] and "no password" not in unlink[0]["data-confirm"]

    # Unlinking a user with no password would lock them out, so the API refuses it: offer the reset instead.
    gh_dialog = _dialog(page, f"edit-{gh_only.id}")
    assert "Signs in with GitHub as <strong>@hubot</strong>" in gh_dialog and "/github" not in gh_dialog
    assert "Has no password: Reset password sets one and also unlinks GitHub." in gh_dialog
    assert "Has no password" not in dialog

    # What deactivating does, and that a user without a password needs one before they can sign in again.
    active = "Deactivated users are signed out, lose their API tokens and GitHub link, and cannot sign in."
    no_password = "They have no password, so reactivating them later needs one: type it under Reset password in the same save."
    assert f"{active}</span>" in dialog and no_password not in dialog
    assert f"{active} {no_password}</span>" in gh_dialog

    assert "/github" not in _dialog(page, f"edit-{plain.id}")
    assert "/github" not in _dialog(page, f"edit-{admin.id}")  # your own link is managed from Profile

    # After a GitHub-only user was deactivated (which unlinks GitHub), nothing is left to sign in with.
    async with get_sessionmaker()() as db:
        await db.execute(text("DELETE FROM oauth_accounts WHERE login = 'hubot'"))
        await db.execute(update(User).where(User.id == gh_only.id).values(is_active=False))
        await db.commit()
    page = (await admin_client.get("/settings/users")).text
    row = re.search(r"ghonly@example\.com</small>.*?</tr>", page, re.S).group(0)
    assert '<span class="subtle">none</span>' in row.split("<td")[2]  # the Sign-in column
    assert (f"{active} They have no password or GitHub link, so they cannot sign in until you set one with Reset password."
            in _dialog(page, f"edit-{gh_only.id}"))


# --------------------------------------------------------------- data safety in slipway.js (spec §15.6)

BACKUPS_JSON = {
    "backups": [
        {"id": "b1", "name": "20261115T101500Z-1a2b3c4d", "reason": "pre_deploy", "status": "ready",
         "taken_at": "2026-11-15T10:15:00+00:00", "db_bytes": 412 * 1024 * 1024, "has_files": True,
         "files_bytes": 3 * 1024 ** 3, "format": "pg-custom", "revision_short": "0042_orders", "commit_sha": "abcdef1234567",
         "release": "r", "deployment_id": "d1", "dirty_of": None, "created_by": None, "note": None,
         "checked_at": "2026-11-15T10:20:00+00:00", "pinned": True,
         "pinned_reason": "it is the roll back point of failed deployment 9f8e7d6c", "restorable": True,
         "reason_text": None, "identity_note": None, "needs_reset_perm": False, "dirty_note": None},
        {"id": "b2", "name": "20261114T101500Z-2b3c4d5e", "reason": "manual", "status": "missing",
         "taken_at": "2026-11-14T10:15:00+00:00", "db_bytes": 10, "has_files": False, "files_bytes": None,
         "format": "pg-custom", "revision_short": None, "commit_sha": None, "release": None, "deployment_id": None,
         "dirty_of": "x", "created_by": "Ada", "note": "before <script>", "checked_at": None, "pinned": False,
         "pinned_reason": None, "restorable": False, "reason_text": "Not on prod-01 any more (checked never)",
         "identity_note": None, "needs_reset_perm": False,
         "dirty_note": "Holds data changed by failed deployment 9f8e7d6c (abc1234)"},
        {"id": "b3", "name": "20261113T101500Z-3c4d5e6f", "reason": "pre_restore", "status": "ready",
         "taken_at": "2026-11-13T10:15:00+00:00", "db_bytes": 2048, "has_files": False, "files_bytes": None,
         "format": "pg-custom", "revision_short": "0041", "commit_sha": "1111111aaaa", "release": None,
         "deployment_id": None, "dirty_of": None, "created_by": None, "note": None, "checked_at": None, "pinned": False,
         "pinned_reason": None, "restorable": True, "reason_text": None,
         "identity_note": "Restoring it also puts back the field encryption key it was made with (FIELD_ENCRYPTION_KEY).",
         "needs_reset_perm": True, "dirty_note": None},
    ],
    "keep": 5, "manual_max": 10, "folder": "/srv/shop/backups", "other_files": 2, "ram_backed": False,
    "data_elsewhere": None, "warning": "A job is running for shop; showing what Slipway recorded",
}

BACKUPS_SCENARIO = """
var el = h("div", { "data-load": "/api/v1/instances/abc/backups?check=true", "data-render": "backups",
  "data-instance": "abc", "data-host": "prod-01", "data-files-label": "Uploads", "data-identity-label": "field encryption key",
  "data-empty": "No backups yet.", "data-job-shas": '{"d1": "fedcba9"}', "data-revision-check": "", "data-has-files-cap": "",
  "data-can-restore": "" __EXTRA__ });
var html = "";
Object.defineProperty(el, "innerHTML", { get: function () { return html; }, set: function (v) { html = v; } });
document.body.appendChild(el);
routes["GET /api/v1/instances/abc/backups"] = { status: 200, body: __BODY__ };
document.dispatchEvent(new Event("DOMContentLoaded"));
await settle();
done({ html: html, calls: fetchCalls });
"""


def _backups_html(tmp_path, body, extra: str = "") -> str:
    scenario = BACKUPS_SCENARIO.replace("__BODY__", json.dumps(body)).replace("__EXTRA__", extra)
    result = run_js(tmp_path, scenario)
    assert result["calls"] == ["GET /api/v1/instances/abc/backups?check=true"]
    return result["html"]


def test_js_backups_renderer_builds_the_card_from_the_api(tmp_path):
    import html as html_lib

    out = _backups_html(tmp_path, BACKUPS_JSON)
    text = html_lib.unescape(out)
    assert "A job is running for shop; showing what Slipway recorded" in text  # the warning callout
    assert "Before deploy fedcba9" in text and "Back up now · Ada" in text and "Before restore" in text
    assert "Roll back point" in text and "with files" in text and "after failed deployment 9f8e7d6c" in text
    assert "412 MiB + 3 GiB uploads" in text and "2 KiB" in text
    assert "2026-11-15 10:15 UTC" in text and "abcdef1 · 0042_orders" in text
    assert ">On host<" in text and ">Missing<" in text and ">Not checked<" in text
    assert "Not on prod-01 any more (checked never)" in text  # instead of a Restore button
    assert "&lt;script&gt;" in out and "<script>" not in out  # notes are escaped
    # Without data:reset: the backup with other keys shows why, and nothing can be deleted.
    assert "Restoring it puts back old field encryption key; that needs data:reset" in text
    assert "Delete</button>" not in out and "Forget</button>" not in out
    assert "2 other files in backups/ weren't made by Slipway and aren't listed." in text
    assert "also hold the uploads" in text
    fills = [json.loads(html_lib.unescape(m)) for m in re.findall(r'data-fill="([^"]*)"', out)]
    assert [f["backup_id"] for f in fills] == ["b1"]
    assert fills[0]["has_files"] is True and fills[0]["release"] == "abcdef1" and fills[0]["no_revision_check"] is False

    out = html_lib.unescape(_backups_html(tmp_path, BACKUPS_JSON, ', "data-can-reset": "", "data-busy": ""'))
    assert ">Forget</button>" in out and out.count(">Delete</button>") == 2
    assert 'disabled title="This backup is pinned: it is the roll back point' in out
    # While a job runs, Restore is off.
    assert re.search(r'data-open="restore-backup"[^>]*disabled title="A job is running', out)

    empty = _backups_html(tmp_path, {"backups": [], "other_files": 0})
    assert "No backups yet." in empty and "<table" not in empty


DIALOG_SCENARIO = """
var input = h("input", { name: "confirm", "data-must-equal": "shop" });
var submit = h("button", { type: "submit", disabled: "" });
var files = h("input", { type: "checkbox", name: "files" });
var tick = h("label", { "data-show-if": "needs_identity" }, [h("input", { type: "checkbox", name: "restore_identity", required: "" })]);
var form = h("form", { "data-form": "POST /api/v1/instances/abc/data/restore", "data-then": "redirect:/deployments/{id}" }, [
  h("input", { type: "hidden", name: "backup_id" }), h("span", { "data-slot": "name" }),
  h("label", { "data-show-if": "has_files" }, [files]), tick, input, submit]);
var dlg = h("dialog", { id: "restore-backup" }, [form]);
var opener = h("button", { "data-open": "restore-backup",
  "data-fill": JSON.stringify({ backup_id: "b1", name: "20261115T101500Z-1a2b3c4d", has_files: true, files: true, needs_identity: false }) });
document.body.appendChild(dlg); document.body.appendChild(opener);
document.dispatchEvent(new Event("DOMContentLoaded"));
input.value = "left over";
user("click", opener);
var opened = { open: "open" in dlg.attrs, disabled: submit.disabled, name: form.querySelector("[data-slot=name]").textContent,
  files: files.checked, tickHidden: tick.hidden, confirm: input.value };
input.value = "Shop"; user("input", input);
var wrongCase = submit.disabled;
input.value = "shop"; user("input", input);
var exact = submit.disabled;
routes["POST /api/v1/instances/abc/data/restore"] = { status: 202, body: { id: "dep1" } };
user("submit", form, { submitter: submit });
await settle();
done({ opened: opened, wrongCase: wrongCase, exact: exact, body: fetchBodies[0], hrefs: hrefs });
"""


def test_js_dialog_fill_and_the_typed_name(tmp_path):
    result = run_js(tmp_path, DIALOG_SCENARIO)
    assert result["opened"] == {"open": True, "disabled": True, "name": "20261115T101500Z-1a2b3c4d", "files": True,
                                "tickHidden": True, "confirm": ""}
    assert result["wrongCase"] is True and result["exact"] is False
    # The hidden identity tick isn't sent; the rest is.
    assert result["body"] == {"backup_id": "b1", "files": True, "confirm": "shop"}
    assert result["hrefs"] == ["http://slipway.test/deployments/dep1"]


SERIALIZE_SCENARIO = """
var form = h("form", {}, [
  h("input", { type: "radio", name: "start_from", value: "empty", "data-no-send": "", checked: "" }),
  h("div", { "data-optional-group": "first_admin" }, [
    h("input", { name: "first_admin.fields.email", type: "email", value: "__EMAIL__" }),
    h("input", { name: "first_admin.fields.username", value: "__USER__" }),
    h("input", { type: "hidden", name: "first_admin.mode", value: "password" }),
    h("input", { name: "first_admin.password", type: "password", value: "" }),
  ]),
  h("input", { name: "confirm", value: "shop" }),
]);
document.body.appendChild(form);
done({ body: window.slipway.serialize(form) });
"""


def test_js_serialize_nests_dotted_names_and_leaves_out_empty_optional_groups(tmp_path):
    filled = run_js(tmp_path, SERIALIZE_SCENARIO.replace("__EMAIL__", "ada@example.com").replace("__USER__", "ada"))
    assert filled["body"] == {"first_admin": {"fields": {"email": "ada@example.com", "username": "ada"}, "mode": "password"},
                              "confirm": "shop"}
    empty = run_js(tmp_path, SERIALIZE_SCENARIO.replace("__EMAIL__", "").replace("__USER__", ""))
    assert empty["body"] == {"confirm": "shop"}


THEN_SCENARIO = """
location.assign = function (u) { hrefs.push("ASSIGN " + u); };
var form = h("form", { "data-form": "POST /api/v1/instances/abc/snapshots", "data-then": "redirect:/deployments/{deployment.id}" }, [
  h("input", { name: "name", value: "shop-1" }), h("button", { type: "submit" })]);
var dl = h("form", { "data-form": "POST /api/v1/snapshots/s1/exports", "data-then": "download" }, [
  h("input", { name: "passphrase", value: "x" }), h("button", { type: "submit" })]);
document.body.appendChild(form); document.body.appendChild(dl);
routes["POST /api/v1/instances/abc/snapshots"] = { status: 202, body: { snapshot: { id: "s1" }, deployment: { id: "d9" } } };
routes["POST /api/v1/snapshots/s1/exports"] = { status: 201, body: { url: "/api/v1/snapshot-exports/tok", bytes: 3 * 1024 * 1024 * 1024 } };
user("submit", form, { submitter: form.querySelector("button") });
await settle();
user("submit", dl, { submitter: dl.querySelector("button") });
await settle();
var s = window.slipway.statusBadge;
done({ hrefs: hrefs, toasts: toasts(), badges: [s("running", "restore"), s("running", "deploy"), s("running"),
  s("succeeded", "backup"), s("succeeded", "deploy"), s("failed", "reset")], sizes: [window.slipway.humanBytes(812 * 1024 * 1024),
  window.slipway.humanBytes(1.9 * 1024 * 1024 * 1024), window.slipway.humanBytes(512)] });
"""


def test_js_then_redirects_by_nested_ids_and_downloads(tmp_path):
    result = run_js(tmp_path, THEN_SCENARIO)
    assert result["hrefs"] == ["http://slipway.test/deployments/d9", "ASSIGN http://slipway.test/api/v1/snapshot-exports/tok"]
    assert "toast success|Download started (3 GiB)" in result["toasts"]
    assert result["badges"] == [["Restoring", "warning spin"], ["Building", "warning spin"], ["Building", "warning spin"],
                                ["Done", "success"], ["Deployed", "success"], ["Failed", "error"]]
    assert result["sizes"] == ["812 MiB", "1.9 GiB", "512 bytes"]


PASSPHRASE_SCENARIO = """
var a = h("input", { id: "pa", name: "passphrase" }), b = h("input", { id: "pb" });
var copy = h("button", { "data-passphrase-copy": "", hidden: "" });
var gen = h("button", { "data-generate-passphrase": "#pa, #pb" });
var form = h("form", {}, [a, b, gen, copy]);
document.body.appendChild(form);
user("click", gen);
var first = a.value;
user("click", gen);
done({ a: a.value, b: b.value, first: first, copyHidden: copy.hidden });
"""


def test_js_generated_passphrases_are_24_base32_characters_in_groups(tmp_path):
    result = run_js(tmp_path, PASSPHRASE_SCENARIO)
    assert re.fullmatch(r"([A-Z2-7]{4}-){5}[A-Z2-7]{4}", result["a"]) and result["a"] == result["b"]
    assert result["first"] != result["a"] and result["copyHidden"] is False


APP_FORM = """
var TREE = __TREE__;
function build(n) { return typeof n === "string" ? n : h(n.tag, n.attrs, n.children.map(build)); }
var form = build(TREE);
document.body.appendChild(form);
routes["GET /api/v1/repositories/__REPO__/branches"] = { status: 200, body: ["main"] };
routes["GET /api/v1/repositories/__REPO__/manifest"] = { status: 200, body: { manifest: __MANIFEST__ } };
document.dispatchEvent(new Event("DOMContentLoaded"));
await settle();
var fs = form.querySelector("[data-app-data]");
done({ hidden: fs.hidden, start: form.querySelector("[data-app-start]").hidden, seed: form.querySelector("[data-app-seed]").hidden,
       admin: form.querySelector("[data-app-admin]").hidden, body: window.slipway.serialize(form) });
"""


async def test_js_instance_form_shows_the_data_fieldset_for_a_manifest_with_data(admin_client, tmp_path):
    from tests.test_data_api import MANIFEST

    repo_id = await _add_repo(91, "shop", detected_config={"manifest": True, "files": ["slipway.yml"]})
    await _host(admin_client)
    page = (await admin_client.get(f"/instances/new?repo={repo_id}")).text
    tree = json.dumps(_form_tree(page))
    plain = {**MANIFEST, "capabilities": [], "data": {**MANIFEST["data"], "volumes": []}, "first_admin": None}
    for man, shown in ((MANIFEST, True), (plain, False)):
        scenario = APP_FORM.replace("__TREE__", tree).replace("__REPO__", repo_id).replace("__MANIFEST__", json.dumps(man))
        result = run_js(tmp_path, scenario)
        assert result["hidden"] is (not shown), result
        if shown:
            # A new instance may start from a snapshot (seed), gets a first admin and starter content.
            assert result["start"] is False and result["seed"] is False and result["admin"] is False
            assert result["body"]["keep_backups"] == 5 and result["body"]["seed_content"] is True
            assert "seed_snapshot_id" not in result["body"] and "seed_from" not in result["body"]
        else:
            assert "keep_backups" not in result["body"] and "seed_content" not in result["body"]


# The Data fieldset's seed choice (§10.7, §15.4): an edit sends seed_snapshot_id only when the user changes it,
# and "A snapshot" is offered only when one is usable (a select of disabled options has no value).
SEED_FORM = """
var TREE = __TREE__;
function build(n) { return typeof n === "string" ? n : h(n.tag, n.attrs, n.children.map(build)); }
var form = build(TREE);
document.body.appendChild(form);
routes["GET /api/v1/repositories/__REPO__/branches"] = { status: 200, body: ["main"] };
routes["GET /api/v1/repositories/__REPO__/manifest"] = { status: 200, body: { manifest: __MANIFEST__ } };
document.dispatchEvent(new Event("DOMContentLoaded"));
await settle();
var fs = form.querySelector("[data-app-data]");
var radio = function (v) { return fs.querySelector('[name="seed_from"][value="' + v + '"]'); };
var select = fs.querySelector("[data-app-snapshot]");
var before = { body: window.slipway.serialize(form), snapshotOff: radio("snapshot").disabled,
  emptyOff: radio("empty").disabled,
  snapshotOn: radio("snapshot").checked, options: select.querySelectorAll("option").map(function (o) { return o.textContent; }),
  value: select.value };
if (__PICK_EMPTY__) {
  radio("snapshot").checked = false; radio("empty").checked = true; user("change", radio("empty"));
}
done({ before: before, body: window.slipway.serialize(form) });
"""


def _seed_form(page: str, repo_id: str, pick_empty: bool = False) -> str:
    from tests.test_data_api import MANIFEST

    return (SEED_FORM.replace("__TREE__", json.dumps(_form_tree(page))).replace("__REPO__", repo_id)
            .replace("__MANIFEST__", json.dumps(MANIFEST)).replace("__PICK_EMPTY__", "true" if pick_empty else "false"))


async def test_js_editing_a_seeded_instance_sends_the_seed_only_when_it_changes(make_client, monkeypatch, tmp_path):
    from slipway.models import Host, Repository
    from tests.test_data_api import ADMIN, SHOP_YML, client_with, clients, github_serving, ready_snapshot, seed

    c = await clients(make_client)
    github_serving(monkeypatch, {"slipway.yml": SHOP_YML})
    await seed()
    async with get_sessionmaker()() as db:
        host = await db.scalar(select(Host))
        repo = await db.scalar(select(Repository))
    sid = await ready_snapshot(c["admin"], "uat-1")
    body = {"name": "UAT two", "repository_id": str(repo.id), "host_id": str(host.id), "build_source": "app",
            "deploy": False, "seed_snapshot_id": str(sid), "first_admin": ADMIN, "keep_backups": 7}
    r = await c["maintainer"].post("/api/v1/instances", json=body)
    assert r.status_code == 201, r.text
    iid = r.json()["id"]

    # A writer without data:reset sees the saved snapshot (read-only) and can still save the instance.
    writer = await client_with(make_client, "writer@example.com", ["instances:read", "instances:write", "repos:read", "hosts:read"])
    page = (await writer.get(f"/instances/{iid}/edit")).text
    result = run_js(tmp_path, _seed_form(page, str(repo.id)))
    assert result["before"]["snapshotOn"] is True and result["before"]["snapshotOff"] is True
    assert result["before"]["value"] == str(sid) and result["before"]["options"][0].startswith("uat-1")
    assert "seed_snapshot_id" not in result["body"] and result["body"]["keep_backups"] == 7
    # Empty can't be picked either: the PATCH would leave the seed as it is (fixcheck F).
    assert result["before"]["emptyOff"] is True
    assert "Changing what it starts with needs the data:reset permission" in page
    # Without data:read the saved seed is listed by its name only (no repository, source or keys).
    [listed] = json.loads(html.unescape(re.search(r"data-snapshots='([^']*)'", page).group(1)))
    assert listed == {"id": str(sid), "name": "uat-1", "app": listed["app"], "status": "ready", "brief": True}
    r = await writer.patch(f"/api/v1/instances/{iid}", json=result["body"])
    assert r.status_code == 200, r.text
    assert r.json()["seed_snapshot"]["name"] == "uat-1"

    # A maintainer's untouched save keeps it too; choosing Empty clears it.
    page = (await c["maintainer"].get(f"/instances/{iid}/edit")).text
    untouched = run_js(tmp_path, _seed_form(page, str(repo.id)))
    assert "seed_snapshot_id" not in untouched["body"] and untouched["before"]["emptyOff"] is False
    cleared = run_js(tmp_path, _seed_form(page, str(repo.id), pick_empty=True))
    assert cleared["body"]["seed_snapshot_id"] is None


async def test_js_a_snapshot_is_offered_only_when_one_is_usable(make_client, monkeypatch, tmp_path):
    from slipway.models import Repository
    from tests.test_data_api import clients, ready_snapshot, seed

    c = await clients(make_client)
    await seed()
    async with get_sessionmaker()() as db:
        repo = await db.scalar(select(Repository))
        repo.detected_config = {"manifest": True, "files": ["slipway.yml"]}  # the form opens in app mode
        await db.commit()
    await ready_snapshot(c["admin"], "fork-1", repository="acme/fork")
    await ready_snapshot(c["admin"], "unknown-1", repository=None)
    # The maintainer has data:reset but not snapshots:download: both snapshots are listed, disabled.
    page = (await c["maintainer"].get(f"/instances/new?repo={repo.id}")).text
    result = run_js(tmp_path, _seed_form(page, str(repo.id)))
    assert len(result["before"]["options"]) == 2 and result["before"]["value"] == ""
    assert result["before"]["snapshotOff"] is True and "seed_snapshot_id" not in result["body"]
    # The admin may download, so the same snapshots are usable.
    page = (await c["admin"].get(f"/instances/new?repo={repo.id}")).text
    result = run_js(tmp_path, _seed_form(page, str(repo.id)))
    assert result["before"]["snapshotOff"] is False
