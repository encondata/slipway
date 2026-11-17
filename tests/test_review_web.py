"""Regression tests for the web-UI review findings (permissions on pages, OAuth errors, forms, slipway.js)."""

from __future__ import annotations

import html
import json
import os
import re
import shutil
import subprocess
import uuid
from html.parser import HTMLParser
from pathlib import Path

import pytest
from sqlalchemy import select

from slipway.core.config import get_settings
from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Repository, Role
from slipway.services import ssh
from tests.conftest import login, make_user

SLIPWAY_JS = Path(__file__).parent.parent / "slipway" / "web" / "static" / "js" / "slipway.js"
JSC = Path("/System/Library/Frameworks/JavaScriptCore.framework/Versions/Current/Helpers/jsc")


# ------------------------------------------------------------------- helpers


async def _add_repo(github_id: int, name: str, **fields) -> str:
    fields.setdefault("detected_config", {"dockerfile": True, "compose_file": None, "files": ["Dockerfile"]})
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=github_id, full_name=f"acme/{name}", owner="acme", name=name,
                          html_url=f"https://github.com/acme/{name}", **fields)
        db.add(repo)
        await db.commit()
        return str(repo.id)


async def _add_role(name: str, permissions: list[str]) -> None:
    async with get_sessionmaker()() as db:
        db.add(Role(name=name, description="", permissions=permissions, is_system=False))
        await db.commit()


async def _client_with(make_client, email: str, permissions: list[str]):
    await _add_role(email.split("@")[0], permissions)
    await make_user(email, roles=[email.split("@")[0]])
    c = make_client()
    await login(c, email)
    return c


SECRETS = ["prod-secret-01", "10.9.8.7", "secret-payroll", "payroll-internal", "release-x", "deadbee", "Rotate payroll DB creds"]


async def _seed_world(admin_client) -> dict[str, str]:
    """A private repo, a host, an instance on it and a finished deployment."""
    repo_id = await _add_repo(41, "secret-payroll", visibility="private")
    host = (await admin_client.post("/api/v1/hosts", json={
        "name": "prod-secret-01", "hostname": "10.9.8.7", "port": 2222, "username": "deploy"})).json()
    inst = (await admin_client.post("/api/v1/instances", json={
        "name": "payroll-internal", "repository_id": repo_id, "host_id": host["id"], "branch": "release-x", "deploy": False,
    })).json()
    async with get_sessionmaker()() as db:
        db.add(Deployment(instance_id=uuid.UUID(inst["id"]), status="succeeded", branch="release-x",
                          commit_sha="deadbeefcafe1234", commit_message="Rotate payroll DB creds"))
        await db.commit()
    return {"repo": repo_id, "host": host["id"], "instance": inst["id"]}


class _Forms(HTMLParser):
    """Collects <form> attributes, and the <input>s inside one <dialog id=...>."""

    def __init__(self, dialog_id: str = "") -> None:
        super().__init__()
        self.dialog_id, self.inside, self.forms, self.inputs, self.dialog_form = dialog_id, False, [], [], {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "form":
            self.forms.append(a)
            if self.inside:
                self.dialog_form = a
        elif tag == "dialog" and a.get("id") == self.dialog_id:
            self.inside = True
        elif tag == "input" and self.inside:
            self.inputs.append(a)

    def handle_endtag(self, tag: str) -> None:
        if tag == "dialog":
            self.inside = False


def _parse(page: str, dialog_id: str = "") -> _Forms:
    parser = _Forms(dialog_id)
    parser.feed(page)
    return parser


def _serialize(inputs: list[dict]) -> dict:
    """What slipway.js serialize() sends for these inputs (checkbox arrays and plain text fields)."""
    out: dict = {}
    for a in inputs:
        if "data-array" in a:
            out.setdefault(a["name"], [])
            if "checked" in a:
                out[a["name"]].append(a["value"])
        elif a.get("value") or "data-keep-empty" in a:
            out[a["name"]] = a.get("value") or ""
    return out


# ------------------------------------------- pages only show what the viewer may read


async def test_overview_shows_nothing_without_read_permissions(admin_client, make_client):
    await _seed_world(admin_client)
    for email, perms in [("analyst@example.com", ["analytics:read"]), ("auditor@example.com", ["audit:read"])]:
        c = await _client_with(make_client, email, perms)
        assert (await c.get("/hosts")).status_code == 403
        r = await c.get("/")
        assert r.status_code == 200
        leaked = [s for s in SECRETS if s in r.text]
        assert not leaked, f"{email} sees {leaked}"
        assert "No hosts yet" not in r.text and "No repositories yet" not in r.text

    await make_user("viewer@example.com", roles=["viewer"])
    viewer = make_client()
    await login(viewer, "viewer@example.com")
    page = (await viewer.get("/")).text
    assert all(s in page for s in SECRETS)


async def test_overview_deployments_without_hosts_read_hide_host_names(admin_client, make_client):
    await _seed_world(admin_client)
    c = await _client_with(make_client, "deps@example.com", ["deployments:read"])
    dep_id = (await c.get("/api/v1/deployments")).json()[0]["id"]
    for path in ("/", "/deployments", "/deployments/history", f"/deployments/{dep_id}"):
        page = (await c.get(path)).text
        assert "payroll-internal" in page and "release-x" in page, path
        assert "prod-secret-01" not in page and "secret-payroll" not in page, path


async def test_repositories_page_needs_instances_read_for_instances(admin_client, make_client):
    ids = await _seed_world(admin_client)
    repo_only = await _client_with(make_client, "repos@example.com", ["repos:read"])
    page = (await repo_only.get(f"/repositories?repo={ids['repo']}")).text
    assert "secret-payroll" in page
    assert not [s for s in ("payroll-internal", "release-x", "prod-secret-01") if s in page]
    assert "Last Deploy" not in page and "No instances" not in page
    assert (await repo_only.get("/repositories?show=deployed")).status_code == 200

    with_instances = await _client_with(make_client, "repoinst@example.com", ["repos:read", "instances:read"])
    page = (await with_instances.get(f"/repositories?repo={ids['repo']}")).text
    assert "payroll-internal" in page and "release-x" in page
    assert "prod-secret-01" not in page


async def test_host_pages_need_instances_read_for_instances(admin_client, make_client):
    ids = await _seed_world(admin_client)
    host_only = await _client_with(make_client, "hostsonly@example.com", ["hosts:read"])
    page = (await host_only.get(f"/hosts/{ids['host']}")).text
    assert "prod-secret-01" in page
    assert not [s for s in ("payroll-internal", "secret-payroll", "release-x") if s in page]
    assert "<th>Instances</th>" not in (await host_only.get("/hosts")).text

    with_instances = await _client_with(make_client, "hostinst@example.com", ["hosts:read", "instances:read"])
    page = (await with_instances.get(f"/hosts/{ids['host']}")).text
    assert "payroll-internal" in page and "release-x" in page
    assert "secret-payroll" not in page


# ------------------------------------------------------------- role editor


async def test_role_editor_keeps_wildcards_and_unknown_permissions(admin_client):
    stored = ["deployments:*", "hosts:read", "instances:*"]
    role = (await admin_client.post("/api/v1/roles", json={"name": "ops", "description": "Ops", "permissions": stored})).json()
    assert role["permissions"] == stored
    await _add_role("superops", ["*"])
    await _add_role("legacy", ["instances:read", "legacy:thing"])
    page = (await admin_client.get("/settings/roles")).text
    async with get_sessionmaker()() as db:
        roles = {r.name: r.id for r in (await db.scalars(select(Role))).all()}

    body = _serialize(_parse(page, f"edit-role-{role['id']}").inputs)
    assert sorted(body["permissions"]) == stored
    body["description"] = "Operations"
    saved = (await admin_client.patch(f"/api/v1/roles/{role['id']}", json=body)).json()
    assert saved["permissions"] == stored and saved["description"] == "Operations"

    assert _serialize(_parse(page, f"edit-role-{roles['superops']}").inputs)["permissions"] == ["*"]
    legacy = _serialize(_parse(page, f"edit-role-{roles['legacy']}").inputs)["permissions"]
    assert sorted(legacy) == ["instances:read", "legacy:thing"]

    offered = {a["value"] for a in _parse(page, "new-role").inputs if a.get("name") == "permissions"}
    assert {"*", "hosts:*", "instances:*", "users:read"} <= offered


# ------------------------------------------------------------ OAuth errors


PHISH = "Slipway moved. Sign in at https://slipway-corp.example.net"


async def test_login_error_only_shows_fixed_messages(client):
    page = (await client.get("/login", params={"error": PHISH})).text
    assert "slipway-corp.example.net" not in page and "Sign-in failed. Please try again." in page
    page = (await client.get("/login", params={"error": "not_allowed", "login": "octo-cat"})).text
    assert "@octo-cat is not allowed to sign in to Slipway" in page
    for bad in ("evil.example/phish", "octocat\n", "x" * 40, "<b>x</b>"):
        page = (await client.get("/login", params={"error": "not_allowed", "login": bad})).text
        assert "This GitHub account is not allowed to sign in" in page and "evil.example" not in page and "<b>x" not in page
    assert "expired or was tampered with" in (await client.get("/login?error=state")).text
    assert "callout error" not in (await client.get("/login")).text


async def test_settings_error_only_shows_fixed_messages(admin_client):
    page = (await admin_client.get("/settings", params={"error": PHISH})).text
    assert "slipway-corp.example.net" not in page and "Sign-in failed. Please try again." in page
    page = (await admin_client.get("/settings", params={"error": "already_linked", "login": "mona"})).text
    assert "@mona is already linked to another Slipway account" in page


async def test_first_admin_callout_respects_github_allowlist(client, monkeypatch):
    assert "the first account becomes admin" in (await client.get("/login")).text
    monkeypatch.setattr(get_settings(), "github_allowed_users", ["alice"])
    page = (await client.get("/login")).text
    assert "the first account becomes admin" not in page and "allow-listed GitHub account" in page
    monkeypatch.setattr(get_settings(), "github_allowed_users", [])
    monkeypatch.setattr(get_settings(), "github_allowed_orgs", ["acme"])
    assert "the first account becomes admin" not in (await client.get("/login")).text


async def test_login_form_redirects_to_sanitized_next(client):
    page = (await client.get("/login?next=/instances/abc%3Ftab%3D1")).text
    assert 'data-then="redirect:/instances/abc?tab=1"' in page
    assert 'data-then="redirect:/"' in (await client.get("/login?next=https://evil.example")).text


# ---------------------------------------------------------- instance form


async def test_edit_form_shows_the_instance_repository_even_when_archived(admin_client):
    await _add_repo(51, "aaa-other")
    web = await _add_repo(52, "zzz-web")
    host = (await admin_client.post("/api/v1/hosts", json={"name": "h", "hostname": "10.0.0.5", "username": "deploy"})).json()
    inst = (await admin_client.post("/api/v1/instances", json={
        "name": "web", "repository_id": web, "host_id": host["id"], "branch": "release", "deploy": False})).json()
    async with get_sessionmaker()() as db:
        (await db.get(Repository, uuid.UUID(web))).archived = True
        await db.commit()

    page = (await admin_client.get(f"/instances/{inst['id']}/edit")).text
    picker = re.search(r'<select[^>]*id="repo-select".*?</select>', page, re.S).group(0)
    assert "acme/zzz-web (archived)" in picker and "acme/aaa-other" not in picker
    assert 'data-current="release"' in page

    async with get_sessionmaker()() as db:
        for repo in (await db.scalars(select(Repository))).all():
            repo.archived = True
        await db.commit()
    page = (await admin_client.get(f"/instances/{inst['id']}/edit")).text
    assert 'id="repo-select"' in page and "No repositories yet" not in page


async def test_create_form_options_carry_their_own_defaults(admin_client):
    await _add_repo(61, "api")
    await _add_repo(62, "web", detected_config={"dockerfile": False, "compose_file": "compose.yaml", "files": ["compose.yaml"]})
    await admin_client.post("/api/v1/hosts", json={"name": "h", "hostname": "10.0.0.5", "username": "deploy"})
    page = (await admin_client.get("/instances/new")).text
    assert 'data-fill-name="web-prod" data-fill-compose_file="compose.yaml" data-fill-build_source="compose"' in page
    assert 'data-fill-name="api-prod" data-fill-compose_file="docker-compose.yml" data-fill-build_source="dockerfile"' in page
    assert "trusted code with host-level access" in page


# ------------------------------------------------- forms never submit by GET


async def test_api_forms_never_fall_back_to_get(admin_client, make_client):
    repo_id = await _add_repo(71, "web")
    host = (await admin_client.post("/api/v1/hosts", json={"name": "h", "hostname": "10.0.0.5", "username": "deploy"})).json()
    inst = (await admin_client.post("/api/v1/instances", json={"name": "web", "repository_id": repo_id, "host_id": host["id"], "deploy": False})).json()
    await admin_client.post("/api/v1/roles", json={"name": "ops", "permissions": ["hosts:read"]})
    pages = ["/settings", "/settings/users", "/settings/roles", "/settings/tokens", "/hosts", f"/hosts/{host['id']}",
             "/instances/new", f"/instances/{inst['id']}/edit"]
    anonymous = make_client()
    checked = [(p, (await admin_client.get(p)).text) for p in pages] + [("/login", (await anonymous.get("/login")).text)]
    for path, page in checked:
        forms = [f for f in _parse(page).forms if "data-form" in f]
        assert forms, path
        for form in forms:
            assert form.get("method") == "post" and form.get("action") == "/js-required", (path, form)

    r = await anonymous.post("/js-required", data={"email": "a@example.com", "password": "hunter2hunter2"})
    assert r.status_code == 400 and "JavaScript required" in r.text and "hunter2" not in r.text


# ---------------------------------------------------------- host setup snippet


async def test_host_setup_snippet_shell_quotes_the_public_key(admin_client, tmp_path):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash not available")
    priv, _ = ssh.generate_keypair("x'; touch \"$HOME/PWNED\"; echo '")
    host = (await admin_client.post("/api/v1/hosts", json={
        "name": "pasted", "hostname": "10.0.0.9", "username": "deploy", "auth_method": "key", "private_key": priv})).json()
    page = (await admin_client.get(f"/hosts/{host['id']}")).text
    snippet = html.unescape(re.search(r'<pre class="code" id="install-cmd">(.*?)</pre>', page, re.S).group(1))
    subprocess.run([bash, "-c", snippet.splitlines()[0]], env={"HOME": str(tmp_path), "PATH": os.environ["PATH"]},
                   check=True, timeout=30, capture_output=True)
    assert not (tmp_path / "PWNED").exists()
    assert (tmp_path / ".ssh" / "authorized_keys").read_text() == host["public_key"] + "\n"


# ----------------------------------------------------------------- slipway.js
# The real slipway.js runs against a small fake DOM under node or macOS JavaScriptCore.

HARNESS = r"""
var out = typeof print === "function" ? print : console.log;
var timers = [];
globalThis.setTimeout = function (fn) { timers.push(fn); return timers.length; };
var window = globalThis;
globalThis.isSecureContext = false;
var navigator = {};
var hrefs = [], execCommands = [], fetchCalls = [], fetchBodies = [], routes = {};
var execResult = true;
var location = {
  origin: "http://slipway.test", protocol: "http:", host: "slipway.test", pathname: "/", search: "",
  get href() { return this.origin + this.pathname + this.search; },
  set href(v) { hrefs.push(String(v)); },
  reload: function () { hrefs.push("RELOAD"); },
};

// Enough of the WHATWG URL parser to resolve origins: tabs/newlines are stripped, "\" counts as "/".
function URL(url, base) {
  var s = String(url).replace(/[\t\n\r]/g, "").replace(/^[\u0000- ]+|[\u0000- ]+$/g, "").replace(/\\/g, "/");
  var b = base === undefined ? null : new URL(base);
  var m = /^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)$/.exec(s);
  if (!m && !b) throw new TypeError("Invalid URL");
  var scheme = m ? m[1].toLowerCase() : b.protocol.slice(0, -1), rest = m ? m[2] : s, host, path;
  if (rest.indexOf("//") === 0) { var hm = /^\/\/([^\/?#]*)(.*)$/.exec(rest); host = hm[1]; path = hm[2] || "/"; }
  else if (!m) { host = b.host; path = rest.charAt(0) === "/" ? rest : "/" + rest; }
  else { host = null; path = rest; }
  this.protocol = scheme + ":"; this.host = host;
  this.origin = host === null ? "null" : this.protocol + "//" + host;
  this.href = (host === null ? this.protocol : this.origin) + path;
}
function URLSearchParams(q) { this.q = String(q || "").replace(/^\?/, ""); }
URLSearchParams.prototype.get = function (k) {
  var parts = this.q ? this.q.split("&") : [];
  for (var i = 0; i < parts.length; i++) { var kv = parts[i].split("="); if (decodeURIComponent(kv[0]) === k) return decodeURIComponent(kv[1] || ""); }
  return null;
};
function Event(type, opts) { this.type = type; this.bubbles = !!(opts && opts.bubbles); this.defaultPrevented = false; this.isTrusted = false; }
Event.prototype.preventDefault = function () { this.defaultPrevented = true; };
function CustomEvent(type, opts) { Event.call(this, type, opts); this.detail = opts && opts.detail; }
CustomEvent.prototype = Object.create(Event.prototype);
function Storage() { this.d = {}; }
Storage.prototype.getItem = function (k) { return k in this.d ? this.d[k] : null; };
Storage.prototype.setItem = function (k, v) { this.d[k] = String(v); };
Storage.prototype.removeItem = function (k) { delete this.d[k]; };
var sessionStorage = new Storage(), localStorage = new Storage();
function matchMedia() { return { matches: false }; }
function confirm() { return true; }
function alert(m) { out("ALERT " + m); }

function fetch(url, opts) {
  fetchCalls.push(opts.method + " " + url);
  fetchBodies.push(opts.body === undefined ? null : JSON.parse(opts.body));
  var r = routes[opts.method + " " + url.split("?")[0]] || { status: 200, body: {} };
  return Promise.resolve({
    status: r.status, ok: r.status >= 200 && r.status < 300, statusText: "HTTP " + r.status,
    json: function () { return Promise.resolve(JSON.parse(JSON.stringify(r.body))); },
  });
}

// ---- selectors: compound selectors, ",", descendant " ", [attr], [attr=v], :checked, :not(...)
function splitTop(sel) {
  var parts = [], depth = 0, cur = "";
  for (var i = 0; i < sel.length; i++) {
    var c = sel[i];
    if (c === "[" || c === "(") depth++;
    if (c === "]" || c === ")") depth--;
    if (c === "," && !depth) { parts.push(cur.trim()); cur = ""; } else cur += c;
  }
  parts.push(cur.trim());
  return parts;
}
var TOKEN = /^(?:([a-zA-Z][\w-]*)|#([\w-]+)|\.([\w-]+)|\[([\w-]+)(?:=(?:"([^"]*)"|'([^']*)'|([^\]]*)))?\]|(:checked)|:not\(([^)]*)\))/;
function parseCompound(s) {
  var c = { tag: null, id: null, classes: [], attrs: [], checked: false, nots: [] }, m;
  while (s.length) {
    m = TOKEN.exec(s);
    if (!m) throw new Error("selector not supported: " + s);
    if (m[1]) c.tag = m[1].toUpperCase();
    else if (m[2]) c.id = m[2];
    else if (m[3]) c.classes.push(m[3]);
    else if (m[4]) c.attrs.push([m[4], m[5] !== undefined ? m[5] : m[6] !== undefined ? m[6] : m[7]]);
    else if (m[8]) c.checked = true;
    else if (m[9] !== undefined) c.nots.push(parseCompound(m[9]));
    s = s.slice(m[0].length);
  }
  return c;
}
function matchCompound(el, c) {
  if (!el.attrs || el.isDocument) return false;
  if (c.tag && el.tagName !== c.tag) return false;
  if (c.id && el.attrs.id !== c.id) return false;
  var cls = (el.attrs["class"] || "").split(/\s+/);
  for (var i = 0; i < c.classes.length; i++) if (cls.indexOf(c.classes[i]) < 0) return false;
  for (i = 0; i < c.attrs.length; i++) {
    var name = c.attrs[i][0], val = c.attrs[i][1];
    if (name === "type" && val !== undefined) { if (el.type !== val) return false; continue; }
    if (!(name in el.attrs)) return false;
    if (val !== undefined && el.attrs[name] !== val) return false;
  }
  if (c.checked && !(el.checked || el.selected)) return false;
  for (i = 0; i < c.nots.length; i++) if (matchCompound(el, c.nots[i])) return false;
  return true;
}
function matchComplex(el, sel) {
  var parts = sel.split(/\s+/).map(parseCompound);
  if (!matchCompound(el, parts[parts.length - 1])) return false;
  var i = parts.length - 2, node = el.parentNode;
  while (i >= 0 && node) { if (matchCompound(node, parts[i])) i--; node = node.parentNode; }
  return i < 0;
}
function matches(el, sel) { return splitTop(sel).some(function (s) { return matchComplex(el, s); }); }

// ---- elements
function camelToData(k) { return "data-" + k.replace(/[A-Z]/g, function (c) { return "-" + c.toLowerCase(); }); }
function El(tag, attrs, children) {
  var self = this;
  this.tagName = tag.toUpperCase(); this.attrs = {}; this.children = []; this.parentNode = null;
  this.listeners = {}; this.style = {}; this._text = ""; this._value = null; this.checked = false; this.selected = false;
  this.dataset = new Proxy({}, {
    get: function (t, k) { var n = camelToData(String(k)); return n in self.attrs ? self.attrs[n] : undefined; },
    set: function (t, k, v) { self.attrs[camelToData(String(k))] = String(v); return true; },
  });
  this.classList = {
    toggle: function (c, on) { var l = (self.attrs["class"] || "").split(/\s+/).filter(function (x) { return x && x !== c; }); if (on) l.push(c); self.attrs["class"] = l.join(" "); },
  };
  for (var k in attrs || {}) this.setAttribute(k, attrs[k]);
  (children || []).forEach(function (c) { if (typeof c === "string") self._text += c; else self.appendChild(c); });
}
El.prototype.setAttribute = function (k, v) {
  this.attrs[k] = String(v);
  if (k === "checked") this.checked = true;
  if (k === "selected") this.selected = true;
};
El.prototype.getAttribute = function (k) { return k in this.attrs ? this.attrs[k] : null; };
El.prototype.hasAttribute = function (k) { return k in this.attrs; };
El.prototype.appendChild = function (c) { if (c.parentNode) c.remove(); c.parentNode = this; this.children.push(c); return c; };
El.prototype.remove = function () { var p = this.parentNode; if (p) { p.children.splice(p.children.indexOf(this), 1); this.parentNode = null; } };
El.prototype.descendants = function () { var all = []; this.children.forEach(function (c) { all.push(c); all.push.apply(all, c.descendants()); }); return all; };
El.prototype.querySelectorAll = function (sel) { return this.descendants().filter(function (e) { return matches(e, sel); }); };
El.prototype.querySelector = function (sel) { return this.querySelectorAll(sel)[0] || null; };
El.prototype.closest = function (sel) { for (var n = this; n && !n.isDocument; n = n.parentNode) if (matches(n, sel)) return n; return null; };
El.prototype.addEventListener = function (type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); };
El.prototype.dispatchEvent = function (ev) {
  if (!ev.target) ev.target = this;
  for (var node = this; node; node = ev.bubbles ? node.parentNode : null) {
    (node.listeners[ev.type] || []).slice().forEach(function (fn) { fn(ev); });
  }
  return !ev.defaultPrevented;
};
El.prototype.focus = function () { document.activeElement = this; };
El.prototype.select = function () { document.selection = { text: this.value, parent: this.parentNode && this.parentNode.tagName }; };
El.prototype.showModal = function () { this.attrs.open = ""; };
El.prototype.close = function () { delete this.attrs.open; };
function prop(name, get, set) { Object.defineProperty(El.prototype, name, { get: get, set: set }); }
prop("id", function () { return this.attrs.id || ""; });
prop("name", function () { return this.attrs.name || ""; });
prop("type", function () { return (this.attrs.type || (this.tagName === "INPUT" ? "text" : "")).toLowerCase(); });
prop("className", function () { return this.attrs["class"] || ""; }, function (v) { this.attrs["class"] = v; });
prop("disabled", function () { return "disabled" in this.attrs; }, function (v) { if (v) this.attrs.disabled = ""; else delete this.attrs.disabled; });
prop("hidden", function () { return "hidden" in this.attrs; }, function (v) { if (v) this.attrs.hidden = ""; else delete this.attrs.hidden; });
prop("form", function () { return this.parentNode ? this.parentNode.closest("form") : null; });
prop("selectedOptions", function () {
  var opts = this.querySelectorAll("option"), sel = opts.filter(function (o) { return o.selected; });
  return sel.length ? sel.slice(0, 1) : opts.slice(0, 1);
});
prop("value", function () {
  if (this.tagName === "SELECT") { var o = this.selectedOptions[0]; return o ? o.value : ""; }
  if (this.tagName === "OPTION") return "value" in this.attrs ? this.attrs.value : this.textContent;
  return this._value !== null ? this._value : (this.attrs.value || "");
}, function (v) {
  if (this.tagName === "SELECT") this.querySelectorAll("option").forEach(function (o) { o.selected = o.value === v; });
  else this._value = String(v);
});
prop("textContent", function () { return this._text + this.children.map(function (c) { return c.textContent; }).join(""); },
  function (v) { this._text = String(v); this.children.slice().forEach(function (c) { c.remove(); }); });
prop("innerHTML", function () { return ""; }, function (v) {
  var self = this, re = /<option ?(selected)?[^>]*>([^<]*)<\/option>/g, m;
  this.textContent = "";
  while ((m = re.exec(v))) { var o = new El("option", m[1] ? { selected: "" } : {}, [m[2]]); self.appendChild(o); }
});
prop("defaultChecked", function () { return "checked" in this.attrs; });
prop("defaultValue", function () { return this.attrs.value || ""; });
prop("attributes", function () { var a = this.attrs; return Object.keys(a).map(function (n) { return { name: n, value: a[n] }; }); });

var document = new El("#document");
document.isDocument = true;
document.body = document.appendChild(new El("body"));
document.documentElement = document.body;
document.createElement = function (t) { return new El(t); };
document.getElementById = function (id) { return document.querySelector("#" + id); };
document.execCommand = function (cmd) { execCommands.push([cmd, document.selection]); return execResult; };
document.body.appendChild(new El("div", { id: "toasts" }));

function h(tag, attrs, children) { return new El(tag, attrs, children); }
function user(type, target, extra) {
  var ev = new Event(type, { bubbles: true }); ev.isTrusted = true;
  for (var k in extra || {}) ev[k] = extra[k];
  target.dispatchEvent(ev);
}
async function settle() { for (var i = 0; i < 50; i++) await Promise.resolve(); }
function toasts() { return document.querySelector("#toasts").children.map(function (c) { return c.className + "|" + c.textContent; }); }
function done(result) { out("RESULT " + JSON.stringify(result)); }
"""


def _js_runtime() -> list[str] | None:
    if node := shutil.which("node"):
        return [node]
    return [str(JSC)] if JSC.exists() else None


def run_js(tmp_path: Path, scenario: str) -> dict:
    runtime = _js_runtime()
    if runtime is None:
        pytest.skip("no JavaScript runtime (node or JavaScriptCore) available")
    script = tmp_path / "scenario.js"
    wrapped = f"(async function () {{\n{scenario}\n}})().catch(function (e) {{ out('ERROR ' + e + '\\n' + e.stack); }});"
    script.write_text(HARNESS + "\n" + SLIPWAY_JS.read_text() + "\n" + wrapped)
    proc = subprocess.run([*runtime, str(script)], capture_output=True, text=True, timeout=60)
    results = [line for line in proc.stdout.splitlines() if line.startswith("RESULT ")]
    assert results, proc.stdout + proc.stderr
    return json.loads(results[-1][7:])


LOGIN_FORM = """
var form = h("form", { id: "login-form", method: "post", action: "/js-required", "data-form": "POST /api/v1/auth/login", "data-then": THEN }, [
  h("input", { name: "email", value: "admin@example.com" }),
  h("input", { name: "password", type: "password", value: "wrong-password" }),
  h("button", { type: "submit" }),
]);
document.body.appendChild(form);
"""


def test_js_failed_login_shows_error_instead_of_reloading(tmp_path):
    result = run_js(tmp_path, """
location.pathname = "/login"; location.search = "?next=%2Finstances%2Fabc";
routes["POST /api/v1/auth/login"] = { status: 401, body: { detail: "Invalid email or password" } };
var THEN = "redirect:/instances/abc";
""" + LOGIN_FORM + """
user("submit", form, { submitter: form.querySelector("button") });
await settle();
done({ hrefs: hrefs, toasts: toasts() });
""")
    assert result["hrefs"] == []
    assert "toast error|Invalid email or password" in result["toasts"]


def test_js_expired_session_redirect_keeps_the_query_string(tmp_path):
    result = run_js(tmp_path, """
location.pathname = "/instances/abc"; location.search = "?tab=logs";
routes["POST /api/v1/instances/abc/deploy"] = { status: 401, body: { detail: "Not authenticated" } };
var btn = h("button", { "data-api": "POST /api/v1/instances/abc/deploy" });
document.body.appendChild(btn);
user("click", btn);
await settle();
done({ hrefs: hrefs });
""")
    assert result["hrefs"] == ["/login?next=%2Finstances%2Fabc%3Ftab%3Dlogs"]


def test_js_redirects_only_stay_on_this_origin(tmp_path):
    result = run_js(tmp_path, """
location.pathname = "/login";
routes["POST /api/v1/auth/login"] = { status: 200, body: { id: "abc", csrf_token: "t" } };
var THEN = "";
""" + LOGIN_FORM + """
var specs = ["redirect:/\\t/evil.example", "redirect:/\\n/evil.example/x", "redirect://evil.example",
             "redirect:https://evil.example/", "redirect:javascript:alert(1)", "redirect:/instances/{id}"];
for (var i = 0; i < specs.length; i++) {
  form.setAttribute("data-then", specs[i]);
  user("submit", form, { submitter: form.querySelector("button") });
  await settle();
}
done({ hrefs: hrefs });
""")
    assert result["hrefs"] == ["/", "/", "/", "/", "/", "http://slipway.test/instances/abc"]


def test_js_copy_falls_back_without_the_clipboard_api(tmp_path):
    result = run_js(tmp_path, """
var plain = h("button", { "data-copy": "ssh-ed25519 AAAA slipway@prod" });
var dlg = h("dialog", { open: "" }, [h("pre", { id: "token-value" }, ["slipway_secret_token\\n"]), h("button", { "data-copy-target": "#token-value" })]);
document.body.appendChild(plain); document.body.appendChild(dlg);
user("click", plain);
await settle();
user("click", dlg.querySelector("button"));
await settle();
var ok = { copies: execCommands.slice(), toasts: toasts() };
execResult = false;
user("click", plain);
await settle();
var failed = toasts().slice(ok.toasts.length);
var clip = [];
navigator.clipboard = { writeText: function (t) { clip.push(t); return Promise.resolve(); } };
globalThis.isSecureContext = true;
user("click", plain);
await settle();
done({ ok: ok, failed: failed, clip: clip, legacyCalls: execCommands.length });
""")
    assert result["ok"]["copies"] == [
        ["copy", {"text": "ssh-ed25519 AAAA slipway@prod", "parent": "BODY"}],
        ["copy", {"text": "slipway_secret_token", "parent": "DIALOG"}],
    ]
    assert result["ok"]["toasts"] == ["toast success|Copied to clipboard"] * 2
    assert len(result["failed"]) == 1 and result["failed"][0].startswith("toast error|Couldn't copy")
    assert result["clip"] == ["ssh-ed25519 AAAA slipway@prod"] and result["legacyCalls"] == 3


def test_js_switching_repository_resets_untouched_defaults(tmp_path):
    result = run_js(tmp_path, """
location.pathname = "/instances/new";
routes["GET /api/v1/repositories/r1/branches"] = { status: 200, body: ["main"] };
routes["GET /api/v1/repositories/r2/branches"] = { status: 200, body: ["trunk"] };
var form = h("form", { "data-form": "POST /api/v1/instances", "data-preview-form": "" }, [
  h("select", { id: "repo-select", name: "repository_id", "data-branches": "#branch-select", "data-fill": "" }, [
    h("option", { value: "r1", "data-default": "main", "data-fill-name": "api-prod", "data-fill-compose_file": "docker-compose.yml", "data-fill-build_source": "dockerfile", selected: "" }, ["acme/api"]),
    h("option", { value: "r2", "data-default": "trunk", "data-fill-name": "web-prod", "data-fill-compose_file": "compose.yaml", "data-fill-build_source": "compose" }, ["acme/web"]),
  ]),
  h("select", { id: "branch-select", name: "branch", "data-current": "" }, [h("option", {}, ["main"])]),
  h("input", { type: "radio", name: "build_source", value: "dockerfile", checked: "" }),
  h("input", { type: "radio", name: "build_source", value: "compose" }),
  h("div", { "data-show-when": "build_source=compose" }, [h("input", { id: "cf", name: "compose_file", value: "docker-compose.yml" })]),
  h("input", { id: "inst-name", name: "name", value: "api-prod" }),
]);
document.body.appendChild(form);
document.dispatchEvent(new Event("DOMContentLoaded"));
await settle();
var repo = document.querySelector("#repo-select");
repo.value = "r2"; user("input", repo); user("change", repo);
await settle();
var switched = window.slipway.serialize(form);
var name = document.querySelector("#inst-name");
name.value = "my-web"; user("input", name);
repo.value = "r1"; user("input", repo); user("change", repo);
await settle();
done({ switched: switched, back: window.slipway.serialize(form) });
""")
    switched, back = result["switched"], result["back"]
    assert switched["repository_id"] == "r2" and switched["branch"] == "trunk"
    assert switched["name"] == "web-prod" and switched["build_source"] == "compose" and switched["compose_file"] == "compose.yaml"
    assert back["name"] == "my-web" and back["build_source"] == "dockerfile" and "compose_file" not in back


def test_js_expired_session_on_auth_endpoints_still_goes_to_login(tmp_path):
    result = run_js(tmp_path, """
location.pathname = "/instances/abc";
["POST /api/v1/auth/logout", "PATCH /api/v1/auth/me", "POST /api/v1/auth/me/password", "DELETE /api/v1/auth/me/github"]
  .forEach(function (r) { routes[r] = { status: 401, body: { detail: "Not authenticated" } }; });
var signOut = h("button", { type: "button", "data-api": "POST /api/v1/auth/logout", "data-then": "redirect:/login" });
document.body.appendChild(signOut);
user("click", signOut);
await settle();
location.pathname = "/settings";
var forms = ["PATCH /api/v1/auth/me", "POST /api/v1/auth/me/password"].map(function (api) {
  return h("form", { method: "post", action: "/js-required", "data-form": api, "data-then": "reload" },
    [h("input", { name: "full_name", value: "Ada" }), h("button", { type: "submit" })]);
});
forms.forEach(function (f) { document.body.appendChild(f); user("submit", f, { submitter: f.querySelector("button") }); });
await settle();
var unlink = h("button", { "data-api": "DELETE /api/v1/auth/me/github", "data-then": "reload" });
document.body.appendChild(unlink);
user("click", unlink);
await settle();
done({ hrefs: hrefs });
""")
    assert result["hrefs"] == ["/login?next=%2Finstances%2Fabc"] + ["/login?next=%2Fsettings"] * 3


ROLE_DIALOGS = """
var FORMS = %s;
for (var i = 0; i < FORMS.length; i++) {
  var form = h("form", FORMS[i].form, FORMS[i].inputs.map(function (a) { return h("input", a); }).concat([h("button", { type: "submit" })]));
  document.body.appendChild(form);
  var submit = function () { user("submit", form, { submitter: form.querySelector("button") }); };
  form.querySelector('[name="description"]').value = "changed";
  submit();
  await settle();
  var legacy = form.querySelector('[value="legacy:thing"]');
  if (legacy) {
    form.querySelector('[value="hosts:read"]').checked = true;
    submit();
    await settle();
    legacy.checked = false;
    submit();
    await settle();
  }
  form.remove();
}
done({ calls: fetchCalls, bodies: fetchBodies });
"""


async def test_role_editor_saves_without_regranting_untouched_permissions(admin_client, make_client, tmp_path):
    ops = (await admin_client.post("/api/v1/roles", json={
        "name": "ops", "description": "Ops", "permissions": ["hosts:*", "instances:read"]})).json()
    await _add_role("legacy", ["instances:read", "legacy:thing"])
    editor = await _client_with(make_client, "roleeditor@example.com",
                                ["roles:read", "roles:write", "hosts:read", "hosts:write", "instances:read"])
    page = (await editor.get("/settings/roles")).text
    async with get_sessionmaker()() as db:
        legacy_id = str((await db.scalar(select(Role).where(Role.name == "legacy"))).id)

    dialogs = []
    for role_id in (ops["id"], legacy_id):
        parsed = _parse(page, f"edit-role-{role_id}")
        assert parsed.dialog_form.get("data-omit-unchanged") == "permissions"
        clean = lambda attrs: {k: "" if v is None else v for k, v in attrs.items()}  # noqa: E731
        dialogs.append({"form": clean(parsed.dialog_form), "inputs": [clean(a) for a in parsed.inputs]})
    sent = run_js(tmp_path, ROLE_DIALOGS % json.dumps(dialogs))
    assert sent["calls"] == [f"PATCH /api/v1/roles/{ops['id']}"] + [f"PATCH /api/v1/roles/{legacy_id}"] * 3

    statuses = []
    for call, body in zip(sent["calls"], sent["bodies"]):
        r = await editor.patch(call.split(" ", 1)[1], json=body)
        statuses.append((r.status_code, r.json()))
    assert [s for s, _ in statuses] == [200, 200, 422, 200]
    ops_saved, legacy_saved, rejected, cleaned = (b for _, b in statuses)
    assert ops_saved["permissions"] == ["hosts:*", "instances:read"] and ops_saved["description"] == "changed"
    assert legacy_saved["permissions"] == ["instances:read", "legacy:thing"]
    assert "Unknown permission(s): legacy:thing" in json.dumps(rejected)
    assert cleaned["permissions"] == ["hosts:read", "instances:read"]
