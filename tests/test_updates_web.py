"""The Updates page: the sidebar item, the page in each state, and its JavaScript.

The server is the fake from test_updates_api (nothing real is touched). The JavaScript runs the real slipway.js
against the fake DOM from test_review_web, built from the page as served.
"""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser

from slipway.services import updates
from slipway.web import pages
from tests.conftest import login, make_user
from tests.test_review_web import run_js
from tests.test_updates_api import (  # noqa: F401 (server is a fixture)
    FROM,
    NEW,
    _checked,
    _configured,
    _host,
    _store_run,
    server,
)

EVIL_BRANCH = "x/<img src=x onerror=alert(1)>"
EVIL_SUBJECT = "</script><script>alert(1)</script>"
EVIL_AUTHOR = "<img src=x onerror=alert(2)>"
RUN_ID = "20261117-100000-abcdef"


def _nav(page: str) -> str:
    return re.search(r'<nav class="nav".*?</nav>', page, re.S).group(0)


# ------------------------------------------------------------------------- sidebar


async def test_updates_nav_item_only_with_the_permission(admin_client, make_client, server):
    nav = _nav((await admin_client.get("/")).text)
    assert nav.index('href="/settings"') < nav.index('href="/updates"')
    assert "nav-badge" not in nav

    await make_user("maint@example.com", roles=["maintainer"])
    other = make_client()
    await login(other, "maint@example.com")
    assert 'href="/updates"' not in _nav((await other.get("/")).text)
    resp = await other.get("/updates")
    assert resp.status_code == 403 and "updates:run" in resp.text
    assert server.commands == []


async def test_nav_badge_counts_new_commits_until_slipway_changes(admin_client, server, monkeypatch):
    await _checked(admin_client, server)
    nav = _nav((await admin_client.get("/hosts")).text)
    assert re.search(r'Updates<span class="nav-badge"[^>]*>2</span>', nav)

    monkeypatch.setenv("SLIPWAY_COMMIT", NEW)  # upgraded since that check: those commits run now
    assert "nav-badge" not in _nav((await admin_client.get("/hosts")).text)


async def test_the_badge_is_read_without_ssh(admin_client, server):
    await _checked(admin_client, server)
    before = len(server.commands)
    await admin_client.get("/hosts")
    await admin_client.get("/settings")
    assert len(server.commands) == before


# ------------------------------------------------------------------------- page states


async def test_page_outside_docker_explains_install_sh(admin_client, server, monkeypatch):
    monkeypatch.setattr(updates, "in_docker", lambda: False)
    page = (await admin_client.get("/updates")).text
    assert "<h1>Updates</h1>" in page
    assert "Slipway isn't running in Docker here, so it can't upgrade itself" in page
    assert "install.sh" in page
    assert 'data-form="PUT /api/v1/updates/config"' not in page
    assert "Check now" not in page and 'id="update-confirm"' not in page


async def test_page_before_setup_lists_pinned_hosts(admin_client, server):
    page = (await admin_client.get("/updates")).text
    assert "Add the server Slipway runs on as a host and verify its key first" in page

    tower = await _host("tower")
    await _host("not-yet", hostname="10.0.0.9", host_key=None, fingerprint=None)
    page = (await admin_client.get("/updates")).text
    assert 'data-form="PUT /api/v1/updates/config"' in page
    assert f'<option value="{tower.id}"' in page and "not-yet" not in page
    assert "Choose the server Slipway runs on" in page
    # The running version comes from the image's stamp; it links to GitHub once a check found the repository.
    assert f'<span class="mono" title="{FROM}">{FROM[:7]}</span>' in page
    assert "2026-11-01 08:00 UTC" in page


async def test_unstamped_image_says_its_commit_was_not_recorded(admin_client, server, monkeypatch):
    monkeypatch.delenv("SLIPWAY_COMMIT")
    monkeypatch.delenv("SLIPWAY_BUILT_AT")
    page = (await admin_client.get("/updates")).text
    assert "Not recorded (built before Slipway recorded its version)" in page


async def test_page_configured_but_not_checked(admin_client, server):
    host = await _configured(admin_client, server)
    page = (await admin_client.get("/updates")).text
    assert f'<option value="{host.id}" selected>' in page
    assert "/mnt/user/slipway" in page and "Not checked yet" in page
    assert 'data-api="POST /api/v1/updates/check"' in page
    # Slipway's own server as a host: who is root on Slipway through it.
    assert "is Slipway's own server." in page and "root on Slipway itself" in page
    assert "<code>admin</code>" in page and "<code>maintainer</code>" in page
    assert "data-update-target" not in page


async def test_page_after_a_check_shows_commits_warnings_and_upgrade(admin_client, server):
    server.branches["main"] = (NEW, "2026-11-16T10:00:00+00:00", EVIL_AUTHOR, EVIL_SUBJECT)
    server.log_commits[0] = (NEW, "2026-11-16T10:00:00+00:00", EVIL_AUTHOR, EVIL_SUBJECT)
    await _checked(admin_client, server)
    page = (await admin_client.get("/updates")).text

    assert "2 new commits on" in page
    assert f'href="https://github.com/encondata/slipway/commit/{NEW}"' in page
    assert "This update changes the database (1 migration)" in page
    assert "This update changes <code>Dockerfile</code>. These run as root on tower." in page
    assert f'href="https://github.com/encondata/slipway/compare/{FROM}...{NEW}"' in page
    button = re.search(r"<button[^>]*data-update-target[^>]*>", page, re.S).group(0)
    assert f'data-sha="{NEW}"' in button and 'data-branch="main"' in button and 'data-followed="1"' in button
    assert 'data-migrations="1"' in button and 'data-privileged="Dockerfile"' in button
    assert f"Upgrade to {NEW[:7]}" in page

    # Text from git is escaped everywhere: no tag from it reaches the page.
    for raw in (EVIL_BRANCH, EVIL_SUBJECT, EVIL_AUTHOR, "<img", "<script>alert"):
        assert raw not in page
    assert "x/&lt;img src=x onerror=alert(1)&gt;" in page
    assert "&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;" in page
    # The other branches: one that came before, one beside, and one whose name Slipway won't use.
    assert "Other branches from the last check" in page
    others = re.search(r"Other branches from the last check.*?</table>", page, re.S).group(0)
    assert others.count("Older than or beside what's running") == 1  # sideways
    assert others.count("Slipway only switches to branch names made of letters, digits and . _ / -") == 1  # the bad name
    assert "data-update-target" not in others


async def test_switch_buttons_for_branches_that_descend(admin_client, server):
    feature = "e" * 40
    server.branches["feature/next"] = (feature, "2026-11-16T11:00:00+00:00", "Ada", "Try something")
    server.privileged[feature] = ["install.sh"]
    await _checked(admin_client, server)
    page = (await admin_client.get("/updates")).text
    button = re.search(r'<button[^>]*data-branch="feature/next"[^>]*>', page, re.S).group(0)
    assert "data-update-target" in button and 'data-followed=""' in button and 'data-privileged="install.sh"' in button
    assert "Switch to feature/next" in page

    server.dirty = " M Dockerfile"  # a reason that blocks every upgrade blocks switching too
    await admin_client.post("/api/v1/updates/check")
    page = (await admin_client.get("/updates")).text
    button = re.search(r'<button[^>]*data-branch="feature/next"[^>]*>', page, re.S).group(0)
    assert "disabled" in button and "data-update-target" not in button
    assert "The install folder has local changes to tracked files: <code> M Dockerfile</code>" in page
    assert "docker-compose.override.yml" in page


def test_switch_reason_ignores_the_followed_branch_only_reasons():
    ov = {"reason": "Slipway is up to date"}
    assert pages.switch_reason(ov) is None
    ov["reason"] = "main doesn't come after the running version: Slipway can't move back or sideways"
    assert pages.switch_reason(ov) is None
    for reason in (updates.MSG_DIRTY, updates.MSG_RUN_RUNNING, updates.MSG_DEPLOYMENT_RUNNING, "Check for updates first"):
        ov["reason"] = reason
        assert pages.switch_reason(ov) == reason
    assert pages.switch_reason({"reason": None}) is None


async def test_up_to_date_has_no_upgrade_button(admin_client, server):
    server.branches["main"] = (FROM, "2026-11-16T10:00:00+00:00", "Jimmy", "Current")
    server.log_commits = []
    await _checked(admin_client, server)
    page = (await admin_client.get("/updates")).text
    assert "Slipway is up to date with" in page
    assert "data-update-target" not in page and "nav-badge" not in page


async def test_failed_check_is_shown(admin_client, server):
    await _configured(admin_client, server)
    server.fetch_fails = "fatal: unable to access 'https://bob:hunter2@github.com/x/y.git/'"
    resp = await admin_client.post("/api/v1/updates/check")
    assert resp.status_code == 502
    page = (await admin_client.get("/updates")).text
    assert "The last check failed" in page and "hunter2" not in page


async def test_history_and_the_run_view(admin_client, server):
    host = await _configured(admin_client, server)
    await _store_run(RUN_ID, host, status="interrupted", message=updates.MSG_INTERRUPTED, finished_at="2026-11-17T10:05:00Z")
    page = (await admin_client.get("/updates")).text
    assert 'class="badge error" data-run-status>Interrupted</span>' in page
    assert f'href="/updates?run={RUN_ID}"' in page
    assert "data-update-run" not in page  # a finished run doesn't open by itself

    page = (await admin_client.get(f"/updates?run={RUN_ID}")).text
    assert f'data-update-run="{RUN_ID}"' in page
    assert f"main: {FROM[:7]} to {NEW[:7]}, started by admin" in page
    for step in ("preflight", "fetch", "build", "backup", "switch", "health", "rollback", "cleanup"):
        assert f'data-step="{step}"' in page

    page = (await admin_client.get("/updates?run=../../etc/shadow")).text
    assert "data-update-run" not in page


async def test_a_running_run_opens_by_itself(admin_client, server):
    host = await _configured(admin_client, server)
    await _store_run(RUN_ID, host)
    server.status[RUN_ID] = json.dumps({"id": RUN_ID, "status": "running", "step": "build", "from": FROM, "to": NEW,
                                        "branch": "main", "started_at": "2026-11-17T10:00:00Z", "finished_at": None,
                                        "message": None, "backup": None, "db_changed": False, "pid": 4242,
                                        "boot_id": server.boot_id, "heartbeat_at": "2026-11-17T10:00:01Z"})
    page = (await admin_client.get("/updates")).text
    assert f'data-update-run="{RUN_ID}"' in page
    assert "An upgrade is running. Its steps and log are shown above." in page


# ------------------------------------------------------------------------- JavaScript


class _Tree(HTMLParser):
    """<main class="content"> of a page as {tag, attrs, children}, with entities decoded as a browser does."""

    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr", "use"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root: dict | None = None
        self.stack: list[dict] = []

    def handle_starttag(self, tag, attrs):
        a = {k: v or "" for k, v in attrs}
        if not self.stack and (self.root is not None or tag != "main"):
            return
        node = {"tag": tag, "attrs": a, "children": []}
        if self.stack:
            self.stack[-1]["children"].append(node)
        else:
            self.root = node
        if tag not in self.VOID:
            self.stack.append(node)

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        while self.stack and self.stack.pop()["tag"] != tag:
            pass

    def handle_data(self, data):
        if self.stack:
            self.stack[-1]["children"].append(data)


def _tree(page: str) -> dict:
    parser = _Tree()
    parser.feed(page)
    assert parser.root is not None
    return parser.root


PAGE = """
var TREE = __TREE__;
function build(n) { return typeof n === "string" ? n : h(n.tag, n.attrs, n.children.map(build)); }
document.body.appendChild(build(TREE));
location.pathname = "/updates";
function text(sel) { return document.querySelectorAll(sel).map(function (n) { return n.textContent.trim(); }); }
function shown(sel) { return document.querySelectorAll(sel).map(function (n) { return !n.hidden; }); }
"""


async def test_js_confirm_dialog_sets_git_text_as_text_and_starts_once(admin_client, server, tmp_path):
    server.branches["main"] = (NEW, "2026-11-16T10:00:00+00:00", EVIL_AUTHOR, EVIL_SUBJECT)
    await _checked(admin_client, server)
    page = (await admin_client.get("/updates")).text
    result = run_js(tmp_path, PAGE.replace("__TREE__", json.dumps(_tree(page))) + """
routes["POST /api/v1/updates/runs"] = { status: 202, body: { id: "%s" } };
var btn = document.querySelector("[data-update-target]");
user("click", btn);
var dlg = document.querySelector("#update-confirm");
var form = dlg.querySelector("form");
var filled = {
  open: "open" in dlg.attrs, sha: text('[data-confirm-text="sha"]'), branch: text('[data-confirm-text="branch"]'),
  subject: text('[data-confirm-text="subject"]'), author: text('[data-confirm-text="author"]'),
  other: shown('[data-confirm-show="other"]'), migrations: shown('[data-confirm-show="migrations"]'),
  privileged: shown('[data-confirm-show="privileged"]'), files: text('[data-confirm-text="privileged"]'),
  count: text('[data-confirm-text="migrations-count"]'),
  compare: dlg.querySelector('[data-confirm-link="compare"]').getAttribute("href"),
  body: window.slipway.serialize(form),
};
var submit = form.querySelector('[type="submit"]');
user("submit", form, { submitter: submit });
await settle();
user("submit", form, { submitter: submit });
await settle();
done({ filled: filled, posts: fetchCalls.filter(function (c) { return c.indexOf("POST") === 0; }), bodies: fetchBodies,
       hrefs: hrefs, disabled: submit.disabled });
""" % RUN_ID)
    filled = result["filled"]
    assert filled["open"] and filled["sha"] == [NEW] and filled["branch"] == ["main", "main"]
    assert filled["subject"] == [EVIL_SUBJECT] and filled["author"] == [EVIL_AUTHOR]
    assert filled["other"] == [False] and filled["migrations"] == [True] and filled["privileged"] == [True]
    assert filled["files"] == ["Dockerfile"]
    assert filled["count"] == ["1 migration"]
    assert filled["compare"] == f"https://github.com/encondata/slipway/compare/{FROM}...{NEW}"
    assert filled["body"] == {"branch": "main", "sha": NEW}
    assert result["posts"] == ["POST /api/v1/updates/runs"]  # the second submit sent nothing
    assert result["hrefs"] == [f"http://slipway.test/updates?run={RUN_ID}"]
    assert result["disabled"] is True


async def test_js_confirm_dialog_checks_the_compare_link(tmp_path, admin_client, server):
    await _checked(admin_client, server)
    page = (await admin_client.get("/updates")).text
    result = run_js(tmp_path, PAGE.replace("__TREE__", json.dumps(_tree(page))) + """
var btn = document.querySelector("[data-update-target]");
btn.setAttribute("data-compare", "javascript:alert(1)");
btn.setAttribute("data-followed", "");
btn.setAttribute("data-branch", "%s");
user("click", btn);
var link = document.querySelector('[data-confirm-link="compare"]');
done({ href: link.getAttribute("href"), hidden: link.hidden, other: shown('[data-confirm-show="other"]'),
       branch: text('[data-confirm-text="branch"]') });
""" % EVIL_BRANCH.replace('"', '\\"'))
    assert result["href"] is None and result["hidden"] is True
    assert result["other"] == [True] and result["branch"] == [EVIL_BRANCH, EVIL_BRANCH]


async def test_js_run_view_follows_the_run_through_a_restart(tmp_path, admin_client, server):
    host = await _configured(admin_client, server)
    await _store_run(RUN_ID, host, status="failed")  # rendered as finished: the page doesn't SSH for it
    page = (await admin_client.get(f"/updates?run={RUN_ID}")).text
    url = f"GET /api/v1/updates/runs/{RUN_ID}"
    result = run_js(tmp_path, PAGE.replace("__TREE__", json.dumps(_tree(page))) + """
var URL_ = "%s";
var LOG = "==> build: Builds it\\n\\u001b[31m<b>red</b>\\u001b[0m done\\n";
function state() {
  var el = document.querySelector("[data-update-run]");
  var steps = {};
  el.querySelectorAll("[data-step]").forEach(function (li) { steps[li.getAttribute("data-step")] = li.hidden ? "hidden" : li.className; });
  var badge = el.querySelector("[data-run-status]");
  var restart = el.querySelector("[data-run-restarting]");
  var msg = el.querySelector("[data-run-message]");
  return { steps: steps, badge: badge.className + "|" + badge.textContent, log: el.querySelector("[data-run-log]").textContent,
           restarting: restart.hidden ? null : restart.textContent.trim(), message: msg.hidden ? null : msg.className + "|" + msg.textContent,
           reload: !el.querySelector("[data-run-reload]").hidden, timers: timers.length };
}
routes[URL_] = { status: 200, body: { status: "running", step: "build", message: null, log: LOG, final: false } };
document.dispatchEvent(new Event("DOMContentLoaded"));
await settle();
var building = state();
routes[URL_] = { status: 503 };
timers.shift()();
await settle();
var down = state();
routes[URL_] = { status: 200, body: { status: "succeeded", step: "cleanup", message: "", log: LOG + "==> cleanup\\n", final: true } };
timers.shift()();
await settle();
var finished = state();
done({ building: building, down: down, finished: finished });
""" % url)
    building, down, finished = result["building"], result["down"], result["finished"]
    assert building["badge"] == "badge warning spin|Running"
    assert building["steps"]["preflight"] == "update-step done" and building["steps"]["fetch"] == "update-step done"
    assert building["steps"]["build"] == "update-step active" and building["steps"]["backup"] == "update-step pending"
    assert building["steps"]["rollback"] == "hidden"
    assert building["log"] == "==> build: Builds it\n<b>red</b> done\n"  # escapes stripped, tags kept as text
    assert building["timers"] == 1 and not building["reload"]

    assert down["restarting"] == "Slipway is restarting…" and down["timers"] == 1
    assert down["badge"] == "badge warning spin|Running"

    assert finished["badge"] == "badge success|Upgraded" and finished["restarting"] is None
    assert finished["message"] == "callout success|Slipway was upgraded. Reload to use the new version."
    assert finished["reload"] and finished["timers"] == 0
    assert all(v == "update-step done" for k, v in finished["steps"].items() if k != "rollback")


async def test_js_run_view_shows_rollbacks_and_stops_on_refusals(tmp_path, admin_client, server):
    host = await _configured(admin_client, server)
    await _store_run(RUN_ID, host, status="failed")
    page = (await admin_client.get(f"/updates?run={RUN_ID}")).text
    url = f"GET /api/v1/updates/runs/{RUN_ID}"
    result = run_js(tmp_path, PAGE.replace("__TREE__", json.dumps(_tree(page))) + """
var URL_ = "%s";
routes[URL_] = { status: 200, body: { status: "rolled_back", step: "rollback", message: "%s", log: "", final: true } };
document.dispatchEvent(new Event("DOMContentLoaded"));
await settle();
var el = document.querySelector("[data-update-run]");
var rolled = { rollback: el.querySelector('[data-step="rollback"]').className, hidden: el.querySelector('[data-step="rollback"]').hidden,
               message: el.querySelector("[data-run-message]").textContent, timers: timers.length,
               badge: el.querySelector("[data-run-status]").textContent };
routes[URL_] = { status: 409, body: { detail: "tower changed since updates were set up: save it on the Updates page again" } };
el.setAttribute("data-update-run", "%s");
document.dispatchEvent(new Event("DOMContentLoaded"));
await settle();
done({ rolled: rolled, refused: el.querySelector("[data-run-message]").textContent, timers: timers.length });
""" % (url, EVIL_SUBJECT.replace("/", "\\/"), RUN_ID))
    rolled = result["rolled"]
    assert rolled["rollback"] == "update-step done" and rolled["hidden"] is False
    assert rolled["badge"] == "Rolled back" and rolled["message"] == EVIL_SUBJECT and rolled["timers"] == 0
    assert result["refused"].startswith("tower changed since updates were set up") and result["timers"] == 0


async def test_js_run_view_marks_the_step_that_failed_before_the_rollback(tmp_path, admin_client, server):
    host = await _configured(admin_client, server)
    await _store_run(RUN_ID, host, status="failed")
    page = (await admin_client.get(f"/updates?run={RUN_ID}")).text
    url = f"GET /api/v1/updates/runs/{RUN_ID}"
    result = run_js(tmp_path, PAGE.replace("__TREE__", json.dumps(_tree(page))) + """
var URL_ = "%s";
var el = document.querySelector("[data-update-run]");
function steps() {
  var out = {};
  el.querySelectorAll("[data-step]").forEach(function (li) { out[li.getAttribute("data-step")] = li.hidden ? "hidden" : li.className.replace("update-step ", ""); });
  return out;
}
var seen = [];
var answers = [
  { status: "rolled_back", step: "rollback", failed_step: "health", message: "x", log: "", final: true },
  { status: "rollback_failed", step: "rollback", failed_step: "switch", message: "x", log: "", final: true },
  { status: "running", step: "rollback", failed_step: "health", message: null, log: "", final: false },
  { status: "rolled_back", step: "rollback", message: "x", log: "", final: true },
];
for (var i = 0; i < answers.length; i++) {
  routes[URL_] = { status: 200, body: answers[i] };
  timers.length = 0;
  document.dispatchEvent(new Event("DOMContentLoaded"));
  await settle();
  seen.push(steps());
}
done(seen);
""" % url)
    health, switch, running, older = result
    assert health == {"preflight": "done", "fetch": "done", "build": "done", "backup": "done", "switch": "done",
                      "health": "failed", "rollback": "done", "cleanup": "pending"}
    # The switch failed: the health check never ran.
    assert switch["switch"] == "failed" and switch["health"] == "pending" and switch["rollback"] == "failed"
    assert running["health"] == "failed" and running["rollback"] == "active"
    assert older["health"] == "failed" and older["rollback"] == "done"  # no failed_step: the health check


async def test_js_run_view_stops_polling_an_unreadable_run(tmp_path, admin_client, server):
    host = await _configured(admin_client, server)
    await _store_run(RUN_ID, host, status="failed")
    page = (await admin_client.get(f"/updates?run={RUN_ID}")).text
    url = f"GET /api/v1/updates/runs/{RUN_ID}"
    result = run_js(tmp_path, PAGE.replace("__TREE__", json.dumps(_tree(page))) + """
routes["%s"] = { status: 200, body: { status: "unknown", step: null, final: false, log: "",
                                       message: "The run's status file is missing." } };
document.dispatchEvent(new Event("DOMContentLoaded"));
await settle();
var el = document.querySelector("[data-update-run]");
var msg = el.querySelector("[data-run-message]");
done({ timers: timers.length, gets: fetchCalls.length, message: msg.hidden ? null : msg.className + "|" + msg.textContent,
       reload: !el.querySelector("[data-run-reload]").hidden, badge: el.querySelector("[data-run-status]").textContent });
""" % url)
    assert result["timers"] == 0 and result["gets"] == 1
    assert result["message"] == "callout error|The run's status file is missing."
    assert result["reload"] and result["badge"] == "Unknown"


async def test_the_running_callout_links_to_the_run_when_another_is_open(admin_client, server):
    host = await _configured(admin_client, server)
    older = "20261116-100000-abcdef"
    await _store_run(older, host, status="succeeded", finished_at="2026-11-16T10:05:00Z")
    await _store_run(RUN_ID, host)
    server.status[RUN_ID] = json.dumps({"id": RUN_ID, "status": "running", "step": "build", "from": FROM, "to": NEW,
                                        "branch": "main", "started_at": "2026-11-17T10:00:00Z", "finished_at": None,
                                        "message": None, "backup": None, "db_changed": False, "pid": 4242,
                                        "boot_id": server.boot_id, "heartbeat_at": "2026-11-17T10:00:01Z"})
    page = (await admin_client.get(f"/updates?run={older}")).text
    assert f'data-update-run="{older}"' in page
    assert "Its steps and log are shown above" not in page
    assert f'An upgrade is running. <a href="/updates?run={RUN_ID}">See its steps and log</a>' in page


async def test_the_confirm_dialog_says_when_the_backup_is_restored(admin_client, server):
    await _checked(admin_client, server)
    page = (await admin_client.get("/updates")).text
    assert "it rolls back to this version and restores the backup" not in page
    assert ("If the new version doesn't start, it rolls back to this version. If the new version already changed "
            "the database, the backup is restored too.") in page
