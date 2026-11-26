"""The Deployments page (one group per instance) and the History page (every deployment, a page at a time)."""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime, timedelta

from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Instance
from slipway.web.pages import GROUP_EARLIER, HISTORY_PAGE_SIZE
from tests.conftest import login, make_user
from tests.test_review_web import _add_repo, _client_with, run_js
from tests.test_updates_web import PAGE, _tree

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def _sha(n: int) -> str:
    return f"{n:07x}" + "a" * 33


async def _instance(admin_client, name: str, host: dict, repo_id: str) -> str:
    return (await admin_client.post("/api/v1/instances", json={
        "name": name, "repository_id": repo_id, "host_id": host["id"], "branch": "main", "deploy": False,
    })).json()["id"]


async def _deploys(instance_id: str, statuses: list[str], start: int = 0, live: str | None = None) -> list[str]:
    """One deployment per status, oldest first, an hour apart from T0 + start hours."""
    ids = []
    async with get_sessionmaker()() as db:
        for n, status in enumerate(statuses):
            dep = Deployment(instance_id=uuid.UUID(instance_id), status=status, branch="main",
                             commit_sha=_sha(start + n), commit_message=f"commit {start + n}",
                             created_at=T0 + timedelta(hours=start + n), log="build log text")
            db.add(dep)
            await db.flush()
            ids.append(str(dep.id))
        if live:
            (await db.get(Instance, uuid.UUID(instance_id))).current_commit_sha = live
        await db.commit()
    return ids


async def _world(admin_client) -> dict:
    """alpha: eight deployments, the latest failed. beta: one. gamma: an older one still building under a newer one.

    An instance has at most one deployment queued or building (a unique index), so gamma's busy one is older.
    """
    repo_id = await _add_repo(51, "shop-front")
    host = (await admin_client.post("/api/v1/hosts", json={
        "name": "rack-07", "hostname": "10.1.2.3", "username": "deploy"})).json()
    ids = {name: await _instance(admin_client, name, host, repo_id) for name in ("alpha", "beta", "gamma")}
    ids["alpha-deps"] = await _deploys(ids["alpha"], ["succeeded"] * 7 + ["failed"], live=_sha(6))
    ids["beta-deps"] = await _deploys(ids["beta"], ["succeeded"], start=20)
    ids["gamma-deps"] = await _deploys(ids["gamma"], ["succeeded", "running", "succeeded"], start=2)
    ids["repo"], ids["host"] = repo_id, host["id"]
    return ids


def _nav(page: str) -> str:
    return re.search(r'<nav class="hsl-nav".*?</nav>', page, re.S).group(0)


def _tbodies(page: str) -> list[str]:
    return re.findall(r"<tbody.*?</tbody>", page, re.S)


# ----------------------------------------------------------------------- /deployments


async def test_one_group_per_instance_busy_then_failed_then_newest(admin_client):
    ids = await _world(admin_client)
    page = (await admin_client.get("/deployments")).text
    assert "<h1>Deployments</h1>" in page
    assert 'href="/deployments/history"' in page
    rows = re.findall(r'<tr class="dep-row".*?</tr>', page, re.S)
    names = [re.search(r"<strong>(\w+)</strong>", r).group(1) for r in rows]
    assert names == ["gamma", "alpha", "beta"]  # building or queued, then failed, then the rest newest first
    assert "build log text" not in page


async def test_a_group_shows_its_latest_and_folds_the_earlier_ones(admin_client):
    ids = await _world(admin_client)
    page = (await admin_client.get("/deployments")).text
    alpha = ids["alpha-deps"]
    fold = f"dep-earlier-{ids['alpha']}"
    group, earlier = (b for b in _tbodies(page) if f'"{fold}"' in b)
    assert f'href="/deployments/{alpha[-1]}"' in group and "Failed" in group
    assert 'Live: <span class="mono">0000006</span>' in group  # still running the last good commit
    assert f'<tbody class="dep-earlier" id="{fold}" hidden>' in earlier
    shown = re.findall(r'href="/deployments/([0-9a-f-]{36})"', earlier)
    assert shown == list(reversed(alpha[-1 - GROUP_EARLIER:-1]))  # the next five, newest first
    assert "2 more in History" in earlier
    assert f'href="/deployments/history?instance={ids["alpha"]}"' in earlier


async def test_anything_else_building_or_queued_stays_in_view(admin_client):
    ids = await _world(admin_client)
    page = (await admin_client.get("/deployments")).text
    fold = f"dep-earlier-{ids['gamma']}"
    group, earlier = (b for b in _tbodies(page) if f'"{fold}"' in b)
    newest, running, oldest = reversed(ids["gamma-deps"])
    assert f"/deployments/{newest}" in group
    assert "Also building" in group and f"/deployments/{running}" in group
    assert f"/deployments/{oldest}" in earlier and f"/deployments/{running}" not in earlier
    assert "All 3 in History" in earlier


async def test_an_instance_with_one_deployment_has_nothing_to_open(admin_client):
    ids = await _world(admin_client)
    page = (await admin_client.get("/deployments")).text
    assert f"dep-earlier-{ids['beta']}" not in page
    beta = next(b for b in _tbodies(page) if f"/deployments/{ids['beta-deps'][0]}" in b)
    assert "data-expand" not in beta


async def test_empty_deployments_page(admin_client, make_client):
    page = (await admin_client.get("/deployments")).text
    assert "No deployments yet" in page and 'href="/instances/new"' in page
    viewer = await _client_with(make_client, "deps@example.com", ["deployments:read"])
    page = (await viewer.get("/deployments")).text
    assert "No deployments yet" in page and 'href="/instances/new"' not in page


async def test_js_opens_and_closes_the_earlier_deployments(admin_client, tmp_path):
    ids = await _world(admin_client)
    page = (await admin_client.get("/deployments")).text
    fold = f"dep-earlier-{ids['alpha']}"
    result = run_js(tmp_path, PAGE.replace("__TREE__", json.dumps(_tree(page))) + """
var body = document.getElementById("%s");
var toggle = document.querySelector('button[aria-controls="%s"]');
var before = body.hidden;
user("click", toggle, { button: 0 });
var opened = [body.hidden, toggle.getAttribute("aria-expanded")];
user("click", toggle, { button: 0 });
done({ before: before, opened: opened, closed: body.hidden });
""" % (fold, fold))
    assert result == {"before": True, "opened": [False, "true"], "closed": True}


# ----------------------------------------------------------------------- /deployments/history


async def test_history_lists_every_deployment_flat(admin_client):
    ids = await _world(admin_client)
    page = (await admin_client.get("/deployments/history")).text
    assert "<h1>History</h1>" in page and '<a href="/deployments">Deployments</a>' in page
    listed = re.findall(r'href="/deployments/([0-9a-f-]{36})"', page)
    everything = ids["alpha-deps"] + ids["beta-deps"] + ids["gamma-deps"]
    assert sorted(listed) == sorted(everything)
    assert listed[0] == ids["beta-deps"][0]  # newest first
    assert "pager" not in page  # one page only


async def test_history_filters_by_status_and_instance(admin_client):
    ids = await _world(admin_client)
    page = (await admin_client.get("/deployments/history?status=failed")).text
    assert re.findall(r'href="/deployments/([0-9a-f-]{36})"', page) == [ids["alpha-deps"][-1]]

    page = (await admin_client.get(f"/deployments/history?instance={ids['gamma']}")).text
    assert sorted(re.findall(r'href="/deployments/([0-9a-f-]{36})"', page)) == sorted(ids["gamma-deps"])
    assert 'class="chip filter-chip" href="/deployments/history"' in page  # clears the instance
    assert f'href="/deployments/history?status=failed&amp;instance={ids["gamma"]}"' in page  # status keeps it

    page = (await admin_client.get(f"/deployments/history?status=failed&instance={ids['beta']}")).text
    assert "No deployments with this status" in page and 'href="/instances/new"' not in page


async def test_history_ignores_unknown_or_malformed_params(admin_client):
    ids = await _world(admin_client)
    total = len(ids["alpha-deps"] + ids["beta-deps"] + ids["gamma-deps"])
    for query in ("instance=not-a-uuid", f"instance={uuid.uuid4()}", "page=abc", "page=-3", "page=999"):
        r = await admin_client.get(f"/deployments/history?{query}")
        assert r.status_code == 200, query
        assert len(re.findall(r'href="/deployments/[0-9a-f-]{36}"', r.text)) == total, query


async def test_history_pages(admin_client):
    ids = await _world(admin_client)
    await _deploys(ids["beta"], ["succeeded"] * HISTORY_PAGE_SIZE, start=100)
    total = HISTORY_PAGE_SIZE + 12
    first = (await admin_client.get("/deployments/history")).text
    assert len(re.findall(r'href="/deployments/[0-9a-f-]{36}"', first)) == HISTORY_PAGE_SIZE
    assert f"1–{HISTORY_PAGE_SIZE} of {total}" in first
    assert 'href="/deployments/history?page=2" rel="next">Older' in first and 'rel="prev"' not in first

    second = (await admin_client.get("/deployments/history?page=2")).text
    assert len(re.findall(r'href="/deployments/[0-9a-f-]{36}"', second)) == 12
    assert f"{HISTORY_PAGE_SIZE + 1}–{total} of {total}" in second
    assert 'href="/deployments/history" rel="prev">Newer' in second and 'rel="next"' not in second
    assert ids["alpha-deps"][0] in second  # the oldest is last


# ----------------------------------------------------------------------- sidebar and permissions


async def test_sidebar_history_item_and_the_active_one(admin_client):
    ids = await _world(admin_client)
    for path, active in (("/deployments", "/deployments"), ("/deployments/history", "/deployments/history"),
                         (f"/deployments/{ids['beta-deps'][0]}", "/deployments"), ("/hosts", "/hosts")):
        nav = _nav((await admin_client.get(path)).text)
        assert re.findall(r'<a href="([^"]+)" class="[^"]*" aria-current="page"', nav) == [active], path
        assert '<a href="/deployments/history" class="' in nav and " nav-sub" in nav
        assert nav.index('href="/deployments"') < nav.index('href="/deployments/history"') < nav.index('href="/hosts"')
    overview = (await admin_client.get("/")).text
    assert '<a class="link-more" href="/deployments/history">' in overview


async def test_both_pages_need_deployments_read(admin_client, make_client):
    await _world(admin_client)
    other = await _client_with(make_client, "hosts@example.com", ["hosts:read"])
    for path in ("/deployments", "/deployments/history"):
        r = await other.get(path)
        assert r.status_code == 403 and "deployments:read" in r.text, path
    nav = _nav((await other.get("/hosts")).text)
    assert "/deployments" not in nav


async def test_deployments_read_alone_hides_what_it_cannot_open(admin_client, make_client):
    ids = await _world(admin_client)
    c = await _client_with(make_client, "deps@example.com", ["deployments:read"])
    for path in ("/deployments", "/deployments/history", f"/deployments/history?instance={ids['alpha']}"):
        page = (await c.get(path)).text
        assert "alpha" in page and "beta" in page or "?instance=" in path, path
        assert 'href="/instances/' not in page, path
        assert "rack-07" not in page and "shop-front" not in page, path
    await make_user("viewer@example.com", roles=["viewer"])
    viewer = make_client()
    await login(viewer, "viewer@example.com")
    page = (await viewer.get("/deployments")).text
    assert f'href="/instances/{ids["alpha"]}"' in page and "rack-07" in page and "acme/shop-front" in page
