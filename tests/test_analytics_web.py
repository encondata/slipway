"""The Analytics page: the range control, each section's states, permission gating, escaping, table views,
and the chart hover layer in slipway.js (run against the fake DOM from test_review_web).

Everything is seeded relative to now, since the page reads the real clock. Nothing real is touched.
"""

from __future__ import annotations

import html
import json
import re
from datetime import timedelta
from pathlib import Path

from slipway.db.base import utcnow
from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Host, Instance, Repository
from tests.conftest import make_user
from tests.test_host_metrics import _add_host, _add_samples
from tests.test_review_web import SLIPWAY_JS, _client_with, run_js
from tests.test_updates_web import PAGE, _tree

EVIL_INSTANCE = "<img src=x onerror=alert(1)>"
EVIL_ERROR = "<script>alert(2)</script> build failed"
EVIL_MESSAGE = "Fix <b onmouseover=alert(3)>it</b>"
EVIL_HOST = "<svg onload=alert(4)>"


async def _seed_deploys() -> dict:
    """An instance with an evil name: a success two days ago, then a failure today, so it is failing now."""
    now = utcnow()
    async with get_sessionmaker()() as db:
        host = Host(name="prod-01", hostname="10.0.0.5", username="deploy")
        repo = Repository(github_id=7, full_name="acme/web", owner="acme", name="web", html_url="https://github.com/acme/web")
        db.add_all([host, repo])
        await db.flush()
        inst = Instance(name=EVIL_INSTANCE, slug="evil", repository_id=repo.id, host_id=host.id, branch="main")
        db.add(inst)
        await db.flush()
        ok = Deployment(instance_id=inst.id, status="succeeded", branch="main", created_at=now - timedelta(days=2),
                        started_at=now - timedelta(days=2), finished_at=now - timedelta(days=2) + timedelta(minutes=3))
        cancelled = Deployment(instance_id=inst.id, status="cancelled", branch="main", created_at=now - timedelta(days=1))
        bad = Deployment(instance_id=inst.id, status="failed", branch="main", created_at=now - timedelta(hours=1),
                         started_at=now - timedelta(hours=1), finished_at=now - timedelta(minutes=58),
                         error=EVIL_ERROR + "\nsecond line", commit_sha="0123456789abcdef0123456789abcdef01234567",
                         commit_message=EVIL_MESSAGE + "\n\nbody")
        db.add_all([ok, cancelled, bad])
        await db.commit()
        return {"instance": inst.id, "ok": ok.id, "bad": bad.id}


async def _seed_host(name: str = EVIL_HOST, *, hours: int = 6, gap_after: int | None = None) -> str:
    """A pinned host with a sample every 5 minutes for ``hours`` hours, missing an hour after ``gap_after``."""
    host_id = await _add_host(name)
    now = utcnow()
    samples = []
    for i in range(hours * 12):
        at = now - timedelta(minutes=5 * (hours * 12 - i))
        if gap_after is not None and gap_after * 12 <= i < (gap_after + 1) * 12:
            continue
        samples.append((at, 10 + i % 7, 40 + i % 5, 61.0))
    await _add_samples(host_id, samples)
    return str(host_id)


def _section(page: str, name: str) -> str:
    """One top-level section of the page, up to the next one."""
    start = page.find(f'data-section="{name}"')
    if start < 0:
        return ""
    ends = [i for i in (page.find("data-section=", start + 1), page.find("</main>", start)) if i >= 0]
    return page[start:min(ends)]


def _charts(page: str) -> list[dict]:
    return [json.loads(html.unescape(m)) for m in re.findall(r"data-chart='([^']*)'", page)]


def _points(page: str) -> list[dict]:
    return [json.loads(html.unescape(m)) for m in re.findall(r"data-points='([^']*)'", page)]


# ------------------------------------------------------------------- range control


async def test_range_links_default_to_30_days(admin_client):
    for query, active in (("", 30), ("?days=7", 7), ("?days=90", 90), ("?days=14", 30), ("?days=abc", 30), ("?days=-7", 30)):
        resp = await admin_client.get(f"/analytics{query}")
        assert resp.status_code == 200
        page = resp.text
        nav = re.search(r'<nav class="segmented" aria-label="Time range">.*?</nav>', page, re.S).group(0)
        assert re.findall(r'href="/analytics\?days=(\d+)"', nav) == ["7", "30", "90"]
        assert re.findall(r'href="/analytics\?days=(\d+)" class="active" aria-current="page"', nav) == [str(active)]
        assert f"over the last {active} days" in page


async def test_logs_keeps_its_placeholder(admin_client):
    page = (await admin_client.get("/logs")).text
    assert "Coming soon" in page
    page = (await admin_client.get("/analytics")).text
    assert "Coming soon" not in page and "mobile analytics" not in page.lower()
    assert "<h1>Analytics</h1>" in page


# ------------------------------------------------------------------- empty states


async def test_empty_states_without_deploys_or_hosts(admin_client):
    page = (await admin_client.get("/analytics?days=7")).text
    assert "No deploys in the last 7 days" in _section(page, "deploys")
    assert "No checked hosts yet" in _section(page, "hosts")
    assert "data-chart" not in page


async def _hosts_with_poll(client, interval: str, monkeypatch) -> str:
    from slipway.core.config import get_settings
    monkeypatch.setenv("SLIPWAY_HOST_POLL_INTERVAL", interval)
    get_settings.cache_clear()
    try:
        return _section((await client.get("/analytics")).text, "hosts")
    finally:
        get_settings.cache_clear()


async def test_host_history_empty_state_names_the_check_interval(admin_client, monkeypatch):
    await _add_host("quiet")
    await _add_host("unpinned", pinned=False)
    hosts = await _hosts_with_poll(admin_client, "300", monkeypatch)
    assert "No host history yet" in hosts
    assert "Host history starts with the next health check; hosts are checked every 5 minutes." in hosts
    assert "unpinned" not in hosts
    assert "hosts are checked every 90 seconds." in await _hosts_with_poll(admin_client, "90", monkeypatch)
    hosts = await _hosts_with_poll(admin_client, "0", monkeypatch)
    assert "Background checks are off, so run Check on the host page." in hosts
    monkeypatch.undo()
    from slipway.core.config import get_settings
    get_settings.cache_clear()


async def test_a_host_without_samples_next_to_one_with_samples(admin_client):
    await _seed_host("busy")
    await _add_host("idle")
    hosts = _section((await admin_client.get("/analytics?days=7")).text, "hosts")
    idle = hosts[hosts.index(">idle</a>"):]
    assert "No checks in the last 7 days." in idle and "data-chart" not in idle.split('class="card host-trend"')[0]


# ------------------------------------------------------------------- deploys


async def test_deploys_section_with_data(admin_client):
    ids = await _seed_deploys()
    page = (await admin_client.get("/analytics?days=7")).text
    deploys = _section(page, "deploys")
    for label in ("Deploys", "Success rate", "Median time", "Time to recover"):
        assert f"</svg> {label}</div>" in deploys
    assert "Higher is better" in deploys and "Lower is better" in deploys
    assert "50%" in deploys  # one success, one failure
    assert "No deploys in the previous 7 days" in deploys

    # The stacked bars: a legend naming each series, a <title> per day for no-JS readers, and a table view.
    assert re.search(r'chart-swatch ok[^>]*></i>Succeeded</li><li><i class="chart-swatch fail[^>]*></i>Failed</li>'
                     r'<li><i class="chart-swatch cancel[^>]*></i>Cancelled</li>', deploys)
    bars = [c for c in _charts(deploys) if c["kind"] == "bars"]
    assert len(bars) == 1 and len(bars[0]["rows"]) == 7
    assert [s["name"] for s in bars[0]["series"]] == ["Succeeded", "Failed", "Cancelled"]
    assert sum(sum(r["values"]) for r in bars[0]["rows"]) == 3
    assert len(re.findall(r"<title>[^<]+: \d+ succeeded, \d+ failed, \d+ cancelled</title>", deploys)) == 7
    assert deploys.count('<details class="table-view">') == 1
    assert len(re.findall(r'class="chart-seg (ok|fail|cancel)"', deploys)) == 3

    # By instance: the name escaped, Failing, and the last deploy linking to it.
    assert html.escape(EVIL_INSTANCE, quote=False) in deploys and EVIL_INSTANCE not in deploys
    assert '<span class="badge error">Failing</span>' in deploys
    assert f'href="/deployments/{ids["bad"]}"' in deploys
    assert f'href="/instances/{ids["instance"]}"' in deploys
    assert "acme/web · prod-01" in deploys

    # Recent failures: first error line and commit message escaped, the second line left out.
    assert html.escape(EVIL_ERROR, quote=False) in deploys and EVIL_ERROR not in deploys
    assert "second line" not in deploys
    assert "0123456" in deploys and html.escape(EVIL_MESSAGE, quote=False) in deploys and EVIL_MESSAGE not in deploys
    assert "body" not in re.sub(r"<[^>]+>", "", deploys.split("Recent failures")[1]).split("By person")[0]

    # By person: nobody triggered these.
    assert "<td>Deleted user</td><td class=\"num\">3</td><td class=\"num\">1</td>" in deploys


async def test_stat_deltas_against_the_previous_window(admin_client):
    now = utcnow()
    async with get_sessionmaker()() as db:
        host = Host(name="h", hostname="h", username="u")
        repo = Repository(github_id=9, full_name="a/b", owner="a", name="b", html_url="https://github.com/a/b")
        db.add_all([host, repo])
        await db.flush()
        inst = Instance(name="api", slug="api", repository_id=repo.id, host_id=host.id, branch="main")
        db.add(inst)
        await db.flush()
        for created, status in [(now - timedelta(days=9), "succeeded"), (now - timedelta(days=9, hours=1), "failed"),
                                (now - timedelta(hours=3), "succeeded"), (now - timedelta(hours=2), "succeeded"),
                                (now - timedelta(hours=1), "succeeded")]:
            db.add(Deployment(instance_id=inst.id, status=status, branch="main", created_at=created,
                              started_at=created, finished_at=created + timedelta(minutes=2)))
        await db.commit()
    deploys = _section((await admin_client.get("/analytics?days=7")).text, "deploys")
    assert re.search(r'class="delta good">.*?delta-up.*?\+50%</span>\s*<span>vs previous 7 days</span>', deploys, re.S)
    assert re.search(r'class="delta good">.*?delta-up.*?\+50 pts</span>', deploys, re.S)
    assert re.search(r'class="delta ">.*?delta-flat.*?No change</span>', deploys, re.S)  # median 2m both times


async def test_deploy_tables_scroll_inside_their_wrapper(admin_client):
    await _seed_deploys()
    deploys = _section((await admin_client.get("/analytics")).text, "deploys")
    assert deploys.count('class="card-body flush table-wrap"') == 2
    assert '<div class="table-wrap"><table class="table">' in deploys.replace("\n", "").replace("  ", "")


# ------------------------------------------------------------------- hosts


async def test_hosts_section_draws_one_card_per_pinned_host(admin_client):
    host_id = await _seed_host(hours=6, gap_after=2)
    hosts = _section((await admin_client.get("/analytics?days=7")).text, "hosts")
    assert f'href="/hosts/{host_id}"' in hosts
    assert html.escape(EVIL_HOST, quote=False) in hosts and EVIL_HOST not in hosts
    assert "4 CPUs · 8.0 GB memory · Not checked yet" in hosts
    for name in ("CPU load", "Memory", "Disk"):
        assert f"<h3>{name}</h3>" in hosts
    lines = [c for c in _charts(hosts) if c["kind"] == "line"]
    assert [c["key"] for c in lines] == ["cpu", "mem", "disk"]
    assert {c["points"] for c in lines} == {f"points-{host_id}"} and f'id="points-{host_id}"' in hosts
    (points,) = _points(hosts)
    assert not points["hourly"] and "cpu_peak" not in points and points["span"] == 7 * 86400
    assert len(points["t"]) == len(points["cpu"]) == len(points["disk"]) == 6 * 12 - 12
    # The missing hour splits every line into two runs.
    assert hosts.count('<path class="chart-line"') == 6
    assert "<dt>Latest</dt><dd>61%</dd>" in hosts  # disk
    # One table view for the host's charts, hourly at this range.
    assert hosts.count('<details class="table-view">') == 1
    assert "<th>Hour</th>" in hosts and "<th class=\"num\">Disk max</th>" in hosts
    # aria-labels name the chart; the host name in them is escaped too.
    assert re.search(r'aria-label="CPU load on [^"<>]*, last 7 days, 0 to 100%\. The values are in the table below\."', hosts)


async def test_long_ranges_use_hourly_points_with_peaks(admin_client):
    await _seed_host("db-01", hours=4)
    hosts = _section((await admin_client.get("/analytics?days=30")).text, "hosts")
    assert [c["key"] for c in _charts(hosts) if c["kind"] == "line"] == ["cpu", "mem", "disk"]
    (points,) = _points(hosts)
    assert points["hourly"] and len(points["t"]) == len(points["cpu_peak"]) == len(points["mem_peak"]) in (4, 5)
    assert "disk_peak" not in points  # an hour's disk figure is its peak already
    assert "<th>Day</th>" in hosts


# ------------------------------------------------------------------- permissions


async def test_sections_follow_permissions(make_client):
    await make_user("admin@example.com")
    await _seed_deploys()
    await _seed_host("web-01")

    nothing = await _client_with(make_client, "plain@example.com", [])
    resp = await nothing.get("/analytics")
    assert resp.status_code == 403 and "analytics:read" in resp.text

    only = await _client_with(make_client, "only@example.com", ["analytics:read"])
    page = (await only.get("/analytics")).text
    assert not _section(page, "deploys") and not _section(page, "hosts")
    assert "Your roles can't see either." in html.unescape(page)

    dep = await _client_with(make_client, "dep@example.com", ["analytics:read", "deployments:read"])
    page = (await dep.get("/analytics")).text
    assert _section(page, "deploys") and not _section(page, "hosts")
    assert 'href="/instances/' not in page  # no instances:read: the name is plain text

    hst = await _client_with(make_client, "hst@example.com", ["analytics:read", "hosts:read"])
    page = (await hst.get("/analytics")).text
    assert _section(page, "hosts") and not _section(page, "deploys")
    assert "web-01" in page and EVIL_INSTANCE not in page


async def test_viewer_sees_both_sections(make_client):
    await make_user("admin@example.com")
    await _seed_deploys()
    await _seed_host("web-01")
    await make_user("viewer@example.com", roles=["viewer"])
    from tests.conftest import login
    c = make_client()
    await login(c, "viewer@example.com")
    page = (await c.get("/analytics")).text
    assert _section(page, "deploys") and _section(page, "hosts")


# ------------------------------------------------------------------- hover layer

HOVER = PAGE.replace('location.pathname = "/updates";', 'location.pathname = "/analytics";') + """
El.prototype.getBoundingClientRect = function () { return { left: 100, top: 0, width: 700, height: 160 }; };
function tipOf(plot) {
  var tip = plot.querySelector(".chart-tip");
  return { hidden: tip.hidden, text: tip.children.map(function (c) { return c.textContent; }), flip: tip.className.indexOf("flip") >= 0,
           left: tip.style.left };
}
document.dispatchEvent(new Event("DOMContentLoaded"));
var plots = document.querySelectorAll("[data-chart]");
"""


async def test_js_bar_tooltip_follows_the_pointer_and_the_keyboard(admin_client, tmp_path):
    await _seed_deploys()
    page = (await admin_client.get("/analytics?days=7")).text
    spec = next(c for c in _charts(page) if c["kind"] == "bars")
    result = run_js(tmp_path, HOVER.replace("__TREE__", json.dumps(_tree(page))) + """
var bars = plots[0];
var hidden = tipOf(bars).hidden;
user("pointermove", bars, { clientX: 100 + 700 * (6.5 / 7) });  // today, the last slot
var last = tipOf(bars);
var active = bars.querySelectorAll(".is-active").map(function (g) { return g.getAttribute("data-i"); });
user("pointermove", bars, { clientX: 100 + 5 });
var first = tipOf(bars);
user("pointerleave", bars);
var left = { hidden: tipOf(bars).hidden, active: bars.querySelectorAll(".is-active").length, dim: bars.className.indexOf("has-active") >= 0 };
bars.focus(); user("focus", bars);
var focused = tipOf(bars);
var keys = [];
["ArrowLeft", "Home", "ArrowLeft", "End", "ArrowRight", "PageUp"].forEach(function (k) {
  user("keydown", bars, { key: k }); keys.push(tipOf(bars).text[0]);
});
user("keydown", bars, { key: "Escape" });
done({ after: bars.querySelectorAll("title").length, hidden: hidden, last: last, active: active,
       first: first, left: left, focused: focused, keys: keys, escaped: tipOf(bars).hidden });
""")
    labels = [r["label"] for r in spec["rows"]]
    today = spec["rows"][-1]["values"]
    assert page.count("<title>") - page.count("</title>") == 0 and _section(page, "deploys").count("<title>") == 7
    assert result["after"] == 0  # the browser's own tooltips make way for the layer's
    assert result["hidden"] is True
    assert result["last"]["text"] == [labels[-1], f"{today[0]}Succeeded", f"{today[1]}Failed", f"{today[2]}Cancelled"]
    assert result["last"]["flip"] and result["active"] == ["6"]
    assert result["first"]["text"][0] == labels[0] and not result["first"]["flip"]
    assert result["left"] == {"hidden": True, "active": 0, "dim": False}
    assert result["focused"]["text"][0] == labels[-1]
    assert result["keys"] == [labels[5], labels[0], labels[0], labels[6], labels[6], labels[5]]
    assert result["escaped"] is True


async def test_js_line_tooltip_snaps_to_the_nearest_point(admin_client, tmp_path):
    await _seed_host("web-01", hours=2)
    page = (await admin_client.get("/analytics?days=7")).text
    (cpu,) = _points(page)
    cpu["v"] = cpu["cpu"]
    result = run_js(tmp_path, HOVER.replace("__TREE__", json.dumps(_tree(page))) + """
var cpu = plots.filter(function (p) { return JSON.parse(p.getAttribute("data-chart")).key === "cpu"; })[0];
user("pointermove", cpu, { clientX: 100 + 700 });  // the right edge: the newest sample
var tip = tipOf(cpu);
var cross = cpu.querySelector(".chart-cross"), dot = cpu.querySelector(".chart-dot");
var shown = { cross: !cross.hidden, crossLeft: cross.style.left, dotTop: dot.style.top };
user("pointermove", cpu, { clientX: 100 });  // the left edge: the oldest sample, a week of nothing away
var oldest = tipOf(cpu).text;
user("pointerleave", cpu);
done({ tip: tip, shown: shown, oldest: oldest, hidden: tipOf(cpu).hidden && cross.hidden && dot.hidden });
""")
    def fmt(v: float) -> str:
        return f"{v:.1f}%" if v < 10 else f"{round(v)}%"
    tip = result["tip"]
    assert tip["text"][1] == fmt(cpu["v"][-1]) + "CPU load" and len(tip["text"]) == 2
    assert re.fullmatch(r"(Sun|Mon|Tue|Wed|Thu|Fri|Sat) \d{1,2} [A-Z][a-z]{2}, \d\d:\d\d UTC", tip["text"][0])
    assert tip["flip"]
    assert result["shown"]["cross"] and result["shown"]["crossLeft"] == tip["left"]
    assert float(result["shown"]["dotTop"].rstrip("%")) == 100 - cpu["v"][-1]
    assert result["oldest"][1] == fmt(cpu["v"][0]) + "CPU load"
    assert result["hidden"] is True


async def test_js_hourly_tooltip_shows_the_hour_and_its_peak(admin_client, tmp_path):
    await _seed_host("web-01", hours=3)
    page = (await admin_client.get("/analytics?days=90")).text
    result = run_js(tmp_path, HOVER.replace("__TREE__", json.dumps(_tree(page))) + """
var mem = plots.filter(function (p) { return JSON.parse(p.getAttribute("data-chart")).key === "mem"; })[0];
user("keydown", mem, { key: "End" });
done({ text: tipOf(mem).text });
""")
    head, avg, peak = result["text"]
    assert re.fullmatch(r"\w{3} \d{1,2} \w{3}, \d\d:00–\d\d:00 UTC", head)
    assert avg.endswith("Memory, average") and peak.endswith("Peak")


def test_js_chart_layer_sets_text_only():
    source = SLIPWAY_JS.read_text()
    layer = source[source.index("// -------------------------------------------------------------- charts"):source.index("// -------------------------------------------------------------- boot")]
    assert "innerHTML" not in layer and "insertAdjacentHTML" not in layer and "outerHTML" not in layer
    assert "textContent" in layer


def test_charts_template_has_no_external_assets():
    charts = (Path(SLIPWAY_JS).parents[2] / "templates" / "_charts.html").read_text()
    assert "http" not in charts and "<script" not in charts


def test_dense_lines_are_thinned_but_keep_every_peak():
    from slipway.web import pages
    run = [(i / 2016, 20.0 + (i % 3)) for i in range(2016)]
    run[1000] = (1000 / 2016, 97.0)
    run[1500] = (1500 / 2016, 0.5)
    thin = pages._thin(run)
    assert len(thin) <= 2 * pages.PLOT_COLUMNS + 2
    assert thin[0] == run[0] and thin[-1] == run[-1] and run[1000] in thin and run[1500] in thin
    assert thin == sorted(thin)
    short = run[:100]
    assert pages._thin(short) == short
