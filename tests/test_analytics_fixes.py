"""Regression tests for the analytics review: equal windows, name gating, deleted users, restart-cut
durations, recovery keys and bounds, the created_at index, host history retention, and the page's labels,
tooltips and accessibility. Everything is seeded straight into the database; nothing real is touched.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sqlite3
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import delete, select

from slipway.core.permissions import PERMISSION_DESCRIPTIONS, Perm
from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Host, HostSample, User
from slipway.services import analytics, host_metrics
from slipway.web import pages
from tests.conftest import make_user
from tests.test_analytics import _dep, _seed_instances, _stats, at
from tests.test_analytics_web import HOVER, _charts, _section, _seed_deploys, _seed_host
from tests.test_host_metrics import NOW as HOST_NOW
from tests.test_host_metrics import ROOT, _add_host, _add_samples, _alembic, _count, _hourly
from tests.test_review_web import SLIPWAY_JS, _client_with, run_js
from tests.test_updates_web import _tree

CSS = Path(SLIPWAY_JS).parents[1] / "css" / "slipway.css"


# ------------------------------------------------------------------ deploy stats


async def test_previous_window_is_as_long_as_this_one():
    """One deploy a day at 12:00, just after midnight: this window and the one before hold the same count."""
    web, _ = await _seed_instances()
    now = datetime(2026, 11, 20, 0, 30, tzinfo=UTC)
    async with get_sessionmaker()() as db:
        db.add_all(_dep(web, "succeeded", datetime(2026, 11, d, 12, tzinfo=UTC), 2) for d in range(1, 20))
        await db.commit()
    prev_start, start, end = analytics.window(7, now)
    assert start - prev_start == end - start
    stats = await _stats(days=7, now=now)
    t = stats["totals"]
    assert t["deploys"] == t["previous"]["deploys"] == 6
    assert len(stats["by_day"]) == 7 and stats["by_day"][0]["date"] == date(2026, 11, 14)
    assert pages._deploy_tiles(t, 7)["deploys"]["text"] == "No change"


async def test_by_day_adds_up_to_the_deploy_count_while_deploys_run():
    web, _ = await _seed_instances()
    async with get_sessionmaker()() as db:
        db.add_all([_dep(web, "succeeded", at(17, 8), 2), _dep(web, "running", at(17, 10)), _dep(web, "queued", at(17, 11))])
        await db.commit()
    stats = await _stats()
    t = stats["totals"]
    assert sum(d["succeeded"] + d["failed"] + d["cancelled"] for d in stats["by_day"]) == t["deploys"] == 1
    assert (t["running"], t["queued"]) == (1, 1)
    assert sum(r["deploys"] for r in stats["by_instance"]) == 1
    assert stats["by_instance"][0]["last_deploy"]["status"] == "queued"


async def test_deploys_by_a_deleted_user_are_not_called_automatic():
    web, _ = await _seed_instances()
    carol = await make_user("carol@example.com", roles=["developer"])
    async with get_sessionmaker()() as db:
        db.add(_dep(web, "failed", at(17, 9), 1, carol))
        await db.commit()
        await db.execute(delete(User).where(User.id == carol.id))
        await db.commit()
    (person,) = (await _stats())["by_person"]
    assert person == {"id": None, "name": "Deleted user", "deploys": 1, "failed": 1}


async def test_durations_leave_out_deploys_a_restart_cut_off():
    web, _ = await _seed_instances()
    async with get_sessionmaker()() as db:
        db.add_all([
            _dep(web, "succeeded", at(16, 9), 2),
            _dep(web, "succeeded", at(16, 10), 2),
            # Killed while running on the 15th; Slipway came back a day and a half later.
            _dep(web, "failed", at(15, 9), 60 * 36, error=analytics.RESTART_ERROR),
        ])
        await db.commit()
    stats = await _stats()
    t = stats["totals"]
    assert (t["median_seconds"], t["p90_seconds"]) == (120, 120)
    assert t["failed"] == 1  # still counted as a failure
    assert stats["by_instance"][0]["median_seconds"] == 120


def test_restart_error_matches_the_deployer():
    source = (ROOT / "slipway" / "services" / "deployer.py").read_text()
    assert f'dep.error = "{analytics.RESTART_ERROR}"' in source


async def test_recovery_belongs_to_the_window_its_success_was_created_in():
    """A success created before the window's start that finished after it recovers the previous window."""
    web, _ = await _seed_instances()
    async with get_sessionmaker()() as db:
        db.add_all([
            _dep(web, "failed", at(10, 20), 5),
            _dep(web, "succeeded", at(10, 23, 50), 10),  # finishes 11-11 00:00, the window's start
        ])
        await db.commit()
    t = (await _stats())["totals"]
    assert t["deploys"] == 0 and t["mttr_seconds"] is None
    assert t["previous"]["mttr_seconds"] == (at(11, 0) - at(10, 20, 5)).total_seconds()


async def test_recovery_reads_only_the_history_it_needs():
    web, _ = await _seed_instances()
    async with get_sessionmaker()() as db:
        # A long history, ending in a success in September...
        db.add_all(
            _dep(web, "failed" if i % 2 else "succeeded", datetime(2025, 1, 1, tzinfo=UTC) + timedelta(hours=i), 1)
            for i in range(41)
        )
        db.add(_dep(web, "succeeded", at(1, 9, month=9), 1))
        # ...then a failure left open at the previous window's start, recovered in this window.
        db.add_all([_dep(web, "failed", at(1, 9, month=10), 1), _dep(web, "succeeded", at(12, 9), 1)])
        await db.commit()
    prev_start, _, end = analytics.window(7, at(17, 12))
    async with get_sessionmaker()() as db:
        rows = await analytics._recovery_rows(db, prev_start, end)
    assert len(rows) == 3  # September's success, October's failure and the recovery
    t = (await _stats())["totals"]
    assert t["mttr_seconds"] == (at(12, 9, 1) - at(1, 9, 1, month=10)).total_seconds()


def test_deployments_are_indexed_by_creation_time(tmp_path):
    assert "ix_deployments_created_at" in {ix.name for ix in Deployment.__table__.indexes}
    url = f"sqlite+aiosqlite:///{tmp_path}/m.db"
    _alembic(url, "upgrade", "head")
    with sqlite3.connect(tmp_path / "m.db") as conn:
        assert "ix_deployments_created_at" in {row[1] for row in conn.execute("PRAGMA index_list(deployments)")}
    _alembic(url, "downgrade", "0006")
    with sqlite3.connect(tmp_path / "m.db") as conn:
        assert "ix_deployments_created_at" not in {row[1] for row in conn.execute("PRAGMA index_list(deployments)")}


# ------------------------------------------------------------------ names and permissions


async def _api_instance(client) -> dict:
    r = await client.get("/api/v1/analytics/deploys?days=7")
    assert r.status_code == 200, r.text
    (row,) = r.json()["by_instance"]
    return row


async def test_api_hides_repository_and_host_names_without_their_permissions(make_client):
    await make_user("admin@example.com")
    await _seed_deploys()
    plain = await _client_with(make_client, "plain@example.com", ["deployments:read", "analytics:read"])
    row = await _api_instance(plain)
    assert row["repository"] is None and row["host"] is None
    assert "prod-01" not in (await plain.get("/api/v1/analytics/deploys?days=7")).text
    repos = await _client_with(make_client, "repos@example.com", ["deployments:read", "analytics:read", "repos:read"])
    assert ((row := await _api_instance(repos))["repository"], row["host"]) == ("acme/web", None)
    both = await _client_with(make_client, "both@example.com",
                              ["deployments:read", "analytics:read", "repos:read", "hosts:read"])
    assert ((row := await _api_instance(both))["repository"], row["host"]) == ("acme/web", "prod-01")


async def test_page_hides_repository_and_host_names_without_their_permissions(make_client):
    await make_user("admin@example.com")
    await _seed_deploys()
    plain = await _client_with(make_client, "plain@example.com", ["deployments:read", "analytics:read"])
    deploys = _section((await plain.get("/analytics?days=7")).text, "deploys")
    assert "Failing" in deploys  # the table is there
    assert "acme/web" not in deploys and "prod-01" not in deploys and " · " not in deploys
    hosts = await _client_with(make_client, "hosts@example.com", ["deployments:read", "analytics:read", "hosts:read"])
    deploys = _section((await hosts.get("/analytics?days=7")).text, "deploys")
    assert "<small>prod-01</small>" in deploys and "acme/web" not in deploys


def test_analytics_permission_says_what_it_shows():
    text = PERMISSION_DESCRIPTIONS[Perm.ANALYTICS_READ]
    assert "mobile" not in text.lower()
    assert "deploy" in text and "host" in text and "deployments:read" in text and "hosts:read" in text


# ------------------------------------------------------------------ host history


async def test_retention_rolls_up_samples_older_than_the_raw_window_before_deleting_them():
    """Retention off for 10 days: the next run still rolls up every day before pruning the raw samples."""
    host = await _add_host("a")
    await _add_samples(host, [(HOST_NOW - timedelta(days=d), 10.0 + d, 50.0, None) for d in range(10, 0, -1)])
    async with get_sessionmaker()() as db:
        assert await host_metrics.retention_once(db, now=HOST_NOW) == 10
    rows = await _hourly()
    assert [r.hour for r in rows] == [host_metrics.floor_hour(HOST_NOW - timedelta(days=d)) for d in range(10, 0, -1)]
    assert rows[0].cpu_max == 20.0
    assert await _count(HostSample) == 8  # days 9 and 10 pruned, after their rollup
    async with get_sessionmaker()() as db:  # still idempotent
        assert await host_metrics.retention_once(db, now=HOST_NOW) == 0


async def test_retention_loop_runs_soon_after_start(monkeypatch):
    for interval, first in ((3600, host_metrics.FIRST_RUN_DELAY), (60, 60)):
        sleeps: list[float] = []
        runs: list[int] = []

        async def fake_sleep(seconds, sleeps=sleeps, runs=runs):
            sleeps.append(seconds)
            if len(sleeps) == 2:
                raise asyncio.CancelledError

        async def once(db, now=None, runs=runs):
            runs.append(len(sleeps))

        monkeypatch.setattr(host_metrics, "get_settings", lambda i=interval: type("S", (), {"metrics_retention_interval": i})())
        monkeypatch.setattr(host_metrics.asyncio, "sleep", fake_sleep)
        monkeypatch.setattr(host_metrics, "retention_once", once)
        with pytest.raises(asyncio.CancelledError):
            await host_metrics.retention_forever()
        assert sleeps == [first, interval] and runs == [1]


async def test_a_host_deleted_during_retention_does_not_stop_the_run(monkeypatch):
    gone = await _add_host("gone")
    kept = await _add_host("kept")
    await _add_samples(gone, [(HOST_NOW - timedelta(hours=3), 10.0, 10.0, None)])
    await _add_samples(kept, [(HOST_NOW - timedelta(hours=3), 20.0, 20.0, None),
                              (HOST_NOW - timedelta(days=9), 20.0, 20.0, None)])
    real_bucket = host_metrics._bucket

    def bucket_then_delete(rows):  # a user deletes the host right after rollup read its samples
        out = real_bucket(rows)
        if out:
            with sqlite3.connect(_db_file()) as conn:
                conn.execute("PRAGMA foreign_keys=ON")
                conn.execute("DELETE FROM hosts WHERE id = ?", (gone.hex,))
        return out

    monkeypatch.setattr(host_metrics, "_bucket", bucket_then_delete)
    async with get_sessionmaker()() as db:
        assert await host_metrics.retention_once(db, now=HOST_NOW) == 2  # kept: three hours and nine days ago
    assert {r.host_id for r in await _hourly()} == {kept}
    async with get_sessionmaker()() as db:
        assert (await db.scalars(select(HostSample.at).where(HostSample.host_id == kept))).all() == [
            HOST_NOW - timedelta(hours=3)
        ]  # the nine day old sample was pruned in the same run
        assert await db.get(Host, gone) is None


def _db_file() -> str:
    url = os.environ["SLIPWAY_DATABASE_URL"]
    if not url.startswith("sqlite"):
        pytest.skip("deletes the host through SQLite directly")
    return url.split(":///", 1)[1]


# ------------------------------------------------------------------ page


async def test_long_range_host_charts_say_they_plot_hourly_averages(admin_client):
    await _seed_host("db-01", hours=4)
    hourly = _section((await admin_client.get("/analytics?days=30")).text, "hosts")
    assert hourly.count("<dt>Peak</dt>") == 3 and "<dt>Max</dt>" not in hourly
    assert hourly.count("Hourly averages") == 2 and hourly.count("Hourly peaks") == 1  # CPU, memory; disk
    lines = {c["key"]: c for c in _charts(hourly) if c["kind"] == "line"}
    assert [lines[k]["value_name"] for k in ("cpu", "mem", "disk")] == ["CPU load, average", "Memory, average", "Disk, peak"]
    raw = _section((await admin_client.get("/analytics?days=7")).text, "hosts")
    assert raw.count("<dt>Max</dt>") == 3 and "Hourly averages" not in raw and "Hourly peaks" not in raw


async def test_js_hourly_disk_tooltip_says_peak(admin_client, tmp_path):
    await _seed_host("web-01", hours=3)
    page = (await admin_client.get("/analytics?days=90")).text
    result = run_js(tmp_path, HOVER.replace("__TREE__", json.dumps(_tree(page))) + """
var disk = plots.filter(function (p) { return JSON.parse(p.getAttribute("data-chart")).key === "disk"; })[0];
user("keydown", disk, { key: "End" });
done({ text: tipOf(disk).text });
""")
    assert len(result["text"]) == 2 and result["text"][1].endswith("Disk, peak")


async def test_js_tooltip_stays_inside_a_narrow_plot(admin_client, tmp_path):
    await _seed_deploys()
    page = (await admin_client.get("/analytics?days=7")).text
    result = run_js(tmp_path, HOVER.replace("__TREE__", json.dumps(_tree(page))) + """
Object.defineProperty(El.prototype, "offsetWidth", { get: function () {
  return this.className.indexOf("chart-tip") >= 0 && !this.hidden ? 150 : 0; } });
var bars = plots[0];
bars.clientWidth = 267;
function at(frac) {
  user("pointermove", bars, { clientX: 100 + 700 * frac });
  var tip = bars.querySelector(".chart-tip");
  return { cls: tip.className, left: tip.style.left };
}
done({ left: at(0.5 / 7), middle: at(3.5 / 7), right: at(6.5 / 7) });
""")
    def edges(state, slot):
        x = (slot + 0.5) / 7 * 267
        if "pin" in state["cls"]:
            left = float(state["left"].removesuffix("px"))
            return left, left + 150
        if "flip" in state["cls"]:
            return x - 14 - 150, x - 14
        return x + 14, x + 14 + 150
    for key, slot in (("left", 0), ("middle", 3), ("right", 6)):
        lo, hi = edges(result[key], slot)
        assert 0 <= lo and hi <= 267, (key, result[key])
    assert "flip" not in result["left"]["cls"] and "pin" in result["middle"]["cls"] and "flip" in result["right"]["cls"]


async def test_js_screen_readers_hear_the_keyboard_not_the_pointer(admin_client, tmp_path):
    await _seed_deploys()
    page = (await admin_client.get("/analytics?days=7")).text
    labels = [r["label"] for r in next(c for c in _charts(page) if c["kind"] == "bars")["rows"]]
    result = run_js(tmp_path, HOVER.replace("__TREE__", json.dumps(_tree(page))) + """
var bars = plots[0];
var tip = bars.querySelector(".chart-tip");
var live = bars.querySelectorAll("[aria-live]");
user("pointermove", bars, { clientX: 100 + 5 });
var head = tip.children[0];
user("pointermove", bars, { clientX: 100 + 10 });  // the same day
var same = tip.children[0] === head;
var afterPointer = live[0].textContent;
bars.focus(); user("keydown", bars, { key: "End" });
done({ tipLive: tip.getAttribute("aria-live"), lives: live.length, same: same, afterPointer: afterPointer,
       afterKey: live[0].textContent });
""")
    assert result["tipLive"] is None and result["lives"] == 1
    assert result["same"] is True  # moving within a day does not rebuild the tip
    assert result["afterPointer"] == ""
    assert result["afterKey"].startswith(labels[-1] + ", ") and "Succeeded" in result["afterKey"]


def test_ninety_day_axes_thin_their_labels_on_phones():
    by_day = [{"date": date(2026, 8, 20) + timedelta(days=i), "succeeded": 1, "failed": 0, "cancelled": 0}
              for i in range(90)]
    chart = pages._deploy_chart(by_day)
    shown = sorted(label["pos"] for label in chart["xlabels"] if not label["minor"])
    assert len(shown) >= 3 and all(b - a >= 0.18 for a, b in zip(shown, shown[1:]))
    assert not max(chart["xlabels"], key=lambda label: label["pos"])["minor"]  # today keeps its label
    now = datetime(2026, 11, 17, 12, tzinfo=UTC)
    shown = sorted(label["pos"] for label in pages._time_axis(now - timedelta(days=90), now, 90) if not label["minor"])
    assert len(shown) >= 3 and all(b - a >= 0.18 for a, b in zip(shown, shown[1:]))


def test_success_rate_tile_with_only_cancelled_deploys():
    totals = {"deploys": 2, "success_rate": None, "median_seconds": 120.0, "mttr_seconds": None,
              "previous": {"deploys": 1, "success_rate": None, "median_seconds": 60.0, "mttr_seconds": None}}
    tiles = pages._deploy_tiles(totals, 30)
    assert tiles["rate"]["note"] == "No deploys succeeded or failed in the last 30 days"
    totals["success_rate"] = 0.5
    assert pages._deploy_tiles(totals, 30)["rate"]["note"] == "No deploys succeeded or failed in the previous 30 days"


@pytest.mark.parametrize(("rate", "text"), [
    (1, "100%"), (0, "0%"), (0.5, "50%"), (0.29, "29%"), (2 / 3, "66.7%"), (199 / 200, "99.5%"),
    (1999 / 2000, "99.9%"), (2499 / 2500, "99.9%"), (1 / 2500, "0.1%"), (1 / 2000, "0.1%"), (None, "—"),
])
def test_success_rate_shows_100_or_0_only_when_exact(rate, text):
    assert pages.fmt_rate(rate) == text


def test_forced_colours_keep_the_outcomes_apart():
    css = CSS.read_text()
    block = css[css.index("@media (forced-colors: active)"):]
    block = block[:block.index("\n}\n")]
    colours = {}
    for key in ("ok", "fail", "cancel"):
        m = re.search(rf"\.chart-seg\.{key}, \.chart-swatch\.{key} \{{ fill: (\w+); background: (\w+);", block)
        assert m and m.group(1) == m.group(2), key
        colours[key] = m.group(1)
    assert len(set(colours.values())) == 3
    assert not re.search(r"\.chart-seg, \.chart-swatch \{", block)
