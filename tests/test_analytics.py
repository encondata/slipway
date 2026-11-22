"""Deploy analytics (the service and its numbers) and the analytics API's permissions.

Deployments are seeded straight into the database with a fixed ``now``; nothing real is touched.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import pytest

from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Host, Instance, Repository
from slipway.services import analytics, host_metrics
from tests.conftest import login, make_user

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
SHA = "0123456789abcdef0123456789abcdef01234567"


def at(day: int, hour: int, minute: int = 0, month: int = 11) -> datetime:
    return datetime(2026, month, day, hour, minute, tzinfo=UTC)


async def _seed_instances() -> tuple[Instance, Instance]:
    async with get_sessionmaker()() as db:
        host = Host(name="prod-01", hostname="10.0.0.5", username="deploy")
        web_repo = Repository(github_id=1, full_name="acme/web", owner="acme", name="web", html_url="https://github.com/acme/web")
        api_repo = Repository(github_id=2, full_name="acme/api", owner="acme", name="api", html_url="https://github.com/acme/api")
        db.add_all([host, web_repo, api_repo])
        await db.flush()
        web = Instance(name="web", slug="web", repository_id=web_repo.id, host_id=host.id, branch="main")
        api = Instance(name="api", slug="api", repository_id=api_repo.id, host_id=host.id, branch="main")
        db.add_all([web, api])
        await db.commit()
        return web, api


def _dep(instance, status, created, minutes=None, user=None, **kw) -> Deployment:
    """A deployment created at ``created`` that ran for ``minutes`` (None: never started or not finished)."""
    started = kw.pop("started", created if minutes is not None or status == "running" else None)
    finished = created + timedelta(minutes=minutes) if minutes is not None else None
    return Deployment(
        instance_id=instance.id, status=status, branch="main", created_at=created, started_at=started,
        finished_at=finished, triggered_by_id=user.id if user else None, commit_sha=SHA, **kw,
    )


@pytest.fixture
async def seeded() -> dict:
    """With days=7 the window is 11-11 00:00 to 11-17 12:00; the previous window, just as long, is 11-04 12:00
    to 11-11 00:00."""
    web, api = await _seed_instances()
    alice = await make_user("alice@example.com", roles=["developer"])
    bob = await make_user("bob@example.com", roles=["developer"])
    deps = {
        # Previous window: two failures, then a recovery 2h05m after the first failure finished.
        "p0": _dep(web, "failed", at(5, 10), 5, alice, error="first"),
        "p1": _dep(web, "failed", at(5, 11), 2, alice, error="second"),
        "p2": _dep(web, "succeeded", at(5, 12), 10, bob),
        # Long before both windows.
        "old": _dep(api, "succeeded", at(1, 9, month=10), 1, bob),
        # This window.
        "d3": _dep(web, "succeeded", at(12, 9), 1, alice),
        "d4": _dep(web, "failed", at(14, 9), 2, alice, error="\n  boom: build failed  \nsecond line",
                   commit_message="Fix the build\n\nLonger body"),
        "d5": _dep(web, "failed", at(15, 9), 3, None, error="x" * 500),
        "d6": _dep(web, "succeeded", at(16, 9), 4, bob),
        "d7": _dep(web, "cancelled", at(16, 10), 5, alice),
        "d8": _dep(api, "failed", at(17, 8), 10, bob),
        "d9": _dep(api, "running", at(17, 11)),
        "d10": _dep(web, "queued", at(17, 11, 30)),  # an instance has one deploy queued or running at most
    }
    async with get_sessionmaker()() as db:
        db.add_all(deps.values())
        await db.commit()
    return {"web": web, "api": api, "alice": alice, "bob": bob, "deps": deps}


async def _stats(days: int = 7, now: datetime = NOW) -> dict:
    async with get_sessionmaker()() as db:
        return await analytics.deploy_stats(db, days=days, now=now)


async def test_totals_percentiles_and_recovery(seeded):
    stats = await _stats()
    assert stats["start"] == at(11, 0) and stats["end"] == NOW and stats["previous_start"] == at(4, 12)
    t = stats["totals"]
    # Finished deploys only: the running and the queued one are counted under running and queued.
    assert (t["deploys"], t["succeeded"], t["failed"], t["cancelled"]) == (6, 2, 3, 1)
    assert (t["running"], t["queued"]) == (1, 1)
    assert t["success_rate"] == pytest.approx(0.4)
    # Finished durations: 60, 120, 180, 240, 300, 600 seconds.
    assert t["median_seconds"] == 210
    assert t["p90_seconds"] == pytest.approx(450)
    # The run d4, d5 ends with d6: counted from d4, the run's first failure.
    assert t["mttr_seconds"] == (at(16, 9, 4) - at(14, 9, 2)).total_seconds()


async def test_previous_window_numbers(seeded):
    prev = (await _stats())["totals"]["previous"]
    assert (prev["deploys"], prev["succeeded"], prev["failed"], prev["cancelled"]) == (3, 1, 2, 0)
    assert prev["success_rate"] == pytest.approx(1 / 3)
    # Durations 120, 300, 600.
    assert prev["median_seconds"] == 300
    assert prev["p90_seconds"] == pytest.approx(540)
    assert prev["mttr_seconds"] == (at(5, 12, 10) - at(5, 10, 5)).total_seconds()
    assert "previous" not in prev and "running" not in prev


async def test_by_day_has_every_day_including_empty_ones(seeded):
    by_day = (await _stats())["by_day"]
    assert [d["date"] for d in by_day] == [date(2026, 11, d) for d in range(11, 18)]
    counts = {d["date"].day: (d["succeeded"], d["failed"], d["cancelled"]) for d in by_day}
    assert counts == {
        11: (0, 0, 0), 12: (1, 0, 0), 13: (0, 0, 0), 14: (0, 1, 0), 15: (0, 1, 0), 16: (1, 0, 1), 17: (0, 1, 0),
    }
    assert len((await _stats(days=30))["by_day"]) == 30
    assert len((await _stats(days=90))["by_day"]) == 90


async def test_by_instance(seeded):
    rows = (await _stats())["by_instance"]
    assert [r["slug"] for r in rows] == ["web", "api"]
    web, api = rows
    assert web["id"] == seeded["web"].id
    assert (web["name"], web["repository"], web["host"]) == ("web", "acme/web", "prod-01")
    assert (web["deploys"], web["failed"]) == (5, 2)
    assert web["success_rate"] == pytest.approx(0.5)
    assert web["median_seconds"] == 180
    # Still queued: the time is when it was created.
    assert web["last_deploy"] == {"id": seeded["deps"]["d10"].id, "status": "queued", "at": at(17, 11, 30)}
    assert web["recovering"] is False  # its latest outcome succeeded; the cancel and the queued one say nothing

    assert (api["deploys"], api["failed"], api["success_rate"], api["median_seconds"]) == (1, 1, 0.0, 600)
    # Still running: the time is when it was created.
    assert api["last_deploy"] == {"id": seeded["deps"]["d9"].id, "status": "running", "at": at(17, 11)}
    assert api["recovering"] is True


async def test_by_person_names_deploys_without_a_trigger(seeded):
    people = (await _stats())["by_person"]
    assert [(p["name"], p["deploys"], p["failed"]) for p in people] == [
        ("alice", 3, 1), ("bob", 2, 1), ("Deleted user", 1, 1),
    ]
    assert people[0]["id"] == seeded["alice"].id and people[2]["id"] is None


async def test_recent_failures_clip_the_first_error_line(seeded):
    failures = (await _stats())["recent_failures"]
    assert [f["id"] for f in failures] == [seeded["deps"][k].id for k in ("d8", "d5", "d4")]
    d8, d5, d4 = failures
    assert d8["error"] == "" and d8["instance"]["slug"] == "api" and d8["at"] == at(17, 8, 10)
    assert len(d5["error"]) == 200 and d5["error"].endswith("…")
    assert d4["error"] == "boom: build failed"
    assert d4["commit_sha"] == "0123456" and d4["commit_message"] == "Fix the build"
    assert d5["commit_message"] is None


async def test_recent_failures_keep_the_latest_ten():
    web, _ = await _seed_instances()
    async with get_sessionmaker()() as db:
        db.add_all(_dep(web, "failed", at(17, 0) + timedelta(minutes=i), 1, error=f"e{i}") for i in range(12))
        await db.commit()
    failures = (await _stats())["recent_failures"]
    assert [f["error"] for f in failures] == [f"e{i}" for i in range(11, 1, -1)]


async def test_success_rate_is_none_without_finished_deploys():
    web, _ = await _seed_instances()
    async with get_sessionmaker()() as db:
        db.add(_dep(web, "queued", at(17, 10)))
        await db.commit()
    stats = await _stats()
    t = stats["totals"]
    assert (t["deploys"], t["queued"]) == (0, 1)
    assert t["success_rate"] is None and t["median_seconds"] is None and t["p90_seconds"] is None
    assert t["mttr_seconds"] is None
    assert stats["by_instance"][0]["success_rate"] is None
    assert stats["by_instance"][0]["recovering"] is False
    assert all(d["succeeded"] == d["failed"] == d["cancelled"] == 0 for d in stats["by_day"])


async def test_empty_window():
    stats = await _stats(days=30)
    assert stats["totals"]["deploys"] == 0 and stats["totals"]["previous"]["deploys"] == 0
    assert stats["by_instance"] == stats["by_person"] == stats["recent_failures"] == []
    assert len(stats["by_day"]) == 30


async def test_recovery_needs_the_success_in_the_window():
    """A run that started before the window still counts, from its first failure, when the success is inside."""
    web, api = await _seed_instances()
    async with get_sessionmaker()() as db:
        db.add_all([
            _dep(web, "failed", at(9, 10), 1),  # previous window
            _dep(web, "cancelled", at(10, 10), 1),  # does not end the run
            _dep(web, "failed", at(11, 10), 1),
            _dep(web, "succeeded", at(12, 10), 1),
            _dep(web, "succeeded", at(13, 10), 1),  # no failure before it: not a recovery
            _dep(api, "failed", at(16, 10), 1),  # never recovered
        ])
        await db.commit()
    t = (await _stats())["totals"]
    assert t["mttr_seconds"] == (at(12, 10, 1) - at(9, 10, 1)).total_seconds()
    assert t["previous"]["mttr_seconds"] is None


def test_percentile_interpolates():
    assert analytics.percentile([], 0.9) is None
    assert analytics.percentile([5], 0.9) == 5
    assert analytics.percentile([1, 2, 3, 4], 0.5) == 2.5
    assert analytics.percentile([10, 0, 20], 1.0) == 20


async def test_days_must_be_7_30_or_90():
    async with get_sessionmaker()() as db:
        with pytest.raises(ValueError):
            await analytics.deploy_stats(db, days=14, now=NOW)


# The API.


async def test_deploys_api_returns_iso_utc_with_z(admin_client, seeded):
    r = await admin_client.get("/api/v1/analytics/deploys?days=90")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["days"] == 90 and len(data["by_day"]) == 90
    assert data["end"].endswith("Z") and "+00:00" not in r.text
    assert data["by_day"][0]["date"] == data["start"][:10]
    assert {p["name"] for p in data["by_person"]} == {"alice", "bob", "Deleted user"}
    assert data["by_instance"][0]["last_deploy"]["at"].endswith("Z")
    assert isinstance(data["by_instance"][0]["id"], str)
    assert (await admin_client.get("/api/v1/analytics/deploys")).json()["days"] == 30


@pytest.mark.parametrize("days", ["14", "0", "-7", "abc", "7.5"])
async def test_api_rejects_other_days(admin_client, days):
    assert (await admin_client.get(f"/api/v1/analytics/deploys?days={days}")).status_code == 422
    assert (await admin_client.get(f"/api/v1/analytics/hosts?days={days}")).status_code == 422


async def test_analytics_api_needs_sign_in(client):
    assert (await client.get("/api/v1/analytics/deploys")).status_code == 401
    assert (await client.get("/api/v1/analytics/hosts")).status_code == 401


async def _client_with(admin_client, make_client, name: str, permissions: list[str]):
    r = await admin_client.post("/api/v1/roles", json={"name": name, "permissions": permissions})
    assert r.status_code == 201, r.text
    await make_user(f"{name}@example.com", roles=[name])
    c = make_client()
    await login(c, f"{name}@example.com")
    return c


async def test_api_permissions(admin_client, make_client, monkeypatch):
    calls: list[int] = []

    async def fake_trends(db, *, days, now=None):
        calls.append(days)
        return [{"id": "h1", "name": "prod-01", "series": [{"at": NOW, "cpu": 10.0, "mem": 20.0, "disk": None}]}]

    monkeypatch.setattr(host_metrics, "host_trends", fake_trends)

    no_analytics = await _client_with(admin_client, make_client, "ops-reader", ["deployments:read", "hosts:read"])
    deploys_only = await _client_with(admin_client, make_client, "deploy-analyst", ["deployments:read", "analytics:read"])
    hosts_only = await _client_with(admin_client, make_client, "host-analyst", ["hosts:read", "analytics:read"])
    analytics_only = await _client_with(admin_client, make_client, "analyst", ["analytics:read"])

    for c in (no_analytics, analytics_only, hosts_only):
        r = await c.get("/api/v1/analytics/deploys")
        assert r.status_code == 403, r.text
    for c in (no_analytics, analytics_only, deploys_only):
        r = await c.get("/api/v1/analytics/hosts")
        assert r.status_code == 403, r.text
    assert calls == []

    assert (await deploys_only.get("/api/v1/analytics/deploys?days=7")).status_code == 200
    r = await hosts_only.get("/api/v1/analytics/hosts")
    assert r.status_code == 200, r.text
    assert r.json()[0]["series"][0]["at"] == "2026-11-17T12:00:00Z"
    assert (await hosts_only.get("/api/v1/analytics/hosts?days=30")).status_code == 200
    assert calls == [7, 30]


async def test_every_built_in_role_can_read_analytics(admin_client, make_client, monkeypatch):
    async def fake_trends(db, *, days, now=None):
        return []

    monkeypatch.setattr(host_metrics, "host_trends", fake_trends)
    await make_user("viewer@example.com", roles=["viewer"])
    viewer = make_client()
    await login(viewer, "viewer@example.com")
    assert (await viewer.get("/api/v1/analytics/deploys")).status_code == 200
    assert (await viewer.get("/api/v1/analytics/hosts")).json() == []


async def test_hosts_api_uses_the_real_trends(admin_client):
    host = (await admin_client.post("/api/v1/hosts", json={"name": "prod-01", "hostname": "10.0.0.5", "username": "deploy"})).json()
    r = await admin_client.get("/api/v1/analytics/hosts?days=90")
    assert r.status_code == 200, r.text
    assert isinstance(r.json(), list)
    assert all(h["id"] == host["id"] for h in r.json())
    assert "+00:00" not in r.text
