"""Hostnames published in Switchyard: the client, the sync rules, the deploy hook, settings and API."""

from __future__ import annotations

import uuid

import httpx
import pytest
from sqlalchemy import select, update

from slipway.db.session import get_sessionmaker
from slipway.models import AppSetting, Deployment, Host, Instance, Repository
from slipway.services import deployer, switchyard
from tests.conftest import login, make_user
from tests.fake_switchyard import KEY, FakeSwitchyard
from tests.test_deployer import FakeGitHub, FakeRemote, _connect, _instance, _seed


@pytest.fixture
def fake_sy(monkeypatch):
    fake = FakeSwitchyard()
    monkeypatch.setattr(switchyard, "transport_factory", lambda: httpx.MockTransport(fake.handle))
    return fake


async def _configure(url: str = "https://sy.example.test", key: str = KEY, tls: str = "auto") -> None:
    async with get_sessionmaker()() as db:
        db.add(AppSetting(key=switchyard.SETTING_KEY, value={"url": url, "default_tls_mode": tls}, secret=key))
        await db.commit()


async def _get(model, id_):
    async with get_sessionmaker()() as db:
        return await db.get(model, id_)


async def _seed_routes(routes: list[dict], **fields) -> uuid.UUID:
    """A Dockerfile instance publishing 8080 -> 3000 with ``routes``; returns the queued deployment."""
    dep_id = await _seed({})
    async with get_sessionmaker()() as db:
        await db.execute(update(Instance).values(routes=routes, **fields))
        await db.commit()
    return dep_id


ROUTE = {"hostname": "app.example.com", "service": None, "container": 3000, "tls_mode": "auto"}


# ------------------------------------------------------------------- targets


def test_route_targets():
    inst = _instance(routes=[ROUTE, {**ROUTE, "hostname": "x.example.com", "container": 9}])
    ok, missing = switchyard.route_targets(inst)
    assert (ok.address, ok.port, ok.problem) == ("10.0.0.1", 8080, None)
    assert missing.problem == "container port 9 is not published on the host"
    inst.host.proxy_address = "192.168.1.20"
    assert switchyard.route_targets(inst)[0].upstream == "192.168.1.20:8080"
    compose = _instance(build_source="compose", published_ports=[
        {"service": "web", "container": 80, "protocol": "tcp", "host": 8081},
        {"service": "api", "container": 80, "protocol": "tcp", "host": 9000},
    ], routes=[{**ROUTE, "service": "api", "container": 80}, {**ROUTE, "hostname": "w.example.com", "service": "db", "container": 80}])
    api, db = switchyard.route_targets(compose)
    assert api.port == 9000 and db.problem == "db container port 80 is not published on the host"


@pytest.mark.parametrize("value, ok", [
    ("App.Example.com.", "app.example.com"), ("a-b.c.example.io", "a-b.c.example.io"),
    ("localhost", None), ("-a.example.com", None), ("a_b.example.com", None), ("*.example.com", None), ("1.2.3.4", None),
])
def test_clean_hostname(value, ok):
    if ok:
        assert switchyard.clean_hostname(value) == ok
    else:
        with pytest.raises(ValueError):
            switchyard.clean_hostname(value)


# ----------------------------------------------------------------- deploy sync


async def test_deploy_creates_the_host_and_applies(fake_sy):
    await _configure()
    dep_id = await _seed_routes([ROUTE])
    await deployer.run_deployment(dep_id, connect=_connect(FakeRemote()), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded", dep.log
    (host,) = fake_sy.hosts.values()
    assert host["domains"] == ["app.example.com"] and host["tls_mode"] == "auto" and host["force_https"] is True
    assert host["upstreams"] == [{"scheme": "http", "skip_tls_verify": False, "host": "10.0.0.1", "port": 8080}]
    assert "Managed by Slipway" in host["notes"] and str(dep.instance_id) in host["notes"]
    assert fake_sy.applies == ["Slipway: web"]
    assert "Proxy: created app.example.com → 10.0.0.1:8080 in Switchyard" in dep.log and "Proxy: applied in Switchyard" in dep.log
    (entry,) = dep.instance.proxy_entries
    assert entry["state"] == "live" and entry["switchyard_id"] == host["id"] and entry["upstream"] == "10.0.0.1:8080"


async def test_redeploy_follows_a_moved_port_and_keeps_switchyard_settings(fake_sy):
    await _configure()
    dep_id = await _seed_routes([ROUTE])
    await deployer.run_deployment(dep_id, connect=_connect(FakeRemote()), github=FakeGitHub)
    hid = next(iter(fake_sy.hosts))
    fake_sy.hosts[hid]["policy_ids"] = [7]  # set by someone in Switchyard
    fake_sy.hosts[hid]["notes"] += "\nOps: keep the geo policy"
    inst_id = (await _get(Deployment, dep_id)).instance_id
    # 8080 is now taken by another container, so the next deploy moves the port.
    remote = FakeRemote(responses={"/proc/net": "docker\t\t\tother\t0.0.0.0:8080->80/tcp"})
    async with get_sessionmaker()() as db:
        dep2 = Deployment(instance_id=inst_id, branch="main", log="")
        db.add(dep2)
        await db.commit()
    await deployer.run_deployment(dep2.id, connect=_connect(remote), github=FakeGitHub)
    dep2 = await _get(Deployment, dep2.id)
    assert dep2.status == "succeeded", dep2.log
    host = fake_sy.hosts[hid]
    assert host["upstreams"][0]["port"] == 8081 and host["policy_ids"] == [7] and "geo policy" in host["notes"]
    assert "Proxy: updated app.example.com → 10.0.0.1:8081 in Switchyard" in dep2.log
    assert len(fake_sy.applies) == 2


async def test_nothing_changed_means_no_apply(fake_sy):
    await _configure()
    dep_id = await _seed_routes([ROUTE])
    await deployer.run_deployment(dep_id, connect=_connect(FakeRemote()), github=FakeGitHub)
    inst = (await _get(Deployment, dep_id)).instance
    entries = await switchyard.sync(inst, say=_noop)
    assert entries[0]["state"] == "live" and len(fake_sy.applies) == 1


async def test_other_pending_changes_are_not_applied(fake_sy):
    await _configure()
    fake_sy.someone_edits()
    dep_id = await _seed_routes([ROUTE])
    await deployer.run_deployment(dep_id, connect=_connect(FakeRemote()), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded" and fake_sy.applies == []
    assert "not applied, because other changes were waiting in Switchyard" in dep.log
    assert dep.instance.proxy_entries[0]["state"] == "staged"
    # Still someone else's edit waiting: a later sync stages again rather than applying it.
    entries = await switchyard.sync(dep.instance, say=_noop)
    assert entries[0]["state"] == "staged" and fake_sy.applies == []
    # A person applies everything in Switchyard; the next sync sees nothing of Slipway's pending.
    fake_sy.version += 1
    fake_sy.changes = 0
    entries = await switchyard.sync(dep.instance, say=_noop)
    assert entries[0]["state"] == "live" and fake_sy.applies == []


async def test_slipways_own_staged_edits_are_applied_later(fake_sy):
    await _configure()
    fake_sy.apply_fails = True
    dep_id = await _seed_routes([ROUTE])
    await deployer.run_deployment(dep_id, connect=_connect(FakeRemote()), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert "Switchyard could not apply" in dep.log and dep.instance.proxy_entries[0]["state"] == "error"
    # Only Slipway's own edit is pending, so the next sync applies it even though nothing changed.
    fake_sy.apply_fails = False
    lines: list[str] = []
    entries = await switchyard.sync(dep.instance, say=_collect(lines))
    assert lines == ["Proxy: applied in Switchyard (changes Slipway staged earlier)"]
    assert entries[0]["state"] == "live" and fake_sy.applies == ["Slipway: web"]


async def test_a_switchyard_that_never_applied_is_left_to_a_person(fake_sy):
    await _configure()
    fake_sy.version = None
    dep_id = await _seed_routes([ROUTE])
    await deployer.run_deployment(dep_id, connect=_connect(FakeRemote()), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert fake_sy.applies == [] and "Switchyard has not applied a config yet; apply once there" in dep.log


async def test_drift_is_not_overwritten(fake_sy):
    await _configure()
    fake_sy.drift = True
    dep_id = await _seed_routes([ROUTE])
    await deployer.run_deployment(dep_id, connect=_connect(FakeRemote()), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert fake_sy.applies == [] and "changed outside Switchyard" in dep.log


async def test_a_hostname_someone_else_uses_is_left_alone(fake_sy):
    await _configure()
    theirs = fake_sy.add(domains=["app.example.com"], upstreams=[{"scheme": "http", "host": "10.9.9.9", "port": 80}])
    dep_id = await _seed_routes([ROUTE, {**ROUTE, "hostname": "ok.example.com"}])
    await deployer.run_deployment(dep_id, connect=_connect(FakeRemote()), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded", dep.log
    assert fake_sy.hosts[theirs["id"]]["upstreams"][0]["host"] == "10.9.9.9"
    bad, good = dep.instance.proxy_entries
    assert bad["state"] == "error" and f"Switchyard host #{theirs['id']}, which Slipway did not create" in bad["message"]
    assert good["state"] == "live" and fake_sy.applies == ["Slipway: web"]


async def test_removed_hostname_is_deleted_and_recreated_if_deleted_in_switchyard(fake_sy):
    await _configure()
    dep_id = await _seed_routes([ROUTE, {**ROUTE, "hostname": "old.example.com"}])
    await deployer.run_deployment(dep_id, connect=_connect(FakeRemote()), github=FakeGitHub)
    inst = (await _get(Deployment, dep_id)).instance
    old_id = next(e["switchyard_id"] for e in inst.proxy_entries if e["hostname"] == "old.example.com")
    app_id = next(e["switchyard_id"] for e in inst.proxy_entries if e["hostname"] == "app.example.com")
    del fake_sy.hosts[app_id]  # someone deleted it in Switchyard
    inst.routes = [ROUTE]
    lines: list[str] = []
    entries = await switchyard.sync(inst, say=_collect(lines))
    assert old_id not in fake_sy.hosts and "Proxy: removed old.example.com from Switchyard" in lines
    assert [e["hostname"] for e in entries] == ["app.example.com"] and entries[0]["switchyard_id"] != app_id
    assert [h["domains"] for h in fake_sy.hosts.values()] == [["app.example.com"]]


async def test_not_configured_does_not_fail_the_deploy(fake_sy):
    dep_id = await _seed_routes([ROUTE])
    await deployer.run_deployment(dep_id, connect=_connect(FakeRemote()), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded" and "Switchyard is not set up" in dep.log and fake_sy.calls == []


async def test_switchyard_down_does_not_fail_the_deploy(monkeypatch):
    def down(request):
        raise httpx.ConnectError("connection refused")
    monkeypatch.setattr(switchyard, "transport_factory", lambda: httpx.MockTransport(down))
    await _configure()
    dep_id = await _seed_routes([ROUTE])
    await deployer.run_deployment(dep_id, connect=_connect(FakeRemote()), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded" and "Could not reach Switchyard" in dep.log
    assert dep.instance.proxy_entries[0]["state"] == "error"


async def test_unpublished_port_is_reported(fake_sy):
    await _configure()
    dep_id = await _seed_routes([{**ROUTE, "container": 4000}])
    await deployer.run_deployment(dep_id, connect=_connect(FakeRemote()), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert "app.example.com: container port 4000 is not published on the host; not published" in dep.log
    assert fake_sy.hosts == {} and fake_sy.applies == []


async def _noop(line: str) -> None:
    return None


def _collect(lines: list[str]):
    async def say(line: str) -> None:
        lines.append(line)
    return say


# ------------------------------------------------------------------------ API


async def test_settings_api(admin_client, fake_sy):
    r = await admin_client.put("/api/v1/settings/switchyard", json={"url": "https://sy.example.test/api/"})
    assert r.status_code == 422 and "API key" in r.text
    r = await admin_client.put("/api/v1/settings/switchyard", json={"url": "ftp://x"})
    assert r.status_code == 422
    r = await admin_client.put("/api/v1/settings/switchyard",
                               json={"url": "https://sy.example.test/api/", "api_key": KEY, "default_tls_mode": "dns"})
    assert r.status_code == 200, r.text
    assert r.json()["url"] == "https://sy.example.test" and r.json()["has_api_key"] and KEY not in r.text
    # An empty key keeps the stored one.
    r = await admin_client.put("/api/v1/settings/switchyard", json={"url": "https://sy.example.test", "api_key": ""})
    assert r.json()["has_api_key"] and r.json()["default_tls_mode"] == "auto"
    assert r.json()["api_key_prefix"] == KEY[:9]
    r = await admin_client.post("/api/v1/settings/switchyard/test")
    assert r.status_code == 200 and r.json()["message"].startswith("Connected: Switchyard has 0 host(s).")
    # A browser-filled password is refused instead of saved.
    r = await admin_client.put("/api/v1/settings/switchyard", json={"url": "https://sy.example.test", "api_key": "MyLoginPassw0rd!"})
    assert r.status_code == 422 and "not a Switchyard API key" in r.text
    # A key Switchyard does not know: the hint names the saved prefix and the URL.
    other = "sy_" + "w" * 43
    r = await admin_client.put("/api/v1/settings/switchyard", json={"url": "https://sy.example.test", "api_key": other})
    assert r.status_code == 200
    r = await admin_client.post("/api/v1/settings/switchyard/test")
    assert r.status_code == 502 and "starts with sy_wwwwww…" in r.json()["detail"] and "https://sy.example.test" in r.json()["detail"]
    r = await admin_client.put("/api/v1/settings/switchyard", json={"url": "https://sy.example.test", "api_key": " " + KEY + "\n"})
    assert r.status_code == 200
    fake_sy.denied.add("GET /api/config/preview")
    r = await admin_client.post("/api/v1/settings/switchyard/test")
    assert r.status_code == 502 and "config.apply" in r.json()["detail"]
    page = await admin_client.get("/settings/integrations")
    assert page.status_code == 200 and "sy.example.test" in page.text and KEY not in page.text
    assert f"Saved key: <code>{KEY[:9]}…</code>" in page.text and 'autocomplete="new-password"' in page.text
    r = await admin_client.put("/api/v1/settings/switchyard", json={"clear": True})
    assert r.json()["configured"] is False


async def test_settings_need_settings_write(client, make_client):
    await make_user("admin@example.com")
    await make_user("dev@example.com", roles=["maintainer"])
    await login(client, "dev@example.com")
    assert (await client.get("/api/v1/settings/switchyard")).status_code == 403
    assert (await client.get("/settings/integrations")).status_code in (403, 404)


async def test_instance_routes_api(admin_client, fake_sy):
    async with get_sessionmaker()() as db:
        host = Host(name="h1", hostname="10.0.0.9", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
        repo = Repository(github_id=7, full_name="acme/app", owner="acme", name="app",
                          html_url="https://github.com/acme/app", detected_config={})
        db.add_all([host, repo])
        await db.commit()
    base = {"repository_id": str(repo.id), "host_id": str(host.id), "branch": "main", "deploy": False}
    route = {"hostname": "App.Example.com", "container": 3000}
    r = await admin_client.post("/api/v1/instances", json={**base, "name": "one", "routes": [route]})
    assert r.status_code == 201, r.text
    one = r.json()
    assert one["routes"] == [{"hostname": "app.example.com", "service": None, "container": 3000, "tls_mode": "auto"}]
    r = await admin_client.post("/api/v1/instances", json={**base, "name": "two", "routes": [route]})
    assert r.status_code == 409 and "instance one" in r.text
    r = await admin_client.patch(f"/api/v1/instances/{one['id']}", json={"routes": [route, route]})
    assert r.status_code == 422
    r = await admin_client.patch(f"/api/v1/instances/{one['id']}", json={"routes": [{**route, "hostname": "nope"}]})
    assert r.status_code == 422
    # Not deployed yet: nothing to publish.
    r = await admin_client.post(f"/api/v1/instances/{one['id']}/proxy/sync")
    assert r.status_code == 400
    r = await admin_client.patch(f"/api/v1/hosts/{host.id}", json={"proxy_address": "192.168.1.9"})
    assert r.status_code == 200 and r.json()["proxy_address"] == "192.168.1.9"
    r = await admin_client.patch(f"/api/v1/hosts/{host.id}", json={"proxy_address": ""})
    assert r.json()["proxy_address"] is None


async def test_sync_endpoint_and_delete_remove_the_hosts(client, fake_sy):
    await _configure()
    dep_id = await _seed_routes([ROUTE])  # creates admin@example.com
    admin_client = client
    await login(admin_client, "admin@example.com")
    await deployer.run_deployment(dep_id, connect=_connect(FakeRemote()), github=FakeGitHub)
    inst_id = (await _get(Deployment, dep_id)).instance_id
    r = await admin_client.post(f"/api/v1/instances/{inst_id}/proxy/sync")
    assert r.status_code == 200 and r.json()["ok"] and "warning" not in r.json()
    fake_sy.someone_edits()
    async with get_sessionmaker()() as db:
        await db.execute(update(Instance).values(routes=[ROUTE, {**ROUTE, "hostname": "b.example.com"}]))
        await db.commit()
    r = await admin_client.post(f"/api/v1/instances/{inst_id}/proxy/sync")
    assert r.json()["warning"].startswith("app.example.com: Waiting for an apply in Switchyard")
    fake_sy.version += 1  # a person applied it all in Switchyard
    fake_sy.changes = 0
    r = await admin_client.delete(f"/api/v1/instances/{inst_id}?purge=false")
    assert r.status_code == 204, r.text
    assert fake_sy.hosts == {} and fake_sy.applies[-1] == "Slipway: web"


# --------------------------------------------------------------------- owners


ENV_ID = uuid.UUID("00000000-0000-0000-0000-0000000000e1")


class _Env:
    """Stands in for an Environment row: Owner.of only needs its table name, id and name."""

    __tablename__ = "environments"

    def __init__(self, id_: uuid.UUID = ENV_ID, name: str = "uat") -> None:
        self.id, self.name = id_, name


TARGET = switchyard.Target("app.example.com", "auto", "10.0.0.12", 8000)


def test_instance_marker_is_unchanged():
    inst = _instance()
    assert switchyard.marker(inst) == (
        "Managed by Slipway: instance web (00000000-0000-0000-0000-000000000001). "
        "Domains, upstreams and TLS mode are set from Slipway on every deploy."
    )
    assert switchyard._marker is switchyard.marker and switchyard.Owner.of(inst) == switchyard.Owner("instance", inst.id, "web")
    # The helpers traffic.py shares with the instance sync are the same objects under both names.
    assert switchyard._lock is switchyard.lock and switchyard._blocker is switchyard.blocker
    assert switchyard._load_edits is switchyard.load_edits and switchyard._save_edits is switchyard.save_edits
    assert switchyard._desired is switchyard.desired and switchyard._differs is switchyard.differs


def test_owners():
    inst, env = _instance(), _Env()
    other_env = _Env(uuid.UUID("00000000-0000-0000-0000-0000000000e2"), "prod")
    assert switchyard.marker(env) == (
        f"Managed by Slipway: environment uat ({ENV_ID}). "
        "Domains, upstreams and TLS mode are set from Slipway when traffic moves."
    )

    # An environment's host is the environment's only, even when its notes mention an instance.
    env_host = {"id": 4, **switchyard.desired(None, TARGET, env)}
    env_host["notes"] += f"\nOps: moved here from Managed by Slipway instance {inst.id}"
    assert switchyard.owned_by(env_host, env) and switchyard.owned_by(env_host, switchyard.Owner.of(env))
    assert not switchyard.owned_by(env_host, other_env)
    assert not switchyard.owned_by(env_host, inst) and not switchyard.owned_by(env_host, inst.id)
    assert switchyard.describe_owner(env_host) == "environment uat"

    # A host an instance made before environments existed stays its instance's.
    legacy = {"id": 5, "notes": switchyard.marker(inst) + "\nOps: keep the geo policy"}
    assert switchyard.owned_by(legacy, inst) and switchyard.owned_by(legacy, inst.id)
    assert not switchyard.owned_by(legacy, env)
    assert switchyard.describe_owner(legacy) == "instance web"

    # No marker, or a marker naming someone else: nobody's in Slipway.
    for notes in ("", "Made by hand", f"Managed by Slipway, they said ({ENV_ID})"):
        host = {"id": 6, "notes": notes}
        assert not switchyard.owned_by(host, env) and not switchyard.owned_by(host, inst)
        assert switchyard.describe_owner(host) == "someone else"

    with pytest.raises(TypeError):
        switchyard.Owner.of(object())


def test_desired_for_an_environment_keeps_switchyards_fields():
    env = _Env()
    theirs = {"id": 3, "type": "proxy", "enabled": False, "domains": ["app.example.com"], "policy_ids": [7],
              "upstreams": [{"scheme": "https", "skip_tls_verify": True, "host": "10.0.0.11", "port": 8000}],
              "tls_mode": "auto", "force_https": True, "notes": "", "created_at": "x", "updated_at": "y"}
    theirs["notes"] = switchyard.marker(env) + "\nOps: geo policy"
    body = switchyard.desired(theirs, TARGET, env)
    assert body["upstreams"] == [{"scheme": "https", "skip_tls_verify": True, "host": "10.0.0.12", "port": 8000}]
    assert body["policy_ids"] == [7] and body["enabled"] is False and body["notes"] == theirs["notes"]
    assert "id" not in body and "created_at" not in body and switchyard.differs(theirs, body)
    assert not switchyard.differs({**body, "id": 3}, switchyard.desired({**body, "id": 3}, TARGET, env))
    # A host of nobody's gets the environment's marker on top of its notes.
    adopted = switchyard.desired({**theirs, "notes": "Made by hand"}, TARGET, env)
    assert adopted["notes"] == switchyard.marker(env) + "\nMade by hand" and switchyard.owned_by(adopted, env)


async def test_an_instance_hostname_held_by_an_environment_names_it(fake_sy):
    await _configure()
    env_host = fake_sy.add(**switchyard.desired(None, switchyard.Target("app.example.com", "auto", "10.0.0.12", 8000), _Env()))
    dep_id = await _seed_routes([ROUTE])
    await deployer.run_deployment(dep_id, connect=_connect(FakeRemote()), github=FakeGitHub)
    dep = await _get(Deployment, dep_id)
    assert dep.status == "succeeded", dep.log
    (entry,) = dep.instance.proxy_entries
    assert entry["state"] == "error"
    assert f"Switchyard host #{env_host['id']}, which belongs to environment uat; remove it there" in entry["message"]
    assert fake_sy.hosts[env_host["id"]]["upstreams"][0]["host"] == "10.0.0.12" and fake_sy.applies == []


async def test_own_edits_count_from_the_last_apply(fake_sy):
    await _configure()
    async with switchyard.lock:
        state = await switchyard.own_edits({"last_applied": {"n": 4}})
        assert state == {"version": 4, "edits": 0}
        state["edits"] += 2
        await switchyard.save_edits(state)
        assert await switchyard.own_edits({"last_applied": {"n": 4}}) == {"version": 4, "edits": 2}
        # Applied since (by anyone): Slipway's edits went live with it.
        assert await switchyard.own_edits({"last_applied": {"n": 5}}) == {"version": 5, "edits": 0}
    assert switchyard.applied_edits({"n": 6}, 5) == {"version": 6, "edits": 0}
    assert switchyard.applied_edits(None, 5) == {"version": 5, "edits": 0}
    assert switchyard.blocker({"last_applied": {"n": 4}, "pending": True, "changes": 2}, 2) is None
    assert switchyard.blocker({"last_applied": {"n": 4}, "pending": True, "changes": 3}, 2) == "other changes were waiting in Switchyard"


# ---------------------------------------------------------------- traffic address


async def test_load_config_returns_the_traffic_address(admin_client, fake_sy):
    async with get_sessionmaker()() as db:
        assert await switchyard.load_config(db) is None
    await _configure()
    async with get_sessionmaker()() as db:
        assert (await switchyard.load_config(db)).traffic_address == ""
        row = await db.scalar(select(AppSetting).where(AppSetting.key == switchyard.SETTING_KEY))
        row.value = {**row.value, "traffic_address": "192.168.1.5:443"}
        await db.commit()
    async with get_sessionmaker()() as db:
        config = await switchyard.load_config(db)
    assert (config.url, config.api_key, config.traffic_address) == ("https://sy.example.test", KEY, "192.168.1.5:443")
    # Saving a new API key (and the URL with it) keeps the traffic address.
    other = "sy_" + "n" * 43
    r = await admin_client.put("/api/v1/settings/switchyard", json={"url": "https://sy2.example.test", "api_key": other})
    assert r.status_code == 200, r.text
    async with get_sessionmaker()() as db:
        config = await switchyard.load_config(db)
    assert (config.url, config.api_key, config.traffic_address) == ("https://sy2.example.test", other, "192.168.1.5:443")


@pytest.mark.parametrize("value, ok", [
    ("", ""), ("  ", ""), ("192.168.1.5", "192.168.1.5"), ("192.168.1.5:8443", "192.168.1.5:8443"),
    ("Proxy.Example.com.", "proxy.example.com"), ("proxy.example.com:443", "proxy.example.com:443"),
    ("[FD00::1]:443", "[fd00::1]:443"), ("fd00::1", "fd00::1"), ("[fd00::1]", "fd00::1"),
    ("proxy.example.com:", None), ("proxy.example.com:0", None), ("proxy.example.com:70000", None),
    ("https://proxy.example.com", None), ("proxy.example.com/x", None), ("a b", None), ("[fd00::1]x", None),
    ("proxy.example.com:44a", None), ("fd00::1:443:x", None),
])
def test_clean_traffic_address(value, ok):
    if ok is not None:
        assert switchyard.clean_traffic_address(value) == ok
    else:
        with pytest.raises(ValueError, match="is not a traffic address"):
            switchyard.clean_traffic_address(value)


# ------------------------------------------------------------------- the fake


async def test_the_fakes_seams(monkeypatch):
    from tests import fake_switchyard

    fake = fake_switchyard.install(monkeypatch)
    await fake_switchyard.configure(traffic_address="10.0.0.2")
    async with get_sessionmaker()() as db:
        config = await switchyard.load_config(db)
    assert config.traffic_address == "10.0.0.2"
    fake.fail_on = {("PUT", 2): 500}
    fake.someone_edits_after("POST /api/hosts", lambda f: f.hosts[1].update(enabled=False))
    async with switchyard.SwitchyardClient(config) as sy:
        one = await sy.create_host({"domains": ["a.example.com"], "notes": ""})
        assert fake.hosts[1]["enabled"] is False and fake.changes == 2  # Slipway's create and the foreign edit
        await sy.update_host(one["id"], {**one, "enabled": True})
        with pytest.raises(switchyard.SwitchyardError) as exc:
            await sy.update_host(one["id"], {**one, "enabled": True})
        assert exc.value.status_code == 500 and fake.changes == 3
        fake.apply_fails_once()
        with pytest.raises(switchyard.SwitchyardError):
            await sy.apply("first")
        assert (await sy.apply("second"))["n"] == 2 and fake.applies == ["second"]
        fake.delete_id_then_reuse(1)
        assert switchyard.describe_owner(await sy.get_host(1)) == "someone else"
        assert list(fake.hosts_by_domain()) == ["other-1.example.net"]
        assert (await sy.preview())["pending"] is False
    assert fake.api_calls()[0] == "POST /api/hosts" and fake.api_calls()[0].body["domains"] == ["a.example.com"]
    assert [c.method for c in fake.api_calls()] == ["POST", "PUT", "PUT", "POST", "POST", "GET", "GET"]
    assert "changed" in fake.calls
