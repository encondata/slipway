"""Hostnames published in Switchyard: the client, the sync rules, the deploy hook, settings and API."""

from __future__ import annotations

import json
import uuid

import httpx
import pytest
from sqlalchemy import update

from slipway.db.session import get_sessionmaker
from slipway.models import AppSetting, Deployment, Host, Instance, Repository
from slipway.services import deployer, switchyard
from tests.conftest import login, make_user
from tests.test_deployer import FakeGitHub, FakeRemote, _connect, _instance, _seed

KEY = "sy_" + "T3stK3y" * 6 + "x"  # sy_ and 43 characters, like a real key


class FakeSwitchyard:
    """Enough of Switchyard's API: hosts with ids, 409 on a used domain, staged changes, preview and apply."""

    def __init__(self) -> None:
        self.hosts: dict[int, dict] = {}
        self.next_id = 1
        self.version: int | None = 1  # last applied config version (None: never applied)
        self.changes = 0  # audit-log edits since that version, by anyone
        self.drift = False
        self.apply_fails = False
        self.applies: list[str] = []
        self.calls: list[str] = []
        self.denied: set[str] = set()  # "METHOD /path" prefixes answered with 403

    def someone_edits(self) -> None:
        """An edit made in Switchyard's UI and not applied."""
        self.changes += 1

    def add(self, **host) -> dict:
        host = {"id": self.next_id, "type": "proxy", "enabled": True, "upstreams": [], "tls_mode": "auto",
                "force_https": True, "notes": "", "policy_ids": [], **host}
        self.hosts[self.next_id] = host
        self.next_id += 1
        return host

    def handle(self, request: httpx.Request) -> httpx.Response:
        call = f"{request.method} {request.url.path}"
        self.calls.append(call)
        if request.headers.get("Authorization") != f"Bearer {KEY}":
            return httpx.Response(401, json={"error": "invalid_api_key", "message": "The API key is wrong."})
        if any(call.startswith(d) for d in self.denied):
            return httpx.Response(403, json={"error": "missing_permission", "message": "This key lacks the operation."})
        path = request.url.path.removeprefix("/api")
        body = json.loads(request.content) if request.content else None
        if path == "/hosts" and request.method == "GET":
            return httpx.Response(200, json=list(self.hosts.values()))
        if path == "/hosts" and request.method == "POST":
            if any(d in h["domains"] for h in self.hosts.values() for d in body["domains"]):
                return httpx.Response(409, json={"error": "conflict", "message": "A domain is already used."})
            self._changed()
            return httpx.Response(201, json=self.add(**body))
        if path.startswith("/hosts/"):
            hid = int(path.split("/")[2])
            if hid not in self.hosts:
                return httpx.Response(404, json={"error": "not_found", "message": "No such host."})
            if request.method == "GET":
                return httpx.Response(200, json=self.hosts[hid])
            if request.method == "PUT":
                self.hosts[hid] = {**body, "id": hid}
                self._changed()
                return httpx.Response(200, json=self.hosts[hid])
            if request.method == "DELETE":
                del self.hosts[hid]
                self._changed()
                return httpx.Response(204)
        if path == "/config/preview":
            pending = self.changes > 0 or self.version is None
            last = {"n": self.version, "result": "ok"} if self.version else None
            return httpx.Response(200, json={"pending": pending, "drift": self.drift,
                                             "changes": max(self.changes, int(pending)), "last_applied": last})
        if path == "/config/apply":
            if self.apply_fails:
                return httpx.Response(422, json={"error": "caddy_rejected", "message": "Caddy said no."})
            self.applies.append(body.get("note", ""))
            self.version = (self.version or 0) + 1
            self.changes = 0
            return httpx.Response(200, json={"n": self.version, "result": "ok", "applied_by": "api:slipway"})
        return httpx.Response(404, json={"error": "not_found", "message": path})

    def _changed(self) -> None:
        self.calls.append("changed")
        self.changes += 1


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
