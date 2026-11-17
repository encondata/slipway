"""Page rendering smoke tests plus host/instance API flows."""

from __future__ import annotations

import pytest

from slipway.services import deployer, hosts, ssh
from slipway.db.session import get_sessionmaker
from slipway.models import Repository
from tests.conftest import login, make_user


async def test_anonymous_pages_redirect_to_login(client):
    r = await client.get("/hosts")
    assert r.status_code == 302 and r.headers["location"] == "/login?next=/hosts"
    r = await client.get("/login")
    assert r.status_code == 200 and "Continue with GitHub" in r.text


async def test_favicon_ico_redirects_to_the_svg_icon(client):
    r = await client.get("/favicon.ico")
    assert r.status_code == 301 and r.headers["location"] == "/static/img/favicon.svg"
    icon = await client.get("/static/img/favicon.svg")
    assert icon.status_code == 200 and icon.headers["content-type"].startswith("image/svg+xml")


def test_asyncssh_connection_chatter_is_kept_out_of_info_logs(app):
    import logging

    assert logging.getLogger("asyncssh").getEffectiveLevel() == logging.WARNING


async def _seed_repo() -> str:
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=7, full_name="acme/web", owner="acme", name="web", html_url="https://github.com/acme/web",
                          detected_config={"dockerfile": True, "compose_file": None, "files": ["Dockerfile"]})
        db.add(repo)
        await db.commit()
        return str(repo.id)


async def test_every_page_renders_for_admin(admin_client, monkeypatch):
    repo_id = await _seed_repo()
    host = (await admin_client.post("/api/v1/hosts", json={"name": "prod-01", "hostname": "10.0.0.5", "username": "deploy", "environment": "prod"})).json()
    inst = (await admin_client.post("/api/v1/instances", json={
        "name": "web prod", "repository_id": repo_id, "host_id": host["id"], "deploy": False,
        "env": {"NODE_ENV": "production"}, "ports": [{"host": 8080, "container": 3000}],
    })).json()
    pages = [
        "/", "/repositories", f"/repositories?repo={repo_id}", "/hosts", f"/hosts/{host['id']}", "/instances",
        "/instances/new", f"/instances/{inst['id']}", f"/instances/{inst['id']}/edit", "/deployments",
        "/deployments/history",
        "/analytics", "/logs", "/search?q=web", "/settings", "/settings/tokens", "/settings/users",
        "/settings/roles", "/settings/audit",
    ]
    for page in pages:
        r = await admin_client.get(page)
        assert r.status_code == 200, f"{page}: {r.status_code}\n{r.text[:2000]}"
        assert "Slipway" in r.text
    assert "ssh-ed25519" in (await admin_client.get(f"/hosts/{host['id']}")).text
    assert (await admin_client.get("/hosts/00000000-0000-0000-0000-000000000000")).status_code == 404


def test_no_emoji_in_the_interface():
    """The interface uses icons from icons.svg, never emoji, in templates, scripts or page code."""
    import re
    from pathlib import Path

    import slipway

    emoji = re.compile("[\U0001F000-\U0001FAFF☀-⛿⬀-⯿️‍]")
    root = Path(slipway.__file__).parent
    found = [
        f"{path.relative_to(root)}:{n}"
        for path in sorted(root.rglob("*")) if path.suffix in {".html", ".js", ".css", ".py"}
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1) if emoji.search(line)
    ]
    assert not found, f"emoji in {found}"


async def test_overview_has_no_greeting(admin_client):
    page = (await admin_client.get("/")).text
    assert "<h1>Overview</h1>" in page
    assert not any(g in page for g in ("Good morning", "Good afternoon", "Good evening"))


async def test_repository_details_open_in_place(admin_client):
    """Each repository row has its details right below it: closed (README not fetched) until clicked, and
    open on load for ?repo=, even when the filter would hide that repository."""
    repo_id = await _seed_repo()
    host = (await admin_client.post("/api/v1/hosts", json={"name": "prod-01", "hostname": "10.0.0.5", "username": "deploy"})).json()
    await admin_client.post("/api/v1/instances", json={"name": "web prod", "repository_id": repo_id, "host_id": host["id"], "deploy": False})

    closed = (await admin_client.get("/repositories")).text
    assert f'data-expand="repo-details-{repo_id}"' in closed
    assert f'<tr class="repo-details" id="repo-details-{repo_id}" hidden>' in closed
    assert f'data-load-later="/api/v1/repositories/{repo_id}/readme"' in closed
    assert f'data-load="/api/v1/repositories/{repo_id}/readme"' not in closed
    assert 'id="details"' not in closed  # no panel at the bottom of the page any more
    assert "web prod" in closed  # the repository's instances are in its details row

    opened = (await admin_client.get(f"/repositories?repo={repo_id}&show=unconfigured")).text
    assert f'<tr class="repo-details" id="repo-details-{repo_id}" >' in opened
    assert f'data-load="/api/v1/repositories/{repo_id}/readme"' in opened
    assert 'aria-expanded="true"' in opened


async def test_malformed_page_params_are_friendly(admin_client):
    assert (await admin_client.get("/repositories?repo=")).status_code == 200
    assert (await admin_client.get("/instances/new?repo=not-a-uuid")).status_code == 200
    r = await admin_client.get("/instances/not-a-uuid", headers={"Accept": "text/html"})
    assert r.status_code == 404 and "<html" in r.text
    r = await admin_client.get("/api/v1/instances/not-a-uuid")
    assert r.status_code == 422 and "detail" in r.json()


async def test_viewer_sees_403_page(make_client):
    await make_user("admin@example.com")
    await make_user("viewer@example.com", roles=["viewer"])
    viewer = make_client()
    await login(viewer, "viewer@example.com")
    r = await viewer.get("/settings/users")
    assert r.status_code == 403 and "users:read" in r.text
    assert (await viewer.get("/instances/new")).status_code == 403
    assert (await viewer.get("/")).status_code == 200


async def test_host_key_methods(admin_client):
    gen = (await admin_client.post("/api/v1/hosts", json={"name": "a", "hostname": "10.0.0.1", "username": "deploy"})).json()
    assert gen["auth_method"] == "key" and gen["public_key"].startswith("ssh-ed25519")
    priv, pub = ssh.generate_keypair("mine")
    pasted = (await admin_client.post("/api/v1/hosts", json={
        "name": "b", "hostname": "10.0.0.2", "username": "deploy", "auth_method": "key", "private_key": priv})).json()
    assert pasted["public_key"] == pub
    r = await admin_client.post("/api/v1/hosts", json={"name": "c", "hostname": "10.0.0.3", "username": "deploy", "auth_method": "key", "private_key": "junk"})
    assert r.status_code == 400
    r = await admin_client.post("/api/v1/hosts", json={"name": "d", "hostname": "10.0.0.3; rm -rf /", "username": "deploy"})
    assert r.status_code == 422
    assert "private_key" not in gen and "password" not in gen


async def test_host_check_pins_key_and_deploy_requires_pin(admin_client, monkeypatch):
    repo_id = await _seed_repo()
    host = (await admin_client.post("/api/v1/hosts", json={"name": "prod-01", "hostname": "10.0.0.5", "username": "deploy"})).json()

    submitted = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, inst_id: submitted.append(dep_id))
    r = await admin_client.post("/api/v1/instances", json={"name": "web", "repository_id": repo_id, "host_id": host["id"]})
    assert r.status_code == 400 and "not been verified" in r.json()["detail"]

    key = ssh.generate_keypair()[1]

    async def fake_probe(target):
        return ssh.ProbeResult(host_key=key, fingerprint=ssh.fingerprint(key), os_info="Debian 13", cpus=2,
                               cpu_percent=10, mem_total_mb=4096, mem_percent=40, docker_version="27.0",
                               docker_error=None, containers_running=0)

    monkeypatch.setattr(hosts.ssh, "probe", fake_probe)
    checked = (await admin_client.post(f"/api/v1/hosts/{host['id']}/check")).json()
    assert checked["status"] == "healthy" and checked["host_key_fingerprint"].startswith("SHA256:")

    r = await admin_client.post("/api/v1/instances", json={"name": "web", "repository_id": repo_id, "host_id": host["id"]})
    assert r.status_code == 201, r.text
    assert len(submitted) == 1
    inst = r.json()
    assert inst["slug"] == "web" and inst["env_keys"] == []
    # A second deploy while one is queued is refused.
    assert (await admin_client.post(f"/api/v1/instances/{inst['id']}/deploy")).status_code == 409
    deps = (await admin_client.get(f"/api/v1/deployments?instance_id={inst['id']}")).json()
    assert deps[0]["status"] == "queued"
    detail = (await admin_client.get(f"/api/v1/deployments/{deps[0]['id']}?log_offset=0")).json()
    assert detail["log"] == "" and detail["log_offset"] == 0


@pytest.mark.parametrize("payload", [
    {"dockerfile_path": "../../etc/shadow"},
    {"env": {"BAD KEY": "x"}},
    {"volumes": [{"source": "relative/path", "target": "/data"}]},
    {"ports": [{"host": 70000, "container": 80}]},
])
async def test_instance_validation(admin_client, payload):
    repo_id = await _seed_repo()
    host = (await admin_client.post("/api/v1/hosts", json={"name": "h", "hostname": "10.0.0.5", "username": "deploy"})).json()
    body = {"name": "web", "repository_id": repo_id, "host_id": host["id"], "deploy": False, **payload}
    assert (await admin_client.post("/api/v1/instances", json=body)).status_code == 422


async def test_env_values_need_write_permission(admin_client, make_client):
    repo_id = await _seed_repo()
    host = (await admin_client.post("/api/v1/hosts", json={"name": "h", "hostname": "10.0.0.5", "username": "deploy"})).json()
    inst = (await admin_client.post("/api/v1/instances", json={
        "name": "web", "repository_id": repo_id, "host_id": host["id"], "deploy": False, "env": {"SECRET": "hunter2"}})).json()
    assert (await admin_client.get(f"/api/v1/instances/{inst['id']}/env")).json() == {"SECRET": "hunter2"}
    await make_user("dev@example.com", roles=["developer"])
    dev = make_client()
    await login(dev, "dev@example.com")
    assert (await dev.get(f"/api/v1/instances/{inst['id']}/env")).status_code == 403
    assert (await dev.get(f"/api/v1/instances/{inst['id']}")).json()["env_keys"] == ["SECRET"]


async def test_secrets_encrypted_at_rest(admin_client):
    await admin_client.post("/api/v1/hosts", json={"name": "h", "hostname": "10.0.0.5", "username": "deploy", "auth_method": "password", "password": "pa55word"})
    async with get_sessionmaker()() as db:
        raw = (await db.execute(__import__("sqlalchemy").text("SELECT password FROM hosts"))).scalar_one()
    assert raw and "pa55word" not in raw
