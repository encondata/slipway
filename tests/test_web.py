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


# ------------------------------------------------------------------ data safety pages (spec §15, test 41)

import html as _html  # noqa: E402
import re as _re  # noqa: E402
import uuid as _uuid  # noqa: E402
from datetime import timedelta as _td  # noqa: E402
from html.parser import HTMLParser as _HTMLParser  # noqa: E402

from slipway.models import Deployment, Instance, Snapshot  # noqa: E402
from slipway.services import data as _data  # noqa: E402
from tests.test_data_api import KEY_B, SHA, T0, add, backup_row, client_with, job, seed, steps  # noqa: E402


class _Tags(_HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str]]] = []

    def handle_starttag(self, tag, attrs) -> None:
        self.tags.append((tag, {k: v or "" for k, v in attrs}))


def _tags(page: str) -> list[tuple[str, dict[str, str]]]:
    parser = _Tags()
    parser.feed(page)
    return parser.tags


def _dialog_html(page: str, dialog_id: str) -> str:
    start = page.index(f'id="{dialog_id}"')
    return page[start: page.index("</dialog>", start)]


async def _roles(make_client) -> dict:
    """Signed-in clients: admin (the first user), viewer, developer and maintainer."""
    out = {}
    for role in ("admin", "viewer", "developer", "maintainer"):
        await make_user(f"{role}@example.com", roles=None if role == "admin" else [role])
        c = make_client()
        await login(c, f"{role}@example.com")
        out[role] = c
    return out


async def test_the_backups_card_is_for_app_instances_and_data_read(make_client):
    c = await _roles(make_client)
    iid = await seed()
    plain = await seed(name="plain", build_source="dockerfile", app_state=None)
    await add(backup_row(iid, at=T0, checked_at=T0), backup_row(iid, at=T0 + _td(hours=1), status="missing"))
    page = (await c["admin"].get(f"/instances/{iid}")).text
    assert 'id="backups-card"' in page and 'data-render="backups"' in page
    assert f'data-load="/api/v1/instances/{iid}/backups?check=true"' in page
    assert "keeps the newest 5 (and up to 10 you take yourself)" in page
    # Rows are rendered from the stored backups; the missing one can be forgotten, not restored.
    assert "On host" in page and "Missing" in page and ">Forget</button>" in page and "Restore…" in page
    assert "Not on prod-01 any more" in page
    assert 'id="backups-card"' not in (await c["admin"].get(f"/instances/{plain}")).text
    # data:read is enough to see it (a viewer), but not to act on it.
    viewer = (await c["viewer"].get(f"/instances/{iid}")).text
    assert 'id="backups-card"' in viewer and "Restore…" not in viewer and ">Delete</button>" not in viewer
    assert 'data-open="backup-now"' not in viewer and 'id="restore-backup"' not in viewer
    reader = await client_with(make_client, "ireader@example.com", ["instances:read"])
    assert 'id="backups-card"' not in (await reader.get(f"/instances/{iid}")).text
    # A developer backs up and restores; deleting is data:reset.
    dev = (await c["developer"].get(f"/instances/{iid}")).text
    assert 'data-open="backup-now"' in dev and 'data-open="take-snapshot"' in dev and "Restore…" in dev
    assert ">Delete</button>" not in dev and 'id="reset-data"' not in dev
    assert ">Delete</button>" in (await c["maintainer"].get(f"/instances/{iid}")).text


async def test_restore_dialog_holds_the_typed_name_and_the_identity_tick_needs_data_reset(make_client):
    c = await _roles(make_client)
    iid = await seed()
    other_keys = backup_row(iid, at=T0, checked_at=T0, identity={"FIELD_ENCRYPTION_KEY": KEY_B})
    await add(other_keys)
    for role in ("maintainer", "developer"):
        page = (await c[role].get(f"/instances/{iid}")).text
        dialog = _dialog_html(page, "restore-backup")
        confirm = next(a for t, a in _tags(dialog) if t == "input" and a.get("name") == "confirm")
        assert confirm["data-must-equal"] == "shop" and confirm["autocomplete"] == "off"
        submit = next(a for t, a in _tags(dialog) if t == "button" and a.get("type") == "submit")
        assert "disabled" in submit and "Restore backup" in dialog
        assert ('name="restore_identity"' in dialog) is (role == "maintainer")
    # The backup with other keys: a maintainer gets a Restore button whose fill asks for the tick; a developer
    # gets the reason instead.
    page = (await c["maintainer"].get(f"/instances/{iid}")).text
    fill = next(_json_loads(a["data-fill"]) for t, a in _tags(page) if a.get("data-open") == "restore-backup")
    assert fill["backup_id"] == str(other_keys.id) and fill["needs_identity"] is True
    assert fill["identity_note"].startswith("Restoring it also puts back the field encryption key")
    dev = (await c["developer"].get(f"/instances/{iid}")).text
    assert "Restoring it puts back old field encryption key; that needs data:reset" in dev
    assert not [a for t, a in _tags(dev) if a.get("data-open") == "restore-backup"]


def _json_loads(text: str):
    import json

    return json.loads(text)


async def test_dirty_and_hold_callouts(admin_client):
    iid = await seed()
    point = backup_row(iid, at=T0, checked_at=T0)
    await add(point)
    dep = await job(iid, "deploy", "failed", at=T0 + _td(minutes=1), backup_id=point.id,
                    steps=steps(backup="succeeded", start="failed"))
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, iid)
        inst.data_dirty = _data.mark_dirty(None, dep, step="start")
        inst.status = "failed"
        await db.commit()
    page = (await admin_client.get(f"/instances/{iid}")).text
    assert f"shop's data was changed by failed deployment {dep.id.hex[:8]} ({dep.short_sha})." in page
    assert f'href="/deployments/{dep.id}#roll-back-panel">Roll back…' in page
    assert "Roll back point" in page  # the chip on the pinned backup

    # A restore that failed while replacing the data holds it: the hold text, and Deploy is off.
    restore = await job(iid, "restore", "failed", at=T0 + _td(minutes=5), backup_id=point.id, restore_backup_id=point.id,
                        commit_sha=SHA, steps=steps(release="succeeded", backup="succeeded", stop="succeeded",
                                                    restore="failed"))
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, iid)
        inst.data_dirty = _data.mark_dirty(inst.data_dirty, restore, step="restore")
        await db.commit()
    page = _html.unescape((await admin_client.get(f"/instances/{iid}")).text)
    assert "shop's last restore stopped part-way (step 4/4: Restore), so its database may be empty or half-restored." in page
    assert f'href="/deployments/{restore.id}">View the job' in page
    assert f"Restore {point.name}…" in page
    deploy = next(a for t, a in _tags(page) if a.get("data-api", "").endswith("/deploy"))
    assert "disabled" in deploy and deploy["title"].startswith("shop's last restore stopped part-way")
    # The job's page says the data may be half-restored.
    job_page = (await admin_client.get(f"/deployments/{restore.id}")).text
    assert "The database may be empty or half-restored, and the app is stopped." in job_page
    assert "Restore of shop" in job_page


async def test_roll_back_is_offered_only_when_available_and_says_what_it_also_undoes(admin_client):
    iid = await seed()
    point = backup_row(iid, at=T0, checked_at=T0)
    await add(point)
    first = await job(iid, "deploy", "failed", at=T0 + _td(minutes=1), backup_id=point.id,
                      steps=steps(backup="succeeded", start="failed"))
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, iid)
        inst.data_dirty = _data.mark_dirty(None, first, step="start")
        inst.status = "failed"
        await db.commit()
    second = await job(iid, "deploy", "failed", at=T0 + _td(minutes=3), steps=steps(backup="succeeded", start="failed"))
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, iid)
        inst.data_dirty = _data.mark_dirty(inst.data_dirty, second, step="start")
        await db.commit()

    page = _html.unescape((await admin_client.get(f"/deployments/{second.id}")).text)
    assert 'id="roll-back-panel"' in page and 'data-open="roll-back"' in page
    dialog = _dialog_html(page, "roll-back")
    assert f"This also undoes failed deployment {first.id.hex[:8]} before it" in dialog
    assert f"backup {point.name}" in _re.sub(r"<[^>]+>", "", dialog)
    assert 'data-must-equal="shop"' in dialog
    # The earlier deployment isn't the latest job any more: no panel, only the reason.
    page = _html.unescape((await admin_client.get(f"/deployments/{first.id}")).text)
    assert 'data-open="roll-back"' not in page and 'id="roll-back"' not in page
    assert f"Roll back isn't available: Deployment {second.id.hex[:8]} ran after this deployment" in page


async def test_snapshots_page_needs_data_read_and_offers_what_each_role_may_do(make_client):
    c = await _roles(make_client)
    async with get_sessionmaker()() as db:
        db.add(Snapshot(name="uat-1", status="ready", origin="upload", app="acme-shop", app_name="Acme shop",
                        repository="acme/shop", db_bytes=5 * 1024 * 1024, db_sha256="0" * 64, file_sha256="1" * 64,
                        file_bytes=6 * 1024 * 1024, identity_keys=["FIELD_ENCRYPTION_KEY"], notes="Seed data"))
        db.add(Snapshot(name="locked-1", status="locked", origin="import", expires_at=T0 + _td(days=7)))
        await db.commit()
    reader = await client_with(make_client, "ireader@example.com", ["instances:read"])
    assert (await reader.get("/snapshots")).status_code == 403
    assert 'href="/snapshots"' not in (await reader.get("/")).text
    viewer = await c["viewer"].get("/snapshots")
    assert viewer.status_code == 200 and "uat-1" in viewer.text and "Seed data" in viewer.text
    assert 'href="/snapshots"' in viewer.text  # the nav entry
    assert "Upload…" not in viewer.text and "Download…" not in viewer.text and ">Rename" not in viewer.text
    assert "6 MiB of 100 GiB used" in viewer.text and "data-poll-reload" not in viewer.text
    maint = (await c["maintainer"].get("/snapshots")).text
    assert "Upload…" in maint and "Unlock…" in maint and "Download…" not in maint and "Rename" in maint
    assert 'id="upload-snapshot"' in maint and 'data-upload="/api/v1/snapshots/upload"' in maint
    admin = _html.unescape((await c["admin"].get("/snapshots")).text)
    assert "Download…" in admin and 'data-generate-passphrase' in admin
    fill = next(_json_loads(a["data-fill"]) for t, a in _tags(admin) if a.get("data-open") == "download-snapshot")
    assert fill["action"].endswith("/exports") and fill["identity"] == "identity keys (FIELD_ENCRYPTION_KEY)"
    # A snapshot being checked makes the page poll.
    async with get_sessionmaker()() as db:
        db.add(Snapshot(name="checking-1", status="checking", origin="import"))
        await db.commit()
    assert 'data-poll-reload="5000"' in (await c["viewer"].get("/snapshots")).text


async def test_snapshots_page_answers_503_when_storage_is_unusable(admin_client, monkeypatch):
    from slipway.services import snapshots as snapshot_service

    monkeypatch.setattr(snapshot_service, "storage_problem", lambda: "SLIPWAY_STORAGE_DIR (/x) isn't writable by Slipway")
    r = await admin_client.get("/snapshots")
    assert r.status_code == 503 and "isn&#39;t writable by Slipway" in r.text


async def test_reset_and_start_over_are_data_reset_and_follow_the_instance(make_client):
    c = await _roles(make_client)
    iid = await seed()
    async with get_sessionmaker()() as db:
        db.add(Snapshot(name="uat-1", status="ready", origin="upload", app="acme-shop", repository="acme/shop",
                        db_sha256="0" * 64, file_sha256="1" * 64))
        db.add(Snapshot(name="other-repo", status="ready", origin="upload", app="acme-shop", repository="acme/fork",
                        db_sha256="0" * 64, file_sha256="1" * 64))
        await db.commit()
    page = _html.unescape((await c["maintainer"].get(f"/instances/{iid}")).text)
    dialog = _dialog_html(page, "reset-data")
    assert "Deletes shop-shop_pgdata on prod-01" in _re.sub(r"<[^>]+>", "", dialog)
    assert "uat-1" in dialog and "other-repo" in dialog
    # A snapshot of another repository needs snapshots:download (the maintainer lacks it).
    options = {a["value"]: a for t, a in _tags(dialog) if t == "option"}
    assert len(options) == 2 and sum("disabled" in a for a in options.values()) == 1
    assert "needs snapshots:download" in dialog
    # A first admin is asked for when starting empty (the manifest declares one), and starter content offered.
    assert 'name="first_admin.fields.username"' in dialog and 'data-required-when="start_from=empty"' in dialog
    assert 'name="seed"' in dialog and 'data-optional-group="first_admin"' in dialog
    assert 'id="reset-data"' not in (await c["developer"].get(f"/instances/{iid}")).text
    # A never-live instance with a release of a failed first deploy gets Start over instead.
    never = await seed(name="never", live=False, app_state={"manifest": {}})
    await job(never, "deploy", "failed", release="/x/releases/abc", steps=steps(start="failed"))
    page = (await c["maintainer"].get(f"/instances/{never}")).text
    assert 'data-open="start-over"' in page and 'id="start-over"' in page and 'id="reset-data"' not in page


async def test_kind_aware_badges_titles_and_the_what_column(admin_client):
    iid = await seed()
    running = await job(iid, "restore", "running", at=T0 + _td(minutes=2), commit_sha=SHA)
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, iid)
        inst.status = "deploying"
        await db.commit()
    page = (await admin_client.get(f"/instances/{iid}")).text
    assert '<span class="badge warning spin" >Restoring</span>' in page
    assert "<td class=\"nowrap\">Restore</td>" in page  # the What column
    detail = (await admin_client.get(f"/deployments/{running.id}")).text
    assert "Restore of shop" in detail and 'data-kind="restore"' in detail and ">Restoring</span>" in detail
    done = await job(iid, "backup", "succeeded", at=T0 + _td(minutes=3), commit_sha=SHA)
    detail = (await admin_client.get(f"/deployments/{done.id}")).text
    assert "Back up of shop" in detail and ">Done</span>" in detail


async def test_first_admin_card_and_starter_content(admin_client):
    from slipway.models import FirstAdmin

    iid = await seed(content_pending=True)
    async with get_sessionmaker()() as db:
        db.add(FirstAdmin(instance_id=iid, fields={"username": "ada", "email": "ada@example.com"}, mode="password",
                          password="pw-not-shown-123", status="pending", last_error="The app's first-admin command failed (exit 2)"))
        await db.commit()
    page = _html.unescape((await admin_client.get(f"/instances/{iid}")).text)
    assert "ada@example.com" in page and "Not created yet" in page and "first-admin command failed (exit 2)" in page
    assert "Create it now" in page and "Change…" in page and "pw-not-shown-123" not in page
    assert "Add starter content" in page
    dialog = _dialog_html(page, "first-admin")
    assert 'value="ada"' in dialog and 'name="fields.username"' in dialog and "Leave it empty to keep" in dialog


async def test_instance_form_offers_seed_snapshots_only_with_data_reset(make_client):
    c = await _roles(make_client)
    await seed()
    async with get_sessionmaker()() as db:
        db.add(Snapshot(name="uat-1", status="ready", origin="upload", app="acme-shop", repository="acme/shop",
                        db_sha256="0" * 64, file_sha256="1" * 64, identity_keys=["FIELD_ENCRYPTION_KEY"]))
        await db.commit()
    page = (await c["maintainer"].get("/instances/new")).text
    box = next(a for t, a in _tags(page) if "data-app-data" in a)
    snaps = _json_loads(box["data-snapshots"])
    assert [s["name"] for s in snaps] == ["uat-1"] and "data-can-seed" in box and "data-can-download" not in box
    assert 'data-full-name="acme/shop"' in page and 'name="keep_backups"' in page
    page = (await c["admin"].get("/instances/new")).text
    assert "data-can-download" in next(a for t, a in _tags(page) if "data-app-data" in a)
    writer = await client_with(make_client, "w2@example.com", ["instances:write", "instances:read"])
    page = (await writer.get("/instances/new")).text
    box = next(a for t, a in _tags(page) if "data-app-data" in a)
    assert _json_loads(box["data-snapshots"]) == [] and "Starting from a snapshot needs the data:reset permission" in page


async def test_reset_offers_from_a_snapshot_only_when_one_is_usable(make_client):
    c = await _roles(make_client)
    iid = await seed()
    async with get_sessionmaker()() as db:
        db.add(Snapshot(name="fork-1", status="ready", origin="upload", app="acme-shop", repository="acme/fork",
                        db_sha256="0" * 64, file_sha256="1" * 64))
        db.add(Snapshot(name="unknown-1", status="ready", origin="upload", app="acme-shop", repository=None,
                        db_sha256="0" * 64, file_sha256="1" * 64))
        await db.commit()
    # Every snapshot needs snapshots:download, which the maintainer lacks: a select of disabled options sends
    # no snapshot_id, so the reset would start empty. "From a snapshot" is off instead.
    dialog = _html.unescape(_dialog_html((await c["maintainer"].get(f"/instances/{iid}")).text, "reset-data"))
    radios = {a["value"]: a for t, a in _tags(dialog) if a.get("name") == "start_from"}
    assert "disabled" in radios["snapshot"] and "(each needs snapshots:download)" in dialog
    select = next(a for t, a in _tags(dialog) if t == "select")
    assert select["data-required-when"] == "start_from=snapshot"
    assert all("disabled" in a for t, a in _tags(dialog) if t == "option")
    # The admin may download, so they can pick one.
    dialog = _dialog_html((await c["admin"].get(f"/instances/{iid}")).text, "reset-data")
    radios = {a["value"]: a for t, a in _tags(dialog) if a.get("name") == "start_from"}
    assert "disabled" not in radios["snapshot"] and "each needs" not in dialog
    # One usable snapshot is enough for the maintainer.
    async with get_sessionmaker()() as db:
        db.add(Snapshot(name="uat-1", status="ready", origin="upload", app="acme-shop", repository="acme/shop",
                        db_sha256="0" * 64, file_sha256="1" * 64))
        await db.commit()
    dialog = _dialog_html((await c["maintainer"].get(f"/instances/{iid}")).text, "reset-data")
    radios = {a["value"]: a for t, a in _tags(dialog) if a.get("name") == "start_from"}
    assert "disabled" not in radios["snapshot"]


async def test_undo_on_a_job_page_follows_the_restore_rules(make_client):
    c = await _roles(make_client)
    iid = await seed()
    # A reset from a snapshot replaced the identity keys: the backup taken before it has the old ones.
    before = backup_row(iid, at=T0, reason="pre_reset", checked_at=T0, identity={"FIELD_ENCRYPTION_KEY": KEY_B})
    await add(before)
    reset = await job(iid, "reset", "succeeded", at=T0 + _td(minutes=1), backup_id=before.id, commit_sha=SHA,
                      steps=steps(backup="succeeded", reset="succeeded"))

    # The maintainer (data:reset) gets Undo… and the dialog with the identity tick.
    page = (await c["maintainer"].get(f"/deployments/{reset.id}")).text
    assert 'data-open="restore-backup"' in page and 'id="restore-backup"' in page
    assert 'name="restore_identity"' in _dialog_html(page, "restore-backup")
    # The developer may restore but not put the keys back: Undo… is off, with the reason, and no dialog.
    page = _html.unescape((await c["developer"].get(f"/deployments/{reset.id}")).text)
    assert "Undo…" in page and 'data-open="restore-backup"' not in page and 'id="restore-backup"' not in page
    assert 'disabled title="Restoring it puts back old field encryption key; that needs data:reset"' in page
    # A role that may restore but not create deployments still gets Undo… (POST /data/restore is data:restore).
    restorer = await client_with(make_client, "restorer@example.com",
                                 ["deployments:read", "instances:read", "data:read", "data:restore"])
    other = await seed(name="other")
    same = backup_row(other, at=T0, reason="pre_restore", checked_at=T0)
    await add(same)
    restore = await job(other, "restore", "succeeded", at=T0 + _td(minutes=1), backup_id=same.id,
                        restore_backup_id=same.id, commit_sha=SHA, steps=steps(backup="succeeded", restore="succeeded"))
    page = (await restorer.get(f"/deployments/{restore.id}")).text
    assert 'data-open="restore-backup"' in page and 'id="restore-backup"' in page
    assert "Retry" not in page and "Redeploy" not in page
    # While another job runs, Undo… waits.
    await job(other, "backup", "running", at=T0 + _td(minutes=2), commit_sha=SHA)
    page = _html.unescape((await restorer.get(f"/deployments/{restore.id}")).text)
    assert 'data-open="restore-backup"' not in page
    assert 'disabled title="A job is running for this instance; wait for it to finish"' in page


async def test_retry_of_a_restore_that_puts_keys_back_needs_data_reset(make_client):
    c = await _roles(make_client)
    iid = await seed()
    old = backup_row(iid, at=T0, checked_at=T0, identity={"FIELD_ENCRYPTION_KEY": KEY_B})
    pre = backup_row(iid, at=T0 + _td(minutes=1), reason="pre_restore", checked_at=T0)
    await add(old, pre)
    failed = await job(iid, "restore", "failed", at=T0 + _td(minutes=2), backup_id=pre.id, restore_backup_id=old.id,
                       commit_sha=SHA, options={"files": False, "restore_identity": True},
                       steps=steps(backup="succeeded", restore="failed"))
    page = (await c["maintainer"].get(f"/deployments/{failed.id}")).text
    assert 'data-open="retry-job"' in page and 'id="retry-job"' in page
    page = _html.unescape((await c["developer"].get(f"/deployments/{failed.id}")).text)
    assert 'data-open="retry-job"' not in page and 'id="retry-job"' not in page
    assert ('disabled title="This restore puts back the backup\'s field encryption key; retrying it needs data:reset"'
            in page)
    # As the API says.
    r = await c["developer"].post(f"/api/v1/deployments/{failed.id}/retry", json={"confirm": "shop"})
    assert r.status_code == 403 and "data:reset" in r.json()["detail"]
