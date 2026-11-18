"""Apps that describe themselves in slipway.yml: parsing, planning, a real-shell deploy, steps and retries."""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, update

from slipway.api.v1 import repositories as repositories_api
from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Host, Instance, Repository, User
from slipway.services import deployer, manifest, switchyard
from slipway.services.github import GitHubClient
from tests.test_deployer import SHA, FakeGitHub, FakeRemote, _connect, _instance, write_source_archive
from tests.test_final_remote import ShellRemote, _deployment, _local, _queue, _seed_at, docker_shim  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = (ROOT / "docs/examples/serversherpa.slipway.yml").read_text()

APP_YML = """\
version: 1
name: Demo
env_file: deploy/env.example
placeholder: CHANGEME
settings:
  APP_DOMAIN: {label: Base domain, required: true}
  APP_LOG: {label: Log level, default: info}
vars:
  APP_ENV: "{slipway.slug}"
  APP_REPO: "{slipway.release}"
  APP_TAG: "{slipway.sha12}"
secrets:
  APP_SECRET: hex
  APP_KEY: fernet
services:
  web: {port: 8080, port_var: APP_WEB_PORT, hostname: "www.{APP_DOMAIN}"}
  admin: {port: 8081, port_var: APP_ADMIN_PORT, hostname: "admin.{APP_DOMAIN}", optional: true}
  mail: {port: 8025, port_var: APP_MAIL_PORT, optional: true, default: false}
optional_services: {var: APP_EXTRAS, none: none}
projects: ["demo-{APP_ENV}-web", "demo-{APP_ENV}-db"]
images: ["demo-web:{APP_TAG}"]
commands:
  build: [sh, deploy/app, build, "{slipway.env_dir}"]
  start: [sh, deploy/app, up, "{slipway.env_dir}"]
  stop: [sh, deploy/app, down, "{slipway.env_dir}"]
"""

ENV_EXAMPLE = """\
# Demo settings
APP_ENV=dev
APP_DOMAIN=example.com
APP_WEB_PORT=8080
APP_SECRET=CHANGEME
APP_KEY=CHANGEME
APP_COLOR=blue
"""

# Records each call and the .env it saw; fails "up" while $FAIL_FLAG exists.
APP_SCRIPT = """\
cmd=$1; dir=$2
echo "$cmd $dir" >> "$APP_LOG"
[ "$cmd" = up ] && [ -n "$FAIL_FLAG" ] && [ -f "$FAIL_FLAG" ] && { echo "migration failed" >&2; exit 1; }
cp "$dir/.env" "$APP_LOG.$cmd.env"
exit 0
"""

BUILTINS = dict(slug="uat", name="UAT", release="/srv/x/releases/r1", env_dir="/srv/x/shared", sha=SHA, sha12=SHA[:12],
                host="10.0.0.1", deployment="0123abcd")


def _plan(man: manifest.Manifest, **kw) -> manifest.AppPlan:
    args = dict(template=ENV_EXAMPLE, builtins=BUILTINS, settings={"APP_DOMAIN": "uat.example.com"}, chosen=None,
                host_ports={}, secrets={"APP_SECRET": "s3cret", "APP_KEY": "k3y"}, env={})
    args.update(kw)
    return manifest.plan(man, **args)


# ------------------------------------------------------------------------- parsing


def test_the_serversherpa_example_parses():
    man = manifest.parse(EXAMPLE)
    assert man.name == "ServerSherpa" and man.env_file == "deploy/stack/env.example"
    assert [s.name for s in man.optional_services] == ["kiosk", "wiki", "learn", "status", "mailpit"]
    assert {s.key: s.kind for s in man.secrets}["SS_TOTP_ENCRYPTION_KEY"] == "fernet"
    assert man.commands["start"] == ("deploy/stack/ss-stack", "up", "{slipway.env_dir}")
    # Phase 2: its data (tests/test_manifest_data.py plans it).
    assert man.identity_keys() == ["SS_TOTP_ENCRYPTION_KEY", "SS_PASSWORD_PEPPER"]
    assert man.data.app == "serversherpa" and man.data.format == "pg-custom"
    assert [v.holds for v in man.data.volumes] == ["database", "files", "other"]
    assert man.commands["dump"] == ("deploy/stack/ss-stack", "pgdump", "{slipway.env_dir}", "{slipway.out}")
    assert "has_data" in man.commands and man.first_admin is not None and man.first_admin.exists_codes == (10,)
    assert man.capabilities() == manifest.CAPABILITIES  # it can do everything


@pytest.mark.parametrize(("text", "message"), [
    ("name: x\ncommands: {start: [a]}", "version: must be 1"),
    ("version: 1\nname: x\ncommands: {start: [a]}\nbogus: 1", "unknown key bogus"),
    ("version: 1\nname: x", "start is required"),
    ("version: 1\nname: x\nvars: {A: '1'}\nsecrets: {A: hex}\ncommands: {start: [a]}", "A is already set by vars.A"),
    ("version: 1\nname: x\nservices: {w: {port: 1, optional: true}}\ncommands: {start: [a]}", "set var"),
    ("version: 1\nname: x\nservices: {w: {hostname: a.b}}\ncommands: {start: [a]}", "needs a tcp port"),
    ("version: 1\nname: x\nservices: {w: {port_var: P}}\ncommands: {start: [a]}", "needs the default port"),
    ("version: 1\nname: x\nservices: {a: {port: 80}, b: {port: 80}}\ncommands: {start: [a]}", "also a's port"),
    ("version: 1\nname: x\nsecrets: {A: rsa}\ncommands: {start: [a]}", "must be one of hex"),
    ("version: 1\nname: x\nvars: {A: '{slipway.nope}'}\ncommands: {start: [a]}", "is not one of"),
    ("version: 1\nname: x\nvars: {A: 'a { b'}\ncommands: {start: [a]}", "lone"),
    ("version: 1\nname: x\nenv_file: ../etc/passwd\ncommands: {start: [a]}", "not a safe path"),
    ("version: 1\nname: x\ncommands: {start: [a], deploy: [b]}", "unknown command"),
    ("version: [", "not valid YAML"),
])
def test_bad_manifests_say_what_is_wrong(text, message):
    with pytest.raises(manifest.ManifestError, match=re.escape(message)):
        manifest.parse(text)


def test_secrets_have_the_right_shape():
    hex_secret, fernet, token = (manifest.Secret("A", "hex"), manifest.Secret("B", "fernet"), manifest.Secret("C", "token"))
    assert re.fullmatch(r"[0-9a-f]{64}", hex_secret.generate())
    assert len(base64.urlsafe_b64decode(fernet.generate())) == 32
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", token.generate())
    man = manifest.parse(APP_YML)
    assert set(manifest.new_secrets(man, {})) == {"APP_SECRET", "APP_KEY"}
    assert manifest.new_secrets(man, {"APP_SECRET": "x", "APP_KEY": "y"}) == {}


# ------------------------------------------------------------------------ planning


def test_plan_fills_in_the_env_routes_projects_and_commands():
    man = manifest.parse(APP_YML)
    plan = _plan(man, chosen=["admin"], host_ports={"web": 8090}, env={"APP_COLOR": "red"})
    env = plan.env
    assert env["APP_ENV"] == "uat" and env["APP_REPO"] == BUILTINS["release"] and env["APP_TAG"] == SHA[:12]
    assert env["APP_DOMAIN"] == "uat.example.com" and env["APP_LOG"] == "info"  # a setting's default
    assert env["APP_WEB_PORT"] == "8090" and env["APP_ADMIN_PORT"] == "8081" and "APP_MAIL_PORT" not in env
    assert env["APP_EXTRAS"] == "admin" and env["APP_COLOR"] == "red" and env["APP_SECRET"] == "s3cret"
    assert plan.routes == [{"hostname": "www.uat.example.com", "service": "web", "container": 8080},
                           {"hostname": "admin.uat.example.com", "service": "admin", "container": 8081}]
    assert plan.projects == ["demo-uat-web", "demo-uat-db"] and plan.images == [f"demo-web:{SHA[:12]}"]
    assert plan.commands["start"] == {"argv": ["sh", "deploy/app", "up", "/srv/x/shared"], "stream": None}
    assert "APP_SECRET" not in plan.public_env
    assert _plan(man, chosen=[]).env["APP_EXTRAS"] == "none"
    assert _plan(man).env["APP_EXTRAS"] == "admin"  # each optional service's default


def test_plan_refuses_what_would_break_the_app():
    man = manifest.parse(APP_YML)
    with pytest.raises(manifest.ManifestError, match=r"Set Base domain \(APP_DOMAIN\)"):
        _plan(man, settings={})
    with pytest.raises(manifest.ManifestError, match="APP_WEB_PORT is set from slipway.yml"):
        _plan(man, env={"APP_WEB_PORT": "1"})
    leaky = manifest.parse(APP_YML.replace('APP_ENV: "{slipway.slug}"', 'APP_ENV: "{APP_SECRET}"'))
    with pytest.raises(manifest.ManifestError, match="is a secret"):
        _plan(leaky)
    with pytest.raises(manifest.ManifestError, match="still CHANGEME"):
        _plan(manifest.parse(APP_YML.replace("  APP_KEY: fernet\n", "")), secrets={"APP_SECRET": "s"})
    with pytest.raises(manifest.ManifestError, match="not a hostname"):
        _plan(man, settings={"APP_DOMAIN": "bad domain"})


def test_env_file_keeps_the_template_and_appends_the_rest():
    lines, values = manifest.parse_env_template("# c\nA=1\nB='two'\nA=3\n")
    assert values == {"A": "3", "B": "two"}
    out = manifest.render_env(lines, {"A": "x", "B": "with space", "C": "it's", "D": "$HOME"})
    assert out == "# c\nA=x\nB='with space'\n\n# Set by Slipway\nC=\"it's\"\nD='$HOME'\n"


# ----------------------------------------------------------------- real-shell deploy


class _AppGitHub(FakeGitHub):
    files = {"slipway.yml": APP_YML, "deploy/env.example": ENV_EXAMPLE, "deploy/app": APP_SCRIPT}

    async def download_tarball(self, repo_id, sha, dest: Path):
        FakeGitHub.calls.append(f"tarball {repo_id}@{sha}")
        return write_source_archive(dest, self.files)


APP_FIELDS = dict(build_source="app", app_settings={"APP_DOMAIN": "uat.example.com"}, app_services=["admin"])


async def _seed_app(root: Path, *, signed_in: bool = False, **fields) -> tuple[uuid.UUID, uuid.UUID]:
    """An app instance deploying into ``root``. ``signed_in``: the admin_client fixture made the user already."""
    if not signed_in:
        return await _seed_at(root, **{**APP_FIELDS, **fields})
    async with get_sessionmaker()() as db:
        user = (await db.execute(select(User).where(User.email == "admin@example.com"))).scalar_one()
        host = Host(name="prod-01", hostname="10.0.0.1", username="deploy", host_key="ssh-ed25519 AAAA", metrics={},
                    deploy_root=str(root))
        repo = Repository(github_id=42, full_name="acme/web", owner="acme", name="web",
                          html_url="https://github.com/acme/web", detected_config={})
        inst = Instance(name="web", slug="web-prod", branch="main", host=host, repository=repo, env={"A": "1"},
                        ports=[], volumes=[], **{**APP_FIELDS, **fields})
        db.add(inst)
        await db.commit()
        return inst.id, user.id


async def _instance_row(instance_id: uuid.UUID) -> Instance:
    async with get_sessionmaker()() as db:
        return await db.get(Instance, instance_id)


async def test_an_app_deploys_from_its_manifest(tmp_path, docker_shim):  # noqa: F811
    env, docker_log = docker_shim
    app_log = tmp_path / "app.log"
    root = tmp_path / "root"
    inst_id, user_id = await _seed_app(root)
    dep_id = await _queue(inst_id, user_id)
    remote = ShellRemote("sh", {**env, "APP_LOG": str(app_log)})
    await deployer.run_deployment(dep_id, connect=_local(remote), github=_AppGitHub)
    dep = await _deployment(dep_id)
    assert dep.status == "succeeded", (dep.error, dep.log)

    shared = root / "web-prod" / "shared"
    release = root / "web-prod" / "releases" / f"{SHA[:12]}-{dep_id.hex[:8]}"
    assert app_log.read_text().splitlines() == [f"build {shared}", f"up {shared}"]
    written = (shared / ".env").read_text()
    assert (shared / ".env").stat().st_mode & 0o777 == 0o600
    assert written.startswith("# Demo settings\nAPP_ENV=web-prod\nAPP_DOMAIN=uat.example.com\nAPP_WEB_PORT=8080\n")
    assert f"APP_REPO={release}\n" in written and "APP_EXTRAS=admin\n" in written and "A=1\n" in written
    assert "CHANGEME" not in written and "APP_COLOR=blue\n" in written

    inst = await _instance_row(inst_id)
    assert set(inst.app_secrets) == {"APP_SECRET", "APP_KEY"} and f"APP_SECRET={inst.app_secrets['APP_SECRET']}\n" in written
    assert inst.app_state["projects"] == ["demo-web-prod-web", "demo-web-prod-db"]
    assert [r["hostname"] for r in inst.app_state["routes"]] == ["www.uat.example.com", "admin.uat.example.com"]
    assert {(p["service"], p["host"]) for p in inst.published_ports} == {("web", 8080), ("admin", 8081)}
    assert [(s["key"], s["status"]) for s in dep.steps] == [
        ("resolve", "succeeded"), ("source", "succeeded"), ("upload", "succeeded"), ("manifest", "succeeded"),
        ("ports", "succeeded"), ("settings", "succeeded"), ("build", "succeeded"), ("backup", "skipped"),
        ("start", "succeeded"), ("finish", "succeeded"), ("proxy", "succeeded"),
    ]  # an app without data gets exactly one more step than before phase 2: backup, skipped (I7)
    assert f"{deployer.STEP_MARK}9/11: Start" in dep.log

    # A second deploy keeps the secrets, and the routes point at the published ports.
    first = dict(inst.app_secrets)
    await deployer.run_deployment(await _queue(inst_id, user_id), connect=_local(remote), github=_AppGitHub)
    assert (await _instance_row(inst_id)).app_secrets == first
    targets = switchyard.route_targets(await _instance_row(inst_id))
    assert [(t.hostname, t.port, t.problem) for t in targets] == [
        ("www.uat.example.com", 8080, None), ("admin.uat.example.com", 8081, None)]


async def test_a_failed_start_is_retried_without_rebuilding(tmp_path, docker_shim, admin_client, monkeypatch):  # noqa: F811
    submitted: list[uuid.UUID] = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, inst_id: submitted.append(dep_id))
    env, _ = docker_shim
    app_log, flag = tmp_path / "app.log", tmp_path / "fail"
    flag.write_text("")
    root = tmp_path / "root"
    inst_id, user_id = await _seed_app(root, signed_in=True)
    dep_id = await _queue(inst_id, user_id)
    remote = ShellRemote("sh", {**env, "APP_LOG": str(app_log), "FAIL_FLAG": str(flag)})
    await deployer.run_deployment(dep_id, connect=_local(remote), github=_AppGitHub)
    dep = await _deployment(dep_id)
    assert dep.status == "failed" and "migration failed" in dep.error
    assert {s["key"]: s["status"] for s in dep.steps}["start"] == "failed"
    release = Path(dep.release)
    assert release.is_dir() and "so a retry can start from it" in dep.log

    flag.unlink()
    app_log.write_text("")
    r = await admin_client.post(f"/api/v1/deployments/{dep_id}/retry")
    assert r.status_code == 202, r.text
    retry_id = uuid.UUID(r.json()["id"])
    assert submitted == [retry_id]
    await deployer.run_deployment(retry_id, connect=_local(remote), github=_AppGitHub)
    retry = await _deployment(retry_id)
    assert retry.status == "succeeded", (retry.error, retry.log)
    assert retry.retry_of_id == dep_id and retry.release == dep.release and retry.commit_sha == SHA
    assert {s["key"]: s["status"] for s in retry.steps} | {} == {
        "resolve": "succeeded", "source": "skipped", "upload": "skipped", "manifest": "succeeded",
        "ports": "succeeded", "settings": "succeeded", "build": "skipped", "backup": "skipped", "start": "succeeded",
        "finish": "succeeded", "proxy": "succeeded",
    }
    assert app_log.read_text().splitlines() == [f"up {root / 'web-prod' / 'shared'}"]  # no second build
    assert (root / "web-prod" / "current").resolve() == release.resolve()


async def test_retry_is_refused_for_what_cannot_be_retried(admin_client, monkeypatch):
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, inst_id: None)
    root = Path("/srv/never-used")
    inst_id, user_id = await _seed_app(root, signed_in=True)
    dep_id = await _queue(inst_id, user_id)
    assert (await admin_client.post(f"/api/v1/deployments/{dep_id}/retry")).status_code == 409  # still queued
    async with get_sessionmaker()() as db:
        await db.execute(update(Deployment).where(Deployment.id == dep_id).values(status="failed"))
        await db.commit()
    r = await admin_client.post(f"/api/v1/deployments/{dep_id}/retry")
    assert r.status_code == 409 and "before it resolved a commit" in r.json()["detail"]


async def test_a_missing_setting_fails_before_anything_runs(tmp_path, docker_shim):  # noqa: F811
    env, _ = docker_shim
    app_log = tmp_path / "app.log"
    root = tmp_path / "root"
    inst_id, user_id = await _seed_app(root, app_settings={})
    dep_id = await _queue(inst_id, user_id)
    await deployer.run_deployment(dep_id, connect=_local(ShellRemote("sh", {**env, "APP_LOG": str(app_log)})),
                                  github=_AppGitHub)
    dep = await _deployment(dep_id)
    assert dep.status == "failed" and "Set Base domain (APP_DOMAIN)" in dep.error
    assert {s["key"]: s["status"] for s in dep.steps}["manifest"] == "failed"
    assert not app_log.exists() and not list((root / "web-prod" / "releases").iterdir())  # the release was removed


async def test_taken_app_ports_move_and_go_back_to_the_app():
    root = Path("/opt/slipway")
    inst_id, user_id = await _seed_app(root)
    dep_id = await _queue(inst_id, user_id)
    # Another container holds 8080; the app's own project holds 8081 (a redeploy), which stays.
    scan = ("docker\t\tother\tother-1\t0.0.0.0:8080->80/tcp\n"
            "docker\t\tdemo-web-prod-web\tdemo-admin\t0.0.0.0:8081->8081/tcp\n")
    files = {"slipway.yml": APP_YML, "deploy/env.example": ENV_EXAMPLE}
    remote = FakeRemote(responses={"/proc/net": scan})

    class GH(_AppGitHub):
        pass
    GH.files = files
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=GH)
    dep = await _deployment(dep_id)
    assert dep.status == "succeeded", (dep.error, dep.log)
    env_file = remote.files["/opt/slipway/web-prod/shared/.env"]
    assert "APP_WEB_PORT=8082\n" in env_file and "APP_ADMIN_PORT=8081\n" in env_file
    assert "Host port 8080/tcp (web container port 8080) is used by container other-1; using 8082 instead" in dep.log
    inst = await _instance_row(inst_id)
    assert {"service": "web", "container": 8080, "protocol": "tcp", "host": 8082, "auto": True} in inst.port_overrides
    assert any(c.startswith(f"cd /opt/slipway/web-prod/releases/{SHA[:12]}") and "deploy/app up" in c
               for c in remote.commands)


# --------------------------------------------------------------- operating an app


def _app(**state) -> Instance:
    return _instance(build_source="app", app_state={
        "projects": ["demo-x-web", "demo-x-db"], "commands": {"stop": ["sh", "deploy/app", "down", "/d"]},
        "releases": {"r1": ["demo-web:aaa"], "r2": ["demo-web:bbb"]}, **state})


def test_app_status_logs_and_actions_cover_every_project():
    inst = _app()
    status = deployer.status_command(inst)
    assert "label=com.docker.compose.project=demo-x-web" in status and "label=com.docker.compose.project=demo-x-db" in status
    assert "docker compose -p demo-x-db logs --tail 50" in deployer.logs_command(inst, 50)
    stop = deployer.control_command(inst, "stop")
    assert stop.index("demo-x-db stop") < stop.index("demo-x-web stop")  # stopped in reverse
    assert "Nothing to do" in deployer.control_command(_instance(build_source="app"), "start")


def test_app_teardown_stops_it_removes_its_projects_and_images_but_never_volumes():
    command = deployer.teardown_command(_app())
    assert "cd /opt/slipway/web-prod/current && sh deploy/app down /d" in command
    assert "docker compose -p demo-x-web down --remove-orphans" in command
    assert "docker image rm demo-web:aaa demo-web:bbb" in command
    app_part = command.split("docker ps -aq --filter label=slipway.instance")[0]  # before the generic cleanup
    assert "--volumes" not in app_part and " -v" not in app_part


def test_app_teardown_reads_the_stop_command_in_both_stored_forms():
    # Phase 2 stores commands as {"argv", "stream"}; app_state saved before it holds plain lists.
    new = deployer.teardown_command(_app(commands={"stop": {"argv": ["sh", "deploy/app", "down", "/d"], "stream": None}}))
    assert "cd /opt/slipway/web-prod/current && sh deploy/app down /d" in new
    assert "argv" not in new and "stream" not in new


def test_app_commands_fill_slots_and_refuse_a_missing_one():
    cmd = {"argv": ["deploy/dump", "--out", {"slot": "out"}], "stream": None}
    assert deployer.app_command("/r", cmd, slots={"out": "/b/x y"}) == "cd /r && ./deploy/dump --out '/b/x y'"
    with pytest.raises(deployer.DeployError, match=r"no value for \{slipway.out\}"):
        deployer.app_command("/r", cmd)


def test_app_commands_run_from_the_release():
    assert deployer.app_command("/r", ["deploy/run", "a b"]) == "cd /r && ./deploy/run 'a b'"
    assert deployer.app_command("/r", ["sh", "-c", "x"]) == "cd /r && sh -c x"
    with pytest.raises(manifest.ManifestError):
        deployer.app_command("/r", ["../bin/evil"])


# --------------------------------------------------------------------------- API


async def test_the_form_reads_a_branch_s_manifest(admin_client, monkeypatch):
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=7, full_name="acme/app", owner="acme", name="app", html_url="https://github.com/acme/app",
                          detected_config={})
        db.add(repo)
        await db.commit()
        repo_id = repo.id
    texts = {"slipway.yml": APP_YML, "broken.yml": "version: 2"}

    missing = httpx.Response(404, json={"message": "Not Found"})

    def handler(request: httpx.Request) -> httpx.Response:
        if "/commits/" in request.url.path:  # the branch exists only as "main"
            if not request.url.path.endswith("/commits/main"):
                return missing
            return httpx.Response(200, json={"sha": SHA, "commit": {"message": "m", "author": {}}, "author": None})
        name = request.url.path.split("/contents/", 1)[1]
        if request.url.params["ref"] != "main":
            return missing
        return httpx.Response(200, text=texts[name]) if name in texts else missing

    monkeypatch.setattr(repositories_api, "GitHubClient", lambda token: GitHubClient(token, transport=httpx.MockTransport(handler)))
    url = f"/api/v1/repositories/{repo_id}/manifest?branch=main"
    body = (await admin_client.get(url)).json()
    assert body["found"] and body["manifest"]["name"] == "Demo"
    assert [s["key"] for s in body["manifest"]["settings"]] == ["APP_DOMAIN", "APP_LOG"]
    assert (await admin_client.get(url + "&path=broken.yml")).json()["error"] == "slipway.yml: version: must be 1"
    assert (await admin_client.get(url + "&path=nope.yml")).json() == {"found": False, "path": "nope.yml"}
    assert (await admin_client.get(url + "&path=../x")).status_code == 400
    # A branch (or repository) GitHub won't show this token is an error, not a missing slipway.yml:
    # the form then keeps the manifest from the last deploy.
    r = await admin_client.get(f"/api/v1/repositories/{repo_id}/manifest?branch=gone")
    assert r.status_code == 502 and "Not Found" in r.json()["detail"]


async def test_app_instances_keep_their_settings_and_never_show_secrets(admin_client):
    root = Path("/opt/slipway")
    inst_id, _ = await _seed_app(root, signed_in=True)
    async with get_sessionmaker()() as db:
        await db.execute(update(Instance).where(Instance.id == inst_id).values(app_secrets={"APP_SECRET": "hidden"}))
        await db.commit()
    r = await admin_client.patch(f"/api/v1/instances/{inst_id}", json={
        "app_settings": {"APP_DOMAIN": "prod.example.com"}, "app_services": ["mail", "admin", "mail"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["app_settings"] == {"APP_DOMAIN": "prod.example.com"} and body["app_services"] == ["admin", "mail"]
    assert body["app_secret_keys"] == ["APP_SECRET"] and "hidden" not in json.dumps(body)
    r = await admin_client.patch(f"/api/v1/instances/{inst_id}", json={"app_settings": {"BAD KEY": "x"}})
    assert r.status_code == 422


# ------------------------------------------------------------ review fixes (phase 1)


def test_env_file_lines_slipway_does_not_set_are_kept_as_written():
    template = 'A=1  # port\nB=${A}/x\nC="q\\"x"\nF="two words" # c\nX=CHANGEME # fill in\n'
    lines, values = manifest.parse_env_template(template)
    assert values == {"A": "1", "B": "${A}/x", "C": 'q"x', "F": "two words", "X": "CHANGEME"}
    out = manifest.render_env(lines, {**values, "X": "set"}, ["X"])
    assert out == 'A=1  # port\nB=${A}/x\nC="q\\"x"\nF="two words" # c\nX=set\n'
    man = manifest.parse("version: 1\nname: x\nenv_file: e\nplaceholder: CHANGEME\ncommands: {start: [a]}")
    with pytest.raises(manifest.ManifestError, match="X is still CHANGEME"):
        manifest.plan(man, template=template, builtins=BUILTINS, settings={}, chosen=None, host_ports={}, secrets={}, env={})


@pytest.mark.parametrize("value", ["pa;id", "~/data", "a b", "it's", 'say "hi"', "50%", "a#b", "*", "x=y,z",
                                   "pa55\\", "it's a\\b", 'it\'s \\ "q"\\', "C:\\dir\\"])
def test_env_values_read_the_same_in_a_shell_as_written(tmp_path, value):
    (tmp_path / ".env").write_text(f"V={manifest.format_value(value, 'V')}\n")
    out = subprocess.run(["/bin/sh", "-c", 'set -a; . ./.env; printf %s "$V"'], cwd=tmp_path, capture_output=True,
                         text=True, env={"PATH": os.environ["PATH"], "HOME": "/nonexistent"})
    assert out.returncode == 0 and out.stdout == value, out


@pytest.mark.parametrize(("value", "why"), [("it's $5", "single quote"), ("it's `id`", "single quote"),
                                           ("$HOME\\", "backslash at the end"), ("`id`\\", "backslash at the end")])
def test_env_values_no_quoting_can_carry_are_refused(value, why):
    with pytest.raises(manifest.ManifestError, match=why):
        manifest.format_value(value, "V")


@pytest.mark.parametrize("value", ["pa55\\", "it's a\\b", 'it\'s \\ "q"\\', "a\\nb\\", "plain\\path"])
def test_env_values_compose_reads_as_written(value):
    """Compose's dotenv reading (as parse_env_template mirrors it) gets the value back, the line after intact."""
    _, values = manifest.parse_env_template(f"V={manifest.format_value(value, 'V')}\nNEXT=after\n")
    assert values == {"V": value, "NEXT": "after"}


def test_vars_see_final_ports_and_earlier_vars_only():
    man = manifest.parse(APP_YML.replace('  APP_TAG: "{slipway.sha12}"\n',
                                         '  APP_TAG: "{slipway.sha12}"\n  APP_URL: "http://{slipway.host}:{APP_WEB_PORT}/{APP_ENV}"\n'))
    assert _plan(man, host_ports={"web": 8090}).env["APP_URL"] == "http://10.0.0.1:8090/uat"
    early = manifest.parse(APP_YML.replace('  APP_ENV: "{slipway.slug}"\n', '  APP_FIRST: "{APP_TAG}"\n  APP_ENV: "{slipway.slug}"\n'))
    with pytest.raises(manifest.ManifestError, match="APP_TAG} is set later in vars"):
        _plan(early)


def test_instance_variables_never_reach_templates():
    man = manifest.parse(APP_YML.replace('start: [sh, deploy/app, up, "{slipway.env_dir}"]',
                                         'start: [sh, deploy/app, up, "{APP_COLOR}"]'))
    with pytest.raises(manifest.ManifestError, match="APP_COLOR} is set in the instance's environment variables"):
        _plan(man, env={"APP_COLOR": "hunter2"})
    assert _plan(man).commands["start"]["argv"][-1] == "blue"  # the env_file default is fine


def test_bare_yaml_numbers_are_not_taken_as_text():
    with pytest.raises(manifest.ManifestError, match='put numbers, versions and octal values in quotes'):
        manifest.parse("version: 1\nname: x\nvars: {PY: 3.10}\ncommands: {start: [a]}")


async def _deploy(inst_id, user_id, remote, gh=_AppGitHub) -> Deployment:
    dep_id = await _queue(inst_id, user_id)
    await deployer.run_deployment(dep_id, connect=_local(remote), github=gh)
    return await _deployment(dep_id)


async def _retry(dep: Deployment, user_id, remote, gh=_AppGitHub) -> Deployment:
    async with get_sessionmaker()() as db:
        new = Deployment(instance_id=dep.instance_id, branch="main", triggered_by_id=user_id, log="", retry_of_id=dep.id)
        db.add(new)
        await db.commit()
        new_id = new.id
    await deployer.run_deployment(new_id, connect=_local(remote), github=gh)
    return await _deployment(new_id)


async def test_a_retry_after_a_move_uses_the_release_in_the_new_folder(tmp_path, docker_shim):  # noqa: F811
    env, _ = docker_shim
    flag = tmp_path / "fail"
    flag.write_text("")
    old, new = tmp_path / "old", tmp_path / "new"
    inst_id, user_id = await _seed_app(old)
    remote = ShellRemote("sh", {**env, "APP_LOG": str(tmp_path / "app.log"), "FAIL_FLAG": str(flag)})
    first = await _deploy(inst_id, user_id, remote)
    assert first.status == "failed"
    shutil.copytree(old / "web-prod", new / "web-prod", symlinks=True)  # what a folder move does
    async with get_sessionmaker()() as db:
        await db.execute(update(Instance).where(Instance.id == inst_id).values(deploy_dir=str(new / "web-prod")))
        await db.commit()
    flag.unlink()
    retry = await _retry(first, user_id, remote)
    assert retry.status == "succeeded", (retry.error, retry.log)
    moved = new / "web-prod" / "releases" / Path(first.release).name
    assert retry.release == str(moved) and os.readlink(new / "web-prod" / "current") == str(moved)


async def test_a_retry_that_fails_early_keeps_the_release_it_reused(tmp_path, docker_shim):  # noqa: F811
    env, _ = docker_shim
    flag = tmp_path / "fail"
    flag.write_text("")
    inst_id, user_id = await _seed_app(tmp_path / "root")
    remote = ShellRemote("sh", {**env, "APP_LOG": str(tmp_path / "app.log"), "FAIL_FLAG": str(flag)})
    first = await _deploy(inst_id, user_id, remote)
    async with get_sessionmaker()() as db:  # the retry now fails reading slipway.yml's settings
        await db.execute(update(Instance).where(Instance.id == inst_id).values(app_settings={}))
        await db.commit()
    retry = await _retry(first, user_id, remote)
    assert retry.status == "failed" and "Set Base domain" in retry.error
    assert Path(first.release).is_dir() and "so a retry can start from it" in retry.log


async def test_a_failed_deploy_leaves_the_app_state_of_the_live_release(tmp_path, docker_shim):  # noqa: F811
    env, _ = docker_shim
    flag = tmp_path / "fail"
    inst_id, user_id = await _seed_app(tmp_path / "root")
    remote = ShellRemote("sh", {**env, "APP_LOG": str(tmp_path / "app.log"), "FAIL_FLAG": str(flag)})
    assert (await _deploy(inst_id, user_id, remote)).status == "succeeded"

    class Renamed(_AppGitHub):
        files = {**_AppGitHub.files, "slipway.yml": APP_YML.replace('"demo-{APP_ENV}-web"', '"demo-{APP_ENV}-app"')}

    flag.write_text("")
    assert (await _deploy(inst_id, user_id, remote, Renamed)).status == "failed"
    inst = await _instance_row(inst_id)
    assert inst.app_state["projects"] == ["demo-web-prod-web", "demo-web-prod-db"]  # still what runs
    assert inst.app_state["known_projects"] == ["demo-web-prod-web", "demo-web-prod-db", "demo-web-prod-app"]
    teardown = deployer.teardown_command(inst)
    assert all(f"-p {p} down" in teardown for p in inst.app_state["known_projects"])
    assert "demo-web-prod-app" in deployer.leftovers_command(inst) and "demo-web-prod-app" in deployer.bind_sources_command(inst)
    # The failed release's new project may have containers up: status, logs and stop see it too.
    assert "demo-web-prod-app" in deployer.status_command(inst) and "demo-web-prod-app" in deployer.logs_command(inst)
    assert inst.app_state["starting"] == ["demo-web-prod-app", "demo-web-prod-db"]
    assert deployer.app_projects(inst) == ["demo-web-prod-web", "demo-web-prod-db", "demo-web-prod-app"]


async def test_two_apps_on_a_host_cannot_share_a_project(tmp_path, docker_shim):  # noqa: F811
    env, _ = docker_shim
    inst_id, user_id = await _seed_app(tmp_path / "root")
    async with get_sessionmaker()() as db:
        first = await db.get(Instance, inst_id)
        other = Instance(name="other", slug="other", branch="main", host_id=first.host_id, repository_id=first.repository_id,
                         env={}, ports=[], volumes=[], status="running",
                         app_state={"projects": ["demo-web-prod-db"]}, build_source="app")
        db.add(other)
        await db.commit()
    dep = await _deploy(inst_id, user_id, ShellRemote("sh", {**env, "APP_LOG": str(tmp_path / "app.log")}))
    assert dep.status == "failed" and "demo-web-prod-db is also instance other's" in dep.error


async def test_a_compose_retry_reads_port_variables_from_the_release():
    yml = 'services:\n  web:\n    ports: ["${WEB_PORT:-8080}:80"]\n'
    hex_dump = " ".join(f"{b:02x}" for b in yml.encode())

    class OldCompose(FakeRemote):
        async def run(self, command, *, check=True, on_line=None, timeout=None):
            if "--no-interpolate" in command:
                raise deployer.ssh.CommandFailed(command, 1, "invalid port")
            return await super().run(command, check=check, on_line=on_line, timeout=timeout)

    remote = OldCompose(responses={"od -An -v -tx1": hex_dump})
    raw = await deployer._port_variables_source(remote, _instance(build_source="compose"), "/r", None)
    assert raw == {"services": {"web": {"ports": ["${WEB_PORT:-8080}:80"]}}}
    assert any("/r/docker-compose.yml" in c for c in remote.commands)


async def test_the_instances_list_names_apps(admin_client):
    await _seed_app(Path("/opt/slipway"), signed_in=True)
    page = (await admin_client.get("/instances")).text
    assert '<td class="muted">App</td>' in page


# ------------------------------------------------------------ review fixes (phase 1, round 2)


def test_running_compose_env_again_keeps_the_repository_defaults(tmp_path):
    """A retry or a port move runs it again on the same release: the repository's .env is still read."""
    from tests.test_final_remote import _at
    inst = _at(tmp_path, build_source="compose")
    paths = deployer.paths_for(inst)
    release = Path(paths.release(SHA, uuid.uuid4()))
    release.mkdir(parents=True)
    (release / ".env").write_text("POSTGRES_DB=app\n")
    Path(paths.shared).mkdir(parents=True)
    Path(paths.slipway_env_file).write_text("SECRET=x\n")
    for _ in range(2):
        out = subprocess.run(["sh", "-c", deployer.compose_env_command(inst, str(release))], capture_output=True, text=True)
        assert out.returncode == 0, out
        assert Path(paths.env_file).read_text() == "POSTGRES_DB=app\n\nSECRET=x\n"
    assert (release / ".env").is_symlink() and (release / deployer.REPO_ENV_FILE).read_text() == "POSTGRES_DB=app\n"


def test_unexpanded_env_file_defaults_cannot_be_copied():
    man = manifest.parse(APP_YML.replace('  APP_TAG: "{slipway.sha12}"\n', '  APP_TAG: "{slipway.sha12}"\n  APP_CORS: "{APP_URL}"\n'))
    with pytest.raises(manifest.ManifestError, match=r"vars.APP_CORS: \{APP_URL\} comes from deploy/env.example with a \$"):
        _plan(man, template=ENV_EXAMPLE + "APP_URL=https://www.${APP_DOMAIN}\n")
    # Single quotes are literal for Compose too, and a default Slipway sets is its own value.
    assert _plan(man, template=ENV_EXAMPLE + "APP_URL='https://www.${APP_DOMAIN}'\n").env["APP_CORS"] == "https://www.${APP_DOMAIN}"
    assert _plan(man, template=ENV_EXAMPLE + "APP_URL=https://www.example.com\n").env["APP_CORS"] == "https://www.example.com"
    # A $ in a comment isn't part of the value.
    for line in ("APP_URL=https://www.example.com  # or ${APP_DOMAIN}\n", 'APP_URL="https://www.example.com" # was $OLD\n'):
        assert _plan(man, template=ENV_EXAMPLE + line).env["APP_CORS"] == "https://www.example.com"


def test_app_start_and_stop_fail_when_docker_cannot_list_containers(tmp_path, docker_shim):  # noqa: F811
    env, _ = docker_shim
    for action in ("start", "stop"):
        command = deployer.control_command(_app(), action)
        assert subprocess.run(["sh", "-c", command], env={**env, "FAKE_PS_FAILS": "1"}, capture_output=True).returncode != 0
        assert subprocess.run(["sh", "-c", command], env=env, capture_output=True).returncode == 0  # no containers: nothing to do


async def _raw_app_secrets(instance_id: uuid.UUID, value: str | None) -> None:
    from sqlalchemy import Text, column, table
    raw = table("instances", column("id", Instance.__table__.c.id.type), column("app_secrets", Text()))
    async with get_sessionmaker()() as db:
        await db.execute(update(raw).where(raw.c.id == instance_id).values(app_secrets=value))
        await db.commit()


async def test_unreadable_app_secrets_are_never_replaced_by_new_ones(tmp_path, docker_shim):  # noqa: F811
    from slipway.core.crypto import encrypt
    env, _ = docker_shim
    remote = ShellRemote("sh", {**env, "APP_LOG": str(tmp_path / "app.log")})
    inst_id, user_id = await _seed_app(tmp_path / "root")
    await _raw_app_secrets(inst_id, encrypt("null"))  # what rotate-encryption-key --clear-unreadable leaves
    dep = await _deploy(inst_id, user_id, remote)
    assert dep.status == "failed" and "can't be decrypted" in dep.error and "APP_SECRET, APP_KEY" in dep.error
    assert (await _instance_row(inst_id)).app_secrets is None  # nothing was generated

    # Setting every secret on the instance (their old values) lets it deploy again.
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, inst_id)
        inst.env = {"A": "1", "APP_SECRET": "old-secret", "APP_KEY": "old-key"}
        await db.commit()
    dep = await _deploy(inst_id, user_id, remote)
    assert dep.status == "succeeded", (dep.error, dep.log)
    written = (tmp_path / "root" / "web-prod" / "shared" / ".env").read_text()
    assert "APP_SECRET=old-secret\n" in written and "APP_KEY=old-key\n" in written
    # They are kept as the app's secrets (not new random ones), so the variables can go again.
    assert (await _instance_row(inst_id)).app_secrets == {"APP_SECRET": "old-secret", "APP_KEY": "old-key"}
    async with get_sessionmaker()() as db:
        (await db.get(Instance, inst_id)).env = {"A": "1"}
        await db.commit()
    assert (await _deploy(inst_id, user_id, remote)).status == "succeeded"
    assert "APP_SECRET=old-secret\n" in (tmp_path / "root" / "web-prod" / "shared" / ".env").read_text()


async def test_clearing_unreadable_keys_flags_app_secrets_for_re_entry(tmp_path):
    from slipway import cli
    inst_id, _ = await _seed_app(tmp_path / "root")
    await _raw_app_secrets(inst_id, "not-a-token-any-key-can-read")
    async with get_sessionmaker()() as db:
        await cli._rotate_secrets(db, clear_unreadable=True)
        await db.commit()
    async with get_sessionmaker()() as db:
        stored = await db.scalar(select(Instance.app_secrets.is_not(None)).where(Instance.id == inst_id))
        assert stored and (await db.get(Instance, inst_id)).app_secrets is None


async def test_projects_already_on_the_host_are_not_taken_over(tmp_path, docker_shim):  # noqa: F811
    env, _ = docker_shim
    root = tmp_path / "root"
    inst_id, user_id = await _seed_app(root)
    shell = {**env, "APP_LOG": str(tmp_path / "app.log")}
    dep = await _deploy(inst_id, user_id, ShellRemote("sh", {**shell, "FAKE_PS": "aaaaaaaaaaaa"}))
    assert dep.status == "failed" and "already runs containers in the Compose projects demo-web-prod-db, demo-web-prod-web," in dep.error

    # Volumes without containers: a deleted instance's data, made with secrets this one doesn't have.
    (root / ".slipway-kept").mkdir(parents=True)
    (root / ".slipway-kept" / "web-prod-0123abcd.env").write_text("APP_SECRET=old\n")
    volumes = {**shell, "FAKE_VOLUMES": "demo-web-prod-db_data"}
    dep = await _deploy(inst_id, user_id, ShellRemote("sh", volumes))
    assert dep.status == "failed" and "already has the volumes demo-web-prod-db_data" in dep.error
    assert "Set APP_SECRET, APP_KEY as environment variables" in dep.error
    assert str(root / ".slipway-kept" / "web-prod-0123abcd.env") in dep.error
    assert not (await _instance_row(inst_id)).app_secrets  # neither check kept generated secrets

    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, inst_id)
        inst.env = {"APP_SECRET": "old", "APP_KEY": "old-key"}
        await db.commit()
    assert (await _deploy(inst_id, user_id, ShellRemote("sh", volumes))).status == "succeeded"
    assert (await _instance_row(inst_id)).app_secrets == {"APP_SECRET": "old", "APP_KEY": "old-key"}
    # Its own projects from then on: their volumes are its data.
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, inst_id)
        inst.env = {}
        await db.commit()
    dep = await _deploy(inst_id, user_id, ShellRemote("sh", volumes))
    assert dep.status == "succeeded", dep.error
    assert "starting" not in (await _instance_row(inst_id)).app_state


async def test_deleting_an_app_keeps_its_env_next_to_its_volumes(tmp_path, docker_shim):  # noqa: F811
    from tests.test_final_remote import _at
    env, _ = docker_shim
    inst = _at(tmp_path, build_source="app", app_state={"projects": ["demo-x-web"], "known_projects": ["demo-x-db"]})
    paths = deployer.paths_for(inst)
    Path(paths.shared).mkdir(parents=True)
    Path(paths.env_file).write_text("APP_SECRET=s3cret\n")
    warning = await deployer.destroy(inst, connect=_local(ShellRemote("sh", {**env, "FAKE_VOLUMES": "demo-x-db_data"})))
    kept = Path(deployer.kept_env_path(paths, inst))
    assert kept.read_text() == "APP_SECRET=s3cret\n" and kept.stat().st_mode & 0o777 == 0o600
    assert warning and str(kept) in warning and not Path(paths.base).exists()

    # Without volumes there is no data to open, and nothing is kept.
    inst2 = _at(tmp_path / "two", build_source="app", app_state={"projects": ["demo-y-web"]})
    paths2 = deployer.paths_for(inst2)
    Path(paths2.shared).mkdir(parents=True)
    Path(paths2.env_file).write_text("APP_SECRET=s3cret\n")
    assert await deployer.destroy(inst2, connect=_local(ShellRemote("sh", env))) is None
    assert not (tmp_path / "two" / ".slipway-kept").exists()


async def test_an_app_whose_env_cannot_be_copied_keeps_its_folder(tmp_path, docker_shim):  # noqa: F811
    """The folder's parent isn't writable (mkdir's error names .slipway-kept): the folder and its .env stay."""
    from tests.test_final_remote import _at
    env, _ = docker_shim
    parent = tmp_path / "opt"
    inst = _at(parent, build_source="app", app_state={"projects": ["demo-x-web"]})
    paths = deployer.paths_for(inst)
    Path(paths.shared).mkdir(parents=True)
    Path(paths.env_file).write_text("APP_SECRET=s3cret\n")
    parent.chmod(0o555)
    try:
        warning = await deployer.destroy(inst, connect=_local(ShellRemote("sh", {**env, "FAKE_VOLUMES": "demo-x-web_data"})))
    finally:
        parent.chmod(0o755)
    assert Path(paths.env_file).read_text() == "APP_SECRET=s3cret\n"
    assert warning and f"they stay in {paths.env_file}" in warning


async def test_a_delete_that_fails_removes_the_copy_it_made(tmp_path, docker_shim):  # noqa: F811
    from tests.test_final_remote import _at
    env, _ = docker_shim
    inst = _at(tmp_path, build_source="app", app_state={"projects": ["demo-x-web"]})
    paths = deployer.paths_for(inst)
    Path(paths.shared).mkdir(parents=True)
    Path(paths.env_file).write_text("APP_SECRET=s3cret\n")
    remote = ShellRemote("sh", {**env, "FAKE_VOLUMES": "demo-x-web_data", "FAKE_PS": "aaaaaaaaaaaa"})
    with pytest.raises(deployer.DeployError, match="still on"):
        await deployer.destroy(inst, connect=_local(remote))
    assert not Path(deployer.kept_env_path(paths, inst)).exists() and Path(paths.env_file).exists()


async def test_an_empty_variable_does_not_stand_in_for_an_unreadable_secret(tmp_path, docker_shim):  # noqa: F811
    from slipway.core.crypto import encrypt
    env, _ = docker_shim
    inst_id, user_id = await _seed_app(tmp_path / "root")
    async with get_sessionmaker()() as db:
        (await db.get(Instance, inst_id)).env = {"APP_SECRET": "", "APP_KEY": "old-key"}
        await db.commit()
    await _raw_app_secrets(inst_id, encrypt("null"))
    dep = await _deploy(inst_id, user_id, ShellRemote("sh", {**env, "APP_LOG": str(tmp_path / "app.log")}))
    assert dep.status == "failed" and "can't be decrypted" in dep.error and "APP_SECRET" in dep.error
    assert (await _instance_row(inst_id)).app_secrets is None


async def test_failed_deploys_do_not_pile_up_releases(tmp_path, docker_shim):  # noqa: F811
    env, _ = docker_shim
    flag = tmp_path / "fail"
    root = tmp_path / "root"
    inst_id, user_id = await _seed_app(root)
    remote = ShellRemote("sh", {**env, "APP_LOG": str(tmp_path / "app.log"), "FAIL_FLAG": str(flag)})
    assert (await _deploy(inst_id, user_id, remote)).status == "succeeded"
    live = (root / "web-prod" / "current").resolve()
    flag.write_text("")
    for _ in range(5):
        last = await _deploy(inst_id, user_id, remote)
        assert last.status == "failed"
    releases = list((root / "web-prod" / "releases").iterdir())
    assert len(releases) == deployer.KEEP_RELEASES + 1  # the live one and the newest failed ones
    assert Path(last.release) in releases and live in [r.resolve() for r in releases]
    assert "Removed the release of an older failed deployment" in last.log

    # Retrying a failed deployment whose release is gone downloads its commit again.
    async with get_sessionmaker()() as db:
        oldest = (await db.execute(select(Deployment).where(Deployment.instance_id == inst_id, Deployment.status == "failed")
                                   .order_by(Deployment.created_at))).scalars().first()
    assert not Path(oldest.release).exists()
    flag.unlink()
    retry = await _retry(oldest, user_id, remote)
    assert retry.status == "succeeded", (retry.error, retry.log)
    assert "no longer on prod-01: downloading the commit again" in retry.log
    assert {s["key"]: s["status"] for s in retry.steps}["source"] == "succeeded"


async def test_retry_is_refused_once_the_instance_deploys_another_branch(admin_client, monkeypatch):
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, inst_id: None)
    inst_id, user_id = await _seed_app(Path("/srv/never-used"), signed_in=True)
    dep_id = await _queue(inst_id, user_id)
    async with get_sessionmaker()() as db:
        await db.execute(update(Deployment).where(Deployment.id == dep_id).values(
            status="failed", commit_sha=SHA, branch="experimental"))
        await db.commit()
    r = await admin_client.post(f"/api/v1/deployments/{dep_id}/retry")
    assert r.status_code == 409 and "now deploys main" in r.json()["detail"]
    page = await admin_client.get(f"/deployments/{dep_id}")
    assert f"/api/v1/deployments/{dep_id}/retry" not in page.text


async def test_only_those_who_set_up_instances_read_manifests(client, make_client):
    from tests.conftest import login, make_user
    await make_user("admin@example.com")
    await make_user("viewer@example.com", roles=["viewer"])
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=8, full_name="acme/v", owner="acme", name="v", html_url="https://github.com/acme/v",
                          detected_config={})
        db.add(repo)
        await db.commit()
        repo_id = repo.id
    await login(client, "viewer@example.com")
    r = await client.get(f"/api/v1/repositories/{repo_id}/manifest?branch=main&path=.env.production")
    assert r.status_code == 403
    admin = make_client()
    await login(admin, "admin@example.com")
    r = await admin.get(f"/api/v1/repositories/{repo_id}/manifest?branch=main&path=.env.production")
    assert r.status_code == 400 and "not a .yml or .yaml file" in r.json()["detail"]


def test_asset_version_survives_a_file_vanishing(tmp_path, monkeypatch):
    from slipway.web import pages
    (tmp_path / "a.css").write_text("a")
    gone = tmp_path / "b.js"
    gone.write_text("b")
    real_is_file = Path.is_file

    def is_file(self):
        result = real_is_file(self)
        if self == gone:
            self.unlink()  # replaced between the check and the stat
        return result

    monkeypatch.setattr(pages, "STATIC_DIR", tmp_path)
    monkeypatch.setattr(pages, "_asset_stamp", (0.0, ""))
    monkeypatch.setattr(Path, "is_file", is_file)
    assert len(pages.asset_version()) == 12
