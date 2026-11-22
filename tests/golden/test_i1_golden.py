"""Test 44 (phase 3, I1): instances outside environments behave exactly as in phase 2.

Standalone Dockerfile, compose and app instances (an app without data and one with data) are deployed, backed
up, restored, reset and given a snapshot as phase 2 tests do, and what Slipway did is compared with what Slipway
did at 83dca5d (the commit before phase 3), stored in ``phase2.json`` next to this file:

- every job's step keys, names, outcomes and notes, and the step lists ``steps_for`` gives each kind;
- the bytes of the ``.env`` (and ``slipway.env``) each job wrote;
- the commands the app ran (its ``$APP_LOG``) and the commands sent to the host of a Dockerfile or compose
  instance;
- every Switchyard call with its body (so the markers too).

Ids are fixed and the temporary folder is replaced by ``<TMP>``, so the record doesn't depend on the run. To
write the file again from a checkout of 83dca5d, run this module there with ``SLIPWAY_WRITE_GOLDEN`` set to the
path to write; nothing else may change it.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, update

from slipway.db.session import get_sessionmaker
from slipway.models import AppSetting, Deployment, Host, Instance, Repository, User
from slipway.services import deployer, switchyard
from tests.conftest import make_user
from tests.test_data_jobs import DF_SHIM, App, DataGitHub, _get
from tests.test_deployer import FakeGitHub, FakeRemote, _connect
from tests.test_final_remote import docker_shim  # noqa: F401

try:  # phase 3 moved the fake out of test_switchyard.py
    from tests.fake_switchyard import KEY, FakeSwitchyard
except ImportError:  # pragma: no cover - the 83dca5d checkout that writes the golden file
    from tests.test_switchyard import KEY, FakeSwitchyard

GOLDEN = Path(__file__).with_name("phase2.json")
INSTANCE_ID = uuid.UUID("00000000-0000-4000-8000-0000000000a1")
USER_EMAIL = "golden@example.com"
SECRETS = {"APP_SECRET": "5" * 64, "APP_KEY": "k" * 43 + "="}
ROUTE = {"hostname": "app.example.com", "service": None, "container": 3000, "tls_mode": "auto"}
COMPOSE_CONFIG = {"services": {"web": {"image": "nginx", "ports": [
    {"mode": "ingress", "target": 80, "published": "8080", "protocol": "tcp"}]}}}


def _dep_id(n: int) -> uuid.UUID:
    return uuid.UUID(f"{n:08x}-0000-4000-9000-000000000000")


class Recorder:
    """Switchyard calls with their bodies, read off the fake's transport."""

    def __init__(self, fake: FakeSwitchyard) -> None:
        self.fake, self.calls = fake, []

    def handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.calls.append({"method": request.method, "path": request.url.path, "body": body})
        return self.fake.handle(request)

    def take(self) -> list[dict]:
        out, self.calls = self.calls, []
        return out


@pytest.fixture
def sy(monkeypatch):
    rec = Recorder(FakeSwitchyard())
    monkeypatch.setattr(switchyard, "transport_factory", lambda: httpx.MockTransport(rec.handle))
    return rec


async def _configure_switchyard() -> None:
    async with get_sessionmaker()() as db:
        db.add(AppSetting(key=switchyard.SETTING_KEY, value={"url": "https://sy.example.test",
                                                             "default_tls_mode": "auto"}, secret=KEY))
        await db.commit()


class Normal:
    """Replaces what changes between runs: the temporary folder, and dates and times in notes and names."""

    def __init__(self, tmp: Path | None = None) -> None:
        self.tmp = str(tmp) if tmp is not None else None

    def text(self, value: str) -> str:
        if self.tmp:
            value = value.replace(os.path.realpath(self.tmp), "<TMP>").replace(self.tmp, "<TMP>")
        value = re.sub(r"\d{8}T\d{6}Z?", "<STAMP>", value)
        # Ids Slipway makes (backups, snapshots); the fixed instance and deployment ids stay.
        value = re.sub(r"\b[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}\b",
                       lambda m: m.group(0) if re.search(r"4000-?[89]000", m.group(0)) else "<ID>", value)
        value = re.sub(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?(\.\d+)?( UTC|Z|\+00:00)?", "<TIME>", value)
        value = re.sub(r"\b\d+(\.\d+)? (B|KiB|MiB|GiB|bytes)\b", "<SIZE>", value)
        return value

    def value(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.value(v) for v in value]
        if isinstance(value, dict):
            return {k: self.value(v) for k, v in value.items()}
        return value


def _steps(dep: Deployment, norm: Normal) -> list[list]:
    return [[r["key"], r["name"], r["status"], norm.text(r.get("note") or "")] for r in dep.steps or []]


def _step_lists() -> dict[str, list[str]]:
    """``steps_for`` of a standalone app instance and of Dockerfile and compose instances, for every kind and
    every combination of its flags (pure: nothing is deployed)."""
    out: dict[str, list[str]] = {}
    host = Host(name="prod-01", hostname="10.0.0.1", username="deploy")
    for source in ("dockerfile", "compose", "app"):
        inst = Instance(id=INSTANCE_ID, name="web", slug="web-prod", branch="main", host=host, build_source=source,
                        ports=[], volumes=[], env={})
        kinds = ["deploy"] if source != "app" else ["deploy", "restore", "rollback", "reset", "backup", "snapshot",
                                                     "admin", "content"]
        for kind in kinds:
            for flags in range(1 << 7):
                kw = dict(snapshot=bool(flags & 1), first_admin=bool(flags & 2), seed=bool(flags & 4),
                          files=bool(flags & 8), stop_app=bool(flags & 16), stopped=bool(flags & 32),
                          start_over=bool(flags & 64))
                rows = deployer.steps_for(inst, kind, **kw,
                                          rollback_of=_dep_id(7) if kind == "rollback" else None)
                out[f"{source}/{kind}/{flags}"] = [f"{r['key']}={r['name']}" for r in rows]
        out[f"{source}/new_steps"] = [f"{r['key']}={r['name']}" for r in deployer.new_steps(inst)]
    return out


# ------------------------------------------------------------------ Dockerfile and compose instances


async def _seed_plain(build_source: str, **fields) -> None:
    await make_user(USER_EMAIL)
    async with get_sessionmaker()() as db:
        host = Host(name="prod-01", hostname="10.0.0.1", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
        repo = Repository(github_id=42, full_name="acme/web", owner="acme", name="web",
                          html_url="https://github.com/acme/web", detected_config={})
        inst = Instance(id=INSTANCE_ID, name="web", slug="web-prod", branch="main", host=host, repository=repo,
                        env={"NODE_ENV": "production", "SECRET": "s3cret-value"}, build_source=build_source,
                        ports=[{"host": 8080, "container": 3000, "protocol": "tcp"}], volumes=[],
                        compose_file="compose.yml", routes=[ROUTE], **fields)
        db.add(inst)
        await db.commit()


async def _run_plain(n: int, remote: FakeRemote) -> Deployment:
    async with get_sessionmaker()() as db:
        user = await db.scalar(select(User).where(User.email == USER_EMAIL))
        db.add(Deployment(id=_dep_id(n), instance_id=INSTANCE_ID, branch="main", triggered_by_id=user.id, log=""))
        await db.commit()
    await deployer.run_deployment(_dep_id(n), connect=_connect(remote), github=FakeGitHub)
    return await _get(Deployment, _dep_id(n))


def _plain_record(dep: Deployment, remote: FakeRemote, sy: Recorder) -> dict:
    norm = Normal()
    files = {k: (v if isinstance(v, str) else f"<{len(v)} bytes>") for k, v in sorted(remote.files.items())
             if k.endswith((".env", "slipway.env", ".yml", ".json"))}
    return {"status": dep.status, "error": dep.error, "steps": _steps(dep, norm), "files": files,
            "commands": [norm.text(c) for c in remote.commands], "switchyard": sy.take()}


async def _dockerfile_case(sy: Recorder) -> dict:
    await _configure_switchyard()
    await _seed_plain("dockerfile")
    out = {}
    for n in (1, 2):
        remote = FakeRemote()
        out[f"deploy{n}"] = _plain_record(await _run_plain(n, remote), remote, sy)
    return out


async def _compose_case(sy: Recorder) -> dict:
    await _configure_switchyard()
    await _seed_plain("compose", published_ports=[])
    async with get_sessionmaker()() as db:
        await db.execute(update(Instance).values(routes=[{**ROUTE, "service": "web", "container": 80}]))
        await db.commit()
    out = {}
    for n in (1, 2):
        remote = FakeRemote(responses={" config --format json": json.dumps(COMPOSE_CONFIG)})
        out[f"deploy{n}"] = _plain_record(await _run_plain(n, remote), remote, sy)
    return out


# ------------------------------------------------------------------------------ app instances

PLAIN_YML = """\
version: 1
name: Plain
env_file: deploy/env.example
placeholder: CHANGEME
settings:
  APP_DOMAIN: {label: Base domain, required: true}
vars:
  APP_ENV: "{slipway.slug}"
  APP_REPO: "{slipway.release}"
secrets:
  APP_SECRET: hex
services:
  web: {port: 8080, port_var: APP_WEB_PORT, hostname: "www.{APP_DOMAIN}"}
projects: ["plain-{APP_ENV}-web"]
commands:
  build: [sh, deploy/app, build, "{slipway.env_dir}"]
  start: [sh, deploy/app, up, "{slipway.env_dir}"]
  stop: [sh, deploy/app, down, "{slipway.env_dir}"]
"""


def _gh(yml: str) -> type[DataGitHub]:
    files = dict(DataGitHub.files)
    files["slipway.yml"] = yml
    files["deploy/env.example"] = "APP_ENV=dev\nAPP_DOMAIN=example.com\nAPP_SECRET=CHANGEME\n"

    class GH(DataGitHub):
        pass

    GH.files = files
    return GH


class GoldenApp(App):
    """test_data_jobs's App with fixed ids, so its records don't depend on the run."""

    n = 0

    async def seed(self, *, env=None, **fields) -> None:
        user = await make_user(USER_EMAIL)
        async with get_sessionmaker()() as db:
            host = Host(name="prod-01", hostname="10.0.0.1", username="deploy", host_key="ssh-ed25519 AAAA",
                        metrics={}, deploy_root=str(self.root))
            repo = Repository(github_id=42, full_name="acme/web", owner="acme", name="web",
                              html_url="https://github.com/acme/web", detected_config={})
            inst = Instance(id=INSTANCE_ID, name="web", slug="web-prod", branch="main", host=host, repository=repo,
                            env=env or {}, ports=[], volumes=[], build_source="app",
                            app_settings={"APP_DOMAIN": "uat.example.com"}, app_secrets=dict(SECRETS), **fields)
            db.add(inst)
            await db.commit()
            self.instance_id, self.user_id = inst.id, user.id

    async def queue(self, **fields) -> uuid.UUID:
        GoldenApp.n += 1
        return await super().queue(id=_dep_id(GoldenApp.n), **fields)


def _app_record(app: GoldenApp, dep: Deployment, sy: Recorder, seen: list[int]) -> dict:
    norm = Normal(app.tmp)
    calls = app.calls()
    new, seen[0] = calls[seen[0]:], len(calls)
    shared = app.base / "shared"
    env_files = {p.name: norm.text(p.read_text()) for p in sorted(shared.glob("*env*")) if p.is_file()} \
        if shared.exists() else {}
    return {"status": dep.status, "error": norm.text(dep.error or ""), "steps": _steps(dep, norm),
            "env_files": env_files, "app_log": new, "switchyard": norm.value(sy.take())}


async def _app_case(app: GoldenApp, sy: Recorder, with_data: bool) -> dict:
    GoldenApp.n = 0
    app.env["FAKE_VOLUME_FILE"] = str(app.tmp / "volumes")
    await _configure_switchyard()
    await app.seed()
    if with_data:
        from tests.test_data_jobs import _add_first_admin
        await _add_first_admin(app.instance_id)
    gh = DataGitHub if with_data else _gh(PLAIN_YML)
    seen = [0]
    out = {}
    out["deploy1"] = _app_record(app, await app.deploy(gh), sy, seen)
    app.state.mkdir(exist_ok=True)
    (app.state / "rev").write_text("rev-1\n")
    out["deploy2"] = _app_record(app, await app.deploy(gh), sy, seen)
    if not with_data:
        return out
    out["backup"] = _app_record(app, await app.deploy(gh, kind="backup"), sy, seen)
    rows = await app.backups_rows()
    out["restore"] = _app_record(app, await app.deploy(gh, kind="restore", restore_backup_id=rows[-1].id), sy, seen)
    out["reset"] = _app_record(app, await app.deploy(gh, kind="reset", options={"seed": True}), sy, seen)
    out["content"] = _app_record(app, await app.deploy(gh, kind="content"), sy, seen)
    flag = app.tmp / "fail"
    flag.write_text("")
    app.env["FAIL_FLAG"] = str(flag)
    failed = await app.deploy(gh)
    out["failed"] = _app_record(app, failed, sy, seen)
    flag.unlink()
    inst = await app.instance()
    out["dirty"] = Normal(app.tmp).value({k: v for k, v in (inst.data_dirty or {}).items() if k != "at"})
    backup_id = ((inst.data_dirty or {}).get("first") or {}).get("backup_id")
    out["rollback"] = _app_record(app, await app.deploy(gh, kind="rollback", restore_backup_id=uuid.UUID(backup_id),
                                                        options={"rollback_of": failed.id.hex}), sy, seen)
    return out


@pytest.fixture
def golden_app(tmp_path, docker_shim):  # noqa: F811
    env, _ = docker_shim
    df = Path(env["PATH"].split(":")[0]) / "df"
    df.write_text(DF_SHIM)
    df.chmod(0o755)
    return GoldenApp(tmp_path, env)


# ------------------------------------------------------------------------------------- compare


def _check(name: str, got) -> None:
    got = json.loads(json.dumps(got, sort_keys=True, default=str))
    target = os.environ.get("SLIPWAY_WRITE_GOLDEN")
    if target:
        path = Path(target)
        stored = json.loads(path.read_text()) if path.exists() else {}
        stored[name] = got
        path.write_text(json.dumps(stored, indent=1, sort_keys=True) + "\n")
        return
    want = json.loads(GOLDEN.read_text())[name]
    assert got == want


def test_step_lists_are_phase_2s():
    _check("step_lists", _step_lists())


async def test_a_dockerfile_instance_deploys_and_publishes_as_in_phase_2(sy):
    _check("dockerfile", await _dockerfile_case(sy))


async def test_a_compose_instance_deploys_and_publishes_as_in_phase_2(sy):
    _check("compose", await _compose_case(sy))


async def test_an_app_without_data_deploys_as_in_phase_2(golden_app, sy):
    _check("app_plain", await _app_case(golden_app, sy, with_data=False))


async def test_an_app_with_data_deploys_backs_up_restores_and_resets_as_in_phase_2(golden_app, sy):
    _check("app_data", await _app_case(golden_app, sy, with_data=True))


def test_the_instance_marker_is_phase_2s():
    inst = Instance(id=INSTANCE_ID, name="web", slug="web-prod")
    marker = switchyard._marker(inst) if hasattr(switchyard, "_marker") else switchyard.marker(inst)
    _check("marker", marker)
