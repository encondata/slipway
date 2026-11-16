"""Several fake hosts for environment tests (phase 3 §16.1).

``MultiRemote`` is a ``connect`` factory keyed on the target's hostname: each host gets its own ``ShellRemote``
(commands run in a real shell on this machine) with its own deploy root, ``$STATE``, ``$APP_LOG``,
``$DOCKER_LOG`` and ``$CURL_LOG``, and the fake ``docker``, ``df`` and ``curl`` first on PATH.

The app (``ENV_SCRIPT``) keeps its "database" in ``<folder>/state/db``. An app slot whose data is on a data
server (``APP_EXTERNAL=1`` in its ``.env``) uses the data server's folder instead (``DATA_STATE``, the data
server's ``shared`` folder its ``provides`` names), so a migration a slot runs is seen on the data host.
``ENV_YML`` declares health paths, ``migrations``, ``data.attach`` and ``data.server``.
"""

from __future__ import annotations

import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from slipway.db.session import get_sessionmaker
from slipway.models import AppSetting, Deployment, Environment, Host, Instance, Repository
from slipway.services import cloudflare
from tests.conftest import make_user
from tests.test_data_jobs import DF_SHIM, DataGitHub
from tests.test_final_remote import DOCKER_SHIM, ShellRemote

ENV_YML = """\
version: 1
name: Demo
env_file: deploy/env.example
placeholder: CHANGEME
settings:
  APP_DOMAIN: {label: Base domain, required: true}
vars:
  APP_ENV: "{slipway.slug}"
  APP_REPO: "{slipway.release}"
  APP_SLOT: "{slipway.slot}"
secrets:
  APP_SECRET: hex
  APP_KEY: {kind: fernet, identity: true}
  DB_PASSWORD: hex
services:
  web: {port: 8080, port_var: APP_WEB_PORT, hostname: "www.{APP_DOMAIN}", health: /healthz}
  files: {port: 9000, port_var: APP_FILES_PORT, hostname: "files.{APP_DOMAIN}"}
projects: ["demo-{APP_ENV}-web", "demo-{APP_ENV}-db"]
images: ["demo-web:{slipway.sha12}"]
data:
  app: demo
  format: demo-v1
  migrations: expand_contract
  volumes:
    - {name: "demo-{APP_ENV}-db_data", holds: database}
  attach:
    needs: {db: postgres}
    env:
      APP_EXTERNAL: "1"
      DB_HOST: "{data.db.host}"
      DB_PORT: "{data.db.port}"
      DATA_STATE: "{data.db.database}"
      DATABASE_URL: "postgres://{data.db.user}:{data.db.password}@{data.db.host}:{data.db.port}/demo"
  server:
    services: [files]
    ports: {db: {port: 5432, port_var: DB_PORT}}
    secrets: [DB_PASSWORD]
    env: {DB_PUBLISH: "1", DB_ALLOW: "{server.clients}"}
    projects: ["demo-{APP_ENV}-db"]
    volumes: ["demo-{APP_ENV}-db_data"]
    commands:
      start: [sh, deploy/app, data-start, "{slipway.env_dir}"]
      has_data: [sh, deploy/app, has-data, "{slipway.env_dir}", --server]
    provides:
      db: {host: "{server.host}", port: "{server.port.db}", database: "{slipway.env_dir}", user: demo,
           password: "{secret.DB_PASSWORD}", tls: disable, ca_b64: ""}
commands:
  build: [sh, deploy/app, build, "{slipway.env_dir}"]
  start: [sh, deploy/app, up, "{slipway.env_dir}"]
  stop: [sh, deploy/app, down, "{slipway.env_dir}"]
  has_data: [sh, deploy/app, has-data, "{slipway.env_dir}"]
  data_up: [sh, deploy/app, data, "{slipway.env_dir}"]
  dump: [sh, deploy/app, pgdump, "{slipway.env_dir}", "{slipway.out}"]
  verify_dump: [sh, deploy/app, verify-dump, "{slipway.env_dir}", "{slipway.in}"]
  revision: [sh, deploy/app, revision, "{slipway.env_dir}"]
  accepts: [sh, deploy/app, accepts, "{slipway.env_dir}", "{slipway.in}"]
  restore: [sh, deploy/app, restore, "{slipway.env_dir}", "{slipway.in}"]
  seed: [sh, deploy/app, seed, "{slipway.env_dir}"]
first_admin:
  command: [sh, deploy/app, admin, "{slipway.env_dir}", --email, "{admin.email}", --name, "{admin.name}"]
  fields:
    email: {label: Email, kind: email}
    name: {label: Name}
  password: {stdin: true, args: [--password-stdin]}
  exists_codes: [10]
"""

ENV_EXAMPLE = ("APP_ENV=dev\nAPP_DOMAIN=example.com\nAPP_SECRET=CHANGEME\nAPP_KEY=CHANGEME\nDB_PASSWORD=CHANGEME\n"
               "DB_HOST=localhost\nDB_PORT=5432\n")

# The app. Each call is logged in $APP_LOG with the release whose .env it saw.
ENV_SCRIPT = r"""
cmd=$1; dir=$2; shift 2
val() { sed -n "s/^$1=//p" "$dir/.env"; }
repo=$(val APP_REPO)
echo "$cmd ${repo##*/}" >> "$APP_LOG"
if [ "$(val APP_EXTERNAL)" = 1 ]; then db="$(val DATA_STATE)/../state"; else db="$dir/../state"; fi
mkdir -p "$db"
# With $FAKE_VOLUME_FILE the database lives in a "volume" that starting the data services creates: a new one is empty.
volume() {
  if [ -n "$FAKE_VOLUME_FILE" ] && ! grep -q 'db_data ' "$FAKE_VOLUME_FILE" 2>/dev/null; then
    e=$(val APP_ENV); rm -f "$db/db"; echo "demo-$e-db_data demo-$e-db" >> "$FAKE_VOLUME_FILE"
  fi
}
case "$cmd" in
  build|down) ;;
  data|data-start) [ "$(val APP_EXTERNAL)" = 1 ] || volume ;;
  up)
    [ -n "$LOCK_PEEK" ] && { printf 'lock: '; cat "$LOCK_PEEK" 2>/dev/null || echo none; } >> "$APP_LOG"
    [ -n "$FAIL_FLAG" ] && [ -f "$FAIL_FLAG" ] && { echo "migration failed" >&2; exit 1; }
    echo "MIGRATED $(val APP_SLOT)" >> "$db/db"
    [ -n "$NEW_REV" ] && echo "$NEW_REV" > "$db/rev"
    val APP_KEY > "$dir/../keys" ;;
  has-data)
    [ -n "$FAKE_VOLUME_FILE" ] && ! grep -q 'db_data ' "$FAKE_VOLUME_FILE" 2>/dev/null && exit 3
    if [ "$1" = --server ]; then [ -f "$db/db" ] && exit 0; exit 3; fi
    [ "$(val DB_PUBLISH)" = 1 ] && exit 4
    [ -f "$db/db" ] && exit 0; exit 3 ;;
  pgdump) { echo "DB:"; cat "$db/db"; } > "$1" ;;
  verify-dump) [ "$(head -n 1 "$1")" = "DB:" ] ;;
  revision) cat "$db/rev" 2>/dev/null ;;
  accepts)
    r=$(cat "$1")
    for u in $UNKNOWN_REVS; do [ "$r" = "$u" ] && { echo "unknown revision $r"; exit 3; }; done
    exit 0 ;;
  restore) tail -n +2 "$1" > "$db/db" ;;
  seed) echo SEEDED >> "$db/db" ;;
  admin)
    IFS= read -r pw || pw=""
    echo "args=$* pwlen=${#pw}" >> "$ADMIN_LOG"
    exit "${ADMIN_RC:-0}" ;;
esac
exit 0
"""

# docker: the probe's `docker run ... psql` answers as $FAKE_PSQL says (empty: it signs in); the rest is the shim
# of test_final_remote.
DOCKER_ENV_SHIM = """#!/bin/sh
if [ "$1" = run ] && echo "$*" | grep -q psql; then
  echo "$*" >> "$DOCKER_LOG"
  [ -n "$PGPASSWORD" ] && echo "probe: PGPASSWORD set (${#PGPASSWORD} characters)" >> "$DOCKER_LOG"
  if [ -n "$FAKE_PSQL" ]; then echo "$FAKE_PSQL" >&2; exit 2; fi
  echo 1
  exit 0
fi
exec "$(dirname "$0")/docker-base" "$@"
"""

# curl: prints the code $FAKE_HTTP_CODES gives the Host header ("host=code host=code"), else 200.
CURL_SHIM = """#!/bin/sh
host=""
while [ $# -gt 0 ]; do
  case "$1" in -H) case "$2" in "Host: "*) host=${2#Host: } ;; esac; shift ;; esac
  shift
done
echo "$host" >> "$CURL_LOG"
code=200
for pair in $FAKE_HTTP_CODES; do [ "${pair%%=*}" = "$host" ] && code=${pair#*=}; done
printf '%s' "$code"
"""

ADDRESSES = {"blue": "10.0.0.11", "green": "10.0.0.12", "data": "10.0.0.13"}
SECRETS = {"APP_SECRET": "5" * 64, "APP_KEY": "k" * 43 + "=", "DB_PASSWORD": "d" * 32 + "pw"}


class EnvGitHub(DataGitHub):
    files = {"slipway.yml": ENV_YML, "deploy/env.example": ENV_EXAMPLE, "deploy/app": ENV_SCRIPT}


def github(yml: str = ENV_YML) -> type[EnvGitHub]:
    class GH(EnvGitHub):
        files = {"slipway.yml": yml, "deploy/env.example": ENV_EXAMPLE, "deploy/app": ENV_SCRIPT}
    return GH


@dataclass
class FakeHost:
    """One host: its folders, its logs, and the ShellRemote every session to it uses."""

    name: str
    address: str
    tmp: Path
    remote: ShellRemote
    env: dict[str, str]

    @property
    def root(self) -> Path:
        return self.tmp / "root"

    def log(self, name: str) -> list[str]:
        path = Path(self.env[name])
        return path.read_text().splitlines() if path.exists() else []

    def calls(self) -> list[str]:
        return self.log("APP_LOG")

    def docker(self) -> list[str]:
        return self.log("DOCKER_LOG")

    def folder(self, slug: str) -> Path:
        return self.root / slug

    def clear(self) -> None:
        for key in ("APP_LOG", "DOCKER_LOG", "CURL_LOG", "ADMIN_LOG"):
            Path(self.env[key]).write_text("")


class MultiRemote:
    """A ``connect`` factory for several hosts, keyed on the target's hostname (§16.1)."""

    def __init__(self, tmp: Path, names: dict[str, str] | None = None, shell: str = "sh") -> None:
        bin_dir = tmp / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        for name, text in (("docker-base", DOCKER_SHIM), ("docker", DOCKER_ENV_SHIM), ("df", DF_SHIM),
                           ("curl", CURL_SHIM)):
            (bin_dir / name).write_text(text)
            (bin_dir / name).chmod(0o755)
        self.hosts: dict[str, FakeHost] = {}
        self.opened: list[str] = []  # the hostnames sessions were opened to, in order
        for name, address in (names or ADDRESSES).items():
            base = tmp / f"host-{name}"
            base.mkdir(parents=True, exist_ok=True)
            env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "HOME": str(base), "STATE": str(base / "state"),
                   "FAKE_DF_KB": str(100 * 1024 * 1024)}
            for key, file in (("APP_LOG", "app.log"), ("DOCKER_LOG", "docker.log"), ("CURL_LOG", "curl.log"),
                              ("ADMIN_LOG", "admin.log")):
                env[key] = str(base / file)
                (base / file).write_text("")
            self.hosts[name] = FakeHost(name, address, base, ShellRemote(shell, env), env)
        self.by_address = {h.address: h for h in self.hosts.values()}

    def __getitem__(self, name: str) -> FakeHost:
        return self.hosts[name]

    def connect(self, target: Any):
        host = self.by_address[target.hostname]
        self.opened.append(target.hostname)

        @asynccontextmanager
        async def session():
            yield host.remote

        return session()

    def clear(self) -> None:
        for host in self.hosts.values():
            host.clear()
        self.opened.clear()


@dataclass
class Seeded:
    env_id: uuid.UUID
    user_id: uuid.UUID
    ids: dict[str, uuid.UUID] = field(default_factory=dict)  # slot -> instance id
    host_ids: dict[str, uuid.UUID] = field(default_factory=dict)


async def seed_env(multi: MultiRemote, *, mode: str = "server", slots: tuple[str, ...] = ("blue", "green"),
                   name: str = "uat", traffic: dict | None = None, secrets: dict | None = None,
                   env: dict | None = None, auto_activate: bool = False, hosts: dict[str, str] | None = None,
                   **owner_fields: Any) -> Seeded:
    """An environment, its hosts (one per slot, 10.0.0.11-13) and its slot instances, as ``POST /environments``
    writes them. ``hosts`` maps a slot to the FakeHost it uses (default: the one of its own name)."""
    user = await make_user(f"admin-{uuid.uuid4().hex[:6]}@example.com")
    wanted = [*slots, *(["data"] if mode == "server" else [])]
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=42, full_name="acme/web", owner="acme", name="web",
                          html_url="https://github.com/acme/web", detected_config={})
        row = Environment(name=name, repository=repo, branch="main", data_mode=mode,
                          app_settings={"APP_DOMAIN": f"{name}.example.com"}, app_secrets=dict(secrets or SECRETS),
                          env=dict(env or {}), traffic=traffic or {"switch": "none", "dns": None},
                          auto_activate=auto_activate, created_by_id=user.id,
                          hostnames=hostnames(name, mode))
        db.add(row)
        await db.flush()
        made: dict[str, Host] = {}
        seeded = Seeded(env_id=row.id, user_id=user.id)
        owner = "data" if mode == "server" else "blue"
        for slot in wanted:
            fake = multi[(hosts or {}).get(slot, slot)]
            host = made.get(fake.name)
            if host is None:
                host = Host(name=f"{fake.name}-host", hostname=fake.address, username="deploy",
                            host_key="ssh-ed25519 AAAA", metrics={}, deploy_root=str(fake.root))
                made[fake.name] = host
            inst = Instance(name=f"{name} {slot}", slug=f"{name}-{slot}", branch="main", host=host, repository=repo,
                            env={}, ports=[], volumes=[], build_source="app", environment_id=row.id, slot=slot,
                            **(owner_fields if slot == owner else {}))
            db.add(inst)
            await db.flush()
            seeded.ids[slot] = inst.id
            seeded.host_ids[slot] = host.id
        await db.commit()
    return seeded


def hostnames(name: str, mode: str) -> list[dict[str, Any]]:
    """``env.hostnames`` as ``environments.create`` plans them for ENV_YML (§10.1)."""
    files = "server" if mode == "server" else "active"
    return [{"hostname": f"files.{name}.example.com", "service": "files", "container": 9000, "follows": files,
             "health": "/"},
            {"hostname": f"www.{name}.example.com", "service": "web", "container": 8080, "follows": "active",
             "health": "/healthz"}]


async def queue(seeded: Seeded, slot: str, **fields: Any) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        fields.setdefault("branch", "main")
        dep = Deployment(instance_id=seeded.ids[slot], environment_id=seeded.env_id,
                         triggered_by_id=seeded.user_id, log="", **fields)
        db.add(dep)
        await db.commit()
        return dep.id


async def configure_cloudflare(zone: str = "example.com", public_ip: str = "203.0.113.7") -> None:
    from tests.fake_cloudflare import TOKEN
    async with get_sessionmaker()() as db:
        db.add(AppSetting(key=cloudflare.SETTING_KEY, value={"zone": zone, "public_ip": public_ip, "proxied": False},
                          secret=TOKEN))
        await db.commit()
