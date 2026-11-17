"""Several fake hosts for environment tests (phase 3 §16.1).

``MultiRemote`` is a ``connect`` factory keyed on the target's hostname: each host gets its own ``ShellRemote``
(commands run in a real shell on this machine) with its own deploy root, ``$STATE``, ``$APP_LOG``,
``$DOCKER_LOG`` and ``$CURL_LOG``, and the fake ``docker``, ``df`` and ``curl`` first on PATH.

The app (``ENV_SCRIPT``) keeps its "database" in ``<folder>/state/db``. An app slot whose data is on a data
server (``APP_EXTERNAL=1`` in its ``.env``) uses the data server's folder instead (``DATA_STATE``, the data
server's ``shared`` folder its ``provides`` names), so a migration a slot runs is seen on the data host.
``ENV_YML`` declares health paths, ``migrations``, ``data.attach`` and ``data.server``.

Phases 4 and 5 reach droplets and VMs by address, so ``MultiRemote`` also answers by address
(``multi["10.0.0.11"]``) and takes hosts that appear later (``add``). Each host can present its own host key
(``present_key``, ``pinned_key``): a connect whose pinned key differs raises ``ssh.HostKeyMismatch``, as
``ssh.connect`` does. A host that has no key of its own checks nothing, as phase 3's tests expect. A host can
refuse its first connections while it boots (``booting``) or drop every connection from Slipway, as a cloud
firewall does (``firewalled``). Shims answer ``cloud-init status`` (``$FAKE_CLOUD_INIT``), record the SQL
``docker run ... psql`` reads from stdin (``$PSQL_LOG``, with a mode that fails right after a ``DROP DATABASE``
line), and every session sees ``$SSH_CONNECTION`` naming Slipway's address (``slipway_address``).
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
from slipway.services import cloudflare, ssh
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
#
# What psql reads on stdin (the SQL of a managed database's setup or reset; the probe sends nothing past the
# password its shell reads first) is appended to $PSQL_LOG as one block per run, ended by a "-- end" line.
# With the file $FAKE_PSQL_DROP_FAILS present, psql takes the lines up to and including the first DROP DATABASE,
# then fails as a connection cut there does; the file is removed, so the next run works (P4 test 84).
DOCKER_ENV_SHIM = """#!/bin/sh
if [ "$1" = run ] && echo "$*" | grep -q psql; then
  echo "$*" >> "$DOCKER_LOG"
  [ -n "$PGPASSWORD" ] && echo "probe: PGPASSWORD set (${#PGPASSWORD} characters)" >> "$DOCKER_LOG"
  sql=$(cat)
  if [ -n "$sql" ] && [ -n "$PSQL_LOG" ]; then
    if [ -n "$FAKE_PSQL_DROP_FAILS" ] && [ -f "$FAKE_PSQL_DROP_FAILS" ] && printf '%s\\n' "$sql" | grep -q 'DROP DATABASE'; then
      printf '%s\\n' "$sql" | awk '{print} /DROP DATABASE/ {exit}' >> "$PSQL_LOG"
      echo "-- cut" >> "$PSQL_LOG"
      rm -f "$FAKE_PSQL_DROP_FAILS"
      echo "psql: error: server closed the connection unexpectedly" >&2
      exit 2
    fi
    printf '%s\\n' "$sql" >> "$PSQL_LOG"
    echo "-- end" >> "$PSQL_LOG"
  fi
  if [ -n "$FAKE_PSQL" ]; then echo "$FAKE_PSQL" >&2; exit 2; fi
  echo 1
  exit 0
fi
exec "$(dirname "$0")/docker-base" "$@"
"""

# cloud-init: ``cloud-init status [--wait] [--long] [--format json]`` answers as $FAKE_CLOUD_INIT says (done, the
# default; running, which --wait waits out; degraded, done with recoverable errors, exit 2; error, exit 1, with
# $FAKE_CLOUD_INIT_ERROR as its error). Each call's arguments go to $CLOUD_INIT_LOG.
CLOUD_INIT_SHIM = """#!/bin/sh
echo "$*" >> "$CLOUD_INIT_LOG"
[ "$1" = status ] || { echo "cloud-init: only status is faked" >&2; exit 2; }
shift
wait=""; json=""
for a in "$@"; do
  case "$a" in --wait|-w) wait=1 ;; --format=json|json) json=1 ;; esac
done
state=${FAKE_CLOUD_INIT:-done}
if [ "$state" = running ] && [ -n "$wait" ]; then printf '...\\n'; state=done; fi
error=${FAKE_CLOUD_INIT_ERROR:-Failed to run module scripts-user}
case "$state" in
  done) status=done; extended=done; code=0; errors="" ;;
  degraded) status=done; extended="degraded done"; code=2; errors="" ;;
  error) status=error; extended=error; code=1; errors="$error" ;;
  *) status=running; extended=running; code=0; errors="" ;;
esac
if [ -n "$json" ]; then
  if [ -n "$errors" ]; then list="[\\"$errors\\"]"; else list="[]"; fi
  printf '{"boot_status_code": "enabled-by-generator", "datasource": "fake", "detail": "DataSourceFake", '
  printf '"errors": %s, "extended_status": "%s", "last_update": "Thu, 01 Jan 1970 00:00:01 +0000", ' "$list" "$extended"
  printf '"recoverable_errors": {}, "status": "%s"}\\n' "$status"
else
  echo "status: $status"
  [ -n "$errors" ] && echo "errors: $errors"
fi
exit $code
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
    """One host: its folders, its logs, and the ShellRemote every session to it uses.

    ``host_key`` is the public key it presents (None: it checks no pin, as phase 3's hosts do); ``refuse`` is how
    many connects it still refuses while it boots; ``firewalled`` drops every connection from Slipway."""

    name: str
    address: str
    tmp: Path
    remote: ShellRemote
    env: dict[str, str]
    host_key: str | None = None
    refuse: int = 0
    firewalled: bool = False

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

    def cloud_init(self) -> list[str]:
        """The arguments of each ``cloud-init`` call."""
        return self.log("CLOUD_INIT_LOG")

    def sql(self) -> list[str]:
        """What each ``docker run ... psql`` read on stdin, one string per run (a cut run ends ``-- cut``)."""
        out, block = [], []
        for line in self.log("PSQL_LOG"):
            if line in ("-- end", "-- cut"):
                out.append("\n".join(block + ([line] if line == "-- cut" else [])))
                block = []
            else:
                block.append(line)
        return out

    def folder(self, slug: str) -> Path:
        return self.root / slug

    def clear(self) -> None:
        for key in LOGS:
            Path(self.env[key]).write_text("")


# Each host's logs: the variable its shims read, and the file.
LOGS = {"APP_LOG": "app.log", "DOCKER_LOG": "docker.log", "CURL_LOG": "curl.log", "ADMIN_LOG": "admin.log",
        "CLOUD_INIT_LOG": "cloud-init.log", "PSQL_LOG": "psql.log"}
# The address a fake host sees Slipway connect from ($SSH_CONNECTION's first field).
SLIPWAY_ADDRESS = "198.51.100.7"


def _same_key(a: str | None, b: str | None) -> bool:
    """Two OpenSSH public key lines name the same key (the comment doesn't count)."""
    return bool(a and b) and a.split()[:2] == b.split()[:2]


class MultiRemote:
    """A ``connect`` factory for several hosts, found by the target's hostname: an address, or a host's name
    (§16.1; phases 4 and 5 reach droplets and VMs by address)."""

    def __init__(self, tmp: Path, names: dict[str, str] | None = None, shell: str = "sh") -> None:
        self.tmp, self.shell = tmp, shell
        self.bin_dir = tmp / "bin"
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        for name, text in (("docker-base", DOCKER_SHIM), ("docker", DOCKER_ENV_SHIM), ("df", DF_SHIM),
                           ("curl", CURL_SHIM), ("cloud-init", CLOUD_INIT_SHIM)):
            (self.bin_dir / name).write_text(text)
            (self.bin_dir / name).chmod(0o755)
        self.hosts: dict[str, FakeHost] = {}
        self.by_address: dict[str, FakeHost] = {}
        self.opened: list[str] = []  # the hostnames sessions were opened to, in order
        self.targets: list[Any] = []  # the SSHTarget of every connect, refused ones too
        self.slipway_address = SLIPWAY_ADDRESS
        for name, address in (names or ADDRESSES).items():
            self.add(name, address)

    def add(self, name: str, address: str, *, host_key: str | None = None) -> FakeHost:
        """A host that appears now (a droplet or VM once it has its address)."""
        if name in self.hosts or address in self.by_address:
            raise ValueError(f"a fake host named {name} or at {address} exists")
        base = self.tmp / f"host-{name}"
        base.mkdir(parents=True, exist_ok=True)
        env = {"PATH": f"{self.bin_dir}:{os.environ['PATH']}", "HOME": str(base), "STATE": str(base / "state"),
               "FAKE_DF_KB": str(100 * 1024 * 1024),
               "SSH_CONNECTION": f"{self.slipway_address} 51234 {address} 22"}
        for key, file in LOGS.items():
            env[key] = str(base / file)
            (base / file).write_text("")
        host = FakeHost(name, address, base, ShellRemote(self.shell, env), env, host_key=host_key)
        self.hosts[name] = host
        self.by_address[address] = host
        return host

    def __getitem__(self, key: str) -> FakeHost:
        """A host by its name or its address."""
        return self.hosts[key] if key in self.hosts else self.by_address[key]

    def __contains__(self, key: str) -> bool:
        return key in self.hosts or key in self.by_address

    # ------------------------------------------------------------------ seams

    def present_key(self, key: str, public_key: str | None) -> None:
        """The host named or at ``key`` presents ``public_key`` from now on (None: it checks no pin again)."""
        self[key].host_key = public_key

    def new_key(self, key: str) -> str:
        """A fresh ed25519 host key for the host named or at ``key``, which presents it from now on."""
        _private, public = ssh.generate_keypair(f"root@{self[key].name}")
        self.present_key(key, public)
        return public

    def pinned_key(self, address: str) -> str | None:
        """The public key the host at ``address`` presents: what a provider should pin."""
        return self[address].host_key

    def booting(self, address: str, n: int) -> None:
        """The next ``n`` connects to ``address`` are refused, as a machine that is still booting refuses them."""
        self[address].refuse = n

    def firewalled(self, ip: str, on: bool = True) -> None:
        """Connections from Slipway to ``ip`` time out (a cloud firewall drops them) until called with False."""
        self[ip].firewalled = on

    def set_slipway_address(self, address: str) -> None:
        """The address every host sees Slipway connect from (``$SSH_CONNECTION``'s first field)."""
        self.slipway_address = address
        for host in self.hosts.values():
            host.env["SSH_CONNECTION"] = f"{address} 51234 {host.address} 22"

    # ---------------------------------------------------------------- connect

    def connect(self, target: Any):
        """A session to the target's host. Like ``ssh.open_session``, it fails when entered: an unknown name, a
        firewall drop, a refusal while booting, or a pinned key the host doesn't present."""
        self.targets.append(target)

        @asynccontextmanager
        async def session():
            yield self._reach(target).remote

        return session()

    def _reach(self, target: Any) -> FakeHost:
        where = f"{target.hostname}:{getattr(target, 'port', 22)}"
        host = self.by_address.get(target.hostname) or self.hosts.get(target.hostname)
        if host is None:
            raise ssh.SSHError(f"Could not connect to {where}: [Errno 8] nodename nor servname provided, or not known")
        if host.firewalled:
            raise ssh.SSHError(f"Could not connect to {where}: timed out")
        if host.refuse > 0:
            host.refuse -= 1
            raise ssh.SSHError(f"Could not connect to {where}: [Errno 61] Connect call failed ('{host.address}', 22)")
        if host.host_key is not None:
            pinned = getattr(target, "pinned_host_key", None)
            if not pinned:
                raise ssh.HostKeyNotPinned("Host key not verified yet: run a connection test on this host first")
            if not _same_key(pinned, host.host_key):
                raise ssh.HostKeyMismatch(ssh._KEY_MISMATCH)
        self.opened.append(target.hostname)
        return host

    def clear(self) -> None:
        for host in self.hosts.values():
            host.clear()
        self.opened.clear()
        self.targets.clear()


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
