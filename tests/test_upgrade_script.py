"""The upgrade script (slipway/updates/upgrade.sh), run for real under bash.

Each test builds an install folder that is a real git clone of a local bare origin, and puts fake `docker`,
`df`, `curl` (and sometimes `flock`) first on PATH. The fake docker keeps its state in files (tags, images,
containers, the database revision) so a test can steer it and read back what happened. Nothing here touches
real Docker or the network.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import textwrap
import time
from importlib import resources
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RUN_ID = "20261117-120000-abc123"
OLD_IMAGE = "sha256:" + "a" * 64
OLD_CID = "0123456789ab"
DB_CID = "dbdbdbdbdbdb"
BOOT_ID = "11111111-2222-3333-4444-555555555555"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None or shutil.which("git") is None,
                                reason="needs bash and git")

FAKE_DOCKER = r"""#!/usr/bin/env bash
# Fake docker for tests. State and controls live in $FAKE.
F=$FAKE
printf '%s\n' "$*" >> "$F/calls.log"
ctl() { [ -e "$F/$1" ]; }
# The script's pid, from its status file (docker may run under timeout, so $PPID isn't the script).
kill_script() { kill -TERM "$(sed -n 's/.*"pid":\([0-9]*\).*/\1/p' .slipway-updates/*.json | head -n 1)"; }
tagfile() { printf '%s/tags/%s' "$F" "$(printf '%s' "$1" | tr ':/' '__')"; }
resolve() { case $1 in sha256:*) printf '%s' "$1" ;; *) cat "$(tagfile "$1")" 2>/dev/null ;; esac; }
cur() { cat "$F/slipway_cid" 2>/dev/null; }
img_commit() { c=$(sed -n 's/^SLIPWAY_COMMIT=//p' "$F/images/$1.env" 2>/dev/null); printf '%s' "${c:-none}"; }
cur_commit() { img_commit "$(cat "$F/cont/$(cur).image")"; }
running() { [ "$(cat "$F/cont/$(cur).running" 2>/dev/null)" = true ]; }
db_hash() { awk '/^  db:/ { f = 1; next } /^  [a-z]/ { f = 0 } f' docker-compose.yml | cksum | awk '{ print $1 }'; }

if [ "$1" = compose ]; then
  shift
  case "$*" in
    version) echo "Docker Compose version v2.30.0" ;;
    "ps --status running --services") cat "$F/services" ;;
    "ps -q slipway") running && cur ;;
    "ps -q db") echo "$(cat "$F/db_cid")" ;;
    "config --hash db") echo "db $(db_hash)" ;;
    "build slipway")
      printf 'SLIPWAY_COMMIT=%s\nSLIPWAY_BRANCH=%s\nSLIPWAY_BUILT_AT=%s\n' \
        "${SLIPWAY_COMMIT-}" "${SLIPWAY_BRANCH-}" "${SLIPWAY_BUILT_AT-}" > "$F/build_env"
      if ctl kill_on_build; then kill_script; exit 0; fi
      if ctl build_fail; then echo "build failed" >&2; exit 1; fi
      id="sha256:${SLIPWAY_COMMIT}000000000000000000000000"
      printf 'PATH=/usr/bin\nSLIPWAY_COMMIT=%s\n' "$SLIPWAY_COMMIT" > "$F/images/$id.env"
      echo "$id" > "$(tagfile slipway:latest)"
      ;;
    "stop -t 30 slipway")
      n=$(($(cat "$F/stops" 2>/dev/null || echo 0) + 1)); echo "$n" > "$F/stops"
      if [ "$(cat "$F/stop_fail_nth" 2>/dev/null)" = "$n" ]; then echo "stop failed" >&2; exit 1; fi
      echo false > "$F/cont/$(cur).running" ;;
    "up -d --no-build --no-deps slipway")
      if ctl up_fail; then exit 1; fi
      img=$(resolve slipway:latest)
      c=$(cur)
      if [ "$(cat "$F/cont/$c.image")" != "$img" ]; then
        n=$(($(cat "$F/counter") + 1)); echo "$n" > "$F/counter"
        c=$(printf 'c0ffee%06d' "$n"); echo "$c" > "$F/slipway_cid"
        echo "$img" > "$F/cont/$c.image"; echo 0 > "$F/cont/$c.restarts"
      fi
      echo true > "$F/cont/$c.running"
      commit=$(img_commit "$img")
      if [ -f "$F/migrate_to" ]; then
        read -r mc rev < "$F/migrate_to"
        [ "$mc" = "$commit" ] && echo "$rev" > "$F/db_rev"
      fi
      if [ -e "$F/break_rev_on_up" ] && [ "$(cat "$F/break_rev_on_up")" = "$commit" ]; then touch "$F/db_rev_fail"; fi
      if ctl chmod_dump_on_up; then chmod 644 .slipway-updates/*-before.dump; fi
      ;;
    "exec -T slipway python -c "*)
      if ctl hang_probe; then sleep 3600; fi
      if [ -f "$F/kill_on_probe" ]; then
        n=$(($(cat "$F/kill_on_probe") - 1)); echo "$n" > "$F/kill_on_probe"
        [ "$n" = 0 ] && kill_script
      fi
      running || exit 1
      ctl "health_fail_$(cur_commit)" && exit 1
      exit 0 ;;
    "logs --no-color --no-log-prefix --tail 60 slipway")
      cat "$F/output_$(cur_commit)" 2>/dev/null ;;
    "run --rm --no-deps --user root -v "*":/files --entrypoint sh db -c chown 10001:10001 /files && chmod 700 /files")
      ctl run_fail && { echo "permission denied" >&2; exit 1; }
      a="$*"; d=${a#run --rm --no-deps --user root -v }; d=${d%%:/files*}
      chmod 700 "$d"; echo "$d" > "$F/files_given" ;;
    "exec -T slipway printenv SLIPWAY_COMMIT")
      running || exit 1
      c=$(cur_commit); [ "$c" != none ] || exit 1; echo "$c" ;;
    "exec -T db psql -U slipway -d slipway -Atc SELECT version_num FROM alembic_version")
      ctl db_rev_fail && { echo "connection refused" >&2; exit 2; }
      cat "$F/db_rev" ;;
    "exec -T db psql -U slipway -d slipway -Atc SELECT pg_database_size('slipway')") cat "$F/db_size" ;;
    "exec -T db psql -U slipway -d slipway -Atc SELECT count(*) FROM deployments WHERE status IN ('queued', 'running')")
      # $F/active_deploys: "<n>" deployments, or "<n> <reads>" to drop to 0 after that many reads.
      read -r n left 2>/dev/null < "$F/active_deploys" || n=0
      if [ -n "${left:-}" ]; then
        [ "$left" -le 1 ] && echo 0 > "$F/active_deploys" || echo "$n $((left - 1))" > "$F/active_deploys"
      fi
      echo "${n:-0}" ;;
    "exec -T db psql -U slipway -d postgres -v ON_ERROR_STOP=1 -c "*)
      ctl psql_fail && exit 1
      echo "" > "$F/db_rev" ;;
    "exec -T db pg_dump -U slipway -Fc slipway")
      if ctl dump_fail; then echo "PGDMP partial"; exit 1; fi
      printf 'PGDMP rev=%s\n' "$(cat "$F/db_rev")" ;;
    "exec -T db pg_restore --list")
      input=$(cat); ctl list_fail && exit 1
      case $input in PGDMP*) exit 0 ;; *) exit 1 ;; esac ;;
    "exec -T db pg_restore -U slipway -d slipway --exit-on-error --single-transaction --no-owner")
      input=$(cat)
      if ctl restore_fail; then echo "pg_restore: error" >&2; exit 1; fi
      rm -f "$F/db_rev_fail"
      if ctl restore_wrong_rev; then echo rev9 > "$F/db_rev"; exit 0; fi
      printf '%s\n' "${input#PGDMP rev=}" > "$F/db_rev" ;;
    *) echo "fake docker: unknown compose call: $*" >&2; exit 99 ;;
  esac
  exit 0
fi
case $1 in
  tag)
    case $2 in slipway:before-*) ctl tag_back_fail && { echo "tag failed" >&2; exit 1; } ;; esac
    id=$(resolve "$2"); [ -n "$id" ] || exit 1; echo "$id" > "$(tagfile "$3")" ;;
  inspect)
    case $3 in
      '{{.Image}}') cat "$F/cont/$4.image" ;;
      '{{.State.Running}} {{.State.Restarting}} {{.RestartCount}}')
        # Like Docker: a crash-looping container reads as running and restarting, its count going up.
        r=$(cat "$F/cont/$4.restarts") restarting=false
        if ctl "crashloop_$(img_commit "$(cat "$F/cont/$4.image")")"; then
          r=$((r + 1)); echo "$r" > "$F/cont/$4.restarts"; restarting=true
        fi
        echo "$(cat "$F/cont/$4.running") $restarting $r" ;;
      *config-hash*) cat "$F/db_label_hash" ;;
      *) exit 99 ;;
    esac ;;
  image)
    case $2 in
      inspect) id=$(resolve "$3"); [ -n "$id" ] || exit 1; cat "$F/images/$id.env" 2>/dev/null ;;
      ls) ctl kill_on_image_ls && kill_script
          for t in "$F"/tags/slipway_*; do [ -e "$t" ] && echo "slipway:${t##*/slipway_}"; done ;;
      *) exit 99 ;;
    esac ;;
  rmi) rm -f "$(tagfile "$2")" ;;
  info) echo /var/lib/docker ;;
  *) echo "fake docker: unknown call: $*" >&2; exit 99 ;;
esac
"""

FAKE_DF = r"""#!/usr/bin/env bash
# Fake df -Pk -- <path>: free KB from $FAKE/df/<path with / as _>, else plenty. The mount point is the path.
p=${!#}
[ "$p" = . ] && p=$PWD
key=$(printf '%s' "$p" | tr '/' '_')
avail=$(cat "$FAKE/df/$key" 2>/dev/null || echo 100000000)
echo "Filesystem 1024-blocks Used Available Capacity Mounted on"
echo "/dev/fake 200000000 1 $avail 1% $p"
"""

FAKE_CURL = """#!/usr/bin/env bash
printf 'curl %s\\n' "$*" >> "$FAKE/calls.log"
exit 0
"""

FAKE_FLOCK = """#!/usr/bin/env bash
printf 'flock %s\\n' "$*" >> "$FAKE/calls.log"
exit "$(cat "$FAKE/flock_rc")"
"""

COMPOSE = textwrap.dedent("""\
    name: slipway
    services:
      db:
        image: postgres:17-alpine
      slipway:
        image: slipway:latest
    """)


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True, env=_git_env()).stdout.strip()


def _git_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="T", GIT_AUTHOR_EMAIL="t@x",
               GIT_COMMITTER_NAME="T", GIT_COMMITTER_EMAIL="t@x")
    return env


def _write_exec(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(0o755)


class Rig:
    """A server with an install folder, a local origin and fake docker."""

    def __init__(self, tmp: Path, *, shallow: bool = False):
        self.tmp = tmp
        self.origin = tmp / "origin.git"
        self.src = tmp / "src"
        self.dir = tmp / "install"
        self.fake = tmp / "fake"
        self.bin = tmp / "bin"
        self.lock = tmp / "upgrade.lock"
        self.boot_file = tmp / "boot_id"
        for d in (self.fake / "tags", self.fake / "images", self.fake / "cont", self.fake / "df", self.bin):
            d.mkdir(parents=True)

        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.origin)], check=True, env=_git_env())
        self.src.mkdir()
        git(self.src, "init", "-q", "-b", "main")
        git(self.src, "remote", "add", "origin", str(self.origin))
        (self.src / "docker-compose.yml").write_text(COMPOSE)
        (self.src / "Dockerfile").write_text("FROM python:3.13-slim\n")
        (self.src / ".gitignore").write_text(".slipway-updates/\n.env\n")
        (self.src / "README.md").write_text("zero\n")
        self.c0 = self.commit("zero")
        (self.src / "README.md").write_text("one\n")
        self.c1 = self.commit("one")
        git(self.src, "push", "-q", "origin", "main")
        if shallow:
            subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{self.origin}", str(self.dir)],
                           check=True, env=_git_env(), capture_output=True)
        else:
            subprocess.run(["git", "clone", "-q", str(self.origin), str(self.dir)], check=True, env=_git_env())
        (self.src / "README.md").write_text("two\n")
        self.c2 = self.commit("two")
        git(self.src, "push", "-q", "origin", "main")

        state = self.dir / ".slipway-updates"
        state.mkdir(mode=0o700)
        self.state = state
        self.script = state / f"upgrade-{RUN_ID}.sh"
        self.script.write_bytes(resources.files("slipway.updates").joinpath("upgrade.sh").read_bytes())

        _write_exec(self.bin / "docker", FAKE_DOCKER)
        _write_exec(self.bin / "df", FAKE_DF)
        _write_exec(self.bin / "curl", FAKE_CURL)
        self.boot_file.write_text(BOOT_ID + "\n")

        f = self.fake
        (f / "calls.log").write_text("")
        (f / "services").write_text("db\nslipway\n")
        (f / "db_cid").write_text(DB_CID + "\n")
        (f / "slipway_cid").write_text(OLD_CID + "\n")
        (f / "counter").write_text("0\n")
        (f / "cont" / f"{OLD_CID}.image").write_text(OLD_IMAGE + "\n")
        (f / "cont" / f"{OLD_CID}.running").write_text("true\n")
        (f / "cont" / f"{OLD_CID}.restarts").write_text("0\n")
        self.set_old_stamp(self.c1)
        self.tag("slipway:latest", OLD_IMAGE)
        (f / "db_rev").write_text("rev1\n")
        (f / "db_size").write_text("10485760\n")  # 10 MB
        (f / "db_label_hash").write_text(self.docker("compose", "config", "--hash", "db").split()[1] + "\n")
        (f / "calls.log").write_text("")

    # -- setup helpers

    def commit(self, message: str, cwd: Path | None = None) -> str:
        cwd = cwd or self.src
        git(cwd, "add", "-A")
        git(cwd, "commit", "-q", "-m", message)
        return git(cwd, "rev-parse", "HEAD")

    def set_old_stamp(self, commit: str | None) -> None:
        env = "PATH=/usr/bin\n" + (f"SLIPWAY_COMMIT={commit}\n" if commit else "SLIPWAY_COMMIT=\n")
        (self.fake / "images" / f"{OLD_IMAGE}.env").write_text(env)

    def tag(self, name: str, image: str) -> None:
        (self.fake / "tags" / name.replace(":", "_").replace("/", "_")).write_text(image + "\n")

    def tag_of(self, name: str) -> str | None:
        p = self.fake / "tags" / name.replace(":", "_").replace("/", "_")
        return p.read_text().strip() if p.exists() else None

    def control(self, name: str, value: str = "") -> None:
        (self.fake / name).write_text(value)

    def env(self) -> dict[str, str]:
        env = _git_env()
        env.update(
            PATH=f"{self.bin}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
            FAKE=str(self.fake),
            SLIPWAY_UPGRADE_LOCK=str(self.lock),
            SLIPWAY_UPGRADE_BOOT_ID_FILE=str(self.boot_file),
            SLIPWAY_UPGRADE_POLL="0.05",
            SLIPWAY_UPGRADE_STEADY="0",
            SLIPWAY_UPGRADE_TIMEOUT="2",
        )
        return env

    def docker(self, *args: str) -> str:
        return subprocess.run([str(self.bin / "docker"), *args], cwd=self.dir, env=self.env(), check=True,
                              capture_output=True, text=True).stdout

    # -- running

    def run(self, target: str | None = None, branch: str = "main", from_: str | None = None,
            args: list[str] | None = None, timeout: float = 120, **env: str) -> subprocess.CompletedProcess:
        if args is None:
            args = ["--id", RUN_ID, "--target", target or self.c2, "--branch", branch]
            if from_:
                args += ["--from", from_]
        e = self.env()
        e.update(env)
        # Like the service, but with a loose umask: the script must tighten it itself.
        cmd = ('umask 022; exec bash ".slipway-updates/upgrade-$0.sh" "$@" '
               '> ".slipway-updates/$0.log" 2>&1 < /dev/null')
        return subprocess.run(["bash", "-c", cmd, RUN_ID, *args], cwd=self.dir, env=e, timeout=timeout)

    @property
    def status(self) -> dict:
        return json.loads((self.state / f"{RUN_ID}.json").read_text())

    @property
    def log(self) -> str:
        return (self.state / f"{RUN_ID}.log").read_text()

    @property
    def calls(self) -> list[str]:
        return (self.fake / "calls.log").read_text().splitlines()

    def index(self, call: str) -> int:
        return next(i for i, c in enumerate(self.calls) if c.startswith(call))

    def head(self) -> str:
        return git(self.dir, "rev-parse", "HEAD")

    def branch(self) -> str:
        return git(self.dir, "symbolic-ref", "--short", "-q", "HEAD")

    def current_image(self) -> str:
        cid = (self.fake / "slipway_cid").read_text().strip()
        return (self.fake / "cont" / f"{cid}.image").read_text().strip()

    def db_rev(self) -> str:
        return (self.fake / "db_rev").read_text().strip()


@pytest.fixture
def rig(tmp_path: Path) -> Rig:
    return Rig(tmp_path)


def _new_image(commit: str) -> str:
    return f"sha256:{commit}000000000000000000000000"


def assert_nothing_changed(rig: Rig) -> None:
    assert rig.head() == rig.c1 and rig.branch() == "main"
    assert rig.tag_of("slipway:latest") == OLD_IMAGE
    assert not any(c.startswith(("compose up", "compose stop")) for c in rig.calls)


# --------------------------------------------------------------------------------- success


def test_success(rig: Rig):
    for old in ("20260101-000000-aaaaaa", "20260201-000000-bbbbbb", "20260301-000000-cccccc",
                "20260401-000000-dddddd"):
        (rig.state / f"{old}-before.dump").write_text("PGDMP old\n")
    rig.tag("slipway:before-20260101-000000-aaaaaa", "sha256:" + "b" * 64)

    r = rig.run()

    assert r.returncode == 0, rig.log
    s = rig.status
    assert s["status"] == "succeeded" and s["step"] == "cleanup"
    assert (s["id"], s["from"], s["to"], s["branch"]) == (RUN_ID, rig.c1, rig.c2, "main")
    assert s["backup"] == f".slipway-updates/{RUN_ID}-before.dump" and s["db_changed"] is False
    assert isinstance(s["pid"], int) and s["pid"] > 0 and s["boot_id"] == BOOT_ID
    for key in ("started_at", "finished_at", "heartbeat_at"):
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", s[key])
    assert "Slipway now runs" in s["message"]

    # The checkout is at the target, the new image runs, the old one is kept as this run's before tag.
    assert rig.head() == rig.c2 and rig.branch() == "main"
    assert rig.tag_of("slipway:latest") == _new_image(rig.c2) == rig.current_image()
    assert rig.tag_of(f"slipway:before-{RUN_ID}") == OLD_IMAGE
    assert rig.tag_of("slipway:before-20260101-000000-aaaaaa") is None

    # The build got the stamp.
    stamp = dict(line.split("=", 1) for line in (rig.fake / "build_env").read_text().splitlines())
    assert stamp["SLIPWAY_COMMIT"] == rig.c2 and stamp["SLIPWAY_BRANCH"] == "main"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", stamp["SLIPWAY_BUILT_AT"])

    # The 3 newest dumps stay.
    dumps = sorted(p.name for p in rig.state.glob("*-before.dump"))
    assert dumps == ["20260301-000000-cccccc-before.dump", "20260401-000000-dddddd-before.dump",
                     f"{RUN_ID}-before.dump"]

    # Order: build while the old one runs, then stop, back up, start the new one.
    calls = rig.calls
    assert rig.index("compose build slipway") < rig.index("compose stop -t 30 slipway") \
        < rig.index("compose exec -T db pg_dump") < rig.index("compose exec -T db pg_restore --list") \
        < rig.index("compose up -d --no-build --no-deps slipway")
    assert all("--no-deps" in c for c in calls if c.startswith("compose up"))
    assert not any(c.startswith("curl") for c in calls)
    assert sum(c.startswith("compose exec -T slipway python -c") for c in calls) >= 3
    assert not any("pg_restore -U" in c or "DROP DATABASE" in c for c in calls)
    for step in ("preflight", "fetch", "build", "backup", "switch", "health", "cleanup"):
        assert f"==> {step}: " in rig.log
    assert "==> rollback" not in rig.log
    assert not rig.lock.with_suffix(".lock.d").exists()


def test_files_are_private_even_with_a_loose_umask(rig: Rig):
    assert rig.run().returncode == 0, rig.log
    assert stat.S_IMODE(rig.state.stat().st_mode) == 0o700
    for name in (f"{RUN_ID}.json", f"{RUN_ID}.log", f"{RUN_ID}-before.dump", f"upgrade-{RUN_ID}.sh"):
        assert stat.S_IMODE((rig.state / name).stat().st_mode) == 0o600, name


def test_health_needs_steady_checks_spanning_the_window(rig: Rig):
    # 2 s: `date +%s` counts whole seconds, so 1 s can pass with three quick checks across a tick.
    r = rig.run(SLIPWAY_UPGRADE_STEADY="2", SLIPWAY_UPGRADE_TIMEOUT="20")
    assert r.returncode == 0, rig.log
    assert sum(c.startswith("compose exec -T slipway python -c") for c in rig.calls) > 3


def test_shallow_install_is_unshallowed(tmp_path: Path):
    rig = Rig(tmp_path, shallow=True)
    assert git(rig.dir, "rev-parse", "--is-shallow-repository") == "true"
    assert rig.run().returncode == 0, rig.log
    assert git(rig.dir, "rev-parse", "--is-shallow-repository") == "false"
    assert rig.head() == rig.c2


def test_untracked_override_file_is_fine(rig: Rig):
    (rig.dir / "docker-compose.override.yml").write_text("services: {}\n")
    assert rig.run().returncode == 0, rig.log
    assert (rig.dir / "docker-compose.override.yml").exists()


# --------------------------------------------------------------------------------- failures before the switch


def test_build_failure_puts_checkout_and_image_back(rig: Rig):
    rig.tag("slipway:latest", OLD_IMAGE)
    rig.control("build_fail")
    r = rig.run()
    assert r.returncode == 1
    s = rig.status
    assert s["status"] == "failed" and s["step"] == "build" and "didn't build" in s["message"]
    assert_nothing_changed(rig)
    assert rig.current_image() == OLD_IMAGE


def test_target_that_changes_the_db_container_is_refused_after_checkout(rig: Rig):
    (rig.src / "docker-compose.yml").write_text(COMPOSE.replace("postgres:17-alpine", "postgres:18-alpine"))
    c3 = rig.commit("postgres 18")
    git(rig.src, "push", "-q", "origin", "main")
    r = rig.run(target=c3)
    assert r.returncode == 1
    s = rig.status
    assert s["status"] == "failed" and s["step"] == "build"
    assert s["message"] == "This version changes the database container. Run install.sh by hand."
    assert_nothing_changed(rig)
    assert not any(c.startswith("compose build") for c in rig.calls)


def test_preflight_refuses_when_db_settings_changed_since_it_started(rig: Rig):
    rig.control("db_label_hash", "somethingelse\n")
    r = rig.run()
    assert r.returncode == 1
    s = rig.status
    assert s["status"] == "failed" and s["step"] == "preflight"
    assert s["message"] == ("The database settings changed since it started (.env or docker-compose.yml). "
                            "Run install.sh by hand.")
    assert_nothing_changed(rig)
    assert not any(c.startswith("tag ") for c in rig.calls)


def test_local_edits_to_tracked_files_are_refused(rig: Rig):
    (rig.dir / "docker-compose.yml").write_text(COMPOSE + "# my edit\n")
    r = rig.run()
    assert r.returncode == 1
    s = rig.status
    assert s["step"] == "preflight" and s["message"].startswith("The install folder has local changes to tracked files.")
    assert "docker-compose.override.yml" in s["message"]
    assert (rig.dir / "docker-compose.yml").read_text().endswith("# my edit\n")  # untouched
    assert rig.head() == rig.c1


def test_low_space_for_docker_images_is_refused(rig: Rig):
    (rig.fake / "df" / "_var_lib_docker").write_text("1048576\n")  # 1 GB
    r = rig.run()
    assert r.returncode == 1
    s = rig.status
    assert s["step"] == "preflight" and "/var/lib/docker" in s["message"] and "Not enough free space" in s["message"]
    assert_nothing_changed(rig)


def test_low_space_for_the_backup_is_refused(rig: Rig):
    rig.control("db_size", str(500 * 1024 * 1024) + "\n")  # 500 MB database needs 1100 MB
    (rig.fake / "df" / str(rig.dir).replace("/", "_")).write_text(str(800 * 1024) + "\n")
    r = rig.run()
    assert r.returncode == 1
    s = rig.status
    assert s["step"] == "preflight" and str(rig.dir) in s["message"] and "1100 MB needed" in s["message"]


def test_services_not_running_is_refused(rig: Rig):
    rig.control("services", "db\n")
    assert rig.run().returncode == 1
    assert rig.status["step"] == "preflight" and "must both be running" in rig.status["message"]


@pytest.mark.parametrize("which", ["older", "sideways"])
def test_target_that_does_not_descend_fails_at_fetch(rig: Rig, which: str):
    if which == "older":
        target, branch = rig.c0, "main"
    else:
        git(rig.src, "checkout", "-q", "-b", "side", rig.c0)
        (rig.src / "side.txt").write_text("side\n")
        target, branch = rig.commit("side"), "side"
        git(rig.src, "push", "-q", "origin", "side")
    r = rig.run(target=target, branch=branch)
    assert r.returncode == 1
    s = rig.status
    assert s["status"] == "failed" and s["step"] == "fetch" and "can't move back or sideways" in s["message"]
    assert_nothing_changed(rig)
    assert not any(c.startswith("tag ") for c in rig.calls)


def test_target_not_on_the_branch_fails_at_fetch(rig: Rig):
    r = rig.run(target="f" * 40)
    assert r.returncode == 1
    assert rig.status["step"] == "fetch" and "isn't on origin" in rig.status["message"]


def test_backup_failure_brings_the_current_version_back(rig: Rig):
    rig.control("dump_fail")
    r = rig.run()
    assert r.returncode == 1, rig.log
    s = rig.status
    assert s["status"] == "failed" and s["step"] == "backup" and "running again" in s["message"]
    assert s["backup"] is None
    assert rig.head() == rig.c1 and rig.tag_of("slipway:latest") == OLD_IMAGE
    assert rig.current_image() == OLD_IMAGE
    assert (rig.fake / "cont" / f"{OLD_CID}.running").read_text().strip() == "true"
    assert not (rig.state / f"{RUN_ID}-before.dump").exists()
    assert rig.index("compose stop -t 30 slipway") < rig.index("compose up -d --no-build --no-deps slipway")


def test_unreadable_backup_brings_the_current_version_back(rig: Rig):
    rig.control("list_fail")
    assert rig.run().returncode == 1
    assert rig.status["step"] == "backup" and "can't be read back" in rig.status["message"]
    assert rig.current_image() == OLD_IMAGE


# --------------------------------------------------------------------------------- rollback


def test_health_failure_without_a_db_change_rolls_back(rig: Rig):
    rig.control(f"health_fail_{rig.c2}")
    r = rig.run()
    assert r.returncode == 2, rig.log
    s = rig.status
    assert s["status"] == "rolled_back" and s["step"] == "rollback" and s["db_changed"] is False
    assert rig.head() == rig.c1 and rig.branch() == "main"
    assert rig.tag_of("slipway:latest") == OLD_IMAGE == rig.current_image()
    switch = rig.index("compose up -d --no-build --no-deps slipway")
    stops = [i for i, c in enumerate(rig.calls) if c == "compose stop -t 30 slipway"]
    assert len(stops) == 2 and stops[1] > switch  # the failed new version is stopped first
    assert not any("pg_restore -U" in c or "DROP DATABASE" in c for c in rig.calls)
    assert all("--no-deps" in c for c in rig.calls if c.startswith("compose up"))


def test_health_failure_with_a_db_change_restores_the_backup(rig: Rig):
    rig.control("migrate_to", f"{rig.c2} rev2\n")
    rig.control(f"health_fail_{rig.c2}")
    r = rig.run()
    assert r.returncode == 2, rig.log
    s = rig.status
    assert s["status"] == "rolled_back" and s["db_changed"] is True and "restored" in s["message"]
    assert rig.db_rev() == "rev1"
    calls = rig.calls
    drop = rig.index("compose exec -T db psql -U slipway -d postgres -v ON_ERROR_STOP=1")
    assert "-c DROP DATABASE slipway WITH (FORCE) -c CREATE DATABASE slipway OWNER slipway" in calls[drop]
    restore = rig.index("compose exec -T db pg_restore -U slipway -d slipway --exit-on-error --single-transaction --no-owner")
    rollback_stop = max(i for i, c in enumerate(calls) if c == "compose stop -t 30 slipway")
    last_up = max(i for i, c in enumerate(calls) if c.startswith("compose up"))
    assert rollback_stop < drop < restore < last_up
    assert rig.current_image() == OLD_IMAGE and rig.head() == rig.c1


def test_crash_looping_new_version_is_rolled_back(rig: Rig):
    rig.control(f"crashloop_{rig.c2}")
    r = rig.run()
    assert r.returncode == 2, rig.log
    assert rig.status["status"] == "rolled_back"


def test_crash_loop_gives_up_early_and_keeps_the_output(rig: Rig):
    # Docker reports a crash-looping container as running: the restarts give it away, long before the limit.
    rig.control(f"crashloop_{rig.c2}")
    rig.control(f"output_{rig.c2}", "Running upgrade 0006 -> 0007\nTraceback (most recent call last):\n"
                "sqlalchemy.exc.ProgrammingError: column \"label\" does not exist\x1b[0m\r\n")
    started = time.monotonic()
    r = rig.run(SLIPWAY_UPGRADE_TIMEOUT="60")
    assert r.returncode == 2, rig.log
    assert time.monotonic() - started < 30
    s = rig.status
    assert s["status"] == "rolled_back"
    assert s["message"].startswith("The new version kept crashing on start. Its last output is in the log.")
    log = rig.log
    assert "Health: the container keeps stopping and Docker keeps restarting it." in log
    assert "Gave up: the container restarted 3 times" in log
    assert "The last lines the new version printed:" in log
    assert '    | sqlalchemy.exc.ProgrammingError: column "label" does not exist[0m\n' in log
    assert "\x1b" not in log and "\r" not in log
    # The output is read before the rollback stops and replaces the container.
    calls = rig.calls
    logs = rig.index("compose logs --no-color --no-log-prefix --tail 60 slipway")
    assert logs < max(i for i, c in enumerate(calls) if c == "compose stop -t 30 slipway")
    assert rig.current_image() == OLD_IMAGE


def test_health_failure_keeps_the_output(rig: Rig):
    rig.control(f"health_fail_{rig.c2}")
    rig.control(f"output_{rig.c2}", "INFO:     Waiting for application startup.\n")
    r = rig.run()
    assert r.returncode == 2, rig.log
    assert rig.status["message"].startswith("The new version didn't pass its health check. Its last output is in the log.")
    assert "    | INFO:     Waiting for application startup." in rig.log
    assert "Gave up after 2 seconds." in rig.log


def test_health_failure_without_output_says_so(rig: Rig):
    rig.control(f"health_fail_{rig.c2}")
    r = rig.run()
    assert r.returncode == 2, rig.log
    assert "The new version printed nothing (or its output could not be read)." in rig.log


def test_previous_version_failing_at_rollback_keeps_its_output(rig: Rig):
    rig.control(f"health_fail_{rig.c2}")
    rig.control(f"health_fail_{rig.c1}")
    rig.control(f"output_{rig.c1}", "old version trouble\n")
    r = rig.run()
    assert r.returncode == 3, rig.log
    assert "The last lines the previous version printed:" in rig.log
    assert "    | old version trouble" in rig.log


def test_checkout_is_readable_by_everyone_despite_the_script_umask(rig: Rig):
    # The image copies alembic/ and slipway/ with these modes, and Slipway runs as uid 10001: a new migration
    # checked out as 600 crashed it on start.
    (rig.src / "alembic" / "versions").mkdir(parents=True)
    (rig.src / "alembic" / "versions" / "0099_new.py").write_text("revision = '0099'\n")
    (rig.src / "README.md").write_text("three\n")
    c3 = rig.commit("a new migration")
    git(rig.src, "push", "-q", "origin", "main")
    r = rig.run(target=c3)
    assert r.returncode == 0, rig.log
    for path in (rig.dir / "alembic" / "versions" / "0099_new.py", rig.dir / "README.md"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o644, path
    assert stat.S_IMODE((rig.dir / "alembic").stat().st_mode) == 0o755
    assert stat.S_IMODE((rig.state / f"{RUN_ID}.json").stat().st_mode) == 0o600  # its own files stay private


def test_rolled_back_checkout_is_readable_too(rig: Rig):
    rig.control(f"health_fail_{rig.c2}")
    r = rig.run()
    assert r.returncode == 2, rig.log
    assert stat.S_IMODE((rig.dir / "README.md").stat().st_mode) == 0o644


# --------------------------------------------------------------------------------- snapshot folder

MOUNTED = COMPOSE + "        volumes:\n          - ${SLIPWAY_DATA_DIR:-./data}/files:/var/lib/slipway\n"


def _target_with_the_mount(rig: Rig) -> str:
    (rig.src / "docker-compose.yml").write_text(MOUNTED)
    c3 = rig.commit("mount the snapshot folder")
    git(rig.src, "push", "-q", "origin", "main")
    return c3


def test_snapshot_folder_is_made_for_slipway(rig: Rig):
    c3 = _target_with_the_mount(rig)
    r = rig.run(target=c3)
    assert r.returncode == 0, rig.log
    files = rig.dir / "data" / "files"
    assert files.is_dir() and stat.S_IMODE(files.stat().st_mode) == 0o700
    # Not root here, so chown fails and a throwaway db container does it, after the build and before the stop.
    assert (rig.fake / "files_given").read_text().strip() == str(files)
    calls = rig.calls
    run = rig.index("compose run --rm --no-deps --user root -v ")
    assert rig.index("compose build slipway") < run < rig.index("compose stop -t 30 slipway")
    assert f"Made {files} for stored snapshots." in rig.log
    assert f"Gave {files} to Slipway (uid 10001, mode 700)." in rig.log
    assert calls


def test_snapshot_folder_follows_the_data_dir_in_env(rig: Rig, tmp_path: Path):
    c3 = _target_with_the_mount(rig)
    data = tmp_path / "appdata"
    (rig.dir / ".env").write_text(f'SLIPWAY_DATA_DIR="{data}/"\n')
    r = rig.run(target=c3)
    assert r.returncode == 0, rig.log
    assert (data / "files").is_dir()
    assert (rig.fake / "files_given").read_text().strip() == str(data / "files")


def test_snapshot_folder_failure_is_logged_and_the_upgrade_goes_on(rig: Rig):
    c3 = _target_with_the_mount(rig)
    rig.control("run_fail")
    r = rig.run(target=c3)
    assert r.returncode == 0, rig.log
    files = rig.dir / "data" / "files"
    assert (f"Could not give {files} to Slipway, so stored snapshots won't work. "
            f"Run: sudo chown 10001:10001 {files} && sudo chmod 700 {files}") in rig.log


def test_no_snapshot_folder_without_the_mount(rig: Rig):
    r = rig.run()
    assert r.returncode == 0, rig.log
    assert not (rig.dir / "data").exists()
    assert not any(c.startswith("compose run") for c in rig.calls)


def test_switch_failure_rolls_back(rig: Rig):
    rig.control("up_fail")
    r = rig.run()
    # The rollback's own `up` fails too, so this ends as rollback_failed.
    assert r.returncode == 3
    s = rig.status
    assert s["status"] == "rollback_failed" and f".slipway-updates/{RUN_ID}-before.dump" in s["message"]
    assert "docs/updates.md" in s["message"]


def test_unreadable_revision_at_rollback_counts_as_changed(rig: Rig):
    rig.control("break_rev_on_up", rig.c2)
    rig.control(f"health_fail_{rig.c2}")
    r = rig.run()
    assert r.returncode == 2, rig.log
    assert rig.status["db_changed"] is True
    assert any("pg_restore -U slipway -d slipway" in c for c in rig.calls)


def test_rollback_failure(rig: Rig):
    rig.control(f"health_fail_{rig.c2}")
    rig.control(f"health_fail_{rig.c1}")  # the old version doesn't come back either
    r = rig.run()
    assert r.returncode == 3
    s = rig.status
    assert s["status"] == "rollback_failed" and s["step"] == "rollback"
    assert f".slipway-updates/{RUN_ID}-before.dump" in s["message"] and "docs/updates.md" in s["message"]
    assert s["finished_at"]


def test_pg_restore_failure_is_rollback_failed(rig: Rig):
    rig.control("migrate_to", f"{rig.c2} rev2\n")
    rig.control(f"health_fail_{rig.c2}")
    rig.control("restore_fail")
    r = rig.run()
    assert r.returncode == 3
    s = rig.status
    assert s["status"] == "rollback_failed" and "Could not restore the backup" in s["message"]
    assert any("DROP DATABASE" in c for c in rig.calls)


def test_restored_revision_must_match(rig: Rig):
    rig.control("migrate_to", f"{rig.c2} rev2\n")
    rig.control(f"health_fail_{rig.c2}")
    rig.control("restore_wrong_rev")
    r = rig.run()
    assert r.returncode == 3
    s = rig.status
    assert s["status"] == "rollback_failed" and "revision rev9, not rev1" in s["message"]


def test_backup_with_changed_permissions_is_not_restored(rig: Rig):
    rig.control("migrate_to", f"{rig.c2} rev2\n")
    rig.control(f"health_fail_{rig.c2}")
    rig.control("chmod_dump_on_up")
    r = rig.run()
    assert r.returncode == 3
    s = rig.status
    assert s["status"] == "rollback_failed"
    assert s["message"].startswith("Rolling back failed: The backup's permissions changed, so it was not restored")
    assert not any("pg_restore -U" in c or "DROP DATABASE" in c for c in rig.calls)


def test_head_that_is_not_the_running_commit(rig: Rig):
    # Slipway runs c0 (the image says so), but the checkout moved to c1 without a rebuild, and slipway:latest
    # is some other image left by a failed install.sh.
    rig.set_old_stamp(rig.c0)
    rig.tag("slipway:latest", "sha256:" + "e" * 64)
    rig.control(f"health_fail_{rig.c2}")
    r = rig.run(from_=rig.c0)
    assert r.returncode == 2, rig.log
    s = rig.status
    assert s["status"] == "rolled_back" and s["from"] == rig.c0
    assert f"The checkout is at {rig.c1} but Slipway runs {rig.c0}" in rig.log
    assert rig.tag_of(f"slipway:before-{RUN_ID}") == OLD_IMAGE  # the running container's image
    assert rig.head() == rig.c0 and rig.branch() == "main"  # rollback restores what was running
    assert rig.current_image() == OLD_IMAGE


def test_unstamped_old_image_rolls_back_on_health_alone(rig: Rig):
    rig.set_old_stamp(None)
    rig.control(f"health_fail_{rig.c2}")
    r = rig.run(from_=rig.c1)
    assert r.returncode == 2, rig.log
    assert rig.status["status"] == "rolled_back"


# --------------------------------------------------------------------------------- the lock


def _dead_pid() -> int:
    p = subprocess.Popen(["true"])
    p.wait()
    return p.pid


def _no_flock(rig: Rig) -> None:
    """Make flock fail the way it does without lock support, so the lock folder is used."""
    _write_exec(rig.bin / "flock", FAKE_FLOCK)
    rig.control("flock_rc", "38\n")


def test_lock_held_exits_75(rig: Rig):
    _no_flock(rig)
    held = Path(f"{rig.lock}.d")
    held.mkdir()
    (held / "owner").write_text(f"{os.getpid()} {BOOT_ID}\n")
    r = rig.run()
    assert r.returncode == 75
    s = rig.status
    assert s["status"] == "failed" and s["message"] == "Another upgrade is running."
    assert held.exists() and (held / "owner").read_text().startswith(str(os.getpid()))
    assert_nothing_changed(rig)


@pytest.mark.parametrize("stale", ["dead pid", "other boot"])
def test_stale_lock_is_taken_over(rig: Rig, stale: str):
    _no_flock(rig)
    held = Path(f"{rig.lock}.d")
    held.mkdir()
    owner = f"{_dead_pid()} {BOOT_ID}" if stale == "dead pid" else f"{os.getpid()} 99999999-0000-0000-0000-000000000000"
    (held / "owner").write_text(owner + "\n")
    r = rig.run()
    assert r.returncode == 0, rig.log
    assert "Taking over a stale lock" in rig.log
    assert not held.exists()


def test_flock_held_exits_75(rig: Rig):
    _write_exec(rig.bin / "flock", FAKE_FLOCK)
    rig.control("flock_rc", "1\n")
    assert rig.run().returncode == 75
    assert rig.status["message"] == "Another upgrade is running."
    assert "flock -w 30 9" in rig.calls  # waits a little for a check that is finishing


def test_flock_error_falls_back_to_the_lock_folder(rig: Rig):
    _no_flock(rig)
    r = rig.run()
    assert r.returncode == 0, rig.log
    assert "Using a lock folder instead" in rig.log
    assert not Path(f"{rig.lock}.d").exists()


# --------------------------------------------------------------------------------- arguments and the trap


@pytest.mark.parametrize("args", [
    ["--id", "nope", "--target", "a" * 40, "--branch", "main"],
    ["--id", RUN_ID, "--target", "abc", "--branch", "main"],
    ["--id", RUN_ID, "--target", "A" * 40, "--branch", "main"],
    ["--id", RUN_ID, "--target", "a" * 40, "--branch", "-x"],
    ["--id", RUN_ID, "--target", "a" * 40, "--branch", "a..b"],
    ["--id", RUN_ID, "--target", "a" * 40, "--branch", "/main"],
    ["--id", RUN_ID, "--target", "a" * 40, "--branch", "main/"],
    ["--id", RUN_ID, "--target", "a" * 40, "--branch", "main.lock"],
    ["--id", RUN_ID, "--target", "a" * 40, "--branch", "ma;in"],
    ["--id", RUN_ID, "--target", "a" * 40, "--branch", "x" * 101],
    ["--id", RUN_ID, "--target", "a" * 40, "--branch", "main", "--from", "--output=x"],
    ["--id", RUN_ID, "--target", "a" * 40, "--branch", "main", "--extra"],
    ["--id", RUN_ID, "--target"],
])
def test_bad_arguments_exit_64(rig: Rig, args: list[str]):
    r = rig.run(args=args)
    assert r.returncode == 64
    assert rig.calls == []
    status_file = rig.state / f"{RUN_ID}.json"
    if args[1] == RUN_ID and len(args) > 3:
        assert rig.status["status"] == "failed" and "bad argument" in rig.status["message"]
    elif args[1] != RUN_ID:
        assert not status_file.exists()


def test_unexpected_exit_is_recorded_and_undone(rig: Rig):
    rig.control("kill_on_build")
    r = rig.run()
    assert r.returncode == 143
    s = rig.status
    assert s["status"] == "failed" and s["step"] == "build" and "stopped unexpectedly" in s["message"]
    assert s["finished_at"]
    assert rig.head() == rig.c1 and rig.branch() == "main"
    assert rig.tag_of("slipway:latest") == OLD_IMAGE
    assert not any(c.startswith("compose up") for c in rig.calls)


def test_status_json_is_valid_with_odd_characters(rig: Rig):
    odd = rig.tmp / 'odd "dir" \\ here'
    shutil.move(str(rig.dir), odd)
    rig.dir, rig.state = odd, odd / ".slipway-updates"
    (rig.fake / "df" / str(odd).replace("/", "_")).write_text("10\n")
    assert rig.run().returncode == 1
    assert str(odd) in rig.status["message"]


# --------------------------------------------------------------------------------- the build stamp


def test_script_is_package_data():
    assert resources.files("slipway.updates").joinpath("upgrade.sh").is_file()
    assert '"updates/*.sh"' in (ROOT / "pyproject.toml").read_text()


def test_dockerfile_carries_the_stamp_after_the_dependencies():
    text = (ROOT / "Dockerfile").read_text()
    for name in ("SLIPWAY_COMMIT", "SLIPWAY_BRANCH", "SLIPWAY_BUILT_AT"):
        assert f"ARG {name}=" in text and f"{name}=${name}" in text
    assert text.index("RUN pip install .") < text.index("ARG SLIPWAY_COMMIT=")


def test_compose_passes_the_stamp_as_build_args():
    text = (ROOT / "docker-compose.yml").read_text()
    for name in ("SLIPWAY_COMMIT", "SLIPWAY_BRANCH", "SLIPWAY_BUILT_AT"):
        assert f"{name}: ${{{name}:-}}" in text
    assert "image: slipway:latest" in text and "context: ." in text


def test_install_sh_exports_the_stamp_before_building():
    text = (ROOT / "install.sh").read_text()
    export = text.index('export SLIPWAY_COMMIT="$(git rev-parse HEAD)" SLIPWAY_BRANCH="$BRANCH"')
    assert export < text.index("docker compose up -d --build")
    assert "SLIPWAY_BUILT_AT=" in text[export:text.index("docker compose up -d --build")]


def test_state_folder_is_ignored():
    assert ".slipway-updates/" in (ROOT / ".gitignore").read_text().splitlines()
    assert ".slipway-updates/" in (ROOT / ".dockerignore").read_text().splitlines()


def test_scripts_parse():
    for path in (ROOT / "slipway" / "updates" / "upgrade.sh", ROOT / "install.sh"):
        subprocess.run(["bash", "-n", str(path)], check=True)


# --------------------------------------------------------------------------------- stopped or stuck half way


def test_signal_after_the_switch_rolls_back(rig: Rig):
    # The new version migrated the database and never gets healthy; the script is killed on the third probe.
    rig.control("migrate_to", f"{rig.c2} rev2\n")
    rig.control(f"health_fail_{rig.c2}")
    rig.control("kill_on_probe", "3")
    r = rig.run(SLIPWAY_UPGRADE_TIMEOUT="30")
    assert r.returncode == 2, rig.log
    s = rig.status
    assert s["status"] == "rolled_back" and s["step"] == "rollback" and s["failed_step"] == "health"
    assert s["db_changed"] is True and "stopped unexpectedly during health" in s["message"]
    assert "Stopped by a signal (TERM)." in rig.log and "==> rollback" in rig.log
    assert rig.tag_of("slipway:latest") == OLD_IMAGE == rig.current_image()
    assert rig.head() == rig.c1 and rig.db_rev() == "rev1"
    assert not rig.lock.with_suffix(".lock.d").exists()


def test_signal_during_cleanup_is_still_a_success(rig: Rig):
    rig.control("kill_on_image_ls")
    r = rig.run()
    s = rig.status
    assert s["status"] == "succeeded" and s["step"] == "cleanup", rig.log
    assert "stopped early" in s["message"] and s["finished_at"]
    assert rig.head() == rig.c2 and rig.current_image() == _new_image(rig.c2)
    assert "==> rollback" not in rig.log
    assert r.returncode == 143


def test_build_failure_that_cannot_be_put_back_is_rollback_failed(rig: Rig):
    rig.control("build_fail")
    rig.control("tag_back_fail")
    r = rig.run()
    assert r.returncode == 3
    s = rig.status
    assert s["status"] == "rollback_failed" and s["step"] == "build"
    assert "could not be put back" in s["message"] and "docs/updates.md" in s["message"]
    assert rig.head() == rig.c1  # what could be put back was
    assert not any(c.startswith(("compose up", "compose stop")) for c in rig.calls)


def test_signal_before_the_switch_that_cannot_be_put_back_is_rollback_failed(rig: Rig):
    rig.control("kill_on_build")
    rig.control("tag_back_fail")
    r = rig.run()
    assert r.returncode == 3
    s = rig.status
    assert s["status"] == "rollback_failed" and "stopped unexpectedly during build" in s["message"]
    assert "could not be put back" in s["message"]


def test_failure_before_the_switch_puts_the_checkout_back_where_it_was(rig: Rig):
    # Slipway runs c0 (the image says so) but the checkout was moved to c1 by hand without a rebuild.
    rig.set_old_stamp(rig.c0)
    rig.control("build_fail")
    r = rig.run(from_=rig.c0)
    assert r.returncode == 1 and rig.status["status"] == "failed"
    assert rig.head() == rig.c1 and rig.branch() == "main"
    assert git(rig.dir, "rev-parse", "main") == rig.c1  # the local branch didn't move either


def test_rollback_keeps_going_when_the_stop_fails(rig: Rig):
    # Without a database change a failed stop doesn't matter: `up` replaces the new container.
    rig.control(f"health_fail_{rig.c2}")
    rig.control("stop_fail_nth", "2")  # 1 = the backup's stop, 2 = the rollback's
    r = rig.run()
    assert r.returncode == 2, rig.log
    s = rig.status
    assert s["status"] == "rolled_back" and s["failed_step"] == "health"
    assert rig.tag_of("slipway:latest") == OLD_IMAGE == rig.current_image() and rig.head() == rig.c1
    assert "Could not stop the new version." in rig.log


def test_rollback_with_a_db_change_and_a_failed_stop_does_the_safe_parts(rig: Rig):
    rig.control("migrate_to", f"{rig.c2} rev2\n")
    rig.control(f"health_fail_{rig.c2}")
    rig.control("stop_fail_nth", "2")
    r = rig.run()
    assert r.returncode == 3
    s = rig.status
    assert s["status"] == "rollback_failed"
    assert "Could not stop the new version, so the database was not restored." in s["message"]
    assert "Done: tagged the previous image, restored the checkout." in s["message"]
    assert f".slipway-updates/{RUN_ID}-before.dump" in s["message"]
    # The image tag and checkout are back; the database and the restart were left alone.
    assert rig.tag_of("slipway:latest") == OLD_IMAGE and rig.head() == rig.c1
    assert not any("DROP DATABASE" in c or "pg_restore -U" in c for c in rig.calls)
    assert sum(c.startswith("compose up") for c in rig.calls) == 1


def test_rollback_restores_the_checkout_when_the_tag_back_fails(rig: Rig):
    rig.control(f"health_fail_{rig.c2}")
    rig.control("tag_back_fail")
    r = rig.run()
    assert r.returncode == 3
    s = rig.status
    assert s["status"] == "rollback_failed" and "Could not tag the previous image." in s["message"]
    assert "restored the checkout" in s["message"] and "The previous version was not started." in s["message"]
    assert rig.head() == rig.c1 and rig.branch() == "main"
    assert sum(c.startswith("compose up") for c in rig.calls) == 1  # no restart on the new image


def test_switch_failure_marks_the_switch_as_the_failed_step(rig: Rig):
    rig.control("up_fail")
    rig.run()
    assert rig.status["failed_step"] == "switch" and rig.status["step"] == "rollback"


def test_a_hung_health_probe_times_out(rig: Rig):
    # docker exec never returns: each probe is cut off, so the health deadline still applies.
    rig.control("hang_probe")
    try:
        r = rig.run(timeout=60, SLIPWAY_UPGRADE_PROBE_TIMEOUT="1")
    finally:
        subprocess.run(["pkill", "-f", "sleep 3600"], check=False)
    s = rig.status
    assert s["status"] == "rollback_failed" and r.returncode == 3  # the old version's probes hang too
    assert s["failed_step"] == "health"
    assert "Gave up after 2 seconds." in rig.log
    assert "The previous version didn't pass its health check." in s["message"]
    assert rig.tag_of("slipway:latest") == OLD_IMAGE and rig.head() == rig.c1


# --------------------------------------------------------------------------------- running deployments


def test_waits_for_a_running_deployment_before_stopping(rig: Rig):
    rig.control("active_deploys", "1 3\n")  # one deployment, finished after three reads
    r = rig.run()
    assert r.returncode == 0, rig.log
    assert "Waiting for 1 deployment(s) to end before stopping Slipway." in rig.log
    reads = [i for i, c in enumerate(rig.calls) if "FROM deployments" in c]
    assert len(reads) == 4 and reads[-1] < rig.index("compose stop -t 30 slipway")


def test_a_deployment_that_keeps_running_stops_the_upgrade_before_anything_stops(rig: Rig):
    rig.control("active_deploys", "2\n")
    r = rig.run(SLIPWAY_UPGRADE_DEPLOY_WAIT="1")
    assert r.returncode == 1, rig.log
    s = rig.status
    assert s["status"] == "failed" and s["step"] == "backup"
    assert s["message"] == "A deployment is still running after 1 seconds. Try again when it finishes."
    assert_nothing_changed(rig)


# --------------------------------------------------------------------------------- the lock folder


def test_young_lock_folder_without_an_owner_is_held(rig: Rig):
    _no_flock(rig)
    Path(f"{rig.lock}.d").mkdir()  # its holder may still be writing the owner file
    assert rig.run().returncode == 75
    assert Path(f"{rig.lock}.d").exists()


def test_old_lock_folder_without_an_owner_is_taken_over(rig: Rig):
    _no_flock(rig)
    held = Path(f"{rig.lock}.d")
    held.mkdir()
    old = time.time() - 120
    os.utime(held, (old, old))  # its holder was killed right after making it
    r = rig.run()
    assert r.returncode == 0, rig.log
    assert "Taking over a stale lock (its folder has had no owner for" in rig.log
    assert not held.exists() and not list(rig.tmp.glob("upgrade.lock.d.stale.*"))
