#!/usr/bin/env bash
# Slipway's upgrade script. The running Slipway copies it to its own server and starts it, detached, from the
# install folder (the compose project's working_dir):
#
#   bash .slipway-updates/upgrade-<id>.sh --id <id> --target <40-hex sha> --branch <branch> [--from <40-hex sha>]
#
# --from is the commit the running image was built from. Without it the checkout's HEAD is used.
#
# Steps: preflight, fetch, build, backup, switch, health, then cleanup on success or rollback on failure.
# The current version keeps running through fetch and build; it is stopped only for the backup and the switch.
# Status goes to .slipway-updates/<id>.json (rewritten atomically), output to stdout (the service sends it
# to .slipway-updates/<id>.log).
#
# Exit codes: 0 succeeded, 1 failed (nothing changed, or it was all put back before the switch), 2 rolled
# back, 3 rollback failed (something could not be put back), 64 bad arguments, 75 another upgrade is running.
# A signal ends the run with 143, 130 or 129 when nothing had changed yet.
#
# For tests only: SLIPWAY_UPGRADE_LOCK, SLIPWAY_UPGRADE_BOOT_ID_FILE, SLIPWAY_UPGRADE_POLL,
# SLIPWAY_UPGRADE_STEADY, SLIPWAY_UPGRADE_TIMEOUT, SLIPWAY_UPGRADE_PROBE_TIMEOUT, SLIPWAY_UPGRADE_LOCK_WAIT
# and SLIPWAY_UPGRADE_DEPLOY_WAIT override the lock path, the boot id file and the timing.
#
# Every docker and git fetch call runs under `timeout` when the server has it, so one hung call can't hold
# the run (and the lock) forever.
#
# Plain bash (3.2 and later), git, docker and coreutils. No python or jq on the server.
umask 077
set -u
set -o pipefail
# No set -e: every step checks its own commands, so a rollback always gets to run.

export GIT_TERMINAL_PROMPT=0
export LC_ALL=C

STATE_DIR=.slipway-updates
SHA_RE='^[0-9a-f]{40}$'
ID_RE='^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$'
BRANCH_RE='^[A-Za-z0-9._/-]{1,100}$'
CID_RE='^[0-9a-f]{12,64}$'
IMAGE_RE='^(sha256:)?[0-9a-f]{12,64}$'
REV_RE='^[A-Za-z0-9_]{1,64}$'
NUM_RE='^[0-9]+$'
POLL_RE='^[0-9]+(\.[0-9]+)?$'

LOCK=${SLIPWAY_UPGRADE_LOCK:-/tmp/slipway-upgrade.lock}
BOOT_ID_FILE=${SLIPWAY_UPGRADE_BOOT_ID_FILE:-/proc/sys/kernel/random/boot_id}
POLL=${SLIPWAY_UPGRADE_POLL:-3}
STEADY=${SLIPWAY_UPGRADE_STEADY:-15}
HEALTH_LIMIT=${SLIPWAY_UPGRADE_TIMEOUT:-300}
PROBE_TIMEOUT=${SLIPWAY_UPGRADE_PROBE_TIMEOUT:-20}
LOCK_WAIT=${SLIPWAY_UPGRADE_LOCK_WAIT:-30}
DEPLOY_WAIT=${SLIPWAY_UPGRADE_DEPLOY_WAIT:-600}
[[ $POLL =~ $POLL_RE ]] || POLL=3
[[ $STEADY =~ $NUM_RE ]] || STEADY=15
[[ $HEALTH_LIMIT =~ $NUM_RE ]] || HEALTH_LIMIT=300
[[ $PROBE_TIMEOUT =~ $NUM_RE ]] && [ "$PROBE_TIMEOUT" -gt 0 ] || PROBE_TIMEOUT=20
[[ $LOCK_WAIT =~ $NUM_RE ]] || LOCK_WAIT=30
[[ $DEPLOY_WAIT =~ $NUM_RE ]] || DEPLOY_WAIT=600
# Time limits, in seconds, for one call.
T_QUICK=60     # ps, inspect, tag, psql, config, logs
T_STOP=120     # compose stop -t 30
T_UP=300       # compose up
T_BUILD=3600   # compose build
T_DB=1800      # pg_dump, pg_restore, recreating the database
T_FETCH=600    # git fetch
STALE_LOCK_AGE=60  # a lock folder without an owner file this old was left by a killed run

ID="" TARGET="" BRANCH="" FROM_ARG=""
STATUS=running STEP=preflight MESSAGE="" FROM="" BACKUP="" DB_CHANGED=false FAILED_STEP=""
STARTED_AT="" FINISHED_AT="" BOOT_ID=""
STATUS_READY=0     # 1 once the status file may be written
IN_ROLLBACK=0
IN_TRAP=0          # 1 while the EXIT trap runs
TAGGED=0           # slipway:before-<id> exists
CHECKED_OUT=0      # the checkout may have moved to the target
OLD_STOPPED=0      # the current version was stopped for the backup
SWITCHED=0         # the new version was started
HEALTHY=0          # the new version passed its health check
CRASHED=0          # the last health check gave up because the container kept restarting
CRASH_LIMIT=3      # restarts during a health check that mean the container crashes on start
LOG_LINES=60       # lines of a container's own output copied into this log when it isn't healthy
SLIPWAY_UID=10001  # the user Slipway runs as in its image (Dockerfile)
LOCK_KIND=""       # flock or mkdir, once held
PROBLEMS="" DONE_PARTS=""  # what a rollback could not do, and what it did
SLIPWAY_CID="" DB_CID="" RUNNING_IMAGE="" OLD_BRANCH="" ORIG_HEAD="" PRE_REV="" BEFORE_STAMP="" EOO="" WAIT_WHY=""

# ------------------------------------------------------------------------------------------ helpers

utc_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { printf '%s %s\n' "$(utc_now)" "$*"; }
short() { printf '%s' "${1:0:12}"; }

valid_sha() { [[ $1 =~ $SHA_RE ]]; }
valid_id() { [[ $1 =~ $ID_RE ]]; }
valid_branch() {
  [[ $1 =~ $BRANCH_RE ]] || return 1
  case $1 in -* | /* | */ | *.lock | *..*) return 1 ;; esac
  return 0
}

# A JSON string, or null when the value is empty. Quotes and backslashes are escaped and control characters
# become spaces, so any value is safe here.
json_str() {
  local s=$1
  [ -n "$s" ] || { printf 'null'; return; }
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=$(printf '%s' "$s" | tr '\000-\037\177' ' ')
  printf '"%s"' "$s"
}

write_status() {
  [ "$STATUS_READY" = 1 ] || return 0
  local tmp="$STATE_DIR/$ID.json.tmp" pid_json=$$ msg=${MESSAGE:0:500}
  {
    printf '{"id":%s,"status":%s,"step":%s,' "$(json_str "$ID")" "$(json_str "$STATUS")" "$(json_str "$STEP")"
    printf '"from":%s,"to":%s,"branch":%s,' "$(json_str "$FROM")" "$(json_str "$TARGET")" "$(json_str "$BRANCH")"
    printf '"started_at":%s,"finished_at":%s,' "$(json_str "$STARTED_AT")" "$(json_str "$FINISHED_AT")"
    printf '"message":%s,"backup":%s,"db_changed":%s,' "$(json_str "$msg")" "$(json_str "$BACKUP")" "$DB_CHANGED"
    printf '"failed_step":%s,' "$(json_str "$FAILED_STEP")"
    printf '"pid":%s,"boot_id":%s,"heartbeat_at":%s}\n' "$pid_json" "$(json_str "$BOOT_ID")" "$(json_str "$(utc_now)")"
  } > "$tmp" 2>/dev/null && mv -f "$tmp" "$STATE_DIR/$ID.json" 2>/dev/null \
    || printf '%s Could not write %s/%s.json.\n' "$(utc_now)" "$STATE_DIR" "$ID"
}

set_step() { # set_step <name> <what it does>
  STEP=$1
  printf '==> %s: %s\n' "$1" "$2"
  write_status
}

finish() { # finish <status> <message> <exit code>
  STATUS=$1 MESSAGE=$2 FINISHED_AT=$(utc_now)
  write_status
  log "Finished: $1. $2"
  # Called from the EXIT trap (a rollback after a signal), exit doesn't run the trap again: tidy up here.
  if [ "$IN_TRAP" = 1 ]; then rm -f "$STATE_DIR/$ID.json.tmp" 2>/dev/null; release_lock; fi
  exit "$3"
}

fail() { finish failed "$1" 1; }

backup_hint() { if [ -n "$BACKUP" ]; then printf 'The backup is %s. ' "$BACKUP"; fi; }

on_exit() {
  local rc=$?
  IN_TRAP=1
  # A trap can run inside a call whose output goes elsewhere (a probe's > /dev/null): back to the log.
  exec 1>&7 2>&8
  if [ "$STATUS" = running ] && [ "$STATUS_READY" = 1 ]; then
    # Something ended the script without a final status: a signal, or a bug.
    if [ "$IN_ROLLBACK" = 1 ]; then
      STATUS=rollback_failed rc=3
      MESSAGE="The upgrade stopped during the rollback. $(backup_hint)Follow the by-hand steps in docs/updates.md."
    elif [ "$HEALTHY" = 1 ]; then
      STATUS=succeeded
      MESSAGE="Slipway now runs $(short "$TARGET") from $BRANCH. The cleanup of older backups and image tags stopped early."
    elif [ "$SWITCHED" = 1 ]; then
      # The new version was started but never passed its health check: put the previous one back.
      log "The upgrade stopped unexpectedly during $STEP, after the new version was started. Rolling back."
      rollback "The upgrade stopped unexpectedly during $STEP." # ends the script
    else
      log "The upgrade stopped unexpectedly during $STEP. Putting things back."
      if undo_before_switch; then
        STATUS=failed
        MESSAGE="The upgrade stopped unexpectedly during $STEP. Nothing was changed."
      else
        STATUS=rollback_failed rc=3
        MESSAGE="The upgrade stopped unexpectedly during $STEP and the previous version could not be put back. $(backup_hint)Follow the by-hand steps in docs/updates.md."
      fi
    fi
    FINISHED_AT=$(utc_now)
    write_status
    log "Finished: $STATUS. $MESSAGE"
  fi
  rm -f "$STATE_DIR/$ID.json.tmp" 2>/dev/null
  release_lock
  exit "$rc"
}

on_signal() { # on_signal <name> <exit code>
  exec 1>&7 2>&8
  log "Stopped by a signal ($1)."
  if [ "$IN_TRAP" = 1 ]; then
    # Stopped again while putting things back: say so, then stop.
    if [ "$STATUS" = running ] && [ "$STATUS_READY" = 1 ]; then
      STATUS=rollback_failed FINISHED_AT=$(utc_now)
      MESSAGE="The upgrade was stopped again while putting the previous version back. $(backup_hint)Follow the by-hand steps in docs/updates.md."
      write_status
      log "Finished: $STATUS. $MESSAGE"
    fi
    rm -f "$STATE_DIR/$ID.json.tmp" 2>/dev/null
    release_lock
    exit 3
  fi
  exit "$2"
}

# ------------------------------------------------------------------------------------------ the lock

# One upgrade at a time on this machine. The lock lives in /tmp (RAM on Unraid, cleared on reboot), the same
# file the service's checks take with flock. The script waits a little for it (a check may be finishing its
# fetch); flock exit 1 then means another holder. Any other failure (flock missing, or no lock support) falls
# back to a directory holding "pid boot_id", taken over when that process is gone, the machine has restarted
# since, or the folder has had no owner file for STALE_LOCK_AGE seconds (its holder was killed right after
# making it).
take_lock() {
  if command -v flock >/dev/null 2>&1 && { exec 9>>"$LOCK"; } 2>/dev/null; then
    flock -w "$LOCK_WAIT" 9
    local rc=$?
    if [ "$rc" = 0 ]; then LOCK_KIND=flock; return 0; fi
    if [ "$rc" = 1 ]; then return 75; fi
    exec 9>&-
    log "flock failed (exit $rc). Using a lock folder instead."
  fi
  local dir="$LOCK.d" owner pid boot age aside
  if mkdir "$dir" 2>/dev/null; then
    printf '%s %s\n' "$$" "$BOOT_ID" > "$dir/owner"
    LOCK_KIND=mkdir
    return 0
  fi
  owner=$(cat "$dir/owner" 2>/dev/null) || owner=""
  if [ -z "$owner" ]; then
    age=$(path_age "$dir")
    # Young: its holder may still be writing the owner file.
    [[ $age =~ $NUM_RE ]] && [ "$age" -ge "$STALE_LOCK_AGE" ] || return 75
    log "Taking over a stale lock (its folder has had no owner for $age seconds)."
  else
    read -r pid boot <<< "$owner"
    if [[ ${pid:-} =~ $NUM_RE ]] && kill -0 "$pid" 2>/dev/null && [ "${boot:-}" = "$BOOT_ID" ]; then
      return 75
    fi
    log "Taking over a stale lock (pid ${pid:-unknown} is gone or the server restarted)."
  fi
  # Rename it out of the way (atomic: only one taker wins), then make a fresh one.
  aside="$dir.stale.$$"
  mv "$dir" "$aside" 2>/dev/null || return 75
  if [ "$(cat "$aside/owner" 2>/dev/null)" != "$owner" ]; then
    # Another run took it over between the read and the rename: put its lock back and step aside.
    if mkdir "$dir" 2>/dev/null; then cat "$aside/owner" > "$dir/owner" 2>/dev/null; fi
    rm -rf "$aside"
    return 75
  fi
  rm -rf "$aside"
  mkdir "$dir" 2>/dev/null || return 75
  printf '%s %s\n' "$$" "$BOOT_ID" > "$dir/owner"
  LOCK_KIND=mkdir
  return 0
}

release_lock() {
  if [ "$LOCK_KIND" = mkdir ]; then rm -rf "$LOCK.d"; fi
  LOCK_KIND=""
}

# ------------------------------------------------------------------------------------------ time limits

# coreutils (and BSD) timeout, else busybox's without -k, else none: then calls run without a limit.
TIMEOUT_KIND=none
if command -v timeout >/dev/null 2>&1; then
  if timeout -k 5 5 true >/dev/null 2>&1; then TIMEOUT_KIND=kill
  elif timeout 5 true >/dev/null 2>&1; then TIMEOUT_KIND=plain; fi
fi

limit() { # limit <seconds> <command> [args]: the command, stopped after <seconds> (exit 124)
  local secs=$1
  shift
  case $TIMEOUT_KIND in
    kill) timeout -k 10 "$secs" "$@" ;;
    plain) timeout "$secs" "$@" ;;
    *) "$@" ;;
  esac
}

# ------------------------------------------------------------------------------------------ remote reads

db_psql() { limit "$T_QUICK" docker compose exec -T db psql -U slipway -d slipway -Atc "$1" < /dev/null; }

active_deployments() { # prints how many deployments are queued or running; fails when it can't be read
  local n
  n=$(db_psql "SELECT count(*) FROM deployments WHERE status IN ('queued', 'running')") || return 1
  n=${n//$'\r'/}
  [[ $n =~ $NUM_RE ]] || return 1
  printf '%s' "$n"
}

# Slipway refuses new deployments while an upgrade runs, but one may have started just before. Stopping
# Slipway would cut it off half done, so wait for it (up to DEPLOY_WAIT seconds).
wait_for_deployments() {
  local n deadline said=0
  deadline=$(($(date +%s) + DEPLOY_WAIT))
  while :; do
    n=$(active_deployments) || { WAIT_WHY="Could not read whether a deployment is running."; return 1; }
    [ "$n" = 0 ] && return 0
    if [ "$(date +%s)" -ge "$deadline" ]; then
      WAIT_WHY="A deployment is still running after $DEPLOY_WAIT seconds. Try again when it finishes."
      return 1
    fi
    [ "$said" = 1 ] || log "Waiting for $n deployment(s) to end before stopping Slipway."
    said=1
    write_status # heartbeat
    sleep "$POLL"
  done
}

db_revision() { # prints the alembic revision; fails when it can't be read
  local rev
  rev=$(db_psql 'SELECT version_num FROM alembic_version') || return 1
  rev=${rev//$'\r'/}
  [[ $rev =~ $REV_RE ]] || return 1
  printf '%s' "$rev"
}

# The db container must have been created from the compose config as it is now. Otherwise `up` would
# recreate it (another data folder, password or image): that is install.sh's job, by hand.
db_config_hash() {
  limit "$T_QUICK" docker compose config --hash db 2>/dev/null < /dev/null | awk '$1 == "db" { print $2; exit }'
}
db_running_hash() {
  limit "$T_QUICK" docker inspect -f '{{index .Config.Labels "com.docker.compose.config-hash"}}' "$DB_CID" \
    2>/dev/null < /dev/null | tr -d '\r'
}
db_hash_matches() {
  local want got
  want=$(db_config_hash)
  got=$(db_running_hash)
  if [ -z "$want" ] || [ -z "$got" ]; then log "Could not read the db container's config hash."; return 1; fi
  [ "$want" = "$got" ] || { log "db config hash is $want but the running db container has $got."; return 1; }
}

free_kb() { # free_kb <path> -> "<available KB> <mount point>"
  df -Pk -- "$1" 2>/dev/null | awk 'NR == 2 { a = $4; $1 = $2 = $3 = $4 = $5 = ""; sub(/^ +/, ""); print a " " $0 }'
}

STAT_GNU=0
stat -c %a / >/dev/null 2>&1 && STAT_GNU=1
mode_uid() { # mode_uid <file> -> "<octal mode> <uid>"
  if [ "$STAT_GNU" = 1 ]; then stat -c '%a %u' -- "$1" 2>/dev/null; else stat -f '%Lp %u' -- "$1" 2>/dev/null; fi
}
path_age() { # path_age <path> -> seconds since it was last modified
  local m
  if [ "$STAT_GNU" = 1 ]; then m=$(stat -c %Y -- "$1" 2>/dev/null); else m=$(stat -f %m -- "$1" 2>/dev/null); fi
  [[ $m =~ $NUM_RE ]] || return 1
  printf '%s' "$(($(date +%s) - m))"
}

image_stamp() { # image_stamp <image> -> the SLIPWAY_COMMIT it was built with, or nothing
  local stamp
  stamp=$(limit "$T_QUICK" docker image inspect "$1" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null < /dev/null \
    | tr -d '\r' | sed -n 's/^SLIPWAY_COMMIT=//p' | tail -n 1)
  if valid_sha "$stamp"; then printf '%s' "$stamp"; fi
}

git_supports_eoo() { # --end-of-options came in git 2.24
  local major minor
  read -r major minor <<< "$(git --version 2>/dev/null | sed -n 's/^git version \([0-9]*\)\.\([0-9]*\).*/\1 \2/p')"
  [[ ${major:-0} =~ $NUM_RE ]] && [[ ${minor:-0} =~ $NUM_RE ]] || return 1
  [ "${major:-0}" -gt 2 ] || { [ "${major:-0}" -eq 2 ] && [ "${minor:-0}" -ge 24 ]; }
}

# ------------------------------------------------------------------------------------------ putting back

restore_checkout() { # restore_checkout <commit>: back on the branch it was on (or detached) at <commit>
  if [ -n "$OLD_BRANCH" ]; then
    git checkout -q -f -B "$OLD_BRANCH" ${EOO:+"$EOO"} "$1" || return 1
  else
    git checkout -q -f ${EOO:+"$EOO"} "$1" || return 1
  fi
  log "The checkout is back at $(short "$1")."
}

# Undo whatever happened before the switch: the checkout (back where it was, which may not be the running
# commit), the slipway:latest tag and, after the backup step stopped it, the current version. Returns 1 when
# something could not be put back.
undo_before_switch() {
  local ok=0
  if [ "$CHECKED_OUT" = 1 ]; then restore_checkout "$ORIG_HEAD" || { log "Could not restore the checkout."; ok=1; }; fi
  if [ "$TAGGED" = 1 ]; then
    limit "$T_QUICK" docker tag "slipway:before-$ID" slipway:latest < /dev/null \
      || { log "Could not tag slipway:before-$ID as slipway:latest."; ok=1; }
  fi
  if [ "$OLD_STOPPED" = 1 ]; then
    log "Starting the current version again."
    if limit "$T_UP" docker compose up -d --no-build --no-deps slipway < /dev/null && health "$BEFORE_STAMP" ""; then
      OLD_STOPPED=0
    else
      log "The current version did not start again."
      container_output "current version"
      ok=1
    fi
  fi
  return "$ok"
}

# A failure before the switch: put things back, then end as failed when that worked, else rollback_failed.
undo_and_fail() { # undo_and_fail <why>
  log "$1"
  if undo_before_switch; then fail "$1"; fi
  finish rollback_failed "$1 The install folder could not be put back. $(backup_hint)Follow the by-hand steps in docs/updates.md." 3
}

# ------------------------------------------------------------------------------------------ health

# health <expected commit or empty> <container id it must not be> -> 0 once healthy.
# Healthy: the container answers its health URL from inside, carries the expected stamp, is running and has
# not restarted, three checks in a row spanning at least STEADY seconds. Gives up after HEALTH_LIMIT seconds,
# or as soon as the container has restarted CRASH_LIMIT times (it crashes on start: waiting won't help; then
# CRASHED=1). Docker reports a container that keeps restarting as running, so Restarting and the restart
# count are what tell a crash loop from a slow start.
# Each probe is limited to PROBE_TIMEOUT seconds; one that hangs counts as a failed check.
health() {
  local want=$1 not_cid=$2 deadline now streak=0 streak_start=0 base_cid="" base_restarts="" cid st running
  local restarting restarts first_cid="" first_restarts=0 crashes=0 why last_why="" got
  CRASHED=0
  deadline=$(($(date +%s) + HEALTH_LIMIT))
  while :; do
    write_status # heartbeat
    why=""
    cid=$(limit "$PROBE_TIMEOUT" docker compose ps -q slipway 2> /dev/null < /dev/null | head -n 1 | tr -d '\r')
    if ! [[ $cid =~ $CID_RE ]]; then
      why="no slipway container yet"
    elif [ -n "$not_cid" ] && [ "$cid" = "$not_cid" ]; then
      why="the old container is still the one running"
    else
      st=$(limit "$PROBE_TIMEOUT" docker inspect -f '{{.State.Running}} {{.State.Restarting}} {{.RestartCount}}' \
        "$cid" 2> /dev/null < /dev/null | tr -d '\r')
      read -r running restarting restarts <<< "$st"
      [[ ${restarts:-} =~ $NUM_RE ]] || restarts=""
      if [ "$cid" != "$base_cid" ] || [ "$restarts" != "$base_restarts" ]; then
        streak=0 base_cid=$cid base_restarts=$restarts
      fi
      if [ -n "$restarts" ]; then
        if [ "$cid" != "$first_cid" ]; then first_cid=$cid first_restarts=$restarts; fi
        crashes=$((restarts - first_restarts))
      fi
      if [ "$restarting" = true ] || [ "$crashes" -gt 0 ]; then
        why="the container keeps stopping and Docker keeps restarting it"
      elif [ "$running" != true ]; then
        why="the container isn't running"
      elif ! limit "$PROBE_TIMEOUT" docker compose exec -T slipway python -c \
        "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health',timeout=4)" \
        < /dev/null > /dev/null 2>&1; then
        why="the health URL doesn't answer yet"
      elif [ -n "$want" ]; then
        got=$(limit "$PROBE_TIMEOUT" docker compose exec -T slipway printenv SLIPWAY_COMMIT < /dev/null 2> /dev/null | tr -d '\r')
        [ "$got" = "$want" ] || why="the container runs ${got:-an unstamped image}, not $want"
      fi
    fi
    now=$(date +%s)
    if [ -z "$why" ]; then
      streak=$((streak + 1))
      [ "$streak" = 1 ] && streak_start=$now
      if [ "$streak" -ge 3 ] && [ $((now - streak_start)) -ge "$STEADY" ]; then
        log "Healthy: $cid passed $streak checks in a row."
        return 0
      fi
      why="passing ($streak)"
    else
      streak=0
    fi
    [ "$why" = "$last_why" ] || log "Health: $why."
    last_why=$why
    if [ "$crashes" -ge "$CRASH_LIMIT" ]; then
      log "Gave up: the container restarted $crashes times, so it stops by itself soon after it starts."
      CRASHED=1
      return 1
    fi
    if [ "$now" -gt "$deadline" ]; then
      log "Gave up after $HEALTH_LIMIT seconds."
      return 1
    fi
    sleep "$POLL"
  done
}

# container_output <whose>: copy the last LOG_LINES lines the slipway container printed into this log, so a
# version that crashes on start says why. The rollback recreates the container, which loses its output.
# Control characters other than tabs are dropped. Best effort: no output is only noted.
container_output() {
  local out
  out=$(limit "$T_QUICK" docker compose logs --no-color --no-log-prefix --tail "$LOG_LINES" slipway < /dev/null 2>&1 \
    | tr -d '\000-\010\013-\037\177')
  if [ -z "$out" ]; then
    log "The $1 printed nothing (or its output could not be read)."
    return 0
  fi
  log "The last lines the $1 printed:"
  printf '%s\n' "$out" | sed 's/^/    | /'
}

# The folder docker-compose.yml mounts at /var/lib/slipway, for stored snapshots: <SLIPWAY_DATA_DIR from .env,
# default ./data>/files. install.sh makes it for Slipway (uid 10001, mode 700); an install made before that
# has none, and Docker would make it for root, which Slipway can't write. Like install.sh: chown it here,
# else from a throwaway container of the database image. Best effort: Slipway starts without it (only stored
# snapshots need it), so a failure is logged with the command to run by hand.
prepare_files() {
  grep -q ':/var/lib/slipway' docker-compose.yml 2> /dev/null || return 0
  local dir mu
  dir=$(sed -n 's/^SLIPWAY_DATA_DIR=//p' .env 2> /dev/null | tail -n 1 | tr -d '\r')
  dir=${dir#\"} dir=${dir%\"} dir=${dir#\'} dir=${dir%\'}
  dir=${dir:-./data}
  dir="${dir%/}/files"
  case $dir in /*) ;; *) dir="$PWD/${dir#./}" ;; esac
  case $dir in
    *:* | *,* | *$'\n'*) log "Skipped making the snapshot folder: its path ($dir) has a character Docker can't mount."; return 0 ;;
  esac
  mu=$(mode_uid "$dir")
  [ "$mu" = "700 $SLIPWAY_UID" ] && return 0
  if [ ! -d "$dir" ]; then
    if ! mkdir -p -- "$dir" 2> /dev/null; then
      log "Could not make $dir for stored snapshots. Run: sudo mkdir -p $dir && sudo chown $SLIPWAY_UID:$SLIPWAY_UID $dir && sudo chmod 700 $dir"
      return 0
    fi
    log "Made $dir for stored snapshots."
  fi
  if { chown "$SLIPWAY_UID:$SLIPWAY_UID" "$dir" && chmod 700 "$dir"; } 2> /dev/null \
    || limit "$T_UP" docker compose run --rm --no-deps --user root -v "$dir:/files" --entrypoint sh db \
      -c "chown $SLIPWAY_UID:$SLIPWAY_UID /files && chmod 700 /files" < /dev/null > /dev/null 2>&1; then
    log "Gave $dir to Slipway (uid $SLIPWAY_UID, mode 700)."
  else
    log "Could not give $dir to Slipway, so stored snapshots won't work. Run: sudo chown $SLIPWAY_UID:$SLIPWAY_UID $dir && sudo chmod 700 $dir"
  fi
}

# ------------------------------------------------------------------------------------------ steps

preflight() {
  set_step preflight "Checks the tools, the install folder, the containers and free space."
  command -v git >/dev/null 2>&1 || fail "git is not installed."
  limit "$T_QUICK" docker compose version >/dev/null 2>&1 < /dev/null || fail "Docker Compose v2 is not available."
  [ -f docker-compose.yml ] && [ -d .git ] || fail "This folder isn't a Slipway install (no docker-compose.yml or .git)."

  local dirty
  dirty=$(git status --porcelain --untracked-files=no) || fail "git status failed in the install folder."
  if [ -n "$dirty" ]; then
    log "Local changes:"
    printf '%s\n' "$dirty"
    fail "The install folder has local changes to tracked files. Move them to docker-compose.override.yml (Docker Compose reads it on its own) or undo them, then try again."
  fi

  local services
  services=$(limit "$T_QUICK" docker compose ps --status running --services < /dev/null | tr -d '\r') || fail "docker compose ps failed."
  grep -qx slipway <<< "$services" && grep -qx db <<< "$services" \
    || fail "The slipway and db containers must both be running."
  SLIPWAY_CID=$(limit "$T_QUICK" docker compose ps -q slipway < /dev/null | head -n 1 | tr -d '\r')
  DB_CID=$(limit "$T_QUICK" docker compose ps -q db < /dev/null | head -n 1 | tr -d '\r')
  [[ $SLIPWAY_CID =~ $CID_RE ]] && [[ $DB_CID =~ $CID_RE ]] || fail "Could not find the slipway and db containers."
  RUNNING_IMAGE=$(limit "$T_QUICK" docker inspect -f '{{.Image}}' "$SLIPWAY_CID" < /dev/null | tr -d '\r')
  [[ $RUNNING_IMAGE =~ $IMAGE_RE ]] || fail "Could not read the image of the running slipway container."
  log "Running: container $SLIPWAY_CID, image $RUNNING_IMAGE."

  limit "$T_QUICK" docker compose config --hash db >/dev/null 2>&1 < /dev/null \
    || fail "docker compose config failed. Check .env and docker-compose.yml."
  db_hash_matches || fail "The database settings changed since it started (.env or docker-compose.yml). Run install.sh by hand."

  local head
  head=$(git rev-parse --verify -q HEAD) || fail "Could not read the checkout's commit."
  valid_sha "$head" || fail "Could not read the checkout's commit."
  ORIG_HEAD=$head # a failure before the switch puts the checkout back here
  if [ -n "$FROM_ARG" ]; then
    if [ "$head" != "$FROM_ARG" ]; then
      log "The checkout is at $head but Slipway runs $FROM_ARG. Using $FROM_ARG as the starting point."
    fi
  fi
  valid_sha "$FROM" || fail "Could not tell which commit Slipway runs."
  OLD_BRANCH=$(git symbolic-ref --short -q HEAD) || OLD_BRANCH=""
  log "From $FROM (branch ${OLD_BRANCH:-detached}) to $TARGET on $BRANCH."

  PRE_REV=$(db_revision) || fail "Could not read the database revision."
  log "Database revision: $PRE_REV."
  local db_bytes
  db_bytes=$(db_psql "SELECT pg_database_size('slipway')" | tr -d '\r')
  [[ $db_bytes =~ $NUM_RE ]] || fail "Could not read the database size."

  # Images and build cache live in Docker's root folder (docker.img on Unraid); the backup lives here.
  local root root_free here_free root_kb root_mnt here_kb here_mnt need_root need_here
  root=$(limit "$T_QUICK" docker info -f '{{.DockerRootDir}}' < /dev/null 2>/dev/null | tr -d '\r')
  case $root in /*) ;; *) fail "Could not read Docker's root folder." ;; esac
  root_free=$(free_kb "$root")
  here_free=$(free_kb .)
  read -r root_kb root_mnt <<< "$root_free"
  read -r here_kb here_mnt <<< "$here_free"
  [[ ${root_kb:-} =~ $NUM_RE ]] && [[ ${here_kb:-} =~ $NUM_RE ]] || fail "Could not read free disk space."
  need_root=$((3 * 1024 * 1024))
  need_here=$((2 * db_bytes / 1024 + 100 * 1024))
  if [ "$root_mnt" = "$here_mnt" ]; then
    need_root=$((need_root + need_here))
  elif [ "$here_kb" -lt "$need_here" ]; then
    fail "Not enough free space on $here_mnt for the backup: $((here_kb / 1024)) MB free, $((need_here / 1024)) MB needed."
  fi
  [ "$root_kb" -ge "$need_root" ] \
    || fail "Not enough free space on $root_mnt (Docker's images): $((root_kb / 1024)) MB free, $((need_root / 1024)) MB needed."
  log "Free space: $((root_kb / 1024)) MB on $root_mnt, $((here_kb / 1024)) MB on $here_mnt."
}

fetch() {
  set_step fetch "Fetches $BRANCH from origin."
  if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = true ]; then
    log "The checkout is shallow. Fetching the full history once."
    limit "$T_FETCH" git fetch --quiet --unshallow origin < /dev/null || log "git fetch --unshallow failed."
    [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" != true ] || fail "Could not fetch the full history from origin."
  fi
  limit "$T_FETCH" git fetch --quiet origin "+refs/heads/$BRANCH:refs/remotes/origin/$BRANCH" < /dev/null \
    || fail "Could not fetch $BRANCH from origin."
  git cat-file -e ${EOO:+"$EOO"} "$TARGET^{commit}" 2>/dev/null || fail "Commit $(short "$TARGET") isn't on origin."
  git merge-base --is-ancestor ${EOO:+"$EOO"} "$TARGET" "refs/remotes/origin/$BRANCH" \
    || fail "Commit $(short "$TARGET") isn't on $BRANCH."
  git cat-file -e ${EOO:+"$EOO"} "$FROM^{commit}" 2>/dev/null \
    || fail "The running commit $(short "$FROM") isn't in the install folder's history."
  git merge-base --is-ancestor ${EOO:+"$EOO"} "$FROM" "$TARGET" \
    || fail "Commit $(short "$TARGET") doesn't come after the running version $(short "$FROM"). Slipway can't move back or sideways."
}

build() {
  set_step build "Builds the new version while the current one keeps running."
  TAGGED=1
  limit "$T_QUICK" docker tag "$RUNNING_IMAGE" "slipway:before-$ID" < /dev/null || { TAGGED=0; fail "Could not tag the running image."; }
  BEFORE_STAMP=$(image_stamp "slipway:before-$ID")
  log "Tagged the running image as slipway:before-$ID (built from ${BEFORE_STAMP:-an unrecorded commit})."
  CHECKED_OUT=1
  git checkout -q -f -B "$BRANCH" ${EOO:+"$EOO"} "$TARGET" || undo_and_fail "Could not check out $(short "$TARGET")."
  db_hash_matches || undo_and_fail "This version changes the database container. Run install.sh by hand."
  limit "$T_BUILD" env SLIPWAY_COMMIT="$TARGET" SLIPWAY_BRANCH="$BRANCH" SLIPWAY_BUILT_AT="$(utc_now)" \
    docker compose build slipway < /dev/null \
    || undo_and_fail "The new version didn't build. The log has the reason."
  prepare_files
}

backup_failed() {
  log "$1"
  rm -f "$STATE_DIR/$ID-before.dump"
  BACKUP=""
  if undo_before_switch; then fail "$1 The current version is running again."; fi
  finish rollback_failed "$1 The current version did not start again. Follow the by-hand steps in docs/updates.md." 3
}

backup() {
  set_step backup "Stops the current version and backs up the database."
  local dump="$STATE_DIR/$ID-before.dump"
  wait_for_deployments || undo_and_fail "$WAIT_WHY"
  OLD_STOPPED=1
  limit "$T_STOP" docker compose stop -t 30 slipway < /dev/null || backup_failed "Could not stop the current version."
  limit "$T_DB" docker compose exec -T db pg_dump -U slipway -Fc slipway < /dev/null > "$dump" \
    || backup_failed "The database backup failed."
  [ -s "$dump" ] || backup_failed "The database backup is empty."
  limit "$T_DB" docker compose exec -T db pg_restore --list < "$dump" > /dev/null \
    || backup_failed "The database backup can't be read back."
  chmod 600 "$dump"
  BACKUP=$dump
  write_status
  log "Backed up the database to $dump."
}

switch() {
  set_step switch "Starts the new version. Slipway is offline until it is up."
  SWITCHED=1
  limit "$T_UP" docker compose up -d --no-build --no-deps slipway < /dev/null || rollback "The new version didn't start."
}

problem() { log "$1"; PROBLEMS="${PROBLEMS:+$PROBLEMS }$1"; }
did() { DONE_PARTS="${DONE_PARTS:+$DONE_PARTS, }$1"; }

restore_db() { # returns 1 (after saying why with problem) when the backup could not be restored
  local dump="$STATE_DIR/$ID-before.dump" mu rev
  mu=$(mode_uid "$dump")
  if [ "$mu" != "600 $(id -u)" ]; then
    log "The backup's mode and owner are '${mu:-unknown}', not '600 $(id -u)'."
    problem "The backup's permissions changed, so it was not restored; restore it by hand."
    return 1
  fi
  log "Restoring the database from $dump."
  limit "$T_DB" docker compose exec -T db psql -U slipway -d postgres -v ON_ERROR_STOP=1 \
    -c 'DROP DATABASE slipway WITH (FORCE)' -c 'CREATE DATABASE slipway OWNER slipway' < /dev/null \
    || { problem "Could not recreate the database."; return 1; }
  limit "$T_DB" docker compose exec -T db pg_restore -U slipway -d slipway --exit-on-error --single-transaction --no-owner < "$dump" \
    || { problem "Could not restore the backup."; return 1; }
  rev=$(db_revision) || { problem "Could not read the database revision after the restore."; return 1; }
  [ "$rev" = "$PRE_REV" ] || { problem "The restored database is at revision $rev, not $PRE_REV."; return 1; }
  log "The database is back at revision $PRE_REV."
}

# Puts the previous version back, as far as it can: every step that doesn't depend on one that failed is
# still tried (the database is restored only when the new version was stopped; the previous version is
# started only when its image tag and, if needed, the database are back). Without a database change, a
# failed stop doesn't matter: `up` replaces the new container anyway.
rollback() { # rollback <why>
  IN_ROLLBACK=1
  FAILED_STEP=$STEP
  set_step rollback "Puts the previous version back."
  log "$1"
  PROBLEMS="" DONE_PARTS=""
  local stopped=1 tagged=1 db_ok=1 rev
  if limit "$T_STOP" docker compose stop -t 30 slipway < /dev/null; then did "stopped the new version"
  else stopped=0; log "Could not stop the new version."; fi
  if rev=$(db_revision); then
    [ "$rev" = "$PRE_REV" ] || DB_CHANGED=true
    log "Database revision now: $rev."
  else
    log "Could not read the database revision. Restoring the backup to be safe."
    DB_CHANGED=true
  fi
  write_status
  if limit "$T_QUICK" docker tag "slipway:before-$ID" slipway:latest < /dev/null; then did "tagged the previous image"
  else tagged=0; problem "Could not tag the previous image."; fi
  if restore_checkout "$FROM"; then did "restored the checkout"; else problem "Could not restore the checkout."; fi
  if [ "$DB_CHANGED" = true ]; then
    if [ "$stopped" = 0 ]; then
      db_ok=0
      problem "Could not stop the new version, so the database was not restored."
    elif restore_db; then
      did "restored the database"
    else
      db_ok=0
    fi
  fi
  if [ "$tagged" = 1 ] && [ "$db_ok" = 1 ]; then
    if ! limit "$T_UP" docker compose up -d --no-build --no-deps slipway < /dev/null; then
      problem "The previous version didn't start."
    elif ! health "$BEFORE_STAMP" ""; then
      container_output "previous version"
      problem "The previous version didn't pass its health check."
    fi
  else
    problem "The previous version was not started."
  fi
  if [ -n "$PROBLEMS" ]; then
    finish rollback_failed "Rolling back failed: $PROBLEMS Done: ${DONE_PARTS:-nothing}. The backup is $STATE_DIR/$ID-before.dump. Follow the by-hand steps in docs/updates.md." 3
  fi
  if [ "$DB_CHANGED" = true ]; then
    finish rolled_back "$1 The previous version is running again, with the database restored from the backup." 2
  fi
  finish rolled_back "$1 The previous version is running again." 2
}

cleanup() {
  set_step cleanup "Removes older backups and image tags."
  local tag dumps old
  while read -r tag; do
    case $tag in
      "slipway:before-$ID") ;;
      slipway:before-*) limit "$T_QUICK" docker rmi "$tag" < /dev/null > /dev/null || log "Could not remove $tag." ;;
    esac
  done < <(limit "$T_QUICK" docker image ls --format '{{.Repository}}:{{.Tag}}' slipway < /dev/null 2>/dev/null | tr -d '\r')
  dumps=$(cd "$STATE_DIR" && ls -1 | grep -E '^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}-before\.dump$' | sort -r)
  while read -r old; do
    [ -n "$old" ] || continue
    if rm -f "$STATE_DIR/$old"; then log "Removed the older backup $old."; else log "Could not remove $old."; fi
  done <<< "$(printf '%s\n' "$dumps" | tail -n +4)"
  finish succeeded "Slipway now runs $(short "$TARGET") from $BRANCH." 0
}

# ------------------------------------------------------------------------------------------ main

bad_args() {
  printf 'upgrade.sh: %s\n' "$1" >&2
  if valid_id "$ID" && [ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ]; then
    valid_sha "$TARGET" || TARGET=""
    valid_branch "$BRANCH" || BRANCH=""
    STATUS_READY=1
    finish failed "The upgrade was started with a bad argument: $1" 64
  fi
  exit 64
}

main() {
  while [ $# -gt 0 ]; do
    case $1 in
      --id | --target | --branch | --from)
        [ $# -ge 2 ] || bad_args "$1 needs a value."
        case $1 in
          --id) ID=$2 ;;
          --target) TARGET=$2 ;;
          --branch) BRANCH=$2 ;;
          --from) FROM_ARG=$2 ;;
        esac
        shift 2
        ;;
      *) bad_args "unknown argument." ;;
    esac
  done
  valid_id "$ID" || bad_args "the id must look like 20260101-120000-abcdef."
  valid_sha "$TARGET" || bad_args "the target must be a full 40-character commit sha."
  valid_branch "$BRANCH" || bad_args "the branch name isn't allowed."
  [ -z "$FROM_ARG" ] || valid_sha "$FROM_ARG" || bad_args "--from must be a full 40-character commit sha."

  if [ -L "$STATE_DIR" ]; then printf 'upgrade.sh: %s is a symlink.\n' "$STATE_DIR" >&2; exit 1; fi
  mkdir -p "$STATE_DIR" || exit 1
  # The backup holds the whole database: keep everything here private, whatever made it.
  local f
  chmod 700 "$STATE_DIR"
  for f in "$STATE_DIR"/* "$STATE_DIR"/.[!.]*; do
    if [ -f "$f" ] && [ ! -L "$f" ]; then chmod 600 "$f"; fi
  done
  log "Set $STATE_DIR to mode 700 and its files to mode 600."

  STARTED_AT=$(utc_now)
  BOOT_ID=$(tr -cd '0-9a-f-' 2>/dev/null < "$BOOT_ID_FILE") || BOOT_ID=""
  git_supports_eoo && EOO=--end-of-options
  if [ -n "$FROM_ARG" ]; then
    FROM=$FROM_ARG
  else
    FROM=$(git rev-parse --verify -q HEAD 2>/dev/null) || FROM=""
    valid_sha "$FROM" || FROM=""
  fi
  STATUS_READY=1
  exec 7>&1 8>&2 # the log, for the traps
  trap on_exit EXIT
  trap 'on_signal TERM 143' TERM
  trap 'on_signal INT 130' INT
  trap 'on_signal HUP 129' HUP
  log "Upgrade $ID: pid $$, boot id ${BOOT_ID:-unknown}."
  [ "$TIMEOUT_KIND" != none ] || log "timeout isn't installed: docker and git calls run without a time limit."
  write_status

  local rc=0
  take_lock || rc=$?
  if [ "$rc" != 0 ]; then finish failed "Another upgrade is running." 75; fi

  preflight
  fetch
  build
  backup
  switch
  set_step health "Waits until the new version answers, steadily, from inside its container."
  if ! health "$TARGET" "$SLIPWAY_CID"; then
    container_output "new version"
    if [ "$CRASHED" = 1 ]; then
      rollback "The new version kept crashing on start. Its last output is in the log."
    fi
    rollback "The new version didn't pass its health check. Its last output is in the log."
  fi
  HEALTHY=1
  cleanup
}

main "$@"
