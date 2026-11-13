#!/usr/bin/env bash
# Slipway server installer.
#
#   curl -fsSL https://raw.githubusercontent.com/encondata/slipway/main/install.sh | bash
#
# Clones or updates the repository, writes .env with fresh secrets and an administrator
# account on first run, builds the image and brings the stack up. Safe to run again: it
# never overwrites an existing .env, and it never invents a second administrator.
#
# Slipway serves plain HTTP on port 8000 and expects a reverse proxy in front of it for TLS.
set -euo pipefail

# Under curl | bash, bash reads this script from standard input while it runs, so a command
# that also reads standard input would swallow the rest of it. Everything is in main(), which
# bash reads in full before running any of it.
main() {

REPO="${SLIPWAY_REPO:-https://github.com/encondata/slipway.git}"
BRANCH="${SLIPWAY_BRANCH:-main}"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
die() { printf '\n\033[31m%s\033[0m\n' "$*" >&2; exit 1; }
# Ask on the terminal even under curl | bash (which has the script, not the keyboard, on
# standard input). With no terminal at all the suggestion is used.
ask() { # ask "Question" "suggestion" -> answer on stdout
  local answer=""
  if { exec 3</dev/tty; } 2>/dev/null; then
    printf '\n%s [%s] ' "$1" "$2" > /dev/tty
    read -r answer <&3 || answer=""
    exec 3<&-
  fi
  printf '%s' "${answer:-$2}"
}

UNRAID=no; [ -d /mnt/user ] && [ -f /etc/unraid-version ] && UNRAID=yes
if ! command -v git >/dev/null 2>&1; then
  [ "$UNRAID" = yes ] && die "git is not installed. On Unraid, add it with the NerdTools or un-get plugin (Apps tab), then run this again."
  die "git is not installed."
fi
command -v curl >/dev/null 2>&1 || die "curl is not installed."
command -v docker >/dev/null 2>&1 || die "docker is not installed. See https://docs.docker.com/get-docker/"
if ! docker compose version >/dev/null 2>&1; then
  [ "$UNRAID" = yes ] && die "This needs Docker Compose v2. On Unraid, install the Docker Compose Manager plugin (Apps tab), then run this again."
  die "This needs Docker Compose v2 (the 'docker compose' subcommand)."
fi
docker info >/dev/null 2>&1 || die "Docker is installed but not running. Start it and try again."

# Where it goes. Suggested: where it runs now, so an update is just Enter; otherwise the
# array on Unraid, or the home directory. SLIPWAY_DIR skips the question.
RUNNING_WD="$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.project.working_dir" }}' \
  slipway-slipway-1 2>/dev/null || true)"
if [ -n "$RUNNING_WD" ]; then DEFAULT_DIR="$RUNNING_WD"
elif [ -d /mnt/user ]; then DEFAULT_DIR=/mnt/user/slipway
else DEFAULT_DIR="$HOME/slipway"; fi
DIR="${SLIPWAY_DIR:-}"
[ -n "$DIR" ] || DIR="$(ask "Install Slipway where?" "$DEFAULT_DIR")"
case "$DIR" in "~"*) DIR="$HOME${DIR#\~}" ;; esac
DIR="${DIR%/}"
case "$DIR" in /*) ;; *) die "Please give a full path, starting with /." ;; esac
if [ -n "$RUNNING_WD" ] && [ "$DIR" != "$RUNNING_WD" ]; then
  die "Slipway is already running from $RUNNING_WD. Run this again and keep that folder, or stop it first:
  docker compose -f $RUNNING_WD/docker-compose.yml down"
fi
# Somewhere with files in it that are not Slipway would make git refuse to clone.
if [ -d "$DIR" ] && [ ! -d "$DIR/.git" ] && [ -n "$(ls -A "$DIR" 2>/dev/null)" ]; then
  die "$DIR already has other files in it. Choose an empty or new folder."
fi

# When something will not start: which containers are up, and the last words of each, so
# the reason is on screen rather than behind another command.
report() {
  printf '\n\033[1mContainers:\033[0m\n' >&2
  docker compose ps -a >&2 || true
  for svc in db slipway; do
    printf '\n\033[1mLast lines from %s:\033[0m\n' "$svc" >&2
    docker compose logs --no-color --tail 25 "$svc" >&2 2>&1 || true
  done
}

# The compose file lives in the repository, so the code has to come first.
if [ -d "$DIR/.git" ]; then
  say "Updating $DIR"
  # The clone tracks only the branch it was made from, so name where the fetched branch goes:
  # then SLIPWAY_BRANCH can switch an existing install to another branch (and back).
  git -C "$DIR" fetch --depth 1 origin "+refs/heads/$BRANCH:refs/remotes/origin/$BRANCH" \
    || die "Could not fetch branch '$BRANCH' from $(git -C "$DIR" remote get-url origin)."
  git -C "$DIR" checkout -q -f -B "$BRANCH" "origin/$BRANCH"
else
  say "Cloning into $DIR"
  git clone --depth 1 --branch "$BRANCH" "$REPO" "$DIR"
fi

cd "$DIR"

# A little randomness, from openssl when it is there and /dev/urandom when it is not.
rand_hex() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex "$1"
  else head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; fi
}
# A Fernet key: 32 random bytes, URL-safe base64.
fernet_key() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -base64 32
  else head -c 32 /dev/urandom | base64; fi | tr -d '\n' | tr '+/' '-_'
}

if [ ! -f .env ]; then
  PORT="${SLIPWAY_PORT:-8000}"
  URL="${SLIPWAY_BASE_URL:-}"
  [ -n "$URL" ] || URL="$(ask "Public address people will use (your reverse proxy's https:// URL)?" \
    "http://localhost:$PORT")"
  URL="${URL%/}"
  case "$URL" in http://*|https://*) ;; *) die "The address must start with http:// or https://." ;; esac

  say "Generating secrets and an administrator password"
  {
    printf '# Slipway settings, written by install.sh. See .env.example for every option.\n'
    printf 'SLIPWAY_ENV=production\n'
    printf '# The address people use. GitHub sends sign-ins back to <this>/auth/github/callback,\n'
    printf '# and an https:// address turns on secure cookies.\n'
    printf 'SLIPWAY_BASE_URL=%s\n' "$URL"
    printf '# Port on this machine for the reverse proxy to forward to.\n'
    printf 'SLIPWAY_PORT=%s\n\n' "$PORT"
    printf '# Back these up: losing SLIPWAY_ENCRYPTION_KEY makes stored SSH keys and secrets unreadable.\n'
    printf 'SLIPWAY_SECRET_KEY=%s\n' "$(rand_hex 32)"
    printf 'SLIPWAY_ENCRYPTION_KEY=%s\n' "$(fernet_key)"
    printf 'POSTGRES_PASSWORD=%s\n\n' "$(rand_hex 24)"
    printf '# The first administrator. Used only when the database has no accounts yet;\n'
    printf '# after that it is ignored, and the password here is just a record of what\n'
    printf '# was set. Change the password once you have signed in.\n'
    printf 'SLIPWAY_ADMIN_EMAIL=%s\n' "${SLIPWAY_ADMIN_EMAIL:-admin@slipway.local}"
    printf 'SLIPWAY_ADMIN_PASSWORD=%s\n\n' "$(rand_hex 12)"
    printf '# GitHub sign-in and repositories. Create an OAuth app at https://github.com/settings/developers\n'
    printf '# with callback URL %s/auth/github/callback, fill these in and run install.sh again.\n' "$URL"
    printf 'SLIPWAY_GITHUB_CLIENT_ID=\n'
    printf 'SLIPWAY_GITHUB_CLIENT_SECRET=\n\n'
    printf '# Behind a reverse proxy, set this to the address the proxy connects from (as seen inside the\n'
    printf '# container) so rate limits see real client addresses. Never use *.\n'
    printf '# SLIPWAY_FORWARDED_ALLOW_IPS=172.18.0.1\n'
  } > .env
  chmod 600 .env
fi

say "Pulling images"
docker compose pull db

say "Building and starting"
if ! docker compose up -d --build; then
  report
  die "Slipway could not be started; the reason is above."
fi

env_value() { sed -n "s/^$1=//p" .env | tail -1; }
ADMIN_EMAIL="$(env_value SLIPWAY_ADMIN_EMAIL)"
ADMIN_PASSWORD="$(env_value SLIPWAY_ADMIN_PASSWORD)"
URL="$(env_value SLIPWAY_BASE_URL)"
PORT="$(env_value SLIPWAY_PORT)"; PORT="${PORT:-8000}"
BASE="http://127.0.0.1:$PORT"

printf '\nWaiting for the server'
UP=no
for _ in $(seq 1 90); do
  if curl -fsS "$BASE/api/v1/health" >/dev/null 2>&1; then UP=yes; break; fi
  printf '.'; sleep 2
done
printf '\n'
if [ "$UP" != yes ]; then
  report
  die "The server did not answer on $BASE within three minutes; the reason is above. Once it is fixed, run this again: your data is kept."
fi

# Rather than assume the account was created, try it. A 200 means these credentials are
# live and worth printing; anything else means an administrator already existed with a
# different password, and printing this one would be a lie.
ADMIN_WORKS=no
if [ -n "$ADMIN_EMAIL" ] && [ -n "$ADMIN_PASSWORD" ]; then
  CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' \
    --data "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" \
    "$BASE/api/v1/auth/login" 2>/dev/null || true)"
  [ "$CODE" = "200" ] && ADMIN_WORKS=yes
fi

# What the database holds, so an update can be seen to have kept everything.
HELD="$(docker compose exec -T db psql -U slipway -d slipway -Atc \
  "SELECT (SELECT count(*) FROM hosts) || ' hosts, ' || (SELECT count(*) FROM instances) || ' instances, ' ||
          (SELECT count(*) FROM users) || ' accounts'" </dev/null 2>/dev/null || true)"
DATA_DIR="$(env_value SLIPWAY_DATA_DIR)"; DATA_DIR="${DATA_DIR:-$DIR/data}"
GITHUB="not set up yet (see the GitHub lines in $DIR/.env)"
[ -n "$(env_value SLIPWAY_GITHUB_CLIENT_ID)" ] && GITHUB="configured"

say "Slipway is up."
cat <<SUMMARY

  Listening on      0.0.0.0:$PORT  (plain HTTP on every interface, for your reverse proxy)
  Public address    $URL

  Installed in      $DIR
  Data in           $DATA_DIR
  Holding           ${HELD:-(could not read the database)}
  GitHub sign-in    $GITHUB
SUMMARY

if [ "$ADMIN_WORKS" = yes ]; then
  cat <<ADMIN

Sign in at $URL/login with

  Email       $ADMIN_EMAIL
  Password    $ADMIN_PASSWORD

This is also kept in $DIR/.env. Change it under Settings -> Profile.
ADMIN
else
  cat <<ADMIN

An administrator account already exists, so no new one was made and the
password in .env is not it. If nobody knows it any more:

  docker compose -f $DIR/docker-compose.yml exec slipway \\
    slipway create-admin you@example.com --reset-password

which asks for a new password for that address.
ADMIN
fi

cat <<TAIL

  Update   run this installer again
  Logs     docker compose -f $DIR/docker-compose.yml logs -f
  Stop     docker compose -f $DIR/docker-compose.yml down
TAIL
}

main "$@"
