<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/slipway-logo-dark.svg">
    <img src="docs/brand/slipway-logo.svg" alt="Slipway" width="320">
  </picture>
</h1>

**Deploy. Run. Observe.** Slipway lists your GitHub repositories and deploys any of them as Docker
containers on your own Linux hosts over SSH, with user accounts, roles and an audit trail.
Mobile/web analytics and centralized logging are scaffolded for the next phase.

Stack: **FastAPI** · **PostgreSQL** (SQLAlchemy 2 async + Alembic) · server-rendered Jinja UI with
vanilla JS (no Node build) · **asyncssh** · shipped as a **Docker** image.

---

## What works today

| Area | Details |
|---|---|
| Accounts | Email/password (Argon2), GitHub OAuth sign-in, link/unlink GitHub, server-side sessions, CSRF protection, login and sign-up rate limiting, personal API tokens (`Authorization: Bearer slipway_pat_…`) that admins can list and revoke |
| Permissions | Role-based: built-in `admin`, `maintainer`, `developer`, `viewer` + custom roles; users can hold several roles; no privilege escalation (you can only grant, remove or manage what you hold: `users:write` only reaches users whose every permission you also have); last-admin protection; the UI only shows what your roles allow |
| Repositories | Sync from GitHub (owner, collaborator, org repos), detect `Dockerfile` / compose file, README preview, branch picker. Repositories are addressed by their GitHub id, so renames and transfers are followed and a repository re-created under an old name is never deployed |
| Hosts | Add Linux/Docker hosts; Slipway generates an ed25519 key (or use your own key / password); SSH host key pinned on first check (TOFU) and enforced afterwards; health: CPU, RAM, Docker version, containers; background polling (each host checked independently); list containers Slipway did not deploy and claim them as instances |
| Instances | Repo + branch + host + Dockerfile, docker compose *or* an app described by its `slipway.yml`; encrypted env vars, port and volume mappings; deploy, start/stop/restart, live `docker ps`, container logs, destroy |
| Deployments | Source tarball fetched by Slipway and uploaded over SFTP (your GitHub token never touches the host), build output streamed live into the UI, a fresh release directory per deployment with `current` switched only after a successful build, old releases plus superseded images pruned, build logs capped at about 1 MB (start and end kept) |
| Environments | An app from one branch in one slot or in Blue/Green slots that share a data server, on your SSH hosts: deploys go to the idle slot, Activate moves the names in Switchyard after a smoke test and puts them back if a check fails, Switch back, Discard, Cloudflare DNS records ([docs/environments.md](docs/environments.md)) |
| DigitalOcean | An environment's slots on droplets Slipway makes, with managed PostgreSQL, a Spaces bucket, a load balancer with Let's Encrypt certificates and a cloud firewall; a confirmed monthly cost, production safeguards, and backups kept on the Slipway server ([docs/digitalocean.md](docs/digitalocean.md)) |
| VMs | An environment's slots and data server on VMs Slipway makes on Proxmox (Terraform) or standalone ESXi (pyvmomi), with static addresses, resizes at the next deploy, VM snapshots and revert ([docs/machines.md](docs/machines.md)) |
| Audit | Sign-ins, failed logins and password checks, user/role/token/host/instance/deploy actions with actor and IP |
| UI | Light and dark themes from your mockups and asset pack, responsive down to phone width |

## Install on a server

On a Linux machine with Docker and Compose v2:

```bash
curl -fsSL https://raw.githubusercontent.com/encondata/slipway/main/install.sh | bash
```

It asks where to install (default `~/slipway`, or `/mnt/user/slipway` on Unraid) and the address people
will use, clones the repository, writes `.env` with fresh secrets and an administrator account, builds the
image and starts Slipway with PostgreSQL. The database lives in `data/postgres` inside the install folder and
stored snapshots in `data/files` (set `SLIPWAY_DATA_DIR` in `.env` to move both). Run the same command again to
update: it keeps `.env` and the data, and only prints the admin password while it still works. `SLIPWAY_DIR`,
`SLIPWAY_BASE_URL`, `SLIPWAY_PORT` and `SLIPWAY_ADMIN_EMAIL` answer the questions up front; `SLIPWAY_REPO` and
`SLIPWAY_BRANCH` pick another source. Slipway serves plain HTTP on port 8000 for a TLS reverse proxy.
GitHub sign-in needs an OAuth app: the installer's `.env` says where to put its ID and secret.

## Quick start (Docker, by hand)

```bash
cp .env.example .env
docker compose run --rm --no-deps -e SLIPWAY_SKIP_MIGRATIONS=1 slipway slipway generate-secrets   # paste all three values into .env
# edit .env: SLIPWAY_BASE_URL, SLIPWAY_ADMIN_EMAIL/PASSWORD, GitHub OAuth app
mkdir -p data/files && sudo chown 10001:10001 data/files && sudo chmod 700 data/files   # stored snapshots
docker compose up -d --build
```

Open `SLIPWAY_BASE_URL` and sign in. Migrations run automatically on container start.
`POSTGRES_PASSWORD` may contain any character: compose passes it to Slipway as `SLIPWAY_DATABASE_PASSWORD`
instead of putting it in the URL. (Changing it after the database exists does not change the
Postgres user's password.) Outside compose, set `SLIPWAY_DATABASE_URL` and `SLIPWAY_DATABASE_PASSWORD`;
a password written into the URL itself takes precedence.

Put Slipway behind a TLS reverse proxy (Caddy, Traefik, nginx) for anything beyond your LAN:
with an `https://` base URL, cookies become `Secure` and HSTS is sent. Then set
`SLIPWAY_FORWARDED_ALLOW_IPS` to the proxy's address or subnet as Slipway sees it (for a proxy on the Docker
host, the compose network gateway such as `172.18.0.1`, or a CIDR such as `172.16.0.0/12`). Slipway then
takes the client IP from `X-Forwarded-For` for rate limiting and the audit log. Keep the default
(`127.0.0.1`) behind a proxy and every client shares the proxy's IP, so anyone's failed logins slow
everyone down. Never use `*`: any client could then forge its IP. If the proxy runs on the same machine,
publish Slipway on loopback only (`"127.0.0.1:${SLIPWAY_PORT:-8000}:8000"` in docker-compose.yml).
The proxy must also accept request bodies as large as the biggest snapshot you will upload (up to
`SLIPWAY_SNAPSHOT_MAX_BYTES`, 20 GiB by default), for example `client_max_body_size 20g;` in nginx.

**Backing up Slipway itself:** back up `data/postgres` and `data/files` together (stop the stack first, or
dump the database with `pg_dump`), **and** keep `SLIPWAY_ENCRYPTION_KEY` somewhere safe. Stored snapshots in
`data/files` are encrypted under keys that only the database holds, encrypted in turn with that key: without
the key, they can't be opened. `data/files` must belong to uid 10001 with mode 700 (the installer sets this; by
hand: `sudo chown 10001:10001 data/files && sudo chmod 700 data/files`). If it isn't writable, snapshots are
unavailable and say why, while deploys carry on.

**First admin:** whichever comes first becomes admin:
- `SLIPWAY_ADMIN_EMAIL`/`SLIPWAY_ADMIN_PASSWORD` on an empty database. The password must be at least 10
  characters. While `SLIPWAY_ADMIN_EMAIL` is set and Slipway has no accounts, the first account is reserved for it:
  GitHub sign-in and self-registration cannot create it. So if the password is missing or too short, Slipway
  logs an error, the login page says the configured admin was not created, and nobody can claim the seat
  until you fix the password and restart, or run `slipway create-admin`.
- `docker compose exec slipway slipway create-admin you@example.com` (see below).
- The first person to sign in with GitHub, only when `SLIPWAY_ADMIN_EMAIL` is unset. When
  `SLIPWAY_GITHUB_ALLOWED_USERS` or `SLIPWAY_GITHUB_ALLOWED_ORGS` is set, only an allow-listed GitHub account can claim
  this. With neither set, anyone who reaches Slipway first can, so on an internet-facing install set an allowlist
  or use one of the options above.

`slipway create-admin EMAIL` creates a new admin and asks for a password. For an existing account it only
grants the admin role and never changes the password; it prints the account's details (check any linked
GitHub login before promoting an account you didn't create). Add `--reset-password` to set a new password,
which also signs out the account's sessions, deletes its API tokens and unlinks GitHub (the owner relinks it
from Settings → Profile), and `--activate` to re-enable a deactivated account (an account with neither a
password nor a GitHub link also needs `--reset-password`). To script it, pipe the password on stdin:
`printf '%s\n' "$PW" | docker compose exec -T slipway slipway create-admin you@example.com`.

### GitHub OAuth app

1. GitHub → Settings → Developer settings → **OAuth Apps** → New.
2. Homepage URL = `SLIPWAY_BASE_URL`; callback URL = `SLIPWAY_BASE_URL/auth/github/callback`.
3. Put the client ID and secret in `SLIPWAY_GITHUB_CLIENT_ID` / `SLIPWAY_GITHUB_CLIENT_SECRET`.
4. Decide who may create an account by signing in with GitHub: `SLIPWAY_GITHUB_ALLOWED_USERS=alice,id:583231`
   and/or `SLIPWAY_GITHUB_ALLOWED_ORGS=my-org,id:9919` (the orgs setting adds the `read:org` scope). An entry is a
   login/org name or an immutable numeric id written as `id:<number>`. Prefer ids: after a rename or deletion
   anyone can register the old name. Find the `id` at `https://api.github.com/users/<login>` or
   `https://api.github.com/orgs/<org>`. Admins can also add a user with their GitHub username in
   **Settings → Users**, which pins their numeric id.

Slipway never links GitHub to an existing account by matching email. Users link GitHub themselves
from **Settings → Profile** after signing in. Linking, re-authorizing and unlinking need a sign-in from the
last 15 minutes. Admins can remove another user's link from **Settings → Users**
(`DELETE /api/v1/users/{id}/github`) for users who have a password; for the others, resetting the password
sets one and unlinks GitHub.

### Preparing a host

Any Linux machine with Docker Engine 20.10 or later + the compose plugin and SSH. Slipway runs every remote
command with `/bin/sh`, so the deploy user's login shell (bash, zsh, …) does not matter:

1. **Hosts → Add Host**, keep *Generate key*.
2. Slipway shows the public key and a ready-to-paste snippet that authorizes it, creates the deploy
   root (default `/opt/slipway`) and adds the user to the `docker` group.
3. Click **Verify connection**. Slipway records the host key fingerprint and refuses to connect if it ever
   changes (reset it from the host page only if you rebuilt the server). A server that starts offering a
   different *type* of host key is also reported as a mismatch.

Changing a host's hostname or port forgets its pinned key, so verify it again afterwards (the change is
audited). A check that was running while the address or key changed is discarded.

Changing the deploy root of a host with deployed instances moves their files: Slipway copies each
`<slug>/` directory to the new root (through a throwaway container for files containers wrote as root),
re-points `current` and each release's `.env` link, saves the new root, then deletes the old directory.
Containers keep running and named volumes are not touched. An old directory a container still
bind-mounts from is kept, with a note to redeploy that instance and delete it. If a copy fails, the
copies are removed and nothing changes. Change the deploy root on its own, not together with the
address or sign-in, and not while a deployment runs.

**Unraid** keeps only `/mnt` and `/boot` across a restart; the rest of the filesystem lives in RAM. Slipway
recognizes Unraid when it checks the host (`/etc/unraid-version`). A new Unraid host whose deploy root is still
the default `/opt/slipway` gets `/mnt/user/appdata` instead, so instances land in `/mnt/user/appdata/<name>`.
If something is already deployed under a folder Unraid clears, the host page, the instance page and every
deploy log say so; change the deploy root or the instance's folder and Slipway moves the files.

**Each instance's folder** is `<deploy_root>/<slug>/` unless the instance is given a folder of its own
(*Folder on the host* on the instance form or the claim dialog, `deploy_dir` in the API): any absolute path,
such as `/mnt/user/appdata/shop` or `/srv/apps/shop`. Slipway refuses system folders and the roots that hold
other data (`/`, `/etc`, `/usr`, `/boot`, `/mnt/user`, `/mnt/user/appdata`, `/mnt/diskN`, …), a folder that
is, holds or sits inside another instance's, and, on deploy, a folder that already holds files that aren't
Slipway's. It marks the folders it uses with `.slipway-instance`, and deleting an instance removes only what
Slipway put there (`releases/`, `shared/`, `current`, the marker); anything else stays, with a note. Changing
the folder of a deployed instance moves its files there the same way the deploy root moves (an empty folder
made in advance is fine). Instances with a folder of their own stay put when the host's deploy root changes.

On the host each instance's folder holds `releases/<sha12>-<deployment>`,
`current → releases/…` and `shared/.env` (mode 600). Every deployment, even of the same commit, gets a
fresh release directory; the one `current` points to is never touched by a redeploy, and a failed
deployment removes its release again. Keep persistent data in **named volumes or absolute host paths**:
relative bind mounts like `./data` do not survive a redeploy.

Files that containers wrote as root cannot be deleted by the non-root deploy user. Slipway then removes them
through a throwaway container (`docker run --rm --network none -v <deploy_root>:/r alpine:3.20 rm -rf /r/<slug>`),
so the host pulls `alpine:3.20` the first time this is needed. Without registry access, or with userns-remap,
that fallback fails: deleting the instance still succeeds and Slipway reports (and audits) the directory left
for you to remove by hand.

**Compose instances:** Slipway builds `shared/.env` from the repository's own `.env` (next to the compose file)
followed by Slipway's values, so Slipway's values win and the repository's defaults stay. It is passed with
`--env-file` to every compose command and linked as `.env` next to the compose file. Values are quoted so
`$`, `#`, quotes and spaces arrive exactly as entered (they are not `${VAR}`-interpolated). A value that
ends in a backslash and also needs quoting requires a recent Docker Compose release. Values in the repository's `.env` that reference a variable Slipway overrides (for example
`DATABASE_URL=postgres://app:${POSTGRES_PASSWORD}@db/app`) keep the repository's value when the compose file
interpolates them with `${...}` (a service's `env_file: .env` does see Slipway's values), so set the derived
variable in Slipway too.

**Host ports:** before it builds or stops anything, a deployment checks the host ports it will publish
against the ports in use on the host: listening sockets (`/proc/net`), ports Docker publishes for other
containers, and ports other Slipway instances on the host were given (even while they are stopped). Its own
containers' ports count as free. A taken port moves to the next free port above it, and the instance keeps
that port on later deploys; turn off *Use the next free port* on the instance to make the deploy stop
instead. Compose instances read their ports from `docker compose config` and can also set **host port
overrides** (service, container port, host port) without changing the compose file. A moved port is passed
back to Compose through the compose file's own variable when the port is written as one
(`"${WEB_PORT:-8080}:80"`), so every other value that uses `${WEB_PORT}` follows; otherwise through
`shared/compose.ports.yml`, which replaces the service's `ports` with `!override` (Docker Compose 2.24.4 or
later). An older Compose adds those ports instead of replacing them, so there Slipway deploys the release from
the whole resolved compose file with the new ports, `shared/compose.resolved.json`. Like `shared/.env`, that
file holds the interpolated environment values and is readable only by the SSH user. Either way Slipway checks
with `docker compose config` that the ports came out as planned before it stops or starts anything. Only host
ports move: container ports stay the same, so services still reach each other on the compose network.

### Hostnames through Switchyard

An instance can list **hostnames** (`app.example.com`), each pointing at one of its published ports: a compose
service and container port, or a container port in Dockerfile mode, plus the certificate mode. At the end of
every successful deploy, and with **Sync proxy** on the instance page (`POST /api/v1/instances/{id}/proxy/sync`),
Slipway makes [Switchyard](https://github.com/encondata/switchyard) match: one proxy host per hostname, sending
traffic to the Docker host's address on the host port the container port ended up on. A port Slipway moved
because it was taken is followed. Hostnames removed from the instance, and all of them when the instance is
deleted, are removed from Switchyard. A hostname is unique across instances.

- **Connect it** under *Settings → Integrations* (needs `settings:write`): the Switchyard URL and an API key
  made under *Administration → API keys* with `hosts.list`, `hosts.get`, `hosts.create`, `hosts.update`,
  `hosts.delete`, `config.preview` and `config.apply`. The key is encrypted at rest; *Test connection* checks it.
- **Where traffic goes:** the host's address, or the host's *Address for the reverse proxy* when Switchyard
  must reach it by another address than Slipway uses for SSH.
- **Applying:** Switchyard stages changes until an apply, and an apply sends every pending change to Caddy. So
  Slipway applies only when nothing else was waiting and Caddy was not changed outside Switchyard; otherwise
  its changes stay staged and the deploy log (and the instance page) say to apply them in Switchyard.
- **What Slipway changes:** only the hosts it created, which it marks in their notes, and only their domains,
  upstream address and port, and certificate mode. Access policies, headers and other settings made in
  Switchyard stay. A hostname another Switchyard host already uses is left alone and reported.
- A Switchyard problem never fails a deploy: the containers are running, and the problem is in the deploy log
  and on the instance page.

### Apps (slipway.yml)

A repository can describe how it is deployed in a `slipway.yml` at its root (or another path set on the
instance). Choose **App (slipway.yml)** as the build source: the form reads the manifest from the chosen branch
and asks for the settings it names, and shows its optional services. The manifest gives:

- an **`env_file`** template (the app's own `.env.example`) that Slipway fills in and writes to
  `<instance folder>/shared/.env` (mode 600), refusing to deploy while a value is still the manifest's
  `placeholder`, such as `CHANGEME`;
- **settings** asked for on the instance, and **vars** Slipway sets itself (`{slipway.slug}`,
  `{slipway.release}`, `{slipway.sha12}`, `{slipway.env_dir}`…);
- **secrets** Slipway generates on the first deploy (`hex`, `fernet` or `token`) and keeps, encrypted, with the
  instance. Their names are listed on the instance page; their values are never shown. Changing one can lock an
  app out of its own data, so Slipway never regenerates them; an environment variable of the same name
  replaces one;
- **services** with their default port, the variable that sets the host port and a hostname. Taken ports move to
  the next free one and reach the app through that variable, and the hostnames are published in Switchyard like
  any instance's;
- the **Compose projects** the app runs (for status, logs, start/stop and delete), the **images** each release
  builds (removed with the release unless something still uses them), and the **commands** that build, start
  and stop it, run from the release on the host.

An app's commands run on the host as trusted code, like a compose file. See
[docs/examples/serversherpa.slipway.yml](docs/examples/serversherpa.slipway.yml) for a full manifest, and
[docs/manifest.md](docs/manifest.md) for the whole format.

Every deployment, whatever its build source, runs as numbered **steps** shown on the deployment page, each
starting a section of the log. **Retry** runs a failed deployment's commit again (`POST
/api/v1/deployments/{id}/retry`, needs `deployments:create`): the downloaded release and the build are reused
when they are still on the host (a release that failed after its build is kept for that), and the settings,
ports and start run again.

### Claiming containers Slipway did not deploy

The host page lists **unmanaged containers**: compose projects (grouped by `com.docker.compose.project`) and
standalone containers that Slipway did not start, with their image, state, published ports, mounts and, for
compose, the project directory and compose files (`GET /api/v1/hosts/{id}/unmanaged`, needs `hosts:read` and
`instances:read`). Containers labelled `slipway.instance` and compose projects named `slipway-…` are Slipway's
own and are not listed. **Claim** one to have Slipway maintain it from a repository and branch from then on
(`POST /api/v1/hosts/{id}/claim`, needs `instances:write`, plus `deployments:create` to deploy straight away;
audited as `instance.claim`):

- A **compose project** becomes a compose instance that **keeps its project name**. Compose prefixes named
  volumes and networks with the project name (`shop_pgdata`), so every later deploy uses the same volumes and
  Compose replaces the running containers instead of starting a second copy next to them. Services that the
  repository's compose file does not define are removed on deploy (`--remove-orphans`, volumes kept). The
  original project directory is never changed or deleted, but bind mounts written relative to it (`./data`)
  resolve to Slipway's release directory after the claim: the host page warns about them, so change them to
  absolute paths in the repository first.
- A **standalone container** becomes a Dockerfile instance with the container's fixed host ports and its
  named volumes, anonymous volumes (by their id) and bind mounts copied. Other `docker run` options (networks,
  command, restart policy, read-only mounts, an address a port was bound to) are not, and the host page says
  which ones it saw. The first deploy builds the repository's Dockerfile, stops the old container just before
  `docker run` starts the new one, and removes it (never its volumes) once the new one runs. If the new
  container does not start, the old one is started again.
- **Register only** creates the instance without deploying. Nothing on the host changes: the instance shows
  as running (or stopped) with the claimed containers' status, logs and start/stop/restart, its ports are
  reserved like any deployed instance's, and its host and build settings are fixed. Deploy when ready.
- **Import environment variables** is off by default: it reads the containers' variables with `docker
  inspect` (leaving out the ones the image sets) and, for a compose project, the env file Compose read: the
  project's `.env`, or the files given with `--env-file`. That file is usually not in git, so after the claim
  Compose would no longer see it; importing it brings along values that only the compose file uses
  (`"${WEB_PORT}:80"`, `${DATA_DIR}/db`), parsed the way Compose does (quotes, `export`, comments,
  `${VAR:-default}`), and its values win over the containers'. A `.env` the SSH user can't read is read
  through a throwaway `alpine:3.20` container; if that fails too, the claim says so. Multi-line values are
  skipped and listed. These variables usually include passwords and API keys. They are stored encrypted
  like any instance's variables; the audit log records their names, never their values.

A claimed instance never removes volumes: not on deploy, not when it is destroyed (destroying it removes its
containers, images and Slipway's own `<deploy_root>/<slug>`, and keeps anonymous volumes too). Slipway refuses a
claim whose project directory or bind mounts overlap `<deploy_root>/<slug>`, the directory it would own.

An instance's host and build settings (host, Dockerfile or compose, Dockerfile path, build context, compose
file) can only change before its first deployment; after that, destroy it and create a new one. Deleting an
instance, or changing these settings, is refused while a deployment is queued or running.

Dockerfile path, build context and compose file must be relative paths inside the repository that don't
start with `-`. Before uploading, Slipway checks the source archive and refuses the deployment if the build
context, the Dockerfile, the compose file or any directory on the way to them is a symbolic or hard link
(Docker would follow it out of the release directory); links elsewhere in the repository are fine. A
Dockerfile build that leaves no local image fails before the running container is replaced, and Slipway never
pulls the image it built (`docker run --pull=never`).

Branch names can be up to 255 characters and are never shortened. If a repository's GitHub default branch is
longer, Slipway skips build detection for it and asks you to choose a branch when you create an instance.

## Local development

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"   # re-run after pulling (adds bcrypt for passphrase keys)
cp .env.example .env            # set SLIPWAY_ENV=development and an admin email/password
sh scripts/dev.sh               # SQLite at data/slipway-dev.db, auto-reload, http://localhost:8000
.venv/bin/pytest                # includes a real in-process SSH server
```

`scripts/dev.sh` uses SQLite unless `.env` sets `SLIPWAY_DATABASE_URL`, so no Postgres is needed to hack on
the UI. To work on screens with realistic content, seed a separate demo database (refuses to run in
production; it needs an admin first, from `SLIPWAY_ADMIN_EMAIL`/`SLIPWAY_ADMIN_PASSWORD` or `slipway create-admin`;
demo team members have no password and can't sign in):

```bash
SLIPWAY_ENV=development SLIPWAY_DATABASE_URL=sqlite+aiosqlite:///data/slipway-demo.db .venv/bin/python scripts/seed_demo.py
PORT=8001 SLIPWAY_DATABASE_URL=sqlite+aiosqlite:///data/slipway-demo.db sh scripts/dev.sh
```

New migration after changing models: run `sh scripts/dev.sh` once so `data/slipway-dev.db` is at head, then
`SLIPWAY_DATABASE_URL=sqlite+aiosqlite:///$(pwd)/data/slipway-dev.db .venv/bin/alembic revision --autogenerate -m "describe change"`
(leave the variable off if `.env` points `SLIPWAY_DATABASE_URL` at your own database).
Interactive API docs: `/api/docs`.

## Permissions

| Permission | admin | maintainer | developer | viewer |
|---|:-:|:-:|:-:|:-:|
| `repos:read`, `hosts:read`, `instances:read`, `deployments:read`, `analytics:read`, `logs:read` | ✓ | ✓ | ✓ | ✓ |
| `repos:sync`, `deployments:create`, `instances:operate` (start/stop/restart) | ✓ | ✓ | ✓ | |
| `hosts:write`, `instances:write`, `audit:read`, `users:read`, `roles:read` | ✓ | ✓ | | |
| `users:write`, `roles:write`, `settings:write` | ✓ | | | |
| `data:read` (backups and snapshots: names, sizes, dates) | ✓ | ✓ | ✓ | ✓ |
| `data:backup` (back up now, take snapshots), `data:restore` (restore same-key backups, roll back) | ✓ | ✓ | ✓ | |
| `data:reset` (reset data, seed from snapshots, restore old keys, delete backups and snapshots, overrides), `snapshots:upload` | ✓ | ✓ | | |
| `snapshots:download` (passphrase-encrypted downloads; seeding another repository's instances) | ✓ | | | |
| `environments:read` | ✓ | ✓ | ✓ | ✓ |
| `traffic:switch`, `providers:read` (DigitalOcean, Proxmox and ESXi accounts, never their secrets) | ✓ | ✓ | ✓ | |
| `environments:write`, `environments:delete`, `providers:spend` (confirm a monthly cost), `machines:write` (make, resize and snapshot VMs) | ✓ | ✓ | | |
| `providers:write` (add, change, test, trust and remove those accounts) | ✓ | | | |

See [docs/environments.md](docs/environments.md#permissions) for what the environment, traffic, provider and machine permissions allow.

`hosts:write` and `instances:write` are privileged. Whoever holds them controls SSH credentials and
container mounts, which effectively means root on those hosts. Pinning a host key on first contact
needs `hosts:write`; later health checks only need `hosts:read`. Through Slipway, environment variable values
are only readable with `instances:write`.

`data:*` does not include `snapshots:*`. `snapshots:upload` is privileged because a snapshot's database runs as
SQL inside the app it seeds; `snapshots:download` because a snapshot holds a whole database and its identity
keys. A snapshot's app name is a guard against mistakes, not against attackers: deploy access together with push
access already means root on the host.

**Compose instances run repository-defined containers as root.** Slipway runs the compose file from the
deployed branch as is (bind mounts, `privileged`, host namespaces and so on), ignoring the instance's port
mapping and volume settings (only host ports can be overridden). So anyone who can push to that branch, together with anyone holding
`deployments:create`, effectively has root on that host and can read every other instance's `shared/.env`
there. Use one host per trust level and protect deployed branches; on hosts that run compose instances from
less-trusted branches, consider rootless Docker or userns-remap. The instance form shows this warning.

The role editor shows every permission a role holds, including `*`, `resource:*` wildcards and permissions
Slipway no longer knows; saving without touching the boxes keeps them. Uncheck an unknown permission before
changing a role's other permissions.

## Security notes

- SSH keys, passwords, GitHub tokens and env vars are encrypted at rest with Fernet (`SLIPWAY_ENCRYPTION_KEY`).
  Back this key up. To rotate it: set `SLIPWAY_ENCRYPTION_KEY=new,old` (new first) and restart, run
  `slipway rotate-encryption-key` (`docker compose exec slipway slipway rotate-encryption-key`), which re-encrypts
  every stored secret and lists any it couldn't read, then remove the old key and restart. If a key is lost,
  secrets encrypted with it read as empty and Slipway logs the affected columns at startup; re-enter them (host
  key or password on the host page, env vars on the instance, GitHub by re-linking), or erase them with
  `slipway rotate-encryption-key --clear-unreadable`. In development the key is derived from `SLIPWAY_SECRET_KEY`,
  so changing that has the same effect.
  An instance whose environment variables can't be decrypted says so on its page and in the API
  (`env_unreadable: true`; `GET /api/v1/instances/{id}/env` answers 409), and its deployments are refused
  until the variables are re-entered or cleared ("Clear stored variables" on the Configure form, or
  `PATCH /api/v1/instances/{id}` with `{"clear_env": true}`). Saving the form without entering variables keeps
  the unreadable values, so restoring the old key still recovers them; `--clear-unreadable` keeps that
  deploy guard for instances.
- Sessions are opaque random tokens (only a SHA-256 hash is stored) in an `HttpOnly`, `SameSite=Lax` cookie;
  cookie-authenticated writes must echo a per-session CSRF token. API tokens skip CSRF but cannot mint tokens,
  change the password or unlink GitHub. Setting a first password on a GitHub-only account, linking or re-authorizing GitHub, and unlinking it also need a sign-in
  from the last 15 minutes.
- An admin password reset or deactivation signs the user out everywhere, deletes their API tokens and unlinks
  GitHub; until they relink, deploys they trigger fall back to `SLIPWAY_GITHUB_SERVICE_TOKEN` or public repositories.
  Reactivating an account with no password needs a new password in the same change.
  Changing your own password (Settings → Profile; `PATCH /api/v1/users/{your id}` refuses a password) signs
  out your other sessions but keeps your API tokens; revoke them under Settings → Tokens. Admins can list and
  revoke another user's tokens with `GET /api/v1/users/{id}/tokens` and `DELETE /api/v1/users/{id}/tokens/{token_id}`.
- Rate limits are in-process (single node) and count failures only. Password login: 10 per 5 minutes per
  client + email (IPv6 grouped by /48), 30 per 5 minutes per client IP (IPv6 /64), and 50 per 15 minutes per
  email across all clients. Attempts are counted before the password is checked, so parallel bursts are
  limited too. The per-email cap limits distributed guessing to about 4,800 guesses per account per day, but
  it is a hard block: failures kept up from two or more addresses keep that account's password login at 429,
  for the owner too, until 15 minutes after they stop (GitHub sign-in is unaffected). Self-registration is
  limited to 10 attempts per IP per hour; wrong current passwords on the password form to 5 per session and
  25 per user per 15 minutes (audited as `auth.password_change_failed`).
- With `SLIPWAY_ALLOW_SIGNUP=true`, `/api/v1/auth/register` reveals whether an email already has an account
  (rate limited per IP); Slipway has no email verification yet.
- Every remote command is built with `shlex.quote` and run with `/bin/sh` with stdin closed; paths and names are
  validated against traversal and injection. Text containing NUL characters is refused (PostgreSQL can't store
  it): request bodies get a 422 and URLs with `%00` a 400. Build output lines longer than 16 KiB are cut.
- Strict CSP (`script-src 'self'`), `X-Frame-Options: DENY`, `nosniff`, HSTS when served over HTTPS.
  In production, SQL errors do not include bound parameter values. The `httpx`/`httpcore` loggers stay at
  WARNING even with `SLIPWAY_LOG_LEVEL=DEBUG`, because their request logs include short-lived GitHub download tokens.

## Project layout

```
slipway/
  core/        config, permissions catalogue, encryption, password/token hashing, rate limiting
  db/          engine/session, declarative base + portable column types
  models/      users/roles/sessions/tokens, hosts, repositories, instances/deployments, audit
  services/    auth, users, github, ssh, hosts (health), repos (sync), deployer (pipeline + runner),
               ports (host port checks), discovery (unmanaged containers)
  api/v1/      JSON API routers
  web/         page routes, GitHub OAuth flow, Jinja templates, static CSS/JS/icons
alembic/       migrations
docker/        container entrypoint (runs migrations)
scripts/       dev server, demo-data seeder
tests/         pytest suite
```

## Roadmap

- **Analytics:** ingest API with per-app keys for Android/iOS/web SDKs, sessions, crashes, ANR, release health.
- **Logs:** structured log ingestion, search, live streaming across instances.
- **GitHub App** instead of user OAuth tokens for repo access, plus push webhooks for auto-deploy.
- **Job queue** (e.g. arq + Redis) so deployments survive restarts and run on several Slipway replicas.
  Today they run as in-process tasks, and anything in flight at restart is marked failed. Rate limits are
  also per process and would move to Redis.
- Zero-downtime deploys (start new container, health check, then swap), rollbacks to a previous release.
- Per-project / per-host permission scoping, teams, SSO (OIDC), and email verification for open sign-up.
