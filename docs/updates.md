# Updates

The Updates page shows which version of Slipway is running, which newer commits are on the branch it follows,
and lets an admin upgrade Slipway without running Docker commands by hand.

## How it works

An upgrade replaces the Slipway container, so it can't run inside that container. Instead, Slipway connects
over SSH to the server it runs on, copies its own upgrade script there and starts it in the background. The
script does the work and writes its progress to files in the install folder. The page reads those files, so it
keeps showing progress while Slipway restarts.

The script that runs is always the one from the running version of Slipway, never the one in the new commit.

## What you need

- Slipway installed with `install.sh`, so it runs in Docker from a git checkout (on Unraid, `/mnt/user/slipway`).
- Slipway's own server added under Hosts, with its SSH key pinned (open the host and run a check).
- An SSH user on that host who can run `docker` and write the install folder. On Unraid that is `root`.
- `git` on the server (the same one `install.sh` needs). `flock` is used when it is there.
- The `updates:run` permission. Only the built-in admin role has it.

Then open Updates, choose the host and save. Slipway finds its own container on that host, reads the install
folder from the container's compose labels and follows the branch the checkout is on (or `main`).

## Security

Read this before you set it up.

- **Slipway's own server is now a host: anyone who can create or deploy instances on it is root on Slipway
  itself.** A compose instance runs as root on its host, and on this host that reaches `.env` (the secret and
  encryption keys) and the database. Only give `instances:write` and `deployments:create` on this host to people
  you would make admins. The Updates page lists the roles that hold them.
- The upgrade builds and runs the new commit's `Dockerfile`, `docker-compose.yml` and build as root. Anyone who
  can push to the branch you upgrade to can run code as root on the server when you click Upgrade. The page
  warns when an update changes `docker-compose.yml`, `Dockerfile`, `.dockerignore`, `install.sh` or the upgrade
  script, and links to the changes. Check them before you upgrade.
- Saving the host and starting an upgrade only work from the web UI. API tokens can read the page's data and
  run a check, but can't do either.
- Slipway records the host's address, user and pinned key when you save. If any of them changes later (someone
  with `hosts:write` edits the host or resets its key), checks and upgrades stop with "changed since updates
  were set up". Save the host on the Updates page again once you trust it.
- The backups in `.slipway-updates/` hold the whole database: accounts, password hashes and encrypted keys.
  The script keeps that folder at mode 700 and its files at mode 600, and repairs them on every run. Keep the
  `slipway` share's SMB and NFS export off on Unraid, and don't use Unraid's New Permissions tool on it.
- If the checkout's `origin` URL holds a token (`https://user:token@github.com/...`), git can print it in an
  error. Slipway hides such credentials in the log it shows, but a deploy key or the public HTTPS URL is safer.

## Checking for updates

Check now (and a check every 6 hours) fetches every branch from `origin` into the install folder, then shows:

- the new commits on the followed branch, newest first (up to 100);
- database migrations the update adds;
- changes to the files that run as root (see above);
- the other branches, and which of them Slipway can switch to.

Slipway only moves forward: a commit must come after the one that runs now. Older code can't run on a newer
database, so going back means restoring a backup by hand.

A check is skipped while an upgrade runs. Local changes to tracked files in the install folder block upgrades
(see below).

## What an upgrade does

The current version keeps running until the backup. The steps, in order:

1. **preflight**: checks the tools, the install folder, that `slipway` and `db` run, free space (3 GB for
   Docker's images, twice the database size for the backup) and that the database container still matches
   `docker-compose.yml` and `.env`. Nothing is changed if it fails.
2. **fetch**: fetches the branch and checks that the target commit comes after the running one.
3. **build**: tags the running image as `slipway:before-<id>`, checks out the target and builds it. If the
   build fails, or the new commit changes the database container, the checkout and image are put back and the
   current version never stops.
4. **backup**: waits for any deployment that is still running (up to 10 minutes), then stops the current
   version and backs up the database to `.slipway-updates/<id>-before.dump`. If that fails, the current version
   starts again.
5. **switch**: starts the new version. Slipway is offline for about a minute.
6. **health**: waits up to 5 minutes for the new container to answer its health check three times in a row
   over at least 15 seconds, with the new commit stamped in it, without restarting.
7. **cleanup** (success): removes older `slipway:before-*` tags and keeps the 3 newest backups.

If the new version isn't healthy, **rollback** stops it, puts the old image and checkout back, restores the
backup when the database changed, and starts the old version. Only the slipway container is recreated; the
database container is never touched. When one part of the rollback fails, the parts that don't depend on it
still run (the checkout and image tag are always put back), and the run's message says what was done and what
wasn't.

If the script is stopped after the new version was started (the server shuts down, or someone kills it), it
rolls back on its way out. Every docker and `git fetch` call has a time limit, so a call that hangs fails that
step instead of holding the run forever.

A run ends as one of:

| Status | Meaning |
|---|---|
| succeeded | The new version runs. |
| failed | Nothing changed, or everything was put back before the new version started. |
| rolled_back | The new version didn't start; the old one runs again. |
| rollback_failed | Something could not be put back, before or after the switch. The message says what. Follow the steps below. |
| interrupted | The script stopped before it finished: the server restarted or the script was killed. Check what runs, then follow the steps below if needed. |

Slipway keeps the last 20 runs. Each one shows its steps and the end of its log.

## Things to know

- **Local changes**: an upgrade checks out the new commit, which would throw away edits to tracked files, so
  any edit stops it. Put your changes in `docker-compose.override.yml` in the install folder instead (Docker
  Compose reads it on its own, and git leaves it alone). For example, to publish Slipway on loopback only:

  ```yaml
  services:
    slipway:
      ports: !override
        - "127.0.0.1:${SLIPWAY_PORT:-8000}:8000"
  ```

- **Database container changes**: if `.env` or `docker-compose.yml` changed the database container since it
  started (another data folder, password or image), the upgrade stops. Run `install.sh` by hand for that.
- **Don't run `install.sh` while an upgrade runs.** It fetches and checks out in the same folder.
- **Running deployments**: an upgrade can't start while a deployment is queued or running, and deployments
  can't start while an upgrade runs, since stopping Slipway would cut them off. If one started just before the
  upgrade, the upgrade waits for it (up to 10 minutes) before it stops Slipway, and gives up without changing
  anything if it is still running then.
- **Starting slowly**: if the upgrade script hasn't written its first status within 10 seconds (a disk
  spinning up, say), the run stays Running and the page keeps reading it. It is marked failed only when its
  process is gone without a status, or none shows up within 10 minutes.

## Fixing it by hand

The run's files are in the install folder:

```bash
cd /mnt/user/slipway            # your install folder
ls -t .slipway-updates/          # <id>.json, <id>.log and <id>-before.dump per run
cat .slipway-updates/<id>.json   # from, to, branch, step, db_changed, backup
tail -n 100 .slipway-updates/<id>.log
```

To put the previous version back:

```bash
docker compose stop slipway
docker tag slipway:before-<id> slipway:latest
git checkout -f -B <branch> <from>       # the branch and "from" commit Slipway ran before
```

Only when the database changed (`db_changed` is true, or you aren't sure), restore the backup:

```bash
docker compose exec -T db psql -U slipway -d postgres -v ON_ERROR_STOP=1 \
  -c 'DROP DATABASE slipway WITH (FORCE)' -c 'CREATE DATABASE slipway OWNER slipway'
docker compose exec -T db pg_restore -U slipway -d slipway --exit-on-error --single-transaction --no-owner \
  < .slipway-updates/<id>-before.dump
```

Then start it and watch it come up:

```bash
docker compose up -d --no-build --no-deps slipway
docker compose logs -f slipway
```

A run that was killed may leave its lock behind when `flock` isn't installed. The next run takes it over when
its process is gone, but if no upgrade runs (`ps aux | grep upgrade-`) you can remove it with
`rm -rf /tmp/slipway-upgrade.lock.d`. A restart clears it too.
