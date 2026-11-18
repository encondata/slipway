# Bringing Sirdar into Slipway

Status: phases 1 (manifest and steps), 2 (data safety) and 3 (environments and slots) are
built on branch `sirdar` (from `instance-folders`). Phases 2 and 3 still have to pass their
real-host checks below. Phases 4 to 6 are the plan.

## Goal

Slipway deploys ServerSherpa the way Sirdar does today, with Blue/Green slots on
several servers, managed or self-hosted Postgres, Spaces or another S3-compatible store, backups and
snapshots, on SSH hosts, DigitalOcean, Proxmox and ESXi. Nothing in Slipway is
written for ServerSherpa: the repository describes itself, so the next app like
it deploys the same way. Once it matches Sirdar, Sirdar is retired.

## What each has today

| | Slipway | Sirdar (BaseCampV3 `sirdar` branch) |
|---|---|---|
| Backend | Python, FastAPI, async SQLAlchemy, Alembic, Postgres | the same |
| Web | Jinja pages and `slipway.js` | React (about 20k lines), imports portal code |
| Sign-in | its own users, roles, GitHub | portal users ranked admin, their portal passwords and 2FA |
| What it deploys | any repository: a Dockerfile or a compose file | ServerSherpa only: the five stacks in `deploy/stack`, through `ss-stack` |
| Unit | instance: one repository, one branch, one host; phase 3: environment, one or two app slots and a data server, each an instance | environment: one ServerSherpa, one or two slots |
| Engine | shell over its own SSH session, one log per deployment | 17 numbered steps as Ansible playbooks, one log per step, retry from the failed step |
| Targets | SSH hosts | SSH, Proxmox (Terraform), ESXi (pyvmomi), DigitalOcean (VPC, droplets, managed Postgres, Spaces, load balancer, firewall, certificates) |
| Traffic | Switchyard routes; phase 3: Activate repoints an environment's names in Switchyard, and Cloudflare DNS records at a fixed address | Cloudflare DNS, Nginx Proxy Manager on the LAN, DigitalOcean load balancer plus Caddy in the cloud |
| Data | phase 2: a backup before every change that replaces data, the Backups list, restore, reset, roll back, encrypted snapshots ([snapshots.md](snapshots.md)) | a dump before each Update only (not before a restore or a reset), restore, reset, roll back, snapshot bundles, VM snapshots |

Sirdar's ServerSherpa knowledge sits in a few modules: `envfile.py` (the `.env`
keys, the secrets and how each is generated, the services and their ports),
`apps.py` (optional apps, SMTP), `first_admins.py`, `bundle.py` (snapshot
bundles that carry the pepper and the 2FA key) and the `ss-stack` calls in the
playbooks. The rest is general: providers, slots, the step runner, DNS, the
load-balancer switch, dumps.

## The idea: the repository describes itself

ServerSherpa's knowledge moves out of the deployer and into a manifest in the
app's repository, `slipway.yml`. BaseCampV3 already has most of what the
manifest points at: `ss-stack` runs the stacks in order, dumps, restores and
creates the first admin.

The format is described in [manifest.md](manifest.md), and the ServerSherpa
manifest is [examples/serversherpa.slipway.yml](examples/serversherpa.slipway.yml)
(BaseCampV3's `slipway.yml` on branch `slipway-manifest`). Phase 1, in short:

- `env_file` is the app's own `.env` template (ServerSherpa's
  `deploy/stack/env.example`). Slipway writes `<instance folder>/shared/.env` from
  it, keeping its lines and order and filling in the values below, and refuses to
  deploy while a value is still the `placeholder` (`CHANGEME`).
- `settings` are what the instance form asks for (base domain, proxy address).
  `vars` are what Slipway sets itself, from `{slipway.slug}`, `{slipway.release}`,
  `{slipway.sha12}` and the like.
- `secrets` are generated once (`hex`, `fernet` or `token`), stored encrypted
  with the instance and never shown again. A variable of the same name set on the
  instance replaces one.
- `services` name each service's default port, the variable that sets its host
  port, and its hostname. Optional ones are listed in one variable (`STACK_APPS`).
  Taken ports move to the next free one and go back to the app through those
  variables, and the hostnames become Switchyard routes.
- `projects` are the Compose projects the app runs, used for status, logs, start,
  stop and delete. `images` are the image references a release builds (tagged per
  release, such as `serversherpa-api:{STACK_IMAGE_TAG}`); Slipway removes them
  with the release, never one another release or container still uses.
- `commands` are `build`, `start` and `stop`: programs in the repository, run from
  the release.

Phase 2 adds the app's data (all optional; [manifest.md](manifest.md#data) has
every key):

- `data` says what the data is: the app's id (`serversherpa`; a snapshot seeds
  only an app with the same id), the dump's format label (`pg-custom`), the
  Docker volumes that hold it (the database, the SeaweedFS objects and the status
  page's volume, which Reset deletes), the files' format and the words the
  dialogs use for the identity keys.
- `secrets` marked `identity: true` (`SS_PASSWORD_PEPPER`, `SS_TOTP_ENCRYPTION_KEY`)
  are the keys the data was made with. They travel with every backup and
  snapshot, and a restore puts them back.
- `commands` gains the data commands, each an `ss-stack` subcommand.
  `{slipway.out}` and `{slipway.in}` are the files Slipway names; it checks,
  hashes, keeps and prunes them itself, so `dump` is `ss-stack pgdump` (one file,
  no naming or rotation of its own), not `ss-stack dump`.
- `first_admin` is how a deploy creates the first account. The password goes to
  `ss-stack admin` on stdin, never in argv.

```yaml
secrets:
  SS_TOTP_ENCRYPTION_KEY: {kind: fernet, identity: true}
  SS_PASSWORD_PEPPER:     {kind: hex, identity: true}

data:
  app: serversherpa
  format: pg-custom
  volumes:
    - {name: "ss-{STACK_ENV}-db_pgdata",           holds: database}
    - {name: "ss-{STACK_ENV}-storage_seaweeddata", holds: files}
    - {name: "ss-{STACK_ENV}-status_status-data",  holds: other}
  files: {format: serversherpa-objects-v1, label: Uploaded files}

commands:                       # added to build, start and stop
  has_data:     [deploy/stack/ss-stack, has-data, "{slipway.env_dir}"]
  data_up:      [deploy/stack/ss-stack, data, "{slipway.env_dir}"]
  dump:         [deploy/stack/ss-stack, pgdump, "{slipway.env_dir}", "{slipway.out}"]
  verify_dump:  [deploy/stack/ss-stack, verify-dump, "{slipway.env_dir}", "{slipway.in}"]
  revision:     [deploy/stack/ss-stack, revision, "{slipway.env_dir}"]
  accepts:      [deploy/stack/ss-stack, accepts, "{slipway.env_dir}", "{slipway.in}"]
  restore:      [deploy/stack/ss-stack, restore, "{slipway.env_dir}", "{slipway.in}"]
  export_files: [deploy/stack/ss-stack, export-objects, "{slipway.env_dir}", "{slipway.out}"]
  import_files: [deploy/stack/ss-stack, import-objects, "{slipway.env_dir}", "{slipway.in}"]
  after_import: [deploy/stack/ss-stack, clear-sessions, "{slipway.env_dir}"]
  seed:         [deploy/stack/ss-stack, seed, "{slipway.env_dir}"]

first_admin:                    # ss-stack admin runs serversherpa bootstrap-admin itself
  command: [deploy/stack/ss-stack, admin, "{slipway.env_dir}", --email, "{admin.email}",
            --first-name, "{admin.first_name}", --last-name, "{admin.last_name}",
            --role, super_admin, --link-minutes, "240"]
  password: {min_length: 8, stdin: true, args: [--password-stdin]}
  invite:   {args: [--invite]}
  done_codes: [0]
  exists_codes: [10]            # the account already exists
```

The draft's sketch of this was wrong in one place: its first admin passed
`bootstrap-admin` to `ss-stack admin`, which already runs it (so
`bootstrap-admin` reached the command twice and it failed with a usage error),
and it lacked the required `--first-name` and `--last-name`.

Phase 3 adds the keys an environment needs ([manifest.md](manifest.md#environments-attach-and-server)):
`services.<name>.health` (the path the checks request), `data.migrations:
expand_contract` (required for two app slots), `data.attach` (the `.env` keys that
point an app slot at data on another host, built from named endpoints such as
`{data.db.host}`) and `data.server` (which services, ports, secrets, projects,
volumes and commands the data server uses, and the endpoints it provides). Phase 4
fills the same `data.attach` from a managed Postgres and a Spaces bucket. An
instance outside an environment whose data lives outside its host
(`STACK_EXTERNAL_DATA=1`, `STACK_DB_HOST`, or a hand-made data VM, where
`ss-stack has-data` exits 4) is still backed up, and Slipway still won't restore
over it, roll it back, reset it or seed it.

A repository without `slipway.yml` deploys exactly as it does today.

## New pieces in Slipway

**Environments and slots (phase 3, built).** An environment is one app from one
repository and branch: it has its settings, secrets, attached data and public names.
It runs in one slot, or in two for Blue/Green with a data server both slots use. Each
slot and the data server is an ordinary Slipway instance on a host, so the existing
deploy, logs, ports and folders keep working, and each can be on a different server.
One slot is active. Instances that don't belong to an environment keep working as
they do now. [environments.md](environments.md) explains how to set one up and run it.

**Providers that make hosts.** A host gets a provider: `ssh` (today's hosts),
`digitalocean`, `proxmox` or `esxi`. A provider creates the server, pins its host
key before the first connection (cloud-init on DigitalOcean, as Sirdar does),
resizes it, snapshots it and destroys it. What it creates is an ordinary host in
the Hosts list, marked as owned by its environment.

**Data resources.** A managed Postgres cluster, a Spaces bucket and its scoped key,
or the app's own self-hosted stacks. They are tracked in a `resources` table
(provider, provider id, tags, encrypted credentials), so Slipway only ever changes
or deletes what it recorded, as Sirdar does with `managed_records` and
`do_resources`. Their credentials go into the slot's `.env` under the keys the
manifest names.

**Traffic switches.** The active slot is switched through one interface. Phase 3
builds its Switchyard backend: Activate repoints the environment's Switchyard hosts
in one apply, checks the names through Switchyard, and puts them back if anything
fails (the role Nginx Proxy Manager plays in Sirdar). Phase 4 adds the DigitalOcean
load balancer (add the new droplet, wait for health, smoke test, remove the old
one). Cloudflare DNS is not a switch: Slipway keeps an A record per public name at
one fixed address (the WAN address, or later the load balancer's), as Sirdar does.

**Steps.** Every deployment runs as numbered steps (Resolve the commit, Download
the source, Upload the release, Read slipway.yml, Check host ports, Write the
settings, Build, Start, Switch to the new release, Update Switchyard). Each step's
status, times and note are kept on the deployment (`deployments.steps`), and the
deployment keeps one log in which each step starts with a `── Step N/M: name`
line. Retry runs a failed deployment's commit again: it reuses the release and the
build when they are still on the host (the release of a deployment that failed
after its build is kept for that), and runs the settings, ports and start again.
Phase 2 adds Back up the data (after Build) to an app's deploys, and data jobs
(restore, reset, roll back, snapshots, first admin, starter content) run as
deployments of their own kind with their own steps. Phase 3 adds the environment's
steps: Check the slot (smoke test), Update Switchyard, Update DNS records, Stop and
start Blue and Green around a data job, and the steps of the jobs that run on the
environment itself (Activate, Publish names, Discard, Remove a slot, Delete). Phase 5
adds Prepare server.

**Backups and snapshots (phase 2).** A backup before every change that replaces
data: before a deploy (which migrates), a restore, a reset and a roll back, kept
per instance (newest N) on its host. Sirdar dumps only before an Update. Restore,
reset, start over and roll back, each refused before it changes anything when the
copy doesn't fit. Snapshots (the database, the files and the manifest's `identity`
secrets, encrypted) to seed new instances, kept on the Slipway server, and
downloadable with a passphrase. [snapshots.md](snapshots.md) describes them. VM
snapshots on Proxmox and ESXi come with phase 5.

## Decisions taken in this draft

1. **One engine: Slipway's.** Sirdar's playbooks (about 900 lines) mostly run
   `ss-stack`, write files and install Docker. They are ported to Slipway's shell
   steps, which are tested against real shells with `LocalRemote`. No Ansible.
2. **Switchyard replaces Nginx Proxy Manager** for LAN Blue/Green (NPM is no
   longer in use).
3. **Terraform stays for Proxmox** and pyvmomi stays for ESXi, both ported as they
   are.
4. **Slipway's users and roles.** No portal sign-in: the people who need access
   already have Slipway accounts. The new actions get
   permissions of their own (create environment, switch traffic, restore data,
   delete environment); the ones that replace or remove data need the
   environment's name typed back, as in Sirdar.
5. **The web pages are rebuilt in Slipway's style.** The seven-step Deploy flow
   becomes a page with the same steps.

## Phases

Each phase merges on its own and leaves Slipway working.

1. **Manifest and steps (built).** `slipway.yml`, generated secrets, optional
   services, numbered steps and retry. ServerSherpa deploys to one SSH host with
   its own Postgres and object store. BaseCampV3's `slipway.yml` is on branch
   `slipway-manifest` (PR #2); it still has to be deployed on a real host.
2. **Data safety (built; real-host checks to do).** Backups before changes, the
   Backups list, restore, reset, start over, roll back, snapshots (take, upload,
   download, seed a new instance from one), starter content and the first admin.
   The design is [phase2-data-safety.md](phase2-data-safety.md). BaseCampV3's side
   is on `slipway-manifest` too: the data commands in `slipway.yml`, the new
   `ss-stack` subcommands (`has-data`, `accepts`, `verify-dump`, `clear-sessions`,
   `export-objects`, `import-objects`; `seed` adds the Learning space itself when
   learn runs), `deploy/stack/objects.py`, and `scripts/make-seed-snapshot.sh`
   making Slipway snapshots with `slipway snapshot pack`.

   **Real-host checks** (not in CI). Deploy BaseCampV3 `slipway-manifest` twice,
   then:
   1. Back up now;
   2. take a snapshot;
   3. reset from it;
   4. roll back a commit with a failing migration;
   5. download it with a passphrase and import it into a second Slipway;
   6. seed a new instance from it;
   7. Start over after a failed first deploy;
   8. an instance with `STACK_EXTERNAL_DATA=1` shows that its data lives outside
      the host, and still backs up.

   After each, a user signs in with their own password and 2FA.
3. **Environments and slots (built; real-host checks to do).** Environments,
   Blue/Green on SSH hosts with a separate data server, Switchyard switching,
   Activate and switch back, Discard of a failed idle-slot deploy, Cloudflare DNS.
   The design is [phase3-environments.md](phase3-environments.md); how to use it is
   [environments.md](environments.md). BaseCampV3's side is on `slipway-manifest`:
   the phase 3 keys in `slipway.yml`, `ss-stack has-data --server`, a data server
   that runs only its db and storage stacks (`STACKS=(db storage)` with
   `STACK_DB_PUBLISH=1`, and `restore` stopping only the app stacks it runs), and
   `deploy/stack/test-server-role.sh`.

   **Real-host checks** (not in CI). Three LAN hosts with pinned keys (blue, green,
   data), Switchyard with a traffic address, Cloudflare with a test zone, and
   BaseCampV3 `slipway-manifest`:
   1. create `uat` as Blue/Green with DNS and `tls_mode auto`: the chain deploys the
      data server (its DNS records and `spaces` host appear), then blue, then
      activates blue and adds the starter content; Back up now carries the
      environment's identity keys;
   2. deploy a commit with an expand migration to green while blue serves, and
      activate green: the same session and 2FA still work;
   3. switch back (while a Back up now runs) and forward again; switch back once
      more and deploy a fix to green: the lag check refuses it until confirmed;
   4. deploy a commit whose migration fails to the idle slot, then Discard it
      (nothing restored); repeat and Roll back instead (both slots stop, the failed
      one stays stale);
   5. restore a backup (both slots stopped, the lead slot migrated and started
      before the job ends); make the lead slot's start fail once and see the job
      fail and hold; take a snapshot and seed a second environment from it;
   6. remove green, add it on another host with the data server updated, deploy
      to it;
   7. stop Switchyard during an Activate (names put back), then Resolve;
   8. delete `uat`: only the records and hosts Slipway made are gone, and the
      volumes and backups stay on the data host;
   9. a standalone ServerSherpa instance on one of the hosts deploys and publishes
      as before throughout;
   10. restart Slipway during the chain (after the data server deploy's `finish`):
       the environment page's notice continues it.

   After each, a user signs in with their own password and 2FA.
4. **DigitalOcean.** Accounts (production and development), VPC, droplets as hosts,
   managed Postgres, Spaces bucket and key, load balancer, firewall, certificates,
   the load-balancer switch, delete with the name and the production phrase.
5. **Proxmox and ESXi.** Creating, resizing, snapshotting and destroying VMs.
6. **Retiring Sirdar.** Delete its environments with Sirdar itself, so it removes
   the cloud resources it recorded, then shut it down. Nothing is imported.

## Settled

- **No Sirdar environment has to survive.** They are all demo and dev, and can be
  destroyed. Slipway imports nothing from Sirdar: no environments, secrets,
  snapshots or recorded resources, and no adopt-from-Sirdar path.
- **Nginx Proxy Manager is gone.** Switchyard is the only LAN proxy and the LAN
  traffic switch. No NPM backend is built.
- **No portal sign-in.** Everyone who needs Slipway already has a Slipway account.
  Nothing from Sirdar's portal-user import is carried over.
