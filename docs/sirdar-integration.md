# Bringing Sirdar into Slipway

Status: phase 1 is built on branch `sirdar` (from `instance-folders`); phases 2 to 6 are the plan.

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
| Unit | instance: one repository, one branch, one host | environment: one ServerSherpa, one or two slots |
| Engine | shell over its own SSH session, one log per deployment | 17 numbered steps as Ansible playbooks, one log per step, retry from the failed step |
| Targets | SSH hosts | SSH, Proxmox (Terraform), ESXi (pyvmomi), DigitalOcean (VPC, droplets, managed Postgres, Spaces, load balancer, firewall, certificates) |
| Traffic | Switchyard routes | Cloudflare DNS, Nginx Proxy Manager on the LAN, DigitalOcean load balancer plus Caddy in the cloud |
| Data | the app's own volumes | dumps before every change, restore, reset, roll back, snapshot bundles, VM snapshots |

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

Phase 1's format is in `slipway/services/manifest.py`, and the ServerSherpa
manifest is [examples/serversherpa.slipway.yml](examples/serversherpa.slipway.yml).
In short:

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

Phase 2 adds what this needs for data (a sketch):

```yaml
data:                           # what Slipway can attach instead of the app's own
  postgres:
    self_hosted: deploy/stack/db          # skipped when a managed one is attached
    env: {url: SS_DATABASE_URL, ssl: SS_DATABASE_SSL, ca: SS_DATABASE_CA_B64, password: POSTGRES_PASSWORD}
  objects:
    self_hosted: deploy/stack/storage
    env: {bucket: SS_SPACES_BUCKET, key: SS_SPACES_ACCESS_KEY, secret: SS_SPACES_SECRET_KEY,
          endpoint: SS_SPACES_ENDPOINT, region: SS_SPACES_REGION, path_style: SS_SPACES_USE_PATH_STYLE}
  external_flag: STACK_EXTERNAL_DATA

secrets:
  SS_PASSWORD_PEPPER: {kind: hex, identity: true}   # travels with snapshots

commands:                       # added to build, start and stop
  dump: [deploy/stack/ss-stack, pgdump, "{slipway.env_dir}", "{out}"]
  restore: [deploy/stack/ss-stack, restore, "{slipway.env_dir}", "{in}"]
  revision: [deploy/stack/ss-stack, revision, "{slipway.env_dir}"]
  first_admin: [deploy/stack/ss-stack, admin, "{slipway.env_dir}", bootstrap-admin, --email, "{email}"]

migrations: expand_contract     # Blue/Green slots share one database
```

A repository without `slipway.yml` deploys exactly as it does today.

## New pieces in Slipway

**Environments and slots.** An environment is one app from one repository and
branch: it has its settings, secrets, attached data and public names. It runs in
one slot, or in two for Blue/Green. Each slot is an ordinary Slipway instance on a
host, so the existing deploy, logs, ports and folders keep working, and each slot
can be on a different server. One slot is active. Instances that don't belong to
an environment keep working as they do now.

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

**Traffic switches.** The active slot is switched through one interface with
three backends: the DigitalOcean load balancer (add the new droplet, wait for
health, smoke test, remove the old one), Switchyard on the LAN (repoint the routes,
the role Nginx Proxy Manager plays in Sirdar), and Cloudflare DNS for the public
names.

**Steps.** Every deployment runs as numbered steps (Resolve the commit, Download
the source, Upload the release, Read slipway.yml, Check host ports, Write the
settings, Build, Start, Switch to the new release, Update Switchyard). Each step's
status, times and note are kept on the deployment (`deployments.steps`), and the
deployment keeps one log in which each step starts with a `── Step N/M: name`
line. Retry runs a failed deployment's commit again: it reuses the release and the
build when they are still on the host (the release of a deployment that failed
after its build is kept for that), and runs the settings, ports and start again.
Environment deploys will add Prepare server, Pre-deploy dump, Restore, Smoke test,
Switch traffic and the teardown steps.

**Backups and snapshots.** A dump before every change that replaces data, kept
per environment (newest N). Restore, reset, roll back. Snapshot bundles (database
plus the manifest's `identity` secrets, encrypted) to seed new environments, and
VM snapshots on Proxmox and ESXi.

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
   its own Postgres and object store. Still to do: add `slipway.yml` to BaseCampV3
   and deploy it on a real host.
2. **Data safety.** Dumps before changes, the Backups list, restore, reset, roll
   back, snapshot bundles and seeding a new environment from one, the first admin.
3. **Environments and slots.** Environments, Blue/Green on SSH hosts with a
   separate data server, Switchyard switching, Activate, Cloudflare DNS.
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
