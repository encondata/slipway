# DigitalOcean

An environment can run on **DigitalOcean** instead of your own hosts. Slipway then makes everything the
environment needs in your DigitalOcean account: a VPC, one droplet per app slot, a managed PostgreSQL
cluster, a Spaces bucket and its key, a load balancer with a Let's Encrypt certificate, and a cloud
firewall. It records each object it makes, changes only those, and removes them all when you delete the
environment.

This page is for the people who set this up and run it. How environments work in general (slots, Activate,
the data owner, backups) is in [environments.md](environments.md). The design, with every rule and message,
is [phase4-digitalocean.md](phase4-digitalocean.md). The app side is
[manifest.md](manifest.md#digitalocean-edge-and-datamanaged).

## What you need first

1. **A DigitalOcean account in Slipway**, added by an admin under *Settings → Integrations*
   ([Accounts](#accounts)).
2. **Cloudflare**, set up under *Settings → Integrations* ([environments.md](environments.md#cloudflare)).
   Slipway proves the certificate's names to Let's Encrypt with DNS records in Cloudflare, and points the
   environment's names at the load balancer there. Without it the flow doesn't offer DigitalOcean.
3. **An app that can run on managed data behind a load balancer.** Its `slipway.yml` needs `edge` (the
   port and health path the load balancer uses) and `data.managed` (a PostgreSQL database with its
   version, and optionally a bucket). Blue/Green also needs `data.migrations: expand_contract`.
   [manifest.md](manifest.md#digitalocean-edge-and-datamanaged) has the keys.
4. **The `providers:spend` permission** for whoever creates the environment, adds a slot or grows its
   sizes, because each of these confirms a monthly cost. Maintainers have it.

## Accounts

Open *Settings → Integrations*. The **DigitalOcean** card lists the accounts. Anyone with
`providers:read` (developers and maintainers) sees it; only admins (`providers:write`) add, change, test or
remove an account.

An account has:

- **Name**: unique, and kept even after the account is removed, so old logs still name it.
- **API token**: write-only. Slipway stores it encrypted and shows only its last characters. The same
  token can't serve two accounts.
- **Region**: the default for new environments. The list shows the regions that offer Spaces.
- **Production**: an account for production environments only (see [Production](#production-retiring-and-taking-off-the-air)).
- **SSH sources**: the addresses Slipway connects from ([SSH sources](#ssh-sources-and-the-lock-out-guard)).
- **Monthly limit** (optional): the most the account's environments may cost together, in dollars.
- **Price overrides** (optional): see [What an environment costs](#what-an-environment-costs).

### The token

Make a token in DigitalOcean's control panel. A full-access token works. A custom-scoped one must be able
to read the account, regions and sizes, and to read, create, change and delete droplets, VPCs, database
clusters, Spaces keys, certificates, load balancers and firewalls.

**Test** reads the account (its status, team and droplet limit), checks the region, and reads one of each
kind of object Slipway uses. Slipway can't check that the token may create and delete these without making
one, and Test says so. When a step later meets a token that can't do something, DigitalOcean answers 403
and the step stops before it changes anything:

```
shop-do's token can't create load balancers (DigitalOcean answered 403). Slipway changed nothing: give the token that scope, then retry
```

Fix the token's scopes, then **Retry** the job. Slipway never reads a 403 as "gone".

The token belongs to one DigitalOcean team. Once an environment uses the account, a new token from another
team is refused, because the environment's objects are in the first team. With no environment using it,
the team is learned again by the next Test or deploy.

### Removing an account

**Remove** asks for the account's name. It is refused while an environment that isn't deleted, or a VM,
uses the account. An account that only deleted environments point at is kept as a **Removed** row: its token
and settings are cleared and it can't be chosen again, but its name stays for the old logs.

## SSH sources and the lock-out guard

Each droplet's cloud firewall lets SSH in only from the account's **SSH sources** (addresses or ranges,
such as `203.0.113.7` or `203.0.113.0/24`). They are required. `0.0.0.0/0` is allowed when you type it,
and every page that shows the account then warns `SSH to <env>'s droplets is open to the internet`.

Slipway can't learn the address it connects from before it has a droplet. Once it reaches one, it asks the
droplet which address it sees (`$SSH_CONNECTION`) and remembers it for the environment (the newest ten). From
then on the account refuses SSH sources that leave that address out:

```
Slipway connects to shop's droplets from 203.0.113.7, which these SSH sources leave out: Slipway would lose SSH to them, and with it backups, snapshots and Delete
```

A change of SSH sources reaches each firewall at the environment's next deploy. After that change Slipway
opens a fresh SSH connection to every built droplet. If one fails, it puts the previous firewall rule back
and the step fails.

## What an environment makes

| Object | Name | Made by |
|---|---|---|
| VPC | `slipway-<env>` | the first deploy's `prepare` |
| Cloud firewall | `slipway-<env>-fw` | `prepare`, before the first droplet |
| Droplet, one per app slot | `slipway-<env>-blue`, `slipway-<env>-green` | that slot's first deploy (`prepare`) |
| Spaces bucket and its key | `slipway-<env>-<id>` | `prepare`, when `data.managed` has a bucket |
| PostgreSQL cluster | `slipway-<env>-db` | the first deploy's `database` step |
| Certificate (Let's Encrypt) | `slipway-<env>-<yyyymmddhhmm>` | the first deploy's `edge` step, and renewals |
| Load balancer | `slipway-<env>-lb` | the first deploy's `edge` step |

Slipway matches these names exactly, never by prefix, so environments `prod` and `prod-eu` never mix.
Droplets and clusters also carry Slipway's tags (`slipway`, `slipway-env-<environment id>`,
`slipway-env:<name>`, and on droplets `slipway-slot:<slot>`). Slipway never calls DigitalOcean's tags API.
If an object no longer looks like Slipway's (renamed, retagged, moved), the step stops and changes nothing.

**The firewall is made first.** It applies to the environment's droplets by tag, so a droplet is covered
from its first boot: its SSH port is never open to the world, only to the SSH sources. Once the load
balancer exists, the firewall also lets the load balancer reach the app's port. Outbound traffic is open.

**The load balancer** takes HTTPS on 443 with the certificate, and HTTP on 80, and sends both as plain HTTP
to `edge.port` on the active slot's droplet. HTTP isn't redirected: the app does that itself, from
`X-Forwarded-Proto`. Its health check requests `edge.health`.

**The database cluster** lets in only the environment's droplets (its trusted sources). The app's role and
database are made from `data.managed`'s names, and the app connects with TLS.

## Droplets

Each droplet is an ordinary host in the Hosts list, named `slipway-<env>-<slot>`, marked as made by the
environment. Slipway made it, so it runs only that environment's slot: Delete, Reset key, Check before it is
built, and edits of its address or credentials are refused on the Hosts page. Its label and description
can still change. It goes when its slot is removed or the environment is deleted.

- **Image**: Ubuntu 24.04 (`ubuntu-24-04-x64`), set up by cloud-init with Ubuntu's `docker.io` and
  `docker-compose-v2` packages. Nothing is downloaded from outside the distribution.
- **The `slipway` user** is the one Slipway logs in as. It is in the `docker` group and has **no sudo**.
  Docker access is root-equivalent anyway, and no step needs sudo. Root login and password SSH are off.
- **The host key** is made by Slipway for each droplet and handed to cloud-init. Slipway pins it before the
  droplet exists and trusts only a droplet that answers with exactly that key. Nothing is trusted on first
  contact.
- **No monitoring agent and no droplet agent.** Slipway turns off DigitalOcean's metrics agent and its
  droplet agent (the web console). It reads none of their data, and the console is a way in that it doesn't
  need. You can install either by hand.
- **The root password email.** DigitalOcean emails a root password for every droplet made without one of
  the account's DigitalOcean SSH keys. Slipway doesn't register any. The email is harmless: root login and
  password SSH are both off on the droplet.

A droplet's host reads **Not built yet** until its first deploy makes it, then **Building**, **Ready**, or
**Gone** when DigitalOcean no longer has it.

### A droplet deleted by hand

The next deploy to that slot makes it again, with a new host key that Slipway pins again. If it was the
active slot, nothing answers through the load balancer meanwhile.

The environment page's DigitalOcean card reads DigitalOcean each time the page opens. It lists the droplet as
**Gone**, and for the active slot it says nothing answers and offers **Deploy to <slot>** straight away. The
same read marks the slot's host **Gone** (not while a job of the environment is queued or running, whose own
steps look). From then on the page says so at the top on every view, and offers **Deploy to <slot>** (and
**activate** the other slot, when it has a live release). A deploy to the other slot also notices a droplet
that is gone and marks its host **Gone**.

The deploy puts the new droplet on the load balancer itself, with no Activate. While a slot's droplet is
gone, the data commands run on the other slot.

## What an environment costs

Creating an environment shows an estimate on the Review step:

| Line | Price from |
|---|---|
| One line per droplet size | DigitalOcean's API (`GET /sizes`) |
| The database cluster, per size and node count | Slipway's price table |
| The load balancer | Slipway's price table |
| The Spaces subscription (paid once per account) | Slipway's price table |
| VPC, cloud firewall, certificate | free, listed so every object is named |

The foot of every estimate says `Estimated, prices as of <date>; bandwidth beyond the allowance,
DigitalOcean backups and taxes are extra.`

**Slipway's price table** (`do_rules.PRICES`, dated 2026-11-15) and its list of regions that offer Spaces
(`do_rules.SPACES_REGIONS`) are written in the code and **haven't been checked against DigitalOcean's
pricing page yet**. That check is part of the first real-account run ([phase4-digitalocean.md](phase4-digitalocean.md)
§20.3 item 1). Until then, read the estimate as a guide. Nothing Slipway does depends on the figures beyond
what you confirm.

An admin can override the table per account with **Price overrides**, a JSON object of the same shape with
its own date, in US cents a month:

```json
{"as_of": "2026-12-01",
 "database": {"db-s-1vcpu-2gb": {"1": 3000, "2": 6000}},
 "load_balancer": {"1": 1200},
 "spaces": 500}
```

Any part may be left out; the rest comes from Slipway's table. The estimate's date is the oldest date of
the prices it used.

### Confirming the cost

To create the environment you type the monthly total, such as `84.00`. Slipway then reads DigitalOcean's
prices again. If the total changed since the page showed it, the create is refused with `The estimate
changed to $<x> a month (DigitalOcean's prices moved): check it again`, and nothing is made.

**Add a slot** and **Grow…** (bigger droplet or database, or a standby node) show the new total and the
change from today's, and ask for the new total typed the same way.

With a **monthly limit** on the account, a create, Add slot or Grow that would bring the account's
environments over it is refused: `This would bring <account>'s estimate to $<x> a month, over its limit of
$<y>`.

At run time every create is checked against the plan you confirmed. A step that would make anything else
(a third droplet, a cluster of another size, a second load balancer) fails before it sends the create:
`This would make <object>, which <env>'s confirmed plan doesn't include: ... Slipway changed nothing`.

### While it isn't live yet

An environment that never went live but has DigitalOcean objects shows a **Billing** callout: `<n>
DigitalOcean objects exist for <env> and cost about $<x> a month: retry the failed deploy, or delete the
environment to remove them.` The Environments list marks it too.

## Pending creates and request tags

A create can be sent and its answer lost: a timeout, a restart of Slipway, a cancelled job. Slipway never
sends a second create on a guess. Before each create it writes a **pending row** with a fresh request id,
and sends that id with the create: as the tag `slipway-req:<id>` on a droplet or cluster, in the VPC's
description, or in a key's or certificate's name.

When a step meets a pending row, it looks the object up by that id. Found, it records it (audited
`resource.adopt`). Not found, it looks again: only after two lookups, at least 60 seconds apart and at
least 60 seconds after the send, both say absent does it drop the row and create again. Until then the step
waits up to three minutes, then fails with `A <kind> create from <when> may still appear in DigitalOcean;
retry in a few minutes. Slipway made nothing new`.

The environment page lists pending creates older than ten minutes. The request tags stay on their droplets
and clusters, and DigitalOcean keeps the tag names in the account's tag list after the objects are gone.
They cost nothing.

## Managed data

The environment's data lives in the cluster and the bucket, not on a droplet. Its **data owner** (the
`data` instance) has no host of its own: Backups, restores, resets, snapshots and the first admin run their
commands **on an app slot's droplet**, the data runner:

1. the active slot (or the slot deployed last), when it has a live release and its droplet is built;
2. else the other app slot, when it can (the log says why: `blue's droplet isn't built; running the data
   commands on green`);
3. else, during a deploy, the deploying slot's new release.

When no slot can run them, data jobs are refused with `<env> has no slot that can run its data commands:
deploy to <slot> first`. A managed environment's Deploy never goes to the data owner: there is no data
server to deploy.

Reset empties the database (dropped and made again as the cluster's admin) and the bucket. A bucket or
cluster that is gone under live data isn't remade by itself. The deploy fails, saying that Slipway won't make
an empty one by itself, and the deployment's page offers **Make it again, empty…** (needs `data:reset` and
the typed name). Then restore a backup.

## Backups on Slipway

A droplet can be rebuilt at any time, so a managed environment's backups are **kept on the Slipway
server**, not on a droplet. Each backup is dumped on the data runner, streamed to Slipway, checked against
its hash, encrypted with a key of its own, and only then removed from the droplet. A restore streams it back
for the one job and removes the copy afterwards.

- They live in `<storage dir>/backups/<owner id>/`. The Backups card lists them as **On Slipway** under the
  **Stored** column.
- `SLIPWAY_BACKUP_TOTAL_BYTES` (default 100 GiB) caps all of them together. A backup that wouldn't fit, or
  wouldn't leave the free-space margin, is refused before the dump.
- After a key change that lost the backups' keys, a backup can only be deleted (`Slipway can't open this
  backup any more (SLIPWAY_ENCRYPTION_KEY changed)`).
- A half-copied backup left by a restart is removed when Slipway starts.

**When the environment is deleted**, its backups are moved to `<storage dir>/kept/<env>-<id>/` with a
`README.txt` naming the environment and the date. Slipway no longer lists them; remove the folder by hand.
These files **can't be decrypted afterwards**: each backup's key was kept with its row, and the rows go with
the environment. To keep the data, take a snapshot before you delete (the Delete dialog does that by default).

## Certificates

The `edge` step gets a certificate from Let's Encrypt for the environment's names, proving them with DNS
records in Cloudflare, and puts it on the load balancer. Tick **Let's Encrypt staging** in the flow for a
test environment: staging certificates aren't trusted by browsers, and Slipway's own checks then don't
verify them. Production environments can't use staging.

Slipway renews certificates itself. A loop looks every `SLIPWAY_CERT_RENEW_INTERVAL` seconds (default 21600,
six hours; the first pass five minutes after start; `0` turns it off) at every live DigitalOcean
environment. When the served certificate has 30 days or fewer left, it queues a **Renew the certificate**
job, started by Slipway (`Started by Slipway (certificate renewal)`). It skips an environment with a job
queued or running, and one whose last renewal failed within 24 hours. A renewal it can't queue is audited
`certificate.renew_refused`, at most once a day.

**Renew now** on the environment page queues the same job by hand (needs `traffic:switch`). When the
certificate has 14 days or fewer left and the last renewal failed, the page says so. Activate also renews
first when the certificate doesn't cover the names it is about to serve.

## Sizes and resizes

Sizes only grow. **Grow…** (the DigitalOcean card, `environments:write` and `providers:spend`) sets a bigger
droplet size, a bigger database size, or a standby node. A standby can be added, never removed. The cluster
grows in the next deploy's `database` step.

A droplet is resized in the `resize` step of **its slot's next deploy**, after the backup, so every check
of that deploy comes first and a deploy that is refused never powers it off. The step powers the droplet
off, resizes it and powers it on again (`Resizing <droplet> to <size>: it stops for a few minutes`). A
Single environment is down meanwhile. The active slot of a Blue/Green environment isn't resized while it is
active: deploy to it once it is idle. Until then its row says `Resize pending: applies at <slot>'s next
deploy`.

### A droplet left powered off

If Slipway restarts between the power off and the power on, the droplet stays off. The environment's
notice says `<slot>'s droplet may be powered off: deploy to <slot> again`, and the DigitalOcean card shows
`<droplet> is powered off. The next deploy to its slot powers it on first.` The next deploy to that slot
powers it on before anything else, then goes on as usual.

## Production, retiring and taking off the air

A **production** environment:

- needs a production account, and a production account serves only production environments;
- runs Blue/Green;
- is never activated by itself, and can't use Let's Encrypt staging;
- is the only production environment of its repository and `slipway.yml` (retire the old one first);
- asks for its name typed on Activate and Switch back.

It is removed in three steps:

1. **Retire…** (typed name). A retiring environment still takes deploys and data jobs, but no Activate:
   `<env> is retiring: it only goes dark`. **Un-retire…** takes it back.
2. **Take off the air…** (typed name, `traffic:switch` and `environments:delete`). Slipway takes every
   droplet off the load balancer. The environment's names answer 503 from the load balancer until their DNS
   records are moved or removed, and the page says when it went off the air.
3. **Delete** with a snapshot and the phrase `delete production <name>`. If the data is held but no slot
   can run the data commands, deploy first, or type a second phrase, `delete production <name> without a
   snapshot`. A retry of the deletion asks the phrases again.

## Delete

**Delete environment** (needs `environments:delete`, typed name) lists every DigitalOcean object it
removes, with its monthly price. The cluster and the bucket are the data's only home, so:

- **Take a snapshot first** is ticked by default when the environment holds data and a slot can run its
  commands. The deletion starts once the snapshot is stored.
- Unticking it shows the **Delete <env>'s data with it** box (`drop_data`), which needs `data:reset`.
  Without a snapshot and without that box, Delete is refused.
- An environment that never held data (its first deploy failed before it started the app) needs neither:
  `<env> never held data, so there is nothing to snapshot`.
- When no slot can run the data commands, the snapshot can't be taken: deploy first, or tick the box.

The deletion's steps are `check`, `undns`, `slots`, `data_server`, `cloud` and `forget`. `check` reads
every recorded object first and stops before anything changes if one no longer looks like Slipway's. `cloud`
deletes the droplets, the load balancer, the certificates, the cluster, the bucket (emptied first) and its
keys, the firewall and the VPC, then reads DigitalOcean once more and fails naming anything still there.
Each step can run again, so a **Retry** carries on where it stopped.

**What goes:** every DigitalOcean object Slipway recorded for the environment, the DNS records it created,
the droplets' host rows.

**What stays:** the backups, in `kept/` on the Slipway server ([above](#backups-on-slipway)); snapshots stored
on Slipway; DNS records Slipway claimed rather than created; the environment's row, jobs, logs and audit
trail; the request tag names in the account's tag list.

## Permissions

| Permission | Roles | Allows |
|---|---|---|
| `providers:read` | developer, maintainer, admin | see the accounts (never their tokens), their regions, sizes and prices |
| `providers:write` | admin | add, change, test and remove accounts |
| `providers:spend` | maintainer, admin | confirm a cost: create a DigitalOcean environment, add a slot, grow its sizes |

Everything else is [environments.md](environments.md#permissions)'s: `environments:write`,
`environments:delete`, `traffic:switch` and phase 2's `data:*`. Delete without a snapshot also needs
`data:reset`.

## Settings

| Setting | Default | What it does |
|---|---|---|
| `SLIPWAY_BACKUP_TOTAL_BYTES` | 107374182400 (100 GiB) | all backups kept on Slipway, added up |
| `SLIPWAY_CERT_RENEW_INTERVAL` | 21600 | seconds between renewal passes; 0 turns the loop off |
| `SLIPWAY_ACME_DIRECTORY` | Let's Encrypt's production directory | where certificates come from |
| `SLIPWAY_ACME_STAGING_DIRECTORY` | Let's Encrypt's staging directory | used by environments with staging ticked |

## Timeouts

Each provider step has its own limit: `prepare` 50 minutes, `resize` 60, `database` 65, `edge` 40, Reset's
`wipe` 45; the environment's `certificate` step 45 and the deletion's `cloud` step 75. These are worked out
from the waits inside each step, not yet measured on a real account.

## API

Everything is under `/api/v1`.

| Method and path | Does |
|---|---|
| `GET /provider-accounts?provider=`, `GET /provider-accounts/{id}` | list, show (never the token) |
| `POST /provider-accounts`, `PATCH /provider-accounts/{id}` | add, change (an omitted token keeps the stored one) |
| `DELETE /provider-accounts/{id}` `{confirm}` | remove |
| `POST /provider-accounts/{id}/test`, `POST /provider-accounts/test` `{secret, region?}` | Test a saved account, or a token before it is saved |
| `GET /provider-accounts/{id}/catalog?region=` | regions, droplet and database sizes, PostgreSQL versions |
| `POST /environments` `{placement: {provider: "digitalocean", account_id, region?, slots, droplet_size, db_size, ...}, production?, confirm_cost}` | create (`?check=true` answers the plan and `cost` without making anything) |
| `PATCH /environments/{id}` `{cloud: {droplet_size?, db_size?, db_standby?}, confirm_cost}` | grow |
| `POST /environments/{id}/slots` `{confirm_cost}` | add a slot |
| `GET /environments/{id}/cloud` | each recorded object read live: ok, gone or changed, with its price and power |
| `POST /environments/{id}/certificate` | Renew now |
| `POST /environments/{id}/retire` `{confirm}`, `DELETE /environments/{id}/retire` `{confirm}` | retire, un-retire |
| `POST /environments/{id}/deactivate` `{confirm}` | take off the air |
| `DELETE /environments/{id}` `{confirm, snapshot?, drop_data?, confirm_production?, confirm_no_snapshot?}` | delete |
