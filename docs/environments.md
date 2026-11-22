# Environments

An **environment** is one app, from one repository and branch, that Slipway runs in one or two
**slots**. A slot is an ordinary Slipway instance on one of your hosts. With two slots you get
Blue/Green: every deploy goes to the idle slot, and **Activate** moves the traffic to it. The old
slot keeps running, so going back is a switch, not a rebuild.

This page is for the people who set environments up and run them. The design, with every rule and
message, is [phase3-environments.md](phase3-environments.md). The app side is
[manifest.md](manifest.md#environments-attach-and-server).

Slots can also run on machines Slipway makes itself: droplets on DigitalOcean, or VMs on Proxmox and ESXi.
[Where it runs](#where-it-runs) below gives the choice; [digitalocean.md](digitalocean.md) and
[machines.md](machines.md) describe each in full.

Instances that aren't in an environment work exactly as before.

## Words used here

| Word | Meaning |
|---|---|
| App slot | `blue` or `green`: an instance that runs the app. |
| Data server | `data`: an instance on a host of its own that runs only the app's data services (for ServerSherpa, Postgres and the SeaweedFS file store). Both app slots use it. |
| Data owner | The instance that holds the data: the data server, or the only slot when there is no data server. Backups, the first admin and the data's "dirty" state live on it. |
| Active slot | The app slot that takes the traffic. Nothing is active until the first Activate. |
| Idle slot | The other app slot. It keeps running on the same data, ready to switch back to. |
| Lead slot | The slot Slipway starts first after a data job: the active one, or, with none, the one deployed last. |
| Stale slot | An app slot that a data job stopped, or that was discarded after a failed deploy. Activate refuses it until you deploy to it again. |

## The three shapes

| Shape | Slots | Data | Traffic |
|---|---|---|---|
| Single | `blue` | in `blue`, as a normal instance | each deploy updates `blue` in place |
| Single with a data server | `blue` + `data` | on the data server | each deploy updates `blue` in place |
| Blue/Green | `blue`, `green` + `data` | on the data server | deploys go to the idle slot; Activate moves the app's names |

A single slot with a data server can gain a second slot later. A single slot that keeps its own data
can't: its data would have to move.

The slots are instances named `<env> blue`, `<env> green` and `<env> data`, with the slugs
`<env>-blue`, `<env>-green` and `<env>-data`. These slugs are reserved for the environment while it
exists, even for a slot it doesn't have yet. An environment's name is 2 to 26 lowercase letters,
digits and hyphens, starting with a letter. The limit leaves room for `-green` inside the 32
characters some apps allow for their own names.

## Where it runs

The flow's second step asks **Where** the environment runs:

| Where | Slots run on | Data | Traffic |
|---|---|---|---|
| **Hosts**, each one you added | your SSH hosts, as described on this page | in the slot, or on a data server host | Switchyard, and optionally Cloudflare DNS |
| **Hosts**, with **New VM on <account>** for a slot | a VM Slipway makes on Proxmox or ESXi at the slot's first deploy ([machines.md](machines.md)) | the same: in the slot, or on a data server VM | the same |
| **DigitalOcean** | one droplet per app slot, made by Slipway ([digitalocean.md](digitalocean.md)) | a managed PostgreSQL cluster and a Spaces bucket | a DigitalOcean load balancer, with Cloudflare DNS always on |

A slot can mix: blue on a host you added and green on a new VM, for example. All the new VMs of one
environment use one account and one network.

**Hosts Slipway made** (droplets and VMs) are ordinary rows in the Hosts list, marked with a provider chip
(`DigitalOcean droplet`, `Proxmox VM`, `ESXi VM`) that links their environment and slot, and a build chip:
`Not built yet`, `Building`, `Ready`, `Gone`, and for VMs `Lost`, `Hidden` or `Off` when the hypervisor was
read. They belong to their environment: only its slots run there, and Delete, Reset key, Check before they
are built, and edits of their address or credentials are refused with the reason. Their label and
description can still change. They go when their slot is removed or the environment is deleted.

Slipway trusts such a host's SSH key without anyone pressing Verify: it never trusts a key on first
contact. On DigitalOcean it makes the host key itself and pins it before the droplet exists. On Proxmox it
reads the new VM's key through the guest agent; on ESXi it makes the key and hands it to cloud-init.

On a page of an environment that runs on DigitalOcean or on VMs you also find:

- in the header, `DigitalOcean · <region>`, `Production` and `Retiring` chips;
- callouts for billing objects of an environment that never went live, SSH open to the internet, a gone
  or powered-off droplet, a pending create, a certificate near its end, and an environment taken off the
  air (a VM left off by a resize shows in the environment's notice);
- on DigitalOcean, a **DigitalOcean** card: account and team, region, the load balancer's address, the
  certificate with **Renew now**, the estimate, the sizes with **Grow…**, and every object Slipway recorded,
  read live;
- on the **Slots** card, each made host's size and chips, a `Resize pending: applies at <slot>'s next
  deploy` line, and for VMs their live power (`Running`, `Off`, `Busy: <task>`), **Resize…** and
  **Forget the VM…**;
- for a single slot that keeps its data on a VM, a **VM snapshots** card;
- in the danger zone, **Retire…**, **Un-retire…** and **Take off the air…** for production;
- Delete, Remove slot, Deploy, Add a slot and Retry dialogs that name the droplets and VMs, their prices
  or sizes, and the choices that go with them (a snapshot first, `Delete <env>'s data with it`,
  `Forget the VMs Slipway can't remove`).

## What you need first

1. **Hosts.** One per slot, and in Blue/Green a third one for the data server. Each must be added
   and verified (its SSH key pinned). See [Hosts and their LAN address](#hosts-and-their-lan-address).
   A slot can instead be a new VM ([machines.md](machines.md)); a DigitalOcean environment needs no host
   of yours ([digitalocean.md](digitalocean.md)).
2. **Switchyard**, connected under *Settings → Integrations*, with its **traffic address** set. Two
   slots need it: Switchyard is how traffic moves. See [Switchyard](#switchyard-and-its-traffic-address).
3. **Cloudflare** (optional), if Slipway should publish the DNS records. See [Cloudflare](#cloudflare).
4. **An app that declares it can run this way.** Its `slipway.yml` must have:
   - `data.migrations: expand_contract` for two slots ([the rule](#the-expandcontract-rule-and-the-lag-check));
   - `data.attach`: the `.env` keys that point an app slot at data on another host;
   - `data.server`: which of the app's services run on the data server, its ports and secrets, and
     the commands it uses there;
   - optionally `services.<name>.health`: the path the checks request (default `/`).

   [manifest.md](manifest.md#environments-attach-and-server) describes these keys, and
   [examples/serversherpa.slipway.yml](examples/serversherpa.slipway.yml) is a full example. Without
   `data.server`, an app can still run as a single slot that keeps its own data.

## Hosts and their LAN address

The data server lets the app slots into its database by IP address. For ServerSherpa that is
`pg_hba.conf`, written from `STACK_DB_ALLOW`. Slipway fills that list with each app slot host's
**client address**:

- the host's **LAN address**, when it is set;
- otherwise its **Address for the reverse proxy**, or its hostname.

Whichever is used must be an **IP address**, not a name. Slipway refuses to create the environment,
add the slot or deploy to it otherwise, and says which host to fix.

Set the **LAN address** (on the host's form) when a host has more than one network and its
connections to other LAN hosts leave from an address other than the one Switchyard uses. When you
are not sure, deploy: before anything restarts, a slot's `settings` step signs in to the data server's
database from the slot's host. If the data server refuses it, the step fails with psql's answer. When
that answer is `no pg_hba.conf entry for host "<address>"`, the message tells you to set the host's
LAN address to that address and update the data server.

Rules for where slots go:

- The data server needs a **host of its own**. A container on the same host would reach the database
  from a Docker address, which the data server can't let in by host address.
- Two app slots may share a host. Slipway accepts that with a warning: one host problem then stops
  both.
- Two slots on one host get different ports, as two instances would.

## Switchyard and its traffic address

Connect Switchyard under *Settings → Integrations* as for instances: its URL and an API key with
`hosts.list`, `hosts.get`, `hosts.create`, `hosts.update`, `hosts.delete`, `config.preview` and
`config.apply`.

Then set **Traffic address**: the address where Switchyard serves your sites, such as
`192.168.1.5` or `proxy.example.com:8443` (without a port, 443; or 80 for a name whose TLS mode is
`off`). After a switch, Slipway
requests every name from the Slipway server through that address. It sends the name as the `Host`
header and the TLS server name, so it checks what a visitor would get. Without a traffic address the
check is skipped, and the step ends with a warning saying to set it.

What Slipway does in Switchyard for an environment:

- It makes one Switchyard host per public name. Each carries a note saying the environment manages
  it. Leave that note alone: without it, Slipway no longer touches the host.
- It changes only the hosts it recorded, and only their domains, upstream and TLS mode. Policies,
  headers and other settings you make in Switchyard stay.
- A name already used by a Switchyard host that isn't the environment's is a **blocker**. So is a
  host that serves the name together with other names. Slipway then changes nothing and says which
  host is in the way.
- It applies only when nothing else is waiting in Switchyard's *Review & apply* and Caddy wasn't
  changed outside Switchyard. Otherwise an Activate is refused before it writes anything.

Names that belong to the data server's services (ServerSherpa's `spaces.<domain>`) always point at
the data server. The others follow the active slot.

## Cloudflare

Cloudflare is optional. When it is on, Slipway keeps an **A record** for every public name of the
environment, pointing at one fixed address: your WAN address, which forwards to Switchyard. The
record doesn't change on a switch. On the LAN, the switch happens in Switchyard.

Set it up under *Settings → Integrations → Cloudflare*:

- **Zone**: the domain, such as `example.com`. Every public name of an environment that publishes
  DNS must be inside it.
- **Public IP**: the IPv4 address the records point at. An environment can use another one.
- **Proxied**: the default for new records.
- **API token**: make one in Cloudflare with *Zone → DNS → Edit* and *Zone → Zone → Read*, limited to
  that zone. Slipway stores it encrypted and never shows it again (only its last four characters).
  **Test** checks that the token is active, finds the zone and can read its records. It can't check
  that the token may edit them without changing one.

Slipway marks the records it creates with the comment `Managed by Slipway: <env> (<id>)`. It
changes only records it recorded, and deletes only those it created that still carry that comment.

For each name, the environment page's Traffic card shows one of these:

| Status | Meaning |
|---|---|
| Up to date | The record is Slipway's and right. |
| Will update | The record is Slipway's; its address or proxied flag is different. |
| Will create | No record of any kind is at the name. |
| Covered | No record at the name, but a wildcard such as `*.uat.example.com` already sends it to the right address. Nothing is written. |
| Not Slipway's (**Claim**) | Exactly one A record is there that nobody recorded. It blocks publishing until you claim it. Slipway then keeps it up to date and never deletes it. |
| Blocked | The name is outside the zone, or has a CNAME or AAAA record, or two A records, or another environment's record, or Slipway's record was renamed. Fix it in Cloudflare. |

AAAA records aren't managed. An AAAA record at a managed name is a conflict.

You can remove the Cloudflare settings only while no environment publishes DNS through it.

## Create a Blue/Green environment

Open **Environments → New environment** (needs `environments:write`). The page has seven steps.
Each **Next** asks Slipway to check what you have filled in so far, so a problem shows on the step
that holds it.

1. **Environment**: the name, the repository, the branch, and (under Advanced) the path of
   `slipway.yml`.
2. **Servers**: Single slot, or Blue/Green. A single slot can keep its data on a server of its own.
   Blue/Green is offered only when the branch's `slipway.yml` declares a data server and
   expand/contract migrations. **Where** chooses Hosts or DigitalOcean ([Where it runs](#where-it-runs)),
   and **Production** shows when a production DigitalOcean account exists.
3. **Hosts**: one for Blue, one for Green and one for the data server. Each may be a host you added or
   a new VM. For DigitalOcean this step is **DigitalOcean** instead: the account, region, droplet and
   database sizes, a standby node, and Let's Encrypt staging.
4. **Settings**: the app's settings, optional services and environment variables. Every member's
   `.env` gets them. A variable may not set a key that `data.attach.env` or `data.server.env`
   writes.
5. **Traffic**: the public names, where each one goes, and its TLS mode. Switchyard or none (none
   only for a single slot). Whether to publish DNS records in Cloudflare, at which address, and
   proxied or not. For Blue/Green: whether a deploy that passes its check is activated by itself.
6. **Data**: start empty (with the first admin, when the app has one) or from a snapshot of the same
   app; how many backups to keep.
7. **Review & Deploy**: Slipway creates the environment, starts its first deployment and opens the
   environment page. It lists each new VM, and for DigitalOcean the monthly estimate, whose total you
   type to confirm it.

The app's **secrets are generated when the environment is created**, from `slipway.yml` at the
branch head. Both slots and the data server share them, so sessions and two-factor codes survive a
switch. They are never shown. When a later `slipway.yml` adds a secret, the first job that needs it
generates it once and saves it on the environment.

### What the first deploy does

The first deploy is a chain of jobs. Each has its own log and its own **Retry**. A failure stops the
chain, and a retry that succeeds carries it on.

1. **Update the data server.** Slipway writes the data server's `.env` (only the secrets it needs;
   the others are written empty), starts the data services and records which hosts it lets in.
   Then it publishes the DNS records and creates the Switchyard hosts of the names that follow the
   data server. No app name is routed yet.
2. **Deploy to blue.** Blue's `.env` points at the data server. Slipway signs in to the database from
   blue's host, builds and starts blue (it migrates the empty database), creates the first admin and
   checks blue on its host. Traffic is not moved.
3. **Activate blue.** Slipway checks blue again, makes sure the DNS records are there, points the
   app's names at blue in Switchyard and checks them through Switchyard. The environment is then
   **Live**. When the data started empty, the app's starter content is added now, on blue, because
   it may need the public names.

A single slot that keeps its own data skips step 1.

## Deploy, Activate, Switch back

**Deploy** (needs `deployments:create`) always goes to the **idle** slot. With one slot, it updates
that slot in place, and its names follow it.

A deploy to the idle slot:

1. backs the data up **on the data server**, with the data server's own release;
2. checks that the new release accepts the data's revision, and that the active release still does
   too ([the lag check](#the-expandcontract-rule-and-the-lag-check));
3. starts the idle slot, which migrates the shared database while the active slot keeps serving;
4. checks the idle slot on its host. A failure here is only a warning.

Traffic stays where it is. The `traffic` step says `Traffic stays on <blue>; activate <green> to
move it`. With *Activate automatically* on, Slipway queues the Activate itself, and the Activate's
own check stops it if the slot fails.

**Activate** (needs `traffic:switch`) moves the app's names to a slot. Its steps:

1. **Check**: Slipway refuses, before changing anything, when the slot never deployed, its latest
   deploy failed, it is stale, the data is held or dirty, another job holds the traffic, or the
   Switchyard plan has a blocker.
2. **Start** the slot, when it is stopped.
3. **Smoke test** on the slot's host. A failing name fails the job, and nothing has changed.
4. **DNS**, when it is on. A name that has no record yet must be created first, because Caddy can't
   get a certificate without one. If that fails, the job fails and traffic stays where it was. When
   every record already exists, a Cloudflare problem is only a warning, so a Cloudflare outage never
   blocks a switch back.
5. **Switch**: one plan, one batch of changes, one Switchyard apply. Then Slipway checks the names
   through Switchyard. Only when that check passes does it record the slot as active. On any failure
   (or a cancel, or Slipway stopping) it puts every name back as it was and says
   `Traffic stays on <blue>`.

**Switch back to <blue>** is an Activate of the slot that was active before. Nothing is rebuilt and
no data changes. It can run while a Back up now, or a snapshot that doesn't stop the app, is running.

### The smoke test and the public check

- **Smoke test**: on the slot's host, for each name, `curl` (or `wget` when there is no `curl`) to the
  slot's published port with the name as the `Host` header and the service's health path. 200 to 399
  passes; redirects aren't followed. Each failing name is tried 5 times, 10 seconds apart. Names that
  follow the data server aren't part of a slot's smoke test.
- **Public check**: from the Slipway server, through Switchyard's traffic address, with the name as
  the TLS server name. The certificate is checked, except for names with the `internal` TLS mode
  (`off` uses plain HTTP). 6 rounds 10 seconds apart, or 12 when the switch created a host (Caddy is
  getting its certificate). Only failing names are retried.

## The expand/contract rule and the lag check

With two slots, the idle slot's `start` migrates the database **while the active slot keeps serving
it with the previous release**. That is safe only if each release's migrations add first and remove
later:

- release N+1 adds columns and tables and keeps the old ones working;
- a later release removes what nothing uses any more.

That is what `data.migrations: expand_contract` in `slipway.yml` says. Slipway can't check it, so an
environment with two slots needs the app to declare it.

The rule holds between neighbouring releases only. After a **switch back**, the active slot runs
release N on a database that N+1 migrated. A deploy of N+2 to the idle slot could remove something N
still uses. So before an idle slot's `start`, Slipway runs the **active** release's `accepts` command
on the database's revision. When it answers "no", the deploy fails before anything starts:

> blue (abc1234) already runs on a database migrated past it (revision r42, by green's def5678). A new
> release may remove what blue still uses. Activate green again and deploy to blue, or deploy again
> confirming that this release removes nothing blue uses.

When you know the new release removes nothing (a code fix with the same migrations, say), use
**Deploy again, confirming** on the failed deploy's page, or deploy again and tick **This release
removes nothing <blue> (<sha7>) uses** (`acknowledge_schema: true` in the API). The Deploy dialog
shows that box after a switch back. Without a switch back, the check passes quietly.

Going back to an older commit by deploying it is still refused by `accepts` when the database has
moved on. Switch back is the way back: it needs no `start`.

## When a deploy to the idle slot fails: Discard or Roll back

A deploy that fails after its `start` began leaves the data **dirty**: it may have been migrated part
way. Activate is then refused until it is settled. There are two ways, and Discard comes first.

**Discard <green>** (needs `deployments:create` and `traffic:switch`) keeps the data as it is:

1. it checks that the active slot's release accepts the database's current revision. If not, it
   stops before changing anything and tells you to roll back;
2. it stops green and marks it stale;
3. it smoke-tests the active slot on the current data. If that fails, the job fails and the data
   stays dirty;
4. it marks the data as checked.

Nothing is restored, so nothing users wrote through the active slot is lost. Deploy to green again
when it's fixed.

Discard works because the active slot kept serving the whole time, and because a migration that
failed usually rolled back in its own transaction (ServerSherpa's Alembic does). A migration that
succeeded is one the active slot accepts, by the expand/contract rule.

**Roll back** (needs `deployments:create`, `data:restore` and, with a data server, `data:reset`)
puts the database back as it was in the pre-deploy backup. **Writes made through the active slot
since that backup are lost.** Both app slots are stopped while it runs. Then the active slot is
started again, and the failed slot stays stopped and stale until you deploy to it.

Roll back is offered only while another slot is active. After a successful Activate there is no roll
back: use Switch back (code only), or restore that backup by hand.

**Retry** of the failed deploy is the third choice. It reuses the pre-deploy backup and, when it
succeeds, clears the dirty state.

## Data in an environment

Everything that touches the data runs **where the data is**. With a data server, that is the data
server's host, with its live release: backups, restore, reset, the revision check, file export and
import. Only three commands need the app's code and run on an app slot: `accepts`, the first admin
and starter content.

- **Backups** are files in the data server's `backups/` folder on its host. Slipway takes one before
  every deploy to a slot, every data server update, every restore, roll back and reset, and on
  **Back up now**. They don't depend on which slot is active, and they survive removing a slot.
  Each backup carries the environment's identity keys (for ServerSherpa, the password pepper and
  the 2FA key), even though the data server's own `.env` leaves them empty.
- **Restore, Roll back and Reset** stop **both** app slots before they change the data, because
  restoring under a running app can corrupt the copy. Afterwards, before the job counts as done,
  Slipway starts the **lead** slot with its normal `start`, which migrates the restored data. The
  other slot is started again only if it runs the same commit and the identity keys didn't change.
  Otherwise it stays stopped and **stale**, with `deploy to it before activating it`. If the lead
  slot doesn't start, the job fails and the data is held. The hold text names the stopped slots.
- **Reset** also deletes each app slot's own volumes (for ServerSherpa, the status page's), after
  the same label check as the data server's.
- **Take snapshot** runs on the data server. With *stop the app*, both slots are stopped and started
  again around the export.
- **Create the first admin** and **Add starter content** run on the active slot.

Data actions live on the environment page. On an app slot's own page they are refused with a pointer
to the environment, because the slot shares its data. Wherever a phase 2 dialog asks you to type a
name, type the **environment's** name.

While the data is **held** after a failed restore, roll back or reset, Slipway refuses deploys,
Activate, Discard, starting or restarting an app slot, snapshots, the first admin and starter
content. Retry, restore, reset, roll back, Back up now, removing a slot and Delete stay allowed.

## Updating the data server

**Deploy → The data server** updates it on its own. It is never part of a slot deploy.

- It backs its data up first, then starts its data services. They restart if their images changed,
  and the active slot loses its database connection for a moment.
- It keeps the names that follow the data server up to date in Switchyard. It never touches the
  app's names.
- It smoke-tests the active slot afterwards. A failure is a warning.
- It is refused before `start` when a port the slots use would move (because it was taken):
  `The data server's ports would move (db 5432 → 5433), and the slots' settings name the old ones`.
  Free the port on the data host. Ports normally stay where the first deploy put them.

Update the data server after you add a slot on a new host, or change a host's LAN address, so it
lets that host in. A slot deploy refuses until it does.

## Settings, variables and secrets

Settings, optional services, variables and secrets belong to the **environment**, not to its slots.
Change them on the environment page. They reach each slot on its next deploy, and until then the page
says that the slot keeps the settings it was deployed with.

The environment's variables go into every member's `.env`, the data server's included. Values that
hold a secret, such as the database URL built from the password, are hidden in logs and never
stored in plain text.

If `SLIPWAY_ENCRYPTION_KEY` changes and the old key is lost, Slipway can't read the environment's
secrets. It never makes new ones (that would lock the app out of its own data). Every job of the
environment then fails with `Slipway lost <env>'s secrets (SLIPWAY_ENCRYPTION_KEY changed): put the
old key back first in the list and run slipway rotate-encryption-key`.

## Publish names

**Publish names** (needs `traffic:switch`) brings Switchyard and DNS up to date for what is live,
without a deploy. Use it after a deploy's `traffic` or `dns` step warned, or after you fixed
something in Switchyard or Cloudflare.

It points the data server's names at the data server, and the app's names at the slot recorded as
active. It never moves a name to another slot. Any blocker fails the step with the list, before it
writes anything.

The `traffic` step of a deploy works the same way: a sync that never moves a name to another slot.
An idle slot's deploy doesn't touch Switchyard at all.

## Unresolved switches

If a switch fails and Slipway can't put every name back (Switchyard went away, or someone changed a
host in the meantime), the switch is **unresolved**: traffic may be split between the slots. The
same happens when Slipway restarts in the middle of a switch.

The environment page then says so. Until it is settled, Slipway refuses deploys to the app slots,
Discard, removing a slot, and restore, roll back and reset. It also never syncs the app's names. Still allowed:
Activate (either slot), Resolve, updating the data server, Publish names (only the data server's
names), Back up now, snapshots that don't stop the app, and Delete.

To settle it:

- **Activate** either slot. That points every name at it again; or
- fix the hosts in Switchyard, then use **Resolve** (typed name). Slipway reads Switchyard. When every
  app name points at one slot, it records that slot as active. Otherwise it says which name goes
  where. Resolve also refuses while other changes are waiting in Switchyard, since the hosts then
  aren't what Caddy serves.

## The data server's open ports

Slipway doesn't manage host firewalls: that needs root, and Slipway's hosts may run as a docker-group
user or on Unraid. The data server's access control is the app's own:

- Postgres lets in only the app slots' addresses (`pg_hba.conf`, from `STACK_DB_ALLOW`), and needs
  the password;
- the file store (SeaweedFS) needs its key.

But the ports themselves (for ServerSherpa, `STACK_DB_PORT`, default 5432, and `STACK_SPACES_PORT`,
default 9000) are **reachable from every machine on the LAN**. The environment page's Data card shows
the actual ports and the addresses let in. A host firewall such as `ufw` doesn't stop this, because
Docker's published ports bypass the host's `INPUT` rules.

To limit them, add rules to Docker's `DOCKER-USER` chain on the data server, as root. In this
example, `eth0` is the data server's LAN interface, `10.0.0.11` and `10.0.0.12` are the app slots'
hosts, and `10.0.0.2` is Switchyard (which reaches the file store for `spaces.<domain>`):

```sh
# Postgres: only the app slots' hosts
iptables -I DOCKER-USER -i eth0 -p tcp -m conntrack --ctorigdstport 5432 --ctdir ORIGINAL -j DROP
iptables -I DOCKER-USER -i eth0 -p tcp -m conntrack --ctorigdstport 5432 --ctdir ORIGINAL -s 10.0.0.12 -j RETURN
iptables -I DOCKER-USER -i eth0 -p tcp -m conntrack --ctorigdstport 5432 --ctdir ORIGINAL -s 10.0.0.11 -j RETURN
# File store: only Switchyard
iptables -I DOCKER-USER -i eth0 -p tcp -m conntrack --ctorigdstport 9000 --ctdir ORIGINAL -j DROP
iptables -I DOCKER-USER -i eth0 -p tcp -m conntrack --ctorigdstport 9000 --ctdir ORIGINAL -s 10.0.0.2 -j RETURN
```

- `-I` puts each rule first, so each `DROP` goes in before the `RETURN`s that come ahead of it.
- `--ctorigdstport` matches the port the client asked for, before Docker rewrote it to the
  container's port.
- `-i eth0` leaves traffic between containers on the data server alone.
- Use the addresses Slipway lists as let in (the hosts' LAN addresses when set), and change the
  rules when you add, move or remove a slot.
- These rules don't survive a reboot by themselves. Save them the way your distribution does
  (`netfilter-persistent save` on Debian and Ubuntu, for example).
- Check from another machine afterwards: `nc -vz <data host> 5432` should fail there and work from
  an app slot's host.

**ServerSherpa's `STACK_BIND_IP`** limits which interface Postgres and SeaweedFS listen on. On a
data server with more than one network, bind them to the LAN interface by adding the key to
`data.server.env` in `slipway.yml`, for example `STACK_BIND_IP: "{server.host}"`, which is the data
host's proxy address (use a literal IP when that address is a name). Don't set it as an environment
variable: those reach every member, and an app slot can't bind to the data server's address.

## Add or remove a slot

**Add a slot** (needs `environments:write`) turns a single slot with a data server into Blue/Green.
It needs expand/contract migrations at the branch head, and a host whose client address is an IP and
isn't the data server's. Leave *Update the data server now* ticked: Slipway then updates the data
server so it lets the new host in, and deploys the new slot after it (without activating it).
Otherwise, update the data server first, then deploy to the slot.

**Remove a slot** (needs `environments:delete`, typed name) removes the slot's containers and folder.
Its `.env` is kept in `.slipway-kept` on its host and its volumes stay. The data isn't touched. It is
refused for the active slot (activate the other one first), the only slot, the data server, and the
slot whose failed deploy left the data dirty (discard or roll back first). Afterwards the data server
still lets that host in; update the data server to stop that.

## Delete an environment

**Delete environment** (needs `environments:delete`, typed name) can take a snapshot first (needs
`data:backup`). The deletion then starts when the snapshot is stored.

The deletion is one job with these steps. Each can run again, so a **Retry** carries on where it
stopped:

1. **Remove the Switchyard hosts** Slipway made for the environment, then apply once. A host that no
   longer carries the environment's note is forgotten, not deleted. When other changes are waiting in
   Switchyard, the deletes stay staged and the step warns you to apply them there.
2. **Remove the DNS records** Slipway created. Claimed records are forgotten, not deleted.
3. **Remove Blue and Green**: containers and folders.
4. **Remove the data server**: containers and folder.
5. **Forget** the environment. Its name can then be used again.

If Switchyard or Cloudflare can't be reached, its step fails. Retry it when they are back, or retry
choosing to **forget** the Switchyard hosts and DNS records: Slipway still tries to delete them, and
when it can't, it stops tracking them and leaves them for you to delete.

**What goes:** the Switchyard hosts and DNS records Slipway created; the containers and folders of
every slot and of the data server.

**What stays:**

- the data volumes, on the data server and on the slots (Slipway never removes data volumes);
- the data server's backups, moved to `<deploy root>/.slipway-kept/<env>-data-<id>.backups/` on its
  host, each with an `.identity.env` file holding the keys that backup needs;
- each member's `.env`, in `<deploy root>/.slipway-kept/` on its host (readable only by the SSH
  user; the slots' files hold every secret);
- DNS records Slipway claimed rather than created, and anything Slipway didn't make;
- the images on each host, and snapshots stored on Slipway;
- the environment's row, its jobs and their logs, and the audit trail (an environment is never hard
  deleted).

To remove the data for good, delete the volumes and the kept folder on each host by hand.

An environment on DigitalOcean or on VMs Slipway made is different: its machines, disks and cloud objects
go with it, and so does its data unless a snapshot is taken first. See
[digitalocean.md](digitalocean.md#delete) and [machines.md](machines.md#removing-a-slot-or-deleting-the-environment).

## Jobs, locking and restarts

- An environment runs **one job at a time**, with one exception: an Activate (or Switch back) may
  run while a Back up now, or a snapshot that doesn't stop the app, is running. Anything else waits
  or is refused with `A job is already running for <env> (...); wait for it to finish`.
- The jobs that run on the environment itself are Activate, Publish names, Discard, Remove a slot and
  Delete. They appear in the Deployments list with the environment and no instance.
- **Chains** (the first deploy, an automatic Activate, Add a slot, a snapshot before Delete) are
  started by the job that finished. When Slipway can't start the next job (for example the user lost
  the permission, or Slipway was stopping or restarted), the environment page shows a notice with a
  button that starts it by hand.
- After a restart, a job that was interrupted is failed, as for instances. An interrupted switch is
  marked unresolved. An interrupted delete stays *Deleting*, and only its retry is accepted. A slot
  deploy cut off during `start` leaves the data dirty, and leaves its line in the data server's
  lock, because the migration may still be running. The data server's next job is then refused, as
  for any command left running, until that line ends (after one more `start` timeout) or you stop
  the process the message names.

## Permissions

| Permission | Roles | Allows |
|---|---|---|
| `environments:read` | viewer, developer, maintainer, admin | the Environments pages: slots, traffic, DNS records |
| `environments:write` | maintainer, admin | create environments, change their settings, add slots. Privileged: like `instances:write`, an environment runs its branch's `slipway.yml` commands on every host it uses |
| `environments:delete` | maintainer, admin | remove slots and delete environments (typed name) |
| `traffic:switch` | developer, maintainer, admin | Activate, Switch back, Publish names, Claim a DNS record, Resolve, and Discard (with `deployments:create`); Renew now and Take off the air on DigitalOcean |
| `providers:read` | developer, maintainer, admin | see the DigitalOcean, Proxmox and ESXi accounts (never their secrets) |
| `providers:write` | admin | add, change, test, trust and remove those accounts |
| `providers:spend` | maintainer, admin | confirm a monthly cost: create a DigitalOcean environment, add a slot to it, grow its sizes |
| `machines:write` | maintainer, admin | make VMs for environments, resize them, take and delete VM snapshots, forget a lost VM |

Deploys need `deployments:create`, and also `traffic:switch` when the deploy will go live by itself.
Backups, restore, reset and snapshots use phase 2's `data:*` permissions on the data owner. Roll back
of a failed slot deploy with a data server also needs `data:reset`, because it throws away what the
active slot wrote since the backup. The Cloudflare settings need `settings:write`.

## Limits and timeouts

- At most 50 public names per environment, two app slots and one data server.
- Smoke test: 5 tries, 10 seconds apart, per name; 10 seconds per request.
- Database sign-in check: 10 seconds to connect; the command may take 2 minutes (to pull
  `postgres:16-alpine` the first time).
- Public check: 6 rounds 10 seconds apart (12 when a host was created); 10 seconds per request.
- Switchyard calls: 30 seconds; an apply: 90 seconds; putting names back after a failure: up to 2
  minutes. Cloudflare calls: 30 seconds, with one retry when Cloudflare asks to slow down.
- Activate's `switch` step: 20 minutes in all.

## API

Everything is under `/api/v1`. A job answers `202` with the deployment; a refusal answers `409` with
the reason, a typed name that doesn't match `422`.

| Method and path | Does |
|---|---|
| `GET /environments`, `GET /environments/{id}` | list, show (with the slots and the actions available) |
| `POST /environments` (`?check=true` only checks) | create |
| `PATCH /environments/{id}` | change settings, variables, TLS modes, traffic |
| `POST /environments/{id}/deploy` `{target?: "slot" \| "data", slot?, acknowledge_schema?}` | deploy to the idle slot or the data server |
| `POST /environments/{id}/activate` `{slot}` | Activate or Switch back |
| `POST /environments/{id}/publish` | Publish names |
| `POST /environments/{id}/discard` `{slot}` | Discard a failed idle-slot deploy |
| `POST /environments/{id}/notice/continue` | start the job a stopped chain didn't |
| `GET /environments/{id}/traffic/plan` (`?slot=` for an Activate) | what Switchyard and DNS would change; writes nothing |
| `POST /environments/{id}/traffic/resolve` `{confirm}` | Resolve an unresolved switch |
| `GET /environments/{id}/dns`, `POST /environments/{id}/dns/claim` `{hostname}` | DNS records and their status; claim one |
| `POST /environments/{id}/slots` `{host_id?, machine?, confirm_cost?, update_data_server?}` | add a slot (on a host, a new VM, or DigitalOcean) |
| `DELETE /environments/{id}/slots/{slot}` `{confirm, forget_vms?}` | remove a slot |
| `DELETE /environments/{id}` `{confirm, snapshot?: {name}, drop_data?, confirm_production?, confirm_no_snapshot?, forget_vms?}` | delete |
| `GET/PUT /settings/cloudflare`, `POST /settings/cloudflare/test` | Cloudflare settings |
| `PUT /settings/switchyard` | gains `traffic_address` |

DigitalOcean's routes (accounts, the cost, `GET .../cloud`, retire, take off the air, renew) are listed in
[digitalocean.md](digitalocean.md#api), and the VM routes (machines, resize, Forget, VM snapshots, free
addresses) in [machines.md](machines.md#api).

Instance endpoints called on a slot refuse what belongs to the environment (its settings, deploy,
delete, proxy sync, and data actions on an app slot that shares a data server), each with a message
that says where to do it instead. Name changes and start, stop and restart still work, except that a
stale slot can't be started.
