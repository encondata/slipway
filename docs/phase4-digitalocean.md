# Phase 4 design: DigitalOcean

Branch `machines`. This is the design for phase 4 of bringing Sirdar into Slipway: DigitalOcean accounts, droplets made as Slipway hosts, the `managed` data mode (managed PostgreSQL and a Spaces bucket), the `do_lb` traffic backend, certificates, the VPC and cloud firewall, sizes and regions, cost safety, teardown, and the production safeguards Sirdar had. It builds on phase 3 (`docs/phase3-environments.md`, "P3" below), which is built and is the contract, and on phase 2 (`docs/phase2-data-safety.md`, "P2").

**References.** `SD/` is Sirdar's `sirdar/api/src/sirdar_api/deploy/`, `SR/` its `api/routes/`, `SM/` its `api/migrations/versions/`, `ST/` its `api/tests/`, `SW/` its `web/src/` (all in `repos/BaseCampV3-sirdar`). `SS/` is BaseCampV3 on branch `slipway-manifest`. Slipway line numbers are given only for files phase 3 does not change (`services/ssh.py`, `services/hosts.py`, `services/snapfile.py`, `core/config.py`, `core/crypto.py`); everything phase 3 builds is cited by P3 section.

**Settled and taken as given.** No Sirdar environment survives and nothing is imported. Switchyard is the only LAN proxy; it plays no part on DigitalOcean. No portal sign-in. One engine: Slipway's shell steps over its own SSH, no Ansible. Terraform and pyvmomi are phase 5. No real cloud call is made by any test: the DigitalOcean API runs on `httpx.MockTransport`, Spaces and ACME too.

**What P3 §14 and §10.9 fixed, and where this spec honours it.** `data_mode = managed` takes its endpoints from `resources` through the same `data.attach` and `{data.*}` values (§10.2). The data owner is still a `slot = data` instance that runs no containers; its commands run through a member session on an app slot's droplet; its Backup, FirstAdmin and dirty-state rows never move; backups move to the Slipway server (`Backup.location`) (§10.6). The `postgres` need's `database`, `user` and `password` secret are what the role and database are made from, with `tls: require` and the cluster's CA (§10.3). Droplets are `Host` rows with `provider = digitalocean`, `provider_id`, a pre-pinned `host_key` and `owner_environment_id`; teardown destroys owned hosts after `slots` (§9, §15.11). `do_lb` implements `TrafficBackend` with join, health, settle, public check, drop, prove, put back (§11.6). Production and the delete phrase are environment flags (§13).

**Where this spec departs from P3 §10.9, and why.** P3 §10.9 says nothing in `traffic.switch` changes for `do_lb`. That can't hold, and slice S05 makes `traffic.py` backend-neutral in these tested ways: (1) the lock comes from the backend (`backend.lock(ctx)`), and is threaded through `switch`, `sync` and the shielded put-back (`_shielded_put_back`, whose duck-typed `put_back_locked` becomes part of the protocol); Switchyard's returns `switchyard.lock` (`_lock` is only its alias), so P3's behaviour is unchanged; (2) a fourth mode, `deactivate`, which `context()` and `switch()` accept, with its own plan, apply and verify (§11.6), because P3's `verify` is the public check, which a Deactivate fails by design; (3) `sync` hands its Switchyard-specific body to the backend and then calls the backend's `repair` hook, through which `do_lb` writes, but only to put the **recorded active** slot's droplet back on the load balancer (§11.6 "sync repair"), never to move traffic to another slot (P3 I6 holds); (4) `traffic.plan_for` and, later, `api/v1/environments._plan_blockers` ask for Switchyard's settings only when the backend is Switchyard; (5) `public_check` gains `insecure` (Let's Encrypt staging) and backend-neutral texts (a `via` label naming the path). P3's own tests and the phase 3 golden files keep passing (S05's "done when").

**Revision.** This revision answers the critique (`scratchpad/phase4/critique.md`). Appendix A gives each point's verdict and where it is handled.

**Reconciled with phase 5.** The build plan for phases 4 and 5 (`scratchpad/phase45/plan.md`) settled where this spec and `docs/phase5-machines.md` ("P5") disagreed, in its section Decisions (numbered 1-46, cited below as "Decision n"); this text states those decisions. Droplets are not rows of P5's `machines` table (Decision 1). What the two phases share is one `provider_accounts` table and a host-level contract: `hosts.provider_state` with a common `phase` key (`planned | creating | ready | gone`), `Host.is_built`, `ssh.HostNotBuilt`, one owned-host refusal, one address-holder check, and one `prepare` and one `resize` step key that the deployer dispatches by provider (§3.3, §14.2). The implementation slices are the plan's (§21).

**Built.** Phase 4 is built, with phase 5, on branch `machines`, against fakes only; the real-account run (§20.3) is still to do. §23 records where the code differs from this text, slice by slice, and what is still open; where the two disagree, §23 describes the code. How to use it is [digitalocean.md](digitalocean.md).

---

## 0. Decisions and why

| # | Decision | Why |
|---|---|---|
| D1 | **Accounts are rows of one `provider_accounts` table shared by the three providers** (`digitalocean` here; `proxmox` and `esxi` are phase 5's), any number, each with a name, a `production` flag, the API token (the `secret` column, EncryptedText, write-only) and, in its `config`, a default region, the team it answers for, the SSH sources for the cloud firewall, an optional monthly limit and optional price overrides (§3.1). | Sirdar had two fixed rows, `production` and `development` (`SD/do_accounts.py:29-30`). The integration plan's "production and development" is kept as the flag: a production environment needs a production account and a non-production one may not use it (§13), which is what the two rows were for. Named rows also hold phase 5's credentials without a second table. |
| D2 | **No renewal token.** Droplets get no DigitalOcean token and no ACME key. Slipway is the only issuer and renewer of the load balancer's certificate (DNS-01 through Cloudflare, from the Slipway server). It writes no `SS_CERT_*` keys, so ServerSherpa's cert-worker idles. | Sirdar's second token existed only so the cert-worker on each droplet could renew by HTTP-01 (`SD/do_accounts.py:1-7`, `SD/do_envs.py:358-366`; `SS/api/src/serversherpa/certs/worker.py:1-16`). With it, a broken droplet could rewrite the load balancer, and two issuers raced: Sirdar's switch and renewal both had to accept a certificate the worker had swapped in meanwhile (`SD/do_provision.py:1282-1300`, `:1339-1366`). The worker already idles when its keys are unset (`worker.py:379`). |
| D3 | **An environment is frozen on the team its token first answers for** (`environments.provider_team`). Every DigitalOcean step reads `GET /account` first and refuses another team before any write. Saving a token of another team is refused while live environments use the account. | Sirdar's team freeze (`SD/do_provision.py:442-457`, `:1130-1141`; `SD/do_accounts.py:252-266`). A token swapped for another team's would otherwise create a second set of objects there and lose track of the first. |
| D4 | **Droplets are ordinary `Host` rows** (`provider = digitalocean`, `provider_id` = droplet id, `owner_environment_id`), made **planned** at environment create so slot instances have a `host_id` (P3 §14's phase 5 idea, used here too). `provider_state.phase` is `planned`, `creating`, `ready` or `gone`. Slipway makes one SSH client key per droplet host (stored as any key host's) and a fresh ed25519 **host key pair** for each droplet create; the public half becomes `hosts.host_key` **before** the create is sent, and is never cleared while the host is `creating`. The private half exists only in the create's user-data: Slipway never stores it. | Every deploy, log, control and data mechanism then works on droplets unchanged (P3 D1). Sirdar delivered a generated host key through cloud-init and trusted only it (`SD/cloudinit.py:75-93`, `SD/do_provision.py:922-943`); writing it into `host_key` up front means `ssh.connect` (`services/ssh.py:530-594`) checks against a pin on the very first connection. There is no trust on first use. A droplet whose create answer was lost is then still checked against the key written before the POST (DigitalOcean never returns `user_data`). Slipway never needs the private half after the POST, so keeping it would be a secret at rest for no gain. |
| D5 | **One manifest, then three provisioning steps, at the front of every slot deploy on DigitalOcean.** The step list starts `resolve` (Slipway server, GitHub only), then `prepare`, `database` and `edge`, then P3's `source, upload, manifest…`. `prepare` first reads slipway.yml **at the resolved commit** through GitHub (`gh.get_file(repo, path, sha)`, the call P3 §9.1 uses) and stores its hash; `manifest` later checks the uploaded file has that hash. `prepare`: team, the frozen edge values, VPC, cloud firewall (SSH rule only), bucket and its key, this slot's droplet, pin, Slipway's address, cloud-init. `database`: cluster, trusted sources, role and database. `edge`: certificate, load balancer, the firewall's load-balancer rule. Each is idempotent: it makes what is missing and fixes drift, and never replaces what exists. Only the deploying slot's droplet is made. A new droplet size is applied later in the same deploy, by the shared `resize` step after `backup` (D15, §9.4), never by `prepare`. | Sirdar's step 0 in the same order (`SD/do_provision.py:420-440`). The three steps use manifest values (`edge.port`, `edge.health`, the routes, `data.managed.db`), so they must read the same commit the rest of the deploy uses; reading it before `resolve` would mean either the previous release's manifest (none on a first deploy) or a branch head that can move. Three steps give each its own timeout and a log a person can read. A deploy to green must not touch blue's droplet; Sirdar ensured every slot's droplet on every run (`:664-715`) but grew only the deploy slot's (`:717-733`). |
| D6 | **Managed data mode.** The data owner is a `slot = data` instance with **no host** (`instances.host_id` becomes nullable for it alone) and no folder. Its commands run through the **data runner**: the lead slot's live release on its droplet; when the lead slot's droplet isn't built, the other app slot's live release; with neither, in a slot deploy, the deploying slot's new release (§10.4). | P3 §14 and D3: the owner never moves, so backups, the first admin and the dirty state stay in one place. A host row for the owner would have to point at one of the droplets, which come and go. The fallback keeps backups, snapshots and the next deploy working when one droplet is gone. |
| D7 | **Backups of managed data live on the Slipway server**, encrypted per backup with the snapshot container (`services/snapfile.py:428`), under `SLIPWAY_STORAGE_DIR/backups/<owner id>/`. The dump is written on the data runner's droplet, checked there, streamed to Slipway and deleted from the droplet. | Teardown destroys droplets, and `prepare` rebuilds a gone one empty; a backup kept on a droplet dies with it. Sirdar kept dumps on whichever slot ran them (sirdar-envs-slots §7). DigitalOcean's own daily cluster backups can't be checked by Slipway and restore only into a new cluster; they are left as they are and named on the page. |
| D8 | **The managed database is made in its trusted-sources lock from the first second**: `rules` (the environment's recorded droplets) go in the create body, and every `database` step reconciles them before anything uses the database. The role and database are made over SSH on the slot's droplet as `doadmin`, with the SCRAM verifier of the environment's secret, never the password, and the password and CA on stdin. | Sirdar (`SD/do_provision.py:848-856`, `:894-920`, `:945-961`; `SD/pgauth.py:21-50`). A cluster without rules accepts every address. The verifier keeps the plaintext out of the server and its logs. The client is `postgres:<version>-alpine` through Docker, as ServerSherpa's own client is (`SS/deploy/stack/ss-stack:265-287`), so cloud-init installs no PostgreSQL package. |
| D9 | **Spaces through S3 SigV4**, Sirdar's client ported (`SD/spaces.py`, `SD/s3sig.py`). A temporary full-access key creates, empties or deletes the bucket and is deleted in a `finally`; the bucket's own read-write key goes to the app. CORS comes from the manifest. | The DigitalOcean API can't make buckets (`SD/spaces.py:1-20`). A key scoped to one bucket limits a leaked `.env`. Sirdar hard-coded the CORS apps (`SD/do_provision.py:88`). |
| D10 | **`do_lb` is phase 3's `TrafficBackend`** (P3 §10.2, §10.9): `plan` reads; `apply` joins the new droplet, checks its own health over SSH, waits the load balancer's settle time, runs the public check through the load balancer, drops the old droplet, waits again and proves the switch by re-reading; `verify` runs the public check once more; `put_back` puts the previous `droplet_ids` back. Mode `deactivate` empties the targets and verifies that they are empty. Mode `sync` writes only to put the recorded active slot's current droplet back (the "sync repair", §11.6, through the backend's `repair` hook). It never takes `switchyard.lock`: its lock comes from `backend.lock(ctx)` (S05). | Sirdar's `_go_live` (`SD/do_provision.py:1219-1311`). Join-then-drop means no gap: the old droplet serves until the new one passed through the real path. Re-reading catches another writer. Sirdar's `_go_live` also ran on every single-slot deploy and added the droplet when the load balancer lacked it (`:1237-1263`); without the sync repair a rebuilt droplet or a remade load balancer would leave the site with no target and no way to add one. |
| D11 | **The load balancer is made with no targets.** Its `droplet_ids` are written only by Activate, Switch back, Deactivate and the sync repair. `edge` never writes them. | Sirdar's step 0 set targets only on a load balancer it created, and then only the active slot's (`SD/do_provision.py:26-30`, `:1050-1053`). With no targets at create, `edge` can't move traffic even on a rebuild, which is what P3 I6 asks; the sync repair then adds the recorded active slot back, and only that slot. |
| D12 | **Certificates**: Let's Encrypt by DNS-01 through the Cloudflare integration, uploaded as a `custom` certificate named `slipway-<env>-<UTC yyyymmddhhmm>`. It covers the **union** of the active-following names of every app slot's live release, plus the deploying slot's new release during a deploy. A name leaves only when no slot's live release serves it any more. An issued chain and key are kept encrypted on a pending row until the upload is recorded, and reused on a retry. Renewed at **30 days or fewer** by a background loop that queues a `certificate` job; a failed renewal backs off 24 hours. | DigitalOcean's own `lets_encrypt` type needs DigitalOcean DNS, and the zone is in Cloudflare (sirdar-digitalocean §10). Sirdar renewed at 14 days because the worker went first at 30 (`SD/certs.py:23-24`); with one renewer, 30 days leaves room for two weeks of failures. Names come from the manifest; Sirdar's fixed list lacked `learn` (`SD/certs.py:26`). The union means a deploy to the idle slot can never drop a name the live slot (or the Switch back target) still serves. Keeping the issued certificate means a failed upload never orders the same names again: Let's Encrypt allows 5 certificates per identical name set per 7 days. |
| D13 | **One VPC per environment** (`slipway-<env>`, DigitalOcean's default range, Slipway's marker in its description). Its range becomes `{edge.trusted}`. | Sirdar (`SD/do_provision.py:459-497`). ServerSherpa's Caddy trusts `X-Forwarded-For` only from that range (`SS/deploy/stack/proxy/Caddyfile:9-20`). |
| D14 | **The cloud firewall exists before the first droplet and lets SSH in only from the account's `ssh_sources`.** `prepare` makes it with the SSH rule only, before `POST /droplets`; it applies by the environment's tag, so it covers a droplet from its first boot. `edge` adds the HTTP rule from the load balancer with a PUT. Outbound is open. `ssh_sources` is required when the account is saved; `0.0.0.0/0` may be typed and is then shown as a warning everywhere. On the first connection to each droplet Slipway reads `$SSH_CONNECTION` and records the address it connects from (`cloud.slipway_addresses`). An account save whose sources would leave out a recorded address is refused, and after any change to the SSH rule Slipway opens a fresh SSH connection and puts the previous rules back if it fails. | Sirdar opened SSH to the world (`SD/do_provision.py:298-311`), flagged as its weak point (sirdar-digitalocean §12); making the firewall in `edge` would repeat that for the whole first run. Slipway can't learn its own egress address before the first droplet without asking an outside service, so the person states it; once a droplet answers, the droplet tells Slipway the address it sees, and Slipway then guards against locking itself out, which would stop every backup and snapshot and so block a production delete. |
| D15 | **Region fixed at create; sizes grow only.** Region, droplet size and database size are checked live against `GET /regions`, `GET /sizes` and `GET /databases/options`. A PATCH may grow the droplet size (same family, at least as large in vCPUs, memory and disk, larger in one), the database size, or add a standby node, never the reverse. A new droplet size is applied by the next deploy to each slot, in its `resize` step after `backup` (so every refusal of that deploy comes first and a deploy that refuses never powers the droplet off), never to the active slot of two. `edge.port`, `edge.health` and `data.managed.db.version` are **frozen** in `environments.cloud` (the version at create, the port and path at the first `edge`); a release that changes one fails `prepare` before any write. | Sirdar (`SD/do_envs.py:114-202`, `SD/do_provision.py:717-733`, `:793-815`, `:863-879`). A resize stops the droplet and grows its disk, which can't be undone. The load balancer's forwarding rule, health check and firewall rule are shared by both slots, so an idle-slot release that moved them would move them under the live slot too; a cluster's major version can't be changed back. |
| D16 | **Cost safety: nothing billable is made without a typed confirmation of its monthly estimate.** Create, Add slot and a size PATCH answer `?check=true` with every object that will exist and its estimated monthly price, and need `confirm_cost` equal to the total (`"84.00"`, the figure shown). The confirmed plan is stored; `prepare`, `database` and `edge` refuse at run time to make anything it doesn't cover, counting recorded rows, pending rows and live tagged objects. An account's optional monthly limit refuses a create that would pass it. | Sirdar showed no prices. Typing the total proves the person read it, where a tick box doesn't. The run-time check means a later bug or a changed manifest can't make a second load balancer or a bigger cluster nobody confirmed; counting pending rows and live objects means an object whose answer was lost still counts. Droplet prices come from `GET /sizes`; the rest from a dated table (D17). |
| D17 | **Prices that the API doesn't give come from a table in code** (`do_rules.PRICES`, with its `as_of` date), which an admin may override per account (the account's `config.prices`; there is no install-wide override). Every estimate says `Estimated, prices as of <date>; bandwidth and backups are extra`. | `GET /sizes` carries `price_monthly`; the database options, load balancers and Spaces don't, as far as Sirdar's client shows (`SD/do_api.py:196-200`). A wrong table is a wrong estimate, so its age is always shown and a real-account check compares it (§20.3). |
| D18 | **An intent row before every create; the real row the moment DigitalOcean answers.** Before any billable or credential-bearing create (droplet, cluster, VPC, firewall, load balancer, certificate upload, bucket, Spaces key) Slipway commits a **pending** `resources` row (`provider_id = "pending:<nonce>"`, `details.pending = {nonce, sent_at, body_hash}`), and puts the nonce where DigitalOcean keeps it (§6.4). The answer replaces the pending row in one commit, with its credentials. A pending row is never created around: the next step looks the object up (by nonce or by its fixed name), adopts what it finds, and sends the create again only after two lookups at least 60 s apart both say absent. Half-made objects stay recorded and cost money until Retry or Delete; a recorded object that is gone is forgotten and made again (inside the confirmed plan); one that no longer matches stops the step with `Slipway changed nothing`. The environment page shows a **Billing** callout while a never-live environment holds objects. | Sirdar's record-before-wait and adoption rules (`SD/do_envs.py:6-8`, `:426-439`; `SD/do_provision.py:15-24`, `:735-745`) cover a lost answer only when the object is already listed by the time of the retry. A quick retry, a cancel or a step timeout during the POST would otherwise make a second droplet that bills, and the run-time plan check couldn't see it. DigitalOcean's lists can lag a create, hence two lookups apart. A failed first deploy can leave a database cluster running for days unnoticed; the callout names the monthly cost. |
| D19 | **Teardown finds every object before it checks any, and checks every object before deleting any.** The `cloud` step first runs every adoption rule of §6.2 for every kind (strays and lost answers included) and records what it finds, then checks all, then deletes in Sirdar's order: load balancer, certificates, firewall, droplets (and their host rows), database, Spaces keys, the bucket (emptied first), the VPC. It runs the find again at the end, after its own temporary key is deleted, so a lost answer of that run is caught too. `resources.environment_id` stays `ON DELETE RESTRICT` and P3's `forget` step still requires no rows left. | Sirdar's step 18 (`SD/do_provision.py:1396-1450`, `:1541-1587`) swept only droplets and clusters, so a load balancer, bucket, firewall, certificate or a full-access setup key whose answer was lost outlived "Nothing of <env> is left". Deleting before checking could remove half and stop at an object someone renamed, leaving a mess with no record of why. |
| D20 | **Production is an environment flag set at create.** A production environment runs Blue/Green, on a production account, without auto-activate or staging certificates. Activate and Switch back need its name typed. It is deleted only after **Retire** (typed name), once nothing is live (**Deactivate**, typed name), with a **snapshot first** and the phrase `delete production <name>`, checked again on every retry. The snapshot is skipped when the data owner never held data; when it holds data but no runner can be reached, a second phrase `delete production <name> without a snapshot` replaces it (§13). At most one non-retiring production per repository and manifest path. | Sirdar's rules (`SM/0010:65-71`; `SR/deploy.py:745`, `:1153-1177`, `:1267-1280`, `:1334-1335`, `:1615-1617`; `SD/do_envs.py:74-107`, `:283-289`). The per-repository scope replaces Sirdar's global one because Slipway runs many apps; it keeps the "new production built while the old one retires" cutover. |
| D21 | **DigitalOcean environments always use `data_mode = managed`, `traffic.switch = do_lb` and Cloudflare DNS**, with one or two app slots named `blue` and `green`. | Sirdar's DigitalOcean environments always had a managed database, a load balancer and DNS (`SD/environments.py:514-518`, sirdar-digitalocean §4). A single droplet holding its own data is cheaper, but teardown or a rebuild would destroy its data; it is open question 6. P3's slot names stay (Sirdar's `orange`/`purple`, `SD/do_envs.py:27-29`, are not kept). |
| D22 | **slipway.yml gains `edge`** (how the app serves its names behind a cloud load balancer: the port, the health path, `.env` keys, extra projects) **and `data.managed`** (per need: the engine version, the database, user and password secret, the CORS apps; the services that don't run; managed-only `.env` keys; command overrides). | Caddy on :80, the `/healthz` path, `STACK_CADDY`, the Docker subnet, Caddy's address, `STACK_TRUSTED_PROXIES`, the database and user names, the CORS apps were all ServerSherpa knowledge Sirdar hard-coded (`SD/do_envs.py:33-36`, `:348-357`; `SD/do_provision.py:87-88`, `:263`). |
| D23 | **Phase 2's data features all work on managed data**, through P3's mode `server` lists with the data runner in place of the data server. Reset empties the database (as `doadmin`, in a form a cut-off run can repeat) and the bucket instead of removing volumes. Backup check, retention and delete branch on `Backup.location` in `data.py` itself. | Sirdar refused restore, reset and roll back on DigitalOcean (`SD/pipeline.py:135`, `:306-312`). P3 already makes them safe on shared data (stop both slots, lead slot first, D16 of P3). |
| D24 | **Cloud-init is minimal and from the distribution**: hostname, the `slipway` user (docker group, no sudo, locked password, Slipway's key), the generated host key only, no password SSH, no root, `docker.io` and `docker-compose-v2` from Ubuntu 24.04's archive, `/opt/slipway` owned by `slipway`, and a ready marker. The user's name is `cloudinit.GUEST_USER`, the same user phase 5's VMs get (they keep passwordless sudo; droplets get none). The droplet is made with `monitoring: false` and `with_droplet_agent: false`. | Sirdar's user-data minus the PostgreSQL client (D8) plus Docker (`SD/cloudinit.py:75-93`, `:114-127`). No `curl | sh`. DigitalOcean's `monitoring: true` installs its agent through vendor-data from its own script, which is a `curl | sh` in all but name, and Slipway reads none of its metrics. Its droplet agent (the web console) is installed the same way unless the body turns it off, and Slipway never uses it. Slipway's hosts already run as docker-group users (P3 D19); sudo is not needed by any step. |
| D25 | **The DigitalOcean client is Sirdar's `do_api.py`, merged with `digitalocean.py`'s reads**: one seam, 30 s timeout, 200 per page, at most 10 pages, one retry after a 429 (writes too), one retry of a GET on 502/503/504, no other retried write, IDs checked before they go into a path, and DigitalOcean's `message` never kept. **Only a 404 means gone.** A 403 (or 401, or any other error) on a read stops the step and never forgets a row. | `SD/do_api.py:1-13`, `:64-189`; sirdar-digitalocean §18 asks for the merge. A 429 means DigitalOcean did nothing, so sending a write again can't make a duplicate. Other writes are never retried because they may have landed; a lost answer is what the intent row (D18) is for. The custom-scoped tokens §8's hint asks for answer 403, not 404, for a kind they can't read; reading that as "gone" would forget a billing object and make a second one. |
| D26 | **New permissions**: `providers:read`, `providers:write` (admin only: tokens can spend money; it covers every account write of every provider, Proxmox and ESXi included) and `providers:spend` (confirm a cost: create, add slot, grow). Phase 5 adds `machines:write` for VMs (§4.1). | Integration doc decision 4. Spending is separate from configuring an environment, so a maintainer who may edit settings needn't be able to start a database cluster. |
| D27 | **An idle-slot deploy never changes what the live slot is served through.** The certificate only gains names during a deploy (D12); the port, health path and database version are frozen (D15); `droplet_ids` are never written by `edge` (D11). | P3 I6 in spirit: the live slot shares the load balancer, its certificate and the firewall with the idle one. |
| D28 | **A gone active droplet can be rebuilt by deploying to it.** P3 §9.3's refusal of a deploy to the active slot doesn't apply when the active slot's droplet host isn't built (`not Host.is_built`: `planned`, `creating` or `gone`): it serves nothing. Nor while a rebuild left it built with no live release (its old one moved to `app_state.gone_live` and none went live since, `jobs.release_gone`), so a failed rebuild deploy can be retried or deployed again. Its `traffic` step is then the sync repair, which puts the new droplet on the load balancer. | Neither of the old ways out worked: deploying to the idle slot ran its pre-deploy backup on the gone droplet, and activating an idle slot that was never deployed is refused. |

---

## 1. Invariants

- **J1. Nothing changes for SSH environments and standalone instances.** P3's golden tests (P3 test 44) pass unchanged, plus a phase 4 golden for a P3 Blue/Green environment (test 70).
- **J2. No billable object without a confirmed cost.** Every DigitalOcean create is inside `environments.cloud.plan`, which a person with `providers:spend` confirmed by typing its monthly total. A step that would make anything else fails before the create.
- **J3. Record before send, and again before wait.** Before any DigitalOcean create a pending `resources` row is committed; the answer replaces it in one commit, with any secret the answer carries, before Slipway waits for the object or does anything else (D18, §6.4).
- **J4. Only what Slipway recorded and still matches.** Slipway changes or deletes a DigitalOcean object only when a `resources` row names it and the live object still carries the marks of §6.2. Anything else in the way stops the step before any write.
- **J5. Check everything before deleting anything.** Teardown and Remove slot read every object they will delete and check its marks first.
- **J6. Droplets are trusted only by the host key Slipway generated.** `hosts.host_key` is written before the first connection; a droplet that answers with another key gets nothing.
- **J7. No DigitalOcean token and no ACME key on a droplet.** No `.env` key, file or argument carries one.
- **J8. The managed database is never open to every address.** Its trusted sources are in its create body and are reconciled before any step uses it.
- **J9. One team per environment.** A token that answers for another team writes nothing.
- **J10. Production can't be lost by one click.** It is deleted only when retiring, dark, snapshotted and confirmed with the phrase; its traffic moves only with its name typed.
- **J11. Managed data's backups are on the Slipway server, encrypted.** No backup of managed data lives only on a droplet.
- **J12. No create while one may be in flight.** A step never sends a create for a kind and name that has a pending row, until lookups say the earlier one is absent (§6.4).
- **J13. Only a 404 means gone.** A 401, 403 or any other error on a read stops the step; no row is forgotten and nothing is made again because of it.
- **J14. Slipway never firewalls itself out.** SSH is never open to more than `ssh_sources`, and no change to the SSH rule stays in place unless a fresh SSH connection succeeds after it (§11.4).
- **J15. An idle-slot deploy never changes what the live slot serves** (D27).

---

## 2. Concepts

| Term | Meaning |
|---|---|
| Account | A `provider_accounts` row: a DigitalOcean API token and what goes with it (D1). |
| Placement | Where an environment runs: `ssh` (P3, hosts chosen by hand) or `digitalocean` (this phase). Stored as `environments.provider`. |
| Droplet host | A `Host` with `provider = digitalocean`, owned by one environment, made, rebuilt and destroyed by it. |
| Data runner | The member a managed owner's command runs through: the lead slot's live release on its droplet; else the other app slot's live release; else, in a slot deploy, the deploying slot's new release (D6, §10.4). |
| Pending row | A `resources` row written just before a create, holding the nonce that finds the object if the answer is lost (§6.4). |
| Edge | The load balancer, its certificate and the cloud firewall: what sits between the internet and the droplets. Also the manifest section that says how the app serves behind it. |
| Plan (cost) | The list of DigitalOcean objects an environment may have, with sizes, counts and estimated prices, as confirmed (§12). |
| Production | An environment with `production = true` (§13). |

Shapes on DigitalOcean (always `managed`, `do_lb`, Cloudflare DNS):

| Shape | App slots | Objects |
|---|---|---|
| Single | `blue` | VPC, 1 droplet, database cluster, bucket + key, load balancer, certificate, firewall |
| Blue/Green | `blue`, `green` | the same with 2 droplets; green's droplet is made by its first deploy |

---

## 3. Data model and migrations 0010 and 0011

New model file `slipway/models/provider.py` (`ProviderAccount` and the enum `ProviderKind`: `digitalocean`, `proxmox`, `esxi`), imported in `models/__init__.py`. Phase 5's tables (`machines`, `machine_snapshots`, `terraform_states`, `address_claims`) are in `slipway/models/machine.py`; droplets never use them (Decision 1).

### 3.1 `provider_accounts`

One table for the three providers (Decision 2; P5 §3.1 is the same table).

| column | type | notes |
|---|---|---|
| id, created_at, updated_at | UUIDPrimaryKey, Timestamps | |
| provider | String(16) NOT NULL | `digitalocean`, `proxmox` or `esxi` |
| name | String(64) NOT NULL UNIQUE | across every provider; `^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`, checked in the service |
| production | Boolean NOT NULL default false | D1, §13; only a DigitalOcean account can be one |
| secret | EncryptedText NULL | DigitalOcean: the API token (Proxmox: the whole token, ESXi: the password); write-only; NULL means "not set" |
| secret_hint | String(16) NOT NULL default `''` | the token's last 4 characters |
| config | JSON NOT NULL default `{}` | DigitalOcean: `{region, ssh_sources, monthly_limit_cents, prices, team: {id, name} \| null}`. `region` the default region, `^[a-z]{3}[0-9]$` (`SD/do_accounts.py:31`); `ssh_sources` 1-10 CIDRs (IPv4 or IPv6), required before the account can build (D14); `monthly_limit_cents` D16, null is no limit; `prices` an admin's override of `do_rules.PRICES` for this account (D17), same shape, checked by `do_rules.check_prices`; `team.id` is `team.uuid`, else `personal:<uuid or email>` (`SD/do_accounts.py:196-207`). Proxmox and ESXi: P5 §3.1 |
| tls | JSON NULL | always NULL for DigitalOcean (Proxmox and ESXi: the pinned certificate) |
| status | String(16) NOT NULL default `unknown` | `unknown`, `ok`, `warning`, `error` from the last Test |
| checks | JSON NOT NULL default `[]` | the last Test's checks (`vmtypes.Check.to_dict`); DigitalOcean's pass, warn and fail are stored as `ok`, `warning`, `error` |
| facts | JSON NOT NULL default `{}` | what the last Test read (DigitalOcean: the droplet limit and count) |
| last_checked_at | DateTime NULL | |
| removed_at | DateTime NULL | set when Remove keeps the row as a tombstone (§8) |
| created_by_id, updated_by_id | Uuid FK users SET NULL | |

Constraints: `UNIQUE (name)`; `CHECK (provider IN ('digitalocean','proxmox','esxi'))`; `CHECK (NOT production OR provider = 'digitalocean')`.

### 3.2 `environments` additions (P3 §3.1)

| column | type | notes |
|---|---|---|
| provider | String(16) NOT NULL server_default `'ssh'` | `ssh` or `digitalocean` (the placement) |
| provider_account_id | Uuid FK provider_accounts RESTRICT NULL | set for `digitalocean`; RESTRICT so an account can't be dropped while an environment row points at it (deleted environments included: their teardown log names it) |
| provider_team | String(80) NULL | frozen by the first DigitalOcean step (D3) |
| cloud | JSON NOT NULL server_default `'{}'` | `{region, droplet_size, droplet_image, db_size, db_nodes, db_version, acme_staging, vpc_range, lb_ip, edge: {port, health} \| null, slipway_addresses: [ip], certificate: {id, name, not_after, names}, plan: Plan, cost: {total_cents, lines, as_of, confirmed_by_id, confirmed_at}}`. `droplet_size`, `db_size` and `db_nodes` are the **confirmed** sizes (they equal `plan`'s); what each droplet actually is lives in its host's `provider_state.size`, so a pending resize ("Resize pending: applies at <slot>'s next deploy") is the difference between the two (§15.7). `db_version` is set at create from the manifest and never changes; `edge` is set by the first `edge` step (D15). `slipway_addresses` are the addresses droplets saw Slipway connect from (D14), at most 10, newest first. |
| production | Boolean NOT NULL server_default false | §13 |
| retiring_at | DateTime NULL | §13 |
| retired_by_id | Uuid FK users SET NULL | |

Constraints:
- `CHECK ((provider = 'digitalocean') = (provider_account_id IS NOT NULL))` (`ck_environments_provider_account`).
- `CHECK (provider <> 'digitalocean' OR data_mode = 'managed')` (`ck_environments_do_managed`).
- `CHECK (NOT production OR provider = 'digitalocean')` (`ck_environments_production_do`, open question 3).
- `CHECK (retiring_at IS NULL OR production)` (`ck_environments_retiring`).
- `CHECK (NOT production OR NOT auto_activate)` (`ck_environments_production_auto`).
- `Index("ux_environments_one_production", "repository_id", "manifest_file", unique=True, where production AND retiring_at IS NULL AND deleted_at IS NULL)` (D20; Sirdar's `environments_one_production`, `SM/0010:69-71`).

`environments.traffic` takes `switch: "do_lb"`; its `dns.address` is written by `edge` (the load balancer's IP) and can't be set by a person for a DigitalOcean environment. **Traffic follows placement** (D21, Decision 24): `do_lb` only with placement `digitalocean`, and placement `digitalocean` only with `do_lb`, checked by `environments.validate_create` (field `traffic.switch`); `PATCH /environments/{id}` refuses a change of `traffic.switch` or `traffic.dns.address` on a DigitalOcean environment, and refuses `do_lb` on an SSH one. On a DigitalOcean environment a PATCH whose `traffic` leaves out `switch` keeps `do_lb`, one that leaves out `dns` keeps the stored records (its names must still be in the Cloudflare zone, rule 7), and the public IP isn't asked for, since the address is the load balancer's (empty until the first `edge`, as at create). The Settings page sends `switch: do_lb` as a fixed value and shows only `Proxied`: no Switchyard choice, address, DNS untick or Switchyard TLS modes. A phase 5 environment with VMs is placement `ssh`: its new VMs are given as `hosts.<slot> = {machine: …}` (P5 §9.2).

### 3.3 `hosts` additions (P3 §3.5)

| column | type | notes |
|---|---|---|
| provider_state | JSON NOT NULL server_default `'{}'` | droplet hosts: `{phase: planned \| creating \| ready \| gone, droplet_name, region, size, image, public_ip, private_ip, built_at}`; VM hosts (phase 5): `{phase}`, written with each machine stage change |

Migration 0010 adds this column (with `provider_accounts`), since phase 5's VM hosts use it too (§3.10). This is the **host-level contract** both phases share (Decisions 1, 6):
- `Host.is_built` (property) = `provider == "ssh" or provider_state.get("phase") == "ready"`. `hosts.set_phase(host, phase, **fields)` writes the phase (a new dict, so the change is seen); the caller commits. Droplets move `planned → creating → ready`, and to `gone` when their recorded droplet is found gone (a 404); `prepare` moves a gone host back to `planned` before it builds again (§6.3, §9.2 step 1). A VM's phase follows its `machines.stage` in the same transaction (P5 §3.6).
- `ssh.SSHTarget.from_host(host, *, building=False)` (`services/ssh.py:94`) raises `HostNotBuilt("<host> isn't built yet: deploy <env> to build it")` for a host that isn't built; no SSH is attempted. `HostNotBuilt` subclasses `Exception`, **not** `ssh.SSHError`, so no handler that treats an `SSHError` as a network failure (the poller, the API's 502) ever sees it. Every API path that can meet it answers 409 with its text.
- `hosts.check_host(db, host, *, building=False)` passes `building` to `from_host`, and never writes `host_key` for a host whose provider isn't `ssh` (no trust on first use). Only the providers' `prepare` drivers (`do_provision.prepare`, P5's `machines.prepare`) pass `building=True`.
- The background poller skips hosts that aren't built (`services/hosts.py:124-135`).
- A provider host's key is written only by its provider's `prepare`: here before the create is sent (§9.2), in phase 5 by `machines.pin` (P5 §6.4).

While `phase = creating`, `host_key` always holds the public half of the key sent with the latest create and is never cleared (§9.2); it is cleared only when the host goes back to `planned` from `gone` or from a `creating` whose pending row lookups both said absent. A planned droplet host comes from `hosts.planned_host(...)` (Decision 9): `name = "slipway-<env>-<slot>"` (equal to `do_rules.droplet_name`, and to P5's `vmnet.vm_name` for a VM), `hostname = "<droplet name>.invalid"` (a placeholder that never resolves), `port = 22`, `username = "slipway"` (`cloudinit.GUEST_USER`), `label = <env>`, a description naming the environment and slot, `deploy_root = "/opt/slipway"`, `auth_method = key` with a key pair Slipway generated (`ssh.generate_keypair("slipway@<name>")`, `services/ssh.py:239`), `host_key` NULL, `provider_state = {phase: planned}`, `owner_environment_id` set by the caller once the environment row exists.

**Rules for owned hosts** (`owner_environment_id` not NULL), one helper for every provider, `hosts.owned_host_refusal(host, *, action) -> str | None` (Decision 7, with P5 D18's scope):
- Refused with 409: `PATCH /hosts/{id}` of the address (`hostname`, `proxy_address`, `lan_address`), the port, user or credentials or the deploy root; `DELETE /hosts/{id}`; `POST /hosts/{id}/reset-host-key`; the deploy-root move; `POST /instances` and a placement change onto it; another environment's `hosts.<slot> = <host id>`; Add slot with its `host_id`; the unmanaged-instance claim. The label and description stay editable. The texts name the kind and the owner: `<host> is a droplet Slipway made for <env>; …` (P5: `a VM Slipway made`).
- `POST /hosts/{id}/check` answers 409 while the host isn't built, and is allowed once built.
- `hosts.owned_by(env, host)` (`host.owner_environment_id == env.id`) is the one predicate by which Remove slot and teardown delete instance rows without SSH (§14.3).
- `hosts.address_holder(db, address, *, except_host_id) -> Host | None` is the one address-holder check (Decision 8): another host whose `hostname`, `proxy_address` or `lan_address` is the address (§9.2 step 5, P5 §6.4).

**The not-built rule** (Decisions 12, 28; P3 §14's unpinned-host refusal, replaced for provider hosts): a deploy whose step list contains `prepare` is allowed; `remove_slot` and `teardown` are allowed on owned hosts in any phase; every other kind is refused `<slot>'s server isn't built yet: deploy to <slot> first` (P5 §10.4 keeps its variant for a VM data server). SSH hosts keep P3's unpinned refusal unchanged. D28's deploy to the active slot is written on `is_built`.

### 3.4 `instances` change (P3 §3.2)

`host_id` becomes nullable, with `CHECK (host_id IS NOT NULL OR (slot = 'data' AND environment_id IS NOT NULL))` (`ck_instances_host`). Only a managed environment's data owner has no host. The check can't see `environments.data_mode`, so it would also let a mode `server` data owner lose its host; `environments.create` is what enforces the rest: it writes a host-less owner only for `data_mode = managed`, and every write of `instances.host_id` outside create refuses NULL. Every code path that reads `instance.host` is reached for that owner only through the data runner (§10.4), and the Instances list and host pages leave it out (`Instance.host_id IS NOT NULL`). The ripple is wide: on the phase 3 tree `grep -n '\.host\b'` finds 72 sites in `services/deployer.py`, 10 in `api/v1/instances.py`, 5 in `services/data.py`, 5 in `web/pages.py`, 7 in `services/env_jobs.py`, 6 in `services/environments.py`, 4 in `services/jobs.py`, 7 in `services/traffic.py` and 3 in `api/v1/environments.py` (ports, folders, locks, `recover_interrupted`, the poller and the unmanaged claim among them). Each slice that owns one of these files makes the sites the owner can reach None-safe (S14a: deployer, data, traffic, the instance API; S15: env_jobs, environments; S12: jobs; S20: the other API modules; S21: pages), and test 80 builds a managed owner and calls every instance API and recovery path on it, expecting a 409 or a skip and never an `AttributeError`.

### 3.5 `backups` additions (`models/data.py:43-85`)

| column | type | notes |
|---|---|---|
| location | String(8) NOT NULL server_default `'host'` | `host` (P2: on the owner's host) or `slipway` (D7) |
| data_key | EncryptedText NULL | the per-backup key for a `slipway` backup's container files |
| stored_bytes | BigInteger NULL | what the encrypted files take on the Slipway server |

`CHECK (location = 'host' OR data_key IS NOT NULL OR status <> 'ready')` (`ck_backups_slipway_key`). Files: `<storage_dir>/backups/<owner id>/<name>.db.sbc` and `<name>.files.sbc`, each written first as `<file>.part`, fsynced, then renamed (§10.5).

### 3.6 `deployments`

`kind` gains `certificate` (Renew certificate) and `deactivate` (§14.1). Both are environment-level (`instance_id` NULL, P3 D9). `options` gains `confirm_cost` (the total typed, for the audit), `rebuild` (objects made again because they were gone), `production_confirmed` (a teardown whose phrase was checked), `manifest_sha256` (the slipway.yml `prepare` read at the resolved commit, §14.3), `by` (`"renewals"` for a job the renewal loop queued, §15.12), `no_snapshot` (a production delete confirmed without a snapshot, §13) and `drop_data` (a delete that destroys the managed data without a snapshot, §13; the same flag as P5's VM data, Decision 26). Phase 5 adds `vm_snapshot`, `vm_revert` and `vm_drop` to the same `DeploymentKind` (`models/instance.py:49-65`).

### 3.7 `resources` (P3 §3.4, no column change)

| kind | provider_id | name | details | credentials | tags |
|---|---|---|---|---|---|
| `vpc` | VPC uuid | `slipway-<env>` | `{region, ip_range}` | | |
| `droplet` | droplet id | `slipway-<env>-<slot>` | `{slot, host_id, size, region, public_ip, private_ip}` | | the four tags and the request tag |
| `database` | cluster uuid | `slipway-<env>-db` | `{host, port, version, size, nodes, ca_b64}` (private connection) | `{admin_password}` (doadmin) | the three env tags and the request tag |
| `bucket` | bucket name | the same | `{region, endpoint}` | | |
| `spaces_key` | access key id | `slipway-<env>-<id8>-<nonce>` (the bucket's) or `slipway-<env>-<id8>-setup-<nonce>` | `{bucket, permission, role: bucket \| setup}` | `{secret_key}` (the bucket key only) | |
| `load_balancer` | LB uuid | `slipway-<env>-lb` | `{ip, vpc_id, size_unit}` | | |
| `certificate` | certificate uuid | `slipway-<env>-<stamp>` | `{not_after, dns_names}` | while pending only: `{private_key, leaf, chain}` (§11.2) | |
| `firewall` | firewall uuid | `slipway-<env>-fw` | `{ssh_sources, lb_rule: bool}` | | |

**Pending rows** (§6.4): `provider_id = "pending:<nonce>"` (16 hex characters), the name the object will have, `details.pending = {nonce, sent_at, body_hash, looked: [at…]}`, and, for a certificate, the issued chain and key in `credentials`. The unique `(environment_id, kind, name)` means one pending create per name. A droplet host's private key is never stored anywhere (D4).

`instance_id` is set on a `droplet` row (the slot). `origin` is always `created`; DigitalOcean code never writes `claimed` (as Sirdar, `SM/0010:139`). `rotate-encryption-key` covers `credentials` already (P3 §3.8). `--clear-unreadable` refuses to erase the SSH key of a droplet's host (`hosts.private_key` with `owner_environment_id` set), which can't be entered again by hand; P5 §3.9 has the text.

**Intent rows are DigitalOcean's only** (Decision 27): phase 5's VMs write their `vm` rows through `machines.reserve_vmid` and `machines.record_vm` (P5 §6.9) and never write a pending row. The additions below change nothing P5 relies on: a bare `record` of another environment's provider id still raises `ResourceTaken`, and a same-environment re-record still updates the row it finds.

**`services/resources.py` additions** (phase 3's built API has no credentials, tags or pending rows; slice S07 adds them, with `tests/test_resources.py`):
- `record(..., *, actor=None, credentials=None, tags=None, audit_action=None, replaces=None)`: `credentials` (EncryptedJSON) and `tags` are written in the same commit as the row, so a Spaces secret or a doadmin password is never between two commits; `audit_action` overrides `resource.create` with `resource.adopt` or `resource.rebuild` (the rule is passed in `details` for the audit); `replaces` names a pending row of the same environment, kind and name that the real row takes over in the same transaction (the `_clash` name rule treats it as the row itself).
- `record_pending(env_id, provider, kind, name, *, nonce, body_hash, instance_id=None, credentials=None, actor=None) -> uuid`: commits a pending row; raises `ResourceTaken` when the name already has a row (recorded or pending). Audit `resource.pending`.
- `pending(db, env_id, provider, kind) -> list[Resource]` and `looked(row_id, at)` (appends a lookup time, committed at once).
- `set_credentials(row_id, value | None) -> bool`: committed at once.
- `owned` leaves out pending rows unless `include_pending=True`.

### 3.8 `app_settings` rows

- `acme` (new, inserted empty by migration 0011, and by the store when it is missing): `value = {accounts: {<directory url>: {kid}}}`; `secret` = JSON `{<directory url>: <ES256 account key PEM>}`. One account key per directory, made on first use (`SD/certs.py:66-99`). A new key is generated outside any transaction; then `acme_store.AccountKeys.put_if_absent` inserts the row when it is missing (a racing insert's `IntegrityError` on the key is swallowed), takes `SELECT … FOR UPDATE` of it, and writes the key only when the directory has no key yet; otherwise the stored key is used and the new one dropped. Writing a new key also drops that directory's `value.accounts[<directory>]` in the same transaction, since its `kid` belonged to a key that is gone (`rotate-encryption-key --clear-unreadable` sets an unreadable `secret` to NULL and leaves `value`), so the next order registers the new key. So two `certificate` steps never overwrite each other's key, and a database built without the migration (tests build the schema with `create_all`) works the same (Decision 40).

Price overrides are per account only (`config.prices`, §3.1; Decision 41): there is no install-wide price row. `do_rules.price_layers(account, install)` keeps its second parameter and is always called with `install=None`.

### 3.9 Settings (`core/config.py:24-179`)

`SLIPWAY_ACME_DIRECTORY` (default Let's Encrypt), `SLIPWAY_ACME_STAGING_DIRECTORY`, `SLIPWAY_CERT_RENEW_INTERVAL` (seconds, default 21600), `SLIPWAY_BACKUP_TOTAL_BYTES` (default 100 GiB: the Slipway-stored backups' quota, next to `snapshot_total_bytes`, `core/config.py:80-81`).

### 3.10 Migrations 0010 and 0011

Three linear revisions after phase 3's `0009`, all written by slice S03 (Decision 5); patterns as P3 §3.7, none inspecting the database to decide what to create. 0012 is phase 5's (P5 §3.8).

**`alembic/versions/20261118_0010_provider_accounts.py`** (`revision='0010'`, `down_revision='0009'`), the provider core both phases use. **Upgrade:** 1. `create_table provider_accounts` (§3.1). 2. `batch_alter_table hosts`: `provider_state`. **Downgrade** refuses while `provider_accounts` has rows or any host has `provider <> 'ssh'` (`Remove the DigitalOcean, Proxmox and ESXi accounts first`), then reverses 2 and 1.

**`alembic/versions/20261118_0011_digitalocean.py`** (`revision='0011'`, `down_revision='0010'`). **Upgrade:** 1. `batch_alter_table environments`: the columns of §3.2 with their checks and `ux_environments_one_production`. 2. `batch_alter_table instances`: `alter_column("host_id", nullable=True)` (the FK stays RESTRICT), `ck_instances_host`. 3. `batch_alter_table backups`: `location`, `data_key`, `stored_bytes`, `ck_backups_slipway_key`. 4. Insert the empty `acme` row into `app_settings` when it is missing.

**Downgrade of 0011** (refuses while anything would be orphaned, as `SM/0010:152-165`):
1. A live environment with `provider = 'digitalocean'`, or any `resources` row with `provider = 'digitalocean'`: `RuntimeError("Slipway still manages DigitalOcean objects for <names>: delete those environments first")`.
2. Any backup with `location = 'slipway'`: `RuntimeError("<n> backups are stored on this Slipway server; delete them first")`.
3. Any instance with `host_id IS NULL`: the same text as 1.
4. Then reverse 4 to 1 (the `acme` row is deleted: it holds only ACME account keys, which Let's Encrypt lets Slipway make again).

`tests/test_migration_0010.py` and `tests/test_migration_0011.py` run on SQLite and on PostgreSQL when `SLIPWAY_TEST_DATABASE_URL` is set; S03 is done only once the PostgreSQL run passed (P3 §3.7's rule). `tests/test_migration_0009.py` upgrades to `'0009'` instead of `head` (its refused `downgrade 0008` must still leave `version_num == ['0009']`), and its `alembic check` (models equal migrations) moves to `tests/test_migration_0012.py`, which upgrades to head.

---

## 4. Permissions and audit

### 4.1 Permissions

| Perm | Description | Roles |
|---|---|---|
| `providers:read` | See provider accounts of every provider (names, regions, teams, limits, networks; never secrets), the catalog of regions and sizes, and an account's free addresses | developer, maintainer (`_READ_ALL` minus viewer) |
| `providers:write` | Add, change, test, trust and remove provider accounts (DigitalOcean, Proxmox, ESXi) and their secrets | admin only |
| `providers:spend` | Confirm a monthly cost: create a DigitalOcean environment, add a slot to one, grow its sizes | maintainer |

Phase 5 adds `machines:write` (maintainer) for VMs; the four are added in one edit of `core/permissions.py` (Decision 4).

| Action | Permission(s) |
|---|---|
| Create a DigitalOcean environment | P3's (`environments:write` …) + `providers:spend` |
| Add a slot, grow sizes | `environments:write` + `providers:spend` |
| Deploy, Activate, Switch back, Publish, Discard | P3's; a production Activate also needs the name typed |
| Renew certificate now | `traffic:switch` |
| Retire, un-retire | `environments:delete` + typed name |
| Deactivate | `traffic:switch` + `environments:delete` + typed name |
| Delete | P3's + `data:backup` (the snapshot is mandatory for production that holds data and default for managed data that holds data) + the phrase for production. Without a snapshot while the owner holds data: `drop_data: true`, which needs `data:reset` (Decision 26: Delete destroys the data's only home); on production that holds data, also `environments:delete` + the second phrase (§13) |
| Retry | P3's. `data.RETRY_PERMISSION` gives `certificate` and `deactivate` `traffic:switch`, and `RETRY_EXTRA` adds `environments:delete` to `deactivate`, which asks the typed name again (`CONFIRMED_KINDS`); a production `teardown` asks the phrase again (Decision 37) |
| The renewal loop's `certificate` job | none: the system actor (§15.12) |

`SYSTEM_ROLES` are re-synced at startup (P3 §4.1).

### 4.2 Audit actions

Never tokens, keys, passwords, CA private parts or certificate private keys.

| Action | Details |
|---|---|
| `provider_account.create`, `.update`, `.delete` | name, provider, production, region, changed field names ("token replaced"); one set of actions for every provider (P5 §4.2 adds `.trust`) |
| `provider_account.test` | name, the check results (no values) |
| `environment.cost_confirmed` | the plan's lines and total, the figure typed, the deployment it covers |
| `environment.resize` | old and new sizes, the cost delta |
| `environment.retire`, `.unretire`, `.deactivate` | by whom |
| `resource.pending`, `.create`, `.adopt`, `.rebuild`, `.delete`, `.forget` | provider, kind, name, provider_id (the nonce for a pending row); adopt names the rule that matched |
| `certificate.issue`, `certificate.renew_queued` | names, not_after, staging (renew_queued: by, deployment_id, staging, names, not_after, read_from; no actor) |
| `certificate.renew_refused` | by (`renewals`), reason; no actor; at most once in 24 hours per environment (§23, S19) |
| `environment.team_frozen` | the team id and name |
| `environment.edge_frozen` | the port and health path |
| `environment.slipway_address` | the address a droplet saw Slipway connect from (first time only) |
| `environment.delete_without_snapshot` | by whom, why no runner could be reached |

---

## 5. Manifest additions (`slipway/services/manifest.py`)

### 5.1 Grammar

```yaml
edge:                                   # optional; how the app serves its names behind a cloud load balancer
  port: 80                              # the host port each app slot serves plain HTTP on (1-65535)
  health: /healthz                      # what the load balancer asks for, with a Host outside the app's names
  env:                                  # 1-30 keys written into every app slot's .env behind a load balancer
    STACK_CADDY: "1"
    STACK_NETWORK_SUBNET: 172.30.0.0/24
    STACK_PROXY_IP: 172.30.0.2          # a setting: behind a load balancer the form doesn't ask for it
    STACK_BIND_IP: 127.0.0.1
    STACK_HOSTS_IP: "{edge.address}"
    STACK_TRUSTED_PROXIES: "{edge.trusted}"
  projects: ["ss-{STACK_ENV}-proxy"]    # 0-4 projects the edge adds (stopped, checked and removed like the rest)

data:
  managed:                              # optional; how the app runs on a managed database and object store
    skip: [spaces]                      # services that don't run when the data is managed
    db:      {version: "16", database: serversherpa, user: serversherpa, password: "{secret.POSTGRES_PASSWORD}"}
    objects: {cors: [portal, kiosk, wiki]}
    env:                                # 0-20 keys written into every app slot's .env only when the data is managed
      SS_SPACES_BUCKET: "{data.objects.bucket}"
    commands:                           # replace these commands in managed mode: has_data, data_up
      has_data: [deploy/stack/ss-stack, has-data, "{slipway.env_dir}", --external]
```

`data.managed.<need>` names each `data.attach.needs` entry (P3 §5.1); `skip`, `env` and `commands` are reserved and can't be need names. Per kind:

| kind | keys | what the provider fills in for `{data.<need>.*}` |
|---|---|---|
| `postgres` | `version` (`"13"`-`"17"`, required), `database`, `user` (`^[a-z_][a-z0-9_]{0,62}$`, `SD/pgauth.py:12`), `password` (exactly one `{secret.K}`) | `host`, `port` (the private connection), `database`, `user`, `password`, `tls = require`, `ca_b64` (the cluster's CA) |
| `s3` | `cors` (0-10 service names with a hostname; their `https://` origins may PUT, GET and HEAD) | `endpoint = https://<region>.digitaloceanspaces.com`, `region`, `bucket`, `access_key`, `secret_key`, `path_style = false` |

**Template values added:**

| Value | Allowed in | Filled with |
|---|---|---|
| `{edge.address}` | `edge.env` | the load balancer's IP (`environments.cloud.lb_ip`) |
| `{edge.trusted}` | `edge.env` | the VPC's range (`environments.cloud.vpc_range`) |

### 5.2 Validation (`ManifestError("slipway.yml: <where>: <message>")`)

1. Top-level keys gain `edge`; `data` gains `managed`.
2. `edge.port` 1-65535 and not a service's `port` — `edge.port: 8000 is the api service's port`. `edge.health` a path (P3 §5.2 rule 3's pattern).
3. `edge.env` keys: env keys, settings or vars; not secrets or `port_var`s — `edge.env.SS_JWT_SECRET: is a secret; Slipway generates it`. Templates may use `{edge.*}`, settings and vars; not `{secret.*}`, `{data.*}` or `{server.*}`. A setting named here is **set by the edge**: not required, and not asked for, in a `do_lb` environment.
4. `edge.projects` templates like `projects`; none equal to one already in `projects`.
5. `data.managed` needs `data.attach` — `data.managed needs data.attach: the app slots must be told where the data is` — and an entry for every need and no other — `data.managed: needs an entry for objects (data.attach.needs lists it)`.
6. `postgres` entries: `version` required and one of 13-17 — `data.managed.db.version: '12' isn't a version DigitalOcean offers here (13-17)`; `password` exactly one declared `{secret.K}` — `data.managed.db.password: must be one secret, such as "{secret.POSTGRES_PASSWORD}"`; identifiers per the pattern.
7. `s3` entries: each `cors` name a declared service with a hostname and not in `skip`.
8. `skip`: declared services; not optional-only names that don't exist.
9. `commands` keys ∈ {has_data, data_up}; argv rules as `commands`.
10. The environment's own variables may not set an `edge.env` or `data.managed.env` key (P3 §5.2 rule 13 gains both).
11. `data.managed.env` follows P3's rule 5 for `attach.env` exactly (keys not settings, vars, secrets or port vars; `{data.x.y}` a declared need and field; `{secret.K}` declared), and its keys may not repeat an `attach.env` key — `data.managed.env.STACK_DB_HOST: is already set by data.attach.env`. Its values come after `attach.env` and before `edge.env` in the `.env`. A key the `env_file` already has (ServerSherpa's `SS_SPACES_BUCKET`, `deploy/stack/env.example:50`) is allowed, as in `attach.env`: it isn't a setting or var.

`to_json` adds `edge` (port, health, env keys, projects) and `data.managed` (skip, needs with their keys, env keys, commands keys). `capabilities()` gains `edge` and `managed`; `digitalocean` = `edge` + `managed` + every `attach.needs` entry covered. `bluegreen` becomes `(data.server or data.managed) and migrations == "expand_contract"` (Decision 20), so an app whose data is only managed can run two slots on DigitalOcean; for every P3 manifest the answer is unchanged.

### 5.3 Plan roles (P3 §5.3)

P3's `slot` role gains `without: set[str]` (P3: `server.services`; managed: `data.managed.skip`), `managed: bool` and `edge_values: {address, trusted} | None`. With `managed`, the plan adds `data.managed.env` right after `attach.env`. With `edge_values`, the plan adds `edge.env` after those (a setting named there takes the edge's value), adds `edge.projects` to `projects`, and keeps only `data.volumes` with `holds: other` (the database and files are managed). `has_data` and `data_up` take `data.managed.commands` when the data mode is `managed`. Without `managed` and `edge_values` the `slot` role is byte-identical to P3's (J1): a LAN Blue/Green slot's `.env` gains no line, because the managed-only keys live in `data.managed.env`, not in `attach.env`.

### 5.4 ServerSherpa additions (BaseCampV3 `slipway.yml` and `docs/examples/serversherpa.slipway.yml`)

```yaml
edge:
  port: 80
  health: /healthz
  env:
    STACK_CADDY: "1"
    STACK_NETWORK_SUBNET: 172.30.0.0/24
    STACK_PROXY_IP: 172.30.0.2
    STACK_BIND_IP: 127.0.0.1
    STACK_HOSTS_IP: "{edge.address}"
    STACK_TRUSTED_PROXIES: "{edge.trusted}"
  projects: ["ss-{STACK_ENV}-proxy"]

data:                                     # attach is P3's, unchanged
  managed:
    skip: [spaces]
    db:      {version: "16", database: serversherpa, user: serversherpa, password: "{secret.POSTGRES_PASSWORD}"}
    objects: {cors: [portal, kiosk, wiki]}
    env:
      SS_SPACES_BUCKET: "{data.objects.bucket}"   # the env_file's default is "serversherpa"; Spaces names are global
    commands:
      has_data: [deploy/stack/ss-stack, has-data, "{slipway.env_dir}", --external]
```

What this gives for environment `prod` (STACK_DOMAIN `serversherpa.com`, region `nyc3`), on blue's droplet: `STACK_EXTERNAL_DATA=1`, `STACK_DB_HOST=private-slipway-prod-db-…`, `STACK_DB_PORT=25060`, `STACK_DB_SSLMODE=require`, `SS_DATABASE_URL=postgresql+asyncpg://serversherpa:<hex>@…:25060/serversherpa` (hidden), `SS_DATABASE_SSL=require`, `SS_DATABASE_CA_B64=<CA>`, `SS_SPACES_ENDPOINT=https://nyc3.digitaloceanspaces.com`, `SS_SPACES_BUCKET=slipway-prod-1a2b3c4d`, `SS_SPACES_ACCESS_KEY=<id>`, `SS_SPACES_SECRET_KEY=<secret>` (hidden), `SS_SPACES_USE_PATH_STYLE=false`, `STACK_CADDY=1`, `STACK_PROXY_IP=172.30.0.2`, `STACK_BIND_IP=127.0.0.1`, `STACK_HOSTS_IP=<LB IP>`, `STACK_TRUSTED_PROXIES=10.116.0.0/20`, every secret. No `SS_CERT_*` key (D2). `ss-stack up` then runs storage (mailpit only), api, web, status and proxy (`SS/deploy/stack/ss-stack:198-199`); Caddy publishes :80 and the services bind to 127.0.0.1. The routes are every hostname but `spaces`. This is what Sirdar's `env_extra` wrote, minus the cert-worker's keys (`SD/do_envs.py:348-366`).

**BaseCampV3 changes** (the old slice G4, test 32): work in the BaseCampV3 `slipway-manifest` branch, outside this repository. It is not one of the plan's slices and is tracked separately, after S04 fixes the keys (Decision 35):
1. `ss-stack has-data <env-dir> --external`: with `STACK_EXTERNAL_DATA=1`, ask the external database through `pg()` (`ss-stack:269-287`): 0 when `alembic_version` exists, 3 when it doesn't, 1 when the database doesn't answer. Without `--external` the exit-4 rule is unchanged (`ss-stack:571-590`), so a phase 2 instance with external data still refuses restores.
2. `slipway.yml` as above; `docs/examples` copy.
3. `deploy/stack/env.example`: the "DigitalOcean droplet (Sirdar writes these)" block says Slipway writes them from `edge` and `data.managed`, and that the `SS_CERT_*` keys stay unset (the cert-worker idles).
4. `deploy/stack/test-managed-role.sh` (new): runs the real `ss-stack` against a managed-role `.env` with a `docker` shim, and checks that `has-data --external`, `pgdump`, `restore`, `revision`, `export-objects` and `import-objects` run their client containers with `PGSSLMODE=verify-full` and the CA mounted, and that `up` names the proxy stack and no db stack.

---

## 6. DigitalOcean objects: names, tags and ownership

### 6.1 Names and tags (`do_rules.py`)

| Object | Name |
|---|---|
| VPC | `slipway-<env>` (description `slipway:<env id> Made by Slipway for environment <env>.`) |
| Droplet | `slipway-<env>-<slot>` (also its hostname; `^slipway-[a-z][a-z0-9-]{0,40}[a-z0-9]$`) |
| Database cluster | `slipway-<env>-db` |
| Bucket | `slipway-<env>-<env id hex[:8]>` (globally unique, `SD/do_envs.py:58-59`) |
| Bucket key / setup key | `slipway-<env>-<id8>-<nonce>` / `slipway-<env>-<id8>-setup-<nonce>` (`<id8>` = env id hex[:8]; the nonce of its pending row, §6.4) |
| Load balancer | `slipway-<env>-lb` |
| Firewall | `slipway-<env>-fw` |
| Certificate | `slipway-<env>-<UTC yyyymmddhhmm>` (`SD/certs.py:40-41`) |

Names are **matched exactly, never by prefix**: environment `prod`'s prefix `slipway-prod-` is also the start of every name of an environment `prod-eu`. A Spaces key is ours when its name matches `^slipway-<env>-<id8>-(setup-)?[0-9a-f]{16}$`; a certificate when its name matches `^slipway-<env>-[0-9]{12}$`. Droplets and clusters carry the env-id tag, and the VPC its env-id marker, so their exact names suffice.

Tags, set in the create bodies of droplets and clusters only (DigitalOcean's tags API is never called, `SD/do_envs.py:62-69`): `slipway`, `slipway-env-<env id>` (the ownership tag), `slipway-env:<name>`, on droplets `slipway-slot:<slot>`, and the **request tag** `slipway-req:<nonce>` of the create that made it. The firewall applies by `slipway-env-<env id>`. The VPC's description ends ` req:<nonce>`.

### 6.2 Ownership: what Slipway changes, adopts or stops on

| Kind | A recorded one still matches when | Not recorded: adopted only when | Otherwise |
|---|---|---|---|
| droplet, database | the exact name, and both `slipway` and `slipway-env-<id>` tags (`SD/do_provision.py:1122-1128`) | it has both tags, the exact name and the request tag of a pending row; a droplet also only while its host is `creating` with a `host_key` (the pin then decides, §9.2) | the env tag without `slipway`: stop. **Two** of one name with both tags (recorded or not): stop, naming both ids, never adopt either |
| VPC | the exact name and `slipway:<env id>` in its description (`:459-497`) | the same, with a pending row's ` req:<nonce>` | a same-named VPC without the marker: stop |
| load balancer | the exact name, inside the environment's VPC | the same name inside the environment's VPC (`:1024-1049`) | the name elsewhere: stop |
| firewall | the exact name | the name and the env tag (`:1081-1108`) | the name without the tag: stop |
| spaces_key | listed by DigitalOcean under the recorded name | never adopted: its secret is shown once (`:574-596`). A key whose name matches §6.1's pattern, whose grants are only on our bucket or full access, and that no row records, is deleted (a lost answer or a left setup key, `:535-537`) | a key matching the pattern with grants on another bucket: stop |
| certificate | `certs.is_ours`: the name matches §6.1's pattern and `dns_names` equals the wanted names exactly (`SD/certs.py:44-51`, which matched by prefix) | the name of a pending row (picks up an upload whose answer was lost, `SD/do_provision.py:980-985`), or `is_ours` | teardown: any name matching the pattern whose `dns_names` are all among the environment's hostnames (`env.hostnames`) |
| bucket | `provider_id` equals the environment's bucket name (`:1406-1410`) | the create is idempotent: 409 then a HEAD under our key (`SD/spaces.py:124-143`) | another account has the name: stop |

Every stop says what it found and ends `Slipway changed nothing: fix it by hand, then retry`. A 403 on any read in this table stops the step with `<account>'s token can't read <kind>s (DigitalOcean answered 403). Slipway changed nothing: give the token that scope, then retry` (J13).

### 6.3 Half-made, lost and gone objects

| Situation | What the next step does | Recorded as |
|---|---|---|
| A step failed after some creates | the objects stay recorded; the step's Retry (or the next deploy) continues and makes only what is missing | the failed deployment; the Billing callout (§17.2) while the environment was never live |
| A create was sent and its answer lost (timeout, restart, cancel, step timeout) | its pending row stays; the next step looks it up by nonce or name (§6.4) and records it, or, after two lookups 60 s apart say absent, drops the row and creates again | `resource.adopt` with the rule |
| A recorded object is gone (a 404 on its own GET) | forgotten and made again, inside the confirmed plan; a gone **droplet** host goes back to `planned` (its pin and address cleared) | `resource.rebuild`; `options.rebuild` |
| A read answers 403, 401 or another error | the step stops; nothing is forgotten (J13) | the step's error |
| A recorded object no longer matches (renamed, retagged, moved) | the step stops before any write | the step's error |
| A temporary setup key is left over | deleted at the start of the next `prepare` | log line |
| A rebuilt load balancer has a new IP | `edge` records it; every slot whose `.env` names the old IP is marked stale (`Its .env names the old load balancer address; deploy to it`), and the same deploy's `dns` step, listed after `edge`, moves the records (§11.3; a Publish when that step ended in a warning) | log line, P3 `slot_state.stale` |
| A gone droplet of the **active** slot | nothing rebuilds it by itself. Once its host is marked `gone` (by the DigitalOcean card's GET /cloud, K1, or a deploy's `prepare`), the page says `<blue>'s droplet is gone, so nothing answers through the load balancer: deploy to <blue> to build it again` (and, when green has a live release that isn't stale, `or activate <green>`); until then the card's live callout says the same with **Deploy to <blue>**. A deploy to the active slot is allowed while its droplet isn't built (D28); its `traffic` step's sync repair puts the new droplet on the load balancer (§11.6). Owner jobs run on the other slot meanwhile (§10.4) | the environment page |
| A remade load balancer on a live environment | it has no targets (D11); the next deploy's `traffic` step or a Publish runs the sync repair for the recorded active slot | log line |

### 6.4 Intent rows (pending creates)

Every create in §9-§11 and §15.11 follows the same five steps (`do_provision.create_once(kind, name, body, find)`):

1. **Look first.** The kind's pending rows for this name: for each, `find(nonce, name)` reads DigitalOcean (droplets and clusters by the request tag `slipway-req:<nonce>` through `?tag_name=`; the VPC by name and ` req:<nonce>` in its description; the load balancer by name in the VPC; the firewall by name and tag; a certificate by its stamped name; a Spaces key by its `…-<nonce>` name (§6.1); the bucket by its fixed name with a HEAD). Found → `record(..., replaces=<pending>, audit_action="resource.adopt")`, done. Absent → `looked(row, now)`.
2. **Not yet.** A pending row is dropped only when two lookups, both at least 60 s after `sent_at` and at least 60 s apart, said absent. Until then the step waits (polling every 10 s, at most 3 minutes) and looks again; past that it fails `A <kind> create from <when> may still appear in DigitalOcean; retry in a few minutes. Slipway made nothing new`. No create is sent while a pending row of the kind and name is kept (J12).
3. **Check the plan** (§12.3), counting recorded rows, kept pending rows and live tagged objects.
4. **Write the intent.** A fresh nonce (16 hex characters, `secrets.token_hex(8)`); `record_pending(..., nonce, body_hash = sha256 of the body without secrets)` commits. For a droplet the host row's new `host_key` is written in the **same** transaction (§9.2).
5. **Send, then record.** The create goes out with the nonce in it. Its answer: `record(..., replaces=<pending>, credentials=…, tags=…)` in one commit. A 4xx answer that proves nothing was made (400, 401, 403, 422) drops the pending row; a timeout, a 5xx or a cancel keeps it. A cancel (P3's shielded cancel, or a step timeout) never lands between the answer and the record: step 5's send and record run under `asyncio.shield`, bounded by the client's 30 s timeout. A restart can still cut it; the pending row is what covers that.

The request tag stays on a droplet or cluster for its life. DigitalOcean keeps a tag name in the account's tag list after its last object is gone; Slipway never calls the tags API (§6.1), so these names are left (open question 22).

---

## 7. The DigitalOcean client (`slipway/services/digitalocean.py`)

Sirdar's `do_api.py` ported (`SD/do_api.py:1-375`), with `digitalocean.py`'s reads merged in (D25):

- Base `https://api.digitalocean.com/v2`, `Authorization: Bearer <token>` only, `User-Agent: Slipway`, timeout 30 s, `per_page` 200, at most 10 pages (`DigitalOceanError("DigitalOcean listed more than Slipway reads")`).
- Errors: `DigitalOceanError(reason, status)` with Slipway's text; `NotFound` (404 only: `get_*` returns None, `delete_*` returns False), `Forbidden` (403: always raised, on a GET as on a write, never turned into None or False; its text names the kind, `The token can't read load balancers (DigitalOcean answered 403)`), 401 → `DigitalOcean rejected the API token`, a network error → `Couldn't reach the DigitalOcean API`. Callers decide "gone" only from None/False (J13). DigitalOcean's error `id` is named only when it matches `[a-z_]{1,40}` (`SD/do_api.py:64-68`); its `message` never.
- 429: wait `Retry-After`, else `RateLimit-Reset` minus now, else 5 s, at most 30 s, retry once (`:81-92`, `:129-136`), writes included: a 429 means DigitalOcean did nothing (Decision 19). 502/503/504 on a GET: retry once after 2 s. No other write is retried.
- A 202 or 204 with no body is `{}`; a non-object body is `DigitalOcean sent a response Slipway didn't understand`.
- IDs that go into a path must match `[A-Za-z0-9-]{1,128}` (`:95-100`).
- `transport_factory` seam (tests use `httpx.MockTransport(FakeDigitalOcean().handler)`), as Switchyard's and Cloudflare's. The autouse test guard replaces it with a transport that fails any request (§20.1).
- The token is added to the job's `ssh.Redactor`.

Methods (each one call, as Sirdar's): `account`, `regions`, `sizes`, `database_options`; `vpcs`, `vpc`, `create_vpc`, `delete_vpc`, `vpc_members`; `droplet`, `droplets_tagged`, `create_droplet`, `delete_droplet`, `droplet_action`, `get_action`; `database`, `databases_tagged`, `create_database`, `database_firewall`, `set_database_firewall`, `database_ca`, `resize_database`, `delete_database`; `spaces_keys`, `create_spaces_key`, `delete_spaces_key`; `certificates`, `certificate`, `create_certificate`, `delete_certificate`; `load_balancers`, `load_balancer`, `create_load_balancer`, `update_load_balancer`, `delete_load_balancer`; `firewalls`, `firewall`, `create_firewall`, `update_firewall`, `delete_firewall`. Helper `droplet_ips(droplet) -> (public, private)` (`:103-107`).

`digitalocean.poll(fetch, ready, seconds, what)` polls every 10 s; an object that disappears mid-wait fails `<what> disappeared from DigitalOcean while Slipway waited`; a timeout fails `<what> wasn't ready after <n> minutes` (`SD/do_provision.py:403-411`). Every wait has its own limit, listed with the step sums in §18.

---

## 8. Accounts (`slipway/services/provider_accounts.py`)

One service and one router (`slipway/api/v1/provider_accounts.py`, at `/api/v1/provider-accounts`) for the three providers, with a small per-provider dispatch (Decision 3); P5 §9.1 gives the Proxmox and ESXi rules. Reads need `providers:read`, every write `providers:write`.

- **Save** (`POST /provider-accounts`, `PATCH /provider-accounts/{id}`, partial): name, production, region, `ssh_sources`, `monthly_limit_cents`, `prices`, and the token (`secret`, write-only: omitted keeps it, `clear_secret` drops it). The token is any 1-200 printable characters (the form hints `dop_v1_…`, `SW/pages/settings/DoAccountModal.tsx:19-22`); `ssh_sources` go through `do_rules.normalise_ssh_sources`, `prices` through `do_rules.check_prices`. A bad field raises `vmtypes.AccountInvalid` (422 with `field`).
  - The same token can't serve two accounts: `This token already belongs to account <name>` (`SD/do_accounts.py:236-239`).
  - "Environments that use the account", here and in §12.2, means every environment row with `provider_account_id` = the account and `deleted_at IS NULL`: statuses `new`, `live` and `deleting` all count, since those are the ones that can still hold billing objects (§12.4).
  - When environments use the account, the new token's team is read **before** the row is locked, then the save is checked again under `SELECT … FOR UPDATE`: another team is refused (`<n> environments were built in team <team>; a token for <other> can't manage them`), and an environment that started using the account meanwhile makes the save answer 409 `Save again: an environment started using this account` (`SD/do_accounts.py:229-266`).
  - With no environment, the team is cleared and learned again by Test or the first `prepare`.
  - `production` can't be turned off while a production environment uses the account; `ssh_sources` must stay non-empty while any environment uses it.
  - **Lock-out guard** (J14): new `ssh_sources` must contain every address in `cloud.slipway_addresses` of every environment that uses the account, else 409 `Slipway connects to <env>'s droplets from <ip>, which these SSH sources leave out: Slipway would lose SSH to them, and with it backups, snapshots and Delete`. The next `prepare` or `edge` of each environment writes the new rule (§11.4).
- **Test** (`POST /provider-accounts/{id}/test`, or `POST /provider-accounts/test` with an unsaved token, DigitalOcean only, registered before the `/{id}` routes): `GET /account` (status, team, droplet limit and count), `GET /regions` (the default region available), and one read of each kind Slipway uses (`/vpcs`, `/droplets`, `/databases`, `/spaces/keys`, `/certificates`, `/load_balancers`, `/firewalls`, `per_page=1`). Each is `pass`, `warn` or `fail`, stored as `ok`, `warning` or `error`; the answer is `{status, checks, facts}`, as for every provider. The message ends `Slipway can't check that the token may create and delete these without making one.` (as P3's Cloudflare test). A test of a saved, unused account remembers the team. A Test whose token was replaced or cleared while DigitalOcean answered keeps nothing (no status, facts or team) and answers 409 `test_stale` (P5 §9.1). `POST /provider-accounts/{id}/trust` answers 409 for a DigitalOcean account (it pins no certificate).
- **Remove** (`DELETE /provider-accounts/{id} {confirm}`, typed name, every provider): refused while a not-deleted environment uses it (`deleted_at IS NULL`: `Environments <names> use <account>; delete them first`) or any machine does (phase 5). With no environment or machine row at all, the row is deleted. When only deleted environments point at it, RESTRICT keeps the row, so it is kept as a **tombstone** instead: `secret = NULL`, `config` cleared (team, region and `ssh_sources` with it), `removed_at` set, `name` kept so the old teardown logs still name it; the card shows it as `Removed` and it can't be chosen for a new environment. Audit `provider_account.delete` either way.
- **Catalog** (`GET /provider-accounts/{id}/catalog?region=`, `providers:read`, DigitalOcean only): regions (`available`), droplet sizes offered in the region with `vcpus`, `memory`, `disk`, `price_monthly`, database sizes per node count from `GET /databases/options` (`options.pg.layouts`, `SD/do_envs.py:154-157`), the PostgreSQL versions offered, and whether the region has Spaces (`do_rules.SPACES_REGIONS`, open question 5). Cached in memory for 10 minutes per account and region for the pages; `catalog(account, region, fresh=True)` skips the cache, and Create, Add slot and a growing PATCH call it that way (§12.2).
- **Environments use an account by reference.** Create holds the account row `FOR UPDATE` until commit (`SD/environments.py:505-511`), so a save can't change its team under a create. No HTTP call is made while that lock is held (§12.2).

---

## 9. Droplets as hosts

### 9.1 User-data (`do_rules.droplet_userdata`)

```yaml
#cloud-config
hostname: slipway-<env>-<slot>
preserve_hostname: false
ssh_pwauth: false
disable_root: true
users:
  - {name: slipway, shell: /bin/bash, lock_passwd: true,
     ssh_authorized_keys: ["<the host row's public_key>"]}
ssh_deletekeys: true
ssh_genkeytypes: []
ssh_keys: {ed25519_private: "<generated>", ed25519_public: "<generated>"}
growpart: {mode: auto, devices: ["/"]}
resize_rootfs: true
package_update: true
packages: [docker.io, docker-compose-v2, curl]
write_files:
  - path: /etc/systemd/system/docker.service.d/slipway-metadata.conf
    owner: root:root
    permissions: "0644"
    content: |
      [Service]
      ExecStartPost=/bin/sh -c '<block>'
runcmd:
  - [usermod, -aG, docker, slipway]
  - [install, -d, -o, slipway, -g, slipway, -m, "0755", /opt/slipway]
  - [systemctl, daemon-reload]
  - [systemctl, enable, --now, docker]
  - [sh, -c, "{ <block>; } && touch /var/lib/slipway-ready"]
```

`<block>` is `iptables -C DOCKER-USER -d 169.254.169.254/32 -j DROP 2>/dev/null || iptables -I DOCKER-USER -d 169.254.169.254/32 -j DROP` (`do_rules.METADATA_BLOCK`). DigitalOcean serves the user-data, the private host key in it, at `http://169.254.169.254/metadata/v1/user-data` for the droplet's lifetime, and containers reach that address through Docker's NAT; the rule drops it for everything Docker forwards (every bridge network). The drop-in adds it again whenever Docker starts (a reboot, a restart), and the ready marker is written only once the rule is in place, so a droplet without it never passes step 9 of §9.2. A container on the host's network (`network_mode: host`) is not forwarded and can still read it; the droplet user has no sudo, so the key can't be rotated after the pin instead (D24).

The `docker` group exists only once `docker.io` is installed, and cloud-init creates users before it installs packages, so the user joins the group in `runcmd`, which runs after the packages. (Real-account check §20.3 item 2 confirms `id slipway` lists `docker`.) The hostname is checked against the pattern; the document must stay under 64 KiB (the fake refuses more, `ST/fake_digitalocean.py:9`). The host's private key appears only in this document, which is built in memory, sent once and never stored or logged (it is added to the Redactor).

The user is `cloudinit.GUEST_USER` (`do_rules.DROPLET_USER = cloudinit.GUEST_USER`), the name phase 5's VMs use too; droplets keep their own `do_rules.droplet_userdata` and get no sudo (D24), where VMs get passwordless sudo (P5 §6.5).

DigitalOcean emails a root password for a droplet made without DigitalOcean SSH keys. It is harmless here (`disable_root`, no password SSH), and docs/digitalocean.md says so.

### 9.2 `prepare`: the slot's droplet

`prepare` runs, in order: the manifest read (§14.3), the team check, the VPC (§11.1), the cloud firewall with the SSH rule (§11.4), the bucket and its key (§10.3), then the deploying slot's droplet (`ctx.slot`):
1. **Recorded row.** Read it. A 404 → forget it, set the host `planned` (`hosts.set_phase`), clear `host_key`, `hostname` and the pin (`SD/do_provision.py:747-758`). Present → check §6.2's marks; a droplet found `off` (a run stopped between a resize's `power_off` and `power_on`, §9.4) is powered on first (wait 5 min), before the pin. A 403 or other error stops (J13).
2. **Pending row** (a create whose answer was lost): §6.4 step 1. A droplet found by its request tag is adopted only when the host row is `creating` and holds a `host_key`; the pin check in step 7 then decides whether it is trusted. If the host has no `host_key` (it can't, by §3.3, but a hand edit could do it), the found droplet is ours (both tags, the exact name, our request tag), so it is deleted and made again, never trusted. The host never leaves `creating` while a pending row is kept. When every kept row was judged absent (and forgotten), the tagged droplets are read again before the create: an unrecorded droplet of the slot's name with both tags (a lost create that appeared late) stops the step with the `no record of making it` refusal of §6.2, so the slot never gets a second droplet.
3. **None: create** (§6.4 steps 3-5). Generate a host key pair. In one transaction: the pending row and the host row (`phase = creating`, `host_key` = the public half, `host_key_fingerprint` = `ssh.fingerprint`, `services/ssh.py:253`). Then `POST /droplets {name, region, size, image: ubuntu-24-04-x64, vpc_uuid, ipv6: false, monitoring: false, with_droplet_agent: false, tags (with the request tag), user_data}` (`SD/do_provision.py:773-777`). The answer: `record(droplet, replaces=<pending>, tags=…)` and `hosts.provider_id` in one commit. The private half is dropped from memory.
4. Wait for `status == active` and both a public and a private IPv4 (10 min, `:705-712`).
5. **Address check.** Refused if a host row **not owned by this environment** holds the address as its `hostname`, `proxy_address` or `lan_address` (`hosts.address_holder`, the broad check phase 5 uses too, Decision 8; `SD/vmcommon.py:105` `check_address`): `<ip> is still the address of host <name>, which Slipway lists separately. DigitalOcean gave that address to <droplet>, so <name> no longer points at the machine it was added for: change or remove host <name>, then retry`. The droplet **stays recorded** (it bills until Retry or Delete), the host stays `creating`, and the Billing callout names it. A retry after the fix continues from step 5.
6. Set `hostname = <public ip>`, `provider_id` and `provider_state` (the droplet's name, region, size, image and addresses) in one transaction. A droplet that was not `ready` before this step stays `creating` (not built): it becomes `ready`, with `built_at`, only after steps 7-9 succeeded, so a failed pin or cloud-init leaves it unbuilt and the next `prepare` treats it as a new droplet (the 10-minute wait, the audit).
7. **Confirm the pin**: connect with the pinned key (`SSHTarget.from_host(host, building=True)`) every 10 s for up to 10 min, or 2 min for a droplet that was already `ready` before this step (`ssh.connect`, `services/ssh.py:530-594`). `SSHError` (not up yet) retries; `HostKeyMismatch` fails at once: `<droplet> answered SSH with a host key Slipway didn't generate for it. Slipway trusted nothing and sent it nothing. Check it in DigitalOcean, then retry` (`SD/do_provision.py:936-942`). A timeout with every try a TCP timeout (the cloud firewall drops, sshd refuses) fails `Slipway couldn't reach <droplet> on SSH for 10 minutes. The cloud firewall lets SSH in only from <sources>: if Slipway connects from another address, add it to <account>'s SSH sources, then retry`. On success `host.key_pinned` is audited, once per key (`provider_state.pinned_fp` names the fingerprint audited, so a retry after a cloud-init failure doesn't audit it again).
8. **Slipway's address**: on the pinned connection, `printf '%s' "$SSH_CONNECTION"`; its first field is the address the droplet sees Slipway connect from. It is added to `cloud.slipway_addresses` (audit `environment.slipway_address` the first time), and from then on the account's lock-out guard (§8) keeps it in the SSH sources. A droplet that answered at all was reached through the firewall, so the address is inside the rule the firewall has now.
9. **Readiness**: `cloud-init status --wait >/dev/null 2>&1; test -f /var/lib/slipway-ready && docker version --format '{{.Server.Version}}'` (15 min SSH timeout, `SD/do_provision.py:90`, `:113`). A failure fails the step: `cloud-init didn't finish setting up <droplet> (<last line>). Retry the deploy`.
10. **Resize check** (reads only), when `cloud.droplet_size` differs from the droplet's and the slot isn't the active one of two: the size can still be applied (the catalog: same family, offered in the region, a grow in every way). A refusal fails `prepare` here, before any change and before the deploy's own refusals. `prepare` never powers a droplet off or resizes it (Decision 14): the resize is the deploy's `resize` step (§9.4).

The host poller (`services/hosts.py:124-135`) picks the host up once it is built.

### 9.3 Removing a droplet (`do_provision.remove_droplet`)

Used by Remove slot (§14.3) and teardown. Driven from the slot's `droplet` resource row and its owned host row, never from the instance, so a retry can always see what is left:
1. Check the row's marks (J5); with no row, skip to 4.
2. `DELETE /droplets/{id}` (a 404 counts as done; any other error fails and keeps everything).
3. `resources.forget(row, deleted=True)`.
4. Reconcile the database's trusted sources without it (§10.2).
5. Delete the slot's instance row (`instances.host_id` is RESTRICT, so it goes before the host).
6. Delete the host row.
Each step commits on its own. Teardown runs 1-4 and 6 here; its `slots` step already removed the instance rows.

### 9.4 The `resize` step (`do_provision.resize_droplet`)

The one shared `resize` step key (Decision 14; P5 §6.7 is the VM side). It is listed in `PRE_START_STEPS` after `backup` when, at queue time, the droplet's applied size (its host's `provider_state.size`) differs from `cloud.droplet_size` and the slot isn't the active one of two; so every refusal of the deploy (`resolve`, `prepare`'s checks, `manifest`, `settings`, `build`, the lag check in `backup`) comes first, and a Single environment is never powered off by a deploy that then refuses (P3 I5).
1. The rule again (the slot may have become active meanwhile: the step is `skipped`); the size check of §9.2 step 10 again.
2. `power_off` (wait 5 min), `resize {size, disk: true}` (wait 30 min), `power_on` (wait 5 min), each polled through `GET /droplets/{id}/actions/{aid}`. The `power_off` POST is shielded and its action id noted the moment DigitalOcean takes it; from then on `power_on` runs in a `finally` under `asyncio.shield`, so a failed resize, a cancel or the step timeout, during the power_off's wait too, still powers the droplet on (after a cut or failed power_off: once that action ended, and only when the droplet reads `off`) (at its old size when the resize didn't finish, `SD/do_provision.py:793-815`). The log says `Resizing <droplet> to <size>: it stops for a few minutes`. A size that wouldn't grow is left alone with a note (`:729-732`).
3. Wait for SSH with the pinned key again (10 min); write `provider_state.size`.

A restart between `power_off` and `power_on` (the shielded `finally` covers cancels and timeouts, not a restart) leaves the droplet off: recovery writes the notice of §15.13, and the next `prepare` powers it on (§9.2 step 1).

---

## 10. Managed data

### 10.1 `database` step: the cluster

1. Recorded `database` row: read, check marks. A 404 → forget it and make it again, except when the environment has ever gone live or holds seeded data: then the step fails `<env>'s database cluster is gone from DigitalOcean, and its data with it. Slipway won't make an empty one by itself: retry with "Make it again, empty" (the environment's name typed), then restore a backup` (retry body `rebuild_data: true`, open question 7). A pending row → §6.4 step 1 (by the request tag).
2. None: §6.4. `POST /databases {name, engine: pg, version: cloud.db_version, region, size, num_nodes, private_network_uuid: <vpc>, tags (with the request tag), rules: [{type: droplet, value: <id>} for every recorded droplet]}` (`SD/do_provision.py:851-856`); the answer is recorded with `credentials = {admin_password}` in the same commit.
3. Wait for `online` (30 min). The trusted sources in the create body protect it meanwhile (J8); nothing uses it before step 4.
4. **Trusted sources** (`:894-920`): `GET /databases/{id}/firewall`; when it differs from the recorded droplets, `PUT` it; 409 or 422 (not ready) is retried every poll for up to 10 minutes; any other failure fails `<reason> Slipway couldn't set the database's trusted sources, so it may be reachable from any address. Retry: Slipway sets them again before anything uses the database`.
5. Grow (size or a standby node) only once online and only upward, then wait for it to leave `online` (up to 60 s) and come back (30 min) (`:863-879`, `:817-825`), then step 4 again. A cluster whose live `version` differs from `cloud.db_version` stops the step (`<cluster> runs PostgreSQL <x>, but <env> was made for <y>. Slipway changed nothing`).
6. Read `private_connection.host`/`port` and `connection.password` (doadmin; falling back to the create answer, then to the stored value, `:880-887`), `GET /databases/{id}/ca` (`SD/do_api.py:281-286`). Store `details` and `credentials` (`set_credentials`).
7. **Role and database** on the deploying slot's droplet (the member session), one command, `do_rules.psql_command` (5 min SSH timeout):

```
set -e
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT; umask 077
IFS= read -r pw; IFS= read -r ca
printf '%s:%s:defaultdb:doadmin:%s\n' <host> <port> "$pw" > "$d/pgpass"
printf '%s' "$ca" | base64 -d > "$d/ca.pem"
docker run --rm -i -v "$d:/s:ro" -e PGPASSFILE=/s/pgpass postgres:<version>-alpine \
  psql "host=<host> port=<port> dbname=defaultdb user=doadmin sslmode=verify-full sslrootcert=/s/ca.pem" \
  -v ON_ERROR_STOP=1 -q -f -
```

Stdin (`do_rules.psql_stdin`): the doadmin password, already escaped for `.pgpass` (`\` and `:`), so it reaches the file from stdin and never the command line (Decision 19); the CA in base64; then `do_rules.setup_sql(role, database, verifier=do_rules.scram_sha256(<secret>))`, the secret being the one this release renders: when the stored secrets lack the one `data.managed.<db>.password` names (a release that adds or renames it), the step takes the environment's variable of that name, else generates it as `settings` would, and keeps it with the environment at once by compare-and-set on `secrets_version` (`deployer._role_secrets`); with the stored secrets unreadable the variables must set every secret, as `settings` asks, and the slot's `data_values` render the password from those same secrets (`slot_values(..., secrets=)`). The environment has one role, so while another slot is live the step never changes its password: the database row records the secret it was last set from (`details.role_secret`, a name), a secret the release adds in its place takes that secret's value, and a release whose password secret has another value is refused before psql runs (`<slot> is live and connects to <env>'s database with the value of <old>, ... The role's password was not changed`) (`SD/pgauth.py:21-50`; the script is Sirdar's `_PSQL`, `SD/do_provision.py:96-112`, with Docker in place of a local `psql`). The host and port are quoted inline with `q()`. The doadmin password, the verifier and the secret are added to the Redactor. The SQL is idempotent: the role if missing, its password, `GRANT <role> TO doadmin`, the database if missing, its owner. A non-zero exit fails `The managed database didn't accept Slipway's setup (psql exited <n>)`.

### 10.2 Trusted-source changes

Adding a droplet (a new slot, a rebuild) and removing one (Remove slot, teardown) reconcile the rules right after the droplet change, in the same step. A droplet is in the rules before its slot's `settings` step runs the database probe (P3 §6, which runs in mode `managed` too, with `sslmode=require`).

### 10.3 `prepare`: the bucket and its key

Sirdar's `_bucket` (`SD/do_provision.py:515-596`), with intent rows: forget recorded keys DigitalOcean no longer lists (only a full listing that answered 200 counts, J13), delete every unrecorded key §6.2 says to delete (left setup keys, lost answers), check a recorded bucket with a HEAD under its key (gone → make it again: refused like a gone cluster when the owner has data), make the bucket with a temporary full-access key (`[{bucket: "", permission: fullaccess}]`, its own pending row, deleted in a `finally`, `:499-507`, `:639-651`), make the bucket's own `readwrite` key and store its secret in `credentials` in the same commit as the row (`record(..., credentials={secret_key})`), then CORS: `PUT, GET, HEAD` from `https://<hostname>` of each `data.managed.objects.cors` service, headers `*`, expose `ETag`, max-age 3000 (`SD/spaces.py:244-260`), written only when it differs, with the temporary key when the bucket's own is refused (`SD/do_provision.py:605-637`).

### 10.4 The data runner

`deployer.data_runner(env, job) -> _AppRun` (P3 §7.1 Members; Decision 18) in mode `managed`. A slot **can run** the data when its droplet host is built (`Host.is_built`) and it has a live release; a slot whose host is `planned`, `creating` or `gone` can't. In order:
1. the lead slot (P3 §2) with its live release, when it can run;
2. else the other app slot with its live release, when it can run (the log says `<blue>'s droplet isn't built; running the data commands on <green>`);
3. else, in a slot deploy, the deploying slot with its new release (as before any slot is deployed);
4. else the job is refused: owner jobs other than Start over answer `<env> has no slot that can run its data commands: deploy to <blue> first`.

This is evaluated when the job is queued (for the refusal) and again in the step that first needs the runner (it may have changed). A deploy to green while blue's droplet is gone therefore takes its pre-deploy backup on green's new release (rule 3), and Back up now, restore and snapshot run on green once green is live (rule 2).

The runner's `.env` is its own (slot role, with the managed values and the edge); P3's "data server's live release" rows of §7.1 read "the data runner" here. Each command takes the runner member's host lock (P3 §7.1). **The migration lock** (P3 §7.1): an owner job in mode `managed` first reads the `.slipway-lock` of **every** app slot over its member session; a left `d` line in either waits or refuses as P2 does for a left lock. A slot deploy writes its `d` line in its own lock only.

### 10.5 Backups on the Slipway server (`slipway/services/backup_store.py`)

- **Take**: the owner's `dump` writes `{slipway.out}` = `<runner folder>/backups/.incoming/<name>.db` on the runner's droplet (P2's paths), `verify_dump` checks it there, then `backup_store.pull(member, remote_path, backup)` streams it (`RemoteSession.read_stream`) through `snapfile.ContainerWriter` under a new per-backup key (`snapfile.new_data_key`) into `<storage_dir>/backups/<owner id>/<name>.db.sbc.part`, hashing the plaintext; the hash must equal P2's host-side `db_sha256`, else the step fails `The backup changed on its way to Slipway` and the `.part` file is removed. Then the file is fsynced, renamed to `<name>.db.sbc`, and the directory fsynced; only then is the droplet copy deleted. A `.sbc` file therefore always holds a whole, checked container. Files (`export_files`) the same. The row gets `location = slipway`, `data_key`, `stored_bytes`.
- **Space**: before the dump, P2's free-space check runs on the runner's droplet (`backup_free_margin_mb`), and Slipway checks its own storage: free space and `SLIPWAY_BACKUP_TOTAL_BYTES` (`Slipway's backup storage is full (<used> of <limit>): delete old backups or raise SLIPWAY_BACKUP_TOTAL_BYTES`). Both of Slipway's limits count the backups still being copied: a `pending` (or restart-left `unverified`) Slipway row with no `stored_bytes` counts as `stored_size` of its measured sizes, committed before its pull starts, so two environments' backups copied at once can't both take room only one has; the free-space check sets aside what those copies have still to write (less their `.part` bytes). `pull` checks again, leaving out the backup's own row, refuses a backup with no recorded size, and cuts the stream off with `The backup changed on its way to Slipway` once it passes the size measured on the runner.
- **Use** (restore, roll back, a seeding reset): `backup_store.push(member, backup)` decrypts and streams into `<runner folder>/backups/.incoming/<name>.db` (`write_stream`), checks the hash on the droplet, the command reads `{slipway.in}`, and the copy is removed in a `finally`.
- **Check** (`?check=true`, P2): the Slipway files exist, decrypt and hash to the recorded values; `missing` or `changed` as P2. A row a restart left `unverified` is not checked: it may have been cut before its key was recorded, so it stays `unverified` (never `changed` or the key-lost text) until `settle_unverified` keeps or forgets it; a missing key is reported as lost only on a row past `pending` and `unverified`.
- **Retention and Delete** (P2): delete the Slipway files. Pinned backups are kept as P2.
- **Where P2's code changes** (`services/data.py`, slice S14b). `check_backups`, `confirm_backup`, `settle_unverified` and `apply_retention` take a `remote: Remote | None` and branch on each row's `location`: rows with `location = slipway` are checked, settled and deleted through `backup_store` (`check`, `delete`) with no SSH, and `remote` may be None when every row is a Slipway row (the managed owner has no host). `settle_unverified` for a Slipway row: the `.sbc` files exist and hash to the recorded values → `ready`; else `failed` with P2's text. The deployer's retention after every backup and the data API's backup endpoints (`api/v1/instances.py`, slice S20: check, delete, download refused with `This backup is stored on Slipway; restore it from the environment page`) call these with `remote = None` for the managed owner.
- **Start-up sweep**: `backup_store.sweep()` in the lifespan removes every `*.part` under `<storage_dir>/backups/` before the runner starts, then P2's recovery marks the interrupted backup `unverified` and `settle_unverified` settles it on the owner's next job.
- **Key rotation**: `rotate-encryption-key` re-encrypts `data_key` (an EncryptedText column, covered by the walk, `core/crypto.py:104-108`); `--clear-unreadable` clears it and the backup then answers `Slipway can't open this backup any more (SLIPWAY_ENCRYPTION_KEY changed)` and can only be deleted.
- **Teardown**: the owner's Slipway files move to `<storage_dir>/kept/<env>-<env id hex[:8]>/` with a `README.txt` naming the environment and date (as P2 D18 keeps a host's `backups/`); the dialog says where. They are counted in nothing and removed by hand.

### 10.6 Phase 2 features on managed data

P3 §7.3's mode `server` column, with the data runner in place of the data server and these differences:

| Feature | Managed |
|---|---|
| Back up now | kind `backup` on the owner; dump on the runner, stored on Slipway; nothing stopped |
| Restore, roll back | `check, backup, stop_slots, restore, ⟨files⟩, start_slots, finish, ⟨first_admin⟩, traffic`: no `release/manifest/settings/build` (the runner's live release is already built and its `.env` is its own) and no data-server `stop`/`start` (the cluster is always up). `ss-stack restore` empties the schema and runs `pg_restore` through `pg()` (`SS/deploy/stack/ss-stack:453-490`) |
| Reset | `check, backup, stop_slots, wipe, ⟨restore, files, after_import⟩ˢ, start_slots, finish, ⟨first_admin⟩ᵃ, ⟨seed⟩ᵒ, traffic`. Before anything stops, `backup` checks what `wipe` needs (`deployer._wipe_precheck`): the cluster's address and a readable doadmin password (else `Slipway can't read doadmin's password for <cluster>: … Slipway changed nothing: deploy to a slot, whose database step reads it from DigitalOcean again, then retry`), and the bucket side, `do_provision.wipe_check`: the bucket recorded, the team, and a temporary full-access key made, used for a HEAD of the bucket and deleted again. A refusal there fails `backup`, so nothing is stopped or held. **`wipe`** (`Empty the database and the bucket`): first the bucket (below), so a failure there leaves the database as it was and its text says so rather than `Slipway changed nothing`; then, as doadmin on the runner (the §10.1 command), `do_rules.reset_sql`: `DROP DATABASE IF EXISTS <db> WITH (FORCE);` then `SELECT 'CREATE DATABASE <db> OWNER <role>' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '<db>') \gexec` (the two can't share a transaction, so a run cut off between them leaves no database, and the retry, which P2's hold allows, ends with an empty one either way); the bucket emptied with a temporary full-access key, made only after the team check (D3, J9: another team gets no key) (page by page; unfinished multipart uploads aborted, `SD/spaces.py:156-230`, `SD/do_provision.py:1507-1528`); slot-local volumes (`holds: other`) removed on each slot (P3 §7.3) |
| Start over (never live) | `backup, stop_slots, wipe` |
| Take snapshot | export on the runner, streamed to Slipway as P2; `stop_app` stops both slots |
| Seed a new environment | the first app slot deploy is the seeding deploy: P2's `check, stop, restore, files, after_import` before `start`, run as the owner's commands on the deploying slot (the runner); `import-objects` writes to the bucket |
| `has_data` exit 4 | fails the step `<env>'s data is managed; data.managed.commands.has_data must answer for the managed database (exit 4 means "elsewhere")` |

Everything else (dirty state, hold, lead slot, stale slots, the lag check, expand/contract, Discard) is P3's, unchanged.

---

## 11. The edge: certificate, load balancer, firewall, VPC

### 11.1 `prepare`: the VPC

Sirdar's `_vpc` (`SD/do_provision.py:459-497`): recorded and gone → forget and remake; recorded and unmarked → stop; a pending row → §6.4 step 1; unrecorded with the name and marker → adopt; unrecorded with the name and no marker → stop; none → §6.4, `POST /vpcs {name, region, description}` (the marker and ` req:<nonce>`), record. `cloud.vpc_range = ip_range`.

### 11.2 `edge` step: the certificate (`slipway/services/certs.py`, `acme.py`)

1. `wanted` = the sorted union of the active-following hostnames (P3 §10.1; on DigitalOcean every route follows the active slot, `skip` services have none) of **every app slot's live release** (`app_state.routes`; `certs.wanted_names`) and, in a deploy, of the deploying slot's new release (from the manifest `prepare` read). A name therefore leaves the certificate only when no slot's live release serves it: after both slots were deployed without it, at the next renewal or `edge`. Every one must be inside the Cloudflare zone (P3 §9.1 refusal 7). At most 100 names (Let's Encrypt).
2. Find ours: the certificate the load balancer serves when it is ours and unrecorded (record it), a pending certificate row whose stamped name DigitalOcean lists (an upload whose answer was lost: record it, clear its credentials), every listed certificate that `is_ours` and isn't recorded (record it), every recorded one that answers 404 (forget it) (`SD/do_provision.py:968-992`).
3. The best is the one expiring last; on a tie, the one the load balancer serves (`:993-996`).
4. When there is none, or the best has 30 days or fewer, or its `dns_names` aren't exactly `wanted`:
   a. **Reuse a kept certificate**: a pending certificate row whose `dns_names` equal `wanted` and whose `not_after` is more than 30 days away, and which DigitalOcean doesn't list (two lookups, §6.4): upload it again under the same name.
   b. **Else issue.** First sweep left challenge records for the order's names (`certs.sweep_challenges(txt, wanted)`): every TXT `_acme-challenge.<name>` of a wanted name with Slipway's comment `Managed by Slipway: ACME challenge` is deleted (a crashed run's leftovers). Records at other names are left: every environment shares the zone and the comment, so a zone-wide sweep would delete another environment's challenge in flight (Decision 19). Then the ACME order for `wanted` with DNS-01: for each name a TXT record with that comment (Cloudflare's `create_txt`, added in S05, through `acme_store.TxtRecords`), held for 15 s, deleted in a `finally`; a failed delete is logged, never raised; these records are not in `resources` (`SD/certs.py:102-117`; sirdar-traffic §2). The issued chain and key are written **at once** to a pending `certificate` row (`credentials = {private_key, leaf, chain}`, `details = {not_after, dns_names, pending}`) before anything else can fail.
   c. `POST /certificates {name, type: custom, private_key, leaf_certificate, certificate_chain}`; the answer replaces the pending row in one commit with `credentials = NULL` and `details = {not_after, dns_names}`. The private key never touches disk or the log (added to the Redactor).
   So a failed upload, a timeout, a restart or a cancel after a successful order never orders the same names again while the kept certificate has more than 30 days left (D12). `fake_acme` counts orders (test 74).
5. `cloud.certificate = {id, name, not_after, names}`.

Staging (`cloud.acme_staging`, non-production only) uses `SLIPWAY_ACME_STAGING_DIRECTORY`, and the public check then runs with `verify=False`, logged (`SD/do_provision.py:1210`).

### 11.3 `edge` step: the load balancer

**Frozen values first** (D15): on the environment's first `edge`, `cloud.edge = {port: edge.port, health: edge.health}` is written (audit `environment.edge_frozen`). Afterwards `prepare` has already refused a release whose values differ (§14.3), so `edge` always builds with `cloud.edge`, never with the release's.

Recorded → read, check name and VPC; a 404 → forget and make again (nothing can point at it any more: the next deploy's `traffic` step or a Publish puts the active slot back on it, §6.3). Its new IP is recorded at once; when a DNS record Slipway published for the environment names another address, the deploy lists `dns` (`Move DNS to the load balancer's new address`) right after `edge` and publishes every name there, so no name keeps pointing at the address DigitalOcean released. That step never fails the deploy: a refusal or a Cloudflare failure ends it as a warning that a Publish moves them. A pending row → §6.4 step 1. Unrecorded → adopt by name in the VPC. None → §6.4, `POST /load_balancers` with:

```
{name, region, size_unit: 1, vpc_uuid,
 forwarding_rules: [{entry https 443 → http <edge.port>, certificate_id, tls_passthrough: false},
                    {entry http 80 → http <edge.port>}],
 health_check: {protocol: http, port: <edge.port>, path: <edge.health>, check_interval_seconds: 10,
                response_timeout_seconds: 5, healthy_threshold: 3, unhealthy_threshold: 3},
 redirect_http_to_https: false, droplet_ids: []}
```

(`SD/do_provision.py:253-266`; HTTP:80 stays open without a redirect because the app redirects itself using `X-Forwarded-Proto`, `SS/deploy/stack/proxy/Caddyfile:22-51`; `droplet_ids` is empty by D11). The answer replaces the pending row (§6.4). An existing one whose HTTPS rule names another certificate gets a full-body `PUT` (`lb_update_body`: the live body without `id, ip, ipv6, status, created_at`, `region` as its slug, no `size` beside `size_unit`, no `tag` beside `droplet_ids`, `:269-285`), after waiting for `active` (DigitalOcean refuses a PUT mid-change, `:1157-1168`). Wait for `active` and an `ip` (10 min); `cloud.lb_ip` and `traffic.dns.address` = the IP. An existing load balancer whose forwarding port or health check differs from `cloud.edge` stops the step (`<lb> no longer forwards to port <port>: Slipway changed nothing`): it was changed by hand. Then delete our certificates that aren't the served one and whose names are not `wanted` (a "403 in use" is left for the next run, `:1068-1079`); a 403 that isn't "in use" stops (J13).

### 11.4 The cloud firewall (`prepare` makes it, `edge` completes it)

The whole body (`SD/do_provision.py:301-311`, with D14's SSH sources):

```
{name: slipway-<env>-fw, tags: [slipway-env-<id>], droplet_ids: [],
 inbound_rules:  [{tcp 22 from addresses: <account.ssh_sources>},
                  {tcp <cloud.edge.port> from load_balancer_uids: [<lb id>]}],   # only once the LB exists
 outbound_rules: [{tcp all}, {udp all}, {icmp}] to 0.0.0.0/0 and ::/0}
```

- **`prepare`**, before the droplet: the firewall is made (§6.4) or read. Made with the SSH rule and the outbound rules only; it applies by tag, so the droplet is covered from its first boot and its SSH port is never open to the world (D14).
- **`edge`**, after the load balancer: when the HTTP rule is missing or names another load balancer or port, a `PUT` with the whole body; `details.lb_rule = true`.
- **Drift** (either step): compared after normalising (DigitalOcean answers `"0"` for `all`, `:314-334`); fixed with a `PUT`, never delete and create (`:1081-1118`).
- **SSH rule changes are proven** (J14). After any `PUT` that changes the SSH rule (new account sources, or drift), Slipway opens a **fresh** SSH connection to every built droplet of the environment (`ssh.connect`, a new session, 2 minutes each). If one fails, the previous body is `PUT` back and the step fails `After the cloud firewall's SSH rule changed, Slipway couldn't reach <droplet> any more, so it put the previous rule back. Slipway connects from <cloud.slipway_addresses>; keep it in <account>'s SSH sources`. With no built droplet the change stands (nothing can be locked out yet). A built droplet that DigitalOcean reports `off` (a resize cut by a restart, §9.4) can't answer, so it is left out of the proof (`<droplet> is powered off, so the new SSH rule is proven when it is powered on`): the `prepare` that powers it on (§9.2 step 1) proves the rule with its pin, which fails with the sources text of §9.2 step 7 when the rule leaves Slipway out.
- With `0.0.0.0/0` or `::/0` in the sources the log and the page warn `SSH to <env>'s droplets is open to the internet`.

### 11.5 The edge in `.env`

`edge_values = {address: cloud.lb_ip, trusted: cloud.vpc_range}` (§5.3) go into every app slot's plan (`do_provision.slot_values`). `app_state.live.edge`, a new key, records them; a slot whose recorded address differs from `cloud.lb_ip` is stale (§6.3).

### 11.6 The `do_lb` backend (`slipway/services/do_lb.py`)

Implements P3's `TrafficBackend` (P3 §10.2). `name = "do_lb"`. Registered with `traffic.register(DoLbBackend())` when `slipway.services.do_lb` is imported (the app's lifespan imports it; S05 adds `register`; P3's `BACKENDS` dict is otherwise unchanged).

**What S05 changes in `traffic.py`** (said plainly, since P3 §10.9 said nothing would; Decision 16):
- `TrafficBackend` gains `lock(ctx) -> asyncio.Lock`, `who_is_live(ctx) -> list[str]` (the slots whose hosts the backend serves now), `put_back_locked(ctx, plan, applied)` (until now duck-typed in `_shielded_put_back`) and `repair(ctx) -> SyncResult | None` (Switchyard returns None). Every acquire of the Switchyard lock in `switch`, `sync` and `_shielded_put_back` becomes `backend.lock(ctx)`. `SwitchyardBackend.lock` returns `switchyard.lock` (`_lock` is only its alias), so Switchyard's behaviour is unchanged.
- `SwitchContext.mode` gains `deactivate` (`to_slot` is None); `context()` accepts it and `switch()` no longer forces `activate`. In that mode `traffic.switch` refuses on blockers as `activate` does, runs `backend.verify`, which each backend defines for the mode, and its failure texts read `Traffic stays on <from>`. Switchyard's `plan` answers a blocker `<env> uses Switchyard; take its names off in Switchyard instead` (open question 3).
- `sync` hands its Switchyard-specific body (the count of its own edits, the traffic address, the Switchyard plan texts, the public check) to the backend, then calls `backend.repair(ctx)` when nothing is unresolved; for Switchyard the result equals P3's.
- `plan_for` asks for Switchyard's settings only when the backend is Switchyard (S20 does the same in `api/v1/environments._plan_blockers`).
- `traffic.register(backend)` adds to `BACKENDS`; `public_check` takes an explicit `address`, `insecure` (skip certificate checks, for Let's Encrypt staging) and `via` (the path named in its log and failure texts; P3's texts by default).
- `traffic.switch` only returns its `SwitchResult`; the fields it implies (`active_slot_id = slot` for `activate`, `= NULL` for `deactivate`, status `live`) are written by the caller in `env_jobs.py` (P3 §9.5 step 6; S15 adds the `deactivate` branch).
- **Resolve** (Decision 17) is dispatched in `env_jobs.resolve`: it calls `traffic.backend_for(env).who_is_live(ctx)` under `backend.lock(ctx)` instead of the Switchyard lock; the API only maps `DigitalOceanError` to 502. `env_jobs.recover` calls `switchyard.hold_in` only when `options.switch.backend == "switchyard"`, and recovers an interrupted `deactivate` too (§15.13).

The backend:
- **`lock(ctx)`**: an `asyncio.Lock` per load balancer id, also taken by the `certificate` job's HTTPS rule PUT. The environment's `(env, traffic)` runner key already serialises them; this lock covers a renewal loop bug.
- **`configured(db)`**: the account has a token; the environment's team is set or learnable.
- **`plan(ctx)`** (reads only): the team check (D3); the recorded load balancer (`This environment has no load balancer yet: deploy it first` / `… is gone: deploy again to make it` / `… is no longer named …`); its `status == active` (else blocker `The load balancer is applying a change; try again in a minute`); `previous` = its `droplet_ids` that are recorded droplets of this environment and still exist (DigitalOcean drops deleted droplets from a load balancer; an id that is neither recorded nor live is a blocker `The load balancer sends traffic to droplet <id>, which isn't <env>'s: Slipway changed nothing`); the target slot's recorded droplet, live, with both tags; the HTTPS rule's certificate is recorded and its `dns_names` cover the target slot's routes (else blocker `The certificate doesn't cover <names>: Renew the certificate first`). One `Change(hostname = <lb name>, action = update | none, external_id = <lb id>, before = {droplet_ids: previous}, after = {droplet_ids: [new]}, summary = "slipway-prod-lb → green (droplet 4002), was blue (4001)")`. Mode `deactivate` plans `after = {droplet_ids: []}`. Mode `sync`: below.
- **`apply(ctx, plan)`**, mode `activate` (`SD/do_provision.py:1256-1276`):
  1. When `previous` is already `[new]`: nothing to write; return.
  2. `PUT previous + [new]` (wait `active` before and after, 3 min each, `:1162-1168`); `options.switch.changed` updated in its own transaction.
  3. The slot's own health over its member session: `curl -fsS -o /dev/null --max-time 5 -H 'Host: slipway-health.invalid' 'http://127.0.0.1:<cloud.edge.port><cloud.edge.health>'` every 10 s for up to 5 min (`:1181-1197`); a Host outside the app's names reaches the health route (`Caddyfile:27-29`).
  4. Sleep the settle time `healthy_threshold × check_interval_seconds + 10` from the live body (`:1170-1179`).
  5. The public check (P3 §10.8's `traffic.public_check`, with `address = <lb ip>:443`, rounds enough to outlast the settle time, `:1199-1213`; every name is asked over HTTPS with the certificate verified, whatever its Switchyard TLS mode in `route_tls` or Switchyard's default says, except with staging certificates); a failure raises `SwitchFailed("<n> of <m> names didn't answer through the load balancer: <names>")`.
  6. `PUT [new]` (wait `active`), sleep the settle time again.
  7. **Prove**: `GET` the load balancer: `droplet_ids` must be exactly `[new]` and the HTTPS certificate recorded (`:1282-1300`); else `SwitchFailed("The load balancer's targets changed during the switch (now <ids>): something else updated it")`.
  8. `Applied(changes, apply_n = None)`.
- **`apply`**, mode `deactivate` (Sirdar's no-slot branch, `SD/do_provision.py:1230-1236`): wait `active`; `PUT []`; wait `active`; prove: `droplet_ids` exactly `[]`. `options.switch.changed` as above.
- **`verify(ctx, plan)`**: mode `activate`, the public check through the load balancer once more (6 rounds); mode `deactivate`, a `GET` that finds no targets (the names answer 503 by design, so the public check is **not** run); mode `sync`, the public check (1 round, a warning).
- **`put_back(ctx, plan, applied)`** (never raises): wait `active`, `PUT previous`, re-read: equal → done; else `PutBack.failed` with `Point load balancer <name> at <slot> (droplet <id>) in DigitalOcean, then use Resolve` (`:1302-1311`). P3's `traffic.switch` turns that into `traffic_state.unresolved` (P3 §10.6). The switch waits for it `put_back_timeout` seconds, not P3's 120: two waits for `active` (3 min each), three DigitalOcean requests at their timeout with a 429 retry, and a minute's margin (11.5 min), so a slow put-back that lands isn't reported as unresolved. That figure isn't a strict bound on DigitalOcean (one request can retry a 502 and a 429 again), so `put_back_locked` runs its calls under its own `asyncio.timeout` of that wait less 30 s and, past it, ends with the by-hand text (`DigitalOcean took longer than <n> s`): the switch's wait never ends before the put-back does. In a sync repair whose `previous` was empty, there is nothing to put back: done.
- **`remove(ctx)`**: an empty plan with the note `The load balancer goes with the DigitalOcean objects` (teardown's `cloud` step deletes it, §15.11).
- **`who_is_live(ctx)`**: the slots whose recorded droplets are the load balancer's targets (one slot when one droplet is the only target). Resolve (P3 §9.12) sets that slot active, or answers 409 naming the targets when they aren't exactly one slot's droplet; `env_jobs.resolve` dispatches it (Decision 17). After a cut-off Deactivate (the unresolved switch names a `deactivate` job and no target slot), no target means the empty list stands: Resolve records what Deactivate's own closing write would have (`active_slot_id = NULL`, `traffic_state.deactivated`, audit `environment.resolve` with `slot: null`).
- **`sync` and the sync repair** (P3 §10.1 mode `sync`: a deploy's `traffic` step, and Publish, whose environment step is named `Update the load balancer` for `do_lb`), through the backend's `repair` hook. Skipped while a switch is unresolved (P3 I6). When nothing is recorded active: no write. When the **recorded active** slot's current droplet is the load balancer's only target: no write, the public check as a warning. Otherwise (no targets, only ids that are gone, or the active slot's old droplet id after a rebuild) it runs the **repair** for that same slot: `previous` = the live, recorded targets (usually none); `PUT [active droplet]`; its health over SSH; settle; public check; prove. A failing health or public check is a warning (nothing answered before either); a failing prove raises as in `activate`. It never adds another slot's droplet, so traffic never moves between slots (P3 I6).

P3's `dns` step publishes every route at `traffic.dns.address`, which is the load balancer's IP; DNS never moves on a switch (P3 D14). It never falls back to Cloudflare's public IP: until `edge` has written the address, Publish names and the dry run are refused (`<env>'s load balancer isn't made yet: deploy first`), and so is the `dns` step.

---

## 12. Cost safety

### 12.1 The plan and its estimate (`do_rules.cost`)

`cloud.plan` = `{droplets: n, droplet_size, db_size, db_nodes, db_version, lb_size_unit: 1, bucket: 1, certificates: 1, vpc: 1, firewall: 1}`. `do_rules.cost(plan, catalog, prices) -> Cost{lines, total_cents, as_of}`:

| Line | Price from |
|---|---|
| `<n> × droplet <size>` (`<vcpus> vCPU, <memory> GB, <disk> GB`) | `GET /sizes` `price_monthly` (`api`) |
| Database cluster `<size>` × `<nodes>` node(s), PostgreSQL `<version>` | the table (`table`) |
| Load balancer, 1 node | the table |
| Spaces subscription (per account; already paid if the account uses Spaces) | the table |
| VPC, cloud firewall, certificate | $0.00, listed so every object is named |

Totals are in cents, shown as dollars with two decimals. The foot says `Estimated, prices as of <as_of>; bandwidth beyond the allowance, DigitalOcean backups and taxes are extra.` `as_of` is the table's date (the account's override in `config.prices` has its own). The prices come from `do_rules.price_layers(account.config.prices, None)`: the account's override, then the code's table; there is no install-wide layer (Decision 41).

### 12.2 Confirmation

- `POST /environments?check=true` (DigitalOcean placement) answers `cost` at the top level and the objects under `plan.cloud` (§15.1, §16). `POST /environments` needs `confirm_cost` equal to `cost.total` as shown (`"84.00"`; a leading `$` and surrounding spaces are ignored), else 422 `{detail: "Type 84.00 to confirm about $84.00 a month", field: "confirm_cost"}`. **Before** the transaction opens, the request reads the catalog uncached (`catalog(..., fresh=True)`, §8) and computes the cost; a total different from `confirm_cost` answers 409 `The estimate changed to $<x> a month (DigitalOcean's prices moved): check it again`, so a stale page can't confirm. Inside the transaction (account row `FOR UPDATE`) only stored values are compared: the cost just computed, the limit, and the other environments' stored totals. No HTTP call is made under the lock.
- Add slot and a growing PATCH answer the **new** total and the delta (`+$<d> a month`) and need `confirm_cost` equal to the new total, with the same before-the-transaction read.
- The account's `monthly_limit_cents`: the sum of `cloud.cost.total_cents` over the environments that use the account (`deleted_at IS NULL`, §8) plus the new total must not pass it: 409 `This would bring <account>'s estimate to $<x> a month, over its limit of $<y>`.
- Stored: `cloud.plan`, `cloud.cost` with `confirmed_by_id`, `confirmed_at`; audit `environment.cost_confirmed`.

### 12.3 At run time

`prepare`, `database` and `edge` compare every create with `cloud.plan` before sending it (§6.4 step 3). The count for a kind is recorded rows + pending rows + live objects that carry the environment's tag (droplets and clusters through `?tag_name=slipway-env-<id>`) or its fixed name (the load balancer in the VPC, the bucket), each object counted once. A droplet beyond `droplets`, a cluster of another size or node count, a second load balancer or bucket fails `This would make <object>, which <env>'s confirmed plan doesn't include: <how to confirm it>. Slipway changed nothing`. Remaking a gone object is inside the plan (it replaces one). Sizes are only ever the confirmed ones: a growing PATCH changes `cloud.plan` and `cloud.droplet_size` together when it is confirmed (§15.7).

### 12.4 While unfinished

A never-live environment (status `new`) with any DigitalOcean row, pending rows included, shows the **Billing** callout: `<n> DigitalOcean objects exist for <env> and cost about $<x> a month: retry the failed deploy, or delete the environment to remove them.` The list page marks it.

---

## 13. Production safeguards

- **Create**: `production: true` needs a `production` account, two app slots (`Production runs Blue and Green`), `auto_activate` false, `acme_staging` false; a non-production environment may not use a production account (`<account> is for production environments`). `ux_environments_one_production` (409 `<repo>'s <manifest> already has a production environment, <name>; retire it first`).
- **Activate and Switch back** of a production environment need `confirm` = its name (P3 open question 2; `SR/deploy.py:1334-1335`); the route takes `ActivateIn = SlotIn + confirm?`, passes `confirm` into the job's options, and the fence refuses a production activate without the typed name (422) (Decision 39); the dialog shows the field.
- **Retire** (`POST /environments/{id}/retire {confirm}`): sets `retiring_at`. Retire and Un-retire are refused while a job of the environment is queued or running (P3's busy text), as Grow is. A retiring production refuses any activate of a slot (`<env> is retiring: it only goes dark`, `SR/deploy.py:1267-1270`): when it is queued, again in the activate's `check`, and once more under the backend's lock just before the switch's first write. It accepts deploys (a fix) and data jobs. While a production environment isn't retiring, Remove slot is refused (`Production runs Blue and Green: retire <env> first`): with one slot, every deploy would replace the live release in place. **Un-retire** (`DELETE /environments/{id}/retire {confirm}`): refused when another non-retiring production exists for the same repository and manifest (the unique index; a lost race answers the same 409, `SR/deploy.py:765-769`).
- **Deactivate** (`POST /environments/{id}/deactivate {confirm}`, kind `deactivate`): only a retiring production with an active slot (`SR/deploy.py:1273-1280`). Steps `check, switch`: `traffic.switch` in mode `deactivate` (§11.6): plan `after = {droplet_ids: []}`, `PUT []`, prove, verify that the targets are empty (no public check), put back on failure; then `env_jobs` writes `active_slot_id = NULL` in the switch's closing transaction (audit `environment.deactivate`). The public names answer 503 from the load balancer afterwards; the dialog says so.
- **Delete**: needs `retiring_at`, no active slot (`Deactivate <env> first`), `confirm_production = "delete production <name>"` (422 otherwise) and a snapshot, with two exceptions:
  - **The owner never held data** (`fresh_data == "empty"`, no backup row that reached `ready`, and no app slot deploy whose `start` step began): no snapshot is needed; the dialog says `<env> never held data, so there is nothing to snapshot`, and a `snapshot` in the body is ignored with that note. This is the production environment whose first deploy failed in `prepare`, `database` or `edge`.
  - **It holds data, but no slot can run the data commands** (§10.4 rule 4: every app slot's droplet is gone or not built): the snapshot can't be taken. The dialog offers `Deploy to <blue> first, then delete with a snapshot`, or a second phrase `confirm_no_snapshot = "delete production <name> without a snapshot"` (422 otherwise), which needs `environments:delete`; `options.no_snapshot = true`, audit `environment.delete_without_snapshot`.
  - Otherwise `snapshot` is required (422 `A production environment is deleted only after a snapshot`).
  The rules are read under `SELECT … FOR UPDATE` of the environment row, so Un-retire can't race them (`SR/deploy.py:1153-1164`). The snapshot then the teardown chain is P3 §9.10's. The teardown's `check` step reads them again, and a retry of the teardown asks the phrase (and the second phrase, when it was used) again (`SR/deploy.py:1615-1617`).
- **Managed data, any environment** (Decision 26, the rule P5 §9.9 applies to a data VM): the cluster and the bucket are the data's only home, so Delete takes a snapshot unless the body has `drop_data: true`, which needs `data:reset` (403 without it; 409 `<env>'s data is in its managed database, which Delete destroys: take a snapshot first, or confirm that the data goes with it`, field `drop_data`, when neither is given, as P5's text for a data VM). An owner that never held data (the test above) needs neither. Production's phrases stay on top of this. Delete's `Take a snapshot first` is ticked by default when the owner holds data and a slot can run its commands; unticking it shows `The database cluster and the bucket are destroyed with <env>. Without a snapshot the data is gone for good.` and the `[ ] Delete <env>'s data with it` box (`drop_data`, `data:reset`). It is **unticked** by default, with the note, when the owner never held data, and disabled (`No slot can run the data commands: deploy to <blue> first`) when no slot can run them. This is stricter than this spec's first revision, which let a non-production delete go without a snapshot on a warning alone (plan Open questions).

---

## 14. Jobs

### 14.1 Kinds (P3 §8.1 additions)

| kind | runs on | label | steps |
|---|---|---|---|
| deploy (app slot, DigitalOcean) | the slot | `Deploy to <green>` | §14.3 |
| certificate | the environment | `Renew the certificate` | `check, certificate` |
| deactivate | the environment | `Take <env> off the air` | `check, switch` |
| teardown (DigitalOcean) | the environment | `Delete environment` | `check, undns, slots, data_server, cloud, forget` |
| remove_slot (DigitalOcean) | the environment | `Remove <green>` | `check, slot` |

`data.ENV_KINDS` gains `certificate` and `deactivate`. Runner keys (P3 §8.2, `data.env_keys`): `certificate` takes the traffic key alone, `((env, "traffic"),)`; `deactivate` both keys (Decision 22). `queue_job` gains the fences of §13, the not-built rule (§3.3), the data runner refusal (§10.4 rule 4), the system actor (§15.12), and one change to P3 §9.3's refusal: a deploy to the active slot is allowed while that slot's droplet host isn't built (`not Host.is_built`, D28), or while its rebuilt host has no live release yet (`jobs.release_gone`). The retry rows are `data.RETRY_PERMISSION` and `RETRY_EXTRA` (§4.1).

### 14.2 Step catalogue additions (`STEP_NAMES`)

Each timeout is at least the sum of the waits inside the step plus a margin; §18 gives the sums. Two catalogues hold them (Decision 13). **Member steps** (a slot's or the owner's job) are keys of `deployer.STEP_NAMES`, named per provider in `steps_for`; their timeouts are a new mechanism in the deployer (none existed: only `env_jobs._step` used `asyncio.timeout`): `deployer.STEP_TIMEOUTS` plus per-provider overrides, so `prepare` and `resize` share one key with phase 5's VMs and take each provider's limit. A timeout cancels the step; its shielded parts still finish. **Environment steps** are keys of `environments.ENV_STEP_NAMES` and `ENV_STEP_TIMEOUTS`, applied by `env_jobs._step`.

| key | catalogue | name | timeout |
|---|---|---|---|
| `prepare` | member | `Prepare DigitalOcean` (VMs: P5 §10.2) | 50 min (VMs 120) |
| `resize` | member | `Resize <droplet> to <size>` (VMs: `Resize <vm> to <size>`) | 60 min (VMs 90) |
| `database` | member | `Set up the database` | 65 min |
| `edge` | member | `Set up the load balancer` | 40 min |
| `wipe` | member | `Empty the database and the bucket` | 45 min |
| `certificate` | environment | `Renew the certificate` | 45 min |
| `cloud` | environment | `Remove the DigitalOcean objects` | 75 min |
| `switch` (deactivate) | environment | `Take traffic off {from_slot}` (`env_steps_for`'s format values gain `from_slot`) | 20 min (P3's) |

Publish's environment step `traffic` is named per backend in `env_steps_for`: `Update Switchyard` for Switchyard (P3's, unchanged), `Update the load balancer` for `do_lb`. The sync skip text for an environment with no backend stays P3's (`doesn't publish its names through Switchyard`); a `do_lb` environment always has a backend, so it never shows. The phase 5 VM kinds' member steps (`vm_snapshot`, `prune`, `vm_revert`, `wait`, `vm_settle`, `vm_drop`) and environment steps (`machine`, `machines`) are in the same two catalogues (P5 §10.2).

### 14.3 Step lists (DigitalOcean)

⟨…⟩ as P3 §8.4.

- **deploy, app slot:** `resolve, prepare, database, edge, ⟨dns⟩ˡ, source, upload, manifest, ports, settings, build, ⟨check, stop, restore, files, after_import⟩ˢ, backup, ⟨resize⟩ʳ, start, finish, ⟨first_admin⟩ᵃ, smoke, traffic`.
  - `resolve` first, then `prepare`, for both providers (Decision 12); a `prepare` failure fails the job and nothing after it runs. `resolve` is P3's (GitHub only, on the Slipway server). Its reuse probe of a retried release (`deployer.py`'s `if reuse:` block) treats a host that isn't built as "release gone" and downloads again, without SSH.
  - `prepare` starts by reading slipway.yml **at the resolved commit** (`gh.get_file(repo, manifest_file, commit_sha)`), parsing it and storing `options.manifest_sha256`. It refuses, before any DigitalOcean write: the `digitalocean` capability missing; `edge.port` or `edge.health` differing from `cloud.edge` (`<sha7> changes edge.port from 80 to 8080, but <env>'s load balancer and firewall were made for 80: a new port needs a new environment. Slipway changed nothing`); `data.managed.db.version` differing from `cloud.db_version` (the same form). `prepare`, `database` and `edge` use only this parsed manifest. On a retry the commit is the same, so the hash is too.
  - `manifest` (P3's) additionally checks that the uploaded slipway.yml's sha256 equals `options.manifest_sha256`, else fails `The slipway.yml on <droplet> isn't the one Slipway provisioned from`.
  - `settings` includes the database probe (P3 §6, `sslmode=require`). `backup` runs on the data runner (§10.4), with P3's lag check.
  - ʳ: the shared `resize` step (§9.4), in `PRE_START_STEPS` after `backup`, listed when the droplet's applied size differs from `cloud.droplet_size` at queue time and the slot isn't the active one of two (Decision 14).
  - `traffic` is the `do_lb` sync, with its repair (§11.6), when the deploying slot is the recorded active slot (a Single environment in place, or a rebuild of the active slot's gone droplet, D28); else skipped `Traffic stays on <blue>; activate <green> to move it`. Like every member `traffic` step it never fails the job (P3 §8.4).
  - ˢ: the first app slot deploy of a seeded environment (§10.6).
  - ˡ: added when `edge` left the load balancer at another address than the environment's published DNS records (§11.3).
- **activate:** `check, ⟨start_slot⟩ʳ, smoke, ⟨certificate⟩ᶜ, ⟨dns⟩ᵈ, switch, ⟨seed⟩ᵏ`. ᶜ: the served certificate doesn't cover the target slot's routes, or has 30 days or fewer. Its `wanted` is §11.2's union, so the slot giving up traffic keeps its names for a Switch back.
- **restore, rollback, reset, start over, snapshot, backup (owner):** §10.6.
- **publish:** P3's list; its `traffic` step is named `Update the load balancer` and runs the `do_lb` sync with its repair (§11.6).
- **certificate:** `check` (team, a load balancer recorded, no unresolved switch); `certificate` (`do_provision.renew`): §11.2 steps 2-4, then the load balancer's HTTPS rule `PUT` (under `do_lb`'s lock), a re-read (a certificate other than ours fails `The load balancer serves a certificate that isn't Slipway's for <env>. Slipway deleted nothing`, `SD/do_provision.py:1339-1366`), `cloud.certificate`, old certificates deleted.
- **remove_slot:** `check` (P3 §9.9's refusals, the marks of the slot's droplet); `slot`: `do_provision.remove_droplet` (§9.3: the droplet, its row, the trusted sources, the instance row, the host row, in that order; no SSH, the droplet goes), then `cloud.plan.droplets = 1` and `cloud.cost` recomputed and audited, **last**. **Retry:** continues while a `droplet` row or an owned host row for the slot remains; only when neither remains and the instance is gone does `slot` answer `Already removed` (P3 §9.9's rule, narrowed).
- **teardown:** `check` (P3 §9.10 + §13 + `do_provision.check_all`, J5); `undns` (P3); `slots`: each app slot's instance row deleted without SSH (its droplet goes in `cloud`), green first; `data_server`: the owner row deleted, its Slipway backup files kept (§10.5); `cloud` (§15.11); `forget` (P3: no `resources` row left, pending rows included). P3's `unroute` is skipped (no `proxy_host` rows; `do_lb.remove` notes why).
- The remove_slot and teardown lists stay per provider (Decision 15): these for DigitalOcean (the droplet goes inside `slot`, in §9.3's order, so test 46's order holds), and P5 §10.3's `check, slot, ⟨machine⟩` and `check, unroute, undns, slots, data_server, ⟨machines⟩, forget` for VMs. What they share is `hosts.owned_by(env, host)`: `slot`, `slots` and `data_server` delete the instance rows of owned hosts without SSH, whatever the provider.

### 14.4 Concurrency

P3's runner keys cover every DigitalOcean job of an environment: two slot deploys, a deploy and an Activate, a renewal and an Activate never run together. Nothing is serialised per account: two environments in one account provision side by side (each touches only its own objects, J4). The renewal loop queues through `queue_job`, so a running job makes it wait for the next round. A `certificate` job takes only the traffic key, but P3's partial index `ux_deployments_one_active_env` stays, so a renewal also waits for a running Back up now; the loop skips busy environments (Decision 22).

---

## 15. Flows

Refusals are answered before anything changes (P3 I5); typed-text mismatches are 422 and are checked first.

### 15.1 Create (`POST /environments`, placement `digitalocean`)

**Body additions:** `placement: {provider: "digitalocean", account_id, region, droplet_size, db_size, db_standby: bool, acme_staging: bool}`, `production: bool`, `confirm_cost`; `data_mode` takes `managed` (forced here). `hosts` is not given (the droplets are made). `traffic` is fixed: `{switch: "do_lb", dns: {proxied: bool}}`. `environments.provider` stores the placement (`ssh` or `digitalocean`); an environment with phase 5 VMs is placement `ssh` (P5 §9.2), and one create body serves both (Decision 24).

**Refusals** (`environments.validate_create`, after P3 §9.1's name, repository and settings rules):
1. `providers:spend` (403).
2. The account: exists, is a DigitalOcean account (`<account> is a <Proxmox or ESXi> account: choose Hosts under Where`; P5 §9.2 refuses the other way round), has a token that opens (`Slipway can't read <account>'s token any more: enter it again`), `ssh_sources` set, production rules (§13).
3. The manifest's `digitalocean` capability (`<repo>'s slipway.yml at <branch> doesn't say how it runs on managed data behind a load balancer (data.managed and edge)`), and `bluegreen` for two slots (P3 §7.6; with Decision 20, `data.managed` with `expand_contract` migrations gives it).
4. The catalog (live reads): the region available and in `SPACES_REGIONS`; the droplet size offered there; the database size in the layout for the node count (`db_standby` → 2; `SD/do_envs.py:186-192`); the manifest's PostgreSQL version offered.
5. Cloudflare configured and every name inside its zone (DigitalOcean environments always publish DNS).
6. Host names `slipway-<env>-blue` (and `-green`) free (`A host named slipway-<env>-blue already exists: rename it, or pick another environment name`).
7. Traffic follows placement (§3.2): placement `digitalocean` needs `traffic.switch = do_lb`, and `do_lb` is refused on placement `ssh` (field `traffic.switch`).
8. The cost (§12.2): `confirm_cost` against the fresh catalog read made before the transaction; then, inside it, the limit.

Validation runs on unsaved `Host` stand-ins from `hosts.planned_host(...)`, so P3's readers of `CreatePlan.hosts: dict[str, Host]` keep working; `CreatePlan.planned` holds the provider plans (Decision 24).

**Writes** (one transaction, account row `FOR UPDATE`, no HTTP inside): the environment (`provider`, account, `cloud` with sizes, `db_version` from the manifest, plan, cost), the planned host rows (`hosts.planned_host`, with `owner_environment_id`), the slot instances on them, the data owner (no host; `create` is the only writer of a host-less owner, and only for `data_mode = managed`, §3.4) with P3's owner fields and FirstAdmin row; audit `environment.create` and `environment.cost_confirmed`. Nothing is sent to DigitalOcean except the catalog reads.

**`?check=true`**: P3's answer plus `cost` at the top level and the DigitalOcean objects under `plan.cloud`; each planned slot's `plan.slots[<slot>]` gives `{host_id: null, host: "slipway-<env>-<slot>", planned: "digitalocean"}` (P5's VMs come under `plan.machines`).

### 15.2 First deploy

`POST /environments/{id}/deploy` on a `new` DigitalOcean environment queues a deploy of `blue` with `options.chain`, `go_live` (P3 §9.2's mode `slot` path: there is no data server deploy). A managed environment never deploys its data owner: `api/v1/environments.deploy_environment`'s `server_first` applies only to `data_mode = server` (Decision 21).

1. `resolve`: the commit.
2. `prepare`: slipway.yml read at that commit and its hash stored, team frozen (`environment.team_frozen`), VPC, the cloud firewall (SSH rule only), bucket and key, blue's droplet built, pinned, Slipway's address recorded, ready.
3. `database`: the cluster with blue in its trusted sources, online, the role and database made on blue's droplet.
4. `edge`: `cloud.edge` frozen, certificate issued for every name, the load balancer with no targets, the firewall's load-balancer rule.
5. `source` … `manifest` (the hash checked) … `settings` (slot role, managed values, edge values; the probe from blue's droplet) … `build`; the seeding steps when seeded; `backup` (`No data yet` on a fresh database); `start` (migrates); `finish`; `first_admin`; `smoke` on blue's droplet; `traffic` skipped `Nothing is live yet; Activate follows`.
6. Hook → `activate` of blue: `check`, `smoke`, `dns` (every record created at the load balancer's IP), `switch` (`previous = []`; join blue; health; settle; public check; prove), `active_slot_id`, status `live`, `seed`.

A failure stops the chain; Retry continues (P3 §8.5). Objects made so far stay (§6.3).

### 15.3 Deploy to the idle slot

P3 §9.3 with §14.3's list. The first deploy to green builds its droplet (inside the plan: `droplets = 2`), adds it to the trusted sources and runs the role SQL again on green (idempotent). The backup runs on blue's droplet (the runner) and is stored on Slipway. The certificate gains green's new names and keeps every name blue serves (§11.2); the port, health path and database version can't change (§14.3), so nothing blue is served through moves (J15).

**Deploy to the active slot whose droplet is gone** (D28): allowed by `queue_job` while the slot's host isn't built. `prepare` builds a new droplet with a new host key; owner commands run on the other slot if it can run them (§10.4), else on this slot's new release; `traffic` runs the sync repair, which puts the new droplet on the load balancer. In Blue/Green the other slot keeps its own state and stays idle.

### 15.4 Activate, Switch back

P3 §9.5-9.6 with the `do_lb` backend and §14.3's list; production needs the name.

### 15.5 Add a slot (`POST /environments/{id}/slots {confirm_cost}`)

The body is the one `SlotAdd {host_id?, machine?, confirm_cost?}` (Decision 25): on DigitalOcean neither host field is given and `confirm_cost` is required (on SSH placement exactly one of the two host fields, P5 §9.5). The rules are a service helper, `environments.add_slot_plan`, that the API calls. P3 §9.8's refusals (no `host_id`: the droplet is made) plus `providers:spend` and the new total confirmed (audit `environment.cost_confirmed`). Writes the planned host row and `<env>-green`, `plan.droplets = 2`, the new cost. Then `Deploy to <green>` builds it. No data server to update.

### 15.6 Remove a slot

P3 §9.9's refusals, then §14.3's `remove_slot`. The cost drops (`cloud.plan.droplets = 1`, `cloud.cost` recomputed and audited) only once the droplet and the host row are gone, as the step's last write.

### 15.7 Grow sizes (`PATCH /environments/{id} {cloud: {droplet_size?, db_size?, db_standby?}, confirm_cost}`)

Refused while a job runs or the environment is retiring. Checked against the live catalog, read before the transaction (§12.2; §0 D15, `SD/do_envs.py:160-202`): `do_shrink_refused` texts — `<size> isn't larger than <current> in every way`, `A standby node can be added but not removed`, `<size> has no 2-node layout`. A confirmed PATCH writes `cloud.droplet_size`, `db_size`, `db_nodes`, `plan` and `cost` together (there is no unconfirmed stored size); the rules are the service helper `environments.grow_plan`. The new size is applied by the next deploy to each slot, in its `resize` step after `backup` (§9.4; droplet, never the active one of two), and by the next `database` step (cluster). Until then the Slots card shows, per slot whose host's `provider_state.size` differs from `cloud.droplet_size`, `Resize pending: applies at <green>'s next deploy`, the one phrase VMs use too (Decision 33). Audit `environment.resize` and `environment.cost_confirmed`.

### 15.8 Renew the certificate

Queued by the loop (§15.12) or `POST /environments/{id}/certificate` (`traffic:switch`). §14.3's list. A failed renewal leaves the old certificate serving; the page shows `Renews on its own; the last try failed <when>: <reason>`.

### 15.9 Retire, un-retire, Deactivate

§13. Retire and un-retire are service helpers (`environments.retire`, `environments.unretire`; audit `environment.retire`, `environment.unretire`); un-retire is `DELETE /environments/{id}/retire {confirm}` (Decision 38), and the action key in `EnvironmentOut.actions` is `unretire`.

### 15.10 Delete (`DELETE /environments/{id} {confirm, snapshot?, drop_data?, confirm_production?, confirm_no_snapshot?, forget_vms?}`)

P3 §9.10 with §13's rules and §14.3's list. One body serves both phases (`drop_data` is §13's and P5's; `forget_vms` is P5's); the rules are the service helper `environments.delete_problem`, which also says when the delete goes without a snapshot, so the API audits `environment.delete_without_snapshot`. The dialog lists every recorded DigitalOcean object with its monthly price, the Cloudflare records Slipway made, and what stays (the Slipway-stored backups in `kept/`, snapshots, claimed records).

### 15.11 The `cloud` step (`do_provision.destroy`)

1. The team check (D3).
2. **Find** (`do_provision.sweep`), every kind, before any check: each pending row is resolved by §6.4 step 1 (found → recorded; absent twice → dropped); then every unrecorded object §6.2 would adopt is recorded (`resource.adopt`, rule `teardown`):
   - droplets and clusters with both tags and a name starting `slipway-<env>-` (`:1387-1394`, `:1554-1557`); one with the env tag alone is logged and left;
   - the VPC by its name and marker;
   - the load balancer by name inside the recorded VPC;
   - the firewall by name and the env tag;
   - certificates whose name matches §6.1's pattern and whose names are all the environment's (§6.2's teardown rule);
   - the bucket by its fixed name: a HEAD with a fresh temporary setup key (its own pending row);
   - Spaces keys whose name matches §6.1's pattern, with grants only on our bucket, or full access.
   A 403 on any of these reads stops the step (J13): nothing is deleted on a partial view.
3. `check_all` (J5): every recorded object that still exists matches §6.2 (`SD/do_provision.py:1396-1450`); the certificate the load balancer serves is recorded when ours. Any mismatch fails `<what> no longer looks like Slipway's <name>. Slipway changed nothing`.
4. In order, each forgotten as it goes: load balancer; certificates (403/409/422 "in use" retried for 10 min, `:1457-1471`); firewall; droplets and their host rows (§9.3 steps 1-4 and 6); the database cluster; Spaces keys but the temporary one; the bucket, emptied first with the temporary key (30 min, `:1507-1528`); the temporary key (in a `finally`); the VPC, retried on 403/409/422 while it has members for 10 min, stopping at once on a 403 with no members (a scope problem), and naming up to 10 members on timeout, cut to safe characters (`:1473-1505`).
5. **Find again** (step 2's Spaces-key and pending-row parts, and every kind once more): a lost answer of this run's own temporary key, or anything that appeared meanwhile, is recorded and deleted. The step fails if anything is still found after that, naming it.
6. Leftover ACME challenge records with Slipway's comment for the environment's names are deleted from Cloudflare (§11.2).
7. `Nothing of <env> is left on DigitalOcean.`

A failure leaves the environment `deleting` (P3); the retry continues from what is left.

### 15.12 The renewal loop (`slipway/services/renewals.py`)

Started in the app's lifespan; first run 5 minutes after start, then every `SLIPWAY_CERT_RENEW_INTERVAL` (`SD/renewals.py:24`, `:125-136`). For each live DigitalOcean environment: skip when a job runs, status isn't `live`, or its latest `certificate` job failed within 24 hours (`:59-73`); read the served certificate's `not_after` from DigitalOcean (any failure: use `cloud.certificate.not_after`; never log the error's text, `:29-50`); 30 days or fewer → `jobs.queue_job(kind="certificate", user=None, system="renewals")`; audit `certificate.renew_queued`. A database hiccup is logged by type and the loop goes on.

**The system actor.** `queue_job` accepts `user=None` only together with `system="renewals"` and only for `kind = certificate`. It skips the permission checks, stores `triggered_by_id = NULL` and `options.by = "renewals"`, and audits with no actor (`by: renewals`). It applies these fences, as for a person: the environment `deleting` or `deleted`; a running job whose keys meet `(env, traffic)` (busy); an unresolved switch. It doesn't apply the owner's hold or dirty state: a certificate job changes no data. It leaves `environments.notice` as it is: `queue_job` clears the notice for every other job, but a renewal must never erase a stopped chain's notice and its Continue follow-up (`notice.next`, Decision 23). A refused queue is logged and audited once per day per environment, not raised. The deployment page shows `Started by Slipway (certificate renewal)`.

### 15.13 Recovery after a restart

P3 §9.13, plus:
- `prepare`, `database`, `edge`, `cloud`, `wipe` interrupted: failed, nothing more. What was answered is recorded and what was sent is pending (J3); the next run resolves each pending row by §6.4. A host left `creating` **stays `creating`**, with its `host_key`, until the next `prepare` resolves its pending row (adopt and pin, or two absent lookups and a new create); recovery never clears it (§3.3).
- A `resize` step interrupted between `power_off` and `power_on` by a restart (the shielded `finally` covers cancels and timeouts, §9.4): `recover_interrupted` writes the notice `<slot>'s droplet may be powered off: deploy to <slot> again` (in P3's dict shape `{text, at, deployment_id, next: None}`, and never over a notice that carries a `next`, Decision 23), and the next deploy's `prepare` finds the droplet `off` and powers it on first (§9.2 step 1). The environment page shows `<droplet> is powered off` from `GET /environments/{id}/cloud`'s live read meanwhile.
- `certificate` interrupted after the order: the kept certificate on its pending row is uploaded by the next run without a new order (§11.2 4a); interrupted after the upload and before the PUT: the next run finds the recorded certificate and uses it.
- `deactivate` interrupted with `options.switch.changed`: `traffic_state.unresolved` (P3's rule). `env_jobs.recover` handles `deactivate` and calls `switchyard.hold_in` only for a Switchyard switch (Decision 17).
- A backup interrupted mid-stream: every `*.part` under the Slipway backup store is removed at start-up (`backup_store.sweep`, before the runner starts); the row is `unverified` (P2's rule) and `settle_unverified` settles it from the Slipway files (§10.5).

---

## 16. API

Everything under `/api/v1`. `DigitalOceanError` → 502 with its text; `HostNotBuilt` → 409 with its text, on every path that can meet it.

The accounts router is `slipway/api/v1/provider_accounts.py` at `/api/v1/provider-accounts`, for every provider (Decision 3; P5 §11 has the Proxmox and ESXi rows).

| Method and path | Permission(s) | Body | Answers |
|---|---|---|---|
| GET /provider-accounts | providers:read | `?provider` | 200 `[ProviderAccountOut]` |
| POST /provider-accounts | providers:write | `ProviderAccountIn` | 201; 409/422 |
| GET /provider-accounts/{id} | providers:read | | 200 `ProviderAccountOut` |
| PATCH /provider-accounts/{id} | providers:write | `ProviderAccountUpdate` (partial; an omitted secret keeps the stored one) | 200; 409/422 |
| DELETE /provider-accounts/{id} | providers:write | `{confirm}` (the name typed) | 204; 409 |
| POST /provider-accounts/{id}/test | providers:write | | 200 `{status, checks, facts}`; 409 `test_stale`; 502 |
| POST /provider-accounts/test | providers:write | `{secret, region?}` (DigitalOcean only, unsaved; registered before `/{id}`) | 200 `{status, checks, facts}` |
| POST /provider-accounts/{id}/trust | providers:write | `{fingerprint}` | Proxmox and ESXi only; 409 for DigitalOcean |
| GET /provider-accounts/{id}/catalog | providers:read | `?region` | DigitalOcean only: 200 `{regions, sizes, db_sizes, db_versions, spaces}`; 502 |
| POST /environments | P3 + providers:spend | + `placement`, `production`, `confirm_cost`; `?check=true` | P3 + `cost` (top level), `plan.cloud`, planned `plan.slots` |
| PATCH /environments/{id} | environments:write + providers:spend (sizes) | + `cloud`, `confirm_cost`; `?check=true` with `cloud` alone (a grow) | 200 (`?check=true`: `ChangeCheckOut {ok, plan: {from, to}, cost}`, nothing written; any other field 422); 409/422 (a change of `traffic.switch` or `traffic.dns.address` on a DigitalOcean environment, or `do_lb` on an SSH one, is refused; `auto_activate: true` on production is 409 `A production environment waits for Activate: turn Activate automatically off`, field `auto_activate`) |
| POST /environments/{id}/slots | environments:write + providers:spend | `SlotAdd {host_id?, machine?, confirm_cost?}` (DigitalOcean: `confirm_cost` only); `?check=true` | 201 (`?check=true`: 200 `ChangeCheckOut {ok, plan: {slot, host_id, host, planned, machine?}, cost}` after every refusal but the typed total, nothing written) |
| POST /environments/{id}/activate | traffic:switch | `ActivateIn = SlotIn + confirm?` (the name, production) | 202; 422; 409 for a plan blocker, except `The certificate doesn't cover …` when the Activate lists its `certificate` step (`certificate_due`), which renews before the switch, as the job's own check. `GET /traffic/plan?slot=` moves the same blocker into `switch.notes` (`<…>: Activate's certificate step renews it before the switch`), so the Activate dialog enables as the API does |
| POST /environments/{id}/notice/continue | the follow-up's own (P3 D12) | `ConfirmIn?`: the name, for an Activate of a production environment while a slot is live (Decision 39); `actions.continue.needs_confirm` says so, and the notice's button then opens a dialog that asks for the name | 202; 422 |
| POST /environments/{id}/certificate | traffic:switch | | 202 |
| POST /environments/{id}/retire, DELETE …/retire | environments:delete | `{confirm}` | 200; 409/422 |
| POST /environments/{id}/deactivate | traffic:switch + environments:delete | `{confirm}` | 202; 409/422 |
| GET /environments/{id}/cloud | environments:read | | 200 `{account, team, region, plan, cost, objects: [{kind, name, provider_id, status: ok \| gone \| changed, detail, monthly_cents}], certificate, lb_ip, notes}` (live reads); a recorded droplet whose GET answered 404 marks its slot's host `gone` by `_other_gone`'s rule (`do_provision.mark_gone`: the environment's own `ready` host that still names that droplet), audit `host.gone`, its text in `notes`; nothing is marked while a job of the environment is queued or running; 502 |
| DELETE /environments/{id} | P3 + data:backup (with a snapshot); data:reset with `drop_data` | `EnvironmentDelete` + `drop_data`, `confirm_production`, `confirm_no_snapshot` (§13), `forget_vms` (P5) | P3 |
| POST /deployments/{id}/retry | P3, with `data.RETRY_PERMISSION` and `RETRY_EXTRA` on member and environment jobs alike (§4.1) | + `confirm_production` and, when the delete used it, `confirm_no_snapshot` (production teardown), `rebuild_data` with `confirm` (a gone cluster or bucket, §10.1), `drop_data`, `forget_vms` (P5), each asked again on every retry (`ENV_ONE_SHOT`); `confirm` for a `deactivate` retry (`CONFIRMED_KINDS`) and for an `activate` retry of a production environment (Decision 39; not for a chained first activate while nothing is live), `needs_confirm` in its actions; a teardown retry whose data's only home goes without a snapshot first (`delete_problem`'s rule, Decision 26) is 409 with its text unless `drop_data` (data:reset) | P3 |

**Schemas** (`slipway/schemas.py`; Decision 33):

```text
ProviderAccountIn = DigitalOceanAccountIn | ProxmoxAccountIn | EsxiAccountIn   # discriminated on provider
DigitalOceanAccountIn {provider: "digitalocean", name, secret?, production?, region, ssh_sources: [cidr],
  monthly_limit_cents?, prices?}
ProviderAccountUpdate {every field optional; DigitalOcean: clear_secret?}
ProviderAccountOut {id, provider, name, production, has_secret, secret_hint, status, checks, facts,
  last_checked_at, removed, used_by: [{environment, slot?, name?}],
  + DigitalOcean: region, team_name, ssh_sources, ssh_open: bool, monthly_limit_cents, estimate_cents}
EnvironmentCreate += {placement?: {provider: "digitalocean", account_id, region, droplet_size, db_size,
  db_standby?, acme_staging?}, production?, confirm_cost?}   # data_mode += managed; traffic.switch += do_lb
Cost {lines: [{what, detail, monthly_cents, source: "api" | "table"}], total, total_cents, as_of, delta?}
EnvironmentOut += {provider, production, retiring_at, cloud: {account: {id, name}, region, sizes,
  lb_ip, certificate: {name, not_after, days_left}, cost, billing_open: bool} | null,
  actions += {retire, unretire, deactivate, renew_certificate, grow}}
SlotAdd {host_id?, machine?, confirm_cost?}
ActivateIn = SlotIn + {confirm?}
RetireIn {confirm}
HostOut += {owned_by: {id, name, slot} | null, built: bool, provider_state,
  machine: {stage, account} | null}                         # machine: P5's VMs
EnvironmentDelete += {drop_data?, confirm_production?, confirm_no_snapshot?, forget_vms?}
RetryIn += {confirm_production?, confirm_no_snapshot?, rebuild_data?, drop_data?, forget_vms?}
BackupOut += {location}
```

A slot whose droplet is behind its confirmed size shows `Resize pending: applies at <slot>'s next deploy` in `EnvironmentOut` (Decision 33).

---

## 17. Pages

### 17.1 Settings › Integrations: DigitalOcean accounts

One Integrations page holds three account cards, DigitalOcean, Proxmox and VMware ESXi (P5 §12.1), from one account-list partial, and one `_account_dialogs.html` with a field set per provider (Decision 33). The Integrations tab and page show with `providers:read` or `settings:write`; the Switchyard and Cloudflare cards still need `settings:write`; the account cards need `providers:read` and their buttons `providers:write`. The DigitalOcean card lists accounts (Name · Production chip · Region · Team · Estimate of its environments · Environments). **Add account** (`providers:write`) opens a dialog: Name, `[ ] For production environments`, Default region (a select once the token tests), API token (write-only, `Set (…abcd)`), SSH sources (one CIDR per line; hint `The addresses Slipway connects from. 0.0.0.0/0 lets the whole internet try SSH.`), Monthly limit (optional), **Test** (the checks as a list), **Save**. **Remove…** with the typed name. The hint under the token: `A token with read and write on droplets, databases, load balancers, firewalls, VPCs, certificates and Spaces keys. Droplets never receive it.`

### 17.2 Environment flow (`/environments/new`, P3 §12.3)

Step 2 **Servers** gains `Where: ( ) Hosts (servers you added, or new VMs on Proxmox or ESXi) / ( ) DigitalOcean` (disabled with the reason, in this order: no `providers:spend`; no `providers:read`, so no account is listed: `Choosing a DigitalOcean account needs the providers:read permission`; no account: `Add a DigitalOcean account in Settings › Integrations first`; no Cloudflare) and, for production accounts, `[ ] Production` (forces Blue/Green; hint `Production runs Blue and Green, waits for Activate, and is deleted only after it is retired and snapshotted.`). Step 3 **Hosts** becomes **DigitalOcean** for that placement: Account, Region (catalog), Droplet size (catalog, with prices), Database size, `[ ] Standby node`, `[ ] Let's Encrypt staging` (not production). Step 5 **Traffic** shows `Through: DigitalOcean load balancer` and the DNS checkbox fixed on. Step 7 **Review** shows the cost table (every line, the total, the foot of §12.1) and a field `Type <total> to confirm about $<total> a month`; **Deploy** stays disabled until it matches. A step's check that refuses on `confirm_cost` (the account's monthly limit; a check never sends the typed total) shows its text on the step the user is on, which then stays; and any refused check forgets the estimate, so Review never shows, or accepts, an older total (review F23).

### 17.3 Environment page (P3 §12.2)

- Header chips: `DigitalOcean · <region>`, `Production`, `Retiring`.
- Callouts, added after P3's: **Billing** (§12.4); `SSH to <env>'s droplets is open to the internet` (with the account link) when `ssh_sources` holds `0.0.0.0/0`; a gone active droplet (§6.3, with **Deploy to <blue>**); a droplet left powered off (§15.13); a pending create older than 10 minutes (`A <kind> create from <when> hasn't shown up in DigitalOcean yet; the next deploy looks again`); a host that holds a droplet's address (§9.2 step 5, naming the host to fix); a certificate with 14 days or fewer and a failed last renewal.
- **DigitalOcean** card (`data-load="/api/v1/environments/{id}/cloud"`): Account and team · Region · Load balancer IP · Certificate (`Valid until <date>`, **Renew now**) · Estimate (`About $<x> a month`) · Sizes (**Grow…**) · Objects (Kind · Name · Status OK/Gone/Changed · Monthly). A 502 shows the client's text.
- **Slots** card: the host column shows the droplet (`slipway-prod-green · s-2vcpu-4gb · 203.0.113.12`) with the provider chip `DigitalOcean droplet` and a build chip, one of `Not built yet`, `Building`, `Ready` and `Gone` (shown as `Gone: deploy to rebuild`), one per phase (VMs add `Lost`, `Hidden` and `Off`, P5 §12.3), and `Resize pending: applies at <slot>'s next deploy` when its size is behind the confirmed one (§15.7; Decision 33).
- **Backups** card subtitle: `Database dumps stored encrypted on this Slipway server. Slipway takes one before every deploy and every change that replaces data. DigitalOcean also keeps its own daily backups of the cluster; Slipway doesn't use them.`
- **Danger zone**: **Retire…** / **Un-retire…** and **Take off the air…** for production; **Delete environment…** with §13's states (disabled with the reason until retiring and dark).

### 17.4 Dialogs (`_environment_dialogs.html`)

- **Activate** and **Switch back** (production): add the typed name (`ActivateIn.confirm`). The button starts with `data-plan-blocked="1"` and stays off, whatever is typed, until the traffic plan has loaded with no blocker; a failed read keeps it off (review F46).
- **Grow** and **Add a slot** price through the API's dry run (`?check=true`, `ChangeCheckOut`: every refusal of the change runs, nothing is written, `cost.total` is the figure to type and `cost.delta` the change).
- **Grow**: the size selects, the cost delta, the confirm field; `The droplet stops for a few minutes when a deploy resizes it; its disk grows and can't shrink again. The database stays up while it resizes.`
- **Add a slot**: the cost delta and the confirm field.
- **Retire**: `<env> keeps serving. While it retires, no slot can be activated; when the new production is live, take <env> off the air and delete it.` Typed name.
- **Take off the air**: `The load balancer stops sending traffic to <blue>. <names> answer 503 until the DNS records are moved or removed.` Typed name.
- **Delete** (DigitalOcean): §15.10's lists; `Take a snapshot first` in §13's states (ticked, unticked with `never held data`, or disabled with `no slot can run the data commands`; forced for production that holds data and can run them); unticked while the owner holds data, the one `[ ] Delete <env>'s data with it` box (`drop_data`, needs `data:reset`; the same box P5's Delete dialog uses for a data VM); for production a field `Type delete production <env>`; for production that must take a snapshot, a user who can't take one (no `data:backup`, or no dump command) gets `A production environment is deleted only after a snapshot, and taking one needs the data:backup permission`, no `drop_data` box and **Delete** kept off (review F49); and, only when no slot can run the data commands, a second field `Type delete production <env> without a snapshot` beside the **Deploy to <blue> first** button.

### 17.5 Other pages

Hosts list: droplet hosts carry the provider chip `DigitalOcean droplet` (P5: `Proxmox VM`, `ESXi VM`) linking the environment and slot, and the build chip; Check, Edit address, Reset key and Delete are hidden with `hosts.owned_host_refusal`'s reason, and the label and description stay editable. Host detail: the provider state and a link to the environment. Deployment detail: the provisioning steps' logs; a `cloud` step lists what it removed. `slipway.js`: `renderers.cloud_objects`, the cost table renderer, `data-must-equal` on the cost field (it already compares text exactly; the renderer sets the value with two decimals), and `STATUS`/`STEP_BADGE` learn all five new kinds: `certificate`, `deactivate` and phase 5's `vm_snapshot`, `vm_revert`, `vm_drop`.

---

## 18. Concurrency, limits, timeouts

- Client: 30 s per call, one 429 retry (≤ 30 s), one GET retry on 502-504, 200 per page, 10 pages. Polls every 10 s. ACME: 3 s polls, 100 tries (`SD/acme.py:32-33`); DNS settle 15 s (`SD/certs.py:25`).
- **Every wait has its own limit** (`SD/do_provision.py:83-85` where Sirdar had one): pending lookups 3 min per kind; droplet active 10 min; SSH pin 10 min (2 min for a droplet already ready); cloud-init 15 min; power on of a droplet found off 5; in `resize`, power off 5, resize 30, power on 5, SSH after a resize 10; database online 30 min; trusted sources 10 min after online; database resize 1 + 30 min; role SQL 5 min; load balancer active 10 min (3 min inside `switch`); fresh SSH after a firewall SSH-rule change 2 min per droplet; health 5 min; certificate in use 10 min; bucket emptying 30 min; VPC delete 10 min.
- **Step timeouts are the sums plus a margin** (§14.2). `prepare`: fixed work (manifest, team, VPC, firewall, bucket and keys, the read-only resize check) ≈ 4 min + lookups 3; then either a new droplet (10 + 10 + 15 = 35) or an existing one found off (5 + 2 = 7): at most 42, timeout 50. `resize` (§9.4, the grow moved out of `prepare`, Decision 14): the size check ≈ 1 + power off 5 + resize 30 + power on 5 + SSH 10 = 51, timeout 60. Both figures are derived, not measured; the real-account run (§20.3) checks them. `database`: a new cluster (lookups 3 + 30 + 10 + 5 = 48) or a grow (10 + 31 + 10 + 5 = 56): at most 56, timeout 65. `edge`: lookups 3 + certificate ≈ 6 (ACME 5, settle, upload) + load balancer 20 (active before and after a PUT) + firewall PUT and fresh SSH 4.5: ≈ 34, timeout 40. `certificate`: ACME 6 + load balancer 20 + old certificates in use 10 + lookups 3: 39, timeout 45. `wipe`: SQL 5 + bucket 30 + slot volumes 4: 39, timeout 45. `cloud`: finds 2 × 5 + certificates 10 + bucket 30 + VPC 10 + the rest ≈ 4: 64, timeout 75. P3's `switch` (20 min) holds the `do_lb` switch: active waits 3 × 3 + health 5 + 2 settle waits (40 s each with the default health check) + public checks ≈ 3: ≈ 18.5.
- A step timeout cancels the step; the shielded parts (a create's send and record, §6.4; `power_on` after a `power_off`, §9.4; P3's put-back) still finish.
- DigitalOcean's published limits (5,000 requests an hour, 250 a minute per token, from memory, sirdar-digitalocean §16) are far above one provisioning run (≈ 150 calls with the 10 s polls); the 429 retry covers bursts.
- At most 2 app slots, 1 cluster, 1 load balancer per environment; 50 names (P3); the certificate covers at most 100 names (Let's Encrypt's limit), so 50 is the binding one.
- The renewal loop queues at most one `certificate` job per environment per round.

---

## 19. Room for phases 5 and 6

- **Phase 5 (Proxmox, ESXi).** What the two phases share is a host-level contract, not a table of machines (Decision 1). `provider_accounts` holds their accounts too (`provider = proxmox | esxi`; `secret` takes the Proxmox token or the ESXi password, `config` their fields and networks, `tls` the pinned certificate; P5 §3.1). Planned host rows (`hosts.planned_host`), `hosts.provider_state.phase`, `Host.is_built`, `ssh.HostNotBuilt`, the not-built rule, `hosts.owned_host_refusal`, `hosts.owned_by` and `hosts.address_holder` (§3.3) apply to their VM hosts as they are, and the deployer dispatches the one `prepare` and the one `resize` step key by provider (`do_provision.prepare` and `resize_droplet` here, `machines.prepare` and `machines.resize_step` there). Their VMs keep their own `machines` table and their `vm` rows in `resources`, written through `machines.reserve_vmid` and `record_vm` (P5 §6.9); intent rows (§6.4) stay DigitalOcean's (Decision 27). The pinning mechanisms differ and both stay: a droplet's key is written before the create is sent, a VM's only by `machines.pin` after a connection presents the key read out of band. The shared rule is that a provider host's key is written only by its provider's `prepare`, with no trust on first use (Decision 8). Cost safety doesn't apply on the LAN.
- **Phase 6 (retire Sirdar).** Sirdar deletes its own DigitalOcean environments with its step 18 before it is shut down; Slipway adopts nothing of Sirdar's: its tags are `sirdar*`, never `slipway*` (§6.1), so no adoption rule matches.

---

## 20. Tests

### 20.1 Fakes

- **`tests/fake_digitalocean.py`** (new; Sirdar's `ST/fake_digitalocean.py` ported): in-memory account and teams, regions, sizes **with `price_monthly`**, database options with layouts and versions, VPCs (unique names, members, lingering deletes), droplets (polls to active, IPs `203.0.113.<n>` distinct per droplet, actions with `action_polls`, `action_errors`, `action_stall`, resize only when off), databases (polls to online, firewall rules that refuse unknown droplets, `firewall_wait`, CA, `db_resize_polls`), Spaces keys (secret shown once), certificates (`dns_names` parsed from the uploaded leaf, `cert_in_use_polls`), load balancers (full-body PUT, `lb_apply_polls`, refuses `droplet_ids` with `tag`, refuses an unknown `certificate_id`), firewalls (full-body PUT), `fail[(method, path)]`, `lose_answer[(method, path)]` (the write lands, the answer is a timeout), `lost_visible_after` (seconds of the fake's clock before a lost object shows in lists and tag queries, default 0; tests use 30 and 90), `forbid[kind]` (every request for that kind answers 403, as a custom-scoped token does), `rate_limit_once`, `down`, `requests` and `writes()`, `?tag_name=` filtering, and Spaces keys with their grants. It parses each droplet's `user_data` and keeps its `ssh_keys.ed25519_public`. Its clock is the test's (`freezegun`-style `advance(seconds)`), so the 60 s lookups run instantly.
- **`tests/fake_spaces.py`** (Sirdar's ported): buckets, objects, multipart uploads, CORS, SigV4 header check, `BucketAlreadyOwnedByYou` and a foreign-owned name.
- **`tests/fake_acme.py`** (new): an RFC 8555 directory over `MockTransport` that checks the DNS-01 TXT value through `FakeCloudflare`'s records and issues a self-signed chain for the asked names with a chosen `not_after`. It counts orders per name set (`orders[names]`) and can refuse a sixth within its fake week, as Let's Encrypt does.
- **`FakeCloudflare`** (P3) gains TXT records.
- **`MultiRemote`** (P3 `tests/fake_hosts.py`, extended by slice S06 for both phases; phase 5's `tests/fake_vm_hosts.py` adds only its sudo, apt, usermod and dpkg shims, Decision 30) keyed by address as well as by name, so the droplets' IPs reach it; a `pinned_key` seam returns the fake droplet's delivered public key, or another key for the mismatch test; `docker run … psql`, `cloud-init` and `printf "$SSH_CONNECTION"` shims log their stdin and argv (the last answers `198.51.100.7 51234 <ip> 22`); `firewalled(ip)` makes connections to a droplet time out, as a cloud firewall drop does; and a psql shim mode that fails after the `DROP DATABASE` line.
- `traffic.transport_factory` (P3) for the public check through the load balancer's IP.
- **The guard** (`tests/hypervisor_guard.py`, autouse in `tests/conftest.py`, with the alias fixture `no_real_clouds`; Decision 29): beside phase 5's seams it replaces the `transport_factory` of `digitalocean`, `spaces`, `acme`, `cloudflare`, `switchyard` and `traffic` (the public check) with an `httpx.MockTransport` whose handler raises `RealHypervisorCall` naming the system, so building a client stays harmless and only a request fails; each fake's `use_fake` replaces it again. `github.py`'s `transport_factory`, used when a caller passes no `transport`, is guarded the same way, and SSH dials reach only loopback (P5 §16.1). `tests/conftest.py` also sets `SLIPWAY_CERT_RENEW_INTERVAL=0`.
- **`tests/do_fixtures.py`** (S09a): builders for a DigitalOcean account row, an environment with placement `digitalocean`, its planned host rows, slot instances and the host-less managed owner, inserted directly.
- **Phase 3 goldens** (`tests/golden/test_phase3_golden.py`, S06, Decision 31): recorded on the untouched phase 3 engine from a frozen copy of the phase 3 example, `tests/golden/serversherpa_p3.slipway.yml`, so this phase's edit of `docs/examples/serversherpa.slipway.yml` never changes their input; they record the step lists, `.env` bytes and the Switchyard and Cloudflare calls of an activate and of every sync path.

### 20.2 Numbered tests (slice in brackets)

The brackets name this spec's original slices (F1-K1). The plan's slices (§21) carry the same numbers: each slice's section lists the tests it runs (S01 moves F1-F4's, S03 has 20-24, S20 has 64-68, and so on).

1. [F1] Client: every method's path and body; 404 → None/False; 401, 403, other 4xx texts; a 403 on every `get_*` and list raises `Forbidden`, never None or an empty list (J13); DigitalOcean's `message` never in an error; an `id` named only when it matches the pattern.
2. [F1] 429 with `Retry-After`, with `RateLimit-Reset`, with neither (5 s), capped at 30 s, retried once, a second 429 fails; a GET retried once on 503; a POST never retried.
3. [F1] Paging: `links.pages.next` followed; an 11th page fails with Slipway's text.
4. [F1] A malformed id never reaches the URL; the token is only in the Authorization header (the fake records headers).
5. [F1] `droplet_ips` with none, one and both addresses.
6. [F1] The fake: a droplet becomes active after `boot_polls`; `lose_answer` lands the object.
7. [F2] SigV4 signatures against known vectors; virtual-hosted addressing; DOCTYPE in XML refused.
8. [F2] `create_bucket`: 200, `BucketAlreadyOwnedByYou`, a 409 then HEAD 200 (ours), a 409 then HEAD 403 (another account's).
9. [F2] `empty_bucket` pages and aborts multipart uploads; CORS read, compare, write only when different.
10. [F3] ACME: account key made once per directory and reused; `kid` remembered; an order for 6 names with DNS-01; challenge TXT records created with the comment and deleted even when the order fails; the private key never in any log line.
11. [F3] `is_ours` (the exact name pattern, so `prod`'s rule never matches `prod-eu`'s certificate, and exact names), `not_after`, best-certificate choice (latest expiry, tie → the served one), due at 30 days.
12. [F3] Staging directory selection; production refuses staging (pure rule).
13. [F4] `droplet_userdata`: the keys, the user (`cloudinit.GUEST_USER`), no sudo, the `usermod -aG docker` line after the packages, packages, runcmd, the hostname pattern, under 64 KiB; `droplet_body` has `monitoring: false` and `with_droplet_agent: false`.
14. [F4] `scram_sha256` against PostgreSQL's known verifier for a fixed salt; `setup_sql` and `reset_sql` refuse bad identifiers and verifiers.
15. [F4] `lb_body`, `lb_update_body` (read-only fields, region slug, size vs size_unit, tag vs droplet_ids), `https_certificate`.
16. [F4] Firewall body with `ssh_sources`; `_firewall_matches` with DigitalOcean's `"0"` ports and reordered rules.
17. [F4] Size rules: `size_parts`, `grows`, droplet grow against the catalog (another family, not offered in the region, retired size falling back to the slug), database grow and standby rules.
18. [F4] `cost`: lines from `price_monthly` and the table, the account's override over the code's (`price_layers` called with `install=None`), totals in cents, `as_of` shown; a missing price in the table fails `Slipway has no price for <x>; set one on the account`.
19. [F4] Names, tags and the exact-match patterns of §6.1 (`prod` against `prod-eu` and `prod-setup`); the bucket name stays under 63 characters for a 26-character environment name.
20. [G1] Migrations 0010 and 0011 upgrade and downgrade on SQLite and PostgreSQL; 0011's downgrade refuses with a live DigitalOcean environment, a DigitalOcean resource, a Slipway-stored backup or a host-less instance, and deletes the `acme` row; 0010's refuses while an account or a provider host exists; `tests/test_migration_0009.py` upgrades to `'0009'`, and `alembic check` runs at head in `tests/test_migration_0012.py`.
21. [G1] Constraints: the provider/account check, the provider and production checks on `provider_accounts`, the unique account name, `ck_environments_do_managed`, production checks, `ux_environments_one_production` (a second non-retiring production for one repository and manifest raises; a retiring one doesn't block), `ck_instances_host`, `ck_backups_slipway_key`.
22. [G1] Roles hold exactly §4.1's permissions after bootstrap.
23. [G1] `HostNotBuilt` from `SSHTarget.from_host` for planned and creating hosts, and not with `building=True`; `HostNotBuilt` is not an `SSHError`; the poller skips them; `rotate-encryption-key` re-encrypts `provider_accounts.secret` and `backups.data_key`, walking each table by its own primary key; `--clear-unreadable` sets an unreadable `secret` to NULL (it is not a re-enter column) and marks the account `status = error` with the check `The token couldn't be read after a key change: enter it again`, and clears `data_key` (that backup becomes delete-only).
24. [G1] `Host.is_built` for `ssh` and each droplet phase.
25. [G2] The ServerSherpa manifest plans the `slot` role with managed values and the edge: §5.4's keys, `SS_DATABASE_URL` and `SS_SPACES_SECRET_KEY` hidden, no `spaces` route or port, the proxy project added, only `holds: other` volumes, `STACK_PROXY_IP` from the edge, no `SS_CERT_*` key; P3's `slot` role output unchanged without `edge_values` (byte compare).
26. [G2] The bad-manifest table for every rule of §5.2 with its exact text, including rule 11: a `data.managed.env` key that is a setting, a var, a secret, a port var or an `attach.env` key; and the accepted case of an `env_file` key such as `SS_SPACES_BUCKET`.
27. [G2] A setting named in `edge.env` isn't required in a `do_lb` environment and still is elsewhere.
28. [G2] `capabilities()` gives `edge`, `managed` and `digitalocean`; `to_json` round-trips.
29. [G2] The Django example of P3 §5.5 with a `data.managed` block plans in the managed role.
30. [G3] Cloudflare `create_txt` and its deletion against FakeCloudflare; the token never in an error.
31. [G3] `traffic.register`, the backend `lock` (`switch`, `sync` and the shielded put-back take and release it, after a cancel during verify too; Switchyard's is `switchyard.lock`), `put_back_locked` and `repair` on the protocol (`sync` calls `repair`), mode `deactivate` through `context()` and `switch()` (blockers refuse, `verify` is the backend's, failure texts naming it), `plan_for` asking for Switchyard's settings only for Switchyard, `public_check` with an explicit address, `insecure` and `via`, and `who_is_live` on the Switchyard backend with one, two and no slots; P3's `tests/test_traffic.py` and the phase 3 golden files pass unchanged.
32. [G4] `deploy/stack/test-managed-role.sh` passes, and fails on the unchanged `ss-stack` (has-data exits 4). This runs in BaseCampV3, outside this repository (Decision 35).
33. [H1] Accounts, through `/api/v1/provider-accounts`: save, the token write-only with its hint, the same token on two accounts refused, a token of another team refused while environments use the account (the team read happens before the lock; a create racing in answers "Save again"), clear refused while in use, `ssh_sources` required, production flag rules, remove refused while referenced.
34. [H1] Test: each check's pass, warn and fail; an over-limit droplet count warns; the unsaved-token test writes nothing.
35. [H1] Catalog: sizes with prices in the region only, database sizes per node count, versions, Spaces regions; cached for 10 minutes.
36. [H2] `prepare` on an empty account: team frozen and audited, VPC, setup key made and deleted, bucket, bucket key with its secret saved, CORS, the cloud firewall (SSH rule only) **before** `POST /droplets`, blue's droplet with the generated host key in user-data and in `host_key` **before** the POST, waited, address set, pin confirmed, Slipway's address from `$SSH_CONNECTION` in `cloud.slipway_addresses`, cloud-init readiness, `monitoring: false` and `with_droplet_agent: false` in the body; no private host key in any row or log; `prepare` never powers a droplet off (the grow is test 76's `resize_droplet`); a pending row committed before each create and replaced in one commit by its answer, with the Spaces secret and the doadmin password in that same commit; every row survives a rollback of the job's session.
37. [H2] `prepare` again: nothing written (the fake's `writes()` is empty) and every object read.
38. [H2] Lost answers, for every create kind (droplet, cluster, VPC, firewall, load balancer, certificate, bucket, bucket key, setup key) with `lose_answer` and an **immediate** retry, with `lost_visible_after` 30 and 90: the retry sends no second create, waits, finds the object by nonce or name and records it (`resource.adopt`); a Spaces key found is deleted and made again; with the object truly absent, two lookups 60 s apart drop the pending row and the create is sent once more.
39. [H2] Stops: a droplet with the env tag but not `slipway`, a same-named VPC without the marker, a load balancer of that name in another VPC, a firewall without the tag, a recorded droplet renamed; each fails with `Slipway changed nothing` and the fake got no write after the read.
40. [H2] Gone objects: a recorded droplet gone (404) → host back to `planned`, pin cleared, a new droplet with a **new** host key; a gone cluster with data on the owner refuses; a gone load balancer is remade and the slots become stale. With `forbid[kind]` instead of a 404, each step stops with the 403 text and nothing is forgotten or made (J13).
41. [H2] The pin: the droplet answering with another key fails at once, no command sent; SSH not up yet retries until it answers.
42. [H2] `database`: rules in the create body equal the recorded droplets; a drifted rule set is put back; 422 retried until accepted; another error fails with the "may be reachable" text; online wait; grow only upward and only once online; the role SQL on the slot's droplet with the doadmin password, the CA and the SQL on stdin and none of them in argv or the log; the verifier, not the secret, in the SQL.
43. [H2] `edge`: `cloud.edge` frozen on the first run; certificate issued for every active-following name and none for `spaces`; the load balancer made with `droplet_ids: []` and the HTTPS rule on the certificate; an existing load balancer whose certificate differs gets one full-body PUT after an `active` wait; old certificates deleted, an in-use one left; the firewall gains the load-balancer rule with one PUT; drift put back with a PUT; after an SSH-rule change a fresh SSH connection to each built droplet, and with `firewalled(ip)` the previous rules are PUT back and the step fails with the lock-out text.
44. [H2] Run-time plan check: a second droplet, a larger cluster or a second load balancer outside `cloud.plan` fails before the create; a pending row and an unrecorded tagged droplet each count; a remake of a gone object passes.
45. [H2] `destroy`: the find before `check_all`, and `check_all` before any delete (one renamed object → no delete at all), strays with both tags deleted, the env tag alone left, the order of §15.11, certificates in use retried, the bucket emptied then deleted, the VPC retried while members linger, a 403 with no members stops, every row forgotten, host rows deleted. Then, for **each kind**, a `lose_answer` on its create with no retry before Delete: the find records it and it is deleted, and "Nothing of <env> is left" is true of the fake; a lost answer of the teardown's own setup key is caught by the second find; a full-access setup key left by a stopped run is deleted; `forbid[kind]` stops the step before any delete.
46. [H2] Remove a droplet: the marks, the droplet, its row, the trusted sources without it, the instance row, the host row, in that order; `fail[("DELETE", "/droplets/…")]` once keeps the instance, the host and the row, and the retry ends with no droplet and with `plan.droplets` dropped only at the end.
47. [H3] `do_lb.plan` only GETs; its blockers (no load balancer, renamed, not active, the droplet missing or untagged, a certificate not covering the routes).
48. [H3] `do_lb` switch from blue to green: PUT `[blue, green]`, health over green's member session with the off-names Host header, the settle sleep from the live body, the public check through the load balancer's IP with SNI, PUT `[green]`, settle, prove; `options.switch.changed` saved after each PUT; verify runs once more.
49. [H3] Put-back at every failure point: health fails, the public check fails, the second PUT fails, prove finds another target, a cancel during verify (shielded put-back, P3); a failing put-back returns `unresolved` with the by-hand text.
50. [H3] First activation (`previous = []`) and Deactivate (`[] after`), each put back on failure; Deactivate's verify checks the targets are empty and does **not** run the public check (the fake load balancer answers 503); `who_is_live` with one, two and no targets.
51. [H4] `backup_store.pull`: encrypted container written to `.part`, fsynced and renamed, plaintext hash checked against the host's, a mismatch removes the `.part` and fails, a stream cut mid-way leaves no `.sbc`, the droplet copy removed only after the rename; `sweep` removes every `.part`; `push` writes, checks and removes in a `finally`; the quota and free-space refusals.
52. [H4] `?check=true` of a Slipway backup: ok, missing, changed; Delete removes the files; an unreadable `data_key` makes the backup delete-only.
53. [I1] First chain on DigitalOcean (fakes everywhere, MultiRemote keyed by the fake's IPs): `resolve`, then `prepare` (slipway.yml read at the resolved commit, hash stored), `database`, `edge`, then `source`; `manifest` checks the hash; blue's `.env` per §5.4; the probe with `sslmode=require`; `backup` `No data yet` through blue (the runner); `first_admin`; `smoke`; `traffic` skipped; the chained activate: `dns` records at the load balancer's IP, the `do_lb` switch, `active_slot_id`, status `live`, `seed`.
54. [I1] Deploy to green: green's droplet built and added to the trusted sources; the role SQL run again on green; the pre-deploy backup dumped on **blue's** droplet with blue's live release, streamed to Slipway, removed from blue; green's `accepts`; the lag check on blue; `traffic` skipped.
55. [I1] Restore on managed data: refusals before any stop; `stop_slots` on both droplets; the backup pushed to the runner, `ss-stack restore` there, the copy removed; `start_slots` with blue's live `start` before `finish`; green per P3; no `release`/`build`/`stop`/`start` rows on the owner.
56. [I1] Reset on managed data: `wipe` runs `DROP DATABASE … WITH (FORCE)` and `CREATE DATABASE` as doadmin on the runner, empties the bucket with a temporary key deleted afterwards, removes `holds: other` volumes on each slot; `first_admin` and `seed` after `start_slots`.
57. [I1] A seeded DigitalOcean environment: blue's first deploy runs the seeding steps on blue as the owner's commands; `import-objects` targets the bucket; the snapshot's identity becomes the environment's secrets.
58. [I1] The migration lock in managed mode: a `d` line left in green's lock makes the owner's Back up now (running on blue) wait.
59. [I1] `has_data` exit 4 on the runner fails with §10.6's text.
60. [I1] Renewal loop: due at 30 days queues one `certificate` job; a failed one within 24 hours, a running job or a non-live environment queue nothing; a DigitalOcean read failure falls back to the stored date; the `certificate` job uploads, PUTs the HTTPS rule, re-reads, keeps ours, deletes the old.
61. [I1] Recovery: an interrupted `prepare` after the droplet create but before the record → the host stays `creating` with its key, and the next `prepare` adopts the droplet and pins it with the key written before the POST; with that key cleared by hand, the adopted droplet is deleted and made again, never trusted; an interrupted `deactivate` sets `unresolved`; a half-streamed backup's `.part` is removed at start-up by the real pull path's sweep, no `.sbc` is left, and the row settles from the Slipway files.
62. [I1] Production fences: activate without the name (422), any activate of a retiring production (409), deactivate of a non-retiring one (409), delete without retiring, while live, without the phrase or without a snapshot; a teardown retry asks the phrase again. A production whose first deploy failed in `database` (never held data) is deleted without a snapshot, with the note; one that holds data with every droplet gone needs the second phrase, audits `environment.delete_without_snapshot`, and its retry asks both phrases. A non-production managed environment that holds data is deleted without a snapshot only with `drop_data: true` and `data:reset` (403 without the permission, 409 without the flag).
63. [I1] Run-time not-built fence: a job on a planned host is refused unless it is a deploy whose step list contains `prepare` (`resolve` runs first, then `prepare`), or a `remove_slot` or `teardown` on an owned host; control actions on a planned slot answer 409 with `HostNotBuilt`'s text.
64. [J1] Create on DigitalOcean: every refusal of §15.1 with its text and `field` (including `do_lb` on placement `ssh` and another switch on placement `digitalocean`), nothing written; `?check=true` returns the cost at the top level, `plan.cloud` and the planned slots, and writes nothing; `confirm_cost` mismatch (422) and a moved estimate (409); the account limit; the rows written (planned hosts, slot instances, the host-less owner); audit without secrets.
65. [J1] PATCH sizes: grow rules, cost delta and confirm; Add slot and Remove slot change the plan and the cost.
66. [J1] Owned hosts (`hosts.owned_host_refusal`): PATCH of the address or credentials, DELETE, reset-host-key, the deploy-root move, `POST /instances`, a placement change and the unmanaged claim answer 409; the label and description stay editable; check answers 409 while not built and is allowed once built.
67. [J1] `GET /environments/{id}/cloud` lists each object with ok, gone and changed; 502 with the client's text when DigitalOcean is down.
68. [J1] Permissions matrix for every §16 endpoint, including `providers:spend` on create, add slot and grow, and admin-only account writes.
69. [K1] Pages: the accounts card and dialog (token write-only), the flow's DigitalOcean fields and the Review cost table with the confirm field, the environment page's DigitalOcean card, Billing and open-SSH callouts, the production danger zone states, owned hosts read-only; JS: the cost renderer and the confirm field enabling Deploy.
70. [I1] J1: a P3 Blue/Green environment on SSH hosts and a standalone instance keep P3's step keys, `.env` bytes and Switchyard calls: the phase 3 golden files (recorded from the frozen `tests/golden/serversherpa_p3.slipway.yml`, §20.1), and the same scenarios run again with the phase 4 `docs/examples/serversherpa.slipway.yml` (recorded in `tests/golden/phase4_serversherpa_lan.json`): no `SS_SPACES_BUCKET` line appears in a LAN slot's `.env`.
71. [G1] `resources`: `record` writes `credentials` and `tags` in the row's own commit; `replaces` turns a pending row into the real one in one transaction; `record_pending` refuses a name that has a row; `set_credentials` sets and clears; `audit_action` writes `resource.adopt` / `.rebuild`; `owned` leaves pending rows out unless asked; P3's resource tests pass.
72. [H2] Duplicates: two droplets (or two clusters) of one name with both tags stop `prepare` naming both ids, with no write.
73. [H2] Firewall first: the fake's request log has the firewall create before `POST /droplets`; with `firewalled(ip)` (Slipway's address outside the sources) the pin wait fails with the SSH-sources text and nothing is sent to the droplet.
74. [H2] Kept certificate: three failed uploads (`fail[("POST", "/certificates")]`), then a retry: `fake_acme.orders` is 1 and the certificate is uploaded; after a restart between the order and the upload, the next run uploads the kept one; its credentials are cleared once it is recorded; a kept certificate with 30 days or fewer is ordered again.
75. [H2] Certificate union: a deploy to green whose release drops `learn` keeps `learn` on the served certificate while blue's live release has it; after blue is also deployed without it, the next `edge` issues one without it.
76. [H2] `resize_droplet` (the `resize` step, §9.4) cancelled during its poll, and one hitting the member-step timeout, ends with the droplet `active`: `power_on` ran in the shielded `finally`. A deploy refused before `resize` never powers the droplet off.
77. [H2] A cancel at each create's POST: the pending row stays, the answer (when the fake gave one) is recorded, and no second create follows on retry.
78. [H2] Address collision: a droplet given a hand-added host's address fails step 5 naming that host; the droplet stays recorded and the Billing callout counts it; after the host is edited, the retry continues and pins; a host owned by this environment isn't compared.
79. [H3] Sync repair: with no targets, `sync` puts the recorded active slot's droplet on, checks health, settles, runs the public check and proves; with the active slot already the only target it writes nothing; it never adds the other slot's droplet; skipped while a switch is unresolved; a failing public check is a warning.
80. [I1] The host-less owner: every instance API (`api/v1/instances.py`) and every recovery path (`recover_interrupted`, the poller, the unmanaged claim, the deploy-root move) on a managed owner answers 409 or skips, never an `AttributeError`; `environments.create` never writes a host-less owner in mode `server`.
81. [I1] Single environment, droplet deleted: the next deploy rebuilds it with a new host key and its `traffic` step leaves the load balancer on the new droplet id; a remade load balancer gets the active slot's droplet back from Publish.
82. [I1] Blue/Green, blue active, blue's droplet deleted: a deploy to green succeeds with its pre-deploy backup taken on green's new release; Activate green works; Back up now then runs on green; a deploy to blue is allowed (D28) and its `traffic` step repairs nothing while green is active, or repairs blue when blue is still recorded active.
83. [I1] Frozen values: a release that changes `edge.port`, `edge.health` or `data.managed.db.version` fails `prepare` before any DigitalOcean write (the fake's `writes()` is empty) and before `start`; an uploaded slipway.yml that differs from the provisioning one fails `manifest`.
84. [I1] `wipe` retried after a run that stopped between `DROP` and `CREATE` (the psql shim) ends with an empty database owned by the role.
85. [I1] `data.py` on Slipway backups: retention on managed data deletes the Slipway files and sends no SSH (`remote = None`); `check_backups` and `settle_unverified` read the Slipway files.
86. [I1] The renewal loop's job: `triggered_by_id` NULL, `options.by = "renewals"`, no permission check; refused (logged, audited once) by a running job, an unresolved switch, a deleting environment; not by the owner's hold.
87. [H1] Accounts: `new` and `deleting` environments count for the limit and for Remove; Remove with only deleted environments keeps the row as a tombstone (`secret` NULL, `config` cleared, `removed_at` set, the name kept); a save whose `ssh_sources` leave out a recorded `slipway_addresses` entry answers 409.
88. [J1] Create, Add slot and grow read the catalog before the transaction: the fake's transport fails the test if called while the account row is locked; a moved estimate answers 409; a confirmed grow writes `cloud.droplet_size` and `plan` together and `EnvironmentOut` shows `Resize pending: applies at <slot>'s next deploy` for a slot behind.
89. [F3] ACME: TXT challenge records with Slipway's comment left by a crash are swept before an order, for the order's names only (one at another name is left), one without the comment is left; two first uses of a directory at once store one account key and both use it, also when the `acme` row is missing at first use.
90. [J1] Resolve on a `do_lb` environment (`env_jobs.resolve`, through the backend's `who_is_live` and `lock`) sets the active slot, or answers 409 naming the targets; a DigitalOcean failure answers 502.

### 20.3 Real account (not in CI)

A development DigitalOcean account and team, a Cloudflare test zone, BaseCampV3 `slipway-manifest` with the G4 changes. Every object is removed at the end (item 11 checks it).

1. Add the account with the operator's address as SSH source; Test passes; the catalog's droplet prices match the control panel; the table's database, load balancer and Spaces prices match DigitalOcean's pricing page, and `SPACES_REGIONS` matches the regions that offer Spaces (update `PRICES`, `SPACES_REGIONS` and `as_of` if not). Until this item is done, `do_rules.PRICES` (as_of 2026-11-15) and `SPACES_REGIONS` are dated and unchecked; nothing in the code depends on the figures, and every estimate prints its `as_of` (Decision 36). Check the derived step timeouts of §18 (`prepare` 50, `resize` 60 minutes) on the same run.
2. Create `do1` (Single, staging certificate), confirm the cost, deploy: the chain builds everything, the cloud firewall exists before the droplet (the control panel's history), `cloud.slipway_addresses` holds the operator's address, neither DigitalOcean's monitoring agent nor its droplet agent runs on the droplet, `id slipway` lists `docker` and no `sudo`, `ssh -o StrictHostKeyChecking=yes` with the pinned key works, the database rejects a connection from the operator's laptop (trusted sources), the names answer through the load balancer, starter content is there.
3. Back up now: the file is on Slipway, not on the droplet. Restore it. Reset it, then restore again.
4. Add green (confirm the delta), deploy with an expand migration, activate green while blue serves; switch back.
5. Delete green's droplet in the control panel; deploy to green: it is rebuilt with a new host key and pinned again.
6. Kill Slipway during `prepare` right after the droplet create; restart and retry: the droplet is adopted, not doubled.
7. Grow the droplet size and add a standby node; deploy to the idle slot: only it resizes; the cluster grows.
8. Renew the certificate by hand (staging): the load balancer moves to the new certificate; the old one is deleted.
9. Create `prod1` on a production account; retire, deactivate, delete with the snapshot and the phrase.
10. Delete green's droplet while green is active on `do1`'s Blue/Green copy (or blue's on the Single `do1` before item 11): deploy to that slot rebuilds it and the load balancer serves it again with no Activate.
11. Delete `do1`: the control panel shows no `slipway-do1-*` object, no tagged droplet or cluster, no Spaces key, no bucket, no VPC; the Cloudflare records Slipway made are gone; the backups sit in `kept/`.

---

## 21. Implementation slices

Phases 4 and 5 are built together from one plan, `scratchpad/phase45/plan.md`, whose slices replace this section's first table (F1-F4, G1-G5, H1-H4, I1, J1-J2, K1). Groups F (F1-F4) and phase 5's A2-A5 were built first, as new files; slice S01 moves their staged tests into `tests/`. Groups run in order; slices in one group run in parallel and share no file, tests included. After each group the full suite passes, and from S06 on the phase 3 golden files pass unchanged after every slice. Each slice's section in the plan names its files, the spec sections and numbered tests it covers, and what done means.

| Group | Slices |
|---|---|
| 1 Foundation | S01 Housekeeping: staged tests into `tests/`, one guard, settings, packaging, image, the slipway user; S02 Reconcile the phase 4 and phase 5 design docs with the plan; S03 Schema: provider accounts, DigitalOcean columns, machines tables, permissions, key rotation; S04 Manifest additions: `edge`, `data.managed`, managed slot role (old G2); S06 Host fakes (old G5) and phase 3 golden files |
| 2 Shared services and the traffic interface | S05 Traffic backend interface and Cloudflare TXT records (old G3, widened); S07 Host contract, resources extensions and the Slipway backup store; S08 Provider accounts for DigitalOcean, Proxmox and ESXi |
| 3 Providers, first half | S09a DigitalOcean provisioner, part 1: `create_once`, `prepare`, resize, rebuild, recovery (old H2); S10 `do_lb` traffic backend (old H3); S11a Machines core (P5 B1, shared part) |
| 4 Providers, second half | S09b DigitalOcean provisioner, part 2: database, edge, certificates, ACME store, teardown (old H2); S11b Proxmox provider |
| 5 Pipeline and ESXi | S12 Provider steps in the pipeline: `prepare`, `resize`, `database`, `edge`, step timeouts, the not-built fences; S13 ESXi provider |
| 6 Host-less paths, DigitalOcean environment jobs, account pages | S14a Owner and instance paths without a host, and the not-built instance answers; S15 Environment jobs for DigitalOcean, and owned-host removal without SSH; S21 Accounts and hosts pages |
| 7 Managed data, VM environment jobs, renewals | S14b Managed data owner: data runner, `wipe`, backups on Slipway, owner lists; S17 VM environment jobs; S19 Certificate renewal loop and the app lifespan |
| 8 VM jobs and create rules | S16 VM snapshot, revert and drop jobs; S18 Create, Add slot, Delete, sizes and production rules for both placements |
| 9 Environment, host, instance and retry API | S20 Environment, host, instance and retry API for DigitalOcean and owned hosts (old J1 plus the shared host rules) |
| 10 VM API, DigitalOcean chains, DigitalOcean pages | S22 VM API; S23 DigitalOcean end-to-end chains and the ServerSherpa LAN golden; S24a Environment pages for DigitalOcean |
| 11 VM pages | S24b Environment pages for VMs |
| 12 Docs | S25 Docs: DigitalOcean, machines, integration status, and the specs' final state (old J2) |

Where the old slices went: H4 (the backup store) is in S07; I1 is split across S12, S14a, S14b, S15, S19 and S23; J1 is S18 (the service rules) and S20 (the routes); K1 is S21 and S24a. Old G4 (ServerSherpa's `slipway.yml`, `ss-stack has-data --external`, `env.example`, `test-managed-role.sh`; test 32) is work in the BaseCampV3 `slipway-manifest` branch, outside this repository: it is not one of the plan's slices and is tracked separately, after S04 fixes the keys (Decision 35). Each slice recorded what it did differently in `scratchpad/phase45/deviations-<slice>.md` and what it put off in `later-<slice>.md`; S25 folded them into §23. Every group's gate ran the whole suite on SQLite and it passed (3091 passed, 8 skipped after group 11); the gates of groups 1 and 3-5 also ran it on PostgreSQL 16, and later slices ran their own files there.

---

## 22. Open questions, with the default chosen

1. **The cert-worker and a renewal token.** Default: **neither** (D2). Slipway renews from its server; the worker idles. If Slipway is down for 30 days the certificate can lapse; the page warns at 14 days.
2. **SSH sources.** Default: **required on the account**, `0.0.0.0/0` allowed when typed, with a warning on every page that shows it (D14). Slipway can't learn its egress address before the first droplet without an outside service; after that each droplet tells it (`$SSH_CONNECTION`), and the account refuses sources that leave a learned address out.
3. **Production on LAN environments.** Default: **DigitalOcean only** (`ck_environments_production_do`), as Sirdar. Deactivate on Switchyard (removing the active-following hosts) isn't designed yet.
4. **One production per repository and manifest.** Default: **yes**; a cutover retires the old one first.
5. **Prices and Spaces regions not in the API.** Default: a **dated table in code** with per-account overrides only (D17; no install-wide override, Decision 41); the real-account check updates it (§20.3 item 1). The estimate always shows its date.
6. **A cheap single-droplet shape with its own data.** Default: **not built** (D21): a rebuilt or deleted droplet takes the data with it, and backups would need the same Slipway storage anyway. Can come later as `data_mode = slot` on DigitalOcean with mandatory Slipway-stored backups.
7. **A gone cluster or bucket under live data.** Default: **refuse to remake it by itself**; the person retries with `rebuild_data: true` (typed name) and then restores a backup. Remaking empty data silently would look like a working environment with no data.
8. **Database standby.** Default: **can be added, never removed** (Sirdar, `SD/do_envs.py:180-181`).
9. **Snapshot before deleting a non-production managed environment.** Default: **ticked, can be unticked** with a warning, when the owner holds data and a slot can run its commands; **unticked** when it never held data or no slot was ever deployed; production can't untick it while it holds data and a slot can run (§13).
10. **Droplet image.** Default: **`ubuntu-24-04-x64`**, fixed in code (Sirdar, `SD/do_envs.py:32`). A setting can come when 26.04 is out.
11. **Sudo for the droplet user.** Default: **none** (D24); docker-group access is root-equivalent anyway, and no step needs sudo.
12. **Docker from Ubuntu's archive or from Docker's repository.** Default: **Ubuntu's** `docker.io` and `docker-compose-v2` (no third-party script). If ServerSherpa needs a newer Compose feature, `edge` could later name a package source.
13. **Renewal threshold.** Default: **30 days**, every 6 hours, 24-hour backoff after a failure.
14. **Backups of a deleted managed environment.** Default: **kept on the Slipway server in `kept/`**, removed by hand; snapshots are the supported way to keep data.
15. **Rebuilding the active slot's gone droplet.** Default: **not by itself, but a deploy to it is allowed** (D28): its `traffic` step's sync repair puts the new droplet on the load balancer. Activating the idle slot is offered too when it has a live release.
16. **Account monthly limit.** Default: **none set**; the field is offered.
17. **The delete phrase for non-production.** Default: **the name only** (P3), the phrase for production.
18. **Deactivate.** Default: **retiring production only** (Sirdar).
19. **PostgreSQL version.** Default: **required in `data.managed.db.version`**; an upgrade of a live cluster isn't offered (DigitalOcean's in-place upgrade can't be put back), so a new major version means a new environment seeded from a snapshot.
20. **Registering Slipway's key with DigitalOcean's SSH-key list** (to stop the root-password email). Default: **no**; it would be an account-wide object Slipway must own and clean up, for a cosmetic gain.
21. **Changing `edge.port` or `edge.health` on a live environment.** Default: **refused** (D15, §14.3); a new port means a new environment seeded from a snapshot. A designed edge change (both slots, the forwarding rule, the health check and the firewall moved in one job) can come later.
22. **Request tags left in the account's tag list.** Default: **left** (§6.4). They cost nothing, and deleting tags would mean Slipway calling the tags API, which it never does (§6.1).
23. **Two droplets or clusters of one name, both tagged as Slipway's.** Default: **stop and change nothing**, naming both ids (§6.2). With intent rows this can only follow a hand action or a bug; picking one could delete the wrong one.
24. **A droplet's new address is still a hand-added host's.** Default: **refuse in step 5, keep the droplet recorded**, and name the host row to fix (§9.2). The refusal holds even when that host's last check failed: its row would still send its own instances' deploys to the droplet's address.
25. **DigitalOcean's monitoring agent and droplet agent.** Default: **both off** (`monitoring: false`, `with_droplet_agent: false`, D24). They install through DigitalOcean's own script, Slipway reads none of the metrics, and the droplet agent's web console is a way in that Slipway doesn't need; a person who wants either can install it by hand.
26. **Deleting production that holds data when no slot can run its data commands.** Default: **Deploy first is offered, or a second typed phrase** (`delete production <name> without a snapshot`, §13), audited. Refusing outright would leave a billing environment that can't be removed.
27. **How long a pending create is waited for.** Default: **two lookups at least 60 s apart, both at least 60 s after the send, at most 3 minutes in one step** (§6.4); a longer lag fails the step without making anything, and its retry looks again.
28. **Where Slipway reads the provisioning manifest.** Default: **through GitHub at the resolved commit** (`gh.get_file`), the call P3 §9.1 uses; Slipway keeps no repository mirror.

---

## 23. As built

Phase 4 was built with phase 5 in twelve groups (§21), against fakes only. This section records where the code differs from, or goes beyond, the text above; **where the two disagree, this section describes the code**. Each item names the slice whose notes it comes from (`scratchpad/phase45/deviations-<slice>.md`). Texts in backticks are the code's. Items still open are in §23.20.

### 23.1 Hosts, owned hosts and the host-less owner (§3.3, §3.4)

- `ssh.host_is_built(host)` is what `SSHTarget.from_host` and the hosts helpers use; it treats an unsaved row's `provider = None` as `ssh`, so phase 3 code that builds `Host(...)` objects keeps working. `Host.is_built` is unchanged (S07).
- `check_host` calls `from_host` before writing `last_checked_at`, so a refused (not built) check writes nothing. A provider host with no pinned key is never probed: it gets `status = error` and `<host> has no pinned host key. Slipway pins it itself when it builds the machine: deploy again` (S07).
- `owned_host_refusal(host, *, action, owner=None, slot=None, account=None)`; `owned_host_problem(db, host, *, action)` reads the names; `edit_refusal(host, fields)` maps a PATCH. Actions: the PATCH field names, `instance`, `placement`, `environment`, `add_slot`, `claim`, `delete`, `reset_key`, `move_root`, `check` (refused only while not built). Droplet texts: `<host> goes when <env> is deleted` (a data host), `<host> is a <droplet|VM> Slipway made for <env>; its deploy root stays where Slipway set it`, `<host>'s key was made by Slipway with the droplet for <env>; Slipway changes it only when it builds the droplet again`, `Slipway pins <host>'s key itself when it makes the droplet: deploy to <slot>` (S07).
- `address_holder` gained `except_environment_id` and compares the address as given and lower-cased. Extras: `hosts.PHASES`, `phase_of`, `kind_of`, `planned_name` (ValueError past 64 characters), `name_clash`; `planned_host(..., deploy_root=)` refuses provider `ssh` and defaults the hostname to `<name>.invalid` (S07).
- The API (S20): an owned-host PATCH field counts only when it would change the row; `name` is refused with the edit text; a deploy-root change with deployed instances gets the `move_root` text. `POST /hosts/{id}/check` on a provider host needs only `hosts:read`; while not built it answers the owned text (409). `GET /hosts/{id}/unmanaged` on an unbuilt host answers 409 with `HostNotBuilt`'s text. `HostOut.owned_by.slot` is the machine row's slot, else the owning environment's instance on the host.
- `prepare` reads, with its own GET, any other slot's recorded droplet missing from its tag listing; a 404 sets that host's phase `gone` and logs `Droplet <name> is gone from DigitalOcean: deploy to <slot> to build it again`. Nothing is written to DigitalOcean, and no extra read happens while every recorded droplet is listed (S23).
- The host-less owner (S14a, S20): every `<x>.host.name` read goes through `data.host_label` (`its managed database` for the owner). `deployer.host_of(instance)` raises for the owner. `GET /instances` leaves host-less rows out; `GET` and `PATCH /instances/{owner}` answer 200 with `host` and `host_id` null; control, containers and logs answer 409 `<env>'s data is in its managed database, so it has no server of its own: manage it from <env>'s page`. An app slot of a managed environment says its data `lives in its managed database`. `traffic.target` reports `<instance> has no server of its own`. A deploy of the owner is refused at run time: `<env>'s data is in its managed database, so there is no data server to deploy: deploy to <slot> instead`. Recovery and the poller needed no change.

### 23.2 Schema, migrations and key rotation (§3.5, §3.10)

- `rotate-encryption-key --clear-unreadable` on a `location = slipway` backup that is `ready` also sets `status = changed`, because `ck_backups_slipway_key` forbids a ready Slipway backup without its key; the fix-up reports `N backup(s) lost the key ...; they can only be deleted now`. An account whose secret was cleared gets one check `{name: "secret", level: "error", text: "The token couldn't be read after a key change: enter it again"}` ("password" for ESXi) (S03).
- Migration 0011's downgrade also deletes deployments of the kinds `certificate` and `deactivate`. The `acme` row it inserts is `value = {}`, `secret = NULL`; an existing row is kept (S03).
- Constraint names: `uq_provider_accounts_name`, `ux_environments_one_production`, `pk_address_claims` (S03).

### 23.3 Permissions and audit (§4)

- Maintainer's description mentions cloud costs, VMs and provider accounts (S03).
- `provider_account.*` details: create and update `{name, provider, production, region | url}` plus `changed` (field names, `token replaced`, `token cleared`, `password replaced`, `certificate forgotten`); test `{name, provider, status, checks: [{name, level}]}`; trust `{name, provider, fingerprint, subject, not_after}`; delete `{name, provider, tombstone}`; target type `provider_account` (S08).
- `do_provision.remove_droplet` audits `environment.resize` for the plan's drop to one droplet (`from {droplets: 2}`, `to {droplets: 1}`, old and new cents, delta), also on the `Already removed` path (S09b). Remove slot on DigitalOcean audits `environment.slot_remove` with `host` (the droplet name) and `owned: true` (S15).
- `environment.deactivate` is audited by the route at queue time with `{name, by, slot, deployment}` (S20). `certificate.renew_queued` and `certificate.renew_refused` are §4.2's rows (S19).

### 23.4 Manifest (§5)

- Rule 10 (an environment variable may not set an `edge.env` or `data.managed.env` key) applies only to a plan made with `managed` or `edge_values`: `check_instance_env(..., managed=False, edge=False)`. On a LAN environment those keys aren't Slipway's, so phase 3 is unchanged (S04).
- Only `holds: other` volumes are kept when either `managed` or `edge_values` is given. `plan(role="slot", managed=True)` defaults `without` to `data.managed.skip`. Without the new parameters the slot role renders byte for byte as phase 3 (S04).
- `CAPABILITIES` gains `edge`, `managed`, `digitalocean` before `attach`, `server`, `bluegreen` (S04).
- Extra refusals: `edge` needs both `port` and `health`; `edge.env` keys may not repeat `optional_services.var`, a `data.attach.env` or a `data.managed.env` key; `edge.env` templates may use only `{edge.address}`, `{edge.trusted}`, settings and vars; `{edge.*}` outside `edge.env` is refused; a postgres entry needs `version`, `database`, `user` and `password`, names follow `'<x>' isn't a PostgreSQL name: ...`, and the password's secret must be declared; `cors` services need a hostname and may not be skipped; endpoint names `skip`, `env` and `commands` are reserved beside `data.managed` (S04).
- `to_json` holds `edge {port, health, env: [keys], projects}` and `data.managed {skip, needs, env: [keys], commands: [keys]}`; the password is its `{secret.K}` template. Helpers: `edge_settings()`, `required_settings(edge=)`, `password_secret(need)`, `services_for(..., without=)` (S04).
- `tests/test_manifest_env.py::_phase2` also strips `data.managed` and `edge`, and `test_manifest_data.py` passes `managed=None`: one line each (S04).

### 23.5 Names, intent rows and `create_once` (§6)

- `create_once` takes a `CreateSpec` (name, body(nonce), send, find, ident, details, credentials, tags, adoptable, discard, stray, before_intent, same_pending, pending_credentials, nothing_made, rebuild, size, nodes), with public builders per kind. It never reads recorded rows: its callers do (S09a).
- §6.4 step 4's one transaction is two commits: the host row (`creating`, `host_key`, fingerprint) is committed first, then the pending row. A crash between them leaves a creating host with a key and no pending row; the next `prepare` makes a new key and a new create. `hosts.provider_id` is written in its own commit right after `record` and again on every `prepare` (S09a).
- `resources.record(..., rule=, audit_action=, replaces=, credentials=, tags=)`: `audit_action` is one of `resource.create`, `.adopt`, `.rebuild`, `.claim`; a `pending:` provider id is refused; `replaces` updates the pending row in place, ignores a `replaces` that no longer exists, and refuses one of another kind, name or environment. `record_pending` refuses with `Environment <env> is still waiting to learn whether its <kind> <name> was made (request <nonce>)` (S07).
- `plan_check(db, env, kind, *, client=None, remake=False, size=None, nodes=None, name=None)` counts droplets, clusters, load balancers, buckets, VPCs and firewalls (not keys or certificates) and reads DigitalOcean before its own database reads. Its text: `This would make <object>, which <env>'s confirmed plan doesn't include: <how>. Slipway changed nothing` (S09a).
- An unrecorded tagged droplet or cluster with no pending row is a stop, never adopted outside teardown (S09a, S09b).

### 23.6 Accounts (§8)

- `ProviderAccountOut` is a union of `DigitalOceanAccountOut`, `ProxmoxAccountOut` and `EsxiAccountOut` (`schemas.provider_account_out`), with `removed_at`, `created_at`, `updated_at` and DigitalOcean's `prices`; each `used_by` item is `{environment, environment_id, slot, name}` (S08).
- `GET /{id}/catalog` answers `{region, regions, sizes, db_sizes, db_versions, spaces, region_has_spaces}` (S08).
- Turning `production` on is refused while a non-production environment uses the account: `<names> use(s) <account> and isn't/aren't production: a production account serves only production environments` (S08).
- Names are unique case-blind; a clash with a tombstone says `An account named <x> already exists: it was removed, but keeps its name so old logs can still name it. Pick another name` (S08).
- A new secret or a cleared token resets `status` to `unknown` and clears `checks`, `facts` and `last_checked_at`. A tombstone clears `tls`, `checks`, `facts` and `status`; PATCH, Test, Trust, catalog and a second DELETE answer 409 `<name> was removed: add a new account instead` (S08).
- Test's checks, in order: `account`, `region`, `team` (a saved account whose environments are frozen on another team), `droplets` (warns at the limit or with room for fewer than two), `vpcs`, `databases`, `spaces_keys`, `certificates`, `load_balancers`, `firewalls`, then the `scopes` note. Facts `{team, account_status, droplet_limit, droplet_count}`. Test never answers 502: every failure is a failed check (S08).
- The token is 1-200 printable ASCII characters without spaces; `monthly_limit_cents` is 1 to 10^10 or null. The service functions commit themselves (S08).
- Errors: 422 `{detail, field}`; refusals `{detail, field?, code?, certificate?}` (S08).
- The Integrations page (S21): visible with `providers:read` or `settings:write`; the Switchyard and Cloudflare cards still need `settings:write`. The DigitalOcean region select lists `do_rules.SPACES_REGIONS`. An edit sends only the fields that changed, so untouched SSH sources never re-run the lock-out guard; the limit is typed in dollars and sent as cents, and the dialog shows the stored limit exactly (`1234567.89`), so an edit that leaves it alone doesn't send it. Removed accounts are listed last with a `Removed` badge.

### 23.7 Droplets (§9)

- Texts the spec left open (S09a): `<host> has no pinned host key, so Slipway can't trust <droplet>`, `<What> failed: DigitalOcean's action ended errored`, `<droplet> can't become <size>: <problem>. Slipway changed nothing`, the team mismatch, the missing token and SSH sources, the frozen `edge.health` and `data.managed.<need>.version`, the missing `digitalocean` capability. The pin's timeout uses the firewall text unless a try failed authentication.
- Readiness: on failure its last line comes from a second `cloud-init status | tail -n 1`. The marker is `do_provision.READY_MARKER` (so tests can move it). Docker's version is stored only when printed (S09a).
- `phase = ready` is set at §9.2 step 6, before the pin. `provider_state` holds `droplet_name, region, size, image, public_ip, private_ip` and `built_at`. A slot whose host was built before gets its next droplet audited `resource.rebuild` and noted in `options.rebuild` (S09a).
- When `prepare` remakes the deploying slot's gone droplet, the slot's `app_state.live` moves to `app_state.gone_live`, so the data runner uses rule 2 or 3 of §10.4 (S23). After a `prepare` the deployer reloads the other members' hosts and the instance's `app_state` (S23).
- `prepare` lists the env-tagged droplets once, right after the team check, so duplicates (test 72) and half-tagged droplets (test 39) stop before the VPC or firewall is touched (S09a).
- `remove_droplet(ctx, slot)` also drops `cloud.plan.droplets` to 1 and recomputes `cloud.cost` from the live catalog, keeping `confirmed_by_id` and `confirmed_at`. A pending droplet row for the slot is resolved first. Host and instance rows go with plain DELETE statements (S09b).
- `resize_droplet` waits for a resize DigitalOcean already took before its shielded `power_on`; `provider_state.size` is written when the resize action completes, before the SSH wait. A droplet already off skips `power_off`. The step doesn't start the live release again; its note is `Resized to <size>` (S09a, S12).
- The deploy's SSH session is reopened after a resize (a `_Reopenable` proxy), because the droplet restarts (S12).

### 23.8 Managed data (§10.1-§10.3)

- `database` returns None when the manifest has no managed PostgreSQL need, and never PUTs an empty trusted-source list (DigitalOcean reads one as every address). A droplet found gone is left out of the trusted sources and the create body (S09b, S23).
- Grow problems (a smaller size, a standby removed) leave the cluster alone with a note, not a failure (S09b).
- `_setup_role` runs its SQL over a fresh session to the slot's droplet; the redactor gets doadmin's password, the app secret and the verifier (S09b).
- Setup keys are made only when needed (a bucket to make or check, or CORS the bucket's key can't set), so a second `prepare` writes nothing. A setup key left by a crash, and every unrecorded key of ours with only our grants, are deleted at the start of the bucket step. A recorded bucket key whose secret can't be read is deleted and made again. The bucket is made only when the manifest has an `s3` managed need (S09a).
- `slot_values(db, env, slot_instance, *, man)`: postgres `{host (private), port, database, user, password, tls: require, ca_b64}`, s3 `{endpoint, region, bucket, access_key, secret_key, path_style: "false"}`; `edge_values` holds only the keys that are set (S09b).

### 23.9 The data runner (§10.4)

- `data.runner_choice(env, members, deploying=None)` gives rules 1-3 and the rule-2 log line (`blue's droplet isn't built; running the data commands on green`, or `blue has no live release; ...`). `can_run_data`, `data_runner_of` and `hostless_refusal(db, owner, start_over=)` are built on it, so the queue (`require_data_job`) and the run (`deployer._start`) agree. `deployer.data_runner(env, job) -> _AppRun`; `_owner_run(c)` replaces every `c.member(owner_slot)` of the slot paths (S14b).
- A managed owner job runs as a root `_AppRun` whose instance, session and folder are the runner slot's, while `c.owner` stays the owner; the data steps write the data fields on `c.owner` (S14b).
- **The owner's `app_state` mirrors its runner's live release** (`data.runner_live`, with `live.runner = <slot>`), so readers outside data.py work unchanged. It is written when a managed slot goes live, when an owner job opens its runner, and in the transactions of Activate, Deactivate, Resolve and `_remove_instance` (S14b, gate 7).
- Opening the runner reads every other deployed slot's lock: a live `d` line refuses with P2's text (`... is still running on slipway-shop-green ... Wait for it to end and retry`); "waits" in test 58 is that refusal (S14b).
- `data.runner_keys` counts the owner as running on an app slot, so its Back up now and snapshot take both environment keys (S14b).
- Start over on managed data runs on the built app slot with the newest deploy release when no slot can run the data (S14b).
- Starter content after the first activate counts the app slots' deploys for a host-less owner (`env_jobs._seed_skip`); before, it was always skipped (S23).
- `server_first` applies only to `data_mode == server` (Decision 21); `POST /environments/{id}/deploy {target: data}` on a managed environment answers 409 `<env>'s data is in its managed database: it has no data server to deploy` (S20).

### 23.10 Backups on Slipway (§10.5)

- `backup_store.pull(remote, owner, backup, *, sources: {part: path}, say=None) -> Stored`; `apply(backup, stored)` sets location, key and size and the caller commits. `push(remote, owner, backup, *, targets, say=None)` is an async context manager whose copies go when the block ends. `check(owner, backup) -> Checked(status, text)`; `usable`, `delete`, `sweep`, `space_problem(need, *, db=None)` (S07).
- Free-space text: `Only <free> is free in Slipway's backup storage; the backup needs about <need>. Delete old backups and retry. Nothing was changed.` (S07).
- `push` checks the hash on the stream and on the runner; a runner without a hash tool only logs. A pull whose runner copy can't be removed still succeeds, with `Couldn't remove the copy of <name> on the runner; its next job clears that folder` (S07).
- Managed backups are written `location = slipway` from the start, dumped into P2's `backups/.incoming/<name>.<part>.partial` files (no `.json` sidecar), hashed, pulled with no session held, then `apply` and ready in one commit. A runner with no hash tool fails the backup: `<host> has none of sha256sum, shasum or openssl; a backup kept on Slipway needs one` (S14b).
- A restore pushes the stored backup once per job into `.incoming/<name>.db` (and `.files`) and removes the copies in the job's `finally` (S14b).
- `check_backups`, `confirm_backup`, `settle_unverified` and `apply_retention` take `remote: Remote | None`. Slipway rows are always fully decrypted and hashed; retention deletes their files without a confirmation round; settle keeps an unverified row only when its key reads and its files check, else removes the files and forgets the row. Texts: `Removed old backups from Slipway: ...`, `Backup <name> was kept on Slipway before Slipway restarted; checked it and kept it`, `The backup <name> on Slipway is missing` (S14b).
- `DELETE /instances/{owner}/backups/{id}` of a Slipway row removes its files and its row with no SSH (204), keeping P2's refusals; `?check=true` on the owner runs `check_backups(None, ...)`. **There is no backup download route**, so the download refusal text was not added (S20).
- The Backups card names `Slipway` for the owner and heads its column `Stored`; rows read `On Slipway` (gate 11, S24a).
- `keep(owner, *, env_name, env_id, at=None)` moves the files to `kept/` at teardown with `README.txt` (S07, S15).

### 23.11 Phase 2 features on managed data (§10.6, §11.5)

- The owner's step lists (S14b): restore `check, backup, stop_slots, restore, ⟨files⟩, start_slots, finish, ⟨first_admin⟩, traffic`; roll back the same without files and first_admin; reset `⟨check⟩ˢ, backup, stop_slots, wipe, ⟨restore, files, after_import⟩ˢ, start_slots, finish, ⟨first_admin⟩, ⟨seed⟩, traffic` (`check` only with a snapshot, as P3); Start over `backup, stop_slots, wipe`; Back up now `release, backup`; snapshot `release, ⟨stop_slots⟩, export, ⟨start_slots⟩, store`; admin `release, first_admin`; content `release, seed`. The `release` step (`Check <slot>'s live release`) opens the runner; restore, roll back and reset open it before their first step. Step names name the runner's droplet.
- `finish` of an owner job switches nothing; the owner's status, `current_commit_sha` and `last_deployed_at` never change (S14b).
- `wipe` runs `do_provision.reset_command` under the runner's lock, then `do_provision.empty_bucket` (a temporary full-access key, deleted in a `finally`), then each slot's own volumes, then P3's `has_data` check. Its refusals come before anything stops. It is one of `data.REPLACING_STEPS`, so a reset cut in it holds the data. Texts: `The managed database didn't take the reset (psql exited <n>); it may have no database <db> now. Retry: the reset ends with an empty one either way.`, `Emptied the bucket (<n> files deleted)` (S14b).
- `has_data` exit 4 fails with §10.6's text in the backup probe, the seeding check and the wipe (S14b).
- The first app slot deploy of a managed environment takes the owner's `seed_snapshot_id` (test 57) (S14b).
- The database probe on managed data: `... can't sign in to <env>'s database at <host>:<port> (<psql>). The managed database lets in only the droplets in its trusted sources: deploy to <slot> again, which sets them before anything uses the database` (S14b).
- A managed slot renders with `role=slot`, `do_provision.slot_values`, `managed=True` and the edge values (read again for each render), and `check_instance_env(..., managed=True, edge=True)`. `app_state.live.edge` records the edge values a release went live with (S14b).

### 23.12 Certificates and the load balancer (§11.2, §11.3)

- The certificate upload doesn't go through `create_once`, so a pending row can't lose the kept chain and key: the edge writes its own pending row with the credentials right after the order and uploads shielded. A retry first looks twice, 60 s apart, for a lost upload by its stamped name. A pending row that can't be reused (30 days or fewer, other names) is dropped at once (S09b).
- Old certificates: every recorded certificate but the served one is deleted, except one that still covers exactly the wanted names with more than 30 days left; `in use` 403s wait for the next run (S09b).
- Stamped names use real time and move on one minute while a name is taken (S09b).
- `edge(ctx, *, deploying_routes=None)`; the deployer passes none, since no plan is rendered before `source`, and the fallback uses `env.hostnames` whose service the release runs. Without the Cloudflare integration, edge and renew stop with a plain text (S09b, S12).
- Stale slots: when `cloud.lb_ip` changes, an app slot with a live release whose `live.edge.address` differs gets `slot_state.stale` (S09b).
- An existing load balancer's edge check is skipped for one this run created. The HTTPS certificate PUT takes `do_lb.lock_for(env.id)` (S09b).
- `renew(ctx, *, hold_lock=True)`; the certificate job passes `hold_lock=False` under the lock. Notes: `Renewed: <name>, valid until <date>`, `<name> is still good, valid until <date>; nothing to renew` (S09b).
- ACME challenge TXT records are made with `ttl: 60` and no `proxied`; one page of 100 is listed per sweep, filtered again by comment (S05).
- acme_store: writes in one process also take an asyncio lock, since SQLite ignores row locks; an unreadable or empty secret reads as no keys (S09b).

### 23.13 The traffic interface and `do_lb` (§11.6)

- `TrafficBackend` also declares `label`, `via`, `errors`, `pending(plan)` and `check_sync(ctx, result)` (S05). Switchyard's are `"Switchyard"`, `"Switchyard"`, `(SwitchyardError,)`. do_lb's label is `DigitalOcean`, via `the load balancer`.
- Repair runs after every sync body when nothing is unresolved, without the lock (the backend takes it); its result is merged into the sync's (S05).
- `_shielded_put_back(..., held: asyncio.Lock | None)`; `public_check(routes, address, ..., insecure=, via=)`; `no_address(via)`; `switch()` raises ValueError for a mode other than activate or deactivate (S05).
- Mode `deactivate` in `context()`: `to_slot` None, scope the active slot; switch's texts `Plan to take <env>'s traffic off <slot>:` and `Checking that <via> sends no traffic to <slot>` (S05).
- For a backend other than Switchyard the "nothing was live" failure says `Slipway put back what it had written`; `plan_for` asks the backend's `configured(db)` (S05).
- `SwitchyardBackend.who_is_live` matches recorded hosts' upstreams with each slot's `traffic.target`, as Resolve does (S05).
- do_lb's lock is keyed by environment id (`do_lb.lock_for(env_id)`), so a remade load balancer keeps it. `configured(db)` answers None; `plan` checks the token, a removed account and the team (S10).
- do_lb's blockers (S10): `<account>'s token answers for team <name>, not the team <env> was built in: Slipway changed nothing`; the renamed load balancer; `<slot> has no droplet yet: deploy to <slot> first`; `<slot>'s droplet <name> is gone: deploy to <slot> to make it again`; the untagged droplet; `The load balancer serves a certificate Slipway didn't record for <env>: Renew the certificate first`; the health text `<slot>'s droplet didn't pass its health check (<path> on port <port>) in 5 minutes: <last answer>`; the deactivate verify `The load balancer <name> still sends traffic to <slots>`; prove `The load balancer's certificate changed during the switch: something else updated it`.
- A target id that is a recorded droplet counts only while it exists; an unrecorded live droplet among the targets is a blocker; a gone unrecorded id is ignored (S10).
- The health command is `curl -sS -o /dev/null -w '%{http_code}' --max-time 5 -H 'Host: slipway-health.invalid' 'http://127.0.0.1:<port><path>'`; 200-399 passes (S10).
- A first activation writes one PUT. `options.switch.changed` entries are `{hostname: <lb name>, id, droplet_ids}`, saved after each PUT (S10).
- The by-hand put-back goes through the generic text: `<reason>. Slipway couldn't put 1 of 1 back: point load balancer slipway-uat-lb at blue (droplet 3001). Check them in DigitalOcean, then use Resolve on the environment page` (S10).
- Sync repair finds the other slot's live droplet among the targets: it writes nothing and warns `The load balancer sends traffic to <slot> (<id>), but <active> is the live slot: activate one of them`. A refused repair PUT is a warning; a failing prove raises SwitchFailed (S10).
- `who_is_live` returns `[]` with no load balancer or no targets and raises TrafficError for a foreign live droplet (S10). Resolve on do_lb holds `backend.lock` for its read and write, with texts `The load balancer sends traffic to blue and green: activate one of them` and `The load balancer sends <env>'s traffic to no slot: activate one of them`; `DigitalOceanError` maps to 502 in the route (S15, S20).
- `unresolved_text` says `use Resolve once the load balancer is right` for do_lb; "Slipway changed nothing" is said once (S15).
- Recovery calls `switchyard.hold_in` when `options.switch.backend` is `switchyard`, or when the record names no backend and the switch is none, switchyard or unset (a record from before S05) (S15).

### 23.14 Cost (§12)

- `validate_create` (and `?check=true`) prices the plan from a fresh catalog read and checks the limit; the typed `confirm_cost` is checked in `create`, `add_slot` and `grow`, so a check needs no figure. A figure equal to the cached estimate the page showed, while the fresh one differs, answers 409 `The estimate changed...`; any other mismatch 422 (S18).
- Add slot and Grow have `?check=true` (review K6): every refusal but the typed total, the plan and `cost` (with `delta`) as `ChangeCheckOut`, nothing written. Their dialogs price through it and show `The new estimate is about $X a month (+$D a month)`; before, they read the total from the 422's text (S24a).

### 23.15 Production (§13)

- The typed fences (`jobs.confirm_refusal`, 422: the name for a production Activate or Switch back, the phrases for a production teardown) run only in `queue_job`, so pages and Retry still offer the job. A chained activate while nothing is live needs no name. Activate checks the typed name before the 409s (S18, S20).
- `jobs.production_problem` (409) is in `job_refusal`: a retiring production only goes dark; Deactivate needs a retiring production with a live slot; a teardown needs retiring and off the air, and a snapshot first. **The teardown's `check` calls it again at run time** (S18, gate 8).
- Deactivate's refusals (`environments.deactivate_problem`): `Only a retiring production environment is taken off the air: retire <env> first`, `<env> doesn't publish its names, so there is no traffic to take off`, `<env> has no live slot: there is no traffic to take off`. It is allowed while a switch is unresolved and clears it. The job records `traffic_state.deactivated = {deployment_id, from_slot, at}`; the status stays `live` (S15).
- A production that holds data with no slot able to run the data commands needs the second phrase, `environments:delete` **and** `drop_data` with `data:reset` (S18).
- "Never held data" (`environments.never_held_data`) also accepts `fresh_data` unset when nothing ever went live, since a first deploy that failed in `prepare`, `database` or `edge` leaves it unset (S18). **This rule applies only to DigitalOcean placement, production, or an environment with a VM host**; a phase 3 environment on SSH hosts keeps P3's Delete answers (gate 9).

### 23.16 Jobs and steps (§14)

- `steps_for` stays synchronous with a `provider: ProviderSteps | None` keyword; `deployer.provider_steps(db, instance, env, members, *, resize=None)` works it out at the queue and again in `_start`, keeping the queued resize decision (S12).
- The managed slot list uses mode slot's order: `build, ⟨check⟩ˢ, backup, ⟨resize⟩ʳ, ⟨stop, restore, files, after_import⟩ˢ, start` (S12).
- Step names: defaults `Prepare the server`, `Resize the server`, `Set up the database`, `Set up the load balancer`, `Empty the database and the bucket`; on DigitalOcean `Prepare DigitalOcean` and `Resize <droplet> to <size>`. Every member job's `traffic` step on a do_lb environment is `Update the load balancer` (S12).
- Timeouts: `STEP_TIMEOUTS` plus `PROVIDER_STEP_TIMEOUTS`, read by `step_timeout(key, provider)` through `deployer._timed_step`; a timeout fails `<step name> timed out after <n> minutes` (S12).
- "When the instance is RUNNING" reads the status the job started with (`_Job.status_before`) (S12).
- The manifest hash is compared only for a DigitalOcean deploy of a new release; provider steps write options of their own, so the deployer re-reads them after each provider step (S12).
- Not-built rule: a `destroying` machine takes only a retry of its removing kind; a target with no host skips the host checks; D28 is written on `ssh.host_is_built` (S12).
- System actor: `queue_job(..., system='renewals')` only for kind `certificate`, never for a retry, a user or an instance. The certificate kind meets the unresolved-switch fence (S12).
- `jobs.KIND_PROBLEMS` answers None, a text (409) or a JobRefused, called after the environment kinds' own refusals (S12).
- Labels: `Renew the certificate`, `Take off the air`; nouns `certificate renewal`, `deactivation` (S12).
- Environment steps (S15): `certificate` (`Renew the certificate`, 45 minutes), `cloud` (`Remove the DigitalOcean objects`, 75 minutes); Deactivate `check, switch` with `Take traffic off {from_slot}` (`every slot` when nothing is active); Publish's `traffic` is `Update the load balancer`. Activate lists `certificate` when `certificate_due` finds the served certificate missing, at 30 days or fewer, or not covering the target's names; its check then leaves out do_lb's `The certificate doesn't cover ` blocker.
- `_fence` (Decision 28): Remove slot is allowed on an owned host in any phase; the other kinds need a built host (S15).
- `environments.attach_problem` answers None outside mode server; `data_values` and `owner_builtins` raise `<env>'s data is managed by DigitalOcean: it has no data server to attach to` for a host-less owner (S15).

### 23.17 Flows (§15)

- Create (S18): `PlacementIn.slots` (1 or 2, default 1); production needs 2. A DigitalOcean create is refused when `slipway.yml` has no managed PostgreSQL need; `region` defaults to the account's. New texts include `A DigitalOcean environment makes its droplets: leave hosts out`, `Managed data comes only with DigitalOcean placement: ...`, `Only a DigitalOcean environment can be a production environment`, `A DigitalOcean environment's traffic goes through its load balancer: choose the DigitalOcean load balancer`, and the 502 `Slipway couldn't read DigitalOcean's catalog for <a>: <error>`.
- The service helpers come in check and write pairs: `add_slot_plan` + `add_slot`, `grow_plan` + `grow`; `retire` and `unretire(db, env, ctx, confirm)`; `delete_problem -> DeletePlan`. Add slot on DigitalOcean answers the note `Deploy to <slot> to build it` (S18, S20).
- Grow (S20): `grow_plan` runs before the other PATCH fields, `grow` after them, in one commit; `environment.update` is written only when something besides the sizes changed. Grow needs `providers:spend`.
- Traffic PATCH on a DigitalOcean environment (S20): the switch stays `do_lb` (`<env>'s traffic goes through its load balancer: a DigitalOcean environment keeps the DigitalOcean load balancer`), DNS stays on (`A DigitalOcean environment always publishes its names in Cloudflare: DNS stays on`), the address can't be typed (`<env>'s records point at its load balancer, whose address Slipway sets: leave the address out`); `proxied` may change.
- Remove slot (S15): the narrowed retry's check note is `<slot>'s droplet isn't removed yet; Slipway goes on from where it stopped`. An owned host is never connected to (`Removing <inst>: <host> is a <droplet|VM> Slipway made for <env>, so nothing is run on it`); a host-less owner's stored backups go through `backup_store.keep` (`The backups Slipway stored for <inst> were moved to <folder>`).
- Retire and un-retire answer `EnvironmentOut`; un-retire's body is optional. Deactivate is queued with `options.confirmed = true`. The certificate route answers 409 when the switch isn't do_lb or no load balancer is recorded (S20).
- Delete (S18, S20): `DeletePlan.snapshot_options()` gives `{then: teardown, then_options: {confirm_production, drop_data, forget_vms}}`; `next_job` copies them into the teardown and adds `snapshot_first: true`, which the production fence reads (`then_options` is in `ENV_ONE_SHOT`). The answer is `DeploymentOut` plus `note`.
- The `cloud` step (S09b): two rounds of find, `check_all` and delete, then a final read that fails naming what is still there. The setup key is made only when needed, and a lost answer of its create is resolved at once. Each droplet's host row goes with it, other owned DigitalOcean host rows at the end. The VPC delete retries while it has members for 10 minutes; a 403 that isn't about members stops at once.
- The teardown's `check` (S15) checks the team read-only and runs `do_provision.check_all` with no sweep, so a renamed object stops it before any DNS record or instance goes. Texts: `<env>'s DigitalOcean account is gone, so Slipway can't reach its objects`, `<account> has no API token: set it in Settings → Integrations, then retry`.
- The renewal loop (S19): due means `certs.is_due(not_after)` (30 days or fewer, or unknown), not `needs_new`; a change of names is left to `edge` and to Activate's `certificate` step. Only environments `live`, placed on DigitalOcean with `traffic.switch = do_lb` are read; one with no load balancer is skipped. Only the latest `certificate` job counts for the 24-hour backoff (its `finished_at`, else `created_at`). The served certificate is read from the load balancer's HTTPS rule; any failure falls back to `cloud.certificate.not_after`, logging only the error's type. The first pass is 300 s after start. A refused queue is logged and audited `certificate.renew_refused` at most once a day; the owner's hold doesn't refuse a renewal, and the notice is left as it is.
- Recovery (S09a, S12, S19): `recover_prepare` changes nothing and returns log lines; the interrupted-resize notice is written after recovery's transaction, through Decision 23's rule. The lifespan runs `backup_store.sweep()` in a thread before `recover_interrupted` (an OSError is logged and start-up goes on) and imports `do_lb` so the backend is registered.

### 23.18 API (§16)

- `InstanceOut.host` and `host_id`, `SlotOut.host` and the summary's `host_name` are nullable for the owner. `SlotOut` gains `resize_pending`. `EnvironmentOut` gains `provider`, `production`, `retiring_at` and `cloud` (S20).
- `EnvironmentOut.cloud` is read from the database only: `{account, team, region, sizes, lb_ip, certificate: {name, not_after, days_left} | null, cost, objects (a count), billing_open, pending_resizes}` (S20).
- `GET /environments/{id}/cloud` (in `api/v1/environments.py`) answers `{account, team, region, plan, cost, lb_ip, certificate, objects: [{kind, name, provider_id, status, detail, monthly_cents, power?}], pending: [{kind, name, sent_at}], notes}`. The bucket isn't read live (`Recorded; Slipway reads it at teardown`). A droplet that is off adds `<droplet> is powered off`. 409 for a removed account or an unreadable token, 502 with the client's text otherwise. It writes nothing (S20).
- Create maps a `DigitalOceanError` to 502, and an address-claim IntegrityError (at flush or commit) to 409. `_plan_blockers` maps `HostNotBuilt` to 409 and `DigitalOceanError` to 502 (S20).
- Retry (S20): `RetryIn` gains `confirm_production`, `confirm_no_snapshot`, `rebuild_data`, `drop_data` and `forget_vms`, each asked again on every retry and checked for kind and permission (`rebuild_data` only on a member deploy, with `data:reset` and the typed name; `drop_data` only on a teardown). `actions.retry` gains `needs_phrases` and `offers_forget_vms`; a member job's `also_needs` gains `RETRY_EXTRA`. `CONFIRMED_KINDS` gains `deactivate`.
- `actions` gains `retire`, `unretire`, `deactivate`, `renew_certificate`, `grow` (with `pending`), `delete_data {holds_data, data_home, can_snapshot, production}`; `delete` keeps its shape (S18).

### 23.19 Pages and tests (§17, §20)

- Pages (S21, S24a, gate 10, gate 11): the chips (`provider_chip`, `build_chip`) are Jinja globals in pages.py. Owned-host actions are hidden with the refusal's reason. Instances, search and repository lists leave host-less rows out; the owner's page says its data is in a managed database. The flow's Where radio disables DigitalOcean without an account, without `providers:spend`, without Cloudflare, or without the `digitalocean` capability; Production forces Blue/Green and turns off auto-activate and staging; the flow's typed total is sent only with the create. FIELD_STEP sends `placement.provider`, `placement.slots` and `production` to step 2 and `confirm_cost` to step 7. The environment page's callouts follow §17.3's order, plus `<env> was taken off the air <when>: its names answer 503 from the load balancer until their DNS records are moved or removed`; the address-holder callout shows the newest failed slot deploy's refusal. The renewal line reads `Renews on its own 30 days before it runs out`, or `Renews on its own; the last try failed <when>: <first line of the error>`. The Data card shows only for mode server. The deployment page says `Slipway (certificate renewal)` and `Started by Slipway (certificate renewal).`. `RUNNING` (slipway.js) and `RUNNING_LABELS` (_macros.html) learn the five kinds (`Renewing`, `Taking off the air`, `Taking VM snapshot`, `Reverting`, `Deleting VM snapshot`); `STATUS` and `STEP_BADGE` are keyed by status, so they needed no change. `checkMustEqual` counts a cost field only once its figure is known, and keeps a submit off while `data-plan-blocked="1"`.
- The guard (S01): request-time failures name the host, never the URL; a test that must keep a real seam marks itself `@pytest.mark.own_guard`.
- Fakes (S06): `MultiRemote.connect` fails when the session is entered; an unknown hostname raises `ssh.SSHError`; `firewalled(ip)` times out, `booting` refuses; host keys are checked only for a host that presents one; the psql shim records stdin in `$PSQL_LOG`; `$SSH_CONNECTION` is an environment variable of every fake host's shell.
- The phase 3 goldens run through the services the API calls and record more than §20.1 lists (app logs, docker commands, every Cloudflare request, the environment's phase 3 fields). `scenario_folder` (tests/golden/test_phase3_golden.py) runs each scenario in a folder of exactly `TMP_LEN` characters, and `Norm` turns a clipped tail of that path into `<TMP, cut>`, so a clipped path in the record doesn't move with pytest's counter or the temporary folder's location (S06, gate 6; review F50). Test 70 passes pytest's own `tmp_path`.
- Test 70 (S23): the phase 3 scenarios run with the phase 4 example match `phase3.json`; `tests/golden/phase4_serversherpa_lan.json` records only Single and standalone, with an `env_file` that has no `SS_SPACES_BUCKET` line. Blue/Green in mode server keeps the env_file's default `SS_SPACES_BUCKET=serversherpa`, since the example's `data.server.provides.objects.bucket` is `{SS_SPACES_BUCKET}`. Test 81 makes the remade load balancer by deleting it in the fake; test 82 is two tests from one setup; the restart between power off and power on is a BaseException in the resize action.
- Where the numbered tests are: 23 test_host_contract.py and test_rotate_provider_secrets.py; 51 test_backup_store.py; 52 test_backup_store.py and test_do_api.py; 71 test_resources.py; 25-29 test_manifest_managed.py; 30 test_cloudflare.py; 31 test_traffic_backends.py; 33-35, 87 test_provider_accounts.py; 36-41, 44, 72 (droplet), 73, 76-78 test_do_provision.py; 40 (cluster, load balancer), 42, 43, 45, 46, 74, 75 test_do_cloud.py; 47-50, 79 test_do_lb.py; 53, 54, 70, 81, 82, 83 test_do_pipeline.py; 55-59, 84, 85 test_do_managed_data.py; 60 and 61 test_do_env_jobs.py, test_renewals.py and test_do_managed_data.py (61 is covered in two halves); 62, 64, 80, 88 test_do_create.py and test_do_api.py; 63 test_provider_pipeline.py and test_do_owner_paths.py; 65, 67, 68 test_do_api.py; 66 test_owned_hosts_api.py; 69 test_do_web.py; 86 test_renewals.py; 89 test_acme_store.py; 90 test_do_env_jobs.py.

### 23.20 Still open after the build

- **Kept backups can't be decrypted.** Files `backup_store.keep()` moves to `kept/` are encrypted under per-backup keys that go with the environment's rows. Snapshots are the supported way to keep data (open question 14); a later change could export the keys wrapped with a passphrase.
- **GET /cloud marks a gone droplet's host** (done in review, K1): a recorded droplet whose own GET answered 404 sets its slot's host `gone` by `_other_gone`'s rule (`do_provision.mark_gone`), audited `host.gone`, unless a job of the environment is queued or running; the deploy fence (D28) then sees it.
- **A backup download route** doesn't exist. If one is added, it must refuse `location = slipway` rows with `This backup is stored on Slipway; restore it from the environment page`.
- **`?check=true` on `POST /environments/{id}/slots` and a growing PATCH** (done in review, K6): the dialogs price through it.
- **A read-only `GET /provider-accounts/{id}/certificate`** would replace the all-zeros fingerprint the Trust button sends to learn the live certificate.
- **The by-hand put-back text** (§11.6) is the generic one; the spec's exact wording needs a per-backend hook in `traffic._failure_text`.
- **`.env.example`** doesn't list `SLIPWAY_BACKUP_TOTAL_BYTES`, `SLIPWAY_CERT_RENEW_INTERVAL` and `SLIPWAY_ACME_*`; docs/digitalocean.md does.
- **P3 §7.6** doesn't yet say that Blue/Green also takes `data.managed` (Decision 20).
- **BaseCampV3's side** (old G4, test 32) and the real-account run (§20.3) are not done; the price table and `SPACES_REGIONS` stay unchecked until §20.3 item 1.
- **Not run:** the whole suite on PostgreSQL after group 5 (groups 6-11 ran their own files on PostgreSQL 16 only); the pages in a real browser (only under the fake DOM).

---

## Appendix A. Critique responses

This appendix records the revision that answered the critique. Its slice names (G1, H2, I1, J1, K1) and figures (the `prepare` timeout of 70 minutes, migration 0010 holding everything) are that revision's; §3.10, §14.2, §18 and §21 give the current ones.

Each point was checked against the code in the checkout (phase 3's built `services/resources.py`, `models/environment.py`, `services/data.py`, `services/ssh.py`, `services/deployer.py`'s `resolve`, `services/manifest.py`'s `_set_by`/`_attach`, `api/v1/repositories.py`), P3's spec, and ServerSherpa's `slipway.yml` and `deploy/stack/env.example`. "Accepted" means the fix is in; "accepted, changed" means the problem is real and the fix differs; "partly correct" means part of the claim didn't hold.

| # | Point | Verdict | What was checked | Where it is handled |
|---|---|---|---|---|
| 1 | No record before a create; a lost answer can double-bill | **Accepted, changed.** Intent rows as proposed. The nonce goes in the request tag (droplets, clusters), the VPC description and the Spaces key name; the load balancer, firewall, bucket and certificate are found by their fixed (or stamped) names, since DigitalOcean gives them no free field and their names are already unique per environment. Duplicates stop, never pick (open question 23). | The spec's §9.2 "pending note" was undefined; `resources.record` writes only after the answer. | D18, J3, J12, §3.7, §6.2, §6.4, §12.3; tests 38, 44, 72, 77 |
| 2 | Recovery clears the pin a lost droplet needs | **Accepted.** `host_key` is never cleared while `creating`; adoption needs the key; no key → delete and remake; `host_key_private` dropped. | §15.13 and §9.2 step 1 did combine that way. | D4, §3.3, §3.7, §9.1, §9.2 steps 2-3, §15.13; test 61 |
| 3 | Teardown sweeps only droplets and clusters | **Accepted.** The `cloud` step finds every kind before checking, and again at the end. Certificates use a teardown rule (prefix and names among the environment's), since `is_ours` needs the exact wanted names. | Sirdar's `_destroy` scope as cited. | D19, §6.2, §15.11; test 45 |
| 4 | Firewall arrives late and can lock Slipway out | **Accepted, changed.** The firewall is made in `prepare` before the droplet, SSH rule only. Slipway's address can't be learned before the first droplet without an outside service, so it is learned from `$SSH_CONNECTION` on the first pinned connection and then guarded (account saves that drop it are refused; every SSH-rule change is proven by a fresh connection, else put back). Before that, a firewalled pin wait fails naming the sources. | `ssh.connect` and the pin flow; D14's old reason. | D14, J14, §8, §9.2 steps 7-8, §11.4; tests 43, 73, 87 |
| 5 | No path puts the active droplet back on the load balancer | **Accepted.** The sync repair, for the recorded active slot only, skipped while unresolved. | P3 §9.5 refusal 2 and §9.11's sync scope; Sirdar `_go_live`. | D10, D11, §6.3, §11.6, §14.3; tests 79, 81 |
| 6 | A gone active droplet in Blue/Green can't be recovered | **Accepted.** The runner falls back to a slot that can run; a deploy to the active slot is allowed while its droplet isn't built. | P3 §9.3's refusal; `SSHTarget.from_host` would raise `HostNotBuilt`. | D6, D28, §10.4, §14.1, §15.3; test 82 |
| 7 | Deactivate doesn't fit `traffic.switch` | **Accepted.** Mode `deactivate` in G3, verify by empty targets, `active_slot_id = NULL` written by `env_jobs`; the departure from P3 §10.9 is stated in the preamble and §11.6. | P3 §10.2's modes and step 4; §9.5 step 6. | Preamble, D10, §11.6, §13; tests 31, 50 |
| 8 | An idle-slot deploy changes shared objects | **Accepted, changed.** Certificate names are the union of every slot's live routes plus the deploying slot's, so a name leaves only when no live release serves it (not "at Activate": the slot giving up traffic must keep its names for Switch back). Port, health path and database version are frozen and checked in `prepare`, before any write, rather than in `manifest`. | `do_lb.plan`'s blocker now checks "covers the target slot's routes". | D12, D15, D27, J15, §11.2, §11.3, §14.3; tests 75, 83 |
| 9 | Which slipway.yml do the provisioning steps read? | **Accepted, changed.** `resolve` moves first; `prepare` reads slipway.yml at the resolved commit and stores its hash; `manifest` checks it. Slipway has no repository mirror: P3 §9.1 reads through GitHub (`gh.get_file(repo, path, ref)`, `api/v1/repositories.py:105`), and so does `prepare`, with the commit sha as `ref`. `resolve`'s reuse probe SSHes the host (`deployer.py`'s `if reuse:` block), so it now treats an unbuilt host as "release gone". | `deployer.py`'s `resolve` step uses GitHub only, then a probe. | D5, §14.3, §15.2, open question 28; tests 53, 83 |
| 10 | The `resources` API can't do what phase 4 asks | **Accepted.** Confirmed: `record` has no `credentials`, `tags` or audit override, though the columns exist (`models/environment.py`). G1 adds them, with pending rows, `replaces` and `set_credentials`. | `services/resources.py` as built. | §3.7, slice G1; test 71 |
| 11 | P2's backup code assumes a host; `.part` inconsistency | **Accepted.** `check_backups`, `confirm_backup`, `settle_unverified` and `apply_retention` take `remote` today; I1 adds the `location` branch with `remote = None`; J1 the owner's backup endpoints; files go through `.part`, fsync and rename, with a start-up sweep. | `services/data.py:1401-1501` signatures. | D23, §3.5, §10.5, §15.13, slices H4, I1, J1; tests 51, 61, 85 |
| 12 | Remove slot deletes the instance first; its retry says "Already removed" | **Accepted.** Driven from the droplet row; the critique's order; `plan` and `cost` last; retry continues while a droplet row or owned host remains. | P3 §9.9's retry rule; `instances.host_id` RESTRICT. | §9.3, §14.3, §15.6; test 46 |
| 13 | Delete impossible for a production that never deployed a slot | **Accepted.** No snapshot when the owner never held data; a second phrase when it holds data but no slot can run; the box unticked by default when no slot was ever deployed. | §10.4's old refusal; §13's rule. | D20, §4.1, §13, §16, §17.4, open question 26; test 62 |
| 14 | Slice order: fakes and Resolve | **Accepted.** New slice G5 owns `tests/fake_hosts.py` (a P3 S8a file, so group G); H2 and H3 depend on it. G3 keeps `who_is_live` on the backends; J1 changes Resolve's dispatch in `api/v1/environments.py`. | P3 §17: `fake_hosts.py` is S8a's, Resolve is S9's. | §21; test 90 |
| 15 | The ServerSherpa manifest change breaks J1; rule 5 | **Partly correct.** The J1 break is real: an `attach.env` key is written in mode `server` too. Fixed with `data.managed.env`, written only when the data is managed. The rule-5 concern doesn't hold: `SS_SPACES_BUCKET` is neither a setting nor a var in ServerSherpa's `slipway.yml`; it is an `env_file` default (`deploy/stack/env.example:50`), and `_set_by` refuses only settings, vars, secrets and port variables. The test case was added anyway. | `manifest.py` `_set_by`, `_attach`; BaseCampV3 `slipway.yml:23-50`. | D22, §5.1, §5.2 rule 11, §5.3, §5.4; tests 26, 70 |
| 16 | Let's Encrypt's duplicate-certificate limit | **Accepted.** The issued chain and key are kept encrypted on a pending row before the upload, reused while more than 30 days remain, cleared once recorded; `fake_acme` counts orders. | Let's Encrypt's 5-per-week limit per identical name set. | D12, §3.7, §11.2, §15.13; test 74 |
| 17 | Step timeouts shorter than their waits; a cancel leaves the droplet off | **Accepted.** Every wait has its own limit; each step timeout is the stated sum plus a margin (prepare 70, database 65, edge 40, certificate 45, wipe 45, cloud 75 min); `power_on` runs in a shielded `finally`; the database step now waits for `online` before reconciling trusted sources, so the two waits no longer add up. | The old §9.2 and §10.1 waits. | §9.2 steps 7 and 10, §10.1, §14.2, §18; test 76 |
| 18 | `wipe` can't be retried after it stops between DROP and CREATE | **Accepted.** `DROP DATABASE IF EXISTS … WITH (FORCE)`, then `CREATE` only when missing (`\gexec`). | The two statements can't share a transaction. | §10.6; test 84 |
| 19 | A droplet whose address is already a host's | **Accepted in part.** The droplet stays recorded and billing is shown; the message names the host row to fix; the comparison leaves out this environment's own hosts. The refusal is **kept** for a hand-added host whose last check failed: that row would still send its instances' deploys to the droplet's address (the pin would stop them, but the person should fix the row). | `SD/vmcommon.py:105`. | §9.2 step 5, §17.3, open question 24; test 78 |
| 20 | Accounts and limits: what "live environments" means; Remove | **Accepted.** Every environment with `deleted_at IS NULL`; Remove refuses while one uses the account, deletes the row when none ever did, and clears it when only deleted ones point at it. | `environments.deleted_at` and the `deleted` check (`models/environment.py:82`). | §8, §12.2; test 87 |
| 21 | DigitalOcean calls inside the create transaction | **Accepted.** The catalog is read uncached before the transaction; inside it only stored values are compared. | §12.2's old wording. | §8, §12.2, §15.1, §15.7; test 88 |
| 22 | The renewal loop queues with `user=None` | **Accepted.** A named system actor (`system="renewals"`, `triggered_by_id = NULL`, `options.by`), with the fences busy, unresolved and deleting, and not the hold. | P3 §8.5's `queue_job(…, user, …)`. | §3.6, §4.1, §15.12, slice I1; test 86 |
| 23 | `pending_sizes` contradicts itself | **Accepted.** Dropped. A confirmed PATCH writes the sizes and the plan together; "grows on its next deploy" is the difference between `cloud.droplet_size` and the host's `provider_state.size`. | §15.7's old wording. | §3.2, §12.3, §15.7, §17.3; test 88 |
| 24 | ACME leftovers and races | **Accepted.** Challenge records with Slipway's comment are swept before every order and in teardown; the account key is written put-if-absent under `FOR UPDATE` of an `acme` row that migration 0011 creates (and the store inserts when missing). | `app_settings` rows are per key; the row didn't exist before first use. | §3.8, §3.10, §11.2, §15.11; test 89 |
| 25 | `instances.host_id` nullable: a wide ripple | **Accepted.** The ripple was counted (55 `.host` sites in `deployer.py`, 12 in `api/v1/instances.py`, 4 in `data.py`, 2 in `web/pages.py` today); `environments.create` is the only writer of a host-less owner and only in managed mode; test 80 in I1 calls every instance API and recovery path. I1 owns `api/v1/instances.py`'s host-less refusals; J1 its backup endpoints. | `grep -n '\.host\b'`. | §3.4, §15.1, §21; test 80 |
| 26 | `monitoring: true` installs DigitalOcean's agent | **Accepted.** Turned off. | DigitalOcean installs the agent through its own vendor-data script. | D24, §9.2 step 3, open question 25; test 36 |
| 27 | Missing tests: cancels, the `.part` sweep, 403s | **Accepted.** A 403 on any read stops the step and never forgets (J13); the client raises `Forbidden` on GETs; `forbid[kind]` in the fake; cancel tests per create and for the resize; the sweep against the real pull path. | `digitalocean.py`'s planned `NotFound`/`Forbidden` split. | D25, J13, §6.2, §7, §20.1; tests 1, 40, 45, 61, 76, 77 |

**Found while revising (not in the critique).** Matching Spaces keys and certificates by the prefix `slipway-<env>-` (as Sirdar's `is_ours` does) would let environment `prod`'s sweep match environment `prod-eu`'s objects, and point 3's wider sweep made that dangerous: it deletes what it matches. Spaces keys now carry the environment id (`slipway-<env>-<id8>-…`), and both kinds are matched by an exact pattern (§6.1, §6.2; tests 11, 19). Droplets, clusters and the VPC were already safe: they carry the environment id in a tag or the marker.
