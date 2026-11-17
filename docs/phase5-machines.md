# Phase 5 design: Proxmox and ESXi

Branch `machines`. This is the design for phase 5 of bringing Sirdar into Slipway: environments whose slots and data server run on VMs that Slipway makes, sizes, snapshots and destroys on Proxmox (through Terraform) and on standalone ESXi (through pyvmomi). It builds on phase 3 ("P3", `docs/phase3-environments.md`, built), which is the contract here, especially P3 §14 ("Room for phases 4-6") and §10.9. It builds on phase 2 ("P2", `docs/phase2-data-safety.md`) for data safety.

Line references are to Slipway at 83dca5d for files phase 3 does not change (`models/host.py` is changed by P3 S2 only by adding columns, `services/ssh.py`, `services/hosts.py`, `services/switchyard.py` outside P3 S4's owner helpers, `core/config.py`, `Dockerfile`). Files phase 3 is rewriting are named by function, never by line. `SD/` is Sirdar's backend, BaseCampV3 branch `sirdar`, `sirdar/api/src/sirdar_api/`. Sirdar's README is `SR/README.md` (`sirdar/README.md`).

Settled before this design and taken as given: no Sirdar environment survives and nothing is imported; Switchyard is the only LAN proxy; no portal sign-in; one engine (Slipway's shell steps, no Ansible); Terraform stays for Proxmox and pyvmomi for ESXi. No test makes a real hypervisor, Terraform, TLS or TCP call: Proxmox is an httpx `MockTransport`, Terraform a fake binary, ESXi a fake behind Slipway's own `EsxiApi` (§16.1).

**Revised after the critique** (`phase5/critique.md`). Appendix B gives each point's verdict and where it is handled. The main changes: VM snapshot ability now comes from the storage (D23); a half-made Proxmox clone is recognised without its tags and waited for while locked (§7.4 C3); VM ids are reserved through a machines-level helper (D10); `nextid?vmid` tells a hidden VM from a gone one (D25); a resize is its own `resize` step after `backup` (D12); Remove slot and Delete check that every VM can go before they change anything (D26); running hypervisor tasks are waited for (D24); and the slices now match the files they need (§17).

**What phase 5 shares with phase 4** (`docs/phase4-digitalocean.md`, "P4"). Both phases are built together from one plan, `scratchpad/phase45/plan.md`, whose section Decisions (numbered 1-46, cited below as "Decision n") settled where the two specs disagreed; this text states those decisions. **`machines` is for VMs only** (Decision 1): droplets are not rows of it, and every `machines` column but `stage` and `size` is a hypervisor's. What the two phases share is one `provider_accounts` table (§3.1) and a **host-level contract** (P4 §3.3): `hosts.provider_state` with a common `phase` key (`planned | creating | ready | gone`), `Host.is_built`, `ssh.HostNotBuilt`, one owned-host refusal (`hosts.owned_host_refusal`), one address-holder check (`hosts.address_holder`), planned host rows from `hosts.planned_host`, and one `prepare` and one `resize` step key that the deployer dispatches by provider. The machines core (§6) is phase 5's own and plugs into that contract. Phase 5 adds no traffic backend: Switchyard (P3 §10.3) serves VM slots exactly as it serves SSH hosts, and `do_lb` (P4 §11.6) is untouched.

**Built.** Phase 5 is built, with phase 4, on branch `machines`, against fakes only; the real-host checks (§16.3) and the networked session (§16.3 item 18) are still to do. §19 records where the code differs from this text, slice by slice, and what is still open; where the two disagree, §19 describes the code. Line references to 83dca5d below are that revision's. How to use it is [machines.md](machines.md).

---

## 0. Decisions and why

| # | Decision | Why |
|---|---|---|
| D1 | **A VM is a host.** Each VM Slipway makes is an ordinary `Host` row (`provider = proxmox` or `esxi`, `owner_environment_id` set), with a `machines` row for what only the hypervisor needs and a P3 `resources` row (kind `vm`) for ownership. Deploys reach it through `SSHTarget.from_host` (ssh.py:94) like any host. | Every SSH path, pin check (ssh.py:530-594), health poll (hosts.py:124-134) and deploy step works unchanged. P3 §14 fixed this shape. Sirdar built an SSH config on the fly from the VM row (`SD/deploy/vms.py:355-377`); Slipway's Hosts table already holds that. |
| D2 | **Planned hosts.** Environment create and Add slot write, for each new VM, a `Host` row (`hosts.planned_host`, named `slipway-<env>-<slot>`, the VM's name) with the VM's static address as `hostname`, user `slipway` (`cloudinit.GUEST_USER`), a generated client key, `provider_state = {phase: planned}` and **no host key**. Slot instances point at it. Nothing touches the hypervisor at create. | `instances.host_id` is RESTRICT and NOT NULL for every slot (instance.py:86; phase 4 lets only a managed environment's data owner have none), so the slot needs a host before the VM exists (P3 §14). Keeping create offline keeps P3 §9.1's rule "No host is touched" and its `?check=true` dry run. |
| D3 | **`prepare` comes right after `resolve` in every deploy to a VM member** (an app slot or the data server whose host is a machine), as it does for a droplet (Decision 12). It makes the VM, continues a half-made one, or checks a made one; pins the host key; and sets up Docker on a new VM. It never resizes and never stops a made VM: when a resize will apply, it only runs the resize's read-only checks, so a resize that can't go fails the deploy before `source` (D12). Data jobs on a made VM have no `prepare`. | Sirdar runs its step 0 on every deploy (`SD/deploy/provision.py:216-255`). Every SSH step after it needs the VM, so it must come before `source`; `resolve` runs on the Slipway server and needs no host, so it goes first for both providers, and a bad ref then costs nothing on the hypervisor. Making a planned or half-made VM before the deploy's own refusals is allowed: nothing of the app runs there yet, no data or traffic depends on it, and the retry continues it. Data jobs need the VM as it is; a VM that is down fails them at SSH with the usual text. For a provider host, P3 §14's unpinned-host refusal becomes the not-built rule (§10.4): a deploy whose step list contains `prepare` is allowed. |
| D4 | **Static addresses only.** Every VM gets a static IPv4 address on one of the account's **networks** (subnet, gateway, DNS servers, an optional address pool Slipway picks from). All VMs of one environment use one account and one network. | A Slipway host is addressed by `hostname`; the data server's `{server.clients}` (P3 D18), Switchyard upstreams (`route_targets`, switchyard.py:268) and the poller assume it doesn't move. The data server's first deploy runs before the app VMs exist, so their addresses must be known then (Sirdar requires static for Blue/Green for the same reason, `SD/deploy/vms.py:153-178`). One network gives the three VMs one subnet and gateway, as Sirdar; Slipway can't check routing between networks. |
| D5 | **Proxmox through a bundled Terraform root module.** Slipway ships `slipway/terraform/proxmox-vm/` (static HCL, exact Terraform and `bpg/proxmox` versions) and writes only `terraform.tfvars.json` per VM, from the machine's frozen spec. One state per VM. Plans are read with `show -json`; a plan that deletes anything is refused unless the VM is half-made (D9) or the job is Remove. | Sirdar rendered `main.tf.json` in Python (`SD/deploy/terraform.py:82-119`). A static module can be read and reviewed as Terraform, and its variables are the only interface. One state per VM means a plan for green can never touch blue or the data server. The delete rule is Sirdar's (`SD/deploy/provision.py:356-369`), relaxed for Slipway's own half-made VM (D9). |
| D6 | **Terraform state lives in Slipway's database** (`terraform_states`, encrypted), with a working copy in `<storage_dir>/terraform/<machine id>/`. Before a run Slipway reconciles the two by lineage and serial; after every command that can write state it saves the state back in its own transaction. A lock column (compare-and-set on the deployment id), Terraform's own local lock in the working folder, and a PID file guard against two runs. | The state is the only record Terraform can destroy from ("Losing it means VMs must be removed by hand", `sirdar/docker-compose.yml:46-48`). The database already holds every other record of the VM (`machines`, `resources`, the host and its pin), so one database backup restores a consistent set; a state file in the files folder could be restored from another day than the rows that name its VM. Encryption with `SLIPWAY_ENCRYPTION_KEY` covers it in key rotation. The working copy stays on disk so a Terraform that outlived a crashed Slipway still holds its lock there. |
| D7 | **ESXi through pyvmomi, as Sirdar does it**: an empty VM with the owner marker and guestinfo cloud-init, the seed VM's single disk copied in thin, attached and grown, then powered on (`SD/deploy/esxi.py:331-352`, `SD/deploy/esxi_provision.py:342-422`). Standalone ESXi with a paid licence; vCenter is refused at Test. | Sirdar's path is tested (76 ESXi tests) and needs no template feature ESXi lacks. vCenter has templates and its own customisation, a different model (open question 9). |
| D8 | **No trust on first use for a VM.** Slipway learns the expected host key out of band, then pins it only after an SSH connection that presents exactly that key succeeds. Proxmox: the key is read through the guest agent's `file-read` over the pinned API (`SD/deploy/provision.py:393-419`). ESXi: Slipway generates the host key and hands it to cloud-init (`SD/deploy/cloudinit.py:75-93`); the private half is deleted from the VM's guestinfo and from Slipway's database once the pin is made. `check_host` never pins a provider host. | Sirdar's rule (`SD/deploy/vmcommon.py:174-203`). TOFU on a fresh VM's address would trust whatever answers there first. |
| D9 | **Half-made VMs are finished or rebuilt; made VMs are never rebuilt.** A machine is `planned`, `creating`, `booting` or `ready`. Before `ready` nothing of the app has run on it, so Slipway may delete and recreate its own half-made VM (identity checked first). Once `ready`, a VM that is gone or not Slipway's any more stops every step that needs it, with the way out spelled out. | Sirdar refuses to rebuild after `created` (`SD/deploy/provision.py:234-237`) but has no path past a failed first apply: Terraform marks the half-made VM tainted, the next plan is a replace, and `PLAN_DESTROYS` refuses it (`provision.py:65`, `356-369`), so the environment is stuck until deleted. Slipway's boundary is where data can first exist. |
| D10 | **Record before wait.** The Proxmox VM id is reserved by `machines.reserve_vmid` (§6.9) **before** Terraform runs: it records a `resources` row (`UNIQUE(provider, kind, provider_id)`) and counts an id as taken when any row holds it for another machine, in this environment or another, or when any machine's `ids.vmid` on the account holds it. ESXi's moref and instance UUID are recorded the moment `CreateVM_Task` answers; until then the VM is found again by its marker and name (E3). Each VM snapshot name, and each hypervisor task Slipway starts, is recorded before Slipway waits on it. Each write is its own committed transaction. | Sirdar's rule (`SD/deploy/vmcommon.py:68-72`), with its ESXi snapshot order for both providers: Proxmox recorded the name only after the task (`SD/deploy/provision.py:428-434`), so a task that outlived its wait left a snapshot Sirdar could neither list nor prune. P3's unique constraint replaces the `proxmox_vms_vmid_key` retry (`provision.py:163-171`). A bare `resources.record` isn't enough: for the same environment it updates the row it finds (services/resources.py, `record` and `_clash`), so green could take blue's reserved, unbuilt id and blue's row with it. |
| D11 | **VM snapshots are not backups.** They get their own table (`machine_snapshots`), their own jobs (`vm_snapshot`, `vm_revert`, `vm_drop`) and their own card. They exist only for an environment with **one app slot in data mode `slot` on a VM** (the VM holds the app and its data) whose storage can take them (D23). Blue/Green and data-server environments have none. | A P2 backup is an app-level dump that `accepts` can check, that moves between hosts, that seeds snapshots, and that restore puts back with the app running its own commands. A VM snapshot is the whole disk: code, data, Docker, the OS and Slipway's release folders and lock, kept on the hypervisor and gone with the VM. Reverting a data server VM under running slots breaks P3 I8; reverting an app slot VM leaves Slipway's records wrong. Sirdar takes none for Blue/Green and refuses to restore one there (`SD/deploy/vmsteps.py:47-49`, `66-68`). P3 §14: "VM snapshots get their own table". |
| D12 | **Resize applies in its own `resize` step of the slot's next deploy, never under traffic.** PATCH stores the wanted size. The deploy's `resize` step runs after `backup` and before `stop`/`start`, so every refusal of the deploy (resolve, manifest, settings, build, the database probe, the lag check) comes first. It ends by starting the live release again when the instance is RUNNING. It is never applied to the active slot of two (it waits until that slot is idle and deployed), nor to the data server once ready. Disks only grow. The VM is shut down cleanly first, on both providers. | Sirdar applies sizes in step 0 (`SD/deploy/vms.py:420-438`) and leaves the Blue/Green data VM as built (`SD/deploy/vmsteps.py:58-63`). Applying it in `prepare` would shut a single slot down for a deploy that then refuses (M9, P3 I5). Starting the live release afterwards keeps P2's rule that the old release runs until `start`, whatever the app's restart policy, and keeps an idle slot ready for Switch back. Sirdar left the Proxmox reboot behaviour to `bpg/proxmox` defaults, unproven (sirdar-vms §8); a shutdown first makes it the same on both providers, and cloud-init's growpart grows the root file system at the next boot. |
| D13 | **One snapshot before a resize, one before a revert, where the storage allows it.** A Proxmox resize takes a `pre_resize` VM snapshot first (it holds the old sizing). ESXi can't grow a disk that has snapshots, so a grow deletes Slipway's own snapshots (named in the dialog) and refuses any other; a cores or memory change on ESXi takes `pre_resize` too. A revert first takes `pre_revert`, so a revert can itself be reverted, except on storage that rolls back only to the newest snapshot (ZFS), where it is never taken and the dialog says the revert can't be undone. | Sirdar's orders (`SD/deploy/provision.py:238-245`, `SD/deploy/esxi_provision.py:281-299`, `458-477`). P2's rule "a copy before every change that replaces data" can't be met with a P2 backup here: it would live on the VM the revert rolls back. On ZFS a `pre_revert` would always be newer than the target, and Proxmox would then refuse the rollback (D23). |
| D14 | **Docker comes from Ubuntu's archive.** On a new VM, `prepare` waits for cloud-init, then installs `docker.io` and `docker-compose-v2` with `apt-get` through `sudo -n` when `docker compose version` fails, adds the `slipway` user to the `docker` group, creates the deploy root and reconnects. Nothing is downloaded from outside the distribution. | Sirdar ran `get.docker.com` as root on every Bootstrap (`SD/deploy/ansible/tasks/docker.yml:27-44`). Ubuntu's packages are signed by the archive's keys and need no script. Slipway needs Docker 20.10 or later with Compose v2 (`PULL_NEVER_UNSUPPORTED`, deployer.py), which Ubuntu 24.04's packages meet. A template with Docker already installed skips the install. |
| D15 | **Accounts are rows, not settings.** `provider_accounts` holds each Proxmox cluster or ESXi host Slipway may use (several of each), with its networks, its write-only secret and its pinned TLS certificate. The same table holds phase 4's DigitalOcean accounts (Decision 2). | Standalone ESXi means one account per host; P3's single `app_settings` rows (`switchyard`, `cloudflare`) fit one service each. Sirdar's credential rules carry over (`SD/deploy/integrations.py:45-52`): the secret is reused only while the target fields are unchanged, and the URL can't change or the account be removed while a machine uses it. |
| D16 | **The hypervisor API's certificate is pinned**, by fingerprint confirmed by a person (Sirdar's `tls_pin.py`, ported whole). Proxmox: an httpx transport and Terraform's `SSL_CERT_FILE` trust that certificate alone. ESXi: host-name checking off (its default certificate names `localhost.localdomain`), the pin and pyvmomi's thumbprint check on. | `SD/deploy/tls_pin.py:108-124`, `SD/deploy/terraform.py:159-181`, `SD/deploy/esxi.py:698-705`. Self-signed hypervisor certificates are the norm on a LAN. |
| D17 | **Secrets never leave Slipway's process except as Terraform's environment.** The Proxmox token reaches Terraform only as `PROXMOX_VE_API_TOKEN`, with an allowlisted environment; the ESXi password stays in-process. Both, and the token's secret part, are added to the job's redactor. | `SD/deploy/terraform.py:201-213`, `SR/README.md` (ESXi password "stays inside Sirdar's process"). |
| D18 | **A VM Slipway made belongs to one environment.** Only that environment's own members run on it. Every path that puts an instance on a host refuses it: `POST /instances` and a placement change, another environment's `POST /environments` with `hosts.<slot> = <host id>`, Add slot with `host_id`, and the unmanaged-instance claim. Editing its address (`hostname`, `proxy_address`, `lan_address`) or credentials, Check host before it is built, Reset host key and Delete host all answer 409. It goes with Remove slot or Delete environment. One helper, `hosts.owned_host_refusal(host, *, action)`, gives every one of these answers, for droplets too (Decision 7). | Its disk, address and keys are the environment's. An instance of anything else there would be destroyed with the environment without anyone deciding it. `proxy_address` and `lan_address` move Switchyard's upstream and `{server.clients}` and change M10's address checks, so they belong to the environment too. |
| D19 | **Deleting an environment destroys its VMs and the data on them.** When the data owner's host is a VM Slipway made, Delete takes a P2 snapshot first by default; skipping it needs `data:reset` and an explicit `drop_data` (one flag for the data's only home, a data VM here and a managed cluster in P4 §13; Decision 26). | P3's Delete keeps data volumes and backups on the data host (P3 §9.10 step 5). On a VM that is destroyed, nothing stays. A P2 snapshot lives on the Slipway server and seeds a new environment. |
| D20 | **Slipway's VMs carry Slipway's markers.** Proxmox: the name `slipway-<env>-<slot>`, tags `slipway` and `env-<environment id>`, the node it was made on, and a description naming the environment. ESXi: the name, extraConfig `slipway.machine=<machine id>` and `slipway.environment=<environment id>` (not `guestinfo.*`, so the guest can't change them), and an annotation. Every change re-reads the VM and checks them. | Sirdar's markers (`SD/deploy/terraform.py:92-94`, `SD/deploy/esxi.py:41-43`) with Slipway's names, so a Sirdar VM (tag `sirdar`) is never Slipway's during phase 6's overlap. Proxmox reuses free ids, so a recorded id alone proves nothing (`SD/deploy/provision.py:291-306`). |
| D21 | **No manifest additions.** | VM sizes, networks and templates are the operator's choices for one environment; the app already says what it runs (images, ports, data). ServerSherpa needs no change. |
| D22 | **New permission `machines:write`** (maintainer): create environments with VMs, resize them, take and delete VM snapshots, forget a lost VM. Revert needs `data:reset` as well and the environment's name typed. Accounts need `providers:write` (admin only) to change and `providers:read` to list, for every provider (Decision 4). | VMs spend hypervisor CPU, memory and storage that other systems share. Revert replaces data (P2's `data:reset` covers "restore old identity keys" and resets). |
| D23 | **Snapshot ability comes from the storage.** Each machine has a `snapshot_mode`: `any` (LVM-thin, Ceph RBD, qcow2 on a file storage, ESXi), `newest_only` (Proxmox `zfspool`) or `none` (thick LVM, raw files). Proxmox: Test records the storage's type in the account's `facts`; when the VM becomes ready, `prepare` asks Proxmox (`GET …/qemu/{vmid}/feature?feature=snapshot`) and combines the answer with the type. The module writes qcow2 disks on file storages so they can take snapshots. With `none`, the VM snapshots card is disabled with the reason and no `pre_resize` is taken. With `newest_only`, a revert is offered only to the newest snapshot on the VM. | Proxmox's ZFS plugin rolls back only to the newest snapshot (`ZFSPoolPlugin::volume_rollback_is_possible`: "can't rollback, '<snap>' is not most recent snapshot"), and `local-zfs` is the default storage of a ZFS install. Thick LVM and raw files take no snapshots at all. Checking up front keeps every refusal before a change (M9). |
| D24 | **Running hypervisor tasks are waited for, not killed.** Before any change to a VM, Slipway looks for a task still running on it (Proxmox: the VM's `lock` and the node's active tasks for that id; ESXi: `recentTask` in state `running`), its own or anyone's, and waits for it (10 minutes) or refuses. Each task Slipway starts is recorded in `machines.last_task` before the wait. On cancel or timeout Slipway stops only Terraform (SIGINT) and an ESXi disk copy (`CancelTask`); it never stops a snapshot, rollback, revert or delete task. | An asyncio cancel doesn't stop a server-side task, so a retry could delete a disk still being copied or snapshot during a rollback. Stopping a snapshot or rollback half-way leaves a locked VM and a half-made snapshot that only a person can clear (`qm unlock`, `delsnapshot --force`); waiting is safer, and those tasks are short. A disk copy is long, can be cancelled cleanly, and its partial file is deleted by E5's rule. |
| D25 | **Hidden and gone are told apart by `nextid`.** When `find_vm` doesn't see a recorded id, Slipway asks `GET /cluster/nextid?vmid=<id>`, which answers for any id whatever the token can see: free means gone, used means hidden (or taken by a VM outside the pool). | `/cluster/resources` lists only VMs the token can audit. Without this, a VM deleted by hand would block Delete for good, and an id used outside the pool would make every retry plan a create Proxmox refuses. |
| D26 | **Remove slot and Delete check that every VM can go before they change anything.** Their `check` step runs `describe` and the destroy preconditions of §7.7 and §8.5 for every machine involved; `machines.remove` checks them again. A retry may take `forget_vms: true` (typed name, `machines:write` + `environments:delete`), which forgets the machines the hypervisor can't account for after one more `describe`, and names them in the environment's notice for removal by hand. | Otherwise rows, routes and DNS go first and the machine then refuses, leaving a half-deleted environment that only a fix by hand can move. `forget_vms` mirrors P3's `forget_traffic` (P3 §9.10): the way past an outside system Slipway can't change. |
| D27 | **Slipway's container gets 60 seconds to stop** (`stop_grace_period: 60s` in `docker-compose.yml`). On shutdown the runner cancels jobs; Terraform gets SIGINT and 30 seconds to save its state; ESXi copies are cancelled. | Docker's default grace is 10 seconds, so a `docker compose stop` or an upgrade would SIGKILL Terraform before it saved its state, the most common way a clone is left half-made. |

---

## 1. Invariants

- **M1. Nothing changes for SSH hosts.** Instances, environments and jobs whose hosts have `provider = ssh` keep P3's step lists, refusals, `.env` bytes and Switchyard calls exactly. P3's golden tests stay green (test 64).
- **M2. Only what Slipway recorded, and only while it still carries the marker.** Slipway changes, snapshots, reverts or destroys a VM only when a `resources` row of the environment names it and the live VM has the D20 markers (and, on Proxmox, is on the recorded node). Anything else stops the step before any change.
- **M3. A ready VM is never rebuilt by itself.** A `ready` machine whose VM is gone or not Slipway's fails every step that needs it. Only Forget a lost VM (§9.10) or Delete moves past it, and only for app slots (data-holding VMs: Delete only).
- **M4. No host key is trusted on first use.** A provider host's key is written only by its provider's `prepare` (Decision 8); a VM host's `host_key` only by `machines.pin`, after an SSH connection that presents the key read through the guest agent (Proxmox) or generated by Slipway (ESXi). `check_host` and Reset host key never write one for a provider host.
- **M5. Record before wait.** Every hypervisor id, snapshot name and task Slipway starts is committed in its own transaction before Slipway waits on the hypervisor or Terraform, or is carried in a marker Slipway can find the VM by. ESXi's `CreateVM_Task` is the one wait before the id is known: its VM carries the `slipway.machine` marker and the machine's name, and E3 adopts it. The copied disk is found again by its fixed path, `<vm folder>/<vm>-disk0.vmdk` (E5, §8.5).
- **M6. Terraform deletes only in Remove, or Slipway's own half-made VM.** A plan with a `delete` action is refused in every other case, before `apply`. A half-made VM's identity is checked on the hypervisor first.
- **M7. One writer per state.** At most one Terraform process runs against a machine's state: the runner keys (one job per environment, P3 D8), the `terraform_states.lock_id` compare-and-set, Terraform's own lock in the working folder and the PID check (§7.3).
- **M8. Traffic-taking VMs are not rebooted by Slipway.** No resize, shutdown or revert of the active slot of two, or of a ready data server, is ever planned.
- **M9. Refuse before changing** (P3 I5). Every flow in §9 lists its refusals; each is checked before the first hypervisor write, Terraform `apply`, shutdown or SSH change. A deploy's refusals all come before its `resize` step (D12). Remove slot and Delete check every VM in `check`, before any row, route or name goes (D26). The one change before a deploy's own refusals is `prepare` making a planned or half-made VM (D3).
- **M10. One claim per address.** No two machines hold one address (`address_claims` primary key), and a VM is never pinned at an address another host row uses.
- **M11. Secrets stay out of argv, files and logs** (D17). The `.tfvars` file, the working folder and every log line are free of the token, password and host private key; the redactor hides them anyway.
- **M12. One task at a time on a VM.** No change to a VM starts while a hypervisor task runs on it (D24). Slipway waits for it, bounded, or refuses before the change.
- **M13. One machine per hypervisor id.** A VM id or UUID is recorded for at most one machine. A `vm` resource row's `details.machine_id` never changes (§6.9).

---

## 2. Concepts

| Term | Meaning |
|---|---|
| Account | A `provider_accounts` row: one Proxmox cluster (its API URL, node, pool, storage, template) or one ESXi host (URL, user, datastore, resource pool, seed VM), its secret, its pinned certificate and its networks. Phase 4's DigitalOcean accounts are rows of the same table. |
| Network | One entry of an account's `networks`: a name, the bridge and VLAN (Proxmox) or port group (ESXi), the subnet, gateway, DNS servers and an optional pool of addresses Slipway may pick from. |
| Machine | A VM Slipway makes for one slot (`blue`, `green` or `data`) of one environment: a `machines` row plus its `Host` row and, once it has a hypervisor id, its `resources` row. |
| Stage | `planned` (nothing on the hypervisor), `creating` (Slipway has started making it; the hypervisor may hold part of it), `booting` (it exists; Slipway waits for its address, pins its key, sets up Docker), `ready` (pinned and set up: from now on M3), `destroying` (Remove has started). |
| Half-made | A machine in `creating` or `booting`. |
| Lost | A `ready` machine whose VM the hypervisor doesn't have, or has without Slipway's markers. |
| VM snapshot | A disk-only hypervisor snapshot of a single-slot, mode `slot` environment's VM: `slipway-<YYYYMMDDTHHMMSSZ>`, reason `manual`, `pre_resize` or `pre_revert`. Not a P2 snapshot. |
| Wanted size, applied size | `machines.size` (what the person asked for) and `machines.applied` (what the hypervisor has). A difference is a pending resize. |
| Snapshot mode | `machines.snapshot_mode` (D23): `any`, `newest_only` (revert only to the newest snapshot, no `pre_revert`), `none` (no VM snapshots). NULL until the VM is ready. |
| Hidden | A recorded Proxmox id that `find_vm` doesn't see but `nextid?vmid` says is used (D25). |
| Busy | A VM with a hypervisor task still running (D24). |

Shapes with VMs (P3 §2's shapes, each slot host either an SSH host or a new VM):

| Shape | VMs Slipway makes | VM snapshots | Resize |
|---|---|---|---|
| Single, mode `slot` | `blue` | yes when `snapshot_mode` isn't `none` (§9.6-9.8) | at each deploy of blue (downtime, said in the dialog) |
| Single with a data server | `blue`, `data` | no | blue at its deploys; data never |
| Blue/Green | `blue`, `green`, `data` | no | the idle slot at its deploy; data never |

---

## 3. Data model and migration

New models live in two files, imported in `slipway/models/__init__.py` (Decision 2): `slipway/models/provider.py` (`ProviderAccount` and the enum of provider names `ProviderKind`: `digitalocean`, `proxmox`, `esxi`), which phase 4 uses too, and `slipway/models/machine.py` (`Machine`, `MachineSnapshot`, `TerraformState`, `AddressClaim`, enums `MachineStage`, `SnapshotReason`, `SnapshotMode`), which only VMs use. `MachineProvider` is only the protocol of §6.1.

### 3.1 `provider_accounts` (one table for the three providers)

The same table as P4 §3.1; phase 4's DigitalOcean accounts are rows of it too.

| column | type | notes |
|---|---|---|
| id, created_at, updated_at | UUIDPrimaryKey, Timestamps | |
| provider | String(16) NOT NULL | `proxmox`, `esxi` or `digitalocean`; `CHECK` in the three |
| name | String(64) NOT NULL UNIQUE | across every provider; shown everywhere; `^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`, checked in the service |
| production | Boolean NOT NULL default false | `CHECK (NOT production OR provider = 'digitalocean')`: always false here |
| config | JSON NOT NULL default `{}` | Proxmox `{url, node, pool, storage, template_vmid, token_id}`; ESXi `{url, user, datastore, resource_pool, source_vm}`; both `networks: [Network]`. DigitalOcean: P4 §3.1 |
| secret | EncryptedText NULL | Proxmox: the whole token `user@realm!tokenid=<uuid>`; ESXi: the password (DigitalOcean: the API token). Write-only |
| secret_hint | String(16) NOT NULL default `''` | Proxmox: the token id's last 4 characters; ESXi: `set` |
| tls | JSON NULL | `{pem, fingerprint_sha256, subject, issuer, not_after, sans, trusted_at, trusted_by}`: the pinned certificate; NULL until a person trusts one (always NULL for DigitalOcean) |
| status | String(16) NOT NULL default `unknown` | `unknown`, `ok`, `warning`, `error` from the last Test |
| checks | JSON NOT NULL default `[]` | the last Test's checks, `vmtypes.Check.to_dict()`: `[{name, ok, level, text}]` |
| facts | JSON NOT NULL default `{}` | what the last Test read, for rules that need it: Proxmox `{version, storage_type, storage_content, free_gb, template_ciupgrade}`; ESXi `{version, free_gb}` |
| last_checked_at | DateTime NULL | |
| removed_at | DateTime NULL | set when Remove keeps the row as a tombstone (§9.1) |
| created_by_id, updated_by_id | Uuid FK users SET NULL | |

`Network` (validated by `vmnet.check_network_profile`): `{name: ^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$ (unique in the account), bridge: str, vlan_tag: 1-4094 | null (Proxmox), port_group: str (ESXi), subnet: "a.b.c.d/nn" (prefix 8-30, canonical), gateway: IPv4 in subnet, not its network or broadcast address, dns_servers: [IPv4] (0-3, canonical; empty means the gateway), pool: {first, last} | null (inside the subnet, first ≤ last, excluding gateway, network and broadcast)}`. The name rules for bridge, storage, node, pool and port group are Sirdar's (`SD/deploy/integrations.py:70-85`).

### 3.2 `machines` (VMs only)

| column | type | notes |
|---|---|---|
| id, timestamps | | |
| environment_id | Uuid FK environments RESTRICT, index | |
| host_id | Uuid FK hosts RESTRICT, UNIQUE | the planned or made host |
| account_id | Uuid FK provider_accounts RESTRICT | an account can't be deleted while a machine uses it |
| provider | String(16) NOT NULL | copy of the account's: `proxmox` or `esxi` (a droplet is never a machine, Decision 1) |
| slot | String(8) NOT NULL | `blue`, `green`, `data` |
| name | String(63) NOT NULL | the VM's name and guest host name: `slipway-<env>-<slot>` (§5) |
| stage | String(16) NOT NULL default `planned` | §2 |
| spec | JSON NOT NULL | frozen at create from the account: Proxmox `{node, pool, storage, storage_type, file_format, template_vmid, bridge, vlan_tag}` (`storage_type` from the last Test's `facts`); ESXi `{api_host, datastore, resource_pool, source_vm, port_group}` |
| network | JSON NOT NULL | frozen: `{name, address, prefix, gateway, dns_servers}` |
| size | JSON NOT NULL | wanted `{cores, memory_mb, disk_gb}` |
| applied | JSON NULL | what the hypervisor has: `{cores, memory_mb, disk_gb, at, deployment_id}` |
| ids | JSON NOT NULL default `{}` | Proxmox `{vmid}`; ESXi `{moref, instance_uuid, vm_path}` |
| host_key_public | Text NULL | the expected key: ESXi from create; Proxmox once read through the agent |
| host_key_private | EncryptedText NULL | ESXi only; NULL after the scrub (§8.2 step E9) |
| keep_vm_snapshots | Integer NOT NULL default 3 | automatic VM snapshots kept (1-10) |
| snapshot_mode | String(12) NULL | `any`, `newest_only`, `none` (D23); set when the VM becomes ready |
| last_task | JSON NULL | the hypervisor task Slipway last started on the VM: `{id, kind, started_at, deployment_id}` (a Proxmox UPID or an ESXi task moref); written before the wait (M5), cleared when it ends |
| last_error | String(500) NULL | the last `prepare` or `resize` failure, for the page |
| ready_at | DateTime NULL | |
| created_by_id | Uuid FK users SET NULL | |

Constraints: `UniqueConstraint(account_id, name)`, `UniqueConstraint(environment_id, slot)`, `CHECK (provider IN ('proxmox','esxi'))`, `CHECK (stage IN ('planned','creating','booting','ready','destroying'))`, `CHECK (stage <> 'ready' OR ready_at IS NOT NULL)`, `CHECK (snapshot_mode IS NULL OR snapshot_mode IN ('any','newest_only','none'))`.

The `Host` row of a machine (P3 §3.5 columns plus phase 4's `provider_state`, P4 §3.3), from `hosts.planned_host(...)` (Decision 9): `name = "slipway-<env>-<slot>"` (the VM name; `vmnet.host_row_name` returns `vmnet.vm_name`), `hostname = network.address`, `port = 22`, `username = slipway` (`cloudinit.GUEST_USER`), `label = <env>`, `description = "VM Slipway made for <env>'s <slot> slot on <account>"`, `auth_method = key`, `private_key` and `public_key` from `ssh.generate_keypair("slipway@<vm name>")` (ssh.py:239), `host_key = NULL`, `provider_state = {phase: planned}`, `provider`, `provider_id` (the resource's provider id once known), `owner_environment_id`, `deploy_root` default.

The `resources` row (P3 §3.4) is written when the hypervisor id exists: `provider` the account's, `kind = vm`, `provider_id = "<account id>:<vmid>"` (Proxmox) or `"<account id>:<instance uuid>"` (ESXi), `name` the VM name, `origin = created`, `instance_id` the slot instance, `details = {machine_id, node | moref}`. Both providers' ids are only unique within an account, so the account id is part of the provider id. Machines write it only through `machines.reserve_vmid` and `machines.record_vm` (§6.9), never through a bare `resources.record`, so a row's `details.machine_id` never changes (M13).

### 3.3 `machine_snapshots`

| column | type | notes |
|---|---|---|
| id, timestamps | | |
| machine_id | Uuid FK machines CASCADE, index | |
| name | String(40) NOT NULL | `slipway-YYYYMMDDTHHMMSSZ` (Proxmox names: a letter first, `[A-Za-z0-9_-]`, at most 40) |
| reason | String(16) NOT NULL | `manual`, `pre_resize`, `pre_revert` |
| status | String(16) NOT NULL default `pending` | `pending` (recorded, task running), `ready`, `missing` (the hypervisor doesn't have it), `failed` |
| deployment_id | Uuid FK deployments SET NULL | the job that took it |
| commit_sha | String(40) NULL | the instance's live commit then |
| app_state | JSON NULL | a copy of the instance's `app_state` then |
| fresh_data | String(8) NULL | the instance's then |
| identity | EncryptedJSON NULL | the data's identity values then (as `Backup.identity`) |
| identity_fp | String(64) NOT NULL | as `Backup.identity_fp` |
| backups | JSON NOT NULL default `[]` | names of the P2 backups on the VM then |
| sizes | JSON NOT NULL | the applied size then |
| quiesced | Boolean NULL | ESXi: whether VMware Tools quiesced; Proxmox NULL |
| note | String(300) NULL | |
| taken_at | DateTime NOT NULL | |
| created_by_id | Uuid FK users SET NULL | |

`UniqueConstraint(machine_id, name)`.

### 3.4 `terraform_states`

| column | type | notes |
|---|---|---|
| machine_id | Uuid PK, FK machines RESTRICT | one state per VM |
| lineage | String(64) NULL | Terraform's, from the first state written; NULL until the first save |
| serial | Integer NOT NULL default 0 | |
| sha256 | String(64) NULL | of the state bytes |
| state | EncryptedText NULL | the whole `terraform.tfstate` (at most 4 MiB, else the save fails the step) |
| lock_id | Uuid NULL | the deployment running Terraform (no foreign key: the deployment row may be gone, §7.3 step 1) |
| locked_at | DateTime NULL | |
| module_sha | String(64) NULL | the bundled module's hash at the last apply |
| terraform_version | String(16) NULL | |

RESTRICT: a machine row is deleted only after its state row, which Remove deletes once the VM is confirmed gone.

### 3.5 `address_claims`

| column | type | notes |
|---|---|---|
| address | String(45) PK | the IPv4 literal |
| host_id | Uuid FK hosts CASCADE, UNIQUE | the planned or made host |
| created_at | DateTime NOT NULL | |

Inserted in the same transaction as the host. The primary key is the lock: two environments picking one address can't both commit (SQLite and PostgreSQL alike, where Sirdar used `pg_advisory_xact_lock`, `SD/deploy/vms.py:230-234`). Deleted with the host.

### 3.6 `deployments` and `instances`

- `DeploymentKind` (instance.py:49-65) gains `vm_snapshot`, `vm_revert`, `vm_drop` (each fits `String(16)`; phase 4 adds `certificate` and `deactivate`). They run on the slot instance (the data owner, P3 D3) with `environment_id` set.
- `options` gains: `vm_snapshot_id` (revert, drop), `skip_pre_revert` (revert), `vm_snapshot_pre` (revert: the `pre_revert` row of the first attempt), `note` (snapshot), `resize` (deploy: the size the `resize` step applied, for the log and retry), `drop_data` (teardown; the flag P4 §13 uses for managed data, Decision 26), `forget_vms` (a retry of `remove_slot` or `teardown`, D26).
- Phase 5 adds no column to `instances` or `hosts`. It uses phase 4's `hosts.provider_state` (migration 0010, P4 §3.3): **`hosts.provider_state.phase` is written with every stage change**, in the same transaction, through `hosts.set_phase` (Decision 6): `planned` → `planned`, `creating` and `booting` → `creating`, `ready` → `ready`, `destroying` → `gone`. So `Host.is_built` is true exactly for a `ready` machine's host, and `SSHTarget.from_host` raises `HostNotBuilt` for every other one unless the caller is the `prepare` driver (`building=True`).

### 3.7 Settings (`slipway/core/config.py`, not changed by P3)

| setting | default | notes |
|---|---|---|
| `terraform_binary` | `terraform` | an absolute path or a name on `PATH` |
| `terraform_cli_config` | `/etc/slipway/terraformrc` | the image's mirror-only config (§13) |
| `terraform_dir` | `<storage_dir>/terraform` | working folders, mode 700 (storage_dir is config.py:78) |
| `terraform_parallel` | 2 (1-8) | Terraform processes at once across Slipway |
| `vm_address_probe` | true | the TCP probe of §7.4; tests patch the probe itself |

### 3.8 Migrations

Three linear revisions after phase 3's `0009`, all written by slice S03 (Decision 5), each unconditional (no "create what is missing"), patterns as P3 §3.7, with NAMING_CONVENTION names:

1. **`20261118_0010_provider_accounts.py`** (`revision='0010'`, `down_revision='0009'`): `provider_accounts` (§3.1) and `hosts.provider_state` (P4 §3.3), the provider core both phases use. Its downgrade refuses while `provider_accounts` has rows or any host has `provider <> 'ssh'` (`Remove the DigitalOcean, Proxmox and ESXi accounts first`).
2. **`20261118_0011_digitalocean.py`** (`revision='0011'`, `down_revision='0010'`): phase 4's columns and the `acme` row (P4 §3.10).
3. **`20261118_0012_machines.py`** (`revision='0012'`, `down_revision='0011'`): `machines` (§3.2, with `CHECK (provider IN ('proxmox','esxi'))`), `address_claims`, `terraform_states`, `machine_snapshots` (§3.3-3.5).

**Upgrade (0012):** create `machines`, `address_claims`, `terraform_states`, `machine_snapshots`.

**Downgrade (0012):** refuses while `machines` has rows (`Delete the environments with Proxmox or ESXi VMs first (still here: <names>)`); `deployments` rows of the VM kinds are deleted first; drops the four tables in reverse order. `tests/test_migration_0012.py` also runs `alembic check` at head (models equal migrations), moved there from `tests/test_migration_0009.py`.

### 3.9 Key rotation (`slipway/cli.py` `rotate-encryption-key`)

The walk over `encrypted_columns(Base.metadata)` picks up `provider_accounts.secret`, `backups.data_key` (phase 4), `machines.host_key_private`, `machine_snapshots.identity` and `terraform_states.state`, and updates each table by its own primary key (`terraform_states` has `machine_id`, not `id`; Decision 32). An unreadable `provider_accounts.secret` is set to NULL by `--clear-unreadable` (it is not one of the re-enter columns, which would store an encrypted `null` that reads as set), and the account gets `status = error` and one error check asking for it again (`The token couldn't be read after a key change: enter it again`; for ESXi, the password). `--clear-unreadable` **refuses** when a `terraform_states.state` can't be read: `Slipway can't read the Terraform state of <vm> with any key in SLIPWAY_ENCRYPTION_KEY. Put the old key back first; without the state Slipway can't remove the VM`. An unreadable `host_key_private` on a machine that isn't `ready` is cleared; the next `prepare` makes a new pair and, by E1's rules (§8.2), either just uses it (no VM yet), rewrites the VM's user-data (a VM never powered on) or makes the half-made VM again (one that may have booted with the old key). On a `ready` machine it is already NULL. `--clear-unreadable` never erases the SSH key of a host an environment made (`hosts.private_key` with `owner_environment_id` set: a droplet or a VM; the host page refuses credentials on such a host, so it couldn't be entered again). It keeps the value as it is, still readable with the old key, lists the host (`Kept the SSH key of <n> host(s) Slipway made, which no configured key can read: ... Put the old key back after the new one in SLIPWAY_ENCRYPTION_KEY and run this again to re-encrypt it; until then Slipway can't reach them:` and the names), and goes ahead with the rest of the rotation and its fix-ups, so one lost host key doesn't block them for the whole install. A hand-added host's key is still cleared, as in phase 3. While the old key stays lost, such a host's environment can't run anything over SSH; a production one that held data can't take the snapshot its Delete needs, so it stays until the key is found or the operator removes its cloud objects by hand. Connecting to such a host with no readable key fails with `ssh.OWNED_KEY_UNREADABLE`, which asks for the old key rather than pointing at the host page. A `machine_snapshots.identity` it erases makes the row `failed` (`Marked <n> VM snapshot(s) failed; their identity values were lost, so they can't be reverted to. Delete them on the environment's page:` and the names); a later `describe` doesn't make it `ready` again.

---

## 4. Permissions and audit

### 4.1 Permissions (`Perm`, core/permissions.py)

| Perm | Description | Roles |
|---|---|---|
| `machines:write` | Make VMs on Proxmox and ESXi for environments, resize them, take and delete VM snapshots, forget a lost VM (privileged: VMs use the hypervisor's CPU, memory and storage) | maintainer |

Phase 4's `providers:read` (developer, maintainer), `providers:write` (admin only) and `providers:spend` (maintainer) are added in the same edit of `core/permissions.py` (Decision 4; P4 §4.1); the account rules below use the first two for every provider.

Who needs what (additions to P3 §4.1):

| Action | Permission(s) |
|---|---|
| Add, edit, trust, test or remove a Proxmox or ESXi account | `providers:write` (admin only) |
| List accounts and their networks and free addresses (the create flow) | `providers:read` |
| Create an environment with new VMs; add a slot on a new VM | P3's + `machines:write` |
| Deploy to a VM slot (its `prepare` may make the VM; its `resize` step may apply a stored resize) | P3's (`deployments:create`, …); the resize was approved by whoever stored it |
| Change a VM's wanted size or `keep_vm_snapshots` | `machines:write` |
| Take or delete a VM snapshot | `machines:write` |
| Revert to a VM snapshot | `machines:write` + `data:reset`, environment name typed |
| Forget a lost VM | `machines:write` + `environments:delete`, environment name typed |
| Delete an environment whose data is on a VM, without a snapshot | P3's + `data:reset` and `drop_data: true` |
| Retry | the kind's own, from `data.RETRY_PERMISSION` and `RETRY_EXTRA` (Decision 37): `vm_snapshot`/`vm_drop` `machines:write`; `vm_revert` `machines:write` + `data:reset`, with the instance's name typed again |
| Retry `remove_slot` or `teardown` with `forget_vms: true` | P3's retry permission + `machines:write` + `environments:delete`, environment name typed |

`SYSTEM_ROLES` re-sync at startup gives existing installs the permission (users.py).

### 4.2 Audit actions (`audit.record`)

Never secrets, tokens, passwords, private keys or identity values.

| Action | Details |
|---|---|
| `provider_account.create`, `.update`, `.delete` | provider, name, changed fields (names only for the secret: "token replaced"); one set for every provider (P4 §4.2) |
| `provider_account.test` | name, the check results (no values) |
| `provider_account.trust` | name, fingerprint, subject, not_after |
| `machine.plan` | environment, slot, account, network, address, size |
| `machine.reserve` | vmid or instance uuid |
| `machine.create` | name, ids |
| `machine.adopt` | an ESXi VM found by its markers after a lost record |
| `machine.rebuild` | a half-made VM deleted to be made again, and why |
| `host.key_pinned` (existing) | + `how`: `read through the Proxmox guest agent` / `generated by Slipway` |
| `machine.ready` | name, address, applied size |
| `machine.resize` | from, to, the deployment |
| `machine.left_off` | a VM left off or stopped by a cut-off or failed resize (§9.12) |
| `machine.snapshot`, `machine.snapshot_delete` | name, reason |
| `machine.revert` | snapshot name, its time and commit, identity restored (yes/no) |
| `machine.destroy` | name, ids |
| `machine.forget` | name, ids, why: `lost` (§9.10) or `forget_vms` with the refusal it got past (D26) |

---

## 5. Names, sizes and networks

No manifest additions (D21).

**Names.** VM name and guest host name: `slipway-<env>-<slot>` (`<env>` is P3's 2-26 characters, so at most 40 characters, a DNS label). Checked by `vmnet.check_vm_name` (`^slipway-[a-z][a-z0-9-]{0,24}[a-z0-9]-(blue|green|data)$`) before it reaches Terraform or cloud-init, for both providers (Sirdar checked only ESXi's, sirdar-vms §14.3). Host row name: the VM name `slipway-<env>-<slot>` too (`vmnet.host_row_name` returns `vmnet.vm_name`; a droplet's host row is named the same way, Decision 9), unique among hosts; a clash refuses create with `A host named <x> already exists: rename it, or pick another environment name`.

**Sizes.** `cores` 1-64, `memory_mb` 2048-262144, `disk_gb` 20-4096, `keep_vm_snapshots` 1-10 (Sirdar's `DEFAULTS` and `LIMITS`, `SD/deploy/vms.py:32-35`). Defaults 4 cores, 8192 MB, 64 GB for every VM, the data server included. Disks never shrink. Create's `?check=true` warns (never refuses) when the account's last Test found less free storage than the sum of the new disks.

**Networks.** An environment's new VMs share one account and one network (D4). Each VM's address is either typed (`10.0.0.12`, the prefix comes from the network) or `auto`: the lowest pool address that is free by §6.6 at create time. A typed address must be inside the network's subnet and pass `vmnet.check_address` (not the network, broadcast, multicast, link-local, reserved, 0/8 or loopback address; not the gateway; loopback only with the test switch `vmnet.ALLOW_LOOPBACK`, as `SD/deploy/vms.py:107-136`). DNS servers come from the network (empty: the gateway, as `SD/deploy/cloudinit.py:53-72`); Proxmox now gets them too, through the module's `initialization.dns` (sirdar-vms §14.3).

---

## 6. The machines core

Phase 5's own: droplets don't use it (Decision 1). It plugs into the host-level contract both phases share (P4 §3.3): every stage change writes `hosts.provider_state.phase` (§3.6), `hosts.check_host` and `SSHTarget.from_host` take `building=True` only from `machines.prepare`, and the owned-host and address-holder checks are `hosts.owned_host_refusal` and `hosts.address_holder`.

### 6.1 The interface (`slipway/services/machines.py`, `slipway/services/providers/`)

```python
@dataclass
class MachineContext:
    machine: Machine; host: Host; account: ProviderAccount; env: Environment
    deployment_id: uuid.UUID | None; user_id: uuid.UUID | None
    say: Log; hide: ssh.Redactor; connect: ConnectFactory
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    now: Callable[[], datetime] = utcnow

@dataclass
class Ensured:
    address: str                          # where the VM answers
    expected_key: str                     # the OpenSSH public host key to pin
    how: str                              # "read through the Proxmox guest agent" | "generated by Slipway"
    reread_key: Callable[[], Awaitable[str]] | None   # Proxmox while booting: read the key again (§6.4)
    warnings: list[str]

@dataclass
class ResizePlan:                         # what check_resize found; resize applies exactly this
    to: dict; snapshot_first: bool; drop_snapshots: list[str]; changes: list[str]

@dataclass
class MachineState:                       # read-only view for pages and refusals
    exists: bool; ours: bool; why_not_ours: str | None
    hidden: bool                          # Proxmox: recorded id used but not visible (D25)
    power: str | None                     # running | stopped | suspended
    busy: str | None                      # a running task: "snapshot (started 10:02)" (D24)
    addresses: list[str]; applied: dict | None
    snapshot_mode: str | None             # D23
    snapshots: list[SnapshotView]         # name, id, created, ours (recorded), newest
    error: str | None                     # "busy" or why the account couldn't be read

class MachineProvider(Protocol):
    name: ClassVar[str]                                           # proxmox | esxi
    def clean_config(self, config: dict, secret: str | None) -> dict   # delegates to the client module (A3, A5)
    async def test(self, account: ProviderAccount) -> list[Check]      # not used for accounts (below)
    def freeze(self, account: ProviderAccount, network: dict) -> dict  # machines.spec at create
    async def ensure(self, ctx: MachineContext) -> Ensured        # make, continue, start; never resizes
    async def after_pin(self, ctx: MachineContext) -> None        # ESXi: scrub the user-data; others: nothing
    async def describe(self, ctx: MachineContext) -> MachineState # reads only
    async def check_resize(self, ctx) -> ResizePlan               # reads only; MachineError when it can't go
    async def resize(self, ctx, plan: ResizePlan) -> dict         # the applied size; leaves the VM running
    async def snapshot(self, ctx, row: MachineSnapshot) -> bool   # True when quiesced (ESXi)
    async def revert(self, ctx, row: MachineSnapshot) -> None
    async def drop_snapshot(self, ctx, row: MachineSnapshot) -> None
    async def stop(self, ctx, *, timeout: int) -> None            # clean shutdown, or MachineError
    async def destroy_blockers(self, ctx) -> list[Blocker]        # reads only; [] when destroy may go
    async def destroy(self, ctx) -> list[str]                     # idempotent; what it did, for the log

PROVIDERS: dict[str, MachineProvider] = {"proxmox": ProxmoxProvider(), "esxi": EsxiProvider()}
```

`slipway/services/providers/__init__.py` resolves each provider lazily (`provider_for(kind)`), so pyvmomi stays optional and a provider not built yet answers `MachineError("This Slipway has no <Proxmox|ESXi> provider yet")`. Accounts are tested through the client modules as built, not through `MachineProvider.test` (Decision 34): `proxmox.run_test` returns `TestResult(checks, facts)`, `esxi.run_test` returns `list[Check]` and writes `account.facts`, and `provider_accounts` normalises both into `{status, checks, facts}`.

`Blocker(text, forgettable)`: `forgettable` is true when `forget_vms` may get past it (D26: hidden, unreachable or unusable account, marker gone, a disk Slipway didn't put there); false when the cause is Slipway's own and passing would leave a record wrong (a running task, a Terraform lock held by a live process).

Every provider error is a `MachineError(text)` carrying Slipway's own sentence, never the upstream text (Sirdar's rule, `SD/deploy/proxmox.py:131-146`, `SD/deploy/esxi.py:199-242`). The deployer turns it into a step failure. `MachineError`, `AccountInvalid(field, text)`, `Check` and `Blocker` live in `slipway/services/vmtypes.py` (A2), so the clients (A3, A5) and the accounts service (S08) use them without the providers.

Shared helpers in `machines.py`, used by both VM providers: `plan(db, env, slot, account, network, address, size, user) -> (Host, Machine)` (§6.2), `prepare(ctx) -> None` (§6.3), `pin(...)` (§6.4), `bootstrap(...)` (§6.5), `addresses_in_use(db, ...)` and `claim(...)` (§6.6), `resize_step(ctx)` (§6.7), `tasks.wait_idle(...)` (§6.8), `reserve_vmid(...)` and `record_vm(...)` (§6.9), `blockers(ctx)` and `remove(ctx, forget=False)` (§9.5, §9.9), `lost_text(machine)`, `stage_of(host) -> str | None`, `recover_prepare(db, deployment)` (§9.12). The owned-host refusal of D18 is `hosts.owned_host_refusal(host, *, action) -> str | None`, one helper for droplets and VMs (Decision 7).

### 6.2 Planning (`machines.plan`)

Called inside P3's create and Add slot transactions, in the caller's transaction; touches no hypervisor.
1. `vmnet.check_vm_name(name)`; the host name `slipway-<env>-<slot>` free among hosts (`A host named <x> already exists: rename it, or pick another environment name`).
2. The address: typed, or `auto` from the pool (§5). §6.6's registry says it is free.
3. Writes the `Host` row (§3.2, from `hosts.planned_host(..., provider, hostname=<static address>, description=…)` with `owner_environment_id` set), the `AddressClaim`, and the `Machine` (`stage = planned`, `spec = provider.freeze(account, network)`, `network`, `size`). ESXi: an ed25519 host key pair (`asyncssh.generate_private_key("ssh-ed25519")`, as `SD/deploy/vms.py:188-194`) into `host_key_public` and `host_key_private`.
4. Audit `machine.plan`.

`services/environments.create` writes in the caller's transaction and the API commits (`api/v1/environments.py`), so an `IntegrityError` on the claim's unique constraint (the name NAMING_CONVENTION gives it) surfaces at that commit. The service half leaves nothing written after the rollback; the API catches it around the commit of create and of Add slot and answers 409 `<address> was just taken by another environment: pick another address` with field `hosts.<slot>.machine.address` (Decision 43; every other database error stays a 500). The address named is the one taken (`environments.claim_conflict`): PostgreSQL's detail `Key (address)=(<address>)` (asyncpg keeps it in the error's `detail`, apart from the message) matched exactly, never a prefix of another planned address; when the error doesn't carry it (SQLite), the claims are read again after the rollback and the first planned address another host now holds is named.

### 6.3 The prepare driver (`machines.prepare`)

Runs as the `prepare` step (§10.3), right after `resolve` (Decision 12). It makes, continues or checks the VM. It never stops a made VM and never resizes (D3, D12). In order:
1. Loads the account; refuses when its secret or pinned certificate is missing or unreadable (`Proxmox account <a> can't be used: <why>. Fix it in Settings → Integrations, then retry.`). On a `ready` machine with no resize to apply, this is the warning of the last paragraph instead.
2. `ensured = await provider.ensure(ctx)` (§7.4, §8.2). Each stage change (`creating`, `booting`) is written in its own transaction when the provider reaches it, with `hosts.provider_state.phase` in the same transaction (§3.6). Before any change to an existing VM, `tasks.wait_idle` (§6.8).
3. When the host is unpinned, or `ensured.expected_key` differs from `host.host_key`: `pin(...)` (§6.4), then `provider.after_pin(ctx)`. A pinned host whose key is unchanged needs nothing more: the deploy's own SSH connection checks it.
4. When the stage isn't `ready`: `bootstrap(...)` (§6.5), then `hosts.check_host(db, host, building=True)` (hosts.py:33-87; the host isn't built yet, so only the `prepare` driver may pass `building=True`, and `check_host` never pins a provider host) to fill Docker's version, the OS and metrics, then `snapshot_mode` from `describe` (D23), then in one transaction `stage = ready` (phase `ready`), `ready_at`, `applied`, `snapshot_mode`, `last_error = NULL`; audit `machine.ready`.
5. When the job lists a `resize` step (§9.4's rule held at queue time) and `size != applied`: `provider.check_resize(ctx)`, which reads only. A refusal fails the step here, before `source`, with its text and `To deploy without the resize, set <vm>'s size back to <applied> on the environment page`. The plan is not kept: `resize` checks again.

Each part has its own time limit (§14). The step's overall limit is their sum, 120 minutes; when a part runs out, the step's error names it (`Timed out after 25 minutes installing Docker on <vm>`).

On a `ready` machine with nothing to resize, when the hypervisor API can't be reached, the step ends as `warning` (`Couldn't reach Proxmox to check <vm>; carrying on over SSH`) and the deploy continues: SSH with the pinned key is the real check, and a deploy shouldn't depend on the hypervisor's API being up. With a resize to apply, an unreachable API fails the step (`Slipway can't reach <account> to resize <vm>`). Any other failure fails the step; `last_error` keeps its text.

### 6.4 Pinning (`machines.pin`)

`pin(db, host, *, address, expected_key, how, connect, tries, poll, sleep) -> None`:
1. Refuses when another host row (not this one) holds the address: `hosts.address_holder(db, address, except_host_id=host.id)`, the one check droplets use too (Decision 8), over `hostname`, `proxy_address` and `lan_address`: `<address> is the address of host <name>; Slipway won't pin a VM's key there` (Sirdar's rule, `SD/deploy/vmcommon.py:216-218`). The SSH port is `machines.SSH_PORT` (22), which test 18 points at its server.
2. Up to `tries` times: `connect(SSHTarget(hostname=address, port=22, username=slipway, private_key=host.private_key, pinned_host_key=expected_key))` (the target `SSHTarget.from_host(host, building=True)` gives, with the expected key pinned), then `true`. `HostKeyMismatch` fails at once (`The VM at <address> answered SSH with a key that isn't the one <how>. Slipway pinned nothing.`), except when `ensured.reread_key` is set (a Proxmox VM still `booting`): then the key is read again through the agent, `machines.host_key_public` updated if it changed, and the loop goes on, within the same time limit. The agent's file is the out-of-band truth, so reading it again trusts nothing new; it covers a template's old key that cloud-init's `cc_ssh` hasn't replaced yet. A refused or timed-out connection, or "authentication failed" while cloud-init may still be creating the user, sleeps `poll` and tries again. After the last try: `<vm> didn't answer SSH at <address> in <n> minutes` (or, after mismatches, the mismatch text).
3. Compare-and-set, as `check_host` does (hosts.py:57-71): `UPDATE hosts SET host_key, host_key_fingerprint WHERE id = :id AND hostname = :address AND port = 22 AND (host_key IS NULL OR host_key = :expected)`. Rowcount 0: `<host> changed while Slipway was pinning it; Slipway pinned nothing`. Audit `host.key_pinned` with `how`.

Tests reach a real asyncssh server on 127.0.0.1 with `vmnet.ALLOW_LOOPBACK` (test 18); everywhere else `connect` is the fake hosts factory (P3 §16.1 `MultiRemote`), which checks the target's pinned key against the fake VM's own key.

### 6.5 Bootstrap (`machines.bootstrap`)

Over an SSH session with the pinned key, each command with its own timeout, every root command through `sudo -n` (cloud-init gives the `slipway` user, `cloudinit.GUEST_USER`, passwordless sudo: Proxmox through cloud-init's `ciuser` taking over the Ubuntu cloud image's default user, ESXi through Slipway's user-data, `sudo: ALL=(ALL) NOPASSWD:ALL`; droplets have no sudo, P4 D24):

| part | command | timeout | refusal |
|---|---|---|---|
| sudo | `sudo -n true` | 30 s | `<vm>'s slipway user can't use sudo without a password; check the template's cloud-init` |
| cloud-init | `cloud-init status --wait` (exit 0 or 2 accepted) | 10 min | `cloud-init didn't finish on <vm> in 10 minutes` |
| Docker | `docker compose version >/dev/null 2>&1 \|\| { sudo -n apt-get -o DPkg::Lock::Timeout=600 update -q && sudo -n env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -q docker.io docker-compose-v2; }` | 25 min | the apt output's last line: `Couldn't install Docker on <vm>: …`; a lock still held after 10 minutes: `Something on <vm> (usually unattended-upgrades) held the package lock for 10 minutes; retry the deploy` |
| service | `sudo -n systemctl enable --now docker` | 2 min | |
| group | `id -nG slipway \| grep -qw docker \|\| sudo -n usermod -aG docker slipway`, then a new SSH session | 1 min | |
| folder | `sudo -n install -d -o slipway -g slipway -m 0755 <deploy_root>` | 30 s | |
| check | `docker info --format '{{.ServerVersion}}'` in the new session | 1 min | `Docker on <vm> doesn't answer for the slipway user` |

Every part is safe to run again, so a retry after a cut-off starts over. Bootstrap runs only until the machine is `ready`; a later Docker problem shows in the deploy as on any host.

On a fresh Ubuntu 24.04 VM, `apt-daily` and `unattended-upgrades` start at boot and hold the dpkg lock for minutes; `cloud-init status --wait` doesn't wait for them, hence `DPkg::Lock::Timeout` (apt 1.9.11 and later; 24.04 has 2.7). The image needs a reachable Ubuntu mirror; docs/machines.md says so, and says to set the Proxmox template's `ciupgrade 0` so cloud-init doesn't upgrade every package on the first boot (§7.1's Test warns when it is on).

### 6.7 The resize step (`machines.resize_step`)

Runs as the `resize` step of an app slot's deploy (§10.3), listed when §9.4's rule holds at queue time. It comes after `backup` and before `stop`/`start`, so every refusal of the deploy is already behind it (D12).
1. §9.4's rule again (the slot may have become active meanwhile: the step is `skipped`, `<blue> takes the traffic now; the resize waits`). `size == applied`: `skipped`.
2. `tasks.wait_idle` (§6.8); `plan = provider.check_resize(ctx)` (the read-only checks again).
3. `provider.resize(ctx, plan)` (§7.5, §8.3). It shuts the VM down, resizes it and starts it, then checks the address and the pinned key.
4. When the instance is RUNNING: the live release's projects started (`docker compose start`, as the control action, under the instance's lock), so the old release runs until `start` replaces it, as P2 expects, and an idle slot stays ready for Switch back. A failure here fails the step: `<vm> is resized, but <slot>'s live release didn't start: <error>`.
5. `applied` written with the deployment id; `options.resize` set; audit `machine.resize`; the step's note says `Resized to 4 vCPU, 8 GB, 80 GB`.

A failure in step 3 after the shutdown leaves the VM as the provider says (Proxmox: started again at the old size when possible; ESXi: off, §8.3 step 3); Slipway then sets the environment's notice (`<vm> was left off during a resize: deploy to <slot> again to finish it`) and audits `machine.left_off`. A step cut off part way (its time limit, or Slipway stopping) is handled the same way, shielded from the cancel: Proxmox starts the VM again, and a VM `describe` doesn't report running gets the notice and `machine.left_off`, with `last_error` `The resize of <vm> was cut off before it finished`. After any failure or cut-off, `applied` takes the size `describe` reads when it differs from the old one, so a resize that went through isn't done again. A cut-off also marks the deployment's `pre_resize` row failed while it is still `pending` (`machines._cut_pre_resize`, as `_VmRun.take` does), so Delete, Revert and prune don't treat it as still being taken; the next VM job's settle makes it ready if the snapshot is there. The step's limit is 90 minutes.

**VM notices** (Decision 23; here, §9.5, §9.7 and §9.12) are written in P3's dict shape `{text, at, deployment_id, next: None}`. A VM notice never replaces a notice that carries a `next` (a stopped chain's follow-up, which the page's Continue button reads); then it lives only in `machines.last_error` or the job's log.

### 6.8 Hypervisor tasks (`machines.tasks`)

`wait_idle(ctx, *, limit=600)` runs before every change to an existing VM (start, shutdown, resize, snapshot, revert, delete, destroy, `delete_vm`, disk copy and delete):
- Proxmox: the VM's `lock` from `vm_config` (`clone`, `snapshot`, `rollback`, `backup`, `migrate`, …) and `vm_tasks(node, vmid)` (`GET /nodes/{node}/tasks?vmid=<id>&source=active`). ESXi: `recentTask` of the VM in state `running` or `queued`.
- While any is there, it polls every 5 s up to `limit`, logging `Waiting for Proxmox's <type> task on VM <vmid> (started <time>)`. Still there after the limit: `Proxmox is still running <type> on VM <vmid> (since <time>); Slipway changed nothing. Wait for it to finish, or stop it in Proxmox, then retry` (a clone: `Proxmox is still cloning VM <vmid>`).
- A `lock` with no task running (a task that died) refuses at once: `VM <vmid> is locked (<lock>) with no task running; check it in Proxmox and run "qm unlock <vmid>", then retry`.

Every task Slipway starts is written to `machines.last_task` in its own transaction before the wait, and cleared when it ends. On cancel or a step timeout, Slipway stops only Terraform (§7.3) and an ESXi `CopyVirtualDisk` task (`CancelTask` when `cancelable`), and leaves every other task to finish (D24). The log and `last_error` name the task left running (`VM snapshot task UPID:… may still be running on <node>`), and the next change waits for it. Recovery (§9.12) keeps `last_task` for the same reason.

### 6.9 Recording hypervisor ids (`machines.reserve_vmid`, `machines.record_vm`)

Both write the `vm` resource row and the machine's `ids`, each in its own transaction, and are the only writers of `vm` rows (M13).

`reserve_vmid(machine, account) -> int` (Proxmox, §7.4 C2), up to 20 tries:
1. A `vm` row of this account whose `details.machine_id` is this machine: its id is given back (a crash between the two writes, healed).
2. Candidate: `next_vmid()`, or `vmid_free(previous + 1)` after a taken one.
3. Taken, try the next: any `vm` row holding `(provider, vm, "<account>:<candidate>")` for **another machine**, whatever its environment; any machine on the account whose `ids.vmid` is the candidate.
4. Free: `resources.record(env, "proxmox", "vm", "<account>:<candidate>", name, created, details={machine_id, node})`. `ResourceTaken` (another environment's row, written meanwhile) counts as taken. Then `machines.ids.vmid`; audit `machine.reserve`.
5. After 20 tries: `Slipway couldn't find a free VM id in 20 tries (from <first>): other machines hold the next ones reserved`.

Step 3 is what guarantees test 24b (Decision 27): `resources.record` updates a row of the same environment that it finds (`services/resources.py`, `record` and `_clash`), so without the `details.machine_id` check green could take blue's reserved, unbuilt id and blue's row with it. Phase 4's extensions to `resources` (pending rows, credentials, `replaces`) don't change that, and VMs never write a pending row.

`record_vm(machine, provider_id, details)` (ESXi E3 and E4): first forgets any `vm` row of this machine with another `provider_id` (`resources.forget`, audit `machine.rebuild` with the old id), then records the new one. A row of another machine with that provider id refuses (`<id> is recorded for <other vm>; Slipway changed nothing`).

### 6.6 The address registry (`machines.addresses_in_use`, `machines.claim`)

An address is **in use** when it is (sources read under no lock; the claim's primary key is the lock):
- any `address_claims.address`;
- any host's `hostname`, `proxy_address` or `lan_address`, names resolved with a 2-second timeout each (a name that doesn't resolve counts as nothing);
- any account's API host (resolved);
- Switchyard's URL host and `traffic_address` (P3 §3.6);
- the network's gateway and DNS servers.

`prepare` checks again before boot, with live probes (M9): a TCP connect to `<address>:22` (3 s, `machines.tcp_open`, which the test guard patches) refuses `Something already answers SSH at <address>, so Slipway won't give that address to a new VM. Free it, or recreate the environment with another address`; on ESXi, any VM reporting the address through VMware Tools refuses (`<other> on ESXi already reports <address>`), as `SD/deploy/esxi_provision.py:342-366`. The probe is skipped when the VM there is the machine's own half-made VM.

The text of a refusal names the holder: `<address> is used by host <name>` / `is reserved for <env>'s <slot> VM` / `is the Proxmox API's address` / `is Switchyard's traffic address` / `is the network's gateway`.

---

## 7. Proxmox

### 7.1 Client (`slipway/services/proxmox.py`)

An httpx client on `<url>/api2/json` with `Authorization: PVEAPIToken=<token>` and `httpx.AsyncHTTPTransport(verify=tls_pin.pinned_context(pem))` (host names checked), timeout 30 s; tests swap `proxmox.transport_factory` for `MockTransport` as switchyard.py does. Ported from `SD/deploy/proxmox.py` with its error mapping: `version`, `nodes`, `next_vmid`, `vmid_free`, `find_vm` (`GET /cluster/resources?type=vm`: name, node, status, tags; `SD/deploy/proxmox.py:206-217`), `vm_config`, `status`, `start`, `shutdown` (`POST …/status/shutdown`, `timeout`), `delete_vm` (`DELETE /nodes/{node}/qemu/{vmid}?purge=1&destroy-unreferenced-disks=1`), `agent_ipv4` (skipping `lo`, `docker*`, `br-*`, `veth*`, 169.254/16; `:241-257`), `agent_file` (`:260-264`), `snapshots` (without `current`, each with its `parent`, so the newest is known), `take_snapshot` (`vmstate=0`), `rollback`, `delete_snapshot`, `wait(upid)` (OK or `WARNINGS…` pass; `:291-311`), `vm_tasks(node, vmid)` (`GET /nodes/{node}/tasks?vmid=<id>&source=active`), `snapshot_feature(node, vmid)` (`GET /nodes/{node}/qemu/{vmid}/feature?feature=snapshot` → `hasFeature`), `storage_info(node, storage)` (`GET /nodes/{node}/storage?storage=<name>`: `type`, `content`, `avail`; it needs only `Datastore.Audit`, unlike `GET /storage/{storage}`), `bridge`, `permissions(path)` (`GET /access/permissions?path=`, for Test). `vmid_free(id)` is `GET /cluster/nextid?vmid=<id>`: Proxmox answers for any id, whatever the token can see (D25). A certificate the pin refuses answers `Proxmox's certificate isn't the one Slipway trusts. If it was renewed on purpose, trust the new one in Settings → Integrations.` Reads made for a page use a 5-second timeout and answer `live.error` instead of failing the page.

`clean_config(config, secret)` and `run_test(account)` live in this module (not in the provider), so the accounts service (`provider_accounts`, S08) needs only A3 and A5.

**Test** (`proxmox.run_test`): the version; the node; the pool visible to the token; the template exists, is a template and has the agent on (off is a warning), and its `ciupgrade` is off (on is a warning: `The template upgrades every package at first boot (ciupgrade 1); set "qm set <id> --ciupgrade 0" so a new VM's first boot takes a predictable time`); the storage's type, content and free space, written to `facts` (`lvm` is a warning: `<storage> is thick LVM: Slipway's VMs there can't have VM snapshots`; `zfspool` a note: `ZFS rolls back only to the newest VM snapshot`); the bridge (403 is a warning: `Sys.Audit` on the node is optional); the token's privileges on `/pool/<pool>` against the role in §13.3 (each missing one named).

### 7.2 The bundled module (`slipway/terraform/proxmox-vm/`)

Package data (pyproject `[tool.setuptools.package-data] slipway = ["terraform/**/*"]`). Files:
- `versions.tf`: `required_version = "= 1.16.5"`, `bpg/proxmox` `= 0.115.0` (Sirdar's pins, `SD/deploy/terraform.py:33-34`). `terraform.TERRAFORM_VERSION` and `PROVIDER_VERSION` equal them (test 12).
- `.terraform.lock.hcl`: the provider's lock entry, with the `zh:` hashes of the linux_amd64 and linux_arm64 zips (the same SHA-256 the Dockerfile checks, test 39) and their `h1:` hashes. Shipped, never written by Slipway's `init`.
- `variables.tf`: `endpoint`, `node`, `vm_id`, `name`, `pool`, `tags`, `description`, `template_vm_id`, `datastore`, `file_format` (`qcow2` or `raw`), `bridge`, `vlan_id` (nullable), `cores`, `memory_mb`, `disk_gb`, `address_cidr`, `gateway`, `dns_servers`, `ssh_public_key`. Each with a `validation` block for the obvious ranges.
- `main.tf`: `provider "proxmox" { endpoint = var.endpoint, insecure = false }`; one `proxmox_virtual_environment_vm.vm` as Sirdar's (`SD/deploy/terraform.py:90-112`): full clone of the template on the node and datastore, `started = true`, `on_boot = true`, `stop_on_destroy = true`, `purge_on_destroy = true`, `reboot_after_update = false` (Slipway shuts the VM down itself, D12), `timeout_clone = 1800`, agent on with a 5-minute timeout, `cpu.type = host`, `virtio-scsi-single`, `scsi0` disk with discard, iothread and `file_format`, a virtio NIC on the bridge with the VLAN, `initialization` with the `slipway` user (`username` equals `cloudinit.GUEST_USER`, test 12) and key, the static `ip_config` and `dns.servers` (and `upgrade = false` when 0.115.0's schema has that attribute: A4 checks the provider schema with `terraform providers schema -json` once and records the answer in test 12; without it, Test's `ciupgrade` warning stands), `lifecycle { ignore_changes = [clone] }`.
- `outputs.tf`: `vm_id`.

Slipway writes `terraform.tfvars.json` from the machine (`spec`, `network`, `size`, `ids.vmid`, the host's public key, `tags` sorted as Proxmox stores them, so `["env-<environment id>", "slipway"]`, `file_format = qcow2` on a file storage (`dir`, `nfs`, `cifs`, `glusterfs`, from the account's `facts.storage_type`, frozen into `spec` at create) and `raw` otherwise, `description = "Managed by Slipway: environment <env> (<environment id>), <slot> slot. Change or delete it from Slipway, not here."`). The token is never in it. `module_sha` (the sha256 of the module files, the lock file included) is recorded with each apply; a newer Slipway whose module changed plans against the old state like any change, and M6 still applies. A `ready` VM is planned only for a resize (§7.5), whose check names any other attribute a newer module would change and refuses; docs/machines.md says how to apply such a change by hand.

### 7.3 State, working folder and locking (`slipway/services/terraform.py`)

`Workdir(machine_id)` is `<terraform_dir>/<machine id>/`, mode 700 (`SD/deploy/terraform.py:146-181`), holding the module files, `terraform.tfvars.json`, `proxmox-ca.pem` (exactly one certificate, else refused before anything is written: an empty `SSL_CERT_FILE` would fall back to the system's trust, `:57-60`), an empty `ca/`, `home/`, `.terraform/`, `terraform.tfstate`, the transient `tfplan`, and `slipway-run.json` (`{pid, deployment_id, args, started_at}`).

`async with terraform.session(machine, deployment_id, say) as tf:` does, in order, before any Terraform command:
1. **Lock row.** `UPDATE terraform_states SET lock_id = :dep, locked_at = now WHERE machine_id = :m AND (lock_id IS NULL OR lock_id = :dep OR lock_id NOT IN (SELECT id FROM deployments WHERE status IN ('queued', 'running')))` (row inserted first if absent). So a lock whose deployment row is gone (a slot's deployments cascade when Remove slot deletes the instance) is taken over like one whose job finished. Rowcount 0: `Terraform state of <vm> is in use by deployment <d8>; wait for it to finish`. A lock taken over is logged.
2. **No live process.** When `slipway-run.json` names a PID that is alive and whose command line is the Terraform binary: `Terraform is still running for <vm> (from deployment <d8>, pid <n>): wait for it to finish, then retry`. (Slipway starts Terraform in its own session, `start_new_session=True`, so it can outlive a crashed Slipway process inside a container that kept running.)
3. **Reconcile.** Reads the folder's `terraform.tfstate` (lineage, serial) and the row. Folder missing or older (same lineage, lower serial): the row's state is written into the folder. Folder newer (same lineage, higher serial): the folder's is saved to the row first, logged `Kept Terraform's state #<serial> from the working folder (Slipway stopped before saving it)`. Different lineages: `Slipway has two different Terraform states for <vm>; it changed nothing. Compare them in <folder> and the database before going on` (the step fails; docs/machines.md says how to choose). A row with NULL lineage (a first apply whose save never ran) counts as older than any folder state: the folder's is saved to the row. Both empty: nothing to reconcile.
4. **Files.** The module files, the shipped `.terraform.lock.hcl`, tfvars and CA written; `crash.log` and old `tfplan` removed (`:159-181`).
5. **init** (offline: the mirror-only CLI config) when `.terraform` is missing, or when the folder's `slipway-init.json` (`{module_sha, terraform_version}`) differs from the bundled module's hash and the binary's version. Then `init -input=false -lockfile=readonly`: Terraform installs the provider the shipped lock file names from the mirror, and refuses one whose hash doesn't match. `slipway-init.json` is written after it succeeds. So a newer Slipway whose provider changed re-initialises instead of failing with "doesn't match the dependency lock file".

On leaving (success, failure, timeout or cancel), always: the folder's state is saved to the row when its serial moved (own transaction), `slipway-run.json` removed, the lock row released. A state over 4 MiB fails the save: `Terraform's state for <vm> is larger than Slipway keeps (4 MiB)`.

**Runner** (`SubprocessTerraform`, Sirdar's, `SD/deploy/terraform.py:243-311`): `_spawn` is the one place a process starts (the test guard allows only `fake-terraform`); environment allowlisted (`PATH`, `LANG`, `TZ`) plus `HOME`, `TF_CLI_CONFIG_FILE`, `TF_IN_AUTOMATION=1`, `TF_INPUT=0`, `CHECKPOINT_DISABLE=1`, `SSL_CERT_FILE`, `SSL_CERT_DIR` and `PROXMOX_VE_API_TOKEN` (`:201-213`); output streamed line by line into the job's `LogSink` through its redactor, lines over 1 MiB dropped; a timeout or cancel sends SIGINT to the process group (Terraform saves its state), SIGKILL after 30 s. The wait after SIGINT is shielded from a second cancel, so Slipway's own shutdown (the runner cancels every job, deployer.py `DeployRunner.shutdown`) still gives Terraform its 30 seconds; `docker-compose.yml`'s `stop_grace_period: 60s` (D27) leaves room for it. A global `asyncio.Semaphore(terraform_parallel)` bounds processes. Each command has its own timeout: `init` 5 min, `plan` 10 min, `show` 2 min, `apply` 40 min (it holds the clone task, up to 30 min), `destroy` 20 min.

**Reading plans.** `plan -input=false -no-color -out=tfplan`, then `show -json -no-color tfplan` read into memory and never logged (it holds the full attribute set). `terraform.plan_changes(doc) -> list[Change(address, actions, before, after)]`; a document of another shape raises `PlanUnreadable` (`Slipway couldn't read Terraform's plan, so it applied nothing`). `apply -input=false -no-color tfplan` applies exactly the plan read. `destroy -auto-approve` only in Remove.

### 7.4 Proxmox `ensure` (`ProxmoxProvider.ensure`)

`find_vm` results are judged by `_ours(found)`: name equals `machine.name`, tags hold `slipway` and `env-<environment id>`, node equals `spec.node` (else `VM <vmid> (<name>) is on node <n> now, not <node>. Slipway changed nothing: move it back, or fix it by hand, then retry`, `SD/deploy/provision.py:302-305`). The account's current `node` is never used for an existing machine; the frozen `spec` is.

`_our_clone(found, config)` recognises Slipway's own half-made clone, which may not have its tags yet: Proxmox's clone call (`POST /nodes/{node}/qemu/{template}/clone`) takes `name`, `description` and `pool` but no tags, so `bpg/proxmox` sets the tags in a later config update, and a Terraform killed in between leaves a VM without them. It holds when the name equals `machine.name`, the node equals `spec.node`, the VM is in `spec.pool`, its tags are none or exactly Slipway's two, and its description is empty or names this environment's id (A3 checks which of name, description and pool 0.115.0's `vmCreateClone` passes to the clone call, and test 7 pins it). It is used only while the state holds no resource and the machine isn't `ready`.

**Stage `ready`** (reads only, then at most a start; a resize is the `resize` step's, §6.7):
- PR1. `find_vm(vmid)`: not ours → `VM <vmid> on Proxmox isn't <vm> any more; Slipway changed nothing`. None → `vmid_free(vmid)` (D25): free → the lost text (§9.10 names the way out); used → `Slipway can't see VM <vmid> on <account>: the token may have lost its rights on /pool/<pool>, or the VM was moved out of the pool. Slipway changed nothing`. Unreachable API with no resize to apply → the §6.3 warning.
- PR2. Not running → `tasks.wait_idle`, then `start`, wait for the task.
- PR3. `agent_ipv4` within 5 minutes must hold `network.address` (`<vm> came up at <addresses>, not <address>. Check the template's cloud-init settings`, `:386-391`); an agent that never answers is a warning when SSH then works.
- PR4. Returns `Ensured(address, expected_key = host.host_key, how=…, reread_key=None)`.

**Stage `planned`, `creating` or `booting`:**
- C1. The address: §6.6's registry again (excluding this machine's own claim and host row) and the TCP probe (skipped once the VM exists and is ours).
- C2. **Reserve the id** (no `ids.vmid`): `machines.reserve_vmid` (§6.9).
- C3. **Session** (§7.3: lock, PID check, state reconciled), then **identify the id**. First `tasks.wait_idle` on the id (D24): a clone task outlives a killed Terraform and holds `lock: clone` until it ends, so Slipway waits for it (10 minutes), else `Proxmox is still cloning VM <vmid>; Slipway changed nothing. Retry when it has finished`. Then `find_vm(vmid)`, judged against whether the state holds the resource:
  - **State has the resource:**
    - ours: carry on (C4 allows the replace of a tainted create);
    - someone else's: `VM <vmid> on Proxmox isn't the <vm> Slipway made. Slipway changed nothing: remove or rename that VM, or delete this environment`;
    - none, `vmid_free` says free: our VM is gone; the resource is removed from the state with `terraform state rm` inside the session (a half-made VM only, M3), and the plan makes it again;
    - none, `vmid_free` says used: `Slipway can't see VM <vmid> (check the token's rights on /pool/<pool>); Slipway changed nothing`.
  - **State has no resource** (our clone never ran, or Terraform was killed before it saved the state):
    - `_ours` or `_our_clone`: our half-made clone. `delete_vm` (after `tasks.wait_idle`), wait for the task, audit `machine.rebuild` (`Removed the half-made <vm> (VM <vmid>) from an earlier attempt`). Only before `ready` (M3);
    - someone else's VM: our VM can't be absent from the state and look like that, so Proxmox reused the id. In any stage before `ready`: forget the resource row and `ids.vmid` (audit `machine.rebuild`, `VM <vmid> is someone else's now; reserving another id`) and go back to C2;
    - none, `vmid_free` says free: carry on;
    - none, `vmid_free` says used (a VM outside the token's pool holds the id): forget the row and `ids.vmid`, back to C2 (logged `VM id <vmid> is used by a VM Slipway can't see; reserving another`).
- C4. **Plan.** A VM the state already holds (not a tainted create) is planned at the size it was made at (the state's `cpu`, `memory`, `disk`), so a size stored while it isn't ready (§9.4) gives no change here and waits for the resize step once it is ready; a VM made new is planned at `size`. `plan_changes` must hold exactly one change, of `proxmox_virtual_environment_vm.vm`, with actions `["create"]`, or (only when the state holds that resource tainted by our own failed create, and C3 confirmed the VM is ours) `["delete", "create"]` / `["create", "delete"]`. Anything else: `Terraform's plan for <vm> does more than make it (<actions>), so Slipway applied nothing`.
- C5. `stage = creating` (own transaction); a host still pinned to an earlier VM's key (that VM was gone, half-made or lost its id) is unpinned with `machines.unpin` (audit `host.key_reset`, `<vm> is made again with a new host key`); then `apply tfplan`. A failure: `Terraform couldn't make <vm>. See the log above.` The state is saved whatever happened (§7.3).
- C6. `stage = booting`. Waits (5 minutes, every 5 s) for `agent_ipv4` to report `network.address` (PR3's texts).
- C7. Waits (10 minutes, every 5 s) until `agent_file("/var/lib/cloud/instance/boot-finished")` can be read: cloud-init's `cc_ssh` makes the host keys after the address is set, so reading earlier could return a template's old key. Timeout: `cloud-init didn't finish on <vm> in 10 minutes (read through the guest agent)`.
- C8. Reads `/etc/ssh/ssh_host_ed25519_key.pub` through `agent_file` (5 minutes, every 5 s) and parses it with `asyncssh.import_public_key` (`The VM's SSH host key, read through its guest agent, isn't a key Slipway can use`). `machines.host_key_public` is set.
- C9. Returns `Ensured(address, expected_key, how="read through the Proxmox guest agent", reread_key=<C8 again>)`. The driver pins (a mismatch while `booting` re-reads the key, §6.4), bootstraps and marks `ready` (§6.3).

### 7.5 Proxmox resize

`check_resize` (reads only; run by `prepare` and again by `resize`, §6.3, §6.7):
1. Refusals: `size.disk_gb < applied.disk_gb` (PATCH refuses it already); `find_vm` ours and visible (PR1's texts); a **first plan** (session, `plan`, `show`) must hold exactly one `update` of the VM changing only `cpu`, `memory`, `disk` sizes (and `started`); else `Terraform's plan for <vm> would change more than its size (<attributes>); Slipway applied nothing`. Tags are written in Proxmox's sorted order (§7.2), so a plan never shows a tag change from ordering alone.
2. A disk grow on a qcow2 disk that has VM snapshots: `Proxmox can't grow <vm>'s qcow2 disk while it has VM snapshots (<names>); delete them first`. (LVM-thin, ZFS and Ceph allow it.)
3. `snapshot_first` is true when the environment has VM snapshots and `snapshot_mode` isn't `none` (D11, D23).

`resize(ctx, plan)` (the `resize` step, after `tasks.wait_idle`):
1. `pre_resize` VM snapshot when `plan.snapshot_first` (§9.6's take, `reason = pre_resize`), recorded before its task.
2. `shutdown` with a 5-minute timeout, then `status` stopped; else `<vm> didn't shut down in 5 minutes; Slipway left it running at its old size` (the VM is started again if it stopped later).
3. A **second plan** from the stopped VM; its change set must equal the first's (ignoring `started`); else the VM is started again and the step fails with the difference.
4. `apply tfplan` (`started = true` starts it), then PR3's address wait and a pin check (an SSH session with the pinned key, tried every 5 s for 5 minutes, since the agent can report the address before sshd listens; another key fails at once). A plan with no size change (an earlier resize whose record was cut off) returns the VM's size at once, with no snapshot and no shutdown. Once the shutdown was asked for, a failure or a cut-off starts the VM again (shielded). A failed apply: the VM is started again at whatever size Proxmox has, `applied` is re-read from `vm_config`, and the step fails `Terraform couldn't resize <vm>; it is running at <size>`.
5. `df -BG --output=size / | tail -1` over SSH: when the root file system is more than 2 GB smaller than `disk_gb - 2`, the step ends as `warning`: `<vm>'s disk grew to <n> GB but its root file system is <m> GB: cloud-init's growpart didn't run; run "sudo growpart /dev/sda 1 && sudo resize2fs /dev/sda1" on it`.

Real-host check 16.3.4 confirms each storage type.

### 7.6 Proxmox snapshots and revert

- **Snapshot mode** (D23, at ready): `snapshot_feature` false → `none`; true with `facts.storage_type` (frozen in `spec.storage_type`) `zfspool` → `newest_only`; true otherwise → `any`.
- Take: refused with `none` (`<storage> (<type>) can't take VM snapshots of <vm>`). `tasks.wait_idle`; the row (`pending`) committed, then `take_snapshot(vmid, name, description, vmstate=0)` with its UPID in `last_task`, and `wait`. On a timeout or task error, Slipway waits 15 s and lists the snapshots: present → the row stays (`ready`, noted `The task ended late`); absent → `failed`. Proxmox freezes the file systems through the guest agent when it can; either way the copy is at least crash-consistent, which Postgres recovers from.
- Revert: `tasks.wait_idle`, `rollback(vmid, name)` (the VM stops: `vmstate=0`), then `start`, then PR3. With `newest_only`, the `check` step has already refused when the target isn't the newest snapshot on the VM (§9.7), so Proxmox's "not most recent snapshot" can't happen after a change.
- Drop: `tasks.wait_idle`, `delete_snapshot(vmid, name)`.
- The id rule for every call: the name must be on the hypervisor exactly once and recorded on this machine.

### 7.7 Proxmox destroy (`ProxmoxProvider.destroy_blockers`, `.destroy`, in Remove)

`destroy_blockers` (reads only; run in `check` and again by `machines.remove`, D26), as the cases below decide, returns:
- the account unusable or unreachable (`Slipway can't reach <account>, so it can't remove <vm>`, forgettable);
- a hidden VM (case 3 with `vmid_free` used, forgettable);
- a VM at the id that isn't ours while the machine reached `ready` (`VM <vmid> isn't <vm> any more`, forgettable);
- ours but on another node (forgettable);
- a task running on it after `tasks.wait_idle`'s limit, or the Terraform state locked by a live process (not forgettable: wait, then retry).

`destroy`, as Sirdar's `_destroy` (`SD/deploy/provision.py:470-518`), with the half-made cases:
1. No `ids.vmid`: `Slipway never made <vm>`.
2. An id but the VM isn't ours (by `_ours` or `_our_clone`) while the machine never reached `ready`, or none is there and `vmid_free` says free: the resource row is forgotten, `VM <vmid> was never made by Slipway, or is gone; forgetting the id`.
3. None there, the state holds the resource, the machine reached `ready`: `vmid_free(vmid)` (D25). Free: `VM <vmid> is already gone`; the resource is dropped from the state and the row forgotten. Used: `Slipway can't see VM <vmid> (check the token's rights on /pool/<pool>); nothing was removed` (a blocker, so `check` has already refused it).
4. Ours, in the state: `tasks.wait_idle`, session, `destroy -auto-approve`, then `find_vm` must be none and `vmid_free` free (`VM <vmid> is still there after Terraform's destroy. Remove it by hand in Proxmox, then retry`).
5. Ours (or our clone), not in the state (only possible before `ready`): `tasks.wait_idle`, stop, `delete_vm`.
6. Then: the resource row forgotten, the `terraform_states` row deleted, the working folder removed, the host row's pin cleared with the host row itself later (§9.9).

---

## 8. ESXi

### 8.1 Client (`slipway/services/esxi.py`)

Ported from `SD/deploy/esxi.py`: the `EsxiApi` protocol (`:149-176`: `about`, `license_editions`, `datastore`, `network_names`, `resource_pool_names`, `find_vm(uuid)`, `find_vm_by_name`, `guest_ips`, `disk_users`, `create_vm`, `file_exists`, `copy_disk`, `delete_disk`, `attach_disk`, `grow_disk`, `set_size`, `set_extra_config`, `power_on`, `shutdown_guest`, `power_off`, `guest`, `snapshots`, `take_snapshot(quiesce)`, `revert_snapshot`, `delete_snapshot`, `destroy`), plus Slipway's `running_tasks(uuid)` (the VM's `recentTask` in state `running` or `queued`), `list_folder(path)` (the datastore browser, for E4 and §8.5) and `cancel_task(task)`, and `PyvmomiEsxi`, which implements it over one `ServiceInstance` with a one-thread executor (pyvmomi objects aren't thread-safe). Every task it starts is reported to the caller (for `last_task`) before it is waited on, with a 30-minute limit. On that timeout or a cancel it calls `CancelTask` only for `CopyVirtualDisk` (when the task is `cancelable`), and leaves other tasks to finish (D24).

`clean_config(config, secret)` and `run_test(account)` live in this module, as in proxmox.py. `_smart_connect` (`:698-705`) is the only call that opens a real session (the test guard patches it): `sslContext = tls_pin.pinned_context(pem, check_hostname=False)`, `thumbprint` from the pin, `httpConnectionTimeout = 30`, sign-in bounded at 35 s. `esxi.session(account)` signs in and always disconnects. pyvmomi is imported only inside `esxi.py`.

Markers: `OWNER_KEYS = {"slipway.machine": <machine id>, "slipway.environment": <environment id>}`; `VmInfo.owner` reads `slipway.machine`.

**Test** (`esxi.run_test`): `about.apiType == "HostAgent"` (`VirtualCenter`: `Slipway works with a standalone ESXi host, not vCenter`); the licence edition isn't `esxBasic` (`ESXi's licence doesn't allow changes through its API (free ESXi is read-only); Slipway needs a paid licence`, `:53-57`); the datastore and its free space; every network's port group; the resource pool; the seed VM exists, is powered off, has exactly one disk and no snapshots (`:802-820`).

### 8.2 ESXi `ensure` (`EsxiProvider.ensure`)

Before anything, the machine's frozen `spec.api_host` must equal the account's API host: `<vm> was made on <host>, but the account now points at <other>; Slipway changed nothing` (`SD/deploy/esxi_provision.py:161-169`).

**Stage `ready`** (reads only, then at most a power-on; a resize is the `resize` step's, §6.7): E-R1 `find_vm(ids.instance_uuid)`: none → the lost text (a same-named VM with our marker under another UUID adds `<vm> carries this environment's marker but isn't the VM Slipway recorded; remove it by hand`); name or marker differ → `The VM Slipway recorded for <env> isn't <vm> with its marker any more; Slipway changed nothing` (`SD/deploy/esxi_provision.py:219-228`). E-R2 the disk check: exactly one disk, the one Slipway copied (`<vm>-disk0.vmdk` in the VM's folder, any snapshot deltas above it; `esxi_provision.py:249-258`). E-R3 power on when off (after `tasks.wait_idle`), then Tools' address within 5 minutes must be `network.address` (real vNICs only, no link-local or loopback; `SD/deploy/esxi.py:275-298`). E-R4 returns `Ensured(address, host_key_public, "generated by Slipway", reread_key=None)`.

**Stage `planned`, `creating` or `booting`:**
- E1. **The host key pair.** Missing or unreadable with the current `SLIPWAY_ENCRYPTION_KEY` (§3.9): a new pair is made only where no VM can hold the old one. With no `ids` and no VM found by E3: regenerated, logged. With a VM that exists and the stage `creating` (never powered on: `booting` is written before `power_on`, E6): regenerated, then `guestinfo.userdata` rewritten with the new pair (`set_extra_config`) before `power_on`, logged `Made a new host key for <vm> and wrote it into its cloud-init settings`. With a VM in `booting` (it may have booted and installed the old key): the half-made VM is destroyed (§8.5's rules) and made again from E4 with a new pair (D9), audit `machine.rebuild`. A readable pair is never replaced.
- E2. Recorded UUID: `find_vm`; ours → continue at E5; none while `creating`/`booting` → `The half-made <vm> is gone from ESXi; making it again`: in one step the ids are cleared and the old `vm` resource row is forgotten (`resources.forget`), audit `machine.rebuild` (`esxi_provision.py:263-272`), so E4's new row doesn't meet P3's `uq_resources_environment_id_kind_name`; not ours → refused as E-R1.
- E3. No UUID: `find_vm_by_name(name)`; ours (`slipway.machine` = this machine) → adopted: ids recorded, `machines.record_vm` (§6.9), audit `machine.adopt` (`Found <vm> from an earlier attempt`); someone else's → `ESXi already has a VM named <vm> that isn't this environment's. Slipway changed nothing: rename or remove it, or recreate the environment` (`esxi_provision.py:234-247`).
- E4. Still none: §6.6's checks again, `guest_ips()` (no VM may report the address), the TCP probe. The folder `[<datastore>] <vm>/`: when it exists, `list_folder`; files there that no VM uses and that are Slipway's disk (`<vm>-disk0.vmdk`, `<vm>-disk0-flat.vmdk`) are deleted; any other file refuses (`[<datastore>] <vm>/ already holds files no VM uses (<names>). Slipway changed nothing: remove them in the ESXi Host Client, then retry`). Without this, ESXi would put the new VM in `<vm>_1/` and the old files would stay for good. Then `stage = creating` and `create_vm(spec)`: `ubuntu64Guest`, a PVSCSI controller, a vmxnet3 NIC on the port group, `disk.EnableUUID=TRUE`, the markers, the annotation, the cores and memory, and `guestinfo.metadata`/`guestinfo.userdata` (base64, §8.4) (`SD/deploy/esxi.py:331-352`). The moref, instance UUID and VMX path are recorded at once, with `machines.record_vm` (`esxi_provision.py:230-232`, `379-380`). Audit `machine.create`.
- E5. The disk (`esxi_provision.py:393-422`): `tasks.wait_idle` (a copy from a cut-off attempt may still run, D24); with no disk attached, a file at `<vm>-disk0.vmdk` from an earlier attempt is deleted only when no VM has it attached (`<path> is attached to <vms>, so Slipway won't delete it`); the seed is checked again (`esxi_provision.py:384-391`); `copy_disk(seed, path)` thin, its task in `last_task`; `attach_disk`; re-read; the disk check; `grow_disk` to `size.disk_gb` when smaller.
- E6. `stage = booting`; `power_on`.
- E7. Tools' address within 5 minutes (E-R3's texts).
- E8. Returns `Ensured(address, host_key_public, "generated by Slipway")`. The driver pins (§6.4).
- E9. `after_pin`: `set_extra_config({"guestinfo.userdata": "", "guestinfo.userdata.encoding": ""})` (an empty value deletes the key, `SD/deploy/cloudinit.py:105-107`) and `machines.host_key_private = NULL` in its own transaction. ESXi may still hold a copy in `vmware.log` (`SR/README.md`); docs/machines.md says so.

### 8.3 ESXi resize

`check_resize` (reads only; `SD/deploy/esxi_provision.py:424-489`):
1. Refusals: shrink (PATCH refuses it already); E-R1 and E-R2; a disk grow while the VM has any snapshot Slipway didn't record, or two snapshots with one name: `ESXi can't grow a disk that has VM snapshots, and <names> aren't Slipway's; delete them in ESXi first`.
2. Cores or memory only: `snapshot_first` when the environment has VM snapshots (§9.6). A grow: Slipway's own snapshots of the VM go in `drop_snapshots` (the dialog named them, §12.4), no snapshot is taken first (D13).

`resize(ctx, plan)` (the `resize` step, after `tasks.wait_idle`):
1. `pre_resize` when `plan.snapshot_first`.
2. `shutdown_guest`, then up to 5 minutes for `poweredOff`; else `<vm> didn't shut down in 5 minutes; Slipway left it running at its old size`.
3. `set_size(cores, memory_mb)`; for a grow, `delete_snapshot` each listed one (rows `missing`, audit `machine.snapshot_delete`), then `grow_disk`. A failure here leaves the VM off: `Slipway left <vm> off at <state>; retry the deploy to finish the resize` (`esxi_provision.py:483-489`), with §6.7's notice.
4. `power_on`; E-R3's address check; a pin check (as §7.5 step 4). A VM that has the size already, with no snapshot to delete, returns at once; a cut-off after the shutdown leaves it off with §6.7's notice.
5. §7.5's growpart check.

### 8.4 Guest customisation (`slipway/services/cloudinit.py`)

Ported from `SD/deploy/cloudinit.py:53-107`, static addresses only:
- `metadata(machine_id, hostname, address_cidr, gateway, dns_servers)`: `instance-id: slipway-<machine id>`, `local-hostname`, netplan v2 matched on `driver: vmxnet3` with the address, a default route and `nameservers` (the servers, else the gateway), `cleanup-guestinfo: [userdata]`.
- `userdata(hostname, ssh_public_key, host_key_private, host_key_public)`: the `slipway` user (`cloudinit.GUEST_USER = "slipway"`, gecos `Slipway`; `sudo: ALL=(ALL) NOPASSWD:ALL`, password locked, Slipway's client key), `ssh_pwauth: false`, `disable_root: true`, `ssh_deletekeys: true`, `ssh_genkeytypes: []`, `ssh_keys` with the generated ed25519 pair, growpart and `resize_rootfs`.
- `guestinfo(meta, user)` and `scrub()`.
- Every value is checked again before it is written (host name rule, canonical CIDR, at most 3 canonical IPv4 DNS servers); a bad one raises `ValueError` before any YAML exists.

Droplets keep their own user-data, `do_rules.droplet_userdata` (P4 §9.1, no sudo); it imports only the user's name (`do_rules.DROPLET_USER = cloudinit.GUEST_USER`).

### 8.5 ESXi snapshots, revert, destroy

ESXi's `snapshot_mode` is always `any`.

- Take: `tasks.wait_idle`; row (`pending`) committed, then `take_snapshot(memory=False, quiesce=True)`; `QuiesceFailed` → again with `quiesce=False`, logged `VMware Tools couldn't quiesce the file systems; taking a crash-consistent snapshot instead`; on a task error, 15 s grace, then present → `ready`, absent → `failed` (`SD/deploy/esxi_provision.py:536-566`). A name that appears twice is never picked for revert or delete (`:568-582`).
- Revert: `tasks.wait_idle`; exactly one match, `revert_snapshot` (the VM is off afterwards), `power_on`, E-R3 (`:586-612`).
- **Destroy blockers** (reads only; `check` and `machines.remove`, D26): the account unusable or unreachable; a same-named VM with our marker under another UUID; the recorded VM's name or marker changed; a disk that isn't Slipway's (`Destroy_Task` deletes every attached disk); a task still running after `tasks.wait_idle`'s limit (not forgettable). All but the last are forgettable.
- Destroy (`:616-666`): by UUID, else by name with our marker (an unfinished create). `tasks.wait_idle` (a copy may still run: it is cancelled when it is Slipway's own, D24). The unattached disk: when `<vm folder>/<vm>-disk0.vmdk` exists and no VM uses it (E5's `disk_users` rule), it is deleted first, since `Destroy_Task` deletes only attached disks (Sirdar's `_remove`, `esxi_provision.py:647-666`, leaks it). Power off when on; `destroy`; `find_vm` must be none (`<vm> is still there after destroy. Remove it by hand in the ESXi Host Client, then retry`). Then `list_folder(<vm folder>)`: gone or empty passes; files left are named as a warning (`ESXi left <files> in <folder>; Slipway no longer records them: delete them in the ESXi Host Client`). No UUID and no marked VM by name: the folder rule alone, then `Slipway never made <vm>`.

---

## 9. Flows

Every flow lists its refusals (each answered before anything changes, M9), its steps, what a retry does and what is recorded. Refusals are 409 unless marked; typed-name mismatches are 422 and are checked first (P2 §13).

### 9.1 Accounts (`/provider-accounts`)

One service (`slipway/services/provider_accounts.py`) and one router (`slipway/api/v1/provider_accounts.py`) for the three providers, with a per-provider dispatch (Decision 3); P4 §8 gives the DigitalOcean rules. Reads need `providers:read`, writes `providers:write`.

**Create** (`POST`, `providers:write`). Refusals, in order: `provider` is `proxmox`, `esxi` or `digitalocean` (422; DigitalOcean's fields are P4 §8's); `name` rule and unique; `provider.clean_config` (422 with `field`: URL `https://host[:port]`, a Proxmox URL without a port stored with `:8006` so the certificate pinned, the API and Terraform's endpoint name one port (a row stored without one before is called, and given to Terraform, on `:8006` too: `proxmox.endpoint`), node, pool, storage, bridge and port group names, `template_vmid` 100-999999999, the token format `user@realm!tokenid=<uuid>` (`SD/deploy/integrations.py:75-82`), the ESXi user rule, each network per §3.1, network names unique); the secret is required. Then **trust**: without `trust_fingerprint`, Slipway fetches the live leaf certificate unverified (`tls_pin.read_certificate`, 10 s) and answers 409 `{code: "tls_untrusted", certificate: {fingerprint_sha256, subject, issuer, not_before, not_after, sans}}` with nothing written; with `trust_fingerprint` equal to the live one, the PEM is stored in `tls` (a different one: 409 `tls_mismatch` with the live certificate). Writes the row; audit `provider_account.create` and `.trust`. Test runs once in the background of the response (its result fills `status` and `checks`).

**Update** (`PATCH /{id}`, partial: an omitted field keeps its value). Refusals: as create; while any machine uses the account, the URL (and ESXi's user) can't change: `<account> has VMs (<names>): its URL can't change. Make another account for the new address`; a network a machine uses can't be removed or renamed (`<network> is used by <vms>`; its other fields may change: machines keep their frozen copy, §3.2). The stored secret is kept when the body leaves it empty **and** the URL (and ESXi user) are unchanged; otherwise it is required (`SD/deploy/integrations.py:45-52`). A changed URL forgets the pin (trust again). Audit `provider_account.update`.

**Trust** (`POST /{id}/trust {fingerprint}`): for a renewed certificate. The live leaf must match; stored; audit. Every client call made with the old pin answered the "certificate changed" text until then.

**Test** (`POST /{id}/test`): the client module's `run_test` (§7.1, §8.1), normalised by `provider_accounts` (Decision 34); 200 `{status, checks, facts}`, the same shape for every provider; the row keeps them. Audit `provider_account.test`. No lock is held while the provider answers; when the secret, the URL (ESXi: or the user) or the pinned certificate changed meanwhile, nothing is kept and the answer is 409 `{code: "test_stale"}` (`<name> changed while the Test ran: test again`).

**Remove** (`DELETE /{id} {confirm}`, the account's name typed, as for every provider): refused while a machine or a not-deleted environment references it (`<account> has VMs: <names>. Delete their environments first`). With nothing referencing it the row is deleted; otherwise (only deleted rows point at it) it is kept as a tombstone: `secret = NULL`, `config` cleared, `removed_at` set, the name kept (P4 §8). Audit `provider_account.delete`.

### 9.2 Create an environment with VMs (`POST /environments`)

P3 §9.1, with each of `hosts.blue`, `hosts.green` and `hosts.data` either a host id (P3's rules) or `{machine: {account_id, network, address: <IPv4> | "auto", cores?, memory_mb?, disk_gb?}}`. The environment's placement (`environments.provider`) is `ssh`: VMs are hosts Slipway makes, chosen under **Where: Hosts**; placement `digitalocean` is phase 4's (P4 §15.1). One create body serves both (Decision 24).

**Refusals** added at P3's step 4 (Hosts), field `hosts.<slot>`, in order:
0. A host id (not a `machine`) whose host has `owner_environment_id` set: `<host> is a VM of environment <env>; only its slots run there` (D18; `hosts.owned_host_refusal`, checked in P3's refusal 4 beside "pinned"; a droplet gets the same refusal with its own wording).
1. Any `machine` without `machines:write`: 403.
2. The account exists and is a Proxmox or ESXi account (`<account> is a DigitalOcean account: choose DigitalOcean under Where`, Decision 24), has its secret and a pinned certificate (`Trust <account>'s certificate in Settings → Integrations first`); it has been tested (Proxmox: `facts.storage_type` is known, else `Test <account> first: Slipway needs to know its storage type`); its last Test isn't `error` (`<account>'s last test failed: <check>. Test it again in Settings → Integrations`).
3. Every new VM uses the same account and network (`<env>'s VMs share one account and one network`); the network exists on the account.
4. The address: typed ones per §5 and §6.6; two VMs of the request never share one; `auto` takes the lowest free pool addresses in slot order (`<network> has no free address left in its pool`; without a pool: `<network> has no address pool: type an address`).
5. Sizes (§5); the VM name free on the account and the host name free (§6.2).
6. P3's other host rules hold by construction (a VM is its own host; its `client_address` is its IP). Validation runs on unsaved `Host` stand-ins from `hosts.planned_host(...)`, so P3's readers of `CreatePlan.hosts: dict[str, Host]` (`_placeholder_builtins`, `address_problem`, `slot_folder_problem`, `server_values` with the planned addresses as `{server.clients}`) keep working; `CreatePlan.planned` holds the provider plans (Decision 24).

**Writes** (P3's single transaction, in the caller's transaction; the API commits): P3's rows, then `machines.plan` for each VM (host, claim, machine). Audit `environment.create` gains `machines: {slot: {account, network, address, size}}`; one `machine.plan` per VM. A claim conflict at the commit answers 409 `<address> was just taken by another environment: pick another address`, field `hosts.<slot>.machine.address`, and nothing is written (§6.2, Decision 43).

**`?check=true`**: P3's answer plus `plan.machines: [{slot, name, account, network, address, size}]`, each planned slot's `plan.slots[<slot>] = {host_id: null, host: "slipway-<env>-<slot>", planned: "<proxmox | esxi>"}`, and warnings (`<account> hasn't been tested since <time>`; `<storage> has <n> GB free; the new disks need <m> GB`, from the last Test). No `cost`: that top-level key is DigitalOcean's (P4 §12). No hypervisor call, no probe.

### 9.3 Deploy to a VM slot or VM data server

P3 §9.2, §9.3 and §9.7, with `resolve` then `prepare` first and, for an app slot with a pending resize, `resize` after `backup` (§10.3). At queue: §10.4's fences. At run: §6.3, then P3's steps, with §6.7 in its place. The first chain of a Blue/Green environment on three new VMs makes the data VM in the data server's deploy, then blue's VM in blue's deploy (P3's order); each VM takes several minutes (clone or copy, first boot, Docker). The data server's `{server.clients}` names the app VMs' planned addresses from the start (D4).

**Retry:** runs `prepare` again, which continues where the attempt stopped (§9.11), and `resize` again when `size != applied` (it checks the VM's actual size first: a resize that was applied but not recorded is recorded and skipped). Nothing is undone between attempts. A deploy that fails after `resize` leaves the VM at its new size with the live release started (§6.7 step 4).

**Recorded:** the step's note (`Made <vm> (VM 123) at 10.0.0.12; Docker 26.1`, `Resized to …`, `Checked <vm>`), the machine's stage and `applied`, audit rows of §4.2.

### 9.4 Resize (`PATCH /environments/{id}/machines/{slot}`)

Body `{cores?, memory_mb?, disk_gb?, keep_vm_snapshots?}`.

**Refusals:** `machines:write` (403); the environment `deleting`/`deleted`; the slot's host isn't a machine (`<slot> runs on host <h>, which Slipway didn't make`); a size out of range (422); `disk_gb` below `applied.disk_gb` (422 `Disks only grow: <vm> has <n> GB`); the data server once `ready` (`The data server's VM keeps its size: both slots' data is on it. docs/machines.md shows how to grow it by hand`).

**Writes:** `machines.size` (and `keep_vm_snapshots`); audit `environment.update` with `machine.<slot>: <from> → <to>`. Nothing touches the hypervisor.

**When it is applied.** The deploy lists a `resize` step (§10.3) when, at queue time, `size != applied`, the job is a deploy of this slot, the machine is `ready` (a planned VM is simply made at `size`), the slot isn't the data server, and the slot isn't the active one of two app slots (D12, M8). `prepare` runs the read-only checks early (§6.3 step 5); `resize` (§6.7) checks the rule again and applies it after `backup`. Since P3 deploys always go to the idle slot (P3 D11), the active slot's pending resize waits until it is idle and deployed again; the page says `Resize pending: applies at <slot>'s next deploy`, the one phrase droplets use too (Decision 33), and the Resize dialog explains the wait. The PATCH rules are the service helper `environments.resize_plan`. The step is the one shared `resize` key (P4 §9.4 is the droplet side). The Deploy dialog says `<vm> is resized to 8 vCPU, 16 GB, 128 GB after the backup: it shuts down for a minute or two` and, for a single slot, `<env> is down meanwhile`; on ESXi with a grow and VM snapshots, `ESXi can't keep VM snapshots across a disk grow: <names> are deleted`; with `snapshot_mode = none`, `No VM snapshot is taken first: <storage> can't take one`.

### 9.5 Add and remove a slot

**Add a slot** (P3 §9.8): the body is the one `SlotAdd {host_id?, machine?, confirm_cost?}` (Decision 25): on SSH placement exactly one of `host_id` and `machine` (§9.2's shape; it must use the account and network of the environment's other VMs, if any); `confirm_cost` is DigitalOcean's (P4 §15.5). The rules are a service helper, `environments.add_slot_plan`, that the API calls. §9.2's refusals 0-5 apply (a `host_id` of another environment's VM, or of this environment's own data VM, is refused by 0); writes the instance and `machines.plan`, with §9.2's claim-conflict 409 at the commit. The data server must be updated before the new slot's first deploy as in P3 (its `{server.clients}` gains the new address).

**Remove a slot** (P3 §9.9; `DELETE /environments/{id}/slots/{slot}` with body `RemoveSlotIn {confirm?, forget_vms?}`, Decision 44): P3's refusals, then the machine's: the account usable (`Slipway can't reach <account>, so it can't remove <vm>: retry when it answers`) and `provider.destroy_blockers` (§7.7, §8.5), each a 409 before the job is queued, unless the body has `forget_vms: true` (which needs `machines:write` + `environments:delete` and the environment's name typed) and every blocker is forgettable (D26). Steps `check, slot, machine` (§10.3):
- `check`: P3's, then `machines.blockers(ctx)` again at run time (D26). Any blocker fails the step with its text; nothing has been removed.
- `slot`: for a host the environment owns (`hosts.owned_by(env, host)`, the predicate droplets use too, Decision 15), no SSH teardown (`<vm> goes in the next step`); the instance row is deleted in its own transaction.
- `machine`: `machines.remove(ctx)`: `blockers` once more (a guard), the machine to `destroying` (own transaction), `provider.destroy` (§7.7, §8.5), then in one transaction the `terraform_states` row, the `machine_snapshots` rows (cascade), the machine, the host and its claim; the working folder is removed after the commit. Audit `machine.destroy`.

**Retry:** `slot` answers `Already removed`; `machine` continues (a destroyed VM is `already gone`). A retry with `forget_vms: true` (typed name, `machines:write` + `environments:delete`, D26) runs `describe` once more; a machine whose only blockers are forgettable is then forgotten instead of destroyed (`machines.remove(ctx, forget=True)`: the same rows go, no hypervisor call), audit `machine.forget` (`why: forget_vms`, with the blocker), and the environment's notice says `Slipway forgot <vm> (<ids> on <account>) without removing it: <blocker>. Remove it by hand.` (§6.7's notice rule). A blocker that isn't forgettable still fails the step.

### 9.6 Take a VM snapshot (`POST /environments/{id}/vm-snapshots {note?}`)

**Refusals:** `machines:write` (403); the environment isn't one app slot in mode `slot` on a `ready` machine (`VM snapshots are for an environment whose one slot runs on a VM Slipway made`); `snapshot_mode = none` (`<storage> (<type>) can't take VM snapshots of <vm>`, D23); a job running (P3 §8.2); the owner's hold (`<env>'s data is held after <job>: settle that first`); 10 `manual` snapshots already (`<vm> has 10 VM snapshots you took; delete one first`); the account unusable.

**Steps** (kind `vm_snapshot`, on the slot instance):
1. `check`: again at run time; `describe`: the VM is ours. A task still running on it is waited for by `tasks.wait_idle` (§6.8) before the snapshot starts, or refuses after the limit.
2. `vm_snapshot`: the row (`pending`, `reason = manual`, `name = slipway-<now UTC>`, the instance's `app_state`, live commit, `fresh_data`, the owner's identity values and fingerprint, the names of its `ready` P2 backups, `applied`) committed first (M5), then `provider.snapshot`; `ready` (or the §7.6/§8.5 late-task rule); audit `machine.snapshot`.
3. `prune`: deletes the oldest `pre_resize` and `pre_revert` rows beyond `keep_vm_snapshots` (and their hypervisor snapshots); `manual` ones only by hand; a name that appears twice on ESXi is never deleted (logged).

**Retry:** takes a new one; a `pending` row of the failed attempt is checked first and becomes `ready` or `failed`.

### 9.7 Revert to a VM snapshot (`POST /environments/{id}/vm-snapshots/{sid}/revert {confirm, skip_pre_revert?}`)

What it does: the VM's whole disk goes back to the snapshot, so code, data, Docker and the release folders are as they were then. Writes since then are lost, including P2 backups taken on the VM since.

**Refusals:** `confirm` ≠ the environment's name (422); `machines:write` + `data:reset` (403); the snapshot isn't this environment's machine's; its identity values can't be read (its `identity_fp` isn't the fingerprint of no keys but `identity` reads as NULL: `<name>'s identity values can't be read any more (SLIPWAY_ENCRYPTION_KEY changed): put the old key back or delete it`, or, once `--clear-unreadable` erased them, `<name>'s identity values were erased when SLIPWAY_ENCRYPTION_KEY changed: delete it`; again in `check`); it isn't `ready`; §9.6's shape rule; a job running; with `snapshot_mode = newest_only`, the snapshot isn't the newest on the VM (below). The owner's hold does **not** refuse it (a revert is one way out of a hold).

**Steps** (kind `vm_revert`):
1. `check`: the VM ours and `ready`; the snapshot's name on the hypervisor exactly once (`The VM snapshot <name> is gone from <account>` / `<account> has <n> VM snapshots named <name>; Slipway won't pick one`). With `newest_only` (ZFS, D23): the snapshot must be the newest of **all** the VM's snapshots on Proxmox, Slipway's or not (`Proxmox can roll ZFS back only to the newest VM snapshot; <names> are newer. Delete them first, or revert to <newest>`). Every refusal comes here, before any change.
2. `vm_snapshot` (unless `skip_pre_revert`, which is forced on with `newest_only`): a `pre_revert` snapshot of the VM as it is now, as §9.6 step 2, so this revert can itself be reverted. A retry keeps the first attempt's when it is `ready` (`options.vm_snapshot_pre`). On ZFS a `pre_revert` would be newer than the target and Proxmox would refuse step 3, so none is taken and the dialog says `On ZFS storage this revert can't be undone: Slipway can't keep a VM snapshot of <vm> as it is now`.
3. `vm_revert`: `provider.revert` (§7.6, §8.5). `options.revert_started` is written `false` first and `true` once the provider is about to start the revert task (`MachineContext.before_change`, fired when its `tasks.wait_idle` finds the VM idle or, at the latest, when `tasks.started` records a task); a refusal before that (the snapshot gone or twice, a task still running, the account, the VM not Slipway's) changed nothing and holds nothing (§9.12).
4. `wait`: the VM's address and an SSH session with the pinned key (the snapshot was taken after the first boot, so the key is the same; a different one fails `pinned nothing`).
5. `vm_settle`, over SSH then in one transaction:
   - `: > <instance folder>/.slipway-lock`: every line there is stale, because this job holds both of the environment's runner keys and the VM's memory wasn't in the snapshot, so no command from before is still running;
   - the instance's `app_state`, `fresh_data` and live commit from the row; the owner's `data_dirty` and hold cleared; `live_identity` from the row when the row recorded identity values (a row that recorded none leaves it as it is, so the identity guard of the data stays);
   - when the row's `identity_fp` differs from the environment's identity values now, those secrets in `environments.app_secrets` are set from the row with the P3 §6 compare-and-set on `secrets_version` (as a P2 restore with an identity override);
   - `applied` from the row's `sizes` (the hypervisor restored the VM's settings too), so the next deploy applies `size` again;
   - P2's `check_backups` over the owner's backup rows: those taken after the snapshot become `missing`;
   - audit `machine.revert`.
6. `restart`: the live release's projects started (`docker compose start`, as the control action); a failure fails the job with `<vm> is back at <snapshot>, but <env> didn't start: <error>. Start it from the instance page`, the records already matching the VM.
7. `traffic`: P3's in-place sync for the single slot (warning only), since the ports in the restored `app_state` may differ.

**Recorded:** the deployment, audit, and the environment `notice` (§6.7's rule): `Reverted to <name> (<time>, <sha7>). Backups taken after it were on the VM and are gone: <names>. Settings changed since then apply at the next deploy.`

### 9.8 Delete a VM snapshot (`DELETE /environments/{id}/vm-snapshots/{sid}`)

**Refusals:** `machines:write`; not this environment's; `pending`; a job running; the data owner's hold is a revert's to this snapshot (`<env>'s data is held until <vm> is reverted to <name> again, so Slipway keeps <name>: revert to it first`; again in `check`). **Steps** (kind `vm_drop`): `check`, `vm_drop` (`provider.drop_snapshot` when the name is there exactly once; absent: nothing to delete), then the row is deleted; audit `machine.snapshot_delete`. **Retry:** runs again.

### 9.9 Delete an environment with VMs (`DELETE /environments/{id}`)

P3 §9.10, with D19. The body is phase 4's `EnvironmentDelete {confirm, snapshot?, drop_data?, confirm_production?, confirm_no_snapshot?, forget_vms?}` (P4 §15.10), and the rules are the service helper `environments.delete_problem`.

**Refusals** added: when the data owner's host is a machine and the body has neither `snapshot` nor `drop_data: true`: `<env>'s data is on <vm>, which Delete destroys: take a snapshot first, or confirm that the data goes with it` (field `drop_data`); `drop_data` without `data:reset` (403). One flag for the data's only home, a data VM here and the managed cluster in P4 §13 (Decision 26); as there, an owner that never held data (`fresh_data == "empty"`, no backup that reached `ready`, no deploy whose `start` began) needs neither. for each machine, the account usable and `provider.destroy_blockers` (D26), answered before the snapshot or the teardown is queued (`Slipway can't remove <vm>: <blocker>. Nothing was changed`). The body may carry `forget_vms: true` (same permissions as on a retry, D26): forgettable blockers then pass, so an environment whose account is gone for good can still be deleted.

**Steps:** P3's `check, unroute, undns, slots, data_server, forget`, with `machines` before `forget`:
- `check`: P3's, then `machines.blockers(ctx)` for every machine (D26). Any blocker fails the step before `unroute`: no Switchyard host, DNS record, instance or Backup row has gone.
- `slots` and `data_server`: for a member on a host the environment owns (`hosts.owned_by`), no SSH teardown (`<vm> goes in Remove the VMs`); the instance row is deleted (its Backup and FirstAdmin rows cascade, as P3).
- `machines`: §9.5's `machines.remove` for each machine, green, then blue, then data. When an app VM can't be removed (something changed since `check`), the data VM is kept and the step fails naming both (`Slipway couldn't remove <green vm>: <why>. <data vm> was kept; retry once that is fixed`), as `SD/deploy/vmsteps.py:19-20` (the order) and `120-141` (keeping the data VM). Every `vm` resource row is forgotten as its VM goes, so P3's `forget` finds `resources` empty.

**The dialog** (§12.4) lists the VMs and their disks among what goes, and the data with them unless a snapshot is taken.

**Retry:** idempotent, as P3. A retry may take `forget_vms: true` (§9.5's rule, D26) beside P3's `forget_traffic`, for any machine, the data VM included: a VM deleted by hand, or hidden, or on an account that is gone for good no longer keeps the environment in `deleting`.

### 9.10 Forget a lost VM (`POST /environments/{id}/machines/{slot}/forget {confirm}`)

For an app slot whose VM is gone (someone deleted it on the hypervisor). It lets the slot's next deploy make a new VM.

**Refusals:** `confirm` (422); `machines:write` + `environments:delete` (403); the machine isn't `ready` (`<vm> isn't made yet: deploy to <slot> to finish it`); the slot is `data`, or the environment is mode `slot` (`<vm> held <env>'s data. Slipway can't make it again without that data: delete the environment, and create it again from a snapshot if you have one`); the slot is the active one of two (`<blue> takes the traffic: activate <green> first`); a job running; `describe` finds the VM there and ours (`Slipway can still see <vm> on <account>: remove the slot instead`); `describe` finds it hidden (D25: `Proxmox still has VM <vmid>, but the token can't see it. Give it back its rights on /pool/<pool>, or remove the VM by hand, then try again`); the account can't be reached (502 `Slipway can't check <account> now, so it won't forget <vm>`).

**Writes** (under `runner.exclusive` with both environment keys, one transaction): the `vm` resource rows forgotten; the `terraform_states` row deleted (the folder after commit); the machine back to `planned` (`ids = {}`, `applied`, `ready_at`, `host_key_public` cleared; ESXi a new host key pair); the host's `host_key` and fingerprint cleared, status `unknown`; the slot instance `status = created`, `app_state = NULL`, `slot_state.stale = {reason: "Its VM was lost; the next deploy makes a new one"}`; audit `machine.forget`. The next deploy to the slot runs §7.4/§8.2 from `planned`.

### 9.11 Half-made VMs

What `prepare` (P) and Remove (R) do in each case. "Ours" is §7.4's or §8.2's marker check.

| Case | Proxmox | ESXi |
|---|---|---|
| `planned`, no id | P: makes it. R: nothing | same |
| id reserved, nothing on the hypervisor (`nextid` free) | P: plans a create with that id. R: forgets the id | P: clears the ids and the old row, creates. R: nothing |
| id reserved, the state has no resource, someone else's VM there, or an id used by a VM the token can't see | P: forgets the id, reserves another (C3), in any stage before `ready`. R: forgets the id | n/a (UUIDs aren't reused) |
| ours, not in Terraform's state, tags missing or not (Terraform killed after the clone started) | P: waits for the clone task and `lock: clone` to end, deletes it through the API, makes it again (`machine.rebuild`). R: the same wait, then deletes it through the API | n/a |
| ours, in the state as tainted (Terraform's create failed part way) | P: the plan's replace is allowed (C4). R: `terraform destroy` | n/a |
| ours, made, not yet booted or pinned (`creating`/`booting`) | P: starts it, waits for cloud-init's `boot-finished`, reads the key, pins (re-reading a stale key), sets up Docker | P: finishes the disk (a running copy waited for; a half-copied file deleted when unattached), powers on, waits, pins, scrubs |
| ours, made, record lost (Slipway stopped before recording the UUID) | n/a (the id is recorded first) | P: adopts it by its marker (`machine.adopt`). R: destroys it by name and marker |
| ours, made, gone while `creating`/`booting` | P: makes it again (the resource dropped from the state) | P: makes it again (the old `vm` row forgotten first) |
| a half-copied disk with no VM (Delete ran during a build, or the record was lost) | n/a | P: E4 deletes Slipway's own disk file in `<vm>/` before creating. R: deleted before the folder check |
| ESXi host key unreadable | n/a (read through the agent) | P: no VM, regenerated; `creating`, regenerated and the user-data rewritten; `booting`, the VM made again (E1) |
| a VM of that name or id without our markers | P and R: refuse, change nothing | same |
| a task still running on the VM (any case above) | P and R: wait for it (10 minutes), then refuse, change nothing (D24) | same |
| `ready`, gone (`nextid` free) | P: the lost text (M3); Forget (§9.10) for app slots. R: `already gone` | P: the lost text. R: `already gone` |
| `ready`, hidden (`nextid` used, not visible) | P: refuse, naming the pool rights. R: refused in `check`; `forget_vms` gets past it | n/a |
| `ready`, someone changed its disks (ESXi) | n/a | P: refuse. R: refused in `check`; `forget_vms` gets past it (`<vm> has a disk Slipway didn't put there`) |

Bootstrap (§6.5) is safe to repeat, so a VM cut off during it is simply bootstrapped again.

### 9.12 Recovery after a restart (P3 §9.13 additions)

- A job interrupted in `prepare`: the machine keeps its stage and gets `last_error = "Slipway restarted while preparing <vm>"`; recovery (`machines.recover_prepare`, called from `recover_interrupted`) clears `terraform_states.lock_id` for that deployment. `slipway-run.json` stays until the next session's PID check (§7.3 step 2). `last_task` stays, so the retry waits for a task still running (D24). The retry continues (§9.11).
- A job interrupted in `resize`: the VM may be off (ESXi, §8.3 step 3) or stopped (Proxmox, §7.5 step 2) at either size. Recovery sets `environments.notice` (`<vm> was left off during a resize: deploy to <slot> again to finish it`; §6.7's notice rule), `last_error`, and audits `machine.left_off`. The Slots card shows the VM's live power state from `GET …/machines` (`Off`), and Activate refuses a slot whose VM is off (§10.4). The next deploy's `prepare` starts the VM (§7.4 PR2, §8.2 E-R3) and its `resize` finishes the change.
- A `pending` VM snapshot row of an interrupted job: `failed`, unless the next `describe` (the page's card, the next snapshot job's `check`) finds the name on the hypervisor, which makes it `ready`.
- `vm_revert` interrupted at or after `vm_revert` (in `vm_revert` itself only when `options.revert_started` isn't `false`, §9.7 step 3; the same rule for a failure): the owner gets P2's hold: `Slipway restarted while reverting <vm> to <name>. The VM's disk may already be back at <name> while Slipway's records name a later release: revert to <name> again`. A P2 restore isn't offered: `app_state.live.release` may name a release that isn't on the disk any more, so its `release` step would fail. A retry (typed name) is accepted.
- `machine`/`machines` interrupted: the machine stays `destroying`, the environment `deleting` (P3); only the retry is accepted (with `forget_vms` when the VM can't be accounted for, D26).

---

## 10. Jobs and steps

### 10.1 Kinds

| kind | runs on | label | steps |
|---|---|---|---|
| vm_snapshot | the slot instance (data owner) | `Take a VM snapshot` | `check, vm_snapshot, prune` |
| vm_revert | the slot instance | `Revert to <name>` | `check, ⟨vm_snapshot⟩, vm_revert, wait, vm_settle, restart, traffic` |
| vm_drop | the slot instance | `Delete VM snapshot <name>` | `check, vm_drop` |

`data.py` gains their `KIND_LABELS`/`KIND_NOUNS`; `CHANGING_KINDS` gains `vm_revert` (it replaces data, so P2's "latest changing job" sees it and an older failed deploy's retry doesn't inherit a backup across it). Runner keys: both environment keys (P3 §8.2 "everything else"). `HOLD_REFUSES` gains `vm_snapshot`. Their own refusals live in `vm_jobs.py` and are registered into `jobs.KIND_PROBLEMS`, a registry `job_refusal` consults, so the VM kinds need no edit of `jobs.py` (Decision 45). Retry permissions are `data.RETRY_PERMISSION` and `RETRY_EXTRA` (§4.1).

### 10.2 Step catalogue additions

Two catalogues, as P4 §14.2 (Decision 13). **Member steps** are keys of `deployer.STEP_NAMES`, named per provider in `steps_for`, with their timeouts in the deployer's `STEP_TIMEOUTS` plus per-provider overrides (a mechanism phase 4 and phase 5 add together; until then only `env_jobs._step` had timeouts). `prepare` and `resize` are one key each for droplets and VMs, with each provider's limit. **Environment steps** are keys of `environments.ENV_STEP_NAMES` and `ENV_STEP_TIMEOUTS`.

| key | catalogue | name | timeout |
|---|---|---|---|
| `prepare` | member | `Prepare the VM <vm> on <account>` (droplets: `Prepare DigitalOcean`) | 120 min (droplets 50) |
| `resize` | member | `Resize <vm> to <size>` | 90 min (droplets 60) |
| `vm_snapshot` | member | `Take a VM snapshot of <vm>` (in a revert: `Take a VM snapshot first`) | 35 min (ESXi's wait for another task, the quiesced and the crash-consistent tasks, the grace) |
| `prune` | member | `Delete old VM snapshots` | 45 min (two deletes, each a wait for another task and a consolidating delete) |
| `vm_revert` | member | `Revert <vm> to <name>` | 30 min |
| `wait` | member | `Wait for <vm> to answer` | 10 min |
| `vm_settle` | member | `Bring Slipway's records back to <name>` | 2 min |
| `vm_drop` | member | `Delete the VM snapshot <name>` | 25 min (a wait for another task and a consolidating delete) |
| `machine` | environment | `Remove the VM <vm>` | 30 min |
| `machines` | environment | `Remove the VMs` | 60 min |

`check` in the VM kinds is named `Check <vm> and its VM snapshots`. `restart` and `traffic` keep P2's and P3's names.

### 10.3 Step lists

- **deploy, data server, host a machine:** `resolve, prepare`, then P3's list from `source` unchanged.
- **deploy, app slot, mode `server`, host a machine:** `resolve, prepare, source, upload, manifest, ports, settings, build, backup, ⟨resize⟩ʳ, start, finish, ⟨first_admin⟩ᵃ, smoke, traffic`.
- **deploy, app slot, mode `slot`, host a machine:** `resolve, prepare`, then P3's list from `source` with `⟨resize⟩ʳ` after `backup`, before `⟨stop⟩ˢ` (or `start` when not seeding).
- **remove_slot:** `check, slot, ⟨machine⟩ᵐ` (built by `environments.env_steps_for`, S17).
- **teardown:** `check, unroute, undns, slots, data_server, ⟨machines⟩ᵐ, forget` (`env_steps_for`, S17).

The remove_slot and teardown lists stay per provider (Decision 15): a DigitalOcean environment's are P4 §14.3's (`check, slot` and `check, undns, slots, data_server, cloud, forget`). Both use `hosts.owned_by(env, host)` to delete the instance rows of owned hosts without SSH.
- **vm_snapshot, vm_revert, vm_drop:** §10.1 (ᵖ: `vm_snapshot` unless `skip_pre_revert`).
- **Every other kind, and every member on an SSH host:** P3's lists unchanged (M1).

ᵐ the slot's host (remove_slot) or any member's host (teardown) is a machine. ʳ §9.4's rule holds at queue time.

`prepare` runs right after `resolve`, for both providers (Decision 12; `resolve` runs on the Slipway server and needs no host), and is a change step: its failure fails the job and nothing after it runs; a cut-off during it ends the job CANCELLED with the machine's stage as it was. It runs inside the member-step timeout of 120 minutes, the sum of its parts (§14). After it, the deployer re-reads the host (`populate_existing`) so `SSHTarget.from_host` (ssh.py:94) carries the new pin. Its note and warnings follow P3 §8.4's rules for notes. `resize` is a change step in `PRE_START_STEPS` (P3 §8.4), inside a 90-minute timeout; nothing after `backup` and before it can refuse, so the deploy's refusals all precede it (D12, M9). P3 §14's "`prepare` … makes or resizes the VM" is refined here: `prepare` still lifts the unpinned-host refusal (a deploy whose step list contains `prepare`), but it follows `resolve`, and the resize is its own step.

### 10.4 Fences (`jobs.queue_job`, P3 §8.5)

In `jobs.queue_job` (S12):
- **The not-built rule** (Decisions 12, 28; P4 §3.3), for every provider host: P3's "host unpinned" refusal is replaced, for a host whose provider isn't `ssh`, by the not-built rule. A **deploy** of a member whose host isn't built (its step list contains `prepare`) is allowed; `remove_slot` and `teardown` are allowed on owned hosts in any phase (a planned VM that was never made can be removed); every other kind on such a member is refused `<green>'s server isn't built yet: deploy to <green> first` (the data server keeps its own text: `Deploy <env> first: its data server's VM isn't made yet`, and an Activate onto a VM that isn't made gets the activate's own `<green>'s VM isn't made yet: deploy to <green> first`). SSH hosts keep P3's unpinned refusal. `HostNotBuilt`, raised by `SSHTarget.from_host` on any path the fences didn't cover, answers 409 with its text.
- A machine in `destroying`: only the retry of the job that removes it.
- A deploy with `prepare` whose machine isn't `ready` and whose account can't be used (no secret, no pin): `<account> can't be used: <why>`. A `ready` machine's deploy goes ahead and `prepare` warns (§6.3).
- A retry with `forget_vms`: only of `remove_slot` or `teardown`, with the typed name and §4.1's permissions.

Elsewhere, each in the file that owns the path:
- Activate's host check (P3 §9.5 refusal 4, `environments.activate_problem` and `env_jobs.py`, S17) gives `<green>'s VM isn't made yet`, and refuses a slot whose VM is off (`<green>'s VM <vm> is off: deploy to <green> again to finish its resize`), read through `describe` in `check`.
- `validate_create` and Add slot (`environments.py`, S18): §9.2's refusal 0.
- `POST /instances` and a placement change (`api/v1/instances.py`), and the unmanaged-instance claim (`api/v1/unmanaged.py`), onto a host with `owner_environment_id`: `<host> is a VM of environment <env>; only its slots run there` (D18; S20). All use `hosts.owned_host_refusal`, which droplets share (Decision 7).

### 10.5 Locking

P3's runner keys cover every job above. Inside them: the Terraform lock row, PID check and folder lock (§7.3, M7) and the global `terraform_parallel` semaphore. ESXi sessions per account come from two pools that never wait on each other: **jobs** `esxi.job_sessions[account_id] = Semaphore(2)`, held for one provider call (`ensure`, `resize`, `snapshot`, …) and released between steps; **page reads** `esxi.read_sessions[account_id] = Semaphore(2)`, taken with a 5-second wait, else `live.error = "busy"` (`<account> is busy with other work; try again in a minute`), each read in its own short session. So a 30-minute disk copy never makes `GET …/machines` or `…/vm-snapshots` wait. Proxmox has no session; page reads use the 5-second timeout of §7.1. No machine operation holds `switchyard.lock`.

---

## 11. API

Everything under `/api/v1`. Queued jobs follow P3 §11's pattern. `MachineError` → 502 when the hypervisor couldn't be reached, else 409; `AccountInvalid` → 422 `{detail, field}`; `HostNotBuilt` → 409 with its text.

The accounts router is `slipway/api/v1/provider_accounts.py`, shared with DigitalOcean (P4 §16 has its rows: the unsaved-token `POST /provider-accounts/test` and `GET …/{id}/catalog`).

| Method and path | Permission(s) | Body | Answers |
|---|---|---|---|
| GET /provider-accounts | providers:read | `?provider` | 200 `[ProviderAccountOut]` |
| POST /provider-accounts | providers:write | `ProviderAccountIn` | 201; 409 `tls_untrusted`/`tls_mismatch` with `certificate`; 422 |
| GET /provider-accounts/{id} | providers:read | | 200 |
| PATCH /provider-accounts/{id} | providers:write | `ProviderAccountUpdate` (partial; an omitted secret is kept only while the URL and ESXi user are unchanged) | 200; 409; 422 |
| POST /provider-accounts/{id}/trust | providers:write | `{fingerprint}` | 200; 409 `tls_mismatch` (409 for a DigitalOcean account) |
| POST /provider-accounts/{id}/test | providers:write | | 200 `{status, checks, facts}`; 409 `test_stale`; 502 |
| DELETE /provider-accounts/{id} | providers:write | `{confirm}` (the name typed) | 204; 409 while machines or environments use it |
| GET /provider-accounts/{id}/addresses | providers:read | `?network&count` | 200 `{free: [ip], in_use: [{address, by}]}` (registry only, no probe; Proxmox and ESXi only) |
| GET /environments/{id}/machines | environments:read | `?blockers=true` | 200 `[MachineOut]` (with `live: MachineState`); 502 per account, as `live.error`. With `blockers=true` each VM also gives `blockers: [{text, forgettable}]` (`machines.blockers`, as Remove slot's and Delete's check read them, within `LIVE_LIMIT`) and `forgettable` (it has blockers and `forget_vms` gets past every one); both null when not asked or not read in time |
| PATCH /environments/{id}/machines/{slot} | machines:write | `{cores?, memory_mb?, disk_gb?, keep_vm_snapshots?}` | 200 `MachineOut`; 409; 422 |
| POST /environments/{id}/machines/{slot}/forget | machines:write + environments:delete | `{confirm}` | 200 `MachineOut`; 409; 422; 502 |
| GET /environments/{id}/vm-snapshots | environments:read | | 200 `[VmSnapshotOut]` (records joined with the live list); 502 as `error` |
| POST /environments/{id}/vm-snapshots | machines:write | `{note?}` | 202 `DeploymentOut` |
| POST /environments/{id}/vm-snapshots/{sid}/revert | machines:write + data:reset | `{confirm, skip_pre_revert?}` | 202; 409; 422 |
| DELETE /environments/{id}/vm-snapshots/{sid} | machines:write | | 202 |

**Changed endpoints:**
- `POST /environments`, `POST /environments/{id}/slots`: `hosts.<slot>` / the `SlotAdd` body take `{machine: MachineSpecIn}` (§9.2, §9.5). A claim conflict at the commit answers 409 `<address> was just taken by another environment: pick another address`, field `hosts.<slot>.machine.address` (Decision 43).
- `DELETE /environments/{id}`: `drop_data?: bool` (§9.9; needs `data:reset`), `forget_vms?: bool` (D26), in phase 4's `EnvironmentDelete`.
- `DELETE /environments/{id}/slots/{slot}`: body `RemoveSlotIn {confirm?, forget_vms?}`; `forget_vms` needs `machines:write` + `environments:delete` and the environment's name typed (§9.5, Decision 44).
- `POST /deployments/{id}/retry` (P3 §11): `forget_vms?: bool` for `remove_slot` and `teardown` (`machines:write` + `environments:delete`, typed name), asked again on each retry; a `vm_revert` retry asks the instance's name typed and applies `RETRY_EXTRA` (`data:reset`) on the member-job path too (Decision 37).
- `POST /hosts/{id}/claim` (unmanaged instances, `api/v1/unmanaged.py`) onto a host with `owner_environment_id`: 409, §10.4's text.
- `GET /environments/{id}`: `EnvironmentOut.machines: [MachineOut]` (records only; live state from the endpoint above), `actions` gains `resize: {slot: {available, reason, pending, applies_at}}`, `vm_snapshots: {available, reason}`, `forget: {slot: {available, reason}}`.
- Hosts (`api/v1/hosts.py`), for a host Slipway made (`hosts.owned_host_refusal`, which gives a droplet the same answers in its own words, P4 §3.3): PATCH of `hostname`, `proxy_address`, `lan_address`, `port`, `username`, credentials or `deploy_root` → 409 `<host> is a VM Slipway made for <env>; change it on the environment` (label and description stay editable); `DELETE` → 409 `<host> goes when <env> removes its <slot> slot`; `POST /hosts/{id}/check` while not built → 409 `Slipway pins <host>'s key itself when it makes the VM: deploy to <slot>`; reset-host-key → 409 `<host>'s key was pinned from <account>. If the VM was rebuilt by hand, use Forget the VM on <env>`.
- `POST /instances`: §10.4's 409.

**Schemas** (`slipway/schemas.py`; Decision 33):

```text
Network {name, bridge?, vlan_tag?, port_group?, subnet, gateway, dns_servers: [ipv4], pool: {first, last} | null}
ProviderAccountIn = ProxmoxAccountIn | EsxiAccountIn | DigitalOceanAccountIn   # discriminated on provider (P4 §16)
ProxmoxAccountIn {provider: "proxmox", name, secret?, trust_fingerprint?,
  url, node, pool, storage, template_vmid, networks: [Network]}
EsxiAccountIn {provider: "esxi", name, secret?, trust_fingerprint?,
  url, user, datastore, resource_pool, source_vm, networks: [Network]}
ProviderAccountUpdate {every field optional}
ProviderAccountOut {id, provider, name, production, has_secret, secret_hint (last 4 of the token id / "set"),
  status, checks, facts, last_checked_at, removed, used_by: [{environment, slot?, name?}],
  + Proxmox and ESXi: url, node or datastore fields, networks,
    tls: {fingerprint_sha256, subject, not_after} | null}
MachineSpecIn {account_id, network, address: ipv4 | "auto", cores?, memory_mb?, disk_gb?}
SlotAdd {host_id?, machine?: MachineSpecIn, confirm_cost?}   # SSH placement: exactly one of host_id and machine
RemoveSlotIn {confirm?, forget_vms?}
MachineOut {slot, name, account: {id, name, provider}, network, address, stage, size, applied,
  pending_resize: bool, applies_at: "next deploy" | "when idle" | "never (data server)" | null,
  keep_vm_snapshots, snapshot_mode, last_task, ready_at, last_error, host_id,
  live?: MachineState}                       # power, busy, hidden, error ("busy")
VmSnapshotOut {id, name, reason, status, taken_at, commit_sha, note, quiesced, sizes,
  on_hypervisor: bool | null, newest: bool, revert: {available, reason}, backups_after: [names]}
EnvironmentCreate.hosts.<slot>: uuid | {machine: MachineSpecIn}
EnvironmentDelete += {drop_data?, forget_vms?}               # phase 4's body (P4 §16)
HostOut += {owned_by: {id, name, slot} | null, built: bool, provider_state,
  machine: {stage, account} | null}
```

`used_by` replaces the earlier `machines` list (and P4's `environments`) for every provider (Decision 33).

---

## 12. Pages and slipway.js

Server-rendered, in the style of P3 §12.

### 12.1 Settings › Integrations (`settings/integrations.html`)

One Integrations page holds three account cards, **DigitalOcean** (P4 §17.1), **Proxmox** and **VMware ESXi**, from one account-list partial, with one `_account_dialogs.html` holding a field set per provider (Decision 33). The tab and page show with `providers:read` or `settings:write`; the account cards need `providers:read` and their buttons `providers:write`. The Proxmox and ESXi cards are each a list of accounts (Name · URL · Networks · Status chip with the last Test's time · VMs) and **Add account**. The account dialog: the provider's fields with hints (Proxmox: `The API token, user@realm!tokenid=<secret>. Slipway shows it never again.`; ESXi: `A local user with the Administrator role. Standalone ESXi can't limit it to some VMs; Slipway's markers are what protect the others.`), a **Networks** table (Name · Bridge and VLAN / Port group · Subnet · Gateway · DNS · Pool) with Add and Remove rows. Saving an untrusted certificate opens **Trust this certificate?** with its fingerprint, subject, issuer, expiry and names, and the hint `Compare the fingerprint with the one Proxmox shows under Node › System › Certificates` (ESXi: `…with "openssl x509 -in /etc/vmware/ssl/rui.crt -noout -fingerprint -sha256" in the ESXi Shell`). **Test** shows each check with its level. **Remove** asks for the account's name typed (`DELETE {confirm}`) and shows the 409 text when VMs use it.

### 12.2 The create flow (P3 §12.3)

Step 2's `Where` (P4 §17.2) offers `Hosts (servers you added, or new VMs on Proxmox or ESXi)` or `DigitalOcean`; VMs are under Hosts. Step 3 **Hosts**: each slot's select lists the SSH hosts (P3's rules) and, per usable account, `New VM on <account>`. Choosing one opens a sub-form: Network (select), Address (`( ) Pick one from the pool` / `( ) Type it`, the pool's next free addresses from `GET /provider-accounts/{id}/addresses`), vCPU, Memory (GB), Disk (GB), with the hint `Slipway makes slipway-<name>-<slot> at this address when its first deploy starts.` Once one slot is a new VM, the others' `New VM` options are limited to that account and network. Without `machines:write` the VM options are disabled with `Making VMs needs the machines:write permission`. Without `providers:read` no account is listed, nor its networks, subnets or pool (§11): the step says `New VMs on Proxmox or ESXi need the providers:read permission to choose an account.` when an account exists (with no SSH host the flow still shows, not `No hosts yet`, whenever any provider account exists), and the Add slot dialog (§9.5) offers no new VM. The `FIELD_STEP` map sends `hosts.*` fields to step 3. Step 7 **Review** lists each VM: name, account, address, size.

### 12.3 The environment page (P3 §12.2)

- **Slots** card: the Host column shows a VM as `<vm> on <account>` with the provider chip `Proxmox VM` or `ESXi VM` and a build chip, the one set droplets use (`Not built yet`, `Building`, `Ready`, `Gone`) plus the VM-only `Lost`, `Hidden` and `Off` (Decision 33), its address and size (`4 vCPU · 8 GB · 64 GB`), its live power state from `GET …/machines` (`Running`, `Off`, `Busy: snapshot`; `Couldn't check` with `live.error`), and `Resize pending: applies at <slot>'s next deploy` when `size ≠ applied`. Row actions: **Resize…** (machines:write; not on a ready data server), **Forget the VM…** (when `Lost` and allowed). `last_error` shows under the row while the machine isn't `ready`, or after a resize left it off.
- **VM snapshots** card (only for §9.6's shape): `data-load="/api/v1/environments/{id}/vm-snapshots"`. With `snapshot_mode = none` the card shows only `<storage> (<type>) can't take VM snapshots, so <vm> has none. Backups (above) still work.` and no buttons. Columns Name · Taken · Why (`By hand`, `Before a resize`, `Before a revert`) · Commit · Note · On <account> (`Yes` / `Not there any more`). Buttons **Take a VM snapshot…**, row **Revert…** (disabled with `revert.reason` on ZFS when newer snapshots exist: `Delete the newer ones first: <names>`), row **Delete…**. Lede: `A VM snapshot is the whole VM's disk at one moment: the app, its data and the system. Reverting loses everything written since, backups on the VM included. Backups (above) are the way to restore only the data.`
- The member banner of a VM slot's instance page adds `Its host is the VM <vm>, which Slipway made on <account>.`

### 12.4 Dialogs (`_environment_dialogs.html`)

- **Resize**: vCPU, memory, disk (minimum the applied disk); text `Applies at <slot>'s next deploy, after its backup: Slipway shuts <vm> down, resizes it and starts it again.` plus, for the active slot of two, `<blue> takes the traffic now, so this waits until you deploy to it after activating the other slot.`
- **Take a VM snapshot**: Note; `ESXi and Proxmox keep it beside the VM. VM snapshots slow some storage down: Slipway keeps the newest <n> it takes by itself, and those you take until you delete them.`
- **Revert**: `Puts <vm>'s whole disk back to <name> (<time>, commit <sha7>). Everything written since is lost, including these backups: <names>. Slipway first takes a VM snapshot of <vm> as it is now, so you can revert this too.` `[ ] Don't take that snapshot` ; typed name. **Revert**. On ZFS (`newest_only`) the snapshot sentence and the checkbox are replaced by `On ZFS storage this revert can't be undone: Slipway can't keep a VM snapshot of <vm> as it is now.`
- **Delete VM snapshot**: `Deletes <name> from <account>. It can't be undone.` **Delete**.
- **Forget the VM**: `<vm> isn't on <account> any more. Slipway forgets it and makes a new VM at <address> when you next deploy to <slot>.` Typed name.
- **Delete environment** (P3's) gains, when VMs exist, `These VMs are destroyed with their disks: <names>.` and, when the data is on one, `[x] Take a snapshot first` checked and, when unticked, the one `[ ] Delete <env>'s data with it` box (`drop_data`, `data:reset`; the same box P4 §17.4 uses for managed data) required. With `forget_vms` offered as on a retry (§12.5): when every VM's blockers are read (`GET .../machines?blockers=true`, when the dialog opens) and `forget_vms` gets past all of them, with the blockers named.
- **Remove slot** gains, when the slot's VM has blockers that are all forgettable (read with `?blockers=true` when the dialog opens, and named), `[ ] Forget the VM Slipway can't remove (you remove it by hand)` (`forget_vms`, with the typed name).
- **Deploy** (P3's) gains the §9.4 resize sentences and, for a planned VM, `Slipway makes <vm> first (several minutes).`

### 12.5 Other pages

- **Hosts** list and detail: a provider chip (`Proxmox VM`, `ESXi VM`; droplets `DigitalOcean droplet`) with the environment and slot, and the build chip; Check, Edit address, Reset key and Delete are hidden with `hosts.owned_host_refusal`'s reason in a title; a planned host's status reads `Not built yet`.
- **Deployment detail**: the `prepare` and `resize` steps' logs; the VM kinds' labels; a revert's notice. Retry of a failed `remove_slot` or `teardown` whose `check` or `machine(s)` step failed on a forgettable blocker offers `[ ] Forget the VMs Slipway can't remove (you remove them by hand)` beside P3's `forget_traffic`, with the typed name; the dialog reads the blockers when it opens (`?blockers=true`, the job's slot or every VM) and hides the box when `forget_vms` would not get past them.

### 12.6 slipway.js

1. `wireEnvFlow` (P3): the VM sub-form, the addresses call, the account and network lock-step, `FIELD_STEP` for `hosts.<slot>.machine.*`.
2. `renderers.vm_snapshots(el, data)`: the card's rows and buttons (`data-open` for the dialogs).
3. `wireAccountForm(root)`: one form for every provider against `/api/v1/provider-accounts`: the networks table rows, the trust dialog from a 409 `tls_untrusted` answer (re-submits with `trust_fingerprint`).
4. `STATUS`/`STEP_BADGE` know all five new kinds: `vm_snapshot`, `vm_revert`, `vm_drop` (`running` reads Snapshotting, Reverting, Deleting) and phase 4's `certificate` and `deactivate`.

---

## 13. Image and dependencies

### 13.1 Dockerfile

A build stage as Sirdar's (`sirdar/Dockerfile:15-45`): `FROM python:3.13-slim AS terraform`, `ARG TERRAFORM_VERSION=1.16.5`, `ARG PROXMOX_PROVIDER_VERSION=0.115.0`, a SHA-256 per architecture (amd64, arm64) for each zip, `sha256sum -c`, Terraform unzipped into `/usr/local/bin`, the provider zip placed in the filesystem mirror `/opt/terraform/providers/registry.terraform.io/bpg/proxmox/`. The final image copies both, `docker/terraformrc` to `/etc/slipway/terraformrc`, and installs `requirements-esxi.txt` with `pip install --require-hashes --no-deps` before `pip install .` (`sirdar/Dockerfile:58-64`). `terraform_dir` is created by Slipway at run time under the mounted storage folder, mode 700 (Dockerfile at 83dca5d already makes `/var/lib/slipway` uid 10001, mode 700).

`docker-compose.yml` gains `stop_grace_period: 60s` on the `slipway` service (D27). At 83dca5d it sets none, so Docker's 10-second default applies. docs/machines.md says that a shorter grace leaves half-made VMs for the next deploy to clean up.

### 13.2 `docker/terraformrc`

```hcl
disable_checkpoint = true
provider_installation {
  filesystem_mirror {
    path    = "/opt/terraform/providers"
    include = ["registry.terraform.io/bpg/proxmox"]
  }
  direct { exclude = ["*/*"] }
}
```

`init` never goes online and can't pick up a provider that wasn't checksummed.

### 13.3 The Proxmox role (docs/machines.md, and what Test checks)

From `SR/README.md` (the Proxmox section), with Slipway's names. Two users are told apart: the Proxmox API user `slipway@pve`, whose token Slipway holds, and the `slipway` Linux user that cloud-init makes on each VM (`cloudinit.GUEST_USER`, with passwordless sudo through `ciuser` taking over the Ubuntu cloud image's default user, which holds only for Ubuntu cloud images). Role `SlipwayProvision` with `VM.Allocate VM.Clone VM.Audit VM.PowerMgmt VM.Config.CDROM VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network VM.Config.Options VM.Snapshot VM.Snapshot.Rollback VM.GuestAgent.Audit VM.GuestAgent.FileRead Datastore.AllocateSpace Datastore.Audit SDN.Use Pool.Audit Sys.Audit` (Proxmox 8: `VM.Monitor` in place of the two `VM.GuestAgent` ones); a user `slipway@pve`; ACLs on `/pool/slipway`, `/storage/<storage>`, `/sdn/zones/localnetwork/<bridge>` and optionally `/nodes/<node>`; a token with `--privsep 0`. The template: Ubuntu 24.04's cloud image with `qemu-guest-agent` added by `virt-customize`, `/etc/machine-id` truncated, `/etc/ssh/ssh_host_*` deleted and `cloud-init clean` run (so no clone starts with the template's host key, §7.4 C7), boot disk `scsi0`, cloud-init drive `ide2`, `--agent enabled=1`, `--ciupgrade 0`, inside the pool. Docker may be preinstalled in it (D14). The VMs need a reachable Ubuntu mirror for the Docker install. Storage: LVM-thin, ZFS, Ceph or a file storage (qcow2) for VM snapshots; thick LVM works but has none (D23).

### 13.4 Python

`pyproject.toml`: `pyvmomi==8.0.3.0.1` (8.0.3 still supports ESXi 7; Sirdar's pin, `sirdar/api/pyproject.toml`) in the `dev` extra and in a new `esxi` extra, and `[tool.setuptools.package-data] slipway = ["terraform/**/*", "terraform/**/.terraform.lock.hcl"]` (setuptools' `*` skips dotfiles). pyvmomi 8.0.3.0.1 is an sdist, so the image's `--require-hashes` install builds it with a build backend pip doesn't hash-check; the Dockerfile says so, and pre-building a pinned wheel waits for the networked session (§16.3 item 18, Decision 36). `requirements-esxi.txt`: `pyvmomi==8.0.3.0.1` and `six==1.17.0` with their PyPI hashes (`sirdar/api/requirements-esxi.txt:1-9`). Nothing else is new: httpx, asyncssh, cryptography and pyyaml are already there (pyproject.toml at 83dca5d).

---

## 14. Concurrency, limits, timeouts

- One job per environment (P3 D8). Terraform: `terraform_parallel` processes across Slipway (default 2), one per state (M7). ESXi: two job sessions and two page-read sessions per account at once (§10.5).
- Calls: Proxmox 30 s (page reads 5 s); ESXi 30 s, sign-in 35 s; the TCP probe 3 s; each name lookup 2 s; the certificate fetch 10 s.
- Terraform commands: `init` 5 min, `plan` 10 min, `show` 2 min, `apply` 40 min (the module's `timeout_clone` is 30 min inside it), `destroy` 20 min; then SIGINT, SIGKILL after 30 s; the container's stop grace 60 s (D27).
- Hypervisor tasks: Proxmox clone 30 min (inside `apply`), other tasks 10 min; ESXi disk copy 30 min, other tasks 10 min; waiting for a task already running (D24) 10 min; a snapshot's late-task grace 15 s.
- **`prepare`'s parts**, each with its own limit, which the step's error names when it runs out. A new Proxmox VM: registry and probe 1, plan 10, apply 40, agent address 5, `boot-finished` 10, host key 5, pin 5, bootstrap 40 (sudo 0.5, cloud-init 10, Docker 25 with apt's lock wait of 10 inside it, service 2, group 1, folder 0.5, check 1): 116 min. A new ESXi VM: registry, guest IPs and probe 1, create 1, disk copy 30, attach and grow 10, Tools' address 5, pin 5, scrub 1, bootstrap 40: 93 min. A ready VM: a few seconds, plus a start and the address wait (5) when it was off, plus `check_resize`'s plan (10). The step's overall limit is 120 min.
- **`resize`'s parts**: Proxmox: plan 10, `pre_resize` 10, shutdown 5, plan 10, apply 40, address 5, pin 5, start the release 2: 87 min. ESXi: `pre_resize` 10, shutdown 5, size, snapshot deletes and grow 10, power on 1, Tools' address 5, pin 5, start the release 2: 38 min. The step's limit is 90 min.
- Other job step timeouts (§10.2's catalogues): `machine` 30 min, `machines` 60 min; `vm_snapshot` 35 min; `prune` 45 min; `vm_revert` 30 min; `vm_drop` 25 min (each holds the task waits inside it, review F36); `wait` 10 min; `vm_settle` 2 min.
- Limits: three machines per environment (blue, green, data); 10 `manual` VM snapshots per VM; `keep_vm_snapshots` 1-10; a Terraform state of at most 4 MiB; 20 networks per account; a pool of at most 4096 addresses.

---

## 15. Room for phases 4 and 6

- **Phase 4 (DigitalOcean)** shares a host-level contract with this phase, not the machines core (Decision 1). It shares migration 0010 (`provider_accounts`, with its DigitalOcean config, P4 §3.1, and `hosts.provider_state`), planned host rows from `hosts.planned_host`, the phase key and `Host.is_built`, `ssh.HostNotBuilt`, the not-built rule, `hosts.owned_host_refusal`, `hosts.owned_by`, `hosts.address_holder`, the slot host name `slipway-<env>-<slot>`, the `slipway` user's name (`cloudinit.GUEST_USER`; droplets keep their own user-data and no sudo), and the one `prepare` and one `resize` step key that the deployer dispatches by provider (P4 §3.3, §9.4, §14.2). It uses none of `machines`, `machine_snapshots`, `terraform_states`, `address_claims`, `MachineProvider`, `machines.pin`, `bootstrap` or `reserve_vmid`: droplet state lives in `hosts.provider_state` and `resources` rows, with DigitalOcean's own intent rows (P4 §6.4). Its pinning differs and stays its own: the generated public key is written into `host_key` before `POST /droplets` and the private half is never stored (P4 D4), so nothing is wiped after the pin. The rule both keep is that a provider host's key is written only by its provider's `prepare`, with no trust on first use (Decision 8). The resize rule is the same: in the shared `resize` step after `backup`, never on the active slot of two (P4 §9.4, D12 here).
- **Phase 6 (retire Sirdar).** Sirdar's VMs carry the `sirdar` tag and `sirdar.environment` marker, never Slipway's (D20), so neither tool touches the other's VMs. Slipway's registry doesn't know Sirdar's addresses, but the TCP probe and ESXi's guest-IP check refuse a running one. Use separate Proxmox pools and tokens for the two during the overlap. Sirdar removes its own VMs before it is shut down.

---

## 16. Tests

### 16.1 Fakes

- **`tests/fake_proxmox.py`** (new): `FakeProxmox(state_path)`, an httpx `MockTransport` handler whose state is a JSON file, so the fake Terraform (another process) and the fake API see the same VMs. It checks `Authorization: PVEAPIToken=…`, and models nodes, the pool, the template, VMs (id, name, node, tags, status, config, the agent's addresses and host key file, snapshots), tasks with UPIDs (ok, error, never finishing), `/cluster/nextid` (with `?vmid=`) and `/access/permissions`. Knobs: `agent_late(n)`, `agent_wrong_address()`, `deny(path)`, `task_fails(kind)`, `snapshot_task_late()` (times out, then appears), `reuse_vmid(vmid, name)` (someone else's VM), `remove_vm(vmid)`, `move_node(vmid)`, `untag(vmid)`, `resize_refused_with_snapshots()`. It behaves as Proxmox where the design depends on it: tags are stored sorted; `/cluster/resources` lists only VMs in the token's pool, while `/cluster/nextid?vmid=` answers for every VM; `storage_type` (`lvmthin`, `zfspool`, `lvm`, `dir` with a `file_format`) drives `…/feature?feature=snapshot` and, on `zfspool`, refuses a rollback to any snapshot but the newest with Proxmox's text; a clone made through the fake Terraform starts with name, description and pool, no tags and `lock: clone`. More knobs: `hidden(vmid)` (a VM outside the pool at that id), `clone_lock_outlives(n)` (the clone task and lock stay for n polls after Terraform dies), `task_outlives_cancel(kind, n)` (a snapshot or rollback task that keeps running for n polls after Slipway stops waiting), `stale_template_key(n)` (the key file holds the template's key for n reads, and `boot-finished` is missing until then), `stale_lock(vmid, lock)` (a lock with no task), `template_ciupgrade(on)`.
- **`tests/bin/fake-terraform`** (new, a Python script; tests write a `fake-terraform` wrapper naming `sys.executable`): `version -json`, `init` (requires `TF_CLI_CONFIG_FILE`; with `-lockfile=readonly` refuses a `.terraform.lock.hcl` whose version or hash doesn't match its provider, as Terraform does), `plan -out` (reads the tfvars, its state and `$FAKE_PVE_STATE`; plans create, update, replace when tainted, or nothing, as `bpg/proxmox` does; `clone` changes ignored; a tag list in another order than the VM's sorted one shows as a change; refuses with "doesn't match the dependency lock file" when `.terraform` was initialised for another provider version), `show -json`, `apply tfplan` (clones in `$FAKE_PVE_STATE` as two writes, the clone then the tags, writes `terraform.tfstate` with serial + 1 and a lineage, holds `.terraform.tfstate.lock.info` while running), `destroy -auto-approve`, `state rm`. Knobs from `$FAKE_TF_SCRIPT`: `fail_after_clone` (the VM exists, the state has it tainted), `die_after_clone` (the VM exists untagged with `lock: clone` for `clone_lock_outlives` polls, no state: a SIGKILL), `hang` (until SIGINT, then writes its state and exits 1), `ignore_sigint`, `print` (lines such as the token or one of 2 MiB), `plan_extra` (adds a delete or another resource), `lineage`. Every run's argv, environment names and cwd go to `$FAKE_TF_LOG`.
- **`tests/fake_esxi.py`** (new): `FakeEsxi`, an in-memory `EsxiApi` that behaves like ESXi where Slipway depends on it (Sirdar's `api/tests/fake_esxi.py`): unique names, VM folders (a VM created where a folder of its name exists goes in `<name>_1/`, as ESXi does), copy, attach and grow (no grow with snapshots), size changes only while off, revert leaves the VM off, destroy refused while on and deleting only attached disks (an unattached file stays in the folder), Tools addresses, extraConfig, snapshot deltas, the datastore browser, `recentTask`; knobs for quiesce failure, task timeouts, a late snapshot, apiType and licence, `task_running(kind, n)` (a task in `recentTask` for n polls), `copy_cut(n)` (a copy that leaves a partial file), `copy_cancelable(bool)`.
- **`tests/fake_vim.py`** (new): just enough pyvmomi stand-ins (`Task`, `VirtualMachine` with `config.extraConfig`, `guest.net`, the snapshot tree and disk backings; `ServiceInstance.content` with `searchIndex`, `viewManager`, `virtualDiskManager`, `about`, `licenseManager`) for `PyvmomiEsxi`'s unit tests.
- **`tests/fake_vm_hosts.py`** (new, S11a): it extends the common part of `tests/fake_hosts.py` that S06 builds for both phases (an address-keyed `MultiRemote`, per-address host keys raising `HostKeyMismatch`, `booting(n)`, `firewalled(ip)`; Decision 30) with only the VM shims. Each fake VM has its own host key; the connect factory raises `HostKeyMismatch` when the target's pinned key differs and `SSHError` while the VM is "booting" (a counter); `sudo`, `cloud-init`, `apt-get`, `usermod`, `id -nG slipway`, `install`, `docker info`, `docker compose start` and `df` shims answer the bootstrap from per-VM state (`docker compose version` fails until `apt-get install` ran). Knob `dpkg_locked(n)`: `apt-get` without `DPkg::Lock::Timeout` fails at once with "Could not get lock /var/lib/dpkg/lock-frontend"; with it, it waits n polls and goes on (or fails with the lock text when n is beyond the timeout).
- **Guard** (`tests/hypervisor_guard.py`, new in A2: the fixture `no_real_hypervisors`): `terraform._spawn` allows only a `fake-terraform` path; `esxi._smart_connect`, `machines.tcp_open` and `machines.resolve` fail the test unless replaced; `tls_pin.read_certificate` only reaches 127.0.0.1; `proxmox.transport_factory` raises unless replaced. Each patch is applied only when its module imports (so A2's file works before A3-A5 and B1 exist). A blocked attempt fails the test at teardown (Sirdar `api/tests/conftest.py:173-224`). From S01 on, `tests/conftest.py` registers the module (`pytest_plugins = ["tests.hypervisor_guard"]`) and makes the fixture autouse, with an alias fixture `no_real_clouds`, and the guard also replaces the `transport_factory` seams of `digitalocean`, `spaces`, `acme`, `cloudflare`, `switchyard` and `traffic` (the public check) with an `httpx.MockTransport` whose handler raises `RealHypervisorCall` naming the system, so building a client stays harmless and only a request fails (Decision 29, P4 §20.1). `github.py`'s `transport_factory` (used when a caller passes no `transport`) is guarded the same way, and `asyncssh.connect` and `asyncssh.get_server_host_key`, which `ssh.connect` and so `ssh.probe` and `hosts.check_host` dial through, reach only loopback (or a name that can't be encoded, which never leaves the machine).
- **`tests/vm_fixtures.py`** (S11a): builders for a Proxmox and an ESXi account row with a trusted certificate, and an environment with planned VM hosts and machines.
- **Phase 3 goldens** (S06, Decision 31): recorded on the untouched phase 3 engine from a frozen copy of the phase 3 example, `tests/golden/serversherpa_p3.slipway.yml`; test 64 is this check.

### 16.2 Numbered tests (slice in brackets)

The brackets name this spec's original slices (A1-E). The plan's slices (§17) carry the same numbers: each slice's section lists the tests it runs (S01 moves A2-A5's, S03 has 1-2, S11a has 18-22, and so on).

1. [A1] Migrations: 0010 creates `provider_accounts` (with `hosts.provider_state`) and 0012 creates `machines` (with `CHECK (provider IN ('proxmox','esxi'))`), `address_claims`, `terraform_states` and `machine_snapshots`, each with its constraints and NAMING_CONVENTION names; 0012's `down_revision` is `0011`; none inspects the database to decide what to create; downgrade round trips on SQLite (and PostgreSQL with `SLIPWAY_TEST_DATABASE_URL`); 0012's downgrade refuses with any machine, 0010's with any account or provider host; `ProviderKind` is the enum's name and no model is called `MachineProvider`.
2. [A1] Constraints: a second claim of one address raises IntegrityError; two machines on one host; `(account_id, name)`; `(environment_id, slot)`; the provider, stage and `snapshot_mode` CHECKs; RESTRICT on `terraform_states` and `provider_accounts`.
3. [A2] `tls_pin`: `load_one` refuses two certificates, garbage and empty; `pinned_context` trusts exactly one, allows a partial chain, needs TLS 1.2; `check_hostname=False` for ESXi; the fingerprint format.
4. [A2] `vmnet.check_network_profile` and `check_address` over Sirdar's table (prefix 8-30, network, broadcast, multicast, link-local, reserved, 0/8, loopback without the switch, a gateway outside or equal); pools (inside, ordered, excluding gateway, network, broadcast); `allocate` takes the lowest free address, skipping claims and in-use ones.
5. [A2] Names (`slipway-<env>-<slot>`, a 26-character environment), sizes, `keep_vm_snapshots`, DNS servers (at most 3, canonical), snapshot names round-trip.
6. [A2] `cloudinit.metadata`/`userdata` exact YAML (the user `slipway`, `cloudinit.GUEST_USER`, with passwordless sudo); `guestinfo` base64 and encodings; `scrub`; a bad CIDR, host name or DNS server raises before any YAML.
7. [A3] Proxmox client against FakeProxmox: the token header; the pinned transport; every error mapped to Slipway's text (never the upstream one); task waits (OK, WARNINGS, error, timeout); `find_vm` across nodes; `agent_ipv4` filtering; `agent_file`; snapshots without `current`, with parents and the newest marked; `next_vmid`; `vmid_free` answering "used" for a VM `find_vm` can't see (`hidden`); `vm_tasks`, a VM's `lock`, `snapshot_feature`, `storage_info`'s type; `delete_vm`'s query; page reads give up after 5 s; `clean_config`'s rules. Which of name, description and pool the provider's clone call carries is pinned here (§7.4's `_our_clone`).
8. [A3] Proxmox Test: node, pool, template (not a template, agent off as a warning, `ciupgrade` on as a warning), storage (type, content and free space written to `facts`; `lvm` a warning, `zfspool` a note), bridge 403 as a warning, missing privileges named.
9. [A4] Runner: only the allowlisted environment reaches the fake (`$FAKE_TF_LOG`); the token is in the environment and in no argv or file of the working folder; `SSL_CERT_FILE`/`SSL_CERT_DIR`/`HOME`.
10. [A4] Runner output: streamed line by line through the redactor (a printed token is hidden); a 2 MiB line is dropped and reading goes on; a timeout sends SIGINT to the group (the fake writes its state), SIGKILL after the grace when it ignores SIGINT; a cancel does the same and re-raises; a second cancel during the SIGINT grace doesn't cut the grace short; each command gets its own timeout (`init` 5, `plan` 10, `show` 2, `apply` 40, `destroy` 20 min, patched short).
11. [A4] `plan_changes`: create, update, replace both orders, delete, no-op; a malformed document raises `PlanUnreadable`; `show` output is never logged.
12. [A4] The module: every variable in `variables.tf` is a key Slipway writes in `terraform.tfvars.json` and back; `required_version` and the provider version equal `TERRAFORM_VERSION` and `PROVIDER_VERSION`; `.terraform.lock.hcl` names that provider version; `reboot_after_update = false`; `timeout_clone = 1800`; `ignore_changes = [clone]`; `initialization`'s `username` equals `cloudinit.GUEST_USER`; `initialization.upgrade = false` present exactly when the recorded 0.115.0 schema has it; `tags` written sorted; `file_format` qcow2 for `dir`/`nfs`/`cifs`/`glusterfs` and raw otherwise; no secret in the tfvars.
13. [A4] Working folder: mode 700; the CA file must be one certificate (refused before anything is written); reconcile with an in-memory `StateStore`: store newer → written to the folder; folder newer with the same lineage → saved first and logged; a row with NULL lineage and a folder state → the folder's saved; different lineages → refused; a state over 4 MiB → refused on save. `init` runs when `.terraform` is missing or `slipway-init.json` names another module hash or Terraform version, and not otherwise; the shipped lock file is copied in; after a fake provider upgrade, `plan` without re-init fails with the lock-file text and the session's re-init makes it pass.
14. [A4] Locks: the store's compare-and-set refuses a lock held by a running deployment and takes over one held by a finished one, and one whose deployment row no longer exists (logged); a live PID in `slipway-run.json` refuses; a dead one is ignored; the lock is released and the state saved after success, failure, timeout and cancel.
15. [A5] FakeEsxi behaves as ESXi in each listed respect (its own test, as Sirdar's).
16. [A5] `PyvmomiEsxi` over `fake_vim`: task states and fault mapping; `QuiesceFailed`; `guest_ipv4` (real vNICs, no link-local); `owner_of`; `create_config` (PVSCSI, vmxnet3, `disk.EnableUUID`, both markers, guestinfo keys); `_smart_connect` arguments (thumbprint, `check_hostname=False`, timeout); calls run on the one-thread executor.
17. [A5] ESXi Test: `VirtualCenter` refused; `esxBasic` refused; datastore, port groups, resource pool, and each seed rule; `clean_config`'s rules; on a timeout or cancel `PyvmomiEsxi` cancels a `CopyVirtualDisk` task that is `cancelable` and no other kind.
18. [B1] `machines.pin`: a real asyncssh server on 127.0.0.1 (`ALLOW_LOOPBACK`) presenting the expected key → pinned by compare-and-set and audited with `how`; another key → `pinned nothing`, no write; with `reread_key`, a mismatch re-reads and pins once the key read matches, and still pins nothing when it never does; retries while the port refuses; refused at another host's address; a concurrent address change → nothing written.
19. [B1] The registry: in use via a host's `hostname`, `proxy_address`, `lan_address` (names resolved through the patched resolver), a claim, an account's API host, Switchyard's URL and traffic address, the gateway, a DNS server; each refusal names the holder.
20. [B1] `machines.plan`: the host row's fields (named `slipway-<env>-<slot>`, user `slipway`, unpinned, generated client key, provider, owner, phase `planned`), the claim, the machine (`planned`, frozen spec, network, size), ESXi's encrypted host key pair; a taken host name; a claim conflict at commit writes nothing.
21. [B1] The driver: stage changes each in their own transaction, with `hosts.provider_state.phase` in the same one; `check_host(..., building=True)` after bootstrap fills Docker's version; `ready_at`, `applied`, `snapshot_mode`, `last_error` written; on a ready VM with the API down and no resize, the step is a `warning` and nothing else runs; with a resize to apply, the API down fails it; `check_resize` runs (reads only) and its refusal fails `prepare` with the "set the size back" text; `prepare` never shuts a ready VM down (FakeProxmox saw no shutdown, FakeEsxi no `shutdown_guest`); a part that runs out of time is named in the error; any other failure keeps `last_error`.
22. [B1] Bootstrap against `fake_vm_hosts`: the commands in order through `sudo -n`, naming the `slipway` user; both `apt-get` calls carry `-o DPkg::Lock::Timeout=600`; with `dpkg_locked(n)` the install waits and succeeds, and beyond the timeout fails with the lock text; Docker installed only when `docker compose version` fails; a new session after `usermod`; each refusal text (no sudo, cloud-init timeout, apt failure); running it twice changes nothing.
23. [B1] Proxmox, new VM, end to end (FakeProxmox, fake Terraform, fake VM host): registry check → probe → id reserved and the resource row committed **before** the first Terraform run → plan, show, check → `creating` → apply → state saved to `terraform_states` → `booting` → agent address → `boot-finished` → agent key → pin → bootstrap → `ready` with `snapshot_mode`; the token in no argv, file or log line.
24. [B1] Id race: two machines of different environments get the same `nextid`; the second counts it taken (another machine's row) and takes the next id; 20 taken ids give the text; a crash between the row and `ids.vmid` gives the id back on the next run.
24b. [B1] Same environment: blue reserves 106 and fails before its clone; green's `nextid` answers 106; green skips it (blue's row names blue) and reserves 107; blue's row still has `details.machine_id` = blue and its name; an id held only by another machine's `ids.vmid` is skipped too; no `vm` row's `machine_id` ever changes.
25. [B1] Proxmox half-made, every Proxmox row of §9.11: tainted after `fail_after_clone` → the retry's replace is allowed after the identity check; `die_after_clone` (untagged, `lock: clone` for 3 polls) → Slipway waits for the lock, recognises the clone by name, node, pool and description, deletes it through the API (`machine.rebuild`) and makes it again; the lock outliving the 10-minute wait (patched short) → `still cloning`, nothing deleted; a foreign VM at the id with the state empty → re-reserved while `planned`, `creating` or `booting`; a foreign VM while the state has the resource → refused; an id used by a hidden VM with the state empty → re-reserved, with the state holding it → refused naming the pool rights; gone while `booting` (`nextid` free) → dropped from the state and made again.
26. [B1] Proxmox ready: no Terraform run, a stopped VM is started, the address checked; gone (`nextid` free) → the lost text; hidden (`nextid` used) → the pool-rights text; untagged, renamed, or on another node → refused with nothing changed (FakeProxmox saw only GETs).
27. [B1] Proxmox `check_resize` and `resize`: the first plan (an update of sizes only, no tag change because tags are sorted), the `pre_resize` snapshot recorded before its task (none with `snapshot_mode = none`), the shutdown, the second plan equal, apply, start, the same key, the applied size returned; a plan with a delete or another attribute refuses in `check_resize`; a qcow2 grow with snapshots refuses in `check_resize`; a shutdown timeout leaves the VM running at its old size; a failed apply starts the VM again and re-reads its size; the growpart warning.
28. [B1] Proxmox snapshots: `snapshot_mode` from the storage type and the feature check (`lvmthin` any, `zfspool` newest_only, `lvm` none, `dir` qcow2 any, raw none); the row is `pending` and the UPID in `last_task` before the wait; a late task (`snapshot_task_late`) ends `ready` after the grace; a failed one `failed`; revert starts the VM and re-checks the address; on `zfspool` FakeProxmox refuses a rollback to an older snapshot with Proxmox's text, which Slipway never reaches because `check` refuses first (test 47); drop.
29. [B1] Proxmox `destroy_blockers` and `destroy`, every case of §7.7: never made; reserved and never ours (released); ready, not visible and `nextid` free → `already gone`, the state row, resource row and folder go; ready and hidden (`nextid` used) → a forgettable blocker, nothing removed; ours in the state (`destroy`, then gone); ours not in the state, tagged or not (API delete after the lock wait); still there afterwards (refused); a running task → a blocker that isn't forgettable.
30. [B1] ESXi, new VM, end to end: the API-host check; the registry, guest-IP check and probe; `create_vm` with both markers and guestinfo; ids and the resource recorded at once; the disk copied, attached and grown; powered on; Tools' address; pinned with the generated key; the user-data scrubbed and `host_key_private` NULL; bootstrap; `ready`.
31. [B1] ESXi half-made: a lost record adopted by its marker (audited); the same name with another owner refused; a half-copied disk deleted only when unattached (attached → refused), after a running copy is waited for; a recorded UUID gone while `creating` → the old `vm` row forgotten, a new VM made and recorded with no `ResourceTaken`, `machine.rebuild` audited; a leftover `<vm>/` folder holding only Slipway's disk → cleaned before create (no `<vm>_1/`); one holding other files → refused before create; ready and gone → the lost text; a foreign disk refused.
31b. [B1] ESXi host key regeneration (E1): no VM → a new pair; a VM in `creating` → a new pair and `guestinfo.userdata` rewritten before `power_on`, then the pin succeeds; a VM in `booting` → destroyed and made again with a new pair (`machine.rebuild`); a readable pair is never replaced.
32. [B1] ESXi `check_resize` and `resize`: cores and memory with a `pre_resize` snapshot; a grow with a foreign or duplicate snapshot refused in `check_resize`; a grow deleting Slipway's snapshots (rows `missing`); a shutdown timeout leaves it on at the old size; a failure while off leaves it off with the retry text and the environment notice.
33. [B1] ESXi snapshot (quiesce, then crash-consistent), late task, revert (powered on after), duplicate names never picked, `destroy_blockers` (each forgettable or not), destroy (an unattached `<vm>-disk0.vmdk` deleted first, powered off, gone afterwards, the folder checked and leftovers named as a warning).
34. [B1] The database `StateStore`: lineage, serial and sha saved in their own transaction (they survive the caller's rollback); `lock_id` compare-and-set on SQLite and PostgreSQL; recovery clears the lock of an interrupted deployment.
35. [A2, B1] The guard: a test that calls the real `_spawn`, `_smart_connect`, `tcp_open` or a non-127.0.0.1 certificate fetch fails at teardown; A2 tests the fixture with stand-in modules; S01 that it is autouse and that each of the six HTTP seams of P4 §20.1 raises on a request when not replaced, while building a client doesn't.
36. [B2] Accounts API (`/api/v1/provider-accounts`, `providers:read` to list, `providers:write` to change): create without trust → 409 `tls_untrusted` with the certificate and nothing written; with the matching fingerprint → stored; a wrong one → 409 `tls_mismatch`; secrets write-only (`has_secret`, `secret_hint`); every `clean_config` rule with its `field`; audit rows without secrets.
37. [B2] Update (`PATCH`) and remove (`DELETE {confirm}`): the secret reused only with the same URL (and ESXi user); a URL change while a machine uses the account → 409; a used network can't be removed or renamed; delete refused while used, a tombstone when only deleted rows point at it; a URL change forgets the pin.
38. [B2] Test endpoint answers and stores `status`, `checks` and `facts` (both `run_test` shapes normalised); the addresses endpoint lists free pool addresses and who holds the others, with no probe.
39. [B3] Image: the Dockerfile's Terraform and provider versions equal the module constants; each architecture has a SHA-256 line; `requirements-esxi.txt` pins the pyproject version with hashes and is installed with `--require-hashes --no-deps` before `pip install .`; `terraformrc` allows only the mirror; the module's `.terraform.lock.hcl` `zh:` hashes equal the Dockerfile's per-architecture SHA-256; `docker-compose.yml`'s `slipway` service has `stop_grace_period` of at least 60 s, more than the Terraform SIGINT grace (30 s) plus a margin.
40. [C1] `steps_for`: a member deploy on a machine lists `resolve` then `prepare` first, and `resize` after `backup` and before `stop`/`start` only when §9.4's rule holds (never for the data server or the active slot of two); members on SSH hosts, standalone instances and every data kind are unchanged (P3's golden files).
40b. [C2] `env_steps_for`: `remove_slot` and `teardown` list `machine`/`machines` only when a machine is involved.
41. [C1] Fences in `queue_job` (the not-built rule): a deploy is queued on a not-ready machine's host; `remove_slot` and `teardown` are queued on an owned host in any phase; backup, restore and the rest are refused with §10.4's texts; P3's unpinned refusal stays for SSH hosts; a `destroying` machine refuses all but the retry; an unusable account refuses the deploy; `forget_vms` only on a `remove_slot` or `teardown` retry, with the typed name and both permissions.
42. [C1] Pipeline: `resolve` runs, then `prepare`; a `prepare` failure fails the job and nothing after it ran (no `source`, no upload); after it the deployer's SSH target carries the new pin; a cut-off in `prepare` ends CANCELLED with the stage as it was.
43. [C1] The resize rule and step: a pending resize is applied in `resize` on a single slot's deploy and on the idle slot's; never on the data server, never on the active slot of two (the step is `skipped` and says it waits, also when the slot became active after queueing); a planned VM is made at `size` with no resize. A deploy whose `manifest` step fails, one whose `settings` probe fails, and one refused by the lag check in `backup` never shut the VM down (the fake hypervisors saw no shutdown). After `resize` the live release's projects are started when the instance is RUNNING (`docker compose start` ran), so a deploy that fails at `start` leaves the old release up; on the idle slot of two, its live release is running again after the step (what Switch back needs). A `resize` that leaves the VM off sets the environment's notice.
44. [C2] Blue/Green on three new Proxmox VMs (P3's chain, test P3-30's shape): the data server's deploy makes the data VM first and its `.env` names the planned blue and green addresses as clients; blue's deploy makes blue's VM; the chained activate makes the environment live; Switchyard upstreams are the VMs' addresses.
45. [C2] Mixed: blue on an SSH host, green and the data server on new ESXi VMs; green's deploy makes its VM; activate; nothing about blue changes.
46. [C1] `vm_snapshot`: each refusal of §9.6; the row with `app_state`, identity, backups and sizes committed before the task; prune keeps the newest automatic ones and never a manual one or an ESXi duplicate.
47. [C1] `vm_revert`: the typed name is checked first (422), then `data:reset` (403); each refusal of §9.7; `pre_revert` taken (kept by a retry); revert; `wait` with the same key; `vm_settle` empties `.slipway-lock`, restores `app_state`, `fresh_data`, `live_identity` and `applied`, clears the hold and `data_dirty`, writes the identity secrets with `secrets_version` + 1 when they differ, and marks backups taken since `missing`; `restart` failing leaves records matching the VM; `traffic` is warning-only; the notice names the lost backups. On `zfspool`: a revert to a snapshot that isn't the newest is refused in `check` (the fake saw only GETs), no `pre_revert` is taken for the newest, and the rollback succeeds; with `snapshot_mode = none`, `vm_snapshot`'s `check` refuses (the API's 409 is test 59's, the card test 62's).
48. [C1] `vm_drop` deletes on the hypervisor and the row; a name gone from the hypervisor just deletes the row; a `pending` row refuses.
49. [C1] Recovery: an interrupted `prepare` (fake Terraform `hang`) leaves the stage, clears the lock, keeps the PID file until the next session's check and keeps `last_task`; an interrupted `resize` sets the notice, `last_error` and `machine.left_off`; an interrupted revert sets the hold with §9.12's text, which offers only reverting again; a `pending` snapshot becomes `ready` when found later; a task left running by a cancel (`task_outlives_cancel`) is waited for by the next change, which then goes ahead, or refuses after the limit.
50. [C1] `check_host` refuses an unbuilt provider host (`HostNotBuilt`) unless called with `building=True`, and never pins a provider host; the poller skips it; `rotate-encryption-key` walks each table by its own primary key; `--clear-unreadable` refuses on an unreadable Terraform state and re-encrypts the readable ones, and an unreadable account secret becomes NULL with the account marked to ask for it again.
51. [C1] `CHANGING_KINDS` holds `vm_revert` (an older failed deploy's retry backs up afresh after a revert); runner keys of the VM kinds are both environment keys; labels and step names.
52. [C2] `validate_create` with machines, one test per refusal of §9.2 (each with its `field`, nothing written): no `machines:write` (403), an untrusted or failing account, two accounts or networks, an address outside the subnet, in use, claimed or the gateway, an empty pool, two VMs on one address, a size out of range, a taken host name, an account never tested (no `facts.storage_type`), a host id that is another environment's VM (refusal 0); `?check=true` lists the planned VMs and warnings and calls no hypervisor.
53. [C2] Create writes the environment, instances, hosts, claims and machines in one transaction; a claim conflict at commit (another create took the address) → 409 `<address> was just taken by another environment: pick another address`, field `hosts.<slot>.machine.address`, and none of it is written (the service half: nothing left after the rollback; the HTTP half: two creates racing, one 201 and one 409).
54. [C2] Add a slot on a new VM (must match the account and network); Add a slot with the `host_id` of another environment's VM → 409; Remove it: `slot` runs no SSH command on the VM, `machine` destroys it, and the host row, claim, state and machine rows are gone; a retry after `slot` continues. One test per blocker (a foreign disk on ESXi, the marker lost, another node, hidden, the account unreachable, a running task): the API refuses, and when the blocker appears after queueing, `check` fails with the instance row, its deployments and the machine untouched. A retry with `forget_vms` forgets a hidden VM (audit, notice), and still fails on a running task.
55. [C2] Teardown with VMs: `slots` and `data_server` skip SSH for VM members; `machines` goes green, blue, data; an app VM that fails after `check` keeps the data VM and fails naming both; the retry finishes; `forget` finds `resources` empty; Delete without a snapshot needs `drop_data` and `data:reset`. A blocker on any VM refuses `DELETE` and, when it appears after queueing, fails `check` with every Switchyard host, DNS record, instance and Backup row still there. A data VM deleted by hand (`nextid` free) is `already gone`; a hidden data VM blocks until a retry with `forget_vms` (typed name, `machines:write` + `environments:delete`; without either → 403/422) forgets it after one more `describe`, writes the notice and lets the environment reach `deleted`; `DELETE` with `forget_vms` does the same for an account that is gone.
56. [C2] Forget a lost VM: each refusal (VM still visible, hidden, data VM, mode `slot`, active slot of two, API down → 502); on success the machine is `planned`, the host unpinned, the slot stale and `created`; the next deploy makes a new VM at the same address and pins its new key.
57. [D] Permissions matrix: viewer, developer, maintainer and admin against every §11 endpoint, including create with a machine, delete with `drop_data`, revert, forget, the accounts routes (developer lists, only admin writes) and the VM kinds' retries.
58. [D] Hosts API on a provider host (`hosts.owned_host_refusal`): each 409 of §11 (PATCH `hostname`, `proxy_address`, `lan_address`, credentials or deploy root, DELETE, check while not built, reset key); label and description still editable; `HostOut.owned_by`, `built`, `provider_state` and `machine`. `POST /instances` and a placement change onto an owned host → 409; `POST /hosts/{id}/claim` (unmanaged) onto an owned host → 409; the retry and delete bodies accept `forget_vms`.
59. [D] `EnvironmentOut.machines` and `actions` (resize pending and where it applies, forget, vm_snapshots with `snapshot_mode`); `GET …/machines` with the account down gives `live.error`, with a job holding both ESXi job sessions still answers within 5 s (the read pool), and shows `power` and `busy`; `GET …/vm-snapshots` marks names gone from the hypervisor, marks the newest, gives `revert.reason` on ZFS, and lists backups taken after each; `POST …/vm-snapshots` with `snapshot_mode = none` → 409.
60. [D] `PATCH …/machines/{slot}`: sizes stored only; shrink 422; ready data server 409; nothing reaches the hypervisor.
61. [D] `DELETE /environments/{id}` body rules: `drop_data` required when the data is on a VM and no snapshot is taken; with a snapshot the P3 chain runs and then the teardown removes the VMs.
62. [E] Pages: the Integrations cards and the account dialog with networks and the trust dialog; the flow's VM sub-form and review; the Slots card's VM chips, sizes, pending resize and last error; the VM snapshots card and its dialogs (typed name on revert; the ZFS wording; the `none` card); the Slots card's power state and `Hidden` chip; the retry's `forget_vms` checkbox; the Delete dialog's VM lines and data tick; Hosts list chips and hidden actions.
63. [E] JS (`run_js`): the VM sub-form checks and the addresses call; account and network lock-step; `FIELD_STEP` for machine fields; the trust re-submit; `renderers.vm_snapshots`.
64. [C1] M1: P3's golden step lists, `.env` bytes and Switchyard calls for environments on SSH hosts and for standalone instances are unchanged (`tests/golden/test_phase3_golden.py`, recorded from the frozen `tests/golden/serversherpa_p3.slipway.yml` before any engine change, §16.1).
65. [C2] Activate: a slot whose VM is off (after a resize left it off) is refused at the API and in `check` with §10.4's text; a VM not made yet gives the "isn't made yet" text; nothing changed in Switchyard.
66. [B1] `tasks.wait_idle`: a Proxmox `lock` with a running task (a vzdump backup, say) is waited for and the change then runs; one outliving the limit (patched short) refuses with the task named and nothing changed; a `lock` with no task refuses with the `qm unlock` text; ESXi `task_running` the same; every task Slipway starts is in `last_task` before its wait and cleared after; Slipway never sends `DELETE /nodes/{node}/tasks/{upid}`.
67. [B1] A stale template key: with `stale_template_key(3)`, C7 waits until `boot-finished` can be read and C8 then reads the VM's own key; when the key file is still stale after `boot-finished`, the pin's `reread_key` path pins the right key; a key that never matches pins nothing.

### 16.3 Real host (not in CI)

1. Proxmox 8 and 9 with the docs/machines.md setup; trust the certificate; Test passes; remove one privilege and see Test name it.
2. Create `uat` as Blue/Green on three new Proxmox VMs from a pool, with DNS; the chain makes the data VM, then blue's, activates blue; sign in with password and 2FA.
3. Deploy to green (its VM is made), activate it, switch back.
4. Resize green (cores, memory, disk) and deploy: the VM shuts down, comes back at the new size, its root file system grew; on LVM-thin, on ZFS, and on a directory (qcow2) storage with a VM snapshot (the refusal text).
5. `docker kill` Slipway during green's first `apply`; restart; retry: the half-made VM is replaced or deleted and made again; `terraform_states` matches the folder; nothing is left in Proxmox.
6. Delete green's VM by hand in Proxmox; deploy to green (the lost text); Forget the VM; deploy (a new VM at the same address, a new key pinned).
7. ESXi 8 standalone, licensed, with the seed OVA: an account, Test; a single-slot mode `slot` environment on a new ESXi VM; ServerSherpa deployed (Docker installed by Slipway); take a VM snapshot; change data; revert (the data is back, later backups shown missing); revert the revert.
8. ESXi resize with a disk grow while two Slipway VM snapshots exist: both deleted, the disk grown, the file system too.
9. Delete both environments: the VMs are gone from both hypervisors; claims, states and machine rows are gone; the addresses can be used again; Delete without a snapshot needed the tick.
10. A Sirdar VM in the same Proxmox cluster is never touched (its tag), and its address is refused by the probe.
11. Rotate `SLIPWAY_ENCRYPTION_KEY`; then remove a slot (Terraform reads the re-encrypted state).
12. Deploy to a ready VM while Proxmox's API is down: `prepare` warns and the deploy succeeds.
13. ZFS (`local-zfs`): take two VM snapshots, revert to the older (refused in `check` naming the newer one, nothing changed), delete the newer, revert (no `pre_revert`, the dialog's ZFS text). LVM-thin: revert to an older snapshot with a `pre_revert`, then revert the revert. Thick LVM: the card says no VM snapshots and a resize takes none.
14. `docker compose stop` during green's first `apply` with the 60 s grace: Terraform saves its state. Then with `stop_grace_period: 5s`: the clone is left untagged and locked; the retry waits for the clone task, recognises the clone and makes it again. Check which of name, description and pool 0.115.0 sets in the clone call, and that the tags come in a later update.
15. Remove the token's rights on one VM (move it out of the pool): its page shows `Hidden`; Delete refuses in `check` with nothing removed; a retry with `forget_vms` forgets it. Delete a data VM by hand: Delete finds it `already gone`.
16. A fresh Ubuntu 24.04 template with `unattended-upgrades` on: the Docker install waits for the dpkg lock and succeeds. A template booted once with its host keys left in place: the pin still trusts only the clone's own key.
17. ESXi: cut a deploy off during the disk copy (restart Slipway): the copy task is cancelled, the retry deletes the partial file and copies again; Delete during a build leaves no file in the datastore and no `<vm>_1/` folder later.
18. **The networked session** (Decision 36; until it runs, the Proxmox path can't run outside tests): generate `slipway/terraform/proxmox-vm/.terraform.lock.hcl` (`terraform providers lock -platform=linux_amd64 -platform=linux_arm64` with Terraform 1.16.5 and `bpg/proxmox` 0.115.0), check whether 0.115.0's schema has `initialization.upgrade` with a non-root token, run `terraform validate` on the module, record the Dockerfile's per-architecture SHA-256 lines (placeholders until then), and remove the lock-file skips from the tests. Decide there whether to pre-build a pyvmomi wheel in the Dockerfile's build stage and pin its hash, or accept that the sdist's build backend isn't hash-checked (§13.4). Meanwhile `terraform.session` refuses cleanly, and the tests use a fake-mirror lock file.

---

## 17. Implementation slices

Phases 4 and 5 are built together from one plan, `scratchpad/phase45/plan.md`, whose slices replace this section's first table (A1-A5, B1-B3, C1-C2, D1-D2, E). Slices A2-A5 were built first, as new files; slice S01 moves their staged tests into `tests/`. Groups run in order; slices in one group run in parallel and share no file, tests included. After each group the full suite passes, and from S06 on the phase 3 golden files pass unchanged after every slice (test 64). Each slice's section in the plan names its files, the spec sections and numbered tests it covers, and what done means.

| Group | Slices |
|---|---|
| 1 Foundation | S01 Housekeeping: staged tests into `tests/`, one guard, settings, packaging, image, the slipway user (old B3 with A2-A5's moves); S02 Reconcile the phase 4 and phase 5 design docs with the plan; S03 Schema: provider accounts, DigitalOcean columns, machines tables, permissions, key rotation (old A1); S04 Manifest additions (phase 4); S06 Host fakes and phase 3 golden files |
| 2 Shared services and the traffic interface | S05 Traffic backend interface and Cloudflare TXT records (phase 4); S07 Host contract, resources extensions and the Slipway backup store; S08 Provider accounts for DigitalOcean, Proxmox and ESXi (old B2) |
| 3 Providers, first half | S09a DigitalOcean provisioner, part 1; S10 `do_lb` traffic backend; S11a Machines core (old B1, shared part) |
| 4 Providers, second half | S09b DigitalOcean provisioner, part 2; S11b Proxmox provider (old B1, Proxmox half) |
| 5 Pipeline and ESXi | S12 Provider steps in the pipeline: `prepare`, `resize`, `database`, `edge`, step timeouts, the not-built fences (old C1's pipeline and fences); S13 ESXi provider (old B1, ESXi half) |
| 6 Host-less paths, DigitalOcean environment jobs, account pages | S14a Owner and instance paths without a host (phase 4); S15 Environment jobs for DigitalOcean, and owned-host removal without SSH; S21 Accounts and hosts pages |
| 7 Managed data, VM environment jobs, renewals | S14b Managed data owner (phase 4); S17 VM environment jobs: remove slot, teardown, Forget, Activate checks (old C2, jobs half); S19 Certificate renewal loop (phase 4) |
| 8 VM jobs and create rules | S16 VM snapshot, revert and drop jobs (old C1, the VM kinds); S18 Create, Add slot, Delete, sizes and production rules for both placements (old C2, rules half) |
| 9 Environment, host, instance and retry API | S20 Environment, host, instance and retry API, with the shared host rules |
| 10 VM API, DigitalOcean chains, DigitalOcean pages | S22 VM API: machines, resize, Forget, VM snapshots, addresses, `forget_vms` on remove-slot (old D1); S23 DigitalOcean chains; S24a Environment pages for DigitalOcean |
| 11 VM pages | S24b Environment pages for VMs (old E) |
| 12 Docs | S25 Docs: DigitalOcean, machines, integration status, and the specs' final state (old D2) |

The VM chains (tests 44, 45) run in S18; the guard's autouse half (test 35) and the image (test 39) in S01. Each slice recorded what it did differently in `scratchpad/phase45/deviations-<slice>.md` and what it put off in `later-<slice>.md`; S25 folded them into §19. Every group's gate ran the whole suite on SQLite and it passed (3091 passed, 8 skipped after group 11); the gates of groups 1 and 3-5 also ran it on PostgreSQL 16, and later slices ran their own files there.

---

## 18. Open questions, with the default chosen

1. **Terraform or OpenTofu.** Default: **Terraform** (settled), pinned as Sirdar pins it. `terraform_binary` may name `tofu`, which reads the same module; that is documented and not tested.
2. **DHCP for a single VM.** Default: **static only** (D4). DHCP would need an "address moved" path for the host row, Switchyard and the pin.
3. **Resizing the data server.** Default: **not offered** once it is ready (D12); docs/machines.md shows how to grow it by hand during a quiet window (Slipway never re-applies a ready data server, so the change doesn't fight Terraform).
4. **VM snapshots for Blue/Green or a data server.** Default: **none** (D11). The other slot is the way back for code; P2 backups are the way back for data.
5. **VMs for standalone instances** ("New host → VM on Proxmox"). Default: **not built**: a VM is owned by an environment, which decides when it goes. A single-slot environment gives the same result.
6. **Where Docker comes from.** Default: **Ubuntu's archive** (`docker.io`, `docker-compose-v2`) when the template lacks it (D14); `get.docker.com` never.
7. **How Proxmox VMs get their host key.** Default: **read through the guest agent** (D8). Handing a generated key through cloud-init user-data would need snippet storage and SSH to the node.
8. **Making the first chain's VMs in parallel.** Default: **one by one**, each in its own member's deploy (P3's chain). A separate "Prepare the VMs" job could make all three at once later.
9. **vCenter.** Default: **refused** at Test (D7). vCenter has templates and guest customisation of its own; that is a third provider, not ESXi.
10. **Forget a lost VM that held data.** Default: **not offered** (§9.10): delete the environment and create it again from a snapshot.
11. **A VM that won't shut down for a resize.** Default: **refuse** and leave it running at its old size; a hard power-off option can come later.
12. **Firewall on Slipway's VMs** (P3 D19). Default: **none**; Slipway's VMs give the `slipway` user passwordless sudo (droplets give it none, P4 D24), so a `DOCKER-USER` step for them is the natural first place to add P3's open question 1 later.
13. **More than one network per environment.** Default: **one** (D4).
14. **Address reuse after a delete.** Default: **at once**: the claim goes with the host row; `prepare`'s probe catches a VM someone left running there.
15. **Automatic VM snapshots kept.** Default: **3** per VM (Sirdar's default), 1-10.
16. **Guest operating systems.** Default: **Ubuntu 24.04** templates and seeds are what Slipway documents and checks (`apt-get`, cloud-init, netplan matched on vmxnet3); others may work and aren't supported.
17. **A VM snapshot before every deploy** (as Sirdar's step 0 did). Default: **no**: P2 backs up the data before every deploy and Roll back undoes it; VM snapshots are for resizes, reverts and the person's own checkpoints (D11, D13), and they slow ESXi disks while they exist.
18. **Reverting to an older snapshot on ZFS.** Default: **refuse in `check`**, naming the newer snapshots; the person deletes them first (D23). A "delete the newer ones, then revert" option (what `zfs rollback -r` does) can come later, with the names in the dialog.
19. **A `pre_resize` snapshot on ZFS.** Default: **still taken**: the old sizing is the likeliest way back. It becomes the newest snapshot, so the card says older ones can be reverted to only after it is deleted (or pruned).
20. **Which storages give VM snapshots.** Default: **Proxmox's own feature check, plus the ZFS rule** (D23). Thick LVM has none today; if Proxmox's LVM volume-chain snapshots are turned on, the feature check says so and the VM gets `any`.
21. **Stopping hypervisor tasks on cancel.** Default: **only Terraform and ESXi disk copies** are stopped; snapshot, rollback, revert and delete tasks run to the end and the next change waits for them (D24).
22. **Forgetting a VM Slipway can't remove.** Default: **only with an explicit `forget_vms`** (typed name, `machines:write` + `environments:delete`), on Delete, Remove slot or their retry; never by itself, and the notice names what to remove by hand (D26).
23. **Where `prepare` runs.** Default: **right after `resolve`**, for both providers (Decision 12; it was first, before `resolve`, in this spec's earlier revision), with the resize moved later to its own step (D3, D12). `resolve` runs on the Slipway server and needs no host, so a bad ref fails before anything is made; `source`, `upload` and every later step need the VM, so `prepare` comes before them. A `prepare` failure fails the job and nothing after it runs.
24. **The container's stop grace.** Default: **60 s** in `docker-compose.yml` (D27); other ways of running Slipway are told in docs/machines.md to give at least that.
25. **Proxmox's first-boot upgrade.** Default: **off** through the module when 0.115.0 supports it, else a Test warning and docs (`ciupgrade 0`); Slipway never edits the template.

---

## 19. As built

Phase 5 was built with phase 4 in twelve groups (§17), against fakes only. This section records where the code differs from, or goes beyond, the text above; **where the two disagree, this section describes the code**. Each item names the slice whose notes it comes from (`scratchpad/phase45/deviations-<slice>.md`). Texts in backticks are the code's. P4 §23 holds what is shared with phase 4 (owned hosts, accounts, the API's retry fields, the pages' common pieces). Items still open are in §19.14.

### 19.1 Image, packaging and the guard (§13, §16.1)

- The Dockerfile takes `TERRAFORM_VERSION` and `PROXMOX_PROVIDER_VERSION`, and four SHA-256 arguments (`TERRAFORM_SHA256_LINUX_{AMD64,ARM64}`, `PROXMOX_PROVIDER_SHA256_LINUX_{AMD64,ARM64}`) set to `PLACEHOLDER-not-recorded-yet`, which `sha256sum -c` rejects, so **the image doesn't build until the networked session records the sums** (§16.3 item 18). Another architecture stops the build. The provider zip goes into the packed mirror layout (S01).
- `slipway/terraform/proxmox-vm/.terraform.lock.hcl` isn't shipped yet; `terraform.session` refuses with `Slipway's bundled Terraform module has no .terraform.lock.hcl, so this build of Slipway can't run Terraform`, and the two lock-file tests skip (S01).
- cloud-init's user has gecos `Slipway`; `cloudinit.DEPLOY_USER` is gone with no alias. `main.tf` says above `user_account` that `ciuser` takes over the image's default user and its sudo (S01).
- The guard is autouse; a test that must keep a real seam marks itself `@pytest.mark.own_guard`; a blocked request names the host, never the URL (S01).
- `tests/fake_vm_hosts.py` is a `MultiRemote` subclass, `VmRemote`, with knobs `no_sudo`, `apt_fails`, `cloud_init(state, sleep=)`, readers `vm_log`, `docker_installed`, `in_docker_group`, `boot_esxi_vm` and `guestinfo_host_key`, and `probe_through(multi)` as an `ssh.probe` stand-in. `tests/vm_fixtures.py` adds `SimpleFreeze`, `quiet_network`, `Lines`, `no_sleep`, `context`, `machine_row`, `a_user` (S11a, S13).

### 19.2 Data model and key rotation (§3, §3.9)

- Extras with no schema effect: `AccountStatus`, `ACCOUNT_NAME_RE`, `ProviderKind.is_hypervisor`, `ProviderAccount.has_secret` and `.is_removed`, `Machine.is_ready`, and `Machine.host` / `Machine.account` relationships. `machine_snapshots.status` is a plain string (`pending`, `ready`, `missing`, `failed`). `AddressClaim.created_at` has a server default (S03).
- Rotation's work is `cli._rotate(db, clear_unreadable)`; unreadable columns read `<table>.<column> (<pk name> <value>)`. `--clear-unreadable` over an unreadable Terraform state raises `cli.RotationRefused` before anything changes and exits `Nothing was changed. <§3.9's text>`, naming several states comma-separated (S03).
- The machines core copies the stage into `hosts.provider_state["stage"]` (and `from_stage` while destroying), beside `phase` (S11a).

### 19.3 Audit (§4.2)

- `machine.reserve` is written by the core: `reserve_vmid` (`{name, vmid}`) and `record_vm` with ids (`{name, instance_uuid, moref}`); `record_vm` audits `machine.rebuild` (`{name, old, new}`) when it forgets an older row (S11a).
- Proxmox (S11b): `machine.rebuild` also for C4's tainted replace (why `Terraform's earlier create failed part way`), a VM gone before it was ready (`gone before it was ready`), the half-made clone (`a half-made VM Terraform's state doesn't hold`) and someone else's VM at the id (`someone else's VM holds the id`); `machine.create` `{name, ids: {vmid}, node}`. An id held by a VM Slipway can't see is only logged.
- ESXi (S13): `machine.create` `{name, ids: {instance_uuid, moref}, datastore}`, `machine.adopt` `{name, ids}`, `machine.rebuild` `{name, old, why}`; `machines.ids` is `{instance_uuid, moref, vm_path}`. The ESXi resize audits `machine.snapshot_delete` `{name, snapshot, why: "resize"}` and marks the rows `missing`.
- `machine.left_off` is written by `machines.left_off`, which `resize_step` and the restart recovery both call, so it is written once (S11a, S12).
- VM jobs (S16): `machine.snapshot` `{name, snapshot, reason, quiesced}` (quiesced None on Proxmox); `machine.snapshot_delete` `{name, snapshot, reason, why}` with why `prune` or `deleted`; `machine.revert` `{name, snapshot, taken_at, commit_sha, identity_restored}`.
- `machine.forget` `{name, ids, why: lost, environment, slot}`, and the `vm` rows audited `resource.forget` (S17).
- `host.key_reset` is also written by `machines.unpin` (S13).

### 19.4 The machines core (§6)

- **Protocol** (S11a): providers also have `label` (`Proxmox`, `ESXi`) and `async running(ctx) -> list[Busy]`, the task list `tasks.wait_idle` polls; `Busy(kind, where, started_at, task_id, lock, vmid)`, where a `lock` without a `task_id` is a dead task's lock and refuses at once (with `qm unlock <vmid>` on Proxmox). `wait_idle(ctx, *, read=None, limit=None, poll=None)` counts its limit in polls and reads `TASK_WAIT_LIMIT` and `TASK_POLL` when called (S11a, S13). `tasks.started` and `tasks.ended` write and clear `last_task`. `load_context(db, *, machine_id=None, host_id=None, ...)` is new.
- **Shared helpers** (S13): `snapshots_allowed(ctx)` (D11's shape), `pre_resize_row(ctx)`, `growpart_warning(ctx, disk_gb)`, `probe_address(ctx)`, `unpin(ctx, why)`. Proxmox keeps its own copies of `snapshots_allowed` and `growpart_warning`; both providers use `pre_resize_row`, which is `vm_jobs.new_row`'s (review F1).
- **`plan(db, env, slot, account, network, address, size, user, *, provider=None, deploy_root=None, keep_vm_snapshots=None)`** raises `machines.PlanProblem(text, field)` with fields `hosts.<slot>`, `hosts.<slot>.machine.address|network|size|account` or `name`. It never flushes, so the claim's conflict surfaces at the caller's commit (S11a).
- **`prepare(ctx, *, resize=False) -> (status, note)`**: `warning` for a ready VM whose hypervisor can't be reached or whose account can't be used (`Couldn't check <vm> on <account> (<why>); carrying on over SSH`). A successful prepare of a ready VM clears an old `last_error`; a destroying machine is refused (`<vm> is being removed; only the retry of that removal can run`). The resize refusal's sentences are joined with a full stop (S11a, S13).
- **`pin(host, *, address, expected_key, how, connect, tries=60, poll=5, sleep, reread_key=None, machine=None, user_id=None, vm=None) -> str`** takes no session; it opens its own for the address check and the compare-and-set, which checks the row's own port (S11a).
- **`resize_step(ctx, *, instance=None, start_release=None) -> (status, note)`** writes `applied`, `options.resize` and `machine.resize` right after the provider's resize, before the live release starts again, so a failed start (`<vm> is resized, but <slot>'s live release didn't start: ...`) doesn't resize again next time. It ends `warning` (`Resized to <size>. <warning>`) when the provider returns `warnings`. A failed resize while `describe` doesn't say running calls `machines.left_off` (S11a, S13).
- **Registry** (S11a): `addresses_in_use(db, *, network=None, except_host_id=None) -> {address: phrase}`, `address_problem`, `claim`, `check_address_free(ctx, *, probe=True)`. New texts: `is one of the network's DNS servers`, `is Switchyard's address`, `is reserved for host <name>`, `<address> is used by ..., so Slipway won't give it to <vm>. Slipway changed nothing`. `.invalid` names and literal IPs are never resolved.
- **`blockers(ctx)`** (S11a): a planned machine with no ids has none; an account that can't be used gives a forgettable blocker (`<account> can't be used (<why>), so Slipway can't remove <vm>: fix the account, then retry`); a non-unreachable `MachineError` from `destroy_blockers` is not forgettable.
- **`remove(ctx, *, forget=False) -> list[str]`** refuses while an instance uses the host (`<vm> still runs the <slot> slot's instance; Slipway removes the VM after the slot`), deletes the rows with plain DELETE statements in one transaction and removes the working folder after the commit. A machine with no blockers is destroyed even with `forget=True` (S11a).
- The lost text: `<vm> is gone from <account>. Slipway never makes a ready VM again by itself: use Forget the VM on <env>, then deploy to <slot> to make a new one` (S11a).
- `terraform_store` is module-level `lock`, `unlock`, `load`, `save`, plus `clear_lock` and `forget`; `load` treats an undecryptable state as empty (S11a).
- `vmnet.host_row_name` returns the VM name (S11a).

### 19.5 Proxmox (§7)

- A **tainted** state also accepts the untagged clone through `_our_clone` (name, node, pool, tags none or ours, description naming the environment), so C4's replace is allowed after `fail_after_clone` (S11b).
- `snapshot_first` is true when the shape has VM snapshots, `snapshot_mode` isn't `none`, and the resize doesn't grow a qcow2 disk (Proxmox refuses that grow over a snapshot) (S11b).
- `snapshot(ctx, row)` writes the row's status itself: `ready`, `ready` with note `The task ended late` (after 15 s and a list), or `failed` with `Proxmox didn't take the VM snapshot <name> of <vm>`. It returns False (Proxmox doesn't quiesce). On a task timeout `last_task` stays set (S11b).
- `ProxmoxClient` has no hard stop, so deleting a running half-made VM through the API and `stop()` shut it down cleanly first (S11b).
- Terraform runs only inside a job: `Slipway runs Terraform for <vm> only inside a job; it changed nothing` (S11b).
- Re-reservation loops at most 20 rounds, then `Slipway couldn't find a VM id for <vm> that no other VM uses; it changed nothing` (S11b).
- A made VM whose stage never moved is started through the API before the plan, not made again (S11b).
- `revert` itself refuses a non-newest target on `newest_only`, as a second line behind S16's `check` (S11b).
- `destroy` leaves every row (the `vm` rows, `terraform_states`, the working folder) to `machines.remove` and never runs `state rm` (S11b).
- `describe` returns `MachineState(ours=False, why_not_ours=...)` instead of raising; `busy` is `<type> (started HH:MM)` or `locked (<lock>)` (S11b).
- `running(ctx)` lists the VM's active tasks, then its config lock, re-reading the tasks once before it reports a dead task's lock (S11b).
- Texts (S11b): `<vm>'s guest agent didn't report an address in 5 minutes. Check that the template has qemu-guest-agent installed and its agent option on`; `<vm>'s guest agent didn't answer in 5 minutes; carrying on over SSH`; `Slipway couldn't read <vm>'s SSH host key through its guest agent in 5 minutes`; `<vm>'s disk can't shrink from <a> GB to <b> GB`; `Terraform's plan for <vm> changed while it was off (<what>); Slipway started it again at its old size and applied nothing`; `<vm> is resized, but Slipway couldn't reach it over SSH with its pinned key: <error>`; `VM <vmid> is still there after Slipway deleted it. Remove it by hand in Proxmox, then retry`; `<vm>'s storage reverts only to its newest VM snapshot (<newest>), not <name>; Slipway changed nothing`; `Terraform is still running for <vm> (pid <n>): wait for it to finish, then retry`.

### 19.6 ESXi (§8)

- Every call opens `esxi.session(account, purpose=...)`: `read` when the context has no deployment, `job` otherwise. The session helper first refuses an account that now points at another host (`ApiHostMoved`), which `destroy_blockers` reports as a forgettable blocker (S13). A sign-in cut off by its 35-second limit or by a cancel (a page read's 15-second limit) signs the session it opens later out on its own thread, and gives its pool place back only then (review F35).
- "Ours" means the name is the machine's, `slipway.machine` is the machine id and `slipway.environment` the environment id (S13).
- The disk path is the VM's own folder (`<vm>-disk0.vmdk` in `VmInfo.folder`) (S13).
- E1's exceptions: a VM whose host is already pinned to `host_key_public` needs no private half; a new VM made while the host is still pinned to an old key clears the pin first with `machines.unpin`. `ensure` scrubs a pinned VM's user-data and private key when an earlier `after_pin` failed (S13).
- E4: a `-flat.vmdk` counts as Slipway's only next to its `-disk0.vmdk`; the registry, guest IPs and the probe run in that order (S13).
- A snapshot error of any kind gets the 15-second grace; an unreadable list counts as absent; `quiesced` is written (S13).
- `check_resize`: a grow drops every snapshot on the VM, all of which must be recorded with unique names; `missing` rows don't count as recorded (S13).
- Destroy: Slipway's own cancelable copy doesn't block; `destroy` cancels it. Leftover files are returned as a warning line (S13).
- `describe` reads `ours=False` with the disk text for a VM whose disks were changed; `SnapshotView.newest` is ESXi's current snapshot (S13).
- Texts (S13): `VMware Tools on <vm> didn't report an address in 5 minutes. Check that the seed VM has open-vm-tools installed`; `VMware Tools on <vm> didn't answer in 5 minutes; carrying on over SSH`; `<vm> came up at <ips>, not <address>. Check the seed VM's cloud-init and the network's settings`; `<other> on ESXi already reports <address>, so Slipway won't give that address to <vm>. Slipway changed nothing`; `<vm> has a disk Slipway didn't put there; Slipway changed nothing`; `<vm> has <n> VM snapshots named <name> on ESXi, so Slipway won't pick one; Slipway changed nothing`; `ESXi didn't take the VM snapshot <name> of <vm>`; the annotation `Made by Slipway for <env>'s <slot> slot. Remove it from Slipway, not by hand.`
- The ESXi provider never imports pyvmomi; only the real `esxi.session` does, so its tests run without pyvmomi (S13).

### 19.7 Accounts (§9.1)

- The account answers are P4 §23.6's union; Proxmox's carries `pool`, `storage`, `template_vmid`, ESXi's `resource_pool`, `source_vm` (S08).
- The Test after a create runs through FastAPI `BackgroundTasks` in its own session, audited with the creator as actor; any exception is logged and swallowed (S08).
- A PATCH may carry `trust_fingerprint` to pin the new address's certificate in the same save; without it a URL change forgets the pin. Refusal fields: `url` (or `user` when only ESXi's user changed), `networks`, `secret` (S08).
- The certificate in `tls_untrusted` and `tls_mismatch` is `{fingerprint_sha256, subject, issuer, not_before, not_after, sans}`; `tls.trusted_by` stores the user's email (S08).
- Remove texts: `<account> has VMs: <names>. Delete their environments first`; the typed name `Type the account's name, <name>, exactly to confirm` (S08).
- The page (S21): no route returns an account's live certificate, so **Trust…** and an edit that changes the URL (or ESXi's user) first send a fingerprint of 32 zero bytes; the service answers 409 `tls_mismatch` with the live certificate and writes nothing. The networks table follows the provider (bridge and VLAN, or port group). Test in the Proxmox and ESXi dialogs shows only when editing.
- `GET /provider-accounts/{id}/addresses?network&count` answers `{network, subnet, pool, free, in_use: [{address, by, text}]}`; `in_use` covers every held address in the subnet; `network` may be left out when there is one; `count` defaults to 10 (1-256). A DigitalOcean or removed account answers 409 (S22).

### 19.8 Create, add, resize, remove (§9.2-§9.5)

- Create (S18): `MachineSpecIn {account_id, network, address, cores?, memory_mb?, disk_gb?}` flat. `<a> is given to both <s1> and <s2>: give each VM its own address`. `?check=true` warns `<account> hasn't been tested yet`, or `... since <time> UTC` after 24 hours; the storage line uses the last Test's `free_gb`. The VM name isn't checked on the hypervisor (no call at create). A claim conflict is caught at `create`'s and `add_slot`'s last flush (409, Decision 43's text) and again at the route's commit; a `PlanProblem` at write time answers 409 with its own text (S18, S20).
- `environments.resize_plan` writes the size itself. The PATCH route needs `machines:write`, answers `MachineOut` without `live`, and 404 for an unknown slot (S18, S22).
- Remove slot (S17): `remove_slot_problem(..., forget_vms=False, read_vms=True)`; a slot whose instance is gone but whose VM is left can be removed again. A retry queued after the instance went has its `machine` step inserted by `check`, which notes `<slot>'s VM <vm> isn't removed yet; Slipway goes on from where it stopped`. Blocker texts are the core's as they are; `check` logs each (`<vm> can't be removed now: <text>`, `(forgettable)`). `machine` and `machines` end `warning` when a VM was forgotten or ESXi left files. Notes: `<vm> goes in the next step`, `<green vm> and <blue vm> go in Remove the VMs`.
- `forget_vms` (S12, S20, S22): `job_refusal` refuses it on any kind but `remove_slot` and `teardown` (409) and without `machines:write` and `environments:delete` (403); a first Remove slot may carry it, not only a retry. `DELETE /environments/{id}/slots/{slot}` takes `RemoveSlotIn {confirm, forget_vms}`; the route checks the permissions after the typed name (`Forgetting a VM needs the machines:write and environments:delete permissions`) and the queue checks them again.
- Activate (S17, S18): a slot whose VM isn't made gets `<slot>'s VM isn't made yet: deploy to <slot> first`, from the queue's not-built fence and again in the job's check. Last of all, `vm_off_problem` reads a ready VM through `describe` and refuses one whose power isn't running (`<slot>'s VM <vm> is off: deploy to <slot> again to finish its resize`); a VM that can't be read doesn't refuse. The environment page's `actions` and a failed environment job's Retry (`env_job_actions`, on GET /deployments/{id} and the deployment page) skip that read (`environments.page_view`: a page view reads no hypervisor): the queue and the job's `check` still make it.

### 19.9 VM snapshots (§9.6-§9.8, §9.12)

- Queued step lists name the VM but not the snapshot, and always list a revert's `vm_snapshot`; `_start` lists them again through `vm_jobs.job_steps`. The routes also set `dep.steps` from it after queueing (S16, S22).
- Refusals are registered in `jobs.KIND_PROBLEMS` and also answer 403: `Taking a VM snapshot needs the machines:write permission`, `Reverting to a VM snapshot needs the data:reset permission`, `Deleting a VM snapshot needs the machines:write permission`. `vm_jobs.revert_request_problem` gives the typed name (422), then the 403s, for the route (S16).
- The owner's hold refuses a VM snapshot with P3's fence text, not §9.6's (S16).
- ZFS: the queue refuses a revert when Slipway recorded a newer ready snapshot; `check` refuses for any newer snapshot on Proxmox (S16).
- `check` settles rows: pending, failed or missing found exactly once become `ready`; pending not found `failed`; ready not found `missing` (S16). `GET .../vm-snapshots` applies the same rules when the VM was read, is Slipway's, and no job is queued or running (S22).
- `prune` only warns; it deletes ready automatic rows beyond `keep_vm_snapshots` and every automatic row that is `failed` or `missing`; a name there twice is kept and logged (S16).
- **A revert that fails in-process** in `vm_revert`, `wait` or `vm_settle` holds the data too, with `Slipway couldn't finish reverting <vm> to <name>. The VM's disk may already be back at <name> while Slipway's records name a later release: revert to <name> again`. Both holds stop at the end of `vm_settle` (`options.settled`). The text is stored in `data_dirty.last.text`, which `data.hold_text` shows, adding `Start, Restart and Deploy are off until then.`, with no P2 restore offered (S16, gate 8, S24b).
- VM jobs never set the instance `deploying`; a revert's `restart` sets `running` or `stopped`; with no live release in the snapshot it is skipped and the status becomes `stopped` or `created` (S16).
- vm_settle runs P2's `check_backups` on the VM and the notice names the missing rows not in the snapshot's list; it is written right after vm_settle's transaction (S16).
- `wait` retries every 5 seconds, 120 times; another host key fails at once with `<vm> answered SSH at <address> with a key that isn't the one Slipway pinned; Slipway pinned nothing` (S16).
- vm_settle empties `.slipway-lock` only when it exists; `restart` takes and releases the host lock (S16).
- Options: `vm_snapshot_taken`, `vm_snapshot_pre` (carried to a retry), `settled`; `ONE_SHOT_OPTIONS` gains `settled` and `vm_snapshot_taken` (S16).
- One row builder, `vm_jobs.new_row`, for manual, `pre_revert` and (through `machines.pre_resize_row`, both providers) `pre_resize` rows, with the identity values, their fingerprint and the ready backups (S16, review F1).
- A snapshot whose provider call failed before its task started is `failed` at once; `vm_drop` on a VM gone (not hidden) deletes only the row (S16).
- Texts: `That VM snapshot isn't one of <env>'s`, `The VM snapshot <name> isn't ready (<status>)`, `The VM snapshot <name> is still being taken; wait for it to finish` (S16).
- Step timeouts: `vm_snapshot` 35, `prune` 45, `vm_revert` 30, `wait` 10, `vm_settle` 2, `vm_drop` 25 minutes (S16; raised in review F36 to hold the task waits inside them). A `vm_snapshot` step cut off by its limit marks its `pending` row `failed`; a snapshot that appears later is made `ready` by the next VM job's settle.

### 19.10 Delete and Forget (§9.9, §9.10)

- Delete's choices ride on the snapshot taken first (`then_options`), and production rules are P4's; "never held data" applies to an environment with a VM host (P4 §23.15) (S18, gate 9).
- The teardown's `forget` step keeps a notice this teardown wrote, so a VM forgotten with `forget_vms` stays named once the environment is deleted. The `machines` step stops at the first VM that fails, naming the data VM as kept (S17).
- Forget (S17): `forget_vm_problem(db, env, slot, members=None)` returns a `JobRefused` (409, or 502 when the account can't be checked). Extra refusals: `<env>'s <slot> slot has no VM`, `<account> can't be used (<why>), so Slipway won't forget <vm>: fix the account first`, a non-unreachable read error (502). Any VM `describe` finds at the recorded id refuses with `Slipway can still see <vm> on <account>: remove the slot instead`, so only a VM that is gone may be forgotten. Forget also deletes the machine's `machine_snapshots` rows and clears `last_task`, `last_error` and `snapshot_mode`; the host's `provider_state` goes back to `planned`. `env_jobs.forget_vm` returns `Slipway forgot <vm>; the next deploy to <slot> makes a new VM at <address>`.
- The route (S22) checks the typed name (422), then `machines:write` and `environments:delete` (403); an unknown slot is 404, a slot with no VM 409 `<env>'s <slot> slot has no VM Slipway made`; it answers `MachineOut` with `note`.

### 19.11 Jobs, steps and fences (§10)

- Step names: `Prepare the VM <vm> on <account>` (`Prepare the VM <host>` when the machine row is missing), `Resize <vm> to <size>`; neutral defaults for the VM kinds' keys (`Take a VM snapshot`, `Revert the VM`, `Wait for the VM to answer`, `Bring Slipway's records back`, `Delete the VM snapshot`), named per VM and snapshot by vm_jobs. Labels `Take a VM snapshot`, `Revert to a VM snapshot`, `Delete a VM snapshot` (S12).
- `machine` (`Remove the VM <vm>`, 30 minutes) and `machines` (`Remove the VMs`, 60 minutes) (S17).
- `machines.load_context` always gets the job's `deployment_id` (Terraform's lock key; ESXi's session purpose) (S12).
- Recovery: a VM cut off in `prepare` logs `<vm> keeps its stage (<stage>); the next deploy to <slot> continues from there`; one cut off in `resize` goes through `machines.left_off` (`Slipway restarted while resizing <vm>`). `vm_jobs.recover` fails an interrupted job's pending rows and holds the data for a revert cut between `vm_revert` and the end of `vm_settle` (S12, S16).
- `shutdown` needed no change: it cancels every task and waits without a limit (S12).

### 19.12 API (§11)

- `GET /environments/{id}/machines` answers each `MachineOut` with `live: MachineStateOut {exists, ours, why_not_ours, hidden, lost, power, busy, addresses, applied, snapshot_mode, error, detail}`; `lost` and `detail` are new. `error` is `busy` when ESXi's read pool is full (`<account> is busy with other work; try again in a minute`), the account's problem when it can't be used (no read), or the read's error. `live` is null for a VM with no ids yet. Each read is bounded by `asyncio.wait_for`, 5 s for Proxmox and 15 s for ESXi; "busy" is recognised by the text `is busy with` (S22).
- `GET /environments/{id}/vm-snapshots` answers an object, `VmSnapshotsOut {slot, vm, snapshot_mode, error, detail, take: {available, reason}, snapshots: [VmSnapshotOut]}`, newest first; each snapshot has `revert` and `drop` `{available, reason}`, `on_hypervisor`, `newest` and `backups_after`. The VM is the environment's one app slot's (blue with two, where `take.available` is false) (S22).
- Snapshot routes: POST and DELETE need `machines:write`; Revert needs only `environments:read` at the route so the typed name comes first. A snapshot id that isn't the environment's is 404. The queued `deployment.create` audit carries the snapshot's name (S22).
- `MachineOut.applies_at` is `next deploy`, `when idle` (the active slot of two) or `never (data server)`; the pages use the one phrase `Resize pending: applies at <slot>'s next deploy`, with ` when <slot> is idle` for the active slot of two (S22, S24b).
- `EnvironmentOut.machines` lists the records; `actions.vm_snapshots` gains `snapshot_mode` and `vm`; `HostOut.machine` is `{stage, account: {id, name, provider}}` (S22).
- `actions` gains `resize` and `forget` per slot (Forget without a hypervisor read) and `vm_snapshots` (S18).
- Retry: a `vm_revert` retry asks the typed name and `data:reset`; the VM kinds skip `data.require_data_job` (S20).

### 19.13 Pages (§12)

- The page makes **no hypervisor read** for the VM cells: they show what Slipway recorded (`<vm> on <account> · 4 vCPU · 8 GB · 64 GB`, the address and network, the build chip, the pending phrase, `last_error`). `renderers.vm_live` loads `GET .../machines` and writes the power (`Running`, `Off`, `Busy: <task>`, `Gone`, `Not Slipway's`, `Can't be seen`, `Couldn't check`) and the `Lost`, `Hidden` and `Off` chips. `environments.actions` makes no `describe` for Activate either: a page view skips `vm_off_problem`, and the queue and the job's `check` still read the VM (S24b, S17; review K5).
- Forget the VM is rendered hidden and shown once the live read says `lost`. `forget_vms` on Remove slot and Delete is rendered shown when the account can't be used (known without a read); when the dialog opens it reads `GET .../machines?blockers=true` and shows the box only when the VMs have blockers and every one is forgettable, naming them (review K4; the Slots card's power read no longer guesses). A read that doesn't answer in time leaves the box as rendered. A VM gone by hand isn't a blocker. The deployment page offers it on the retry of a failed Remove slot or teardown that failed in `check`, `machine` or `machines` (`pages.offers_forget_vms`) (S24b).
- The create flow's VM sub-form is one macro (`vm_machine_fields`), shared with Add a slot; memory is typed in GB; the address is picked from `GET .../addresses` (read once per account and network, each slot starting on a different free address) or typed; a network with no pool or no free address switches to typing. Lock-step: the lead VM is the first of blue, green and data on a new VM; other accounts' options are disabled with `: <env>'s VMs share one account and one network`. Add a slot is locked on the server through `pages.vm_accounts(account_id=, network=)`. Every Proxmox and ESXi account not removed is listed; one that can't be used is disabled with its reason, and every one without `machines:write` with `Making VMs needs the machines:write permission` (S24b).
- Step 3's own checks: `Choose a network for <slot>'s VM`, `<x> isn't an IPv4 address, such as 10.0.0.12`, and no address given twice. Review lists `New VM <name> on <account>, at <address> on <network>, 4 vCPU · 8 GB · 64 GB` (S24b).
- Deploy dialog sentences come from `pages.vm_view`: `Slipway makes <vm> first (several minutes).`, `<vm> is resized to ... after the backup: it shuts down for a minute or two.` (with ` <env> is down meanwhile.` for a single slot), the ESXi disk-grow sentence, and `No VM snapshot is taken first: <storage> can't take one.` (S24b).
- The Resize dialog per VM slot has vCPU, memory (GB, `data-scale="1024"`), disk (with `Disks only grow: <vm> has <n> GB.`) and `VM snapshots Slipway keeps`; its button is hidden for a ready data server (S24b).
- The VM snapshots card shows for one app slot in mode slot on a VM Slipway made; with `snapshot_mode = none` it is static (`<storage> (<type>) can't take VM snapshots, so <vm> has none. Backups (above) still work.`). Its columns: Name (with `Newest` and a status badge), Taken, Why, Commit, Note, `On <account>` (`Yes`, `Not there any more`, `Couldn't check`). The Revert dialog names the backups lost (`Everything written since is lost, including these backups: <names>.`) and uses P5's sentence on ZFS (S24b).
- Delete for VMs: `These VMs are destroyed with their disks: <names>.`, a Goes list naming each VM with its account (the data VM `with its disks and <env>'s data and backups`). Remove slot: `Removes <slot> and its VM <vm> from <account>, with its disks.` (S24b).
- The running labels are `Taking VM snapshot`, `Reverting`, `Deleting VM snapshot` (P4 §23.19) (S24a, gate 10).
- Owned-host notes on the instance page: `Its host is the VM <name>, which Slipway made on <account>.` (S21).

### 19.14 Still open after the build

- **The networked session** (§16.3 item 18): the Terraform lock file, the Dockerfile's four SHA-256 sums, `initialization.upgrade` in the provider schema, `terraform validate`, and the pyvmomi wheel question. Until then the image doesn't build and the Proxmox path can't run outside the tests.
- **Forget-by-approximation** (done in review, K4): `GET .../machines?blockers=true` lists each VM's blockers with their forgettable flags, and the Remove slot, Delete and retry dialogs offer `forget_vms` from them. ESXi's `destroy_blockers` still opens a `job` session even for a page's read, so while a job holds both of an account's job sessions the read answers null and the page's own state stays.
- **Activate's describe on page views.** Done in review (K5): `environments.actions` skips it.
- **VM_NOT_MADE at the queue.** Done in review (K3): `jobs.not_built_problem` gives the VM text, and test_provider_pipeline's test 41 expects it.
- **Proxmox `pin` after a remake.** Done in review (F11/K2): C5 unpins before making the VM again.
- **ESXi Forget** doesn't refuse a VM carrying the environment's marker under another UUID.
- **Optional:** `ProxmoxClient.stop` (qmstop) for a half-made VM that ignores ACPI; a `ReadBusy` error class in esxi.py; page clients (`for_account(page=True)`) in Proxmox's `describe`; the providers using the core's shared helpers.
- **Not run:** the real-host checks (§16.3), the whole suite on PostgreSQL after group 5, and the pages in a real browser.
- **Where the numbered tests are:** 18-22, 24, 24b, 34 test_machines.py; 23, 25-29, 66 (Proxmox), 67 test_provider_proxmox.py; 21 (ESXi), 30-33, 31b, 66 (ESXi) test_provider_esxi.py; 35 test_hypervisor_guard.py; 36-38 test_provider_accounts.py (38's addresses half in test_env_machines_api.py); 39 test_image.py; 40-43 (Proxmox), 49, 51 test_provider_pipeline.py; 43 (ESXi), 46-49 test_vm_jobs.py; 44, 45, 52, 53 (service), 54 (add) test_env_machines_create.py; 50 test_host_contract.py and test_rotate_provider_secrets.py; 40b, 54 (remove), 55 (job), 56, 65 test_env_machines.py; 47, 55-60 (API halves) test_env_machines_api.py; 53 (HTTP), 58, 61 test_owned_hosts_api.py; 62, 63 test_machines_web.py and test_accounts_web.py; 64 tests/golden.

---

## Appendix A. Sirdar code checked against the research

Every claim this design takes from Sirdar, read in `SD/` on branch `sirdar`. The research (sirdar-vms.md) was right except where noted.

| Claim | Where | Note |
|---|---|---|
| Terraform 1.16.5 and `bpg/proxmox` 0.115.0, exact pins | `SD/deploy/terraform.py:33-34`, `114-116` | confirmed |
| `main.tf.json` rendered per VM; tags, description, `stop_on_destroy`, `purge_on_destroy`, `ignore_changes = [clone]` | `SD/deploy/terraform.py:82-119` | confirmed; Slipway ships the same resource as a static module (D5) |
| Any plan with `delete` refused | `SD/deploy/terraform.py:122-138`; `SD/deploy/provision.py:356-369` | confirmed. **Not in the research:** nothing handles a tainted first create, so a failed first apply leaves a replace that `PLAN_DESTROYS` (`provision.py:65`) refuses forever; D9 fixes it |
| Working folder per VM, mode 700, CA file must be one certificate, crash log and old plan removed | `SD/deploy/terraform.py:141-181`, `57-60` | confirmed |
| Allowlisted environment, the token only as `PROXMOX_VE_API_TOKEN` | `SD/deploy/terraform.py:201-213` | confirmed |
| SIGINT to the process group, SIGKILL after 30 s; 25-minute timeout; 1 MiB line limit | `SD/deploy/terraform.py:44`, `48`, `243-311` | confirmed |
| Id reserved before Terraform, 20 tries, unique `vmid` | `SD/deploy/provision.py:59-62`, `163-171`, `276-289` | confirmed |
| Ownership: name, `sirdar` tag, node | `SD/deploy/provision.py:291-306` | confirmed |
| Snapshot before resize; name recorded after the task (the gap) | `SD/deploy/provision.py:238-245`, `421-443` (`434`) | confirmed; Slipway records first (D10) |
| Retry reuses the snapshot without checking it exists (Proxmox) | `SD/deploy/provision.py:423-425`; ESXi checks at `SD/deploy/esxi_provision.py:538-543` | confirmed; Slipway checks for both |
| Address from the agent; host key read through `file-read` | `SD/deploy/provision.py:50-53`, `371-419`; `SD/deploy/proxmox.py:241-264` | confirmed |
| Destroy rules (never built, invisible while in state, tag, node, missing state) | `SD/deploy/provision.py:470-518` | confirmed |
| Pin loop: trust only the expected key, retry while SSH is down | `SD/deploy/vmcommon.py:174-203`; settle refuses a saved target's address `206-233` | confirmed |
| Static network rules and the Blue/Green three-on-one-subnet rule | `SD/deploy/vms.py:107-136`, `153-178` | confirmed |
| Sizes and limits; VM name rule; generated ESXi host key | `SD/deploy/vms.py:32-35`, `73-80`, `188-194` | confirmed; the name rule applies only to ESXi in Sirdar (`vms.py:335`) |
| ESXi `EsxiApi` protocol; owner key in extraConfig; free licence refused | `SD/deploy/esxi.py:43`, `53-57`, `149-176` | confirmed |
| Empty VM spec: PVSCSI, vmxnet3, `disk.EnableUUID`, guestinfo | `SD/deploy/esxi.py:331-352` | confirmed |
| `_smart_connect`: pinned context without host-name check, thumbprint, 30 s | `SD/deploy/esxi.py:698-705` | confirmed |
| Lookup by UUID, adoption by marker, half-copied disk rule, seed checks, record at once | `SD/deploy/esxi_provision.py:219-258`, `342-422` | confirmed |
| Snapshot recorded first, quiesce fallback, grace, duplicates never picked | `SD/deploy/esxi_provision.py:536-582` | confirmed |
| Destroy: UUID or marker; foreign disks refused; powered off first | `SD/deploy/esxi_provision.py:616-666` | confirmed |
| Cloud-init metadata, user-data with the generated host key, scrub | `SD/deploy/cloudinit.py:53-107` | confirmed |
| Pinned TLS context, exactly one certificate, partial chain, TLS 1.2 | `SD/deploy/tls_pin.py:108-124` | confirmed |
| Token format | `SD/deploy/integrations.py:75-82` | confirmed |
| Blue/Green: no VM snapshots, no VM restore, data VM left as built, data VM first | `SD/deploy/vmsteps.py:19-20`, `43-68` | confirmed (refusal `47-49`, `as_built` `58-63`, no snapshots `66-68`; the research cites `56-64` and `65-67`) |
| Docker installed with `get.docker.com` on every Bootstrap | `SD/deploy/ansible/tasks/docker.yml:27-44` | **Not in sirdar-vms.md**; Slipway uses Ubuntu's packages (D14) |
| Template setup, Proxmox role and token, ESXi seed and user | `SR/README.md` (Proxmox and ESXi sections) | confirmed; moves into docs/machines.md with Slipway's names |
| Offline image build: per-architecture SHA-256, filesystem mirror, hash-pinned pyvmomi | `sirdar/Dockerfile:15-64`, `sirdar/terraformrc` | confirmed; Slipway adds `direct { exclude = ["*/*"] }` |

Slipway shapes this design relies on, checked again on the phase 3 tree (branch `machines`): `Host` and `is_pinned` (models/host.py:30, :91); `SSHTarget.from_host` (services/ssh.py:94); `generate_keypair` and `fingerprint` (ssh.py:239-255); `connect` accepting only the pinned key and refusing an unpinned host (ssh.py:530-594); `probe` as the only TOFU caller (ssh.py:671-676); `check_host`'s compare-and-set and first-contact pin (services/hosts.py:33-87); the poller over pinned hosts only (hosts.py:124-135); Switchyard's `route_targets` and `lock` (services/switchyard.py:268, :443-444, where `_lock` is an alias of `lock`); `instances.host_id` RESTRICT and `DeploymentKind` (models/instance.py:86, :49-65); `ConnectFactory` and every pipeline connection through `SSHTarget.from_host` (deployer.py:119, 4711, 4733); `storage_dir` (core/config.py:78); the storage folder's owner and mode (Dockerfile at 83dca5d).

---

## Appendix B. Critique responses

This appendix records the revision that answered the critique. Its slice names (A1-E), the two machines revisions of row 18 and `prepare` before `resolve` are that revision's; §3.8, §10.3, §17 and the plan's Decisions give the current ones (three linear migrations 0010-0012; `resolve` then `prepare`).

Each point of `phase5/critique.md`, checked first against Slipway's tree (83dca5d plus phase 3's files as they stand), the phase 3 spec, Sirdar's code and the Proxmox, ESXi and Ubuntu behaviour named. "Agreed" means the point holds and the critique's fix is taken; "Agreed, changed" means the point holds and the fix differs, with why.

| # | Point | What was checked | Verdict | Where handled |
|---|---|---|---|---|
| 1 | ZFS rolls back only to the newest snapshot; `pre_revert` always breaks revert; LVM and raw take none | Proxmox's ZFS plugin refuses a rollback past newer snapshots; the old §9.7 took `pre_revert` before `vm_revert`; Test checked only free space | Agreed, changed: the type comes from `GET /nodes/{node}/storage?storage=` (needs only `Datastore.Audit`, unlike `GET /storage/{storage}`), combined with Proxmox's per-VM `feature?feature=snapshot`; file storages get qcow2 disks so they can take snapshots; on ZFS `pre_revert` is never taken | D11, D13, D23; §2, §3.1 `facts`, §3.2 `snapshot_mode`, §7.1 Test, §7.2 `file_format`, §7.5, §7.6, §9.4 dialog, §9.6, §9.7 `check`, §12.3-12.4, §13.3; tests 8, 28, 47, 59, 62; FakeProxmox `storage_type`; real host 16.3.13; open questions 18-20 |
| 2 | Terraform killed mid-clone leaves an untagged, locked VM C3 can't handle; Docker's 10 s grace kills Terraform first | Proxmox's clone call takes `name`, `description` and `pool` but no tags, so the tags come in a later update; the clone task is server-side and keeps `lock: clone`; `docker-compose.yml` sets no `stop_grace_period`; `DeployRunner.shutdown` cancels jobs and Terraform needs 30 s after SIGINT | Agreed | §7.4 `_our_clone` and C3 (task wait, state-has-resource and no-resource branches, `nextid` for invisible ids, re-reserve before `ready`); §7.3 shielded SIGINT grace; D27, §13.1 `stop_grace_period: 60s`; D2 docs; fake-terraform `die_after_clone` and FakeProxmox `clone_lock_outlives`, `hidden`; tests 25, 39; real host 16.3.14 |
| 3 | A slot can take another slot's reserved vmid and its resource row | `resources.record` and `_clash` (services/resources.py): for the same environment and provider id it updates the row, replacing `name` and `details`; `ResourceTaken` only across environments | Agreed | D10, M13, §3.2 resource note, §6.9 `reserve_vmid` (taken = another machine's row anywhere, or any machine's `ids.vmid`), §7.4 C2; tests 24, 24b |
| 4 | A ready Proxmox VM deleted by hand blocks Delete for good | Old §7.7 case 3 refused with no way past; §9.10 refused the data VM and mode `slot`; P3 §9.13 accepts only the retry | Agreed | D25 (`nextid?vmid` tells gone from hidden), D26 (`forget_vms` on Delete, Remove slot and their retries), §3.6, §4.1, §4.2, §7.4 PR1, §7.7, §9.5, §9.9, §9.10, §11, §12.5; tests 26, 29, 55, 56, 58; real host 16.3.15; open question 22 |
| 5 | The resize ran in `prepare`, before the deploy's refusals, and nothing restarted the live release | `prepare` before `resolve` (old §10.3); P3 §8.4's lists put the manifest hostname check, the database probe and the lag check (in `backup`) after it; nothing started the old release after the boot | Agreed, changed: `resize` goes after `backup`, not before it, because the lag check is in `backup` and is a refusal; `prepare` runs the resize's read-only checks early so a resize that can't go still fails first | D3, D12, M9, §6.3 step 5, §6.7, §7.5, §8.3, §9.3, §9.4, §10.3 (P3 §14's wording refined), §14; tests 21, 40, 43; open question 23 |
| 6 | Remove slot and Delete change things before checking that the VM can go | Old §9.5 deleted the instance in `slot` before `machine` checked; old §9.9 ran `unroute`, `undns`, `slots`, `data_server` first | Agreed | D26, M9, §6.1 `destroy_blockers` and `Blocker`, §7.7, §8.5, §9.5 and §9.9 (`check` and the API refuse; `machines.remove` checks again); tests 29, 33, 54, 55 |
| 7 | ESXi "gone while creating" leaves the old `vm` row, so E4 hits `ResourceTaken` | `uq_resources_environment_id_kind_name` (models/environment.py) and `_clash`'s same-name branch | Agreed | §6.9 `record_vm`, §8.2 E2 (forget the row with the ids, audit `machine.rebuild`), E3, E4; test 31 |
| 8 | ESXi leaks half-copied, unattached disks; the next create lands in `<name>_1/` | Sirdar's `_remove` (`esxi_provision.py:647-666`) destroys only; `create_vm` uses `vmPathName = "[<datastore>]"` (`esxi.py:350`), so ESXi picks the folder | Agreed, extended: E4 also cleans Slipway's own leftover disk in the folder before creating, and refuses other files | §8.1 `list_folder`, §8.2 E4, §8.5 destroy; FakeEsxi `_1` rule and unattached files; tests 31, 33; real host 16.3.17 |
| 9 | ESXi host key regenerated after `create_vm` guarantees a pin mismatch | Old E1 and §3.9 regenerated on any machine that "never booted", but the old key was already in `guestinfo.userdata` | Agreed | §3.9, §8.2 E1 (no VM: regenerate; `creating`: regenerate and rewrite the user-data before `power_on`; `booting`: rebuild); §9.11; test 31b |
| 10 | Cancel and timeouts leave hypervisor tasks running; the next step doesn't look | Only Terraform was stopped; `PyvmomiEsxi` cancelled only on its own timeout | Agreed, changed: Slipway waits for any running task before a change, but stops only Terraform and ESXi disk copies; stopping a Proxmox snapshot or rollback half-way (`DELETE /nodes/{node}/tasks/{upid}`) leaves a locked VM and a half-made snapshot, which is worse than waiting; ESXi snapshot tasks are mostly not cancelable | D24, M12, §3.2 `last_task`, §6.8, §7.4-7.7 and §8.2-8.5 (`wait_idle` before each change), §8.1, §9.12; FakeProxmox `task_outlives_cancel`, `stale_lock`, FakeEsxi `task_running`; tests 17, 49, 66; open question 21 |
| 11 | A VM host can be used by another environment, Add slot or an unmanaged claim; `proxy_address`/`lan_address` stay editable | P3 §9.1 refusal 4 and §9.8 ask only that the host be pinned; `api/v1/unmanaged.py`'s `POST /hosts/{id}/claim` checks no owner; `api/v1/hosts.py` PATCH writes `proxy_address` and `lan_address` | Agreed | D18, §6.1 `owned_host_refusal`, §9.2 refusal 0, §9.5, §10.4, §11 (Hosts PATCH list, claim); tests 52, 54, 58 |
| 12 | The Docker install meets the dpkg lock | `cloud-init status --wait` doesn't wait for `apt-daily`/`unattended-upgrades`; Proxmox's cloud-init upgrades packages by default (`ciupgrade`) | Agreed | §6.5 (`DPkg::Lock::Timeout=600`, 25-minute part, lock text, mirror note), §7.1 Test's `ciupgrade` warning, §7.2 `upgrade = false` when 0.115.0 has it, §13.3; `dpkg_locked(n)`; tests 8, 12, 22; real host 16.3.16; open question 25 |
| 13 | Proxmox can read the host key before cloud-init remakes it | The address is set in cloud-init's init-local stage, host keys later by `cc_ssh`; a booted template keeps its keys | Agreed (both fixes) | §7.4 C7 (wait for `boot-finished` through the agent), §6.4 (`reread_key` while `booting`), §13.3 (delete host keys, `cloud-init clean`); FakeProxmox `stale_template_key`; tests 18, 23, 67; real host 16.3.16 |
| 14 | The slices don't match the files they need | B2 called B1's `clean_config`/`test` in the same group and needed `schemas.py` (D1's); `env_steps_for` is in `environments.py` (P3 §8.4), C2's; `POST /instances` is `api/v1/instances.py`, D1's; the guard arrived in B1 while G2 tests needed it | Agreed | §6.1 (`clean_config`/`test` delegate to the clients; types in A2's `vmtypes.py`), §7.1, §8.1, §16.1 guard, §17 (A2 owns `tests/hypervisor_guard.py`, B2 owns its schemas, test 40 split into 40/40b, 41's `POST /instances` in 58, 44-45 and Activate in C2) |
| 15 | The timeouts don't add up; long ESXi jobs block page loads | 45 minutes against parts summing to well over 100; a 30-minute clone inside a 25-minute Terraform command; one `Semaphore(2)` for jobs and pages | Agreed | §6.3 (per-part limits, 120 min, the part named), §6.7 (90 min), §7.3 (per-command timeouts, `apply` 40 min), §10.5 (separate job and read pools, 5 s wait, `live.error = "busy"`), §14; tests 10, 21, 59 |
| 16 | Terraform upgrades aren't handled | `init` ran only when `.terraform` was missing; no lock file anywhere | Agreed, changed: the module ships `.terraform.lock.hcl` (its `zh:` hashes equal the Dockerfile's SHA-256), and `init -lockfile=readonly` runs whenever the module hash or Terraform version differs from the folder's `slipway-init.json`, rather than `init -upgrade` recording the hashes | §7.2, §7.3 step 4-5; tests 12, 13, 39 |
| 17 | State lock takeover and NULL lineage | `lock_id` has no foreign key, so a lock whose deployment row cascaded away matched nothing | Agreed | §3.4, §7.3 steps 1 and 3; tests 13, 14 |
| 18 | The migration is conditional; one name for two things | Old §3.8 created "only what is missing"; `MachineProvider` named both the enum and the protocol | Agreed, changed: the core revision holds `provider_accounts` and `machines` only; `address_claims` and `terraform_states` go with `machine_snapshots` in phase 5's own revision, since phase 4 doesn't use them (§15) | §3 (`ProviderKind`), §3.8, §15, §17 A1; test 1 |
| 19 | The fakes skip the behaviour the design relies on; tags must be sorted | The old fakes had no ZFS rule, tag ordering, clone lock, invisible ids, `_1` folders, stale keys or dpkg lock | Agreed | §7.2 sorted tags, §7.5, §16.1 (every knob named), §16.3 steps 13-17; tests 25, 27, 28, 31, 66, 67 |
| 20 | Recovery: a resize left off has no record; the revert hold offers a restore that can't work | Old §9.12 set only `last_error`; old hold text offered "or restore a backup" | Agreed | §4.2 `machine.left_off`, §6.7, §8.3, §9.12, §10.4 (Activate refuses an off VM), §12.3 power state; tests 49, 65 |
| 21 | M5 overstated the ESXi path | `CreateVM_Task` is waited before the UUID is known; E3's marker and name adoption covers it | Agreed | M5, D10 |
