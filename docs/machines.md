# VMs on Proxmox and ESXi

An environment's slots and data server can run on **VMs that Slipway makes** on a Proxmox cluster
(through Terraform) or a standalone ESXi host (through pyvmomi). Slipway makes each VM at its slot's first
deploy, pins its SSH host key, installs Docker, and from then on treats it as an ordinary host. It resizes
the VM, takes VM snapshots of it, and destroys it when the slot or the environment goes.

This page is for the people who set this up and run it. How environments work in general is in
[environments.md](environments.md). The design, with every rule and message, is
[phase5-machines.md](phase5-machines.md). The app needs nothing new in its `slipway.yml`.

## Two users called slipway

Two different users carry the name, and it helps to keep them apart:

- **`slipway@pve`** is the **Proxmox API user**. Slipway holds an API token for it and makes VMs with it.
  You create it once, on Proxmox ([Proxmox](#proxmox)).
- **`slipway`** is the **Linux user on each VM**, which Slipway logs in as over SSH. Cloud-init makes it on
  the VM's first boot, with Slipway's SSH key and **passwordless sudo**. On ESXi, Slipway's own user-data
  makes it. On Proxmox, cloud-init's `ciuser` setting takes over the Ubuntu cloud image's default user and
  its sudo rule, which holds only for Ubuntu cloud images.

Droplets on DigitalOcean have a `slipway` user too, but with no sudo ([digitalocean.md](digitalocean.md#droplets)).

## What you need first

1. **A Proxmox or ESXi account in Slipway**, added by an admin under *Settings → Integrations*, with its
   certificate trusted and a passing Test ([Accounts](#accounts)).
2. **A network on that account** with a subnet, a gateway and preferably an address pool. Every VM gets a
   static address ([Networks and addresses](#networks-and-addresses)).
3. **A template** (Proxmox) or **seed VM** (ESXi) made from Ubuntu 24.04's cloud image.
4. **A reachable Ubuntu mirror** from the VMs, unless the template already has Docker: Slipway installs
   Ubuntu's `docker.io` and `docker-compose-v2` packages on a new VM. Nothing is downloaded from anywhere
   else.
5. **The `machines:write` permission** for whoever creates an environment with VMs, resizes them or takes
   VM snapshots. Maintainers have it.
6. For Proxmox, **this build of Slipway must ship Terraform's lock file**
   ([The Terraform lock file](#the-terraform-lock-file)).

## Proxmox

### The role, the user and the token

Make a pool (for example `slipway`) for the template and the VMs Slipway makes. Then a role with exactly
what Slipway needs:

```sh
pveum role add SlipwayProvision -privs "VM.Allocate VM.Clone VM.Audit VM.PowerMgmt VM.Config.CDROM \
  VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network \
  VM.Config.Options VM.Snapshot VM.Snapshot.Rollback VM.GuestAgent.Audit VM.GuestAgent.FileRead \
  Datastore.AllocateSpace Datastore.Audit SDN.Use Pool.Audit Sys.Audit"
```

On Proxmox 8, use `VM.Monitor` instead of the two `VM.GuestAgent` privileges (Proxmox 9 split it in two).
`Sys.Audit` is optional and counts on `/nodes/<node>`: without it Test can't check the network's bridge and
only warns.

Then the user, its rights and a token:

```sh
pveum user add slipway@pve
pveum acl modify /pool/slipway -user slipway@pve -role SlipwayProvision
pveum acl modify /storage/<storage> -user slipway@pve -role SlipwayProvision
pveum acl modify /sdn/zones/localnetwork/<bridge> -user slipway@pve -role SlipwayProvision
pveum user token add slipway@pve slipway --privsep 0
```

Optionally add `pveum acl modify /nodes/<node> -user slipway@pve -role SlipwayProvision`, so Test can check
the bridges. The token is shown once, as
`slipway@pve!slipway=<uuid>`; that whole value is what Slipway's account form calls the token.

### The template

From Ubuntu 24.04's cloud image:

1. Add the guest agent: `virt-customize -a noble-server-cloudimg-amd64.img --install qemu-guest-agent`.
2. Truncate `/etc/machine-id`, delete `/etc/ssh/ssh_host_*` and run `cloud-init clean`, so no clone starts
   with the template's host key.
3. Make the VM with the image as its boot disk `scsi0`, a cloud-init drive on `ide2`, `--agent enabled=1`
   and `--ciupgrade 0`, inside the pool, and convert it to a template.

`--ciupgrade 0` keeps cloud-init from upgrading every package at first boot, so a new VM's first boot takes
a predictable time. Test warns when it is on. Docker may be installed in the template already; Slipway then
skips its install.

Slipway reads each new VM's host key through the guest agent, over the Proxmox API whose certificate you
trusted, and pins it before its first SSH connection. That is why the agent matters, and why the template
must have no host keys of its own.

### Storage and VM snapshots

Which storage the VMs use decides whether they can have VM snapshots:

| Storage | VM snapshots |
|---|---|
| LVM-thin, Ceph RBD, a file storage (dir, NFS, CIFS, GlusterFS; Slipway writes qcow2 disks there) | any snapshot can be reverted to |
| ZFS (`zfspool`, such as `local-zfs`) | only the newest snapshot can be reverted to |
| thick LVM, raw files | none |

Test records the storage's type, and the VM records what Proxmox says once it is made.

## ESXi

Slipway works with a **standalone ESXi host** with a **paid licence** (free ESXi's API is read-only). Test
refuses vCenter. The account needs:

- the host's **URL** and a **user and password** whose role can create, change, power, snapshot and delete
  VMs and copy and delete files on the datastore. The password stays inside Slipway's process;
- a **datastore** for the VMs;
- a **port group** per network;
- optionally a **resource pool**;
- a **seed VM**: Ubuntu 24.04's cloud image with `open-vm-tools`, powered off, with exactly one disk and
  no VM snapshots. Slipway copies its disk for every new VM.

On ESXi, Slipway generates each VM's host key, hands it to cloud-init through the VM's guestinfo settings,
and pins it. Once the pin is made it deletes the user-data from the VM's settings and the private key from
its own database. **ESXi may still hold a copy of the user-data in the VM's `vmware.log`**, which includes
that private key. Limit who can read the datastore's VM folders.

## Accounts

Under *Settings → Integrations*, the **Proxmox** and **VMware ESXi** cards list the accounts. Anyone with
`providers:read` sees them; only admins (`providers:write`) add, change, trust, test or remove one.

- **Adding** one asks Slipway to read the API's certificate first. The dialog shows it (fingerprint,
  subject, issuer, expiry, names) and asks **Trust this certificate?**. Slipway then trusts that
  certificate alone for this account. Test runs by itself after the save.
- **A renewed certificate** stops every call with the "certificate changed" answer until someone with
  `providers:write` presses **Trust…** on the card again.
- **Edit**: the secret is kept when you leave it empty and the URL (and ESXi's user) don't change. While a
  VM uses the account its URL can't change (make another account for the new address), and a network a VM
  uses can't be removed or renamed.
- **Remove** asks for the account's name and is refused while a VM or an environment uses it. An account
  only deleted environments point at is kept as a **Removed** row.

## Networks and addresses

Every VM gets a **static IPv4 address** on one of the account's networks. A network has a name, a subnet, a
gateway, DNS servers (empty means the gateway), optionally an **address pool** (`first` to `last`, at most
4096 addresses), and on Proxmox a bridge and an optional VLAN tag, on ESXi a port group.

All the VMs of one environment use **one account and one network**, so they share a subnet and a gateway.

In the create flow each VM's address is picked from the pool or typed. Slipway keeps a registry of every
address it gave out or knows a host by, and refuses one already in use. Before it makes a VM it also checks
that nothing answers on that address's SSH port (`SLIPWAY_VM_ADDRESS_PROBE`), so a forgotten machine
left running there is caught. An address goes back to the pool once its VM is deleted.

## Creating an environment with VMs

In **Environments → New environment**, choose **Hosts** under *Where*. On the Hosts step each slot's select
offers your hosts and **New VM on <account>** for every Proxmox and ESXi account. Choosing a new VM opens a
small form: network, address (from the pool or typed), vCPU, memory in GB and disk in GB. The defaults are 4
vCPU, 8 GB and 64 GB. Limits: 1-64 vCPU, 2-256 GB of memory, 20-4096 GB of disk.

Once one slot is a new VM, the other slots' new VMs keep its account and network. Review lists each VM:
`New VM slipway-uat-blue on pve, at 10.0.0.12 on lan, 4 vCPU · 8 GB · 64 GB`.

**Nothing touches the hypervisor at create.** Slipway writes a planned host row per VM, named
`slipway-<env>-<slot>` (which is also the VM's name), and claims its address. The check may warn that the
account hasn't been tested lately, or that the storage's free space (from the last Test) is less than the
new disks need.

A VM Slipway made belongs to its environment: only that environment's slots run on it. The Hosts page
refuses Delete, Reset key, edits of its address or credentials, and Check before it is built. It goes when
its slot is removed or the environment is deleted.

## What a deploy does to a VM

The first deploy to a slot on a new VM runs `prepare` right after `resolve`. It makes the VM (Proxmox:
Terraform clones the template; ESXi: Slipway makes an empty VM and copies the seed's disk in), boots it,
waits for cloud-init, pins its host key, then over SSH checks that `slipway` can use sudo, installs Docker
when it is missing, adds `slipway` to the `docker` group and makes the deploy root. Each VM takes several
minutes. The step is named `Prepare the VM slipway-uat-blue on pve`, and its limit is 120 minutes.

On a VM that is already made, `prepare` only checks it (and starts it if it is off). If the hypervisor can't
be reached, it warns and the deploy goes on over SSH.

**A deploy cut off half way** (a failure, a restart, a cancel) leaves the VM half-made. Before the slot ever
runs the app, Slipway may finish it, or delete its own half-made VM and make it again, after checking that it
really is Slipway's (its name and Slipway's tags or markers). Once a VM is ready, Slipway never makes it
again by itself.

A running hypervisor task on the VM (Slipway's own or anyone's) is waited for, up to 10 minutes, before any
change. Slipway never stops a snapshot, rollback or delete task; on a cancel it stops only Terraform and an
ESXi disk copy.

## Terraform (Proxmox)

Slipway ships its own Terraform module, `slipway/terraform/proxmox-vm/`, with exact versions of Terraform
(1.16.5) and the `bpg/proxmox` provider (0.115.0). For each VM it writes only the variables. The image
installs both from checksummed downloads into an offline mirror (`docker/terraformrc`), so `terraform init`
never goes online.

**The state lives in Slipway's database**, encrypted with `SLIPWAY_ENCRYPTION_KEY` like every other
secret, one per VM. A working copy is kept in `<terraform dir>/<machine id>/` (by default
`<storage dir>/terraform/`, mode 700). Before each run Slipway makes the two agree: the newer one wins, and
after every command that can write state, the state is saved back.

If the two have **different lineages**, the step fails with `Slipway has two different Terraform states for
<vm>; it changed nothing. Compare them in <folder> and the database before going on`. Look at which one
holds the VM that is really on Proxmox (its `vmid`), then, with no job running on the environment:

- to keep the **database's** state, move `terraform.tfstate` out of the working folder; the next run
  writes the database's copy there;
- to keep the **folder's** state, clear the database's copy, for example
  `UPDATE terraform_states SET lineage = NULL WHERE machine_id = '<machine id>';`; the next run saves the
  folder's copy.

Then retry the job.

### The Terraform lock file

Terraform needs `slipway/terraform/proxmox-vm/.terraform.lock.hcl`, which pins the provider's hashes. It
ships with Slipway, for `linux_amd64` and `linux_arm64`, next to the Dockerfile's SHA-256 lines for the
Terraform and provider downloads; `tests/test_image.py` checks that the two agree. When the Terraform or
provider version changes, record the new sums from the releases' `SHA256SUMS` files and regenerate the lock
file in that folder with `terraform providers lock -platform=linux_amd64 -platform=linux_arm64`. A build
without the lock file fails every Proxmox `prepare` with `Slipway's bundled Terraform module has no
.terraform.lock.hcl, so this build of Slipway can't run Terraform`. ESXi doesn't use Terraform.

The module leaves cloud-init's first-boot package upgrade (`ciupgrade`) to the template, so it works on
Proxmox versions before 8.1, which don't have the option: a clone keeps the template's setting. Make the
template with `--ciupgrade 0` (Test warns when it is on).

`SLIPWAY_TERRAFORM_BINARY` may name OpenTofu's `tofu`, which reads the same module; that isn't tested.

### pyvmomi

ESXi support uses pyvmomi 8.0.3.0.1, pinned with its hash. It is published only as a source package, so the
image builds it during `pip install`, and the build backend pip uses for that isn't hash-checked. The
Dockerfile says so; that gap is accepted, and no pinned wheel is pre-built.

## Resizing

**Resize…** on a VM's row (needs `machines:write`) sets new vCPU, memory and disk sizes, and how many
automatic VM snapshots to keep. Disks only grow. Nothing touches the hypervisor then: the new size applies
in the `resize` step of **the slot's next deploy**, after its backup, so every check of that deploy comes
first. The VM shuts down cleanly, is resized and starts again, and its live release is started again. A
single-slot environment is down meanwhile. The active slot of two isn't resized while it is active: its row
says `Resize pending: applies at <slot>'s next deploy when <slot> is idle`.

- **Proxmox** takes a `pre_resize` VM snapshot first where the storage allows it. Cloud-init grows the root
  file system at boot; the step warns if it didn't.
- **ESXi can't grow a disk that has VM snapshots.** A disk grow deletes Slipway's own snapshots of the VM
  (the Deploy dialog names them) and refuses if the VM has snapshots Slipway didn't take. A vCPU or memory
  change takes a `pre_resize` snapshot.

If Slipway restarts during a resize, the VM may be left off. The environment's notice says so, Activate
refuses that slot, and the next deploy to it starts the VM and finishes the resize.

### Growing the data server's VM by hand

Slipway doesn't resize the data server's VM once it is made: both slots' data is on it. To grow it, pick a
quiet window and do it on the hypervisor yourself:

1. Stop both app slots from their instance pages, then shut the data VM down.
2. On Proxmox, change its cores and memory and grow its disk (`qm set <vmid> --cores 8 --memory 16384`,
   `qm resize <vmid> scsi0 +64G`); on ESXi, the same in the Host Client. On ESXi, delete its VM snapshots
   first.
3. Start it. Cloud-init's growpart grows the root file system at boot; check with `df -h /`.
4. Start the app slots again.

Slipway never applies a size to a ready data server, so the change doesn't fight Terraform.

## VM snapshots

A VM snapshot is the whole disk: code, data, Docker and Slipway's release folders, kept on the hypervisor
and gone with the VM. It isn't a backup. Slipway offers them only for an environment of **one app slot that
keeps its own data, on a VM Slipway made**, whose storage can take them. Blue/Green and data-server
environments have none: the other slot is the way back for code, and backups are the way back for data.

The **VM snapshots** card on the environment page lists them, newest first, with why each was taken and
whether the hypervisor still has it.

- **Take a VM snapshot…** (`machines:write`): with an optional note. You can keep 10 you took; delete one
  first after that. Slipway also takes `pre_resize` and `pre_revert` snapshots, and keeps the newest 3 of
  those by default (1-10, set in Resize…).
- **Revert…** (`machines:write` and `data:reset`, typed name): the VM's disk goes back to the snapshot.
  Everything written since is lost, including the backups taken since (the dialog names them). Slipway
  first takes a `pre_revert` snapshot, so the revert can itself be reverted, unless you skip it. It then
  puts its own records (the live release, the data's state, the identity keys) back to what they were, and
  starts the app.
- **On ZFS** a revert goes only to the newest snapshot, and it can't be undone: Slipway can't keep a
  `pre_revert` snapshot. To go back further, delete the newer snapshots first.
- **Delete** removes one snapshot.

If a revert fails, or Slipway restarts during it, the data is held: the disk may already be back while the
records name a later release. Revert to the same snapshot again.

## A VM deleted by hand

Slipway never makes a ready VM again by itself. A deploy to a slot whose VM is gone fails with the lost
text, which points at **Forget the VM…**. That button shows on the slot's row once the live read finds the
VM gone (needs `machines:write` and `environments:delete`, typed name). Slipway then forgets the VM's
records, and the slot's next deploy makes a new VM at the same address with a new host key.

Forget is refused while Slipway can still see the VM, for the active slot of two, and for a VM that held
the data (the data server, or a single slot that keeps its own data). That data is gone with the VM: delete
the environment and create it again from a snapshot.

A Proxmox VM that the token can no longer see (moved out of the pool) shows as **Hidden**, not gone.

## Removing a slot or deleting the environment

**Remove a slot** and **Delete environment** first check that every VM involved can go (`check` step). If
one can't (the account is gone, the VM is hidden, it lost Slipway's markers, its disks were changed by
hand), nothing has been removed yet. When the VM is one Slipway can't account for, tick **Forget the VMs
Slipway can't remove** (needs `machines:write` and `environments:delete`, typed name). Slipway then forgets
those VMs instead of destroying them, and the environment's notice names them for you to remove by hand.

The deletion destroys the VMs with their disks, green, then blue, then the data VM. If an app VM can't be
removed, the data VM is kept and the step fails naming both.

When the data lives on a VM (the data server, or a single slot that keeps its own data), the VM is the
data's only home. Delete then takes a snapshot first by default. Going without one needs the **Delete
<env>'s data with it** box (`drop_data`) and `data:reset`. An environment that never held data needs
neither.

**What goes:** the VMs and their disks, their VM snapshots, their Terraform state and working folders, their
host rows, their address claims, and phase 3's Switchyard hosts and DNS records. **What stays:** P2 snapshots
stored on Slipway, and on ESXi any file the destroy left in the VM's folder (the step warns and names them).

## Restarts and Slipway's stop grace

`docker-compose.yml` gives Slipway's container **60 seconds** to stop (`stop_grace_period: 60s`). On
shutdown Slipway cancels its jobs: Terraform gets SIGINT and time to save its state, and ESXi disk copies are
cancelled. Docker's default of 10 seconds would kill Terraform before it saved, which is the commonest way a
clone is left half-made. If you run Slipway another way, give it at least 60 seconds too. A shorter grace
leaves half-made VMs for the next deploy to clean up.

## Permissions

| Permission | Roles | Allows |
|---|---|---|
| `providers:read` | developer, maintainer, admin | see the accounts (never their secrets), their networks and free addresses |
| `providers:write` | admin | add, change, trust, test and remove accounts |
| `machines:write` | maintainer, admin | make VMs for environments, resize them, take and delete VM snapshots, forget a lost VM |

Reverting a VM snapshot also needs `data:reset`. Forget the VM, and forgetting VMs on Remove or Delete,
also need `environments:delete`.

## Settings

| Setting | Default | What it does |
|---|---|---|
| `SLIPWAY_TERRAFORM_BINARY` | `terraform` | the Terraform binary |
| `SLIPWAY_TERRAFORM_CLI_CONFIG` | `/etc/slipway/terraformrc` | the offline mirror's CLI config |
| `SLIPWAY_TERRAFORM_DIR` | `<storage dir>/terraform` | the working folders |
| `SLIPWAY_TERRAFORM_PARALLEL` | 2 | Terraform processes at once (1-8) |
| `SLIPWAY_VM_ADDRESS_PROBE` | `true` | probe a new VM's address before making it |

## API

Everything is under `/api/v1`.

| Method and path | Does |
|---|---|
| `POST /provider-accounts` `{provider: "proxmox" \| "esxi", name, secret, url, ..., networks, trust_fingerprint?}` | add (409 `tls_untrusted` with the certificate when not trusted yet) |
| `POST /provider-accounts/{id}/trust` `{fingerprint}` | trust the live certificate |
| `GET /provider-accounts/{id}/addresses?network=&count=` | free pool addresses, and who holds the others |
| `POST /environments` with `hosts.<slot> = {machine: {account_id, network, address, cores?, memory_mb?, disk_gb?}}` | create with new VMs |
| `POST /environments/{id}/slots` `{machine}` | add a slot on a new VM |
| `GET /environments/{id}/machines` | each VM's record, with a live read of its power, tasks and state |
| `PATCH /environments/{id}/machines/{slot}` `{cores?, memory_mb?, disk_gb?, keep_vm_snapshots?}` | resize at the next deploy |
| `POST /environments/{id}/machines/{slot}/forget` `{confirm}` | forget a lost VM |
| `GET /environments/{id}/vm-snapshots`, `POST /environments/{id}/vm-snapshots` `{note?}` | list, take |
| `POST /environments/{id}/vm-snapshots/{sid}/revert` `{confirm, skip_pre_revert?}` | revert |
| `DELETE /environments/{id}/vm-snapshots/{sid}` | delete a VM snapshot |
| `DELETE /environments/{id}/slots/{slot}` `{confirm, forget_vms?}` | remove a slot |
| `DELETE /environments/{id}` `{confirm, snapshot?, drop_data?, forget_vms?}` | delete |
