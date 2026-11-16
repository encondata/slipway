# Backups and snapshots

Slipway keeps two kinds of copies of an app's data:

- **Backups** stay on the instance's host, next to the app. Slipway takes one before every change
  that replaces data (a deploy, a restore, a reset, a roll back) and whenever someone presses
  **Back up now**. They are what Restore and Roll back put back.
- **Snapshots** are kept on the Slipway server, encrypted. A snapshot holds an app's database, its
  files and the identity keys its data needs. A new instance, or **Reset data**, can start from
  one, on any host. A snapshot can be downloaded with a passphrase and uploaded to another Slipway.

Both work only for app instances whose `slipway.yml` declares its data and the commands that dump
and restore it ([manifest.md](manifest.md#data)). Nothing in Slipway knows how a particular app
stores its data: it runs the app's own commands, checks what they wrote, and keeps track of it.

---

## Contents

1. [What every copy carries](#what-every-copy-carries)
2. [Backups on the host](#backups-on-the-host)
3. [Snapshots on the Slipway server](#snapshots-on-the-slipway-server)
4. [Taking a snapshot](#taking-a-snapshot)
5. [Uploading and unlocking](#uploading-and-unlocking)
6. [Downloading](#downloading)
7. [Starting an instance from a snapshot](#starting-an-instance-from-a-snapshot)
8. [Deleting](#deleting)
9. [Making a snapshot file yourself: `slipway snapshot pack`](#making-a-snapshot-file-yourself-slipway-snapshot-pack)
10. [The file formats](#the-file-formats)
11. [Permissions and trust](#permissions-and-trust)
12. [Server settings and storage](#server-settings-and-storage)
13. [ServerSherpa](#serversherpa)

---

## What every copy carries

- **The database**, as the app's `dump` command wrote it, with its `data.format` label and, when
  the app has a `revision` command, the schema revision it was at.
- **The files**, when the app declares `export_files` (for a backup, when that backup includes
  them).
- **The identity keys** its data was made with: the values of the secrets marked
  `identity: true` (such as a password pepper or the key that encrypts 2FA seeds). Data without
  its keys is unreadable: people can't sign in, encrypted columns can't be decrypted. So the keys
  travel with the data, and restoring a copy puts its keys back. A restore that would change the
  keys says so first, and needs the `data:reset` permission.

Before Slipway replaces data with a copy it checks, and refuses before changing anything, that:

- the copy is complete (size and SHA-256 as recorded);
- its format label equals the target release's `data.format`;
- the target release accepts its revision (when the release has `revision` and `accepts`);
- for a snapshot, it is of the same app (`data.app`) and, unless you may download snapshots, from
  the same repository.

## Backups on the host

Backups live in the instance folder on the host, readable only by the SSH user:

```
<instance folder>/backups/
  20261115T101500Z-1a2b3c4d.dump    the database
  20261115T101500Z-1a2b3c4d.files   the files (only for backups "with files")
  20261115T101500Z-1a2b3c4d.json    what Slipway knows about it (never a secret value)
```

The instance's **Backups** card lists them. Slipway keeps the newest *Backups to keep* (5 by
default) of the ones it took itself, and never prunes the backup a failed job may still need for
Retry, Roll back or Undo. Backups you took with **Back up now** are deleted only by hand (at most
10 per instance, `SLIPWAY_MANUAL_BACKUPS_MAX`).

When an instance is deleted, its backups move to `<root>/.slipway-kept/` on the host with its
`.env`, each with a `<name>.identity.env` holding its identity keys, so they can still be used by
hand.

## Snapshots on the Slipway server

The **Snapshots** page lists every snapshot: its app, repository, where it came from, when it was
made, its revision, the sizes of its database and files, and its status:

| Status | Meaning |
|---|---|
| Taking | A snapshot job is copying it from an instance. |
| Locked | An encrypted file was uploaded and waits for its passphrase. It is deleted when nobody unlocks it within 7 days (`SLIPWAY_SNAPSHOT_LOCKED_DAYS`). |
| Checking | Slipway is checking it, every member and checksum, before it can be used. |
| Ready | It can seed instances and be downloaded. |
| Failed | The take or the check failed; the reason is shown. Delete it. |

Every stored snapshot is one encrypted file under a random key of its own. That key is kept in
Slipway's database, encrypted with `SLIPWAY_ENCRYPTION_KEY`. Unencrypted data never touches the
server's disk.

## Taking a snapshot

**Take snapshot** on an instance's Backups card (`data:backup`) runs a job on the host. It starts
only the data services, dumps the database, checks the dump, exports the files, and streams them
to the Slipway server, where they are encrypted as they arrive. The identity keys come from the
instance's live state.

- Tick **Stop the app while copying** (needs `instances:operate` too) for a consistent copy: the
  app is down while the data is exported, and is started again afterwards. Without it, the
  database and the files are copied a moment apart while the app runs, and the job log says so.
- An instance whose data a failed job left half-changed can't be snapshotted until it is retried,
  restored or rolled back: a snapshot of it would seed others with that state.

## Uploading and unlocking

**Upload…** on the Snapshots page (`snapshots:upload`) takes either:

- a **`.slipway-snapshot` file**, downloaded from a Slipway or made with
  `slipway snapshot pack --passphrase-stdin`. It is encrypted, so Slipway stores it as it is and
  shows it as Locked. **Unlock…** asks for its passphrase (at most 5 tries per 10 minutes); Slipway
  then checks the whole file and marks it Ready, or Failed with the reason.
- a **plain `.tar` or `.tar.gz`**, made with `slipway snapshot pack` without a passphrase. Slipway
  encrypts it while it is uploaded, checks it in the same pass, and refuses it if anything is
  wrong. Delete your plain copy afterwards: it holds the identity keys unencrypted.

A file is at most 20 GiB (the members added up, `SLIPWAY_SNAPSHOT_MAX_BYTES`), and all snapshots
together at most 100 GiB (`SLIPWAY_SNAPSHOT_TOTAL_BYTES`). A reverse proxy in front of Slipway
must accept request bodies that large.

## Downloading

**Download…** (`snapshots:download`) asks for a passphrase (12 to 1024 characters; **Generate**
makes a strong one). Slipway puts a new key block, derived from the passphrase with scrypt, in
front of the stored, still-encrypted file and streams it to you as `<name>.slipway-snapshot`.
`SLIPWAY_ENCRYPTION_KEY` never leaves the server, and Slipway doesn't keep the passphrase: without
it, the file can't be opened. Anyone with the file **and** the passphrase can read the whole
database and its identity keys.

The download link works once, for the user who asked for it, for 10 minutes.

## Starting an instance from a snapshot

On the instance form, **Start with: A snapshot** (`data:reset`) makes the first deploy restore it:
after the build, Slipway checks the snapshot, copies it to the host, restores the database and the
files, runs the app's `after_import` (ServerSherpa signs everyone out there), and only then starts
the app. Its identity keys become the instance's. A first admin is optional: give one only if the
snapshot has no account you can sign in with.

- The first deploy refuses to seed a host that already has data for the instance, and says how to
  start afresh.
- **Reset data → From a snapshot** (`data:reset`) does the same on a live instance, after backing
  up the data it replaces.
- A snapshot from another repository (or an unknown one) also needs `snapshots:download`.
- When the data lives outside the host (`has_data` exits 4: a managed or shared database), Slipway
  backs it up but won't seed it, restore over it or reset it.

## Deleting

**Delete** (`data:reset`) removes a snapshot and its file. It is refused while the snapshot is in
use: being taken or checked, used by a running job, the starting snapshot of an instance that has
never gone live, or the one a failed restore still needs.

## Making a snapshot file yourself: `slipway snapshot pack`

`slipway snapshot pack` turns a dump you made yourself (from a laptop, or from a backup kept on a
host) into a file to upload. It runs anywhere Slipway is installed and needs no server.

```
slipway snapshot pack --app ID --app-name NAME --format F --database FILE [--revision-file R]
    [--commit SHA] [--repository OWNER/NAME] [--files FILE --files-format F]
    [--identity-env keys.env --identity K1,K2] [--source S] [--notes T] [--passphrase-stdin] --out FILE
```

| Option | Meaning |
|---|---|
| `--app`, `--app-name` | `data.app` and `name` from the app's slipway.yml. A snapshot seeds only an app with the same id. |
| `--format` | `data.format` from the app's slipway.yml, such as `pg-custom`. |
| `--database` | The database dump, as the app's `dump` command writes it. |
| `--revision-file` | A file holding the schema revision, as `commands.revision` prints it. Without it, Slipway can't check the revision against a release. |
| `--commit`, `--repository` | The commit and the GitHub repository the data belongs to. Seeding an instance of another repository needs `snapshots:download`. |
| `--files`, `--files-format` | The files archive, as `commands.export_files` writes it, and `data.files.format`. |
| `--identity-env`, `--identity` | A `KEY=value` file and the keys of it to include (the secrets marked `identity: true`). |
| `--source`, `--notes` | Where the data comes from (default: this computer's name), and notes shown with the snapshot. |
| `--passphrase-stdin` | Encrypt the file with a passphrase: one line on stdin, or typed twice at a terminal. **Recommended**: without it the file, identity keys included, is plain. |
| `--out` | The file to write. It must not exist yet; it is written owner-only, through `<out>.partial`. |

It prints the file's size and SHA-256 and what to do next.

## The file formats

**Inside** every snapshot is an uncompressed POSIX (PAX) tar with exactly these regular files, in
this order:

1. `slipway-snapshot.json`: what the snapshot is;
2. `identity.json`: the identity keys and their values (only when it carries any);
3. `database`: the dump;
4. `files`: the files archive (only when it has files).

```json
{"format": "slipway-snapshot", "version": 1,
 "app": "serversherpa", "app_name": "ServerSherpa", "repository": "encondata/BaseCampV3",
 "commit": "<40 hex>", "source": "uat", "created_at": "2026-11-15T10:15:00Z", "notes": "",
 "database": {"format": "pg-custom", "revision": "0090", "bytes": 431234567, "sha256": "<64 hex>"},
 "files": {"format": "serversherpa-objects-v1", "bytes": 1234, "sha256": "<64 hex>"},
 "identity": {"keys": ["SS_PASSWORD_PEPPER", "SS_TOTP_ENCRYPTION_KEY"], "bytes": 120, "sha256": "<64 hex>"},
 "producer": "slipway 0.9.0"}
```

`repository`, `commit`, `revision`, `files` and `identity` may be null. Unknown keys, other
members, extra bytes, links and sparse files are refused, and every size and checksum must match.
A gzipped tar is accepted on upload; bz2, xz and zstd aren't.

**The encrypted file** (`.slipway-snapshot`, stored as `.sbx`) is that tar in AES-256-GCM chunks:

```
"SLWSNAP1" | header length | header JSON | key block length | key block JSON | chunks
```

- The header names the cipher (`aes-256-gcm-stream`), the chunk size (1 MiB) and a nonce prefix.
  Each chunk is authenticated with the header's hash and its own number, and the last one is
  marked, so a reordered, cut-off, extended or altered file is refused.
- The key block is `{"kdf": "none"}` on a Slipway server (the key is in its database), or
  `{"kdf": "scrypt", "log2_n": 17, "r": 8, "p": 1, …}` in a downloaded or packed file: the data
  key, wrapped with a key derived from the passphrase.

## Permissions and trust

| Permission | Allows | Roles |
|---|---|---|
| `data:read` | Seeing backups and snapshots (names, sizes, dates; never their contents) | viewer, developer, maintainer |
| `data:backup` | Back up now; take, rename and keep snapshots | developer, maintainer |
| `data:restore` | Restore a backup made with the same keys; roll back a failed deploy | developer, maintainer |
| `data:reset` | Reset data, start instances from a snapshot, restore old identity keys, delete backups and snapshots | maintainer |
| `snapshots:upload` | Upload snapshot files | maintainer |
| `snapshots:download` | Download snapshots; seed instances of another repository from them | admin only |

Restore, Reset, Start over and Roll back also need the instance's name typed back.

A snapshot's database runs as SQL inside the app it seeds, and it carries the keys people sign in
with. Upload and seed only snapshots you trust. The `data.app` check guards against mistakes, not
against an attacker: a slipway.yml can claim any app id. That is why uploading is a maintainer's
permission and downloading an admin's.

## Server settings and storage

| Setting | Default | Meaning |
|---|---|---|
| `SLIPWAY_STORAGE_DIR` | `/var/lib/slipway` in the image (`data/files` on the server) | Where snapshots are kept: `bundles/<id>.sbx`, and `incoming/` for transfers in flight. Owner-only (uid 10001). |
| `SLIPWAY_SNAPSHOT_MAX_BYTES` | 20 GiB | The largest snapshot accepted. |
| `SLIPWAY_SNAPSHOT_TOTAL_BYTES` | 100 GiB | All stored snapshots together. |
| `SLIPWAY_SNAPSHOT_TRANSFERS` | 2 | Takes, uploads, checks and downloads at once (1-8). |
| `SLIPWAY_SNAPSHOT_KDF_SLOTS` | 2 | Passphrase key derivations at once (1-4). |
| `SLIPWAY_SNAPSHOT_LOCKED_DAYS` | 7 | How long an uploaded file waits for its passphrase. |
| `SLIPWAY_BACKUP_FREE_MARGIN_MB` | 1024 | Free space a host must keep beyond a backup's expected size. |
| `SLIPWAY_MANUAL_BACKUPS_MAX` | 10 | Backups taken by hand that one instance may keep. |

**Back up `data/files` together with `data/postgres`, and keep `SLIPWAY_ENCRYPTION_KEY`.**
Without the key, the stored snapshots can't be opened. `slipway rotate-encryption-key` re-wraps
the snapshots' keys with the new key; the files themselves don't change.

If the storage folder isn't writable, the Snapshots page and its API answer with the command that
fixes it; deploys and backups are unaffected.

## ServerSherpa

ServerSherpa (BaseCampV3) declares all of this in its
[slipway.yml](examples/serversherpa.slipway.yml), through `deploy/stack/ss-stack`:

| slipway.yml | ss-stack | What it does |
|---|---|---|
| `has_data` | `has-data` | 0 when the database volume has ServerSherpa's tables; 3 when there is no volume or no tables; 4 with `STACK_EXTERNAL_DATA=1`, `STACK_DB_HOST` or on a LAN data VM (`STACK_DB_PUBLISH=1`) |
| `data_up` | `data` | starts only the database and the object store |
| `dump` | `pgdump` | `pg_dump -Fc --no-owner --no-acl` to the file Slipway names (format `pg-custom`) |
| `verify_dump` | `verify-dump` | `pg_restore` reads the whole archive to `/dev/null`, in a container with no network |
| `revision` | `revision` | prints the Alembic revision, such as `0127` |
| `accepts` | `accepts` | 0 when the commit has the migration `<revision>_*.py`; this is a membership test, so a dump from another branch is refused too |
| `restore` | `restore` | stops the API, the web apps and the status page, empties the schema and runs `pg_restore` |
| `export_files`, `import_files` | `export-objects`, `import-objects` | `deploy/stack/objects.py` in the release's api image: every object of the bucket in one PAX tar (format `serversherpa-objects-v1`, content types in `SLIPWAY.content_type`), and back |
| `after_import` | `clear-sessions` | signs everyone out: a copy's sessions belong to its source |
| `seed` | `seed` | label fonts and templates, and the Learning space when the learning site runs |

Its identity keys are `SS_PASSWORD_PEPPER` and `SS_TOTP_ENCRYPTION_KEY` (the "sign-in keys"):
with them, people sign in with the passwords and 2FA codes they had when the data was made.

`scripts/make-seed-snapshot.sh` in BaseCampV3 makes an encrypted snapshot from the Mac dev stack
(the dev Postgres, the dev bucket and the repo `.env`'s two keys) with `slipway snapshot pack`:

```
printf '%s\n' "$PASSPHRASE" | scripts/make-seed-snapshot.sh --out seed.slipway-snapshot
```

Upload it on the Snapshots page; Slipway asks for the passphrase.
