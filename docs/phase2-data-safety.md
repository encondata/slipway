# Phase 2 design: Data safety (final)

Branch `sirdar` at 46ab8f2. This is the final, complete design for phase 2 of bringing Sirdar into Slipway: dumps before changes, the Backups list, restore, reset, roll back, snapshot bundles (take, upload, download, import, seed), starter content and the first admin. It replaces the merged design. Every critique point from the four reviews (correctness, data loss, security, generality) was checked against the code. Most were accepted and are built in below. The rejected ones are listed, with the reason, in Appendix A.

Line references are to Slipway at 46ab8f2 unless another file is named. Nothing in Slipway is written for ServerSherpa: the repository describes itself in slipway.yml (§2), and a repository without slipway.yml, or whose slipway.yml declares no data, deploys exactly as today (I7).

---

## 0. Decisions and why

The fixed decisions from the user (Seed Data recipes later; bundles stored, uploadable and downloadable with a passphrase; Slipway owns dump naming and retention; a safety dump before every data-replacing change; jobs on the deployments machinery; typed names and own permissions; Slipway's users only; ServerSherpa declares its commands in its own slipway.yml) are taken as given. The decisions made in this design:

| # | Decision | Why (verified in the code) |
|---|---|---|
| D1 | Every data job is a `Deployment` with a `kind`. | `Steps`, `LogSink`, `_finish`, the runner lock and retry are keyed on Deployment (deployer.py:1088-1349, 2190-2326). `_active_deployment` (instances.py:100-108) and `hosts._deploying` count every queued or running row, so moves, placement changes and deletes are already refused while any job runs. |
| D2 | Restore, roll back and reset redeploy the **live release in place**, with data steps between `build` and `start`. They never call GitHub. | `_install` already reuses a kept release: it skips the upload (1693-1700) and re-reads slipway.yml from the folder (1665-1680). No old commit is fetched, so "a commit without slipway.yml can't be deployed" (1915-1917) never applies, and a restore works while GitHub is down. |
| D3 | **Live render.** Every job that runs the live release's commands re-reads its slipway.yml from `current` and re-plans with the inputs the live release went live with (stored in `app_state.live` at `finish`), today's paths, the stored secrets and the instance's variables, then writes `shared/.env`. No `.env.live` copy and no stored argv are used. | `{slipway.env_dir}` and `{slipway.release}` render as absolute paths (deployer.py:1875-1879), and folder moves never update `app_state` (920-1085), so stored commands go stale after a move. After a failed deploy, `shared/.env` belongs to the failed release (1974-1985) while `current` is the old one (1730-1742). Re-rendering with the *current* settings would deploy settings edited for the failed release (correctness 13, data-loss 15). |
| D4 | The pre-deploy dump runs the **live release's** `data_up`, `dump`, `revision` and `verify_dump` against the live render. The new release's commands are used only when the live release declares no `dump` (the deploy that adds it). The step runs after `build` and puts the new `.env` back when it ends. | The live release's code made the data, so the backup carries the live format, which is what Roll back needs (§9.2 rule 4). The live ss-stack can't read the new `.env` (its `check_apps` dies on an app it doesn't know, ss-stack:372-376). Running after `build` keeps the window between dump and `start` short. |
| D5 | Runtime values are **slots**: `{slipway.out}`, `{slipway.in}` and `{admin.<field>}`. Each is a whole argument, rendered as `{"slot": …}` objects and quoted at run time. Commands that move a file can use **stream mode** (`stdout: true` or `stdin: true`) instead, so a plain `pg_dump`/`mysqldump` works without a wrapper script. | `plan()` renders every argument eagerly and raises "has no value" (manifest.py:433-434, 662-665); an object never collides with rendered text. `app_command` quotes every item (1886). Stream mode also avoids bind-mounting the 0700 backups folder into containers that run as another user. |
| D6 | **Revision** is captured from stdout to a file (stderr goes to the log), up to 16 KiB of opaque text. `accepts` reads it from `{slipway.in}` (or on stdin) and answers 0 (yes), 3 (no) or anything else (the check failed). | It isn't Alembic-specific. A Django state (one head per app) fits, and a stray stderr line such as Compose's `Removed` can't become the revision (ssh.py:188-190 merges the streams). |
| D7 | Whether data exists: an optional `commands.has_data` (0 data here, 3 empty, 4 the data lives outside this host) decides. Without it, Slipway probes the declared volumes. Exit 4 keeps backups but refuses Restore, Roll back, Reset and seeding in phase 2. | ServerSherpa already runs with `STACK_EXTERNAL_DATA=1` or a LAN data VM set as instance variables (ss-stack:21, 69; `check_instance_env` allows them, manifest.py:554-562), and then has no db volume. A volume-only probe would skip the backup and let Reset run `DROP SCHEMA` on a shared database. |
| D8 | **Identity secrets.** Each backup and snapshot carries the identity values its data was made with. Slipway tracks those values in `instances.live_identity` (EncryptedJSON), set at `finish` and in the `restore` step. Restoring brings the keys back. Doing that (a non-empty override) needs `data:reset`. | It avoids Sirdar's clock comparison and its "blocked after a key change" state. Reading from `live_identity` rather than the current settings stops an edited but undeployed variable from being recorded as the data's key (data-loss 4). Requiring `data:reset` stops a developer from quietly reviving keys that were rotated after a leak (security 6). |
| D9 | **Data dirty state.** `instances.data_dirty` records the first job since the last success that began changing data and then failed, together with its pre-change backup. `hold: true` marks a restore-type failure in which the database may be empty. Roll back restores that first backup. | It handles two failed deploys in a row (correctness 4), keeps the true rollback point pinned, labels backups of half-changed data (data-loss 6, 12) and fences off partial restores. |
| D10 | "Latest job" means the latest **data-changing** job (deploy, restore, rollback, reset, admin, content). Backup jobs and snapshot jobs never move it. | Otherwise a "Back up now" after a failed deploy would unpin the rollback point, disable Roll back and make a retry back up half-migrated data (correctness 3, data-loss 5). |
| D11 | **Retry** keeps the first pre-change backup only when the parent began a change step. It skips change steps the parent finished (`done_by`). It takes an extra `pre_retry` backup when the app was started by hand since. | This keeps I1 in both directions (data-loss 7): no stale backup is reused for unchanged data, and no new "pre-change" copy is taken of half-changed data. |
| D12 | `first_admin` and `seed` run **after `finish`**. Their failure is a step `warning` and the job still succeeds. "Create it now" and "Add starter content" redo them. | Before `finish`, a failure leaves a running app that Slipway treats as never deployed, with no proxy and no live release for "Create it now" (correctness 9). |
| D13 | **Host lock** `<base>/.slipway-lock` holds the job id, the host's boot id, the PID of the command and its key. Liveness is decided by the PID (`/proc/<pid>` or `kill -0`, `ps -p` only on a host without `/proc`, and alive when none of them can tell) plus the boot id, never by a deadline. The lock is kept when a command didn't return an exit status. | `proc.kill()` without a pty doesn't reliably stop the remote process (ssh.py:202-209), and shutdown cancels tasks (2319-2323). A deadline would either let a retry overlap a running `pg_restore` or block plain deploys for an hour after a crash (correctness 6, data-loss 1 and 14). |
| D14 | No cancel in phase 2. | `kill()` is unreliable over SSH. Every command has a timeout, the host lock fences what may still be running, and Retry recovers. |
| D15 | Stored snapshots are always one `.sbx` file under a per-snapshot data key (DEK) held in `snapshots.data_key` (EncryptedText), with key block `kdf:none`. A download writes a new scrypt key block in front of the unchanged body. An imported file's passphrase key block is held in the row only until it is unlocked. | Whole databases at rest are ciphertext under a random key, never under a human passphrase (security 3). `rotate-encryption-key` re-wraps the DEK (crypto.py:104-108). A 20 GB export costs one key derivation plus a copy. |
| D16 | Snapshot seeding is bound to the **repository**. A snapshot whose repository isn't the instance's, or is unknown, needs `snapshots:download` to seed or reset from. | `data.app` is whatever the target slipway.yml claims, so it guards against mistakes, not against attackers (security 1). |
| D17 | Data-only jobs stop and start the app with `control_command` (`docker compose stop`/`start`, deployer.py:533-572), never with the manifest's `stop`/`start`. | `ss-stack down` removes containers, after which Start reports success with nothing running. `ss-stack up` migrates (correctness 5). |
| D18 | Destroy moves `backups/` to `.slipway-kept` only after teardown and the leftovers check pass, with a `<name>.json` sidecar (metadata) and a `<name>.identity.env` (0600) next to each dump. | The current code keeps `.env` before teardown and puts it back on failure (730-746). Moving backups that early would strand them (correctness 10, data-loss 2). Without rows, kept dumps need their metadata and keys next to them (generality 8, data-loss 16). |

Two claims in the plan doc are wrong and are corrected in docs/sirdar-integration.md (slice 7). Sirdar doesn't "dump before every change" (docs/sirdar-integration.md:25, 132-135): it dumps only before Update. Its first_admin sketch (:83-86) passes `bootstrap-admin` twice and lacks the name fields.

---

## 1. Invariants

- **I1. A verified copy comes first.** Nothing that replaces or deletes app data runs until a copy of the data is on the host and has been checked: exit 0; a regular, non-symlink, non-empty file; size recorded; SHA-256 recorded when the host has a tool; `verify_dump` passed when declared. Data-replacing steps are `start` on a deploy (it migrates), and `reset`, `restore`, `files`, `after_import` on a data job. The only exceptions are explicit, audited and typed: `skip_backup`, and a safety dump while a hold stands (§8.4).
- **I2. A chain's first pre-change backup is never replaced or pruned** while it can still be retried, rolled back to or undone, and the rollback point of a dirty instance is pinned until the instance is clean again.
- **I3. Data and its identity keys travel together.** Backups and snapshots store the identity values their data was made with. `.env`, `app_secrets` and `live_identity` change together in the `restore` step and nowhere else.
- **I4. Refuse before changing.** Typed name, checksums, format, revision, repository and app id, identity rules, free space, "the host already has data", the host lock and image freshness are all checked in steps that come before the first change.
- **I5. Nothing is deleted by pattern.** Slipway deletes only file names it recorded (re-checked against `NAME_RE`) and volume names it rendered. A volume is deleted only when its `com.docker.compose.project` label is one of the app's own projects. Host files are removed only after the same SSH session has just confirmed them.
- **I6. Partial states are fenced off** by `data_dirty` and its hold (§8.4).
- **I7. Nothing changes for others.** Dockerfile and compose instances keep their exact step lists (`step_keys`, deployer.py:1217-1220) and get no lock file. An app whose slipway.yml declares no data gets exactly one extra step, `backup`, skipped with "slipway.yml declares no data", and a lock file that never blocks it.

---

## 2. Manifest additions (`slipway/services/manifest.py`)

### 2.1 Grammar of the new keys

```yaml
secrets:
  KEY: {kind: hex|fernet|token, bytes: 32, identity: true}   # identity: default false

data:                               # optional; needed by every data feature
  app: <id>                         # required with commands.dump. ^[a-z0-9][a-z0-9._-]{0,63}$
                                    # Never change it: snapshots seed only an app with the same id.
  format: <label>                   # required with commands.dump. ^[a-z0-9][a-z0-9._+-]{0,39}$
                                    # What dump writes and restore reads; Slipway compares labels only.
  volumes:                          # 0-20 entries; needed by reset, and by dump unless has_data is declared
    - {name: <template>, holds: database|files|other}
  files:                            # present iff commands.export_files is declared
    format: <label>                 # same regex as data.format
    label: <text>                   # <= 40 chars, default "Files"
  identity_label: <text>            # <= 60 chars, default "identity keys"
  identity_help: <text>             # <= 300 chars; what losing them means for this app (shown in dialogs)

commands:                           # COMMANDS (manifest.py:71) grows; only start stays required
  build | start | stop              # unchanged form: a list (argv)
  has_data:     [...]               # exit 0 data here, 3 empty, 4 the data lives outside this host
  data_up:      [...]               # start only what holds data; exit 0 once it accepts connections
  dump:         [..., "{slipway.out}", ...]   | {run: [...], stdout: true}
  verify_dump:  [..., "{slipway.in}", ...]    | {run: [...], stdin: true}
  revision:     [...]               # prints the revision on stdout (Slipway captures stdout to a file)
  accepts:      [..., "{slipway.in}", ...]    | {run: [...], stdin: true}
  restore:      [..., "{slipway.in}", ...]    | {run: [...], stdin: true}
  export_files: [..., "{slipway.out}", ...]   | {run: [...], stdout: true}
  import_files: [..., "{slipway.in}", ...]    | {run: [...], stdin: true}
  after_import: [...]               # after another instance's data is in, before start
  seed:         [...]               # starter content after an empty start

first_admin:                        # optional
  help: <text <= 300>
  command: [..., "{admin.<field>}", ...]
  fields:                           # 1-8; name ^[a-z][a-z0-9_]{0,30}$
    <field>: {label: <text <= 60>, kind: text|email, help: <text <= 200>, max: 1-254}  # max default 200, email 254
  password:                         # optional: offers "Set a password"
    min_length: 8                   # 8-128, default 8 (Slipway's floor is 8 whatever the app allows)
    stdin: true                     # the password as one line on the command's stdin
    # env: VAR                      # or: Slipway reads stdin into $VAR, then execs the command
    args: [--password-stdin]        # appended in password mode; <= 10 items, no slots
  invite:                           # optional: offers "Email them a link"
    label: <text <= 60>
    args: [--invite]                # appended in invite mode; <= 10 items, no slots
  done_codes: [0]                   # default [0]
  exists_codes: [10]                # default []: "that account already exists" counts as done
  messages: {<code>: <text <= 300>}

timeouts: {<command>|first_admin: <minutes 1-1440>}
```

**Default timeouts (minutes):** build 60, start 60 (today's 3600 s, deployer.py:1797-1805), stop 15, has_data 2, data_up 15, dump 120, verify_dump 30, revision 2, accepts 2, restore 240, export_files 240, import_files 240, after_import 30, seed 30, first_admin 10.

### 2.2 Slots and stream mode

| Slot | Allowed only in | Filled with |
|---|---|---|
| `{slipway.out}` | dump, export_files (list form): required, exactly once | `<base>/backups/.incoming/<name>.dump.partial` and the like |
| `{slipway.in}` | verify_dump, accepts, restore, import_files (list form): required, exactly once | a verified file Slipway names; for accepts, a 0600 file holding the revision |
| `{admin.<field>}` | first_admin.command; every declared field used at least once, every slot a declared field | validated operator input (§11.1) |

**Stream mode.** `{run: [argv], stdout: true}` (dump, export_files) or `{run: [argv], stdin: true}` (verify_dump, accepts, restore, import_files). The argv then holds no slot, and Slipway runs `exec ./prog args > <partial>` or `exec ./prog args < <file>`, so stderr still reaches the log. A mapping has exactly `run` plus one flag that fits the command.

**Checks in `parse`**, run before `check_template` (manifest.py:401-412) runs on the other arguments. All raise `ManifestError("slipway.yml: <where>: <message>")`:

1. An argument that contains a slot token but isn't exactly that token:
   `commands.dump[3]: {slipway.out} must be a whole argument; write --out and {slipway.out} as two arguments, or use stdout: true`.
2. A slot in a command that doesn't allow it, or anywhere else (vars, hostnames, projects, images, data.volumes, args lists):
   `commands.start[2]: {slipway.out} can only be used in commands.dump and commands.export_files`.
3. `argv[0]` is a slot: `commands.dump[0]: the program can't be a value filled at run time`.
4. A required slot missing, or used twice:
   `commands.dump: needs {slipway.out} exactly once (the file Slipway gives it to write), or write it as {run: [...], stdout: true}`.
5. A mapping with both a slot and a flag, the wrong flag, or other keys:
   `commands.restore: give either {slipway.in} or stdin: true, not both`.

**Rendering.**

- `plan()` (manifest.py:565-675) turns each argument that is exactly a slot into `{"slot": "out" | "in" | "admin.<f>"}`. The other arguments render as today.
- A command is stored as `{"argv": [...], "stream": "stdout" | "stdin" | null}`. `AppPlan.commands` becomes `dict[str, dict]`. The program check (manifest.py:666-671) looks only at `argv[0]`, which is never a slot.
- `app_command(release, cmd, *, slots=None, stream_path=None, lock=None, umask=False)` replaces each slot object with `slots[name]` (a missing value raises `DeployError("commands.dump: Slipway gave no value for {slipway.out}")`) and quotes every item with `q()`, as today (deployer.py:1886). With `lock`, it prefixes the lock write (§4.5) and runs the program with `exec`. With `stream_path`, it adds `> P` or `< P`. `umask=True` prefixes `umask 077 &&`. That is used for the data commands and first_admin only, so existing app commands keep running exactly as today (security 12).
- `teardown_command` (624-628) keeps using `app_state["commands"]["stop"]`. It is read through a helper that accepts both the old list form and the new dict form.

### 2.3 Validation rules

- **Top-level whitelist** (manifest.py:257-258) gains `data`, `first_admin` and `timeouts`.
- **Secrets.** The spec `_only` (manifest.py:303) gains `identity`, checked with `_bool`. `Secret` gains `identity: bool = False`. At most 16 per manifest: `secrets: at most 16 can be identity secrets`. Add `Manifest.identity_keys()`.
- **Dump** needs `data.app` and `data.format`, and either `has_data` or at least one volume with `holds: database` or `files`:
  `commands.dump needs commands.has_data, or a data.volumes entry that holds: database or files, so Slipway can tell an instance with data from a new one`.
- **Restore** needs `dump` (`Slipway restores only what it backed up`), `data_up` (`Slipway stops the app and starts only the data services before a restore`) and `stop` (`commands.restore needs commands.stop: Slipway stops the app before replacing its data`).
- **Other dependencies.** `verify_dump`, `revision` and `has_data` need `dump`. `accepts` needs `revision`. `after_import` needs `restore`. `seed` needs `dump` (Slipway must be able to tell an empty start).
- **Files.** `export_files` and `import_files` come together, and `data.files` is present if and only if they are:
  `commands.export_files and commands.import_files come together, with data.files: a snapshot taken here must be restorable here`.
- **`data.volumes`.**
  - Each entry is a mapping with exactly `name` and `holds`. `name` passes `check_template`, and `holds` is one of `database`, `files` or `other`.
  - Rendered in `plan()`, each name must match `^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$` and be unique. There is **no** project-prefix rule: Compose volumes with an explicit `name:` keep their project label. The label is the real check, made at reset (§7.5).
  - `AppPlan.volumes = [{"name", "holds"}]`.
- **`first_admin`.**
  - `command` is required, with the usual argv rules (at most 50 items, one line each).
  - 1-8 `fields`.
  - At least one of `password` and `invite`.
  - `password` needs exactly one of `stdin: true` and `env: VAR`. `VAR` matches `^[A-Z][A-Z0-9_]{0,63}$`, isn't a secret, setting or var key, and isn't one of `PATH HOME SHELL IFS ENV BASH_ENV CDPATH PS4 USER LOGNAME`, nor starts with `LD_` or `DYLD_`:
    `first_admin.password.env: PATH can't carry the password (the shell or loader reads it)`.
  - `min_length` is 8-128.
  - Codes are ints 0-255. `done_codes` and `exists_codes` don't overlap, with at most 20 in total. `messages` keys are ints 1-255 that are not done or exists codes.
- **`timeouts`.** Keys are declared commands or `first_admin`; values are ints 1-1440.

### 2.4 `to_json`, capabilities, `app_state`

`to_json` (manifest.py:163-176) adds `secrets[].identity`, `data` (`app`, `format`, `volumes`, `files|null`, `identity_label`, `identity_help`), `first_admin` (the help, fields, `password: {min_length, mode}|null`, `invite: {label}|null`, codes and messages), `timeouts` and `capabilities`.

`Manifest.capabilities()` is a pure function:

| Capability | Requires |
|---|---|
| backup | dump |
| verify | verify_dump |
| restore | dump + restore (+ stop + data_up, from validation) |
| revision_check | revision + accepts |
| files | export_files |
| reset | restore + at least one `data.volumes` entry |
| snapshot | backup |
| seed | restore |
| first_admin | first_admin |
| starter_content | seed |

The live release's capabilities decide what the pages and endpoints offer.

`app_state` (built in settings, 1998-2001, saved at `finish`) gains:

- `"live"`: `{release: <folder name>, deployment: <hex>, sha, settings: {…app_settings used}, services: [...chosen], host_ports: {...}, projects: [...], volumes: [...], env_fp}`. `env_fp` is a salted SHA-256 of the instance variables used, for a warning only.
- `"commands"` keeps the stop argv for teardown.

Nothing else is stored: data jobs live-render (D3). `app_settings` are not secret (secrets are separate, manifest.py:613-631), so `live.settings` may be plain JSON.

### 2.5 A second app (Django, no object store, no wrapper scripts)

```yaml
projects: ["shop-{slipway.slug}"]
vars: {COMPOSE_PROJECT_NAME: "shop-{slipway.slug}"}
data:
  app: acme-shop
  format: pg-custom
  volumes: [{name: "shop-{slipway.slug}_pgdata", holds: database}]
  identity_label: field encryption key
  identity_help: Encrypted columns (customer addresses) can only be read with the key they were written with.
secrets:
  FIELD_ENCRYPTION_KEY: {kind: fernet, identity: true}
commands:
  start:    [docker, compose, -p, "shop-{slipway.slug}", --env-file, "{slipway.env_dir}/.env", up, -d, --build, --wait]
  stop:     [docker, compose, -p, "shop-{slipway.slug}", --env-file, "{slipway.env_dir}/.env", down]
  data_up:  [docker, compose, -p, "shop-{slipway.slug}", --env-file, "{slipway.env_dir}/.env", up, -d, --wait, db]
  dump:     {run: [docker, compose, -p, "shop-{slipway.slug}", exec, -T, db, pg_dump, -Fc, -U, shop, shop], stdout: true}
  verify_dump: {run: [docker, run, --rm, -i, --network, none, "postgres:16-alpine", pg_restore, --list], stdin: true}
  restore:  {run: [docker, compose, -p, "shop-{slipway.slug}", exec, -T, db, sh, -c,
                   "psql -U shop -d shop -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public' && pg_restore --exit-on-error --no-owner -U shop -d shop"],
             stdin: true}
  revision: [docker, compose, -p, "shop-{slipway.slug}", exec, -T, web, python, manage.py, showmigrations, --plan]
first_admin:
  command: [docker, compose, -p, "shop-{slipway.slug}", --env-file, "{slipway.env_dir}/.env", run, --rm, -T,
            -e, DJANGO_SUPERUSER_PASSWORD, web, python, manage.py, createsuperuser, --noinput,
            --username, "{admin.username}", --email, "{admin.email}"]
  fields: {username: {label: Username, max: 150}, email: {label: Email, kind: email}}
  password: {min_length: 10, env: DJANGO_SUPERUSER_PASSWORD}
  messages: {1: "Django refused the user (is the username taken?); the log shows why."}
```

This app gets Backups, Restore, Reset, database-only snapshots and seeding. The revision is the whole migration plan (an opaque text that is shown in short). It has no `accepts`, so its dialogs say "Slipway can't check this backup's revision against the release". A test parses this example **and** plans it (§18.2).

---

## 3. Command contracts and the ServerSherpa side

### 3.1 What Slipway guarantees around each command

Every command runs on the host as `cd <release> && [umask 077 &&] <lock write> && exec ./<program> args… [> P | < P]`, with no environment passed (deployer.py:1882-1887). The app reads `{slipway.env_dir}/.env`, which Slipway has just written by live render or by `settings`. Output is streamed into the job log after redaction (§12.2).

| Command | Guaranteed beforehand | Expected |
|---|---|---|
| has_data | `.env` written | exit 0: the data is on this host; 3: no data yet; 4: the data lives outside this host (external or shared database). Anything else fails the step. |
| data_up | `.env` written | starts only the data services; idempotent; exit 0 once they accept connections |
| dump | data_up ran; `backups/.incoming` exists (0700); the output path doesn't exist | writes one complete file (to `{slipway.out}`, or to stdout in stream mode); exit 0 only when it is complete |
| verify_dump | the file is complete | reads it without changing anything; exit 0 when it is a usable dump |
| revision | data services up | prints the schema revision on stdout (≤16 KiB, trimmed). An empty output or a non-zero exit means "unknown". stderr goes to the log. |
| accepts | runs in the *target* release; no database needed | reads the revision from `{slipway.in}` or stdin. Exit 0: this release can run data at that revision (it may migrate it forward). Exit 3: it can't, and its last line says why. Anything else: the check itself failed. |
| restore | the app is stopped (Slipway ran `stop`); data_up ran; the input is a verified regular file | replaces the whole database; never starts the app |
| export_files / import_files | as for dump / restore | writes, or puts back, one opaque files archive; import may keep files that aren't in it |
| after_import | after another instance's data (a snapshot) is in, before start | adjusts imported data (forgets sessions, rewrites URLs); idempotent |
| seed | after start and finish, only after an empty start | adds starter content; idempotent |
| first_admin.command | after finish | done codes mean created; exists codes mean it was already there. The password arrives on stdin, or in `$VAR` via a stdin read, never in argv. |

**Compatibility.** Before replacing data, Slipway checks that (1) the `data.format` labels are equal, and (2) when the target release has `revision_check` and the source has a revision, `accepts` exits 0. A normal deploy runs the new release's `accepts` on the live revision too (§7.5 backup). Changing a dump format incompatibly means changing `data.format`; older backups then show "not restorable by this release" instead of failing half-way.

### 3.2 ServerSherpa `slipway.yml` (BaseCampV3 PR #2, branch `slipway-manifest`; also `docs/examples/serversherpa.slipway.yml`)

Only the changed and new keys are shown; phase 1 keys stay as they are.

```yaml
secrets:
  POSTGRES_PASSWORD: hex
  SPACES_SECRET_KEY: hex
  SS_JWT_SECRET: hex
  SS_TOTP_ENCRYPTION_KEY: {kind: fernet, identity: true}   # 2FA seeds in the database are encrypted with it
  SS_PASSWORD_PEPPER:     {kind: hex, identity: true}      # password hashes are peppered with it
  SS_WIKI_SERVICE_TOKEN: hex

data:
  app: serversherpa
  format: pg-custom                       # pg_dump -Fc --no-owner --no-acl (ss-stack pgdump)
  volumes:
    - {name: "ss-{STACK_ENV}-db_pgdata",           holds: database}
    - {name: "ss-{STACK_ENV}-storage_seaweeddata", holds: files}
    - {name: "ss-{STACK_ENV}-status_status-data",  holds: other}
  files: {format: serversherpa-objects-v1, label: Uploaded files}
  identity_label: sign-in keys
  identity_help: People sign in with the passwords and 2FA codes they had when the data was made.

commands:
  build:        [deploy/stack/ss-stack, build, "{slipway.env_dir}"]
  start:        [deploy/stack/ss-stack, up, "{slipway.env_dir}"]
  stop:         [deploy/stack/ss-stack, down, "{slipway.env_dir}"]
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

first_admin:
  help: The first deploy creates this person as ServerSherpa's first super admin. The password is never emailed.
  command: [deploy/stack/ss-stack, admin, "{slipway.env_dir}", --email, "{admin.email}",
            --first-name, "{admin.first_name}", --last-name, "{admin.last_name}",
            --role, super_admin, --link-minutes, "240"]
  fields:
    first_name: {label: First name, max: 100}
    last_name:  {label: Last name, max: 100}
    email:      {label: Email, kind: email}
  password: {min_length: 8, stdin: true, args: [--password-stdin]}
  invite:   {label: Email them a link to set their password, args: [--invite]}
  done_codes: [0]
  exists_codes: [10]
  messages:
    2: ServerSherpa refused the request (usage error); see the log.
    3: The password is shorter than ServerSherpa's password policy allows.
    4: ServerSherpa has no global role super_admin.
    5: ServerSherpa can't send email, so it can't send an invite. Set a password instead, or configure SS_SMTP_HOST (or turn on mailpit).
    6: ServerSherpa failed while creating the account; see the api container's logs.
    7: A person with that email exists in ServerSherpa without an account; give them one in the portal, or use another email.
    8: ServerSherpa refused the email address (it refuses .local and .test domains).

timeouts: {restore: 120, export_files: 120, import_files: 120}
```

Notes:

- **`ss-stack admin`** already prepends `serversherpa bootstrap-admin` (ss-stack@main:486-491), so the word isn't repeated.
- **`pgdump`, not `dump`.** `dump` does its own naming and `STACK_KEEP_DUMPS` retention, which decision 3 gives to Slipway. `pgdump` writes `$out.partial` and renames it (ss-stack:454-466).
- **Restore.** `ss-stack restore` stops the writers itself and empties the schema (ss-stack:380-416). Restoring the instance's own backup keeps sessions. A snapshot's `after_import` clears them.
- **Reset** deletes all three volumes, as Sirdar's `down --volumes` did. The dialog names `status-data` as "deleted, and in no backup".
- **External data.** With `STACK_EXTERNAL_DATA=1` or `STACK_DB_HOST` set, `has-data` exits 4. Backups still work (pgdump supports external mode), and Restore, Reset and seeding are refused in phase 2 (§17).

### 3.3 ss-stack additions (small and generic, decision 8)

Each follows ss-stack's own patterns: `umask 077`, `.partial` plus traps, `die` (exit 1) and `usage` (exit 2).

1. **`has-data <env-dir>`.**
   - `external` or `lan_db` → exit 4.
   - Otherwise, when the `ss-$STACK_ENV-db_pgdata` volume is missing → exit 3.
   - Otherwise, with the db stack up, `SELECT to_regclass('public.alembic_version') IS NOT NULL` true → exit 0. An empty volume → exit 3.
2. **`accepts <env-dir> <file>`.**
   - Read `rev=$(head -c 200 "$file")`.
   - `[[ $rev =~ ^[0-9]{1,8}$ ]]` fails → print `<rev> isn't a ServerSherpa migration number`, exit 3.
   - `compgen -G "$STACK_DIR/../../api/migrations/versions/${rev}_*.py"` finds a file → exit 0.
   - Otherwise print `This commit has no migration <rev>: the data is newer than this commit, or from another branch; deploy a commit that has it` and exit 3.
   - This is a membership test, not Sirdar's `<=` (restore.yml:21-44), so a dump from another branch is refused too.
3. **`verify-dump <env-dir> <file>`.** `docker run --rm -i --network none postgres:16-alpine pg_restore --list < "$file" >/dev/null || die "not a complete pg_dump archive"`.
4. **`clear-sessions <env-dir>`.** `psql_run "$CLEAR_SESSIONS"` (ss-stack:306-307), split out of `restore --clear-sessions`.
5. **`export-objects <env-dir> <out>` and `import-objects <env-dir> <in>`.**
   - They run `docker run --rm --network "ss-$STACK_ENV" --env-file "$env_dir/.env" --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$STACK_DIR/objects.py:/objects.py:ro" -v "$(dirname "$f"):/work" "serversherpa-api:$(env_value STACK_IMAGE_TAG)" python /objects.py export|import "/work/$(basename "$f")"`.
   - `--user` is the SSH user, so the 0700 folder is readable.
   - `deploy/stack/objects.py` is Sirdar's `export_objects`/`import_objects` (bundle.py:443-521), moved into BaseCampV3. The PAX key becomes `SLIPWAY.content_type`, and import also reads `SIRDAR.content_type`. Import streams each member to `put_object` and never writes members to disk.
6. **`seed <env-dir>`** adds `--learning` itself when `learn` is in STACK_APPS.
7. **`scripts/make-seed-snapshot.sh`** calls `slipway snapshot pack --repository encondata/BaseCampV3 --passphrase-stdin …` (§10.9) instead of `bundle.py pack`.

---

## 4. Host layout and file protocol

### 4.1 Instance folder (`InstancePaths`, deployer.py:208-259)

```
<base>/
  .slipway-instance
  .slipway-lock                          NEW (app instances): "<dep uuid> <boot id> <pid> <key> <d|->"
  current -> releases/<sha12>-<dep8>
  releases/...
  shared/.env                            written by live render or settings (0600)
  backups/                               NEW (0700)
    20261115T101500Z-1a2b3c4d.dump       (0600) database dump
    20261115T101500Z-1a2b3c4d.files      (0600) files archive (only for backups "with files")
    20261115T101500Z-1a2b3c4d.json       (0600) sidecar: metadata, never secret values
    .incoming/                           (0700) work area, emptied by every job's first host step
      20261115T101500Z-1a2b3c4d.dump.partial
      job-<dep8>/{database,files,revision,revision.out}
```

- `InstancePaths` gains `backups`, `incoming` and `lock`.
- `SLIPWAY_ENTRIES` (deployer.py:280) becomes `("releases", "shared", "current", "backups", ".slipway-lock", MARKER_FILE)`.
- **Names.** `NAME_RE = ^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$` and `FILE_RE = ^<name>\.(dump|files|json)$`. The time comes from Slipway's UTC clock and the suffix is `Backup.id.hex[:8]`. The API never takes a file name: it takes a `Backup.id` filtered by `instance_id` (security 11), re-checks `row.name` against `NAME_RE`, and builds the path from `paths.backups`.
- **Sidecar `<name>.json`:** `{"format": "slipway-backup", "version": 1, app, data_format, files_format, revision_short, commit, release, taken_at, reason, db_sha256, db_bytes, files_sha256, files_bytes, identity_keys, identity_fp, producer}`.
- **Portable shell only.** No `find -printf`.
  - SHA-256: `{ sha256sum -- F 2>/dev/null || shasum -a 256 -- F 2>/dev/null || openssl dgst -sha256 -r F; } | sed -n '1s/^\([0-9a-f]\{64\}\).*/slipway-sha: \1/p'`
  - Free space: `df -Pk -- D | awk 'NR==2 {print "slipway-df: " $4}'`
  - File check: `if [ -f "$f" ] && [ ! -L "$f" ]; then echo "slipway-bk: ok $f $(wc -c < "$f" | tr -d ' ')"; else echo "slipway-bk: gone $f"; fi`
  - **Volume probe** (data-loss 8). Only "not listed by a working `docker volume ls`" counts as absent:
    `vols=$(docker volume ls -q) || { echo 'slipway-probe: no-docker'; exit 1; }; for v in V…; do if printf '%s\n' "$vols" | grep -Fxq -- "$v"; then echo "slipway-probe: present $v $(docker volume inspect -f '{{index .Labels "com.docker.compose.project"}}' -- "$v")"; else echo "slipway-probe: absent $v"; fi; done`
  - **Volume sizes** for the first estimate: `docker system df -v --format '{{range .Volumes}}{{.Name}} {{.Size}}{{"\n"}}{{end}}' 2>/dev/null`. When that fails, the log says so and the estimate falls back (§4.2).

### 4.2 Writing a backup (inside the `backup` step)

1. **Free space.**
   - Estimate = 1.25 × (`db_bytes` + `files_bytes` when this backup includes files) of the instance's last ready backup.
   - With no earlier backup (or the first one with files), use the sizes of the declared volumes it covers, from `docker system df -v`. If that fails, use 256 MiB and log it.
   - Need = estimate + `SLIPWAY_BACKUP_FREE_MARGIN_MB` (default 1024).
   - Less free fails with: `Only 812 MiB is free in <base>/backups on <host>; the backup needs about 1.9 GiB. Free some space (old backups are on the Backups card) and retry. Nothing was changed.`
2. Run `umask 077 && mkdir -p B/.incoming && chmod 700 B B/.incoming`.
3. Run `dump` with `out=B/.incoming/<name>.dump.partial` (or as `> P` in stream mode), with `umask=True`.
4. Run `[ -f P ] && [ ! -L P ] && [ -s P ] && chmod 600 P`, then measure the size and the sha. An empty file fails with: `commands.dump exited 0 but wrote nothing to <path>`.
5. Run `verify_dump` on `P` when declared. Otherwise log `slipway.yml has no verify_dump: checked only that the dump isn't empty`.
6. With files: run `export_files` to `<name>.files.partial`, then check and hash it the same way.
7. Run `mv -f -- P B/<name>.dump` (and the same for `.files`), then write the sidecar `B/<name>.json` with `write_text` (0600). This is atomic: same folder.
8. On any failure: `rm -f -- B/.incoming/<name>.*`. The row is deleted and the step fails.

If the host has no hash tool, `sha256` is NULL and the log says once: `<host> has none of sha256sum, shasum or openssl: Slipway checks this backup by size only`. On a RAM-backed Unraid folder (`ram_backed`, deployer.py:157-159), the step logs: `Warning: <base> is in RAM on <host> (Unraid): backups there are lost when it restarts; move the instance's folder under /mnt/user`. The Backups card shows the same warning.

### 4.3 Retention

`N = instance.keep_backups` (default 5, 1-100). Retention runs right after a backup becomes ready, in the same SSH session.

- **Pinned** (never pruned):
  - `backup_id` and `restore_backup_id` of the instance's latest *data-changing* job (D10) and of every active job;
  - `data_dirty.first.backup_id` and `data_dirty.last.backup_id`;
  - the backup just taken.
- **Clean candidates:** `reason != manual`, `dirty_of IS NULL`, status `ready`. The newest N that aren't pinned are kept.
- **Dirty candidates** (taken while `data_dirty` was set, so the data was half-changed): `reason != manual`, status `ready`. The newest 2 that aren't pinned are kept. They never push out clean backups.
- **Manual backups** are deleted by hand only, at most `SLIPWAY_MANUAL_BACKUPS_MAX` (default 10) per instance. "Back up now" beyond that answers 409: `<name> already has 10 backups you took yourself; delete one first` (security 8).
- **Deleting.** Before any `rm`, the same session re-runs the file check (§4.4) for the doomed names. Only files confirmed `ok` with the recorded size are removed (`rm -f -- B/<name>.dump B/<name>.files B/<name>.json`), and then their rows. Rows in `missing` or `changed` are never pruned automatically: the card offers **Forget** for them. A failure logs `Warning: couldn't remove old backups: <line>` and never fails the job.

### 4.4 Checking backups on the host

One command checks up to 100 names: `cd B 2>/dev/null || { echo 'slipway-bk: nodir'; exit 0; }` followed by the file-check loop.

- It checks only rows in `ready`, `missing`, `changed` or `unverified`. Rows are updated conditionally (`WHERE id=? AND status=<read>`).
- `nodir` and SSH errors change **no** row; the answer carries a `warning`.
- Present, same size (and the same sha when it is re-hashed) → `ready`, so a file that reappears is restorable again. Absent → `missing`. Size differs → `changed`. `checked_at` is set.
- `GET …/backups?check=true` runs it inside `runner.exclusive` without waiting. When the runner is busy, it returns the stored rows with `warning: "A job is running for <name>; showing what Slipway recorded"` (security 7).
- The `check` step of restore kinds also re-hashes when a sha is recorded (600 s timeout).
- **`unverified`** rows (a restart between `mv` and the database update, data-loss 17) are settled by the next job's `release` step. A present final file means it is complete (the `mv` comes after verification): measure it, hash it, mark it `ready`. No file: delete the row.

### 4.5 Host lock (app instances)

**Format.** One line: `<deployment uuid> <boot id> <pid> <key> <d|->`.

- `boot id` is `cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo -`.
- `key` is the command or step key.
- `d` marks a data command: dump, export_files, restore, import_files, after_import, seed, first_admin, the reset volume removal, and `start` when the manifest declares `dump`.

**Acquiring** (the first host step of every app job, right after `_take_dir`, deployer.py:1694 and 1702):

1. Read `L`. When it exists and names another deployment, print `slipway-lock: held <line> alive=<0|1>`. `alive` is 1 when the boot ids are equal (or either is `-`) and the PID still runs: `/proc/<pid>` exists or `kill -0 <pid>` succeeds; on a host without `/proc`, `ps -p <pid>` decides, and when `ps -p` doesn't work there either the holder counts as alive.
2. Slipway decides:
   - not alive → take it over and log `Took over the lock of job <id8> (its <key> has ended)`;
   - alive with `-` → take it over and log `Warning: job <id8>'s <key> (pid <pid>) may still be running on <host>`;
   - alive with `d` → fail before anything runs, unless `take_over_lock` (needs `data:reset` and the typed name):
     `Job <id8>'s <key> (pid <pid>) is still running on <host>; Slipway lost track of it when it restarted or the command timed out. Wait for it to end and retry, or stop it (kill <pid>) and retry.`
3. Write the job's own line.

**While running.** Each command rewrites the line from inside the command itself: `printf '%s %s %s %s %s\n' ID "$BOOT" "$$" KEY F > L && exec ./prog …`. After `exec`, `$$` is the program's PID. Slipway's own shell snippets do the same with their shell's PID.

**Releasing** (data-loss 1). The lock is removed in `finally` only if the last command returned an exit status. After a timeout, a cancellation or an SSH error, it is left in place and the log says `<key> (pid <pid>) may still be running on <host>; the next job waits until it has ended`.

Plain apps (no data) never write `d`, so they are never blocked (I7, correctness 6b).

### 4.6 Destroy and folder moves

**Destroy** order (deployer.py:708-761, reordered):

1. Teardown.
2. Leftovers check. If containers are left, raise as today; nothing has been moved yet.
3. `keep_env_command`. Its condition becomes "volumes exist **or** `backups/` holds a `*.dump`". It copies `.env` as today, then:
   - writes `<name>.identity.env` (0600, `KEY=value` lines from `Backup.identity`) for each ready backup with identity values, into `backups/`, via `write_text` (data-loss 16);
   - runs `rm -rf -- backups/.incoming; [ -n "$(ls -A backups 2>/dev/null)" ] && mv -- backups <root>/.slipway-kept/<slug>-<id8>.backups`, adding `-<UTC stamp>` when that name exists;
   - prints `slipway-env-kept` and `slipway-backups-kept <n>`.
4. `remove_dir_command`. `_remove_base_command` (874-888) adds `rmdir -- backups 2>/dev/null; rm -f -- .slipway-lock`.

A failed move keeps the whole folder (the existing `keep_folder` path, 731-746) with:
`Kept <base> on <host>: its backups could not be moved to <root>/.slipway-kept (<detail>)`.

The note becomes `Kept the app's volumes on <host>, and its settings, secrets and 3 backups (with their sign-in keys) in <root>/.slipway-kept/ (readable only by <user>)`. The audit record `instance.delete` lists the kept names and SHA-256s. Backup rows cascade away; snapshots keep `source_instance_id = NULL`. `projects_on_host_command` (2074-2091) also lists `<slug>-[0-9a-f]*\.backups` as `k`, so the "volumes already exist" error names them.

**Folder and root moves** copy `backups/` (`cp -a`, 823-843). Rows hold names, not paths, and data jobs live-render with today's paths (D3). `move_prepare_command` (805-820) adds `du -sk <old base>` against `df -Pk <new root>`, which prints `slipway-move: nospace <need> <free>`, with the message:
`<new root> on <host> has <free> free; moving <instance> needs <need> (its backups included). Free some space or delete old backups first.`

A host can't change once an instance has been deployed (instances.py:255-262), so backups never end up on another host.

---

## 5. Slipway server storage

- **Settings** (core/config.py:24-74):
  - `storage_dir: str = "data/files"`. Not `data_dir`: docker-compose.yml:18-20 already uses `SLIPWAY_DATA_DIR` as the host path.
  - `snapshot_max_bytes` = 20 GiB (sum of the members; the upload cap; inflation limit).
  - `snapshot_total_bytes` = 100 GiB (quota over all stored `.sbx`).
  - `snapshot_transfers` = 2 (1-8).
  - `snapshot_kdf_slots` = 2 (1-4).
  - `snapshot_locked_days` = 7.
  - `backup_free_margin_mb` = 1024.
  - `manual_backups_max` = 10.
- **Dockerfile:** before `USER slipway` (Dockerfile:11,23), `ENV SLIPWAY_STORAGE_DIR=/var/lib/slipway` and `RUN mkdir -p /var/lib/slipway && chown 10001:10001 /var/lib/slipway && chmod 700 /var/lib/slipway`.
- **docker-compose.yml:** the `slipway` service gains `volumes: ["${SLIPWAY_DATA_DIR:-./data}/files:/var/lib/slipway"]`.
- **install.sh:** `mkdir -p data/files && chown 10001:10001 data/files && chmod 700 data/files`.
- **README:**
  - back up `data/files` together with `data/postgres` **and** keep `SLIPWAY_ENCRYPTION_KEY`: without the key, stored snapshots can't be opened;
  - a reverse proxy must accept request bodies up to the cap.
- **Layout:**

  ```
  <storage>/                 0700
    bundles/<snapshot id>.sbx     0600  every stored snapshot (key block kdf:none)
    incoming/<uuid>.partial       0600  uploads and takes in flight (ciphertext only)
  ```

  Files are opened with `O_CREAT|O_EXCL|O_NOFOLLOW`. Plaintext never touches this disk.
- **Startup** (main.py lifespan, after `recover_interrupted`, main.py:91): `snapshots.prepare_storage()` creates and checks the folders, removes `incoming/*`, and re-queues validation of `checking` rows. A background `snapshots.sweep_forever()` (hourly, cancelled with the poller) deletes `locked` rows past `expires_at`, together with their files. If the folder isn't writable, the snapshot endpoints and the Snapshots page answer 503 `SLIPWAY_STORAGE_DIR (/var/lib/slipway) isn't writable by Slipway (uid 10001): on the server, run chown 10001 <folder> && chmod 700 <folder>`. Deploys are unaffected.
- **Space** (security 8). Before accepting any upload, and before a take's `store`:
  - `disk_usage.free ≥ expected + 2 GiB`, re-checked every GiB while streaming;
  - stored total + expected ≤ `snapshot_total_bytes`.
  - Failures: 507 `Slipway's storage has <free> free; this snapshot needs about <need>`, or 409 `Snapshots on this Slipway already use <used> of <quota> (SLIPWAY_SNAPSHOT_TOTAL_BYTES); delete some first`.

---

## 6. Data model and migration 0008

New models live in `slipway/models/data.py` (Backup, Snapshot, FirstAdmin) and are imported in `slipway/models/__init__.py`.

### 6.1 `backups`

| column | type | notes |
|---|---|---|
| id, created_at, updated_at | UUIDPrimaryKey, Timestamps (db/base.py:51-69) | |
| instance_id | Uuid FK instances.id ON DELETE CASCADE, index | |
| deployment_id | Uuid FK deployments.id ON DELETE SET NULL, `use_alter` | the job that took it |
| name | String(32) NOT NULL | `NAME_RE` |
| reason | String(16) NOT NULL | `pre_deploy`, `pre_retry`, `pre_restore`, `pre_reset`, `pre_rollback` or `manual` |
| status | String(16) NOT NULL default `pending` | `pending`, `unverified`, `ready`, `missing` or `changed` |
| format | String(40) NOT NULL | `data.format` of the release whose dump ran |
| db_bytes, db_sha256 | BigInteger NULL, String(64) NULL | |
| has_files, files_format, files_bytes, files_sha256 | Boolean default false, String(40), BigInteger, String(64) | |
| revision | Text NULL | ≤16 KiB |
| commit_sha | String(40) NULL | `instance.current_commit_sha` when taken |
| release | String(64) NULL | folder of the release whose dump ran |
| dirty_of | Uuid NULL (FK deployments SET NULL, `use_alter`) | `data_dirty.first.deployment_id` when taken while dirty |
| identity_keys | JSON NOT NULL default `[]` | |
| identity | EncryptedJSON NULL | values in effect (from `live_identity`) |
| identity_fp | String(64) NOT NULL | §9.1 |
| note | String(300) NULL | |
| created_by_id | Uuid FK users SET NULL | |
| taken_at | DateTime NOT NULL | |
| finished_at, checked_at | DateTime NULL | |

Constraints: `UniqueConstraint(instance_id, name)`, `Index(instance_id, taken_at)`, `CHECK (status <> 'ready' OR db_bytes IS NOT NULL)` and `CHECK (NOT has_files OR status <> 'ready' OR files_bytes IS NOT NULL)`.

### 6.2 `snapshots`

| column | type | notes |
|---|---|---|
| id, timestamps | | |
| name | String(64) UNIQUE NOT NULL | `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` |
| notes | Text NOT NULL default '' | ≤2000 |
| status | String(16) NOT NULL | `pending`, `locked`, `checking`, `ready` or `failed` |
| origin | String(16) NOT NULL | `instance`, `upload` (plain) or `import` (encrypted) |
| app, app_name, repository, source | String(64), String(100), String(200), String(100), all NULL | `repository` is `owner/name` |
| source_instance_id | Uuid FK instances SET NULL | |
| commit_sha | String(40) NULL | |
| source_created_at | DateTime NULL | |
| db_format | String(40) NULL | |
| db_revision | Text NULL | |
| db_bytes, db_sha256 | BigInteger NULL, String(64) NULL | |
| files_format, files_bytes, files_sha256 | NULL when there are no files | |
| identity_keys | JSON NOT NULL default `[]` | names only |
| data_key | EncryptedText NULL | base64 of the 32-byte DEK |
| import_keyblock | JSON NULL | the passphrase key block of a `locked` import; removed on unlock |
| expires_at | DateTime NULL | for `locked` rows |
| file_bytes, file_sha256 | BigInteger NULL, String(64) NULL | the stored `.sbx` |
| deployment_id | Uuid FK deployments SET NULL, `use_alter` | |
| created_by_id | Uuid FK users SET NULL | |
| error | String(500) NULL | |

`CHECK (status <> 'ready' OR (file_sha256 IS NOT NULL AND db_sha256 IS NOT NULL AND app IS NOT NULL))`. `data_key` is deliberately left out of the CHECK, so `rotate-encryption-key --clear-unreadable` can clear it (security 13 / data-loss 13).

### 6.3 `first_admins`

| column | type |
|---|---|
| id, timestamps | |
| instance_id | Uuid FK instances CASCADE UNIQUE |
| fields | JSON NOT NULL (`{field: value}`, no secrets) |
| mode | String(8): `password` or `invite` |
| password | EncryptedText NULL |
| status | String(8): `pending` or `done` |
| existed | Boolean default false |
| done_at | DateTime NULL |
| deployment_id | Uuid FK deployments SET NULL |
| last_error | String(300) NULL |
| created_by_id | Uuid FK users SET NULL |

Constraints: `CHECK (mode = 'password' OR password IS NULL)` and `CHECK (status = 'pending' OR password IS NULL)`.

### 6.4 `deployments` additions (instance.py:135-155)

| column | type | notes |
|---|---|---|
| kind | String(16) NOT NULL server_default `deploy`, index | `deploy`, `restore`, `rollback`, `reset`, `backup`, `snapshot`, `admin` or `content` |
| previous_sha | String(40) NULL | `instance.current_commit_sha` at queue time (display) |
| backup_id | Uuid FK backups SET NULL | the chain's pre-change backup (taken or inherited) |
| restore_backup_id | Uuid FK backups SET NULL | what restore or rollback puts back |
| snapshot_id | Uuid FK snapshots SET NULL | restored or taken |
| options | JSON NOT NULL server_default `'{}'` | §7.1 |

`branch` stays NOT NULL; data jobs store `instance.branch` and copy the commit fields of the live release's deployment. A new partial unique index `ux_deployments_one_active` on `(instance_id)` WHERE `status IN ('queued','running')` (`postgresql_where` and `sqlite_where`).

### 6.5 `instances` additions (instance.py:46-132)

| column | type | notes |
|---|---|---|
| keep_backups | Integer NOT NULL server_default 5 | 1-100 |
| seed_snapshot_id | Uuid FK snapshots SET NULL | restored by the first deploy; cleared when that **job succeeds** |
| seed_content | Boolean NOT NULL server_default true | run `seed` on an empty first deploy |
| content_pending | Boolean NOT NULL server_default false | a `seed` step ended in warning |
| live_identity | EncryptedJSON NULL | identity values the data now carries (D8) |
| identity_changed_at | DateTime NULL | |
| identity_source | String(300) NULL | e.g. `snapshot uat-2026-11-15` |
| data_dirty | JSON NULL | §8.4 |
| fresh_data | String(8) NULL | `empty` or `snapshot`: data that only Slipway's own never-live attempts created (§7.5 backup) |
| last_control_at | DateTime NULL | the last control start or restart |

`instances.live_identity` joins `_REENTER_COLUMNS` (cli.py:177). A cleared value becomes an encrypted null, and data jobs then answer `Deploy <name> once: Slipway lost the keys its data was made with (SLIPWAY_ENCRYPTION_KEY changed)`.

### 6.6 Migration `alembic/versions/20261116_0008_data_safety.py`

`revision='0008'`, `down_revision='0007'`. It follows the 0007 patterns (JSON/JSONB variant, `batch_alter_table`), the 0005 patterns (ids and timestamps) and NAMING_CONVENTION (db/base.py:17-23).

0. **Mark leftover active rows failed** (correctness 12). Migrations run before `recover_interrupted` (main.py:91), so this migration itself sets `status='failed'`, `error='Interrupted by a Slipway restart'` and `finished_at=now` on deployments in `queued`/`running`, and moves their instance from `deploying` to `failed`, as deployer.py:2300-2317 does.
1. `create_table snapshots` (without `deployment_id`).
2. `create_table backups` (without `deployment_id` and `dirty_of`).
3. `create_table first_admins`.
4. `batch_alter_table instances`: the §6.5 columns and `fk_instances_seed_snapshot_id_snapshots`.
5. `batch_alter_table deployments`: the §6.4 columns and their FKs, `ix_deployments_kind` and `ux_deployments_one_active`.
6. `batch_alter_table backups` and `snapshots`: `deployment_id` (and `dirty_of`) with their FKs. This comes last because of the cycle.
7. `downgrade()` reverses all of it (it doesn't undo step 0).

`tests/test_final_data.py:392-395` runs upgrade to head and downgrade to 0007.

### 6.7 `rotate-encryption-key` (cli.py:180-215)

After the column loop with `--clear-unreadable`, per-table fix-ups run (raw SQL by table name):

- snapshots: `ready` with `data_key IS NULL` → `failed`, error `Its key was lost with an old SLIPWAY_ENCRYPTION_KEY; delete it`;
- first_admins: `pending`, `password` mode, `password IS NULL` → `last_error='Set the password again'`.

Unreadable `backups.identity` leaves the row as is: §9.2 rule 5 explains it. The command's output lists each category.

---

## 7. Jobs

### 7.1 Kinds

| kind | label | family | instance status while running | options |
|---|---|---|---|---|
| deploy | Deploy | pipeline | DEPLOYING → RUNNING / FAILED | `started_empty`, `skip_backup`, `skip_revision_check`, `override_hold` |
| restore | Restore | pipeline, live release | DEPLOYING | `files`, `prev_status`, `undo_of?`, `restore_identity`, `skip_backup` |
| rollback | Roll back | pipeline, live release | DEPLOYING | `rollback_of`, `prev_status`, `skip_backup` |
| reset | Reset data | pipeline, live release (or **Start over**) | DEPLOYING | `seed`, `prev_status`, `started_empty`, `start_over`, `skip_backup` |
| backup | Back up | data-only | unchanged | `files`, `restop` |
| snapshot | Take snapshot | data-only | unchanged | `stop_app`, `restop` |
| admin | Create first admin | data-only | unchanged | |
| content | Add starter content | data-only | unchanged | |

**Which instances get data kinds.** Only `build_source == APP` instances whose `app_state.live` exists. Others get:
`Slipway doesn't know <name>'s data commands yet: deploy it once more (any commit whose slipway.yml declares commands.dump), then try again.`
Start over is the exception: it is for never-live instances (§7.5).

**On success.** Pipeline kinds set RUNNING, `current_commit_sha` and `last_deployed_at` (2237-2243), clear `data_dirty`, set `live_identity` from the rendered plan (§9.1), clear `seed_snapshot_id` and clear `fresh_data`. Start over leaves the status as it was. Data-only kinds call `_finish(dep, SUCCEEDED)` with no instance fields, except that `content` clears `content_pending`.

**On failure or cancel** (both paths of `run_deployment`, 2209-2233, correctness note):

- **Pipeline kinds**, when a change step began (`start` for deploy; `stop` onward for restore, rollback and reset): FAILED, and `data_dirty` is updated (§8.4).
- **Restore kinds that failed before anything changed:** `options.prev_status` is put back; the old app still runs.
- **A deploy that failed before `start`:** FAILED as today, with no dirty state.
- **Data-only kinds** never change the status.

### 7.2 Step catalogue (`STEP_NAMES`, deployer.py:1200-1211)

| key | name (per kind) |
|---|---|
| release | Check the live release |
| check | Check the backup · Check the snapshot |
| backup | Back up the data |
| stop | Stop the app |
| reset | Delete the data |
| restore | Restore the database · Restore the snapshot's database · (rollback) Restore the backup from before deployment `<d8>` |
| files | Restore the files |
| after_import | Prepare the imported data |
| first_admin | Create the first admin |
| seed | Add starter content |
| export | Export the data on `<host>` |
| store | Keep the snapshot on Slipway |
| restart | Start the app again |
| restop | Stop the data services again |

- `steps_for(instance, kind, plan)` replaces `new_steps(instance)` (1223) and writes per-kind names. `Steps` already stores names per row (1239-1245).
- For non-app instances, `step_keys` is unchanged (I7).
- `Steps.skip` gains `listed_only=True`, so `_install`'s `steps.skip("upload", …)` (1700) doesn't append a row for kinds that don't list it (`_row` appends unknown keys today, 1239-1245).
- The `_pre_start` and `_post_finish` runners iterate **the listed rows in order**, so execution order always equals display order (correctness 16).

### 7.3 Step lists

⟨…⟩ marks steps listed only when the condition, known at queue time, holds.

- **deploy (app):** `resolve, source, upload, manifest, ports, settings, build, ⟨check⟩ˢ, backup, ⟨stop, restore, files, after_import⟩ˢ, start, finish, ⟨first_admin⟩ᵃ, ⟨seed⟩ᵉ, proxy`
- **restore:** `release, manifest, settings, build, check, backup, stop, restore, ⟨files⟩ᶠ, start, finish, ⟨first_admin⟩ᵃ, proxy`
- **rollback:** `release, manifest, settings, build, check, backup, stop, restore, start, finish, ⟨first_admin⟩ᵃ, proxy`
- **reset:** `release, manifest, settings, build, ⟨check⟩ˢ, backup, stop, reset, ⟨restore, files, after_import⟩ˢ, start, finish, ⟨first_admin⟩ᵃ, ⟨seed⟩ᵒ, proxy`
- **reset, Start over:** `release, backup, stop, reset`
- **backup:** `release, backup, ⟨restop⟩ᵖ`
- **snapshot:** `release, ⟨stop⟩ᵗ, export, ⟨restart⟩ᵗ, store, ⟨restop⟩ᵖ`
- **admin:** `release, first_admin`
- **content:** `release, seed`

Conditions:

- ˢ the chain restores a snapshot: `deployment.snapshot_id` is set (copied down retries; set from `instance.seed_snapshot_id` when the chain starts on a never-live instance, or from the reset body). Finished steps are skipped through `done_by`.
- ᵃ a pending FirstAdmin exists.
- ᵉ no snapshot in the chain, `instance.seed_content`, and either the chain `started_empty` or (never live and `fresh_data == 'empty'`). At run time it is skipped unless the manifest has `seed`.
- ᵒ reset to empty with `options.seed`.
- ᶠ `options.files`.
- ᵗ `options.stop_app` and the instance is RUNNING at queue time.
- ᵖ the instance is STOPPED at queue time.

Restore kinds list no `ports` step: they use the live `host_ports` (D3).

### 7.4 Which release, which commands, which `.env`

| Job | Release that runs | Commands from | `.env` |
|---|---|---|---|
| deploy | the new release | the new plan | written in `settings` (deployer.py:1974-1985) |
| deploy's pre-deploy backup | the live release (`current`) when its slipway.yml declares `dump`; otherwise the new one | the live render (the new plan as fallback) | the live render writes the live `.env`; the new `.env` is written back in `finally`, logged `Put back the settings of release <sha7>` |
| restore, rollback, reset | the live release, reused | its slipway.yml, re-read in `manifest`, planned with `app_state.live` inputs | re-rendered in `settings` |
| backup, snapshot, admin, content | the live release, not restarted | the live render in `release` | written by the live render |
| Start over | the newest release of the instance still on the host | its slipway.yml, planned with today's inputs | re-rendered |

**Live render (`_live_plan`, D3).**

1. `live = app_state["live"]`, or refuse as in §7.1.
2. `release = paths.releases/<live.release>`. Check that `readlink current` equals `releases/<live.release>` and that the folder exists. Otherwise: `The live release on <host> isn't the one Slipway recorded (current points at <x>); deploy again first.`
3. Read slipway.yml and the `env_file` template from the folder (`_read_release_file`).
4. `manifest.plan(..., builtins=app_builtins(instance, release, live.sha, UUID(live.deployment)), settings=live.settings, chosen=live.services, host_ports=live.host_ports, secrets=app_secrets, env=instance env)`.
5. `plan.projects` must equal `live.projects` and the volume names must equal `live.volumes` (data-loss 15). Otherwise: `Release <sha7> would now run under other names (<diff>) than it runs with; an environment variable changed them. Put it back, or deploy, then retry.`
6. The plan's identity values must equal `live_identity` when that is set (data-loss 4). Otherwise: `<KEY> differs from the value <name>'s data was made with (an environment variable of the instance changed since <sha7> went live). Put the variable back, or deploy, then retry.`
7. When `env_fp` differs, log `The instance's environment variables changed since <sha7> went live; Slipway renders with the current ones`.
8. Write `.env`.

**Reusing the live release** (restore kinds), in `_start`:

- `live_dep` is the SUCCEEDED deployment whose id hex equals `live.deployment`;
- `job.retry = _Retry(id, sha, release, reusable=True)` (1303-1308);
- `job.live_inputs = live`.

`_pipeline` (2135-2187) opens no GitHub client for these kinds, builds `CommitInfo` from the copied fields, and lists no `resolve`, `source` or `upload` row. The `release` step does `_take_dir`, the host lock, empties `.incoming`, settles `unverified` rows and checks `current`. `_install` then follows its reuse path. `_install_app` takes `live_inputs`, and its `plan_with` uses them instead of `instance.app_settings`, `app_services` and the port plan (correctness 13).

**Image freshness** (generality 6). A reused release skips its build only when every `images` template contains `{slipway.sha}`, `{slipway.sha12}`, `{slipway.release}` or `{slipway.deployment}` and `_images_exist` (1864-1869) is true. Otherwise it rebuilds from the release folder and logs `Rebuilding release <sha7>: its images aren't tagged per release (slipway.yml images), so the ones on <host> may be another release's`. The Restore and Roll back dialogs say `Slipway rebuilds <sha7> first (up to <build timeout>)` when that applies.

### 7.5 Step algorithms

All app commands go through `_run_commands` (1797-1805). It gains `timeout=` (from the manifest), `slots=`, `stream=`, `input=`, `lock_key=` and `shown=` (the `$` text).

#### backup

The reason comes from the kind: `pre_deploy`, `pre_restore`, `pre_reset`, `pre_rollback` or `manual`. Files are included for `pre_reset`, for `pre_restore` when the restore puts files back, and for `manual` when ticked.

1. **Inherited** (§8.1, only when the parent began a change step).
   - Re-check the inherited backup on the host (exists, size, sha).
   - Fine → skip: `Keeping the backup taken before the first attempt: <name> (taken <UTC>)`, and set `dep.backup_id`.
   - Gone → `warning`: `The backup taken before the first attempt (<name>) is no longer on <host>; a new one now would hold half-changed data, so none is taken.` Set `dep.backup_id = NULL`.
   - If `instance.last_control_at > parent.finished_at`, also take a `pre_retry` backup (steps 4-12). Its failure is a `warning` (`The app was started by hand after the first attempt, and its data could not be backed up again: writes since <time> aren't in any backup`).
2. **`options.skip_backup`:** `warning`, `Skipped on request by <user>: the data is changed without a backup`.
3. **Commands** (§7.4). With no `dump` in either release: skip with `slipway.yml declares no data`, and set `started_empty = True`.
4. **Probe.** When `has_data` is declared, run it (live render or new plan, as for the dump). Otherwise probe the union of `live.volumes` and the new plan's volumes (data-loss 8). `no-docker` fails with `Couldn't check <host> for the app's data: docker didn't answer (<detail>)`. A `has_data` exit other than 0, 3 or 4 fails with `commands.has_data exited <n>; Slipway can't tell whether <name> has data. Nothing was changed.`
5. **No data** (exit 3, or no `database`/`files` volume present): skip with `No data yet: <reason>`. Set `options.started_empty = True` (saved). When never live, set `fresh_data = 'empty'` unless it is `snapshot`.
6. **Seeding over data** (the chain restores a snapshot onto a never-live instance) with data present and `fresh_data` NULL: fail with
   `<host> already has data for this app (<v1>). Seeding from snapshot <name> would replace it: deploy without the snapshot, then Reset data from it, or remove the volumes (docker volume rm <v1>) to start afresh.`
   This probe also runs at the start of `check` (snapshot), so the refusal comes before staging.
7. **Data present, no dump** (deploy only): `warning`, `slipway.yml has no dump command, so the data in <v1> was not backed up`. Continue.
8. **`data_dirty` set** (dirty backup): the row gets `dirty_of`, and the log says `The data was changed by failed <kind> <d8>: this backup holds that state`. While `data_dirty.hold` is set, a failed dump becomes a `warning` instead of failing (the database may not be dumpable). `data_dirty.first.backup_id` stays pinned.
9. **Free space** (§4.2), then `data_up`.
10. Insert `Backup(pending, …, identity=live_identity or the rendered values, identity_fp, dirty_of, taken_at=now)` and commit. When `live_identity` is NULL (deployed before phase 2), the rendered identity values are used and `live_identity` is set from them, logged.
11. **Revision.** Run `revision` with stdout to `.incoming/job-<d8>/revision.out` (check=False). Read at most 16 KiB. An empty output or a non-zero exit stores NULL and logs `Couldn't read the database's revision (exit 1); the backup is kept without one`.
12. **Write** per §4.2. The row becomes `ready`, `dep.backup_id` is set, and the log says `Backed up the data: <name> (412 MiB)`. Then retention (§4.3).
13. **Revision check on deploy** (generality 10). When the kind is deploy, the live revision is known, the live release isn't the new one and the new release has `revision_check`: run the **new** release's `accepts` with the revision file. Exit 3 fails with `Release <sha7> can't run the data at revision <short>: <line>. Nothing was changed. Deploy a commit that can, or deploy with "Skip the revision check".` `options.skip_revision_check` (data:restore + typed name) turns it into a `warning`.
14. **On failure** of the dump: delete the row and raise `The backup failed (commands.dump exited 1), so Slipway changed nothing; the database is as it was. Is the database running? Fix the cause, then retry.` When Retry can skip it, this is added: ` If the data can't be backed up, Retry without the backup.`

#### check: backup (restore, rollback)

Every failure ends with ` Nothing was changed.`

1. The row passes §9.2. Otherwise its reason.
2. Host check: present, size equal, sha equal. Otherwise `The backup <name> on <host> is missing` or `… has changed since Slipway took it (size or checksum differ); Slipway won't restore it`.
3. With `options.files`: the same for `.files`, and the release must have `import_files`.
4. `accepts` (target = live release) when `revision_check` is declared and the backup has a revision. Slipway writes the revision to `.incoming/job-<d8>/revision`. Exit 3 → `Release <sha7> can't open a database at revision <short>: <last line>`. Another exit → `The revision check failed (commands.accepts exited <n>)`. Without `revision_check`, log `Slipway can't check this backup's revision against release <sha7> (slipway.yml has no accepts command)`. When the backup is dirty, log it as well.
5. Compute `job.override` (§9.3). A non-empty override without `options.restore_identity` fails with `This backup was made with other <identity label>; restoring it puts them back. Restore it again with "Put back its <identity label>" (needs data:reset).`

#### check: snapshot (seeding deploy, reset from a snapshot)

This step takes the **transfer semaphore** for the staging.

1. Probe for existing data (backup step 6) on seeding deploys.
2. The snapshot is `ready` with a readable `data_key`. Otherwise `The snapshot's key can't be decrypted with SLIPWAY_ENCRYPTION_KEY`, or `The snapshot was deleted`.
3. **Repository** (security 1, rechecked at run time): `snapshot.repository == instance.repository.full_name`, or the job's `triggered_by` still holds `snapshots:download`. Otherwise `Snapshot <name> was made from <repo or "an unknown repository">; seeding <instance> (<repo>) from it needs the snapshots:download permission`.
4. `app` equals the release's `data.app` (`This snapshot is of app <a> (<name>); <instance> runs <b>`). `db_format` equals `data.format`.
5. **Files.** If the snapshot has files, `files_format` must match and `import_files` must be declared (`The snapshot has <files label>, and release <sha7> can't import files (no commands.import_files)`). Without files, log `The snapshot has no files; <label> start empty`.
6. **Identity.** For each key in the release's `identity_keys()` that the snapshot lacks, keep the instance's own value and log a warning (generality 7): `The snapshot has no <KEY> (release <sha7> marks it as identity); the instance keeps its own. Anything in the snapshot's data that needed the source's <KEY> can't be read here.` Extra snapshot keys are ignored, with a log line. A snapshot value that fails the §9.3 validation fails the step.
7. No instance env var sets an identity key that the override changes (§9.3).
8. `accepts` with `db_revision`.
9. Free space on the host ≥ `db_bytes + files_bytes + 512 MiB`.
10. **Staging.** Decrypt `bundles/<id>.sbx` in a thread through the §10.3 validator. Members flow through an 8 × 1 MiB queue into `remote.write_stream()`, to `.incoming/job-<d8>/{database,files}.partial` (0600). Compare the in-transit sha and the host sha with the manifest, then `mv` to the final names.
11. `identity.json` is held in memory as `job.override` and is never written to the host.

#### stop

1. The live release's `stop` from the plan (same release), with the stop timeout.
2. For each project in `app_state["starting"]` that is not in the plan's projects: `(cd / && docker compose -p P down --remove-orphans)`. Those are a failed release's containers.
3. `leftovers` of the plan's projects must show no running containers: `Containers of <name> are still running on <host> (<ids>); nothing was deleted or restored`.

#### reset

1. Probe the volumes. When `has_data` exits 4: `<name>'s data lives outside <host> (commands.has_data says so); Slipway can only reset data in volumes it can delete.`
2. Each present volume's `com.docker.compose.project` label must be in `app_known_projects(instance) ∪ plan.projects` (2046-2050). Otherwise: `The volume <v> belongs to the Compose project <p>, not to this app; Slipway won't delete it. Nothing was deleted.` A present volume with no label is refused the same way (`external` or hand-made volumes).
3. `(cd / && docker compose -p P down --remove-orphans)` for each known project.
4. `docker volume rm -- V…` for the present ones (lock key `reset`, flag `d`, 300 s). A volume in use: `Could not delete <v>: <docker's line>`.
5. Probe again. Any declared volume left: `Reset ran, but <v> is still on <host>`.
6. Log `Deleted the data: <v1>, <v2>, <v3>`. When `has_data` is declared, it must now exit 3.
7. **Start over** then sets `fresh_data='empty'`, puts the FirstAdmin row back to `pending` (keeping its fields; a password is needed again unless one is still stored) and leaves the instance's status as it was.

#### restore

1. `data_up`.
2. `restore` with `in=` the backup's `.dump` or `.incoming/job-<d8>/database` (stream mode: `< file`), lock flag `d`.
3. On failure: `commands.restore exited <n>: the database may be empty or half-restored, and the app is stopped. Retry this job, or restore another backup (the one taken just before is <name>).`
4. On success, in the same step and the same database transaction:
   - if `job.override` is non-empty: re-plan with `secrets={**secrets, **override}` and rewrite `shared/.env`;
   - `_save_instance(app_secrets={**stored, **override}, live_identity=<new effective values>, identity_changed_at=now, identity_source="<backup|snapshot> <name>")`;
   - audit `instance.identity_secrets`;
   - log `<KEY>, <KEY> now come from <source>.`, followed by `identity_help` when declared;
   - on a never-live instance, set `fresh_data='snapshot'`.

`seed_snapshot_id` is **not** cleared here, only when the job succeeds (correctness 8, data-loss 18).

#### files

`import_files` with the backup's `.files` or the staged `files`. It is skipped with a note when there is nothing to import. Failure: `commands.import_files exited <n>: some files may be missing. Retry this job.`

#### after_import

Runs `after_import` when declared, only after a snapshot restore.

#### first_admin (§11.2), seed (§11.3)

Both run after `finish`.

#### export (snapshot kind)

The transfer semaphore is taken in `release`, **before** `stop` (data-loss 10). The step works in `.incoming/job-<d8>/`:

1. `data_up`, `revision` (to file), `dump` to `database` (check, sha, `verify_dump`), and `export_files` to `files` when declared.
2. The identity values come from `live_identity`.
3. A host with no hash tool fails: `<host> has none of sha256sum, shasum or openssl; a snapshot needs one`.

Refused at queue time while `data_dirty` is set: `<name>'s data was left half-changed by <kind> <d8>; a snapshot of it would seed others with that. Retry, restore or roll back first.`

#### restart / restop / stop (data-only kinds)

These use `control_command(instance, "start" | "stop")` (D17).

- `restart` runs right after `export`, and also in a `finally` around the export when `stop` succeeded.
- `restop` runs at the end, and also in `finally`.

#### store

1. Slipway space and quota checks (§5).
2. In a thread, write the tar `slipway-snapshot.json`, `identity.json`, `database` (from `remote.read_stream()`) and `files`, through the encryptor, into `incoming/<snapshot id>.partial`.
3. Each member's in-transit sha must equal the host's: otherwise `<member> changed while it was copied`.
4. `mv` to `bundles/<id>.sbx`. The row becomes `ready` with every field.
5. Without `stop_app`, log `The database and the files were copied a moment apart while the app ran`.
6. On failure the row becomes `failed` with `error`, and the partial is removed. The host staging folder is always removed in `finally`.

#### finish

Unchanged (`ln -sfn`, save `app_state`, prune), plus saving `app_state.live` and, on success, `live_identity`. For restore kinds the target is `current` itself.

### 7.6 Dispatch

- `_Job` (1311-1319) gains `kind`, `options`, `snapshot`, `restore_backup`, `inherited_backup`, `extra_pre_retry`, `done_by`, `override`, `live_inputs` and `parent`.
- `run_deployment` (2190-2243): `backup`, `snapshot`, `admin` and `content` go to `_data_job` (its own `async with connect`, no proxy step). Start over goes to `_start_over`. Everything else goes to `_pipeline`.
- `_install_app` calls `_pre_start(ctx)` between build and start. It runs the listed rows among `check`, `backup`, `stop`, `reset`, `restore`, `files` and `after_import`, in their listed order.
- `_install` calls `_post_finish(ctx)` after `finish`, inside the SSH session: `first_admin`, then `seed`. Their failures end the step as `warning` and never raise.
- `_prune_after_failure` (1756-1765) selects `kind == 'deploy'` only.
- `log.info("Deployment %s failed: %s", …)` (2216) logs `sink.scrub(str(exc))` (§12.2).

**`recover_interrupted`** (2300-2317) also:

- turns `pending` backups into `unverified`;
- marks `pending` snapshots `failed` (`Slipway restarted while this snapshot was being taken; take it again`);
- re-queues `checking` validations;
- for interrupted pipeline jobs, sets `prev_status` or `data_dirty` per §7.1, using the step rows (a `running` change step counts as begun).

---

## 8. Retry, roll back, undo, dirty state, cancel

### 8.1 Retry (`POST /deployments/{id}/retry`, deployments.py:54-78)

The body is optional: `{confirm?, skip_backup?, take_over_lock?}`.

**"Latest changing job"** is `data.latest_changing_job(instance)`: the newest deployment with kind in (deploy, restore, rollback, reset, admin, content) (D10).

`queue_deployment(retry_of=dep)` copies kind, options (without the one-shot flags), `restore_backup_id`, `snapshot_id` and the commit fields. It copies `backup_id` and sets `options.inherit` only when **both** of these hold:

1. `dep` is the latest changing job;
2. a change step of `dep` began (any row among `start` for deploy, or `reset`, `restore`, `files`, `after_import`, with status other than `pending`/`skipped`).

Otherwise the retry takes a fresh backup like any first attempt (data-loss 7a).

`_start` sets `job.done_by` for each of `reset`, `restore`, `files` and `after_import` whose parent row `succeeded` or carries `done_by`. Those steps are skipped with `Done by the first attempt (<id8>); not repeated`. `stop`, `start` and `finish` always run again.

| kind | extra checks | notes |
|---|---|---|
| deploy | branch == instance.branch (today) | reuses the release (today); see the inheritance rule |
| restore, rollback, reset | `data:restore` (reset: `data:reset`); `confirm == instance.name` (422); the latest changing job (409 `Only the most recent job of <name> can be retried; <kind> <id8> ran after it`) | live release; `check` runs again; the source backup is pinned |
| chains restoring a snapshot | a deleted snapshot whose `restore` hadn't succeeded → 409 `The snapshot this job restores was deleted; start a new reset instead` | |
| snapshot | `data:backup`, and the row still exists | the row goes back to `pending` |
| backup, admin, content | their own permission | a fresh run |

- **`skip_backup: true`** only when the parent's `backup` step failed; it needs `data:reset` and the typed name (`Retry without the backup is only for a job whose backup failed`). Audited.
- **`take_over_lock: true`** needs `data:reset` and the typed name (§4.5).

### 8.2 Roll back (`POST /deployments/{id}/rollback`, body `{confirm}`)

`data.rollback_state(db, dep) -> (bool, reason)` is shared by the API, the page and `DeploymentDetail.actions`. Roll back is available iff:

1. `dep.kind == "deploy"` and its status is failed or cancelled → otherwise `Only a failed deployment can be rolled back`.
2. `dep` is the latest changing job → otherwise `<kind> <id8> ran after this deployment; restore a backup instead`.
3. `instance.data_dirty` is set with `first.kind == "deploy"` → otherwise `Nothing to roll back: this deployment failed before it changed the data; <name> still runs <sha7>`.
4. `data_dirty.first.backup_id` points at a `ready` `pre_deploy` row → otherwise `There is no backup from before the first failed deploy (it had no data yet, or the backup is gone)`.
5. `instance.current_commit_sha` is set → otherwise `This was the first deploy: use Start over instead`.
6. The live manifest has `restore`, the backup passes §9.2, and `data_shared_reason` is None.

The rollback point is **the backup taken before the first failed deploy since the instance was last clean**, which may predate `dep` (correctness 4). When it does, the dialog says `This also undoes failed deployment <d8> before it (<sha7>).`

The job runs with `kind=rollback`, `restore_backup_id=data_dirty.first.backup_id`, `options.rollback_of=dep.id` and the live commit:

1. live render (the live `.env` and image tag come back);
2. check;
3. a `pre_rollback` backup of the migrated database, labelled "for diagnosis";
4. stop, then restore;
5. the live `start`.

Files are not rolled back, and the dialog says so. When the instance was started by hand since the first failure (`last_control_at`), the dialog adds `<name> was started by hand on <date>: what was written since is lost too.`

### 8.3 Undo

Undo isn't a new endpoint. On the page of a finished **restore or reset** job (not a rollback, correctness 11) that is the latest changing job and whose `backup_id` is `ready`, **Undo…** opens the Restore dialog for that backup, with `files` ticked when the backup has files. The undo's own `backup` step copies the current data first. `options.undo_of` records the link. A `pre_rollback` backup can still be restored by hand, and the Restore check refuses it when `accepts` says the live release can't run it.

### 8.4 `data_dirty` and the hold

**Shape:** `{first: {deployment_id, kind, backup_id, at}, last: {deployment_id, kind, step, backup_id, at}, hold: bool}`.

**Set** by `run_deployment` or `recover_interrupted` when a pipeline job fails after a change step began. `first` is kept if already set; `last` is replaced. `hold` becomes true when a restore, rollback or reset job failed in `reset`, `restore`, `files` or `after_import`.

**Cleared** when any pipeline job (deploy, restore, rollback, reset, Start over) succeeds.

**While `hold` is true, refused with 409 and the hold text:**

- `POST /instances/{id}/deploy`;
- `control` start and restart;
- Take snapshot;
- admin and content.

Retry, restore, reset, rollback and Back up now stay allowed.

**While dirty without hold:** Take snapshot is refused (§7.5). Everything else is allowed, and backups taken are marked dirty.

**Hold text:** `<name>'s last <kind> stopped part-way (step 9/14: Restore the database), so its database may be empty or half-restored. Retry it, or restore the backup taken just before it (<backup>). Start, Restart and Deploy are off until then.`

**Escape:** `{"override_hold": true, "confirm": "<name>"}` on deploy and control, with `data:reset`, audited as `instance.hold_override`. On control, `hold` is set to false at once (the dirty state stays).

### 8.5 Cancel: not in phase 2

See D14. Shutdown still cancels (2209-2214). The lock stays when a command didn't return (§4.5), and `recover_interrupted` records the dirty state.

---

## 9. Identity secrets and what can be restored

### 9.1 Effective values and fingerprint

- **Rendered identity values:** `{k: plan.env[k] for k in identity_keys()}` (an instance env var replaces a secret, manifest.py:577-582).
- **`live_identity`** is set at `finish` from the rendered values and in `restore` from the override (I3). The data's keys are what the app last went live with.
- **Fingerprint:** `identity_fp(row_id, keys, values) = sha256(b"slipway-identity-v1\0" + row_id.bytes + "".join(f"{k}={values[k]}\n" for k in sorted(keys)))`. The salt is the row id. At list time, it is recomputed over `row.identity_keys` with `live_identity`.

### 9.2 A backup is restorable iff all of these hold

The first failing rule's text replaces the Restore button.

| # | Rule | Reason text |
|---|---|---|
| 1 | app instance with a live release | `Deploy the instance first` |
| 2 | the live release has `restore` | `<sha7>'s slipway.yml has no restore command` |
| 3 | status `ready` | `Being taken` · `Not checked since Slipway restarted` · `Not on <host> any more (checked <UTC>)` · `Its size on <host> changed since Slipway took it` |
| 4 | `format` equals the live `data.format` | `Taken in format <a>; release <sha7> restores <b>` |
| 5 | identity: fingerprint equal, **or** `identity` readable and no differing key pinned by an instance env var | `Taken with other <identity label>, which Slipway can't decrypt any more (SLIPWAY_ENCRYPTION_KEY changed): put the old key back first in the list and run slipway rotate-encryption-key` · `Taken with another <KEY>, and the instance's environment variable <KEY> sets this one: remove the variable (its value stays the stored secret), then restore` |
| 6 | `data_shared_reason(instance)` is None | the hook's text |

When rule 5 passes because the values are readable but differ, the row carries `identity_note`: `Restoring it also puts back the <identity label> it was made with (<KEYS>; changed <date>: <identity_source>).`, followed by `identity_help` when declared. It also carries `needs_reset_perm: true`.

A dirty backup gets the note `Holds data changed by failed <kind> <d8> (<sha7>)`.

### 9.3 Overrides

- **Restore and rollback:** `{k: v for k, v in backup.identity.items() if k in release.identity_keys() and live_identity.get(k) != v}`.
- **Snapshot:** the snapshot's values for the release's identity keys that it has.
- **Validation** against the target secret's kind:
  - hex `^([0-9a-f]{2}){16,128}$`;
  - fernet: url-safe base64 of 32 bytes;
  - token `^[A-Za-z0-9_-]{16,256}$`;
  - no control characters, and not the manifest `placeholder`.

  Failure: `The snapshot's <KEY> isn't a valid <kind> key`.
- An instance env var pinning a key the override changes is refused: 409 at queue time and again in `check`.
- A non-empty override requires `options.restore_identity` (the dialog tick), which needs `data:reset` (D8).
- Overrides are written only in the `restore` step.

---

## 10. Snapshots

### 10.1 Inner format (plaintext), version 1

A POSIX ustar/PAX tar, uncompressed. Gzip is accepted on input. Members are regular files only, exactly these and in this order:

1. `slipway-snapshot.json` (≤64 KiB);
2. `identity.json` (≤16 KiB; present iff `identity` is non-null);
3. `database`;
4. `files` (iff `files` is non-null).

```json
{"format": "slipway-snapshot", "version": 1,
 "app": "serversherpa", "app_name": "ServerSherpa", "repository": "encondata/BaseCampV3",
 "commit": "<40 hex>", "source": "uat", "created_at": "2026-11-15T10:15:00Z", "notes": "",
 "database": {"format": "pg-custom", "revision": "0090", "bytes": 431234567, "sha256": "<64 hex>"},
 "files": {"format": "serversherpa-objects-v1", "bytes": 1234, "sha256": "<64 hex>"},
 "identity": {"keys": ["SS_PASSWORD_PEPPER", "SS_TOTP_ENCRYPTION_KEY"], "bytes": 120, "sha256": "<64 hex>"},
 "producer": "slipway 0.9.0"}
```

**Rules.**

- `commit`, `revision`, `repository`, `files` and `identity` may be null.
- Unknown keys are refused.
- `format` must be exactly `slipway-snapshot`. Any other `version` → `This snapshot was made by a newer Slipway (format version 2); update Slipway to import it`.
- `app` and the formats follow §2.1. `repository` is `^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`. `source` is `^[A-Za-z0-9][A-Za-z0-9._ -]{0,99}$`. `created_at` is exactly `YYYY-MM-DDTHH:MM:SSZ`. `revision` is ≤16 KiB with no NUL.
- `identity.keys` are unique ENV keys, at most 16, equal to the keys of `identity.json`, with values of 1-4096 characters and no control characters.
- The members present must equal the members declared.

### 10.2 Encrypted container `.sbx` (`slipway/services/snapfile.py`, stdlib plus `cryptography`)

```
magic          8   b"SLWSNAP1"
header_len     4   big-endian, <= 4096
header         JSON {"v":1,"cipher":"aes-256-gcm-stream","chunk_log2":20,"nonce_prefix":"<b64, 7 bytes>","id":"<uuid>"}
keyblock_len   4   big-endian, <= 4096
keyblock       JSON {"kdf":"none"}                                    (stored on a Slipway; DEK in snapshots.data_key)
                  | {"kdf":"scrypt","log2_n":17,"r":8,"p":1,"salt":"<b64 16>","nonce":"<b64 12>","wrapped":"<b64 48>"}
chunks         C_0 … C_last
```

- `H = SHA-256(magic ‖ header_len ‖ header)`.
- Chunk *i* uses nonce `prefix(7) ‖ be32(i) ‖ last(1)` and `AESGCM(DEK).encrypt(nonce, P_i, aad=H)`.
- Non-final chunks are exactly `C = 2^chunk_log2` plaintext bytes (16 ≤ chunk_log2 ≤ 24). The final chunk has 0..C-1 bytes and `last=1`, and EOF must follow it. The counter is limited to 2^32-1. This detects reordering, truncation, appended data and header tampering.
- **Wrapping:** `KEK = scrypt(NFC(passphrase).encode(), salt, n=2^log2_n, r, p, 32)` and `wrapped = AESGCM(KEK).encrypt(nonce, DEK, aad=H)`.
- **Accepted parameters** (security 10): `17 ≤ log2_n ≤ 18`, `r == 8`, `p == 1`. Slipway and `pack` write 17. Anything else is refused before scrypt runs: `This file asks for key-derivation settings Slipway doesn't accept`. Key derivation runs in `asyncio.to_thread` inside the **KDF semaphore** (`snapshot_kdf_slots`, separate from transfers).
- **Passphrase:** 12-1024 characters, no control characters. It is never stored, logged or audited.
- **Size** = `16 + header_len + keyblock_len + P + 16·(⌊P/C⌋+1)`.
- **Errors:**
  - `This isn't a Slipway snapshot file`;
  - `That passphrase doesn't open this file`;
  - `The file is damaged (part i+1 doesn't decrypt)`;
  - `The file is incomplete`;
  - `The file has data after its end`.
- **Export re-wraps:** a new scrypt key block goes in front of the unchanged stored body. `SLIPWAY_ENCRYPTION_KEY` never leaves the server and never encrypts a portable file.
- **Stored form** is always key block `kdf:none` (D15).

### 10.3 Streaming validation (in a thread)

1. Decrypt chunk by chunk.
2. **Sniff the plaintext yourself** (security 2):
   - `1f 8b` → decompress with Slipway's own `zlib.decompressobj(wbits=31)` and `max_length` reads;
   - `ustar` at offset 257 → plain;
   - anything else → `The file isn't a Slipway snapshot (not a tar or tar.gz)`.

   bz2, xz and zstd are refused.
3. A capped reader limits decompressed bytes to the declared sizes plus 1 MiB, and absolutely to 4 × `snapshot_max_bytes`.
4. `tarfile.open(fileobj=capped, mode="r|")` with Sirdar's `_SafeInfo` (bundle.py:173-183): PAX or GNU headers over 64 KiB are refused before they are buffered. Member type must be `REGTYPE` or `AREGTYPE`. PAX keys are limited to `path`, `size`, `mtime` and `SLIPWAY.*`. `GNU.sparse.*` keys, GNU long names and sparse types are refused.
5. Exact names, in order, no duplicates. Each header size equals the declared `bytes`, each sha256 matches, and nothing follows the last member.
6. Errors raise `SnapshotError(reason)` with safe text, e.g. `The file isn't a complete Slipway snapshot (it ends inside 'database')`.

### 10.4 Take (`POST /instances/{id}/snapshots {name, notes?, stop_app?}`)

1. Checks: name regex (422); name free (409 `There is already a snapshot named <n>`); live capability `snapshot` (409); no `data_dirty` (409); storage (503). `stop_app` needs `instances:operate` too (security 9).
2. Insert `Snapshot(pending, origin=instance, app, app_name, repository=instance.repository.full_name, source=instance.name, source_instance_id)`.
3. Queue a `snapshot` job and answer 202 `{snapshot, deployment}`.

### 10.5 Upload and import

`POST /snapshots/upload?name=&notes=` takes a raw `application/octet-stream` body (XHR sends `X-CSRF-Token`) and needs `snapshots:upload`. Uploads count in the transfer semaphore.

1. **Checks:** name and notes; storage (503); name free (409); `Content-Length` required (411) and ≤ cap (413 `The file is larger than this Slipway accepts (20 GiB, SLIPWAY_SNAPSHOT_MAX_BYTES)`); space and quota (§5).
2. **Sniff the first bytes.**
   - **`SLWSNAP1` (encrypted).** Parse the header and key block. The key block must be `scrypt` with accepted parameters, otherwise 422. Write `magic | header | {"kdf":"none"} key block | body` to `incoming/<uuid>.partial`, hashing as it goes. Insert a `locked` row (`origin=import`, `import_keyblock`, `expires_at = now + snapshot_locked_days`, `file_sha256`, `file_bytes`), `mv` the file to `bundles/<id>.sbx`, and answer 201.
   - **Plain** (`1f 8b`, or `ustar` at 257). Generate a DEK. In one streaming pass (request → bounded queue → thread), encrypt into the partial **and** validate (§10.3). Insert a `ready` row (`origin=upload`, metadata from `slipway-snapshot.json`, `repository` included) and answer 201. A validation failure answers 422 and removes the partial.
   - **Anything else:** 422 `Choose a Slipway snapshot: a .slipway-snapshot file downloaded from a Slipway, or a .tar or .tar.gz made with slipway snapshot pack`.
3. Bytes past the declared length or the cap → 413. A `ClientDisconnect` → 400 `The upload stopped before the end of the file`. The partial is always removed in `finally`. A duplicate name (IntegrityError) → 409.
4. **Unlock:** `POST /snapshots/{id}/unlock {passphrase}` (`snapshots:upload`; 409 unless `locked`).
   - Derive the KEK inside the KDF semaphore and unwrap with `aad=H`.
   - Failure → 422 `That passphrase doesn't open this file`; the row stays `locked`. At most 5 attempts per user per 10 minutes, then 429.
   - Success: store `data_key`, clear `import_keyblock` and `expires_at`, set `checking`, validate in the background, then `ready` (metadata filled) or `failed` (the `.sbx` is deleted). Answers 202.
5. **Audit:** `snapshot.upload` (name, size, file sha, encrypted), `snapshot.unlock`, `snapshot.ready` and `snapshot.failed`.

### 10.6 Download (export with a passphrase)

1. **`POST /snapshots/{id}/exports {passphrase}`** (`snapshots:download`; 409 unless ready).
   - Derive the KEK (KDF semaphore), wrap the DEK and build the key block, then discard the passphrase.
   - Create a 32-byte token, stored hashed in an in-process dict as `{user_id, snapshot_id, keyblock, expires: now+10 min}`, at most 3 per user.
   - Audit `snapshot.export` and answer 201 `{url: "/api/v1/snapshot-exports/<token>", expires_at, bytes}`.
2. **`GET /api/v1/snapshot-exports/{token}`.**
   - Requires the same user, still holding `snapshots:download`. Single use: the token is popped, otherwise 404 `This download link was used or has expired; start the download again`.
   - The response is a `StreamingResponse` with `application/octet-stream`, `Content-Disposition: attachment; filename="<name>.slipway-snapshot"`, `Content-Length` and `Cache-Control: no-store`.
   - The body is `magic | header | new keyblock | stored chunks`. The stored file is re-hashed while it streams, and the final chunk is held back until the hash equals `file_sha256`. A mismatch aborts, so the receiver sees `The file is incomplete`.
   - It counts in the transfer semaphore. Audit `snapshot.download` (bytes sent).

### 10.7 Seeding a new instance; reset from a snapshot

**On create:** `InstanceCreate.seed_snapshot_id` needs `instances:write` + `data:reset`, and `snapshots:download` when `snapshot.repository` isn't the instance's repository or is null (D16).

- The snapshot must be `ready` (409).
- Its `app` must equal the branch manifest's `data.app`. That is checked again in `check`, and is a guard against mistakes, not a security check.
- `body.env` must not set an identity key that the snapshot carries (409).

**A first admin is allowed with a seed** (generality 7). It runs after `finish`, and exists codes cover accounts that are already there.

**On edit:** while `seed_snapshot_id` is set and the instance has never gone live, changing `repository`, `branch`, `manifest_file` or `seed_snapshot_id` needs `data:reset` (403 `<name> starts from snapshot <s>; changing what code receives it needs data:reset`).

**Reset from a snapshot:** `POST /instances/{id}/data/reset {confirm, snapshot_id}`, with the same permission rule.

### 10.8 Delete (`DELETE /snapshots/{id}`, `data:reset`)

The row is loaded `FOR UPDATE`. It answers 409 `Snapshot <n> is in use: <reason>` when any of these hold:

- the status is `pending` or `checking`;
- an active job has `snapshot_id = id`;
- a never-live instance has it as `seed_snapshot_id`;
- the latest changing job of some instance references it, has failed, and its `restore` hadn't succeeded.

Otherwise it deletes the row, commits, unlinks the file and audits. `PATCH /snapshots/{id} {name?, notes?}` (`data:backup`) renames.

### 10.9 `slipway snapshot pack` (cli.py)

```
slipway snapshot pack --app ID --app-name NAME --format F --database FILE [--revision-file R] [--commit SHA]
    [--repository OWNER/NAME] [--files FILE --files-format F] [--identity-env keys.env --identity K1,K2]
    [--source S] [--notes T] [--passphrase-stdin] --out FILE
```

- It writes §10.1 (plain), or §10.2 with an scrypt key block (log2_n 17) when `--passphrase-stdin` is given. The encrypted form is recommended.
- It refuses an existing `--out` and writes through `<out>.partial` (0600).
- It prints the size, the SHA-256 and the next step: `Upload it on Slipway's Snapshots page (it asks for the passphrase)`. In plain mode it adds `…, then delete it: its keys are not encrypted`.
- `snapfile.py` imports only the stdlib and `cryptography`.

---

## 11. First admin and starter content

### 11.1 Entering it

**Where.** On create (`InstanceCreate.first_admin: {fields, mode, password?}`), or later with `PUT /instances/{id}/first-admin`.

**Who may set it** (security 5):

| Instance | Permission |
|---|---|
| never live | `instances:write` |
| live, with a pending row (left by a reset to empty or Start over) | `instances:write` |
| live otherwise (no row, or done) | `data:reset` + `confirm` (typed name), audited with `live: true` |

**Checks** against the manifest (`app_state.manifest` when deployed, otherwise the branch manifest the form loaded):

- every declared field is present, and no others;
- text: 1..max characters after strip, no Cc/Zl/Zp, not starting with `-`;
- email: ≤254 characters, `^[^@\s]{1,64}@[^@\s]+\.[^@\s.]{2,}$`, not starting with `-`;
- password mode: max(8, `min_length`) to 1024 characters with no control characters, and `password` must be declared;
- invite mode: no password (422 `A first admin invited by email has no password`), and `invite` must be declared.

**Refusals:**

- 409 `The first admin was already created; change their password in the app` (unless it is the data:reset path above);
- 409 while a job runs (checked inside `runner.exclusive`);
- 422 when the manifest has no `first_admin`.

`DELETE` drops a pending row. Audit `instance.first_admin` records `{email-like fields only, mode}`, never a password.

### 11.2 The `first_admin` step (after `finish`)

1. Re-read the row. Missing or done → skip with `No first admin to create` or `Already created on <date>`.
2. Decrypt the password. Unreadable → `warning`: `The first admin's password can't be decrypted with SLIPWAY_ENCRYPTION_KEY; set it again on the instance, then Create it now`.
3. Validate against the release's `first_admin`. A mismatch → `warning`: `The first admin doesn't fit release <sha7>'s slipway.yml: <what>. Change it on the instance, then Create it now.`
4. `sink.hide.add(password)`.
5. `argv = command + (password.args | invite.args)` with the `admin.*` slots, `umask=True`, lock flag `d`.
   - **stdin mode:** `remote.run(cmd, input=password + "\n", check=False, timeout=…)`.
   - **env mode:** `cd R && { IFS= read -r p || exit 97; VAR=$p; export VAR; unset p; exec ./prog args…; }` with the same input. Exit 97 → `the password didn't arrive on stdin`.
   - **invite mode:** no input.
   - The `$` line shows the argv: fields are visible, the password never is.
6. **Exit code.**
   - A done code → mark it done with a conditional update `WHERE id=? AND updated_at=<read>`. A lost race → `warning`: `The first admin was changed while it was being created; Create it now to create the new one`. Clear `password`, set `done_at` and `deployment_id`.
   - An exists code → the same, with `existed=true` and the log `An account for <email> already existed in the app; Slipway left it as it is`.
   - Anything else → `warning` with `messages[code]` or `The app's first-admin command failed (exit <code>)`, plus ` Change the first admin on the instance if needed, then Create it now.` Save `last_error` and keep the password.

The job succeeds either way (D12). **Create it now** (`POST /instances/{id}/first-admin/run`, kind admin, `deployments:create`) runs while the row is pending and the instance is RUNNING without a hold.

A reset to empty whose manifest declares `first_admin` requires one (422 `After the reset the app has no accounts: give a first admin so someone can sign in`). Start over keeps the existing row and returns it to pending.

### 11.3 Starter content (`seed`, after `first_admin`)

It runs when the condition ᵉ or ᵒ holds and the manifest declares `seed`; otherwise it is skipped with the reason. A failure ends the step as `warning` and sets `content_pending`. **Add starter content** (kind `content`, `deployments:create`) is offered while `content_pending` is true and clears it on success.

---

## 12. RemoteSession and logs (`slipway/services/ssh.py`)

### 12.1 New and changed methods

- **`run(..., input: str | None = None, scrub: Callable[[str], str] | None = None)`** (ssh.py:168-226).
  - With `input`: `create_process(stdin=asyncssh.PIPE)`, then `proc.stdin.write(input)` and `write_eof()`. Otherwise `DEVNULL` as today (186). `CommandFailed` never includes the input.
  - With `scrub`: each raw line is scrubbed **before** `clip_line` and before it is stored for `CommandFailed` (security 4b).
- **`read_stream(path, chunk=1 MiB) -> AsyncIterator[bytes]`.** `sftp.lstat` must report a regular file. Then `sftp.open(path, "rb")`, with each read inside `asyncio.wait_for(…, 300)`. A stall gives `The transfer from <host> stalled for 5 minutes`.
- **`write_stream(path, chunks, mode=0o600) -> int`.** `sftp.open(path, FXF_WRITE|FXF_CREAT|FXF_EXCL, SFTPAttrs(permissions=mode))`, the same stall timeout, then `chmod`.
- **`put(local, remote, mode=None)`:** an optional chmod.
- asyncssh and OS errors become `SSHError("Could not read/write <path>: …")`.

### 12.2 Redaction

`LogSink` (1088-1158) gains `hide` with an `add(value)` method and `scrub(text)`. Each hidden value of length ≥ 6 (≥ 4 for the first-admin password), longest first, is replaced with `[hidden]`.

**Applied:**

- in `RemoteSession.run` through the `scrub` callback, before clipping;
- in `line()`;
- to notes in `Steps.end`/`skip`, **before** the `[:300]` cut (1271);
- to `_finish` errors before the `[:2000]` cut (1173);
- to the server log line at 2216 (security 4d, correctness 15).

**Filled with** (security 4a and 4c):

- every `app_secrets` value, at `_start`;
- secrets generated or adopted in `manifest` (`sink.hide.add` at 1937-1950);
- every instance env value of ≥ 6 characters (manifest.py:613-615 already treats each as possibly secret);
- override values, as soon as they are read (`check`);
- `live_identity` values;
- the first-admin password.

**Limitation**, in the docs: a value printed split or encoded differently isn't caught.

---

## 13. API

Everything is under `/api/v1`. Queued jobs follow the existing pattern: build the row, `audit.record`, `db.commit()`, `runner.submit`, 202 `DeploymentOut` (instances.py:433-441). RunnerBusy → 409, DeployError → 400, SSHError → 502. An IntegrityError on `ux_deployments_one_active` → 409 `A job is already running for this instance; wait for it to finish`.

**Every record id is loaded filtered by its instance** (security 11): `Backup.id == bid AND Backup.instance_id == instance_id`. Mismatches answer 404.

| Method and path | Permission(s) | Body | Answers |
|---|---|---|---|
| GET /instances/{id}/backups?check=bool | instances:read + data:read | | 200 `{backups: [BackupOut], keep, manual_max, folder, other_files, warning?}` (§4.4) |
| POST /instances/{id}/backups | data:backup | `{files?, note?≤200}` | 202 (kind backup); 409: not deployed / no `backup` capability / busy / manual cap |
| DELETE /instances/{id}/backups/{bid} | data:reset | | 204; 409 `This backup is pinned: <why>`; 502. Under `runner.exclusive`; a `missing` row is just forgotten |
| POST /instances/{id}/data/restore | data:restore (+ data:reset when `restore_identity`) | `{backup_id, confirm, files?, restore_identity?}` | 202; 422 confirm, or files on a backup without files; 404; 409 with the §9.2 reason, `needs restore_identity`, busy, not deployed |
| POST /instances/{id}/data/reset | data:reset (+ snapshots:download per D16) | `{confirm, snapshot_id?, seed?, first_admin?}` | 202; 422 (confirm, missing first admin); 409 (no `reset` capability: `slipway.yml at <sha7> declares no data volumes and restore command, so Slipway can't reset it`; snapshot not ready or another app; env pins identity; data elsewhere) |
| POST /instances/{id}/data/start-over | data:reset | `{confirm}` | 202; 409 `<name> has gone live; use Reset data` / `Slipway has no release of <name> on <host> to back up its data with; deploy once more, or remove the volumes by hand` |
| POST /instances/{id}/snapshots | data:backup (+ instances:operate with stop_app) | `{name, notes?, stop_app?}` | 202 `{snapshot, deployment}`; 409; 422; 503 |
| GET / PUT / DELETE /instances/{id}/first-admin | instances:read / per §11.1 / instances:write | FirstAdminIn (+ `confirm?`) | 200 `{fields, mode, status, existed, done_at, last_error}` (never the password); 404; 409; 422 |
| POST /instances/{id}/first-admin/run | deployments:create | | 202 (kind admin); 409 |
| POST /instances/{id}/content/run | deployments:create | | 202 (kind content); 409 unless `content_pending` |
| POST /instances/{id}/deploy | deployments:create (+ data:reset for override_hold/take_over_lock; + data:restore for skip_revision_check) | optional `{override_hold?, take_over_lock?, skip_revision_check?, confirm?}` | as today, plus the hold 409 |
| POST /instances/{id}/actions/{action} | instances:operate (+ data:reset for override) | optional `{override_hold?, confirm?}` | runs inside `runner.exclusive` (correctness 14): busy → 409 `A job is running for this instance (<Kind>); wait for it to finish`; hold 409 for start/restart; start and restart set `last_control_at` |
| POST /instances, PATCH /instances/{id} | instances:write (+ per §10.7) | + `keep_backups`, `seed_content`, `seed_snapshot_id`, `first_admin` (create only) | as today |
| POST /deployments/{id}/retry | deployments:create + the kind's permission | optional `{confirm?, skip_backup?, take_over_lock?}` | 202; 409/422 per §8.1 |
| POST /deployments/{id}/rollback | deployments:create + data:restore | `{confirm}` | 202; 409 `Roll back isn't available: <reason>` |
| GET /deployments/{id} | deployments:read | | `DeploymentDetail` + `actions` |
| GET /snapshots, GET /snapshots/{id} | data:read | | `[SnapshotOut]`, newest first |
| POST /snapshots/upload?name&notes | snapshots:upload | raw body | 201; 400; 409; 411; 413; 422; 503; 507 |
| POST /snapshots/{id}/unlock | snapshots:upload | `{passphrase}` | 202; 409; 422; 429 |
| PATCH /snapshots/{id} | data:backup | `{name?, notes?}` | 200; 409 |
| DELETE /snapshots/{id} | data:reset | | 204; 409 |
| POST /snapshots/{id}/exports | snapshots:download | `{passphrase}` | 201 `{url, expires_at, bytes}`; 409; 422 |
| GET /snapshot-exports/{token} | snapshots:download (same user) | | 200 stream; 404 |

**Typed confirmation.**

- `confirm` must equal `instance.name` exactly (case-sensitive, no trim).
- It is checked **first**, before any other state check: 422 `Type the instance's name, <name>, exactly to confirm`.
- Required for: restore, reset, start-over, rollback, retries of those, `skip_backup`, `override_hold`, `take_over_lock`, `skip_revision_check`, and first-admin PUT on a live instance.
- Deleting backups and snapshots uses the browser `confirm()`.

**Shared checks:** `data.require_data_job(db, instance, kind)`.

- 400 `Only app instances (slipway.yml) can back up, restore or reset their data`;
- 409 "not deployed or no live state" (§7.1);
- 409 `The live release's slipway.yml has no dump command, so Slipway can't back up the data first` (restore, reset, rollback);
- 409 `… has no restore command`;
- the delete and busy checks from `queue_deployment`;
- hold and dirty rules (§8.4);
- `data_shared_reason`.

`queue_deployment` (instances.py:130-146) becomes `queue_deployment(db, instance, user, *, kind="deploy", retry_of=None, options=None, **refs)`. It sets `previous_sha` and `steps = steps_for(...)`, and its busy text becomes `A job is already running for this instance (<Kind label>); wait for it to finish`.

**Schemas** (`slipway/schemas.py`):

- `DeploymentOut` (594-630) adds `kind`, `previous_sha`, non-secret `options`, `backup` `{id, name, taken_at, status}|None`, `restore_backup` (same shape) and `snapshot` `{id, name, status}|None`.
- `DeploymentDetail.actions`: `{retry: {available, reason, needs_confirm, offers_skip_backup}, rollback: {available, reason, also_undoes}, undo: {available, backup_id, files}}`, from `data.job_actions`.
- `BackupOut`: `{id, name, reason, status, taken_at, db_bytes, has_files, files_bytes, format, revision_short, commit_sha, release, deployment_id, dirty_of, created_by, note, checked_at, pinned, pinned_reason, restorable, reason_text, identity_note, needs_reset_perm}`.
- `SnapshotOut`: the §6.2 fields except the key material, plus `revision_short`, `has_files` and `seeding_needs_download` (computed per instance on the form).
- `FirstAdminIn`: `{fields, mode, password?, confirm?}`.
- `InstanceOut` adds `keep_backups`, `seed_content`, `content_pending`, `seed_snapshot`, `first_admin`, `data_dirty` (without ids of secrets), `identity_changed_at` and `identity_source`.

---

## 14. Permissions and audit

### 14.1 Permissions (`Perm`, core/permissions.py:13-30; descriptions 33-57)

| Perm | Description | Roles |
|---|---|---|
| `data:read` | View backups and snapshots (names, sizes, dates; never their contents) | viewer, developer, maintainer (`_READ_ALL`) |
| `data:backup` | Back up instances now; take, rename and keep snapshots | developer, maintainer |
| `data:restore` | Restore a backup made with the same keys, and roll back a failed deploy (replaces an instance's data; the name must be typed) | developer, maintainer |
| `data:reset` | Reset or start over an instance's data, start instances from a snapshot, restore old identity keys, delete backups and snapshots, override a data hold or a host lock, skip a backup, create a first admin in a live app | maintainer |
| `snapshots:upload` | Upload snapshot files (privileged: a snapshot's database runs as SQL inside the app it seeds) | maintainer |
| `snapshots:download` | Download snapshots as passphrase-encrypted files, and seed instances of another repository from them (privileged: a snapshot holds a whole database and its identity keys) | admin only (`*`) |

Roles are refreshed at bootstrap (users.py:29-42), and the role editor lists the new permissions (pages.py:141-148). `data:*` doesn't include `snapshots:*`. The docs state the trust model: `data.app` is a guard against mistakes; deploy access plus push access already means root on the host (core/permissions.py:44-51).

### 14.2 Audit actions (audit.py:25-48)

Never passwords, passphrases or identity values.

| Action | Details |
|---|---|
| `backup.create` | files, note |
| `backup.delete` | name, sha256 (or "forgotten") |
| `instance.restore` | backup name, taken_at, files, identity_restored |
| `instance.rollback` | deployment, backup, also_undoes |
| `instance.reset` | to (empty or a snapshot name), seed, first-admin email |
| `instance.start_over` | volumes |
| `instance.hold_override` | the hold |
| `instance.identity_secrets` | keys, source |
| `instance.first_admin` | set, changed or dropped; email-like fields, mode, live |
| `instance.first_admin_run`, `instance.content_run` | none |
| `snapshot.take`, `.upload`, `.unlock`, `.ready`, `.failed`, `.update`, `.delete`, `.expired` | name, app, repository, origin, sizes, sha256 |
| `snapshot.export` / `snapshot.download` | name, bytes / bytes sent |
| `deployment.retry` (existing) | + kind, skip_backup, take_over_lock |
| `deployment.create` (existing) | + override_hold, skip_revision_check |
| `instance.create` / `.update` / `.delete` (existing) | + seed_snapshot, first-admin email, kept backups |

---

## 15. Pages and slipway.js

### 15.1 Instance detail (`instance_detail.html`, handler pages.py:434-448)

The handler adds `backups` (newest first, at most 50, with `restorable` and `reason` computed in Python), `first_admin`, `capabilities` (from `app_state.manifest`), `active_job`, `ready_snapshots` (same `app`, with whether seeding needs download), `data_dirty` and `ram_backed`.

- **Dirty/hold callout** at the top.
  - With a hold: the §8.4 text, with "View the job" and "Restore <backup>…".
  - Dirty without a hold: `<name>'s data was changed by failed deployment <d8> (<sha7>). Roll back, retry or deploy a fix.`, with a Roll back… link when it is available.
- **Backups card**, after Deployments (lines 129-147) and before the Danger zone (150), for app instances and `data:read`.
  - Subtitle: `Database dumps in <folder>/backups on <host>. Slipway takes one before every deploy and every change that replaces data, and keeps the newest <N> (and up to <M> you take yourself).`
  - The RAM warning when `ram_backed`.
  - Buttons:
    - **Refresh** (`?check=true`);
    - **Back up now…** (`data:backup`): a dialog with "Include <files label>" when the `files` capability exists, and a note;
    - **Take snapshot…** (`data:backup`; disabled while dirty, with the reason).
  - Body: `<div data-load="/api/v1/instances/{id}/backups?check=true" data-render="backups">`.
  - Columns:
    - Taken (UTC, local time in the title);
    - Why: `Before deploy <sha7>`, `Before retry`, `Before restore`, `Before reset`, `Before roll back (for diagnosis)` or `Back up now · <user>`, with chips `with files`, `Roll back point`, `Kept for undo` and `after failed <kind> <d8>`;
    - Data: sha7 and revision short;
    - Size;
    - On host: `On host`, `Missing`, `Changed`, `Not checked` or `Unverified`;
    - Actions: **Restore…** (`data:restore`; disabled while a job runs; when `needs_reset_perm` and the user lacks `data:reset`, the reason `Restoring it puts back old <identity label>; that needs data:reset`) or the reason text; **Delete** (`data:reset`, with `data-confirm`; it reads **Forget** for missing rows).
  - Footer: the files note, and `N other files in backups/ weren't made by Slipway and aren't listed.`
  - Empty states: `No backups yet. Slipway takes one before each deploy once the app has data.` / `This app's slipway.yml declares no dump command, so Slipway can't back it up.` / `<name>'s data lives outside <host>: Slipway backs it up but can't restore or reset it yet.`
- **Danger zone:**
  - **Reset data…** (`data:reset`), or **Start over…** while the instance has never gone live and a release exists, disabled with the reason when unavailable;
  - the Destroy text gains `Volumes and backups stay on <host> (backups, with their sign-in keys, move to .slipway-kept).`
- **First admin card:**
  - while pending: fields, mode, `Not created yet`, `last_error`, **Change…** and **Create it now** (only when RUNNING);
  - when done, for `data:reset`: **Create another first admin…** (typed name).
- **Starter content:** while `content_pending`, a muted line with **Add starter content**.
- **Overview:** `Starts from snapshot <name> on its first deploy`; `First admin: <email> (Not created yet / Created <date> / Already existed)`; `<identity label> from <identity_source> since <date>`.
- **Deployments table:** a **What** column with the kind label.

### 15.2 Dialogs (partial `_data_dialogs.html`)

Each is a `<dialog>` holding `form[data-form="POST …"]` with `data-then="redirect:/deployments/{id}"`. The typed-name field is `<input name="confirm" data-must-equal="{{ instance.name }}" autocomplete="off" spellcheck="false" maxlength="100">`, labelled `Type <name> to confirm`. The danger button stays disabled until the value matches.

- **Restore a backup.**
  - A kv list: Backup, Taken, Why, Release, Revision, Size.
  - `[ ] Also put back the <files label>` when the backup has files.
  - The identity note with `[ ] Put back its <identity label>` (`restore_identity`; required when shown; hidden without `data:reset`).
  - The rebuild note (§7.4), the dirty note, and `Slipway can't check this backup's revision against the release` when that applies.
  - Text: `Puts <instance>'s database back to this backup, then starts release <sha7> again (it migrates the data forward). Slipway first backs up the database as it is now, so you can undo this from the job's page. Everything written since <taken> is lost. The app is down while it runs.`
  - Button: **Restore backup**.
- **Reset data.**
  - `( ) Start empty  ( ) From a snapshot [select]`. Snapshots that need `snapshots:download` are disabled with that reason for users without it.
  - First-admin fields (required when declared and starting empty; optional with a snapshot).
  - `[x] Add starter content` (empty only).
  - Text: `Deletes <v1>, <v2>, <v3> on <host> and starts <instance> again <empty | from <snapshot>>. Slipway first backs up the database and the <files label>.`
  - In bold: `Deleted and in no backup: <v3>.`
  - With a snapshot: `Its <identity label> replace this instance's. <identity_help>`. For uploads: `A snapshot's database runs as SQL inside the app's database: only use snapshots you trust.`
- **Start over:** `Deletes <volumes> on <host>, which <name>'s failed first deploys created, after backing them up. The next deploy starts empty<, or from snapshot <s>>.`
- **Roll back** (deployment page): `Puts the database back as it was before deployment <d8> (backup <name>, taken <time>) and starts <live sha7> again, the release that was running. <also undoes …> Slipway first backs up the database as it is now, for diagnosis. Everything written since <time> is lost. <files label> aren't rolled back.`, plus the control note (§8.2).
- **Retry** (gated kinds): the typed name, plus `[ ] Retry without the backup` when `offers_skip_backup` and the user has `data:reset`.
- **Take snapshot:**
  - name (default `{slug}-{YYYY-MM-DD-HHmm}` UTC, checked client-side) and notes;
  - `[ ] Stop the app while copying (consistent; the app is down while the data is exported on the host)`, shown only with `instances:operate`;
  - text: `Copies <instance>'s database<, its <files label>> and its <identity label> into a snapshot kept, encrypted, on this Slipway server.`
- **Upload snapshot:**
  - file input (`.slipway-snapshot,.tar,.tar.gz,.tgz`), name, notes, and `<progress>` with `Uploading 1.2 of 4.0 GB… keep this page open`;
  - when `File.slice(0,8)` is `SLWSNAP1`: `This file is encrypted: Slipway asks for its passphrase once it has arrived (within 7 days).`
  - A locked result opens **Unlock**.
- **Download snapshot:**
  - text: `The file holds the whole database<, the <files label>> of <source> and its <identity label>. Slipway encrypts it with a passphrase you choose: anyone with the file and the passphrase can read everything in it. Slipway doesn't keep the passphrase; without it the file can't be opened.`
  - passphrase with **Generate** (24 base32 characters in groups of four, from `crypto.getRandomValues`) and **Copy**; Repeat; `[ ] I've stored the passphrase somewhere safe` (required);
  - on success `location.assign(data.url)` and the toast `Download started (<size>)`.

### 15.3 Deployment detail (`deployment_detail.html`)

- Title by kind (e.g. `Restore of <instance>`). The "Build" stat card (line 31) becomes **What**.
- Rows: `Backup taken first: <name>` (or `kept from the first attempt`), `Restores: <backup>`, `Snapshot: <name>`.
- Retry/Redeploy (lines 14-23) are driven by `actions.retry`. Gated kinds open the retry dialog; backup, snapshot, admin and content get a plain **Try again**.
- **Roll back panel** when available; otherwise, on a failed deploy, a muted line with the reason. **Undo…** when available.
- Callout after a failed restore kind: `The database may be empty or half-restored, and the app is stopped. Retry this job, or restore the backup taken just before it.`
- Warning steps after `finish` show their note with **Create it now** / **Add starter content** links.
- Retry note (line 34): `Retry of …: the same <kind>, keeping the backup from before the first attempt.` when it inherited.

### 15.4 Instance form (`instance_form.html` app section; `wireAppForm` in slipway.js)

The **Data** fieldset appears when the previewed manifest has capabilities:

- **Backups to keep** (1-100, default 5).
- **Start with** (create, or edit while never live): `( ) Empty` / `( ) A snapshot` (ready snapshots with `app == data.app`).
  - Disabled without `data:reset`, with `Starting from a snapshot needs the data:reset permission`.
  - Snapshots of another repository are disabled without `snapshots:download`.
  - With a snapshot chosen: `The first deploy restores <name>: its database, its <files label> and its <identity label> (<keys>).` plus `identity_help`.
- **First admin** (when declared): help, inputs (`type=email`, `maxlength`), and `( ) Set a password` (password and repeat, `minlength`, hint `At least <min> characters. It is passed to the app once and then forgotten.`) or `( ) <invite label>`. Optional when a snapshot is chosen, with the hint `Only needed if the snapshot has no account you can sign in with.`
- **Starter content** (when `seed` is declared): a checkbox bound to `seed_content`, hidden with a snapshot.

### 15.5 Snapshots page (`/snapshots`, `need(ctx, Perm.DATA_READ)`)

- Nav entry `("/snapshots", "database", "Snapshots", Perm.DATA_READ)` after Instances (base.html:17-25).
- Lede: `A snapshot holds an app's database, its files and the keys its data needs. New instances and Reset data can start from one. Snapshots are kept encrypted on this Slipway server; download one with a passphrase to keep a copy that doesn't depend on this Slipway.`
- **Upload…** (`snapshots:upload`).
- Columns: Name (+ notes), App, Repository, Source, Created, Revision, Database, Files, Status (Taking, Locked with `until <date>`, Checking, Ready, Failed with the error), Actions (Unlock…, Download…, Rename, Delete).
- `data-poll-reload="5000"` while any row is pending or checking.
- Empty state: `No snapshots yet. Take one from an instance's Backups card, or upload a file.`
- A footer shows usage: `<used> of <quota> used`.

### 15.6 slipway.js additions

1. **`[data-must-equal]`:** toggles `disabled` on the form's submit button; re-evaluated when its dialog opens.
2. **`data-fill` on `[data-open]`** (slipway.js:270-280): JSON that sets `[name=k].value` and `[data-slot=k].textContent`, and toggles `[data-show-if=k]`, before `showModal()`.
3. **`renderers.backups(el, data)`** (slipway.js:397): rows carry `data-open="restore-backup" data-fill='{…}'`; `data.warning` shows as a callout.
4. **`form[data-upload]`:** XHR `POST` with the raw `File` body, `?name&notes` and `X-CSRF-Token`. `upload.onprogress` drives `<progress>`. Errors go through the dialog error path (223-244). On 201: reload, or open Unlock when the result is `locked`.
5. **`then("download")`** (81-88): `location.assign(sameOrigin(data.url))`.
6. **`[data-generate-passphrase]`** fills its targets and reveals Copy.
7. **`[data-poll-reload]`:** reloads while `document.visibilityState === "visible"`.
8. **`STATUS` and `STEP_BADGE`** (352-357) and `_macros.html:23-35` become kind-aware. `running` reads Building, Restoring, Resetting, Rolling back, Backing up, Taking snapshot, Creating admin or Adding content. `succeeded` reads "Done" for non-deploy kinds. The instance badge uses `active_job.kind`.

---

## 16. Concurrency, limits, timeouts

- **One job per instance:**
  1. the runner lock (2260-2274);
  2. the `queue_deployment` check;
  3. `ux_deployments_one_active`;
  4. on the host, `.slipway-lock`.

  `control`, backup deletion, `?check=true` and first-admin edits run inside `runner.exclusive`. Moves, placement, delete and root moves are already refused while jobs run (instances.py:254, 283, 365; hosts.py:213).
- **Data scope.** Every per-instance serialisation goes through `data.data_scope_key(instance)` (the instance id in phase 2), so phase 3 can serialise per environment when slots share data.
- **Server-wide.**
  - The transfer semaphore (`snapshot_transfers`) covers take/store, staging, uploads, validation and download streams. A waiting job logs `Waiting for another snapshot transfer to finish`.
  - The KDF semaphore (`snapshot_kdf_slots`) covers unlock and export.
- **Timeouts:**
  - manifest defaults (§2.1);
  - probes and host checks 60 s; hashing 600 s; SFTP stall 300 s; `docker volume rm` 300 s;
  - export tickets 10 minutes; locked imports 7 days.
- **Sizes:**
  - snapshot members ≤ 20 GiB; inflation ≤ declared + 1 MiB and ≤ 4 × cap; quota 100 GiB;
  - `slipway-snapshot.json` 64 KiB; `identity.json` 16 KiB; PAX headers 64 KiB; `.sbx` header and key block 4 KiB each;
  - revision 16 KiB;
  - backup checks 100 names per call;
  - manual backups 10 per instance;
  - stored log 1 MB (79-80).

---

## 17. Room for phases 3+

- **Shared or external data.** `data.data_shared_reason(instance) -> str | None` is called by restorable, reset, rollback, seeding and Start over, and by their endpoints and buttons. In phase 2 it returns text only when `has_data` last answered 4: `<name>'s data lives outside <host> (an external or shared database); Slipway backs it up but won't restore, reset or seed it yet`. The answer is cached in `app_state.live.data_elsewhere` and refreshed by each probe. Phase 3 adds `<env>'s data is shared by its slots: restore it from the environment, not from slot <slot>`. That replaces Sirdar's DigitalOcean and Blue/Green refusals (pipeline.py:132-135) and closes its UI gap.
- **Managed data** (phase 4) adds an attached resource, an optional `commands.reset` for attached data, and lifts the exit-4 refusal per attached resource.
- **Backup locations.** `Backup.location` comes later (data servers); the step machinery and `kind` set stay.
- **Releases.** `app_state.live` plus kept releases leave room for rolling back a succeeded deploy, which needs per-release live inputs.
- **First admin** is keyed per instance; phase 3 moves the row to the environment.
- **Manifest.** `migrations: expand_contract` stays an unknown key until phase 3.
- **VM snapshots** (phase 5) become a `vm_snapshot` step prepended to restore, reset and rollback.
- **Seed Data recipes, scratch Postgres, `reset_passwords`** come later (decision 1). The snapshot format's `version` and its unknown-key refusal mean recipe extras arrive as version 2.
- **Kept backups.** An "Adopt kept backups" action could later read the sidecars and identity files.

---

## 18. Test plan

### 18.1 Fakes to extend

- **`APP_SCRIPT`** (tests/test_app_manifest.py:68-74) becomes a small app with its "database" in `$STATE/db` and its files in `$STATE/files`:
  - `has-data` exits per `$STATE/where` (`here` 0, none 3, `elsewhere` 4);
  - `data` logs;
  - `pgdump <dir> <out>`: copy, failing with `$DUMP_FAIL`, writing nothing with `$DUMP_EMPTY`;
  - `verify-dump`: the file starts with `DB:`;
  - `revision` prints `$STATE/rev`, and writes noise to stderr;
  - `accepts <dir> <file>`: exit 3 when its content is in `$UNKNOWN_REVS`;
  - `restore`: copies, and with `$RESTORE_FAIL` truncates and exits 1; `$RESTORE_SLEEP` sleeps (for the lock);
  - `export-objects`/`import-objects`: copy;
  - `clear-sessions` and `seed`: log, with `$SEED_FAIL`;
  - `admin`: reads one stdin line, writes `args=<argv> pwlen=<n>` to `$ADMIN_LOG`, exits `${ADMIN_RC:-0}`;
  - `up`: appends `MIGRATED` and writes the identity keys from `.env` to `$STATE/keys`.

  A stream-mode variant (`dump: {run: [cat, …], stdout: true}`) is tested too.
- **`APP_YML`** (29-55) gains the data block, `has_data`, identity on `APP_KEY`, and `first_admin` with password and invite. A second YAML declares stream mode and per-release image tags.
- **`DOCKER_SHIM`** (tests/test_final_remote.py:47-73):
  - volumes are lines `NAME LABEL` in `$FAKE_VOLUME_FILE`;
  - `volume ls -q` fails with `$FAKE_NO_DOCKER`;
  - `volume inspect -f` prints the label;
  - `volume rm` deletes, or fails "volume is in use" for `$FAKE_VOLUME_BUSY`;
  - `system df -v` prints sizes from `$FAKE_VOLUME_SIZES`;
  - `compose -p P stop|start|down` are logged.
- **`df` shim** prints `$FAKE_DF_KB`.
- **`ShellRemote`** (96-119): `run(input=, scrub=)`, `read_stream`/`write_stream` on the local filesystem with `O_EXCL`, and a hook to simulate a timeout (the process keeps running).
- **`FakeRemote`** (tests/test_deployer.py:141-170): records `inputs` as `(command, sha256(input), len)` and serves `files`.
- **`LocalRemote`** (tests/test_review_deploy_pipeline.py:68-81): gains `input`, `write_text` and the streams.
- **conftest** sets `SLIPWAY_STORAGE_DIR` to `tmp_path` (conftest.py:10-21).

### 18.2 Unit tests

1. **`tests/test_manifest_data.py`:**
   - the ServerSherpa example parses and plans (both identity keys, three volumes, `has_data`, an admin argv without `bootstrap-admin`);
   - the Django example parses **and plans** (generality 13);
   - a MySQL stream-mode example, and a no-data example (the only difference is the skipped `backup` step);
   - the bad-manifest table with exact messages:
     - `--out={slipway.out}`;
     - a slot in `start`, in `vars`, as argv[0], or twice;
     - a slot together with `stdout: true`; `stdin` on dump;
     - dump without format, app, or volume/has_data;
     - restore without dump, data_up or stop;
     - accepts without revision;
     - export without import or data.files;
     - `holds: data`; duplicate volumes;
     - an unused field, or an undeclared `{admin.x}`;
     - password with both stdin and env; env `PATH` / `LD_PRELOAD` / a secret key; neither password nor invite; `min_length: 4`;
     - overlapping codes; a message for a done code;
     - `identity: "yes"`; 17 identity secrets;
     - `timeouts` for an undeclared command, or 0.
2. **plan and app_command:**
   - slots become objects, quoted at run time (`a'; rm -rf /@x.io` stays one argument);
   - a missing slot raises;
   - stream mode renders `> P` / `< P`;
   - the lock prefix and `exec`;
   - `umask` only for data commands;
   - `to_json` and `capabilities()` round-trip;
   - teardown reads both command forms.
3. **`data` rules:**
   - name regex;
   - retention (manual kept and capped; pinned latest-changing and dirty refs kept; backup jobs don't move "latest"; dirty ones kept 2; missing rows never rm'd; rm only after re-confirmation);
   - the §9.2 matrix with exact messages;
   - the fingerprint is stable and salted;
   - `rollback_state` for every reason, including two failed deploys;
   - `latest_changing_job`;
   - retry inheritance (began vs not began; `last_control_at`).
4. **`snapfile`:**
   - plain round trip, database-only, gzip;
   - refusals: wrong order, extra member, symlink, hardlink, device, sparse (GNU type `S` and `GNU.sparse.*` PAX), GNU long name, unknown PAX key, `../x`, duplicate, oversize manifest, unknown key, version 2, a PAX header over 64 KiB, a gzip bomb, an **xz stream** and a **bz2 stream** (refused before decompressing), sha mismatch, trailing member, identity key mismatch;
   - container: round trip at P = 0, 1, C-1, C, C+1, 3C; truncation at a chunk boundary; a flipped middle byte ("damaged part 2"); swapped chunks; appended bytes; a grafted key block; `log2_n` 16 and 19 and `p=2` refused before scrypt; a wrong passphrase; re-wrap keeps the body bytes identical; the stored form has `kdf:none`; `Content-Length` equals the bytes written.
5. **Redaction:**
   - a secret in a line, a step note, `dep.error` and the server log becomes `[hidden]`;
   - a secret straddling the 300-character note cut and the `MAX_LINE_CHARS` line cut is still hidden;
   - a secret generated in `manifest` and an override read in `check` are hidden in later lines;
   - an env value `postgres://u:pw@h` is hidden;
   - 5-character values are untouched.
6. **rotate-encryption-key `--clear-unreadable`:** with an unreadable snapshot `data_key` it succeeds, and the row becomes `failed`.

### 18.3 Pipeline tests (`tests/test_data_jobs.py`; ShellRemote + docker shim + APP_SCRIPT, for each shell in SHELLS)

7. **First deploy, no data:**
   - `backup` skipped "No data yet", `started_empty` and `fresh_data='empty'` set;
   - `finish`, then `first_admin` (the password on stdin; absent from the log, notes, `dep.error`, audit and `FakeRemote.commands`; the row done, its password NULL), then `seed`;
   - `app_state.live` and `live_identity` saved;
   - the step order assertion (test_app_manifest.py:235-240) and the retry map (274-278) updated.
8. **Second deploy with data:**
   - `$APP_LOG` order: live `data`, `revision`, live `pgdump`, `verify-dump`, then the new `up`;
   - the dump ran with the **live** `.env` (`STACK_REPO_DIR` of the live release) and the new `.env` was put back before `up`;
   - modes 0600/0700, `.incoming` empty, sidecar present;
   - the row is ready, `format` the live one, revision from stdout only (the stderr noise not stored).
9. **Deploy changing `data.format`** then failing at `up`: Roll back is available and restores (correctness 1 / generality 2).
10. **Dump fails or writes nothing:** the deploy fails, `up` never ran, `current` unchanged, no row, no partial. Free space below need fails before `revision`. The first backup's estimate uses `system df` sizes.
11. **Revision check on deploy:** a live revision in `$UNKNOWN_REVS` for the new release fails before `up`; `skip_revision_check` gives a warning.
12. **Retry:**
    - after an `up` failure: one `pgdump` in total, "Keeping the backup…";
    - after a failure in `build`: a fresh backup;
    - after a control Start between: an extra `pre_retry` backup;
    - after deleting the inherited file: `warning`;
    - Back up now between a failed deploy and its retry: the retry still inherits, Roll back stays available, the backup stays pinned;
    - `skip_backup` gives a warning, and 422 when the backup didn't fail.
13. **Two failed deploys** B then C: Roll back of C restores B's pre-deploy backup and says it undoes B; that backup survived retention with `keep_backups=1`.
14. **Folder move, then Back up now, Take snapshot and Create it now:** all use the new paths (correctness 2).
15. **Restore:**
    - a failed deploy changed `.env` and a setting; the restore re-renders with `app_state.live` settings;
    - order: check, a `pre_restore` dump, stop (live plus `starting` down), data, restore, up;
    - `$STATE/db` is the backup plus `MIGRATED`; FakeGitHub got no calls; images skipped only with per-release tags (and rebuilt otherwise, logged).
16. **Restore refusals** before any `down`: missing, changed, format, `accepts` 3, and an override without `restore_identity` or without `data:reset`. Status back to RUNNING.
17. **Restore fails mid-way:**
    - the hold is set; deploy, start and restart give 409; `override_hold` without `data:reset` gives 403;
    - the retry inherits, re-runs `restore` and clears the dirty state;
    - Undo restores `pre_restore`;
    - repair attempts don't prune the hold's backup; dirty backups are labelled.
18. **Rollback:** deploy B fails at `up`; the rollback leaves `$STATE/db` as before B plus one `MIGRATED`, with a `pre_rollback` backup, and `current`/`STACK_IMAGE_TAG` are A's. No Undo offered after the rollback. Unavailable with each §8.2 reason.
19. **Reset to empty:**
    - a `pre_reset` with `.files`; volumes down, then rm;
    - `first_admin` required (422);
    - seed runs after `finish`;
    - a foreign-labelled or unlabelled volume is refused before `stop`;
    - a busy volume fails with docker's line;
    - `has_data` exit 4 is refused.
20. **Reset from a snapshot:**
    - order check → backup → stop (correctness 16);
    - staging checksums; `import-objects` and `clear-sessions` ran;
    - `.env`, `app_secrets` and `live_identity` change only after `restore`, and are unchanged with `RESTORE_FAIL`;
    - an older backup then needs `restore_identity`, and restoring it puts the old keys back (`$STATE/keys`);
    - another app → 409; another repository → 403 without download; an unknown revision fails in `check` with no `rm` in `$DOCKER_LOG`;
    - a snapshot lacking an identity key warns and keeps the instance's value.
21. **Seeded first deploy:**
    - restore before `up`; a first admin allowed after `finish`;
    - `seed_snapshot_id` cleared only at success;
    - `import-objects` failing, then Retry: the files step runs again and `restore` is skipped (correctness 8);
    - onto pre-existing volumes: refused before staging;
    - after a failed seeded attempt, a new deploy without the snapshot doesn't run `seed` (`fresh_data='snapshot'`).
22. **Start over** after a failed first deploy: backup, down, volumes removed, `fresh_data='empty'`, the first admin pending again; the next deploy is empty.
23. **Identity env pin:** a variable setting `APP_KEY` refuses a differing restore and seeding with the reason. An edited but undeployed `APP_KEY` makes Back up now refuse (data-loss 4).
24. **Back up now:** after a failed deploy, the live render rewrites `.env`; the status is unchanged; control answers 409 while it runs; on STOPPED, `restop` runs `compose stop` (not `ss-stack down`), and a later control Start starts the containers (correctness 5).
25. **Take snapshot:**
    - `bundles/<id>.sbx` has `SLWSNAP1` and `kdf:none`, decrypts with the stored DEK and validates;
    - host staging removed on success and on failure;
    - the quota fails `store`;
    - `stop_app` runs compose stop, export, then start **before** `store`; with `store` failing, the app is running;
    - refused while dirty; `stop_app` without `instances:operate` gives 403.
26. **Upload, unlock, export and import across two Slipways:**
    - plain tar and tar.gz become ready inline, and no file under storage contains the plaintext identity value;
    - export, then upload elsewhere: `locked`, with a stored file whose key block is `kdf:none` and `import_keyblock` in the row; wrong passphrase 422 (still locked); right one `checking` → `ready`; seeding works;
    - a locked row past `expires_at` is swept;
    - the ticket is single use, expires, and gives 404 to another user;
    - 411, 413 (declared and streamed), and 507 when the disk is low; a disconnect gives 400 with the partial removed;
    - a stored file altered on disk aborts the download before the final chunk.
27. **Destroy and moves:**
    - destroy with containers left behind leaves `backups/` in place and the rows `ready` (data-loss 2);
    - a successful destroy moves `backups/` with `.json` and `.identity.env` (0600), and the note names them;
    - a folder move copies backups and restore finds them; the move free-space check refuses with the message.
28. **Host lock:**
    - a timed-out `restore` (`RESTORE_SLEEP`, ShellRemote's timeout hook) leaves the lock; a retry refuses with the PID message while the process lives, and takes over after it exits;
    - a lock with another boot id is taken over;
    - a non-data lock is taken over with a warning;
    - Dockerfile and compose instances have no lock file.
29. **`recover_interrupted`:**
    - `pending` backups become `unverified`, and the next job settles them both ways;
    - pending snapshots fail, `checking` ones are re-validated;
    - an interrupted `restore` sets dirty with hold;
    - an interrupted `backup` puts back `prev_status`.
30. **I7 regression:** Dockerfile and compose step keys equal phase 1's exactly. An app without `data` deploys with `backup` skipped and nothing else changed (its existing commands are not prefixed with `umask`).
31. **Log redaction end to end:** APP_SCRIPT echoing `APP_SECRET` shows `[hidden]`.

### 18.4 API and web

32. **Permissions matrix** (test_permissions.py style): viewer, developer, maintainer and admin against every §13 endpoint, including restore with `restore_identity`, seeding from another repository, first-admin PUT on a live instance, and `stop_app`.
33. **Cross-instance ids:** `DELETE /instances/A/backups/<B's id>` and restore with B's backup id give 404 (security 11).
34. **Typed confirm:** 422 on a mismatch or a case difference for every gated action. A mistyped name on a missing backup gives 422, not 404.
35. **Concurrency:** two restore POSTs give one 202 and one 409. An IntegrityError from the partial index maps to 409. A control action during a backup job gives 409.
36. **`GET backups?check=true`:** with `connect` raising → stored rows plus a warning; while busy → stored rows plus "A job is running"; `nodir` changes no row; a file that reappears → `ready`.
37. **First admin:** PUT while a job runs gives 409; done gives 409 (except the data:reset path); invite without invite declared gives 422; GET never returns the password.
38. **Snapshot delete** is refused in each in-use case.
39. **Audit rows** carry no passwords, passphrases or identity values (scan the details JSON).
40. **Migration 0008:** upgrade marks leftover active rows failed (two active rows for one instance don't break the index); downgrade works; the partial index exists.
41. **Pages** (`test_web.py`):
    - the Backups card only for app instances with `data:read`;
    - Roll back only when available, with "also undoes";
    - `/snapshots` needs `data:read`;
    - the dirty and hold callouts;
    - `data-must-equal` holds the name;
    - the identity tick appears only with `data:reset`;
    - smoke tests for the renderers.

### 18.5 Real host (not in CI)

Deploy BaseCampV3 `slipway-manifest` twice, then:

1. Back up now;
2. take a snapshot;
3. reset from it;
4. roll back a commit with a failing migration;
5. download with a passphrase and import into a second Slipway;
6. seed a new instance from it;
7. Start over a failed first deploy;
8. an instance with `STACK_EXTERNAL_DATA=1` shows "data lives outside" and still backs up.

After each, a user signs in with their own password and 2FA.

---

## 19. Implementation slices

Slices are in dependency order. Slices in the same group touch disjoint files and can run in parallel.

| Slice | Group | Depends on | Files | Done when |
|---|---|---|---|---|
| **S1 Manifest grammar** | A (parallel) | none | `slipway/services/manifest.py`; `tests/test_manifest_data.py` (new); `tests/test_app_manifest.py` (example assertions only); `docs/examples/serversherpa.slipway.yml`; `docs/manifest.md` | §2 parses, validates and plans; tests 1-2 pass |
| **S2 Remote and redaction primitives** | A (parallel) | none | `slipway/services/ssh.py`; `tests/test_ssh.py` | `input`, `scrub`, `read_stream`, `write_stream`, `put(mode)`, with tests (stdin via `cat`, stall, symlink refused, scrub before clip) |
| **S3 Snapshot file format and CLI** | A (parallel) | none | `slipway/services/snapfile.py` (new); `slipway/cli.py` (`snapshot pack`, rotate fix-ups); `tests/test_snapfile.py` (new) | §10.1-10.3 and §10.9 and §6.7; tests 4 and 6 |
| **S4 Schema, settings, permissions** | A (parallel) | none | `slipway/models/data.py` (new), `slipway/models/instance.py`, `slipway/models/__init__.py`, `alembic/versions/20261116_0008_data_safety.py` (new), `slipway/core/permissions.py`, `slipway/core/config.py`, `Dockerfile`, `docker-compose.yml`, `install.sh`, `.env.example`, `README.md`, `tests/test_final_data.py` | §5-§6 and §14.1; test 40 |
| **S5 Data rules and snapshot storage** | B (two parallel halves) | S3, S4 | (a) `slipway/services/data.py` (new): names, shell builders, probe, retention, host check, restorable rules, fingerprint and overrides, `rollback_state`, `job_actions`, `latest_changing_job`, `data_shared_reason`, `data_scope_key`, `require_data_job`; `tests/test_data_rules.py` (new). (b) `slipway/services/snapshots.py` (new): storage, quota, upload/unlock, background validation, export tickets, delete rules, `prepare_storage`, `sweep_forever`; `tests/test_snapshots_service.py` (new) | test 3 (a); the service-level parts of test 26 (b) |
| **S6 Deployer** | C (sequential) | S1, S2, S5 | `slipway/services/deployer.py`; `tests/test_data_jobs.py` (new); `tests/test_deployer.py`, `tests/test_final_remote.py`, `tests/test_review_deploy_pipeline.py` (fakes) | §4, §7-§9, §11.2-11.3, §12.2; tests 5, 7-31. Internally done in two passes: (i) paths, lock, steps, live render, backup step, redaction, `.finish` live state; (ii) restore kinds, data-only kinds, Start over, retry, destroy, recover |
| **S7a API** | D (parallel with S7b, after S6) | S6 | `slipway/schemas.py`, `slipway/api/v1/instances.py`, `slipway/api/v1/deployments.py`, `slipway/api/v1/snapshots.py` (new), `slipway/api/v1/__init__.py`, `slipway/main.py`, `tests/test_permissions.py`, `tests/test_data_api.py` (new) | §13; tests 32-39 |
| **S7b ServerSherpa side and docs** | D (parallel; may start after S1) | S1 (grammar), S3 (pack CLI) | BaseCampV3 PR #2: `slipway.yml`, `deploy/stack/ss-stack` (`has-data`, `accepts`, `verify-dump`, `clear-sessions`, `export-objects`, `import-objects`, `seed --learning`), `deploy/stack/objects.py`, `scripts/make-seed-snapshot.sh`; Slipway `docs/snapshots.md` (new), `docs/sirdar-integration.md` | §3.2-3.3; the real-host checklist §18.5 |
| **S8 Web** | E (after S7a) | S7a | `slipway/web/pages.py`; templates `instance_detail.html`, `deployment_detail.html`, `instance_form.html`, `snapshots.html` (new), `_data_dialogs.html` (new), `base.html`, `_macros.html`; `slipway/static/js/slipway.js`; `tests/test_web.py`, `tests/test_final_ui.py` | §15; test 41 |

Parallel groups: S1, S2, S3 and S4 together; S5a with S5b; S7a with S7b (S7b can start as soon as S1 and S3 land). S6 and S8 are single-owner because each centres on one large file (`deployer.py`, `slipway.js` plus the templates).

---

## Appendix A. Critique points rejected (wholly or in part)

| Critique point | What was rejected | Reason |
|---|---|---|
| Correctness 1: "run the pre-deploy backup before `settings`" | The position only (the fix itself, live commands and the live format, is accepted) | Running it after `build` with a live-rendered `.env`, then writing the new `.env` back, gives the same guarantee and a much shorter window between the dump and `start` (the build can take an hour while the live app keeps taking writes). |
| Correctness 2: "alternatively have the move code rewrite `app_state`" | The alternative | The live render (D3) fixes moves, settings drift and failed-deploy `.env` in one place. Rewriting stored argv in every move path is fragile, as the critique itself says. |
| Correctness 6: "let `deployments:create` take over the lock when the PID is dead" | A permission for takeover of dead locks | A dead PID is taken over automatically, with no permission. Only a *live* data command needs `take_over_lock` (data:reset plus typed name). |
| Data-loss 3: "the `restore` step writes the override into `.env.live`" | `.env.live` itself | `.env.live` is dropped altogether in favour of live render plus `live_identity` (D3, D8), which also covers moves. |
| Data-loss 9: "refuse data features on Unraid RAM-backed paths" | The refusal (the race fixes, `nodir`, re-ready and confirm-before-rm are accepted) | A dump in RAM still protects the deploy it precedes, and refusing would block deploys of existing instances (every deploy of a data app runs `backup`). Slipway warns on the card and in each backup step, and the free-space check covers RAM exhaustion. |
| Data-loss 11: "measure volumes with `docker run --rm -v V:/v:ro <helper> du -sk`" | The helper-image method | It needs a pullable image on possibly offline hosts. `docker system df -v` gives the same sizes with no image, with a logged fallback. Volume size is used only when there is no earlier backup. |
| Data-loss 12: "record `instance.data_commit_sha` whenever a start begins" | The extra column | `data_dirty` plus `Backup.dirty_of` carry the same fact (which failed job changed the data, and at which sha) and also drive rollback and pinning. |
| Data-loss 6: "exclude backups taken while dirty from the N count" (keep them indefinitely) | Keeping them without limit | They are kept while pinned, plus the newest two. More copies of half-migrated data add disk pressure without adding a usable restore point. |
| Security 5: "allow PUT only before the first deploy or as part of a reset" | The total ban on a live instance | Losing the only admin account in a live app is a real recovery need. It is allowed only with `data:reset` plus the typed name, and audited with `live: true`, which meets the critique's own "anything else" condition. |
| Security 6: "a 'retire these keys' action with `identity_retired_fps`" | The retire action | Key rotation itself isn't a Slipway feature yet. Requiring `data:reset` plus an explicit tick for any key-reviving restore closes the developer path the critique describes. Retiring keys belongs with a rotation feature. |
| Generality 5: "an optional `commands.reset` now, for bind-mount or SQLite apps" | `commands.reset` in phase 2 | Reset is the one action that destroys data without a restore source. Keeping it to label-checked, Slipway-rendered volume names (I5) makes it auditable. An app-supplied delete command comes with phase 4's attached-data semantics, where it is needed anyway. Such apps can still back up and restore. |
| Generality 8: "an 'Adopt kept backups' action" | The action | It needs trust decisions (which kept folder belongs to which new instance, identity reconciliation) that phase 2 doesn't otherwise need. The sidecar `.json` and `.identity.env` make kept backups usable by hand, and `slipway snapshot pack` can turn one into a snapshot to upload. Noted in §17. |
| Generality 9: "let `started_empty` carry over to any chain while never live" (as the only fix) | Carrying the flag alone | It can't tell "empty" from "partly restored snapshot" (data-loss 18). `fresh_data` (`empty` / `snapshot`) plus Start over covers both scenarios. |
| Generality 11: "fall back to `docker compose -p P down` when `stop` is missing" | The fallback | Requiring `commands.stop` with `restore` is explicit and testable, and every realistic app with a restore command can declare one. A silent `down` of every project could also stop services the app didn't mean to stop. |
| Generality 3: "`revision` writes to `{slipway.out}`" | The slot form | Capturing stdout to a file gives the same separation from stderr without asking every app for a file-writing wrapper. ServerSherpa's existing `ss-stack revision` already prints to stdout. `accepts` does take the revision as a file (`{slipway.in}` or stdin). |

---

## Appendix B. Open questions for the user

1. **External or shared databases in phase 2.** With `has_data` exit 4 (ServerSherpa with `STACK_EXTERNAL_DATA=1` or a LAN data VM), Slipway backs up but refuses Restore, Roll back, Reset and seeding until phases 3-4. Sirdar restores into a DigitalOcean managed database when no other slot has deployed. Is the phase 2 refusal acceptable, or should a single-instance external database be restorable now (with a manifest or instance flag declaring it unshared)?
2. **Who may bring old identity keys back.** This design requires `data:reset` (maintainer) for any restore that changes the identity keys. Normal restores and roll back with the same keys stay with developers. Is that the right split?
3. **First admin in a live app.** Should a maintainer be able to create a first admin in a live, populated app (`data:reset` plus the typed name, to recover a lost admin account)? Or should first admin be limited strictly to empty starts, as in Sirdar?
