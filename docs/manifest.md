# slipway.yml

A repository describes how it is deployed in a `slipway.yml`. An instance whose build source is
**App (slipway.yml)** reads it from the commit it deploys: at the root, or at the path set on the
instance (a `.yml` or `.yaml` file, at most 256 KB). Slipway knows nothing about the app beyond what
this file says, so any app is deployed the same way.

The file has two parts:

- **Deploying** (phase 1): the settings Slipway asks for, the values it sets, the secrets it
  generates once and keeps, the services and their ports and hostnames, the Compose projects and
  images the app makes, and the commands that build, start and stop it.
- **Data** (phase 2, all optional): what the app's data is, and the commands that back it up,
  check it, restore it and add a first admin. These are what Backups, Restore, Reset, Roll back,
  snapshots, starter content and the first admin use. A `slipway.yml` without them deploys
  exactly as before; its deploys show a skipped `backup` step that says
  `slipway.yml declares no data`.
- **Environments** (phase 3, all optional): health paths for smoke tests, and how the app runs as
  Blue/Green app slots that share a data server (`data.migrations`, `data.attach`, `data.server`).
  An instance outside an environment ignores them.

A complete example is [examples/serversherpa.slipway.yml](examples/serversherpa.slipway.yml).
Slipway checks the whole file before anything runs, and a mistake fails the deploy with a message
that names the key, such as `slipway.yml: commands.dump[3]: {slipway.out} must be a whole argument`.

An app's commands run on the host as trusted code, like a compose file.

---

## Contents

1. [Top-level keys](#top-level-keys)
2. [Templates](#templates)
3. [The .env file](#the-env-file)
4. [settings](#settings)
5. [vars](#vars)
6. [secrets](#secrets)
7. [services and optional_services](#services-and-optional_services)
8. [projects and images](#projects-and-images)
9. [commands](#commands)
10. [data](#data)
11. [Slots and stream mode](#slots-and-stream-mode)
12. [What each data command must do](#what-each-data-command-must-do)
13. [first_admin](#first_admin)
14. [timeouts](#timeouts)
15. [Which commands go together](#which-commands-go-together)
16. [What Slipway offers an app](#what-slipway-offers-an-app)
17. [Environments: attach and server](#environments-attach-and-server)
18. [Examples](#examples)

---

## Top-level keys

| Key | Required | What it is |
|---|---|---|
| `version` | yes | Always `1`. |
| `name` | yes | The app's name, shown on the instance page (at most 100 characters). |
| `env_file` | no | The app's own `.env` template in the repository, such as `deploy/stack/env.example`. |
| `placeholder` | no | A value that means "not set yet", such as `CHANGEME`. Slipway refuses to deploy while any value is still this. |
| `settings` | no | Values asked for on the instance. |
| `vars` | no | Values Slipway sets. |
| `secrets` | no | Values Slipway generates once and keeps. |
| `services` | no | What the app serves: ports, port variables, hostnames. |
| `optional_services` | with optional services | The variable that lists the optional services that run. |
| `projects` | no | The Compose projects the app's commands create (at most 20). |
| `images` | no | The images a release builds (at most 30). |
| `commands` | yes (`start`) | How to build, start and stop the app, and its data commands. |
| `data` | no | What the app's data is, and how it runs in an environment. |
| `first_admin` | no | How to create the app's first administrator. |
| `timeouts` | no | How long commands may run, in minutes. |

Any other key is refused, so a typing mistake never goes unnoticed. Text values are one line. YAML
reads a bare number as a number (`3.10` becomes `3.1`), so put numbers, versions and octal values
that are meant as text in quotes: `"3.10"`, `"0755"`, `"240"`.

## Templates

Most values are templates:

- `{slipway.<name>}` is a value Slipway knows about the deploy:

  | Name | Value |
  |---|---|
  | `slipway.slug` | the instance's slug, such as `uat` |
  | `slipway.name` | the instance's name |
  | `slipway.release` | the release folder on the host (absolute) |
  | `slipway.env_dir` | the folder that holds the `.env` (`<instance folder>/shared`, absolute) |
  | `slipway.sha`, `slipway.sha12` | the commit, in full or its first 12 characters |
  | `slipway.host` | the host's address |
  | `slipway.deployment` | the first 8 characters of the deployment's id |
  | `slipway.environment` | the environment's name, such as `uat`; empty for an instance outside an environment |
  | `slipway.slot` | the slot: `blue`, `green` or `data` (the data server); empty outside an environment |

- `{KEY}` is the value `KEY` has in the app's `.env`: a setting, a var, a port variable or an
  `env_file` default.
- `{{` and `}}` are literal braces.

A template can't use a secret, nor a value the instance's own environment variables set: what
templates render is stored with the instance and shown in the deploy log, and either could be a
password. An `env_file` default that Compose would expand (`${OTHER}`, unquoted or in double
quotes) can't be used either, because Slipway would copy its unexpanded text; set it in `settings`
or `vars` instead.

`{data.<endpoint>.<field>}`, `{secret.<KEY>}`, `{server.host}`, `{server.port.<name>}` and
`{server.clients}` are values of an environment, allowed only in `data.attach` and `data.server`
([Environments](#environments-attach-and-server)); anywhere else Slipway refuses them and says where
they can be used.

`{slipway.out}`, `{slipway.in}` and `{admin.<field>}` are not template values. They are
[slots](#slots-and-stream-mode), filled in when a command runs, and only some commands can use them.

## The .env file

On every deploy Slipway writes `<instance folder>/shared/.env` (mode 600) from `env_file`. The lines
for the keys Slipway sets get their values; every other line is kept exactly as written, so Compose
reads the file as before. Keys Slipway sets that the template doesn't have are added at the end,
under `# Set by Slipway`.

When the same key comes from several places, the later one in this list wins:

1. the `env_file` defaults;
2. the settings;
3. the port variables and the optional services variable;
4. `vars`;
5. the secrets;
6. the instance's own environment variables.

In an environment, an app slot whose data is on the data server also gets `data.attach.env`, and
the data server `data.server.env`, both between `vars` and the secrets
([Environments](#environments-attach-and-server)).

Their keys never overlap, except that an environment variable of the instance may replace a secret
or an `env_file` default. It may not replace a setting, a var or a port variable: Slipway refuses
the deploy and says which.

Values are written so that Compose and a shell sourcing the file read the same thing. A value that
holds a single quote (or ends in a backslash) and also a `$` or a backtick can't be written that way,
and is refused.

## settings

Values asked for on the instance's form:

```yaml
settings:
  STACK_DOMAIN:
    label: Base domain                 # default: the key
    help: The public names are <service>.<base domain>.
    example: uat.example.com           # shown in the empty field
    default: ""                        # used when the instance leaves it empty
    required: true                     # refuse to deploy without a value
```

## vars

Values Slipway sets itself, rendered in order. Each one sees the ones before it, never one still to
come:

```yaml
vars:
  STACK_ENV: "{slipway.slug}"
  STACK_REPO_DIR: "{slipway.release}"
  STACK_IMAGE_TAG: "{slipway.sha12}"
```

## secrets

Values Slipway generates on the first deploy and keeps, encrypted, with the instance. Their names
are listed on the instance page; their values are never shown. Slipway never regenerates one,
because a new value can lock an app out of its own data.

```yaml
secrets:
  POSTGRES_PASSWORD: hex                             # the short form: just the kind
  SS_JWT_SECRET: {kind: token, bytes: 48}
  SS_PASSWORD_PEPPER: {kind: hex, identity: true}    # the data can't be used without it
```

| Key | Default | Meaning |
|---|---|---|
| `kind` | `hex` | `hex` (hex digits), `fernet` (a Fernet key: always 32 bytes) or `token` (URL-safe base64 without padding) |
| `bytes` | `32` | random bytes, 16-128 |
| `identity` | `false` | phase 2: the app's data is made with this value (see below) |

An environment variable of the instance with the same name replaces a secret, and Slipway keeps
that value as the secret, so the variable can be removed later.

**Identity secrets.** Mark a secret `identity: true` when the app's data can't be used without the
value it was made with: a key that encrypts columns, a pepper in password hashes, a key that
encrypts 2FA seeds. Each backup and snapshot carries the identity values its data was made with,
and restoring the data brings them back, so people can still sign in and encrypted columns still
read. Ordinary passwords between the app's own services (`POSTGRES_PASSWORD`) are not identity
secrets. At most 16 secrets can be identity secrets. `data.identity_label` and
`data.identity_help` say what they are in the dialogs.

## services and optional_services

What the app serves, and on which ports:

```yaml
services:
  api:     {port: 8000, port_var: STACK_API_PORT, hostname: "api.{STACK_DOMAIN}", health: /healthz}
  kiosk:   {port: 8090, port_var: STACK_KIOSK_PORT, hostname: "kiosk.{STACK_DOMAIN}", optional: true}
  mailpit: {port: 8025, port_var: STACK_MAILPIT_PORT, optional: true, default: false}

optional_services: {var: STACK_APPS, none: none}
```

| Key | Meaning |
|---|---|
| `port` | the service's default host port (1-65535) |
| `port_var` | the variable the app reads its host port from. When the port is taken on the host, Slipway moves the service to the next free port and sets this variable. Needs `port`. |
| `protocol` | `tcp` (default) or `udp` |
| `hostname` | a template for the public name. Slipway publishes it in Switchyard, like any instance's routes. Needs a tcp `port`. |
| `optional` | the instance chooses whether it runs |
| `default` | whether an optional service runs when the instance hasn't chosen (default `true`) |
| `health` | the path an environment's smoke tests request from the service's hostname, such as `/healthz` (default `/`); an answer of 200-399 passes. A path starts with `/` and has at most 200 of `A-Z a-z 0-9 . _ ~ / % ? & = + -`. Needs `hostname`. |

With any optional service, `optional_services.var` names the variable that lists the ones that run,
comma-separated, and `none` is its value when none do. A service name is lowercase letters, digits,
`-` and `_`.

## projects and images

```yaml
projects: ["ss-{STACK_ENV}-db", "ss-{STACK_ENV}-api"]
images:   ["serversherpa-api:{STACK_IMAGE_TAG}"]
```

- **projects** are the Compose projects the app's commands create. Slipway uses them for status,
  logs, start, stop and delete, and refuses a deploy whose projects another instance, or another
  app on the host, already uses.
- **images** are what a release builds, each with its tag. Slipway removes them with the release,
  unless something still uses them. A retry skips the build while the images are still on the host.
  Restore and Roll back, which reuse the live release, skip it only when every tag names the
  release (`{slipway.sha}`, `{slipway.sha12}`, `{slipway.release}` or `{slipway.deployment}`,
  directly or through a var such as `STACK_IMAGE_TAG` above); otherwise they rebuild first,
  because images under a fixed tag may be another release's.

## commands

Each command is a list: the program, then its arguments (at most 50, one line each). The program is
a path in the repository (run from the release folder, such as `deploy/stack/ss-stack`) or a
program on the host's `PATH` (such as `docker`). Slipway runs it on the host as
`cd <release> && <program> <arguments>`, each argument quoted, with no environment of its own: the
app reads `{slipway.env_dir}/.env`, which Slipway has just written.

| Command | Required | Meaning |
|---|---|---|
| `build` | no | builds the release (images); a retry may skip it |
| `start` | **yes** | starts or updates the app, migrations included; it must return once the app is up |
| `stop` | no | stops the app; used when the instance is deleted and before a restore |
| `has_data` | no | data: is there data on this host? |
| `data_up` | no | data: start only the services that hold data |
| `dump` | no | data: write a backup of the database |
| `verify_dump` | no | data: check a backup without changing anything |
| `revision` | no | data: print the data's schema revision |
| `accepts` | no | data: can this release run data at a given revision? |
| `restore` | no | data: replace the database with a backup |
| `export_files` | no | data: write an archive of the app's files (uploads) |
| `import_files` | no | data: put an archive of files back |
| `after_import` | no | data: adjust another instance's data after it is restored here |
| `seed` | no | data: add starter content to an empty app |

What each data command must do is in [What each data command must do](#what-each-data-command-must-do).
Slipway stops and starts the app for Stop, Start and the data jobs with `docker compose stop` and
`start` on its projects, not with the manifest's `stop` and `start`: those may remove containers
or run migrations.

## data

What the app's data is. Every data feature needs it.

```yaml
data:
  app: serversherpa
  format: pg-custom
  volumes:
    - {name: "ss-{STACK_ENV}-db_pgdata",           holds: database}
    - {name: "ss-{STACK_ENV}-storage_seaweeddata", holds: files}
    - {name: "ss-{STACK_ENV}-status_status-data",  holds: other}
  files: {format: serversherpa-objects-v1, label: Uploaded files}
  identity_label: sign-in keys
  identity_help: People sign in with the passwords and 2FA codes they had when the data was made.
```

| Key | Meaning |
|---|---|
| `app` | The app's id: lowercase letters, digits, `.`, `_` and `-`, at most 64, starting with a letter or digit. Required with `commands.dump`. A snapshot seeds only an app with the same id, so **never change it**. |
| `format` | A label for what `dump` writes and `restore` reads, such as `pg-custom` or `mysql-sql`: lowercase letters, digits, `.`, `_`, `+` and `-`, at most 40. Required with `commands.dump`. Slipway compares labels only: a backup is restorable when its format equals the release's. **Change it when the dump format changes incompatibly**; older backups then show "not restorable by this release" instead of failing half-way. |
| `volumes` | The Docker volumes that hold the app's data, at most 20. Each is `{name, holds}`: `name` is a template that renders to a Docker volume name, and `holds` is `database`, `files` or `other`. Reset deletes these volumes (only those whose Compose project label is one of the app's own projects). Without `has_data`, Slipway looks for the `database` and `files` volumes to tell whether there is data yet. An `other` volume is deleted by Reset and is in no backup, and the Reset dialog says so. |
| `files` | Present exactly when `commands.export_files` is: `format` (a label, as for `data.format`) and `label` (what the files are called in the dialogs, at most 40, default `Files`). |
| `identity_label` | What the [identity secrets](#secrets) are called in the dialogs, at most 60 characters (default `identity keys`). |
| `identity_help` | What losing them means for this app, at most 300 characters, shown where a restore or snapshot would change them. |
| `migrations` | `expand_contract` (the only value): each release's migrations only add, and what they remove is removed a release later, so the release before runs on the schema the next one migrates. Two app slots on one set of data need it. |
| `attach` | How the app runs on a host that doesn't hold its data. See [Environments](#environments-attach-and-server). |
| `server` | How the app's own data services run alone on a data server. See [Environments](#environments-attach-and-server). |

Volume names may use the app's vars, settings and builtins; they may not use a secret. Two entries
may not render to the same name.

## Slots and stream mode

A command that moves a file needs a value only known when it runs: the file. Such values are
**slots**:

| Slot | Allowed only in | Filled with |
|---|---|---|
| `{slipway.out}` | `dump`, `export_files` | the file the command writes; Slipway names it, in a folder only the SSH user can read |
| `{slipway.in}` | `verify_dump`, `accepts`, `restore`, `import_files` | the file the command reads: a checked backup, or, for `accepts`, a file holding the revision |
| `{admin.<field>}` | `first_admin.command` | what the operator entered for that field (checked first) |

The rules:

- A slot is a **whole argument**. Write `--out` and `{slipway.out}` as two arguments, never
  `--out={slipway.out}`, so a value Slipway fills in can never change the rest of the command.
- A command that allows `{slipway.out}` or `{slipway.in}` needs it **exactly once**.
- A slot is never the program (the first item).
- A slot anywhere else (another command, `vars`, hostnames, projects, images, `data.volumes`,
  `first_admin`'s `args`) is refused.

Slipway quotes each slot's value when it runs the command, like every other argument.

**Stream mode.** A command that writes or reads its file can use stdout or stdin instead of a slot,
so plain tools such as `pg_dump`, `mysqldump`, `pg_restore` and `mysql` work without a wrapper
script:

```yaml
dump:    {run: [docker, compose, -p, "shop-{slipway.slug}", exec, -T, db, pg_dump, -Fc, -U, shop, shop], stdout: true}
restore: {run: [docker, compose, -p, "shop-{slipway.slug}", exec, -T, db, pg_restore, --no-owner, -U, shop, -d, shop], stdin: true}
```

- `stdout: true` (for `dump` and `export_files`): Slipway runs the command as
  `<program> <arguments> > <file>`.
- `stdin: true` (for `verify_dump`, `accepts`, `restore` and `import_files`): Slipway runs it as
  `<program> <arguments> < <file>`.

stderr still goes to the deploy log. The mapping has exactly `run` and that one flag, set to `true`,
and `run` holds no slot: give either `{slipway.out}` or `stdout: true`, not both. Stream mode also
avoids mounting Slipway's backups folder into a container that runs as another user.

## What each data command must do

Every data command runs from the release, as other commands do, after Slipway has written the
`.env`. Its output goes into the job log, with secret values hidden. Data commands run with
`umask 077`, so the files they make are readable only by the SSH user.

| Command | Slipway has made sure | The command must |
|---|---|---|
| `has_data` | the `.env` is written | exit **0** when the data is on this host, **3** when there is no data yet, **4** when the data lives outside this host (an external or shared database). Anything else fails the step. |
| `data_up` | the `.env` is written | start only the services that hold data; be safe to run twice; exit 0 once they accept connections |
| `dump` | `data_up` ran; the output file doesn't exist | write one complete file (to `{slipway.out}`, or to stdout), and exit 0 only when it is complete |
| `verify_dump` | the file is complete | read it without changing anything; exit 0 when it is a usable dump |
| `revision` | the data services are up | print the schema revision on stdout (at most 16 KiB; Slipway trims it). Slipway reads stdout only, so log lines on stderr can't become the revision. An empty output or a non-zero exit means "unknown". |
| `accepts` | it runs in the *target* release; no database is needed | read a revision from `{slipway.in}` (or stdin). Exit **0**: this release can run data at that revision (it may migrate it forward). Exit **3**: it can't, and its last line says why. Anything else: the check itself failed. |
| `restore` | the app is stopped (Slipway ran `stop`); `data_up` ran; the input is a checked, regular file | replace the whole database; never start the app |
| `export_files` | as for `dump` | write one archive of the app's files |
| `import_files` | as for `restore` | put the archive back (it may keep files that aren't in it) |
| `after_import` | another instance's data (a snapshot) is in; the app isn't started yet | adjust the imported data, such as forgetting sessions or rewriting URLs; be safe to run twice |
| `seed` | the app started on empty data and is live | add starter content; be safe to run twice |

**What Slipway checks before replacing data.** The backup's `data.format` must equal the target
release's. When the target release has both `revision` and `accepts` and the backup has a revision,
`accepts` must exit 0. A normal deploy also runs the new release's `accepts` on the live data's
revision, before it changes anything.

**Before a deploy changes data,** Slipway backs it up with the commands of the release that is
live, because that release's code made the data. The new release's commands are used only when the
live release declares no `dump` (the deploy that adds it).

## first_admin

How to create the app's first administrator, so someone can sign in after the first deploy (or
after a reset to empty). Slipway asks for the fields on the instance and runs the command once the
deploy has finished. The password never goes in the command line: it arrives on the command's stdin.

```yaml
first_admin:
  help: The first deploy creates this person as the first super admin.
  command: [deploy/stack/ss-stack, admin, "{slipway.env_dir}", --email, "{admin.email}",
            --first-name, "{admin.first_name}", --last-name, "{admin.last_name}"]
  fields:
    first_name: {label: First name, max: 100}
    last_name:  {label: Last name, max: 100}
    email:      {label: Email, kind: email}
  password: {min_length: 8, stdin: true, args: [--password-stdin]}
  invite:   {label: Email them a link to set their password, args: [--invite]}
  done_codes: [0]
  exists_codes: [10]
  messages:
    3: The password is shorter than the app's password policy allows.
```

| Key | Meaning |
|---|---|
| `help` | shown above the fields, at most 300 characters |
| `command` | required: the program and its arguments, as for `commands`. Every field is used in it at least once as `{admin.<field>}`, and every `{admin.…}` slot names a field. |
| `fields` | 1-8 fields. A name is a lowercase letter, then lowercase letters, digits and `_` (at most 31). Each has `label` (at most 60, default the name), `kind` (`text` or `email`), `help` (at most 200) and `max` (1-254 characters; default 200, or 254 for an email). |
| `password` | offers "Set a password". `min_length` is 8-128 (default 8; Slipway never accepts fewer than 8). Give **one** of `stdin: true` (the password is one line on the command's stdin) or `env: VAR` (Slipway reads stdin into `$VAR`, then runs the command). `args` (at most 10) are added to the command in this mode. |
| `invite` | offers "Email them a link" instead of a password. `label` is the choice's text (at most 60); `args` (at most 10) are added to the command in this mode. |
| `done_codes` | exit codes that mean the account was created (default `[0]`) |
| `exists_codes` | exit codes that mean the account already existed; that counts as done (default none) |
| `messages` | what to tell the operator for other exit codes (1-255), at most 300 characters each |

At least one of `password` and `invite` is required. With `env:`, `VAR` is uppercase letters, digits
and `_`, starting with a letter. It can't be a key slipway.yml already sets (a setting, var, secret
or port variable), nor one the shell or the loader reads for itself: `PATH`, `HOME`, `SHELL`,
`IFS`, `ENV`, `BASH_ENV`, `CDPATH`, `PS4`, `USER`, `LOGNAME`, or any `LD_…` or `DYLD_…`.
`args` are templates and can't hold slots. Codes are 0-255; `done_codes` and `exists_codes` don't
overlap and hold at most 20 codes in all; `messages` can't be given for a done or exists code.

A failed first admin doesn't fail the deploy: the step ends as a warning with the app's message,
and **Create it now** on the instance runs it again.

## timeouts

How long a command may run, in minutes (1-1440). Each key is a declared command or `first_admin`:

```yaml
timeouts: {restore: 120, export_files: 120, import_files: 120}
```

The defaults:

| Command | Minutes | Command | Minutes |
|---|---|---|---|
| build | 60 | revision | 2 |
| start | 60 | accepts | 2 |
| stop | 15 | restore | 240 |
| has_data | 2 | export_files | 240 |
| data_up | 15 | import_files | 240 |
| dump | 120 | after_import | 30 |
| verify_dump | 30 | seed | 30 |
| first_admin | 10 | | |

## Which commands go together

Slipway refuses a slipway.yml whose data commands can't work together:

| Declared | Needs | Why |
|---|---|---|
| `dump` | `data.app`, `data.format`, and `has_data` or a `data.volumes` entry that holds `database` or `files` | snapshots are matched on the id; backups are compared on the format; Slipway must tell an instance with data from a new one |
| `restore` | `dump`, `data_up`, `stop` | Slipway restores only what it backed up, and stops the app and starts only the data services before a restore |
| `verify_dump`, `revision`, `has_data`, `seed` | `dump` | they check, describe or depend on what `dump` backs up |
| `accepts` | `revision` | it is given the revision that `revision` prints |
| `after_import` | `restore` | it runs after a restore |
| `export_files` | `import_files`, `data.files` and `dump` (and the other way round) | a snapshot taken here must be restorable here, and files are backed up with the database |

## What Slipway offers an app

What a release's slipway.yml declares decides what the instance page and the API offer for it:

| Feature | Needs |
|---|---|
| Backups (and the backup before every deploy) | `dump` |
| Checking backups | `verify_dump` |
| Restore and Roll back | `dump` and `restore` |
| Checking a backup's revision against a release | `revision` and `accepts` |
| Files in backups and snapshots | `export_files` |
| Reset data | `restore` and at least one `data.volumes` entry |
| Snapshots | `dump` |
| Starting a new instance from a snapshot | `restore` |
| First admin | `first_admin` |
| Starter content | `seed` |
| An environment with a data server (one app slot) | `data.attach` and `data.server` |
| Blue/Green (two app slots on one data server) | `data.server` and `data.migrations: expand_contract` |

When `has_data` exits 4 (the data lives outside the host), Slipway still backs the data up, but
won't restore it, roll it back, reset it or seed it.

## Environments: attach and server

An **environment** runs one app as up to two **app slots** (`blue`, `green`) and, with a data
server, one **data server** (`data`). Every slot is an instance of its own on an SSH host. In mode
`slot`, the one app slot holds its own data and deploys as any instance does. In mode `server`, the
data server runs only the app's data services, and the app slots reach it over the network;
`data.attach` and `data.server` say how. Slipway knows nothing more about the app than this.

```yaml
data:
  migrations: expand_contract
  attach:                            # an app slot whose data is on the data server
    needs: {db: postgres, objects: s3}
    env:
      STACK_EXTERNAL_DATA: "1"
      STACK_DB_HOST: "{data.db.host}"
      SS_DATABASE_URL: "postgresql+asyncpg://{data.db.user}:{data.db.password}@{data.db.host}:{data.db.port}/{data.db.database}"
      SS_DATABASE_CA_B64: "{data.db.ca_b64}"
      SS_SPACES_SECRET_KEY: "{data.objects.secret_key}"
  server:                            # the data server
    services: [spaces]
    ports: {db: {port: 5432, port_var: STACK_DB_PORT}}
    secrets: [POSTGRES_PASSWORD, SPACES_SECRET_KEY]
    env: {STACK_DB_PUBLISH: "1", STACK_DB_ALLOW: "{server.clients}"}
    projects: ["ss-{STACK_ENV}-db", "ss-{STACK_ENV}-storage"]
    volumes: ["ss-{STACK_ENV}-db_pgdata", "ss-{STACK_ENV}-storage_seaweeddata"]
    commands:
      start:    [deploy/stack/ss-stack, data, "{slipway.env_dir}"]
      has_data: [deploy/stack/ss-stack, has-data, "{slipway.env_dir}", --server]
    provides:
      db: {host: "{server.host}", port: "{server.port.db}", database: serversherpa, user: serversherpa,
           password: "{secret.POSTGRES_PASSWORD}", tls: disable, ca_b64: ""}
      objects: {endpoint: "https://spaces.{STACK_DOMAIN}", region: us-east-1, bucket: "{SS_SPACES_BUCKET}",
                access_key: serversherpa, secret_key: "{secret.SPACES_SECRET_KEY}", path_style: "true"}
```

**`data.attach`**

| Key | Meaning |
|---|---|
| `needs` | The data endpoints the app reads: 1 to 4 names (a lowercase letter, then lowercase letters, digits and `_`), each with its kind, `postgres` or `s3`. |
| `env` | 1 to 40 `.env` keys written into every app slot's `.env` when its data isn't on the slot (after `vars`, before the secrets). A key may not be a setting, a var, a secret or a port variable. Values may use `{data.<endpoint>.<field>}` (a declared endpoint and a field of its kind) and `{secret.<KEY>}`, as well as the usual template values. A value that renders to nothing is **left out** of the `.env`, and the `env_file`'s own line for it, if any, stays as written: one `attach` serves a data server without a CA and a managed database with one. |

**Endpoint kinds and their fields**

| Kind | Fields | Secret fields |
|---|---|---|
| `postgres` | `host`, `port`, `database`, `user`, `password`, `tls` (`disable` or `require`), `ca_b64` (may be empty; with `tls: require`, a CA means the app checks the server's certificate and name) | `password` |
| `s3` | `endpoint`, `region`, `bucket`, `access_key`, `secret_key`, `path_style` (`true` or `false`) | `secret_key` |

A value made with a secret (`{secret.<KEY>}`, or a secret field such as `{data.db.password}`) is a
**secret value**: like a secret, it is hidden in logs, never stored with the instance, and can't be
used by another template.

**`data.server`** needs `data.attach` (the app slots must be told where the server is) and
`commands.dump` (Slipway backs the data up on the server).

| Key | Meaning |
|---|---|
| `services` | The services that run on the data server, such as an object store. Each must be declared, not optional, with a `port`. Their hostnames follow the data server, never the active slot. |
| `ports` | Up to 8 ports only the data server publishes, such as its database: `{port, port_var}`. A name is a lowercase letter, then lowercase letters, digits and `_`, and not a service's name; `port_var` is a variable no service, setting, var or secret sets. |
| `secrets` | The only secrets written on the data server; every other secret's line is written empty (`KEY=`). It must list every secret `provides` uses. The data's [identity values](#secrets) Slipway records come from the environment, never from these empty lines. |
| `env` | Up to 20 `.env` keys written only on the data server (after `vars`). Not a setting, var, secret or port variable. Values may use `{server.host}`, `{server.port.<name>}` and `{server.clients}`, never a secret or a `{data.…}` value. |
| `projects` | The `projects` entries (exactly as written there) that run on the data server. Default: every project. |
| `volumes` | The `data.volumes` names (exactly as written there) that live on the data server. Default: every volume. The others stay on each app slot (ServerSherpa's status page, for one), and Reset clears them there. |
| `commands` | Commands that replace the app's own on the data server: `build`, `start`, `stop`, `has_data` and `data_up`, written as in `commands` (no slots). Every other command, `dump` and `restore` included, runs as declared, with the server's `.env`. |
| `provides` | Every `needs` endpoint, with every field of its kind: what the app slots are told. A secret field is exactly one `{secret.<KEY>}`, so Slipway knows which secret it is. Values may use `{server.host}`, `{server.port.<name>}`, `{secret.<KEY>}` and the usual template values. |

**Environment values**

| Value | Allowed in | Filled with |
|---|---|---|
| `{data.<endpoint>.<field>}` | `data.attach.env` | what the environment provides: the data server's rendered `provides` |
| `{secret.<KEY>}` | `data.attach.env`, `data.server.provides` | the environment's secret (an environment variable of the same name replaces it) |
| `{server.host}` | `data.server.provides`, `data.server.env` | the data server host's address |
| `{server.port.<name>}` | `data.server.provides`, `data.server.env` | the host port the data server got for `data.server.ports.<name>`, or for a service in `data.server.services` |
| `{server.clients}` | `data.server.env` | the app slots' hosts' LAN addresses (or proxy addresses), sorted, each once, comma-separated |

**What each member gets**

| | App slot holding its data, or no environment | App slot, data on the data server | Data server |
|---|---|---|---|
| Services, port variables and routes | as declared | without `data.server.services` | `data.server.services` and `data.server.ports` |
| `.env` keys added | none | `data.attach.env` | `data.server.env` |
| Secrets | all | all | `data.server.secrets`; the others written empty |
| Projects | all | all | `data.server.projects` |
| Volumes | all | `data.volumes` without `data.server.volumes` | `data.server.volumes` |
| Commands | as declared | as declared | `commands`, with `data.server.commands` in place of the app's |

The environment's own variables may not set a key that `data.attach.env`, `data.server.env` or a
`data.server.ports` variable sets.

`migrations: expand_contract` is a promise Slipway can't check: during a deploy to the idle slot,
its `start` migrates the shared database while the active slot keeps serving the release before.
Two app slots need it.

## Examples

**ServerSherpa** ([examples/serversherpa.slipway.yml](examples/serversherpa.slipway.yml)) uses
every feature, through its `deploy/stack/ss-stack` script, environments with a data server
included.

**A Django app with PostgreSQL**, no object store and no wrapper scripts:

```yaml
version: 1
name: Acme shop
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

It gets Backups, Restore, Roll back, Reset and database-only snapshots. Its revision is the whole
migration plan. It has no `accepts`, so the dialogs say Slipway can't check a backup's revision
against the release.

For Blue/Green, the same app adds a data server that is a plain Postgres container from its compose
file (its compose file leaves out its `db` service when `DB_EXTERNAL` is set, and the `db` service
reads `DB_LISTEN` and `DB_ALLOW`):

```yaml
secrets:
  DB_PASSWORD: hex
  FIELD_ENCRYPTION_KEY: {kind: fernet, identity: true}
data:
  migrations: expand_contract
  attach:
    needs: {db: postgres}
    env:
      DATABASE_URL: "postgres://{data.db.user}:{data.db.password}@{data.db.host}:{data.db.port}/{data.db.database}?sslmode={data.db.tls}"
      DB_EXTERNAL: "1"
  server:
    ports: {db: {port: 5432, port_var: DB_PORT}}
    secrets: [DB_PASSWORD]
    env: {DB_LISTEN: "0.0.0.0", DB_ALLOW: "{server.clients}"}
    projects: ["shop-{slipway.slug}"]
    volumes: ["shop-{slipway.slug}_pgdata"]
    commands:
      start: [docker, compose, -p, "shop-{slipway.slug}", --env-file, "{slipway.env_dir}/.env", up, -d, --wait, db]
    provides:
      db: {host: "{server.host}", port: "{server.port.db}", database: shop, user: shop,
           password: "{secret.DB_PASSWORD}", tls: disable, ca_b64: ""}
```

**An app without data** keeps the phase 1 keys only:

```yaml
version: 1
name: Static site
projects: ["site-{slipway.slug}"]
commands:
  build: [sh, deploy/app, build, "{slipway.env_dir}"]
  start: [sh, deploy/app, up, "{slipway.env_dir}"]
  stop:  [sh, deploy/app, down, "{slipway.env_dir}"]
```
