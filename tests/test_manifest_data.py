"""slipway.yml's data keys (phase 2): what parses, what is refused and why, and what plan() renders."""

from __future__ import annotations

import copy
import dataclasses
import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from slipway.services import manifest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = (ROOT / "docs/examples/serversherpa.slipway.yml").read_text()
SHA = "0123456789abcdef0123456789abcdef01234567"
BUILTINS = dict(slug="uat", name="UAT", release="/srv/x/releases/r1", env_dir="/srv/x/shared", sha=SHA, sha12=SHA[:12],
                host="10.0.0.1", deployment="0123abcd")

# The Django app of spec §2.5: no object store and no wrapper scripts.
DJANGO = """\
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
"""

# MySQL in stream mode: mysqldump and mysql read and write the file Slipway names through stdout and stdin.
MYSQL = """\
version: 1
name: Blog
vars: {BLOG_ENV: "{slipway.slug}"}
projects: ["blog-{BLOG_ENV}"]
data:
  app: blog
  format: mysql-sql
  volumes: [{name: "blog-{BLOG_ENV}_mysql", holds: database}, {name: "blog-{BLOG_ENV}_uploads", holds: files}]
commands:
  start:   [docker, compose, -p, "blog-{BLOG_ENV}", up, -d, --wait]
  stop:    [docker, compose, -p, "blog-{BLOG_ENV}", down]
  data_up: [docker, compose, -p, "blog-{BLOG_ENV}", up, -d, --wait, db]
  dump:    {run: [docker, compose, -p, "blog-{BLOG_ENV}", exec, -T, db, sh, -c,
                  'exec mysqldump --single-transaction -uroot -p"$MYSQL_ROOT_PASSWORD" blog'], stdout: true}
  restore: {run: [docker, compose, -p, "blog-{BLOG_ENV}", exec, -T, db, sh, -c,
                  'exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD" blog'], stdin: true}
"""

# An app with no data: it deploys exactly as before phase 2.
NO_DATA = """\
version: 1
name: Static
vars: {SITE_ENV: "{slipway.slug}"}
projects: ["site-{SITE_ENV}"]
secrets: {SITE_KEY: hex}
commands:
  build: [sh, deploy/app, build, "{slipway.env_dir}"]
  start: [sh, deploy/app, up, "{slipway.env_dir}"]
  stop:  [sh, deploy/app, down, "{slipway.env_dir}"]
"""


def _plan(man: manifest.Manifest, **kw: Any) -> manifest.AppPlan:
    args: dict[str, Any] = dict(template=None, builtins=BUILTINS, settings={}, chosen=None, host_ports={},
                                secrets={s.key: f"secret-{s.key.lower()}" for s in man.secrets}, env={})
    args.update(kw)
    return manifest.plan(man, **args)


# ------------------------------------------------------------------------ examples


def test_the_serversherpa_example_parses_and_plans():
    man = manifest.parse(EXAMPLE)
    assert man.identity_keys() == ["SS_TOTP_ENCRYPTION_KEY", "SS_PASSWORD_PEPPER"]
    assert {s.key: s.identity for s in man.secrets}["SS_JWT_SECRET"] is False
    # Its environment keys (data.migrations, attach, server) are tests/test_manifest_env.py's; data.managed is
    # tests/test_manifest_managed.py's.
    assert dataclasses.replace(man.data, migrations=None, attach=None, server=None, managed=None) == manifest.DataSpec(
        app="serversherpa", format="pg-custom",
        volumes=(manifest.Volume("ss-{STACK_ENV}-db_pgdata", "database"),
                 manifest.Volume("ss-{STACK_ENV}-storage_seaweeddata", "files"),
                 manifest.Volume("ss-{STACK_ENV}-status_status-data", "other")),
        files=manifest.DataFiles("serversherpa-objects-v1", "Uploaded files"), identity_label="sign-in keys",
        identity_help="People sign in with the passwords and 2FA codes they had when the data was made.")
    assert "has_data" in man.commands and man.streams == {}
    assert man.capabilities() == manifest.CAPABILITIES
    assert man.timeout("restore") == 120 * 60 and man.timeout("dump") == 120 * 60 and man.timeout("revision") == 2 * 60
    fa = man.first_admin
    assert fa is not None and [f.name for f in fa.fields] == ["first_name", "last_name", "email"]
    assert fa.fields[2].kind == "email" and fa.fields[2].max == 254 and fa.fields[0].max == 100
    assert fa.password == manifest.AdminPassword(min_length=8, env=None, args=("--password-stdin",))
    assert fa.invite == manifest.AdminInvite("Email them a link to set their password", ("--invite",))
    assert fa.done_codes == (0,) and fa.exists_codes == (10,) and sorted(fa.messages) == [2, 3, 4, 5, 6, 7, 8]

    plan = _plan(man, settings={"STACK_DOMAIN": "uat.example.com", "STACK_PROXY_IP": "10.0.0.2"})
    assert plan.volumes == [{"name": "ss-uat-db_pgdata", "holds": "database"},
                            {"name": "ss-uat-storage_seaweeddata", "holds": "files"},
                            {"name": "ss-uat-status_status-data", "holds": "other"}]
    assert plan.commands["dump"] == {"argv": ["deploy/stack/ss-stack", "pgdump", "/srv/x/shared", {"slot": "out"}],
                                     "stream": None}
    assert plan.commands["restore"]["argv"][-1] == {"slot": "in"}
    assert plan.commands["has_data"] == {"argv": ["deploy/stack/ss-stack", "has-data", "/srv/x/shared"], "stream": None}
    admin = plan.first_admin
    assert admin is not None and "bootstrap-admin" not in admin["argv"]  # ss-stack admin adds it itself
    assert admin["argv"] == ["deploy/stack/ss-stack", "admin", "/srv/x/shared", "--email", {"slot": "admin.email"},
                             "--first-name", {"slot": "admin.first_name"}, "--last-name", {"slot": "admin.last_name"},
                             "--role", "super_admin", "--link-minutes", "240"]
    assert admin["password_args"] == ["--password-stdin"] and admin["invite_args"] == ["--invite"]


def test_the_django_example_parses_and_plans():
    man = manifest.parse(DJANGO)
    assert man.identity_keys() == ["FIELD_ENCRYPTION_KEY"]
    assert man.streams == {"dump": "stdout", "verify_dump": "stdin", "restore": "stdin"}
    # No accepts: no revision check. No export_files: database-only snapshots. No seed: no starter content.
    assert man.capabilities() == ("backup", "verify", "restore", "reset", "snapshot", "seed", "first_admin")
    assert man.first_admin is not None and man.first_admin.password == manifest.AdminPassword(
        min_length=10, env="DJANGO_SUPERUSER_PASSWORD")
    assert man.first_admin.invite is None and man.first_admin.messages == {
        1: "Django refused the user (is the username taken?); the log shows why."}

    plan = _plan(man)
    assert plan.volumes == [{"name": "shop-uat_pgdata", "holds": "database"}]
    assert plan.commands["dump"] == {"argv": ["docker", "compose", "-p", "shop-uat", "exec", "-T", "db", "pg_dump", "-Fc",
                                              "-U", "shop", "shop"], "stream": "stdout"}
    restore = plan.commands["restore"]
    assert restore["stream"] == "stdin" and restore["argv"][-1].startswith("psql -U shop -d shop -c 'DROP SCHEMA")
    assert plan.commands["verify_dump"]["stream"] == "stdin" and plan.commands["revision"]["stream"] is None
    assert plan.first_admin is not None and plan.first_admin["argv"][-4:] == [
        "--username", {"slot": "admin.username"}, "--email", {"slot": "admin.email"}]
    assert plan.first_admin["password_args"] == [] and plan.first_admin["invite_args"] == []
    assert plan.env["FIELD_ENCRYPTION_KEY"] == "secret-field_encryption_key"


def test_a_mysql_app_streams_its_dump_and_restore():
    man = manifest.parse(MYSQL)
    assert man.capabilities() == ("backup", "restore", "reset", "snapshot", "seed")
    plan = _plan(man)
    assert plan.commands["dump"]["stream"] == "stdout" and plan.commands["restore"]["stream"] == "stdin"
    assert plan.commands["dump"]["argv"][-1] == 'exec mysqldump --single-transaction -uroot -p"$MYSQL_ROOT_PASSWORD" blog'
    assert not any(isinstance(a, dict) for cmd in plan.commands.values() for a in cmd["argv"])  # no slots at all
    assert [v["name"] for v in plan.volumes] == ["blog-uat_mysql", "blog-uat_uploads"]


def test_an_app_without_data_plans_as_before():
    man = manifest.parse(NO_DATA)
    assert man.capabilities() == () and man.identity_keys() == [] and man.first_admin is None
    assert man.data == manifest.DataSpec() and man.timeouts == {}
    plan = _plan(man)
    assert plan.commands == {
        "build": {"argv": ["sh", "deploy/app", "build", "/srv/x/shared"], "stream": None},
        "start": {"argv": ["sh", "deploy/app", "up", "/srv/x/shared"], "stream": None},
        "stop": {"argv": ["sh", "deploy/app", "down", "/srv/x/shared"], "stream": None},
    }
    assert plan.volumes == [] and plan.first_admin is None and plan.projects == ["site-uat"]
    body = man.to_json()
    assert body["data"] == {"app": None, "format": None, "volumes": [], "files": None, "identity_label": "identity keys",
                            "identity_help": ""}
    assert body["first_admin"] is None and body["capabilities"] == [] and body["streams"] == {}
    assert body["timeouts"] == {"build": 60, "start": 60, "stop": 15}


# --------------------------------------------------------------- bad manifests

BASE: dict[str, Any] = {
    "version": 1, "name": "Shop",
    "vars": {"SHOP_ENV": "{slipway.slug}"},
    "secrets": {"SHOP_KEY": "hex"},
    "data": {"app": "shop", "format": "pg-custom", "volumes": [{"name": "shop-{SHOP_ENV}_db", "holds": "database"}]},
    "commands": {"start": ["up"], "stop": ["down"], "data_up": ["data"], "dump": ["dump", "{slipway.out}"],
                 "restore": ["restore", "{slipway.in}"]},
}
ADMIN: dict[str, Any] = {"command": ["admin", "--email", "{admin.email}"], "fields": {"email": {"kind": "email"}},
                         "password": {"stdin": True}}


def _merge(base: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """``base`` with ``changes``: mappings merge, anything else replaces, and None removes the key."""
    out = copy.deepcopy(base)
    for key, value in changes.items():
        if value is None:
            out.pop(key, None)
        elif isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _yml(**changes: Any) -> str:
    return yaml.safe_dump(_merge(BASE, changes), sort_keys=False)


def test_the_base_of_the_bad_manifest_table_is_good():
    man = manifest.parse(_yml(first_admin=ADMIN))
    assert man.capabilities() == ("backup", "restore", "reset", "snapshot", "seed", "first_admin")


@pytest.mark.parametrize(("changes", "message"), [
    # Slots
    ({"commands": {"dump": ["dump", "--out={slipway.out}"]}},
     "commands.dump[1]: {slipway.out} must be a whole argument; write --out and {slipway.out} as two arguments, "
     "or use stdout: true"),
    ({"commands": {"restore": ["restore", "{slipway.in}.sql"]}},
     "commands.restore[1]: {slipway.in} must be a whole argument; give it an argument of its own, or use stdin: true"),
    ({"commands": {"start": ["up", "{slipway.out}"]}},
     "commands.start[1]: {slipway.out} can only be used in commands.dump and commands.export_files"),
    ({"commands": {"dump": ["dump", "{slipway.in}"]}},
     "commands.dump[1]: {slipway.in} can only be used in commands.verify_dump, commands.accepts, commands.restore "
     "and commands.import_files"),
    ({"vars": {"SHOP_FILE": "{slipway.in}"}},
     "vars.SHOP_FILE: {slipway.in} can only be used in commands.verify_dump, commands.accepts, commands.restore "
     "and commands.import_files"),
    ({"projects": ["shop-{admin.email}"]}, "projects[0]: {admin.email} can only be used in first_admin.command"),
    ({"data": {"volumes": [{"name": "{slipway.out}", "holds": "database"}]}},
     "data.volumes[0].name: {slipway.out} can only be used in commands.dump and commands.export_files"),
    ({"commands": {"dump": ["{slipway.out}"]}}, "commands.dump[0]: the program can't be a value filled at run time"),
    ({"commands": {"dump": ["dump", "{slipway.out}", "{slipway.out}"]}},
     "commands.dump: needs {slipway.out} exactly once (the file Slipway gives it to write), "
     "or write it as {run: [...], stdout: true}"),
    ({"commands": {"restore": ["restore"]}},
     "commands.restore: needs {slipway.in} exactly once (the file Slipway gives it to read), "
     "or write it as {run: [...], stdin: true}"),
    # Stream mode
    ({"commands": {"dump": {"run": ["dump", "{slipway.out}"], "stdout": True}}},
     "commands.dump: give either {slipway.out} or stdout: true, not both"),
    ({"commands": {"dump": {"run": ["dump"], "stdin": True}}},
     "commands.dump: stdin: true doesn't fit dump, which writes a file: write {run: [...], stdout: true}"),
    ({"commands": {"restore": {"run": ["restore"], "stdout": True}}},
     "commands.restore: stdout: true doesn't fit restore, which reads a file: write {run: [...], stdin: true}"),
    ({"commands": {"dump": {"run": ["dump"], "stdout": True, "shell": True}}},
     "commands.dump: unknown key shell (allowed: run, stdout)"),
    ({"commands": {"dump": {"run": ["dump"], "stdout": False}}},
     "commands.dump.stdout: must be true (or write the command as a list with {slipway.out})"),
    ({"commands": {"dump": {"run": ["dump"]}}},
     "commands.dump: give stdout: true with run, or write the command as a list with {slipway.out}"),
    ({"commands": {"start": {"run": ["up"], "stdout": True}}},
     "commands.start: must be a list: the program, then its arguments"),
    # What dump needs
    ({"data": {"format": None}},
     "commands.dump needs data.format: a label (such as pg-custom) for what dump writes and restore reads"),
    ({"data": {"app": None}},
     "commands.dump needs data.app: the app's id (such as serversherpa), which snapshots are matched on"),
    ({"data": {"volumes": [{"name": "shop-{SHOP_ENV}_logs", "holds": "other"}]}},
     "commands.dump needs commands.has_data, or a data.volumes entry that holds: database or files, "
     "so Slipway can tell an instance with data from a new one"),
    ({"data": {"app": "Shop!"}},
     "data.app: an app id is lowercase letters, digits, '.', '_' and '-', at most 64, such as serversherpa"),
    ({"data": {"format": "pg custom"}},
     "data.format: a format label is lowercase letters, digits, '.', '_', '+' and '-', at most 40, such as pg-custom"),
    # What restore needs
    ({"commands": {"dump": None}}, "commands.restore needs commands.dump: Slipway restores only what it backed up"),
    ({"commands": {"data_up": None}},
     "commands.restore needs commands.data_up: Slipway stops the app and starts only the data services before a restore"),
    ({"commands": {"stop": None}},
     "commands.restore needs commands.stop: Slipway stops the app before replacing its data"),
    # Other dependencies
    ({"commands": {"accepts": ["accepts", "{slipway.in}"]}},
     "commands.accepts needs commands.revision: it is given the revision that revision prints"),
    ({"commands": {"restore": None, "dump": None, "verify_dump": ["check", "{slipway.in}"]}},
     "commands.verify_dump needs commands.dump: it checks the file dump writes"),
    ({"commands": {"restore": None, "after_import": ["forget-sessions"]}},
     "commands.after_import needs commands.restore: it runs after another instance's data is restored"),
    ({"commands": {"restore": None, "dump": None, "seed": ["seed"]}},
     "commands.seed needs commands.dump: Slipway must be able to tell an empty start"),
    ({"commands": {"export_files": ["export", "{slipway.out}"]}, "data": {"files": {"format": "tar"}}},
     "commands.export_files and commands.import_files come together, with data.files: "
     "a snapshot taken here must be restorable here"),
    ({"commands": {"export_files": ["export", "{slipway.out}"], "import_files": ["import", "{slipway.in}"]}},
     "commands.export_files and commands.import_files come together, with data.files: "
     "a snapshot taken here must be restorable here"),
    ({"data": {"files": {"format": "tar"}}},
     "commands.export_files and commands.import_files come together, with data.files: "
     "a snapshot taken here must be restorable here"),
    # data.volumes
    ({"data": {"volumes": [{"name": "shop-{SHOP_ENV}_db", "holds": "data"}]}},
     "data.volumes[0].holds: must be one of database, files, other"),
    ({"data": {"volumes": [{"name": "shop-{SHOP_ENV}_db", "holds": "database"},
                           {"name": "shop-{SHOP_ENV}_db", "holds": "files"}]}},
     "data.volumes[1].name: shop-{SHOP_ENV}_db is listed twice"),
    ({"data": {"volumes": [{"name": "shop-{SHOP_ENV}_db"}]}},
     "data.volumes[0]: give name (the volume) and holds (database, files or other)"),
    ({"data": {"volumes": [{"name": "shop-{SHOP_ENV}_db", "holds": "database", "size": 1}]}},
     "data.volumes[0]: unknown key size (allowed: name, holds)"),
    # first_admin
    ({"first_admin": {**ADMIN, "fields": {"email": {"kind": "email"}, "name": {}}}},
     "first_admin.fields.name: isn't used: put {admin.name} in first_admin.command"),
    ({"first_admin": {**ADMIN, "command": ["admin", "--email", "{admin.email}", "{admin.x}"]}},
     "first_admin.command[3]: {admin.x} is not one of the fields (email)"),
    ({"first_admin": {**ADMIN, "command": ["admin", "--email={admin.email}"]}},
     "first_admin.command[1]: {admin.email} must be a whole argument; write --email and {admin.email} as two arguments"),
    ({"first_admin": {**ADMIN, "command": ["admin", "{admin.email}", "{slipway.out}"]}},
     "first_admin.command[2]: {slipway.out} can only be used in commands.dump and commands.export_files"),
    ({"first_admin": {**ADMIN, "password": {"stdin": True, "args": ["--for", "{admin.email}"]}}},
     "first_admin.password.args[1]: {admin.email} can only be used in first_admin.command"),
    ({"first_admin": {**ADMIN, "fields": {}}},
     "first_admin.fields: give 1 to 8 fields: what Slipway asks for the first admin"),
    ({"first_admin": {**ADMIN, "fields": {"Email": {}}}},
     "first_admin.fields.Email: a field name is a lowercase letter, then lowercase letters, digits and '_', at most 31"),
    ({"first_admin": {**ADMIN, "password": {"stdin": True, "env": "ADMIN_PASSWORD"}}},
     "first_admin.password: give either stdin: true or env: VAR, not both"),
    ({"first_admin": {**ADMIN, "password": {}}},
     "first_admin.password: give stdin: true (the password as one line on the command's stdin) "
     "or env: VAR (Slipway puts it in $VAR)"),
    ({"first_admin": {**ADMIN, "password": {"env": "PATH"}}},
     "first_admin.password.env: PATH can't carry the password (the shell or loader reads it)"),
    ({"first_admin": {**ADMIN, "password": {"env": "LD_PRELOAD"}}},
     "first_admin.password.env: LD_PRELOAD can't carry the password (the shell or loader reads it)"),
    ({"first_admin": {**ADMIN, "password": {"env": "SHOP_KEY"}}},
     "first_admin.password.env: SHOP_KEY is already set by secrets.SHOP_KEY; give the password a variable of its own"),
    ({"first_admin": {**ADMIN, "password": {"env": "SHOP_ENV"}}},
     "first_admin.password.env: SHOP_ENV is already set by vars.SHOP_ENV; give the password a variable of its own"),
    ({"first_admin": {**ADMIN, "password": {"env": "admin_pw"}}},
     "first_admin.password.env: admin_pw must be uppercase letters, digits and '_', starting with a letter"),
    ({"first_admin": {**ADMIN, "password": None}},
     "first_admin: give password, invite or both: how the first admin signs in for the first time"),
    ({"first_admin": {**ADMIN, "password": {"stdin": True, "min_length": 4}}},
     "first_admin.password.min_length: must be a whole number from 8 to 128"),
    ({"first_admin": {**ADMIN, "done_codes": [0, 10], "exists_codes": [10]}},
     "first_admin: exit code 10 is in both done_codes and exists_codes"),
    ({"first_admin": {**ADMIN, "done_codes": [0, 1], "messages": {1: "Done already"}}},
     "first_admin.messages.1: 1 is a done code; messages are for the codes that fail"),
    ({"first_admin": {**ADMIN, "exists_codes": [10], "messages": {10: "It exists"}}},
     "first_admin.messages.10: 10 is an exists code; messages are for the codes that fail"),
    ({"first_admin": {**ADMIN, "messages": {256: "Too big"}}},
     "first_admin.messages: 256 is not an exit code from 1 to 255"),
    ({"first_admin": {**ADMIN, "done_codes": [0, 300]}}, "first_admin.done_codes[1]: must be an exit code, 0-255"),
    ({"first_admin": {**ADMIN, "done_codes": list(range(15)), "exists_codes": list(range(15, 21))}},
     "first_admin: done_codes and exists_codes hold at most 20 codes in all"),
    ({"first_admin": {**ADMIN, "command": None}},
     "first_admin: give command: the program that creates the first admin, then its arguments"),
    # Secrets
    ({"secrets": {"SHOP_KEY": {"kind": "hex", "identity": "yes"}}}, "secrets.SHOP_KEY.identity: must be true or false"),
    ({"secrets": {f"KEY_{i}": {"kind": "hex", "identity": True} for i in range(17)}},
     "secrets: at most 16 can be identity secrets"),
    # Timeouts
    ({"timeouts": {"verify_dump": 10}}, "timeouts.verify_dump: slipway.yml declares no commands.verify_dump"),
    ({"timeouts": {"first_admin": 10}}, "timeouts.first_admin: slipway.yml declares no first_admin"),
    ({"timeouts": {"dump": 0}}, "timeouts.dump: must be a whole number of minutes from 1 to 1440 (a day)"),
    ({"timeouts": {"dump": 1441}}, "timeouts.dump: must be a whole number of minutes from 1 to 1440 (a day)"),
    ({"timeouts": {"backup": 5}},
     "timeouts.backup: is not a command (allowed: build, start, stop, has_data, data_up, dump, verify_dump, revision, "
     "accepts, restore, export_files, import_files, after_import, seed, first_admin)"),
    # The top level
    ({"migrations": "expand_contract"}, "the file: unknown key migrations"),
])
def test_bad_data_manifests_say_exactly_what_is_wrong(changes, message):
    with pytest.raises(manifest.ManifestError) as caught:
        manifest.parse(_yml(**changes))
    if message.startswith("the file: unknown key"):
        assert str(caught.value).startswith(f"slipway.yml: {message} ")
    else:
        assert str(caught.value) == f"slipway.yml: {message}"


def test_sixteen_identity_secrets_are_allowed():
    man = manifest.parse(_yml(secrets={f"KEY_{i}": {"kind": "hex", "identity": True} for i in range(16)}))
    assert len(man.identity_keys()) == 16


def test_a_first_admin_with_only_an_invite_and_the_defaults():
    man = manifest.parse(_yml(first_admin={**ADMIN, "password": None, "invite": {"args": ["--invite"]}}))
    fa = man.first_admin
    assert fa is not None and fa.password is None and fa.invite == manifest.AdminInvite(
        "Email them a link to set their password", ("--invite",))
    assert fa.done_codes == (0,) and fa.exists_codes == () and fa.messages == {}
    assert fa.fields == (manifest.AdminField(name="email", label="Email", kind="email", help="", max=254),)
    assert manifest.parse(_yml(first_admin={**ADMIN, "fields": {"email": {}, "first_name": {}},
                                            "command": ["a", "{admin.email}", "{admin.first_name}"]})
                          ).first_admin.fields[1] == manifest.AdminField(name="first_name", label="First name")


# ----------------------------------------------------------------- plan and json


def test_slots_stay_objects_and_template_text_is_rendered():
    yml = _yml(commands={"dump": ["dump", "--to", "{slipway.out}", "--host", "{slipway.host}", "{{slipway.out}}"]},
               first_admin={**ADMIN, "password": {"stdin": True, "args": ["--env", "{slipway.env_dir}"]}})
    plan = _plan(manifest.parse(yml))
    # An escaped brace is text, never a slot.
    assert plan.commands["dump"]["argv"] == ["dump", "--to", {"slot": "out"}, "--host", "10.0.0.1", "{slipway.out}"]
    assert plan.first_admin == {"argv": ["admin", "--email", {"slot": "admin.email"}], "stream": None,
                                "password_args": ["--env", "/srv/x/shared"], "invite_args": []}
    assert manifest.whole_slot("{slipway.out}") == "out" and manifest.whole_slot("{admin.email}") == "admin.email"
    assert manifest.whole_slot("{{slipway.out}}") is None and manifest.whole_slot("{slipway.slug}") is None
    assert json.loads(json.dumps(plan.commands)) == plan.commands  # app_state stores it as JSON


def test_operator_input_has_no_way_into_a_rendered_command():
    # What an operator types fills a slot only when the deployer runs the command; plan() never sees it,
    # so a value like this can't change what the command is.
    plan = _plan(manifest.parse(_yml(first_admin=ADMIN)))
    assert plan.first_admin is not None and plan.first_admin["argv"][2] == {"slot": "admin.email"}
    with pytest.raises(manifest.ManifestError, match="must be a whole argument"):
        manifest.parse(_yml(first_admin={**ADMIN, "command": ["sh", "-c", "admin {admin.email}"]}))


def test_volume_names_are_rendered_and_checked():
    yml = _yml(settings={"SHOP_DB": {"label": "Database volume", "default": "shop_db"}},
               data={"volumes": [{"name": "{SHOP_DB}", "holds": "database"},
                                 {"name": "shop-{SHOP_ENV}_files", "holds": "files"}]})
    man = manifest.parse(yml)
    assert [v["name"] for v in _plan(man).volumes] == ["shop_db", "shop-uat_files"]
    with pytest.raises(manifest.ManifestError, match=re.escape("data.volumes[0].name: '../db' is not a Docker volume name")):
        _plan(man, settings={"SHOP_DB": "../db"})
    with pytest.raises(manifest.ManifestError, match=re.escape("data.volumes[1].name: 'shop-uat_files' is listed twice")):
        _plan(man, settings={"SHOP_DB": "shop-uat_files"})
    # A secret can't name a volume: the names are stored and logged.
    with pytest.raises(manifest.ManifestError, match="is a secret"):
        _plan(manifest.parse(_yml(data={"volumes": [{"name": "v-{SHOP_KEY}", "holds": "database"}]})))


def test_the_first_admin_program_is_checked_like_the_others():
    with pytest.raises(manifest.ManifestError, match=re.escape("first_admin.command[0]: '../bin/admin' is not a safe path")):
        _plan(manifest.parse(_yml(first_admin={**ADMIN, "command": ["../bin/admin", "{admin.email}"]})))


def test_to_json_and_capabilities_round_trip():
    for text in (EXAMPLE, DJANGO, MYSQL, NO_DATA):
        man = manifest.parse(text)
        body = man.to_json()
        assert json.loads(json.dumps(body)) == body
        assert body["capabilities"] == list(man.capabilities())
        assert [s["identity"] for s in body["secrets"]] == [s.identity for s in man.secrets]
    body = manifest.parse(EXAMPLE).to_json()
    assert body["data"]["files"] == {"format": "serversherpa-objects-v1", "label": "Uploaded files"}
    assert body["data"]["volumes"][0] == {"name": "ss-{STACK_ENV}-db_pgdata", "holds": "database"}
    assert body["timeouts"]["restore"] == 120 and body["timeouts"]["dump"] == 120 and body["timeouts"]["first_admin"] == 10
    assert body["first_admin"]["password"] == {"min_length": 8, "mode": "stdin"}
    assert body["first_admin"]["invite"] == {"label": "Email them a link to set their password"}
    assert body["first_admin"]["messages"]["2"].startswith("ServerSherpa refused")  # JSON keys are text
    assert "command" not in body["first_admin"]  # the page needs the fields, not the argv
    django = manifest.parse(DJANGO).to_json()
    assert django["first_admin"]["password"] == {"min_length": 10, "mode": "env"} and django["first_admin"]["invite"] is None
    assert django["streams"] == {"dump": "stdout", "verify_dump": "stdin", "restore": "stdin"}


@pytest.mark.parametrize(("commands", "volumes", "expected"), [
    ({"dump": ["d", "{slipway.out}"], "has_data": ["h"]}, [], ("backup", "snapshot")),
    ({"dump": ["d", "{slipway.out}"], "has_data": ["h"], "restore": ["r", "{slipway.in}"], "data_up": ["u"],
      "stop": ["s"]}, [], ("backup", "restore", "snapshot", "seed")),  # no volumes: nothing for reset to delete
    ({"dump": ["d", "{slipway.out}"], "has_data": ["h"], "revision": ["v"]}, [], ("backup", "snapshot")),
    ({"dump": ["d", "{slipway.out}"], "has_data": ["h"], "revision": ["v"], "accepts": ["a", "{slipway.in}"],
      "seed": ["s"]}, [], ("backup", "revision_check", "snapshot", "starter_content")),
])
def test_capabilities_follow_the_commands(commands, volumes, expected):
    text = yaml.safe_dump({"version": 1, "name": "x", "data": {"app": "x", "format": "f", "volumes": volumes},
                           "commands": {"start": ["up"], **commands}})
    assert manifest.parse(text).capabilities() == expected


def test_timeouts_default_per_command():
    man = manifest.parse(_yml(timeouts={"dump": 5}))
    assert man.timeout("dump") == 300 and man.timeout("restore") == 240 * 60 and man.timeout("start") == 3600
    assert set(manifest.DEFAULT_TIMEOUTS) == {*manifest.COMMANDS, "first_admin"}


def test_stored_commands_are_read_in_either_form():
    assert manifest.command_argv(["sh", "deploy/app", "down"]) == ["sh", "deploy/app", "down"]  # before phase 2
    assert manifest.command_argv({"argv": ["sh", "deploy/app", "down"], "stream": None}) == ["sh", "deploy/app", "down"]
    assert manifest.command_argv(None) is None and manifest.command_argv({}) is None and manifest.command_argv([]) is None
