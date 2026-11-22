"""slipway.yml's DigitalOcean keys (phase 4, spec §5): edge and data.managed, what is refused and why, the slot role
on managed data behind a load balancer, and the capabilities they give (tests 25-29 of §20.2)."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from slipway.services import do_rules, manifest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = (ROOT / "docs/examples/serversherpa.slipway.yml").read_text()
SHA = "0123456789abcdef0123456789abcdef01234567"
BUILTINS = dict(slug="uat-blue", name="UAT blue", release="/srv/x/releases/r1", env_dir="/srv/x/shared", sha=SHA,
                sha12=SHA[:12], host="10.0.0.11", deployment="0123abcd", environment="uat", slot="blue")
PROD = {**BUILTINS, "slug": "prod-blue", "name": "prod blue", "host": "203.0.113.10", "environment": "prod"}

# Enough of BaseCampV3's deploy/stack/env.example for the plans below.
ENV_EXAMPLE = """\
# ServerSherpa stack
STACK_ENV=CHANGEME
STACK_DOMAIN=CHANGEME
SS_SPACES_BUCKET=serversherpa
SS_JWT_SECRET=CHANGEME
SS_PASSWORD_PEPPER=CHANGEME
SS_DATABASE_CA_B64=
"""
SECRETS = {
    "POSTGRES_PASSWORD": "pg-" + "1" * 61, "SPACES_SECRET_KEY": "sp-" + "2" * 61, "SS_JWT_SECRET": "jwt-" + "3" * 60,
    "SS_TOTP_ENCRYPTION_KEY": "totp-key-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "SS_PASSWORD_PEPPER": "pepper-" + "4" * 57,
    "SS_WIKI_SERVICE_TOKEN": "wiki-" + "5" * 59,
}
# What a LAN data server provides (P3), for the byte compare.
LAN_VALUES = {
    "db": {"host": "10.0.0.13", "port": "5432", "database": "serversherpa", "user": "serversherpa",
           "password": SECRETS["POSTGRES_PASSWORD"], "tls": "disable", "ca_b64": ""},
    "objects": {"endpoint": "https://spaces.uat.example.com", "region": "us-east-1", "bucket": "serversherpa",
                "access_key": "serversherpa", "secret_key": SECRETS["SPACES_SECRET_KEY"], "path_style": "true"},
}
# What DigitalOcean gives environment prod in nyc3 (§5.4): the cluster's private connection and the bucket's key.
DB_HOST = "private-slipway-prod-db-do-user-1-0.b.db.ondigitalocean.com"
SPACES_SECRET = "spaces-" + "9" * 36
MANAGED_VALUES = {
    "db": {"host": DB_HOST, "port": "25060", "database": "serversherpa", "user": "serversherpa",
           "password": SECRETS["POSTGRES_PASSWORD"], "tls": "require", "ca_b64": "LS0tLS1CRUdJTiBDRVJU"},
    "objects": {"endpoint": "https://nyc3.digitaloceanspaces.com", "region": "nyc3", "bucket": "slipway-prod-1a2b3c4d",
                "access_key": "DO00ABCDEFGHIJKLMNOP", "secret_key": SPACES_SECRET, "path_style": "false"},
}
EDGE_VALUES = {"address": "203.0.113.50", "trusted": "10.116.0.0/20"}


def _dump(man_module: Any, plan: manifest.AppPlan) -> str:
    """A plan as canonical JSON, its rendered .env included: what the byte compare compares."""
    out = dataclasses.asdict(plan)
    out["secret_values"] = sorted(out["secret_values"])
    lines, _ = man_module.parse_env_template(ENV_EXAMPLE)
    out["env_text"] = man_module.render_env(lines, plan.env, plan.written)
    return json.dumps(out, sort_keys=True)


def _env_text(plan: manifest.AppPlan) -> str:
    lines, _ = manifest.parse_env_template(ENV_EXAMPLE)
    return manifest.render_env(lines, plan.env, plan.written)


def _managed_plan(man: manifest.Manifest, **kw: Any) -> manifest.AppPlan:
    args: dict[str, Any] = dict(template=ENV_EXAMPLE, builtins=PROD, settings={"STACK_DOMAIN": "serversherpa.com"},
                                chosen=["kiosk", "wiki", "learn", "status"], host_ports={}, secrets=SECRETS, env={},
                                role="slot", data_values=MANAGED_VALUES, managed=True, edge_values=EDGE_VALUES)
    args.update(kw)
    return manifest.plan(man, **args)


# ------------------------------------------------------- test 25: ServerSherpa on managed data


def test_serversherpa_plans_the_slot_role_with_managed_values_and_the_edge():
    man = manifest.parse(EXAMPLE)
    plan = _managed_plan(man)
    env = plan.env
    # §5.4's keys: data.attach.env with DigitalOcean's values, data.managed.env, then edge.env.
    assert {k: env[k] for k in ("STACK_EXTERNAL_DATA", "STACK_DB_HOST", "STACK_DB_PORT", "STACK_DB_SSLMODE",
                                "SS_DATABASE_SSL", "SS_DATABASE_CA_B64", "SS_SPACES_ENDPOINT", "SS_SPACES_BUCKET",
                                "SS_SPACES_ACCESS_KEY", "SS_SPACES_USE_PATH_STYLE")} == {
        "STACK_EXTERNAL_DATA": "1", "STACK_DB_HOST": DB_HOST, "STACK_DB_PORT": "25060", "STACK_DB_SSLMODE": "require",
        "SS_DATABASE_SSL": "require", "SS_DATABASE_CA_B64": "LS0tLS1CRUdJTiBDRVJU",
        "SS_SPACES_ENDPOINT": "https://nyc3.digitaloceanspaces.com", "SS_SPACES_BUCKET": "slipway-prod-1a2b3c4d",
        "SS_SPACES_ACCESS_KEY": "DO00ABCDEFGHIJKLMNOP", "SS_SPACES_USE_PATH_STYLE": "false"}
    assert env["SS_DATABASE_URL"] == (f"postgresql+asyncpg://serversherpa:{SECRETS['POSTGRES_PASSWORD']}@{DB_HOST}:25060/"
                                      "serversherpa")
    assert {k: env[k] for k in ("STACK_CADDY", "STACK_NETWORK_SUBNET", "STACK_PROXY_IP", "STACK_BIND_IP",
                                "STACK_HOSTS_IP", "STACK_TRUSTED_PROXIES")} == {
        "STACK_CADDY": "1", "STACK_NETWORK_SUBNET": "172.30.0.0/24", "STACK_PROXY_IP": "172.30.0.2",
        "STACK_BIND_IP": "127.0.0.1", "STACK_HOSTS_IP": "203.0.113.50", "STACK_TRUSTED_PROXIES": "10.116.0.0/20"}
    assert all(env[s] == SECRETS[s] for s in SECRETS)  # every secret
    # Hidden: the URL with the password in it and the bucket's secret key, never in what templates or logs see.
    assert {"SS_DATABASE_URL", "SS_SPACES_SECRET_KEY"} <= set(plan.written)
    assert env["SS_DATABASE_URL"] in plan.secret_values and SPACES_SECRET in plan.secret_values
    assert "SS_DATABASE_URL" not in plan.public_env and "SS_SPACES_SECRET_KEY" not in plan.public_env
    assert plan.public_env["SS_SPACES_BUCKET"] == "slipway-prod-1a2b3c4d" and plan.public_env["STACK_PROXY_IP"] == "172.30.0.2"
    # No spaces route or port; the routes are every hostname but spaces.
    assert "spaces" not in [s.name for s in plan.services] and "STACK_SPACES_PORT" not in plan.written
    assert [r["service"] for r in plan.routes] == ["api", "portal", "kiosk", "wiki", "learn", "status"]
    assert all(r["hostname"].endswith(".serversherpa.com") for r in plan.routes)
    # The proxy project added; only the holds: other volume (the database and files are managed).
    assert plan.projects == ["ss-prod-blue-db", "ss-prod-blue-storage", "ss-prod-blue-api", "ss-prod-blue-web",
                             "ss-prod-blue-status", "ss-prod-blue-proxy"]
    assert plan.volumes == [{"name": "ss-prod-blue-status_status-data", "holds": "other"}]
    # has_data takes data.managed.commands; data_up and the rest stay as declared.
    assert plan.commands["has_data"] == {"argv": ["deploy/stack/ss-stack", "has-data", "/srv/x/shared", "--external"],
                                         "stream": None}
    assert plan.commands["data_up"] == {"argv": ["deploy/stack/ss-stack", "data", "/srv/x/shared"], "stream": None}
    # No SS_CERT_* key (D2).
    assert not [k for k in plan.written if k.startswith("SS_CERT_")]
    # The order in the .env: data.attach.env, then data.managed.env, then edge.env, then the secrets.
    order = plan.written
    assert order.index("SS_SPACES_USE_PATH_STYLE") < order.index("SS_SPACES_BUCKET") < order.index("STACK_CADDY") \
        < order.index("POSTGRES_PASSWORD")
    text = _env_text(plan)
    assert "SS_SPACES_BUCKET=slipway-prod-1a2b3c4d\n" in text and "SS_SPACES_BUCKET=serversherpa" not in text
    assert plan.identity == {"SS_TOTP_ENCRYPTION_KEY": SECRETS["SS_TOTP_ENCRYPTION_KEY"],
                             "SS_PASSWORD_PEPPER": SECRETS["SS_PASSWORD_PEPPER"]}


# Phase 3's slot, app and server roles, recorded from the phase 3 manifest.py and the phase 3 example (before the
# edge and data.managed blocks): every AppPlan field and the rendered .env, as canonical JSON.
P3_SHA256 = {
    "slot": "516528b239312302ad2011995c40b33ef34c7979dab46ef9c5c4457c0f34a241",
    "app": "6d1031bf9a36c7d17ee6871f08f40e9a7bce75eda1ac8620da0827a334c839bf",
    "server": "1d8e631c558c4f3625ab9c8272800157e68a863dfced9263fc26660636262215",
}
P3_SLOT_ENV = (
    "# ServerSherpa stack\nSTACK_ENV=uat-blue\nSTACK_DOMAIN=uat.example.com\nSS_SPACES_BUCKET=serversherpa\n"
    "SS_JWT_SECRET=jwt-333333333333333333333333333333333333333333333333333333333333\n"
    "SS_PASSWORD_PEPPER=pepper-444444444444444444444444444444444444444444444444444444444\nSS_DATABASE_CA_B64=\n\n"
    "# Set by Slipway\nSTACK_PROXY_IP=10.0.0.2\nSS_LOG_LEVEL=INFO\nSTACK_API_PORT=18000\nSTACK_PORTAL_PORT=8091\n"
    "STACK_WIKI_PORT=8096\nSTACK_APPS=wiki\nSTACK_REPO_DIR=/srv/x/releases/r1\nSTACK_IMAGE_TAG=0123456789ab\n"
    "STACK_EXTERNAL_DATA=1\nSTACK_DB_HOST=10.0.0.13\nSTACK_DB_PORT=5432\nSTACK_DB_NAME=serversherpa\n"
    "STACK_DB_USER=serversherpa\nSTACK_DB_SSLMODE=disable\n"
    "SS_DATABASE_URL=postgresql+asyncpg://serversherpa:pg-1111111111111111111111111111111111111111111111111111111111111"
    "@10.0.0.13:5432/serversherpa\nSS_DATABASE_SSL=disable\nSS_SPACES_ENDPOINT=https://spaces.uat.example.com\n"
    "SS_SPACES_REGION=us-east-1\nSS_SPACES_ACCESS_KEY=serversherpa\n"
    "SS_SPACES_SECRET_KEY=sp-2222222222222222222222222222222222222222222222222222222222222\nSS_SPACES_USE_PATH_STYLE=true\n"
    "POSTGRES_PASSWORD=pg-1111111111111111111111111111111111111111111111111111111111111\n"
    "SPACES_SECRET_KEY=sp-2222222222222222222222222222222222222222222222222222222222222\n"
    "SS_TOTP_ENCRYPTION_KEY=totp-key-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
    "SS_WIKI_SERVICE_TOKEN=wiki-55555555555555555555555555555555555555555555555555555555555\n"
)


def _p3_plans(man: manifest.Manifest, **slot_kw: Any) -> dict[str, manifest.AppPlan]:
    settings = {"STACK_DOMAIN": "uat.example.com", "STACK_PROXY_IP": "10.0.0.2"}
    base: dict[str, Any] = dict(template=ENV_EXAMPLE, builtins=BUILTINS, settings=settings, secrets=SECRETS, env={})
    return {
        "slot": manifest.plan(man, chosen=["wiki"], host_ports={"api": 18000}, role="slot", data_values=LAN_VALUES,
                              **base, **slot_kw),
        "app": manifest.plan(man, chosen=None, host_ports={}, **base),
        "server": manifest.plan(man, chosen=None, host_ports={}, role="server",
                                server_values={"host": "10.0.0.13", "clients": ["10.0.0.11", "10.0.0.12"]}, **base),
    }


@pytest.mark.parametrize("slot_kw", [{}, {"managed": False, "edge_values": None, "without": None}])
def test_without_managed_and_edge_values_every_role_renders_byte_for_byte_as_phase_3(slot_kw):
    plans = _p3_plans(manifest.parse(EXAMPLE), **slot_kw)
    assert _env_text(plans["slot"]) == P3_SLOT_ENV
    for role, plan in plans.items():
        assert hashlib.sha256(_dump(manifest, plan).encode()).hexdigest() == P3_SHA256[role], role


def test_an_explicit_without_replaces_the_data_servers_services():
    man = manifest.parse(EXAMPLE)
    plan = _p3_plans(man, without={"spaces", "portal"})["slot"]
    assert [s.name for s in plan.services] == ["api", "wiki"] and "STACK_PORTAL_PORT" not in plan.written
    assert [s.name for s in man.services_for("slot", None, without=set())][:3] == ["api", "portal", "spaces"]
    assert [s.name for s in man.services_for("app", None, without={"api"})][0] == "api"  # only the slot role


# ------------------------------------------------------------- test 26: the bad-manifest table

BASE: dict[str, Any] = {
    "version": 1, "name": "Shop",
    "settings": {"SHOP_DOMAIN": {"required": True}, "PROXY_IP": {"label": "Proxy address", "required": True}},
    "vars": {"SHOP_ENV": "{slipway.slug}", "SHOP_MODE": "lan"},
    "secrets": {"DB_PASSWORD": "hex", "S3_SECRET": "hex"},
    "services": {
        "web": {"port": 8000, "port_var": "WEB_PORT", "hostname": "shop.{SHOP_DOMAIN}", "health": "/healthz"},
        "files": {"port": 9000, "port_var": "FILES_PORT", "hostname": "files.{SHOP_DOMAIN}"},
        "mailpit": {"port": 8025, "port_var": "MAIL_PORT", "optional": True},
    },
    "optional_services": {"var": "SHOP_APPS", "none": "none"},
    "projects": ["shop-{SHOP_ENV}", "shop-{SHOP_ENV}-db"],
    "edge": {
        "port": 80, "health": "/healthz",
        "env": {"PROXY_IP": "172.30.0.2", "SHOP_HOSTS_IP": "{edge.address}", "SHOP_TRUSTED": "{edge.trusted}",
                "SHOP_MODE": "lb-{slipway.slot}"},
        "projects": ["shop-{SHOP_ENV}-proxy"],
    },
    "data": {
        "app": "shop", "format": "pg-custom", "migrations": "expand_contract",
        "volumes": [{"name": "shop-{SHOP_ENV}-db_pg", "holds": "database"},
                    {"name": "shop-{SHOP_ENV}_files", "holds": "files"},
                    {"name": "shop-{SHOP_ENV}_cache", "holds": "other"}],
        "attach": {
            "needs": {"db": "postgres", "objects": "s3"},
            "env": {"DB_HOST": "{data.db.host}", "S3_URL": "{data.objects.endpoint}",
                    "DATABASE_URL": "postgres://{data.db.user}:{data.db.password}@{data.db.host}:{data.db.port}/"
                                    "{data.db.database}?sslmode={data.db.tls}",
                    "S3_KEY": "{data.objects.secret_key}"},
        },
        "managed": {
            "skip": ["files"],
            "db": {"version": "16", "database": "shop", "user": "shop", "password": "{secret.DB_PASSWORD}"},
            "objects": {"cors": ["web"]},
            "env": {"S3_BUCKET": "{data.objects.bucket}", "DB_CA": "{data.db.ca_b64}", "S3_ID": "{data.objects.access_key}"},
            "commands": {"has_data": ["data", "has", "--external"]},
        },
    },
    "commands": {"start": ["up"], "stop": ["down"], "has_data": ["data", "has"], "data_up": ["data"],
                 "dump": ["dump", "{slipway.out}"], "restore": ["restore", "{slipway.in}"]},
}


def _yml(*changes: tuple[str, Any]) -> str:
    """BASE with each (dotted path, value) set; a value of None removes the key."""
    raw = copy.deepcopy(BASE)
    for path, value in changes:
        *parents, last = path.split(".")
        node = raw
        for key in parents:
            node = node[key]
        if value is None:
            node.pop(last, None)
        else:
            node[last] = value
    return yaml.safe_dump(raw, sort_keys=False)


SHOP_VALUES = {
    "db": {"host": "private-db", "port": "25060", "database": "shop", "user": "shop", "password": "pw" * 16,
           "tls": "require", "ca_b64": "Q0E="},
    "objects": {"endpoint": "https://nyc3.digitaloceanspaces.com", "region": "nyc3", "bucket": "slipway-shop-1a2b3c4d",
                "access_key": "DO00KEY", "secret_key": "s3-secret", "path_style": "false"},
}
SHOP_SECRETS = {"DB_PASSWORD": "pw" * 16, "S3_SECRET": "s3"}


def _shop_plan(man: manifest.Manifest, **kw: Any) -> manifest.AppPlan:
    args: dict[str, Any] = dict(template=None, builtins={**PROD, "slug": "shop-blue"}, settings={"SHOP_DOMAIN": "shop.example.com"},
                                chosen=None, host_ports={}, secrets=SHOP_SECRETS, env={}, role="slot",
                                data_values=SHOP_VALUES, managed=True, edge_values=EDGE_VALUES)
    args.update(kw)
    return manifest.plan(man, **args)


def test_the_base_of_the_bad_manifest_table_is_good_and_plans():
    man = manifest.parse(_yml())
    plan = _shop_plan(man)
    assert plan.env["PROXY_IP"] == "172.30.0.2" and plan.env["SHOP_HOSTS_IP"] == "203.0.113.50"
    assert plan.env["SHOP_MODE"] == "lb-blue"  # a var named in edge.env takes the edge's value behind it
    assert plan.env["S3_BUCKET"] == "slipway-shop-1a2b3c4d" and plan.env["DB_CA"] == "Q0E="
    assert [s.name for s in plan.services] == ["web", "mailpit"]  # files skipped (data.managed.skip)
    assert plan.projects == ["shop-shop-blue", "shop-shop-blue-db", "shop-shop-blue-proxy"]
    assert plan.volumes == [{"name": "shop-shop-blue_cache", "holds": "other"}]
    assert plan.commands["has_data"]["argv"] == ["data", "has", "--external"]
    assert man.data.managed is not None and man.data.managed.password_secret("db") == "DB_PASSWORD"


@pytest.mark.parametrize(("changes", "message"), [
    # rule 1
    ([("edge.bogus", 1)], "edge: unknown key bogus (allowed: port, health, env, projects)"),
    ([("data.managed.db.host", "x")], "data.managed.db: unknown key host (allowed: version, database, user, password)"),
    ([("data.managed.objects.bucket", "x")], "data.managed.objects: unknown key bucket (allowed: cors)"),
    # rule 2
    ([("edge.port", 8000)], "edge.port: 8000 is the web service's port"),
    ([("edge.port", 0)], "edge.port: must be a port number, 1-65535"),
    ([("edge.port", None)], "edge: give port (the host port each app slot serves plain HTTP on) and health "
                            "(the path the load balancer asks for)"),
    ([("edge.health", None)], "edge: give port (the host port each app slot serves plain HTTP on) and health "
                              "(the path the load balancer asks for)"),
    ([("edge.health", "healthz")], "edge.health: 'healthz' is not a path such as /healthz"),
    # rule 3
    ([("edge.env", {"DB_PASSWORD": "x"})], "edge.env.DB_PASSWORD: is a secret; Slipway generates it"),
    ([("edge.env", {"WEB_PORT": "80"})], "edge.env.WEB_PORT: is a port variable; Slipway sets it"),
    ([("edge.env", {"SHOP_APPS": "x"})], "edge.env.SHOP_APPS: is optional_services.var; Slipway sets it"),
    ([("edge.env", {"DB_HOST": "x"})], "edge.env.DB_HOST: is already set by data.attach.env"),
    ([("edge.env", {"S3_BUCKET": "x"})], "edge.env.S3_BUCKET: is already set by data.managed.env"),
    ([("edge.env", {})], "edge.env: give 1 to 30 keys"),
    ([("edge.env", {f"K{i}": "x" for i in range(31)})], "edge.env: give 1 to 30 keys"),
    ([("edge.env", {"X": "{secret.DB_PASSWORD}"})],
     "edge.env.X: {secret.DB_PASSWORD} can't be used here: edge.env may use {edge.address}, {edge.trusted}, settings and vars"),
    ([("edge.env", {"X": "{data.db.host}"})],
     "edge.env.X: {data.db.host} can't be used here: edge.env may use {edge.address}, {edge.trusted}, settings and vars"),
    ([("edge.env", {"X": "{server.host}"})],
     "edge.env.X: {server.host} can't be used here: edge.env may use {edge.address}, {edge.trusted}, settings and vars"),
    ([("edge.env", {"X": "{edge.port}"})], "edge.env.X: {edge.port} is not one of edge.address, edge.trusted"),
    ([("edge.env", {"X": "{slipway.out}"})], "edge.env.X: {slipway.out} can only be used in commands.dump and commands.export_files"),
    ([("vars.LB", "{edge.address}")], "vars.LB: {edge.address} can only be used in edge.env"),
    ([("data.attach.env.LB", "{edge.trusted}")], "data.attach.env.LB: {edge.trusted} can only be used in edge.env"),
    # rule 4
    ([("edge.projects", ["shop-{SHOP_ENV}"])], "edge.projects[0]: 'shop-{SHOP_ENV}' is already one of projects"),
    ([("edge.projects", ["a", "a"])], "edge.projects: 'a' is listed twice"),
    ([("edge.projects", ["a", "b", "c", "d", "e"])], "edge.projects: must be a list of at most 4"),
    ([("edge.projects", ["{secret.DB_PASSWORD}"])],
     "edge.projects[0]: {secret.DB_PASSWORD} can only be used in data.attach.env and data.server.provides"),
    # rule 5
    ([("data.attach", None)], "data.managed needs data.attach: the app slots must be told where the data is"),
    ([("data.managed.objects", None)], "data.managed: needs an entry for objects (data.attach.needs lists it)"),
    ([("data.managed.files", {})], "data.managed.files: isn't one of data.attach.needs (db, objects)"),
    ([("data.attach.needs", {"db": "postgres", "env": "s3"}), ("data.attach.env", {"DB_HOST": "{data.db.host}"})],
     "data.attach.needs.env: skip, env and commands are data.managed's own keys, so they can't be endpoint names"),
    # rule 6
    ([("data.managed.db.version", None)], "data.managed.db: needs version (postgres entries have version, database, user, password)"),
    ([("data.managed.db.password", None)], "data.managed.db: needs password (postgres entries have version, database, user, password)"),
    ([("data.managed.db.version", "12")], "data.managed.db.version: '12' isn't a version DigitalOcean offers here (13-17)"),
    ([("data.managed.db.version", "18")], "data.managed.db.version: '18' isn't a version DigitalOcean offers here (13-17)"),
    ([("data.managed.db.version", 16)], 'data.managed.db.version: must be text: put numbers, versions and octal values in quotes'),
    ([("data.managed.db.password", "hunter2")], 'data.managed.db.password: must be one secret, such as "{secret.POSTGRES_PASSWORD}"'),
    ([("data.managed.db.password", "{secret.DB_PASSWORD}x")],
     'data.managed.db.password: must be one secret, such as "{secret.POSTGRES_PASSWORD}"'),
    ([("data.managed.db.password", "{secret.NOPE}")], "data.managed.db.password: {secret.NOPE} isn't one of secrets"),
    ([("data.managed.db.user", "Shop")], "data.managed.db.user: 'Shop' isn't a PostgreSQL name: a lowercase letter or '_', "
                                         "then lowercase letters, digits and '_', at most 63"),
    ([("data.managed.db.database", "9shop")], "data.managed.db.database: '9shop' isn't a PostgreSQL name"),
    ([("data.managed.db.user", "a" * 64)], "data.managed.db.user: must be one line of at most 63 characters"),
    # the reserved names (later-F4 item 2): what do_rules.setup_sql and reset_sql would refuse later
    ([("data.managed.db.user", "doadmin")], "data.managed.db.user: 'doadmin' is reserved by PostgreSQL or DigitalOcean"),
    ([("data.managed.db.user", "postgres")], "data.managed.db.user: 'postgres' is reserved by PostgreSQL or DigitalOcean"),
    ([("data.managed.db.user", "pg_shop")], "data.managed.db.user: 'pg_shop' is reserved by PostgreSQL or DigitalOcean"),
    ([("data.managed.db.database", "defaultdb")],
     "data.managed.db.database: 'defaultdb' is reserved by PostgreSQL or DigitalOcean"),
    ([("data.managed.db.database", "template1")],
     "data.managed.db.database: 'template1' is reserved by PostgreSQL or DigitalOcean"),
    ([("data.managed.db.database", "pg_data")], "data.managed.db.database: 'pg_data' is reserved by PostgreSQL or DigitalOcean"),
    # rule 7
    ([("data.managed.objects.cors", ["nope"])], "data.managed.objects.cors[0]: nope is not one of services"),
    ([("data.managed.objects.cors", ["web", "mailpit"])],
     "data.managed.objects.cors[1]: mailpit has no hostname, so it has no origin to allow"),
    ([("data.managed.objects.cors", ["files"])], "data.managed.objects.cors[0]: files is in data.managed.skip, so it doesn't run"),
    ([("data.managed.objects.cors", ["web"] * 11)], "data.managed.objects.cors: must be a list of at most 10"),
    ([("data.managed.objects.cors", ["web", "web"])], "data.managed.objects.cors: web is listed twice"),
    # rule 8
    ([("data.managed.skip", ["nope"])], "data.managed.skip[0]: nope is not one of services"),
    ([("data.managed.skip", "files")], "data.managed.skip: must be a list of at most 20"),
    # rule 9
    ([("data.managed.commands", {"dump": ["d"]})], "data.managed.commands.dump: unknown command (allowed: has_data, data_up)"),
    ([("data.managed.commands", {"has_data": "has"})],
     "data.managed.commands.has_data: must be a list: the program, then its arguments"),
    ([("data.managed.commands", {"data_up": ["up", "{slipway.out}"]})],
     "data.managed.commands.data_up[1]: {slipway.out} can only be used in commands.dump and commands.export_files"),
    # rule 11
    ([("data.managed.env", {"SHOP_DOMAIN": "x"})], "data.managed.env.SHOP_DOMAIN: is an app setting (settings.SHOP_DOMAIN)"),
    ([("data.managed.env", {"SHOP_ENV": "x"})], "data.managed.env.SHOP_ENV: is already set by vars.SHOP_ENV"),
    ([("data.managed.env", {"DB_PASSWORD": "x"})],
     "data.managed.env.DB_PASSWORD: is a secret (secrets.DB_PASSWORD); use {secret.DB_PASSWORD} in a value instead"),
    ([("data.managed.env", {"WEB_PORT": "x"})], "data.managed.env.WEB_PORT: is a port variable; Slipway sets it"),
    ([("data.managed.env", {"DB_HOST": "x"})], "data.managed.env.DB_HOST: is already set by data.attach.env"),
    ([("data.managed.env", {"X": "{data.files.bucket}"})], "data.managed.env.X: {data.files.bucket} isn't one of "
                                                           "data.attach.needs (db, objects)"),
    ([("data.managed.env", {"X": "{data.db.bucket}"})], "data.managed.env.X: {data.db.bucket} isn't a field of a postgres "
                                                        "endpoint (host, port, database, user, password, tls, ca_b64)"),
    ([("data.managed.env", {"X": "{secret.NOPE}"})], "data.managed.env.X: {secret.NOPE} isn't one of secrets"),
    ([("data.managed.env", {"X": "{server.host}"})],
     "data.managed.env.X: {server.host} can only be used in data.server.provides and data.server.env"),
    ([("data.managed.env", {"X": "{edge.address}"})], "data.managed.env.X: {edge.address} can only be used in edge.env"),
    ([("data.managed.env", {f"K{i}": "x" for i in range(21)})], "data.managed.env: give at most 20 keys"),
])
def test_the_bad_manifest_table(changes, message):
    with pytest.raises(manifest.ManifestError) as err:
        manifest.parse(_yml(*changes))
    assert str(err.value).startswith(f"slipway.yml: {message}")


def test_what_the_table_accepts():
    # An env_file key (ServerSherpa's SS_SPACES_BUCKET) is neither a setting nor a var: data.managed.env may set it.
    man = manifest.parse(EXAMPLE)
    assert man.data.managed is not None and man.data.managed.env == {"SS_SPACES_BUCKET": "{data.objects.bucket}"}
    # A secret in data.managed.env is allowed, as in data.attach.env, and hides what it makes.
    man = manifest.parse(_yml(("data.managed.env", {"S3_URL2": "https://{data.objects.access_key}:{secret.S3_SECRET}@x"})))
    plan = _shop_plan(man)
    assert plan.env["S3_URL2"] == "https://DO00KEY:s3@x" and plan.env["S3_URL2"] in plan.secret_values
    assert "S3_URL2" not in plan.public_env
    # A value that renders to nothing is left out, as in data.attach.env.
    plan = _shop_plan(manifest.parse(_yml()), data_values={**SHOP_VALUES, "db": {**SHOP_VALUES["db"], "ca_b64": ""}})
    assert "DB_CA" not in plan.written
    # skip, env and commands are optional; an s3 need's entry may be empty; edge.projects is optional.
    lean = _yml(("data.managed", {"db": {"version": "13", "database": "shop", "user": "_shop", "password": "{secret.DB_PASSWORD}"},
                                  "objects": None}), ("edge.projects", None))
    man = manifest.parse(lean)
    assert man.data.managed is not None and man.data.managed.needs["objects"] == {"cors": ()}
    assert man.edge is not None and man.edge.projects == ()
    # A name the pattern allows and PostgreSQL doesn't reserve, such as user (do_rules quotes it).
    assert manifest.parse(_yml(("data.managed.db.user", "user"))).data.managed.needs["db"]["user"] == "user"
    # Every do_rules reserved name is refused here (the table checks some; this checks they're the same lists).
    for name in do_rules.RESERVED_ROLES:
        with pytest.raises(manifest.ManifestError, match="is reserved by PostgreSQL or DigitalOcean"):
            manifest.parse(_yml(("data.managed.db.user", name)))
    for name in do_rules.RESERVED_DATABASES:
        with pytest.raises(manifest.ManifestError, match="is reserved by PostgreSQL or DigitalOcean"):
            manifest.parse(_yml(("data.managed.db.database", name)))


def test_the_environments_variables_may_not_set_what_edge_and_managed_set():
    man = manifest.parse(_yml())
    # Rule 10: on an app slot on managed data behind a load balancer.
    for key, where in (("S3_BUCKET", "managed"), ("SHOP_TRUSTED", "edge")):
        with pytest.raises(manifest.ManifestError) as err:
            _shop_plan(man, env={key: "mine"})
        assert str(err.value) == (f"{key} is set from slipway.yml's edge.env or data.managed.env; remove it from the "
                                  "environment's variables"), where
    with pytest.raises(manifest.ManifestError, match="S3_BUCKET, SHOP_TRUSTED are set from slipway.yml's edge.env"):
        manifest.check_instance_env(man, {"S3_BUCKET": "a", "SHOP_TRUSTED": "b"}, "slot", managed=True, edge=True)
    # Elsewhere Slipway doesn't set them, so an environment variable may (a LAN slot, P3 unchanged).
    lan = {**SHOP_VALUES, "db": {**SHOP_VALUES["db"], "tls": "disable"}}
    plan = _shop_plan(man, env={"S3_BUCKET": "mine", "SHOP_TRUSTED": "x"}, managed=False, edge_values=None,
                      settings={"SHOP_DOMAIN": "shop.example.com", "PROXY_IP": "10.0.0.2"}, data_values=lan)
    assert plan.env["S3_BUCKET"] == "mine"
    manifest.check_instance_env(man, {"S3_BUCKET": "a"}, "slot")
    manifest.check_instance_env(man, {"S3_BUCKET": "a"}, "slot", edge=True)  # only managed sets S3_BUCKET


def test_the_slot_role_refuses_what_the_manifest_lacks():
    no_edge = manifest.parse(_yml(("edge", None)))
    with pytest.raises(manifest.ManifestError, match="has no edge, so the app can't serve its names behind a load balancer"):
        _shop_plan(no_edge)
    no_managed = manifest.parse(_yml(("data.managed", None)))
    with pytest.raises(manifest.ManifestError, match="has no data.managed, so the app can't run on a managed database"):
        _shop_plan(no_managed)
    man = manifest.parse(_yml())
    for kw in ({"managed": True}, {"edge_values": EDGE_VALUES}, {"without": set()}):
        with pytest.raises(ValueError, match="are for the slot role"):
            _shop_plan(man, role="app", **{"managed": False, "edge_values": None, **kw})
    with pytest.raises(manifest.ManifestError, match=r"edge.env.SHOP_HOSTS_IP: \{edge.address\} has no value"):
        _shop_plan(man, edge_values={"trusted": "10.116.0.0/20"})
    # The edge alone (data elsewhere): edge.env and the proxy project, data.attach.env from the data server.
    plan = _shop_plan(man, managed=False, data_values={**SHOP_VALUES, "db": {**SHOP_VALUES["db"], "tls": "disable"}})
    assert "S3_BUCKET" not in plan.written and plan.env["PROXY_IP"] == "172.30.0.2"
    assert plan.projects[-1] == "shop-shop-blue-proxy" and plan.commands["has_data"]["argv"] == ["data", "has"]
    assert [s.name for s in plan.services] == ["web", "files", "mailpit"]  # no data server: nothing taken away


# --------------------------------------------- test 27: a setting the edge sets isn't required


def test_a_setting_named_in_edge_env_is_not_required_behind_a_load_balancer():
    man = manifest.parse(EXAMPLE)
    assert man.edge_settings() == {"STACK_PROXY_IP"}
    assert [s.key for s in man.required_settings()] == ["STACK_DOMAIN", "STACK_PROXY_IP"]
    assert [s.key for s in man.required_settings(edge=True)] == ["STACK_DOMAIN"]
    # Behind the load balancer: not asked for, and the edge's value wins over one that was given.
    plan = _managed_plan(man)
    assert plan.env["STACK_PROXY_IP"] == "172.30.0.2"
    plan = _managed_plan(man, settings={"STACK_DOMAIN": "serversherpa.com", "STACK_PROXY_IP": "10.0.0.2"})
    assert plan.env["STACK_PROXY_IP"] == "172.30.0.2"
    # Still required everywhere else.
    missing = "Set Proxy address (STACK_PROXY_IP) in the app settings of the instance"
    with pytest.raises(manifest.ManifestError, match=missing.replace("(", r"\(").replace(")", r"\)")):
        _managed_plan(man, edge_values=None)
    with pytest.raises(manifest.ManifestError, match=r"Set Proxy address \(STACK_PROXY_IP\)"):
        manifest.plan(man, template=ENV_EXAMPLE, builtins=BUILTINS, settings={"STACK_DOMAIN": "uat.example.com"},
                      chosen=None, host_ports={}, secrets=SECRETS, env={})
    with pytest.raises(manifest.ManifestError, match=r"Set Base domain \(STACK_DOMAIN\)"):
        _managed_plan(man, settings={})
    # An app without an edge: every required setting stays required.
    no_edge = manifest.parse(_yml(("edge", None)))
    assert no_edge.edge_settings() == set()
    assert [s.key for s in no_edge.required_settings(edge=True)] == ["SHOP_DOMAIN", "PROXY_IP"]


# ----------------------------------------------- test 28: capabilities and to_json


def test_capabilities_give_edge_managed_and_digitalocean():
    caps = manifest.parse(EXAMPLE).capabilities()
    assert caps == manifest.CAPABILITIES
    assert caps[-6:] == ("edge", "managed", "digitalocean", "attach", "server", "bluegreen")
    assert {"edge", "managed", "digitalocean"} <= set(manifest.parse(_yml()).capabilities())
    only = lambda *changes: {c for c in manifest.parse(_yml(*changes)).capabilities()  # noqa: E731
                             if c in ("edge", "managed", "digitalocean")}
    assert only(("edge", None)) == {"managed"}
    assert only(("data.managed", None)) == {"edge"}
    assert only(("edge", None), ("data.managed", None)) == set()


def test_bluegreen_takes_a_data_server_or_managed_data():
    # Decision 20: a managed-only app can run two slots on DigitalOcean.
    assert "bluegreen" in manifest.parse(_yml()).capabilities()  # managed, no data server
    assert "bluegreen" not in manifest.parse(_yml(("data.migrations", None))).capabilities()
    assert "bluegreen" not in manifest.parse(_yml(("data.managed", None))).capabilities()
    # The example cut the way tests/test_env_rules.py cuts it (no data server, no data.managed): no Blue/Green.
    no_server = EXAMPLE[:EXAMPLE.index("  # The data server:")] + EXAMPLE[EXAMPLE.index("\ncommands:"):]
    man = manifest.parse(no_server)
    assert man.data.server is None and man.data.managed is None and "bluegreen" not in man.capabilities()


def test_to_json_round_trips_with_edge_and_managed():
    for text in (EXAMPLE, _yml(), _yml(("edge", None)), _yml(("data.managed", None))):
        man = manifest.parse(text)
        body = man.to_json()
        assert json.loads(json.dumps(body)) == body
        assert body["capabilities"] == list(man.capabilities())
    body = manifest.parse(EXAMPLE).to_json()
    assert body["edge"] == {
        "port": 80, "health": "/healthz",
        "env": ["STACK_CADDY", "STACK_NETWORK_SUBNET", "STACK_PROXY_IP", "STACK_BIND_IP", "STACK_HOSTS_IP",
                "STACK_TRUSTED_PROXIES"],
        "projects": ["ss-{STACK_ENV}-proxy"],
    }
    assert body["data"]["managed"] == {
        "skip": ["spaces"],
        "needs": {"db": {"version": "16", "database": "serversherpa", "user": "serversherpa",
                         "password": "{secret.POSTGRES_PASSWORD}"},
                  "objects": {"cors": ["portal", "kiosk", "wiki"]}},
        "env": ["SS_SPACES_BUCKET"],
        "commands": ["has_data"],
    }
    # Only when declared, so what is stored for an app without them stays as it was (I1).
    bare = manifest.parse(_yml(("edge", None), ("data.managed", None))).to_json()
    assert "edge" not in bare and "managed" not in bare["data"]


# ---------------------------------------- test 29: the Django example on managed data

DJANGO = """\
version: 1
name: Acme shop
settings:
  SHOP_DOMAIN: {label: Domain, required: true}
secrets:
  DB_PASSWORD: hex
  FIELD_ENCRYPTION_KEY: {kind: fernet, identity: true}
services:
  web: {port: 8000, port_var: WEB_PORT, hostname: "{SHOP_DOMAIN}", health: /healthz/}
projects: ["shop-{slipway.slug}"]
data:
  app: acme-shop
  format: pg-custom
  migrations: expand_contract
  volumes: [{name: "shop-{slipway.slug}_pgdata", holds: database}]
  attach:
    needs: {db: postgres}
    env:
      DATABASE_URL: "postgres://{data.db.user}:{data.db.password}@{data.db.host}:{data.db.port}/{data.db.database}?sslmode={data.db.tls}"
      DB_EXTERNAL: "1"            # the app's compose file leaves out its db service with this
  managed:
    db: {version: "16", database: shop, user: shop, password: "{secret.DB_PASSWORD}"}
edge:
  port: 80
  health: /healthz/
  env: {WEB_PORT: "80"}
commands:
  start:    [docker, compose, -p, "shop-{slipway.slug}", --env-file, "{slipway.env_dir}/.env", up, -d, --build, --wait]
  stop:     [docker, compose, -p, "shop-{slipway.slug}", --env-file, "{slipway.env_dir}/.env", down]
  data_up:  [docker, compose, -p, "shop-{slipway.slug}", --env-file, "{slipway.env_dir}/.env", up, -d, --wait, db]
  dump:     {run: [docker, compose, -p, "shop-{slipway.slug}", exec, -T, db, pg_dump, -Fc, -U, shop, shop], stdout: true}
  restore:  {run: [docker, compose, -p, "shop-{slipway.slug}", exec, -T, db, pg_restore, --clean, -U, shop, -d, shop],
             stdin: true}
"""


def test_the_django_example_with_data_managed_plans_in_the_managed_role():
    # WEB_PORT is a port variable: the edge can't set it, so the Django app serves its port as declared.
    with pytest.raises(manifest.ManifestError, match="edge.env.WEB_PORT: is a port variable; Slipway sets it"):
        manifest.parse(DJANGO)
    man = manifest.parse(DJANGO.replace('env: {WEB_PORT: "80"}', 'env: {TRUSTED_PROXIES: "{edge.trusted}"}'))
    caps = man.capabilities()
    assert {"managed", "edge", "digitalocean", "bluegreen"} <= set(caps) and "server" not in caps
    values = {"db": {"host": "private-shop-db", "port": "25060", "database": "shop", "user": "shop",
                     "password": "pw" * 16, "tls": "require", "ca_b64": "Q0E="}}
    plan = manifest.plan(man, template=None, builtins={**PROD, "slug": "shop-blue"}, settings={"SHOP_DOMAIN": "shop.example.com"},
                         chosen=None, host_ports={"web": 8000}, secrets={"DB_PASSWORD": "pw" * 16, "FIELD_ENCRYPTION_KEY": "fek"},
                         env={}, role="slot", data_values=values, managed=True, edge_values=EDGE_VALUES)
    assert plan.env["DATABASE_URL"] == f"postgres://shop:{'pw' * 16}@private-shop-db:25060/shop?sslmode=require"
    assert plan.env["DATABASE_URL"] in plan.secret_values and "DATABASE_URL" not in plan.public_env
    assert plan.env["DB_EXTERNAL"] == "1" and plan.env["TRUSTED_PROXIES"] == "10.116.0.0/20"
    assert plan.env["WEB_PORT"] == "8000"
    assert plan.volumes == [] and plan.projects == ["shop-shop-blue"]  # its only volume holds the database
    assert [r["hostname"] for r in plan.routes] == ["shop.example.com"]
    assert plan.commands["data_up"]["argv"][-1] == "db"  # no data.managed.commands: as declared
    assert plan.identity == {"FIELD_ENCRYPTION_KEY": "fek"}
