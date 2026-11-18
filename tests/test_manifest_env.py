"""slipway.yml's environment keys (phase 3, spec §5): health paths, data.migrations, data.attach and data.server,
what is refused and why, and what plan() renders in its three roles (tests 1-5 of §16.2)."""

from __future__ import annotations

import copy
import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from slipway.services import manifest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = (ROOT / "docs/examples/serversherpa.slipway.yml").read_text()
SHA = "0123456789abcdef0123456789abcdef01234567"
BUILTINS = dict(slug="uat-blue", name="UAT blue", release="/srv/x/releases/r1", env_dir="/srv/x/shared", sha=SHA,
                sha12=SHA[:12], host="10.0.0.11", deployment="0123abcd")
MEMBER = {**BUILTINS, "environment": "uat", "slot": "blue"}

# Enough of BaseCampV3's deploy/stack/env.example for the plans below: the bucket provides reads, a commented
# line, and secrets still CHANGEME (the data server's blanks must never trip the placeholder check).
ENV_EXAMPLE = """\
# ServerSherpa stack
STACK_ENV=CHANGEME
STACK_DOMAIN=CHANGEME
SS_SPACES_BUCKET=serversherpa
SS_JWT_SECRET=CHANGEME
SS_PASSWORD_PEPPER=CHANGEME
# SS_DATABASE_CA_B64=           the cluster's CA, base64 PEM
SS_DATABASE_CA_B64=
"""
SETTINGS = {"STACK_DOMAIN": "uat.example.com", "STACK_PROXY_IP": "10.0.0.2"}
SECRETS = {
    "POSTGRES_PASSWORD": "pg-" + "1" * 61, "SPACES_SECRET_KEY": "sp-" + "2" * 61, "SS_JWT_SECRET": "jwt-" + "3" * 60,
    "SS_TOTP_ENCRYPTION_KEY": "totp-key-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "SS_PASSWORD_PEPPER": "pepper-" + "4" * 57,
    "SS_WIKI_SERVICE_TOKEN": "wiki-" + "5" * 59,
}
# What the data server of `uat` provides once it is live (environments.data_values renders it from the server role).
DATA_VALUES = {
    "db": {"host": "10.0.0.13", "port": "5432", "database": "serversherpa", "user": "serversherpa",
           "password": SECRETS["POSTGRES_PASSWORD"], "tls": "disable", "ca_b64": ""},
    "objects": {"endpoint": "https://spaces.uat.example.com", "region": "us-east-1", "bucket": "serversherpa",
                "access_key": "serversherpa", "secret_key": SECRETS["SPACES_SECRET_KEY"], "path_style": "true"},
}


def _plan(man: manifest.Manifest, **kw: Any) -> manifest.AppPlan:
    args: dict[str, Any] = dict(template=ENV_EXAMPLE, builtins=BUILTINS, settings=SETTINGS, chosen=None, host_ports={},
                                secrets=SECRETS, env={})
    args.update(kw)
    return manifest.plan(man, **args)


def _env_text(plan: manifest.AppPlan, template: str = ENV_EXAMPLE) -> str:
    lines, _ = manifest.parse_env_template(template)
    return manifest.render_env(lines, plan.env, plan.written)


def _phase2(text: str) -> str:
    """The manifest as phase 2 knew it: without health, data.migrations, data.attach and data.server."""
    raw = yaml.safe_load(text)
    for spec in raw["services"].values():
        spec.pop("health", None)
    for key in ("migrations", "attach", "server"):
        raw["data"].pop(key, None)
    return yaml.safe_dump(raw, sort_keys=False)


# --------------------------------------------------------------- test 1: ServerSherpa


def test_the_serversherpa_example_parses_with_its_environment_keys():
    man = manifest.parse(EXAMPLE)
    assert [(s.name, s.health) for s in man.services if s.health] == [
        ("api", "/healthz"), ("spaces", "/healthz"), ("wiki", "/healthz"), ("status", "/healthz")]
    assert man.health_path("api") == "/healthz" and man.health_path("portal") == "/"
    assert man.data.migrations == "expand_contract"
    attach, server = man.data.attach, man.data.server
    assert attach is not None and attach.needs == {"db": "postgres", "objects": "s3"} and len(attach.env) == 14
    assert server is not None and server.services == ("spaces",) and server.secrets == ("POSTGRES_PASSWORD", "SPACES_SECRET_KEY")
    assert server.ports == (manifest.ServerPort("db", 5432, "STACK_DB_PORT"),)
    assert server.projects == ("ss-{STACK_ENV}-db", "ss-{STACK_ENV}-storage")
    assert server.volumes == ("ss-{STACK_ENV}-db_pgdata", "ss-{STACK_ENV}-storage_seaweeddata")
    assert sorted(server.commands) == ["has_data", "start"]
    assert man.member_keys() == set(attach.env) | {"STACK_DB_PUBLISH", "STACK_DB_ALLOW", "STACK_DB_PORT"}


def test_the_app_role_plans_byte_for_byte_as_phase_2():
    new, old = manifest.parse(EXAMPLE), manifest.parse(_phase2(EXAMPLE))
    for chosen in (None, ["wiki", "learn"], []):
        args = dict(chosen=chosen, host_ports={"api": 18000, "spaces": 19000})
        now, before = _plan(new, **args), _plan(old, **args)
        assert [s.health for s in now.services][:3] == ["/healthz", None, "/healthz"]  # the one new thing: the paths
        now.services = [dataclasses.replace(s, health=None) for s in now.services]
        assert now == before  # every other field, AppPlan.identity included
        assert _env_text(now) == _env_text(before)
        assert now.role == "app" and now.secret_values == set() and now.server_ports == {} and now.provides == {}
    # Without the member builtins (the deployer's today), with them, and with a member's env: the same bytes.
    assert _env_text(_plan(new, builtins=MEMBER)) == _env_text(_plan(old, builtins=MEMBER))


def test_the_slot_role_points_the_app_at_the_data_server():
    man = manifest.parse(EXAMPLE)
    plan = _plan(man, role="slot", builtins=MEMBER, data_values=DATA_VALUES, host_ports={"api": 18000}, chosen=["wiki"])
    env = plan.env
    assert plan.role == "slot"
    assert "spaces" not in {r["service"] for r in plan.routes} and "spaces" not in {s.name for s in plan.services}
    assert [r["hostname"] for r in plan.routes] == ["api.uat.example.com", "portal.uat.example.com", "wiki.uat.example.com"]
    assert plan.env["STACK_APPS"] == "wiki"
    assert "STACK_SPACES_PORT" not in plan.written and env["STACK_API_PORT"] == "18000"
    attached = set(man.data.attach.env) - {"SS_DATABASE_CA_B64"}  # the empty one is left out
    assert attached <= set(plan.written) and "SS_DATABASE_CA_B64" not in plan.written
    assert env["STACK_EXTERNAL_DATA"] == "1" and env["STACK_DB_HOST"] == "10.0.0.13" and env["STACK_DB_PORT"] == "5432"
    assert env["STACK_DB_SSLMODE"] == "disable" and env["SS_SPACES_ENDPOINT"] == "https://spaces.uat.example.com"
    assert env["SS_DATABASE_URL"] == (f"postgresql+asyncpg://serversherpa:{SECRETS['POSTGRES_PASSWORD']}"
                                      "@10.0.0.13:5432/serversherpa")
    assert env["SS_SPACES_SECRET_KEY"] == SECRETS["SPACES_SECRET_KEY"]
    # Made with a secret: hidden, and never a value templates or the stored state see.
    assert {env["SS_DATABASE_URL"], env["SS_SPACES_SECRET_KEY"]} <= plan.secret_values
    assert "SS_DATABASE_URL" not in plan.public_env and "SS_SPACES_SECRET_KEY" not in plan.public_env
    assert plan.public_env["STACK_DB_HOST"] == "10.0.0.13"
    assert all(env[k] not in plan.secret_values for k in plan.public_env if env[k])
    # attach.env comes after vars and before the secrets; every secret is written on an app slot.
    order = plan.written
    assert order.index("STACK_IMAGE_TAG") < order.index("STACK_EXTERNAL_DATA") < order.index("POSTGRES_PASSWORD")
    assert all(env[k] == v for k, v in SECRETS.items())
    assert plan.identity == {"SS_TOTP_ENCRYPTION_KEY": SECRETS["SS_TOTP_ENCRYPTION_KEY"],
                             "SS_PASSWORD_PEPPER": SECRETS["SS_PASSWORD_PEPPER"]}
    # Every project, the slot-local volume only (the status page's), the app's own commands.
    assert plan.projects == ["ss-uat-blue-db", "ss-uat-blue-storage", "ss-uat-blue-api", "ss-uat-blue-web",
                             "ss-uat-blue-status"]
    assert plan.volumes == [{"name": "ss-uat-blue-status_status-data", "holds": "other"}]
    assert plan.commands["start"]["argv"][1] == "up" and plan.commands["has_data"]["argv"][-1] == "/srv/x/shared"
    text = _env_text(plan)
    assert "SS_DATABASE_CA_B64=\n" in text and "# SS_DATABASE_CA_B64=           the cluster's CA" in text


def test_the_server_role_runs_only_the_data_services():
    man = manifest.parse(EXAMPLE)
    plan = _plan(man, role="server", builtins={**MEMBER, "slug": "uat-data", "slot": "data"},
                 host_ports={"spaces": 9000, "db": 5433, "api": 18000},
                 server_values={"host": "10.0.0.13", "clients": ["10.0.0.12", "10.0.0.11", "10.0.0.12"]})
    env = plan.env
    assert plan.role == "server" and [s.name for s in plan.services] == ["spaces", "db"]
    assert plan.server_ports == {"spaces": 9000, "db": 5433}
    assert [r["hostname"] for r in plan.routes] == ["spaces.uat.example.com"]
    assert env["STACK_SPACES_PORT"] == "9000" and env["STACK_DB_PORT"] == "5433" and "STACK_API_PORT" not in plan.written
    assert env["STACK_DB_PUBLISH"] == "1" and env["STACK_DB_ALLOW"] == "10.0.0.11,10.0.0.12"
    assert env["STACK_ENV"] == "uat-data" and "STACK_EXTERNAL_DATA" not in plan.written
    # Only the server's secrets; the other four are written empty while identity keeps the real values.
    assert env["POSTGRES_PASSWORD"] == SECRETS["POSTGRES_PASSWORD"] and env["SPACES_SECRET_KEY"] == SECRETS["SPACES_SECRET_KEY"]
    blank = ["SS_JWT_SECRET", "SS_TOTP_ENCRYPTION_KEY", "SS_PASSWORD_PEPPER", "SS_WIKI_SERVICE_TOKEN"]
    assert all(env[k] == "" and k in plan.written for k in blank)
    assert plan.identity == {"SS_TOTP_ENCRYPTION_KEY": SECRETS["SS_TOTP_ENCRYPTION_KEY"],
                             "SS_PASSWORD_PEPPER": SECRETS["SS_PASSWORD_PEPPER"]}
    text = _env_text(plan)
    # Blank, where env.example has CHANGEME: the placeholder check runs after the blanks and passes.
    assert "\nSS_JWT_SECRET=\n" in text and "\nSS_PASSWORD_PEPPER=\n" in text and "CHANGEME" not in text
    assert all(value not in text for key, value in SECRETS.items() if key in blank)
    assert plan.projects == ["ss-uat-data-db", "ss-uat-data-storage"]
    assert plan.volumes == [{"name": "ss-uat-data-db_pgdata", "holds": "database"},
                            {"name": "ss-uat-data-storage_seaweeddata", "holds": "files"}]
    assert plan.commands["start"] == {"argv": ["deploy/stack/ss-stack", "data", "/srv/x/shared"], "stream": None}
    assert plan.commands["has_data"] == {"argv": ["deploy/stack/ss-stack", "has-data", "/srv/x/shared", "--server"],
                                         "stream": None}
    assert plan.commands["dump"]["argv"][-1] == {"slot": "out"} and plan.commands["stop"]["argv"][1] == "down"
    # What the app slots are told: environments.data_values reads it.
    assert plan.provides == {
        "db": {"host": "10.0.0.13", "port": "5433", "database": "serversherpa", "user": "serversherpa",
               "password": SECRETS["POSTGRES_PASSWORD"], "tls": "disable", "ca_b64": ""},
        "objects": {"endpoint": "https://spaces.uat.example.com", "region": "us-east-1", "bucket": "serversherpa",
                    "access_key": "serversherpa", "secret_key": SECRETS["SPACES_SECRET_KEY"], "path_style": "true"},
    }
    assert "POSTGRES_PASSWORD" not in plan.public_env


def test_the_server_role_needs_its_address_and_takes_port_overrides():
    man = manifest.parse(EXAMPLE)
    with pytest.raises(manifest.ManifestError, match=r"data.server.provides.db.host: \{server.host\} has no value"):
        _plan(man, role="server", server_values={"clients": []})
    plan = _plan(man, role="server", host_ports={"db": 5433},
                 server_values={"host": "10.0.0.13", "clients": "10.0.0.12,10.0.0.11", "ports": {"db": 6543}})
    assert plan.env["STACK_DB_PORT"] == "6543" and plan.provides["db"]["port"] == "6543"
    assert plan.env["STACK_DB_ALLOW"] == "10.0.0.11,10.0.0.12"
    # An instance variable replacing a secret the server doesn't hold is blank there too; identity keeps it.
    plan = _plan(man, role="server", env={"SS_PASSWORD_PEPPER": "old-pepper"}, server_values={"host": "10.0.0.13"})
    assert plan.env["SS_PASSWORD_PEPPER"] == "" and plan.identity["SS_PASSWORD_PEPPER"] == "old-pepper"


def test_the_slot_role_needs_the_data_servers_values():
    man = manifest.parse(EXAMPLE)
    with pytest.raises(manifest.ManifestError, match=r"data.attach.env.STACK_DB_HOST: \{data.db.host\} has no value"):
        _plan(man, role="slot")
    # {secret.K} and the secret fields are the secret as the app gets it: an instance variable replaces it.
    values = copy.deepcopy(DATA_VALUES)
    plan = _plan(man, role="slot", data_values=values, env={"POSTGRES_PASSWORD": "kept-from-before"})
    assert plan.env["POSTGRES_PASSWORD"] == "kept-from-before"
    assert SECRETS["POSTGRES_PASSWORD"] in plan.env["SS_DATABASE_URL"]  # what the data server provides


def test_roles_need_the_keys_they_render():
    no_env = manifest.parse(_phase2(EXAMPLE))
    with pytest.raises(manifest.ManifestError, match="has no data.attach"):
        _plan(no_env, role="slot", data_values=DATA_VALUES)
    with pytest.raises(manifest.ManifestError, match="has no data.server"):
        _plan(no_env, role="server", server_values={"host": "10.0.0.13"})
    with pytest.raises(ValueError, match="unknown plan role"):
        _plan(no_env, role="blue")


# ------------------------------------------------------------- test 2: bad manifests

BASE: dict[str, Any] = {
    "version": 1, "name": "Shop",
    "settings": {"SHOP_DOMAIN": {"required": True}},
    "vars": {"SHOP_ENV": "{slipway.slug}"},
    "secrets": {"DB_PASSWORD": "hex", "S3_SECRET": "hex", "SHOP_KEY": {"kind": "hex", "identity": True}},
    "services": {
        "web": {"port": 8000, "port_var": "WEB_PORT", "hostname": "shop.{SHOP_DOMAIN}", "health": "/healthz"},
        "files": {"port": 9000, "port_var": "FILES_PORT", "hostname": "files.{SHOP_DOMAIN}"},
        "mailpit": {"port": 8025, "port_var": "MAIL_PORT", "optional": True},
    },
    "optional_services": {"var": "SHOP_APPS", "none": "none"},
    "projects": ["shop-{SHOP_ENV}", "shop-{SHOP_ENV}-db"],
    "data": {
        "app": "shop", "format": "pg-custom", "migrations": "expand_contract",
        "volumes": [{"name": "shop-{SHOP_ENV}-db_pg", "holds": "database"}, {"name": "shop-{SHOP_ENV}_cache", "holds": "other"}],
        "attach": {
            "needs": {"db": "postgres", "objects": "s3"},
            "env": {"DB_HOST": "{data.db.host}", "DB_CA": "{data.db.ca_b64}", "S3_URL": "{data.objects.endpoint}",
                    "DATABASE_URL": "postgres://{data.db.user}:{data.db.password}@{data.db.host}:{data.db.port}/{data.db.database}",
                    "S3_KEY": "{data.objects.secret_key}", "SHOP_SITE": "https://shop.{SHOP_DOMAIN}",
                    "SHOP_ENVIRONMENT": "{slipway.environment}-{slipway.slot}"},
        },
        "server": {
            "services": ["files"],
            "ports": {"db": {"port": 5432, "port_var": "DB_PORT"}},
            "secrets": ["DB_PASSWORD", "S3_SECRET"],
            "env": {"DB_ALLOW": "{server.clients}", "DB_LISTEN": "{server.host}:{server.port.db}"},
            "projects": ["shop-{SHOP_ENV}-db"],
            "volumes": ["shop-{SHOP_ENV}-db_pg"],
            "commands": {"start": ["up", "db"]},
            "provides": {
                "db": {"host": "{server.host}", "port": "{server.port.db}", "database": "shop", "user": "shop",
                       "password": "{secret.DB_PASSWORD}", "tls": "disable", "ca_b64": ""},
                "objects": {"endpoint": "http://{server.host}:{server.port.files}", "region": "us-east-1", "bucket": "shop",
                            "access_key": "shop", "secret_key": "{secret.S3_SECRET}", "path_style": "true"},
            },
        },
    },
    "commands": {"start": ["up"], "stop": ["down"], "data_up": ["data"], "dump": ["dump", "{slipway.out}"],
                 "restore": ["restore", "{slipway.in}"]},
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


def test_the_base_of_the_bad_manifest_table_is_good():
    man = manifest.parse(_yml())
    assert man.capabilities()[-3:] == ("attach", "server", "bluegreen")
    builtins = {**MEMBER, "slug": "shop-blue"}
    values = {"db": {"host": "10.0.0.13", "port": "5432", "database": "shop", "user": "shop", "password": "pw",
                     "tls": "disable", "ca_b64": ""},
              "objects": {"endpoint": "http://10.0.0.13:9000", "region": "us-east-1", "bucket": "shop",
                          "access_key": "shop", "secret_key": "s3", "path_style": "true"}}
    secrets = {"DB_PASSWORD": "pw", "S3_SECRET": "s3", "SHOP_KEY": "key"}
    for role, extra in (("app", {}), ("slot", {"data_values": values}),
                        ("server", {"server_values": {"host": "10.0.0.13", "clients": ["10.0.0.11"]}})):
        manifest.plan(man, template=None, builtins=builtins, settings={"SHOP_DOMAIN": "shop.example.com"}, chosen=None,
                      host_ports={}, secrets=secrets, env={}, role=role, **extra)


@pytest.mark.parametrize(("changes", "message"), [
    # rule 2
    ([("data.migrations", "big_bang")], "data.migrations: the only value is expand_contract"),
    # rule 3
    ([("services.mailpit.health", "/")], "services.mailpit.health: a health path needs a hostname"),
    ([("services.web.health", "/x y")], "services.web.health: '/x y' is not a path such as /healthz"),
    ([("services.web.health", "healthz")], "services.web.health: 'healthz' is not a path such as /healthz"),
    # rule 4
    ([("data.attach.needs", {"db": "mysql"})],
     "data.attach.needs.db: 'mysql' isn't a kind Slipway can provide (postgres, s3)"),
    ([("data.attach.needs", {})], "data.attach.needs: give 1 to 4 endpoints the app reads, each a kind (postgres, s3)"),
    ([("data.attach.needs", {"Db": "postgres"})], "data.attach.needs.Db: an endpoint name is a lowercase letter"),
    # rule 5
    ([("data.attach.env.DATABASE_URL", "postgres://{data.db.sslmode}")],
     "data.attach.env.DATABASE_URL: {data.db.sslmode} isn't a field of a postgres endpoint "
     "(host, port, database, user, password, tls, ca_b64)"),
    ([("data.attach.env.CACHE", "{data.cache.host}")],
     "data.attach.env.CACHE: {data.cache.host} isn't one of data.attach.needs (db, objects)"),
    ([("data.attach.env.X", "{secret.NOPE}")], "data.attach.env.X: {secret.NOPE} isn't one of secrets"),
    ([("data.attach.env.X", "{server.host}")],
     "data.attach.env.X: {server.host} can only be used in data.server.provides and data.server.env"),
    ([("data.attach.env.WEB_PORT", "1")], "data.attach.env.WEB_PORT: is a port variable; Slipway sets it"),
    ([("data.attach.env.SHOP_DOMAIN", "x")], "data.attach.env.SHOP_DOMAIN: is an app setting (settings.SHOP_DOMAIN)"),
    ([("data.attach.env.SHOP_ENV", "x")], "data.attach.env.SHOP_ENV: is already set by vars.SHOP_ENV"),
    ([("data.attach.env.DB_PASSWORD", "x")], "data.attach.env.DB_PASSWORD: is a secret (secrets.DB_PASSWORD)"),
    ([("data.attach.env", {})], "data.attach.env: give 1 to 40 keys"),
    ([("data.attach.env.X", "{data.db}")], "data.attach.env.X: {data.db} is not {data.<endpoint>.<field>}"),
    # templates elsewhere
    ([("vars.X", "{data.db.host}")], "vars.X: {data.db.host} can only be used in data.attach.env"),
    ([("projects", ["shop-{secret.DB_PASSWORD}"])],
     "projects[0]: {secret.DB_PASSWORD} can only be used in data.attach.env and data.server.provides"),
    ([("commands.start", ["up", "{server.clients}"])],
     "commands.start[1]: {server.clients} can only be used in data.server.env"),
    ([("data.server.commands.start", ["up", "{data.db.host}"])],
     "data.server.commands.start[1]: {data.db.host} can only be used in data.attach.env"),
    # rule 6
    ([("data.attach", None)], "data.server needs data.attach: the app slots must be told where the server is"),
    ([("commands.dump", None), ("commands.restore", None)],
     "data.server needs commands.dump: Slipway backs the data up on the server"),
    ([("data.server.provides.objects.secret_key", None)],
     "data.server.provides.objects: needs secret_key (s3 endpoints have endpoint, region, bucket, access_key, "
     "secret_key, path_style)"),
    ([("data.server.provides.objects", None)], "data.server.provides: needs objects (every data.attach.needs endpoint)"),
    ([("data.server.provides.cache", {"host": "x"})], "data.server.provides.cache: isn't one of data.attach.needs (db, objects)"),
    ([("data.server.provides.db.sslmode", "disable")],
     "data.server.provides.db.sslmode: isn't a field of a postgres endpoint (host, port, database, user, password, "
     "tls, ca_b64)"),
    ([("data.server.provides.db.password", "x{secret.DB_PASSWORD}")],
     'data.server.provides.db.password: must be one secret, such as "{secret.DB_PASSWORD}"'),
    ([("data.server.provides.db.password", "hunter2")],
     'data.server.provides.db.password: must be one secret, such as "{secret.DB_PASSWORD}"'),
    ([("data.server.provides.db.tls", "verify-full")], "data.server.provides.db.tls: 'verify-full' isn't disable or require"),
    ([("data.server.provides.objects.path_style", "yes")], "data.server.provides.objects.path_style: 'yes' isn't true or false"),
    ([("data.server.provides.db.port", 5432)], "data.server.provides.db.port: must be text"),
    ([("data.server.provides.db.password", "{secret.NOPE}")],
     "data.server.provides.db.password: {secret.NOPE} isn't one of secrets"),
    ([("data.server.provides.db.host", "{server.port.nope}")],
     "data.server.provides.db.host: {server.port.nope} isn't one of data.server.ports or data.server.services (db, files)"),
    ([("data.server.provides.db.host", "{server.clients}")],
     "data.server.provides.db.host: {server.clients} can only be used in data.server.env"),
    ([("data.server.provides.db.host", "{data.db.host}")],
     "data.server.provides.db.host: {data.db.host} can only be used in data.attach.env"),
    ([("data.server.provides.db.host", "{server.name}")],
     "data.server.provides.db.host: {server.name} is not one of server.host, server.port.<name>, server.clients"),
    # rule 7
    ([("data.server.services", ["mailpit"])], "data.server.services: mailpit is optional; a data server's services always run"),
    ([("data.server.services", ["redis"])], "data.server.services: redis is not one of services"),
    # rule 8
    ([("data.server.ports", {"web": {"port": 5432, "port_var": "DB_PORT"}})],
     "data.server.ports.web: is a service's name; give the port another name"),
    ([("data.server.ports.db.port", 70000)], "data.server.ports.db.port: must be a port number, 1-65535"),
    ([("data.server.ports.db.port", 9000)], "data.server.ports.db.port: 9000/tcp is also files's port"),
    ([("data.server.ports.db.port_var", "WEB_PORT")],
     "data.server.ports.db.port_var: WEB_PORT is already set by services.web.port_var"),
    ([("data.server.ports.db.port_var", "SHOP_KEY")], "data.server.ports.db.port_var: SHOP_KEY is already set by secrets.SHOP_KEY"),
    ([("data.server.ports.db.port_var", None)], "data.server.ports.db: give port (the port it listens on) and port_var"),
    # rule 9
    ([("data.server.secrets", ["DB_PASSWORD"])],
     "data.server.provides.objects.secret_key: uses S3_SECRET, which data.server.secrets doesn't list"),
    ([("data.server.secrets", ["DB_PASSWORD", "S3_SECRET", "NOPE"])], "data.server.secrets[2]: NOPE is not one of secrets"),
    # rule 10
    ([("data.server.env.X", "{secret.DB_PASSWORD}")],
     "data.server.env.X: {secret.DB_PASSWORD} can only be used in data.attach.env and data.server.provides"),
    ([("data.server.env.X", "{data.db.host}")], "data.server.env.X: {data.db.host} can only be used in data.attach.env"),
    ([("data.server.env.DB_PORT", "1")], "data.server.env.DB_PORT: is a port variable; Slipway sets it"),
    ([("data.server.env.SHOP_KEY", "1")], "data.server.env.SHOP_KEY: is a secret (secrets.SHOP_KEY)"),
    # rule 11
    ([("data.server.volumes", ["shop-{SHOP_ENV}-db_pg", "shop-{SHOP_ENV}-files"])],
     "data.server.volumes[1]: 'shop-{SHOP_ENV}-files' is not one of data.volumes"),
    ([("data.server.projects", ["shop-{slipway.slug}-db"])],
     "data.server.projects[0]: 'shop-{slipway.slug}-db' is not one of projects"),
    # rule 12
    ([("data.server.commands.dump", ["dump", "{slipway.out}"])],
     "data.server.commands.dump: unknown command (allowed: build, start, stop, has_data, data_up)"),
    ([("data.server.commands.stop", ["down", "{slipway.out}"])],
     "data.server.commands.stop[1]: {slipway.out} can only be used in commands.dump and commands.export_files"),
    ([("data.server.bogus", 1)], "data.server: unknown key bogus"),
    ([("data.attach.bogus", 1)], "data.attach: unknown key bogus"),
])
def test_bad_environment_manifests_say_exactly_what_is_wrong(changes, message):
    with pytest.raises(manifest.ManifestError) as err:
        manifest.parse(_yml(*changes))
    assert str(err.value).startswith(f"slipway.yml: {message}"), str(err.value)


def test_an_environment_variable_may_not_set_what_attach_and_server_set():
    man = manifest.parse(_yml())
    manifest.check_instance_env(man, {"DB_HOST": "10.9.9.9"})  # a standalone instance may: the key is its own
    for role, key in (("slot", "DB_HOST"), ("server", "DB_ALLOW"), ("slot", "DB_PORT"), ("server", "S3_URL")):
        with pytest.raises(manifest.ManifestError) as err:
            manifest.check_instance_env(man, {key: "x"}, role)
        assert str(err.value) == (f"{key} is set from slipway.yml's data.attach or data.server; "
                                  "remove it from the environment's variables")
    with pytest.raises(manifest.ManifestError, match="DB_HOST is set from slipway.yml's data.attach"):
        manifest.plan(man, template=None, builtins=MEMBER, settings={"SHOP_DOMAIN": "shop.example.com"}, chosen=None,
                      host_ports={}, secrets={"DB_PASSWORD": "pw", "S3_SECRET": "s3", "SHOP_KEY": "k"},
                      env={"DB_HOST": "10.9.9.9"}, role="slot", data_values={})
    # The phase 1 rule still comes first, with its own text.
    with pytest.raises(manifest.ManifestError, match="WEB_PORT is set from slipway.yml; remove it from the instance's"):
        manifest.check_instance_env(man, {"WEB_PORT": "1"}, "slot")


# ------------------------------------------- test 3: member builtins, empty attach values


def test_member_builtins_render_for_members_and_are_empty_outside_an_environment():
    text = _yml(("vars.SHOP_WHERE", "{slipway.environment}/{slipway.slot}"))
    man = manifest.parse(text)
    args: dict[str, Any] = dict(template=None, settings={"SHOP_DOMAIN": "shop.example.com"}, chosen=None, host_ports={},
                                secrets={"DB_PASSWORD": "pw", "S3_SECRET": "s3", "SHOP_KEY": "k"}, env={})
    standalone = manifest.plan(man, builtins=BUILTINS, **args)  # the deployer's builtins today: no environment
    assert standalone.env["SHOP_WHERE"] == "/"
    blank = manifest.plan(man, builtins={**BUILTINS, "environment": "", "slot": ""}, **args)
    assert blank.env == standalone.env
    values = {"db": {"host": "10.0.0.13", "port": "5432", "database": "shop", "user": "shop", "password": "pw",
                     "tls": "disable", "ca_b64": ""},
              "objects": {"endpoint": "http://10.0.0.13:9000", "region": "us-east-1", "bucket": "shop",
                          "access_key": "shop", "secret_key": "s3", "path_style": "true"}}
    green = manifest.plan(man, builtins={**MEMBER, "slot": "green"}, role="slot", data_values=values, **args)
    assert green.env["SHOP_WHERE"] == "uat/green" and green.env["SHOP_ENVIRONMENT"] == "uat-green"
    data = manifest.plan(man, builtins={**MEMBER, "slot": "data"}, role="server",
                         server_values={"host": "10.0.0.13", "clients": ["10.0.0.11"]}, **args)
    assert data.env["SHOP_WHERE"] == "uat/data"


def test_an_attach_value_that_renders_empty_is_left_out():
    man = manifest.parse(_yml())
    template = "DB_CA=from-the-env-file  # the repository's own line\nDB_HOST=localhost\n"
    values = {"db": {"host": "10.0.0.13", "port": "5432", "database": "shop", "user": "shop", "password": "pw",
                     "tls": "disable", "ca_b64": ""},
              "objects": {"endpoint": "http://10.0.0.13:9000", "region": "us-east-1", "bucket": "shop",
                          "access_key": "shop", "secret_key": "s3", "path_style": "true"}}
    args: dict[str, Any] = dict(template=template, builtins=MEMBER, settings={"SHOP_DOMAIN": "shop.example.com"},
                                chosen=None, host_ports={}, secrets={"DB_PASSWORD": "pw", "S3_SECRET": "s3", "SHOP_KEY": "k"},
                                env={}, role="slot")
    plan = manifest.plan(man, data_values=values, **args)
    assert "DB_CA" not in plan.written and plan.env["DB_HOST"] == "10.0.0.13"
    text = manifest.render_env(manifest.parse_env_template(template)[0], plan.env, plan.written)
    assert text.splitlines()[:2] == ["DB_CA=from-the-env-file  # the repository's own line", "DB_HOST=10.0.0.13"]
    # A managed database with a CA (phase 4): the same attach writes it.
    with_ca = copy.deepcopy(values)
    with_ca["db"]["ca_b64"] = "LS0tLS1CRUdJTg=="
    assert manifest.plan(man, data_values=with_ca, **args).env["DB_CA"] == "LS0tLS1CRUdJTg=="


# ------------------------------------------------------------- test 4: a second app

# The Django app of spec §5.5: only a database, whose data server is a plain Postgres container.
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
commands:
  start:    [docker, compose, -p, "shop-{slipway.slug}", --env-file, "{slipway.env_dir}/.env", up, -d, --build, --wait]
  stop:     [docker, compose, -p, "shop-{slipway.slug}", --env-file, "{slipway.env_dir}/.env", down]
  data_up:  [docker, compose, -p, "shop-{slipway.slug}", --env-file, "{slipway.env_dir}/.env", up, -d, --wait, db]
  dump:     {run: [docker, compose, -p, "shop-{slipway.slug}", exec, -T, db, pg_dump, -Fc, -U, shop, shop], stdout: true}
  restore:  {run: [docker, compose, -p, "shop-{slipway.slug}", exec, -T, db, pg_restore, --clean, -U, shop, -d, shop],
             stdin: true}
"""


def test_the_django_example_parses_and_plans_in_all_three_roles():
    man = manifest.parse(DJANGO)
    assert man.capabilities()[-3:] == ("attach", "server", "bluegreen")
    assert man.health_path("web") == "/healthz/"
    args: dict[str, Any] = dict(template=None, settings={"SHOP_DOMAIN": "shop.example.com"}, chosen=None,
                                secrets={"DB_PASSWORD": "pw" * 16, "FIELD_ENCRYPTION_KEY": "fek"}, env={})

    app = manifest.plan(man, builtins={**BUILTINS, "slug": "shop"}, host_ports={"web": 8001}, **args)
    assert app.env["WEB_PORT"] == "8001" and "DB_PORT" not in app.written and "DATABASE_URL" not in app.env
    assert app.volumes == [{"name": "shop-shop_pgdata", "holds": "database"}] and app.projects == ["shop-shop"]
    assert app.routes == [{"hostname": "shop.example.com", "service": "web", "container": 8000}]

    server = manifest.plan(man, builtins={**MEMBER, "slug": "prod-data", "slot": "data"}, host_ports={"db": 5432},
                           role="server", server_values={"host": "10.1.0.13", "clients": ["10.1.0.12", "10.1.0.11"]},
                           **args)
    assert [s.name for s in server.services] == ["db"] and server.routes == [] and server.server_ports == {"db": 5432}
    assert server.env["DB_PORT"] == "5432" and server.env["DB_ALLOW"] == "10.1.0.11,10.1.0.12"
    assert server.env["DB_LISTEN"] == "0.0.0.0" and "WEB_PORT" not in server.written
    assert server.env["DB_PASSWORD"] == "pw" * 16 and server.env["FIELD_ENCRYPTION_KEY"] == ""
    assert server.identity == {"FIELD_ENCRYPTION_KEY": "fek"}
    assert server.projects == ["shop-prod-data"] and server.volumes == [{"name": "shop-prod-data_pgdata", "holds": "database"}]
    assert server.commands["start"]["argv"][-3:] == ["-d", "--wait", "db"]
    assert server.commands["dump"]["stream"] == "stdout"  # the app's own data commands, as declared
    assert server.provides == {"db": {"host": "10.1.0.13", "port": "5432", "database": "shop", "user": "shop",
                                      "password": "pw" * 16, "tls": "disable", "ca_b64": ""}}

    blue = manifest.plan(man, builtins={**MEMBER, "slug": "prod-blue"}, host_ports={"web": 8000}, role="slot",
                         data_values=server.provides, **args)
    assert blue.env["DATABASE_URL"] == f"postgres://shop:{'pw' * 16}@10.1.0.13:5432/shop?sslmode=disable"
    assert blue.env["DB_EXTERNAL"] == "1" and blue.env["DATABASE_URL"] in blue.secret_values
    assert "DATABASE_URL" not in blue.public_env and blue.public_env["DB_EXTERNAL"] == "1"
    assert blue.volumes == [] and blue.projects == ["shop-prod-blue"]  # its only volume is on the data server
    assert [r["hostname"] for r in blue.routes] == ["shop.example.com"] and blue.identity == server.identity


# ----------------------------------------------------- test 5: to_json and capabilities


def test_to_json_and_capabilities_round_trip():
    for text in (EXAMPLE, DJANGO, _yml(), _phase2(EXAMPLE)):
        man = manifest.parse(text)
        body = man.to_json()
        assert json.loads(json.dumps(body)) == body
        assert body["capabilities"] == list(man.capabilities())
    body = manifest.parse(EXAMPLE).to_json()
    assert {s["name"]: s["health"] for s in body["services"]}["api"] == "/healthz"
    assert {s["name"]: s["health"] for s in body["services"]}["portal"] is None
    data = body["data"]
    assert data["migrations"] == "expand_contract"
    assert data["attach"] == {"needs": {"db": "postgres", "objects": "s3"}, "env": list(manifest.parse(EXAMPLE).data.attach.env)}
    assert data["server"] == {
        "services": ["spaces"], "ports": {"db": {"port": 5432, "port_var": "STACK_DB_PORT"}},
        "secrets": ["POSTGRES_PASSWORD", "SPACES_SECRET_KEY"], "env": ["STACK_DB_PUBLISH", "STACK_DB_ALLOW"],
        "projects": ["ss-{STACK_ENV}-db", "ss-{STACK_ENV}-storage"],
        "volumes": ["ss-{STACK_ENV}-db_pgdata", "ss-{STACK_ENV}-storage_seaweeddata"],
        "commands": ["start", "has_data"],
        "provides": {"db": ["host", "port", "database", "user", "password", "tls", "ca_b64"],
                     "objects": ["endpoint", "region", "bucket", "access_key", "secret_key", "path_style"]},
    }
    assert "{secret." not in json.dumps(data["server"])  # field names only, never what they are made of
    assert body["capabilities"][-3:] == ["attach", "server", "bluegreen"]
    # An app outside environments stores what it stored before (I1): no new data keys, no new capabilities.
    old = manifest.parse(_phase2(EXAMPLE)).to_json()
    assert set(old["data"]) == {"app", "format", "volumes", "files", "identity_label", "identity_help"}
    assert not {"attach", "server", "bluegreen"} & set(old["capabilities"])


@pytest.mark.parametrize(("changes", "expected"), [
    ([], ("attach", "server", "bluegreen")),
    ([("data.migrations", None)], ("attach", "server")),  # a data server, but slots can't share it
    ([("data.server", None)], ("attach",)),
    ([("data.server", None), ("data.attach", None)], ()),
])
def test_environment_capabilities_follow_the_keys(changes, expected):
    caps = manifest.parse(_yml(*changes)).capabilities()
    assert tuple(c for c in caps if c in ("attach", "server", "bluegreen")) == expected


def test_services_for_each_role():
    man = manifest.parse(EXAMPLE)
    assert [s.name for s in man.services_for("app", None)] == [s.name for s in man.services_on(None)]
    assert "spaces" not in [s.name for s in man.services_for("slot", ["wiki"])]
    assert [(s.name, s.port, s.port_var, s.hostname) for s in man.services_for("server", ["wiki"])] == [
        ("spaces", 9000, "STACK_SPACES_PORT", "spaces.{STACK_DOMAIN}"), ("db", 5432, "STACK_DB_PORT", None)]
