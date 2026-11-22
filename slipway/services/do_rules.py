"""The pure rules of Slipway's DigitalOcean placement (phase 4).

Nothing here talks to DigitalOcean, a database or a host: every function takes plain values (and the
dictionaries DigitalOcean answers with) and returns names, request bodies, verdicts or text. The
provisioner (``do_provision``), the load balancer backend (``do_lb``), accounts and the environment
flows build on them, and the rules can be tested without a fake.

What lives here:

* names and tags of every object an environment owns, the request tag of a create, and the exact
  patterns that say an object is ours (never a prefix: ``prod``'s prefix is also the start of
  ``prod-eu``'s names);
* the droplet's cloud-init user-data and its create body (``monitoring`` and the droplet agent off);
* PostgreSQL authentication: the SCRAM-SHA-256 verifier of a password, the idempotent setup SQL, the
  repeatable reset SQL, and the psql command that runs either as ``doadmin`` through Docker;
* the load balancer and cloud firewall bodies and the matchers that compare them with what
  DigitalOcean answers;
* the size rules (sizes only grow) and the checks against the live catalog;
* ``PRICES`` (the dated table for what the API doesn't price), ``SPACES_REGIONS`` and ``cost``.

Secrets (the host's private key, passwords, verifiers) pass through some of these functions; none of
them logs or keeps anything, and no error message carries a secret value.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import shlex
import stringprep
import unicodedata
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

import yaml

from slipway.services import cloudinit

q = shlex.quote


class DoRuleError(ValueError):
    """A value Slipway refuses to build a DigitalOcean object or command from (plain-English text)."""


# ---------------------------------------------------------------------- names and tags

# The same rule as ``slipway.models.environment.ENVIRONMENT_NAME_RE`` (2-26 characters). Copied rather
# than imported so this module stays free of the models; ``test_do_rules`` checks the two agree.
ENV_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,24}[a-z0-9]$")
SLOTS = ("blue", "green")  # D21: DigitalOcean environments use only these app slots
DROPLET_NAME_RE = re.compile(r"^slipway-[a-z][a-z0-9-]{0,40}[a-z0-9]$")
NONCE_RE = re.compile(r"^[0-9a-f]{16}$")
DROPLET_IMAGE = "ubuntu-24-04-x64"  # open question 10

BASE_TAG = "slipway"
CHANGED_NOTHING = "Slipway changed nothing: fix it by hand, then retry"


def _env(env: str) -> str:
    if not isinstance(env, str) or not ENV_NAME_RE.fullmatch(env):
        raise DoRuleError(f"{env!r} isn't an environment name Slipway uses for DigitalOcean objects")
    return env


def _slot(slot: str) -> str:
    if slot not in SLOTS:
        raise DoRuleError(f"{slot!r} isn't an app slot: DigitalOcean environments use blue and green")
    return slot


def _uuid(env_id: uuid.UUID | str) -> uuid.UUID:
    try:
        return env_id if isinstance(env_id, uuid.UUID) else uuid.UUID(str(env_id))
    except ValueError:
        raise DoRuleError(f"{env_id!r} isn't an environment id") from None


def _nonce(nonce: str) -> str:
    if not isinstance(nonce, str) or not NONCE_RE.fullmatch(nonce):
        raise DoRuleError("A request nonce is 16 lowercase hex characters")
    return nonce


def new_nonce() -> str:
    """A fresh nonce for a pending create (§6.4 step 4)."""
    return secrets.token_hex(8)


def id8(env_id: uuid.UUID | str) -> str:
    """The first 8 hex characters of the environment id, which make bucket and key names unique."""
    return _uuid(env_id).hex[:8]


def vpc_name(env: str) -> str:
    return f"slipway-{_env(env)}"


def vpc_marker(env_id: uuid.UUID | str) -> str:
    return f"slipway:{_uuid(env_id)}"


def vpc_description(env: str, env_id: uuid.UUID | str, nonce: str) -> str:
    """The VPC's description: Slipway's marker first, the request nonce last (§6.1)."""
    return f"{vpc_marker(env_id)} Made by Slipway for environment {_env(env)}. req:{_nonce(nonce)}"


def vpc_is_marked(vpc: Mapping[str, Any], env_id: uuid.UUID | str) -> bool:
    """Whether a VPC's description starts with this environment's marker (the whole first word)."""
    words = str(vpc.get("description") or "").split()
    return bool(words) and words[0] == vpc_marker(env_id)


def vpc_request_nonce(vpc: Mapping[str, Any]) -> str | None:
    """The nonce in a VPC's description (`` req:<nonce>`` at its end), or None."""
    m = re.search(r"(?:^|\s)req:([0-9a-f]{16})\Z", str(vpc.get("description") or ""))
    return m.group(1) if m else None


def droplet_name(env: str, slot: str) -> str:
    """``slipway-<env>-<slot>``, which is also the droplet's hostname."""
    name = f"slipway-{_env(env)}-{_slot(slot)}"
    if not DROPLET_NAME_RE.fullmatch(name):  # always true for a valid env and slot; kept as the hostname guard
        raise DoRuleError(f"{name} isn't a valid droplet hostname")
    return name


def database_name(env: str) -> str:
    return f"slipway-{_env(env)}-db"


def bucket_name(env: str, env_id: uuid.UUID | str) -> str:
    """``slipway-<env>-<id8>``: Spaces names are global, so the id keeps it unique (at most 43 characters)."""
    return f"slipway-{_env(env)}-{id8(env_id)}"


def spaces_key_name(env: str, env_id: uuid.UUID | str, nonce: str, *, setup: bool = False) -> str:
    """The bucket's key (``slipway-<env>-<id8>-<nonce>``) or a temporary setup key (``…-setup-<nonce>``)."""
    middle = "setup-" if setup else ""
    return f"slipway-{_env(env)}-{id8(env_id)}-{middle}{_nonce(nonce)}"


def spaces_key_re(env: str, env_id: uuid.UUID | str) -> re.Pattern[str]:
    return re.compile(rf"^slipway-{re.escape(_env(env))}-{id8(env_id)}-(setup-)?([0-9a-f]{{16}})$")


def spaces_key_is_ours(name: str, env: str, env_id: uuid.UUID | str) -> bool:
    return bool(spaces_key_re(env, env_id).fullmatch(name or ""))


def spaces_key_nonce(name: str, env: str, env_id: uuid.UUID | str) -> str | None:
    m = spaces_key_re(env, env_id).fullmatch(name or "")
    return m.group(2) if m else None


def spaces_key_is_setup(name: str, env: str, env_id: uuid.UUID | str) -> bool:
    m = spaces_key_re(env, env_id).fullmatch(name or "")
    return bool(m and m.group(1))


def lb_name(env: str) -> str:
    return f"slipway-{_env(env)}-lb"


def firewall_name(env: str) -> str:
    return f"slipway-{_env(env)}-fw"


def certificate_name(env: str, when: datetime) -> str:
    """``slipway-<env>-<UTC yyyymmddhhmm>``."""
    if when.tzinfo is None:
        raise DoRuleError("A certificate's stamp needs a time with its time zone")
    return f"slipway-{_env(env)}-{when.astimezone(UTC):%Y%m%d%H%M}"


def certificate_name_re(env: str) -> re.Pattern[str]:
    return re.compile(rf"^slipway-{re.escape(_env(env))}-[0-9]{{12}}$")


def certificate_name_matches(name: str, env: str) -> bool:
    return bool(certificate_name_re(env).fullmatch(name or ""))


def env_tag(env_id: uuid.UUID | str) -> str:
    """The ownership tag, ``slipway-env-<env id>``; the cloud firewall applies by it."""
    return f"slipway-env-{_uuid(env_id)}"


def request_tag(nonce: str) -> str:
    return f"slipway-req:{_nonce(nonce)}"


def request_nonce(tags: Iterable[str] | None) -> str | None:
    """The nonce of the request tag among ``tags``, or None."""
    for tag in tags or ():
        m = re.fullmatch(r"slipway-req:([0-9a-f]{16})", str(tag))
        if m:
            return m.group(1)
    return None


def tags(env: str, env_id: uuid.UUID | str, *, nonce: str, slot: str | None = None) -> list[str]:
    """The create-body tags of a droplet (with ``slot``) or a database cluster (without).

    ``slipway``, the ownership tag, ``slipway-env:<name>``, a droplet's ``slipway-slot:<slot>``, and the
    request tag of the create. DigitalOcean's tags API is never called: these go in the create body only.
    """
    out = [BASE_TAG, env_tag(env_id), f"slipway-env:{_env(env)}"]
    if slot is not None:
        out.append(f"slipway-slot:{_slot(slot)}")
    out.append(request_tag(nonce))
    return out


def has_both_tags(obj: Mapping[str, Any], env_id: uuid.UUID | str) -> bool:
    live = set(obj.get("tags") or ())
    return BASE_TAG in live and env_tag(env_id) in live


def _kind_text(kind: str) -> str:
    return kind.replace("_", " ")


def pick_tagged(
    objects: Iterable[Mapping[str, Any]], name: str, env_id: uuid.UUID | str, kind: str
) -> Mapping[str, Any] | None:
    """The one droplet or cluster named exactly ``name`` with both of the environment's tags (§6.2).

    None when there is none. Raises ``DoRuleError`` (the step stops, nothing is changed) when one of the
    name carries the environment's tag without ``slipway``, or when two carry both tags: Slipway never
    picks one of two, since the wrong pick could be deleted.
    """
    env_t = env_tag(env_id)
    named = [o for o in objects if o.get("name") == name]
    half = [o for o in named if env_t in set(o.get("tags") or ()) and BASE_TAG not in set(o.get("tags") or ())]
    if half:
        raise DoRuleError(
            f"{_kind_text(kind).capitalize()} {name} ({half[0].get('id')}) carries {env_t} but not the "
            f"{BASE_TAG} tag. {CHANGED_NOTHING}"
        )
    ours = [o for o in named if has_both_tags(o, env_id)]
    if len(ours) > 1:
        ids = ", ".join(str(o.get("id")) for o in ours)
        raise DoRuleError(f"DigitalOcean has {len(ours)} {_kind_text(kind)}s named {name} with Slipway's tags ({ids}). "
                          f"{CHANGED_NOTHING}")
    return ours[0] if ours else None


def tagged_matches(obj: Mapping[str, Any], name: str, env_id: uuid.UUID | str) -> bool:
    """A recorded droplet or cluster still matches: the exact name and both tags (§6.2)."""
    return obj.get("name") == name and has_both_tags(obj, env_id)


def body_hash(body: Mapping[str, Any], secret_keys: Iterable[str] = ("user_data", "private_key")) -> str:
    """sha256 of a create body without its secret fields (``details.pending.body_hash``, §6.4)."""
    drop = set(secret_keys)
    clean = {k: v for k, v in body.items() if k not in drop}
    return hashlib.sha256(json.dumps(clean, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


# ---------------------------------------------------------------------- droplets

USERDATA_LIMIT = 64 * 1024  # DigitalOcean refuses user-data of 64 KiB or more
READY_MARKER = "/var/lib/slipway-ready"
DEPLOY_ROOT = "/opt/slipway"
# The same Linux user as on VMs, but with no sudo on a droplet (D24).
DROPLET_USER = cloudinit.GUEST_USER
# DigitalOcean serves the droplet's user-data (with its private host key) at this address to anything on the
# droplet. Containers reach it through Docker's NAT unless DOCKER-USER drops it: cloud-init adds the rule
# (idempotently) before the ready marker, and a systemd drop-in adds it again whenever Docker starts (§9.1).
METADATA_ADDRESS = "169.254.169.254"
METADATA_BLOCK = (f"iptables -C DOCKER-USER -d {METADATA_ADDRESS}/32 -j DROP 2>/dev/null || "
                  f"iptables -I DOCKER-USER -d {METADATA_ADDRESS}/32 -j DROP")
METADATA_DROPIN = "/etc/systemd/system/docker.service.d/slipway-metadata.conf"


class _CloudConfigDumper(yaml.SafeDumper):
    """Writes multi-line strings (the host's private key) as literal blocks, so the file stays readable."""


def _str_representer(dumper: yaml.SafeDumper, value: str) -> yaml.ScalarNode:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


_CloudConfigDumper.add_representer(str, _str_representer)


def _one_line(value: str, what: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\n" in value or "\r" in value:
        raise DoRuleError(f"{what} must be one line")
    return value.strip()


def droplet_userdata(
    env: str, slot: str, *, authorized_key: str, host_private_key: str, host_public_key: str
) -> str:
    """The droplet's cloud-init document (§9.1).

    ``authorized_key`` is the droplet host row's own public key (the one Slipway logs in with); the host
    key pair is the one generated for this create, whose public half is already in ``hosts.host_key``.
    The private half appears only in this document: the caller sends it once and keeps nothing.
    """
    hostname = droplet_name(env, slot)
    key = _one_line(authorized_key, "The droplet's login key")
    public = _one_line(host_public_key, "The droplet's host key")
    if not public.startswith("ssh-ed25519 "):
        raise DoRuleError("The droplet's host key must be an ed25519 key")
    if "PRIVATE KEY" not in (host_private_key or ""):
        raise DoRuleError("The droplet's private host key isn't an OpenSSH private key")
    private = host_private_key if host_private_key.endswith("\n") else host_private_key + "\n"
    doc = {
        "hostname": hostname,
        "preserve_hostname": False,
        "ssh_pwauth": False,
        "disable_root": True,
        # No ``sudo`` and no groups: the docker group exists only once docker.io is installed, and
        # cloud-init makes users before it installs packages, so runcmd adds the user to it below.
        "users": [{
            "name": DROPLET_USER,
            "shell": "/bin/bash",
            "lock_passwd": True,
            "ssh_authorized_keys": [key],
        }],
        "ssh_deletekeys": True,
        "ssh_genkeytypes": [],
        "ssh_keys": {"ed25519_private": private, "ed25519_public": public},
        "growpart": {"mode": "auto", "devices": ["/"]},
        "resize_rootfs": True,
        "package_update": True,
        "packages": ["docker.io", "docker-compose-v2", "curl"],
        # Written before the packages, so Docker's first start already runs it.
        "write_files": [{
            "path": METADATA_DROPIN,
            "owner": "root:root",
            "permissions": "0644",
            "content": f"[Service]\nExecStartPost=/bin/sh -c '{METADATA_BLOCK}'\n",
        }],
        "runcmd": [
            ["usermod", "-aG", "docker", DROPLET_USER],
            ["install", "-d", "-o", DROPLET_USER, "-g", DROPLET_USER, "-m", "0755", DEPLOY_ROOT],
            ["systemctl", "daemon-reload"],
            ["systemctl", "enable", "--now", "docker"],
            # No ready marker (so no ready droplet) unless containers can't read the metadata address.
            ["sh", "-c", f"{{ {METADATA_BLOCK}; }} && touch {READY_MARKER}"],
        ],
    }
    text = "#cloud-config\n" + yaml.dump(doc, Dumper=_CloudConfigDumper, sort_keys=False, width=4096)
    if len(text.encode()) >= USERDATA_LIMIT:
        raise DoRuleError(f"The droplet's user-data would be {len(text.encode())} bytes; DigitalOcean takes "
                          "less than 64 KiB")
    return text


def droplet_body(
    env: str, env_id: uuid.UUID | str, slot: str, *, region: str, size: str, vpc_uuid: str, nonce: str,
    user_data: str,
) -> dict[str, Any]:
    """``POST /droplets`` (§9.2 step 3). ``monitoring`` is off: DigitalOcean's agent installs through its
    own script and Slipway reads none of its metrics (D24). The droplet agent (DigitalOcean's web
    console) is off for the same reason: Slipway reaches the droplet only over SSH."""
    return {
        "name": droplet_name(env, slot),
        "region": region,
        "size": size,
        "image": DROPLET_IMAGE,
        "vpc_uuid": vpc_uuid,
        "ipv6": False,
        "monitoring": False,
        "with_droplet_agent": False,
        "tags": tags(env, env_id, nonce=nonce, slot=slot),
        "user_data": user_data,
    }


def vpc_body(env: str, env_id: uuid.UUID | str, *, region: str, nonce: str) -> dict[str, Any]:
    """``POST /vpcs``: DigitalOcean picks its default range (D13)."""
    return {"name": vpc_name(env), "region": region, "description": vpc_description(env, env_id, nonce)}


def database_rules(droplet_ids: Iterable[int | str]) -> list[dict[str, str]]:
    """The cluster's trusted sources: exactly the environment's recorded droplets (J8)."""
    return [{"type": "droplet", "value": str(i)} for i in sorted({str(i) for i in droplet_ids}, key=_id_key)]


def _id_key(value: str) -> tuple[int, str]:
    return (int(value), "") if value.isdigit() else (1 << 62, value)


def database_rules_match(live_rules: Iterable[Mapping[str, Any]], droplet_ids: Iterable[int | str]) -> bool:
    """Whether ``GET /databases/{id}/firewall``'s rules are exactly the recorded droplets."""
    live = {(str(r.get("type")), str(r.get("value"))) for r in live_rules}
    return live == {("droplet", str(i)) for i in droplet_ids}


def database_body(
    env: str, env_id: uuid.UUID | str, *, region: str, size: str, nodes: int, version: str, vpc_uuid: str,
    nonce: str, droplet_ids: Iterable[int | str],
) -> dict[str, Any]:
    """``POST /databases`` with its trusted sources in the body, so it is never open to every address (D8)."""
    return {
        "name": database_name(env),
        "engine": "pg",
        "version": str(version),
        "region": region,
        "size": size,
        "num_nodes": int(nodes),
        "private_network_uuid": vpc_uuid,
        "tags": tags(env, env_id, nonce=nonce),
        "rules": database_rules(droplet_ids),
    }


# ---------------------------------------------------------------------- PostgreSQL authentication

PG_IDENT_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
SCRAM_RE = re.compile(r"^SCRAM-SHA-256\$[1-9][0-9]{3,6}:[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]{43}=:[A-Za-z0-9+/]{43}=$")
SCRAM_ITERATIONS = 4096  # PostgreSQL's default (scram_iterations)
# Names a role or database of the app may not take: DigitalOcean's own, PostgreSQL's, and the
# templates. Resetting must never drop one of these, and the app's role must never be doadmin.
RESERVED_ROLES = frozenset({"doadmin", "postgres", "public", "_dodb", "none", "current_user", "session_user"})
RESERVED_DATABASES = frozenset({"defaultdb", "postgres", "template0", "template1", "_dodb"})


def _saslprep(password: str) -> bytes:
    """The password as SCRAM hashes it, the way PostgreSQL's ``pg_saslprep`` prepares it.

    An ASCII password is used as it is. Otherwise SASLprep (RFC 4013) maps and normalises it; when the
    result holds a prohibited character, PostgreSQL falls back to the raw bytes, and so does this.
    """
    raw = password.encode("utf-8")
    if password.isascii():
        return raw
    mapped = "".join(
        " " if stringprep.in_table_c12(ch) else ch for ch in password if not stringprep.in_table_b1(ch)
    )
    text = unicodedata.normalize("NFKC", mapped)
    if not text:
        return raw
    prohibited = (
        stringprep.in_table_c12, stringprep.in_table_c21, stringprep.in_table_c22, stringprep.in_table_c3,
        stringprep.in_table_c4, stringprep.in_table_c5, stringprep.in_table_c6, stringprep.in_table_c7,
        stringprep.in_table_c8, stringprep.in_table_c9, stringprep.in_table_a1,
    )
    if any(check(ch) for ch in text for check in prohibited):
        return raw
    # RFC 3454 §6: a string with right-to-left characters must start and end with one and hold no
    # left-to-right character.
    if any(stringprep.in_table_d1(ch) for ch in text):
        if any(stringprep.in_table_d2(ch) for ch in text):
            return raw
        if not (stringprep.in_table_d1(text[0]) and stringprep.in_table_d1(text[-1])):
            return raw
    return text.encode("utf-8")


def scram_sha256(password: str, *, salt: bytes | None = None, iterations: int = SCRAM_ITERATIONS) -> str:
    """PostgreSQL's SCRAM-SHA-256 verifier of ``password`` (what ``pg_authid.rolpassword`` holds).

    ``SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>``, all base64. The server stores and
    checks this; the plaintext never reaches it or its logs (D8). A fresh 16-byte salt by default.
    """
    if not isinstance(password, str) or not password:
        raise DoRuleError("The database password is empty")
    if not 1000 <= iterations <= 9_999_999:
        raise DoRuleError("SCRAM iterations must be between 1000 and 9999999")
    salt = secrets.token_bytes(16) if salt is None else salt
    if not salt:
        raise DoRuleError("A SCRAM salt can't be empty")
    salted = hashlib.pbkdf2_hmac("sha256", _saslprep(password), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return f"SCRAM-SHA-256${iterations}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"


def _ident(value: str, what: str, reserved: frozenset[str]) -> str:
    if not isinstance(value, str) or not PG_IDENT_RE.fullmatch(value):
        raise DoRuleError(f"{what} {value!r} must be 1-63 lowercase letters, digits and underscores, "
                          "starting with a letter or underscore")
    if value in reserved or value.startswith("pg_"):
        raise DoRuleError(f"{what} {value!r} is reserved by PostgreSQL or DigitalOcean; pick another name")
    return value


def _verifier(value: str) -> str:
    if not isinstance(value, str) or not SCRAM_RE.fullmatch(value):
        # The value itself is never echoed: it is derived from a secret.
        raise DoRuleError("The database password must be given as a SCRAM-SHA-256 verifier")
    return value


def setup_sql(role: str, database: str, *, verifier: str) -> str:
    """The app's role and database, made idempotently as ``doadmin`` (§10.1 step 7).

    The role if missing, its password (the verifier, never the plaintext), ``GRANT <role> TO doadmin``
    (so doadmin may make the database owned by it), the database if missing, and its owner. ``CREATE
    DATABASE`` can't run in a transaction or a DO block, so it goes through psql's ``\\gexec``.
    Identifiers are checked against the manifest's pattern and double-quoted as well.
    """
    role = _ident(role, "The database user", RESERVED_ROLES)
    database = _ident(database, "The database", RESERVED_DATABASES)
    verifier = _verifier(verifier)
    return (
        f"SELECT 'CREATE ROLE \"{role}\" LOGIN' WHERE NOT EXISTS "
        f"(SELECT FROM pg_roles WHERE rolname = '{role}') \\gexec\n"
        f"ALTER ROLE \"{role}\" WITH LOGIN PASSWORD '{verifier}';\n"
        f"GRANT \"{role}\" TO doadmin;\n"
        f"SELECT 'CREATE DATABASE \"{database}\" OWNER \"{role}\"' WHERE NOT EXISTS "
        f"(SELECT FROM pg_database WHERE datname = '{database}') \\gexec\n"
        f"ALTER DATABASE \"{database}\" OWNER TO \"{role}\";\n"
    )


def reset_sql(role: str, database: str) -> str:
    """Empty the app's database (Reset's ``wipe``, §10.6), in a form a cut-off run can simply repeat.

    The drop and the create can't share a transaction, so a run stopped between them leaves no
    database; running this again then makes the empty one, and running it after a whole run drops and
    makes it again. Either way it ends with an empty database owned by the role.
    """
    role = _ident(role, "The database user", RESERVED_ROLES)
    database = _ident(database, "The database", RESERVED_DATABASES)
    return (
        f"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE);\n"
        f"SELECT 'CREATE DATABASE \"{database}\" OWNER \"{role}\"' WHERE NOT EXISTS "
        f"(SELECT FROM pg_database WHERE datname = '{database}') \\gexec\n"
    )


_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_PG_VERSION_RE = re.compile(r"^[0-9]{2}$")


def psql_command(*, host: str, port: int, version: str) -> str:
    """The shell command that runs SQL from stdin as ``doadmin`` on a droplet (§10.1 step 7).

    Its stdin is ``psql_stdin(...)``: the doadmin password (already escaped for ``.pgpass``), the
    cluster's CA in base64, then the SQL. Neither secret is ever on a command line. The client is
    ``postgres:<version>-alpine`` through Docker, so the droplet needs no PostgreSQL package.
    """
    if not _HOST_RE.fullmatch(host or ""):
        raise DoRuleError(f"{host!r} isn't a database host name")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise DoRuleError(f"{port!r} isn't a database port")
    if not _PG_VERSION_RE.fullmatch(str(version)):
        raise DoRuleError(f"{version!r} isn't a PostgreSQL major version")
    conninfo = (f"host={host} port={port} dbname=defaultdb user=doadmin "
                "sslmode=verify-full sslrootcert=/s/ca.pem")
    return "\n".join([
        "set -e",
        """d=$(mktemp -d); trap 'rm -rf "$d"' EXIT; umask 077""",
        "IFS= read -r pw; IFS= read -r ca",
        f"""printf '%s:%s:defaultdb:doadmin:%s\\n' {q(host)} {q(str(port))} "$pw" > "$d/pgpass\"""",
        """printf '%s' "$ca" | base64 -d > "$d/ca.pem\"""",
        f"""docker run --rm -i -v "$d:/s:ro" -e PGPASSFILE=/s/pgpass {q(f"postgres:{version}-alpine")} \\""",
        f"  psql {q(conninfo)} \\",
        "  -v ON_ERROR_STOP=1 -q -f -",
    ]) + "\n"


def pgpass_escape(value: str) -> str:
    """A ``.pgpass`` field: backslashes and colons escaped with a backslash."""
    return value.replace("\\", "\\\\").replace(":", "\\:")


_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def psql_stdin(*, admin_password: str, ca_b64: str, sql: str) -> str:
    """What ``psql_command`` reads: the password line, the CA line, then the SQL."""
    if not admin_password or "\n" in admin_password or "\r" in admin_password:
        raise DoRuleError("The database's admin password is empty or holds a line break")
    ca = "".join((ca_b64 or "").split())
    if not _B64_RE.fullmatch(ca):
        raise DoRuleError("The database's CA certificate isn't base64")
    return f"{pgpass_escape(admin_password)}\n{ca}\n{sql}"


# ---------------------------------------------------------------------- the load balancer

LB_READ_ONLY = ("id", "ip", "ipv6", "status", "created_at")
LB_HEALTH = {"check_interval_seconds": 10, "response_timeout_seconds": 5,
             "healthy_threshold": 3, "unhealthy_threshold": 3}


def _port(port: int) -> int:
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise DoRuleError(f"{port!r} isn't a port")
    return port


def lb_body(
    env: str, *, region: str, vpc_uuid: str, port: int, health: str, certificate_id: str
) -> dict[str, Any]:
    """``POST /load_balancers`` (§11.3): HTTPS and HTTP in, plain HTTP to ``edge.port``, no targets (D11).

    HTTP:80 stays open without a redirect: the app redirects itself using ``X-Forwarded-Proto``.
    """
    port = _port(port)
    if not isinstance(health, str) or not health.startswith("/"):
        raise DoRuleError(f"{health!r} isn't a health check path")
    return {
        "name": lb_name(env),
        "region": region,
        "size_unit": 1,
        "vpc_uuid": vpc_uuid,
        "forwarding_rules": [
            {"entry_protocol": "https", "entry_port": 443, "target_protocol": "http", "target_port": port,
             "certificate_id": certificate_id, "tls_passthrough": False},
            {"entry_protocol": "http", "entry_port": 80, "target_protocol": "http", "target_port": port},
        ],
        "health_check": {"protocol": "http", "port": port, "path": health, **LB_HEALTH},
        "redirect_http_to_https": False,
        "droplet_ids": [],
    }


def _https_rule(lb: Mapping[str, Any]) -> Mapping[str, Any] | None:
    for rule in lb.get("forwarding_rules") or ():
        if str(rule.get("entry_protocol")).lower() == "https" and int(rule.get("entry_port") or 0) == 443:
            return rule
    return None


def https_certificate(lb: Mapping[str, Any]) -> str | None:
    """The certificate id the load balancer serves on HTTPS:443, or None."""
    rule = _https_rule(lb)
    return (rule.get("certificate_id") or None) if rule else None


def lb_update_body(
    live: Mapping[str, Any], *, certificate_id: str | None = None, droplet_ids: Sequence[int] | None = None
) -> dict[str, Any]:
    """The full body for ``PUT /load_balancers/{id}``, made from the live one (§11.3, D10).

    DigitalOcean's PUT replaces everything, so it starts from what is there and changes only what the
    caller names: without the read-only fields, with ``region`` as its slug, without ``size`` when
    ``size_unit`` is set (it refuses both), and without ``tag`` beside ``droplet_ids`` (it refuses both).
    """
    body = {k: copy.deepcopy(v) for k, v in live.items() if k not in LB_READ_ONLY}
    region = body.get("region")
    if isinstance(region, Mapping):
        body["region"] = region.get("slug")
    if body.get("size_unit") is not None:
        body.pop("size", None)
    if droplet_ids is not None:
        body["droplet_ids"] = [int(i) for i in droplet_ids]
    if "droplet_ids" in body or not body.get("tag"):
        body.pop("tag", None)
    if certificate_id is not None:
        rule = _https_rule(body)
        if rule is None:
            raise DoRuleError(f"Load balancer {live.get('name')} has no HTTPS rule on port 443 to put the "
                              f"certificate on. {CHANGED_NOTHING}")
        rule["certificate_id"] = certificate_id
    return body


def lb_targets(lb: Mapping[str, Any]) -> list[int]:
    return [int(i) for i in lb.get("droplet_ids") or ()]


def lb_matches(lb: Mapping[str, Any], env: str, vpc_uuid: str) -> bool:
    """Ours: the exact name inside the environment's VPC (§6.2)."""
    return lb.get("name") == lb_name(env) and lb.get("vpc_uuid") == vpc_uuid


def lb_edge_problem(lb: Mapping[str, Any], *, port: int, health: str) -> str | None:
    """Why an existing load balancer no longer serves the frozen edge (changed by hand), or None."""
    name = lb.get("name")
    rules = lb.get("forwarding_rules") or []
    entries = {(str(r.get("entry_protocol")).lower(), int(r.get("entry_port") or 0)): r for r in rules}
    for entry in (("https", 443), ("http", 80)):
        rule = entries.get(entry)
        if rule is None or int(rule.get("target_port") or 0) != port \
                or str(rule.get("target_protocol")).lower() != "http":
            return f"{name} no longer forwards to port {port}: Slipway changed nothing"
    check = lb.get("health_check") or {}
    if int(check.get("port") or 0) != port or check.get("path") != health \
            or str(check.get("protocol")).lower() != "http":
        return f"{name} no longer checks {health} on port {port}: Slipway changed nothing"
    return None


def settle_seconds(lb: Mapping[str, Any]) -> int:
    """How long a target change takes to settle: ``healthy_threshold × check_interval_seconds + 10``."""
    check = lb.get("health_check") or {}
    threshold = int(check.get("healthy_threshold") or LB_HEALTH["healthy_threshold"])
    interval = int(check.get("check_interval_seconds") or LB_HEALTH["check_interval_seconds"])
    return threshold * interval + 10


# ---------------------------------------------------------------------- the cloud firewall

ANYWHERE = ("0.0.0.0/0", "::/0")
OPEN_SSH_WARNING = "SSH to {env}'s droplets is open to the internet"
MAX_SSH_SOURCES = 10


def normalise_ssh_sources(sources: Iterable[str]) -> list[str]:
    """The account's SSH sources, checked: 1-10 IPv4 or IPv6 addresses or CIDRs, written as networks."""
    if isinstance(sources, str):
        raise DoRuleError("SSH sources must be a list of addresses")
    out: list[str] = []
    for raw in sources:
        try:
            net = str(ipaddress.ip_network(str(raw).strip(), strict=False))
        except ValueError:
            raise DoRuleError(f"{str(raw)[:60]!r} isn't an IP address or CIDR range") from None
        if net not in out:
            out.append(net)
    if not out:
        raise DoRuleError("Give at least one SSH source: the address Slipway connects to droplets from")
    if len(out) > MAX_SSH_SOURCES:
        raise DoRuleError(f"Give at most {MAX_SSH_SOURCES} SSH sources")
    return out


def open_to_world(sources: Iterable[str]) -> bool:
    return any(_net(s) in ANYWHERE for s in sources)


def _net(value: Any) -> str:
    try:
        return str(ipaddress.ip_network(str(value).strip(), strict=False))
    except ValueError:
        return str(value)


def firewall_body(
    env: str, env_id: uuid.UUID | str, *, ssh_sources: Iterable[str], lb_id: str | None = None,
    port: int | None = None,
) -> dict[str, Any]:
    """The cloud firewall's whole body (§11.4), for its create and every PUT.

    ``prepare`` makes it with the SSH rule only (``lb_id`` None), before the first droplet; ``edge``
    adds the rule that lets the load balancer reach ``edge.port``. It applies by the environment's tag.
    """
    sources = normalise_ssh_sources(ssh_sources)
    inbound: list[dict[str, Any]] = [{"protocol": "tcp", "ports": "22", "sources": {"addresses": sources}}]
    if lb_id is not None:
        if port is None:
            raise DoRuleError("The firewall's load balancer rule needs the edge port")
        inbound.append({"protocol": "tcp", "ports": str(_port(port)), "sources": {"load_balancer_uids": [lb_id]}})
    anywhere = {"addresses": list(ANYWHERE)}
    return {
        "name": firewall_name(env),
        "tags": [env_tag(env_id)],
        "droplet_ids": [],
        "inbound_rules": inbound,
        "outbound_rules": [
            {"protocol": "tcp", "ports": "all", "destinations": dict(anywhere)},
            {"protocol": "udp", "ports": "all", "destinations": dict(anywhere)},
            {"protocol": "icmp", "destinations": dict(anywhere)},
        ],
    }


_ENDPOINT_KEYS = ("addresses", "droplet_ids", "load_balancer_uids", "kubernetes_ids", "tags")


def _norm_ports(protocol: str, ports: Any) -> str:
    if protocol == "icmp":
        return ""  # ICMP has no ports; DigitalOcean answers "0"
    text = str(ports if ports is not None else "").strip().lower()
    return "all" if text in ("", "0", "all", "1-65535") else text


def _norm_rule(rule: Mapping[str, Any], side: str) -> tuple:
    protocol = str(rule.get("protocol") or "").lower()
    ends = rule.get(side) or {}
    parts = []
    for key in _ENDPOINT_KEYS:
        values = ends.get(key) or []
        if key == "addresses":
            norm = tuple(sorted({_net(v) for v in values}))
        else:
            norm = tuple(sorted({str(v) for v in values}))
        if norm:
            parts.append((key, norm))
    return (protocol, _norm_ports(protocol, rule.get("ports")), tuple(parts))


def _norm_rules(rules: Iterable[Mapping[str, Any]] | None, side: str) -> list[tuple]:
    return sorted(_norm_rule(r, side) for r in rules or ())


def firewall_matches(live: Mapping[str, Any], wanted: Mapping[str, Any]) -> bool:
    """Whether the live firewall is what ``wanted`` says, after normalising (§11.4 Drift).

    DigitalOcean answers ``"0"`` for ``all`` ports and may list rules, addresses and tags in another
    order; neither is drift.
    """
    if live.get("name") != wanted.get("name"):
        return False
    if set(live.get("tags") or ()) != set(wanted.get("tags") or ()):
        return False
    if {str(i) for i in live.get("droplet_ids") or ()} != {str(i) for i in wanted.get("droplet_ids") or ()}:
        return False
    return (_norm_rules(live.get("inbound_rules"), "sources") == _norm_rules(wanted.get("inbound_rules"), "sources")
            and _norm_rules(live.get("outbound_rules"), "destinations")
            == _norm_rules(wanted.get("outbound_rules"), "destinations"))


_firewall_matches = firewall_matches  # the name Sirdar's code and the spec's tests use


def firewall_ssh_sources(fw: Mapping[str, Any]) -> frozenset[str]:
    """The addresses the firewall lets in on SSH (every TCP rule that covers port 22)."""
    out: set[str] = set()
    for rule in fw.get("inbound_rules") or ():
        if str(rule.get("protocol")).lower() != "tcp":
            continue
        if _norm_ports("tcp", rule.get("ports")) not in ("22", "all"):
            continue
        out.update(_net(a) for a in (rule.get("sources") or {}).get("addresses") or ())
    return frozenset(out)


def firewall_ssh_changed(live: Mapping[str, Any], wanted: Mapping[str, Any]) -> bool:
    """Whether a PUT of ``wanted`` changes who may reach SSH (the change Slipway must prove, J14)."""
    return firewall_ssh_sources(live) != firewall_ssh_sources(wanted)


def firewall_has_lb_rule(fw: Mapping[str, Any], *, lb_id: str, port: int) -> bool:
    """Whether the firewall lets ``lb_id`` reach ``port`` (``details.lb_rule``)."""
    for rule in fw.get("inbound_rules") or ():
        if str(rule.get("protocol")).lower() == "tcp" and _norm_ports("tcp", rule.get("ports")) == str(port) \
                and lb_id in ((rule.get("sources") or {}).get("load_balancer_uids") or ()):
            return True
    return False


def firewall_adoptable(fw: Mapping[str, Any], env: str, env_id: uuid.UUID | str) -> bool:
    """An unrecorded firewall is adopted only with the exact name and the environment's tag (§6.2)."""
    return fw.get("name") == firewall_name(env) and env_tag(env_id) in set(fw.get("tags") or ())


# ---------------------------------------------------------------------- Spaces keys


def spaces_key_verdict(
    key: Mapping[str, Any], env: str, env_id: uuid.UUID | str, *, bucket: str, recorded: Iterable[str]
) -> str:
    """What to do with a listed Spaces key (§6.2): ``keep``, ``delete``, ``stop`` or ``foreign``.

    ``foreign``: not ours by name. ``keep``: ours and recorded. An unrecorded key of ours whose grants
    are only on our bucket or full access is a lost answer or a left setup key: ``delete``. One with
    grants on another bucket: ``stop``.
    """
    name = str(key.get("name") or "")
    if not spaces_key_is_ours(name, env, env_id):
        return "foreign"
    if name in set(recorded):
        return "keep"
    for grant in key.get("grants") or ():
        on = grant.get("bucket") or ""
        full = grant.get("permission") == "fullaccess" and on == ""
        if not (full or on == bucket):
            return "stop"
    return "delete"


# ---------------------------------------------------------------------- sizes

_VCPU_RE = re.compile(r"^([0-9]+)vcpu$")
_AMOUNT_RE = re.compile(r"^([0-9]+)(mb|gb|tb)$")
_MB = {"mb": 1, "gb": 1024, "tb": 1024 * 1024}


@dataclass(frozen=True)
class SizeParts:
    """A size as Slipway compares it. ``memory`` in MB and ``disk`` in GB, None when unknown."""

    slug: str
    family: str
    vcpus: int | None
    memory: int | None
    disk: int | None


def size_parts(slug: str, catalog_size: Mapping[str, Any] | None = None) -> SizeParts:
    """The family, vCPUs, memory and disk of a droplet or database size.

    The family comes from the slug: its words that aren't amounts (``s-2vcpu-4gb-amd`` is ``s-amd``,
    ``db-s-1vcpu-2gb`` is ``db-s``, ``c-4`` is ``c``). The amounts come from the catalog's entry when
    there is one, else from the slug (a retired size the catalog no longer lists, or a database size,
    which the API gives no amounts for): ``<n>vcpu``, the first ``<n>gb`` or ``<n>mb`` as memory, a second
    as disk, and a bare number as vCPUs.
    """
    family: list[str] = []
    vcpus = memory = disk = None
    for word in str(slug or "").lower().split("-"):
        if m := _VCPU_RE.fullmatch(word):
            vcpus = int(m.group(1))
        elif m := _AMOUNT_RE.fullmatch(word):
            amount = int(m.group(1)) * _MB[m.group(2)]
            if memory is None:
                memory = amount
            elif disk is None:
                disk = amount // 1024
        elif word.isdigit():
            vcpus = int(word) if vcpus is None else vcpus
        elif word:
            family.append(word)
    if not family:
        raise DoRuleError(f"{slug!r} isn't a size Slipway can read")
    if catalog_size is not None:
        vcpus = _int_or(catalog_size.get("vcpus"), vcpus)
        memory = _int_or(catalog_size.get("memory"), memory)
        disk = _int_or(catalog_size.get("disk"), disk)
    return SizeParts(slug=slug, family="-".join(family), vcpus=vcpus, memory=memory, disk=disk)


def _int_or(value: Any, default: int | None) -> int | None:
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def grows(current: SizeParts, new: SizeParts) -> bool:
    """Whether ``new`` is a grow of ``current``: the same family, at least as large in every amount both
    know, and larger in one (D15). An amount ``current`` doesn't know (a retired size's disk) is skipped;
    one ``new`` doesn't know can't be shown to be at least as large, so it is no grow."""
    if current.family != new.family:
        return False
    larger = False
    for attr in ("vcpus", "memory", "disk"):
        old, now = getattr(current, attr), getattr(new, attr)
        if old is None:
            continue
        if now is None or now < old:
            return False
        larger = larger or now > old
    return larger


def _sizes(catalog: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {s["slug"]: s for s in catalog.get("sizes") or () if s.get("slug")}


def droplet_size_problem(slug: str, catalog: Mapping[str, Any]) -> str | None:
    """Why ``slug`` can't be a new droplet's size in the catalog's region, or None."""
    if slug not in _sizes(catalog):
        return f"{slug} isn't a droplet size DigitalOcean offers in {catalog.get('region')}"
    return None


def droplet_grow_problem(current: str, new: str, catalog: Mapping[str, Any]) -> str | None:
    """Why the droplet size can't go from ``current`` to ``new`` (§15.7), or None (a grow, or no change).

    ``new`` must be offered in the region now. ``current`` may have been retired: then its amounts come
    from its slug.
    """
    if new == current:
        return None
    sizes = _sizes(catalog)
    if new not in sizes:
        return f"{new} isn't a droplet size DigitalOcean offers in {catalog.get('region')}"
    old = size_parts(current, sizes.get(current))
    now = size_parts(new, sizes[new])
    if old.family != now.family:
        return (f"{new} is another kind of droplet than {current}: a droplet only grows within its kind "
                f"({old.family})")
    if not grows(old, now):
        return f"{new} isn't larger than {current} in every way"
    return None


def database_sizes(catalog: Mapping[str, Any], nodes: int) -> list[str]:
    return list((catalog.get("database_sizes") or {}).get(str(nodes)) or ())


def database_size_problem(slug: str, nodes: int, catalog: Mapping[str, Any]) -> str | None:
    """Why ``slug`` with ``nodes`` nodes can't be a new cluster in the catalog's region, or None."""
    if nodes not in (1, 2):
        return "A cluster has one node, or two with a standby"
    if slug not in database_sizes(catalog, nodes):
        return f"{slug} has no {nodes}-node layout"
    return None


def database_grow_problem(
    current: str, current_nodes: int, new: str, new_nodes: int, catalog: Mapping[str, Any]
) -> str | None:
    """Why the cluster can't go to ``new`` × ``new_nodes`` (§15.7), or None (a grow, or no change).

    A standby can be added, never removed; the size must have a layout for the node count and, when it
    changes, be larger in every way within its family.
    """
    if new_nodes < current_nodes:
        return "A standby node can be added but not removed"
    if new == current and new_nodes == current_nodes:
        return None
    if problem := database_size_problem(new, new_nodes, catalog):
        return problem
    if new != current:
        old, now = size_parts(current), size_parts(new)
        if old.family != now.family or not grows(old, now):
            return f"{new} isn't larger than {current} in every way"
    return None


def region_problem(catalog: Mapping[str, Any]) -> str | None:
    """Why the catalog's region can't hold an environment (open for new objects, with Spaces), or None."""
    region = catalog.get("region")
    info = next((r for r in catalog.get("regions") or () if r.get("slug") == region), None)
    if info is None or not info.get("available"):
        return f"{region} isn't open for new objects in DigitalOcean"
    if region not in SPACES_REGIONS:
        return f"{region} has no Spaces, which the environment's bucket needs; pick one of " \
               f"{', '.join(sorted(SPACES_REGIONS))}"
    return None


def db_version_problem(version: str, catalog: Mapping[str, Any]) -> str | None:
    offered = list(catalog.get("database_versions") or ())
    if str(version) not in offered:
        return (f"PostgreSQL {version} isn't offered by DigitalOcean here "
                f"({', '.join(offered) if offered else 'it offers none'})")
    return None


def build_catalog(
    region: str, regions: Iterable[Mapping[str, Any]], sizes: Iterable[Mapping[str, Any]],
    database_options: Mapping[str, Any],
) -> dict[str, Any]:
    """The catalog the pages, the checks and ``cost`` read (§8), from ``GET /regions``, ``GET /sizes`` and
    ``GET /databases/options`` (either the whole answer or its ``options``).

    ``sizes`` keeps only droplet sizes available in ``region``; ``database_sizes`` maps a node count
    (as a string, as JSON keeps it) to the PostgreSQL sizes with that layout.
    """
    pg = (database_options.get("options") or database_options).get("pg") or {}
    db_sizes: dict[str, list[str]] = {}
    for layout in pg.get("layouts") or ():
        db_sizes[str(int(layout.get("num_nodes") or 0))] = list(layout.get("sizes") or ())
    return {
        "region": region,
        "regions": [{"slug": r.get("slug"), "name": r.get("name"), "available": bool(r.get("available")),
                     "spaces": r.get("slug") in SPACES_REGIONS} for r in regions],
        "sizes": [
            {"slug": s.get("slug"), "vcpus": s.get("vcpus"), "memory": s.get("memory"), "disk": s.get("disk"),
             "price_monthly": s.get("price_monthly"), "description": s.get("description")}
            for s in sizes if s.get("available", True) and region in (s.get("regions") or ())
        ],
        "database_sizes": db_sizes,
        "database_versions": [str(v) for v in pg.get("versions") or ()],
        "database_regions": list(pg.get("regions") or ()),
        "spaces": region in SPACES_REGIONS,
    }


# ---------------------------------------------------------------------- prices and cost

# Spaces regions: the API doesn't list them (open question 5). §20.3's real-account check confirms
# this list; a region missing here can't be chosen, which is the safe side.
SPACES_REGIONS = frozenset({"ams3", "blr1", "fra1", "lon1", "nyc3", "sfo2", "sfo3", "sgp1", "syd1", "tor1"})

# What DigitalOcean's API doesn't price, in US cents a month (D17). Database prices are per node
# count, as strings so an override stored as JSON has the same shape. The real-account check
# (§20.3 item 1) compares this with DigitalOcean's pricing page; update ``as_of`` with the numbers.
PRICES: dict[str, Any] = {
    "as_of": "2026-11-15",
    "database": {
        "db-s-1vcpu-1gb": {"1": 1500},
        "db-s-1vcpu-2gb": {"1": 3000, "2": 6000},
        "db-s-2vcpu-4gb": {"1": 6000, "2": 12000},
        "db-s-4vcpu-8gb": {"1": 12000, "2": 24000},
        "db-s-6vcpu-16gb": {"1": 24000, "2": 48000},
        "db-s-8vcpu-32gb": {"1": 48000, "2": 96000},
        "db-s-16vcpu-64gb": {"1": 96000, "2": 192000},
    },
    "load_balancer": {"1": 1200},  # per size_unit
    "spaces": 500,  # the account's Spaces subscription
}

COST_NOTE = ("Estimated, prices as of {as_of}; bandwidth beyond the allowance, DigitalOcean backups and "
             "taxes are extra.")


def check_prices(value: Any) -> dict[str, Any]:
    """An override of ``PRICES`` (an account's ``prices``; there is no install-wide one), checked: the same
    shape, any part of it, whole cents, and its own ``as_of`` (yyyy-mm-dd)."""
    if not isinstance(value, Mapping):
        raise DoRuleError("Prices must be an object like Slipway's own table")
    unknown = set(value) - {"as_of", "database", "load_balancer", "spaces"}
    if unknown:
        raise DoRuleError(f"Prices can't set {', '.join(sorted(unknown))}")
    as_of = value.get("as_of")
    try:
        datetime.strptime(str(as_of), "%Y-%m-%d")
    except ValueError:
        raise DoRuleError("Prices need their date, as_of, as yyyy-mm-dd") from None

    def cents(v: Any, where: str) -> int:
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise DoRuleError(f"Prices: {where} must be whole cents (0 or more)")
        return v

    out: dict[str, Any] = {"as_of": str(as_of)}
    if "database" in value:
        if not isinstance(value["database"], Mapping):
            raise DoRuleError("Prices: database must map sizes to node counts")
        out["database"] = {}
        for size, by_nodes in value["database"].items():
            if not isinstance(by_nodes, Mapping):
                raise DoRuleError(f"Prices: database {size} must map node counts to cents")
            out["database"][str(size)] = {str(n): cents(c, f"database {size} × {n}") for n, c in by_nodes.items()}
    if "load_balancer" in value:
        if not isinstance(value["load_balancer"], Mapping):
            raise DoRuleError("Prices: load_balancer must map size units to cents")
        out["load_balancer"] = {str(u): cents(c, f"load_balancer {u}") for u, c in value["load_balancer"].items()}
    if "spaces" in value:
        out["spaces"] = cents(value["spaces"], "spaces")
    return out


def price_layers(
    account: Mapping[str, Any] | None = None, install: Mapping[str, Any] | None = None
) -> list[tuple[str, Mapping[str, Any]]]:
    """The price tables in the order they win: the account's override, then Slipway's. ``install`` is kept for
    an install-wide layer; callers pass None (phase 4 Decision 41: overrides are per account)."""
    layers: list[tuple[str, Mapping[str, Any]]] = []
    if account:
        layers.append(("account", account))
    if install:
        layers.append(("install", install))
    layers.append(("table", PRICES))
    return layers


def _lookup(layers: Sequence[tuple[str, Mapping[str, Any]]], path: Sequence[str], what: str) -> tuple[int, str, str]:
    for source, table in layers:
        node: Any = table
        for key in path:
            node = node.get(key) if isinstance(node, Mapping) else None
            if node is None:
                break
        if isinstance(node, int) and not isinstance(node, bool):
            return node, source, str(table.get("as_of") or PRICES["as_of"])
    raise DoRuleError(f"Slipway has no price for {what}; set one on the account")


def _api_cents(value: Any) -> int:
    return int((Decimal(str(value)) * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def dollars(cents: int) -> str:
    """Cents as the figure people type: ``8400`` is ``"84.00"``."""
    sign = "-" if cents < 0 else ""
    return f"{sign}{abs(cents) // 100}.{abs(cents) % 100:02d}"


def delta_text(old_cents: int, new_cents: int) -> str:
    d = new_cents - old_cents
    return f"{'+' if d >= 0 else '-'}${dollars(abs(d))} a month"


def _gb(memory_mb: Any) -> str:
    gb = Decimal(int(memory_mb)) / 1024
    return f"{gb.normalize():f}"


@dataclass
class CostLine:
    object: str  # droplet, database, load_balancer, spaces, vpc, firewall, certificate
    label: str
    count: int
    unit_cents: int
    cents: int
    source: str  # api, table, account, install, or none for the free objects

    def to_json(self) -> dict[str, Any]:
        return {"object": self.object, "label": self.label, "count": self.count, "unit_cents": self.unit_cents,
                "cents": self.cents, "amount": dollars(self.cents), "source": self.source}


@dataclass
class Cost:
    lines: list[CostLine] = field(default_factory=list)
    total_cents: int = 0
    as_of: str = ""

    @property
    def total(self) -> str:
        return dollars(self.total_cents)

    @property
    def note(self) -> str:
        return COST_NOTE.format(as_of=self.as_of)

    def to_json(self) -> dict[str, Any]:
        return {"lines": [line.to_json() for line in self.lines], "total_cents": self.total_cents,
                "total": self.total, "as_of": self.as_of, "note": self.note}


def make_plan(*, droplets: int, droplet_size: str, db_size: str, db_nodes: int, db_version: str) -> dict[str, Any]:
    """``cloud.plan`` (§12.1): every object the environment may have."""
    if droplets not in (1, 2):
        raise DoRuleError("A DigitalOcean environment has one droplet or two (Blue/Green)")
    if db_nodes not in (1, 2):
        raise DoRuleError("A cluster has one node, or two with a standby")
    return {"droplets": droplets, "droplet_size": droplet_size, "db_size": db_size, "db_nodes": db_nodes,
            "db_version": str(db_version), "lb_size_unit": 1, "bucket": 1, "certificates": 1, "vpc": 1,
            "firewall": 1}


def cost(
    plan: Mapping[str, Any], catalog: Mapping[str, Any],
    prices: Sequence[tuple[str, Mapping[str, Any]]] | None = None,
) -> Cost:
    """The plan's estimated monthly cost (§12.1).

    Droplets are priced from the catalog's ``price_monthly`` (DigitalOcean's ``GET /sizes``); the
    database, load balancer and Spaces from ``prices`` (``price_layers(account, install)``; Slipway's
    own table when None). ``as_of`` is the oldest date among the tables a price came from, so an old
    override never hides behind a newer table. A price no table has fails with what to set.
    """
    layers = list(prices) if prices is not None else price_layers()
    lines: list[CostLine] = []
    dates: list[str] = []

    n = int(plan["droplets"])
    size = plan["droplet_size"]
    entry = _sizes(catalog).get(size)
    if entry is None or entry.get("price_monthly") is None:
        raise DoRuleError(f"DigitalOcean doesn't price droplet size {size} in {catalog.get('region')}")
    unit = _api_cents(entry["price_monthly"])
    lines.append(CostLine("droplet", f"{n} × droplet {size} ({entry.get('vcpus')} vCPU, "
                                     f"{_gb(entry.get('memory') or 0)} GB, {entry.get('disk')} GB)",
                          n, unit, n * unit, "api"))

    db_size, nodes = plan["db_size"], int(plan["db_nodes"])
    unit, source, as_of = _lookup(layers, ("database", db_size, str(nodes)), f"database {db_size} with {nodes} "
                                  f"node{'s' if nodes != 1 else ''}")
    lines.append(CostLine("database", f"Database cluster {db_size} × {nodes} node{'s' if nodes != 1 else ''}, "
                                      f"PostgreSQL {plan['db_version']}", 1, unit, unit, source))
    dates.append(as_of)

    units = int(plan.get("lb_size_unit") or 1)
    unit, source, as_of = _lookup(layers, ("load_balancer", str(units)), f"a load balancer of {units} node"
                                  f"{'s' if units != 1 else ''}")
    lines.append(CostLine("load_balancer", f"Load balancer, {units} node{'s' if units != 1 else ''}",
                          1, unit, unit, source))
    dates.append(as_of)

    unit, source, as_of = _lookup(layers, ("spaces",), "the Spaces subscription")
    lines.append(CostLine("spaces", "Spaces subscription (per account; already paid if the account uses Spaces)",
                          1, unit, unit, source))
    dates.append(as_of)

    for obj, label in (("vpc", "VPC"), ("firewall", "Cloud firewall"), ("certificate", "Certificate")):
        lines.append(CostLine(obj, label, 1, 0, 0, "none"))

    return Cost(lines=lines, total_cents=sum(line.cents for line in lines), as_of=min(dates))


def parse_confirm(typed: Any) -> str | None:
    """The figure a person typed to confirm a cost, as ``"84.00"``, or None when it isn't one.

    A leading ``$`` and surrounding spaces are ignored; otherwise it must be the figure as shown, with
    its two decimals (``84`` doesn't confirm ``84.00``: typing what is shown proves it was read).
    """
    text = str(typed if typed is not None else "").strip()
    text = text[1:].strip() if text.startswith("$") else text
    if not re.fullmatch(r"(0|[1-9][0-9]{0,8})\.[0-9]{2}", text):
        return None
    return text


def confirm_problem(typed: Any, estimate: Cost) -> str | None:
    """The 422 text when ``typed`` isn't the estimate's total, else None (§12.2)."""
    if parse_confirm(typed) == estimate.total:
        return None
    return f"Type {estimate.total} to confirm about ${estimate.total} a month"
