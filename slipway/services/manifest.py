"""``slipway.yml``: an app that describes how it is deployed.

A repository with a manifest is deployed as an *app* (``BuildSource.APP``). The manifest names
the settings Slipway asks for, the values Slipway sets, the secrets it generates once and keeps,
the services and the variables that set their host ports, the commands that build, start and stop
the app, and the Compose projects those commands create. Slipway knows nothing about the app
beyond that, so any app can be deployed the same way::

    version: 1
    name: ServerSherpa
    env_file: deploy/stack/env.example     # defaults, written in this order
    placeholder: CHANGEME                  # refuse to deploy while a value is still this
    settings:                              # asked for on the instance
      STACK_DOMAIN: {label: Base domain, required: true, example: uat.example.com}
    vars:                                  # set by Slipway
      STACK_ENV: "{slipway.slug}"
      STACK_REPO_DIR: "{slipway.release}"
    secrets:                               # generated once, kept with the instance
      SS_JWT_SECRET: hex
      SS_TOTP_ENCRYPTION_KEY: fernet
    services:
      api: {port: 8000, port_var: STACK_API_PORT, hostname: "api.{STACK_DOMAIN}"}
      wiki: {port: 8096, port_var: STACK_WIKI_PORT, hostname: "wiki.{STACK_DOMAIN}", optional: true}
    optional_services: {var: STACK_APPS, none: none}
    projects: ["{STACK_ENV}-api", "{STACK_ENV}-web"]
    images: ["example-api:{slipway.sha12}", "example-web:{slipway.sha12}"]   # what a release builds
    commands:
      build: [deploy/stack/ss-stack, build, "{slipway.env_dir}"]
      start: [deploy/stack/ss-stack, up, "{slipway.env_dir}"]
      stop: [deploy/stack/ss-stack, down, "{slipway.env_dir}"]

Templates: ``{slipway.<name>}`` is one of ``BUILTINS``, and ``{KEY}`` is the value ``KEY`` has in
the app's ``.env``. A secret can't be used, nor a value the instance's own environment variables set
(what templates render is stored with the instance and shown in the deploy log). ``vars`` are rendered
in order, each seeing the ones before it. ``{{`` and ``}}`` are literal braces.

Slipway writes the ``.env`` from ``env_file``: the lines for the keys it sets get their values, and every
other line is kept exactly as written, so Compose reads it as before.

An app with data says so too (all optional; a manifest without them deploys as before)::

    secrets:
      SS_PASSWORD_PEPPER: {kind: hex, identity: true}   # the data can't be used without it
    data:
      app: serversherpa                                 # what snapshots are matched on
      format: pg-custom                                 # what dump writes and restore reads
      volumes: [{name: "ss-{STACK_ENV}-db_pgdata", holds: database}]
    commands:
      data_up: [deploy/stack/ss-stack, data, "{slipway.env_dir}"]
      dump: [deploy/stack/ss-stack, pgdump, "{slipway.env_dir}", "{slipway.out}"]
      verify_dump: {run: [docker, run, --rm, -i, "postgres:16-alpine", pg_restore, --list], stdin: true}
    first_admin:
      command: [deploy/stack/ss-stack, admin, "{slipway.env_dir}", --email, "{admin.email}"]
      fields: {email: {label: Email, kind: email}}
      password: {stdin: true, args: [--password-stdin]}
    timeouts: {restore: 120}                            # minutes

``{slipway.out}``, ``{slipway.in}`` and ``{admin.<field>}`` are *slots*: values Slipway fills in when it
runs the command (a file it names, or what an operator typed). Each is a whole argument, and ``plan``
leaves it as ``{"slot": ...}`` for the deployer to fill in and quote. docs/manifest.md has the whole format.

Everything here is pure: parsing, checking, rendering. The deployer does the I/O.
"""

from __future__ import annotations

import base64
import posixpath
import re
import secrets as _secrets
from dataclasses import dataclass, field
from typing import Any

import yaml

DEFAULT_FILE = "slipway.yml"
MAX_BYTES = 256 * 1024

ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\Z")
SERVICE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}\Z")  # what Compose accepts as a project name
# An image a release builds, with its tag: Slipway removes it once the release is gone.
IMAGE_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
HOSTNAME_RE = re.compile(r"^(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
_SAFE_PATH = re.compile(r"^[A-Za-z0-9._/@+-]+\Z")
_PLACEHOLDER = re.compile(r"\{\{|\}\}|\{([^{}]*)\}|[{}]")
_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")
# Values written to .env without quotes: what a shell sourcing the file and Compose both read the same way.
_RAW_VALUE = re.compile(r"^[A-Za-z0-9._+/=:@%^*!?,-]*\Z")

# {slipway.<name>} in a template.
BUILTINS = ("slug", "name", "release", "env_dir", "sha", "sha12", "host", "deployment")
# Only start is required. The rest after stop are about the app's data (docs/manifest.md says what each does).
COMMANDS = ("build", "start", "stop", "has_data", "data_up", "dump", "verify_dump", "revision", "accepts", "restore",
            "export_files", "import_files", "after_import", "seed")
SECRET_KINDS = ("hex", "fernet", "token")

# The commands that move a file, the slot that names it and the stream flag that can replace the slot:
# {slipway.out} is the file a command writes, {slipway.in} the one it reads.
FILE_COMMANDS: dict[str, tuple[str, str]] = {
    "dump": ("out", "stdout"), "export_files": ("out", "stdout"),
    "verify_dump": ("in", "stdin"), "accepts": ("in", "stdin"), "restore": ("in", "stdin"), "import_files": ("in", "stdin"),
}
# How long each command may run, in minutes, unless slipway.yml's timeouts say otherwise.
DEFAULT_TIMEOUTS = {
    "build": 60, "start": 60, "stop": 15, "has_data": 2, "data_up": 15, "dump": 120, "verify_dump": 30, "revision": 2,
    "accepts": 2, "restore": 240, "export_files": 240, "import_files": 240, "after_import": 30, "seed": 30,
    "first_admin": 10,
}
MAX_TIMEOUT = 1440  # minutes: a day
# What the pages and endpoints offer an app, in this order (Manifest.capabilities).
CAPABILITIES = ("backup", "verify", "restore", "revision_check", "files", "reset", "snapshot", "seed", "first_admin",
                "starter_content")
HOLDS = ("database", "files", "other")
MAX_IDENTITY = 16

APP_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}\Z")
DATA_FORMAT_RE = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,39}\Z")
VOLUME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\Z")  # a Docker volume name
FIELD_RE = re.compile(r"^[a-z][a-z0-9_]{0,30}\Z")
PASSWORD_VAR_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}\Z")
# Variables the shell or the dynamic loader reads for itself: a password put in one would be acted on.
_SHELL_VARS = frozenset({"PATH", "HOME", "SHELL", "IFS", "ENV", "BASH_ENV", "CDPATH", "PS4", "USER", "LOGNAME"})
_PROGRAM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*\Z")
_WHOLE = re.compile(r"^\{([^{}]*)\}\Z")


class ManifestError(ValueError):
    pass


# ------------------------------------------------------------------------- model


@dataclass(frozen=True)
class Setting:
    key: str
    label: str
    help: str = ""
    example: str = ""
    default: str = ""
    required: bool = False


@dataclass(frozen=True)
class Secret:
    key: str
    kind: str = "hex"
    bytes: int = 32
    identity: bool = False  # the app's data can't be used without it: it travels with backups and snapshots

    def generate(self) -> str:
        raw = _secrets.token_bytes(self.bytes)
        if self.kind == "hex":
            return raw.hex()
        if self.kind == "fernet":
            return base64.urlsafe_b64encode(raw).decode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")


@dataclass(frozen=True)
class Service:
    name: str
    port: int | None = None
    port_var: str | None = None
    protocol: str = "tcp"
    hostname: str | None = None  # template
    optional: bool = False
    default: bool = True  # an optional service is on unless this is false


@dataclass(frozen=True)
class Volume:
    name: str  # template
    holds: str  # database, files or other


@dataclass(frozen=True)
class DataFiles:
    format: str
    label: str = "Files"


@dataclass(frozen=True)
class DataSpec:
    """What slipway.yml says about the app's data (``data:``). Every field is optional."""

    app: str | None = None
    format: str | None = None
    volumes: tuple[Volume, ...] = ()
    files: DataFiles | None = None
    identity_label: str = "identity keys"
    identity_help: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "app": self.app, "format": self.format,
            "volumes": [{"name": v.name, "holds": v.holds} for v in self.volumes],
            "files": {"format": self.files.format, "label": self.files.label} if self.files else None,
            "identity_label": self.identity_label, "identity_help": self.identity_help,
        }


@dataclass(frozen=True)
class AdminField:
    name: str
    label: str
    kind: str = "text"  # text or email
    help: str = ""
    max: int = 200


@dataclass(frozen=True)
class AdminPassword:
    """How the first admin's password reaches the command: on its stdin, or (``env``) in that variable."""

    min_length: int = 8
    env: str | None = None
    args: tuple[str, ...] = ()  # templates, appended in password mode

    @property
    def mode(self) -> str:
        return "env" if self.env else "stdin"


@dataclass(frozen=True)
class AdminInvite:
    label: str
    args: tuple[str, ...] = ()  # templates, appended in invite mode


@dataclass(frozen=True)
class FirstAdmin:
    command: tuple[str, ...]  # templates and {admin.<field>} slots
    fields: tuple[AdminField, ...]
    help: str = ""
    password: AdminPassword | None = None
    invite: AdminInvite | None = None
    done_codes: tuple[int, ...] = (0,)
    exists_codes: tuple[int, ...] = ()
    messages: dict[int, str] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "help": self.help,
            "fields": [f.__dict__ for f in self.fields],
            "password": {"min_length": self.password.min_length, "mode": self.password.mode} if self.password else None,
            "invite": {"label": self.invite.label} if self.invite else None,
            "done_codes": list(self.done_codes), "exists_codes": list(self.exists_codes),
            "messages": {str(code): text for code, text in self.messages.items()},
        }


@dataclass(frozen=True)
class Manifest:
    name: str
    env_file: str | None = None
    placeholder: str | None = None
    settings: tuple[Setting, ...] = ()
    vars: dict[str, str] = field(default_factory=dict)
    secrets: tuple[Secret, ...] = ()
    services: tuple[Service, ...] = ()
    optional_var: str | None = None
    optional_none: str = ""
    projects: tuple[str, ...] = ()
    images: tuple[str, ...] = ()
    commands: dict[str, tuple[str, ...]] = field(default_factory=dict)  # argv templates (slots kept as written)
    streams: dict[str, str] = field(default_factory=dict)  # command: "stdout" or "stdin", for those in stream mode
    data: DataSpec = field(default_factory=DataSpec)
    first_admin: FirstAdmin | None = None
    timeouts: dict[str, int] = field(default_factory=dict)  # minutes, as slipway.yml sets them

    # -- what the instance chooses

    @property
    def optional_services(self) -> list[Service]:
        return [s for s in self.services if s.optional]

    def services_on(self, chosen: list[str] | None) -> list[Service]:
        """The services that run: every required one, and the optional ones ``chosen`` names
        (``None``: each optional service's default)."""
        out = []
        for s in self.services:
            if not s.optional:
                out.append(s)
            elif (s.name in chosen) if chosen is not None else s.default:
                out.append(s)
        return out

    def setting_keys(self) -> set[str]:
        return {s.key for s in self.settings}

    def slipway_keys(self) -> set[str]:
        """Keys Slipway sets itself, which the instance's own variables may not change."""
        keys = set(self.vars) | {s.port_var for s in self.services if s.port_var}
        if self.optional_var:
            keys.add(self.optional_var)
        return keys

    def secret_keys(self) -> set[str]:
        return {s.key for s in self.secrets}

    def identity_keys(self) -> list[str]:
        """The secrets the app's data is made with, in slipway.yml's order."""
        return [s.key for s in self.secrets if s.identity]

    # -- what the app can do with its data

    def capabilities(self) -> tuple[str, ...]:
        """The data features slipway.yml makes possible, in ``CAPABILITIES`` order."""
        has = set(self.commands)
        on = {
            "backup": "dump" in has,
            "verify": "verify_dump" in has,
            "restore": {"dump", "restore"} <= has,  # parse also made sure of stop and data_up
            "revision_check": {"revision", "accepts"} <= has,
            "files": "export_files" in has,
            "reset": "restore" in has and bool(self.data.volumes),
            "snapshot": "dump" in has,
            "seed": "restore" in has,
            "first_admin": self.first_admin is not None,
            "starter_content": "seed" in has,
        }
        return tuple(c for c in CAPABILITIES if on[c])

    def timeout(self, command: str) -> int:
        """How long ``command`` (or ``first_admin``) may run, in seconds."""
        return self.timeouts.get(command, DEFAULT_TIMEOUTS[command]) * 60

    def to_json(self) -> dict[str, Any]:
        """What the API and the instance page show (and what is stored with the instance)."""
        timed = [*self.commands, *(["first_admin"] if self.first_admin else [])]
        return {
            "name": self.name,
            "env_file": self.env_file,
            "placeholder": self.placeholder,  # a restored identity value may not be it (§9.3)
            "settings": [s.__dict__ for s in self.settings],
            "vars": dict(self.vars),
            "secrets": [{"key": s.key, "kind": s.kind, "identity": s.identity} for s in self.secrets],
            "services": [s.__dict__ for s in self.services],
            "optional_var": self.optional_var,
            "projects": list(self.projects),
            "images": list(self.images),
            "commands": {k: list(v) for k, v in self.commands.items()},
            "streams": dict(self.streams),
            "data": self.data.to_json(),
            "first_admin": self.first_admin.to_json() if self.first_admin else None,
            "timeouts": {k: self.timeout(k) // 60 for k in timed},  # minutes, the defaults filled in
            "capabilities": list(self.capabilities()),
        }


# ----------------------------------------------------------------------- parsing


def _err(where: str, message: str) -> ManifestError:
    return ManifestError(f"slipway.yml: {where}: {message}")


def _mapping(value: Any, where: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise _err(where, "must be a mapping")
    return value


def _str(value: Any, where: str, *, max_len: int = 500, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        # YAML has already changed a bare number (3.10 is 3.1, 0755 is 493), so it can't be taken as text.
        raise _err(where, 'must be text: put numbers, versions and octal values in quotes, such as "3.10"')
    text = value
    if not text and not allow_empty:
        raise _err(where, "must not be empty")
    if len(text) > max_len or any(c in text for c in "\r\n\x00"):
        raise _err(where, f"must be one line of at most {max_len} characters")
    return text


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise _err(where, "must be true or false")
    return value


def _only(data: dict[str, Any], allowed: tuple[str, ...], where: str) -> None:
    unknown = sorted(set(data) - set(allowed))
    if unknown:
        raise _err(where, f"unknown key{'s' if len(unknown) > 1 else ''} {', '.join(map(str, unknown))} "
                          f"(allowed: {', '.join(allowed)})")


def _env_key(key: Any, where: str) -> str:
    if not isinstance(key, str) or not ENV_KEY_RE.match(key):
        raise _err(where, f"{key!r} is not a valid environment variable name")
    return key


def clean_repo_path(value: Any, where: str) -> str:
    """A path inside the repository: relative, no ``..``, no option-looking names."""
    text = _str(value, where, max_len=255)
    norm = posixpath.normpath(text)
    if norm.startswith("/") or norm == "." or norm.split("/")[0] == ".." or norm.startswith("-") \
            or not _SAFE_PATH.match(norm):
        raise _err(where, f"'{text}' is not a safe path inside the repository")
    return norm


def clean_manifest_file(path: str) -> str:
    """The manifest's path in the repository: a ``.yml`` or ``.yaml`` file (raises ValueError otherwise)."""
    if not path.lower().endswith((".yml", ".yaml")):
        raise ValueError(f"'{path}' is not a .yml or .yaml file")
    return path


def _port(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise _err(where, "must be a port number, 1-65535")
    return value


def parse(text: str) -> Manifest:
    """Parse and check a manifest; raise ManifestError naming what is wrong."""
    if len(text.encode("utf-8", "replace")) > MAX_BYTES:
        raise ManifestError(f"slipway.yml is larger than {MAX_BYTES // 1024} KB")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ManifestError(f"slipway.yml is not valid YAML: {exc}") from None
    data = _mapping(data, "the file")
    _only(data, ("version", "name", "env_file", "placeholder", "settings", "vars", "secrets", "services",
                 "optional_services", "projects", "images", "commands", "data", "first_admin", "timeouts"), "the file")
    if data.get("version") != 1:
        raise _err("version", "must be 1")
    name = _str(data.get("name"), "name", max_len=100)
    env_file = clean_repo_path(data["env_file"], "env_file") if data.get("env_file") is not None else None
    placeholder = _str(data["placeholder"], "placeholder", max_len=100) if data.get("placeholder") is not None else None

    taken: dict[str, str] = {}

    def claim(key: str, what: str) -> None:
        if key in taken:
            raise _err(what, f"{key} is already set by {taken[key]}")
        taken[key] = what

    settings = []
    for key, spec in _mapping(data.get("settings"), "settings").items():
        where = f"settings.{key}"
        _env_key(key, where)
        spec = _mapping(spec, where)
        _only(spec, ("label", "help", "example", "default", "required"), where)
        claim(key, where)
        settings.append(Setting(
            key=key,
            label=_str(spec.get("label", key), f"{where}.label", max_len=100),
            help=_str(spec.get("help", ""), f"{where}.help", allow_empty=True),
            example=_str(spec.get("example", ""), f"{where}.example", allow_empty=True),
            default=_str(spec.get("default", ""), f"{where}.default", allow_empty=True),
            required=_bool(spec.get("required", False), f"{where}.required"),
        ))

    variables = {}
    for key, value in _mapping(data.get("vars"), "vars").items():
        _env_key(key, f"vars.{key}")
        claim(key, f"vars.{key}")
        variables[key] = _str(value, f"vars.{key}", max_len=1000, allow_empty=True)
        check_template(variables[key], f"vars.{key}")

    secret_list = []
    for key, spec in _mapping(data.get("secrets"), "secrets").items():
        where = f"secrets.{key}"
        _env_key(key, where)
        claim(key, where)
        if isinstance(spec, str):
            spec = {"kind": spec}
        spec = _mapping(spec, where)
        _only(spec, ("kind", "bytes", "identity"), where)
        kind = spec.get("kind", "hex")
        if kind not in SECRET_KINDS:
            raise _err(f"{where}.kind", f"must be one of {', '.join(SECRET_KINDS)}")
        size = spec.get("bytes", 32)
        if isinstance(size, bool) or not isinstance(size, int) or not 16 <= size <= 128:
            raise _err(f"{where}.bytes", "must be a whole number from 16 to 128")
        if kind == "fernet" and size != 32:
            raise _err(f"{where}.bytes", "a Fernet key is always 32 bytes")
        identity = _bool(spec.get("identity", False), f"{where}.identity")
        secret_list.append(Secret(key=key, kind=kind, bytes=size, identity=identity))
    if sum(s.identity for s in secret_list) > MAX_IDENTITY:
        raise _err("secrets", f"at most {MAX_IDENTITY} can be identity secrets")

    services = []
    ports_used: dict[tuple[int, str], str] = {}
    for svc, spec in _mapping(data.get("services"), "services").items():
        where = f"services.{svc}"
        if not isinstance(svc, str) or not SERVICE_RE.match(svc):
            raise _err(where, "a service name is lowercase letters, digits, '-' and '_'")
        spec = _mapping(spec, where)
        _only(spec, ("port", "port_var", "protocol", "hostname", "optional", "default"), where)
        port = _port(spec["port"], f"{where}.port") if spec.get("port") is not None else None
        port_var = _env_key(spec["port_var"], f"{where}.port_var") if spec.get("port_var") is not None else None
        if port_var and port is None:
            raise _err(where, "port_var needs the default port in port")
        if port_var:
            claim(port_var, f"{where}.port_var")
        protocol = spec.get("protocol", "tcp")
        if protocol not in ("tcp", "udp"):
            raise _err(f"{where}.protocol", "must be tcp or udp")
        if port is not None:
            if (port, protocol) in ports_used:
                raise _err(f"{where}.port", f"{port}/{protocol} is also {ports_used[(port, protocol)]}'s port")
            ports_used[(port, protocol)] = svc
        hostname = spec.get("hostname")
        if hostname is not None:
            hostname = _str(hostname, f"{where}.hostname", max_len=253)
            check_template(hostname, f"{where}.hostname")
            if port is None or protocol != "tcp":
                raise _err(where, "a hostname needs a tcp port")
        services.append(Service(
            name=svc, port=port, port_var=port_var, protocol=protocol, hostname=hostname,
            optional=_bool(spec.get("optional", False), f"{where}.optional"),
            default=_bool(spec.get("default", True), f"{where}.default"),
        ))

    opt = _mapping(data.get("optional_services"), "optional_services")
    _only(opt, ("var", "none"), "optional_services")
    optional_var = _env_key(opt["var"], "optional_services.var") if opt.get("var") is not None else None
    if optional_var:
        claim(optional_var, "optional_services.var")
    if any(s.optional for s in services) and not optional_var:
        raise _err("optional_services", "set var: the variable that lists the optional services that run")
    optional_none = _str(opt.get("none", ""), "optional_services.none", max_len=50, allow_empty=True)

    projects = tuple(_template_list(data.get("projects"), "projects", 20))
    images = tuple(_template_list(data.get("images"), "images", 30))

    commands: dict[str, tuple[str, ...]] = {}
    streams: dict[str, str] = {}
    for key, spec in _mapping(data.get("commands"), "commands").items():
        where = f"commands.{key}"
        if key not in COMMANDS:
            raise _err(where, f"unknown command (allowed: {', '.join(COMMANDS)})")
        commands[key], stream = _command(key, spec, where)
        if stream:
            streams[key] = stream
    if "start" not in commands:
        raise _err("commands", "start is required: the command that starts or updates the app")

    data_spec = _data(data.get("data"))
    first_admin = _first_admin(data["first_admin"], taken) if data.get("first_admin") is not None else None
    _check_data_rules(commands, data_spec)
    timeouts = _timeouts(data.get("timeouts"), commands, first_admin)

    return Manifest(
        name=name, env_file=env_file, placeholder=placeholder, settings=tuple(settings), vars=variables,
        secrets=tuple(secret_list), services=tuple(services), optional_var=optional_var, optional_none=optional_none,
        projects=projects, images=images, commands=commands, streams=streams, data=data_spec, first_admin=first_admin,
        timeouts=timeouts,
    )


def _template_list(value: Any, where: str, limit: int) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > limit:
        raise _err(where, f"must be a list of at most {limit}")
    out = []
    for i, item in enumerate(value):
        text = _str(item, f"{where}[{i}]", max_len=200)
        check_template(text, f"{where}[{i}]")
        out.append(text)
    return out


# --------------------------------------------------------------- commands and slots


def _slot(name: str) -> str | None:
    """The slot a placeholder names (``out``, ``in`` or ``admin.<field>``), or None for a template value."""
    if name in ("slipway.out", "slipway.in"):
        return name.removeprefix("slipway.")
    if name.startswith("admin."):
        return name
    return None


def _slot_places(slot: str) -> str:
    if slot.startswith("admin."):
        return "first_admin.command"
    places = [f"commands.{k}" for k, (s, _) in FILE_COMMANDS.items() if s == slot]
    return ", ".join(places[:-1]) + " and " + places[-1]


def whole_slot(arg: str) -> str | None:
    """The slot ``arg`` is, when it is exactly one slot token (the only way parse lets a slot be written)."""
    m = _WHOLE.match(arg)
    return _slot(m.group(1)) if m else None


def _argv(value: Any, where: str, *, allowed: Any = lambda slot: False, hint: str = "",
          limit: int = 50) -> tuple[tuple[str, ...], list[str]]:
    """An argv (the program, then its arguments) and the slots it uses. ``allowed(slot)`` says which slots
    it may hold; each must be a whole argument, and never the program. ``hint`` ends the whole-argument message."""
    if not isinstance(value, list) or not value or len(value) > limit:
        raise _err(where, "must be a list: the program, then its arguments"
                   + (f" (at most {limit})" if isinstance(value, list) and value else ""))
    args = tuple(_str(a, f"{where}[{i}]", max_len=1000, allow_empty=i > 0) for i, a in enumerate(value))
    used: list[str] = []
    for i, a in enumerate(args):
        names = [n for n in placeholders(a) if _slot(n) is not None]
        if not names:
            check_template(a, f"{where}[{i}]")
            continue
        if i == 0:
            raise _err(f"{where}[0]", "the program can't be a value filled at run time")
        for n in names:
            if not allowed(_slot(n)):
                raise _err(f"{where}[{i}]", f"{{{n}}} can only be used in {_slot_places(_slot(n))}")
        token = "{" + names[0] + "}"
        if a != token:
            before, _, after = a.partition(token)
            how = (f"write {before.rstrip('=')} and {token} as two arguments" if before.rstrip("=") and not after
                   else "give it an argument of its own")
            raise _err(f"{where}[{i}]", f"{token} must be a whole argument; {how}{hint}")
        used.append(_slot(names[0]) or "")
    return args, used


def _command(key: str, spec: Any, where: str) -> tuple[tuple[str, ...], str | None]:
    """One of commands: a list, or for a command that moves a file, ``{run: [...], stdout|stdin: true}``.
    Returns the argv and its stream (None when the file is a slot, or the command moves none)."""
    if key not in FILE_COMMANDS:
        return _argv(spec, where)[0], None
    slot, flag = FILE_COMMANDS[key]
    token = f"{{slipway.{slot}}}"
    if isinstance(spec, dict):
        other = "stdin" if flag == "stdout" else "stdout"
        if other in spec:
            does = "writes" if flag == "stdout" else "reads"
            raise _err(where, f"{other}: true doesn't fit {key}, which {does} a file: write {{run: [...], {flag}: true}}")
        _only(spec, ("run", flag), where)
        if "run" not in spec:
            raise _err(where, "give the program and its arguments in run")
        if flag not in spec:
            raise _err(where, f"give {flag}: true with run, or write the command as a list with {token}")
        if spec[flag] is not True:
            raise _err(f"{where}.{flag}", f"must be true (or write the command as a list with {token})")
        run = spec["run"]
        if isinstance(run, list) and any(isinstance(a, str) and token in a for a in run):
            raise _err(where, f"give either {token} or {flag}: true, not both")
        return _argv(run, f"{where}.run")[0], flag
    args, used = _argv(spec, where, allowed=lambda s: s == slot, hint=f", or use {flag}: true")
    if len(used) != 1:
        does = "write" if slot == "out" else "read"
        raise _err(where, f"needs {token} exactly once (the file Slipway gives it to {does}), "
                          f"or write it as {{run: [...], {flag}: true}}")
    return args, None


def _text(spec: dict[str, Any], key: str, where: str, default: str, max_len: int) -> str:
    return _str(spec.get(key, default), f"{where}.{key}", max_len=max_len, allow_empty=not default)


def _label(value: Any, pattern: re.Pattern[str], where: str, what: str) -> str:
    text = _str(value, where, max_len=100)
    if not pattern.match(text):
        raise _err(where, what)
    return text


def _data(value: Any) -> DataSpec:
    spec = _mapping(value, "data")
    _only(spec, ("app", "format", "volumes", "files", "identity_label", "identity_help"), "data")
    fmt_rule = "a format label is lowercase letters, digits, '.', '_', '+' and '-', at most 40, such as pg-custom"
    app = _label(spec["app"], APP_ID_RE, "data.app",
                 "an app id is lowercase letters, digits, '.', '_' and '-', at most 64, such as serversherpa") \
        if spec.get("app") is not None else None
    fmt = _label(spec["format"], DATA_FORMAT_RE, "data.format", fmt_rule) if spec.get("format") is not None else None
    raw = spec.get("volumes")
    if raw is None:
        raw = []
    if not isinstance(raw, list) or len(raw) > 20:
        raise _err("data.volumes", "must be a list of at most 20")
    volumes: list[Volume] = []
    for i, entry in enumerate(raw):
        where = f"data.volumes[{i}]"
        entry = _mapping(entry, where)
        _only(entry, ("name", "holds"), where)
        if "name" not in entry or "holds" not in entry:
            raise _err(where, "give name (the volume) and holds (database, files or other)")
        name = _str(entry["name"], f"{where}.name", max_len=255)
        check_template(name, f"{where}.name")
        if entry["holds"] not in HOLDS:
            raise _err(f"{where}.holds", f"must be one of {', '.join(HOLDS)}")
        if any(v.name == name for v in volumes):
            raise _err(f"{where}.name", f"{name} is listed twice")
        volumes.append(Volume(name=name, holds=entry["holds"]))
    files = None
    if spec.get("files") is not None:
        fspec = _mapping(spec["files"], "data.files")
        _only(fspec, ("format", "label"), "data.files")
        if fspec.get("format") is None:
            raise _err("data.files", "give format: a label for what export_files writes and import_files reads")
        files = DataFiles(format=_label(fspec["format"], DATA_FORMAT_RE, "data.files.format", fmt_rule),
                          label=_text(fspec, "label", "data.files", "Files", 40))
    return DataSpec(app=app, format=fmt, volumes=tuple(volumes), files=files,
                    identity_label=_text(spec, "identity_label", "data", "identity keys", 60),
                    identity_help=_text(spec, "identity_help", "data", "", 300))


def _check_data_rules(commands: dict[str, tuple[str, ...]], data: DataSpec) -> None:
    """What the data commands need of each other and of ``data``."""
    def need(message: str) -> ManifestError:
        return ManifestError(f"slipway.yml: {message}")

    has = set(commands)
    if "dump" in has:
        if data.app is None:
            raise need("commands.dump needs data.app: the app's id (such as serversherpa), which snapshots are matched on")
        if data.format is None:
            raise need("commands.dump needs data.format: a label (such as pg-custom) for what dump writes and restore reads")
        if "has_data" not in has and not any(v.holds in ("database", "files") for v in data.volumes):
            raise need("commands.dump needs commands.has_data, or a data.volumes entry that holds: database or files, "
                       "so Slipway can tell an instance with data from a new one")
    if "restore" in has:
        for other, why in (("dump", "Slipway restores only what it backed up"),
                           ("data_up", "Slipway stops the app and starts only the data services before a restore"),
                           ("stop", "Slipway stops the app before replacing its data")):
            if other not in has:
                raise need(f"commands.restore needs commands.{other}: {why}")
    for key, other, why in (
        ("verify_dump", "dump", "it checks the file dump writes"),
        ("revision", "dump", "Slipway records the revision with each backup"),
        ("has_data", "dump", "it tells Slipway whether there is data to back up"),
        ("accepts", "revision", "it is given the revision that revision prints"),
        ("after_import", "restore", "it runs after another instance's data is restored"),
        ("seed", "dump", "Slipway must be able to tell an empty start"),
        ("export_files", "dump", "Slipway backs up the files together with the database"),
    ):
        if key in has and other not in has:
            raise need(f"commands.{key} needs commands.{other}: {why}")
    if ("export_files" in has) != ("import_files" in has) or ("export_files" in has) != (data.files is not None):
        raise need("commands.export_files and commands.import_files come together, with data.files: "
                   "a snapshot taken here must be restorable here")


def _codes(value: Any, where: str, default: tuple[int, ...]) -> tuple[int, ...]:
    if value is None:
        return default
    if not isinstance(value, list) or len(value) > 20:
        raise _err(where, "must be a list of exit codes")
    out: list[int] = []
    for i, code in enumerate(value):
        if isinstance(code, bool) or not isinstance(code, int) or not 0 <= code <= 255:
            raise _err(f"{where}[{i}]", "must be an exit code, 0-255")
        if code in out:
            raise _err(where, f"lists {code} twice")
        out.append(code)
    return tuple(out)


def _admin_args(spec: dict[str, Any], where: str) -> tuple[str, ...]:
    if spec.get("args") is None:
        return ()
    return _argv(spec["args"], f"{where}.args", limit=10)[0]


def _first_admin(value: Any, taken: dict[str, str]) -> FirstAdmin:
    where = "first_admin"
    spec = _mapping(value, where)
    _only(spec, ("help", "command", "fields", "password", "invite", "done_codes", "exists_codes", "messages"), where)

    raw_fields = _mapping(spec.get("fields"), f"{where}.fields")
    if not 1 <= len(raw_fields) <= 8:
        raise _err(f"{where}.fields", "give 1 to 8 fields: what Slipway asks for the first admin")
    fields = []
    for name, fspec in raw_fields.items():
        fwhere = f"{where}.fields.{name}"
        if not isinstance(name, str) or not FIELD_RE.match(name):
            raise _err(fwhere, "a field name is a lowercase letter, then lowercase letters, digits and '_', at most 31")
        fspec = _mapping(fspec, fwhere)
        _only(fspec, ("label", "kind", "help", "max"), fwhere)
        kind = fspec.get("kind", "text")
        if kind not in ("text", "email"):
            raise _err(f"{fwhere}.kind", "must be text or email")
        size = fspec.get("max", 254 if kind == "email" else 200)
        if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= 254:
            raise _err(f"{fwhere}.max", "must be a whole number from 1 to 254")
        fields.append(AdminField(name=name, label=_text(fspec, "label", fwhere, name.replace("_", " ").capitalize(), 60),
                                 kind=kind, help=_text(fspec, "help", fwhere, "", 200), max=size))
    declared = {f.name for f in fields}

    if spec.get("command") is None:
        raise _err(where, "give command: the program that creates the first admin, then its arguments")
    command, used = _argv(spec["command"], f"{where}.command", allowed=lambda s: s.startswith("admin."))
    for i, arg in enumerate(command):
        slot = whole_slot(arg)
        if slot and slot.removeprefix("admin.") not in declared:
            raise _err(f"{where}.command[{i}]", f"{{{slot}}} is not one of the fields ({', '.join(sorted(declared))})")
    for f in fields:
        if f"admin.{f.name}" not in used:
            raise _err(f"{where}.fields.{f.name}", f"isn't used: put {{admin.{f.name}}} in first_admin.command")

    password = None
    if spec.get("password") is not None:
        pwhere = f"{where}.password"
        pspec = _mapping(spec["password"], pwhere)
        _only(pspec, ("min_length", "stdin", "env", "args"), pwhere)
        stdin = _bool(pspec.get("stdin", False), f"{pwhere}.stdin")
        env = pspec.get("env")
        if stdin and env is not None:
            raise _err(pwhere, "give either stdin: true or env: VAR, not both")
        if not stdin and env is None:
            raise _err(pwhere, "give stdin: true (the password as one line on the command's stdin) "
                               "or env: VAR (Slipway puts it in $VAR)")
        if env is not None:
            env = _str(env, f"{pwhere}.env", max_len=64)
            if not PASSWORD_VAR_RE.match(env):
                raise _err(f"{pwhere}.env", f"{env} must be uppercase letters, digits and '_', starting with a letter")
            if env in _SHELL_VARS or env.startswith(("LD_", "DYLD_")):
                raise _err(f"{pwhere}.env", f"{env} can't carry the password (the shell or loader reads it)")
            if env in taken:
                raise _err(f"{pwhere}.env", f"{env} is already set by {taken[env]}; give the password a variable of its own")
        size = pspec.get("min_length", 8)
        if isinstance(size, bool) or not isinstance(size, int) or not 8 <= size <= 128:
            raise _err(f"{pwhere}.min_length", "must be a whole number from 8 to 128")
        password = AdminPassword(min_length=size, env=env, args=_admin_args(pspec, pwhere))

    invite = None
    if spec.get("invite") is not None:
        iwhere = f"{where}.invite"
        ispec = _mapping(spec["invite"], iwhere)
        _only(ispec, ("label", "args"), iwhere)
        invite = AdminInvite(label=_text(ispec, "label", iwhere, "Email them a link to set their password", 60),
                             args=_admin_args(ispec, iwhere))
    if password is None and invite is None:
        raise _err(where, "give password, invite or both: how the first admin signs in for the first time")

    done = _codes(spec.get("done_codes"), f"{where}.done_codes", (0,))
    if not done:
        raise _err(f"{where}.done_codes", "must list at least one exit code")
    exists = _codes(spec.get("exists_codes"), f"{where}.exists_codes", ())
    both = sorted(set(done) & set(exists))
    if both:
        raise _err(where, f"exit code {both[0]} is in both done_codes and exists_codes")
    if len(done) + len(exists) > 20:
        raise _err(where, "done_codes and exists_codes hold at most 20 codes in all")
    messages: dict[int, str] = {}
    for code, text in _mapping(spec.get("messages"), f"{where}.messages").items():
        mwhere = f"{where}.messages.{code}"
        if isinstance(code, bool) or not isinstance(code, int) or not 1 <= code <= 255:
            raise _err(f"{where}.messages", f"{code!r} is not an exit code from 1 to 255")
        if code in done or code in exists:
            what = "a done code" if code in done else "an exists code"
            raise _err(mwhere, f"{code} is {what}; messages are for the codes that fail")
        messages[code] = _str(text, mwhere, max_len=300)
    return FirstAdmin(command=command, fields=tuple(fields), help=_text(spec, "help", where, "", 300), password=password,
                      invite=invite, done_codes=done, exists_codes=exists, messages=messages)


def _timeouts(value: Any, commands: dict[str, tuple[str, ...]], first_admin: FirstAdmin | None) -> dict[str, int]:
    out = {}
    for key, minutes in _mapping(value, "timeouts").items():
        where = f"timeouts.{key}"
        if key not in DEFAULT_TIMEOUTS:
            raise _err(where, f"is not a command (allowed: {', '.join(DEFAULT_TIMEOUTS)})")
        if key not in commands and not (key == "first_admin" and first_admin):
            raise _err(where, f"slipway.yml declares no {key if key == 'first_admin' else 'commands.' + key}")
        if isinstance(minutes, bool) or not isinstance(minutes, int) or not 1 <= minutes <= MAX_TIMEOUT:
            raise _err(where, f"must be a whole number of minutes from 1 to {MAX_TIMEOUT} (a day)")
        out[key] = minutes
    return out


# ---------------------------------------------------------------------- templates


def placeholders(template: str) -> list[str]:
    """The names a template uses, in order."""
    return [m.group(1) for m in _PLACEHOLDER.finditer(template) if m.group(1) is not None]


def check_template(template: str, where: str) -> None:
    for m in _PLACEHOLDER.finditer(template):
        token, name = m.group(0), m.group(1)
        if token in ("{{", "}}"):
            continue
        if name is None:
            raise _err(where, "a lone '{' or '}' (write '{{' or '}}' for a brace)")
        slot = _slot(name)
        if slot is not None:  # a value filled at run time: only where _argv allows it, never in a template
            raise _err(where, f"{{{name}}} can only be used in {_slot_places(slot)}")
        if name.startswith("slipway."):
            if name.removeprefix("slipway.") not in BUILTINS:
                raise _err(where, f"{{{name}}} is not one of {', '.join('slipway.' + b for b in BUILTINS)}")
        elif not ENV_KEY_RE.match(name):
            raise _err(where, f"{{{name}}} is neither a {{slipway.…}} value nor a variable name")


def render(template: str, builtins: dict[str, str], env: dict[str, str], where: str,
           *, hidden: frozenset[str] | set[str] = frozenset(), blocked: dict[str, str] | None = None) -> str:
    """Fill in a template. ``hidden`` keys (the secrets) and ``blocked`` ones (name: why) can't be used."""
    why = {k: "is a secret and can't be used here" for k in hidden}
    why.update(blocked or {})

    def one(m: re.Match[str]) -> str:
        token, name = m.group(0), m.group(1)
        if token == "{{":
            return "{"
        if token == "}}":
            return "}"
        if name is None:
            raise ManifestError(f"{where}: a lone '{token}'")
        if name.startswith("slipway."):
            return builtins[name.removeprefix("slipway.")]
        if name in why:
            raise ManifestError(f"{where}: {{{name}}} {why[name]}")
        if name not in env:
            raise ManifestError(f"{where}: {{{name}}} has no value")
        return env[name]

    return _PLACEHOLDER.sub(one, template)


# -------------------------------------------------------------------------- .env


def parse_env_template(text: str) -> tuple[list[str], dict[str, str]]:
    """The lines of an env file and the values it assigns, read as Compose reads them (the last one wins).

    Unquoted values lose a `` #`` comment and surrounding blanks; single quotes are literal; double quotes
    take ``\\"`` and ``\\\\``. ``${VAR}`` is left as written.
    """
    lines = text.replace("\r\n", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    values: dict[str, str] = {}
    for line in lines:
        m = _ENV_LINE.match(line)
        if m:
            values[m.group(1)] = _env_value(m.group(2))
    return lines, values


def expanding_keys(text: str) -> set[str]:
    """The keys whose value in an env file (the last assignment) is unquoted or double-quoted and holds a
    ``$``: Compose expands those when it reads the file, so their text isn't the value the app gets."""
    keys: set[str] = set()
    for line in text.replace("\r\n", "\n").split("\n"):
        m = _ENV_LINE.match(line)
        if m:
            raw = m.group(2).strip()
            if raw[:1] != "'" and "$" in _env_value(raw):  # the value only: never a # comment after it
                keys.add(m.group(1))
            else:
                keys.discard(m.group(1))
    return keys


def _env_value(raw: str) -> str:
    raw = raw.strip()
    if raw[:1] == "'":
        end = raw.find("'", 1)
        return raw[1:end] if end > 0 else raw[1:]
    if raw[:1] == '"':
        out, i = [], 1
        while i < len(raw):
            c = raw[i]
            if c == "\\" and i + 1 < len(raw) and raw[i + 1] in '"\\':
                out.append(raw[i + 1])
                i += 2
                continue
            if c == '"':
                break
            out.append(c)
            i += 1
        return "".join(out)
    return re.split(r"\s+#", raw, maxsplit=1)[0].strip()


def format_value(value: str, key: str = "the value") -> str:
    """A value as written to .env, so that Compose and a shell sourcing the file both read ``value``.

    Raw when that is safe, else in single quotes (literal for both). Compose reads a quote after a
    backslash as escaped, so a value ending in a backslash, like one with a single quote, goes in double
    quotes with each backslash and double quote escaped. That only works when it has no ``$`` or
    backtick: one with both can't be written so that both read it the same, so it is refused.
    """
    if _RAW_VALUE.match(value):
        return value
    if "'" not in value and not value.endswith("\\"):
        return f"'{value}'"
    if any(c in value for c in "$`"):
        why = "a single quote" if "'" in value else "a backslash at the end"
        raise ManifestError(f"{key}: a value with {why} can't also hold $ or ` in the .env; change one of them")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_env(lines: list[str], values: dict[str, str], keys: list[str] | set[str] | None = None) -> str:
    """The env file: the template's lines, with ``keys`` (default: all of ``values``) set where it assigns
    them and added at the end where it doesn't. Every other line is kept as written."""
    keys = list(values) if keys is None else [k for k in values if k in set(keys)]
    wanted = set(keys)
    out, written = [], set()
    for line in lines:
        m = _ENV_LINE.match(line)
        if m and m.group(1) in wanted:
            key = m.group(1)
            if key in written:  # a later assignment of the same key: drop it, the first one has the value
                continue
            out.append(f"{key}={format_value(values[key], key)}")
            written.add(key)
        else:
            out.append(line)
    rest = [k for k in keys if k not in written]
    if rest:
        out.extend(["", "# Set by Slipway"])
        out.extend(f"{k}={format_value(values[k], k)}" for k in rest)
    return "\n".join(out) + "\n"


# -------------------------------------------------------------------- deploy plan


@dataclass
class AppPlan:
    """Everything a deploy of an app needs, rendered."""

    env: dict[str, str]  # the whole .env, secrets included
    written: list[str]  # the keys Slipway sets in it (the env_file's other lines are kept as written)
    public_env: dict[str, str]  # what templates can use: no secrets, nothing the instance's own variables set
    services: list[Service]
    routes: list[dict[str, Any]]  # [{hostname, service, container}]
    projects: list[str]
    images: list[str]
    # {name: {"argv": [...], "stream": "stdout" | "stdin" | None}}. An argument that is a slot is {"slot": "out" |
    # "in" | "admin.<field>"}, filled in (and quoted) when the command runs; every other one is rendered text.
    commands: dict[str, dict[str, Any]]
    volumes: list[dict[str, str]] = field(default_factory=list)  # [{name, holds}], rendered
    # {"argv": [...], "stream": None, "password_args": [...], "invite_args": [...]}, or None
    first_admin: dict[str, Any] | None = None


def check_instance_env(manifest: Manifest, env: dict[str, str]) -> None:
    """The instance's own variables may not change what Slipway sets."""
    clash = sorted(set(env) & (manifest.slipway_keys() | manifest.setting_keys()))
    if clash:
        raise ManifestError(
            f"{', '.join(clash)} {'is' if len(clash) == 1 else 'are'} set from slipway.yml; remove "
            f"{'it' if len(clash) == 1 else 'them'} from the instance's environment variables "
            "(use the app settings or a port override instead)"
        )


def plan(
    manifest: Manifest,
    *,
    template: str | None,
    builtins: dict[str, str],
    settings: dict[str, str],
    chosen: list[str] | None,
    host_ports: dict[str, int],
    secrets: dict[str, str],
    env: dict[str, str],
) -> AppPlan:
    """Render an app's ``.env``, routes, projects and commands.

    ``host_ports`` maps each running service with a ``port_var`` to the host port it gets. The
    order values win in, last first: the instance's own variables, the secrets, ``vars``, the ports
    and optional services, the settings, the ``env_file`` defaults. (Their keys never overlap, except
    an instance variable replacing a secret or a default.)
    """
    check_instance_env(manifest, env)
    _, defaults = parse_env_template(template or "")
    values = dict(defaults)
    written: list[str] = []

    def put(key: str, value: str) -> None:
        values[key] = value
        if key not in written:
            written.append(key)

    missing = []
    for s in manifest.settings:
        value = (settings.get(s.key) or "").strip() or s.default
        if not value and s.required:
            missing.append(f"{s.label} ({s.key})")
        if value or s.key not in values:
            put(s.key, value)
    if missing:
        raise ManifestError(f"Set {', '.join(missing)} in the app settings of the instance")
    on = manifest.services_on(chosen)
    for s in on:
        if s.port_var:
            put(s.port_var, str(host_ports.get(s.name, s.port)))
    if manifest.optional_var:
        names = [s.name for s in on if s.optional]
        put(manifest.optional_var, ",".join(names) if names else manifest.optional_none)
    # Templates never see a secret, nor a value the instance's own variables set (it may be a password, and
    # what templates render is stored and logged).
    hidden = manifest.secret_keys()
    blocked = {k: "is set in the instance's environment variables and can't be used here" for k in env if k not in hidden}
    # An env_file default Compose expands (${OTHER}) would be copied as its unexpanded text.
    expanding = expanding_keys(template or "")

    def unexpanded() -> dict[str, str]:
        return {k: f"comes from {manifest.env_file} with a $ that Compose expands and Slipway doesn't; "
                   "set it in settings or vars instead" for k in expanding if k not in written}

    # vars in order: each sees the ones before it, never an env_file default of one still to come.
    later = {k: "is set later in vars: list it first" for k in manifest.vars}
    for key, tmpl in manifest.vars.items():
        later.pop(key)
        stale = unexpanded()
        ctx = {k: v for k, v in values.items() if k not in hidden and k not in blocked and k not in stale}
        put(key, render(tmpl, builtins, ctx, f"vars.{key}", hidden=hidden, blocked={**blocked, **stale, **later,
                        key: "is the variable being set"}))
    for s in manifest.secrets:
        put(s.key, secrets[s.key])
    for key, value in env.items():
        put(key, value)
    if manifest.placeholder:
        left = sorted(k for k, v in values.items() if v == manifest.placeholder)
        if left:
            raise ManifestError(
                f"{', '.join(left)} {'is' if len(left) == 1 else 'are'} still {manifest.placeholder}: set "
                f"{'it' if len(left) == 1 else 'them'} as an app setting or environment variable"
            )
    public = {k: v for k, v in values.items() if k not in hidden and k not in blocked}
    stale = unexpanded()
    usable = {k: v for k, v in public.items() if k not in stale}
    blocked = {**blocked, **stale}
    routes = []
    for s in on:
        if s.hostname:
            host = render(s.hostname, builtins, usable, f"services.{s.name}.hostname", hidden=hidden, blocked=blocked).lower()
            if not HOSTNAME_RE.match(host):
                raise ManifestError(f"services.{s.name}.hostname: '{host}' is not a hostname")
            routes.append({"hostname": host, "service": s.name, "container": s.port})
    projects = []
    for i, tmpl in enumerate(manifest.projects):
        name = render(tmpl, builtins, usable, f"projects[{i}]", hidden=hidden, blocked=blocked)
        if not PROJECT_RE.match(name):
            raise ManifestError(f"projects[{i}]: '{name}' is not a Compose project name")
        projects.append(name)
    images = []
    for i, tmpl in enumerate(manifest.images):
        ref = render(tmpl, builtins, usable, f"images[{i}]", hidden=hidden, blocked=blocked)
        if not IMAGE_RE.match(ref):
            raise ManifestError(f"images[{i}]: '{ref}' is not an image name with a tag, such as example-api:1a2b3c4d5e6f")
        images.append(ref)
    def argv(templates: tuple[str, ...], where: str) -> list[Any]:
        """Render a command; a slot stays an object for the deployer to fill in when it runs the command."""
        out: list[Any] = []
        for i, a in enumerate(templates):
            slot = whole_slot(a)
            out.append({"slot": slot} if slot else render(a, builtins, usable, f"{where}[{i}]", hidden=hidden, blocked=blocked))
        return out

    def program_ok(program: str, where: str) -> None:  # argv[0] is never a slot (parse refuses one)
        if "/" in program:
            clean_repo_path(program, where)
        elif not _PROGRAM.match(program):
            raise ManifestError(f"{where}: '{program}' is not a program name or a path in the repository")

    commands = {key: {"argv": argv(t, f"commands.{key}"), "stream": manifest.streams.get(key)}
                for key, t in manifest.commands.items()}
    for key, cmd in commands.items():
        program_ok(cmd["argv"][0], f"commands.{key}[0]")
    first_admin = None
    if manifest.first_admin:
        fa = manifest.first_admin
        first_admin = {
            "argv": argv(fa.command, "first_admin.command"), "stream": None,
            "password_args": argv(fa.password.args, "first_admin.password.args") if fa.password else [],
            "invite_args": argv(fa.invite.args, "first_admin.invite.args") if fa.invite else [],
        }
        program_ok(first_admin["argv"][0], "first_admin.command[0]")
    volumes: list[dict[str, str]] = []
    for i, vol in enumerate(manifest.data.volumes):
        where = f"data.volumes[{i}].name"
        name = render(vol.name, builtins, usable, where, hidden=hidden, blocked=blocked)
        if not VOLUME_RE.match(name):
            raise ManifestError(f"{where}: '{name}' is not a Docker volume name")
        if any(v["name"] == name for v in volumes):
            raise ManifestError(f"{where}: '{name}' is listed twice")
        volumes.append({"name": name, "holds": vol.holds})
    for key in written:
        format_value(values[key], key)  # refuse a value the .env can't hold before anything runs
    return AppPlan(env=values, written=written, public_env=public, services=on, routes=routes, projects=projects, images=images,
                   commands=commands, volumes=volumes, first_admin=first_admin)


def command_argv(command: Any) -> list[Any] | None:
    """A stored command's argv, in either form ``app_state["commands"]`` has held: a list (before data
    commands) or ``{"argv": [...], "stream": ...}``. None when there is none."""
    if isinstance(command, dict):
        command = command.get("argv")
    return list(command) if isinstance(command, list) and command else None


def new_secrets(manifest: Manifest, existing: dict[str, str]) -> dict[str, str]:
    """The manifest's secrets that ``existing`` lacks, generated."""
    return {s.key: s.generate() for s in manifest.secrets if not existing.get(s.key)}
