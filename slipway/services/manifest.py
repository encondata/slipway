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

ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SERVICE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")  # what Compose accepts as a project name
# An image a release builds, with its tag: Slipway removes it once the release is gone.
IMAGE_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_SAFE_PATH = re.compile(r"^[A-Za-z0-9._/@+-]+$")
_PLACEHOLDER = re.compile(r"\{\{|\}\}|\{([^{}]*)\}|[{}]")
_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")
# Values written to .env without quotes: what a shell sourcing the file and Compose both read the same way.
_RAW_VALUE = re.compile(r"^[A-Za-z0-9._+/=:@%^*!?,-]*$")

# {slipway.<name>} in a template.
BUILTINS = ("slug", "name", "release", "env_dir", "sha", "sha12", "host", "deployment")
COMMANDS = ("build", "start", "stop")
SECRET_KINDS = ("hex", "fernet", "token")


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
    commands: dict[str, tuple[str, ...]] = field(default_factory=dict)

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

    def to_json(self) -> dict[str, Any]:
        """What the API and the instance page show (and what is stored with the instance)."""
        return {
            "name": self.name,
            "env_file": self.env_file,
            "settings": [s.__dict__ for s in self.settings],
            "vars": dict(self.vars),
            "secrets": [{"key": s.key, "kind": s.kind} for s in self.secrets],
            "services": [s.__dict__ for s in self.services],
            "optional_var": self.optional_var,
            "projects": list(self.projects),
            "images": list(self.images),
            "commands": {k: list(v) for k, v in self.commands.items()},
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
                 "optional_services", "projects", "images", "commands"), "the file")
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
        _only(spec, ("kind", "bytes"), where)
        kind = spec.get("kind", "hex")
        if kind not in SECRET_KINDS:
            raise _err(f"{where}.kind", f"must be one of {', '.join(SECRET_KINDS)}")
        size = spec.get("bytes", 32)
        if isinstance(size, bool) or not isinstance(size, int) or not 16 <= size <= 128:
            raise _err(f"{where}.bytes", "must be a whole number from 16 to 128")
        if kind == "fernet" and size != 32:
            raise _err(f"{where}.bytes", "a Fernet key is always 32 bytes")
        secret_list.append(Secret(key=key, kind=kind, bytes=size))

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

    commands = {}
    for key, argv in _mapping(data.get("commands"), "commands").items():
        where = f"commands.{key}"
        if key not in COMMANDS:
            raise _err(where, f"unknown command (allowed: {', '.join(COMMANDS)})")
        if not isinstance(argv, list) or not argv or len(argv) > 50:
            raise _err(where, "must be a list: the program, then its arguments")
        args = [_str(a, f"{where}[{i}]", max_len=1000, allow_empty=i > 0) for i, a in enumerate(argv)]
        for i, a in enumerate(args):
            check_template(a, f"{where}[{i}]")
        commands[key] = tuple(args)
    if "start" not in commands:
        raise _err("commands", "start is required: the command that starts or updates the app")

    return Manifest(
        name=name, env_file=env_file, placeholder=placeholder, settings=tuple(settings), vars=variables,
        secrets=tuple(secret_list), services=tuple(services), optional_var=optional_var, optional_none=optional_none,
        projects=projects, images=images, commands=commands,
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
    commands: dict[str, list[str]]


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
    commands = {
        key: [render(a, builtins, usable, f"commands.{key}[{i}]", hidden=hidden, blocked=blocked) for i, a in enumerate(argv)]
        for key, argv in manifest.commands.items()
    }
    for key, argv in commands.items():
        program = argv[0]
        if "/" in program:
            clean_repo_path(program, f"commands.{key}[0]")
        elif not re.match(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$", program):
            raise ManifestError(f"commands.{key}[0]: '{program}' is not a program name or a path in the repository")
    for key in written:
        format_value(values[key], key)  # refuse a value the .env can't hold before anything runs
    return AppPlan(env=values, written=written, public_env=public, services=on, routes=routes, projects=projects, images=images,
                   commands=commands)


def new_secrets(manifest: Manifest, existing: dict[str, str]) -> dict[str, str]:
    """The manifest's secrets that ``existing`` lacks, generated."""
    return {s.key: s.generate() for s in manifest.secrets if not existing.get(s.key)}
