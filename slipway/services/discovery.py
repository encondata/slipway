"""Find containers on a host that Slipway did not deploy, so they can be claimed as instances.

Slipway only knows containers it started itself: Dockerfile-mode containers carry the label
``slipway.instance=<id>`` and compose projects are named ``slipway-<slug>``. Everything else on
the host is *unmanaged*. ``DISCOVER_COMMAND`` lists every container with ``docker container
inspect``, and ``parse`` groups the unmanaged ones: one group per compose project
(``com.docker.compose.project``) and one per standalone container.

The command prints three lines per container, each a kind word and one JSON value:

    container {"id": ..., "name": ..., "image": ..., "state": ..., labels Slipway reads}
    ports <id> {"80/tcp": [{"HostIp": "", "HostPort": "8080"}], ...}
    mounts <id> [{"Type": "volume", "Name": ..., "Destination": ...}, ...]

Ports and mounts are separate lines so that a container with a huge port range only loses its
ports line (cut at ``ssh.MAX_LINE_CHARS``), which is then reported, rather than disappearing.
Lines that are not recognised (warnings, errors, a container removed meanwhile) are skipped.

Nothing here changes anything on the host. Environment variables are not read by the listing;
``env_command`` reads them for one claim, and only when the user asks for it: the containers'
variables, and the project's env files (the ``.env`` Compose read, which also holds values that are
only substituted into the compose file and that no container sees).
"""

from __future__ import annotations

import json
import posixpath
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

q = shlex.quote

_ID_RE = re.compile(r"^[0-9a-f]{64}$")
# Compose project names: lowercase letters, digits, dashes and underscores, starting with a letter or digit.
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,254}$")
_VOLUME_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
MANAGED_PREFIX = "slipway-"


def _label(name: str) -> str:
    return f'(index .Config.Labels "{name}")'


_CONTAINER_FIELDS = {
    "id": ".Id",
    "name": ".Name",
    "image": ".Config.Image",
    "state": ".State.Status",
    "started_at": ".State.StartedAt",
    "network_mode": ".HostConfig.NetworkMode",
    "instance": _label("slipway.instance"),
    "project": _label("com.docker.compose.project"),
    "service": _label("com.docker.compose.service"),
    "working_dir": _label("com.docker.compose.project.working_dir"),
    "config_files": _label("com.docker.compose.project.config_files"),
    # Only set when the project was started with --env-file; otherwise Compose read <working_dir>/.env.
    "env_files": _label("com.docker.compose.project.environment_file"),
}
_FORMAT = (
    "container {" + ",".join(f'"{k}":{{{{json {v}}}}}' for k, v in _CONTAINER_FIELDS.items()) + "}\n"
    "ports {{.Id}} {{json .HostConfig.PortBindings}}\n"
    "mounts {{.Id}} {{json .Mounts}}"
)

# Exits non-zero only when docker itself cannot be used; a container removed between the list
# and the inspect just has no lines. The ids go through xargs: zsh does not split ``$ids``.
DISCOVER_COMMAND = (
    "ids=$(docker ps -aq --no-trunc) || exit 1; "
    f"[ -z \"$ids\" ] || printf '%s\\n' \"$ids\" | xargs docker container inspect --format {q(_FORMAT)} 2>/dev/null; "
    "exit 0"
)


# Env files larger than this are cut (a .env is a few KB).
MAX_ENV_FILE_BYTES = 256 * 1024
_READER_IMAGE = "alpine:3.20"  # the deployer's cleanup image: reads files the SSH user may not


def _env_file_part(index: int, path: str) -> str:
    """Print ``dotenv-begin <i>``, the file as hex (``od``: any bytes, short lines), ``dotenv-end <i>``.

    Or ``dotenv-missing <i>`` / ``dotenv-unreadable <i>``. A file the SSH user cannot read (a root-owned
    .env, mode 600) is read through a throwaway container, as the deployer deletes root-owned files.
    """
    f, d, b = q(path), q(posixpath.dirname(path)), q(posixpath.basename(path))
    via_docker = f"docker run --rm --network none -v {d}:/r:ro {_READER_IMAGE}"
    return (
        f"if [ -r {f} ]; then echo 'dotenv-begin {index}'; head -c {MAX_ENV_FILE_BYTES} -- {f} | od -An -v -tx1; "
        f"echo 'dotenv-end {index}'; "
        f"elif {via_docker} test -f /r/{b} >/dev/null 2>&1; then echo 'dotenv-begin {index}'; "
        f"{via_docker} head -c {MAX_ENV_FILE_BYTES} /r/{b} | od -An -v -tx1; echo 'dotenv-end {index}'; "
        f"elif [ -e {f} ]; then echo 'dotenv-unreadable {index}'; else echo 'dotenv-missing {index}'; fi"
    )


def readable_env_file(path: str) -> bool:
    """An env file path Slipway will try to read: absolute, and usable as a ``docker run -v`` source."""
    norm = posixpath.normpath(path) if path else ""
    return norm.startswith("/") and norm != "/" and ":" not in norm and "\n" not in norm


def env_command(container_ids: list[str], env_files: list[str] | None = None) -> str:
    """Print ``env <id> <container env> <image env>`` (JSON lists) for each container, then each env file.

    The output holds secrets: it is parsed, never logged or stored as text.
    """
    parts = []
    for cid in container_ids:
        if not _ID_RE.match(cid):
            raise ValueError(f"Invalid container id {cid!r}")
        parts.append(
            f"img=$(docker container inspect --format '{{{{.Image}}}}' {cid} 2>/dev/null) && "
            f"printf 'env {cid} %s %s\\n' "
            f"\"$(docker container inspect --format '{{{{json .Config.Env}}}}' {cid})\" "
            f"\"$(docker image inspect --format '{{{{json .Config.Env}}}}' \"$img\" 2>/dev/null || echo '[]')\""
        )
    for index, path in enumerate(env_files or []):
        if not readable_env_file(path):
            raise ValueError(f"Invalid env file path {path!r}")
        parts.append(_env_file_part(index, posixpath.normpath(path)))
    return "; ".join(parts) + "; exit 0" if parts else "exit 0"


# ------------------------------------------------------------------------ results


@dataclass
class Port:
    container: int
    protocol: str
    host: int | None  # None: Docker picks a free port each time the container starts
    host_ip: str = ""
    service: str | None = None


@dataclass
class Mount:
    type: str  # bind, volume, tmpfs, ...
    source: str  # host path for bind mounts, volume name for volumes
    target: str
    read_only: bool = False
    anonymous: bool = False  # a volume Docker named with a random id
    service: str | None = None


@dataclass
class Container:
    id: str
    name: str
    image: str
    state: str
    started_at: str = ""
    network_mode: str = ""
    service: str | None = None
    ports: list[Port] = field(default_factory=list)
    mounts: list[Mount] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)  # "ports" / "mounts" lines that could not be read


@dataclass
class Group:
    """A compose project or a standalone container that Slipway does not manage."""

    kind: str  # "compose" or "container"
    key: str  # "compose:<project>" or "container:<id>"
    name: str  # the project name, or the container name
    state: str  # running, partial (some running), or the containers' state (exited, created, ...)
    containers: list[Container]
    images: list[str]
    ports: list[Port]
    mounts: list[Mount]
    project: str | None = None
    container_id: str | None = None
    working_dir: str | None = None
    config_files: list[str] = field(default_factory=list)
    # Env files Compose read for the project (``--env-file``, else ``<working_dir>/.env`` if it exists).
    env_files: list[str] = field(default_factory=list)
    compose_file: str | None = None  # suggested compose file path in the repository
    warnings: list[str] = field(default_factory=list)

    @property
    def running(self) -> bool:
        return any(c.state == "running" for c in self.containers)


# ------------------------------------------------------------------------ parsing


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _ports(data: Any, service: str | None) -> list[Port]:
    out: list[Port] = []
    if not isinstance(data, dict):
        return out
    for spec, bindings in sorted(data.items()):
        number, _, protocol = str(spec).partition("/")
        if not number.isdigit():
            continue
        for b in bindings or []:
            if not isinstance(b, dict):
                continue
            host = _text(b.get("HostPort"))
            out.append(Port(
                container=int(number), protocol=protocol or "tcp",
                host=int(host) if host.isdigit() and 0 < int(host) < 65536 else None,
                host_ip=_text(b.get("HostIp")), service=service,
            ))
    return out


def _mounts(data: Any, service: str | None) -> list[Mount]:
    out: list[Mount] = []
    if not isinstance(data, list):
        return out
    for m in data:
        if not isinstance(m, dict):
            continue
        kind = _text(m.get("Type"))
        name = _text(m.get("Name"))
        source = name if kind == "volume" and name else _text(m.get("Source"))
        out.append(Mount(
            type=kind, source=source, target=_text(m.get("Destination")),
            read_only=m.get("RW") is False, anonymous=kind == "volume" and bool(_ID_RE.match(name)), service=service,
        ))
    return out


def parse_containers(output: str) -> tuple[list[Container], dict[str, dict[str, str]]]:
    """Containers from ``DISCOVER_COMMAND`` output, with each one's Slipway and compose labels."""
    containers: dict[str, Container] = {}
    labels: dict[str, dict[str, str]] = {}
    pending: dict[str, list[tuple[str, str]]] = {}  # ports/mounts lines seen before their container line
    for line in output.splitlines():
        kind, _, rest = line.partition(" ")
        if kind == "container":
            try:
                data = json.loads(rest)
            except ValueError:
                continue
            cid = _text(data.get("id")) if isinstance(data, dict) else ""
            if not _ID_RE.match(cid):
                continue
            c = Container(
                id=cid, name=_text(data.get("name")).lstrip("/"), image=_text(data.get("image")),
                state=_text(data.get("state")) or "unknown", started_at=_text(data.get("started_at")),
                network_mode=_text(data.get("network_mode")), service=_text(data.get("service")) or None,
            )
            c.unreadable = ["ports", "mounts"]  # until their lines arrive
            containers[cid] = c
            labels[cid] = {
                k: _text(data.get(k)) for k in ("instance", "project", "working_dir", "config_files", "env_files")
            }
            for what, value in pending.pop(cid, []):
                _attach(c, what, value)
        elif kind in ("ports", "mounts"):
            cid, _, value = rest.partition(" ")
            if not _ID_RE.match(cid):
                continue
            if cid in containers:
                _attach(containers[cid], kind, value)
            else:
                pending.setdefault(cid, []).append((kind, value))
    return list(containers.values()), labels


def _attach(c: Container, what: str, value: str) -> None:
    try:
        data = json.loads(value)
    except ValueError:
        return  # stays in c.unreadable
    if what == "ports":
        c.ports = _ports(data, c.service)
    else:
        c.mounts = _mounts(data, c.service)
    c.unreadable = [u for u in c.unreadable if u != what]


def parse(
    output: str, *, claimed_projects: set[str] | frozenset[str] = frozenset(),
    claimed_containers: set[str] | frozenset[str] = frozenset(),
) -> list[Group]:
    """Unmanaged groups in ``DISCOVER_COMMAND`` output, compose projects first, then by name.

    Skipped: containers with a ``slipway.instance`` label, compose projects named ``slipway-...``,
    and what instances already claimed (``claimed_projects`` names, ``claimed_containers`` ids).
    """
    containers, labels = parse_containers(output)
    projects: dict[str, list[Container]] = {}
    standalone: list[Container] = []
    for c in containers:
        lab = labels[c.id]
        project = lab["project"]
        if lab["instance"] or project.startswith(MANAGED_PREFIX) or project in claimed_projects:
            continue
        if c.id in claimed_containers:
            continue
        if project:
            projects.setdefault(project, []).append(c)
        else:
            standalone.append(c)
    groups = [_compose_group(name, members, labels) for name, members in sorted(projects.items())]
    groups += [_container_group(c) for c in sorted(standalone, key=lambda c: c.name)]
    return groups


def _state(containers: list[Container]) -> str:
    states = {c.state for c in containers}
    if states == {"running"}:
        return "running"
    if "running" in states:
        return "partial"
    return states.pop() if len(states) == 1 else "stopped"


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))


def _inside(path: str, directory: str) -> bool:
    """``path`` is ``directory`` or below it. Docker Desktop shows bind sources under ``/host_mnt``."""
    path, directory = posixpath.normpath(path), posixpath.normpath(directory)
    candidates = [path, path.removeprefix("/host_mnt")] if path.startswith("/host_mnt/") else [path]
    return any(p == directory or p.startswith(directory.rstrip("/") + "/") for p in candidates)


def inside(path: str, directory: str) -> bool:
    return _inside(path, directory)


def _port_warnings(ports: list[Port]) -> list[str]:
    out = []
    for p in ports:
        where = f"{p.service} " if p.service else ""
        if p.host is None:
            out.append(f"{where}container port {p.container}/{p.protocol} has no fixed host port; Docker picks one, so it is not copied")
        elif p.protocol not in ("tcp", "udp"):
            out.append(f"Host port {p.host}/{p.protocol} is not TCP or UDP and is not copied")
    return out


def _compose_group(project: str, members: list[Container], labels: dict[str, dict[str, str]]) -> Group:
    members = sorted(members, key=lambda c: (c.service or "", c.name))
    working_dirs = _unique([labels[c.id]["working_dir"] for c in members])
    config_files = _unique([f.strip() for c in members for f in labels[c.id]["config_files"].split(",")])
    working_dir = working_dirs[0] if working_dirs else None
    env_files = _unique([f.strip() for c in members for f in labels[c.id]["env_files"].split(",")])
    if not env_files and working_dir:
        env_files = [posixpath.join(working_dir, ".env")]
    ports = [p for c in members for p in c.ports]
    mounts = [m for c in members for m in c.mounts]
    group = Group(
        kind="compose", key=f"compose:{project}", name=project, state=_state(members), containers=members,
        images=_unique([c.image for c in members]), ports=ports, mounts=mounts, project=project,
        working_dir=working_dir, config_files=config_files, compose_file=_suggest_compose_file(config_files, working_dir),
        env_files=[f for f in env_files if readable_env_file(f)],
    )
    w = group.warnings
    if not PROJECT_RE.match(project):
        w.append(f"The project name {project!r} is not one Slipway can keep; this project cannot be claimed")
    if len(working_dirs) > 1:
        w.append("The containers were started from different directories: " + ", ".join(working_dirs))
    if working_dir:
        for m in mounts:
            if m.type == "bind" and _inside(m.source, working_dir):
                w.append(
                    f"{m.service or 'A service'} mounts {m.source}, inside the project directory. A relative path in "
                    "the compose file (./...) resolves to Slipway's release directory after the claim, so that service "
                    f"would start without this data. Use the absolute path {m.source} in the repository's compose file first."
                )
    w.extend(_port_warnings(ports))
    for c in members:
        w.extend(f"Could not read the {what} of {c.name}" for what in c.unreadable)
    return group


def _container_group(c: Container) -> Group:
    group = Group(
        kind="container", key=f"container:{c.id}", name=c.name, state=c.state, containers=[c],
        images=_unique([c.image]), ports=list(c.ports), mounts=list(c.mounts), container_id=c.id,
    )
    w = group.warnings
    w.extend(_port_warnings(c.ports))
    for p in c.ports:
        if p.host is not None and p.host_ip and p.host_ip not in ("0.0.0.0", "::"):
            w.append(
                f"Host port {p.host} is published only on {p.host_ip}; Slipway publishes ports on all addresses, "
                "so after a deploy it is reachable from outside the host"
            )
    for m in c.mounts:
        if m.type not in ("bind", "volume"):
            w.append(f"The {m.type or 'unknown'} mount at {m.target} is not copied")
        elif m.anonymous:
            w.append(f"The anonymous volume at {m.target} is kept by its id {m.source[:12]}…, so its data stays")
        elif m.type == "bind" and ":" in m.source:
            w.append(f"The bind mount {m.source} contains ':' and is not copied")
        elif m.read_only:
            w.append(f"{m.source} is mounted read-only at {m.target}; Slipway mounts volumes read-write")
    if c.network_mode and c.network_mode not in ("default", "bridge"):
        w.append(f"The container uses the network {c.network_mode!r}; Slipway runs it on the default bridge network")
    w.extend(f"Could not read the {what} of {c.name}" for what in c.unreadable)
    return group


def _suggest_compose_file(config_files: list[str], working_dir: str | None) -> str | None:
    """The first compose file, relative to the project directory (Compose puts it there by default)."""
    if not config_files:
        return None
    first = config_files[0]
    if working_dir and _inside(first, working_dir) and first != working_dir:
        return posixpath.relpath(posixpath.normpath(first), posixpath.normpath(working_dir))
    return posixpath.basename(first) or None


# -------------------------------------------------------------- claiming helpers


def dockerfile_ports(group: Group) -> list[dict[str, Any]]:
    """``Instance.ports`` rows for the ports a standalone container publishes (fixed TCP/UDP ports only)."""
    seen, out = set(), []
    for p in group.ports:
        if p.host is None or p.protocol not in ("tcp", "udp"):
            continue
        key = (p.host, p.protocol)
        if key in seen:  # the same port on IPv4 and IPv6
            continue
        seen.add(key)
        out.append({"host": p.host, "container": p.container, "protocol": p.protocol})
    return out


def dockerfile_volumes(group: Group) -> list[dict[str, Any]]:
    """``Instance.volumes`` rows: named (and anonymous, by id) volumes and bind mounts."""
    out = []
    for m in group.mounts:
        if m.type == "volume" and _VOLUME_NAME_RE.match(m.source):
            source = m.source
        elif m.type == "bind" and m.source.startswith("/") and ":" not in m.source:
            source = m.source
        else:
            continue
        if not m.target.startswith("/") or ":" in m.target:
            continue
        out.append({"source": source, "target": m.target})
    return out


def published_rows(group: Group) -> list[dict[str, Any]]:
    """``Instance.published_ports`` rows for a compose project, as the last deploy would store them."""
    seen, out = set(), []
    for p in group.ports:
        if p.host is None or p.protocol not in ("tcp", "udp"):
            continue
        key = (p.service, p.container, p.protocol, p.host)
        if key in seen:
            continue
        seen.add(key)
        row: dict[str, Any] = {"service": p.service, "container": p.container, "protocol": p.protocol, "host": p.host}
        if p.host_ip and p.host_ip not in ("0.0.0.0", "::"):
            row["host_ip"] = p.host_ip
        out.append(row)
    return out


def parse_env(output: str, container_ids: list[str]) -> tuple[dict[str, str], list[str]]:
    """Variables set on the containers and not inherited unchanged from their images.

    Returns (variables, names skipped because containers disagree on the value or it is unusable).
    """
    found: dict[str, dict[str, str]] = {}
    for line in output.splitlines():
        if not line.startswith("env "):
            continue
        parts = line.split(" ", 2)
        if len(parts) != 3 or parts[1] not in container_ids:
            continue
        own, image = _split_json_lists(parts[2])
        if own is None:
            continue
        inherited = set(image or [])
        found[parts[1]] = {}
        for item in own:
            if not isinstance(item, str) or "=" not in item or item in inherited:
                continue
            key, _, value = item.partition("=")
            found[parts[1]][key] = value
    merged: dict[str, str] = {}
    skipped: set[str] = set()
    for values in found.values():
        for key, value in values.items():
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key) or "\n" in value or "\r" in value or "\x00" in value:
                skipped.add(key)
            elif key in merged and merged[key] != value:
                skipped.add(key)
            else:
                merged.setdefault(key, value)
    for key in skipped:
        merged.pop(key, None)
    return merged, sorted(skipped)


def _split_json_lists(text: str) -> tuple[list[Any] | None, list[Any] | None]:
    """Two JSON lists separated by a space (either may be ``null``)."""
    decoder = json.JSONDecoder()
    try:
        first, end = decoder.raw_decode(text)
        second, _ = decoder.raw_decode(text[end:].lstrip())
    except ValueError:
        return None, None
    as_list = lambda v: v if isinstance(v, list) else ([] if v is None else None)  # noqa: E731
    return as_list(first), as_list(second)


# ----------------------------------------------------------------- env files


@dataclass
class EnvFiles:
    values: dict[str, str] = field(default_factory=dict)  # every file, later files win
    read: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # names whose value Slipway can't store (multi-line, bad name)


def parse_env_files(output: str, env_files: list[str]) -> EnvFiles:
    """The env files in ``env_command`` output, parsed as Compose reads them, in order."""
    result = EnvFiles()
    chunks: dict[int, list[str]] = {}
    done: dict[int, str] = {}
    current: int | None = None
    for line in output.splitlines():
        word, _, rest = line.strip().partition(" ")
        if word in ("dotenv-begin", "dotenv-end", "dotenv-missing", "dotenv-unreadable") and rest.isdigit():
            index = int(rest)
            if word == "dotenv-begin":
                current, chunks[index] = index, []
            else:
                done[index] = "read" if word == "dotenv-end" and current == index else word.removeprefix("dotenv-")
                current = None
        elif current is not None:
            chunks[current].append(line)
    for index, path in enumerate(env_files):
        state = done.get(index, "unreadable")
        if state == "missing":
            result.missing.append(path)
            continue
        if state != "read":
            result.unreadable.append(path)
            continue
        try:
            raw = bytes.fromhex(" ".join(chunks.get(index, [])))
        except ValueError:
            result.unreadable.append(path)
            continue
        result.read.append(path)
        values, skipped = parse_dotenv(raw.decode("utf-8", "replace"), dict(result.values))
        result.values.update(values)
        result.skipped.extend(k for k in skipped if k not in result.skipped)
    for key in list(result.values):
        value = result.values[key]
        if not _ENV_KEY_RE.match(key) or "\n" in value or "\r" in value or "\x00" in value:
            del result.values[key]
            if key not in result.skipped:
                result.skipped.append(key)
    return result


_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DOTENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
_VAR_RE = re.compile(r"\$(?:\$|\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-?+])([^}]*))?\}|([A-Za-z_][A-Za-z0-9_]*))")
_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"', "$": "$$"}


def _interpolate(value: str, known: dict[str, str]) -> str:
    """``$VAR``, ``${VAR}``, ``${VAR:-default}``, ``${VAR-default}``, ``${VAR:+alt}``; ``$$`` is a ``$``.

    Unknown variables become empty, as Compose substitutes them (it also looks at its own process
    environment, which is the SSH user's shell here and not worth copying).
    """
    def sub(m: re.Match[str]) -> str:
        if m.group(0) == "$$":
            return "$"
        name = m.group(1) or m.group(4)
        op, arg = m.group(2), m.group(3) or ""
        value = known.get(name)
        if op in (":-", ":?"):
            return value if value else (_interpolate(arg, known) if op == ":-" else "")
        if op in ("-", "?"):
            return value if value is not None else (_interpolate(arg, known) if op == "-" else "")
        if op == ":+":
            return _interpolate(arg, known) if value else ""
        if op == "+":
            return _interpolate(arg, known) if value is not None else ""
        return value or ""
    return _VAR_RE.sub(sub, value)


def parse_dotenv(text: str, known: dict[str, str] | None = None) -> tuple[dict[str, str], list[str]]:
    """``KEY=value`` lines as Compose's dotenv reader takes them.

    ``export`` prefixes and ``#`` comments are ignored. Single-quoted values are literal; double-quoted
    ones take ``\\n``-style escapes and, like unquoted ones, ``${VAR}`` substitution from earlier lines
    (and ``known``). Unquoted values end at `` #``. Quoted values may span lines. Returns (values,
    names of lines that could not be read).
    """
    known = dict(known or {})
    values: dict[str, str] = {}
    skipped: list[str] = []
    i, n = 0, len(text)
    while i < n:
        end = text.find("\n", i)
        end = n if end < 0 else end
        line = text[i:end].strip()
        if not line or line.startswith("#"):
            i = end + 1
            continue
        if line.startswith("export ") or line.startswith("export\t"):
            line = line[7:].lstrip()
        key, sep, rest = line.partition("=")
        key = key.strip()
        if not sep or not _DOTENV_KEY_RE.match(key):
            if key and key not in skipped and sep:
                skipped.append(key)
            i = end + 1
            continue
        # Where the value starts in ``text`` (quoted values may run past this line).
        start = text.find("=", i) + 1
        while start < n and text[start] in " \t":
            start += 1
        quote = text[start] if start < n else ""
        if quote in ("'", '"'):
            j, out = start + 1, []
            while j < n and text[j] != quote:
                if quote == '"' and text[j] == "\\" and j + 1 < n:
                    out.append(_ESCAPES.get(text[j + 1], "\\" + text[j + 1]))
                    j += 2
                    continue
                out.append(text[j])
                j += 1
            if j >= n:  # no closing quote: Compose refuses the file; skip the line
                skipped.append(key)
                i = end + 1
                continue
            value = "".join(out)
            if quote == '"':
                value = _interpolate(value, known)
            nl = text.find("\n", j)
            i = n if nl < 0 else nl + 1
        else:
            value = text[start:end]
            comment = re.search(r"\s#", value)
            if comment:
                value = value[: comment.start()]
            value = _interpolate(value.strip(), known)
            i = end + 1
        values[key] = known[key] = value
    return values, skipped
