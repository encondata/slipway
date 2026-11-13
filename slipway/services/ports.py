"""Host ports: find what a deployment publishes, what the host already uses, and move clashes.

A deployment publishes host ports from ``Instance.ports`` (Dockerfile mode) or from the compose
file as Compose resolves it on the host (``docker compose config --format json``). Before
anything is started, Slipway lists the ports in use on the host: listening sockets from
``/proc/net`` and the ports Docker publishes for containers, minus the ones this instance's own
containers hold (a redeploy frees them). Ports other Slipway instances on the host were given
count as taken too, even while those instances are stopped.

A port that is taken moves to the next free port above it when the instance allows it
(``Instance.auto_ports``); otherwise the deployment stops before it touches what is running.

In compose mode a moved port is passed back to Compose in one of two ways:

* When the compose file takes the host port from a variable (``"${WEB_PORT:-8080}:80"``),
  Slipway sets that variable, so everything else that interpolates it (``APP_URL:
  http://host:${WEB_PORT}``) gets the new port too.
* Otherwise Slipway writes an override file that replaces the service's ``ports`` with
  ``!override`` (Docker Compose 2.24.4 or later). An older Compose adds those ports instead of
  replacing them, so there Slipway runs the release from the whole resolved compose file with
  the new ports. The repository's files are never changed.

Only the host side of a mapping moves. Container ports stay the same, so services keep
reaching each other on the compose network as before.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from typing import Any

import yaml

PROTOCOLS = ("tcp", "udp")
_VAR_RE = re.compile(r"^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)(?::?-[^}]*)?\}|([A-Za-z_][A-Za-z0-9_]*))$")
_DOCKER_PORT_RE = re.compile(r":(\d+)(?:-(\d+))?->(\d+)(?:-(\d+))?/(tcp|udp|sctp)")
SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

# Prints "proc <file> <local address>" for each listening TCP socket and bound UDP socket, then
# "docker\t<instance label>\t<compose project>\t<name>\t<ports>" for each running container.
SCAN_COMMAND = (
    "for f in tcp tcp6 udp udp6; do [ -r /proc/net/$f ] && "
    "awk -v f=$f 'NR>1 && ($4==\"0A\" || (f ~ /^udp/ && $4==\"07\")) {print \"proc\", f, $2}' /proc/net/$f; done; "
    "docker ps --format "
    "'docker\\t{{.Label \"slipway.instance\"}}\\t{{.Label \"com.docker.compose.project\"}}\\t{{.Names}}\\t{{.Ports}}'"
)


class PortError(RuntimeError):
    pass


@dataclass(frozen=True)
class Binding:
    """One published port: host port ``host`` on the host goes to ``container`` in ``service``."""

    service: str | None  # None in Dockerfile mode
    container: int
    protocol: str
    host: int
    host_ip: str = ""
    var: str | None = None  # compose variable that sets the host port, when it is just ``${VAR}``

    @property
    def key(self) -> tuple[str | None, int, str]:
        return (self.service, self.container, self.protocol)

    def describe(self) -> str:
        where = f"{self.service} " if self.service else ""
        return f"{self.host}/{self.protocol} ({where}container port {self.container})"


# ------------------------------------------------------------------------- reading


def _split_outside_braces(value: str) -> list[str]:
    parts, depth, cur = [], 0, ""
    for ch in value:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
        if ch == ":" and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return parts


def _variable(published: Any) -> str | None:
    if not isinstance(published, str):
        return None
    m = _VAR_RE.match(published.strip())
    return (m.group(1) or m.group(2)) if m else None


def _raw_variables(raw: dict[str, Any] | None) -> dict[tuple[str, int, str], str]:
    """(service, container port, protocol) -> the variable that alone sets its host port.

    ``raw`` is ``docker compose config --no-interpolate --format json``: there Compose keeps a
    short-syntax port with a variable as the string it was written as.
    """
    found: dict[tuple[str, int, str], str] = {}
    for name, svc in ((raw or {}).get("services") or {}).items():
        for p in (svc or {}).get("ports") or []:
            if isinstance(p, dict):
                var, target, proto = _variable(p.get("published")), p.get("target"), p.get("protocol") or "tcp"
            elif isinstance(p, str):
                spec, _, proto = p.partition("/")
                parts = _split_outside_braces(spec)
                if len(parts) not in (2, 3):
                    continue
                var, target, proto = _variable(parts[-2]), parts[-1], proto or "tcp"
            else:
                continue
            if var and str(target).isdigit():
                found[(name, int(target), str(proto))] = var
    return found


def compose_bindings(config: dict[str, Any], raw: dict[str, Any] | None = None) -> list[Binding]:
    """Published ports of a resolved compose config (``docker compose config --format json``).

    Ports without a host port, or with a host port range (Docker picks one), are left out.
    """
    variables = _raw_variables(raw)
    out: list[Binding] = []
    for name, svc in sorted((config.get("services") or {}).items()):
        for p in (svc or {}).get("ports") or []:
            if not isinstance(p, dict):
                continue
            published, target, proto = str(p.get("published") or ""), p.get("target"), p.get("protocol") or "tcp"
            if not published.isdigit() or not isinstance(target, int) or proto not in PROTOCOLS:
                continue
            host = int(published)
            if not 1 <= host <= 65535:
                continue
            out.append(Binding(name, target, proto, host, str(p.get("host_ip") or ""), variables.get((name, target, proto))))
    return out


def dockerfile_bindings(ports: list[dict[str, Any]]) -> list[Binding]:
    return [
        Binding(None, int(p["container"]), "udp" if p.get("protocol") == "udp" else "tcp", int(p["host"]))
        for p in ports
    ]


_HEX_LINE = re.compile(r"^(?:\s*[0-9a-f]{2})+\s*$")


def parse_compose_output(output: str) -> dict[str, Any]:
    """The configuration printed by ``deployer.compose_config_command``: a hex dump of the JSON.

    Lines that are not hex (a warning from the login shell, say) are skipped. Output that holds
    no hex at all is read as JSON text.
    """
    hex_lines = [line for line in output.splitlines() if _HEX_LINE.match(line)]
    if not hex_lines:
        return parse_compose_json(output)
    try:
        text = bytes.fromhex("".join("".join(hex_lines).split())).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise PortError(f"Could not read the configuration Docker Compose printed: {exc}") from exc
    return parse_compose_json(text)


class _ComposeLoader(yaml.SafeLoader):
    """Safe YAML loading that reads Compose's own tags (``!reset``, ``!override``) as plain values."""


def _untagged(loader: yaml.SafeLoader, suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_scalar(node)


_ComposeLoader.add_multi_constructor("!", _untagged)


def load_compose_yaml(text: str) -> dict[str, Any] | None:
    """A compose file as written (variables not interpolated), or None if it does not parse."""
    try:
        data = yaml.load(text, Loader=_ComposeLoader)  # noqa: S506 - a SafeLoader subclass
    except yaml.YAMLError:
        return None
    return data if isinstance(data, dict) else None


def parse_compose_json(output: str) -> dict[str, Any]:
    """The JSON object in command output that may carry warnings around it."""
    start, end = output.find("{"), output.rfind("}")
    if start < 0 or end < start:
        raise PortError("Docker Compose printed no configuration")
    try:
        data = json.loads(output[start : end + 1])
    except ValueError as exc:
        raise PortError(f"Could not read the configuration Docker Compose printed: {exc}") from exc
    if not isinstance(data, dict):
        raise PortError("Docker Compose printed no configuration")
    return data


# ------------------------------------------------------------------------ the host


@dataclass
class HostPorts:
    """Ports in use on a host, each with a short description of what uses it."""

    taken: dict[tuple[int, str], str] = field(default_factory=dict)
    own: set[tuple[int, str]] = field(default_factory=set)  # held by this instance's containers

    def user(self, port: int, protocol: str) -> str | None:
        if (port, protocol) in self.own:
            return None
        return self.taken.get((port, protocol))

    def reserve(self, port: int, protocol: str, what: str) -> None:
        self.taken.setdefault((port, protocol), what)


def parse_scan(
    output: str, *, instance_id: str, compose_project: str, own_names: frozenset[str] | set[str] = frozenset(),
) -> HostPorts:
    """Read ``SCAN_COMMAND`` output. Lines it does not recognise (warnings, errors) are skipped.

    The instance's own containers: those with its label, in its compose project, or named in
    ``own_names`` (a claimed container the first deploy replaces).
    """
    result = HostPorts()
    sockets: set[tuple[int, str]] = set()
    for line in output.splitlines():
        if line.startswith("proc "):
            parts = line.split()
            if len(parts) != 3 or ":" not in parts[2]:
                continue
            try:
                port = int(parts[2].rsplit(":", 1)[1], 16)
            except ValueError:
                continue
            if port:
                sockets.add((port, "udp" if parts[1].startswith("udp") else "tcp"))
        elif line.startswith("docker\t"):
            parts = line.split("\t", 4)
            if len(parts) != 5:
                continue
            _, label, project, name, ports = parts
            own = label == instance_id or (project and project == compose_project) or name in own_names
            for m in _DOCKER_PORT_RE.finditer(ports):
                if m.group(5) not in PROTOCOLS:
                    continue
                first = int(m.group(1))
                last = int(m.group(2) or first)
                for port in range(first, min(last, 65535) + 1):
                    if own:
                        result.own.add((port, m.group(5)))
                    else:
                        result.taken.setdefault((port, m.group(5)), f"container {name}")
    for key in sockets:
        result.taken.setdefault(key, "a process on the host")
    return result


# ------------------------------------------------------------------------ planning


@dataclass
class PortPlan:
    declared: list[Binding]  # as the compose file / instance declares them
    bindings: list[Binding]  # the host ports to use, in the same order
    moved: list[tuple[Binding, Binding, str]]  # (wanted, given, why) for each clash that was moved

    @property
    def changed(self) -> list[tuple[Binding, Binding]]:
        """(declared, final) for each binding whose host port is not the declared one."""
        return [(a, b) for a, b in zip(self.declared, self.bindings, strict=True) if a.host != b.host]


def plan(
    declared: list[Binding],
    host_ports: HostPorts,
    *,
    overrides: dict[tuple[str | None, int, str], int] | None = None,
    auto: bool,
    host_name: str,
) -> PortPlan:
    """Choose a host port for each binding; raise PortError on a clash ``auto`` may not fix."""
    overrides = overrides or {}
    # Ports this instance's own mappings ask for: a moved port skips them rather than taking one
    # a later mapping needs (6000-6001 with 6000 taken moves 6000 to 6002, not 6001).
    wanted_ports = {(overrides.get(b.key, b.host), b.protocol) for b in declared}
    assigned: dict[tuple[int, str], Binding] = {}
    final: list[Binding] = []
    moved: list[tuple[Binding, Binding, str]] = []
    for b in declared:
        wanted = replace(b, host=overrides.get(b.key, b.host))

        def user_of(port: int, protocol: str = b.protocol, b: Binding = b) -> str | None:
            other = assigned.get((port, protocol))
            if other is not None and other.key != b.key:
                return f"{other.service or 'another mapping'} of this instance"
            return host_ports.user(port, protocol)

        used_by = user_of(wanted.host)
        given = wanted
        if used_by:
            if not auto:
                raise PortError(
                    f"Host port {wanted.describe()} is already used by {used_by} on {host_name}. "
                    "Set a port override on the instance, or turn on automatic port assignment."
                )
            port = next(
                (p for p in range(wanted.host + 1, 65536) if (p, b.protocol) not in wanted_ports and not user_of(p)), None
            )
            if port is None:
                raise PortError(f"No free host port above {wanted.host}/{b.protocol} on {host_name}")
            given = replace(wanted, host=port)
            moved.append((wanted, given, f"used by {used_by}"))
        assigned.setdefault((given.host, given.protocol), given)
        final.append(given)
    return PortPlan(declared=list(declared), bindings=final, moved=moved)


# --------------------------------------------------------------- passing it back


def compose_changes(
    plan_: PortPlan, config: dict[str, Any]
) -> tuple[dict[str, str], str | None]:
    """How to give Compose the planned ports: (variables to set, override file content or None).

    A variable is used when every binding it sets moves to the same new port; any other moved
    binding goes into an override that replaces its service's whole ``ports`` list.
    """
    changed = plan_.changed
    if not changed:
        return {}, None
    by_var: dict[str, set[int]] = {}
    all_with_var: dict[str, int] = {}
    for b in plan_.declared:
        if b.var:
            all_with_var[b.var] = all_with_var.get(b.var, 0) + 1
    changed_with_var: dict[str, int] = {}
    for old, new in changed:
        if old.var:
            by_var.setdefault(old.var, set()).add(new.host)
            changed_with_var[old.var] = changed_with_var.get(old.var, 0) + 1
    variables = {
        var: str(next(iter(ports)))
        for var, ports in by_var.items()
        if len(ports) == 1 and changed_with_var[var] == all_with_var[var]
    }
    literal = {old.service for old, _ in changed if not (old.var and old.var in variables)}
    if not literal:
        return variables, None

    final = {(b.service, b.container, b.protocol, b.host_ip): b.host for b in plan_.bindings}
    lines = ["# Written by Slipway: host ports moved because they were in use or overridden.", "services:"]
    services = config.get("services") or {}
    for name in sorted(n for n in literal if n):
        lines.append(f"  {json.dumps(name)}:")
        lines.append("    ports: !override")
        for p in (services.get(name) or {}).get("ports") or []:
            entry = dict(p)
            key = (name, entry.get("target"), entry.get("protocol") or "tcp", str(entry.get("host_ip") or ""))
            if key in final:
                entry["published"] = str(final[key])
            lines.append(f"      - {json.dumps(entry, sort_keys=True)}")
    return variables, "\n".join(lines) + "\n"


def resolved_with_ports(config: dict[str, Any], plan_: PortPlan) -> str:
    """``config`` (``docker compose config --format json``) with the planned host ports, as JSON.

    Used whole as the compose file where Compose ignores ``!override``. Compose prints ``$`` in
    values as ``$$``, so reading it back gives the same values.
    """
    final = {(b.service, b.container, b.protocol, b.host_ip): b.host for b in plan_.bindings}
    out = json.loads(json.dumps(config))
    for name, svc in (out.get("services") or {}).items():
        for p in (svc or {}).get("ports") or []:
            key = (name, p.get("target"), p.get("protocol") or "tcp", str(p.get("host_ip") or ""))
            if isinstance(p, dict) and key in final:
                p["published"] = str(final[key])
    return json.dumps(out, indent=1, sort_keys=True) + "\n"


def binding_rows(plan_: PortPlan) -> list[dict[str, Any]]:
    """The plan as stored on the instance (``published_ports``), with the declared port when it differs."""
    rows = []
    for declared, b in zip(plan_.declared, plan_.bindings, strict=True):
        row: dict[str, Any] = {"service": b.service, "container": b.container, "protocol": b.protocol, "host": b.host}
        if b.host_ip:
            row["host_ip"] = b.host_ip
        if declared.host != b.host:
            row["declared"] = declared.host
        rows.append(row)
    return rows
