"""Hostnames for instances, served by Switchyard (a Caddy reverse proxy with a REST API).

An instance lists the hostnames that should reach it (``Instance.routes``): each names a
published port (compose service + container port, or the container port in Dockerfile mode).
After every successful deploy, and on demand, Slipway makes Switchyard match:

* one Switchyard proxy host per hostname, sending traffic to the Docker host's address
  (``Host.upstream_address``) on the host port the port ended up on, so a port Slipway moved
  because it was taken is followed automatically;
* hostnames removed from the instance have their Switchyard host deleted.

Switchyard stages changes until ``POST /api/config/apply``, and an apply sends *every*
pending change to Caddy. So Slipway applies only when everything pending is its own:
``GET /api/config/preview`` reports ``changes``, the number of edits (audit-log entries, one per
host created, changed or deleted) since the last applied version ``last_applied.n``, and Slipway
counts its own edits since that version (stored with the settings). When the preview counts more,
someone else's edits are waiting, so Slipway's stay staged and the deploy log says to apply them in
Switchyard. It does not apply either when Caddy was changed outside Switchyard (``drift``) or when
Switchyard has never applied a config.

Slipway marks the hosts it creates in their notes and only ever changes their domains,
upstreams and certificate mode; access policies, headers and the rest stay as set in Switchyard.
A host belongs to one **owner**: a standalone instance (``sync`` below) or an environment, whose
hosts are written by ``slipway.services.traffic`` with this module's lock, edit counter and
body helpers. Each owner's marker names it, so a host is only ever changed by the owner whose
marker it carries.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.db.base import utcnow
from slipway.db.session import session_scope
from slipway.models import AppSetting, BuildSource, Instance

log = logging.getLogger(__name__)

SETTING_KEY = "switchyard"
TLS_MODES = ("auto", "dns", "internal", "off")
# What an API key needs in Switchyard (Administration → API keys).
REQUIRED_OPERATIONS = (
    "hosts.list", "hosts.get", "hosts.create", "hosts.update", "hosts.delete", "config.preview", "config.apply",
)
# Switchyard keys are "sy_" and 43 URL-safe base64 characters; it lists each by its first 9 characters.
API_KEY_RE = re.compile(r"^sy_[A-Za-z0-9_-]{20,200}$")
KEY_PREFIX_LEN = 9
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")
MARKER = "Managed by Slipway"

Log = Callable[[str], Awaitable[None]]


class SwitchyardError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None, code: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code


# ------------------------------------------------------------------------ settings


@dataclass(frozen=True)
class SwitchyardConfig:
    url: str
    api_key: str
    default_tls_mode: str = "auto"
    # Where Switchyard serves the hostnames (``host[:port]``), for checking a name through it after a
    # switch. Empty: that check is skipped with a warning.
    traffic_address: str = ""


async def load_config(db: AsyncSession) -> SwitchyardConfig | None:
    """The configured connection, or None when it is not set up (or its key can't be decrypted)."""
    row = await db.scalar(select(AppSetting).where(AppSetting.key == SETTING_KEY))
    if row is None or not row.secret or not (row.value or {}).get("url"):
        return None
    return SwitchyardConfig(
        url=row.value["url"], api_key=row.secret, default_tls_mode=row.value.get("default_tls_mode") or "auto",
        traffic_address=row.value.get("traffic_address") or "",
    )


async def default_tls_mode(db: AsyncSession) -> str:
    row = await db.scalar(select(AppSetting).where(AppSetting.key == SETTING_KEY))
    return ((row.value if row else None) or {}).get("default_tls_mode") or "auto"


def clean_url(value: str) -> str:
    value = (value or "").strip().rstrip("/")
    if value.endswith("/api"):
        value = value[:-4]
    if not re.match(r"^https?://[^\s/]+(?:/[^\s]*)?$", value):
        raise ValueError("Switchyard URL must start with http:// or https://, such as https://switchyard.example.com")
    return value


def clean_api_key(value: str) -> str:
    value = (value or "").strip()
    if not API_KEY_RE.match(value):
        raise ValueError(
            "That is not a Switchyard API key: those start with sy_ and are shown once, when the key is made. "
            "If your browser filled this box in, clear it and paste the key."
        )
    return value


def clean_hostname(value: str) -> str:
    value = (value or "").strip().lower().rstrip(".")
    if not HOSTNAME_RE.match(value):
        raise ValueError(f"'{value}' is not a valid hostname (such as app.example.com)")
    return value


def clean_traffic_address(value: str) -> str:
    """``host[:port]`` where Switchyard serves the hostnames; "" when cleared.

    The host is a hostname or an IP address (an IPv6 address in brackets when a port follows).
    """
    value = (value or "").strip().lower().rstrip("/")
    if not value:
        return ""
    problem = (f"'{value}' is not a traffic address: give the hostname or IP address where Switchyard "
               "serves your sites, with an optional :port, such as 192.168.1.5 or proxy.example.com:8443")
    host, port = value, ""
    if value.startswith("["):  # [IPv6]:port
        host, sep, rest = value[1:].partition("]")
        if not sep or (rest and not rest.startswith(":")):
            raise ValueError(problem)
        port = rest[1:]
        if rest and not port:
            raise ValueError(problem)
    elif value.count(":") == 1:
        host, port = value.split(":")
        if not port:
            raise ValueError(problem)
    if port and (not port.isdigit() or not 1 <= int(port) <= 65535):
        raise ValueError(problem)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is None and not HOSTNAME_RE.match(host.rstrip(".")):
        raise ValueError(problem)
    if ip is not None and ip.version == 6:
        host = f"[{ip.compressed}]" if port else ip.compressed
    elif ip is not None:
        host = str(ip)
    else:
        host = host.rstrip(".")
    return f"{host}:{int(port)}" if port else host


# -------------------------------------------------------------------------- client


Transport = httpx.AsyncBaseTransport | None
# Tests swap this for an httpx.MockTransport.
transport_factory: Callable[[], Transport] = lambda: None  # noqa: E731


class SwitchyardClient:
    def __init__(self, config: SwitchyardConfig, *, transport: Transport = None) -> None:
        self._client = httpx.AsyncClient(
            base_url=config.url,
            headers={"Authorization": f"Bearer {config.api_key}", "User-Agent": "Slipway"},
            timeout=30,
            transport=transport if transport is not None else transport_factory(),
        )

    async def __aenter__(self) -> SwitchyardClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    async def _call(self, method: str, path: str, body: Any = None, *, timeout: float | None = None) -> Any:
        try:
            resp = await self._client.request(method, path, json=body, timeout=timeout or 30)
        except httpx.HTTPError as exc:
            raise SwitchyardError(f"Could not reach Switchyard ({type(exc).__name__}: {exc})") from exc
        if resp.status_code >= 400:
            try:
                data = resp.json()
                code, message = str(data.get("error") or ""), str(data.get("message") or resp.text[:200])
                if data.get("fields"):
                    message += " " + "; ".join(f"{k}: {v}" for k, v in data["fields"].items())
            except (ValueError, AttributeError):
                code, message = "", resp.text[:200] or resp.reason_phrase
            raise SwitchyardError(f"Switchyard {method} {path}: {message}", resp.status_code, code)
        if resp.status_code == 204 or not resp.content:
            return None
        try:
            return resp.json()
        except ValueError as exc:
            raise SwitchyardError(f"Switchyard {method} {path}: the answer is not JSON (is this Switchyard's URL?)") from exc

    async def list_hosts(self) -> list[dict[str, Any]]:
        return await self._call("GET", "/api/hosts") or []

    async def get_host(self, host_id: int) -> dict[str, Any] | None:
        try:
            return await self._call("GET", f"/api/hosts/{int(host_id)}")
        except SwitchyardError as exc:
            if exc.status_code == 404:
                return None
            raise

    async def create_host(self, body: dict[str, Any]) -> dict[str, Any]:
        return await self._call("POST", "/api/hosts", body)

    async def update_host(self, host_id: int, body: dict[str, Any]) -> dict[str, Any]:
        return await self._call("PUT", f"/api/hosts/{int(host_id)}", body)

    async def delete_host(self, host_id: int) -> None:
        try:
            await self._call("DELETE", f"/api/hosts/{int(host_id)}")
        except SwitchyardError as exc:
            if exc.status_code != 404:
                raise

    async def preview(self) -> dict[str, Any]:
        return await self._call("GET", "/api/config/preview") or {}

    async def apply(self, note: str) -> dict[str, Any]:
        return await self._call("POST", "/api/config/apply", {"note": note[:200]}, timeout=90)


async def check_connection(config: SwitchyardConfig) -> str:
    """A one-line description of what the key can do; raises SwitchyardError when it can't connect."""
    async with SwitchyardClient(config) as sy:
        hosts = await sy.list_hosts()
        preview = await sy.preview()
    pending = " There are changes waiting to be applied in Switchyard." if preview.get("pending") else ""
    return f"Connected: Switchyard has {len(hosts)} host(s).{pending}"


# ------------------------------------------------------------------------ planning


@dataclass(frozen=True)
class Target:
    """Where one route should send traffic, or why it can't yet."""

    hostname: str
    tls_mode: str
    address: str | None = None
    port: int | None = None
    problem: str | None = None

    @property
    def upstream(self) -> str:
        return f"{self.address}:{self.port}"


def route_targets(instance: Instance) -> list[Target]:
    """Each route of ``instance`` with the host port its container port is published on."""
    out = []
    compose = instance.build_source in (BuildSource.COMPOSE, BuildSource.APP)
    if compose:
        published = [p for p in instance.published_ports or [] if p.get("protocol", "tcp") == "tcp"]
    else:
        published = [{"service": None, "container": p["container"], "host": p["host"]}
                     for p in instance.ports or [] if p.get("protocol", "tcp") == "tcp"]
    routes = list(instance.routes or [])
    if instance.build_source == BuildSource.APP:  # the hostnames slipway.yml gives its services
        mine = {r["hostname"] for r in routes}
        routes += [r for r in (instance.app_state or {}).get("routes") or [] if r.get("hostname") not in mine]
    for r in routes:
        hostname, tls = r["hostname"], r.get("tls_mode") or "auto"
        want = (r.get("service") or None) if compose else None
        match = next(
            (p for p in published if int(p["container"]) == int(r["container"]) and (not compose or p.get("service") == want)),
            None,
        )
        if match is None:
            what = f"{want} container port {r['container']}" if compose else f"container port {r['container']}"
            out.append(Target(hostname, tls, problem=f"{what} is not published on the host"))
            continue
        out.append(Target(hostname, tls, instance.host.upstream_address, int(match["host"])))
    return out


# --------------------------------------------------------------------------- owners


@dataclass(frozen=True)
class Owner:
    """Who in Slipway a Switchyard host belongs to: an ``instance`` or an ``environment``."""

    kind: str
    id: uuid.UUID
    name: str

    @classmethod
    def of(cls, subject: Owner | Instance | Any) -> Owner:
        """The owner for an Owner, an Instance or an Environment row."""
        if isinstance(subject, Owner):
            return subject
        if isinstance(subject, Instance):
            return cls("instance", subject.id, subject.name)
        if getattr(subject, "__tablename__", None) == "environments":
            return cls("environment", subject.id, subject.name)
        raise TypeError(f"Switchyard hosts belong to an instance or an environment, not {type(subject).__name__}")

    def __str__(self) -> str:
        return f"{self.kind} {self.name}"


# The marker line Slipway writes into a host's notes: "Managed by Slipway: <kind> <name> (<id>)."
_MARKER_RE = re.compile(
    re.escape(MARKER) + r": (instance|environment) (.+?) \(([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\)"
)


def marker(owner: Owner | Instance | Any) -> str:
    """The text Slipway puts at the top of the notes of each host it creates for ``owner``."""
    owner = Owner.of(owner)
    if owner.kind == "instance":
        return f"{MARKER}: instance {owner.name} ({owner.id}). Domains, upstreams and TLS mode are set from Slipway on every deploy."
    return (f"{MARKER}: environment {owner.name} ({owner.id}). "
            "Domains, upstreams and TLS mode are set from Slipway when traffic moves.")


def _markers(host: dict[str, Any]) -> list[Owner]:
    """Every owner a Slipway marker in ``host``'s notes names, first first."""
    return [Owner(kind, uuid.UUID(id_), name) for kind, name, id_ in _MARKER_RE.findall(host.get("notes") or "")]


def marked_owner(host: dict[str, Any]) -> Owner | None:
    """The owner named by the first Slipway marker in ``host``'s notes, or None without one."""
    found = _markers(host)
    return found[0] if found else None


def owned_by(host: dict[str, Any], owner: Owner | Instance | uuid.UUID | Any) -> bool:
    """Whether ``host`` carries ``owner``'s marker (a bare id is taken as an instance's, as before).

    An instance owns a host whose notes hold the marker text and its id, as Slipway has always
    checked, unless the host is marked for an environment. An environment owns only a host whose
    marker names it.
    """
    owner = Owner("instance", owner, "") if isinstance(owner, uuid.UUID) else Owner.of(owner)
    notes = host.get("notes") or ""
    if MARKER not in notes or str(owner.id) not in notes:
        return False
    environments = [o for o in _markers(host) if o.kind == "environment"]
    if owner.kind == "instance":
        return not environments
    return any(str(o.id) == str(owner.id) for o in environments)


def describe_owner(host: dict[str, Any]) -> str:
    """Who ``host`` belongs to, for conflict messages: "instance X", "environment Y" or "someone else"."""
    found = marked_owner(host)
    return str(found) if found is not None else "someone else"


def desired(host: dict[str, Any] | None, target: Target, owner: Owner | Instance | Any) -> dict[str, Any]:
    """``host`` (a Switchyard host, or None for a new one) with Slipway's fields set for ``owner``."""
    owner = Owner.of(owner)
    body = dict(host or {"type": "proxy", "enabled": True, "hsts": False, "compression": True})
    body["type"] = "proxy"
    body["domains"] = [target.hostname]
    keep = (host or {}).get("upstreams") or [{}]
    body["upstreams"] = [{**{"scheme": "http", "skip_tls_verify": False}, **{k: v for k, v in keep[0].items() if k in ("scheme", "skip_tls_verify")},
                          "host": target.address, "port": target.port}]
    if body.get("tls_mode") != target.tls_mode:
        body["tls_mode"] = target.tls_mode
        body["force_https"] = target.tls_mode != "off"
    notes = (host or {}).get("notes") or ""
    if not owned_by({"notes": notes}, owner):
        notes = (marker(owner) + ("\n" + notes if notes else "")).strip()
    body["notes"] = notes
    for k in ("id", "created_at", "updated_at"):
        body.pop(k, None)
    return body


def differs(host: dict[str, Any], body: dict[str, Any]) -> bool:
    """Whether writing ``body`` would change any field Slipway sets on ``host``."""
    return any(host.get(k) != body.get(k) for k in ("type", "domains", "upstreams", "tls_mode", "force_https", "notes"))


# The names this module used before environments, kept for callers and tests that use them.
_marker = marker
_owned_by = owned_by
_desired = desired
_differs = differs


# ----------------------------------------------------------------------------- sync


async def sync(instance: Instance, *, say: Log, client: SwitchyardClient | None = None,
               config: SwitchyardConfig | None = None, remove_all: bool = False) -> list[dict[str, Any]]:
    """Make Switchyard match ``instance.routes`` (or remove everything with ``remove_all``).

    Returns the new ``proxy_entries``. Never raises for Switchyard problems: they are reported
    through ``say`` and in each entry's ``state``/``message``.
    """
    previous = {e["hostname"]: e for e in instance.proxy_entries or []}
    targets = [] if remove_all else route_targets(instance)
    if not targets and not previous:
        return []
    if config is None:
        async with session_scope() as db:
            config = await load_config(db)
    if config is None:
        await say("Proxy: Switchyard is not set up (Settings → Integrations); hostnames were not published")
        return [_entry(t.hostname, previous.get(t.hostname, {}).get("switchyard_id"), None, "error",
                       "Switchyard is not set up") for t in targets]
    own_client = client is None
    sy = client or SwitchyardClient(config)
    try:
        return await _sync(sy, instance, targets, previous, say)
    finally:
        if own_client:
            await sy.__aexit__(None, None, None)


def _entry(hostname: str, sid: int | None, upstream: str | None, state: str, message: str = "") -> dict[str, Any]:
    return {"hostname": hostname, "switchyard_id": sid, "upstream": upstream, "state": state,
            "message": message[:300], "synced_at": utcnow().isoformat()}


# One writer at a time (an instance's sync, an environment's switch or put-back), so Slipway's count
# of its own unapplied edits stays right. Hold it for reading, writing and applying together, and
# never across a wait such as checking the names through Switchyard.
lock = asyncio.Lock()
_lock = lock


async def load_edits() -> dict[str, Any]:
    """Slipway's own edit count as saved: ``{"version": last_applied.n it counts from, "edits": n}``."""
    async with session_scope() as db:
        row = await db.scalar(select(AppSetting).where(AppSetting.key == SETTING_KEY))
        return dict(((row.value if row else None) or {}).get("edits") or {})


async def save_edits(state: dict[str, Any]) -> None:
    async with session_scope() as db:
        row = await db.scalar(select(AppSetting).where(AppSetting.key == SETTING_KEY))
        if row is not None:
            row.value = {**(row.value or {}), "edits": state}


async def own_edits(preview: dict[str, Any]) -> dict[str, Any]:
    """Slipway's own unapplied edits against ``preview``'s ``last_applied.n``.

    A config applied since the count was saved took those edits live with it, so the count starts
    again from 0 at the new version. Add one to ``"edits"`` per host created, changed or deleted,
    and save it with ``save_edits`` (after an apply: ``applied_edits``). Call it under ``lock``.
    """
    version = (preview.get("last_applied") or {}).get("n")
    state = await load_edits()
    if state.get("version") != version or "edits" not in state:
        state = {"version": version, "edits": 0}
    return state


def applied_edits(applied: dict[str, Any] | None, version: int | None) -> dict[str, Any]:
    """The edit count after Slipway's own apply answered ``applied``: nothing of Slipway's is pending."""
    return {"version": (applied or {}).get("n", version), "edits": 0}


_load_edits = load_edits
_save_edits = save_edits


# Edits an environment's unresolved switch left staged (phase 3 §10.6) are counted with the rest, and also
# under ``"held"`` by environment id. They stay Slipway's, but no apply may take them live except that
# environment's own (an Activate, which checks every name afterwards, or a teardown, which deletes the hosts):
# applying them would put an unchecked slot live (I6). An apply in Switchyard settles them: the count starts
# again at the new version, ``"held"`` with it.


def held(state: dict[str, Any], *, but: str | None = None) -> int:
    """How many counted edits unresolved switches left staged, leaving out environment ``but``'s."""
    return sum(int(n or 0) for key, n in (state.get("held") or {}).items() if key != but)


def own_count(state: dict[str, Any], *, holder: str | None = None) -> int:
    """How many of Slipway's counted edits an apply may take live: all but those another environment's
    unresolved switch left staged (``holder``: the environment applying, or None for anyone else)."""
    return max(int(state.get("edits") or 0) - held(state, but=holder), 0)


HELD = "an environment's unresolved switch left changes waiting in Switchyard; resolve it first"


def blocked(preview: dict[str, Any], state: dict[str, Any], *, holder: str | None = None) -> str | None:
    """``blocker`` for an apply by ``holder`` (see ``own_count``), saying so when held edits are the reason."""
    why = blocker(preview, own_count(state, holder=holder))
    if why and why == OTHER_CHANGES and held(state, but=holder) \
            and int(preview.get("changes") or 0) <= int(state.get("edits") or 0):
        return HELD
    return why


def hold(state: dict[str, Any], holder: str) -> dict[str, Any]:
    """``state`` with every counted edit not already held for another environment held for ``holder``.

    Called when ``holder``'s switch ends unresolved: whatever of Slipway's is staged then may belong to the
    half-done switch, so none of it is applied except by that environment (or in Switchyard)."""
    out = dict(state)
    marks = dict(out.get("held") or {})
    marks[holder] = max(int(out.get("edits") or 0) - held(out, but=holder), 0)
    out["held"] = {k: v for k, v in marks.items() if v}
    return out


def release(state: dict[str, Any], holder: str) -> dict[str, Any]:
    """``state`` without the edits held for ``holder`` (its unresolved switch was settled)."""
    out = dict(state)
    marks = {k: v for k, v in (out.get("held") or {}).items() if k != holder}
    if marks:
        out["held"] = marks
    else:
        out.pop("held", None)
    return out


async def hold_edits(holder: str) -> None:
    """Save ``hold(...)`` of the saved count (call it under ``lock``)."""
    await save_edits(hold(await load_edits(), holder))


async def release_edits(holder: str) -> None:
    """Save ``release(...)`` of the saved count (call it under ``lock``)."""
    state = await load_edits()
    if holder in (state.get("held") or {}):
        await save_edits(release(state, holder))


async def hold_in(db: AsyncSession, holder: str) -> None:
    """``hold_edits`` inside the caller's transaction (recovery after a restart)."""
    row = await db.scalar(select(AppSetting).where(AppSetting.key == SETTING_KEY))
    if row is not None and (row.value or {}).get("edits"):
        row.value = {**(row.value or {}), "edits": hold(dict(row.value["edits"]), holder)}


OTHER_CHANGES = "other changes were waiting in Switchyard"


def blocker(preview: dict[str, Any], own_edits: int) -> str | None:
    """Why Slipway must not apply now, or None when everything pending is its own."""
    if preview.get("caddy_error"):
        return f"Switchyard cannot read Caddy's config ({preview['caddy_error']})"
    if preview.get("drift"):
        return "Caddy's config was changed outside Switchyard"
    if not preview.get("last_applied"):
        return "Switchyard has not applied a config yet; apply once there"
    if preview.get("pending") and int(preview.get("changes") or 0) > own_edits:
        return OTHER_CHANGES
    return None


_blocker = blocker


async def apply_blocker(config: SwitchyardConfig, *, client: SwitchyardClient | None = None) -> str | None:
    """Why a sync now would leave its changes staged instead of applying them, or None.

    A migration asks first: once the old host's containers are stopped, a staged change would leave the
    hostnames pointing at them. Edits an environment's unresolved switch holds count against it (``blocked``).
    """
    sy = client or SwitchyardClient(config)
    try:
        preview = await sy.preview()
    except SwitchyardError as exc:
        return str(exc)
    finally:
        if client is None:
            await sy.__aexit__(None, None, None)
    return blocked(preview, await own_edits(preview))


async def _sync(sy: SwitchyardClient, instance: Instance, targets: list[Target],
                previous: dict[str, dict[str, Any]], say: Log) -> list[dict[str, Any]]:
    async with lock:
        return await _sync_locked(sy, instance, targets, previous, say)


async def _sync_locked(sy: SwitchyardClient, instance: Instance, targets: list[Target],
                       previous: dict[str, dict[str, Any]], say: Log) -> list[dict[str, Any]]:
    try:
        before = await sy.preview()
    except SwitchyardError as exc:
        await say(f"Proxy: {exc}; hostnames were not changed")
        return [_entry(t.hostname, previous.get(t.hostname, {}).get("switchyard_id"), None, "error", str(exc))
                for t in targets]
    version = (before.get("last_applied") or {}).get("n")
    state = await own_edits(before)
    why_not = blocked(before, state)  # edits an environment's unresolved switch left are never taken live here
    owner = Owner.of(instance)

    entries: list[dict[str, Any]] = []
    changed = False
    by_domain: dict[str, dict[str, Any]] | None = None
    for t in targets:
        sid = previous.get(t.hostname, {}).get("switchyard_id")
        if t.problem:
            await say(f"Proxy: {t.hostname}: {t.problem}; not published")
            entries.append(_entry(t.hostname, sid, None, "error", t.problem))
            continue
        try:
            host = await sy.get_host(sid) if sid else None
            if host is not None and not owned_by(host, owner):
                host = None  # the id now belongs to someone else's host
            if host is None:
                if by_domain is None:
                    by_domain = {d: h for h in await sy.list_hosts() for d in h.get("domains") or []}
                found = by_domain.get(t.hostname)
                if found is not None and not owned_by(found, owner):
                    theirs = describe_owner(found)
                    whose = "which Slipway did not create" if theirs == "someone else" else f"which belongs to {theirs}"
                    raise SwitchyardError(
                        f"{t.hostname} is already used by Switchyard host #{found.get('id')}, {whose}; "
                        "remove it there or pick another hostname", 409, "conflict")
                host = found
            body = desired(host, t, owner)
            if host is None:
                host = await sy.create_host(body)
                await say(f"Proxy: created {t.hostname} → {t.upstream} in Switchyard")
                changed = True
                state["edits"] += 1
            elif differs(host, body):
                host = await sy.update_host(host["id"], body)
                await say(f"Proxy: updated {t.hostname} → {t.upstream} in Switchyard")
                changed = True
                state["edits"] += 1
            entries.append(_entry(t.hostname, host.get("id"), t.upstream, "live"))
        except SwitchyardError as exc:
            await say(f"Proxy: {t.hostname}: {exc}")
            entries.append(_entry(t.hostname, sid, t.upstream, "error", str(exc)))

    wanted = {t.hostname for t in targets}
    for hostname, old in previous.items():
        if hostname in wanted or not old.get("switchyard_id"):
            continue
        try:
            host = await sy.get_host(old["switchyard_id"])
            if host is not None and owned_by(host, owner):
                await sy.delete_host(old["switchyard_id"])
                await say(f"Proxy: removed {hostname} from Switchyard")
                changed = True
                state["edits"] += 1
        except SwitchyardError as exc:
            await say(f"Proxy: could not remove {hostname}: {exc}")
            entries.append(_entry(hostname, old["switchyard_id"], old.get("upstream"), "error", f"not removed: {exc}"))

    if own_count(state) and why_not:
        await say(f"Proxy: not applied, because {why_not}; review and apply in Switchyard to put the hostnames live")
        entries = [{**e, "state": "staged", "message": "Waiting for an apply in Switchyard"} if e["state"] == "live" else e
                   for e in entries]
    elif own_count(state):
        try:
            applied = await sy.apply(f"Slipway: {instance.name}")
            state = applied_edits(applied, version)
            await say("Proxy: applied in Switchyard" + ("" if changed else " (changes Slipway staged earlier)"))
        except SwitchyardError as exc:
            await say(f"Proxy: Switchyard could not apply: {exc}")
            entries = [{**e, "state": "error", "message": f"Apply failed: {exc}"} if e["state"] == "live" else e
                       for e in entries]
    await save_edits(state)
    return entries


async def sync_and_store(instance: Instance, *, say: Log, remove_all: bool = False) -> list[dict[str, Any]]:
    """``sync``, then save the result on the instance (unless it was removed)."""
    entries = await sync(instance, say=say, remove_all=remove_all)
    if not remove_all:
        async with session_scope() as db:
            await db.execute(update(Instance).where(Instance.id == instance.id).values(proxy_entries=entries))
    instance.proxy_entries = entries
    return entries
