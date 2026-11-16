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
"""

from __future__ import annotations

import asyncio
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


async def load_config(db: AsyncSession) -> SwitchyardConfig | None:
    """The configured connection, or None when it is not set up (or its key can't be decrypted)."""
    row = await db.scalar(select(AppSetting).where(AppSetting.key == SETTING_KEY))
    if row is None or not row.secret or not (row.value or {}).get("url"):
        return None
    return SwitchyardConfig(
        url=row.value["url"], api_key=row.secret, default_tls_mode=row.value.get("default_tls_mode") or "auto"
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
    compose = instance.build_source == BuildSource.COMPOSE
    if compose:
        published = [p for p in instance.published_ports or [] if p.get("protocol", "tcp") == "tcp"]
    else:
        published = [{"service": None, "container": p["container"], "host": p["host"]}
                     for p in instance.ports or [] if p.get("protocol", "tcp") == "tcp"]
    for r in instance.routes or []:
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


def _marker(instance: Instance) -> str:
    return f"{MARKER}: instance {instance.name} ({instance.id}). Domains, upstreams and TLS mode are set from Slipway on every deploy."


def _owned_by(host: dict[str, Any], instance_id: uuid.UUID) -> bool:
    return MARKER in (host.get("notes") or "") and str(instance_id) in (host.get("notes") or "")


def _desired(host: dict[str, Any] | None, target: Target, instance: Instance) -> dict[str, Any]:
    """``host`` (a Switchyard host, or None for a new one) with Slipway's fields set."""
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
    if not _owned_by({"notes": notes}, instance.id):
        notes = (_marker(instance) + ("\n" + notes if notes else "")).strip()
    body["notes"] = notes
    for k in ("id", "created_at", "updated_at"):
        body.pop(k, None)
    return body


def _differs(host: dict[str, Any], body: dict[str, Any]) -> bool:
    return any(host.get(k) != body.get(k) for k in ("type", "domains", "upstreams", "tls_mode", "force_https", "notes"))


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


# One sync at a time, so Slipway's count of its own unapplied edits stays right.
_lock = asyncio.Lock()


async def _load_edits() -> dict[str, Any]:
    async with session_scope() as db:
        row = await db.scalar(select(AppSetting).where(AppSetting.key == SETTING_KEY))
        return dict(((row.value if row else None) or {}).get("edits") or {})


async def _save_edits(state: dict[str, Any]) -> None:
    async with session_scope() as db:
        row = await db.scalar(select(AppSetting).where(AppSetting.key == SETTING_KEY))
        if row is not None:
            row.value = {**(row.value or {}), "edits": state}


def _blocker(preview: dict[str, Any], own_edits: int) -> str | None:
    """Why Slipway must not apply now, or None when everything pending is its own."""
    if preview.get("caddy_error"):
        return f"Switchyard cannot read Caddy's config ({preview['caddy_error']})"
    if preview.get("drift"):
        return "Caddy's config was changed outside Switchyard"
    if not preview.get("last_applied"):
        return "Switchyard has not applied a config yet; apply once there"
    if preview.get("pending") and int(preview.get("changes") or 0) > own_edits:
        return "other changes were waiting in Switchyard"
    return None


async def _sync(sy: SwitchyardClient, instance: Instance, targets: list[Target],
                previous: dict[str, dict[str, Any]], say: Log) -> list[dict[str, Any]]:
    async with _lock:
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
    state = await _load_edits()
    if state.get("version") != version or "edits" not in state:  # applied since: earlier edits went live with it
        state = {"version": version, "edits": 0}
    blocker = _blocker(before, state["edits"])

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
            if host is not None and not _owned_by(host, instance.id):
                host = None  # the id now belongs to someone else's host
            if host is None:
                if by_domain is None:
                    by_domain = {d: h for h in await sy.list_hosts() for d in h.get("domains") or []}
                found = by_domain.get(t.hostname)
                if found is not None and not _owned_by(found, instance.id):
                    raise SwitchyardError(
                        f"{t.hostname} is already used by Switchyard host #{found.get('id')}, which Slipway did not "
                        "create; remove it there or pick another hostname", 409, "conflict")
                host = found
            body = _desired(host, t, instance)
            if host is None:
                host = await sy.create_host(body)
                await say(f"Proxy: created {t.hostname} → {t.upstream} in Switchyard")
                changed = True
                state["edits"] += 1
            elif _differs(host, body):
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
            if host is not None and _owned_by(host, instance.id):
                await sy.delete_host(old["switchyard_id"])
                await say(f"Proxy: removed {hostname} from Switchyard")
                changed = True
                state["edits"] += 1
        except SwitchyardError as exc:
            await say(f"Proxy: could not remove {hostname}: {exc}")
            entries.append(_entry(hostname, old["switchyard_id"], old.get("upstream"), "error", f"not removed: {exc}"))

    if state["edits"] and blocker:
        await say(f"Proxy: not applied, because {blocker}; review and apply in Switchyard to put the hostnames live")
        entries = [{**e, "state": "staged", "message": "Waiting for an apply in Switchyard"} if e["state"] == "live" else e
                   for e in entries]
    elif state["edits"]:
        try:
            applied = await sy.apply(f"Slipway: {instance.name}")
            state = {"version": (applied or {}).get("n", version), "edits": 0}
            await say("Proxy: applied in Switchyard" + ("" if changed else " (changes Slipway staged earlier)"))
        except SwitchyardError as exc:
            await say(f"Proxy: Switchyard could not apply: {exc}")
            entries = [{**e, "state": "error", "message": f"Apply failed: {exc}"} if e["state"] == "live" else e
                       for e in entries]
    await _save_edits(state)
    return entries


async def sync_and_store(instance: Instance, *, say: Log, remove_all: bool = False) -> list[dict[str, Any]]:
    """``sync``, then save the result on the instance (unless it was removed)."""
    entries = await sync(instance, say=say, remove_all=remove_all)
    if not remove_all:
        async with session_scope() as db:
            await db.execute(update(Instance).where(Instance.id == instance.id).values(proxy_entries=entries))
    instance.proxy_entries = entries
    return entries
