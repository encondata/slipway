"""DNS records for environments, kept in Cloudflare.

An environment that publishes DNS gets one A record per public hostname, pointing at a fixed
address (the site's WAN address, ``public_ip``, or the environment's own ``traffic.dns.address``).
Records never move when traffic switches between slots: Switchyard does that on the LAN.

This module holds the pieces that don't need an environment:

* the integration settings (``app_settings`` row ``cloudflare``: zone, zone id, public IP and the
  proxied default in ``value``, the API token in ``secret``) and the checks for what people type;
* ``CloudflareClient``, the handful of API calls Slipway makes;
* ``plan_dns``, which decides, per hostname, whether a record is up to date, needs a change,
  can be created, is covered by a wildcard, could be claimed, is one Slipway made but never recorded
  (adopt), or is in someone else's way. It is a pure function, so the rules can be tested without
  Cloudflare; ``read_state`` reads what it needs.

Slipway changes or deletes only records it has a ``resources`` row for, and changes or deletes those it
created only while the live record still carries its comment (a claimed record is kept current whatever
its comment says). The token is never logged or put in an error.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import uuid
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.models import AppSetting

SETTING_KEY = "cloudflare"
API_URL = "https://api.cloudflare.com/client/v4"
PROVIDER = "cloudflare"
KIND = "dns_record"
MARKER = "Managed by Slipway"
TIMEOUT = 30
MAX_RETRY_AFTER = 30  # seconds; a 429 is retried once, after at most this long
MESSAGE_CHARS = 200  # how much of Cloudflare's own error text goes into ours
# Record types that can't sit beside Slipway's A record at a name: a CNAME (DNS forbids it), an
# AAAA (IPv6 clients would go somewhere Slipway doesn't manage; open question 6) and NS (the name
# is delegated elsewhere, so a record here would never be served).
BLOCKING_TYPES = ("CNAME", "AAAA", "NS")
ZONE_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")
# Cloudflare API tokens are 40 URL-safe characters today; allow some room either way.
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{30,200}$")


class CloudflareError(RuntimeError):
    """A Cloudflare call failed. ``str()`` is Slipway's text, with Cloudflare's codes and some of its message."""

    def __init__(self, message: str, status_code: int | None = None, codes: Iterable[int] = ()) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.codes = list(codes)


class RecordGone(CloudflareError):
    """The record Slipway tried to change no longer exists."""


# The codes of a 404 about the zone (or the route) rather than the record: the record may well still exist,
# so it is never taken to be gone (Cloudflare answers 81044 for a record that doesn't exist).
ZONE_CODES = frozenset({7000, 7003})


# ------------------------------------------------------------------------ settings


@dataclass(frozen=True)
class CloudflareConfig:
    zone: str
    token: str
    zone_id: str | None = None
    public_ip: str | None = None
    proxied: bool = False

    def __repr__(self) -> str:  # keep the token out of logs and tracebacks
        return (f"CloudflareConfig(zone={self.zone!r}, zone_id={self.zone_id!r}, public_ip={self.public_ip!r}, "
                f"proxied={self.proxied!r}, token=<hidden>)")


async def load_config(db: AsyncSession) -> CloudflareConfig | None:
    """The configured integration, or None when it is not set up (or its token can't be decrypted)."""
    row = await db.scalar(select(AppSetting).where(AppSetting.key == SETTING_KEY))
    value = (row.value if row else None) or {}
    if row is None or not row.secret or not value.get("zone"):
        return None
    return CloudflareConfig(
        zone=value["zone"], token=row.secret, zone_id=value.get("zone_id") or None,
        public_ip=value.get("public_ip") or None, proxied=bool(value.get("proxied")),
    )


def token_hint(token: str | None) -> str:
    """The last 4 characters, shown as ``Set (…abcd)``; empty when there is no token."""
    return (token or "")[-4:]


def clean_zone(value: str) -> str:
    value = (value or "").strip().lower().rstrip(".")
    if not ZONE_RE.match(value):
        raise ValueError(f"'{value}' is not a domain name (such as example.com): give the zone as Cloudflare lists it")
    return value


def clean_public_ip(value: str | None) -> str | None:
    """An IPv4 address, or None when left empty. Records are A records only, so IPv6 is refused."""
    value = (value or "").strip()
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"'{value}' is not an IP address (such as 203.0.113.10)") from None
    if address.version != 4:
        raise ValueError("Slipway publishes A records only, so the public address must be an IPv4 address")
    return str(address)


def clean_token(value: str) -> str:
    value = (value or "").strip()
    if value.lower().startswith("bearer "):
        value = value[7:].strip()
    if not TOKEN_RE.match(value):
        raise ValueError(
            "That is not a Cloudflare API token: make one under My Profile → API Tokens with Zone → DNS → Edit "
            "for the zone, and paste the token it shows once. If your browser filled this box in, clear it."
        )
    return value


def in_zone(hostname: str, zone: str) -> bool:
    """Whether ``hostname`` is the zone itself or a name under it."""
    hostname, zone = hostname.lower().rstrip("."), zone.lower().rstrip(".")
    return hostname == zone or hostname.endswith("." + zone)


def wildcard_for(hostname: str, zone: str) -> str | None:
    """``*.<parent>`` for a name inside the zone, the wildcard that would answer for it; None for the apex."""
    hostname = hostname.lower().rstrip(".")
    if not in_zone(hostname, zone) or hostname == zone.lower().rstrip(".") or "." not in hostname:
        return None
    return "*." + hostname.split(".", 1)[1]


def comment_for(env_name: str, env_id: uuid.UUID | str) -> str:
    """The comment on every record Slipway makes for an environment (Cloudflare allows 100 characters)."""
    return f"{MARKER}: {env_name} ({_hex12(env_id)})"[:100]


def is_ours(comment: str | None, env_id: uuid.UUID | str) -> bool:
    """Whether a record's comment says Slipway made it for this environment (the name may have changed since)."""
    comment = comment or ""
    return comment.startswith(MARKER) and f"({_hex12(env_id)})" in comment


def _hex12(env_id: uuid.UUID | str) -> str:
    return (env_id.hex if isinstance(env_id, uuid.UUID) else uuid.UUID(str(env_id)).hex)[:12]


# -------------------------------------------------------------------------- client


Transport = httpx.AsyncBaseTransport | None
# Tests swap this for an httpx.MockTransport.
transport_factory: Callable[[], Transport] = lambda: None  # noqa: E731
# Tests swap this to skip the wait before a 429 is retried.
sleep: Callable[[float], Awaitable[None]] = asyncio.sleep


def _retry_after(resp: httpx.Response) -> float:
    try:
        wait = float(resp.headers.get("Retry-After") or 1)
    except ValueError:
        wait = 1.0  # an HTTP date or junk: wait a second
    return min(max(wait, 0.0), MAX_RETRY_AFTER)


class CloudflareClient:
    def __init__(self, token: str, *, transport: Transport = None, base_url: str = API_URL) -> None:
        self._token = token
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}", "User-Agent": "Slipway"},
            timeout=TIMEOUT,
            transport=transport if transport is not None else transport_factory(),
        )

    async def __aenter__(self) -> CloudflareClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    def _scrub(self, text: str) -> str:
        return text.replace(self._token, "<token>") if self._token else text

    async def _send(self, method: str, path: str, params: dict[str, Any] | None, body: Any) -> httpx.Response:
        try:
            return await self._client.request(method, path, params=params, json=body)
        except httpx.HTTPError as exc:
            raise CloudflareError(self._scrub(f"Could not reach Cloudflare ({type(exc).__name__}: {exc})")) from None

    async def _call(self, method: str, path: str, *, params: dict[str, Any] | None = None, body: Any = None) -> Any:
        """``result`` of a successful call; raises CloudflareError otherwise. A 429 is retried once."""
        resp = await self._send(method, path, params, body)
        if resp.status_code == 429:
            await sleep(_retry_after(resp))
            resp = await self._send(method, path, params, body)
        if resp.status_code < 400 and not resp.content:
            return None
        try:
            data = resp.json()
        except ValueError:
            data = None
        if resp.status_code >= 400 or not isinstance(data, dict) or data.get("success") is False:
            raise self._error(method, path, resp, data)
        return data.get("result")

    def _error(self, method: str, path: str, resp: httpx.Response, data: Any) -> CloudflareError:
        errors = (data.get("errors") if isinstance(data, dict) else None) or []
        codes = [int(e["code"]) for e in errors if isinstance(e, dict) and str(e.get("code", "")).isdigit()]
        theirs = "; ".join(str(e.get("message") or "") for e in errors if isinstance(e, dict)) or resp.text
        theirs = self._scrub(" ".join(theirs.split()))[:MESSAGE_CHARS]
        status = resp.status_code
        if status in (401, 403):
            ours = "Cloudflare refused the token (check that it is active and may edit DNS in this zone)"
        elif status == 404 and set(codes) & ZONE_CODES:
            ours = "Cloudflare doesn't know that zone, or this token can't see it"
        elif status == 404:
            ours = "Cloudflare doesn't know that zone or record"
        elif status == 429:
            ours = "Cloudflare is limiting requests; try again in a minute"
        elif status >= 500:
            ours = "Cloudflare had a problem"
        elif status >= 400:
            ours = "Cloudflare rejected the request"
        else:
            ours = "Cloudflare's answer was not what Slipway expected"
        detail = ", ".join(str(c) for c in codes)
        text = f"{ours} ({method} {path}, HTTP {status}" + (f", code {detail}" if detail else "") + ")"
        if theirs:
            text += f": {theirs}"
        gone = status == 404 and "/dns_records/" in path and not set(codes) & ZONE_CODES
        cls = RecordGone if gone else CloudflareError
        return cls(text, status, codes)

    # -- the calls Slipway makes

    async def verify_token(self) -> bool:
        result = await self._call("GET", "/user/tokens/verify")
        return (result or {}).get("status") == "active"

    async def zone_id(self, zone: str) -> str:
        zones = await self._call("GET", "/zones", params={"name": zone, "status": "active"}) or []
        if len(zones) > 1:
            raise CloudflareError(f"This token sees {len(zones)} active zones named {zone}; give it access to one only")
        if not zones:
            raise CloudflareError(f"No active zone {zone} for this token")
        return str(zones[0]["id"])

    async def records(self, zone_id: str, name: str) -> list[dict[str, Any]]:
        """Every record at exactly ``name``, of every type."""
        return list(await self._call("GET", f"/zones/{zone_id}/dns_records",
                                     params={"name": name, "per_page": 100}) or [])

    async def get_record(self, zone_id: str, record_id: str) -> dict[str, Any] | None:
        """The record, or None when Cloudflare says it doesn't exist. A 404 about the zone raises."""
        try:
            return await self._call("GET", f"/zones/{zone_id}/dns_records/{record_id}")
        except RecordGone:
            return None

    async def create_a(self, zone_id: str, name: str, content: str, proxied: bool, comment: str) -> dict[str, Any]:
        return await self._call("POST", f"/zones/{zone_id}/dns_records", body={
            "type": "A", "name": name, "content": content, "ttl": 1, "proxied": bool(proxied), "comment": comment,
        })

    async def update_a(self, zone_id: str, record_id: str, content: str, proxied: bool,
                       comment: str) -> dict[str, Any]:
        """PATCH the record; TTL goes back to automatic, so a claimed record ends up like a created one."""
        return await self._call("PATCH", f"/zones/{zone_id}/dns_records/{record_id}", body={
            "content": content, "proxied": bool(proxied), "ttl": 1, "comment": comment,
        })

    async def delete_record(self, zone_id: str, record_id: str) -> bool:
        """True when deleted, False when it was already gone. A 404 about the zone raises."""
        try:
            await self._call("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")
        except RecordGone:
            return False
        return True

    async def can_read_records(self, zone_id: str) -> None:
        await self._call("GET", f"/zones/{zone_id}/dns_records", params={"per_page": 1})


async def check_connection(config: CloudflareConfig) -> str:
    """The Test button's one line; raises CloudflareError when something is wrong."""
    async with CloudflareClient(config.token) as cf:
        if not await cf.verify_token():
            raise CloudflareError("Cloudflare says this token is not active")
        zone_id = await cf.zone_id(config.zone)
        await cf.can_read_records(zone_id)
    return (f"Connected: zone {config.zone}; the token is active and can read its records. "
            "Slipway can't check that it may edit them without changing one.")


# ------------------------------------------------------------------------ planning


# What plan_dns decides for a name (§10.4). ``ok`` and ``covered`` need nothing; ``update`` and
# ``create`` are writes; ``claimable`` and ``conflict`` are blockers. Stale rows are ``delete`` or ``forget``.
OK, UPDATE, CREATE, COVERED, CLAIMABLE, CONFLICT = "ok", "update", "create", "covered", "claimable", "conflict"
DELETE, FORGET = "delete", "forget"
# ``adopt``: the name's only A record carries this environment's comment but no row names it (Slipway made it and
# lost the answer, or stopped before recording it). Not a blocker: the publisher records it (origin created) before
# any write, forgetting ``row_id`` first when ``forget_row`` is set, then updates it when ``after`` is set. A
# publisher that doesn't know this status leaves the record as it is, which is no worse than before.
ADOPT = "adopt"
BLOCKING = (CLAIMABLE, CONFLICT)


@dataclass(frozen=True)
class DnsRow:
    """The parts of a ``resources`` row (provider cloudflare, kind dns_record) that planning needs."""

    id: uuid.UUID | None
    environment_id: uuid.UUID
    provider_id: str
    name: str
    origin: str  # created | claimed


def as_row(row: Any) -> DnsRow:
    """A ``Resource`` (or a dict with the same keys) as a DnsRow."""
    get = row.get if isinstance(row, Mapping) else lambda k, d=None: getattr(row, k, d)
    env_id = get("environment_id")
    return DnsRow(
        id=get("id"),
        environment_id=env_id if isinstance(env_id, uuid.UUID) else uuid.UUID(str(env_id)),
        provider_id=str(get("provider_id")),
        name=str(get("name")).lower().rstrip("."),
        origin=str(get("origin") or "created"),
    )


def zone_of(row: Any, default: str) -> str:
    """The zone id a ``resources`` row's record was made or claimed in (``details.zone_id``), else ``default``."""
    get = row.get if isinstance(row, Mapping) else lambda k, d=None: getattr(row, k, d)
    return str((get("details") or {}).get("zone_id") or default)


def _is_dns_row(row: Any) -> bool:
    """Skip rows of other providers or kinds, in case a caller passed every resource of an environment."""
    get = row.get if isinstance(row, Mapping) else lambda k, d=None: getattr(row, k, d)
    return get("provider", PROVIDER) == PROVIDER and get("kind", KIND) == KIND


@dataclass
class DnsChange:
    name: str
    status: str
    record_id: str | None = None  # the Cloudflare record this is about, when there is one
    row_id: uuid.UUID | None = None  # our resources row for the name, when there is one
    forget_row: bool = False  # the row names a record that is gone: forget it before writing
    before: dict[str, Any] | None = None  # the record as read
    after: dict[str, Any] | None = None  # {content, proxied} Slipway will write (update, create)
    message: str = ""  # a summary, or for a blocker why

    def to_json(self) -> dict[str, Any]:
        out = asdict(self)
        out["row_id"] = str(self.row_id) if self.row_id else None
        return out


@dataclass
class DnsPlan:
    changes: list[DnsChange] = field(default_factory=list)  # one per wanted name, then the stale rows

    @property
    def blockers(self) -> list[str]:
        return [c.message for c in self.changes if c.status in BLOCKING]

    @property
    def writes(self) -> list[DnsChange]:
        return [c for c in self.changes if c.status in (UPDATE, CREATE, DELETE)]

    def by_name(self) -> dict[str, DnsChange]:
        return {c.name: c for c in self.changes if c.status not in (DELETE, FORGET)}

    def to_json(self) -> dict[str, Any]:
        return {"changes": [c.to_json() for c in self.changes], "blockers": self.blockers}


def _summary(record: Mapping[str, Any] | None) -> str:
    if not record:
        return ""
    proxied = ", proxied" if record.get("proxied") else ""
    return f"{record.get('type')} {record.get('content')}{proxied}"


def _matches(record: Mapping[str, Any], want: Mapping[str, Any]) -> bool:
    return (record.get("type") == "A" and record.get("content") == want["content"]
            and bool(record.get("proxied")) == bool(want["proxied"]))


def plan_dns(
    wanted: Mapping[str, Mapping[str, Any]],
    records_by_name: Mapping[str, list[Mapping[str, Any]]],
    wildcards: Mapping[str, list[Mapping[str, Any]]],
    rows: Iterable[Any],
    env_id: uuid.UUID,
    *,
    zone: str,
    env_names: Mapping[uuid.UUID, str] | None = None,
) -> DnsPlan:
    """What publishing ``wanted`` (``{hostname: {content, proxied}}``) would do. Reads and writes nothing.

    ``records_by_name``: every record Slipway read, keyed by its own name: the records at each wanted
    name, and the record each of this environment's rows names, wherever it now is (``read_state``
    reads both). A row whose record isn't among them is taken to be gone.
    ``wildcards``: the records at ``*.<parent>`` for each wanted name (``wildcard_for``).
    ``rows``: the Cloudflare ``dns_record`` resources of **every** environment, so a record another
    environment holds is seen as theirs. ``zone``: names outside it are conflicts.
    """
    env_names = env_names or {}
    all_rows = [as_row(r) for r in rows if _is_dns_row(r)]
    mine = {r.name: r for r in all_rows if r.environment_id == env_id}
    holder = {r.provider_id: r for r in all_rows}  # record id -> the row holding it
    by_id = {str(rec.get("id")): (name.lower().rstrip("."), rec)
             for name, recs in records_by_name.items() for rec in recs}

    def at(name: str) -> list[Mapping[str, Any]]:
        return [rec for n, recs in records_by_name.items() if n.lower().rstrip(".") == name for rec in recs]

    def held_elsewhere(rec: Mapping[str, Any], name: str) -> str | None:
        """Why this record isn't free for ``name``: another environment's, or ours under another name."""
        row = holder.get(str(rec.get("id")))
        if row is None or (row.environment_id == env_id and row.name == name):
            return None
        if row.environment_id != env_id:
            who = env_names.get(row.environment_id)
            return (f"{name}: its A record is managed by "
                    + (f"environment {who}" if who else "another Slipway environment"))
        return f"{name}: its A record is the one Slipway made for {row.name}; it was renamed in Cloudflare"

    def adoptable(a_records: list, blocking: list) -> bool:
        """A lone A record carrying this environment's comment that no row holds (F42)."""
        return (len(a_records) == 1 and not blocking and holder.get(str(a_records[0].get("id"))) is None
                and is_ours(a_records[0].get("comment"), env_id))

    plan = DnsPlan()
    for raw_name in sorted(wanted):
        name = raw_name.lower().rstrip(".")
        want = {"content": wanted[raw_name]["content"], "proxied": bool(wanted[raw_name].get("proxied"))}
        target = f"A {want['content']}" + (", proxied" if want["proxied"] else "")
        here = at(name)
        a_records = [r for r in here if r.get("type") == "A"]
        blocking = [r for r in here if r.get("type") in BLOCKING_TYPES]
        row = mine.get(name)

        def change(status: str, message: str, record: Mapping[str, Any] | None = None, **kw: Any) -> None:
            plan.changes.append(DnsChange(
                name=name, status=status, record_id=str(record["id"]) if record else None,
                row_id=row.id if row else None, before=dict(record) if record else None, message=message, **kw))

        if not in_zone(name, zone):
            change(CONFLICT, f"{name} isn't in the Cloudflare zone {zone}")
            continue

        if row is not None:
            found = by_id.get(row.provider_id)
            if found is not None and found[0] != name:
                change(CONFLICT, f"{name}: the record Slipway recorded for it is now named {found[0]} in Cloudflare; "
                       "rename it back or delete it there", found[1])
                continue
            if found is not None:
                record = found[1]
                others = [r for r in here if str(r.get("id")) != row.provider_id]
                if record.get("type") != "A":
                    change(CONFLICT, f"{name}: the record Slipway recorded is now a {record.get('type')} record; "
                           "change it back to A or delete it in Cloudflare", record)
                elif row.origin != "claimed" and not is_ours(record.get("comment"), env_id):
                    # I7: Slipway changes a record it created only while it still carries its comment.
                    change(CONFLICT, f"{name}: someone took this record over in Cloudflare (its comment no longer "
                           f"says Slipway manages it, and it is {_summary(record)}); put Slipway's comment back, "
                           "or delete the record there so Slipway can make it again", record)
                elif [r for r in others if r.get("type") == "A"]:
                    change(CONFLICT, f"{name} has {len(a_records)} A records; Slipway manages one of them, "
                           "so delete the others in Cloudflare", record)
                elif [r for r in others if r.get("type") in BLOCKING_TYPES]:
                    bad = next(r for r in others if r.get("type") in BLOCKING_TYPES)
                    change(CONFLICT, f"{name} also has a {bad.get('type')} record; delete it in Cloudflare", record)
                elif _matches(record, want):
                    change(OK, f"{name} → {target}", record)
                else:
                    change(UPDATE, f"{name} → {target} (was {_summary(record)})", record, after=want)
                continue
            # Our record is gone. Something else at the name is in the way (unless it is one Slipway made for this
            # environment and never recorded: adopted below); otherwise plan it afresh.
            if (a_records or blocking) and not adoptable(a_records, blocking):
                bad = (a_records or blocking)[0]
                change(CONFLICT, f"{name}: the record Slipway made is gone and Cloudflare now has a {bad.get('type')} "
                       f"record there ({_summary(bad)}) that Slipway didn't make", bad)
                continue

        forget_row = row is not None  # reached only with no row, or a row whose record is gone
        if blocking:
            bad = blocking[0]
            change(CONFLICT, f"{name} has a {bad.get('type')} record in Cloudflare ({bad.get('content')}); "
                   "delete it there, or publish another name", bad, forget_row=forget_row)
        elif len(a_records) > 1:
            change(CONFLICT, f"{name} has {len(a_records)} A records in Cloudflare; leave at most one",
                   forget_row=forget_row)
        elif a_records:
            why = held_elsewhere(a_records[0], name)
            if why:
                change(CONFLICT, why, a_records[0], forget_row=forget_row)
            elif adoptable(a_records, blocking):
                record = a_records[0]
                if _matches(record, want):
                    change(ADOPT, f"{name}: Slipway made this record ({_summary(record)}) but hadn't recorded it; "
                           "it will be recorded", record, forget_row=forget_row)
                else:
                    change(ADOPT, f"{name} → {target} (Slipway made this record but hadn't recorded it; "
                           f"was {_summary(record)})", record, after=want, forget_row=forget_row)
            else:
                change(CLAIMABLE, f"{name} already has an A record ({_summary(a_records[0])}) that Slipway didn't "
                       "make; claim it on the environment page, or delete it in Cloudflare", a_records[0],
                       forget_row=forget_row)
        elif not here and _covered(name, zone, wildcards, want):
            change(COVERED, f"{name} is answered by the wildcard {wildcard_for(name, zone)} ({target})",
                   forget_row=forget_row)
        else:
            change(CREATE, f"{name} → {target} (new)", after=want, forget_row=forget_row)

    # Rows for names no longer wanted: delete what Slipway made and still carries its comment.
    wanted_names = {n.lower().rstrip(".") for n in wanted}
    for name in sorted(set(mine) - wanted_names):
        row = mine[name]
        found = by_id.get(row.provider_id)
        record = found[1] if found else None
        still_ours = (record is not None and found[0] == name and record.get("type") == "A"
                      and is_ours(record.get("comment"), env_id))
        if row.origin == "created" and still_ours:
            plan.changes.append(DnsChange(name=name, status=DELETE, record_id=row.provider_id, row_id=row.id,
                                          before=dict(record), message=f"{name}: remove {_summary(record)}"))
        else:
            why = ("claimed, so Cloudflare keeps it" if row.origin == "claimed"
                   else "no longer Slipway's record" if record is not None else "already gone")
            plan.changes.append(DnsChange(name=name, status=FORGET, record_id=row.provider_id, row_id=row.id,
                                          before=dict(record) if record else None, message=f"{name}: forget ({why})"))
    return plan


def _covered(name: str, zone: str, wildcards: Mapping[str, list[Mapping[str, Any]]],
             want: Mapping[str, Any]) -> bool:
    """Whether ``*.<parent>`` already answers for ``name`` with exactly the wanted A record."""
    wild = wildcard_for(name, zone)
    if wild is None:
        return False
    recs = [r for n, rs in wildcards.items() if n.lower().rstrip(".") == wild for r in rs]
    a_records = [r for r in recs if r.get("type") == "A"]
    return (len(a_records) == 1 and not [r for r in recs if r.get("type") in BLOCKING_TYPES]
            and _matches(a_records[0], want))


async def read_state(
    client: CloudflareClient, zone_id: str, zone: str, names: Iterable[str], my_rows: Iterable[Any],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    """What ``plan_dns`` needs from Cloudflare: ``(records_by_name, wildcards)``. Reads only.

    Reads the records at each name inside the zone, the wildcard above each, and every record one
    of ``my_rows`` (this environment's rows) names that wasn't found at its own name, in the row's zone.
    """
    names = sorted({n.lower().rstrip(".") for n in names})
    records_by_name: dict[str, list[dict[str, Any]]] = {}
    for name in names:
        if in_zone(name, zone):
            records_by_name[name] = await client.records(zone_id, name)
    wildcards: dict[str, list[dict[str, Any]]] = {}
    for wild in sorted({w for n in names if (w := wildcard_for(n, zone))}):
        wildcards[wild] = await client.records(zone_id, wild)
    seen = {str(r.get("id")) for recs in records_by_name.values() for r in recs}
    for raw in (r for r in my_rows if _is_dns_row(r)):
        row = as_row(raw)
        if row.provider_id in seen:
            continue
        # In the zone the row records (a record is never looked for in another zone and taken to be gone).
        record = await client.get_record(zone_of(raw, zone_id), row.provider_id)
        if record is not None:
            records_by_name.setdefault(str(record.get("name", "")).lower().rstrip("."), []).append(record)
            seen.add(row.provider_id)
    return records_by_name, wildcards
