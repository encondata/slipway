"""The DigitalOcean API client: the calls Slipway makes, and nothing else.

One seam (``transport_factory``) for tests, as Cloudflare's and Switchyard's. The rules every call
follows (phase 4 §7, D25):

* ``https://api.digitalocean.com/v2``, ``Authorization: Bearer <token>`` and ``User-Agent: Slipway``
  only; 30 s per call; lists read 200 a page and at most 10 pages.
* **Only a 404 means gone.** ``get``-style methods (``droplet``, ``vpc``, ``load_balancer`` …)
  answer None on a 404, ``delete_*`` answer False. A 403 is always ``Forbidden``, on a read as on
  a write: it is never turned into None, False or an empty list, so a token that can't read a kind
  never makes Slipway forget a billing object and make a second one (J13). A 401 is
  ``DigitalOcean rejected the API token``; anything else is a ``DigitalOceanError``.
* A 429 is retried once, after ``Retry-After``, else ``RateLimit-Reset`` minus now, else 5 s, and
  never more than 30 s. A 429 means DigitalOcean did nothing, so writes are retried after one too.
  A GET that answers 502, 503 or 504 is retried once after 2 s. Any other write is never retried:
  it may have landed, and a lost answer is what the pending ``resources`` row is for (§6.4).
* IDs are checked before they go into a path. DigitalOcean's error ``id`` is named only when it
  looks like one (``[a-z_]{1,40}``); its ``message`` is never kept, since it can carry anything.
* The token is never put in an error, a repr or a URL. Pass the job's ``ssh.Redactor`` and the
  token is added to it.

``poll`` is the wait every provisioning step uses (``waits.poll`` in the design).
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

API_URL = "https://api.digitalocean.com/v2"
TIMEOUT = 30
PER_PAGE = 200
MAX_PAGES = 10
MAX_RETRY_AFTER = 30.0  # seconds; a 429 is retried once, after at most this long
DEFAULT_RETRY_AFTER = 5.0  # a 429 that names no wait
GET_RETRY_WAIT = 2.0  # before the one retry of a GET that answered 502, 503 or 504
GET_RETRY_STATUSES = (502, 503, 504)
POLL_EVERY = 10.0

# IDs Slipway puts in a path (droplet ids are numbers, the rest UUIDs; Spaces access keys are
# upper-case letters and digits). Anything else is refused before a request is made.
ID_RE = re.compile(r"^[A-Za-z0-9-]{1,128}$")
# DigitalOcean's tag names: letters, digits, ``:``, ``-`` and ``_``, at most 255.
TAG_RE = re.compile(r"^[A-Za-z0-9:_-]{1,255}$")
# DigitalOcean's error ids (``not_found``, ``unprocessable_entity``, ``forbidden``) are named in our
# text only when they look like one.
ERROR_ID_RE = re.compile(r"^[a-z_]{1,40}$")
# A 403 or 409 whose message says the object is in use (a certificate on a load balancer, a VPC
# with members). Only this flag is kept, never the message itself.
IN_USE_RE = re.compile(r"\bin[ -]use\b|\bbeing used\b|\bhas members\b|\bwith members\b", re.I)

# The first path segment -> how our texts name the kind.
_KINDS = {
    "account": "the account",
    "regions": "regions",
    "sizes": "sizes",
    "vpcs": "VPCs",
    "droplets": "droplets",
    "databases": "databases",
    "spaces": "Spaces keys",
    "certificates": "certificates",
    "load_balancers": "load balancers",
    "firewalls": "firewalls",
}
_VERBS = {"GET": "read", "POST": "create", "PUT": "change", "PATCH": "change", "DELETE": "delete"}


class DigitalOceanError(RuntimeError):
    """A DigitalOcean call failed. ``str()`` is Slipway's own text.

    ``status`` is the HTTP status (None when DigitalOcean wasn't reached or its answer made no
    sense); ``error_id`` is DigitalOcean's error id when it looked like one; ``in_use`` says the
    answer was about an object still in use (a certificate on a load balancer, a VPC with members).
    """

    def __init__(self, reason: str, status: int | None = None, *, method: str = "", path: str = "",
                 error_id: str | None = None, in_use: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status
        self.method = method
        self.path = path
        self.error_id = error_id
        self.in_use = in_use


class NotFound(DigitalOceanError):
    """A 404: the object is gone. The only error that means so."""


class Forbidden(DigitalOceanError):
    """A 403: the token may not do this (a custom-scoped token, or an object in use). Never "gone"."""


class Unauthorized(DigitalOceanError):
    """A 401: the token is wrong, expired or revoked."""


class Unreachable(DigitalOceanError):
    """No answer: a network error or a timeout. A write may still have landed."""


def check_id(value: Any) -> str:
    """``value`` as a string fit for a URL path, or a DigitalOceanError before any request is made."""
    text = str(value) if isinstance(value, (str, int)) and not isinstance(value, bool) else ""
    if not ID_RE.fullmatch(text):
        # The value itself isn't repeated: it may be anything, and it didn't come from DigitalOcean.
        raise DigitalOceanError("That isn't a DigitalOcean id Slipway can use, so Slipway didn't send the request")
    return text


def check_tag(value: str) -> str:
    if not isinstance(value, str) or not TAG_RE.fullmatch(value):
        raise DigitalOceanError(
            "That isn't a DigitalOcean tag name Slipway can use, so Slipway didn't send the request")
    return value


def droplet_ips(droplet: dict[str, Any] | None) -> tuple[str | None, str | None]:
    """``(public, private)`` IPv4 addresses of a droplet, each None until DigitalOcean assigned it."""
    public = private = None
    networks = (droplet or {}).get("networks") or {}
    for net in networks.get("v4") or []:
        if not isinstance(net, dict) or not net.get("ip_address"):
            continue
        if net.get("type") == "public" and public is None:
            public = str(net["ip_address"])
        elif net.get("type") == "private" and private is None:
            private = str(net["ip_address"])
    return public, private


# -------------------------------------------------------------------------- seams


Transport = httpx.AsyncBaseTransport | None
# Tests swap this for ``lambda: httpx.MockTransport(FakeDigitalOcean().handler)``.
transport_factory: Callable[[], Transport] = lambda: None  # noqa: E731
# Tests swap these for the fake's clock, so waits take no time.
sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
clock: Callable[[], float] = time.time  # wall clock, for RateLimit-Reset (a Unix time)
monotonic: Callable[[], float] = time.monotonic  # for poll's limit


def _retry_after(resp: httpx.Response) -> float:
    """How long to wait before the one retry of a 429."""
    wait: float | None = None
    try:
        wait = float(resp.headers["Retry-After"])
    except (KeyError, ValueError):
        try:
            wait = float(resp.headers["RateLimit-Reset"]) - clock()
        except (KeyError, ValueError):
            wait = None
    if wait is None:
        wait = DEFAULT_RETRY_AFTER
    return min(max(wait, 0.0), MAX_RETRY_AFTER)


def _kind(path: str) -> str:
    first = path.strip("/").split("/", 1)[0]
    return _KINDS.get(first, "that")


# -------------------------------------------------------------------------- client


class DigitalOceanClient:
    """One account's token. Use as ``async with DigitalOceanClient(token, redactor=r) as do: …``."""

    def __init__(self, token: str, *, redactor: Any = None, transport: Transport = None,
                 base_url: str = API_URL) -> None:
        self._token = token
        if redactor is not None:
            redactor.add(token)
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}", "User-Agent": "Slipway"},
            timeout=TIMEOUT,
            follow_redirects=False,  # the token goes to api.digitalocean.com only
            transport=transport if transport is not None else transport_factory(),
        )

    def __repr__(self) -> str:  # keep the token out of logs and tracebacks
        return "DigitalOceanClient(token=<hidden>)"

    async def __aenter__(self) -> DigitalOceanClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- transport

    async def _send(self, method: str, path: str, params: dict[str, Any] | None, body: Any) -> httpx.Response:
        try:
            return await self._client.request(method, path, params=params, json=body)
        except httpx.HTTPError as exc:
            # Only the exception's type: its text can hold the URL and, from some transports, headers.
            raise Unreachable(f"Couldn't reach the DigitalOcean API ({type(exc).__name__})",
                              method=method, path=path) from None

    async def _call(self, method: str, path: str, *, params: dict[str, Any] | None = None,
                    body: Any = None) -> dict[str, Any]:
        """The answer's JSON object (``{}`` for an empty 2xx); raises DigitalOceanError otherwise."""
        resp = await self._send(method, path, params, body)
        if resp.status_code == 429:
            await sleep(_retry_after(resp))
            resp = await self._send(method, path, params, body)
        if method == "GET" and resp.status_code in GET_RETRY_STATUSES:
            await sleep(GET_RETRY_WAIT)
            resp = await self._send(method, path, params, body)
            if resp.status_code == 429:  # the retry was limited: one wait, one more try
                await sleep(_retry_after(resp))
                resp = await self._send(method, path, params, body)
        if resp.status_code >= 400:
            raise self._error(method, path, resp)
        if resp.status_code < 200 or resp.status_code >= 300:
            raise self._misunderstood(method, path, resp.status_code)
        if not resp.content or not resp.content.strip():
            return {}
        try:
            data = resp.json()
        except ValueError:
            data = None
        if not isinstance(data, dict):
            raise self._misunderstood(method, path, resp.status_code)
        return data

    def _misunderstood(self, method: str, path: str, status: int | None) -> DigitalOceanError:
        return DigitalOceanError(f"DigitalOcean sent a response Slipway didn't understand ({method} {path})",
                                 status, method=method, path=path)

    def _error(self, method: str, path: str, resp: httpx.Response) -> DigitalOceanError:
        status = resp.status_code
        try:
            data = resp.json()
        except ValueError:
            data = None
        data = data if isinstance(data, dict) else {}
        raw_id = data.get("id")
        error_id = raw_id if isinstance(raw_id, str) and ERROR_ID_RE.fullmatch(raw_id) else None
        message = data.get("message")
        in_use = isinstance(message, str) and bool(IN_USE_RE.search(message))  # the flag only; never the text
        kind = _kind(path)
        where = f"{method} {path}, HTTP {status}" + (f", {error_id}" if error_id else "")
        kw = {"method": method, "path": path, "error_id": error_id, "in_use": in_use}
        if status == 401:
            return Unauthorized("DigitalOcean rejected the API token", status, **kw)
        if status == 403:
            verb = _VERBS.get(method, "use")
            if method == "POST" and "/actions" in path:
                verb = "change"
            if in_use:
                return Forbidden(f"DigitalOcean won't {verb} it while it is in use ({where})", status, **kw)
            return Forbidden(f"The token can't {verb} {kind} (DigitalOcean answered 403)", status, **kw)
        if status == 404:
            return NotFound(f"DigitalOcean doesn't have that ({where})", status, **kw)
        if status == 429:
            return DigitalOceanError(f"DigitalOcean is limiting requests; try again in a minute ({where})",
                                     status, **kw)
        if status >= 500:
            return DigitalOceanError(f"DigitalOcean had a problem ({where})", status, **kw)
        return DigitalOceanError(f"DigitalOcean refused the request ({where})", status, **kw)

    # -- helpers

    async def _get(self, path: str, key: str, *, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
        """``answer[key]``, or None on a 404. Every other error raises (J13)."""
        try:
            data = await self._call("GET", path, params=params)
        except NotFound:
            return None
        return self._obj(data, key, "GET", path)

    def _obj(self, data: dict[str, Any], key: str, method: str, path: str) -> dict[str, Any]:
        value = data.get(key)
        if not isinstance(value, dict):
            raise self._misunderstood(method, path, None)
        return value

    async def _write(self, method: str, path: str, body: Any, key: str | None) -> dict[str, Any]:
        data = await self._call(method, path, body=body)
        if key is None:
            return data
        return self._obj(data, key, method, path)

    async def _delete(self, path: str) -> bool:
        """True when deleted, False when it was already gone (404). Every other error raises."""
        try:
            await self._call("DELETE", path)
        except NotFound:
            return False
        return True

    async def _list(self, path: str, key: str, *, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Every item of a paged list, following ``links.pages.next``; at most 10 pages.

        Only the page number is taken from ``next``: the request goes to the same path on the
        same base URL, so the token can't be sent anywhere else.
        """
        items: list[dict[str, Any]] = []
        page = 1
        for _ in range(MAX_PAGES):
            query = dict(params or {})
            query.update(per_page=PER_PAGE, page=page)
            data = await self._call("GET", path, params=query)
            if key not in data:  # an answer without the list is never read as an empty one (J13)
                raise self._misunderstood("GET", path, None)
            value = data[key]
            if value is None:
                value = []  # DigitalOcean answers ``"databases": null`` when there are none
            if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
                raise self._misunderstood("GET", path, None)
            items.extend(value)
            next_page = self._next_page(data, path, page)
            if next_page is None:
                return items
            page = next_page
        raise DigitalOceanError("DigitalOcean listed more than Slipway reads", method="GET", path=path)

    def _next_page(self, data: dict[str, Any], path: str, page: int) -> int | None:
        links = data.get("links")
        pages = links.get("pages") if isinstance(links, dict) else None
        nxt = pages.get("next") if isinstance(pages, dict) else None
        if not nxt:
            return None
        try:
            url = httpx.URL(str(nxt))
            number = int(url.params.get("page", ""))
        except (ValueError, TypeError, httpx.InvalidURL):
            raise self._misunderstood("GET", path, None) from None
        if number <= page:
            raise self._misunderstood("GET", path, None)
        return number

    # -- account and catalog

    async def account(self) -> dict[str, Any]:
        """``GET /account``: status, ``team {uuid, name}``, droplet limit."""
        return self._obj(await self._call("GET", "/account"), "account", "GET", "/account")

    async def regions(self) -> list[dict[str, Any]]:
        return await self._list("/regions", "regions")

    async def sizes(self) -> list[dict[str, Any]]:
        """Droplet sizes, each with ``vcpus``, ``memory``, ``disk``, ``price_monthly`` and ``regions``."""
        return await self._list("/sizes", "sizes")

    async def database_options(self) -> dict[str, Any]:
        """``GET /databases/options``, whole: ``options.pg.{regions, versions, layouts}`` and more."""
        return await self._call("GET", "/databases/options")

    # -- VPCs

    async def vpcs(self) -> list[dict[str, Any]]:
        return await self._list("/vpcs", "vpcs")

    async def vpc(self, vpc_id: str) -> dict[str, Any] | None:
        return await self._get(f"/vpcs/{check_id(vpc_id)}", "vpc")

    async def create_vpc(self, body: dict[str, Any]) -> dict[str, Any]:
        """``POST /vpcs {name, region, description}`` (and ``ip_range`` when given)."""
        return await self._write("POST", "/vpcs", body, "vpc")

    async def delete_vpc(self, vpc_id: str) -> bool:
        return await self._delete(f"/vpcs/{check_id(vpc_id)}")

    async def vpc_members(self, vpc_id: str) -> list[dict[str, Any]] | None:
        """Members (``{urn, name, created_at}``) of a VPC; None when the VPC is gone."""
        path = f"/vpcs/{check_id(vpc_id)}/members"
        try:
            return await self._list(path, "members")
        except NotFound:
            return None

    # -- droplets

    async def droplet(self, droplet_id: str | int) -> dict[str, Any] | None:
        return await self._get(f"/droplets/{check_id(droplet_id)}", "droplet")

    async def droplets_tagged(self, tag: str) -> list[dict[str, Any]]:
        """``GET /droplets?tag_name=<tag>``: the env tag, or a create's request tag (§6.4)."""
        return await self._list("/droplets", "droplets", params={"tag_name": check_tag(tag)})

    async def create_droplet(self, body: dict[str, Any]) -> dict[str, Any]:
        """``POST /droplets``. The body carries ``user_data``, with the host's private key: it is
        sent once and never kept or logged here."""
        return await self._write("POST", "/droplets", body, "droplet")

    async def delete_droplet(self, droplet_id: str | int) -> bool:
        return await self._delete(f"/droplets/{check_id(droplet_id)}")

    async def droplet_action(self, droplet_id: str | int, type: str, **params: Any) -> dict[str, Any]:
        """``POST /droplets/{id}/actions {type, …}`` (``power_off``, ``power_on``, ``resize`` with
        ``size`` and ``disk``). Returns the action; poll it with ``get_action``."""
        body = {"type": type, **params}
        return await self._write("POST", f"/droplets/{check_id(droplet_id)}/actions", body, "action")

    async def get_action(self, droplet_id: str | int, action_id: str | int) -> dict[str, Any] | None:
        return await self._get(f"/droplets/{check_id(droplet_id)}/actions/{check_id(action_id)}", "action")

    # -- managed databases

    async def database(self, database_id: str) -> dict[str, Any] | None:
        return await self._get(f"/databases/{check_id(database_id)}", "database")

    async def databases_tagged(self, tag: str) -> list[dict[str, Any]]:
        return await self._list("/databases", "databases", params={"tag_name": check_tag(tag)})

    async def create_database(self, body: dict[str, Any]) -> dict[str, Any]:
        """``POST /databases``; the answer carries ``connection.password`` (doadmin's)."""
        return await self._write("POST", "/databases", body, "database")

    async def database_firewall(self, database_id: str) -> list[dict[str, Any]] | None:
        """The cluster's trusted sources (``[{type, value, …}]``); None when the cluster is gone."""
        path = f"/databases/{check_id(database_id)}/firewall"
        try:
            data = await self._call("GET", path)
        except NotFound:
            return None
        rules = data.get("rules")
        if rules is None:
            return []
        if not isinstance(rules, list) or not all(isinstance(r, dict) for r in rules):
            raise self._misunderstood("GET", path, None)
        return rules

    async def set_database_firewall(self, database_id: str, rules: list[dict[str, Any]]) -> None:
        """``PUT /databases/{id}/firewall {rules}``: the whole list. A 409 or 422 means "not ready"."""
        await self._call("PUT", f"/databases/{check_id(database_id)}/firewall", body={"rules": rules})

    async def database_ca(self, database_id: str) -> str | None:
        """The cluster's CA certificate, base64 as DigitalOcean gives it; None when the cluster is gone."""
        path = f"/databases/{check_id(database_id)}/ca"
        try:
            data = await self._call("GET", path)
        except NotFound:
            return None
        cert = self._obj(data, "ca", "GET", path).get("certificate")
        if not isinstance(cert, str) or not cert:
            raise self._misunderstood("GET", path, None)
        return cert

    async def resize_database(self, database_id: str, size: str, num_nodes: int) -> None:
        await self._call("PUT", f"/databases/{check_id(database_id)}/resize",
                         body={"size": size, "num_nodes": num_nodes})

    async def delete_database(self, database_id: str) -> bool:
        return await self._delete(f"/databases/{check_id(database_id)}")

    # -- Spaces keys

    async def spaces_keys(self) -> list[dict[str, Any]]:
        """Every Spaces key (``{name, access_key, grants, created_at}``; never a secret)."""
        return await self._list("/spaces/keys", "keys")

    async def create_spaces_key(self, name: str, grants: list[dict[str, Any]]) -> dict[str, Any]:
        """``POST /spaces/keys {name, grants}``. Its ``secret_key`` is shown this once."""
        return await self._write("POST", "/spaces/keys", {"name": name, "grants": grants}, "key")

    async def delete_spaces_key(self, access_key: str) -> bool:
        return await self._delete(f"/spaces/keys/{check_id(access_key)}")

    # -- certificates

    async def certificates(self) -> list[dict[str, Any]]:
        return await self._list("/certificates", "certificates")

    async def certificate(self, certificate_id: str) -> dict[str, Any] | None:
        return await self._get(f"/certificates/{check_id(certificate_id)}", "certificate")

    async def create_certificate(self, body: dict[str, Any]) -> dict[str, Any]:
        """``POST /certificates {name, type: custom, private_key, leaf_certificate, certificate_chain}``."""
        return await self._write("POST", "/certificates", body, "certificate")

    async def delete_certificate(self, certificate_id: str) -> bool:
        """False when already gone. A certificate a load balancer still uses raises ``Forbidden``
        with ``in_use`` set; the caller leaves it for the next run."""
        return await self._delete(f"/certificates/{check_id(certificate_id)}")

    # -- load balancers

    async def load_balancers(self) -> list[dict[str, Any]]:
        return await self._list("/load_balancers", "load_balancers")

    async def load_balancer(self, lb_id: str) -> dict[str, Any] | None:
        return await self._get(f"/load_balancers/{check_id(lb_id)}", "load_balancer")

    async def create_load_balancer(self, body: dict[str, Any]) -> dict[str, Any]:
        return await self._write("POST", "/load_balancers", body, "load_balancer")

    async def update_load_balancer(self, lb_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """``PUT /load_balancers/{id}`` with the **whole** body: what it leaves out, DigitalOcean resets."""
        return await self._write("PUT", f"/load_balancers/{check_id(lb_id)}", body, "load_balancer")

    async def delete_load_balancer(self, lb_id: str) -> bool:
        return await self._delete(f"/load_balancers/{check_id(lb_id)}")

    # -- cloud firewalls

    async def firewalls(self) -> list[dict[str, Any]]:
        return await self._list("/firewalls", "firewalls")

    async def firewall(self, firewall_id: str) -> dict[str, Any] | None:
        return await self._get(f"/firewalls/{check_id(firewall_id)}", "firewall")

    async def create_firewall(self, body: dict[str, Any]) -> dict[str, Any]:
        return await self._write("POST", "/firewalls", body, "firewall")

    async def update_firewall(self, firewall_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """``PUT /firewalls/{id}`` with the whole body (name, rules, tags, droplet ids)."""
        return await self._write("PUT", f"/firewalls/{check_id(firewall_id)}", body, "firewall")

    async def delete_firewall(self, firewall_id: str) -> bool:
        return await self._delete(f"/firewalls/{check_id(firewall_id)}")


# --------------------------------------------------------------------------- waits


def _span(seconds: float) -> str:
    if seconds >= 60 and seconds % 60 == 0:
        minutes = int(seconds // 60)
        return f"{minutes} minute" + ("" if minutes == 1 else "s")
    whole = int(seconds)
    return f"{whole} second" + ("" if whole == 1 else "s")


async def poll(fetch: Callable[[], Awaitable[Any]], ready: Callable[[Any], bool], seconds: float, what: str,
               *, every: float = POLL_EVERY) -> Any:
    """Read with ``fetch`` every ``every`` seconds until ``ready(obj)``; returns that object.

    ``fetch`` answers None when the object is gone (a 404): the wait fails at once with
    ``<what> disappeared from DigitalOcean while Slipway waited``. Past ``seconds`` it fails
    ``<what> wasn't ready after <n> minutes``. Any error ``fetch`` raises (a 403, say) is raised as is.
    """
    deadline = monotonic() + seconds
    while True:
        obj = await fetch()
        if obj is None:
            raise DigitalOceanError(f"{what} disappeared from DigitalOcean while Slipway waited")
        if ready(obj):
            return obj
        if monotonic() + every > deadline:
            raise DigitalOceanError(f"{what} wasn't ready after {_span(seconds)}")
        await sleep(every)
