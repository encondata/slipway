"""DigitalOcean Spaces buckets through the S3 API (Sirdar's ``spaces.py``, ported).

The DigitalOcean API can make Spaces keys but not buckets, so ``prepare`` and teardown talk S3 to
Spaces directly: make a bucket, check it is there, empty it, delete it, and read or set its CORS
rules. Requests use virtual-hosted addressing (``<bucket>.<region>.digitaloceanspaces.com``) and are
signed with SigV4 (``s3sig``), the region slug being the signing region.

What callers rely on:

* **Only a 404 means gone** (J13). ``bucket_exists`` is True on 200, False on 404, and raises on
  anything else; a 403 is always ``SpacesDenied``, never "absent".
* ``create_bucket`` is idempotent: our own bucket answers ``BucketAlreadyOwnedByYou``, or a 409 that a
  HEAD under the same key then answers 200. A name another account holds raises ``BucketTaken``.
* Writes are never retried (they may have landed); a GET or HEAD is retried once on 500, 502, 503 or
  504 (Spaces answers ``SlowDown`` with a 503 under load).
* Errors carry Slipway's own text. An S3 error ``<Code>`` is named when it is plain letters; Spaces'
  ``<Message>`` never is. The secret key is never logged, put in an error or in ``repr``.
* Responses are parsed with the standard library's ElementTree, which never fetches external
  entities; a body carrying a DOCTYPE is refused before parsing, so no entity can be declared.

Known limitation (as Sirdar's): versioned buckets. Slipway never turns versioning on, so
``empty_bucket`` deletes current objects and aborts unfinished multipart uploads, but doesn't remove
old versions or delete markers; a bucket someone versioned by hand refuses ``delete_bucket`` with
``BucketNotEmpty``, and the error says so.

Which key does what (the temporary full-access key, the bucket's own read-write key, deleting the
temporary one in a ``finally``) is the provisioner's business (spec §10.3); this module only signs
with the key it is given.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

import httpx

from slipway.services import s3sig

TIMEOUT = 30  # seconds per call, as the DigitalOcean client
MAX_PAGES = 10_000  # listing pages one empty_bucket reads before it gives up (1,000 keys a page)
GET_RETRY_WAIT = 2.0  # seconds before the one retry of a GET or HEAD on a 5xx
RETRIED_STATUSES = (500, 502, 503, 504)
DOMAIN = "digitaloceanspaces.com"
XMLNS = "http://s3.amazonaws.com/doc/2006-03-01/"

# DigitalOcean's bucket rules: 3-63 lowercase letters, digits and dashes, starting and ending with a
# letter or digit. No dots: a dotted name would break virtual-hosted TLS and could change the host.
BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
# A region slug such as nyc3 or sfo3. It becomes part of the host name, so nothing but letters,
# digits and dashes.
REGION_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")
_CODE_RE = re.compile(r"<Code>([A-Za-z]{1,60})</Code>")
_PLAIN_CODE_RE = re.compile(r"^[A-Za-z]{1,60}$")
_SAFE_CHARS_RE = re.compile(r"[^A-Za-z0-9._/@+=:, -]")

Transport = httpx.AsyncBaseTransport | None
# Tests swap this for an httpx.MockTransport over FakeSpaces.
transport_factory: Callable[[], Transport] = lambda: None  # noqa: E731
# Tests swap these to skip the wait before a retry, or to fix the signing time.
sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
clock: Callable[[], datetime] = lambda: datetime.now(UTC)  # noqa: E731


class SpacesError(RuntimeError):
    """A Spaces call failed. ``str()`` is Slipway's text; ``status`` and ``code`` are Spaces' answer."""

    def __init__(self, message: str, status: int | None = None, code: str | None = None) -> None:
        super().__init__(message)
        self.reason = message
        self.status = status
        self.code = code


class SpacesDenied(SpacesError):
    """Spaces answered 403 to the key, so a caller may retry with a key that may do more."""


class BucketTaken(SpacesError):
    """Another account holds the bucket's name (bucket names are global across Spaces)."""


@dataclass(frozen=True)
class SpacesKey:
    access_key: str
    secret_key: str = field(repr=False)


def endpoint(region: str) -> str:
    """The S3 endpoint an app is given (``SS_SPACES_ENDPOINT``), path-style off."""
    _check_region(region)
    return f"https://{region}.{DOMAIN}"


def bucket_host(bucket: str, region: str) -> str:
    _check_bucket(bucket)
    _check_region(region)
    return f"{bucket}.{region}.{DOMAIN}"


def _check_bucket(bucket: object) -> None:
    if not isinstance(bucket, str) or not BUCKET_RE.fullmatch(bucket):
        raise SpacesError("That isn't a valid Spaces bucket name (3-63 lowercase letters, digits and dashes)")


def _check_region(region: object) -> None:
    if not isinstance(region, str) or not REGION_RE.fullmatch(region):
        raise SpacesError("That isn't a valid Spaces region (a slug such as nyc3)")


def _safe(text: str, limit: int = 80) -> str:
    """An object name cut to safe characters, for an error message."""
    text = _SAFE_CHARS_RE.sub("?", text)
    return text if len(text) <= limit else text[:limit] + "…"


def _code(resp: httpx.Response) -> str | None:
    found = _CODE_RE.search(resp.text or "")
    return found.group(1) if found else None


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _elements(root: ET.Element, name: str) -> list[ET.Element]:
    """Direct children named ``name``, with or without the S3 namespace."""
    return [el for el in root if _local(el.tag) == name]


def _child_text(el: ET.Element, name: str) -> str:
    found = _elements(el, name)
    return (found[0].text or "") if found else ""


def _parse(resp: httpx.Response, what: str) -> ET.Element:
    content = resp.content or b""
    if b"<!DOCTYPE" in content.upper() or b"<!ENTITY" in content.upper():
        raise SpacesError(f"Spaces sent {what} Slipway didn't understand", resp.status_code)
    try:
        return ET.fromstring(content)
    except ET.ParseError:
        raise SpacesError(f"Spaces sent {what} Slipway didn't understand", resp.status_code) from None


def _refused(resp: httpx.Response, what: str) -> SpacesError:
    code = _code(resp)
    return SpacesError(f"Spaces refused to {what} ({code or f'HTTP {resp.status_code}'})", resp.status_code, code)


def _md5(doc: bytes) -> str:
    # S3 requires Content-MD5 on a multi-object delete and a CORS write; it is an integrity check only.
    return base64.b64encode(hashlib.md5(doc, usedforsecurity=False).digest()).decode()


# ------------------------------------------------------------------------------------------ CORS

CORS_METHODS = ("GET", "HEAD", "PUT")
CORS_HEADERS = ("*",)  # the presigned URL signs what matters; any request header may pass
CORS_EXPOSE = ("ETag",)
CORS_MAX_AGE = 3000


@dataclass(frozen=True, order=True)
class CorsRule:
    origins: tuple[str, ...]
    methods: tuple[str, ...]
    headers: tuple[str, ...]
    expose: tuple[str, ...] = ()
    max_age: int = 0


def cors_rule(origins: Iterable[str]) -> CorsRule:
    """PUT, GET and HEAD from ``origins``, headers ``*``, ``ETag`` exposed, max-age 3000 (sorted, so rules compare)."""
    return CorsRule(tuple(sorted(set(origins))), tuple(sorted(CORS_METHODS)), tuple(sorted(CORS_HEADERS)),
                    tuple(sorted(CORS_EXPOSE)), CORS_MAX_AGE)


def wanted_cors(hostnames: Iterable[str]) -> list[CorsRule]:
    """The bucket's rules for the hostnames of ``data.managed.objects.cors``'s services: one rule
    with their ``https://`` origins, or none when no service is named (S3 refuses a rule without an origin)."""
    origins = sorted({f"https://{h.strip().lower().rstrip('.')}" for h in hostnames if h and h.strip()})
    return [cors_rule(origins)] if origins else []


def _cors_xml(rules: list[CorsRule]) -> bytes:
    parts = [f'<CORSConfiguration xmlns="{XMLNS}">']
    for r in rules:
        parts.append("<CORSRule>")
        parts += [f"<AllowedOrigin>{escape(v)}</AllowedOrigin>" for v in r.origins]
        parts += [f"<AllowedMethod>{escape(v)}</AllowedMethod>" for v in r.methods]
        parts += [f"<AllowedHeader>{escape(v)}</AllowedHeader>" for v in r.headers]
        parts += [f"<ExposeHeader>{escape(v)}</ExposeHeader>" for v in r.expose]
        parts.append(f"<MaxAgeSeconds>{int(r.max_age)}</MaxAgeSeconds></CORSRule>")
    parts.append("</CORSConfiguration>")
    return "".join(parts).encode()


def _same_rules(a: list[CorsRule], b: list[CorsRule]) -> bool:
    return sorted(a) == sorted(b)


# ---------------------------------------------------------------------------------------- client


class SpacesClient:
    """S3 calls in one region, signed with one key. Use as ``async with SpacesClient(region, key) as s3``."""

    def __init__(self, region: str, key: SpacesKey, *, transport: Transport = None) -> None:
        _check_region(region)
        self.region = region
        self._key = key
        self._client = httpx.AsyncClient(
            timeout=TIMEOUT, headers={"User-Agent": "Slipway"},
            transport=transport if transport is not None else transport_factory(),
        )

    def __repr__(self) -> str:  # SpacesKey already hides the secret; say so plainly anyway
        return f"SpacesClient(region={self.region!r}, access_key={self._key.access_key!r}, secret_key=<hidden>)"

    async def __aenter__(self) -> SpacesClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- one request

    async def _send(self, method: str, bucket: str, *, path: str = "/", query: dict[str, str] | None = None,
                    body: bytes = b"", headers: dict[str, str] | None = None,
                    raise_on_403: bool = True) -> httpx.Response:
        host = bucket_host(bucket, self.region)
        query = query or {}
        url = f"https://{host}{s3sig.canonical_path(path)}"
        if query:
            url += "?" + s3sig.canonical_query(query)
        payload = hashlib.sha256(body).hexdigest()
        retries = 1 if method in ("GET", "HEAD") else 0
        while True:
            # Signed afresh for each attempt, so a retry after a wait carries a current date.
            signed = s3sig.sign(method=method, host=host, path=path, query=query, headers=headers or {},
                                payload_sha256=payload, access_key=self._key.access_key,
                                secret_key=self._key.secret_key, region=self.region, now=clock())
            try:
                resp = await self._client.request(method, url, content=body, headers=signed)
            except httpx.HTTPError:
                # Never the exception's own text: it can carry the request, though not the secret.
                raise SpacesError("Couldn't reach DigitalOcean Spaces") from None
            if resp.status_code in RETRIED_STATUSES and retries:
                retries -= 1
                await sleep(GET_RETRY_WAIT)
                continue
            break
        if resp.status_code == 403 and raise_on_403:
            code = _code(resp)
            raise SpacesDenied(f"Spaces refused the key {self._key.access_key} for the bucket {bucket} "
                               f"({code or 'HTTP 403'})", 403, code)
        return resp

    # -- buckets

    async def create_bucket(self, bucket: str) -> bool:
        """True: made now. False: it was already this account's.

        Spaces may answer a re-create of our own bucket with ``BucketAlreadyExists`` rather than
        ``BucketAlreadyOwnedByYou``, so any other 409 is checked with a HEAD under the same key:
        200 means ours; 403 means another account has the name (``BucketTaken``); 404 means no bucket
        answers to it yet (one may have just been deleted), which also stops, without guessing.
        """
        resp = await self._send("PUT", bucket)
        if resp.status_code == 200:
            return True
        if resp.status_code == 409 and _code(resp) == "BucketAlreadyOwnedByYou":
            return False
        if resp.status_code == 409:
            probe = await self._send("HEAD", bucket, raise_on_403=False)
            if probe.status_code == 200:
                return False
            if probe.status_code == 403:
                raise BucketTaken(f"Another Spaces account already has the bucket {bucket} (bucket names are "
                                  "shared by every DigitalOcean account)", 409, _code(resp))
            if probe.status_code == 404:
                raise SpacesError(f"Spaces says the bucket name {bucket} is taken, but no bucket of that name "
                                  "answers; if it was just deleted, retry in a few minutes", 409, _code(resp))
            raise _refused(probe, f"show the bucket {bucket}")
        raise _refused(resp, f"make the bucket {bucket}")

    async def bucket_exists(self, bucket: str) -> bool:
        """True on 200, False on 404 only (J13); a 403 raises ``SpacesDenied``, anything else ``SpacesError``."""
        resp = await self._send("HEAD", bucket)
        if resp.status_code == 200:
            return True
        if resp.status_code == 404:
            return False
        raise _refused(resp, f"show the bucket {bucket}")

    async def delete_bucket(self, bucket: str) -> bool:
        """True when deleted, False when it was already gone. The bucket must be empty (``empty_bucket``)."""
        resp = await self._send("DELETE", bucket)
        if resp.status_code in (200, 204):
            return True
        if resp.status_code == 404:
            return False
        if resp.status_code == 409 and _code(resp) == "BucketNotEmpty":
            raise SpacesError(f"Spaces won't delete the bucket {bucket}: it still holds objects (if someone "
                              "turned versioning on, old versions remain; remove them by hand)", 409, "BucketNotEmpty")
        raise _refused(resp, f"delete the bucket {bucket}")

    async def empty_bucket(self, bucket: str) -> int:
        """Delete every object, a listing page (up to 1,000) at a time, listing again from the start
        after each delete, then abort every unfinished multipart upload. Returns the objects deleted
        (0 when the bucket doesn't exist). Old versions aren't touched (see the module docstring)."""
        deleted = await self._delete_objects(bucket)
        if deleted is None:
            return 0
        await self._abort_uploads(bucket)
        return deleted

    async def _delete_objects(self, bucket: str) -> int | None:
        """None: the bucket is gone. Counts only the keys Spaces reports as ``<Deleted>``; any per-key ``<Error>`` raises."""
        deleted = 0
        for _ in range(MAX_PAGES):
            resp = await self._send("GET", bucket, query={"list-type": "2"})
            if resp.status_code == 404:
                return None if deleted == 0 else deleted
            if resp.status_code != 200:
                raise _refused(resp, f"list the bucket {bucket}")
            keys = [_child_text(c, "Key") for c in _elements(_parse(resp, "a listing"), "Contents")]
            if not keys:
                return deleted
            doc = ("<Delete><Quiet>false</Quiet>"
                   + "".join(f"<Object><Key>{escape(k)}</Key></Object>" for k in keys)
                   + "</Delete>").encode()
            resp = await self._send("POST", bucket, query={"delete": ""}, body=doc,
                                    headers={"Content-MD5": _md5(doc), "Content-Type": "application/xml"})
            if resp.status_code != 200:
                raise _refused(resp, f"delete objects in the bucket {bucket}")
            result = _parse(resp, "a delete result")
            errors = _elements(result, "Error")
            if errors:
                codes = (_child_text(e, "Code") for e in errors)
                code = next((c for c in codes if _PLAIN_CODE_RE.fullmatch(c)), None)
                noun = "object" if len(errors) == 1 else "objects"
                raise SpacesError(f"Spaces couldn't delete {len(errors)} {noun} in the bucket {bucket} "
                                  f"({code or 'no reason given'})", 200, code)
            done = len(_elements(result, "Deleted"))
            if done == 0:
                # Listing again would list the same keys for ever.
                raise SpacesError(f"Spaces deleted nothing from the bucket {bucket}, so Slipway stopped", 200)
            deleted += done
        raise SpacesError(f"The bucket {bucket} has more objects than Slipway deletes in one step; retry to go on")

    async def _abort_uploads(self, bucket: str) -> None:
        for _ in range(MAX_PAGES):
            resp = await self._send("GET", bucket, query={"uploads": ""})
            if resp.status_code == 404:
                return
            if resp.status_code != 200:
                raise _refused(resp, f"list the unfinished uploads in the bucket {bucket}")
            uploads = [(_child_text(u, "Key"), _child_text(u, "UploadId"))
                       for u in _elements(_parse(resp, "an upload listing"), "Upload")]
            if not uploads:
                return
            for name, upload_id in uploads:
                if not name or not upload_id:
                    raise SpacesError("Spaces sent an upload listing Slipway didn't understand", 200)
                if any(part in (".", "..") for part in name.split("/")):
                    # httpx folds "." and ".." path parts away, so the request would name another key.
                    raise SpacesError(f"The bucket {bucket} has an unfinished upload named {_safe(name)!r}, which "
                                      "Slipway can't address; abort it by hand, then retry")
                resp = await self._send("DELETE", bucket, path="/" + name, query={"uploadId": upload_id})
                if resp.status_code not in (200, 204, 404):
                    raise _refused(resp, f"abort an unfinished upload in the bucket {bucket}")
        raise SpacesError(f"The bucket {bucket} has more unfinished uploads than Slipway aborts in one step; "
                          "retry to go on")

    # -- CORS

    async def bucket_cors(self, bucket: str) -> list[CorsRule]:
        """The bucket's CORS rules ([] when it has none). A missing bucket raises."""
        resp = await self._send("GET", bucket, query={"cors": ""})
        if resp.status_code == 404 and _code(resp) == "NoSuchCORSConfiguration":
            return []
        if resp.status_code != 200:
            raise _refused(resp, f"show the CORS rules of the bucket {bucket}")
        rules = []
        for el in _elements(_parse(resp, "a CORS configuration"), "CORSRule"):
            def texts(name: str, el: ET.Element = el) -> tuple[str, ...]:
                return tuple(sorted((e.text or "").strip() for e in _elements(el, name)))
            age = _child_text(el, "MaxAgeSeconds").strip()
            rules.append(CorsRule(texts("AllowedOrigin"), texts("AllowedMethod"), texts("AllowedHeader"),
                                  texts("ExposeHeader"), int(age) if age.isdigit() else 0))
        return rules

    async def put_bucket_cors(self, bucket: str, rules: list[CorsRule]) -> None:
        """Replace the bucket's CORS rules (at least one; ``delete_bucket_cors`` clears them)."""
        if not rules:
            raise ValueError("put_bucket_cors needs at least one rule; use delete_bucket_cors")
        doc = _cors_xml(rules)
        resp = await self._send("PUT", bucket, query={"cors": ""}, body=doc,
                                headers={"Content-MD5": _md5(doc), "Content-Type": "application/xml"})
        if resp.status_code not in (200, 204):
            raise _refused(resp, f"set the CORS rules of the bucket {bucket}")

    async def delete_bucket_cors(self, bucket: str) -> None:
        resp = await self._send("DELETE", bucket, query={"cors": ""})
        if resp.status_code not in (200, 204):
            raise _refused(resp, f"clear the CORS rules of the bucket {bucket}")

    async def ensure_cors(self, bucket: str, wanted: list[CorsRule]) -> bool:
        """Read the rules and write ``wanted`` only when they differ (order doesn't count). True when
        written. A 403 on either call is ``SpacesDenied``, so the caller can try its full-access key."""
        current = await self.bucket_cors(bucket)
        if _same_rules(current, wanted):
            return False
        if wanted:
            await self.put_bucket_cors(bucket, wanted)
        else:
            await self.delete_bucket_cors(bucket)
        return True
