"""A stand-in for the DigitalOcean Spaces S3 calls ``slipway/services/spaces.py`` makes (Sirdar's
``fake_spaces.py``, ported).

Virtual-hosted only (``<bucket>.<region>.digitaloceanspaces.com``; a path-style request answers 400):
create, HEAD, list (v2, paged), multi-object delete, list and abort multipart uploads, delete, and
the bucket's CORS rules (GET, PUT, DELETE ``?cors``).

Every request must carry a SigV4 ``Authorization`` whose access key is a key the fake knows. The fake
re-computes the signature from the request **as received**, with its own canonicalisation (not
``s3sig``'s), and the key's grants must cover the bucket (``fullaccess`` covers every bucket).

Keys come from ``keys``: a mapping ``access_key -> {"secret_key", "grants": [{"bucket", "permission"}]}``
such as ``FakeDigitalOcean().spaces_keys`` (so a key the DigitalOcean fake made, or deleted, is what
Spaces accepts), or a callable that looks one up, or None for the fake's own store, filled with ``add_key``.

Knobs: ``foreign`` (bucket names another account owns: PUT answers 409 ``BucketAlreadyExists``,
anything else 403), ``recreate_conflict`` (re-creating your own bucket answers ``BucketAlreadyExists``,
as Spaces may, instead of ``BucketAlreadyOwnedByYou``), ``undeletable`` (keys a multi-delete reports as
a per-key ``AccessDenied`` inside a 200), ``cors_needs_fullaccess`` (a bucket-scoped key gets
``AccessDenied`` on ``?cors``), ``fail_next`` (a queue of ``(status, code)`` answers for the next
signed requests), ``page_size`` and ``down``. ``cors`` holds each bucket's rules as dicts;
``requests`` every request seen.

Use it with::

    fake = FakeSpaces()
    monkeypatch.setattr(spaces, "transport_factory", fake.transport)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import itertools
import re
import secrets
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import quote, unquote
from xml.sax.saxutils import escape

import httpx

NS = "http://s3.amazonaws.com/doc/2006-03-01/"
_AUTH_RE = re.compile(r"^AWS4-HMAC-SHA256 Credential=([^/,]+)/(\d{8})/([a-z0-9-]+)/s3/aws4_request, "
                      r"SignedHeaders=([a-z0-9;-]+), Signature=([0-9a-f]{64})$")
_HOST_RE = re.compile(r"^([a-z0-9][a-z0-9-]{1,61}[a-z0-9])\.([a-z0-9-]+)\.digitaloceanspaces\.com$")

KeyLookup = Mapping[str, Mapping[str, Any]] | Callable[[str], Mapping[str, Any] | None]


def xml_error(status: int, code: str) -> httpx.Response:
    return httpx.Response(status, content=f"<Error><Code>{code}</Code><Message>Spaces says no</Message></Error>".encode(),
                          headers={"content-type": "application/xml"})


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _canonical_query(raw: bytes) -> str:
    """Decode the query as sent, then re-encode each part (RFC 3986), sorted."""
    pairs = []
    for part in raw.decode().split("&") if raw else []:
        name, _, value = part.partition("=")
        pairs.append((quote(unquote(name), safe="-_.~"), quote(unquote(value), safe="-_.~")))
    return "&".join(f"{n}={v}" for n, v in sorted(pairs))


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


class FakeSpaces:
    def __init__(self, keys: KeyLookup | None = None) -> None:
        self._own_keys: dict[str, dict[str, Any]] = {}
        self._keys: KeyLookup = self._own_keys if keys is None else keys
        self.buckets: dict[str, dict[str, bytes]] = {}
        self.uploads: dict[str, dict[str, str]] = {}  # bucket -> {upload id: object key}
        self.cors: dict[str, list[dict[str, Any]]] = {}
        self.requests: list[httpx.Request] = []
        self.page_size = 1000
        self.down = False
        self.foreign: set[str] = set()
        self.recreate_conflict = False
        self.undeletable: set[str] = set()
        self.cors_needs_fullaccess = False
        self.fail_next: list[tuple[int, str]] = []
        self._ids = itertools.count(1)

    # -- set-up helpers

    def add_key(self, name: str, grants: list[dict[str, str]]) -> dict[str, Any]:
        """A key in the fake's own store; returns ``{name, access_key, secret_key, grants}``."""
        access = "DO00" + secrets.token_hex(8).upper()
        key = {"name": name, "access_key": access, "secret_key": secrets.token_urlsafe(32), "grants": grants}
        self._own_keys[access] = key
        return key

    def key(self, access_key: str) -> Mapping[str, Any] | None:
        if callable(self._keys):
            return self._keys(access_key)
        return self._keys.get(access_key)

    def put(self, bucket: str, key: str, data: bytes) -> None:
        self.buckets.setdefault(bucket, {})[key] = data

    def start_upload(self, bucket: str, key: str) -> str:
        upload_id = f"2~upload-{next(self._ids):04d}"
        self.uploads.setdefault(bucket, {})[upload_id] = key
        return upload_id

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def writes(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.method not in ("GET", "HEAD")]

    # -- checks

    def _signature_ok(self, request: httpx.Request, region: str, auth: re.Match[str]) -> bool:
        access_key, date, scope_region, signed, signature = auth.groups()
        key = self.key(access_key)
        amz_date = request.headers.get("x-amz-date", "")
        sent_hash = request.headers.get("x-amz-content-sha256", "")
        if (key is None or scope_region != region or not re.fullmatch(r"\d{8}T\d{6}Z", amz_date)
                or not amz_date.startswith(date) or sent_hash != hashlib.sha256(request.content).hexdigest()):
            return False
        names = signed.split(";")
        if not {"host", "x-amz-date", "x-amz-content-sha256"} <= set(names) or names != sorted(names):
            return False
        if "content-md5" in request.headers and "content-md5" not in names:
            return False
        if any(n not in request.headers for n in names):
            return False
        raw_path, _, raw_query = request.url.raw_path.partition(b"?")
        block = "".join(f"{n}:{' '.join(request.headers[n].split())}\n" for n in names)
        canonical = "\n".join([request.method, raw_path.decode(), _canonical_query(raw_query), block, signed, sent_hash])
        scope = f"{date}/{region}/s3/aws4_request"
        to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
        k = _hmac(("AWS4" + key["secret_key"]).encode(), date)
        for part in (region, "s3", "aws4_request"):
            k = _hmac(k, part)
        expected = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    def _grants(self, access_key: str) -> list[Mapping[str, Any]]:
        return list((self.key(access_key) or {}).get("grants") or [])

    def _allowed(self, access_key: str, bucket: str, method: str = "GET") -> bool:
        """``fullaccess`` covers every bucket; ``readwrite`` its bucket; ``read`` its bucket for GET and HEAD only."""
        for g in self._grants(access_key):
            if g.get("permission") == "fullaccess":
                return True
            if g.get("bucket") == bucket and (g.get("permission") == "readwrite" or method in ("GET", "HEAD")):
                return True
        return False

    def _full(self, access_key: str) -> bool:
        return any(g.get("permission") == "fullaccess" for g in self._grants(access_key))

    @staticmethod
    def _md5_ok(request: httpx.Request) -> bool:
        md5 = base64.b64encode(hashlib.md5(request.content).digest()).decode()
        return request.headers.get("content-md5") == md5

    # -- the handler

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.down:
            raise httpx.ConnectError("unreachable", request=request)
        host = _HOST_RE.match(request.url.host)
        if host is None:
            return xml_error(400, "InvalidRequest")  # path-style or not Spaces
        bucket, region = host.groups()
        auth = _AUTH_RE.match(request.headers.get("authorization", ""))
        if auth is None or self.key(auth.group(1)) is None:
            return xml_error(403, "InvalidAccessKeyId")
        if not self._signature_ok(request, region, auth):
            return xml_error(403, "SignatureDoesNotMatch")
        if self.fail_next:
            status, code = self.fail_next.pop(0)
            return xml_error(status, code)
        access = auth.group(1)
        method, path, params = request.method, request.url.path, request.url.params
        if path == "/" and "cors" in params:
            return self._cors(request, bucket, access)
        if path == "/" and method == "PUT":
            if bucket in self.foreign:
                return xml_error(409, "BucketAlreadyExists")
            if not self._allowed(access, bucket, method):
                return xml_error(403, "AccessDenied")
            if bucket in self.buckets:
                return xml_error(409, "BucketAlreadyExists" if self.recreate_conflict else "BucketAlreadyOwnedByYou")
            self.buckets[bucket] = {}
            return httpx.Response(200)
        if bucket in self.foreign or not self._allowed(access, bucket, method):
            return xml_error(403, "AccessDenied")
        if bucket not in self.buckets:
            return xml_error(404, "NoSuchBucket")
        objects = self.buckets[bucket]
        uploads = self.uploads.setdefault(bucket, {})
        if path == "/" and method == "HEAD":
            return httpx.Response(200)
        if path == "/" and method == "GET" and params.get("list-type") == "2":
            keys = sorted(objects)
            start = int(params.get("continuation-token") or 0)
            page = keys[start:start + self.page_size]
            more = start + self.page_size < len(keys)
            body = [f'<ListBucketResult xmlns="{NS}"><Name>{bucket}</Name><IsTruncated>{str(more).lower()}</IsTruncated>']
            body += [f"<Contents><Key>{escape(k)}</Key><Size>{len(objects[k])}</Size></Contents>" for k in page]
            if more:
                body.append(f"<NextContinuationToken>{start + self.page_size}</NextContinuationToken>")
            body.append("</ListBucketResult>")
            return httpx.Response(200, content="".join(body).encode())
        if path == "/" and method == "GET" and "uploads" in params:
            page = sorted(uploads.items())[:self.page_size]
            more = len(uploads) > self.page_size
            body = [f'<ListMultipartUploadsResult xmlns="{NS}"><IsTruncated>{str(more).lower()}</IsTruncated>']
            body += [f"<Upload><Key>{escape(k)}</Key><UploadId>{u}</UploadId></Upload>" for u, k in page]
            body.append("</ListMultipartUploadsResult>")
            return httpx.Response(200, content="".join(body).encode())
        if path == "/" and method == "POST" and "delete" in params:
            if not self._md5_ok(request):
                return xml_error(400, "InvalidDigest")
            root = ET.fromstring(request.content)
            quiet = any(_local(e.tag) == "Quiet" and (e.text or "").strip() == "true" for e in root)
            body = [f'<DeleteResult xmlns="{NS}">']
            for el in root.iter():
                if _local(el.tag) != "Key":
                    continue
                name = el.text or ""
                if name in self.undeletable:
                    body.append(f"<Error><Key>{escape(name)}</Key><Code>AccessDenied</Code>"
                                "<Message>Access Denied</Message></Error>")
                    continue
                objects.pop(name, None)
                if not quiet:
                    body.append(f"<Deleted><Key>{escape(name)}</Key></Deleted>")
            body.append("</DeleteResult>")
            return httpx.Response(200, content="".join(body).encode())
        if path != "/" and method == "DELETE" and "uploadId" in params:
            if uploads.get(params["uploadId"]) != path[1:]:
                return xml_error(404, "NoSuchUpload")
            del uploads[params["uploadId"]]
            return httpx.Response(204)
        if path == "/" and method == "DELETE":
            if objects or uploads:
                return xml_error(409, "BucketNotEmpty")
            del self.buckets[bucket]
            self.uploads.pop(bucket, None)
            self.cors.pop(bucket, None)
            return httpx.Response(204)
        return xml_error(405, "MethodNotAllowed")

    def _cors(self, request: httpx.Request, bucket: str, access: str) -> httpx.Response:
        if bucket in self.foreign or not self._allowed(access, bucket, request.method):
            return xml_error(403, "AccessDenied")
        if bucket not in self.buckets:
            return xml_error(404, "NoSuchBucket")
        if self.cors_needs_fullaccess and not self._full(access):
            return xml_error(403, "AccessDenied")
        if request.method == "GET":
            if not self.cors.get(bucket):
                return xml_error(404, "NoSuchCORSConfiguration")
            body = [f'<CORSConfiguration xmlns="{NS}">']
            for r in self.cors[bucket]:
                body.append("<CORSRule>")
                for tag, k in (("AllowedOrigin", "origins"), ("AllowedMethod", "methods"),
                               ("AllowedHeader", "headers"), ("ExposeHeader", "expose")):
                    body += [f"<{tag}>{escape(v)}</{tag}>" for v in r[k]]
                body.append(f"<MaxAgeSeconds>{r['max_age']}</MaxAgeSeconds></CORSRule>")
            body.append("</CORSConfiguration>")
            return httpx.Response(200, content="".join(body).encode())
        if request.method == "PUT":
            if not self._md5_ok(request):
                return xml_error(400, "InvalidDigest")
            root = ET.fromstring(request.content)

            def texts(el: ET.Element, tag: str) -> list[str]:
                return [(e.text or "").strip() for e in el if _local(e.tag) == tag]

            rules = []
            for el in root:
                if _local(el.tag) != "CORSRule":
                    continue
                if not texts(el, "AllowedOrigin") or not texts(el, "AllowedMethod"):
                    return xml_error(400, "MalformedXML")  # S3 needs an origin and a method in each rule
                age = texts(el, "MaxAgeSeconds")
                rules.append({"origins": texts(el, "AllowedOrigin"), "methods": texts(el, "AllowedMethod"),
                              "headers": texts(el, "AllowedHeader"), "expose": texts(el, "ExposeHeader"),
                              "max_age": int(age[0]) if age else 0})
            if not rules:
                return xml_error(400, "MalformedXML")
            self.cors[bucket] = rules
            return httpx.Response(200)
        if request.method == "DELETE":
            self.cors.pop(bucket, None)
            return httpx.Response(204)
        return xml_error(405, "MethodNotAllowed")
