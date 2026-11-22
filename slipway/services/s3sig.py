"""AWS Signature Version 4 for the few S3 calls Slipway makes to DigitalOcean Spaces.

Spaces speaks the S3 API, and the DigitalOcean API can't make or empty buckets, so Slipway signs
those requests itself (Sirdar's ``s3sig.py``, ported). There is no boto3: it would bypass the httpx
transports the tests replace.

Pure functions. The secret key only feeds the HMAC chain; it is never returned, put in a header or
put in an error. The signer follows the S3 flavour of SigV4: the path is URI-encoded once and never
normalised, the payload hash is sent as ``x-amz-content-sha256`` and signed, and the query is sorted
and RFC 3986-encoded. ``tests/test_spaces.py`` checks it against AWS's published S3 examples.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from datetime import UTC, datetime
from urllib.parse import quote

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
ALGORITHM = "AWS4-HMAC-SHA256"


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def signing_key(secret_key: str, date: str, region: str, service: str) -> bytes:
    """The derived key for one day, region and service (``date`` is ``YYYYMMDD``)."""
    k = _hmac(("AWS4" + secret_key).encode(), date)
    k = _hmac(k, region)
    k = _hmac(k, service)
    return _hmac(k, "aws4_request")


def _encode(value: str) -> str:
    # RFC 3986 unreserved characters stay; everything else, "/" included, is percent-encoded.
    return quote(value, safe="-_.~")


def canonical_path(path: str) -> str:
    """The URI-encoded path, as both the canonical request and the URL use it ("/" kept)."""
    return quote(path, safe="/-_.~")


def canonical_query(query: Mapping[str, str]) -> str:
    """``k=v`` pairs sorted by encoded name; a sub-resource such as ``?cors`` is ``cors=``."""
    pairs = sorted((_encode(k), _encode(v)) for k, v in query.items())
    return "&".join(f"{k}={v}" for k, v in pairs)


def canonical_request(*, method: str, host: str, path: str, query: Mapping[str, str],
                      headers: Mapping[str, str], payload_sha256: str, amz_date: str) -> tuple[str, str]:
    """``(canonical request, signed header names)``. Header values are trimmed and inner runs of
    spaces folded, as SigV4 asks; ``host``, ``x-amz-date`` and ``x-amz-content-sha256`` are always signed."""
    canon = {k.lower(): " ".join(str(v).split()) for k, v in headers.items()}
    canon |= {"host": host, "x-amz-date": amz_date, "x-amz-content-sha256": payload_sha256}
    names = sorted(canon)
    signed = ";".join(names)
    request = "\n".join([
        method.upper(), canonical_path(path), canonical_query(query),
        "".join(f"{n}:{canon[n]}\n" for n in names), signed, payload_sha256,
    ])
    return request, signed


def sign(*, method: str, host: str, path: str, query: Mapping[str, str], headers: Mapping[str, str],
         payload_sha256: str, access_key: str, secret_key: str, region: str, now: datetime,
         service: str = "s3") -> dict[str, str]:
    """``headers`` plus ``x-amz-date``, ``x-amz-content-sha256`` and ``Authorization``.

    ``now`` must be timezone-aware; it is converted to UTC. ``host`` is not added to the returned
    headers: httpx sets it from the URL, which is the same value.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    now = now.astimezone(UTC)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    request, signed = canonical_request(method=method, host=host, path=path, query=query, headers=headers,
                                        payload_sha256=payload_sha256, amz_date=amz_date)
    scope = f"{date}/{region}/{service}/aws4_request"
    to_sign = "\n".join([ALGORITHM, amz_date, scope, hashlib.sha256(request.encode()).hexdigest()])
    signature = hmac.new(signing_key(secret_key, date, region, service), to_sign.encode(),
                         hashlib.sha256).hexdigest()
    return {
        **headers,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_sha256,
        "Authorization": f"{ALGORITHM} Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={signature}",
    }
