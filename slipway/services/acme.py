"""A small ACME (RFC 8555) client: enough of Let's Encrypt for DNS-01 orders from the Slipway server.

Slipway is the only issuer of a DigitalOcean environment's certificate (phase 4 D2, D12). This module
holds the protocol and the key handling; ``certs.issue`` drives an order with it and owns the DNS
records and the account key store.

* The account key is ES256 (P-256), one per ACME directory, kept by the caller (``certs.AccountKeys``).
  Requests are signed as RFC 8555 §6.2 asks: a ``jwk`` header for ``newAccount``, the account's
  ``kid`` URL for everything after.
* Every POST takes a fresh nonce; a ``badNonce`` answer is retried once with the nonce it carries.
* The certificate key is RSA 2048, made in memory for each order and returned to the caller as PEM.
  Nothing here writes a file or logs a key: errors carry the ACME problem's type and some of its
  ``detail`` text, never a request body.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
from collections.abc import Awaitable, Callable, Iterable
from datetime import UTC, datetime
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

TIMEOUT = 30
POLL_SECONDS = 3  # between two reads of an authorization or an order (SD/acme.py:32-33)
POLL_TRIES = 100
DETAIL_CHARS = 200  # how much of the ACME server's own problem text goes into ours
PROBLEM = "urn:ietf:params:acme:error:"
PEM_CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----\s.+?-----END CERTIFICATE-----", re.S)

Transport = httpx.AsyncBaseTransport | None
# Tests swap this for an httpx.MockTransport.
transport_factory: Callable[[], Transport] = lambda: None  # noqa: E731
# Tests swap this so polls don't wait.
sleep: Callable[[float], Awaitable[None]] = asyncio.sleep


class AcmeError(RuntimeError):
    """An ACME call failed. ``str()`` is Slipway's text with the problem's type and some of its detail."""

    def __init__(self, message: str, *, problem: str | None = None, status_code: int | None = None) -> None:
        super().__init__(message)
        self.problem = problem  # the short type, e.g. "rateLimited", or None
        self.status_code = status_code


class RateLimited(AcmeError):
    """The ACME server refused because of a rate limit (Let's Encrypt: 5 certificates per name set a week)."""


# ------------------------------------------------------------------------ keys and encoding


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_account_key() -> str:
    """A new ES256 account key, as unencrypted PKCS#8 PEM."""
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode("ascii")


def load_account_key(pem: str) -> ec.EllipticCurvePrivateKey:
    try:
        key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    except (ValueError, TypeError):
        raise AcmeError("The stored ACME account key can't be read") from None
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise AcmeError("The stored ACME account key isn't a P-256 key")
    return key


def jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    numbers = key.public_key().public_numbers()
    return {"crv": "P-256", "kty": "EC",
            "x": b64url(numbers.x.to_bytes(32, "big")), "y": b64url(numbers.y.to_bytes(32, "big"))}


def thumbprint(key: ec.EllipticCurvePrivateKey) -> str:
    """RFC 7638: SHA-256 of the JWK's required members in lexicographic order, no whitespace."""
    canonical = json.dumps(jwk(key), sort_keys=True, separators=(",", ":")).encode("ascii")
    return b64url(hashlib.sha256(canonical).digest())


def dns01_value(token: str, key: ec.EllipticCurvePrivateKey) -> str:
    """The TXT value for a DNS-01 challenge (RFC 8555 §8.4)."""
    authorization = f"{token}.{thumbprint(key)}".encode("ascii")
    return b64url(hashlib.sha256(authorization).digest())


def sign(key: ec.EllipticCurvePrivateKey, protected: dict[str, Any], payload: Any) -> dict[str, str]:
    """A flattened JWS. ``payload`` None is a POST-as-GET (an empty payload, RFC 8555 §6.3)."""
    protected_b64 = b64url(json.dumps(protected, separators=(",", ":")).encode("utf-8"))
    payload_b64 = "" if payload is None else b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    der = key.sign(f"{protected_b64}.{payload_b64}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return {"protected": protected_b64, "payload": payload_b64, "signature": b64url(signature)}


def new_certificate_key() -> str:
    """A fresh RSA 2048 key for one certificate, as unencrypted PKCS#8 PEM."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode("ascii")


def make_csr(names: Iterable[str], key_pem: str) -> bytes:
    """A DER CSR for ``names`` (all as SANs; the first is also the common name)."""
    names = list(names)
    key = serialization.load_pem_private_key(key_pem.encode("ascii"), password=None)
    builder = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False))
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def split_chain(pem: str) -> tuple[str, str]:
    """(leaf, the rest of the chain) from a PEM bundle, leaf first as ACME sends it."""
    blocks = [m.group(0).strip() + "\n" for m in PEM_CERT_RE.finditer(pem or "")]
    if not blocks:
        raise AcmeError("The ACME server sent no certificate")
    return blocks[0], "".join(blocks[1:])


def load_certificate(pem: str) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(pem.encode("ascii"))
    except ValueError:
        raise AcmeError("The certificate can't be read") from None


def certificate_names(pem: str) -> list[str]:
    """The DNS names a PEM certificate covers (its SANs), sorted and lower case."""
    cert = load_certificate(pem)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return sorted({n.lower() for n in san.get_values_for_type(x509.DNSName)})


def certificate_not_after(pem: str) -> datetime:
    return load_certificate(pem).not_valid_after_utc.astimezone(UTC)


# ------------------------------------------------------------------------ the client


def _short(problem_type: str | None) -> str | None:
    if not problem_type:
        return None
    return problem_type.removeprefix(PROBLEM)


class AcmeClient:
    """One ACME session against ``directory_url`` with one account key.

    ``kid`` is the account URL when it is already known; ``register`` finds or makes the account
    otherwise (``newAccount`` with a known key returns the existing account, RFC 8555 §7.3.1).
    """

    def __init__(self, directory_url: str, account_key_pem: str, *, kid: str | None = None,
                 transport: Transport = None) -> None:
        self.directory_url = directory_url
        self._key = load_account_key(account_key_pem)
        self.kid = kid
        self._nonce: str | None = None
        self._directory: dict[str, Any] | None = None
        self._client = httpx.AsyncClient(
            timeout=TIMEOUT, headers={"User-Agent": "Slipway"},
            transport=transport if transport is not None else transport_factory(),
        )

    def __repr__(self) -> str:  # never shows the key
        return f"AcmeClient({self.directory_url!r}, kid={self.kid!r})"

    async def __aenter__(self) -> AcmeClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    # -- plumbing

    async def _request(self, method: str, url: str, **kw: Any) -> httpx.Response:
        try:
            resp = await self._client.request(method, url, **kw)
        except httpx.HTTPError as exc:
            raise AcmeError(f"Could not reach the ACME server at {httpx.URL(url).host} ({type(exc).__name__})") from None
        nonce = resp.headers.get("Replay-Nonce")
        if nonce:
            self._nonce = nonce
        return resp

    async def directory(self) -> dict[str, Any]:
        if self._directory is None:
            resp = await self._request("GET", self.directory_url)
            if resp.status_code >= 400:
                raise self._error("GET", "directory", resp)
            data = self._json(resp)
            if not all(isinstance(data.get(k), str) for k in ("newNonce", "newAccount", "newOrder")):
                raise AcmeError(f"{self.directory_url} isn't an ACME directory")
            self._directory = data
        return self._directory

    async def _fresh_nonce(self) -> str:
        if self._nonce:
            nonce, self._nonce = self._nonce, None
            return nonce
        resp = await self._request("HEAD", (await self.directory())["newNonce"])
        if not self._nonce:
            raise AcmeError(f"The ACME server gave no nonce (HTTP {resp.status_code})")
        nonce, self._nonce = self._nonce, None
        return nonce

    async def _post(self, url: str, payload: Any, *, what: str, use_jwk: bool = False,
                    accept: str | None = None) -> httpx.Response:
        if not use_jwk and not self.kid:
            raise AcmeError("Slipway has no ACME account yet")
        for attempt in (1, 2):
            protected: dict[str, Any] = {"alg": "ES256", "nonce": await self._fresh_nonce(), "url": url}
            if use_jwk:
                protected["jwk"] = jwk(self._key)
            else:
                protected["kid"] = self.kid
            headers = {"Content-Type": "application/jose+json"}
            if accept:
                headers["Accept"] = accept
            resp = await self._request("POST", url, content=json.dumps(sign(self._key, protected, payload)),
                                       headers=headers)
            if resp.status_code < 400:
                return resp
            error = self._error("POST", what, resp)
            if error.problem == "badNonce" and attempt == 1:
                continue  # RFC 8555 §6.5: retry with the nonce the error carried
            raise error
        raise AssertionError("unreachable")

    @staticmethod
    def _json(resp: httpx.Response) -> dict[str, Any]:
        try:
            data = resp.json()
        except ValueError:
            data = None
        if not isinstance(data, dict):
            raise AcmeError(f"The ACME server's answer was not what Slipway expected (HTTP {resp.status_code})")
        return data

    def _error(self, method: str, what: str, resp: httpx.Response) -> AcmeError:
        try:
            data = resp.json()
        except ValueError:
            data = None
        problem = _short(data.get("type")) if isinstance(data, dict) else None
        detail = " ".join(str(data.get("detail") or "").split())[:DETAIL_CHARS] if isinstance(data, dict) else ""
        status = resp.status_code
        if problem == "rateLimited" or status == 429:
            ours = "The ACME server is limiting certificates for these names; try again later"
            cls: type[AcmeError] = RateLimited
        elif problem in ("unauthorized", "accountDoesNotExist") or status in (401, 403):
            ours = "The ACME server refused the request"
            cls = AcmeError
        elif status >= 500:
            ours = "The ACME server had a problem"
            cls = AcmeError
        else:
            ours = "The ACME server rejected the request"
            cls = AcmeError
        text = f"{ours} ({method} {what}, HTTP {status}" + (f", {problem}" if problem else "") + ")"
        if detail:
            text += f": {detail}"
        return cls(text, problem=problem, status_code=status)

    # -- the calls

    def dns01_value(self, token: str) -> str:
        return dns01_value(token, self._key)

    async def register(self, contact: Iterable[str] = ()) -> str:
        """The account URL (``kid``) for this key, made when it doesn't exist yet."""
        payload: dict[str, Any] = {"termsOfServiceAgreed": True}
        contact = list(contact)
        if contact:
            payload["contact"] = contact
        resp = await self._post((await self.directory())["newAccount"], payload, what="newAccount", use_jwk=True)
        kid = resp.headers.get("Location")
        if not kid:
            raise AcmeError("The ACME server didn't say which account this key belongs to")
        self.kid = kid
        return kid

    async def new_order(self, names: Iterable[str]) -> tuple[str, dict[str, Any]]:
        """(order URL, order) for ``names``."""
        payload = {"identifiers": [{"type": "dns", "value": n} for n in names]}
        resp = await self._post((await self.directory())["newOrder"], payload, what="newOrder")
        url = resp.headers.get("Location")
        order = self._json(resp)
        if not url or not isinstance(order.get("authorizations"), list) or not isinstance(order.get("finalize"), str):
            raise AcmeError("The ACME server's order was not what Slipway expected")
        return url, order

    async def get(self, url: str, what: str) -> dict[str, Any]:
        return self._json(await self._post(url, None, what=what))

    async def answer(self, challenge_url: str) -> dict[str, Any]:
        """Tell the server the challenge is ready (an empty JSON object, RFC 8555 §7.5.1)."""
        return self._json(await self._post(challenge_url, {}, what="challenge"))

    async def wait(self, url: str, what: str, *, done: str = "valid",
                   tries: int = POLL_TRIES, every: float = POLL_SECONDS) -> dict[str, Any]:
        """Poll an authorization or order until ``done``; ``invalid`` fails at once."""
        for attempt in range(tries):
            obj = await self.get(url, what)
            status = obj.get("status")
            if status == done:
                return obj
            if status in ("invalid", "deactivated", "expired", "revoked"):
                problem, detail = _object_problem(obj)
                raise AcmeError(f"The ACME server marked the {what} {status}" + (f": {detail}" if detail else ""),
                                problem=problem)
            if attempt + 1 < tries:
                await sleep(every)
        raise AcmeError(f"The ACME {what} wasn't {done} after {tries} tries")

    async def finalize(self, finalize_url: str, csr_der: bytes) -> dict[str, Any]:
        return self._json(await self._post(finalize_url, {"csr": b64url(csr_der)}, what="finalize"))

    async def download(self, certificate_url: str) -> str:
        resp = await self._post(certificate_url, None, what="certificate", accept="application/pem-certificate-chain")
        return resp.text


def _object_problem(obj: dict[str, Any]) -> tuple[str | None, str]:
    """(short type, detail cut short) from an object's own ``error`` or its first failed challenge's."""
    errors = [obj.get("error")] + [c.get("error") for c in obj.get("challenges") or [] if isinstance(c, dict)]
    for err in errors:
        if isinstance(err, dict) and (err.get("type") or err.get("detail")):
            return _short(err.get("type")), " ".join(str(err.get("detail") or "").split())[:DETAIL_CHARS]
    return None, ""
