"""Enough of an RFC 8555 ACME server for Slipway's certificate code, over ``httpx.MockTransport``.

It checks every JWS (signature, nonce, URL, ``jwk`` or a known ``kid``), validates DNS-01 against the TXT
records a lookup gives it (``FakeCloudflare``'s records, or the in-memory ``MemoryTxtRecords`` below), and
issues a chain for the asked names signed by its own self-signed root, with a chosen ``not_after``. It
counts orders per name set (``orders[names]``) and refuses a sixth for the same names within its fake
week, as Let's Encrypt does. Its clock is the test's: ``advance(seconds)``.

Inject it with::

    fake = FakeAcme(txt.lookup)
    monkeypatch.setattr(acme, "transport_factory", lambda: httpx.MockTransport(fake.handle))
"""

from __future__ import annotations

import asyncio
import hashlib
import itertools
import json
import uuid
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import NameOID

from slipway.services import acme
from slipway.services.certs import AccountKey, TxtRecord

BASE = "https://acme.test"
DIRECTORY = f"{BASE}/directory"
WEEK = 7 * 86400
PROBLEM = "urn:ietf:params:acme:error:"

TxtLookup = Callable[[str], list[str]]


def _problem(status: int, kind: str, detail: str) -> httpx.Response:
    return httpx.Response(status, headers={"Content-Type": "application/problem+json"},
                          json={"type": PROBLEM + kind, "detail": detail, "status": status})


def _public_key(jwk: dict[str, str]) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("not a P-256 key")
    x = int.from_bytes(acme.b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(acme.b64url_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def _thumbprint(jwk: dict[str, str]) -> str:
    canonical = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, sort_keys=True, separators=(",", ":"))
    return acme.b64url(hashlib.sha256(canonical.encode()).digest())


class FakeAcme:
    def __init__(self, txt_lookup: TxtLookup | None = None, *, base: str = BASE) -> None:
        self.base = base
        self.directory_url = f"{base}/directory"
        self.txt_lookup: TxtLookup = txt_lookup or (lambda name: [])
        self.now = 0.0  # the fake clock, in seconds; advance() moves it
        self.not_after: datetime | None = None  # what issued leaves expire at (default: 90 days on)
        self.duplicate_limit: int | None = 5  # orders per identical name set per fake week
        self.fail_validation = False  # every DNS-01 check fails, whatever the records say
        self.bad_nonce_once = False  # the next signed request answers badNonce
        self.issue_other_names: list[str] | None = None  # a misbehaving server: the leaf names these instead

        self.orders: Counter[tuple[str, ...]] = Counter()
        self._order_times: dict[tuple[str, ...], list[float]] = {}
        self.accounts: dict[str, dict[str, Any]] = {}  # kid -> {jwk, thumbprint}
        self.registrations = 0  # newAccount calls that made an account
        self.requests: list[dict[str, Any]] = []  # {method, path, payload}
        self.seen_txt: dict[str, list[str]] = {}  # challenge record name -> the values present when it was checked
        self._nonces: set[str] = set()
        self._ids = itertools.count(1)
        self._authz: dict[str, dict[str, Any]] = {}
        self._challenges: dict[str, dict[str, Any]] = {}  # id -> {authz, token}
        self._order: dict[str, dict[str, Any]] = {}
        self._certs: dict[str, str] = {}

        self._ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake ACME Root")])
        start = datetime.now(UTC) - timedelta(days=1)
        self.ca_pem = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
                       .public_key(self._ca_key.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(start).not_valid_after(start + timedelta(days=3650))
                       .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                       .sign(self._ca_key, hashes.SHA256())
                       .public_bytes(serialization.Encoding.PEM).decode())
        self._ca_name = ca_name

    # -- helpers for tests

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def paths(self) -> list[str]:
        return [r["path"] for r in self.requests]

    @staticmethod
    def names_key(names: list[str]) -> tuple[str, ...]:
        return tuple(sorted(n.lower() for n in names))

    # -- the server

    def _url(self, path: str) -> str:
        return f"{self.base}{path}"

    def _new_nonce(self) -> str:
        nonce = uuid.uuid4().hex
        self._nonces.add(nonce)
        return nonce

    def handle(self, request: httpx.Request) -> httpx.Response:
        resp = self._handle(request)
        resp.headers["Replay-Nonce"] = self._new_nonce()
        return resp

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path == "/directory":
            self.requests.append({"method": "GET", "path": path, "payload": None})
            return httpx.Response(200, json={
                "newNonce": self._url("/new-nonce"), "newAccount": self._url("/new-account"),
                "newOrder": self._url("/new-order"), "meta": {"termsOfService": self._url("/terms")}})
        if path == "/new-nonce" and request.method in ("HEAD", "GET"):
            self.requests.append({"method": request.method, "path": path, "payload": None})
            return httpx.Response(200)
        if request.method != "POST":
            return _problem(405, "malformed", "Method not allowed")
        if request.headers.get("Content-Type") != "application/jose+json":
            return _problem(415, "malformed", "Content-Type must be application/jose+json")

        try:
            jws = json.loads(request.content)
            protected = json.loads(acme.b64url_decode(jws["protected"]))
            payload = json.loads(acme.b64url_decode(jws["payload"])) if jws["payload"] else None
        except (ValueError, KeyError, TypeError):
            return _problem(400, "malformed", "Unparseable JWS")
        self.requests.append({"method": "POST", "path": path, "payload": payload})

        if self.bad_nonce_once:
            self.bad_nonce_once = False
            return _problem(400, "badNonce", "JWS has an invalid anti-replay nonce")
        nonce = protected.get("nonce")
        if nonce not in self._nonces:
            return _problem(400, "badNonce", "JWS has an invalid anti-replay nonce")
        self._nonces.discard(nonce)
        if protected.get("url") != str(request.url):
            return _problem(401, "unauthorized", "JWS url doesn't match the request")
        if protected.get("alg") != "ES256":
            return _problem(400, "badSignatureAlgorithm", "Only ES256 here")

        if path == "/new-account":
            if "jwk" not in protected or "kid" in protected:
                return _problem(400, "malformed", "newAccount needs a jwk")
            jwk = protected["jwk"]
        else:
            account = self.accounts.get(str(protected.get("kid")))
            if account is None:
                return _problem(400, "accountDoesNotExist", "No account by that kid")
            jwk = account["jwk"]
        try:
            r_s = acme.b64url_decode(jws["signature"])
            signature = encode_dss_signature(int.from_bytes(r_s[:32], "big"), int.from_bytes(r_s[32:], "big"))
            _public_key(jwk).verify(signature, f"{jws['protected']}.{jws['payload']}".encode(),
                                    ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError, KeyError):
            return _problem(400, "malformed", "JWS signature doesn't verify")

        if path == "/new-account":
            return self._new_account(jwk, payload or {})
        thumb = _thumbprint(jwk)
        parts = [p for p in path.split("/") if p]
        if parts == ["new-order"]:
            return self._new_order(payload or {})
        if len(parts) == 2 and parts[0] == "authz":
            return self._get_authz(parts[1])
        if len(parts) == 2 and parts[0] == "chall":
            return self._answer(parts[1], thumb)
        if len(parts) == 2 and parts[0] == "order":
            return self._get_order(parts[1])
        if len(parts) == 2 and parts[0] == "finalize":
            return self._finalize(parts[1], payload or {})
        if len(parts) == 2 and parts[0] == "cert":
            pem = self._certs.get(parts[1])
            if pem is None:
                return _problem(404, "malformed", "No such certificate")
            return httpx.Response(200, headers={"Content-Type": "application/pem-certificate-chain"}, text=pem)
        return _problem(404, "malformed", "No route")

    def _new_account(self, jwk: dict[str, str], payload: dict[str, Any]) -> httpx.Response:
        thumb = _thumbprint(jwk)
        for kid, account in self.accounts.items():
            if account["thumbprint"] == thumb:
                return httpx.Response(200, headers={"Location": kid}, json={"status": "valid"})
        if payload.get("onlyReturnExisting"):
            return _problem(400, "accountDoesNotExist", "No account for this key")
        if not payload.get("termsOfServiceAgreed"):
            return _problem(403, "userActionRequired", "Agree to the terms first")
        kid = self._url(f"/acct/{next(self._ids)}")
        self.accounts[kid] = {"jwk": jwk, "thumbprint": thumb}
        self.registrations += 1
        return httpx.Response(201, headers={"Location": kid}, json={"status": "valid"})

    def _new_order(self, payload: dict[str, Any]) -> httpx.Response:
        idents = payload.get("identifiers") or []
        names = [str(i.get("value", "")).lower() for i in idents if isinstance(i, dict) and i.get("type") == "dns"]
        if not names or len(names) != len(idents):
            return _problem(400, "malformed", "An order needs dns identifiers")
        key = self.names_key(names)
        recent = [t for t in self._order_times.get(key, []) if self.now - t < WEEK]
        if self.duplicate_limit is not None and len(recent) >= self.duplicate_limit:
            return _problem(429, "rateLimited",
                            f"too many certificates ({self.duplicate_limit}) already issued for this exact set "
                            "of identifiers in the last 168h0m0s")
        self._order_times[key] = recent + [self.now]
        self.orders[key] += 1

        oid = str(next(self._ids))
        authz_urls = []
        for name in names:
            aid = str(next(self._ids))
            cid = str(next(self._ids))
            wildcard = name.startswith("*.")
            self._authz[aid] = {"identifier": {"type": "dns", "value": name.removeprefix("*.")},
                                "wildcard": wildcard, "status": "pending", "challenge": cid}
            self._challenges[cid] = {"authz": aid, "token": acme.b64url(uuid.uuid4().bytes), "status": "pending",
                                     "error": None}
            authz_urls.append(self._url(f"/authz/{aid}"))
        self._order[oid] = {"names": list(key), "authorizations": authz_urls, "status": "pending",
                            "finalize": self._url(f"/finalize/{oid}"), "certificate": None}
        return httpx.Response(201, headers={"Location": self._url(f"/order/{oid}")}, json=self._order_json(oid))

    def _order_json(self, oid: str) -> dict[str, Any]:
        order = self._order[oid]
        if order["status"] in ("pending", "ready"):
            states = [self._authz[u.rsplit("/", 1)[1]]["status"] for u in order["authorizations"]]
            if any(s == "invalid" for s in states):
                order["status"] = "invalid"
            elif all(s == "valid" for s in states):
                order["status"] = "ready"
        body = {"status": order["status"], "identifiers": [{"type": "dns", "value": n} for n in order["names"]],
                "authorizations": order["authorizations"], "finalize": order["finalize"]}
        if order["certificate"]:
            body["certificate"] = order["certificate"]
        return body

    def _challenge_json(self, cid: str) -> dict[str, Any]:
        ch = self._challenges[cid]
        body = {"type": "dns-01", "url": self._url(f"/chall/{cid}"), "token": ch["token"], "status": ch["status"]}
        if ch["error"]:
            body["error"] = ch["error"]
        return body

    def _get_authz(self, aid: str) -> httpx.Response:
        authz = self._authz.get(aid)
        if authz is None:
            return _problem(404, "malformed", "No such authorization")
        body = {"identifier": authz["identifier"], "status": authz["status"],
                "challenges": [self._challenge_json(authz["challenge"])]}
        if authz["wildcard"]:
            body["wildcard"] = True
        return httpx.Response(200, json=body)

    def _answer(self, cid: str, thumb: str) -> httpx.Response:
        ch = self._challenges.get(cid)
        if ch is None:
            return _problem(404, "malformed", "No such challenge")
        authz = self._authz[ch["authz"]]
        record = "_acme-challenge." + authz["identifier"]["value"]
        values = list(self.txt_lookup(record))
        self.seen_txt[record] = values
        expected = acme.b64url(hashlib.sha256(f"{ch['token']}.{thumb}".encode()).digest())
        if expected in values and not self.fail_validation:
            ch["status"] = authz["status"] = "valid"
        else:
            ch["status"] = authz["status"] = "invalid"
            ch["error"] = {"type": PROBLEM + "unauthorized",
                           "detail": f"Incorrect TXT record found at {record}" if values
                           else f"No TXT record found at {record}"}
        return httpx.Response(200, json=self._challenge_json(cid))

    def _get_order(self, oid: str) -> httpx.Response:
        if oid not in self._order:
            return _problem(404, "malformed", "No such order")
        return httpx.Response(200, json=self._order_json(oid))

    def _finalize(self, oid: str, payload: dict[str, Any]) -> httpx.Response:
        if oid not in self._order:
            return _problem(404, "malformed", "No such order")
        body = self._order_json(oid)
        if body["status"] != "ready":
            return _problem(403, "orderNotReady", f"Order's status (\"{body['status']}\") is not acceptable for finalization")
        try:
            csr = x509.load_der_x509_csr(acme.b64url_decode(payload["csr"]))
            san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            asked = sorted(n.lower() for n in san.get_values_for_type(x509.DNSName))
        except (KeyError, ValueError, x509.ExtensionNotFound):
            return _problem(400, "badCSR", "Unparseable CSR")
        order = self._order[oid]
        if asked != order["names"]:
            return _problem(400, "badCSR", "CSR names don't match the order")
        names = self.issue_other_names or asked
        start = datetime.now(UTC) - timedelta(hours=1)
        end = self.not_after or (start + timedelta(days=90))
        leaf = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
                .issuer_name(self._ca_name).public_key(csr.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(min(start, end - timedelta(days=1))).not_valid_after(end)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
                .sign(self._ca_key, hashes.SHA256()))
        cert_id = str(next(self._ids))
        self._certs[cert_id] = leaf.public_bytes(serialization.Encoding.PEM).decode() + self.ca_pem
        order["status"] = "valid"
        order["certificate"] = self._url(f"/cert/{cert_id}")
        return httpx.Response(200, headers={"Location": self._url(f"/order/{oid}")}, json=self._order_json(oid))


# ------------------------------------------------------------------------ the protocols' fakes


class MemoryTxtRecords:
    """``certs.TxtRecords`` in memory. ``lookup`` is what DNS would answer, for ``FakeAcme``."""

    def __init__(self) -> None:
        self.records: dict[str, TxtRecord] = {}
        self.created: list[TxtRecord] = []
        self.deleted: list[str] = []
        self.fail_delete = False  # every delete raises (the record stays)

    def add(self, name: str, content: str, comment: str | None) -> TxtRecord:
        rec = TxtRecord(uuid.uuid4().hex, name, content, comment)
        self.records[rec.id] = rec
        return rec

    def lookup(self, name: str) -> list[str]:
        return [r.content for r in self.records.values() if r.name == name]

    async def create(self, name: str, content: str, comment: str) -> str:
        rec = self.add(name, content, comment)
        self.created.append(rec)
        return rec.id

    async def list(self, comment: str) -> list[TxtRecord]:
        return [r for r in self.records.values() if r.comment == comment]

    async def delete(self, record_id: str) -> None:
        if self.fail_delete:
            raise RuntimeError("Cloudflare had a problem")
        self.records.pop(record_id, None)
        self.deleted.append(record_id)


class FakeCloudflareTxt:
    """``certs.TxtRecords`` straight onto ``FakeCloudflare``'s records (G3 adds the real client calls)."""

    def __init__(self, fake_cf: Any, zone_id: str) -> None:
        self.cf = fake_cf
        self.zone_id = zone_id

    def lookup(self, name: str) -> list[str]:
        return [r["content"] for r in self.cf.records.values() if r["type"] == "TXT" and r["name"] == name]

    async def create(self, name: str, content: str, comment: str) -> str:
        return self.cf.add_record(self.zone_id, "TXT", name, content, comment=comment)["id"]

    async def list(self, comment: str) -> list[TxtRecord]:
        return [TxtRecord(r["id"], r["name"], r["content"], r["comment"]) for r in self.cf.records.values()
                if r["zone_id"] == self.zone_id and r["type"] == "TXT" and r["comment"] == comment]

    async def delete(self, record_id: str) -> None:
        self.cf.records.pop(record_id, None)


class MemoryAccountKeys:
    """``certs.AccountKeys`` in memory, put-if-absent under a lock as the ``FOR UPDATE`` store is.
    ``get`` yields once so two first uses started together both see no key."""

    def __init__(self) -> None:
        self.keys: dict[str, str] = {}
        self.kids: dict[str, str] = {}
        self.puts = 0  # put_if_absent calls that stored a key
        self._lock = asyncio.Lock()

    async def get(self, directory: str) -> AccountKey | None:
        await asyncio.sleep(0)
        if directory not in self.keys:
            return None
        return AccountKey(directory, self.keys[directory], self.kids.get(directory))

    async def put_if_absent(self, directory: str, pem: str) -> AccountKey:
        async with self._lock:
            if directory not in self.keys:
                self.keys[directory] = pem
                self.puts += 1
            return AccountKey(directory, self.keys[directory], self.kids.get(directory))

    async def remember_kid(self, directory: str, kid: str) -> None:
        self.kids[directory] = kid
