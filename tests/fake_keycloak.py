"""A stand-in for the HackSpaceLabs Keycloak, and the portal's owner check, behind an ``httpx.MockTransport``.

It serves discovery, signing keys and a token endpoint (authorization code with PKCE, and refresh), signs real
RS256 tokens, and has switches to make it misbehave, so the code under test verifies everything for real.
Mirrors Switchyard's ``internal/hslsso/hslssotest``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "http://kc.test/realms/test"
CLIENT_ID = "slipway"
CLIENT_SECRET = "client-secret-for-tests"
PORTAL = "http://portal.test"


@dataclass
class KcUser:
    sub: str
    username: str
    email: str = ""
    email_verified: bool = False
    name: str = ""
    roles: list[str] | None = None  # None: no hsl_roles claim at all, as Keycloak does for someone with no role
    disabled: bool = False


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@dataclass
class FakeKeycloak:
    session_lifetime: int = 345600  # refresh_expires_in: 96 hours; 2592000 with "Remember me"
    # Misbehaviour switches.
    down: bool = False  # token endpoint answers 503
    discovery_down: bool = False
    wrong_issuer: bool = False
    wrong_audience: bool = False
    wrong_nonce: bool = False
    bad_signature: bool = False
    auth_age: int = 0  # how long ago the person typed their password (auth_time), in seconds
    portal_status: int = 200
    users: dict[str, KcUser] = field(default_factory=dict)
    refresh_requests: int = 0
    owner_requests: list[str] = field(default_factory=list)
    token_requests: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.key, self.other_key = _key(), _key()
        self.codes: dict[str, dict[str, str]] = {}
        self.refresh: dict[str, str] = {}  # refresh token -> Keycloak session id
        self.sessions: dict[str, str] = {}  # session id -> sub

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def add(self, user: KcUser) -> KcUser:
        self.users[user.sub] = user
        return user

    def sign_out(self, sub: str) -> None:
        for sid in [s for s, owner in self.sessions.items() if owner == sub]:
            del self.sessions[sid]

    def authorize(self, auth_url: str, sub: str) -> str:
        """Play the browser and Keycloak's form: check the request, sign in as ``sub``, return the callback URL."""
        parts = urlsplit(auth_url)
        assert f"{parts.scheme}://{parts.netloc}{parts.path}" == f"{ISSUER}/protocol/openid-connect/auth", auth_url
        q = {k: v[0] for k, v in parse_qs(parts.query).items()}
        assert q["client_id"] == CLIENT_ID and q["response_type"] == "code" and q["code_challenge_method"] == "S256"
        assert q["code_challenge"] and q["state"] and q["nonce"] and q["scope"] == "openid profile email", q
        code, sid = secrets.token_urlsafe(18), secrets.token_urlsafe(18)
        self.codes[code] = {"sub": sub, "nonce": q["nonce"], "challenge": q["code_challenge"],
                            "redirect": q["redirect_uri"], "sid": sid}
        self.sessions[sid] = sub
        return f"{q['redirect_uri']}?{urlencode({'code': code, 'state': q['state']})}"

    # ------------------------------------------------------------------ HTTP

    def handle(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.startswith(PORTAL):
            return self._owner(request)
        if url == f"{ISSUER}/.well-known/openid-configuration":
            if self.discovery_down:
                return httpx.Response(503)
            return httpx.Response(200, json={
                "issuer": ISSUER,
                "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
                "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
                "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
                "end_session_endpoint": f"{ISSUER}/protocol/openid-connect/logout",
                "code_challenge_methods_supported": ["plain", "S256"],
            })
        if url == f"{ISSUER}/protocol/openid-connect/certs":
            jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
            enc = dict(jwk, kid="enc1", use="enc", alg="RSA-OAEP")
            return httpx.Response(200, json={"keys": [enc, dict(jwk, kid="k1", use="sig", alg="RS256")]})
        if url == f"{ISSUER}/protocol/openid-connect/token" and request.method == "POST":
            return self._token(request)
        return httpx.Response(404)

    def _token(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            return httpx.Response(503, text="unavailable")
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        self.token_requests.append(form)
        auth = request.headers.get("authorization", "")
        ident, _, secret = base64.b64decode(auth.removeprefix("Basic ")).decode().partition(":") if auth else ("", "", "")
        if ident != CLIENT_ID or secret != CLIENT_SECRET:
            return httpx.Response(401, json={"error": "invalid_client"})
        nonce = ""
        if form.get("grant_type") == "authorization_code":
            grant = self.codes.pop(form.get("code", ""), None)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(form.get("code_verifier", "").encode()).digest()).rstrip(b"=").decode()
            if grant is None or grant["redirect"] != form.get("redirect_uri") or grant["challenge"] != challenge:
                return httpx.Response(400, json={"error": "invalid_grant"})
            sub, sid, nonce = grant["sub"], grant["sid"], grant["nonce"]
        elif form.get("grant_type") == "refresh_token":
            self.refresh_requests += 1
            sid = self.refresh.get(form.get("refresh_token", ""), "")
            sub = self.sessions.get(sid, "")
            if not sub:
                return httpx.Response(400, json={"error": "invalid_grant", "error_description": "Session not active"})
        else:
            return httpx.Response(400, json={"error": "unsupported_grant_type"})
        user = self.users.get(sub)
        if user is None or user.disabled:
            self.sessions.pop(sid, None)
            return httpx.Response(400, json={"error": "invalid_grant", "error_description": "User disabled"})
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": ISSUER + ("-other" if self.wrong_issuer else ""),
            "aud": "someone-else" if self.wrong_audience else CLIENT_ID,
            "azp": "someone-else" if self.wrong_audience else CLIENT_ID,
            "sub": sub, "sid": sid, "typ": "ID", "iat": now, "exp": now + 300, "auth_time": now - self.auth_age,
            "preferred_username": user.username, "email_verified": user.email_verified, "name": user.name,
        }
        if user.email:
            claims["email"] = user.email
        if user.roles is not None:
            claims["hsl_roles"] = user.roles
        if nonce:
            claims["nonce"] = "not-the-nonce" if self.wrong_nonce else nonce
        key = self.other_key if self.bad_signature else self.key
        id_token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "k1"})
        refresh = secrets.token_urlsafe(24)
        self.refresh[refresh] = sid
        return httpx.Response(200, json={
            "access_token": secrets.token_urlsafe(24), "token_type": "Bearer", "expires_in": 300,
            "refresh_token": refresh, "refresh_expires_in": self.session_lifetime, "id_token": id_token,
        })

    def _owner(self, request: httpx.Request) -> httpx.Response:
        """The portal gateway's GET /internal/apps/<app>/owners/<sub> (work package 1i)."""
        prefix = f"{PORTAL}/internal/apps/{CLIENT_ID}/owners/"
        if request.headers.get("authorization") != f"Bearer {CLIENT_SECRET}" or not str(request.url).startswith(prefix):
            return httpx.Response(404, text="Not found")
        sub = str(request.url)[len(prefix):]
        self.owner_requests.append(sub)
        if self.portal_status != 200:
            return httpx.Response(self.portal_status)
        user = self.users.get(sub)
        if user is None:
            return httpx.Response(200, json={"enabled": False, "roles": []})
        return httpx.Response(200, json={"enabled": not user.disabled, "roles": user.roles or []})
