"""Sign in with HackSpaceLabs: talking to the HackSpaceLabs Keycloak (OpenID Connect, authorization code with
PKCE S256, state and nonce), rechecking sessions with refresh tokens, and the portal's owner check for API tokens.

The contract is PLAN.md section 5 in the HSL Suite workspace; Switchyard's ``internal/hslsso`` is the reference
implementation this follows.

Discovery is lazy: nothing is fetched until the first sign-in or recheck, a failure is retried on the next call,
and a working configuration is kept for an hour (if a refetch fails, the last good one stays in use). Slipway
never fails to start, or turns sign-in off, because Keycloak could not be reached.

Errors come in three kinds. ``Refused``: Keycloak definitely said no (``invalid_grant`` because the person signed
out, was disabled or their session expired, or an answer for somebody else): end the session. ``InvalidToken``:
an ID token failed verification: end the session or refuse the sign-in. ``Unavailable``: anything else
(network, timeout, 5xx, discovery, keys): keep the session and try again later.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

import httpx
import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.core.config import get_settings
from slipway.models import Role

log = logging.getLogger(__name__)

Transport = httpx.AsyncBaseTransport | None
# Used for every request to Keycloak and the portal. Tests swap it for an httpx.MockTransport; the test guard makes
# the real one refuse every request.
transport_factory: Callable[[], Transport] = lambda: None  # noqa: E731

DISCOVERY_TTL = 3600.0  # seconds a working discovery document is used before it is fetched again
HTTP_TIMEOUT = 10.0
RECHECK_TIMEOUT = 5.0  # PLAN.md 5.7: a recheck waits at most this long for Keycloak
LEEWAY = 60  # seconds of clock skew allowed on exp and iat
DEFAULT_SESSION = timedelta(hours=96)  # when Keycloak does not say how long its session lasts
OWNER_CHECK_EVERY = 300.0  # seconds between portal owner checks of one person (PLAN.md D18)


class HslError(RuntimeError):
    """Base of the three kinds below. The message never contains a token."""


class Refused(HslError):
    """Keycloak definitely ended the session or refused the request. End the app's session."""


class InvalidToken(HslError):
    """An ID token failed verification. End the session or refuse the sign-in."""


class Unavailable(HslError):
    """Keycloak could not be asked. Keep the app's session and try again later."""


@dataclass
class Claims:
    """The ID-token claims Slipway uses."""

    sub: str
    sid: str = ""
    preferred_username: str = ""
    name: str = ""
    email: str = ""
    email_verified: bool = False
    # The roles of this app's Keycloak client. Keycloak leaves the claim out for someone with no role: [] then.
    roles: list[str] = field(default_factory=list)
    nonce: str = ""
    auth_time: int | None = None

    @classmethod
    def of(cls, payload: dict[str, Any]) -> Claims:
        def text(key: str) -> str:
            value = payload.get(key)
            return value.strip() if isinstance(value, str) else ""

        roles = payload.get("hsl_roles")
        auth_time = payload.get("auth_time")
        return cls(
            sub=text("sub"), sid=text("sid"), preferred_username=text("preferred_username"), name=text("name"),
            email=text("email").lower(), email_verified=payload.get("email_verified") is True,
            roles=[r for r in roles if isinstance(r, str)] if isinstance(roles, list) else [],
            nonce=text("nonce"),
            auth_time=auth_time if isinstance(auth_time, int) and not isinstance(auth_time, bool) else None,
        )


@dataclass
class Tokens:
    """The result of a sign-in or a recheck."""

    claims: Claims
    id_token: str
    refresh_token: str
    # Keycloak's refresh_expires_in in seconds: how much longer its session lasts (96 hours, or 30 days with
    # "Remember me"). 0 when Keycloak did not say.
    refresh_expires_in: int = 0

    @property
    def session_lifetime(self) -> timedelta:
        """How long the app's session lasts: Keycloak's own session, or 96 hours when it did not say."""
        return timedelta(seconds=self.refresh_expires_in) if self.refresh_expires_in > 0 else DEFAULT_SESSION


@dataclass
class Flow:
    """One sign-in attempt's secrets. Kept in the encrypted flow cookie until the callback (PLAN.md 5.4)."""

    state: str
    nonce: str
    verifier: str

    @classmethod
    def new(cls) -> Flow:
        # 43 to 128 characters for the verifier (RFC 7636); token_urlsafe(48) gives 64.
        return cls(state=secrets.token_urlsafe(32), nonce=secrets.token_urlsafe(32), verifier=secrets.token_urlsafe(48))

    @property
    def challenge(self) -> str:
        digest = hashlib.sha256(self.verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@dataclass
class _Provider:
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    end_session_endpoint: str
    fetched: float
    keys: dict[str, jwt.PyJWK] = field(default_factory=dict)


def with_origin(url: str, origin: str) -> str:
    """``url`` with its scheme and host replaced by ``origin``'s."""
    parts, base = urlsplit(url), urlsplit(origin)
    return urlunsplit((base.scheme, base.netloc, parts.path, parts.query, parts.fragment))


def _oauth_error(response: httpx.Response) -> str:
    try:
        data = response.json()
    except ValueError:
        return ""
    error = data.get("error") if isinstance(data, dict) else None
    return error if isinstance(error, str) else ""


class Client:
    """Talks to Keycloak for Slipway's client. Safe to share between requests."""

    def __init__(
        self, *, issuer: str, client_id: str, client_secret: str, redirect_url: str, internal_url: str = "",
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self._secret = client_secret
        self.redirect_url = redirect_url
        self.internal_url = internal_url.rstrip("/")
        self._clock = clock
        self._current: _Provider | None = None
        self._lock = asyncio.Lock()

    def _http(self, timeout: float = HTTP_TIMEOUT) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=transport_factory(), timeout=timeout, follow_redirects=False)

    # ------------------------------------------------------------------ discovery

    async def _provider(self) -> _Provider:
        async with self._lock:
            current = self._current
            if current is not None and self._clock() - current.fetched < DISCOVERY_TTL:
                return current
            try:
                self._current = await self._discover()
            except Unavailable:
                if current is not None:
                    return current
                raise
            return self._current

    async def _discover(self) -> _Provider:
        base = with_origin(self.issuer, self.internal_url) if self.internal_url else self.issuer
        try:
            async with self._http() as http:
                response = await http.get(f"{base}/.well-known/openid-configuration")
        except httpx.HTTPError as exc:
            raise Unavailable(f"discovery: request failed ({type(exc).__name__})") from None
        if response.status_code != 200:
            raise Unavailable(f"discovery: HTTP {response.status_code}")
        try:
            doc = response.json()
        except ValueError:
            raise Unavailable("discovery: not JSON") from None
        if not isinstance(doc, dict):
            raise Unavailable("discovery: not a JSON object")
        if doc.get("issuer") != self.issuer:
            raise Unavailable(f"discovery: issuer is {str(doc.get('issuer'))[:200]!r}, expected {self.issuer!r}")
        endpoints = {k: doc.get(k) for k in ("authorization_endpoint", "token_endpoint", "jwks_uri", "end_session_endpoint")}
        if not all(isinstance(endpoints[k], str) and endpoints[k] for k in ("authorization_endpoint", "token_endpoint", "jwks_uri")):
            raise Unavailable("discovery: missing endpoints")
        methods = doc.get("code_challenge_methods_supported")
        if isinstance(methods, list) and methods and "S256" not in methods:
            raise Unavailable("discovery: PKCE S256 not supported")
        token, jwks = str(endpoints["token_endpoint"]), str(endpoints["jwks_uri"])
        if self.internal_url:
            # Keycloak lists its public addresses whatever address it was asked through (PLAN.md 5.1). Calls from
            # here go to the internal origin; the browser keeps using the public ones.
            token, jwks = with_origin(token, self.internal_url), with_origin(jwks, self.internal_url)
        end_session = endpoints["end_session_endpoint"]
        return _Provider(
            authorization_endpoint=str(endpoints["authorization_endpoint"]), token_endpoint=token, jwks_uri=jwks,
            end_session_endpoint=end_session if isinstance(end_session, str) else "", fetched=self._clock(),
        )

    async def _fetch_keys(self, provider: _Provider) -> None:
        try:
            async with self._http() as http:
                response = await http.get(provider.jwks_uri)
            if response.status_code != 200:
                raise Unavailable(f"signing keys: HTTP {response.status_code}")
            keys = response.json().get("keys", [])
        except (httpx.HTTPError, ValueError, AttributeError) as exc:
            raise Unavailable(f"signing keys: request failed ({type(exc).__name__})") from None
        usable: dict[str, jwt.PyJWK] = {}
        for data in keys if isinstance(keys, list) else []:
            if not isinstance(data, dict) or data.get("use", "sig") != "sig" or data.get("kty") != "RSA":
                continue
            try:
                key = jwt.PyJWK(data, algorithm="RS256")
            except jwt.PyJWKError:
                continue
            usable[str(data.get("kid", ""))] = key
        provider.keys = usable

    async def _key(self, provider: _Provider, kid: str) -> jwt.PyJWK:
        """The realm key ``kid``. An unknown key id refetches the key set once (Keycloak rotated its keys)."""
        if kid not in provider.keys:
            await self._fetch_keys(provider)
        key = provider.keys.get(kid)
        if key is None:
            raise InvalidToken("signed with a key the realm does not list")
        return key

    # -------------------------------------------------------------- the flow

    async def authorization_url(self, flow: Flow, *, prompt: str = "", max_age: int | None = None) -> str:
        """Where to send the browser to sign in. ``prompt="login"`` asks for the password even when Keycloak has
        a session; ``max_age=0`` also makes Keycloak report a fresh ``auth_time``."""
        provider = await self._provider()
        params = {
            "response_type": "code", "client_id": self.client_id, "redirect_uri": self.redirect_url,
            "scope": "openid profile email", "state": flow.state, "nonce": flow.nonce,
            "code_challenge": flow.challenge, "code_challenge_method": "S256",
        }
        if prompt:
            params["prompt"] = prompt
        if max_age is not None:
            params["max_age"] = str(max_age)
        joiner = "&" if "?" in provider.authorization_endpoint else "?"
        return f"{provider.authorization_endpoint}{joiner}{urlencode(params)}"

    async def _token_request(self, provider: _Provider, form: dict[str, str], timeout: float) -> httpx.Response:
        # client_secret_basic, with id and secret form-encoded first as RFC 6749 2.3.1 asks.
        auth = httpx.BasicAuth(quote(self.client_id, safe=""), quote(self._secret, safe=""))
        try:
            async with self._http(timeout) as http:
                return await http.post(provider.token_endpoint, data=form, auth=auth, headers={"Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise Unavailable(f"token request failed ({type(exc).__name__})") from None

    async def exchange(self, code: str, flow: Flow) -> Tokens:
        """Turn the callback's code into tokens and verify the ID token, including its nonce."""
        provider = await self._provider()
        response = await self._token_request(provider, {
            "grant_type": "authorization_code", "code": code, "redirect_uri": self.redirect_url,
            "code_verifier": flow.verifier,
        }, HTTP_TIMEOUT)
        if response.status_code >= 500:
            raise Unavailable(f"code exchange: HTTP {response.status_code}")
        if response.status_code != 200:
            raise Refused(f"code exchange: HTTP {response.status_code} {_oauth_error(response)[:60]}".rstrip())
        return await self._tokens(provider, response, nonce=flow.nonce)

    async def refresh(self, refresh_token: str, subject: str) -> Tokens:
        """Recheck a session. ``subject`` is whose session it is; an answer for anyone else is ``Refused``."""
        provider = await self._provider()
        response = await self._token_request(provider, {
            "grant_type": "refresh_token", "refresh_token": refresh_token,
        }, RECHECK_TIMEOUT)
        if response.status_code != 200:
            error = _oauth_error(response)
            if response.status_code == 400 and error == "invalid_grant":
                raise Refused("refresh: invalid_grant")
            raise Unavailable(f"refresh: HTTP {response.status_code} {error[:60]}".rstrip())
        tokens = await self._tokens(provider, response, keep_refresh=refresh_token)
        if tokens.claims.sub != subject:
            raise Refused("refresh: the session now belongs to someone else")
        return tokens

    async def _tokens(self, provider: _Provider, response: httpx.Response, *, nonce: str = "", keep_refresh: str = "") -> Tokens:
        try:
            body = response.json()
        except ValueError:
            raise Unavailable("token response: not JSON") from None
        if not isinstance(body, dict):
            raise Unavailable("token response: not a JSON object")
        raw = body.get("id_token")
        if not isinstance(raw, str) or not raw:
            raise InvalidToken("no ID token in the response")
        claims = await self.verify(provider, raw, nonce=nonce)
        refresh = body.get("refresh_token")
        lifetime = body.get("refresh_expires_in")
        return Tokens(
            claims=claims, id_token=raw,
            refresh_token=refresh if isinstance(refresh, str) and refresh else keep_refresh,
            refresh_expires_in=lifetime if isinstance(lifetime, int) and not isinstance(lifetime, bool) and lifetime > 0 else 0,
        )

    async def verify(self, provider: _Provider, raw: str, *, nonce: str = "") -> Claims:
        """PLAN.md 5.5 step 4: RS256 against the realm keys; iss, aud (and azp), exp and iat with 60 s leeway;
        the nonce when one is given; a non-empty sub."""
        try:
            header = jwt.get_unverified_header(raw)
        except jwt.PyJWTError:
            raise InvalidToken("ID token is malformed") from None
        if header.get("alg") != "RS256":
            raise InvalidToken("ID token is not signed with RS256")
        key = await self._key(provider, str(header.get("kid", "")))
        try:
            payload = jwt.decode(
                raw, key=key, algorithms=["RS256"], audience=self.client_id, issuer=self.issuer, leeway=LEEWAY,
                options={"require": ["iss", "sub", "aud", "exp", "iat"]},
            )
        except jwt.PyJWTError as exc:
            raise InvalidToken(f"ID token rejected ({type(exc).__name__})") from None
        if payload.get("iss") != self.issuer:
            raise InvalidToken("ID token has the wrong issuer")
        audience = payload.get("aud")
        if isinstance(audience, list) and len(audience) > 1 and payload.get("azp") != self.client_id:
            raise InvalidToken("ID token was issued to another client")
        claims = Claims.of(payload)
        if not claims.sub:
            raise InvalidToken("ID token has no subject")
        if nonce and not secrets.compare_digest(claims.nonce.encode(), nonce.encode()):
            raise InvalidToken("ID token nonce does not match")
        return claims

    async def end_session_url(self, id_token: str, post_logout: str) -> str:
        """Keycloak's sign-out address, coming back to ``post_logout`` (registered exactly: <base url>/signed-out).
        Without ``id_token`` Keycloak asks the person to confirm first."""
        provider = await self._provider()
        if not provider.end_session_endpoint:
            raise Unavailable("no end_session_endpoint")
        params = {"client_id": self.client_id, "post_logout_redirect_uri": post_logout}
        if id_token:
            params["id_token_hint"] = id_token
        joiner = "&" if "?" in provider.end_session_endpoint else "?"
        return f"{provider.end_session_endpoint}{joiner}{urlencode(params)}"


_client: tuple[tuple[str, ...], Client] | None = None


def reset() -> None:
    """Forget the cached client (its discovery and keys) and the owner checks. For tests and settings changes."""
    global _client
    _client = None
    _owners.clear()


def client() -> Client | None:
    """The Keycloak client for the current settings, or None when HackSpaceLabs sign-in is off."""
    global _client
    settings = get_settings()
    if not settings.hsl_enabled:
        return None
    config = (settings.hsl_oidc_issuer, settings.hsl_oidc_client_id, settings.hsl_oidc_client_secret,
              settings.hsl_callback_url, settings.hsl_oidc_internal_url)
    if _client is None or _client[0] != config:
        _client = (config, Client(
            issuer=config[0], client_id=config[1], client_secret=config[2], redirect_url=config[3], internal_url=config[4],
        ))
    return _client[1]


async def known_roles(db: AsyncSession, claimed: list[str]) -> list[Role]:
    """The Slipway roles named in the claim (built-in and custom ones of the same name), by name."""
    names = {r for r in claimed if r}
    if not names:
        return []
    return list((await db.scalars(select(Role).where(Role.name.in_(names)).order_by(Role.name))).all())


def sealed(tokens: Tokens) -> dict[str, str]:
    """What a session keeps of a sign-in, encrypted: whose it is, the refresh token and the latest ID token."""
    return {"sub": tokens.claims.sub, "refresh_token": tokens.refresh_token, "id_token": tokens.id_token}


# -------------------------------------------------------------- owner check (D18)

# Keycloak user id -> (when it was asked, monotonic; whether the owner may use their API tokens).
_owners: dict[str, tuple[float, bool]] = {}


def owner_check_configured() -> bool:
    settings = get_settings()
    return bool(settings.hsl_portal_internal_url and settings.hsl_oidc_client_secret)


async def owner_allowed(db: AsyncSession, subject: str) -> bool:
    """Whether the HackSpaceLabs person ``subject`` may still use their API tokens: the portal says they are
    enabled and hold a Slipway role. Asked at most every five minutes per person. When the portal can't answer,
    the last answer stands, and someone never checked yet is let through (the outage rule, PLAN.md D5)."""
    if not owner_check_configured():
        return True
    now = time.monotonic()
    cached = _owners.get(subject)
    if cached is not None and now - cached[0] < OWNER_CHECK_EVERY:
        return cached[1]
    answer = await _ask_portal(subject)
    if answer is None:
        verdict = cached[1] if cached is not None else True
    else:
        enabled, roles = answer
        verdict = enabled and bool(await known_roles(db, roles))
        if not verdict:
            log.info("API tokens of HackSpaceLabs user %s refused: %s", subject,
                     "no Slipway role" if enabled else "disabled or removed in HackSpaceLabs")
    _owners[subject] = (now, verdict)
    return verdict


async def _ask_portal(subject: str) -> tuple[bool, list[str]] | None:
    """The portal's answer (enabled, roles), or None when it couldn't be had."""
    settings = get_settings()
    url = (f"{settings.hsl_portal_internal_url}/internal/apps/{quote(settings.hsl_oidc_client_id, safe='')}"
           f"/owners/{quote(subject, safe='')}")
    try:
        async with httpx.AsyncClient(transport=transport_factory(), timeout=RECHECK_TIMEOUT, follow_redirects=False) as http:
            response = await http.get(url, headers={
                "Authorization": f"Bearer {settings.hsl_oidc_client_secret}", "Accept": "application/json",
            })
    except httpx.HTTPError as exc:
        log.warning("Couldn't reach the HackSpaceLabs portal to check an API token's owner (%s); allowing it for now",
                    type(exc).__name__)
        return None
    if response.status_code == 400:
        return False, []  # the portal can't read this id as a Keycloak user, so it is nobody it knows
    if response.status_code == 404:
        log.error("The HackSpaceLabs portal refused Slipway's owner check (HTTP 404). Check HSL_PORTAL_INTERNAL_URL "
                  "(the gateway itself, not through the proxy) and HSL_OIDC_CLIENT_SECRET; allowing the token for now")
        return None
    if response.status_code != 200:
        log.warning("The HackSpaceLabs portal couldn't check an API token's owner (HTTP %d); allowing it for now",
                    response.status_code)
        return None
    try:
        data = json.loads(response.content)
    except ValueError:
        data = None
    if not isinstance(data, dict) or not isinstance(data.get("enabled"), bool) or not isinstance(data.get("roles"), list):
        log.warning("The HackSpaceLabs portal's owner check answer wasn't understood; allowing the token for now")
        return None
    return data["enabled"], [r for r in data["roles"] if isinstance(r, str)]
