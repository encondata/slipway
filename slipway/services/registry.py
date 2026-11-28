"""Public container images: parse a reference, resolve its tag to a digest, read what the image declares.

Slipway reads images anonymously over the OCI distribution API (``/v2/<name>/manifests/<ref>``), with the
bearer token a registry hands out to anyone for public images. Only registries in ``KNOWN_REGISTRIES`` and
``SLIPWAY_IMAGE_REGISTRIES`` are asked, so a reference typed into the instance form can't make the Slipway
server reach into its own network.

An instance of an image is deployed like a Dockerfile instance whose Dockerfile is ``FROM <image>@<digest>``
(see ``image_dockerfile``): the host pulls the image, and ports, volumes, variables, hostnames and releases all
work as they do for a Dockerfile.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

import httpx

from slipway.core.config import get_settings

DOCKER_HUB = "docker.io"
DOCKER_HUB_API = "registry-1.docker.io"
# Public registries that hand out anonymous pull tokens. lscr.io is LinuxServer's front for ghcr.io.
KNOWN_REGISTRIES = (
    DOCKER_HUB, "ghcr.io", "lscr.io", "quay.io", "gcr.io", "registry.gitlab.com", "public.ecr.aws",
    "mcr.microsoft.com", "registry.k8s.io",
)
REF_MAX = 255  # instances.image

_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_NAME_RE = re.compile(rf"^{_COMPONENT}(?:/{_COMPONENT})*$")
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*(?::[0-9]{1,5})?$")
_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

INDEX_TYPES = ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")
MANIFEST_TYPES = ("application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json")
ACCEPT = ", ".join((*INDEX_TYPES, *MANIFEST_TYPES))
DOC_LIMIT = 4 * 1024 * 1024  # a manifest, an index or an image config

Transport = httpx.AsyncBaseTransport | None
# Tests swap it for an httpx.MockTransport; the test guard makes the real one refuse every request.
transport_factory: Callable[[], Transport] = lambda: None  # noqa: E731


class RegistryError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code

    @property
    def transient(self) -> bool:
        return self.status_code is None or self.status_code >= 500 or self.status_code == 429


@dataclass(frozen=True)
class ImageRef:
    """A parsed reference: ``registry`` as people write it (``docker.io``), the repository ``name`` in it
    (``library/nginx``), and a ``tag`` or a ``digest`` (one of them is always set)."""

    registry: str
    name: str
    tag: str | None = None
    digest: str | None = None

    @property
    def api_host(self) -> str:
        return DOCKER_HUB_API if self.registry == DOCKER_HUB else self.registry

    @property
    def repository(self) -> str:
        """``nginx`` for Docker Hub's official images, ``linuxserver/jellyfin``, ``ghcr.io/owner/app``."""
        if self.registry == DOCKER_HUB:
            return self.name.removeprefix("library/")
        return f"{self.registry}/{self.name}"

    @property
    def reference(self) -> str:
        """The tag or digest the registry is asked for."""
        return self.digest or self.tag or "latest"

    @property
    def label(self) -> str:
        """The reference as stored and shown: ``nginx:1.27``, ``ghcr.io/owner/app@sha256:…``."""
        return f"{self.repository}@{self.digest}" if self.digest else f"{self.repository}:{self.tag}"

    @property
    def branch(self) -> str:
        """What stands in for a branch on the instance and its deployments: the tag, or ``digest``."""
        return self.tag or "digest"

    def pinned(self, digest: str) -> str:
        """The full reference of one exact image, as the generated Dockerfile's FROM line names it."""
        return f"{self.registry}/{self.name}@{digest}"

    @property
    def page_url(self) -> str | None:
        if self.registry == DOCKER_HUB:
            return f"https://hub.docker.com/{'_' if self.name.startswith('library/') else 'r'}/{self.repository}"
        if self.registry == "lscr.io" and self.name.startswith("linuxserver/"):
            return f"https://docs.linuxserver.io/images/docker-{self.name.removeprefix('linuxserver/')}/"
        if self.registry == "ghcr.io":
            return f"https://ghcr.io/{self.name}"  # GHCR sends browsers on to the package's page
        if self.registry == "quay.io":
            return f"https://quay.io/repository/{self.name}"
        return None


def _from_hub_url(text: str) -> str | None:
    """``https://hub.docker.com/r/owner/name`` (or ``/_/nginx``, with ``/tags`` or ``?tab=…``) as a reference."""
    parts = urlsplit(text)
    if parts.hostname not in ("hub.docker.com", "registry.hub.docker.com"):
        return None
    bits = [b for b in parts.path.split("/") if b]
    if len(bits) >= 2 and bits[0] == "_":
        return bits[1]
    if len(bits) >= 3 and bits[0] in ("r", "repository") and bits[1] != "_":
        return f"{bits[1]}/{bits[2]}"
    if len(bits) >= 3 and bits[0] == "repository" and bits[1] == "_":
        return bits[2]
    return None


def parse(text: str) -> ImageRef:
    """Parse ``nginx``, ``linuxserver/jellyfin:latest``, ``ghcr.io/owner/app:v1``, ``name@sha256:…`` or a
    Docker Hub page URL. Raises ValueError with a sentence fit for the form."""
    value = (text or "").strip()
    if not value:
        raise ValueError("Enter an image, such as nginx:latest or ghcr.io/owner/app:1.0")
    if "://" in value:
        hub = _from_hub_url(value)
        if hub is None:
            raise ValueError("Enter the image's name (such as linuxserver/jellyfin:latest), or a hub.docker.com page")
        value = hub
    if len(value) > REF_MAX or any(c.isspace() for c in value):
        raise ValueError(f"An image reference has no spaces and at most {REF_MAX} characters")
    rest, _, digest = value.partition("@")
    if digest and not DIGEST_RE.match(digest):
        raise ValueError("A digest is written sha256: followed by 64 lowercase hex digits")
    tag = None
    slash = rest.rfind("/")
    colon = rest.rfind(":")
    if colon > slash:
        rest, tag = rest[:colon], rest[colon + 1:]
        if not _TAG_RE.match(tag):
            raise ValueError(f"'{tag}' is not a valid image tag")
    first, sep, remainder = rest.partition("/")
    if sep and ("." in first or ":" in first or first == "localhost"):
        registry, name = first.lower(), remainder
        if not _DOMAIN_RE.match(registry):
            raise ValueError(f"'{first}' is not a valid registry name")
    else:
        registry, name = DOCKER_HUB, rest
    if registry in ("index.docker.io", "registry-1.docker.io", "registry.hub.docker.com"):
        registry = DOCKER_HUB
    if not _NAME_RE.match(name):
        raise ValueError(f"'{name}' is not a valid image name (lowercase letters, digits, and . _ - / between them)")
    if registry == DOCKER_HUB and "/" not in name:
        name = f"library/{name}"
    if not digest and not tag:
        tag = "latest"
    ref = ImageRef(registry=registry, name=name, tag=tag, digest=digest or None)
    if len(ref.label) > REF_MAX:
        raise ValueError(f"An image reference has at most {REF_MAX} characters")
    return ref


def allowed_registries() -> tuple[str, ...]:
    return (*KNOWN_REGISTRIES, *get_settings().image_registries)


def check_allowed(ref: ImageRef) -> None:
    if ref.registry not in allowed_registries():
        raise ValueError(
            f"Slipway doesn't read images from {ref.registry}. Public images on Docker Hub, GHCR, lscr.io, Quay, GCR, "
            "GitLab, ECR Public and MCR work; an administrator can add others with SLIPWAY_IMAGE_REGISTRIES"
        )


def image_dockerfile(ref: ImageRef, digest: str) -> str:
    """What an image instance builds: the image itself, pinned to the digest the deploy resolved."""
    return (f"# Generated by Slipway: {ref.label}\n"
            f"FROM {ref.pinned(digest)}\n")


@dataclass
class ImageInfo:
    """What an image says about itself, for the instance form: its ports, volumes and default variables."""

    ref: str
    digest: str
    platform: str | None = None
    ports: list[dict[str, Any]] = field(default_factory=list)  # [{container, protocol}]
    volumes: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    title: str | None = None
    description: str | None = None
    source: str | None = None
    page_url: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {"ref": self.ref, "digest": self.digest, "platform": self.platform, "ports": self.ports,
                "volumes": self.volumes, "env": self.env, "title": self.title, "description": self.description,
                "source": self.source, "page_url": self.page_url}


def _challenge(header: str) -> dict[str, str]:
    """The parameters of ``WWW-Authenticate: Bearer realm="…",service="…",scope="…"``."""
    scheme, _, params = header.strip().partition(" ")
    if scheme.lower() != "bearer":
        return {}
    return {k.lower(): v for k, v in re.findall(r'(\w+)="([^"]*)"', params)}


class RegistryClient:
    """Anonymous reads from one registry. Use as an async context manager."""

    def __init__(self, ref: ImageRef, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.ref = ref
        self._token: str | None = None
        self._client = httpx.AsyncClient(
            timeout=30, follow_redirects=True, headers={"User-Agent": "Slipway"},
            transport=transport if transport is not None else transport_factory(),
        )

    async def __aenter__(self) -> RegistryClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    def _url(self, kind: str, reference: str) -> str:
        return f"https://{self.ref.api_host}/v2/{quote(self.ref.name, safe='/')}/{kind}/{quote(reference, safe=':')}"

    async def _authenticate(self, header: str) -> None:
        params = _challenge(header)
        realm = params.get("realm", "")
        if urlsplit(realm).scheme != "https":
            raise RegistryError(f"{self.ref.registry} asked to sign in somewhere Slipway won't go", 401)
        query = {k: params[k] for k in ("service", "scope") if params.get(k)}
        query.setdefault("scope", f"repository:{self.ref.name}:pull")
        try:
            resp = await self._client.get(f"{realm}?{urlencode(query)}")
            data = resp.json() if resp.status_code == 200 else {}
        except (httpx.HTTPError, ValueError) as exc:
            raise RegistryError(f"{self.ref.registry}: sign-in failed ({type(exc).__name__})") from exc
        token = data.get("token") or data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise RegistryError(f"{self.ref.registry} refused anonymous access to {self.ref.repository}", resp.status_code)
        self._token = token

    async def _get(self, url: str, accept: str | None = None, *, method: str = "GET") -> httpx.Response:
        for attempt in range(2):
            headers = {"Accept": accept} if accept else {}
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"
            try:
                resp = await self._client.request(method, url, headers=headers)
            except httpx.HTTPError as exc:
                raise RegistryError(f"{self.ref.registry}: request failed ({type(exc).__name__})") from exc
            if resp.status_code == 401 and attempt == 0 and "www-authenticate" in resp.headers:
                await self._authenticate(resp.headers["www-authenticate"])
                continue
            break
        if resp.status_code in (401, 403, 404):
            raise RegistryError(f"{self.ref.label} was not found on {self.ref.registry}, or it isn't public",
                                resp.status_code)
        if resp.status_code == 429:
            raise RegistryError(f"{self.ref.registry} is rate limiting requests; try again in a few minutes", 429)
        if resp.status_code >= 400:
            raise RegistryError(f"{self.ref.registry} answered {resp.status_code} for {self.ref.label}", resp.status_code)
        if len(resp.content) > DOC_LIMIT:
            raise RegistryError(f"{self.ref.registry} sent more than Slipway reads for {self.ref.label}")
        return resp

    async def _document(self, kind: str, reference: str, accept: str | None = None) -> tuple[dict[str, Any], str, str]:
        """A manifest, index or blob as JSON, its digest (checked against the content) and its media type."""
        resp = await self._get(self._url(kind, reference), accept)
        digest = "sha256:" + hashlib.sha256(resp.content).hexdigest()
        if DIGEST_RE.match(reference) and digest != reference:
            raise RegistryError(f"{self.ref.registry} sent content that doesn't match {reference[:19]}…")
        try:
            data = json.loads(resp.content)
        except ValueError as exc:
            raise RegistryError(f"{self.ref.registry} sent an unreadable manifest for {self.ref.label}") from exc
        if not isinstance(data, dict):
            raise RegistryError(f"{self.ref.registry} sent an unreadable manifest for {self.ref.label}")
        media = str(data.get("mediaType") or resp.headers.get("content-type", "")).split(";")[0].strip()
        return data, digest, media

    async def resolve(self) -> str:
        """The digest the tag (or digest) names now: of the index for a multi-platform image."""
        if self.ref.digest:
            await self._get(self._url("manifests", self.ref.digest), ACCEPT, method="HEAD")
            return self.ref.digest
        resp = await self._get(self._url("manifests", self.ref.reference), ACCEPT, method="HEAD")
        digest = resp.headers.get("docker-content-digest", "")
        if DIGEST_RE.match(digest):
            return digest
        _, digest, _ = await self._document("manifests", self.ref.reference, ACCEPT)
        return digest

    async def inspect(self, platform: str = "linux/amd64") -> ImageInfo:
        """Resolve the reference and read the image config for ``platform`` (or the first Linux one)."""
        doc, digest, media = await self._document("manifests", self.ref.reference, ACCEPT)
        chosen = None
        if media in INDEX_TYPES or "manifests" in doc:
            entries = [m for m in doc.get("manifests") or [] if isinstance(m, dict)]
            want_os, _, want_arch = platform.partition("/")

            def plat(m: dict[str, Any]) -> tuple[str, str]:
                p = m.get("platform") or {}
                return str(p.get("os") or ""), str(p.get("architecture") or "")

            pick = next((m for m in entries if plat(m) == (want_os, want_arch)), None) \
                or next((m for m in entries if plat(m)[0] == "linux" and plat(m)[1] != "unknown"), None)
            if pick is None or not DIGEST_RE.match(str(pick.get("digest") or "")):
                raise RegistryError(f"{self.ref.label} has no Linux image")
            chosen = "/".join(plat(pick))
            doc, _, _ = await self._document("manifests", str(pick["digest"]), ", ".join(MANIFEST_TYPES))
        config_digest = str((doc.get("config") or {}).get("digest") or "")
        if not DIGEST_RE.match(config_digest):
            raise RegistryError(f"{self.ref.label}'s manifest names no image config")
        config, _, _ = await self._document("blobs", config_digest)
        return info_from_config(self.ref, digest, config, chosen)


def info_from_config(ref: ImageRef, digest: str, config: dict[str, Any], platform: str | None) -> ImageInfo:
    inner = config.get("config") or {}
    ports = []
    for key in sorted((inner.get("ExposedPorts") or {}).keys()):
        number, _, proto = str(key).partition("/")
        if number.isdigit() and 0 < int(number) < 65536:
            ports.append({"container": int(number), "protocol": "udp" if proto == "udp" else "tcp"})
    env: dict[str, str] = {}
    for item in inner.get("Env") or []:
        k, sep, v = str(item).partition("=")
        if sep and k and k not in ("PATH", "HOME", "HOSTNAME", "TERM", "LANG", "LANGUAGE", "LC_ALL"):
            env[k] = v
    labels = inner.get("Labels") or {}

    def label(key: str) -> str | None:
        v = labels.get(key)
        return str(v)[:500] if v else None

    return ImageInfo(
        ref=ref.label, digest=digest, platform=platform, ports=ports[:50],
        volumes=sorted(str(v) for v in (inner.get("Volumes") or {}).keys())[:50], env=dict(list(env.items())[:50]),
        title=label("org.opencontainers.image.title"), description=label("org.opencontainers.image.description"),
        source=label("org.opencontainers.image.source") or label("org.opencontainers.image.url"),
        page_url=ref.page_url,
    )


async def resolve(ref: ImageRef, *, transport: httpx.AsyncBaseTransport | None = None) -> str:
    check_allowed(ref)
    async with RegistryClient(ref, transport=transport) as client:
        return await client.resolve()


async def inspect(ref: ImageRef, *, transport: httpx.AsyncBaseTransport | None = None) -> ImageInfo:
    check_allowed(ref)
    async with RegistryClient(ref, transport=transport) as client:
        return await client.inspect()
