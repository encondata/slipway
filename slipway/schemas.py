"""Pydantic request/response models for the JSON API."""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.core.permissions import validate_permissions
from slipway.models import Backup, Deployment, FirstAdmin, Host, Instance, Repository, Snapshot, User
from slipway.services import data, deployer, manifest, ports, registry, switchyard

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
_VOLUME_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
# Branch names are identifiers and never cut, so the limit is that of the columns holding them (255).
BRANCH_MAX = Instance.__table__.c.branch.type.length


def _no_nul(value: str) -> str:
    if "\x00" in value:
        raise ValueError("must not contain NUL characters")
    return value


# Request text. PostgreSQL rejects NUL in text and jsonb values, so it is refused here with a 422.
# Passwords stay plain ``str``: they are only hashed or encrypted, never stored as text.
NoNul = AfterValidator(_no_nul)
# ``name: Str = Field(max_length=...)`` checks the field's own constraints first. Optional fields and
# item types put them before NoNul (``Annotated[str, Field(...), NoNul] | None``): constraints that
# follow a validator are checked outside the string, with vaguer messages and no OpenAPI pattern.
Str = Annotated[str, NoNul]

# List items are bounded like the columns they end up in (roles.name is String(64)).
RoleName = Annotated[str, Field(max_length=64), NoNul]
Permission = Annotated[str, Field(max_length=64), NoNul]
EnvKey = Annotated[str, Field(max_length=255), NoNul]
EnvValue = Annotated[str, Field(max_length=32768), NoNul]


class Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------------- auth


class LoginIn(BaseModel):
    email: Str = Field(max_length=320)
    password: str = Field(max_length=500)


class RegisterIn(BaseModel):
    email: EmailStr = Field(max_length=320)
    password: str = Field(max_length=500)
    full_name: Str = Field("", max_length=200)


class ProfileUpdate(BaseModel):
    full_name: Str = Field(max_length=200)


class PasswordChange(BaseModel):
    current_password: str | None = Field(None, max_length=500)
    new_password: str = Field(max_length=500)


# -------------------------------------------------------------------------- users


class UserOut(Out):
    id: uuid.UUID
    email: str
    full_name: str
    display_name: str
    avatar_url: str | None
    is_active: bool
    roles: list[str]
    permissions: list[str]
    github_login: str | None
    has_password: bool
    created_at: datetime
    last_login_at: datetime | None

    @classmethod
    def of(cls, user: User) -> UserOut:
        return cls(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            display_name=user.display_name,
            avatar_url=user.avatar_url,
            is_active=user.is_active,
            roles=user.role_names,
            permissions=sorted(user.permissions),
            github_login=user.github.login if user.github else None,
            has_password=user.password_hash is not None,
            created_at=user.created_at,
            last_login_at=user.last_login_at,
        )


class SessionOut(BaseModel):
    user: UserOut
    csrf_token: str


class UserCreate(BaseModel):
    email: EmailStr = Field(max_length=320)
    full_name: Str = Field("", max_length=200)
    password: str | None = Field(None, max_length=500)
    # Pre-link a GitHub account so the user can sign in with GitHub straight away.
    github_login: Annotated[str, Field(max_length=39, pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$"), NoNul] | None = None
    roles: list[RoleName] = Field(default_factory=lambda: ["viewer"], max_length=50)


class UserUpdate(BaseModel):
    full_name: Annotated[str, Field(max_length=200), NoNul] | None = None
    is_active: bool | None = None
    roles: list[RoleName] | None = Field(None, max_length=50)
    password: str | None = Field(None, max_length=500)


# -------------------------------------------------------------------------- roles


class RoleOut(Out):
    id: uuid.UUID
    name: str
    description: str
    permissions: list[str]
    is_system: bool


class RoleIn(BaseModel):
    name: Str = Field(pattern=r"^[a-z][a-z0-9_-]{1,63}$")
    description: Str = Field("", max_length=255)
    permissions: list[Permission] = Field(max_length=200)

    @field_validator("permissions")
    @classmethod
    def _perms(cls, v: list[str]) -> list[str]:
        return validate_permissions(v)


class RoleUpdate(BaseModel):
    description: Annotated[str, Field(max_length=255), NoNul] | None = None
    permissions: list[Permission] | None = Field(None, max_length=200)

    @field_validator("permissions")
    @classmethod
    def _perms(cls, v: list[str] | None) -> list[str] | None:
        return None if v is None else validate_permissions(v)


class PermissionOut(BaseModel):
    name: str
    description: str


# ------------------------------------------------------------------------- tokens


class TokenOut(Out):
    id: uuid.UUID
    name: str
    prefix: str
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None


class TokenCreate(BaseModel):
    name: Str = Field(min_length=1, max_length=100)
    expires_in_days: int | None = Field(None, ge=1, le=3650)


class TokenCreated(TokenOut):
    token: str


# -------------------------------------------------------------------------- hosts


class HostOut(Out):
    id: uuid.UUID
    name: str
    hostname: str
    port: int
    username: str
    label: str
    # The label's old name, kept as a copy for one release (phase 3 D21).
    environment: str = ""
    description: str
    deploy_root: str
    proxy_address: str | None = None
    lan_address: str | None = None
    provider: str = "ssh"
    provider_id: str | None = None
    owner_environment_id: uuid.UUID | None = None
    auth_method: str
    public_key: str | None
    host_key_fingerprint: str | None
    status: str
    last_checked_at: datetime | None
    last_error: str | None
    docker_version: str | None
    os_info: str | None
    metrics: dict[str, Any]
    os_type: str | None = None
    setup_status: str | None = None
    setup_step: str | None = None
    setup_error: str | None = None
    created_at: datetime
    # Phases 4 and 5 (Decision 33): the environment that made the host ({id, name, slot}), None for a host added
    # by hand; whether it is built (a droplet or VM not made yet isn't); what its provider recorded.
    owned_by: dict[str, Any] | None = None
    built: bool = True
    provider_state: dict[str, Any] = {}
    # Phase 5 (P5 §11): a VM Slipway made: {stage, account: {id, name, provider}}; None for any other host.
    machine: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _copy_label(self) -> HostOut:
        self.environment = self.label
        return self


class HostSetupOut(BaseModel):
    status: str | None
    step: str | None
    error: str | None
    log: str


_UNIX_USER = r"^[a-z_][a-z0-9_.-]*$"
AdminUser = Annotated[str, Field(min_length=1, max_length=64, pattern=_UNIX_USER), NoNul]
AdminPassword = Annotated[str, Field(min_length=1, max_length=500), NoNul]


class HostSetupIn(BaseModel):
    """The one-time admin login Slipway uses to prepare a new server. Never stored."""

    admin_username: AdminUser = "root"
    admin_password: AdminPassword


class _HostFields(BaseModel):
    hostname: Annotated[str, Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9.:\-\[\]]+$"), NoNul] | None = None
    port: int | None = Field(None, ge=1, le=65535)
    username: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z_][a-z0-9_.-]*$"), NoNul] | None = None
    label: Annotated[str, Field(max_length=32), NoNul] | None = None
    # The label's old name, still accepted for one release (phase 3 D21).
    environment: Annotated[str, Field(max_length=32), NoNul] | None = None
    description: Annotated[str, Field(max_length=255), NoNul] | None = None
    deploy_root: Annotated[str, Field(max_length=255), NoNul] | None = None
    # Address the reverse proxy uses for this host's ports; "" clears it (then the hostname is used).
    proxy_address: Annotated[str, Field(max_length=255, pattern=r"^$|^[A-Za-z0-9.\-]+$|^\[[0-9A-Fa-f:.]+\]$"), NoNul] | None = None
    # The address this host's connections to other LAN hosts come from, when it isn't the proxy address
    # (a multi-homed host): an IP literal, since a data server's allow list takes addresses. "" clears it.
    lan_address: Annotated[str, Field(max_length=45), NoNul] | None = None
    private_key: Annotated[str, Field(max_length=20000), NoNul] | None = None
    key_passphrase: str | None = Field(None, max_length=500)
    password: str | None = Field(None, max_length=500)

    @field_validator("lan_address")
    @classmethod
    def _lan_address(cls, v: str | None) -> str | None:
        if not v:
            return v
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError:
            raise ValueError("Enter an IP address, such as 10.0.0.12") from None

    @model_validator(mode="after")
    def _label_alias(self) -> _HostFields:
        if self.label is not None and self.environment is not None and self.label != self.environment:
            raise ValueError("Send label or environment (its old name), not both with different values")
        if self.label is None:
            self.label = self.environment
        return self

    @field_validator("deploy_root")
    @classmethod
    def _root(cls, v: str | None) -> str | None:
        return None if v is None else deployer.clean_deploy_root(v)

    @field_validator("hostname")
    @classmethod
    def _hostname(cls, v: str | None) -> str | None:
        if v is None or ":" in v or v.startswith("["):  # IPv6 literals are checked when connecting
            return v
        labels = v.rstrip(".").split(".")
        if not all(0 < len(label) <= 63 and not label.startswith("-") for label in labels):
            raise ValueError("Enter a valid hostname or IP address")
        return v


class HostCreate(_HostFields):
    name: Str = Field(pattern=_NAME_RE.pattern)
    hostname: Str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9.:\-\[\]]+$")
    username: Str = Field(min_length=1, max_length=64, pattern=r"^[a-z_][a-z0-9_.-]*$")
    port: int = Field(22, ge=1, le=65535)
    # "generate" asks Slipway to create an ed25519 key pair and show the public key.
    auth_method: Literal["generate", "key", "password"] = "generate"
    os_type: Literal["ubuntu"] = "ubuntu"
    # "existing": the SSH user and Docker are set up already. "new": Slipway signs in once with the admin
    # login below and sets the server up itself (user, its own generated key, Docker, deploy root).
    setup: Literal["existing", "new"] = "existing"
    admin_username: AdminUser | None = None
    admin_password: AdminPassword | None = None


class HostUpdate(_HostFields):
    name: Annotated[str, Field(pattern=_NAME_RE.pattern), NoNul] | None = None
    auth_method: Literal["generate", "key", "password"] | None = None


# --------------------------------------------------------------------------- repos


class RepoOut(Out):
    id: uuid.UUID
    github_id: int
    full_name: str
    owner: str
    name: str
    description: str
    visibility: str
    default_branch: str
    html_url: str
    language: str | None
    archived: bool
    pushed_at: datetime | None
    detected_config: dict[str, Any]
    deployable: bool
    default_branch_usable: bool
    synced_at: datetime | None

    @classmethod
    def of(cls, repo: Repository) -> RepoOut:
        return cls.model_validate(repo)


class SyncOut(BaseModel):
    created: int
    updated: int
    total: int


class RepoImportIn(BaseModel):
    """A GitHub repository anyone may read (or one your token can), by URL or ``owner/name``."""

    url: Annotated[str, Field(min_length=3, max_length=300), NoNul]


class ImageInfoOut(BaseModel):
    ref: str
    digest: str
    platform: str | None = None
    ports: list[dict[str, Any]] = []
    volumes: list[str] = []
    env: dict[str, str] = {}
    title: str | None = None
    description: str | None = None
    source: str | None = None
    page_url: str | None = None


# ----------------------------------------------------------------------- instances


class PortMapping(BaseModel):
    host: int = Field(ge=1, le=65535)
    container: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"


class PortOverride(BaseModel):
    """Compose mode: publish ``service``'s ``container`` port on host port ``host`` instead."""

    service: Str = Field(min_length=1, max_length=128, pattern=ports.SERVICE_RE.pattern)
    container: int = Field(ge=1, le=65535)
    host: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    auto: bool = False  # chosen by Slipway because the port was taken


class Route(BaseModel):
    """A hostname the reverse proxy sends to one of the instance's published ports."""

    hostname: Str = Field(min_length=1, max_length=253)
    service: Annotated[str, Field(max_length=128, pattern=r"^$|" + ports.SERVICE_RE.pattern), NoNul] | None = None
    container: int = Field(ge=1, le=65535)
    tls_mode: Literal["auto", "dns", "internal", "off"] = "auto"

    @field_validator("hostname")
    @classmethod
    def _hostname(cls, v: str) -> str:
        return switchyard.clean_hostname(v)

    @field_validator("service")
    @classmethod
    def _service(cls, v: str | None) -> str | None:
        return v or None


class VolumeMapping(BaseModel):
    source: Str = Field(min_length=1, max_length=255)
    target: Str = Field(min_length=1, max_length=255)

    @field_validator("source")
    @classmethod
    def _source(cls, v: str) -> str:
        v = v.strip()
        if ":" in v or not (v.startswith("/") or _VOLUME_NAME_RE.match(v)):
            raise ValueError("Volume source must be an absolute host path or a named volume")
        return v

    @field_validator("target")
    @classmethod
    def _target(cls, v: str) -> str:
        v = v.strip()
        if ":" in v or not v.startswith("/"):
            raise ValueError("Volume target must be an absolute path inside the container")
        return v


class FirstAdminIn(BaseModel):
    """The first admin an app's ``first_admin`` command creates: the manifest's fields, and a password or an
    invite. It is checked against the release's slipway.yml (§11.1). ``confirm`` (the instance's name) is
    needed only to set one on a live app that has none pending."""

    fields: dict[Annotated[str, Field(max_length=64), NoNul], Annotated[str, Field(max_length=1024), NoNul]] = Field(
        max_length=20)
    mode: Literal["password", "invite"]
    password: str | None = Field(None, max_length=1024)
    confirm: Annotated[str, Field(max_length=100), NoNul] | None = None


class _InstanceFields(BaseModel):
    branch: Annotated[str, Field(min_length=1, max_length=BRANCH_MAX, pattern=r"^[A-Za-z0-9._/-]+$"), NoNul] | None = None
    build_source: Literal["dockerfile", "compose", "app", "image"] | None = None
    # Image mode: a public container image (``nginx:1.27``, ``ghcr.io/owner/app:v1``, a hub.docker.com URL).
    image: Annotated[str, Field(max_length=500), NoNul] | None = None
    dockerfile_path: Annotated[str, Field(max_length=255), NoNul] | None = None
    build_context: Annotated[str, Field(max_length=255), NoNul] | None = None
    compose_file: Annotated[str, Field(max_length=255), NoNul] | None = None
    # App mode: the manifest in the repository, its settings' values and the optional services that run
    # (None leaves them as they are; on create, each optional service's default).
    manifest_file: Annotated[str, Field(max_length=255), NoNul] | None = None
    app_settings: dict[EnvKey, Annotated[str, Field(max_length=4096), NoNul]] | None = Field(None, max_length=100)
    app_services: list[Annotated[str, Field(max_length=63, pattern=manifest.SERVICE_RE.pattern)]] | None = Field(None, max_length=50)
    # The instance's own folder on the host; "" goes back to <host deploy root>/<slug>.
    deploy_dir: Annotated[str, Field(max_length=255), NoNul] | None = None
    env: dict[EnvKey, EnvValue] | None = Field(None, max_length=500)
    ports: list[PortMapping] | None = Field(None, max_length=100)
    volumes: list[VolumeMapping] | None = Field(None, max_length=100)
    auto_ports: bool | None = None
    port_overrides: list[PortOverride] | None = Field(None, max_length=100)
    routes: list[Route] | None = Field(None, max_length=20)
    # Data (app instances): how many automatic backups to keep, starter content on an empty first deploy,
    # and a snapshot the first deploy restores (needs data:reset, §10.7).
    keep_backups: int | None = Field(None, ge=1, le=100)
    seed_content: bool | None = None
    seed_snapshot_id: uuid.UUID | None = None

    @field_validator("routes")
    @classmethod
    def _one_route_per_hostname(cls, v: list[Route] | None) -> list[Route] | None:
        seen = set()
        for r in v or []:
            if r.hostname in seen:
                raise ValueError(f"{r.hostname} is listed twice")
            seen.add(r.hostname)
        return v

    @field_validator("deploy_dir")
    @classmethod
    def _deploy_dir(cls, v: str | None) -> str | None:
        return v if not v or not v.strip() else deployer.clean_instance_dir(v)

    @field_validator("port_overrides")
    @classmethod
    def _one_override_per_port(cls, v: list[PortOverride] | None) -> list[PortOverride] | None:
        seen = set()
        for o in v or []:
            key = (o.service, o.container, o.protocol)
            if key in seen:
                raise ValueError(f"Two port overrides for {o.service} container port {o.container}/{o.protocol}")
            seen.add(key)
        return v

    @field_validator("app_settings")
    @classmethod
    def _app_settings(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        return None if v is None else deployer.clean_env(v)

    @field_validator("app_services")
    @classmethod
    def _app_services(cls, v: list[str] | None) -> list[str] | None:
        return None if v is None else sorted(set(v))

    @field_validator("dockerfile_path", "compose_file", "manifest_file")
    @classmethod
    def _rel(cls, v: str | None) -> str | None:
        return None if v is None else deployer.clean_relative_path(v)

    @field_validator("manifest_file")
    @classmethod
    def _manifest_file(cls, v: str | None) -> str | None:
        return None if v is None else manifest.clean_manifest_file(v)

    @field_validator("build_context")
    @classmethod
    def _ctx(cls, v: str | None) -> str | None:
        return None if v is None else deployer.clean_relative_path(v, allow_dot=True)

    @field_validator("env")
    @classmethod
    def _env(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        return None if v is None else deployer.clean_env(v)

    @field_validator("image")
    @classmethod
    def _image(cls, v: str | None) -> str | None:
        if v is None:
            return None
        ref = registry.parse(v)
        registry.check_allowed(ref)
        return ref.label


class InstanceCreate(_InstanceFields):
    name: Str = Field(min_length=1, max_length=100)
    # A repository's code, or (build_source "image") a container image and no repository.
    repository_id: uuid.UUID | None = None
    host_id: uuid.UUID
    build_source: Literal["dockerfile", "compose", "app", "image"] = "dockerfile"
    deploy: bool = True
    first_admin: FirstAdminIn | None = None


class InstanceUpdate(_InstanceFields):
    name: Annotated[str, Field(min_length=1, max_length=100), NoNul] | None = None
    host_id: uuid.UUID | None = None
    # Erase the stored variables on purpose, including ones that can no longer be decrypted.
    # (An empty ``env`` never replaces variables that can't be decrypted.)
    clear_env: bool = False


class FirstAdminOut(BaseModel):
    """The first admin as stored: its fields and state, never the password."""

    fields: dict[str, Any]
    mode: str
    status: str
    existed: bool
    done_at: datetime | None
    last_error: str | None
    has_password: bool  # a password is stored (it is needed again after a key change, §6.7)

    @classmethod
    def of(cls, row: FirstAdmin) -> FirstAdminOut:
        return cls(fields=dict(row.fields or {}), mode=row.mode, status=row.status, existed=bool(row.existed),
                   done_at=row.done_at, last_error=row.last_error, has_password=row.password is not None)


def _folder(i: Instance) -> str:
    try:
        return deployer.instance_dir(i)
    except deployer.DeployError:
        return ""


class InstanceOut(Out):
    id: uuid.UUID
    name: str
    slug: str
    repository_id: uuid.UUID | None  # None for an instance of a container image
    repository: str  # the repository's owner/name, or the image
    image: str | None = None
    # None for a managed environment's data owner, which has no host (phase 4 §3.4).
    host_id: uuid.UUID | None
    host: str | None
    branch: str
    build_source: str
    dockerfile_path: str
    build_context: str
    compose_file: str
    manifest_file: str = manifest.DEFAULT_FILE
    app_settings: dict[str, str] = {}
    app_services: list[str] | None = None
    # Names of the secrets Slipway generated for the app (never their values).
    app_secret_keys: list[str] = []
    # What the last deploy read from slipway.yml and rendered: {manifest, routes, projects, ...}.
    app_state: dict[str, Any] | None = None
    env_keys: list[str]
    # Variables are stored but can't be decrypted with the configured SLIPWAY_ENCRYPTION_KEY.
    env_unreadable: bool = False
    ports: list[dict[str, Any]]
    volumes: list[dict[str, Any]]
    auto_ports: bool
    port_overrides: list[dict[str, Any]]
    # Host ports the last deployment published; ``declared`` is the port the compose file asked for.
    published_ports: list[dict[str, Any]]
    # The compose project name Slipway uses (a claimed project keeps its own).
    compose_project: str
    deploy_dir: str | None = None
    folder: str = ""  # where the instance's files are on the host
    routes: list[dict[str, Any]] = []
    proxy_entries: list[dict[str, Any]] = []
    # What the instance was claimed from, when it was claimed (see POST /hosts/{id}/claim).
    claim: dict[str, Any] | None = None
    status: str
    current_commit_sha: str | None
    last_deployed_at: datetime | None
    created_at: datetime
    # Data safety (app instances).
    keep_backups: int = 5
    seed_content: bool = True
    content_pending: bool = False
    seed_snapshot: dict[str, Any] | None = None  # {id, name, status}: the snapshot the first deploy restores
    first_admin: FirstAdminOut | None = None  # never the password
    # The first failed job that began changing the data, and whether Start, Restart and Deploy are held (§8.4).
    data_dirty: dict[str, Any] | None = None
    identity_changed_at: datetime | None = None
    identity_source: str | None = None
    # Phase 3: the environment this instance is a slot of ({id, name}), and which slot; None for standalone.
    environment: dict[str, Any] | None = None
    slot: str | None = None

    @classmethod
    def of(cls, i: Instance, *, env_unreadable: bool = False, seed_snapshot: Snapshot | None = None,
           first_admin: FirstAdmin | None = None) -> InstanceOut:
        """``env_unreadable``, the seed snapshot and the first admin need queries (see ``instance_out``), so
        callers pass them."""
        return cls(
            id=i.id,
            name=i.name,
            slug=i.slug,
            repository_id=i.repository_id,
            repository=i.source_name,
            image=i.image,
            host_id=i.host_id,
            host=i.host.name if i.host is not None else None,
            branch=i.branch,
            build_source=i.build_source,
            dockerfile_path=i.dockerfile_path,
            build_context=i.build_context,
            compose_file=i.compose_file,
            manifest_file=i.manifest_file or manifest.DEFAULT_FILE,
            app_settings=i.app_settings or {},
            app_services=i.app_services,
            app_secret_keys=sorted((i.app_secrets or {}).keys()) if i.build_source == "app" else [],
            app_state=i.app_state,
            env_keys=sorted((i.env or {}).keys()),
            env_unreadable=env_unreadable,
            ports=i.ports,
            volumes=i.volumes,
            auto_ports=i.auto_ports,
            port_overrides=i.port_overrides or [],
            published_ports=i.published_ports or [],
            compose_project=i.compose_project,
            deploy_dir=i.deploy_dir,
            folder=_folder(i),
            routes=i.routes or [],
            proxy_entries=i.proxy_entries or [],
            claim=i.claim,
            status=i.status,
            current_commit_sha=i.current_commit_sha,
            last_deployed_at=i.last_deployed_at,
            created_at=i.created_at,
            keep_backups=i.keep_backups if i.keep_backups is not None else 5,
            seed_content=True if i.seed_content is None else i.seed_content,
            content_pending=bool(i.content_pending),
            seed_snapshot=({"id": seed_snapshot.id, "name": seed_snapshot.name, "status": seed_snapshot.status}
                           if seed_snapshot is not None else None),
            first_admin=FirstAdminOut.of(first_admin) if first_admin is not None else None,
            data_dirty=i.data_dirty or None,
            identity_changed_at=i.identity_changed_at,
            identity_source=i.identity_source,
            environment=_environment_ref(i),
            slot=i.slot,
        )


def _environment_ref(i: Instance) -> dict[str, Any] | None:
    env = data.loaded_environment(i) if i.environment_id is not None else None
    if env is None:
        return {"id": i.environment_id, "name": None} if i.environment_id is not None else None
    return {"id": env.id, "name": env.name}


async def instance_outs(db: AsyncSession, instances: list[Instance], *,
                        unreadable: set[uuid.UUID] | None = None) -> list[InstanceOut]:
    """``InstanceOut`` for many instances, with their seed snapshots and first admins in two queries."""
    ids = [i.id for i in instances]
    seeds = {i.seed_snapshot_id for i in instances if i.seed_snapshot_id is not None}
    snaps: dict[uuid.UUID, Snapshot] = {}
    if seeds:
        snaps = {s.id: s for s in (await db.scalars(select(Snapshot).where(Snapshot.id.in_(seeds)))).all()}
    admins: dict[uuid.UUID, FirstAdmin] = {}
    if ids:
        admins = {a.instance_id: a for a in (await db.scalars(select(FirstAdmin).where(FirstAdmin.instance_id.in_(ids)))).all()}
    unreadable = unreadable or set()
    return [InstanceOut.of(i, env_unreadable=i.id in unreadable,
                           seed_snapshot=snaps.get(i.seed_snapshot_id) if i.seed_snapshot_id else None,
                           first_admin=admins.get(i.id)) for i in instances]


class ClaimGroup(BaseModel):
    """Which unmanaged group to claim, as ``GET /hosts/{id}/unmanaged`` returned it (other fields are ignored)."""

    kind: Literal["compose", "container"]
    project: Annotated[str, Field(max_length=255), NoNul] | None = None
    container_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$"), NoNul] | None = None


class ClaimIn(BaseModel):
    """Claim an unmanaged compose project or container as an instance.

    Build settings default to what the group suggests: compose mode for a compose project (keeping
    its project name), Dockerfile mode with the container's ports and volumes otherwise.
    """

    group: ClaimGroup
    repository_id: uuid.UUID
    name: Str = Field(min_length=1, max_length=100)
    branch: Annotated[str, Field(min_length=1, max_length=BRANCH_MAX, pattern=r"^[A-Za-z0-9._/-]+$"), NoNul] | None = None
    build_source: Literal["dockerfile", "compose"] | None = None
    dockerfile_path: Annotated[str, Field(max_length=255), NoNul] | None = None
    build_context: Annotated[str, Field(max_length=255), NoNul] | None = None
    compose_file: Annotated[str, Field(max_length=255), NoNul] | None = None
    # The instance's own folder on the host; default <host deploy root>/<slug>.
    deploy_dir: Annotated[str, Field(max_length=255), NoNul] | None = None
    ports: list[PortMapping] | None = Field(None, max_length=100)  # Dockerfile mode; default: the container's
    volumes: list[VolumeMapping] | None = Field(None, max_length=100)  # Dockerfile mode; default: the container's
    auto_ports: bool | None = None
    # Copy the containers' environment variables (minus the image's own) into the instance. They
    # usually include secrets, so this is off unless asked for.
    import_env: bool = False
    # False: register only. The instance points at what runs now; nothing on the host changes.
    deploy: bool = True

    @field_validator("dockerfile_path", "compose_file")
    @classmethod
    def _rel(cls, v: str | None) -> str | None:
        return None if v is None else deployer.clean_relative_path(v)

    @field_validator("build_context")
    @classmethod
    def _ctx(cls, v: str | None) -> str | None:
        return None if v is None else deployer.clean_relative_path(v, allow_dot=True)

    @field_validator("deploy_dir")
    @classmethod
    def _claim_deploy_dir(cls, v: str | None) -> str | None:
        return None if not v or not v.strip() else deployer.clean_instance_dir(v)


class ClaimOut(InstanceOut):
    deployment_id: uuid.UUID | None = None
    env_imported: list[str] = Field(default_factory=list)  # names only, never values
    env_skipped: list[str] = Field(default_factory=list)  # containers disagree on the value, or it is unusable
    env_files_read: list[str] = Field(default_factory=list)  # the project's env files that were imported
    env_files_missing: list[str] = Field(default_factory=list)
    env_files_unreadable: list[str] = Field(default_factory=list)
    warning: str | None = None


class ActionOut(BaseModel):
    ok: bool
    output: str = ""


# --------------------------------------------------------------------- deployments


# Options of a job the API shows. Every option is a plain flag or id (none is secret); ``confirm`` is never
# stored, and is left out here in case an older row carries it.
_HIDDEN_OPTIONS = frozenset({"confirm"})


def _backup_ref(row: Backup | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {"id": row.id, "name": row.name, "taken_at": row.taken_at, "status": row.status}


def _switch_summary(record: Any) -> Any:
    """``options.switch`` as the API shows it (phase 3 §11): where traffic went from and to, the hostnames
    created, changed and deleted, and whether Switchyard applied it. The bodies Slipway read first stay out."""
    if not isinstance(record, dict):
        return record

    def names(key: str) -> list[str]:
        return [str(e.get("hostname")) for e in record.get(key) or [] if isinstance(e, dict) and e.get("hostname")]

    return {"backend": record.get("backend"), "from_slot": record.get("from_slot"), "to_slot": record.get("to_slot"),
            "created": names("created"), "changed": names("changed"), "deleted": names("deleted"),
            "applied": bool(record.get("applied"))}


def _options_out(options: dict[str, Any] | None) -> dict[str, Any]:
    out = {k: v for k, v in (options or {}).items() if k not in _HIDDEN_OPTIONS}
    if "switch" in out:
        out["switch"] = _switch_summary(out["switch"])
    return out


class DeploymentOut(BaseModel):
    id: uuid.UUID
    # None for a job of a whole environment (activate, publish, discard, remove_slot, teardown).
    instance_id: uuid.UUID | None
    instance_name: str | None
    # The environment the job belongs to ({id, name}), and the slot it ran on or is about.
    environment: dict[str, Any] | None = None
    slot: str | None = None
    status: str
    branch: str
    commit_sha: str | None
    commit_message: str | None
    commit_author: str | None
    triggered_by: str | None
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    created_at: datetime
    # [{key, name, status, started_at?, finished_at?, offset?, note?}]
    steps: list[dict[str, Any]] = []
    retry_of_id: uuid.UUID | None = None
    # What the job does (deploy, restore, rollback, reset, backup, snapshot, admin, content) and with what.
    kind: str = "deploy"
    previous_sha: str | None = None  # the instance's live commit when the job was queued
    options: dict[str, Any] = {}
    backup: dict[str, Any] | None = None  # {id, name, taken_at, status}: the backup taken (or kept) first
    restore_backup: dict[str, Any] | None = None  # the backup a restore or roll back puts back
    snapshot: dict[str, Any] | None = None  # {id, name, status}: the snapshot restored or taken

    @classmethod
    def of(cls, d: Deployment, *, backups: dict[uuid.UUID, Backup] | None = None,
           snapshots: dict[uuid.UUID, Snapshot] | None = None) -> DeploymentOut:
        """``backups`` and ``snapshots`` hold the rows the job points at (see ``deployment_outs``); without
        them the references are left out."""
        backups, snapshots = backups or {}, snapshots or {}
        snap = snapshots.get(d.snapshot_id) if d.snapshot_id else None
        instance = d.instance if d.instance_id is not None else None
        env = d.environment if d.environment_id is not None else None
        slot = (instance.slot if instance is not None else None) or (d.options or {}).get("slot")
        return cls(
            id=d.id,
            instance_id=d.instance_id,
            instance_name=instance.name if instance is not None else None,
            environment={"id": env.id, "name": env.name} if env is not None else None,
            slot=str(slot) if slot else None,
            status=d.status,
            branch=d.branch,
            commit_sha=d.commit_sha,
            commit_message=d.commit_message,
            commit_author=d.commit_author,
            triggered_by=d.triggered_by.display_name if d.triggered_by else None,
            started_at=d.started_at,
            finished_at=d.finished_at,
            error=d.error,
            created_at=d.created_at,
            steps=d.steps or [],
            retry_of_id=d.retry_of_id,
            kind=d.kind or "deploy",
            previous_sha=d.previous_sha,
            options=_options_out(d.options),
            backup=_backup_ref(backups.get(d.backup_id)) if d.backup_id else None,
            restore_backup=_backup_ref(backups.get(d.restore_backup_id)) if d.restore_backup_id else None,
            snapshot={"id": snap.id, "name": snap.name, "status": snap.status} if snap is not None else None,
        )


async def deployment_outs(db: AsyncSession, deps: list[Deployment]) -> list[DeploymentOut]:
    """``DeploymentOut`` for many jobs, with the backups and snapshots they point at in two queries."""
    bids = {b for d in deps for b in (d.backup_id, d.restore_backup_id) if b is not None}
    sids = {d.snapshot_id for d in deps if d.snapshot_id is not None}
    backups: dict[uuid.UUID, Backup] = {}
    snapshots: dict[uuid.UUID, Snapshot] = {}
    if bids:
        backups = {b.id: b for b in (await db.scalars(select(Backup).where(Backup.id.in_(bids)))).all()}
    if sids:
        snapshots = {s.id: s for s in (await db.scalars(select(Snapshot).where(Snapshot.id.in_(sids)))).all()}
    return [DeploymentOut.of(d, backups=backups, snapshots=snapshots) for d in deps]


async def deployment_out(db: AsyncSession, dep: Deployment) -> DeploymentOut:
    return (await deployment_outs(db, [dep]))[0]


class DeploymentDetail(DeploymentOut):
    log: str
    log_offset: int
    # What the deployment page offers (data.job_actions): {retry: {available, reason, needs_confirm,
    # offers_skip_backup, ...}, rollback: {available, reason, also_undoes, ...}, undo: {available, backup_id, files}}
    actions: dict[str, Any] = {}


# Typed confirmation (§13): the instance's name, exactly. Checked by the endpoint before anything else.
Confirm = Annotated[str, Field(max_length=100), NoNul]


class DeployIn(BaseModel):
    """Optional flags of ``POST /instances/{id}/deploy``; each needs its permission and the typed name."""

    override_hold: bool = False  # data:reset
    take_over_lock: bool = False  # data:reset
    skip_revision_check: bool = False  # data:restore
    confirm: Confirm | None = None


class ControlIn(BaseModel):
    override_hold: bool = False  # data:reset and the typed name: start or restart while a data hold stands
    confirm: Confirm | None = None


class RetryIn(BaseModel):
    confirm: Confirm | None = None
    skip_backup: bool = False  # data:reset: only for a job whose backup failed
    take_over_lock: bool = False  # data:reset
    # A teardown's retry forgets the Switchyard hosts and DNS records it can't delete (the typed name).
    forget_traffic: bool = False
    # Phases 4 and 5 (P4 §16, P5 §11): asked again on every retry, never copied from the job retried.
    confirm_production: Confirm | None = None  # a production teardown: "delete production <name>"
    confirm_no_snapshot: Confirm | None = None  # ... when it went without a snapshot
    rebuild_data: bool = False  # make a gone cluster or bucket again, empty (data:reset, the typed name)
    drop_data: bool = False  # a teardown whose data's only home goes with it (data:reset)
    forget_vms: bool = False  # Remove slot or teardown: forgettable VM blockers pass (machines:write, the name)


class ConfirmIn(BaseModel):
    confirm: Confirm | None = None


# --------------------------------------------------------------------------- data


class BackupCreate(BaseModel):
    files: bool = False  # include the app's files (slipway.yml export_files)
    note: Annotated[str, Field(max_length=200), NoNul] | None = None


class RestoreIn(BaseModel):
    backup_id: uuid.UUID
    confirm: Confirm | None = None
    files: bool = False  # put the files back too
    restore_identity: bool = False  # put back the identity keys the backup was made with (data:reset)


class ResetIn(BaseModel):
    confirm: Confirm | None = None
    snapshot_id: uuid.UUID | None = None  # start from this snapshot instead of empty
    seed: bool | None = None  # add starter content after an empty start (default: the instance's setting)
    first_admin: FirstAdminIn | None = None


class SnapshotTake(BaseModel):
    name: Annotated[str, Field(max_length=64), NoNul]
    notes: Annotated[str, Field(max_length=2000), NoNul] | None = None
    stop_app: bool = False  # stop the app while copying (instances:operate)


class SnapshotUpdate(BaseModel):
    name: Annotated[str, Field(max_length=64), NoNul] | None = None
    notes: Annotated[str, Field(max_length=2000), NoNul] | None = None


class PassphraseIn(BaseModel):
    # Checked by snapfile (12-1024 characters, no control characters); never stored, logged or audited.
    passphrase: str = Field(max_length=1024)


class BackupOut(BaseModel):
    id: uuid.UUID
    name: str
    reason: str
    status: str
    taken_at: datetime
    db_bytes: int | None
    has_files: bool
    files_bytes: int | None
    format: str
    revision_short: str | None
    commit_sha: str | None
    release: str | None
    deployment_id: uuid.UUID | None
    dirty_of: uuid.UUID | None
    created_by: str | None
    note: str | None
    checked_at: datetime | None
    pinned: bool
    pinned_reason: str | None
    restorable: bool
    reason_text: str | None  # why it can't be restored (shown instead of the Restore button)
    identity_note: str | None
    needs_reset_perm: bool  # restoring it puts back other identity keys: data:reset
    dirty_note: str | None = None
    location: str = "host"  # host (the instance's backups folder) or slipway (Slipway's storage, P4 §10.5)

    @classmethod
    def of(cls, view: data.BackupView, *, created_by: str | None = None, note: str | None = None) -> BackupOut:
        row = view.row
        return cls(
            id=row.id, name=row.name, reason=row.reason, status=row.status, taken_at=row.taken_at,
            db_bytes=row.db_bytes, has_files=bool(row.has_files), files_bytes=row.files_bytes, format=row.format,
            revision_short=view.revision_short, commit_sha=row.commit_sha, release=row.release,
            deployment_id=row.deployment_id, dirty_of=row.dirty_of, created_by=created_by,
            note=row.note if row.note is not None else note, checked_at=row.checked_at, pinned=view.pinned,
            pinned_reason=view.pinned_reason, restorable=view.restorable, reason_text=view.reason_text,
            identity_note=view.identity_note, needs_reset_perm=view.needs_reset_perm, dirty_note=view.dirty_note,
            location=str(row.location or "host"),
        )


class SnapshotOut(BaseModel):
    """A stored snapshot: what it holds and where it came from, never its key material."""

    id: uuid.UUID
    name: str
    notes: str
    status: str
    origin: str
    app: str | None
    app_name: str | None
    repository: str | None
    source: str | None
    source_instance_id: uuid.UUID | None
    commit_sha: str | None
    source_created_at: datetime | None
    db_format: str | None
    db_revision: str | None
    revision_short: str | None
    db_bytes: int | None
    db_sha256: str | None
    has_files: bool
    files_format: str | None
    files_bytes: int | None
    files_sha256: str | None
    identity_keys: list[str]  # names only
    expires_at: datetime | None  # a locked import is deleted after this
    file_bytes: int | None
    file_sha256: str | None
    deployment_id: uuid.UUID | None
    created_by_id: uuid.UUID | None
    error: str | None
    created_at: datetime
    # Only with ``?instance_id=``: seeding that instance from it needs snapshots:download (another repository).
    seeding_needs_download: bool | None = None

    @classmethod
    def of(cls, s: Snapshot, *, seeding_needs_download: bool | None = None) -> SnapshotOut:
        return cls(
            id=s.id, name=s.name, notes=s.notes or "", status=s.status, origin=s.origin, app=s.app,
            app_name=s.app_name, repository=s.repository, source=s.source, source_instance_id=s.source_instance_id,
            commit_sha=s.commit_sha, source_created_at=s.source_created_at, db_format=s.db_format,
            db_revision=s.db_revision, revision_short=data.revision_short(s.db_revision), db_bytes=s.db_bytes,
            db_sha256=s.db_sha256, has_files=s.files_format is not None or s.files_bytes is not None,
            files_format=s.files_format, files_bytes=s.files_bytes, files_sha256=s.files_sha256,
            identity_keys=list(s.identity_keys or []), expires_at=s.expires_at, file_bytes=s.file_bytes,
            file_sha256=s.file_sha256, deployment_id=s.deployment_id, created_by_id=s.created_by_id, error=s.error,
            created_at=s.created_at, seeding_needs_download=seeding_needs_download,
        )


def seeding_needs_download(snapshot: Snapshot, repository: str | None) -> bool:
    """Seeding an instance of ``repository`` from ``snapshot`` needs snapshots:download (D16): the snapshot is
    of another repository, or of one nobody recorded."""
    return not snapshot.repository or snapshot.repository != repository


# --------------------------------------------------------------------- environments (phase 3 §11)

# An environment's name is checked by environments.validate_create (2-26 characters, §2), which answers with
# {detail, field}; the schema only bounds it, so a long name gets that answer and not a schema error.
EnvName = Annotated[str, Field(max_length=100), NoNul]
SlotKey = Literal["blue", "green", "data"]
TlsMode = Literal["auto", "dns", "internal", "off"]


class DnsIn(BaseModel):
    """``traffic.dns``: publish an A record for every name, at ``address`` (default: Cloudflare's public IP)."""

    address: Annotated[str, Field(max_length=45), NoNul] | None = None
    proxied: bool | None = None  # default: the Cloudflare integration's


class TrafficIn(BaseModel):
    # ``do_lb``: a DigitalOcean environment's load balancer, only with placement digitalocean (phase 4 §3.2).
    switch: Literal["none", "switchyard", "do_lb"] = "none"
    dns: DnsIn | None = None
    # Turning DNS off: forget, without deleting, the records whose Cloudflare zone is gone (deleted and added
    # again, or moved to another account), since there is nothing left there to delete.
    forget_lost_zone: bool = False


class _EnvironmentFields(BaseModel):
    settings: dict[EnvKey, Annotated[str, Field(max_length=4096), NoNul]] | None = Field(None, max_length=100)
    services: list[Annotated[str, Field(max_length=63, pattern=manifest.SERVICE_RE.pattern)]] | None = Field(
        None, max_length=50)
    env: dict[EnvKey, EnvValue] | None = Field(None, max_length=500)
    route_tls: dict[Annotated[str, Field(max_length=253), NoNul], TlsMode] | None = Field(None, max_length=50)
    auto_activate: bool | None = None
    traffic: TrafficIn | None = None
    keep_backups: int | None = None  # 1-100, checked with the environment's own message
    seed_content: bool | None = None

    @field_validator("settings", "env")
    @classmethod
    def _clean(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        return None if v is None else deployer.clean_env(v)

    @field_validator("services")
    @classmethod
    def _services(cls, v: list[str] | None) -> list[str] | None:
        return None if v is None else sorted(set(v))

    @field_validator("route_tls")
    @classmethod
    def _route_tls(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        return None if v is None else {switchyard.clean_hostname(k): m for k, m in v.items()}


# Phase 4 (§15.1) and phase 5 (§9.2): where the environment runs. One create body serves both (Decision 24).
DoSize = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$")]
CostFigure = Annotated[str, Field(max_length=20), NoNul]  # the monthly total as shown, "84.00" (§12.2)


class PlacementIn(BaseModel):
    """``placement`` of a DigitalOcean environment (P4 §15.1). ``region`` defaults to the account's; ``slots`` is
    1 (blue) or 2 (Blue/Green)."""

    provider: Literal["digitalocean"]
    account_id: uuid.UUID
    region: Annotated[str, Field(max_length=8, pattern=r"^[a-z]{3}[0-9]$")] | None = None
    droplet_size: DoSize
    db_size: DoSize
    db_standby: bool = False
    acme_staging: bool = False
    slots: Literal[1, 2] = 1


class MachineSpecIn(BaseModel):
    """A new VM (P5 §9.2): one of the account's networks, a typed IPv4 address or ``auto``, and its size."""

    account_id: uuid.UUID
    network: Annotated[str, Field(min_length=1, max_length=40), NoNul]
    address: Annotated[str, Field(max_length=15), NoNul] | None = "auto"
    cores: int | None = None
    memory_mb: int | None = None
    disk_gb: int | None = None

    def size(self) -> dict[str, int]:
        return {k: v for k, v in (("cores", self.cores), ("memory_mb", self.memory_mb), ("disk_gb", self.disk_gb))
                if v is not None}


class MachineIn(BaseModel):
    """``hosts.<slot> = {machine: …}``: a VM Slipway makes for the slot."""

    machine: MachineSpecIn


class EnvironmentCreate(_EnvironmentFields):
    name: EnvName
    repository_id: uuid.UUID
    branch: Annotated[str, Field(min_length=1, max_length=BRANCH_MAX, pattern=r"^[A-Za-z0-9._/-]+$"), NoNul] | None = None
    manifest_file: Annotated[str, Field(max_length=255), NoNul] | None = None
    # ``managed`` is forced with placement digitalocean (P4 D21).
    data_mode: Literal["slot", "server", "managed"]
    # A host id (P3), or a new VM (P5 §9.2). Left out with placement digitalocean: the droplets are made.
    hosts: dict[SlotKey, uuid.UUID | MachineIn] = {}
    seed_snapshot_id: uuid.UUID | None = None
    first_admin: FirstAdminIn | None = None
    placement: PlacementIn | None = None
    production: bool = False
    confirm_cost: CostFigure | None = None


class CloudSizesIn(BaseModel):
    """A DigitalOcean environment's sizes, grown by PATCH (P4 §15.7): sizes only grow, a standby is only added."""

    droplet_size: DoSize | None = None
    db_size: DoSize | None = None
    db_standby: bool | None = None


class EnvironmentUpdate(_EnvironmentFields):
    """PATCH: only the fields sent change. Each slot uses them from its next deploy. ``cloud`` grows a
    DigitalOcean environment's sizes and needs ``confirm_cost`` (``environments.grow_plan``)."""

    cloud: CloudSizesIn | None = None
    confirm_cost: CostFigure | None = None


class EnvDeployIn(BaseModel):
    """``POST /environments/{id}/deploy``: the idle slot by default, or the data server (``target: data``)."""

    target: Literal["slot", "data"] = "slot"
    slot: Literal["blue", "green"] | None = None
    # The deploy goes ahead although the active slot's release is behind the database (§7.6).
    acknowledge_schema: bool = False
    # Deploy again, confirming: the commit the refused deploy was of, so the acknowledgement covers that release
    # and not whatever the branch moved on to. Only a commit a deploy of that slot was already of.
    commit_sha: str | None = Field(None, pattern=r"^[0-9a-f]{40}$")


class SlotIn(BaseModel):
    slot: Literal["blue", "green"]


class ActivateIn(SlotIn):
    """Activate and Switch back: a production environment's name typed (P4 §13, Decision 39)."""

    confirm: Confirm | None = None


class RetireIn(BaseModel):
    """Retire and un-retire a production environment (P4 §13): its name typed."""

    confirm: Confirm | None = None


class SlotAdd(BaseModel):
    """Add the second app slot (Decision 25). On SSH placement exactly one of ``host_id`` and ``machine`` (P5
    §9.5); on DigitalOcean neither, and ``confirm_cost`` the new monthly total (P4 §15.5)."""

    host_id: uuid.UUID | None = None
    machine: MachineSpecIn | None = None
    confirm_cost: CostFigure | None = None
    update_data_server: bool = False  # queue an update of the data server so it lets the new host in


class HostnameIn(BaseModel):
    hostname: Annotated[str, Field(min_length=1, max_length=253), NoNul]

    @field_validator("hostname")
    @classmethod
    def _hostname(cls, v: str) -> str:
        return switchyard.clean_hostname(v)


class SnapshotFirst(BaseModel):
    name: Annotated[str, Field(max_length=64), NoNul]
    notes: Annotated[str, Field(max_length=2000), NoNul] | None = None


class EnvironmentDelete(BaseModel):
    """One body for both phases (P4 §15.10, P5 §9.9); the rules are ``environments.delete_problem``."""

    confirm: Confirm | None = None
    snapshot: SnapshotFirst | None = None  # take a snapshot of the data first (data:backup)
    # Delete without a snapshot although the data's only home (a managed cluster, a data VM) goes (data:reset).
    drop_data: bool = False
    confirm_production: Confirm | None = None  # "delete production <name>"
    confirm_no_snapshot: Confirm | None = None  # "delete production <name> without a snapshot"
    forget_vms: bool = False  # forgettable VM blockers pass (machines:write, environments:delete)


class RemoveSlotIn(BaseModel):
    """Remove a slot (P3 §9.9, P5 §9.5, Decision 44): the environment's name typed; ``forget_vms`` lets the slot's
    forgettable VM blockers pass (machines:write and environments:delete)."""

    confirm: Confirm | None = None
    forget_vms: bool = False


class MachineResizeIn(BaseModel):
    """``PATCH /environments/{id}/machines/{slot}`` (P5 §9.4): the VM's wanted size and how many automatic VM
    snapshots it keeps. Stored only; the slot's next deploy applies it. ``environments.resize_plan`` checks it."""

    cores: int | None = None
    memory_mb: int | None = None
    disk_gb: int | None = None
    keep_vm_snapshots: int | None = None


class VmSnapshotIn(BaseModel):
    """Take a VM snapshot (P5 §9.6)."""

    note: Annotated[str, Field(max_length=300), NoNul] | None = None


class VmRevertIn(BaseModel):
    """Revert to a VM snapshot (P5 §9.7): the environment's name typed; ``skip_pre_revert`` takes no snapshot of
    the VM as it is first (ZFS never takes one)."""

    confirm: Confirm | None = None
    skip_pre_revert: bool = False


class MachineStateOut(BaseModel):
    """What the hypervisor shows of a VM now (``machines.MachineState``), read for a page. ``error`` is ``busy``
    when the account's page reads are all taken, else why the account couldn't be read; ``detail`` says it in
    a sentence."""

    exists: bool | None = None
    ours: bool | None = None
    why_not_ours: str | None = None
    hidden: bool = False
    lost: bool = False  # ready, and gone from the hypervisor (Forget the VM, P5 §9.10)
    power: str | None = None
    busy: str | None = None
    addresses: list[str] = []
    applied: dict[str, Any] | None = None
    snapshot_mode: str | None = None
    error: str | None = None
    detail: str | None = None


class MachineBlockerOut(BaseModel):
    """One reason the VM can't be removed now (``vmtypes.Blocker``): ``forgettable`` when ``forget_vms`` gets
    past it."""

    text: str
    forgettable: bool


class MachineOut(BaseModel):
    """A VM Slipway made for an environment's slot (P5 §11). ``applies_at`` says when a pending resize is
    applied: ``next deploy``, ``when idle`` (the active slot of two) or ``never (data server)``.

    ``blockers`` and ``forgettable`` are read only for ``GET .../machines?blockers=true`` (None otherwise, or
    when the read didn't answer in time): what stops Remove slot and Delete removing the VM now, as their check
    reads it (``machines.blockers``), and whether ``forget_vms`` gets past all of it (False when nothing blocks
    the removal, or a blocker isn't forgettable)."""

    slot: str
    name: str
    account: dict[str, Any]  # {id, name, provider}
    network: str | None
    address: str | None
    stage: str
    size: dict[str, Any]
    applied: dict[str, Any] | None = None
    pending_resize: bool = False
    applies_at: Literal["next deploy", "when idle", "never (data server)"] | None = None
    keep_vm_snapshots: int
    snapshot_mode: str | None = None
    last_task: dict[str, Any] | None = None
    ready_at: datetime | None = None
    last_error: str | None = None
    host_id: uuid.UUID
    live: MachineStateOut | None = None
    note: str | None = None  # Forget the VM: what Slipway did
    blockers: list[MachineBlockerOut] | None = None
    forgettable: bool | None = None

    @classmethod
    def of(cls, machine: Any, *, active: bool = False, live: MachineStateOut | None = None,
           note: str | None = None, blockers: list[Any] | None = None) -> MachineOut:
        """``active``: the slot takes the traffic in an environment of two app slots."""
        from slipway.services import machines

        network = dict(machine.network or {})
        account = machine.account
        pending = machine.stage == "ready" and machines.size_differs(machine)
        applies_at = None
        if pending:
            applies_at = "never (data server)" if machine.slot == "data" else "when idle" if active else "next deploy"
        return cls(
            slot=machine.slot, name=machine.name,
            account={"id": account.id, "name": account.name, "provider": account.provider} if account is not None
            else {"id": machine.account_id, "name": None, "provider": machine.provider},
            network=network.get("name"), address=network.get("address"), stage=machine.stage,
            size=dict(machine.size or {}), applied=dict(machine.applied) if machine.applied else None,
            pending_resize=pending, applies_at=applies_at, keep_vm_snapshots=machine.keep_vm_snapshots,
            snapshot_mode=machine.snapshot_mode, last_task=machine.last_task, ready_at=machine.ready_at,
            last_error=machine.last_error, host_id=machine.host_id, live=live, note=note,
            blockers=None if blockers is None else [MachineBlockerOut(text=str(b.text), forgettable=bool(b.forgettable))
                                                    for b in blockers],
            forgettable=None if blockers is None else bool(blockers) and all(b.forgettable for b in blockers),
        )


class VmSnapshotOut(BaseModel):
    """A VM snapshot Slipway recorded, joined with the hypervisor's list (P5 §11). ``on_hypervisor`` is None
    when the hypervisor couldn't be read; ``backups_after`` are the data's backups taken after it, which a
    revert loses."""

    id: uuid.UUID
    name: str
    reason: str
    status: str
    taken_at: datetime
    commit_sha: str | None = None
    note: str | None = None
    quiesced: bool | None = None
    sizes: dict[str, Any] = {}
    on_hypervisor: bool | None = None
    newest: bool = False
    revert: dict[str, Any] = {}  # {available, reason}
    drop: dict[str, Any] = {}  # {available, reason}
    backups_after: list[str] = []


class VmSnapshotsOut(BaseModel):
    """``GET /environments/{id}/vm-snapshots``: the VM the snapshots are of (the environment's one app slot), its
    snapshot mode, the live read's error (``busy`` or why the account couldn't be read, with ``detail``), whether
    a new one can be taken, and the snapshots, newest first."""

    slot: str | None = None
    vm: str | None = None
    snapshot_mode: str | None = None
    error: str | None = None
    detail: str | None = None
    take: dict[str, Any] = {}  # {available, reason}
    snapshots: list[VmSnapshotOut] = []


class SlotHost(BaseModel):
    id: uuid.UUID
    name: str
    address: str
    upstream_address: str
    lan_address: str | None = None


class SlotOut(BaseModel):
    slot: str
    instance_id: uuid.UUID
    role: Literal["app", "data"]
    host: SlotHost | None  # None for a managed environment's data owner (phase 4 §3.4)
    status: str
    active: bool
    # {sha, deployed_at, release, settings_differ}: what runs now, and whether the environment's settings
    # changed since (they reach the slot with its next deploy).
    live: dict[str, Any] | None = None
    last_check: dict[str, Any] | None = None
    stale: dict[str, Any] | None = None
    ports: list[dict[str, Any]] = []
    # "Resize pending: applies at <slot>'s next deploy" (Decision 33), set by the environment's answer.
    resize_pending: str | None = None

    @classmethod
    def of(cls, env: Any, i: Instance, *, resize_pending: str | None = None) -> SlotOut:
        live = data.live_state(i)
        live_out = None
        if live is not None or i.current_commit_sha:
            live = live or {}
            settings = {str(k): str(v) for k, v in (live.get("settings") or {}).items()}
            wanted = {str(k): str(v) for k, v in (env.app_settings or {}).items()}
            live_out = {"sha": live.get("sha") or i.current_commit_sha, "deployed_at": i.last_deployed_at,
                        "release": live.get("release"), "settings_differ": bool(live) and settings != wanted}
        state = i.slot_state or {}
        ports = [{"service": p.get("service") or "", "container": p.get("container"), "host": p.get("host")}
                 for p in i.published_ports or []]
        named = {p["service"] for p in ports}
        for name, port in ((live or {}).get("host_ports") or {}).items() if i.slot == "data" else ():
            if name not in named:
                ports.append({"service": str(name), "container": None, "host": port})
        h = i.host
        return cls(slot=str(i.slot), instance_id=i.id, role="data" if i.slot == "data" else "app",
                   host=SlotHost(id=h.id, name=h.name, address=h.address, upstream_address=h.upstream_address,
                                 lan_address=h.lan_address) if h is not None else None,
                   status=i.status, active=env.active_slot_id == i.id, live=live_out,
                   last_check=state.get("last_check") if isinstance(state.get("last_check"), dict) else None,
                   stale=state.get("stale") if isinstance(state.get("stale"), dict) else None, ports=ports,
                   resize_pending=resize_pending)


class ChangeCheckOut(BaseModel):
    """``?check=true`` on ``POST /environments/{id}/slots`` and on a growing ``PATCH /environments/{id}`` (P4
    §15.5, §15.7): every refusal ran and nothing was written. ``plan`` is the slot (``slot``, ``host_id``,
    ``host``, ``planned``, a new VM's ``machine``) or the sizes (``from``, ``to``); ``cost`` the new estimate
    (``lines``, ``total_cents``, ``total``, ``as_of``, ``note``, ``delta`` from the stored one), for DigitalOcean
    only, and the figure ``confirm_cost`` must then be."""

    ok: bool = True
    plan: dict[str, Any]
    cost: dict[str, Any] | None = None


class SlotAdded(SlotOut):
    deployment: DeploymentOut | None = None  # the data server's update, with update_data_server
    note: str | None = None


class EnvironmentSummary(BaseModel):
    id: uuid.UUID
    name: str
    status: str
    repository: dict[str, Any]  # {id, full_name}
    branch: str
    data_mode: str
    active_slot: str | None
    slots: list[dict[str, Any]]  # [{slot, host_name, status, sha7}]
    last_job: dict[str, Any] | None = None  # {id, kind, status, finished_at}

    @staticmethod
    def parts(env: Any, members: dict[str, Instance], last: Deployment | None) -> dict[str, Any]:
        order = {"blue": 0, "green": 1, "data": 2}
        slots = sorted(members.values(), key=lambda m: order.get(str(m.slot), 3))
        active = next((m.slot for m in slots if m.id == env.active_slot_id), None)
        return {
            "id": env.id, "name": env.name, "status": env.status,
            "repository": {"id": env.repository_id, "full_name": env.repository.full_name if env.repository else None},
            "branch": env.branch, "data_mode": env.data_mode, "active_slot": active,
            "slots": [{"slot": m.slot, "host_name": m.host.name if m.host is not None else None, "status": m.status,
                       "sha7": (m.current_commit_sha or "")[:7] or None} for m in slots],
            "last_job": {"id": last.id, "kind": last.kind, "status": last.status, "finished_at": last.finished_at,
                         "label": data.dep_label(last)} if last is not None else None,
        }

    @classmethod
    def of(cls, env: Any, members: dict[str, Instance], last: Deployment | None) -> EnvironmentSummary:
        return cls(**cls.parts(env, members, last))


class EnvironmentOut(EnvironmentSummary):
    manifest_file: str
    auto_activate: bool
    traffic: dict[str, Any]
    traffic_state: dict[str, Any]
    route_tls: dict[str, Any]
    hostnames: list[dict[str, Any]]
    settings: dict[str, Any]
    services: list[str] | None
    secrets: list[str]  # names only, never the values
    env_keys: list[str]
    # The environment's variables are stored but can't be decrypted with SLIPWAY_ENCRYPTION_KEY.
    env_unreadable: bool = False
    slots: list[SlotOut]  # type: ignore[assignment]  # the full rows here
    data_owner_id: uuid.UUID | None
    # {keep_backups, seed_snapshot, first_admin, data_dirty, capabilities}: the data owner's (D3)
    data: dict[str, Any]
    active_job: DeploymentOut | None = None
    notice: dict[str, Any] | None = None
    created_by: str | None = None
    created_at: datetime
    deleted_at: datetime | None = None
    actions: dict[str, Any] = {}
    warnings: list[str] = []  # POST /environments: what was accepted but is worth knowing
    # Phase 4 (§16): the placement (ssh or digitalocean), production and retiring; for a DigitalOcean environment
    # what Slipway recorded of its cloud (``environment_out`` builds it; no DigitalOcean read).
    provider: str = "ssh"
    production: bool = False
    retiring_at: datetime | None = None
    cloud: dict[str, Any] | None = None
    # Phase 5 (P5 §11): the environment's VMs, from Slipway's records (GET .../machines reads them live).
    machines: list[MachineOut] = []


# --------------------------------------------------------------------------- audit


class AuditOut(BaseModel):
    id: uuid.UUID
    action: str
    actor: str | None
    target_type: str | None
    target_id: str | None
    summary: str
    ip: str | None
    created_at: datetime


def host_out(host: Host, *, owned_by: dict[str, Any] | None = None,
             machine: dict[str, Any] | None = None) -> HostOut:
    """``owned_by`` ({id, name, slot}) names the environment that made the host, ``machine`` ({stage, account})
    the VM it is; the API reads both (``api/v1/hosts.owned_by_of``, ``machines_of``)."""
    from slipway.services import ssh

    out = HostOut.model_validate(host)
    out.owned_by = owned_by
    out.machine = machine
    out.built = ssh.host_is_built(host)
    out.provider_state = dict(host.provider_state or {})
    return out


# ------------------------------------------------------------ provider accounts (phase 4 §16, phase 5 §11)
#
# Field types are loose on purpose: services/provider_accounts.py checks every value and answers 422 with the
# field it refused (``vmtypes.AccountInvalid``), with texts a person can act on. The bounds here only keep
# absurd input out. Secrets are write-only: no answer carries one.

AccountName = Annotated[str, Field(max_length=100), NoNul]
AccountSecret = Annotated[str, Field(max_length=500), NoNul]
AccountText = Annotated[str, Field(max_length=300), NoNul]
NetText = Annotated[str, Field(max_length=100), NoNul]
SshSource = Annotated[str, Field(max_length=60), NoNul]


class AddressPool(BaseModel):
    model_config = ConfigDict(extra="forbid")

    first: NetText
    last: NetText


class Network(BaseModel):
    """One network of a Proxmox or ESXi account (phase 5 §3.1), checked by ``vmnet.check_network_profile``."""

    model_config = ConfigDict(extra="forbid")

    name: NetText
    bridge: NetText | None = None  # Proxmox
    vlan_tag: int | None = None  # Proxmox
    port_group: NetText | None = None  # ESXi
    subnet: NetText
    gateway: NetText
    dns_servers: list[NetText] = Field(default_factory=list, max_length=10)
    pool: AddressPool | None = None


class DigitalOceanAccountIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Literal["digitalocean"]
    name: AccountName
    secret: AccountSecret | None = None
    production: bool = False
    region: Annotated[str, Field(max_length=20), NoNul]
    ssh_sources: list[SshSource] = Field(max_length=50)
    monthly_limit_cents: int | None = None
    prices: dict[str, Any] | None = None


class ProxmoxAccountIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Literal["proxmox"]
    name: AccountName
    secret: AccountSecret | None = None
    trust_fingerprint: AccountText | None = None
    url: AccountText
    node: AccountText
    pool: AccountText
    storage: AccountText
    template_vmid: int | str
    networks: list[Network] = Field(max_length=50)


class EsxiAccountIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Literal["esxi"]
    name: AccountName
    secret: AccountSecret | None = None
    trust_fingerprint: AccountText | None = None
    url: AccountText
    user: AccountText
    datastore: AccountText
    resource_pool: AccountText | None = None  # ESXi's root pool, Resources, when left out
    source_vm: AccountText
    networks: list[Network] = Field(default_factory=list, max_length=50)


ProviderAccountIn = Annotated[DigitalOceanAccountIn | ProxmoxAccountIn | EsxiAccountIn, Field(discriminator="provider")]


class ProviderAccountUpdate(BaseModel):
    """PATCH: every field optional, and an omitted one keeps its value. A field of another provider's account is
    refused by name. An omitted secret is kept (for Proxmox and ESXi only while the URL and user stay)."""

    model_config = ConfigDict(extra="forbid")

    name: AccountName | None = None
    secret: AccountSecret | None = None
    clear_secret: bool = False  # DigitalOcean: drop the stored token
    production: bool | None = None
    region: Annotated[str, Field(max_length=20), NoNul] | None = None
    ssh_sources: list[SshSource] | None = Field(None, max_length=50)
    monthly_limit_cents: int | None = None  # null clears the limit
    prices: dict[str, Any] | None = None  # null drops the override
    trust_fingerprint: AccountText | None = None
    url: AccountText | None = None
    node: AccountText | None = None
    pool: AccountText | None = None
    storage: AccountText | None = None
    template_vmid: int | str | None = None
    user: AccountText | None = None
    datastore: AccountText | None = None
    resource_pool: AccountText | None = None
    source_vm: AccountText | None = None
    networks: list[Network] | None = Field(None, max_length=50)


class AccountTestIn(BaseModel):
    """POST /provider-accounts/test: a DigitalOcean token that isn't saved."""

    secret: AccountSecret
    region: Annotated[str, Field(max_length=20), NoNul] | None = None


class TrustIn(BaseModel):
    fingerprint: AccountText


class AccountDelete(BaseModel):
    confirm: Confirm | None = None


class AccountTestOut(BaseModel):
    status: str
    checks: list[dict[str, Any]]
    facts: dict[str, Any]


class AccountUse(BaseModel):
    environment: str
    environment_id: uuid.UUID
    slot: str | None = None  # a VM's slot
    name: str | None = None  # a VM's name


class PinnedCertificate(BaseModel):
    fingerprint_sha256: str
    subject: str
    not_after: str | None = None


class _AccountOutBase(BaseModel):
    id: uuid.UUID
    name: str
    production: bool
    has_secret: bool
    secret_hint: str
    status: str
    checks: list[dict[str, Any]]
    facts: dict[str, Any]
    last_checked_at: datetime | None
    removed: bool
    removed_at: datetime | None
    used_by: list[AccountUse]
    created_at: datetime
    updated_at: datetime


class DigitalOceanAccountOut(_AccountOutBase):
    provider: Literal["digitalocean"]
    region: str | None = None
    team_name: str | None = None
    ssh_sources: list[str] = []
    ssh_open: bool = False  # an SSH source is 0.0.0.0/0 or ::/0
    monthly_limit_cents: int | None = None
    estimate_cents: int = 0  # the confirmed monthly cost of the environments that use it
    prices: dict[str, Any] | None = None


class _HypervisorAccountOut(_AccountOutBase):
    url: str | None = None
    networks: list[dict[str, Any]] = []
    tls: PinnedCertificate | None = None


class ProxmoxAccountOut(_HypervisorAccountOut):
    provider: Literal["proxmox"]
    node: str | None = None
    pool: str | None = None
    storage: str | None = None
    template_vmid: int | None = None


class EsxiAccountOut(_HypervisorAccountOut):
    provider: Literal["esxi"]
    user: str | None = None
    datastore: str | None = None
    resource_pool: str | None = None
    source_vm: str | None = None


ProviderAccountOut = Annotated[DigitalOceanAccountOut | ProxmoxAccountOut | EsxiAccountOut,
                               Field(discriminator="provider")]


def provider_account_out(account: Any, *, used_by: list[dict[str, Any]],
                         estimate_cents: int = 0) -> DigitalOceanAccountOut | ProxmoxAccountOut | EsxiAccountOut:
    """The answer for one ``provider_accounts`` row; never its secret."""
    from slipway.services import do_rules

    config = account.config or {}
    common: dict[str, Any] = {
        "id": account.id, "name": account.name, "production": account.production,
        "has_secret": bool(account.secret), "secret_hint": account.secret_hint or "",
        "status": account.status, "checks": list(account.checks or []), "facts": dict(account.facts or {}),
        "last_checked_at": account.last_checked_at, "removed": account.removed_at is not None,
        "removed_at": account.removed_at, "used_by": used_by,
        "created_at": account.created_at, "updated_at": account.updated_at,
    }
    if account.provider == "digitalocean":
        sources = list(config.get("ssh_sources") or [])
        return DigitalOceanAccountOut(
            provider="digitalocean", **common, region=config.get("region"),
            team_name=(config.get("team") or {}).get("name"), ssh_sources=sources,
            ssh_open=do_rules.open_to_world(sources), monthly_limit_cents=config.get("monthly_limit_cents"),
            estimate_cents=estimate_cents, prices=config.get("prices"))
    tls = account.tls or None
    hypervisor = {"url": config.get("url"), "networks": list(config.get("networks") or []),
                  "tls": {k: tls.get(k) for k in ("fingerprint_sha256", "subject", "not_after")} if tls else None}
    if account.provider == "proxmox":
        return ProxmoxAccountOut(provider="proxmox", **common, **hypervisor, node=config.get("node"),
                                 pool=config.get("pool"), storage=config.get("storage"),
                                 template_vmid=config.get("template_vmid"))
    return EsxiAccountOut(provider="esxi", **common, **hypervisor, user=config.get("user"),
                          datastore=config.get("datastore"), resource_pool=config.get("resource_pool"),
                          source_vm=config.get("source_vm"))
