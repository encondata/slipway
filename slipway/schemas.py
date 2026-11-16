"""Pydantic request/response models for the JSON API."""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, EmailStr, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.core.permissions import validate_permissions
from slipway.models import Backup, Deployment, FirstAdmin, Host, Instance, Repository, Snapshot, User
from slipway.services import data, deployer, manifest, ports, switchyard

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
    environment: str
    description: str
    deploy_root: str
    proxy_address: str | None = None
    auth_method: str
    public_key: str | None
    host_key_fingerprint: str | None
    status: str
    last_checked_at: datetime | None
    last_error: str | None
    docker_version: str | None
    os_info: str | None
    metrics: dict[str, Any]
    created_at: datetime


class _HostFields(BaseModel):
    hostname: Annotated[str, Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9.:\-\[\]]+$"), NoNul] | None = None
    port: int | None = Field(None, ge=1, le=65535)
    username: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z_][a-z0-9_.-]*$"), NoNul] | None = None
    environment: Annotated[str, Field(max_length=32), NoNul] | None = None
    description: Annotated[str, Field(max_length=255), NoNul] | None = None
    deploy_root: Annotated[str, Field(max_length=255), NoNul] | None = None
    # Address the reverse proxy uses for this host's ports; "" clears it (then the hostname is used).
    proxy_address: Annotated[str, Field(max_length=255, pattern=r"^$|^[A-Za-z0-9.\-]+$|^\[[0-9A-Fa-f:.]+\]$"), NoNul] | None = None
    private_key: Annotated[str, Field(max_length=20000), NoNul] | None = None
    key_passphrase: str | None = Field(None, max_length=500)
    password: str | None = Field(None, max_length=500)

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
    build_source: Literal["dockerfile", "compose", "app"] | None = None
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


class InstanceCreate(_InstanceFields):
    name: Str = Field(min_length=1, max_length=100)
    repository_id: uuid.UUID
    host_id: uuid.UUID
    build_source: Literal["dockerfile", "compose", "app"] = "dockerfile"
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
    repository_id: uuid.UUID
    repository: str
    host_id: uuid.UUID
    host: str
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
            repository=i.repository.full_name,
            host_id=i.host_id,
            host=i.host.name,
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
        )


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


class DeploymentOut(BaseModel):
    id: uuid.UUID
    instance_id: uuid.UUID
    instance_name: str
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
        return cls(
            id=d.id,
            instance_id=d.instance_id,
            instance_name=d.instance.name,
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
            options={k: v for k, v in (d.options or {}).items() if k not in _HIDDEN_OPTIONS},
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


def host_out(host: Host) -> HostOut:
    return HostOut.model_validate(host)
