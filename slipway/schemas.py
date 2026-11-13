"""Pydantic request/response models for the JSON API."""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, EmailStr, Field, field_validator

from slipway.core.permissions import validate_permissions
from slipway.models import Deployment, Host, Instance, Repository, User
from slipway.services import deployer, ports

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


class _InstanceFields(BaseModel):
    branch: Annotated[str, Field(min_length=1, max_length=BRANCH_MAX, pattern=r"^[A-Za-z0-9._/-]+$"), NoNul] | None = None
    build_source: Literal["dockerfile", "compose"] | None = None
    dockerfile_path: Annotated[str, Field(max_length=255), NoNul] | None = None
    build_context: Annotated[str, Field(max_length=255), NoNul] | None = None
    compose_file: Annotated[str, Field(max_length=255), NoNul] | None = None
    env: dict[EnvKey, EnvValue] | None = Field(None, max_length=500)
    ports: list[PortMapping] | None = Field(None, max_length=100)
    volumes: list[VolumeMapping] | None = Field(None, max_length=100)
    auto_ports: bool | None = None
    port_overrides: list[PortOverride] | None = Field(None, max_length=100)

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

    @field_validator("dockerfile_path", "compose_file")
    @classmethod
    def _rel(cls, v: str | None) -> str | None:
        return None if v is None else deployer.clean_relative_path(v)

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
    build_source: Literal["dockerfile", "compose"] = "dockerfile"
    deploy: bool = True


class InstanceUpdate(_InstanceFields):
    name: Annotated[str, Field(min_length=1, max_length=100), NoNul] | None = None
    host_id: uuid.UUID | None = None
    # Erase the stored variables on purpose, including ones that can no longer be decrypted.
    # (An empty ``env`` never replaces variables that can't be decrypted.)
    clear_env: bool = False


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
    # What the instance was claimed from, when it was claimed (see POST /hosts/{id}/claim).
    claim: dict[str, Any] | None = None
    status: str
    current_commit_sha: str | None
    last_deployed_at: datetime | None
    created_at: datetime

    @classmethod
    def of(cls, i: Instance, *, env_unreadable: bool = False) -> InstanceOut:
        """``env_unreadable`` needs a query (see ``api.v1.instances.env_unreadable``), so callers pass it."""
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
            env_keys=sorted((i.env or {}).keys()),
            env_unreadable=env_unreadable,
            ports=i.ports,
            volumes=i.volumes,
            auto_ports=i.auto_ports,
            port_overrides=i.port_overrides or [],
            published_ports=i.published_ports or [],
            compose_project=i.compose_project,
            claim=i.claim,
            status=i.status,
            current_commit_sha=i.current_commit_sha,
            last_deployed_at=i.last_deployed_at,
            created_at=i.created_at,
        )


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

    @classmethod
    def of(cls, d: Deployment) -> DeploymentOut:
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
        )


class DeploymentDetail(DeploymentOut):
    log: str
    log_offset: int


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
