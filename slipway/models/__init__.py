"""Import every model so ``Base.metadata`` is complete (Alembic and create_all rely on this)."""

from slipway.models.audit import AuditEvent
from slipway.models.data import (
    Backup,
    BackupReason,
    BackupStatus,
    FirstAdmin,
    FirstAdminMode,
    FirstAdminStatus,
    Snapshot,
    SnapshotOrigin,
    SnapshotStatus,
)
from slipway.models.environment import (
    DataMode,
    Environment,
    EnvironmentStatus,
    Resource,
    ResourceOrigin,
    SlotName,
)
from slipway.models.host import Host, HostAuthMethod, HostStatus
from slipway.models.instance import (
    BuildSource,
    Deployment,
    DeploymentKind,
    DeploymentStatus,
    FreshData,
    Instance,
    InstanceStatus,
)
from slipway.models.repository import Repository
from slipway.models.setting import AppSetting
from slipway.models.user import ApiToken, OAuthAccount, Role, User, UserSession, user_roles

__all__ = [
    "ApiToken",
    "AppSetting",
    "AuditEvent",
    "Backup",
    "BackupReason",
    "BackupStatus",
    "BuildSource",
    "DataMode",
    "Deployment",
    "DeploymentKind",
    "DeploymentStatus",
    "Environment",
    "EnvironmentStatus",
    "FirstAdmin",
    "FirstAdminMode",
    "FirstAdminStatus",
    "FreshData",
    "Host",
    "HostAuthMethod",
    "HostStatus",
    "Instance",
    "InstanceStatus",
    "OAuthAccount",
    "Repository",
    "Resource",
    "ResourceOrigin",
    "Role",
    "SlotName",
    "Snapshot",
    "SnapshotOrigin",
    "SnapshotStatus",
    "User",
    "UserSession",
    "user_roles",
]
