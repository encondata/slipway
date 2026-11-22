"""Import every model so ``Base.metadata`` is complete (Alembic and create_all rely on this)."""

from slipway.models.audit import AuditEvent
from slipway.models.data import (
    Backup,
    BackupLocation,
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
from slipway.models.host import Host, HostAuthMethod, HostOS, HostSetupStatus, HostStatus
from slipway.models.instance import (
    BuildSource,
    Deployment,
    DeploymentKind,
    DeploymentStatus,
    FreshData,
    Instance,
    InstanceStatus,
)
from slipway.models.machine import (
    AddressClaim,
    Machine,
    MachineSnapshot,
    MachineStage,
    SnapshotMode,
    SnapshotReason,
    TerraformState,
)
from slipway.models.metrics import HostSample, HostSampleHourly
from slipway.models.provider import AccountStatus, ProviderAccount, ProviderKind
from slipway.models.repository import Repository
from slipway.models.setting import AppSetting
from slipway.models.user import ApiToken, OAuthAccount, Role, User, UserSession, user_roles

__all__ = [
    "AccountStatus",
    "AddressClaim",
    "ApiToken",
    "AppSetting",
    "AuditEvent",
    "Backup",
    "BackupLocation",
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
    "HostSample",
    "HostSampleHourly",
    "HostOS",
    "HostSetupStatus",
    "HostStatus",
    "Instance",
    "InstanceStatus",
    "Machine",
    "MachineSnapshot",
    "MachineStage",
    "OAuthAccount",
    "ProviderAccount",
    "ProviderKind",
    "Repository",
    "Resource",
    "ResourceOrigin",
    "Role",
    "SlotName",
    "Snapshot",
    "SnapshotMode",
    "SnapshotOrigin",
    "SnapshotReason",
    "SnapshotStatus",
    "TerraformState",
    "User",
    "UserSession",
    "user_roles",
]
