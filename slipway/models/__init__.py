"""Import every model so ``Base.metadata`` is complete (Alembic and create_all rely on this)."""

from slipway.models.audit import AuditEvent
from slipway.models.host import Host, HostAuthMethod, HostStatus
from slipway.models.instance import BuildSource, Deployment, DeploymentStatus, Instance, InstanceStatus
from slipway.models.repository import Repository
from slipway.models.setting import AppSetting
from slipway.models.user import ApiToken, OAuthAccount, Role, User, UserSession, user_roles

__all__ = [
    "ApiToken",
    "AppSetting",
    "AuditEvent",
    "BuildSource",
    "Deployment",
    "DeploymentStatus",
    "Host",
    "HostAuthMethod",
    "HostStatus",
    "Instance",
    "InstanceStatus",
    "OAuthAccount",
    "Repository",
    "Role",
    "User",
    "UserSession",
    "user_roles",
]
