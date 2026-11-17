"""Permission catalogue and the built-in roles.

Permissions are ``resource:action`` strings. Roles hold a list of permissions and users
hold any number of roles; a user's effective permissions are the union. ``*`` grants
everything and ``resource:*`` grants every action on one resource.
"""

from __future__ import annotations

from enum import StrEnum


class Perm(StrEnum):
    USERS_READ = "users:read"
    USERS_WRITE = "users:write"
    ROLES_READ = "roles:read"
    ROLES_WRITE = "roles:write"
    HOSTS_READ = "hosts:read"
    HOSTS_WRITE = "hosts:write"
    REPOS_READ = "repos:read"
    REPOS_SYNC = "repos:sync"
    INSTANCES_READ = "instances:read"
    INSTANCES_WRITE = "instances:write"
    INSTANCES_OPERATE = "instances:operate"
    DEPLOYMENTS_READ = "deployments:read"
    DEPLOYMENTS_CREATE = "deployments:create"
    ANALYTICS_READ = "analytics:read"
    LOGS_READ = "logs:read"
    AUDIT_READ = "audit:read"
    SETTINGS_WRITE = "settings:write"
    UPDATES_RUN = "updates:run"


PERMISSION_DESCRIPTIONS: dict[str, str] = {
    Perm.USERS_READ: "View user accounts",
    Perm.USERS_WRITE: "Create, edit, deactivate users and assign roles",
    Perm.ROLES_READ: "View roles and their permissions",
    Perm.ROLES_WRITE: "Create, edit and delete custom roles",
    Perm.HOSTS_READ: "View Docker hosts and their health",
    Perm.HOSTS_WRITE: "Add, edit, remove hosts and manage SSH credentials (privileged)",
    Perm.REPOS_READ: "View GitHub repositories known to Slipway",
    Perm.REPOS_SYNC: "Sync repositories from GitHub",
    Perm.INSTANCES_READ: "View instances, container status and logs",
    Perm.INSTANCES_WRITE: (
        "Create, configure and destroy instances (privileged: controls host mounts; "
        "a compose instance runs whatever its branch's compose file defines, as root on the host)"
    ),
    Perm.INSTANCES_OPERATE: "Start, stop and restart instances",
    Perm.DEPLOYMENTS_READ: "View deployments and build output",
    Perm.DEPLOYMENTS_CREATE: (
        "Trigger deployments (for compose instances, together with push access to the branch "
        "this means root on the host, including other instances' secrets there)"
    ),
    Perm.ANALYTICS_READ: "View deploy and host analytics (also needs deployments:read or hosts:read)",
    Perm.LOGS_READ: "View platform and application logs",
    Perm.AUDIT_READ: "View the audit log",
    Perm.SETTINGS_WRITE: "Change Slipway-wide settings",
    Perm.UPDATES_RUN: (
        "See Slipway's version and upgrade it (privileged: runs the upgrade on Slipway's own server as that "
        "host's SSH user. Slipway's own server is then a host: anyone who can create or deploy instances on it "
        "is root on Slipway itself)"
    ),
}

ALL_PERMISSIONS: list[str] = [p.value for p in Perm]

_READ_ALL = [
    Perm.HOSTS_READ,
    Perm.REPOS_READ,
    Perm.INSTANCES_READ,
    Perm.DEPLOYMENTS_READ,
    Perm.ANALYTICS_READ,
    Perm.LOGS_READ,
]

SYSTEM_ROLES: dict[str, dict[str, object]] = {
    "admin": {
        "description": "Full access to everything, including users, roles and hosts.",
        "permissions": ["*"],
    },
    "maintainer": {
        "description": "Manages hosts, instances and deployments. Cannot manage users or roles.",
        "permissions": [
            *_READ_ALL,
            Perm.HOSTS_WRITE,
            Perm.REPOS_SYNC,
            Perm.INSTANCES_WRITE,
            Perm.INSTANCES_OPERATE,
            Perm.DEPLOYMENTS_CREATE,
            Perm.USERS_READ,
            Perm.ROLES_READ,
            Perm.AUDIT_READ,
        ],
    },
    "developer": {
        "description": "Deploys and operates existing instances.",
        "permissions": [
            *_READ_ALL,
            Perm.REPOS_SYNC,
            Perm.INSTANCES_OPERATE,
            Perm.DEPLOYMENTS_CREATE,
        ],
    },
    "viewer": {
        "description": "Read-only access to repositories, hosts, instances and deployments.",
        "permissions": list(_READ_ALL),
    },
}


def has_permission(granted: set[str] | frozenset[str], needed: str) -> bool:
    if "*" in granted or needed in granted:
        return True
    resource = needed.split(":", 1)[0]
    return f"{resource}:*" in granted


def validate_permissions(perms: list[str]) -> list[str]:
    valid = set(ALL_PERMISSIONS) | {"*"} | {f"{p.split(':')[0]}:*" for p in ALL_PERMISSIONS}
    unknown = [p for p in perms if p not in valid]
    if unknown:
        raise ValueError(f"Unknown permission(s): {', '.join(unknown)}")
    return sorted(set(perms))
