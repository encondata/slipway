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
    DATA_READ = "data:read"
    DATA_BACKUP = "data:backup"
    DATA_RESTORE = "data:restore"
    DATA_RESET = "data:reset"
    SNAPSHOTS_UPLOAD = "snapshots:upload"
    SNAPSHOTS_DOWNLOAD = "snapshots:download"
    ENVIRONMENTS_READ = "environments:read"
    ENVIRONMENTS_WRITE = "environments:write"
    ENVIRONMENTS_DELETE = "environments:delete"
    TRAFFIC_SWITCH = "traffic:switch"
    PROVIDERS_READ = "providers:read"
    PROVIDERS_WRITE = "providers:write"
    PROVIDERS_SPEND = "providers:spend"
    MACHINES_WRITE = "machines:write"


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
    Perm.ANALYTICS_READ: "View mobile and web analytics",
    Perm.LOGS_READ: "View platform and application logs",
    Perm.AUDIT_READ: "View the audit log",
    Perm.SETTINGS_WRITE: "Change Slipway-wide settings",
    Perm.DATA_READ: "View backups and snapshots (names, sizes, dates; never their contents)",
    Perm.DATA_BACKUP: "Back up instances now; take, rename and keep snapshots",
    Perm.DATA_RESTORE: (
        "Restore a backup made with the same keys, and roll back a failed deploy "
        "(replaces an instance's data; the name must be typed)"
    ),
    Perm.DATA_RESET: (
        "Reset or start over an instance's data, start instances from a snapshot, restore old identity keys, "
        "delete backups and snapshots, override a data hold or a host lock, skip a backup, "
        "create a first admin in a live app"
    ),
    Perm.SNAPSHOTS_UPLOAD: (
        "Upload snapshot files (privileged: a snapshot's database runs as SQL inside the app it seeds)"
    ),
    Perm.SNAPSHOTS_DOWNLOAD: (
        "Download snapshots as passphrase-encrypted files, and seed instances of another repository from them "
        "(privileged: a snapshot holds a whole database and its identity keys)"
    ),
    Perm.ENVIRONMENTS_READ: "View environments, their slots, traffic and DNS records",
    Perm.ENVIRONMENTS_WRITE: (
        "Create and configure environments and add slots (privileged: like instances:write, an environment "
        "runs its branch's slipway.yml commands on every host it uses)"
    ),
    Perm.ENVIRONMENTS_DELETE: "Remove slots and delete environments (the name must be typed)",
    Perm.TRAFFIC_SWITCH: (
        "Move an environment's traffic to a slot (activate, switch back), publish its names (Switchyard and DNS), "
        "claim records, resolve a stuck switch and discard a failed idle slot"
    ),
    Perm.PROVIDERS_READ: (
        "See DigitalOcean, Proxmox and ESXi accounts (names, regions, teams, limits, networks; never tokens or "
        "passwords) and their regions, sizes and free addresses"
    ),
    Perm.PROVIDERS_WRITE: "Add, change, test, trust and remove DigitalOcean, Proxmox and ESXi accounts and their secrets",
    Perm.PROVIDERS_SPEND: (
        "Confirm a monthly cost: create a DigitalOcean environment, add a slot to one, grow its sizes"
    ),
    Perm.MACHINES_WRITE: (
        "Make VMs on Proxmox and ESXi for environments, resize them, take and delete VM snapshots, forget a lost VM "
        "(privileged: VMs use the hypervisor's CPU, memory and storage)"
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
    Perm.DATA_READ,
    Perm.ENVIRONMENTS_READ,
]

SYSTEM_ROLES: dict[str, dict[str, object]] = {
    "admin": {
        "description": "Full access to everything, including users, roles and hosts.",
        "permissions": ["*"],
    },
    "maintainer": {
        "description": (
            "Manages hosts, instances, environments, deployments and their data, confirms cloud costs and makes "
            "VMs. Cannot manage users, roles or provider accounts, or download snapshots."
        ),
        "permissions": [
            *_READ_ALL,
            Perm.HOSTS_WRITE,
            Perm.REPOS_SYNC,
            Perm.INSTANCES_WRITE,
            Perm.INSTANCES_OPERATE,
            Perm.DEPLOYMENTS_CREATE,
            Perm.DATA_BACKUP,
            Perm.DATA_RESTORE,
            Perm.DATA_RESET,
            Perm.SNAPSHOTS_UPLOAD,
            Perm.ENVIRONMENTS_WRITE,
            Perm.ENVIRONMENTS_DELETE,
            Perm.TRAFFIC_SWITCH,
            Perm.PROVIDERS_READ,
            Perm.PROVIDERS_SPEND,
            Perm.MACHINES_WRITE,
            Perm.USERS_READ,
            Perm.ROLES_READ,
            Perm.AUDIT_READ,
        ],
    },
    "developer": {
        "description": (
            "Deploys and operates existing instances and environments, switches environments' traffic, "
            "and backs up and restores their data."
        ),
        "permissions": [
            *_READ_ALL,
            Perm.REPOS_SYNC,
            Perm.INSTANCES_OPERATE,
            Perm.DEPLOYMENTS_CREATE,
            Perm.DATA_BACKUP,
            Perm.DATA_RESTORE,
            Perm.TRAFFIC_SWITCH,
            Perm.PROVIDERS_READ,
        ],
    },
    "viewer": {
        "description": (
            "Read-only access to repositories, hosts, instances, environments, deployments, backups and snapshots."
        ),
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
