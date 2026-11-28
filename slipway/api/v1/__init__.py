from fastapi import APIRouter

from slipway.api.v1 import (
    analytics,
    audit,
    auth,
    deployments,
    environments,
    hosts,
    images,
    instances,
    provider_accounts,
    repositories,
    roles,
    settings,
    snapshots,
    system,
    tokens,
    unmanaged,
    updates,
    users,
)

api_router = APIRouter()
for module in (system, auth, users, roles, tokens, hosts, unmanaged, repositories, instances, images, environments, deployments,
               analytics, snapshots, audit, settings, provider_accounts, updates):
    api_router.include_router(module.router)
