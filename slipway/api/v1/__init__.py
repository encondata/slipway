from fastapi import APIRouter

from slipway.api.v1 import (
    audit,
    auth,
    deployments,
    environments,
    hosts,
    instances,
    provider_accounts,
    repositories,
    roles,
    settings,
    snapshots,
    system,
    tokens,
    unmanaged,
    users,
)

api_router = APIRouter()
for module in (system, auth, users, roles, tokens, hosts, unmanaged, repositories, instances, environments, deployments,
               snapshots, audit, settings, provider_accounts):
    api_router.include_router(module.router)
