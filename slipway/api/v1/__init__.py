from fastapi import APIRouter

from slipway.api.v1 import (
    audit,
    auth,
    deployments,
    hosts,
    instances,
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
for module in (system, auth, users, roles, tokens, hosts, unmanaged, repositories, instances, deployments, snapshots,
               audit, settings):
    api_router.include_router(module.router)
