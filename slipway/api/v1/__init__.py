from fastapi import APIRouter

from slipway.api.v1 import analytics, audit, auth, deployments, hosts, instances, repositories, roles, settings, system, tokens, unmanaged, updates, users

api_router = APIRouter()
for module in (system, auth, users, roles, tokens, hosts, unmanaged, repositories, instances, deployments, analytics, audit, settings, updates):
    api_router.include_router(module.router)
