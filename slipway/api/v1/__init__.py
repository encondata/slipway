from fastapi import APIRouter

from slipway.api.v1 import audit, auth, deployments, hosts, instances, repositories, roles, settings, system, tokens, unmanaged, users

api_router = APIRouter()
for module in (system, auth, users, roles, tokens, hosts, unmanaged, repositories, instances, deployments, audit, settings):
    api_router.include_router(module.router)
