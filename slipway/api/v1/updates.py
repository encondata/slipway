"""Slipway's own version and upgrades of it (see slipway/services/updates.py and docs/updates.md).

Every route takes ``require(Perm.UPDATES_RUN)``, which also checks the CSRF header on cookie-authenticated
writes; no route checks permissions by hand. GET routes only read, and reconcile a run's stored status with
the server's; they never start, stop or configure anything. Configuring and starting an upgrade need a web
session: an API token cannot do either.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from pydantic import AfterValidator, BaseModel, Field

from slipway.api.deps import DB, require
from slipway.core.permissions import Perm
from slipway.services import ssh, updates
from slipway.services.auth import AuthContext

router = APIRouter(prefix="/updates", tags=["updates"])

Upgrader = Annotated[AuthContext, require(Perm.UPDATES_RUN)]


def _branch(value: str) -> str:
    if not updates.valid_branch(value):
        raise ValueError("That branch name isn't allowed")
    return value


def _sha(value: str) -> str:
    if not updates.valid_sha(value):
        raise ValueError("Give the full 40-character commit sha")
    return value


Branch = Annotated[str, Field(min_length=1, max_length=100), AfterValidator(_branch)]
Sha = Annotated[str, Field(min_length=40, max_length=40), AfterValidator(_sha)]


class ConfigIn(BaseModel):
    host_id: uuid.UUID
    branch: Branch | None = None


class RunIn(BaseModel):
    branch: Branch
    sha: Sha


def _refusal(exc: updates.UpdateError) -> JSONResponse:
    body: dict[str, Any] = {"detail": exc.detail}
    if exc.field:
        body["field"] = exc.field
    return JSONResponse(body, status_code=exc.status)


def _ssh_failed(exc: ssh.SSHError) -> JSONResponse:
    return JSONResponse({"detail": updates.redact(ssh.clip(str(exc), 2000))}, status_code=status.HTTP_502_BAD_GATEWAY)


def _token_refused(ctx: AuthContext) -> JSONResponse | None:
    if ctx.via != "session":
        return JSONResponse({"detail": updates.MSG_TOKEN}, status_code=status.HTTP_403_FORBIDDEN)
    return None


@router.get("")
async def get_overview(ctx: Upgrader, db: DB) -> Any:
    return await updates.overview(db)


@router.put("/config")
async def put_config(body: ConfigIn, ctx: Upgrader, request: Request, db: DB) -> Any:
    if (refused := _token_refused(ctx)) is not None:
        return refused
    try:
        return await updates.configure(db, host_id=body.host_id, branch=body.branch, actor=ctx.user, request=request)
    except updates.UpdateError as exc:
        return _refusal(exc)
    except ssh.SSHError as exc:
        return _ssh_failed(exc)


@router.get("/branches")
async def get_branches(ctx: Upgrader, request: Request, db: DB) -> Any:
    """The branches on GitHub (the install's origin), read live over SSH, for Branch to follow."""
    try:
        return await updates.remote_branches(db, actor=ctx.user, request=request)
    except updates.UpdateError as exc:
        return _refusal(exc)
    except ssh.SSHError as exc:
        return _ssh_failed(exc)


@router.post("/check")
async def post_check(ctx: Upgrader, request: Request, db: DB) -> Any:
    try:
        return await updates.check(db, actor=ctx.user, request=request, manual=True)
    except updates.UpdateError as exc:
        return _refusal(exc)
    except ssh.SSHError as exc:
        return _ssh_failed(exc)


@router.post("/runs", status_code=status.HTTP_202_ACCEPTED)
async def post_run(body: RunIn, ctx: Upgrader, request: Request, db: DB) -> Any:
    try:
        run_id = await updates.start_run(
            db, branch=body.branch, sha=body.sha, ctx_via=ctx.via, actor=ctx.user, request=request
        )
    except updates.UpdateError as exc:
        return _refusal(exc)
    except ssh.SSHError as exc:
        return _ssh_failed(exc)
    return {"id": run_id}


@router.get("/runs")
async def get_runs(ctx: Upgrader, db: DB) -> Any:
    return await updates.list_runs(db)


@router.get("/runs/{run_id}")
async def get_run(run_id: str, ctx: Upgrader, request: Request, db: DB) -> Any:
    # Checked against the id pattern before anything else (no SSH for anything else): a 404, not a 422.
    if not updates.valid_id(run_id):
        return JSONResponse({"detail": "Unknown id"}, status_code=status.HTTP_404_NOT_FOUND)
    try:
        return await updates.get_run(db, run_id, actor=ctx.user, request=request)
    except updates.UpdateError as exc:
        return _refusal(exc)
    except ssh.SSHError as exc:
        return _ssh_failed(exc)
