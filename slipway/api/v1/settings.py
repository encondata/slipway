"""Slipway-wide settings kept in the database: the Switchyard connection."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from slipway.api.deps import DB, require
from slipway.core.permissions import Perm
from slipway.models import AppSetting
from slipway.schemas import NoNul
from slipway.services import audit, switchyard
from slipway.services.auth import AuthContext

router = APIRouter(prefix="/settings", tags=["settings"])

Admin = Annotated[AuthContext, require(Perm.SETTINGS_WRITE)]


class SwitchyardIn(BaseModel):
    url: Annotated[str, Field(max_length=500), NoNul] = ""
    # Empty keeps the stored key; clear removes the whole connection.
    api_key: Annotated[str, Field(max_length=500), NoNul] = ""
    default_tls_mode: Literal["auto", "dns", "internal", "off"] = "auto"
    clear: bool = False


class SwitchyardOut(BaseModel):
    configured: bool
    url: str
    has_api_key: bool
    default_tls_mode: str
    required_operations: list[str] = list(switchyard.REQUIRED_OPERATIONS)


async def _row(db: DB) -> AppSetting | None:
    return await db.scalar(select(AppSetting).where(AppSetting.key == switchyard.SETTING_KEY))


def _out(row: AppSetting | None) -> SwitchyardOut:
    value = (row.value if row else None) or {}
    return SwitchyardOut(
        configured=bool(row and row.secret and value.get("url")),
        url=value.get("url", ""),
        has_api_key=bool(row and row.secret),
        default_tls_mode=value.get("default_tls_mode") or "auto",
    )


@router.get("/switchyard")
async def get_switchyard(ctx: Admin, db: DB) -> SwitchyardOut:
    return _out(await _row(db))


@router.put("/switchyard")
async def put_switchyard(body: SwitchyardIn, ctx: Admin, request: Request, db: DB) -> SwitchyardOut:
    row = await _row(db)
    if body.clear:
        if row is not None:
            await db.delete(row)
        audit.record(db, "settings.switchyard", actor=ctx.user, summary="Removed the Switchyard connection", request=request)
        await db.commit()
        return _out(None)
    try:
        url = switchyard.clean_url(body.url)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if row is None:
        row = AppSetting(key=switchyard.SETTING_KEY, value={})
        db.add(row)
    if not body.api_key and not row.secret:
        raise HTTPException(422, "Enter the Switchyard API key")
    row.value = {**(row.value or {}), "url": url, "default_tls_mode": body.default_tls_mode}
    changed = ["URL", "default TLS mode"]
    if body.api_key:
        row.secret = body.api_key.strip()
        changed.append("API key")
    audit.record(db, "settings.switchyard", actor=ctx.user, summary=f"Updated the Switchyard connection ({', '.join(changed)})",
                 details={"url": url}, request=request)
    await db.commit()
    return _out(row)


@router.post("/switchyard/test")
async def test_switchyard(ctx: Admin, db: DB) -> dict[str, object]:
    config = await switchyard.load_config(db)
    if config is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Save the Switchyard URL and API key first")
    await db.commit()
    try:
        message = await switchyard.check_connection(config)
    except switchyard.SwitchyardError as exc:
        hint = ""
        if exc.status_code == 401:
            hint = " Check the API key: it may be wrong, revoked or expired."
        elif exc.status_code == 403:
            hint = " Give the key these operations in Switchyard: " + ", ".join(switchyard.REQUIRED_OPERATIONS) + "."
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"{exc}.{hint}") from exc
    return {"ok": True, "message": message}
