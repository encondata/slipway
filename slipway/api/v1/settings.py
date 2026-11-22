"""Slipway-wide settings kept in the database: the Switchyard connection and the Cloudflare DNS integration."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from slipway.api.deps import DB, require
from slipway.core.permissions import Perm
from slipway.models import AppSetting, Environment, Resource
from slipway.schemas import NoNul
from slipway.services import audit, cloudflare, switchyard
from slipway.services.auth import AuthContext

router = APIRouter(prefix="/settings", tags=["settings"])

Admin = Annotated[AuthContext, require(Perm.SETTINGS_WRITE)]


class SwitchyardIn(BaseModel):
    url: Annotated[str, Field(max_length=500), NoNul] = ""
    # Empty keeps the stored key; clear removes the whole connection.
    api_key: Annotated[str, Field(max_length=500), NoNul] = ""
    default_tls_mode: Literal["auto", "dns", "internal", "off"] = "auto"
    # Where Switchyard serves the hostnames (host[:port]), for the check through it after a switch (phase 3
    # §10.8). None keeps the stored one; "" clears it.
    traffic_address: Annotated[str, Field(max_length=300), NoNul] | None = None
    clear: bool = False


class SwitchyardOut(BaseModel):
    configured: bool
    url: str
    has_api_key: bool
    # The key's first characters, as Switchyard's API keys page lists them.
    api_key_prefix: str = ""
    default_tls_mode: str
    traffic_address: str = ""
    required_operations: list[str] = list(switchyard.REQUIRED_OPERATIONS)


async def _row(db: DB) -> AppSetting | None:
    return await db.scalar(select(AppSetting).where(AppSetting.key == switchyard.SETTING_KEY))


def _out(row: AppSetting | None) -> SwitchyardOut:
    value = (row.value if row else None) or {}
    return SwitchyardOut(
        configured=bool(row and row.secret and value.get("url")),
        url=value.get("url", ""),
        has_api_key=bool(row and row.secret),
        api_key_prefix=(row.secret or "")[: switchyard.KEY_PREFIX_LEN] if row else "",
        default_tls_mode=value.get("default_tls_mode") or "auto",
        traffic_address=value.get("traffic_address") or "",
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
    key = None
    if body.api_key:
        try:
            key = switchyard.clean_api_key(body.api_key)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
    traffic_address = None
    if body.traffic_address is not None:
        try:
            traffic_address = switchyard.clean_traffic_address(body.traffic_address)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
    row.value = {**(row.value or {}), "url": url, "default_tls_mode": body.default_tls_mode}
    changed = ["URL", "default TLS mode"]
    if traffic_address is not None:
        row.value = {**row.value, "traffic_address": traffic_address}
        changed.append(f"traffic address {traffic_address}" if traffic_address else "traffic address cleared")
    if key:
        row.secret = key
        row.value = {**row.value, "edits": {}}  # a new key may be for another Switchyard
        changed.append(f"API key {key[: switchyard.KEY_PREFIX_LEN]}…")
    audit.record(db, "settings.switchyard", actor=ctx.user, summary=f"Updated the Switchyard connection ({', '.join(changed)})",
                 details={"url": url, "traffic_address": row.value.get("traffic_address") or ""}, request=request)
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
            prefix = config.api_key[: switchyard.KEY_PREFIX_LEN]
            hint = (
                f" Slipway's saved key starts with {prefix}…; in Switchyard under Administration → API keys, "
                "check that an active key with that prefix exists"
                + (f" on {config.url}" if config.url else "")
                + ". If not, paste the key again (browsers sometimes fill this box with a saved password)."
            )
        elif exc.status_code == 403:
            hint = " Give the key these operations in Switchyard: " + ", ".join(switchyard.REQUIRED_OPERATIONS) + "."
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"{exc}.{hint}") from exc
    return {"ok": True, "message": message}


# ------------------------------------------------------------------------ Cloudflare (phase 3 §10.10)


class CloudflareIn(BaseModel):
    zone: Annotated[str, Field(max_length=253), NoNul] = ""
    # The WAN address published records point at (an environment may give its own).
    public_ip: Annotated[str, Field(max_length=45), NoNul] = ""
    proxied: bool = False  # records go through Cloudflare's proxy by default
    # Required the first time, write-only after: empty keeps the stored token.
    token: Annotated[str, Field(max_length=500), NoNul] = ""
    clear: bool = False  # remove the integration


class CloudflareOut(BaseModel):
    configured: bool
    zone: str = ""
    zone_id: str = ""
    public_ip: str = ""
    proxied: bool = False
    has_token: bool = False
    token_hint: str = ""  # the token's last 4 characters, shown as "Set (…abcd)"


async def _cloudflare_row(db: DB) -> AppSetting | None:
    return await db.scalar(select(AppSetting).where(AppSetting.key == cloudflare.SETTING_KEY))


def _cloudflare_out(row: AppSetting | None) -> CloudflareOut:
    value = (row.value if row else None) or {}
    return CloudflareOut(
        configured=bool(row and row.secret and value.get("zone")), zone=value.get("zone") or "",
        zone_id=value.get("zone_id") or "", public_ip=value.get("public_ip") or "",
        proxied=bool(value.get("proxied")), has_token=bool(row and row.secret),
        token_hint=cloudflare.token_hint(row.secret if row else None),
    )


async def _dns_users(db: DB) -> list[str]:
    """The live environments that publish DNS records through Cloudflare, and every environment Slipway still
    keeps a record there for (teardown needs Cloudflare to delete them)."""
    rows = (await db.execute(select(Environment.name, Environment.traffic)
                             .where(Environment.deleted_at.is_(None)).order_by(Environment.name))).all()
    users = {name for name, traffic in rows if (traffic or {}).get("dns")}
    return sorted(users | {name for name, _ in await _recorded(db)})


async def _recorded(db: DB) -> list[tuple[str, str | None]]:
    """``(environment name, zone id)`` of every Cloudflare record Slipway keeps a row for."""
    rows = (await db.execute(select(Environment.name, Resource.details)
                             .join(Environment, Environment.id == Resource.environment_id)
                             .where(Resource.provider == cloudflare.PROVIDER, Resource.kind == cloudflare.KIND))).all()
    return [(name, (details or {}).get("zone_id")) for name, details in rows]


async def _zone_holders(db: DB, zone_id: str | None = None) -> list[str]:
    """The environments with a record Slipway keeps outside ``zone_id`` (any record, when None)."""
    return sorted({name for name, held in await _recorded(db) if zone_id is None or held != zone_id})


def _zone_kept(users: list[str], zone: str | None, then: str = "then change the zone") -> str:
    where = f"the Cloudflare zone {zone}" if zone else "another Cloudflare zone"
    return (f"Environments {', '.join(users)} keep DNS records in {where}; turn DNS off on them first (Slipway "
            f"removes their records, or forgets them when their zone is gone), {then}")


@router.get("/cloudflare")
async def get_cloudflare(ctx: Admin, db: DB) -> CloudflareOut:
    return _cloudflare_out(await _cloudflare_row(db))


@router.put("/cloudflare")
async def put_cloudflare(body: CloudflareIn, ctx: Admin, request: Request, db: DB) -> CloudflareOut:
    """Save the zone, the public IP and the token. Saving looks the zone up and checks the token with Cloudflare,
    so a typing mistake is caught here rather than in a deploy. The token is never shown again."""
    row = await _cloudflare_row(db)
    if body.clear:
        users = await _dns_users(db)
        if users:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                f"Environments {', '.join(users)} publish DNS records through Cloudflare; turn that off "
                                "on them first")
        if row is not None:
            await db.delete(row)
        audit.record(db, "settings.cloudflare", actor=ctx.user, summary="Removed the Cloudflare integration",
                     request=request)
        await db.commit()
        return _cloudflare_out(None)
    try:
        zone = cloudflare.clean_zone(body.zone)
        public_ip = cloudflare.clean_public_ip(body.public_ip)
        token = cloudflare.clean_token(body.token) if body.token else None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if token is None and not (row and row.secret):
        raise HTTPException(422, "Enter the Cloudflare API token")
    old_zone = ((row.value if row else None) or {}).get("zone") or ""
    if old_zone and zone != old_zone:
        # Records Slipway keeps in the old zone would be looked for in the new one and forgotten as gone.
        users = await _zone_holders(db)
        if users:
            raise HTTPException(status.HTTP_409_CONFLICT, _zone_kept(users, old_zone))
    use = token or (row.secret if row else "") or ""
    await db.commit()  # release the DB connection during the HTTP calls
    try:
        async with cloudflare.CloudflareClient(use) as cf:
            if not await cf.verify_token():
                raise cloudflare.CloudflareError("Cloudflare says this token is not active")
            zone_id = await cf.zone_id(zone)
    except cloudflare.CloudflareError as exc:
        raise HTTPException(422, str(exc)) from exc
    users = await _zone_holders(db, zone_id)
    if users:
        # The zone this token finds isn't the one the records are in (a token for another account, say).
        raise HTTPException(status.HTTP_409_CONFLICT, _zone_kept(
            users, None, "or use a token that sees the zone they are in"))
    row = await _cloudflare_row(db)
    if row is None:
        row = AppSetting(key=cloudflare.SETTING_KEY, value={})
        db.add(row)
    row.value = {**(row.value or {}), "zone": zone, "zone_id": zone_id, "public_ip": public_ip,
                 "proxied": bool(body.proxied)}
    changed = [f"zone {zone}", f"public IP {public_ip}" if public_ip else "no public IP",
               "proxied" if body.proxied else "not proxied"]
    if token:
        row.secret = token
        changed.append("token replaced")
    audit.record(db, "settings.cloudflare", actor=ctx.user, request=request,
                 summary=f"Updated the Cloudflare integration ({', '.join(changed)})",
                 details={"zone": zone, "public_ip": public_ip, "proxied": bool(body.proxied),
                          "token_replaced": bool(token)})
    await db.commit()
    return _cloudflare_out(row)


@router.post("/cloudflare/test")
async def test_cloudflare(ctx: Admin, db: DB) -> dict[str, object]:
    config = await cloudflare.load_config(db)
    if config is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Save the Cloudflare zone and API token first")
    await db.commit()
    try:
        message = await cloudflare.check_connection(config)
    except cloudflare.CloudflareError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    return {"ok": True, "message": message}
