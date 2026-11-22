"""Provider accounts for every provider: DigitalOcean, Proxmox and ESXi (phase 4 §8 and §16, phase 5 §9.1 and §11).

Reads need ``providers:read``, every write ``providers:write`` (admin only). The rules are in
``services/provider_accounts.py``; this module maps them to HTTP: ``AccountInvalid`` is 422 with ``field``,
a refusal its own status (409 ``tls_untrusted`` and ``tls_mismatch`` carry the live certificate), and a
DigitalOcean API failure 502. ``POST /provider-accounts/test`` is registered before the ``/{id}`` routes.
``GET /provider-accounts/{id}/addresses`` lists a network's free pool addresses and their holders (phase 5 §11).
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Query, Request, status
from fastapi.responses import JSONResponse, Response

from slipway.api.deps import DB, not_found, require
from slipway.core.permissions import Perm
from slipway.models import ProviderAccount, ProviderKind
from slipway.schemas import (
    AccountDelete,
    AccountTestIn,
    AccountTestOut,
    ProviderAccountIn,
    ProviderAccountOut,
    ProviderAccountUpdate,
    TrustIn,
    provider_account_out,
)
from slipway.services import digitalocean
from slipway.services import provider_accounts as accounts
from slipway.services.auth import AuthContext
from slipway.services.vmtypes import AccountInvalid

router = APIRouter(prefix="/provider-accounts", tags=["provider accounts"])

Reader = Annotated[AuthContext, require(Perm.PROVIDERS_READ)]
Writer = Annotated[AuthContext, require(Perm.PROVIDERS_WRITE)]


def _refusal(exc: Exception) -> JSONResponse:
    if isinstance(exc, AccountInvalid):
        return JSONResponse({"detail": exc.text, "field": exc.field}, status_code=422)
    if isinstance(exc, accounts.AccountRefused):
        return JSONResponse(exc.body(), status_code=exc.status)
    if isinstance(exc, digitalocean.DigitalOceanError):
        return JSONResponse({"detail": str(exc)}, status_code=502)
    raise exc


async def _get(db: DB, account_id: uuid.UUID) -> ProviderAccount:
    account = await accounts.get(db, account_id)
    if account is None:
        raise not_found("Provider account")
    return account


async def _out(db: DB, account: ProviderAccount) -> Any:
    estimate = await accounts.estimate_cents(db, account.id) if account.provider == ProviderKind.DIGITALOCEAN else 0
    return provider_account_out(account, used_by=await accounts.used_by(db, account), estimate_cents=estimate)


def _fields(body: Any) -> dict[str, Any]:
    """The fields the request set (an omitted one keeps its value); a network's null keys are dropped."""
    fields = body.model_dump(exclude_unset=True)
    if fields.get("networks") is not None:
        fields["networks"] = [{k: v for k, v in net.items() if v is not None} for net in fields["networks"]]
    return fields


@router.get("")
async def list_accounts(ctx: Reader, db: DB, provider: Annotated[str | None, Query(max_length=16)] = None
                        ) -> list[ProviderAccountOut]:
    if provider is not None and provider not in accounts.PROVIDER_KINDS:
        return _refusal(AccountInvalid("provider", "Pick digitalocean, proxmox or esxi"))  # type: ignore[return-value]
    return [await _out(db, account) for account in await accounts.list_accounts(db, provider)]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_account(body: ProviderAccountIn, ctx: Writer, request: Request, db: DB,
                         background: BackgroundTasks) -> ProviderAccountOut:
    try:
        account = await accounts.create(db, _fields(body), actor=ctx.user, request=request)
    except (AccountInvalid, accounts.AccountRefused, digitalocean.DigitalOceanError) as exc:
        return _refusal(exc)  # type: ignore[return-value]
    if account.provider != ProviderKind.DIGITALOCEAN:
        # Phase 5 §9.1: a new Proxmox or ESXi account is tested once, after this answer.
        background.add_task(accounts.test_in_background, account.id, ctx.user.id if ctx.user else None)
    return await _out(db, account)


@router.post("/test")
async def test_unsaved(body: AccountTestIn, ctx: Writer) -> AccountTestOut:
    try:
        answer = await accounts.test_unsaved(body.secret, body.region)
    except (AccountInvalid, accounts.AccountRefused, digitalocean.DigitalOceanError) as exc:
        return _refusal(exc)  # type: ignore[return-value]
    return AccountTestOut(**answer.to_json())


@router.get("/{account_id}")
async def get_account(account_id: uuid.UUID, ctx: Reader, db: DB) -> ProviderAccountOut:
    return await _out(db, await _get(db, account_id))


@router.patch("/{account_id}")
async def update_account(account_id: uuid.UUID, body: ProviderAccountUpdate, ctx: Writer, request: Request,
                         db: DB) -> ProviderAccountOut:
    account = await _get(db, account_id)
    try:
        account = await accounts.update(db, account, _fields(body), actor=ctx.user, request=request)
    except (AccountInvalid, accounts.AccountRefused, digitalocean.DigitalOceanError) as exc:
        await db.rollback()
        return _refusal(exc)  # type: ignore[return-value]
    return await _out(db, account)


@router.delete("/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_account(account_id: uuid.UUID, ctx: Writer, request: Request, db: DB,
                         body: AccountDelete | None = None) -> Response:
    account = await _get(db, account_id)
    try:
        await accounts.remove(db, account, body.confirm if body else None, actor=ctx.user, request=request)
    except (AccountInvalid, accounts.AccountRefused) as exc:
        await db.rollback()
        return _refusal(exc)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{account_id}/test")
async def test_account(account_id: uuid.UUID, ctx: Writer, request: Request, db: DB) -> AccountTestOut:
    account = await _get(db, account_id)
    try:
        answer = await accounts.test(db, account, actor=ctx.user, request=request)
    except (AccountInvalid, accounts.AccountRefused, digitalocean.DigitalOceanError) as exc:
        await db.rollback()
        return _refusal(exc)  # type: ignore[return-value]
    return AccountTestOut(**answer.to_json())


@router.post("/{account_id}/trust")
async def trust_account(account_id: uuid.UUID, body: TrustIn, ctx: Writer, request: Request,
                        db: DB) -> ProviderAccountOut:
    account = await _get(db, account_id)
    try:
        account = await accounts.trust(db, account, body.fingerprint, actor=ctx.user, request=request)
    except (AccountInvalid, accounts.AccountRefused) as exc:
        await db.rollback()
        return _refusal(exc)  # type: ignore[return-value]
    return await _out(db, account)


@router.get("/{account_id}/catalog")
async def account_catalog(account_id: uuid.UUID, ctx: Reader, db: DB,
                          region: Annotated[str | None, Query(max_length=20)] = None) -> dict[str, Any]:
    account = await _get(db, account_id)
    await db.commit()  # no transaction stays open while DigitalOcean answers
    try:
        built = await accounts.catalog(account, region)
    except (AccountInvalid, accounts.AccountRefused, digitalocean.DigitalOceanError) as exc:
        return _refusal(exc)  # type: ignore[return-value]
    return accounts.catalog_out(built)


@router.get("/{account_id}/addresses")
async def account_addresses(account_id: uuid.UUID, ctx: Reader, db: DB,
                            network: Annotated[str | None, Query(max_length=40)] = None,
                            count: Annotated[int, Query()] = accounts.ADDRESS_COUNT) -> dict[str, Any]:
    """Phase 5 §11: ``{network, subnet, pool, free: [ip], in_use: [{address, by, text}]}`` for a Proxmox or ESXi
    account's network, from Slipway's records (no probe). The create flow and Add a slot offer ``free``."""
    account = await _get(db, account_id)
    try:
        return await accounts.addresses(db, account, network, count)
    except (AccountInvalid, accounts.AccountRefused) as exc:
        return _refusal(exc)  # type: ignore[return-value]
