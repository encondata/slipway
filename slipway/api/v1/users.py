"""Admin user management."""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Annotated

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from slipway.api.deps import DB, not_found, require
from slipway.core.permissions import Perm, has_permission
from slipway.core.security import hash_password_async
from slipway.models import ApiToken, OAuthAccount, Role, User
from slipway.schemas import TokenOut, UserCreate, UserOut, UserUpdate
from slipway.services import audit
from slipway.services.auth import AuthContext, revoke_user_credentials
from slipway.services.github import GitHubClient, GitHubError
from slipway.services.repos import github_token_for
from slipway.services.users import UserError, check_password_strength, create_user, ensure_not_last_admin

router = APIRouter(prefix="/users", tags=["users"])

Reader = Annotated[AuthContext, require(Perm.USERS_READ)]
Writer = Annotated[AuthContext, require(Perm.USERS_WRITE)]


def _check_grantable(roles: Iterable[Role], actor: User, verb: str = "grant") -> None:
    # No privilege escalation: you may only grant or take away permissions you hold yourself.
    for role in roles:
        if not all(has_permission(actor.permissions, p) for p in role.permissions):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"You cannot {verb} the '{role.name}' role")


def _ensure_can_manage(actor: User, target: User) -> None:
    """users:write only reaches users whose every permission the actor holds too."""
    if target.id != actor.id and not all(has_permission(actor.permissions, p) for p in target.permissions):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You cannot manage a user who has permissions you don't have")


async def _roles(db: DB, names: list[str], actor: User) -> list[Role]:
    roles = (await db.scalars(select(Role).where(Role.name.in_(names)))).all()
    missing = set(names) - {r.name for r in roles}
    if missing:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown role(s): {', '.join(sorted(missing))}")
    _check_grantable(roles, actor)
    return list(roles)


async def _get(db: DB, user_id: uuid.UUID) -> User:
    user = await db.get(User, user_id)
    if user is None:
        raise not_found("User")
    return user


@router.get("")
async def list_users(ctx: Reader, db: DB) -> list[UserOut]:
    users = (await db.scalars(select(User).order_by(User.created_at))).all()
    return [UserOut.of(u) for u in users]


async def _resolve_github(db: DB, login: str, actor: User) -> OAuthAccount:
    token, _ = github_token_for(actor)
    await db.commit()  # don't hold a pooled connection across the GitHub call
    try:
        async with GitHubClient(token) as gh:
            profile = await gh.get_user_by_login(login)
    except GitHubError as exc:
        if exc.status_code == 404:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"GitHub user @{login} not found") from exc
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Could not reach GitHub; try again") from exc
    gh_id = str(profile["id"])
    taken = await db.scalar(
        select(OAuthAccount).where(OAuthAccount.provider == "github", OAuthAccount.provider_user_id == gh_id)
    )
    if taken is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"@{profile['login']} is already linked to another account")
    return OAuthAccount(provider="github", provider_user_id=gh_id, login=profile["login"])


@router.post("", status_code=201)
async def create(body: UserCreate, ctx: Writer, request: Request, db: DB) -> UserOut:
    if not body.password and not body.github_login:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Give the user a password or a GitHub username to sign in with")
    await _roles(db, body.roles, ctx.user)
    account = await _resolve_github(db, body.github_login, ctx.user) if body.github_login else None
    try:
        # An empty roles list means no roles; create_user only fills in the default for None.
        user = await create_user(
            db, email=str(body.email), password=body.password, full_name=body.full_name, role_names=body.roles,
            allow_first_admin=False,
        )
    except UserError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if account is not None:
        user.oauth_accounts.append(account)
    audit.record(db, "user.create", actor=ctx.user, target=user, summary=f"Created {user.email}", request=request)
    await db.commit()
    return UserOut.of(user)


@router.get("/{user_id}")
async def get_user(user_id: uuid.UUID, ctx: Reader, db: DB) -> UserOut:
    return UserOut.of(await _get(db, user_id))


@router.patch("/{user_id}")
async def update(user_id: uuid.UUID, body: UserUpdate, ctx: Writer, request: Request, db: DB) -> UserOut:
    user = await _get(db, user_id)
    _ensure_can_manage(ctx.user, user)
    if body.password and user.id == ctx.user.id:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Change your own password from your profile (POST /api/v1/auth/me/password)"
        )
    revoke = reset = False
    try:
        password_hash = None
        if body.password:
            check_password_strength(body.password)
            password_hash = await hash_password_async(body.password)
        if body.roles is not None:
            new_roles = await _roles(db, body.roles, ctx.user)
            _check_grantable([r for r in user.roles if r.name not in body.roles], ctx.user, "remove")
            if "admin" not in body.roles:
                await ensure_not_last_admin(db, user)
            user.roles = new_roles
        if body.is_active is not None and body.is_active != user.is_active:
            if user.id == ctx.user.id:
                raise UserError("You cannot deactivate your own account")
            if not body.is_active:
                await ensure_not_last_admin(db, user)
                revoke = True
            elif user.password_hash is None and user.github is None and user.hackspacelabs is None and password_hash is None:
                # Deactivation unlinked GitHub, so a GitHub-only account would come back with no way in.
                raise UserError(
                    f"{user.email} has no password or GitHub link to sign in with (deactivating unlinks GitHub); "
                    "set a password to reactivate it"
                )
            user.is_active = body.is_active
        if body.full_name is not None:
            user.full_name = body.full_name.strip()
        if password_hash is not None:
            user.password_hash = password_hash
            revoke = reset = True
    except UserError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if revoke:
        # A reset or deactivation must cut off every credential: sessions, API tokens and GitHub links. A reset also
        # unlinks HackSpaceLabs; deactivation keeps that link, so the person's next sign-in finds this (inactive)
        # account instead of being given a new one.
        unlinked = await revoke_user_credentials(db, user, reset=reset)
        for login in unlinked:
            audit.record(db, "user.hackspacelabs_unlinked", actor=ctx.user, target=user,
                         summary=f"Unlinked HackSpaceLabs account {login} from {user.email} (password reset)", request=request)
    details = body.model_dump(exclude_none=True, exclude={"password"})
    if body.password:
        details["password_reset"] = True
    audit.record(
        db, "user.update", actor=ctx.user, target=user, summary=f"Updated {user.email}", details=details, request=request
    )
    await db.commit()
    await db.refresh(user)
    return UserOut.of(user)


@router.delete("/{user_id}", status_code=204)
async def delete(user_id: uuid.UUID, ctx: Writer, request: Request, db: DB) -> None:
    user = await _get(db, user_id)
    if user.id == ctx.user.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot delete your own account")
    _ensure_can_manage(ctx.user, user)
    try:
        await ensure_not_last_admin(db, user)
    except UserError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    audit.record(db, "user.delete", actor=ctx.user, target=user, summary=f"Deleted {user.email}", request=request)
    await db.delete(user)
    await db.commit()


@router.delete("/{user_id}/github", status_code=204)
async def unlink_user_github(user_id: uuid.UUID, ctx: Writer, request: Request, db: DB) -> None:
    """Remove a user's GitHub link (one they did not add, say) without deleting the account.

    Only the link goes; their password, sessions and API tokens stay. A user with no password is
    refused, since the link is their only way in: a password reset sets one, signs them out,
    deletes their API tokens and unlinks GitHub (the users page offers that instead).
    """
    user = await _get(db, user_id)
    if user.id == ctx.user.id:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Unlink your own GitHub from your profile (DELETE /api/v1/auth/me/github)"
        )
    _ensure_can_manage(ctx.user, user)
    account = user.github
    if account is None:
        return
    if user.password_hash is None and user.hackspacelabs is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"{user.email} has no password and could no longer sign in; reset their password instead, "
            "which also unlinks GitHub",
        )
    user.oauth_accounts.remove(account)
    audit.record(
        db, "user.github_unlinked", actor=ctx.user, target=user,
        summary=f"Unlinked @{account.login} from {user.email}", request=request,
    )
    await db.commit()


@router.get("/{user_id}/tokens")
async def list_user_tokens(user_id: uuid.UUID, ctx: Writer, db: DB) -> list[TokenOut]:
    user = await _get(db, user_id)
    _ensure_can_manage(ctx.user, user)
    tokens = await db.scalars(
        select(ApiToken).where(ApiToken.user_id == user.id).order_by(ApiToken.created_at.desc())
    )
    return [TokenOut.model_validate(t) for t in tokens]


@router.delete("/{user_id}/tokens/{token_id}", status_code=204)
async def revoke_user_token(user_id: uuid.UUID, token_id: uuid.UUID, ctx: Writer, request: Request, db: DB) -> None:
    user = await _get(db, user_id)
    _ensure_can_manage(ctx.user, user)
    token = await db.get(ApiToken, token_id)
    if token is None or token.user_id != user.id:
        raise not_found("Token")
    audit.record(
        db, "token.revoke", actor=ctx.user, target=token,
        summary=f"Revoked API token {token.name} of {user.email}", request=request,
    )
    await db.delete(token)
    await db.commit()
