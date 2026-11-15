"""Command-line helpers: ``slipway serve``, ``slipway migrate``, ``slipway create-admin``, ``slipway generate-secrets``,
``slipway rotate-encryption-key``."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import secrets
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.fernet import Fernet

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def generate_secrets() -> None:
    print(f"SLIPWAY_SECRET_KEY={secrets.token_urlsafe(48)}")
    print(f"SLIPWAY_ENCRYPTION_KEY={Fernet.generate_key().decode()}")
    print(f"POSTGRES_PASSWORD={secrets.token_urlsafe(24)}")


def migrate() -> None:
    from alembic import command
    from alembic.config import Config

    # alembic.ini lives in the project root (/app in the Docker image), not in site-packages.
    candidates = [Path(os.environ.get("SLIPWAY_ALEMBIC_INI", "alembic.ini")), Path(__file__).resolve().parent.parent / "alembic.ini"]
    ini = next((p for p in candidates if p.is_file()), None)
    if ini is None:
        sys.exit("alembic.ini not found; run from the project root or set SLIPWAY_ALEMBIC_INI")
    command.upgrade(Config(str(ini)), "head")


def _read_password() -> str:
    from slipway.services.users import UserError

    try:
        password = getpass.getpass("Password (10+ characters): ")
        # A password piped in on stdin is read once; only a typed one is confirmed.
        if sys.stdin.isatty() and getpass.getpass("Repeat password: ") != password:
            raise UserError("Passwords do not match")
    except EOFError:
        raise UserError("No password given") from None
    return password


async def _password_needed(db: AsyncSession, args: argparse.Namespace) -> bool:
    """create-admin prompts for a new account, or with --reset-password, unless --password was given."""
    from slipway.services.users import get_user_by_email

    if args.password:
        return False
    return args.reset_password or await get_user_by_email(db, args.email) is None


async def _ensure_admin(db: AsyncSession, args: argparse.Namespace) -> list[str]:
    """Create ``args.email`` as an admin, or grant admin to the existing account. Returns what was done."""
    from sqlalchemy import delete, func, select

    from slipway.core.security import hash_password
    from slipway.models import ApiToken, UserSession
    from slipway.services import audit
    from slipway.services.auth import revoke_user_github, revoke_user_sessions
    from slipway.services.users import (
        UserError,
        check_password_strength,
        create_user,
        get_role,
        get_user_by_email,
        seed_system_roles,
    )

    await seed_system_roles(db)
    user = await get_user_by_email(db, args.email)
    if user is None:
        if not args.password:
            raise UserError("A new account needs a password")
        user = await create_user(
            db, email=args.email, password=args.password, full_name=args.name, role_names=["admin"],
            allow_first_admin=True,
        )
        audit.record(db, "user.create", target=user, summary=f"Created admin {user.email} with slipway create-admin")
        return [f"Created admin {user.email}."]

    if args.password and not args.reset_password:
        raise UserError(f"{user.email} already exists; add --reset-password to change its password. Nothing was changed.")
    new_password = args.password if args.reset_password else None
    if args.reset_password:
        check_password_strength(new_password or "")
    # Deactivation unlinks GitHub, so a deactivated GitHub-only account has no way to sign in left.
    no_way_in = new_password is None and user.password_hash is None and user.github is None
    if no_way_in and not user.is_active and args.activate:
        raise UserError(
            f"{user.email} has no password or GitHub link to sign in with; add --reset-password to reactivate it. "
            "Nothing was changed."
        )

    github = f"@{user.github.login}" if user.github else "none"
    lines = [
        f"{user.email} already exists (created {user.created_at:%Y-%m-%d}, active: {'yes' if user.is_active else 'no'}, "
        f"password: {'set' if user.password_hash else 'none'}, GitHub: {github})."
    ]
    changes = []
    admin = await get_role(db, "admin")
    if admin in user.roles:
        lines.append("Already an admin.")
    else:
        user.roles.append(admin)
        changes.append("granted admin")
        lines.append("Granted the admin role.")

    if new_password is None:
        lines.append("Password NOT changed (use --reset-password to set a new one).")
        if no_way_in:
            lines.append("It has no password or GitHub link, so nobody can sign in to it (use --reset-password).")
    else:
        user.password_hash = hash_password(new_password)
        sessions = await db.scalar(select(func.count()).select_from(UserSession).where(UserSession.user_id == user.id))
        await revoke_user_sessions(db, user)
        tokens = (await db.execute(delete(ApiToken).where(ApiToken.user_id == user.id))).rowcount
        # A GitHub link is a credential too: one planted with a stolen session must not survive the reset.
        unlinked = await revoke_user_github(db, user)
        changes.append("password reset")
        lines.append(f"Password reset; signed out {sessions} session(s) and deleted {tokens} API token(s).")
        if unlinked:
            lines.append(
                f"Unlinked GitHub {', '.join(f'@{login}' for login in unlinked)}; "
                "the owner can link it again from Settings -> Profile after signing in with the new password."
            )

    if not user.is_active and args.activate:
        user.is_active = True
        changes.append("reactivated")
        lines.append("Account reactivated.")
    elif not user.is_active:
        lines.append("Account is still INACTIVE and cannot sign in (use --activate).")

    if changes:
        audit.record(db, "user.update", target=user, summary=f"slipway create-admin: {', '.join(changes)}")
    return lines


async def _with_db[T](action: Callable[[AsyncSession, argparse.Namespace], Awaitable[T]], args: argparse.Namespace) -> T:
    """Run ``action`` in one committed session, then close the engine (each CLI command runs its own loop)."""
    from slipway.db.session import dispose_engine, get_sessionmaker

    try:
        async with get_sessionmaker()() as db:
            result = await action(db, args)
            await db.commit()
            return result
    finally:
        await dispose_engine()


def create_admin(args: argparse.Namespace) -> None:
    from slipway.services.users import UserError

    try:
        # Prompt outside the event loop so Ctrl-C at the prompt stops the command straight away.
        if asyncio.run(_with_db(_password_needed, args)):
            args.password = _read_password()
        lines = asyncio.run(_with_db(_ensure_admin, args))
    except UserError as exc:
        sys.exit(f"Error: {exc}")
    except KeyboardInterrupt:
        sys.exit("\nCancelled; nothing was changed.")
    print("\n".join(lines))


_REENTER_COLUMNS = {("instances", "env"), ("instances", "app_secrets")}


async def _rotate_secrets(db: AsyncSession, *, clear_unreadable: bool = False) -> tuple[int, list[str]]:
    """Re-encrypt every stored secret with the first key, bypassing the ORM types.

    Returns the number re-encrypted and a description of each value no configured key could decrypt.
    """
    from sqlalchemy import Text, column, select, table, update

    import slipway.models  # noqa: F401  (registers every table on Base.metadata)
    from slipway.core.crypto import DecryptionError, encrypt, encrypted_columns, rotate
    from slipway.db.base import Base

    rotated, unreadable = 0, []
    for source, col in encrypted_columns(Base.metadata):
        raw = table(source.name, column("id", source.c.id.type), column(col.name, Text()))
        value_col = raw.c[col.name]
        rows = (await db.execute(select(raw.c.id, value_col).where(value_col.is_not(None)).with_for_update())).all()
        for row_id, token in rows:
            try:
                new = rotate(token)
            except DecryptionError:
                unreadable.append(f"{source.name}.{col.name} (id {row_id})")
                if not clear_unreadable:
                    continue
                # Instance env and app secrets become an encrypted JSON null, not NULL: the deployer treats
                # that as "needs re-entry" and refuses to deploy, instead of deploying with no variables or
                # generating new secrets the app's existing data won't open with.
                new = encrypt("null") if (source.name, col.name) in _REENTER_COLUMNS else None
            else:
                rotated += 1
            await db.execute(update(raw).where(raw.c.id == row_id).values({col.name: new}))
    return rotated, unreadable


def rotate_encryption_key(args: argparse.Namespace) -> None:
    rotated, unreadable = asyncio.run(
        _with_db(lambda db, a: _rotate_secrets(db, clear_unreadable=a.clear_unreadable), args)
    )
    print(f"Re-encrypted {rotated} secret(s) with the first SLIPWAY_ENCRYPTION_KEY.")
    if not unreadable:
        print("Older keys can now be removed from SLIPWAY_ENCRYPTION_KEY.")
        return
    if args.clear_unreadable:
        print(f"Erased {len(unreadable)} secret(s) no configured key could decrypt; re-enter them in Slipway.")
        print("Instances listed here refuse to deploy until their variables are re-entered or cleared, or, for")
        print("app secrets, until each secret is set as an instance variable (its old value, to keep the app's data):")
        print("\n".join(f"  {u}" for u in unreadable))
        return
    print(f"{len(unreadable)} secret(s) could not be decrypted with any configured key and were left unchanged:")
    print("\n".join(f"  {u}" for u in unreadable))
    sys.exit(
        "Keep the old key: add it after the new one in SLIPWAY_ENCRYPTION_KEY and run this again. "
        "If it is lost, re-enter those secrets in Slipway or rerun with --clear-unreadable."
    )


def serve(args: argparse.Namespace) -> None:
    import uvicorn

    from slipway.core.config import get_settings

    uvicorn.run(
        "slipway.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        proxy_headers=True,
        forwarded_allow_ips=get_settings().forwarded_allow_ips,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="slipway", description="Slipway management commands")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("serve", help="Run the web server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--reload", action="store_true")

    sub.add_parser("migrate", help="Apply database migrations")
    sub.add_parser(
        "generate-secrets", help="Print fresh SLIPWAY_SECRET_KEY / SLIPWAY_ENCRYPTION_KEY / POSTGRES_PASSWORD values"
    )

    p = sub.add_parser("create-admin", help="Create an admin user, or grant admin to an existing one")
    p.add_argument("email")
    p.add_argument("--name", default="Administrator", help="Full name for a new account")
    p.add_argument("--password", help="Password for a new account (prompted for if omitted), or with --reset-password")
    p.add_argument(
        "--reset-password",
        action="store_true",
        help="Existing account: set a new password, sign out its sessions, delete its API tokens and unlink GitHub",
    )
    p.add_argument("--activate", action="store_true", help="Existing account: reactivate it if it was deactivated")

    p = sub.add_parser(
        "rotate-encryption-key", help="Re-encrypt stored secrets with the first key in SLIPWAY_ENCRYPTION_KEY"
    )
    p.add_argument(
        "--clear-unreadable",
        action="store_true",
        help="Erase secrets no configured key can decrypt (they must then be re-entered)",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "serve":
        serve(args)
    elif args.command == "migrate":
        migrate()
    elif args.command == "generate-secrets":
        generate_secrets()
    elif args.command == "create-admin":
        create_admin(args)
    elif args.command == "rotate-encryption-key":
        rotate_encryption_key(args)


if __name__ == "__main__":
    main()
