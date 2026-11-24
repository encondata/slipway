"""Command-line helpers: ``slipway serve``, ``slipway migrate``, ``slipway create-admin``, ``slipway generate-secrets``,
``slipway rotate-encryption-key``, ``slipway snapshot pack``."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import re
import secrets
import socket
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
    from slipway.services.auth import revoke_user_github, revoke_user_hackspacelabs, revoke_user_sessions
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
    # Deactivation unlinks GitHub, so a deactivated GitHub-only account has no way to sign in left. A HackSpaceLabs
    # link survives deactivation and is a way in.
    no_way_in = new_password is None and user.password_hash is None and user.github is None and user.hackspacelabs is None
    if no_way_in and not user.is_active and args.activate:
        raise UserError(
            f"{user.email} has no password or GitHub link to sign in with; add --reset-password to reactivate it. "
            "Nothing was changed."
        )

    github = f"@{user.github.login}" if user.github else "none"
    lines = [
        f"{user.email} already exists (created {user.created_at:%Y-%m-%d}, active: {'yes' if user.is_active else 'no'}, "
        f"password: {'set' if user.password_hash else 'none'}, GitHub: {github}"
        + (f", HackSpaceLabs: {user.hackspacelabs.login}" if user.hackspacelabs else "") + ")."
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
        # So is a HackSpaceLabs link: with it, the new password could not be used (it signs in only there).
        if unlinked_hsl := await revoke_user_hackspacelabs(db, user):
            changes.append("HackSpaceLabs unlinked")
            lines.append(
                f"Unlinked HackSpaceLabs {', '.join(unlinked_hsl)}; the account signs in with the new password now, "
                "and the owner can link HackSpaceLabs again from Settings -> Profile."
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


_REENTER_COLUMNS = {
    ("instances", "env"),
    ("instances", "app_secrets"),
    ("instances", "live_identity"),
    # An environment's variables and shared secrets (phase 3 D5): its member jobs refuse to run rather
    # than regenerate secrets the environment's data won't open with.
    ("environments", "env"),
    ("environments", "app_secrets"),
}


class RotationRefused(RuntimeError):
    """rotate-encryption-key --clear-unreadable would erase something Slipway can't work without."""


_TERRAFORM_STATE_LOST = (
    "Slipway can't read the Terraform state of {vm} with any key in SLIPWAY_ENCRYPTION_KEY. "
    "Put the old key back first; without the state Slipway can't remove the VM"
)


async def _refuse_lost_terraform_states(db: AsyncSession) -> None:
    """--clear-unreadable never erases a VM's Terraform state: without it Slipway can't remove the VM."""
    from sqlalchemy import text

    from slipway.core.crypto import DecryptionError, decrypt

    rows = (await db.execute(text(
        "SELECT m.name, t.state FROM terraform_states t JOIN machines m ON m.id = t.machine_id "
        "WHERE t.state IS NOT NULL ORDER BY m.name"
    ))).all()
    lost = []
    for name, token in rows:
        try:
            decrypt(token)
        except DecryptionError:
            lost.append(name)
    if lost:
        raise RotationRefused(_TERRAFORM_STATE_LOST.format(vm=", ".join(lost)))


_OWNED_HOST_KEY_KEPT = (
    "Kept the SSH key of {n} host(s) Slipway made, which no configured key can read: Slipway made them, so the "
    "key can't be entered again by hand. Put the old key back after the new one in SLIPWAY_ENCRYPTION_KEY and "
    "run this again to re-encrypt it; until then Slipway can't reach them:"
)


async def _owned_host_ids(db: AsyncSession) -> set[object]:
    """The hosts an environment made (a droplet or a VM): --clear-unreadable never erases their SSH key, since
    the host page refuses a key for such a host and nothing else can set it again. It keeps the value as it is
    (still readable with the old key) and lists the host, and the rest of the rotation goes ahead (F20)."""
    from sqlalchemy import select

    from slipway.db.base import Base

    hosts = Base.metadata.tables["hosts"]  # its id and owner only: no encrypted column is read
    return set((await db.execute(select(hosts.c.id).where(hosts.c.owner_environment_id.is_not(None)))).scalars())


async def _rotate(
    db: AsyncSession, *, clear_unreadable: bool = False
) -> tuple[int, list[str], list[tuple[str, str, object]]]:
    """Re-encrypt every stored secret with the first key, bypassing the ORM types.

    Returns the number re-encrypted, a description of each value no configured key could decrypt, and
    (with ``clear_unreadable``) the (table, column, primary key) of each value erased. Each table is
    updated by its own primary key (terraform_states has machine_id, not id).
    """
    from sqlalchemy import Text, case, column, select, table, update

    import slipway.models  # noqa: F401  (registers every table on Base.metadata)
    from slipway.core.crypto import DecryptionError, encrypt, encrypted_columns, rotate
    from slipway.db.base import Base

    if clear_unreadable and "terraform_states" in Base.metadata.tables:
        await _refuse_lost_terraform_states(db)
    owned = await _owned_host_ids(db) if clear_unreadable and "hosts" in Base.metadata.tables else set()

    rotated, unreadable, cleared, kept = 0, [], [], []
    for source, col in encrypted_columns(Base.metadata):
        (pk,) = source.primary_key.columns
        extra = [column("status", Text()), column("location", Text())] if source.name == "backups" else []
        raw = table(source.name, column(pk.name, pk.type), column(col.name, Text()), *extra)
        key_col, value_col = raw.c[pk.name], raw.c[col.name]
        rows = (await db.execute(select(key_col, value_col).where(value_col.is_not(None)).with_for_update())).all()
        for row_id, token in rows:
            values: dict[str, object]
            try:
                values = {col.name: rotate(token)}
            except DecryptionError:
                if clear_unreadable and (source.name, col.name) == ("hosts", "private_key") and row_id in owned:
                    kept.append(row_id)  # left as it is: see _owned_host_ids
                    continue
                unreadable.append(f"{source.name}.{col.name} ({pk.name} {row_id})")
                if not clear_unreadable:
                    continue
                cleared.append((source.name, col.name, row_id))
                # Instance and environment env and app secrets become an encrypted JSON null, not NULL: the
                # deployer treats that as "needs re-entry" and refuses to deploy, instead of deploying with no
                # variables or generating new secrets the app's existing data won't open with. Everything
                # else (a provider account's secret among them) becomes NULL: an encrypted null would read
                # as a secret that is set.
                values = {col.name: encrypt("null") if (source.name, col.name) in _REENTER_COLUMNS else None}
                if (source.name, col.name) == ("backups", "data_key"):
                    # A backup on the Slipway server without its key can only be deleted; it can't stay
                    # ready (ck_backups_slipway_key).
                    values["status"] = case(
                        ((raw.c.location == "slipway") & (raw.c.status == "ready"), "changed"), else_=raw.c.status
                    )
            else:
                rotated += 1
            await db.execute(update(raw).where(key_col == row_id).values(values))
    return rotated, unreadable, cleared, kept


async def _rotate_secrets(db: AsyncSession, *, clear_unreadable: bool = False) -> tuple[int, list[str]]:
    """Re-encrypt every stored secret with the first key, bypassing the ORM types.

    Returns the number re-encrypted and a description of each value no configured key could decrypt.
    Raises RotationRefused (changing nothing) when --clear-unreadable would erase a Terraform state; the SSH
    key of a host an environment made is kept as it is (``_owned_host_ids``).
    """
    rotated, unreadable, _, _ = await _rotate(db, clear_unreadable=clear_unreadable)
    return rotated, unreadable


_SNAPSHOT_KEY_LOST = "Its key was lost with an old SLIPWAY_ENCRYPTION_KEY; delete it"
_FIRST_ADMIN_PASSWORD_LOST = "Set the password again"
# What a provider account whose secret was erased shows until a person enters it again.
_ACCOUNT_SECRET_LOST = "The {what} couldn't be read after a key change: enter it again"


def _secret_word(provider: str) -> str:
    return "password" if provider == "esxi" else "token"


async def _fix_up_cleared(db: AsyncSession, cleared: list[tuple[str, str, object]] | None = None) -> list[str]:
    """After --clear-unreadable, mark rows whose erased secret they can't work without. Returns what was done.

    ``cleared`` is what the rotation erased, as (table, column, primary key). Raw SQL by table name, like
    the column loop: the ORM types would turn unreadable values into None.
    """
    from sqlalchemy import Text, column, select, table, text, update

    import slipway.models  # noqa: F401  (registers every table on Base.metadata)
    from slipway.db.base import Base, JSONType

    lines: list[str] = []
    tables = Base.metadata.tables
    if "snapshots" in tables:
        # A ready snapshot without its data key can never be opened again: its .sbx is ciphertext only.
        lost = (await db.execute(text(
            "SELECT name FROM snapshots WHERE status = 'ready' AND data_key IS NULL ORDER BY name"
        ))).scalars().all()
        if lost:
            await db.execute(
                text("UPDATE snapshots SET status = 'failed', error = :error WHERE status = 'ready' AND data_key IS NULL"),
                {"error": _SNAPSHOT_KEY_LOST},
            )
            lines.append(f"Marked {len(lost)} snapshot(s) failed; their key was lost, so delete them on the Snapshots page:")
            lines.extend(f"  {name}" for name in lost)
    if "first_admins" in tables:
        where = "status = 'pending' AND mode = 'password' AND password IS NULL"
        waiting = (await db.execute(text(f"SELECT instance_id FROM first_admins WHERE {where}"))).scalars().all()
        if waiting:
            await db.execute(text(f"UPDATE first_admins SET last_error = :error WHERE {where}"),
                             {"error": _FIRST_ADMIN_PASSWORD_LOST})
            lines.append(
                f"{len(waiting)} first admin(s) waiting to be created lost their password; "
                "set it again on the instance's page:"
            )
            lines.extend(f"  first_admins (instance {instance_id})" for instance_id in waiting)
    backups = [row_id for name, col, row_id in cleared or () if (name, col) == ("backups", "data_key")]
    if backups:
        lines.append(
            f"{len(backups)} backup(s) lost the key their files on this Slipway server are under; "
            "they can only be deleted now."
        )
    vm_snapshots = [row_id for name, col, row_id in cleared or () if (name, col) == ("machine_snapshots", "identity")]
    if vm_snapshots and "machine_snapshots" in tables:
        # The VM's data in such a snapshot was made with identity values Slipway no longer has: a revert would
        # bring that data back under today's secrets, so the revert refuses it and it can only be deleted.
        source = tables["machine_snapshots"]
        raw = table("machine_snapshots", column("id", source.c.id.type), column("name", Text()),
                    column("status", Text()))
        lost_names = (await db.execute(
            select(raw.c.name).where(raw.c.id.in_(vm_snapshots)).order_by(raw.c.name)
        )).scalars().all()
        await db.execute(update(raw).where(raw.c.id.in_(vm_snapshots)).values(status="failed"))
        lines.append(f"Marked {len(lost_names)} VM snapshot(s) failed; their identity values were lost, so they can't "
                     "be reverted to. Delete them on the environment's page:")
        lines.extend(f"  {name}" for name in lost_names)
    accounts = [row_id for name, col, row_id in cleared or () if (name, col) == ("provider_accounts", "secret")]
    if accounts and "provider_accounts" in tables:
        source = tables["provider_accounts"]
        raw = table("provider_accounts", column("id", source.c.id.type), column("name", Text()),
                    column("provider", Text()), column("status", Text()), column("checks", JSONType))
        rows = (await db.execute(
            select(raw.c.id, raw.c.name, raw.c.provider).where(raw.c.id.in_(accounts)).order_by(raw.c.name)
        )).all()
        for row_id, _, provider in rows:
            check = {"name": "secret", "ok": False, "level": "error",
                     "text": _ACCOUNT_SECRET_LOST.format(what=_secret_word(provider))}
            await db.execute(update(raw).where(raw.c.id == row_id).values(status="error", checks=[check]))
        lines.append(
            f"{len(rows)} provider account(s) lost their token or password; enter it again on the Integrations page:"
        )
        lines.extend(f"  {name} ({provider})" for _, name, provider in rows)
    return lines


async def _rotate_all(db: AsyncSession, args: argparse.Namespace) -> tuple[int, list[str], list[str]]:
    rotated, unreadable, cleared, kept = await _rotate(db, clear_unreadable=args.clear_unreadable)
    fixed = await _fix_up_cleared(db, cleared) if args.clear_unreadable else []
    if kept:
        from sqlalchemy import select

        from slipway.db.base import Base

        hosts = Base.metadata.tables["hosts"]
        names = (await db.execute(select(hosts.c.name).where(hosts.c.id.in_(kept)).order_by(hosts.c.name))).scalars()
        fixed = [_OWNED_HOST_KEY_KEPT.format(n=len(kept)), *(f"  {name}" for name in names), *fixed]
    return rotated, unreadable, fixed


def rotate_encryption_key(args: argparse.Namespace) -> None:
    try:
        rotated, unreadable, fixed = asyncio.run(_with_db(_rotate_all, args))
    except RotationRefused as exc:
        sys.exit(f"Nothing was changed. {exc}")
    print(f"Re-encrypted {rotated} secret(s) with the first SLIPWAY_ENCRYPTION_KEY.")
    kept = bool(fixed) and fixed[0].startswith("Kept the SSH key")
    if not unreadable:
        if not kept:
            print("Older keys can now be removed from SLIPWAY_ENCRYPTION_KEY.")
        if fixed:
            print("\n".join(fixed))
        return
    if args.clear_unreadable:
        print(f"Erased {len(unreadable)} secret(s) no configured key could decrypt; re-enter them in Slipway.")
        print("Instances listed here refuse to deploy until their variables are re-entered or cleared, or, for")
        print("app secrets, until each secret is set as an instance variable (its old value, to keep the app's data):")
        print("\n".join(f"  {u}" for u in unreadable))
        if any(u.startswith("environments.") for u in unreadable):
            print("Environments listed here refuse their jobs until their variables are re-entered in the")
            print("environment's settings, or, for environments.app_secrets, until each secret is set as a variable")
            print("of the environment (its old value); the next deploy in it then keeps them as its secrets.")
        if fixed:
            print("\n".join(fixed))
        return
    print(f"{len(unreadable)} secret(s) could not be decrypted with any configured key and were left unchanged:")
    print("\n".join(f"  {u}" for u in unreadable))
    sys.exit(
        "Keep the old key: add it after the new one in SLIPWAY_ENCRYPTION_KEY and run this again. "
        "If it is lost, re-enter those secrets in Slipway or rerun with --clear-unreadable."
    )


_ENV_FILE_LINE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def _read_env_file(path: str) -> dict[str, str]:
    """KEY=VALUE lines (``export`` and one pair of matching quotes allowed; # comments). Values are secrets:
    no message quotes them."""
    from slipway.services.snapfile import SnapshotError

    values: dict[str, str] = {}
    with open(path, encoding="utf-8") as f:
        for number, line in enumerate(f, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = _ENV_FILE_LINE.match(stripped)
            if match is None:
                raise SnapshotError(f"{path} line {number} isn't KEY=VALUE")
            key, value = match.group(1), match.group(2).strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            values[key] = value
    return values


def _read_passphrase() -> str:
    """One line from stdin (--passphrase-stdin). Typed at a terminal, it is asked twice."""
    from slipway.services.snapfile import SnapshotError

    if sys.stdin.isatty():
        passphrase = getpass.getpass("Passphrase (12+ characters): ")
        if getpass.getpass("Repeat passphrase: ") != passphrase:
            raise SnapshotError("The passphrases don't match")
        return passphrase
    line = sys.stdin.readline()
    if not line:
        raise SnapshotError("--passphrase-stdin was given, but stdin was empty")
    return line.removesuffix("\n").removesuffix("\r")


def _input_file(path: str, flag: str, *, allow_empty: bool = False) -> tuple[int, str]:
    """Size and SHA-256 of an input file, refusing anything but a readable regular file."""
    import stat

    from slipway.services.snapfile import SnapshotError, file_digest

    try:
        info = os.stat(path)
    except OSError as exc:
        raise SnapshotError(f"{flag} {path}: {exc.strerror}") from None
    if not stat.S_ISREG(info.st_mode):
        raise SnapshotError(f"{flag} {path} isn't a regular file")
    if not info.st_size and not allow_empty:
        raise SnapshotError(f"{flag} {path} is empty")
    try:
        return file_digest(path)
    except OSError as exc:
        raise SnapshotError(f"{flag} {path}: {exc.strerror}") from None


def _default_source() -> str:
    """This computer's short name, made to fit the snapshot's ``source`` rule."""
    name = re.sub(r"[^A-Za-z0-9._ -]", "-", socket.gethostname().split(".")[0])[:100].lstrip("._ -")
    return name or "local"


def _pack_snapshot(args: argparse.Namespace) -> list[str]:
    from slipway import __version__
    from slipway.services import snapfile
    from slipway.services.snapfile import SnapshotError

    if (args.files is None) != (args.files_format is None):
        raise SnapshotError("--files and --files-format come together")
    if (args.identity_env is None) != (args.identity is None):
        raise SnapshotError("--identity-env and --identity come together")

    revision = None
    if args.revision_file is not None:
        try:
            with open(args.revision_file, "rb") as f:
                raw = f.read(snapfile.REVISION_MAX + 1)
        except OSError as exc:
            raise SnapshotError(f"--revision-file {args.revision_file}: {exc.strerror}") from None
        if len(raw) > snapfile.REVISION_MAX:
            raise SnapshotError("--revision-file is over 16 KiB")
        try:
            # Trimmed, as Slipway trims what commands.revision prints; an empty file means "unknown".
            revision = raw.decode("utf-8").strip() or None
        except UnicodeDecodeError:
            raise SnapshotError("--revision-file isn't UTF-8 text") from None

    identity = None
    if args.identity_env is not None:
        keys = [k.strip() for k in args.identity.split(",") if k.strip()]
        if not keys:
            raise SnapshotError("--identity names no keys")
        if len(set(keys)) != len(keys):
            raise SnapshotError("--identity names a key twice")
        try:
            env = _read_env_file(args.identity_env)
        except (OSError, UnicodeDecodeError) as exc:
            raise SnapshotError(f"--identity-env {args.identity_env}: {getattr(exc, 'strerror', None) or exc}") from None
        missing = [k for k in keys if k not in env]
        if missing:
            raise SnapshotError(f"{args.identity_env} doesn't set {', '.join(missing)}")
        identity = {k: env[k] for k in keys}

    db_bytes, db_sha = _input_file(args.database, "--database")
    files = None
    if args.files is not None:
        files_bytes, files_sha = _input_file(args.files, "--files", allow_empty=True)
        files = {"format": args.files_format, "bytes": files_bytes, "sha256": files_sha}
    manifest = snapfile.build_manifest(
        app=args.app, app_name=args.app_name, source=args.source or _default_source(),
        database={"format": args.format, "revision": revision, "bytes": db_bytes, "sha256": db_sha},
        repository=args.repository, commit=args.commit, notes=args.notes, files=files, identity=identity,
        producer=f"slipway {__version__}",
    )
    snapfile.validate_manifest(manifest)
    if identity is not None:
        snapfile.validate_identity(identity, list(identity))
    if os.path.lexists(args.out):
        raise SnapshotError(f"{args.out} already exists; choose another --out or remove it first")

    passphrase = _read_passphrase() if args.passphrase_stdin else None
    result = snapfile.pack(
        args.out, manifest, database_path=args.database, files_path=args.files, identity=identity,
        passphrase=passphrase,
    )
    lines = [f"Wrote {result.path}: {result.bytes} bytes, SHA-256 {result.sha256}."]
    if result.encrypted:
        lines.append("Upload it on Slipway's Snapshots page (it asks for the passphrase).")
    else:
        what = "its keys are not encrypted" if result.has_identity else "it is not encrypted"
        lines.append(f"Upload it on Slipway's Snapshots page, then delete it: {what}.")
        lines.append("Add --passphrase-stdin to write an encrypted file instead.")
    return lines


def snapshot_pack(args: argparse.Namespace) -> None:
    from slipway.services.snapfile import SnapshotError

    try:
        lines = _pack_snapshot(args)
    except SnapshotError as exc:
        sys.exit(f"Error: {exc}")
    except OSError as exc:
        sys.exit(f"Error: {exc.strerror or exc}")
    except KeyboardInterrupt:
        sys.exit("\nCancelled; nothing was written.")
    print("\n".join(lines))


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

    p = sub.add_parser("snapshot", help="Work with snapshot files")
    snap = p.add_subparsers(dest="snapshot_command", required=True, metavar="pack")
    p = snap.add_parser(
        "pack",
        help="Make a snapshot file from a database dump (and optionally files and identity keys) to upload to Slipway",
    )
    p.add_argument("--app", required=True, help="The app id: data.app in the app's slipway.yml")
    p.add_argument("--app-name", required=True, help="The app's name, as people know it")
    p.add_argument("--format", required=True, help="The dump's format: data.format in the app's slipway.yml")
    p.add_argument("--database", required=True, metavar="FILE", help="The database dump")
    p.add_argument("--revision-file", metavar="FILE", help="A file holding the database's revision (what commands.revision prints)")
    p.add_argument("--commit", metavar="SHA", help="The commit the data was made with (40 hex characters)")
    p.add_argument("--repository", metavar="OWNER/NAME", help="The GitHub repository the data belongs to")
    p.add_argument("--files", metavar="FILE", help="The app's files, as commands.export_files writes them")
    p.add_argument("--files-format", metavar="F", help="Their format: data.files.format in the app's slipway.yml")
    p.add_argument("--identity-env", metavar="FILE", help="A KEY=VALUE file holding the identity keys")
    p.add_argument("--identity", metavar="K1,K2", help="Which keys of --identity-env to include")
    p.add_argument("--source", help="Where the data comes from (default: this computer's name)")
    p.add_argument("--notes", default="", help="Notes shown with the snapshot")
    p.add_argument(
        "--passphrase-stdin",
        action="store_true",
        help="Encrypt the file with a passphrase read from stdin (recommended; asked twice at a terminal)",
    )
    p.add_argument("--out", required=True, metavar="FILE", help="The file to write (must not exist yet)")
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
    elif args.command == "snapshot" and args.snapshot_command == "pack":
        snapshot_pack(args)


if __name__ == "__main__":
    main()
