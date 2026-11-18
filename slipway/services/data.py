"""Rules for an app instance's data: backup names, host checks, retention, what can be restored, and
which data jobs may run.

Backups are dump files in ``<instance folder>/backups`` on the host. Slipway names them itself
(``NAME_RE``), records each in a ``Backup`` row, and deletes only names it recorded, after the same SSH
session has just confirmed them (I5). Everything here is used by the deployer (the job steps), the API
(the endpoints' checks) and the pages (buttons and their reasons), so the three always agree.

The shell snippets are portable (sh, dash, bash and zsh; GNU and BSD tools): no ``find -printf``, no
word splitting of variables (zsh doesn't split them), and every path quoted.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import posixpath
import re
import shlex
import uuid
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from fastapi import HTTPException, status
from sqlalchemy import delete, func, select, update
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer
from sqlalchemy.orm.attributes import set_committed_value
from sqlalchemy.orm.base import NO_VALUE

from slipway import __version__
from slipway.core.config import get_settings
from slipway.db.base import utcnow
from slipway.models import (
    Backup,
    BackupReason,
    BackupStatus,
    BuildSource,
    Deployment,
    DeploymentKind,
    DeploymentStatus,
    FirstAdmin,
    FirstAdminStatus,
    Instance,
    InstanceStatus,
    Snapshot,
)
from slipway.services import ssh

q = shlex.quote

# ----------------------------------------------------------------------- names

# <UTC time>-<Backup.id hex[:8]>: the time comes from Slipway's clock, never from the host.
NAME_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z")
FILE_RE = re.compile(r"^([0-9]{8}T[0-9]{6}Z-[0-9a-f]{8})\.(dump|files|json)$")
BACKUP_PARTS = ("dump", "files", "json")

BACKUPS_DIR = "backups"
INCOMING_DIR = ".incoming"  # work area inside backups/, emptied by every job's first host step
LOCK_FILE = ".slipway-lock"

# Kinds (DeploymentKind values) grouped by what they do.
CHANGING_KINDS = ("deploy", "restore", "rollback", "reset", "admin", "content")  # move "the latest job" (D10)
PIPELINE_KINDS = ("deploy", "restore", "rollback", "reset")
RESTORE_KINDS = ("restore", "rollback", "reset")  # run the live release again with data steps
DATA_ONLY_KINDS = ("backup", "snapshot", "admin", "content")
# Phase 3: jobs of a whole environment (instance_id is None, environment_id is set). None of them changes the
# data, so CHANGING_KINDS stays as it is.
ENV_KINDS = ("activate", "publish", "discard", "remove_slot", "teardown")
KIND_LABELS = {
    "deploy": "Deploy", "restore": "Restore", "rollback": "Roll back", "reset": "Reset data", "backup": "Back up",
    "snapshot": "Take snapshot", "admin": "Create first admin", "content": "Add starter content",
    "activate": "Activate", "publish": "Publish names", "discard": "Discard", "remove_slot": "Remove slot",
    "teardown": "Delete environment",
}
# How a job is named inside a sentence ("failed deployment 1a2b3c4d").
KIND_NOUNS = {
    "deploy": "deployment", "restore": "restore", "rollback": "roll back", "reset": "reset", "backup": "backup",
    "snapshot": "snapshot", "admin": "first-admin job", "content": "starter-content job",
    "activate": "activation", "publish": "name publishing", "discard": "discard", "remove_slot": "slot removal",
    "teardown": "teardown",
}
# Steps that replace or delete data on a data job (I1); a job that failed in one of them leaves a hold.
REPLACING_STEPS = ("reset", "restore", "files", "after_import")
NOT_BEGUN = ("pending", "skipped")

CHECK_BATCH = 100  # backup names per host check (§4.4)
DIRTY_KEEP = 2  # automatic backups of half-changed data kept besides the pinned ones (§4.3)
PROBE_TIMEOUT = 60  # seconds: probes and host checks
HASH_TIMEOUT = 600  # seconds: checks that hash the files again
VOLUME_RM_TIMEOUT = 300
MIB = 1024 * 1024
FALLBACK_ESTIMATE = 256 * MIB  # a first backup's size when Docker can't tell the volumes' sizes
REVISION_SHORT_CHARS = 40

SHA_MARK = "slipway-sha:"
DF_MARK = "slipway-df:"
BK_MARK = "slipway-bk:"
PROBE_MARK = "slipway-probe:"
LOCK_MARK = "slipway-lock:"
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class DataError(RuntimeError):
    """A data rule refused, or a host check failed; the message is meant for the user."""


Say = Callable[[str], Awaitable[None]]  # writes a line to the job's log


class Remote(Protocol):
    async def run(self, command: str, *, check: bool = True, on_line: Any = None,
                  timeout: float | None = None) -> tuple[int, str]: ...


def backup_name(backup_id: uuid.UUID, at: datetime) -> str:
    """The name of a backup's files: ``20261115T101500Z-1a2b3c4d``."""
    return f"{at.astimezone(UTC):%Y%m%dT%H%M%SZ}-{backup_id.hex[:8]}"


def check_name(name: str) -> str:
    """``name`` if it is a backup name Slipway makes; anything else raises (it never reaches a shell)."""
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise DataError(f"{name!r} isn't a backup name Slipway made")
    return name


def backups_dir(base: str) -> str:
    return f"{base}/{BACKUPS_DIR}"


def incoming_dir(base: str) -> str:
    return f"{backups_dir(base)}/{INCOMING_DIR}"


def job_dir(base: str, deployment_id: uuid.UUID) -> str:
    """A job's own staging folder: ``backups/.incoming/job-<d8>``."""
    return f"{incoming_dir(base)}/job-{deployment_id.hex[:8]}"


def lock_path(base: str) -> str:
    return f"{base}/{LOCK_FILE}"


def backup_file(backups: str, name: str, part: str) -> str:
    """``backups/<name>.dump`` (or ``.files``, ``.json``), from a re-checked name."""
    if part not in BACKUP_PARTS:
        raise ValueError(part)
    return f"{backups}/{check_name(name)}.{part}"


def partial_file(backups: str, name: str, part: str) -> str:
    """Where a backup's file is written before it is checked: ``backups/.incoming/<name>.<part>.partial``."""
    if part not in ("dump", "files"):
        raise ValueError(part)
    return f"{backups}/{INCOMING_DIR}/{check_name(name)}.{part}.partial"


def kind_label(kind: str) -> str:
    return KIND_LABELS.get(kind, kind)


def kind_noun(kind: str) -> str:
    return KIND_NOUNS.get(kind, kind)


def revision_short(revision: str | None) -> str | None:
    """A revision shown in short: its last non-empty line (a migration plan ends with the newest), cut."""
    if not revision:
        return None
    lines = [ln.strip() for ln in revision.splitlines() if ln.strip()]
    if not lines:
        return None
    last = lines[-1]
    return last if len(last) <= REVISION_SHORT_CHARS else last[: REVISION_SHORT_CHARS - 1] + "…"


def human_bytes(n: int | None) -> str:
    """812 MiB, 1.9 GiB, 20 GiB, 1.5 KiB: binary units (as df -k counts), one decimal, a whole number without
    its ".0". The Backups card and the Snapshots page both use it."""
    if n is None:
        return "an unknown size"
    for unit, scale in (("TiB", 1024 * 1024 * MIB), ("GiB", 1024 * MIB), ("MiB", MIB), ("KiB", 1024)):
        if n >= scale:
            return f"{n / scale:.1f}".removesuffix(".0") + f" {unit}"
    return f"{n} bytes"


def _utc(at: datetime | None) -> str:
    return at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC") if at else "never"


def _date(at: datetime) -> str:
    return at.astimezone(UTC).strftime("%Y-%m-%d")


# ------------------------------------------------------------------ live state


def live_state(instance: Instance) -> dict[str, Any] | None:
    """What the live release went live with (``app_state.live``, saved at finish), or None."""
    if instance.build_source != BuildSource.APP:
        return None
    live = (instance.app_state or {}).get("live")
    return live if isinstance(live, dict) and live.get("release") else None


def live_manifest(instance: Instance) -> dict[str, Any]:
    """The live release's slipway.yml as ``Manifest.to_json`` stored it ({} before the first deploy)."""
    found = (instance.app_state or {}).get("manifest")
    return found if isinstance(found, dict) else {}


def capabilities(instance: Instance) -> set[str]:
    """The data features the live release offers (``Manifest.capabilities``)."""
    if live_state(instance) is None:
        return set()
    return {str(c) for c in live_manifest(instance).get("capabilities") or []}


def live_sha7(instance: Instance) -> str:
    live = live_state(instance) or {}
    return str(live.get("sha") or instance.current_commit_sha or "")[:7]


def identity_label(instance: Instance) -> str:
    return (live_manifest(instance).get("data") or {}).get("identity_label") or "identity keys"


def identity_help(instance: Instance) -> str:
    return (live_manifest(instance).get("data") or {}).get("identity_help") or ""


def release_identity_keys(manifest_json: dict[str, Any]) -> list[str]:
    """The identity secrets a stored manifest declares, in slipway.yml's order."""
    return [str(s["key"]) for s in manifest_json.get("secrets") or [] if isinstance(s, dict) and s.get("identity")]


def plan_identity(plan: Any, keys: Iterable[str]) -> dict[str, str]:
    """The identity values a rendered plan's data is made with (phase 3 §5.3): ``AppPlan.identity``, which holds
    them even where the server role writes the line empty, and for a key it lacks, the rendered ``.env``'s value
    (``rendered_identity``). In the app and slot roles both are the same."""
    known = getattr(plan, "identity", None) or {}
    env = getattr(plan, "env", None) or {}
    return {k: known[k] if k in known else env[k] for k in keys if k in known or k in env}


# ------------------------------------------------------------ environments (phase 3)

ENV_DATA, ENV_TRAFFIC = "data", "traffic"
# The environment kinds that only read the data: they hold the data key alone, so an activate (the traffic key
# alone) runs beside them (D8). A snapshot belongs here only when it doesn't stop the app, and neither does when
# it runs on an app slot (mode slot) or stops the owner again at its end (``env_keys``).
_DATA_ONLY_ENV = ("backup",)


def variables_of(instance: Instance) -> dict[str, str]:
    """The variables the instance's releases render with: its own, or for a member of an environment the
    environment's (phase 3 D5), when the environment is loaded."""
    if instance.environment_id is None:
        return dict(instance.env or {})
    environment = loaded_environment(instance)
    return dict((environment.env if environment is not None else instance.env) or {})


def loaded_environment(instance: Instance) -> Any:
    """``instance.environment`` when it is already loaded (selectin), else None: never a lazy load, which an
    async session can't do."""
    if instance.environment_id is None and "environment" not in instance.__dict__:
        return None
    value = sa_inspect(instance).attrs.environment.loaded_value
    return None if value is NO_VALUE else value


def env_keys(environment_id: uuid.UUID, kind: str | None, options: dict[str, Any] | None = None, *,
             on_app_slot: bool = False) -> tuple[Any, ...]:
    """The runner keys of a job of an environment (D8): ``(env, "data")`` alone for a backup and for a snapshot
    that doesn't stop the app, ``(env, "traffic")`` alone for an activate, and both for everything else.
    Sorted, so two jobs never take them in opposite orders.

    A backup or snapshot takes both keys after all when it runs on an app slot (``on_app_slot``: in mode
    ``slot`` the data owner is the slot an activate starts, checks and switches to, and both jobs would write
    the slot host's one-line lock), or when it will stop the owner again at its end (``options.restop``), which
    would stop what an activate beside it had just started."""
    opts = options or {}
    reads_only = kind in _DATA_ONLY_ENV or (kind == DeploymentKind.SNAPSHOT and not opts.get("stop_app"))
    if reads_only and not on_app_slot and not opts.get("restop"):
        return ((environment_id, ENV_DATA),)
    if kind == DeploymentKind.ACTIVATE:
        return ((environment_id, ENV_TRAFFIC),)
    return ((environment_id, ENV_DATA), (environment_id, ENV_TRAFFIC))


def runner_keys(instance: Instance, kind: str | None = None, options: dict[str, Any] | None = None) -> tuple[Any, ...]:
    """What a job (or a change that isn't a job, with ``kind`` None) is serialised on: the instance's id for a
    standalone instance, as before environments; the environment's keys for a member (``env_keys``). A change
    that isn't a job (control, a backup delete, a check, the deploy-root move) takes both environment keys."""
    if instance.environment_id is None:
        return (instance.id,)
    return env_keys(instance.environment_id, kind, options, on_app_slot=instance.slot in ("blue", "green"))


def job_keys(dep: Deployment, instance: Instance | None = None) -> tuple[Any, ...]:
    """The runner keys a queued or running deployment holds. ``instance`` is the job's instance when the caller
    has it loaded (else ``dep.instance``)."""
    if dep.instance_id is None:
        assert dep.environment_id is not None
        return env_keys(dep.environment_id, dep.kind, dep.options)
    inst = instance if instance is not None else dep.instance
    if dep.environment_id is not None and (inst is None or inst.environment_id is None):
        return env_keys(dep.environment_id, dep.kind, dep.options)
    if inst is None:
        return (dep.instance_id,)
    return runner_keys(inst, dep.kind, dep.options)


def keys_meet(a: Iterable[Any], b: Iterable[Any]) -> bool:
    return bool(set(a) & set(b))


async def active_env_jobs(db: AsyncSession, environment_id: uuid.UUID) -> list[Deployment]:
    """Every queued or running job of the environment: its members' and its own, oldest first."""
    return list((await db.scalars(
        select(Deployment).options(defer(Deployment.log))
        .where(Deployment.environment_id == environment_id,
               Deployment.status.in_([DeploymentStatus.QUEUED, DeploymentStatus.RUNNING]))
        .order_by(Deployment.created_at, Deployment.id)
    )).all())


def slot_text(slot: str | None) -> str:
    """How a slot is named in a sentence: ``blue``, ``green``, ``the data server``."""
    return "the data server" if slot == "data" else str(slot or "")


def job_label(kind: str, *, slot: str | None = None, back: bool = False) -> str:
    """What a job of an environment is called on its pages (§8.1): ``Deploy to green``, ``Update the data
    server``, ``Activate green``, ``Switch back to blue``... Standalone jobs keep ``kind_label``."""
    if kind == DeploymentKind.DEPLOY:
        return "Update the data server" if slot == "data" else f"Deploy to {slot}" if slot else "Deploy"
    if kind == DeploymentKind.ACTIVATE:
        return f"Switch back to {slot}" if back else f"Activate {slot}"
    if kind == DeploymentKind.DISCARD:
        return f"Discard {slot}"
    if kind == DeploymentKind.REMOVE_SLOT:
        return f"Remove {slot}"
    return kind_label(kind)


def dep_label(dep: Deployment) -> str:
    """``job_label`` of a deployment: its slot is its instance's, or ``options.slot`` for an environment job."""
    opts = dep.options or {}
    slot = opts.get("slot")
    if dep.instance_id is not None and dep.instance is not None and dep.instance.slot:
        slot = dep.instance.slot
    if dep.environment_id is None:
        return kind_label(dep.kind)
    return job_label(dep.kind, slot=slot, back=bool(opts.get("back")))


def confirm_name(instance: Instance) -> str:
    """The name a typed confirmation must equal (D20): the environment's for a member, so people type the name
    they see on the environment page; the instance's own otherwise."""
    env = loaded_environment(instance)
    return env.name if env is not None else instance.name


def is_shared_slot(instance: Instance, environment: Any = None) -> bool:
    """An app slot whose data is on a data server (mode ``server``): it has no data of its own."""
    env = environment if environment is not None else loaded_environment(instance)
    return env is not None and env.data_mode != "slot" and instance.slot in ("blue", "green")


def data_shared_reason(instance: Instance, *, environment: Any = None, owner: Instance | None = None) -> str | None:
    """Why Slipway won't restore, reset or seed this instance's data, or None.

    Phase 3: an app slot in mode ``server`` shares its environment's data, which lives on the data server
    (``owner`` names its host; pass it, or the text says "its data server"). The data owner and a mode ``slot``
    slot answer as phase 2.

    Phase 2: only when the last probe found the data outside the host (``has_data`` exit 4), as cached in
    ``app_state.live.data_elsewhere``.
    """
    env = environment if environment is not None else loaded_environment(instance)
    if is_shared_slot(instance, env):
        where = owner.host.name if owner is not None else "its data server"
        return (f"{env.name}'s data is shared by its slots and lives on {where}: back it up, restore or reset it "
                "from the environment page")
    live = live_state(instance)
    if live and live.get("data_elsewhere"):
        return (f"{instance.name}'s data lives outside {instance.host.name} (an external or shared database); "
                "Slipway backs it up but won't restore, reset or seed it yet")
    return None


# Every refusal of a job because ``commands.has_data`` exited 4 says this (deployer ``_elsewhere_text``).
ELSEWHERE_MARK = "(commands.has_data says so)"


def refused_elsewhere(row: dict[str, Any] | None) -> bool:
    """Whether a failed step was refused because the data lives outside the host. A never-live instance has no
    ``app_state.live`` to cache that in, so its failed job's step note is the only record of it."""
    return bool(row and row.get("status") == "failed" and ELSEWHERE_MARK in str(row.get("note") or ""))


# ----------------------------------------------------------------- shell: files


def _sha_pipeline(path: str) -> str:
    """The first tool that works of sha256sum, shasum and openssl, on an already quoted ``path``."""
    return (f"{{ sha256sum -- {path} 2>/dev/null || shasum -a 256 -- {path} 2>/dev/null || "
            f"openssl dgst -sha256 -r {path} 2>/dev/null; }}")


def sha_command(path: str) -> str:
    """Prints ``slipway-sha: <hex>``, or nothing when the host has no tool for it."""
    return f"{_sha_pipeline(q(path))} | sed -n '1s/^\\([0-9a-f]\\{{64\\}}\\).*/{SHA_MARK} \\1/p'"


def parse_sha(output: str) -> str | None:
    for line in output.splitlines():
        if line.startswith(SHA_MARK):
            value = line[len(SHA_MARK):].strip()
            if _SHA_RE.match(value):
                return value
    return None


def free_space_command(path: str) -> str:
    """Prints ``slipway-df: <free KiB>`` for the filesystem holding ``path``."""
    return f"df -Pk -- {q(path)} | awk 'NR==2 {{print \"{DF_MARK} \" $4}}'"


def parse_free_kb(output: str) -> int | None:
    for line in output.splitlines():
        if line.startswith(DF_MARK):
            value = line[len(DF_MARK):].strip()
            if value.isdigit():
                return int(value)
    return None


def file_check_command(backups: str, files: Iterable[str], *, hashed: Iterable[str] = ()) -> str:
    """Check backup files by name in ``backups``: ``slipway-bk: ok <file> <size>`` or ``gone <file>``.

    Files in ``hashed`` are hashed too (``slipway-sha: <file> <hex>``, the hex empty without a tool). A
    missing folder prints ``slipway-bk: nodir`` and nothing else. Only names matching FILE_RE are accepted.
    """
    hashed = [f for f in dict.fromkeys(hashed)]
    plain = [f for f in dict.fromkeys(files) if f not in hashed]
    for f in (*plain, *hashed):
        if not FILE_RE.match(f):
            raise DataError(f"{f!r} isn't a backup file Slipway made")
    if not plain and not hashed:
        raise ValueError("no files to check")
    ok = f'echo "{BK_MARK} ok $f $(wc -c < "$f" | tr -d \' \')"'
    gone = f'echo "{BK_MARK} gone $f"'
    sha = (f"h=$({_sha_pipeline('"$f"')} | sed -n '1s/^\\([0-9a-f]\\{{64\\}}\\).*/\\1/p'); "
           f'echo "{SHA_MARK} $f $h"')
    parts = [f"cd {q(backups)} 2>/dev/null || {{ echo '{BK_MARK} nodir'; exit 0; }}"]
    if plain:
        parts.append(f'for f in {" ".join(plain)}; do if [ -f "$f" ] && [ ! -L "$f" ]; then {ok}; else {gone}; fi; done')
    if hashed:
        parts.append(f'for f in {" ".join(hashed)}; do if [ -f "$f" ] && [ ! -L "$f" ]; then {ok}; {sha}; '
                     f"else {gone}; fi; done")
    return "; ".join(parts)


@dataclass
class FileCheck:
    nodir: bool = False
    sizes: dict[str, int | None] = field(default_factory=dict)  # file -> size, None when it isn't there
    shas: dict[str, str | None] = field(default_factory=dict)  # file -> sha256, None without a hash tool


def parse_file_check(output: str) -> FileCheck:
    found = FileCheck()
    for line in output.splitlines():
        if line.startswith(BK_MARK):
            words = line[len(BK_MARK):].split()
            if words == ["nodir"]:
                found.nodir = True
            elif len(words) == 3 and words[0] == "ok" and words[2].isdigit():
                found.sizes[words[1]] = int(words[2])
            elif len(words) == 2 and words[0] == "gone":
                found.sizes[words[1]] = None
        elif line.startswith(SHA_MARK):
            words = line[len(SHA_MARK):].split()
            if words:
                found.shas[words[0]] = words[1] if len(words) == 2 and _SHA_RE.match(words[1]) else None
    return found


def prepare_backups_command(backups: str) -> str:
    """Create ``backups/`` and its work area, readable only by the SSH user (§4.2 step 2)."""
    b, i = q(backups), q(f"{backups}/{INCOMING_DIR}")
    return (f"{{ [ ! -L {b} ] && [ ! -L {i} ]; }} || {{ echo '{BK_MARK} link'; exit 1; }}; "
            f"umask 077 && mkdir -p -- {i} && chmod 700 {b} {i}")


def empty_incoming_command(backups: str) -> str:
    """Empty the work area (every job's first host step): what a crashed job left there is never used."""
    return f"rm -rf -- {q(backups + '/' + INCOMING_DIR)}"


def partial_check_command(path: str) -> str:
    """After a command wrote ``path``: a regular, non-empty file, made 0600, then measured and hashed.

    Prints ``slipway-bk: ok <file> <size>`` and ``slipway-sha: <file> <hex>`` (``<file>`` is the basename),
    or ``slipway-bk: empty <file>``.
    """
    p, name = q(path), posixpath.basename(path)
    return (f"if [ -f {p} ] && [ ! -L {p} ] && [ -s {p} ] && chmod 600 {p}; then "
            f'echo "{BK_MARK} ok {name} $(wc -c < {p} | tr -d \' \')"; '
            f"h=$({_sha_pipeline(p)} | sed -n '1s/^\\([0-9a-f]\\{{64\\}}\\).*/\\1/p'); "
            f'echo "{SHA_MARK} {name} $h"; '
            f"else echo '{BK_MARK} empty {name}'; fi")


def empty_output_message(command: str, path: str) -> str:
    return f"commands.{command} exited 0 but wrote nothing to {path}"


def finalize_command(moves: dict[str, str]) -> str:
    """Move checked partials to their final names (same folder tree, so each move is atomic)."""
    return " && ".join(f"mv -f -- {q(src)} {q(dst)}" for src, dst in moves.items())


def discard_partials_command(backups: str, name: str) -> str:
    """Remove a failed backup's partial files, by their exact names (never by a pattern, I5)."""
    files = [partial_file(backups, name, part) for part in ("dump", "files")]
    return f"rm -f -- {' '.join(q(f) for f in files)}"


def remove_backup_command(backups: str, names: Iterable[str]) -> str:
    """Remove confirmed backups' files (``.dump``, ``.files``, ``.json``) by name."""
    files = [backup_file(backups, n, part) for n in names for part in BACKUP_PARTS]
    return f"rm -f -- {' '.join(q(f) for f in files)}"


def sidecar(row: Backup, *, app: str | None) -> str:
    """``<name>.json`` next to the dump: what the backup is, for someone with only the folder. Never secrets."""
    return json.dumps({
        "format": "slipway-backup", "version": 1, "app": app, "data_format": row.format,
        "files_format": row.files_format if row.has_files else None, "revision_short": revision_short(row.revision),
        "commit": row.commit_sha, "release": row.release, "taken_at": row.taken_at.astimezone(UTC).isoformat(),
        "reason": row.reason, "db_sha256": row.db_sha256, "db_bytes": row.db_bytes,
        "files_sha256": row.files_sha256 if row.has_files else None, "files_bytes": row.files_bytes if row.has_files else None,
        "identity_keys": list(row.identity_keys or []), "identity_fp": row.identity_fp, "producer": f"slipway {__version__}",
    }, indent=2) + "\n"


def no_hash_tool_message(host: str) -> str:
    return f"{host} has none of sha256sum, shasum or openssl: Slipway checks this backup by size only"


# ----------------------------------------------------------------- free space


def parse_docker_size(text: str) -> int | None:
    """``1.234GB``, ``512kB``, ``0B`` (Docker counts in powers of 1000; ``MiB`` and the like are accepted too)."""
    m = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([kKMGTP]?)(i?)B\s*", text or "")
    if not m:
        return None
    power = " KMGTP".index(m.group(2).upper() or " ")
    return int(float(m.group(1)) * (1024 if m.group(3) else 1000) ** power)


VOLUME_SIZES_COMMAND = ("docker system df -v --format "
                        "'{{range .Volumes}}{{.Name}} {{.Size}}{{\"\\n\"}}{{end}}' 2>/dev/null")


def parse_volume_sizes(output: str) -> dict[str, int]:
    sizes: dict[str, int] = {}
    for line in output.splitlines():
        words = line.split()
        if len(words) == 2:
            size = parse_docker_size(words[1])
            if size is not None:
                sizes[words[0]] = size
    return sizes


@dataclass
class Estimate:
    bytes: int
    notes: list[str]  # what the log says about how it was made


def estimate_backup(*, last_db_bytes: int | None, last_files_bytes: int | None, include_files: bool,
                    volumes: list[dict[str, str]], volume_sizes: dict[str, int] | None) -> Estimate:
    """1.25 × the instance's last ready backup (§4.2); with none, the declared volumes it covers; else 256 MiB.

    ``volume_sizes`` is None when ``docker system df -v`` failed.
    """
    notes: list[str] = []

    def from_volumes(holds: str) -> int | None:
        names = [v["name"] for v in volumes if v.get("holds") == holds]
        known = [volume_sizes[n] for n in names if n in (volume_sizes or {})]
        return sum(known) if known else None

    db = last_db_bytes
    if db is None:
        db = from_volumes("database")
        if db is None:
            notes.append(f"Docker didn't tell the volumes' sizes; Slipway expects about {human_bytes(FALLBACK_ESTIMATE)}")
            db = FALLBACK_ESTIMATE
    files = 0
    if include_files:
        files = last_files_bytes if last_files_bytes is not None else (from_volumes("files") or 0)
    return Estimate(bytes=int((db + files) * 1.25), notes=notes)


def free_space_problem(*, free_kb: int | None, estimate: int, where: str, host: str) -> str | None:
    """The refusal when ``where`` lacks the estimate plus ``SLIPWAY_BACKUP_FREE_MARGIN_MB``, or None."""
    if free_kb is None:
        return f"Couldn't tell how much space is free in {where} on {host} (df gave no answer). Nothing was changed."
    need = estimate + get_settings().backup_free_margin_mb * MIB
    free = free_kb * 1024
    if free >= need:
        return None
    return (f"Only {human_bytes(free)} is free in {where} on {host}; the backup needs about {human_bytes(need)}. "
            "Free some space (old backups are on the Backups card) and retry. Nothing was changed.")


async def last_ready_sizes(db: AsyncSession, instance_id: uuid.UUID) -> tuple[int | None, int | None]:
    """(db_bytes of the last ready backup, files_bytes of the last ready backup with files)."""
    ready = select(Backup).where(Backup.instance_id == instance_id, Backup.status == BackupStatus.READY)
    last = await db.scalar(ready.order_by(Backup.taken_at.desc()).limit(1))
    with_files = await db.scalar(ready.where(Backup.has_files.is_(True)).order_by(Backup.taken_at.desc()).limit(1))
    return (last.db_bytes if last else None), (with_files.files_bytes if with_files else None)


# ---------------------------------------------------------------------- probe


def volume_probe_command(names: Iterable[str]) -> str:
    """Which of the volumes exist, with their Compose project label (§4.1).

    Only "not listed by a working ``docker volume ls``" counts as absent: when Docker doesn't answer,
    it prints ``slipway-probe: no-docker`` and fails.
    """
    names = list(dict.fromkeys(names))
    if not names:
        raise ValueError("no volumes to probe")
    for n in names:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}", n):
            raise DataError(f"{n!r} isn't a Docker volume name")
    label = q('{{index .Labels "com.docker.compose.project"}}')
    return (f"vols=$(docker volume ls -q) || {{ echo '{PROBE_MARK} no-docker'; exit 1; }}; "
            f"for v in {' '.join(q(n) for n in names)}; do "
            f'if printf \'%s\\n\' "$vols" | grep -Fxq -- "$v"; then '
            f'echo "{PROBE_MARK} present $v $(docker volume inspect -f {label} -- "$v")"; '
            f'else echo "{PROBE_MARK} absent $v"; fi; done')


@dataclass
class VolumeProbe:
    present: dict[str, str]  # volume -> its com.docker.compose.project label ("" when it has none)
    absent: list[str]


def parse_volume_probe(output: str, *, host: str) -> VolumeProbe:
    present: dict[str, str] = {}
    absent: list[str] = []
    for line in output.splitlines():
        if not line.startswith(PROBE_MARK):
            continue
        words = line[len(PROBE_MARK):].split()
        if words == ["no-docker"]:
            other = [ln.strip() for ln in output.splitlines() if ln.strip() and not ln.startswith(PROBE_MARK)]
            detail = other[-1] if other else "no output"
            raise DataError(f"Couldn't check {host} for the app's data: docker didn't answer ({detail})")
        if len(words) >= 2 and words[0] == "present":
            label = " ".join(words[2:])
            present[words[1]] = "" if label == "<no value>" else label
        elif len(words) == 2 and words[0] == "absent":
            absent.append(words[1])
    return VolumeProbe(present=present, absent=absent)


@dataclass
class DataProbe:
    state: str  # "here", "empty" or "elsewhere"
    reason: str  # for the log: "No data yet: <reason>", or which volumes hold it
    present: list[str] = field(default_factory=list)  # data volumes found (database or files)


def has_data_result(exit_status: int, *, name: str) -> DataProbe:
    """What ``commands.has_data`` answered: 0 data here, 3 none yet, 4 the data lives outside this host."""
    if exit_status == 0:
        return DataProbe("here", "commands.has_data found data")
    if exit_status == 3:
        return DataProbe("empty", "commands.has_data found none")
    if exit_status == 4:
        return DataProbe("elsewhere", "commands.has_data says the data lives outside this host")
    raise DataError(f"commands.has_data exited {exit_status}; Slipway can't tell whether {name} has data. "
                    "Nothing was changed.")


def volumes_result(probe: VolumeProbe, volumes: list[dict[str, str]], *, host: str) -> DataProbe:
    """Data exists when a declared volume that holds the database or files is on the host."""
    data = [v["name"] for v in volumes if v.get("holds") in ("database", "files")]
    found = [n for n in data if n in probe.present]
    if found:
        return DataProbe("here", f"{', '.join(found)} on {host}", present=found)
    if not data:
        return DataProbe("empty", "slipway.yml declares no volume that holds the database or files")
    return DataProbe("empty", f"{', '.join(data)} {'is' if len(data) == 1 else 'are'} not on {host}")


def foreign_volume(present: dict[str, str], projects: Iterable[str]) -> str | None:
    """Reset's label check (I5): the refusal for the first present volume that isn't one of the app's own."""
    own = set(projects)
    for name, label in present.items():
        if not label:
            return (f"The volume {name} has no Compose project label, so it isn't one of this app's own; "
                    "Slipway won't delete it. Nothing was deleted.")
        if label not in own:
            return f"The volume {name} belongs to the Compose project {label}, not to this app; Slipway won't delete it. Nothing was deleted."
    return None


# ---------------------------------------------------------------------- lock


def lock_line_command(lock: str, deployment_id: uuid.UUID, key: str, *, data: bool) -> str:
    """Write the job's lock line, with this shell's PID; ``exec`` after it hands the PID to the program (§4.5).

    Ends without a separator, so the caller adds `` && exec ./prog …``.
    """
    if not re.fullmatch(r"[a-z_]{1,32}", key):
        raise ValueError(key)
    return ("BOOT=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || printf '%s\\n' -); "
            f"printf '%s %s %s %s %s\\n' {q(str(deployment_id))} \"$BOOT\" \"$$\" {key} {'d' if data else '-'} > {q(lock)}")


def lock_read_command(lock: str, deployment_id: uuid.UUID) -> str:
    """Print ``slipway-lock: held <line> alive=<0|1>`` when another job holds the lock.

    Alive: the boot ids are equal (or either is ``-``) and the process exists. ``/proc/<pid>`` or the
    ``kill -0`` builtin (it sends no signal) decides; BusyBox ``ps`` has no ``-p``, so ``ps -p`` is only
    asked on a host without ``/proc``, and when it doesn't work there either the holder counts as alive.
    """
    lk = q(lock)
    return (f"if [ -f {lk} ]; then read -r lid lboot lpid lkey lflag < {lk}; "
            f"if [ -n \"$lid\" ] && [ \"$lid\" != {q(str(deployment_id))} ]; then {_LOCK_ALIVE}"
            f'echo "{LOCK_MARK} held $lid $lboot $lpid $lkey $lflag alive=$alive"; fi; fi; true')


# Sets ``alive`` (0 or 1) for the lock line read into lboot and lpid (see lock_read_command).
_LOCK_ALIVE = ("boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || printf '%s\\n' -); alive=0; "
               'case "$lpid" in ""|0|*[!0-9]*) ;; *) '
               'if [ "$lboot" = - ] || [ "$boot" = - ] || [ "$lboot" = "$boot" ]; then '
               'if [ -d "/proc/$lpid" ] || kill -0 "$lpid" 2>/dev/null; then alive=1; '
               'elif [ ! -d /proc/self ]; then '
               'if ps -p "$$" >/dev/null 2>&1; then ps -p "$lpid" >/dev/null 2>&1 && alive=1; else alive=1; fi; '
               'fi; fi ;; esac; ')


def lock_own_command(lock: str, deployment_id: uuid.UUID) -> str:
    """Print ``slipway-lock: own <pid> <key> alive=<0|1>`` while the lock names this job: the command a job
    leaves running (a timeout, a cut-off) wrote its own PID there (§4.5)."""
    lk = q(lock)
    return (f"if [ -f {lk} ]; then read -r lid lboot lpid lkey lflag < {lk}; "
            f"if [ \"$lid\" = {q(str(deployment_id))} ]; then {_LOCK_ALIVE}"
            f'echo "{LOCK_MARK} own $lpid $lkey alive=$alive"; fi; fi; true')


def parse_own_lock(output: str, key: str) -> str | None:
    """The PID of ``key`` from ``lock_own_command``'s output, when that command still runs (else None)."""
    for line in output.splitlines():
        if line.startswith(LOCK_MARK):
            words = line[len(LOCK_MARK):].split()
            if (len(words) == 4 and words[0] == "own" and words[1].isdigit() and words[2] == key
                    and words[3] == "alive=1"):
                return words[1]
    return None


def lock_release_command(lock: str, deployment_id: uuid.UUID) -> str:
    """Remove the lock only while it still names this job."""
    lk = q(lock)
    return (f"if [ -f {lk} ]; then read -r lid rest < {lk}; "
            f"[ \"$lid\" = {q(str(deployment_id))} ] && rm -f -- {lk}; fi; true")


@dataclass
class HeldLock:
    deployment: str
    boot: str
    pid: str
    key: str
    data: bool
    alive: bool

    @property
    def job(self) -> str:
        return self.deployment.replace("-", "")[:8]


def parse_lock(output: str) -> HeldLock | None:
    for line in output.splitlines():
        if line.startswith(LOCK_MARK):
            words = line[len(LOCK_MARK):].split()
            if len(words) == 7 and words[0] == "held" and words[6] in ("alive=0", "alive=1"):
                return HeldLock(deployment=words[1], boot=words[2], pid=words[3], key=words[4],
                                data=words[5] == "d", alive=words[6] == "alive=1")
    return None


def lock_verdict(held: HeldLock | None, *, host: str, take_over: bool = False) -> str | None:
    """What to log when taking the lock over (None: nothing held). Raises when a data command still runs."""
    if held is None:
        return None
    if not held.alive:
        return f"Took over the lock of job {held.job} (its {held.key} has ended)"
    if not held.data:
        return f"Warning: job {held.job}'s {held.key} (pid {held.pid}) may still be running on {host}"
    if take_over:
        return (f"Warning: took over the lock of job {held.job} on request; its {held.key} (pid {held.pid}) "
                f"may still be running on {host}")
    raise DataError(f"Job {held.job}'s {held.key} (pid {held.pid}) is still running on {host}; Slipway lost track of it "
                    "when it restarted or the command timed out. Wait for it to end and retry, or stop it "
                    f"(kill {held.pid}) and retry.")


def lock_left_text(key: str, pid: str | int | None, host: str) -> str:
    """``<key> (pid <pid>) may still be running on <host>``: a command the job left running (§4.5)."""
    shown = f" (pid {pid})" if pid else ""
    return f"{key}{shown} may still be running on {host}"


def lock_left_message(key: str, pid: str | int | None, host: str) -> str:
    return f"{lock_left_text(key, pid, host)}; the next job waits until it has ended"


# -------------------------------------------------------------- identity keys


def identity_fp(row_id: uuid.UUID, keys: Iterable[str], values: dict[str, str] | None) -> str:
    """The fingerprint of the identity values ``keys`` have in ``values``, salted with the row's id (§9.1).

    A key missing from ``values`` counts as a value of its own (NUL can't be in a variable's value).
    """
    values = values or {}
    text = "".join(f"{k}={values[k]}\n" if k in values else f"{k}\x00\n" for k in sorted(set(keys)))
    return hashlib.sha256(b"slipway-identity-v1\x00" + row_id.bytes + text.encode()).hexdigest()


def rendered_identity(env: dict[str, str], keys: Iterable[str]) -> dict[str, str]:
    """The identity values a rendered plan uses (an instance variable replaces a secret)."""
    return {k: env[k] for k in keys if k in env}


def restore_override(identity: dict[str, str] | None, release_keys: Iterable[str],
                     live: dict[str, str] | None) -> dict[str, str]:
    """The identity values restoring a backup puts back: the release's keys whose values differ (§9.3)."""
    live = live or {}
    keys = set(release_keys)
    return {k: v for k, v in (identity or {}).items() if k in keys and live.get(k) != v}


_HEX_KEY = re.compile(r"^(?:[0-9a-f]{2}){16,128}$")
_TOKEN_KEY = re.compile(r"^[A-Za-z0-9_-]{16,256}$")


def identity_value_ok(value: Any, kind: str, *, placeholder: str | None = None) -> bool:
    """Whether ``value`` is a valid key of the secret's kind (hex, fernet or token)."""
    if not isinstance(value, str) or not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return False
    if placeholder and value == placeholder:
        return False
    if kind == "hex":
        return bool(_HEX_KEY.match(value))
    if kind == "token":
        return bool(_TOKEN_KEY.match(value))
    if kind == "fernet":
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}=", value):
            return False
        try:
            return len(base64.urlsafe_b64decode(value)) == 32
        except (binascii.Error, ValueError):
            return False
    return False


def check_override(override: dict[str, str], manifest_json: dict[str, Any], *, source: str = "snapshot") -> None:
    """Raise when an override value isn't a valid key of the target secret's kind (§9.3)."""
    kinds = {str(s["key"]): str(s.get("kind") or "hex") for s in manifest_json.get("secrets") or [] if isinstance(s, dict)}
    for key in sorted(override):
        kind = kinds.get(key, "hex")
        if not identity_value_ok(override[key], kind, placeholder=manifest_json.get("placeholder")):
            raise DataError(f"The {source}'s {key} isn't a valid {kind} key")


def env_pinned(override: dict[str, str], env: dict[str, str] | None) -> list[str]:
    """The keys the override changes that an instance environment variable sets (and would win over)."""
    return sorted(k for k in override if k in (env or {}))


def env_pin_message(key: str, *, source: str = "backup") -> str:
    lead = "Taken with another" if source == "backup" else f"The {source} has another"
    return (f"{lead} {key}, and the instance's environment variable {key} sets this one: remove the variable "
            "(its value stays the stored secret), then restore")


# ---------------------------------------------------------- what can be restored


@dataclass
class Restorable:
    ok: bool
    reason: str | None = None  # the first failing rule's text (§9.2), shown instead of the Restore button
    override: dict[str, str] = field(default_factory=dict)  # identity values restoring it puts back
    identity_note: str | None = None
    needs_reset_perm: bool = False  # restoring it brings back other identity keys (data:reset, D8)
    dirty_note: str | None = None


def dirty_note(dirty_job: Deployment | None) -> str:
    if dirty_job is None:
        return "Holds data changed by a failed job"
    return f"Holds data changed by failed {kind_noun(dirty_job.kind)} {dirty_job.id.hex[:8]} ({dirty_job.short_sha})"


def restorable(instance: Instance, row: Backup, *, dirty_job: Deployment | None = None,
               env: dict[str, str] | None = None) -> Restorable:
    """Whether the backup can be restored into the live release, with the first failing rule's reason (§9.2).

    ``env``: the variables the live release renders with (a job's own); by default the instance's, or for a
    member of an environment the environment's (phase 3 D5), which win over a restored identity value too."""
    note = dirty_note(dirty_job) if row.dirty_of is not None else None

    def no(reason: str) -> Restorable:
        return Restorable(ok=False, reason=reason, dirty_note=note)

    host = instance.host.name
    live = live_state(instance)
    if live is None:
        return no("Deploy the instance first")
    man, sha7 = live_manifest(instance), live_sha7(instance)
    if "restore" not in capabilities(instance):
        return no(f"{sha7}'s slipway.yml has no restore command")
    if row.status != BackupStatus.READY:
        return no({
            BackupStatus.PENDING: "Being taken",
            BackupStatus.UNVERIFIED: "Not checked since Slipway restarted",
            BackupStatus.MISSING: f"Not on {host} any more (checked {_utc(row.checked_at)})",
            BackupStatus.CHANGED: f"Its size on {host} changed since Slipway took it",
        }.get(row.status, f"Its state is {row.status}"))
    wanted = (man.get("data") or {}).get("format")
    if row.format != wanted:
        return no(f"Taken in format {row.format}; release {sha7} restores {wanted or 'no format'}")
    label = identity_label(instance)
    override: dict[str, str] = {}
    if identity_fp(row.id, row.identity_keys or [], instance.live_identity) != row.identity_fp:
        if row.identity is None:
            return no(f"Taken with other {label}, which Slipway can't decrypt any more (SLIPWAY_ENCRYPTION_KEY "
                      "changed): put the old key back first in the list and run slipway rotate-encryption-key")
        override = restore_override(row.identity, release_identity_keys(man), instance.live_identity)
        pinned = env_pinned(override, env if env is not None else variables_of(instance))
        if pinned:
            return no(env_pin_message(pinned[0]))
    shared = data_shared_reason(instance)
    if shared:
        return no(shared)
    result = Restorable(ok=True, override=override, dirty_note=note)
    if override:
        changed = ""
        if instance.identity_changed_at:
            changed = f"; changed {_date(instance.identity_changed_at)}"
            if instance.identity_source:
                changed += f": {instance.identity_source}"
        text = f"Restoring it also puts back the {label} it was made with ({', '.join(sorted(override))}{changed})."
        help_text = identity_help(instance)
        result.identity_note = f"{text} {help_text}" if help_text else text
        result.needs_reset_perm = True
    return result


# ---------------------------------------------------------------------- jobs


def _steps(dep: Deployment) -> dict[str, dict[str, Any]]:
    return {str(r.get("key")): r for r in dep.steps or [] if isinstance(r, dict)}


def _began(row: dict[str, Any] | None) -> bool:
    return row is not None and row.get("status") not in NOT_BEGUN


def change_began(dep: Deployment) -> bool:
    """Whether a failed pipeline job began changing the data (§7.1): ``start`` for a deploy (it migrates; a
    deploy restoring a snapshot also from its data steps), ``stop`` onward for restore, roll back and reset."""
    rows = _steps(dep)
    if dep.kind == DeploymentKind.DEPLOY:
        keys: tuple[str, ...] = ("start", *REPLACING_STEPS)
    elif dep.kind in RESTORE_KINDS:
        keys = ("stop", *REPLACING_STEPS, "start", "finish")
    else:
        return False
    return any(_began(rows.get(k)) for k in keys)


def slots_left_stopped(dep: Deployment) -> list[str]:
    """The app slots a data owner job's ``stop_slots`` stopped while they ran (``options.slots_were``) and that
    nothing started again (``options.slots_started``): [] when the step never began (phase 3 §9.13)."""
    if not _began(_steps(dep).get("stop_slots")):
        return []
    options = dep.options or {}
    started = {str(s) for s in options.get("slots_started") or []}
    return [str(s) for s, was in (options.get("slots_were") or {}).items() if was == "running" and str(s) not in started]


def left_stopped(dep: Deployment) -> bool:
    """Whether a snapshot job stopped the app (``stop_app``) and didn't start it again: its ``stop`` began and
    its ``restart`` didn't succeed (a failed restart, or a Slipway that was killed during the export)."""
    if dep.kind != DeploymentKind.SNAPSHOT:
        return False
    rows = _steps(dep)
    return _began(rows.get("stop")) and (rows.get("restart") or {}).get("status") != "succeeded"


def replacing_began(dep: Deployment) -> bool:
    """Whether a change step of ``dep`` began, as retry inheritance counts it (§8.1)."""
    rows = _steps(dep)
    keys = (("start",) if dep.kind == DeploymentKind.DEPLOY else ()) + REPLACING_STEPS
    return any(_began(rows.get(k)) for k in keys)


def mark_dirty(old: dict[str, Any] | None, dep: Deployment, *, step: str | None, at: datetime | None = None) -> dict[str, Any]:
    """``instance.data_dirty`` after ``dep`` failed in ``step`` having begun a change (§8.4).

    ``first`` is kept when already set and ``last`` replaced. ``hold`` stays once set, and is set when a restore,
    roll back or reset failed while replacing data.
    """
    at_text = (at or utcnow()).isoformat()
    rows = list(dep.steps or [])
    number = next((i + 1 for i, r in enumerate(rows) if r.get("key") == step), None)
    name = next((str(r.get("name") or step) for r in rows if r.get("key") == step), step)
    backup = dep.backup_id.hex if dep.backup_id else None
    first = (old or {}).get("first") or {"deployment_id": dep.id.hex, "kind": dep.kind, "backup_id": backup, "at": at_text}
    last = {"deployment_id": dep.id.hex, "kind": dep.kind, "step": step, "backup_id": backup, "at": at_text,
            "step_text": f"step {number}/{len(rows)}: {name}" if number else (name or "")}
    # Start over is the exception: a never-live instance has no live app to keep from starting, and no backup it
    # could restore, so a hold would only block the deploy that is its way forward.
    start_over = bool((dep.options or {}).get("start_over"))
    hold = bool((old or {}).get("hold")) or (dep.kind in RESTORE_KINDS and step in REPLACING_STEPS and not start_over)
    return {"first": first, "last": last, "hold": hold}


def _uuid(value: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value)) if value else None
    except ValueError:
        return None


async def _instance_of(db: AsyncSession, dep: Deployment) -> Instance:
    """The job's instance, loaded in this session (never by a lazy load, which an async session can't do)."""
    instance = await db.get(Instance, dep.instance_id)
    if instance is None:
        raise DataError("The instance of this job was deleted")
    return instance


async def _backup_of(db: AsyncSession, instance: Instance, backup_id: Any) -> Backup | None:
    bid = _uuid(backup_id)
    if bid is None:
        return None
    return await db.scalar(select(Backup).where(Backup.id == bid, Backup.instance_id == instance.id))


async def _job(db: AsyncSession, instance: Instance, dep_id: Any) -> Deployment | None:
    did = _uuid(dep_id)
    if did is None:
        return None
    return await db.scalar(select(Deployment).options(defer(Deployment.log))
                           .where(Deployment.id == did, Deployment.instance_id == instance.id))


async def owner_for(db: AsyncSession, instance: Instance) -> Instance:
    """The instance that holds ``instance``'s data fields (D3): itself, unless it is an app slot of an environment
    whose data is on a data server (``environments.owner_of``)."""
    if instance.environment_id is None:
        return instance
    from slipway.services import environments  # environments imports this module

    return await environments.owner_of(db, instance) or instance


def stopped_text(slots: Iterable[str]) -> str:
    """``Blue and Green are stopped`` / ``Blue is stopped``: what a data job that stopped the app slots left."""
    names = [str(s).capitalize() for s in slots]
    if not names:
        return ""
    return f"{' and '.join(names)} {'is' if len(names) == 1 else 'are'} stopped"


async def hold_text(db: AsyncSession, instance: Instance) -> str | None:
    """The refusal while ``data_dirty.hold`` stands (§8.4), or None.

    For a member of an environment the hold is the data owner's, named by the environment (§7.5). A data job that
    stopped the app slots (``stop_slots``) records them in ``data_dirty.last.slots_stopped``, and a lead slot that
    didn't start again records ``last.start_error = {slot, error}``; the text then says so (§7.4).
    """
    owner = await owner_for(db, instance)
    dirty = owner.data_dirty or {}
    if not dirty.get("hold"):
        return None
    last = dirty.get("last") or {}
    backup = await _backup_of(db, owner, last.get("backup_id"))
    where = f" ({last['step_text']})" if last.get("step_text") else ""
    before = f"restore the backup taken just before it ({backup.name})" if backup else "restore an earlier backup"
    kind = kind_noun(str(last.get("kind") or "job"))
    text = (f"{confirm_name(owner)}'s last {kind} stopped part-way{where}, so its "
            f"database may be empty or half-restored. Retry it, or {before}. Start, Restart and Deploy are off until then.")
    stopped = stopped_text(last.get("slots_stopped") or [])
    failed = last.get("start_error") if isinstance(last.get("start_error"), dict) else None
    if failed and stopped:
        text += f" {failed.get('slot')} didn't start again after the {kind} ({failed.get('error')}); {stopped}."
    elif stopped:
        text += f" {stopped}."
    return text


def dirty_snapshot_text(instance: Instance, environment: Any = None) -> str | None:
    """Why a snapshot is refused while the data is half-changed (§7.5 export), or None. ``environment``: the
    member's environment, when the caller has it (else ``instance.environment`` when loaded)."""
    dirty = instance.data_dirty
    if not dirty:
        return None
    first = dirty.get("first") or {}
    d8 = str(first.get("deployment_id") or "")[:8]
    # A member's data is its environment's: the owner is named as the environment, as in hold_text (§7.5).
    env = environment if environment is not None and instance.environment_id is not None else None
    name = env.name if env is not None else confirm_name(instance)
    return (f"{name}'s data was left half-changed by {kind_noun(str(first.get('kind') or 'job'))} {d8}; "
            "a snapshot of it would seed others with that. Retry, restore or roll back first.")


async def latest_changing_job(db: AsyncSession, instance: Instance | uuid.UUID, *,
                              exclude: uuid.UUID | None = None,
                              past_server_deploys: bool = False) -> Deployment | None:
    """The newest job that may have changed the data (D10): backups and snapshots never count. ``exclude`` leaves
    out one job (a retry that has just started asks about the jobs before it).

    For a member of an environment it is the newest such job of the whole environment, whichever member it ran on
    (phase 3 §7.5): the slots and the data server share one set of data.

    ``past_server_deploys``: look past the data server's deploys (Update the data server) that replaced no data.
    They run no app migration and never settle a failed slot deploy (§7.5), so a failed slot deploy's roll back
    and its retry's inheritance still stand after one. A data server deploy that began a data step (it restored a
    snapshot onto fresh data) still counts."""
    if isinstance(instance, Instance):
        instance_id, env_id = instance.id, instance.environment_id
    else:
        instance_id = instance
        env_id = await db.scalar(select(Instance.environment_id).where(Instance.id == instance_id))
    stmt = select(Deployment).options(defer(Deployment.log)).where(Deployment.kind.in_(CHANGING_KINDS))
    if env_id is not None:
        stmt = stmt.where(Deployment.environment_id == env_id)
    else:
        stmt = stmt.where(Deployment.instance_id == instance_id)
    if exclude is not None:
        stmt = stmt.where(Deployment.id != exclude)
    # The id settles equal times.
    stmt = stmt.order_by(Deployment.created_at.desc(), Deployment.id.desc())
    if env_id is None or not past_server_deploys:
        return await db.scalar(stmt.limit(1))
    servers = set((await db.scalars(select(Instance.id).where(
        Instance.environment_id == env_id, Instance.slot == "data"))).all())
    offset, batch = 0, 20
    while True:
        rows = (await db.scalars(stmt.offset(offset).limit(batch))).all()
        for job in rows:
            if job.kind == DeploymentKind.DEPLOY and job.instance_id in servers and not _replaced_data(job):
                continue
            return job
        if len(rows) < batch:
            return None
        offset += batch


def _replaced_data(dep: Deployment) -> bool:
    """Whether a deploy began one of its data steps (restoring a snapshot, or resetting for one)."""
    rows = _steps(dep)
    return any(_began(rows.get(k)) for k in REPLACING_STEPS)


async def active_job(db: AsyncSession, instance_id: uuid.UUID) -> Deployment | None:
    return await db.scalar(
        select(Deployment).options(defer(Deployment.log))
        .where(Deployment.instance_id == instance_id,
               Deployment.status.in_([DeploymentStatus.QUEUED, DeploymentStatus.RUNNING]))
        .order_by(Deployment.created_at.desc()).limit(1)
    )


def busy_text(job: Deployment) -> str:
    return f"A job is already running for this instance ({kind_label(job.kind)}); wait for it to finish"


@dataclass
class Inheritance:
    """What a retry takes over from the job it retries (§8.1, D11)."""

    inherit: bool  # keep the parent's pre-change backup instead of taking a new one
    backup_id: uuid.UUID | None
    pre_retry: bool  # the app was started by hand since: take a pre_retry backup as well
    done_by: dict[str, str]  # step -> id hex of the attempt that did it (skipped as "Done by the first attempt")


async def retry_inheritance(db: AsyncSession, parent: Deployment, *, exclude: uuid.UUID | None = None) -> Inheritance:
    """``exclude``: the retry itself, when it is already queued (``_start``)."""
    instance = await _instance_of(db, parent)
    # An Update the data server since doesn't stop a slot deploy's retry inheriting (§7.5, as rollback_state).
    latest = await latest_changing_job(db, instance, exclude=exclude,
                                       past_server_deploys=_app_slot_deploy(parent, instance))
    is_latest = latest is not None and latest.id == parent.id
    inherit = is_latest and replacing_began(parent)
    rows = _steps(parent)
    done_by = {}
    # A data step the first attempt finished is only "done" while nothing changed the data since: a later
    # reset, restore or deploy may have undone it (Start over deletes what a seeding deploy restored).
    for key in REPLACING_STEPS if is_latest else ():
        row = rows.get(key)
        if row is None:
            continue
        if row.get("done_by"):
            done_by[key] = str(row["done_by"])
        elif row.get("status") == "succeeded":
            done_by[key] = parent.id.hex
    pre_retry = bool(inherit and instance.last_control_at and parent.finished_at
                     and instance.last_control_at > parent.finished_at)
    return Inheritance(inherit=inherit, backup_id=parent.backup_id if inherit else None, pre_retry=pre_retry,
                       done_by=done_by)


def _app_slot_deploy(dep: Deployment, instance: Instance) -> bool:
    """A deploy to an app slot of an environment (not to its data server, nor a standalone instance's)."""
    return dep.kind == DeploymentKind.DEPLOY and instance.environment_id is not None \
        and instance.slot in ("blue", "green")


@dataclass
class RollbackState:
    """``rollback_state``: unpacks as ``(available, reason)``; the rest is for the dialog and the job."""

    available: bool
    reason: str | None
    backup: Backup | None = None  # the rollback point
    also_undoes: str | None = None  # the dialog's line when the rollback point predates the deployment
    first_deployment_id: str | None = None
    # Phase 3, mode server: the roll back runs on the data owner and throws away what the active slot wrote since
    # the backup, so it needs data:reset as well as data:restore (D17).
    needs_reset: bool = False
    owner_id: uuid.UUID | None = None  # the instance the roll back job runs on (the data owner)

    def __iter__(self):
        return iter((self.available, self.reason))


async def _environment_of(db: AsyncSession, instance: Instance) -> Any:
    if instance.environment_id is None:
        return None
    env = loaded_environment(instance)
    if env is not None:
        return env
    from slipway.models import Environment

    return await db.get(Environment, instance.environment_id)


async def _env_job(db: AsyncSession, instance: Instance, dep_id: Any) -> Deployment | None:
    """A job of ``instance``, or of any member of its environment."""
    if instance.environment_id is None:
        return await _job(db, instance, dep_id)
    did = _uuid(dep_id)
    if did is None:
        return None
    return await db.scalar(select(Deployment).options(defer(Deployment.log))
                           .where(Deployment.id == did, Deployment.environment_id == instance.environment_id))


async def rollback_state(db: AsyncSession, dep: Deployment) -> RollbackState:
    """Whether Roll back is offered for ``dep``, and why not (§8.2).

    For a member of an environment the rules are read against the data owner's dirty state and backups, and the
    roll back runs there (phase 3 §7.3). In mode ``server`` it is the second way past a failed deploy (Discard is
    the first): it needs an active slot other than the failed one, which it starts again on the restored data,
    and ``data:reset`` (``needs_reset``), since it loses what that slot wrote since the backup.
    """
    if dep.kind != DeploymentKind.DEPLOY or dep.status not in (DeploymentStatus.FAILED, DeploymentStatus.CANCELLED) \
            or dep.instance_id is None:
        return RollbackState(False, "Only a failed deployment can be rolled back")
    instance = await _instance_of(db, dep)
    owner = await owner_for(db, instance)
    env = await _environment_of(db, instance)
    shared = env is not None and env.data_mode != "slot"
    # An Update the data server since doesn't count (§7.5: it never settles a failed slot deploy, and the dirty
    # state and its pre-deploy backup are unchanged by it).
    latest = await latest_changing_job(db, instance, past_server_deploys=_app_slot_deploy(dep, instance))
    if latest is not None and latest.id != dep.id:
        return RollbackState(False, f"{kind_noun(latest.kind).capitalize()} {latest.id.hex[:8]} ran after this deployment; "
                                    "restore a backup instead")
    first = (owner.data_dirty or {}).get("first") or {}
    if first.get("kind") != DeploymentKind.DEPLOY:
        runs = (f"{instance.name} still runs {instance.current_commit_sha[:7]}" if instance.current_commit_sha
                else f"{instance.name} hasn't gone live yet")
        return RollbackState(False, f"Nothing to roll back: this deployment failed before it changed the data; {runs}")
    backup = await _backup_of(db, owner, first.get("backup_id"))
    if backup is None or backup.status != BackupStatus.READY or backup.reason != BackupReason.PRE_DEPLOY:
        return RollbackState(False, "There is no backup from before the first failed deploy (it had no data yet, "
                                    "or the backup is gone)")
    if shared:
        if env.active_slot_id is None:
            return RollbackState(False, "Nothing is live to start again on the data a roll back puts back: retry the "
                                        "deployment instead", backup)
        if env.active_slot_id == instance.id:
            return RollbackState(False, f"{instance.slot} takes the traffic and this was its own deploy: retry the "
                                        "deployment instead", backup)
    elif not instance.current_commit_sha:
        return RollbackState(False, "This was the first deploy: use Start over instead")
    if "restore" not in capabilities(owner):
        return RollbackState(False, f"{live_sha7(owner)}'s slipway.yml has no restore command")
    rule = restorable(owner, backup)
    if not rule.ok:
        return RollbackState(False, rule.reason, backup)
    if rule.override:
        # A roll back never changes the identity keys (it has no "put back its keys" tick).
        return RollbackState(False, f"The backup from before the first failed deploy was made with other "
                                    f"{identity_label(owner)}; restore it from the Backups card instead", backup)
    first_id = str(first.get("deployment_id") or "")
    also = None
    if first_id and first_id != dep.id.hex:
        earlier = await _env_job(db, instance, first_id)
        sha = f" ({earlier.short_sha})" if earlier is not None and earlier.commit_sha else ""
        also = f"This also undoes failed deployment {first_id[:8]} before it{sha}."
    return RollbackState(True, None, backup, also, first_id or None, needs_reset=shared, owner_id=owner.id)


@dataclass
class DiscardState:
    """``discard_state``: unpacks as ``(available, reason)``."""

    available: bool
    reason: str | None
    slot: str | None = None  # the app slot whose failed deploy Discard settles
    deployment_id: str | None = None  # that failed deploy (the owner's ``data_dirty.first``)

    def __iter__(self):
        return iter((self.available, self.reason))


async def discard_state(db: AsyncSession, env: Any, slot: str | None = None) -> DiscardState:
    """Whether Discard <slot> is offered (phase 3 §9.14, D17): a deploy to the idle slot failed after its
    ``start`` began, so the owner is dirty, while the active slot kept serving. ``slot`` None: the slot the
    owner's dirty state names. The checks are §9.14's refusals, in its order."""
    from slipway.services import environments, jobs  # both import this module

    members = await environments.members(db, env)
    apps = environments.app_members(members)
    owner = environments.owner_in(env, members)
    first = ((owner.data_dirty if owner is not None else None) or {}).get("first") or {}
    failed = await db.scalar(select(Deployment).options(defer(Deployment.log)).where(
        Deployment.id == _uuid(first.get("deployment_id")), Deployment.environment_id == env.id)) \
        if _uuid(first.get("deployment_id")) else None
    failed_slot = next((s for s, m in members.items() if failed is not None and m.id == failed.instance_id), None)
    slot = slot or (failed_slot if failed_slot in environments.APP_SLOTS else None)
    out = DiscardState(False, None, slot, failed.id.hex if failed is not None else None)

    def no(reason: str) -> DiscardState:
        out.reason = reason
        return out

    if env.data_mode == "slot" or len(apps) < 2:
        only = apps[0].slot if apps else "blue"
        return no(f"Roll back or retry instead: {only} is {env.name}'s only slot")
    target = members.get(slot) if slot else None
    if target is None or failed is None or failed.kind != DeploymentKind.DEPLOY or failed.instance_id != target.id:
        return no(f"{slot or 'This slot'} has no failed deploy to discard")
    if env.active_slot_id == target.id:
        return no(f"{slot} takes the traffic: retry its deploy or roll back instead")
    if env.active_slot_id is None:
        return no("Nothing is live to check the data with: roll back or retry")
    held = await hold_text(db, owner)
    if held:
        return no(held)
    later = await _failed_since(db, env, members, owner, target)
    if later:
        return no(later)
    busy = await jobs.busy_job(db, env, env_keys(env.id, DeploymentKind.DISCARD))
    if busy is not None:
        return no(environments.busy_text(env, busy))
    unresolved = environments.unresolved_text(env)
    if unresolved:
        return no(unresolved)
    out.available = True
    return out


async def _failed_since(db: AsyncSession, env: Any, members: dict[str, Instance], owner: Instance | None,
                        target: Instance) -> str | None:
    """Why Discard <slot> would wipe more than the slot's own mark, or None. Settle clears the owner's whole
    ``data_dirty``, so its ``last`` must be a deploy of the slot too (the failed deploy, or a retry or new deploy
    of the slot that failed again). A later job on another member that left the data half-changed, such as an
    Update the data server that failed in its start, is retried first. A deploy of that member that succeeded
    after it settles it (a data server deploy never clears ``data_dirty`` itself, §7.5)."""
    last = ((owner.data_dirty if owner is not None else None) or {}).get("last") or {}
    last_id = _uuid(last.get("deployment_id"))
    if last_id is None:
        return None
    job = await db.scalar(select(Deployment).options(defer(Deployment.log)).where(
        Deployment.id == last_id, Deployment.environment_id == env.id))
    if job is None or (job.kind == DeploymentKind.DEPLOY and job.instance_id == target.id):
        return None
    if job.kind == DeploymentKind.DEPLOY and job.instance_id is not None:
        since = await db.scalar(select(Deployment.id).where(
            Deployment.instance_id == job.instance_id, Deployment.kind == DeploymentKind.DEPLOY,
            Deployment.status == DeploymentStatus.SUCCEEDED, Deployment.created_at > job.created_at).limit(1))
        if since is not None:
            return None
    slot = next((s for s, m in members.items() if m.id == job.instance_id), None)
    label = job_label(job.kind, slot=slot) if slot else kind_label(job.kind)
    return (f"{label} {job.id.hex[:8]} failed after {target.slot}'s deploy and left {env.name}'s data half-changed "
            "too: retry it first")


# What a job's end writes on the data owner (phase 3 §7.5), by kind and outcome. Outcomes: ``succeeded``,
# ``changed`` (failed or interrupted after a change began) and ``unchanged`` (failed before anything changed).
# Actions: ``mark`` data_dirty as P2 §8.4 (``mark_dirty``), ``clear`` it, ``clear_if_same_slot`` (only when its
# ``first`` is a deploy of this same slot), ``set`` (live_identity: the job's identity values, as P2), ``if_unset``
# (live_identity only when it has none, from AppPlan.identity), ``restore`` (live_identity as the restore step
# left it), ``keep`` (left as the job's own steps wrote it), ``now`` (the time).
_P2_DEPLOY_OK = {"data_dirty": "clear", "live_identity": "set", "fresh_data": "clear", "seed_snapshot_id": "clear"}


def owner_writes(kind: str, outcome: str, instance: Instance, *, environment: Any = None) -> dict[str, str]:
    """Which of the data owner's phase 2 fields a job of ``kind`` on ``instance`` writes when it ends with
    ``outcome``, and how (the §7.5 table, as a pure function). The fields always go to ``owner_for(instance)``:
    the instance itself for a standalone instance, a mode ``slot`` slot or the data server, whose phase 2 rules
    are unchanged. ``{}``: nothing on the owner."""
    if outcome not in ("succeeded", "changed", "unchanged"):
        raise ValueError(outcome)
    env = environment if environment is not None else loaded_environment(instance)
    member = env is not None
    if outcome == "unchanged":
        return {}
    if kind == DeploymentKind.DISCARD:
        return {"data_dirty": "clear"} if outcome == "succeeded" else {}
    if kind == "control":  # a control start or restart of any app slot (P2 §8.1 retry rule)
        return {"last_control_at": "now"}
    if kind == DeploymentKind.DEPLOY:
        if outcome == "changed":
            return {"data_dirty": "mark"}
        if not member or env.data_mode == "slot":
            return dict(_P2_DEPLOY_OK)
        if instance.slot == "data":
            # It ran no app migration, so it never settles a failed slot deploy; and fresh_data stays as its
            # start left it, so the first app slot deploy on the empty data still creates the first admin (§8.4 ᵃ).
            return {"live_identity": "if_unset", "fresh_data": "keep", "seed_snapshot_id": "clear"}
        return {"live_identity": "if_unset", "fresh_data": "clear", "seed_snapshot_id": "clear",
                "data_dirty": "clear_if_same_slot"}
    if kind in RESTORE_KINDS:
        return {"data_dirty": "clear", "live_identity": "restore"} if outcome == "succeeded" else {"data_dirty": "mark"}
    if kind == DeploymentKind.CONTENT and outcome == "succeeded":
        return {"content_pending": "clear"}
    return {}


def _restores_snapshot(dep: Deployment) -> bool:
    """A deploy or reset chain that restores a snapshot (its snapshot may since have been deleted)."""
    if dep.snapshot_id is not None:
        return dep.kind in (DeploymentKind.DEPLOY, DeploymentKind.RESET)
    return dep.kind in (DeploymentKind.DEPLOY, DeploymentKind.RESET) and "restore" in _steps(dep)


RETRY_PERMISSION = {
    "deploy": "deployments:create", "restore": "data:restore", "rollback": "data:restore", "reset": "data:reset",
    "backup": "data:backup", "snapshot": "data:backup", "admin": "deployments:create", "content": "deployments:create",
    # Phase 3 §4.1: Discard needs deployments:create as well (RETRY_EXTRA).
    "activate": "traffic:switch", "publish": "traffic:switch", "discard": "traffic:switch",
    "remove_slot": "environments:delete", "teardown": "environments:delete",
}
RETRY_EXTRA = {"discard": ("deployments:create",)}


SNAPSHOT_STEPS = ("restore", "files", "after_import")  # the steps of a chain that read the snapshot


def snapshot_steps_left(dep: Deployment, done_by: dict[str, str]) -> bool:
    """Whether a retry of a chain restoring a snapshot still has a step to run that needs the snapshot."""
    rows = _steps(dep)
    return any(key in rows and key not in done_by and rows[key].get("status") != "skipped" for key in SNAPSHOT_STEPS)


async def _snapshot_label(db: AsyncSession, snapshot_id: uuid.UUID | None) -> str:
    snap = await db.get(Snapshot, snapshot_id) if snapshot_id is not None else None
    return f"snapshot {snap.name}" if snap is not None else "a snapshot that was deleted"


async def seed_change_text(db: AsyncSession, instance: Instance, dep: Deployment) -> str | None:
    """A deploy retry seeds what its first attempt seeded; refused when the instance now starts from something
    else (changing the seed needs data:reset, §10.7), or has gone live since. None when they agree."""
    seed = instance.seed_snapshot_id if not instance.current_commit_sha else None
    if dep.snapshot_id is None and not _restores_snapshot(dep):
        if seed is None:
            return None
        return (f"This deployment started {instance.name} empty, and {instance.name} now starts from "
                f"{await _snapshot_label(db, seed)}: deploy the instance instead")
    if dep.snapshot_id is not None and dep.snapshot_id == seed:
        return None
    # A deleted snapshot that a never-live seed still pointed at can't happen (in_use_reason): with no seed now,
    # the seed was cleared since, and the retry would go live on the deleted snapshot's data instead of empty.
    started = f"This deployment started {instance.name} from {await _snapshot_label(db, dep.snapshot_id)}"
    if instance.current_commit_sha:
        return f"{started}, and {instance.name} has gone live since: deploy the instance instead"
    now = f"from {await _snapshot_label(db, seed)}" if seed is not None else "empty"
    return f"{started}, and {instance.name} now starts {now}: deploy the instance instead"


async def retry_refusal(db: AsyncSession, instance: Instance, dep: Deployment) -> str | None:
    """What would refuse the job if it were started again today (§8.1): a retry never gets around a check the
    first attempt had to pass. None when nothing does."""
    kind = dep.kind or DeploymentKind.DEPLOY
    if kind in (DeploymentKind.DEPLOY, DeploymentKind.SNAPSHOT, DeploymentKind.ADMIN, DeploymentKind.CONTENT):
        # Deploy is off while the data is held (§8.4); the retry the hold text means is the held job's own.
        held = await hold_text(db, instance)
        if held:
            return held
    if kind == DeploymentKind.SNAPSHOT:
        return dirty_snapshot_text(instance, await _environment_of(db, instance))
    if kind == DeploymentKind.BACKUP:
        if (dep.options or {}).get("files") and "files" not in capabilities(instance):
            return (f"{live_sha7(instance)}'s slipway.yml has no export_files command, so Slipway can't back up "
                    f"{instance.name}'s files")
        return await manual_cap_text(db, instance)
    if kind == DeploymentKind.CONTENT and not instance.content_pending:
        return f"{instance.name} has no starter content waiting to be added"
    if kind == DeploymentKind.ADMIN:
        pending = await db.scalar(select(FirstAdmin.id).where(FirstAdmin.instance_id == instance.id,
                                                             FirstAdmin.status == FirstAdminStatus.PENDING))
        if pending is None:
            return f"No first admin is waiting to be created in {instance.name}"
        if instance.status != InstanceStatus.RUNNING:
            return f"{instance.name} isn't running: start it, then create the first admin"
    return None


async def _retry_also_needs(db: AsyncSession, dep: Deployment, instance: Instance) -> list[str]:
    """The permissions POST /deployments/{id}/retry asks besides the kind's own (``permission``): data:reset to
    put back identity keys or to roll back shared data (mode ``server``, D17), instances:operate to stop the app
    for a snapshot."""
    out: list[str] = []
    options = dep.options or {}
    env = await _environment_of(db, instance)
    if options.get("restore_identity") or (dep.kind == DeploymentKind.ROLLBACK and env is not None
                                           and env.data_mode != "slot"):
        out.append("data:reset")
    if options.get("stop_app"):
        out.append("instances:operate")
    return out


async def retry_state(db: AsyncSession, dep: Deployment) -> dict[str, Any]:
    """``actions.retry`` of the deployment page (§8.1)."""
    instance = await _instance_of(db, dep)
    out: dict[str, Any] = {"available": False, "reason": None, "needs_confirm": dep.kind in RESTORE_KINDS,
                           "offers_skip_backup": False, "inherits": False,
                           "permission": RETRY_PERMISSION.get(dep.kind, "deployments:create")}
    if instance.environment_id is not None:  # a standalone instance's answer stays phase 2's (I1)
        out["also_needs"] = await _retry_also_needs(db, dep, instance)

    def no(reason: str) -> dict[str, Any]:
        return {**out, "reason": reason}

    if dep.status not in (DeploymentStatus.FAILED, DeploymentStatus.CANCELLED):
        return no("Only a failed or interrupted deployment can be retried")
    if dep.kind == DeploymentKind.DEPLOY:
        if not dep.commit_sha:
            return no("This deployment failed before it resolved a commit: deploy again instead")
        if dep.branch != instance.branch:
            return no(f"This deployment was of branch {dep.branch}, and the instance now deploys {instance.branch}: "
                      "deploy the instance instead")
        seed = await seed_change_text(db, instance, dep)
        if seed:
            return no(seed)
    if dep.kind in RESTORE_KINDS:
        latest = await latest_changing_job(db, instance)
        if latest is not None and latest.id != dep.id:
            return no(f"Only the most recent job of {instance.name} can be retried; "
                      f"{kind_noun(latest.kind)} {latest.id.hex[:8]} ran after it")
    inherit = await retry_inheritance(db, dep)
    if _restores_snapshot(dep):
        gone = dep.snapshot_id is None or await db.get(Snapshot, dep.snapshot_id) is None
        if gone and snapshot_steps_left(dep, inherit.done_by):
            # What is left to do (restore, files, after_import) reads the snapshot (§8.1, §10.8).
            return no("The snapshot this job restores was deleted; start a new reset instead")
    if dep.kind == DeploymentKind.SNAPSHOT and (dep.snapshot_id is None or await db.get(Snapshot, dep.snapshot_id) is None):
        return no("The snapshot this job took was deleted; take a new one instead")
    running = await active_job(db, instance.id)
    if running is not None:
        return no(busy_text(running))
    env = await _environment_of(db, instance)
    if env is not None:
        # The environment's fences, as the retry endpoint asks them through job_refusal (hold, an unresolved
        # switch, the slot that serves traffic), so the page never offers a retry the API refuses.
        from slipway.services import environments, jobs  # both import this module

        fenced = await jobs.environment_fence(db, env, await environments.members(db, env), instance=instance,
                                              kind=dep.kind or DeploymentKind.DEPLOY, options=dep.options or {},
                                              retry_of=dep)
        if fenced is not None:
            return no(fenced.text)
    refused = await retry_refusal(db, instance, dep)
    if refused:
        return no(refused)
    backup_row = _steps(dep).get("backup")
    skip = bool(backup_row and backup_row.get("status") == "failed")
    if skip and (dep.kind in RESTORE_KINDS or _restores_snapshot(dep)) and (
            data_shared_reason(instance) or refused_elsewhere(backup_row)):
        # Skipping the backup never lets data outside the host be replaced (D7, I4): the retry would only be
        # refused again in its backup step.
        skip = False
    return {**out, "available": True, "offers_skip_backup": skip, "inherits": inherit.inherit}


async def undo_state(db: AsyncSession, dep: Deployment) -> dict[str, Any]:
    """``actions.undo``: a finished restore or reset that is the latest changing job, with its backup ready (§8.3)."""
    out: dict[str, Any] = {"available": False, "backup_id": None, "files": False, "reason": None}
    if dep.kind not in (DeploymentKind.RESTORE, DeploymentKind.RESET) or dep.is_active:
        return out
    instance = await _instance_of(db, dep)
    latest = await latest_changing_job(db, instance)
    if latest is None or latest.id != dep.id:
        return out
    backup = await _backup_of(db, instance, dep.backup_id)
    if backup is None or backup.status != BackupStatus.READY:
        return out
    rule = restorable(instance, backup)
    return {"available": rule.ok, "backup_id": str(backup.id), "files": bool(backup.has_files), "reason": rule.reason}


async def job_actions(db: AsyncSession, dep: Deployment) -> dict[str, Any]:
    """``DeploymentDetail.actions``: what the deployment page offers, and why not."""
    roll = await rollback_state(db, dep)
    return {
        "retry": await retry_state(db, dep),
        "rollback": {"available": roll.available, "reason": roll.reason, "also_undoes": roll.also_undoes,
                     "backup_id": str(roll.backup.id) if roll.available and roll.backup else None},
        "undo": await undo_state(db, dep),
    }


# ---------------------------------------------------------------- the queue checks


def not_live_text(instance: Instance) -> str:
    return (f"Slipway doesn't know {instance.name}'s data commands yet: deploy it once more (any commit whose "
            "slipway.yml declares commands.dump), then try again.")


async def identity_lost(db: AsyncSession, instance: Instance) -> bool:
    """``live_identity`` is stored but reads as nothing (cleared by rotate-encryption-key, or another key)."""
    if instance.live_identity is not None:
        return False
    return bool(await db.scalar(select(Instance.live_identity.is_not(None)).where(Instance.id == instance.id)))


async def start_over_refusal(db: AsyncSession, instance: Instance, *, environment: Any = None) -> str | None:
    """Why Start over is refused, or None: the instance has gone live (phase 2). On the data server of a mode
    ``server`` environment, the rule is the environment's (§7.3): no app slot has ever gone live (none has a
    live commit, none is active, no Activate succeeded); the data server's own first deploy doesn't count."""
    env = environment if environment is not None else loaded_environment(instance)
    if env is None or env.data_mode == "slot" or instance.slot != "data":
        return f"{instance.name} has gone live; use Reset data" if instance.current_commit_sha else None
    went_live = env.active_slot_id is not None or bool(await db.scalar(
        select(Instance.id).where(Instance.environment_id == env.id, Instance.slot.in_(("blue", "green")),
                                  Instance.current_commit_sha.is_not(None)).limit(1)))
    if not went_live:
        went_live = bool(await db.scalar(select(Deployment.id).where(
            Deployment.environment_id == env.id, Deployment.kind == DeploymentKind.ACTIVATE,
            Deployment.status == DeploymentStatus.SUCCEEDED).limit(1)))
    return f"An app slot of {env.name} has gone live; use Reset data" if went_live else None


async def require_data_job(db: AsyncSession, instance: Instance, kind: str, *, start_over: bool = False) -> dict[str, Any]:
    """The checks every data endpoint shares (§13); raises HTTPException. Returns ``app_state.live`` ({} for Start over).

    Kinds: restore, rollback, reset, backup, snapshot, admin and content (``start_over`` with reset).
    """
    if kind not in KIND_LABELS or kind == DeploymentKind.DEPLOY:
        raise ValueError(kind)
    if instance.build_source != BuildSource.APP:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Only app instances (slipway.yml) can back up, restore or reset their data")
    live = live_state(instance)
    if start_over:
        refused = await start_over_refusal(db, instance)
        if refused:
            raise HTTPException(status.HTTP_409_CONFLICT, refused)
        live = {}
    elif live is None:
        raise HTTPException(status.HTTP_409_CONFLICT, not_live_text(instance))
    if not start_over:
        caps, sha7 = capabilities(instance), live_sha7(instance)
        if kind in RESTORE_KINDS and "backup" not in caps:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                "The live release's slipway.yml has no dump command, so Slipway can't back up the data first")
        if kind in RESTORE_KINDS and "restore" not in caps:
            raise HTTPException(status.HTTP_409_CONFLICT, "The live release's slipway.yml has no restore command")
        if kind == DeploymentKind.RESET and "reset" not in caps:
            raise HTTPException(status.HTTP_409_CONFLICT, f"slipway.yml at {sha7} declares no data volumes and restore "
                                                          "command, so Slipway can't reset it")
        if kind in (DeploymentKind.BACKUP, DeploymentKind.SNAPSHOT) and "backup" not in caps:
            raise HTTPException(status.HTTP_409_CONFLICT, f"{sha7}'s slipway.yml has no dump command, so Slipway "
                                                          f"can't back up {instance.name}")
        if kind == DeploymentKind.ADMIN and "first_admin" not in caps:
            raise HTTPException(status.HTTP_409_CONFLICT, f"{sha7}'s slipway.yml declares no first_admin")
        if kind == DeploymentKind.CONTENT and "starter_content" not in caps:
            raise HTTPException(status.HTTP_409_CONFLICT, f"{sha7}'s slipway.yml has no seed command")
    from slipway.services import deployer  # the deployer imports this module

    if deployer.runner.is_deleting(runner_keys(instance, kind)):
        raise HTTPException(status.HTTP_409_CONFLICT, "This instance is being deleted")
    running = await active_job(db, instance.id)
    if running is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, busy_text(running))
    if kind in (*RESTORE_KINDS, DeploymentKind.BACKUP, DeploymentKind.SNAPSHOT) and not start_over \
            and await identity_lost(db, instance):
        raise HTTPException(status.HTTP_409_CONFLICT, f"Deploy {instance.name} once: Slipway lost the keys its data was "
                                                      "made with (SLIPWAY_ENCRYPTION_KEY changed)")
    if kind in (DeploymentKind.SNAPSHOT, DeploymentKind.ADMIN, DeploymentKind.CONTENT):
        held = await hold_text(db, instance)
        if held:
            raise HTTPException(status.HTTP_409_CONFLICT, held)
    if kind == DeploymentKind.SNAPSHOT:
        dirty = dirty_snapshot_text(instance, await _environment_of(db, instance))
        if dirty:
            raise HTTPException(status.HTTP_409_CONFLICT, dirty)
    if kind in RESTORE_KINDS:
        shared = data_shared_reason(instance)
        if shared:
            raise HTTPException(status.HTTP_409_CONFLICT, shared)
    return live or {}


async def manual_cap_text(db: AsyncSession, instance: Instance) -> str | None:
    """The refusal when the instance has SLIPWAY_MANUAL_BACKUPS_MAX backups taken by hand (§4.3), or None."""
    cap = get_settings().manual_backups_max
    count = await db.scalar(select(func.count()).select_from(Backup).where(
        Backup.instance_id == instance.id, Backup.reason == BackupReason.MANUAL))
    if (count or 0) >= cap:
        return f"{instance.name} already has {cap} backups you took yourself; delete one first"
    return None


# ------------------------------------------------------------------ retention


async def pinned_backups(db: AsyncSession, instance: Instance) -> dict[uuid.UUID, str]:
    """The backups retention never prunes, and why (§4.3; also the 409 ``This backup is pinned: <why>``)."""
    pinned: dict[uuid.UUID, str] = {}

    def pin(value: Any, why: str) -> None:
        bid = _uuid(value)
        if bid is not None and bid not in pinned:
            pinned[bid] = why

    dirty = instance.data_dirty or {}
    first, last = dirty.get("first") or {}, dirty.get("last") or {}
    pin(first.get("backup_id"), f"it is the roll back point of failed {kind_noun(str(first.get('kind')))} "
                                f"{str(first.get('deployment_id') or '')[:8]}")
    pin(last.get("backup_id"), f"it was taken just before failed {kind_noun(str(last.get('kind')))} "
                               f"{str(last.get('deployment_id') or '')[:8]}")
    active = (await db.scalars(select(Deployment).options(defer(Deployment.log)).where(
        Deployment.instance_id == instance.id,
        Deployment.status.in_([DeploymentStatus.QUEUED, DeploymentStatus.RUNNING])))).all()
    for job in active:
        pin(job.backup_id, f"{kind_noun(job.kind)} {job.id.hex[:8]} is using it")
        pin(job.restore_backup_id, f"{kind_noun(job.kind)} {job.id.hex[:8]} is restoring it")
    latest = await latest_changing_job(db, instance)
    if latest is not None:
        d8 = latest.id.hex[:8]
        if latest.kind in (DeploymentKind.RESTORE, DeploymentKind.RESET):
            pin(latest.backup_id, f"it is kept for undoing {kind_noun(latest.kind)} {d8}")
        else:
            pin(latest.backup_id, f"it was taken before {kind_noun(latest.kind)} {d8}, the latest job that changed the data")
        pin(latest.restore_backup_id, f"{kind_noun(latest.kind)} {d8} restored it, and can be retried")
    return pinned


def choose_doomed(rows: Iterable[Backup], pinned: Iterable[uuid.UUID], keep: int) -> list[Backup]:
    """The automatic backups beyond the newest ``keep`` clean and newest DIRTY_KEEP dirty ones, pinned ones aside.

    Only ``ready`` rows are candidates: missing, changed, unverified and pending rows are never pruned
    automatically, and backups taken by hand are deleted by hand only.
    """
    pinned = set(pinned)
    ready = sorted((r for r in rows if r.status == BackupStatus.READY and r.reason != BackupReason.MANUAL),
                   key=lambda r: r.taken_at, reverse=True)
    clean = [r for r in ready if r.dirty_of is None and r.id not in pinned]
    dirty = [r for r in ready if r.dirty_of is not None and r.id not in pinned]
    return clean[max(1, keep):] + dirty[DIRTY_KEEP:]


def _expected(row: Backup) -> dict[str, int | None]:
    """The files a backup row recorded, with their sizes (the sidecar isn't size-checked)."""
    files: dict[str, int | None] = {f"{row.name}.dump": row.db_bytes}
    if row.has_files:
        files[f"{row.name}.files"] = row.files_bytes
    return files


def _judge(row: Backup, check: FileCheck, *, parts: Iterable[str] | None = None) -> tuple[str, bool]:
    """(status the host check gives the row, whether a hash was missing)."""
    no_hash = False
    for file, size in _expected(row).items():
        part = file.rsplit(".", 1)[1]
        if parts is not None and part not in parts:
            continue
        found = check.sizes.get(file)
        if found is None:
            return BackupStatus.MISSING, no_hash
        if size is not None and found != size:
            return BackupStatus.CHANGED, no_hash
        recorded = row.db_sha256 if part == "dump" else row.files_sha256
        if file in check.shas:
            if check.shas[file] is None:
                no_hash = True
            elif recorded and check.shas[file] != recorded:
                return BackupStatus.CHANGED, no_hash
    if row.status == BackupStatus.UNVERIFIED and row.db_bytes is None:
        return BackupStatus.UNVERIFIED, no_hash  # nothing recorded to compare with: the release step settles it
    return BackupStatus.READY, no_hash


async def _set_status(db: AsyncSession, row: Backup, read: str, new: str, at: datetime) -> bool:
    """Change the row only if nobody changed it since it was read (``WHERE id=? AND status=<read>``)."""
    result = await db.execute(update(Backup).where(Backup.id == row.id, Backup.status == read)
                              .values(status=new, checked_at=at).execution_options(synchronize_session=False))
    if result.rowcount:
        # Mirror the change on the loaded row as its stored state, so the session never writes it again.
        set_committed_value(row, "status", new)
        set_committed_value(row, "checked_at", at)
    return bool(result.rowcount)


@dataclass
class CheckResult:
    statuses: dict[uuid.UUID, str] = field(default_factory=dict)  # the status the host check gave each row
    warning: str | None = None  # the check couldn't run; no row was changed
    no_hash_tool: bool = False


CHECKABLE = (BackupStatus.READY, BackupStatus.MISSING, BackupStatus.CHANGED, BackupStatus.UNVERIFIED)


async def check_backups(remote: Remote, db: AsyncSession, rows: Iterable[Backup], backups: str, host: str, *,
                        rehash: bool = False, parts: Iterable[str] | None = None) -> CheckResult:
    """Check backups' files on the host and record what was found (§4.4). The caller commits.

    Present with the recorded size (and sha, when ``rehash``) → ready; absent → missing; another size → changed.
    A missing folder or an SSH error changes no row and gives a ``warning``. ``parts`` limits which files are
    checked (``("dump",)`` when a restore doesn't put the files back).
    """
    todo = [r for r in rows if r.status in CHECKABLE and NAME_RE.match(r.name or "")]
    result = CheckResult()
    parts = tuple(parts) if parts is not None else None
    for start in range(0, len(todo), CHECK_BATCH):
        batch = todo[start:start + CHECK_BATCH]
        files = [f for r in batch for f in _expected(r) if parts is None or f.rsplit(".", 1)[1] in parts]
        hashed = [f for r in batch for f, _ in _expected(r).items()
                  if rehash and (r.db_sha256 if f.endswith(".dump") else r.files_sha256)]
        try:
            code, output = await remote.run(file_check_command(backups, files, hashed=[f for f in hashed if f in files]),
                                            check=False, timeout=HASH_TIMEOUT if rehash else PROBE_TIMEOUT)
        except ssh.SSHError as exc:
            result.warning = f"Couldn't check the backups on {host} ({exc}); showing what Slipway recorded"
            return result
        check = parse_file_check(output)
        if check.nodir:
            result.warning = f"{backups} isn't on {host}; showing what Slipway recorded"
            return result
        if code != 0 and not check.sizes:
            result.warning = f"Couldn't check the backups on {host} (exit {code}); showing what Slipway recorded"
            return result
        now = utcnow()
        for row in batch:
            new, no_hash = _judge(row, check, parts=parts)
            result.no_hash_tool |= no_hash
            if not (new == row.status == BackupStatus.UNVERIFIED):
                await _set_status(db, row, row.status, new, now)  # lost only to a concurrent change of the row
            result.statuses[row.id] = new  # what the host showed
    return result


async def confirm_backup(remote: Remote, db: AsyncSession, row: Backup, backups: str, host: str, *,
                         files: bool = False) -> str | None:
    """Before restoring ``row``: its files present, with the recorded size and sha. None, or the refusal."""
    if row.status not in CHECKABLE:
        return f"The backup {row.name} isn't ready ({row.status})"
    parts = ("dump", "files") if files else ("dump",)
    found = await check_backups(remote, db, [row], backups, host, rehash=True, parts=parts)
    if found.warning:
        return f"The backup {row.name} on {host} is missing ({found.warning})"
    now = found.statuses.get(row.id)
    if now == BackupStatus.MISSING:
        return f"The backup {row.name} on {host} is missing"
    if now == BackupStatus.CHANGED:
        return f"The backup {row.name} on {host} has changed since Slipway took it (size or checksum differ); Slipway won't restore it"
    if now != BackupStatus.READY:
        return f"The backup {row.name} isn't ready ({now})"
    return None


async def settle_unverified(remote: Remote, db: AsyncSession, instance: Instance, backups: str) -> list[str]:
    """Rows left ``unverified`` by a restart (§4.4): a present final file is complete (it was moved there only
    after it was checked), so measure, hash and keep it; without one, forget the row. Returns log lines."""
    host = instance.host.name
    rows = (await db.scalars(select(Backup).where(Backup.instance_id == instance.id,
                                                  Backup.status == BackupStatus.UNVERIFIED))).all()
    rows = [r for r in rows if NAME_RE.match(r.name or "")]
    lines: list[str] = []
    for start in range(0, len(rows), CHECK_BATCH):
        batch = rows[start:start + CHECK_BATCH]
        files = [f"{r.name}.{part}" for r in batch for part in (("dump", "files") if r.has_files else ("dump",))]
        code, output = await remote.run(file_check_command(backups, [], hashed=files), check=False, timeout=HASH_TIMEOUT)
        check = parse_file_check(output)
        if check.nodir:
            for row in batch:
                await db.execute(delete(Backup).where(Backup.id == row.id, Backup.status == BackupStatus.UNVERIFIED))
                lines.append(f"Backup {row.name} never finished before Slipway restarted; forgot it")
            continue
        if code != 0 and not check.sizes:
            lines.append(f"Warning: couldn't check the backups left unfinished by a restart (exit {code})")
            continue
        for row in batch:
            size = check.sizes.get(f"{row.name}.dump")
            if size is None:
                await db.execute(delete(Backup).where(Backup.id == row.id, Backup.status == BackupStatus.UNVERIFIED))
                lines.append(f"Backup {row.name} never finished before Slipway restarted; forgot it")
                continue
            values: dict[str, Any] = {"status": BackupStatus.READY, "db_bytes": size,
                                      "db_sha256": check.shas.get(f"{row.name}.dump"), "checked_at": utcnow(),
                                      "finished_at": row.finished_at or utcnow()}
            files_size = check.sizes.get(f"{row.name}.files")
            if row.has_files and files_size is None:
                values.update(has_files=False, files_format=None, files_bytes=None, files_sha256=None)
                lines.append(f"Backup {row.name} lost its files archive in a restart; it is kept with the database only")
            elif row.has_files:
                values.update(files_bytes=files_size, files_sha256=check.shas.get(f"{row.name}.files"))
            await db.execute(update(Backup).where(Backup.id == row.id, Backup.status == BackupStatus.UNVERIFIED)
                             .values(**values).execution_options(synchronize_session=False))
            lines.append(f"Backup {row.name} was written before Slipway restarted; checked it and kept it ({human_bytes(size)})")
    return lines


async def apply_retention(remote: Remote, db: AsyncSession, instance: Instance, backups: str, *,
                          just_taken: uuid.UUID | None, say: Say) -> list[str]:
    """Remove the automatic backups beyond what the instance keeps (§4.3), right after one became ready.

    Files are removed only when the same session has just confirmed them with their recorded sizes, and their
    rows only after that. A failure logs a warning and never fails the job. Returns the names removed; the
    caller commits.
    """
    host = instance.host.name
    rows = (await db.scalars(select(Backup).where(Backup.instance_id == instance.id))).all()
    pinned = set(await pinned_backups(db, instance))
    if just_taken is not None:
        pinned.add(just_taken)
    keep = min(max(instance.keep_backups or 5, 1), 100)
    doomed = [r for r in choose_doomed(rows, pinned, keep) if NAME_RE.match(r.name or "")]
    if not doomed:
        return []
    try:
        found = await check_backups(remote, db, doomed, backups, host)
        if found.warning:
            await say(f"Warning: couldn't remove old backups: {found.warning}")
            return []
        confirmed = [r for r in doomed if found.statuses.get(r.id) == BackupStatus.READY]
        if not confirmed:
            return []
        code, output = await remote.run(remove_backup_command(backups, [r.name for r in confirmed]),
                                        check=False, timeout=PROBE_TIMEOUT)
    except (ssh.SSHError, DataError) as exc:
        await say(f"Warning: couldn't remove old backups: {exc}")
        return []
    if code != 0:
        last = next((ln for ln in reversed(output.splitlines()) if ln.strip()), f"exit {code}")
        await say(f"Warning: couldn't remove old backups: {last}")
        return []
    await db.execute(delete(Backup).where(Backup.id.in_([r.id for r in confirmed]))
                     .execution_options(synchronize_session=False))
    names = [r.name for r in confirmed]
    await say(f"Removed old backups: {', '.join(names)} (keeping the newest {keep})")
    return names


# ------------------------------------------------------------------ the Backups card


@dataclass
class BackupView:
    """A backup with what the Backups card and BackupOut show beside the stored fields."""

    row: Backup
    pinned: bool
    pinned_reason: str | None
    restorable: bool
    reason_text: str | None
    identity_note: str | None
    needs_reset_perm: bool
    dirty_note: str | None
    revision_short: str | None


async def backup_views(db: AsyncSession, instance: Instance, rows: Iterable[Backup]) -> list[BackupView]:
    rows = list(rows)
    pinned = await pinned_backups(db, instance)
    dirty_ids = {r.dirty_of for r in rows if r.dirty_of is not None}
    jobs: dict[uuid.UUID, Deployment] = {}
    if dirty_ids:
        found = await db.scalars(select(Deployment).options(defer(Deployment.log)).where(Deployment.id.in_(dirty_ids)))
        jobs = {d.id: d for d in found}
    out = []
    for row in rows:
        rule = restorable(instance, row, dirty_job=jobs.get(row.dirty_of) if row.dirty_of else None)
        out.append(BackupView(row=row, pinned=row.id in pinned, pinned_reason=pinned.get(row.id), restorable=rule.ok,
                              reason_text=rule.reason, identity_note=rule.identity_note,
                              needs_reset_perm=rule.needs_reset_perm, dirty_note=rule.dirty_note,
                              revision_short=revision_short(row.revision)))
    return out
