"""Build and run instances on remote Docker hosts over SSH.

Pipeline for one deployment:

1. Check the repository by its GitHub id, then resolve the branch to a commit SHA.
2. Download the source tarball on the Slipway server (the GitHub token never reaches the host)
   and refuse it if the build context, Dockerfile or compose file path is a link.
3. Upload it over SFTP and unpack into ``<folder>/releases/<sha12>-<deployment>``, where the
   instance's folder is ``Instance.deploy_dir`` or else ``<host deploy root>/<slug>``. Slipway marks
   the folder as the instance's (``.slipway-instance``) and refuses one holding other files.
4. Write ``shared/.env`` (mode 600) from the instance's encrypted environment variables.
   Compose mode writes them to ``shared/slipway.env`` and builds ``shared/.env`` on the host
   from the repository's ``.env`` followed by Slipway's values, so Slipway's values win. (A repository
   value that interpolates one Slipway overrides keeps the repository's value in ``${...}`` of the
   compose file; ``env_file: .env`` sees Slipway's.)
5. Check the host ports the deployment publishes against the ports in use on the host, and
   move taken ones to the next free port when the instance allows it (see ``services.ports``).
   Compose mode reads them from ``docker compose config`` and passes moved ports back through
   the compose file's own variables or ``shared/compose.ports.yml``; a Compose older than
   2.24.4 ignores that file's ``!override``, so then the release runs from the resolved compose
   file with the new ports (``shared/compose.resolved.json``).
6. ``docker build`` + ``docker run`` (Dockerfile mode) or ``docker compose up -d --build``.
7. Point ``current`` at the new release and prune old releases/images.

Every deployment gets its own release directory, so the one ``current`` points to is never
touched by a redeploy. A failed deployment removes its release again unless containers were
started from it. Persistent data must live in named volumes or absolute host paths:
relative bind mounts (``./data``) do not survive a redeploy.

App instances (slipway.yml) also run data jobs, each a Deployment with a ``kind`` (spec §7): restore, roll back
and reset run the live release again in place with data steps between build and start; Back up now, Take
snapshot, Create first admin and Add starter content use the live release as it runs; Start over cleans up
after failed first deploys. Nothing replaces app data before a checked copy of it is on the host (I1).

Claimed instances (see ``api.v1.unmanaged``) were running before Slipway knew them. A claimed
compose project keeps its project name, so Compose replaces its containers and keeps its named
volumes. A claimed standalone container is stopped just before ``docker run``, removed once the
new container started (or started again if it did not), and reached by its id until then. No
command run for a claimed instance removes a volume.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import posixpath
import queue
import re
import shlex
import tarfile
import tempfile
import threading
import time
import unicodedata
import uuid
import zlib
from collections import Counter, defaultdict, deque
from collections.abc import AsyncIterator, Awaitable, Callable, Hashable, Iterable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from sqlalchemy import delete, func, null, select, update

from slipway import __version__
from slipway.core.config import get_settings
from slipway.core.permissions import Perm
from slipway.db.base import Base, utcnow
from slipway.db.session import session_scope
from slipway.models import (
    Backup,
    BackupReason,
    BackupStatus,
    BuildSource,
    DataMode,
    Deployment,
    DeploymentKind,
    DeploymentStatus,
    Environment,
    FirstAdmin,
    FirstAdminStatus,
    FreshData,
    Host,
    Instance,
    InstanceStatus,
    Repository,
    Snapshot,
    SnapshotStatus,
    User,
)
from slipway.models.data import REVISION_MAX_BYTES
from slipway.models.environment import SECRETS_LOST
from slipway.services import audit, data, environments, manifest, ports, snapfile, snapshots, ssh, switchyard, traffic
from slipway.services.github import CommitInfo, GitHubClient, GitHubError
from slipway.services.repos import github_token_for
from slipway.services.snapfile import SnapshotError

log = logging.getLogger(__name__)

q = shlex.quote
KEEP_RELEASES = 3
SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SAFE_PATH = re.compile(r"^[A-Za-z0-9._/@+-]+$")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\Z")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_CONTAINER_ID = re.compile(r"[0-9a-f]{12,64}")

# Small image used to delete files that containers wrote as root (pulled on first use).
CLEANUP_IMAGE = "alpine:3.20"
# The stored build log keeps its first and last part, about 1 MB in total.
LOG_HEAD_CHARS = 512 * 1024
LOG_TAIL_CHARS = 512 * 1024
MAX_LINE_CHARS = ssh.MAX_LINE_CHARS  # per line of the stored log, as LogSink clips with ssh.clip_line
# Seconds to wait between attempts to record a deployment's result.
FINISH_RETRY_DELAYS: tuple[float, ...] = (0.5, 1, 2, 4, 8, 15, 30)

ENV_UNREADABLE = "Environment variables could not be decrypted; re-enter them on the instance and deploy again"
# A member's variables are its environment's (phase 3 §6): they are re-entered there.
ENV_UNREADABLE_MEMBER = ("{env}'s environment variables could not be decrypted; re-enter them in the environment's "
                         "settings and run this again")

ConnectFactory = Callable[[ssh.SSHTarget], AbstractAsyncContextManager[ssh.RemoteSession]]
GitHubFactory = Callable[[str | None], GitHubClient]


class DeployError(RuntimeError):
    pass


class RunnerBusy(RuntimeError):
    pass


# ---------------------------------------------------------------------- validation


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:63].strip("-")
    if not SLUG_RE.match(slug):
        raise ValueError("Name must contain letters or numbers")
    return slug


def clean_relative_path(value: str, *, allow_dot: bool = False) -> str:
    """Normalise a repository-relative path, rejecting absolute paths, traversal and options."""
    value = (value or "").strip()
    norm = posixpath.normpath(value) if value else "."
    if norm == ".":
        if allow_dot:
            return "."
        raise ValueError("Path is required")
    if norm.startswith("/") or norm.split("/")[0] == ".." or not _SAFE_PATH.match(norm):
        raise ValueError(f"'{value}' is not a safe relative path")
    if norm.startswith("-"):  # docker reads "-" as stdin and "-x" as an option
        raise ValueError(f"'{value}' is not a safe relative path: it must not start with '-'")
    return norm


def clean_deploy_root(value: str) -> str:
    raw = (value or "").strip()
    norm = posixpath.normpath(raw) if raw else ""
    if not norm.startswith("/") or norm == "/" or ".." in raw.split("/") or not _SAFE_PATH.match(norm):
        raise ValueError("Deploy root must be an absolute path such as /opt/slipway")
    return norm


# Folders an instance's own folder may never be, or be inside of: the system's, and the roots that hold
# other data (Unraid's shares and disks among them). ``rm`` runs inside an instance's folder, so this
# keeps a typo from pointing it at one of them.
_RESERVED_DIRS = frozenset({
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/media", "/mnt", "/opt", "/proc", "/root",
    "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var", "/var/lib", "/mnt/user", "/mnt/user0", "/mnt/cache",
    "/mnt/disks", "/mnt/remotes", "/mnt/addons", "/mnt/rootshare", "/mnt/user/appdata", "/mnt/user/system",
    "/mnt/user/domains", "/mnt/user/isos",
})
_RESERVED_TREES = ("/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/sbin", "/sys", "/usr", "/var/lib/docker")
_DISK_RE = re.compile(r"^/mnt/(?:disk\d+|cache[\w-]*|pool[\w-]*)$")


def clean_instance_dir(value: str) -> str:
    """An instance's own folder: absolute, safe, and not a system folder or a root that holds other data."""
    try:
        norm = clean_deploy_root(value)
    except ValueError:
        raise ValueError("The folder must be an absolute path such as /mnt/user/appdata/my-app") from None
    if norm in _RESERVED_DIRS or _DISK_RE.match(norm) or any(_inside(norm, t) for t in _RESERVED_TREES):
        raise ValueError(f"{norm} is a system folder or holds other data; give the instance a folder of its own, "
                         "such as /mnt/user/appdata/my-app")
    return norm


def ram_backed(host: Host, path: str) -> bool:
    """On Unraid only /boot and /mnt survive a restart; the rest of the filesystem lives in RAM."""
    return (host.os_info or "").startswith("Unraid") and not (_inside(path, "/mnt") or _inside(path, "/boot"))


def clean_env(env: dict[str, str]) -> dict[str, str]:
    for key, value in env.items():
        if not ENV_KEY_RE.match(key):
            raise ValueError(f"'{key}' is not a valid environment variable name")
        if "\n" in value or "\r" in value:
            raise ValueError(f"Value for {key} must be a single line")
        if "\x00" in value:
            raise ValueError(f"Value for {key} contains a NUL character")
    return env


def clean_text(value: str) -> str:
    """Text PostgreSQL accepts: NUL becomes U+FFFD and unpaired surrogates are replaced."""
    return value.replace("\x00", "�").encode("utf-8", "replace").decode("utf-8")


def _fit(model: type[Base], column: str, value: str) -> str:
    """``value`` cleaned and cut to the length of ``model.column``."""
    return clean_text(value)[: model.__table__.c[column].type.length]


def render_env(env: dict[str, str]) -> str:
    """``KEY=value`` lines for ``docker run --env-file``, which takes values literally."""
    return "".join(f"{k}={v}\n" for k, v in sorted(clean_env(dict(env)).items()))


def _dotenv_quote(value: str) -> str:
    # Compose reads single-quoted values literally (only \' is an escape); the rest need double
    # quotes with backslash, double quote and $ escaped. Older Compose releases treat any quote
    # after a backslash as escaped, so a trailing backslash is left unquoted where that is safe.
    if value.endswith("\\") and value == value.strip() and not any(c in value for c in "$#'\""):
        return value
    if "'" not in value and not value.endswith("\\"):
        return f"'{value}'"
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "$$")
    return f'"{escaped}"'


def render_compose_env(env: dict[str, str]) -> str:
    """Lines for Compose's dotenv parser, quoted so every value arrives unchanged."""
    return "".join(f"{k}={_dotenv_quote(v)}\n" for k, v in sorted(clean_env(dict(env)).items()))


# ------------------------------------------------------------------------ commands


@dataclass(frozen=True)
class InstancePaths:
    """An instance's folder on its host, ``root/slug``: ``slug`` is the folder's own name (for a folder
    the instance was given, not necessarily the instance's slug)."""

    root: str
    slug: str

    @classmethod
    def of(cls, base: str) -> InstancePaths:
        return cls(posixpath.dirname(base), posixpath.basename(base))

    @property
    def base(self) -> str:
        return f"{self.root}/{self.slug}"

    @property
    def releases(self) -> str:
        return f"{self.base}/releases"

    @property
    def shared(self) -> str:
        return f"{self.base}/shared"

    @property
    def env_file(self) -> str:
        return f"{self.shared}/.env"

    @property
    def slipway_env_file(self) -> str:
        """Compose mode: Slipway's own values, merged after the repository's .env into ``env_file``."""
        return f"{self.shared}/slipway.env"

    @property
    def ports_override_file(self) -> str:
        """Compose mode: replaces the ``ports`` of services whose host ports Slipway moved."""
        return f"{self.shared}/compose.ports.yml"

    @property
    def resolved_compose_file(self) -> str:
        """Compose mode, older Compose only: the whole resolved compose file with the moved ports.

        Holds interpolated environment values, so it is written mode 600 like ``env_file``.
        """
        return f"{self.shared}/compose.resolved.json"

    @property
    def current(self) -> str:
        return f"{self.base}/current"

    @property
    def backups(self) -> str:
        """App mode: the instance's backups (0700), each a ``<name>.dump`` with its sidecar (services.data)."""
        return data.backups_dir(self.base)

    @property
    def incoming(self) -> str:
        """App mode: where backups are written before they are checked; emptied by every job's first host step."""
        return data.incoming_dir(self.base)

    @property
    def lock(self) -> str:
        """App mode: the host lock, naming the job and the PID of the command it runs (§4.5)."""
        return data.lock_path(self.base)

    def release(self, sha: str, deployment_id: uuid.UUID) -> str:
        return f"{self.releases}/{sha[:12]}-{deployment_id.hex[:8]}"


def instance_dir(instance: Instance, host: Host | None = None) -> str:
    """The instance's folder on its host: ``deploy_dir``, or ``<host deploy root>/<slug>``."""
    if not SLUG_RE.match(instance.slug):
        raise DeployError(f"Invalid instance slug {instance.slug!r}")
    try:
        if instance.deploy_dir:
            return clean_instance_dir(instance.deploy_dir)
        return f"{clean_deploy_root((host or instance.host).deploy_root)}/{instance.slug}"
    except ValueError as exc:
        raise DeployError(str(exc)) from exc


def paths_for(instance: Instance) -> InstancePaths:
    return InstancePaths.of(instance_dir(instance))


MARKER_FILE = ".slipway-instance"
# What Slipway puts in an instance's folder; nothing else in it is ever removed.
SLIPWAY_ENTRIES = ("releases", "shared", "current", data.BACKUPS_DIR, data.LOCK_FILE, MARKER_FILE)
DIR_MARK = "slipway-dir:"


def take_dir_command(instance: Instance) -> str:
    """Create the instance's folder or accept it, and mark it as the instance's.

    A folder is accepted when it is new or empty, already marked as this instance's, or holds only
    what Slipway puts there (a folder from before the marker). Otherwise prints a ``DIR_MARK`` line
    and fails, before anything is written.
    """
    paths = paths_for(instance)
    base, marker, me = q(paths.base), q(f"{paths.base}/{MARKER_FILE}"), q(str(instance.id))
    keep = " ".join(f"-e {q(n)}" for n in SLIPWAY_ENTRIES)
    return (
        f"mkdir -p -- {base} 2>/dev/null; [ -d {base} ] && [ -w {base} ] || {{ echo {q(DIR_MARK + ' not-writable')}; exit 1; }}; "
        f"if [ -f {marker} ]; then owner=$(head -n 1 {marker}); "
        f'[ "$owner" = {me} ] || {{ echo "{DIR_MARK} owner $owner"; exit 1; }}; '
        f"else other=$(ls -A {base} | grep -v -x {keep} | head -n 5 | tr '\\n' ' '); "
        f'[ -z "$other" ] || {{ echo "{DIR_MARK} other $other"; exit 1; }}; fi; '
        f"printf '%s\\n' {me} > {marker}"
    )


def take_dir_error(instance: Instance, output: str) -> DeployError:
    paths, host = paths_for(instance), instance.host
    line = next((ln.split(DIR_MARK, 1)[1].strip() for ln in output.splitlines() if DIR_MARK in ln), "")
    if line.startswith("owner"):
        return DeployError(f"{paths.base} on {host.name} belongs to another Slipway instance; give this one its own folder")
    if line.startswith("other"):
        found = line.removeprefix("other").strip()
        return DeployError(f"{paths.base} on {host.name} already holds files that are not Slipway's ({found}); "
                           "choose an empty or new folder")
    return DeployError(
        f"Slipway can't create or write to {paths.base} on {host.name} as {host.username}. On the host, run: "
        f"sudo mkdir -p {q(paths.base)} && sudo chown {q(host.username)} {q(paths.base)}"
    )


def _project_dir(instance: Instance, release_dir: str) -> str:
    """The directory holding the compose file in a release: Compose resolves relative paths from it."""
    return posixpath.normpath(posixpath.join(release_dir, posixpath.dirname(instance.compose_file) or "."))


def _compose(
    instance: Instance, override: str | None = None, *, resolved: str | None = None, release_dir: str | None = None
) -> str:
    """The compose command line.

    The port files are only passed where containers are created (start, stop, restart and logs do
    not depend on the host ports): ``override`` is added after the compose file, and ``resolved``
    replaces it, keeping the project directory in ``release_dir``.
    """
    env_file = paths_for(instance).env_file
    base = f"docker compose -p {q(instance.compose_project)} --env-file {q(env_file)}"
    if resolved:
        if release_dir is None:
            raise ValueError("resolved needs release_dir")
        return f"{base} --project-directory {q(_project_dir(instance, release_dir))} -f {q(resolved)}"
    extra = f" -f {q(override)}" if override else ""
    return f"{base} -f {q(instance.compose_file)}{extra}"


def compose_config_command(
    instance: Instance, release_dir: str, *, override: str | None = None, resolved: str | None = None,
    interpolate: bool = True,
) -> str:
    """Print the resolved compose file as JSON, as a hex dump (``od``) so it arrives byte for byte.

    Run after the merged ``.env`` is in place. On failure prints Compose's error instead. The
    output holds environment values: it is parsed, never logged.
    """
    compose = _compose(instance, override, resolved=resolved, release_dir=release_dir)
    flag = "" if interpolate else " --no-interpolate"
    return (
        f"cd {q(release_dir)} && "
        f"{{ out=$({compose} config --format json{flag} 2>/dev/null) || {{ {compose} config --quiet{flag}; exit 1; }}; }} && "
        "printf '%s' \"$out\" | od -An -v -tx1"
    )


def _label(instance: Instance) -> str:
    return f"slipway.instance={instance.id}"


def _remove_containers(instance: Instance) -> str:
    """Remove the Dockerfile-mode container and its anonymous volumes (a claimed instance keeps them).

    Containers are found by this instance's label, never by name alone, so a container of
    another instance that happens to have the same name is left alone.
    """
    v = "" if instance.claim else " -v"
    return f"docker ps -aq --filter {q('label=' + _label(instance))} | xargs -r docker rm -f{v} >/dev/null 2>&1 || true"


def _compose_project_down(instance: Instance) -> str:
    """Remove the compose project's containers by project name, with their anonymous volumes.

    A claimed instance keeps anonymous volumes: they may hold the app's data from before the claim.
    Named volumes are never removed.
    """
    p = q(instance.compose_project)
    v = "" if instance.claim else " -v"
    return f"(cd / && docker compose -p {p} rm -f -s{v}; docker compose -p {p} down --remove-orphans) >/dev/null 2>&1 || true"


# ------------------------------------------------- claimed standalone containers
#
# A claimed standalone container has no ``slipway.instance`` label, so it is reached by the id
# stored in ``Instance.claim`` until the first deployment replaces it: that deployment stops it
# just before ``docker run``, removes it (never its volumes) once the new container started, and
# starts it again if ``docker run`` failed.


def _claimed_id(instance: Instance) -> str:
    cid = instance.claimed_container or ""
    if not _CONTAINER_ID.fullmatch(cid):
        raise DeployError(f"Invalid claimed container id {cid!r}")
    return cid


def claimed_state_command(instance: Instance) -> str:
    """Prints ``true`` / ``false`` (running or not), or ``missing`` when the container is gone."""
    return f"docker container inspect --format '{{{{.State.Running}}}}' {_claimed_id(instance)} 2>/dev/null || echo missing"


def _stop_claimed(instance: Instance) -> str:
    """Stop the claimed container if it is still there; fail (so nothing runs twice) if it won't stop."""
    cid = _claimed_id(instance)
    return f"if docker container inspect {cid} >/dev/null 2>&1; then docker stop {cid} >/dev/null || exit 1; fi"


def claimed_remove_command(instance: Instance) -> str:
    """Remove the claimed container, keeping its volumes (no ``-v``)."""
    cid = _claimed_id(instance)
    return f"if docker container inspect {cid} >/dev/null 2>&1; then docker rm -f {cid} >/dev/null; fi"


PULL_NEVER_UNSUPPORTED = "docker run on this host does not accept --pull=never: Slipway needs Docker 20.10 or later"
# Parses the run flags without running anything. An older CLI rejects --pull only when the
# container is started, after the running one was removed, so this runs before the build.
_PULL_NEVER_CHECK = f"docker run --pull=never --help >/dev/null 2>&1 || {{ echo {q(PULL_NEVER_UNSUPPORTED)}; exit 1; }}"


def _root_rm(parent: str, name: str) -> str:
    """Delete ``parent/name`` through a throwaway container, for files containers wrote as root."""
    return f"docker run --rm --network none -v {parent}:/r {CLEANUP_IMAGE} rm -rf -- /r/{name}"


REPO_ENV_FILE = ".env.slipway-repo"  # the repository's own .env, once .env is a link to shared/.env


def compose_env_command(instance: Instance, release_dir: str) -> str:
    """Build ``shared/.env``: the repository's .env defaults, with Slipway's values after them so they win.

    The first run moves the repository's .env aside before linking .env to ``shared/.env``, so running it
    again on the same release (a port move, a retry) still starts from the repository's defaults.
    """
    paths = paths_for(instance)
    project_dir = _project_dir(instance, release_dir)
    env, merged = q(paths.env_file), q(paths.env_file + ".new")
    return (
        f"cd {q(project_dir)} && umask 077 && "
        f"{{ if [ -f .env ] && [ ! -L .env ]; then mv -f .env {REPO_ENV_FILE}; fi; }} && "
        f"{{ if [ -f {REPO_ENV_FILE} ] && [ ! -L {REPO_ENV_FILE} ]; then cat {REPO_ENV_FILE}; echo; fi; "
        f"cat {q(paths.slipway_env_file)}; }} > {merged} && "
        f"mv -f {merged} {env} && ln -sfn {env} .env"
    )


def build_commands(
    instance: Instance, release_dir: str, sha: str, *, override: str | None = None, resolved: str | None = None
) -> list[str]:
    """Commands (run in order) that build and start a release.

    When Slipway moved ports that the compose file fixes, ``override`` is the ports override file,
    or ``resolved`` the whole resolved compose file to use instead (older Compose).
    """
    paths = paths_for(instance)
    label = _label(instance)
    if instance.build_source == BuildSource.COMPOSE:
        return [
            compose_env_command(instance, release_dir),
            _remove_containers(instance),
            f"cd {q(release_dir)} && {_compose(instance, override, resolved=resolved, release_dir=release_dir)} "
            "up -d --build --remove-orphans",
        ]

    image = f"slipway/{instance.slug}:{sha[:12]}"
    run = [
        # Never pull: slipway/<slug> on Docker Hub belongs to someone else.
        "docker run -d --pull=never",
        f"--name {q(instance.container_name)}",
        "--restart unless-stopped",
        f"--env-file {q(paths.env_file)}",
        f"--label {q(label)} --label slipway.managed=true",
    ]
    for p in instance.ports:
        run.append(f"-p {int(p['host'])}:{int(p['container'])}/{'udp' if p.get('protocol') == 'udp' else 'tcp'}")
    for v in instance.volumes:
        run.append(f"-v {q(str(v['source']) + ':' + str(v['target']))}")
    run.append(q(image))
    return [
        # Fail here, before the running container is removed, if docker run cannot take
        # --pull=never or the build exits 0 without loading the image (e.g. a docker-container
        # buildx builder).
        f"{_PULL_NEVER_CHECK}; cd {q(release_dir)} && BUILDKIT_PROGRESS=plain docker build --pull "
        f"-t {q(image)} -f {q(instance.dockerfile_path)} --label {q(label)} {q(instance.build_context)} "
        f"&& docker image inspect --format . {q(image)} >/dev/null",
        (f"{_stop_claimed(instance)}; " if instance.claimed_container else "")
        + f"{_remove_containers(instance)}; {_compose_project_down(instance)}",
        " ".join(run),
    ]


def prune_command(instance: Instance, release_dir: str) -> str:
    """Remove old releases and superseded images.

    Never removes the release ``current`` points to or the one just deployed. Exits non-zero
    when some release could not be removed. The loop runs in a subshell, so its ``exit`` ends
    only the loop in every shell (zsh runs a pipeline's last part in the current shell).
    """
    paths = paths_for(instance)
    releases = q(paths.releases)
    keep = q(posixpath.basename(release_dir))
    return (
        f"cd {releases} || exit 1; "
        f"find . -maxdepth 1 -name '.upload-*' -mmin +60 -delete 2>/dev/null; "
        f"cur=$(readlink {q(paths.current)}); cur=${{cur##*/}}; "
        f"ls -1t | tail -n +{KEEP_RELEASES + 1} | ( failed=0; while IFS= read -r d; do "
        f'{{ [ "$d" = "$cur" ] || [ "$d" = {keep} ]; }} && continue; '
        f'rm -rf -- "$d" 2>/dev/null || {_root_rm(releases, chr(34) + "$d" + chr(34))} || failed=1; '
        f"done; exit $failed ); rc=$?; "
        f"docker image ls --format '{{{{.Repository}}}}:{{{{.Tag}}}}' {q('slipway/' + instance.slug)} "
        f"| tail -n +{KEEP_RELEASES + 1} | xargs -r docker image rm >/dev/null 2>&1; "
        f"docker image prune -f --filter {q('label=' + _label(instance))} >/dev/null 2>&1; "
        f"docker image prune -f --filter {q('label=com.docker.compose.project=' + instance.compose_project)} >/dev/null 2>&1; "
        f"exit $rc"
    )


ACTIONS = ("start", "stop", "restart")


def _owned_container(instance: Instance) -> str:
    """Shell test: the container named after the instance carries this instance's label."""
    fmt = '{{index .Config.Labels "slipway.instance"}}'
    return f'[ "$(docker container inspect -f {q(fmt)} {q(instance.container_name)} 2>/dev/null)" = {q(str(instance.id))} ]'


def _not_owned_message(instance: Instance) -> str:
    return q(f"No container named {instance.container_name} belongs to this instance")


def control_command(instance: Instance, action: str) -> str:
    if action not in ACTIONS:
        raise ValueError(f"Unknown action {action}")
    if instance.claimed_container:
        return f"docker {action} {_claimed_id(instance)}"
    if instance.build_source == BuildSource.APP:
        return _app_projects_command(instance, action)
    if instance.build_source == BuildSource.COMPOSE:
        if instance.claim_pending:  # no release yet: Compose finds the project's containers by name
            return f"cd / && docker compose -p {q(instance.compose_project)} {action}"
        return f"cd {q(paths_for(instance).current)} && {_compose(instance)} {action}"
    return (
        f"{_owned_container(instance)} || {{ echo {_not_owned_message(instance)}; exit 1; }}; "
        f"docker {action} {q(instance.container_name)}"
    )


CONTAINER_FIELDS = ("Names", "Image", "State", "Status", "Ports", "RunningFor")
# One JSON object per container with only these fields: ``{{json .}}`` includes every label, so
# its line can pass the ``ssh.MAX_LINE_CHARS`` cap and no longer parse.
_CONTAINER_FORMAT = "{" + ",".join(f'"{k}":{{{{json .{k}}}}}' for k in CONTAINER_FIELDS) + "}"


def _project_filter(project: str) -> str:
    return q(f"label=com.docker.compose.project={project}")


def _app_projects_command(instance: Instance, action: str) -> str:
    """start / restart the app's projects in order, stop them in reverse; a project with no containers is skipped."""
    projects = app_projects(instance)
    if action == "stop":
        projects = projects[::-1]
    if not projects:
        return "echo 'Nothing to do: this app has not been deployed yet'"
    # A failed docker ps fails the action too: its empty output would otherwise read as "no containers".
    parts = [f'if ids=$(docker ps -aq --filter {_project_filter(p)}); then '
             f'[ -z "$ids" ] || docker compose -p {q(p)} {action} || rc=1; else rc=1; fi'
             for p in projects]
    return "cd / && rc=0; " + "; ".join(parts) + "; exit $rc"


def status_command(instance: Instance) -> str:
    if instance.build_source == BuildSource.APP:
        projects = app_projects(instance)
        return "; ".join(f"docker ps -a --filter {_project_filter(p)} --format {q(_CONTAINER_FORMAT)}"
                         for p in projects) or "true"
    if instance.build_source == BuildSource.COMPOSE:
        flt = f"label=com.docker.compose.project={instance.compose_project}"
    else:
        flt = f"label=slipway.instance={instance.id}"
    command = f"docker ps -a --filter {q(flt)} --format {q(_CONTAINER_FORMAT)}"
    if instance.claimed_container:
        command += f"; docker ps -a --filter id={_claimed_id(instance)} --format {q(_CONTAINER_FORMAT)}"
    return command


def logs_command(instance: Instance, tail: int = 200) -> str:
    tail = max(1, min(int(tail), 5000))
    if instance.build_source == BuildSource.APP:
        projects = app_projects(instance)
        if not projects:
            return "echo 'This app has not been deployed yet'"
        return "cd / && { " + "; ".join(
            f"docker compose -p {q(p)} logs --tail {tail} --timestamps --no-color" for p in projects) + "; } 2>&1"
    if instance.claimed_container:
        return f"docker logs --tail {tail} --timestamps {_claimed_id(instance)} 2>&1"
    if instance.build_source == BuildSource.COMPOSE and instance.claim_pending:
        return f"cd / && docker compose -p {q(instance.compose_project)} logs --tail {tail} --timestamps --no-color 2>&1"
    if instance.build_source == BuildSource.COMPOSE:
        return (
            f"cd {q(paths_for(instance).current)} && "
            f"{_compose(instance)} logs --tail {tail} --timestamps --no-color 2>&1"
        )
    return (
        f"if {_owned_container(instance)}; then "
        f"docker logs --tail {tail} --timestamps {q(instance.container_name)} 2>&1; "
        f"else echo {_not_owned_message(instance)}; fi"
    )


def teardown_command(instance: Instance) -> str:
    """Stop and remove what the instance runs on its host, whichever build mode deployed it."""
    paths = paths_for(instance)
    images = (
        f"{{ docker image ls -q {q('slipway/' + instance.slug)}; "
        f"docker image ls -aq --filter {q('label=' + _label(instance))}; "
        f"docker image ls -aq --filter {q('label=com.docker.compose.project=' + instance.compose_project)}; }} "
        f"| sort -u | xargs -r docker image rm -f >/dev/null 2>&1"
    )
    app: list[str] = []
    if instance.build_source == BuildSource.APP:
        state = instance.app_state or {}
        # Read through command_argv: app_state holds either the old list form or {"argv", "stream"}.
        stop = manifest.command_argv((state.get("commands") or {}).get("stop"))
        if stop:
            app.append(f"({app_command(paths.current, stop)}) >/dev/null 2>&1")
        app += [f"(cd / && docker compose -p {q(p)} down --remove-orphans) >/dev/null 2>&1" for p in app_known_projects(instance)]
        refs = sorted({r for refs in (state.get("releases") or {}).values() for r in refs if manifest.IMAGE_RE.match(r)})
        if refs:  # without -f: one another instance's container still uses stays
            app.append(f"docker image rm {' '.join(q(r) for r in refs)} >/dev/null 2>&1")
    return "; ".join([
        *app,
        *([claimed_remove_command(instance)] if instance.claimed_container else []),
        _remove_containers(instance),
        _compose_project_down(instance),
        f"(cd {q(paths.current)} && {_compose(instance)} down --remove-orphans --rmi local) >/dev/null 2>&1",
        images,
        "true",
    ])


def leftovers_command(instance: Instance) -> str:
    """Prints the ids of any container still belonging to the instance (stderr is mixed in)."""
    claimed = f" && docker ps -aq --filter id={_claimed_id(instance)}" if instance.claimed_container else ""
    app = "".join(f" && docker ps -aq --filter {_project_filter(p)}" for p in app_known_projects(instance))
    return (
        f"docker ps -aq --filter {q('label=' + _label(instance))} && "
        f"docker ps -aq --filter {q('label=com.docker.compose.project=' + instance.compose_project)}"
        f"{claimed}{app}"
    )


def _container_ids(output: str) -> list[str]:
    """Container ids in command output, ignoring warnings docker prints to stderr."""
    return [line.strip() for line in output.splitlines() if _CONTAINER_ID.fullmatch(line.strip())]


def release_users_command(instance: Instance) -> str:
    """Prints the project directory of each of the instance's compose containers.

    Fails when docker cannot list them. The ids go through xargs: zsh does not split ``$ids``.
    """
    fmt = '{{index .Config.Labels "com.docker.compose.project.working_dir"}}'
    flt = q("label=com.docker.compose.project=" + instance.compose_project)
    more = "".join(
        f"more=$(docker ps -aq --filter {_project_filter(p)}) && ids=$(printf '%s\\n%s' \"$ids\" \"$more\" | sed '/^$/d') && "
        for p in app_known_projects(instance)
    )
    return (
        f"ids=$(docker ps -aq --filter {flt}) && {more}"
        f"{{ [ -z \"$ids\" ] || printf '%s\\n' \"$ids\" | xargs docker container inspect -f {q(fmt)}; }}"
    )


def unpack_command(release_dir: str, upload: str) -> str:
    """Unpack the uploaded tarball into a new release, then remove the upload either way."""
    return (
        f"mkdir -p {q(release_dir)} && tar -xzf {q(upload)} -C {q(release_dir)} --strip-components=1; "
        f"rc=$?; rm -f {q(upload)}; exit $rc"
    )


def discard_command(instance: Instance, release_dir: str, upload: str) -> str:
    """Remove the upload and the release of a deployment that failed before ``current`` moved."""
    releases = q(paths_for(instance).releases)
    return (
        f"rm -f -- {q(upload)}; "
        f"rm -rf -- {q(release_dir)} 2>/dev/null || {_root_rm(releases, q(posixpath.basename(release_dir)))}"
    )


def remove_dir_command(instance: Instance) -> str:
    return _remove_base_command(paths_for(instance))


def _claim_dir_inside(instance: Instance, directory: str) -> bool:
    """The claimed compose project's own directory is ``directory`` or below it (never delete it)."""
    working_dir = (instance.claim or {}).get("working_dir") or ""
    norm = posixpath.normpath(working_dir) if working_dir else ""
    return bool(norm) and (norm == directory or norm.startswith(directory + "/") or directory.startswith(norm + "/"))


KEPT_MARK = "slipway-env-kept"  # a line of its own: error messages naming the .slipway-kept folder never equal it
BACKUPS_KEPT_MARK = "slipway-backups-kept"  # "<mark> <number of dumps> <folder>"
BACKUPS_FAILED_MARK = "slipway-backups-failed"
DUMPS_MARK = "slipway-dump:"


def kept_backups_path(paths: InstancePaths, instance: Instance) -> str:
    """Where deleting an app instance moves its ``backups/`` folder (a UTC time is added when it is taken)."""
    return f"{paths.root}/.slipway-kept/{paths.slug}-{instance.id.hex[:8]}.backups"


def _dumps_listing(backups: str) -> str:
    """Names of the ``*.dump`` files in ``backups`` (no glob: zsh fails an unmatched one)."""
    return f"ls -A {q(backups)} 2>/dev/null | grep '\\.dump$'"


def keep_env_command(instance: Instance) -> str:
    """App mode, after teardown: keep what the app's data needs outside the folder (§4.6).

    When the app's projects still have volumes, or ``backups/`` holds a dump, ``shared/.env`` is copied out
    (mode 600; prints ``KEPT_MARK``) and ``backups/`` is moved to ``.slipway-kept`` (prints ``BACKUPS_KEPT_MARK
    <dumps> <folder>``). A failed copy of the .env exits 1; a failed move of the backups exits 2 (the folder,
    with both, then stays where it is)."""
    paths = paths_for(instance)
    dest = kept_env_path(paths, instance)
    vols = "; ".join(f"docker volume ls -q --filter {_project_filter(p)}" for p in app_known_projects(instance)) or "true"
    b, kept = q(paths.backups), q(kept_backups_path(paths, instance))
    return (
        f"v=$({{ {vols}; }} 2>/dev/null); d=$({_dumps_listing(paths.backups)}); "
        f"[ -n \"$v\" ] || [ -n \"$d\" ] || exit 0; "
        f"umask 077 && mkdir -p {q(posixpath.dirname(dest))} || exit 1; "
        f"if [ -f {q(paths.env_file)} ]; then cp -f {q(paths.env_file)} {q(dest)} && echo {q(KEPT_MARK)} || exit 1; fi; "
        f"if [ -d {b} ] && [ ! -L {b} ]; then rm -rf -- {q(paths.incoming)}; "
        f"if [ -n \"$(ls -A {b} 2>/dev/null)\" ]; then k={kept}; "
        f"[ -e \"$k\" ] && k=\"$k-$(date -u +%Y%m%dT%H%M%SZ)\"; "
        f"mv -- {b} \"$k\" 2>&1 || {{ echo {q(BACKUPS_FAILED_MARK)}; exit 2; }}; "
        f"n=$(ls -A \"$k\" | grep -c '\\.dump$'); echo \"{BACKUPS_KEPT_MARK} $n $k\"; fi; fi; true"
    )


async def _write_identity_files(remote: ssh.RemoteSession, instance: Instance, paths: InstancePaths,
                                names: list[str], report: dict[str, Any] | None) -> None:
    """Next to each kept dump, ``<name>.identity.env`` (0600): the identity values its data was made with,
    which only Slipway's database held (data-loss 16). The rows go with the instance."""
    async with session_scope() as db:
        rows = (await db.scalars(select(Backup).where(Backup.instance_id == instance.id,
                                                      Backup.status == BackupStatus.READY))).all()
    listed = set(names)
    kept = []
    for row in rows:
        if not data.NAME_RE.match(row.name or "") or row.name not in listed:
            continue
        kept.append({"name": row.name, "db_sha256": row.db_sha256})
        if row.identity:
            text = "".join(f"{k}={v}\n" for k, v in sorted(row.identity.items()) if "\n" not in str(v))
            await remote.write_text(f"{paths.backups}/{row.name}.identity.env", text)
    if report is not None:
        report["backups"] = kept


async def keep_identity_files(instance: Instance, *, connect: ConnectFactory = ssh.open_session) -> str | None:
    """Removing an instance from Slipway only (purge=false): its dumps stay on the host, and the rows that hold
    their identity values go. When a ready backup was taken with other identity values than the data's
    (``live_identity``, which ``shared/.env`` keeps), the ``<name>.identity.env`` files are written next to the
    dumps, as Destroy does (D18); nothing else on the host changes. A warning when that couldn't be done."""
    if instance.build_source != BuildSource.APP:
        return None
    async with session_scope() as db:
        rows = (await db.scalars(select(Backup).where(Backup.instance_id == instance.id,
                                                      Backup.status == BackupStatus.READY))).all()
    live = instance.live_identity or {}
    others = sorted(r.name for r in rows if data.NAME_RE.match(r.name or "") and r.identity
                    and any(live.get(k) != v for k, v in r.identity.items()))
    if not others:
        return None
    paths = paths_for(instance)
    host = instance.host.name
    try:
        async with connect(ssh.SSHTarget.from_host(instance.host)) as remote:
            _, listing = await remote.run(_dumps_listing(paths.backups), check=False, timeout=60)
            dumps = [ln.strip()[:-5] for ln in listing.splitlines() if data.FILE_RE.match(ln.strip())]
            if dumps:
                await _write_identity_files(remote, instance, paths, dumps, None)
    except Exception as exc:  # never block removing the instance on it: say what is lost
        return (f"The {data.identity_label(instance)} of backup{'s' if len(others) != 1 else ''} {', '.join(others)} "
                f"could not be written next to {'them' if len(others) != 1 else 'it'} on {host} "
                f"({clean_text(str(exc))[:200]}); Slipway no longer has a copy")
    return None


async def destroy(instance: Instance, *, connect: ConnectFactory = ssh.open_session,
                  report: dict[str, Any] | None = None) -> str | None:
    """Remove the instance's containers, images and files from its host.

    Raises if containers are left behind. Returns a warning naming what is left when only
    files could not be removed, or, for an app whose volumes or backups stay, where its ``.env`` and its
    backups were kept. ``report`` (optional) receives ``backups``: the names and SHA-256s of the backups kept
    (for the audit record), and ``kept_backups``: their folder.
    """
    paths = paths_for(instance)
    host = instance.host.name
    kept: str | None = None  # where the app's .env was copied
    kept_backups: tuple[int, str] | None = None  # (dumps, folder) the app's backups were moved to
    async with connect(ssh.SSHTarget.from_host(instance.host)) as remote:
        # Teardown and the leftovers check come first: nothing has been moved when containers stay (data-loss 2).
        await remote.run(teardown_command(instance), timeout=600)
        _, left = await remote.run(leftovers_command(instance), timeout=60)
        if _container_ids(left):
            raise DeployError(f"Containers of {instance.name} are still on {host}; nothing was deleted")
        if instance.build_source == BuildSource.APP:
            _, listing = await remote.run(_dumps_listing(paths.backups), check=False, timeout=60)
            dumps = [ln.strip()[:-5] for ln in listing.splitlines() if data.FILE_RE.match(ln.strip())]
            if dumps:
                await _write_identity_files(remote, instance, paths, dumps, report)
            if dumps or app_known_projects(instance):
                # The volumes stay (Slipway never removes data); their secrets are only in the .env and this row.
                status, output = await remote.run(keep_env_command(instance), check=False, timeout=600)
                lines = [ln.strip() for ln in output.splitlines()]
                if any(ln == KEPT_MARK for ln in lines):
                    kept = kept_env_path(paths, instance)
                for ln in lines:
                    words = ln.split(" ", 2)
                    if len(words) == 3 and words[0] == BACKUPS_KEPT_MARK and words[1].isdigit():
                        kept_backups = (int(words[1]), words[2])
                if status == 2:
                    detail = next((clean_text(ln)[:200] for ln in lines if ln and ln != BACKUPS_FAILED_MARK
                                   and ln != KEPT_MARK), "")
                    if kept:
                        with contextlib.suppress(Exception):
                            await remote.run(f"rm -f -- {q(kept)}", check=False, timeout=60)
                    return (f"Kept {paths.base} on {host}: its backups could not be moved to {paths.root}/.slipway-kept"
                            + (f" ({detail})" if detail else ""))
                if status != 0:
                    return (f"Kept {paths.base} on {host}: the app's volumes stay, and its settings and secrets could "
                            f"not be copied to {posixpath.dirname(kept_env_path(paths, instance))}, so they stay in "
                            f"{paths.env_file}")
        if report is not None and kept_backups is not None:
            report["kept_backups"] = kept_backups[1]
        notes = []
        if kept_backups is not None:
            n = kept_backups[0]
            label = data.identity_label(instance)
            what = f"settings, secrets and {n}" if kept else str(n)
            volumes = f"the app's volumes on {host}, and " if app_known_projects(instance) else ""
            notes.append(f"Kept {volumes}its {what} backup{'s' if n != 1 else ''} (with their {label}) in "
                         f"{paths.root}/.slipway-kept/ (readable only by {instance.host.username})")
        elif kept:
            notes.append(f"Kept the app's volumes on {host}, and its settings and secrets in {kept} "
                         f"(readable only by {instance.host.username})")
        if _claim_dir_inside(instance, paths.base):
            return " ".join([*notes, f"Kept {paths.base} on {host}: the claimed project's own directory is inside it"])
        status, output = await remote.run(remove_dir_command(instance), check=False, timeout=600)
    if status == 0:
        return " ".join(notes) or None
    left = left_behind(output)
    if left is not None:
        notes.append(f"Kept {paths.base} on {host}: it also holds files Slipway did not put there ({left})")
        return " ".join(notes)
    detail = clean_text(output.strip().splitlines()[-1])[:200] if output.strip() else ""
    notes.append(f"Could not remove {paths.base} on {host}; delete it by hand" + (f" ({detail})" if detail else ""))
    return " ".join(notes)


# ------------------------------------------------------------ moving the deploy root
#
# A host's deploy root can change while instances are deployed on it. Slipway copies each
# instance's directory to the new root, points the symbolic links it made there (``current``
# and each release's ``.env``) at the copy, saves the new root, then removes the old directory
# unless a container still bind-mounts files from it. Containers keep running throughout:
# Compose finds them by project name, the environment was read when they were created, and
# named volumes are not touched.

MOVE_MARK = "slipway-move:"


def _inside(path: str, directory: str) -> bool:
    return path == directory or path.startswith(directory + "/")


Move = tuple[Instance, InstancePaths, InstancePaths]


def check_move(instances: list[Instance], old_root: str, new_root: str) -> None:
    """Raise DeployError when the instances' directories can't move from ``old_root`` to ``new_root``."""
    _check_moves([(inst, InstancePaths(old_root, inst.slug), InstancePaths(new_root, inst.slug)) for inst in instances],
                 new_root)


def _check_moves(moves: list[Move], target: str) -> None:
    for inst, old_paths, new_paths in moves:
        old, new = old_paths.base, new_paths.base
        if _inside(new, old) or _inside(old, new):
            raise DeployError(f"{target} overlaps {old}, which holds {inst.name}; choose a folder outside it")
        if _claim_dir_inside(inst, old) or _claim_dir_inside(inst, new):
            raise DeployError(
                f"The directory {inst.name} was claimed from overlaps {old} or {new}; choose another folder"
            )


def _moving(paths: InstancePaths) -> str:
    """Where an instance's directory is copied before it gets its final name."""
    return f"{paths.root}/.{paths.slug}.moving"


def move_prepare_command(new: list[InstancePaths], old: list[InstancePaths] | None = None) -> str:
    """Create the new folders' parents and check nothing is in the way; on failure prints a MOVE_MARK line.

    A new folder may already exist if it is empty (made in advance, say); it is removed so the copy
    can take its name. With ``old`` (the same order), a folder holding backups must fit where it goes:
    ``slipway-move: nospace <need KiB> <free KiB> <old folder>`` (§4.6).
    """
    parts = []
    for root in dict.fromkeys(p.root for p in new):
        r = q(root)
        parts.append(f"mkdir -p -- {r} 2>/dev/null; [ -d {r} ] && [ -w {r} ] || "
                     f"{{ echo {q(f'{MOVE_MARK} not-writable {root}')}; exit 1; }}")
    for p in new:
        base = q(p.base)
        parts.append(f"if [ -L {base} ] || {{ [ -e {base} ] && ! rmdir -- {base} 2>/dev/null; }}; "
                     f"then echo {q(f'{MOVE_MARK} exists {p.base}')}; exit 1; fi")
    for o, n in zip(old or [], new, strict=False):
        b = q(o.backups)
        parts.append(
            f"if [ -d {b} ]; then need=$(du -sk -- {q(o.base)} 2>/dev/null | awk '{{print $1}}'); "
            f"free=$(df -Pk -- {q(n.root)} | awk 'NR==2 {{print $4}}'); "
            f'if [ -n "$need" ] && [ -n "$free" ] && [ "$need" -gt "$free" ]; then '
            f'echo "{MOVE_MARK} nospace $need $free {o.base}"; exit 1; fi; fi'
        )
    return "; ".join(parts)


def move_copy_command(old: InstancePaths, new: InstancePaths) -> str:
    """Copy the instance's directory next to its new place and re-point the links into it.

    Prints ``slipway-move: absent`` when there is nothing to copy (Unraid, for one, clears /opt
    when it restarts). Files containers wrote as root are copied through a throwaway container.
    """
    name = posixpath.basename(_moving(new))
    in_docker = (
        f"docker run --rm --network none -v {q(old.root)}:/o:ro -v {q(new.root)}:/n {CLEANUP_IMAGE} "
        f"sh -c {q(f'rm -rf /n/{name} && cp -a /o/{old.slug} /n/{name}')}"
    )
    return (
        f"old={q(old.base)}; new={q(new.base)}; tmp={q(_moving(new))}; "
        f'if [ ! -e "$old" ]; then echo {q(MOVE_MARK + " absent")}; exit 0; fi; '
        f'rm -rf -- "$tmp" 2>/dev/null; '
        f'{{ {{ [ ! -e "$tmp" ] && cp -a -- "$old" "$tmp" 2>/dev/null; }} || {in_docker}; }} && '
        f'find "$tmp" -type l | {{ ok=0; while IFS= read -r l; do '
        f'lt=$(readlink "$l") || {{ ok=1; continue; }}; '
        f'case "$lt" in "$old"|"$old"/*) ln -sfn -- "$new${{lt#"$old"}}" "$l" || ok=1;; esac; '
        f"done; exit $ok; }}"
    )


def move_discard_command(new: InstancePaths) -> str:
    """Remove a copy (finished or not) made by a move that did not go through."""
    root, tmp = q(new.root), posixpath.basename(_moving(new))
    return (
        f"rm -rf -- {q(_moving(new))} {q(new.base)} 2>/dev/null || "
        f"{{ {_root_rm(root, q(tmp))}; {_root_rm(root, q(new.slug))}; }}"
    )


def bind_sources_command(instance: Instance) -> str:
    """Prints the host path of each bind mount of the instance's containers. Fails when docker can't list them."""
    fmt = '{{range .Mounts}}{{if eq .Type "bind"}}{{println .Source}}{{end}}{{end}}'
    lists = [
        f"docker ps -aq --filter {q('label=' + _label(instance))}",
        f"docker ps -aq --filter {q('label=com.docker.compose.project=' + instance.compose_project)}",
    ]
    if instance.claimed_container:
        lists.append(f"docker ps -aq --filter id={_claimed_id(instance)}")
    lists += [f"docker ps -aq --filter {_project_filter(p)}" for p in app_known_projects(instance)]
    return (
        f"ids=$({' && '.join(lists)}) && "
        f"{{ [ -z \"$ids\" ] || printf '%s\\n' \"$ids\" | sort -u | xargs docker container inspect -f {q(fmt)}; }}"
    )


LEFT_MARK = "slipway-left:"


def _remove_base_command(paths: InstancePaths, *, backups: bool = False) -> str:
    """Remove what Slipway put in the folder, then the folder if nothing else is in it.

    Files someone else put there stay: the command then prints ``LEFT_MARK`` and their names, and
    fails. Files containers wrote as root are removed through a throwaway container. ``backups/`` goes only
    when it is empty (destroy moved it away first), unless ``backups`` (a folder move copied it: §4.6).
    """
    base = q(paths.base)
    parts = [f"[ -e {base} ] || [ -L {base} ] || exit 0; cd {base} || exit 1"]
    for name in ("releases", "shared"):
        parts.append(f"{{ rm -rf -- {name} 2>/dev/null || {_root_rm(base, name)} >/dev/null 2>&1; }}")
    if backups:
        parts.append(f"{{ [ ! -e {data.BACKUPS_DIR} ] || rm -rf -- {data.BACKUPS_DIR}; }}")
    else:
        parts.append(f"{{ rmdir -- {data.BACKUPS_DIR}/{data.INCOMING_DIR} {data.BACKUPS_DIR} 2>/dev/null; true; }}")
    parts.append(f"rm -f -- current {MARKER_FILE} {data.LOCK_FILE}; cd / && rmdir -- {base} 2>/dev/null")
    parts.append(
        f"if [ -e {base} ]; then echo \"{LEFT_MARK} $(ls -A {base} | head -n 5 | tr '\\n' ' ')\"; exit 1; fi"
    )
    return "; ".join(parts)


def left_behind(output: str) -> str | None:
    """The names ``_remove_base_command`` reported as not Slipway's, or None."""
    return next((ln.split(LEFT_MARK, 1)[1].strip() for ln in output.splitlines() if LEFT_MARK in ln), None)


def _last_line(output: str) -> str:
    lines = [line for line in output.strip().splitlines() if line.strip()]
    return clean_text(lines[-1].strip())[:200] if lines else ""


async def move_deploy_root(
    host: Host,
    instances: list[Instance],
    new_root: str,
    *,
    save: Callable[[], Awaitable[None]],
    connect: ConnectFactory = ssh.open_session,
) -> list[str]:
    """Move the instances' directories from the host's deploy root to ``new_root``.

    ``save`` stores the new root; it runs once every copy is in place. If anything fails before
    that, the copies are removed again and nothing changed. Returns notes for the user: old
    directories that had to stay, or instances that had no files to move.
    """
    old_root, new_root = clean_deploy_root(host.deploy_root), clean_deploy_root(new_root)
    check_move(instances, old_root, new_root)
    moves = [(inst, InstancePaths(old_root, inst.slug), InstancePaths(new_root, inst.slug)) for inst in instances]
    return await _move_dirs(host, moves, new_root, save=save, connect=connect)


async def move_instance_dir(
    instance: Instance,
    new_dir: str,
    *,
    save: Callable[[], Awaitable[None]],
    connect: ConnectFactory = ssh.open_session,
) -> list[str]:
    """Move one instance's folder to ``new_dir`` (any folder of its own on the host), as ``move_deploy_root`` does."""
    try:
        new = InstancePaths.of(clean_instance_dir(new_dir))
    except ValueError as exc:
        raise DeployError(str(exc)) from exc
    moves: list[Move] = [(instance, paths_for(instance), new)]
    _check_moves(moves, new.base)
    return await _move_dirs(instance.host, moves, new.base, save=save, connect=connect)


async def _move_dirs(
    host: Host, moves: list[Move], target: str, *, save: Callable[[], Awaitable[None]], connect: ConnectFactory,
) -> list[str]:
    notes: list[str] = []
    async with connect(ssh.SSHTarget.from_host(host)) as remote:
        status, output = await remote.run(move_prepare_command([new for _, _, new in moves], [old for _, old, _ in moves]),
                                          check=False, timeout=600)
        if status:
            room = next((ln.split(" nospace ", 1)[1].split(" ", 2) for ln in output.splitlines()
                         if f"{MOVE_MARK} nospace " in ln), None)
            if room is not None and len(room) == 3 and room[0].isdigit() and room[1].isdigit():
                who = next((inst.name for inst, old, _ in moves if old.base == room[2]), "the instance")
                raise DeployError(
                    f"{target} on {host.name} has {data.human_bytes(int(room[1]) * 1024)} free; moving {who} needs "
                    f"{data.human_bytes(int(room[0]) * 1024)} (its backups included). Free some space or delete old "
                    "backups first.")
            if f"{MOVE_MARK} not-writable" in output:
                where = next((ln.split(" not-writable ", 1)[1].strip() for ln in output.splitlines()
                              if f"{MOVE_MARK} not-writable " in ln), target)
                raise DeployError(
                    f"Slipway can't create or write to {where} on {host.name} as {host.username}. On the host, run: "
                    f"sudo mkdir -p {q(where)} && sudo chown {q(host.username)} {q(where)}"
                )
            taken = next((line.split(" exists ", 1)[1] for line in output.splitlines() if f"{MOVE_MARK} exists " in line), "")
            raise DeployError(
                f"{taken or 'A folder Slipway needs'} already exists on {host.name}; remove it or choose another folder"
            )

        async def discard() -> None:
            for _, _, new in moves:
                try:
                    await remote.run(move_discard_command(new), check=False, timeout=600)
                except Exception as exc:  # best effort: the move already failed
                    log.warning("Could not remove %s after a failed move: %s", new.base, exc)

        copied: list[tuple[Instance, InstancePaths, InstancePaths]] = []
        try:
            for inst, old, new in moves:
                status, output = await remote.run(move_copy_command(old, new), check=False, timeout=3600)
                if status:
                    detail = _last_line(output)
                    raise DeployError(
                        f"Could not copy {old.base} to {new.base} on {host.name}"
                        + (f" ({detail})" if detail else "") + ". Nothing was changed."
                    )
                if f"{MOVE_MARK} absent" in output:
                    notes.append(f"{old.base} was not on {host.name}, so {inst.name} had no files to move; "
                                 "its next deployment creates them.")
                else:
                    copied.append((inst, old, new))
            if copied:
                command = " && ".join(f"mv -- {q(_moving(new))} {q(new.base)}" for _, _, new in copied)
                status, output = await remote.run(command, check=False, timeout=120)
                if status:
                    detail = _last_line(output)
                    raise DeployError(f"Could not move the copies into {target}" + (f" ({detail})" if detail else "")
                                      + ". Nothing was changed.")
            await save()
        except BaseException:
            await discard()
            raise

        # The new root is saved: from here on, failures only leave old files behind.
        for inst, old, _ in copied:
            try:
                status, output = await remote.run(bind_sources_command(inst), check=False, timeout=60)
                if status:
                    notes.append(f"Kept {old.base}: Docker could not say whether {inst.name}'s containers use it. "
                                 f"Delete it once {inst.name} is redeployed.")
                    continue
                if any(_inside(line.strip(), old.base) for line in output.splitlines() if line.strip()):
                    notes.append(f"Kept {old.base}: {inst.name}'s containers mount files from it. "
                                 f"Redeploy {inst.name}, then delete {old.base}.")
                    continue
                status, output = await remote.run(_remove_base_command(old, backups=True), check=False, timeout=600)
            except (ssh.SSHError, DeployError) as exc:
                notes.append(f"Could not remove {old.base} ({exc}); delete it by hand.")
                continue
            if status:
                left = left_behind(output)
                if left is not None:
                    notes.append(f"Kept {old.base}: it also holds files Slipway did not put there ({left}).")
                    continue
                detail = _last_line(output)
                notes.append(f"Could not remove {old.base}; delete it by hand" + (f" ({detail})." if detail else "."))
    return notes


# ------------------------------------------------------------------ source archive


def guarded_paths(instance: Instance) -> dict[str, tuple[bool, str]]:
    """Release paths the build resolves, mapped to (must be a directory, description).

    Docker and Compose follow symbolic links in these, so a link would make them build from
    (or write to) files outside the release. ``-f`` is resolved from the release root, as
    the build commands run there.
    """
    if instance.build_source == BuildSource.COMPOSE:
        settings = [("compose file", instance.compose_file, False)]
    elif instance.build_source == BuildSource.APP:
        settings = [("manifest", instance.manifest_file, False)]
    else:
        settings = [("build context", instance.build_context, True), ("Dockerfile", instance.dockerfile_path, False)]
    guarded: dict[str, tuple[bool, str]] = {}
    for name, value, is_dir in settings:
        norm = posixpath.normpath(value or ".")
        parts = [] if norm == "." else norm.split("/")
        for i in range(1, len(parts) + 1):
            path = "/".join(parts[:i])
            whole = i == len(parts)
            what = f"the {name} '{norm}'" if whole else f"'{path}' in the {name} path '{norm}'"
            must_be_dir = is_dir or not whole
            if path in guarded:
                must_be_dir = must_be_dir or guarded[path][0]
                what = guarded[path][1]
            guarded[path] = (must_be_dir, what)
    return guarded


def _extracted_name(name: str) -> str | None:
    """Where ``tar --strip-components=1`` puts relative member ``name`` in the release (None: nowhere)."""
    _, sep, rest = name.partition("/")
    rest = rest.lstrip("/")
    return posixpath.normpath(rest) if sep and rest else None


def check_source_archive(tarball: Path, guarded: dict[str, tuple[bool, str]]) -> None:
    """Raise DeployError if a guarded path in the archive is a link (or not a directory as needed).

    Runs on the Slipway server before the upload, naming members the way the host's tar extracts them.
    """
    try:
        with tarfile.open(tarball, "r:gz") as archive:
            while (member := archive.next()) is not None:
                archive.members.clear()  # only listing: keep no member list for repositories with many files
                # GitHub never writes these; tar implementations disagree on where they go.
                if member.name.startswith("/") or ".." in member.name.split("/"):
                    raise DeployError(f"The source archive contains the unsafe path {member.name!r}; refusing to deploy")
                path = _extracted_name(member.name)
                if path not in guarded:
                    continue
                must_be_dir, what = guarded[path]
                if member.issym():
                    kind = "a symbolic link"
                elif member.islnk():
                    kind = "a hard link"
                elif must_be_dir and not member.isdir():
                    kind = "not a directory"
                else:
                    continue
                raise DeployError(f"{what[0].upper()}{what[1:]} is {kind} in the repository; refusing to deploy")
    except (tarfile.TarError, OSError, EOFError, zlib.error) as exc:
        raise DeployError(f"The source archive could not be read: {exc}") from exc


# ------------------------------------------------------------------------- logging


class LogSink:
    """Buffers build output and appends it to ``deployments.log`` about once a second.

    Writes never raise: a failed write is kept and retried with the next flush. The stored
    log is capped: past ``LOG_HEAD_CHARS`` only the last ``LOG_TAIL_CHARS`` are kept, and
    ``close`` appends them.

    ``hide`` holds the secret values of the job (the app's secrets, the instance's variables, identity keys,
    the first admin's password): ``scrub`` replaces each with ``[hidden]``, and every line, step note and
    error is scrubbed before it is cut or stored (§12.2). A value printed split up or encoded differently
    is not caught.
    """

    def __init__(self, deployment_id: uuid.UUID, flush_interval: float = 1.0, *, hide: ssh.Redactor | None = None) -> None:
        self.deployment_id = deployment_id
        self.flush_interval = flush_interval
        self.hide = hide if hide is not None else ssh.Redactor()
        self._buf: list[str] = []
        self._size = 0  # characters stored or waiting in _buf
        self._new = 0  # lines since the last flush attempt
        self._tail: deque[str] = deque()
        self._tail_size = 0
        self._dropped = 0
        self._truncated = False
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    def scrub(self, text: str) -> str:
        return self.hide.scrub(text)

    async def line(self, text: str) -> None:
        entry = f"[{utcnow():%H:%M:%S}] {ssh.clip_line(self.scrub(clean_text(text)))}\n"
        if not self._truncated and self._size + len(entry) <= LOG_HEAD_CHARS:
            self._buf.append(entry)
            self._size += len(entry)
        else:
            if not self._truncated:
                self._truncated = True
                self._buf.append("[... output truncated; the end of the log is added when the deployment finishes ...]\n")
            self._keep_tail(entry)
        self._new += 1
        if time.monotonic() - self._last >= self.flush_interval or self._new >= 200:
            await self.flush()

    def _keep_tail(self, entry: str) -> None:
        self._tail.append(entry)
        self._tail_size += len(entry)
        while self._tail_size > LOG_TAIL_CHARS and len(self._tail) > 1:
            self._tail_size -= len(self._tail.popleft())
            self._dropped += 1

    async def close(self) -> None:
        """Add the kept end of a truncated log, then flush."""
        if self._tail:
            if self._dropped:
                self._buf.append(f"[... {self._dropped} line(s) omitted ...]\n")
            self._buf.extend(self._tail)
            self._tail.clear()
            self._tail_size = 0
        await self.flush()

    async def flush(self) -> None:
        async with self._lock:
            self._new = 0
            self._last = time.monotonic()
            if not self._buf:
                return
            count = len(self._buf)
            chunk = "".join(self._buf[:count])
            try:
                async with session_scope() as db:
                    await db.execute(
                        update(Deployment)
                        .where(Deployment.id == self.deployment_id)
                        .values(log=func.coalesce(Deployment.log, "") + chunk)
                    )
            except Exception as exc:
                log.warning("Could not save build log of deployment %s: %s", self.deployment_id, exc)
                return
            del self._buf[:count]


# ------------------------------------------------------------------------ pipeline


async def _finish(
    deployment_id: uuid.UUID,
    dep_status: DeploymentStatus,
    *,
    error: str | None = None,
    short: bool = False,
    scrub: Callable[[str], str] | None = None,
    owner_id: uuid.UUID | None = None,
    owner_fields: dict[str, Any] | None = None,
    **instance_fields: Any,
) -> None:
    """Record the outcome, retrying with backoff so a deployment never stays running.

    ``scrub`` hides the job's secrets in ``error`` before it is cut (a secret straddling the cut stays hidden).
    ``owner_fields`` go to the data owner ``owner_id`` in the same transaction: a job on an app slot of an
    environment writes the phase 2 data fields there (phase 3 §7.5). A job of a whole environment (no instance)
    records the deployment row alone.
    """
    if error is not None:
        error = clean_text(scrub(error) if scrub else error)[:2000]
    delays = FINISH_RETRY_DELAYS[:3] if short else FINISH_RETRY_DELAYS
    for attempt in range(len(delays) + 1):
        try:
            async with session_scope() as db:
                found = (await db.execute(select(Deployment.instance_id, Deployment.environment_id)
                                          .where(Deployment.id == deployment_id))).first()
                if found is None or (found[0] is None and found[1] is None):
                    return
                instance_id = found[0]
                await db.execute(
                    update(Deployment)
                    .where(Deployment.id == deployment_id)
                    .values(status=dep_status, error=error, finished_at=utcnow())
                )
                if instance_id is not None and instance_fields:
                    await db.execute(update(Instance).where(Instance.id == instance_id).values(**instance_fields))
                if owner_id is not None and owner_id != instance_id and owner_fields:
                    await db.execute(update(Instance).where(Instance.id == owner_id).values(**owner_fields))
            return
        except Exception as exc:
            if attempt == len(delays):
                log.error("Could not record the result of deployment %s: %s", deployment_id, exc)
                return
            log.warning("Recording the result of deployment %s failed, retrying: %s", deployment_id, exc)
            await asyncio.sleep(delays[attempt])


# ------------------------------------------------------------------------- steps

STEP_NAMES = {
    "resolve": "Resolve the commit",
    "source": "Download the source",
    "upload": "Upload the release",
    "release": "Check the live release",
    "manifest": "Read slipway.yml",
    "settings": "Write the settings",
    "ports": "Check host ports",
    "build": "Build",
    "check": "Check the backup",
    "backup": "Back up the data",
    "stop": "Stop the app",
    "reset": "Delete the data",
    "restore": "Restore the database",
    "files": "Restore the files",
    "after_import": "Prepare the imported data",
    "start": "Start",
    "finish": "Switch to the new release",
    "first_admin": "Create the first admin",
    "seed": "Add starter content",
    "export": "Export the data",
    "store": "Keep the snapshot on Slipway",
    "restart": "Start the app again",
    "restop": "Stop the data services again",
    "proxy": "Update Switchyard",
    # Phase 3 (§8.3): the steps of environment members' jobs.
    "smoke": "Check the slot",
    "traffic": "Update Switchyard",
    "dns": "Update DNS records",
    "stop_slots": "Stop Blue and Green",
    "start_slots": "Start the slots again",
}
STEP_STATES = ("pending", "running", "succeeded", "failed", "skipped", "warning")
# The header line each step starts with in the log; the deployment page splits the log on it.
STEP_MARK = "── Step "
# The steps of a deploy that run between build and start, in this order when listed (§7.3).
PRE_START_STEPS = ("check", "backup", "stop_slots", "stop", "reset", "restore", "files", "after_import")
# Between start and finish (phase 3 §8.4): a change step, so its failure fails the job before anything is live.
PRE_FINISH_STEPS = ("start_slots",)
# The steps that run after finish, inside the same SSH session; they never fail the job (D12). An environment
# member's job also checks its slot (smoke), publishes DNS records and updates Switchyard (traffic) there.
POST_FINISH_STEPS = ("first_admin", "seed", "smoke", "dns", "traffic")


def step_keys(instance: Instance) -> list[str]:
    """A deploy's steps. Dockerfile and compose instances keep exactly these (I7); see ``steps_for``."""
    if instance.build_source == BuildSource.APP:
        return ["resolve", "source", "upload", "manifest", "ports", "settings", "build", "backup", "start", "finish",
                "proxy"]
    return ["resolve", "source", "upload", "settings", "ports", "build", "start", "finish", "proxy"]


def steps_for(
    instance: Instance, kind: str = DeploymentKind.DEPLOY, *, snapshot: bool = False, first_admin: bool = False,
    seed: bool = False, files: bool = False, stop_app: bool = False, stopped: bool = False, start_over: bool = False,
    rollback_of: uuid.UUID | None = None, environment: Any = None, members: dict[str, Instance] | None = None,
) -> list[dict[str, Any]]:
    """The numbered steps of a job, with the names its kind gives them (§7.2, §7.3).

    ``environment`` and ``members``: the instance is a slot of that environment (phase 3 §8.4), whose lists
    ``_member_steps`` gives. Standalone instances keep exactly phase 2's lists (I1).

    The flags are the conditions known when the job is queued: ``snapshot`` the chain restores a snapshot,
    ``first_admin`` a first admin is pending, ``seed`` starter content may be added after an empty start (the
    deploy drops the step again when the release's slipway.yml has no seed command), ``files`` a restore
    puts the files back, ``stop_app`` a snapshot stops the running app, ``stopped`` the instance is stopped
    (data-only jobs stop its data services again at the end), ``start_over`` a reset of a never-live instance.
    """
    if instance.build_source != BuildSource.APP:
        return [{"key": k, "name": STEP_NAMES[k], "status": "pending"} for k in step_keys(instance)]
    if environment is not None and instance.environment_id is not None:
        return _member_steps(instance, environment, members or {}, kind, snapshot=snapshot, first_admin=first_admin,
                             seed=seed, files=files, stop_app=stop_app, stopped=stopped, start_over=start_over,
                             rollback_of=rollback_of)
    after = ["first_admin"] if first_admin else []
    if kind == DeploymentKind.DEPLOY:
        keys = ["resolve", "source", "upload", "manifest", "ports", "settings", "build",
                *(["check"] if snapshot else []), "backup",
                *(["stop", "restore", "files", "after_import"] if snapshot else []),
                "start", "finish", *after, *(["seed"] if seed else []), "proxy"]
    elif kind == DeploymentKind.RESTORE:
        keys = ["release", "manifest", "settings", "build", "check", "backup", "stop", "restore",
                *(["files"] if files else []), "start", "finish", *after, "proxy"]
    elif kind == DeploymentKind.ROLLBACK:
        keys = ["release", "manifest", "settings", "build", "check", "backup", "stop", "restore", "start", "finish",
                *after, "proxy"]
    elif kind == DeploymentKind.RESET and start_over:
        keys = ["release", "backup", "stop", "reset"]
    elif kind == DeploymentKind.RESET:
        keys = ["release", "manifest", "settings", "build", *(["check"] if snapshot else []), "backup", "stop", "reset",
                *(["restore", "files", "after_import"] if snapshot else []), "start", "finish", *after,
                *(["seed"] if seed else []), "proxy"]
    elif kind == DeploymentKind.BACKUP:
        keys = ["release", "backup", *(["restop"] if stopped else [])]
    elif kind == DeploymentKind.SNAPSHOT:
        keys = ["release", *(["stop"] if stop_app else []), "export", *(["restart"] if stop_app else []), "store",
                *(["restop"] if stopped else [])]
    elif kind == DeploymentKind.ADMIN:
        keys = ["release", "first_admin"]
    elif kind == DeploymentKind.CONTENT:
        keys = ["release", "seed"]
    else:
        raise ValueError(f"Unknown kind of job {kind!r}")
    names = dict(STEP_NAMES)
    if snapshot:
        names.update(check="Check the snapshot", restore="Restore the snapshot's database")
    if kind == DeploymentKind.ROLLBACK and rollback_of is not None:
        names["restore"] = f"Restore the backup from before deployment {rollback_of.hex[:8]}"
    if kind == DeploymentKind.SNAPSHOT:
        names["export"] = f"Export the data on {instance.host.name}"
    return [{"key": k, "name": names[k], "status": "pending"} for k in keys]


def _member_steps(
    instance: Instance, env: Any, members: dict[str, Instance], kind: str, *, snapshot: bool, first_admin: bool,
    seed: bool, files: bool, stop_app: bool, stopped: bool, start_over: bool, rollback_of: uuid.UUID | None,
) -> list[dict[str, Any]]:
    """An environment member's steps (phase 3 §8.4). Mode ``slot``: phase 2's lists, with ``smoke`` and
    ``traffic`` in place of ``proxy`` and no ``seed`` in a deploy (a new environment seeds at its first
    Activate, D24). Mode ``server``: the slot deploy, the data server deploy, and the data owner's jobs with
    ``stop_slots`` and ``start_slots`` around the data steps."""
    slot = str(instance.slot or "")
    server = env.data_mode == DataMode.SERVER
    apps = environments.app_members(members)
    active = environments.active_member(env, members)
    after = ["first_admin"] if first_admin else []
    snap_check = ["check"] if snapshot else []
    snap_restore = ["stop", "restore", "files", "after_import"] if snapshot else []
    dns = ["dns"] if (env.traffic or {}).get("dns") else []
    names = dict(STEP_NAMES)
    owner = environments.owner_in(env, members)
    lead = environments.lead_slot(env, members)
    names["stop_slots"] = "Stop Blue and Green" if len(apps) > 1 else f"Stop {(apps[0].slot if apps else 'blue').capitalize()}"
    names["start_slots"] = f"Start {(lead.slot if lead is not None else 'the slots').capitalize()} again" \
        if lead is not None else "Start the slots again"
    if kind == DeploymentKind.DEPLOY and slot == environments.DATA_SLOT:
        keys = ["resolve", "source", "upload", "manifest", "ports", "settings", "build", *snap_check, "backup",
                *snap_restore, "start", "finish", *dns, "traffic", *(["smoke"] if active is not None else [])]
        if active is not None:
            names["smoke"] = f"Check {active.slot} on {active.host.name}"
    elif kind == DeploymentKind.DEPLOY:
        keys = ["resolve", "source", "upload", "manifest", "ports", "settings", "build",
                *([] if server else snap_check), "backup", *([] if server else snap_restore),
                "start", "finish", *after, "smoke", "traffic"]
        names["smoke"] = f"Check {slot} on {instance.host.name}"
        if server and owner is not None:
            names["backup"] = f"Back up the data on {owner.host.name}"
    elif not server:
        rows = steps_for(instance, kind, snapshot=snapshot, first_admin=first_admin, seed=seed, files=files,
                         stop_app=stop_app, stopped=stopped, start_over=start_over, rollback_of=rollback_of)
        return [{**r, "key": "traffic"} if r["key"] == "proxy" else r for r in rows]
    elif kind == DeploymentKind.RESTORE:
        keys = ["release", "manifest", "settings", "build", "check", "backup", "stop_slots", "stop", "restore",
                *(["files"] if files else []), "start", "start_slots", "finish", *after, "traffic"]
    elif kind == DeploymentKind.ROLLBACK:
        keys = ["release", "manifest", "settings", "build", "check", "backup", "stop_slots", "stop", "restore", "start",
                "start_slots", "finish", "traffic"]
    elif kind == DeploymentKind.RESET and start_over:
        keys = ["release", "backup", "stop_slots", "stop", "reset"]
    elif kind == DeploymentKind.RESET:
        keys = ["release", "manifest", "settings", "build", *snap_check, "backup", "stop_slots", "stop", "reset",
                *(["restore", "files", "after_import"] if snapshot else []), "start", "start_slots", "finish", *after,
                *(["seed"] if seed else []), "traffic"]
    elif kind == DeploymentKind.SNAPSHOT:
        keys = ["release", *(["stop_slots"] if stop_app else []), "export", *(["start_slots"] if stop_app else []),
                "store", *(["restop"] if stopped else [])]
        if stop_app:
            names["start_slots"] = "Start Blue and Green again" if len(apps) > 1 else names["start_slots"]
        names["export"] = f"Export the data on {instance.host.name}"
    else:
        return steps_for(instance, kind, snapshot=snapshot, first_admin=first_admin, seed=seed, files=files,
                         stop_app=stop_app, stopped=stopped, start_over=start_over, rollback_of=rollback_of)
    if snapshot:
        names.update(check="Check the snapshot", restore="Restore the snapshot's database")
    if kind == DeploymentKind.ROLLBACK and rollback_of is not None:
        names["restore"] = f"Restore the backup from before deployment {rollback_of.hex[:8]}"
    return [{"key": k, "name": names[k], "status": "pending"} for k in keys]


def new_steps(instance: Instance) -> list[dict[str, Any]]:
    """A deploy's steps as queued (the job settles the conditional ones when it starts)."""
    return steps_for(instance)


# Options a retry never copies: each needs its own typed confirmation, ``prev_status`` is what the instance
# is when the retry starts (a half-restored app must not go back to "running"), and ``restop`` is whether the app
# is stopped when the retry starts (an app started since must not be stopped by a Back up or a snapshot).
ONE_SHOT_OPTIONS = frozenset({"skip_backup", "take_over_lock", "override_hold", "skip_revision_check", "inherit",
                              "confirm", "prev_status", "restop"})


async def retry_values(db: Any, parent: Deployment) -> dict[str, Any]:
    """The fields ``queue_deployment(retry_of=parent)`` gives the retry (§8.1): the kind, the options (without
    the one-shot ones), what it restores, and the commit of a job that runs the live release. The first
    attempt's pre-change backup is inherited (``backup_id`` and ``options.inherit``) only when the parent is
    the latest data-changing job and began a change step (D11); otherwise the retry backs up afresh."""
    inheritance = await data.retry_inheritance(db, parent)
    options = {k: v for k, v in (parent.options or {}).items() if k not in ONE_SHOT_OPTIONS}
    values: dict[str, Any] = {"kind": parent.kind or DeploymentKind.DEPLOY, "branch": parent.branch,
                              "restore_backup_id": parent.restore_backup_id, "snapshot_id": parent.snapshot_id,
                              "previous_sha": parent.previous_sha}
    if parent.kind not in (None, DeploymentKind.DEPLOY):
        values.update(commit_sha=parent.commit_sha, commit_message=parent.commit_message,
                      commit_author=parent.commit_author)
    if inheritance.inherit and inheritance.backup_id is not None:
        options["inherit"] = True
        values["backup_id"] = inheritance.backup_id
    if parent.kind in data.DATA_ONLY_KINDS:
        instance = await db.get(Instance, parent.instance_id)
        options["restop"] = instance is not None and instance.status == InstanceStatus.STOPPED
    values["options"] = options
    return values


class Steps:
    """The deployment's numbered steps: their state is saved on the deployment, and each starts a log section.

    Saving never raises (a failed save is retried with the next change).
    """

    def __init__(self, deployment_id: uuid.UUID, rows: list[dict[str, Any]], sink: LogSink) -> None:
        self.deployment_id = deployment_id
        self.rows = [dict(r) for r in rows]
        self.sink = sink
        self._current: dict[str, Any] | None = None

    def _row(self, key: str) -> tuple[int, dict[str, Any]]:
        for i, row in enumerate(self.rows):
            if row["key"] == key:
                return i, row
        row = {"key": key, "name": STEP_NAMES.get(key, key), "status": "pending"}
        self.rows.append(row)
        return len(self.rows) - 1, row

    def status(self, key: str) -> str | None:
        return next((r["status"] for r in self.rows if r["key"] == key), None)

    async def _save(self) -> None:
        try:
            async with session_scope() as db:
                await db.execute(update(Deployment).where(Deployment.id == self.deployment_id)
                                 .values(steps=[dict(r) for r in self.rows]))
        except Exception as exc:
            log.warning("Could not save the steps of deployment %s: %s", self.deployment_id, exc)

    async def begin(self, key: str) -> None:
        i, row = self._row(key)
        row.update(status="running", started_at=utcnow().isoformat())
        row.pop("note", None)
        self._current = row
        await self.sink.line(f"{STEP_MARK}{i + 1}/{len(self.rows)}: {row['name']}")
        await self._save()

    async def end(self, status: str, *, note: str | None = None) -> None:
        row = self._current
        if row is None:
            return
        row.update(status=status, finished_at=utcnow().isoformat())
        if note:
            row["note"] = clean_text(self.sink.scrub(note))[:300]
        self._current = None
        await self._save()

    def listed(self, key: str) -> bool:
        return any(r["key"] == key for r in self.rows)

    async def drop(self, key: str) -> None:
        """Take a step that hasn't begun off the list (one listed in case the release would need it)."""
        if self.status(key) == "pending":
            self.rows = [r for r in self.rows if r["key"] != key]
            await self._save()

    async def skip(self, key: str, note: str, *, listed_only: bool = False) -> None:
        """Mark ``key`` skipped. ``listed_only``: do nothing when the job's list has no such step."""
        if listed_only and not self.listed(key):
            return
        i, row = self._row(key)
        row.update(status="skipped", note=clean_text(self.sink.scrub(note))[:300])
        await self.sink.line(f"{STEP_MARK}{i + 1}/{len(self.rows)}: {row['name']}: skipped. {note}")
        await self._save()

    @asynccontextmanager
    async def step(self, key: str) -> AsyncIterator[None]:
        await self.begin(key)
        try:
            yield
        except BaseException as exc:
            await self.end("failed", note=str(exc) or type(exc).__name__)
            raise
        await self.end("succeeded")

    async def close(self) -> None:
        """At the end: a step still running failed (it was interrupted)."""
        if self._current is not None:
            await self.end("failed", note="Interrupted")
        await self._save()


# A release folder's name: <sha12>-<deployment id8> (see InstancePaths.release).
_RELEASE_NAME = re.compile(r"[0-9a-f]{12}-[0-9a-f]{8}")


@dataclass
class _Retry:
    id: uuid.UUID  # the deployment being retried
    sha: str
    release: str | None
    reusable: bool  # its release and build can be used again


@dataclass
class _Job:
    instance: Instance
    branch: str
    user: User | None
    env: dict[str, str] | None  # None when the stored values cannot be decrypted
    secrets: dict[str, str] | None  # the app's generated secrets; None when they cannot be decrypted
    steps: list[dict[str, Any]]
    retry: _Retry | None = None
    deployment_id: uuid.UUID = uuid.UUID(int=0)
    kind: str = DeploymentKind.DEPLOY
    options: dict[str, Any] = field(default_factory=dict)
    hide: ssh.Redactor = field(default_factory=ssh.Redactor)  # the job's secret values, hidden in its log
    never_live: bool = False  # the instance had never gone live when the job started
    inherited_backup_id: uuid.UUID | None = None  # a retry keeps the first attempt's pre-change backup (§8.1)
    pre_retry: bool = False  # ... and backs up again: the app was started by hand since that attempt
    parent_finished_at: Any = None  # when the attempt being retried ended
    # Filled in while the job runs.
    lock_held: bool = False  # this job wrote its line to the host lock
    lock_left: str | None = None  # a command that may still run on the host (timed out, cancelled): keep the lock
    lock_pid: str | None = None  # that command's PID, read back from the lock line it wrote
    lock_cut: bool = False  # lock_left is only the job's kind: it was cut off between commands, so no PID to read
    # The commit whose release `finish` made live (current switched, app_state saved): from then on the job has
    # gone live, and nothing after it (pruning, first_admin, seed, proxy, a cut-off) can make it fail (D12).
    went_live: str | None = None
    data_app: bool = False  # the live or the new slipway.yml declares data
    # commands.has_data said the data lives outside the host (exit 4); None when this job didn't probe (a skipped
    # or inherited backup), and the live release's record then stands.
    data_elsewhere: bool | None = None
    identity: dict[str, str] | None = None  # the identity values the release went live with (live_identity)
    ctx: Any = None  # the app run (_AppRun), for the steps after finish
    # Restore, roll back and reset (D2): the live release runs again, with the inputs it went live with.
    live_inputs: dict[str, Any] | None = None  # app_state.live
    start_over: bool = False  # a reset of a never-live instance (§7.5 reset, Start over)
    # An app slot deploy in mode server while no app has run on the shared data (jobs.identity_replaceable, read
    # when the job starts): its identity values become the data's at finish.
    replace_identity: bool = False
    prev_status: str | None = None  # put back when a restore-type job changed nothing (§7.1)
    snapshot_id: uuid.UUID | None = None  # the chain restores (or the job takes) this snapshot
    restore_backup_id: uuid.UUID | None = None  # what a restore or roll back puts back
    done_by: dict[str, str] = field(default_factory=dict)  # step -> the attempt that already did it (§8.1)
    override: dict[str, str] = field(default_factory=dict)  # identity values the restore puts back (§9.3)
    restore_from: dict[str, Any] = field(default_factory=dict)  # {database, files, name, source}: what restore reads
    exported: dict[str, Any] = field(default_factory=dict)  # the snapshot kind's export, for store
    # Phase 3: a slot of an environment. Its settings, services, variables and secrets are the environment's
    # (§6); the phase 2 data fields are the data owner's (D3), which is the instance itself outside environments.
    environment: Any = None  # the Environment row, as the job started
    owner: Instance | None = None  # the data owner
    members: dict[str, Instance] = field(default_factory=dict)  # the environment's instances by slot
    role: str = "app"  # how slipway.yml is planned for this instance: app, slot or server (§5.3)
    settings: dict[str, str] | None = None  # the environment's settings (None: the instance's own)
    services: list[str] | None = None  # ... and its optional services
    secrets_version: int = 0  # environments.secrets_version when the secrets were read (§6 compare-and-set)
    connect: Any = None  # the job's SSH session factory, for the other members' hosts (§7.1 Members)
    data_values: dict[str, dict[str, str]] | None = None  # what an app slot attaches to (§6), once worked out
    revision_before: str | None = None  # the data's revision the pre-deploy backup read (§8.4 smoke)
    lead_side: Any = None  # the lead slot's live render after start_slots (first_admin and seed run there)

    @property
    def member(self) -> bool:
        return self.environment is not None

    @property
    def data_owner(self) -> Instance:
        return self.owner if self.owner is not None else self.instance


async def _start(deployment_id: uuid.UUID) -> _Job | None:
    async with session_scope() as db:
        dep = await db.get(Deployment, deployment_id)
        if dep is None or dep.status != DeploymentStatus.QUEUED:
            return None
        instance = dep.instance
        environment = await db.get(Environment, instance.environment_id) if instance.environment_id else None
        if environment is not None:
            # A slot of an environment: the environment's variables and secrets (phase 3 §6, D5).
            env = environment.env
            if env is None:
                stored = await db.scalar(select(Environment.env.is_not(None)).where(Environment.id == environment.id))
                env = None if stored else {}
            secrets = environment.app_secrets
            if secrets is None:
                stored = await db.scalar(select(Environment.app_secrets.is_not(None))
                                         .where(Environment.id == environment.id))
                secrets = None if stored else {}
        else:
            env = instance.env
            if env is None:
                stored = await db.scalar(select(Instance.env.is_not(None)).where(Instance.id == instance.id))
                env = None if stored else {}
            secrets = instance.app_secrets
            if secrets is None:
                stored = await db.scalar(select(Instance.app_secrets.is_not(None)).where(Instance.id == instance.id))
                secrets = None if stored else {}
        retry = None
        first = None
        if dep.retry_of_id is not None:
            first = await db.get(Deployment, dep.retry_of_id)
            if first is not None and first.commit_sha:
                built = any(r.get("key") == "build" and r.get("status") in ("succeeded", "skipped") for r in first.steps or [])
                named = bool(first.release) and _RELEASE_NAME.fullmatch(posixpath.basename(first.release)) is not None
                retry = _Retry(id=first.id, sha=first.commit_sha, release=first.release,
                               reusable=built and named and first.instance_id == instance.id)
        kind = dep.kind or DeploymentKind.DEPLOY
        options = dict(dep.options or {})
        never_live = instance.current_commit_sha is None
        job = _Job(instance=instance, branch=dep.branch, user=dep.triggered_by, env=env, secrets=secrets, steps=[],
                   retry=retry, deployment_id=dep.id, kind=kind, options=options, never_live=never_live)
        members: dict[str, Instance] = {}
        if environment is not None:
            members = await environments.members(db, environment)
            job.environment, job.members = environment, members
            job.owner = environments.owner_in(environment, members) or instance
            job.settings = {str(k): str(v) for k, v in (environment.app_settings or {}).items()}
            job.services = list(environment.app_services) if environment.app_services is not None else None
            job.secrets_version = int(environment.secrets_version or 0)
            if instance.slot == environments.DATA_SLOT:
                job.role = "server"
            elif environment.data_mode == DataMode.SERVER:
                job.role = "slot"
            # The environment's fences again, as they stand now and before anything changes (I2): two requests can
            # both pass queue_job's checks before either commits, e.g. an activate of green and a deploy to green.
            from slipway.services import jobs  # jobs imports the deployer

            refused = await jobs.environment_fence(db, environment, members, instance=instance, kind=kind,
                                                   options=options, retry_of=first)
            problem = refused.text if refused is not None else None
            if problem is None and kind == DeploymentKind.DEPLOY and instance.slot in environments.APP_SLOTS:
                job.replace_identity = job.owner is not None and job.owner.id != instance.id \
                    and jobs.identity_replaceable(job.owner, members)
                problem = jobs.identity_problem(environment, job.owner, instance, members)
            if problem:
                raise DeployError(problem)
        owner = job.data_owner
        data_only = kind in data.DATA_ONLY_KINDS
        if instance.build_source == BuildSource.APP:
            job.start_over = kind == DeploymentKind.RESET and bool(options.get("start_over"))
            if kind in data.RESTORE_KINDS:
                # What the instance was before the job, so a job that changed nothing leaves it so (§7.1).
                if not options.get("prev_status"):
                    options["prev_status"] = instance.status if instance.status != InstanceStatus.DEPLOYING \
                        else InstanceStatus.FAILED
                job.prev_status = str(options["prev_status"])
                job.data_app = True
            # A first deploy of an instance created from a snapshot restores it (§10.7).
            if (kind == DeploymentKind.DEPLOY and never_live and dep.snapshot_id is None and dep.retry_of_id is None
                    and instance.seed_snapshot_id is not None and owner is instance):
                dep.snapshot_id = instance.seed_snapshot_id
            job.snapshot_id, job.restore_backup_id = dep.snapshot_id, dep.restore_backup_id
            if kind == DeploymentKind.SNAPSHOT and dep.snapshot_id is not None and dep.retry_of_id is not None:
                snap = await db.get(Snapshot, dep.snapshot_id)
                if snap is not None and snap.status == SnapshotStatus.FAILED:
                    snap.status, snap.error = SnapshotStatus.PENDING, None  # taken again (§8.1)
            # Inherit the first attempt's backup only when queue_deployment said so (§8.1, D11).
            if options.get("inherit") and dep.backup_id is not None:
                job.inherited_backup_id = dep.backup_id
                job.parent_finished_at = first.finished_at if first is not None else None
                job.pre_retry = bool(owner.last_control_at and job.parent_finished_at
                                     and owner.last_control_at > job.parent_finished_at)
            if first is not None and first.instance_id == instance.id and first.kind == kind:
                # Only while the attempt being retried is still the latest changing job: a later one (Start over,
                # another restore) may have undone what it did (§8.1).
                job.done_by = (await data.retry_inheritance(db, first, exclude=dep.id)).done_by
                changed = await data.seed_change_text(db, instance, first) if kind == DeploymentKind.DEPLOY else None
                if changed:
                    raise DeployError(changed)  # the seed changed after the retry was queued (§10.7)
                if (dep.snapshot_id is None and data._restores_snapshot(first)
                        and data.snapshot_steps_left(first, job.done_by)):
                    raise DeployError("The snapshot this job restores was deleted; start a new reset instead")
            if kind in data.RESTORE_KINDS and not job.start_over:
                live = data.live_state(instance)
                if live is not None and _RELEASE_NAME.fullmatch(str(live.get("release") or "")) \
                        and _SHA_RE.match(str(live.get("sha") or "")):
                    # The live release is reused as it is on the host: no GitHub, no upload (D2).
                    job.live_inputs = live
                    job.retry = _Retry(id=uuid.UUID(str(live["deployment"])), sha=str(live["sha"]),
                                       release=f"{paths_for(instance).releases}/{live['release']}", reusable=True)
                    if not dep.commit_sha:
                        source = await db.get(Deployment, job.retry.id)
                        dep.commit_sha = str(live["sha"])
                        if source is not None:
                            dep.commit_message, dep.commit_author = source.commit_message, source.commit_author
            # The first admin and starter content are the data owner's (phase 3 D3).
            pending_admin = await db.scalar(select(FirstAdmin.id).where(
                FirstAdmin.instance_id == owner.id, FirstAdmin.status == FirstAdminStatus.PENDING))
            snapshot = dep.snapshot_id is not None
            seed = (not snapshot and instance.seed_content
                    and (bool(options.get("started_empty"))
                         or (never_live and instance.fresh_data in (None, FreshData.EMPTY))))
            if environment is not None and pending_admin is not None and kind == DeploymentKind.DEPLOY:
                if instance.slot == environments.DATA_SLOT:
                    pending_admin = None  # the data server runs no app: the first app slot deploy creates it
                elif owner is not instance:
                    # Only the first app slot deploy that starts on the empty data (§8.4 ᵃ).
                    first_slot = not any(m.current_commit_sha for m in environments.app_members(members))
                    if not (first_slot and owner.fresh_data in (None, FreshData.EMPTY)):
                        pending_admin = None
            # Worked out again here, not taken from the queued options: the app may have been started since (D17).
            stopped = instance.status == InstanceStatus.STOPPED
            if data_only:
                options["restop"] = stopped
            dep.steps = steps_for(instance, kind, snapshot=snapshot and kind != DeploymentKind.SNAPSHOT,
                                  first_admin=pending_admin is not None,
                                  seed=bool(seed) if kind == DeploymentKind.DEPLOY else bool(options.get("seed")),
                                  files=bool(options.get("files")), rollback_of=_as_uuid(options.get("rollback_of")),
                                  start_over=job.start_over,
                                  stop_app=bool(options.get("stop_app")) and (
                                      instance.status == InstanceStatus.RUNNING
                                      or (environment is not None and environment.data_mode == DataMode.SERVER)),
                                  stopped=stopped and data_only, environment=environment, members=members)
            dep.options = dict(options)
            _hide_instance_values(job.hide, owner, env, secrets)
        else:
            dep.steps = new_steps(instance)
        job.steps = dep.steps
        dep.status = DeploymentStatus.RUNNING
        dep.started_at = utcnow()
        if not (data_only and instance.build_source == BuildSource.APP):
            instance.status = InstanceStatus.DEPLOYING  # data-only jobs never change the status (§7.1)
        return job


def _as_uuid(value: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value)) if value else None
    except ValueError:
        return None


def _env_unreadable(job: _Job) -> str:
    """The refusal of a job whose variables can't be decrypted: on the instance, or on a member's environment."""
    return ENV_UNREADABLE_MEMBER.format(env=job.environment.name) if job.member else ENV_UNREADABLE


def _hide_instance_values(hide: ssh.Redactor, instance: Instance, env: dict[str, str] | None,
                          secrets: dict[str, str] | None) -> None:
    """App mode: every value that may be secret is hidden in the job's log (§12.2): the app's secrets, the
    instance's variables (any of them may be a password, manifest.plan treats them so) and the identity values
    the data was made with. Values shorter than six characters stay (they would blank out ordinary words)."""
    for value in (secrets or {}).values():
        hide.add(str(value))
    for value in (env or {}).values():
        hide.add(str(value))
    for value in (instance.live_identity or {}).values():
        hide.add(str(value))


async def _check_repository(gh: GitHubClient, repo: Repository, sink: LogSink) -> None:
    """Make sure the repository still has the GitHub id Slipway knows; follow renames and transfers."""
    try:
        data = await gh.get_repository(repo.github_id)
    except GitHubError as exc:
        if exc.status_code == 404:
            data = None
        else:
            raise
    if not data:
        raise DeployError(f"GitHub repository {repo.full_name} (id {repo.github_id}) was not found or is not accessible")
    if data.get("id") != repo.github_id:
        raise DeployError(f"GitHub returned a different repository for {repo.full_name}; refusing to deploy")
    current = {
        "full_name": data.get("full_name"),
        "owner": (data.get("owner") or {}).get("login"),
        "name": data.get("name"),
        "html_url": data.get("html_url"),
    }
    changed = {
        k: _fit(Repository, k, v) for k, v in current.items() if isinstance(v, str) and v and v != getattr(repo, k)
    }
    if not changed:
        return
    async with session_scope() as db:
        await db.execute(update(Repository).where(Repository.id == repo.id).values(**changed))
    if "full_name" in changed:
        await sink.line(f"Repository is now {changed['full_name']} on GitHub (was {repo.full_name})")
    for key, value in changed.items():
        setattr(repo, key, value)


async def _discard_release(
    remote: ssh.RemoteSession, instance: Instance, release: str, upload: str, sink: LogSink
) -> None:
    """Best effort after a failed deploy: remove its upload and release, unless a container uses it.

    A compose ``up`` that failed half way may have started containers from the new release, so
    the release stays while any compose container's project directory is inside it.
    """
    try:
        _, users = await remote.run(release_users_command(instance), timeout=60)
        in_use = any(line.strip() == release or line.strip().startswith(release + "/") for line in users.splitlines())
        command = f"rm -f -- {q(upload)}" if in_use else discard_command(instance, release, upload)
        status, _ = await remote.run(command, check=False, timeout=600)
    except Exception as exc:
        log.warning("Could not clean up the release of a failed deployment: %s", exc)
        return
    if in_use:
        await sink.line(f"Kept {release}: containers started from it are still there")
    elif status == 0:
        await sink.line(f"Removed unused release {release}")
    else:
        await sink.line(f"Warning: could not remove unused release {release}")


# One port check at a time per host, so two deployments can't both pick the same free port.
# A check stores its result on the instance before the lock is released, and the next check
# counts it as taken.
_host_port_locks: defaultdict[uuid.UUID, asyncio.Lock] = defaultdict(asyncio.Lock)


async def _reserved_ports(instance: Instance) -> list[tuple[int, str, str]]:
    """(port, protocol, instance name) for the host ports other deployed instances on the host use."""
    async with session_scope() as db:
        rows = (await db.execute(
            select(Instance.name, Instance.build_source, Instance.ports, Instance.published_ports).where(
                Instance.host_id == instance.host_id,
                Instance.id != instance.id,
                Instance.status != InstanceStatus.CREATED,
            )
        )).all()
    out = []
    for name, source, configured, published in rows:
        for p in (configured if source == BuildSource.DOCKERFILE else published) or []:
            try:
                out.append((int(p["host"]), "udp" if p.get("protocol") == "udp" else "tcp", name))
            except (KeyError, TypeError, ValueError):
                continue
    return out


async def _plan_ports(
    remote: ssh.RemoteSession, instance: Instance, declared: list[ports.Binding], sink: LogSink,
    *, projects: frozenset[str] = frozenset(), check: Callable[[ports.PortPlan], None] | None = None,
) -> ports.PortPlan:
    """Check ``declared`` against the host, move clashes if allowed, and store the result.

    Raises DeployError on a clash the instance does not allow Slipway to move. ``check`` may refuse the plan
    (raising DeployError) before anything is stored.
    """
    overrides: dict[tuple[str | None, int, str], int] = {}
    by_service = instance.build_source in (BuildSource.COMPOSE, BuildSource.APP)
    if by_service:
        for o in instance.port_overrides or []:
            overrides[(o["service"], int(o["container"]), o.get("protocol") or "tcp")] = int(o["host"])
    async with _host_port_locks[instance.host_id]:
        _, output = await remote.run(ports.SCAN_COMMAND, check=False, timeout=60)
        own_names = {instance.running_container_name} if instance.claimed_container else set()
        host_ports = ports.parse_scan(
            output, instance_id=str(instance.id), compose_project=instance.compose_project, own_names=own_names,
            projects=projects,
        )
        for port, protocol, name in await _reserved_ports(instance):
            host_ports.reserve(port, protocol, f"Slipway instance {name}")
        try:
            plan = ports.plan(declared, host_ports, overrides=overrides, auto=instance.auto_ports, host_name=instance.host.name)
        except ports.PortError as exc:
            raise DeployError(str(exc)) from exc
        for wanted, given, why in plan.moved:
            await sink.line(f"Host port {wanted.describe()} is {why}; using {given.host} instead")
        if check is not None:
            check(plan)
        fields: dict[str, Any] = {"published_ports": ports.binding_rows(plan)}
        if by_service:
            fields["port_overrides"] = _merge_overrides(instance.port_overrides or [], plan)
        else:
            fields["ports"] = [
                {**p, "host": b.host} for p, b in zip(instance.ports, plan.bindings, strict=True)
            ]
        async with session_scope() as db:
            await db.execute(update(Instance).where(Instance.id == instance.id).values(**fields))
    for key, value in fields.items():
        setattr(instance, key, value)
    return plan


def _merge_overrides(current: list[dict[str, Any]], plan: ports.PortPlan) -> list[dict[str, Any]]:
    """The instance's port overrides with each port Slipway moved added (marked ``auto``)."""
    merged = [dict(o) for o in current]
    for wanted, given, _ in plan.moved:
        row = next(
            (o for o in merged if (o["service"], int(o["container"]), o.get("protocol") or "tcp") == wanted.key), None
        )
        if row is None:
            merged.append({"service": wanted.service, "container": wanted.container, "protocol": wanted.protocol,
                           "host": given.host, "auto": True})
        else:
            row.update(host=given.host, auto=True)
    return merged


async def _compose_config(remote: ssh.RemoteSession, instance: Instance, release: str, **kw: Any) -> dict[str, Any]:
    _, output = await remote.run(compose_config_command(instance, release, **kw), timeout=300)
    try:
        return ports.parse_compose_output(output)
    except ports.PortError as exc:
        raise DeployError(str(exc)) from exc


def read_source_file(tarball: Path, path: str, limit: int = 2 * 1024 * 1024) -> str | None:
    """The text of release path ``path`` in the source archive (None if missing, not a file or too big)."""
    try:
        with tarfile.open(tarball, "r:gz") as archive:
            while (member := archive.next()) is not None:
                archive.members.clear()
                if _extracted_name(member.name) != path:
                    continue
                if not member.isfile() or member.size > limit:
                    return None
                fh = archive.extractfile(member)
                return fh.read().decode("utf-8", "replace") if fh else None
    except (tarfile.TarError, OSError, EOFError, zlib.error):
        return None
    return None


async def _port_variables_source(
    remote: ssh.RemoteSession, instance: Instance, release: str, tarball: Path | None,
) -> dict[str, Any] | None:
    """The compose file with its ``${...}`` left in, to find the variables that set host ports.

    ``docker compose config --no-interpolate`` follows ``extends`` and ``include``; a Compose
    older than about 2.20 fails on a variable in a short-syntax port, so then the compose file
    is read from the source archive instead.
    """
    try:
        return await _compose_config(remote, instance, release, interpolate=False)
    except (DeployError, ssh.SSHError):
        pass
    path = posixpath.normpath(instance.compose_file)
    if tarball is not None:
        text = await asyncio.to_thread(read_source_file, tarball, path)
    else:  # a retry reusing its release: read it there
        text = await _read_release_file(remote, release, path)
    return ports.load_compose_yaml(text) if text is not None else None


def _port_tuples(bindings: list[ports.Binding]) -> list[tuple[str, int, str, str, int]]:
    return sorted((b.service or "", b.container, b.protocol, b.host_ip, b.host) for b in bindings)


def _port_mismatch(instance: Instance, plan: ports.PortPlan, applied: list[ports.Binding]) -> DeployError:
    want, got = set(_port_tuples(plan.bindings)), set(_port_tuples(applied))
    fmt = lambda items: ", ".join(f"{s} {h}->{c}/{p}" for s, c, p, _, h in sorted(items)) or "none"  # noqa: E731
    return DeployError(
        f"Docker Compose on {instance.host.name} did not apply the new host ports "
        f"(expected {fmt(want - got)}; got {fmt(got - want)}); nothing was started"
    )


async def _prepare_compose_ports(
    remote: ssh.RemoteSession, instance: Instance, release: str, env: dict[str, str], sink: LogSink,
    tarball: Path | None = None,
) -> dict[str, str]:
    """Check the compose file's host ports and pass any that move back to Compose.

    Runs after ``shared/.env`` is merged. Returns the port file arguments for ``build_commands``:
    ``{}``, ``{"override": ...}`` or, when this Compose ignores ``!override``, ``{"resolved": ...}``.
    """
    paths = paths_for(instance)
    await sink.line("Checking the host ports the compose file publishes")
    config = await _compose_config(remote, instance, release)
    raw = await _port_variables_source(remote, instance, release, tarball)
    declared = ports.compose_bindings(config, raw)
    plan = await _plan_ports(remote, instance, declared, sink)
    variables, override = ports.compose_changes(plan, config)
    for old, new in plan.changed:
        if not any(old.key == w.key for w, _, _ in plan.moved):
            await sink.line(f"Using host port {new.host} for {old.service} container port {old.container} (port override)")
    await remote.run(f"rm -f -- {q(paths.ports_override_file)} {q(paths.resolved_compose_file)}")
    if variables:
        await remote.write_text(paths.slipway_env_file, render_compose_env({**env, **variables}))
        await remote.run(compose_env_command(instance, release))
        await sink.line("Set " + ", ".join(f"{k}={v}" for k, v in sorted(variables.items())) + " for the compose file")
    if override is None and not variables:
        return {}
    files: dict[str, str] = {}
    if override is not None:
        await remote.write_text(paths.ports_override_file, override)
        await sink.line(f"Wrote host port changes to {paths.ports_override_file}")
        files = {"override": paths.ports_override_file}
    # Check that Compose applied them before anything starts.
    applied = ports.compose_bindings(await _compose_config(remote, instance, release, **files))
    if _port_tuples(applied) == _port_tuples(plan.bindings):
        return files
    if override is None:
        raise _port_mismatch(instance, plan, applied)
    # A Compose older than 2.24.4 adds the override's ports to the file's instead of replacing them.
    # Run this release from the resolved compose file with the planned ports instead.
    await remote.run(f"rm -f -- {q(paths.ports_override_file)}")
    await sink.line(
        f"Docker Compose on {instance.host.name} does not support !override (it needs 2.24.4 or later); "
        f"using the resolved compose file with the new ports, {paths.resolved_compose_file}"
    )
    current = await _compose_config(remote, instance, release)  # with any variables set above
    await remote.write_text(paths.resolved_compose_file, ports.resolved_with_ports(current, plan))
    files = {"resolved": paths.resolved_compose_file}
    applied = ports.compose_bindings(await _compose_config(remote, instance, release, **files))
    if _port_tuples(applied) != _port_tuples(plan.bindings):
        raise _port_mismatch(instance, plan, applied)
    return files


async def _restart_claimed(remote: ssh.RemoteSession, instance: Instance, sink: LogSink) -> None:
    """After a failed first deploy: start the claimed container again (it was running before)."""
    name = instance.running_container_name
    try:
        await remote.run(f"docker start {_claimed_id(instance)}", timeout=120)
    except Exception as exc:
        log.warning("Could not restart claimed container %s: %s", name, exc)
        await sink.line(f"Warning: could not start the claimed container {name} again; start it by hand")
    else:
        await sink.line(f"Started the claimed container {name} again")


async def _replace_claimed(remote: ssh.RemoteSession, instance: Instance, sink: LogSink) -> None:
    """After the first successful deploy of a claimed instance: drop the old container, mark the claim done."""
    if instance.claimed_container:
        name = instance.running_container_name
        status, _ = await remote.run(claimed_remove_command(instance), check=False, timeout=120)
        if status == 0:
            await sink.line(f"Removed the claimed container {name}; its volumes were kept")
        else:
            await sink.line(f"Warning: could not remove the claimed container {name} (stopped); remove it by hand")
    claim = {**(instance.claim or {}), "replaced": True, "replaced_at": utcnow().isoformat()}
    async with session_scope() as db:
        await db.execute(update(Instance).where(Instance.id == instance.id).values(claim=claim))
    instance.claim = claim


@dataclass
class _Run:
    """What one deployment has done so far on the host (for cleaning up after a failure)."""

    release: str
    upload: str
    tarball: Path | None
    built: bool = False  # the build step succeeded: keep the release so a retry can reuse it
    claimed_running: bool = False  # the claimed container ran before this deploy
    stopped_claimed: bool = False  # this deploy stopped it


async def _take_dir(remote: ssh.RemoteSession, instance: Instance, sink: LogSink) -> None:
    paths = paths_for(instance)
    status, output = await remote.run(take_dir_command(instance), check=False, timeout=60)
    if status:
        raise take_dir_error(instance, output)
    if ram_backed(instance.host, paths.base):
        await sink.line(
            f"Warning: {instance.host.name} runs Unraid, which clears {paths.base} when it restarts. Set the instance's "
            "folder (or the host's deploy root) to a path under /mnt/user, such as /mnt/user/appdata; Slipway moves the files."
        )


async def _acquire_lock(remote: ssh.RemoteSession, instance: Instance, job: _Job, sink: LogSink) -> None:
    """App mode, the first host step of every job (§4.5): take the host lock, then empty the backups' work area.

    A lock whose command has ended (or whose host restarted) is taken over; a live non-data command only gets
    a warning; a live data command (a restore, a dump) refuses the job before anything runs, unless the job was
    queued with ``take_over_lock``. What a crashed job left in ``backups/.incoming`` is never used, so it goes.
    """
    paths = paths_for(instance)
    _, output = await remote.run(data.lock_read_command(paths.lock, job.deployment_id), check=False, timeout=60)
    try:
        verdict = data.lock_verdict(data.parse_lock(output), host=instance.host.name,
                                    take_over=bool(job.options.get("take_over_lock")))
    except data.DataError as exc:
        raise DeployError(str(exc)) from None
    if verdict:
        await sink.line(verdict)
    await remote.run(data.lock_line_command(paths.lock, job.deployment_id, job.kind, data=False), timeout=60)
    job.lock_held = True
    await remote.run(data.empty_incoming_command(paths.backups), timeout=60)
    await _settle_unverified(remote, instance, sink)


async def _settle_unverified(remote: ssh.RemoteSession, instance: Instance, sink: LogSink) -> None:
    """Backups a restart left ``unverified`` (§4.4): kept when their file is complete, forgotten otherwise."""
    async with session_scope() as db:
        waiting = await db.scalar(select(Backup.id).where(Backup.instance_id == instance.id,
                                                          Backup.status == BackupStatus.UNVERIFIED).limit(1))
        if waiting is None:
            return
        for line in await data.settle_unverified(remote, db, instance, paths_for(instance).backups):
            await sink.line(line)


async def _release_lock(remote: ssh.RemoteSession, instance: Instance, job: _Job, sink: LogSink) -> None:
    """Remove the job's lock line, unless a command may still be running on the host (timed out or cut off):
    then it stays, and the next job waits until that command has ended."""
    if not job.lock_held:
        return
    if job.lock_left:
        await _read_left_pid(remote, instance, job)
        await sink.line(data.lock_left_message(job.lock_left, job.lock_pid, instance.host.name))
        return
    with contextlib.suppress(Exception):
        await remote.run(data.lock_release_command(paths_for(instance).lock, job.deployment_id), check=False, timeout=60)
    job.lock_held = False


def _mark_cut_off(job: _Job) -> None:
    """The job was cut off (shutdown): keep the lock for the command that was running, or for the job itself
    when it was between commands."""
    if not job.lock_left:
        job.lock_left, job.lock_cut = job.kind, True


async def _read_left_pid(remote: ssh.RemoteSession, instance: Instance, job: _Job) -> None:
    """Best effort: ``job.lock_pid`` from the lock line the command left running wrote (§4.5), while it runs.
    Not when the job was cut off between commands: every lock line names a command, never the job's kind, so
    the read could never match, and on a dead link it would only hold up the shutdown."""
    if job.lock_pid or not job.lock_left or job.lock_cut:
        return
    with contextlib.suppress(Exception):
        _, output = await remote.run(data.lock_own_command(paths_for(instance).lock, job.deployment_id),
                                     check=False, timeout=30)
        job.lock_pid = data.parse_own_lock(output, job.lock_left)


def _left_text(c: _AppRun) -> str:
    """``<key> (pid <pid>) may still be running on <host>`` for the command the job left running."""
    return data.lock_left_text(str(c.job.lock_left), c.job.lock_pid, c.instance.host.name)


async def _record_release(deployment_id: uuid.UUID, release: str) -> None:
    async with session_scope() as db:
        await db.execute(update(Deployment).where(Deployment.id == deployment_id).values(release=release))


def read_hex_output(output: str) -> bytes:
    """Bytes from ``od -An -v -tx1`` output (other lines, such as warnings, are skipped)."""
    hex_lines = [line for line in output.splitlines() if ports._HEX_LINE.match(line)]
    return bytes.fromhex("".join(hex_lines).replace(" ", ""))


async def _read_release_file(remote: ssh.RemoteSession, release: str, path: str, limit: int = 2 * 1024 * 1024) -> str | None:
    """The text of ``path`` in a release on the host (None if missing, a link or too big)."""
    full = q(posixpath.join(release, path))
    status, output = await remote.run(
        f"[ -f {full} ] && [ ! -L {full} ] && [ $(wc -c < {full}) -le {limit} ] && od -An -v -tx1 {full}",
        check=False, timeout=120,
    )
    if status:
        return None
    return read_hex_output(output).decode("utf-8", "replace")


async def _source_file(remote: ssh.RemoteSession, run: _Run, path: str) -> str | None:
    if run.tarball is not None:
        return await asyncio.to_thread(read_source_file, run.tarball, path)
    return await _read_release_file(remote, run.release, path)


async def _install(
    remote: ssh.RemoteSession, instance: Instance, deployment_id: uuid.UUID, sha: str, tarball: Path | None,
    job: _Job, sink: LogSink, steps: Steps,
) -> None:
    paths = paths_for(instance)
    reuse = job.retry is not None and job.retry.reusable and bool(job.retry.release)
    # The reused release by its name in the instance's folder now: a move since then copied it there.
    release = (posixpath.join(paths.releases, posixpath.basename(job.retry.release)) if reuse
               else paths.release(sha, deployment_id))
    run = _Run(release=release, upload=f"{paths.releases}/.upload-{deployment_id.hex}.tar.gz", tarball=tarball)
    await _record_release(deployment_id, release)
    try:
        await _install_locked(remote, instance, deployment_id, sha, tarball, job, sink, steps, paths, release, run, reuse)
    except asyncio.CancelledError:
        _mark_cut_off(job)  # cut off part-way: what ran may still be running
        raise
    finally:
        if instance.build_source == BuildSource.APP and job.lock_held:
            await _remove_job_dir(remote, instance, job)
        if isinstance(job.ctx, _AppRun):
            await job.ctx.close_members()
        await _release_lock(remote, instance, job, sink)


async def _install_locked(
    remote: ssh.RemoteSession, instance: Instance, deployment_id: uuid.UUID, sha: str, tarball: Path | None,
    job: _Job, sink: LogSink, steps: Steps, paths: InstancePaths, release: str, run: _Run, reuse: bool,
) -> None:
    app = instance.build_source == BuildSource.APP
    if job.live_inputs is not None:
        async with steps.step("release"):
            await _take_dir(remote, instance, sink)
            await _acquire_lock(remote, instance, job, sink)
            await _check_live_release(remote, instance, paths, str(job.live_inputs["release"]))
            await sink.line(f"Running the live release {sha[:7]} again ({release})")
    elif reuse:
        await _take_dir(remote, instance, sink)
        if app:
            await _acquire_lock(remote, instance, job, sink)
        status, _ = await remote.run(f"[ -d {q(release)} ]", check=False, timeout=60)
        if status:
            raise DeployError(f"The release {release} is no longer on {instance.host.name}; deploy again instead of retrying")
        assert job.retry is not None
        await steps.skip("upload", f"Reusing {release} from deployment {job.retry.id.hex[:8]}", listed_only=True)
    else:
        async with steps.step("upload"):
            await _take_dir(remote, instance, sink)
            if app:
                await _acquire_lock(remote, instance, job, sink)
            await remote.run(f"mkdir -p {q(paths.releases)} {q(paths.shared)}")
            try:
                assert tarball is not None
                await remote.put(tarball, run.upload)
                await remote.run(unpack_command(release, run.upload))
            except Exception:
                await _discard_release(remote, instance, release, run.upload, sink)
                raise
            await sink.line(f"Unpacked release into {release}")
    try:
        if instance.build_source == BuildSource.APP:
            state = await _install_app(remote, instance, deployment_id, sha, job, run, sink, steps)
        elif instance.build_source == BuildSource.COMPOSE:
            state = await _install_compose(remote, instance, sha, job, run, sink, steps)
        else:
            state = await _install_dockerfile(remote, instance, sha, job, run, sink, steps)
    except Exception:
        if run.stopped_claimed:
            await _restart_claimed(remote, instance, sink)
        if job.live_inputs is not None:
            pass  # the live release: it stays as it is
        elif run.built or reuse:  # a reused release was kept by the deployment it came from: never remove it
            with contextlib.suppress(Exception):
                await remote.run(f"rm -f -- {q(run.upload)}", check=False, timeout=60)
            await sink.line(f"Kept {release} so a retry can start from it")
            await _prune_after_failure(remote, instance, release, sink)
        else:
            await _discard_release(remote, instance, release, run.upload, sink)
        raise
    async with steps.step("finish"):
        if instance.claim_pending:
            await _replace_claimed(remote, instance, sink)
        await remote.run(f"ln -sfn {q(release)} {q(paths.current)}")
        await sink.line(f"Switched {paths.current} to {release}")
        if state is not None:  # what the app runs now: status, logs, stop and Switchyard follow it from here
            # ``went_live`` names this job, so a restart from here on still counts it as live (_recover_instance).
            state["went_live"] = deployment_id.hex
            live_fields: dict[str, Any] = {"app_state": state}
            kept: dict[str, str] = {}
            unkept: list[str] = []
            owner = job.data_owner
            owner_elsewhere = owner is not instance
            # A data server deploy runs no app migration: it records the identity only when there is none yet,
            # as an app slot's deploy does (§7.5).
            server_deploy = job.member and instance.slot == environments.DATA_SLOT \
                and job.kind == DeploymentKind.DEPLOY
            # No app had run on the shared data when this app slot deploy began: its values become the data's.
            replace = owner_elsewhere and job.kind == DeploymentKind.DEPLOY and job.replace_identity
            unchanged: list[str] = []
            if job.data_app and job.identity is not None:
                known = dict(owner.live_identity or {})
                if not owner_elsewhere and not (server_deploy and known):
                    live_fields["live_identity"] = job.identity  # the data is now this release's (D8)
                    known = dict(job.identity)
                elif not known or replace:
                    known = dict(job.identity)  # an app slot's first: _member_went_live records it on the owner
                unchanged = sorted(k for k, v in job.identity.items() if k in known and known[k] != v)
                # Only the values the data is made with now; an app slot's deploy was refused otherwise.
                kept = {k: v for k, v in _identity_from_variables(job).items() if known.get(k) == v}
                if kept:
                    # The stored secret becomes the value the data is now made with, so removing the variable
                    # later keeps it (what the restore refusal tells the operator to do). Only while a ready
                    # backup still holds the stored one: a secret Slipway made is never thrown away (§9.1).
                    held = await _backed_up_secrets(owner, job.secrets or {}, kept)
                    unkept = sorted(k for k in kept if k not in held)
                    kept = {k: v for k, v in kept.items() if k in held}
                if kept and job.member:
                    job.secrets = {**(job.secrets or {}), **kept}
                    await _secrets_saved(job, job.secrets)
                elif kept:
                    job.secrets = live_fields["app_secrets"] = {**(job.secrets or {}), **kept}
            if job.member and job.kind == DeploymentKind.DEPLOY:
                live_fields["slot_state"] = {k: v for k, v in (instance.slot_state or {}).items() if k != "stale"}
            if owner_elsewhere and job.data_app and job.identity and (not owner.live_identity or replace):
                # An app slot's first deploy on the shared data: the owner's identity in the same transaction as
                # went_live, so a restart between them can't leave a live release with no identity recorded.
                async with session_scope() as db:
                    await db.execute(update(Instance).where(Instance.id == instance.id).values(**live_fields))
                    fresh = await db.get(Instance, owner.id)
                    if fresh is not None and (fresh.live_identity is None or replace):
                        fresh.live_identity = dict(job.identity)
                        owner.live_identity = dict(job.identity)
                for key, value in live_fields.items():
                    setattr(instance, key, value)
            else:
                await _save_instance(instance, **live_fields)
            job.went_live = sha  # before any other await: a cut-off from here on still counts as live (D12)
            if job.member:
                await _member_went_live(job, instance, state)
            whose = f"{job.environment.name}'s variables" if job.member else "the instance's environment variables"
            if kept:
                await sink.line(f"Kept {', '.join(sorted(kept))} from {whose} as the app's secrets: the data is made "
                                "with them now")
            if unkept:
                await sink.line(f"Warning: {', '.join(unkept)} now comes from {whose}, and no backup holds the "
                                "stored secret it replaces, so Slipway keeps that secret. Removing the variable "
                                "brings it back.")
            if unchanged:
                await sink.line(f"Warning: {', '.join(unchanged)} of {whose} differs from the value "
                                f"{owner.name}'s data was made with; the data keeps its value (only a restore "
                                "changes it), and an app slot's deploy is refused until the variable is put back")
        try:
            status, output = await remote.run(prune_command(instance, release), check=False, timeout=600)
            if status != 0:
                detail = " ".join(output.strip().splitlines()[-3:])
                await sink.line(f"Warning: some old releases could not be removed. {detail}".strip())
            if state is not None:
                await _prune_app_images(remote, instance, state, sink)
        except Exception as exc:
            if job.went_live is None:
                raise
            # The release is live: tidying up after it never fails the job.
            await sink.line(f"Warning: old releases and images could not be removed: {exc}")
    if app and job.ctx is not None:
        await _post_finish(job.ctx)


async def _prune_after_failure(remote: ssh.RemoteSession, instance: Instance, release: str, sink: LogSink) -> None:
    """Best effort: keep only the newest few releases that failed deploys kept, so a run of failures doesn't fill
    the host's disk.

    Newest goes by the last deployment that used a release (a retry reuses one). Never removed: the live release,
    one a succeeded deployment ran (the normal prune keeps those), one a container still uses, and any image
    (the live release's may be older than the failed ones).
    """
    try:
        paths = paths_for(instance)
        async with session_scope() as db:
            rows = (await db.execute(
                select(Deployment.release, Deployment.status).where(
                    Deployment.instance_id == instance.id, Deployment.release.is_not(None),
                    Deployment.kind == DeploymentKind.DEPLOY)
                .order_by(Deployment.created_at.desc())
            )).all()
        ran = {posixpath.basename(r) for r, st in rows if st == DeploymentStatus.SUCCEEDED}
        failed = [n for n in dict.fromkeys(posixpath.basename(r) for r, st in rows
                                           if st in (DeploymentStatus.FAILED, DeploymentStatus.CANCELLED,
                                                     DeploymentStatus.RUNNING))
                  if _RELEASE_NAME.fullmatch(n) and n not in ran]
        _, listing = await remote.run(_image_list_command(paths.releases), check=False, timeout=60)
        present = {line.strip() for line in listing.splitlines()}
        failed = [n for n in failed if n in present]  # a release discarded when its build failed takes no place
        keep = {posixpath.basename(release), *failed[:KEEP_RELEASES]}
        old = [n for n in failed if n not in keep]
        if not old:
            return
        _, current = await remote.run(f"readlink {q(paths.current)}", check=False, timeout=60)
        _, users = await remote.run(release_users_command(instance), timeout=60)
        used = {posixpath.basename(current.strip())} | {
            n for n in old for line in users.splitlines()
            if line.strip() == f"{paths.releases}/{n}" or line.strip().startswith(f"{paths.releases}/{n}/")}
        for name in old:
            if name in used:
                continue
            status, _ = await remote.run(discard_command(instance, f"{paths.releases}/{name}", f"{paths.releases}/.none"),
                                         check=False, timeout=600)
            await sink.line(f"Removed the release of an older failed deployment: {name}" if status == 0
                            else f"Warning: could not remove the release of an older failed deployment: {name}")
        if instance.build_source == BuildSource.APP and instance.app_state:
            await _prune_app_images(remote, instance, dict(instance.app_state), sink)
    except Exception as exc:
        log.warning("Could not prune releases after a failed deployment: %s", exc)


async def _claimed_state(remote: ssh.RemoteSession, instance: Instance, run: _Run) -> None:
    if instance.claimed_container:
        _, state = await remote.run(claimed_state_command(instance), check=False, timeout=60)
        run.claimed_running = state.strip().splitlines()[-1:] == ["true"]


async def _run_commands(
    remote: ssh.RemoteSession, instance: Instance, commands: list[str], run: _Run, sink: LogSink,
) -> None:
    stop_claimed = _stop_claimed(instance) if instance.claimed_container else None
    for command in commands:
        await sink.line(f"$ {command}")
        if stop_claimed and stop_claimed in command:
            run.stopped_claimed = run.claimed_running
        await remote.run(command, on_line=sink.line, scrub=sink.scrub, timeout=3600)


async def _install_dockerfile(
    remote: ssh.RemoteSession, instance: Instance, sha: str, job: _Job, run: _Run, sink: LogSink, steps: Steps,
) -> None:
    paths = paths_for(instance)
    env = job.env or {}
    async with steps.step("settings"):
        await remote.write_text(paths.env_file, render_env(env))
        await sink.line(f"Wrote {len(env)} environment variable(s) to {paths.env_file}")
        await _claimed_state(remote, instance, run)
    if instance.ports:
        async with steps.step("ports"):
            await _plan_ports(remote, instance, ports.dockerfile_bindings(instance.ports), sink)
    else:
        await steps.skip("ports", "No port mappings")
    build, *start = build_commands(instance, run.release, sha)
    image = f"slipway/{instance.slug}:{sha[:12]}"
    if job.retry is not None and job.retry.reusable and await _images_exist(remote, [image]):
        await steps.skip("build", f"Reusing the image {image} from deployment {job.retry.id.hex[:8]}")
    else:
        async with steps.step("build"):
            await _run_commands(remote, instance, [build], run, sink)
    run.built = True
    async with steps.step("start"):
        await _run_commands(remote, instance, start, run, sink)
    return None


async def _install_compose(
    remote: ssh.RemoteSession, instance: Instance, sha: str, job: _Job, run: _Run, sink: LogSink, steps: Steps,
) -> None:
    paths = paths_for(instance)
    env = job.env or {}
    async with steps.step("settings"):
        await remote.write_text(paths.slipway_env_file, render_compose_env(env))
        await sink.line(f"Wrote {len(env)} environment variable(s) to {paths.slipway_env_file}")
        await _claimed_state(remote, instance, run)
        command = compose_env_command(instance, run.release)
        await sink.line(f"$ {command}")
        await remote.run(command, on_line=sink.line, scrub=sink.scrub, timeout=3600)
    async with steps.step("ports"):
        files = await _prepare_compose_ports(remote, instance, run.release, env, sink, run.tarball)
    _, *start = build_commands(instance, run.release, sha, **files)
    async with steps.step("build"):
        await _run_commands(remote, instance, [compose_build_command(instance, run.release, **files)], run, sink)
    run.built = True
    async with steps.step("start"):
        await _run_commands(remote, instance, start, run, sink)
    return None


def compose_build_command(instance: Instance, release_dir: str, *, override: str | None = None,
                          resolved: str | None = None) -> str:
    """Build the compose file's images (Start's ``up --build`` then finds them in the cache)."""
    return f"cd {q(release_dir)} && {_compose(instance, override, resolved=resolved, release_dir=release_dir)} build"


async def _images_exist(remote: ssh.RemoteSession, images: list[str]) -> bool:
    if not images:
        return False
    status, _ = await remote.run(f"docker image inspect --format . {' '.join(q(i) for i in images)} >/dev/null 2>&1",
                                 check=False, timeout=120)
    return status == 0


# ------------------------------------------------------------------- app mode


def app_builtins(instance: Instance, release: str, sha: str, deployment_id: uuid.UUID) -> dict[str, str]:
    env = data.loaded_environment(instance) if instance.environment_id is not None else None
    return {
        "slug": instance.slug, "name": instance.name, "release": release, "env_dir": paths_for(instance).shared,
        "sha": sha, "sha12": sha[:12], "host": instance.host.address, "deployment": deployment_id.hex[:8],
        # Phase 3 §5.1: the environment's name and the slot; empty for standalone instances.
        "environment": env.name if env is not None else "", "slot": str(instance.slot or "") if env is not None else "",
    }


def _clients(job: _Job) -> list[str]:
    """``{server.clients}``: the app slots' hosts' client addresses, sorted and unique (§5.1)."""
    return sorted({m.host.client_address for m in environments.app_members(job.members) if m.host.client_address})


def _server_values(job: _Job, instance: Instance) -> dict[str, Any] | None:
    """The data server's ``server_values`` (§6): its own host's address and the app slots' client addresses."""
    if job.role != "server":
        return None
    return {"host": instance.host.upstream_address, "clients": _clients(job)}


async def _secrets_saved(job: _Job, secrets: dict[str, str]) -> None:
    """Keep the app's secrets: on the instance, or for a member of an environment on the environment, by
    compare-and-set on ``secrets_version`` (§6, I3): a change made since the job read them fails the step."""
    if not job.member:
        await _save_instance(job.instance, app_secrets=secrets)
        return
    env = job.environment
    async with session_scope() as db:
        result = await db.execute(
            update(Environment).where(Environment.id == env.id, Environment.secrets_version == job.secrets_version)
            .values(app_secrets=secrets, secrets_version=Environment.secrets_version + 1)
            .execution_options(synchronize_session=False))
        if result.rowcount != 1:
            raise DeployError(f"{env.name}'s secrets changed while this job ran; retry it")
    job.secrets_version += 1
    env.app_secrets = secrets


async def _owner_live_release(c: _AppRun) -> tuple[manifest.Manifest, str | None]:
    """The data owner's live release's slipway.yml and env_file, read on its host (an app slot's ``data_values``
    are rendered from them, §6)."""
    m = await c.member(environments.owner_slot(c.job.environment))
    live = data.live_state(m.instance)
    if live is None:
        raise DeployError(environments.no_server_text(c.job.environment))
    release = await _check_live_release(m.remote, m.instance, m.paths, str(live.get("release") or ""))
    text = await _read_release_file(m.remote, release, m.instance.manifest_file)
    if text is None:
        raise DeployError(f"{m.instance.manifest_file} of the data server's live release can't be read in {release}")
    try:
        man = manifest.parse(text)
    except manifest.ManifestError as exc:
        raise DeployError(f"The data server's live release: {exc}") from exc
    template = await _read_release_file(m.remote, release, man.env_file) if man.env_file else None
    return man, template


async def _data_values(c: _AppRun) -> dict[str, dict[str, str]] | None:
    """An app slot's ``data_values`` in mode ``server`` (§6): the data server's rendered provides, once per job.
    Refused, before anything changes, when the data server isn't ready for this slot."""
    job = c.job
    if job.data_values is not None or not job.member or job.environment.data_mode != DataMode.SERVER:
        return job.data_values
    instance = c.instance
    if instance.slot not in environments.APP_SLOTS:
        return None
    env = job.environment
    owner = job.data_owner
    problem = environments.attach_problem(env, owner, instance)
    if problem:
        raise DeployError(problem)
    man, template = await _owner_live_release(c)
    view = Environment(id=env.id, name=env.name, app_secrets=dict(job.secrets or {}), env=dict(job.env or {}))
    try:
        job.data_values = environments.data_values(view, owner, man, template=template)
    except environments.DataValuesError as exc:
        raise DeployError(str(exc)) from None
    for need in job.data_values.values():
        for key in ("password", "secret_key"):
            if need.get(key):
                c.sink.hide.add(str(need[key]))
    return job.data_values


# slipway.yml's data commands, and first_admin: they run under ``umask 077`` (what they write stays the SSH
# user's). build, start and stop keep running exactly as before data commands existed (security 12).
UMASK_COMMANDS = frozenset({*manifest.COMMANDS[3:], "first_admin"})
# Commands that change or write the app's data: their host lock line carries ``d``, so a later job waits for
# them to end (§4.5). ``start`` counts too when slipway.yml declares ``dump`` (it migrates).
LOCK_DATA_COMMANDS = frozenset({"dump", "export_files", "restore", "import_files", "after_import", "seed",
                                "first_admin", "reset"})


@dataclass(frozen=True)
class LockLine:
    """The host lock line a command writes for itself before it runs (``data.lock_line_command``)."""

    path: str
    deployment_id: uuid.UUID
    key: str
    data: bool


def app_command(
    release: str, cmd: Any, *, slots: dict[str, str] | None = None, stream_path: str | None = None,
    stream: str | None = None, lock: LockLine | None = None, umask: bool = False, name: str | None = None,
    env_from_stdin: str | None = None,
) -> str:
    """Run one of slipway.yml's commands from the release: a program in the repository, or one on the PATH.

    ``cmd`` is a plan's ``{"argv": [...], "stream": ...}`` or the older plain argv list. An argument that is
    ``{"slot": name}`` is replaced by ``slots[name]``; every item is quoted. ``stream_path`` is the file a
    command in stream mode writes (``stdout``) or reads (``stdin``); ``stream`` overrides the command's own
    mode (the revision is captured from stdout this way). ``lock`` writes the host lock line first and then
    ``exec``s the program, so the line names the program's PID. ``umask`` makes what it writes private.
    ``env_from_stdin`` reads one line of stdin into that variable before the program starts (the first
    admin's password, which never appears in argv). Without any of these the command is exactly the one
    Slipway always ran: ``cd <release> && <program> <args>``."""
    argv = manifest.command_argv(cmd)
    where = f"commands.{name}: " if name and name != "first_admin" else ("first_admin.command: " if name else "")
    if not argv:
        raise DeployError(f"{where}slipway.yml gave an empty command")
    args: list[str] = []
    for a in argv:
        if isinstance(a, dict):
            slot = str(a.get("slot", ""))
            if slots is None or slot not in slots:
                shown = "slipway." + slot if slot in ("in", "out") else slot
                raise DeployError(f"{where}Slipway gave no value for {{{shown}}}")
            a = slots[slot]
        args.append(a)
    program = args[0]
    if "/" in program:
        program = "./" + manifest.clean_repo_path(program, "the command")
    run = " ".join(q(a) for a in [program, *args[1:]])
    direction = stream or (cmd.get("stream") if isinstance(cmd, dict) else None)
    if direction is not None:
        if direction not in ("stdout", "stdin"):
            raise DeployError(f"{where}unknown stream mode {direction!r}")
        if not stream_path:
            raise DeployError(f"{where}Slipway gave no file for its {direction}")
        run += f" {'>' if direction == 'stdout' else '<'} {q(stream_path)}"
    if lock is None and not umask and env_from_stdin is None:
        return f"cd {q(release)} && {run}"
    if env_from_stdin is not None:
        if not manifest.PASSWORD_VAR_RE.match(env_from_stdin):
            raise DeployError(f"{where}{env_from_stdin!r} can't carry the password")
        # Exit 97: nothing arrived on stdin. The variable is set only in this shell, which execs the program.
        inner = (f"{{ IFS= read -r p || exit 97; {env_from_stdin}=$p; export {env_from_stdin}; unset p; "
                 f"exec {run}; }}")
    else:
        inner = f"exec {run}"
    if lock is not None:
        inner = f"{data.lock_line_command(lock.path, lock.deployment_id, lock.key, data=lock.data)} && {inner}"
    return f"cd {q(release)} && {'umask 077 && ' if umask else ''}{{ {inner}; }}"


async def _save_instance(instance: Instance, **fields: Any) -> None:
    async with session_scope() as db:
        await db.execute(update(Instance).where(Instance.id == instance.id).values(**fields))
    for key, value in fields.items():
        setattr(instance, key, value)


@dataclass
class _Side:
    """One release's slipway.yml rendered for this host: what runs its commands, and the ``.env`` they read."""

    man: manifest.Manifest
    plan: manifest.AppPlan
    release: str  # its folder on the host
    sha: str
    content: str = ""  # the shared/.env this rendering writes

    @property
    def sha7(self) -> str:
        return self.sha[:7]


@dataclass
class _AppRun:
    """An app job on its host: the session, the job and its steps, and the release it deploys."""

    remote: ssh.RemoteSession
    instance: Instance
    job: _Job
    sink: LogSink
    steps: Steps
    paths: InstancePaths
    new: _Side | None = None  # the release being deployed (None for jobs that only use the live release)
    live: _Side | None = None  # the live release rendered by this job already (a data job's release step)
    replan: Callable[[dict[str, str]], manifest.AppPlan] | None = None  # ``new`` planned with other secrets
    template: str | None = None  # ``new``'s env_file template
    data_up: bool = False  # ``data_up`` ran since the app was last stopped (restore, files, after_import need it)
    # Phase 3 §7.1: the other members of the environment this job runs commands on, by slot, each an _AppRun of
    # its own (its host's session, folder and lock) sharing this job, its log and its steps. Opened lazily.
    members: dict[str, _AppRun] = field(default_factory=dict)
    stack: contextlib.AsyncExitStack | None = None  # closes the members' sessions when the job ends
    lock_held: bool = False  # a member: this job wrote its line to the member's host lock
    root: _AppRun | None = None  # a member: the job's own run, which holds the members

    @property
    def owner(self) -> Instance:
        """The data owner, whose phase 2 fields this job reads (the instance itself outside environments)."""
        return self.job.data_owner

    async def member(self, slot: str) -> _AppRun:
        """The member ``slot`` of the job's environment: this run itself when it is that member."""
        if self.instance.slot == slot:
            return self
        if self.root is not None:
            return await self.root.member(slot)
        if slot in self.members:
            return self.members[slot]
        instance = self.job.members.get(slot)
        if instance is None or self.job.connect is None:
            raise DeployError(f"{self.job.environment.name if self.job.member else self.instance.name} has no {slot}")
        if self.stack is None:
            self.stack = contextlib.AsyncExitStack()
        host = instance.host
        await self.sink.line(f"Connecting to {host.username}@{host.address} ({data.slot_text(slot)})")
        remote = await self.stack.enter_async_context(self.job.connect(ssh.SSHTarget.from_host(host)))
        m = _AppRun(remote=remote, instance=instance, job=self.job, sink=self.sink, steps=self.steps,
                    paths=paths_for(instance), root=self)
        self.members[slot] = m
        await _member_lock(m)
        return m

    async def close_members(self) -> None:
        """Release each member's host lock (unless a command may still run there) and close its session."""
        for m in self.members.values():
            if m.lock_held and not self.job.lock_left:
                with contextlib.suppress(Exception):
                    await m.remote.run(data.lock_release_command(m.paths.lock, self.job.deployment_id), check=False,
                                       timeout=60)
                m.lock_held = False
        self.members = {}
        if self.stack is not None:
            stack, self.stack = self.stack, None
            with contextlib.suppress(Exception):
                await stack.aclose()


async def _member_lock(m: _AppRun) -> None:
    """Before a job runs commands on another member's host (§7.1): that host's lock, as ``_acquire_lock`` takes
    a job's own (a live data command there refuses the job before anything runs)."""
    _, output = await m.remote.run(data.lock_read_command(m.paths.lock, m.job.deployment_id), check=False, timeout=60)
    try:
        verdict = data.lock_verdict(data.parse_lock(output), host=m.instance.host.name,
                                    take_over=bool(m.job.options.get("take_over_lock")))
    except data.DataError as exc:
        raise DeployError(str(exc)) from None
    if verdict:
        await m.sink.line(verdict)
    await m.remote.run(f"mkdir -p -- {q(m.paths.base)}", check=False, timeout=60)
    await m.remote.run(data.lock_line_command(m.paths.lock, m.job.deployment_id, m.job.kind, data=False), timeout=60)
    m.lock_held = True


async def _app_run(
    c: _AppRun, side: _Side, name: str, *, cmd: Any = None, slots: dict[str, str] | None = None,
    stream_path: str | None = None, stream: str | None = None, check: bool = True, input: str | None = None,
    env_from_stdin: str | None = None, lock_data: bool | None = None, timeout: float | None = None,
) -> tuple[int, str]:
    """Run slipway.yml's command ``name`` of ``side``'s release, under the host lock, logged and scrubbed.

    The ``$`` line shows the command as the app sees it (never the lock line, never a password: that one
    arrives on stdin). When the command doesn't return an exit status (it timed out, SSH broke, Slipway was
    stopped), it may still be running, so the job leaves the host lock in place (§4.5). It then runs no other
    command: each one rewrites the lock line, and the next job must keep waiting for the one left running.
    """
    await _refuse_while_left(c, f"commands.{name}")
    cmd = side.plan.commands[name] if cmd is None else cmd
    data_flag = name in LOCK_DATA_COMMANDS if lock_data is None else lock_data
    lock = LockLine(c.paths.lock, c.job.deployment_id, name, data_flag)
    command = app_command(side.release, cmd, slots=slots, stream_path=stream_path, stream=stream, lock=lock,
                          umask=name in UMASK_COMMANDS, name=name, env_from_stdin=env_from_stdin)
    shown = app_command(side.release, cmd, slots=slots, stream_path=stream_path, stream=stream, name=name)
    await c.sink.line(f"$ {shown}")
    extra: dict[str, Any] = {"input": input} if input is not None else {}
    try:
        return await c.remote.run(command, check=check, on_line=c.sink.line, scrub=c.sink.scrub,
                                  timeout=timeout or side.man.timeout(name), **extra)
    except ssh.CommandFailed:
        raise
    except (ssh.SSHError, asyncio.CancelledError):
        c.job.lock_left = name
        raise


async def _refuse_while_left(c: _AppRun, what: str) -> None:
    """A command the job left running holds the host lock line: nothing may rewrite it (§4.5)."""
    if c.job.lock_left:
        await _read_left_pid(c.remote, c.instance, c.job)
        raise DeployError(f"Slipway didn't run {what}: {_left_text(c)}. Retry once it has ended.")


def env_fingerprint(instance: Instance, env: dict[str, str]) -> str:
    """A salted SHA-256 of the instance's variables, to tell later that they changed (never the values)."""
    text = "".join(f"{k}={v}\n" for k, v in sorted(env.items()))
    return hashlib.sha256(b"slipway-env-v1\x00" + instance.id.bytes + text.encode()).hexdigest()


def _env_content(template: str | None, plan: manifest.AppPlan) -> str:
    lines, _ = manifest.parse_env_template(template or "")
    try:
        return manifest.render_env(lines, plan.env, plan.written)
    except manifest.ManifestError as exc:
        raise DeployError(str(exc)) from exc


async def _install_app(
    remote: ssh.RemoteSession, instance: Instance, deployment_id: uuid.UUID, sha: str, job: _Job, run: _Run,
    sink: LogSink, steps: Steps,
) -> dict[str, Any]:
    paths = paths_for(instance)
    # The job's run on its host; the release it deploys is filled in once its settings are written.
    c = _AppRun(remote=remote, instance=instance, job=job, sink=sink, steps=steps, paths=paths)
    job.ctx = c
    live = job.live_inputs  # restore, roll back, reset: the live release again, with what it went live with (D3)
    # The release's {slipway.deployment} is the deployment that made it (a reused live release keeps its own).
    made_by = uuid.UUID(str(live["deployment"])) if live is not None else deployment_id
    builtins = app_builtins(instance, run.release, sha, made_by)
    env = job.env or {}
    if live is not None:
        settings = {str(k): str(v) for k, v in (live.get("settings") or {}).items()}
        chosen = live.get("services")
    elif job.member:  # the environment's settings and services (phase 3 §6)
        settings, chosen = dict(job.settings or {}), job.services
    else:
        settings, chosen = dict(instance.app_settings or {}), instance.app_services
    role_kw: dict[str, Any] = {}
    if job.role != "app":
        role_kw["role"] = job.role

    def plan_with(host_ports: dict[str, int], with_secrets: dict[str, str] | None = None) -> manifest.AppPlan:
        try:
            return manifest.plan(
                man, template=template, builtins=builtins, settings=settings,
                chosen=chosen, host_ports=host_ports, secrets=with_secrets if with_secrets is not None else secrets,
                env=env, **role_kw,
            )
        except manifest.ManifestError as exc:
            raise DeployError(str(exc)) from exc
        except KeyError as exc:
            raise DeployError(f"slipway.yml needs the secret {exc.args[0]}, which Slipway doesn't have") from exc

    async with steps.step("manifest"):
        text = await _source_file(remote, run, instance.manifest_file)
        if text is None:
            raise DeployError(f"{instance.manifest_file} was not found in {instance.repository.full_name} at {sha[:7]} "
                              "(or it is a link, or larger than 2 MB)")
        try:
            man = manifest.parse(text)
        except manifest.ManifestError as exc:
            raise DeployError(str(exc)) from exc
        template = None
        if man.env_file:
            template = await _source_file(remote, run, man.env_file)
            if template is None:
                raise DeployError(f"slipway.yml: env_file {man.env_file} was not found in the repository (or it is a link)")
        if job.secrets is None:
            unset = [s.key for s in man.secrets if not env.get(s.key)]
            if unset and job.member:
                name = job.environment.name
                raise DeployError(
                    f"Slipway lost {name}'s secrets (SLIPWAY_ENCRYPTION_KEY changed): put the old key back first in "
                    f"the list and run slipway rotate-encryption-key, or set each of them as a variable of {name}: "
                    f"{', '.join(unset)} (their old values, or the app's existing data won't open)")
            if unset:
                raise DeployError(
                    "The app's stored secrets can't be decrypted with the configured SLIPWAY_ENCRYPTION_KEY. Restore "
                    "the old key (see slipway rotate-encryption-key), or set each of them as an environment variable "
                    f"of the instance: {', '.join(unset)} (their old values, or the app's existing data won't open)")
            if job.member:
                # Kept as the environment's secrets below, by compare-and-set on secrets_version (§6, I3): its
                # other jobs can run again from then on.
                await sink.line(f"{job.environment.name}'s stored secrets can't be decrypted; its variables set "
                                "every one, so Slipway keeps them as its secrets")
            else:
                await sink.line("The stored secrets can't be decrypted; the instance's environment variables set "
                                "every one")
        secrets = dict(job.secrets or {})
        if job.member:
            try:
                manifest.check_instance_env(man, env, job.role)
            except manifest.ManifestError as exc:
                raise DeployError(str(exc)) from exc
        fresh = manifest.new_secrets(man, secrets)
        # A secret the instance's variables set is kept as that value (the one the app's data was made with),
        # never replaced by a new one: the variable can then be removed safely.
        adopted = sorted(k for k in fresh if env.get(k))
        fresh.update({k: env[k] for k in adopted})
        secrets.update(fresh)
        for value in fresh.values():
            sink.hide.add(value)
        job.secrets = secrets  # the live render of the backup step uses them too
        if job.role == "slot":
            role_kw["data_values"] = await _data_values(c)
        elif job.role == "server":
            role_kw["server_values"] = _server_values(job, instance)
        first = plan_with({})
        if job.member and job.data_owner is not instance and live is None:
            # An app slot on shared data goes live only with the identity values the data was made with (I3).
            problem = _slot_identity_problem(job, first, man.identity_keys())
            if problem:
                raise DeployError(problem)
        await _check_projects_free(instance, first.projects)
        await _check_projects_on_host(remote, instance, first.projects, [s.key for s in man.secrets], env)
        if job.member:
            names = {str(r["hostname"]) for r in first.routes}
            async with session_scope() as db:
                taken = await environments.hostname_conflict(db, names, environment_id=job.environment.id)
            if taken:
                raise DeployError(taken)
        if fresh:  # kept only once the app may use them
            await _secrets_saved(job, secrets)
            generated = sorted(set(fresh) - set(adopted))
            where = f"environment {job.environment.name}" if job.member else "the instance"
            if generated:
                await sink.line(f"Generated {len(generated)} secret(s) and kept them with {where}: {', '.join(generated)}")
            if adopted:
                whose = f"{job.environment.name}'s variables" if job.member else "the instance's environment variables"
                await sink.line(f"Kept {', '.join(adopted)} from {whose} as the app's secrets")
        await sink.line(f"{man.name}: running {', '.join(s.name for s in first.services) or 'no services'}")
        if "seed" not in man.commands:
            await steps.drop("seed")  # listed in case this release adds starter content: it doesn't

    planned = [s for s in first.services if s.port_var]
    fixed = [s for s in first.services if s.port is not None and not s.port_var]
    host_ports: dict[str, int] = {}
    if live is not None:  # the live release keeps its host ports (no ports step, §7.3)
        try:
            host_ports = {str(k): int(v) for k, v in (live.get("host_ports") or {}).items()}
        except (TypeError, ValueError) as exc:
            raise DeployError(f"Slipway's record of {instance.name}'s live release is damaged ({exc}); deploy again "
                              "first.") from exc
    elif planned:
        async with steps.step("ports"):
            declared = [ports.Binding(service=s.name, container=s.port, protocol=s.protocol, host=s.port) for s in planned]
            # A data server's port the app slots' settings name may not move (§9.7, I5): refused before the
            # moved port is stored, so freeing the port and deploying again works.
            def refuse(plan: ports.PortPlan) -> None:
                _refuse_moved_ports(job, instance, {b.service: b.host for b in plan.bindings if b.service})

            port_plan = await _plan_ports(remote, instance, declared, sink, projects=frozenset(first.projects),
                                          check=refuse if job.role == "server" else None)
            host_ports = {b.service: b.host for b in port_plan.bindings if b.service}
            if fixed:
                rows = list(instance.published_ports) + [
                    {"service": s.name, "container": s.port, "protocol": s.protocol, "host": s.port} for s in fixed
                ]
                await _save_instance(instance, published_ports=rows)
    else:
        await steps.skip("ports", "slipway.yml sets no port variables")
        await _save_instance(instance, published_ports=[
            {"service": s.name, "container": s.port, "protocol": s.protocol, "host": s.port} for s in fixed
        ])

    async with steps.step("settings"):
        if job.role == "server" and live is None:
            _refuse_moved_ports(job, instance, host_ports)
        final = plan_with(host_ports)
        if live is not None:
            problem = (_live_names_problem(final, live, sha[:7])
                       or _identity_problem(c.owner, final, man.identity_keys(), sha[:7], shared=_shares_data(job)))
            if problem:
                raise DeployError(problem)
            if live.get("env_fp") and live.get("env_fp") != env_fingerprint(instance, env):
                await sink.line(f"The instance's environment variables changed since {sha[:7]} went live; Slipway "
                                "renders with the current ones")
        moved = [p for p in final.projects if p not in first.projects]  # a project name that uses a moved port
        if moved:
            await _check_projects_free(instance, moved)
            await _check_projects_on_host(remote, instance, moved, [s.key for s in man.secrets], env)
        content = _env_content(template, final)
        for value in final.secret_values:
            sink.hide.add(value)
        await remote.write_text(paths.env_file, content)
        await sink.line(f"Wrote {len(final.written)} value(s) to {paths.env_file} ({len(man.secrets)} of them secret)")
        if job.role == "slot" and live is None:
            await _probe_data_server(c, man)  # before build: nothing has restarted (§6)
        old = dict(instance.app_state or {})
        name = posixpath.basename(run.release)
        releases = dict(old.get("releases") or {})
        releases[name] = sorted(set(releases.get(name) or []) | set(final.images))
        known = list(dict.fromkeys([*app_known_projects(instance), *final.projects]))
        # Only what cleanup and the controls need is saved now (the images this release builds, every project
        # the app may have containers in, the ones this release starts); the rest once the release is live, in
        # the finish step.
        # An app slot's own volumes too (role slot), so a reset or Start over on the data server can delete them
        # although this release never went live (phase 3 §7.3).
        volumes = {str(v.get("name")): v for v in [*(old.get("starting_volumes") or []), *final.volumes]
                   if isinstance(v, dict) and v.get("name")} if job.role == "slot" else {}
        await _save_instance(instance, app_state={**old, "releases": releases, "known_projects": known,
                                                  "starting": list(dict.fromkeys([*(old.get("starting") or []),
                                                                                  *final.projects])),
                                                  **({"starting_volumes": list(volumes.values())} if volumes else {})})
        state = {
            "manifest": man.to_json(), "routes": final.routes, "projects": final.projects,
            "commands": final.commands, "images": final.images, "releases": releases, "known_projects": known,
        }

    c.new = _Side(man=man, plan=final, release=run.release, sha=sha, content=content)
    c.replan = lambda with_secrets: plan_with(host_ports, with_secrets)
    c.template = template
    if live is not None:
        c.live = c.new  # the release being run is the live one: its backup uses this rendering
    reusable = job.retry is not None and job.retry.reusable
    if reusable and live is not None and not _images_per_release(man):
        # Another release may have built images under the same names since (generality 6).
        await sink.line(f"Rebuilding release {sha[:7]}: its images aren't tagged per release (slipway.yml images), so "
                        f"the ones on {instance.host.name} may be another release's")
        reusable = False
    if reusable and await _images_exist(remote, final.images):
        assert job.retry is not None
        await steps.skip("build", f"Reusing the images from deployment {job.retry.id.hex[:8]}")
    elif "build" in final.commands:
        async with steps.step("build"):
            await _app_run(c, c.new, "build")
    else:
        await steps.skip("build", "slipway.yml has no build command")
    run.built = True
    await _pre_start(c)
    async with steps.step("start"):
        # start migrates the data when the app has any: a later job waits for it (lock flag d). An app slot's
        # start migrates the shared database: the data owner's lock says so too while it runs (§7.1).
        holder = await _owner_d_line(c) if job.role == "slot" and "dump" in man.commands else None
        await _app_run(c, c.new, "start", lock_data="dump" in man.commands)
        if holder is not None:
            await _owner_d_line_done(c, holder)
    keys = man.identity_keys()
    # The environment's values, also where the server role writes the line empty (§5.3, I3); a restore may have
    # put other keys back.
    job.identity = data.plan_identity(c.new.plan, keys)
    job.data_app = job.data_app or _declares_data(man)
    await _pre_finish(c)
    # What the release goes live with: data jobs render its commands again from these (D3).
    state["live"] = {
        "release": name, "deployment": made_by.hex, "sha": sha,
        "settings": settings,
        "services": list(chosen) if chosen is not None else None,
        "host_ports": host_ports, "projects": final.projects, "volumes": final.volumes,
        "env_fp": env_fingerprint(instance, env),
        "data_elsewhere": (job.data_elsewhere if job.data_elsewhere is not None
                           else bool((data.live_state(instance) or {}).get("data_elsewhere"))),
    }
    if job.role == "server":
        # The app slots' addresses its database lets in (§6): an app slot is refused until it is one of them.
        state["live"]["clients"] = _clients(job) if live is None else list((live.get("clients") or []))
    return state


# The builtins that make an image name differ from one release to the next.
_PER_RELEASE = frozenset({"slipway.sha", "slipway.sha12", "slipway.release", "slipway.deployment"})
_SLOT = re.compile(r"\{\{|\}\}|\{([^{}]*)\}")  # as manifest.render reads a template: {{ and }} are literal


def images_per_release(images: Iterable[str], variables: dict[str, Any]) -> bool:
    """Whether every ``images`` template names the release (§7.4 image freshness): one of ``_PER_RELEASE``,
    directly or through ``vars`` that do (``serversherpa-api:{STACK_IMAGE_TAG}`` with ``STACK_IMAGE_TAG:
    "{slipway.sha12}"``). Images can't use an instance variable, and a var sees only the vars before it."""
    per: set[str] = set()

    def names_release(template: str) -> bool:
        return any(m.group(1) in _PER_RELEASE or m.group(1) in per for m in _SLOT.finditer(template))

    for key, template in variables.items():
        if names_release(str(template)):
            per.add(str(key))
    refs = [str(i) for i in images]
    return bool(refs) and all(names_release(i) for i in refs)


def _images_per_release(man: manifest.Manifest) -> bool:
    return images_per_release(man.images, man.vars)


def _declares_data(man: manifest.Manifest) -> bool:
    return "dump" in man.commands or bool(man.data.volumes)


# ------------------------------------------------------------- the live release (D3)

LIVE_MARK = "slipway-live: ok"


async def _check_live_release(remote: ssh.RemoteSession, instance: Instance, paths: InstancePaths, name: str) -> str:
    """``current`` must point at the release Slipway recorded as live, and its folder must be there."""
    release = f"{paths.releases}/{name}"
    _, output = await remote.run(f"readlink {q(paths.current)}; [ -d {q(release)} ] && [ ! -L {q(release)} ] && "
                                 f"echo {q(LIVE_MARK)}", check=False, timeout=60)
    lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
    target = next((ln for ln in lines if ln != LIVE_MARK), "")
    if LIVE_MARK not in lines or target.rstrip("/") not in (release, f"releases/{name}"):
        raise DeployError(f"The live release on {instance.host.name} isn't the one Slipway recorded (current points at "
                          f"{target or 'nothing'}); deploy again first.")
    return release


def _live_names_problem(plan: manifest.AppPlan, live: dict[str, Any], sha7: str) -> str | None:
    """The live render must run under the names the release runs with (data-loss 15)."""
    want_projects = [str(p) for p in live.get("projects") or []]
    want_volumes = [str(v.get("name")) if isinstance(v, dict) else str(v) for v in live.get("volumes") or []]
    got_volumes = [v["name"] for v in plan.volumes]
    diff = []
    if plan.projects != want_projects:
        diff.append(f"projects {', '.join(plan.projects) or 'none'} instead of {', '.join(want_projects) or 'none'}")
    if got_volumes != want_volumes:
        diff.append(f"volumes {', '.join(got_volumes) or 'none'} instead of {', '.join(want_volumes) or 'none'}")
    if diff:
        return (f"Release {sha7} would now run under other names ({'; '.join(diff)}) than it runs with; an "
                "environment variable changed them. Put it back, or deploy, then retry.")
    return None


def _slot_identity_problem(job: _Job, plan: manifest.AppPlan, keys: list[str]) -> str | None:
    """A deploy of an app slot whose data is on another instance renders the identity values the shared data
    was made with (``owner.live_identity``), or is refused before anything changes: the slot can't record a new
    value, and the other slot would go on running with the old one on the same data."""
    from slipway.services import jobs  # jobs imports the deployer

    known = job.data_owner.live_identity or {}
    if job.replace_identity:
        return None  # no app has run on the data yet: this deploy's values become the data's at finish
    rendered = data.plan_identity(plan, keys)
    differing = [k for k in keys if k in known and rendered.get(k) != known[k]]
    if differing:
        return jobs.identity_text(job.environment, job.data_owner, differing[0])
    return None


def _put_back_text(instance: Instance, sha7: str, *, shared: bool = False) -> str:
    """The end of a refusal whose identity value differs from the data's. ``shared``: the data is a mode
    ``server`` environment's, which no deploy changes (only a restore of a backup made with the new value)."""
    if shared:
        return (f"(an environment variable changed it since {sha7} went live). The data's value changes only with "
                "a restore of a backup made with the new one: put the variable back, then retry.")
    return (f"(an environment variable of the instance changed since {sha7} went live). Put the variable back, or "
            "deploy, then retry.")


def _shares_data(job: _Job) -> bool:
    return bool(job.member and job.environment is not None and job.environment.data_mode != DataMode.SLOT)


def _identity_problem(instance: Instance, plan: manifest.AppPlan, keys: list[str], sha7: str, *,
                      shared: bool = False) -> str | None:
    """The live render's identity values must be the ones the data was made with (data-loss 4)."""
    known = instance.live_identity or {}
    rendered = data.plan_identity(plan, keys)
    differing = [k for k in keys if k in known and rendered.get(k) != known[k]]
    if differing:
        return (f"{differing[0]} differs from the value {instance.name}'s data was made with "
                + _put_back_text(instance, sha7, shared=shared))
    return None


async def _member_went_live(job: _Job, instance: Instance, state: dict[str, Any]) -> None:
    """At a member's ``finish`` (§9.3): the data owner's identity when it has none yet (from the environment's
    values), the environment's names as this release serves them, and which app slot finished a deploy last
    (the lead slot when nothing is active, D16). Never fails the job, which is live."""
    try:
        async with session_scope() as db:
            env = await db.get(Environment, job.environment.id, with_for_update=True)
            if env is None:
                return
            owner = job.data_owner
            if owner is not instance and job.data_app and job.identity:
                fresh = await db.get(Instance, owner.id)
                if fresh is not None and fresh.live_identity is None:
                    fresh.live_identity = dict(job.identity)
                    owner.live_identity = dict(job.identity)
            if job.kind == DeploymentKind.DEPLOY:
                follows = traffic.SERVER if instance.slot == environments.DATA_SLOT else traffic.ACTIVE
                health = {str(sv.get("name")): sv.get("health") for sv in (state.get("manifest") or {}).get(
                    "services") or [] if isinstance(sv, dict)}
                mine = [{"hostname": r["hostname"], "service": r.get("service"), "container": r.get("container"),
                         "follows": follows, "health": health.get(str(r.get("service"))) or "/"}
                        for r in state.get("routes") or []]
                # A name another member's live release still serves stays (the active slot's, when this was
                # the idle one): DNS and the names other instances can't take follow env.hostnames.
                others = (await environments.members(db, env)).values()
                held = environments.held_names(others, besides=instance.id)
                env.hostnames = environments.refreshed_hostnames(env.hostnames or [], mine, follows=(follows,),
                                                                 held=held)
                if instance.slot in environments.APP_SLOTS:
                    ts = dict(env.traffic_state or {})
                    ts["last_slot_deploy"] = {"slot": instance.slot, "deployment_id": job.deployment_id.hex,
                                              "at": utcnow().isoformat()}
                    env.traffic_state = ts
    except Exception as exc:  # the release is live: recording around it never fails the job
        log.warning("Could not record environment state after deployment %s: %s", job.deployment_id, exc)


def _identity_from_variables(job: _Job) -> dict[str, str]:
    """The identity values a release goes live with that an instance variable sets in place of a different
    stored secret. They become the stored secrets at ``finish``, with ``live_identity``: otherwise removing the
    variable would render the old secret, and every later backup, restore and deploy would refuse it."""
    env, secrets = job.env or {}, job.secrets or {}
    return {k: v for k, v in (job.identity or {}).items() if env.get(k) == v and k in secrets and secrets[k] != v}


async def _backed_up_secrets(instance: Instance, secrets: dict[str, str], keys: Iterable[str]) -> set[str]:
    """Which of ``keys`` a ready backup of the instance holds with its stored secret's value: those can be
    replaced in ``app_secrets``, since restoring that backup brings the old value back with its data."""
    wanted = {k: secrets[k] for k in keys if k in secrets}
    if not wanted:
        return set()
    async with session_scope() as db:
        rows = (await db.scalars(select(Backup.identity).where(
            Backup.instance_id == instance.id, Backup.status == BackupStatus.READY))).all()
    return {k for k, v in wanted.items() if any(isinstance(r, dict) and r.get(k) == v for r in rows)}


def _role(job: _Job, instance: Instance) -> str:
    """How slipway.yml is planned for ``instance`` (§5.3): ``server`` for a data server, ``slot`` for an app slot
    whose data is on one, ``app`` otherwise (standalone instances, mode ``slot``)."""
    if instance.environment_id is None or not job.member:
        return "app"
    if instance.slot == environments.DATA_SLOT:
        return "server"
    return "slot" if job.environment.data_mode == DataMode.SERVER else "app"


async def _live_plan(c: _AppRun, *, deploying: bool = False, write: bool = True) -> _Side:
    """Render the live release's slipway.yml again, with the inputs it went live with (``app_state.live``),
    today's paths, the stored secrets and the instance's variables, and write its ``shared/.env`` (§7.4).

    ``deploying``: the pre-deploy backup of a deploy. An identity value an instance variable changed (set,
    edited or removed) for the new release is then rendered with the value the data was made with (the deploy
    brings in the new one, and the backup keeps the old); any other job refuses, so it never runs the live
    release with keys its data wasn't made with.
    """
    instance, remote, job = c.instance, c.remote, c.job
    host = instance.host.name
    live = data.live_state(instance)
    if live is None:
        raise DeployError(data.not_live_text(instance))
    name = str(live.get("release") or "")
    sha = str(live.get("sha") or "")
    if not _RELEASE_NAME.fullmatch(name) or not _SHA_RE.match(sha):
        raise DeployError(f"Slipway's record of {instance.name}'s live release is damaged; deploy again first.")
    release = await _check_live_release(remote, instance, c.paths, name)
    text = await _read_release_file(remote, release, instance.manifest_file)
    if text is None:
        raise DeployError(f"{instance.manifest_file} of the live release {sha[:7]} can't be read in {release} on {host}; "
                          "deploy again first.")
    try:
        man = manifest.parse(text)
    except manifest.ManifestError as exc:
        raise DeployError(f"The live release {sha[:7]}: {exc}") from exc
    template = None
    if man.env_file:
        template = await _read_release_file(remote, release, man.env_file)
        if template is None:
            raise DeployError(f"The live release {sha[:7]}: env_file {man.env_file} can't be read in {release}")
    env = dict(job.env or {})
    keys = man.identity_keys()
    known = c.owner.live_identity or {}
    role = _role(job, instance)
    role_kw: dict[str, Any] = {}
    if role == "slot":
        role_kw = {"role": role, "data_values": await _data_values(c)}
    elif role == "server":
        role_kw = {"role": role, "server_values": {"host": instance.host.upstream_address,
                                                    "clients": list(live.get("clients") or [])}}

    def render(env: dict[str, str]) -> manifest.AppPlan:
        try:
            return manifest.plan(
                man, template=template,
                builtins=app_builtins(instance, release, sha, uuid.UUID(str(live["deployment"]))),
                settings={str(k): str(v) for k, v in (live.get("settings") or {}).items()},
                chosen=live.get("services"),
                host_ports={str(k): int(v) for k, v in (live.get("host_ports") or {}).items()},
                secrets=dict(job.secrets or {}), env=env, **role_kw,
            )
        except manifest.ManifestError as exc:
            raise DeployError(f"Release {sha[:7]} can't be rendered again for {instance.name}: {exc}") from exc
        except KeyError as exc:
            raise DeployError(f"Release {sha[:7]} needs the secret {exc.args[0]}, which Slipway doesn't have") from exc
        except ValueError as exc:
            raise DeployError(f"Slipway's record of {instance.name}'s live release is damaged ({exc}); deploy again first.") from exc

    plan = render(env)
    problem = _live_names_problem(plan, live, sha[:7])
    if problem:
        raise DeployError(problem)
    rendered = data.plan_identity(plan, keys)
    differing = [k for k in keys if k in known and rendered.get(k) != known[k]]
    if differing:
        if not deploying:
            raise DeployError(f"{differing[0]} differs from the value {instance.name}'s data was made with "
                              + _put_back_text(instance, sha[:7], shared=_shares_data(job)))
        plan = render({**env, **{k: known[k] for k in differing}})
        await c.sink.line(f"Backing up with the {', '.join(differing)} the data was made with; the new value goes "
                          "live with the new release")
    if live.get("env_fp") and live.get("env_fp") != env_fingerprint(instance, env):
        await c.sink.line(f"The instance's environment variables changed since {sha[:7]} went live; Slipway renders "
                          "with the current ones")
    content = _env_content(template, plan)
    for value in plan.secret_values:
        c.sink.hide.add(value)
    if write:
        await remote.write_text(c.paths.env_file, content)
        await c.sink.line(f"Wrote the settings of the live release {sha[:7]} to {c.paths.env_file}")
    return _Side(man=man, plan=plan, release=release, sha=sha, content=content)


# ------------------------------------------------------------------ data steps


async def _pre_start(c: _AppRun) -> None:
    """The listed steps between build and start, in their listed order (correctness 16)."""
    for row in list(c.steps.rows):
        key = row["key"]
        if key not in PRE_START_STEPS:
            continue
        handler = _PRE_START.get(key)
        if handler is None:
            raise DeployError(f"Slipway can't run the step {row['name']!r} for this job yet")
        await handler(c)


async def _post_finish(c: _AppRun) -> None:
    """first_admin, then seed, when listed. Their failures end the step as a warning; the job still succeeds."""
    for row in list(c.steps.rows):
        if row["key"] in POST_FINISH_STEPS and row.get("status") == "pending":
            await _POST_FINISH[row["key"]](c)


async def _outcome_step(c: _AppRun, key: str, body: Callable[[], Awaitable[tuple[str, str | None]]], *,
                        never_fail: bool = False) -> None:
    """Run a step whose body says how it ended: ``("succeeded" | "skipped" | "warning", note)``.

    ``never_fail``: an error ends it as a warning instead of failing the job (the steps after finish, D12).
    """
    await c.steps.begin(key)
    try:
        status, note = await body()
    except Exception as exc:
        if not never_fail:
            await c.steps.end("failed", note=str(exc) or type(exc).__name__)
            raise
        status, note = "warning", str(exc) or type(exc).__name__
    except BaseException:
        await c.steps.end("failed", note="Interrupted")
        raise
    if note and status in ("skipped", "warning"):
        await c.sink.line(f"Warning: {note}" if status == "warning" else note)
    await c.steps.end(status, note=note)


async def _save_options(job: _Job, **values: Any) -> None:
    job.options.update(values)
    async with session_scope() as db:
        await db.execute(update(Deployment).where(Deployment.id == job.deployment_id).values(options=dict(job.options)))


async def _set_backup_id(job: _Job, backup_id: uuid.UUID | None) -> None:
    async with session_scope() as db:
        await db.execute(update(Deployment).where(Deployment.id == job.deployment_id).values(backup_id=backup_id))


BACKUP_REASONS = {
    DeploymentKind.DEPLOY: BackupReason.PRE_DEPLOY, DeploymentKind.RESTORE: BackupReason.PRE_RESTORE,
    DeploymentKind.ROLLBACK: BackupReason.PRE_ROLLBACK, DeploymentKind.RESET: BackupReason.PRE_RESET,
    DeploymentKind.BACKUP: BackupReason.MANUAL,
}


def _backup_files(job: _Job) -> bool:
    """Files are backed up before a reset, before a restore that puts files back, and when "Back up now" asks."""
    if job.kind == DeploymentKind.RESET:
        return True
    return job.kind in (DeploymentKind.RESTORE, DeploymentKind.BACKUP) and bool(job.options.get("files"))


async def _backup_step(c: _AppRun) -> None:
    await _outcome_step(c, "backup", lambda: _backup(c))


async def _backup(c: _AppRun) -> tuple[str, str | None]:
    """The ``backup`` step (§7.5): a verified copy of the data before anything changes it (I1)."""
    job = c.job
    reason = BACKUP_REASONS.get(job.kind, BackupReason.MANUAL)
    if c.steps.listed("reset") and not job.done_by.get("reset"):
        await _reset_precheck(c)  # a foreign volume refuses the reset before anything stops (I4)
    no_new_backup = job.inherited_backup_id is not None or bool(job.options.get("skip_backup"))
    if no_new_backup:
        # The change steps that follow change the app's data: a failure in them leaves it dirty (§8.4, I6).
        job.data_app = job.data_app or _has_declared_data(c)
        if _replacing(job):
            await _refuse_elsewhere(c)  # the probe that refuses it in _backup_with doesn't run (I4)
    checks: str | None = None
    if no_new_backup and job.role == "slot" and c.instance is job.instance and job.kind == DeploymentKind.DEPLOY:
        # No backup reads the revision here, but the revision check and the D7 lag check still run (§7.6).
        checks = await _member_checks(c, await _owner_revision(c))
    if job.inherited_backup_id is not None:
        if job.role == "slot" and c.instance is job.instance:  # the backup is on the data host (§7.2)
            status, note = await _inherited_backup(await c.member(environments.owner_slot(job.environment)))
        else:
            status, note = await _inherited_backup(c)
        return _with_warning(status, note, checks)
    if job.options.get("skip_backup"):
        who = job.user.email if job.user is not None else "someone"
        return _with_warning("warning", f"Skipped on request by {who}: the data is changed without a backup", checks)
    if job.role == "slot" and c.instance is job.instance and job.kind == DeploymentKind.DEPLOY:
        return await _member_backup(c)
    taken = await _take_backup(c, reason, files=_backup_files(job))
    if taken is None:
        return "skipped", "slipway.yml declares no data"
    status, note, _ = taken
    return status, note if status != "succeeded" else None


async def _inherited_backup(c: _AppRun) -> tuple[str, str | None]:
    """A retry of a job that began changing the data keeps that job's pre-change backup (§8.1, D11)."""
    job, instance, host = c.job, c.instance, c.instance.host.name
    async with session_scope() as db:
        row = await db.get(Backup, job.inherited_backup_id)
        if row is None or row.instance_id != instance.id:
            problem: str | None = "gone"
            name = "its backup"
        else:
            name = row.name
            problem = await data.confirm_backup(c.remote, db, row, c.paths.backups, host, files=row.has_files)
            taken_at = _utc_text(row.taken_at)
    if problem is None:
        await _set_backup_id(job, job.inherited_backup_id)
        status, note = "skipped", f"Keeping the backup taken before the first attempt: {name} (taken {taken_at})"
    else:
        await _set_backup_id(job, None)
        status, note = "warning", (f"The backup taken before the first attempt ({name}) is no longer on {host}; a new "
                                   "one now would hold half-changed data, so none is taken.")
    if job.pre_retry:
        since = _utc_text(job.parent_finished_at) if job.parent_finished_at else "the first attempt"
        try:
            again = await _take_backup(c, BackupReason.PRE_RETRY, files=False, sets_dep=False)
        except Exception as exc:
            if job.lock_left:  # its dump may still run: nothing else may run under the lock (§4.5)
                raise
            log.info("pre_retry backup of %s failed: %s", instance.id, c.sink.scrub(str(exc)))
            again = None
            failed = True
        else:
            failed = again is None or again[0] != "succeeded"
        if failed:
            await c.sink.line(f"Warning: The app was started by hand after the first attempt, and its data could not be "
                              f"backed up again: writes since {since} aren't in any backup")
            status = "warning"
    return status, note


def _replacing(job: _Job) -> bool:
    """A job that replaces or deletes the data: restore, roll back, reset, Start over, or seeding from a snapshot."""
    return job.snapshot_id is not None or job.kind in data.RESTORE_KINDS


def _has_declared_data(c: _AppRun) -> bool:
    """Whether the live or the new slipway.yml declares data (a dump command or data volumes)."""
    live = data.live_state(c.instance)
    live_json = data.live_manifest(c.instance) if live is not None else {}
    return ("dump" in (live_json.get("commands") or {}) or bool((live or {}).get("volumes"))
            or (c.new is not None and _declares_data(c.new.man)))


def _elsewhere_text(instance: Instance) -> str:
    return (f"{instance.name}'s data lives outside {instance.host.name} {data.ELSEWHERE_MARK}; Slipway backs it "
            "up but won't restore, reset or seed it yet. Nothing was changed.")


async def _cache_elsewhere(c: _AppRun, elsewhere: bool) -> None:
    """Keep ``app_state.live.data_elsewhere`` as the last probe found it, also when the job then fails (§17)."""
    state = dict(c.instance.app_state or {})
    live = state.get("live")
    if not isinstance(live, dict) or bool(live.get("data_elsewhere")) == elsewhere:
        return
    await _save_instance(c.instance, app_state={**state, "live": {**live, "data_elsewhere": elsewhere}})


async def _refuse_elsewhere(c: _AppRun) -> None:
    """A replacing job whose backup is skipped or inherited still asks ``has_data`` where the data lives: an
    external or shared database is never restored, reset or seeded (D7, I4). Only exit 4 refuses here; the
    data may be half-changed, so any other answer lets the job go on."""
    side = c.new
    if side is None or "has_data" not in side.plan.commands:
        return
    code, _ = await _app_run(c, side, "has_data", check=False)
    if code == 4:
        c.job.data_elsewhere = True
        await _cache_elsewhere(c, True)
        raise DeployError(_elsewhere_text(c.instance))


def _utc_text(at: Any) -> str:
    return at.strftime("%Y-%m-%d %H:%M UTC") if at else "an unknown time"


def _volume_union(*lists: list[Any]) -> list[dict[str, str]]:
    seen: dict[str, dict[str, str]] = {}
    for vols in lists:
        for v in vols or []:
            if isinstance(v, dict) and v.get("name") and str(v["name"]) not in seen:
                seen[str(v["name"])] = {"name": str(v["name"]), "holds": str(v.get("holds") or "other")}
    return list(seen.values())


async def _probe_data(c: _AppRun, side: _Side, volumes: list[dict[str, str]]) -> data.DataProbe:
    """Whether the app has data on the host: ``commands.has_data`` when declared, else the declared volumes."""
    if "has_data" in side.plan.commands:
        code, _ = await _app_run(c, side, "has_data", check=False)
        try:
            return data.has_data_result(code, name=c.instance.name)
        except data.DataError as exc:
            raise DeployError(str(exc)) from None
    if not volumes:
        return data.DataProbe("empty", "slipway.yml declares no volume that holds the database or files")
    _, output = await c.remote.run(data.volume_probe_command(v["name"] for v in volumes), check=False,
                                   timeout=data.PROBE_TIMEOUT)
    try:
        return data.volumes_result(data.parse_volume_probe(output, host=c.instance.host.name), volumes,
                                   host=c.instance.host.name)
    except data.DataError as exc:
        raise DeployError(str(exc)) from None


def _file_args(cmd: dict[str, Any], slot: str, path: str) -> dict[str, Any]:
    """How a file command gets its file: as its ``{slipway.<slot>}`` argument, or on stdout/stdin."""
    return {"stream_path": path} if cmd.get("stream") else {"slots": {slot: path}}


async def _read_small(remote: ssh.RemoteSession, path: str, limit: int) -> str | None:
    """The first ``limit`` bytes of a small file on the host as text (None when it isn't a regular file)."""
    p = q(path)
    status, output = await remote.run(f"[ -f {p} ] && [ ! -L {p} ] && head -c {int(limit)} {p} | od -An -v -tx1",
                                      check=False, timeout=60)
    if status:
        return None
    return read_hex_output(output).decode("utf-8", "replace")


def _last_line(output: str, default: str = "") -> str:
    return next((ln.strip() for ln in reversed(output.splitlines()) if ln.strip()), default)


async def _take_backup(c: _AppRun, reason: str, *, files: bool, sets_dep: bool = True,
                       ) -> tuple[str, str | None, uuid.UUID | None] | None:
    """Back up the data with the live release's commands (D4), or the new release's when the live one has no
    dump. Returns None when neither slipway.yml declares data, else ``(status, note, backup id)``.

    On a deploy the live render writes the live ``.env`` first and the new one is put back afterwards, and the
    new release's ``accepts`` then checks the live data's revision (generality 10).
    """
    job, instance, new = c.job, c.instance, c.new
    live = data.live_state(instance)
    live_json = data.live_manifest(instance) if live is not None else {}
    use_live = live is not None and "dump" in (live_json.get("commands") or {})
    live_volumes = list((live or {}).get("volumes") or [])
    if not _has_declared_data(c):
        await _save_options(job, started_empty=True)
        return None
    job.data_app = True
    rendered_here = False
    if use_live and c.live is not None:
        side = c.live
    elif use_live:
        # A deploy, and a Start over (which deletes the data), back up with the values the data was made with.
        side = await _live_plan(c, deploying=job.kind == DeploymentKind.DEPLOY or job.start_over)
        rendered_here = True
    elif new is not None:
        side = new
    else:
        raise DeployError(data.not_live_text(instance))
    revision: str | None = None
    try:
        result = await _backup_with(c, side, reason, files=files, sets_dep=sets_dep,
                                    volumes=_volume_union(live_volumes, new.plan.volumes if new else []))
        status, note, backup_id, revision = result
        job.revision_before = revision or job.revision_before
    finally:
        if rendered_here and new is not None:
            await c.remote.write_text(c.paths.env_file, new.content)
            await c.sink.line(f"Put back the settings of release {new.sha7}")
    if (job.kind == DeploymentKind.DEPLOY and new is not None and revision and live is not None
            and str(live.get("release")) != posixpath.basename(new.release)
            and {"revision", "accepts"} <= set(new.plan.commands)):
        warning = await _check_new_revision(c, new, revision)
        if warning:
            status, note = "warning", warning if not note else f"{note} {warning}"
    return status, note, backup_id


async def _check_new_revision(c: _AppRun, new: _Side, revision: str) -> str | None:
    """Can the release being deployed run the live data's revision? Refuses before start (I4)."""
    code, output = await _accepts(c, new, revision)
    short = data.revision_short(revision) or "?"
    if code == 0:
        await c.sink.line(f"Release {new.sha7} can run the data at revision {short}")
        return None
    if code == 3:
        why = f"Release {new.sha7} can't run the data at revision {short}: {_last_line(output, 'it says no')}."
        if c.job.options.get("skip_revision_check"):
            return f"{why} Deploying anyway, as asked (Skip the revision check)."
        raise DeployError(f"{why} Nothing was changed. Deploy a commit that can, or deploy with \"Skip the revision check\".")
    raise DeployError(f"The revision check failed (commands.accepts exited {code}). Nothing was changed.")


async def _backup_with(
    c: _AppRun, side: _Side, reason: str, *, files: bool, sets_dep: bool, volumes: list[dict[str, str]],
) -> tuple[str, str | None, uuid.UUID | None, str | None]:
    """Probe, then write and check the backup per §4.2. Returns (status, note, backup id, revision)."""
    job, instance, remote, sink = c.job, c.instance, c.remote, c.sink
    host = instance.host.name
    cmds = side.plan.commands
    probe = await _probe_data(c, side, volumes)
    if probe.state == "elsewhere" and instance.slot == environments.DATA_SLOT and job.member:
        raise DeployError(f"{job.environment.name}'s data server says its data lives elsewhere (commands.has_data exit "
                          "4); data.server.commands.has_data must answer for the server's own database")
    job.data_elsewhere = probe.state == "elsewhere"
    await _cache_elsewhere(c, job.data_elsewhere)  # the queue checks read it, also after this job fails
    replacing = _replacing(job)
    if probe.state == "elsewhere" and replacing:
        raise DeployError(_elsewhere_text(instance))
    if probe.state == "here" and job.snapshot_id is not None and job.never_live and instance.fresh_data is None:
        raise DeployError(await _seeding_over_data(c, probe))
    if probe.state == "empty":
        await _save_options(job, started_empty=True)
        if job.never_live and instance.fresh_data != FreshData.SNAPSHOT:
            await _save_instance(instance, fresh_data=FreshData.EMPTY)
        return "skipped", f"No data yet: {probe.reason}", None, None
    if "dump" not in cmds:
        where = ", ".join(probe.present) or "its volumes"
        if replacing:
            # §7.5 step 7 is for deploys only: a job that deletes or replaces the data needs a copy first (I1).
            verb = "delete" if job.kind == DeploymentKind.RESET else "replace"
            raise DeployError(f"{instance.name} has data on {host} ({where}), and slipway.yml has no dump command, so "
                              f"Slipway can't back it up first. Nothing was changed. To {verb} it anyway, Retry "
                              "without the backup.")
        return "warning", f"slipway.yml has no dump command, so the data in {where} was not backed up", None, None
    if probe.state == "elsewhere":
        await sink.line(f"{probe.reason}: Slipway backs it up, but won't restore, reset or seed it yet")
    dirty = instance.data_dirty or {}
    dirty_first = dirty.get("first") or {}
    if dirty:
        await sink.line(f"The data was changed by failed {data.kind_noun(str(dirty_first.get('kind') or 'job'))} "
                        f"{str(dirty_first.get('deployment_id') or '')[:8]}: this backup holds that state")
    if files and "export_files" not in cmds:
        files = False
    backups = c.paths.backups
    await remote.run(data.prepare_backups_command(backups), timeout=60)

    # Free space (§4.2 step 1): 1.25 × the last backup, or the volumes' sizes, plus the margin.
    async with session_scope() as db:
        last_db, last_files = await data.last_ready_sizes(db, instance.id)
    sizes: dict[str, int] | None = None
    if last_db is None or (files and last_files is None):
        status, output = await remote.run(data.VOLUME_SIZES_COMMAND, check=False, timeout=data.PROBE_TIMEOUT)
        sizes = data.parse_volume_sizes(output) if status == 0 else None
        if sizes is None:
            await sink.line(f"Couldn't read the volumes' sizes on {host} (docker system df -v exited {status})")
    estimate = data.estimate_backup(last_db_bytes=last_db, last_files_bytes=last_files, include_files=files,
                                    volumes=volumes, volume_sizes=sizes)
    for line in estimate.notes:
        await sink.line(line)
    _, output = await remote.run(data.free_space_command(backups), check=False, timeout=data.PROBE_TIMEOUT)
    problem = data.free_space_problem(free_kb=data.parse_free_kb(output), estimate=estimate.bytes,
                                      where=backups, host=host)
    if problem:
        raise DeployError(problem)
    if ram_backed(instance.host, c.paths.base):
        await sink.line(f"Warning: {c.paths.base} is in RAM on {host} (Unraid): backups there are lost when it restarts; "
                        "move the instance's folder under /mnt/user")
    if "data_up" in cmds:
        await _app_run(c, side, "data_up")

    # The row first (pending), so a restart between here and the end leaves a trace (§4.4 unverified).
    keys = side.man.identity_keys()
    rendered = data.plan_identity(side.plan, keys)  # the environment's values, also on a data server (I3)
    known = instance.live_identity or {}
    identity = {k: known.get(k, rendered.get(k)) for k in keys if k in known or k in rendered}
    if keys and instance.live_identity is None:
        await _save_instance(instance, live_identity=dict(rendered))
        await sink.line(f"Recorded {', '.join(keys)} as the {side.man.data.identity_label} {instance.name}'s data is made with")
    for value in identity.values():
        sink.hide.add(value)
    row_id = uuid.uuid4()
    taken_at = utcnow()
    name = data.backup_name(row_id, taken_at)
    async with session_scope() as db:
        db.add(Backup(
            id=row_id, instance_id=instance.id, deployment_id=job.deployment_id, name=name, reason=reason,
            status=BackupStatus.PENDING, format=side.man.data.format or "", has_files=files,
            files_format=side.man.data.files.format if files and side.man.data.files else None,
            commit_sha=instance.current_commit_sha, release=posixpath.basename(side.release)[:64],
            dirty_of=_as_uuid(dirty_first.get("deployment_id")) if dirty else None,
            identity_keys=keys, identity=identity or None, identity_fp=data.identity_fp(row_id, keys, identity),
            created_by_id=job.user.id if job.user is not None else None, taken_at=taken_at,
            # Back up now's note (POST /instances/{id}/backups keeps it in the job's options).
            note=str(job.options.get("note"))[:300] if job.kind == DeploymentKind.BACKUP and job.options.get("note")
            else None,
        ))
    job_dir = data.job_dir(c.paths.base, job.deployment_id)
    partials = {"dump": data.partial_file(backups, name, "dump")}
    if files:
        partials["files"] = data.partial_file(backups, name, "files")
    try:
        await remote.run(f"umask 077 && mkdir -p -- {q(job_dir)}", timeout=60)
        revision = await _read_revision(c, side, job_dir)
        measured: dict[str, tuple[int, str | None]] = {}
        no_hash = False
        for part, command, verify in (("dump", "dump", "verify_dump"), ("files", "export_files", None)):
            if part not in partials:
                continue
            path = partials[part]
            code, _ = await _app_run(c, side, command, check=False, **_file_args(cmds[command], "out", path))
            if code != 0:
                raise _DumpFailed(command, code)
            _, output = await remote.run(data.partial_check_command(path), check=False, timeout=data.HASH_TIMEOUT)
            found = data.parse_file_check(output)
            base = posixpath.basename(path)
            size = found.sizes.get(base)
            if size is None:
                raise DeployError(data.empty_output_message(command, path))
            sha = found.shas.get(base)
            no_hash = no_hash or sha is None
            measured[part] = (size, sha)
            if verify and verify in cmds:
                code, _ = await _app_run(c, side, verify, check=False, **_file_args(cmds[verify], "in", path))
                if code != 0:
                    raise DeployError(f"The backup failed its check (commands.{verify} exited {code}), so Slipway "
                                      "changed nothing; the database is as it was. Fix the cause, then retry.")
            elif verify:
                await sink.line("slipway.yml has no verify_dump: checked only that the dump isn't empty")
        if no_hash:
            await sink.line(data.no_hash_tool_message(host))
        await remote.run(data.finalize_command({p: data.backup_file(backups, name, part) for part, p in partials.items()}),
                         timeout=60)
        db_bytes, db_sha = measured["dump"]
        files_bytes, files_sha = measured.get("files", (None, None))
        async with session_scope() as db:
            row = await db.get(Backup, row_id)
            assert row is not None
            row.status, row.db_bytes, row.db_sha256 = BackupStatus.READY, db_bytes, db_sha
            row.files_bytes, row.files_sha256 = files_bytes, files_sha
            row.revision = revision
            row.finished_at = row.checked_at = utcnow()
            await remote.write_text(data.backup_file(backups, name, "json"), data.sidecar(row, app=side.man.data.app))
    except _DumpFailed as exc:
        await _discard_backup(c, row_id, name)
        if dirty.get("hold"):
            return ("warning", f"The backup failed (commands.{exc.command} exited {exc.code}); the data was left "
                    "half-changed, so it may not be dumpable. Continuing without a backup.", None, None)
        raise DeployError(
            f"The backup failed (commands.{exc.command} exited {exc.code}), so Slipway changed nothing; the database is "
            "as it was. Is the database running? Fix the cause, then retry. If the data can't be backed up, Retry "
            "without the backup.") from None
    except BaseException:
        with contextlib.suppress(Exception):
            await _discard_backup(c, row_id, name)
        raise
    finally:
        with contextlib.suppress(Exception):  # the folder stays while it holds a staged snapshot
            await remote.run(f"rm -f -- {q(job_dir + '/revision.out')}; rmdir -- {q(job_dir)} 2>/dev/null; true",
                             check=False, timeout=60)
    if sets_dep:
        await _set_backup_id(job, row_id)
    size_text = data.human_bytes(db_bytes + (files_bytes or 0))
    await sink.line(f"Backed up the data: {name} ({size_text})")
    async with session_scope() as db:
        fresh = await db.get(Instance, instance.id)
        if fresh is not None:
            await data.apply_retention(remote, db, fresh, backups, just_taken=row_id, say=sink.line)
    return "succeeded", None, row_id, revision


class _DumpFailed(Exception):
    def __init__(self, command: str, code: int) -> None:
        super().__init__(f"commands.{command} exited {code}")
        self.command, self.code = command, code


async def _discard_backup(c: _AppRun, row_id: uuid.UUID, name: str) -> None:
    """A failed backup leaves nothing: its partial files (by their exact names) and its row go."""
    with contextlib.suppress(Exception):
        await c.remote.run(data.discard_partials_command(c.paths.backups, name), check=False, timeout=60)
    async with session_scope() as db:
        await db.execute(delete(Backup).where(Backup.id == row_id))


async def _read_revision(c: _AppRun, side: _Side, job_dir: str) -> str | None:
    """``commands.revision``'s stdout, captured to a file (stderr goes to the log), up to 16 KiB (D6)."""
    if "revision" not in side.plan.commands:
        return None
    out = f"{job_dir}/revision.out"
    code, _ = await _app_run(c, side, "revision", stream_path=out, stream="stdout", check=False)
    text = (await _read_small(c.remote, out, REVISION_MAX_BYTES) or "").strip() if code == 0 else ""
    if not text:
        await c.sink.line(f"Couldn't read the database's revision (exit {code}); the backup is kept without one")
        return None
    await c.sink.line(f"The database is at revision {data.revision_short(text)}")
    return text


# --------------------------------------------------- first admin and starter content (§11.2, §11.3)

_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s.]{2,}$")


def _bad_text(value: str) -> bool:
    return any(unicodedata.category(ch) in ("Cc", "Zl", "Zp") for ch in value)


def first_admin_problem(spec: manifest.FirstAdmin, fields: dict[str, Any], mode: str, password: str | None) -> str | None:
    """What makes a first admin unfit for a release's ``first_admin`` (§11.1), or None."""
    names = {f.name for f in spec.fields}
    if set(fields) != names:
        missing, extra = sorted(names - set(fields)), sorted(set(fields) - names)
        return "; ".join(filter(None, [f"it needs {', '.join(missing)}" if missing else "",
                                       f"it doesn't know {', '.join(extra)}" if extra else ""]))
    for f in spec.fields:
        value = fields[f.name]
        if not isinstance(value, str):
            return f"{f.label} must be text"
        # The raw value is checked: it is what reaches the command (blanks around a text field are dropped).
        if f.kind == "email":
            if (len(value) > min(254, f.max) or not _EMAIL_RE.match(value) or _bad_text(value)
                    or value.startswith("-")):
                return f"{f.label} isn't an email address"
        else:
            text = value.strip()
            if not 1 <= len(text) <= f.max or _bad_text(value) or text.startswith("-"):
                return f"{f.label} must be 1 to {f.max} characters of plain text, not starting with -"
    if mode == "password":
        if spec.password is None:
            return "it can't set a password (invite them instead)"
        least = max(8, spec.password.min_length)
        if password is None or not least <= len(password) <= 1024 or _bad_text(password):
            return f"the password must be {least} to 1024 characters"
    elif mode == "invite":
        if spec.invite is None:
            return "it can't invite by email (set a password instead)"
        if password:
            return "a first admin invited by email has no password"
    else:
        return f"unknown mode {mode!r}"
    return None


def _runs_on_lead(c: _AppRun) -> bool:
    """A data owner job in mode ``server``: the app runs on the lead slot, not on the data server (§7.1)."""
    return c.job.member and c.instance.slot == environments.DATA_SLOT


async def _first_admin_step(c: _AppRun) -> None:
    body = (lambda: _on_lead(c, _first_admin)) if _runs_on_lead(c) else (lambda: _first_admin(c))
    await _outcome_step(c, "first_admin", body, never_fail=True)


async def _first_admin(c: _AppRun) -> tuple[str, str | None]:
    side, instance, job = c.new, c.owner, c.job
    assert side is not None
    again = " Change the first admin on the instance if needed, then Create it now."
    async with session_scope() as db:
        row = await db.scalar(select(FirstAdmin).where(FirstAdmin.instance_id == instance.id))
        if row is None:
            return "skipped", "No first admin to create"
        if row.status == FirstAdminStatus.DONE:
            return "skipped", f"Already created on {row.done_at:%Y-%m-%d}" if row.done_at else "Already created"
        stored = await db.scalar(select(FirstAdmin.password.is_not(None)).where(FirstAdmin.id == row.id))
        row_id, read_at, fields, mode, password = row.id, row.updated_at, dict(row.fields or {}), row.mode, row.password
    spec, planned = side.man.first_admin, side.plan.first_admin
    if spec is None or planned is None:
        return "warning", (f"The first admin doesn't fit release {side.sha7}'s slipway.yml: it declares no first_admin."
                           " Change it on the instance, then Create it now.")
    if mode == "password" and password is None:
        if stored:
            return "warning", ("The first admin's password can't be decrypted with SLIPWAY_ENCRYPTION_KEY; set it again "
                               "on the instance, then Create it now")
        return "warning", "The first admin has no password; set it again on the instance, then Create it now"
    problem = first_admin_problem(spec, fields, mode, password)
    if problem:
        return "warning", (f"The first admin doesn't fit release {side.sha7}'s slipway.yml: {problem}. Change it on the "
                           "instance, then Create it now.")
    if job.lock_left:  # an earlier command may still run, and holds the host lock line (§4.5)
        await _read_left_pid(c.remote, c.instance, job)
        return "warning", f"The first admin wasn't created: {_left_text(c)}. Create it now once it has ended."
    if password:
        c.sink.hide.add(password, min_length=4)
    argv = [*planned["argv"], *(planned["password_args"] if mode == "password" else planned["invite_args"])]
    slots = {f"admin.{k}": str(v).strip() for k, v in fields.items()}  # as first_admin_problem checked them
    env_var = spec.password.env if mode == "password" and spec.password is not None else None
    code, output = await _app_run(
        c, side, "first_admin", cmd={"argv": argv, "stream": None}, slots=slots, check=False,
        input=password + "\n" if mode == "password" and password is not None else None, env_from_stdin=env_var,
    )
    if code in spec.done_codes or code in spec.exists_codes:
        existed = code in spec.exists_codes
        async with session_scope() as db:
            done = await db.execute(
                update(FirstAdmin).where(FirstAdmin.id == row_id, FirstAdmin.updated_at == read_at,
                                         FirstAdmin.status == FirstAdminStatus.PENDING)
                .values(status=FirstAdminStatus.DONE, password=None, done_at=utcnow(),
                        deployment_id=job.deployment_id, existed=existed, last_error=None))
        if not done.rowcount:
            return "warning", "The first admin was changed while it was being created; Create it now to create the new one"
        who = next((str(fields[f.name]) for f in spec.fields if f.kind == "email"), None) or "the first admin"
        if existed:
            return "succeeded", f"An account for {who} already existed in the app; Slipway left it as it is"
        await c.sink.line(f"Created the first admin ({who})")
        return "succeeded", None
    if code == 97 and env_var:
        message = "The first admin's password didn't arrive on stdin."
    else:
        message = spec.messages.get(code) or f"The app's first-admin command failed (exit {code})."
    message = message.rstrip() + again
    async with session_scope() as db:
        await db.execute(update(FirstAdmin).where(FirstAdmin.id == row_id)
                         .values(last_error=clean_text(c.sink.scrub(message))[:300]))
    return "warning", message


async def _seed_step(c: _AppRun) -> None:
    body = (lambda: _on_lead(c, _seed)) if _runs_on_lead(c) else (lambda: _seed(c))
    await _outcome_step(c, "seed", body, never_fail=True)


async def _seed(c: _AppRun) -> tuple[str, str | None]:
    side, instance, job = c.new, c.owner, c.job
    assert side is not None
    if "seed" not in side.plan.commands:
        return "skipped", "slipway.yml has no seed command"
    if job.kind == DeploymentKind.DEPLOY:
        empty = bool(job.options.get("started_empty")) or (job.never_live and instance.fresh_data == FreshData.EMPTY)
        if not instance.seed_content:
            return "skipped", "Starter content is off for this instance"
        if not empty:
            return "skipped", "The app already had data: starter content is only added after an empty start"
    if job.lock_left:  # first_admin timed out and may still run: it keeps the host lock line (§4.5)
        await _read_left_pid(c.remote, c.instance, job)
        await _save_instance(instance, content_pending=True)
        return "warning", f"The starter content wasn't added: {_left_text(c)}. Add starter content once it has ended."
    code, _ = await _app_run(c, side, "seed", check=False)
    if code:
        await _save_instance(instance, content_pending=True)
        return "warning", f"commands.seed exited {code}: the starter content may be missing. Add starter content to try again."
    return "succeeded", None


# ------------------------------------------- restore, roll back, reset and seeding (§7.5)

STAGE_HEADROOM = 512 * 1024 * 1024  # free space a staged snapshot needs on the host beyond its own size
STAGE_DEPTH = 8  # pieces in flight between the decrypting thread and the upload


def _refuse(text: str) -> DeployError:
    """A check step's refusal: it comes before anything changed (I4)."""
    return DeployError(f"{text.rstrip('.')}. Nothing was changed.")


async def _done_by_first(c: _AppRun, key: str) -> bool:
    """A retry doesn't repeat a data step the attempt it retries finished (§8.1): skip it, and say so."""
    by = c.job.done_by.get(key)
    if not by or not c.steps.listed(key):
        return False
    _, row = c.steps._row(key)
    row["done_by"] = by
    await c.steps.skip(key, f"Done by the first attempt ({by[:8]}); not repeated")
    return True


async def _snapshot_name(snapshot_id: uuid.UUID | None) -> str:
    async with session_scope() as db:
        snap = await db.get(Snapshot, snapshot_id) if snapshot_id is not None else None
    return snap.name if snap is not None else "(deleted)"


async def _seeding_over_data(c: _AppRun, probe: data.DataProbe) -> str:
    """The refusal to seed a new instance over data its host already has (§7.5 backup step 6)."""
    name = await _snapshot_name(c.job.snapshot_id)
    where = ", ".join(probe.present) or probe.reason
    volumes = " ".join(probe.present) or "<volume>"
    return (f"{c.instance.host.name} already has data for this app ({where}). Seeding from snapshot {name} would "
            f"replace it: deploy without the snapshot, then Reset data from it, or remove the volumes (docker volume "
            f"rm {volumes}) to start afresh.")


async def _accepts(c: _AppRun, side: _Side, revision: str) -> tuple[int, str]:
    """Run ``side``'s ``accepts`` on a revision Slipway writes to a 0600 file (D6)."""
    job_dir = data.job_dir(c.paths.base, c.job.deployment_id)
    path = f"{job_dir}/revision"
    await c.remote.run(f"umask 077 && mkdir -p -- {q(job_dir)}", timeout=60)
    await c.remote.write_text(path, revision)
    try:
        return await _app_run(c, side, "accepts", check=False, **_file_args(side.plan.commands["accepts"], "in", path))
    finally:
        with contextlib.suppress(Exception):  # the folder goes too unless it holds a staged snapshot
            await c.remote.run(f"rm -f -- {q(path)}; rmdir -- {q(job_dir)} 2>/dev/null; true", check=False, timeout=60)


async def _lead_accepts(c: _AppRun, side: _Side, revision: str) -> tuple[int, str, str] | None:
    """``accepts`` for a restore kind: the release that will run the data next (§7.1). On a data server that is
    the lead slot's live release, on its host (None when no app slot runs, or none was deployed); otherwise the
    job's own release. Returns (exit code, output, the release's sha7)."""
    if not _runs_on_lead(c):
        code, output = await _accepts(c, side, revision)
        return code, output, side.sha7
    lead = _lead_of(c.job)  # the slot start_slots will start (one that runs now)
    if lead is None:
        return None
    m = await c.member(str(lead.slot))
    lead_side = await _live_plan(m, write=False)
    if "accepts" not in lead_side.plan.commands:
        return None
    code, output = await _accepts(m, lead_side, revision)
    return code, output, f"{lead_side.sha7} on {lead.slot}"


async def _remove_job_dir(remote: ssh.RemoteSession, instance: Instance, job: _Job) -> None:
    """The job's own work folder in ``backups/.incoming`` (a staged snapshot, an export) goes at the end."""
    if not (job.restore_from.get("staged") or job.exported) or job.lock_left:
        return  # a command that may still run reads it: the next job's first step empties .incoming
    with contextlib.suppress(Exception):
        await remote.run(f"rm -rf -- {q(data.job_dir(paths_for(instance).base, job.deployment_id))}", check=False,
                         timeout=600)


async def _check_step(c: _AppRun) -> None:
    body = _check_snapshot if c.job.snapshot_id is not None else _check_backup
    await _outcome_step(c, "check", lambda: body(c))


async def _check_backup(c: _AppRun) -> tuple[str, str | None]:
    """Restore and roll back: the backup passes §9.2, is on the host unchanged, and the live release can run it."""
    job, instance, side, sink = c.job, c.instance, c.new, c.sink
    assert side is not None
    host, cmds, label = instance.host.name, side.plan.commands, side.man.data.identity_label
    files = bool(job.options.get("files"))
    async with session_scope() as db:
        row = None
        if job.restore_backup_id is not None:
            row = await db.scalar(select(Backup).where(Backup.id == job.restore_backup_id,
                                                       Backup.instance_id == instance.id))
        if row is None:
            raise _refuse("The backup to restore was deleted")
        dirty_job = await db.get(Deployment, row.dirty_of) if row.dirty_of is not None else None
        rule = data.restorable(instance, row, dirty_job=dirty_job, env=dict(job.env or {}))
        if not rule.ok:
            raise _refuse(rule.reason or "The backup can't be restored")
        if files and not row.has_files:
            raise _refuse(f"The backup {row.name} has no files")
        if files and "import_files" not in cmds:
            raise _refuse(f"Release {side.sha7} can't import files (no commands.import_files)")
        problem = await data.confirm_backup(c.remote, db, row, c.paths.backups, host, files=files)
        if problem:
            raise _refuse(problem)
        name, revision = row.name, row.revision
    await sink.line(f"The backup {name} is on {host}, unchanged since Slipway took it")
    if rule.dirty_note:
        await sink.line(f"This backup: {rule.dirty_note}")
    if {"revision", "accepts"} <= set(cmds) and revision:
        short = data.revision_short(revision)
        found = await _lead_accepts(c, side, revision)
        if found is None:
            none = "is running" if _deployed_apps(job) else "has been deployed yet"
            await sink.line(f"No app slot {none}: nothing checks the backup's revision")
        else:
            code, output, sha7 = found
            if code == 3:
                raise _refuse(f"Release {sha7} can't open a database at revision {short}: {_last_line(output, 'it says no')}")
            if code:
                raise _refuse(f"The revision check failed (commands.accepts exited {code})")
            await sink.line(f"Release {sha7} can open the database at revision {short}")
    elif "accepts" in cmds:
        await sink.line(f"The backup {name} has no revision; Slipway can't check it against release {side.sha7}")
    else:
        await sink.line(f"Slipway can't check this backup's revision against release {side.sha7} (slipway.yml has no "
                        "accepts command)")
    override = dict(rule.override)
    if override and job.kind == DeploymentKind.ROLLBACK:
        raise _refuse(f"The backup from before the failed deploy was made with other {label}; restore it from the "
                      "Backups card instead")
    if override and not job.options.get("restore_identity"):
        raise _refuse(f"This backup was made with other {label}; restoring it puts them back. Restore it again with "
                      f"\"Put back its {label}\" (needs data:reset)")
    for value in override.values():
        sink.hide.add(value)
    job.override = override
    job.restore_from = {"database": data.backup_file(c.paths.backups, name, "dump"),
                        "files": data.backup_file(c.paths.backups, name, "files") if files else None,
                        "name": name, "source": f"backup {name}"}
    return "succeeded", None


async def _check_snapshot(c: _AppRun) -> tuple[str, str | None]:
    """A seeding deploy or a reset from a snapshot: every check before anything stops, then the staging (I4)."""
    job, instance, side, sink, remote = c.job, c.instance, c.new, c.sink, c.remote
    assert side is not None
    host, man, cmds = instance.host.name, side.man, side.plan.commands
    if job.kind == DeploymentKind.DEPLOY:
        probe = await _probe_data(c, side, side.plan.volumes)
        if probe.state == "elsewhere":
            raise _refuse(f"{instance.name}'s data lives outside {host} (commands.has_data says so); Slipway won't seed it")
        if probe.state == "here" and instance.fresh_data is None:
            raise DeployError(await _seeding_over_data(c, probe))
    async with session_scope() as db:
        snap = await db.get(Snapshot, job.snapshot_id) if job.snapshot_id is not None else None
        if snap is None:
            raise _refuse("The snapshot was deleted")
        if snap.status != SnapshotStatus.READY:
            raise _refuse(f"Snapshot {snap.name} isn't ready ({snap.status})")
        try:
            key = snapshots.data_key(snap)
        except snapshots.SnapshotsError as exc:
            raise _refuse(exc.message) from None
        name, repository, app, app_name = snap.name, snap.repository, snap.app, snap.app_name
        db_format, db_revision, db_bytes = snap.db_format, snap.db_revision, int(snap.db_bytes or 0)
        files_format, files_bytes = snap.files_format, int(snap.files_bytes or 0)
    repo = instance.repository.full_name
    if repository != repo and not (job.user is not None and job.user.can(Perm.SNAPSHOTS_DOWNLOAD)):
        raise _refuse(f"Snapshot {name} was made from {repository or 'an unknown repository'}; seeding {instance.name} "
                      f"({repo}) from it needs the snapshots:download permission")
    if app != man.data.app:
        raise _refuse(f"This snapshot is of app {app} ({app_name}); {instance.name} runs {man.data.app}")
    if db_format != man.data.format:
        raise _refuse(f"The snapshot's database is in format {db_format}; release {side.sha7} restores {man.data.format}")
    if "restore" not in cmds:
        raise _refuse(f"Release {side.sha7}'s slipway.yml has no restore command")
    files_label = (man.data.files.label if man.data.files else "files").lower()
    if files_format:
        if man.data.files is None or files_format != man.data.files.format:
            wanted = man.data.files.format if man.data.files else "no files"
            raise _refuse(f"The snapshot's files are in format {files_format}; release {side.sha7} imports {wanted}")
        if "import_files" not in cmds:
            raise _refuse(f"The snapshot has {files_label}, and release {side.sha7} can't import files "
                          "(no commands.import_files)")
    else:
        await sink.line(f"The snapshot has no files; {files_label} start empty")
    if {"revision", "accepts"} <= set(cmds) and db_revision:
        short = data.revision_short(db_revision)
        code, output = await _accepts(c, side, db_revision)
        if code == 3:
            raise _refuse(f"Release {side.sha7} can't open a database at revision {short}: {_last_line(output, 'it says no')}")
        if code:
            raise _refuse(f"The revision check failed (commands.accepts exited {code})")
        await sink.line(f"Release {side.sha7} can open the database at revision {short}")
    elif "accepts" not in cmds:
        await sink.line(f"Slipway can't check the snapshot's revision against release {side.sha7} (slipway.yml has no "
                        "accepts command)")
    # Free space for the staged copy.
    await remote.run(data.prepare_backups_command(c.paths.backups), timeout=60)
    _, output = await remote.run(data.free_space_command(c.paths.backups), check=False, timeout=data.PROBE_TIMEOUT)
    free_kb = data.parse_free_kb(output)
    need = db_bytes + files_bytes + STAGE_HEADROOM
    if free_kb is None or free_kb * 1024 < need:
        free = data.human_bytes(free_kb * 1024) if free_kb is not None else "an unknown amount of space"
        raise _refuse(f"Only {free} is free in {c.paths.backups} on {host}; the snapshot needs about "
                      f"{data.human_bytes(need)}")
    assert job.snapshot_id is not None
    async with snapshots.transfer(on_wait=lambda: sink.line("Waiting for another snapshot transfer to finish")):
        job.restore_from = {"staged": True}  # the job's folder holds what was staged: removed at the end
        contents, staged = await _stage_snapshot(c, job.snapshot_id, key)
    await sink.line(f"Copied snapshot {name} to {host} and checked it ({data.human_bytes(db_bytes + files_bytes)})")
    # Identity (§9.3): the snapshot's values for the release's identity keys that it has.
    keys = man.identity_keys()
    values = contents.identity or {}
    warnings = []
    for k in keys:
        if k not in values:
            warnings.append(f"The snapshot has no {k} (release {side.sha7} marks it as identity); the instance keeps "
                            f"its own. Anything in the snapshot's data that needed the source's {k} can't be read here.")
    extra = sorted(set(values) - set(keys))
    if extra:
        await sink.line(f"The snapshot also has {', '.join(extra)}, which release {side.sha7} doesn't use; Slipway "
                        "ignores them")
    override = {k: values[k] for k in keys if k in values}
    for value in override.values():
        sink.hide.add(value)
    try:
        data.check_override(override, man.to_json(), source="snapshot")
    except data.DataError as exc:
        raise _refuse(str(exc)) from None
    env = job.env or {}
    pinned = sorted(k for k in override if k in env and env[k] != override[k])
    if pinned:
        raise _refuse(data.env_pin_message(pinned[0], source="snapshot"))
    job.override = override
    job.restore_from = {"database": staged["database"], "files": staged.get("files"), "name": name,
                        "source": f"snapshot {name}", "snapshot": True, "staged": True}
    return ("warning", " ".join(warnings)) if warnings else ("succeeded", None)


class _Stopped(Exception):
    """The staging gave up (the upload failed): the decrypting thread stops."""


async def _stage_snapshot(c: _AppRun, snapshot_id: uuid.UUID, key: bytes) -> tuple[snapfile.SnapshotContents, dict[str, str]]:
    """Decrypt the stored ``.sbx`` in a thread through the validator (§10.3) and upload its members as they come
    to ``.incoming/job-<d8>/{database,files}`` (0600). Each member's checksum is checked in transit by the
    validator and again on the host before it gets its final name."""
    remote, host = c.remote, c.instance.host.name
    job_dir = data.job_dir(c.paths.base, c.job.deployment_id)
    await remote.run(f"umask 077 && mkdir -p -- {q(job_dir)}", timeout=60)
    path = snapshots.bundle_path(snapshot_id)
    pieces: queue.Queue[tuple[str, str | None, Any]] = queue.Queue(STAGE_DEPTH)
    stop = threading.Event()
    max_bytes = get_settings().snapshot_max_bytes

    def put(item: tuple[str, str | None, Any]) -> None:
        while True:
            if stop.is_set():
                raise _Stopped
            try:
                pieces.put(item, timeout=0.1)
                return
            except queue.Full:
                continue

    def sink(name: str, chunk: bytes | None) -> None:
        put(("chunk", name, chunk) if chunk is not None else ("done", name, None))

    def work() -> None:
        try:
            contents = snapfile.validate(snapfile.open_container(path, key), max_bytes=max_bytes, sink=sink)
            put(("end", None, contents))
        except _Stopped:
            pass
        except BaseException as exc:  # handed to the event loop, which raises it
            with contextlib.suppress(_Stopped):
                put(("error", None, exc))

    async def get() -> tuple[str, str | None, Any]:
        while True:
            try:
                return await asyncio.to_thread(pieces.get, True, 0.5)
            except queue.Empty:
                if worker.done():
                    raise DeployError("Slipway couldn't read the stored snapshot") from None

    worker = asyncio.ensure_future(asyncio.to_thread(work))
    staged: dict[str, str] = {}
    on_host: dict[str, str | None] = {}
    contents: snapfile.SnapshotContents | None = None
    try:
        item = await get()
        while contents is None:
            kind, name, value = item
            if kind == "error":
                if isinstance(value, SnapshotError | OSError):
                    raise _refuse(f"The stored snapshot can't be used: {value}")
                raise value
            if kind == "end":
                contents = value
                break
            assert name in (snapfile.DATABASE, snapfile.FILES)
            partial = f"{job_dir}/{name}.partial"
            after: list[tuple[str, str | None, Any]] = []

            async def member(first: tuple[str, str | None, Any], name: str = name,
                             after: list[tuple[str, str | None, Any]] = after) -> AsyncIterator[bytes]:
                item = first
                while True:
                    kind, which, value = item
                    if kind == "chunk" and which == name:
                        yield value
                    elif kind == "done" and which == name:
                        return
                    else:  # an error part-way: the upload ends here, and the error is raised below
                        after.append(item)
                        return
                    item = await get()

            await remote.write_stream(partial, member(item))
            if after:
                item = after[0]
                continue
            # The validator matched the member's size and checksum in transit; the host's copy must match too.
            _, output = await remote.run(data.sha_command(partial), check=False, timeout=data.HASH_TIMEOUT)
            staged[name] = partial
            on_host[name] = data.parse_sha(output)
            item = await get()
        assert contents is not None
        if snapfile.DATABASE not in staged:
            raise _refuse("The snapshot has no database")
        for name in list(staged):
            entry = contents.manifest["database" if name == snapfile.DATABASE else "files"]
            if on_host.get(name) and on_host[name] != entry["sha256"]:
                raise _refuse(f"The snapshot's {name} changed while it was copied to {host}")
            final = f"{job_dir}/{name}"
            await remote.run(f"mv -f -- {q(staged[name])} {q(final)}", timeout=60)
            staged[name] = final
        return contents, staged
    finally:
        stop.set()
        with contextlib.suppress(BaseException):
            await worker


async def _stop_step(c: _AppRun) -> None:
    async with c.steps.step("stop"):
        if c.job.kind in data.DATA_ONLY_KINDS:
            await _control(c, "stop")
        else:
            await _stop_app(c)


async def _stop_app(c: _AppRun) -> None:
    """Stop the release with its own ``stop``, then what a failed release left running (§7.5 stop)."""
    side, instance, remote, sink = c.new, c.instance, c.remote, c.sink
    assert side is not None
    host = instance.host.name
    c.data_up = False  # the release's stop may stop the data services too (ss-stack down does)
    if "stop" in side.plan.commands:
        await _app_run(c, side, "stop")
    else:
        await sink.line(f"Release {side.sha7}'s slipway.yml has no stop command")
    for project in (instance.app_state or {}).get("starting") or []:
        project = str(project)
        if project in side.plan.projects or not manifest.PROJECT_RE.match(project):
            continue
        command = f"(cd / && docker compose -p {q(project)} down --remove-orphans)"
        await sink.line(f"$ {command}")
        await remote.run(command, on_line=sink.line, scrub=sink.scrub, timeout=side.man.timeout("stop"))
    if not side.plan.projects:
        return
    check = "; ".join(f"docker ps -q --filter {_project_filter(p)} || exit 1" for p in side.plan.projects)
    status, output = await remote.run(check, check=False, timeout=60)
    if status:
        raise DeployError(f"Couldn't check that {instance.name} stopped on {host} (docker ps exited {status}); "
                          "nothing was deleted or restored")
    running = _container_ids(output)
    if running:
        raise DeployError(f"Containers of {instance.name} are still running on {host} ({', '.join(running[:5])}); "
                          "nothing was deleted or restored")


async def _control(c: _AppRun, action: str) -> None:
    """Data-only jobs stop and start the app's containers as they are (D17), never with slipway.yml's own
    stop or start (``ss-stack down`` removes containers, ``up`` migrates)."""
    command = control_command(c.instance, action)
    await c.sink.line(f"$ {command}")
    await c.remote.run(command, on_line=c.sink.line, scrub=c.sink.scrub, timeout=600)


def _locked(c: _AppRun, key: str, command: str) -> str:
    """A shell command of Slipway's own that changes data, under the host lock with its own PID (§4.5)."""
    return f"{{ {data.lock_line_command(c.paths.lock, c.job.deployment_id, key, data=True)} && exec {command}; }}"


async def _probe_volumes(c: _AppRun) -> data.VolumeProbe:
    assert c.new is not None
    names = [v["name"] for v in c.new.plan.volumes]
    if not names:
        return data.VolumeProbe(present={}, absent=[])
    _, output = await c.remote.run(data.volume_probe_command(names), check=False, timeout=data.PROBE_TIMEOUT)
    try:
        return data.parse_volume_probe(output, host=c.instance.host.name)
    except data.DataError as exc:
        raise DeployError(str(exc)) from None


def _own_projects(c: _AppRun) -> list[str]:
    assert c.new is not None
    return list(dict.fromkeys([*app_known_projects(c.instance), *c.new.plan.projects]))


async def _reset_precheck(c: _AppRun) -> None:
    """Before anything stops (I4, I5): a reset deletes only volumes of the app's own Compose projects. In mode
    ``server`` that holds on each app slot's host too, for its slot-local volumes (phase 3 §7.3)."""
    problem = data.foreign_volume((await _probe_volumes(c)).present, _own_projects(c))
    if problem:
        raise DeployError(problem)
    for m, names in await _slot_local_volumes(c):
        problem = data.foreign_volume((await _probe_named(m, names)).present, app_known_projects(m.instance))
        if problem:
            raise DeployError(problem)


async def _slot_local_volumes(c: _AppRun) -> list[tuple[_AppRun, list[str]]]:
    """A reset on the data server of a mode ``server`` environment also deletes each deployed app slot's own
    volumes (``data.volumes`` minus ``data.server.volumes``, as the slot's live release rendered them, §7.3)."""
    job = c.job
    if not (job.member and job.environment.data_mode == DataMode.SERVER and c.instance.slot == environments.DATA_SLOT):
        return []
    found = []
    for inst in _deployed_apps(job):
        # The live release's, and those of a deploy that failed after it (or before any went live: Start over).
        listed = [*((data.live_state(inst) or {}).get("volumes") or []),
                  *((inst.app_state or {}).get("starting_volumes") or [])]
        names = list(dict.fromkeys(str(v.get("name") if isinstance(v, dict) else v) for v in listed))
        if names:
            found.append((await c.member(str(inst.slot)), names))
    return found


async def _probe_named(m: _AppRun, names: list[str]) -> data.VolumeProbe:
    _, output = await m.remote.run(data.volume_probe_command(names), check=False, timeout=data.PROBE_TIMEOUT)
    try:
        return data.parse_volume_probe(output, host=m.instance.host.name)
    except data.DataError as exc:
        raise DeployError(str(exc)) from None


async def _reset_slot_volumes(c: _AppRun, m: _AppRun, names: list[str]) -> None:
    """Delete an app slot's own volumes on its host (stopped by ``stop_slots``): its projects are taken down
    first, since Docker keeps a volume a stopped container uses. Only its own labels (I5)."""
    job, sink, slot, host = c.job, c.sink, str(m.instance.slot), m.instance.host.name
    probe = await _probe_named(m, names)
    own = app_known_projects(m.instance)
    problem = data.foreign_volume(probe.present, own)
    if problem:
        raise DeployError(problem)
    present = [n for n in names if n in probe.present]
    if not present:
        await sink.line(f"{slot} on {host} has no data of its own to delete")
        return
    for project in own:
        command = f"(cd / && docker compose -p {q(project)} down --remove-orphans)"
        await sink.line(f"$ {command}")
        await m.remote.run(command, on_line=sink.line, scrub=sink.scrub, timeout=600)
    # Its containers are gone: start_slots must start it with its live start, or leave it stale.
    await _save_options(job, slots_downed=[*(job.options.get("slots_downed") or []), slot])
    shown = f"docker volume rm -- {' '.join(q(v) for v in present)}"
    await sink.line(f"$ {shown}")
    try:
        code, output = await m.remote.run(_locked(m, "reset", shown), check=False, on_line=sink.line,
                                          scrub=sink.scrub, timeout=data.VOLUME_RM_TIMEOUT)
    except (ssh.SSHError, asyncio.CancelledError):
        job.lock_left = "reset"
        raise
    left = [n for n in present if n in (await _probe_named(m, present)).present]
    if code or left:
        which = left[0] if left else present[0]
        raise DeployError(f"Could not delete {which} on {host}: {_last_line(output, f'docker volume rm exited {code}')}")
    await sink.line(f"Deleted {slot}'s own data on {host}: {', '.join(present)}")


async def _reset_step(c: _AppRun) -> None:
    if await _done_by_first(c, "reset"):
        return
    async with c.steps.step("reset"):
        await _reset(c)


async def _reset(c: _AppRun) -> None:
    """Delete the app's data volumes: only names Slipway rendered, only with the app's own label (I5)."""
    job, instance, side, remote, sink = c.job, c.instance, c.new, c.remote, c.sink
    assert side is not None
    host, cmds = instance.host.name, side.plan.commands
    if "has_data" in cmds:
        code, _ = await _app_run(c, side, "has_data", check=False)
        if code == 4:
            raise DeployError(f"{instance.name}'s data lives outside {host} (commands.has_data says so); Slipway can only "
                              "reset data in volumes it can delete.")
    names = [v["name"] for v in side.plan.volumes]
    probe = await _probe_volumes(c)
    own = _own_projects(c)
    problem = data.foreign_volume(probe.present, own)
    if problem:
        raise DeployError(problem)
    c.data_up = False
    for project in own:
        command = f"(cd / && docker compose -p {q(project)} down --remove-orphans)"
        await sink.line(f"$ {command}")
        await remote.run(command, on_line=sink.line, scrub=sink.scrub, timeout=side.man.timeout("stop"))
    present = [n for n in names if n in probe.present]
    if present:
        shown = f"docker volume rm -- {' '.join(q(v) for v in present)}"
        await _refuse_while_left(c, shown)
        await sink.line(f"$ {shown}")
        try:
            code, output = await remote.run(_locked(c, "reset", shown), check=False, on_line=sink.line, scrub=sink.scrub,
                                            timeout=data.VOLUME_RM_TIMEOUT)
        except (ssh.SSHError, asyncio.CancelledError):
            job.lock_left = "reset"
            raise
        if code:
            after = await _probe_volumes(c)
            which = next((n for n in present if n in after.present), present[0])
            raise DeployError(f"Could not delete {which}: {_last_line(output, f'docker volume rm exited {code}')}")
    left = [n for n in names if n in (await _probe_volumes(c)).present]
    if left:
        raise DeployError(f"Reset ran, but {left[0]} is still on {host}")
    await sink.line(f"Deleted the data: {', '.join(present)}" if present else "There was no data to delete")
    for m, slot_names in await _slot_local_volumes(c):
        await _reset_slot_volumes(c, m, slot_names)
    if "has_data" in cmds:
        code, _ = await _app_run(c, side, "has_data", check=False)
        if code != 3:
            raise DeployError(f"Reset ran, but commands.has_data still finds data (it exited {code})")
    await _save_options(job, started_empty=True)
    if job.start_over:
        # The instance starts again as new: its next deploy is an empty start, and the first admin is made again.
        await _save_instance(instance, fresh_data=FreshData.EMPTY)
        async with session_scope() as db:
            await db.execute(update(FirstAdmin).where(FirstAdmin.instance_id == instance.id).values(
                status=FirstAdminStatus.PENDING, done_at=None, existed=False, deployment_id=None))


async def _restore_step(c: _AppRun) -> None:
    if await _done_by_first(c, "restore"):
        return
    async with c.steps.step("restore"):
        await _restore(c)


async def _restore(c: _AppRun) -> None:
    job, side, sink = c.job, c.new, c.sink
    assert side is not None
    source = job.restore_from
    cmds = side.plan.commands
    if not source.get("database"):
        raise DeployError("Slipway has nothing to restore (the check step found nothing)")
    if "restore" not in cmds:
        raise DeployError(f"Release {side.sha7}'s slipway.yml has no restore command")
    await _data_up_after_stop(c, side)
    code, _ = await _app_run(c, side, "restore", check=False, **_file_args(cmds["restore"], "in", source["database"]))
    if code:
        async with session_scope() as db:
            before_id = await db.scalar(select(Deployment.backup_id).where(Deployment.id == job.deployment_id))
            before = await db.get(Backup, before_id) if before_id is not None else None
        another = f" (the one taken just before is {before.name})" if before is not None else ""
        raise DeployError(f"commands.restore exited {code}: the database may be empty or half-restored, and the app is "
                          f"stopped. Retry this job, or restore another backup{another}.")
    await sink.line(f"Restored the database from {source['source']}")
    await _apply_override(c)


async def _apply_override(c: _AppRun) -> None:
    """After a restore that succeeded, and only then (I3): the identity keys the data was made with come back,
    in ``.env``, ``app_secrets`` and ``live_identity`` together."""
    job, instance, side, sink = c.job, c.instance, c.new, c.sink
    assert side is not None
    source = job.restore_from
    override = {k: v for k, v in job.override.items() if (job.secrets or {}).get(k) != v
                or (instance.live_identity or {}).get(k) != v}
    if override:
        assert c.replan is not None
        secrets = {**(job.secrets or {}), **override}
        plan = c.replan(secrets)
        content = _env_content(c.template, plan)
        await c.remote.write_text(c.paths.env_file, content)
        c.new = replace(side, plan=plan, content=content)
        if c.live is side:
            c.live = c.new
        job.secrets = secrets
        keys = side.man.identity_keys()
        effective = {**(instance.live_identity or {}), **data.plan_identity(plan, keys)}
        now = utcnow()
        fields = {"app_secrets": secrets, "live_identity": effective, "identity_changed_at": now,
                  "identity_source": _fit(Instance, "identity_source", str(source["source"]))}
        async with session_scope() as db:
            if job.member:
                # The environment's secrets (bumping secrets_version) and the owner's identity, in one
                # transaction (§6 Identity, I3); the data server's .env keeps the keys blank.
                env = job.environment
                result = await db.execute(
                    update(Environment).where(Environment.id == env.id,
                                              Environment.secrets_version == job.secrets_version)
                    .values(app_secrets=secrets, secrets_version=Environment.secrets_version + 1)
                    .execution_options(synchronize_session=False))
                if result.rowcount != 1:
                    raise DeployError(f"{env.name}'s secrets changed while this job ran; retry it")
                fields.pop("app_secrets")
            await db.execute(update(Instance).where(Instance.id == instance.id).values(**fields))
            audit.record(db, "instance.identity_secrets", actor=job.user, target=instance,
                         summary=f"{', '.join(sorted(override))} of {instance.name} now come from {source['source']}",
                         details={"keys": sorted(override), "source": source["source"]})
        if job.member:
            job.secrets_version += 1
            job.environment.app_secrets = secrets
            await _save_options(job, identity_changed=True)
        for key, value in fields.items():
            setattr(instance, key, value)
        help_text = side.man.data.identity_help
        await sink.line(f"{', '.join(sorted(override))} now come from {source['source']}."
                        + (f" {help_text}" if help_text else ""))
    if job.never_live and source.get("snapshot"):
        await _save_instance(instance, fresh_data=FreshData.SNAPSHOT)


async def _data_up_after_stop(c: _AppRun, side: _Side) -> None:
    """Start the data services for restore, import_files and after_import (§3.1), once after the app stopped: a
    retry that skips the restore as done still needs them for the files."""
    if "data_up" in side.plan.commands and not c.data_up:
        await _app_run(c, side, "data_up")
        c.data_up = True


async def _files_step(c: _AppRun) -> None:
    if await _done_by_first(c, "files"):
        return
    await _outcome_step(c, "files", lambda: _files(c))


async def _files(c: _AppRun) -> tuple[str, str | None]:
    side, source = c.new, c.job.restore_from
    assert side is not None
    path = source.get("files")
    if not path:
        return "skipped", ("The snapshot has no files" if source.get("snapshot") else "This restore doesn't put the "
                           "files back")
    cmds = side.plan.commands
    if "import_files" not in cmds:
        raise DeployError(f"Release {side.sha7} can't import files (no commands.import_files)")
    await _data_up_after_stop(c, side)
    code, _ = await _app_run(c, side, "import_files", check=False, **_file_args(cmds["import_files"], "in", path))
    if code:
        raise DeployError(f"commands.import_files exited {code}: some files may be missing. Retry this job.")
    return "succeeded", None


async def _after_import_step(c: _AppRun) -> None:
    if await _done_by_first(c, "after_import"):
        return
    await _outcome_step(c, "after_import", lambda: _after_import(c))


async def _after_import(c: _AppRun) -> tuple[str, str | None]:
    side = c.new
    assert side is not None
    if not c.job.restore_from.get("snapshot"):
        return "skipped", "Only after a snapshot is restored"
    if "after_import" not in side.plan.commands:
        return "skipped", "slipway.yml has no after_import command"
    await _data_up_after_stop(c, side)
    code, _ = await _app_run(c, side, "after_import", check=False)
    if code:
        raise DeployError(f"commands.after_import exited {code}: the imported data may not be ready. Retry this job.")
    return "succeeded", None



# ------------------------------------------------------- environment members (phase 3 §6, §7)


def _refuse_moved_ports(job: _Job, instance: Instance, host_ports: dict[str, int]) -> None:
    """A data server deploy may not move a port the app slots' settings name (§9.7): refused before ``start``."""
    live = data.live_state(instance) or {}
    old = {str(k): int(v) for k, v in (live.get("host_ports") or {}).items() if str(v).isdigit()}
    moved = [f"{k} {old[k]} → {host_ports[k]}" for k in sorted(old) if k in host_ports and host_ports[k] != old[k]]
    if moved:
        raise DeployError(f"The data server's ports would move ({', '.join(moved)}), and the slots' settings name "
                          f"the old ones: free the port on {instance.host.name}, or recreate the slots")


async def _probe_data_server(c: _AppRun, man: manifest.Manifest) -> None:
    """Sign in to the data server's database from the app slot's host before anything restarts (§6). Only
    ``postgres`` needs are probed; an ``s3`` one goes through Switchyard."""
    job = c.job
    attach = man.data.attach
    if attach is None or not job.data_values:
        return
    for need, kind in attach.needs.items():
        if kind != "postgres" or need not in job.data_values:
            continue
        v = job.data_values[need]
        try:
            port = int(v.get("port") or 0)
        except ValueError:
            raise DeployError(f"{job.environment.name}'s data server gave {need} the port {v.get('port')!r}") from None
        await c.sink.line(f"Checking that {c.instance.slot} can sign in to {job.environment.name}'s database at "
                          f"{v.get('host')}:{port}")
        problem = await traffic.probe_database(
            c.remote, c.instance, env_name=job.environment.name, host=str(v.get("host")), port=port,
            database=str(v.get("database")), user=str(v.get("user")), password=str(v.get("password") or ""),
            sslmode=str(v.get("tls") or "disable"), scrub=c.sink.scrub)
        if problem:
            raise DeployError(problem)
        await c.sink.line("It signed in")


HOLDER_MARK = "slipway-holder:"


async def _owner_d_line(c: _AppRun) -> tuple[_AppRun, str] | None:
    """While an app slot's ``start`` migrates the shared database, the data owner's host lock carries a ``d`` line
    for this job (§7.1), so the owner's next job waits for it as for any data command left running. The line
    names a holder on the data host (a ``sleep`` as long as ``start`` may take), since the command itself runs
    on another host; killing the holder lets the owner's jobs run again."""
    owner = await c.member(environments.owner_slot(c.job.environment))
    assert c.new is not None
    seconds = max(60, int(c.new.man.timeout("start")))
    lock = owner.paths.lock
    command = ("BOOT=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || printf '%s\\n' -); "
               f"nohup sleep {seconds} >/dev/null 2>&1 & pid=$!; "
               f"printf '%s %s %s %s %s\\n' {q(str(c.job.deployment_id))} \"$BOOT\" \"$pid\" start d > {q(lock)} && "
               f"echo \"{HOLDER_MARK} $pid\"")
    _, output = await owner.remote.run(command, timeout=60)
    pid = next((ln.split()[-1] for ln in output.splitlines() if ln.startswith(HOLDER_MARK)), "")
    await c.sink.line(f"Marked {owner.instance.host.name}'s lock while {c.instance.slot}'s start migrates the database")
    return owner, pid


async def _owner_d_line_done(c: _AppRun, held: tuple[_AppRun, str]) -> None:
    """``start`` returned: the owner's lock names this job again without ``d``. A ``start`` that may still run
    (timed out, cut off) keeps the line."""
    owner, pid = held
    if c.job.lock_left:
        await c.sink.line(f"{owner.instance.host.name}'s lock keeps the mark: {c.instance.slot}'s start may still run")
        return
    kill = f"kill {int(pid)} 2>/dev/null; " if pid.isdigit() else ""
    with contextlib.suppress(Exception):
        await owner.remote.run(kill + data.lock_line_command(owner.paths.lock, c.job.deployment_id, c.job.kind,
                                                              data=False), check=False, timeout=60)


async def _pre_finish(c: _AppRun) -> None:
    """The listed steps between start and finish (§8.4 PRE_FINISH_STEPS)."""
    for row in list(c.steps.rows):
        if row["key"] in PRE_FINISH_STEPS and row.get("status") == "pending":
            await _PRE_FINISH[row["key"]](c)


def _deployed_apps(job: _Job) -> list[Instance]:
    """The app slots a data job on the shared database stops (D16, I8): each that went live, and each whose
    deploy failed after its release was written, whose containers may run (``app_projects``, §9.14)."""
    return [m for m in environments.app_members(job.members) if m.current_commit_sha or app_projects(m)]


def _was_running(job: _Job, m: Instance) -> bool:
    """Whether a data job starts an app slot again afterwards: it is RUNNING and not stale, or (for a restore,
    roll back or reset, which start the lead with its live ``start``) the failed data job before this one
    stopped it and didn't start it again (``data_dirty.last.slots_stopped``). A snapshot only compose-starts
    the containers as they were, with no ``start``, so it starts only slots that were running: after a reset
    whose ``start`` failed the data is new, and the old containers may not accept it."""
    if environments.stale_of(m):
        return False
    if m.status == InstanceStatus.RUNNING:
        return True
    if job.kind not in data.RESTORE_KINDS:
        return False
    last = (job.data_owner.data_dirty or {}).get("last") or {}
    return str(m.slot) in [str(s) for s in last.get("slots_stopped") or []]


def _lead_of(job: _Job, were: dict[str, str] | None = None) -> Instance | None:
    """The lead slot (D16), chosen only from the deployed app slots that were running (``were``: the statuses
    ``stop_slots`` recorded): the active one, or else the one deployed last. None when none was running."""
    def runs(m: Instance) -> bool:
        if not m.current_commit_sha:
            return False
        if were is not None:
            return were.get(str(m.slot)) == InstanceStatus.RUNNING and not environments.stale_of(m)
        return _was_running(job, m)

    lead = environments.lead_slot(job.environment, job.members)
    if lead is not None and lead.slot in environments.APP_SLOTS and runs(lead):
        return lead
    running = [m for m in environments.app_members(job.members) if runs(m)]
    return max(running, key=lambda m: m.last_deployed_at or utcnow()) if running else None


def _slot_names(slots: Iterable[str], one: str, many: str) -> str:
    names = [str(s).capitalize() for s in slots]
    return f"{' and '.join(names)} {one if len(names) == 1 else many}"


async def _stop_slots_step(c: _AppRun) -> None:
    await _outcome_step(c, "stop_slots", lambda: _stop_slots(c))


async def _stop_slots(c: _AppRun) -> tuple[str, str | None]:
    """Stop every app slot that may run before a data job replaces the shared data (D16, I8). Each host is
    reached first, and the lead slot's live render checked, so a refusal fails the step before anything stops
    (I5). ``slots_were`` records what each slot goes back to: ``running`` for one that ran (``_was_running``),
    else its status. A stop that fails or is cut off part-way starts again what it stopped."""
    job = c.job
    apps = _deployed_apps(job)
    if not apps:
        return "skipped", "No app slot has been deployed yet"
    were = {str(m.slot): str(InstanceStatus.RUNNING) if _was_running(job, m) else str(m.status) for m in apps}
    lead = _lead_of(job, were)
    runs = [await c.member(str(m.slot)) for m in apps]
    if lead is not None and job.kind in data.RESTORE_KINDS and not job.start_over:
        await _lead_precheck(c, await c.member(str(lead.slot)))
    # A retry carries its parent's options: what this job started, and how its lead failed, are its own.
    await _save_options(job, slots_were=were, lead=str(lead.slot) if lead is not None else None, slots_started=[],
                        start_error=None)
    before = {str(m.instance.slot): str(m.instance.status) for m in runs}
    stopped: list[_AppRun] = []
    try:
        for m in runs:
            command = _app_projects_command(m.instance, "stop")
            await c.sink.line(f"$ {command}")
            try:
                await m.remote.run(command, on_line=c.sink.line, scrub=c.sink.scrub, timeout=600)
            finally:
                stopped.append(m)  # also a stop that failed or was cut off part-way: some of it may be stopped
            await _save_instance(m.instance, status=InstanceStatus.STOPPED)
            await c.sink.line(f"Stopped {m.instance.slot} on {m.instance.host.name}")
    except Exception as exc:
        error = (str(exc) or type(exc).__name__).rstrip(".")
        back, left = await _start_again(c, stopped, before)
        if left:
            raise DeployError(f"{error}. {data.stopped_text(left)}: start {'it' if len(left) == 1 else 'them'} "
                              "again on the instance page") from None
        if back:
            raise DeployError(f"{error}. Slipway started {' and '.join(s.capitalize() for s in back)} again; nothing "
                              "was changed") from None
        raise
    except BaseException:
        await _start_again(c, stopped, before)  # cut off (a shutdown): what it stopped runs again, as before
        raise
    return "succeeded", None


def _left_down(options: dict[str, Any]) -> list[str]:
    """The app slots a data job stopped while they ran and didn't start again (``slots_were``, ``slots_started``):
    the ones its dirty state and hold text name, and the next data job starts again (``_was_running``)."""
    started = {str(s) for s in options.get("slots_started") or []}
    return [str(s) for s, status in (options.get("slots_were") or {}).items()
            if status == InstanceStatus.RUNNING and str(s) not in started]


async def _start_again(c: _AppRun, reached: list[_AppRun], before: dict[str, str]) -> tuple[list[str], list[str]]:
    """After a ``stop_slots`` that failed or was cut off: start again each slot it reached that was RUNNING when
    the step began, and give the others back the status they had. A slot stopped before (by the failed job
    this one follows, say) stays stopped. Returns (the slots started again, those left stopped); never raises."""
    job = c.job
    back: list[str] = []
    left: list[str] = []
    for m in reached:
        slot = str(m.instance.slot)
        was_stopped = m.instance.status == InstanceStatus.STOPPED  # this job saved it STOPPED (or it was)
        try:
            if before.get(slot) != InstanceStatus.RUNNING:
                if before.get(slot):
                    await _save_instance(m.instance, status=before[slot])
                continue
            await _compose_start(c, m)
            await _save_options(job, slots_started=[*(job.options.get("slots_started") or []), slot])
            back.append(slot)
            await c.sink.line(f"Started {slot} again")
        except Exception as exc:
            if was_stopped:
                left.append(slot)
            with contextlib.suppress(Exception):
                await c.sink.line(f"Couldn't start {slot} again: {exc}")
    return back, left


async def _lead_precheck(c: _AppRun, lead: _AppRun) -> None:
    """Before anything stops (I5): the lead slot's live render as ``start_slots`` will make it (the data server
    lets its host in, the data values, the identity keys, the names, the secrets), so a refusal there comes
    while the app still runs."""
    job = c.job
    try:
        await _live_plan(lead, write=False)
    except DeployError as exc:
        raise _refuse(f"{lead.instance.slot} couldn't start again after the {data.kind_noun(job.kind)} "
                      f"({str(exc).rstrip('.')})") from None
    finally:
        job.data_values = None  # start_slots renders them again, with the secrets as they are then


async def _start_slots_step(c: _AppRun) -> None:
    await _outcome_step(c, "start_slots", lambda: _start_slots(c))


async def _compose_start(c: _AppRun, m: _AppRun) -> None:
    command = _app_projects_command(m.instance, "start")
    await c.sink.line(f"$ {command}")
    await m.remote.run(command, on_line=c.sink.line, scrub=c.sink.scrub, timeout=600)
    await _save_instance(m.instance, status=InstanceStatus.RUNNING)


async def _mark_stale(instance: Instance, reason: str, job: _Job) -> None:
    state = dict(instance.slot_state or {})
    state["stale"] = {"reason": reason, "at": utcnow().isoformat(), "deployment_id": job.deployment_id.hex}
    await _save_instance(instance, slot_state=state)


async def _start_slots(c: _AppRun) -> tuple[str, str | None]:
    """Start the app slots again before the owner's ``finish`` (D16, I9). The lead slot gets its live render with
    the current data values and secrets, then its live ``start`` (it migrates). The other one is started as it
    was only when it runs the lead's commit and the identity keys didn't change; otherwise it stays stopped and
    is marked stale. A snapshot starts both as they were.

    Only a slot that was running before the job (``slots_were``) and isn't stale is started: one that was
    stopped stays stopped (and becomes stale if it couldn't have been started), one that is stale keeps its
    mark, and one whose deploy failed (any other status) is marked stale, since its containers may be that
    failed release (§9.14)."""
    job = c.job
    were = dict(job.options.get("slots_were") or {})
    if not were:
        return "skipped", "No app slot has been deployed yet"
    started: list[str] = list(job.options.get("slots_started") or [])

    def ran(slot: str) -> bool:
        return were.get(slot) == InstanceStatus.RUNNING and not environments.stale_of(job.members[slot])

    if job.kind == DeploymentKind.SNAPSHOT:
        kept: list[str] = []
        for slot in were:
            if slot in started:
                continue
            if not ran(slot):
                kept.append(slot)
                continue
            await _compose_start(c, await c.member(slot))
            started.append(slot)
            await _save_options(job, slots_started=started)
        if kept:
            return "succeeded", f"{_slot_names(kept, 'stays', 'stay')} stopped, as before the snapshot"
        return "succeeded", None
    env = job.environment
    noun = data.kind_noun(job.kind)
    lead_slot = str(job.options.get("lead") or "")
    lead: _AppRun | None = None
    if lead_slot in were and ran(lead_slot):
        lead = await c.member(lead_slot)
        job.data_values = None  # rendered again with the secrets as they are now
        try:
            side = await _live_plan(lead)
            await _app_run(lead, side, "start", lock_data=True)
        except Exception as exc:
            error = _last_line(exc.output, str(exc)) if isinstance(exc, ssh.CommandFailed) else (str(exc) or type(exc).__name__)
            error = clean_text(c.sink.scrub(error))[:200]
            await _save_options(job, start_error={"slot": lead_slot, "error": error})
            raise DeployError(f"{lead_slot} didn't start again after the {noun} ({error}); "
                              f"{data.stopped_text(_left_down(job.options))}") from None
        lead.new = lead.live = job.lead_side = side
        await _save_instance(lead.instance, status=InstanceStatus.RUNNING)
        started.append(lead_slot)
        await _save_options(job, slots_started=started)
        await c.sink.line(f"Started {lead_slot} again with its live release {side.sha7}")
    changed = bool(job.options.get("identity_changed"))
    failed_slot = await _rolled_back_slot(job)
    stale: list[str] = []
    kept = []
    for slot in were:
        if (slot == lead_slot and lead is not None) or slot in started:
            continue
        other = job.members[slot]
        if environments.stale_of(other):
            kept.append(slot)  # it keeps its mark: deployed again first (D16, D17)
            continue
        downed = slot in (job.options.get("slots_downed") or [])  # a reset removed its containers and volumes
        fits = (lead is not None and other.current_commit_sha == lead.instance.current_commit_sha and not changed
                and slot != failed_slot and not downed and were.get(slot) in (InstanceStatus.RUNNING,
                                                                               InstanceStatus.STOPPED))
        if fits and ran(slot):
            await _compose_start(c, await c.member(slot))
            started.append(slot)
            await _save_options(job, slots_started=started)
        elif fits:
            kept.append(slot)  # stopped before the job, and it could run on the data: it stays as it was
        else:
            await _mark_stale(other, f"Stopped when {env.name}'s data was {_restored_word(job.kind)}; deploy to it "
                                     "before activating it", job)
            stale.append(slot)
    notes: list[str] = []
    if lead is None:
        notes.append(f"No app slot was running before the {noun}, so none was started")
    if stale:
        notes.append(f"{', '.join(stale)} stays stopped: deploy to it before activating it")
    if kept:
        notes.append(f"{', '.join(kept)} stays stopped, as before the {noun}")
    return "succeeded", "; ".join(notes) or None


async def _rolled_back_slot(job: _Job) -> str | None:
    """A roll back of a failed slot deploy: that slot (it stays stopped and stale, D17)."""
    if job.kind != DeploymentKind.ROLLBACK:
        return None
    first = (job.data_owner.data_dirty or {}).get("first") or {}
    dep_id = _as_uuid(job.options.get("rollback_of")) or _as_uuid(first.get("deployment_id"))
    if dep_id is None:
        return None
    async with session_scope() as db:
        dep = await db.get(Deployment, dep_id)
    found = next((m for m in job.members.values() if dep is not None and m.id == dep.instance_id), None)
    return str(found.slot) if found is not None and found.slot in environments.APP_SLOTS else None


def _restored_word(kind: str) -> str:
    return {DeploymentKind.RESET: "reset", DeploymentKind.ROLLBACK: "rolled back"}.get(kind, "restored")


async def _smoke_step(c: _AppRun) -> None:
    await _outcome_step(c, "smoke", lambda: _smoke(c), never_fail=True)


async def _env_now(job: _Job) -> tuple[Any, dict[str, Instance]]:
    async with session_scope() as db:
        env = await db.get(Environment, job.environment.id)
        assert env is not None
        return env, await environments.members(db, env)


async def _smoke_one(c: _AppRun, target: _AppRun, env: Any, mem: dict[str, Instance]) -> traffic.CheckResult:
    planned = traffic.routes(env, target.instance, environments.owner_in(env, mem))
    check = await traffic.smoke(target.remote, target.instance, planned, say=c.sink.line)
    await traffic.save_last_check(target.instance.id, check, c.job.deployment_id)
    return check


async def _smoke(c: _AppRun) -> tuple[str, str | None]:
    """A member deploy's slot smoke test (§10.8), a warning when it fails (P2 D12). An app slot checks itself and,
    when its migration moved the shared database, the active slot too; a data server deploy checks the active
    slot (its database may have restarted under it)."""
    job = c.job
    env, mem = await _env_now(job)
    active = environments.active_member(env, mem)
    if c.instance.slot == environments.DATA_SLOT:
        if active is None:
            return "skipped", "Nothing is live to check"
        target = await c.member(str(active.slot))
        target.instance = active
        check = await _smoke_one(c, target, env, mem)
        if not check.ok:
            return "warning", f"{active.slot}: {check.message} after the data server restarted"
        return "succeeded", None
    c.instance = mem.get(str(c.instance.slot), c.instance)
    check = await _smoke_one(c, c, env, mem)
    notes: list[str] = []
    status = "succeeded" if check.ok else "warning"
    if not check.ok:
        notes.append(check.message)
    moved = await _migration_note(c, env, active)
    if moved is not None:
        text, other = moved
        notes.append(text)
        if other is not None and not other.ok:
            status = "warning"
            notes.append(f"{active.slot}: {other.message}")
    return status, " ".join(notes) or None


async def _migration_note(c: _AppRun, env: Any, active: Instance | None
                          ) -> tuple[str, traffic.CheckResult | None] | None:
    """With ``migrations: expand_contract``, when this slot's start moved the database's revision, the active
    slot keeps running on it: say so and check it too (§7.4 smoke)."""
    job = c.job
    if (c.new is None or c.new.man.data.migrations != "expand_contract" or active is None
            or active.id == c.instance.id or not job.revision_before or job.environment.data_mode != DataMode.SERVER):
        return None
    owner = await c.member(environments.owner_slot(job.environment))
    side = owner.live or await _live_plan(owner, write=False)
    job_dir = data.job_dir(owner.paths.base, job.deployment_id)
    await owner.remote.run(f"umask 077 && mkdir -p -- {q(job_dir)}", timeout=60)
    try:
        after = await _read_revision(owner, side, job_dir)
    finally:
        with contextlib.suppress(Exception):
            await owner.remote.run(f"rm -f -- {q(job_dir + '/revision.out')}; rmdir -- {q(job_dir)} 2>/dev/null; true",
                                   check=False, timeout=60)
    if not after or after == job.revision_before:
        return None
    text = (f"Migrated the database from {data.revision_short(job.revision_before)} to {data.revision_short(after)}; "
            f"{active.slot} ({str(active.current_commit_sha or '')[:7]}) keeps running on it")
    other = await c.member(str(active.slot))
    async with session_scope() as db:
        fresh = await db.get(Environment, env.id)
        mem = await environments.members(db, fresh)
    other.instance = mem.get(str(active.slot), other.instance)
    return text, await _smoke_one(c, other, fresh, mem)


async def _dns_step(c: _AppRun) -> None:
    await _outcome_step(c, "dns", lambda: _dns(c), never_fail=True)


async def _dns(c: _AppRun) -> tuple[str, str | None]:
    """A data server deploy publishes every route's record at the fixed address (§7.4, D24); never fails it."""
    env, _ = await _env_now(c.job)
    if not (env.traffic or {}).get("dns"):
        return "skipped", f"{env.name} publishes no DNS records"
    await traffic.publish_dns(env, c.sink.line, actor=c.job.user)
    return "succeeded", None


async def _traffic_step(c: _AppRun) -> None:
    await _outcome_step(c, "traffic", lambda: _traffic(c), never_fail=True)


async def _traffic(c: _AppRun) -> tuple[str, str | None]:
    """A member's ``traffic`` step (§7.4), in place of ``proxy``: a sync that never moves a name to another slot
    (I6). The data server and the data owner's jobs sync the names that follow the data server; an app slot
    syncs every name only while it is the active one."""
    job, instance = c.job, c.instance
    async with session_scope() as db:
        env = await db.get(Environment, job.environment.id)
        assert env is not None
        if (env.traffic or {}).get("switch", "none") == "none":
            return "skipped", f"{env.name} doesn't publish its names through Switchyard"
        mem = await environments.members(db, env)
        active = environments.active_member(env, mem)
        slot = str(instance.slot)
        if slot == environments.DATA_SLOT:
            include_active = False
        elif active is None:
            if job.options.get("go_live"):
                return "skipped", "Nothing is live yet; Activate follows"
            return "skipped", f"Nothing is live yet; activate {slot} to publish it"
        elif active.id != instance.id:
            return "skipped", f"Traffic stays on {active.slot}; activate {slot} to move it"
        elif environments.unresolved_text(env):
            return "skipped", "Traffic may be split between the slots; resolve it first"
        else:
            include_active = True
        ctx = await traffic.context(db, env, "sync", include_active=include_active, deployment_id=job.deployment_id,
                                    say=c.sink.line, connect=job.connect)
    result = await traffic.sync(ctx)
    if result.skipped:
        return "skipped", result.skipped
    if result.warnings:
        return "warning", "; ".join(result.warnings)
    return "succeeded", None


async def _member_backup(c: _AppRun) -> tuple[str, str | None]:
    """An app slot's pre-deploy backup in mode ``server`` (§7.2): the data server's live release dumps the shared
    data on its own host (D4); then this release's ``accepts`` runs on the revision here, and, with an active
    slot, the active slot's live ``accepts`` (the lag check, §7.6). Both refuse before ``start``."""
    job = c.job
    owner = await c.member(environments.owner_slot(job.environment))
    taken = await _take_backup(owner, BackupReason.PRE_DEPLOY, files=False)
    if taken is None:
        return "skipped", "slipway.yml declares no data"
    status, note, backup_id = taken
    if backup_id is not None:
        await _set_backup_id(job, backup_id)
    status, note = _with_warning(status, note, await _member_checks(c, job.revision_before))
    return status, note if status != "succeeded" else None


def _with_warning(status: str, note: str | None, warning: str | None) -> tuple[str, str | None]:
    if not warning:
        return status, note
    return "warning", warning if not note else f"{note} {warning}"


async def _member_checks(c: _AppRun, revision: str | None) -> str | None:
    """An app slot deploy's checks on the shared database's revision before its ``start`` (§7.6): this release's
    ``accepts``, then the active slot's (the D7 lag check). Both refuse; a warning comes back as text."""
    new = c.new
    if not revision or new is None or not {"revision", "accepts"} <= set(new.plan.commands):
        return None
    warning = await _check_new_revision(c, new, revision)
    await _lag_check(c, revision)
    return warning


async def _owner_revision(c: _AppRun) -> str | None:
    """The shared database's revision, read with the data server's live release on its host, without a dump
    (a slot deploy whose backup is skipped or kept from the first attempt)."""
    job = c.job
    owner = await c.member(environments.owner_slot(job.environment))
    if data.live_state(owner.instance) is None:
        return None
    side = owner.live or await _live_plan(owner, write=False)
    job_dir = data.job_dir(owner.paths.base, job.deployment_id)
    await owner.remote.run(f"umask 077 && mkdir -p -- {q(job_dir)}", timeout=60)
    try:
        revision = await _read_revision(owner, side, job_dir)
    finally:
        with contextlib.suppress(Exception):
            await owner.remote.run(f"rm -f -- {q(job_dir + '/revision.out')}; rmdir -- {q(job_dir)} 2>/dev/null; true",
                                   check=False, timeout=60)
    job.revision_before = revision or job.revision_before
    return revision


async def _lag_check(c: _AppRun, revision: str) -> None:
    """Expand/contract holds between adjacent releases (D7, §7.6): before the idle slot's ``start``, the active
    slot's live release must still accept the database's revision, unless the deploy was confirmed past it."""
    job = c.job
    active = environments.active_member(job.environment, job.members)
    if active is None or active.id == c.instance.id or active.slot not in environments.APP_SLOTS:
        return
    m = await c.member(str(active.slot))
    side = await _live_plan(m, write=False)
    if "accepts" not in side.plan.commands:
        return
    code, output = await _accepts(m, side, revision)
    short = data.revision_short(revision) or "?"
    if code == 0:
        await c.sink.line(f"{active.slot} ({side.sha7}) can run the data at revision {short} too")
        return
    if code != 3:
        raise DeployError(f"The revision check of {active.slot} failed (commands.accepts exited {code}). Nothing was "
                          "changed.")
    if job.options.get("behind_ok"):
        await c.sink.line(f"Warning: {active.slot} ({side.sha7}) already runs on a database migrated past it; "
                          "deploying anyway, as confirmed")
        return
    by = next((m2 for m2 in environments.app_members(job.members) if m2.id != active.id), c.instance)
    raise DeployError(
        f"{active.slot} ({side.sha7}) already runs on a database migrated past it (revision {short}, by {by.slot}'s "
        f"{str(by.current_commit_sha or '')[:7]}). A new release may remove what {active.slot} still uses. Activate "
        f"{by.slot} again and deploy to {active.slot}, or deploy again confirming that this release removes nothing "
        f"{active.slot} uses.")


async def _on_lead(c: _AppRun, body: Callable[[_AppRun], Awaitable[tuple[str, str | None]]]
                   ) -> tuple[str, str | None]:
    """A data owner job's first admin or starter content in mode ``server``: on the lead slot, with the live
    render ``start_slots`` gave it (§7.1). Create it now and Add starter content (kinds ``admin`` and
    ``content``, no ``start_slots``) run on the active slot, or with none on the lead slot, with its live render
    (§7.3)."""
    job = c.job
    lead_slot = job.options.get("lead")
    if lead_slot and job.lead_side is not None:
        lead = await c.member(str(lead_slot))
        lead.new = job.lead_side
        return await body(lead)
    if job.kind not in (DeploymentKind.ADMIN, DeploymentKind.CONTENT):
        return "skipped", "No app slot runs the app to do it in"
    found = environments.lead_slot(job.environment, job.members)
    if found is None or found.slot not in environments.APP_SLOTS or not found.current_commit_sha:
        return "skipped", "No app slot runs the app to do it in"
    if found.status != InstanceStatus.RUNNING or environments.stale_of(found):
        return "warning", f"{found.slot} isn't running: start it, then try again"
    lead = await c.member(str(found.slot))
    lead.new = lead.live = await _live_plan(lead, write=False)
    await _save_options(job, lead=str(found.slot))
    return await body(lead)


_PRE_FINISH: dict[str, Callable[[_AppRun], Awaitable[None]]] = {"start_slots": _start_slots_step}

_PRE_START: dict[str, Callable[[_AppRun], Awaitable[None]]] = {
    "check": _check_step, "backup": _backup_step, "stop": _stop_step, "reset": _reset_step, "restore": _restore_step,
    "files": _files_step, "after_import": _after_import_step, "stop_slots": _stop_slots_step,
}
_POST_FINISH: dict[str, Callable[[_AppRun], Awaitable[None]]] = {
    "first_admin": _first_admin_step, "seed": _seed_step, "smoke": _smoke_step, "dns": _dns_step,
    "traffic": _traffic_step,
}


# ---------------------------------------------------------------- data-only jobs (§7.5)


async def _data_job(job: _Job, sink: LogSink, steps: Steps, connect: ConnectFactory) -> None:
    """Back up now, take a snapshot, create the first admin, add starter content: with the live release as it
    runs (no build, no proxy). These jobs never change the instance's status (§7.1)."""
    instance = job.instance
    if instance.build_source != BuildSource.APP or data.live_state(instance) is None:
        raise DeployError(data.not_live_text(instance))
    if job.env is None:
        raise DeployError(_env_unreadable(job))
    async with contextlib.AsyncExitStack() as stack:
        await sink.line(f"Connecting to {instance.host.username}@{instance.host.address}")
        remote = await stack.enter_async_context(connect(ssh.SSHTarget.from_host(instance.host)))
        c = _AppRun(remote=remote, instance=instance, job=job, sink=sink, steps=steps, paths=paths_for(instance))
        job.ctx = c
        job.data_app = True
        try:
            async with steps.step("release"):
                if job.kind == DeploymentKind.SNAPSHOT:
                    # Taken before the app stops, so a stopped app never waits for a transfer slot (data-loss 10).
                    await stack.enter_async_context(snapshots.transfer(
                        on_wait=lambda: sink.line("Waiting for another snapshot transfer to finish")))
                await _take_dir(remote, instance, sink)
                await _acquire_lock(remote, instance, job, sink)
                c.live = c.new = await _live_plan(c)
                job.identity = dict(instance.live_identity or {}) or None
            if job.kind == DeploymentKind.BACKUP:
                await _backup_step(c)
            elif job.kind == DeploymentKind.SNAPSHOT:
                await _snapshot_steps(c)
            elif job.kind == DeploymentKind.ADMIN:
                await _first_admin_step(c)
            elif job.kind == DeploymentKind.CONTENT:
                await _seed_step(c)
            else:
                raise DeployError(f"Slipway can't run {data.kind_label(job.kind)} jobs this way")
        except asyncio.CancelledError:
            _mark_cut_off(job)
            raise
        finally:
            if steps.status("restop") == "pending" and job.lock_held:
                # The app was stopped: what data_up started stops again, whatever happened (D17).
                await _outcome_step(c, "restop", lambda: _control_outcome(c, "stop"), never_fail=True)
            await _remove_job_dir(remote, instance, job)
            await c.close_members()
            await _release_lock(remote, instance, job, sink)


async def _control_outcome(c: _AppRun, action: str) -> tuple[str, str | None]:
    await _control(c, action)
    return "succeeded", None


async def _snapshot_steps(c: _AppRun) -> None:
    """stop (when asked), export, start again, store: the app runs again before the copy to Slipway (§7.5)."""
    job = c.job
    try:
        stopping = c.steps.listed("stop")
        slots = c.steps.listed("stop_slots")  # mode server: the app slots stop, the data server keeps running
        exported = False
        try:
            if stopping:
                await _stop_step(c)
            if slots:
                await _stop_slots_step(c)
            async with c.steps.step("export"):
                await _export(c)
            exported = True
        finally:
            if stopping:  # also when the export failed: the app never stays stopped
                await _outcome_step(c, "restart", lambda: _control_outcome(c, "start"), never_fail=not exported)
            if slots and c.steps.status("stop_slots") in ("succeeded", "failed"):
                await _outcome_step(c, "start_slots", lambda: _start_slots(c), never_fail=not exported)
        await _outcome_step(c, "store", lambda: _store(c))
    except BaseException as exc:
        await _snapshot_failed(job, c.sink.scrub(str(exc) or type(exc).__name__))
        raise


async def _snapshot_failed(job: _Job, error: str) -> None:
    if job.snapshot_id is None:
        return
    with contextlib.suppress(Exception):
        async with session_scope() as db:
            await db.execute(update(Snapshot).where(Snapshot.id == job.snapshot_id,
                                                    Snapshot.status == SnapshotStatus.PENDING)
                             .values(status=SnapshotStatus.FAILED, error=clean_text(error)[:500]))


async def _export(c: _AppRun) -> None:
    """The snapshot's dump (and files) in the job's work folder on the host, checked and hashed (§7.5 export)."""
    job, side, remote, sink = c.job, c.new, c.remote, c.sink
    assert side is not None
    host, cmds = c.instance.host.name, side.plan.commands
    if "dump" not in cmds:
        raise DeployError(f"Release {side.sha7}'s slipway.yml has no dump command, so Slipway can't take a snapshot")
    job_dir = data.job_dir(c.paths.base, job.deployment_id)
    await remote.run(data.prepare_backups_command(c.paths.backups), timeout=60)
    await remote.run(f"umask 077 && mkdir -p -- {q(job_dir)}", timeout=60)
    job.exported = {"dir": job_dir}
    if "data_up" in cmds:
        await _app_run(c, side, "data_up")
    job.exported["revision"] = await _read_revision(c, side, job_dir)
    parts: dict[str, tuple[str, str | None]] = {snapfile.DATABASE: ("dump", "verify_dump")}
    if "export_files" in cmds and side.man.data.files is not None:
        parts[snapfile.FILES] = ("export_files", None)
    for part, (command, verify) in parts.items():
        path = f"{job_dir}/{part}"
        code, _ = await _app_run(c, side, command, check=False, **_file_args(cmds[command], "out", path))
        if code:
            raise DeployError(f"The export failed (commands.{command} exited {code}); {c.instance.name}'s data wasn't "
                              "changed. Is the database running? Fix the cause, then retry.")
        _, output = await remote.run(data.partial_check_command(path), check=False, timeout=data.HASH_TIMEOUT)
        found = data.parse_file_check(output)
        size, sha = found.sizes.get(part), found.shas.get(part)
        if size is None:
            raise DeployError(data.empty_output_message(command, path))
        if sha is None:
            raise DeployError(f"{host} has none of sha256sum, shasum or openssl; a snapshot needs one")
        if verify and verify in cmds:
            code, _ = await _app_run(c, side, verify, check=False, **_file_args(cmds[verify], "in", path))
            if code:
                raise DeployError(f"The export failed its check (commands.{verify} exited {code}); {c.instance.name}'s "
                                  "data wasn't changed.")
        job.exported[part] = {"path": path, "bytes": size, "sha256": sha}
    total = sum(int(job.exported[p]["bytes"]) for p in parts)
    await sink.line(f"Exported the data on {host} ({data.human_bytes(total)})")


_SOURCE_BAD = re.compile(r"[^A-Za-z0-9._ -]")


def _snapshot_source(name: str) -> str:
    """The instance's name as a snapshot's ``source`` (letters, digits, '.', '_', ' ' and '-')."""
    text = _SOURCE_BAD.sub("-", name).strip()[:100]
    return text if text and text[0].isalnum() else f"i{text}"[:100]


class _QueueReader:
    """A ``read(n)`` file for the thread writing a snapshot, fed by the event loop from ``remote.read_stream``."""

    def __init__(self) -> None:
        self._q: queue.Queue[bytes | None] = queue.Queue(STAGE_DEPTH)
        self._buf = b""
        self._eof = False
        self._stopped = threading.Event()  # the reader gave up: put returns False
        self._failed = threading.Event()  # the feeding side gave up: read raises

    def put(self, chunk: bytes | None) -> bool:
        while not self._stopped.is_set():
            try:
                self._q.put(chunk, timeout=0.1)
                return True
            except queue.Full:
                continue
        return False

    def stop(self) -> None:
        self._stopped.set()

    def fail(self) -> None:
        self._failed.set()
        self._stopped.set()

    def read(self, n: int = -1, /) -> bytes:
        while not self._buf and not self._eof:
            if self._failed.is_set():
                raise _Stopped
            try:
                item = self._q.get(timeout=0.1)
            except queue.Empty:
                continue
            if item is None:
                self._eof = True
            else:
                self._buf = item
        if n < 0:
            out, self._buf = self._buf, b""
        else:
            out, self._buf = self._buf[:n], self._buf[n:]
        return out


class _GuardedWriter:
    def __init__(self, out: snapfile.ContainerWriter, guard: snapshots.SpaceGuard) -> None:
        self._out, self._guard = out, guard

    def write(self, chunk: bytes) -> int:
        n = self._out.write(chunk)
        self._guard.wrote(len(chunk))
        return n


async def _store(c: _AppRun) -> tuple[str, str | None]:
    """Copy the export into an encrypted ``.sbx`` on Slipway (§7.5 store). Plaintext never touches its disk:
    the host's files stream through the encryptor, and each member is hashed again on the way."""
    job, instance, side, sink = c.job, c.instance, c.new, c.sink
    assert side is not None
    exported, man = job.exported, side.man
    async with session_scope() as db:
        snap = await db.get(Snapshot, job.snapshot_id) if job.snapshot_id is not None else None
        if snap is None:
            raise DeployError("The snapshot was deleted while it was being taken")
        snap_id, snap_name, notes = snap.id, snap.name, snap.notes or ""
    keys = man.identity_keys()
    identity = {k: str(v) for k, v in (instance.live_identity or {}).items() if k in keys} or None
    db_part = exported[snapfile.DATABASE]
    files_part = exported.get(snapfile.FILES)
    repository = instance.repository.full_name
    try:
        manifest_json = snapfile.build_manifest(
            app=str(man.data.app), app_name=man.name[:100], source=_snapshot_source(instance.name),
            database={"format": man.data.format, "revision": exported.get("revision"), "bytes": db_part["bytes"],
                      "sha256": db_part["sha256"]},
            repository=repository if snapfile.REPOSITORY_RE.match(repository or "") else None,
            commit=side.sha if _SHA_RE.match(side.sha) else None, notes=notes,
            files=({"format": man.data.files.format, "bytes": files_part["bytes"], "sha256": files_part["sha256"]}
                   if files_part and man.data.files else None),
            identity=identity, producer=f"slipway {__version__}",
        )
        snapfile.validate_manifest(manifest_json, max_bytes=get_settings().snapshot_max_bytes)
    except SnapshotError as exc:
        raise DeployError(f"The snapshot can't be made: {exc}") from None
    plaintext = int(db_part["bytes"]) + int(files_part["bytes"] if files_part else 0) + snapfile.MANIFEST_MAX
    try:
        async with session_scope() as db, snapshots.reserve(db, snapshots.stored_size(plaintext)) as guard:
            await db.commit()  # no read transaction stays open during the copy
            size, sha, key = await _write_bundle(c, snap_id, manifest_json, identity, guard)
            # READY is committed before the reservation goes: until then the row is pending, and the stored
            # total doesn't count it, so an upload checking the quota in between would count it nowhere.
            try:
                async with session_scope() as done:
                    snap = await done.get(Snapshot, snap_id)
                    if snap is None:
                        raise DeployError("The snapshot was deleted while it was being taken")
                    snapshots.apply_manifest(snap, manifest_json)
                    snap.data_key = snapshots.encode_key(key)
                    snap.file_bytes, snap.file_sha256 = size, sha
                    snap.status, snap.error = SnapshotStatus.READY, None
                    snap.deployment_id, snap.source_instance_id = job.deployment_id, instance.id
            except BaseException:
                snapshots.remove_bundle(snap_id)
                raise
    except snapshots.SnapshotsError as exc:
        raise DeployError(exc.message) from None
    await sink.line(f"Kept snapshot {snap_name} on Slipway ({data.human_bytes(size)}, encrypted)")
    if files_part and not job.options.get("stop_app"):
        return "succeeded", "The database and the files were copied a moment apart while the app ran"
    return "succeeded", None


async def _write_bundle(c: _AppRun, snap_id: uuid.UUID, manifest_json: dict[str, Any], identity: dict[str, str] | None,
                        guard: snapshots.SpaceGuard) -> tuple[int, str, bytes]:
    """Stream the exported members from the host through the tar writer and the encryptor, in a thread, into
    ``incoming/<snapshot id>.partial``, then move it to ``bundles/``. Returns (size, sha256, data key)."""
    exported = c.job.exported
    key = snapfile.new_data_key()
    bundle = snapshots.NewBundle(stem=str(snap_id))
    readers = {name: _QueueReader() for name in (snapfile.DATABASE, snapfile.FILES) if name in exported}
    max_bytes = get_settings().snapshot_max_bytes

    def work() -> None:
        try:
            writer = bundle.encrypting(key)
            snapfile.write_tar(_GuardedWriter(writer, guard), manifest_json, identity=identity,
                               database=readers[snapfile.DATABASE], files=readers.get(snapfile.FILES),
                               max_bytes=max_bytes)
            writer.close()
            bundle.close()
        finally:
            for reader in readers.values():
                reader.stop()

    worker = asyncio.ensure_future(asyncio.to_thread(work))
    try:
        for name, reader in readers.items():
            async for chunk in c.remote.read_stream(exported[name]["path"]):
                if not await asyncio.to_thread(reader.put, chunk):
                    break  # the writer stopped (it raises below)
            await asyncio.to_thread(reader.put, None)
        await worker
        bundle.install(snap_id)
    except BaseException as exc:
        for reader in readers.values():
            reader.fail()
        with contextlib.suppress(BaseException):
            await worker
        bundle.discard()
        if isinstance(exc, SnapshotError):
            raise DeployError(str(exc)) from None
        raise
    return bundle.bytes, bundle.sha256, key


# ------------------------------------------------------------------- Start over (§7.5 reset)


async def _start_over(job: _Job, sink: LogSink, steps: Steps, connect: ConnectFactory) -> None:
    """A never-live instance whose first deploys failed: back up, stop and delete what they left, with the
    newest release still on the host. The instance's status stays as it was."""
    instance = job.instance
    if job.env is None:
        raise DeployError(_env_unreadable(job))
    async with session_scope() as db:
        refused = await data.start_over_refusal(db, instance, environment=job.environment)
    if refused:
        raise DeployError(refused)
    await sink.line(f"Connecting to {instance.host.username}@{instance.host.address}")
    async with connect(ssh.SSHTarget.from_host(instance.host)) as remote:
        c = _AppRun(remote=remote, instance=instance, job=job, sink=sink, steps=steps, paths=paths_for(instance))
        job.ctx = c
        try:
            async with steps.step("release"):
                await _take_dir(remote, instance, sink)
                await _acquire_lock(remote, instance, job, sink)
                c.new = await _newest_release(c)
            await _pre_start(c)
            if _role(job, instance) == "server" and (instance.current_commit_sha or data.live_state(instance)):
                await sink.line(f"{instance.name} is stopped and {job.environment.name}'s data is gone: deploy "
                                f"{job.environment.name} next, which updates the data server first")
        except asyncio.CancelledError:
            _mark_cut_off(job)
            raise
        finally:
            await c.close_members()
            await _release_lock(remote, instance, job, sink)


async def _newest_release(c: _AppRun) -> _Side:
    """The newest release of the instance still on the host, planned with today's inputs (§7.4)."""
    instance, remote, job = c.instance, c.remote, c.job
    host = instance.host.name
    async with session_scope() as db:
        rows = (await db.execute(
            select(Deployment.id, Deployment.release, Deployment.commit_sha).where(
                Deployment.instance_id == instance.id, Deployment.kind == DeploymentKind.DEPLOY,
                Deployment.release.is_not(None))
            .order_by(Deployment.created_at.desc()))).all()
    _, listing = await remote.run(_image_list_command(c.paths.releases), check=False, timeout=60)
    present = {line.strip() for line in listing.splitlines()}
    found = next(((dep_id, posixpath.basename(release), sha) for dep_id, release, sha in rows
                  if _RELEASE_NAME.fullmatch(posixpath.basename(release)) and posixpath.basename(release) in present
                  and _SHA_RE.match(sha or "")), None)
    if found is None:
        raise DeployError(f"Slipway has no release of {instance.name} on {host} to back up its data with; deploy once "
                          "more, or remove the volumes by hand")
    dep_id, name, sha = found
    release = f"{c.paths.releases}/{name}"
    text = await _read_release_file(remote, release, instance.manifest_file)
    if text is None:
        raise DeployError(f"{instance.manifest_file} can't be read in {release} on {host}")
    try:
        man = manifest.parse(text)
    except manifest.ManifestError as exc:
        raise DeployError(f"Release {sha[:7]}: {exc}") from exc
    template = None
    if man.env_file:
        template = await _read_release_file(remote, release, man.env_file)
        if template is None:
            raise DeployError(f"Release {sha[:7]}: env_file {man.env_file} can't be read in {release}")
    host_ports: dict[str, int] = {}
    for row in instance.published_ports or []:
        with contextlib.suppress(TypeError, ValueError, KeyError):
            if row.get("service"):
                host_ports[str(row["service"])] = int(row["host"])
    if job.member:  # the environment's settings and services, in the member's role (phase 3 §5.3, §6)
        settings, chosen = dict(job.settings or {}), job.services
    else:
        settings, chosen = dict(instance.app_settings or {}), instance.app_services
    role = _role(job, instance)
    role_kw: dict[str, Any] = {}
    if role == "server":
        role_kw = {"role": role, "server_values": {"host": instance.host.upstream_address, "clients": _clients(job)}}
    elif role == "slot":
        role_kw = {"role": role, "data_values": await _data_values(c)}
    try:
        plan = manifest.plan(man, template=template, builtins=app_builtins(instance, release, sha, dep_id),
                             settings=settings, chosen=chosen, host_ports=host_ports,
                             secrets=dict(job.secrets or {}), env=dict(job.env or {}), **role_kw)
    except manifest.ManifestError as exc:
        raise DeployError(f"Release {sha[:7]} can't be rendered for {instance.name}: {exc}") from exc
    except KeyError as exc:
        raise DeployError(f"Release {sha[:7]} needs the secret {exc.args[0]}, which Slipway doesn't have") from exc
    # Today's inputs may render other project names than the failed deploys used (an edited setting, say).
    # Stop and reset act on every one of them, so each must be one of this instance's own (I5).
    known = app_known_projects(instance)
    other = [p for p in plan.projects if p not in known]
    if other:
        raise DeployError(
            f"Release {sha[:7]} would now run under other Compose projects ({', '.join(other)}) than "
            f"{instance.name}'s deploys used ({', '.join(known) or 'none'}); a setting or an environment variable "
            "changed them. Put it back, then retry. Nothing was changed.")
    await _check_projects_free(instance, plan.projects)
    content = _env_content(template, plan)
    await remote.write_text(c.paths.env_file, content)
    await c.sink.line(f"Wrote the settings of release {sha[:7]} ({release}) to {c.paths.env_file}")
    c.job.data_app = True
    return _Side(man=man, plan=plan, release=release, sha=sha, content=content)



def _image_list_command(releases: str) -> str:
    return f"ls -1 {q(releases)} 2>/dev/null"


async def _prune_app_images(remote: ssh.RemoteSession, instance: Instance, state: dict[str, Any], sink: LogSink) -> None:
    """Remove the images of releases that are gone (never one a kept release also uses, nor one in use)."""
    releases: dict[str, list[str]] = dict(state.get("releases") or {})
    _, output = await remote.run(_image_list_command(paths_for(instance).releases), check=False, timeout=60)
    present = {line.strip() for line in output.splitlines() if line.strip()}
    kept = {name: refs for name, refs in releases.items() if name in present}
    gone = sorted({ref for name, refs in releases.items() if name not in present for ref in refs}
                  - {ref for refs in kept.values() for ref in refs})
    gone = [ref for ref in gone if manifest.IMAGE_RE.match(ref)]
    if gone:
        # Without -f: an image a container still uses (another instance's, say) stays.
        await remote.run(f"docker image rm {' '.join(q(r) for r in gone)} >/dev/null 2>&1; true", check=False, timeout=600)
        await sink.line(f"Removed the images of old releases: {', '.join(gone)}")
    if kept != releases:
        state = {**state, "releases": kept}
        await _save_instance(instance, app_state=state)


def app_projects(instance: Instance) -> list[str]:
    """The Compose projects status, logs, start and stop act on: the live release's, then those of a deploy
    that failed after it (``starting``, dropped once a release goes live), whose containers may be up."""
    state = instance.app_state or {}
    names = [*(state.get("projects") or []), *(state.get("starting") or [])]
    return [p for p in dict.fromkeys(str(n) for n in names) if manifest.PROJECT_RE.match(p)]


def app_known_projects(instance: Instance) -> list[str]:
    """Every Compose project the app's deploys used, failed ones included (teardown, leftovers, moves)."""
    state = instance.app_state or {}
    names = [*(state.get("projects") or []), *(state.get("known_projects") or [])]
    return [p for p in dict.fromkeys(str(n) for n in names) if manifest.PROJECT_RE.match(p)]


async def _check_projects_free(instance: Instance, projects: list[str]) -> None:
    """Refuse project names another instance on the host uses: stop and delete would act on its containers."""
    async with session_scope() as db:
        others = (await db.scalars(select(Instance).where(
            Instance.host_id == instance.host_id, Instance.id != instance.id))).all()
    for other in others:
        theirs = {other.compose_project, *app_known_projects(other)}
        clash = sorted(set(projects) & theirs)
        if clash:
            raise DeployError(f"slipway.yml: the Compose project {', '.join(clash)} is also instance {other.name}'s on "
                              f"{instance.host.name}; make the project names in slipway.yml include {{slipway.slug}}")


HOST_MARK = "slipway-host:"


def kept_env_path(paths: InstancePaths, instance: Instance) -> str:
    """Where deleting an app instance leaves its ``.env`` (secrets included) when its volumes stay."""
    return f"{paths.root}/.slipway-kept/{paths.slug}-{instance.id.hex[:8]}.env"


def projects_on_host_command(instance: Instance, projects: list[str]) -> str:
    """Prints ``HOST_MARK c <project>`` for each project with containers on the host, ``HOST_MARK v <project>
    <volume>`` for each of its volumes, and ``HOST_MARK k <file>`` for each ``.env`` a deleted instance in
    the same folder left. Fails when docker can't list them."""
    paths = paths_for(instance)
    parts = []
    for p in projects:
        flt = _project_filter(p)
        parts.append(
            f'ids=$(docker ps -aq --filter {flt}) || exit 1; [ -z "$ids" ] || echo {q(f"{HOST_MARK} c {p}")}; '
            f'vols=$(docker volume ls -q --filter {flt}) || exit 1; '
            f'[ -z "$vols" ] || printf \'%s\\n\' "$vols" | sed {q(f"s/^/{HOST_MARK} v {p} /")}'
        )
    kept = q(f"{paths.root}/.slipway-kept")
    slug = paths.slug.replace(".", "\\.")
    names = " ".join(f"-e {q(slug + pattern)}" for pattern in
                     ("-[0-9a-f]*\\.env", "-[0-9a-f]*\\.backups", "-[0-9a-f]*\\.backups-[0-9TZ]*"))
    parts.append(f"{{ ls -1 {kept} 2>/dev/null | grep -x {names} | sed {q(f's/^/{HOST_MARK} k /')}; true; }}")
    return "; ".join(parts)


async def _check_projects_on_host(
    remote: ssh.RemoteSession, instance: Instance, projects: list[str], secrets: list[str], env: dict[str, str]
) -> None:
    """Refuse projects that are new to this instance but already on the host.

    Their containers aren't the app's own: the port check would count them as free and stop and delete
    would act on them. Their volumes hold data made with secrets this instance doesn't have (another
    stack's, or a deleted instance's), unless the instance's environment variables set every secret.
    """
    new = [p for p in projects if p not in app_known_projects(instance)]
    if not new:
        return
    _, output = await remote.run(projects_on_host_command(instance, new), timeout=60)
    rows = [ln.split(HOST_MARK, 1)[1].split() for ln in output.splitlines() if HOST_MARK in ln]
    running = sorted({r[1] for r in rows if len(r) >= 2 and r[0] == "c"})
    volumes = sorted({r[2] for r in rows if len(r) >= 3 and r[0] == "v"})
    kept_dir = f"{paths_for(instance).root}/.slipway-kept"
    kept = sorted({f"{kept_dir}/{r[1]}" for r in rows if len(r) >= 2 and r[0] == "k"})
    host = instance.host.name
    if running:
        raise DeployError(
            f"{host} already runs containers in the Compose project{'s' if len(running) > 1 else ''} "
            f"{', '.join(running)}, which Slipway didn't start "
            "for this instance; remove them, or change the project names in slipway.yml")
    unset = [k for k in secrets if not env.get(k)]
    if volumes and unset:
        where = f" A deleted instance's values are in {', '.join(kept)}." if kept else ""
        raise DeployError(
            f"{host} already has the volumes {', '.join(volumes[:10])}{' and more' if len(volumes) > 10 else ''} of "
            f"Compose project(s) this instance is about to use. Their data was made with other secrets than the ones "
            f"Slipway would generate. Set {', '.join(unset)} as environment variables of the instance, with the values "
            f"that data was made with, or remove the volumes (docker volume rm) to start afresh.{where}")


def has_routes(instance: Instance) -> bool:
    if instance.environment_id is not None:
        return False  # an environment's names are published by the traffic code only (D22)
    return bool(instance.routes or instance.proxy_entries or
                (instance.build_source == BuildSource.APP and (instance.app_state or {}).get("routes")))


# ------------------------------------------------------------------------ pipeline


async def _pipeline(
    deployment_id: uuid.UUID, job: _Job, sink: LogSink, steps: Steps, connect: ConnectFactory, github: GitHubFactory
) -> CommitInfo:
    instance, branch = job.instance, job.branch
    repo, host = instance.repository, instance.host
    if job.kind in data.RESTORE_KINDS:
        return await _live_pipeline(deployment_id, job, sink, steps, connect)
    if job.kind != DeploymentKind.DEPLOY:
        raise DeployError(f"Slipway can't run {data.kind_label(job.kind)} jobs this way")
    if job.env is None:
        raise DeployError(_env_unreadable(job))
    token, source = github_token_for(job.user)
    reuse = job.retry is not None and job.retry.reusable
    with tempfile.TemporaryDirectory(prefix="slipway-") as tmp:
        tarball: Path | None = None
        async with github(token) as gh:
            async with steps.step("resolve"):
                # Deploy again, confirming names the refused deploy's commit (phase 3 §7.6).
                pinned = str(job.options.get("pin_commit") or "") if job.retry is None else ""
                ref = job.retry.sha if job.retry is not None else (pinned or branch)
                what = f"{repo.full_name}@{ref[:12] if job.retry is not None or pinned else ref}"
                await sink.line(f"Resolving {what} using {source}"
                                + (f" (the commit of deployment {job.retry.id.hex[:8]})" if job.retry else "")
                                + (" (the commit the refused deploy was of)" if pinned else ""))
                await _check_repository(gh, repo, sink)
                commit = await gh.get_commit(repo.github_id, ref)
                if not _SHA_RE.match(commit.sha or ""):
                    raise DeployError(f"GitHub returned an invalid commit id for {ref}")
                if job.retry is not None and commit.sha != job.retry.sha:
                    raise DeployError("GitHub returned another commit than the one being retried")
                if pinned and commit.sha != pinned:
                    raise DeployError("GitHub returned another commit than the one asked for")
                message = _fit(Deployment, "commit_message", commit.message or "")
                author = _fit(Deployment, "commit_author", commit.author or "")
                async with session_scope() as db:
                    await db.execute(
                        update(Deployment)
                        .where(Deployment.id == deployment_id)
                        .values(commit_sha=commit.sha, commit_message=message, commit_author=author or None)
                    )
                await sink.line(f"Commit {commit.sha[:7]} — {message} ({author})")
            if reuse:
                assert job.retry is not None and job.retry.release
                kept = posixpath.join(paths_for(instance).releases, posixpath.basename(job.retry.release))
                async with connect(ssh.SSHTarget.from_host(host)) as probe:
                    gone, _ = await probe.run(f"[ -d {q(kept)} ]", check=False, timeout=60)
                if gone:
                    await sink.line(f"The release {kept} is no longer on {host.name}: downloading the commit again")
                    job.retry.reusable = reuse = False
            if reuse:
                await steps.skip("source", f"Reusing the release of deployment {job.retry.id.hex[:8]}")
            else:
                async with steps.step("source"):
                    tarball = Path(tmp) / "source.tar.gz"
                    size = await gh.download_tarball(repo.github_id, commit.sha, tarball)
                    await sink.line(f"Downloaded source archive ({size / 1024:.0f} KiB)")
                    await asyncio.to_thread(check_source_archive, tarball, guarded_paths(instance))

        await sink.line(f"Connecting to {host.username}@{host.address}")
        async with connect(ssh.SSHTarget.from_host(host)) as remote:
            await _install(remote, instance, deployment_id, commit.sha, tarball, job, sink, steps)
    return commit


async def _live_pipeline(
    deployment_id: uuid.UUID, job: _Job, sink: LogSink, steps: Steps, connect: ConnectFactory,
) -> CommitInfo:
    """Restore, roll back and reset: the live release again, in place, with data steps between build and start
    (D2). GitHub is never called: the release is on the host, and its commit is the live one."""
    instance = job.instance
    if job.live_inputs is None or job.retry is None:
        raise DeployError(data.not_live_text(instance))
    if job.env is None:
        raise DeployError(_env_unreadable(job))
    async with session_scope() as db:
        dep = await db.get(Deployment, deployment_id)
        message = (dep.commit_message if dep is not None else None) or ""
        author = (dep.commit_author if dep is not None else None) or ""
    commit = CommitInfo(sha=job.retry.sha, message=message, author=author, date=None)
    await sink.line(f"{data.kind_label(job.kind)} of {instance.name}: the live release {commit.sha[:7]} runs again")
    await sink.line(f"Connecting to {instance.host.username}@{instance.host.address}")
    async with connect(ssh.SSHTarget.from_host(instance.host)) as remote:
        await _install(remote, instance, deployment_id, commit.sha, None, job, sink, steps)
    return commit


async def _failure_fields(deployment_id: uuid.UUID, job: _Job) -> dict[str, Any]:
    """The instance fields a failed job leaves (§7.1, §8.4).

    A deploy: FAILED, and ``data_dirty`` when it began changing an app's data (its ``start`` began). A restore,
    roll back or reset: FAILED with ``data_dirty`` once its ``stop`` began, otherwise the status it had (the old
    app still runs). Start over keeps the status it had either way. Data-only jobs never change the instance,
    except a snapshot that stopped the app and couldn't start it again: STOPPED, as the app is.
    """
    if job.instance.build_source == BuildSource.APP and job.kind in data.DATA_ONLY_KINDS:
        return await _left_stopped_fields(deployment_id, job.instance)
    restore_kind = job.instance.build_source == BuildSource.APP and job.kind in data.RESTORE_KINDS
    fields: dict[str, Any] = {"status": InstanceStatus.FAILED}
    if job.start_over and job.prev_status:
        fields["status"] = job.prev_status
    if job.instance.build_source != BuildSource.APP or not job.data_app:
        return fields
    owner = job.data_owner  # an app slot's failed deploy marks the data owner dirty (phase 3 §7.5)
    try:
        async with session_scope() as db:
            dep = await db.get(Deployment, deployment_id)
            inst = await db.get(Instance, owner.id)
            if dep is None or inst is None or not data.change_began(dep):
                if restore_kind and job.prev_status:
                    fields["status"] = job.prev_status
                return fields
            step = next((r.get("key") for r in dep.steps or [] if r.get("status") in ("failed", "running")), None)
            dirty = data.mark_dirty(inst.data_dirty, dep, step=step)
            _note_slots(dirty, job, step)
    except Exception as exc:  # recording the dirty state must never keep the job from ending
        log.warning("Could not record the data state of deployment %s: %s", deployment_id, exc)
        return fields
    if owner is job.instance:
        fields["data_dirty"] = dirty
    else:
        fields.update(owner_id=owner.id, owner_fields={"data_dirty": dirty})
    return fields


def _note_slots(dirty: dict[str, Any], job: _Job, step: str | None) -> None:
    """A data owner job that stopped the app slots (``stop_slots``) records them in the dirty state, and a lead
    slot that didn't start again its error, so the hold text says so (§7.4). A failure in ``start_slots``
    holds the data: the app slots are down (I9)."""
    if not job.options.get("slots_were"):
        return
    still = _left_down(job.options)
    last = dict(dirty.get("last") or {})
    if still:
        last["slots_stopped"] = still
    if job.options.get("start_error"):
        last["start_error"] = job.options["start_error"]
    dirty["last"] = last
    if step == "start_slots":
        dirty["hold"] = True


async def _left_stopped_fields(deployment_id: uuid.UUID, instance: Instance) -> dict[str, Any]:
    """STOPPED when a snapshot job stopped the running app and didn't start it again (data.left_stopped)."""
    try:
        async with session_scope() as db:
            dep = await db.get(Deployment, deployment_id)
            inst = await db.get(Instance, instance.id)
            if dep is not None and inst is not None and inst.status == InstanceStatus.RUNNING and data.left_stopped(dep):
                return {"status": InstanceStatus.STOPPED}
    except Exception as exc:  # never keeps the job from ending
        log.warning("Could not read the steps of deployment %s: %s", deployment_id, exc)
    return {}


def _settle_after_live(rows: list[dict[str, Any]], interrupted: str, not_run: str) -> list[dict[str, Any]]:
    """The steps of a job cut off after it went live: from ``finish`` on, the one cut off becomes a warning and
    those it never reached are skipped. The proxy note says how to update Switchyard by hand."""
    out: list[dict[str, Any]] = []
    after = False
    for row in rows:
        row = dict(row)
        after = after or row.get("key") == "finish"
        note: str | None = None
        if after and row.get("status") in ("running", "failed"):
            row["status"], note = "warning", interrupted
        elif after and row.get("status") == "pending":
            row["status"], note = "skipped", not_run
        if note is not None:
            if row.get("key") == "proxy":
                note += ". Use Sync proxy on the instance page to update Switchyard"
            elif row.get("key") == "traffic":
                note += ". Use Publish names on the environment page to update Switchyard"
            row["note"] = note
        out.append(row)
    return out


def _seed_missed(kind: str, rows: list[dict[str, Any]], options: dict[str, Any], instance: Instance,
                 never_live: bool) -> bool:
    """Whether a job cut off after it went live never finished a seed it would have run (content_pending)."""
    row = next((r for r in rows if r.get("key") == "seed"), None)
    if row is None or row.get("status") not in ("pending", "running", "failed"):
        return False
    if kind != DeploymentKind.DEPLOY:
        return True
    return bool(instance.seed_content) and (bool(options.get("started_empty"))
                                            or (never_live and instance.fresh_data == FreshData.EMPTY))


async def _note_went_live(deployment_id: uuid.UUID, job: _Job) -> None:
    """Set ``job.went_live`` when ``finish`` saved app_state naming this job but was cut off before it noted so
    in memory (a cancel landing in the save's commit): the stored state is what a restart would go by (D12)."""
    if job.went_live is not None or job.instance.build_source != BuildSource.APP or job.start_over \
            or job.kind in data.DATA_ONLY_KINDS:
        return
    try:
        async with session_scope() as db:
            state = await db.scalar(select(Instance.app_state).where(Instance.id == job.instance.id))
    except Exception as exc:  # the in-memory record stands
        log.warning("Could not read the live state of deployment %s: %s", deployment_id, exc)
        return
    if isinstance(state, dict) and state.get("went_live") == deployment_id.hex:
        sha = str((state.get("live") or {}).get("sha") or "")
        if sha:
            job.instance.app_state = state
            job.went_live = sha


async def _end_after_live(deployment_id: uuid.UUID, job: _Job, commit: CommitInfo | None, sink: LogSink,
                          steps: Steps, word: str, why: str) -> None:
    """A job cut off (or failing) once its release went live still succeeds (D12): the release is live and
    healthy, so the instance records it as live, its data as clean, and nothing offers to roll it back."""
    sha = commit.sha if commit is not None else str(job.went_live)
    why = clean_text(sink.scrub(why))[:200]
    missed =_seed_missed(job.kind, steps.rows, job.options, job.instance, job.never_live)
    steps._current = None
    steps.rows = _settle_after_live(steps.rows, f"Interrupted: {why}", f"Not run: {why}")
    await sink.line(f"{word} cut off after release {sha[:7]} went live ({why}); it still counts as succeeded")
    await steps.close()
    await sink.close()
    fields = await _success_record(job, CommitInfo(sha=sha, message="", author="", date=None), steps)
    if missed:
        if "owner_fields" in fields:
            fields["owner_fields"] = {**fields["owner_fields"], "content_pending": True}
        else:
            fields["content_pending"] = True
    await _finish(deployment_id, DeploymentStatus.SUCCEEDED, short=True, **fields)


_OWN_FIELDS = ("status", "current_commit_sha", "last_deployed_at")


async def _success_record(job: _Job, commit: CommitInfo | None, steps: Steps) -> dict[str, Any]:
    """``_finish``'s fields for a job that succeeded: phase 2's for a standalone instance; for a member of an
    environment, the slot's own fields on it and the phase 2 data fields on the data owner (§7.5's table)."""
    fields = _success_fields(job, commit, steps)
    if not job.member:
        return fields
    instance, owner = job.instance, job.data_owner
    if owner is instance:
        if instance.slot == environments.DATA_SLOT and job.kind == DeploymentKind.DEPLOY:
            # It ran no app migration: it never settles a failed slot deploy, and fresh_data stays as its start
            # left it, so the first app slot deploy on the empty data still creates the first admin (§7.5).
            fields.pop("data_dirty", None)
            fields.pop("fresh_data", None)
            # Nor can it change what the data was made with: live_identity only when there is none (``finish``
            # recorded it then).
            if instance.live_identity:
                fields.pop("live_identity", None)
        return fields
    own = {k: v for k, v in fields.items() if k in _OWN_FIELDS}
    rest = {k: v for k, v in fields.items() if k not in _OWN_FIELDS}
    owner_fields: dict[str, Any] = {}
    if job.kind == DeploymentKind.DEPLOY:
        owner_fields.update(fresh_data=None, seed_snapshot_id=None)
        try:
            async with session_scope() as db:
                fresh = await db.get(Instance, owner.id)
                first = ((fresh.data_dirty if fresh is not None else None) or {}).get("first") or {}
                first_dep = await db.get(Deployment, data._uuid(first.get("deployment_id"))) \
                    if first.get("deployment_id") else None
                if first_dep is not None and first_dep.kind == DeploymentKind.DEPLOY \
                        and first_dep.instance_id == instance.id:
                    owner_fields["data_dirty"] = null()  # a retry, or a new deploy, of the slot that failed
                if fresh is not None and fresh.live_identity is None and job.identity:
                    owner_fields["live_identity"] = job.identity
        except Exception as exc:  # never keeps the job from ending
            log.warning("Could not read the data owner of deployment %s: %s", job.deployment_id, exc)
    else:
        owner_fields.update({k: v for k, v in rest.items() if k in ("content_pending",)})
    return {**own, "owner_id": owner.id, "owner_fields": owner_fields}


def _success_fields(job: _Job, commit: CommitInfo | None, steps: Steps) -> dict[str, Any]:
    instance = job.instance
    if instance.build_source == BuildSource.APP and job.kind in data.DATA_ONLY_KINDS:
        if job.kind == DeploymentKind.CONTENT and steps.status("seed") == "succeeded":
            return {"content_pending": False}
        return {}
    if job.start_over:
        # Its stop and reset took the app down: a data server that ran is stopped now (phase 3 §7.3).
        status = job.prev_status or instance.status
        out: dict[str, Any] = {"status": InstanceStatus.STOPPED if status == InstanceStatus.RUNNING else status,
                               "data_dirty": null()}
        if _role(job, instance) == "server" and (instance.current_commit_sha or data.live_state(instance)):
            # Its database is gone: the data server is as if never deployed, so the environment's next deploy
            # updates it first (a slot deploy is refused until then, attach_problem) and the new data's
            # identity is recorded afresh.
            state = {k: v for k, v in (instance.app_state or {}).items() if k != "live"}
            out.update(current_commit_sha=None, app_state=state, live_identity=null())
        return out
    assert commit is not None
    fields: dict[str, Any] = {"status": InstanceStatus.RUNNING, "current_commit_sha": commit.sha,
                              "last_deployed_at": utcnow()}
    if instance.build_source == BuildSource.APP:
        # The data is now what this release made of it: clean, and made with these identity values (D8, D9).
        fields.update(data_dirty=null(), seed_snapshot_id=None, fresh_data=None)
        if job.data_app and job.identity is not None:
            fields["live_identity"] = job.identity
    return fields


async def run_deployment(
    deployment_id: uuid.UUID,
    *,
    connect: ConnectFactory = ssh.open_session,
    github: GitHubFactory = GitHubClient,
) -> None:
    if await _environment_level(deployment_id):
        # A job of a whole environment (D9): its own steps, in env_jobs, then the chain hook (§8.5).
        from slipway.services import env_jobs  # it uses the deployer's pieces

        await env_jobs.run(deployment_id, connect=connect, github=github)
        with contextlib.suppress(Exception):
            await environments.after_job(deployment_id)
        return
    try:
        job = await _start(deployment_id)
    except Exception as exc:
        log.warning("Deployment %s could not start: %s", deployment_id, exc)
        await _finish(deployment_id, DeploymentStatus.FAILED, error=f"Could not start the deployment: {exc}")
        return
    if job is None:
        return
    job.connect = connect

    sink = LogSink(deployment_id, hide=job.hide)
    steps = Steps(deployment_id, job.steps, sink)
    app = job.instance.build_source == BuildSource.APP
    data_only = app and job.kind in data.DATA_ONLY_KINDS
    word = "Deployment" if job.kind == DeploymentKind.DEPLOY else data.kind_label(job.kind)
    commit: CommitInfo | None = None
    try:
        if job.member and job.secrets is None and job.kind != DeploymentKind.DEPLOY:
            # Never generated again (§3.8). A deploy goes on when the environment's variables set every secret
            # of its release, and keeps them as the environment's (_install_app); nothing else can.
            raise DeployError(SECRETS_LOST.format(env=job.environment.name))
        if data_only:
            await _data_job(job, sink, steps, connect)
        elif job.start_over:
            await _start_over(job, sink, steps, connect)
        else:
            commit = await _pipeline(deployment_id, job, sink, steps, connect, github)
    except asyncio.CancelledError:
        await _note_went_live(deployment_id, job)
        if job.went_live is not None:  # after finish: the release is live, so the job still succeeds (D12)
            await _end_after_live(deployment_id, job, commit, sink, steps, word, "Slipway is shutting down")
            await _shutdown_notice(deployment_id, job)
            raise
        await sink.line(f"{word} interrupted: Slipway is shutting down")
        await steps.close()
        await sink.close()
        if job.kind == DeploymentKind.SNAPSHOT:
            await _snapshot_failed(job, "Interrupted: Slipway was shutting down; take it again")
        await _finish(deployment_id, DeploymentStatus.CANCELLED, error="Interrupted", short=True,
                      **await _failure_fields(deployment_id, job))
        raise
    except Exception as exc:
        await _note_went_live(deployment_id, job)
        if job.went_live is not None:
            log.warning("Deployment %s went live, then: %s", deployment_id, sink.scrub(str(exc)))
            await sink.line(f"Warning: {exc}")
            await _end_after_live(deployment_id, job, commit, sink, steps, word, str(exc) or type(exc).__name__)
            await _after_job(deployment_id, job)
            return
        log.info("Deployment %s failed: %s", deployment_id, sink.scrub(str(exc)))
        await sink.line(f"{word} failed: {exc}")
        await steps.close()
        await sink.close()
        if job.kind == DeploymentKind.SNAPSHOT:
            await _snapshot_failed(job, sink.scrub(str(exc)))
        await _finish(deployment_id, DeploymentStatus.FAILED, error=str(exc), scrub=sink.scrub,
                      **await _failure_fields(deployment_id, job))
        return
    if not steps.listed("proxy") and app:
        pass  # data-only jobs and Start over leave the proxy as it is
    elif has_routes(job.instance):
        await steps.begin("proxy")
        try:
            await switchyard.sync_and_store(job.instance, say=sink.line)
        except asyncio.CancelledError:  # the release is live: a shutdown here still ends the job as succeeded
            await _end_after_live(deployment_id, job, commit, sink, steps, word, "Slipway is shutting down")
            await _shutdown_notice(deployment_id, job)
            raise
        except Exception as exc:  # the containers are running: a proxy problem never fails the deploy
            log.warning("Proxy sync after deployment %s failed: %s", deployment_id, sink.scrub(str(exc)))
            await sink.line(f"Proxy: could not update Switchyard: {exc}")
            await steps.end("warning", note=str(exc))
        else:
            await steps.end("succeeded")
    else:
        await steps.skip("proxy", "No hostnames")
    await sink.line(f"{word} succeeded")
    await steps.close()
    await sink.close()
    await _finish(deployment_id, DeploymentStatus.SUCCEEDED, **await _success_record(job, commit, steps))
    await _after_job(deployment_id, job)


async def _environment_level(deployment_id: uuid.UUID) -> bool:
    """Whether the deployment is a job of a whole environment (no instance, phase 3 D9)."""
    try:
        async with session_scope() as db:
            found = (await db.execute(select(Deployment.instance_id, Deployment.environment_id)
                                      .where(Deployment.id == deployment_id))).first()
    except Exception:
        return False
    return found is not None and found[0] is None and found[1] is not None


async def _after_job(deployment_id: uuid.UUID, job: _Job) -> None:
    """The chain hook (phase 3 §8.5, D12): after a job of an environment succeeded while Slipway runs normally,
    queue the next job by the chain's rules. Never from ``_finish``, which also records successes during a
    shutdown; never fails the job, which has already ended."""
    if not job.member:
        return
    try:
        await environments.after_job(deployment_id)
    except Exception as exc:
        log.warning("The chain after deployment %s didn't continue: %s", deployment_id, exc)


async def _shutdown_notice(deployment_id: uuid.UUID, job: _Job) -> None:
    """A job recorded as succeeded while Slipway shuts down doesn't start the next job of its chain; the
    environment's notice says so, with a button that starts it by hand (§8.5)."""
    if not job.member:
        return
    with contextlib.suppress(Exception):
        await environments.chain_notice(deployment_id, why="shutdown")


RunnerKey = Hashable


def _keys(keys: Any) -> tuple[RunnerKey, ...]:
    """The runner keys a caller passes, sorted and without repeats: a tuple of keys (``data.runner_keys``,
    ``data.job_keys``), or one key alone (a standalone instance's id, as callers passed before environments).
    Sorted on their text, so two jobs never take the same locks in opposite orders."""
    if isinstance(keys, (tuple, list, set, frozenset)) and not (
            isinstance(keys, tuple) and len(keys) == 2 and isinstance(keys[1], str) and not isinstance(keys[0], tuple)):
        found = tuple(keys)
    else:
        found = (keys,)
    return tuple(sorted(set(found), key=str))


class DeployRunner:
    """Runs deployments as in-process asyncio tasks, one at a time per runner key.

    A standalone instance's jobs hold one key, its id; an environment's jobs hold one or both of
    ``(env, "data")`` and ``(env, "traffic")`` (phase 3 D8, ``data.runner_keys``). A job waits until it holds
    every key it names, taken in a fixed order.

    Good enough for a single Slipway container. Swap for a queue + worker (arq, Celery...)
    if you need deployments to survive restarts or run on several Slipway replicas.
    """

    def __init__(self) -> None:
        self._tasks: set[asyncio.Task[None]] = set()
        self._locks: defaultdict[RunnerKey, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._pending: Counter[RunnerKey] = Counter()  # deploy tasks submitted and not finished, per key
        self._exclusive: set[RunnerKey] = set()
        self._deleting: set[RunnerKey] = set()

    def submit(self, deployment_id: uuid.UUID, keys: Any) -> None:
        held = _keys(keys)
        for key in held:
            self._pending[key] += 1

        async def _run() -> None:
            try:
                async with contextlib.AsyncExitStack() as stack:
                    for key in held:
                        await stack.enter_async_context(self._locks[key])
                    await run_deployment(deployment_id)
            finally:
                for key in held:
                    self._pending[key] -= 1
                    if self._pending[key] <= 0:
                        del self._pending[key]

        task = asyncio.create_task(_run(), name=f"deploy-{deployment_id}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def busy(self, keys: Any) -> bool:
        return any(self._pending[k] > 0 or k in self._exclusive for k in _keys(keys))

    def is_deleting(self, keys: Any) -> bool:
        return any(k in self._deleting for k in _keys(keys))

    @asynccontextmanager
    async def exclusive(self, keys: Any, *, deleting: bool = False) -> AsyncIterator[None]:
        """Hold the deploy locks of ``keys`` without waiting; raise RunnerBusy if one is in use.

        Deployments submitted meanwhile wait until the block exits.
        """
        held = _keys(keys)
        if self.busy(held):
            raise RunnerBusy("A deployment or another change is in progress for this instance; try again when it finishes")
        self._exclusive.update(held)
        if deleting:
            self._deleting.update(held)
        try:
            async with contextlib.AsyncExitStack() as stack:
                for key in held:
                    await stack.enter_async_context(self._locks[key])
                yield
        finally:
            self._exclusive.difference_update(held)
            self._deleting.difference_update(held)

    async def recover_interrupted(self) -> None:
        """Mark deployments left queued/running by a previous process as failed, and settle what their data
        steps left (§7.6): pending backups become ``unverified`` (the next job checks them), pending snapshots
        fail, background checks start again, a job that had begun changing the data leaves ``data_dirty`` (a
        running change step counts as begun), and a restore-type job that changed nothing puts the status back.
        The host lock stays: a command may still be running there (§4.5)."""
        async with session_scope() as db:
            stale = (
                await db.scalars(
                    select(Deployment).where(
                        Deployment.status.in_([DeploymentStatus.QUEUED, DeploymentStatus.RUNNING])
                    )
                )
            ).all()
            recovered_live: list[uuid.UUID] = []
            for dep in stale:
                dep.status = DeploymentStatus.FAILED
                dep.steps = [{**r, "status": "failed", "note": "Interrupted"} if r.get("status") == "running" else r
                             for r in dep.steps or []]
                dep.error = "Interrupted by a Slipway restart"
                dep.finished_at = utcnow()
                owner = await _recovery_owner(db, dep)
                _recover_instance(dep, owner=owner, settles=await _settles_owner(db, dep, owner))
                if dep.instance_id is None and dep.environment_id is not None:
                    from slipway.services import env_jobs  # it uses the deployer's pieces

                    await env_jobs.recover(db, dep)  # an environment-level job settles its own (§9.13)
                if dep.status == DeploymentStatus.SUCCEEDED and dep.environment_id is not None:
                    recovered_live.append(dep.id)
            await db.execute(update(Backup).where(Backup.status == BackupStatus.PENDING)
                             .values(status=BackupStatus.UNVERIFIED).execution_options(synchronize_session=False))
            await db.execute(update(Snapshot).where(Snapshot.status == SnapshotStatus.PENDING)
                             .values(status=SnapshotStatus.FAILED,
                                     error="Slipway restarted while this snapshot was being taken; take it again")
                             .execution_options(synchronize_session=False))
            checking = list((await db.scalars(select(Snapshot.id).where(Snapshot.status == SnapshotStatus.CHECKING))).all())
        for snapshot_id in checking:
            snapshots.schedule_validation(snapshot_id)
        # A job of an environment recovery marked succeeded has no Retry, and its chain hook never ran: the
        # environment's notice offers the next job instead (§8.5, §9.13).
        for dep_id in recovered_live:
            with contextlib.suppress(Exception):
                await environments.chain_notice(dep_id, why="restart")

    async def shutdown(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)


def _declared_data(dep: Deployment) -> bool:
    """Whether an interrupted deploy's slipway.yml declared data (its backup step got past "declares no data")."""
    row = next((r for r in dep.steps or [] if r.get("key") == "backup"), None)
    if row is None:
        return False
    return not (row.get("status") in ("pending", "skipped") and row.get("note") in (None, "slipway.yml declares no data"))


async def _recovery_owner(db: Any, dep: Deployment) -> Instance | None:
    """The data owner of an interrupted member job, when it isn't the job's own instance (phase 3 §9.13)."""
    instance = dep.instance
    if instance is None or instance.environment_id is None:
        return None
    owner = await environments.owner_of(db, instance)
    return owner if owner is not None and owner.id != instance.id else None


async def _settles_owner(db: Any, dep: Deployment, owner: Instance | None) -> bool:
    """Whether a slot deploy that went live settles its data owner's dirty state: its ``first`` is a deploy of
    this same slot (a retry, or a new deploy of the slot that failed), as ``_success_record`` has it (§7.5)."""
    if owner is None or (dep.kind or DeploymentKind.DEPLOY) != DeploymentKind.DEPLOY:
        return False
    first = (owner.data_dirty or {}).get("first") or {}
    first_id = data._uuid(first.get("deployment_id"))
    if first_id is None:
        return False
    first_dep = await db.get(Deployment, first_id)
    return first_dep is not None and first_dep.kind == DeploymentKind.DEPLOY and first_dep.instance_id == dep.instance_id


def _recover_instance(dep: Deployment, *, owner: Instance | None = None, settles: bool = False) -> None:
    """The instance fields an interrupted job leaves, as ``_failure_fields`` sets them for a failed one (§7.1).

    A job of a whole environment has no instance (S8b's jobs settle their own). For an app slot whose data owner
    is another instance (``owner``), the phase 2 data fields are written there (§7.5). A data owner job that had
    stopped the app slots leaves them stopped, and its dirty state names them (§9.13).
    """
    instance = dep.instance
    if instance is None:
        return
    kind = dep.kind or DeploymentKind.DEPLOY
    app = instance.build_source == BuildSource.APP
    if app and kind in data.DATA_ONLY_KINDS:
        # Data-only jobs never change the status, but a snapshot cut off with the app stopped leaves it stopped.
        if instance.status == InstanceStatus.RUNNING and data.left_stopped(dep):
            instance.status = InstanceStatus.STOPPED
            dep.error = (f"{dep.error}. The app was stopped for the snapshot and Slipway didn't start it again; "
                         "start it on the instance page.")
        down = data.slots_left_stopped(dep)
        if down:  # mode server: the app slots were stopped, the data server kept running
            dep.error = f"{dep.error}. {_left_down_text(down, 'the snapshot')}"
        return
    if app and kind in data.PIPELINE_KINDS and (instance.app_state or {}).get("went_live") == dep.id.hex:
        _recover_live(dep, owner=owner, settles=settles)
        return
    if app and kind in data.PIPELINE_KINDS and (kind != DeploymentKind.DEPLOY or _declared_data(dep)) \
            and data.change_began(dep):
        step = next((r.get("key") for r in dep.steps or [] if r.get("status") in ("failed", "running")), None)
        target = owner if owner is not None else instance
        dirty = data.mark_dirty(target.data_dirty, dep, step=step)
        if (dep.options or {}).get("slots_were"):
            last = dict(dirty.get("last") or {})
            last["slots_stopped"] = _left_down(dep.options or {})
            dirty["last"] = last
            if step == "start_slots":
                dirty["hold"] = True
        target.data_dirty = dirty
        start_over = kind == DeploymentKind.RESET and bool((dep.options or {}).get("start_over"))
        if instance.status == InstanceStatus.DEPLOYING:
            prev = (dep.options or {}).get("prev_status") if start_over else None
            instance.status = prev or InstanceStatus.FAILED
        return
    if app and kind in data.RESTORE_KINDS:
        if instance.status == InstanceStatus.DEPLOYING:
            instance.status = (dep.options or {}).get("prev_status") or InstanceStatus.FAILED
        down = data.slots_left_stopped(dep)
        if down:  # cut off in stop_slots: the data is as it was, the slots it stopped stay stopped
            dep.error = f"{dep.error}. {_left_down_text(down, f'the {data.kind_noun(kind)}')}; nothing else was changed"
        return
    if instance.status == InstanceStatus.DEPLOYING:
        instance.status = InstanceStatus.FAILED


def _left_down_text(slots: list[str], what: str) -> str:
    """The note of a job Slipway lost after its stop_slots stopped running app slots it never started again."""
    them = "it" if len(slots) == 1 else "them"
    return (f"Slipway stopped {' and '.join(s.capitalize() for s in slots)} for {what} and didn't start {them} "
            f"again: start {them} on the instance page")


def _recover_live(dep: Deployment, *, owner: Instance | None = None, settles: bool = False) -> None:
    """A job Slipway lost after its ``finish`` made the release live (app_state.went_live names it): it
    succeeded (D12), as ``_end_after_live`` records it in-process, with ``_success_record``'s data fields (§7.5).
    The steps after finish that it was cut off in become warnings, the ones it never reached are skipped.
    live_identity was saved at finish (an app slot's first deploy saves its owner's in the same transaction).

    ``settles``: an app slot deploy whose owner's dirty state names a deploy of this same slot first."""
    instance = dep.instance
    kind = dep.kind or DeploymentKind.DEPLOY
    missed = _seed_missed(kind, list(dep.steps or []), dict(dep.options or {}), instance,
                          never_live=instance.current_commit_sha is None)
    dep.status = DeploymentStatus.SUCCEEDED
    dep.error = None
    dep.steps = _settle_after_live(list(dep.steps or []), "Interrupted by a Slipway restart",
                                   "Not run: Slipway restarted")
    live = data.live_state(instance) or {}
    instance.status = InstanceStatus.RUNNING
    instance.current_commit_sha = str(live.get("sha") or dep.commit_sha or instance.current_commit_sha or "") or None
    instance.last_deployed_at = dep.finished_at or utcnow()
    target = owner if owner is not None else instance  # an app slot's data fields are its owner's (§7.5)
    server_deploy = (instance.environment_id is not None and instance.slot == environments.DATA_SLOT
                     and kind == DeploymentKind.DEPLOY)
    if owner is None and server_deploy:
        # It ran no app migration: the dirty state stays, and fresh_data too, so the first app slot deploy on
        # the empty data still creates the first admin.
        target.seed_snapshot_id = None
    elif owner is None:
        target.data_dirty = null()
        target.seed_snapshot_id = None
        target.fresh_data = None
    elif kind == DeploymentKind.DEPLOY:
        target.seed_snapshot_id = None
        target.fresh_data = None
        if settles:
            target.data_dirty = null()
    if missed:
        target.content_pending = True


runner = DeployRunner()


async def run_on_instance(
    instance: Instance, command: str, *, connect: ConnectFactory = ssh.open_session, check: bool = True
) -> str:
    async with connect(ssh.SSHTarget.from_host(instance.host)) as remote:
        _, output = await remote.run(command, check=check, timeout=120)
    return output
