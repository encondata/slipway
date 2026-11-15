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

Claimed instances (see ``api.v1.unmanaged``) were running before Slipway knew them. A claimed
compose project keeps its project name, so Compose replaces its containers and keeps its named
volumes. A claimed standalone container is stopped just before ``docker run``, removed once the
new container started (or started again if it did not), and reached by its id until then. No
command run for a claimed instance removes a volume.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import posixpath
import re
import shlex
import tarfile
import tempfile
import time
import uuid
import zlib
from collections import Counter, defaultdict, deque
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, update

from slipway.db.base import Base, utcnow
from slipway.db.session import session_scope
from slipway.models import BuildSource, Deployment, DeploymentStatus, Host, Instance, InstanceStatus, Repository, User
from slipway.services import manifest, ports, ssh, switchyard
from slipway.services.github import CommitInfo, GitHubClient, GitHubError
from slipway.services.repos import github_token_for

log = logging.getLogger(__name__)

q = shlex.quote
KEEP_RELEASES = 3
SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SAFE_PATH = re.compile(r"^[A-Za-z0-9._/@+-]+$")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
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
SLIPWAY_ENTRIES = ("releases", "shared", "current", MARKER_FILE)
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
        stop = state.get("commands", {}).get("stop")
        if stop:
            app.append(f"({app_command(paths.current, list(stop))}) >/dev/null 2>&1")
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


def keep_env_command(instance: Instance) -> str:
    """App mode: copy ``shared/.env`` out of the folder (mode 600) when the app's projects still have volumes,
    so their data can be opened again. Prints ``KEPT_MARK`` when it copied it."""
    paths = paths_for(instance)
    dest = kept_env_path(paths, instance)
    vols = "; ".join(f"docker volume ls -q --filter {_project_filter(p)}" for p in app_known_projects(instance))
    return (
        f"v=$({{ {vols}; }} 2>/dev/null); [ -n \"$v\" ] && [ -f {q(paths.env_file)} ] || exit 0; "
        f"umask 077 && mkdir -p {q(posixpath.dirname(dest))} && cp -f {q(paths.env_file)} {q(dest)} && echo {q(KEPT_MARK)}"
    )


async def destroy(instance: Instance, *, connect: ConnectFactory = ssh.open_session) -> str | None:
    """Remove the instance's containers, images and files from its host.

    Raises if containers are left behind. Returns a warning naming what is left when only
    files could not be removed, or, for an app whose volumes stay, where its ``.env`` was kept.
    """
    paths = paths_for(instance)
    host = instance.host.name
    kept: str | None = None  # where the app's .env was copied
    keep_folder = False  # the copy failed: the folder, with its .env, stays
    async with connect(ssh.SSHTarget.from_host(instance.host)) as remote:
        if instance.build_source == BuildSource.APP and app_known_projects(instance):
            # The volumes stay (Slipway never removes data); their secrets are only in the .env and this row.
            status, output = await remote.run(keep_env_command(instance), check=False, timeout=120)
            if status == 0 and any(line.strip() == KEPT_MARK for line in output.splitlines()):
                kept = kept_env_path(paths, instance)
            elif status != 0:
                keep_folder = True
        await remote.run(teardown_command(instance), timeout=600)
        _, left = await remote.run(leftovers_command(instance), timeout=60)
        if _container_ids(left):
            if kept:  # the instance stays: so does its .env, in its folder
                with contextlib.suppress(Exception):
                    await remote.run(f"rm -f -- {q(kept)}", check=False, timeout=60)
            raise DeployError(f"Containers of {instance.name} are still on {host}; nothing was deleted")
        notes = [f"Kept the app's volumes on {host}, and its settings and secrets in {kept} "
                 f"(readable only by {instance.host.username})"] if kept else []
        if keep_folder:
            return (f"Kept {paths.base} on {host}: the app's volumes stay, and its settings and secrets could not be "
                    f"copied to {posixpath.dirname(kept_env_path(paths, instance))}, so they stay in {paths.env_file}")
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


def move_prepare_command(new: list[InstancePaths]) -> str:
    """Create the new folders' parents and check nothing is in the way; on failure prints a MOVE_MARK line.

    A new folder may already exist if it is empty (made in advance, say); it is removed so the copy
    can take its name.
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


def _remove_base_command(paths: InstancePaths) -> str:
    """Remove what Slipway put in the folder, then the folder if nothing else is in it.

    Files someone else put there stay: the command then prints ``LEFT_MARK`` and their names, and
    fails. Files containers wrote as root are removed through a throwaway container.
    """
    base = q(paths.base)
    parts = [f"[ -e {base} ] || [ -L {base} ] || exit 0; cd {base} || exit 1"]
    for name in ("releases", "shared"):
        parts.append(f"{{ rm -rf -- {name} 2>/dev/null || {_root_rm(base, name)} >/dev/null 2>&1; }}")
    parts.append(f"rm -f -- current {MARKER_FILE}; cd / && rmdir -- {base} 2>/dev/null")
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
        status, output = await remote.run(move_prepare_command([new for _, _, new in moves]), check=False, timeout=60)
        if status:
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
                status, output = await remote.run(_remove_base_command(old), check=False, timeout=600)
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
    """

    def __init__(self, deployment_id: uuid.UUID, flush_interval: float = 1.0) -> None:
        self.deployment_id = deployment_id
        self.flush_interval = flush_interval
        self._buf: list[str] = []
        self._size = 0  # characters stored or waiting in _buf
        self._new = 0  # lines since the last flush attempt
        self._tail: deque[str] = deque()
        self._tail_size = 0
        self._dropped = 0
        self._truncated = False
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def line(self, text: str) -> None:
        entry = f"[{utcnow():%H:%M:%S}] {ssh.clip_line(clean_text(text))}\n"
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
    **instance_fields: Any,
) -> None:
    """Record the outcome, retrying with backoff so a deployment never stays running."""
    if error is not None:
        error = clean_text(error)[:2000]
    delays = FINISH_RETRY_DELAYS[:3] if short else FINISH_RETRY_DELAYS
    for attempt in range(len(delays) + 1):
        try:
            async with session_scope() as db:
                instance_id = await db.scalar(select(Deployment.instance_id).where(Deployment.id == deployment_id))
                if instance_id is None:
                    return
                await db.execute(
                    update(Deployment)
                    .where(Deployment.id == deployment_id)
                    .values(status=dep_status, error=error, finished_at=utcnow())
                )
                if instance_fields:
                    await db.execute(update(Instance).where(Instance.id == instance_id).values(**instance_fields))
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
    "manifest": "Read slipway.yml",
    "settings": "Write the settings",
    "ports": "Check host ports",
    "build": "Build",
    "start": "Start",
    "finish": "Switch to the new release",
    "proxy": "Update Switchyard",
}
STEP_STATES = ("pending", "running", "succeeded", "failed", "skipped", "warning")
# The header line each step starts with in the log; the deployment page splits the log on it.
STEP_MARK = "── Step "


def step_keys(instance: Instance) -> list[str]:
    if instance.build_source == BuildSource.APP:
        return ["resolve", "source", "upload", "manifest", "ports", "settings", "build", "start", "finish", "proxy"]
    return ["resolve", "source", "upload", "settings", "ports", "build", "start", "finish", "proxy"]


def new_steps(instance: Instance) -> list[dict[str, Any]]:
    return [{"key": k, "name": STEP_NAMES[k], "status": "pending"} for k in step_keys(instance)]


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
            row["note"] = clean_text(note)[:300]
        self._current = None
        await self._save()

    async def skip(self, key: str, note: str) -> None:
        i, row = self._row(key)
        row.update(status="skipped", note=clean_text(note)[:300])
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


async def _start(deployment_id: uuid.UUID) -> _Job | None:
    async with session_scope() as db:
        dep = await db.get(Deployment, deployment_id)
        if dep is None or dep.status != DeploymentStatus.QUEUED:
            return None
        instance = dep.instance
        env = instance.env
        if env is None:
            stored = await db.scalar(select(Instance.env.is_not(None)).where(Instance.id == instance.id))
            env = None if stored else {}
        secrets = instance.app_secrets
        if secrets is None:
            stored = await db.scalar(select(Instance.app_secrets.is_not(None)).where(Instance.id == instance.id))
            secrets = None if stored else {}
        retry = None
        if dep.retry_of_id is not None:
            first = await db.get(Deployment, dep.retry_of_id)
            if first is not None and first.commit_sha:
                built = any(r.get("key") == "build" and r.get("status") in ("succeeded", "skipped") for r in first.steps or [])
                named = bool(first.release) and _RELEASE_NAME.fullmatch(posixpath.basename(first.release)) is not None
                retry = _Retry(id=first.id, sha=first.commit_sha, release=first.release,
                               reusable=built and named and first.instance_id == instance.id)
        dep.status = DeploymentStatus.RUNNING
        dep.started_at = utcnow()
        dep.steps = new_steps(instance)
        instance.status = InstanceStatus.DEPLOYING
        return _Job(instance=instance, branch=dep.branch, user=dep.triggered_by, env=env, secrets=secrets,
                    steps=dep.steps, retry=retry)


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
    *, projects: frozenset[str] = frozenset(),
) -> ports.PortPlan:
    """Check ``declared`` against the host, move clashes if allowed, and store the result.

    Raises DeployError on a clash the instance does not allow Slipway to move.
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
    if reuse:
        await _take_dir(remote, instance, sink)
        status, _ = await remote.run(f"[ -d {q(release)} ]", check=False, timeout=60)
        if status:
            raise DeployError(f"The release {release} is no longer on {instance.host.name}; deploy again instead of retrying")
        await steps.skip("upload", f"Reusing {release} from deployment {job.retry.id.hex[:8]}")
    else:
        async with steps.step("upload"):
            await _take_dir(remote, instance, sink)
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
        if run.built or reuse:  # a reused release was kept by the deployment it came from: never remove it
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
            await _save_instance(instance, app_state=state)
        status, output = await remote.run(prune_command(instance, release), check=False, timeout=600)
        if status != 0:
            detail = " ".join(output.strip().splitlines()[-3:])
            await sink.line(f"Warning: some old releases could not be removed. {detail}".strip())
        if state is not None:
            await _prune_app_images(remote, instance, state, sink)


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
                    Deployment.instance_id == instance.id, Deployment.release.is_not(None))
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
        await remote.run(command, on_line=sink.line, timeout=3600)


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
        await remote.run(command, on_line=sink.line, timeout=3600)
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
    return {
        "slug": instance.slug, "name": instance.name, "release": release, "env_dir": paths_for(instance).shared,
        "sha": sha, "sha12": sha[:12], "host": instance.host.address, "deployment": deployment_id.hex[:8],
    }


def app_command(release: str, argv: list[str]) -> str:
    """Run one of slipway.yml's commands from the release: a program in the repository, or one on the PATH."""
    program = argv[0]
    if "/" in program:
        program = "./" + manifest.clean_repo_path(program, "the command")
    return f"cd {q(release)} && {' '.join(q(a) for a in [program, *argv[1:]])}"


async def _save_instance(instance: Instance, **fields: Any) -> None:
    async with session_scope() as db:
        await db.execute(update(Instance).where(Instance.id == instance.id).values(**fields))
    for key, value in fields.items():
        setattr(instance, key, value)


async def _install_app(
    remote: ssh.RemoteSession, instance: Instance, deployment_id: uuid.UUID, sha: str, job: _Job, run: _Run,
    sink: LogSink, steps: Steps,
) -> dict[str, Any]:
    paths = paths_for(instance)
    builtins = app_builtins(instance, run.release, sha, deployment_id)
    env = job.env or {}

    def plan_with(host_ports: dict[str, int]) -> manifest.AppPlan:
        try:
            return manifest.plan(
                man, template=template, builtins=builtins, settings=instance.app_settings or {},
                chosen=instance.app_services, host_ports=host_ports, secrets=secrets, env=env,
            )
        except manifest.ManifestError as exc:
            raise DeployError(str(exc)) from exc

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
            if unset:
                raise DeployError(
                    "The app's stored secrets can't be decrypted with the configured SLIPWAY_ENCRYPTION_KEY. Restore "
                    "the old key (see slipway rotate-encryption-key), or set each of them as an environment variable "
                    f"of the instance: {', '.join(unset)} (their old values, or the app's existing data won't open)")
            await sink.line("The stored secrets can't be decrypted; the instance's environment variables set every one")
        secrets = dict(job.secrets or {})
        fresh = manifest.new_secrets(man, secrets)
        # A secret the instance's variables set is kept as that value (the one the app's data was made with),
        # never replaced by a new one: the variable can then be removed safely.
        adopted = sorted(k for k in fresh if env.get(k))
        fresh.update({k: env[k] for k in adopted})
        secrets.update(fresh)
        first = plan_with({})
        await _check_projects_free(instance, first.projects)
        await _check_projects_on_host(remote, instance, first.projects, [s.key for s in man.secrets], env)
        if fresh:  # kept only once the app may use them
            await _save_instance(instance, app_secrets=secrets)
            generated = sorted(set(fresh) - set(adopted))
            if generated:
                await sink.line(f"Generated {len(generated)} secret(s) and kept them with the instance: {', '.join(generated)}")
            if adopted:
                await sink.line(f"Kept {', '.join(adopted)} from the instance's environment variables as the app's secrets")
        await sink.line(f"{man.name}: running {', '.join(s.name for s in first.services) or 'no services'}")

    planned = [s for s in first.services if s.port_var]
    fixed = [s for s in first.services if s.port is not None and not s.port_var]
    host_ports: dict[str, int] = {}
    if planned:
        async with steps.step("ports"):
            declared = [ports.Binding(service=s.name, container=s.port, protocol=s.protocol, host=s.port) for s in planned]
            port_plan = await _plan_ports(remote, instance, declared, sink, projects=frozenset(first.projects))
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
        final = plan_with(host_ports)
        moved = [p for p in final.projects if p not in first.projects]  # a project name that uses a moved port
        if moved:
            await _check_projects_free(instance, moved)
            await _check_projects_on_host(remote, instance, moved, [s.key for s in man.secrets], env)
        lines, _ = manifest.parse_env_template(template or "")
        try:
            content = manifest.render_env(lines, final.env, final.written)
        except manifest.ManifestError as exc:
            raise DeployError(str(exc)) from exc
        await remote.write_text(paths.env_file, content)
        await sink.line(f"Wrote {len(final.written)} value(s) to {paths.env_file} ({len(man.secrets)} of them secret)")
        old = dict(instance.app_state or {})
        name = posixpath.basename(run.release)
        releases = dict(old.get("releases") or {})
        releases[name] = sorted(set(releases.get(name) or []) | set(final.images))
        known = list(dict.fromkeys([*app_known_projects(instance), *final.projects]))
        # Only what cleanup and the controls need is saved now (the images this release builds, every project
        # the app may have containers in, the ones this release starts); the rest once the release is live, in
        # the finish step.
        await _save_instance(instance, app_state={**old, "releases": releases, "known_projects": known,
                                                  "starting": list(dict.fromkeys([*(old.get("starting") or []),
                                                                                  *final.projects]))})
        state = {
            "manifest": man.to_json(), "routes": final.routes, "projects": final.projects,
            "commands": final.commands, "images": final.images, "releases": releases, "known_projects": known,
        }

    if job.retry is not None and job.retry.reusable and await _images_exist(remote, final.images):
        await steps.skip("build", f"Reusing the images from deployment {job.retry.id.hex[:8]}")
    elif "build" in final.commands:
        async with steps.step("build"):
            await _run_commands(remote, instance, [app_command(run.release, final.commands["build"])], run, sink)
    else:
        await steps.skip("build", "slipway.yml has no build command")
    run.built = True
    async with steps.step("start"):
        await _run_commands(remote, instance, [app_command(run.release, final.commands["start"])], run, sink)
    return state


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
    name = q(paths.slug.replace(".", "\\.") + "-[0-9a-f]*\\.env")
    parts.append(f"{{ ls -1 {kept} 2>/dev/null | grep -x -- {name} | sed {q(f's/^/{HOST_MARK} k /')}; true; }}")
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
    return bool(instance.routes or instance.proxy_entries or
                (instance.build_source == BuildSource.APP and (instance.app_state or {}).get("routes")))


# ------------------------------------------------------------------------ pipeline


async def _pipeline(
    deployment_id: uuid.UUID, job: _Job, sink: LogSink, steps: Steps, connect: ConnectFactory, github: GitHubFactory
) -> CommitInfo:
    instance, branch = job.instance, job.branch
    repo, host = instance.repository, instance.host
    if job.env is None:
        raise DeployError(ENV_UNREADABLE)
    token, source = github_token_for(job.user)
    reuse = job.retry is not None and job.retry.reusable
    with tempfile.TemporaryDirectory(prefix="slipway-") as tmp:
        tarball: Path | None = None
        async with github(token) as gh:
            async with steps.step("resolve"):
                ref = job.retry.sha if job.retry is not None else branch
                what = f"{repo.full_name}@{ref[:12] if job.retry is not None else ref}"
                await sink.line(f"Resolving {what} using {source}"
                                + (f" (the commit of deployment {job.retry.id.hex[:8]})" if job.retry else ""))
                await _check_repository(gh, repo, sink)
                commit = await gh.get_commit(repo.github_id, ref)
                if not _SHA_RE.match(commit.sha or ""):
                    raise DeployError(f"GitHub returned an invalid commit id for {ref}")
                if job.retry is not None and commit.sha != job.retry.sha:
                    raise DeployError("GitHub returned another commit than the one being retried")
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


async def run_deployment(
    deployment_id: uuid.UUID,
    *,
    connect: ConnectFactory = ssh.open_session,
    github: GitHubFactory = GitHubClient,
) -> None:
    try:
        job = await _start(deployment_id)
    except Exception as exc:
        log.warning("Deployment %s could not start: %s", deployment_id, exc)
        await _finish(deployment_id, DeploymentStatus.FAILED, error=f"Could not start the deployment: {exc}")
        return
    if job is None:
        return

    sink = LogSink(deployment_id)
    steps = Steps(deployment_id, job.steps, sink)
    try:
        commit = await _pipeline(deployment_id, job, sink, steps, connect, github)
    except asyncio.CancelledError:
        await sink.line("Deployment interrupted: Slipway is shutting down")
        await steps.close()
        await sink.close()
        await _finish(deployment_id, DeploymentStatus.CANCELLED, error="Interrupted", short=True, status=InstanceStatus.FAILED)
        raise
    except Exception as exc:
        log.info("Deployment %s failed: %s", deployment_id, exc)
        await sink.line(f"Deployment failed: {exc}")
        await steps.close()
        await sink.close()
        await _finish(deployment_id, DeploymentStatus.FAILED, error=str(exc), status=InstanceStatus.FAILED)
        return
    if has_routes(job.instance):
        await steps.begin("proxy")
        try:
            await switchyard.sync_and_store(job.instance, say=sink.line)
        except Exception as exc:  # the containers are running: a proxy problem never fails the deploy
            log.warning("Proxy sync after deployment %s failed: %s", deployment_id, exc)
            await sink.line(f"Proxy: could not update Switchyard: {exc}")
            await steps.end("warning", note=str(exc)[:300])
        else:
            await steps.end("succeeded")
    else:
        await steps.skip("proxy", "No hostnames")
    await sink.line("Deployment succeeded")
    await steps.close()
    await sink.close()
    await _finish(
        deployment_id,
        DeploymentStatus.SUCCEEDED,
        status=InstanceStatus.RUNNING,
        current_commit_sha=commit.sha,
        last_deployed_at=utcnow(),
    )


class DeployRunner:
    """Runs deployments as in-process asyncio tasks, one at a time per instance.

    Good enough for a single Slipway container. Swap for a queue + worker (arq, Celery...)
    if you need deployments to survive restarts or run on several Slipway replicas.
    """

    def __init__(self) -> None:
        self._tasks: set[asyncio.Task[None]] = set()
        self._locks: defaultdict[uuid.UUID, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._pending: Counter[uuid.UUID] = Counter()  # deploy tasks submitted and not finished
        self._exclusive: set[uuid.UUID] = set()
        self._deleting: set[uuid.UUID] = set()

    def submit(self, deployment_id: uuid.UUID, instance_id: uuid.UUID) -> None:
        self._pending[instance_id] += 1

        async def _run() -> None:
            try:
                async with self._locks[instance_id]:
                    await run_deployment(deployment_id)
            finally:
                self._pending[instance_id] -= 1
                if self._pending[instance_id] <= 0:
                    del self._pending[instance_id]

        task = asyncio.create_task(_run(), name=f"deploy-{deployment_id}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def busy(self, instance_id: uuid.UUID) -> bool:
        return self._pending[instance_id] > 0 or instance_id in self._exclusive

    def is_deleting(self, instance_id: uuid.UUID) -> bool:
        return instance_id in self._deleting

    @asynccontextmanager
    async def exclusive(self, instance_id: uuid.UUID, *, deleting: bool = False) -> AsyncIterator[None]:
        """Hold the instance's deploy lock without waiting; raise RunnerBusy if it is in use.

        Deployments submitted meanwhile wait until the block exits.
        """
        if self.busy(instance_id):
            raise RunnerBusy("A deployment or another change is in progress for this instance; try again when it finishes")
        self._exclusive.add(instance_id)
        if deleting:
            self._deleting.add(instance_id)
        try:
            async with self._locks[instance_id]:
                yield
        finally:
            self._exclusive.discard(instance_id)
            self._deleting.discard(instance_id)

    async def recover_interrupted(self) -> None:
        """Mark deployments left queued/running by a previous process as failed."""
        async with session_scope() as db:
            stale = (
                await db.scalars(
                    select(Deployment).where(
                        Deployment.status.in_([DeploymentStatus.QUEUED, DeploymentStatus.RUNNING])
                    )
                )
            ).all()
            for dep in stale:
                dep.status = DeploymentStatus.FAILED
                dep.steps = [{**r, "status": "failed", "note": "Interrupted"} if r.get("status") == "running" else r
                             for r in dep.steps or []]
                dep.error = "Interrupted by a Slipway restart"
                dep.finished_at = utcnow()
                if dep.instance.status == InstanceStatus.DEPLOYING:
                    dep.instance.status = InstanceStatus.FAILED

    async def shutdown(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)


runner = DeployRunner()


async def run_on_instance(
    instance: Instance, command: str, *, connect: ConnectFactory = ssh.open_session, check: bool = True
) -> str:
    async with connect(ssh.SSHTarget.from_host(instance.host)) as remote:
        _, output = await remote.run(command, check=check, timeout=120)
    return output
