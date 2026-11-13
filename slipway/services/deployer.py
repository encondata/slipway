"""Build and run instances on remote Docker hosts over SSH.

Pipeline for one deployment:

1. Check the repository by its GitHub id, then resolve the branch to a commit SHA.
2. Download the source tarball on the Slipway server (the GitHub token never reaches the host)
   and refuse it if the build context, Dockerfile or compose file path is a link.
3. Upload it over SFTP and unpack into ``<deploy_root>/<slug>/releases/<sha12>-<deployment>``.
4. Write ``shared/.env`` (mode 600) from the instance's encrypted environment variables.
   Compose mode writes them to ``shared/slipway.env`` and builds ``shared/.env`` on the host
   from the repository's ``.env`` followed by Slipway's values, so Slipway's values win. (A repository
   value that interpolates one Slipway overrides keeps the repository's value in ``${...}`` of the
   compose file; ``env_file: .env`` sees Slipway's.)
5. Check the host ports the deployment publishes against the ports in use on the host, and
   move taken ones to the next free port when the instance allows it (see ``services.ports``).
   Compose mode reads them from ``docker compose config`` and passes moved ports back through
   the compose file's own variables or ``shared/compose.ports.yml``.
6. ``docker build`` + ``docker run`` (Dockerfile mode) or ``docker compose up -d --build``.
7. Point ``current`` at the new release and prune old releases/images.

Every deployment gets its own release directory, so the one ``current`` points to is never
touched by a redeploy. A failed deployment removes its release again unless containers were
started from it. Persistent data must live in named volumes or absolute host paths:
relative bind mounts (``./data``) do not survive a redeploy.
"""

from __future__ import annotations

import asyncio
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
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, update

from slipway.db.base import Base, utcnow
from slipway.db.session import session_scope
from slipway.models import BuildSource, Deployment, DeploymentStatus, Instance, InstanceStatus, Repository, User
from slipway.services import ports, ssh
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
    root: str
    slug: str

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
    def current(self) -> str:
        return f"{self.base}/current"

    def release(self, sha: str, deployment_id: uuid.UUID) -> str:
        return f"{self.releases}/{sha[:12]}-{deployment_id.hex[:8]}"


def paths_for(instance: Instance) -> InstancePaths:
    if not SLUG_RE.match(instance.slug):
        raise DeployError(f"Invalid instance slug {instance.slug!r}")
    return InstancePaths(clean_deploy_root(instance.host.deploy_root), instance.slug)


def _compose(instance: Instance, override: str | None = None) -> str:
    """The compose command line. ``override`` (the ports override file) is only passed where
    containers are created; start, stop, restart and logs do not depend on the host ports."""
    env_file = paths_for(instance).env_file
    extra = f" -f {q(override)}" if override else ""
    return f"docker compose -p {q(instance.compose_project)} --env-file {q(env_file)} -f {q(instance.compose_file)}{extra}"


def compose_config_command(instance: Instance, release_dir: str, *, override: str | None = None, interpolate: bool = True) -> str:
    """Print the resolved compose file as JSON, folded into short lines (join them with no separator).

    Run after the merged ``.env`` is in place. On failure prints Compose's error instead. The
    output holds environment values: it is parsed, never logged.
    """
    compose = _compose(instance, override)
    flag = "" if interpolate else " --no-interpolate"
    return (
        f"cd {q(release_dir)} && "
        f"{{ out=$({compose} config --format json{flag} 2>/dev/null) || {{ {compose} config --quiet{flag}; exit 1; }}; }} && "
        "if command -v fold >/dev/null 2>&1; then printf '%s\\n' \"$out\" | fold -w 4000; else printf '%s\\n' \"$out\"; fi"
    )


def _label(instance: Instance) -> str:
    return f"slipway.instance={instance.id}"


def _remove_containers(instance: Instance) -> str:
    """Remove the Dockerfile-mode container and its anonymous volumes.

    Containers are found by this instance's label, never by name alone, so a container of
    another instance that happens to have the same name is left alone.
    """
    return f"docker ps -aq --filter {q('label=' + _label(instance))} | xargs -r docker rm -f -v >/dev/null 2>&1 || true"


def _compose_project_down(instance: Instance) -> str:
    """Remove the compose project's containers (with anonymous volumes) by project name."""
    p = q(instance.compose_project)
    return f"(cd / && docker compose -p {p} rm -f -s -v; docker compose -p {p} down --remove-orphans) >/dev/null 2>&1 || true"


PULL_NEVER_UNSUPPORTED = "docker run on this host does not accept --pull=never: Slipway needs Docker 20.10 or later"
# Parses the run flags without running anything. An older CLI rejects --pull only when the
# container is started, after the running one was removed, so this runs before the build.
_PULL_NEVER_CHECK = f"docker run --pull=never --help >/dev/null 2>&1 || {{ echo {q(PULL_NEVER_UNSUPPORTED)}; exit 1; }}"


def _root_rm(parent: str, name: str) -> str:
    """Delete ``parent/name`` through a throwaway container, for files containers wrote as root."""
    return f"docker run --rm --network none -v {parent}:/r {CLEANUP_IMAGE} rm -rf -- /r/{name}"


def compose_env_command(instance: Instance, release_dir: str) -> str:
    """Build ``shared/.env``: the repository's .env defaults, with Slipway's values after them so they win."""
    paths = paths_for(instance)
    project_dir = posixpath.normpath(posixpath.join(release_dir, posixpath.dirname(instance.compose_file) or "."))
    env, merged = q(paths.env_file), q(paths.env_file + ".new")
    return (
        f"cd {q(project_dir)} && umask 077 && "
        f"{{ if [ -f .env ] && [ ! -L .env ]; then cat .env; echo; fi; cat {q(paths.slipway_env_file)}; }} > {merged} && "
        f"mv -f {merged} {env} && ln -sfn {env} .env"
    )


def build_commands(instance: Instance, release_dir: str, sha: str, *, override: str | None = None) -> list[str]:
    """Commands (run in order) that build and start a release.

    ``override`` is the compose ports override file, when Slipway moved ports that the compose
    file fixes.
    """
    paths = paths_for(instance)
    label = _label(instance)
    if instance.build_source == BuildSource.COMPOSE:
        return [
            compose_env_command(instance, release_dir),
            _remove_containers(instance),
            f"cd {q(release_dir)} && {_compose(instance, override)} up -d --build --remove-orphans",
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
        f"{_remove_containers(instance)}; {_compose_project_down(instance)}",
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
    if instance.build_source == BuildSource.COMPOSE:
        return f"cd {q(paths_for(instance).current)} && {_compose(instance)} {action}"
    return (
        f"{_owned_container(instance)} || {{ echo {_not_owned_message(instance)}; exit 1; }}; "
        f"docker {action} {q(instance.container_name)}"
    )


CONTAINER_FIELDS = ("Names", "Image", "State", "Status", "Ports", "RunningFor")
# One JSON object per container with only these fields: ``{{json .}}`` includes every label, so
# its line can pass the ``ssh.MAX_LINE_CHARS`` cap and no longer parse.
_CONTAINER_FORMAT = "{" + ",".join(f'"{k}":{{{{json .{k}}}}}' for k in CONTAINER_FIELDS) + "}"


def status_command(instance: Instance) -> str:
    if instance.build_source == BuildSource.COMPOSE:
        flt = f"label=com.docker.compose.project={instance.compose_project}"
    else:
        flt = f"label=slipway.instance={instance.id}"
    return f"docker ps -a --filter {q(flt)} --format {q(_CONTAINER_FORMAT)}"


def logs_command(instance: Instance, tail: int = 200) -> str:
    tail = max(1, min(int(tail), 5000))
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
    return "; ".join([
        _remove_containers(instance),
        _compose_project_down(instance),
        f"(cd {q(paths.current)} && {_compose(instance)} down --remove-orphans --rmi local) >/dev/null 2>&1",
        images,
        "true",
    ])


def leftovers_command(instance: Instance) -> str:
    """Prints the ids of any container still belonging to the instance (stderr is mixed in)."""
    return (
        f"docker ps -aq --filter {q('label=' + _label(instance))} && "
        f"docker ps -aq --filter {q('label=com.docker.compose.project=' + instance.compose_project)}"
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
    return (
        f"ids=$(docker ps -aq --filter {flt}) && "
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
    paths = paths_for(instance)
    return (
        f"rm -rf -- {q(paths.base)} 2>/dev/null || {_root_rm(q(paths.root), q(instance.slug))}; "
        f"test ! -e {q(paths.base)}"
    )


async def destroy(instance: Instance, *, connect: ConnectFactory = ssh.open_session) -> str | None:
    """Remove the instance's containers, images and files from its host.

    Raises if containers are left behind. Returns a warning naming what is left when only
    files could not be removed.
    """
    paths = paths_for(instance)
    async with connect(ssh.SSHTarget.from_host(instance.host)) as remote:
        await remote.run(teardown_command(instance), timeout=600)
        _, left = await remote.run(leftovers_command(instance), timeout=60)
        if _container_ids(left):
            raise DeployError(f"Containers of {instance.name} are still on {instance.host.name}; nothing was deleted")
        status, output = await remote.run(remove_dir_command(instance), check=False, timeout=600)
    if status == 0:
        return None
    detail = clean_text(output.strip().splitlines()[-1])[:200] if output.strip() else ""
    return f"Could not remove {paths.base} on {instance.host.name}; delete it by hand" + (f" ({detail})" if detail else "")


# ------------------------------------------------------------------ source archive


def guarded_paths(instance: Instance) -> dict[str, tuple[bool, str]]:
    """Release paths the build resolves, mapped to (must be a directory, description).

    Docker and Compose follow symbolic links in these, so a link would make them build from
    (or write to) files outside the release. ``-f`` is resolved from the release root, as
    the build commands run there.
    """
    if instance.build_source == BuildSource.COMPOSE:
        settings = [("compose file", instance.compose_file, False)]
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


@dataclass
class _Job:
    instance: Instance
    branch: str
    user: User | None
    env: dict[str, str] | None  # None when the stored values cannot be decrypted


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
        dep.status = DeploymentStatus.RUNNING
        dep.started_at = utcnow()
        instance.status = InstanceStatus.DEPLOYING
        return _Job(instance=instance, branch=dep.branch, user=dep.triggered_by, env=env)


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
) -> ports.PortPlan:
    """Check ``declared`` against the host, move clashes if allowed, and store the result.

    Raises DeployError on a clash the instance does not allow Slipway to move.
    """
    overrides: dict[tuple[str | None, int, str], int] = {}
    if instance.build_source == BuildSource.COMPOSE:
        for o in instance.port_overrides or []:
            overrides[(o["service"], int(o["container"]), o.get("protocol") or "tcp")] = int(o["host"])
    async with _host_port_locks[instance.host_id]:
        _, output = await remote.run(ports.SCAN_COMMAND, check=False, timeout=60)
        host_ports = ports.parse_scan(output, instance_id=str(instance.id), compose_project=instance.compose_project)
        for port, protocol, name in await _reserved_ports(instance):
            host_ports.reserve(port, protocol, f"Slipway instance {name}")
        try:
            plan = ports.plan(declared, host_ports, overrides=overrides, auto=instance.auto_ports, host_name=instance.host.name)
        except ports.PortError as exc:
            raise DeployError(str(exc)) from exc
        for wanted, given, why in plan.moved:
            await sink.line(f"Host port {wanted.describe()} is {why}; using {given.host} instead")
        fields: dict[str, Any] = {"published_ports": ports.binding_rows(plan)}
        if instance.build_source == BuildSource.COMPOSE:
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
        return ports.parse_compose_json("".join(output.splitlines()))
    except ports.PortError as exc:
        raise DeployError(str(exc)) from exc


async def _prepare_compose_ports(
    remote: ssh.RemoteSession, instance: Instance, release: str, env: dict[str, str], sink: LogSink,
) -> str | None:
    """Check the compose file's host ports and pass any that move back to Compose.

    Runs after ``shared/.env`` is merged. Returns the override file to pass to ``up``, if any.
    """
    paths = paths_for(instance)
    await sink.line("Checking the host ports the compose file publishes")
    config = await _compose_config(remote, instance, release)
    try:
        raw = await _compose_config(remote, instance, release, interpolate=False)
    except (DeployError, ssh.SSHError):
        raw = None  # only needed to find port variables; without it moved ports use the override file
    declared = ports.compose_bindings(config, raw)
    plan = await _plan_ports(remote, instance, declared, sink)
    variables, override = ports.compose_changes(plan, config)
    for old, new in plan.changed:
        if not any(old.key == w.key for w, _, _ in plan.moved):
            await sink.line(f"Using host port {new.host} for {old.service} container port {old.container} (port override)")
    await remote.run(f"rm -f -- {q(paths.ports_override_file)}")
    if variables:
        await remote.write_text(paths.slipway_env_file, render_compose_env({**env, **variables}))
        await remote.run(compose_env_command(instance, release))
        await sink.line("Set " + ", ".join(f"{k}={v}" for k, v in sorted(variables.items())) + " for the compose file")
    if override is None and not variables:
        return None
    if override is not None:
        await remote.write_text(paths.ports_override_file, override)
        await sink.line(f"Wrote host port changes to {paths.ports_override_file}")
    # Check that Compose applied them: an older Compose ignores !override.
    applied = ports.compose_bindings(await _compose_config(remote, instance, release, override=override and paths.ports_override_file))
    want = sorted((b.service or "", b.container, b.protocol, b.host_ip, b.host) for b in plan.bindings)
    got = sorted((b.service or "", b.container, b.protocol, b.host_ip, b.host) for b in applied)
    if want != got:
        raise DeployError(
            f"Docker Compose on {instance.host.name} did not apply the new host ports. Moving a port the compose "
            "file sets as a number needs Docker Compose 2.24.4 or later; or take the port from a variable, "
            "such as \"${WEB_PORT:-8080}:80\""
        )
    return paths.ports_override_file if override is not None else None


async def _install(
    remote: ssh.RemoteSession, instance: Instance, deployment_id: uuid.UUID, sha: str, tarball: Path,
    env: dict[str, str], sink: LogSink,
) -> None:
    paths = paths_for(instance)
    release = paths.release(sha, deployment_id)
    upload = f"{paths.releases}/.upload-{deployment_id.hex}.tar.gz"
    compose = instance.build_source == BuildSource.COMPOSE
    await remote.run(f"mkdir -p {q(paths.releases)} {q(paths.shared)}")
    try:
        await remote.put(tarball, upload)
        await remote.run(unpack_command(release, upload))
        await sink.line(f"Unpacked release into {release}")
        if compose:
            env_path, content = paths.slipway_env_file, render_compose_env(env)
        else:
            env_path, content = paths.env_file, render_env(env)
        await remote.write_text(env_path, content)
        await sink.line(f"Wrote {len(env)} environment variable(s) to {env_path}")

        override = None
        commands = build_commands(instance, release, sha)
        if compose:
            await sink.line(f"$ {commands[0]}")
            await remote.run(commands[0], on_line=sink.line, timeout=3600)
            override = await _prepare_compose_ports(remote, instance, release, env, sink)
            commands = build_commands(instance, release, sha, override=override)[1:]
        elif instance.ports:
            await _plan_ports(remote, instance, ports.dockerfile_bindings(instance.ports), sink)
            commands = build_commands(instance, release, sha)
        for command in commands:
            await sink.line(f"$ {command}")
            await remote.run(command, on_line=sink.line, timeout=3600)
    except Exception:
        await _discard_release(remote, instance, release, upload, sink)
        raise
    await remote.run(f"ln -sfn {q(release)} {q(paths.current)}")
    await sink.line(f"Switched {paths.current} to {release}")
    status, output = await remote.run(prune_command(instance, release), check=False, timeout=600)
    if status != 0:
        detail = " ".join(output.strip().splitlines()[-3:])
        await sink.line(f"Warning: some old releases could not be removed. {detail}".strip())


async def _pipeline(
    deployment_id: uuid.UUID, job: _Job, sink: LogSink, connect: ConnectFactory, github: GitHubFactory
) -> CommitInfo:
    instance, branch = job.instance, job.branch
    repo, host = instance.repository, instance.host
    if job.env is None:
        raise DeployError(ENV_UNREADABLE)
    token, source = github_token_for(job.user)
    await sink.line(f"Resolving {repo.full_name}@{branch} using {source}")
    async with github(token) as gh:
        await _check_repository(gh, repo, sink)
        commit = await gh.get_commit(repo.github_id, branch)
        if not _SHA_RE.match(commit.sha or ""):
            raise DeployError(f"GitHub returned an invalid commit id for {branch}")
        message = _fit(Deployment, "commit_message", commit.message or "")
        author = _fit(Deployment, "commit_author", commit.author or "")
        async with session_scope() as db:
            await db.execute(
                update(Deployment)
                .where(Deployment.id == deployment_id)
                .values(commit_sha=commit.sha, commit_message=message, commit_author=author or None)
            )
        await sink.line(f"Commit {commit.sha[:7]} — {message} ({author})")

        with tempfile.TemporaryDirectory(prefix="slipway-") as tmp:
            tarball = Path(tmp) / "source.tar.gz"
            size = await gh.download_tarball(repo.github_id, commit.sha, tarball)
            await sink.line(f"Downloaded source archive ({size / 1024:.0f} KiB)")
            await asyncio.to_thread(check_source_archive, tarball, guarded_paths(instance))

            await sink.line(f"Connecting to {host.username}@{host.address}")
            async with connect(ssh.SSHTarget.from_host(host)) as remote:
                await _install(remote, instance, deployment_id, commit.sha, tarball, job.env, sink)
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
    try:
        commit = await _pipeline(deployment_id, job, sink, connect, github)
    except asyncio.CancelledError:
        await sink.line("Deployment interrupted: Slipway is shutting down")
        await sink.close()
        await _finish(deployment_id, DeploymentStatus.CANCELLED, error="Interrupted", short=True, status=InstanceStatus.FAILED)
        raise
    except Exception as exc:
        log.info("Deployment %s failed: %s", deployment_id, exc)
        await sink.line(f"Deployment failed: {exc}")
        await sink.close()
        await _finish(deployment_id, DeploymentStatus.FAILED, error=str(exc), status=InstanceStatus.FAILED)
        return
    await sink.line("Deployment succeeded")
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
