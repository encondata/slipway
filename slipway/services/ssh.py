"""SSH access to deployment hosts.

Host keys are pinned on first successful connection (trust on first use). Every later
connection must present the same key, otherwise it is refused with ``HostKeyMismatch``.
"""

from __future__ import annotations

import asyncio
import math
import re
import shlex
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import asyncssh
from asyncssh.public_key import get_default_public_key_algs

from slipway.core.config import get_settings

if TYPE_CHECKING:
    from slipway.models import Host

LineCallback = Callable[[str], Awaitable[None]]
# Output kept per line (the deployment log's cap too), and lines kept when output is streamed.
MAX_LINE_CHARS = 16 * 1024
LINE_TRUNCATED = " [line truncated]"
TAIL_LINES = 15
_SEP = "::slipway::"
_UNSAFE_COMMENT = re.compile(r"[^A-Za-z0-9@._-]+")
CREDENTIALS_UNREADABLE = "No usable SSH credentials are stored for this host (missing or could not be decrypted); re-enter them on the host page"
_KEY_MISMATCH = (
    "The host key presented by the server does not match the pinned key. "
    "If the server was rebuilt, reset the pinned key; otherwise this may be an attack."
)
# Prefer ed25519 when pinning, so a later removal of a legacy RSA host key does not break the pin.
_HOST_KEY_ALGS = sorted((a.decode() for a in get_default_public_key_algs()), key=lambda a: a != "ssh-ed25519")
# How a server that cannot use the pinned key type ends the handshake.
_HANDSHAKE_FAILURES = (asyncssh.DisconnectError, ConnectionResetError, ConnectionAbortedError, BrokenPipeError)


class SSHError(RuntimeError):
    pass


class HostKeyMismatch(SSHError):
    pass


class HostKeyNotPinned(SSHError):
    pass


class CommandFailed(SSHError):
    def __init__(self, command: str, exit_status: int, output: str) -> None:
        tail = "\n".join(output.strip().splitlines()[-TAIL_LINES:])
        super().__init__(f"Command exited with status {exit_status}:\n{tail}")
        self.command = command
        self.exit_status = exit_status
        self.output = output


@dataclass
class SSHTarget:
    hostname: str
    port: int
    username: str
    private_key: str | None = None
    key_passphrase: str | None = None
    password: str | None = None
    pinned_host_key: str | None = None

    @classmethod
    def from_host(cls, host: Host) -> SSHTarget:
        return cls(
            hostname=host.hostname,
            port=host.port,
            username=host.username,
            private_key=host.private_key if host.auth_method == "key" else None,
            key_passphrase=host.key_passphrase,
            password=host.password if host.auth_method == "password" else None,
            pinned_host_key=host.host_key,
        )


@dataclass
class ProbeResult:
    host_key: str
    fingerprint: str
    os_info: str
    cpus: int
    cpu_percent: float
    mem_total_mb: int
    mem_percent: float
    docker_version: str | None
    docker_error: str | None
    containers_running: int
    disk_percent: float | None = None  # use of the disk holding Docker's data (or /); None when unknown

    @property
    def metrics(self) -> dict[str, float | int]:
        metrics: dict[str, float | int] = {
            "cpus": self.cpus,
            "cpu_percent": round(self.cpu_percent, 1),
            "mem_total_mb": self.mem_total_mb,
            "mem_percent": round(self.mem_percent, 1),
            "containers_running": self.containers_running,
        }
        if self.disk_percent is not None:
            metrics["disk_percent"] = round(self.disk_percent, 1)
        return metrics


# ---------------------------------------------------------------------------- keys


def clip(value: str, limit: int) -> str:
    """Make remote-supplied text storable: PostgreSQL rejects NUL bytes and over-long values."""
    return value.replace("\x00", "")[:limit]


def clip_line(line: str) -> str:
    """``line`` cut to ``MAX_LINE_CHARS``, marked when something was cut."""
    return line if len(line) <= MAX_LINE_CHARS else line[:MAX_LINE_CHARS] + LINE_TRUNCATED


def safe_comment(comment: str | bytes | None) -> str:
    """A key comment reduced to characters that are safe inside a shell command line."""
    if isinstance(comment, bytes):
        comment = comment.decode("utf-8", "replace")
    return _UNSAFE_COMMENT.sub("-", comment or "").strip("-")[:100]


def public_key_line(key: asyncssh.SSHKey) -> str:
    """The OpenSSH public key line for ``key``, with its comment sanitized (or dropped)."""
    algorithm, data = key.export_public_key("openssh").decode().split()[:2]
    comment = safe_comment(key.get_comment_bytes())
    return f"{algorithm} {data} {comment}" if comment else f"{algorithm} {data}"


def generate_keypair(comment: str = "slipway") -> tuple[str, str]:
    """Return (private_key_openssh, public_key_openssh) for a new ed25519 key."""
    key = asyncssh.generate_private_key("ssh-ed25519", comment=safe_comment(comment) or None)
    return key.export_private_key("openssh").decode(), public_key_line(key)


def public_key_from_private(private_key: str, passphrase: str | None = None) -> str:
    try:
        key = asyncssh.import_private_key(private_key, passphrase)
    except (asyncssh.KeyImportError, ValueError) as exc:
        raise SSHError(f"Invalid private key: {exc}") from exc
    return public_key_line(key)


def fingerprint(public_key: str) -> str:
    return asyncssh.import_public_key(public_key).get_fingerprint("sha256")


# ---------------------------------------------------------------------- connection


class RemoteSession:
    """An open SSH connection with the helpers the deployer needs."""

    def __init__(self, conn: asyncssh.SSHClientConnection) -> None:
        self.conn = conn

    async def run(
        self,
        command: str,
        *,
        check: bool = True,
        on_line: LineCallback | None = None,
        timeout: float | None = None,
    ) -> tuple[int, str]:
        """Run ``command`` with ``/bin/sh`` and return (exit status, output with stderr mixed in).

        sshd hands the command to the user's login shell, so it is wrapped in ``exec /bin/sh -c``:
        Slipway's commands are POSIX sh, which zsh, for one, parses differently. stdin is closed,
        so nothing remote can wait for input. With ``on_line`` every line is passed on and only
        the last ``TAIL_LINES`` are returned, so a long build cannot fill memory. Returned lines
        are cut to ``MAX_LINE_CHARS`` (and marked); ``CommandFailed`` names ``command`` itself.
        """
        lines: deque[str] | list[str] = deque(maxlen=TAIL_LINES) if on_line is not None else []
        callback_error: Exception | None = None  # raised by on_line: passed through, not blamed on SSH
        try:
            async with self.conn.create_process(
                "exec /bin/sh -c " + shlex.quote(command),
                stdin=asyncssh.DEVNULL,
                stderr=asyncssh.STDOUT,
                encoding="utf-8",
                errors="replace",
            ) as proc:

                async def pump() -> None:
                    nonlocal callback_error
                    async for raw in proc.stdout:
                        if not raw:  # EOF marker; a real blank line arrives as "\n"
                            continue
                        line = raw.rstrip("\r\n").replace("\x00", "")
                        lines.append(clip_line(line))
                        if on_line is not None:
                            try:
                                await on_line(line)
                            except Exception as exc:
                                callback_error = exc
                                raise

                try:
                    await asyncio.wait_for(pump(), timeout)
                except TimeoutError as exc:
                    if exc is callback_error:
                        raise
                    with suppress(asyncssh.Error, OSError):
                        proc.kill()
                    raise SSHError(f"Command timed out after {timeout}s") from exc
                await proc.wait()
                status = proc.exit_status if proc.exit_status is not None else -1
        except (asyncssh.Error, OSError) as exc:
            if exc is callback_error:
                raise
            raise SSHError(f"SSH command failed: {exc}") from exc
        output = "\n".join(lines)
        if check and status != 0:
            raise CommandFailed(command, status, output)
        return status, output

    async def put(self, local: Path, remote: str) -> None:
        try:
            async with self.conn.start_sftp_client() as sftp:
                await sftp.put(str(local), remote)
        except (asyncssh.Error, OSError) as exc:
            raise SSHError(f"Could not upload {remote}: {exc}") from exc

    async def write_text(self, remote: str, content: str, mode: int = 0o600) -> None:
        try:
            async with self.conn.start_sftp_client() as sftp:
                attrs = asyncssh.SFTPAttrs(permissions=mode)
                async with sftp.open(remote, "w", attrs) as fh:
                    await fh.write(content)
                await sftp.chmod(remote, mode)
        except (asyncssh.Error, OSError) as exc:
            raise SSHError(f"Could not write {remote}: {exc}") from exc

    def server_host_key(self) -> str:
        key = self.conn.get_server_host_key()
        if key is None:  # pragma: no cover - asyncssh always sets this for clients
            raise SSHError("Server did not present a host key")
        return key.export_public_key("openssh").decode().strip()


def _pinned_key(target: SSHTarget) -> asyncssh.SSHKey | None:
    if not target.pinned_host_key:
        return None
    try:
        return asyncssh.import_public_key(target.pinned_host_key)
    except (asyncssh.KeyImportError, ValueError) as exc:
        raise SSHError(f"The pinned host key could not be loaded: {exc}") from exc


def _key_algs(key: asyncssh.SSHKey) -> list[str]:
    return [alg.decode() for alg in key.sig_algorithms]


async def _offered_key(target: SSHTarget, pinned: asyncssh.SSHKey) -> asyncssh.SSHKey | None:
    """The host key the server offers when the pinned type is preferred but not required."""
    algs = _key_algs(pinned)
    algs += [alg for alg in _HOST_KEY_ALGS if alg not in algs]
    try:
        return await asyncio.wait_for(
            asyncssh.get_server_host_key(target.hostname, target.port, server_host_key_algs=algs, config=None),
            timeout=get_settings().ssh_connect_timeout,
        )
    except (OSError, TimeoutError, asyncssh.Error):
        return None


async def connect(target: SSHTarget, *, allow_unpinned: bool = False) -> RemoteSession:
    if not target.private_key and not target.password:
        raise SSHError(CREDENTIALS_UNREADABLE)
    pinned = _pinned_key(target)
    if pinned is not None:
        # Accept only the pinned key, and only its own algorithms.
        known_hosts: object = ([pinned], [], [])
        host_key_algs = _key_algs(pinned)
    elif allow_unpinned:
        known_hosts = None
        host_key_algs = _HOST_KEY_ALGS
    else:
        raise HostKeyNotPinned("Host key not verified yet: run a connection test on this host first")

    client_keys = None
    if target.private_key:
        try:
            client_keys = [asyncssh.import_private_key(target.private_key, target.key_passphrase)]
        except (asyncssh.KeyImportError, ValueError) as exc:
            raise SSHError(f"Stored private key could not be loaded: {exc}") from exc

    timeout = get_settings().ssh_connect_timeout
    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(
                target.hostname,
                port=target.port,
                username=target.username,
                known_hosts=known_hosts,
                server_host_key_algs=host_key_algs,
                client_keys=client_keys,
                password=target.password,
                agent_path=None,
                config=None,
                keepalive_interval=30,
                connect_timeout=timeout,
            ),
            timeout=timeout + 5,
        )
    except asyncssh.HostKeyNotVerifiable as exc:
        raise HostKeyMismatch(_KEY_MISMATCH) from exc
    except asyncssh.PermissionDenied as exc:
        raise SSHError(f"Authentication failed for {target.username}@{target.hostname}") from exc
    except UnicodeError as exc:  # from the IDNA encoding of the name, e.g. "web..example.com"
        raise SSHError(
            f"Invalid hostname {target.hostname}: each part between dots must be 1 to 63 characters"
        ) from exc
    except (OSError, TimeoutError, asyncssh.Error) as exc:
        if pinned is not None and isinstance(exc, _HANDSHAKE_FAILURES):
            # A server without a key of the pinned type fails the key exchange (OpenSSH just drops
            # the connection). Find out whether it now offers a different key.
            offered = await _offered_key(target, pinned)
            if offered is not None and offered.public_data != pinned.public_data:
                raise HostKeyMismatch(
                    f"The server now offers a {offered.algorithm.decode()} host key instead of the pinned "
                    f"{pinned.algorithm.decode()} key. If the server was rebuilt, reset the pinned key; "
                    "otherwise this may be an attack."
                ) from exc
        raise SSHError(f"Could not connect to {target.hostname}:{target.port}: {exc}") from exc
    presented = conn.get_server_host_key()
    if pinned is not None and (presented is None or presented.public_data != pinned.public_data):
        conn.abort()
        raise HostKeyMismatch(_KEY_MISMATCH)
    return RemoteSession(conn)


@asynccontextmanager
async def open_session(target: SSHTarget, *, allow_unpinned: bool = False) -> AsyncIterator[RemoteSession]:
    session = await connect(target, allow_unpinned=allow_unpinned)
    try:
        yield session
    finally:
        session.conn.close()
        await session.conn.wait_closed()


# --------------------------------------------------------------------------- probe

PROBE_COMMAND = f"""
( [ -f /etc/unraid-version ] && . /etc/unraid-version && echo "Unraid $version" ) || ( . /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" ) || uname -sr; echo '{_SEP}'
nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1; echo '{_SEP}'
cat /proc/loadavg 2>/dev/null; echo '{_SEP}'
grep -E '^(MemTotal|MemAvailable):' /proc/meminfo 2>/dev/null; echo '{_SEP}'
docker version --format '{{{{.Server.Version}}}}' 2>&1; echo "rc=$?"; echo '{_SEP}'
docker ps -q 2>/dev/null | wc -l; echo '{_SEP}'
d=$(docker info -f '{{{{.DockerRootDir}}}}' 2>/dev/null | head -n 1); case "$d" in /*) [ -d "$d" ] || d=/ ;; *) d=/ ;; esac
{{ df -P "$d" 2>/dev/null || df -P / 2>/dev/null; }} | tail -n 1
""".strip()
# df -P's capacity column ("45%") followed by the mount point.
_DF_CAPACITY = re.compile(r"\s(\d{1,3})%\s+/")


def _first_int(text: str, default: int = 0) -> int:
    token = text.split()[0] if text.split() else ""
    return int(token) if token.isascii() and token.isdigit() and len(token) <= 18 else default


def _first_float(text: str) -> float:
    try:
        value = float(text.split()[0]) if text.split() else 0.0
    except ValueError:
        return 0.0
    return value if math.isfinite(value) and value >= 0 else 0.0


def _disk_percent(df_line: str) -> float | None:
    """The capacity from the last line of ``df -P``; None if it cannot be read."""
    lines = df_line.splitlines()
    match = _DF_CAPACITY.search(" " + lines[-1]) if lines else None
    if match is None:
        return None
    value = int(match.group(1))
    return float(value) if value <= 100 else None


def parse_probe(output: str, host_key: str) -> ProbeResult:
    """Parse PROBE_COMMAND output. Never raises: the output comes from the remote machine."""
    parts = [p.strip() for p in output.split(_SEP)]
    parts += [""] * (7 - len(parts))
    os_info, nproc_s, loadavg, meminfo, docker_s, containers_s, df_s = parts[:7]

    cpus = max(1, _first_int(nproc_s, 1))
    load1 = _first_float(loadavg)
    mem: dict[str, int] = {}
    for line in meminfo.splitlines():
        key, _, rest = line.partition(":")
        if rest.split():
            mem[key] = _first_int(rest)  # kB
    total = mem.get("MemTotal", 0)
    available = min(mem.get("MemAvailable", total), total)

    # stderr is merged into stdout, so docker may print warnings before the version.
    docker_lines = [line.strip() for line in docker_s.splitlines() if line.strip()]
    rc_ok = bool(docker_lines) and docker_lines[-1] == "rc=0"
    docker_out = docker_lines[:-1]
    if rc_ok and docker_out:
        docker_version: str | None = clip(docker_out[-1], 64) or None
        docker_error = clip("\n".join(docker_out[:-1]), 500) or None
    else:
        docker_version = None
        docker_error = clip("\n".join(docker_out) or "docker not found", 500)
    return ProbeResult(
        host_key=host_key,
        fingerprint=fingerprint(host_key),
        os_info=clip(os_info.splitlines()[0], 255) if os_info else "",
        cpus=cpus,
        cpu_percent=min(100.0, load1 / cpus * 100),
        mem_total_mb=total // 1024,
        mem_percent=((total - available) / total * 100) if total else 0.0,
        docker_version=docker_version,
        docker_error=docker_error,
        containers_running=_first_int(containers_s),
        disk_percent=_disk_percent(df_s),
    )


async def probe(target: SSHTarget) -> ProbeResult:
    """Connect (pinning the host key if none is stored yet) and gather health information."""
    async with open_session(target, allow_unpinned=True) as session:
        host_key = session.server_host_key()
        _, output = await session.run(PROBE_COMMAND, check=False, timeout=30)
    return parse_probe(output, host_key)
