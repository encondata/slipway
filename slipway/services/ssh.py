"""SSH access to deployment hosts.

Host keys are pinned on first successful connection (trust on first use). Every later
connection must present the same key, otherwise it is refused with ``HostKeyMismatch``.
A host a provider makes (a droplet, a VM) is never trusted on first use: its key is written only
by its provider's ``prepare``, and ``SSHTarget.from_host`` refuses it until it is built (``HostNotBuilt``).
"""

from __future__ import annotations

import asyncio
import math
import re
import shlex
from collections import deque
from collections.abc import AsyncIterable, AsyncIterator, Awaitable, Callable, Iterable
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
Scrubber = Callable[[str], str]
# Output kept per line (the deployment log's cap too), and lines kept when output is streamed.
MAX_LINE_CHARS = 16 * 1024
LINE_TRUNCATED = " [line truncated]"
TAIL_LINES = 15
# A line longer than the SSH receive window (2 MiB) arrives in pieces; they are joined before the
# line is scrubbed, and at most this much of one line is kept (only its start is ever shown).
LONG_LINE_CHARS = 4 * 1024 * 1024
# Copying between hosts (RemoteSession.pipe_to): bytes read at a time, and how long the copy may stall.
PIPE_CHUNK = 256 * 1024
PIPE_IDLE_TIMEOUT = 600.0
_SEP = "::slipway::"
_UNSAFE_COMMENT = re.compile(r"[^A-Za-z0-9@._-]+")
CREDENTIALS_UNREADABLE = "No usable SSH credentials are stored for this host (missing or could not be decrypted); re-enter them on the host page"
# A droplet's or VM's key is Slipway's own and can't be entered on the host page (that edit is refused for a host an
# environment made), so the text names the only fix that works.
OWNED_KEY_UNREADABLE = (
    "Slipway can't read the SSH key it made for this host (missing or could not be decrypted). Put the old key "
    "back in SLIPWAY_ENCRYPTION_KEY, after the new one: the key of a droplet or VM Slipway made can't be entered "
    "by hand"
)
_KEY_MISMATCH = (
    "The host key presented by the server does not match the pinned key. "
    "If the server was rebuilt, reset the pinned key; otherwise this may be an attack."
)
# Prefer ed25519 when pinning, so a later removal of a legacy RSA host key does not break the pin.
_HOST_KEY_ALGS = sorted((a.decode() for a in get_default_public_key_algs()), key=lambda a: a != "ssh-ed25519")
# How a server that cannot use the pinned key type ends the handshake.
_HANDSHAKE_FAILURES = (asyncssh.DisconnectError, ConnectionResetError, ConnectionAbortedError, BrokenPipeError)
# File transfers: the size of each read, how long one SFTP request may take before the transfer
# counts as stalled, and how long closing a file or the SFTP channel may take after a failure
# (a stalled server may never answer the close either). Read at call time, so tests can lower them.
TRANSFER_CHUNK = 1024 * 1024
TRANSFER_STALL_SECONDS = 300.0
TRANSFER_CLOSE_SECONDS = 10.0
_WRITE_NEW = asyncssh.FXF_WRITE | asyncssh.FXF_CREAT | asyncssh.FXF_EXCL
_END = object()
# Redaction: what a hidden value becomes, and the shortest value worth hiding (shorter ones would
# blank out ordinary words; the first-admin password is added with a lower minimum).
HIDDEN = "[hidden]"
MIN_HIDDEN_LENGTH = 6


class SSHError(RuntimeError):
    pass


class HostKeyMismatch(SSHError):
    pass


class HostKeyNotPinned(SSHError):
    pass


class HostNotBuilt(Exception):
    """A host a provider makes (a droplet, a VM) isn't built yet, so there is nothing to connect to.

    Deliberately not an ``SSHError``: nothing that treats an SSHError as a network failure (the poller,
    the API's 502) should ever see it. Every API path that can meet it answers 409 with its text.
    """


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
    owned: bool = False  # a host an environment made (a droplet or a VM): its key can't be entered by hand

    @classmethod
    def from_host(cls, host: Host, *, building: bool = False) -> SSHTarget:
        """The target for ``host``. Raises ``HostNotBuilt`` for a provider's host that isn't built yet, before
        any connection, unless ``building`` (only the providers' ``prepare`` drivers pass it)."""
        if not building and not host_is_built(host):
            raise HostNotBuilt(f"{host.name} isn't built yet: deploy {host.label or host.name} to build it")
        return cls(
            hostname=host.hostname,
            port=host.port,
            username=host.username,
            private_key=host.private_key if host.auth_method == "key" else None,
            key_passphrase=host.key_passphrase,
            password=host.password if host.auth_method == "password" else None,
            pinned_host_key=host.host_key,
            owned=getattr(host, "owner_environment_id", None) is not None,
        )


def host_is_built(host: Host) -> bool:
    """``Host.is_built``, also for a row not saved yet (its ``provider`` is None until the insert, which means
    ``ssh``): an ssh host always is; a provider's host only once its phase is ``ready``."""
    provider = getattr(host, "provider", None) or "ssh"
    return provider == "ssh" or (getattr(host, "provider_state", None) or {}).get("phase") == "ready"


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


# ----------------------------------------------------------------------- redaction


class Redactor:
    """Secret values that must never reach a log line, a step note or an error message.

    ``scrub(text)`` replaces every occurrence of every value with ``[hidden]``. Overlapping or
    adjacent occurrences (of one value or of several) are hidden as one span, so no part of any
    of them is left. Values shorter than ``min_length`` are ignored: hiding them would blank out
    ordinary words. A value that spans several lines is also added line by line, because command
    output is scrubbed one line at a time. A value printed split up or encoded differently (for
    example base64 or URL-quoted) is not caught. The object can be passed as ``scrub=`` itself.
    """

    def __init__(self) -> None:
        self._values: set[str] = set()

    def add(self, value: str | None, *, min_length: int = MIN_HIDDEN_LENGTH) -> None:
        if not value:
            return
        min_length = max(1, min_length)
        if len(value) >= min_length:
            self._values.add(value)
        if "\n" in value:
            for part in value.splitlines():
                part = part.strip("\r")
                if len(part) >= min_length:
                    self._values.add(part)

    def __len__(self) -> int:
        return len(self._values)

    def __repr__(self) -> str:  # never shows the values themselves
        return f"<Redactor hiding {len(self._values)} values>"

    def scrub(self, text: str) -> str:
        if not self._values or not text:
            return text
        spans: list[tuple[int, int]] = []
        for value in self._values:
            start = text.find(value)
            while start != -1:
                spans.append((start, start + len(value)))
                start = text.find(value, start + 1)  # + 1: overlapping occurrences count too
        if not spans:
            return text
        spans.sort()
        out: list[str] = []
        pos = 0
        cut_start, cut_end = spans[0]
        for start, end in spans[1:]:
            if start <= cut_end:  # overlaps or touches the current span: widen it
                cut_end = max(cut_end, end)
                continue
            out += [text[pos:cut_start], HIDDEN]
            pos, (cut_start, cut_end) = cut_end, (start, end)
        out += [text[pos:cut_start], HIDDEN, text[cut_end:]]
        return "".join(out)

    __call__ = scrub


# ---------------------------------------------------------------------------- keys


def clip(value: str, limit: int) -> str:
    """Make remote-supplied text storable: PostgreSQL rejects NUL bytes and over-long values."""
    return value.replace("\x00", "")[:limit]


def clip_line(line: str) -> str:
    """``line`` cut to ``MAX_LINE_CHARS``, marked when something was cut."""
    return line if len(line) <= MAX_LINE_CHARS else line[:MAX_LINE_CHARS] + LINE_TRUNCATED


def _whole_line(pieces: list[str], held: int, scrub: Scrubber | None) -> str:
    """One line of output from the pieces it arrived in, scrubbed, and cut when it was too long to keep."""
    text = "".join(pieces)
    cut = held > LONG_LINE_CHARS
    line = text[:LONG_LINE_CHARS].rstrip("\r\n").replace("\x00", "")
    if scrub is not None:
        line = scrub(line)
    if not cut:
        return line
    if scrub is None:
        # The caller's on_line scrubs (LogSink.line) and cuts it itself: cutting here first could split a
        # secret at the cut, so that its first part no longer matches and is shown.
        return line + LINE_TRUNCATED
    # The end of the kept part may hold the start of a hidden value. Cutting to MAX_LINE_CHARS drops it,
    # unless scrubbing shrank the line that far; then nothing of it is shown.
    if scrub is not None and len(line) < LONG_LINE_CHARS // 2:
        line = HIDDEN
    return line[:MAX_LINE_CHARS] + LINE_TRUNCATED


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

    def __init__(self, conn: asyncssh.SSHClientConnection, host: str | None = None) -> None:
        self.conn = conn
        self._host = host

    @property
    def host(self) -> str:
        """The host's name as Slipway knows it, for messages."""
        if self._host:
            return self._host
        peer = self.conn.get_extra_info("peername")
        return str(peer[0]) if peer else "the host"

    async def run(
        self,
        command: str,
        *,
        check: bool = True,
        on_line: LineCallback | None = None,
        timeout: float | None = None,
        input: str | None = None,
        scrub: Scrubber | None = None,
    ) -> tuple[int, str]:
        """Run ``command`` with ``/bin/sh`` and return (exit status, output with stderr mixed in).

        sshd hands the command to the user's login shell, so it is wrapped in ``exec /bin/sh -c``:
        Slipway's commands are POSIX sh, which zsh, for one, parses differently. stdin is closed,
        so nothing remote can wait for input, unless ``input`` is given: then that text is sent on
        stdin and stdin is closed after it. It is meant for short values such as a password, and
        it never appears in a ``CommandFailed`` (only output does). With ``on_line`` every line
        is passed on and only the last ``TAIL_LINES`` are returned, so a long build cannot fill
        memory. With ``scrub`` each whole line is scrubbed first, before it is cut, passed on or
        kept, so a secret that straddles the cut is still hidden. asyncssh hands over a line longer
        than the receive window in pieces; they are joined first, so that holds for them too. Only
        the first ``LONG_LINE_CHARS`` of a line are kept, and such a line is passed on already cut.
        Returned lines are cut to ``MAX_LINE_CHARS`` (and marked); ``CommandFailed`` names
        ``command`` itself.
        """
        lines: deque[str] | list[str] = deque(maxlen=TAIL_LINES) if on_line is not None else []
        callback_error: Exception | None = None  # raised by on_line: passed through, not blamed on SSH
        try:
            async with self.conn.create_process(
                "exec /bin/sh -c " + shlex.quote(command),
                stdin=asyncssh.DEVNULL if input is None else asyncssh.PIPE,
                stderr=asyncssh.STDOUT,
                encoding="utf-8",
                errors="replace",
            ) as proc:
                if input is not None:
                    # Buffered by asyncssh and sent as the channel window allows; EOF follows it.
                    proc.stdin.write(input)
                    proc.stdin.write_eof()

                async def emit(line: str) -> None:
                    nonlocal callback_error
                    lines.append(clip_line(line))
                    if on_line is not None:
                        try:
                            await on_line(line)
                        except Exception as exc:
                            callback_error = exc
                            raise

                async def pump() -> None:
                    pieces: list[str] = []  # the start of a line that arrived without its newline
                    held = 0
                    async for raw in proc.stdout:
                        if not raw:  # EOF marker; a real blank line arrives as "\n"
                            continue
                        if held <= LONG_LINE_CHARS:
                            pieces.append(raw)
                            held += len(raw)
                        if raw.endswith("\n"):
                            await emit(_whole_line(pieces, held, scrub))
                            pieces, held = [], 0
                    if pieces:  # the output ended without a newline
                        await emit(_whole_line(pieces, held, scrub))

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

    async def put(self, local: Path, remote: str, mode: int | None = None) -> None:
        """Upload ``local`` to ``remote``, then set its permissions to ``mode`` when given."""
        try:
            async with self.conn.start_sftp_client() as sftp:
                await sftp.put(str(local), remote)
                if mode is not None:
                    await sftp.chmod(remote, mode)
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

    async def read_stream(self, path: str, chunk: int | None = None) -> AsyncIterator[bytes]:
        """Yield the remote regular file ``path`` in chunks of up to ``chunk`` bytes (1 MiB).

        A symbolic link, a directory or any other kind of file is refused before it is opened,
        and the file must still look the same (kind, size, modification time) once it is open.
        Each SFTP request may take up to ``TRANSFER_STALL_SECONDS``; a longer one ends the
        transfer with "The transfer from <host> stalled for 5 minutes". asyncssh and OS errors
        become ``SSHError("Could not read <path>: ...")``. A consumer that stops early should
        close the iterator (``contextlib.aclosing``) so the SFTP channel is closed at once.
        """
        size = chunk or TRANSFER_CHUNK
        sftp = await self._start_sftp("read", path)
        try:
            attrs = await self._transfer(sftp.lstat(path), "from", "read", path)
            _require_regular(attrs, path)
            fh = await self._transfer(sftp.open(path, "rb"), "from", "read", path)
            try:
                opened = await self._transfer(fh.stat(), "from", "read", path)
                if opened.type != asyncssh.FILEXFER_TYPE_REGULAR or (opened.size, opened.mtime) != (
                    attrs.size,
                    attrs.mtime,
                ):
                    raise SSHError(f"Could not read {path}: it changed while it was being opened")
                while True:
                    data = await self._transfer(fh.read(size), "from", "read", path)
                    if not data:
                        break
                    yield data
            finally:
                await _quietly(fh.close())
        finally:
            await _close_sftp(sftp)

    async def write_stream(
        self, path: str, chunks: AsyncIterable[bytes] | Iterable[bytes], mode: int = 0o600
    ) -> int:
        """Write ``chunks`` to a new remote file ``path`` with permissions ``mode``; return its size.

        The file is created exclusively: anything already at ``path``, a symbolic link included
        (even a dangling one), is refused and left alone. Each SFTP request may take up to
        ``TRANSFER_STALL_SECONDS`` ("The transfer to <host> stalled for 5 minutes"). An error
        raised by ``chunks`` itself is passed through unchanged; asyncssh and OS errors become
        ``SSHError("Could not write <path>: ...")``. After a failure the partial file stays where
        it is: the caller writes into a staging folder of its own and removes that.
        """
        iterator = aiter(chunks) if isinstance(chunks, AsyncIterable) else _async_iter(chunks)
        sftp = await self._start_sftp("write", path)
        written = 0
        try:
            attrs = asyncssh.SFTPAttrs(permissions=mode)
            fh = await self._transfer(sftp.open(path, _WRITE_NEW, attrs, encoding=None), "to", "write", path)
            try:
                while (piece := await anext(iterator, _END)) is not _END:  # the producer's errors pass through
                    data = bytes(piece)  # type: ignore[arg-type]
                    if not data:
                        continue
                    await self._transfer(fh.write(data), "to", "write", path)
                    written += len(data)
                # The umask may have narrowed the mode given at open; set it exactly on the handle.
                await self._transfer(fh.chmod(mode), "to", "write", path)
                await self._transfer(fh.close(), "to", "write", path)
            finally:
                await _quietly(fh.close())  # a no-op once closed
        finally:
            await _close_sftp(sftp)
        return written

    async def _start_sftp(self, verb: str, path: str) -> asyncssh.SFTPClient:
        try:
            return await asyncio.wait_for(self.conn.start_sftp_client(), TRANSFER_STALL_SECONDS)
        except TimeoutError as exc:
            raise SSHError(f"Could not {verb} {path}: {self.host} did not start an SFTP session") from exc
        except (asyncssh.Error, OSError) as exc:
            raise SSHError(f"Could not {verb} {path}: {exc}") from exc

    async def _transfer[T](self, request: Awaitable[T], direction: str, verb: str, path: str) -> T:
        """Await one SFTP request within the stall limit, turning its errors into ``SSHError``."""
        stall = TRANSFER_STALL_SECONDS
        try:
            return await asyncio.wait_for(request, stall)
        except TimeoutError as exc:  # before OSError: TimeoutError is one
            raise SSHError(f"The transfer {direction} {self.host} stalled for {_duration(stall)}") from exc
        except (asyncssh.Error, OSError) as exc:
            raise SSHError(f"Could not {verb} {path}: {exc}") from exc
    async def pipe_to(
        self,
        target: RemoteSession,
        read_command: str,
        write_command: str,
        *,
        on_progress: Callable[[int], Awaitable[None]] | None = None,
        idle_timeout: float = PIPE_IDLE_TIMEOUT,
    ) -> int:
        """Run ``read_command`` here and feed its output to ``write_command`` on ``target``.

        The bytes pass through Slipway, so neither host has to reach or trust the other. Returns how
        many were copied. Raises ``CommandFailed`` naming the command that failed (this side's first),
        and ``SSHError`` when no data moves for ``idle_timeout`` seconds.
        """
        errors: dict[str, deque[str]] = {"read": deque(maxlen=TAIL_LINES), "write": deque(maxlen=TAIL_LINES)}

        async def collect(stream: asyncssh.SSHReader[bytes], key: str) -> None:
            async for raw in stream:
                line = raw.decode("utf-8", "replace").rstrip("\r\n").replace("\x00", "")
                if line:
                    errors[key].append(clip_line(line))

        total = 0
        writer_ended = False
        try:
            async with self.conn.create_process(
                "exec /bin/sh -c " + shlex.quote(read_command), stdin=asyncssh.DEVNULL, encoding=None,
            ) as reader, target.conn.create_process(
                "exec /bin/sh -c " + shlex.quote(write_command), encoding=None,
            ) as writer:
                side = [
                    asyncio.create_task(collect(reader.stderr, "read")),
                    asyncio.create_task(collect(writer.stderr, "write")),
                    asyncio.create_task(collect(writer.stdout, "write")),
                ]
                try:
                    while True:
                        chunk = await asyncio.wait_for(reader.stdout.read(PIPE_CHUNK), idle_timeout)
                        if not chunk:
                            break
                        writer.stdin.write(chunk)
                        await asyncio.wait_for(writer.stdin.drain(), idle_timeout)
                        total += len(chunk)
                        if on_progress is not None:
                            await on_progress(total)
                    writer.stdin.write_eof()
                    await asyncio.wait_for(reader.wait(), idle_timeout)
                    await asyncio.wait_for(writer.wait(), idle_timeout)
                except TimeoutError as exc:
                    for proc in (reader, writer):
                        with suppress(asyncssh.Error, OSError):
                            proc.kill()
                    raise SSHError(f"The copy stalled: no data moved for {idle_timeout:.0f}s") from exc
                except (BrokenPipeError, ConnectionResetError, asyncssh.Error, OSError):
                    # The writing side ended early (it failed); its exit status says why below.
                    writer_ended = True
                    with suppress(asyncssh.Error, OSError):
                        reader.kill()
                    with suppress(TimeoutError, asyncssh.Error, OSError):
                        await asyncio.wait_for(writer.wait(), 30)
                finally:
                    await asyncio.gather(*side, return_exceptions=True)
                read_status = reader.exit_status if reader.exit_status is not None else -1
                write_status = writer.exit_status if writer.exit_status is not None else -1
        except (asyncssh.Error, OSError) as exc:
            raise SSHError(f"SSH copy failed: {exc}") from exc
        # A failed read usually makes the write fail too (a cut-off archive), so it is named first,
        # unless the writing side ended on its own and the reader was stopped because of it.
        if read_status != 0 and not writer_ended:
            raise CommandFailed(read_command, read_status, "\n".join(errors["read"]))
        if write_status != 0:
            raise CommandFailed(write_command, write_status, "\n".join(errors["write"]))
        return total

    def server_host_key(self) -> str:
        key = self.conn.get_server_host_key()
        if key is None:  # pragma: no cover - asyncssh always sets this for clients
            raise SSHError("Server did not present a host key")
        return key.export_public_key("openssh").decode().strip()


def _require_regular(attrs: asyncssh.SFTPAttrs, path: str) -> None:
    if attrs.type == asyncssh.FILEXFER_TYPE_REGULAR:
        return
    if attrs.type == asyncssh.FILEXFER_TYPE_SYMLINK:
        raise SSHError(f"Could not read {path}: it is a symbolic link, and Slipway reads only regular files")
    raise SSHError(f"Could not read {path}: it is not a regular file")


def _duration(seconds: float) -> str:
    """``300`` as "5 minutes", ``60`` as "1 minute", anything else in seconds."""
    if seconds >= 60 and seconds % 60 == 0:
        minutes = int(seconds // 60)
        return f"{minutes} minute" if minutes == 1 else f"{minutes} minutes"
    return f"{seconds:g} seconds"


async def _quietly(request: Awaitable[object]) -> None:
    """Await a clean-up request for at most ``TRANSFER_CLOSE_SECONDS``, ignoring its failure."""
    with suppress(asyncssh.Error, OSError, ValueError):  # TimeoutError is an OSError
        await asyncio.wait_for(request, TRANSFER_CLOSE_SECONDS)


async def _close_sftp(sftp: asyncssh.SFTPClient) -> None:
    with suppress(asyncssh.Error, OSError):
        sftp.exit()
    await _quietly(sftp.wait_closed())


async def _async_iter[T](items: Iterable[T]) -> AsyncIterator[T]:
    for item in items:
        yield item


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
        raise SSHError(OWNED_KEY_UNREADABLE if target.owned else CREDENTIALS_UNREADABLE)
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
    return RemoteSession(conn, target.hostname)


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
