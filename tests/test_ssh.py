"""SSH layer tests against a real in-process asyncssh server."""

from __future__ import annotations

import asyncio
import contextlib
import os
import shlex
import subprocess

import asyncssh
import pytest

from slipway.services import ssh

PROBE_OUTPUT = """Ubuntu 24.04 LTS
::slipway::
4
::slipway::
1.00 0.50 0.25 1/200 1234
::slipway::
MemTotal:        8000000 kB
MemAvailable:    6000000 kB
::slipway::
27.3.1
rc=0
::slipway::
3
"""


class _Server(asyncssh.SSHServer):
    authorized: asyncssh.SSHKey

    def begin_auth(self, username: str) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        return key.public_data == self.authorized.public_data

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return password == "s3cret"


def sent_command(process: asyncssh.SSHServerProcess) -> str:
    """The command as Slipway built it: run() sends ``exec /bin/sh -c <quoted command>``."""
    words = shlex.split(process.command or "")
    assert words[:3] == ["exec", "/bin/sh", "-c"] and len(words) == 4, process.command
    return words[3]


async def _handle(process: asyncssh.SSHServerProcess) -> None:
    cmd = sent_command(process)
    if "os-release" in cmd:
        process.stdout.write(PROBE_OUTPUT)
        process.exit(0)
    elif cmd.startswith("echo"):
        process.stdout.write("hello\nworld\n")
        process.exit(0)
    else:
        process.stderr.write("boom\n")
        process.exit(3)


@pytest.fixture
async def ssh_server():
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    client_priv, client_pub = ssh.generate_keypair("test")
    _Server.authorized = asyncssh.import_public_key(client_pub)
    server = await asyncssh.create_server(
        _Server, "127.0.0.1", 0, server_host_keys=[host_key], process_factory=_handle, sftp_factory=True
    )
    port = server.sockets[0].getsockname()[1]
    yield {"port": port, "host_key": host_key, "client_key": client_priv}
    server.close()
    await server.wait_closed()


def _target(srv, **kw) -> ssh.SSHTarget:
    return ssh.SSHTarget(hostname="127.0.0.1", port=srv["port"], username="deploy", private_key=srv["client_key"], **kw)


async def test_probe_pins_host_key_and_parses_metrics(ssh_server):
    result = await ssh.probe(_target(ssh_server))
    expected = ssh_server["host_key"].export_public_key("openssh").decode().strip()
    assert result.host_key == expected
    assert result.fingerprint.startswith("SHA256:")
    assert result.os_info == "Ubuntu 24.04 LTS"
    assert result.cpus == 4 and result.cpu_percent == 25.0
    assert result.mem_total_mb == 7812 and round(result.mem_percent) == 25
    assert result.docker_version == "27.3.1" and result.containers_running == 3


async def test_pinned_key_is_enforced(ssh_server):
    good = ssh_server["host_key"].export_public_key("openssh").decode()
    async with ssh.open_session(_target(ssh_server, pinned_host_key=good)) as remote:
        status, output = await remote.run("echo hi")
    assert status == 0 and output == "hello\nworld"

    impostor = asyncssh.generate_private_key("ssh-ed25519").export_public_key("openssh").decode()
    with pytest.raises(ssh.HostKeyMismatch):
        await ssh.connect(_target(ssh_server, pinned_host_key=impostor))


async def test_unpinned_connection_refused_outside_probe(ssh_server):
    with pytest.raises(ssh.HostKeyNotPinned):
        await ssh.connect(_target(ssh_server))


async def test_password_auth_and_bad_credentials(ssh_server):
    pinned = ssh_server["host_key"].export_public_key("openssh").decode()
    target = ssh.SSHTarget(hostname="127.0.0.1", port=ssh_server["port"], username="deploy", password="s3cret", pinned_host_key=pinned)
    async with ssh.open_session(target) as remote:
        assert (await remote.run("echo"))[0] == 0
    target.password = "wrong"
    with pytest.raises(ssh.SSHError, match="Authentication failed"):
        await ssh.connect(target)


async def test_command_failure_and_streaming(ssh_server, tmp_path):
    pinned = ssh_server["host_key"].export_public_key("openssh").decode()
    lines: list[str] = []

    async def on_line(line: str) -> None:
        lines.append(line)

    async with ssh.open_session(_target(ssh_server, pinned_host_key=pinned)) as remote:
        await remote.run("echo", on_line=on_line)
        with pytest.raises(ssh.CommandFailed) as exc:
            await remote.run("false")
        assert exc.value.exit_status == 3 and "boom" in exc.value.output

        env_path = tmp_path / ".env"
        await remote.write_text(str(env_path), "A=1\n")
    assert lines == ["hello", "world"]
    assert env_path.read_text() == "A=1\n"
    assert oct(env_path.stat().st_mode & 0o777) == "0o600"


async def test_unreachable_host():
    target = ssh.SSHTarget(hostname="127.0.0.1", port=1, username="deploy", password="x")
    with pytest.raises(ssh.SSHError, match="Could not connect"):
        await ssh.probe(target)


def test_key_helpers():
    priv, pub = ssh.generate_keypair("slipway@test")
    assert pub.startswith("ssh-ed25519 ") and pub.endswith("slipway@test")
    assert ssh.public_key_from_private(priv) == pub
    with pytest.raises(ssh.SSHError):
        ssh.public_key_from_private("not a key")


def test_parse_probe_without_docker():
    out = PROBE_OUTPUT.replace("27.3.1\nrc=0", "sh: docker: not found\nrc=127")
    key = asyncssh.generate_private_key("ssh-ed25519").export_public_key("openssh").decode()
    result = ssh.parse_probe(out, key)
    assert result.docker_version is None and "not found" in result.docker_error


# ----------------------------------------------- phase 2: stdin, redaction, file streams


def test_redactor_hides_every_part_of_every_value():
    hide = ssh.Redactor()
    hide.add("postgres://u:pw@h")
    hide.add("abcdef")
    hide.add("defghijk")  # overlaps "abcdef" in "abcdefghijk"
    hide.add("short")  # 5 characters: left alone
    hide.add("")
    hide.add(None)
    assert hide.scrub("DATABASE_URL=postgres://u:pw@h/app") == "DATABASE_URL=[hidden]/app"
    assert hide.scrub("x abcdefghijk y") == "x [hidden] y"
    assert hide.scrub("abcdefabcdef") == "[hidden]"
    assert hide.scrub("a short word") == "a short word"
    assert hide("abcdef and abcdef") == "[hidden] and [hidden]"
    assert "abcdef" not in repr(hide) and len(hide) == 3


def test_redactor_minimum_length_and_multi_line_values():
    hide = ssh.Redactor()
    hide.add("pw12", min_length=4)  # the first-admin password may be this short
    hide.add("-----BEGIN KEY-----\nline-one-of-the-key\r\nend\n")
    assert hide.scrub("password pw12 given") == "password [hidden] given"
    # Output is scrubbed line by line, so each long line of a multi-line value is hidden alone.
    assert hide.scrub("got line-one-of-the-key") == "got [hidden]"
    assert hide.scrub("end of output") == "end of output"  # "end" is under 6 characters


def test_stall_durations_read_plainly():
    assert ssh._duration(300) == "5 minutes"
    assert ssh._duration(60) == "1 minute"
    assert ssh._duration(0.25) == "0.25 seconds"


async def _real_shell(process: asyncssh.SSHServerProcess) -> None:
    """Run the command in /bin/sh, as sshd would, with whatever arrives on stdin until EOF."""
    data = await process.stdin.read()  # returns only once the client closes stdin
    proc = await asyncio.create_subprocess_exec(
        "/bin/sh", "-c", process.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    out, _ = await proc.communicate(data.encode())
    process.stdout.write(out.decode())
    process.exit(proc.returncode)


class _StallingSFTP(asyncssh.SFTPServer):
    """An SFTP server on the local filesystem whose reads and writes never answer."""

    release: asyncio.Event

    async def read(self, file_obj, offset, size):
        await self.release.wait()
        return b""

    async def write(self, file_obj, offset, data):
        await self.release.wait()
        return len(data)


@pytest.fixture
async def shell_server():
    """Start a server that runs commands in a real shell; yields a session factory."""
    servers = []
    _StallingSFTP.release = asyncio.Event()

    @contextlib.asynccontextmanager
    async def session(sftp_factory=True):
        host_key = asyncssh.generate_private_key("ssh-ed25519")
        client_priv, client_pub = ssh.generate_keypair("test")
        _Server.authorized = asyncssh.import_public_key(client_pub)
        server = await asyncssh.create_server(
            _Server, "127.0.0.1", 0, server_host_keys=[host_key], process_factory=_real_shell,
            sftp_factory=sftp_factory,
        )
        servers.append(server)
        srv = {"port": server.sockets[0].getsockname()[1], "client_key": client_priv}
        pinned = host_key.export_public_key("openssh").decode()
        async with ssh.open_session(_target(srv, pinned_host_key=pinned)) as remote:
            yield remote

    yield session
    _StallingSFTP.release.set()
    for server in servers:
        server.close()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(server.wait_closed(), 5)


async def test_input_arrives_on_stdin_and_stdin_is_closed_after_it(shell_server):
    async with shell_server() as remote:
        assert remote.host == "127.0.0.1"
        assert await remote.run("cat", input="first line\nsecond\n", timeout=30) == (0, "first line\nsecond")
        # Without input stdin is closed at once, so a command that reads it does not wait.
        assert await remote.run("cat; echo done", timeout=30) == (0, "done")
        # The command reads one line and reports only its length; the error never holds the input.
        with pytest.raises(ssh.CommandFailed) as exc:
            await remote.run('IFS= read -r p; echo "pwlen=${#p}"; exit 5', input="hunter2-secret\n", timeout=30)
    assert exc.value.exit_status == 5 and exc.value.output == "pwlen=14"
    assert "hunter2" not in str(exc.value) and "hunter2" not in exc.value.command


async def test_scrub_runs_on_the_whole_line_before_it_is_cut(shell_server):
    secret = "s3cr3t-token-value"
    hide = ssh.Redactor()
    hide.add(secret)
    # The secret starts 4 characters before the cut, so the cut alone would keep "s3cr".
    pad = ssh.MAX_LINE_CHARS - 4
    command = f"printf 'x%.0s' $(seq {pad}); echo '{secret}tail'; echo 'value: {secret}'; exit 2"
    seen: list[str] = []

    async def on_line(line: str) -> None:
        seen.append(line)

    async with shell_server() as remote:
        _, unscrubbed = await remote.run(command, check=False, timeout=30)
        with pytest.raises(ssh.CommandFailed) as exc:
            await remote.run(command, on_line=on_line, scrub=hide, timeout=30)
        _, kept = await remote.run(command, check=False, scrub=hide.scrub, timeout=30)
    assert unscrubbed.splitlines()[0].endswith("xs3cr" + ssh.LINE_TRUNCATED)  # what the cut alone leaves
    for text in (exc.value.output, str(exc.value), kept, *seen):
        assert "s3cr" not in text
    assert seen == ["x" * pad + "[hidden]tail", "value: [hidden]"]
    assert exc.value.output.splitlines()[1] == "value: [hidden]"
    assert kept.splitlines()[0] == "x" * pad + "[hid" + ssh.LINE_TRUNCATED  # cut after scrubbing


def _x(count: int) -> str:
    """A shell command that prints ``count`` x characters and no newline."""
    return f"head -c {count} /dev/zero | tr '\\0' x"


async def test_a_line_longer_than_the_receive_window_is_scrubbed_whole(shell_server):
    # asyncssh hands over a line longer than its 2 MiB receive window in pieces; the secret straddles the 2 MiB mark.
    secret = "S3CRET-" + "a1b2c3d4" * 4
    hide = ssh.Redactor()
    hide.add(secret)
    window = 2 * 1024 * 1024
    for offset in (10, 30):
        command = f"{_x(window - offset)}; echo '{secret}'; echo after"
        seen: list[str] = []

        async def on_line(line: str) -> None:
            seen.append(line)

        async with shell_server() as remote:
            _, kept = await remote.run(command, on_line=on_line, scrub=hide, timeout=60)
        assert len(seen) == 2, [len(s) for s in seen]
        assert seen[0] == "x" * (window - offset) + "[hidden]"
        assert seen[1] == "after"
        for text in (kept, *seen):
            assert "a1b2" not in text and "S3CR" not in text


async def test_a_very_long_line_is_kept_cut_and_the_next_line_is_whole(shell_server):
    async with shell_server() as remote:
        _, kept = await remote.run(f"{_x(ssh.LONG_LINE_CHARS + 3 * 1024 * 1024)}; echo; echo after", timeout=60)
        _, last = await remote.run(f"echo first; {_x(5)}", timeout=30)  # no newline at the end
    assert kept.splitlines() == ["x" * ssh.MAX_LINE_CHARS + ssh.LINE_TRUNCATED, "after"]
    assert last.splitlines() == ["first", "xxxxx"]


async def test_a_very_long_line_without_scrub_reaches_on_line_uncut(shell_server):
    """Without scrub= the caller's on_line scrubs (LogSink.line): cutting the line to 16 KiB first split a
    secret straddling the cut, and its first part was logged."""
    secret = "S3CRET-" + "a1b2c3d4" * 4
    hide = ssh.Redactor()
    hide.add(secret)
    pad = ssh.MAX_LINE_CHARS - 10
    logged: list[str] = []

    async def on_line(line: str) -> None:  # what LogSink.line stores
        logged.append(ssh.clip_line(hide.scrub(line)))

    async with shell_server() as remote:
        await remote.run(f"{_x(pad)}; printf '%s' '{secret}'; {_x(5 * 1024 * 1024)}; echo; echo after",
                         on_line=on_line, timeout=60)
    assert logged == ["x" * pad + "[hidden]" + "x" * (ssh.MAX_LINE_CHARS - pad - 8) + ssh.LINE_TRUNCATED, "after"]
    assert "S3CR" not in "".join(logged)


async def test_a_cut_line_made_of_hidden_values_shows_no_part_of_one(shell_server):
    # 1000-character values back to back: scrubbing the kept 4 MiB leaves one "[hidden]" span, and the cut
    # at 4 MiB falls inside a value, so the end of the kept part is the start of one.
    secret = "k" + "0123456789" * 99 + "z"
    hide = ssh.Redactor()
    hide.add(secret)
    count = ssh.LONG_LINE_CHARS // len(secret) + 600
    seen: list[str] = []

    async def on_line(line: str) -> None:
        seen.append(line)

    async with shell_server() as remote:
        _, kept = await remote.run(f"yes '{secret}' | head -n {count} | tr -d '\\n'; echo; echo after",
                                   on_line=on_line, scrub=hide, timeout=60)
    assert seen == ["[hidden]" + ssh.LINE_TRUNCATED, "after"]
    assert "0123" not in kept


async def test_read_stream_reads_a_regular_file_in_chunks(shell_server, tmp_path):
    data = os.urandom(10_000)
    (tmp_path / "dump").write_bytes(data)
    async with shell_server() as remote:
        chunks = [c async for c in remote.read_stream(str(tmp_path / "dump"), chunk=4096)]
        assert [len(c) for c in chunks] == [4096, 4096, 1808] and b"".join(chunks) == data
        empty = tmp_path / "empty"
        empty.write_bytes(b"")
        assert [c async for c in remote.read_stream(str(empty))] == []


async def test_read_stream_refuses_symlinks_and_other_kinds(shell_server, tmp_path):
    (tmp_path / "real").write_bytes(b"DB:data")
    (tmp_path / "link").symlink_to(tmp_path / "real")
    (tmp_path / "folder").mkdir()
    async with shell_server() as remote:
        with pytest.raises(ssh.SSHError, match="it is a symbolic link, and Slipway reads only regular files"):
            [c async for c in remote.read_stream(str(tmp_path / "link"))]
        with pytest.raises(ssh.SSHError, match="folder: it is not a regular file"):
            [c async for c in remote.read_stream(str(tmp_path / "folder"))]
        with pytest.raises(ssh.SSHError, match=r"Could not read .*missing: "):
            [c async for c in remote.read_stream(str(tmp_path / "missing"))]
        # The session is still usable after the refusals.
        assert await remote.run("echo ok", timeout=30) == (0, "ok")


async def test_write_stream_creates_a_new_file_with_its_mode(shell_server, tmp_path):
    async def produce():
        yield b"DB:"
        yield bytearray(b"")
        yield memoryview(b"x" * 5000)

    target = tmp_path / "database.partial"
    async with shell_server() as remote:
        assert await remote.write_stream(str(target), produce()) == 5003
        assert await remote.write_stream(str(tmp_path / "files"), [b"one", b"two"], mode=0o640) == 6
    assert target.read_bytes() == b"DB:" + b"x" * 5000
    assert oct(target.stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "files").stat().st_mode & 0o777) == "0o640"


async def test_write_stream_never_replaces_a_file_or_follows_a_symlink(shell_server, tmp_path):
    existing = tmp_path / "existing"
    existing.write_bytes(b"keep me")
    dangling = tmp_path / "dangling"
    dangling.symlink_to(tmp_path / "elsewhere")
    async with shell_server() as remote:
        for path in (existing, dangling):
            with pytest.raises(ssh.SSHError, match=f"Could not write {path}: "):
                await remote.write_stream(str(path), [b"new"])
    assert existing.read_bytes() == b"keep me"
    assert not (tmp_path / "elsewhere").exists() and dangling.is_symlink()


async def test_write_stream_passes_the_producers_errors_through(shell_server, tmp_path):
    class Damaged(ValueError):
        pass

    async def produce():
        yield b"first part"
        raise Damaged("damaged part 2")

    async with shell_server() as remote:
        with pytest.raises(Damaged, match="damaged part 2"):
            await remote.write_stream(str(tmp_path / "x.partial"), produce())
        # The same session goes on working.
        assert await remote.write_stream(str(tmp_path / "y"), [b"ok"]) == 2


async def test_put_sets_the_mode_when_asked(shell_server, tmp_path):
    local = tmp_path / "bundle.tar.gz"
    local.write_bytes(b"archive")
    async with shell_server() as remote:
        await remote.put(local, str(tmp_path / "plain"))
        await remote.put(local, str(tmp_path / "private"), mode=0o600)
    assert (tmp_path / "private").read_bytes() == b"archive"
    assert oct((tmp_path / "private").stat().st_mode & 0o777) == "0o600"
    assert (tmp_path / "plain").read_bytes() == b"archive"


async def test_a_stalled_transfer_fails_and_cleans_up_in_time(shell_server, tmp_path, monkeypatch):
    monkeypatch.setattr(ssh, "TRANSFER_STALL_SECONDS", 0.3)
    monkeypatch.setattr(ssh, "TRANSFER_CLOSE_SECONDS", 0.3)
    (tmp_path / "dump").write_bytes(b"DB:" * 100)
    loop = asyncio.get_running_loop()
    async with shell_server(sftp_factory=_StallingSFTP) as remote:
        started = loop.time()
        with pytest.raises(ssh.SSHError, match=r"^The transfer from 127\.0\.0\.1 stalled for 0\.3 seconds$"):
            [c async for c in remote.read_stream(str(tmp_path / "dump"))]
        with pytest.raises(ssh.SSHError, match=r"^The transfer to 127\.0\.0\.1 stalled for 0\.3 seconds$"):
            await remote.write_stream(str(tmp_path / "out.partial"), [b"DB:data"])
        # The stall timeout plus bounded clean-up, not a hang on the server that stopped answering.
        assert loop.time() - started < 5
        assert await remote.run("echo still here", timeout=30) == (0, "still here")
