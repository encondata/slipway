"""Preparing a new server: Slipway signs in once as an admin and sets the host up itself.

With a one-time admin login (root, or a user that may ``sudo``), Slipway connects, pins the server's host key,
creates the host's SSH user, authorizes Slipway's own key for it, installs Docker (Ubuntu's ``docker.io`` and
``docker-compose-v2`` packages, as ``machines`` does for the VMs it makes), adds the user to the ``docker`` group
and creates the deploy root. It then checks the host as that user, with its key, like any other host.

The admin password is held in memory by the setup task only: it is never stored, logged or audited. ``sudo`` gets
it on stdin (``sudo -S``), never on a command line. Every value placed in the remote script is validated by the
API schemas and quoted with ``shlex.quote``.

Setups run as in-process asyncio tasks, like deployments. One that a restart cut short is marked ``interrupted``
at startup, and can be started again with the admin login.
"""

from __future__ import annotations

import asyncio
import logging
import shlex
import time
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select, update

from slipway.db.base import utcnow
from slipway.db.session import session_scope
from slipway.models import Host, HostOS, HostSetupStatus, HostStatus, User
from slipway.services import audit, ssh
from slipway.services.hosts import check_host

log = logging.getLogger(__name__)

q = shlex.quote
STEP_MARK = "::slipway-step::"
# (step, label) in the order they run; the remote script announces each of the middle ones.
STEPS: tuple[tuple[str, str], ...] = (
    ("connect", "Connect"),
    ("os", "Check Ubuntu"),
    ("user", "Create user"),
    ("key", "Authorize key"),
    ("docker", "Install Docker"),
    ("deploy_root", "Deploy root"),
    ("verify", "Verify"),
)
STEP_NAMES = frozenset(name for name, _ in STEPS)
OS_LABELS = {HostOS.UBUNTU: "Ubuntu"}
LOG_MAX_CHARS = 256 * 1024
FLUSH_SECONDS = 1.0
SCRIPT_TIMEOUT = 30 * 60  # apt on a slow mirror, or waiting for unattended-upgrades to let go of dpkg


@dataclass(frozen=True)
class AdminLogin:
    """The one-time login. ``repr`` leaves the password out, so it cannot reach a log or a traceback."""

    username: str
    password: str = field(repr=False)


class SetupError(RuntimeError):
    pass


# ---------------------------------------------------------------------- script


def ubuntu_script(*, username: str, public_key: str, deploy_root: str) -> str:
    """The setup script, run as root. Safe to run again: each step skips what is already done."""
    apt = "apt-get -q -y -o DPkg::Lock::Timeout=600"
    return f"""set -eu
exec </dev/null
export DEBIAN_FRONTEND=noninteractive
user={q(username)}
key={q(public_key)}
root={q(deploy_root)}
step() {{ echo "{STEP_MARK} $1"; }}

step os
[ -r /etc/os-release ] || {{ echo "Cannot read /etc/os-release: this does not look like Ubuntu"; exit 3; }}
. /etc/os-release
if [ "${{ID:-}}" != ubuntu ]; then echo "This server runs ${{PRETTY_NAME:-an unknown system}}, not Ubuntu"; exit 3; fi
echo "${{PRETTY_NAME:-Ubuntu}}"

step user
if id -u "$user" >/dev/null 2>&1; then
  echo "User $user already exists"
else
  useradd --create-home --shell /bin/bash --user-group "$user"
  usermod -p '*' "$user"
  echo "Created user $user"
fi
group=$(id -gn "$user")
home=$(getent passwd "$user" | cut -d: -f6)
[ -n "$home" ] && [ "$home" != / ] || {{ echo "User $user has no home folder"; exit 4; }}

step key
install -d -m 700 -o "$user" -g "$group" "$home/.ssh"
touch "$home/.ssh/authorized_keys"
if grep -qxF "$key" "$home/.ssh/authorized_keys"; then
  echo "Slipway's key is already authorized"
else
  printf '%s\\n' "$key" >> "$home/.ssh/authorized_keys"
  echo "Authorized Slipway's key for $user"
fi
chown "$user:$group" "$home/.ssh/authorized_keys"
chmod 600 "$home/.ssh/authorized_keys"

step docker
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  echo "Docker is already installed: $(docker --version)"
else
  {apt} update
  {apt} install docker.io docker-compose-v2
fi
if [ -d /run/systemd/system ]; then
  systemctl enable --now docker
elif [ -x /etc/init.d/docker ]; then
  service docker start || service docker status
else
  echo "This server does not run systemd: start the Docker daemon (dockerd) yourself"
fi
groupadd -f docker
usermod -aG docker "$user"
echo "Added $user to the docker group"

step deploy_root
mkdir -p "$root"
chown "$user:$group" "$root"
echo "$root belongs to $user"
"""


def as_root(script: str) -> str:
    """Run ``script`` as root: directly when signed in as root, otherwise with ``sudo -S`` (password on stdin)."""
    inner = "sh -c " + q(script)
    return f'if [ "$(id -u)" -eq 0 ]; then {inner}; else sudo -S -p "" {inner}; fi'


def sudo_problem(output: str, admin: str) -> str | None:
    """A plain explanation when the output shows ``sudo`` refused the admin user."""
    text = output.lower()
    if "incorrect password" in text or "sorry, try again" in text:
        return f"sudo did not accept the password for {admin}"
    if "not in the sudoers file" in text or "is not allowed to run sudo" in text:
        return f"{admin} may not use sudo: sign in as root, or as a user in the sudo group"
    if "sudo: command not found" in text or "sudo: not found" in text:
        return f"sudo is not installed and {admin} is not root: sign in as root"
    if "a terminal is required" in text or "no tty present" in text:
        return f"sudo on this server needs a terminal for {admin}: sign in as root instead"
    return None


# ------------------------------------------------------------------------- log


class SetupLog:
    """Collects the setup's output and step, and writes them to the host row about once a second."""

    def __init__(self, host_id: uuid.UUID, secret: str) -> None:
        self.host_id = host_id
        self.secret = secret
        self.text = ""
        self.step: str | None = None
        self._flushed = 0.0

    def scrub(self, line: str) -> str:
        if len(self.secret) >= 4:
            line = line.replace(self.secret, "********")
        return line

    async def line(self, line: str) -> None:
        line = line.strip("\r")
        if line.startswith(STEP_MARK):
            name = line[len(STEP_MARK):].strip()
            if name in STEP_NAMES:
                await self.set_step(name)
            return
        self.add(line)
        if time.monotonic() - self._flushed >= FLUSH_SECONDS:
            await self.flush()

    def add(self, line: str) -> None:
        self.text += ssh.clip_line(self.scrub(line)) + "\n"
        if len(self.text) > LOG_MAX_CHARS:
            self.text = "[earlier output cut]\n" + self.text[-LOG_MAX_CHARS:]

    async def set_step(self, name: str) -> None:
        self.step = name
        await self.flush()

    async def flush(self, **values: object) -> None:
        self._flushed = time.monotonic()
        async with session_scope() as db:
            await db.execute(
                update(Host).where(Host.id == self.host_id)
                .values(setup_log=ssh.clip(self.text, LOG_MAX_CHARS + 64), setup_step=self.step, **values)
            )


# ---------------------------------------------------------------------- runner


async def run_setup(host_id: uuid.UUID, admin: AdminLogin, actor_id: uuid.UUID | None) -> None:
    out = SetupLog(host_id, admin.password)
    try:
        await _setup(host_id, admin, actor_id, out)
    except asyncio.CancelledError:
        out.add("Slipway stopped before the setup finished.")
        await _finish(out, HostSetupStatus.INTERRUPTED, "Slipway stopped before the setup finished", actor_id)
        raise
    except (SetupError, ssh.SSHError) as exc:
        message = out.scrub(str(exc))
        out.add(message)
        await _finish(out, HostSetupStatus.FAILED, message, actor_id)
    except Exception:
        log.exception("Setting up host %s failed", host_id)
        out.add("Unexpected error; see Slipway's log.")
        await _finish(out, HostSetupStatus.FAILED, "Unexpected error; see Slipway's log", actor_id)
    else:
        await _finish(out, HostSetupStatus.SUCCEEDED, None, actor_id)


async def _finish(out: SetupLog, status: HostSetupStatus, error: str | None, actor_id: uuid.UUID | None) -> None:
    try:
        await out.flush(setup_status=status, setup_error=ssh.clip(error, 2000) if error else None)
        async with session_scope() as db:
            host = await db.get(Host, out.host_id)
            if host is None:
                return
            actor = await db.get(User, actor_id) if actor_id else None
            if status == HostSetupStatus.SUCCEEDED:
                audit.record(db, "host.setup", actor=actor, target=host, summary=f"Set up {host.name}: user {host.username}, SSH key and Docker")
            else:
                audit.record(
                    db, "host.setup_failed", actor=actor, target=host,
                    summary=f"Setting up {host.name} {'stopped' if status == HostSetupStatus.INTERRUPTED else 'failed'}: {error}",
                )
    except Exception:  # the host may have been removed, or the database be unavailable
        log.exception("Could not record the setup result for host %s", out.host_id)


async def _setup(host_id: uuid.UUID, admin: AdminLogin, actor_id: uuid.UUID | None, out: SetupLog) -> None:
    async with session_scope() as db:
        host = await db.get(Host, host_id)
        if host is None:
            raise SetupError("The host was removed")
        if not host.public_key:
            raise SetupError("Slipway has no key for this host")
        name, username, public_key, deploy_root = host.name, host.username, host.public_key, host.deploy_root
        target = ssh.SSHTarget(
            hostname=host.hostname, port=host.port, username=admin.username, password=admin.password,
            pinned_host_key=host.host_key,
        )

    await out.set_step("connect")
    out.add(f"Connecting to {target.hostname}:{target.port} as {admin.username}")
    async with ssh.open_session(target, allow_unpinned=True) as session:
        if target.pinned_host_key is None:
            await _pin(host_id, session.server_host_key(), actor_id, out)
        else:
            out.add("The server presented the pinned host key")
        script = ubuntu_script(username=username, public_key=public_key, deploy_root=deploy_root)
        status, output = await session.run(
            as_root(script), check=False, on_line=out.line, timeout=SCRIPT_TIMEOUT, input=admin.password + "\n",
        )
    if status != 0:
        problem = sudo_problem(output, admin.username)
        raise SetupError(problem or f"Setup stopped at '{_label(out.step)}' (exit status {status}); see the log")

    await out.set_step("verify")
    out.add(f"Checking {name} as {username} with Slipway's key")
    async with session_scope() as db:
        host = await db.get(Host, host_id)
        if host is None:
            raise SetupError("The host was removed")
        actor = await db.get(User, actor_id) if actor_id else None
        checked = await check_host(db, host, actor=actor)
        if checked is None:
            raise SetupError("The host was removed")
        if checked.status in (HostStatus.UNREACHABLE, HostStatus.ERROR):
            raise SetupError(f"Could not sign in as {username} with Slipway's key: {checked.last_error}")
        if not checked.docker_version:
            raise SetupError(f"Docker does not answer for {username}: {checked.last_error or 'unknown error'}")
        out.add(f"Docker {checked.docker_version} on {checked.os_info}")


async def _pin(host_id: uuid.UUID, host_key: str, actor_id: uuid.UUID | None, out: SetupLog) -> None:
    fp = ssh.fingerprint(host_key)
    async with session_scope() as db:
        host = await db.get(Host, host_id)
        if host is None:
            raise SetupError("The host was removed")
        actor = await db.get(User, actor_id) if actor_id else None
        host.host_key, host.host_key_fingerprint = host_key, fp
        audit.record(db, "host.key_pinned", actor=actor, target=host, summary=f"Pinned host key {fp} for {host.name}")
    out.add(f"Pinned the server's host key {fp}")


def _label(step: str | None) -> str:
    return dict(STEPS).get(step or "", step or "start")


class SetupRunner:
    """One setup task at a time per host, in this process."""

    def __init__(self) -> None:
        self._tasks: dict[uuid.UUID, asyncio.Task[None]] = {}

    def running(self, host_id: uuid.UUID) -> bool:
        return host_id in self._tasks

    def start(self, host_id: uuid.UUID, admin: AdminLogin, actor_id: uuid.UUID | None) -> None:
        if host_id in self._tasks:
            raise SetupError("Slipway is already setting up this host")
        task = asyncio.create_task(run_setup(host_id, admin, actor_id), name=f"host-setup-{host_id}")
        self._tasks[host_id] = task
        task.add_done_callback(lambda _: self._tasks.pop(host_id, None))

    async def wait(self, host_id: uuid.UUID) -> None:
        task = self._tasks.get(host_id)
        if task is not None:
            await asyncio.gather(task, return_exceptions=True)

    async def recover_interrupted(self) -> None:
        """Mark setups a previous process left running as interrupted."""
        async with session_scope() as db:
            stale = (await db.scalars(select(Host).where(Host.setup_status == HostSetupStatus.RUNNING))).all()
            for host in stale:
                host.setup_status = HostSetupStatus.INTERRUPTED
                host.setup_error = "Slipway restarted before the setup finished"

    async def shutdown(self) -> None:
        tasks = list(self._tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


def begin(host: Host) -> None:
    """Mark ``host`` as being set up (the caller commits, then starts the task)."""
    host.os_type = host.os_type or HostOS.UBUNTU
    host.setup_status = HostSetupStatus.RUNNING
    host.setup_step = None
    host.setup_log = ""
    host.setup_error = None
    host.setup_started_at = utcnow()


runner = SetupRunner()
