"""Fake VMs for the machines core's bootstrap (phase 5 §6.5, §16.1), on top of ``tests/fake_hosts.py``.

``VmRemote`` is S06's ``MultiRemote`` (found by address, a host key per host, ``booting``, ``firewalled``, the
cloud-init shim) with only the VM shims added: ``sudo``, ``apt-get``, ``usermod``, ``id -nG slipway``,
``install``, ``systemctl`` and a ``docker`` front for ``compose version``, ``version``, ``info`` and
``compose start``. Each VM keeps its state in ``$VM_STATE`` and logs every shimmed call to ``$VM_LOG``.

* Root commands work only through ``sudo -n`` (the shims refuse without it), and ``no_sudo`` makes sudo ask for
  a password, as a template without Slipway's sudo rule does.
* ``docker compose version`` fails until ``apt-get install`` ran; ``docker info`` answers only in a session
  opened after ``usermod -aG docker slipway`` (each session gets the groups the user had when it opened).
* ``dpkg_locked(address, n)``: ``apt-get`` without ``-o DPkg::Lock::Timeout`` fails at once with
  ``Could not get lock /var/lib/dpkg/lock-frontend``; with it, the lock is waited for when ``n`` is within the
  timeout (seconds), and fails with the lock text when it is beyond.
* ``install -d`` creates a folder only inside the fake host's own folder, so nothing outside the test's
  temporary folder is ever touched.
* ``boot_esxi_vm`` is what an ESXi VM's first boot does: the fake VM presents the host key its guestinfo
  user-data carries, as cloud-init's ``ssh_keys`` installs it (S13).
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from tests.fake_hosts import FakeHost, MultiRemote
from tests.test_final_remote import ShellRemote

ROOT_REFUSED = 'echo "$(basename "$0"): Permission denied (are you root?)" >&2; exit 1'

SUDO_SHIM = """#!/bin/sh
echo "sudo $*" >> "$VM_LOG"
[ "$1" = -n ] || { echo "sudo: Slipway always passes -n" >&2; exit 1; }
shift
[ -f "$VM_STATE/no-sudo" ] && { echo "sudo: a password is required" >&2; exit 1; }
FAKE_ROOT=1
export FAKE_ROOT
exec "$@"
"""

APT_SHIM = f"""#!/bin/sh
echo "apt-get $*" >> "$VM_LOG"
[ -n "$FAKE_ROOT" ] || {{ {ROOT_REFUSED}; }}
timeout=""
for a in "$@"; do case "$a" in DPkg::Lock::Timeout=*) timeout=${{a#DPkg::Lock::Timeout=}} ;; esac; done
locked=$(cat "$VM_STATE/dpkg-locked" 2>/dev/null || echo 0)
if [ "$locked" -gt 0 ]; then
  if [ -z "$timeout" ] || [ "$locked" -gt "$timeout" ]; then
    [ -n "$timeout" ] && echo "Waiting for cache lock: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 4242 (unattended-upgr)"
    echo "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 4242 (unattended-upgr)" >&2
    exit 100
  fi
  echo "Waited ${{locked}}s for the dpkg lock held by unattended-upgr" >> "$VM_LOG"
  echo "Waiting for cache lock: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 4242 (unattended-upgr)"
  echo 0 > "$VM_STATE/dpkg-locked"
fi
case " $* " in
  *" install "*)
    [ -f "$VM_STATE/apt-fails" ] && {{ echo "E: Unable to locate package docker-compose-v2" >&2; exit 100; }}
    echo "Setting up docker.io (26.1.3-0ubuntu1) ..."
    touch "$VM_STATE/docker-installed" ;;
  *" update "*) echo "Reading package lists..." ;;
esac
exit 0
"""

USERMOD_SHIM = f"""#!/bin/sh
echo "usermod $*" >> "$VM_LOG"
[ -n "$FAKE_ROOT" ] || {{ {ROOT_REFUSED}; }}
[ "$*" = "-aG docker slipway" ] || {{ echo "usermod: Slipway's fake knows only -aG docker slipway" >&2; exit 2; }}
[ -f "$VM_STATE/docker-installed" ] || {{ echo "usermod: group 'docker' does not exist" >&2; exit 6; }}
touch "$VM_STATE/in-docker-group"
"""

ID_SHIM = """#!/bin/sh
echo "id $*" >> "$VM_LOG"
if [ "$1" = -nG ] && [ "$2" = slipway ]; then
  if [ -f "$VM_STATE/in-docker-group" ]; then echo "slipway sudo docker"; else echo "slipway sudo"; fi
  exit 0
fi
exec /usr/bin/id "$@"
"""

INSTALL_SHIM = f"""#!/bin/sh
echo "install $*" >> "$VM_LOG"
[ -n "$FAKE_ROOT" ] || {{ {ROOT_REFUSED}; }}
[ "$1" = -d ] || {{ echo "install: Slipway's fake knows only -d" >&2; exit 1; }}
eval "dir=\\${{$#}}"
case "$dir" in
  "$HOME"/*) mkdir -p "$dir" ;;
  *) echo "would create $dir" >> "$VM_LOG" ;;
esac
"""

SYSTEMCTL_SHIM = f"""#!/bin/sh
echo "systemctl $*" >> "$VM_LOG"
[ -n "$FAKE_ROOT" ] || {{ {ROOT_REFUSED}; }}
[ -f "$VM_STATE/docker-installed" ] || {{ echo "Failed to enable unit: Unit file docker.service does not exist." >&2; exit 1; }}
exit 0
"""

DOCKER_VM_SHIM = """#!/bin/sh
echo "docker $*" >> "$VM_LOG"
installed() { [ -f "$VM_STATE/docker-installed" ]; }
member() { case " $SESSION_GROUPS " in *" docker "*) return 0 ;; esac; [ -n "$FAKE_ROOT" ]; }
case "$1" in
  compose)
    if [ "$2" = version ]; then
      installed || { echo "docker: 'compose' is not a docker command." >&2; exit 1; }
      echo "Docker Compose version 2.24.6"; exit 0
    fi ;;
  info|version)
    installed || { echo "sh: docker: not found" >&2; exit 127; }
    member || { echo "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock" >&2; exit 1; }
    echo "${FAKE_DOCKER_VERSION:-26.1.3}"; exit 0 ;;
esac
installed || { echo "sh: docker: not found" >&2; exit 127; }
exec "$BASE_DOCKER" "$@"
"""

# cloud-init: S06's shim, after an optional delay (a cloud-init that takes long, for the time limit tests).
CLOUD_INIT_VM_SHIM = """#!/bin/sh
[ -n "$FAKE_CLOUD_INIT_SLEEP" ] && sleep "$FAKE_CLOUD_INIT_SLEEP"
exec "$BASE_CLOUD_INIT" "$@"
"""

VM_SHIMS = {"sudo": SUDO_SHIM, "apt-get": APT_SHIM, "usermod": USERMOD_SHIM, "id": ID_SHIM, "install": INSTALL_SHIM,
            "systemctl": SYSTEMCTL_SHIM, "docker": DOCKER_VM_SHIM, "cloud-init": CLOUD_INIT_VM_SHIM}


class VmRemote(MultiRemote):
    """``MultiRemote`` plus fake VMs (``add_vm``). A session to a VM gets the groups the slipway user had when it
    opened, so ``usermod -aG docker`` counts only from the next session, as on a real host."""

    def __init__(self, tmp: Path, names: dict[str, str] | None = None, shell: str = "sh") -> None:
        super().__init__(tmp, names=names, shell=shell)
        if not names:  # MultiRemote adds phase 3's three hosts when given none; VMs come only from add_vm
            self.hosts.clear()
            self.by_address.clear()
        self.vm_bin = tmp / "vm-bin"
        self.vm_bin.mkdir(parents=True, exist_ok=True)
        for name, text in VM_SHIMS.items():
            (self.vm_bin / name).write_text(text)
            (self.vm_bin / name).chmod(0o755)
        self.vms: set[str] = set()
        self.sessions: list[tuple[str, str]] = []  # (address, the groups the session started with)

    def add_vm(self, name: str, address: str, *, host_key: str | None = None, docker: bool = False,
               sudo: bool = True) -> FakeHost:
        """A fresh VM at ``address`` presenting ``host_key`` (None: a new ed25519 key). ``docker``: Docker is in the
        template already (and the slipway user in its group)."""
        host = self.add(name, address, host_key=host_key)
        if host_key is None:
            self.new_key(address)
        state = host.tmp / "vm-state"
        state.mkdir(exist_ok=True)
        host.env.update(
            PATH=f"{self.vm_bin}:{host.env['PATH']}", VM_STATE=str(state), VM_LOG=str(host.tmp / "vm.log"),
            BASE_DOCKER=str(self.bin_dir / "docker"), BASE_CLOUD_INIT=str(self.bin_dir / "cloud-init"),
        )
        (host.tmp / "vm.log").write_text("")
        if docker:
            (state / "docker-installed").touch()
            (state / "in-docker-group").touch()
        if not sudo:
            (state / "no-sudo").touch()
        self.vms.add(name)
        return host

    # ------------------------------------------------------------------- knobs

    def _state(self, key: str) -> Path:
        return Path(self[key].env["VM_STATE"])

    def dpkg_locked(self, key: str, n: int) -> None:
        """Something holds the dpkg lock for ``n`` seconds (unattended-upgrades on a fresh Ubuntu)."""
        (self._state(key) / "dpkg-locked").write_text(str(n))

    def no_sudo(self, key: str, on: bool = True) -> None:
        path = self._state(key) / "no-sudo"
        path.touch() if on else path.unlink(missing_ok=True)

    def apt_fails(self, key: str) -> None:
        (self._state(key) / "apt-fails").touch()

    def cloud_init(self, key: str, state: str = "done", *, sleep: float | None = None) -> None:
        """What ``cloud-init status`` answers (done, running, degraded, error), after ``sleep`` seconds."""
        self[key].env["FAKE_CLOUD_INIT"] = state
        if sleep is None:
            self[key].env.pop("FAKE_CLOUD_INIT_SLEEP", None)
        else:
            self[key].env["FAKE_CLOUD_INIT_SLEEP"] = str(sleep)

    def docker_installed(self, key: str) -> bool:
        return (self._state(key) / "docker-installed").exists()

    def in_docker_group(self, key: str) -> bool:
        return (self._state(key) / "in-docker-group").exists()

    def vm_log(self, key: str) -> list[str]:
        """Every shimmed call on the VM, in order (``sudo -n ...``, ``apt-get ...``, ``id -nG slipway``...)."""
        path = Path(self[key].env["VM_LOG"])
        return path.read_text().splitlines() if path.exists() else []

    # ---------------------------------------------------------------- connect

    def connect(self, target: Any):
        self.targets.append(target)

        @asynccontextmanager
        async def session():
            host = self._reach(target)
            if host.name not in self.vms:
                yield host.remote
                return
            groups = "slipway sudo docker" if self.in_docker_group(host.address) else "slipway sudo"
            self.sessions.append((host.address, groups))
            remote = ShellRemote(self.shell, {**host.env, "SESSION_GROUPS": groups})
            remote.commands = host.remote.commands  # one list of commands per VM, whatever the session
            yield remote

        return session()


def guestinfo_host_key(extra: dict[str, str]) -> str | None:
    """The ed25519 public host key an ESXi VM's ``guestinfo.userdata`` installs (what cloud-init's ``ssh_keys``
    gives the VM on its first boot), or None when the user-data is gone (scrubbed after the pin)."""
    import base64

    import yaml

    raw = extra.get("guestinfo.userdata")
    if not raw:
        return None
    text = base64.b64decode(raw).decode() if extra.get("guestinfo.userdata.encoding") == "base64" else raw
    doc = yaml.safe_load(text.split("\n", 1)[1] if text.startswith("#cloud-config") else text) or {}
    return ((doc.get("ssh_keys") or {}).get("ed25519_public") or None)


def boot_esxi_vm(vms: VmRemote, name: str, address: str, extra: dict[str, str], **kw: Any) -> FakeHost:
    """What an ESXi VM's first boot does to its fake host: it presents the host key its user-data carries (a VM
    whose user-data is already scrubbed keeps the key it had). The fake VM host is added on its first boot."""
    key = guestinfo_host_key(extra)
    if address not in vms:
        return vms.add_vm(name, address, host_key=key, **kw) if key else vms.add_vm(name, address, **kw)
    if key:
        vms.present_key(address, key)
    return vms[address]


def probe_through(multi: MultiRemote):
    """An ``ssh.probe`` stand-in that runs the real probe command through the fake hosts (so ``check_host`` reads
    Docker's version from the fake VM), for ``monkeypatch.setattr(hosts.ssh, "probe", ...)``."""
    from slipway.services import ssh

    seen: list[Any] = []

    async def probe(target: Any) -> ssh.ProbeResult:
        seen.append(target)
        async with multi.connect(target) as session:
            _, output = await session.run(ssh.PROBE_COMMAND, check=False, timeout=30)
        return ssh.parse_probe(output, target.pinned_host_key or multi.pinned_key(target.hostname) or "")

    probe.seen = seen  # type: ignore[attr-defined]
    return probe


def environ(host: FakeHost) -> dict[str, str]:
    """A copy of the VM's shell environment (for tests that run a shim directly)."""
    return {**os.environ, **host.env}
