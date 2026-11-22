"""Migrate an instance to another host.

A migration is a ``Deployment`` of kind ``migrate``, for an instance outside environments whose
Dockerfile or compose file Slipway deploys (``refusal`` says why another can't move). Its request is in
``options["migration"]``. It runs under the instance's deploy lock like any deployment, in numbered
steps (``deployer.migrate_steps``):

1. Check, before anything changes: both hosts answer, and the instance's folder, the volumes and
   the bind-mounted paths it copies are free on the new host. With hostnames, Switchyard must be
   able to apply right away: once the old containers stop, a staged change would leave the
   hostnames pointing at them.
2. Stop the instance on the old host, so its data does not change while it is copied.
3. Copy, from host to host through Slipway (``RemoteSession.pipe_to``: neither host needs access to
   the other): the ``shared`` files of the instance's folder, each named volume the containers
   use, and each bind-mounted path outside the instance's folder (to the same path). Volumes and
   bind mounts are read and written by a throwaway container, so files containers wrote as root
   keep their owners.
4. Deploy, on the new host, the commit the old host runs (not the branch's newest one).
5. Point the instance at the new host, then sync Switchyard, which sends its hostnames to the new
   host's ports.

If a step before 5 fails, what was copied to the new host is removed and the instance is started
again on the old host. After 5, the old copy stays there, stopped, until ``remove_old_copy``
removes it (``Instance.migrated_from`` records it): moving back is then still possible by hand.
"""

from __future__ import annotations

import asyncio
import json
import logging
import posixpath
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import update

from slipway.db.base import utcnow
from slipway.db.session import session_scope
from slipway.models import BuildSource, DeploymentStatus, Host, Instance, InstanceStatus
from slipway.services import deployer, ssh, switchyard
from slipway.services.deployer import (
    CLEANUP_IMAGE,
    ConnectFactory,
    DeployError,
    GitHubFactory,
    InstancePaths,
    LogSink,
    Steps,
    paths_for,
    placed,
    q,
)
from slipway.services.github import CommitInfo, GitHubClient

log = logging.getLogger(__name__)

# Bind mounts of these are the host's own files (the Docker socket, the clock...), never copied.
SYSTEM_PATHS = (
    "/proc", "/sys", "/dev", "/run", "/var/run", "/etc", "/usr", "/lib", "/lib32", "/lib64", "/bin", "/sbin",
    "/boot", "/tmp", "/var/lib/docker", "/var/log",
)
_VOLUME_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$")
_ANONYMOUS = re.compile(r"^[0-9a-f]{64}$")
PROGRESS_EVERY = 10.0  # seconds between "copied so far" lines


# ------------------------------------------------------------------------ who can move


def _ssh(host: Host | None) -> bool:
    return host is not None and (host.provider or "ssh") == "ssh"


def refusal(instance: Instance, target: Host | None = None) -> str | None:
    """Why ``instance`` can't migrate (to ``target``, when given), or None. Nothing here needs SSH.

    This first version moves standalone instances whose Dockerfile or compose file Slipway deploys, between
    hosts added over SSH. An environment's slots move with the environment's own hosts and traffic switch, and
    a slipway.yml app's data has its own backups and records on its host, so those are refused with a reason.
    """
    if instance.environment_id is not None:
        return (f"{instance.name} is a slot of an environment, which places its slots on its own hosts: "
                "Migrate moves standalone instances only")
    if instance.build_source == BuildSource.APP:
        return (f"{instance.name} is a slipway.yml app, whose data and backups Slipway keeps on its host: "
                "Migrate moves Dockerfile and compose instances only")
    if instance.host is None:
        return f"{instance.name} has no host to move from"
    if not _ssh(instance.host):
        return f"{instance.host.name} is a server a provider made for an environment: Migrate moves from SSH hosts only"
    if target is not None and not _ssh(target):
        return f"{target.name} is a server a provider made for an environment: Migrate moves to SSH hosts only"
    return None


# ------------------------------------------------------------------------ the plan


@dataclass
class Item:
    """One thing a migration copies, or found and leaves alone (``copy`` False, ``note`` says why)."""

    id: str  # "folder", "volume:<name>" or "bind:<path>"
    kind: str  # "folder" | "volume" | "bind"
    name: str  # the path, or the volume's name
    copy: bool = True
    note: str = ""
    conflict: str = ""  # why the new host can't take it as it is; blocks the migration unless skipped
    size_kb: int | None = None
    is_file: bool = False  # a bind-mounted file rather than a folder
    target_empty_dir: bool = False  # bind: the path is an empty folder on the new host already
    labels: dict[str, str] = field(default_factory=dict)  # volume labels (Compose finds its volumes by them)

    def out(self, skip: set[str]) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "name": self.name, "copy": self.copy, "note": self.note,
                "conflict": self.conflict, "size_kb": self.size_kb, "skipped": self.id in skip}

    @property
    def label(self) -> str:
        if self.kind == "folder":
            return f"the instance's settings ({self.name})"
        return f"volume {self.name}" if self.kind == "volume" else self.name


@dataclass
class Plan:
    source: Host
    target: Host
    source_dir: str
    target_dir: str
    running: bool
    items: list[Item] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)  # block the migration
    notes: list[str] = field(default_factory=list)

    def selected(self, skip: set[str]) -> list[Item]:
        return [i for i in self.items if i.copy and i.id not in skip]

    def blocking(self, skip: set[str]) -> list[str]:
        return self.problems + [f"{i.name}: {i.conflict}" for i in self.selected(skip) if i.conflict]

    def total_kb(self, skip: set[str]) -> int:
        return sum(i.size_kb or 0 for i in self.selected(skip))

    def out(self, skip: set[str]) -> dict[str, Any]:
        return {
            "source": self.source.name, "target": self.target.name,
            "source_dir": self.source_dir, "target_dir": self.target_dir, "running": self.running,
            "items": [i.out(skip) for i in self.items], "problems": self.problems, "notes": self.notes,
            "blocking": self.blocking(skip), "total_kb": self.total_kb(skip),
        }


def size_text(kb: int | None) -> str:
    if kb is None:
        return "size unknown"
    value, unit = float(kb), "KiB"
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            break
        value /= 1024
    return f"{value:.0f} {unit}" if unit == "KiB" or value >= 100 else f"{value:.1f} {unit}"


def _inside(path: str, directory: str) -> bool:
    return path == directory or path.startswith(directory + "/")


def mounts_command(instance: Instance) -> str:
    """Prints ``type<TAB>name<TAB>source`` for each mount of the instance's containers."""
    fmt = '{{range .Mounts}}{{printf "%s\\t%s\\t%s\\n" .Type .Name .Source}}{{end}}'
    lists = [
        f"docker ps -aq --filter {q('label=slipway.instance=' + str(instance.id))}",
        f"docker ps -aq --filter {q('label=com.docker.compose.project=' + instance.compose_project)}",
    ]
    return (
        f"ids=$({' && '.join(lists)}) && "
        f"{{ [ -z \"$ids\" ] || printf '%s\\n' \"$ids\" | sort -u | xargs docker container inspect -f {q(fmt)}; }}"
    )


def volume_inspect_command(names: list[str]) -> str:
    fmt = '{{.Name}}\t{{.Driver}}\t{{json .Options}}\t{{json .Labels}}'
    return f"docker volume inspect -f {q(fmt)} {' '.join(q(n) for n in names)}"


def _source_mount(item: Item, at: str) -> str:
    """``--mount`` for reading ``item`` on the old host: unlike ``-v`` it never creates a missing path."""
    kind = "bind" if item.kind == "bind" else "volume"
    return f"--mount {q(f'type={kind},source={item.name},target={at},readonly')}"


def probe_command(items: list[Item]) -> str:
    """Prints ``<n> <dir|file|other>`` for each item, looked at from a throwaway container."""
    mounts = " ".join(_source_mount(item, f"/m/{n}") for n, item in enumerate(items))
    loop = " ".join(str(n) for n in range(len(items)))
    script = (f"for i in {loop}; do if [ -d /m/$i ]; then t=dir; elif [ -f /m/$i ]; then t=file; else t=other; fi; "
              'echo "$i $t"; done')
    return f"docker run --rm --network none {mounts} {CLEANUP_IMAGE} sh -c {q(script)}"


def size_command(items: list[Item], folder: str | None) -> str:
    """Prints ``<n> <KiB>`` for each item (``folder`` for the shared files), as far as ``du`` gets."""
    parts = []
    if folder:
        parts.append(f"s=$(du -sk {q(folder)} 2>/dev/null | cut -f1); echo \"folder ${{s:-?}}\"")
    if items:
        mounts = " ".join(_source_mount(item, f"/m/{n}") for n, item in enumerate(items))
        loop = " ".join(str(n) for n in range(len(items)))
        script = f'for i in {loop}; do s=$(du -sk /m/$i 2>/dev/null | cut -f1); echo "$i ${{s:-?}}"; done'
        parts.append(f"docker run --rm --network none {mounts} {CLEANUP_IMAGE} sh -c {q(script)}")
    return "; ".join(parts) or "true"


def _taken_test(path: str) -> str:
    """Shell test that succeeds when ``path`` holds something (anything but an empty folder or nothing)."""
    p = q(path)
    return (f"{{ [ -e {p} ] || [ -L {p} ]; }} && ! {{ [ -d {p} ] && [ ! -L {p} ] && out=$(ls -A {p} 2>/dev/null) "
            f"&& [ -z \"$out\" ]; }}")


def target_check_command(target_base: str, volumes: list[str], binds: list[str], *, need_image: bool) -> str:
    """Prints a line for each thing in the way on the new host (``folder``, ``volume <n>``, ``bind <path>``,
    ``empty <path>`` for an empty folder there already, ``nodocker``, ``noimage``)."""
    parts = ["docker version --format . >/dev/null 2>&1 || echo nodocker"]
    parts.append(f"if {_taken_test(target_base)}; then echo folder; fi")
    for name in volumes:
        parts.append(f"docker volume inspect -f . {q(name)} >/dev/null 2>&1 && printf 'volume %s\\n' {q(name)}")
    for path in binds:
        p = q(path)
        parts.append(f"if {_taken_test(path)}; then printf 'bind %s\\n' {p}; "
                     f"elif [ -d {p} ]; then printf 'empty %s\\n' {p}; fi")
    if need_image:
        parts.append(f"docker image inspect {CLEANUP_IMAGE} >/dev/null 2>&1 || docker pull -q {CLEANUP_IMAGE} "
                     ">/dev/null 2>&1 || echo noimage")
    return "; ".join(parts) + "; true"


def _system(path: str) -> bool:
    return path == "/" or any(_inside(path, p) for p in SYSTEM_PATHS)


async def build_plan(
    instance: Instance, target: Host, target_dir: str | None, src: ssh.RemoteSession, dst: ssh.RemoteSession,
) -> Plan:
    """What migrating ``instance`` (on its own host) to ``target`` copies, and what stands in the way."""
    source_paths = paths_for(instance)
    with placed(instance, target, target_dir):
        target_paths = paths_for(instance)
    plan = Plan(instance.host, target, source_paths.base, target_paths.base,
                running=instance.status == InstanceStatus.RUNNING)

    status, output = await src.run(mounts_command(instance), check=False, timeout=60)
    if status:
        plan.problems.append(f"Docker on {instance.host.name} could not list {instance.name}'s containers "
                             f"({deployer._last_line(output) or 'no output'})")
        return plan

    volumes: dict[str, Item] = {}
    binds: dict[str, Item] = {}
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        kind, name, source = (p.strip() for p in parts)
        if kind == "volume" and name and name not in volumes:
            volumes[name] = Item(f"volume:{name}", "volume", name)
        elif kind == "bind" and source.startswith("/") and source not in binds:
            binds[source] = Item(f"bind:{source}", "bind", posixpath.normpath(source))

    for item in volumes.values():
        if _ANONYMOUS.match(item.name):
            item.copy, item.note = False, "Anonymous volume: the containers on the new host get new, empty ones"
        elif not _VOLUME_NAME.match(item.name):
            item.copy, item.note = False, "Slipway can't copy a volume with this name"
    for item in binds.values():
        path = item.name
        if _inside(path, source_paths.shared):
            item.copy = False
            item.note = "In the instance's folder: copied with it"
            if source_paths.base != target_paths.base:
                plan.notes.append(f"{path} is mounted by its path, but the instance's folder moves to "
                                  f"{target_paths.base}: update the mount to the new folder")
        elif _inside(path, source_paths.base):
            item.copy, item.note = False, "Inside a release: every deploy starts it empty"
        elif _system(path):
            item.copy, item.note = False, "A system path of the host: not copied"
        elif any(c in path for c in ",:\n\t"):
            item.copy, item.note = False, "Slipway can't copy a path with a comma or colon in it; copy it by hand"

    named = [v for v in volumes.values() if v.copy]
    if named:
        status, output = await src.run(volume_inspect_command([v.name for v in named]), check=False, timeout=60)
        details = {}
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) == 4:
                details[parts[0]] = parts[1:]
        for item in named:
            driver, options, labels = details.get(item.name, ("", "null", "null"))
            if not driver:
                item.copy, item.note = False, "Docker could not describe this volume"
                continue
            try:
                opts, item.labels = json.loads(options) or {}, {str(k): str(v) for k, v in (json.loads(labels) or {}).items()}
            except ValueError:
                opts = {"?": "?"}
            if driver != "local" or opts:
                item.copy = False
                item.note = (f"Uses the {driver} volume driver" if driver != "local" else "A volume with mount options "
                             "(network storage?)") + ": its data is not copied; the new host makes its own"

    copies = [i for i in [*volumes.values(), *binds.values()] if i.copy]
    if copies:
        status, output = await src.run(probe_command(copies), check=False, timeout=300)
        kinds = dict(line.split(" ", 1) for line in output.splitlines() if re.match(r"^\d+ \w+$", line))
        if status:
            plan.problems.append(f"Could not look at the volumes and folders on {instance.host.name} "
                                 f"({deployer._last_line(output) or 'no output'})")
        for n, item in enumerate(copies):
            what = kinds.get(str(n))
            if item.kind == "bind" and what == "file":
                item.is_file = True
                if posixpath.dirname(item.name) == "/":
                    item.copy, item.note = False, "A file directly in /: copy it by hand"
            elif item.kind == "bind" and what == "other":
                item.copy, item.note = False, "Not a file or folder (a socket?): not copied"

    folder_item = Item("folder", "folder", source_paths.shared)
    status, _ = await src.run(f"[ -d {q(source_paths.shared)} ]", check=False, timeout=30)
    if status:
        folder_item.copy, folder_item.note = False, f"Not on {instance.host.name}: the deploy writes it again"
    plan.items = [folder_item, *volumes.values(), *binds.values()]

    copies = [i for i in plan.items if i.copy and i.kind != "folder"]
    try:
        _, output = await src.run(size_command(copies, source_paths.shared if folder_item.copy else None),
                                  check=False, timeout=300)
    except ssh.SSHError:
        output = ""  # du took too long: sizes stay unknown
    for line in output.splitlines():
        key, _, size = line.partition(" ")
        if not size.strip().isdigit():
            continue
        if key == "folder":
            folder_item.size_kb = int(size)
        elif key.isdigit() and int(key) < len(copies):
            copies[int(key)].size_kb = int(size)

    vols = [i.name for i in plan.items if i.copy and i.kind == "volume"]
    bind_paths = [i.name for i in plan.items if i.copy and i.kind == "bind"]
    _, output = await dst.run(target_check_command(target_paths.base, vols, bind_paths, need_image=bool(vols or bind_paths)),
                              check=False, timeout=600)
    for line in output.splitlines():
        word, _, rest = line.strip().partition(" ")
        if word == "nodocker":
            plan.problems.append(f"Docker is not running on {target.name}, or {target.username} can't use it")
        elif word == "noimage":
            plan.problems.append(f"{target.name} could not pull {CLEANUP_IMAGE}, which Slipway copies volumes with")
        elif word == "folder":
            plan.problems.append(f"{target_paths.base} already exists on {target.name} and is not empty; "
                                 "remove it there or choose another folder")
        elif word == "volume":
            for i in plan.items:
                if i.kind == "volume" and i.name == rest:
                    i.conflict = f"a volume with this name already exists on {target.name}; untick it to use that one"
        elif word in ("bind", "empty"):
            for i in plan.items:
                if i.kind == "bind" and i.name == rest:
                    if word == "bind":
                        i.conflict = f"already exists on {target.name}; untick it to keep what is there"
                    else:
                        i.target_empty_dir = True

    if instance.routes or instance.proxy_entries:
        async with session_scope() as db:
            config = await switchyard.load_config(db)
        if config is None:
            plan.notes.append("Switchyard is not set up, so no hostname is changed")
        else:
            blocker = await switchyard.apply_blocker(config)
            if blocker:
                plan.problems.append(
                    f"Switchyard can't apply changes right now ({blocker}). The hostnames would keep pointing at "
                    f"{instance.host.name} after its containers stop: apply or discard the waiting changes in "
                    "Switchyard first"
                )
    if any(o.get("auto") for o in instance.port_overrides or []):
        plan.notes.append(f"Ports Slipway moved on {instance.host.name} are tried as the compose file sets them on "
                          f"{target.name}")
    return plan


async def check(
    instance_id: uuid.UUID, target_id: uuid.UUID, target_dir: str | None, *, connect: ConnectFactory | None = None,
) -> Plan:
    """``build_plan`` over fresh SSH sessions, on a copy of the instance no request's session tracks."""
    connect = connect or ssh.open_session
    async with session_scope() as db:
        instance = await db.get(Instance, instance_id)
        target = await db.get(Host, target_id)
    if instance is None or target is None:
        raise DeployError("The instance or the host is gone")
    async with connect(ssh.SSHTarget.from_host(instance.host)) as src, connect(ssh.SSHTarget.from_host(target)) as dst:
        return await build_plan(instance, target, target_dir, src, dst)


# ------------------------------------------------------------------------- the run


class _Progress:
    """Logs how much of a copy is done, at most every ``PROGRESS_EVERY`` seconds."""

    def __init__(self, sink: LogSink, size_kb: int | None) -> None:
        self.sink, self.size_kb, self.last = sink, size_kb, time.monotonic()

    async def __call__(self, copied: int) -> None:
        now = time.monotonic()
        if now - self.last < PROGRESS_EVERY:
            return
        self.last = now
        of = f" of about {size_text(self.size_kb)}" if self.size_kb else ""
        await self.sink.line(f"  {size_text(copied // 1024)}{of} copied")


def copy_commands(item: Item, source: InstancePaths, target: InstancePaths) -> tuple[str, str]:
    """(read on the old host, write on the new host) for one item."""
    tar = "tar --numeric-owner"
    if item.kind == "folder":
        return f"cd {q(source.base)} && tar -cf - shared", f"tar -C {q(target.base)} -xf -"
    if item.kind == "volume":
        return (
            f"docker run --rm --network none {_source_mount(item, '/v')} {CLEANUP_IMAGE} {tar} -C /v -cf - .",
            f"docker run --rm -i --network none -v {q(item.name + ':/v')} {CLEANUP_IMAGE} {tar} -C /v -xpf -",
        )
    if item.is_file:
        parent, name = posixpath.split(item.name)
        return (
            f"docker run --rm --network none {_source_mount(item, '/s/' + name)} {CLEANUP_IMAGE} {tar} -C /s -cf - {q(name)}",
            f"docker run --rm -i --network none -v {q(parent + ':/d')} {CLEANUP_IMAGE} {tar} -C /d -xpf -",
        )
    return (
        f"docker run --rm --network none {_source_mount(item, '/s')} {CLEANUP_IMAGE} {tar} -C /s -cf - .",
        f"docker run --rm -i --network none -v {q(item.name + ':/d')} {CLEANUP_IMAGE} {tar} -C /d -xpf -",
    )


def volume_create_command(item: Item) -> str:
    labels = "".join(f" --label {q(f'{k}={v}')}" for k, v in sorted(item.labels.items()))
    return f"docker volume create{labels} {q(item.name)} >/dev/null"


def bind_undo_command(item: Item) -> str:
    """Remove what a copy wrote to a bind-mounted path on the new host (emptying a folder that was empty)."""
    if item.target_empty_dir:
        return (f"docker run --rm --network none -v {q(item.name + ':/d')} {CLEANUP_IMAGE} "
                "find /d -mindepth 1 -delete")
    parent, name = posixpath.split(item.name)
    return deployer._root_rm(q(parent), q(name))


class _Run:
    def __init__(self, deployment_id: uuid.UUID, job: deployer._Job, target: Host, target_dir: str | None,
                 skip: set[str], sink: LogSink, steps: Steps, src: ssh.RemoteSession, dst: ssh.RemoteSession,
                 connect: ConnectFactory, github: GitHubFactory) -> None:
        self.deployment_id, self.job, self.instance = deployment_id, job, job.instance
        self.source = job.instance.host
        self.target, self.target_dir, self.skip, self.sink, self.steps = target, target_dir, skip, sink, steps
        self.src, self.dst, self.connect, self.github = src, dst, connect, github
        self.previous = str(job.status_before or InstanceStatus.CREATED)
        self.stopped = False
        self.made_folder = False
        self.deploying = False
        self.made: list[Item] = []  # volumes and bind-mounted paths written on the new host
        self.copied: list[Item] = []
        inst = self.instance
        self.saved_ports = {"ports": list(inst.ports or []), "port_overrides": list(inst.port_overrides or []),
                            "published_ports": list(inst.published_ports or [])}

    @property
    def changed(self) -> bool:
        """Whether anything was changed yet (else a failure leaves nothing to undo)."""
        return self.stopped or self.made_folder or bool(self.made)

    async def say(self, line: str) -> None:
        await self.sink.line(line)

    async def run(self) -> CommitInfo:
        inst, sha, steps = self.instance, self.instance.current_commit_sha, self.steps
        async with steps.step("migrate_check"):
            await self.say(f"Migrating {inst.name} from {self.source.name} to {self.target.name}")
            if not sha:
                raise DeployError(f"{inst.name} has no deployed commit to migrate; deploy it first")
            if inst.claim_pending:
                raise DeployError("A claimed instance moves once Slipway has deployed it; deploy it first")
            plan = await build_plan(inst, self.target, self.target_dir, self.src, self.dst)
            for item in plan.items:
                if item.copy and item.id not in self.skip:
                    await self.say(f"Will copy {item.label} ({size_text(item.size_kb)})")
                else:
                    await self.say(f"Will not copy {item.label}: {'unticked' if item.copy else item.note}")
            for note in plan.notes:
                await self.say(f"Note: {note}")
            blocking = plan.blocking(self.skip)
            if blocking:
                raise DeployError("Nothing was changed. " + "; ".join(blocking))

        if self.previous == InstanceStatus.RUNNING:
            async with steps.step("migrate_stop"):
                await self.say(f"Stopping {inst.name} on {self.source.name}")
                self.stopped = True  # set first: a stop that fails half way is started again by undo()
                await self.src.run(deployer.control_command(inst, "stop"), on_line=self.sink.line, timeout=600)
        elif self.previous == InstanceStatus.FAILED:
            async with steps.step("migrate_stop"):
                # A failed deploy usually leaves the previous containers running: stop them if they are there.
                await self.say(f"Stopping {inst.name} on {self.source.name}, if it runs")
                status, _ = await self.src.run(deployer.control_command(inst, "stop"), check=False, timeout=600)
                self.stopped = status == 0
        else:
            await steps.skip("migrate_stop", f"{inst.name} was not running on {self.source.name}")

        source_paths = paths_for(inst)
        async with steps.step("migrate_copy"):
            with placed(inst, self.target, self.target_dir):
                target_paths = paths_for(inst)
                await self.say(f"Preparing {target_paths.base} on {self.target.name}")
                status, output = await self.dst.run(deployer.take_dir_command(inst), check=False, timeout=60)
                if status:
                    raise deployer.take_dir_error(inst, output)
                self.made_folder = True
                await self.dst.run(f"mkdir -p {q(target_paths.releases)}")
            selected = plan.selected(self.skip)
            for item in selected:
                await self.copy(item, source_paths, target_paths)
            if not selected:
                await self.say("Nothing to copy")

        with placed(inst, self.target, self.target_dir):
            inst.port_overrides = [o for o in inst.port_overrides or [] if not o.get("auto")]
            self.deploying = True
            self.job.options["pin_commit"] = sha  # the commit the old host runs, not the branch's newest
            await self.say(f"Deploying commit {sha[:12]} on {self.target.name}")
            return await deployer._pipeline(self.deployment_id, self.job, self.sink, steps, self.connect, self.github)

    async def copy(self, item: Item, source: InstancePaths, target: InstancePaths) -> None:
        await self.say(f"Copying {item.label} ({size_text(item.size_kb)})")
        if item.kind == "volume":
            self.made.append(item)
            await self.dst.run(volume_create_command(item), timeout=120)
        elif item.kind == "bind":
            self.made.append(item)
        read, write = copy_commands(item, source, target)
        started = time.monotonic()
        copied = await self.src.pipe_to(self.dst, read, write, on_progress=_Progress(self.sink, item.size_kb))
        self.copied.append(item)
        await self.say(f"  {size_text(copied // 1024)} copied in {time.monotonic() - started:.0f}s")

    async def undo(self) -> str:
        """Put things back after a failure; returns the instance's status."""
        inst = self.instance
        await self.say(f"Undoing: removing what was copied to {self.target.name}")
        with placed(inst, self.target, self.target_dir):
            target_paths = paths_for(inst)
            todo = []
            if self.deploying:
                todo.append(("containers", deployer.teardown_command(inst)))
            if self.made_folder:
                todo.append((target_paths.base, deployer._remove_base_command(target_paths)))
        for item in self.made:
            if item.kind == "volume":
                todo.append((f"volume {item.name}", f"docker volume rm {q(item.name)} >/dev/null"))
            else:
                todo.append((item.name, bind_undo_command(item)))
        for what, command in todo:
            try:
                status, output = await self.dst.run(command, check=False, timeout=600)
            except ssh.SSHError as exc:
                status, output = 1, str(exc)
            if status:
                await self.say(f"Warning: could not remove {what} on {self.target.name} "
                               f"({deployer._last_line(output) or 'no output'}); remove it by hand")

        try:
            async with session_scope() as db:
                await db.execute(update(Instance).where(Instance.id == inst.id).values(**self.saved_ports))
            for key, value in self.saved_ports.items():
                setattr(inst, key, value)
        except Exception as exc:  # the instance's ports stay as the new host planned them
            log.warning("Could not restore the ports of %s: %s", inst.name, exc)

        if not self.stopped:
            return self.previous
        try:
            await self.src.run(deployer.control_command(inst, "start"), on_line=self.sink.line, timeout=600)
        except (ssh.SSHError, DeployError) as exc:
            await self.say(f"Warning: could not start {inst.name} on {self.source.name} again ({exc}); start it there")
            return InstanceStatus.STOPPED
        await self.say(f"Started {inst.name} on {self.source.name} again")
        return InstanceStatus.RUNNING if self.previous == InstanceStatus.RUNNING else self.previous

    async def switch(self) -> None:
        """The new host runs the instance: record it, then point Switchyard at it."""
        inst, steps = self.instance, self.steps
        async with steps.step("migrate_switch"):
            migrated_from = {
                "host_id": str(self.source.id), "host_name": self.source.name, "dir": paths_for(inst).base,
                "volumes": [i.name for i in self.copied if i.kind == "volume"],
                "binds": [i.name for i in self.copied if i.kind == "bind"],
                "deployment_id": str(self.deployment_id), "at": utcnow().isoformat(),
            }
            async with session_scope() as db:
                await db.execute(update(Instance).where(Instance.id == inst.id).values(
                    host_id=self.target.id, deploy_dir=self.target_dir, migrated_from=migrated_from,
                    port_overrides=inst.port_overrides or [],  # without the ports Slipway moved on the old host
                ))
            inst.host, inst.host_id, inst.deploy_dir, inst.migrated_from = (
                self.target, self.target.id, self.target_dir, migrated_from)
            await self.say(f"{inst.name} now runs on {self.target.name}")
        if not (inst.routes or inst.proxy_entries):
            await steps.skip("proxy", "No hostnames")
            return
        await steps.begin("proxy")
        try:
            await switchyard.sync_and_store(inst, say=self.say)
        except Exception as exc:  # the containers run: a proxy problem never fails the migration
            log.warning("Proxy sync after migrating %s failed: %s", inst.name, exc)
            await self.say(f"Proxy: could not update Switchyard: {exc}. Use Sync proxy on the instance page")
            await steps.end("warning", note=str(exc))
        else:
            await steps.end("succeeded")


async def _load_target(job: deployer._Job) -> Host | None:
    host_id = (job.options.get("migration") or {}).get("target_host_id")
    if not host_id:
        return None
    async with session_scope() as db:
        return await db.get(Host, uuid.UUID(str(host_id)))


async def run_migration(
    deployment_id: uuid.UUID, job: deployer._Job, *, connect: ConnectFactory = ssh.open_session,
    github: GitHubFactory = GitHubClient,
) -> None:
    sink = LogSink(deployment_id, hide=job.hide)
    steps = Steps(deployment_id, job.steps, sink)
    migration = dict(job.options.get("migration") or {})
    previous = str(job.status_before or InstanceStatus.CREATED)

    async def ended(status: DeploymentStatus, line: str, error: str | None, left: str, *, short: bool = False) -> None:
        await sink.line(line)
        await steps.close()
        await sink.close()
        await deployer._finish(deployment_id, status, error=error, short=short, scrub=sink.scrub, status=left)

    target = await _load_target(job)
    if target is None or target.id == job.instance.host_id:
        await ended(DeploymentStatus.FAILED, "Migration failed: the new host is gone, or is the instance's own host",
                    "The new host is not available", previous)
        return
    run: _Run | None = None
    try:
        await sink.line(f"Connecting to {job.instance.host.name} and {target.name}")
        async with connect(ssh.SSHTarget.from_host(job.instance.host)) as src, \
                connect(ssh.SSHTarget.from_host(target)) as dst:
            run = _Run(deployment_id, job, target, migration.get("target_dir"), set(migration.get("skip") or []),
                       sink, steps, src, dst, connect, github)
            try:
                commit = await run.run()
            except BaseException as exc:
                cancelled = isinstance(exc, asyncio.CancelledError)
                status = previous
                if run.changed:
                    try:
                        status = await asyncio.wait_for(asyncio.shield(run.undo()), 300) if cancelled else await run.undo()
                    except Exception as undo_exc:
                        log.warning("Undoing migration %s failed: %s", deployment_id, undo_exc)
                        await sink.line(f"Warning: undoing the migration failed: {undo_exc}")
                        status = InstanceStatus.FAILED
                raise _Undone(status) from exc
            await run.switch()
    except _Undone as undone:
        exc = undone.__cause__
        if isinstance(exc, asyncio.CancelledError):
            await ended(DeploymentStatus.CANCELLED, "Migration interrupted: Slipway is shutting down", "Interrupted",
                        undone.status, short=True)
            raise exc from None
        log.info("Migration %s failed: %s", deployment_id, sink.scrub(str(exc)))
        await ended(DeploymentStatus.FAILED, f"Migration failed: {exc}", str(exc), undone.status)
        return
    except asyncio.CancelledError:
        await ended(DeploymentStatus.CANCELLED, "Migration interrupted: Slipway is shutting down", "Interrupted",
                    previous, short=True)
        raise
    except Exception as exc:  # connecting failed: nothing was changed
        await ended(DeploymentStatus.FAILED, f"Migration failed: {exc}. Nothing was changed.", str(exc), previous)
        return
    await sink.line(f"Migration succeeded. The stopped copy on {job.instance.migrated_from['host_name']} stays "
                    "there until you remove it from the instance page.")
    await steps.close()
    await sink.close()
    await deployer._finish(deployment_id, DeploymentStatus.SUCCEEDED, status=InstanceStatus.RUNNING,
                           current_commit_sha=commit.sha, last_deployed_at=utcnow())


class _Undone(Exception):  # noqa: N818 - carries the status the instance was left in
    def __init__(self, status: str) -> None:
        super().__init__(status)
        self.status = status


# --------------------------------------------------------------- the old copy


async def remove_old_copy(instance_id: uuid.UUID, *, connect: ConnectFactory | None = None) -> str | None:
    """Remove the stopped copy a migration left on the old host: containers, images, the folder and the
    volumes the migration copied. Paths outside the folder are kept. Returns a warning, or None.

    Raises ``DeployError``/``ssh.SSHError`` when the containers could not be removed (then nothing is recorded
    as removed). Does not clear ``migrated_from``: the caller does, with its audit entry.
    """
    connect = connect or ssh.open_session
    async with session_scope() as db:
        instance = await db.get(Instance, instance_id)
        old = dict(instance.migrated_from or {}) if instance else {}
        host = await db.get(Host, uuid.UUID(old["host_id"])) if old.get("host_id") else None
    if instance is None or not old:
        return None
    if host is None:
        return f"{old.get('host_name', 'The old host')} is no longer in Slipway, so its copy was not touched"
    notes: list[str] = []
    with placed(instance, host, old.get("dir")):
        warning = await deployer.destroy(instance, connect=connect)
        if warning:
            notes.append(warning)
        volumes = [v for v in old.get("volumes") or [] if _VOLUME_NAME.match(v)]
        if volumes:
            async with connect(ssh.SSHTarget.from_host(host)) as remote:
                for name in volumes:
                    status, output = await remote.run(f"docker volume rm {q(name)}", check=False, timeout=120)
                    if status:
                        notes.append(f"Kept volume {name} on {host.name} ({deployer._last_line(output) or 'in use?'})")
    if old.get("binds"):
        notes.append(f"Kept {', '.join(old['binds'])} on {host.name}: Slipway does not delete paths outside the "
                     "instance's folder")
    return " ".join(notes) or None
