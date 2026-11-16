"""Containers on a host that Slipway did not deploy: list them and claim them as instances.

Claiming creates an instance pre-filled from what runs on the host. A compose project keeps its
project name (``Instance.compose_project_name``), so Compose keeps using its named volumes and
networks; a standalone container is replaced by the first deployment (see ``services.deployer``).
Nothing on the host changes when an instance is claimed, and nothing of the claimed app (its
directory, its volumes) is ever deleted by the claim or the deployment that follows it.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import ValidationError
from sqlalchemy import select

from slipway.api.deps import DB, not_found, require
from slipway.api.v1.instances import queue_deployment
from slipway.core.permissions import Perm
from slipway.db.base import utcnow
from slipway.models import BuildSource, Host, Instance, InstanceStatus, Repository
from slipway.schemas import BRANCH_MAX, ClaimIn, ClaimOut, InstanceOut, PortMapping, VolumeMapping
from slipway.services import audit, deployer, discovery, ssh
from slipway.services.auth import AuthContext

router = APIRouter(prefix="/hosts", tags=["hosts"])

Lister = Annotated[AuthContext, require(Perm.HOSTS_READ, Perm.INSTANCES_READ)]
Claimer = Annotated[AuthContext, require(Perm.INSTANCES_WRITE)]

open_session = ssh.open_session  # replaced in tests


async def _host(db: DB, host_id: uuid.UUID) -> Host:
    host = await db.get(Host, host_id)
    if host is None:
        raise not_found("Host")
    if not host.is_pinned:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"Host {host.name} has not been verified yet; run a connection check first"
        )
    return host


async def _claimed(db: DB, host: Host) -> tuple[set[str], set[str]]:
    """Compose project names and standalone container ids the host's instances already stand for."""
    instances = (await db.scalars(select(Instance).where(Instance.host_id == host.id))).all()
    projects = {i.compose_project for i in instances}
    containers = {i.claimed_container for i in instances if i.claimed_container}
    return projects, containers


def _ssh_error(exc: ssh.SSHError) -> HTTPException:
    return HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))


@router.get("/{host_id}/unmanaged")
async def list_unmanaged(host_id: uuid.UUID, ctx: Lister, db: DB) -> list[discovery.Group]:
    """Compose projects and standalone containers on the host that no instance manages."""
    host = await _host(db, host_id)
    projects, containers = await _claimed(db, host)
    await db.commit()  # release the DB connection during SSH
    try:
        async with open_session(ssh.SSHTarget.from_host(host)) as remote:
            _, output = await remote.run(discovery.DISCOVER_COMMAND, timeout=120)
    except ssh.SSHError as exc:
        raise _ssh_error(exc) from exc
    return discovery.parse(output, claimed_projects=projects, claimed_containers=containers)


def _overlaps(path: str, directory: str) -> bool:
    return discovery.inside(path, directory) or discovery.inside(directory, path)


def _check_group(body: ClaimIn) -> str:
    """The group's key; 400 when the request does not name a group Slipway can claim."""
    g = body.group
    if g.kind == "compose":
        if not g.project or not discovery.PROJECT_RE.match(g.project) or g.project.startswith(discovery.MANAGED_PREFIX):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Name the compose project to claim")
        if body.build_source not in (None, BuildSource.COMPOSE):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "A compose project is claimed in compose mode")
        return f"compose:{g.project}"
    if not g.container_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Name the container to claim")
    if body.build_source not in (None, BuildSource.DOCKERFILE):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "A standalone container is claimed in Dockerfile mode")
    return f"container:{g.container_id}"


def _valid_rows(rows: list[dict[str, Any]], model: type[PortMapping] | type[VolumeMapping]) -> list[dict[str, Any]]:
    out = []
    for row in rows:
        try:
            out.append(model.model_validate(row).model_dump())
        except ValidationError:
            continue
    return out


def _compose_file(body: ClaimIn, group: discovery.Group, repo: Repository) -> str:
    if body.compose_file:
        return body.compose_file
    for candidate in (group.compose_file, repo.compose_file):
        if candidate:
            try:
                return deployer.clean_relative_path(candidate)
            except ValueError:
                continue
    return "docker-compose.yml"


@router.post("/{host_id}/claim", status_code=201)
async def claim(host_id: uuid.UUID, body: ClaimIn, ctx: Claimer, request: Request, db: DB) -> ClaimOut:
    """Create an instance for an unmanaged compose project or container.

    With ``deploy`` (the default) the branch is deployed straight away and replaces what runs;
    without it the instance only registers what runs now. ``import_env`` copies the containers'
    environment variables and, for a compose project, the variables in its env files (the ``.env``
    Compose read), which usually hold secrets.
    """
    if body.deploy and not ctx.can(Perm.DEPLOYMENTS_CREATE):
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {Perm.DEPLOYMENTS_CREATE}")
    key = _check_group(body)
    host = await _host(db, host_id)
    repo = await db.get(Repository, body.repository_id)
    if repo is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown repository")
    try:
        slug = deployer.slugify(body.name)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if not body.branch and not repo.default_branch_usable:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Slipway could not store the default branch of {repo.full_name} (its name is longer than "
            f"{BRANCH_MAX} characters); specify a branch",
        )
    base = f"{deployer.clean_deploy_root(host.deploy_root)}/{slug}"
    projects, containers = await _claimed(db, host)
    await db.commit()  # release the DB connection during SSH

    env_output = ""
    try:
        async with open_session(ssh.SSHTarget.from_host(host)) as remote:
            _, output = await remote.run(discovery.DISCOVER_COMMAND, timeout=120)
            group = next(
                (g for g in discovery.parse(output, claimed_projects=projects, claimed_containers=containers) if g.key == key),
                None,
            )
            if group is not None and body.import_env:
                command = discovery.env_command([c.id for c in group.containers], group.env_files)
                _, env_output = await remote.run(command, timeout=300)
    except ssh.SSHError as exc:
        raise _ssh_error(exc) from exc
    if group is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"No unmanaged {'compose project' if body.group.kind == 'compose' else 'container'} like that on {host.name}; "
            "it may have been removed or claimed meanwhile",
        )

    # Slipway owns <deploy root>/<slug>: it writes releases there and deletes it when the instance is
    # destroyed. The claimed app's own files must not be in it.
    for path, what in [(group.working_dir, "The project directory")] + [
        (m.source, f"The bind mount {m.source}") for m in group.mounts if m.type == "bind"
    ]:
        if path and _overlaps(path, base):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"{what} overlaps {base}, the directory Slipway would use for '{slug}'. Choose another name.",
            )

    env: dict[str, str] = {}
    skipped: list[str] = []
    files = discovery.EnvFiles()
    if body.import_env:
        env, skipped = discovery.parse_env(env_output, [c.id for c in group.containers])
        # The project's env files win: Compose substituted their values into the compose file and passed
        # them to services with ``env_file: .env``. Slipway gives them back to Compose the same way.
        files = discovery.parse_env_files(env_output, group.env_files)
        env.update(files.values)
        skipped = sorted({k for k in skipped if k not in env} | set(files.skipped))
    try:
        env = deployer.clean_env(env)
    except ValueError as exc:  # parse_env already drops what clean_env refuses
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    # Checked again after SSH: another request may have claimed the group or taken the name meanwhile.
    if await db.scalar(select(Instance).where(Instance.slug == slug)):
        raise HTTPException(status.HTTP_409_CONFLICT, f"An instance named '{slug}' already exists")
    projects, containers = await _claimed(db, host)
    if group.project in projects or group.container_id in containers:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{group.name} on {host.name} was claimed meanwhile")

    first = group.containers[0]
    claim_record: dict[str, Any] = {
        "kind": group.kind,
        "name": group.name,
        "containers": [c.name for c in group.containers],
        "images": group.images,
        "claimed_at": utcnow().isoformat(),
        "replaced": False,
    }
    fields: dict[str, Any]
    if group.kind == "compose":
        claim_record.update(working_dir=group.working_dir, config_files=group.config_files)
        fields = dict(
            build_source=BuildSource.COMPOSE,
            compose_file=_compose_file(body, group, repo),
            compose_project_name=group.project,
            ports=[], volumes=[], port_overrides=[],
            published_ports=discovery.published_rows(group),
        )
    else:
        claim_record.update(container_id=first.id, container_name=first.name)
        ports = [p.model_dump() for p in body.ports] if body.ports is not None else _valid_rows(
            discovery.dockerfile_ports(group), PortMapping)
        volumes = [v.model_dump() for v in body.volumes] if body.volumes is not None else _valid_rows(
            discovery.dockerfile_volumes(group), VolumeMapping)
        for v in volumes:
            if v["source"].startswith("/") and _overlaps(v["source"], base):
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST, f"The volume {v['source']} overlaps {base}, Slipway's directory for '{slug}'"
                )
        fields = dict(
            build_source=BuildSource.DOCKERFILE,
            dockerfile_path=body.dockerfile_path or "Dockerfile",
            build_context=body.build_context or ".",
            ports=ports, volumes=volumes, port_overrides=[], published_ports=[],
        )

    instance = Instance(
        name=body.name.strip(),
        slug=slug,
        repository=repo,
        host=host,
        branch=body.branch or repo.default_branch,
        env=env,
        auto_ports=True if body.auto_ports is None else body.auto_ports,
        # The app runs on the host already: it counts as deployed (its ports are reserved, its host
        # and build settings fixed), and the instance page shows its containers and logs.
        status=InstanceStatus.RUNNING if group.running else InstanceStatus.STOPPED,
        claim=claim_record,
        created_by_id=ctx.user.id,
        **fields,
    )
    db.add(instance)
    await db.flush()
    what = f"compose project {group.name}" if group.kind == "compose" else f"container {group.name}"
    audit.record(
        db, "instance.claim", actor=ctx.user, target=instance, request=request,
        summary=(
            f"Claimed {what} on {host.name} as {instance.name} ({repo.full_name}@{instance.branch})"
            + ("" if body.deploy else ", register only")
            + (f", imported {len(env)} environment variable(s)" if body.import_env else "")
        ),
        details={
            "kind": group.kind, "name": group.name, "container_id": group.container_id,
            "working_dir": group.working_dir, "register_only": not body.deploy,
            "env_imported": sorted(env), "env_skipped": skipped,
            "env_files_read": files.read, "env_files_unreadable": files.unreadable,
        },
    )
    dep = await queue_deployment(db, instance, ctx.user) if body.deploy else None
    if dep is not None:
        audit.record(db, "deployment.create", actor=ctx.user, target=dep,
                     summary=f"Deploy {instance.name}@{instance.branch}", request=request)
    await db.commit()
    if dep is not None:
        deployer.runner.submit(dep.id, instance.id)
    return ClaimOut(
        **InstanceOut.of(instance).model_dump(),
        deployment_id=dep.id if dep else None, env_imported=sorted(env), env_skipped=skipped,
        env_files_read=files.read, env_files_missing=files.missing, env_files_unreadable=files.unreadable,
        warning=(
            f"Could not read {', '.join(files.unreadable)}: add the variables it holds on the instance before deploying"
            if files.unreadable else None
        ),
    )
