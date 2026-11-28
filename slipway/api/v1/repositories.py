"""GitHub repositories known to Slipway."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy import or_, select

from slipway.api.deps import DB, not_found, require
from slipway.core.permissions import Perm
from slipway.db.base import utcnow
from slipway.models import Repository
from slipway.models.repository import DEFAULT_BRANCH_TOO_LONG
from slipway.schemas import BRANCH_MAX, RepoImportIn, RepoOut, SyncOut
from slipway.services import audit, deployer, manifest
from slipway.services.auth import AuthContext
from slipway.services.github import GitHubClient, GitHubError
from slipway.services.repos import GitHubNotLinked, github_token_for, import_repository, sync_repositories

router = APIRouter(prefix="/repositories", tags=["repositories"])

Reader = Annotated[AuthContext, require(Perm.REPOS_READ)]
Syncer = Annotated[AuthContext, require(Perm.REPOS_SYNC)]
# Reading a manifest reads a file of the repository (its errors quote it): only for those who set up instances
# or environments (the New environment flow reads it too, phase 3 §12.3), who can deploy the repository's code
# anyway.
ManifestReader = Annotated[AuthContext, require(Perm.REPOS_READ)]


async def _get(db: DB, repo_id: uuid.UUID) -> Repository:
    repo = await db.get(Repository, repo_id)
    if repo is None:
        raise not_found("Repository")
    return repo


def _gh_error(exc: GitHubError) -> HTTPException:
    return HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))


@router.get("")
async def list_repos(ctx: Reader, db: DB, q: str | None = None, deployable: bool | None = None) -> list[RepoOut]:
    stmt = select(Repository).order_by(Repository.pushed_at.desc().nulls_last())
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(Repository.full_name.ilike(like), Repository.description.ilike(like)))
    repos = [RepoOut.of(r) for r in (await db.scalars(stmt)).all()]
    if deployable is not None:
        repos = [r for r in repos if r.deployable == deployable]
    return repos


@router.post("/sync")
async def sync(ctx: Syncer, request: Request, db: DB) -> SyncOut:
    try:
        result = await sync_repositories(db, ctx.user)
    except GitHubNotLinked as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except GitHubError as exc:
        raise _gh_error(exc) from exc
    audit.record(
        db, "repos.sync", actor=ctx.user,
        summary=f"Synced {result.total} repositories ({result.created} new)", request=request,
    )
    await db.commit()
    return SyncOut(created=result.created, updated=result.updated, total=result.total)


@router.post("/import")
async def import_repo(body: RepoImportIn, ctx: Syncer, request: Request, db: DB) -> RepoOut:
    """Add a GitHub repository by URL (a community project, say): public ones need no GitHub account."""
    try:
        result = await import_repository(db, ctx.user, body.url)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except GitHubError as exc:
        raise _gh_error(exc) from exc
    repo = result.repo
    audit.record(
        db, "repos.import", actor=ctx.user, target=repo, details={"github_id": repo.github_id, "created": result.created},
        summary=f"{'Added' if result.created else 'Refreshed'} repository {repo.full_name} by URL", request=request,
    )
    await db.commit()
    return RepoOut.of(repo)


@router.get("/{repo_id}")
async def get_repo(repo_id: uuid.UUID, ctx: Reader, db: DB) -> RepoOut:
    return RepoOut.of(await _get(db, repo_id))


@router.get("/{repo_id}/branches")
async def branches(repo_id: uuid.UUID, ctx: Reader, db: DB) -> list[str]:
    repo = await _get(db, repo_id)
    token, _ = github_token_for(ctx.user)
    try:
        async with GitHubClient(token) as gh:
            names = await gh.list_branches(repo.github_id)
    except GitHubError as exc:
        raise _gh_error(exc) from exc
    if not repo.default_branch_usable:  # default_branch is then a stale value or a placeholder: don't promote it
        return sorted(names)
    # Default branch first.
    return sorted(names, key=lambda n: (n != repo.default_branch, n))


@router.get("/{repo_id}/manifest")
async def get_manifest(
    repo_id: uuid.UUID, ctx: ManifestReader, db: DB,
    branch: Annotated[str, Query(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._/-]+$")],
    path: Annotated[str, Query(max_length=255)] = manifest.DEFAULT_FILE,
) -> dict[str, Any]:
    """The repository's slipway.yml on ``branch``, checked: ``{found, manifest?, error?}``."""
    if not (ctx.can(Perm.INSTANCES_WRITE) or ctx.can(Perm.ENVIRONMENTS_WRITE)):
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {Perm.INSTANCES_WRITE}")
    repo = await _get(db, repo_id)
    try:
        path = manifest.clean_manifest_file(deployer.clean_relative_path(path))
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    token, _ = github_token_for(ctx.user)
    try:
        async with GitHubClient(token) as gh:
            text = await gh.get_file(repo.github_id, path, branch)
            if text is None:
                # GitHub answers 404 for a repository or branch this token can't see too: only call the file
                # missing when the branch itself is there (else this raises, and the form keeps what it has).
                await gh.get_commit(repo.github_id, branch)
    except GitHubError as exc:
        raise _gh_error(exc) from exc
    if text is None:
        return {"found": False, "path": path}
    try:
        return {"found": True, "path": path, "manifest": manifest.parse(text).to_json()}
    except manifest.ManifestError as exc:
        return {"found": True, "path": path, "error": str(exc)}


@router.get("/{repo_id}/readme")
async def readme(repo_id: uuid.UUID, ctx: Reader, db: DB) -> dict[str, str | None]:
    repo = await _get(db, repo_id)
    token, _ = github_token_for(ctx.user)
    try:
        async with GitHubClient(token) as gh:
            return {"content": await gh.get_readme(repo.github_id)}
    except GitHubError as exc:
        raise _gh_error(exc) from exc


@router.post("/{repo_id}/detect")
async def detect(
    repo_id: uuid.UUID, ctx: Syncer, db: DB, branch: Annotated[str | None, Query(max_length=BRANCH_MAX)] = None
) -> RepoOut:
    repo = await _get(db, repo_id)
    if not branch and not repo.default_branch_usable:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "This repository's default branch could not be stored; specify a branch"
        )
    token, _ = github_token_for(ctx.user)
    try:
        async with GitHubClient(token) as gh:
            config = await gh.detect_config(repo.github_id, branch or repo.default_branch)
    except GitHubError as exc:
        raise _gh_error(exc) from exc
    if not repo.default_branch_usable:  # still true after detecting another branch
        config = {**config, DEFAULT_BRANCH_TOO_LONG: True}
    repo.detected_config = config
    repo.detected_at = utcnow()
    await db.commit()
    return RepoOut.of(repo)
