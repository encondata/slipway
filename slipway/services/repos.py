"""Sync GitHub repositories into Slipway and pick credentials for GitHub access."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.core.config import get_settings
from slipway.db.base import utcnow
from slipway.models import Repository, User
from slipway.models.repository import DEFAULT_BRANCH_TOO_LONG
from slipway.services.github import GitHubClient, GitHubError, RepoRef, _parse_dt, detect_many

log = logging.getLogger(__name__)
BRANCH_MAX = Repository.__table__.c.default_branch.type.length


class GitHubNotLinked(RuntimeError):
    pass


@dataclass
class SyncResult:
    created: int
    updated: int
    total: int


def github_token_for(user: User | None) -> tuple[str | None, str]:
    """Return (token, description) to use for GitHub calls made on behalf of ``user``.

    A linked account whose token is missing or could not be decrypted counts as not linked.
    """
    account = user.github if user is not None else None
    if account is not None and account.access_token:
        return account.access_token, f"@{account.login}"
    service = get_settings().github_service_token
    if service:
        return service, "the Slipway service token"
    return None, "no credentials (public repositories only)"


async def sync_repositories(db: AsyncSession, user: User, *, client: GitHubClient | None = None) -> SyncResult:
    account = user.github
    if account is None or not account.access_token:
        raise GitHubNotLinked("Link your GitHub account (Settings → Profile) to sync repositories")

    own_client = client is None
    client = client or GitHubClient(account.access_token)
    try:
        # Offset pagination sorted by push time can return a repo twice; keep one per id.
        remote = list({g["id"]: g for g in await client.list_repos()}.values())
        existing = {
            r.github_id: r
            for r in (
                await db.scalars(select(Repository).where(Repository.github_id.in_([g["id"] for g in remote])))
            ).all()
        }
        now = utcnow()
        created = updated = 0
        needs_detection: list[tuple[RepoRef, str]] = []
        by_id: dict[RepoRef, Repository] = {}

        for data in remote:
            repo = existing.get(data["id"])
            pushed_at = _parse_dt(data.get("pushed_at"))
            if repo is None:
                repo = Repository(github_id=data["id"], detected_config={})
                db.add(repo)
                created += 1
            else:
                updated += 1
            branch = data.get("default_branch") or "main"
            changed = (
                repo.pushed_at != pushed_at
                or repo.detected_at is None
                or repo.default_branch != branch
                or not repo.default_branch_usable
            )
            # Clip display text to the column widths: PostgreSQL rejects over-long VARCHAR values.
            repo.full_name = data["full_name"][:200]
            repo.owner = data["owner"]["login"][:100]
            repo.name = data["name"][:100]
            repo.description = data.get("description") or ""
            repo.visibility = (data.get("visibility") or ("private" if data.get("private") else "public"))[:16]
            # A branch name is an identifier: cutting it would name a different branch, so it is never cut.
            usable = len(branch) <= BRANCH_MAX
            if usable:
                repo.default_branch = branch
                if not repo.default_branch_usable:
                    repo.detected_config = {
                        k: v for k, v in repo.detected_config.items() if k != DEFAULT_BRANCH_TOO_LONG
                    }
            else:
                repo.default_branch = repo.default_branch or "main"
                repo.detected_config = {**(repo.detected_config or {}), DEFAULT_BRANCH_TOO_LONG: True}
                log.warning(
                    "The default branch of %s is longer than %d characters; keeping %r and skipping detection. "
                    "Instances of it need an explicit branch.",
                    repo.full_name, BRANCH_MAX, repo.default_branch,
                )
            repo.html_url = data["html_url"][:300]
            repo.language = (data.get("language") or "")[:50] or None
            repo.archived = bool(data.get("archived"))
            repo.pushed_at = pushed_at
            repo.synced_at = now
            repo.synced_by_id = user.id
            by_id[repo.github_id] = repo
            if changed and usable and not repo.archived:
                needs_detection.append((repo.github_id, repo.default_branch))

        for github_id, config in (await detect_many(client, needs_detection)).items():
            by_id[github_id].detected_config = config
            by_id[github_id].detected_at = now

        await db.commit()
        return SyncResult(created=created, updated=updated, total=len(remote))
    finally:
        if own_client:
            await client.__aexit__(None, None, None)


_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


def parse_repo_url(text: str) -> str:
    """``owner/name`` from a GitHub URL (``https://github.com/owner/name``, with ``.git``, ``/tree/…`` or the
    like), an SSH remote (``git@github.com:owner/name.git``) or ``owner/name``. Raises ValueError."""
    value = (text or "").strip()
    github_host = urlsplit(get_settings().github_web_url).hostname or "github.com"
    if value.startswith(f"git@{github_host}:"):
        value = value.split(":", 1)[1]
    elif "://" in value or value.startswith(f"{github_host}/") or value.startswith(f"www.{github_host}/"):
        parts = urlsplit(value if "://" in value else f"https://{value}")
        if (parts.hostname or "").removeprefix("www.") != github_host:
            raise ValueError(f"Enter a {github_host} repository URL or owner/name")
        value = parts.path
    bits = [b for b in value.strip("/").split("/") if b]
    if len(bits) < 2:
        raise ValueError("Enter a repository as owner/name or its GitHub URL")
    owner, name = bits[0], bits[1].removesuffix(".git")
    if not _OWNER_RE.match(owner) or not _NAME_RE.match(name) or name in (".", ".."):
        raise ValueError(f"{owner}/{name} is not a valid GitHub repository name")
    return f"{owner}/{name}"


@dataclass
class ImportResult:
    repo: Repository
    created: bool


def _apply(repo: Repository, data: dict, user: User) -> None:
    branch = data.get("default_branch") or "main"
    repo.full_name = data["full_name"][:200]
    repo.owner = data["owner"]["login"][:100]
    repo.name = data["name"][:100]
    repo.description = data.get("description") or ""
    repo.visibility = (data.get("visibility") or ("private" if data.get("private") else "public"))[:16]
    if len(branch) <= BRANCH_MAX:
        repo.default_branch = branch
        repo.detected_config = {k: v for k, v in (repo.detected_config or {}).items() if k != DEFAULT_BRANCH_TOO_LONG}
    else:
        repo.default_branch = repo.default_branch or "main"
        repo.detected_config = {**(repo.detected_config or {}), DEFAULT_BRANCH_TOO_LONG: True}
    repo.html_url = data["html_url"][:300]
    repo.language = (data.get("language") or "")[:50] or None
    repo.archived = bool(data.get("archived"))
    repo.pushed_at = _parse_dt(data.get("pushed_at"))
    repo.synced_at = utcnow()
    repo.synced_by_id = user.id


async def import_repository(db: AsyncSession, user: User, text: str, *, client: GitHubClient | None = None) -> ImportResult:
    """Add one GitHub repository by URL, such as a community project, so it can be deployed like a synced one.

    Read with the user's own token when GitHub is linked (else the service token, else anonymously): a public
    repository needs no account. It is stored by its GitHub id, as a sync stores it; a repository Slipway
    already knows is refreshed instead. Raises ValueError for an unusable URL and GitHubError from GitHub.
    """
    full_name = parse_repo_url(text)
    token, _ = github_token_for(user)
    own_client = client is None
    client = client or GitHubClient(token)
    try:
        try:
            data = await client.get_repository(full_name)
        except GitHubError as exc:
            if exc.status_code in (403, 429) and "rate limit" in exc.detail.lower():
                raise ValueError("GitHub's limit on requests without an account was reached: link your GitHub account "
                                 "(Settings, Profile) or set SLIPWAY_GITHUB_SERVICE_TOKEN, or try again in an hour") from exc
            if exc.status_code in (401, 403, 404):
                raise ValueError(f"GitHub has no repository {full_name} that Slipway can read "
                                 "(a private one needs your GitHub account linked)") from exc
            raise
        repo = await db.scalar(select(Repository).where(Repository.github_id == data["id"]))
        created = repo is None
        if repo is None:
            repo = Repository(github_id=data["id"], detected_config={})
            db.add(repo)
        _apply(repo, data, user)
        if repo.default_branch_usable and not repo.archived:
            try:
                config = await client.detect_config(repo.github_id, repo.default_branch)
            except GitHubError as exc:
                log.info("Config detection failed for %s: %s", repo.full_name, exc)
            else:
                repo.detected_config = config
                repo.detected_at = utcnow()
        await db.flush()
        return ImportResult(repo=repo, created=created)
    finally:
        if own_client:
            await client.__aexit__(None, None, None)
