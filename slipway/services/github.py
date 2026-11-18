"""GitHub OAuth and REST API client."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

import httpx

from slipway.core.config import get_settings

log = logging.getLogger(__name__)
# httpx logs every request URL at INFO and httpcore every response header at DEBUG, which
# includes the short-lived codeload ?token= links that GitHub redirects tarballs to.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

COMPOSE_FILENAMES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")

# A repository is addressed by its immutable GitHub id (preferred) or by "owner/name".
RepoRef = int | str


class GitHubError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None, detail: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail  # GitHub's own error message, when it sent one

    @property
    def transient(self) -> bool:
        """A network failure or a GitHub-side error, rather than GitHub refusing the request."""
        return self.status_code is None or self.status_code >= 500


@dataclass
class CommitInfo:
    sha: str
    message: str
    author: str
    date: datetime | None


def _failed(what: str, exc: Exception) -> GitHubError:
    return GitHubError(f"{what}: request failed ({type(exc).__name__})")


def _repo_path(repo: RepoRef) -> str:
    if isinstance(repo, int):
        return f"/repositories/{repo}"
    owner, _, name = repo.partition("/")
    return f"/repos/{quote(owner, safe='')}/{quote(name, safe='')}"


def authorize_url(state: str) -> str:
    s = get_settings()
    params = {
        "client_id": s.github_client_id,
        "redirect_uri": s.github_callback_url,
        "scope": s.oauth_scopes,
        "state": state,
        "allow_signup": "false",
    }
    return f"{s.github_web_url}/login/oauth/authorize?{urlencode(params)}"


async def exchange_code(code: str, *, transport: httpx.AsyncBaseTransport | None = None) -> tuple[str, str]:
    """Exchange an OAuth code for (access_token, granted_scopes)."""
    s = get_settings()
    try:
        async with httpx.AsyncClient(timeout=15, transport=transport) as client:
            resp = await client.post(
                f"{s.github_web_url}/login/oauth/access_token",
                headers={"Accept": "application/json"},
                data={
                    "client_id": s.github_client_id,
                    "client_secret": s.github_client_secret,
                    "code": code,
                    "redirect_uri": s.github_callback_url,
                },
            )
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
    except (httpx.HTTPError, ValueError) as exc:
        raise _failed("GitHub token exchange", exc) from exc
    if not isinstance(data, dict):
        data = {}
    if resp.status_code != 200 or not isinstance(data.get("access_token"), str):
        raise GitHubError(str(data.get("error_description") or "GitHub did not return an access token"))
    return data["access_token"], str(data.get("scope") or "")


def _parse_dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


class GitHubClient:
    """Thin async wrapper over the REST API. ``token`` may be None for public data.

    Repository methods take a ``RepoRef``. Pass the numeric GitHub id where you have it:
    an "owner/name" can be re-registered by someone else after a rename or transfer.
    """

    def __init__(self, token: str | None, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Slipway",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.AsyncClient(
            base_url=get_settings().github_api_url,
            headers=headers,
            timeout=30,
            transport=transport,
            follow_redirects=True,
        )

    async def __aenter__(self) -> GitHubClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    async def _get(self, path: str, **params: Any) -> Any:
        try:
            resp = await self._client.get(path, params=params or None)
        except httpx.HTTPError as exc:
            raise _failed(f"GitHub API {path}", exc) from exc
        if resp.status_code >= 400:
            try:
                message = str(resp.json().get("message", resp.text))
            except (ValueError, AttributeError):
                message = resp.text[:200] or resp.reason_phrase
            raise GitHubError(f"GitHub API {path}: {message}", resp.status_code, message)
        try:
            return resp.json()
        except ValueError as exc:
            raise GitHubError(f"GitHub API {path}: invalid JSON response", resp.status_code) from exc

    async def _paginate(self, path: str, **params: Any) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        page = 1
        while True:
            batch = await self._get(path, per_page=100, page=page, **params)
            items.extend(batch)
            if len(batch) < 100 or page >= 20:
                return items
            page += 1

    async def get_user(self) -> dict[str, Any]:
        return await self._get("/user")

    async def get_user_by_login(self, login: str) -> dict[str, Any]:
        return await self._get(f"/users/{quote(login, safe='')}")

    async def get_primary_email(self) -> tuple[str | None, bool]:
        """Return (email, verified) for the user's primary address."""
        try:
            emails = await self._get("/user/emails")
        except GitHubError as exc:
            if exc.transient:  # a hiccup, not "no access to emails"
                raise
            return None, False
        primary = next((e for e in emails if e.get("primary")), None)
        return (primary["email"], bool(primary.get("verified"))) if primary else (None, False)

    async def get_orgs(self) -> list[dict[str, Any]]:
        """The user's organisations, each with a ``login`` and a numeric ``id``."""
        return await self._paginate("/user/orgs")

    async def list_repos(self) -> list[dict[str, Any]]:
        return await self._paginate(
            "/user/repos", affiliation="owner,collaborator,organization_member", sort="pushed"
        )

    async def get_repository(self, repo: RepoRef) -> dict[str, Any]:
        return await self._get(_repo_path(repo))

    async def list_branches(self, repo: RepoRef) -> list[str]:
        branches = await self._paginate(f"{_repo_path(repo)}/branches")
        return [b["name"] for b in branches]

    async def get_commit(self, repo: RepoRef, ref: str) -> CommitInfo:
        data = await self._get(f"{_repo_path(repo)}/commits/{quote(ref, safe='')}")
        commit = data["commit"]
        git_author = commit.get("author") or {}
        author = (data.get("author") or {}).get("login") or git_author.get("name") or ""
        first_line = next(iter((commit.get("message") or "").splitlines()), "")
        return CommitInfo(
            sha=data["sha"],
            message=first_line[:500],
            author=author[:100],
            date=_parse_dt(git_author.get("date")),
        )

    async def detect_config(self, repo: RepoRef, ref: str | None = None) -> dict[str, Any]:
        """Look at the repo root for a Dockerfile / compose file."""
        try:
            entries = await self._get(f"{_repo_path(repo)}/contents/", **({"ref": ref} if ref else {}))
        except GitHubError as exc:
            # Only an empty repository has nothing to detect. A missing ref, or a repo this
            # token cannot see, also gives 404 and must not look like "no Dockerfile".
            if "repository is empty" in exc.detail.lower():
                return {"dockerfile": False, "compose_file": None, "files": []}
            raise
        names = [e["name"] for e in entries if e.get("type") == "file"]
        return {
            "dockerfile": "Dockerfile" in names,
            "compose_file": next((n for n in COMPOSE_FILENAMES if n in names), None),
            "manifest": "slipway.yml" in names,
            "files": sorted(names)[:50],
        }

    async def get_file(self, repo: RepoRef, path: str, ref: str, *, limit: int = 256 * 1024) -> str | None:
        """The text of ``path`` at ``ref`` (None when there is no such file or it is too big)."""
        url = f"{_repo_path(repo)}/contents/{quote(path, safe='/')}"
        try:
            resp = await self._client.get(url, params={"ref": ref}, headers={"Accept": "application/vnd.github.raw+json"})
        except httpx.HTTPError as exc:
            raise _failed(f"GitHub API {url}", exc) from exc
        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            raise GitHubError(f"GitHub API {url}: {resp.text[:200] or resp.reason_phrase}", resp.status_code)
        if len(resp.content) > limit or resp.headers.get("content-type", "").startswith("application/json"):
            return None  # a directory listing, or too big
        return resp.content.decode("utf-8", "replace")

    async def get_readme(self, repo: RepoRef) -> str | None:
        path = f"{_repo_path(repo)}/readme"
        try:
            resp = await self._client.get(path, headers={"Accept": "application/vnd.github.raw+json"})
        except httpx.HTTPError as exc:
            raise _failed(f"GitHub API {path}", exc) from exc
        return resp.text[:20000] if resp.status_code == 200 else None

    async def download_tarball(self, repo: RepoRef, sha: str, dest: Path) -> int:
        """Stream the repository tarball at ``sha`` to ``dest``. Returns bytes written."""
        what = f"Could not download {repo}@{sha[:7]}"
        size = 0
        try:
            async with self._client.stream("GET", f"{_repo_path(repo)}/tarball/{quote(sha, safe='')}") as resp:
                if resp.status_code >= 400:
                    raise GitHubError(f"{what} ({resp.status_code})", resp.status_code)
                with dest.open("wb") as fh:
                    async for chunk in resp.aiter_bytes():
                        fh.write(chunk)
                        size += len(chunk)
        except httpx.HTTPError as exc:
            raise _failed(what, exc) from exc
        return size


async def detect_many(
    client: GitHubClient, repos: list[tuple[RepoRef, str]], concurrency: int = 8
) -> dict[RepoRef, dict]:
    """Detect build config for many (repo, branch) pairs concurrently; failures are skipped."""
    sem = asyncio.Semaphore(concurrency)
    results: dict[RepoRef, dict] = {}

    async def one(repo: RepoRef, branch: str) -> None:
        async with sem:
            try:
                results[repo] = await client.detect_config(repo, branch)
            except Exception as exc:  # one repo must not abort the whole sync
                log.info("Config detection failed for %s: %s", repo, exc)

    await asyncio.gather(*(one(r, b) for r, b in repos))
    return results
