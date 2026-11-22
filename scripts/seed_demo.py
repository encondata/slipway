"""Fill a development database with demo repositories, hosts, instances and deployments.

For UI work without GitHub or real Docker hosts. Refuses to run in production.

    SLIPWAY_DATABASE_URL=sqlite+aiosqlite:///data/slipway-demo.db .venv/bin/python scripts/seed_demo.py

Hosts get random (fake) pinned keys, so "Check" against them will fail; that's expected.
Create your own admin first (SLIPWAY_ADMIN_EMAIL/SLIPWAY_ADMIN_PASSWORD or `slipway create-admin`): the demo
team members have no password and cannot sign in.
"""

from __future__ import annotations

import asyncio
import random
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import func, select  # noqa: E402

from slipway.cli import migrate  # noqa: E402
from slipway.core.config import get_settings  # noqa: E402
from slipway.db.base import utcnow  # noqa: E402
from slipway.db.session import dispose_engine, get_sessionmaker  # noqa: E402
from slipway.models import Deployment, Host, Instance, Repository  # noqa: E402
from slipway.services import ssh  # noqa: E402
from slipway.services.users import bootstrap, create_user, get_user_by_email, user_count  # noqa: E402

REPOS = [
    ("slipway-web", "Slipway web app (dashboard, API, and console)", "TypeScript", "public", True, "docker-compose.yml"),
    ("slipway-api", "Platform API and background workers", "Python", "private", True, None),
    ("slipway-mobile", "iOS and Android mobile app", "Kotlin", "internal", False, None),
    ("portal", "Customer portal and account settings", "TypeScript", "public", True, None),
    ("kiosk", "On-site kiosk app (Electron)", "JavaScript", "internal", True, None),
    ("wiki", "Team wiki and documentation", "Markdown", "public", False, None),
    ("demo-app", "Example app for testing and onboarding", "Go", "public", True, None),
]
HOSTS = [
    ("prod-01", "10.0.1.12", "prod", 42, 68, "healthy"),
    ("prod-02", "10.0.1.13", "prod", 31, 54, "healthy"),
    ("staging-01", "10.0.2.10", "staging", 18, 38, "healthy"),
    ("dev-01", "10.0.2.11", "dev", 82, 79, "warning"),
]
COMMITS = [
    "chore: update deps", "feat: add session analytics", "fix: handle instance scaling",
    "feat: new billing usage view", "feat: add offline mode", "feat: add push notifications",
]


def build_log(name: str, sha: str, ok: bool) -> str:
    lines = [
        f"Resolving acme/{name}@main using @demo",
        f"Commit {sha[:7]} — {random.choice(COMMITS)} (maria)",
        "Downloaded source archive (412 KiB)",
        "Connecting to deploy@10.0.1.12",
        f"Unpacked release into /opt/slipway/{name}/releases/{sha[:12]}",
        f"Wrote 3 environment variable(s) to /opt/slipway/{name}/shared/.env",
        f"$ cd /opt/slipway/{name}/releases/{sha[:12]} && BUILDKIT_PROGRESS=plain docker build --pull -t slipway/{name}:{sha[:12]} .",
        "#1 [internal] load build definition from Dockerfile",
        "#2 [internal] load metadata for docker.io/library/node:22-alpine",
        "#5 [2/5] WORKDIR /app",
        "#6 [3/5] COPY package*.json ./",
        "#7 [4/5] RUN npm ci --omit=dev",
        "#8 [5/5] COPY . .",
    ]
    if ok:
        lines += ["#9 exporting to image", "#9 naming to docker.io/slipway/" + name, f"$ docker run -d --name slipway-{name} ...", "Deployment succeeded"]
    else:
        lines += ["npm ERR! code ERESOLVE", "Deployment failed: Command exited with status 1"]
    return "".join(f"[{(utcnow()):%H:%M:%S}] {line}\n" for line in lines)


async def main() -> None:
    async with get_sessionmaker()() as db:
        await bootstrap(db)
        if await db.scalar(select(func.count()).select_from(Repository)):
            print("Database already has repositories; nothing to do.")
            return
        if await user_count(db) == 0:
            # Otherwise the first demo user would silently become the only (password-less) admin.
            sys.exit("Create an admin first (set SLIPWAY_ADMIN_EMAIL/SLIPWAY_ADMIN_PASSWORD or run `slipway create-admin`)")
        team = []
        for email, name, role in [("maria@example.com", "Maria Lopez", "developer"), ("james@example.com", "James Park", "maintainer"),
                                  ("sarah@example.com", "Sarah Chen", "viewer")]:
            # No password: demo users only fill in "created by" / "triggered by" and never sign in.
            user = await get_user_by_email(db, email) or await create_user(
                db, email=email, password=None, full_name=name, role_names=[role])
            team.append(user)

        now = utcnow()
        repos = {}
        for i, (name, desc, lang, vis, docker, compose) in enumerate(REPOS):
            repos[name] = Repository(
                github_id=900000 + i, full_name=f"acme/{name}", owner="acme", name=name, description=desc,
                visibility=vis, default_branch="develop" if name == "kiosk" else "main",
                html_url=f"https://github.com/acme/{name}", language=lang, pushed_at=now - timedelta(hours=2 + i * 5),
                detected_config={"dockerfile": docker, "compose_file": compose, "files": []},
                detected_at=now, synced_at=now - timedelta(minutes=2),
            )
            db.add(repos[name])

        hosts = {}
        for name, ip, env, cpu, mem, status in HOSTS:
            key = ssh.generate_keypair()[1]
            hosts[name] = Host(
                name=name, hostname=ip, username="deploy", label=env, deploy_root="/opt/slipway",
                auth_method="key", public_key=ssh.generate_keypair(f"slipway@{name}")[1], host_key=key,
                host_key_fingerprint=ssh.fingerprint(key), status=status, last_checked_at=now - timedelta(minutes=3),
                docker_version="27.3.1", os_info="Ubuntu 24.04.1 LTS",
                metrics={"cpus": 8, "cpu_percent": cpu, "mem_total_mb": 32768, "mem_percent": mem, "containers_running": random.randint(3, 14)},
                last_error="Memory pressure above 75%" if status == "warning" else None,
            )
            db.add(hosts[name])

        specs = [
            ("slipway-web-prod", "slipway-web", "prod-01", "compose", "running", [True, True, True]),
            ("slipway-api-prod", "slipway-api", "prod-02", "dockerfile", "running", [True, False, True]),
            ("portal-staging", "portal", "staging-01", "dockerfile", "running", [True]),
            ("kiosk-dev", "kiosk", "dev-01", "dockerfile", "failed", [True, False]),
            ("demo-app-dev", "demo-app", "dev-01", "dockerfile", "stopped", [True]),
        ]
        for slug, repo, host, src, status, history in specs:
            inst = Instance(
                name=slug, slug=slug, repository=repos[repo], host=hosts[host], branch=repos[repo].default_branch,
                build_source=src, compose_file="docker-compose.yml", env={"NODE_ENV": "production", "LOG_LEVEL": "info", "API_URL": "https://api.example.com"},
                ports=[{"host": 8080 + len(slug), "container": 3000, "protocol": "tcp"}] if src == "dockerfile" else [],
                volumes=[{"source": f"/var/lib/slipway/{slug}", "target": "/app/data"}] if src == "dockerfile" else [],
                status=status, created_by_id=team[1].id,
            )
            db.add(inst)
            await db.flush()
            for n, ok in enumerate(history):
                sha = "%040x" % random.getrandbits(160)
                started = now - timedelta(hours=(len(history) - n) * 7 + random.randint(0, 5), minutes=random.randint(0, 59))
                dep = Deployment(
                    instance_id=inst.id, branch=inst.branch, status="succeeded" if ok else "failed",
                    commit_sha=sha, commit_message=random.choice(COMMITS), commit_author="maria",
                    triggered_by_id=random.choice(team).id, started_at=started,
                    finished_at=started + timedelta(seconds=random.randint(40, 260)),
                    error=None if ok else "Command exited with status 1:\nnpm ERR! code ERESOLVE",
                    log=build_log(slug, sha, ok),
                )
                dep.created_at = started
                db.add(dep)
                if ok:
                    inst.current_commit_sha, inst.last_deployed_at = sha, dep.finished_at
        await db.commit()
    await dispose_engine()
    print("Seeded demo data.")


if __name__ == "__main__":
    if get_settings().is_production:
        sys.exit("Refusing to seed demo data in production")
    migrate()  # Alembic runs its own event loop, so do this before ours starts.
    asyncio.run(main())
