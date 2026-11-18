"""The resources service (test 8): rows are committed in their own transaction, one owner per outside
object, and an environment row can't be deleted while it still lists objects."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from slipway.db.session import get_sessionmaker, session_scope
from slipway.models import AuditEvent, Environment, Repository, Resource
from slipway.services import resources


async def _envs(*names: str) -> list[uuid.UUID]:
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=1, full_name="acme/web", owner="acme", name="web", html_url="https://github.com/acme/web")
        db.add(repo)
        await db.flush()
        envs = [Environment(name=n, repository_id=repo.id, branch="main", data_mode="server") for n in names]
        db.add_all(envs)
        await db.commit()
        return [e.id for e in envs]


async def _rows() -> list[Resource]:
    async with get_sessionmaker()() as db:
        return list(await db.scalars(select(Resource).order_by(Resource.name)))


async def _actions() -> list[str]:
    async with get_sessionmaker()() as db:
        return sorted(await db.scalars(select(AuditEvent.action).where(AuditEvent.action.like("resource.%"))))


async def test_record_and_forget_survive_the_callers_rollback():
    (uat,) = await _envs("uat")
    with pytest.raises(RuntimeError):
        async with session_scope() as db:
            env = await db.get(Environment, uat)
            row_id = await resources.record(uat, "switchyard", "proxy_host", 12, "uat.example.com", "created",
                                            {"follows": "active", "upstream": "10.0.0.11:8080"})
            env.notice = {"text": "rolled back with the caller"}
            await db.flush()
            raise RuntimeError("the step failed after the provider answered")
    (row,) = await _rows()
    assert (row.id, row.provider_id, row.origin, row.details["follows"]) == (row_id, "12", "created", "active")
    async with get_sessionmaker()() as db:
        assert (await db.get(Environment, uat)).notice is None  # the caller's own change went

    assert await resources.update_details(row_id, upstream="10.0.0.12:8080", tls_mode="auto")
    (row,) = await _rows()
    assert row.details == {"follows": "active", "upstream": "10.0.0.12:8080", "tls_mode": "auto"}

    with pytest.raises(RuntimeError):
        async with session_scope() as db:
            await db.get(Environment, uat)
            assert await resources.forget(row_id, deleted=True)
            raise RuntimeError("later failure")
    assert await _rows() == []
    assert not await resources.forget(row_id) and not await resources.update_details(row_id, x=1)
    assert await _actions() == ["resource.create", "resource.delete"]


async def test_one_owner_per_outside_object():
    uat, prod = await _envs("uat", "prod")
    first = await resources.record(uat, "cloudflare", "dns_record", "rec-1", "uat.example.com", "claimed",
                                   {"zone_id": "z", "type": "A", "content": "203.0.113.7", "proxied": False})
    # The same object for the same environment again (a retry) updates its row.
    again = await resources.record(uat, "cloudflare", "dns_record", "rec-1", "uat.example.com", "claimed",
                                   {"zone_id": "z", "type": "A", "content": "203.0.113.8", "proxied": False})
    assert again == first and (await _rows())[0].details["content"] == "203.0.113.8"

    with pytest.raises(resources.ResourceTaken, match="already belongs to environment uat"):
        await resources.record(prod, "cloudflare", "dns_record", "rec-1", "uat.example.com", "created")
    # This environment already records the name under another object of that kind.
    with pytest.raises(resources.ResourceTaken, match="already records uat.example.com"):
        await resources.record(uat, "cloudflare", "dns_record", "rec-2", "uat.example.com", "created")
    # Another provider's object with the same id is a different object.
    await resources.record(prod, "switchyard", "proxy_host", "rec-1", "prod.example.com", "created")
    rows = await _rows()
    assert [(r.environment_id, r.provider, r.name) for r in rows] == [
        (prod, "switchyard", "prod.example.com"), (uat, "cloudflare", "uat.example.com"),
    ]
    assert await _actions() == ["resource.claim", "resource.claim", "resource.create"]

    async with get_sessionmaker()() as db:
        assert [r.name for r in await resources.owned(db, uat, "cloudflare", "dns_record")] == ["uat.example.com"]
        assert await resources.owned(db, uat, "switchyard", "proxy_host") == []
        assert [r.name for r in await resources.owned(db, prod, "switchyard", "proxy_host")] == ["prod.example.com"]


async def test_an_environment_with_resources_cannot_be_deleted():
    (uat,) = await _envs("uat")
    row_id = await resources.record(uat, "switchyard", "proxy_host", "7", "uat.example.com", "created")
    async with get_sessionmaker()() as db:
        await db.delete(await db.get(Environment, uat))
        with pytest.raises(IntegrityError):
            await db.commit()
    await resources.forget(row_id)
    async with get_sessionmaker()() as db:
        await db.delete(await db.get(Environment, uat))
        await db.commit()
