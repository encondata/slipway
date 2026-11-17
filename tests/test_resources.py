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


# ------------------------------------------------------------------ phase 4 additions (P4 test 71, §3.7, §6.4)

NONCE = "0123456789abcdef"
SECRET = "spaces-secret-that-must-never-be-audited"


async def _row(row_id: uuid.UUID) -> Resource:
    async with get_sessionmaker()() as db:
        return await db.get(Resource, row_id)


async def _audits() -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        return list(await db.scalars(
            select(AuditEvent).where(AuditEvent.action.like("resource.%")).order_by(AuditEvent.created_at)
        ))


def _no_secret_in(events: list[AuditEvent]) -> None:
    for event in events:
        assert SECRET not in repr(event.details) and SECRET not in (event.summary or "")


async def test_credentials_and_tags_are_written_in_the_rows_own_commit():
    (uat,) = await _envs("uat")
    tags = ["slipway", "slipway-env:uat", "slipway-req:" + NONCE]
    with pytest.raises(RuntimeError):
        async with session_scope() as db:
            await db.get(Environment, uat)
            row_id = await resources.record(uat, "digitalocean", "spaces_key", "AKIA1", "slipway-uat-key", "created",
                                            {"bucket": "slipway-uat", "role": "bucket"},
                                            credentials={"secret_key": SECRET}, tags=tags)
            raise RuntimeError("the step failed after the answer")
    row = await _row(row_id)
    assert (row.credentials, row.tags, row.details["bucket"]) == ({"secret_key": SECRET}, tags, "slipway-uat")

    # A retry that passes no credentials or tags leaves them; set_credentials sets and clears them.
    assert await resources.record(uat, "digitalocean", "spaces_key", "AKIA1", "slipway-uat-key", "created",
                                  {"bucket": "slipway-uat", "role": "bucket"}) == row_id
    assert ((await _row(row_id)).credentials, (await _row(row_id)).tags) == ({"secret_key": SECRET}, tags)
    assert await resources.set_credentials(row_id, {"secret_key": "rotated-" + SECRET})
    assert (await _row(row_id)).credentials == {"secret_key": "rotated-" + SECRET}
    assert await resources.set_credentials(row_id, None)
    assert (await _row(row_id)).credentials is None
    assert not await resources.set_credentials(uuid.uuid4(), None)
    _no_secret_in(await _audits())


async def test_a_pending_row_and_the_real_row_that_replaces_it():
    (uat,) = await _envs("uat")
    pending_id = await resources.record_pending(uat, "digitalocean", "droplet", "slipway-uat-blue", nonce=NONCE,
                                                body_hash="b" * 64)
    row = await _row(pending_id)
    assert resources.is_pending(row) and resources.nonce_of(row) == NONCE
    assert (row.provider_id, row.origin, row.details["pending"]["nonce"], row.details["pending"]["body_hash"]) == (
        f"pending:{NONCE}", "created", NONCE, "b" * 64)
    assert row.details["pending"]["looked"] == [] and row.details["pending"]["sent_at"]

    async with get_sessionmaker()() as db:
        assert await resources.owned(db, uat, "digitalocean", "droplet") == []
        assert [r.id for r in await resources.owned(db, uat, "digitalocean", "droplet", include_pending=True)] == [
            pending_id]
        assert [r.id for r in await resources.pending(db, uat, "digitalocean", "droplet")] == [pending_id]
        assert await resources.pending(db, uat, "digitalocean", "database") == []

    # Looked for and not found: each lookup is noted, committed at once.
    assert await resources.looked(pending_id)
    assert await resources.looked(pending_id)
    assert len((await _row(pending_id)).details["pending"]["looked"]) == 2

    # One pending create per name, and no plain record of the name while it is kept.
    with pytest.raises(resources.ResourceTaken, match="still waiting to learn whether its droplet slipway-uat-blue"):
        await resources.record_pending(uat, "digitalocean", "droplet", "slipway-uat-blue", nonce="f" * 16,
                                       body_hash="c" * 64)
    with pytest.raises(resources.ResourceTaken, match="already records slipway-uat-blue"):
        await resources.record(uat, "digitalocean", "droplet", "4711", "slipway-uat-blue", "created")
    with pytest.raises(ValueError, match="16 hex characters"):
        await resources.record_pending(uat, "digitalocean", "droplet", "x", nonce="short", body_hash="c")
    with pytest.raises(resources.ResourceError, match="record_pending"):
        await resources.record(uat, "digitalocean", "droplet", "pending:1", "x", "created")

    # The answer: the real row takes the pending one over in one transaction (same row).
    real_id = await resources.record(uat, "digitalocean", "droplet", 4711, "slipway-uat-blue", "created",
                                     {"slot": "blue", "size": "s-2vcpu-4gb"}, tags=["slipway"], replaces=pending_id)
    assert real_id == pending_id
    row = await _row(real_id)
    assert (row.provider_id, row.details, row.tags, resources.is_pending(row)) == (
        "4711", {"slot": "blue", "size": "s-2vcpu-4gb"}, ["slipway"], False)
    async with get_sessionmaker()() as db:
        assert await resources.pending(db, uat, "digitalocean", "droplet") == []
        assert [r.provider_id for r in await resources.owned(db, uat, "digitalocean", "droplet")] == ["4711"]
    # A pending row of the name exists again only once the real one is gone.
    with pytest.raises(resources.ResourceTaken, match="already records slipway-uat-blue"):
        await resources.record_pending(uat, "digitalocean", "droplet", "slipway-uat-blue", nonce="e" * 16,
                                       body_hash="c" * 64)

    events = await _audits()
    assert [(e.action, e.details["provider_id"]) for e in events] == [
        ("resource.pending", f"pending:{NONCE}"), ("resource.create", "4711")]
    assert events[0].details["nonce"] == NONCE and events[1].details["replaces"] == NONCE


async def test_a_certificate_keeps_its_credentials_only_while_pending():
    (uat,) = await _envs("uat")
    pending_id = await resources.record_pending(uat, "digitalocean", "certificate", "slipway-uat-20261118",
                                                nonce=NONCE, body_hash="d" * 64,
                                                credentials={"private_key": SECRET, "leaf": "L", "chain": "C"})
    assert (await _row(pending_id)).credentials["private_key"] == SECRET
    await resources.record(uat, "digitalocean", "certificate", "cert-uuid", "slipway-uat-20261118", "created",
                           {"not_after": "2027-02-16"}, replaces=pending_id)
    assert (await _row(pending_id)).credentials is None
    _no_secret_in(await _audits())


async def test_adopt_rebuild_and_a_replaced_row_that_was_already_recorded():
    (uat,) = await _envs("uat")
    pending_id = await resources.record_pending(uat, "digitalocean", "vpc", "slipway-uat", nonce=NONCE,
                                                body_hash="a" * 64)
    # A lost answer found by its request: adopted.
    adopted = await resources.record(uat, "digitalocean", "vpc", "vpc-1", "slipway-uat", "created",
                                     {"region": "ams3"}, replaces=pending_id, audit_action="resource.adopt",
                                     rule="name and req:" + NONCE + " in the description")
    assert adopted == pending_id
    # The object recorded already under another name: the pending row just goes, the recorded row is updated.
    old_fw = await resources.record(uat, "digitalocean", "firewall", "fw-1", "slipway-uat-old-fw", "created")
    second = await resources.record_pending(uat, "digitalocean", "firewall", "slipway-uat-fw", nonce="1" * 16,
                                            body_hash="a" * 64)
    fw = await resources.record(uat, "digitalocean", "firewall", "fw-1", "slipway-uat-fw", "created",
                                replaces=second)
    assert fw == old_fw and await _row(second) is None and (await _row(fw)).name == "slipway-uat-fw"
    # The same answer recorded again with the same replaces (a retry after the commit): the row itself.
    assert await resources.record(uat, "digitalocean", "vpc", "vpc-1", "slipway-uat", "created",
                                  {"region": "ams3"}, replaces=pending_id) == pending_id
    # A replaces naming another kind's or name's row is refused.
    third = await resources.record_pending(uat, "digitalocean", "load_balancer", "slipway-uat-lb", nonce="2" * 16,
                                           body_hash="a" * 64)
    with pytest.raises(resources.ResourceError, match="isn't the pending create of firewall"):
        await resources.record(uat, "digitalocean", "firewall", "fw-1", "slipway-uat-fw", "created", replaces=third)
    with pytest.raises(resources.ResourceError, match="isn't the pending create of firewall"):
        await resources.record(uat, "digitalocean", "firewall", "fw-2", "slipway-uat-fw2", "created", replaces=fw)
    # A pending row that is already gone is no obstacle.
    assert await resources.forget(third)
    lb = await resources.record(uat, "digitalocean", "load_balancer", "lb-1", "slipway-uat-lb", "created",
                                replaces=third)
    # An object made again because the recorded one was gone.
    await resources.forget(lb, deleted=True)
    rebuilt = await resources.record(uat, "digitalocean", "load_balancer", "lb-2", "slipway-uat-lb", "created",
                                     audit_action="resource.rebuild")
    with pytest.raises(ValueError):
        await resources.record(uat, "digitalocean", "vpc", "vpc-9", "x", "created", audit_action="resource.delete")
    events = await _audits()
    adopt = next(e for e in events if e.action == "resource.adopt")
    assert adopt.details["rule"] == f"name and req:{NONCE} in the description" and adopt.details["replaces"] == NONCE
    assert [e.action for e in events if e.action in ("resource.rebuild", "resource.adopt")] == [
        "resource.adopt", "resource.rebuild"]
    assert (await _row(rebuilt)).provider_id == "lb-2"
    for event in events:
        assert set(event.details) >= {"provider", "kind", "name", "provider_id", "environment_id"}


async def test_a_vm_id_another_environment_holds_stays_refused():
    """What P5's reserve_vmid relies on (Decision 27): a bare record of another environment's provider id
    raises ResourceTaken, and a same-environment re-record still updates the row."""
    blue_env, green_env = await _envs("lab", "lab2")
    first = await resources.record(blue_env, "proxmox", "vm", "105", "slipway-lab-blue", "created",
                                   {"machine_id": "m-1"})
    with pytest.raises(resources.ResourceTaken, match="already belongs to environment lab"):
        await resources.record(green_env, "proxmox", "vm", "105", "slipway-lab2-green", "created",
                               {"machine_id": "m-2"})
    assert await resources.record(blue_env, "proxmox", "vm", "105", "slipway-lab-blue", "created",
                                  {"machine_id": "m-1", "node": "pve1"}) == first
    assert (await _row(first)).details == {"machine_id": "m-1", "node": "pve1"}
