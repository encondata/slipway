"""Review of phases 4 and 5, cluster "PostgreSQL run of phases 4 and 5" (K8): PostgreSQL-only regression tests.

These run only when SLIPWAY_TEST_DATABASE_URL names a PostgreSQL database; on SQLite they are skipped, since the
behaviour they pin is what asyncpg reports.

K8/F45: on PostgreSQL an address claim conflict names the address from the error's detail. asyncpg keeps
``Key (address)=(...)`` in ``exc.orig.detail``, not in the message, so reading only ``str(exc.orig)`` fell back to
reading the claims again, and named the wrong slot when the other claim was gone by then.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from slipway.db.session import get_sessionmaker
from slipway.models import AddressClaim, Host
from slipway.services import environments

pytestmark = [
    pytest.mark.usefixtures("no_real_hypervisors"),
    pytest.mark.skipif(not os.environ["SLIPWAY_DATABASE_URL"].startswith("postgresql"),
                       reason="SLIPWAY_TEST_DATABASE_URL does not name a PostgreSQL database"),
]


async def _claim(address: str, name: str) -> None:
    async with get_sessionmaker()() as db:
        host = Host(name=name, hostname=address, username="deploy", metrics={})
        db.add(host)
        await db.flush()
        db.add(AddressClaim(address=address, host_id=host.id))
        await db.commit()


async def _conflict(address: str) -> IntegrityError:
    """The IntegrityError PostgreSQL raises when a second claim of ``address`` is flushed."""
    async with get_sessionmaker()() as db:
        host = Host(name="mine-green", hostname=address, username="deploy", metrics={})
        db.add(host)
        await db.flush()
        db.add(AddressClaim(address=address, host_id=host.id))
        with pytest.raises(IntegrityError) as caught:
            await db.flush()
        await db.rollback()
    return caught.value


async def test_k8_a_claim_conflict_names_the_address_from_postgresqls_detail():
    await _claim("10.0.0.12", "other-green")
    exc = await _conflict("10.0.0.12")
    assert "Key (address)=(10.0.0.12)" in (getattr(exc.orig, "detail", None) or "")
    # The other create's claim is gone by the time the 409 is built: only the detail can name the address.
    async with get_sessionmaker()() as db:
        await db.execute(delete(AddressClaim))
        await db.commit()
    vms = {"blue": "10.0.0.1", "green": "10.0.0.12"}
    async with get_sessionmaker()() as db:
        found = await environments.claim_conflict(db, exc, vms)
    assert found is not None and (found.status, found.field) == (409, "hosts.green.machine.address")
    assert found.detail.startswith("10.0.0.12 was just taken")


async def test_k8_flush_claims_on_postgresql_names_the_slot_and_rolls_back():
    await _claim("10.0.0.12", "other-green")
    async with get_sessionmaker()() as db:
        host = Host(name="mine-green", hostname="10.0.0.12", username="deploy", metrics={})
        db.add(host)
        await db.flush()
        db.add(AddressClaim(address="10.0.0.12", host_id=host.id))
        with pytest.raises(environments.CreateRefused) as caught:
            await environments._flush_claims(db, {"blue": {"address": "10.0.0.1"},
                                                  "green": {"address": "10.0.0.12"}})
    assert (caught.value.status, caught.value.field) == (409, "hosts.green.machine.address")
    async with get_sessionmaker()() as db:  # the rollback left nothing of the refused create
        assert await db.get(AddressClaim, "10.0.0.12") is not None
        assert set(await db.scalars(select(Host.name))) == {"other-green"}


async def test_k8_postgresql_refuses_production_with_auto_activate_by_its_own_check():
    """ck_environments_production_auto is the check PostgreSQL names, as the API's 409 assumes."""
    from tests.test_models_providers import _adds, _base, _do_env

    ids = await _base()
    await _adds(_do_env(ids, "prod", production=True), _do_env(ids, "uat", auto_activate=True))
    async with get_sessionmaker()() as db:
        db.add(_do_env(ids, "prod-auto", production=True, auto_activate=True, manifest_file="api/slipway.yml"))
        with pytest.raises(IntegrityError) as caught:
            await db.commit()
    assert '"ck_environments_production_auto"' in str(caught.value.orig)
