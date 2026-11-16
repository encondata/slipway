"""Review fixes (phase 3) for Add a slot and environment create.

F26/F30: Add a slot refuses an environment whose traffic isn't switched by Switchyard (create's §9.1 rule 7 and
PATCH refuse two app slots without it), and the environment page doesn't offer it.
F29: environment create and Add a slot refuse a slot folder (``<deploy root>/<env>-<slot>``) that is, holds or
is inside another instance's folder on the same host, as ``POST /instances`` does.

Jobs are queued and never run; Switchyard, Cloudflare and GitHub are the fakes of tests/test_env_api.py.
"""

from __future__ import annotations

import uuid

from sqlalchemy import delete, func, select

from slipway.db.session import get_sessionmaker
from slipway.models import AppSetting, AuditEvent, Environment, Instance
from slipway.services import environments
from tests.test_data_api import clients, storage  # noqa: F401  (storage: autouse)
from tests.test_env_api import _create_body, _update, cf, github, no_public_checks, submitted, sy  # noqa: F401
from tests.test_env_rules import _world

BLUE_GREEN = "Blue/Green moves its names in Switchyard when a slot goes live: choose Switchyard"


async def _instances(*where) -> list[tuple[str, str | None]]:
    async with get_sessionmaker()() as db:
        rows = (await db.scalars(select(Instance).where(*where))).all()
        return sorted((i.slug, i.deploy_dir) for i in rows)


async def _slot_adds() -> int:
    async with get_sessionmaker()() as db:
        return int(await db.scalar(select(func.count()).select_from(AuditEvent)
                                   .where(AuditEvent.action == "environment.slot_add")) or 0)


async def _standalone(ids: dict[str, uuid.UUID], host: str, slug: str, deploy_dir: str | None) -> None:
    async with get_sessionmaker()() as db:
        db.add(Instance(name=slug, slug=slug, repository_id=ids["repo"], host_id=ids[f"host_{host}"], branch="main",
                        build_source="app", status="created", deploy_dir=deploy_dir))
        await db.commit()


# ------------------------------------------------------------------- F26 / F30


async def test_add_slot_refuses_an_environment_without_switchyard(make_client):
    c = await clients(make_client)
    ids = await _world(slots=("blue", "data"), live=("blue", "data"), traffic={"switch": "none", "dns": None})
    m, e = c["maintainer"], f"/api/v1/environments/{ids['env']}"
    out = (await m.get(e)).json()
    assert out["actions"]["add_slot"] == {"available": False, "reason": BLUE_GREEN}
    r = await m.post(f"{e}/slots", json={"host_id": str(ids["host_green"]), "update_data_server": True})
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == BLUE_GREEN
    # Nothing was written: no green instance, no audit row, no job.
    assert [s for s, _ in await _instances(Instance.environment_id == ids["env"])] == ["uat-blue", "uat-data"]
    assert await _slot_adds() == 0
    # The traffic settings are untouched.
    async with get_sessionmaker()() as db:
        env = await db.get(Environment, ids["env"])
        assert env is not None and env.traffic == {"switch": "none", "dns": None}


async def test_add_slot_refuses_when_switchyard_isnt_set_up(make_client):
    c = await clients(make_client)
    ids = await _world(slots=("blue", "data"), live=("blue", "data"))
    async with get_sessionmaker()() as db:
        await db.execute(delete(AppSetting).where(AppSetting.key == "switchyard"))
        await db.commit()
    m, e = c["maintainer"], f"/api/v1/environments/{ids['env']}"
    out = (await m.get(e)).json()
    assert out["actions"]["add_slot"] == {"available": False, "reason": environments.SET_UP_SWITCHYARD}
    r = await m.post(f"{e}/slots", json={"host_id": str(ids["host_green"])})
    assert r.status_code == 409 and r.json()["detail"] == environments.SET_UP_SWITCHYARD
    assert await _slot_adds() == 0


async def test_add_slot_is_offered_and_accepted_with_switchyard(make_client):
    c = await clients(make_client)
    ids = await _world(slots=("blue", "data"), live=("blue", "data"))
    m, e = c["maintainer"], f"/api/v1/environments/{ids['env']}"
    assert (await m.get(e)).json()["actions"]["add_slot"]["available"] is True
    r = await m.post(f"{e}/slots", json={"host_id": str(ids["host_green"])})
    assert r.status_code == 201, r.text
    assert r.json()["slot"] == "green"


# ------------------------------------------------------------------------- F29


async def test_create_refuses_a_slot_folder_another_instance_uses(make_client):
    c = await clients(make_client)
    ids = await _world()
    m = c["maintainer"]
    # A standalone instance in /opt/slipway/prod-blue on h-blue (allowed: no environment prod yet).
    r = await m.post("/api/v1/instances", json={"name": "shop", "repository_id": str(ids["repo"]),
                                                "host_id": str(ids["host_blue"]), "deploy": False,
                                                "deploy_dir": "/opt/slipway/prod-blue"})
    assert r.status_code == 201, r.text
    r = await m.post("/api/v1/environments", json=_create_body(ids))
    assert r.status_code == 409, r.text
    assert r.json() == {"detail": "/opt/slipway/prod-blue overlaps /opt/slipway/prod-blue, the folder of instance "
                                  "shop", "field": "hosts.blue"}
    r = await m.post("/api/v1/environments?check=true", json=_create_body(ids))
    assert r.status_code == 409 and r.json()["field"] == "hosts.blue"
    async with get_sessionmaker()() as db:
        assert await db.scalar(select(Environment.id).where(Environment.name == "prod")) is None
    assert await _instances(Instance.slug.like("prod-%")) == []


async def test_create_refuses_folders_that_hold_or_sit_inside_a_slot_folder(make_client):
    c = await clients(make_client)
    ids = await _world()
    m = c["maintainer"]
    # Inside green's folder on h-green.
    await _standalone(ids, "green", "inner", "/opt/slipway/prod-green/inner")
    r = await m.post("/api/v1/environments", json=_create_body(ids))
    assert r.status_code == 409
    assert r.json() == {"detail": "/opt/slipway/prod-green overlaps /opt/slipway/prod-green/inner, the folder of "
                                  "instance inner", "field": "hosts.green"}
    async with get_sessionmaker()() as db:
        await db.execute(delete(Instance).where(Instance.slug == "inner"))
        await db.commit()
    # A folder that holds the data server's folder on h-data.
    await _update(Instance, ids["data"], deploy_dir="/srv/apps")
    async with get_sessionmaker()() as db:
        from slipway.models import Host

        host = await db.get(Host, ids["host_data"])
        assert host is not None
        host.deploy_root = "/srv/apps"
        await db.commit()
    r = await m.post("/api/v1/environments", json=_create_body(ids))
    assert r.status_code == 409
    assert r.json() == {"detail": "/srv/apps/prod-data overlaps /srv/apps, the folder of instance uat data",
                        "field": "hosts.data"}


async def test_a_folder_on_another_host_or_a_neighbour_name_is_no_clash(make_client):
    c = await clients(make_client)
    ids = await _world()
    m = c["maintainer"]
    await _standalone(ids, "green", "other-host", "/opt/slipway/prod-blue")  # h-green, not blue's host
    await _standalone(ids, "blue", "neighbour", "/opt/slipway/prod-blue2")   # a prefix, not a folder of it
    r = await m.post("/api/v1/environments", json=_create_body(ids))
    assert r.status_code == 201, r.text


async def test_add_slot_refuses_a_folder_another_instance_uses(make_client):
    c = await clients(make_client)
    ids = await _world(slots=("blue", "data"), live=("blue", "data"))
    m, e = c["maintainer"], f"/api/v1/environments/{ids['env']}"
    await _standalone(ids, "green", "shop", "/opt/slipway/uat-green")
    r = await m.post(f"{e}/slots", json={"host_id": str(ids["host_green"]), "update_data_server": True})
    assert r.status_code == 409, r.text
    assert r.json() == {"detail": "/opt/slipway/uat-green overlaps /opt/slipway/uat-green, the folder of instance "
                                  "shop", "field": "hosts.green"}
    assert [s for s, _ in await _instances(Instance.environment_id == ids["env"])] == ["uat-blue", "uat-data"]
    assert await _slot_adds() == 0
    # Once the folder is free, the slot is added.
    await _update(Instance, (await _id_of("shop")), deploy_dir="/opt/slipway/shop")
    r = await m.post(f"{e}/slots", json={"host_id": str(ids["host_green"])})
    assert r.status_code == 201, r.text


async def _id_of(slug: str) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        found = await db.scalar(select(Instance.id).where(Instance.slug == slug))
        assert found is not None
        return found


async def test_folder_problem_rule():
    assert environments.folders_overlap("/a/b", "/a/b")
    assert environments.folders_overlap("/a/b", "/a/b/c")
    assert environments.folders_overlap("/a/b/c", "/a/b")
    assert not environments.folders_overlap("/a/b", "/a/bc")
    assert not environments.folders_overlap("/a/bc", "/a/b")
