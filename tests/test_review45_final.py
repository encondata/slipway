"""Review 45, the final fixer: the problems the checkers found in the fixes, each as the case that failed before
its fix.

- F7: when the stored secrets can't be decrypted and the variables set every secret, the release renders the
  password the database step gave the role (the variables), not an empty one; and while another slot is live,
  a deploy to the idle slot never changes the shared role's password from under it.
- F14, F36: a resize cut off while its ``pre_resize`` VM snapshot is being taken leaves that row failed, not
  pending.
- F32: a load balancer put-back that outlasts its budget ends itself before the switch stops waiting, with the
  by-hand text, so the switch never reports a put-back that may still land.

Everything outside Slipway is a fake.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import select, text

from slipway.db.session import get_sessionmaker
from slipway.models import Environment, Machine, MachineSnapshot
from slipway.services import do_lb, machines, traffic
from slipway.services.providers import proxmox as pxp
from tests import test_do_pipeline as dp
from tests import test_provider_proxmox as tp
from tests import vm_fixtures as vf
from tests.test_review45_deployer import PG_YML, _database_url_password

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")


@pytest.fixture
def dpw(tmp_path, monkeypatch) -> dp.World:
    return dp.World(tmp_path, monkeypatch)


# ---------------------------------------------------------------- F7: the role's password and the slot's .env


async def test_f7_unreadable_secrets_recovered_from_variables_render_the_roles_password(dpw):
    await dp.chain(dpw)
    env, _mem = await dpw.members()
    old = dict(env.app_secrets)
    await dp.set_rows(Environment, dpw.env_id, env=dict(old))
    async with get_sessionmaker()() as db:
        await db.execute(text("UPDATE environments SET app_secrets = 'not-a-fernet-token'"))
        await db.commit()
    green = await dpw.run(await dpw.queue(slot="green"))
    dp.ok(green)
    (sql,) = dpw.host("green").sql()
    assert "ALTER ROLE" in sql or "CREATE ROLE" in sql
    assert _database_url_password(dp.env_file(dpw, "green")) == old["POSTGRES_PASSWORD"]
    assert old["POSTGRES_PASSWORD"] not in green.log


async def test_f7_a_renamed_password_secret_keeps_the_live_slots_password(dpw):
    await dp.chain(dpw)
    env, _mem = await dpw.members()
    assert env.active_slot_id is not None
    blue_pw = _database_url_password(dp.env_file(dpw, "blue"))
    dpw.gh.texts = {**dpw.gh.texts, "slipway.yml": PG_YML}
    green = await dpw.run(await dpw.queue(slot="green"))
    dp.ok(green)
    env, _mem = await dpw.members()
    assert env.app_secrets["PG_PASS"] == blue_pw == env.app_secrets["POSTGRES_PASSWORD"]
    assert _database_url_password(dp.env_file(dpw, "green")) == blue_pw
    assert _database_url_password(dp.env_file(dpw, "blue")) == blue_pw
    assert blue_pw not in green.log


async def test_f7_another_password_for_the_role_while_a_slot_is_live_is_refused(dpw):
    await dp.chain(dpw)
    env, _mem = await dpw.members()
    blue_pw = env.app_secrets["POSTGRES_PASSWORD"]
    await dp.set_rows(Environment, dpw.env_id, env={"PG_PASS": "w" * 40})
    dpw.gh.texts = {**dpw.gh.texts, "slipway.yml": PG_YML}
    green = await dpw.run(await dpw.queue(slot="green"))
    assert green.status == "failed"
    assert dp.steps(green)["database"] == "failed"
    assert "blue is live and connects to shop's database with the value of POSTGRES_PASSWORD" in green.error
    assert "The role's password was not changed" in green.error
    assert dpw.host("green").sql() == []  # no psql ran
    env, _mem = await dpw.members()
    assert "PG_PASS" not in env.app_secrets
    assert _database_url_password(dp.env_file(dpw, "blue")) == blue_pw
    assert "w" * 40 not in green.log


# ---------------------------------------------------------------- F14, F36: a resize cut off in its snapshot


@pytest.fixture
def pve(tmp_path, monkeypatch):
    return tp.World(tmp_path, monkeypatch, vf.quiet_network(monkeypatch))


async def test_f36_a_resize_cut_off_in_its_pre_resize_snapshot_leaves_the_row_failed(pve, monkeypatch):
    env, _ctx, _ = await tp.made(pve)
    await tp.grow(env, cores=6)

    async def hangs(self, ctx, row):
        await asyncio.sleep(3600)

    monkeypatch.setattr(pxp.ProxmoxProvider, "snapshot", hangs)
    ctx = await tp.reload(pve, env)
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(machines.resize_step(ctx), 2.0)
    async with get_sessionmaker()() as db:
        rows = list(await db.scalars(select(MachineSnapshot).where(MachineSnapshot.machine_id == env.machines["blue"])))
        machine = await db.get(Machine, env.machines["blue"])
    assert [(r.reason, r.status) for r in rows] == [("pre_resize", "failed")]
    assert machine.last_error == "The resize of slipway-uat-blue was cut off before it finished"


# ---------------------------------------------------------------- F32: the put-back ends within its budget


async def test_f32_a_do_lb_put_back_past_its_budget_ends_before_the_switch_stops_waiting(monkeypatch):
    lines: list[str] = []

    async def say(text: str) -> None:
        lines.append(text)

    @contextlib.asynccontextmanager
    async def client(state):
        yield object()

    async def state(env_id):
        return None

    async def hangs(do, lb_id, name):  # a DigitalOcean read longer than the switch's wait
        await asyncio.sleep(3600)

    monkeypatch.setattr(do_lb, "_put_back_worst", lambda: 0.4)
    monkeypatch.setattr(do_lb, "_state", state)
    monkeypatch.setattr(do_lb, "_client", client)
    monkeypatch.setattr(do_lb, "_wait_active", hangs)
    backend = do_lb.DoLbBackend()
    ctx = SimpleNamespace(env=SimpleNamespace(id=uuid.uuid4()), mode="activate", say=say)
    plan = traffic.Plan("do_lb", meta={"lb_id": "lb-1", "lb_name": "slipway-uat", "previous": [11],
                                       "slot_of": {11: "blue"}})
    applied = traffic.Applied(changes=[traffic.Change("api.uat.example.com", "update", None, None, None, None, "")])
    pb = await traffic._shielded_put_back(backend, ctx, plan, applied, held=None)
    assert pb.not_applied is not None and pb.not_applied.startswith("DigitalOcean took longer than")
    assert pb.failed and pb.failed == ["point load balancer slipway-uat at blue (droplet 11)"]
