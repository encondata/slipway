"""Review 45, cluster "Environment rules and env jobs", K5: the environment page's ``actions`` read no hypervisor.
Activate's VM-off check (``vm_off_problem``, a ``describe``) is left to the queue and the job's own check.
Proxmox is the fake of tests/test_provider_proxmox.py's ``world``; nothing real is called.
"""

from __future__ import annotations

from types import SimpleNamespace

from slipway.db.session import get_sessionmaker
from slipway.models import Environment, User
from slipway.services import environments
from slipway.services.providers import proxmox as pxp
from tests import fake_switchyard
from tests.test_env_machines import _set, deployed, pve_env, ready, refusal
from tests.test_provider_proxmox import net, world  # noqa: F401  (fixtures)

OFF = "green's VM slipway-uat-green is off: deploy to green again to finish its resize"


async def _actions(env) -> dict:
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        user = await db.get(User, env.user_id)
        return await environments.actions(db, row, SimpleNamespace(user=user, can=lambda perm: True))


async def test_k5_a_page_view_of_a_vm_environment_makes_no_describe_call(world, monkeypatch):  # noqa: F811
    fake_switchyard.install(monkeypatch)
    await fake_switchyard.configure()
    env = await pve_env(world)
    await _set(Environment, env.env_id, traffic={"switch": "switchyard", "dns": None})
    for slot in ("blue", "data"):
        await ready(world, env, slot)
    await deployed(env, "blue")
    await _set(Environment, env.env_id, active_slot_id=env.instances["blue"], status="live")
    await ready(world, env, "green", status="stopped")  # left off by a resize
    await deployed(env, "green")

    calls: list[str] = []
    real = pxp.ProxmoxProvider.describe

    async def counted(self, ctx):
        calls.append(ctx.vm)
        return await real(self, ctx)

    monkeypatch.setattr(pxp.ProxmoxProvider, "describe", counted)
    out = await _actions(env)
    assert calls == []
    assert out["activate"]["slot"] == "green" and out["activate"]["available"] is True
    # The queue still reads the VM and refuses it, as the job's check does (P5 §10.4).
    refused = await refusal(env, "activate", slot="green")
    assert refused is not None and (refused.status, refused.text) == (409, OFF)
    assert calls == ["slipway-uat-green"]
    # The page-view switch doesn't leak out of actions.
    assert environments._page_view.get() is False
