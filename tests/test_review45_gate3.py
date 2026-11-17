"""Review of phases 4 and 5, integration gate after fix group 3: regression tests.

F21's page half. POST /notice/continue now takes the typed name for a production Activate while a slot is live
(the "Environments and retry API" cluster), so the notice's Continue button opens a dialog that asks for it and
sends it as ``confirm``, instead of posting an empty body that the API answers with 422.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Environment
from tests import do_fixtures as dof
from tests.test_accounts_web import scenario
from tests.test_data_api import storage  # noqa: F401
from tests.test_do_api import API, built, prod, set_rows, w  # noqa: F401
from tests.test_env_web import _tags
from tests.test_review_web import run_js

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")


async def _deployed(env: dof.DoEnv, slot: str, **options: Any) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=env.ids[slot], environment_id=env.env_id, kind="deploy", status="succeeded",
                         branch="main", commit_sha=dof.SHA, steps=[], options={"slot": slot, **options},
                         finished_at=datetime.now(UTC))
        db.add(dep)
        await db.commit()
        return dep.id


async def _stopped_chain(env: dof.DoEnv, *, live: bool) -> None:
    await built(env, "blue")
    await built(env, "green")
    await _deployed(env, "blue")
    green = await _deployed(env, "green", go_live=True)
    await set_rows(Environment, env.env_id, active_slot_id=env.ids["blue"] if live else None, status="live",
                   notice={"text": "stopped", "deployment_id": green.hex, "next": {"kind": "activate", "slot": "green"}})


async def test_f21_continue_of_a_production_activate_asks_the_name_on_the_page(w, tmp_path):  # noqa: F811
    env = await prod(w)
    await _stopped_chain(env, live=True)
    page = (await w.admin.get(f"/environments/{env.env_id}")).text
    tags = _tags(page)
    assert not any(a.get("data-api", "").endswith("/notice/continue") for _, a, _ in tags)
    button = next(a for t, a, _ in tags if t == "button" and a.get("data-open") == "continue-chain")
    assert "disabled" not in button
    form = next(a for t, a, _ in tags if t == "form" and a.get("data-form", "").endswith("/notice/continue"))
    assert form["data-form"] == f"POST {API}/{env.env_id}/notice/continue"
    assert 'id="continue-chain-confirm" name="confirm" data-must-equal="prod"' in page

    # The real slipway.js sends the typed name, and the API queues the Activate with it.
    result = run_js(tmp_path, scenario(page, ["continue-chain"], """
var form = document.querySelector("#continue-chain form");
var open = h("button", { type: "button", "data-open": "continue-chain" }, []);
document.body.appendChild(open);
await settle();
await click(open);
var before = form.querySelector('[type="submit"]').disabled;
field(form, "confirm").value = "prod";
user("input", field(form, "confirm"));
await settle();
await submit(form);
done({ before: before, calls: fetchCalls, bodies: fetchBodies });
"""))
    assert result["before"] is True
    sent = [b for c, b in zip(result["calls"], result["bodies"]) if c.endswith("/notice/continue")]
    assert sent == [{"confirm": "prod"}]
    resp = await w.admin.post(f"{API}/{env.env_id}/notice/continue", json=sent[0])
    assert resp.status_code == 202, resp.text
    async with get_sessionmaker()() as db:
        new = await db.get(Deployment, uuid.UUID(resp.json()["id"]))
        assert new.kind == "activate" and new.options["confirm"] == "prod"


async def test_f21_continue_without_a_live_slot_or_off_production_stays_one_click(w):  # noqa: F811
    # Nothing live on a production environment: the Activate moves no traffic away, so no name is asked.
    env = await prod(w)
    await _stopped_chain(env, live=False)
    page = (await w.admin.get(f"/environments/{env.env_id}")).text
    assert 'id="continue-chain"' not in page and 'data-open="continue-chain"' not in page
    assert any(a.get("data-api", "").endswith("/notice/continue") for _, a, _ in _tags(page))
    # Not production: the button posts at once, as before.
    other = await dof.make_do_env(name="stage", account_id=w.account_id, slots=("blue", "green"), status="live")
    await _stopped_chain(other, live=True)
    page = (await w.admin.get(f"/environments/{other.env_id}")).text
    assert 'id="continue-chain"' not in page
    button = next(a for _, a, _ in _tags(page) if a.get("data-api", "").endswith("/notice/continue"))
    assert "disabled" not in button
