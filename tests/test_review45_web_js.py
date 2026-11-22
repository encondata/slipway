"""Review 45, the environment dialogs, the new-environment flow and the machine blockers (group 4).

F23: the New environment flow shows a check refusal naming the Review's typed total (the account's monthly limit,
field ``confirm_cost``) at the step the user is on, and a failed check clears the estimate, so Review never shows
(or accepts) an older total. F46: a production Activate's typed name never enables the button before the traffic
plan has loaded with no blocker, nor after its read failed. F49: a production Delete that needs a snapshot the
user can't take offers no ``drop_data`` and keeps Delete off. K4: ``GET .../machines?blockers=true`` reads each
VM's removal blockers as Remove slot's and Delete's check reads them, with ``forgettable``; the Remove slot, Delete
and retry dialogs offer ``forget_vms`` from those flags when they open. K6: ``?check=true`` on ``POST .../slots``
and on a growing ``PATCH``: every refusal runs, the plan and the cost are answered, nothing is written; the Add slot
and Grow dialogs price through it.

The JS runs the real slipway.js under the fake DOM of tests/test_review_web.py. FakeDigitalOcean and FakeProxmox
answer every provider call; jobs are queued and never run.
"""

from __future__ import annotations

import html
import json
import re
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import func, select, update

from slipway.core.permissions import Perm
from slipway.db.session import get_sessionmaker
from slipway.models import (
    AddressClaim,
    AuditEvent,
    Backup,
    Deployment,
    Environment,
    Host,
    Instance,
    Machine,
    User,
)
from slipway.services import do_rules, environments, esxi
from slipway.web import pages
from tests import do_fixtures as dof
from tests import vm_fixtures as vf
from tests.test_accounts_web import scenario
from tests.test_data_api import client_with, clients, storage  # noqa: F401  (storage: autouse)
from tests.test_do_api import API, set_account, submitted, w  # noqa: F401  (fixtures)
from tests.test_do_create import TWO
from tests.test_do_web import _build, _live, _repo
from tests.test_env_machines import BLOCKERS, all_ready, pve_env, quick_tasks  # noqa: F401  (fixture)
from tests.test_env_machines_api import esxi_world  # noqa: F401  (fixture)
from tests.test_env_machines_create import FILES, Ctx, reader, vm
from tests.test_provider_proxmox import World, a_world, net, world  # noqa: F401  (fixtures)
from tests.test_review_web import run_js

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")


def _between(page: str, start: str, end: str) -> str:
    part = page[page.index(start):]
    return part[:part.index(end)]


def _dialog(page: str, dialog_id: str) -> str:
    return _between(page, f'id="{dialog_id}"', "</dialog>")


def _text(fragment: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", fragment))).strip()


async def _count(model: Any, *where: Any) -> int:
    async with get_sessionmaker()() as db:
        return int(await db.scalar(select(func.count()).select_from(model).where(*where)) or 0)


async def _audits(action: str) -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        return list(await db.scalars(select(AuditEvent).where(AuditEvent.action == action)))


async def _cloud(env_id: uuid.UUID) -> dict[str, Any]:
    async with get_sessionmaker()() as db:
        return dict((await db.get(Environment, env_id)).cloud or {})


# ------------------------------------------------------------------------------- F23: the flow's limit

FLOW = """
var form = document.getElementById("env-flow");
var CHECK = "POST /api/v1/environments?check=true";
answers["GET /api/v1/repositories/%(repo)s/branches"] = [{ status: 200, body: ["main"] }];
answers["GET /api/v1/repositories/%(repo)s/manifest?branch=main&path=slipway.yml"] = [{ status: 200, body: { manifest: %(manifest)s } }];
answers["GET /api/v1/provider-accounts/%(account)s/catalog?region=nyc3"] = [{ status: 200, body: %(catalog)s }];
var branch = field(form, "branch");
branch.value = "main"; user("change", branch); await settle();
var where = form.querySelector('[name="where"][value="digitalocean"]');
where.checked = true; form.querySelector('[name="where"][value="hosts"]').checked = false;
user("change", where); await settle();
var droplet = field(form, "placement.droplet_size"), db = field(form, "placement.db_size");
field(form, "name").value = "shop";
var next = form.querySelector("[data-flow-next]"), deploy = form.querySelector("[data-flow-deploy]");
var back = form.querySelector("[data-flow-back]");
function errs() { return [1,2,3,4,5,6,7].map(function (n) { return form.querySelector('[data-step="' + n + '"] [data-step-error]').textContent; }); }
answers[CHECK] = [{ status: 200, body: { ok: true, plan: { hostnames: [] } } }];
await click(next); await click(next);  // step 3: the account and the sizes
droplet.value = "s-1vcpu-1gb"; db.value = "db-s-1vcpu-1gb";
"""


async def _flow(w: Any, tmp_path: Any, body: str) -> dict[str, Any]:
    repo = await _repo()
    page = (await w.c["maintainer"].get("/environments/new")).text
    catalog = (await w.admin.get(f"/api/v1/provider-accounts/{w.account_id}/catalog?region=nyc3")).json()
    manifest = {"name": "shop", "settings": [], "services": [], "secrets": [], "first_admin": None,
                "capabilities": ["backup", "restore", "bluegreen", "managed", "edge", "digitalocean"],
                "edge": {"port": 8080, "health": "/healthz", "env": ["STACK_PROXY_IP"], "projects": []}}
    limit = {"detail": "This would bring do-main's estimate to $147.00 a month, over its limit of $100.00",
             "field": "confirm_cost"}
    cost = {"lines": [], "total_cents": 4700, "total": "47.00", "as_of": "2026-11-15", "note": ""}
    values = {"repo": repo, "manifest": json.dumps(manifest), "account": w.account_id, "catalog": json.dumps(catalog),
              "limit": json.dumps(limit), "cost": json.dumps(cost)}
    return run_js(tmp_path, scenario(page, ["env-flow"], (FLOW + body) % values))


async def test_f23_the_limit_refusal_is_shown_at_the_step_and_nothing_is_created(w, tmp_path):  # noqa: F811
    result = await _flow(w, tmp_path, """
answers[CHECK] = [{ status: 409, body: %(limit)s }];
await click(next);
var first = { step: form._flow.current, errs: errs(), invalid: field(form, "confirm_cost").getAttribute("aria-invalid") };
await click(next);
done({ first: first, step: form._flow.current, errs: errs(), cost: form._flow.cost, deployHidden: deploy.hidden,
       calls: fetchCalls });
""")
    text = "This would bring do-main's estimate to $147.00 a month, over its limit of $100.00"
    # The refusal stays where the sizes were chosen, with its text; Review isn't reached and nothing is created.
    assert result["first"]["step"] == 3 and result["first"]["errs"][2] == text
    assert result["first"]["invalid"] != "true"  # Review's typed total isn't what to fix
    assert result["step"] == 3 and result["errs"][2] == text and result["cost"] is None
    assert result["deployHidden"] is True
    assert "POST /api/v1/environments" not in result["calls"]


async def test_f23_a_failed_check_clears_the_estimate_review_showed(w, tmp_path):  # noqa: F811
    result = await _flow(w, tmp_path, """
// Every check prices it: Review shows $47.00.
answers[CHECK] = [{ status: 200, body: { ok: true, plan: { hostnames: [] }, cost: %(cost)s } }];
for (var i = 0; i < 4; i++) await click(next);
var first = { step: form._flow.current, total: form._flow.cost && form._flow.cost.total };
// Back to the sizes: a larger droplet, whose check refuses on a later step's field (a missing name): the
// flow moves on, without the old estimate.
for (var j = 0; j < 4; j++) await click(back);
var sizes = form._flow.current;
droplet.value = "s-2vcpu-2gb"; user("change", droplet); await settle();
answers[CHECK] = [{ status: 422, body: { detail: "Add a public name", field: "hostnames" } }];
await click(next);
var skipped = { step: form._flow.current, cost: form._flow.cost };
// The last full check refuses on the limit: it is shown on step 6, not Review.
answers[CHECK] = [{ status: 200, body: { ok: true, plan: { hostnames: [] } } }, { status: 200, body: { ok: true, plan: { hostnames: [] } } },
                  { status: 409, body: %(limit)s }];
await click(next); await click(next); await click(next);
done({ first: first, sizes: sizes, skipped: skipped, step: form._flow.current, errs: errs(), cost: form._flow.cost,
       table: form.querySelector("[data-cost-table]").textContent });
""")
    assert result["first"] == {"step": 7, "total": "47.00"}
    assert result["sizes"] == 3
    assert result["skipped"] == {"step": 4, "cost": None}
    assert result["step"] == 6 and result["errs"][5].startswith("This would bring do-main's estimate")
    assert result["cost"] is None and "$47.00" not in result["table"]


# ----------------------------------------------------------------------- F46: Activate's plan gate

PLAN_URL = "/api/v1/environments/%s/traffic/plan?slot=green"


async def _activate_page(env_id: uuid.UUID) -> str:
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env_id)
        db.expunge(row)

    class Auth:
        def can(self, perm: str) -> bool:
            return True

    tpl = pages.templates.env.from_string(
        '{% from "_environment_dialogs.html" import activate_dialog with context %}'
        '{{ activate_dialog(env, "activate-slot", s, "blue", names, lb=True, production=True) }}')
    return tpl.render(env=row, s={"slot": "green", "sha7": "0123456", "host": "slipway-prod-green"},
                      names=[{"hostname": "api.prod.example.com"}], auth=Auth(), Perm=Perm)


async def test_f46_production_activate_stays_off_until_the_plan_loads_without_blockers(w, tmp_path):  # noqa: F811
    env = await dof.make_do_env(name="prod", production=True, account_id=w.account_id)
    page = await _activate_page(env.env_id)
    assert re.search(r'type="submit" data-plan-submit data-plan-blocked="1" disabled', page)
    url = PLAN_URL % env.env_id
    plan = {"routes": [], "switch": {"changes": [], "blockers": []}, "dns": None}
    result = run_js(tmp_path, scenario(page, ["activate-slot"], """
var dlg = document.getElementById("activate-slot"), form = dlg.querySelector("form");
var submitBtn = form.querySelector('[type="submit"]'), typed = field(form, "confirm");
var opener = h("button", { "data-open": "activate-slot" }); document.body.appendChild(opener);
var out = {};
// The read hasn't answered: typing the name leaves the button off.
answers["GET %(url)s"] = [{ status: 200, body: %(plan)s }];
user("click", opener);
typed.value = "prod"; user("input", typed);
out.pending = submitBtn.disabled;
await settle();
out.loaded = submitBtn.disabled;
// The read fails: the box shows the error and the typed name enables nothing.
answers["GET %(url)s"] = [{ status: 502, body: { detail: "Cloudflare didn't answer" } }];
await click(opener);
typed.value = "prod"; user("input", typed); await settle();
out.failed = [submitBtn.disabled, submitBtn.dataset.planBlocked];
// A plan with a blocker: off too.
answers["GET %(url)s"] = [{ status: 200, body: { routes: [], switch: { changes: [], blockers: ["green isn't built"] }, dns: null } }];
await click(opener);
typed.value = "prod"; user("input", typed); await settle();
out.blocked = submitBtn.disabled;
// A plan with no blocker: on once the name is typed.
answers["GET %(url)s"] = [{ status: 200, body: %(plan)s }];
await click(opener);
out.untyped = submitBtn.disabled;
typed.value = "prod"; user("input", typed); await settle();
out.ready = submitBtn.disabled;
done(out);
""" % {"url": url, "plan": json.dumps(plan)}))
    assert result["pending"] is True and result["loaded"] is False
    assert result["failed"] == [True, "1"]
    assert result["blocked"] is True
    assert result["untyped"] is True and result["ready"] is False


# ------------------------------------------------------------------- F49: production Delete, no backup

async def _forced_production(w: Any) -> dof.DoEnv:
    prod = await dof.make_account("do-prod", production=True)
    env = await dof.make_do_env(name="prod", account_id=prod, production=True)
    await _build(env, "blue")
    await _live(env, "blue")
    async with get_sessionmaker()() as db:
        await db.execute(update(Environment).where(Environment.id == env.env_id)
                         .values(active_slot_id=None, retiring_at=datetime.now(UTC)))
        db.add(Backup(instance_id=env.ids["data"], name="b1", reason="manual", status="missing", format="pg-custom",
                      identity_fp="x" * 64, location="slipway", taken_at=datetime.now(UTC)))
        await db.commit()
    return env


async def test_f49_production_delete_without_data_backup_offers_no_drop_data(w, make_client, tmp_path):  # noqa: F811
    env = await _forced_production(w)
    url = f"/environments/{env.env_id}"
    who = await client_with(make_client, "deleter@example.com", [
        "environments:read", "environments:write", "environments:delete", "data:read", "data:reset",
        "instances:read"])
    page = (await who.get(url)).text
    dialog = _dialog(page, "delete-env")
    assert 'data-snapshot-state="forced"' in dialog, _text(dialog)
    assert 'name="drop_data"' not in dialog and "data-drop-data" not in dialog
    assert ("A production environment is deleted only after a snapshot, and taking one needs the data:backup "
            "permission.") in _text(dialog)
    assert re.search(r'type="submit" data-blocked disabled', dialog)
    result = run_js(tmp_path, scenario(page, ["delete-env"], """
var dlg = document.getElementById("delete-env"), form = dlg.querySelector("form");
var submitBtn = form.querySelector('[type="submit"]');
var opener = h("button", { "data-open": "delete-env" }); document.body.appendChild(opener);
await click(opener);
var name = field(form, "confirm"), phrase = field(form, "confirm_production");
name.value = "prod"; user("input", name); phrase.value = "delete production prod"; user("input", phrase);
await settle();
done({ disabled: submitBtn.disabled });
"""))
    assert result["disabled"] is True
    # The API agrees: whatever is sent, it needs a snapshot.
    body = {"confirm": "prod", "confirm_production": "delete production prod", "drop_data": True}
    resp = await who.request("DELETE", f"{API}/{env.env_id}", json=body)
    assert (resp.status_code, resp.json()["detail"]) == (422, "A production environment is deleted only after a snapshot")

    # With data:backup the snapshot is forced and Delete opens once the phrases are typed.
    dialog = _dialog((await w.admin.get(url)).text, "delete-env")
    assert re.search(r'name="snapshot_first" data-no-send checked disabled', dialog)
    assert 'name="drop_data"' not in dialog and "data-blocked" not in dialog and "data-snapshot-needed" not in dialog


# ------------------------------------------------------------------------- K4: the machines' blockers

OTHER = {"blue": "10.0.0.110", "green": "10.0.0.111", "data": "10.0.0.112"}


async def _account(account_id: uuid.UUID) -> Any:
    from slipway.models import ProviderAccount

    async with get_sessionmaker()() as db:
        row = await db.get(ProviderAccount, account_id)
        db.expunge(row)
        return row


@pytest.fixture
async def c(make_client) -> dict[str, Any]:
    return await clients(make_client)


@pytest.mark.parametrize("blocker", list(BLOCKERS))
async def test_k4_machines_lists_each_blocker_with_what_remove_slot_accepts(c, world, quick_tasks, monkeypatch,
                                                                            blocker):
    env = await pve_env(world)
    ids = await all_ready(world, env)
    make, text, forgettable = BLOCKERS[blocker]
    url = f"/api/v1/environments/{env.env_id}/machines"
    plain = {m["slot"]: m for m in (await c["viewer"].get(url)).json()}
    assert plain["green"]["blockers"] is None and plain["green"]["forgettable"] is None  # not asked: not read
    make(world, ids["green"], monkeypatch)
    writes = len(world.writes())
    answer = {m["slot"]: m for m in (await c["viewer"].get(url, params={"blockers": "true"})).json()}
    green = answer["green"]
    assert [b["text"][:len(text)] for b in green["blockers"]] == [text], green
    assert green["blockers"][0]["forgettable"] is forgettable and green["forgettable"] is forgettable
    assert world.writes(writes) == []  # reads only
    # The flag is what Remove slot then does with forget_vms.
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        passed = await environments.remove_slot_problem(db, row, "green", forget_vms=True)
    assert (passed is None) == green["forgettable"]


async def test_k4_nothing_blocking_is_not_forgettable(c, world):
    env = await pve_env(world)
    await all_ready(world, env)
    answer = (await c["viewer"].get(f"/api/v1/environments/{env.env_id}/machines?blockers=true")).json()
    assert {m["slot"]: (m["blockers"], m["forgettable"]) for m in answer} == {
        "blue": ([], False), "green": ([], False), "data": ([], False)}
    # A VM never made holds nothing to block its removal.
    env = await pve_env(world, name="dev", addresses=OTHER, account=await _account(env.account_id))
    answer = (await c["viewer"].get(f"/api/v1/environments/{env.env_id}/machines?blockers=true")).json()
    assert all(m["stage"] == "planned" and m["blockers"] == [] and m["forgettable"] is False for m in answer)


async def test_k4_a_blockers_read_that_doesnt_answer_in_time_is_unknown(c, esxi_world, monkeypatch):  # noqa: F811
    from slipway.api.v1 import environments as env_api
    from tests.test_env_machines_api import esxi_made, idle

    w = esxi_world
    env, _ctx, _log = await esxi_made(w)
    await idle(env)
    monkeypatch.setattr(env_api, "LIVE_LIMIT", {"proxmox": 0.2, "esxi": 0.2})
    key = str(env.account_id)
    for _ in range(esxi.SESSIONS_PER_ACCOUNT):  # a job holds both job sessions
        await esxi.job_sessions[key].acquire()
    try:
        started = time.monotonic()
        (vm_out,) = (await c["viewer"].get(f"/api/v1/environments/{env.env_id}/machines?blockers=true")).json()
        assert time.monotonic() - started < 5
    finally:
        for _ in range(esxi.SESSIONS_PER_ACCOUNT):
            esxi.job_sessions[key].release()
    assert vm_out["live"]["power"] == "running"
    assert vm_out["blockers"] is None and vm_out["forgettable"] is None


def test_k4_vm_forget_offers_only_what_forget_vms_gets_past(tmp_path):
    result = run_js(tmp_path, """
function box(scope, slot) {
  var p = h("p", { "data-render": "vm_forget", "data-forget-scope": scope, "data-forget-slot": slot || "" });
  var cb = h("input", { type: "checkbox", name: "forget_vms" });
  var div = h("div", { "data-forget-vms": "" }, [p, h("label", {}, [cb])]);
  var form = h("form", {}, [div]);
  document.body.appendChild(form);
  return { p: p, div: div, cb: cb };
}
var hidden = { slot: "green", name: "slipway-uat-green", forgettable: true, blockers: [{ text: "Slipway can't see VM 101.", forgettable: true }] };
var busy = { slot: "blue", name: "slipway-uat-blue", forgettable: false, blockers: [{ text: "Proxmox is still running vzdump", forgettable: false }] };
var clear = { slot: "blue", name: "slipway-uat-blue", forgettable: false, blockers: [] };
var unknown = { slot: "blue", name: "slipway-uat-blue", forgettable: null, blockers: null };
var r = window.slipway.renderers.vm_forget, out = {};
var a = box("slot", "green"); a.div.hidden = true; r(a.p, [busy, hidden]);
out.slot = [a.div.hidden, a.p.textContent];
var b = box("all"); b.div.hidden = true; r(b.p, [busy, hidden]);
out.allBusy = b.div.hidden;
var c = box("all"); c.div.hidden = true; r(c.p, [clear, hidden]);
out.allClear = [c.div.hidden, c.p.textContent];
var d = box("all"); d.div.hidden = false; d.cb.checked = true; r(d.p, [clear]);
out.nothing = [d.div.hidden, d.cb.checked];
var e = box("all"); e.div.hidden = false; r(e.p, [unknown, hidden]);
out.unknown = e.div.hidden;
done(out);
""")
    assert result["slot"] == [False, "Slipway can't see VM 101."]
    assert result["allBusy"] is True  # Delete would still stop at blue's task
    assert result["allClear"] == [False, "Slipway can't see VM 101."]
    assert result["nothing"] == [True, False]
    assert result["unknown"] is False  # not read in time: the page's own state stays


async def test_k4_the_dialogs_carry_the_blockers_read(c, world):
    from tests.test_machines_web import _failed_env_job

    env = await pve_env(world)
    await all_ready(world, env)
    page = (await c["maintainer"].get(f"/environments/{env.env_id}")).text
    loader = f'data-load="/api/v1/environments/{env.env_id}/machines?blockers=true" data-render="vm_forget"'
    assert f'{loader} data-forget-scope="slot"' in _dialog(page, "remove-slot")
    assert f'{loader} data-forget-scope="all"' in _dialog(page, "delete-env")
    dep = await _failed_env_job(env, "remove_slot", "machine", vm_step="machine")
    retry = _dialog((await c["maintainer"].get(f"/deployments/{dep}")).text, "retry-env-job")
    assert f'{loader} data-forget-scope="slot" data-forget-slot="green"' in retry
    dep = await _failed_env_job(env, "teardown", "check")
    retry = _dialog((await c["maintainer"].get(f"/deployments/{dep}")).text, "retry-env-job")
    assert f'{loader} data-forget-scope="all"' in retry and "data-forget-vms" in retry


# -------------------------------------------------------------------------------- K6: the dry runs


async def test_k6_add_slot_check_answers_the_slot_and_cost_and_writes_nothing(w):  # noqa: F811
    env = await dof.make_do_env(name="one", account_id=w.account_id, slots=("blue",))
    url = f"{API}/{env.env_id}/slots"
    before = (await _count(Instance), await _count(Host), await _count(AuditEvent), await _cloud(env.env_id))
    resp = await w.admin.post(url, params={"check": "true"}, json={})
    w.locked[0] = False
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["ok"] is True
    assert out["plan"] == {"slot": "green", "host_id": None, "host": "slipway-one-green", "planned": "digitalocean"}
    assert out["cost"]["total"] == TWO and out["cost"]["total_cents"] == 4400
    assert out["cost"]["delta"] == do_rules.delta_text(int(before[3]["cost"]["total_cents"]), 4400)
    assert (await _count(Instance), await _count(Host), await _count(AuditEvent), await _cloud(env.env_id)) == before
    # Every refusal still runs: the permission, a host given, the account's limit.
    resp = await w.c["developer"].post(url, params={"check": "true"}, json={})
    assert resp.status_code == 403
    resp = await w.admin.post(url, params={"check": "true"}, json={"host_id": str(uuid.uuid4())})
    assert (resp.status_code, resp.json()["field"]) == (422, "host_id")
    await set_account(w, monthly_limit_cents=1000)
    resp = await w.admin.post(url, params={"check": "true"}, json={})
    w.locked[0] = False
    assert (resp.status_code, resp.json()["field"]) == (409, "confirm_cost")
    assert "over its limit of $10.00" in resp.json()["detail"]
    await set_account(w, monthly_limit_cents=None)
    # The figure the check answered is the one the add takes.
    resp = await w.admin.post(url, json={"confirm_cost": out["cost"]["total"]})
    w.locked[0] = False
    assert resp.status_code == 201, resp.text


async def test_k6_grow_check_answers_the_sizes_and_cost_and_writes_nothing(w, make_client):  # noqa: F811
    env = await dof.make_do_env(name="grow", account_id=w.account_id, slots=("blue",))
    url = f"{API}/{env.env_id}"
    grow = {"cloud": {"droplet_size": "s-1vcpu-2gb"}}
    plain = await client_with(make_client, "plain@example.com", ["environments:write", "environments:read"])
    before = (await _cloud(env.env_id), await _count(AuditEvent))
    resp = await w.admin.patch(url, params={"check": "true"}, json=grow)
    w.locked[0] = False
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["ok"] is True and out["plan"]["from"]["droplet_size"] == "s-1vcpu-1gb"
    assert out["plan"]["to"]["droplet_size"] == "s-1vcpu-2gb"
    assert out["cost"]["delta"] == do_rules.delta_text(int(before[0]["cost"]["total_cents"]),
                                                       out["cost"]["total_cents"])
    assert (await _cloud(env.env_id), await _count(AuditEvent)) == before
    # A check is for a grow only, and runs the grow's refusals.
    resp = await w.admin.patch(url, params={"check": "true"}, json={**grow, "auto_activate": False})
    assert (resp.status_code, resp.json()["field"]) == (422, "auto_activate")
    resp = await w.admin.patch(url, params={"check": "true"}, json={"keep_backups": 3})
    assert (resp.status_code, resp.json()["field"]) == (422, "keep_backups")
    resp = await w.admin.patch(url, params={"check": "true"}, json={"cloud": {"droplet_size": "s-1vcpu-512mb-10gb"}})
    w.locked[0] = False
    assert (resp.status_code, resp.json()["field"]) == (409, "cloud.droplet_size")
    resp = await plain.patch(url, params={"check": "true"}, json=grow)
    assert (resp.status_code, resp.json()["field"]) == (403, "cloud")
    assert (await _cloud(env.env_id), await _count(AuditEvent)) == before
    # The figure the check answered is the one the grow takes.
    resp = await w.admin.patch(url, json={**grow, "confirm_cost": out["cost"]["total"]})
    w.locked[0] = False
    assert resp.status_code == 200, resp.text
    assert len(await _audits("environment.resize")) == 1


@pytest.fixture
async def vm_world(make_client, monkeypatch) -> dict[str, Any]:
    from slipway.models import AppSetting, Repository
    from slipway.services import switchyard

    roles = await clients(make_client)
    net_ = vf.quiet_network(monkeypatch)
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=4343, full_name="acme/demo", owner="acme", name="demo",
                          html_url="https://github.com/acme/demo", detected_config={})
        db.add(repo)
        db.add(AppSetting(key=switchyard.SETTING_KEY, value={"url": "https://sy.example.test",
                                                             "default_tls_mode": "auto"}, secret="sy_" + "k" * 30))
        await db.commit()
        admin = await db.scalar(select(User).where(User.email == "admin@example.com"))
    monkeypatch.setattr(environments, "github_reader", lambda user: reader(FILES))
    return {"c": roles, "repo_id": repo.id, "user": admin, "pve": await vf.proxmox_account(), "net": net_}


async def test_k6_add_slot_check_on_a_new_vm_plans_it_and_claims_nothing(vm_world):
    from slipway.services.environments import NewEnvironment
    from tests.test_env_machines_create import ADMIN

    v = vm_world
    ctx = Ctx(v["user"])
    request = NewEnvironment(name="prod", repository_id=v["repo_id"], data_mode="server",
                             hosts={"blue": vm(v["pve"]), "data": vm(v["pve"])},
                             settings={"APP_DOMAIN": "prod.example.com"},
                             traffic={"switch": "switchyard", "dns": None}, first_admin=ADMIN)
    async with get_sessionmaker()() as db:
        plan = await environments.validate_create(db, request, ctx, read_file=reader())
        env = await environments.create(db, plan, ctx)
        await db.commit()
        env_id = env.id
    tables = (Instance, Host, Machine, AddressClaim, AuditEvent, Deployment)
    before = [await _count(t) for t in tables]
    machine = {**vm(v["pve"])["machine"], "account_id": str(v["pve"].id)}
    resp = await v["c"]["admin"].post(f"{API}/{env_id}/slots", params={"check": "true"},
                                      json={"machine": machine, "update_data_server": True})
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["cost"] is None and out["plan"]["slot"] == "green" and out["plan"]["planned"] == "proxmox"
    assert out["plan"]["machine"]["address"] == "10.0.0.102" and out["plan"]["machine"]["network"] == "lan"
    assert [await _count(t) for t in tables] == before
    # The data server's update needs deployments:create, checked first, as the add does.
    resp = await v["c"]["developer"].post(f"{API}/{env_id}/slots", params={"check": "true"},
                                          json={"machine": machine, "update_data_server": True})
    assert resp.status_code == 403
    # The add itself then takes the address the check planned.
    resp = await v["c"]["admin"].post(f"{API}/{env_id}/slots", json={"machine": machine})
    assert resp.status_code == 201, resp.text
    async with get_sessionmaker()() as db:
        assert await db.get(AddressClaim, "10.0.0.102") is not None


async def test_k6_the_grow_dialog_prices_through_the_check(w, tmp_path):  # noqa: F811
    env = await dof.make_do_env(name="shop", account_id=w.account_id, slots=("blue",))
    page = (await w.admin.get(f"/environments/{env.env_id}")).text
    catalog = (await w.admin.get(f"/api/v1/provider-accounts/{w.account_id}/catalog?region=nyc3")).json()
    priced = (await w.admin.patch(f"{API}/{env.env_id}?check=true",
                                  json={"cloud": {"droplet_size": "s-2vcpu-2gb"}})).json()
    w.locked[0] = False
    result = run_js(tmp_path, scenario(page, ["grow-env", "add-slot"], """
var dlg = document.getElementById("grow-env"), form = dlg.querySelector("form");
answers["GET /api/v1/provider-accounts/%(account)s/catalog?region=nyc3"] = [{ status: 200, body: %(catalog)s }];
answers["PATCH /api/v1/environments/%(env)s?check=true"] = [{ status: 200, body: %(priced)s }];
var opener = h("button", { "data-open": "grow-env" }); document.body.appendChild(opener);
await click(opener);
field(form, "cloud.droplet_size").value = "s-2vcpu-2gb";
await click(form.querySelector("[data-cost-price]"));
var out = { calls: fetchCalls.slice(), figure: form.querySelector("[data-cost-figure]").textContent,
            text: form.querySelector("[data-cost-text]").textContent };
// A refusal of the check is shown in the dialog, and nothing is asked to be typed.
answers["PATCH /api/v1/environments/%(env)s?check=true"] = [{ status: 409, body: { detail: "s-1vcpu-512mb-10gb is smaller", field: "cloud.droplet_size" } }];
field(form, "cloud.droplet_size").value = "s-1vcpu-512mb-10gb"; user("change", field(form, "cloud.droplet_size")); await settle();
await click(form.querySelector("[data-cost-price]"));
out.refused = [form.querySelector("[data-cost-box]").hidden, form.querySelector('[type="submit"]').disabled];
// Add a slot prices itself when it opens, through its own check.
var add = document.getElementById("add-slot"), addForm = add.querySelector("form");
answers["POST /api/v1/environments/%(env)s/slots?check=true"] = [{ status: 200, body: { ok: true, plan: { slot: "green" }, cost: { total: "44.00", total_cents: 4400, delta: "+$17.00 a month" } } }];
var addOpener = h("button", { "data-open": "add-slot" }); document.body.appendChild(addOpener);
await click(addOpener);
out.add = [addForm.querySelector("[data-cost-box]").hidden, addForm.querySelector("[data-cost-text]").textContent];
out.allCalls = fetchCalls;
done(out);
""" % {"account": w.account_id, "catalog": json.dumps(catalog), "env": env.env_id, "priced": json.dumps(priced)}))
    assert f"PATCH /api/v1/environments/{env.env_id}?check=true" in result["calls"]
    assert f"PATCH /api/v1/environments/{env.env_id}" not in result["allCalls"]  # pricing never changes anything
    assert result["figure"] == priced["cost"]["total"]
    assert result["text"] == f"The new estimate is about ${priced['cost']['total']} a month ({priced['cost']['delta']})."
    assert result["refused"] == [True, True]
    assert result["add"] == [False, "The new estimate is about $44.00 a month (+$17.00 a month)."]
    assert f"POST /api/v1/environments/{env.env_id}/slots" not in result["allCalls"]


# ----------------------------------------------- the flow's same-host warning (browser check after review 45)


async def test_same_host_warning_shows_only_for_two_slots_on_one_host(w, tmp_path):  # noqa: F811
    """The Hosts step's "Blue and Green are on the same host" callout follows the same-host check alone. Its
    data-show-when (where=hosts) sits on a wrapper: on the callout itself it un-hid the warning on every change,
    so a single slot, or two slots on different hosts, were warned too."""
    repo = await _repo()
    async with get_sessionmaker()() as db:
        one = Host(name="lan-01", hostname="10.0.0.5", username="deploy", host_key="ssh-ed25519 AAAAone")
        two = Host(name="lan-02", hostname="10.0.0.6", username="deploy", host_key="ssh-ed25519 AAAAtwo")
        db.add_all([one, two])
        await db.commit()
        ids = {"one": str(one.id), "two": str(two.id)}
    page = (await w.c["maintainer"].get("/environments/new")).text
    manifest = {"name": "shop", "settings": [], "services": [], "secrets": [], "first_admin": None,
                "capabilities": ["backup", "restore", "bluegreen", "expand_contract"]}
    body = """
var form = document.getElementById("env-flow");
answers["GET /api/v1/repositories/%(repo)s/branches"] = [{ status: 200, body: ["main"] }];
answers["GET /api/v1/repositories/%(repo)s/manifest?branch=main&path=slipway.yml"] = [{ status: 200, body: { manifest: %(manifest)s } }];
var branch = field(form, "branch");
branch.value = "main"; user("change", branch); await settle();
var same = form.querySelector("[data-same-host]");
function shown() { return !same.hidden && !same.closest("[hidden]"); }
var blue = field(form, "hosts.blue"), green = field(form, "hosts.green");
var out = {};
blue.value = "%(one)s"; user("change", blue); await settle();
out.single = shown();
var bg = form.querySelector('[name="shape"][value="bluegreen"]');
bg.checked = true; form.querySelector('[name="shape"][value="single"]').checked = false;
user("change", bg); await settle();
green.value = "%(two)s"; user("change", green); await settle();
out.different = shown();
green.value = "%(one)s"; user("change", green); await settle();
out.same = shown();
done(out);
""" % {"repo": repo, "manifest": json.dumps(manifest), **ids}
    result = run_js(tmp_path, scenario(page, ["env-flow"], body))
    assert result == {"single": False, "different": False, "same": True}
