"""The environment pages for VMs (S24b; phase 5 §12.2-12.6).

Phase 5 test 62's remainder: the create flow's VM sub-form and its Review; the Slots card's VM host cell (chips,
sizes, address, pending resize, last error), its power and its Lost, Hidden and Off chips from the live read; Resize
and Forget the VM; the VM snapshots card and its dialogs (Take, Revert with the typed name, the ZFS wording, Delete,
the ``none`` card); the Delete dialog's VM lines, its data tick and forget_vms; Remove slot with forget_vms; the
Deploy dialog's VM sentences; Add a slot on a new VM; the retry's forget_vms box. Test 63's remainder: the VM
sub-form's checks and the addresses call, the account and network lock-step, ``FIELD_STEP`` for the machine fields
and ``renderers.vm_snapshots`` (and the Slots card's ``renderers.vm_live``). The Integrations cards, the account
dialog, the trust re-submit and the hosts pages are S21's (tests/test_accounts_web.py).

Pages are rendered as each role sees them; the JS runs the real slipway.js under the fake DOM of
tests/test_review_web.py, fed the answers of the real routes (FakeProxmox behind them). Jobs a route queues are
recorded, never run.
"""

from __future__ import annotations

import html
import json
import re
import uuid
from typing import Any

import pytest
from sqlalchemy import select, update

from slipway.db.base import utcnow
from slipway.db.session import get_sessionmaker
from slipway.models import Deployment, Environment, Host, Instance, Machine, ProviderAccount, Repository, User
from slipway.web import pages
from tests import vm_fixtures as vf
from tests.test_accounts_web import scenario
from tests.test_data_api import client_with, clients
from tests.test_env_machines import all_ready, pve_env, ready
from tests.test_provider_proxmox import World, a_world, net, world  # noqa: F401  (fixtures)
from tests.test_review_web import run_js
from tests.test_vm_jobs import add_row, pve_ready, snap_name

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")


@pytest.fixture(autouse=True)
def submitted(monkeypatch) -> list[uuid.UUID]:
    from slipway.services import deployer

    found: list[uuid.UUID] = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, keys: found.append(dep_id))
    return found


@pytest.fixture
async def c(make_client) -> dict[str, Any]:
    return await clients(make_client)


# ------------------------------------------------------------------------------------ helpers


async def _set(model: Any, row_id: Any, **values: Any) -> None:
    async with get_sessionmaker()() as db:
        await db.execute(update(model).where(model.id == row_id).values(**values))
        await db.commit()


async def _live(env: vf.VmEnv, slot: str = "blue") -> None:
    """The environment live with ``slot`` active (a release recorded on it)."""
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, env.instances[slot])
        inst.status, inst.current_commit_sha = "running", "0123456789abcdef0123456789abcdef01234567"
        manifest = {"capabilities": ["backup", "restore", "reset", "bluegreen", "server"]}
        inst.app_state = {"live": {"sha": inst.current_commit_sha, "release": "r1"}, "manifest": manifest}
        if "data" in env.instances:  # the data owner runs a release too (its dump command)
            owner = await db.get(Instance, env.instances["data"])
            owner.status, owner.current_commit_sha = "running", inst.current_commit_sha
            owner.app_state = {"live": {"sha": inst.current_commit_sha, "release": "r1"}, "manifest": manifest}
        await db.execute(update(Environment).where(Environment.id == env.env_id)
                         .values(status="live", active_slot_id=inst.id))
        await db.commit()


def _between(page: str, start: str, end: str = "</section>") -> str:
    part = page[page.index(start):]
    return part[:part.index(end)]


def _dialog(page: str, dialog_id: str) -> str:
    return _between(page, f'id="{dialog_id}"', "</dialog>")


def _text(fragment: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", fragment))).strip()


def _row(page: str, slot: str) -> str:
    return _between(page, f'data-slot-row="{slot}"', "</tr>")


# --------------------------------------------------------------- 62: the Slots card's VM cells


async def test_62_slots_card_vm_cells_chips_sizes_pending_and_last_error(c, world):
    env = await pve_env(world)
    await ready(world, env, "blue")
    await ready(world, env, "data")
    await _live(env, "blue")
    async with get_sessionmaker()() as db:
        green = await db.get(Machine, env.machines["green"])
        green.last_error = "Slipway restarted while preparing slipway-uat-green"
        blue = await db.get(Machine, env.machines["blue"])
        blue.size = {"cores": 8, "memory_mb": 16384, "disk_gb": 128}
        data = await db.get(Machine, env.machines["data"])
        data.size = {"cores": 8, "memory_mb": 16384, "disk_gb": 128}  # the data VM keeps its size: no phrase
        await db.commit()
    page = (await c["maintainer"].get(f"/environments/{env.env_id}")).text
    blue_row, green_row, data_row = _row(page, "blue"), _row(page, "green"), _row(page, "data")
    assert "slipway-uat-blue on lab · 4 vCPU · 8 GB · 64 GB" in blue_row  # what it has (applied)
    assert "Proxmox VM" in blue_row and ">Ready<" in blue_row and "10.0.0.100" in blue_row
    assert 'data-vm-live="blue"' in blue_row and 'data-vm-chip="blue"' in blue_row
    assert "Resize pending: applies at blue&#39;s next deploy when blue is idle" in blue_row
    assert ">Not built yet<" in green_row and "Slipway restarted while preparing slipway-uat-green" in green_row
    assert "Resize pending" not in data_row
    # Resize for every VM but the ready data server's; Forget only for app slots, hidden until the live read.
    assert 'data-open="resize-vm-blue"' in blue_row and 'data-open="resize-vm-green"' in green_row
    assert "resize-vm-data" not in data_row
    assert 'id="vm-live" data-load="/api/v1/environments/' in page
    assert 'data-render="vm_live"' in page
    # Forget the VM: not for blue (it takes the traffic), nor green (its VM isn't made yet).
    assert "data-forget-slot" not in page
    # The Remove buttons tell the dialog it is a VM, on which account, and whether forget_vms is offered.
    fill = json.loads(html.unescape(re.search(r'data-remove-slot="green" data-fill=\'([^\']*)\'', green_row).group(1)))
    assert fill["vm"] is True and fill["ssh"] is False and fill["account"] == "lab" and fill["forgettable"] is False
    # A developer reads the same cells without the buttons.
    dev = (await c["developer"].get(f"/environments/{env.env_id}")).text
    assert "slipway-uat-blue on lab" in dev and "resize-vm-" not in dev and "data-forget-slot" not in dev


async def test_62_resize_dialog_and_its_waiting_sentence(c, world):
    env = await pve_env(world)
    await all_ready(world, env)
    await _live(env, "blue")
    page = (await c["maintainer"].get(f"/environments/{env.env_id}")).text
    blue = _dialog(page, "resize-vm-blue")
    assert 'data-form="PATCH /api/v1/environments/' in blue and "/machines/blue" in blue
    assert 'name="memory_mb"' in blue and 'data-scale="1024"' in blue and 'value="8.0"' in blue
    assert re.search(r'name="disk_gb"[^>]*min="64"', blue)
    assert "Applies at blue's next deploy, after its backup: Slipway shuts slipway-uat-blue down, resizes it and " \
           "starts it again." in _text(blue)
    assert "Blue takes the traffic now, so this waits until you deploy to it after activating the other slot." \
        in _text(blue)
    green = _dialog(page, "resize-vm-green")
    assert "takes the traffic now" not in green
    assert 'id="resize-vm-data"' not in page  # a ready data server keeps its size


# ------------------------------------------------ 62/63: the live read (power, Lost, Hidden, Off, Forget)

CAPTURE = """
var captured = {};
function capture(sel, key) {
  document.querySelectorAll(sel).forEach(function (el) {
    var name = key + "-" + el.getAttribute(sel.slice(1, -1));
    Object.defineProperty(el, "innerHTML", { get: function () { return captured[name] || ""; },
                                             set: function (v) { captured[name] = v; } });
  });
}
capture("[data-vm-live]", "live"); capture("[data-vm-chip]", "chip");
await settle();
"""


def _stopped(w: World, vmid: int) -> None:
    with w.fake.edit() as state:
        state["vms"][str(vmid)]["status"] = "stopped"


async def test_62_63_live_read_gives_power_lost_off_and_offers_forget(c, world, tmp_path):
    env = await pve_env(world)
    ids = await all_ready(world, env)
    await _live(env, "blue")
    world.fake.run_task(ids["blue"], "vzdump", polls=None)
    world.fake.remove_vm(ids["green"])  # deleted by hand: lost
    _stopped(world, ids["data"])  # left off after a resize
    async with get_sessionmaker()() as db:
        (await db.get(Machine, env.machines["data"])).last_error = "slipway-uat-data was left off during a resize"
        await db.commit()
    page = (await c["maintainer"].get(f"/environments/{env.env_id}")).text
    assert 'data-forget-slot="green"' in page  # offered by the records, shown only once the read finds it lost
    answer = (await c["maintainer"].get(f"/api/v1/environments/{env.env_id}/machines")).json()
    result = run_js(tmp_path, scenario(page, ["slots-card", "delete-env", "remove-slot"], CAPTURE + """
var data = %s;
window.slipway.renderers.vm_live(document.getElementById("vm-live"), data);
var forget = document.querySelector('[data-forget-slot="green"]');
done({ captured: captured, forgetHidden: forget.hidden,
       dataError: document.querySelector('[data-vm-error="data"]').hidden,
       removeFill: JSON.parse(document.querySelector('[data-remove-slot="green"]').dataset.fill),
       forgetVms: document.querySelector("[data-forget-vms]").hidden });
""" % json.dumps(answer)))
    got = result["captured"]
    assert "Busy: vzdump" in got["live-blue"]
    assert ">Lost<" in got["chip-green"] and "Gone" in got["live-green"]
    assert ">Off<" in got["chip-data"] and "Off" in got["live-data"]
    assert "chip-blue" not in got  # blue keeps the stored Ready chip
    assert result["forgetHidden"] is False and result["dataError"] is False
    # A VM gone from the hypervisor is no Remove blocker ("already gone"); nothing forget_vms is needed for.
    assert result["removeFill"]["forgettable"] is False and result["forgetVms"] is True


async def test_62_63_hidden_vm_and_account_down_offer_forget_vms(c, world, tmp_path, monkeypatch):
    env = await pve_env(world)
    ids = await all_ready(world, env)
    await _live(env, "blue")
    world.fake.remove_vm(ids["green"])
    world.fake.hidden(ids["green"])
    page = (await c["admin"].get(f"/environments/{env.env_id}")).text
    answer = (await c["admin"].get(f"/api/v1/environments/{env.env_id}/machines")).json()
    script = CAPTURE + """
window.slipway.renderers.vm_live(document.getElementById("vm-live"), %s);
done({ captured: captured, forget: (document.querySelector('[data-forget-slot="green"]') || { hidden: "none" }).hidden,
       fill: JSON.parse(document.querySelector('[data-remove-slot="green"]').dataset.fill),
       forgetVms: document.querySelector("[data-forget-vms]").hidden });
"""
    result = run_js(tmp_path, scenario(page, ["slots-card", "delete-env"], script % json.dumps(answer)))
    assert ">Hidden<" in result["captured"]["chip-green"] and "Can&#39;t be seen" in result["captured"]["live-green"]
    assert result["forget"] is True  # hidden isn't lost: Forget stays hidden
    # The power read guesses nothing about forget_vms (K4): the dialogs read the blockers when they open.
    assert result["fill"]["forgettable"] is False and result["forgetVms"] is True
    # Opening Remove slot and Delete reads ?blockers=true, as the jobs' check reads them: a hidden VM is a
    # forgettable blocker, so forget_vms is offered and the blocker named.
    url = f"/api/v1/environments/{env.env_id}/machines?blockers=true"
    blocked = (await c["admin"].get(url)).json()
    green = next(m for m in blocked if m["slot"] == "green")
    assert green["forgettable"] is True and green["blockers"][0]["forgettable"] is True
    dialogs = """
answers["GET %(url)s"] = [{ status: 200, body: %(blocked)s }];
await click(document.querySelector('[data-remove-slot="green"]'));
var remove = document.getElementById("remove-slot");
var out = { removeBox: remove.querySelector("[data-remove-forget]").hidden,
            removeText: remove.querySelector('[data-render="vm_forget"]').textContent };
var opener = h("button", { "data-open": "delete-env" }); document.body.appendChild(opener);
await click(opener);
var del = document.getElementById("delete-env");
out.deleteBox = del.querySelector("[data-forget-vms]").hidden;
out.calls = fetchCalls;
done(out);
"""
    result = run_js(tmp_path, scenario(page, ["slots-card", "delete-env", "remove-slot"], dialogs % {
        "url": url, "blocked": json.dumps(blocked)}))
    assert result["removeBox"] is False and result["deleteBox"] is False
    assert result["removeText"].startswith("Slipway can't see VM ")
    assert result["calls"].count(f"GET {url}") == 2
    # The account can't be reached: every VM's blocker is forgettable, and forget_vms is offered.
    from tests.test_env_machines import unreachable

    unreachable(monkeypatch)
    answer = (await c["admin"].get(f"/api/v1/environments/{env.env_id}/machines")).json()
    result = run_js(tmp_path, scenario(page, ["slots-card", "delete-env"], script % json.dumps(answer)))
    assert "Couldn&#39;t check" in result["captured"]["live-blue"]
    assert "Slipway can&#39;t read slipway-uat-blue on lab now" in result["captured"]["live-blue"]
    blocked = (await c["admin"].get(url)).json()
    assert all(m["forgettable"] is True for m in blocked)
    result = run_js(tmp_path, scenario(page, ["slots-card", "delete-env", "remove-slot"], dialogs % {
        "url": url, "blocked": json.dumps(blocked)}))
    assert result["removeBox"] is False and result["deleteBox"] is False


def test_63_vm_live_view_rules(tmp_path):
    result = run_js(tmp_path, """
var v = window.slipway.vmLiveView;
done({
  planned: v({ slot: "green", stage: "planned", live: null }),
  running: v({ slot: "blue", stage: "ready", live: { exists: true, ours: true, power: "running" } }),
  moved: v({ slot: "blue", stage: "ready", live: { exists: true, ours: false, why_not_ours: "VM 100 isn't slipway-uat-blue any more", power: "running" } }),
  busy: v({ slot: "blue", stage: "ready", live: { error: "busy", detail: "esx-01 is busy with other work; try again in a minute" } }),
  read: v({ slot: "blue", stage: "ready", forgettable: true, live: { exists: true, ours: false, power: "running" } }),
  creating: v({ slot: "blue", stage: "creating", live: { exists: true, ours: true, power: "stopped" } }),
});
""")
    assert result["planned"]["text"] == "" and result["planned"]["chip"] is None
    assert result["running"] == {"chip": None, "text": "Running", "title": "", "lost": False, "off": False,
                                 "forgettable": False}
    assert result["moved"]["chip"] == "lost" and result["moved"]["lost"] is False
    # forgettable is the answer's own flag (?blockers=true), never guessed from the power read (K4).
    assert result["moved"]["forgettable"] is False and result["moved"]["text"] == "Not Slipway's"
    assert result["read"]["forgettable"] is True
    assert result["busy"]["text"] == "Busy: the account" and result["busy"]["forgettable"] is False
    assert result["busy"]["title"] == "esx-01 is busy with other work; try again in a minute"
    # A VM still being made isn't called Off: the chip says Building.
    assert result["creating"]["chip"] is None and result["creating"]["text"] == "Off"


# ------------------------------------------------------------------- 62/63: the VM snapshots card

LEDE = ("A VM snapshot is the whole VM's disk at one moment: the app, its data and the system. Reverting loses "
        "everything written since, backups on the VM included. Backups (above) are the way to restore only the data.")


async def _backup(instance_id: uuid.UUID, name: str, minutes_ago: int) -> None:
    from tests.test_env_machines_api import backup

    await backup(instance_id, name, minutes_ago)


async def test_62_vm_snapshots_card_and_its_dialogs(c, world, tmp_path):
    env = await pve_ready(world)
    page = (await c["maintainer"].get(f"/environments/{env.env_id}")).text
    card = _between(page, 'id="vm-snapshots-card"')
    assert LEDE in _text(card)
    assert f'data-load="/api/v1/environments/{env.env_id}/vm-snapshots" data-render="vm_snapshots"' in card
    assert "data-can-act" in card and 'data-account="lab"' in card
    take = re.search(r'<button[^>]*data-open="vm-snapshot-take"[^>]*>', card).group(0)
    assert "disabled" not in take
    taking = _text(_dialog(page, "vm-snapshot-take"))
    assert "Slipway keeps the newest 3 it takes by itself, and those you take until you delete them." in taking
    revert = _dialog(page, "vm-revert")
    assert 'name="confirm" data-must-equal="uat"' in revert and 'name="skip_pre_revert"' in revert
    assert "Slipway first takes a VM snapshot of slipway-uat-blue as it is now, so you can revert this too." \
        in _text(revert)
    assert "ZFS" not in revert
    drop = _dialog(page, "vm-drop")
    assert "Deletes" in drop and "from lab. It can't be undone." in _text(drop)
    # The forms post through slipway.js, and the delete button isn't left disabled (it asks for no name).
    for dialog in (revert, drop, _dialog(page, "vm-snapshot-take")):
        assert 'action="/js-required"' in dialog and 'data-form="' in dialog
    assert re.search(r'<button class="btn btn-danger solid" type="submit">Delete</button>', drop)
    # A developer sees the card and the rows (data-load), not the buttons or dialogs.
    dev = (await c["developer"].get(f"/environments/{env.env_id}")).text
    assert 'id="vm-snapshots-card"' in dev and "data-can-act" not in dev and 'id="vm-revert"' not in dev

    # The rows, from the real GET (one kept on Proxmox, one gone, backups taken since).
    old = await add_row(env, snap_name(180), minutes_ago=180, world=world, commit_sha="abcdef1234567890")
    gone = await add_row(env, snap_name(120), minutes_ago=120, reason="pre_resize")
    await _backup(env.instances["blue"], "b-after", 30)
    answer = (await c["maintainer"].get(f"/api/v1/environments/{env.env_id}/vm-snapshots")).json()
    result = run_js(tmp_path, """
done({ act: window.slipway.vmSnapshotsHtml(%s, { env: "E", account: "lab", canAct: "" }),
       look: window.slipway.vmSnapshotsHtml(%s, { env: "E", account: "lab" }) });
""" % (json.dumps(answer), json.dumps(answer)))
    act = result["act"]
    assert "<th>On lab</th>" in act and "By hand" in act and "Before a resize" in act
    old_row = _between(act, f'data-vm-snapshot="{old.name}"', "</tr>")
    gone_row = _between(act, f'data-vm-snapshot="{gone.name}"', "</tr>")
    assert ">Yes<" in old_row and "abcdef1" in old_row and 'data-open="vm-revert"' in old_row
    fill = json.loads(html.unescape(re.search(r'data-open="vm-revert" data-fill="([^"]*)"', old_row).group(1)))
    assert fill["action"] == f"POST /api/v1/environments/E/vm-snapshots/{old.id}/revert"
    assert fill["snapshot"] == old.name and fill["sha7"] == "abcdef1"
    assert fill["lost"] == "Everything written since is lost, including these backups: b-after."
    assert ">Not there any more<" in gone_row and ">Missing<" in gone_row
    assert 'data-open="vm-revert"' not in gone_row and "disabled" in gone_row
    assert 'data-open="vm-drop"' in old_row and "DELETE /api/v1/environments/E/vm-snapshots/" in html.unescape(old_row)
    assert "<button" not in result["look"] and old.name in result["look"]


async def test_62_vm_snapshots_on_zfs_and_on_storage_without_them(c, tmp_path, monkeypatch, net):  # noqa: F811
    zfs = a_world(tmp_path, monkeypatch, net, storage_type="zfspool")
    env = await pve_ready(zfs, storage_type="zfspool")
    old = await add_row(env, snap_name(60), world=zfs)
    zfs.fake.add_snapshot(100, "by-hand")
    page = (await c["maintainer"].get(f"/environments/{env.env_id}")).text
    revert = _text(_dialog(page, "vm-revert"))
    assert "On ZFS storage this revert can't be undone: Slipway can't keep a VM snapshot of slipway-uat-blue as it " \
           "is now." in revert
    assert "skip_pre_revert" not in _dialog(page, "vm-revert") and "so you can revert this too" not in revert
    answer = (await c["maintainer"].get(f"/api/v1/environments/{env.env_id}/vm-snapshots")).json()
    result = run_js(tmp_path, "done(window.slipway.vmSnapshotsHtml(%s, { env: 'E', account: 'lab', canAct: '' }));"
                    % json.dumps(answer))
    row = _between(result, f'data-vm-snapshot="{old.name}"', "</tr>")
    assert "Proxmox can roll ZFS back only to the newest VM snapshot; by-hand is newer. Delete it first, or revert " \
           "to by-hand" in html.unescape(row)
    assert 'data-open="vm-revert"' not in row

    async with get_sessionmaker()() as db:
        m = await db.get(Machine, env.machines["blue"])
        m.snapshot_mode, m.spec = "none", {**(m.spec or {}), "storage": "local-lvm", "storage_type": "lvm"}
        await db.commit()
    page = (await c["maintainer"].get(f"/environments/{env.env_id}")).text
    card = _between(page, 'id="vm-snapshots-card"')
    assert "local-lvm (lvm) can&#39;t take VM snapshots, so slipway-uat-blue has none. Backups (above) still work." \
        in card
    assert "data-load" not in card and "<button" not in card
    assert 'id="vm-revert"' not in page and 'id="vm-snapshot-take"' not in page
    none = run_js(tmp_path, "done(window.slipway.vmSnapshotsHtml({ snapshot_mode: 'none', snapshots: [] }, "
                            "{ noneText: 'local-lvm (lvm) can\\'t take VM snapshots' }));")
    assert "local-lvm (lvm) can&#39;t take VM snapshots" in none and "<table" not in none


async def test_62_no_snapshot_card_without_the_shape(c, world):
    env = await pve_env(world)  # Blue/Green with a data server: not VM snapshots' shape
    await all_ready(world, env)
    page = (await c["maintainer"].get(f"/environments/{env.env_id}")).text
    assert 'id="vm-snapshots-card"' not in page and 'id="vm-revert"' not in page


# -------------------------------------------------- 62: Delete, Remove slot and Deploy for VMs


async def test_62_delete_dialog_lists_the_vms_and_ticks_the_data(c, world):
    env = await pve_env(world)
    await all_ready(world, env)
    await _live(env, "blue")
    await _backup(env.instances["data"], "b-1", 60)  # it held data
    page = (await c["maintainer"].get(f"/environments/{env.env_id}")).text
    dialog = _dialog(page, "delete-env")
    text = _text(dialog)
    assert "These VMs are destroyed with their disks: slipway-uat-blue, slipway-uat-green, slipway-uat-data." in text
    assert "The VM slipway-uat-data on lab, with its disks and uat's data and backups" in text
    assert "The VM slipway-uat-green on lab, with its disks" in text
    assert "The data volumes and backups on" not in text  # they go with the data VM
    assert 'data-snapshot-state="ticked"' in dialog
    assert re.search(r'name="snapshot_first" data-no-send checked', dialog)
    assert "slipway-uat-data is destroyed with uat. Without a snapshot the data is gone for good." in text
    assert 'name="drop_data" required' in dialog
    # forget_vms is there for when the live read finds a VM Slipway can't remove; hidden until then.
    forget = re.search(r'<div[^>]*data-forget-vms[^>]*>', dialog).group(0)
    assert "hidden" in forget and 'name="forget_vms"' in dialog

    # The account is removed: no read is needed to know the VMs can't be removed, so forget_vms shows.
    await _set(ProviderAccount, env.account_id, removed_at=utcnow())
    dialog = _dialog((await c["maintainer"].get(f"/environments/{env.env_id}")).text, "delete-env")
    assert "hidden" not in re.search(r'<div[^>]*data-forget-vms[^>]*>', dialog).group(0)


async def test_62_delete_dialog_for_a_role_without_machines_write(make_client, world):
    env = await pve_env(world)
    await all_ready(world, env)
    await _set(ProviderAccount, env.account_id, removed_at=utcnow())
    who = await client_with(make_client, "deleter@example.com",
                            ["environments:read", "environments:delete", "hosts:read", "instances:read"])
    dialog = _dialog((await who.get(f"/environments/{env.env_id}")).text, "delete-env")
    assert re.search(r'name="forget_vms" disabled', dialog)
    assert "needs the machines:write and environments:delete permissions" in dialog
    assert re.search(r'name="drop_data" disabled', dialog) or 'data-snapshot-state="unticked"' in dialog


async def test_62_remove_slot_dialog_for_a_vm_offers_forget_vms(c, world):
    env = await pve_env(world)
    await all_ready(world, env)
    await _live(env, "blue")
    page = (await c["maintainer"].get(f"/environments/{env.env_id}")).text
    dialog = _dialog(page, "remove-slot")
    assert 'data-show-if="vm"' in dialog and 'data-show-if="forgettable"' in dialog
    assert "Removes <span data-slot=\"slot\"></span> and its VM" in dialog
    assert 'name="forget_vms"' in dialog and "Forget the VM Slipway can't remove" in _text(dialog)
    assert 'data-form="DELETE /api/v1/environments/' in dialog and 'name="confirm" data-must-equal="uat"' in dialog


async def test_62_a_phase_3_environment_keeps_its_dialogs(c):
    """No VM: the Slots card, Remove slot and Delete render as before (no live read, no VM lines)."""
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=4242, full_name="acme/p3", owner="acme", name="p3",
                          html_url="https://github.com/acme/p3", detected_config={"manifest": True})
        host = Host(name="box-1", hostname="10.0.0.9", username="deploy", host_key="ssh-ed25519 AAAA")
        db.add_all([repo, host])
        await db.flush()
        env = Environment(name="p3", repository=repo, branch="main", data_mode="slot", app_settings={},
                          app_secrets={}, env={}, traffic={"switch": "none", "dns": None}, hostnames=[])
        db.add(env)
        await db.flush()
        db.add(Instance(name="p3 blue", slug="p3-blue", branch="main", host_id=host.id, repository=repo, env={},
                        ports=[], volumes=[], build_source="app", environment_id=env.id, slot="blue"))
        await db.commit()
        env_id = env.id
    page = (await c["maintainer"].get(f"/environments/{env_id}")).text
    assert 'data-render="vm_live"' not in page and "vm-snapshots-card" not in page and "data-vm-" not in page
    assert "These VMs are destroyed" not in page and "data-remove-slot" not in page


async def test_62_deploy_dialog_vm_sentences(c, world):
    env = await pve_env(world)
    await ready(world, env, "blue")
    await ready(world, env, "data")
    await _live(env, "blue")
    page = (await c["maintainer"].get(f"/environments/{env.env_id}")).text
    assert "Slipway makes slipway-uat-green first (several minutes)." in _text(_dialog(page, "deploy-env"))
    # Green made and grown: the resize after the backup; on ESXi with snapshots they'd be named.
    await ready(world, env, "green")
    async with get_sessionmaker()() as db:
        m = await db.get(Machine, env.machines["green"])
        m.size = {"cores": 8, "memory_mb": 16384, "disk_gb": 128}
        m.snapshot_mode = "none"
        m.spec = {**(m.spec or {}), "storage": "local-lvm"}
        await db.commit()
    text = _text(_dialog((await c["maintainer"].get(f"/environments/{env.env_id}")).text, "deploy-env"))
    assert "slipway-uat-green is resized to 8 vCPU, 16 GB, 128 GB after the backup: it shuts down for a minute or " \
           "two." in text
    assert "uat is down meanwhile" not in text  # Blue/Green: blue keeps serving
    assert "No VM snapshot is taken first: local-lvm can't take one." in text


async def test_62_deploy_dialog_single_slot_resize_and_esxi_snapshots(c, world):
    env = await pve_ready(world)
    async with get_sessionmaker()() as db:
        m = await db.get(Machine, env.machines["blue"])
        m.size = {"cores": 4, "memory_mb": 8192, "disk_gb": 96}
        m.provider = "esxi"  # the sentence is the provider's; the account stays the Proxmox fake's
        await db.commit()
    await add_row(env, "slipway-20261101T000000Z", world=world)
    text = _text(_dialog((await c["maintainer"].get(f"/environments/{env.env_id}")).text, "deploy-env"))
    assert "slipway-uat-blue is resized to 4 vCPU, 8 GB, 96 GB after the backup: it shuts down for a minute or two. " \
           "uat is down meanwhile." in text
    assert "ESXi can't keep VM snapshots across a disk grow: slipway-20261101T000000Z is deleted." in text


# ------------------------------------------------------------- 62/63: Add a slot on a new VM


async def _switchyard(env: vf.VmEnv) -> None:
    from tests import fake_switchyard

    await fake_switchyard.configure()
    await _set(Environment, env.env_id, traffic={"switch": "switchyard", "dns": None})


async def test_62_63_add_a_slot_on_a_new_vm(c, world, tmp_path):
    from slipway.schemas import SlotAdd

    env = await pve_env(world, slots=("blue",))
    await all_ready(world, env)
    await _live(env, "blue")
    await _switchyard(env)
    other = await vf.esxi_account(name="esx-01")  # another account: not offered, the VMs share lab
    async with get_sessionmaker()() as db:  # a host added by hand can take the slot too (the first choice)
        db.add(Host(name="box-1", hostname="10.0.0.9", username="deploy", host_key="ssh-ed25519 AAAA"))
        await db.commit()
    page = (await c["maintainer"].get(f"/environments/{env.env_id}")).text
    dialog = _dialog(page, "add-slot")
    assert "data-vm-slot-form" in dialog and f'value="vm:{env.account_id}"' in dialog
    assert "New VM on lab" in dialog and str(other.id) not in dialog
    assert 'data-vm-form="green"' in dialog and 'name="machine.network"' in dialog
    assert "Slipway makes <span class=\"mono\">slipway-<span data-vm-env>uat</span>-green</span>" in dialog
    addresses = (await c["maintainer"].get(
        f"/api/v1/provider-accounts/{env.account_id}/addresses?network=lan&count=10")).json()
    assert addresses["free"]
    result = run_js(tmp_path, scenario(page, ["add-slot"], """
var url = "/api/v1/provider-accounts/%(account)s/addresses?network=lan&count=10";
answers["GET " + url] = [{ status: 200, body: %(addresses)s }];
answers["POST /api/v1/environments/%(env)s/slots"] = [{ status: 201, body: { slot: "green" } }];
var form = document.querySelector("#add-slot form");
var host = field(form, "host_id"), box = form.querySelector('[data-vm-form="green"]');
var out = { hiddenBefore: box.hidden };
host.value = "vm:%(account)s"; user("change", host); await settle();
var pick = box.querySelector('[data-vm="pick"]');
out.shown = !box.hidden; out.pick = pick.value; out.options = pick.querySelectorAll("option").length;
out.taken = box.querySelector("[data-vm-taken]").textContent;
box.querySelector('[data-vm="memory_gb"]').value = "16";
await submit(form);
out.calls = fetchCalls; out.bodies = fetchBodies;
done(out);
""" % {"account": env.account_id, "addresses": json.dumps(addresses), "env": env.env_id}))
    assert result["hiddenBefore"] is True and result["shown"] is True
    assert result["pick"] == addresses["free"][0] and result["options"] == len(addresses["free"])
    assert result["taken"].startswith("In use on lan: 10.0.0.1 (the network's gateway), ")
    assert result["taken"].endswith(", and 3 more")
    assert f"GET /api/v1/provider-accounts/{env.account_id}/addresses?network=lan&count=10" in result["calls"]
    body = result["bodies"][result["calls"].index(f"POST /api/v1/environments/{env.env_id}/slots")]
    assert "host_id" not in body
    assert body["machine"] == {"account_id": str(env.account_id), "network": "lan", "address": addresses["free"][0],
                               "cores": 4, "memory_mb": 16384, "disk_gb": 64}
    assert SlotAdd.model_validate(body).machine.memory_mb == 16384  # the API takes what the dialog sends


# ------------------------------------------------------------------- 62: the retry's forget_vms


async def _failed_env_job(env: vf.VmEnv, kind: str, failed: str, *, vm_step: str = "machines") -> uuid.UUID:
    keys = ["check", "slot", "machine"] if kind == "remove_slot" else \
        ["check", "unroute", "undns", "slots", "data_server", "machines", "forget"]
    if vm_step not in keys:
        keys = [k for k in keys if k not in ("machine", "machines")]
    steps = [{"key": k, "name": k.capitalize(), "status": "failed" if k == failed else
              "succeeded" if keys.index(k) < keys.index(failed) else "pending"} for k in keys]
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=None, environment_id=env.env_id, kind=kind, status="failed", branch="main",
                         steps=steps, options={"slot": "green"} if kind == "remove_slot" else {"confirmed": True},
                         error="Proxmox still has VM 101, but the token can't see it", log="",
                         triggered_by_id=env.user_id, finished_at=utcnow())
        db.add(dep)
        if kind == "teardown":
            await db.execute(update(Environment).where(Environment.id == env.env_id).values(status="deleting"))
        await db.commit()
        return dep.id


async def test_62_retry_offers_forget_vms_beside_forget_traffic(c, world):
    env = await pve_env(world)
    await all_ready(world, env)
    dep = await _failed_env_job(env, "teardown", "check")
    page = (await c["maintainer"].get(f"/deployments/{dep}")).text
    dialog = _dialog(page, "retry-env-job")
    assert 'name="forget_vms"' in dialog and "Forget the VMs Slipway can't remove" in _text(dialog)
    assert "(you remove them by hand)" in _text(dialog) and 'name="confirm" data-must-equal="uat"' in dialog
    assert 'data-open="retry-env-job"' in page
    # A failure after the VMs went (forget) isn't a VM blocker: no box.
    other = await _failed_env_job(env, "teardown", "forget")
    assert 'name="forget_vms"' not in (await c["maintainer"].get(f"/deployments/{other}")).text


async def test_62_retry_of_remove_slot_and_the_permission(c, world, make_client):
    env = await pve_env(world)
    await all_ready(world, env)
    await _live(env, "blue")
    dep = await _failed_env_job(env, "remove_slot", "machine", vm_step="machine")
    page = (await c["maintainer"].get(f"/deployments/{dep}")).text
    assert 'name="forget_vms"' in _dialog(page, "retry-env-job")
    # A role that may retry the job but not forget VMs sees the box off, with the reason.
    who = await client_with(make_client, "remover@example.com",
                            ["environments:read", "environments:delete", "deployments:read", "deployments:create"])
    dialog = _dialog((await who.get(f"/deployments/{dep}")).text, "retry-env-job")
    assert re.search(r'name="forget_vms" disabled', dialog)
    assert "needs the machines:write and environments:delete permissions" in dialog


def test_62_offers_forget_vms_rule():
    def dep(kind: str, status: str, steps: list[tuple[str, str]]) -> Deployment:
        return Deployment(kind=kind, status=status, steps=[{"key": k, "status": s} for k, s in steps])

    on = {"offers_forget_vms": True}
    assert pages.offers_forget_vms(dep("teardown", "failed", [("check", "failed"), ("machines", "pending")]), on)
    assert pages.offers_forget_vms(dep("remove_slot", "failed", [("check", "succeeded"), ("slot", "succeeded"),
                                                                ("machine", "failed")]), on)
    # No VM step: an environment without VMs. A failure elsewhere, or a job that succeeded: no box.
    assert not pages.offers_forget_vms(dep("teardown", "failed", [("check", "failed"), ("forget", "pending")]), on)
    assert not pages.offers_forget_vms(dep("teardown", "failed", [("machines", "succeeded"),
                                                                 ("forget", "failed")]), on)
    assert not pages.offers_forget_vms(dep("teardown", "succeeded", [("machines", "succeeded")]), on)
    assert not pages.offers_forget_vms(dep("teardown", "failed", [("check", "failed"), ("machines", "pending")]),
                                       {"offers_forget_vms": False})


# ------------------------------------------------------------- 62: the create flow's VM sub-form

DMZ = {"name": "dmz", "bridge": "vmbr1", "vlan_tag": 20, "subnet": "10.0.1.0/24", "gateway": "10.0.1.1",
       "dns_servers": [], "pool": {"first": "10.0.1.100", "last": "10.0.1.150"}}


async def _flow_world() -> dict[str, Any]:
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=777, full_name="acme/shop", owner="acme", name="shop",
                          html_url="https://github.com/acme/shop", detected_config={"manifest": True})
        db.add(repo)
        await db.commit()
    pve = await vf.proxmox_account(networks=[vf.LAN_PVE, DMZ])
    esx = await vf.esxi_account()
    untrusted = await vf.esxi_account(name="esx-new", pem=None)
    return {"repo": repo.id, "pve": pve, "esx": esx, "untrusted": untrusted}


async def test_62_flow_offers_new_vms_per_account_and_role(c, make_client):
    w = await _flow_world()
    page = (await c["maintainer"].get("/environments/new")).text
    assert "No hosts yet" not in page  # VM accounts are enough to start
    blue = _between(page, 'id="env-host-blue"', "</select>")
    assert f'<option value="vm:{w["pve"].id}" data-vm-account="{w["pve"].id}" data-provider="proxmox" ' \
           'data-label="New VM on lab" >New VM on lab</option>' in blue
    assert f'value="vm:{w["esx"].id}"' in blue and "New VM on esx-01" in blue
    assert "New VM on esx-new: Trust esx-new&#39;s certificate in Settings → Integrations first" in blue
    assert re.search(rf'value="vm:{w["untrusted"].id}"[^>]*data-vm-off disabled', blue)
    form = _between(page, 'data-vm-form="blue"', "</p>\n</div>")
    assert 'name="hosts.blue.machine.network"' in form and 'data-account="%s"' % w["pve"].id in form
    assert ">dmz (10.0.1.0/24)<" in form and 'name="hosts.blue.machine.address_from" value="pool" checked' in form
    assert 'name="hosts.blue.machine.cores" type="number" min="1" max="64" value="4"' in form
    assert "Memory (GB)" in form and "Disk (GB)" in form
    assert "Slipway makes <span class=\"mono\">slipway-<span data-vm-env>&lt;name&gt;</span>-blue</span> at this " \
           "address when its first deploy starts." in form
    for slot in ("green", "data"):
        assert f'data-vm-form="{slot}"' in page and f'name="hosts.{slot}.machine.network"' in page
    # Without machines:write every New VM option is off, with the reason (providers:read lists the accounts).
    writer = await client_with(make_client, "writer@example.com", ["environments:read", "environments:write",
                                                                   "hosts:read", "providers:read"])
    other = (await writer.get("/environments/new")).text
    assert "New VM on lab: Making VMs needs the machines:write permission" in other
    assert "Making VMs needs the machines:write permission." in other
    assert not re.search(rf'value="vm:{w["pve"].id}"(?![^>]*disabled)[^>]*>', other)


async def test_63_flow_vm_subform_addresses_lock_step_checks_and_review(c, tmp_path, net):  # noqa: F811
    from slipway.schemas import EnvironmentCreate

    w = await _flow_world()
    pve, esx = str(w["pve"].id), str(w["esx"].id)
    page = (await c["maintainer"].get("/environments/new")).text
    lan = (await c["maintainer"].get(f"/api/v1/provider-accounts/{pve}/addresses?network=lan&count=10")).json()
    dmz = (await c["maintainer"].get(f"/api/v1/provider-accounts/{pve}/addresses?network=dmz&count=10")).json()
    manifest = {"name": "shop", "settings": [], "services": [], "secrets": [], "first_admin": None,
                "capabilities": ["backup", "restore", "bluegreen", "server"]}
    plan = {"hostnames": [], "slots": {},
            "machines": [{"slot": "blue", "name": "slipway-shop-blue", "account": "lab", "network": "lan",
                          "address": lan["free"][0], "size": {"cores": 4, "memory_mb": 8192, "disk_gb": 64}},
                         {"slot": "green", "name": "slipway-shop-green", "account": "lab", "network": "lan",
                          "address": lan["free"][1], "size": {"cores": 2, "memory_mb": 4096, "disk_gb": 40}},
                         {"slot": "data", "name": "slipway-shop-data", "account": "lab", "network": "lan",
                          "address": lan["free"][2], "size": {"cores": 4, "memory_mb": 8192, "disk_gb": 64}}]}
    result = run_js(tmp_path, scenario(page, ["env-flow"], """
location.assign = function (u) { hrefs.push("ASSIGN " + u); };
var form = document.getElementById("env-flow");
var CHECK = "POST /api/v1/environments?check=true";
answers["GET /api/v1/repositories/%(repo)s/branches"] = [{ status: 200, body: ["main"] }];
answers["GET /api/v1/repositories/%(repo)s/manifest?branch=main&path=slipway.yml"] = [{ status: 200, body: { manifest: %(manifest)s } }];
answers["GET /api/v1/provider-accounts/%(pve)s/addresses?network=lan&count=10"] = [{ status: 200, body: %(lan)s }];
answers["GET /api/v1/provider-accounts/%(pve)s/addresses?network=dmz&count=10"] = [{ status: 200, body: %(dmz)s }];
answers[CHECK] = [{ status: 200, body: { ok: true, plan: %(plan)s } }];
var branch = field(form, "branch");
branch.value = "main"; user("change", branch); await settle();
var bg = form.querySelector('[name="shape"][value="bluegreen"]');
bg.checked = true; form.querySelector('[name="shape"][value="single"]').checked = false; user("change", bg); await settle();
field(form, "name").value = "shop"; user("input", field(form, "name")); await settle();
function sel(slot) { return form.querySelector('[data-vm-host="' + slot + '"]'); }
function box(slot) { return form.querySelector('[data-vm-form="' + slot + '"]'); }
function vm(slot, key) { return box(slot).querySelector('[data-vm="' + key + '"]'); }
var out = { mode: field(form, "data_mode").value, hidden: box("blue").hidden };
// Blue on lab, on dmz first: its free addresses are read for dmz, then for lan.
sel("blue").value = "vm:%(pve)s"; user("change", sel("blue")); await settle();
out.blueShown = !box("blue").hidden;
out.blueNetworks = vm("blue", "network").querySelectorAll("option").filter(function (o) { return !o.disabled; }).map(function (o) { return o.value; });
vm("blue", "network").value = "dmz"; user("change", vm("blue", "network")); await settle();
out.dmzPick = vm("blue", "pick").value;
vm("blue", "network").value = "lan"; user("change", vm("blue", "network")); await settle();
// Green and the data server: limited to lab, and to lan; each starts on its own free address.
sel("green").value = "vm:%(pve)s"; user("change", sel("green")); await settle();
sel("data").value = "vm:%(pve)s"; user("change", sel("data")); await settle();
var esxOption = sel("green").querySelector('[value="vm:%(esx)s"]');
out.lock = { esxOff: esxOption.disabled, esxText: esxOption.textContent,
             blueEsx: sel("blue").querySelector('[value="vm:%(esx)s"]').disabled,
             greenNetworks: vm("green", "network").querySelectorAll("option").filter(function (o) { return !o.disabled; }).map(function (o) { return o.value; }) };
out.picks = [vm("blue", "pick").value, vm("green", "pick").value, vm("data", "pick").value];
out.envName = box("green").querySelector("[data-vm-env]").textContent;
vm("green", "cores").value = "2"; vm("green", "memory_gb").value = "4"; vm("green", "disk_gb").value = "40";
var next = form.querySelector("[data-flow-next]");
await click(next); await click(next);
out.at = form._flow.current;
// The step's own checks: a typed address that isn't one, then one given twice.
var typed = box("green").querySelector('[data-vm="from"][value="typed"]');
typed.checked = true; box("green").querySelector('[data-vm="from"][value="pool"]').checked = false; user("change", typed); await settle();
vm("green", "typed").value = "10.0.0.999";
await click(next);
out.bad = [form._flow.current, form.querySelector('[data-step="3"] [data-step-error]').textContent];
vm("green", "typed").value = out.picks[0];
await click(next);
out.twice = form.querySelector('[data-step="3"] [data-step-error]').textContent;
vm("green", "typed").value = out.picks[1];
// Slipway refuses a machine field: the flow stays on step 3 with the text, the field marked.
answers[CHECK] = [{ status: 409, body: { detail: "10.0.0.101 was just taken by another environment: pick another address", field: "hosts.green.machine.address" } },
                  { status: 200, body: { ok: true, plan: %(plan)s } }];
await click(next);
out.refused = [form._flow.current, form.querySelector('[data-step="3"] [data-step-error]').textContent,
               vm("green", "typed").getAttribute("aria-invalid") === "true" || vm("green", "pick").getAttribute("aria-invalid") === "true"];
var dl = form.querySelector("[data-review]"), review = "";
Object.defineProperty(dl, "innerHTML", { get: function () { return review; }, set: function (v) { review = v; } });
await click(next); await click(next); await click(next); await click(next);
out.review = [form._flow.current, review];
out.body = window.slipway.flowBody(form, false, null);
out.fieldStep = ["hosts.green.machine.address", "hosts.blue.machine.network", "hosts.data.machine.size", "hosts.blue.machine"].map(window.slipway.fieldStep);
out.calls = fetchCalls.filter(function (c) { return c.indexOf("addresses") >= 0; });
done(out);
""" % {"repo": w["repo"], "manifest": json.dumps(manifest), "pve": pve, "esx": esx, "lan": json.dumps(lan),
       "dmz": json.dumps(dmz), "plan": json.dumps(plan)}))
    assert result["mode"] == "server" and result["hidden"] is True and result["blueShown"] is True
    assert result["blueNetworks"] == ["lan", "dmz"]
    assert result["dmzPick"] == dmz["free"][0]
    assert result["lock"]["esxOff"] is True and result["lock"]["blueEsx"] is False
    assert result["lock"]["esxText"] == "New VM on esx-01: shop's VMs share one account and one network"
    assert result["lock"]["greenNetworks"] == ["lan"]
    assert result["picks"] == lan["free"][:3]
    assert result["envName"] == "shop" and result["at"] == 3
    assert result["bad"] == [3, "10.0.0.999 isn't an IPv4 address, such as 10.0.0.12"]
    assert result["twice"] == f"{lan['free'][0]} is given to both blue and green: give each VM its own address"
    step, text, marked = result["refused"]
    assert step == 3 and text.startswith("10.0.0.101 was just taken by another environment") and marked
    at, review = result["review"]
    assert at == 7
    assert f"New VM slipway-shop-green on lab, at {lan['free'][1]} on lan, 2 vCPU · 4 GB · 40 GB" in review
    assert f"New VM slipway-shop-data on lab, at {lan['free'][2]} on lan, 4 vCPU · 8 GB · 64 GB" in review
    hosts = result["body"]["hosts"]
    assert hosts["blue"] == {"machine": {"account_id": pve, "network": "lan", "address": lan["free"][0], "cores": 4,
                                         "memory_mb": 8192, "disk_gb": 64}}
    assert hosts["green"]["machine"] == {"account_id": pve, "network": "lan", "address": lan["free"][1], "cores": 2,
                                         "memory_mb": 4096, "disk_gb": 40}
    assert hosts["data"]["machine"]["address"] == lan["free"][2] and result["body"]["data_mode"] == "server"
    assert result["fieldStep"] == [3, 3, 3, 3]
    # Each account and network's free addresses are read once.
    assert sorted(set(result["calls"])) == sorted(result["calls"]) and len(result["calls"]) == 2
    # The API takes the body the flow sends.
    parsed = EnvironmentCreate.model_validate({**result["body"], "repository_id": str(w["repo"])})
    assert parsed.hosts["green"].machine.memory_mb == 4096


async def test_62_a_vm_revert_hold_offers_no_phase_2_restore(c, world):
    from slipway.models import Backup

    env = await pve_ready(world)
    await _live(env, "blue")
    at = utcnow()
    text = ("Slipway restarted while reverting slipway-uat-blue to slipway-20261101T000000Z. The VM's disk may already "
            "be back at slipway-20261101T000000Z while Slipway's records name a later release: revert to "
            "slipway-20261101T000000Z again")
    async with get_sessionmaker()() as db:
        b = Backup(instance_id=env.instances["blue"], name="b-1", reason="manual", status="ready", format="pg-dump-v1",
                   db_bytes=10, db_sha256="0" * 64, identity_fp="0" * 64, taken_at=at, finished_at=at)
        db.add(b)
        await db.flush()
        inst = await db.get(Instance, env.instances["blue"])
        last = {"deployment_id": uuid.uuid4().hex, "kind": "vm_revert", "at": at.isoformat(), "backup_id": str(b.id)}
        inst.data_dirty = {"hold": True, "first": last, "last": last}
        await db.commit()
    from slipway.services.auth import AuthContext

    async def hold_backup() -> Any:
        async with get_sessionmaker()() as db:
            admin = await db.scalar(select(User).where(User.email == "admin@example.com"))
            inst = await db.get(Instance, env.instances["blue"])
            return (await pages.data_view(db, AuthContext(user=admin, via="session"), inst))["hold_backup"]

    assert await hold_backup() is not None  # a phase 2 hold offers the backup taken before it...
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, env.instances["blue"])
        inst.data_dirty = {**inst.data_dirty, "last": {**inst.data_dirty["last"], "text": text}}
        await db.commit()
    page = (await c["maintainer"].get(f"/environments/{env.env_id}")).text
    callout = _between(page, '<div class="callout error" role="alert">', "</div></div></div>")
    assert "revert to slipway-20261101T000000Z again" in _text(callout)
    assert 'data-open="restore-backup"' not in callout and await hold_backup() is None  # ...a VM revert's doesn't
