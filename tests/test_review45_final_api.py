"""Review 45, the final fixer: the API and page problems the checkers found in the fixes, each as the case that
failed before its fix.

- F2, F40: a DigitalOcean environment's PATCH whose traffic object has no ``dns`` still keeps its names inside
  the Cloudflare zone (rule 7).
- F31: the Activate dialog's plan (GET /traffic/plan) doesn't block on a certificate the Activate's own
  certificate step renews, so the page's Activate enables as the API's does.
- F48: with no SSH host and no providers:read, the New environment page still renders the flow with the
  placements' reasons, not "No hosts yet".
- K5: the page of a failed environment job (its Retry) reads no hypervisor.
- K8, F45: the address claim conflict reads asyncpg's ``detail`` attribute, tested on SQLite too.
- F41: a Proxmox URL stored without a port is called, and given to Terraform, on 8006.

The JS runs the real slipway.js under the fake DOM of tests/test_review_web.py. Everything outside Slipway is a
fake; jobs are queued and never run.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy.exc import IntegrityError

from slipway.db.session import get_sessionmaker
from slipway.models import AppSetting, Deployment, Environment, Repository
from slipway.services import cloudflare, do_lb, environments, proxmox, terraform, traffic
from slipway.services.providers import proxmox as pxp
from slipway.web import pages
from tests import do_fixtures as dof
from tests import fake_switchyard
from tests import vm_fixtures as vf
from tests.conftest import make_user
from tests.fake_cloudflare import FakeCloudflare
from tests.test_accounts_web import scenario
from tests.test_data_api import client_with
from tests.test_data_api import storage  # noqa: F401  (autouse)
from tests.test_do_api import API, built, set_rows, submitted, w  # noqa: F401  (fixtures)
from tests.test_env_machines import _set, deployed, pve_env, ready
from tests.test_provider_proxmox import net, world  # noqa: F401  (fixtures)
from tests.test_review45_env_api import _deployed
from tests.test_review45_web_js import PLAN_URL, _activate_page
from tests.test_review_web import run_js

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")


# ------------------------------------------------------------- F2, F40: the zone rule on a traffic without dns


@pytest.mark.parametrize("sent", [None, {}, {"switch": "do_lb"}, {"switch": "do_lb", "dns": {"proxied": False}}])
async def test_f2_a_do_patch_never_stores_names_outside_the_zone(w, sent):  # noqa: F811
    env = await dof.make_do_env(name="zz", account_id=w.account_id)
    async with get_sessionmaker()() as db:
        before = [h["hostname"] for h in (await db.get(Environment, env.env_id)).hostnames or []]
    body: dict = {"settings": {"STACK_DOMAIN": "zz.other.org"}}
    if sent is not None:
        body["traffic"] = sent
    resp = await w.admin.patch(f"{API}/{env.env_id}", json=body)
    assert resp.status_code == 409, resp.text
    assert "isn't in the Cloudflare zone example.com" in resp.json()["detail"]
    async with get_sessionmaker()() as db:
        assert [h["hostname"] for h in (await db.get(Environment, env.env_id)).hostnames or []] == before


async def test_f2_a_do_patch_without_dns_inside_the_zone_still_saves(w):  # noqa: F811
    env = await dof.make_do_env(name="zz", account_id=w.account_id)
    resp = await w.admin.patch(f"{API}/{env.env_id}", json={"traffic": {}, "auto_activate": False})
    assert resp.status_code == 200, resp.text


# ------------------------------------------------------------------- F31: the dialog's certificate blocker


async def test_f31_the_activate_dialog_enables_when_its_certificate_step_renews(w, monkeypatch, tmp_path):  # noqa: F811
    env = await dof.make_do_env(name="cv", account_id=w.account_id, status="live")
    await built(env, "blue")
    await built(env, "green")
    await _deployed(env, "blue", "green")
    await set_rows(Environment, env.env_id, active_slot_id=env.ids["blue"],
                   traffic={"switch": "do_lb", "dns": {"provider": "cloudflare", "address": "203.0.113.10",
                                                       "proxied": False}})
    blockers = ["The certificate doesn't cover green.cv.example.com: Renew the certificate first"]

    async def configured(self, db):
        return None

    async def plan(self, ctx):
        return traffic.Plan(backend="do_lb", blockers=list(blockers))

    monkeypatch.setattr(do_lb.DoLbBackend, "configured", configured)
    monkeypatch.setattr(do_lb.DoLbBackend, "plan", plan)
    cf = FakeCloudflare(token="c" * 40)  # the token test_do_api's world stores
    cf.add_zone("example.com")
    monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(cf.handle))
    resp = await w.admin.get(f"{API}/{env.env_id}/traffic/plan?slot=green")
    assert resp.status_code == 200, resp.text
    assert resp.json()["dns"]["blockers"] == [], resp.text
    answer = resp.json()
    assert answer["switch"]["blockers"] == []
    assert any("certificate step renews it" in n for n in answer["switch"]["notes"])
    # The real dialog with that answer: Activate enables once the name is typed.
    page = await _activate_page(env.env_id)
    url = PLAN_URL % env.env_id
    result = run_js(tmp_path, scenario(page, ["activate-slot"], """
var dlg = document.getElementById("activate-slot"), form = dlg.querySelector("form");
var submitBtn = form.querySelector('[type="submit"]'), typed = field(form, "confirm");
var opener = h("button", { "data-open": "activate-slot" }); document.body.appendChild(opener);
answers["GET %(url)s"] = [{ status: 200, body: %(plan)s }];
await click(opener);
typed.value = "cv"; user("input", typed); await settle();
done({ disabled: submitBtn.disabled, blocked: submitBtn.dataset.planBlocked || "" });
""" % {"url": url, "plan": json.dumps(answer)}))
    assert result == {"disabled": False, "blocked": ""}
    # Another blocker still shows on the plan.
    blockers[:] = ["The load balancer is applying a change; try again in a minute"]
    resp = await w.admin.get(f"{API}/{env.env_id}/traffic/plan?slot=green")
    assert resp.json()["switch"]["blockers"] == blockers


# --------------------------------------------------------------------- F48: no SSH host, no providers:read

WRITER = ["environments:read", "environments:write", "hosts:read", "machines:write", "providers:spend"]


async def test_f48_no_ssh_host_still_shows_the_placements_reasons(make_client):
    await make_user("admin@example.com")
    async with get_sessionmaker()() as db:
        db.add(Repository(github_id=778, full_name="acme/shop", owner="acme", name="shop",
                          html_url="https://github.com/acme/shop", detected_config={"manifest": True}))
        db.add(AppSetting(key=cloudflare.SETTING_KEY, value={"zone": "example.com", "public_ip": None,
                                                             "proxied": False}, secret="c" * 40))
        await db.commit()
    await vf.proxmox_account(name="lab")
    await dof.make_account("do-main")
    writer = await client_with(make_client, "writer@example.com", WRITER)
    page = (await writer.get("/environments/new")).text
    assert "No hosts yet" not in page
    assert pages.DO_ACCOUNTS_TEXT in page and pages.VM_ACCOUNTS_TEXT in page
    assert "do-main" not in page and "lab" not in page.replace("label", "")
    reader = await client_with(make_client, "reader@example.com", [*WRITER, "providers:read"])
    assert "No hosts yet" not in (await reader.get("/environments/new")).text


async def test_f48_no_host_and_no_account_is_still_the_empty_state(make_client):
    await make_user("admin@example.com")
    async with get_sessionmaker()() as db:
        db.add(Repository(github_id=779, full_name="acme/shop", owner="acme", name="shop",
                          html_url="https://github.com/acme/shop", detected_config={"manifest": True}))
        await db.commit()
    writer = await client_with(make_client, "writer@example.com", WRITER)
    assert "No hosts yet" in (await writer.get("/environments/new")).text


# ------------------------------------------------------------------ K5: a failed activate's page, no describe


async def test_k5_a_failed_activates_page_reads_no_hypervisor(world, monkeypatch):  # noqa: F811
    from slipway.api.v1.deployments import env_job_actions

    fake_switchyard.install(monkeypatch)
    await fake_switchyard.configure()
    env = await pve_env(world)
    await _set(Environment, env.env_id, traffic={"switch": "switchyard", "dns": None})
    for slot in ("blue", "data"):
        await ready(world, env, slot)
    await deployed(env, "blue")
    await _set(Environment, env.env_id, active_slot_id=env.instances["blue"], status="live")
    await ready(world, env, "green", status="stopped")
    await deployed(env, "green")
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=None, environment_id=env.env_id, kind="activate", status="failed",
                         branch="main", steps=[], finished_at=datetime.now(UTC),
                         options={"slot": "green", "from_slot": "blue"})
        db.add(dep)
        await db.commit()
        dep_id = dep.id
    calls: list[str] = []
    real = pxp.ProxmoxProvider.describe

    async def counted(self, ctx):
        calls.append(ctx.vm)
        return await real(self, ctx)

    monkeypatch.setattr(pxp.ProxmoxProvider, "describe", counted)
    async with get_sessionmaker()() as db:
        out = await env_job_actions(db, await db.get(Deployment, dep_id))
    assert calls == []
    assert out["retry"]["available"] is True
    # The queue's own check still reads the VM.
    async with get_sessionmaker()() as db:
        problem = await environments.vm_off_problem(db, (await environments.members(
            db, await db.get(Environment, env.env_id)))["green"])
    assert calls == ["slipway-uat-green"] and problem and "is off" in problem


# ---------------------------------------------------------------- K8, F45: asyncpg's detail, on SQLite


class _AsyncpgUniqueViolation(Exception):
    """What SQLAlchemy's asyncpg adapter wraps: the message alone, with the key in ``detail``."""

    def __init__(self) -> None:
        super().__init__('duplicate key value violates unique constraint "pk_address_claims"')
        self.detail = "Key (address)=(10.0.0.12) already exists."


async def test_k8_the_claim_conflict_reads_the_detail_attribute():
    vms = {"blue": "10.0.0.1", "green": "10.0.0.12"}
    exc = IntegrityError("INSERT INTO address_claims ...", {}, _AsyncpgUniqueViolation())
    assert "10.0.0.12" not in str(exc.orig)
    async with get_sessionmaker()() as db:  # no claim in the table: only the detail can name green
        found = await environments.claim_conflict(db, exc, vms)
    assert found is not None and found.field == "hosts.green.machine.address"
    assert found.detail.startswith("10.0.0.12 was just taken")


# ------------------------------------------------------------------- F41: a Proxmox URL stored without a port


def test_f41_a_client_for_a_url_without_a_port_calls_8006():
    seen: list[str] = []

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={"data": {}})

    client = proxmox.ProxmoxClient("https://pve.lan", "user@pam!t=x", "", transport=httpx.MockTransport(answer))
    assert client.url == "https://pve.lan:8006"
    account = SimpleNamespace(name="lab", config={"url": "https://pve.lan/"}, secret="user@pam!t=x",
                              tls={"pem": "pem"})
    assert proxmox.ProxmoxClient.for_account(account, transport=httpx.MockTransport(answer)).url == \
        "https://pve.lan:8006"
    assert proxmox.endpoint("https://pve.lan:8443") == "https://pve.lan:8443"


async def test_f41_terraform_gets_the_port_for_a_url_stored_without_one(monkeypatch):
    got: dict = {}

    class Stop(Exception):
        pass

    def tfvars(**kwargs):
        got.update(kwargs)
        raise Stop

    monkeypatch.setattr(terraform, "tfvars", tfvars)
    ctx = SimpleNamespace(
        deployment_id=uuid.uuid4(), vm="slipway-uat-blue",
        machine=SimpleNamespace(id=uuid.uuid4(), name="slipway-uat-blue", slot="blue", spec={}, network={}),
        account=SimpleNamespace(config={"url": "https://pve.lan"}),
        env=SimpleNamespace(id=uuid.uuid4(), name="uat"), host=SimpleNamespace(public_key=""))
    with pytest.raises(Stop):
        async with pxp.ProxmoxProvider()._session(ctx, 101, {"cores": 2}):
            pass
    assert got["endpoint"] == "https://pve.lan:8006"
