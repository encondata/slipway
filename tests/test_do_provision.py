"""The DigitalOcean provisioner, part 1 (phase 4 §6, §9.1-9.2, §9.4, §12.3, §15.13): create_once, prepare,
resize_droplet, the rebuild of a gone droplet and recovery.

Numbered tests of §20.2: 36 (prepare on an empty account), 37 (prepare again writes nothing), 38 (lost answers
for every create kind), 39 (stops), 40 (the droplet half: a gone droplet, and 403s), 41 (the pin), 44 (the
run-time plan check), 72 (duplicates), 73 (the firewall first), 76 (resize_droplet under a cancel and a step
timeout), 77 (a cancel at each create's POST) and 78 (an address held by another host). Also a droplet found off
powered on before the pin, the frozen values, the team freeze, recovery, and every audit action this part writes,
none of which carries a secret.

Everything outside is a fake: FakeDigitalOcean (whose clock drives every wait), FakeSpaces over the same Spaces
keys, and the droplets as hosts of the address-keyed MultiRemote (tests/do_fixtures.py).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from datetime import timedelta
from typing import Any

import httpx
import pytest
import yaml
from sqlalchemy import select

from slipway.db.session import get_sessionmaker
from slipway.models import AuditEvent, Deployment, Environment, Host, Instance, Resource
from slipway.services import digitalocean, do_provision, do_rules, resources, spaces
from slipway.services.digitalocean import DigitalOceanClient
from slipway.services.do_provision import ProvisionError
from tests import do_fixtures as dof
from tests import fake_digitalocean as fdo

# ------------------------------------------------------------------------------------------------ helpers


async def deployment(env: dof.DoEnv, slot: str = "blue", **options: Any) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=env.ids[slot], environment_id=env.env_id, branch="main", commit_sha=dof.SHA,
                         triggered_by_id=env.user_id, log="", options=options)
        db.add(dep)
        await db.commit()
        return dep.id


async def db_account(env: dof.DoEnv):
    from slipway.models import ProviderAccount
    async with get_sessionmaker()() as db:
        return await db.get(ProviderAccount, env.account_id)


async def options_of(dep_id: uuid.UUID) -> dict[str, Any]:
    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, dep_id)
        return dict(dep.options or {})


async def audits(action: str | None = None) -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        stmt = select(AuditEvent).order_by(AuditEvent.created_at)
        if action is not None:
            stmt = stmt.where(AuditEvent.action == action)
        return list(await db.scalars(stmt))


async def run_prepare(cloud: dof.Cloud, env: dof.DoEnv, slot: str = "blue", **kw: Any) -> do_provision.Prepared:
    return await do_provision.prepare(cloud.context(env, slot, **kw), read_manifest=cloud.read_manifest)


def writes_after(fake: fdo.FakeDigitalOcean, method: str, path: str) -> list[tuple[str, str]]:
    """The writes the fake saw after the last ``method path`` request."""
    idx = max(i for i, r in enumerate(fake.requests) if (r["method"], r["path"]) == (method, path))
    return [(r["method"], r["path"]) for r in fake.requests[idx + 1:] if r["method"] != "GET"]


def first_index(fake: fdo.FakeDigitalOcean, method: str, path: str) -> int:
    return next(i for i, r in enumerate(fake.requests) if (r["method"], r["path"]) == (method, path))


async def dump_everything() -> str:
    """Every value Slipway stored or audited, as text, to look for a secret in."""
    out: list[str] = []
    async with get_sessionmaker()() as db:
        for row in await db.scalars(select(Resource)):
            out.append(json.dumps([row.name, row.provider_id, row.details, row.credentials, row.tags], default=str))
        for row in await db.scalars(select(AuditEvent)):
            out.append(json.dumps([row.summary, row.details], default=str))
        for row in await db.scalars(select(Host)):
            out.append(json.dumps([row.host_key, row.provider_state, row.last_error, row.hostname], default=str))
        for row in await db.scalars(select(Environment)):
            out.append(json.dumps([row.cloud, row.notice, row.traffic_state], default=str))
        for row in await db.scalars(select(Deployment)):
            out.append(json.dumps([row.options, row.log, row.error], default=str))
    return "\n".join(out)


def private_host_key(fake: fdo.FakeDigitalOcean, droplet_id: int) -> str:
    return yaml.safe_load(fake.user_data[droplet_id])["ssh_keys"]["ed25519_private"]


class Gate:
    """Holds the fake's answer to the first ``method path`` request until released, so a test can cancel the step
    while the request is in flight."""

    def __init__(self, fake: fdo.FakeDigitalOcean, method: str, path: str) -> None:
        self.fake, self.key = fake, (method, path)
        self.arrived, self.release = asyncio.Event(), asyncio.Event()
        self.used = False

    async def handler(self, request: httpx.Request) -> httpx.Response:
        if not self.used and (request.method, request.url.path.removeprefix("/v2")) == self.key:
            self.used = True
            self.arrived.set()
            await self.release.wait()
        return self.fake.handler(request)


@pytest.fixture
def cloud(tmp_path, monkeypatch) -> dof.Cloud:
    return dof.Cloud(tmp_path, monkeypatch)


# ------------------------------------------------------------------------------------------- test 36, 73


async def test_36_prepare_on_an_empty_account(cloud):
    env = await dof.make_do_env()
    dep_id = await deployment(env)
    at_post: dict[tuple[str, str], list[dict[str, Any]]] = {}
    host_at_droplet_post: dict[str, Any] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/v2")
        if request.method == "POST" and path in ("/vpcs", "/firewalls", "/spaces/keys", "/droplets"):
            seen = [{"id": r.id, "kind": r.kind, "provider_id": r.provider_id, "credentials": r.credentials}
                    for r in await dof.rows(env)]
            at_post.setdefault((request.method, path), []).append(seen)
            if path == "/droplets":
                host = await dof.host_row(env, "blue")
                body = json.loads(request.content)
                host_at_droplet_post.update(phase=host.provider_state.get("phase"), host_key=host.host_key,
                                            sent=yaml.safe_load(body["user_data"])["ssh_keys"]["ed25519_public"],
                                            body=body)
        return cloud.do.handler(request)

    cloud.transport(handler)
    got = await run_prepare(cloud, env, deployment_id=dep_id)

    # The team, frozen and audited.
    row = await dof.env_row(env)
    assert row.provider_team == fdo.TEAM["uuid"]
    (frozen,) = await audits("environment.team_frozen")
    assert (frozen.target_type, frozen.target_id) == ("environment", str(env.env_id))
    assert frozen.details == {"team_id": fdo.TEAM["uuid"], "team_name": fdo.TEAM["name"], "account": "do-main"}
    assert (await db_account(env)).config["team"] == {"id": fdo.TEAM["uuid"], "name": fdo.TEAM["name"]}

    # Order: the VPC, the firewall, the setup key, the bucket key, the setup key deleted, then the droplet.
    writes = cloud.writes()
    assert writes[:4] == [("POST", "/vpcs"), ("POST", "/firewalls"), ("POST", "/spaces/keys"),
                          ("POST", "/spaces/keys")]
    assert writes[4][0] == "DELETE" and writes[4][1].startswith("/spaces/keys/")
    assert writes[5:] == [("POST", "/droplets")]
    assert first_index(cloud.do, "POST", "/firewalls") < first_index(cloud.do, "POST", "/droplets")  # test 73
    assert not [w for w in writes if "/actions" in w[1]]  # prepare never powers a droplet off

    # The firewall has the SSH rule only, from the account's sources, applied by the env tag.
    (fw,) = cloud.do.firewalls.values()
    assert fw["tags"] == [do_rules.env_tag(env.env_id)]
    assert [r["sources"] for r in fw["inbound_rules"]] == [{"addresses": dof.SSH_SOURCES}]

    # The setup key had full access and is gone, with its row; the bucket key stays, its secret recorded.
    setup_post, key_post = [r["body"] for r in cloud.do.requests
                            if (r["method"], r["path"]) == ("POST", "/spaces/keys")]
    assert setup_post["grants"] == [{"bucket": "", "permission": "fullaccess"}]
    bucket = do_rules.bucket_name("shop", env.env_id)
    assert key_post["grants"] == [{"bucket": bucket, "permission": "readwrite"}]
    (key_row,) = await dof.rows(env, "spaces_key")
    live_key = cloud.do.spaces_keys[key_row.provider_id]
    assert key_row.credentials == {"secret_key": live_key["secret_key"]}
    assert len(cloud.do.spaces_keys) == 1
    (deleted,) = await audits("resource.delete")
    assert deleted.details["kind"] == "spaces_key" and "-setup-" in deleted.details["name"]
    assert deleted.details["provider_id"] == next(r["path"] for r in cloud.do.requests
                                                  if r["method"] == "DELETE").rsplit("/", 1)[1]

    # The bucket, its CORS from the cors services' routes.
    assert bucket in cloud.spaces.buckets
    (bucket_row,) = await dof.rows(env, "bucket")
    assert bucket_row.details == {"region": "nyc3", "endpoint": "https://nyc3.digitaloceanspaces.com"}
    origins = cloud.spaces.cors[bucket][0]["origins"]
    assert sorted(origins) == ["https://kiosk.shop.example.com", "https://portal.shop.example.com",
                               "https://wiki.shop.example.com"]

    # The droplet: the generated host key in user-data and in host_key before the POST, which said no agent.
    assert host_at_droplet_post["phase"] == "creating"
    assert host_at_droplet_post["host_key"] == host_at_droplet_post["sent"]
    body = host_at_droplet_post["body"]
    assert body["monitoring"] is False and body["with_droplet_agent"] is False and body["ipv6"] is False
    assert body["vpc_uuid"] == next(iter(cloud.do.vpcs))
    assert do_rules.request_tag(do_rules.request_nonce(body["tags"])) in body["tags"]
    assert body["size"] == "s-1vcpu-1gb" and body["image"] == "ubuntu-24-04-x64"

    # Waited, address set, ready, pinned, Slipway's address and cloud-init.
    host = await dof.host_row(env, "blue")
    assert host.hostname == got.public_ip == "203.0.113.1"
    assert host.provider_id == got.droplet_id
    assert host.provider_state["phase"] == "ready"
    assert host.provider_state["size"] == "s-1vcpu-1gb" and host.provider_state["private_ip"] == got.private_ip
    assert host.host_key == cloud.do.host_keys[int(got.droplet_id)]
    (pinned,) = await audits("host.key_pinned")
    assert (pinned.target_type, pinned.target_id) == ("host", str(env.host_ids["blue"]))
    assert pinned.details == {"how": do_provision.PIN_HOW, "fingerprint": host.host_key_fingerprint}
    assert row.cloud["slipway_addresses"] == ["198.51.100.7"]
    (address,) = await audits("environment.slipway_address")
    assert (address.target_type, address.target_id) == ("environment", str(env.env_id))
    assert address.details == {"address": "198.51.100.7"}
    assert row.cloud["vpc_range"] == next(iter(cloud.do.vpcs.values()))["ip_range"]
    fake_host = cloud.multi["203.0.113.1"]
    assert any(a.startswith("status --wait") for a in fake_host.cloud_init())
    assert any("SSH_CONNECTION" in c for c in fake_host.remote.commands)

    # A pending row before each create, replaced by its answer (same row, real id, secret in it).
    for (_m, path), snapshots in at_post.items():
        for seen in snapshots:
            assert any(r["provider_id"].startswith("pending:") for r in seen), path
    vpc_pending = next(r for r in at_post[("POST", "/vpcs")][0] if r["kind"] == "vpc")
    (vpc_row,) = await dof.rows(env, "vpc")
    assert vpc_row.id == vpc_pending["id"] and not resources.is_pending(vpc_row)
    key_pending = [r for r in at_post[("POST", "/spaces/keys")][1] if r["kind"] == "spaces_key"
                   and r["provider_id"].startswith("pending:")][-1]
    assert key_pending["id"] == key_row.id and key_pending["credentials"] is None
    assert not [r for r in await dof.rows(env) if resources.is_pending(r)]

    # The manifest read at the resolved commit is hashed into the job's options.
    assert (await options_of(dep_id))["manifest_sha256"] == hashlib.sha256(dof.DO_YML.encode()).hexdigest()

    # No private host key, token or Spaces secret in any row, audit or log line.
    stored = await dump_everything() + "\n".join(cloud.log)
    private = private_host_key(cloud.do, int(got.droplet_id))
    for line in private.splitlines():
        if line and not line.startswith("-----"):
            assert line not in stored
    assert fdo.TOKEN not in stored
    audited = json.dumps([[a.summary, a.details] for a in await audits()])
    assert live_key["secret_key"] not in audited

    # Every create audited: pending (with its nonce) then create, against the same row.
    created = {a.details["kind"]: a for a in await audits("resource.create")}
    assert set(created) == {"vpc", "firewall", "spaces_key", "bucket", "droplet"}
    pending = await audits("resource.pending")
    assert {a.details["kind"] for a in pending} == set(created)
    droplet_row = (await dof.rows(env, "droplet"))[0]
    assert created["droplet"].target_id == str(droplet_row.id)
    assert created["droplet"].details["replaces"] == next(a.details["nonce"] for a in pending
                                                          if a.details["kind"] == "droplet")
    assert next(a for a in pending if a.details["kind"] == "droplet").target_id == str(droplet_row.id)


async def test_36_rows_survive_a_failed_step(cloud):
    """The job's step fails after the creates (cloud-init never wrote its marker): every row is still recorded,
    since each was committed on its own, and the host keeps its key."""
    env = await dof.make_do_env()
    cloud.marker.unlink()
    cloud.host_env["slipway-shop-blue"] = {"FAKE_CLOUD_INIT": "error"}
    with pytest.raises(ProvisionError) as err:
        await run_prepare(cloud, env)
    assert str(err.value) == ("cloud-init didn't finish setting up slipway-shop-blue (errors: Failed to run module "
                              "scripts-user). Retry the deploy")
    kinds = sorted(r.kind for r in await dof.rows(env, include_pending=False))
    assert kinds == ["bucket", "droplet", "firewall", "spaces_key", "vpc"]
    host = await dof.host_row(env, "blue")
    # Not built until cloud-init is done (P4 §9.2): the host keeps its key and stays creating.
    assert host.host_key and host.provider_state["phase"] == "creating"


async def test_73_firewalled_pin_fails_with_the_sources_text(cloud):
    env = await dof.make_do_env()
    cloud.firewalled.add("slipway-shop-blue")
    with pytest.raises(ProvisionError) as err:
        await run_prepare(cloud, env)
    assert str(err.value) == ("Slipway couldn't reach slipway-shop-blue on SSH for 10 minutes. The cloud firewall "
                              "lets SSH in only from 198.51.100.0/24: if Slipway connects from another address, add "
                              "it to do-main's SSH sources, then retry")
    assert cloud.multi["203.0.113.1"].remote.commands == []  # nothing was sent to the droplet
    assert len(cloud.sent) > 10  # it kept trying for the whole wait


# ------------------------------------------------------------------------------------------------ test 37


async def test_37_prepare_again_writes_nothing(cloud):
    env = await dof.make_do_env()
    first = await run_prepare(cloud, env)
    cloud.do.requests.clear()
    cloud.spaces.requests.clear()
    second = await run_prepare(cloud, env)
    assert second.droplet_id == first.droplet_id and not second.created
    assert cloud.do.writes() == []
    assert cloud.spaces.writes() == []
    read = {(r["method"], r["path"]) for r in cloud.do.requests}
    vpc_id, fw_id = next(iter(cloud.do.vpcs)), next(iter(cloud.do.firewalls))
    assert {("GET", "/account"), ("GET", f"/vpcs/{vpc_id}"), ("GET", f"/firewalls/{fw_id}"), ("GET", "/spaces/keys"),
            ("GET", f"/droplets/{first.droplet_id}")} <= read
    assert any(r.method == "HEAD" for r in cloud.spaces.requests)  # the bucket, read under its own key
    # Nothing audited twice: the team, Slipway's address and the pin are first-time events.
    assert len(await audits("environment.team_frozen")) == 1
    assert len(await audits("environment.slipway_address")) == 1
    assert len(await audits("host.key_pinned")) == 1


# ------------------------------------------------------------------------------------------------ test 38


async def _client():
    return DigitalOceanClient(fdo.TOKEN)


async def _spec(kind: str, cloud: dof.Cloud, env: dof.DoEnv, client: DigitalOceanClient) -> do_provision.CreateSpec:
    """One create of each kind, as create_once runs it."""
    row = await dof.env_row(env)
    made = cloud.__dict__.setdefault("made_for_specs", {})
    if "vpc" not in made:
        made["vpc"] = cloud.do.add_vpc(name="test-vpc-for-specs")
    vpc = made["vpc"]
    if kind == "droplet":
        return do_provision.droplet_spec(
            client, row, "blue", instance_id=env.ids["blue"], adoptable=lambda d: True, size="s-1vcpu-1gb",
            body=lambda nonce: do_rules.droplet_body("shop", env.env_id, "blue", region="nyc3", size="s-1vcpu-1gb",
                                                     vpc_uuid=vpc["id"], nonce=nonce, user_data=""))
    if kind == "database":
        return do_provision.database_spec(client, row, region="nyc3", size="db-s-1vcpu-1gb", nodes=1, version="16",
                                          vpc_uuid=vpc["id"], droplet_ids=[])
    if kind == "vpc":
        return do_provision.vpc_spec(client, row, region="nyc3")
    if kind == "firewall":
        return do_provision.firewall_spec(client, row, do_rules.firewall_body("shop", env.env_id,
                                                                              ssh_sources=dof.SSH_SOURCES))
    if kind == "load_balancer":
        if "cert" not in made:
            made["cert"] = cloud.do.add_certificate("test-cert-for-specs", ["api.shop.example.com"])
        cert = made["cert"]
        return do_provision.lb_spec(client, row, do_rules.lb_body("shop", region="nyc3", vpc_uuid=vpc["id"], port=80,
                                                                  health="/healthz", certificate_id=cert["id"]),
                                    vpc_uuid=vpc["id"])
    if kind == "certificate":
        leaf, key = fdo.make_leaf(["api.shop.example.com"])
        name = do_rules.certificate_name("shop", do_provision.now())
        return do_provision.certificate_spec(
            client, row, name, {"name": name, "type": "custom", "private_key": key, "leaf_certificate": leaf},
            not_after=None, dns_names=["api.shop.example.com"],
            pending_credentials={"private_key": key, "leaf": leaf, "chain": ""})
    if kind in ("bucket_key", "setup_key"):
        return do_provision.spaces_key_spec(client, row, bucket=do_rules.bucket_name("shop", env.env_id),
                                            setup=kind == "setup_key")
    if kind == "bucket":
        if "full" not in made:
            made["full"] = cloud.do.add_spaces_key("test-full", [{"bucket": "", "permission": "fullaccess"}])
        full = made["full"]

        async def s3():
            return spaces.SpacesClient("nyc3", spaces.SpacesKey(full["access_key"], full["secret_key"]))
        return do_provision.bucket_spec(row, do_rules.bucket_name("shop", env.env_id), region="nyc3", s3=s3)
    raise AssertionError(kind)


POSTS = {"droplet": "/droplets", "database": "/databases", "vpc": "/vpcs", "firewall": "/firewalls",
         "load_balancer": "/load_balancers", "certificate": "/certificates", "bucket_key": "/spaces/keys",
         "setup_key": "/spaces/keys"}
KIND = {"bucket_key": "spaces_key", "setup_key": "spaces_key"}
ALL_KINDS = ["droplet", "database", "vpc", "firewall", "load_balancer", "certificate", "bucket", "bucket_key",
             "setup_key"]


def _creates(cloud: dof.Cloud, kind: str) -> int:
    if kind == "bucket":
        return sum(1 for r in cloud.spaces.requests if r.method == "PUT" and not r.url.query)
    return sum(1 for r in cloud.do.requests if (r["method"], r["path"]) == ("POST", POSTS[kind]))


def _lose_bucket_answer(cloud: dof.Cloud, monkeypatch) -> None:
    """The bucket's PUT lands, then its answer is lost (a timeout)."""
    state = {"lost": False}

    def handler(request: httpx.Request) -> httpx.Response:
        resp = cloud.spaces.handler(request)
        if request.method == "PUT" and not request.url.query and not state["lost"]:
            state["lost"] = True
            raise httpx.ReadTimeout("lost (fake)", request=request)
        return resp
    monkeypatch.setattr(spaces, "transport_factory", lambda: httpx.MockTransport(handler))


@pytest.mark.parametrize("visible_after", [30, 90])
@pytest.mark.parametrize("kind", ALL_KINDS)
async def test_38_lost_answer_found_on_an_immediate_retry(cloud, monkeypatch, kind, visible_after):
    env = await dof.make_do_env()
    cloud.do.lost_visible_after = visible_after
    if kind == "bucket":
        _lose_bucket_answer(cloud, monkeypatch)
    else:
        cloud.do.lose_answer[("POST", POSTS[kind])] = 1
    ctx = cloud.context(env)
    async with await _client() as client:
        spec = await _spec(kind, cloud, env, client)
        with pytest.raises((digitalocean.DigitalOceanError, spaces.SpacesError)):
            await do_provision.create_once(ctx, client, spec)
        (pending,) = [r for r in await dof.rows(env, KIND.get(kind, kind)) if resources.is_pending(r)]
        started = cloud.do.now
        made = await do_provision.create_once(ctx, client, await _spec(kind, cloud, env, client))
    real = [r for r in await dof.rows(env, KIND.get(kind, kind)) if not resources.is_pending(r)]
    assert not [r for r in await dof.rows(env) if resources.is_pending(r)]
    if kind in ("bucket_key", "setup_key"):
        # Its secret was shown once: the key the lost answer made is deleted and a new one made.
        assert not made.adopted and _creates(cloud, kind) == 2
        assert len(cloud.do.spaces_keys) == 1  # only the new key is left
        deleted = [r for r in cloud.do.requests if r["method"] == "DELETE"]
        assert len(deleted) == 1 and real[0].provider_id in cloud.do.spaces_keys
    else:
        assert made.adopted and _creates(cloud, kind) == 1  # no second create
        assert real[0].id == pending.id  # the pending row became the real one
        (adopt,) = await audits("resource.adopt")
        assert (adopt.target_type, adopt.target_id) == ("resource", str(pending.id))
        assert adopt.details["kind"] == KIND.get(kind, kind) and adopt.details["rule"]
        assert adopt.details["replaces"] == resources.nonce_of(pending)
        if kind != "bucket":
            assert cloud.do.now - started >= visible_after  # it waited for the object to show
    assert len(real) == 1


@pytest.mark.parametrize("kind", ALL_KINDS)
async def test_38_truly_absent_after_two_lookups_is_created_once_more(cloud, kind):
    env = await dof.make_do_env()
    if kind == "bucket":
        cloud.spaces.fail_next.append((500, "InternalError"))
    else:
        cloud.do.fail[("POST", POSTS[kind])] = [500]  # nothing was made, but Slipway can't know that
    ctx = cloud.context(env)
    async with await _client() as client:
        with pytest.raises((digitalocean.DigitalOceanError, spaces.SpacesError)):
            await do_provision.create_once(ctx, client, await _spec(kind, cloud, env, client))
        assert [r for r in await dof.rows(env) if resources.is_pending(r)]
        started = cloud.do.now
        made = await do_provision.create_once(ctx, client, await _spec(kind, cloud, env, client))
    assert not made.adopted
    assert cloud.do.now - started >= 2 * do_provision.PENDING_GAP  # two lookups, 60 s after the send and apart
    if kind != "bucket":
        assert _creates(cloud, kind) == 2  # the failed one, and one more
    assert any("made nothing; sending it again" in line for line in cloud.log)
    forgot = await audits("resource.forget")
    assert len(forgot) == 1 and forgot[0].details["provider_id"].startswith("pending:")


async def test_38_a_pending_create_too_recent_to_judge_stops(cloud, monkeypatch):
    """While the lookups can't yet tell (none is 60 s after the send), the step waits; past its wait it stops,
    keeping the pending row and making nothing new."""
    env = await dof.make_do_env()
    monkeypatch.setattr(do_provision, "PENDING_WAIT", 30.0)
    cloud.do.lose_answer[("POST", "/vpcs")] = 1
    cloud.do.lost_visible_after = 10_000
    async with await _client() as client:
        with pytest.raises(digitalocean.DigitalOceanError):
            await do_provision.create_once(cloud.context(env), client, await _spec("vpc", cloud, env, client))
        (pending,) = await dof.rows(env, "vpc")
        with pytest.raises(ProvisionError) as err:
            await do_provision.create_once(cloud.context(env), client, await _spec("vpc", cloud, env, client))
    assert str(err.value).startswith("A VPC create from ")
    assert str(err.value).endswith("may still appear in DigitalOcean; retry in a few minutes. Slipway made nothing new")
    (kept,) = await dof.rows(env, "vpc")
    assert kept.id == pending.id and resources.is_pending(kept)
    assert len(kept.details["pending"]["looked"]) >= 3  # each lookup is committed
    assert sum(1 for r in cloud.do.requests if (r["method"], r["path"]) == ("POST", "/vpcs")) == 1


async def test_38_droplet_lost_answer_through_prepare_adopts_and_pins(cloud):
    """The real path: a lost droplet answer, an immediate retry, adopted only because the host is creating with
    the key the lost create sent, and then pinned with it."""
    env = await dof.make_do_env()
    cloud.do.lose_answer[("POST", "/droplets")] = 1
    cloud.do.lost_visible_after = 30
    with pytest.raises(ProvisionError):
        await run_prepare(cloud, env)
    host = await dof.host_row(env, "blue")
    assert host.provider_state["phase"] == "creating" and host.host_key
    sent_key = host.host_key
    got = await run_prepare(cloud, env)
    assert sum(1 for w in cloud.writes() if w == ("POST", "/droplets")) == 1
    host = await dof.host_row(env, "blue")
    assert host.host_key == sent_key == cloud.do.host_keys[int(got.droplet_id)]
    assert host.provider_state["phase"] == "ready"
    assert [a.details["kind"] for a in await audits("resource.adopt")] == ["droplet"]


async def test_38_lost_droplet_found_without_a_host_key_is_remade(cloud):
    """§9.2 step 2: a found droplet is ours but can't be trusted when the host holds no key: it goes, and a new
    one is made."""
    env = await dof.make_do_env()
    cloud.do.lose_answer[("POST", "/droplets")] = 1
    with pytest.raises(ProvisionError):
        await run_prepare(cloud, env)
    async with get_sessionmaker()() as db:
        host = await db.get(Host, env.host_ids["blue"])
        host.host_key = None  # a hand edit
        await db.commit()
    await run_prepare(cloud, env)
    writes = cloud.writes()
    assert writes.count(("POST", "/droplets")) == 2
    assert any(m == "DELETE" and p.startswith("/droplets/") for m, p in writes)
    assert len(cloud.do.droplets) == 1


# ------------------------------------------------------------------------------------------------ test 39


async def test_39_droplet_with_the_env_tag_but_not_slipway_stops(cloud):
    env = await dof.make_do_env()
    cloud.do.add_droplet(name="slipway-shop-blue", tags=[do_rules.env_tag(env.env_id)])
    with pytest.raises(ProvisionError) as err:
        await run_prepare(cloud, env)
    assert str(err.value).endswith(do_rules.CHANGED_NOTHING) and "but not the slipway tag" in str(err.value)
    assert cloud.do.writes() == []


async def test_39_same_named_vpc_without_the_marker_stops(cloud):
    env = await dof.make_do_env()
    vpc = cloud.do.add_vpc(name="slipway-shop", description="made by hand")
    with pytest.raises(ProvisionError) as err:
        await run_prepare(cloud, env)
    assert str(err.value) == (f"A VPC named slipway-shop ({vpc['id']}) exists without Slipway's marker for shop. "
                              f"{do_rules.CHANGED_NOTHING}")
    assert cloud.do.writes() == []


async def test_39_load_balancer_of_that_name_in_another_vpc_stops(cloud):
    env = await dof.make_do_env()
    other = cloud.do.add_vpc(name="elsewhere")
    ours = cloud.do.add_vpc(name="slipway-shop-vpc-for-test")
    cloud.do.add_load_balancer(name="slipway-shop-lb", vpc_uuid=other["id"])
    cloud.do.requests.clear()
    async with await _client() as client:
        row = await dof.env_row(env)
        spec = do_provision.lb_spec(client, row, {"name": "slipway-shop-lb"}, vpc_uuid=ours["id"])
        with pytest.raises(ProvisionError) as err:
            await do_provision.create_once(cloud.context(env), client, spec)
    assert "exists outside shop's VPC" in str(err.value) and str(err.value).endswith(do_rules.CHANGED_NOTHING)
    assert cloud.do.writes() == []


async def test_39_firewall_without_the_tag_stops(cloud):
    env = await dof.make_do_env()
    cloud.do.add_firewall(name="slipway-shop-fw", inbound_rules=[{"protocol": "tcp", "ports": "22",
                                                                  "sources": {"addresses": ["0.0.0.0/0"]}}])
    with pytest.raises(ProvisionError) as err:
        await run_prepare(cloud, env)
    assert "exists without shop's tag" in str(err.value) and str(err.value).endswith(do_rules.CHANGED_NOTHING)
    assert writes_after(cloud.do, "GET", "/firewalls") == []


async def test_39_recorded_droplet_renamed_stops(cloud):
    env = await dof.make_do_env()
    got = await run_prepare(cloud, env)
    cloud.do.droplets[int(got.droplet_id)]["name"] = "renamed-by-hand"
    cloud.do.requests.clear()
    with pytest.raises(ProvisionError) as err:
        await run_prepare(cloud, env)
    assert str(err.value) == (f"Droplet slipway-shop-blue ({got.droplet_id}) no longer carries Slipway's name and tags "
                              f"for shop. {do_rules.CHANGED_NOTHING}")
    assert cloud.do.writes() == []


# ------------------------------------------------------------------------------------------- test 40, 44


async def test_40_gone_droplet_is_rebuilt_with_a_new_host_key(cloud):
    env = await dof.make_do_env(slots=("blue",))
    first = await run_prepare(cloud, env)
    old_key = (await dof.host_row(env, "blue")).host_key
    cloud.do.droplets.pop(int(first.droplet_id))
    dep_id = await deployment(env)
    seen: dict[str, Any] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        if (request.method, request.url.path.removeprefix("/v2")) == ("POST", "/droplets"):
            host = await dof.host_row(env, "blue")
            seen.update(phase=host.provider_state.get("phase"), key=host.host_key, hostname=host.hostname)
        return cloud.do.handler(request)
    cloud.transport(handler)
    second = await run_prepare(cloud, env, deployment_id=dep_id)
    assert second.droplet_id != first.droplet_id and second.created
    # Back to planned, its pin cleared, then creating with a new key before the POST.
    assert seen["phase"] == "creating" and seen["key"] != old_key and seen["hostname"] == "slipway-shop-blue.invalid"
    host = await dof.host_row(env, "blue")
    assert host.host_key == cloud.do.host_keys[int(second.droplet_id)] != old_key
    assert host.provider_state["phase"] == "ready"
    (rebuilt,) = await audits("resource.rebuild")
    (row,) = await dof.rows(env, "droplet")
    assert (rebuilt.target_type, rebuilt.target_id) == ("resource", str(row.id))
    assert rebuilt.details["kind"] == "droplet" and rebuilt.details["provider_id"] == second.droplet_id
    assert (await options_of(dep_id))["rebuild"] == ["droplet"]
    assert len(await audits("host.key_pinned")) == 2  # the new droplet's key is pinned again
    # A remake of a gone droplet stays inside a plan of one droplet (test 44's last case).
    assert (await dof.env_row(env)).cloud["plan"]["droplets"] == 1


@pytest.mark.parametrize("kind,path", [("droplets", "/droplets/{droplet}"), ("vpcs", "/vpcs/{vpc}"),
                                       ("firewalls", "/firewalls/{firewall}"), ("spaces_keys", "/spaces/keys")])
async def test_40_a_403_stops_and_forgets_nothing(cloud, kind, path):
    env = await dof.make_do_env()
    await run_prepare(cloud, env)
    before = sorted((r.kind, r.provider_id) for r in await dof.rows(env))
    cloud.do.forbid.add(kind)
    cloud.do.requests.clear()
    with pytest.raises(ProvisionError) as err:
        await run_prepare(cloud, env)
    label = {"droplets": "droplets", "vpcs": "VPCs", "firewalls": "firewalls", "spaces_keys": "Spaces keys"}[kind]
    assert str(err.value) == (f"do-main's token can't read {label} (DigitalOcean answered 403). Slipway changed "
                              "nothing: give the token that scope, then retry")
    assert sorted((r.kind, r.provider_id) for r in await dof.rows(env)) == before
    assert cloud.do.writes() == []
    assert (await dof.host_row(env, "blue")).provider_state["phase"] == "ready"


async def test_44_second_droplet_outside_the_plan_fails_before_the_create(cloud):
    env = await dof.make_do_env(droplets=1)  # two slots, a plan of one droplet
    await run_prepare(cloud, env, "blue")
    with pytest.raises(ProvisionError) as err:
        await run_prepare(cloud, env, "green")
    assert str(err.value) == ("This would make droplet slipway-shop-green, which shop's confirmed plan doesn't "
                              "include: its plan has 1 droplet; Add slot confirms a second one. Slipway changed "
                              "nothing")
    assert cloud.writes().count(("POST", "/droplets")) == 1


async def test_44_an_unrecorded_tagged_droplet_counts(cloud):
    env = await dof.make_do_env(droplets=1)
    stray = cloud.do.add_droplet(name="slipway-shop-green",
                                 tags=["slipway", do_rules.env_tag(env.env_id), "slipway-slot:green"])
    cloud.do.requests.clear()
    with pytest.raises(ProvisionError) as err:
        await run_prepare(cloud, env, "blue")
    assert f"DigitalOcean already lists {stray['id']} with shop's tag" in str(err.value)
    assert ("POST", "/droplets") not in cloud.writes()


async def test_44_a_pending_row_counts(cloud):
    env = await dof.make_do_env(droplets=1)
    await resources.record_pending(env.env_id, "digitalocean", "droplet", "slipway-shop-green",
                                   nonce="0123456789abcdef", body_hash="x")
    with pytest.raises(ProvisionError, match="confirmed plan doesn't include"):
        await run_prepare(cloud, env, "blue")
    assert ("POST", "/droplets") not in cloud.writes()


async def test_44_a_larger_cluster_or_a_second_load_balancer_fails(cloud):
    env = await dof.make_do_env()
    vpc = cloud.do.add_vpc(name="slipway-shop-test")
    async with await _client() as client:
        row = await dof.env_row(env)
        spec = do_provision.database_spec(client, row, region="nyc3", size="db-s-2vcpu-4gb", nodes=1, version="16",
                                          vpc_uuid=vpc["id"], droplet_ids=[])
        with pytest.raises(ProvisionError) as err:
            await do_provision.create_once(cloud.context(env), client, spec)
        assert str(err.value) == ("This would make database cluster slipway-shop-db (db-s-2vcpu-4gb × 1), which shop's "
                                  "confirmed plan doesn't include: the plan's cluster is db-s-1vcpu-1gb × 1; confirm a "
                                  "new size first. Slipway changed nothing")
        await resources.record(env.env_id, "digitalocean", "load_balancer", "lb-1", "slipway-shop-lb", "created")
        async with get_sessionmaker()() as db:
            with pytest.raises(ProvisionError, match="an environment has one load balancer"):
                await do_provision.plan_check(db, row, "load_balancer", client=client)
            await do_provision.plan_check(db, row, "load_balancer", client=client, remake=True)  # a remake passes
    assert cloud.do.writes() == []


# ------------------------------------------------------------------------------------------------ test 41


async def test_41_another_host_key_fails_at_once_and_sends_nothing(cloud):
    env = await dof.make_do_env()
    cloud.wrong_key.add("slipway-shop-blue")
    with pytest.raises(ProvisionError) as err:
        await run_prepare(cloud, env)
    assert str(err.value) == ("slipway-shop-blue answered SSH with a host key Slipway didn't generate for it. "
                              "Slipway trusted nothing and sent it nothing. Check it in DigitalOcean, then retry")
    assert cloud.multi["203.0.113.1"].remote.commands == []
    assert len(cloud.sent) == 1  # no retry after a mismatch
    assert await audits("host.key_pinned") == []


async def test_41_a_host_with_no_pinned_key_is_never_trusted(cloud):
    env = await dof.make_do_env()
    await run_prepare(cloud, env)
    async with get_sessionmaker()() as db:
        host = await db.get(Host, env.host_ids["blue"])
        host.host_key = None  # a hand edit
        await db.commit()
    cloud.sent.clear()
    with pytest.raises(ProvisionError, match="has no pinned host key, so Slipway can't trust slipway-shop-blue"):
        await run_prepare(cloud, env)
    assert cloud.sent == []


async def test_41_ssh_not_up_yet_is_retried(cloud):
    env = await dof.make_do_env()
    cloud.booting["slipway-shop-blue"] = 4
    got = await run_prepare(cloud, env)
    assert len(cloud.sent) == 5
    assert (await dof.host_row(env, "blue")).host_key == cloud.do.host_keys[int(got.droplet_id)]


# ------------------------------------------------------------------------------------------------ test 72


async def test_72_two_droplets_of_one_name_stop_naming_both(cloud):
    env = await dof.make_do_env()
    tags = ["slipway", do_rules.env_tag(env.env_id)]
    a = cloud.do.add_droplet(name="slipway-shop-blue", tags=tags)
    b = cloud.do.add_droplet(name="slipway-shop-blue", tags=tags)
    cloud.do.requests.clear()
    with pytest.raises(ProvisionError) as err:
        await run_prepare(cloud, env)
    assert str(err.value) == (f"DigitalOcean has 2 droplets named slipway-shop-blue with Slipway's tags ({a['id']}, "
                              f"{b['id']}). {do_rules.CHANGED_NOTHING}")
    assert cloud.do.writes() == []


async def test_72_an_unrecorded_droplet_of_our_name_is_never_adopted(cloud):
    env = await dof.make_do_env()
    cloud.do.add_droplet(name="slipway-shop-blue", tags=["slipway", do_rules.env_tag(env.env_id)])
    with pytest.raises(ProvisionError, match="Slipway has no record of making it"):
        await run_prepare(cloud, env)
    assert ("POST", "/droplets") not in cloud.writes()


# ------------------------------------------------------------------------------------------------ test 76


async def _grow(env: dof.DoEnv, size: str = "s-1vcpu-2gb") -> None:
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        row.cloud = {**row.cloud, "droplet_size": size, "plan": {**row.cloud["plan"], "droplet_size": size}}
        await db.commit()


def _yielding_sleep(cloud: dof.Cloud, monkeypatch, pause: float = 0.0) -> None:
    async def sleep(seconds: float) -> None:
        cloud.do.advance(seconds)
        await asyncio.sleep(pause)
    monkeypatch.setattr(digitalocean, "sleep", sleep)


async def test_76_resize_grows_the_droplet(cloud):
    env = await dof.make_do_env()
    got = await run_prepare(cloud, env)
    await _grow(env)
    note = await do_provision.resize_droplet(cloud.context(env))
    assert note is None
    kinds = [r["body"]["type"] for r in cloud.do.requests if r["path"].endswith("/actions") and r["method"] == "POST"]
    assert kinds == ["power_off", "resize", "power_on"]
    resize = next(r["body"] for r in cloud.do.requests if r["path"].endswith("/actions")
                  and r["body"]["type"] == "resize")
    assert resize == {"type": "resize", "size": "s-1vcpu-2gb", "disk": True}
    droplet = cloud.do.droplets[int(got.droplet_id)]
    assert droplet["status"] == "active" and droplet["size_slug"] == "s-1vcpu-2gb"
    assert (await dof.host_row(env, "blue")).provider_state["size"] == "s-1vcpu-2gb"
    assert "Resizing slipway-shop-blue to s-1vcpu-2gb: it stops for a few minutes" in cloud.log


async def test_76_resize_cancelled_during_its_poll_ends_active(cloud, monkeypatch):
    env = await dof.make_do_env()
    got = await run_prepare(cloud, env)
    await _grow(env)
    cloud.do.action_polls = 20  # a slow resize: the cancel comes while Slipway polls it
    _yielding_sleep(cloud, monkeypatch)
    task = asyncio.create_task(do_provision.resize_droplet(cloud.context(env)))
    while not any(a["type"] == "resize" for a in cloud.do.actions.values()):
        await asyncio.sleep(0)
    for _ in range(5):
        await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    droplet = cloud.do.droplets[int(got.droplet_id)]
    assert droplet["status"] == "active"  # power_on ran in the shielded finally, once the resize let it
    assert [a["type"] for a in cloud.do.actions.values()] == ["power_off", "resize", "power_on"]
    # DigitalOcean finished the resize it had taken, and Slipway recorded it before powering on.
    assert (await dof.host_row(env, "blue")).provider_state["size"] == droplet["size_slug"] == "s-1vcpu-2gb"


async def test_76_resize_hitting_the_step_timeout_ends_active(cloud, monkeypatch):
    """S12 builds the real member-step timeout; here the call is wrapped in asyncio.timeout as the step does."""
    env = await dof.make_do_env()
    got = await run_prepare(cloud, env)
    await _grow(env)
    cloud.do.action_polls = 20
    _yielding_sleep(cloud, monkeypatch, pause=0.01)
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.3):
            await do_provision.resize_droplet(cloud.context(env))
    assert cloud.do.droplets[int(got.droplet_id)]["status"] == "active"
    assert [a["type"] for a in cloud.do.actions.values()] == ["power_off", "resize", "power_on"]


async def test_76_a_failed_resize_still_powers_on(cloud):
    env = await dof.make_do_env()
    got = await run_prepare(cloud, env)
    await _grow(env)
    cloud.do.action_errors.add("resize")
    with pytest.raises(ProvisionError, match="Resizing slipway-shop-blue failed: DigitalOcean's action ended errored"):
        await do_provision.resize_droplet(cloud.context(env))
    assert cloud.do.droplets[int(got.droplet_id)]["status"] == "active"


async def test_76_a_deploy_refused_before_resize_never_powers_off(cloud):
    """A size that can't be applied fails prepare's read-only check, before any power action."""
    env = await dof.make_do_env()
    await run_prepare(cloud, env)
    await _grow(env, "c-2")  # another kind of droplet
    with pytest.raises(ProvisionError) as err:
        await run_prepare(cloud, env)
    assert str(err.value).startswith("slipway-shop-blue can't become c-2: c-2 is another kind of droplet")
    assert not [r for r in cloud.do.requests if r["path"].endswith("/actions")]


async def test_76_resize_notes_when_there_is_nothing_to_do(cloud):
    env = await dof.make_do_env()
    await run_prepare(cloud, env)
    assert await do_provision.resize_droplet(cloud.context(env)) == "slipway-shop-blue is already s-1vcpu-1gb"
    await _grow(env, "s-1vcpu-1gb")
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        row.active_slot_id = env.ids["blue"]
        row.cloud = {**row.cloud, "droplet_size": "s-2vcpu-4gb"}
        await db.commit()
    assert (await do_provision.resize_droplet(cloud.context(env))).startswith("blue is the active slot")
    assert not [r for r in cloud.do.requests if r["path"].endswith("/actions")]


async def test_a_droplet_found_off_is_powered_on_before_the_pin(cloud):
    env = await dof.make_do_env()
    got = await run_prepare(cloud, env)
    cloud.do.droplets[int(got.droplet_id)]["status"] = "off"
    cloud.do.requests.clear()
    cloud.sent.clear()
    await run_prepare(cloud, env)
    actions = [i for i, r in enumerate(cloud.do.requests) if r["path"].endswith("/actions") and r["method"] == "POST"]
    assert [cloud.do.requests[i]["body"]["type"] for i in actions] == ["power_on"]
    assert cloud.do.droplets[int(got.droplet_id)]["status"] == "active"
    assert cloud.sent  # pinned after it was on


# ------------------------------------------------------------------------------------------------ test 77


@pytest.mark.parametrize("kind", ["droplet", "database", "vpc", "firewall", "load_balancer", "certificate",
                                  "bucket_key", "setup_key"])
@pytest.mark.parametrize("answer", ["given", "lost"])
async def test_77_cancel_at_the_post_records_the_answer(cloud, kind, answer):
    env = await dof.make_do_env()
    gate = Gate(cloud.do, "POST", POSTS[kind])
    cloud.transport(gate.handler)
    if answer == "lost":
        cloud.do.lose_answer[("POST", POSTS[kind])] = 1
    async with await _client() as client:
        spec = await _spec(kind, cloud, env, client)
        task = asyncio.create_task(do_provision.create_once(cloud.context(env), client, spec))
        await gate.arrived.wait()
        task.cancel()
        await asyncio.sleep(0)
        gate.release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        rows = await dof.rows(env, KIND.get(kind, kind))
        assert len(rows) == 1
        if answer == "given":
            assert not resources.is_pending(rows[0])  # the answer was recorded despite the cancel
            if kind == "bucket_key":
                assert rows[0].credentials and rows[0].credentials["secret_key"]
            if kind == "database":  # doadmin's password came with the answer and went in with the row
                assert rows[0].credentials == {"admin_password": next(iter(cloud.do.databases.values()))[
                    "connection"]["password"]}
        else:
            assert resources.is_pending(rows[0])  # the pending row stays
        keys = kind in ("bucket_key", "setup_key")
        if answer == "given" and not keys:
            # The retry sends no second create: by name the object is adopted again, or its row (or the plan, which
            # now counts it) refuses one.
            try:
                await do_provision.create_once(cloud.context(env), client, await _spec(kind, cloud, env, client))
            except (resources.ResourceTaken, ProvisionError):
                pass
        elif answer == "lost":
            again = await do_provision.create_once(cloud.context(env), client, await _spec(kind, cloud, env, client))
            assert again.adopted != keys  # found by nonce or name; a key is deleted and made again instead
    creates = _creates(cloud, kind)
    if answer == "given":
        assert creates == 1
    else:
        assert creates == (2 if keys else 1)


# ------------------------------------------------------------------------------------------------ test 78


async def test_78_an_address_another_host_holds_stops_until_it_is_edited(cloud):
    env = await dof.make_do_env()
    async with get_sessionmaker()() as db:
        nas = Host(name="nas", hostname="203.0.113.1", username="root", metrics={})
        db.add(nas)
        await db.commit()
    with pytest.raises(ProvisionError) as err:
        await run_prepare(cloud, env)
    assert str(err.value) == ("203.0.113.1 is still the address of host nas, which Slipway lists separately. "
                              "DigitalOcean gave that address to slipway-shop-blue, so nas no longer points at the "
                              "machine it was added for: change or remove host nas, then retry")
    (droplet,) = await dof.rows(env, "droplet")
    assert not resources.is_pending(droplet)  # it stays recorded (and bills: the Billing callout counts it)
    host = await dof.host_row(env, "blue")
    assert host.provider_state["phase"] == "creating" and host.host_key
    assert cloud.sent == []  # nothing connected
    async with get_sessionmaker()() as db:
        row = await db.get(Host, nas.id)
        row.hostname = "10.0.0.50"
        await db.commit()
    got = await run_prepare(cloud, env)
    assert got.droplet_id == droplet.provider_id
    assert cloud.writes().count(("POST", "/droplets")) == 1
    assert (await dof.host_row(env, "blue")).provider_state["phase"] == "ready"


async def test_78_a_host_this_environment_owns_isnt_compared(cloud):
    env = await dof.make_do_env()
    async with get_sessionmaker()() as db:
        green = await db.get(Host, env.host_ids["green"])
        green.lan_address = "203.0.113.1"  # say, left from an earlier build of green
        await db.commit()
    got = await run_prepare(cloud, env)
    assert got.public_ip == "203.0.113.1"


# --------------------------------------------------------------------------- the manifest, the team, recovery


async def test_frozen_edge_and_version_refuse_before_any_write(cloud):
    env = await dof.make_do_env(cloud={"edge": {"port": 8080, "health": "/healthz"}})
    with pytest.raises(ProvisionError) as err:
        await run_prepare(cloud, env, deployment_id=await deployment(env))
    assert str(err.value) == ("0123456 changes edge.port from 8080 to 80, but shop's load balancer and firewall were "
                              "made for 8080: a new port needs a new environment. Slipway changed nothing")
    env2 = await dof.make_do_env(name="shop2", db_version="15", account_id=env.account_id)
    with pytest.raises(ProvisionError, match="changes data.managed.db.version from 15 to 16"):
        await run_prepare(cloud, env2)
    assert cloud.do.requests == []


async def test_a_manifest_without_digitalocean_keys_refuses(cloud):
    env = await dof.make_do_env()
    doc = yaml.safe_load(dof.DO_YML)
    doc.pop("edge")
    cloud.manifest_text = yaml.safe_dump(doc)
    with pytest.raises(ProvisionError, match="can't run on DigitalOcean"):
        await run_prepare(cloud, env)
    assert cloud.do.requests == []


async def test_another_team_writes_nothing(cloud):
    env = await dof.make_do_env()
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        row.provider_team = "another-team-uuid"
        await db.commit()
    with pytest.raises(ProvisionError) as err:
        await run_prepare(cloud, env)
    assert str(err.value) == ("do-main's token now answers for team Slipway Team, but shop was built in team "
                              "another-team-uuid. Slipway changed nothing: put back a token for another-team-uuid, "
                              "then retry")
    assert cloud.do.writes() == []


async def test_no_ssh_sources_refuses_before_the_firewall(cloud):
    account = await dof.make_account("bare", ssh_sources=[])
    env = await dof.make_do_env(account_id=account)
    with pytest.raises(ProvisionError, match="bare has no SSH sources"):
        await run_prepare(cloud, env)
    assert ("POST", "/firewalls") not in cloud.writes() and ("POST", "/droplets") not in cloud.writes()


async def test_firewall_drift_is_put_back_with_a_put_and_proven(cloud):
    env = await dof.make_do_env()
    await run_prepare(cloud, env)
    fw = next(iter(cloud.do.firewalls.values()))
    fw["inbound_rules"][0]["sources"]["addresses"] = ["0.0.0.0/0"]  # opened by hand
    cloud.do.requests.clear()
    cloud.sent.clear()
    await run_prepare(cloud, env)
    assert cloud.writes() == [("PUT", f"/firewalls/{fw['id']}")]
    assert fw["inbound_rules"][0]["sources"]["addresses"] == dof.SSH_SOURCES
    assert len(cloud.sent) >= 2  # the fresh proof connection, then the pin


async def test_firewall_change_that_locks_slipway_out_is_put_back(cloud):
    env = await dof.make_do_env()
    await run_prepare(cloud, env)
    fw = next(iter(cloud.do.firewalls.values()))
    fw["inbound_rules"][0]["sources"]["addresses"] = ["0.0.0.0/0"]
    cloud.multi.firewalled("203.0.113.1")
    with pytest.raises(ProvisionError) as err:
        await run_prepare(cloud, env)
    assert str(err.value) == ("After the cloud firewall's SSH rule changed, Slipway couldn't reach slipway-shop-blue "
                              "any more, so it put the previous rule back. Slipway connects from 198.51.100.7; keep "
                              "it in do-main's SSH sources")
    assert fw["inbound_rules"][0]["sources"]["addresses"] == ["0.0.0.0/0"]  # the previous body went back
    puts = [w for w in cloud.writes() if w[0] == "PUT"]
    assert len(puts) == 2


async def test_a_left_setup_key_and_a_foreign_grant(cloud):
    env = await dof.make_do_env()
    left = cloud.do.add_spaces_key(do_rules.spaces_key_name("shop", env.env_id, "a" * 16, setup=True),
                                   [{"bucket": "", "permission": "fullaccess"}])
    await run_prepare(cloud, env)
    assert left["access_key"] not in cloud.do.spaces_keys
    assert any("left by an earlier run" in line for line in cloud.log)
    env2 = await dof.make_do_env(name="shop3", account_id=env.account_id)
    cloud.do.add_spaces_key(do_rules.spaces_key_name("shop3", env2.env_id, "b" * 16),
                            [{"bucket": "someone-elses", "permission": "readwrite"}])
    cloud.do.requests.clear()
    with pytest.raises(ProvisionError, match="has grants on other buckets"):
        await run_prepare(cloud, env2)
    assert writes_after(cloud.do, "GET", "/spaces/keys") == []


async def test_gone_bucket_with_data_refuses_unless_made_again_empty(cloud):
    env = await dof.make_do_env(status="live")
    await run_prepare(cloud, env)
    bucket = do_rules.bucket_name("shop", env.env_id)
    cloud.spaces.buckets.pop(bucket)
    with pytest.raises(ProvisionError) as err:
        await run_prepare(cloud, env)
    assert str(err.value).startswith(f"shop's bucket {bucket} is gone from Spaces, and its files with it")
    await run_prepare(cloud, env, deployment_id=await deployment(env, rebuild_data=True))
    assert bucket in cloud.spaces.buckets
    assert [a.details["kind"] for a in await audits("resource.rebuild")] == ["bucket"]


async def test_cors_falls_back_to_the_setup_key(cloud):
    env = await dof.make_do_env()
    cloud.spaces.cors_needs_fullaccess = True
    await run_prepare(cloud, env)
    bucket = do_rules.bucket_name("shop", env.env_id)
    assert cloud.spaces.cors[bucket]
    assert len(cloud.do.spaces_keys) == 1  # the setup key it used is gone again


async def test_recover_prepare_leaves_a_creating_host_as_it_is(cloud):
    env = await dof.make_do_env()
    cloud.do.lose_answer[("POST", "/droplets")] = 1
    dep_id = await deployment(env)
    with pytest.raises(ProvisionError):
        await run_prepare(cloud, env, deployment_id=dep_id)
    before = await dof.host_row(env, "blue")
    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, dep_id)
        notes = await do_provision.recover_prepare(db, dep)
    after = await dof.host_row(env, "blue")
    assert after.provider_state == before.provider_state and after.host_key == before.host_key
    assert notes == ["slipway-shop-blue stays building with its host key: the next deploy to it finds out whether its "
                     "droplet was made"]
    assert do_provision.powered_off_notice("blue") == "blue's droplet may be powered off: deploy to blue again"


async def test_prepare_needs_a_droplet_host_of_the_environment(cloud):
    env = await dof.make_do_env()
    async with get_sessionmaker()() as db:
        other = Host(name="hand-added", hostname="10.0.0.9", username="root", metrics={})
        db.add(other)
        await db.flush()
        inst = await db.get(Instance, env.ids["blue"])
        inst.host_id = other.id
        await db.commit()
    with pytest.raises(ProvisionError, match="has no droplet host Slipway made"):
        await run_prepare(cloud, env)


def test_absent_twice_rule():
    t0 = do_provision.now()
    at = lambda s: t0 + timedelta(seconds=s)  # noqa: E731
    assert not do_provision.absent_twice(t0, [at(0), at(30), at(59)])
    assert not do_provision.absent_twice(t0, [at(60), at(100)])
    assert do_provision.absent_twice(t0, [at(10), at(60), at(120)])
    assert not do_provision.absent_twice(t0, [at(120)])


async def test_audit_rows_carry_no_secret(cloud):
    env = await dof.make_do_env()
    await run_prepare(cloud, env)
    text = json.dumps([[a.action, a.summary, a.details] for a in await audits()])
    secrets = [k["secret_key"] for k in cloud.do.spaces_keys.values()] + [fdo.TOKEN]
    for droplet_id in cloud.do.user_data:
        secrets.append(private_host_key(cloud.do, droplet_id).splitlines()[1])
    for value in secrets:
        assert value not in text
    actions = {a.action for a in await audits()}
    assert {"resource.pending", "resource.create", "resource.delete", "environment.team_frozen",
            "environment.slipway_address", "host.key_pinned"} <= actions
