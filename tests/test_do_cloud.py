"""The DigitalOcean provisioner, part 2 (phase 4 §9.3, §10.1-§10.2, §11.2-§11.5, §15.8, §15.11): the ``database``
and ``edge`` steps, the managed slot role's values, Remove slot's droplet, the certificate job and teardown.

Numbered tests of §20.2: 40 (the cluster and load balancer halves: gone objects, and 403s), 42 (``database``), 43
(``edge``), 45 (``destroy``), 46 (removing a droplet), 72 (two clusters of one name), 74 (the kept certificate)
and 75 (the certificate union). Also ``renew``, ``slot_values`` and every audit action this part writes, none of
which carries a secret.

Everything outside is a fake: FakeDigitalOcean (its clock drives every wait), FakeSpaces, FakeAcme validating
DNS-01 through FakeCloudflare's records, FakeCloudflare, and the droplets as hosts of the address-keyed
MultiRemote (tests/do_fixtures.py).
"""

from __future__ import annotations

import json
import types
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from slipway.db.session import get_sessionmaker
from slipway.models import AuditEvent, Deployment, Environment, Host, Instance, Resource
from slipway.services import acme, certs, cloudflare, do_provision, do_rules, resources
from slipway.services.do_provision import ProvisionError
from tests import do_fixtures as dof
from tests import fake_digitalocean as fdo
from tests.fake_acme import FakeAcme, FakeCloudflareTxt
from tests.fake_cloudflare import FakeCloudflare
from tests.fake_hosts import configure_cloudflare

ZONE = "example.com"
NAMES = sorted(f"{s}.shop.example.com" for s in ("api", "portal", "kiosk", "wiki"))

# ------------------------------------------------------------------------------------------------ fixtures


class Edge:
    """Cloudflare and ACME for the certificate: FakeCloudflare holds the zone and the challenge records, FakeAcme
    validates DNS-01 against them."""

    def __init__(self, monkeypatch: Any) -> None:
        self.cf = FakeCloudflare()
        self.zone_id = self.cf.add_zone(ZONE)
        monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(self.cf.handle))
        self.acme = FakeAcme(FakeCloudflareTxt(self.cf, self.zone_id).lookup)
        monkeypatch.setattr(acme, "transport_factory", lambda: httpx.MockTransport(self.acme.handle))

        async def no_wait(_seconds: float) -> None:
            return None
        monkeypatch.setattr(certs, "sleep", no_wait)
        monkeypatch.setattr(acme, "sleep", no_wait)
        settings = types.SimpleNamespace(acme_directory=self.acme.directory_url,
                                         acme_staging_directory=self.acme.directory_url + "-staging")
        monkeypatch.setattr(do_provision, "get_settings", lambda: settings)

    def orders(self, names: list[str] | None = None) -> int:
        return self.acme.orders[tuple(sorted(names or NAMES))]


@pytest.fixture
def cloud(tmp_path, monkeypatch) -> dof.Cloud:
    return dof.Cloud(tmp_path, monkeypatch)


@pytest.fixture
async def edge_fakes(monkeypatch) -> Edge:
    await configure_cloudflare(ZONE)
    return Edge(monkeypatch)


async def deployment(env: dof.DoEnv, slot: str = "blue", **options: Any) -> uuid.UUID:
    async with get_sessionmaker()() as db:
        dep = Deployment(instance_id=env.ids[slot], environment_id=env.env_id, branch="main", commit_sha=dof.SHA,
                         triggered_by_id=env.user_id, log="", options=options)
        db.add(dep)
        await db.commit()
        return dep.id


async def audits(action: str | None = None) -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        stmt = select(AuditEvent).order_by(AuditEvent.created_at)
        if action is not None:
            stmt = stmt.where(AuditEvent.action == action)
        return list(await db.scalars(stmt))


async def prepared(cloud: dof.Cloud, env: dof.DoEnv, slot: str = "blue", **kw: Any) -> do_provision.ProvisionContext:
    """A context that ran ``prepare`` (so its manifest is read and the slot's droplet is built)."""
    ctx = cloud.context(env, slot, **kw)
    await do_provision.prepare(ctx, read_manifest=cloud.read_manifest)
    return ctx


async def built(cloud: dof.Cloud, env: dof.DoEnv, slot: str = "blue", **kw: Any) -> do_provision.ProvisionContext:
    """``prepare``, ``database`` and ``edge`` for a slot, as a first deploy runs them."""
    ctx = await prepared(cloud, env, slot, **kw)
    await do_provision.database(ctx)
    await do_provision.edge(ctx)
    return ctx


def writes_since(fake: fdo.FakeDigitalOcean, mark: int) -> list[tuple[str, str]]:
    return [(r["method"], r["path"]) for r in fake.requests[mark:] if r["method"] != "GET"]


async def set_routes(env: dof.DoEnv, slot: str, routes: list[dict[str, Any]], **state: Any) -> None:
    async with get_sessionmaker()() as db:
        inst = await db.get(Instance, env.ids[slot])
        inst.app_state = {**(inst.app_state or {}), "routes": routes, **state}
        await db.commit()


def routes_without(*services: str) -> list[dict[str, Any]]:
    return [r for r in dof.routes("shop") if r["service"] not in services]


async def stored_text() -> str:
    out: list[str] = []
    async with get_sessionmaker()() as db:
        for row in await db.scalars(select(AuditEvent)):
            out.append(json.dumps([row.summary, row.details], default=str))
        for row in await db.scalars(select(Environment)):
            out.append(json.dumps([row.cloud, row.notice], default=str))
        for row in await db.scalars(select(Deployment)):
            out.append(json.dumps([row.options, row.log, row.error], default=str))
    return "\n".join(out)


def psql_runs(cloud: dof.Cloud, ip: str = "203.0.113.1") -> list[str]:
    return cloud.multi[ip].sql()


# ------------------------------------------------------------------------------------------ test 42: database


async def test_42_database_made_in_its_trusted_sources_with_the_role_on_stdin(cloud):
    env = await dof.make_do_env()
    ctx = await prepared(cloud, env)
    cloud.do.db_polls = 3  # the online wait
    got = await do_provision.database(ctx)

    # The create body names the recorded droplets as trusted sources, and the cluster is in the VPC.
    (post,) = [r["body"] for r in cloud.do.requests if (r["method"], r["path"]) == ("POST", "/databases")]
    (droplet_row,) = await dof.rows(env, "droplet")
    assert post["rules"] == [{"type": "droplet", "value": droplet_row.provider_id}]
    assert post["private_network_uuid"] == next(iter(cloud.do.vpcs))
    assert post["version"] == "16" and post["size"] == "db-s-1vcpu-1gb" and post["num_nodes"] == 1
    assert do_rules.request_tag(do_rules.request_nonce(post["tags"])) in post["tags"]
    (cluster,) = cloud.do.databases.values()
    assert cluster["status"] == "online"
    assert got.database_id == cluster["id"] and got.created

    # Recorded with doadmin's password in the same commit, then its private connection and CA.
    (row,) = await dof.rows(env, "database")
    assert row.credentials == {"admin_password": cluster["connection"]["password"]}
    assert row.details["host"] == cluster["private_connection"]["host"] and row.details["port"] == 25060
    assert row.details["ca_b64"]

    # The role SQL on the slot's droplet: the verifier, never the secret; password and CA on stdin only.
    (sql,) = psql_runs(cloud)
    secret = dof.SECRETS["POSTGRES_PASSWORD"]
    assert "SCRAM-SHA-256$4096:" in sql and secret not in sql
    assert 'CREATE ROLE "serversherpa" LOGIN' in sql and 'CREATE DATABASE "serversherpa"' in sql
    password = cluster["connection"]["password"]
    host = cloud.multi["203.0.113.1"]
    argv = "\n".join(host.docker()) + "\n".join(host.remote.commands)
    assert password not in argv and secret not in argv
    assert "postgres:16-alpine" in "\n".join(host.docker())
    logged = "\n".join(cloud.log) + await stored_text()
    assert password not in logged and secret not in logged and "SCRAM-SHA-256$" not in logged


async def test_42_drifted_sources_put_back_and_not_ready_retried(cloud):
    env = await dof.make_do_env()
    ctx = await prepared(cloud, env)
    await do_provision.database(ctx)
    (cluster,) = cloud.do.databases.values()
    cloud.do.db_rules[cluster["id"]] = []  # someone emptied them by hand
    cloud.do.firewall_wait = 2  # "not ready" twice
    mark = len(cloud.do.requests)
    await do_provision.database(ctx)
    puts = [w for w in writes_since(cloud.do, mark) if w[0] == "PUT"]
    assert puts == [("PUT", f"/databases/{cluster['id']}/firewall")] * 3
    (droplet_row,) = await dof.rows(env, "droplet")
    assert [r["value"] for r in cloud.do.db_rules[cluster["id"]]] == [droplet_row.provider_id]
    # A second run with nothing drifted writes nothing but the idempotent role SQL.
    mark = len(cloud.do.requests)
    await do_provision.database(ctx)
    assert writes_since(cloud.do, mark) == []


async def test_42_another_sources_error_says_it_may_be_reachable(cloud):
    env = await dof.make_do_env()
    ctx = await prepared(cloud, env)
    await do_provision.database(ctx)
    (cluster,) = cloud.do.databases.values()
    cloud.do.db_rules[cluster["id"]] = []
    cloud.do.fail[("PUT", f"/databases/{cluster['id']}/firewall")] = 500
    with pytest.raises(ProvisionError, match="may be reachable from any address. Retry: Slipway sets them again"):
        await do_provision.database(ctx)
    assert not psql_runs(cloud)[1:]  # nothing used the database after the failure


async def test_42_grows_only_upward_and_only_once_online(cloud):
    env = await dof.make_do_env()
    ctx = await prepared(cloud, env)
    await do_provision.database(ctx)
    (cluster,) = cloud.do.databases.values()

    async def set_cloud(**values: Any) -> None:
        async with get_sessionmaker()() as db:
            row = await db.get(Environment, env.env_id)
            row.cloud = {**row.cloud, **values, "plan": {**row.cloud["plan"], **values}}
            await db.commit()

    await set_cloud(db_size="db-s-2vcpu-4gb", db_nodes=2)
    mark = len(cloud.do.requests)
    got = await do_provision.database(ctx)
    resize = [r for r in cloud.do.requests[mark:] if r["method"] == "PUT" and r["path"].endswith("/resize")]
    assert [r["body"] for r in resize] == [{"size": "db-s-2vcpu-4gb", "num_nodes": 2}]
    # Only once online: the resize came after the cluster answered online.
    first_get = next(i for i, r in enumerate(cloud.do.requests[mark:]) if r["path"] == f"/databases/{cluster['id']}")
    assert first_get < cloud.do.requests[mark:].index(resize[0])
    assert cluster["size"] == "db-s-2vcpu-4gb" and cluster["num_nodes"] == 2 and cluster["status"] == "online"
    assert any("is now db-s-2vcpu-4gb" in n for n in got.notes)
    (row,) = await dof.rows(env, "database")
    assert row.details["size"] == "db-s-2vcpu-4gb" and row.details["nodes"] == 2

    # Smaller, or a standby taken away: left alone with a note.
    await set_cloud(db_size="db-s-1vcpu-2gb", db_nodes=1)
    mark = len(cloud.do.requests)
    got = await do_provision.database(ctx)
    assert not [r for r in cloud.do.requests[mark:] if r["path"].endswith("/resize")]
    assert any("stays db-s-2vcpu-4gb" in n for n in got.notes)


async def test_42_a_cluster_of_another_version_stops(cloud):
    env = await dof.make_do_env()
    ctx = await prepared(cloud, env)
    await do_provision.database(ctx)
    (cluster,) = cloud.do.databases.values()
    cluster["version"] = "15"
    with pytest.raises(ProvisionError, match="runs PostgreSQL 15, but shop was made for 16. Slipway changed nothing"):
        await do_provision.database(ctx)


async def test_42_psql_refusing_fails_the_step(cloud):
    env = await dof.make_do_env()
    ctx = await prepared(cloud, env)
    cloud.multi["203.0.113.1"].env["FAKE_PSQL"] = "psql: error: password authentication failed"
    with pytest.raises(ProvisionError, match=r"didn't accept Slipway's setup \(psql exited 2\)"):
        await do_provision.database(ctx)


# ------------------------------------------------------------------------------------- test 72: two clusters


async def test_72_two_clusters_of_one_name_stop_with_no_write(cloud):
    env = await dof.make_do_env()
    ctx = await prepared(cloud, env)
    tags = ["slipway", do_rules.env_tag(env.env_id), "slipway-env:shop"]
    a = cloud.do.add_database(name="slipway-shop-db", tags=tags)
    b = cloud.do.add_database(name="slipway-shop-db-x", tags=tags)
    cloud.do.databases[b["id"]]["name"] = "slipway-shop-db"
    mark = len(cloud.do.requests)
    with pytest.raises(ProvisionError) as exc:
        await do_provision.database(ctx)
    assert a["id"] in str(exc.value) and b["id"] in str(exc.value)
    assert writes_since(cloud.do, mark) == []


async def test_an_unrecorded_cluster_of_our_name_is_never_adopted(cloud):
    env = await dof.make_do_env()
    ctx = await prepared(cloud, env)
    cloud.do.add_database(name="slipway-shop-db", tags=["slipway", do_rules.env_tag(env.env_id)])
    mark = len(cloud.do.requests)
    with pytest.raises(ProvisionError, match="Slipway has no record of making it"):
        await do_provision.database(ctx)
    assert writes_since(cloud.do, mark) == []


# ---------------------------------------------------------------------- test 40: the cluster and load balancer


async def test_40_a_gone_cluster_without_data_is_made_again(cloud):
    env = await dof.make_do_env()
    ctx = await prepared(cloud, env)
    await do_provision.database(ctx)
    (old,) = list(cloud.do.databases)
    del cloud.do.databases[old]
    await do_provision.database(ctx)
    (new,) = list(cloud.do.databases)
    assert new != old
    (row,) = await dof.rows(env, "database")
    assert row.provider_id == new
    assert [a.details["kind"] for a in await audits("resource.rebuild")] == ["database"]


async def test_40_a_gone_cluster_with_data_refuses_until_made_again_empty(cloud):
    env = await dof.make_do_env(status="live")
    ctx = await prepared(cloud, env)
    await do_provision.database(ctx)
    (old,) = list(cloud.do.databases)
    del cloud.do.databases[old]
    mark = len(cloud.do.requests)
    with pytest.raises(ProvisionError, match='and its data with it. Slipway won\'t make an empty one by itself: retry '
                                             'with "Make it again, empty"'):
        await do_provision.database(ctx)
    assert writes_since(cloud.do, mark) == []
    assert [r.provider_id for r in await dof.rows(env, "database")] == [old]  # nothing forgotten

    dep = await deployment(env, rebuild_data=True)
    retry = cloud.context(env, "blue", deployment_id=dep, manifest=ctx.manifest)
    await do_provision.database(retry)
    assert len(cloud.do.databases) == 1 and old not in cloud.do.databases
    async with get_sessionmaker()() as db:
        assert (await db.get(Deployment, dep)).options["rebuild"] == ["database"]


async def test_40_a_gone_load_balancer_is_remade_and_the_slots_become_stale(cloud, edge_fakes):
    env = await dof.make_do_env()
    ctx = await built(cloud, env)
    (lb,) = cloud.do.load_balancers.values()
    old_ip = lb["ip"]
    # Both slots are live and their .env names the load balancer's address.
    for slot in ("blue", "green"):
        await set_routes(env, slot, dof.routes("shop"), live={"edge": {"address": old_ip}, "sha": dof.SHA})
        async with get_sessionmaker()() as db:
            inst = await db.get(Instance, env.ids[slot])
            inst.current_commit_sha = dof.SHA
            await db.commit()
    del cloud.do.load_balancers[lb["id"]]
    got = await do_provision.edge(ctx)
    (new,) = cloud.do.load_balancers.values()
    assert new["id"] != lb["id"] and new["ip"] != old_ip and new["droplet_ids"] == []
    row = await dof.env_row(env)
    assert row.cloud["lb_ip"] == new["ip"] and row.traffic["dns"]["address"] == new["ip"]
    async with get_sessionmaker()() as db:
        green = await db.get(Instance, env.ids["green"])
        blue = await db.get(Instance, env.ids["blue"])
    assert green.slot_state["stale"]["reason"] == do_provision.STALE_LB
    assert "stale" not in (blue.slot_state or {})  # the deploying slot writes the new address itself
    assert any("address is now" in n for n in got.notes)
    assert "load_balancer" in [a.details["kind"] for a in await audits("resource.rebuild")]
    # The firewall's load balancer rule follows the new load balancer.
    (fw,) = cloud.do.firewalls.values()
    assert any(new["id"] in (r["sources"].get("load_balancer_uids") or []) for r in fw["inbound_rules"])


@pytest.mark.parametrize(("kind", "step"), [("databases", "database"), ("load_balancers", "edge"),
                                             ("certificates", "edge")])
async def test_40_a_403_stops_the_step_and_forgets_nothing(cloud, edge_fakes, kind, step):
    env = await dof.make_do_env()
    ctx = await built(cloud, env)
    before = [(r.kind, r.provider_id) for r in await dof.rows(env)]
    cloud.do.forbid.add(kind)
    mark = len(cloud.do.requests)
    with pytest.raises(ProvisionError, match=r"do-main's token can't .* \(DigitalOcean answered 403\)\. Slipway "
                                             "changed nothing: give the token that scope, then retry"):
        await getattr(do_provision, step)(ctx)
    assert writes_since(cloud.do, mark) == []
    assert [(r.kind, r.provider_id) for r in await dof.rows(env)] == before


# ------------------------------------------------------------------------------------------ test 43: edge


async def test_43_edge_on_a_new_environment(cloud, edge_fakes):
    env = await dof.make_do_env()
    ctx = await prepared(cloud, env)
    await do_provision.database(ctx)
    mark = len(cloud.do.requests)
    got = await do_provision.edge(ctx)

    # cloud.edge frozen and audited.
    row = await dof.env_row(env)
    assert row.cloud["edge"] == {"port": 80, "health": "/healthz"}
    (frozen,) = await audits("environment.edge_frozen")
    assert (frozen.target_type, frozen.target_id) == ("environment", str(env.env_id))
    assert frozen.details == {"port": 80, "health": "/healthz"}

    # The certificate: every active-following name, none for spaces (a skipped service), from one order.
    (cert,) = cloud.do.certificates.values()
    assert sorted(cert["dns_names"]) == NAMES and not any("spaces." in n for n in cert["dns_names"])
    assert certs.name_pattern("shop").match(cert["name"])
    assert edge_fakes.orders() == 1
    (issued,) = await audits("certificate.issue")
    assert issued.details["names"] == NAMES and issued.details["staging"] is False
    assert issued.details["not_after"] and issued.details["certificate"] == cert["name"]
    (cert_row,) = await dof.rows(env, "certificate")
    assert cert_row.provider_id == cert["id"] and cert_row.credentials is None
    assert sorted(cert_row.details["dns_names"]) == NAMES
    assert row.cloud["certificate"] == {"id": cert["id"], "name": cert["name"], "not_after": cert["not_after"],
                                        "names": NAMES}
    assert not edge_fakes.cf.records  # the challenge records went with the order

    # The load balancer: no targets, the HTTPS rule on the certificate, in the VPC, HTTP to edge.port.
    (lb,) = cloud.do.load_balancers.values()
    (lb_post,) = [r["body"] for r in cloud.do.requests[mark:]
                  if (r["method"], r["path"]) == ("POST", "/load_balancers")]
    assert lb_post["droplet_ids"] == [] and lb_post["vpc_uuid"] == next(iter(cloud.do.vpcs))
    assert do_rules.https_certificate(lb) == cert["id"]
    assert lb_post["health_check"]["path"] == "/healthz" and lb_post["health_check"]["port"] == 80
    assert row.cloud["lb_ip"] == lb["ip"] == got.lb_ip and row.traffic["dns"]["address"] == lb["ip"]
    assert got.certificate["id"] == cert["id"] and got.issued

    # The firewall gains the load balancer's rule with one PUT.
    (fw,) = cloud.do.firewalls.values()
    puts = [w for w in writes_since(cloud.do, mark) if w == ("PUT", f"/firewalls/{fw['id']}")]
    assert len(puts) == 1
    assert any(r["sources"].get("load_balancer_uids") == [lb["id"]] and r["ports"] == "80" for r in fw["inbound_rules"])
    (fw_row,) = await dof.rows(env, "firewall")
    assert fw_row.details["lb_rule"] is True

    # Order: the certificate upload, then the load balancer, then the firewall.
    writes = writes_since(cloud.do, mark)
    assert writes.index(("POST", "/certificates")) < writes.index(("POST", "/load_balancers")) \
        < writes.index(("PUT", f"/firewalls/{fw['id']}"))

    # A second edge writes nothing.
    mark = len(cloud.do.requests)
    acme_requests = len(edge_fakes.acme.requests)
    await do_provision.edge(ctx)
    assert writes_since(cloud.do, mark) == []
    assert len(edge_fakes.acme.requests) == acme_requests

    # No certificate key, token or doadmin password anywhere it shouldn't be.
    text = await stored_text() + "\n".join(cloud.log)
    assert fdo.TOKEN not in text and "PRIVATE KEY" not in text


async def test_43_an_existing_load_balancer_on_another_certificate_gets_one_put(cloud, edge_fakes):
    env = await dof.make_do_env()
    ctx = await built(cloud, env)
    (lb,) = cloud.do.load_balancers.values()
    (first,) = cloud.do.certificates.values()
    # The certificate is due: the next edge orders a new one and points the load balancer at it.
    cloud.do.certificates[first["id"]]["not_after"] = (datetime.now(UTC) + timedelta(days=10)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    cloud.do.lb_apply_polls = 2
    mark = len(cloud.do.requests)
    await do_provision.edge(ctx)
    lb_puts = [r for r in cloud.do.requests[mark:]
               if (r["method"], r["path"]) == ("PUT", f"/load_balancers/{lb['id']}")]
    assert len(lb_puts) == 1
    body = lb_puts[0]["body"]
    assert "id" not in body and "ip" not in body and body["region"] == "nyc3" and "tag" not in body
    new = do_rules.https_certificate(cloud.do.load_balancers[lb["id"]])
    assert new != first["id"]
    # The put came after an active wait, and the old certificate is deleted once nothing serves it.
    put_at = cloud.do.requests.index(lb_puts[0])
    assert cloud.do.requests[put_at - 1]["path"] == f"/load_balancers/{lb['id']}"
    assert first["id"] not in cloud.do.certificates
    assert edge_fakes.orders() == 2
    deleted = [a.details for a in await audits("resource.delete") if a.details["kind"] == "certificate"]
    assert [d["provider_id"] for d in deleted] == [first["id"]]


async def test_43_an_old_certificate_still_in_use_is_left_for_the_next_run(cloud, edge_fakes):
    env = await dof.make_do_env()
    ctx = await built(cloud, env)
    (first,) = cloud.do.certificates.values()
    cloud.do.certificates[first["id"]]["not_after"] = (datetime.now(UTC) + timedelta(days=5)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    cloud.do._cert_in_use[first["id"]] = 1  # DigitalOcean still calls it in use once
    await do_provision.edge(ctx)
    assert first["id"] in cloud.do.certificates
    assert any("still in use; the next run deletes it" in line for line in cloud.log)
    await do_provision.edge(ctx)
    assert first["id"] not in cloud.do.certificates


async def test_43_a_hand_edited_forwarding_port_stops(cloud, edge_fakes):
    env = await dof.make_do_env()
    ctx = await built(cloud, env)
    (lb,) = cloud.do.load_balancers.values()
    for rule in lb["forwarding_rules"]:
        rule["target_port"] = 8080
    mark = len(cloud.do.requests)
    with pytest.raises(ProvisionError, match="slipway-shop-lb no longer forwards to port 80: Slipway changed nothing"):
        await do_provision.edge(ctx)
    assert writes_since(cloud.do, mark) == []


async def test_43_firewall_drift_is_put_back_with_a_put(cloud, edge_fakes):
    env = await dof.make_do_env()
    ctx = await built(cloud, env)
    (fw,) = cloud.do.firewalls.values()
    fw["inbound_rules"] = [r for r in fw["inbound_rules"] if not r["sources"].get("load_balancer_uids")]
    mark = len(cloud.do.requests)
    await do_provision.edge(ctx)
    assert writes_since(cloud.do, mark) == [("PUT", f"/firewalls/{fw['id']}")]
    assert any(r["sources"].get("load_balancer_uids") for r in cloud.do.firewalls[fw["id"]]["inbound_rules"])


async def _new_sources(env: dof.DoEnv, sources: list[str]) -> None:
    from slipway.models import ProviderAccount
    async with get_sessionmaker()() as db:
        account = await db.get(ProviderAccount, env.account_id)
        account.config = {**account.config, "ssh_sources": sources}
        await db.commit()


async def test_43_an_ssh_rule_change_is_proven_with_a_fresh_connection(cloud, edge_fakes):
    env = await dof.make_do_env()
    ctx = await built(cloud, env)
    await _new_sources(env, ["198.51.100.0/24", "192.0.2.0/24"])
    opened = len(cloud.multi.opened)
    await do_provision.edge(ctx)
    (fw,) = cloud.do.firewalls.values()
    assert do_rules.firewall_ssh_sources(fw) == {"198.51.100.0/24", "192.0.2.0/24"}
    assert cloud.multi.opened[opened:] == ["203.0.113.1"]  # one fresh connection to the built droplet


async def test_43_an_ssh_rule_change_that_locks_slipway_out_is_put_back(cloud, edge_fakes):
    env = await dof.make_do_env()
    ctx = await built(cloud, env)
    (fw,) = cloud.do.firewalls.values()
    before = json.loads(json.dumps(fw["inbound_rules"]))
    await _new_sources(env, ["192.0.2.0/24"])
    cloud.multi.firewalled("203.0.113.1")
    mark = len(cloud.do.requests)
    with pytest.raises(ProvisionError, match="couldn't reach slipway-shop-blue any more, so it put the previous rule "
                                             r"back. Slipway connects from 198\.51\.100\.7; keep it in do-main's SSH "
                                             "sources"):
        await do_provision.edge(ctx)
    assert writes_since(cloud.do, mark) == [("PUT", f"/firewalls/{fw['id']}")] * 2
    assert cloud.do.firewalls[fw["id"]]["inbound_rules"] == before


async def test_43_without_cloudflare_the_certificate_step_stops(cloud):
    env = await dof.make_do_env()
    ctx = await prepared(cloud, env)
    with pytest.raises(ProvisionError, match="Cloudflare integration, which isn't set up"):
        await do_provision.edge(ctx)
    assert not cloud.do.certificates and not cloud.do.load_balancers


# ----------------------------------------------------------------------------- test 74: the kept certificate


async def test_74_failed_uploads_reuse_the_kept_certificate(cloud, edge_fakes):
    env = await dof.make_do_env()
    ctx = await prepared(cloud, env)
    cloud.do.fail[("POST", "/certificates")] = [500, 500, 500]
    for _ in range(3):
        with pytest.raises(ProvisionError, match="DigitalOcean had a problem"):
            await do_provision.edge(ctx)
        (kept,) = await dof.rows(env, "certificate")
        assert resources.is_pending(kept) and kept.credentials["private_key"]
        assert sorted(kept.details["dns_names"]) == NAMES
    await do_provision.edge(ctx)
    assert edge_fakes.orders() == 1  # never ordered again
    (row,) = await dof.rows(env, "certificate")
    assert not resources.is_pending(row) and row.credentials is None and row.id == kept.id
    (cert,) = cloud.do.certificates.values()
    assert cert["name"] == kept.name
    posts = [r for r in cloud.do.requests if (r["method"], r["path"]) == ("POST", "/certificates")]
    assert len(posts) == 4 and len({p["body"]["name"] for p in posts}) == 1
    assert len(await audits("certificate.issue")) == 1


async def test_74_a_restart_between_the_order_and_the_upload_uploads_the_kept_one(cloud, edge_fakes, monkeypatch):
    env = await dof.make_do_env()
    ctx = await prepared(cloud, env)

    class Restart(BaseException):
        pass

    real = do_provision.DigitalOceanClient.create_certificate

    async def cut(self, body):
        raise Restart

    monkeypatch.setattr(do_provision.DigitalOceanClient, "create_certificate", cut)
    with pytest.raises(Restart):
        await do_provision.edge(ctx)
    monkeypatch.setattr(do_provision.DigitalOceanClient, "create_certificate", real)
    (kept,) = await dof.rows(env, "certificate")
    assert resources.is_pending(kept) and kept.credentials["leaf"]
    again = cloud.context(env, "blue", manifest=ctx.manifest)
    await do_provision.edge(again)
    assert edge_fakes.orders() == 1
    (row,) = await dof.rows(env, "certificate")
    assert row.credentials is None and not resources.is_pending(row)


async def test_74_a_kept_certificate_with_30_days_or_fewer_is_ordered_again(cloud, edge_fakes):
    env = await dof.make_do_env()
    ctx = await prepared(cloud, env)
    edge_fakes.acme.not_after = datetime.now(UTC) + timedelta(days=20)
    cloud.do.fail[("POST", "/certificates")] = [500]
    with pytest.raises(ProvisionError):
        await do_provision.edge(ctx)
    edge_fakes.acme.not_after = None
    await do_provision.edge(ctx)
    assert edge_fakes.orders() == 2
    (row,) = await dof.rows(env, "certificate")
    assert not resources.is_pending(row)
    assert certs.not_after(row.details) > datetime.now(UTC) + timedelta(days=60)
    assert any("Dropped the kept certificate" in line for line in cloud.log)


async def test_74_a_lost_upload_answer_is_recorded_not_uploaded_again(cloud, edge_fakes):
    env = await dof.make_do_env()
    ctx = await prepared(cloud, env)
    cloud.do.lose_answer[("POST", "/certificates")] = 1
    with pytest.raises(ProvisionError):
        await do_provision.edge(ctx)
    await do_provision.edge(ctx)
    assert len(cloud.do.certificates) == 1 and edge_fakes.orders() == 1
    (row,) = await dof.rows(env, "certificate")
    assert row.credentials is None and row.provider_id in cloud.do.certificates


# ----------------------------------------------------------------------------- test 75: the certificate union


async def test_75_a_name_leaves_only_when_no_live_slot_serves_it(cloud, edge_fakes):
    env = await dof.make_do_env()
    with_learn = dof.routes("shop") + [{"hostname": "learn.shop.example.com", "service": "learn", "container": 8092,
                                        "follows": "active", "health": "/"}]
    all_names = sorted(NAMES + ["learn.shop.example.com"])
    ctx = await prepared(cloud, env)
    await do_provision.database(ctx)
    await do_provision.edge(ctx, deploying_routes=with_learn)
    await set_routes(env, "blue", with_learn)
    (first,) = cloud.do.certificates.values()
    assert sorted(first["dns_names"]) == all_names

    # Green's release drops learn; blue's live release still serves it: the certificate keeps it.
    green = await prepared(cloud, env, "green")
    await do_provision.database(green)
    await do_provision.edge(green, deploying_routes=dof.routes("shop"))
    assert list(cloud.do.certificates) == [first["id"]]
    await set_routes(env, "green", dof.routes("shop"))

    # Blue deployed without it too: the next edge issues a certificate without learn.
    await set_routes(env, "blue", dof.routes("shop"))
    await do_provision.edge(ctx, deploying_routes=dof.routes("shop"))
    (second,) = cloud.do.certificates.values()
    assert second["id"] != first["id"] and sorted(second["dns_names"]) == NAMES
    assert edge_fakes.orders(all_names) == 1 and edge_fakes.orders(NAMES) == 1


# ------------------------------------------------------------------------------------------- renew (§15.8)


async def test_renew_orders_a_new_certificate_when_due_and_swaps_it(cloud, edge_fakes):
    env = await dof.make_do_env()
    ctx = await built(cloud, env)
    await set_routes(env, "blue", dof.routes("shop"))
    (first,) = cloud.do.certificates.values()
    cloud.do.certificates[first["id"]]["not_after"] = (datetime.now(UTC) + timedelta(days=29)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    job = cloud.context(env, None)
    note = await do_provision.renew(job)
    assert note.startswith("Renewed: slipway-shop-")
    (lb,) = cloud.do.load_balancers.values()
    (cert,) = cloud.do.certificates.values()
    assert do_rules.https_certificate(lb) == cert["id"] != first["id"]
    assert (await dof.env_row(env)).cloud["certificate"]["id"] == cert["id"]
    assert await do_provision.renew(job) == f"{cert['name']} is still good, valid until " \
        f"{certs.not_after(cert).strftime('%Y-%m-%d')}; nothing to renew"


async def test_renew_stops_when_the_load_balancer_serves_a_certificate_that_isnt_ours(cloud, edge_fakes, monkeypatch):
    env = await dof.make_do_env()
    ctx = await built(cloud, env)
    await set_routes(env, "blue", dof.routes("shop"))
    (lb,) = cloud.do.load_balancers.values()
    (first,) = cloud.do.certificates.values()
    cloud.do.certificates[first["id"]]["not_after"] = (datetime.now(UTC) + timedelta(days=3)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    foreign = cloud.do.add_certificate("someone-elses", NAMES)
    real = do_provision.DigitalOceanClient.update_load_balancer

    async def swap(self, lb_id, body):
        out = await real(self, lb_id, body)
        for rule in cloud.do.load_balancers[lb_id]["forwarding_rules"]:
            if rule["entry_protocol"] == "https":
                rule["certificate_id"] = foreign["id"]  # another writer swapped it in meanwhile
        return out

    monkeypatch.setattr(do_provision.DigitalOceanClient, "update_load_balancer", swap)
    with pytest.raises(ProvisionError, match="serves a certificate that isn't Slipway's for shop. Slipway deleted "
                                             "nothing"):
        await do_provision.renew(cloud.context(env, None))
    assert first["id"] in cloud.do.certificates


# ----------------------------------------------------------------------------------------- slot_values


async def test_slot_values_give_the_managed_data_and_the_edge(cloud, edge_fakes):
    env = await dof.make_do_env()
    ctx = await built(cloud, env)
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        inst = await db.get(Instance, env.ids["blue"])
        values, edge_values = await do_provision.slot_values(db, row, inst, man=ctx.manifest)
    (cluster,) = cloud.do.databases.values()
    (key_row,) = await dof.rows(env, "spaces_key")
    assert values["db"] == {"host": cluster["private_connection"]["host"], "port": "25060", "database": "serversherpa",
                            "user": "serversherpa", "password": dof.SECRETS["POSTGRES_PASSWORD"], "tls": "require",
                            "ca_b64": (await dof.rows(env, "database"))[0].details["ca_b64"]}
    assert values["objects"] == {"endpoint": "https://nyc3.digitaloceanspaces.com", "region": "nyc3",
                                 "bucket": do_rules.bucket_name("shop", env.env_id), "access_key": key_row.provider_id,
                                 "secret_key": key_row.credentials["secret_key"], "path_style": "false"}
    (lb,) = cloud.do.load_balancers.values()
    assert edge_values == {"address": lb["ip"], "trusted": row.cloud["vpc_range"]}


async def test_slot_values_before_the_database_is_made_says_so(cloud):
    env = await dof.make_do_env()
    ctx = await prepared(cloud, env)
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        with pytest.raises(ProvisionError, match="database cluster isn't set up yet: deploy to a slot first"):
            await do_provision.slot_values(db, row, None, man=ctx.manifest)


# ------------------------------------------------------------------------------- test 46: remove a droplet


async def test_46_remove_a_droplet_in_order_and_retry(cloud, edge_fakes):
    env = await dof.make_do_env()
    await built(cloud, env, "blue")
    green = await prepared(cloud, env, "green")
    await do_provision.database(green)
    (cluster,) = cloud.do.databases.values()
    droplets = {r.name: r.provider_id for r in await dof.rows(env, "droplet")}
    green_id = droplets["slipway-shop-green"]
    assert {r["value"] for r in cloud.do.db_rules[cluster["id"]]} == set(droplets.values())

    job = cloud.context(env, None)
    cloud.do.fail[("DELETE", f"/droplets/{green_id}")] = [500]
    with pytest.raises(ProvisionError):
        await do_provision.remove_droplet(job, "green")
    # Everything kept: the row, the instance, the host, the plan.
    assert green_id in {r.provider_id for r in await dof.rows(env, "droplet")}
    async with get_sessionmaker()() as db:
        assert await db.get(Instance, env.ids["green"]) is not None
        assert await db.get(Host, env.host_ids["green"]) is not None
    assert (await dof.env_row(env)).cloud["plan"]["droplets"] == 2

    order: list[str] = []
    real_forget, real_set = resources.forget, do_provision.DigitalOceanClient.set_database_firewall
    real_instance, real_host = do_provision._delete_slot_instance, do_provision._delete_host
    real_drop = do_provision._drop_plan

    async def forget(row_id, **kw):
        order.append("row")
        return await real_forget(row_id, **kw)

    async def set_fw(self, db_id, rules):
        order.append("sources")
        return await real_set(self, db_id, rules)

    async def del_instance(ctx, slot):
        order.append("instance")
        return await real_instance(ctx, slot)

    async def del_host(ctx, host_id):
        order.append("host")
        return await real_host(ctx, host_id)

    async def drop(ctx, client, account):
        order.append("plan")
        return await real_drop(ctx, client, account)

    mp = pytest.MonkeyPatch()
    mp.setattr(resources, "forget", forget)
    mp.setattr(do_provision.DigitalOceanClient, "set_database_firewall", set_fw)
    mp.setattr(do_provision, "_delete_slot_instance", del_instance)
    mp.setattr(do_provision, "_delete_host", del_host)
    mp.setattr(do_provision, "_drop_plan", drop)
    mark = len(cloud.do.requests)
    try:
        note = await do_provision.remove_droplet(job, "green")
    finally:
        mp.undo()
    assert order == ["row", "sources", "instance", "host", "plan"]
    first_write = writes_since(cloud.do, mark)[0]
    assert first_write == ("DELETE", f"/droplets/{green_id}")
    assert int(green_id) not in cloud.do.droplets
    assert [r["value"] for r in cloud.do.db_rules[cluster["id"]]] == [droplets["slipway-shop-blue"]]
    async with get_sessionmaker()() as db:
        assert await db.get(Instance, env.ids["green"]) is None
        assert await db.get(Host, env.host_ids["green"]) is None
    row = await dof.env_row(env)
    assert row.cloud["plan"]["droplets"] == 1 and "one droplet" in note
    assert row.cloud["cost"]["total_cents"] < 4700 + 100_000
    (resized,) = await audits("environment.resize")
    assert resized.details["to"] == {"droplets": 1}
    assert await do_provision.remove_droplet(job, "green") == "Already removed"


# --------------------------------------------------------------------------------------- test 45: destroy


async def teardown_ready(env: dof.DoEnv) -> None:
    """What teardown's ``slots`` and ``data_server`` steps leave: no instance rows."""
    from sqlalchemy import delete
    async with get_sessionmaker()() as db:
        await db.execute(delete(Instance).where(Instance.environment_id == env.env_id))
        await db.commit()


def nothing_left(cloud: dof.Cloud) -> None:
    fake = cloud.do
    assert not fake.droplets and not fake.databases and not fake.vpcs and not fake.load_balancers
    assert not fake.firewalls and not fake.certificates and not fake.spaces_keys
    assert not cloud.spaces.buckets


async def test_45_destroy_finds_checks_then_deletes_in_order(cloud, edge_fakes):
    env = await dof.make_do_env()
    await built(cloud, env)
    cloud.spaces.put(do_rules.bucket_name("shop", env.env_id), "uploads/a.png", b"png")
    # A stray droplet with both tags (a lost answer) and one with the env tag alone (someone else's).
    tags = ["slipway", do_rules.env_tag(env.env_id), "slipway-env:shop", "slipway-slot:green"]
    stray = cloud.do.add_droplet(name="slipway-shop-green", tags=tags)
    other = cloud.do.add_droplet(name="slipway-shop-other", tags=[do_rules.env_tag(env.env_id)])
    # A full-access setup key a stopped run left.
    left = cloud.do.add_spaces_key(do_rules.spaces_key_name("shop", env.env_id, "ab" * 8, setup=True),
                                   [{"bucket": "", "permission": "fullaccess"}])
    cloud.do.cert_in_use_polls = 0
    (cert,) = cloud.do.certificates.values()
    cloud.do._cert_in_use[cert["id"]] = 2  # still in use right after its load balancer went
    cloud.do.member_linger = 25.0
    await teardown_ready(env)
    mark = len(cloud.do.requests)
    done = await do_provision.destroy(cloud.context(env, None))
    assert done == "Nothing of shop is left on DigitalOcean."
    # The certificate still in use, and the VPC whose members lingered, were tried again.
    assert len([w for w in writes_since(cloud.do, mark) if w == ("DELETE", f"/certificates/{cert['id']}")]) == 3
    assert len([w for w in writes_since(cloud.do, mark) if w[0] == "DELETE" and w[1].startswith("/vpcs/")]) > 1

    writes = writes_since(cloud.do, mark)
    kinds = []
    for method, path in writes:
        if method != "DELETE":
            continue
        head = path.split("/")[1]
        kinds.append({"spaces": "spaces_keys"}.get(head, head))
    collapsed = [k for i, k in enumerate(kinds) if i == 0 or kinds[i - 1] != k]
    assert collapsed == ["load_balancers", "certificates", "firewalls", "droplets", "databases", "spaces_keys", "vpcs"]
    assert list(cloud.do.droplets) == [other["id"]]  # the env tag alone is left
    del cloud.do.droplets[other["id"]]
    nothing_left(cloud)
    assert stray["id"] not in cloud.do.droplets and left["access_key"] not in cloud.do.spaces_keys
    assert await dof.rows(env) == []
    async with get_sessionmaker()() as db:
        assert list(await db.scalars(select(Host).where(Host.owner_environment_id == env.env_id))) == []
    adopted = [a.details for a in await audits("resource.adopt") if a.details.get("rule") == "teardown"]
    assert {a["provider_id"] for a in adopted} >= {str(stray["id"]), left["access_key"]}
    deleted = {a.details["kind"] for a in await audits("resource.delete")}
    assert deleted >= {"load_balancer", "certificate", "firewall", "droplet", "database", "spaces_key", "bucket", "vpc"}


async def test_45_one_renamed_object_means_no_delete_at_all(cloud, edge_fakes):
    env = await dof.make_do_env()
    await built(cloud, env)
    (fw,) = cloud.do.firewalls.values()
    fw["name"] = "renamed-by-hand"
    await teardown_ready(env)
    mark = len(cloud.do.requests)
    with pytest.raises(ProvisionError, match=f"Firewall {fw['id']} no longer looks like Slipway's slipway-shop-fw. "
                                             "Slipway changed nothing"):
        await do_provision.destroy(cloud.context(env, None))
    assert writes_since(cloud.do, mark) == []


@pytest.mark.parametrize("kind", ["certificates", "load_balancers", "spaces_keys", "firewalls", "databases"])
async def test_45_a_403_stops_before_any_delete(cloud, edge_fakes, kind):
    env = await dof.make_do_env()
    await built(cloud, env)
    await teardown_ready(env)
    cloud.do.forbid.add(kind)
    mark = len(cloud.do.requests)
    with pytest.raises(ProvisionError, match=r"\(DigitalOcean answered 403\)"):
        await do_provision.destroy(cloud.context(env, None))
    assert not [w for w in writes_since(cloud.do, mark) if w[0] == "DELETE"]


async def test_45_a_vpc_403_with_no_members_stops_at_once(cloud, edge_fakes):
    env = await dof.make_do_env()
    await built(cloud, env)
    await teardown_ready(env)
    (vpc_id,) = list(cloud.do.vpcs)
    cloud.do.fail[("DELETE", f"/vpcs/{vpc_id}")] = 403
    with pytest.raises(ProvisionError, match="do-main's token can't delete VPCs"):
        await do_provision.destroy(cloud.context(env, None))
    assert vpc_id in cloud.do.vpcs and not cloud.do.droplets


async def test_45_a_vpc_whose_members_never_go_names_them(cloud, edge_fakes):
    env = await dof.make_do_env()
    await built(cloud, env)
    await teardown_ready(env)
    cloud.do.member_linger = 10_000.0
    with pytest.raises(ProvisionError, match=r"still has members after 10 minutes \(.*slipway-shop-blue"):
        await do_provision.destroy(cloud.context(env, None))


LOST = [
    ("POST", "/vpcs"), ("POST", "/firewalls"), ("POST", "/droplets"), ("POST", "/databases"),
    ("POST", "/load_balancers"), ("POST", "/certificates"), ("POST", "/spaces/keys"),
]


@pytest.mark.parametrize("lost", LOST, ids=[p for _m, p in LOST])
async def test_45_a_lost_create_answer_is_found_and_deleted(cloud, edge_fakes, lost):
    env = await dof.make_do_env()
    cloud.do.lose_answer[lost] = 1 if lost != ("POST", "/spaces/keys") else 2  # the bucket's own key
    try:
        await built(cloud, env)
    except (ProvisionError, Exception):  # noqa: BLE001 - the step whose answer was lost fails; no retry follows
        pass
    assert any(resources.is_pending(r) for r in await dof.rows(env)) or lost == ("POST", "/spaces/keys")
    await teardown_ready(env)
    await do_provision.destroy(cloud.context(env, None))
    nothing_left(cloud)
    assert await dof.rows(env) == []


async def test_45_a_lost_answer_of_the_teardowns_own_setup_key_is_caught(cloud, edge_fakes):
    env = await dof.make_do_env()
    await built(cloud, env)
    await teardown_ready(env)
    cloud.do.lose_answer[("POST", "/spaces/keys")] = 1
    await do_provision.destroy(cloud.context(env, None))
    nothing_left(cloud)
    assert await dof.rows(env) == []


async def test_45_challenge_records_left_for_the_environment_are_swept(cloud, edge_fakes):
    env = await dof.make_do_env()
    await built(cloud, env)
    await teardown_ready(env)
    cf = edge_fakes.cf
    mine = cf.add_record(edge_fakes.zone_id, "TXT", "_acme-challenge.api.shop.example.com", "x",
                         comment=certs.CHALLENGE_COMMENT)
    elsewhere = cf.add_record(edge_fakes.zone_id, "TXT", "_acme-challenge.api.other.example.com", "y",
                              comment=certs.CHALLENGE_COMMENT)
    await do_provision.destroy(cloud.context(env, None))
    assert mine["id"] not in cf.records and elsewhere["id"] in cf.records


# ---------------------------------------------------------------------------------------- no secrets


async def test_no_audit_row_or_log_line_carries_a_secret(cloud, edge_fakes):
    env = await dof.make_do_env()
    await built(cloud, env)
    (cluster,) = cloud.do.databases.values()
    secrets = [fdo.TOKEN, cluster["connection"]["password"], dof.SECRETS["POSTGRES_PASSWORD"],
               *[k["secret_key"] for k in cloud.do.spaces_keys.values()]]
    await teardown_ready(env)
    await do_provision.destroy(cloud.context(env, None))
    audited = json.dumps([[a.summary, a.details] for a in await audits()])
    logged = "\n".join(cloud.log)
    for secret in secrets:
        assert secret not in audited and secret not in logged
    assert "PRIVATE KEY" not in audited and "SCRAM-SHA-256$" not in audited


async def test_rows_of_resources_never_hold_the_certificate_key_once_recorded(cloud, edge_fakes):
    env = await dof.make_do_env()
    await built(cloud, env)
    async with get_sessionmaker()() as db:
        rows = list(await db.scalars(select(Resource).where(Resource.kind == "certificate")))
    assert rows and all(r.credentials is None for r in rows)


async def test_42_a_422_not_ready_is_retried_until_accepted(cloud):
    env = await dof.make_do_env()
    ctx = await prepared(cloud, env)
    await do_provision.database(ctx)
    (cluster,) = cloud.do.databases.values()
    cloud.do.db_rules[cluster["id"]] = []
    path = f"/databases/{cluster['id']}/firewall"
    cloud.do.fail[("PUT", path)] = [422, 422]
    await do_provision.database(ctx)
    assert len([r for r in cloud.do.requests if (r["method"], r["path"]) == ("PUT", path)]) == 3
    assert cloud.do.db_rules[cluster["id"]]


async def test_45_a_lost_bucket_answer_is_found_and_deleted(cloud, edge_fakes, monkeypatch):
    from slipway.services import spaces
    env = await dof.make_do_env()
    state = {"lost": False}

    def handler(request: httpx.Request) -> httpx.Response:
        resp = cloud.spaces.handler(request)
        if request.method == "PUT" and not request.url.query and not state["lost"]:
            state["lost"] = True
            raise httpx.ReadTimeout("lost (fake)", request=request)
        return resp
    monkeypatch.setattr(spaces, "transport_factory", lambda: httpx.MockTransport(handler))
    with pytest.raises(ProvisionError):
        await prepared(cloud, env)
    (pending,) = [r for r in await dof.rows(env, "bucket") if resources.is_pending(r)]
    assert do_rules.bucket_name("shop", env.env_id) in cloud.spaces.buckets
    await teardown_ready(env)
    await do_provision.destroy(cloud.context(env, None))
    nothing_left(cloud)
    assert await dof.rows(env) == []


async def test_renew_under_a_lock_the_caller_holds(cloud, edge_fakes):
    import asyncio

    from slipway.services import do_lb
    env = await dof.make_do_env()
    await built(cloud, env)
    await set_routes(env, "blue", dof.routes("shop"))
    async with do_lb.lock_for(env.env_id):
        note = await asyncio.wait_for(do_provision.renew(cloud.context(env, None), hold_lock=False), 30)
    assert note.endswith("nothing to renew")
