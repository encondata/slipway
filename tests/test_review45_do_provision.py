"""Review fixes for DigitalOcean droplet provisioning (phase 4 §9.1, §9.2, §9.4, §10.6, §11.4, §6.4).

F3/F37: a cancel, the step timeout or a failure while the resize's power_off is polled still powers the droplet
on. F25: a lost create that shows up late is never followed by a second droplet for the slot. F26: a droplet
left off by a cut resize doesn't block an SSH-rule change. F28/F53: a droplet host is built (ready) only once
its pin and cloud-init are confirmed, and the pin that first succeeds is audited. F27: Reset's wipe on another
team writes nothing. F43: containers can't read the droplet's user-data from the metadata address.

Fakes only (tests/do_fixtures.py).
"""

from __future__ import annotations

import asyncio

import pytest
import yaml

from slipway.db.session import get_sessionmaker
from slipway.models import Environment, ProviderAccount
from slipway.services import digitalocean, do_provision, do_rules, manifest, ssh
from slipway.services.do_provision import ProvisionError
from tests import do_fixtures as dof
from tests.test_do_provision import _grow, audits, run_prepare


@pytest.fixture
def cloud(tmp_path, monkeypatch) -> dof.Cloud:
    return dof.Cloud(tmp_path, monkeypatch)


def _yielding_sleep(cloud: dof.Cloud, monkeypatch, pause: float = 0.0) -> None:
    async def sleep(seconds: float) -> None:
        cloud.do.advance(seconds)
        await asyncio.sleep(pause)
    monkeypatch.setattr(digitalocean, "sleep", sleep)


def _action_kinds(cloud: dof.Cloud) -> list[str]:
    return [a["type"] for a in cloud.do.actions.values()]


# ---------------------------------------------------------------------------------------------- F3, F37


async def test_f3_cancel_during_the_power_off_poll_powers_the_droplet_on(cloud, monkeypatch):
    env = await dof.make_do_env(slots=("blue",), droplets=1)  # a Single environment: blue is live
    got = await run_prepare(cloud, env)
    await _grow(env)
    cloud.do.action_polls = 20  # power_off takes a while: the cancel comes while Slipway polls it
    _yielding_sleep(cloud, monkeypatch)
    task = asyncio.create_task(do_provision.resize_droplet(cloud.context(env)))
    while "power_off" not in _action_kinds(cloud):
        await asyncio.sleep(0)
    for _ in range(3):
        await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    droplet = cloud.do.droplets[int(got.droplet_id)]
    # The shielded guard waited for the power_off DigitalOcean took, then powered the droplet on.
    assert _action_kinds(cloud) == ["power_off", "power_on"]
    assert droplet["status"] == "active"
    assert droplet["size_slug"] == "s-1vcpu-1gb"  # never resized
    assert (await dof.host_row(env, "blue")).provider_state["size"] == "s-1vcpu-1gb"


async def test_f37_the_step_timeout_during_the_power_off_poll_powers_the_droplet_on(cloud, monkeypatch):
    env = await dof.make_do_env(slots=("blue",), droplets=1)
    got = await run_prepare(cloud, env)
    await _grow(env)
    cloud.do.action_polls = 20
    _yielding_sleep(cloud, monkeypatch, pause=0.01)
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.1):  # lands during the power_off poll
            await do_provision.resize_droplet(cloud.context(env))
    assert _action_kinds(cloud) == ["power_off", "power_on"]
    assert cloud.do.droplets[int(got.droplet_id)]["status"] == "active"


async def test_f3_a_power_off_that_never_finishes_in_time_still_powers_on(cloud, monkeypatch):
    """The power_off poll gives up (a ProvisionError): DigitalOcean finishes it later, and the guard waits for
    it and powers the droplet on before the step reports the first failure."""
    env = await dof.make_do_env(slots=("blue",), droplets=1)
    got = await run_prepare(cloud, env)
    await _grow(env)
    _yielding_sleep(cloud, monkeypatch)
    real_finish = do_provision._finish
    calls = {"n": 0}

    async def finish(client, droplet_id, action_id, seconds, what):
        calls["n"] += 1
        if calls["n"] == 1:  # the step's own wait for power_off
            raise ProvisionError(f"{what} didn't finish in time")
        return await real_finish(client, droplet_id, action_id, seconds, what)
    monkeypatch.setattr(do_provision, "_finish", finish)
    with pytest.raises(ProvisionError, match="Powering off slipway-shop-blue didn't finish in time"):
        await do_provision.resize_droplet(cloud.context(env))
    assert _action_kinds(cloud) == ["power_off", "power_on"]
    assert cloud.do.droplets[int(got.droplet_id)]["status"] == "active"


async def test_f3_a_power_off_that_errored_sends_no_power_on(cloud):
    """An errored power_off left the droplet on: nothing is powered on (it would only fail)."""
    env = await dof.make_do_env(slots=("blue",), droplets=1)
    got = await run_prepare(cloud, env)
    await _grow(env)
    cloud.do.action_errors.add("power_off")
    with pytest.raises(ProvisionError, match="Powering off slipway-shop-blue failed"):
        await do_provision.resize_droplet(cloud.context(env))
    assert _action_kinds(cloud) == ["power_off"]
    assert cloud.do.droplets[int(got.droplet_id)]["status"] == "active"


# ---------------------------------------------------------------------------------------------------- F25


async def test_f25_a_late_lost_droplet_is_refused_not_doubled(cloud):
    env = await dof.make_do_env()  # blue and green: the plan has 2 droplets
    # Run 1: the create lands, its answer is lost, and the droplet shows in lists only after 1000 s.
    cloud.do.lose_answer[("POST", "/droplets")] = 1
    cloud.do.lost_visible_after = 1000
    with pytest.raises(ProvisionError):
        await run_prepare(cloud, env)
    # Run 2: the pending row is judged absent, the new create answers 504 (nothing made), so it is kept.
    cloud.do.fail[("POST", "/droplets")] = [504]
    with pytest.raises(ProvisionError):
        await run_prepare(cloud, env)
    cloud.do.advance(2000)  # the first droplet is listed now
    [first] = [d for d in cloud.do.droplets.values() if d["name"] == "slipway-shop-blue"]
    posts = sum(1 for w in cloud.writes() if w == ("POST", "/droplets"))
    with pytest.raises(ProvisionError) as err:
        await run_prepare(cloud, env)
    assert str(err.value) == (f"Droplet slipway-shop-blue ({first['id']}) carries shop's tags, but Slipway has no "
                              f"record of making it. {do_rules.CHANGED_NOTHING}")
    assert sum(1 for w in cloud.writes() if w == ("POST", "/droplets")) == posts  # no new create
    named = [d for d in cloud.do.droplets.values() if d["name"] == "slipway-shop-blue"
             and do_rules.has_both_tags(d, env.env_id)]
    assert len(named) == 1


# ---------------------------------------------------------------------------------------------------- F26


async def _change_sources(env: dof.DoEnv) -> None:
    async with get_sessionmaker()() as db:
        row = await db.get(ProviderAccount, env.account_id)
        row.config = {**row.config, "ssh_sources": [*dof.SSH_SOURCES, "192.0.2.0/24"]}
        await db.commit()


def _off_droplets_refuse_ssh(cloud: dof.Cloud) -> None:
    """A powered-off droplet answers nothing; powered on, it answers again."""
    real = cloud.connect

    def connect(target):
        for droplet in cloud.do.droplets.values():
            public, _private = digitalocean.droplet_ips(droplet)
            if public == target.hostname:
                cloud.droplet_host(droplet).firewalled = droplet["status"] == "off"
        return real(target)
    cloud.connect = connect


@pytest.mark.parametrize("deploy_to", ["blue", "green"])
async def test_f26_an_off_droplet_and_new_ssh_sources_still_deploy(cloud, deploy_to):
    env = await dof.make_do_env()
    await run_prepare(cloud, env, "blue")
    green = await run_prepare(cloud, env, "green")
    # A restart cut green's resize between power off and power on; then the account's SSH sources change.
    cloud.do.droplets[int(green.droplet_id)]["status"] = "off"
    _off_droplets_refuse_ssh(cloud)
    await _change_sources(env)
    got = await run_prepare(cloud, env, deploy_to)
    assert got.droplet_id
    fw = next(iter(cloud.do.firewalls.values()))
    assert "192.0.2.0/24" in fw["inbound_rules"][0]["sources"]["addresses"]  # the new rule stayed
    assert "slipway-shop-green is powered off, so the new SSH rule is proven when it is powered on" in cloud.log
    powered_on = cloud.do.droplets[int(green.droplet_id)]["status"] == "active"
    assert powered_on is (deploy_to == "green")  # a deploy powers on only its own slot's droplet


# ---------------------------------------------------------------------------------------------- F28, F53


async def test_f53_a_wrong_key_leaves_the_host_unbuilt(cloud):
    env = await dof.make_do_env()
    cloud.wrong_key.add("slipway-shop-blue")
    with pytest.raises(ProvisionError, match="host key Slipway didn't generate"):
        await run_prepare(cloud, env)
    host = await dof.host_row(env, "blue")
    assert host.provider_state["phase"] == "creating" and not ssh.host_is_built(host)
    assert "built_at" not in host.provider_state
    assert await audits("host.key_pinned") == []


async def test_f28_a_failed_first_pin_keeps_the_new_droplet_wait_and_the_later_pin_is_audited(cloud):
    env = await dof.make_do_env()
    cloud.firewalled.add("slipway-shop-blue")
    with pytest.raises(ProvisionError, match="for 10 minutes"):
        await run_prepare(cloud, env)
    host = await dof.host_row(env, "blue")
    assert host.provider_state["phase"] == "creating" and not ssh.host_is_built(host)
    assert host.hostname == "203.0.113.1"  # the address is known, so the retry can connect
    # The retry of a droplet never confirmed still gets the new droplet's 10 minutes.
    with pytest.raises(ProvisionError, match="for 10 minutes"):
        await run_prepare(cloud, env)
    cloud.multi["203.0.113.1"].firewalled = False
    await run_prepare(cloud, env)
    host = await dof.host_row(env, "blue")
    assert host.provider_state["phase"] == "ready" and ssh.host_is_built(host)
    assert host.provider_state["built_at"]
    [pinned] = await audits("host.key_pinned")
    assert pinned.details["fingerprint"] == host.host_key_fingerprint
    # Once built, a later prepare neither audits the pin again nor moves built_at.
    built_at = host.provider_state["built_at"]
    await run_prepare(cloud, env)
    assert len(await audits("host.key_pinned")) == 1
    assert (await dof.host_row(env, "blue")).provider_state["built_at"] == built_at


async def test_f28_a_pin_confirmed_before_a_cloud_init_failure_is_audited_once(cloud):
    env = await dof.make_do_env()
    cloud.marker.unlink()
    with pytest.raises(ProvisionError, match="cloud-init didn't finish"):
        await run_prepare(cloud, env)
    host = await dof.host_row(env, "blue")
    assert host.provider_state["phase"] == "creating" and not ssh.host_is_built(host)
    cloud.marker.write_text("")
    await run_prepare(cloud, env)
    assert (await dof.host_row(env, "blue")).provider_state["phase"] == "ready"
    assert len(await audits("host.key_pinned")) == 1


# ---------------------------------------------------------------------------------------------------- F27


async def test_f27_reset_wipe_on_another_team_writes_nothing(cloud):
    env = await dof.make_do_env()
    await run_prepare(cloud, env)
    async with get_sessionmaker()() as db:
        row = await db.get(Environment, env.env_id)
        row.provider_team = "another-team-uuid"
        await db.commit()
    cloud.do.requests.clear()
    man = manifest.parse(cloud.manifest_text)
    assert do_provision.objects_need(man) is not None  # the app has a bucket
    with pytest.raises(ProvisionError, match="now answers for team"):
        await do_provision.empty_bucket(cloud.context(env), man)
    assert cloud.do.writes() == []


# ---------------------------------------------------------------------------------------------------- F43


def test_f43_userdata_blocks_the_metadata_address_from_containers():
    login_private, login = ssh.generate_keypair("slipway")
    host_private, host_public = ssh.generate_keypair("root@slipway-prod-blue")
    text = do_rules.droplet_userdata("prod", "blue", authorized_key=login, host_private_key=host_private,
                                     host_public_key=host_public)
    doc = yaml.safe_load(text)
    block = ("iptables -C DOCKER-USER -d 169.254.169.254/32 -j DROP 2>/dev/null || "
             "iptables -I DOCKER-USER -d 169.254.169.254/32 -j DROP")
    # Kept across Docker restarts and reboots: a drop-in runs it whenever Docker starts.
    [dropin] = doc["write_files"]
    assert dropin["path"] == "/etc/systemd/system/docker.service.d/slipway-metadata.conf"
    assert dropin["content"] == f"[Service]\nExecStartPost=/bin/sh -c '{block}'\n"
    # The ready marker is written only once the rule is in place, so no droplet is ready without it.
    runcmd = doc["runcmd"]
    assert runcmd[-1] == ["sh", "-c", f"{{ {block}; }} && touch /var/lib/slipway-ready"]
    assert runcmd.index(["systemctl", "daemon-reload"]) < runcmd.index(["systemctl", "enable", "--now", "docker"])
    assert login_private not in text
