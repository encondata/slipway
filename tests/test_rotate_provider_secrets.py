"""rotate-encryption-key over the provider and machine secrets (phase 4 test 23 and phase 5 test 50, the
rotation halves): provider_accounts.secret, backups.data_key, machines.host_key_private,
machine_snapshots.identity and terraform_states.state are re-encrypted, each table by its own primary key;
--clear-unreadable refuses on an unreadable Terraform state, sets an unreadable account secret to NULL
(never an encrypted null, which would read as a secret that is set) and marks the account to ask for it.
"""

from __future__ import annotations

import argparse
import uuid
from datetime import UTC, datetime

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select, text

from slipway import cli
from slipway.db.session import get_sessionmaker
from slipway.models import (
    AuditEvent,
    Backup,
    Environment,
    Host,
    Instance,
    Machine,
    MachineSnapshot,
    ProviderAccount,
    Repository,
    TerraformState,
)
from tests.test_migration_0009 import K1, K2, K3, encryption_key  # noqa: F401

NOW = datetime(2026, 11, 18, 9, 0, tzinfo=UTC)
TOKEN, PVE_TOKEN, PASSWORD = "dop_v1_" + "a" * 64, "slipway@pve!slipway=0000-1111", "esxi-pass-1"
STATE = '{"version": 4, "lineage": "abc"}'


async def _seed() -> dict[str, uuid.UUID]:
    """Three accounts (one with no secret), an ESXi VM mid-build, a Proxmox VM with its state, a VM snapshot
    and a ready backup stored on the Slipway server."""
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=1, full_name="acme/web", owner="acme", name="web",
                          html_url="https://github.com/acme/web")
        do = ProviderAccount(provider="digitalocean", name="DO", secret=TOKEN, secret_hint="aaaa")
        pve = ProviderAccount(provider="proxmox", name="Lab", secret=PVE_TOKEN)
        esx = ProviderAccount(provider="esxi", name="esx-01", secret=PASSWORD)
        unset = ProviderAccount(provider="proxmox", name="Spare")
        db.add_all([repo, do, pve, esx, unset])
        await db.flush()
        env = Environment(name="lab", repository_id=repo.id, branch="main", data_mode="slot")
        db.add(env)
        await db.flush()
        hosts = {slot: Host(name=f"slipway-lab-{slot}", hostname=f"192.168.1.{n}", username="slipway",
                            provider=provider, owner_environment_id=env.id)
                 for slot, n, provider in (("blue", 50, "esxi"), ("green", 51, "proxmox"))}
        db.add_all(hosts.values())
        await db.flush()

        def machine(slot: str, account: ProviderAccount, **kw) -> Machine:
            return Machine(environment_id=env.id, host_id=hosts[slot].id, account_id=account.id,
                           provider=account.provider, slot=slot, name=f"slipway-lab-{slot}", spec={},
                           network={"address": hosts[slot].hostname}, size={"cores": 2}, **kw)

        blue = machine("blue", esx, stage="creating", host_key_private="-----BEGIN OPENSSH PRIVATE KEY-----x")
        green = machine("green", pve, stage="ready", ready_at=NOW)
        db.add_all([blue, green])
        await db.flush()
        inst = Instance(name="lab green", slug="lab-green", repository_id=repo.id, host_id=hosts["green"].id,
                        branch="main", environment_id=env.id, slot="green")
        db.add_all([TerraformState(machine_id=green.id, state=STATE, serial=3), inst])
        await db.flush()
        db.add_all([
            MachineSnapshot(machine_id=green.id, name="slipway-20261118T090000Z", reason="manual", identity_fp="fp",
                            identity={"SS_JWT_SECRET": "jwt-1"}, sizes={"cores": 2}, taken_at=NOW),
            Backup(instance_id=inst.id, name="b1", reason="manual", status="ready", format="pg_dump", db_bytes=10,
                   identity_fp="fp", taken_at=NOW, location="slipway", data_key="a2V5LTE=", stored_bytes=100),
        ])
        await db.commit()
        return {"do": do.id, "pve": pve.id, "esx": esx.id, "unset": unset.id, "blue": blue.id, "green": green.id}


async def _raw(sql: str) -> str | None:
    async with get_sessionmaker()() as db:
        return await db.scalar(text(sql))


async def _rotate_all(clear: bool) -> tuple[int, list[str], list[str]]:
    async with get_sessionmaker()() as db:
        result = await cli._rotate_all(db, argparse.Namespace(clear_unreadable=clear))
        await db.commit()
        return result


ENCRYPTED = (
    ("provider_accounts", "secret", "name = 'DO'", TOKEN),
    ("provider_accounts", "secret", "name = 'Lab'", PVE_TOKEN),
    ("provider_accounts", "secret", "name = 'esx-01'", PASSWORD),
    ("machines", "host_key_private", "slot = 'blue'", "-----BEGIN OPENSSH PRIVATE KEY-----x"),
    ("terraform_states", "state", "serial = 3", STATE),
    ("machine_snapshots", "identity", "reason = 'manual'", '{"SS_JWT_SECRET": "jwt-1"}'),
    ("backups", "data_key", "name = 'b1'", "a2V5LTE="),
)


async def test_rotation_reencrypts_every_provider_and_machine_secret(encryption_key):  # noqa: F811
    encryption_key(K1)
    ids = await _seed()
    encryption_key(f"{K2},{K1}")
    rotated, unreadable, fixed = await _rotate_all(clear=False)
    assert (rotated, unreadable, fixed) == (len(ENCRYPTED), [], [])

    encryption_key(K2)  # the old key is gone: everything reads under the new one alone
    for table, column, where, plain in ENCRYPTED:
        raw = await _raw(f"SELECT {column} FROM {table} WHERE {where}")
        assert Fernet(K2.encode()).decrypt(raw.encode()).decode() == plain, (table, column)
    async with get_sessionmaker()() as db:
        assert (await db.get(ProviderAccount, ids["do"])).secret == TOKEN
        assert (await db.get(TerraformState, ids["green"])).state == STATE  # updated by machine_id
        assert (await db.get(ProviderAccount, ids["unset"])).secret is None
        assert await db.scalar(select(AuditEvent.id)) is None  # nothing audited, no secret anywhere


async def test_clear_unreadable_refuses_on_an_unreadable_terraform_state(encryption_key):  # noqa: F811
    encryption_key(K1)
    await _seed()
    encryption_key(K3)

    # Without --clear-unreadable it is listed with the rest (by its primary key) and left as it is.
    async with get_sessionmaker()() as db:
        rotated, unreadable = await cli._rotate_secrets(db)
        await db.rollback()
    assert rotated == 0 and len(unreadable) == len(ENCRYPTED)
    machine_id = await _raw("SELECT machine_id FROM terraform_states")
    assert any(u.startswith("terraform_states.state (machine_id ") for u in unreadable)
    assert machine_id is not None

    # With it, the whole run is refused before anything is erased.
    before = {(t, c, w): await _raw(f"SELECT {c} FROM {t} WHERE {w}") for t, c, w, _ in ENCRYPTED}
    with pytest.raises(cli.RotationRefused) as refused:
        await _rotate_all(clear=True)
    assert str(refused.value) == (
        "Slipway can't read the Terraform state of slipway-lab-green with any key in SLIPWAY_ENCRYPTION_KEY. "
        "Put the old key back first; without the state Slipway can't remove the VM"
    )
    assert {(t, c, w): await _raw(f"SELECT {c} FROM {t} WHERE {w}") for t, c, w, _ in ENCRYPTED} == before
    async with get_sessionmaker()() as db:
        assert (await db.get(ProviderAccount, (await db.scalar(
            select(ProviderAccount.id).where(ProviderAccount.name == "DO"))))).status == "unknown"


async def test_clear_unreadable_erases_account_secrets_and_asks_for_them_again(encryption_key):  # noqa: F811
    encryption_key(K1)
    ids = await _seed()
    encryption_key(K3)
    # The Terraform state was written again under the new key, so only the others are lost.
    async with get_sessionmaker()() as db:
        (await db.get(TerraformState, ids["green"])).state = STATE
        await db.commit()

    rotated, unreadable, fixed = await _rotate_all(clear=True)
    assert rotated == 1  # the readable Terraform state, re-encrypted
    assert sorted(u.split(" ")[0] for u in unreadable) == [
        "backups.data_key", "machine_snapshots.identity", "machines.host_key_private",
        "provider_accounts.secret", "provider_accounts.secret", "provider_accounts.secret",
    ]
    # NULL, not an encrypted null: has_secret is false and nothing would send "null" as a token.
    for name in ("DO", "Lab", "esx-01"):
        assert await _raw(f"SELECT secret FROM provider_accounts WHERE name = '{name}'") is None
    async with get_sessionmaker()() as db:
        accounts = {a.name: a for a in (await db.scalars(select(ProviderAccount))).all()}
        for name, word in (("DO", "token"), ("Lab", "token"), ("esx-01", "password")):
            account = accounts[name]
            assert not account.has_secret and account.status == "error", name
            assert account.checks == [{"name": "secret", "ok": False, "level": "error",
                                       "text": f"The {word} couldn't be read after a key change: enter it again"}]
        # An account that never had a secret is left as it was.
        assert (accounts["Spare"].status, accounts["Spare"].checks) == ("unknown", [])

        blue = await db.get(Machine, ids["blue"])
        assert blue.host_key_private is None and blue.stage == "creating"
        snap = await db.scalar(select(MachineSnapshot))
        assert snap.identity is None
        backup = await db.scalar(select(Backup))
        # A Slipway-stored backup without its key can only be deleted: it is no longer ready.
        assert (backup.data_key, backup.status, backup.location) == (None, "changed", "slipway")
        assert (await db.get(TerraformState, ids["green"])).state == STATE
    assert await _raw("SELECT host_key_private FROM machines WHERE slot = 'blue'") is None
    assert Fernet(K3.encode()).decrypt((await _raw("SELECT state FROM terraform_states")).encode()).decode() == STATE

    text_fixed = "\n".join(fixed)
    assert "3 provider account(s) lost their token or password" in text_fixed
    assert "  DO (digitalocean)" in fixed and "  esx-01 (esxi)" in fixed and "  Lab (proxmox)" in fixed
    assert "1 backup(s) lost the key" in text_fixed
    for secret in (TOKEN, PVE_TOKEN, PASSWORD, "jwt-1"):
        assert secret not in text_fixed and all(secret not in u for u in unreadable)

    # A second run finds nothing left to erase and leaves the marks alone.
    rotated, unreadable, fixed = await _rotate_all(clear=True)
    assert (rotated, unreadable) == (1, [])
    async with get_sessionmaker()() as db:
        assert (await db.get(ProviderAccount, ids["do"])).status == "error"
