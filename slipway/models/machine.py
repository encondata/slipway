"""Virtual machines Slipway makes on Proxmox and ESXi for an environment's slots (phase 5).

``machines`` is for VMs only: a DigitalOcean droplet is a host with ``provider_state`` and a ``droplet``
resource, never a row here. Each machine has exactly one host row (the planned or made host Slipway
deploys to over SSH); ``hosts.provider_state.phase`` follows ``stage`` in the same transaction (planned to
planned, creating and booting to creating, ready to ready, destroying to gone).

``address_claims`` reserves a VM's static address from the moment it is planned: the primary key is the
lock, so two environments picking one address can't both commit. ``terraform_states`` holds the whole
Terraform state of a Proxmox VM (encrypted) and its lock. ``machine_snapshots`` records the hypervisor
snapshots Slipway took of a VM, with what the slot was then.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from sqlalchemy import CheckConstraint, ForeignKey, String, Text, UniqueConstraint, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from slipway.core.crypto import EncryptedJSON, EncryptedText
from slipway.db.base import Base, Timestamps, UUIDPrimaryKey, utcnow

if TYPE_CHECKING:
    from slipway.models.host import Host
    from slipway.models.provider import ProviderAccount


class MachineStage(StrEnum):
    PLANNED = "planned"  # recorded at create; nothing on the hypervisor yet
    CREATING = "creating"  # the hypervisor is making it
    BOOTING = "booting"  # made and started; waiting for SSH and the bootstrap
    READY = "ready"  # pinned, bootstrapped, deployable
    DESTROYING = "destroying"  # Remove started deleting it


class SnapshotReason(StrEnum):
    MANUAL = "manual"
    PRE_RESIZE = "pre_resize"
    PRE_REVERT = "pre_revert"


class SnapshotMode(StrEnum):
    """Which VM snapshots a machine can revert to (set when it becomes ready, D23)."""

    ANY = "any"
    NEWEST_ONLY = "newest_only"  # e.g. Proxmox on zfspool: only the newest snapshot can be rolled back to
    NONE = "none"  # the storage can't take snapshots


class Machine(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "machines"
    __table_args__ = (
        UniqueConstraint("account_id", "name", name="uq_machines_account_id"),
        UniqueConstraint("environment_id", "slot", name="uq_machines_environment_id"),
        CheckConstraint("provider IN ('proxmox', 'esxi')", name="provider"),
        CheckConstraint("stage IN ('planned', 'creating', 'booting', 'ready', 'destroying')", name="stage"),
        CheckConstraint("stage <> 'ready' OR ready_at IS NOT NULL", name="ready_at"),
        CheckConstraint("snapshot_mode IS NULL OR snapshot_mode IN ('any', 'newest_only', 'none')", name="snapshot_mode"),
    )

    environment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("environments.id", ondelete="RESTRICT"), index=True
    )
    host_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("hosts.id", ondelete="RESTRICT"), unique=True)
    # RESTRICT: an account can't be deleted while a machine uses it.
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("provider_accounts.id", ondelete="RESTRICT"))
    provider: Mapped[str] = mapped_column(String(16))  # a copy of the account's: proxmox or esxi
    slot: Mapped[str] = mapped_column(String(8))  # blue, green, data
    name: Mapped[str] = mapped_column(String(63))  # the VM's name and guest host name: slipway-<env>-<slot>
    stage: Mapped[str] = mapped_column(String(16), default=MachineStage.PLANNED, server_default="planned")
    # Frozen at create from the account: Proxmox {node, pool, storage, storage_type, file_format,
    # template_vmid, bridge, vlan_tag}; ESXi {api_host, datastore, resource_pool, source_vm, port_group}.
    spec: Mapped[dict[str, Any]] = mapped_column()
    network: Mapped[dict[str, Any]] = mapped_column()  # {name, address, prefix, gateway, dns_servers}
    size: Mapped[dict[str, Any]] = mapped_column()  # wanted {cores, memory_mb, disk_gb}
    applied: Mapped[dict[str, Any] | None] = mapped_column()  # {cores, memory_mb, disk_gb, at, deployment_id}
    ids: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default=text("'{}'"))  # {vmid} | {moref, ...}
    # The host key the VM must show: ESXi's from create, Proxmox's once read through the guest agent.
    host_key_public: Mapped[str | None] = mapped_column(Text)
    # ESXi only: the generated host key's private half, until the scrub (NULL on a ready machine).
    host_key_private: Mapped[str | None] = mapped_column(EncryptedText)
    keep_vm_snapshots: Mapped[int] = mapped_column(default=3, server_default=text("3"))
    snapshot_mode: Mapped[str | None] = mapped_column(String(12))  # SnapshotMode
    # The hypervisor task Slipway last started on the VM: {id, kind, started_at, deployment_id}.
    last_task: Mapped[dict[str, Any] | None] = mapped_column()
    last_error: Mapped[str | None] = mapped_column(String(500))
    ready_at: Mapped[datetime | None]
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    host: Mapped[Host] = relationship(lazy="selectin")
    account: Mapped[ProviderAccount] = relationship(lazy="selectin")

    @property
    def is_ready(self) -> bool:
        return self.stage == MachineStage.READY


class MachineSnapshot(UUIDPrimaryKey, Timestamps, Base):
    """A hypervisor snapshot of a VM that Slipway took, and what the slot was at that moment."""

    __tablename__ = "machine_snapshots"
    __table_args__ = (UniqueConstraint("machine_id", "name", name="uq_machine_snapshots_machine_id"),)

    machine_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("machines.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(40))  # slipway-YYYYMMDDTHHMMSSZ
    reason: Mapped[str] = mapped_column(String(16))  # SnapshotReason
    # pending (recorded, task running), ready, missing (the hypervisor doesn't have it), failed.
    status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    deployment_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("deployments.id", ondelete="SET NULL"))
    commit_sha: Mapped[str | None] = mapped_column(String(40))
    app_state: Mapped[dict[str, Any] | None] = mapped_column()
    fresh_data: Mapped[str | None] = mapped_column(String(8))
    identity: Mapped[dict[str, str] | None] = mapped_column(EncryptedJSON)
    identity_fp: Mapped[str] = mapped_column(String(64))
    backups: Mapped[list[str]] = mapped_column(default=list, server_default=text("'[]'"))
    sizes: Mapped[dict[str, Any]] = mapped_column()
    quiesced: Mapped[bool | None] = mapped_column()  # ESXi: whether VMware Tools quiesced; Proxmox NULL
    note: Mapped[str | None] = mapped_column(String(300))
    taken_at: Mapped[datetime]
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class TerraformState(Base):
    """One VM's Terraform state and its lock. RESTRICT: the machine row goes only after this one."""

    __tablename__ = "terraform_states"

    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="RESTRICT"), primary_key=True
    )
    lineage: Mapped[str | None] = mapped_column(String(64))
    serial: Mapped[int] = mapped_column(default=0, server_default=text("0"))
    sha256: Mapped[str | None] = mapped_column(String(64))
    state: Mapped[str | None] = mapped_column(EncryptedText)  # the whole terraform.tfstate, at most 4 MiB
    # The deployment running Terraform; no foreign key, since that row may be gone.
    lock_id: Mapped[uuid.UUID | None] = mapped_column()
    locked_at: Mapped[datetime | None]
    module_sha: Mapped[str | None] = mapped_column(String(64))
    terraform_version: Mapped[str | None] = mapped_column(String(16))


class AddressClaim(Base):
    """A static IPv4 address taken by a planned or made host, inserted in the same transaction as the host."""

    __tablename__ = "address_claims"

    address: Mapped[str] = mapped_column(String(45), primary_key=True)
    host_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), unique=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow, server_default=func.now())
