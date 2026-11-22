"""machines: Proxmox and ESXi VMs, their address claims, Terraform states and VM snapshots

New tables: machines (one per VM Slipway makes for an environment's slot; VMs only, never droplets),
address_claims (a VM's static address, the primary key being the lock), terraform_states (a Proxmox VM's
encrypted Terraform state and its lock), machine_snapshots (the hypervisor snapshots Slipway took).

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-18 09:20:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0012'
down_revision: str | None = '0011'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql')
VM_KINDS = "('vm_snapshot', 'vm_revert', 'vm_drop')"


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        'machines',
        sa.Column('environment_id', sa.Uuid(), nullable=False),
        sa.Column('host_id', sa.Uuid(), nullable=False),
        sa.Column('account_id', sa.Uuid(), nullable=False),
        sa.Column('provider', sa.String(length=16), nullable=False),
        sa.Column('slot', sa.String(length=8), nullable=False),
        sa.Column('name', sa.String(length=63), nullable=False),
        sa.Column('stage', sa.String(length=16), server_default='planned', nullable=False),
        sa.Column('spec', JSON, nullable=False),
        sa.Column('network', JSON, nullable=False),
        sa.Column('size', JSON, nullable=False),
        sa.Column('applied', JSON, nullable=True),
        sa.Column('ids', JSON, server_default=sa.text("'{}'"), nullable=False),
        sa.Column('host_key_public', sa.Text(), nullable=True),
        sa.Column('host_key_private', sa.Text(), nullable=True),
        sa.Column('keep_vm_snapshots', sa.Integer(), server_default=sa.text('3'), nullable=False),
        sa.Column('snapshot_mode', sa.String(length=12), nullable=True),
        sa.Column('last_task', JSON, nullable=True),
        sa.Column('last_error', sa.String(length=500), nullable=True),
        sa.Column('ready_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_by_id', sa.Uuid(), nullable=True),
        *_timestamps(),
        sa.CheckConstraint("provider IN ('proxmox', 'esxi')", name=op.f('ck_machines_provider')),
        sa.CheckConstraint("stage IN ('planned', 'creating', 'booting', 'ready', 'destroying')",
                           name=op.f('ck_machines_stage')),
        sa.CheckConstraint("stage <> 'ready' OR ready_at IS NOT NULL", name=op.f('ck_machines_ready_at')),
        sa.CheckConstraint("snapshot_mode IS NULL OR snapshot_mode IN ('any', 'newest_only', 'none')",
                           name=op.f('ck_machines_snapshot_mode')),
        sa.ForeignKeyConstraint(['environment_id'], ['environments.id'],
                                name=op.f('fk_machines_environment_id_environments'), ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['host_id'], ['hosts.id'], name=op.f('fk_machines_host_id_hosts'), ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['account_id'], ['provider_accounts.id'],
                                name=op.f('fk_machines_account_id_provider_accounts'), ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'],
                                name=op.f('fk_machines_created_by_id_users'), ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_machines')),
        sa.UniqueConstraint('host_id', name=op.f('uq_machines_host_id')),
        sa.UniqueConstraint('account_id', 'name', name=op.f('uq_machines_account_id')),
        sa.UniqueConstraint('environment_id', 'slot', name=op.f('uq_machines_environment_id')),
    )
    op.create_index(op.f('ix_machines_environment_id'), 'machines', ['environment_id'], unique=False)

    op.create_table(
        'address_claims',
        sa.Column('address', sa.String(length=45), nullable=False),
        sa.Column('host_id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.ForeignKeyConstraint(['host_id'], ['hosts.id'], name=op.f('fk_address_claims_host_id_hosts'),
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('address', name=op.f('pk_address_claims')),
        sa.UniqueConstraint('host_id', name=op.f('uq_address_claims_host_id')),
    )

    op.create_table(
        'terraform_states',
        sa.Column('machine_id', sa.Uuid(), nullable=False),
        sa.Column('lineage', sa.String(length=64), nullable=True),
        sa.Column('serial', sa.Integer(), server_default=sa.text('0'), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=True),
        sa.Column('state', sa.Text(), nullable=True),
        sa.Column('lock_id', sa.Uuid(), nullable=True),
        sa.Column('locked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('module_sha', sa.String(length=64), nullable=True),
        sa.Column('terraform_version', sa.String(length=16), nullable=True),
        sa.ForeignKeyConstraint(['machine_id'], ['machines.id'], name=op.f('fk_terraform_states_machine_id_machines'),
                                ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('machine_id', name=op.f('pk_terraform_states')),
    )

    op.create_table(
        'machine_snapshots',
        sa.Column('machine_id', sa.Uuid(), nullable=False),
        sa.Column('name', sa.String(length=40), nullable=False),
        sa.Column('reason', sa.String(length=16), nullable=False),
        sa.Column('status', sa.String(length=16), server_default='pending', nullable=False),
        sa.Column('deployment_id', sa.Uuid(), nullable=True),
        sa.Column('commit_sha', sa.String(length=40), nullable=True),
        sa.Column('app_state', JSON, nullable=True),
        sa.Column('fresh_data', sa.String(length=8), nullable=True),
        sa.Column('identity', sa.Text(), nullable=True),
        sa.Column('identity_fp', sa.String(length=64), nullable=False),
        sa.Column('backups', JSON, server_default=sa.text("'[]'"), nullable=False),
        sa.Column('sizes', JSON, nullable=False),
        sa.Column('quiesced', sa.Boolean(), nullable=True),
        sa.Column('note', sa.String(length=300), nullable=True),
        sa.Column('taken_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_by_id', sa.Uuid(), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(['machine_id'], ['machines.id'], name=op.f('fk_machine_snapshots_machine_id_machines'),
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['deployment_id'], ['deployments.id'],
                                name=op.f('fk_machine_snapshots_deployment_id_deployments'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'],
                                name=op.f('fk_machine_snapshots_created_by_id_users'), ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_machine_snapshots')),
        sa.UniqueConstraint('machine_id', 'name', name=op.f('uq_machine_snapshots_machine_id')),
    )
    op.create_index(op.f('ix_machine_snapshots_machine_id'), 'machine_snapshots', ['machine_id'], unique=False)


def downgrade() -> None:
    conn = op.get_bind()
    names = conn.execute(sa.text(
        'SELECT DISTINCT e.name FROM machines m JOIN environments e ON e.id = m.environment_id ORDER BY e.name'
    )).scalars().all()
    if names:
        raise RuntimeError(f"Delete the environments with Proxmox or ESXi VMs first (still here: {', '.join(names)})")

    # Jobs of the VM kinds mean nothing below this revision. References are cleared by hand first: SQLite
    # runs migrations without foreign key enforcement, so ON DELETE SET NULL would not fire there.
    jobs = f'SELECT id FROM deployments WHERE kind IN {VM_KINDS}'
    for table, column in (('backups', 'deployment_id'), ('backups', 'dirty_of'), ('first_admins', 'deployment_id'),
                          ('snapshots', 'deployment_id'), ('deployments', 'retry_of_id')):
        conn.execute(sa.text(f'UPDATE {table} SET {column} = NULL WHERE {column} IN ({jobs})'))
    conn.execute(sa.text(f'DELETE FROM deployments WHERE kind IN {VM_KINDS}'))

    op.drop_index(op.f('ix_machine_snapshots_machine_id'), table_name='machine_snapshots')
    op.drop_table('machine_snapshots')
    op.drop_table('terraform_states')
    op.drop_table('address_claims')
    op.drop_index(op.f('ix_machines_environment_id'), table_name='machines')
    op.drop_table('machines')
