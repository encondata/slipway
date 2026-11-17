"""host samples: host_samples, host_samples_hourly, and an index on deployments.created_at

Revision ID: 0006b
Revises: 0006
Create Date: 2026-11-17 10:00:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0006b'
down_revision: str | None = '0006'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'host_samples',
        sa.Column('host_id', sa.Uuid(), nullable=False),
        sa.Column('at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('cpu_percent', sa.Double(), nullable=False),
        sa.Column('mem_percent', sa.Double(), nullable=False),
        sa.Column('disk_percent', sa.Double(), nullable=True),
        sa.Column('containers_running', sa.Integer(), nullable=True),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(['host_id'], ['hosts.id'], name=op.f('fk_host_samples_host_id_hosts'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_host_samples')),
    )
    with op.batch_alter_table('host_samples', schema=None) as batch_op:
        batch_op.create_index('ix_host_samples_host_id_at', ['host_id', 'at'], unique=False)

    op.create_table(
        'host_samples_hourly',
        sa.Column('host_id', sa.Uuid(), nullable=False),
        sa.Column('hour', sa.DateTime(timezone=True), nullable=False),
        sa.Column('cpu_avg', sa.Double(), nullable=False),
        sa.Column('cpu_max', sa.Double(), nullable=False),
        sa.Column('mem_avg', sa.Double(), nullable=False),
        sa.Column('mem_max', sa.Double(), nullable=False),
        sa.Column('disk_max', sa.Double(), nullable=True),
        sa.Column('samples', sa.Integer(), nullable=False),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ['host_id'], ['hosts.id'], name=op.f('fk_host_samples_hourly_host_id_hosts'), ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_host_samples_hourly')),
        sa.UniqueConstraint('host_id', 'hour', name='uq_host_samples_hourly_host_id_hour'),
    )
    # Deploy analytics filters on created_at several times per page load.
    op.create_index('ix_deployments_created_at', 'deployments', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_deployments_created_at', table_name='deployments')
    op.drop_table('host_samples_hourly')
    with op.batch_alter_table('host_samples', schema=None) as batch_op:
        batch_op.drop_index('ix_host_samples_host_id_at')
    op.drop_table('host_samples')
