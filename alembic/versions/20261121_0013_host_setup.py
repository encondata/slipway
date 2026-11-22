"""host setup: hosts.os_type and the setup_* columns

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-21 10:00:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0013'
down_revision: str | None = '0012'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('hosts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('os_type', sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column('setup_status', sa.String(length=16), nullable=True))
        batch_op.add_column(sa.Column('setup_step', sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column('setup_log', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('setup_error', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('setup_started_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('hosts', schema=None) as batch_op:
        for name in ('setup_started_at', 'setup_error', 'setup_log', 'setup_step', 'setup_status', 'os_type'):
            batch_op.drop_column(name)
