"""port assignment: auto_ports, port_overrides, published_ports on instances

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-13 10:00:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0003'
down_revision: str | None = '0002'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql')


def upgrade() -> None:
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.add_column(sa.Column('auto_ports', sa.Boolean(), server_default=sa.true(), nullable=False))
        batch_op.add_column(sa.Column('port_overrides', JSON, server_default=sa.text("'[]'"), nullable=False))
        batch_op.add_column(sa.Column('published_ports', JSON, server_default=sa.text("'[]'"), nullable=False))


def downgrade() -> None:
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.drop_column('published_ports')
        batch_op.drop_column('port_overrides')
        batch_op.drop_column('auto_ports')
