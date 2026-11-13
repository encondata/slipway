"""claimed instances: compose_project_name and claim on instances

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-13 16:00:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0004'
down_revision: str | None = '0003'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql')


def upgrade() -> None:
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.add_column(sa.Column('compose_project_name', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('claim', JSON, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.drop_column('claim')
        batch_op.drop_column('compose_project_name')
