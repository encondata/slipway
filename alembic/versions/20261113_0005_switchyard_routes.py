"""switchyard routes: app_settings, hosts.proxy_address, instances.routes / proxy_entries

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-13 16:00:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0005'
down_revision: str | None = '0004'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql')


def upgrade() -> None:
    op.create_table(
        'app_settings',
        sa.Column('key', sa.String(length=64), nullable=False),
        sa.Column('value', JSON, nullable=False),
        sa.Column('secret', sa.Text(), nullable=True),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_app_settings')),
        sa.UniqueConstraint('key', name=op.f('uq_app_settings_key')),
    )
    with op.batch_alter_table('hosts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('proxy_address', sa.String(length=255), nullable=True))
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.add_column(sa.Column('routes', JSON, server_default=sa.text("'[]'"), nullable=False))
        batch_op.add_column(sa.Column('proxy_entries', JSON, server_default=sa.text("'[]'"), nullable=False))


def downgrade() -> None:
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.drop_column('proxy_entries')
        batch_op.drop_column('routes')
    with op.batch_alter_table('hosts', schema=None) as batch_op:
        batch_op.drop_column('proxy_address')
    op.drop_table('app_settings')
