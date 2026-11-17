"""provider accounts: provider_accounts, hosts.provider_state

New table: provider_accounts (the DigitalOcean, Proxmox and ESXi accounts Slipway makes machines with;
what only one provider needs is in config).
hosts: provider_state, the state of a host a provider makes ({phase: planned | creating | ready | gone, ...}).

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-18 09:00:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0010'
down_revision: str | None = '0009'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql')


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        'provider_accounts',
        sa.Column('provider', sa.String(length=16), nullable=False),
        sa.Column('name', sa.String(length=64), nullable=False),
        sa.Column('production', sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column('secret', sa.Text(), nullable=True),
        sa.Column('secret_hint', sa.String(length=16), server_default='', nullable=False),
        sa.Column('config', JSON, server_default=sa.text("'{}'"), nullable=False),
        sa.Column('tls', JSON, nullable=True),
        sa.Column('status', sa.String(length=16), server_default='unknown', nullable=False),
        sa.Column('checks', JSON, server_default=sa.text("'[]'"), nullable=False),
        sa.Column('facts', JSON, server_default=sa.text("'{}'"), nullable=False),
        sa.Column('last_checked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('removed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_by_id', sa.Uuid(), nullable=True),
        sa.Column('updated_by_id', sa.Uuid(), nullable=True),
        *_timestamps(),
        sa.CheckConstraint("provider IN ('digitalocean', 'proxmox', 'esxi')", name=op.f('ck_provider_accounts_provider')),
        sa.CheckConstraint("NOT production OR provider = 'digitalocean'",
                           name=op.f('ck_provider_accounts_production_do')),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'],
                                name=op.f('fk_provider_accounts_created_by_id_users'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['updated_by_id'], ['users.id'],
                                name=op.f('fk_provider_accounts_updated_by_id_users'), ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_provider_accounts')),
        sa.UniqueConstraint('name', name=op.f('uq_provider_accounts_name')),
    )
    with op.batch_alter_table('hosts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('provider_state', JSON, server_default=sa.text("'{}'"), nullable=False))


def downgrade() -> None:
    conn = op.get_bind()
    accounts = conn.execute(sa.text('SELECT count(*) FROM provider_accounts')).scalar_one()
    made = conn.execute(sa.text("SELECT count(*) FROM hosts WHERE provider <> 'ssh'")).scalar_one()
    if accounts or made:
        raise RuntimeError('Remove the DigitalOcean, Proxmox and ESXi accounts first')

    with op.batch_alter_table('hosts', schema=None) as batch_op:
        batch_op.drop_column('provider_state')
    op.drop_table('provider_accounts')
