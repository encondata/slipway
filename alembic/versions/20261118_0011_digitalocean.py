"""digitalocean: environment placement and production, host-less data owners, backups on Slipway, acme

environments: provider (the placement), provider_account_id, provider_team, cloud, production, retiring_at,
retired_by_id; the checks that tie them together and ux_environments_one_production.
instances: host_id nullable (a managed environment's data owner has no host), ck_instances_host.
backups: location, data_key, stored_bytes, ck_backups_slipway_key.
app_settings: the empty ``acme`` row (ACME account keys), inserted when missing.

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-18 09:10:00.000000
"""
import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0011'
down_revision: str | None = '0010'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql')
ONE_PRODUCTION = 'production AND retiring_at IS NULL AND deleted_at IS NULL'
ENV_CHECKS = (
    ('provider_account', "(provider = 'digitalocean') = (provider_account_id IS NOT NULL)"),
    ('do_managed', "provider <> 'digitalocean' OR data_mode = 'managed'"),
    ('production_do', "NOT production OR provider = 'digitalocean'"),
    ('retiring', 'retiring_at IS NULL OR production'),
    ('production_auto', 'NOT production OR NOT auto_activate'),
)
NEW_KINDS = "('certificate', 'deactivate')"


def upgrade() -> None:
    # 1. Environments: the placement, its account and cloud objects, and the production safeguards.
    with op.batch_alter_table('environments', schema=None) as batch_op:
        batch_op.add_column(sa.Column('provider', sa.String(length=16), server_default='ssh', nullable=False))
        batch_op.add_column(sa.Column('provider_account_id', sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column('provider_team', sa.String(length=80), nullable=True))
        batch_op.add_column(sa.Column('cloud', JSON, server_default=sa.text("'{}'"), nullable=False))
        batch_op.add_column(sa.Column('production', sa.Boolean(), server_default=sa.false(), nullable=False))
        batch_op.add_column(sa.Column('retiring_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('retired_by_id', sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            batch_op.f('fk_environments_provider_account_id_provider_accounts'), 'provider_accounts',
            ['provider_account_id'], ['id'], ondelete='RESTRICT',
        )
        batch_op.create_foreign_key(
            batch_op.f('fk_environments_retired_by_id_users'), 'users', ['retired_by_id'], ['id'], ondelete='SET NULL',
        )
        for name, condition in ENV_CHECKS:
            batch_op.create_check_constraint(batch_op.f(f'ck_environments_{name}'), condition)
        batch_op.create_index(
            'ux_environments_one_production', ['repository_id', 'manifest_file'], unique=True,
            postgresql_where=sa.text(ONE_PRODUCTION), sqlite_where=sa.text(ONE_PRODUCTION),
        )

    # 2. Instances: a managed environment's data owner has no host. The foreign key stays RESTRICT.
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.alter_column('host_id', existing_type=sa.Uuid(), nullable=True)
        batch_op.create_check_constraint(
            batch_op.f('ck_instances_host'), "host_id IS NOT NULL OR (slot = 'data' AND environment_id IS NOT NULL)"
        )

    # 3. Backups stored on the Slipway server, each under its own key.
    with op.batch_alter_table('backups', schema=None) as batch_op:
        batch_op.add_column(sa.Column('location', sa.String(length=8), server_default='host', nullable=False))
        batch_op.add_column(sa.Column('data_key', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('stored_bytes', sa.BigInteger(), nullable=True))
        batch_op.create_check_constraint(
            batch_op.f('ck_backups_slipway_key'), "location = 'host' OR data_key IS NOT NULL OR status <> 'ready'"
        )

    # 4. The acme row, so the certificate steps always find one to lock.
    conn = op.get_bind()
    if not conn.execute(sa.text("SELECT count(*) FROM app_settings WHERE key = 'acme'")).scalar_one():
        settings = sa.table('app_settings', sa.column('id', sa.Uuid()), sa.column('key', sa.String()),
                            sa.column('value', JSON))
        conn.execute(settings.insert().values(id=uuid.uuid4(), key='acme', value={}))


def _refuse_while_digitalocean() -> None:
    """Refuse while anything would be orphaned: DigitalOcean objects, backups only Slipway holds, data
    owners without a host."""
    conn = op.get_bind()
    names = conn.execute(sa.text(
        "SELECT name FROM environments WHERE deleted_at IS NULL AND provider = 'digitalocean' "
        "UNION SELECT e.name FROM environments e JOIN resources r ON r.environment_id = e.id "
        "WHERE r.provider = 'digitalocean' ORDER BY name"
    )).scalars().all()
    if names:
        raise RuntimeError(
            f"Slipway still manages DigitalOcean objects for {', '.join(names)}: delete those environments first"
        )
    stored = conn.execute(sa.text("SELECT count(*) FROM backups WHERE location = 'slipway'")).scalar_one()
    if stored:
        raise RuntimeError(f'{stored} backups are stored on this Slipway server; delete them first')
    hostless = conn.execute(sa.text(
        'SELECT DISTINCT e.name FROM instances i LEFT JOIN environments e ON e.id = i.environment_id '
        'WHERE i.host_id IS NULL ORDER BY e.name'
    )).scalars().all()
    if hostless:
        raise RuntimeError(
            f"Slipway still manages DigitalOcean objects for {', '.join(n or '?' for n in hostless)}: "
            "delete those environments first"
        )

    # Jobs of the kinds this revision added mean nothing below it. References are cleared by hand first:
    # SQLite runs migrations without foreign key enforcement, so ON DELETE SET NULL would not fire there.
    jobs = f'SELECT id FROM deployments WHERE kind IN {NEW_KINDS}'
    for table, column in (('backups', 'deployment_id'), ('backups', 'dirty_of'), ('first_admins', 'deployment_id'),
                          ('snapshots', 'deployment_id'), ('deployments', 'retry_of_id')):
        conn.execute(sa.text(f'UPDATE {table} SET {column} = NULL WHERE {column} IN ({jobs})'))
    conn.execute(sa.text(f'DELETE FROM deployments WHERE kind IN {NEW_KINDS}'))


def downgrade() -> None:
    _refuse_while_digitalocean()

    op.get_bind().execute(sa.text("DELETE FROM app_settings WHERE key = 'acme'"))
    with op.batch_alter_table('backups', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('ck_backups_slipway_key'), type_='check')
        batch_op.drop_column('stored_bytes')
        batch_op.drop_column('data_key')
        batch_op.drop_column('location')
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('ck_instances_host'), type_='check')
        batch_op.alter_column('host_id', existing_type=sa.Uuid(), nullable=False)
    with op.batch_alter_table('environments', schema=None) as batch_op:
        batch_op.drop_index('ux_environments_one_production')
        for name, _ in reversed(ENV_CHECKS):
            batch_op.drop_constraint(batch_op.f(f'ck_environments_{name}'), type_='check')
        batch_op.drop_constraint(batch_op.f('fk_environments_retired_by_id_users'), type_='foreignkey')
        batch_op.drop_constraint(batch_op.f('fk_environments_provider_account_id_provider_accounts'),
                                 type_='foreignkey')
        batch_op.drop_column('retired_by_id')
        batch_op.drop_column('retiring_at')
        batch_op.drop_column('production')
        batch_op.drop_column('cloud')
        batch_op.drop_column('provider_team')
        batch_op.drop_column('provider_account_id')
        batch_op.drop_column('provider')
