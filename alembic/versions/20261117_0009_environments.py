"""environments: environments, resources, slots, environment jobs, host labels

New tables: environments (active_slot_id comes in step 5, closing the instances/environments cycle) and
resources (every Switchyard host and DNS record an environment manages).
hosts: environment -> label; provider, provider_id, lan_address, owner_environment_id.
instances: environment_id, slot, slot_state; one instance per slot of an environment.
deployments: instance_id nullable (environment-level jobs), environment_id, and the partial unique
indexes ux_deployments_one_active_env and ux_deployments_one_active_activate (one job per environment,
plus at most one activate).

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-17 09:00:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0009'
down_revision: str | None = '0008'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql')
LIVE = 'deleted_at IS NULL'
ACTIVE_ENV_JOB = "status IN ('queued', 'running') AND kind <> 'activate'"
ACTIVE_ACTIVATE = "status IN ('queued', 'running') AND kind = 'activate'"


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    ]


def upgrade() -> None:
    # 1. Environments (active_slot_id comes in step 5, once instances can point back).
    op.create_table(
        'environments',
        sa.Column('name', sa.String(length=26), nullable=False),
        sa.Column('repository_id', sa.Uuid(), nullable=False),
        sa.Column('branch', sa.String(length=255), nullable=False),
        sa.Column('manifest_file', sa.String(length=255), server_default='slipway.yml', nullable=False),
        sa.Column('data_mode', sa.String(length=8), nullable=False),
        sa.Column('app_settings', JSON, server_default=sa.text("'{}'"), nullable=False),
        sa.Column('app_services', JSON, nullable=True),
        sa.Column('app_secrets', sa.Text(), nullable=True),
        sa.Column('secrets_version', sa.Integer(), server_default=sa.text('0'), nullable=False),
        sa.Column('env', sa.Text(), nullable=True),
        sa.Column('route_tls', JSON, server_default=sa.text("'{}'"), nullable=False),
        sa.Column('hostnames', JSON, server_default=sa.text("'[]'"), nullable=False),
        sa.Column('auto_activate', sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column('traffic', JSON, server_default=sa.text("""'{"switch": "none", "dns": null}'"""), nullable=False),
        sa.Column('traffic_state', JSON, server_default=sa.text("'{}'"), nullable=False),
        sa.Column('status', sa.String(length=16), server_default='new', nullable=False),
        sa.Column('notice', JSON, nullable=True),
        sa.Column('created_by_id', sa.Uuid(), nullable=True),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('deleted_by_id', sa.Uuid(), nullable=True),
        *_timestamps(),
        sa.CheckConstraint("(status = 'deleted') = (deleted_at IS NOT NULL)", name=op.f('ck_environments_deleted')),
        sa.CheckConstraint("data_mode IN ('slot', 'server', 'managed')", name=op.f('ck_environments_data_mode')),
        sa.ForeignKeyConstraint(['repository_id'], ['repositories.id'],
                                name=op.f('fk_environments_repository_id_repositories'), ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'],
                                name=op.f('fk_environments_created_by_id_users'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['deleted_by_id'], ['users.id'],
                                name=op.f('fk_environments_deleted_by_id_users'), ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_environments')),
    )
    op.create_index('ux_environments_name_live', 'environments', ['name'], unique=True,
                    postgresql_where=sa.text(LIVE), sqlite_where=sa.text(LIVE))

    # 2. Resources: the outside objects an environment manages.
    op.create_table(
        'resources',
        sa.Column('environment_id', sa.Uuid(), nullable=False),
        sa.Column('instance_id', sa.Uuid(), nullable=True),
        sa.Column('provider', sa.String(length=16), nullable=False),
        sa.Column('kind', sa.String(length=32), nullable=False),
        sa.Column('provider_id', sa.String(length=200), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('origin', sa.String(length=8), nullable=False),
        sa.Column('details', JSON, server_default=sa.text("'{}'"), nullable=False),
        sa.Column('tags', JSON, server_default=sa.text("'[]'"), nullable=False),
        sa.Column('credentials', sa.Text(), nullable=True),
        sa.Column('created_by_id', sa.Uuid(), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(['environment_id'], ['environments.id'],
                                name=op.f('fk_resources_environment_id_environments'), ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['instance_id'], ['instances.id'],
                                name=op.f('fk_resources_instance_id_instances'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'],
                                name=op.f('fk_resources_created_by_id_users'), ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_resources')),
        sa.UniqueConstraint('provider', 'kind', 'provider_id', name=op.f('uq_resources_provider_kind_provider_id')),
        sa.UniqueConstraint('environment_id', 'kind', 'name', name=op.f('uq_resources_environment_id_kind_name')),
    )
    op.create_index(op.f('ix_resources_environment_id'), 'resources', ['environment_id'], unique=False)

    # 3. Hosts: the free-text "environment" becomes "label" (same values); provider fields for phases 4-5.
    with op.batch_alter_table('hosts', schema=None) as batch_op:
        batch_op.alter_column('environment', new_column_name='label', existing_type=sa.String(length=32),
                              existing_nullable=False)
        batch_op.add_column(sa.Column('provider', sa.String(length=16), server_default='ssh', nullable=False))
        batch_op.add_column(sa.Column('provider_id', sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column('lan_address', sa.String(length=45), nullable=True))
        batch_op.add_column(sa.Column('owner_environment_id', sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            batch_op.f('fk_hosts_owner_environment_id_environments'), 'environments', ['owner_environment_id'], ['id'],
            ondelete='SET NULL',
        )

    # 4. Instances: slots of an environment.
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.add_column(sa.Column('environment_id', sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column('slot', sa.String(length=8), nullable=True))
        batch_op.add_column(sa.Column('slot_state', JSON, server_default=sa.text("'{}'"), nullable=False))
        batch_op.create_foreign_key(
            batch_op.f('fk_instances_environment_id_environments'), 'environments', ['environment_id'], ['id'],
            ondelete='RESTRICT',
        )
        batch_op.create_index(batch_op.f('ix_instances_environment_id'), ['environment_id'], unique=False)
        batch_op.create_unique_constraint(batch_op.f('uq_instances_environment_id_slot'), ['environment_id', 'slot'])
        batch_op.create_check_constraint(batch_op.f('ck_instances_slot_pair'), '(environment_id IS NULL) = (slot IS NULL)')

    # 5. The active slot, now that both ends exist.
    with op.batch_alter_table('environments', schema=None) as batch_op:
        batch_op.add_column(sa.Column('active_slot_id', sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            batch_op.f('fk_environments_active_slot_id_instances'), 'instances', ['active_slot_id'], ['id'],
            ondelete='SET NULL',
        )

    # 6. Deployments: environment-level jobs have no instance. The instance FK keeps ON DELETE CASCADE and
    # ux_deployments_one_active keeps its WHERE (PostgreSQL alters in place; SQLite's batch copies both).
    with op.batch_alter_table('deployments', schema=None) as batch_op:
        batch_op.alter_column('instance_id', existing_type=sa.Uuid(), nullable=True)
        batch_op.add_column(sa.Column('environment_id', sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            batch_op.f('fk_deployments_environment_id_environments'), 'environments', ['environment_id'], ['id'],
            ondelete='SET NULL',
        )
        batch_op.create_index(batch_op.f('ix_deployments_environment_id'), ['environment_id'], unique=False)
        batch_op.create_check_constraint(
            batch_op.f('ck_deployments_subject'), 'instance_id IS NOT NULL OR environment_id IS NOT NULL'
        )
        batch_op.create_index(
            'ux_deployments_one_active_env', ['environment_id'], unique=True,
            postgresql_where=sa.text(ACTIVE_ENV_JOB), sqlite_where=sa.text(ACTIVE_ENV_JOB),
        )
        batch_op.create_index(
            'ux_deployments_one_active_activate', ['environment_id'], unique=True,
            postgresql_where=sa.text(ACTIVE_ACTIVATE), sqlite_where=sa.text(ACTIVE_ACTIVATE),
        )


def _forget_environments() -> None:
    """Refuse while an environment is live or a resource is recorded; otherwise drop what only phase 3
    could hold: environment-level jobs and the (deleted) environment rows.

    References are cleared by hand before each delete: SQLite runs migrations without foreign key
    enforcement, so ON DELETE SET NULL would not fire there.
    """
    conn = op.get_bind()
    live = conn.execute(sa.text(f'SELECT name FROM environments WHERE {LIVE} ORDER BY name')).scalars().all()
    if live:
        raise RuntimeError(f"Delete every environment before downgrading below 0009 (still here: {', '.join(live)})")
    count = conn.execute(sa.text('SELECT count(*) FROM resources')).scalar_one()
    if count:
        raise RuntimeError(f'resources still lists {count} objects Slipway made; delete their environments first')

    env_jobs = 'SELECT id FROM deployments WHERE instance_id IS NULL'
    for table, column in (('backups', 'deployment_id'), ('backups', 'dirty_of'), ('first_admins', 'deployment_id'),
                          ('snapshots', 'deployment_id'), ('deployments', 'retry_of_id')):
        conn.execute(sa.text(f'UPDATE {table} SET {column} = NULL WHERE {column} IN ({env_jobs})'))
    conn.execute(sa.text('DELETE FROM deployments WHERE instance_id IS NULL'))
    conn.execute(sa.text('UPDATE deployments SET environment_id = NULL WHERE environment_id IS NOT NULL'))
    # A deleted environment has no slots left; any instance still marked as one becomes standalone.
    conn.execute(sa.text('UPDATE instances SET environment_id = NULL, slot = NULL WHERE environment_id IS NOT NULL'))
    conn.execute(sa.text('UPDATE hosts SET owner_environment_id = NULL WHERE owner_environment_id IS NOT NULL'))
    conn.execute(sa.text('DELETE FROM environments'))


def downgrade() -> None:
    _forget_environments()

    with op.batch_alter_table('deployments', schema=None) as batch_op:
        batch_op.drop_index('ux_deployments_one_active_activate')
        batch_op.drop_index('ux_deployments_one_active_env')
        batch_op.drop_constraint(batch_op.f('ck_deployments_subject'), type_='check')
        batch_op.drop_index(batch_op.f('ix_deployments_environment_id'))
        batch_op.drop_constraint(batch_op.f('fk_deployments_environment_id_environments'), type_='foreignkey')
        batch_op.drop_column('environment_id')
        batch_op.alter_column('instance_id', existing_type=sa.Uuid(), nullable=False)
    with op.batch_alter_table('environments', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('fk_environments_active_slot_id_instances'), type_='foreignkey')
        batch_op.drop_column('active_slot_id')
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('ck_instances_slot_pair'), type_='check')
        batch_op.drop_constraint(batch_op.f('uq_instances_environment_id_slot'), type_='unique')
        batch_op.drop_index(batch_op.f('ix_instances_environment_id'))
        batch_op.drop_constraint(batch_op.f('fk_instances_environment_id_environments'), type_='foreignkey')
        batch_op.drop_column('slot_state')
        batch_op.drop_column('slot')
        batch_op.drop_column('environment_id')
    with op.batch_alter_table('hosts', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('fk_hosts_owner_environment_id_environments'), type_='foreignkey')
        batch_op.drop_column('owner_environment_id')
        batch_op.drop_column('lan_address')
        batch_op.drop_column('provider_id')
        batch_op.drop_column('provider')
        batch_op.alter_column('label', new_column_name='environment', existing_type=sa.String(length=32),
                              existing_nullable=False)
    op.drop_index(op.f('ix_resources_environment_id'), table_name='resources')
    op.drop_table('resources')
    op.drop_index('ux_environments_name_live', table_name='environments')
    op.drop_table('environments')
