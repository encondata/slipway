"""data safety: backups, snapshots, first admins, job kinds

Leftover queued/running deployments are marked failed first (this runs before recover_interrupted).
New tables: snapshots, backups, first_admins.
instances: keep_backups, seed_snapshot_id, seed_content, content_pending, live_identity,
identity_changed_at, identity_source, data_dirty, fresh_data, last_control_at.
deployments: kind, previous_sha, backup_id, restore_backup_id, snapshot_id, options, and the
partial unique index ux_deployments_one_active (one queued or running job per instance).
backups.deployment_id / dirty_of and snapshots.deployment_id come last: they close the cycles.

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-16 09:00:00.000000
"""
from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0008'
down_revision: str | None = '0007'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql')
ACTIVE = "status IN ('queued', 'running')"


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    ]


def _fail_leftover_jobs() -> None:
    """What recover_interrupted does at startup, done here because the new index allows only one
    active job per instance and migrations run before Slipway starts."""
    deployments = sa.table(
        'deployments',
        sa.column('id', sa.Uuid()),
        sa.column('instance_id', sa.Uuid()),
        sa.column('status', sa.String()),
        sa.column('steps', JSON),
        sa.column('error', sa.Text()),
        sa.column('finished_at', sa.DateTime(timezone=True)),
        sa.column('updated_at', sa.DateTime(timezone=True)),
    )
    instances = sa.table('instances', sa.column('id', sa.Uuid()), sa.column('status', sa.String()),
                         sa.column('updated_at', sa.DateTime(timezone=True)))
    conn = op.get_bind()
    now = datetime.now(UTC)
    if conn.dialect.name == 'sqlite':
        now = now.replace(tzinfo=None)  # stored as naive UTC there, like every other timestamp
    stale = conn.execute(
        sa.select(deployments.c.id, deployments.c.instance_id, deployments.c.steps)
        .where(deployments.c.status.in_(['queued', 'running']))
    ).all()
    for dep_id, _instance_id, steps in stale:
        steps = [{**s, 'status': 'failed', 'note': 'Interrupted'} if s.get('status') == 'running' else s
                 for s in steps or []]
        conn.execute(
            deployments.update().where(deployments.c.id == dep_id).values(
                status='failed', steps=steps, error='Interrupted by a Slipway restart', finished_at=now, updated_at=now,
            )
        )
    instance_ids = {row.instance_id for row in stale}
    if instance_ids:
        conn.execute(
            instances.update()
            .where(instances.c.id.in_(instance_ids), instances.c.status == 'deploying')
            .values(status='failed', updated_at=now)
        )


def upgrade() -> None:
    # 0. Leftover active jobs, so the partial unique index below can be built.
    _fail_leftover_jobs()

    # 1. Snapshots (deployment_id comes in step 6).
    op.create_table(
        'snapshots',
        sa.Column('name', sa.String(length=64), nullable=False),
        sa.Column('notes', sa.Text(), server_default='', nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('origin', sa.String(length=16), nullable=False),
        sa.Column('app', sa.String(length=64), nullable=True),
        sa.Column('app_name', sa.String(length=100), nullable=True),
        sa.Column('repository', sa.String(length=200), nullable=True),
        sa.Column('source', sa.String(length=100), nullable=True),
        sa.Column('source_instance_id', sa.Uuid(), nullable=True),
        sa.Column('commit_sha', sa.String(length=40), nullable=True),
        sa.Column('source_created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('db_format', sa.String(length=40), nullable=True),
        sa.Column('db_revision', sa.Text(), nullable=True),
        sa.Column('db_bytes', sa.BigInteger(), nullable=True),
        sa.Column('db_sha256', sa.String(length=64), nullable=True),
        sa.Column('files_format', sa.String(length=40), nullable=True),
        sa.Column('files_bytes', sa.BigInteger(), nullable=True),
        sa.Column('files_sha256', sa.String(length=64), nullable=True),
        sa.Column('identity_keys', JSON, server_default=sa.text("'[]'"), nullable=False),
        sa.Column('data_key', sa.Text(), nullable=True),
        sa.Column('import_keyblock', JSON, nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('file_bytes', sa.BigInteger(), nullable=True),
        sa.Column('file_sha256', sa.String(length=64), nullable=True),
        sa.Column('created_by_id', sa.Uuid(), nullable=True),
        sa.Column('error', sa.String(length=500), nullable=True),
        *_timestamps(),
        sa.CheckConstraint(
            "status <> 'ready' OR (file_sha256 IS NOT NULL AND db_sha256 IS NOT NULL AND app IS NOT NULL)",
            name=op.f('ck_snapshots_ready_is_complete'),
        ),
        sa.ForeignKeyConstraint(['source_instance_id'], ['instances.id'],
                                name=op.f('fk_snapshots_source_instance_id_instances'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'],
                                name=op.f('fk_snapshots_created_by_id_users'), ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_snapshots')),
        sa.UniqueConstraint('name', name=op.f('uq_snapshots_name')),
    )

    # 2. Backups (deployment_id and dirty_of come in step 6).
    op.create_table(
        'backups',
        sa.Column('instance_id', sa.Uuid(), nullable=False),
        sa.Column('name', sa.String(length=32), nullable=False),
        sa.Column('reason', sa.String(length=16), nullable=False),
        sa.Column('status', sa.String(length=16), server_default='pending', nullable=False),
        sa.Column('format', sa.String(length=40), nullable=False),
        sa.Column('db_bytes', sa.BigInteger(), nullable=True),
        sa.Column('db_sha256', sa.String(length=64), nullable=True),
        sa.Column('has_files', sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column('files_format', sa.String(length=40), nullable=True),
        sa.Column('files_bytes', sa.BigInteger(), nullable=True),
        sa.Column('files_sha256', sa.String(length=64), nullable=True),
        sa.Column('revision', sa.Text(), nullable=True),
        sa.Column('commit_sha', sa.String(length=40), nullable=True),
        sa.Column('release', sa.String(length=64), nullable=True),
        sa.Column('identity_keys', JSON, server_default=sa.text("'[]'"), nullable=False),
        sa.Column('identity', sa.Text(), nullable=True),
        sa.Column('identity_fp', sa.String(length=64), nullable=False),
        sa.Column('note', sa.String(length=300), nullable=True),
        sa.Column('created_by_id', sa.Uuid(), nullable=True),
        sa.Column('taken_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('checked_at', sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        sa.CheckConstraint("status <> 'ready' OR db_bytes IS NOT NULL", name=op.f('ck_backups_ready_has_db_bytes')),
        sa.CheckConstraint("NOT has_files OR status <> 'ready' OR files_bytes IS NOT NULL",
                           name=op.f('ck_backups_ready_has_files_bytes')),
        sa.ForeignKeyConstraint(['instance_id'], ['instances.id'],
                                name=op.f('fk_backups_instance_id_instances'), ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'],
                                name=op.f('fk_backups_created_by_id_users'), ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_backups')),
        sa.UniqueConstraint('instance_id', 'name', name=op.f('uq_backups_instance_id')),
    )
    op.create_index(op.f('ix_backups_instance_id'), 'backups', ['instance_id'], unique=False)
    op.create_index('ix_backups_instance_id_taken_at', 'backups', ['instance_id', 'taken_at'], unique=False)

    # 3. First admins.
    op.create_table(
        'first_admins',
        sa.Column('instance_id', sa.Uuid(), nullable=False),
        sa.Column('fields', JSON, nullable=False),
        sa.Column('mode', sa.String(length=8), nullable=False),
        sa.Column('password', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=8), nullable=False),
        sa.Column('existed', sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column('done_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('deployment_id', sa.Uuid(), nullable=True),
        sa.Column('last_error', sa.String(length=300), nullable=True),
        sa.Column('created_by_id', sa.Uuid(), nullable=True),
        *_timestamps(),
        sa.CheckConstraint("mode = 'password' OR password IS NULL",
                           name=op.f('ck_first_admins_password_only_in_password_mode')),
        sa.CheckConstraint("status = 'pending' OR password IS NULL",
                           name=op.f('ck_first_admins_password_only_while_pending')),
        sa.ForeignKeyConstraint(['instance_id'], ['instances.id'],
                                name=op.f('fk_first_admins_instance_id_instances'), ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['deployment_id'], ['deployments.id'],
                                name=op.f('fk_first_admins_deployment_id_deployments'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'],
                                name=op.f('fk_first_admins_created_by_id_users'), ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_first_admins')),
        sa.UniqueConstraint('instance_id', name=op.f('uq_first_admins_instance_id')),
    )

    # 4. Instances.
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.add_column(sa.Column('keep_backups', sa.Integer(), server_default=sa.text('5'), nullable=False))
        batch_op.add_column(sa.Column('seed_snapshot_id', sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column('seed_content', sa.Boolean(), server_default=sa.true(), nullable=False))
        batch_op.add_column(sa.Column('content_pending', sa.Boolean(), server_default=sa.false(), nullable=False))
        batch_op.add_column(sa.Column('live_identity', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('identity_changed_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('identity_source', sa.String(length=300), nullable=True))
        batch_op.add_column(sa.Column('data_dirty', JSON, nullable=True))
        batch_op.add_column(sa.Column('fresh_data', sa.String(length=8), nullable=True))
        batch_op.add_column(sa.Column('last_control_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.create_foreign_key(
            batch_op.f('fk_instances_seed_snapshot_id_snapshots'), 'snapshots', ['seed_snapshot_id'], ['id'],
            ondelete='SET NULL',
        )

    # 5. Deployments.
    with op.batch_alter_table('deployments', schema=None) as batch_op:
        batch_op.add_column(sa.Column('kind', sa.String(length=16), server_default='deploy', nullable=False))
        batch_op.add_column(sa.Column('options', JSON, server_default=sa.text("'{}'"), nullable=False))
        batch_op.add_column(sa.Column('previous_sha', sa.String(length=40), nullable=True))
        batch_op.add_column(sa.Column('backup_id', sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column('restore_backup_id', sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column('snapshot_id', sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            batch_op.f('fk_deployments_backup_id_backups'), 'backups', ['backup_id'], ['id'], ondelete='SET NULL'
        )
        batch_op.create_foreign_key(
            batch_op.f('fk_deployments_restore_backup_id_backups'), 'backups', ['restore_backup_id'], ['id'],
            ondelete='SET NULL',
        )
        batch_op.create_foreign_key(
            batch_op.f('fk_deployments_snapshot_id_snapshots'), 'snapshots', ['snapshot_id'], ['id'], ondelete='SET NULL'
        )
        batch_op.create_index(batch_op.f('ix_deployments_kind'), ['kind'], unique=False)
        batch_op.create_index(
            'ux_deployments_one_active', ['instance_id'], unique=True,
            postgresql_where=sa.text(ACTIVE), sqlite_where=sa.text(ACTIVE),
        )

    # 6. The links back to deployments, now that both ends exist.
    with op.batch_alter_table('backups', schema=None) as batch_op:
        batch_op.add_column(sa.Column('deployment_id', sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column('dirty_of', sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            batch_op.f('fk_backups_deployment_id_deployments'), 'deployments', ['deployment_id'], ['id'],
            ondelete='SET NULL',
        )
        batch_op.create_foreign_key(
            batch_op.f('fk_backups_dirty_of_deployments'), 'deployments', ['dirty_of'], ['id'], ondelete='SET NULL'
        )
    with op.batch_alter_table('snapshots', schema=None) as batch_op:
        batch_op.add_column(sa.Column('deployment_id', sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            batch_op.f('fk_snapshots_deployment_id_deployments'), 'deployments', ['deployment_id'], ['id'],
            ondelete='SET NULL',
        )


def downgrade() -> None:
    # Step 0 (failing leftover jobs) is not undone.
    with op.batch_alter_table('snapshots', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('fk_snapshots_deployment_id_deployments'), type_='foreignkey')
        batch_op.drop_column('deployment_id')
    with op.batch_alter_table('backups', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('fk_backups_dirty_of_deployments'), type_='foreignkey')
        batch_op.drop_constraint(batch_op.f('fk_backups_deployment_id_deployments'), type_='foreignkey')
        batch_op.drop_column('dirty_of')
        batch_op.drop_column('deployment_id')
    with op.batch_alter_table('deployments', schema=None) as batch_op:
        batch_op.drop_index('ux_deployments_one_active')
        batch_op.drop_index(batch_op.f('ix_deployments_kind'))
        batch_op.drop_constraint(batch_op.f('fk_deployments_snapshot_id_snapshots'), type_='foreignkey')
        batch_op.drop_constraint(batch_op.f('fk_deployments_restore_backup_id_backups'), type_='foreignkey')
        batch_op.drop_constraint(batch_op.f('fk_deployments_backup_id_backups'), type_='foreignkey')
        batch_op.drop_column('snapshot_id')
        batch_op.drop_column('restore_backup_id')
        batch_op.drop_column('backup_id')
        batch_op.drop_column('previous_sha')
        batch_op.drop_column('options')
        batch_op.drop_column('kind')
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('fk_instances_seed_snapshot_id_snapshots'), type_='foreignkey')
        batch_op.drop_column('last_control_at')
        batch_op.drop_column('fresh_data')
        batch_op.drop_column('data_dirty')
        batch_op.drop_column('identity_source')
        batch_op.drop_column('identity_changed_at')
        batch_op.drop_column('live_identity')
        batch_op.drop_column('content_pending')
        batch_op.drop_column('seed_content')
        batch_op.drop_column('seed_snapshot_id')
        batch_op.drop_column('keep_backups')
    op.drop_table('first_admins')
    op.drop_index('ix_backups_instance_id_taken_at', table_name='backups')
    op.drop_index(op.f('ix_backups_instance_id'), table_name='backups')
    op.drop_table('backups')
    op.drop_table('snapshots')
