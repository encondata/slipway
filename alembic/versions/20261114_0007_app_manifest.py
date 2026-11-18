"""apps from slipway.yml, deployment steps and retries

instances: manifest_file, app_settings, app_services, app_secrets, app_state.
deployments: steps, release, retry_of_id.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-14 18:00:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0007'
down_revision: str | None = '0006'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql')


def upgrade() -> None:
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.add_column(sa.Column('manifest_file', sa.String(length=255), server_default='slipway.yml', nullable=False))
        batch_op.add_column(sa.Column('app_settings', JSON, server_default=sa.text("'{}'"), nullable=False))
        batch_op.add_column(sa.Column('app_services', JSON, nullable=True))
        batch_op.add_column(sa.Column('app_secrets', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('app_state', JSON, nullable=True))
    with op.batch_alter_table('deployments', schema=None) as batch_op:
        batch_op.add_column(sa.Column('steps', JSON, server_default=sa.text("'[]'"), nullable=False))
        batch_op.add_column(sa.Column('release', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('retry_of_id', sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            batch_op.f('fk_deployments_retry_of_id_deployments'), 'deployments', ['retry_of_id'], ['id'], ondelete='SET NULL'
        )


def downgrade() -> None:
    with op.batch_alter_table('deployments', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('fk_deployments_retry_of_id_deployments'), type_='foreignkey')
        batch_op.drop_column('retry_of_id')
        batch_op.drop_column('release')
        batch_op.drop_column('steps')
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.drop_column('app_state')
        batch_op.drop_column('app_secrets')
        batch_op.drop_column('app_services')
        batch_op.drop_column('app_settings')
        batch_op.drop_column('manifest_file')
