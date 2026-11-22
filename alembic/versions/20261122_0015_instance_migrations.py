"""instance migrations: instances.migrated_from

A migration is a deployment of kind 'migrate' (deployments.kind is a plain string), with its request in
deployments.options["migration"]. Only the stopped copy left on the old host needs a column of its own.

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-22 12:00:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0015'
down_revision: str | None = '0014'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql')


def upgrade() -> None:
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.add_column(sa.Column('migrated_from', JSON, nullable=True))


def downgrade() -> None:
    # Migrations still on record are failed and their kind turned back into a deploy, so an older Slipway
    # neither runs one again nor meets a kind it doesn't know.
    op.execute(sa.text(
        "UPDATE deployments SET status = 'failed', error = COALESCE(error, 'Slipway was downgraded') "
        "WHERE kind = 'migrate' AND status IN ('queued', 'running')"
    ))
    op.execute(sa.text("UPDATE deployments SET kind = 'deploy' WHERE kind = 'migrate'"))
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.drop_column('migrated_from')
