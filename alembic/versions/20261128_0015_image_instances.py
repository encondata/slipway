"""image instances: instances.image, repository_id nullable for them

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-28 10:00:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0015'
down_revision: str | None = '0014'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.add_column(sa.Column('image', sa.String(length=255), nullable=True))
        batch_op.alter_column('repository_id', existing_type=sa.Uuid(), nullable=True)
        batch_op.create_check_constraint(batch_op.f('ck_instances_source'),
                                         "(repository_id IS NULL) = (build_source = 'image')")
        batch_op.create_check_constraint(batch_op.f('ck_instances_image'), "build_source <> 'image' OR image IS NOT NULL")


def downgrade() -> None:
    conn = op.get_bind()
    if conn.execute(sa.text("SELECT 1 FROM instances WHERE build_source = 'image' LIMIT 1")).first():
        raise RuntimeError("Delete the instances of container images before downgrading below 0015")
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('ck_instances_image'), type_='check')
        batch_op.drop_constraint(batch_op.f('ck_instances_source'), type_='check')
        batch_op.alter_column('repository_id', existing_type=sa.Uuid(), nullable=False)
        batch_op.drop_column('image')
