"""hackspacelabs sign-in: user_sessions.auth_source, idp_sid, idp_tokens, idp_checked_at, auth_time

A HackSpaceLabs link is an oauth_accounts row with provider 'hackspacelabs' (provider is a plain string), so
only sessions need new columns: where the session came from, and for HackSpaceLabs sessions the Keycloak
session id, the encrypted tokens used to recheck it, when it was last rechecked and when the person last
signed in at Keycloak.

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-24 12:00:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0016'
down_revision: str | None = '0015'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('user_sessions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('auth_source', sa.String(length=16), server_default='local', nullable=False))
        batch_op.add_column(sa.Column('idp_sid', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('idp_tokens', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('idp_checked_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('auth_time', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    # An older Slipway can't recheck a HackSpaceLabs session with Keycloak, so those sessions end here rather
    # than run unchecked until they expire. The HackSpaceLabs links stay: older code ignores them.
    op.execute(sa.text("DELETE FROM user_sessions WHERE auth_source = 'oidc'"))
    with op.batch_alter_table('user_sessions', schema=None) as batch_op:
        batch_op.drop_column('auth_time')
        batch_op.drop_column('idp_checked_at')
        batch_op.drop_column('idp_tokens')
        batch_op.drop_column('idp_sid')
        batch_op.drop_column('auth_source')
