"""add_ban_fields_to_users

Revision ID: b3c4d5e6f7a8
Revises: 69e00397c3ed
Create Date: 2026-03-19 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b3c4d5e6f7a8'
down_revision: Union[str, None] = '69e00397c3ed'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'users',
        sa.Column(
            'is_banned',
            sa.Boolean(),
            nullable=False,
            server_default='0',
        ),
    )
    op.add_column(
        'users',
        sa.Column(
            'ban_reason',
            sa.String(500),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column('users', 'ban_reason')
    op.drop_column('users', 'is_banned')
