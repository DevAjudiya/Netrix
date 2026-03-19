"""create system_metrics table

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
Create Date: 2026-03-19 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd5e6f7a8b9c0'
down_revision = 'c4d5e6f7a8b9'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'system_metrics',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('cpu_percent', sa.Float(), nullable=False),
        sa.Column('memory_percent', sa.Float(), nullable=False),
        sa.Column('redis_status', sa.Boolean(), nullable=False),
        sa.Column('mysql_status', sa.Boolean(), nullable=False),
        sa.Column('nmap_status', sa.Boolean(), nullable=False),
        sa.Column('active_scans', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('queue_depth', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('recorded_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_system_metrics_recorded_at', 'system_metrics', ['recorded_at'])


def downgrade() -> None:
    op.drop_index('ix_system_metrics_recorded_at', table_name='system_metrics')
    op.drop_table('system_metrics')
