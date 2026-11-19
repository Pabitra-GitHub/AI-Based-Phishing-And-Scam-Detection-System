"""Initial schema migration: users, scans, detection_reasons, audit_logs

Revision ID: 001
Revises: None
Create Date: 2026-10-02 12:00:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. users
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=20), nullable=False, server_default='USER'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_users_id', 'users', ['id'], unique=False)
    op.create_index('ix_users_email', 'users', ['email'], unique=True)

    # 2. scans
    op.create_table(
        'scans',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=True),
        sa.Column('session_id', sa.String(length=64), nullable=True),
        sa.Column('input_type', sa.String(length=20), nullable=False, server_default='URL'),
        sa.Column('input_value', sa.String(length=2048), nullable=False),
        sa.Column('risk_score', sa.Integer(), nullable=False),
        sa.Column('rule_score', sa.Integer(), nullable=True, server_default='0'),
        sa.Column('classification', sa.String(length=30), nullable=False),
        sa.Column('ml_probability', sa.Float(), nullable=False),
        sa.Column('model_version', sa.String(length=50), nullable=False, server_default='v2.0.0'),
        sa.Column('recommendation', sa.String(length=500), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('layer_results', sa.Text(), nullable=True),
        sa.Column('redirect_chain', sa.Text(), nullable=True),
        sa.Column('screenshot_path', sa.String(length=500), nullable=True),
        sa.Column('scan_duration_ms', sa.Integer(), nullable=True),
        sa.Column('layers_executed', sa.String(length=50), nullable=True),
    )
    op.create_index('ix_scans_id', 'scans', ['id'], unique=False)
    op.create_index('ix_scans_user_id', 'scans', ['user_id'], unique=False)
    op.create_index('ix_scans_session_id', 'scans', ['session_id'], unique=False)
    op.create_index('ix_scans_created_at', 'scans', ['created_at'], unique=False)

    # 3. detection_reasons
    op.create_table(
        'detection_reasons',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('scan_id', sa.String(length=36), sa.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False),
        sa.Column('title', sa.String(length=100), nullable=True),
        sa.Column('reason', sa.String(length=500), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False, server_default='MEDIUM'),
        sa.Column('source', sa.String(length=20), nullable=False, server_default='RULE'),
        sa.Column('layer', sa.String(length=10), nullable=True),
    )
    op.create_index('ix_detection_reasons_id', 'detection_reasons', ['id'], unique=False)
    op.create_index('ix_detection_reasons_scan_id', 'detection_reasons', ['scan_id'], unique=False)

    # 4. audit_logs
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_audit_logs_id', 'audit_logs', ['id'], unique=False)
    op.create_index('ix_audit_logs_user_id', 'audit_logs', ['user_id'], unique=False)
    op.create_index('ix_audit_logs_created_at', 'audit_logs', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('detection_reasons')
    op.drop_table('scans')
    op.drop_table('users')
