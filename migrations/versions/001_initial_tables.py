"""Initial schema for FileScanner

Revision ID: 001_initial_tables
Revises: 
Create Date: 2026-11-05 10:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '001_initial_tables'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # scan_histories
    op.create_table(
        'scan_histories',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('scan_id', sa.String(length=36), nullable=False),
        sa.Column('scan_type', sa.String(length=20), nullable=False),
        sa.Column('target_name', sa.String(length=255), nullable=True),
        sa.Column('target_url', sa.Text(), nullable=True),
        sa.Column('overall_status', sa.String(length=30), nullable=False, server_default='SCANNING'),
        sa.Column('scanner_status', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scan_histories_id'), 'scan_histories', ['id'], unique=False)
    op.create_index(op.f('ix_scan_histories_scan_id'), 'scan_histories', ['scan_id'], unique=True)

    # scan_files
    op.create_table(
        'scan_files',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('scan_history_id', sa.Integer(), nullable=False),
        sa.Column('original_filename', sa.String(length=255), nullable=False),
        sa.Column('stored_filename', sa.String(length=255), nullable=False),
        sa.Column('file_extension', sa.String(length=50), nullable=True),
        sa.Column('mime_type', sa.String(length=100), nullable=True),
        sa.Column('file_size', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
        sa.Column('scan_status', sa.String(length=30), nullable=False, server_default='SCANNING'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['scan_history_id'], ['scan_histories.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scan_files_id'), 'scan_files', ['id'], unique=False)
    op.create_index(op.f('ix_scan_files_sha256_hash'), 'scan_files', ['sha256_hash'], unique=False)

    # threat_detections
    op.create_table(
        'threat_detections',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('scan_history_id', sa.Integer(), nullable=False),
        sa.Column('scan_file_id', sa.Integer(), nullable=True),
        sa.Column('scanner_name', sa.String(length=50), nullable=False),
        sa.Column('threat_name', sa.String(length=255), nullable=False),
        sa.Column('threat_category', sa.String(length=100), nullable=False),
        sa.Column('severity', sa.String(length=50), nullable=False, server_default='HIGH'),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['scan_file_id'], ['scan_files.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scan_history_id'], ['scan_histories.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_threat_detections_id'), 'threat_detections', ['id'], unique=False)

    # scan_reports
    op.create_table(
        'scan_reports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('scan_history_id', sa.Integer(), nullable=False),
        sa.Column('report_json', sa.JSON(), nullable=False),
        sa.Column('report_path', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['scan_history_id'], ['scan_histories.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scan_reports_id'), 'scan_reports', ['id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_scan_reports_id'), table_name='scan_reports')
    op.drop_table('scan_reports')
    op.drop_index(op.f('ix_threat_detections_id'), table_name='threat_detections')
    op.drop_table('threat_detections')
    op.drop_index(op.f('ix_scan_files_sha256_hash'), table_name='scan_files')
    op.drop_index(op.f('ix_scan_files_id'), table_name='scan_files')
    op.drop_table('scan_files')
    op.drop_index(op.f('ix_scan_histories_scan_id'), table_name='scan_histories')
    op.drop_index(op.f('ix_scan_histories_id'), table_name='scan_histories')
    op.drop_table('scan_histories')

