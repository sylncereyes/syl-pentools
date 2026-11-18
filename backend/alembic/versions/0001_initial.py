"""Initial migration

Revision ID: 0001
Revises: 
Create Date: 2024-01-15 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0001'
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Enable UUID extension
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')
    
    # Users table
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('email', sa.String(255), nullable=False, unique=True),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('full_name', sa.String(255)),
        sa.Column('avatar_url', sa.String(500)),
        sa.Column('role', sa.Enum('owner', 'admin', 'member', 'viewer', name='user_role'), nullable=False, server_default='member'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_verified', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('two_factor_enabled', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('two_factor_secret', sa.String(255)),
        sa.Column('last_login', sa.DateTime(timezone=True)),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_users_email', 'users', ['email'], unique=True)
    
    # Workspaces table
    op.create_table(
        'workspaces',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('slug', sa.String(100), nullable=False, unique=True),
        sa.Column('description', sa.Text()),
        sa.Column('plan', sa.Enum('free', 'netscan', 'appscan', 'exploit', 'enterprise', name='plan_type'), nullable=False, server_default='free'),
        sa.Column('asset_limit', sa.Integer(), nullable=False, server_default='100'),
        sa.Column('concurrent_scan_limit', sa.Integer(), nullable=False, server_default='2'),
        sa.Column('scheduled_scan_limit', sa.Integer(), nullable=False, server_default='10'),
        sa.Column('team_member_limit', sa.Integer(), nullable=False, server_default='10'),
        sa.Column('ai_pentests_enabled', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('branded_reports', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('custom_integrations', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('internal_scanning', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('stripe_customer_id', sa.String(255)),
        sa.Column('stripe_subscription_id', sa.String(255)),
        sa.Column('subscription_status', sa.String(50)),
        sa.Column('subscription_current_period_end', sa.DateTime(timezone=True)),
        sa.Column('settings', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_workspaces_slug', 'workspaces', ['slug'], unique=True)
    
    # Workspace members table
    op.create_table(
        'workspace_members',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('workspace_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('role', sa.Enum('owner', 'admin', 'member', 'viewer', name='user_role'), nullable=False, server_default='member'),
        sa.Column('joined_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('invited_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
    )
    op.create_index('ix_workspace_members_workspace_user', 'workspace_members', ['workspace_id', 'user_id'], unique=True)
    op.create_index('ix_workspace_members_workspace_id', 'workspace_members', ['workspace_id'])
    op.create_index('ix_workspace_members_user_id', 'workspace_members', ['user_id'])
    
    # Assets table
    op.create_table(
        'assets',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('workspace_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('target', sa.String(500), nullable=False),
        sa.Column('type', sa.Enum('hostname', 'ip_address', 'cidr', 'url', name='asset_type'), nullable=False, server_default='hostname'),
        sa.Column('description', sa.Text()),
        sa.Column('resolved_ips', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('is_resolved', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('risk_level', sa.Enum('none', 'low', 'medium', 'high', 'critical', name='asset_risk_level'), nullable=False, server_default='none'),
        sa.Column('risk_score', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('tags', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('metadata', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('total_scans', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_scanned_at', sa.DateTime(timezone=True)),
        sa.Column('open_ports_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('vulnerabilities_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('critical_vulns', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('high_vulns', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('medium_vulns', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('low_vulns', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('deleted_at', sa.DateTime(timezone=True)),
    )
    op.create_index('ix_assets_workspace_id', 'assets', ['workspace_id'])
    op.create_index('ix_assets_target', 'assets', ['target'])
    op.create_index('ix_assets_created_at', 'assets', ['created_at'])
    
    # Asset groups
    op.create_table(
        'asset_groups',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('workspace_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text()),
        sa.Column('color', sa.String(7)),
        sa.Column('is_default', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_asset_groups_workspace_id', 'asset_groups', ['workspace_id'])
    
    op.create_table(
        'asset_group_members',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('group_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('asset_groups.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('added_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_asset_group_members_group_asset', 'asset_group_members', ['group_id', 'asset_id'], unique=True)
    
    # Scans table
    op.create_table(
        'scans',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('workspace_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('assets.id', ondelete='SET NULL'), nullable=True),
        sa.Column('scheduled_scan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scheduled_scans.id', ondelete='SET NULL'), nullable=True),
        sa.Column('name', sa.String(255)),
        sa.Column('type', sa.Enum('website', 'network', 'port', 'subdomain', 'recon', 'password', 'ai_pentest', 'full', name='scan_type'), nullable=False),
        sa.Column('target', sa.String(500), nullable=False),
        sa.Column('intensity', sa.Enum('light', 'normal', 'aggressive', name='scan_intensity'), nullable=False, server_default='normal'),
        sa.Column('is_authenticated', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('auth_config', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('login_recording_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('login_recordings.id'), nullable=True),
        sa.Column('status', sa.Enum('pending', 'queued', 'running', 'paused', 'completed', 'failed', 'cancelled', 'retrying', name='scan_status'), nullable=False, server_default='pending'),
        sa.Column('progress', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('current_step', sa.String(255)),
        sa.Column('steps_completed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('total_steps', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('findings_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('critical_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('high_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('medium_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('low_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('info_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('scanner_version', sa.String(100)),
        sa.Column('scanner_config', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('raw_output_path', sa.String(500)),
        sa.Column('error_message', sa.Text()),
        sa.Column('started_at', sa.DateTime(timezone=True)),
        sa.Column('completed_at', sa.DateTime(timezone=True)),
        sa.Column('duration_seconds', sa.Integer()),
        sa.Column('queued_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('celery_task_id', sa.String(255)),
        sa.Column('retry_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('max_retries', sa.Integer(), nullable=False, server_default='2'),
        sa.Column('parent_scan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scans.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_scans_workspace_id', 'scans', ['workspace_id'])
    op.create_index('ix_scans_asset_id', 'scans', ['asset_id'])
    op.create_index('ix_scans_status', 'scans', ['status'])
    op.create_index('ix_scans_queued_at', 'scans', ['queued_at'])
    op.create_index('ix_scans_celery_task_id', 'scans', ['celery_task_id'])
    op.create_index('ix_scans_workspace_status', 'scans', ['workspace_id', 'status'])
    op.create_index('ix_scans_asset_status', 'scans', ['asset_id', 'status'])
    
    # Scan logs
    op.create_table(
        'scan_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False),
        sa.Column('level', sa.String(20), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('step', sa.String(255)),
        sa.Column('progress', sa.Float()),
        sa.Column('metadata', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_scan_logs_scan_id', 'scan_logs', ['scan_id'])
    op.create_index('ix_scan_logs_created_at', 'scan_logs', ['created_at'])
    
    # Login recordings
    op.create_table(
        'login_recordings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('workspace_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('target_url', sa.String(500), nullable=False),
        sa.Column('steps', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('selectors', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('cookies', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('headers', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('local_storage', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('session_storage', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('is_valid', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('last_validated', sa.DateTime(timezone=True)),
        sa.Column('validation_error', sa.Text()),
        sa.Column('browser_version', sa.String(100)),
        sa.Column('user_agent', sa.String(500)),
        sa.Column('viewport', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
    )
    op.create_index('ix_login_recordings_workspace_id', 'login_recordings', ['workspace_id'])
    
    # Findings table
    op.create_table(
        'findings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('workspace_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.Enum('critical', 'high', 'medium', 'low', 'info', name='finding_severity'), nullable=False),
        sa.Column('status', sa.Enum('open', 'verified', 'false_positive', 'fixed', 'ignored', 'risk_accepted', name='finding_status'), nullable=False, server_default='open'),
        sa.Column('cwe_id', sa.String(20)),
        sa.Column('cve_ids', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('owasp_category', sa.String(100)),
        sa.Column('cvss_score', sa.Float()),
        sa.Column('cvss_vector', sa.String(200)),
        sa.Column('target_url', sa.String(500)),
        sa.Column('parameter', sa.String(255)),
        sa.Column('method', sa.String(20)),
        sa.Column('path', sa.String(500)),
        sa.Column('evidence', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('reproduction_steps', sa.Text()),
        sa.Column('proof_of_concept', sa.Text()),
        sa.Column('remediation', sa.Text()),
        sa.Column('remediation_complexity', sa.String(50)),
        sa.Column('references', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('assigned_to', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('verified_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('verified_at', sa.DateTime(timezone=True)),
        sa.Column('fixed_at', sa.DateTime(timezone=True)),
        sa.Column('fingerprint', sa.String(64)),
        sa.Column('is_duplicate', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('duplicate_of', postgresql.UUID(as_uuid=True), sa.ForeignKey('findings.id'), nullable=True),
        sa.Column('tags', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('source_scanner', sa.String(100)),
        sa.Column('source_finding_id', sa.String(255)),
        sa.Column('source_rule_id', sa.String(255)),
        sa.Column('compliance_mappings', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('closed_at', sa.DateTime(timezone=True)),
    )
    op.create_index('ix_findings_workspace_id', 'findings', ['workspace_id'])
    op.create_index('ix_findings_scan_id', 'findings', ['scan_id'])
    op.create_index('ix_findings_asset_id', 'findings', ['asset_id'])
    op.create_index('ix_findings_severity', 'findings', ['severity'])
    op.create_index('ix_findings_status', 'findings', ['status'])
    op.create_index('ix_findings_fingerprint', 'findings', ['fingerprint'])
    op.create_index('ix_findings_workspace_severity', 'findings', ['workspace_id', 'severity'])
    op.create_index('ix_findings_workspace_status', 'findings', ['workspace_id', 'status'])
    
    # Finding comments
    op.create_table(
        'finding_comments',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('finding_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('is_internal', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_finding_comments_finding_id', 'finding_comments', ['finding_id'])
    
    # Finding attachments
    op.create_table(
        'finding_attachments',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('finding_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False),
        sa.Column('filename', sa.String(255), nullable=False),
        sa.Column('file_path', sa.String(500), nullable=False),
        sa.Column('file_size', sa.Integer()),
        sa.Column('mime_type', sa.String(100)),
        sa.Column('uploaded_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('uploaded_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_finding_attachments_finding_id', 'finding_attachments', ['finding_id'])
    
    # Integrations
    op.create_table(
        'integrations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('workspace_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('type', sa.Enum('slack', 'teams', 'webhook', 'jira', 'github', 'discord', 'vanta', 'burp', 'aws', 'nucleus', 'mcp', 'cicd', 'email', 'pagerduty', 'servicenow', 'zendesk', name='integration_type'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text()),
        sa.Column('config', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('config_encrypted', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_configured', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('last_sync', sa.DateTime(timezone=True)),
        sa.Column('last_error', sa.Text()),
        sa.Column('error_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('severity_filter', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('scan_type_filter', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('asset_filter', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('webhook_url', sa.String(500)),
        sa.Column('webhook_secret', sa.String(255)),
        sa.Column('webhook_events', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('rate_limit_per_minute', sa.Integer(), nullable=False, server_default='60'),
        sa.Column('rate_limit_burst', sa.Integer(), nullable=False, server_default='10'),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_integrations_workspace_id', 'integrations', ['workspace_id'])
    op.create_index('ix_integrations_workspace_type', 'integrations', ['workspace_id', 'type'])
    op.create_index('ix_integrations_is_enabled', 'integrations', ['is_enabled'])
    
    # Integration notifications
    op.create_table(
        'integration_notifications',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('integration_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('integrations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('event_type', sa.String(100), nullable=False),
        sa.Column('payload', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('status', sa.String(50), nullable=False, server_default='pending'),
        sa.Column('response_code', sa.Integer()),
        sa.Column('response_body', sa.Text()),
        sa.Column('error_message', sa.Text()),
        sa.Column('attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('max_attempts', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('next_retry_at', sa.DateTime(timezone=True)),
        sa.Column('sent_at', sa.DateTime(timezone=True)),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_integration_notifications_integration_id', 'integration_notifications', ['integration_id'])
    op.create_index('ix_integration_notifications_status', 'integration_notifications', ['status'])
    op.create_index('ix_integration_notifications_created_at', 'integration_notifications', ['created_at'])
    
    # Report templates
    op.create_table(
        'report_templates',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('workspace_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text()),
        sa.Column('type', sa.Enum('executive', 'technical', 'compliance', 'engagement', 'custom', name='report_template_type'), nullable=False, server_default='custom'),
        sa.Column('compliance_frameworks', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('template_content', sa.Text(), nullable=False),
        sa.Column('template_variables', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('logo_path', sa.String(500)),
        sa.Column('primary_color', sa.String(7)),
        sa.Column('secondary_color', sa.String(7)),
        sa.Column('font_family', sa.String(100)),
        sa.Column('footer_text', sa.Text()),
        sa.Column('sections', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('default_formats', postgresql.JSONB(), nullable=False, server_default='["pdf", "docx"]'),
        sa.Column('is_default', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('is_system', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_report_templates_workspace_id', 'report_templates', ['workspace_id'])
    
    # Reports
    op.create_table(
        'reports',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('workspace_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('template_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('report_templates.id', ondelete='SET NULL'), nullable=True),
        sa.Column('scan_ids', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('finding_ids', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('asset_ids', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('description', sa.Text()),
        sa.Column('format', sa.Enum('pdf', 'docx', 'html', 'csv', 'json', name='report_format'), nullable=False, server_default='pdf'),
        sa.Column('status', sa.Enum('draft', 'generating', 'ready', 'failed', 'expired', name='report_status'), nullable=False, server_default='draft'),
        sa.Column('severity_filter', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('status_filter', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('date_range', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('file_path', sa.String(500)),
        sa.Column('file_size', sa.Integer()),
        sa.Column('page_count', sa.Integer()),
        sa.Column('generation_error', sa.Text()),
        sa.Column('generation_duration_seconds', sa.Float()),
        sa.Column('generated_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('expires_at', sa.DateTime(timezone=True)),
        sa.Column('download_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_downloaded_at', sa.DateTime(timezone=True)),
        sa.Column('compliance_frameworks', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('compliance_mapping', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('engagement_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('engagements.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True)),
    )
    op.create_index('ix_reports_workspace_id', 'reports', ['workspace_id'])
    op.create_index('ix_reports_status', 'reports', ['status'])
    op.create_index('ix_reports_workspace_status', 'reports', ['workspace_id', 'status'])
    
    # Engagements
    op.create_table(
        'engagements',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('workspace_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text()),
        sa.Column('scope', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('rules_of_engagement', sa.Text()),
        sa.Column('lead_tester', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('team_members', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('start_date', sa.DateTime(timezone=True)),
        sa.Column('end_date', sa.DateTime(timezone=True)),
        sa.Column('status', sa.String(50), nullable=False, server_default='planning'),
        sa.Column('deliverables', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True)),
    )
    op.create_index('ix_engagements_workspace_id', 'engagements', ['workspace_id'])
    op.create_index('ix_engagements_status', 'engagements', ['status'])
    
    # Scheduled scans
    op.create_table(
        'scheduled_scans',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('workspace_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text()),
        sa.Column('scan_type', sa.String(50), nullable=False),
        sa.Column('target', sa.String(500), nullable=False),
        sa.Column('asset_ids', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('intensity', sa.String(50), nullable=False, server_default='normal'),
        sa.Column('is_authenticated', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('auth_config', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('login_recording_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('login_recordings.id'), nullable=True),
        sa.Column('frequency', sa.Enum('daily', 'weekly', 'monthly', 'custom', name='schedule_frequency'), nullable=False, server_default='weekly'),
        sa.Column('cron_expression', sa.String(100)),
        sa.Column('timezone', sa.String(50), nullable=False, server_default='UTC'),
        sa.Column('start_time', sa.String(5)),
        sa.Column('end_time', sa.String(5)),
        sa.Column('max_duration_minutes', sa.Integer(), nullable=False, server_default='120'),
        sa.Column('status', sa.Enum('active', 'paused', 'disabled', 'error', name='scheduled_scan_status'), nullable=False, server_default='active'),
        sa.Column('last_run', sa.DateTime(timezone=True)),
        sa.Column('next_run', sa.DateTime(timezone=True)),
        sa.Column('last_run_status', sa.String(50)),
        sa.Column('last_run_error', sa.Text()),
        sa.Column('consecutive_failures', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('notify_on_success', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('notify_on_failure', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('notify_on_findings', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('notification_integration_ids', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('max_retries', sa.Integer(), nullable=False, server_default='2'),
        sa.Column('retry_delay_minutes', sa.Integer(), nullable=False, server_default='30'),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_scheduled_scans_workspace_id', 'scheduled_scans', ['workspace_id'])
    op.create_index('ix_scheduled_scans_status', 'scheduled_scans', ['status'])
    op.create_index('ix_scheduled_scans_next_run', 'scheduled_scans', ['next_run', 'status'])
    op.create_index('ix_scheduled_scans_workspace_status', 'scheduled_scans', ['workspace_id', 'status'])
    
    # Attack surface nodes
    op.create_table(
        'attack_surface_nodes',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('workspace_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=True),
        sa.Column('type', sa.Enum('asset', 'subdomain', 'ip', 'port', 'service', 'technology', 'vulnerability', 'endpoint', 'certificate', 'dns_record', name='node_type'), nullable=False),
        sa.Column('label', sa.String(500), nullable=False),
        sa.Column('value', sa.String(500), nullable=False),
        sa.Column('properties', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('risk_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('criticality', sa.String(50)),
        sa.Column('discovered_by', sa.String(100)),
        sa.Column('discovered_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True)),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_hidden', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_attack_surface_nodes_workspace_id', 'attack_surface_nodes', ['workspace_id'])
    op.create_index('ix_attack_surface_nodes_type', 'attack_surface_nodes', ['type'])
    op.create_index('ix_attack_surface_nodes_value', 'attack_surface_nodes', ['value'])
    op.create_index('ix_attack_surface_nodes_workspace_type', 'attack_surface_nodes', ['workspace_id', 'type'])
    op.create_index('ix_attack_surface_nodes_discovered_at', 'attack_surface_nodes', ['discovered_at'])
    
    # Attack surface edges
    op.create_table(
        'attack_surface_edges',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('workspace_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('source_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('attack_surface_nodes.id', ondelete='CASCADE'), nullable=False),
        sa.Column('target_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('attack_surface_nodes.id', ondelete='CASCADE'), nullable=False),
        sa.Column('type', sa.Enum('resolves_to', 'hosts', 'runs_on', 'uses_tech', 'has_vuln', 'exposes', 'certifies', 'dns_points', name='edge_type'), nullable=False),
        sa.Column('label', sa.String(255)),
        sa.Column('properties', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('weight', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('discovered_by', sa.String(100)),
        sa.Column('discovered_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_attack_surface_edges_workspace_id', 'attack_surface_edges', ['workspace_id'])
    op.create_index('ix_attack_surface_edges_source_target', 'attack_surface_edges', ['source_id', 'target_id'], unique=True)
    op.create_index('ix_attack_surface_edges_type', 'attack_surface_edges', ['type'])
    
    # Attack surface snapshots
    op.create_table(
        'attack_surface_snapshots',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('workspace_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(255)),
        sa.Column('description', sa.Text()),
        sa.Column('node_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('edge_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('asset_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('vulnerability_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('nodes_added', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('nodes_removed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('edges_added', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('edges_removed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('risk_score_delta', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('graph_data', postgresql.JSONB()),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
    )
    op.create_index('ix_attack_surface_snapshots_workspace_id', 'attack_surface_snapshots', ['workspace_id'])
    op.create_index('ix_attack_surface_snapshots_created_at', 'attack_surface_snapshots', ['created_at'])
    
    # User sessions
    op.create_table(
        'user_sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('session_token', sa.String(255), nullable=False, unique=True),
        sa.Column('ip_address', sa.String(45)),
        sa.Column('user_agent', sa.Text()),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_user_sessions_user_id', 'user_sessions', ['user_id'])
    op.create_index('ix_user_sessions_session_token', 'user_sessions', ['session_token'])
    op.create_index('ix_user_sessions_expires_at', 'user_sessions', ['expires_at'])
    
    # API keys
    op.create_table(
        'api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('key_hash', sa.String(255), nullable=False, unique=True),
        sa.Column('key_prefix', sa.String(20), nullable=False),
        sa.Column('scopes', sa.Text()),
        sa.Column('last_used', sa.DateTime(timezone=True)),
        sa.Column('expires_at', sa.DateTime(timezone=True)),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True)),
    )
    op.create_index('ix_api_keys_user_id', 'api_keys', ['user_id'])
    op.create_index('ix_api_keys_key_hash', 'api_keys', ['key_hash'])
    op.create_index('ix_api_keys_key_prefix', 'api_keys', ['key_prefix'])
    
    # Password reset tokens
    op.create_table(
        'password_reset_tokens',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('token_hash', sa.String(255), nullable=False, unique=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True)),
        sa.Column('ip_address', sa.String(45)),
        sa.Column('user_agent', sa.Text()),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_password_reset_tokens_token_hash', 'password_reset_tokens', ['token_hash'])
    op.create_index('ix_password_reset_tokens_user_id', 'password_reset_tokens', ['user_id'])
    op.create_index('ix_password_reset_tokens_expires_at', 'password_reset_tokens', ['expires_at'])
    
    # Email verification tokens
    op.create_table(
        'email_verification_tokens',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('token_hash', sa.String(255), nullable=False, unique=True),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('verified_at', sa.DateTime(timezone=True)),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_email_verification_tokens_token_hash', 'email_verification_tokens', ['token_hash'])
    op.create_index('ix_email_verification_tokens_user_id', 'email_verification_tokens', ['user_id'])
    
    # Invite tokens
    op.create_table(
        'invite_tokens',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('workspace_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('role', sa.String(50), nullable=False, server_default='member'),
        sa.Column('token_hash', sa.String(255), nullable=False, unique=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('accepted_at', sa.DateTime(timezone=True)),
        sa.Column('accepted_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('invited_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_invite_tokens_token_hash', 'invite_tokens', ['token_hash'])
    op.create_index('ix_invite_tokens_workspace_id', 'invite_tokens', ['workspace_id'])
    op.create_index('ix_invite_tokens_email', 'invite_tokens', ['email'])
    op.create_index('ix_invite_tokens_expires_at', 'invite_tokens', ['expires_at'])

def downgrade() -> None:
    # Drop all tables in reverse order
    tables = [
        'invite_tokens', 'email_verification_tokens', 'password_reset_tokens',
        'api_keys', 'user_sessions',
        'attack_surface_snapshots', 'attack_surface_edges', 'attack_surface_nodes',
        'scheduled_scans', 'engagements', 'reports', 'report_templates',
        'integration_notifications', 'integrations',
        'finding_attachments', 'finding_comments', 'findings',
        'login_recordings', 'scan_logs', 'scans',
        'asset_group_members', 'asset_groups', 'assets',
        'workspace_members', 'workspaces',
        'users'
    ]
    for table in tables:
        op.drop_table(table)
    
    # Drop enums
    enums = [
        'user_role', 'plan_type', 'asset_type', 'asset_risk_level',
        'scan_type', 'scan_status', 'scan_intensity',
        'finding_severity', 'finding_status',
        'integration_type', 'report_template_type', 'report_format', 'report_status',
        'schedule_frequency', 'scheduled_scan_status',
        'node_type', 'edge_type'
    ]
    for enum in enums:
        op.execute(f'DROP TYPE IF EXISTS {enum}')