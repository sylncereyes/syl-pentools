"""
syl-pentools API — Starlette + PostgreSQL + Celery + Socket.IO.

The API server owns the database and the realtime socket layer. Scans are
executed by Celery workers (services.scanner_tasks); this process polls the
database for changes and broadcasts them to connected browsers, which keeps
worker and API processes decoupled.
"""
from __future__ import annotations

import asyncio
import contextlib
import sys
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
import os

import socketio
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from starlette.datastructures import Headers
from starlette.routing import Route

from sqlalchemy import func, select

import contextvars
import logging

from core.config import settings
from core.database import AsyncSessionLocal, close_db, init_db
from core.auth import create_token_pair, verify_password, decode_token, verify_token_type
from core.rate_limiter import RateLimitMiddleware
from models.asset import Asset, AssetRiskLevel, AssetType
from models.finding import Finding, FindingStatus, FindingSeverity, FindingComment, FindingAttachment
from models.scan import Scan, ScanLog, ScanStatus, ScanType, ScanIntensity, ScanTemplate
from models.user import User, UserRole, APIKey
from models.workspace import Workspace, WorkspaceMember
from models.schedule import ScheduledScan, ScheduleFrequency, ScheduledScanStatus
from models.robot import Robot, RobotRun, RobotRunStatus
from models.report import Report, ReportTemplate, ReportFormat, ReportStatus, ReportTemplateType
from models.auth_token import PasswordResetToken, EmailVerificationToken, InviteToken
from services.auth_service import AuthService
from services.scanner_tasks import cancel_scan, retry_failed_scan, run_scan_task
from services.scheduler_service import SchedulerService
from services.report_service import generate_report
from services.integration_service import dispatch_event
from services.diff_service import DiffService, run_diff_check
from services.surface_service import AttackSurfaceService
from services.robot_tasks import run_robot_task
from services.email_service import email_service
from services.billing_service import BillingService
from services.mfa_service import MFAService, SSOService



# Observability
import logging
import time
from contextlib import asynccontextmanager
from typing import Optional
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

# Prometheus metrics

# Authenticated scanning
from services.authenticated_scanner import AuthenticatedScanner, AuthenticationConfig

HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"]
)
HTTP_REQUEST_DURATION = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"]
)
ACTIVE_SCANS = Gauge(
    "active_scans",
    "Number of currently running scans"
)
TOTAL_FINDINGS = Gauge(
    "total_findings",
    "Total findings by severity",
    ["severity"]
)
DB_CONNECTIONS = Gauge(
    "db_connections_active",
    "Active database connections"
)
CELERY_TASKS = Counter(
    "celery_tasks_total",
    "Total Celery tasks",
    ["task_name", "status"]
)

logger = logging.getLogger(__name__)

_current_workspace = contextvars.ContextVar("current_workspace", default=None)


# ---------------------------------------------------------------------------
# Realtime
# ---------------------------------------------------------------------------

redis_manager = socketio.AsyncRedisManager(settings.REDIS_URL)
sio = socketio.AsyncServer(
    async_mode="asgi",
    client_manager=redis_manager,
    cors_allowed_origins="*",
)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def _enum(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


def _event(event_type: str, workspace_id: Any, data: dict) -> dict:
    return {
        "event_type": event_type,
        "workspace_id": str(workspace_id),
        "data": data,
        "timestamp": datetime.utcnow().isoformat(),
    }


# ---------------------------------------------------------------------------
# Serializers
# ---------------------------------------------------------------------------

def serialize_workspace(ws: Workspace) -> dict:
    return {
        "id": str(ws.id),
        "name": ws.name,
        "slug": ws.slug,
        "plan": _enum(ws.plan),
        "asset_limit": ws.asset_limit,
        "scan_limit": ws.concurrent_scan_limit,
        "scheduled_scan_limit": ws.scheduled_scan_limit,
        "settings": ws.settings or {},
    }


def serialize_asset(asset: Asset) -> dict:
    return {
        "id": str(asset.id),
        "target": asset.target,
        "type": _enum(asset.type),
        "description": asset.description,
        "risk_level": _enum(asset.risk_level),
        "risk_score": asset.risk_score,
        "scans": asset.total_scans,
        "vulnerabilities": asset.vulnerabilities_count,
        "created_at": _iso(asset.created_at),
        "last_scanned_at": _iso(asset.last_scanned_at),
    }


def serialize_scan(scan: Scan) -> dict:
    return {
        "id": str(scan.id),
        "scan_id": str(scan.id),
        "name": scan.name,
        "type": _enum(scan.type),
        "target": scan.target,
        "status": _enum(scan.status),
        "progress": round(scan.progress or 0, 1),
        "intensity": _enum(scan.intensity),
        "is_authenticated": scan.is_authenticated,
        "current_step": scan.current_step,
        "findings_count": scan.findings_count or 0,
        "critical_count": scan.critical_count or 0,
        "high_count": scan.high_count or 0,
        "medium_count": scan.medium_count or 0,
        "low_count": scan.low_count or 0,
        "info_count": scan.info_count or 0,
        "error_message": scan.error_message,
        "asset_id": str(scan.asset_id) if scan.asset_id else None,
        "started_at": _iso(scan.started_at) or _iso(scan.queued_at) or _iso(scan.created_at),
        "completed_at": _iso(scan.completed_at),
        "duration_seconds": scan.duration_seconds,
        "created_at": _iso(scan.created_at),
    }



def serialize_finding_detail(finding: Finding) -> dict:
    base = serialize_finding(finding)
    
    # Helper to safely load relationship
    def safe_comments():
        try:
            from sqlalchemy import inspect
            if inspect(finding).attrs.comments.loaded:
                return [
                    {
                        "id": str(c.id),
                        "user_id": str(c.user_id),
                        "content": c.content,
                        "is_internal": c.is_internal,
                        "created_at": _iso(c.created_at),
                        "updated_at": _iso(c.updated_at),
                    }
                    for c in (finding.comments or [])
                ]
        except Exception:
            pass
        return []
    
    def safe_attachments():
        try:
            from sqlalchemy import inspect
            if inspect(finding).attrs.attachments.loaded:
                return [
                    {
                        "id": str(a.id),
                        "filename": a.filename,
                        "file_size": a.file_size,
                        "mime_type": a.mime_type,
                        "uploaded_by": str(a.uploaded_by) if a.uploaded_by else None,
                        "uploaded_at": _iso(a.uploaded_at),
                    }
                    for a in (finding.attachments or [])
                ]
        except Exception:
            pass
        return []
    
    base.update({
        "description": finding.description,
        "cvss_vector": finding.cvss_vector,
        "owasp_category": finding.owasp_category,
        "path": finding.path,
        "evidence": finding.evidence or {},
        "reproduction_steps": finding.reproduction_steps,
        "proof_of_concept": finding.proof_of_concept,
        "remediation": finding.remediation,
        "remediation_complexity": finding.remediation_complexity,
        "references": finding.references or [],
        "tags": finding.tags or [],
        "fingerprint": finding.fingerprint,
        "is_duplicate": finding.is_duplicate,
        "duplicate_of": str(finding.duplicate_of) if finding.duplicate_of else None,
        "assigned_to": str(finding.assigned_to) if finding.assigned_to else None,
        "verified_by": str(finding.verified_by) if finding.verified_by else None,
        "verified_at": _iso(finding.verified_at),
        "fixed_at": _iso(finding.fixed_at),
        "source_finding_id": finding.source_finding_id,
        "source_rule_id": finding.source_rule_id,
        "compliance_mappings": finding.compliance_mappings or {},
        "updated_at": _iso(finding.updated_at),
        "closed_at": _iso(finding.closed_at),
        "comments": safe_comments(),
        "attachments": safe_attachments(),
    })
    return base


def serialize_finding(finding: Finding) -> dict:
    return {
        "id": str(finding.id),
        "title": finding.title,
        "description": finding.description,
        "severity": _enum(finding.severity),
        "status": _enum(finding.status),
        "target_url": finding.target_url,
        "parameter": finding.parameter,
        "method": finding.method,
        "cwe_id": finding.cwe_id,
        "cve_ids": finding.cve_ids or [],
        "cvss_score": finding.cvss_score,
        "source_scanner": finding.source_scanner,
        "scan_id": str(finding.scan_id) if finding.scan_id else None,
        "asset_id": str(finding.asset_id),
        "created_at": _iso(finding.created_at),
    }


def serialize_scheduled_scan(s: ScheduledScan) -> dict:
    return {
        "id": str(s.id),
        "name": s.name,
        "description": s.description,
        "scan_type": s.scan_type,
        "target": s.target,
        "intensity": s.intensity,
        "frequency": _enum(s.frequency),
        "cron_expression": s.cron_expression,
        "timezone": s.timezone,
        "start_time": s.start_time,
        "end_time": s.end_time,
        "max_duration_minutes": s.max_duration_minutes,
        "status": _enum(s.status),
        "last_run": _iso(s.last_run),
        "next_run": _iso(s.next_run),
        "last_run_status": s.last_run_status,
        "last_run_error": s.last_run_error,
        "consecutive_failures": s.consecutive_failures,
        "notify_on_success": s.notify_on_success,
        "notify_on_failure": s.notify_on_failure,
        "notify_on_findings": s.notify_on_findings,
        "max_retries": s.max_retries,
        "retry_delay_minutes": s.retry_delay_minutes,
        "created_at": _iso(s.created_at),
        "updated_at": _iso(s.updated_at),
    }


def serialize_scan_template(t: ScanTemplate) -> dict:
    return {
        "id": str(t.id),
        "name": t.name,
        "description": t.description,
        "category": t.category,
        "scan_type": t.scan_type,
        "intensity": t.intensity,
        "scanner_config": t.scanner_config,
        "is_authenticated": t.is_authenticated,
        "auth_config": t.auth_config,
        "is_system": t.is_system,
        "is_public": t.is_public,
        "usage_count": t.usage_count,
        "created_at": _iso(t.created_at),
        "updated_at": _iso(t.updated_at),
    }


def serialize_report(r: Report) -> dict:
    return {
        "id": str(r.id),
        "title": r.title,
        "description": r.description,
        "format": _enum(r.format),
        "status": _enum(r.status),
        "file_path": r.file_path,
        "file_size": r.file_size,
        "page_count": r.page_count,
        "generation_error": r.generation_error,
        "generation_duration_seconds": r.generation_duration_seconds,
        "created_at": _iso(r.created_at),
        "updated_at": _iso(r.updated_at),
        "completed_at": _iso(r.completed_at),
        "expires_at": _iso(r.expires_at),
    }


def serialize_report_template(t: ReportTemplate) -> dict:
    return {
        "id": str(t.id),
        "name": t.name,
        "description": t.description,
        "type": _enum(t.type),
        "compliance_frameworks": t.compliance_frameworks or [],
        "default_formats": t.default_formats or [],
        "is_default": t.is_default,
        "is_system": t.is_system,
        "created_at": _iso(t.created_at),
        "updated_at": _iso(t.updated_at),
    }


def serialize_log(log: ScanLog) -> dict:
    return {
        "id": str(log.id),
        "level": log.level,
        "message": log.message,
        "step": log.step,
        "progress": log.progress,
        "metadata": log.meta or {},
        "created_at": _iso(log.created_at),
    }


# ---------------------------------------------------------------------------
# Integration catalog (configuration stored in workspace.settings)
# ---------------------------------------------------------------------------

INTEGRATION_CATALOG = [
    {"id": "slack", "name": "Slack", "type": "slack", "description": "Send scan notifications to Slack channels."},
    {"id": "teams", "name": "Microsoft Teams", "type": "teams", "description": "Post findings to Teams."},
    {"id": "jira", "name": "Jira", "type": "jira", "description": "Create Jira issues from findings."},
    {"id": "webhook", "name": "Webhook", "type": "webhook", "description": "Send JSON events to any endpoint."},
    {"id": "github", "name": "GitHub", "type": "github", "description": "Open security issues in repositories."},
    {"id": "discord", "name": "Discord", "type": "discord", "description": "Notify a Discord channel."},
    {"id": "aws", "name": "AWS Security Hub", "type": "aws", "description": "Import cloud findings from AWS."},
    {"id": "vanta", "name": "Vanta", "type": "vanta", "description": "Sync evidence for compliance."},
    {"id": "burp", "name": "Burp Suite", "type": "burp", "description": "Import findings from Burp Suite projects."},
    {"id": "nucleus", "name": "Nucleus", "type": "nucleus", "description": "Sync findings with Nucleus vulnerability management."},
    {"id": "mcp", "name": "Model Context Protocol", "type": "mcp", "description": "Integrate with MCP-compatible tools and AI assistants."},
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def default_workspace(db) -> Workspace:
    ws = (await db.execute(select(Workspace).order_by(Workspace.created_at).limit(1))).scalars().first()
    if ws:
        return ws
    ws = Workspace(name="My Workspace", slug="my-workspace")
    db.add(ws)
    await db.flush()

    user = (await db.execute(select(User).limit(1))).scalars().first()
    if not user:
        user = User(
            email="admin@local",
            hashed_password="!",
            full_name="Workspace Owner",
            is_active=True,
            is_verified=True,
        )
        db.add(user)
        await db.flush()
    db.add(WorkspaceMember(workspace_id=ws.id, user_id=user.id, role="owner"))
    await db.commit()
    await db.refresh(ws)
    return ws


async def resolve_workspace(db, workspace_id: Optional[str] = None) -> Workspace:
    if workspace_id:
        try:
            ws = await db.get(Workspace, uuid.UUID(str(workspace_id)))
            if ws:
                return ws
        except (ValueError, TypeError):
            pass
    active = _current_workspace.get()
    if active:
        ws = await db.get(Workspace, active)
        if ws:
            return ws
    return await default_workspace(db)


def _normalize_asset_type(value: str) -> AssetType:
    value = (value or "hostname").lower()
    aliases = {
        "ip": AssetType.IP_ADDRESS,
        "ip_address": AssetType.IP_ADDRESS,
        "ipaddress": AssetType.IP_ADDRESS,
        "hostname": AssetType.HOSTNAME,
        "cidr": AssetType.CIDR,
        "url": AssetType.URL,
        "website": AssetType.URL,
    }
    return aliases.get(value, AssetType.HOSTNAME)


def _normalize_scan_type(value: str) -> Optional[ScanType]:
    try:
        return ScanType(str(value).lower())
    except ValueError:
        return None


def _scan_options(scan: Scan) -> dict:
    return {
        "target": scan.target,
        "scan_type": _enum(scan.type),
        "intensity": _enum(scan.intensity),
        "is_authenticated": scan.is_authenticated,
        "auth_config": scan.auth_config or {},
        "options": scan.scanner_config or {},
    }


async def read_json(request) -> dict:
    try:
        data = await request.json()
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def error(message: str, status: int = 400, code: str = None, field: str = None) -> JSONResponse:
    """Return a standardized error response."""
    error_obj = {"detail": message}
    if code:
        error_obj["code"] = code
    if field:
        error_obj["field"] = field
    return JSONResponse(error_obj, status_code=status)


# ---------------------------------------------------------------------------
# HTTP endpoints
# ---------------------------------------------------------------------------

async def health(request):
    return JSONResponse({"status": "ok", "timestamp": datetime.utcnow().isoformat()})


async def openapi_schema(request):
    """Generate OpenAPI schema dynamically."""
    schema = {
        "openapi": "3.0.3",
        "info": {
            "title": "syl-pentools API",
            "version": "1.0.0",
            "description": "API for syl-pentools - Vulnerability Management Platform",
        },
        "servers": [
            {"url": "http://localhost:8000", "description": "Development server"}
        ],
        "components": {
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                },
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key"
                }
            }
        },
        "security": [
            {"BearerAuth": []},
            {"ApiKeyAuth": []}
        ],
        "paths": {}
    }
    
    # Build paths from routes
    for route in routes:
        if hasattr(route, 'path') and hasattr(route, 'methods'):
            path = route.path
            methods = [m.lower() for m in route.methods] if route.methods else []
            if path not in schema["paths"]:
                schema["paths"][path] = {}
            for method in methods:
                schema["paths"][path][method] = {
                    "summary": route.path,
                    "responses": {"200": {"description": "Success"}}
                }
    
    return JSONResponse(schema)


async def get_current_user_id(request) -> Optional[uuid.UUID]:
    user = await get_current_user(request)
    return user.id if user else None

async def get_current_user(request) -> Optional[User]:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ", 1)[1]
    payload = verify_token_type(token, "access")
    if not payload:
        return None
    user_id = payload.get("sub")
    if not user_id:
        return None
    async with AsyncSessionLocal() as db:
        return await db.get(User, uuid.UUID(user_id))


async def require_auth(request) -> User:
    user = await get_current_user(request)
    if not user:
        raise Exception("Authentication required")
    return user


async def register(request):
    data = await read_json(request)
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    full_name = (data.get("full_name") or "").strip() or None
    if not email or not password:
        return error("Email and password are required", 400)
    if len(password) < 8:
        return error("Password must be at least 8 characters", 400)
    async with AsyncSessionLocal() as db:
        auth = AuthService(db)
        existing = await auth.get_user_by_email(email)
        if existing:
            return error("Email already registered", 400)
        user = await auth.create_user(email=email, password=password, full_name=full_name)
        label = (full_name or email.split("@")[0]).strip() or "My"
        slug_base = "".join(ch if ch.isalnum() else "-" for ch in email.split("@")[0].lower()).strip("-") or "workspace"
        slug = f"{slug_base}-{uuid.uuid4().hex[:6]}"
        workspace = await auth.create_workspace(f"{label}'s Workspace", slug, user.id)
        await db.commit()
        await db.refresh(user)
        tokens = create_token_pair(str(user.id), user.email, user.role.value)
        return JSONResponse({**tokens, "user": {"id": str(user.id), "email": user.email, "full_name": user.full_name, "role": user.role.value}})


async def login(request):
    data = await read_json(request)
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or not password:
        return error("Email and password are required", 400)
    async with AsyncSessionLocal() as db:
        auth = AuthService(db)
        user = await auth.authenticate_user(email, password)
        if not user:
            return error("Invalid credentials", 401)
        tokens = create_token_pair(str(user.id), user.email, user.role.value)
        return JSONResponse({**tokens, "user": {"id": str(user.id), "email": user.email, "full_name": user.full_name, "role": user.role.value}})


async def refresh(request):
    data = await read_json(request)
    refresh_token = data.get("refresh_token") or ""
    if not refresh_token:
        return error("Refresh token required", 400)
    payload = verify_token_type(refresh_token, "refresh")
    if not payload:
        return error("Invalid refresh token", 401)
    user_id = payload.get("sub")
    async with AsyncSessionLocal() as db:
        auth = AuthService(db)
        user = await auth.get_user_by_id(uuid.UUID(user_id))
        if not user or not user.is_active:
            return error("User not found or inactive", 401)
        tokens = create_token_pair(str(user.id), user.email, user.role.value)
        return JSONResponse(tokens)


async def logout(request):
    user = await get_current_user(request)
    if user:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
            async with AsyncSessionLocal() as db:
                auth = AuthService(db)
                await auth.revoke_session(token)
    return JSONResponse({"ok": True})


async def request_password_reset(request):
    data = await read_json(request)
    email = (data.get("email") or "").strip().lower()
    if not email:
        return error("Email is required", 400)
    async with AsyncSessionLocal() as db:
        auth = AuthService(db)
        user = await auth.get_user_by_email(email)
        if not user:
            return JSONResponse({"ok": True})
        ip = request.client.host if request.client else None
        ua = request.headers.get("user-agent")
        reset_token = await auth.create_password_reset_token(user.id, email, ip, ua)
        await db.commit()
        if settings.APP_URL:
            reset_url = f"{settings.APP_URL}/reset-password?token={reset_token.token_hash[:32]}"
            email_service.send_email(
                to=[email],
                subject="Reset your Pentest Tools password",
                body_html=f"""
                <html><body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #2c3e50;">Password Reset Request</h2>
                <p>You requested a password reset for your Pentest Tools account.</p>
                <p style="text-align: center; margin: 30px 0;">
                <a href="{reset_url}" style="background-color: #3498db; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
                    Reset Password
                </a>
                </p>
                <p>Or copy this link: <a href="{reset_url}">{reset_url}</a></p>
                <p>This link expires in 1 hour.</p>
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
                <p style="font-size: 12px; color: #888;">If you didn't request this, you can safely ignore this email.</p>
                </div></body></html>
                """,
                body_text=f"Reset your password: {reset_url}\nThis link expires in 1 hour.",
            )
    return JSONResponse({"ok": True})


async def confirm_password_reset(request):
    data = await read_json(request)
    token = data.get("token") or ""
    new_password = data.get("password") or ""
    if not token or not new_password:
        return error("Token and new password are required", 400)
    if len(new_password) < 8:
        return error("Password must be at least 8 characters", 400)
    async with AsyncSessionLocal() as db:
        auth = AuthService(db)
        reset_token = await auth.validate_password_reset_token(token)
        if not reset_token:
            return error("Invalid or expired token", 400)
        success = await auth.use_password_reset_token(reset_token, new_password)
        if not success:
            return error("Failed to reset password", 500)
        await auth.revoke_all_sessions(reset_token.user_id)
        await db.commit()
    return JSONResponse({"ok": True})


async def resend_email_verification(request):
    user = await get_current_user(request)
    if not user:
        return error("Not authenticated", 401)
    if user.is_verified:
        return error("Email already verified", 400)
    async with AsyncSessionLocal() as db:
        auth = AuthService(db)
        verification_token = await auth.create_email_verification_token(user.id, user.email)
        await db.commit()
        if settings.APP_URL:
            verify_url = f"{settings.APP_URL}/verify-email?token={verification_token.token_hash[:32]}"
            email_service.send_email(
                to=[user.email],
                subject="Verify your Pentest Tools email",
                body_html=f"""
                <html><body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #2c3e50;">Verify Your Email</h2>
                <p>Click the button below to verify your email address:</p>
                <p style="text-align: center; margin: 30px 0;">
                <a href="{verify_url}" style="background-color: #27ae60; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
                    Verify Email
                </a>
                </p>
                <p>Or copy this link: <a href="{verify_url}">{verify_url}</a></p>
                <p>This link expires in 24 hours.</p>
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
                <p style="font-size: 12px; color: #888;">If you didn't create this account, you can safely ignore this email.</p>
                </div></body></html>
                """,
                body_text=f"Verify your email: {verify_url}\nThis link expires in 24 hours.",
            )
    return JSONResponse({"ok": True})


async def verify_email(request):
    token = request.query_params.get("token") or ""
    if not token:
        return error("Token is required", 400)
    async with AsyncSessionLocal() as db:
        auth = AuthService(db)
        verification_token = await auth.verify_email_token(token)
        if not verification_token:
            return error("Invalid or expired token", 400)
        success = await auth.confirm_email(verification_token)
        if not success:
            return error("Failed to verify email", 500)
        await db.commit()
    return JSONResponse({"ok": True, "verified": True})


async def me(request):
    user = await get_current_user(request)
    if not user:
        return error("Not authenticated", 401)
    return JSONResponse({"id": str(user.id), "email": user.email, "full_name": user.full_name, "role": user.role.value, "is_active": user.is_active, "is_verified": user.is_verified, "last_login": user.last_login.isoformat() if user.last_login else None})


# Settings endpoints
async def get_user_profile(request):
    user = await get_current_user(request)
    if not user:
        return error("Not authenticated", 401)
    return JSONResponse({
        "id": str(user.id),
        "email": user.email,
        "full_name": user.full_name,
        "avatar_url": user.avatar_url,
        "bio": getattr(user, "bio", None),
        "timezone": getattr(user, "timezone", "UTC"),
        "language": getattr(user, "language", "en"),
    })


async def update_user_profile(request):
    user = await get_current_user(request)
    if not user:
        return error("Not authenticated", 401)
    data = await read_json(request)
    async with AsyncSessionLocal() as db:
        user = await db.get(User, user.id)
        if not user:
            return error("User not found", 404)
        if "full_name" in data:
            user.full_name = data["full_name"]
        if "avatar_url" in data:
            user.avatar_url = data["avatar_url"]
        if "bio" in data:
            user.bio = data["bio"]
        if "timezone" in data:
            user.timezone = data["timezone"]
        if "language" in data:
            user.language = data["language"]
        await db.commit()
        await db.refresh(user)
        return JSONResponse({
            "id": str(user.id),
            "email": user.email,
            "full_name": user.full_name,
            "avatar_url": user.avatar_url,
            "bio": getattr(user, "bio", None),
            "timezone": getattr(user, "timezone", "UTC"),
            "language": getattr(user, "language", "en"),
        })


async def get_notification_settings(request):
    user = await get_current_user(request)
    if not user:
        return error("Not authenticated", 401)
    # Default notification settings
    settings = getattr(user, "notification_settings", {})
    defaults = {
        "scan_completed": True,
        "critical_findings": True,
        "scheduled_scan_reminders": False,
        "weekly_digest": False,
        "product_updates": True,
        "in_app_scan_status": True,
        "in_app_new_findings": True,
        "in_app_team_activity": True,
    }
    for k, v in defaults.items():
        if k not in settings:
            settings[k] = v
    return JSONResponse(settings)


async def update_notification_settings(request):
    user = await get_current_user(request)
    if not user:
        return error("Not authenticated", 401)
    data = await read_json(request)
    async with AsyncSessionLocal() as db:
        user = await db.get(User, user.id)
        if not user:
            return error("User not found", 404)
        current = getattr(user, "notification_settings", {}) or {}
        current.update(data)
        user.notification_settings = current
        await db.commit()
        return JSONResponse(current)


async def get_appearance_settings(request):
    user = await get_current_user(request)
    if not user:
        return error("Not authenticated", 401)
    settings = getattr(user, "appearance_settings", {})
    defaults = {
        "theme": "system",
        "density": "standard",
        "sidebar_collapsed": False,
    }
    for k, v in defaults.items():
        if k not in settings:
            settings[k] = v
    return JSONResponse(settings)


async def update_appearance_settings(request):
    user = await get_current_user(request)
    if not user:
        return error("Not authenticated", 401)
    data = await read_json(request)
    async with AsyncSessionLocal() as db:
        user = await db.get(User, user.id)
        if not user:
            return error("User not found", 404)
        current = getattr(user, "appearance_settings", {}) or {}
        current.update(data)
        user.appearance_settings = current
        await db.commit()
        return JSONResponse(current)


async def list_sessions(request):
    user = await get_current_user(request)
    if not user:
        return error("Not authenticated", 401)
    auth_header = request.headers.get("Authorization")
    current_token = auth_header.split(" ", 1)[1] if auth_header and auth_header.startswith("Bearer ") else None
    async with AsyncSessionLocal() as db:
        auth = AuthService(db)
        from models.user import UserSession
        from datetime import datetime, timezone
        result = await db.execute(
            select(UserSession).where(
                UserSession.user_id == user.id,
                UserSession.expires_at > datetime.now(timezone.utc),
            ).order_by(UserSession.created_at.desc())
        )
        sessions = result.scalars().all()
        return JSONResponse([{
            "id": str(s.id),
            "ip_address": s.ip_address,
            "user_agent": s.user_agent,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "expires_at": s.expires_at.isoformat() if s.expires_at else None,
            "is_current": current_token and hashlib.sha256(current_token.encode()).hexdigest() == s.session_token,
        } for s in sessions])


async def revoke_session(request):
    user = await get_current_user(request)
    if not user:
        return error("Not authenticated", 401)
    session_id = request.path_params["session_id"]
    async with AsyncSessionLocal() as db:
        from models.user import UserSession
        session = await db.get(UserSession, uuid.UUID(session_id))
        if not session or session.user_id != user.id:
            return error("Session not found", 404)
        await db.delete(session)
        await db.commit()
    return JSONResponse({"ok": True})


async def revoke_all_sessions(request):
    user = await get_current_user(request)
    if not user:
        return error("Not authenticated", 401)
    data = await read_json(request)
    keep_current = data.get("keep_current", False)
    auth_header = request.headers.get("Authorization")
    current_token = auth_header.split(" ", 1)[1] if auth_header and auth_header.startswith("Bearer ") else None
    current_token_hash = hashlib.sha256(current_token.encode()).hexdigest() if current_token else None
    async with AsyncSessionLocal() as db:
        from models.user import UserSession
        from datetime import datetime, timezone
        query = select(UserSession).where(
            UserSession.user_id == user.id,
            UserSession.expires_at > datetime.now(timezone.utc),
        )
        if keep_current and current_token_hash:
            query = query.where(UserSession.session_token != current_token_hash)
        result = await db.execute(query)
        sessions = result.scalars().all()
        for s in sessions:
            await db.delete(s)
        await db.commit()
    return JSONResponse({"ok": True, "revoked": len(sessions)})


async def change_password(request):
    user = await get_current_user(request)
    if not user:
        return error("Not authenticated", 401)
    data = await read_json(request)
    current_password = data.get("current_password") or ""
    new_password = data.get("new_password") or ""
    if not current_password or not new_password:
        return error("Current password and new password are required", 400)
    if len(new_password) < 8:
        return error("Password must be at least 8 characters", 400)
    from core.auth import verify_password, hash_password
    if not verify_password(current_password, user.hashed_password):
        return error("Current password is incorrect", 400)
    user.hashed_password = hash_password(new_password)
    async with AsyncSessionLocal() as db:
        db.add(user)
        await db.commit()
    return JSONResponse({"ok": True})


async def bootstrap(request):
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, request.query_params.get("workspace_id"))
        assets = (await db.execute(
            select(Asset).where(Asset.workspace_id == ws.id, Asset.deleted_at.is_(None)).order_by(Asset.created_at.desc())
        )).scalars().all()
        scans = (await db.execute(
            select(Scan).where(Scan.workspace_id == ws.id).order_by(Scan.created_at.desc()).limit(200)
        )).scalars().all()
        findings = (await db.execute(
            select(Finding).where(Finding.workspace_id == ws.id).order_by(Finding.created_at.desc()).limit(500)
        )).scalars().all()

        cfg = (ws.settings or {}).get("integrations", {})
        integrations = [
            {
                **item,
                "configured": bool(cfg.get(item["id"], {}).get("configured", False)),
                "enabled": bool(cfg.get(item["id"], {}).get("enabled", False)),
            }
            for item in INTEGRATION_CATALOG
        ]

        return JSONResponse({
            "workspace": serialize_workspace(ws),
            "assets": [serialize_asset(a) for a in assets],
            "scans": [serialize_scan(s) for s in scans],
            "findings": [serialize_finding(f) for f in findings],
            "integrations": integrations,
        })


async def get_workspace(request):
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, request.query_params.get("workspace_id"))
        return JSONResponse(serialize_workspace(ws))


async def get_asset(request):
    asset_id = request.path_params["asset_id"]
    try:
        asset_uuid = uuid.UUID(asset_id)
    except (ValueError, TypeError):
        return error("invalid asset id")

    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, request.query_params.get("workspace_id"))
        asset = await db.get(Asset, asset_uuid)
        if not asset or asset.workspace_id != ws.id:
            return error("Asset not found", 404)
        return JSONResponse(serialize_asset(asset))


async def list_assets(request):
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, request.query_params.get("workspace_id"))
        rows = (await db.execute(
            select(Asset).where(Asset.workspace_id == ws.id, Asset.deleted_at.is_(None)).order_by(Asset.created_at.desc())
        )).scalars().all()
        return JSONResponse([serialize_asset(a) for a in rows])


import re
import ipaddress

def _validate_asset_target(target: str, asset_type: str) -> tuple[bool, str]:
    """Validate asset target based on type. Returns (is_valid, error_message)."""
    target = target.strip()
    if not target:
        return False, "target is required"
    
    if asset_type in ("hostname", "url"):
        # Basic hostname/FQDN validation
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if asset_type == "url":
            # For URLs, extract hostname part
            try:
                from urllib.parse import urlparse
                parsed = urlparse(target)
                hostname = parsed.hostname or ""
                if not hostname:
                    return False, "Invalid URL: missing hostname"
                target = hostname
            except Exception:
                return False, "Invalid URL format"
        if not re.match(hostname_pattern, target):
            return False, f"Invalid hostname: {target}"
    elif asset_type == "ip":
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return False, f"Invalid IP address: {target}"
    elif asset_type == "cidr":
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            return False, f"Invalid CIDR notation: {target}"
    else:
        return False, f"Unknown asset type: {asset_type}"
    return True, ""


async def create_asset(request):
    data = await read_json(request)
    target = (data.get("target") or "").strip()
    asset_type = data.get("type", "hostname")
    if not target:
        return error("target is required")
    
    # Validate target
    is_valid, error_msg = _validate_asset_target(target, asset_type)
    if not is_valid:
        return error(error_msg)
    
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, data.get("workspace_id"))
        count = (await db.execute(
            select(func.count(Asset.id)).where(Asset.workspace_id == ws.id, Asset.deleted_at.is_(None))
        )).scalar_one()
        if count >= ws.asset_limit:
            return error("Asset limit reached")
        existing = (await db.execute(
            select(Asset).where(Asset.workspace_id == ws.id, Asset.target == target, Asset.deleted_at.is_(None))
        )).scalars().first()
        if existing:
            return JSONResponse(serialize_asset(existing), status_code=200)
        asset = Asset(
            workspace_id=ws.id,
            target=target,
            type=_normalize_asset_type(asset_type),
            description=data.get("description"),
            risk_level=AssetRiskLevel.NONE,
        )
        db.add(asset)
        await db.commit()
        await db.refresh(asset)
        payload = serialize_asset(asset)
        await sio.emit("asset_created", _event("asset_created", ws.id, payload), room=f"workspace:{ws.id}")
        return JSONResponse(payload, status_code=201)


async def delete_asset(request):
    asset_id = request.path_params["asset_id"]
    async with AsyncSessionLocal() as db:
        try:
            asset = await db.get(Asset, uuid.UUID(asset_id))
        except (ValueError, TypeError):
            return error("invalid asset id")
        if not asset:
            return error("Asset not found", 404)
        asset.deleted_at = datetime.utcnow()
        await db.commit()
        return JSONResponse({"ok": True})


async def list_scans(request):
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, request.query_params.get("workspace_id"))
        rows = (await db.execute(
            select(Scan).where(Scan.workspace_id == ws.id).order_by(Scan.created_at.desc()).limit(200)
        )).scalars().all()
        return JSONResponse([serialize_scan(s) for s in rows])


async def create_scan(request):
    data = await read_json(request)
    target = (data.get("target") or "").strip()
    if not target:
        return error("target is required")
    scan_type = _normalize_scan_type(data.get("type") or data.get("scan_type") or "")
    if not scan_type:
        return error("invalid scan type")

    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, data.get("workspace_id"))

        active = (await db.execute(
            select(func.count(Scan.id)).where(
                Scan.workspace_id == ws.id,
                Scan.status.in_([ScanStatus.PENDING, ScanStatus.QUEUED, ScanStatus.RUNNING]),
            )
        )).scalar_one()
        if active >= ws.concurrent_scan_limit:
            return error("Concurrent scan limit reached")

        asset = None
        asset_id = data.get("asset_id")
        if asset_id:
            try:
                asset = await db.get(Asset, uuid.UUID(str(asset_id)))
            except (ValueError, TypeError):
                asset = None
        if not asset:
            asset = (await db.execute(
                select(Asset).where(
                    Asset.workspace_id == ws.id,
                    Asset.target == target,
                    Asset.deleted_at.is_(None),
                )
            )).scalars().first()
        if not asset:
            asset = Asset(
                workspace_id=ws.id,
                target=target,
                type=_normalize_asset_type(data.get("asset_type", "hostname")),
            )
            db.add(asset)
            await db.flush()

        intensity = ScanIntensity.NORMAL
        if data.get("intensity") in {i.value for i in ScanIntensity}:
            intensity = ScanIntensity(data["intensity"])

        scan = Scan(
            workspace_id=ws.id,
            asset_id=asset.id,
            name=data.get("name") or f"{scan_type.value} scan — {target}",
            type=scan_type,
            target=target,
            intensity=intensity,
            status=ScanStatus.PENDING,
            progress=0.0,
            scanner_config=data.get("options") or data.get("scanner_config") or {},
            is_authenticated=bool(data.get("is_authenticated")),
            auth_config=data.get("auth_config") or {},
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        dispatch_error = None
        try:
            async_result = run_scan_task.apply_async(
                args=[str(scan.id), _scan_options(scan)],
                queue="scanners",
            )
            scan.status = ScanStatus.QUEUED
            scan.celery_task_id = async_result.id
            await db.commit()
            await db.refresh(scan)
        except Exception as exc:  # broker/worker unavailable
            dispatch_error = str(exc)
            scan.status = ScanStatus.FAILED
            scan.error_message = f"Could not queue scan worker: {exc}"
            scan.completed_at = datetime.utcnow()
            await db.commit()
            await db.refresh(scan)

        payload = serialize_scan(scan)
        await sio.emit("scan_started", _event("scan_started", ws.id, payload), room=f"workspace:{ws.id}")
        if dispatch_error:
            return JSONResponse({"detail": "Scan worker unavailable", "scan": payload}, status_code=503)
        return JSONResponse(payload, status_code=201)


async def get_scan(request):
    scan_id = request.path_params["scan_id"]
    async with AsyncSessionLocal() as db:
        try:
            scan = await db.get(Scan, uuid.UUID(scan_id))
        except (ValueError, TypeError):
            return error("invalid scan id")
        if not scan:
            return error("Scan not found", 404)
        logs = (await db.execute(
            select(ScanLog).where(ScanLog.scan_id == scan.id).order_by(ScanLog.created_at)
        )).scalars().all()
        findings = (await db.execute(
            select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.created_at)
        )).scalars().all()
        payload = serialize_scan(scan)
        payload["logs"] = [serialize_log(l) for l in logs]
        payload["findings"] = [serialize_finding(f) for f in findings]
        return JSONResponse(payload)


async def delete_scan(request):
    scan_id = request.path_params["scan_id"]
    async with AsyncSessionLocal() as db:
        try:
            scan = await db.get(Scan, uuid.UUID(scan_id))
        except (ValueError, TypeError):
            return error("invalid scan id")
        if not scan:
            return error("Scan not found", 404)
        if scan.status in (ScanStatus.RUNNING, ScanStatus.QUEUED, ScanStatus.PENDING):
            if scan.celery_task_id:
                with contextlib.suppress(Exception):
                    cancel_scan.apply_async(args=[str(scan.id)], queue="scanners")
            scan.status = ScanStatus.CANCELLED
            scan.completed_at = datetime.utcnow()
            await db.commit()
        return JSONResponse({"ok": True, "status": _enum(scan.status)})


async def retry_scan(request):
    scan_id = request.path_params["scan_id"]
    async with AsyncSessionLocal() as db:
        try:
            scan = await db.get(Scan, uuid.UUID(scan_id))
        except (ValueError, TypeError):
            return error("invalid scan id")
        if not scan:
            return error("Scan not found", 404)
        if scan.status not in (ScanStatus.FAILED, ScanStatus.CANCELLED):
            return error("Only failed or cancelled scans can be retried")
        if (scan.retry_count or 0) >= (scan.max_retries or 2):
            return error("Max retries exceeded")
        scan.retry_count = (scan.retry_count or 0) + 1
        scan.status = ScanStatus.PENDING
        scan.progress = 0.0
        scan.error_message = None
        scan.completed_at = None
        await db.commit()
        await db.refresh(scan)
        try:
            async_result = run_scan_task.apply_async(
                args=[str(scan.id), _scan_options(scan)],
                queue="scanners",
            )
            scan.status = ScanStatus.QUEUED
            scan.celery_task_id = async_result.id
            await db.commit()
            await db.refresh(scan)
        except Exception as exc:
            scan.status = ScanStatus.FAILED
            scan.error_message = f"Could not queue scan worker: {exc}"
            await db.commit()
            await db.refresh(scan)
            return JSONResponse({"detail": "Scan worker unavailable", "scan": serialize_scan(scan)}, status_code=503)
        return JSONResponse(serialize_scan(scan))


async def scan_findings(request):
    scan_id = request.path_params["scan_id"]
    async with AsyncSessionLocal() as db:
        try:
            scan_uuid = uuid.UUID(scan_id)
        except (ValueError, TypeError):
            return error("invalid scan id")
        rows = (await db.execute(
            select(Finding).where(Finding.scan_id == scan_uuid).order_by(Finding.created_at)
        )).scalars().all()
        return JSONResponse([serialize_finding(f) for f in rows])


async def scan_logs(request):
    scan_id = request.path_params["scan_id"]
    async with AsyncSessionLocal() as db:
        try:
            scan_uuid = uuid.UUID(scan_id)
        except (ValueError, TypeError):
            return error("invalid scan id")
        rows = (await db.execute(
            select(ScanLog).where(ScanLog.scan_id == scan_uuid).order_by(ScanLog.created_at)
        )).scalars().all()
        return JSONResponse([serialize_log(l) for l in rows])


async def list_findings(request):
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, request.query_params.get("workspace_id"))
        query = select(Finding).where(Finding.workspace_id == ws.id)
        if request.query_params.get("severity"):
            query = query.where(Finding.severity == request.query_params["severity"])
        if request.query_params.get("status"):
            query = query.where(Finding.status == request.query_params["status"])
        
        # Pagination
        try:
            limit = min(int(request.query_params.get("limit", 50)), 500)
        except (ValueError, TypeError):
            limit = 50
        try:
            offset = max(int(request.query_params.get("offset", 0)), 0)
        except (ValueError, TypeError):
            offset = 0
        
        rows = (await db.execute(query.order_by(Finding.created_at.desc()).limit(limit).offset(offset))).scalars().all()
        return JSONResponse([serialize_finding(f) for f in rows])


async def update_finding(request):
    finding_id = request.path_params["finding_id"]
    data = await read_json(request)
    async with AsyncSessionLocal() as db:
        try:
            finding = await db.get(Finding, uuid.UUID(finding_id))
        except (ValueError, TypeError):
            return error("invalid finding id")
        if not finding:
            return error("Finding not found", 404)
        if data.get("status"):
            try:
                finding.status = FindingStatus(str(data["status"]).lower())
            except ValueError:
                return error("invalid finding status")
            if finding.status in (FindingStatus.FIXED, FindingStatus.FALSE_POSITIVE):
                finding.closed_at = datetime.utcnow()
        await db.commit()
        await db.refresh(finding)
        payload = serialize_finding(finding)
        await sio.emit(
            "finding_updated",
            _event("finding_updated", finding.workspace_id, payload),
            room=f"workspace:{finding.workspace_id}",
        )
        return JSONResponse(payload)


async def list_integrations(request):
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, request.query_params.get("workspace_id"))
        cfg = (ws.settings or {}).get("integrations", {})
        return JSONResponse([
            {
                **item,
                "configured": bool(cfg.get(item["id"], {}).get("configured", False)),
                "enabled": bool(cfg.get(item["id"], {}).get("enabled", False)),
            }
            for item in INTEGRATION_CATALOG
        ])


async def configure_integration(request):
    int_id = request.path_params["int_id"]
    data = await read_json(request)
    if int_id not in {i["id"] for i in INTEGRATION_CATALOG}:
        return error("Unknown integration", 404)
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, data.get("workspace_id"))
        settings = dict(ws.settings or {})
        integrations = dict(settings.get("integrations", {}))
        current = dict(integrations.get(int_id, {}))
        current.update({
            "configured": True,
            "enabled": bool(data.get("enabled", True)),
            "config": data.get("config") or current.get("config") or {},
        })
        integrations[int_id] = current
        settings["integrations"] = integrations
        ws.settings = settings
        # Force SQLAlchemy to notice the JSONB mutation.
        await db.merge(ws)
        await db.commit()
        return JSONResponse({"ok": True, "enabled": current["enabled"]})


async def toggle_integration(request):
    int_id = request.path_params["int_id"]
    if int_id not in {i["id"] for i in INTEGRATION_CATALOG}:
        return error("Unknown integration", 404)
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, request.query_params.get("workspace_id"))
        settings = dict(ws.settings or {})
        integrations = dict(settings.get("integrations", {}))
        current = dict(integrations.get(int_id, {}))
        current["enabled"] = not bool(current.get("enabled", False))
        current["configured"] = True
        integrations[int_id] = current
        settings["integrations"] = integrations
        ws.settings = settings
        await db.merge(ws)
        await db.commit()
        return JSONResponse({"enabled": current["enabled"]})


# ---------------------------------------------------------------------------
# Scheduled Scans
# ---------------------------------------------------------------------------

async def list_scheduled_scans(request):
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, request.query_params.get("workspace_id"))
        rows = (await db.execute(
            select(ScheduledScan).where(ScheduledScan.workspace_id == ws.id).order_by(ScheduledScan.created_at.desc())
        )).scalars().all()
        return JSONResponse([serialize_scheduled_scan(s) for s in rows])


async def create_scheduled_scan(request):
    data = await read_json(request)
    required = ["name", "scan_type", "target", "frequency"]
    for field in required:
        if not data.get(field):
            return error(f"{field} is required", 400)

    try:
        ScanType(data["scan_type"])
    except ValueError:
        return error("invalid scan type", 400)

    try:
        ScheduleFrequency(data["frequency"])
    except ValueError:
        return error("invalid frequency", 400)

    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, data.get("workspace_id"))
        schedule = ScheduledScan(
            workspace_id=ws.id,
            name=data["name"],
            description=data.get("description"),
            scan_type=data["scan_type"],
            target=data["target"],
            asset_ids=data.get("asset_ids") or [],
            intensity=data.get("intensity", "normal"),
            is_authenticated=data.get("is_authenticated", False),
            auth_config=data.get("auth_config") or {},
            scanner_config=data.get("scanner_config") or {},
            frequency=ScheduleFrequency(data["frequency"]),
            cron_expression=data.get("cron_expression"),
            timezone=data.get("timezone", "UTC"),
            start_time=data.get("start_time", "00:00"),
            end_time=data.get("end_time"),
            max_duration_minutes=data.get("max_duration_minutes", 120),
            notify_on_success=data.get("notify_on_success", False),
            notify_on_failure=data.get("notify_on_failure", True),
            notify_on_findings=data.get("notify_on_findings", True),
            notification_integration_ids=data.get("notification_integration_ids") or [],
            max_retries=data.get("max_retries", 2),
            retry_delay_minutes=data.get("retry_delay_minutes", 30),
            status=ScheduledScanStatus.ACTIVE,
        )
        scheduler = SchedulerService(db)
        schedule.next_run = scheduler.calculate_next_run(schedule)
        db.add(schedule)
        await db.commit()
        await db.refresh(schedule)
        return JSONResponse(serialize_scheduled_scan(schedule), status_code=201)


async def get_scheduled_scan(request):
    schedule_id = request.path_params["schedule_id"]
    async with AsyncSessionLocal() as db:
        try:
            schedule = await db.get(ScheduledScan, uuid.UUID(schedule_id))
        except (ValueError, TypeError):
            return error("invalid schedule id")
        if not schedule:
            return error("Schedule not found", 404)
        return JSONResponse(serialize_scheduled_scan(schedule))


async def update_scheduled_scan(request):
    schedule_id = request.path_params["schedule_id"]
    data = await read_json(request)
    async with AsyncSessionLocal() as db:
        try:
            schedule = await db.get(ScheduledScan, uuid.UUID(schedule_id))
        except (ValueError, TypeError):
            return error("invalid schedule id")
        if not schedule:
            return error("Schedule not found", 404)

        if "scan_type" in data:
            try:
                ScanType(data["scan_type"])
            except ValueError:
                return error("invalid scan type", 400)
            schedule.scan_type = data["scan_type"]

        if "frequency" in data:
            try:
                ScheduleFrequency(data["frequency"])
            except ValueError:
                return error("invalid frequency", 400)
            schedule.frequency = ScheduleFrequency(data["frequency"])

        updatable = ["name", "description", "target", "asset_ids", "intensity", "is_authenticated",
                     "auth_config", "scanner_config", "cron_expression", "timezone", "start_time",
                     "end_time", "max_duration_minutes", "notify_on_success", "notify_on_failure",
                     "notify_on_findings", "notification_integration_ids", "max_retries",
                     "retry_delay_minutes", "status"]
        for field in updatable:
            if field in data:
                setattr(schedule, field, data[field])

        if "frequency" in data or "cron_expression" in data or "start_time" in data:
            scheduler = SchedulerService(db)
            schedule.next_run = scheduler.calculate_next_run(schedule)

        await db.commit()
        await db.refresh(schedule)
        return JSONResponse(serialize_scheduled_scan(schedule))


async def delete_scheduled_scan(request):
    schedule_id = request.path_params["schedule_id"]
    async with AsyncSessionLocal() as db:
        try:
            schedule = await db.get(ScheduledScan, uuid.UUID(schedule_id))
        except (ValueError, TypeError):
            return error("invalid schedule id")
        if not schedule:
            return error("Schedule not found", 404)
        await db.delete(schedule)
        await db.commit()
        return JSONResponse({"ok": True})


async def trigger_scheduled_scan(request):
    schedule_id = request.path_params["schedule_id"]
    async with AsyncSessionLocal() as db:
        try:
            schedule = await db.get(ScheduledScan, uuid.UUID(schedule_id))
        except (ValueError, TypeError):
            return error("invalid schedule id")
        if not schedule:
            return error("Schedule not found", 404)
        if schedule.status != ScheduledScanStatus.ACTIVE:
            return error("Schedule is not active", 400)

        scheduler = SchedulerService(db)
        scan = await scheduler.create_scan_from_schedule(schedule)
        await scheduler.dispatch_scan(scan)

        schedule.last_run = datetime.now(timezone.utc)
        schedule.next_run = scheduler.calculate_next_run(schedule, schedule.last_run)
        schedule.consecutive_failures = 0
        schedule.last_run_status = "success"
        await db.commit()
        await db.refresh(schedule)
        return JSONResponse({"scan_id": str(scan.id), "schedule": serialize_scheduled_scan(schedule)})


# ---------------------------------------------------------------------------
# Scan Templates
# ---------------------------------------------------------------------------

async def list_scan_templates(request):
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, request.query_params.get("workspace_id"))
        include_system = request.query_params.get("include_system", "true").lower() == "true"
        query = select(ScanTemplate).where(ScanTemplate.workspace_id == ws.id)
        if not include_system:
            query = query.where(ScanTemplate.is_system == False)
        rows = (await db.execute(query.order_by(ScanTemplate.created_at.desc()))).scalars().all()
        return JSONResponse([serialize_scan_template(t) for t in rows])


async def create_scan_template(request):
    data = await read_json(request)
    required = ["name", "scan_type"]
    for field in required:
        if not data.get(field):
            return error(f"{field} is required", 400)

    try:
        ScanType(data["scan_type"])
    except ValueError:
        return error("invalid scan type", 400)

    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, data.get("workspace_id"))
        template = ScanTemplate(
            workspace_id=ws.id,
            name=data["name"],
            description=data.get("description"),
            category=data.get("category"),
            scan_type=data["scan_type"],
            intensity=data.get("intensity", "normal"),
            scanner_config=data.get("scanner_config") or {},
            is_authenticated=data.get("is_authenticated", False),
            auth_config=data.get("auth_config") or {},
            is_system=False,
            is_public=data.get("is_public", False),
        )
        db.add(template)
        await db.commit()
        await db.refresh(template)
        return JSONResponse(serialize_scan_template(template), status_code=201)


async def get_scan_template(request):
    template_id = request.path_params["template_id"]
    async with AsyncSessionLocal() as db:
        try:
            template = await db.get(ScanTemplate, uuid.UUID(template_id))
        except (ValueError, TypeError):
            return error("invalid template id")
        if not template:
            return error("Template not found", 404)
        return JSONResponse(serialize_scan_template(template))


async def update_scan_template(request):
    template_id = request.path_params["template_id"]
    data = await read_json(request)
    async with AsyncSessionLocal() as db:
        try:
            template = await db.get(ScanTemplate, uuid.UUID(template_id))
        except (ValueError, TypeError):
            return error("invalid template id")
        if not template:
            return error("Template not found", 404)
        if template.is_system:
            return error("Cannot modify system template", 400)

        if "scan_type" in data:
            try:
                ScanType(data["scan_type"])
            except ValueError:
                return error("invalid scan type", 400)
            template.scan_type = data["scan_type"]

        updatable = ["name", "description", "category", "intensity", "scanner_config",
                     "is_authenticated", "auth_config", "is_public"]
        for field in updatable:
            if field in data:
                setattr(template, field, data[field])

        await db.commit()
        await db.refresh(template)
        return JSONResponse(serialize_scan_template(template))


async def delete_scan_template(request):
    template_id = request.path_params["template_id"]
    async with AsyncSessionLocal() as db:
        try:
            template = await db.get(ScanTemplate, uuid.UUID(template_id))
        except (ValueError, TypeError):
            return error("invalid template id")
        if not template:
            return error("Template not found", 404)
        if template.is_system:
            return error("Cannot delete system template", 400)
        await db.delete(template)
        await db.commit()
        return JSONResponse({"ok": True})


async def use_scan_template(request):
    template_id = request.path_params["template_id"]
    data = await read_json(request)
    target = (data.get("target") or "").strip()
    if not target:
        return error("target is required", 400)

    async with AsyncSessionLocal() as db:
        try:
            template = await db.get(ScanTemplate, uuid.UUID(template_id))
        except (ValueError, TypeError):
            return error("invalid template id")
        if not template:
            return error("Template not found", 404)

        ws = await resolve_workspace(db, data.get("workspace_id"))

        active = (await db.execute(
            select(func.count(Scan.id)).where(
                Scan.workspace_id == ws.id,
                Scan.status.in_([ScanStatus.PENDING, ScanStatus.QUEUED, ScanStatus.RUNNING]),
            )
        )).scalar_one()
        if active >= ws.concurrent_scan_limit:
            return error("Concurrent scan limit reached")

        asset = None
        asset_id = data.get("asset_id")
        if asset_id:
            try:
                asset = await db.get(Asset, uuid.UUID(str(asset_id)))
            except (ValueError, TypeError):
                asset = None
        if not asset:
            asset = (await db.execute(
                select(Asset).where(
                    Asset.workspace_id == ws.id,
                    Asset.target == target,
                    Asset.deleted_at.is_(None),
                )
            )).scalars().first()
        if not asset:
            asset = Asset(
                workspace_id=ws.id,
                target=target,
                type=_normalize_asset_type(data.get("asset_type", "hostname")),
            )
            db.add(asset)
            await db.flush()

        scan = Scan(
            workspace_id=ws.id,
            asset_id=asset.id,
            name=data.get("name") or f"{template.name} — {target}",
            type=ScanType(template.scan_type),
            target=target,
            intensity=ScanIntensity(template.intensity),
            status=ScanStatus.PENDING,
            progress=0.0,
            scanner_config=template.scanner_config,
            is_authenticated=template.is_authenticated,
            auth_config=template.auth_config,
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        template.usage_count = (template.usage_count or 0) + 1
        await db.commit()

        try:
            async_result = run_scan_task.apply_async(
                args=[str(scan.id), {
                    "target": scan.target,
                    "scan_type": scan.type.value,
                    "intensity": scan.intensity.value,
                    "is_authenticated": scan.is_authenticated,
                    "auth_config": scan.auth_config,
                    "options": scan.scanner_config,
                }],
                queue="scanners",
            )
            scan.status = ScanStatus.QUEUED
            scan.celery_task_id = async_result.id
            await db.commit()
        except Exception as exc:
            scan.status = ScanStatus.FAILED
            scan.error_message = f"Could not queue scan worker: {exc}"
            await db.commit()

        return JSONResponse(serialize_scan(scan), status_code=201)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

async def list_reports(request):
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, request.query_params.get("workspace_id"))
        status_filter = request.query_params.get("status")
        query = select(Report).where(Report.workspace_id == ws.id)
        if status_filter:
            try:
                query = query.where(Report.status == ReportStatus(status_filter))
            except ValueError:
                return error("invalid status filter", 400)
        rows = (await db.execute(query.order_by(Report.created_at.desc()).limit(200))).scalars().all()
        return JSONResponse([serialize_report(r) for r in rows])


async def create_report(request):
    data = await read_json(request)
    required = ["title", "scan_ids"]
    for field in required:
        if not data.get(field):
            return error(f"{field} is required", 400)

    format_str = data.get("format", "pdf")
    try:
        report_format = ReportFormat(format_str)
    except ValueError:
        return error("invalid format", 400)

    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, data.get("workspace_id"))
        report = Report(
            workspace_id=ws.id,
            template_id=uuid.UUID(data["template_id"]) if data.get("template_id") else None,
            scan_ids=data["scan_ids"],
            finding_ids=data.get("finding_ids") or [],
            asset_ids=data.get("asset_ids") or [],
            title=data["title"],
            description=data.get("description"),
            format=report_format,
            status=ReportStatus.GENERATING,
            severity_filter=data.get("severity_filter") or [],
            status_filter=data.get("status_filter") or [],
            date_range=data.get("date_range") or {},
            compliance_frameworks=data.get("compliance_frameworks") or [],
        )
        db.add(report)
        await db.commit()
        await db.refresh(report)

        # Queue report generation
        from services.report_service import generate_report
        try:
            # Fetch related data
            scans = (await db.execute(
                select(Scan).where(Scan.id.in_(report.scan_ids))
            )).scalars().all()
            findings = (await db.execute(
                select(Finding).where(Finding.id.in_(report.finding_ids)) if report.finding_ids else
                select(Finding).where(Finding.scan_id.in_(report.scan_ids))
            )).scalars().all()
            assets = (await db.execute(
                select(Asset).where(Asset.id.in_(report.asset_ids)) if report.asset_ids else
                select(Asset).where(Asset.workspace_id == ws.id, Asset.deleted_at.is_(None))
            )).scalars().all()

            # Generate report
            start = datetime.now(timezone.utc)
            pdf_bytes = await generate_report(report, ws, scans, findings, assets, format_str)
            duration = (datetime.now(timezone.utc) - start).total_seconds()

            # Save to file
            reports_dir = settings.REPORTS_DIR
            os.makedirs(reports_dir, exist_ok=True)
            filename = f"{report.id}.{format_str}"
            filepath = os.path.join(reports_dir, filename)
            with open(filepath, "wb") as f:
                f.write(pdf_bytes)

            report.status = ReportStatus.READY
            report.file_path = filepath
            report.file_size = len(pdf_bytes)
            report.generation_duration_seconds = duration
            report.completed_at = datetime.now(timezone.utc)
            await db.commit()
            await db.refresh(report)
        except Exception as exc:
            report.status = ReportStatus.FAILED
            report.generation_error = str(exc)
            await db.commit()

        return JSONResponse(serialize_report(report), status_code=201)


async def get_report(request):
    report_id = request.path_params["report_id"]
    async with AsyncSessionLocal() as db:
        try:
            report = await db.get(Report, uuid.UUID(report_id))
        except (ValueError, TypeError):
            return error("invalid report id")
        if not report:
            return error("Report not found", 404)
        return JSONResponse(serialize_report(report))


async def download_report(request):
    report_id = request.path_params["report_id"]
    async with AsyncSessionLocal() as db:
        try:
            report = await db.get(Report, uuid.UUID(report_id))
        except (ValueError, TypeError):
            return error("invalid report id")
        if not report:
            return error("Report not found", 404)
        if report.status != ReportStatus.READY or not report.file_path:
            return error("Report not ready", 400)
        if not os.path.exists(report.file_path):
            return error("Report file not found", 404)

        report.download_count = (report.download_count or 0) + 1
        report.last_downloaded_at = datetime.now(timezone.utc)
        await db.commit()

        from starlette.responses import FileResponse
        return FileResponse(
            report.file_path,
            filename=f"{report.title.replace(' ', '_')}.{report.format.value}",
            media_type="application/pdf" if report.format == ReportFormat.PDF else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )


async def delete_report(request):
    report_id = request.path_params["report_id"]
    async with AsyncSessionLocal() as db:
        try:
            report = await db.get(Report, uuid.UUID(report_id))
        except (ValueError, TypeError):
            return error("invalid report id")
        if not report:
            return error("Report not found", 404)
        if report.file_path and os.path.exists(report.file_path):
            os.remove(report.file_path)
        await db.delete(report)
        await db.commit()
        return JSONResponse({"ok": True})


# Report Templates
async def list_report_templates(request):
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, request.query_params.get("workspace_id"))
        include_system = request.query_params.get("include_system", "true").lower() == "true"
        query = select(ReportTemplate).where(ReportTemplate.workspace_id == ws.id)
        if not include_system:
            query = query.where(ReportTemplate.is_system == False)
        rows = (await db.execute(query.order_by(ReportTemplate.created_at.desc()))).scalars().all()
        return JSONResponse([serialize_report_template(t) for t in rows])


async def create_report_template(request):
    data = await read_json(request)
    required = ["name", "type"]
    for field in required:
        if not data.get(field):
            return error(f"{field} is required", 400)

    try:
        ReportTemplateType(data["type"])
    except ValueError:
        return error("invalid template type", 400)

    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, data.get("workspace_id"))
        template = ReportTemplate(
            workspace_id=ws.id,
            name=data["name"],
            description=data.get("description"),
            type=ReportTemplateType(data["type"]),
            compliance_frameworks=data.get("compliance_frameworks") or [],
            template_content=data.get("template_content") or "",
            template_variables=data.get("template_variables") or {},
            logo_path=data.get("logo_path"),
            primary_color=data.get("primary_color"),
            secondary_color=data.get("secondary_color"),
            font_family=data.get("font_family"),
            footer_text=data.get("footer_text"),
            sections=data.get("sections") or [],
            default_formats=data.get("default_formats") or ["pdf", "docx"],
            is_default=data.get("is_default", False),
            is_system=False,
        )
        db.add(template)
        await db.commit()
        await db.refresh(template)
        return JSONResponse(serialize_report_template(template), status_code=201)


async def get_report_template(request):
    template_id = request.path_params["template_id"]
    async with AsyncSessionLocal() as db:
        try:
            template = await db.get(ReportTemplate, uuid.UUID(template_id))
        except (ValueError, TypeError):
            return error("invalid template id")
        if not template:
            return error("Template not found", 404)
        return JSONResponse(serialize_report_template(template))


async def update_report_template(request):
    template_id = request.path_params["template_id"]
    data = await read_json(request)
    async with AsyncSessionLocal() as db:
        try:
            template = await db.get(ReportTemplate, uuid.UUID(template_id))
        except (ValueError, TypeError):
            return error("invalid template id")
        if not template:
            return error("Template not found", 404)
        if template.is_system:
            return error("Cannot modify system template", 400)

        if "type" in data:
            try:
                ReportTemplateType(data["type"])
            except ValueError:
                return error("invalid template type", 400)
            template.type = ReportTemplateType(data["type"])

        updatable = ["name", "description", "compliance_frameworks", "template_content",
                     "template_variables", "logo_path", "primary_color", "secondary_color",
                     "font_family", "footer_text", "sections", "default_formats",
                     "is_default"]
        for field in updatable:
            if field in data:
                setattr(template, field, data[field])

        await db.commit()
        await db.refresh(template)
        return JSONResponse(serialize_report_template(template))


async def delete_report_template(request):
    template_id = request.path_params["template_id"]
    async with AsyncSessionLocal() as db:
        try:
            template = await db.get(ReportTemplate, uuid.UUID(template_id))
        except (ValueError, TypeError):
            return error("invalid template id")
        if not template:
            return error("Template not found", 404)
        if template.is_system:
            return error("Cannot delete system template", 400)
        await db.delete(template)
        await db.commit()
        return JSONResponse({"ok": True})


# ---------------------------------------------------------------------------
# Diff / Monitoring
# ---------------------------------------------------------------------------

async def compare_scans(request):
    data = await read_json(request)
    baseline_id = data.get("baseline_scan_id")
    current_id = data.get("current_scan_id")

    if not baseline_id or not current_id:
        return error("baseline_scan_id and current_scan_id are required", 400)

    async with AsyncSessionLocal() as db:
        service = DiffService(db)
        try:
            result = await service.compare_scans(uuid.UUID(baseline_id), uuid.UUID(current_id))
        except Exception as exc:
            return error(f"Comparison failed: {exc}", 500)
        return JSONResponse(result)


async def compare_latest_scans(request):
    target = request.query_params.get("target")
    if not target:
        return error("target query parameter required", 400)

    async with AsyncSessionLocal() as db:
        service = DiffService(db)
        result = await service.compare_latest_two_scans(target)
        if result is None:
            return error("Not enough completed scans to compare (need at least 2)", 404)
        return JSONResponse(result)


async def workspace_diff(request):
    workspace_id = request.query_params.get("workspace_id")
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, workspace_id)
        service = DiffService(db)
        diffs = await service.get_all_target_diffs(ws.id)
        return JSONResponse({
            "workspace_id": str(ws.id),
            "targets_compared": len(diffs),
            "diffs": diffs,
        })


async def diff_alerts(request):
    workspace_id = request.query_params.get("workspace_id")
    severity = request.query_params.get("severity", "high")
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, workspace_id)
        service = DiffService(db)
        alerts = await service.check_for_alerts(ws.id, severity)
        return JSONResponse({
            "workspace_id": str(ws.id),
            "severity_threshold": severity,
            "alerts": alerts,
        })


async def run_diff_check_endpoint(request):
    workspace_id = request.query_params.get("workspace_id")
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, workspace_id)
        result = await run_diff_check(ws.id)
        return JSONResponse(result)


# ---------------------------------------------------------------------------
# Attack Surface
# ---------------------------------------------------------------------------

async def attack_surface(request):
    workspace_id = request.query_params.get("workspace_id")
    group_by = request.query_params.get("group_by")
    query = (request.query_params.get("q") or "").strip().lower()
    enabled = {
        "ip_address", "hostname", "port", "protocol", "service", "technology"
    }
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, workspace_id)
        data = await AttackSurfaceService(db).build(ws.id)

    rows = data["rows"]
    if query:
        rows = [
            r for r in rows
            if query in (r["hostname"] or "").lower()
            or query in (r["ip"] or "").lower()
            or any(query in (t or "").lower() for t in r["technologies"])
            or any(query in (p.get("service") or "").lower() for p in r["ports"])
        ]
    data["rows"] = rows
    data["group_by"] = group_by if group_by in enabled else "hostname"
    return JSONResponse(data)


async def attack_surface_stats(request):
    workspace_id = request.query_params.get("workspace_id")
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, workspace_id)
        data = await AttackSurfaceService(db).stats(ws.id)
    return JSONResponse(data)


# ---------------------------------------------------------------------------
# Realtime: socket handlers + database broadcaster
# ---------------------------------------------------------------------------
# Realtime: socket handlers + database broadcaster
# ---------------------------------------------------------------------------

@sio.event
async def connect(sid, environ, auth):
    auth = auth or {}
    workspace_id = auth.get("workspace_id")
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, workspace_id)
        await sio.save_session(sid, {
            "workspace_id": str(ws.id),
            "user_id": auth.get("user_id"),
            "token": auth.get("token"),
        })
        await sio.enter_room(sid, f"workspace:{ws.id}")
        await sio.emit("connected", {"workspace_id": str(ws.id), "socket_id": sid}, to=sid)


@sio.event
async def subscribe(sid, data):
    data = data or {}
    if data.get("scan_id"):
        await sio.enter_room(sid, f"scan:{data['scan_id']}")
    if data.get("asset_id"):
        await sio.enter_room(sid, f"asset:{data['asset_id']}")


@sio.event
async def unsubscribe(sid, data):
    data = data or {}
    if data.get("scan_id"):
        await sio.leave_room(sid, f"scan:{data['scan_id']}")
    if data.get("asset_id"):
        await sio.leave_room(sid, f"asset:{data['asset_id']}")


_broadcast_state: dict[str, tuple] = {}
_finding_cursor: datetime = datetime.utcnow()
_asset_cursor: datetime = datetime.utcnow()
_broadcast_task: Optional[asyncio.Task] = None


async def _broadcast_loop() -> None:
    global _finding_cursor, _asset_cursor
    while True:
        try:
            async with AsyncSessionLocal() as db:
                scans = (await db.execute(
                    select(Scan).order_by(Scan.updated_at.desc()).limit(200)
                )).scalars().all()

                for scan in scans:
                    key = str(scan.id)
                    signature = (
                        _enum(scan.status),
                        round(scan.progress or 0, 1),
                        scan.findings_count or 0,
                        scan.current_step,
                        scan.error_message,
                    )
                    if _broadcast_state.get(key) == signature:
                        continue
                    previous = _broadcast_state.get(key)
                    _broadcast_state[key] = signature
                    status = _enum(scan.status)

                    if status == ScanStatus.COMPLETED.value:
                        event_name = "scan_completed"
                    elif status == ScanStatus.FAILED.value:
                        event_name = "scan_failed"
                    elif previous is None and status in (ScanStatus.PENDING.value, ScanStatus.QUEUED.value):
                        event_name = "scan_started"
                    else:
                        event_name = "scan_progress"

                    payload = serialize_scan(scan)
                    if event_name in ("scan_completed", "scan_failed", "scan_started"):
                        try:
                            await dispatch_event(event_name, scan.workspace_id, payload)
                        except Exception as exc:  # pragma: no cover - best effort
                            logger.warning("integration dispatch failed for %s: %s", event_name, exc)
                    await sio.emit(
                        event_name,
                        _event(event_name, scan.workspace_id, payload),
                        room=f"workspace:{scan.workspace_id}",
                    )

                new_findings = (await db.execute(
                    select(Finding)
                    .where(Finding.created_at > _finding_cursor)
                    .order_by(Finding.created_at)
                    .limit(100)
                )).scalars().all()
                for finding in new_findings:
                    _finding_cursor = finding.created_at or _finding_cursor
                    payload = serialize_finding(finding)
                    await sio.emit(
                        "finding_created",
                        _event("finding_created", finding.workspace_id, payload),
                        room=f"workspace:{finding.workspace_id}",
                    )
                    # Dispatch integration event
                    await dispatch_event("finding_created", finding.workspace_id, payload)

                updated_assets = (await db.execute(
                    select(Asset)
                    .where(Asset.updated_at > _asset_cursor)
                    .order_by(Asset.updated_at)
                    .limit(50)
                )).scalars().all()
                for asset in updated_assets:
                    _asset_cursor = asset.updated_at or _asset_cursor
                    await sio.emit(
                        "asset_updated",
                        _event("asset_updated", asset.workspace_id, serialize_asset(asset)),
                        room=f"workspace:{asset.workspace_id}",
                    )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # keep broadcasting even if one iteration fails
            print(f"[broadcast] error: {exc}")
        await asyncio.sleep(1.0)



# ---------------------------------------------------------------------------
# Auth enforcement / principals
# ---------------------------------------------------------------------------

PUBLIC_API_PATHS = {
    "/api/health",
    "/api/openapi.json",
    "/api/auth/register",
    "/api/auth/login",
    "/api/auth/refresh",
    "/api/auth/password-reset",
    "/api/auth/password-reset/confirm",
    "/api/auth/email-verification/send",
    "/api/auth/email-verification/verify",
}


async def _first_workspace_for_user(db, user_id):
    result = await db.execute(
        select(WorkspaceMember)
        .where(WorkspaceMember.user_id == user_id)
        .order_by(WorkspaceMember.joined_at)
        .limit(1)
    )
    member = result.scalars().first()
    if member:
        return member.workspace_id, member.role
    return None, None


async def _select_workspace(db, user_id, requested: Optional[str]):
    if requested:
        try:
            candidate = uuid.UUID(str(requested))
        except (ValueError, TypeError):
            candidate = None
        if candidate:
            role = await _membership_role(db, candidate, user_id)
            if role:
                return candidate, role
    return await _first_workspace_for_user(db, user_id)


async def _authenticate_http(headers) -> Optional[dict]:
    bearer = headers.get("authorization") or ""
    requested_workspace = headers.get("x-workspace-id")
    api_key = headers.get("x-api-key")
    if not api_key and bearer.lower().startswith("bearer "):
        candidate = bearer[7:].strip()
        if candidate.startswith("pt_"):
            api_key = candidate

    if api_key:
        async with AsyncSessionLocal() as db:
            auth = AuthService(db)
            key = await auth.validate_api_key(api_key)
            if not key:
                return None
            user = await db.get(User, key.user_id)
            if not user or not user.is_active:
                return None
            workspace_id, role = await _select_workspace(db, user.id, requested_workspace)
            await db.commit()
            return {
                "user_id": str(user.id),
                "email": user.email,
                "workspace_id": str(workspace_id) if workspace_id else None,
                "role": role,
                "via": "api_key",
                "api_key_id": str(key.id),
            }

    if bearer.lower().startswith("bearer "):
        payload = verify_token_type(bearer[7:].strip(), "access")
        if not payload:
            return None
        user_id = payload.get("sub")
        if not user_id:
            return None
        try:
            uid = uuid.UUID(str(user_id))
        except (ValueError, TypeError):
            return None
        async with AsyncSessionLocal() as db:
            user = await db.get(User, uid)
            if not user or not user.is_active:
                return None
            workspace_id, role = await _select_workspace(db, user.id, requested_workspace)
            return {
                "user_id": str(user.id),
                "email": user.email,
                "workspace_id": str(workspace_id) if workspace_id else None,
                "role": role,
                "via": "jwt",
            }
    return None


class AuthEnforcementMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        method = scope.get("method", "")
        # Allow OPTIONS preflight requests to pass through for CORS
        if method == "OPTIONS":
            return await self.app(scope, receive, send)
        if not path.startswith("/api/") or path in PUBLIC_API_PATHS:
            return await self.app(scope, receive, send)

        principal = await _authenticate_http(Headers(scope=scope))
        if not principal:
            response = JSONResponse({"detail": "Authentication required"}, status_code=401)
            return await response(scope, receive, send)
        scope.setdefault("state", {})
        scope["state"]["principal"] = principal
        
        # Check X-Workspace-ID header first, then fall back to JWT claim
        headers = Headers(scope=scope)
        header_ws = headers.get("x-workspace-id")
        raw_ws = header_ws if header_ws else principal.get("workspace_id")
        token = None
        if raw_ws:
            try:
                token = _current_workspace.set(uuid.UUID(str(raw_ws)))
            except (ValueError, TypeError):
                token = None
        try:
            await self.app(scope, receive, send)
        finally:
            if token is not None:
                _current_workspace.reset(token)


def get_principal(request) -> Optional[dict]:
    return (request.scope.get("state") or {}).get("principal")


def principal_user_id(request) -> Optional[uuid.UUID]:
    principal = get_principal(request) or {}
    raw = principal.get("user_id")
    try:
        return uuid.UUID(str(raw)) if raw else None
    except (ValueError, TypeError):
        return None


def principal_workspace_id(request) -> Optional[uuid.UUID]:
    principal = get_principal(request) or {}
    raw = principal.get("workspace_id")
    try:
        return uuid.UUID(str(raw)) if raw else None
    except (ValueError, TypeError):
        return None


async def _membership_role(db, workspace_id, user_id) -> Optional[str]:
    if not workspace_id or not user_id:
        return None
    result = await db.execute(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == user_id,
        )
    )
    member = result.scalars().first()
    return member.role if member else None


# ---------------------------------------------------------------------------
# Team, workspaces, API keys
# ---------------------------------------------------------------------------

TEAM_ROLES = {"owner", "admin", "member", "viewer"}


def _serialize_member(member: WorkspaceMember, user: Optional[User], current_user_id=None) -> dict:
    return {
        "id": str(member.user_id),
        "workspace_id": str(member.workspace_id),
        "email": user.email if user else None,
        "full_name": user.full_name if user else None,
        "avatar_url": user.avatar_url if user else None,
        "role": member.role,
        "joined_at": _iso(member.joined_at),
        "last_login": _iso(user.last_login) if user else None,
        "is_active": bool(user.is_active) if user else False,
        "is_current_user": bool(current_user_id and member.user_id == current_user_id),
    }


def _serialize_api_key(key: APIKey) -> dict:
    scopes = []
    if key.scopes:
        try:
            scopes = json.loads(key.scopes) if isinstance(key.scopes, str) else key.scopes
        except (ValueError, TypeError):
            scopes = []
    return {
        "id": str(key.id),
        "name": key.name,
        "prefix": key.key_prefix,
        "scopes": scopes,
        "last_used": _iso(key.last_used),
        "expires_at": _iso(key.expires_at),
        "created_at": _iso(key.created_at),
        "revoked": bool(key.revoked_at),
    }


async def list_workspaces(request):
    user_id = principal_user_id(request)
    async with AsyncSessionLocal() as db:
        auth = AuthService(db)
        workspaces = await auth.get_user_workspaces(user_id)
        memberships = (await db.execute(
            select(WorkspaceMember).where(WorkspaceMember.user_id == user_id)
        )).scalars().all()
        role_by_ws = {m.workspace_id: m.role for m in memberships}
        return JSONResponse([
            {
                "id": str(ws.id),
                "name": ws.name,
                "slug": ws.slug,
                "plan": _enum(ws.plan),
                "role": role_by_ws.get(ws.id),
                "asset_limit": ws.asset_limit,
                "concurrent_scan_limit": ws.concurrent_scan_limit,
                "scheduled_scan_limit": ws.scheduled_scan_limit,
                "team_member_limit": ws.team_member_limit,
            }
            for ws in workspaces
        ])


async def list_team_members(request):
    user_id = principal_user_id(request)
    workspace_id = principal_workspace_id(request)
    if not workspace_id:
        return error("No workspace for this account", 400)
    async with AsyncSessionLocal() as db:
        members = (await db.execute(
            select(WorkspaceMember, User)
            .join(User, User.id == WorkspaceMember.user_id)
            .where(WorkspaceMember.workspace_id == workspace_id)
            .order_by(WorkspaceMember.joined_at)
        )).all()
        workspace = await db.get(Workspace, workspace_id)
        invites = (await db.execute(
            select(InviteToken).where(
                InviteToken.workspace_id == workspace_id,
                InviteToken.accepted_at.is_(None),
                InviteToken.expires_at > datetime.now(timezone.utc),
            ).order_by(InviteToken.created_at.desc())
        )).scalars().all()
        return JSONResponse({
            "workspace": {
                "id": str(workspace.id),
                "name": workspace.name,
                "plan": _enum(workspace.plan),
                "team_member_limit": workspace.team_member_limit,
            },
            "members": [_serialize_member(m, u, user_id) for m, u in members],
            "pending_invites": [
                {
                    "id": str(inv.id),
                    "email": inv.email,
                    "role": inv.role,
                    "expires_at": _iso(inv.expires_at),
                    "created_at": _iso(inv.created_at),
                }
                for inv in invites
            ],
            "roles": ["owner", "admin", "member", "viewer"],
        })


async def invite_team_member(request):
    user_id = principal_user_id(request)
    workspace_id = principal_workspace_id(request)
    data = await read_json(request)
    email = (data.get("email") or "").strip().lower()
    role = (data.get("role") or "member").lower()
    if not email or "@" not in email:
        return error("A valid email is required", 400)
    if role not in TEAM_ROLES or role == "owner":
        return error("Role must be one of admin, member, viewer", 400)

    async with AsyncSessionLocal() as db:
        acting_role = await _membership_role(db, workspace_id, user_id)
        if acting_role not in ("owner", "admin"):
            return error("Only owners and admins can invite members", 403)
        workspace = await db.get(Workspace, workspace_id)
        inviter = await db.get(User, user_id)
        member_count = (await db.execute(
            select(func.count()).select_from(WorkspaceMember).where(WorkspaceMember.workspace_id == workspace_id)
        )).scalar() or 0
        if workspace and workspace.team_member_limit and member_count >= workspace.team_member_limit:
            return error("Team member limit reached for this plan", 400)
        existing_user = (await db.execute(select(User).where(User.email == email))).scalars().first()
        if existing_user:
            already = await _membership_role(db, workspace_id, existing_user.id)
            if already:
                return error("That user is already a member of this workspace", 400)
        auth = AuthService(db)
        invite, token = await auth.create_invite_token(workspace_id, email, role, user_id)
        await db.commit()

        # Send invitation email (non-blocking)
        if workspace and inviter:
            invite_url = f"{settings.APP_URL or 'http://localhost:3000'}/join?token={token}"
            email_service.send_invite_email(
                to=email,
                inviter_name=inviter.full_name or inviter.email,
                workspace_name=workspace.name,
                invite_token=token,
                invite_url=invite_url,
            )

        return JSONResponse({
            "id": str(invite.id),
            "email": invite.email,
            "role": invite.role,
            "token": token,
            "expires_at": _iso(invite.expires_at),
        }, status_code=201)


async def create_team_invite_link(request):
    """Create an invite and return its one-time acceptance token (owner/admin only)."""
    user_id = principal_user_id(request)
    workspace_id = principal_workspace_id(request)
    data = await read_json(request)
    email = (data.get("email") or "").strip().lower()
    role = (data.get("role") or "member").lower()
    if not email or "@" not in email:
        return error("A valid email is required", 400)
    if role not in TEAM_ROLES or role == "owner":
        return error("Role must be one of admin, member, viewer", 400)
    async with AsyncSessionLocal() as db:
        acting_role = await _membership_role(db, workspace_id, user_id)
        if acting_role not in ("owner", "admin"):
            return error("Only owners and admins can invite members", 403)
        workspace = await db.get(Workspace, workspace_id)
        member_count = (await db.execute(
            select(func.count()).select_from(WorkspaceMember).where(WorkspaceMember.workspace_id == workspace_id)
        )).scalar() or 0
        if workspace and workspace.team_member_limit and member_count >= workspace.team_member_limit:
            return error("Team member limit reached for this plan", 400)
        existing_user = (await db.execute(select(User).where(User.email == email))).scalars().first()
        if existing_user and await _membership_role(db, workspace_id, existing_user.id):
            return error("That user is already a member of this workspace", 400)
        auth = AuthService(db)
        invite, token = await auth.create_invite_token(workspace_id, email, role, user_id)
        await db.commit()
        return JSONResponse({
            "id": str(invite.id),
            "email": invite.email,
            "role": invite.role,
            "token": token,
            "expires_at": _iso(invite.expires_at),
        }, status_code=201)


async def accept_team_invite(request):
    user_id = principal_user_id(request)
    data = await read_json(request)
    token = (data.get("token") or "").strip()
    if not token:
        return error("Invite token is required", 400)
    async with AsyncSessionLocal() as db:
        auth = AuthService(db)
        invite = await auth.validate_invite_token(token)
        if not invite:
            return error("Invite is invalid or expired", 400)
        user = await db.get(User, user_id)
        if not user:
            return error("Authentication required", 401)
        if invite.email and user.email.lower() != invite.email.lower():
            return error("This invite was issued to a different email address", 403)
        existing = await _membership_role(db, invite.workspace_id, user_id)
        if existing:
            invite.accepted_at = datetime.now(timezone.utc)
            invite.accepted_by = user_id
            await db.commit()
            return JSONResponse({"ok": True, "workspace_id": str(invite.workspace_id), "role": existing})
        member = await auth.accept_invite(invite, user_id)
        await db.commit()
        return JSONResponse({"ok": True, "workspace_id": str(member.workspace_id), "role": member.role})


async def update_team_member(request):
    acting_id = principal_user_id(request)
    workspace_id = principal_workspace_id(request)
    target_id = request.path_params.get("user_id")
    data = await read_json(request)
    role = (data.get("role") or "").lower()
    if role not in TEAM_ROLES:
        return error("Invalid role", 400)
    try:
        target_uuid = uuid.UUID(str(target_id))
    except (ValueError, TypeError):
        return error("Invalid member id", 400)
    async with AsyncSessionLocal() as db:
        acting_role = await _membership_role(db, workspace_id, acting_id)
        if acting_role not in ("owner", "admin"):
            return error("Only owners and admins can change roles", 403)
        if role == "owner" and acting_role != "owner":
            return error("Only an owner can transfer ownership", 403)
        target_role = await _membership_role(db, workspace_id, target_uuid)
        if not target_role:
            return error("Member not found", 404)
        if target_role == "owner" and role != "owner":
            owners = (await db.execute(
                select(func.count()).select_from(WorkspaceMember).where(
                    WorkspaceMember.workspace_id == workspace_id,
                    WorkspaceMember.role == "owner",
                )
            )).scalar() or 0
            if owners <= 1:
                return error("The workspace must keep at least one owner", 400)
        auth = AuthService(db)
        member = await auth.update_member_role(workspace_id, target_uuid, role)
        await db.commit()
        return JSONResponse(_serialize_member(member, await db.get(User, target_uuid), acting_id))


async def remove_team_member(request):
    acting_id = principal_user_id(request)
    workspace_id = principal_workspace_id(request)
    target_id = request.path_params.get("user_id")
    try:
        target_uuid = uuid.UUID(str(target_id))
    except (ValueError, TypeError):
        return error("Invalid member id", 400)
    async with AsyncSessionLocal() as db:
        acting_role = await _membership_role(db, workspace_id, acting_id)
        if acting_role not in ("owner", "admin"):
            return error("Only owners and admins can remove members", 403)
        target_role = await _membership_role(db, workspace_id, target_uuid)
        if not target_role:
            return error("Member not found", 404)
        if target_role == "owner":
            owners = (await db.execute(
                select(func.count()).select_from(WorkspaceMember).where(
                    WorkspaceMember.workspace_id == workspace_id,
                    WorkspaceMember.role == "owner",
                )
            )).scalar() or 0
            if owners <= 1:
                return error("The workspace must keep at least one owner", 400)
        auth = AuthService(db)
        await auth.remove_workspace_member(workspace_id, target_uuid)
        await db.commit()
        return JSONResponse({"ok": True})


async def cancel_team_invite(request):
    acting_id = principal_user_id(request)
    workspace_id = principal_workspace_id(request)
    invite_id = request.path_params.get("invite_id")
    try:
        invite_uuid = uuid.UUID(str(invite_id))
    except (ValueError, TypeError):
        return error("Invalid invite id", 400)
    async with AsyncSessionLocal() as db:
        acting_role = await _membership_role(db, workspace_id, acting_id)
        if acting_role not in ("owner", "admin"):
            return error("Only owners and admins can cancel invites", 403)
        invite = await db.get(InviteToken, invite_uuid)
        if not invite or invite.workspace_id != workspace_id or invite.accepted_at:
            return error("Invite not found", 404)
        await db.delete(invite)
        await db.commit()
        return JSONResponse({"ok": True})


async def list_api_keys(request):
    user_id = principal_user_id(request)
    async with AsyncSessionLocal() as db:
        keys = (await db.execute(
            select(APIKey).where(APIKey.user_id == user_id).order_by(APIKey.created_at.desc())
        )).scalars().all()
        return JSONResponse([_serialize_api_key(k) for k in keys if not k.revoked_at])


async def create_api_key(request):
    user_id = principal_user_id(request)
    data = await read_json(request)
    name = (data.get("name") or "").strip()
    if not name:
        return error("A key name is required", 400)
    scopes = data.get("scopes") or ["scans:read", "scans:write"]
    if not isinstance(scopes, list):
        return error("Scopes must be a list", 400)
    expires_days = data.get("expires_days")
    try:
        expires_days = int(expires_days) if expires_days else None
    except (ValueError, TypeError):
        return error("expires_days must be a number", 400)
    async with AsyncSessionLocal() as db:
        auth = AuthService(db)
        key, plaintext = await auth.create_api_key(user_id, name, [str(s) for s in scopes], expires_days)
        await db.commit()
        payload = _serialize_api_key(key)
        payload["key"] = plaintext
        return JSONResponse(payload, status_code=201)


async def revoke_api_key(request):
    user_id = principal_user_id(request)
    key_id = request.path_params.get("key_id")
    try:
        key_uuid = uuid.UUID(str(key_id))
    except (ValueError, TypeError):
        return error("Invalid key id", 400)
    async with AsyncSessionLocal() as db:
        auth = AuthService(db)
        removed = await auth.revoke_api_key(user_id, key_uuid)
        await db.commit()
        if not removed:
            return error("API key not found", 404)
        return JSONResponse({"ok": True})



# ---------------------------------------------------------------------------
# Robots (workflow chaining)
# ---------------------------------------------------------------------------

ROBOT_TOOLS = {t.value for t in ScanType}
ROBOT_INTENSITIES = {i.value for i in ScanIntensity}


def _serialize_robot(robot: Robot, last_run: Optional[RobotRun] = None) -> dict:
    steps = robot.steps if isinstance(robot.steps, list) else []
    return {
        "id": str(robot.id),
        "workspace_id": str(robot.workspace_id),
        "name": robot.name,
        "description": robot.description,
        "steps": steps,
        "step_count": len(steps),
        "max_targets": robot.max_targets,
        "is_active": bool(robot.is_active),
        "schedule_cron": robot.schedule_cron,
        "created_at": _iso(robot.created_at),
        "updated_at": _iso(robot.updated_at),
        "last_run": _serialize_robot_run(last_run) if last_run else None,
    }


def _serialize_robot_run(run: RobotRun) -> dict:
    return {
        "id": str(run.id),
        "robot_id": str(run.robot_id),
        "workspace_id": str(run.workspace_id),
        "target": run.target,
        "status": run.status,
        "current_step": run.current_step,
        "total_steps": run.total_steps,
        "steps_state": run.steps_state or [],
        "scan_ids": run.scan_ids or [],
        "error_message": run.error_message,
        "started_at": _iso(run.started_at),
        "completed_at": _iso(run.completed_at),
        "created_at": _iso(run.created_at),
    }


def _validate_robot_steps(raw) -> tuple[Optional[list], Optional[str]]:
    if not isinstance(raw, list) or not raw:
        return None, "steps must be a non-empty list"
    steps = []
    for index, step in enumerate(raw):
        if not isinstance(step, dict):
            return None, f"step {index + 1} must be an object"
        tool = str(step.get("tool") or "").lower()
        if tool not in ROBOT_TOOLS:
            return None, f"step {index + 1}: unknown tool '{tool}'"
        intensity = str(step.get("intensity") or "normal").lower()
        if intensity not in ROBOT_INTENSITIES:
            return None, f"step {index + 1}: unknown intensity '{intensity}'"
        steps.append({"tool": tool, "intensity": intensity})
    return steps, None


async def list_robots(request):
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, request.query_params.get("workspace_id"))
        robots = (await db.execute(
            select(Robot).where(Robot.workspace_id == ws.id).order_by(Robot.created_at.desc())
        )).scalars().all()
        result = []
        for robot in robots:
            last_run = (await db.execute(
                select(RobotRun).where(RobotRun.robot_id == robot.id).order_by(RobotRun.created_at.desc()).limit(1)
            )).scalars().first()
            result.append(_serialize_robot(robot, last_run))
        return JSONResponse(result)


async def create_robot(request):
    data = await read_json(request)
    name = (data.get("name") or "").strip()
    if not name:
        return error("name is required", 400)
    steps, problem = _validate_robot_steps(data.get("steps"))
    if problem:
        return error(problem, 400)
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, data.get("workspace_id"))
        robot = Robot(
            workspace_id=ws.id,
            name=name,
            description=data.get("description"),
            steps=steps,
            max_targets=max(1, min(int(data.get("max_targets") or 10), 50)),
            schedule_cron=(data.get("schedule_cron") or None),
        )
        db.add(robot)
        await db.commit()
        await db.refresh(robot)
        return JSONResponse(_serialize_robot(robot), status_code=201)


async def get_robot(request):
    robot_id = request.path_params.get("robot_id")
    try:
        robot_uuid = uuid.UUID(str(robot_id))
    except (ValueError, TypeError):
        return error("Invalid robot id", 400)
    async with AsyncSessionLocal() as db:
        robot = await db.get(Robot, robot_uuid)
        if not robot:
            return error("Robot not found", 404)
        last_run = (await db.execute(
            select(RobotRun).where(RobotRun.robot_id == robot.id).order_by(RobotRun.created_at.desc()).limit(1)
        )).scalars().first()
        return JSONResponse(_serialize_robot(robot, last_run))


async def update_robot(request):
    robot_id = request.path_params.get("robot_id")
    data = await read_json(request)
    try:
        robot_uuid = uuid.UUID(str(robot_id))
    except (ValueError, TypeError):
        return error("Invalid robot id", 400)
    async with AsyncSessionLocal() as db:
        robot = await db.get(Robot, robot_uuid)
        if not robot:
            return error("Robot not found", 404)
        if "name" in data:
            name = (data.get("name") or "").strip()
            if not name:
                return error("name cannot be empty", 400)
            robot.name = name
        if "description" in data:
            robot.description = data.get("description")
        if "steps" in data:
            steps, problem = _validate_robot_steps(data.get("steps"))
            if problem:
                return error(problem, 400)
            robot.steps = steps
        if "max_targets" in data:
            robot.max_targets = max(1, min(int(data.get("max_targets") or 10), 50))
        if "is_active" in data:
            robot.is_active = bool(data.get("is_active"))
        if "schedule_cron" in data:
            robot.schedule_cron = data.get("schedule_cron") or None
        await db.commit()
        await db.refresh(robot)
        return JSONResponse(_serialize_robot(robot))


async def delete_robot(request):
    robot_id = request.path_params.get("robot_id")
    try:
        robot_uuid = uuid.UUID(str(robot_id))
    except (ValueError, TypeError):
        return error("Invalid robot id", 400)
    async with AsyncSessionLocal() as db:
        robot = await db.get(Robot, robot_uuid)
        if not robot:
            return error("Robot not found", 404)
        await db.delete(robot)
        await db.commit()
        return JSONResponse({"ok": True})


async def run_robot(request):
    robot_id = request.path_params.get("robot_id")
    data = await read_json(request)
    target = (data.get("target") or "").strip()
    if not target:
        return error("target is required", 400)
    try:
        robot_uuid = uuid.UUID(str(robot_id))
    except (ValueError, TypeError):
        return error("Invalid robot id", 400)
    async with AsyncSessionLocal() as db:
        robot = await db.get(Robot, robot_uuid)
        if not robot:
            return error("Robot not found", 404)
        if not robot.is_active:
            return error("Robot is disabled", 400)
        steps = robot.steps if isinstance(robot.steps, list) else []
        if not steps:
            return error("Robot has no steps", 400)
        run = RobotRun(
            robot_id=robot.id,
            workspace_id=robot.workspace_id,
            target=target,
            status=RobotRunStatus.QUEUED.value,
            total_steps=len(steps),
            steps_state=[],
            scan_ids=[],
        )
        db.add(run)
        await db.commit()
        await db.refresh(run)
        try:
            run_robot_task.apply_async(args=[str(robot.id), str(run.id)], queue="scanners")
        except Exception as exc:
            run.status = RobotRunStatus.FAILED.value
            run.error_message = f"Could not queue robot worker: {exc}"
            await db.commit()
            return error(run.error_message, 500)
        return JSONResponse(_serialize_robot_run(run), status_code=201)


async def list_robot_runs(request):
    robot_id = request.query_params.get("robot_id")
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, request.query_params.get("workspace_id"))
        query = select(RobotRun).where(RobotRun.workspace_id == ws.id)
        if robot_id:
            try:
                query = query.where(RobotRun.robot_id == uuid.UUID(str(robot_id)))
            except (ValueError, TypeError):
                return error("Invalid robot id", 400)
        runs = (await db.execute(query.order_by(RobotRun.created_at.desc()).limit(100))).scalars().all()
        return JSONResponse([_serialize_robot_run(r) for r in runs])


async def get_robot_run(request):
    run_id = request.path_params.get("run_id")
    try:
        run_uuid = uuid.UUID(str(run_id))
    except (ValueError, TypeError):
        return error("Invalid run id", 400)
    async with AsyncSessionLocal() as db:
        run = await db.get(RobotRun, run_uuid)
        if not run:
            return error("Robot run not found", 404)
        return JSONResponse(_serialize_robot_run(run))



# ---------------------------------------------------------------------------
# Dashboard analytics and plan usage
# ---------------------------------------------------------------------------

async def workspace_usage(request):
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, request.query_params.get("workspace_id"))
        return JSONResponse(await _build_usage(db, ws))


async def _build_usage(db, ws: Workspace) -> dict:
    from models.schedule import ScheduledScan
    from models.user import User

    assets_used = (await db.execute(
        select(func.count(Asset.id)).where(Asset.workspace_id == ws.id, Asset.deleted_at.is_(None))
    )).scalar_one()
    running = (await db.execute(
        select(func.count(Scan.id)).where(Scan.workspace_id == ws.id, Scan.status == ScanStatus.RUNNING)
    )).scalar_one()
    waiting = (await db.execute(
        select(func.count(Scan.id)).where(Scan.workspace_id == ws.id, Scan.status.in_([ScanStatus.PENDING, ScanStatus.QUEUED]))
    )).scalar_one()
    scheduled = (await db.execute(
        select(func.count(ScheduledScan.id)).where(ScheduledScan.workspace_id == ws.id)
    )).scalar_one()
    members = (await db.execute(
        select(func.count(WorkspaceMember.id)).where(WorkspaceMember.workspace_id == ws.id)
    )).scalar_one()

    return {
        "plan": _enum(ws.plan),
        "assets": {"used": int(assets_used), "limit": ws.asset_limit},
        "running": {"used": int(running), "limit": ws.concurrent_scan_limit},
        "waiting": {"used": int(waiting), "limit": max(1, int(ws.concurrent_scan_limit or 2) * 5)},
        "scheduled": {"used": int(scheduled), "limit": ws.scheduled_scan_limit},
        "team": {"used": int(members), "limit": ws.team_member_limit},
    }


async def dashboard_analytics(request):
    from datetime import timedelta

    try:
        days = max(1, min(int(request.query_params.get("days") or 14), 90))
    except (TypeError, ValueError):
        days = 14

    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, request.query_params.get("workspace_id"))
        since = datetime.utcnow() - timedelta(days=days - 1)
        since = since.replace(hour=0, minute=0, second=0, microsecond=0)

        scans = (await db.execute(
            select(Scan).where(Scan.workspace_id == ws.id, Scan.created_at >= since)
        )).scalars().all()
        findings = (await db.execute(
            select(Finding).where(Finding.workspace_id == ws.id, Finding.created_at >= since)
        )).scalars().all()
        all_open = (await db.execute(
            select(func.count(Finding.id)).where(Finding.workspace_id == ws.id, Finding.status == FindingStatus.OPEN)
        )).scalar_one()

        day_keys = [(since + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days)]
        by_day = {key: {"date": key, "total": 0, "completed": 0, "failed": 0, "findings": 0} for key in day_keys}

        for scan in scans:
            key = scan.created_at.strftime("%Y-%m-%d") if scan.created_at else None
            bucket = by_day.get(key)
            if not bucket:
                continue
            bucket["total"] += 1
            status = _enum(scan.status)
            if status == "completed":
                bucket["completed"] += 1
            elif status == "failed":
                bucket["failed"] += 1

        for finding in findings:
            key = finding.created_at.strftime("%Y-%m-%d") if finding.created_at else None
            bucket = by_day.get(key)
            if bucket:
                bucket["findings"] += 1

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = _enum(finding.severity)
            if severity in severity_counts:
                severity_counts[severity] += 1

        type_counts: dict[str, int] = {}
        for scan in scans:
            key = _enum(scan.type)
            type_counts[key] = type_counts.get(key, 0) + 1

        top_assets = (await db.execute(
            select(Asset.target, func.count(Finding.id).label("n"))
            .join(Finding, Finding.asset_id == Asset.id)
            .where(Asset.workspace_id == ws.id, Finding.status == FindingStatus.OPEN)
            .group_by(Asset.target)
            .order_by(func.count(Finding.id).desc())
            .limit(5)
        )).all()

        usage = await _build_usage(db, ws)
        return JSONResponse({
            "days": days,
            "usage": usage,
            "open_findings": int(all_open),
            "scans_total": len(scans),
            "scans_by_day": [by_day[key] for key in day_keys],
            "findings_by_severity": severity_counts,
            "findings_total": len(findings),
            "scan_types": [{"type": k, "count": v} for k, v in sorted(type_counts.items(), key=lambda item: -item[1])],
            "top_assets": [{"target": target, "findings": int(n)} for target, n in top_assets],
        })



async def import_assets(request):
    data = await read_json(request)
    raw = data.get("targets")
    if raw is None:
        raw = []
    if isinstance(raw, str):
        raw = raw.replace(",", "\n").splitlines()
    if not isinstance(raw, list):
        return error("targets must be a list or newline separated text", 400)
    asset_type = _normalize_asset_type(data.get("type", "hostname"))
    cleaned: list[str] = []
    invalid: list[str] = []
    for item in raw:
        target = str(item or "").strip()
        if not target or target.startswith("#"):
            continue
        if " " in target or len(target) > 500:
            invalid.append(target[:120])
            continue
        if target not in cleaned:
            cleaned.append(target)
    if not cleaned:
        return error("No valid targets found", 400)

    created, skipped, over_limit = [], [], []
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, data.get("workspace_id"))
        used = (await db.execute(
            select(func.count(Asset.id)).where(Asset.workspace_id == ws.id, Asset.deleted_at.is_(None))
        )).scalar_one()
        existing = set((await db.execute(
            select(Asset.target).where(Asset.workspace_id == ws.id, Asset.deleted_at.is_(None))
        )).scalars().all())
        for target in cleaned:
            if target in existing:
                skipped.append(target)
                continue
            if ws.asset_limit is not None and used >= ws.asset_limit:
                over_limit.append(target)
                continue
            asset = Asset(
                workspace_id=ws.id,
                target=target,
                type=asset_type,
                risk_level=AssetRiskLevel.NONE,
            )
            db.add(asset)
            existing.add(target)
            used += 1
            created.append(target)
        await db.commit()
    return JSONResponse({
        "created": created,
        "skipped": skipped,
        "over_limit": over_limit,
        "invalid": invalid,
        "count": len(created),
    })


async def create_finding(request):
    data = await read_json(request)
    title = (data.get("title") or "").strip()
    if not title:
        return error("title is required", 400)
    severity_raw = str(data.get("severity") or "medium").lower()
    try:
        severity = FindingSeverity(severity_raw)
    except ValueError:
        return error("invalid severity", 400)
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, data.get("workspace_id"))
        asset = None
        if data.get("asset_id"):
            try:
                asset = await db.get(Asset, uuid.UUID(str(data["asset_id"])))
            except (ValueError, TypeError):
                asset = None
        if not asset and data.get("target"):
            target = str(data["target"]).strip()
            asset = (await db.execute(
                select(Asset).where(Asset.workspace_id == ws.id, Asset.target == target, Asset.deleted_at.is_(None))
            )).scalars().first()
            if not asset:
                asset = Asset(workspace_id=ws.id, target=target, type=_normalize_asset_type(data.get("asset_type", "hostname")), risk_level=AssetRiskLevel.NONE)
                db.add(asset)
                await db.flush()
        if not asset:
            return error("asset_id or target is required", 400)
        if asset.workspace_id != ws.id:
            return error("Asset not in workspace", 400)

        finding = Finding(
            workspace_id=ws.id,
            asset_id=asset.id,
            scan_id=None,
            title=title,
            description=(data.get("description") or "").strip() or "Reported manually",
            severity=severity,
            status=FindingStatus.OPEN,
            cwe_id=data.get("cwe_id"),
            cvss_score=float(data["cvss_score"]) if data.get("cvss_score") not in (None, "") else None,
            cvss_vector=data.get("cvss_vector"),
            target_url=data.get("target_url") or asset.target,
            parameter=data.get("parameter"),
            method=data.get("method"),
            evidence=data.get("evidence") if isinstance(data.get("evidence"), dict) else {},
            reproduction_steps=data.get("reproduction_steps"),
            remediation=data.get("remediation"),
            tags=data.get("tags") if isinstance(data.get("tags"), list) else [],
            source_scanner="manual",
        )
        db.add(finding)
        await db.commit()
        await db.refresh(finding)
        return JSONResponse(serialize_finding(finding), status_code=201)



async def get_finding_detail(request):
    finding_id = request.path_params["finding_id"]
    async with AsyncSessionLocal() as db:
        try:
            from sqlalchemy.orm import selectinload
            finding = (await db.execute(
                select(Finding)
                .options(selectinload(Finding.comments), selectinload(Finding.attachments))
                .where(Finding.id == uuid.UUID(finding_id))
            )).scalar_one_or_none()
        except (ValueError, TypeError):
            return error("invalid finding id")
        if not finding:
            return error("Finding not found", 404)
        ws = await resolve_workspace(db, request.headers.get("X-Workspace-ID"))
        if finding.workspace_id != ws.id:
            return error("Not found", 404)
        return JSONResponse(serialize_finding_detail(finding))


async def update_finding_extended(request):
    finding_id = request.path_params["finding_id"]
    data = await read_json(request)
    async with AsyncSessionLocal() as db:
        try:
            finding = await db.get(Finding, uuid.UUID(finding_id))
        except (ValueError, TypeError):
            return error("invalid finding id")
        if not finding:
            return error("Finding not found", 404)
        ws = await resolve_workspace(db, request.headers.get("X-Workspace-ID"))
        if finding.workspace_id != ws.id:
            return error("Not found", 404)
        
        # Updatable fields
        if "status" in data:
            try:
                finding.status = FindingStatus(data["status"])
            except ValueError:
                return error("invalid status", 400)
        if "severity" in data:
            try:
                finding.severity = FindingSeverity(data["severity"])
            except ValueError:
                return error("invalid severity", 400)
        if "assigned_to" in data and data["assigned_to"]:
            try:
                finding.assigned_to = uuid.UUID(data["assigned_to"])
            except (ValueError, TypeError):
                return error("invalid assigned_to", 400)
        if "tags" in data and isinstance(data["tags"], list):
            finding.tags = data["tags"]
        if "remediation" in data:
            finding.remediation = data["remediation"]
        if "cvss_score" in data and data["cvss_score"] not in (None, ""):
            finding.cvss_score = float(data["cvss_score"])
        if "cvss_vector" in data:
            finding.cvss_vector = data["cvss_vector"]
        if "evidence" in data and isinstance(data["evidence"], dict):
            finding.evidence = data["evidence"]
        if "reproduction_steps" in data:
            finding.reproduction_steps = data["reproduction_steps"]
        if "proof_of_concept" in data:
            finding.proof_of_concept = data["proof_of_concept"]
        if "references" in data and isinstance(data["references"], list):
            finding.references = data["references"]
        if "compliance_mappings" in data and isinstance(data["compliance_mappings"], dict):
            finding.compliance_mappings = data["compliance_mappings"]
        
        # Status transitions side effects
        if "status" in data:
            if data["status"] == "verified" and not finding.verified_by:
                finding.verified_by = (await get_current_user_id(request)) or None
                finding.verified_at = datetime.now(timezone.utc)
            elif data["status"] == "fixed" and not finding.fixed_at:
                finding.fixed_at = datetime.now(timezone.utc)
            elif data["status"] == "open":
                finding.verified_by = None
                finding.verified_at = None
                finding.fixed_at = None
        
        finding.updated_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(finding)
        return JSONResponse(serialize_finding_detail(finding))


async def upload_finding_attachment(request):
    """Upload an attachment for a finding."""
    finding_id = request.path_params["finding_id"]
    async with AsyncSessionLocal() as db:
        try:
            finding = await db.get(Finding, uuid.UUID(finding_id))
        except (ValueError, TypeError):
            return error("invalid finding id")
        if not finding:
            return error("Finding not found", 404)
        
        # Check workspace access
        ws = await resolve_workspace(db, request.headers.get("X-Workspace-ID"))
        if finding.workspace_id != ws.id:
            return error("Not found", 404)
        
        # Parse multipart form
        form = await request.form()
        file = form.get("file")
        if not file:
            return error("No file provided", 400)
        
        # Read file content
        content = await file.read()
        if not content:
            return error("Empty file", 400)
        
        # Create attachment
        from models.finding import FindingAttachment
        import hashlib
        
        attachment = FindingAttachment(
            finding_id=finding.id,
            filename=file.filename,
            file_size=len(content),
            mime_type=file.content_type or "application/octet-stream",
            uploaded_by=(await get_current_user_id(request)) or None,
            content_hash=hashlib.sha256(content).hexdigest(),
        )
        db.add(attachment)
        await db.commit()
        await db.refresh(attachment)
        
        # Save file to disk
        import os
        from core.config import settings
        upload_dir = os.path.join(settings.REPORTS_DIR, "attachments")
        os.makedirs(upload_dir, exist_ok=True)
        file_path = os.path.join(upload_dir, f"{attachment.id}_{file.filename}")
        with open(file_path, "wb") as f:
            f.write(content)
        
        return JSONResponse({
            "id": str(attachment.id),
            "filename": attachment.filename,
            "file_size": attachment.file_size,
            "mime_type": attachment.mime_type,
            "uploaded_at": attachment.uploaded_at.isoformat() if attachment.uploaded_at else None,
        }, status_code=201)


async def delete_finding_attachment(request):
    """Delete an attachment from a finding."""
    finding_id = request.path_params["finding_id"]
    attachment_id = request.path_params["attachment_id"]
    async with AsyncSessionLocal() as db:
        try:
            finding = await db.get(Finding, uuid.UUID(finding_id))
        except (ValueError, TypeError):
            return error("invalid finding id")
        if not finding:
            return error("Finding not found", 404)
        
        ws = await resolve_workspace(db, request.headers.get("X-Workspace-ID"))
        if finding.workspace_id != ws.id:
            return error("Not found", 404)
        
        from models.finding import FindingAttachment
        attachment = await db.get(FindingAttachment, uuid.UUID(attachment_id))
        if not attachment or attachment.finding_id != finding.id:
            return error("Attachment not found", 404)
        
        # Delete file from disk
        import os
        from core.config import settings
        upload_dir = os.path.join(settings.REPORTS_DIR, "attachments")
        file_path = os.path.join(upload_dir, f"{attachment.id}_{attachment.filename}")
        if os.path.exists(file_path):
            os.remove(file_path)
        
        await db.delete(attachment)
        await db.commit()
        return JSONResponse({"ok": True})


async def list_finding_comments(request):
    finding_id = request.path_params["finding_id"]
    async with AsyncSessionLocal() as db:
        try:
            finding = await db.get(Finding, uuid.UUID(finding_id))
        except (ValueError, TypeError):
            return error("invalid finding id")
        if not finding:
            return error("Finding not found", 404)
        ws = await resolve_workspace(db, request.headers.get("X-Workspace-ID"))
        if finding.workspace_id != ws.id:
            return error("Not found", 404)
        
        # Load comments
        await db.refresh(finding, ["comments"])
        comments = [
            {
                "id": str(c.id),
                "user_id": str(c.user_id),
                "content": c.content,
                "is_internal": c.is_internal,
                "created_at": _iso(c.created_at),
                "updated_at": _iso(c.updated_at),
            }
            for c in (finding.comments or [])
        ]
        return JSONResponse(comments)


async def add_finding_comment(request):
    finding_id = request.path_params["finding_id"]
    data = await read_json(request)
    content = (data.get("content") or "").strip()
    if not content:
        return error("content is required", 400)
    is_internal = data.get("is_internal", True)
    async with AsyncSessionLocal() as db:
        try:
            finding = await db.get(Finding, uuid.UUID(finding_id))
        except (ValueError, TypeError):
            return error("invalid finding id")
        if not finding:
            return error("Finding not found", 404)
        ws = await resolve_workspace(db, request.headers.get("X-Workspace-ID"))
        if finding.workspace_id != ws.id:
            return error("Not found", 404)
        
        user_id = await get_current_user_id(request)
        comment = FindingComment(
            finding_id=finding.id,
            user_id=user_id,
            content=content,
            is_internal=is_internal,
        )
        db.add(comment)
        await db.commit()
        await db.refresh(comment)
        return JSONResponse({
            "id": str(comment.id),
            "user_id": str(comment.user_id),
            "content": comment.content,
            "is_internal": comment.is_internal,
            "created_at": _iso(comment.created_at),
            "updated_at": _iso(comment.updated_at),
        }, status_code=201)


async def bulk_update_findings(request):
    data = await read_json(request)
    finding_ids = data.get("finding_ids") or []
    if not finding_ids:
        return error("finding_ids required", 400)
    updates = data.get("updates") or {}
    if not updates:
        return error("updates required", 400)
    
    async with AsyncSessionLocal() as db:
        ws = await resolve_workspace(db, request.headers.get("X-Workspace-ID"))
        try:
            uuids = [uuid.UUID(fid) for fid in finding_ids]
        except (ValueError, TypeError):
            return error("invalid finding ids", 400)
        
        findings = (await db.execute(
            select(Finding).where(Finding.id.in_(uuids), Finding.workspace_id == ws.id)
        )).scalars().all()
        
        if len(findings) != len(uuids):
            return error("Some findings not found", 404)
        
        user_id = await get_current_user_id(request)
        for finding in findings:

            if "status" in updates:
                try:
                    finding.status = FindingStatus(updates["status"])
                except ValueError:
                    return error("invalid status", 400)
                if updates["status"] == "verified" and not finding.verified_by:
                    finding.verified_by = user_id
                    finding.verified_at = datetime.now(timezone.utc)
                elif updates["status"] == "fixed" and not finding.fixed_at:
                    finding.fixed_at = datetime.now(timezone.utc)
                elif updates["status"] == "open":
                    finding.verified_by = None
                    finding.verified_at = None
                    finding.fixed_at = None
            if "severity" in updates:
                try:
                    finding.severity = FindingSeverity(updates["severity"])
                except ValueError:
                    return error("invalid severity", 400)
            if "assigned_to" in updates and updates["assigned_to"]:
                try:
                    finding.assigned_to = uuid.UUID(updates["assigned_to"])
                except (ValueError, TypeError):
                    return error("invalid assigned_to", 400)
            if "tags" in updates and isinstance(updates["tags"], list):
                finding.tags = updates["tags"]

        
        sys.stdout.flush()
        await db.commit()
        print(f"DEBUG after commit")
        sys.stdout.flush()
        # Re-query with relationships loaded for serialization
        await db.commit()
        print(f"DEBUG after commit")
        sys.stdout.flush()
        # Don't re-query with selectinload - just serialize without comments/attachments for bulk
        # serialize_finding_detail will show empty lists for unloaded relationships
        print(f"DEBUG serializing without re-query...")
        sys.stdout.flush()
        result = [serialize_finding_detail(f) for f in findings]
        print(f"DEBUG serialized: {len(result)}")
        sys.stdout.flush()
        return JSONResponse(result)


# ---------------------------------------------------------------------------
# Billing / Stripe endpoints
# ---------------------------------------------------------------------------


async def create_checkout_session(request):
    user_id = principal_user_id(request)
    workspace_id = principal_workspace_id(request)
    data = await read_json(request)
    plan_str = data.get("plan")
    if not plan_str:
        return error("Plan is required", 400)

    try:
        from models.workspace import PlanType
        plan = PlanType(plan_str)
    except ValueError:
        return error("Invalid plan", 400)

    async with AsyncSessionLocal() as db:
        workspace = await db.get(Workspace, workspace_id)
        if not workspace:
            return error("Workspace not found", 404)

        acting_role = await _membership_role(db, workspace_id, user_id)
        if acting_role != "owner":
            return error("Only workspace owner can manage billing", 403)

        # Create Stripe customer if needed
        user = await db.get(User, user_id)
        if not workspace.stripe_customer_id:
            customer_id = await BillingService.create_customer(db, workspace, user)
            if not customer_id:
                return error("Failed to create billing customer", 500)

        success_url = f"{settings.APP_URL}/settings?billing=success"
        cancel_url = f"{settings.APP_URL}/settings?billing=canceled"
        checkout_url = await BillingService.create_checkout_session(
            workspace, plan, success_url, cancel_url
        )
        if not checkout_url:
            return error("Failed to create checkout session", 500)

        return JSONResponse({"checkout_url": checkout_url})


async def create_portal_session(request):
    user_id = principal_user_id(request)
    workspace_id = principal_workspace_id(request)

    async with AsyncSessionLocal() as db:
        workspace = await db.get(Workspace, workspace_id)
        if not workspace:
            return error("Workspace not found", 404)

        acting_role = await _membership_role(db, workspace_id, user_id)
        if acting_role != "owner":
            return error("Only workspace owner can manage billing", 403)

        if not workspace.stripe_customer_id:
            return error("No billing account found", 404)

        return_url = f"{settings.APP_URL}/settings"
        portal_url = await BillingService.create_portal_session(workspace, return_url)
        if not portal_url:
            return error("Failed to create billing portal session", 500)

        return JSONResponse({"portal_url": portal_url})


async def stripe_webhook(request):
    """Handle Stripe webhook events."""
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    async with AsyncSessionLocal() as db:
        success = await BillingService.handle_webhook(db, payload, sig_header)

    if success:
        return JSONResponse({"received": True})
    else:
        return JSONResponse({"error": "Webhook handling failed"}, status_code=400)


async def get_subscription(request):
    user_id = principal_user_id(request)
    workspace_id = principal_workspace_id(request)

    async with AsyncSessionLocal() as db:
        workspace = await db.get(Workspace, workspace_id)
        if not workspace:
            return error("Workspace not found", 404)
        
        limits = BillingService.get_plan_limits(workspace.plan)
        return JSONResponse({
            "plan": workspace.plan,
            "subscription_status": workspace.subscription_status,
            "current_period_end": workspace.subscription_current_period_end.isoformat() if workspace.subscription_current_period_end else None,
            "limits": limits,
            "subscription": {
                "stripe_subscription_id": workspace.stripe_subscription_id,
                "stripe_customer_id": workspace.stripe_customer_id,
            },
        })# ---------------------------------------------------------------------------
# MFA / SSO endpoints
# ---------------------------------------------------------------------------




async def cancel_subscription(request):
    user_id = principal_user_id(request)
    workspace_id = principal_workspace_id(request)

    async with AsyncSessionLocal() as db:
        workspace = await db.get(Workspace, workspace_id)
        if not workspace:
            return error("Workspace not found", 404)

        acting_role = await _membership_role(db, workspace_id, user_id)
        if acting_role != "owner":
            return error("Only workspace owner can cancel subscription", 403)

        success = await BillingService.cancel_subscription(workspace)
        if not success:
            return error("Failed to cancel subscription", 500)

        return JSONResponse({"status": "canceled_at_period_end"})


async def resume_subscription(request):
    user_id = principal_user_id(request)
    workspace_id = principal_workspace_id(request)

    async with AsyncSessionLocal() as db:
        workspace = await db.get(Workspace, workspace_id)
        if not workspace:
            return error("Workspace not found", 404)

        acting_role = await _membership_role(db, workspace_id, user_id)
        if acting_role != "owner":
            return error("Only workspace owner can resume subscription", 403)

        success = await BillingService.resume_subscription(workspace)
        if not success:
            return error("Failed to resume subscription", 500)

        return JSONResponse({"status": "resumed"})


async def get_mfa_status(request):
    user_id = principal_user_id(request)
    async with AsyncSessionLocal() as db:
        user = await db.get(User, user_id)
        if not user:
            return error("User not found", 404)
        status = await MFAService.get_mfa_status(db, user)
        return JSONResponse(status)


async def setup_totp(request):
    user_id = principal_user_id(request)
    async with AsyncSessionLocal() as db:
        user = await db.get(User, user_id)
        if not user:
            return error("User not found", 404)
        result = await MFAService.setup_totp(db, user)
        return JSONResponse(result)


async def enable_totp(request):
    user_id = principal_user_id(request)
    data = await read_json(request)
    token = data.get("token")
    if not token:
        return error("Token required", 400)
    async with AsyncSessionLocal() as db:
        user = await db.get(User, user_id)
        if not user:
            return error("User not found", 404)
        success = await MFAService.enable_totp(db, user, token)
        if not success:
            return error("Invalid token", 400)
        return JSONResponse({"enabled": True})


async def disable_totp(request):
    user_id = principal_user_id(request)
    async with AsyncSessionLocal() as db:
        user = await db.get(User, user_id)
        if not user:
            return error("User not found", 404)
        success = await MFAService.disable_totp(db, user)
        return JSONResponse({"disabled": success})


async def verify_totp(request):
    user_id = principal_user_id(request)
    data = await read_json(request)
    token = data.get("token")
    if not token:
        return error("Token required", 400)
    async with AsyncSessionLocal() as db:
        user = await db.get(User, user_id)
        if not user:
            return error("User not found", 404)
        valid = await MFAService.verify_totp_token(db, user, token)
        return JSONResponse({"valid": valid})


async def generate_recovery_codes(request):
    user_id = principal_user_id(request)
    async with AsyncSessionLocal() as db:
        user = await db.get(User, user_id)
        if not user:
            return error("User not found", 404)
        codes = await MFAService.generate_recovery_codes(db, user)
        return JSONResponse({"codes": codes})


async def verify_recovery_code(request):
    user_id = principal_user_id(request)
    data = await read_json(request)
    code = data.get("code")
    if not code:
        return error("Code required", 400)
    async with AsyncSessionLocal() as db:
        user = await db.get(User, user_id)
        if not user:
            return error("User not found", 404)
        valid = await MFAService.verify_recovery_code(db, user, code)
        return JSONResponse({"valid": valid})





# ---------------------------------------------------------------------------
# MFA / SSO endpoints
# ---------------------------------------------------------------------------


async def get_mfa_status(request):
    user_id = principal_user_id(request)
    async with AsyncSessionLocal() as db:
        user = await db.get(User, user_id)
        if not user:
            return error("User not found", 404)
        status = await MFAService.get_mfa_status(db, user)
        return JSONResponse(status)


async def setup_totp(request):
    user_id = principal_user_id(request)
    async with AsyncSessionLocal() as db:
        user = await db.get(User, user_id)
        if not user:
            return error("User not found", 404)
        result = await MFAService.setup_totp(db, user)
        return JSONResponse(result)


async def enable_totp(request):
    user_id = principal_user_id(request)
    data = await read_json(request)
    token = data.get("token")
    if not token:
        return error("Token required", 400)
    async with AsyncSessionLocal() as db:
        user = await db.get(User, user_id)
        if not user:
            return error("User not found", 404)
        success = await MFAService.enable_totp(db, user, token)
        if not success:
            return error("Invalid token", 400)
        return JSONResponse({"enabled": True})


async def disable_totp(request):
    user_id = principal_user_id(request)
    async with AsyncSessionLocal() as db:
        user = await db.get(User, user_id)
        if not user:
            return error("User not found", 404)
        success = await MFAService.disable_totp(db, user)
        return JSONResponse({"disabled": success})


async def verify_totp(request):
    user_id = principal_user_id(request)
    data = await read_json(request)
    token = data.get("token")
    if not token:
        return error("Token required", 400)
    async with AsyncSessionLocal() as db:
        user = await db.get(User, user_id)
        if not user:
            return error("User not found", 404)
        valid = await MFAService.verify_totp_token(db, user, token)
        return JSONResponse({"valid": valid})


async def generate_recovery_codes(request):
    user_id = principal_user_id(request)
    async with AsyncSessionLocal() as db:
        user = await db.get(User, user_id)
        if not user:
            return error("User not found", 404)
        codes = await MFAService.generate_recovery_codes(db, user)
        return JSONResponse({"codes": codes})


async def verify_recovery_code(request):
    user_id = principal_user_id(request)
    data = await read_json(request)
    code = data.get("code")
    if not code:
        return error("Code required", 400)
    async with AsyncSessionLocal() as db:
        user = await db.get(User, user_id)
        if not user:
            return error("User not found", 404)
        valid = await MFAService.verify_recovery_code(db, user, code)
        return JSONResponse({"valid": valid})


# SSO endpoints
async def saml_metadata(request):
    """Return SAML metadata XML."""
    if not SSOService.is_saml_configured():
        return error("SAML not configured", 404)
    metadata = SSOService.get_saml_metadata()
    return Response(content=metadata, media_type="application/xml")


async def saml_acs(request):
    """SAML Assertion Consumer Service endpoint."""
    if not SSOService.is_saml_configured():
        return error("SAML not configured", 404)
    return error("SAML ACS not fully implemented", 501)


async def oidc_config(request):
    """Return OIDC configuration."""
    if not SSOService.is_oidc_configured():
        return error("OIDC not configured", 404)
    config = SSOService.get_oidc_config()
    return JSONResponse(config)


async def oidc_callback(request):
    """OIDC callback endpoint."""
    if not SSOService.is_oidc_configured():
        return error("OIDC not configured", 404)
    return error("OIDC callback not fully implemented", 501)





# Prometheus metrics endpoint
async def metrics_endpoint(request):
    """Prometheus metrics endpoint."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )



# Observability helpers
async def update_scan_metrics():
    """Update scan-related metrics from database."""
    async with AsyncSessionLocal() as db:
        from models.scan import Scan, ScanStatus
        from models.finding import Finding, FindingSeverity
        from sqlalchemy import select, func
        
        # Active scans
        active = (await db.execute(
            select(func.count(Scan.id)).where(Scan.status == ScanStatus.RUNNING)
        )).scalar_one()
        ACTIVE_SCANS.set(active)
        
        # Findings by severity
        for severity in FindingSeverity:
            count = (await db.execute(
                select(func.count(Finding.id)).where(Finding.severity == severity)
            )).scalar_one()
            TOTAL_FINDINGS.labels(severity=severity.value).set(count)

def record_celery_task(task_name: str, status: str):
    """Record Celery task metric."""
    CELERY_TASKS.labels(task_name=task_name, status=status).inc()



# Authenticated scan endpoint
async def create_authenticated_scan(request):
    """Create and run an authenticated scan."""
    user_id = principal_user_id(request)
    workspace_id = principal_workspace_id(request)
    data = await read_json(request)
    
    target = data.get("target")
    auth_config = data.get("auth_config", {})
    scan_config = data.get("scan_config", {})
    
    if not target:
        return error("Target is required", 400)
    if not auth_config:
        return error("Auth config is required", 400)
        
    async with AsyncSessionLocal() as db:
        workspace = await db.get(Workspace, workspace_id)
        if not workspace:
            return error("Workspace not found", 404)
            
        acting_role = await _membership_role(db, workspace_id, user_id)
        if acting_role not in ("owner", "admin", "member"):
            return error("Insufficient permissions", 403)
            
        # Create scan record
        from models.scan import Scan, ScanStatus, ScanType, ScanIntensity
        from uuid import uuid4
        scan = Scan(
            workspace_id=workspace_id,
            name=data.get("name", f"Authenticated scan of {target}"),
            type=ScanType.WEBSITE,
            target=target,
            intensity=ScanIntensity.NORMAL,
            status=ScanStatus.PENDING,
            progress=0.0,
            scanner_config={
                "auth_config": auth_config,
                "scan_config": scan_config,
            },
        )
        db.add(scan)
        await db.flush()
        
        # Queue authenticated scan task
        from services.authenticated_scanner import run_authenticated_scan
        async_result = run_authenticated_scan.delay(
            str(scan.id), target, auth_config, scan_config
        )
        scan.celery_task_id = async_result.id
        scan.status = ScanStatus.QUEUED
        await db.commit()
        
        return JSONResponse({
            "scan_id": str(scan.id),
            "status": "queued",
            "celery_task_id": async_result.id,
        }, status_code=201)

routes = [
    Route("/api/health", health, methods=["GET"]),
    Route("/api/openapi.json", openapi_schema, methods=["GET"]),
    Route("/metrics", metrics_endpoint, methods=["GET"]),
    Route("/api/auth/register", register, methods=["POST"]),
    Route("/api/auth/login", login, methods=["POST"]),
    Route("/api/auth/refresh", refresh, methods=["POST"]),
    Route("/api/auth/logout", logout, methods=["POST"]),
    Route("/api/auth/me", me, methods=["GET"]),
    Route("/api/auth/sessions", list_sessions, methods=["GET"]),
    Route("/api/auth/sessions/{session_id}", revoke_session, methods=["DELETE"]),
    Route("/api/auth/sessions/revoke-all", revoke_all_sessions, methods=["POST"]),
    Route("/api/auth/change-password", change_password, methods=["POST"]),
    Route("/api/auth/password-reset", request_password_reset, methods=["POST"]),
    Route("/api/auth/password-reset/confirm", confirm_password_reset, methods=["POST"]),
    Route("/api/auth/email-verification/send", resend_email_verification, methods=["POST"]),
    Route("/api/auth/email-verification/verify", verify_email, methods=["GET"]),
    # User settings
    Route("/api/user/profile", get_user_profile, methods=["GET"]),
    Route("/api/user/profile", update_user_profile, methods=["PATCH"]),
    Route("/api/user/notifications", get_notification_settings, methods=["GET"]),
    Route("/api/user/notifications", update_notification_settings, methods=["PATCH"]),
    Route("/api/user/appearance", get_appearance_settings, methods=["GET"]),
    Route("/api/user/appearance", update_appearance_settings, methods=["PATCH"]),
    Route("/api/bootstrap", bootstrap, methods=["GET"]),
    Route("/api/workspace", get_workspace, methods=["GET"]),
    Route("/api/workspaces", list_workspaces, methods=["GET"]),
    Route("/api/team/members", list_team_members, methods=["GET"]),
    Route("/api/team/invites", invite_team_member, methods=["POST"]),
    Route("/api/team/invites/{invite_id}", cancel_team_invite, methods=["DELETE"]),
    Route("/api/team/invite/accept", accept_team_invite, methods=["POST"]),
    Route("/api/team/members/{user_id}", update_team_member, methods=["PATCH"]),
    Route("/api/team/members/{user_id}", remove_team_member, methods=["DELETE"]),
    Route("/api/api-keys", list_api_keys, methods=["GET"]),
    Route("/api/api-keys", create_api_key, methods=["POST"]),
    Route("/api/api-keys/{key_id}", revoke_api_key, methods=["DELETE"]),
    Route("/api/assets", list_assets, methods=["GET"]),
    Route("/api/assets/{asset_id}", get_asset, methods=["GET"]),
    Route("/api/assets", create_asset, methods=["POST"]),
    Route("/api/assets/import", import_assets, methods=["POST"]),
    Route("/api/assets/{asset_id}", delete_asset, methods=["DELETE"]),
    Route("/api/scans", list_scans, methods=["GET"]),
    Route("/api/scans", create_scan, methods=["POST"]),
    Route("/api/scans/{scan_id}", get_scan, methods=["GET"]),
    Route("/api/scans/{scan_id}", delete_scan, methods=["DELETE"]),
    Route("/api/scans/{scan_id}/retry", retry_scan, methods=["POST"]),
    Route("/api/scans/{scan_id}/findings", scan_findings, methods=["GET"]),
    Route("/api/scans/{scan_id}/logs", scan_logs, methods=["GET"]),
    Route("/api/findings", list_findings, methods=["GET"]),
    Route("/api/findings", create_finding, methods=["POST"]),
    Route("/api/findings/bulk", bulk_update_findings, methods=["POST"]),
    Route("/api/findings/{finding_id}", update_finding, methods=["PATCH"]),
    Route("/api/findings/{finding_id}/detail", get_finding_detail, methods=["GET"]),
    Route("/api/findings/{finding_id}", update_finding_extended, methods=["PATCH"]),
    Route("/api/findings/{finding_id}/comments", list_finding_comments, methods=["GET"]),
    Route("/api/findings/{finding_id}/comments", add_finding_comment, methods=["POST"]),
    Route("/api/findings/{finding_id}/attachments", upload_finding_attachment, methods=["POST"]),
    Route("/api/findings/{finding_id}/attachments/{attachment_id}", delete_finding_attachment, methods=["DELETE"]),
    Route("/api/integrations", list_integrations, methods=["GET"]),
    Route("/api/integrations/{int_id}", configure_integration, methods=["POST"]),
    Route("/api/integrations/{int_id}/toggle", toggle_integration, methods=["PATCH"]),
    Route("/api/scheduled-scans", list_scheduled_scans, methods=["GET"]),
    Route("/api/scheduled-scans", create_scheduled_scan, methods=["POST"]),
    Route("/api/scheduled-scans/{schedule_id}", get_scheduled_scan, methods=["GET"]),
    Route("/api/scheduled-scans/{schedule_id}", update_scheduled_scan, methods=["PATCH"]),
    Route("/api/scheduled-scans/{schedule_id}", delete_scheduled_scan, methods=["DELETE"]),
    Route("/api/scheduled-scans/{schedule_id}/trigger", trigger_scheduled_scan, methods=["POST"]),
    Route("/api/scan-templates", list_scan_templates, methods=["GET"]),
    Route("/api/scan-templates", create_scan_template, methods=["POST"]),
    Route("/api/scan-templates/{template_id}", get_scan_template, methods=["GET"]),
    Route("/api/scan-templates/{template_id}", update_scan_template, methods=["PATCH"]),
    Route("/api/scan-templates/{template_id}", delete_scan_template, methods=["DELETE"]),
    Route("/api/scan-templates/{template_id}/use", use_scan_template, methods=["POST"]),
    Route("/api/reports", list_reports, methods=["GET"]),
    Route("/api/reports", create_report, methods=["POST"]),
    Route("/api/reports/{report_id}", get_report, methods=["GET"]),
    Route("/api/reports/{report_id}/download", download_report, methods=["GET"]),
    Route("/api/reports/{report_id}", delete_report, methods=["DELETE"]),
    Route("/api/report-templates", list_report_templates, methods=["GET"]),
    Route("/api/report-templates", create_report_template, methods=["POST"]),
    Route("/api/report-templates/{template_id}", get_report_template, methods=["GET"]),
    Route("/api/report-templates/{template_id}", update_report_template, methods=["PATCH"]),
    Route("/api/report-templates/{template_id}", delete_report_template, methods=["DELETE"]),
    Route("/api/diff/compare", compare_scans, methods=["POST"]),
    Route("/api/diff/latest", compare_latest_scans, methods=["GET"]),
    Route("/api/diff/workspace", workspace_diff, methods=["GET"]),
    Route("/api/diff/alerts", diff_alerts, methods=["GET"]),
    Route("/api/diff/run", run_diff_check_endpoint, methods=["POST"]),
    Route("/api/robots", list_robots, methods=["GET"]),
    Route("/api/robots", create_robot, methods=["POST"]),
    Route("/api/robots/runs", list_robot_runs, methods=["GET"]),
    Route("/api/robots/runs/{run_id}", get_robot_run, methods=["GET"]),
    Route("/api/robots/{robot_id}", get_robot, methods=["GET"]),
    Route("/api/robots/{robot_id}", update_robot, methods=["PATCH"]),
    Route("/api/robots/{robot_id}", delete_robot, methods=["DELETE"]),
    Route("/api/robots/{robot_id}/run", run_robot, methods=["POST"]),
    Route("/api/dashboard/analytics", dashboard_analytics, methods=["GET"]),
    Route("/api/workspace/usage", workspace_usage, methods=["GET"]),
    Route("/api/attack-surface", attack_surface, methods=["GET"]),
    Route("/api/attack-surface/stats", attack_surface_stats, methods=["GET"]),
    Route("/api/scans/authenticated", create_authenticated_scan, methods=["POST"]),
    # Billing / Stripe
    Route("/api/billing/checkout", create_checkout_session, methods=["POST"]),
    Route("/api/billing/portal", create_portal_session, methods=["POST"]),
    Route("/api/billing/webhook", stripe_webhook, methods=["POST"]),
    Route("/api/billing/subscription", get_subscription, methods=["GET"]),
    Route("/api/billing/subscription/cancel", cancel_subscription, methods=["POST"]),
    Route("/api/billing/subscription/resume", resume_subscription, methods=["POST"]),
    # MFA / SSO
    Route("/api/mfa/status", get_mfa_status, methods=["GET"]),
    Route("/api/mfa/totp/setup", setup_totp, methods=["POST"]),
    Route("/api/mfa/totp/enable", enable_totp, methods=["POST"]),
    Route("/api/mfa/totp/disable", disable_totp, methods=["POST"]),
    Route("/api/mfa/totp/verify", verify_totp, methods=["POST"]),
    Route("/api/mfa/recovery-codes", generate_recovery_codes, methods=["POST"]),
    Route("/api/mfa/recovery-codes/verify", verify_recovery_code, methods=["POST"]),
    # SSO
    Route("/api/sso/saml/metadata", saml_metadata, methods=["GET"]),
    Route("/api/sso/saml/acs", saml_acs, methods=["POST"]),
    Route("/api/sso/oidc/config", oidc_config, methods=["GET"]),
    Route("/api/sso/oidc/callback", oidc_callback, methods=["GET", "POST"]),
]



@contextlib.asynccontextmanager
async def lifespan(app):
    global _broadcast_task, _finding_cursor, _asset_cursor
    async with AsyncSessionLocal() as db:
        await default_workspace(db)
        latest = (await db.execute(select(func.max(Finding.created_at)))).scalar_one_or_none()
        _finding_cursor = latest or datetime.utcnow()
        latest_asset = (await db.execute(select(func.max(Asset.updated_at)))).scalar_one_or_none()
        _asset_cursor = latest_asset or datetime.utcnow()
    _broadcast_task = asyncio.create_task(_broadcast_loop())
    try:
        yield
    finally:
        if _broadcast_task:
            _broadcast_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await _broadcast_task
        await close_db()



# Prometheus metrics middleware

api = Starlette(debug=settings.DEBUG, routes=routes, lifespan=lifespan)
api.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
api.add_middleware(
    RateLimitMiddleware,
    default_limit=100,
    default_window=60,
    auth_limit=30,
    auth_window=60,
)
api.add_middleware(AuthEnforcementMiddleware)

@api.middleware("http")
async def metrics_middleware(request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    
    # Record metrics
    HTTP_REQUESTS_TOTAL.labels(
        method=request.method,
        endpoint=request.url.path,
        status=response.status_code
    ).inc()
    HTTP_REQUEST_DURATION.labels(
        method=request.method,
        endpoint=request.url.path
    ).observe(duration)
    
    return response



# Socket.IO handles /socket.io/*; everything else goes to the Starlette app.
app = socketio.ASGIApp(sio, other_asgi_app=api, socketio_path="socket.io")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
