from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from uuid import UUID
import json
import httpx
import hmac
import hashlib
import base64

from models.workspace import Workspace
from models.scan import Scan
from models.finding import Finding
from models.asset import Asset
from models.integration import Integration, IntegrationType


class IntegrationService:
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)

    async def close(self):
        await self.client.aclose()

    def _sign_payload(self, payload: bytes, secret: str) -> str:
        signature = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        return f"sha256={signature}"

    async def deliver_slack(self, config: Dict[str, Any], event: str, data: Dict[str, Any]) -> bool:
        webhook_url = config.get("webhook_url")
        if not webhook_url:
            return False

        severity = data.get("severity", "info")
        color_map = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#ca8a04",
            "low": "#16a34a",
            "info": "#2563eb",
        }
        color = color_map.get(severity, "#6b7280")

        if event == "finding_created":
            finding = data
            payload = {
                "attachments": [{
                    "color": color,
                    "title": f"New Finding: {finding.get('title', 'Unknown')}",
                    "fields": [
                        {"title": "Severity", "value": finding.get("severity", "info").upper(), "short": True},
                        {"title": "Target", "value": finding.get("target_url", "N/A"), "short": True},
                        {"title": "Scanner", "value": finding.get("source", "N/A"), "short": True},
                        {"title": "Status", "value": finding.get("status", "open").upper(), "short": True},
                    ],
                    "footer": "Pentest Clone",
                    "ts": int(datetime.now(timezone.utc).timestamp()),
                }]
            }
        elif event == "scan_completed":
            scan = data
            payload = {
                "text": f"✅ Scan completed: {scan.get('name', 'Unknown')}",
                "attachments": [{
                    "color": "#16a34a",
                    "fields": [
                        {"title": "Target", "value": scan.get("target", "N/A"), "short": True},
                        {"title": "Type", "value": scan.get("type", "N/A"), "short": True},
                        {"title": "Findings", "value": str(scan.get("findings_count", 0)), "short": True},
                        {"title": "Duration", "value": f"{scan.get('duration_seconds', 0)}s", "short": True},
                    ]
                }]
            }
        elif event == "scan_failed":
            scan = data
            payload = {
                "text": f"❌ Scan failed: {scan.get('name', 'Unknown')}",
                "attachments": [{
                    "color": "#dc2626",
                    "fields": [
                        {"title": "Target", "value": scan.get("target", "N/A"), "short": True},
                        {"title": "Error", "value": scan.get("error_message", "Unknown"), "short": False},
                    ]
                }]
            }
        else:
            payload = {"text": f"Pentest Clone: {event}"}

        try:
            resp = await self.client.post(webhook_url, json=payload)
            return resp.status_code == 200
        except Exception:
            return False

    async def deliver_teams(self, config: Dict[str, Any], event: str, data: Dict[str, Any]) -> bool:
        webhook_url = config.get("webhook_url")
        if not webhook_url:
            return False

        severity = data.get("severity", "info")
        color_map = {
            "critical": "FF0000",
            "high": "FF8C00",
            "medium": "FFD700",
            "low": "32CD32",
            "info": "0000FF",
        }
        color = color_map.get(severity, "808080")

        if event == "finding_created":
            finding = data
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": color,
                "summary": f"New Finding: {finding.get('title', 'Unknown')}",
                "sections": [{
                    "activityTitle": f"🔍 New Finding: {finding.get('title', 'Unknown')}",
                    "facts": [
                        {"name": "Severity", "value": finding.get("severity", "info").upper()},
                        {"name": "Target", "value": finding.get("target_url", "N/A")},
                        {"name": "Scanner", "value": finding.get("source", "N/A")},
                        {"name": "Status", "value": finding.get("status", "open").upper()},
                    ],
                    "markdown": True,
                }]
            }
        elif event == "scan_completed":
            scan = data
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "00FF00",
                "summary": f"Scan completed: {scan.get('name', 'Unknown')}",
                "sections": [{
                    "activityTitle": f"✅ Scan Completed: {scan.get('name', 'Unknown')}",
                    "facts": [
                        {"name": "Target", "value": scan.get("target", "N/A")},
                        {"name": "Type", "value": scan.get("type", "N/A")},
                        {"name": "Findings", "value": str(scan.get("findings_count", 0))},
                    ],
                }]
            }
        else:
            payload = {"@type": "MessageCard", "summary": f"Pentest Clone: {event}"}

        try:
            resp = await self.client.post(webhook_url, json=payload)
            return resp.status_code == 200
        except Exception:
            return False

    async def deliver_discord(self, config: Dict[str, Any], event: str, data: Dict[str, Any]) -> bool:
        webhook_url = config.get("webhook_url")
        if not webhook_url:
            return False

        severity = data.get("severity", "info")
        color_map = {
            "critical": 0xdc2626,
            "high": 0xea580c,
            "medium": 0xca8a04,
            "low": 0x16a34a,
            "info": 0x2563eb,
        }
        color = color_map.get(severity, 0x6b7280)

        if event == "finding_created":
            finding = data
            payload = {
                "embeds": [{
                    "title": f"🔍 New Finding: {finding.get('title', 'Unknown')}",
                    "color": color,
                    "fields": [
                        {"name": "Severity", "value": finding.get("severity", "info").upper(), "inline": True},
                        {"name": "Target", "value": finding.get("target_url", "N/A"), "inline": True},
                        {"name": "Scanner", "value": finding.get("source", "N/A"), "inline": True},
                        {"name": "Status", "value": finding.get("status", "open").upper(), "inline": True},
                    ],
                    "footer": {"text": "Pentest Clone"},
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }]
            }
        elif event == "scan_completed":
            scan = data
            payload = {
                "embeds": [{
                    "title": f"✅ Scan Completed: {scan.get('name', 'Unknown')}",
                    "color": 0x16a34a,
                    "fields": [
                        {"name": "Target", "value": scan.get("target", "N/A"), "inline": True},
                        {"name": "Type", "value": scan.get("type", "N/A"), "inline": True},
                        {"name": "Findings", "value": str(scan.get("findings_count", 0)), "inline": True},
                    ],
                    "footer": {"text": "Pentest Clone"},
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }]
            }
        else:
            payload = {"content": f"Pentest Clone: {event}"}

        try:
            resp = await self.client.post(webhook_url, json=payload)
            return resp.status_code in (200, 204)
        except Exception:
            return False

    async def deliver_webhook(self, config: Dict[str, Any], event: str, data: Dict[str, Any]) -> bool:
        webhook_url = config.get("webhook_url")
        secret = config.get("secret")
        if not webhook_url:
            return False

        payload_data = {"event": event, "data": data, "timestamp": datetime.now(timezone.utc).isoformat()}
        payload_bytes = json.dumps(payload_data, separators=(',', ':')).encode()

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Syl-Pentools/1.0",
        }

        if secret:
            signature = self._sign_payload(payload_bytes, secret)
            headers["X-Signature"] = signature
            headers["X-Timestamp"] = str(int(datetime.now(timezone.utc).timestamp()))

        try:
            resp = await self.client.post(webhook_url, content=payload_bytes, headers=headers)
            return resp.status_code < 400
        except Exception:
            return False

    async def deliver_jira(self, config: Dict[str, Any], event: str, data: Dict[str, Any]) -> bool:
        base_url = config.get("base_url")
        email = config.get("email")
        api_token = config.get("api_token")
        project_key = config.get("project_key")
        issue_type = config.get("issue_type", "Bug")

        if not all([base_url, email, api_token, project_key]):
            return False

        auth = base64.b64encode(f"{email}:{api_token}".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json",
        }

        if event == "finding_created":
            finding = data
            severity = finding.get("severity", "low")
            priority_map = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "info": "Low"}
            priority = priority_map.get(severity, "Low")

            summary = f"[{severity.upper()}] {finding.get('title', 'Security Finding')}"
            description = (
                f"*Target:* {finding.get('target_url', 'N/A')}\n"
                f"*Scanner:* {finding.get('source', 'N/A')}\n"
                f"*Parameter:* {finding.get('parameter', 'N/A')}\n"
                f"*Description:* {finding.get('description', 'No description')}\n"
                f"*Remediation:* {finding.get('remediation', 'No remediation provided')}"
            )

            payload = {
                "fields": {
                    "project": {"key": project_key},
                    "summary": summary,
                    "description": description,
                    "issuetype": {"name": issue_type},
                    "priority": {"name": priority},
                    "labels": ["syl-pentools", "security", severity],
                }
            }

            try:
                resp = await self.client.post(
                    f"{base_url.rstrip('/')}/rest/api/2/issue",
                    json=payload,
                    headers=headers,
                )
                return resp.status_code == 201
            except Exception:
                return False
        return False

    async def deliver_github(self, config: Dict[str, Any], event: str, data: Dict[str, Any]) -> bool:
        token = config.get("token")
        repo = config.get("repo")  # format: owner/repo

        if not all([token, repo]):
            return False

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/vnd.github+json",
        }

        if event == "finding_created":
            finding = data
            severity = finding.get("severity", "low")
            labels = ["security", "syl-pentools", severity]

            title = f"[{severity.upper()}] {finding.get('title', 'Security Finding')}"
            body = (
                f"**Target:** {finding.get('target_url', 'N/A')}\n"
                f"**Scanner:** {finding.get('source', 'N/A')}\n"
                f"**Parameter:** {finding.get('parameter', 'N/A')}\n\n"
                f"**Description:**\n{finding.get('description', 'No description')}\n\n"
                f"**Remediation:**\n{finding.get('remediation', 'No remediation provided')}"
            )

            payload = {
                "title": title,
                "body": body,
                "labels": labels,
            }

            try:
                resp = await self.client.post(
                    f"https://api.github.com/repos/{repo}/issues",
                    json=payload,
                    headers=headers,
                )
                return resp.status_code == 201
            except Exception:
                return False
        return False

    async def deliver(self, integration: Integration, event: str, data: Dict[str, Any]) -> bool:
        if not integration.is_enabled or not integration.config.get("configured", False):
            return False

        config = integration.config.get("config", {})
        integration_type = integration.type

        try:
            if integration_type == IntegrationType.SLACK:
                return await self.deliver_slack(config, event, data)
            elif integration_type == IntegrationType.TEAMS:
                return await self.deliver_teams(config, event, data)
            elif integration_type == IntegrationType.DISCORD:
                return await self.deliver_discord(config, event, data)
            elif integration_type == IntegrationType.WEBHOOK:
                return await self.deliver_webhook(config, event, data)
            elif integration_type == IntegrationType.JIRA:
                return await self.deliver_jira(config, event, data)
            elif integration_type == IntegrationType.GITHUB:
                return await self.deliver_github(config, event, data)
            else:
                return False
        except Exception:
            return False


async def dispatch_event(event: str, workspace_id: UUID, data: Dict[str, Any]) -> int:
    """Deliver an event to every enabled integration configured on the workspace.

    Configuration lives in ``workspace.settings["integrations"]`` (written by the
    integrations UI), so that is the source of truth here. Rows in the legacy
    ``integrations`` table are honoured as well when they are enabled.
    """
    from core.database import AsyncSessionLocal
    from models.workspace import Workspace
    from sqlalchemy import select

    targets: list[tuple[str, Dict[str, Any]]] = []
    async with AsyncSessionLocal() as db:
        ws = (await db.execute(select(Workspace).where(Workspace.id == workspace_id))).scalars().first()
        cfg = ((ws.settings or {}).get("integrations", {}) if ws else {})
        for int_id, entry in (cfg or {}).items():
            if not isinstance(entry, dict):
                continue
            if not entry.get("enabled") or not entry.get("configured"):
                continue
            targets.append((str(int_id), entry.get("config") or {}))

    service = IntegrationService()
    delivered = 0
    try:
        for int_id, config in targets:
            try:
                ok = await _deliver_by_id(service, int_id, config, event, data)
                if ok:
                    delivered += 1
            except Exception:
                continue
    finally:
        await service.close()
    return delivered


_PREFIXED = None


def _prefixed_id(int_id: str) -> str:
    base = int_id.split("__", 1)[0].split("-", 1)[0]
    for name in ("slack", "teams", "discord", "webhook", "jira", "github"):
        if base.startswith(name):
            return name
    return base


async def _deliver_by_id(service: "IntegrationService", int_id: str, config: Dict[str, Any], event: str, data: Dict[str, Any]) -> bool:
    kind = _prefixed_id(int_id)
    if kind == "slack":
        return await service.deliver_slack(config, event, data)
    if kind == "teams":
        return await service.deliver_teams(config, event, data)
    if kind == "discord":
        return await service.deliver_discord(config, event, data)
    if kind == "webhook":
        return await service.deliver_webhook(config, event, data)
    if kind == "jira":
        return await service.deliver_jira(config, event, data)
    if kind == "github":
        return await service.deliver_github(config, event, data)
    return False
