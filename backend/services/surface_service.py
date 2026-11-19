"""Attack surface aggregation from assets, scan evidence and findings.

Builds the flat discovery table used by the Attack Surface view
(IP / hostname / OS / port / protocol / service / URL / technology / vulns).
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.asset import Asset
from models.finding import Finding, FindingSeverity
from models.scan import Scan, ScanStatus


SEVERITY_KEYS = ("critical", "high", "medium", "low", "info")

# whatweb plugin keys that describe metadata rather than a technology
_TECH_NOISE = {"country", "ip", "title", "script", "allow", "uncommonheaders",
               "meta-refresh-redirect", "redirectlocation", "cookies", "email"}


def _clean_target(value: Optional[str]) -> Optional[str]:
    """Normalize a target into a hostname/IP, dropping schemes and paths."""
    if not value:
        return None
    target = value.strip()
    for prefix in ("https://", "http://"):
        if target.startswith(prefix):
            target = target[len(prefix):]
    target = target.split("/")[0].strip()
    if not target or target.startswith("/") or "/" in target:
        return None
    if target.count(":") == 1 and not target.startswith("["):
        target = target.split(":")[0]
    return target or None


def _host_from_url(url: Optional[str]) -> Optional[str]:
    return _clean_target(url)


class AttackSurfaceService:
    """Aggregate the workspace attack surface into host rows."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def _load(self, workspace_id: UUID):
        assets = (
            await self.db.execute(
                select(Asset).where(
                    Asset.workspace_id == workspace_id,
                    Asset.deleted_at.is_(None),
                )
            )
        ).scalars().all()

        findings = (
            await self.db.execute(
                select(Finding).where(Finding.workspace_id == workspace_id)
            )
        ).scalars().all()

        last_scan = (
            await self.db.execute(
                select(Scan.completed_at)
                .where(
                    Scan.workspace_id == workspace_id,
                    Scan.status == ScanStatus.COMPLETED,
                )
                .order_by(Scan.completed_at.desc())
                .limit(1)
            )
        ).scalars().first()

        return assets, findings, last_scan

    @staticmethod
    def _new_host(key: str) -> Dict[str, Any]:
        return {
            "ip": None,
            "hostname": None,
            "os": None,
            "os_accuracy": None,
            "url": None,
            "screenshot": None,
            "ports": [],
            "technologies": [],
            "vulns": {k: 0 for k in SEVERITY_KEYS},
            "_port_keys": set(),
            "_hostnames": set(),
        }

    def _host(self, hosts: Dict[str, Dict[str, Any]], key: str) -> Dict[str, Any]:
        if key not in hosts:
            hosts[key] = self._new_host(key)
        return hosts[key]

    async def build(self, workspace_id: UUID) -> Dict[str, Any]:
        assets, findings, last_scan = await self._load(workspace_id)
        hosts: Dict[str, Dict[str, Any]] = {}

        # 1. Assets
        for asset in assets:
            key = _clean_target(asset.target)
            if not key:
                continue
            host = self._host(hosts, key)
            asset_type = str(
                asset.type.value if hasattr(asset.type, "value") else asset.type
            )
            if asset_type == "ip":
                host["ip"] = host["ip"] or key
            else:
                host["hostname"] = host["hostname"] or key
            for ip in (asset.resolved_ips or []):
                if ip and not host["ip"]:
                    host["ip"] = ip
                if ip:
                    ip_host = self._host(hosts, ip)
                    ip_host["ip"] = ip_host["ip"] or ip
                    if key:
                        ip_host["hostname"] = ip_host["hostname"] or key
                        ip_host["_hostnames"].add(key)
            host["_hostnames"].add(key)
            host["url"] = host["url"] or f"https://{key}"
            if asset.risk_score:
                host["risk_score"] = asset.risk_score
            if asset.risk_level:
                host["risk_level"] = str(
                    asset.risk_level.value if hasattr(asset.risk_level, "value") else asset.risk_level
                )
            if getattr(asset, "last_scanned_at", None):
                host["last_seen"] = asset.last_scanned_at.isoformat()

        # 2. Findings derived surface facts
        for finding in findings:
            evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
            severity = str(
                finding.severity.value if hasattr(finding.severity, "value") else finding.severity
            )
            target_host = (
                evidence.get("host_ip")
                or _host_from_url(getattr(finding, "target_url", None))
                or evidence.get("domain")
                or evidence.get("host")
            )

            if target_host:
                host = self._host(hosts, target_host)
                host["_hostnames"].update(
                    h for h in (evidence.get("hostnames") or []) if h
                )
                if evidence.get("host_ip"):
                    host["ip"] = host["ip"] or evidence["host_ip"]
                if severity in host["vulns"]:
                    host["vulns"][severity] += 1

            # Open ports (network scanner evidence)
            if evidence.get("port") and evidence.get("protocol"):
                port_host = self._host(
                    hosts, evidence.get("host_ip") or target_host or "unknown"
                )
                port_host["ip"] = port_host["ip"] or evidence.get("host_ip")
                port_host["_hostnames"].update(
                    h for h in (evidence.get("hostnames") or []) if h
                )
                service = evidence.get("service") or {}
                port_key = f"{evidence['port']}/{evidence['protocol']}"
                if port_key not in port_host["_port_keys"]:
                    port_host["_port_keys"].add(port_key)
                    port_host["ports"].append({
                        "port": evidence["port"],
                        "protocol": evidence["protocol"],
                        "service": service.get("name"),
                        "product": service.get("product") or None,
                        "version": service.get("version") or None,
                        "state": evidence.get("state", "open"),
                        "target": f"{evidence.get('host_ip') or target_host}:{evidence['port']}",
                        "url": None,
                    })

            # OS fingerprint
            if evidence.get("os_name") and target_host:
                host = self._host(hosts, target_host)
                host["os"] = host["os"] or evidence["os_name"]
                host["os_accuracy"] = host["os_accuracy"] or evidence.get("accuracy")

            # Technology fingerprint (recon')
            if evidence.get("server") or evidence.get("tech_hints") or evidence.get("whatweb_plugins"):
                tech_host = target_host
                if tech_host:
                    host = self._host(hosts, tech_host)
                    if not host["url"] and getattr(finding, "target_url", None):
                        host["url"] = finding.target_url
                    for tech in [
                        evidence.get("server"),
                        evidence.get("powered_by"),
                        *(evidence.get("tech_hints") or []),
                        *(evidence.get("whatweb_plugins") or []),
                    ]:
                        if not tech:
                            continue
                        tech = str(tech)
                        if tech.lower() in _TECH_NOISE:
                            continue
                        if tech not in host["technologies"]:
                            host["technologies"].append(tech)

            # Subdomains discovered
            for sub in (evidence.get("subdomains") or [])[:500]:
                sub_host = self._host(hosts, sub)
                sub_host["hostname"] = sub_host["hostname"] or sub
                sub_host["url"] = sub_host["url"] or f"https://{sub}"
                sub_host["_hostnames"].add(sub)

        # 3. Finalize rows
        rows: List[Dict[str, Any]] = []
        for key, host in hosts.items():
            hostnames = sorted({h for h in host["_hostnames"] if h})
            hostname = host["hostname"] or (hostnames[0] if hostnames else None)
            if not hostname and not host["ip"]:
                hostname = key
            total_vulns = sum(host["vulns"].values())
            rows.append({
                "key": key,
                "ip": host["ip"],
                "hostname": hostname,
                "hostnames": hostnames,
                "os": host["os"],
                "os_accuracy": host["os_accuracy"],
                "url": host["url"],
                "screenshot": host["screenshot"],
                "ports": sorted(host["ports"], key=lambda p: (p["port"], p["protocol"])),
                "port_count": len(host["ports"]),
                "technologies": host["technologies"],
                "vulns": host["vulns"],
                "vuln_count": total_vulns,
                "risk_level": host.get("risk_level"),
                "risk_score": host.get("risk_score"),
                "last_seen": host.get("last_seen"),
            })

        rows.sort(
            key=lambda r: (
                -r["vulns"]["critical"],
                -r["vulns"]["high"],
                -(r["risk_score"] or 0),
                r["hostname"] or r["ip"] or "",
            )
        )

        services = sorted({p["service"] for r in rows for p in r["ports"] if p.get("service")})
        technologies = sorted({t for r in rows for t in r["technologies"]})

        return {
            "workspace_id": str(workspace_id),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "last_scan_at": last_scan.isoformat() if last_scan else None,
            "summary": {
                "hosts": len(rows),
                "ports": sum(r["port_count"] for r in rows),
                "services": len(services),
                "technologies": len(technologies),
                "findings": sum(r["vuln_count"] for r in rows),
                "critical": sum(r["vulns"]["critical"] for r in rows),
                "high": sum(r["vulns"]["high"] for r in rows),
                "medium": sum(r["vulns"]["medium"] for r in rows),
                "low": sum(r["vulns"]["low"] for r in rows),
                "info": sum(r["vulns"]["info"] for r in rows),
            },
            "services": services,
            "technology_list": technologies,
            "rows": rows,
        }

    async def stats(self, workspace_id: UUID) -> Dict[str, Any]:
        data = await self.build(workspace_id)
        return {
            "workspace_id": data["workspace_id"],
            "generated_at": data["generated_at"],
            "summary": data["summary"],
            "top_hosts": data["rows"][:10],
        }
