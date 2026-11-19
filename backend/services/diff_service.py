from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Set
from uuid import UUID
from dataclasses import dataclass
from enum import Enum

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from models.scan import Scan, ScanStatus
from models.finding import Finding, FindingStatus
from models.asset import Asset
from models.workspace import Workspace


class DiffType(str, Enum):
    NEW = "new"
    RESOLVED = "resolved"
    REGRESSED = "regressed"  # Was fixed, now found again
    UNCHANGED = "unchanged"
    CHANGED = "changed"  # Severity/status changed


@dataclass
class FindingDiff:
    finding_id: UUID
    title: str
    target_url: str
    severity: str
    status: str
    diff_type: DiffType
    previous_severity: Optional[str] = None
    previous_status: Optional[str] = None
    scan_id: Optional[UUID] = None
    previous_scan_id: Optional[UUID] = None


class DiffService:
    def __init__(self, db: AsyncSession):
        self.db = db

    def _finding_key(self, finding: Any) -> str:
        """Generate a unique key for a finding to compare across scans."""
        # Use title + target_url + parameter as the key
        parts = [
            finding.title or "",
            finding.target_url or "",
            finding.parameter or "",
            finding.method or "",
        ]
        return "|".join(parts)

    def _normalize_finding(self, finding: Any) -> Dict[str, Any]:
        return {
            "id": str(finding.id),
            "title": finding.title,
            "target_url": finding.target_url,
            "parameter": finding.parameter,
            "method": finding.method,
            "severity": finding.severity.value if finding.severity else "info",
            "status": finding.status.value if finding.status else "open",
            "source_scanner": finding.source_scanner,
            "scan_id": str(finding.scan_id) if finding.scan_id else None,
        }

    async def compare_scans(
        self,
        baseline_scan_id: UUID,
        current_scan_id: UUID,
    ) -> Dict[str, Any]:
        """Compare findings between two scans."""

        # Get findings for both scans
        baseline_findings = (
            await self.db.execute(
                select(Finding).where(Finding.scan_id == baseline_scan_id)
            )
        ).scalars().all()

        current_findings = (
            await self.db.execute(
                select(Finding).where(Finding.scan_id == current_scan_id)
            )
        ).scalars().all()

        # Build maps by finding key
        baseline_map = {self._finding_key(f): self._normalize_finding(f) for f in baseline_findings}
        current_map = {self._finding_key(f): self._normalize_finding(f) for f in current_findings}

        baseline_keys = set(baseline_map.keys())
        current_keys = set(current_map.keys())

        new_keys = current_keys - baseline_keys
        resolved_keys = baseline_keys - current_keys
        common_keys = baseline_keys & current_keys

        diffs: List[Dict[str, Any]] = []

        # New findings
        for key in new_keys:
            f = current_map[key]
            diffs.append({
                "type": DiffType.NEW.value,
                "finding": f,
                "message": f"New finding: {f['title']}",
            })

        # Resolved findings
        for key in resolved_keys:
            f = baseline_map[key]
            diffs.append({
                "type": DiffType.RESOLVED.value,
                "finding": f,
                "message": f"Resolved: {f['title']}",
            })

        # Changed findings (severity or status changed)
        for key in common_keys:
            base = baseline_map[key]
            curr = current_map[key]
            changes = []

            if base["severity"] != curr["severity"]:
                changes.append(f"Severity: {base['severity']} → {curr['severity']}")

            if base["status"] != curr["status"]:
                changes.append(f"Status: {base['status']} → {curr['status']}")

            if changes:
                diffs.append({
                    "type": DiffType.CHANGED.value,
                    "finding": curr,
                    "previous": base,
                    "changes": changes,
                    "message": f"Changed: {curr['title']} ({', '.join(changes)})",
                })

        # Summary counts
        new_count = len(new_keys)
        resolved_count = len(resolved_keys)
        changed_count = sum(1 for d in diffs if d["type"] == DiffType.CHANGED.value)

        return {
            "baseline_scan_id": str(baseline_scan_id),
            "current_scan_id": str(current_scan_id),
            "compared_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_baseline": len(baseline_findings),
                "total_current": len(current_findings),
                "new": new_count,
                "resolved": resolved_count,
                "changed": changed_count,
                "unchanged": len(common_keys) - changed_count,
            },
            "diffs": diffs,
        }

    async def compare_latest_two_scans(self, target: str) -> Optional[Dict[str, Any]]:
        """Find the latest two completed scans for a target and compare them."""
        result = await self.db.execute(
            select(Scan).where(
                Scan.target == target,
                Scan.status == ScanStatus.COMPLETED,
            ).order_by(Scan.completed_at.desc()).limit(2)
        )
        scans = result.scalars().all()

        if len(scans) < 2:
            return None

        # scans[0] is latest, scans[1] is previous
        return await self.compare_scans(scans[1].id, scans[0].id)

    async def get_all_target_diffs(self, workspace_id: UUID) -> List[Dict[str, Any]]:
        """Compare latest two scans for all targets in workspace."""
        # Get all unique targets with completed scans
        result = await self.db.execute(
            select(Scan.target).where(
                Scan.workspace_id == workspace_id,
                Scan.status == ScanStatus.COMPLETED,
            ).distinct()
        )
        targets = [row[0] for row in result.all()]

        diffs = []
        for target in targets:
            diff = await self.compare_latest_two_scans(target)
            if diff and diff["summary"]["new"] + diff["summary"]["resolved"] + diff["summary"]["changed"] > 0:
                diffs.append({
                    "target": target,
                    **diff,
                })

        return diffs

    async def check_for_alerts(self, workspace_id: UUID, severity_threshold: str = "high") -> List[Dict[str, Any]]:
        """Find new high/critical findings in the latest scan for each target."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        threshold = severity_order.get(severity_threshold, 1)

        # Get latest completed scan per target
        result = await self.db.execute(
            select(Scan).where(
                Scan.workspace_id == workspace_id,
                Scan.status == ScanStatus.COMPLETED,
            ).order_by(Scan.target, Scan.completed_at.desc())
        )
        scans = result.scalars().all()

        # Group by target, keep latest
        latest_scans = {}
        for scan in scans:
            if scan.target not in latest_scans:
                latest_scans[scan.target] = scan

        alerts = []
        for target, scan in latest_scans.items():
            # Get previous scan for this target
            prev_result = await self.db.execute(
                select(Scan).where(
                    Scan.target == target,
                    Scan.status == ScanStatus.COMPLETED,
                    Scan.id != scan.id,
                ).order_by(Scan.completed_at.desc()).limit(1)
            )
            prev_scan = prev_result.scalars().first()

            if not prev_scan:
                continue

            diff = await self.compare_scans(prev_scan.id, scan.id)

            # Filter for high/critical new findings
            for d in diff["diffs"]:
                if d["type"] == DiffType.NEW.value:
                    sev = d["finding"]["severity"]
                    if severity_order.get(sev, 5) <= threshold:
                        alerts.append({
                            "target": d["finding"]["target_url"],
                            "finding_title": d["finding"]["title"],
                            "severity": sev,
                            "scan_id": str(scan.id),
                            "scan_name": scan.name,
                            "message": f"New {sev} finding: {d['finding']['title']}",
                        })

        return alerts


async def run_diff_check(workspace_id: UUID) -> Dict[str, Any]:
    """Run diff check for all targets in workspace."""
    from core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        service = DiffService(db)
        diffs = await service.get_all_target_diffs(workspace_id)
        alerts = await service.check_for_alerts(workspace_id)

        return {
            "workspace_id": str(workspace_id),
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "targets_compared": len(diffs),
            "total_changes": sum(
                d["summary"]["new"] + d["summary"]["resolved"] + d["summary"]["changed"]
                for d in diffs
            ),
            "alerts": alerts,
            "diffs": diffs,
        }