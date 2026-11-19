"""Robot (workflow chaining) execution.

A robot is an ordered list of scan steps. A discovery step (subdomain,
domain finder, virtual hosts) feeds the targets it finds into the next
step, so a robot can walk: subdomain discovery -> port scan of each host
-> website scan of each reachable service.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Iterable, Optional
from urllib.parse import urlparse

from core.celery_app import celery_app
from core.database import SyncSessionLocal
from models.asset import Asset, AssetType, AssetRiskLevel
from models.finding import Finding
from models.robot import Robot, RobotRun, RobotRunStatus
from models.scan import Scan, ScanIntensity, ScanStatus, ScanType
from services.scanner_tasks import run_scan_task

logger = logging.getLogger(__name__)

DISCOVERY_TOOLS = {"subdomain", "domain_finder", "vhost", "network"}
EVIDENCE_TARGET_KEYS = ("subdomains", "domains", "vhosts", "hosts", "hostnames")

_HOST_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def _normalize_target(value: str) -> Optional[str]:
    raw = (value or "").strip().lower()
    if not raw:
        return None
    if "://" in raw:
        host = urlparse(raw).hostname or ""
    else:
        host = raw.split("/", 1)[0]
    host = host.split(":", 1)[0].strip(".")
    if not host or not _HOST_RE.match(host):
        return None
    if len(host) > 253:
        return None
    return host


def _scan_type(tool: str) -> Optional[ScanType]:
    try:
        return ScanType(str(tool).lower())
    except ValueError:
        return None


def _discovered_targets(db, scan_id) -> list[str]:
    """Collect hosts discovered by one scan step from finding evidence."""
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    found: list[str] = []
    for finding in findings:
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        for key in EVIDENCE_TARGET_KEYS:
            values = evidence.get(key)
            if not values:
                continue
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, (list, tuple, set)):
                continue
            for value in values:
                if isinstance(value, dict):
                    value = value.get("host") or value.get("hostname") or value.get("name")
                if not isinstance(value, str):
                    continue
                host = _normalize_target(value)
                if host and host not in found:
                    found.append(host)
    return found


def _get_or_create_asset(db, workspace_id, target: str) -> Asset:
    asset = (
        db.query(Asset)
        .filter(Asset.workspace_id == workspace_id, Asset.target == target, Asset.deleted_at.is_(None))
        .first()
    )
    if asset:
        return asset
    asset_type = AssetType.URL if target.startswith("http") else AssetType.HOSTNAME
    asset = Asset(
        workspace_id=workspace_id,
        target=target,
        type=asset_type,
        risk_level=AssetRiskLevel.NONE,
    )
    db.add(asset)
    db.flush()
    return asset


def _run_single_scan(db, workspace_id, target: str, tool: str, intensity: str, name: str) -> Scan:
    asset = _get_or_create_asset(db, workspace_id, target)
    scan_type = _scan_type(tool) or ScanType.WEBSITE
    scan = Scan(
        workspace_id=workspace_id,
        asset_id=asset.id,
        name=name,
        type=scan_type,
        target=target,
        intensity=ScanIntensity(intensity) if intensity in {i.value for i in ScanIntensity} else ScanIntensity.NORMAL,
        status=ScanStatus.PENDING,
        progress=0.0,
        scanner_config={},
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    options = {
        "target": scan.target,
        "scan_type": scan_type.value,
        "intensity": scan.intensity.value if hasattr(scan.intensity, "value") else str(scan.intensity),
        "is_authenticated": False,
        "auth_config": {},
        "options": {},
    }
    try:
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        db.commit()
        run_scan_task.apply(args=[str(scan.id), options])
    except Exception as exc:  # pragma: no cover - provider failure
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan.id).first()
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = f"Robot step failed: {exc}"
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
        logger.warning("robot step %s on %s failed: %s", tool, target, exc)
    db.refresh(scan)
    scan.findings_count = db.query(Finding).filter(Finding.scan_id == scan.id).count()
    return scan


def _update_run(db, run: RobotRun, **fields) -> None:
    for key, value in fields.items():
        setattr(run, key, value)
    db.commit()


@celery_app.task(bind=True, name="robot.run", max_retries=0)
def run_robot_task(self, robot_id: str, run_id: str):
    db = SyncSessionLocal()
    try:
        robot = db.query(Robot).filter(Robot.id == robot_id).first()
        run = db.query(RobotRun).filter(RobotRun.id == run_id).first()
        if not robot or not run:
            logger.warning("robot run %s skipped: missing robot or run", run_id)
            return {"ok": False, "reason": "missing"}

        steps = robot.steps if isinstance(robot.steps, list) else []
        if not steps:
            _update_run(
                db,
                run,
                status=RobotRunStatus.FAILED.value,
                error_message="Robot has no steps",
                completed_at=datetime.now(timezone.utc),
            )
            return {"ok": False, "reason": "no steps"}

        max_targets = max(1, min(int(robot.max_targets or 10), 50))
        _update_run(
            db,
            run,
            status=RobotRunStatus.RUNNING.value,
            started_at=datetime.now(timezone.utc),
            total_steps=len(steps),
            steps_state=[],
        )

        current_targets = [run.target]
        steps_state: list[dict] = []
        all_scan_ids: list[str] = []

        for index, step in enumerate(steps):
            tool = str((step or {}).get("tool") or "website").lower()
            intensity = str((step or {}).get("intensity") or "normal").lower()
            state = {
                "index": index,
                "tool": tool,
                "intensity": intensity,
                "targets": list(current_targets),
                "scan_ids": [],
                "status": "running",
                "findings": 0,
                "discovered": [],
                "error": None,
            }
            steps_state.append(state)
            _update_run(db, run, current_step=index, steps_state=list(steps_state))

            next_targets: list[str] = []
            for target in current_targets[:max_targets]:
                scan = _run_single_scan(db, run.workspace_id, target, tool, intensity, f"Robot {robot.name}: {tool} — {target}")
                state["scan_ids"].append(str(scan.id))
                all_scan_ids.append(str(scan.id))
                state["findings"] += scan.findings_count or 0
                if _enum_value(scan.status) == ScanStatus.FAILED.value:
                    state["error"] = scan.error_message or "scan failed"
                discovered = _discovered_targets(db, scan.id)
                for host in discovered:
                    if host not in next_targets and host != target:
                        next_targets.append(host)
                _update_run(db, run, steps_state=list(steps_state), scan_ids=list(all_scan_ids))

            state["discovered"] = next_targets[:max_targets]
            state["status"] = "failed" if state["error"] and not state["scan_ids"] else "completed"
            _update_run(db, run, steps_state=list(steps_state), scan_ids=list(all_scan_ids))

            if tool in DISCOVERY_TOOLS and next_targets:
                current_targets = next_targets[:max_targets]
            elif not current_targets:
                current_targets = []

        run = db.query(RobotRun).filter(RobotRun.id == run_id).first()
        _update_run(
            db,
            run,
            status=RobotRunStatus.COMPLETED.value,
            current_step=len(steps),
            completed_at=datetime.now(timezone.utc),
            steps_state=list(steps_state),
            scan_ids=list(all_scan_ids),
        )
        return {"ok": True, "scans": len(all_scan_ids)}
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("robot run %s crashed", run_id)
        try:
            run = db.query(RobotRun).filter(RobotRun.id == run_id).first()
            if run:
                run.status = RobotRunStatus.FAILED.value
                run.error_message = str(exc)
                run.completed_at = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            db.rollback()
        return {"ok": False, "error": str(exc)}
    finally:
        db.close()


def _enum_value(value) -> str:
    return value.value if hasattr(value, "value") else str(value)
