"""Celery tasks for running scans"""
from celery import shared_task
from core.celery_app import celery_app
from services.scanner_base import ScannerRegistry
from services.nmap_scanner import NmapScanner
from services.nuclei_scanner import NucleiScanner
from services.sqlmap_scanner import SQLMapScanner
from services.wpscanner import WPScanScanner, DrupalScanner, NucleiCMSScanner
from services.burp_import import BurpImportScanner
from services.api_scanner import APIScanner
from services.cloud_scanner import AzureScanner, GCPScanner, CloudScanner
from services.exploitation import SniperExploiter
from services.discovery_scanners import (
    SubdomainScanner, ReconScanner, PasswordAuditorScanner,
    GoogleHackingScanner, PeopleHunterScanner, DomainFinderScanner,
    VHostScanner, URLFuzzerScanner, HTTPRequestLoggerScanner,
)
from services.email_service import email_service
from datetime import datetime
import asyncio
import uuid
import json
import logging

logger = logging.getLogger(__name__)

# Ensure scanners are registered
for _scanner_cls in (
    NmapScanner, NucleiScanner, SQLMapScanner,
    WPScanScanner, DrupalScanner, NucleiCMSScanner,
    BurpImportScanner, APIScanner,
    AzureScanner, GCPScanner, CloudScanner,
    SniperExploiter,
    SubdomainScanner, ReconScanner, PasswordAuditorScanner,
    GoogleHackingScanner, PeopleHunterScanner, DomainFinderScanner,
    VHostScanner, URLFuzzerScanner, HTTPRequestLoggerScanner,
):
    try:
        _scanner_cls()
    except Exception:  # pragma: no cover - a broken scanner must not block the rest
        pass


@shared_task(bind=True, max_retries=2, default_retry_delay=60)
def run_scan_task(self, scan_id: str, scan_config: dict):
    """
    Main task to run a scan
    
    scan_config contains:
    - target: target to scan
    - scan_type: type of scan
    - intensity: light/normal/aggressive
    - is_authenticated: bool
    - auth_config: dict with auth details
    - options: additional scanner options
    """
    
    async def _run_scan():
        from core.database import SyncSessionLocal
        from models.scan import Scan, ScanStatus, ScanLog
        from models.finding import Finding, FindingSeverity, FindingStatus
        from models.asset import Asset, AssetRiskLevel, AssetType
        from models.workspace import Workspace, WorkspaceMember
        from models.user import User
        from sqlalchemy.orm import Session
        
        db: Session = SyncSessionLocal()
        
        try:
            # Get scan record
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            # Findings require an asset; attach one if the scan was created without it.
            if not scan.asset_id:
                asset = (
                    db.query(Asset)
                    .filter(Asset.workspace_id == scan.workspace_id, Asset.target == scan.target)
                    .first()
                )
                if not asset:
                    asset = Asset(
                        workspace_id=scan.workspace_id,
                        target=scan.target,
                        type=AssetType.HOSTNAME,
                    )
                    db.add(asset)
                    db.flush()
                scan.asset_id = asset.id
                db.commit()
            
            # Update scan status
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            run_started = scan.started_at
            scan.celery_task_id = self.request.id
            db.commit()
            
            # Log start
            log = ScanLog(
                scan_id=scan.id,
                level='info',
                message=f'Scan started with task {self.request.id}',
                step='initialization',
                progress=0.0,
            )
            db.add(log)
            db.commit()
            
            # Determine scanners to run
            scanner_names = _get_scanners_for_type(scan.type)
            
            all_findings = []
            total_scanners = len(scanner_names)
            
            for i, scanner_name in enumerate(scanner_names):
                # Update progress
                progress = (i / total_scanners) * 100
                scan.progress = progress
                scan.current_step = f'Running {scanner_name}'
                db.commit()
                
                # Log progress
                log = ScanLog(
                    scan_id=scan.id,
                    level='info',
                    message=f'Starting {scanner_name}',
                    step=scanner_name,
                    progress=progress,
                )
                db.add(log)
                db.commit()
                
                # Get scanner
                scanner = ScannerRegistry.get(scanner_name)
                if not scanner:
                    log = ScanLog(
                        scan_id=scan.id,
                        level='warning',
                        message=f'Scanner {scanner_name} not found',
                        step=scanner_name,
                    )
                    db.add(log)
                    db.commit()
                    continue
                
                # Prepare options
                options = {
                    'scan_id': str(scan.id),
                    'intensity': scan.intensity.value if hasattr(scan.intensity, 'value') else scan.intensity,
                    'scan_type': scan.type.value if hasattr(scan.type, 'value') else scan.type,
                    'timeout': 3600,
                    **(scan.scanner_config or {}),
                }
                
                # Add authenticated config if needed
                if scan.is_authenticated and scan.auth_config:
                    options['headers'] = scan.auth_config.get('headers', {})
                    options['cookies'] = scan.auth_config.get('cookies', '')
                
                # Run scanner
                try:
                    result = await scanner.scan(scan.target, options)
                    
                    # Log completion
                    log = ScanLog(
                        scan_id=scan.id,
                        level='info' if result.status == 'completed' else 'warning',
                        message=f'{scanner_name} completed with {len(result.findings)} findings',
                        step=scanner_name,
                        progress=((i + 1) / total_scanners) * 100,
                        meta={
                            'findings_count': len(result.findings),
                            'duration': result.duration_seconds,
                        },
                    )
                    db.add(log)
                    
                    # Save findings
                    for finding_data in result.findings:
                        finding = Finding(
                            workspace_id=scan.workspace_id,
                            scan_id=scan.id,
                            asset_id=scan.asset_id,
                            title=finding_data.title,
                            description=finding_data.description,
                            severity=_severity(finding_data.severity),
                            status=FindingStatus.OPEN,
                            cwe_id=finding_data.cwe_id,
                            cve_ids=finding_data.cve_ids,
                            cvss_score=finding_data.cvss_score,
                            cvss_vector=finding_data.cvss_vector,
                            target_url=finding_data.target_url,
                            parameter=finding_data.parameter,
                            method=finding_data.method,
                            path=finding_data.path,
                            evidence=finding_data.evidence,
                            reproduction_steps=finding_data.reproduction_steps,
                            proof_of_concept=finding_data.proof_of_concept,
                            remediation=finding_data.remediation,
                            references=[],
                            fingerprint=_generate_fingerprint(finding_data),
                            source_scanner=finding_data.source_scanner,
                            source_finding_id=finding_data.source_finding_id,
                            source_rule_id=finding_data.source_rule_id,
                            tags=finding_data.tags,
                            compliance_mappings=finding_data.compliance_mappings,
                        )
                        db.add(finding)
                        all_findings.append(finding)
                    
                    db.commit()
                    
                except Exception as e:
                    log = ScanLog(
                        scan_id=scan.id,
                        level='error',
                        message=f'{scanner_name} failed: {str(e)}',
                        step=scanner_name,
                    )
                    db.add(log)
                    db.commit()
            
            # Update scan with results
            scan.findings_count = len(all_findings)
            scan.critical_count = sum(1 for f in all_findings if f.severity == FindingSeverity.CRITICAL)
            scan.high_count = sum(1 for f in all_findings if f.severity == FindingSeverity.HIGH)
            scan.medium_count = sum(1 for f in all_findings if f.severity == FindingSeverity.MEDIUM)
            scan.low_count = sum(1 for f in all_findings if f.severity == FindingSeverity.LOW)
            scan.info_count = sum(1 for f in all_findings if f.severity == FindingSeverity.INFO)
            
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            scan.duration_seconds = int((datetime.utcnow() - run_started).total_seconds())
            scan.progress = 100.0
            scan.current_step = 'Completed'
            
            # Update asset stats
            if scan.asset_id:
                asset = db.query(Asset).filter(Asset.id == scan.asset_id).first()
                if asset:
                    asset.total_scans += 1
                    asset.last_scanned_at = datetime.utcnow()
                    asset.vulnerabilities_count += len(all_findings)
                    asset.critical_vulns += scan.critical_count
                    asset.high_vulns += scan.high_count
                    asset.medium_vulns += scan.medium_count
                    asset.low_vulns += scan.low_count
                    # Update risk level
                    if scan.critical_count > 0:
                        asset.risk_level = AssetRiskLevel.CRITICAL
                    elif scan.high_count > 0:
                        asset.risk_level = AssetRiskLevel.HIGH
                    elif scan.medium_count > 0:
                        asset.risk_level = AssetRiskLevel.MEDIUM
                    elif scan.low_count > 0:
                        asset.risk_level = AssetRiskLevel.LOW
            
            db.commit()
            
            # Final log
            log = ScanLog(
                scan_id=scan.id,
                level='info',
                message=f'Scan completed. Found {len(all_findings)} vulnerabilities.',
                step='completed',
                progress=100.0,
            )
            db.add(log)
            db.commit()
            
            # Send completion notification email
            try:
                from core.config import settings
                workspace = db.query(Workspace).filter(Workspace.id == scan.workspace_id).first()
                if workspace:
                    # Get workspace members with email notifications enabled
                    from models.workspace import WorkspaceMember
                    members = db.query(WorkspaceMember).filter(WorkspaceMember.workspace_id == workspace.id).all()
                    member_emails = []
                    for member in members:
                        user = db.query(User).filter(User.id == member.user_id).first()
                        if user and user.email:
                            member_emails.append(user.email)
                    
                    if member_emails:
                        email_service.send_scan_notification(
                            to=member_emails,
                            scan_name=scan.name,
                            status='completed',
                            findings_count=len(all_findings),
                            workspace_name=workspace.name,
                        )
            except Exception as e:
                logger.warning(f"Failed to send scan completion email: {e}")
            
            return {
                'scan_id': str(scan.id),
                'status': 'completed',
                'findings_count': len(all_findings),
            }
            
        except Exception as e:
            # Handle error
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.FAILED
                scan.error_message = str(e)
                scan.completed_at = datetime.utcnow()
                db.commit()
            
            log = ScanLog(
                scan_id=scan_id,
                level='error',
                message=f'Scan failed: {str(e)}',
                step='error',
            )
            db.add(log)
            db.commit()
            
            raise
        finally:
            db.close()
    
    return asyncio.run(_run_scan())


def _get_scanners_for_type(scan_type) -> list:
    """Get list of scanner names for a scan type"""
    type_str = scan_type.value if hasattr(scan_type, 'value') else scan_type
    
    scanner_map = {
        'website': ['NucleiScanner', 'SQLMapScanner'],
        'network': ['NmapScanner', 'NucleiScanner'],
        'port': ['NmapScanner'],
        'subdomain': ['SubdomainScanner'],
        'recon': ['ReconScanner'],
        'password': ['PasswordAuditorScanner'],
        'cms': ['WPScanScanner', 'DrupalScanner', 'NucleiCMSScanner'],
        'api': ['APIScanner'],
        'cloud': ['CloudScanner', 'AzureScanner', 'GCPScanner'],
        'exploit': ['SniperExploiter'],
        'burp': ['BurpImportScanner'],
        'fuzzer': ['URLFuzzerScanner'],
        'google_hacking': ['GoogleHackingScanner'],
        'people_hunter': ['PeopleHunterScanner'],
        'domain_finder': ['DomainFinderScanner'],
        'vhost': ['VHostScanner'],
        'http_logger': ['HTTPRequestLoggerScanner'],
        'ai_pentest': ['NucleiScanner', 'SQLMapScanner', 'NmapScanner'],
        'full': ['NmapScanner', 'NucleiScanner', 'SQLMapScanner'],
    }
    
    return scanner_map.get(type_str, ['NucleiScanner', 'NmapScanner'])


def _severity(value) -> 'FindingSeverity':
    """Coerce arbitrary scanner severity text into a FindingSeverity."""
    from models.finding import FindingSeverity
    try:
        return FindingSeverity(str(value).strip().lower())
    except Exception:
        return FindingSeverity.INFO


def _generate_fingerprint(finding) -> str:
    """Generate unique fingerprint for finding deduplication"""
    import hashlib
    content = f"{finding.source_scanner}:{finding.source_rule_id}:{finding.target_url}:{finding.parameter}"
    return hashlib.sha256(content.encode()).hexdigest()[:64]


@shared_task(bind=True, max_retries=1)
def retry_failed_scan(self, scan_id: str):
    """Retry a failed scan"""
    from core.database import get_sync_db
    from models.scan import Scan, ScanStatus
    from sqlalchemy.orm import Session
    
    db: Session = next(get_sync_db())
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        return {'error': 'Scan not found'}
    
    if scan.status not in [ScanStatus.FAILED, ScanStatus.CANCELLED]:
        return {'error': 'Scan cannot be retried'}
    
    if scan.retry_count >= scan.max_retries:
        return {'error': 'Max retries exceeded'}
    
    # Reset scan for retry
    scan.status = ScanStatus.PENDING
    scan.retry_count += 1
    scan.error_message = None
    db.commit()
    
    # Queue new scan
    run_scan_task.delay(str(scan.id), {
        'target': scan.target,
        'scan_type': scan.type.value if hasattr(scan.type, 'value') else scan.type,
        'intensity': scan.intensity.value if hasattr(scan.intensity, 'value') else scan.intensity,
        'is_authenticated': scan.is_authenticated,
        'auth_config': scan.auth_config,
        'options': scan.scanner_config,
    })
    
    return {'status': 'retry_queued', 'retry_count': scan.retry_count}


@shared_task
def cancel_scan(scan_id: str):
    """Cancel a running scan"""
    from core.database import get_sync_db
    from models.scan import Scan, ScanStatus
    from sqlalchemy.orm import Session
    
    db: Session = next(get_sync_db())
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        return {'error': 'Scan not found'}
    
    if scan.status in [ScanStatus.RUNNING, ScanStatus.QUEUED, ScanStatus.PENDING]:
        # Revoke Celery task
        if scan.celery_task_id:
            celery_app.control.revoke(scan.celery_task_id, terminate=True)
        
        scan.status = ScanStatus.CANCELLED
        scan.completed_at = datetime.utcnow()
        db.commit()
        return {'status': 'cancelled'}
    
    return {'error': 'Scan cannot be cancelled'}