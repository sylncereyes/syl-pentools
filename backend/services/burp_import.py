"""Burp Suite import parser + finding normalizer"""
import asyncio
import base64
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from pathlib import Path

from services.scanner_base import BaseScanner, ScanResult, ScanFinding, ScannerRegistry
from core.database import get_sync_db
from models.finding import FindingSeverity, FindingStatus
from sqlalchemy.orm import Session
from celery import shared_task


@dataclass
class BurpIssue:
    """Normalized Burp issue"""
    name: str
    severity: str
    confidence: str
    host: str
    path: str
    method: str
    parameter: str
    issue_type: str
    description: str
    remediation: str
    references: List[str]
    request: str
    response: str
    issue_background: str
    remediation_background: str
    cwe_id: str = ""
    wascid: str = ""


class BurpXMLParser:
    """Parse Burp Suite XML export"""
    
    # Burp severity to our severity mapping
    SEVERITY_MAP = {
        'High': 'high',
        'Medium': 'medium',
        'Low': 'low',
        'Information': 'info',
    }
    
    CONFIDENCE_MAP = {
        'Certain': 'high',
        'Firm': 'medium',
        'Tentative': 'low',
    }
    
    @staticmethod
    def parse_file(file_path: str) -> List[Dict]:
        """Parse Burp XML file"""
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        issues = []
        for issue_elem in root.findall('.//issue'):
            issue = BurpXMLParser._parse_issue(issue_elem)
            if issue:
                issues.append(issue)
        
        return issues
    
    @staticmethod
    def parse_bytes(xml_bytes: bytes) -> List[Dict]:
        """Parse Burp XML from bytes"""
        root = ET.fromstring(xml_bytes)
        
        issues = []
        for issue_elem in root.findall('.//issue'):
            issue = BurpXMLParser._parse_issue(issue_elem)
            if issue:
                issues.append(issue)
        
        return issues
    
    @staticmethod
    def _parse_issue(elem: ET.Element) -> Optional[Dict]:
        """Parse single issue element"""
        try:
            # Basic info
            name = elem.findtext('name', '')
            severity = elem.findtext('severity', 'Information')
            confidence = elem.findtext('confidence', 'Tentative')
            
            # Location
            host = elem.findtext('host', '')
            path = elem.findtext('path', '')
            location = elem.findtext('location', '')
            
            # Request/Response
            request_b64 = elem.findtext('request', '')
            response_b64 = elem.findtext('response', '')
            
            request = base64.b64decode(request_b64).decode('utf-8', errors='ignore') if request_b64 else ''
            response = base64.b64decode(response_b64).decode('utf-8', errors='ignore') if response_b64 else ''
            
            # Parse request to get method, path, params
            method, parsed_path, params = BurpXMLParser._parse_request(request)
            
            # Issue details
            issue_type = elem.findtext('type', '')
            description = elem.findtext('issueBackground', '')
            remediation = elem.findtext('remediationBackground', '')
            
            # References
            references = []
            for ref in elem.findall('.//references/ref'):
                references.append(ref.text or '')
            
            # CWE/WASC
            cwe_id = elem.findtext('cwe', '')
            wascid = elem.findtext('wascid', '')
            
            return {
                'name': name,
                'severity': BurpXMLParser.SEVERITY_MAP.get(severity, 'info'),
                'confidence': BurpXMLParser.CONFIDENCE_MAP.get(confidence, 'low'),
                'host': host,
                'path': parsed_path or path,
                'method': method,
                'parameter': BurpXMLParser._extract_parameter(params),
                'issue_type': issue_type,
                'description': description,
                'remediation': remediation,
                'references': references,
                'request': request,
                'response': response,
                'issue_background': description,
                'remediation_background': remediation,
                'cwe_id': cwe_id,
                'wascid': wascid,
            }
        except Exception as e:
            print(f"Error parsing issue: {e}")
            return None
    
    @staticmethod
    def _parse_request(request: str) -> tuple:
        """Parse HTTP request to extract method, path, params"""
        if not request:
            return 'GET', '/', {}
        
        lines = request.split('\n')
        if not lines:
            return 'GET', '/', {}
        
        # First line: METHOD PATH HTTP/VERSION
        first_line = lines[0].strip()
        parts = first_line.split(' ')
        method = parts[0] if len(parts) > 0 else 'GET'
        path = parts[1] if len(parts) > 1 else '/'
        
        # Parse headers and body
        params = {}
        body = ''
        in_body = False
        
        for line in lines[1:]:
            if line == '':
                in_body = True
                continue
            
            if in_body:
                body += line + '\n'
            elif ':' in line:
                # Header
                pass
        
        # Parse query params from path
        if '?' in path:
            path, query = path.split('?', 1)
            for param in query.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k] = v
        
        # Parse body params
        if body:
            if 'application/x-www-form-urlencoded' in request.lower():
                for param in body.split('&'):
                    if '=' in param:
                        k, v = param.split('=', 1)
                        params[k] = v
            elif 'application/json' in request.lower():
                try:
                    json_params = json.loads(body)
                    if isinstance(json_params, dict):
                        params.update(json_params)
                except:
                    pass
        
        return method, path, params
    
    @staticmethod
    def _extract_parameter(params: Dict) -> str:
        """Extract primary parameter name"""
        if not params:
            return ''
        # Return first parameter name
        return list(params.keys())[0] if params else ''


class BurpJSONParser:
    """Parse Burp Suite JSON export (newer versions)"""
    
    @staticmethod
    def parse_file(file_path: str) -> List[Dict]:
        with open(file_path, 'r') as f:
            data = json.load(f)
        return BurpJSONParser.parse_json(data)
    
    @staticmethod
    def parse_bytes(json_bytes: bytes) -> List[Dict]:
        data = json.loads(json_bytes.decode('utf-8'))
        return BurpJSONParser.parse_json(data)
    
    @staticmethod
    def parse_json(data: Dict) -> List[Dict]:
        """Parse Burp JSON format"""
        issues = []
        
        # Handle different JSON structures
        if 'issues' in data:
            issues_data = data['issues']
        elif 'vulnerabilities' in data:
            issues_data = data['vulnerabilities']
        elif isinstance(data, list):
            issues_data = data
        else:
            issues_data = [data]
        
        for issue_data in issues_data:
            issue = BurpJSONParser._parse_issue(issue_data)
            if issue:
                issues.append(issue)
        
        return issues
    
    @staticmethod
    def _parse_issue(data: Dict) -> Optional[Dict]:
        try:
            return {
                'name': data.get('name', data.get('title', '')),
                'severity': data.get('severity', 'info').lower(),
                'confidence': data.get('confidence', 'low').lower(),
                'host': data.get('host', data.get('host_ip', '')),
                'path': data.get('path', data.get('url', '')),
                'method': data.get('method', 'GET').upper(),
                'parameter': data.get('parameter', data.get('param', '')),
                'issue_type': data.get('type', data.get('vuln_type', '')),
                'description': data.get('description', data.get('issueBackground', '')),
                'remediation': data.get('remediation', data.get('remediationBackground', '')),
                'references': data.get('references', data.get('refs', [])),
                'request': data.get('request', data.get('request_raw', '')),
                'response': data.get('response', data.get('response_raw', '')),
                'cwe_id': data.get('cwe', data.get('cwe_id', '')),
                'wascid': data.get('wascid', data.get('wasc_id', '')),
            }
        except Exception as e:
            print(f"Error parsing JSON issue: {e}")
            return None


class BurpImporter:
    """Import and normalize Burp findings"""
    
    SEVERITY_MAP = {
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'info': 'info',
        'information': 'info',
        'critical': 'critical',
    }
    
    @staticmethod
    def import_file(file_path: str) -> List[Dict]:
        """Auto-detect format and import"""
        path = Path(file_path)
        suffix = path.suffix.lower()
        
        if suffix == '.xml':
            return BurpXMLParser.parse_file(file_path)
        elif suffix == '.json':
            return BurpJSONParser.parse_file(file_path)
        else:
            # Try both
            try:
                return BurpXMLParser.parse_file(file_path)
            except:
                try:
                    return BurpJSONParser.parse_file(file_path)
                except:
                    return []
    
    @staticmethod
    def import_bytes(data: bytes) -> List[Dict]:
        """Import from bytes, auto-detect format"""
        # Try XML first
        if data.strip().startswith(b'<?xml') or b'<issues>' in data[:500]:
            return BurpXMLParser.parse_bytes(data)
        
        # Try JSON
        try:
            return BurpJSONParser.parse_bytes(data)
        except:
            pass
        
        return []
    
    @staticmethod
    def normalize_findings(raw_issues: List[Dict]) -> List[Dict]:
        """Normalize raw Burp issues to our finding format"""
        normalized = []
        
        for issue in raw_issues:
            # Generate fingerprint for deduplication
            fingerprint = BurpImporter._generate_fingerprint(issue)
            _host = issue.get('host', '') or ''
            if _host and not _host.startswith('http'):
                _host = 'http://' + _host
            _target_url = f"{_host}{issue.get('path', '')}"
            
            normalized.append({
                'id': hashlib.sha256(f"{issue.get('host')}{issue.get('path')}{issue.get('name')}".encode()).hexdigest()[:16],
                'title': issue.get('name', 'Burp Finding'),
                'description': issue.get('description', ''),
                'severity': BurpImporter.SEVERITY_MAP.get(issue.get('severity', '').lower(), 'info'),
                'status': 'open',
                'target_url': _target_url,
                'parameter': issue.get('parameter', ''),
                'method': issue.get('method', 'GET'),
                'path': issue.get('path', ''),
                'evidence': {
                    'host': issue.get('host'),
                    'issue_type': issue.get('issue_type'),
                    'confidence': issue.get('confidence'),
                    'request': issue.get('request', '')[:2000],
                    'response': issue.get('response', '')[:2000],
                    'cwe_id': issue.get('cwe_id'),
                    'wascid': issue.get('wascid'),
                },
                'reproduction_steps': f"Replay request to {issue.get('host')}{issue.get('path')}",
                'proof_of_concept': issue.get('request', '')[:500],
                'remediation': issue.get('remediation', ''),
                'references': issue.get('references', []),
                'cwe_id': issue.get('cwe_id', ''),
                'source_scanner': 'BurpSuite',
                'source_finding_id': issue.get('id', ''),
                'source_rule_id': 'burp-import',
                'tags': ['burp', 'imported'],
                'fingerprint': fingerprint,
            })
        
        return normalized
    
    @staticmethod
    def _generate_fingerprint(issue: Dict) -> str:
        """Generate fingerprint for deduplication"""
        content = f"{issue.get('host')}{issue.get('path')}{issue.get('name')}{issue.get('parameter')}"
        return hashlib.sha256(content.encode()).hexdigest()[:64]


class BurpImportScanner(BaseScanner):
    """Scanner that imports Burp findings"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "BurpImportScanner"
        self.version = "1.0.0"
    
    def validate_target(self, target: str) -> bool:
        # Target is file path or "auto" for directory scan
        return True
    
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        scan_id = options.get('scan_id', 'unknown')
        started_at = datetime.utcnow()
        
        all_findings = []
        
        # Determine input
        file_path = options.get('file_path', target)
        file_paths = options.get('file_paths', [])
        
        if file_path and file_path != 'auto':
            file_paths = [file_path]
        elif not file_paths and target != 'auto':
            file_paths = [target]
        
        # If directory, scan for XML/JSON files
        if target == 'auto' or (len(file_paths) == 1 and Path(file_paths[0]).is_dir()):
            dir_path = file_paths[0] if file_paths else target
            file_paths = []
            for ext in ['.xml', '.json']:
                file_paths.extend(list(Path(dir_path).rglob(f'*{ext}')))
        
        all_findings = []
        
        for file_path in file_paths:
            try:
                if Path(file_path).is_file():
                    raw_issues = BurpImporter.import_file(str(file_path))
                    normalized = BurpImporter.normalize_findings(raw_issues)
                    
                    # Convert to ScanFinding
                    for norm in normalized:
                        finding = ScanFinding(
                            title=norm['title'],
                            description=norm['description'],
                            severity=norm['severity'],
                            target_url=norm['target_url'],
                            parameter=norm['parameter'],
                            method=norm['method'],
                            path=norm['path'],
                            evidence=norm['evidence'],
                            reproduction_steps=norm['reproduction_steps'],
                            proof_of_concept=norm['proof_of_concept'],
                            remediation=norm['remediation'],
                            cwe_id=norm['cwe_id'],
                            source_scanner=norm['source_scanner'],
                            source_finding_id=norm['source_finding_id'],
                            source_rule_id=norm['source_rule_id'],
                            tags=norm['tags'],
                        )
                        all_findings.append(finding)
                        
            except Exception as e:
                print(f"Error importing {file_path}: {e}")
                continue
        
        completed_at = datetime.utcnow()
        duration = int((completed_at - started_at).total_seconds())
        
        return ScanResult(
            scan_id=options.get('scan_id', 'unknown'),
            scanner_name=self.name,
            status='completed',
            findings=all_findings,
            raw_output=f"Imported {len(all_findings)} findings from {len(file_paths)} files",
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            metadata={
                'files_processed': len(file_paths),
                'total_findings': len(all_findings),
            },
        )


class BurpImportService:
    """Service for managing Burp imports"""
    
    @staticmethod
    def import_to_database(
        db: Session,
        workspace_id: str,
        file_path: str,
        scan_id: str = None,
    ) -> Dict[str, Any]:
        """Import Burp file and save findings to database"""
        from models.scan import Scan, ScanStatus
        from models.finding import Finding, FindingSeverity, FindingStatus
        import uuid
        
        # Create scan record if not provided
        if not scan_id:
            scan = Scan(
                id=f"scan-{uuid.uuid4().hex[:8]}",
                workspace_id=workspace_id,
                name=f"Burp Import - {Path(file_path).name}",
                type="burp_import",
                target=file_path,
                status=ScanStatus.RUNNING,
                started_at=datetime.utcnow(),
            )
            db.add(scan)
            db.commit()
            scan_id = scan.id
        
        # Import findings
        raw_issues = BurpImporter.import_file(file_path)
        normalized = BurpImporter.normalize_findings(raw_issues)
        
        created = 0
        for norm in normalized:
            # Check for duplicates
            existing = db.query(Finding).filter(
                Finding.fingerprint == norm['fingerprint']
            ).first()
            
            if existing:
                continue
            
            finding = Finding(
                workspace_id=workspace_id,
                scan_id=scan_id,
                title=norm['title'],
                description=norm['description'],
                severity=FindingSeverity(norm['severity']),
                status=FindingStatus.OPEN,
                target_url=norm['target_url'],
                parameter=norm['parameter'],
                method=norm['method'],
                path=norm['path'],
                evidence=norm['evidence'],
                reproduction_steps=norm['reproduction_steps'],
                proof_of_concept=norm['proof_of_concept'],
                remediation=norm['remediation'],
                references=norm['references'],
                cwe_id=norm['cwe_id'],
                source_scanner=norm['source_scanner'],
                source_finding_id=norm['source_finding_id'],
                source_rule_id=norm['source_rule_id'],
                tags=norm['tags'],
                fingerprint=norm['fingerprint'],
            )
            db.add(finding)
            created += 1
        
        db.commit()
        
        # Update scan
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.findings_count = created
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            db.commit()
        
        return {
            'scan_id': scan_id,
            'total_issues': len(raw_issues),
            'created_findings': created,
            'skipped_duplicates': len(raw_issues) - created,
        }


# Register Burp import scanner
ScannerRegistry.register(BurpImportScanner())


# Celery task
@shared_task(bind=True, max_retries=1)
def run_burp_import_task(self, scan_id: str, scan_config: dict):
    """Run Burp import task"""
    async def _run():
        from core.database import get_sync_db
        from models.scan import Scan, ScanStatus, ScanLog
        from models.finding import Finding, FindingSeverity, FindingStatus
        from sqlalchemy.orm import Session
        
        db: Session = next(get_sync_db())
        
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")
            
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            scan.celery_task_id = self.request.id
            db.commit()
            
            scanner = BurpImportScanner()
            result = await scanner.scan(scan.target, {
                'scan_id': str(scan.id),
                'file_path': scan_config.get('file_path'),
                'file_paths': scan_config.get('file_paths', []),
            })
            
            for finding_data in result.findings:
                finding = Finding(
                    workspace_id=scan.workspace_id,
                    scan_id=scan.id,
                    asset_id=scan.asset_id,
                    title=finding_data.title,
                    description=finding_data.description,
                    severity=FindingSeverity(finding_data.severity),
                    status=FindingStatus.OPEN,
                    target_url=finding_data.target_url,
                    parameter=finding_data.parameter,
                    method=finding_data.method,
                    path=finding_data.path,
                    evidence=finding_data.evidence,
                    reproduction_steps=finding_data.reproduction_steps,
                    proof_of_concept=finding_data.proof_of_concept,
                    remediation=finding_data.remediation,
                    references=finding_data.references,
                    cwe_id=finding_data.cwe_id,
                    source_scanner=finding_data.source_scanner,
                    source_finding_id=finding_data.source_finding_id,
                    source_rule_id=finding_data.source_rule_id,
                    tags=finding_data.tags,
                    fingerprint=finding_data.evidence.get('fingerprint', ''),
                )
                db.add(finding)
            
            scan.findings_count = len(result.findings)
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
            db.commit()
            
            return {'status': 'completed', 'findings': len(result.findings)}
            
        except Exception as e:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.FAILED
                scan.error_message = str(e)
                scan.completed_at = datetime.utcnow()
                db.commit()
            raise
    
    return asyncio.run(_run())