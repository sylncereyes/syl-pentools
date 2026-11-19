"""Nuclei vulnerability scanner implementation"""
import json
from typing import Dict, Any, List, Optional
import asyncio
import re
from datetime import datetime

from services.scanner_base import BaseScanner, ScanResult, ScanFinding, ScannerRegistry


class NucleiScanner(BaseScanner):
    """Nuclei template-based vulnerability scanner"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "NucleiScanner"
        self.version = "1.0.0"
        # Read from settings if config not provided
        if config:
            self.nuclei_path = config.get('nuclei_path', 'nuclei')
            self.templates_path = config.get('templates_path', '/opt/nuclei-templates')
        else:
            from core.config import settings
            self.nuclei_path = getattr(settings, 'NUCLEI_PATH', 'nuclei')
            self.templates_path = getattr(settings, 'NUCLEI_TEMPLATES_PATH', '/opt/nuclei-templates')
    
    def validate_target(self, target: str) -> bool:
        """Nuclei works with URLs, hostnames, IPs"""
        return bool(target and len(target) > 0)
    
    def _build_nuclei_args(self, target: str, options: Dict[str, Any]) -> List[str]:
        """Build nuclei command line arguments"""
        args = [self.nuclei_path]
        
        # Output format - JSONL for streaming
        args.extend(['-jsonl'])
        
        # Target
        args.extend(['-u', target])
        
        # Templates
        if options.get('templates'):
            for t in options['templates']:
                args.extend(['-t', t])
        elif options.get('tags'):
            for tag in options['tags']:
                args.extend(['-tags', tag])
        elif options.get('severity'):
            args.extend(['-severity', ','.join(options['severity'])])
        else:
            # Default: all templates
            if self.templates_path:
                args.extend(['-t', self.templates_path])
        
        # Exclude
        if options.get('exclude_tags'):
            args.extend(['-exclude-tags', ','.join(options['exclude_tags'])])
        if options.get('exclude_templates'):
            for t in options['exclude_templates']:
                args.extend(['-exclude', t])
        
        # Rate limiting
        if options.get('rate_limit'):
            args.extend(['-rate-limit', str(options['rate_limit'])])
        if options.get('bulk_size'):
            args.extend(['-bulk-size', str(options['bulk_size'])])
        
        # Concurrency
        if options.get('concurrency'):
            args.extend(['-c', str(options['concurrency'])])
        
        # Timeout
        if options.get('timeout'):
            args.extend(['-timeout', str(options['timeout'])])
        if options.get('retries'):
            args.extend(['-retries', str(options['retries'])])
        
        # Headers
        if options.get('headers'):
            for k, v in options['headers'].items():
                args.extend(['-H', f'{k}: {v}'])
        
        # Cookies
        if options.get('cookies'):
            args.extend(['-cookie', options['cookies']])
        
        # Authentication
        if options.get('basic_auth'):
            args.extend(['-basic-auth', options['basic_auth']])
        
        # Proxy
        if options.get('proxy'):
            args.extend(['-proxy', options['proxy']])
        
        # Follow redirects
        if options.get('follow_redirects', True):
            args.append('-follow-redirects')
        else:
            args.append('-no-follow-redirects')
        
        # Max host error
        args.extend(['-max-host-error', '10'])
        
        # Silent mode (only output findings)
        args.append('-silent')
        
        # No color
        args.append('-no-color')
        
        return args
    
    def _parse_nuclei_jsonl(self, output: str) -> List[ScanFinding]:
        """Parse nuclei JSONL output into findings"""
        findings = []
        
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            # Extract template info
            template = result.get('template', '')
            template_id = result.get('template-id', '')
            template_path = result.get('template-path', '')
            
            info = result.get('info', {})
            name = info.get('name', template_id)
            severity = info.get('severity', 'info').lower()
            description = info.get('description', '')
            reference = info.get('reference', [])
            tags = info.get('tags', [])
            authors = info.get('author', [])
            metadata = info.get('metadata', {})
            
            # Extract matched details
            matched = result.get('matched-at', '')
            matched_line = result.get('matched-line', '')
            extracted = result.get('extracted-results', [])
            curl_command = result.get('curl-command', '')
            
            # Request/response
            request = result.get('request', '')
            response = result.get('response', '')
            
            # Host/IP
            host = result.get('host', '')
            ip = result.get('ip', '')
            
            # Build finding
            finding = ScanFinding(
                title=f"Nuclei: {name}" if name else f"Nuclei: {template_id}",
                description=description or f"Template {template_id} matched",
                severity=self._normalize_severity(severity),
                target_url=matched,
                evidence={
                    "template": template,
                    "template_id": template_id,
                    "template_path": template_path,
                    "matched_at": matched,
                    "matched_line": matched_line,
                    "extracted_results": extracted,
                    "curl_command": curl_command,
                    "request": request[:2000] if request else '',
                    "response": response[:2000] if response else '',
                    "host": host,
                    "ip": ip,
                    "tags": tags,
                    "authors": authors,
                    "metadata": metadata,
                    "reference": reference,
                },
                reproduction_steps=f"Run nuclei with template {template_id} against target",
                remediation=info.get('remediation', ''),
                cwe_id=self._extract_cwe(metadata),
                cvss_score=self._extract_cvss(metadata),
                source_scanner="NucleiScanner",
                source_finding_id=f"{host}:{template_id}",
                source_rule_id=template_id,
                tags=["nuclei"] + tags,
            )
            findings.append(finding)
        
        return findings
    
    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity to our standard"""
        severity_map = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'info',
            'unknown': 'info',
        }
        return severity_map.get(severity.lower(), 'info')
    
    def _extract_cwe(self, metadata: Dict) -> str:
        """Extract CWE from metadata"""
        if 'cwe' in metadata:
            cwe = metadata['cwe']
            if isinstance(cwe, list):
                return cwe[0] if cwe else ''
            return str(cwe)
        return ''
    
    def _extract_cvss(self, metadata: Dict) -> Optional[float]:
        """Extract CVSS score from metadata"""
        for key in ['cvss', 'cvss-score', 'cvss_score']:
            if key in metadata:
                try:
                    return float(metadata[key])
                except (ValueError, TypeError):
                    pass
        return None
    
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        """Execute nuclei scan"""
        scan_id = options.get('scan_id', 'unknown')
        started_at = datetime.utcnow()
        
        args = self._build_nuclei_args(target, options)
        
        # Run nuclei
        stdout, stderr, returncode = await self.run_command(args, timeout=options.get('timeout', 1800))
        
        completed_at = datetime.utcnow()
        duration = int((completed_at - started_at).total_seconds())
        
        # Nuclei returns 0 even if no findings, non-zero on error
        if returncode != 0 and not stdout.strip():
            return ScanResult(
                scan_id=scan_id,
                scanner_name=self.name,
                status='failed',
                error_message=stderr or f"Nuclei exited with code {returncode}",
                raw_output=stdout + stderr,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
            )
        
        # Parse results
        findings = self._parse_nuclei_jsonl(stdout)
        
        return ScanResult(
            scan_id=scan_id,
            scanner_name=self.name,
            status='completed',
            findings=findings,
            raw_output=stdout,
            error_message=stderr if stderr else None,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            metadata={
                'target': target,
                'args': ' '.join(args),
                'returncode': returncode,
                'finding_count': len(findings),
            },
        )


# Register scanner
# Register with config from settings
from core.config import settings
nuclei_config = {
    'nuclei_path': getattr(settings, 'NUCLEI_PATH', 'nuclei'),
    'templates_path': getattr(settings, 'NUCLEI_TEMPLATES_PATH', '/opt/nuclei-templates'),
}
ScannerRegistry.register(NucleiScanner(nuclei_config))