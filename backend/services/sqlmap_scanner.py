"""SQLMap SQL injection scanner implementation"""
import json
import re
from typing import Dict, Any, List, Optional
import asyncio
from datetime import datetime

from services.scanner_base import BaseScanner, ScanResult, ScanFinding, ScannerRegistry


class SQLMapScanner(BaseScanner):
    """SQLMap SQL injection scanner"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "SQLMapScanner"
        self.version = "1.0.0"
        self.sqlmap_path = config.get('sqlmap_path', 'sqlmap') if config else 'sqlmap'
    
    def validate_target(self, target: str) -> bool:
        """SQLMap requires a URL with parameters"""
        return bool(target and ('?' in target or '=' in target))
    
    def _build_sqlmap_args(self, target: str, options: Dict[str, Any]) -> List[str]:
        """Build sqlmap command line arguments"""
        args = [self.sqlmap_path]
        
        # Target URL
        args.extend(['-u', target])
        
        # Output directory for JSON
        import tempfile
        output_dir = tempfile.mkdtemp(prefix='sqlmap_')
        args.extend(['--output-dir', output_dir])
        
        # Batch mode (no interaction)
        args.append('--batch')
        
        # JSON output
        args.extend(['--json', f'{output_dir}/results.json'])
        
        # Crawl
        if options.get('crawl'):
            args.extend(['--crawl', str(options['crawl'])])
        
        # Forms
        if options.get('forms', True):
            args.append('--forms')
        
        # Level and risk
        level = options.get('level', 1)
        args.extend(['--level', str(level)])
        
        risk = options.get('risk', 1)
        args.extend(['--risk', str(risk)])
        
        # Techniques
        if options.get('technique'):
            args.extend(['--technique', options['technique']])
        else:
            args.extend(['--technique', 'BEUSTQ'])  # All techniques
        
        # DBMS
        if options.get('dbms'):
            args.extend(['--dbms', options['dbms']])
        
        # Threads
        if options.get('threads'):
            args.extend(['--threads', str(options['threads'])])
        else:
            args.extend(['--threads', '4'])
        
        # Timeouts
        if options.get('timeout'):
            args.extend(['--timeout', str(options['timeout'])])
        
        # Headers
        if options.get('headers'):
            for k, v in options['headers'].items():
                args.extend(['-H', f'{k}: {v}'])
        
        # Cookies
        if options.get('cookies'):
            args.extend(['--cookie', options['cookies']])
        
        # Proxy
        if options.get('proxy'):
            args.extend(['--proxy', options['proxy']])
        
        # Randomize user agent
        args.append('--random-agent')
        
        # Skip WAF detection
        if options.get('skip_waf'):
            args.append('--skip-waf')
        
        # Fresh queries
        args.append('--fresh-queries')
        
        # No color
        args.append('--no-color')
        
        return args
    
    def _parse_sqlmap_json(self, output_dir: str) -> List[ScanFinding]:
        """Parse sqlmap JSON output"""
        import os
        findings = []
        
        json_path = os.path.join(output_dir, 'results.json')
        if not os.path.exists(json_path):
            return findings
        
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return findings
        
        # Parse results
        for url, result in data.items():
            if not isinstance(result, dict):
                continue
            
            # Check for injection points
            if 'injection' not in result:
                continue
            
            for param, injections in result['injection'].items():
                if not isinstance(injections, list):
                    continue
                
                for inj in injections:
                    if not isinstance(inj, dict):
                        continue
                    
                    # Extract injection details
                    param_name = param
                    param_type = inj.get('type', '')
                    param_place = inj.get('place', '')
                    payload = inj.get('payload', '')
                    title = inj.get('title', '')
                    vector = inj.get('vector', '')
                    
                    # DBMS info
                    dbms = result.get('dbms', [])
                    dbms_str = ', '.join(dbms) if dbms else 'Unknown'
                    
                    # Build finding
                    finding = ScanFinding(
                        title=f"SQL Injection in {param_name} ({param_type})",
                        description=f"SQL injection vulnerability found in parameter '{param_name}' "
                                  f"via {param_type} ({param_place}). DBMS: {dbms_str}",
                        severity='high',  # SQLi is typically high/critical
                        target_url=url,
                        parameter=param_name,
                        method=inj.get('method', 'GET'),
                        path=url.split('?')[0] if '?' in url else url,
                        evidence={
                            "url": url,
                            "parameter": param_name,
                            "parameter_type": param_type,
                            "parameter_place": param_place,
                            "payload": payload,
                            "title": title,
                            "vector": vector,
                            "dbms": dbms,
                            "injection_details": inj,
                        },
                        reproduction_steps=f"Use sqlmap with payload: {payload}",
                        proof_of_concept=payload,
                        remediation="Use parameterized queries / prepared statements. "
                                  "Implement input validation and sanitization. "
                                  "Apply principle of least privilege for database accounts.",
                        cwe_id="CWE-89",
                        cvss_score=8.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        source_scanner="SQLMapScanner",
                        source_finding_id=f"{url}:{param_name}",
                        source_rule_id="sqlmap-sqli",
                        tags=["sqli", "sql-injection", "web", "database"],
                    )
                    findings.append(finding)
        
        return findings
    
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        """Execute sqlmap scan"""
        scan_id = options.get('scan_id', 'unknown')
        started_at = datetime.utcnow()
        
        args = self._build_sqlmap_args(target, options)
        
        # Run sqlmap
        stdout, stderr, returncode = await self.run_command(args, timeout=options.get('timeout', 3600))
        
        completed_at = datetime.utcnow()
        duration = int((completed_at - started_at).total_seconds())
        
        # Parse JSON results from output directory
        # Extract output dir from args
        output_dir = None
        for i, arg in enumerate(args):
            if arg == '--output-dir' and i + 1 < len(args):
                output_dir = args[i + 1]
                break
        
        findings = self._parse_sqlmap_json(output_dir) if output_dir else []
        
        # Determine status
        status = 'completed'
        if returncode != 0 and not findings:
            status = 'failed'
        elif returncode != 0:
            status = 'partial'
        
        return ScanResult(
            scan_id=scan_id,
            scanner_name=self.name,
            status=status,
            findings=findings,
            raw_output=stdout + stderr,
            error_message=stderr if stderr and returncode != 0 else None,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=int((completed_at - started_at).total_seconds()),
            metadata={
                'target': target,
                'args': ' '.join(args),
                'returncode': returncode,
                'finding_count': len(findings),
            },
        )


# Register scanner
ScannerRegistry.register(SQLMapScanner())