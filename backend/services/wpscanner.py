"""WordPress/Drupal scanner using WPScan and Nuclei CMS templates"""
import json
import asyncio
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from services.scanner_base import BaseScanner, ScanResult, ScanFinding, ScannerRegistry
from core.database import get_sync_db
from models.finding import FindingSeverity
from sqlalchemy.orm import Session


@dataclass
class WordPressInfo:
    version: str
    plugins: List[Dict]
    themes: List[Dict]
    users: List[str]
    config_backups: List[str]
    wp_json_accessible: bool
    xmlrpc_enabled: bool


class WPScanScanner(BaseScanner):
    """WPScan wrapper for WordPress vulnerability scanning"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "WPScanScanner"
        self.version = "1.0.0"
        self.wpscan_path = config.get('wpscan_path', 'wpscan') if config else 'wpscan'
        self.api_token = config.get('wpscan_api_token') if config else None
    
    def validate_target(self, target: str) -> bool:
        """WPScan requires a WordPress site URL"""
        return bool(target and ('http' in target))
    
    def _build_wpscan_args(self, target: str, options: Dict[str, Any]) -> List[str]:
        args = [self.wpscan_path]
        
        # Target
        args.extend(['--url', target])
        
        # Output format
        args.extend(['--format', 'json'])
        
        # API token for vulnerability database
        if self.api_token:
            args.extend(['--api-token', self.api_token])
        
        # Scan options
        if options.get('enumerate_plugins', True):
            args.append('--enumerate', 'p')
        if options.get('enumerate_themes', True):
            args.append('--enumerate', 't')
        if options.get('enumerate_users', True):
            args.append('--enumerate', 'u')
        if options.get('enumerate_backups', True):
            args.append('--enumerate', 'b')
        if options.get('enumerate_config_backups', True):
            args.append('--enumerate', 'cb')
        if options.get('enumerate_db_exports', True):
            args.append('--enumerate', 'dbe')
        if options.get('enumerate_timthumbs', True):
            args.append('--enumerate', 'tt')
        
        # Detection mode
        detection_mode = options.get('detection_mode', 'mixed')
        args.extend(['--detection-mode', detection_mode])
        
        # Plugins/themes detection
        if options.get('plugins_detection', 'passive') != 'passive':
            args.extend(['--plugins-detection', options['plugins_detection']])
        
        # Max threads
        if options.get('max_threads'):
            args.extend(['--max-threads', str(options['max_threads'])])
        
        # Timeout
        if options.get('timeout'):
            args.extend(['--timeout', str(options['timeout'])])
        
        # Force scan even if not WordPress
        if options.get('force', False):
            args.append('--force')
        
        # Disable TLS checks for testing
        if options.get('disable_tls_checks', False):
            args.append('--disable-tls-checks')
        
        # Random user agent
        args.append('--random-user-agent')
        
        # No banner
        args.append('--no-banner')
        
        # No color
        args.append('--no-color')
        
        return args
    
    def _parse_wpscan_json(self, output: str, target: str) -> List[ScanFinding]:
        findings = []
        
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return findings
        
        # Version vulnerability
        if 'version' in data:
            version_info = data['version']
            if version_info.get('vulnerabilities'):
                for vuln in version_info['vulnerabilities']:
                    finding = ScanFinding(
                        title=f"WordPress Core Vulnerability: {vuln.get('title', 'Unknown')}",
                        description=vuln.get('description', ''),
                        severity=self._map_severity(vuln.get('cvss', {}).get('score', 0)),
                        target_url=target,
                        evidence={
                            'component': 'wordpress_core',
                            'version': version_info.get('number'),
                            'vulnerability': vuln,
                        },
                        cve_ids=[vuln.get('cve')] if vuln.get('cve') else [],
                        cvss_score=vuln.get('cvss', {}).get('score'),
                        cvss_vector=vuln.get('cvss', {}).get('vector'),
                        source_scanner="WPScanScanner",
                        source_finding_id=f"wp_core_{vuln.get('id', 'unknown')}",
                        source_rule_id="wpscan-core",
                        tags=["wordpress", "core", "cms"],
                    )
                    findings.append(finding)
        
        # Plugin vulnerabilities
        if 'plugins' in data:
            for plugin_slug, plugin_info in data['plugins'].items():
                if plugin_info.get('vulnerabilities'):
                    for vuln in plugin_info['vulnerabilities']:
                        finding = ScanFinding(
                            title=f"WordPress Plugin Vulnerability: {plugin_info.get('name', plugin_slug)}",
                            description=vuln.get('description', ''),
                            severity=self._map_severity(vuln.get('cvss', {}).get('score', 0)),
                            target_url=target,
                            evidence={
                                'component': 'plugin',
                                'plugin_slug': plugin_slug,
                                'plugin_name': plugin_info.get('name'),
                                'plugin_version': plugin_info.get('version'),
                                'vulnerability': vuln,
                            },
                            cve_ids=[vuln.get('cve')] if vuln.get('cve') else [],
                            cvss_score=vuln.get('cvss', {}).get('score'),
                            cvss_vector=vuln.get('cvss', {}).get('vector'),
                            source_scanner="WPScanScanner",
                            source_finding_id=f"wp_plugin_{plugin_slug}_{vuln.get('id', 'unknown')}",
                            source_rule_id="wpscan-plugin",
                            tags=["wordpress", "plugin", "cms"],
                        )
                        findings.append(finding)
        
        # Theme vulnerabilities
        if 'themes' in data:
            for theme_slug, theme_info in data['themes'].items():
                if theme_info.get('vulnerabilities'):
                    for vuln in theme_info['vulnerabilities']:
                        finding = ScanFinding(
                            title=f"WordPress Theme Vulnerability: {theme_info.get('name', theme_slug)}",
                            description=vuln.get('description', ''),
                            severity=self._map_severity(vuln.get('cvss', {}).get('score', 0)),
                            target_url=target,
                            evidence={
                                'component': 'theme',
                                'theme_slug': theme_slug,
                                'theme_name': theme_info.get('name'),
                                'theme_version': theme_info.get('version'),
                                'vulnerability': vuln,
                            },
                            cve_ids=[vuln.get('cve')] if vuln.get('cve') else [],
                            cvss_score=vuln.get('cvss', {}).get('score'),
                            cvss_vector=vuln.get('cvss', {}).get('vector'),
                            source_scanner="WPScanScanner",
                            source_finding_id=f"wp_theme_{theme_slug}_{vuln.get('id', 'unknown')}",
                            source_rule_id="wpscan-theme",
                            tags=["wordpress", "theme", "cms"],
                        )
                        findings.append(finding)
        
        # User enumeration
        if 'users' in data:
            for user in data['users']:
                finding = ScanFinding(
                    title=f"WordPress User Enumerated: {user.get('username', 'unknown')}",
                    description=f"User '{user.get('username')}' found via enumeration",
                    severity='info',
                    target_url=target,
                    evidence={
                        'component': 'user_enumeration',
                        'username': user.get('username'),
                        'id': user.get('id'),
                    },
                    source_scanner="WPScanScanner",
                    source_finding_id=f"wp_user_{user.get('username')}",
                    source_rule_id="wpscan-user-enum",
                    tags=["wordpress", "user-enumeration", "information-disclosure"],
                )
                findings.append(finding)
        
        # Backup files
        if 'backups' in data and data['backups']:
            finding = ScanFinding(
                title="WordPress Backup Files Found",
                description=f"Found {len(data['backups'])} accessible backup files",
                severity='medium',
                target_url=target,
                evidence={
                    'component': 'backup_files',
                    'backups': data['backups'],
                },
                source_scanner="WPScanScanner",
                source_finding_id="wp_backups",
                source_rule_id="wpscan-backups",
                tags=["wordpress", "backup", "information-disclosure"],
            )
            findings.append(finding)
        
        # Config backups
        if 'config_backups' in data and data['config_backups']:
            finding = ScanFinding(
                title="WordPress Config Backup Files Found",
                description=f"Found {len(data['config_backups'])} accessible wp-config.php backup files",
                severity='high',
                target_url=target,
                evidence={
                    'component': 'config_backups',
                    'backups': data['config_backups'],
                },
                source_scanner="WPScanScanner",
                source_finding_id="wp_config_backups",
                source_rule_id="wpscan-config-backups",
                tags=["wordpress", "config-backup", "sensitive-data"],
            )
            findings.append(finding)
        
        # XML-RPC
        if data.get('xmlrpc_enabled'):
            finding = ScanFinding(
                title="XML-RPC Enabled",
                description="XML-RPC interface is enabled, which can be used for brute force attacks",
                severity='low',
                target_url=f"{target}/xmlrpc.php",
                evidence={
                    'component': 'xmlrpc',
                    'enabled': True,
                },
                remediation="Disable XML-RPC if not needed, or restrict access via .htaccess",
                source_scanner="WPScanScanner",
                source_finding_id="wp_xmlrpc",
                source_rule_id="wpscan-xmlrpc",
                tags=["wordpress", "xmlrpc", "brute-force"],
            )
            findings.append(finding)
        
        # WP-JSON REST API
        if data.get('wp_json_accessible'):
            finding = ScanFinding(
                title="WordPress REST API (wp-json) Accessible",
                description="The WordPress REST API is accessible, which may leak information",
                severity='info',
                target_url=f"{target}/wp-json/",
                evidence={
                    'component': 'rest_api',
                    'accessible': True,
                },
                source_scanner="WPScanScanner",
                source_finding_id="wp_rest_api",
                source_rule_id="wpscan-rest-api",
                tags=["wordpress", "rest-api", "information-disclosure"],
            )
            findings.append(finding)
        
        return findings
    
    def _map_severity(self, cvss_score: float) -> str:
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        elif cvss_score > 0:
            return 'low'
        return 'info'
    
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        scan_id = options.get('scan_id', 'unknown')
        started_at = datetime.utcnow()
        
        args = self._build_wpscan_args(target, options)
        
        stdout, stderr, returncode = await self.run_command(args, timeout=options.get('timeout', 600))
        
        completed_at = datetime.utcnow()
        duration = int((completed_at - started_at).total_seconds())
        
        if returncode not in [0, 5]:  # WPScan returns 5 when vulnerabilities found
            return ScanResult(
                scan_id=scan_id,
                scanner_name=self.name,
                status='failed',
                error_message=stderr or f"WPScan exited with code {returncode}",
                raw_output=stdout + stderr,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
            )
        
        findings = self._parse_wpscan_json(stdout, target)
        
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


class DrupalScanner(BaseScanner):
    """Drupal vulnerability scanner using Droopescan and Nuclei"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "DrupalScanner"
        self.version = "1.0.0"
        self.droopescan_path = config.get('droopescan_path', 'droopescan') if config else 'droopescan'
    
    def validate_target(self, target: str) -> bool:
        return bool(target and ('http' in target))
    
    def _build_droopescan_args(self, target: str, options: Dict[str, Any]) -> List[str]:
        args = [self.droopescan_path, 'scan', 'drupal']
        
        args.extend(['-u', target])
        args.extend(['--output', 'json'])
        
        if options.get('enumerate_modules', True):
            args.append('--enumerate', 'm')
        if options.get('enumerate_themes', True):
            args.append('--enumerate', 't')
        
        if options.get('threads'):
            args.extend(['--number-of-threads', str(options['threads'])])
        
        return args
    
    def _parse_droopescan_json(self, output: str, target: str) -> List[ScanFinding]:
        findings = []
        
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return findings
        
        # Version
        if 'version' in data:
            version = data['version']
            if version.get('vulnerabilities'):
                for vuln in version['vulnerabilities']:
                    finding = ScanFinding(
                        title=f"Drupal Core Vulnerability: {vuln.get('title', 'Unknown')}",
                        description=vuln.get('description', ''),
                        severity=self._map_severity(vuln.get('cvss', 0)),
                        target_url=target,
                        evidence={
                            'component': 'drupal_core',
                            'version': version.get('version'),
                            'vulnerability': vuln,
                        },
                        cve_ids=[vuln.get('cve')] if vuln.get('cve') else [],
                        cvss_score=vuln.get('cvss'),
                        source_scanner="DrupalScanner",
                        source_finding_id=f"drupal_core_{vuln.get('id', 'unknown')}",
                        source_rule_id="droopescan-core",
                        tags=["drupal", "core", "cms"],
                    )
                    findings.append(finding)
        
        # Modules
        if 'modules' in data:
            for module in data['modules']:
                if module.get('vulnerabilities'):
                    for vuln in module['vulnerabilities']:
                        finding = ScanFinding(
                            title=f"Drupal Module Vulnerability: {module.get('name', 'unknown')}",
                            description=vuln.get('description', ''),
                            severity=self._map_severity(vuln.get('cvss', 0)),
                            target_url=target,
                            evidence={
                                'component': 'module',
                                'module_name': module.get('name'),
                                'module_version': module.get('version'),
                                'vulnerability': vuln,
                            },
                            cve_ids=[vuln.get('cve')] if vuln.get('cve') else [],
                            cvss_score=vuln.get('cvss'),
                            source_scanner="DrupalScanner",
                            source_finding_id=f"drupal_module_{module.get('name')}_{vuln.get('id', 'unknown')}",
                            source_rule_id="droopescan-module",
                            tags=["drupal", "module", "cms"],
                        )
                        findings.append(finding)
        
        # Themes
        if 'themes' in data:
            for theme in data['themes']:
                if theme.get('vulnerabilities'):
                    for vuln in theme['vulnerabilities']:
                        finding = ScanFinding(
                            title=f"Drupal Theme Vulnerability: {theme.get('name', 'unknown')}",
                            description=vuln.get('description', ''),
                            severity=self._map_severity(vuln.get('cvss', 0)),
                            target_url=target,
                            evidence={
                                'component': 'theme',
                                'theme_name': theme.get('name'),
                                'theme_version': theme.get('version'),
                                'vulnerability': vuln,
                            },
                            cve_ids=[vuln.get('cve')] if vuln.get('cve') else [],
                            cvss_score=vuln.get('cvss'),
                            source_scanner="DrupalScanner",
                            source_finding_id=f"drupal_theme_{theme.get('name')}_{vuln.get('id', 'unknown')}",
                            source_rule_id="droopescan-theme",
                            tags=["drupal", "theme", "cms"],
                        )
                        findings.append(finding)
        
        return findings
    
    def _map_severity(self, cvss_score: float) -> str:
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        elif cvss_score > 0:
            return 'low'
        return 'info'
    
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        scan_id = options.get('scan_id', 'unknown')
        started_at = datetime.utcnow()
        
        args = self._build_droopescan_args(target, options)
        
        stdout, stderr, returncode = await self.run_command(args, timeout=options.get('timeout', 300))
        
        completed_at = datetime.utcnow()
        duration = int((completed_at - started_at).total_seconds())
        
        if returncode != 0 and not stdout.strip():
            return ScanResult(
                scan_id=scan_id,
                scanner_name=self.name,
                status='failed',
                error_message=stderr or f"Droopescan exited with code {returncode}",
                raw_output=stdout + stderr,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
            )
        
        findings = self._parse_droopescan_json(stdout, target)
        
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


class NucleiCMSScanner(BaseScanner):
    """Nuclei scanner with CMS-specific templates"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "NucleiCMSScanner"
        self.version = "1.0.0"
        self.nuclei_path = config.get('nuclei_path', 'nuclei') if config else 'nuclei'
        self.templates_path = config.get('templates_path', '/opt/nuclei-templates') if config else '/opt/nuclei-templates'
    
    def validate_target(self, target: str) -> bool:
        return bool(target and ('http' in target))
    
    def _build_nuclei_args(self, target: str, options: Dict[str, Any]) -> List[str]:
        args = [self.nuclei_path]
        
        args.extend(['-jsonl'])
        args.extend(['-u', target])
        
        # CMS-specific tags
        cms_tags = options.get('cms_tags', ['wordpress', 'drupal', 'joomla', 'cms'])
        for tag in cms_tags:
            args.extend(['-tags', tag])
        
        # Also include common web vuln tags
        if options.get('include_web_vulns', True):
            web_tags = ['xss', 'sqli', 'rce', 'lfi', 'rfi', 'ssrf', 'xxe', 'ssti', 'idor']
            for tag in web_tags:
                args.extend(['-tags', tag])
        
        # Exclude info/low if not wanted
        if not options.get('include_info', False):
            args.extend(['-severity', 'low,medium,high,critical'])
        else:
            args.extend(['-severity', 'info,low,medium,high,critical'])
        
        # Rate limiting
        if options.get('rate_limit'):
            args.extend(['-rate-limit', str(options['rate_limit'])])
        
        # Concurrency
        if options.get('concurrency'):
            args.extend(['-c', str(options['concurrency'])])
        
        # Timeout
        if options.get('timeout'):
            args.extend(['-timeout', str(options['timeout'])])
        
        # Headers
        if options.get('headers'):
            for k, v in options['headers'].items():
                args.extend(['-H', f'{k}: {v}'])
        
        # Cookies
        if options.get('cookies'):
            args.extend(['-cookie', options['cookies']])
        
        # Auth
        if options.get('basic_auth'):
            args.extend(['-basic-auth', options['basic_auth']])
        
        # Silent mode
        args.append('-silent')
        args.append('-no-color')
        
        return args
    
    def _parse_nuclei_jsonl(self, output: str, target: str) -> List[ScanFinding]:
        findings = []
        
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                continue
            
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
            
            matched = result.get('matched-at', '')
            matched_line = result.get('matched-line', '')
            extracted = result.get('extracted-results', [])
            curl_command = result.get('curl-command', '')
            
            request = result.get('request', '')
            response = result.get('response', '')
            
            host = result.get('host', '')
            ip = result.get('ip', '')
            
            finding = ScanFinding(
                title=f"Nuclei CMS: {name}" if name else f"Nuclei CMS: {template_id}",
                description=description or f"CMS template {template_id} matched",
                severity=self._map_severity(severity),
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
                source_scanner="NucleiCMSScanner",
                source_finding_id=f"{host}:{template_id}",
                source_rule_id=template_id,
                tags=["nuclei", "cms"] + tags,
            )
            findings.append(finding)
        
        return findings
    
    def _map_severity(self, severity: str) -> str:
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
        if 'cwe' in metadata:
            cwe = metadata['cwe']
            if isinstance(cwe, list):
                return cwe[0] if cwe else ''
            return str(cwe)
        return ''
    
    def _extract_cvss(self, metadata: Dict) -> Optional[float]:
        for key in ['cvss', 'cvss-score', 'cvss_score']:
            if key in metadata:
                try:
                    return float(metadata[key])
                except (ValueError, TypeError):
                    pass
        return None
    
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        scan_id = options.get('scan_id', 'unknown')
        started_at = datetime.utcnow()
        
        args = self._build_nuclei_args(target, options)
        
        stdout, stderr, returncode = await self.run_command(args, timeout=options.get('timeout', 300))
        
        completed_at = datetime.utcnow()
        duration = int((completed_at - started_at).total_seconds())
        
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
        
        findings = self._parse_nuclei_jsonl(stdout, target)
        
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


# Register all CMS scanners
ScannerRegistry.register(WPScanScanner())
ScannerRegistry.register(DrupalScanner())
ScannerRegistry.register(NucleiCMSScanner())