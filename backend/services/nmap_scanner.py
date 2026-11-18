"""Nmap scanner implementation"""
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional
import asyncio
import json
import re
from datetime import datetime

from services.scanner_base import BaseScanner, ScanResult, ScanFinding, ScannerRegistry


class NmapScanner(BaseScanner):
    """Nmap network/port scanner"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "NmapScanner"
        self.version = "1.0.0"
        self.nmap_path = config.get('nmap_path', 'nmap') if config else 'nmap'
    
    def validate_target(self, target: str) -> bool:
        """Nmap can scan IPs, hostnames, CIDR ranges"""
        return bool(target and len(target) > 0)
    
    def _build_nmap_args(self, target: str, options: Dict[str, Any]) -> List[str]:
        """Build nmap command line arguments"""
        args = [self.nmap_path]
        
        # Output format
        args.extend(['-oX', '-'])  # XML output to stdout
        
        # Intensity
        intensity = options.get('intensity', 'normal')
        if intensity == 'light':
            args.extend(['-T3', '--top-ports', '100'])
        elif intensity == 'aggressive':
            args.extend(['-T4', '-A', '-p-', '--script', 'vuln'])
        else:  # normal
            args.extend(['-T4', '-sV', '-sC', '--top-ports', '1000'])
        
        # Scan type specific
        scan_type = options.get('scan_type', 'port')
        if scan_type == 'network':
            args.extend(['-sS', '-sV', '-O', '--script', 'vuln,auth,default'])
        elif scan_type == 'subdomain':
            args.extend(['-sn', '--script', 'dns-brute,dns-zone-transfer'])
        elif scan_type == 'recon':
            args.extend(['-sV', '-sC', '-A', '--script', 'discovery'])
        
        # Custom ports
        if options.get('ports'):
            args.extend(['-p', options['ports']])
        
        # Exclude hosts
        if options.get('exclude'):
            args.extend(['--exclude', options['exclude']])
        
        # Timing
        if options.get('timing'):
            args.extend(['-T', str(options['timing'])])
        
        # Additional scripts
        if options.get('scripts'):
            args.extend(['--script', ','.join(options['scripts'])])
        
        # Verbosity
        if options.get('verbose'):
            args.append('-v')
        
        # Target
        args.append(target)
        
        return args
    
    def _parse_nmap_xml(self, xml_output: str) -> List[ScanFinding]:
        """Parse nmap XML output into findings"""
        findings = []
        
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as e:
            return [ScanFinding(
                title="Nmap XML Parse Error",
                description=f"Failed to parse nmap XML output: {e}",
                severity="info",
                source_scanner="NmapScanner",
                evidence={"error": str(e), "raw_xml": xml_output[:1000]},
            )]
        
        for host in root.findall('host'):
            # Get host address
            address_elem = host.find('address')
            host_ip = address_elem.get('addr') if address_elem is not None else 'unknown'
            hostnames = []
            hostnames_elem = host.find('hostnames')
            if hostnames_elem is not None:
                for hn in hostnames_elem.findall('hostname'):
                    hostnames.append(hn.get('name'))
            
            # Check if host is up
            status_elem = host.find('status')
            if status_elem is not None and status_elem.get('state') != 'up':
                continue
            
            # Parse ports
            ports_elem = host.find('ports')
            if ports_elem is not None:
                for port in ports_elem.findall('port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    
                    state_elem = port.find('state')
                    state = state_elem.get('state') if state_elem is not None else 'unknown'
                    
                    if state != 'open':
                        continue
                    
                    service_elem = port.find('service')
                    service_name = service_elem.get('name') if service_elem is not None else 'unknown'
                    service_product = service_elem.get('product') if service_elem is not None else ''
                    service_version = service_elem.get('version') if service_elem is not None else ''
                    service_extrainfo = service_elem.get('extrainfo') if service_elem is not None else ''
                    
                    # Build finding for open port
                    finding = ScanFinding(
                        title=f"Open Port: {port_id}/{protocol} ({service_name})",
                        description=f"Open port {port_id}/{protocol} running {service_name} "
                                  f"{service_product} {service_version} {service_extrainfo}".strip(),
                        severity=self._assess_port_severity(port_id, service_name),
                        target_url=f"{host_ip}:{port_id}",
                        parameter=f"protocol:{protocol}",
                        method=protocol.upper(),
                        path=f"/{port_id}",
                        evidence={
                            "host_ip": host_ip,
                            "hostnames": hostnames,
                            "port": port_id,
                            "protocol": protocol,
                            "service": {
                                "name": service_name,
                                "product": service_product,
                                "version": service_version,
                                "extrainfo": service_extrainfo,
                            },
                            "state": state,
                        },
                        reproduction_steps=f"Connect to {host_ip}:{port_id} using {protocol}",
                        source_scanner="NmapScanner",
                        source_finding_id=f"{host_ip}:{port_id}",
                        source_rule_id=f"nmap-port-{port_id}",
                        tags=["network", "port", service_name],
                    )
                    findings.append(finding)
            
            # Parse scripts
            for script in host.findall('.//script'):
                script_id = script.get('id')
                script_output = script.get('output', '')
                
                if 'vuln' in script_id.lower() or 'exploit' in script_id.lower():
                    # Vulnerability script output
                    finding = ScanFinding(
                        title=f"Nmap Script: {script_id}",
                        description=script_output[:500],
                        severity=self._assess_script_severity(script_id, script_output),
                        target_url=host_ip,
                        evidence={
                            "host_ip": host_ip,
                            "hostnames": hostnames,
                            "script_id": script_id,
                            "script_output": script_output,
                        },
                        reproduction_steps=f"Run nmap with --script {script_id} against {host_ip}",
                        source_scanner="NmapScanner",
                        source_finding_id=f"{host_ip}:{script_id}",
                        source_rule_id=f"nmap-script-{script_id}",
                        tags=["nmap", "script", "vulnerability"],
                    )
                    findings.append(finding)
            
            # OS detection
            os_elem = host.find('os')
            if os_elem is not None:
                for osmatch in os_elem.findall('osmatch'):
                    finding = ScanFinding(
                        title=f"OS Detection: {osmatch.get('name')}",
                        description=f"Operating system detected: {osmatch.get('name')} "
                                  f"(accuracy: {osmatch.get('accuracy')}%)",
                        severity="info",
                        target_url=host_ip,
                        evidence={
                            "host_ip": host_ip,
                            "os_name": osmatch.get('name'),
                            "accuracy": osmatch.get('accuracy'),
                            "os_class": [
                                {
                                    "type": oc.get('type'),
                                    "vendor": oc.get('vendor'),
                                    "osfamily": oc.get('osfamily'),
                                    "osgen": oc.get('osgen'),
                                }
                                for oc in osmatch.findall('osclass')
                            ],
                        },
                        source_scanner="NmapScanner",
                        source_finding_id=f"{host_ip}:os",
                        source_rule_id="nmap-os-detection",
                        tags=["os", "fingerprint"],
                    )
                    findings.append(finding)
        
        return findings
    
    def _assess_port_severity(self, port: str, service: str) -> str:
        """Assess severity based on port and service"""
        critical_ports = {'21', '22', '23', '135', '139', '445', '1433', '3306', '3389', '5432', '5900', '6379', '27017'}
        high_ports = {'80', '443', '8080', '8443', '3000', '5000', '8000', '9000'}
        
        if port in critical_ports:
            return 'high'
        elif port in high_ports or 'http' in service.lower():
            return 'medium'
        return 'low'
    
    def _assess_script_severity(self, script_id: str, output: str) -> str:
        """Assess severity from script output"""
        output_lower = output.lower()
        if any(kw in output_lower for kw in ['critical', 'exploit', 'rce', 'remote code execution']):
            return 'critical'
        elif any(kw in output_lower for kw in ['high', 'sql injection', 'xss', 'authentication bypass']):
            return 'high'
        elif any(kw in output_lower for kw in ['medium', 'disclosure', 'enumeration']):
            return 'medium'
        return 'low'
    
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        """Execute nmap scan"""
        scan_id = options.get('scan_id', 'unknown')
        started_at = datetime.utcnow()
        
        args = self._build_nmap_args(target, options)
        
        # Run nmap
        stdout, stderr, returncode = await self.run_command(args, timeout=options.get('timeout', 1800))
        
        completed_at = datetime.utcnow()
        duration = int((completed_at - started_at).total_seconds())
        
        if returncode != 0 and not stdout.strip():
            return ScanResult(
                scan_id=scan_id,
                scanner_name=self.name,
                status='failed',
                error_message=stderr or f"Nmap exited with code {returncode}",
                raw_output=stdout + stderr,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
            )
        
        # Parse results
        findings = self._parse_nmap_xml(stdout)
        
        return ScanResult(
            scan_id=scan_id,
            scanner_name=self.name,
            status='completed' if findings else 'completed',
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
            },
        )


# Register scanner
ScannerRegistry.register(NmapScanner())