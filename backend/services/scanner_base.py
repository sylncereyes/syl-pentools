"""Base scanner classes and utilities"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import subprocess
import tempfile
import os
import asyncio
import uuid

@dataclass
class ScanFinding:
    """Standardized finding from any scanner"""
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    target_url: str = ""
    parameter: str = ""
    method: str = ""
    path: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    reproduction_steps: str = ""
    proof_of_concept: str = ""
    remediation: str = ""
    cwe_id: str = ""
    cve_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    source_scanner: str = ""
    source_finding_id: str = ""
    source_rule_id: str = ""
    tags: List[str] = field(default_factory=list)
    compliance_mappings: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanResult:
    """Result of a scan"""
    scan_id: str
    scanner_name: str
    status: str  # completed, failed, partial
    findings: List[ScanFinding] = field(default_factory=list)
    raw_output: str = ""
    error_message: str = ""
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    duration_seconds: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

class BaseScanner(ABC):
    """Abstract base class for all scanners"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.name = self.__class__.__name__
        self.version = "1.0.0"
    
    @abstractmethod
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        """Execute scan against target"""
        pass
    
    @abstractmethod
    def validate_target(self, target: str) -> bool:
        """Validate if target is suitable for this scanner"""
        pass
    
    async def run_command(self, cmd: List[str], timeout: int = 300) -> tuple:
        """Run command and return (stdout, stderr, returncode)"""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return stdout.decode('utf-8', errors='ignore'), stderr.decode('utf-8', errors='ignore'), proc.returncode
        except asyncio.TimeoutError:
            return "", f"Command timed out after {timeout}s", -1
        except Exception as e:
            return "", str(e), -1
    
    def parse_json_output(self, output: str) -> List[Dict]:
        """Parse JSON output, handling both single JSON and JSONL"""
        results = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return results

class ScannerRegistry:
    """Registry for all available scanners"""
    
    _scanners: Dict[str, BaseScanner] = {}
    
    @classmethod
    def register(cls, scanner: BaseScanner):
        cls._scanners[scanner.name.lower()] = scanner
    
    @classmethod
    def get(cls, name: str) -> Optional[BaseScanner]:
        return cls._scanners.get(name.lower())
    
    @classmethod
    def get_all(cls) -> Dict[str, BaseScanner]:
        return cls._scanners.copy()
    
    @classmethod
    def get_by_type(cls, scan_type: str) -> List[BaseScanner]:
        """Get scanners suitable for a scan type"""
        type_map = {
            'network': ['NmapScanner', 'NucleiScanner'],
            'port': ['NmapScanner'],
            'website': ['NucleiScanner', 'SQLMapScanner'],
            'subdomain': ['NmapScanner', 'NucleiScanner'],
            'recon': ['NmapScanner', 'NucleiScanner'],
            'password': ['PasswordAuditorScanner'],
            'fuzzer': ['URLFuzzerScanner'],
            'google_hacking': ['GoogleHackingScanner'],
            'people_hunter': ['PeopleHunterScanner'],
            'domain_finder': ['DomainFinderScanner'],
            'vhost': ['VHostScanner'],
            'http_logger': ['HTTPRequestLoggerScanner'],
        }
        scanner_names = type_map.get(scan_type, [])
        return [cls._scanners.get(n.lower()) for n in scanner_names if n.lower() in cls._scanners]