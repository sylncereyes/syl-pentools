"""Compliance frameworks and mappings"""
from enum import Enum
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
import json


class ComplianceFramework(str, Enum):
    PCI_DSS = "pci_dss"
    ISO_27001 = "iso_27001"
    SOC2 = "soc2"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    NIST_CSF = "nist_csf"
    NIST_800_53 = "nist_800_53"


@dataclass
class ComplianceRequirement:
    """Single compliance requirement"""
    framework: ComplianceFramework
    requirement_id: str
    title: str
    description: str
    category: str
    severity: str  # critical, high, medium, low
    related_cwes: List[str] = field(default_factory=list)
    related_cves: List[str] = field(default_factory=list)
    test_procedures: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


class ComplianceFrameworks:
    """Registry of all compliance frameworks"""
    
    _frameworks: Dict[ComplianceFramework, List[ComplianceRequirement]] = {}
    _cwe_to_requirements: Dict[str, List[ComplianceRequirement]] = {}
    _cve_to_requirements: Dict[str, List[ComplianceRequirement]] = {}
    
    @classmethod
    def initialize(cls):
        """Initialize all framework mappings"""
        cls._load_pci_dss()
        cls._load_iso_27001()
        cls._load_soc2()
        cls._build_indices()
    
    @classmethod
    def _load_pci_dss(cls):
        """Load PCI DSS requirements"""
        requirements = [
            ComplianceRequirement(
                framework=ComplianceFramework.PCI_DSS,
                requirement_id="PCI-DSS-1.1",
                title="Firewall Configuration",
                description="Install and maintain a firewall configuration to protect cardholder data",
                category="Network Security",
                severity="critical",
                related_cwes=["CWE-200", "CWE-284", "CWE-306"],
                test_procedures=[
                    "Verify firewall and router configurations",
                    "Check for unauthorized inbound/outbound traffic",
                    "Verify DMZ implementation",
                ],
                references=["PCI DSS v4.0 Requirement 1"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.PCI_DSS,
                requirement_id="PCI-DSS-2.1",
                title="Default Passwords Changed",
                description="Always change vendor-supplied defaults and remove unnecessary default accounts",
                category="System Configuration",
                severity="critical",
                related_cwes=["CWE-258", "CWE-798", "CWE-1392"],
                test_procedures=[
                    "Verify all default passwords changed",
                    "Check for default accounts",
                    "Verify SNMP community strings changed",
                ],
                references=["PCI DSS v4.0 Requirement 2"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.PCI_DSS,
                requirement_id="PCI-DSS-3.1",
                title="Stored Cardholder Data Protection",
                description="Protect stored cardholder data",
                category="Data Protection",
                severity="critical",
                related_cwes=["CWE-311", "CWE-312", "CWE-319", "CWE-326"],
                test_procedures=[
                    "Verify encryption of stored PAN",
                    "Check key management procedures",
                    "Verify data retention policies",
                ],
                references=["PCI DSS v4.0 Requirement 3"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.PCI_DSS,
                requirement_id="PCI-DSS-4.1",
                title="Encryption of Cardholder Data in Transit",
                description="Encrypt transmission of cardholder data across open, public networks",
                category="Network Security",
                severity="critical",
                related_cwes=["CWE-311", "CWE-319", "CWE-326", "CWE-327"],
                test_procedures=[
                    "Verify TLS 1.2+ for all cardholder data",
                    "Check for certificate validation",
                    "Verify no clear text transmission",
                ],
                references=["PCI DSS v4.0 Requirement 4"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.PCI_DSS,
                requirement_id="PCI-DSS-5.1",
                title="Anti-Virus Software",
                description="Deploy anti-virus software on all systems",
                category="Malware Protection",
                severity="high",
                related_cwes=["CWE-494", "CWE-829"],
                test_procedures=[
                    "Verify AV on all systems",
                    "Check signature updates",
                    "Verify periodic scans",
                ],
                references=["PCI DSS v4.0 Requirement 5"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.PCI_DSS,
                requirement_id="PCI-DSS-6.1",
                title="Secure Development",
                description="Develop and maintain secure systems and applications",
                category="Application Security",
                severity="critical",
                related_cwes=["CWE-79", "CWE-89", "CWE-200", "CWE-287", "CWE-306", "CWE-311", "CWE-319", "CWE-326", "CWE-327", "CWE-352", "CWE-434", "CWE-502", "CWE-601", "CWE-611", "CWE-798", "CWE-918"],
                test_procedures=[
                    "Verify secure coding practices",
                    "Check for OWASP Top 10",
                    "Verify change control procedures",
                ],
                references=["PCI DSS v4.0 Requirement 6"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.PCI_DSS,
                requirement_id="PCI-DSS-7.1",
                title="Access Control - Need to Know",
                description="Restrict access to cardholder data by business need to know",
                category="Access Control",
                severity="high",
                related_cwes=["CWE-284", "CWE-285", "CWE-639"],
                test_procedures=[
                    "Verify role-based access",
                    "Check access review procedures",
                    "Verify least privilege",
                ],
                references=["PCI DSS v4.0 Requirement 7"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.PCI_DSS,
                requirement_id="PCI-DSS-8.1",
                title="Authentication - Unique IDs",
                description="Identify and authenticate access to system components",
                category="Authentication",
                severity="critical",
                related_cwes=["CWE-287", "CWE-288", "CWE-289", "CWE-304", "CWE-306", "CWE-521", "CWE-522", "CWE-523", "CWE-613"],
                test_procedures=[
                    "Verify unique user IDs",
                    "Check MFA implementation",
                    "Verify password policies",
                ],
                references=["PCI DSS v4.0 Requirement 8"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.PCI_DSS,
                requirement_id="PCI-DSS-9.1",
                title="Physical Access Controls",
                description="Restrict physical access to cardholder data",
                category="Physical Security",
                severity="high",
                related_cwes=["CWE-284", "CWE-285"],
                test_procedures=[
                    "Verify physical access controls",
                    "Check visitor logs",
                    "Verify media handling",
                ],
                references=["PCI DSS v4.0 Requirement 9"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.PCI_DSS,
                requirement_id="PCI-DSS-10.1",
                title="Audit Trails",
                description="Track and monitor all access to network resources and cardholder data",
                category="Monitoring",
                severity="high",
                related_cwes=["CWE-778", "CWE-779"],
                test_procedures=[
                    "Verify logging on all systems",
                    "Check log retention",
                    "Verify log review procedures",
                ],
                references=["PCI DSS v4.0 Requirement 10"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.PCI_DSS,
                requirement_id="PCI-DSS-11.1",
                title="Vulnerability Scanning",
                description="Regularly test security systems and processes",
                category="Testing",
                severity="critical",
                related_cwes=["CWE-200", "CWE-284", "CWE-287", "CWE-306", "CWE-311", "CWE-319", "CWE-326", "CWE-327", "CWE-352", "CWE-434", "CWE-502", "CWE-601", "CWE-611", "CWE-798", "CWE-918"],
                test_procedures=[
                    "Verify quarterly external scans",
                    "Verify quarterly internal scans",
                    "Check penetration testing",
                ],
                references=["PCI DSS v4.0 Requirement 11"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.PCI_DSS,
                requirement_id="PCI-DSS-12.1",
                title="Security Policy",
                description="Maintain a policy that addresses information security for all personnel",
                category="Policy",
                severity="high",
                related_cwes=["CWE-284", "CWE-285"],
                test_procedures=[
                    "Verify security policy exists",
                    "Check policy review cycle",
                    "Verify awareness training",
                ],
                references=["PCI DSS v4.0 Requirement 12"]
            ),
        ]
        
        cls._frameworks[ComplianceFramework.PCI_DSS] = requirements
    
    @classmethod
    def _load_iso_27001(cls):
        """Load ISO 27001 Annex A controls"""
        requirements = [
            ComplianceRequirement(
                framework=ComplianceFramework.ISO_27001,
                requirement_id="A.5.1",
                title="Information Security Policies",
                description="Management direction for information security",
                category="Information Security Policies",
                severity="high",
                related_cwes=["CWE-284", "CWE-285"],
                references=["ISO 27001:2022 Annex A.5"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.ISO_27001,
                requirement_id="A.6.1",
                title="Internal Organization",
                description="Internal organization for information security",
                category="Organization of Information Security",
                severity="high",
                related_cwes=["CWE-284", "CWE-285"],
                references=["ISO 27001:2022 Annex A.6"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.ISO_27001,
                requirement_id="A.7.1",
                title="Prior to Employment",
                description="Screening and terms of employment",
                category="Human Resource Security",
                severity="medium",
                related_cwes=["CWE-284", "CWE-285"],
                references=["ISO 27001:2022 Annex A.7"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.ISO_27001,
                requirement_id="A.8.1",
                title="Asset Management",
                description="Responsibility for assets",
                category="Asset Management",
                severity="high",
                related_cwes=["CWE-200", "CWE-284"],
                references=["ISO 27001:2022 Annex A.8"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.ISO_27001,
                requirement_id="A.9.1",
                title="Access Control Policy",
                description="Business requirement for access control",
                category="Access Control",
                severity="critical",
                related_cwes=["CWE-284", "CWE-285", "CWE-639"],
                references=["ISO 27001:2022 Annex A.9"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.ISO_27001,
                requirement_id="A.10.1",
                title="Cryptographic Controls",
                description="Cryptographic controls policy and use",
                category="Cryptography",
                severity="high",
                related_cwes=["CWE-311", "CWE-319", "CWE-326", "CWE-327"],
                references=["ISO 27001:2022 Annex A.10"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.ISO_27001,
                requirement_id="A.11.1",
                title="Physical Security Perimeter",
                description="Physical security perimeter",
                category="Physical and Environmental Security",
                severity="high",
                related_cwes=["CWE-284", "CWE-285"],
                references=["ISO 27001:2022 Annex A.11"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.ISO_27001,
                requirement_id="A.12.1",
                title="Operational Procedures",
                description="Documented operating procedures",
                category="Operations Security",
                severity="high",
                related_cwes=["CWE-284", "CWE-285"],
                references=["ISO 27001:2022 Annex A.12"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.ISO_27001,
                requirement_id="A.12.6",
                title="Technical Vulnerability Management",
                description="Management of technical vulnerabilities",
                category="Operations Security",
                severity="critical",
                related_cwes=["CWE-200", "CWE-284", "CWE-287", "CWE-306", "CWE-311", "CWE-319", "CWE-326", "CWE-327", "CWE-352", "CWE-434", "CWE-502", "CWE-601", "CWE-611", "CWE-798", "CWE-918"],
                test_procedures=[
                    "Verify vulnerability scanning",
                    "Check patch management",
                    "Verify vulnerability remediation",
                ],
                references=["ISO 27001:2022 Annex A.12.6"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.ISO_27001,
                requirement_id="A.13.1",
                title="Network Security",
                description="Network controls and security",
                category="Communications Security",
                severity="critical",
                related_cwes=["CWE-200", "CWE-284", "CWE-287", "CWE-306", "CWE-311", "CWE-319", "CWE-326", "CWE-327"],
                references=["ISO 27001:2022 Annex A.13"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.ISO_27001,
                requirement_id="A.14.1",
                title="Secure Development",
                description="Security requirements of information systems",
                category="System Acquisition, Development and Maintenance",
                severity="critical",
                related_cwes=["CWE-79", "CWE-89", "CWE-200", "CWE-287", "CWE-306", "CWE-311", "CWE-319", "CWE-326", "CWE-327", "CWE-352", "CWE-434", "CWE-502", "CWE-601", "CWE-611", "CWE-798", "CWE-918"],
                references=["ISO 27001:2022 Annex A.14"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.ISO_27001,
                requirement_id="A.16.1",
                title="Incident Management",
                description="Management of information security incidents",
                category="Information Security Incident Management",
                severity="high",
                related_cwes=["CWE-778", "CWE-779"],
                references=["ISO 27001:2022 Annex A.16"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.ISO_27001,
                requirement_id="A.18.1",
                title="Compliance",
                description="Compliance with legal and contractual requirements",
                category="Compliance",
                severity="high",
                related_cwes=["CWE-284", "CWE-285"],
                references=["ISO 27001:2022 Annex A.18"]
            ),
        ]
        
        cls._frameworks[ComplianceFramework.ISO_27001] = requirements
    
    @classmethod
    def _load_soc2(cls):
        """Load SOC 2 Trust Services Criteria"""
        requirements = [
            ComplianceRequirement(
                framework=ComplianceFramework.SOC2,
                requirement_id="CC1.1",
                title="Control Environment",
                description="The entity demonstrates a commitment to integrity and ethical values",
                category="Control Environment",
                severity="high",
                related_cwes=["CWE-284", "CWE-285"],
                references=["SOC 2 Common Criteria CC1.1"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.SOC2,
                requirement_id="CC2.1",
                title="Communication and Information",
                description="The entity obtains or generates and uses relevant, quality information",
                category="Communication and Information",
                severity="medium",
                related_cwes=["CWE-200", "CWE-284"],
                references=["SOC 2 Common Criteria CC2.1"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.SOC2,
                requirement_id="CC3.1",
                title="Risk Assessment",
                description="The entity specifies objectives with sufficient clarity",
                category="Risk Assessment",
                severity="high",
                related_cwes=["CWE-200", "CWE-284", "CWE-287"],
                references=["SOC 2 Common Criteria CC3.1"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.SOC2,
                requirement_id="CC4.1",
                title="Monitoring Activities",
                description="The entity selects, develops, and performs ongoing and/or separate evaluations",
                category="Monitoring Activities",
                severity="high",
                related_cwes=["CWE-778", "CWE-779"],
                references=["SOC 2 Common Criteria CC4.1"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.SOC2,
                requirement_id="CC5.1",
                title="Control Activities",
                description="The entity selects and develops control activities that contribute to the mitigation of risks",
                category="Control Activities",
                severity="high",
                related_cwes=["CWE-284", "CWE-285", "CWE-639"],
                references=["SOC 2 Common Criteria CC5.1"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.SOC2,
                requirement_id="CC6.1",
                title="Logical and Physical Access Controls",
                description="The entity implements logical access security software, infrastructure, and architectures",
                category="Logical and Physical Access Controls",
                severity="critical",
                related_cwes=["CWE-284", "CWE-285", "CWE-287", "CWE-288", "CWE-289", "CWE-304", "CWE-306", "CWE-521", "CWE-522", "CWE-523", "CWE-613"],
                references=["SOC 2 Common Criteria CC6.1"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.SOC2,
                requirement_id="CC7.1",
                title="System Operations",
                description="To meet its objectives, the entity uses detection and monitoring procedures",
                category="System Operations",
                severity="high",
                related_cwes=["CWE-778", "CWE-779", "CWE-200", "CWE-284", "CWE-287"],
                references=["SOC 2 Common Criteria CC7.1"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.SOC2,
                requirement_id="CC8.1",
                title="Change Management",
                description="The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes",
                category="Change Management",
                severity="high",
                related_cwes=["CWE-284", "CWE-285", "CWE-494"],
                references=["SOC 2 Common Criteria CC8.1"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.SOC2,
                requirement_id="CC9.1",
                title="Risk Mitigation",
                description="The entity identifies, selects, and develops risk mitigation activities",
                category="Risk Mitigation",
                severity="high",
                related_cwes=["CWE-200", "CWE-284", "CWE-287"],
                references=["SOC 2 Common Criteria CC9.1"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.SOC2,
                requirement_id="A1.1",
                title="Availability - Capacity Management",
                description="The entity maintains, monitors, and evaluates current processing capacity",
                category="Availability",
                severity="medium",
                related_cwes=["CWE-400", "CWE-770"],
                references=["SOC 2 Availability A1.1"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.SOC2,
                requirement_id="PI1.1",
                title="Processing Integrity - Data Processing",
                description="The entity implements policies and procedures to ensure complete, valid, accurate, timely, and authorized data processing",
                category="Processing Integrity",
                severity="high",
                related_cwes=["CWE-20", "CWE-116", "CWE-119"],
                references=["SOC 2 Processing Integrity PI1.1"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.SOC2,
                requirement_id="C1.1",
                title="Confidentiality - Data Classification",
                description="The entity identifies and maintains confidential information",
                category="Confidentiality",
                severity="high",
                related_cwes=["CWE-200", "CWE-311", "CWE-312", "CWE-319"],
                references=["SOC 2 Confidentiality C1.1"]
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.SOC2,
                requirement_id="P1.1",
                title="Privacy - Notice and Choice",
                description="The entity provides notice to individuals about the privacy practices",
                category="Privacy",
                severity="medium",
                related_cwes=["CWE-359", "CWE-360"],
                references=["SOC 2 Privacy P1.1"]
            ),
        ]
        
        cls._frameworks[ComplianceFramework.SOC2] = requirements
    
    @classmethod
    def _build_indices(cls):
        """Build lookup indices"""
        for framework, requirements in cls._frameworks.items():
            for req in requirements:
                for cwe in req.related_cwes:
                    if cwe not in cls._cwe_to_requirements:
                        cls._cwe_to_requirements[cwe] = []
                    cls._cwe_to_requirements[cwe].append(req)
                
                for cve in req.related_cves:
                    if cve not in cls._cve_to_requirements:
                        cls._cve_to_requirements[cve] = []
                    cls._cve_to_requirements[cve].append(req)
    
    @classmethod
    def get_requirements(cls, framework: ComplianceFramework) -> List[ComplianceRequirement]:
        """Get all requirements for a framework"""
        return cls._frameworks.get(framework, [])
    
    @classmethod
    def get_requirements_by_cwe(cls, cwe: str) -> List[ComplianceRequirement]:
        """Get requirements related to a CWE"""
        return cls._cwe_to_requirements.get(cwe, [])
    
    @classmethod
    def get_requirements_by_cve(cls, cve: str) -> List[ComplianceRequirement]:
        """Get requirements related to a CVE"""
        return cls._cve_to_requirements.get(cve, [])
    
    @classmethod
    def map_findings_to_compliance(cls, findings: List[Dict], frameworks: List[ComplianceFramework]) -> Dict:
        """Map findings to compliance requirements"""
        mapping = {}
        
        for framework in frameworks:
            mapping[framework.value] = {}
            requirements = cls.get_requirements(framework)
            
            for req in requirements:
                matched_findings = []
                
                # Match by CWE
                for finding in findings:
                    finding_cwes = finding.get('cwe_id', '').split(',') if finding.get('cwe_id') else []
                    if req.requirement_id in finding.get('compliance_mappings', {}):
                        matched_findings.append(finding['id'])
                    elif any(cwe in req.related_cwes for cwe in finding_cwes):
                        matched_findings.append(finding['id'])
                
                if matched_findings:
                    mapping[framework.value][req.requirement_id] = {
                        'title': req.title,
                        'severity': req.severity,
                        'matched_findings': matched_findings,
                        'coverage': len(matched_findings) > 0,
                    }
        
        return mapping
    
    @classmethod
    def get_compliance_report(cls, findings: List[Dict], frameworks: List[ComplianceFramework]) -> Dict:
        """Generate compliance report from findings"""
        mapping = cls.map_findings_to_compliance(findings, frameworks)
        
        report = {}
        for framework_name, requirements in mapping.items():
            total = len(cls.get_requirements(ComplianceFramework(framework_name)))
            covered = sum(1 for r in requirements.values() if r['coverage'])
            critical_covered = sum(1 for r in requirements.values() if r['coverage'] and r['severity'] == 'critical')
            high_covered = sum(1 for r in requirements.values() if r['coverage'] and r['severity'] == 'high')
            
            report[framework_name] = {
                'total_requirements': total,
                'covered_requirements': covered,
                'coverage_percentage': (covered / total * 100) if total > 0 else 0,
                'critical_covered': critical_covered,
                'high_covered': high_covered,
                'requirements': requirements,
            }
        
        return report


# Initialize on import
ComplianceFrameworks.initialize()