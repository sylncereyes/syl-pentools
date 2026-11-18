from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, ForeignKey, Enum as SQLEnum, Float, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import uuid
import enum
from datetime import datetime
from .base import Base

class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class FindingStatus(str, enum.Enum):
    OPEN = "open"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"
    IGNORED = "ignored"
    RISK_ACCEPTED = "risk_accepted"

class Finding(Base):
    __tablename__ = "findings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Finding details
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(SQLEnum(FindingSeverity), nullable=False, index=True)
    status = Column(SQLEnum(FindingStatus), default=FindingStatus.OPEN, nullable=False, index=True)
    
    # Classification
    cwe_id = Column(String(20))  # e.g., "CWE-89"
    cve_ids = Column(JSONB, default=[])  # List of CVE IDs
    owasp_category = Column(String(100))  # e.g., "A03:2021-Injection"
    cvss_score = Column(Float)  # CVSS v3.1 score
    cvss_vector = Column(String(200))  # CVSS vector string
    
    # Location
    target_url = Column(String(500))
    parameter = Column(String(255))
    method = Column(String(20))
    path = Column(String(500))
    
    # Evidence
    evidence = Column(JSONB, default={})  # Request/response, screenshots, etc.
    reproduction_steps = Column(Text)
    proof_of_concept = Column(Text)
    
    # Remediation
    remediation = Column(Text)
    remediation_complexity = Column(String(50))  # easy, medium, hard
    references = Column(JSONB, default=[])  # Links to references
    
    # Tracking
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    verified_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    verified_at = Column(DateTime(timezone=True))
    fixed_at = Column(DateTime(timezone=True))
    
    # Deduplication
    fingerprint = Column(String(64), index=True)  # SHA256 for deduplication
    is_duplicate = Column(Boolean, default=False)
    duplicate_of = Column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=True)
    
    # Tags
    tags = Column(JSONB, default=[])
    
    # Source
    source_scanner = Column(String(100))  # nmap, nuclei, sqlmap, etc.
    source_finding_id = Column(String(255))  # Original scanner finding ID
    source_rule_id = Column(String(255))  # Rule/template ID that triggered
    
    # Compliance
    compliance_mappings = Column(JSONB, default={})  # PCI DSS, ISO 27001, SOC 2 mappings
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at = Column(DateTime(timezone=True))
    
    # Relationships
    workspace = relationship("Workspace", back_populates="findings")
    scan = relationship("Scan", back_populates="findings")
    asset = relationship("Asset", back_populates="findings")
    assignee = relationship("User", foreign_keys=[assigned_to])
    verifier = relationship("User", foreign_keys=[verified_by])
    comments = relationship("FindingComment", back_populates="finding", order_by="FindingComment.created_at")
    attachments = relationship("FindingAttachment", back_populates="finding")
    
    __table_args__ = (
        Index("ix_findings_workspace_severity", "workspace_id", "severity"),
        Index("ix_findings_workspace_status", "workspace_id", "status"),
        Index("ix_findings_fingerprint", "fingerprint"),
    )
    
    def __repr__(self):
        return f"<Finding(id={self.id}, title={self.title[:50]}, severity={self.severity})>"


class FindingComment(Base):
    __tablename__ = "finding_comments"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    content = Column(Text, nullable=False)
    is_internal = Column(Boolean, default=True)  # Internal vs client-visible
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    finding = relationship("Finding", back_populates="comments")
    user = relationship("User")


class FindingAttachment(Base):
    __tablename__ = "finding_attachments"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    
    filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)
    file_size = Column(Integer)
    mime_type = Column(String(100))
    
    uploaded_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    uploaded_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    
    # Relationships
    finding = relationship("Finding", back_populates="attachments")