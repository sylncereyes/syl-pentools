from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Enum as SQLEnum, Text, Integer, Index, Float
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import uuid
import enum
from datetime import datetime
from .base import Base

class ReportStatus(str, enum.Enum):
    DRAFT = "draft"
    GENERATING = "generating"
    READY = "ready"
    FAILED = "failed"
    EXPIRED = "expired"

class ReportFormat(str, enum.Enum):
    PDF = "pdf"
    DOCX = "docx"
    HTML = "html"
    CSV = "csv"
    JSON = "json"

class ReportTemplateType(str, enum.Enum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    COMPLIANCE = "compliance"
    ENGAGEMENT = "engagement"
    CUSTOM = "custom"

class ComplianceFramework(str, enum.Enum):
    PCI_DSS = "pci_dss"
    ISO_27001 = "iso_27001"
    SOC2 = "soc2"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    NIST = "nist"

class ReportTemplate(Base):
    __tablename__ = "report_templates"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    
    name = Column(String(255), nullable=False)
    description = Column(Text)
    type = Column(SQLEnum(ReportTemplateType), default=ReportTemplateType.CUSTOM, nullable=False)
    
    # Compliance
    compliance_frameworks = Column(JSONB, default=[])  # List of ComplianceFramework
    
    # Template content (Jinja2)
    template_content = Column(Text, nullable=False)  # Jinja2 template
    template_variables = Column(JSONB, default={})  # Available variables schema
    
    # Branding
    logo_path = Column(String(500))
    primary_color = Column(String(7))
    secondary_color = Column(String(7))
    font_family = Column(String(100))
    footer_text = Column(Text)
    
    # Sections config
    sections = Column(JSONB, default=[])  # Ordered list of sections to include
    
    # Default formats
    default_formats = Column(JSONB, default=["pdf", "docx"])
    
    # Visibility
    is_default = Column(Boolean, default=False)
    is_system = Column(Boolean, default=False)
    
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    workspace = relationship("Workspace")
    reports = relationship("Report", back_populates="template")


class Report(Base):
    __tablename__ = "reports"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    template_id = Column(UUID(as_uuid=True), ForeignKey("report_templates.id", ondelete="SET NULL"), nullable=True)
    
    # Source
    scan_ids = Column(JSONB, default=[])  # List of scan IDs included
    finding_ids = Column(JSONB, default=[])  # List of finding IDs included
    asset_ids = Column(JSONB, default=[])  # List of asset IDs included
    
    # Report config
    title = Column(String(500), nullable=False)
    description = Column(Text)
    format = Column(SQLEnum(ReportFormat), default=ReportFormat.PDF, nullable=False)
    status = Column(SQLEnum(ReportStatus), default=ReportStatus.DRAFT, nullable=False, index=True)
    
    # Filters applied
    severity_filter = Column(JSONB, default=[])
    status_filter = Column(JSONB, default=[])
    date_range = Column(JSONB, default={})  # {start: ..., end: ...}
    
    # Output
    file_path = Column(String(500))
    file_size = Column(Integer)
    page_count = Column(Integer)
    
    # Generation
    generation_error = Column(Text)
    generation_duration_seconds = Column(Float)
    generated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    # Expiry
    expires_at = Column(DateTime(timezone=True))
    download_count = Column(Integer, default=0)
    last_downloaded_at = Column(DateTime(timezone=True))
    
    # Compliance
    compliance_frameworks = Column(JSONB, default=[])
    compliance_mapping = Column(JSONB, default={})  # Finding ID -> framework requirements
    
    # Engagement
    engagement_id = Column(UUID(as_uuid=True), ForeignKey("engagements.id"), nullable=True)
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = Column(DateTime(timezone=True))
    
    # Relationships
    workspace = relationship("Workspace", back_populates="reports")
    template = relationship("ReportTemplate", back_populates="reports")
    engagement = relationship("Engagement", back_populates="reports")
    
    __table_args__ = (
        Index("ix_reports_workspace_status", "workspace_id", "status"),
    )
    
    def __repr__(self):
        return f"<Report(id={self.id}, title={self.title}, format={self.format}, status={self.status})>"


class Engagement(Base):
    __tablename__ = "engagements"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    
    name = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Scope
    scope = Column(JSONB, default={})  # In-scope/out-of-scope targets
    rules_of_engagement = Column(Text)
    
    # Team
    lead_tester = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    team_members = Column(JSONB, default=[])  # List of user IDs
    
    # Timeline
    start_date = Column(DateTime(timezone=True))
    end_date = Column(DateTime(timezone=True))
    
    # Status
    status = Column(String(50), default="planning")  # planning, active, reporting, completed, archived
    
    # Deliverables
    deliverables = Column(JSONB, default=[])  # List of report IDs
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = Column(DateTime(timezone=True))
    
    # Relationships
    workspace = relationship("Workspace")
    reports = relationship("Report", back_populates="engagement")