from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, ForeignKey, Enum as SQLEnum, Float, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import uuid
import enum
from datetime import datetime
from .base import Base

class ScanType(str, enum.Enum):
    WEBSITE = "website"
    NETWORK = "network"
    PORT = "port"
    SUBDOMAIN = "subdomain"
    RECON = "recon"
    PASSWORD = "password"
    CMS = "cms"
    API = "api"
    CLOUD = "cloud"
    EXPLOIT = "exploit"
    BURP = "burp"
    AI_PENTEST = "ai_pentest"
    FULL = "full"
    FUZZER = "fuzzer"
    GOOGLE_HACKING = "google_hacking"
    PEOPLE_HUNTER = "people_hunter"
    DOMAIN_FINDER = "domain_finder"
    VHOST = "vhost"
    HTTP_LOGGER = "http_logger"


class ScanTemplate(Base):
    __tablename__ = "scan_templates"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)

    name = Column(String(255), nullable=False)
    description = Column(Text)
    category = Column(String(50))  # recon, vuln, exploit, etc.

    # Scan config (JSON for flexibility)
    scan_type = Column(String(50), nullable=False)
    intensity = Column(String(50), default="normal")
    scanner_config = Column(JSONB, default={})
    is_authenticated = Column(Boolean, default=False)
    auth_config = Column(JSONB, default={})

    # Visibility
    is_system = Column(Boolean, default=False)  # System templates can't be deleted
    is_public = Column(Boolean, default=False)  # Shared across workspaces

    # Metadata
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    updated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    usage_count = Column(Integer, default=0)

    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    workspace = relationship("Workspace")
    creator = relationship("User", foreign_keys=[created_by])

    def __repr__(self):
        return f"<ScanTemplate(id={self.id}, name={self.name}, type={self.scan_type})>"

class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"

class ScanIntensity(str, enum.Enum):
    LIGHT = "light"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    scheduled_scan_id = Column(UUID(as_uuid=True), ForeignKey("scheduled_scans.id", ondelete="SET NULL"), nullable=True)
    
    # Scan config
    name = Column(String(255))
    type = Column(SQLEnum(ScanType), nullable=False, index=True)
    target = Column(String(500), nullable=False)
    intensity = Column(SQLEnum(ScanIntensity), default=ScanIntensity.NORMAL, nullable=False)
    
    # Authenticated scan config
    is_authenticated = Column(Boolean, default=False)
    auth_config = Column(JSONB, default={})  # {type: "basic|form|header|cookie", credentials: {...}}
    login_recording_id = Column(UUID(as_uuid=True), ForeignKey("login_recordings.id"), nullable=True)
    
    # Status
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    progress = Column(Float, default=0.0)  # 0.0 - 100.0
    current_step = Column(String(255))
    steps_completed = Column(Integer, default=0)
    total_steps = Column(Integer, default=0)
    
    # Results summary
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    
    # Scan metadata
    scanner_version = Column(String(100))
    scanner_config = Column(JSONB, default={})  # Full scanner config used
    raw_output_path = Column(String(500))  # Path to raw scanner output
    error_message = Column(Text)
    
    # Timing
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    duration_seconds = Column(Integer)
    queued_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    
    # Celery task ID
    celery_task_id = Column(String(255), index=True)
    
    # Retry
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=2)
    parent_scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True)
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    workspace = relationship("Workspace", back_populates="scans")
    asset = relationship("Asset", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")
    scheduled_scan = relationship("ScheduledScan", back_populates="scans")
    logs = relationship("ScanLog", back_populates="scan", order_by="ScanLog.created_at")
    login_recording = relationship("LoginRecording")
    
    __table_args__ = (
        Index("ix_scans_workspace_status", "workspace_id", "status"),
        Index("ix_scans_asset_status", "asset_id", "status"),
    )
    
    def __repr__(self):
        return f"<Scan(id={self.id}, type={self.type}, target={self.target}, status={self.status})>"


class ScanLog(Base):
    __tablename__ = "scan_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    
    level = Column(String(20), nullable=False)  # debug, info, warning, error
    message = Column(Text, nullable=False)
    step = Column(String(255))
    progress = Column(Float)
    meta = Column("metadata", JSONB, default=dict)
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    
    # Relationships
    scan = relationship("Scan", back_populates="logs")


class LoginRecording(Base):
    __tablename__ = "login_recordings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    target_url = Column(String(500), nullable=False)
    
    # Recording data
    steps = Column(JSONB, default=[])  # Playwright/Chrome DevTools Protocol steps
    selectors = Column(JSONB, default={})  # Login form selectors
    cookies = Column(JSONB, default={})  # Extracted cookies
    headers = Column(JSONB, default={})  # Auth headers
    local_storage = Column(JSONB, default={})
    session_storage = Column(JSONB, default={})
    
    # Validation
    is_valid = Column(Boolean, default=False)
    last_validated = Column(DateTime(timezone=True))
    validation_error = Column(Text)
    
    # Metadata
    browser_version = Column(String(100))
    user_agent = Column(String(500))
    viewport = Column(JSONB, default={})
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    # Relationships
    workspace = relationship("Workspace")
    scans = relationship("Scan", back_populates="login_recording")