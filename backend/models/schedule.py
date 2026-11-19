from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Enum as SQLEnum, Text, Integer, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import uuid
import enum
from datetime import datetime
from .base import Base

class ScheduleFrequency(str, enum.Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM = "custom"  # Cron expression

class ScheduledScanStatus(str, enum.Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    DISABLED = "disabled"
    ERROR = "error"

class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    
    name = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Scan config
    scan_type = Column(String(50), nullable=False)  # ScanType value
    target = Column(String(500), nullable=False)
    asset_ids = Column(JSONB, default=[])  # Alternative: specific assets
    intensity = Column(String(50), default="normal")
    scanner_config = Column(JSONB, default={})  # Full scanner config
    
    # Authenticated scan
    is_authenticated = Column(Boolean, default=False)
    auth_config = Column(JSONB, default={})
    login_recording_id = Column(UUID(as_uuid=True), ForeignKey("login_recordings.id"), nullable=True)
    
    # Schedule
    frequency = Column(SQLEnum(ScheduleFrequency), default=ScheduleFrequency.WEEKLY, nullable=False)
    cron_expression = Column(String(100))  # For CUSTOM frequency
    timezone = Column(String(50), default="UTC")
    
    # Time window
    start_time = Column(String(5))  # HH:MM
    end_time = Column(String(5))  # HH:MM (optional window)
    max_duration_minutes = Column(Integer, default=120)
    
    # Status
    status = Column(SQLEnum(ScheduledScanStatus), default=ScheduledScanStatus.ACTIVE, nullable=False, index=True)
    last_run = Column(DateTime(timezone=True))
    next_run = Column(DateTime(timezone=True), index=True)
    last_run_status = Column(String(50))  # success, failed, partial
    last_run_error = Column(Text)
    consecutive_failures = Column(Integer, default=0)
    
    # Notifications
    notify_on_success = Column(Boolean, default=False)
    notify_on_failure = Column(Boolean, default=True)
    notify_on_findings = Column(Boolean, default=True)
    notification_integration_ids = Column(JSONB, default=[])
    
    # Retry
    max_retries = Column(Integer, default=2)
    retry_delay_minutes = Column(Integer, default=30)
    
    # Metadata
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    updated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    workspace = relationship("Workspace", back_populates="scheduled_scans")
    scans = relationship("Scan", back_populates="scheduled_scan")
    login_recording = relationship("LoginRecording")
    
    __table_args__ = (
        Index("ix_scheduled_scans_workspace_status", "workspace_id", "status"),
        Index("ix_scheduled_scans_next_run_status", "next_run", "status"),
    )
    
    def __repr__(self):
        return f"<ScheduledScan(id={self.id}, name={self.name}, frequency={self.frequency})>"