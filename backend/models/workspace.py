from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, ForeignKey, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import uuid
import enum
from datetime import datetime
from .base import Base

class PlanType(str, enum.Enum):
    FREE = "free"
    NETSCAN = "netscan"
    APPSCAN = "appscan"
    EXPLOIT = "exploit"
    ENTERPRISE = "enterprise"

class Workspace(Base):
    __tablename__ = "workspaces"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text)
    plan = Column(SQLEnum(PlanType), default=PlanType.FREE, nullable=False)
    
    # Limits
    asset_limit = Column(Integer, default=100)
    concurrent_scan_limit = Column(Integer, default=2)
    scheduled_scan_limit = Column(Integer, default=10)
    team_member_limit = Column(Integer, default=10)
    
    # Features
    ai_pentests_enabled = Column(Boolean, default=False)
    branded_reports = Column(Boolean, default=False)
    custom_integrations = Column(Boolean, default=False)
    internal_scanning = Column(Boolean, default=False)
    
    # Billing
    stripe_customer_id = Column(String(255))
    stripe_subscription_id = Column(String(255))
    subscription_status = Column(String(50))
    subscription_current_period_end = Column(DateTime(timezone=True))
    
    # Settings
    settings = Column(JSONB, default={})  # JSON for flexible settings
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    members = relationship("WorkspaceMember", back_populates="workspace")
    assets = relationship("Asset", back_populates="workspace")
    scans = relationship("Scan", back_populates="workspace")
    findings = relationship("Finding", back_populates="workspace")
    integrations = relationship("Integration", back_populates="workspace")
    reports = relationship("Report", back_populates="workspace")
    scheduled_scans = relationship("ScheduledScan", back_populates="workspace")
    
    def __repr__(self):
        return f"<Workspace(id={self.id}, name={self.name}, plan={self.plan})>"


class WorkspaceMember(Base):
    __tablename__ = "workspace_members"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(SQLEnum("owner", "admin", "member", "viewer", name="user_role"), default="member", nullable=False)
    joined_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    invited_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    # Relationships
    workspace = relationship("Workspace", back_populates="members")
    user = relationship("User", back_populates="workspaces", foreign_keys=[user_id])
    
    __table_args__ = (
        # Unique constraint will be added via migration
    )