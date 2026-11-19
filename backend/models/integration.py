from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Enum as SQLEnum, Text, Index, Integer
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import uuid
import enum
from datetime import datetime
from .base import Base

class IntegrationType(str, enum.Enum):
    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"
    JIRA = "jira"
    GITHUB = "github"
    DISCORD = "discord"
    VANTA = "vanta"
    BURP = "burp"
    AWS = "aws"
    NUCLEUS = "nucleus"
    MCP = "mcp"
    CICD = "cicd"
    EMAIL = "email"
    PAGERDUTY = "pagerduty"
    SERVICENOW = "servicenow"
    ZENDESK = "zendesk"

class Integration(Base):
    __tablename__ = "integrations"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    
    type = Column(SQLEnum(IntegrationType), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Configuration (encrypted sensitive fields)
    config = Column(JSONB, default={})
    config_encrypted = Column(JSONB, default={})  # Encrypted secrets
    
    # Status
    is_enabled = Column(Boolean, default=True, index=True)
    is_configured = Column(Boolean, default=False)
    last_sync = Column(DateTime(timezone=True))
    last_error = Column(Text)
    error_count = Column(Integer, default=0)
    
    # Filters
    severity_filter = Column(JSONB, default=[])  # List of severities to notify
    scan_type_filter = Column(JSONB, default=[])  # List of scan types
    asset_filter = Column(JSONB, default={})  # Asset tags/IDs
    
    # Webhook specific
    webhook_url = Column(String(500))
    webhook_secret = Column(String(255))
    webhook_events = Column(JSONB, default=[])
    
    # Rate limiting
    rate_limit_per_minute = Column(Integer, default=60)
    rate_limit_burst = Column(Integer, default=10)
    
    # Metadata
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    updated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    workspace = relationship("Workspace", back_populates="integrations")
    notifications = relationship("IntegrationNotification", back_populates="integration")
    
    __table_args__ = (
        Index("ix_integrations_workspace_type", "workspace_id", "type"),
    )
    
    def __repr__(self):
        return f"<Integration(id={self.id}, type={self.type}, name={self.name})>"


class IntegrationNotification(Base):
    __tablename__ = "integration_notifications"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    integration_id = Column(UUID(as_uuid=True), ForeignKey("integrations.id", ondelete="CASCADE"), nullable=False, index=True)
    
    event_type = Column(String(100), nullable=False)  # scan_completed, finding_critical, etc.
    payload = Column(JSONB, default={})
    
    status = Column(String(50), default="pending", index=True)  # pending, sent, failed
    response_code = Column(Integer)
    response_body = Column(Text)
    error_message = Column(Text)
    
    attempts = Column(Integer, default=0)
    max_attempts = Column(Integer, default=3)
    next_retry_at = Column(DateTime(timezone=True))
    
    sent_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    
    # Relationships
    integration = relationship("Integration", back_populates="notifications")