from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, ForeignKey, Enum as SQLEnum, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET, CIDR
from sqlalchemy.orm import relationship
import uuid
import enum
from datetime import datetime
from .base import Base

class AssetType(str, enum.Enum):
    HOSTNAME = "hostname"
    IP_ADDRESS = "ip_address"
    CIDR = "cidr"
    URL = "url"

class AssetRiskLevel(str, enum.Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Asset(Base):
    __tablename__ = "assets"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Target
    target = Column(String(500), nullable=False, index=True)
    type = Column(SQLEnum(AssetType), default=AssetType.HOSTNAME, nullable=False)
    description = Column(Text)
    
    # Resolved info
    resolved_ips = Column(JSONB, default=[])  # List of resolved IPs
    is_resolved = Column(Boolean, default=False)
    
    # Risk
    risk_level = Column(SQLEnum(AssetRiskLevel), default=AssetRiskLevel.NONE, nullable=False)
    risk_score = Column(Integer, default=0)  # 0-100
    
    # Metadata
    tags = Column(JSONB, default=[])  # User-defined tags
    meta = Column("metadata", JSONB, default=dict)  # Additional metadata
    
    # Scan stats
    total_scans = Column(Integer, default=0)
    last_scanned_at = Column(DateTime(timezone=True))
    open_ports_count = Column(Integer, default=0)
    vulnerabilities_count = Column(Integer, default=0)
    critical_vulns = Column(Integer, default=0)
    high_vulns = Column(Integer, default=0)
    medium_vulns = Column(Integer, default=0)
    low_vulns = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    deleted_at = Column(DateTime(timezone=True))  # Soft delete
    
    # Relationships
    workspace = relationship("Workspace", back_populates="assets")
    scans = relationship("Scan", back_populates="asset")
    findings = relationship("Finding", back_populates="asset")
    attack_surface_nodes = relationship("AttackSurfaceNode", back_populates="asset")
    
    def __repr__(self):
        return f"<Asset(id={self.id}, target={self.target}, type={self.type})>"


class AssetGroup(Base):
    __tablename__ = "asset_groups"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    color = Column(String(7))  # Hex color
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    assets = relationship("AssetGroupMember", back_populates="group")


class AssetGroupMember(Base):
    __tablename__ = "asset_group_members"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id = Column(UUID(as_uuid=True), ForeignKey("asset_groups.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    added_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    
    # Relationships
    group = relationship("AssetGroup", back_populates="assets")
    asset = relationship("Asset")
    
    __table_args__ = (
        Index("ix_asset_group_member_group_asset", "group_id", "asset_id", unique=True),
    )