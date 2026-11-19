from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Enum as SQLEnum, Text, Integer, Index, Float
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import uuid
import enum
from datetime import datetime
from .base import Base

class NodeType(str, enum.Enum):
    ASSET = "asset"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    PORT = "port"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    VULNERABILITY = "vulnerability"
    ENDPOINT = "endpoint"
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"

class EdgeType(str, enum.Enum):
    RESOLVES_TO = "resolves_to"
    HOSTS = "hosts"
    RUNS_ON = "runs_on"
    USES_TECH = "uses_tech"
    HAS_VULN = "has_vuln"
    EXPOSES = "exposes"
    CERTIFIES = "certifies"
    DNS_POINTS = "dns_points"

class AttackSurfaceNode(Base):
    __tablename__ = "attack_surface_nodes"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True)
    
    type = Column(SQLEnum(NodeType), nullable=False, index=True)
    label = Column(String(500), nullable=False)
    value = Column(String(500), nullable=False, index=True)  # The actual value (IP, domain, etc.)
    
    # Properties
    properties = Column(JSONB, default={})  # Flexible properties per node type
    risk_score = Column(Float, default=0.0)
    criticality = Column(String(50))  # critical, high, medium, low, info
    
    # Discovery
    discovered_by = Column(String(100))  # scanner name
    discovered_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    last_seen = Column(DateTime(timezone=True))
    confidence = Column(Float, default=1.0)  # 0.0 - 1.0
    
    # Status
    is_active = Column(Boolean, default=True)
    is_hidden = Column(Boolean, default=False)
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    workspace = relationship("Workspace")
    asset = relationship("Asset", back_populates="attack_surface_nodes")
    outgoing_edges = relationship("AttackSurfaceEdge", foreign_keys="AttackSurfaceEdge.source_id", back_populates="source")
    incoming_edges = relationship("AttackSurfaceEdge", foreign_keys="AttackSurfaceEdge.target_id", back_populates="target")
    
    __table_args__ = (
        Index("ix_attack_surface_nodes_workspace_type", "workspace_id", "type"),
        Index("ix_attack_surface_nodes_value", "value"),
    )


class AttackSurfaceEdge(Base):
    __tablename__ = "attack_surface_edges"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    
    source_id = Column(UUID(as_uuid=True), ForeignKey("attack_surface_nodes.id", ondelete="CASCADE"), nullable=False, index=True)
    target_id = Column(UUID(as_uuid=True), ForeignKey("attack_surface_nodes.id", ondelete="CASCADE"), nullable=False, index=True)
    
    type = Column(SQLEnum(EdgeType), nullable=False, index=True)
    label = Column(String(255))
    
    # Properties
    properties = Column(JSONB, default={})
    weight = Column(Float, default=1.0)
    
    # Discovery
    discovered_by = Column(String(100))
    discovered_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    confidence = Column(Float, default=1.0)
    
    # Status
    is_active = Column(Boolean, default=True)
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    workspace = relationship("Workspace")
    source = relationship("AttackSurfaceNode", foreign_keys=[source_id], back_populates="outgoing_edges")
    target = relationship("AttackSurfaceNode", foreign_keys=[target_id], back_populates="incoming_edges")
    
    __table_args__ = (
        Index("ix_attack_surface_edges_source_target", "source_id", "target_id", unique=True),
    )


class AttackSurfaceSnapshot(Base):
    __tablename__ = "attack_surface_snapshots"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    
    name = Column(String(255))
    description = Column(Text)
    
    # Stats
    node_count = Column(Integer, default=0)
    edge_count = Column(Integer, default=0)
    asset_count = Column(Integer, default=0)
    vulnerability_count = Column(Integer, default=0)
    
    # Diff from previous
    nodes_added = Column(Integer, default=0)
    nodes_removed = Column(Integer, default=0)
    edges_added = Column(Integer, default=0)
    edges_removed = Column(Integer, default=0)
    risk_score_delta = Column(Float, default=0.0)
    
    # Storage
    graph_data = Column(JSONB)  # Full graph serialization
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    # Relationships
    workspace = relationship("Workspace")