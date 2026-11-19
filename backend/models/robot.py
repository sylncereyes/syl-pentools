import uuid
import enum
from datetime import datetime

from sqlalchemy import Column, String, Text, DateTime, ForeignKey, Integer, Boolean, JSON
from sqlalchemy.dialects.postgresql import UUID, JSONB

from models.base import Base


class RobotRunStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Robot(Base):
    __tablename__ = "robots"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    steps = Column(JSONB, default=list)  # [{"tool": "subdomain", "intensity": "light"}, ...]
    max_targets = Column(Integer, default=10)
    is_active = Column(Boolean, default=True)
    schedule_cron = Column(String(100))
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)


class RobotRun(Base):
    __tablename__ = "robot_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    robot_id = Column(UUID(as_uuid=True), ForeignKey("robots.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    target = Column(String(500), nullable=False)
    status = Column(String(30), default=RobotRunStatus.QUEUED.value, nullable=False)
    current_step = Column(Integer, default=0)
    total_steps = Column(Integer, default=0)
    steps_state = Column(JSONB, default=list)
    scan_ids = Column(JSONB, default=list)
    error_message = Column(Text)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
