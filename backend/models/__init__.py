from .base import Base
from .user import User
from .workspace import Workspace
from .asset import Asset
from .scan import Scan, ScanStatus, ScanType
from .finding import Finding, FindingStatus, FindingSeverity, FindingComment, FindingAttachment
from .integration import Integration, IntegrationType
from .report import Report, ReportTemplate
from .schedule import ScheduledScan
from .auth_token import PasswordResetToken, EmailVerificationToken, InviteToken
from .attack_surface import AttackSurfaceNode, AttackSurfaceEdge, AttackSurfaceSnapshot
from .robot import Robot, RobotRun, RobotRunStatus

__all__ = [
    "Base",
    "User",
    "Workspace",
    "Asset",
    "Scan",
    "ScanStatus",
    "ScanType",
    "Finding",
    "FindingStatus",
    "FindingSeverity",
    "FindingComment",
    "FindingAttachment",
    "Integration",
    "IntegrationType",
    "Report",
    "ReportTemplate",
    "ScheduledScan",
    "PasswordResetToken",
    "EmailVerificationToken",
    "InviteToken",
    "Robot",
    "RobotRun",
    "RobotRunStatus",
]

def _dedupe_indexes(metadata):
    """Remove explicit Index objects that duplicate a column's auto index,
    or share a name with another explicit index (prevents create_all/migration errors)."""
    for table in metadata.tables.values():
        auto_names = {f"ix_{table.name}_{c.name}" for c in table.columns if c.index}
        seen = set()
        for idx in list(table.indexes):
            name = idx.name
            if name in auto_names or name in seen:
                table.indexes.discard(idx)
            else:
                seen.add(name)


_dedupe_indexes(Base.metadata)
