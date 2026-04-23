"""Data models for approval workflow."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class ApprovalStatus(str, Enum):
    """Finding approval status."""

    DRAFT = "DRAFT"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


@dataclass
class ApprovalMetadata:
    """Metadata tracking approval/rejection decisions."""

    status: ApprovalStatus
    reviewer: str
    timestamp: datetime
    reason: Optional[str] = None
    signature_hash: Optional[str] = None  # SHA-256 hash for tamper detection

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "status": self.status.value,
            "reviewer": self.reviewer,
            "timestamp": self.timestamp.isoformat(),
            "reason": self.reason,
            "signature_hash": self.signature_hash,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ApprovalMetadata":
        """Deserialize from dictionary."""
        return cls(
            status=ApprovalStatus(data["status"]),
            reviewer=data["reviewer"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            reason=data.get("reason"),
            signature_hash=data.get("signature_hash"),
        )


@dataclass
class FindingWithApproval:
    """Finding with approval metadata."""

    finding_id: str
    finding: dict  # Original finding.to_dict() output
    approval: Optional[ApprovalMetadata] = None
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "finding_id": self.finding_id,
            "finding": self.finding,
            "approval": self.approval.to_dict() if self.approval else None,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "FindingWithApproval":
        """Deserialize from dictionary."""
        return cls(
            finding_id=data["finding_id"],
            finding=data["finding"],
            approval=(
                ApprovalMetadata.from_dict(data["approval"])
                if data.get("approval")
                else None
            ),
            created_at=datetime.fromisoformat(data["created_at"]),
        )

    @property
    def status(self) -> ApprovalStatus:
        """Get current approval status."""
        return self.approval.status if self.approval else ApprovalStatus.DRAFT

    def is_draft(self) -> bool:
        """Check if finding is in DRAFT state."""
        return self.status == ApprovalStatus.DRAFT

    def is_approved(self) -> bool:
        """Check if finding is approved."""
        return self.status == ApprovalStatus.APPROVED

    def is_rejected(self) -> bool:
        """Check if finding is rejected."""
        return self.status == ApprovalStatus.REJECTED
