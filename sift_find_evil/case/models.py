"""Data models for case management."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


class CaseStatus(str, Enum):
    """Case status."""

    OPEN = "open"
    ACTIVE = "active"
    CLOSED = "closed"


@dataclass
class EvidenceFile:
    """Evidence file registration."""

    file_path: Path
    description: str
    sha256_hash: str
    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    file_size: Optional[int] = None
    evidence_type: Optional[str] = None  # disk_image, memory_dump, pcap, etc.

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "file_path": str(self.file_path),
            "description": self.description,
            "sha256_hash": self.sha256_hash,
            "registered_at": self.registered_at.isoformat(),
            "file_size": self.file_size,
            "evidence_type": self.evidence_type,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EvidenceFile":
        """Deserialize from dictionary."""
        return cls(
            file_path=Path(data["file_path"]),
            description=data["description"],
            sha256_hash=data["sha256_hash"],
            registered_at=datetime.fromisoformat(data["registered_at"]),
            file_size=data.get("file_size"),
            evidence_type=data.get("evidence_type"),
        )


@dataclass
class Case:
    """Forensic investigation case."""

    case_id: str
    name: str
    examiner: str
    created_at: datetime
    status: CaseStatus = CaseStatus.OPEN
    directory: Optional[Path] = None
    description: Optional[str] = None
    closed_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "case_id": self.case_id,
            "name": self.name,
            "examiner": self.examiner,
            "created_at": self.created_at.isoformat(),
            "status": self.status.value,
            "directory": str(self.directory) if self.directory else None,
            "description": self.description,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Case":
        """Deserialize from dictionary."""
        return cls(
            case_id=data["case_id"],
            name=data["name"],
            examiner=data["examiner"],
            created_at=datetime.fromisoformat(data["created_at"]),
            status=CaseStatus(data["status"]),
            directory=Path(data["directory"]) if data.get("directory") else None,
            description=data.get("description"),
            closed_at=(
                datetime.fromisoformat(data["closed_at"])
                if data.get("closed_at")
                else None
            ),
        )
