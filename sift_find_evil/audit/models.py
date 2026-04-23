"""Data models for audit logging."""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class ToolInvocation:
    """Record of a forensic tool invocation."""

    tool: str
    command: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    exit_code: Optional[int] = None
    duration_ms: Optional[int] = None
    output_hash: Optional[str] = None
    examiner: Optional[str] = None
    working_dir: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "tool": self.tool,
            "command": self.command,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "output_hash": self.output_hash,
            "examiner": self.examiner,
            "working_dir": self.working_dir,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ToolInvocation":
        """Deserialize from dictionary."""
        return cls(
            tool=data["tool"],
            command=data["command"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            exit_code=data.get("exit_code"),
            duration_ms=data.get("duration_ms"),
            output_hash=data.get("output_hash"),
            examiner=data.get("examiner"),
            working_dir=data.get("working_dir"),
            stdout=data.get("stdout"),
            stderr=data.get("stderr"),
        )


@dataclass
class AuditEntry:
    """Base audit entry for any logged action."""

    action: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    examiner: Optional[str] = None
    details: Optional[dict] = None

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "action": self.action,
            "examiner": self.examiner,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AuditEntry":
        """Deserialize from dictionary."""
        return cls(
            action=data["action"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            examiner=data.get("examiner"),
            details=data.get("details"),
        )


def calculate_output_hash(output: str) -> str:
    """Calculate SHA-256 hash of tool output."""
    return hashlib.sha256(output.encode("utf-8")).hexdigest()[:16]
