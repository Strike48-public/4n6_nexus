"""Finding dataclass - Core forensic finding representation.

The Finding class is used by all detectors to represent discovered evidence
of malicious activity. It includes confidence scoring, reasoning chains, and
self-correction metadata (contradictions and resolutions).

This class was moved from self_correction/engine.py to enable clean separation
between Community (core detection) and Enterprise (self-correction) editions.
All detectors emit Finding objects regardless of whether self-correction is used.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, List

from .categories import FindingCategory

if TYPE_CHECKING:
    # Import types only for type checking to avoid circular dependencies
    # These types are only used in self-correction (Enterprise)
    pass


@dataclass
class Finding:
    """Represents a forensic finding with confidence and reasoning."""

    # Core finding information
    title: str
    description: str
    finding_type: str  # indicator, behavior, timeline_event
    severity: str  # critical, high, medium, low, info
    category: FindingCategory  # case-agnostic taxonomy label

    # Evidence
    evidence: dict = field(default_factory=dict)

    # Confidence and reasoning
    confidence: float = 0.85
    confidence_label: str = "High"
    reasoning_chain: List[str] = field(default_factory=list)

    # Self-correction metadata (Enterprise features)
    contradictions: List[Any] = field(default_factory=list)  # List[Contradiction]
    resolutions: List[Any] = field(default_factory=list)  # List[Resolution]
    confidence_calculation: dict = field(default_factory=dict)

    # Metadata
    detected_at: datetime = field(default_factory=lambda: datetime.now())
    artifact_sources: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "title": self.title,
            "description": self.description,
            "type": self.finding_type,
            "severity": self.severity,
            "category": self.category.value,
            "evidence": self.evidence,
            "confidence": round(self.confidence, 2),
            "confidence_label": self.confidence_label,
            "reasoning_chain": self.reasoning_chain,
            "contradictions": [c.to_dict() for c in self.contradictions],
            "resolutions": [
                {
                    "type": r.contradiction_type,
                    "method": r.resolution_method,
                    "recovery": r.confidence_recovery,
                    "evidence": r.evidence,
                }
                for r in self.resolutions
            ],
            "confidence_calculation": self.confidence_calculation,
            "detected_at": self.detected_at.isoformat(),
            "artifact_sources": self.artifact_sources,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Finding:
        """Create Finding from dictionary (inverse of to_dict)."""
        return cls(
            title=data["title"],
            description=data["description"],
            finding_type=data["type"],
            severity=data["severity"],
            category=FindingCategory(data["category"]),
            evidence=data.get("evidence", {}),
            confidence=data.get("confidence", 0.85),
            confidence_label=data.get("confidence_label", "High"),
            reasoning_chain=data.get("reasoning_chain", []),
            contradictions=[],  # Skip reconstruction for comparison purposes
            resolutions=[],  # Skip reconstruction for comparison purposes
            confidence_calculation=data.get("confidence_calculation", {}),
            detected_at=datetime.fromisoformat(data["detected_at"]),
            artifact_sources=data.get("artifact_sources", []),
        )
