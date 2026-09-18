"""Data models for report generation."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class ReportFormat(str, Enum):
    """Report output format."""

    MARKDOWN = "markdown"
    HTML = "html"
    PDF = "pdf"


@dataclass
class Report:
    """Forensic investigation report."""

    case_id: str
    case_name: str
    examiner: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    findings: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    iocs: dict = field(default_factory=dict)
    executive_summary: Optional[str] = None
    recommendations: list = field(default_factory=list)
    case_description: Optional[str] = None
    # Self-correction candidate-elimination summary (SFE-fibx.13), loaded from the
    # case's ``findings.hardened.json`` sibling when present. None means no hardened
    # report was produced for this case -- distinct from an empty (all-confirmed)
    # ledger, so the renderer can omit the section rather than overclaim that a
    # self-correction pass ran. Shape: a ``HypothesisLedger.report_summary()`` dict.
    hypothesis_ledger: Optional[dict] = None

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "case_id": self.case_id,
            "case_name": self.case_name,
            "examiner": self.examiner,
            "created_at": self.created_at.isoformat(),
            "findings": self.findings,
            "evidence": self.evidence,
            "iocs": self.iocs,
            "executive_summary": self.executive_summary,
            "recommendations": self.recommendations,
            "case_description": self.case_description,
            "hypothesis_ledger": self.hypothesis_ledger,
        }
