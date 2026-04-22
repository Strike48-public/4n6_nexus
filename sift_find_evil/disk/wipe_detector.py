"""Detect partition-table wipes as an anti-forensic indicator.

A disk where the *primary* GPT (LBA 0-33) has been zeroed while the *secondary*
GPT (trailing LBAs) is still intact is a strong signal that someone wiped the
front of the disk. That pattern shows up routinely in anti-forensic workflows
(e.g. `dd if=/dev/zero of=/dev/sdX bs=1M count=10`) and is exactly what the
CIRCL `wiped_disk.E01` practice image contains.

This detector turns that observation into a CRITICAL finding that plugs into
the same CLI/report pipeline as the MFT/Prefetch/EVTX findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .gpt_inspector import GPTInspection, inspect_ewf, inspect_raw
from ..findings import FindingCategory

WIPE_FINDING_TITLE = "Partition table wiped (primary GPT zeroed, secondary GPT intact)"
WIPE_FINDING_DESCRIPTION = (
    "The primary GPT header at LBA 1 is absent while the secondary GPT at the "
    "last sector is well-formed and enumerates partitions. This asymmetry is "
    "characteristic of a deliberate front-of-disk wipe used to hide evidence; "
    "native OS actions do not produce it."
)


@dataclass(frozen=True)
class WipedDiskFinding:
    """A finding that mirrors the engine `Finding` shape so the CLI can render it."""

    title: str
    description: str
    finding_type: str
    severity: str
    confidence: float
    confidence_label: str
    category: FindingCategory
    evidence: dict[str, Any] = field(default_factory=dict)
    reasoning_chain: list[str] = field(default_factory=list)
    contradictions: list[Any] = field(default_factory=list)
    resolutions: list[Any] = field(default_factory=list)
    confidence_calculation: dict[str, Any] = field(default_factory=dict)
    artifact_sources: list[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        """Convert finding to a dictionary for serialization.

        Returns:
            Dictionary with all finding details in a structure matching the
            engine Finding format for CLI/report rendering.
        """
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
            "contradictions": self.contradictions,
            "resolutions": self.resolutions,
            "confidence_calculation": self.confidence_calculation,
            "detected_at": self.detected_at.isoformat(),
            "artifact_sources": self.artifact_sources,
        }


def _build_reasoning(inspection: GPTInspection) -> list[str]:
    steps: list[str] = []
    steps.append(
        f"Sector 0 (protective MBR): "
        f"{'all zeros' if inspection.primary_mbr_zeroed else 'present'}"
    )
    steps.append(
        f"Sector 1 (primary GPT header): "
        f"{'all zeros' if inspection.primary_header_zeroed else 'parseable'}"
    )
    if inspection.secondary_header:
        sh = inspection.secondary_header
        steps.append(
            f"Secondary GPT header at LBA {sh.my_lba} has valid EFI PART signature"
        )
        steps.append(
            f"Secondary GPT enumerates {len(inspection.secondary_entries)} partition(s)"
        )
        for entry in inspection.secondary_entries:
            steps.append(
                f"  partition {entry.index + 1}: "
                f"LBA {entry.first_lba}-{entry.last_lba} "
                f"({entry.size_bytes / (1024 ** 3):.2f} GiB) "
                f"type={entry.type_guid} name={entry.name!r}"
            )
    steps.append(
        "Asymmetry (primary wiped, secondary valid) cannot be produced by normal "
        "OS behavior; it is the expected outcome of a front-of-disk wipe."
    )
    return steps


def _build_evidence(inspection: GPTInspection, source: Path | None) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "total_sectors": inspection.total_sectors,
        "primary_mbr_zeroed": inspection.primary_mbr_zeroed,
        "primary_header_zeroed": inspection.primary_header_zeroed,
        "primary_header_present": inspection.primary_header is not None,
        "secondary_header_valid": inspection.secondary_valid,
    }
    if source is not None:
        evidence["image_path"] = str(source)
    if inspection.secondary_header:
        evidence["secondary_header"] = inspection.secondary_header.to_dict()
        evidence["secondary_entries"] = [
            e.to_dict() for e in inspection.secondary_entries
        ]
    return evidence


def detect_wiped_disk(
    inspection: GPTInspection,
    *,
    source: Path | None = None,
) -> WipedDiskFinding | None:
    """Return a CRITICAL finding if the GPT layout looks wiped, else None.

    The trigger is asymmetry: primary header missing or zeroed, secondary still
    valid. We do not flag disks where both headers are intact (healthy), nor
    disks where both are missing (likely not GPT at all).
    """
    if not inspection.secondary_valid:
        return None
    if not inspection.primary_wiped:
        return None

    reasoning = _build_reasoning(inspection)
    evidence = _build_evidence(inspection, source)

    return WipedDiskFinding(
        title=WIPE_FINDING_TITLE,
        description=WIPE_FINDING_DESCRIPTION,
        finding_type="indicator",
        severity="critical",
        confidence=0.95,
        confidence_label="Very High",
        category=FindingCategory.ANTI_FORENSICS,
        evidence=evidence,
        reasoning_chain=reasoning,
        artifact_sources=["disk_image"],
        confidence_calculation={
            "base": 0.95,
            "rationale": "Primary/secondary GPT asymmetry is a near-deterministic wipe signature.",
        },
    )


def detect_from_image(image_path: Path) -> WipedDiskFinding | None:
    """Convenience: inspect an E01 or raw image and run the detector."""
    suffix = image_path.suffix.lower()
    if suffix in {".e01", ".ewf"}:
        inspection = inspect_ewf(image_path)
    else:
        inspection = inspect_raw(image_path)
    return detect_wiped_disk(inspection, source=image_path)
