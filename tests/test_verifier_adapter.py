"""Tests for the verifier adapter: self-correction engine -> A2A Verification records.

The dfir-verifier agent challenges analyst findings using the existing
self_correction engine (disk/timeline contradiction logic). This adapter turns a
Finding's self-correction metadata (contradictions, resolutions, confidence
calculation) into the A2A Verification records that get written to the audit log --
so the self-correction loop is traceable per analysis/A2A_MESSAGE_SCHEMA.md.
"""

from __future__ import annotations

from sift_find_evil.findings.finding import Finding
from sift_find_evil.findings.categories import FindingCategory
from sift_find_evil.self_correction.confidence_scorer import Resolution
from sift_find_evil.self_correction.contradiction_detector import (
    Contradiction,
    ContradictionType,
    Severity,
)
from sift_find_evil.self_correction.verifier_adapter import finding_to_verification


def _finding_with_resolved_causality() -> Finding:
    contradiction = Contradiction(
        type=ContradictionType.CAUSALITY_VIOLATION,
        severity=Severity.HIGH,
        description="malware.exe executed at 14:25 but modified at 14:40",
        confidence_impact=-0.50,
    )
    resolution = Resolution(
        contradiction_type="causality_violation",
        resolution_method="event_log_4688_tiebreaker",
        confidence_recovery=0.30,
        evidence={"event_id": 4688, "confirmed_time": "14:25:03"},
    )
    return Finding(
        title="Suspicious Activity: malware.exe",
        description="...",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.TIMELINE_TAMPERING,
        confidence=0.75,
        contradictions=[contradiction],
        resolutions=[resolution],
        confidence_calculation={"initial_confidence": 0.95, "final_confidence": 0.75},
    )


def _finding_clean() -> Finding:
    return Finding(
        title="Benign",
        description="...",
        finding_type="indicator",
        severity="low",
        category=FindingCategory.UNKNOWN,
        confidence=0.85,
        contradictions=[],
        resolutions=[],
        confidence_calculation={"initial_confidence": 0.85, "final_confidence": 0.85},
    )


def test_resolved_contradiction_maps_to_verification():
    v = finding_to_verification(_finding_with_resolved_causality(), finding_id="F-1")

    assert v.finding_id == "F-1"
    assert v.verifier == "verifier"
    assert v.verdict == "contradiction_resolved"
    assert v.domain == "disk_timeline"
    assert v.contradiction_type == "causality_violation"
    assert v.confidence_before == 0.95
    assert v.confidence_after == 0.75
    # delta reflects the contradiction penalty, recovery reflects the resolution
    assert v.confidence_delta == -0.50
    assert v.recovery_delta == 0.30
    assert "event_log" in (v.reasoning or "").lower() or v.reasoning


def test_unresolved_contradiction_maps_to_detected():
    f = _finding_with_resolved_causality()
    f.resolutions = []  # contradiction found but not resolved
    f.confidence = 0.45
    f.confidence_calculation = {"initial_confidence": 0.95, "final_confidence": 0.45}

    v = finding_to_verification(f, finding_id="F-2")

    assert v.verdict == "contradiction_detected"
    assert v.recovery_delta == 0.0
    assert v.confidence_after == 0.45


def test_clean_finding_maps_to_confirmed():
    v = finding_to_verification(_finding_clean(), finding_id="F-3")

    assert v.verdict == "confirmed"
    assert v.contradiction_type is None
    assert v.confidence_before == v.confidence_after == 0.85


def test_verification_is_audit_serializable():
    v = finding_to_verification(_finding_with_resolved_causality(), finding_id="F-1")
    d = v.to_dict()
    assert d["verdict"] == "contradiction_resolved"
    assert d["domain"] == "disk_timeline"
    assert d["confidence_after"] == 0.75
