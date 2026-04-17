"""Tests for the case-agnostic FindingCategory taxonomy (SFE-7).

The category field is the contract that lets acceptance tests assert on *what*
the engine found without needing to know *which case* the image belongs to.
These tests guard that contract.
"""

from __future__ import annotations

import pytest

from sift_find_evil.findings import FindingCategory
from sift_find_evil.self_correction.contradiction_detector import (
    Contradiction,
    ContradictionType,
    Severity,
)
from sift_find_evil.self_correction.engine import Finding, _pick_category


def test_taxonomy_includes_required_categories():
    """The roadmap (SFE-7) requires these specific category names to exist."""
    required = {
        "data_exfiltration",
        "timeline_tampering",
        "process_injection",
        "credential_theft",
        "persistence",
        "lateral_movement",
        "anti_forensics",
        "unknown",
    }
    actual = {member.value for member in FindingCategory}
    missing = required - actual
    assert not missing, f"FindingCategory is missing required values: {missing}"


def test_category_is_required_on_finding():
    """Finding(...) without a category must fail at construction time.

    This is the type-system enforcement the roadmap calls out: a detector
    cannot emit a finding that is not tagged. If this test ever passes when
    category is omitted, the taxonomy has degraded to a free-text field.
    """
    with pytest.raises(TypeError):
        Finding(  # type: ignore[call-arg]
            title="x",
            description="x",
            finding_type="indicator",
            severity="low",
        )


def test_category_round_trips_through_to_dict():
    """JSON output must carry the category string."""
    finding = Finding(
        title="t",
        description="d",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.DATA_EXFILTRATION,
    )
    payload = finding.to_dict()
    assert payload["category"] == "data_exfiltration"


def test_pick_category_prefers_anti_forensics_over_timeline():
    """When contradictions span categories, anti_forensics wins.

    A missing artifact (anti_forensics) paired with a timestomp
    (timeline_tampering) is stronger signal as anti_forensics, so the finding
    should surface under that label.
    """
    contradictions = [
        Contradiction(
            type=ContradictionType.TIMESTOMPING,
            severity=Severity.HIGH,
            description="si/fn skew",
            confidence_impact=-0.2,
        ),
        Contradiction(
            type=ContradictionType.MISSING_ARTIFACT,
            severity=Severity.HIGH,
            description="prefetch missing",
            confidence_impact=-0.2,
        ),
    ]
    assert _pick_category(contradictions) is FindingCategory.ANTI_FORENSICS


def test_pick_category_falls_back_to_timeline_tampering():
    """Pure timestamp contradictions map to timeline_tampering."""
    contradictions = [
        Contradiction(
            type=ContradictionType.CAUSALITY_VIOLATION,
            severity=Severity.HIGH,
            description="prefetch before create",
            confidence_impact=-0.2,
        ),
    ]
    assert _pick_category(contradictions) is FindingCategory.TIMELINE_TAMPERING


def test_pick_category_returns_unknown_for_empty_list():
    """No contradictions means no signal — category must be UNKNOWN, not a guess."""
    assert _pick_category([]) is FindingCategory.UNKNOWN
