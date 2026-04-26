"""Unit tests for ConfidenceScorer."""

from __future__ import annotations

import pytest

from sift_find_evil.self_correction.confidence_scorer import (
    ConfidenceScorer,
    Resolution,
)
from sift_find_evil.self_correction.contradiction_detector import (
    Contradiction,
    ContradictionType,
    Severity,
)


def test_invalid_base_confidence_raises() -> None:
    """Test ConfidenceScorer raises ValueError for invalid base_confidence."""
    with pytest.raises(ValueError, match="base_confidence must be between 0.0 and 1.0"):
        ConfidenceScorer(base_confidence=1.5)

    with pytest.raises(ValueError, match="base_confidence must be between 0.0 and 1.0"):
        ConfidenceScorer(base_confidence=-0.1)


def test_calculate_initial_confidence_high_artifact_count() -> None:
    """Test calculate_initial_confidence with high artifact count."""
    scorer = ConfidenceScorer(base_confidence=0.85)

    confidence = scorer.calculate_initial_confidence(
        artifact_count=5,
        artifact_types=["MFT", "Prefetch", "EventLog"],
    )

    # Base 0.85 + 0.10 (3+ types) + 0.05 (5+ artifacts) = 1.00
    assert confidence == 1.00


def test_calculate_initial_confidence_medium_artifacts() -> None:
    """Test calculate_initial_confidence with medium artifact count."""
    scorer = ConfidenceScorer(base_confidence=0.85)

    confidence = scorer.calculate_initial_confidence(
        artifact_count=3,
        artifact_types=["MFT", "Prefetch"],
    )

    # Base 0.85 + 0.05 (2 types) = 0.90
    assert confidence == 0.90


def test_apply_contradictions_multiple() -> None:
    """Test apply_contradictions with multiple contradictions."""
    scorer = ConfidenceScorer(base_confidence=0.85)

    contradictions = [
        Contradiction(
            type=ContradictionType.TIMESTOMPING,
            severity=Severity.MEDIUM,
            description="Test contradiction 1",
            confidence_impact=-0.10,
        ),
        Contradiction(
            type=ContradictionType.TEMPORAL_MISMATCH,
            severity=Severity.LOW,
            description="Test contradiction 2",
            confidence_impact=-0.05,
        ),
    ]

    confidence = scorer.apply_contradictions(0.90, contradictions)

    # 0.90 - 0.10 - 0.05 = 0.75
    assert confidence == 0.75


def test_apply_contradictions_empty_list() -> None:
    """Test apply_contradictions with empty list returns original confidence."""
    scorer = ConfidenceScorer(base_confidence=0.85)

    confidence = scorer.apply_contradictions(0.90, [])

    assert confidence == 0.90


def test_apply_resolutions_multiple() -> None:
    """Test apply_resolutions with multiple resolutions."""
    scorer = ConfidenceScorer(base_confidence=0.85)

    resolutions = [
        Resolution(
            contradiction_type="timestomping",
            resolution_method="cross_validate",
            confidence_recovery=0.05,
            evidence={},
        ),
        Resolution(
            contradiction_type="temporal_mismatch",
            resolution_method="timestamp_align",
            confidence_recovery=0.10,
            evidence={},
        ),
    ]

    confidence = scorer.apply_resolutions(0.70, resolutions)

    # 0.70 + 0.05 + 0.10 = 0.85
    assert confidence == 0.85


def test_apply_resolutions_empty_list() -> None:
    """Test apply_resolutions with empty list returns original confidence."""
    scorer = ConfidenceScorer(base_confidence=0.85)

    confidence = scorer.apply_resolutions(0.70, [])

    assert confidence == 0.70
