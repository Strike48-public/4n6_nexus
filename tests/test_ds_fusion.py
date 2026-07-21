"""Tests for Dempster-Shafer evidence fusion (idea #19).

Validates BPA construction, Dempster combination with conflict-K,
Yager fallback on high conflict, belief/plausibility bounds, and the
fuse() decision policy. Every positive case is paired with an inverse
or negative control.
"""

from __future__ import annotations

import pytest

from sift_find_evil.fusion.ds_fusion import (
    FusionResult,
    belief,
    dempster_combine,
    detector_bpa,
    fuse,
    plausibility,
)

M = frozenset({"M"})
B = frozenset({"B"})
THETA = frozenset({"M", "B"})

TOL = 1e-9


def _mass_sum(bpa: dict[frozenset[str], float]) -> float:
    return sum(bpa.values())


def test_detector_bpa_sums_to_one_and_discounts_by_rho() -> None:
    # Arrange / Act
    bpa = detector_bpa(confidence=0.8, rho=0.5)

    # Assert
    assert _mass_sum(bpa) == pytest.approx(1.0, abs=TOL)
    assert bpa[M] == pytest.approx(0.4, abs=TOL)
    assert bpa[B] == pytest.approx(0.1, abs=TOL)
    # remaining ignorance
    assert bpa[THETA] == pytest.approx(0.5, abs=TOL)


def test_detector_bpa_full_reliability_no_ignorance() -> None:
    # Inverse control: rho=1.0 leaves no ignorance mass.
    bpa = detector_bpa(confidence=0.9, rho=1.0)

    assert bpa[M] == pytest.approx(0.9, abs=TOL)
    assert bpa[B] == pytest.approx(0.1, abs=TOL)
    assert bpa[THETA] == pytest.approx(0.0, abs=TOL)
    assert _mass_sum(bpa) == pytest.approx(1.0, abs=TOL)


def test_two_agreeing_strong_detectors_low_conflict() -> None:
    # Arrange
    bpa1 = detector_bpa(confidence=0.9, rho=0.9)
    bpa2 = detector_bpa(confidence=0.85, rho=0.9)

    # Act
    combined, k = dempster_combine(bpa1, bpa2)

    # Assert
    assert k < 0.5
    assert belief(combined, "M") > belief(bpa1, "M")
    assert _mass_sum(combined) == pytest.approx(1.0, abs=1e-6)


def test_two_disagreeing_strong_detectors_high_conflict() -> None:
    # Arrange: one says malicious, one says benign, both reliable.
    bpa1 = detector_bpa(confidence=0.95, rho=0.95)
    bpa2 = detector_bpa(confidence=0.05, rho=0.95)

    # Act
    _combined, k = dempster_combine(bpa1, bpa2)

    # Assert: near-total conflict.
    assert k >= 0.7


def test_belief_never_exceeds_plausibility() -> None:
    for conf, rho in [(0.8, 0.9), (0.2, 0.5), (0.5, 0.5), (0.99, 1.0)]:
        bpa = detector_bpa(confidence=conf, rho=rho)
        assert belief(bpa, "M") <= plausibility(bpa, "M") + TOL
        assert belief(bpa, "B") <= plausibility(bpa, "B") + TOL


def test_combined_mass_sums_to_one_under_yager() -> None:
    # High-conflict pair triggers Yager; mass must still sum to 1.
    bpa1 = detector_bpa(confidence=0.98, rho=0.98)
    bpa2 = detector_bpa(confidence=0.02, rho=0.98)

    combined, k = dempster_combine(bpa1, bpa2)

    assert k >= 0.7
    assert _mass_sum(combined) == pytest.approx(1.0, abs=1e-6)
    # Yager dumps conflict into ignorance, so theta should be large.
    assert combined[THETA] > 0.5


def test_fuse_confirm_on_strong_agreement() -> None:
    # Act
    result = fuse([(0.9, 0.95), (0.88, 0.9), (0.85, 0.9)])

    # Assert
    assert isinstance(result, FusionResult)
    assert result.decision == "confirm"
    assert result.bel_malicious >= 0.7
    assert result.conflict_k < 0.5


def test_fuse_conflict_on_strong_disagreement() -> None:
    result = fuse([(0.97, 0.95), (0.03, 0.95)])

    assert result.decision == "conflict"
    assert result.conflict_k >= 0.7


def test_fuse_observe_on_single_weak_detector() -> None:
    # Negative control: weak signal must not confirm.
    result = fuse([(0.55, 0.4)])

    assert result.decision == "observe"
    assert result.bel_malicious < 0.7
    assert result.conflict_k < 0.7


def test_fuse_belief_le_plausibility_and_k_bounds() -> None:
    result = fuse([(0.7, 0.8), (0.6, 0.7)])

    assert result.bel_malicious <= result.pl_malicious + TOL
    assert 0.0 <= result.conflict_k <= 1.0


def test_fuse_empty_raises() -> None:
    # Inverse control: no detectors is a programmer error.
    with pytest.raises(ValueError):
        fuse([])


def test_unknown_hypothesis_raises() -> None:
    # Covers the raise in _hypothesis_set via the public belief/plausibility.
    bpa = detector_bpa(confidence=0.5, rho=0.5)
    with pytest.raises(ValueError):
        belief(bpa, "X")
    with pytest.raises(ValueError):
        plausibility(bpa, "X")


def test_detector_bpa_confidence_out_of_range_raises() -> None:
    # Inverse control: confidence must be in [0, 1].
    with pytest.raises(ValueError):
        detector_bpa(confidence=1.5, rho=0.5)


def test_detector_bpa_rho_out_of_range_raises() -> None:
    # Inverse control: rho must be in [0, 1].
    with pytest.raises(ValueError):
        detector_bpa(confidence=0.5, rho=1.5)


def test_total_conflict_below_threshold_defers_to_yager(monkeypatch) -> None:
    # Force the "denom <= 0 with K below threshold" guard branch by raising the
    # Yager threshold above 1.0 and feeding two fully-disjoint certain BPAs so
    # conflict == 1.0 (K below the raised threshold, denom == 0).
    monkeypatch.setattr("sift_find_evil.fusion.ds_fusion.YAGER_CONFLICT_THRESHOLD", 1.5)
    bpa1 = {M: 1.0, B: 0.0, THETA: 0.0}
    bpa2 = {M: 0.0, B: 1.0, THETA: 0.0}

    combined, k = dempster_combine(bpa1, bpa2)

    assert k == pytest.approx(1.0, abs=TOL)
    assert combined[THETA] == pytest.approx(1.0, abs=TOL)
    assert _mass_sum(combined) == pytest.approx(1.0, abs=TOL)
