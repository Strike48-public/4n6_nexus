"""End-to-end scenario tests: verify precision/recall on synthetic fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.scenario_harness import discover_scenarios, run_scenario


REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = discover_scenarios(REPO_ROOT)


@pytest.mark.parametrize("expectation", SCENARIOS, ids=lambda s: s.name)
def test_scenario_precision_and_recall(expectation):
    """Each scenario must achieve perfect precision and recall on malicious executables."""
    result = run_scenario(expectation)

    assert (
        not result.false_positives
    ), f"{expectation.name}: unexpected false positives: {result.false_positives}"
    assert (
        not result.false_negatives
    ), f"{expectation.name}: missed detections: {result.false_negatives}"
    assert result.precision == 1.0
    assert result.recall == 1.0


def test_clean_baseline_has_zero_findings():
    """Sanity check: clean baseline must produce no findings."""
    clean = next(s for s in SCENARIOS if s.name == "01_clean_baseline")
    result = run_scenario(clean)
    assert result.findings_count == 0


def test_ransomware_confidence_recovers_via_event_log():
    """Causality violations should rebound above 0.60 once Event Log resolves them."""
    ransomware = next(s for s in SCENARIOS if s.name == "02_ransomware")
    result = run_scenario(ransomware)
    assert result.average_confidence >= 0.60
