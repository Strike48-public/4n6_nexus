"""Scenario-path injection detection (SFE-piwv).

The MCP server path already sentinel-wraps hostile tool output (PR #64). The
standalone/harness path that the recall + benchmark corpus is scored on invokes
no LLM, so wrapping has nothing to protect there; the load-bearing move is to
treat an injection attempt *embedded in evidence* as a scoreable detection via
``finding_from_scan``. These tests pin that behaviour end-to-end on a dedicated
synthetic scenario, and guard it against silent regression (mutation guard).
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

from sift_find_evil.findings.categories import FindingCategory
from tests.scenario_harness import discover_scenarios, run_scenario

REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = discover_scenarios(REPO_ROOT)
INJECTION_SCENARIO = "24_evidence_injection"


def _injection_scenario():
    return next((s for s in SCENARIOS if s.name == INJECTION_SCENARIO), None)


def test_injection_scenario_is_discovered():
    """The injection scenario must be picked up by the harness discovery glob."""
    assert _injection_scenario() is not None, (
        f"{INJECTION_SCENARIO} not discovered; a scenario.yaml exposing an "
        "injection fixture is required for injection to be scored."
    )


def test_injection_scenario_emits_exactly_one_injection_finding():
    """A real run over the injection fixture surfaces one injection finding."""
    scenario = _injection_scenario()
    assert scenario is not None
    result = run_scenario(scenario)

    assert result.false_positives == [], result.false_positives
    assert result.false_negatives == [], result.false_negatives
    assert result.precision == 1.0
    assert result.recall == 1.0


def test_injection_finding_is_categorized_and_payload_free():
    """The emitted finding is ANTI_FORENSICS and never re-emits the raw payload."""
    scenario = _injection_scenario()
    assert scenario is not None
    findings = run_scenario(scenario).findings  # type: ignore[attr-defined]
    injection = [
        f
        for f in findings
        if f.category == FindingCategory.ANTI_FORENSICS
        and "injection" in f.title.lower()
    ]
    assert len(injection) == 1, injection
    ev = injection[0].evidence
    # Counts-only contract: aggregate indicators, never the raw hostile text.
    assert "indicator_counts" in ev
    assert ev.get("total_indicators", 0) >= 1


def test_unexpected_injection_finding_counts_as_false_positive():
    """An injection finding with no matching ground truth must lower precision.

    Guards the F1-safety branch: if the detector fires on a scenario that
    declared an injection fixture but expects zero injection findings, the
    surplus must be scored as a false positive, not silently dropped.
    """
    scenario = _injection_scenario()
    assert scenario is not None
    # Same hostile fixture, but ground truth expects NO injection finding.
    no_expectation = dataclasses.replace(scenario, finding_counts={})
    result = run_scenario(no_expectation)

    assert "injection_attempt" in result.false_positives
    assert result.precision < 1.0
