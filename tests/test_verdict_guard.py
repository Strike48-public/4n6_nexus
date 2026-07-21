"""Tests for the verdict rank clamp (gallery idea #10).

A structural severity ceiling: the analyst LLM narrates freely, but a finding's
severity cannot exceed what the deterministic detector output supports, and a
single-source finding cannot reach the top tier without independent
corroboration. This is the cheapest possible hallucination firewall - pure code,
no model, CI-testable.

RED-first: sift_find_evil.findings.verdict_guard did not exist before.
"""

import pytest

from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.findings.verdict_guard import (
    SEVERITY_RANK,
    VerdictClampError,
    clamp_severity,
    guard_finding,
)


def _finding(severity: str, sources: list[str]) -> Finding:
    return Finding(
        title="t",
        description="d",
        finding_type="indicator",
        severity=severity,
        category=FindingCategory.EXECUTION,
        evidence={},
        confidence=0.9,
        artifact_sources=sources,
    )


def test_severity_rank_is_ordered():
    assert SEVERITY_RANK["info"] < SEVERITY_RANK["low"] < SEVERITY_RANK["medium"]
    assert SEVERITY_RANK["medium"] < SEVERITY_RANK["high"] < SEVERITY_RANK["critical"]


def test_claimed_severity_above_engine_is_clamped_down():
    # Detector supports at most 'medium'; analyst claims 'critical'.
    assert clamp_severity(claimed="critical", engine_ceiling="medium") == "medium"


def test_claimed_severity_below_engine_is_left_alone():
    # We never inflate; a conservative claim stays as-is.
    assert clamp_severity(claimed="low", engine_ceiling="critical") == "low"


def test_equal_severity_passes_through():
    assert clamp_severity(claimed="high", engine_ceiling="high") == "high"


def test_guard_finding_downgrades_inflated_severity():
    f = _finding("critical", sources=["MFT", "Prefetch"])
    guarded = guard_finding(f, engine_ceiling="medium")
    assert guarded.severity == "medium"
    # Original finding is not mutated (immutability).
    assert f.severity == "critical"
    # The clamp is recorded in the reasoning chain for the audit trail.
    assert any("clamp" in r.lower() for r in guarded.reasoning_chain)


def test_single_source_finding_capped_below_top_tier():
    # A single-artifact finding cannot be 'critical' until corroborated.
    f = _finding("critical", sources=["shimcache"])
    guarded = guard_finding(f, engine_ceiling="critical")
    assert SEVERITY_RANK[guarded.severity] < SEVERITY_RANK["critical"]


def test_multi_source_finding_may_reach_top_tier():
    f = _finding("critical", sources=["MFT", "EventLog", "Prefetch"])
    guarded = guard_finding(f, engine_ceiling="critical")
    assert guarded.severity == "critical"


def test_unknown_severity_string_raises():
    with pytest.raises(VerdictClampError):
        clamp_severity(claimed="apocalyptic", engine_ceiling="high")
