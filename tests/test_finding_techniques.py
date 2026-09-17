"""Tests for the first-class ``Finding.techniques`` field (SFE-fibx.4 PR-A).

MITRE technique ids were carried under three drifting evidence keys
(``mitre_attack`` list, ``mitre_technique`` scalar, ``mitre`` scalar). This
promotes them to a first-class ``Finding.techniques`` field with a single
accessor, while keeping the legacy evidence keys readable so no serialized
finding or downstream consumer regresses.
"""

from __future__ import annotations

from sift_find_evil.findings.categories import FindingCategory
from sift_find_evil.findings.finding import Finding
from sift_find_evil.reporting.mitre_guardrail import confirmed_matrix


def _finding(**kw) -> Finding:
    """A minimal Finding with overridable fields."""
    base = dict(
        title="t",
        description="d",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.PROCESS_INJECTION,
    )
    base.update(kw)
    return Finding(**base)


# ─── the field exists, defaults empty, round-trips ───────────────────────────


def test_techniques_defaults_empty() -> None:
    """A finding with no techniques has an empty list, not None."""
    assert _finding().techniques == []


def test_techniques_is_serialized_and_round_trips() -> None:
    """to_dict emits techniques; from_dict restores them."""
    f = _finding(techniques=["T1055", "T1071"])
    d = f.to_dict()
    assert d["techniques"] == ["T1055", "T1071"]
    assert Finding.from_dict(d).techniques == ["T1055", "T1071"]


# ─── the single accessor: field first, legacy evidence keys as fallback ──────


def test_mitre_techniques_prefers_first_class_field() -> None:
    """When the field is set it is authoritative, even over evidence keys."""
    f = _finding(techniques=["T1486"], evidence={"mitre_attack": ["T9999"]})
    assert f.mitre_techniques() == ["T1486"]


def test_mitre_techniques_falls_back_to_canonical_evidence_key() -> None:
    """A finding that only set evidence['mitre_attack'] still surfaces techniques."""
    f = _finding(evidence={"mitre_attack": ["T1055", "T1071"]})
    assert f.mitre_techniques() == ["T1055", "T1071"]


def test_mitre_techniques_falls_back_to_legacy_scalar_keys() -> None:
    """The two scalar legacy keys (mitre_technique, mitre) are still honored."""
    assert _finding(evidence={"mitre_technique": "T1110"}).mitre_techniques() == [
        "T1110"
    ]
    assert _finding(evidence={"mitre": "T1021"}).mitre_techniques() == ["T1021"]


def test_mitre_techniques_empty_when_nothing_set() -> None:
    """No field and no evidence key → empty, never a crash."""
    assert _finding().mitre_techniques() == []


# ─── the guardrail reads the first-class field (no regression) ───────────────


def test_confirmed_matrix_reads_first_class_techniques_field() -> None:
    """confirmed_matrix must credit a finding that used ONLY the new field.

    This is the load-bearing non-regression: detectors migrating to techniques=
    must still land in the confirmed MITRE matrix.
    """
    f = _finding(techniques=["T1055"])
    report = confirmed_matrix([f.to_dict()])
    assert "T1055" in {c["technique_id"] for c in report.confirmed}


def test_confirmed_matrix_still_reads_legacy_evidence_keys() -> None:
    """A finding that predates the migration (evidence key only) is still credited."""
    f = _finding(evidence={"mitre_attack": ["T1071"]})
    report = confirmed_matrix([f.to_dict()])
    assert "T1071" in {c["technique_id"] for c in report.confirmed}


# ─── engine-wide coverage: the backfill is load-bearing on the real corpus ───


def test_scenario_findings_overwhelmingly_carry_a_technique() -> None:
    """After the PR-A backfill, nearly every real-corpus finding cites a technique.

    Locks in the sweep so a future detector added without a technique is visible in
    review as a coverage drop. The one documented exception is the injection-attempt
    finding, which maps to no single ATT&CK technique. Gated with the F1 harness so
    this cannot silently regress detection.
    """
    import tests.scenario_harness as harness

    total = 0
    with_technique = 0
    for expectation in harness.discover_scenarios(harness._REPO_ROOT):
        for finding in harness.run_scenario(expectation).findings:
            total += 1
            if finding.mitre_techniques():
                with_technique += 1
    # 122/123 today; assert the invariant, not the exact count, so adding a
    # scenario doesn't spuriously break it — but a mass regression would.
    assert total >= 100
    assert with_technique >= total - 1
