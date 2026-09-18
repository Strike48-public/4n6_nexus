"""Weak-signal additive risk scoring per subject (SFE-kh4h, gallery #32).

The engine scores confidence PER finding but never accumulates independent weak
signals into a subject-level verdict. One off-hours login is noise; off-hours +
mass-download + external-comms on ONE subject is an incident. This overlay groups
findings by canonical entity and sums gated, weighted, spoofability- and
trust-discounted contributions into a banded subject risk score.

It is a PURE, read-only OVERLAY over already-emitted findings (like dedup /
correlation): it never touches ``evidence['executable']``, so F1 is unaffected.

Design pinned by these tests:
  * additivity -- N independent weak signals on one subject sum to more than any
    one alone (the whole point);
  * grouping -- signals on DIFFERENT subjects do NOT combine;
  * the CRITICAL gate -- the top band requires >=2 DISTINCT artifact-type
    corroborators, so a single spoofable signal (however confident) cannot reach
    CRITICAL on its own;
  * spoofability/trust discount -- a single-source, easily-spoofed signal
    contributes less than a corroborated one.

RED-first: sift_find_evil/findings/risk_scoring.py does not exist yet.
"""

from __future__ import annotations

from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.findings.risk_scoring import (
    _TOP_FLOOR,
    RiskBand,
    score_subject_risk,
)


def _f(title, category, executable, confidence, sources):
    return Finding(
        title=title,
        description="d",
        finding_type="indicator",
        severity="high",
        category=category,
        evidence={"executable": executable},
        confidence=confidence,
        artifact_sources=list(sources),
    )


# -- grouping: distinct subjects do not combine ------------------------------


def test_findings_on_different_subjects_do_not_combine():
    findings = [
        _f("a", FindingCategory.EXECUTION, "alpha.exe", 0.6, ["mft"]),
        _f("b", FindingCategory.PERSISTENCE, "beta.exe", 0.6, ["registry"]),
    ]
    subjects = score_subject_risk(findings)
    keys = {s.subject for s in subjects}
    assert keys == {"alpha.exe", "beta.exe"}, "each subject scored separately"
    # Neither inherits the other's contribution.
    for s in subjects:
        assert len(s.contributors) == 1


# -- additivity: independent weak signals accumulate -------------------------


def test_independent_weak_signals_accumulate_above_any_single():
    one = score_subject_risk(
        [_f("x", FindingCategory.EXECUTION, "evil.exe", 0.4, ["mft"])]
    )[0]
    many = score_subject_risk(
        [
            _f("x1", FindingCategory.EXECUTION, "evil.exe", 0.4, ["mft"]),
            _f("x2", FindingCategory.DATA_EXFILTRATION, "evil.exe", 0.4, ["pcap"]),
            _f("x3", FindingCategory.COMMAND_AND_CONTROL, "evil.exe", 0.4, ["evtx"]),
        ]
    )[0]
    assert many.score > one.score, "three weak signals must outweigh one"
    assert 0.0 <= many.score <= 1.0, "score is clamped to [0,1]"


def test_score_is_a_sum_not_a_max_of_contributions():
    """Two IDENTICAL weak signals must score strictly higher than one.

    Mutation guard: if the accumulator took max() (or first/last) instead of
    summing, two identical contributions would score the SAME as one. Identical
    category/confidence AND the same single source (so trust is held constant)
    isolates the additivity of the accumulator itself. Kept below the clamp so
    the doubling is observable.
    """
    single = score_subject_risk(
        [_f("s1", FindingCategory.RECONNAISSANCE, "e.exe", 0.3, ["evtx"])]
    )[0]
    double = score_subject_risk(
        [
            _f("d1", FindingCategory.RECONNAISSANCE, "e.exe", 0.3, ["evtx"]),
            _f("d2", FindingCategory.RECONNAISSANCE, "e.exe", 0.3, ["evtx"]),
        ]
    )[0]
    # Same subject, same single source -> identical trust; only the count differs.
    assert double.distinct_sources == single.distinct_sources == 1
    assert double.score > single.score + 1e-9, "two identical signals must sum, not max"


def test_score_is_clamped_to_one():
    findings = [
        _f(f"n{i}", FindingCategory.CREDENTIAL_THEFT, "evil.exe", 0.99, [src])
        for i, src in enumerate(["mft", "memory", "pcap", "evtx", "registry"])
    ]
    s = score_subject_risk(findings)[0]
    assert s.score <= 1.0


# -- the CRITICAL gate: >=2 distinct artifact-type corroborators -------------


def test_single_source_signal_cannot_reach_critical():
    # Two STRONG findings from ONE artifact source drive the score to the ceiling
    # (1.0), so it clears the HIGH threshold -- yet with only ONE distinct source
    # the corroboration gate must still cap it at HIGH, never CRITICAL. This is the
    # tight guard: score alone would say CRITICAL; only the gate holds it back.
    findings = [
        _f("lone1", FindingCategory.CREDENTIAL_THEFT, "evil.exe", 0.9, ["memory"]),
        _f("lone2", FindingCategory.PROCESS_INJECTION, "evil.exe", 0.9, ["memory"]),
    ]
    s = score_subject_risk(findings)[0]
    assert s.score >= _TOP_FLOOR, "test premise: the score clears the top-tier floor"
    assert s.distinct_sources == 1, "test premise: only one artifact source"
    assert s.band == RiskBand.HIGH, (
        "a single-source subject must cap at HIGH: only the >=2-source gate, not "
        "the score threshold, may keep it out of CRITICAL"
    )


def test_multi_source_corroborated_incident_reaches_critical():
    # Same subject, strong signals across THREE distinct artifact types.
    findings = [
        _f("c1", FindingCategory.CREDENTIAL_THEFT, "evil.exe", 0.9, ["memory"]),
        _f("c2", FindingCategory.ANTI_FORENSICS, "evil.exe", 0.9, ["mft"]),
        _f("c3", FindingCategory.COMMAND_AND_CONTROL, "evil.exe", 0.9, ["pcap"]),
    ]
    s = score_subject_risk(findings)[0]
    assert (
        s.band == RiskBand.CRITICAL
    ), "corroborated multi-artifact compromise on one subject is CRITICAL"
    assert s.distinct_sources >= 2


# -- spoofability / trust discount -------------------------------------------


def test_corroborated_signal_outscores_equal_single_source():
    single = score_subject_risk(
        [_f("s", FindingCategory.EXECUTION, "a.exe", 0.8, ["mft"])]
    )[0]
    corroborated = score_subject_risk(
        [
            _f("c1", FindingCategory.EXECUTION, "b.exe", 0.8, ["mft"]),
            _f("c2", FindingCategory.EXECUTION, "b.exe", 0.8, ["memory"]),
        ]
    )[0]
    assert corroborated.score > single.score, "corroboration raises trust"


# -- overlay invariants ------------------------------------------------------


def test_empty_findings_yield_no_subjects():
    assert score_subject_risk([]) == []


def test_dict_shaped_finding_scores_same_as_dataclass():
    """A finding passed as its to_dict() mapping must score like the dataclass.

    canonical_entity already accepts both shapes; keying category/confidence/
    sources on getattr silently zeroed a dict finding (right subject, lost score
    -> dropped). Reading dict-or-attr fixes that asymmetry.
    """
    f = _f("d", FindingCategory.CREDENTIAL_THEFT, "evil.exe", 0.9, ["memory", "mft"])
    from_obj = score_subject_risk([f])
    from_dict = score_subject_risk([f.to_dict()])
    assert from_obj and from_dict, "neither shape may drop the finding"
    assert from_dict[0].subject == from_obj[0].subject == "evil.exe"
    assert abs(from_dict[0].score - from_obj[0].score) < 1e-9, "shapes score equally"
    assert from_dict[0].band == from_obj[0].band


def test_findings_without_entity_fall_back_to_title_not_dropped():
    # A finding with no structured entity still gets a subject (title fallback),
    # so the overlay never silently drops a scored finding.
    f = Finding(
        title="orphan signal",
        description="d",
        finding_type="indicator",
        severity="medium",
        category=FindingCategory.RECONNAISSANCE,
        evidence={},  # no executable/ip/hash -> no canonical entity
        confidence=0.5,
        artifact_sources=["evtx"],
    )
    subjects = score_subject_risk([f])
    assert len(subjects) == 1
    assert subjects[0].contributors, "the orphan finding is still attributed"


def test_band_ladder_maps_score_ranges_correctly():
    """Pin the LOW/MEDIUM/HIGH ladder for scores below the top-tier floor.

    The band floors name the band a score AT OR ABOVE lands in, so a mid score in
    [_HIGH_FLOOR, _TOP_FLOOR) is HIGH and one in [_MEDIUM_FLOOR, _HIGH_FLOOR) is
    MEDIUM. Regression guard for the earlier misleading threshold naming, and it
    covers the [0.4,0.7) range the reviewer flagged as untested.
    """
    from sift_find_evil.findings.risk_scoring import _band

    assert _band(0.05, 1) == RiskBand.LOW
    assert _band(0.25, 1) == RiskBand.MEDIUM
    assert _band(0.55, 1) == RiskBand.HIGH  # [0.4, 0.7) -> HIGH, not MEDIUM
    assert _band(0.95, 1) == RiskBand.HIGH  # top floor but 1 source -> gated to HIGH
    assert _band(0.95, 2) == RiskBand.CRITICAL  # top floor + corroboration


def test_zero_weight_only_subject_is_omitted_not_a_spurious_low_row():
    """A subject whose only findings are zero-weight (ANALYSIS_GAP/UNKNOWN) is
    omitted -- it carries no risk signal, so it must not clutter the overlay."""
    findings = [
        _f("gap", FindingCategory.ANALYSIS_GAP, "tooling.sys", 0.9, ["memory"]),
        _f("unk", FindingCategory.UNKNOWN, "mystery.dat", 0.9, ["mft"]),
    ]
    assert score_subject_risk(findings) == [], "zero-risk subjects are dropped"


def test_result_is_sorted_by_descending_risk():
    findings = [
        _f("low", FindingCategory.RECONNAISSANCE, "low.exe", 0.3, ["evtx"]),
        _f("hi1", FindingCategory.CREDENTIAL_THEFT, "hi.exe", 0.9, ["memory"]),
        _f("hi2", FindingCategory.ANTI_FORENSICS, "hi.exe", 0.9, ["mft"]),
    ]
    subjects = score_subject_risk(findings)
    scores = [s.score for s in subjects]
    assert scores == sorted(scores, reverse=True), "highest-risk subject first"
