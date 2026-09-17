"""Tests for Finding provenance: source_exec_id + observation/interpretation split.

SFE-fibx.4 PR-B (additive). A finding must be able to cite the specific input it
was derived from (``source_exec_id``) and separate what was OBSERVED (a fact read
from tool output) from what was INTERPRETED (the analytic conclusion). Both are
additive here; PR-C flips ``source_exec_id`` to construction-fails-without-it.

Design: there is NO real per-tool-execution id on the deterministic engine/analyze
path (verified: neither ``analyze_artifacts`` nor the connector adapter carries
one). So ``source_exec_id`` is DERIVED from the finding's own provenance — the
exact consumed record (``evidence['source_span']``, SFE-fsno) when present, else a
stable digest of the artifact source + evidence — computed in ``__post_init__`` when
not explicitly supplied. One format on both the engine and connector paths.
"""

from __future__ import annotations

from sift_find_evil.findings.categories import FindingCategory
from sift_find_evil.findings.finding import Finding


def _finding(**kw) -> Finding:
    base = dict(
        title="t",
        description="d",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.PROCESS_INJECTION,
    )
    base.update(kw)
    return Finding(**base)


# ─── source_exec_id is auto-derived, stable, and artifact-scoped ─────────────


def test_source_exec_id_is_auto_derived_when_not_supplied() -> None:
    """A finding that sets no exec id still gets a non-empty derived one."""
    f = _finding(artifact_sources=["MFT"], evidence={"executable": "evil.exe"})
    assert f.source_exec_id
    assert f.source_exec_id.startswith("mft:")


def test_source_exec_id_is_deterministic_for_same_provenance() -> None:
    """Same artifact + same source record → same id (so it is reproducible)."""
    kw = dict(
        artifact_sources=["MFT"],
        evidence={"source_span": '{"pid": 1234, "addr": "203.0.113.9"}'},
    )
    assert _finding(**kw).source_exec_id == _finding(**kw).source_exec_id


def test_source_exec_id_differs_for_different_source_records() -> None:
    """Two findings from different records get distinct ids (no collision)."""
    a = _finding(artifact_sources=["netscan"], evidence={"source_span": "row-A"})
    b = _finding(artifact_sources=["netscan"], evidence={"source_span": "row-B"})
    assert a.source_exec_id != b.source_exec_id


def test_source_exec_id_prefers_source_span_over_whole_evidence() -> None:
    """When a span is present it, not the whole evidence blob, seeds the id.

    So two findings that share a span but differ in unrelated evidence keys
    (e.g. a volatile detected_at echoed into evidence) still get the SAME id.
    """
    span = '{"pid": 1234}'
    a = _finding(artifact_sources=["netscan"], evidence={"source_span": span, "x": 1})
    b = _finding(artifact_sources=["netscan"], evidence={"source_span": span, "x": 2})
    assert a.source_exec_id == b.source_exec_id


def test_explicit_source_exec_id_is_respected() -> None:
    """A caller that already has a real exec id (e.g. a tool run) can pass it."""
    f = _finding(source_exec_id="mftecmd-001")
    assert f.source_exec_id == "mftecmd-001"


def test_source_exec_id_round_trips() -> None:
    """to_dict emits it; from_dict restores it verbatim (not re-derived)."""
    f = _finding(source_exec_id="vol-042")
    d = f.to_dict()
    assert d["source_exec_id"] == "vol-042"
    assert Finding.from_dict(d).source_exec_id == "vol-042"


def test_stable_default_renders_a_set_as_a_sorted_list() -> None:
    """A set-valued evidence field must not make the id flaky.

    No detector stores a set today, but the id feeds a hard construction gate
    (PR-C), so the derivation must render a set DETERMINISTICALLY. Assert the
    rendering directly (a sorted list), because str(set) orders by hash seed and
    so differs across interpreter runs — a same-process equality check cannot see
    that variance, but the sorted-list contract closes it by construction.
    """
    assert Finding._stable_default({"c", "a", "b"}) == ["a", "b", "c"]
    assert Finding._stable_default(frozenset({3, 1, 2})) == [1, 2, 3]
    # And it still round-trips through the id derivation without raising.
    f = _finding(artifact_sources=["memory"], evidence={"tags": {"a", "b", "c"}})
    assert f.source_exec_id.startswith("memory:")


def test_source_exec_id_derivable_without_artifact_sources() -> None:
    """A finding with neither artifact_sources nor span still gets a stable id.

    (Falls back to an ``unknown:`` scope over the evidence digest — never empty,
    so PR-C's construction-fails-without-it flip has nothing to trip on.)
    """
    f = _finding(evidence={"executable": "x.exe"})
    assert f.source_exec_id
    assert f.source_exec_id.startswith("unknown:")


# ─── observation / interpretation split ──────────────────────────────────────


def test_observation_and_interpretation_default_empty() -> None:
    """Both fields default to empty strings (additive, no detector must set them)."""
    f = _finding()
    assert f.observation == ""
    assert f.interpretation == ""


def test_observation_and_interpretation_round_trip() -> None:
    """The split survives serialization."""
    f = _finding(
        observation="MFT $SI mtime is later than Prefetch last-run by 30m.",
        interpretation="Timestamps were manipulated to hide execution order.",
    )
    d = f.to_dict()
    assert d["observation"] == "MFT $SI mtime is later than Prefetch last-run by 30m."
    assert d["interpretation"] == "Timestamps were manipulated to hide execution order."
    restored = Finding.from_dict(d)
    assert restored.observation == f.observation
    assert restored.interpretation == f.interpretation


# ─── engine-wide: every real-corpus finding gets a source_exec_id ────────────


def test_causality_finding_populates_observation_and_interpretation() -> None:
    """Proof-of-use: the highest-volume finding type actually fills the split.

    The observation cites the raw cross-artifact discrepancy; the interpretation
    is the analytic conclusion. Guards against the fields being dead scaffolding.
    """
    import tests.scenario_harness as harness

    ransomware = next(
        e
        for e in harness.discover_scenarios(harness._REPO_ROOT)
        if e.name == "02_ransomware"
    )
    causality = [
        f
        for f in harness.run_scenario(ransomware).findings
        if f.title.startswith("Suspicious Activity")
    ]
    assert causality, "expected causality findings in 02_ransomware"
    for finding in causality:
        assert finding.observation, "observation must cite the raw discrepancy"
        assert finding.interpretation, "interpretation must state the conclusion"
        assert finding.observation != finding.interpretation


def test_every_scenario_finding_has_a_source_exec_id() -> None:
    """The derivation is load-bearing on the real corpus: no finding is left
    without an exec id, which is the precondition PR-C's flip depends on."""
    import tests.scenario_harness as harness

    total = 0
    missing = 0
    for expectation in harness.discover_scenarios(harness._REPO_ROOT):
        for finding in harness.run_scenario(expectation).findings:
            total += 1
            if not finding.source_exec_id:
                missing += 1
    assert total >= 100
    assert missing == 0
