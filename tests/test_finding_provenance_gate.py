"""The source_exec_id construction gate (SFE-fibx.4 PR-C, breaking).

PR-B made source_exec_id always-derivable; this flips it to an ENFORCED invariant:
a Finding cannot be constructed without a non-empty provenance id. Because
__post_init__ derives one from the finding's own provenance, this never rejects a
real finding (verified across the whole corpus) — it makes the guarantee
un-bypassable: a whitespace-only id is treated as unset (and derived), and if
derivation itself ever produced empty, construction fails loudly rather than
emitting an unprovenanced finding.
"""

from __future__ import annotations

import pytest

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


def test_whitespace_only_exec_id_is_treated_as_unset_and_derived() -> None:
    """A blank/whitespace id must NOT pass as provenance; it is re-derived.

    Guards the truthiness hole: ``if self.source_exec_id`` treated ``"   "`` as
    set, keeping a finding that looked provenanced but was not.
    """
    f = _finding(source_exec_id="   ", artifact_sources=["MFT"])
    assert f.source_exec_id.strip()
    assert f.source_exec_id.startswith("mft:")


def test_explicit_real_exec_id_still_respected() -> None:
    """A genuine tool-run id is still kept verbatim (the gate only rejects empty)."""
    assert _finding(source_exec_id="mftecmd-001").source_exec_id == "mftecmd-001"


def test_construction_fails_when_derivation_yields_empty(monkeypatch) -> None:
    """If derivation ever returns empty, construction must RAISE, not emit a
    finding with no provenance. This is the enforced invariant PR-C adds."""
    monkeypatch.setattr(Finding, "_derive_source_exec_id", lambda self: "")
    with pytest.raises(ValueError, match="source_exec_id"):
        _finding(artifact_sources=["MFT"])


def test_normal_construction_still_succeeds() -> None:
    """The overwhelmingly-common path (no explicit id) is unaffected: derivation
    yields a non-empty id and construction succeeds."""
    f = _finding(artifact_sources=["MFT"], evidence={"executable": "x.exe"})
    assert f.source_exec_id


def test_none_evidence_does_not_crash_derivation() -> None:
    """A caller passing ``evidence=None`` must not crash the derivation.

    Derivation reads ``evidence.get(...)``; an explicit None (from a caller or
    legacy ``"evidence": null`` JSON reaching from_dict) is normalized to {} in
    __post_init__ before that read, so construction still yields a stable id.
    """
    f = _finding(evidence=None, artifact_sources=["MFT"])
    assert f.source_exec_id.startswith("mft:")
    assert f.evidence == {}


def test_legacy_json_with_null_evidence_round_trips() -> None:
    """from_dict on legacy JSON carrying ``evidence: null`` derives cleanly."""
    legacy = {
        "title": "t",
        "description": "d",
        "type": "indicator",
        "severity": "high",
        "category": "process_injection",
        "detected_at": "2025-01-01T00:00:00",
        "evidence": None,
    }
    f = Finding.from_dict(legacy)
    assert f.source_exec_id
    assert f.evidence == {}


def test_every_scenario_finding_survives_the_gate() -> None:
    """The whole real corpus constructs without tripping the gate — proof the flip
    reddens no existing scenario (the precondition for shipping it)."""
    import tests.scenario_harness as harness

    total = 0
    for expectation in harness.discover_scenarios(harness._REPO_ROOT):
        # If any finding tripped the gate, run_scenario would raise here.
        for finding in harness.run_scenario(expectation).findings:
            total += 1
            assert finding.source_exec_id
    assert total >= 100
