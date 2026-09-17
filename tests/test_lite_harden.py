"""Lite-harden for the interactive connector/GUI seam (SFE-i596).

The full ``harden_findings`` overlay (receipts + Merkle anchor + DuckDB
correlation + MITRE) is too heavy for every interactive GUI request, so the live
connector path (analyze_artifacts -> make_analyze_fn) historically returned RAW
detector findings -- which could show a HIGHER, un-clamped severity than the
defensible scored path, and carried no subject-risk triage signal.

``lite_harden`` applies the CHEAP, correctness-critical half: the verdict clamps
(severity ceiling + single-source cap, via guard_finding) and the per-subject
risk overlay (score_subject_risk). It does NOT sign receipts, mint an anchor, or
run correlation -- those stay on the ``analyze --harden`` custody CLI. So the GUI
gets defensible severities + risk bands without the custody-chain cost.

Invariant: F1=1.00 -- clamps only re-derive SEVERITY (metadata), never the
detection scoring key evidence['executable']; risk is a read-only overlay.

RED-first: sift_find_evil.hardening.lite_harden does not exist yet.
"""

from __future__ import annotations

from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.hardening import lite_harden


def _f(title, category, executable, severity, confidence, sources):
    return Finding(
        title=title,
        description="d",
        finding_type="indicator",
        severity=severity,
        category=category,
        evidence={"executable": executable},
        confidence=confidence,
        artifact_sources=list(sources),
    )


# -- the clamps are applied (defensible severities) -------------------------


def test_single_source_severity_is_capped():
    # A lone-source finding claiming 'critical' must be capped by the
    # single-source ceiling -- the whole reason the GUI must not show raw output.
    findings = [
        _f("a", FindingCategory.EXECUTION, "evil.exe", "critical", 0.9, ["mft"]),
    ]
    hardened, _risk = lite_harden(findings)
    assert hardened[0].severity != "critical", (
        "a single-source finding must be clamped below critical pending "
        "corroboration; the GUI must not render the raw un-clamped severity"
    )


def test_corroborated_finding_keeps_its_severity():
    # Two distinct sources on one subject: the single-source cap does not apply.
    findings = [
        _f("a", FindingCategory.EXECUTION, "evil.exe", "high", 0.9, ["mft", "memory"]),
    ]
    hardened, _risk = lite_harden(findings)
    assert hardened[0].severity == "high", "a corroborated finding keeps its severity"


def test_lite_harden_returns_subject_risk():
    findings = [
        _f("a", FindingCategory.CREDENTIAL_THEFT, "evil.exe", "high", 0.9, ["memory"]),
        _f("b", FindingCategory.ANTI_FORENSICS, "evil.exe", "high", 0.9, ["mft"]),
    ]
    _hardened, risk = lite_harden(findings)
    assert risk, "expected a scored subject"
    assert risk[0]["subject"] == "evil.exe"
    assert {"subject", "band", "score", "distinct_sources"} <= set(risk[0])


# -- lite: no receipts / anchor / correlation -------------------------------


def test_lite_harden_does_not_sign_or_correlate():
    """Lite must be cheap: no receipt, no signed_receipt, no anchor.

    Those are the custody-chain features reserved for `analyze --harden`; lite is
    the interactive path, so it returns only clamped findings + risk.
    """
    findings = [
        _f("a", FindingCategory.EXECUTION, "evil.exe", "high", 0.9, ["mft"]),
    ]
    hardened, _risk = lite_harden(findings)
    # Returned findings are plain Finding objects, not receipt-wrapped dicts.
    for f in hardened:
        assert isinstance(f, Finding)
        assert not hasattr(f, "receipt")


# -- overlay invariants -----------------------------------------------------


def test_lite_harden_preserves_finding_count_and_does_not_mutate_input():
    original = _f("a", FindingCategory.EXECUTION, "evil.exe", "critical", 0.9, ["mft"])
    hardened, _risk = lite_harden([original])
    assert len(hardened) == 1, "no finding added or dropped"
    # The input finding object is not mutated in place (clamp returns a copy).
    assert original.severity == "critical", "input finding must not be mutated"


def test_empty_findings_yields_empty_outputs():
    hardened, risk = lite_harden([])
    assert hardened == []
    assert risk == []
