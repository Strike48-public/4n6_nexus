"""Subject risk scoring wired into the hardening overlay (SFE-dkfr).

SFE-kh4h shipped ``findings.risk_scoring.score_subject_risk`` as a tested-but-
unwired pure module. This makes it load-bearing on the SHARED scored path:
``harden_findings`` now computes per-subject risk and exposes it on the
``HardeningReport`` (field + ``to_dict``), so both the recall harness and the
live orchestrator surface it. Additive metadata only -- no finding is added,
dropped, or re-scored -- so F1 is unaffected.

RED-first: HardeningReport had no ``subject_risk`` field / dict key.
"""

from __future__ import annotations

from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.hardening import harden_findings

KEY = b"k" * 32
IMAGE = "a" * 64


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


def test_report_exposes_subject_risk_field_and_dict_key():
    findings = [
        _f("a", FindingCategory.CREDENTIAL_THEFT, "evil.exe", 0.9, ["memory"]),
        _f("b", FindingCategory.ANTI_FORENSICS, "evil.exe", 0.9, ["mft"]),
    ]
    report = harden_findings(findings, image_sha256=IMAGE, receipt_key=KEY)
    assert report.subject_risk, "expected a scored subject"
    as_dict = report.to_dict()
    assert "subject_risk" in as_dict
    # Each entry is the SubjectRisk.to_dict() shape.
    top = report.subject_risk[0]
    assert top["subject"] == "evil.exe"
    assert {"subject", "band", "score", "distinct_sources", "contributors"} <= set(top)


def test_corroborated_multi_artifact_subject_is_critical():
    # Same subject across THREE distinct artifact types -> CRITICAL (gate met).
    findings = [
        _f("c1", FindingCategory.CREDENTIAL_THEFT, "evil.exe", 0.9, ["memory"]),
        _f("c2", FindingCategory.ANTI_FORENSICS, "evil.exe", 0.9, ["mft"]),
        _f("c3", FindingCategory.COMMAND_AND_CONTROL, "evil.exe", 0.9, ["pcap"]),
    ]
    report = harden_findings(findings, image_sha256=IMAGE, receipt_key=KEY)
    assert report.subject_risk[0]["band"] == "critical"


def test_subject_risk_is_sorted_highest_first():
    findings = [
        _f("low", FindingCategory.RECONNAISSANCE, "low.exe", 0.3, ["evtx"]),
        _f("hi1", FindingCategory.CREDENTIAL_THEFT, "hi.exe", 0.9, ["memory"]),
        _f("hi2", FindingCategory.ANTI_FORENSICS, "hi.exe", 0.9, ["mft"]),
    ]
    report = harden_findings(findings, image_sha256=IMAGE, receipt_key=KEY)
    scores = [s["score"] for s in report.subject_risk]
    assert scores == sorted(scores, reverse=True)
    assert report.subject_risk[0]["subject"] == "hi.exe"


def test_subject_risk_is_additive_overlay_finding_count_unchanged():
    findings = [
        _f("a", FindingCategory.EXECUTION, "evil.exe", 0.6, ["mft"]),
        _f("b", FindingCategory.PERSISTENCE, "evil.exe", 0.6, ["registry"]),
    ]
    report = harden_findings(findings, image_sha256=IMAGE, receipt_key=KEY)
    # The overlay does not add/drop findings; the scored set is untouched.
    assert report.finding_count == 2
    assert len(report.hardened) == 2


def test_no_findings_yields_empty_subject_risk():
    report = harden_findings([], image_sha256=IMAGE, receipt_key=KEY)
    assert report.subject_risk == []
    assert "subject_risk" in report.to_dict()


def test_report_with_subject_risk_is_json_serializable():
    import json

    findings = [
        _f("a", FindingCategory.CREDENTIAL_THEFT, "evil.exe", 0.9, ["memory"]),
        _f("b", FindingCategory.COMMAND_AND_CONTROL, "evil.exe", 0.9, ["pcap"]),
    ]
    report = harden_findings(findings, image_sha256=IMAGE, receipt_key=KEY)
    text = json.dumps(report.to_dict())
    assert "subject_risk" in json.loads(text)
