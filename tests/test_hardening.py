"""Tests for the shared finding-hardening pipeline (execution-path convergence).

The orchestrator's demo path already hardens every finding (verdict clamp,
receipt, provenance-style checks, adversarial adjudication, MITRE). The recall
harness produced findings but carried none of that hardening - so the F1=1.00
result and the integrity guarantees ran on disjoint paths. This module extracts
the hardening into one reusable pipeline both paths call, so EVERY scenario's
findings are hardened without changing which findings exist (F1 is unaffected).

RED-first: sift_find_evil.hardening did not exist before.
"""

from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.hardening import HardeningReport, harden_findings

KEY = b"k" * 32
IMAGE = "a" * 64


def _finding(
    title="evil.exe executed",
    severity="high",
    sources=None,
    mitre=None,
    reasoning="a socket to 1.2.3.4 was observed",
):
    ev = {"executable": "evil.exe"}
    if mitre:
        ev["mitre_attack"] = mitre
    return Finding(
        title=title,
        description="d",
        finding_type="indicator",
        severity=severity,
        category=FindingCategory.EXECUTION,
        evidence=ev,
        confidence=0.9,
        reasoning_chain=[reasoning],
        artifact_sources=sources or ["MFT", "Prefetch"],
    )


def test_harden_returns_report_with_one_entry_per_finding():
    findings = [_finding(), _finding(title="other.exe")]
    report = harden_findings(findings, image_sha256=IMAGE, receipt_key=KEY)
    assert isinstance(report, HardeningReport)
    assert len(report.hardened) == 2


def test_every_finding_gets_a_verifiable_receipt():
    findings = [_finding()]
    report = harden_findings(findings, image_sha256=IMAGE, receipt_key=KEY)
    item = report.hardened[0]
    assert "receipt" in item
    assert item["receipt"]["image_sha256"] == IMAGE
    # The receipt verifies against the sealed finding content.
    from sift_find_evil.custody.receipt import verify_receipt

    assert verify_receipt(item["finding"], item["receipt"], key=KEY) is True


def test_hardening_does_not_change_which_executables_are_detected():
    # The invariant that protects F1: hardening must not add/drop/rename findings.
    findings = [_finding(title="a.exe"), _finding(title="b.exe")]
    before = sorted(f.evidence.get("executable", "") for f in findings)
    report = harden_findings(findings, image_sha256=IMAGE, receipt_key=KEY)
    after = sorted(
        item["finding"]["evidence"].get("executable", "") for item in report.hardened
    )
    assert before == after
    assert report.finding_count == len(findings)


def test_single_source_over_read_flagged_multi_source_supported():
    # The seat check judges the reasoning-chain CLAIM, not the title. A
    # single-source finding claiming execution over-reads shimcache/MFT.
    over = _finding(
        title="over", sources=["shimcache"], reasoning="the program executed from disk"
    )
    ok = _finding(
        title="corroborated",
        sources=["MFT", "EventLog", "Prefetch"],
        reasoning="the program executed from disk",
    )
    report = harden_findings([over, ok], image_sha256=IMAGE, receipt_key=KEY)
    sem = {
        item["finding"]["title"]: item["checks"]["tool_semantics"]
        for item in report.hardened
    }
    assert sem["over"] == "MISREAD_TOOL"
    assert sem["corroborated"] == "SUPPORTED"


def test_verdict_clamp_caps_single_source_below_top_tier():
    f = _finding(severity="critical", sources=["shimcache"])
    report = harden_findings([f], image_sha256=IMAGE, receipt_key=KEY)
    assert report.hardened[0]["finding"]["severity"] != "critical"


def test_mitre_matrix_confirmed_from_detector_tags_only():
    f = _finding(mitre=["T1055"])
    report = harden_findings([f], image_sha256=IMAGE, receipt_key=KEY)
    ids = [e["technique_id"] for e in report.mitre_confirmed]
    assert "T1055" in ids


def test_empty_findings_yield_empty_report():
    report = harden_findings([], image_sha256=IMAGE, receipt_key=KEY)
    assert report.finding_count == 0
    assert report.hardened == []
    assert report.mitre_confirmed == []


def test_report_is_json_serializable():
    import json

    report = harden_findings(
        [_finding(mitre=["T1055"])], image_sha256=IMAGE, receipt_key=KEY
    )
    text = json.dumps(report.to_dict())
    assert json.loads(text)["finding_count"] == 1
