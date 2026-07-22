"""Cross-artifact correlation wired into the hardening pipeline (move #3).

SQL cross-artifact + graph cross-host correlation existed with 100% coverage but
were never invoked in an investigation. This wires SQL timeline correlation into
the shared hardening pipeline: findings that carry timeline evidence
(timestamp/source/actor) are correlated across sources, and same-actor
different-type overlaps surface as UNRESOLVED contradictions in the report.
Additive only - findings are never changed, so F1 is unaffected.

RED-first: HardeningReport had no correlation/contradiction fields.
"""

from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.hardening import harden_findings

KEY = b"k" * 32
IMAGE = "a" * 64


def _f(title, source, actor, ts, etype, category=FindingCategory.EXECUTION):
    return Finding(
        title=title,
        description="d",
        finding_type="indicator",
        severity="high",
        category=category,
        evidence={
            "executable": actor,
            "timeline": {
                "ts": ts,
                "source": source,
                "actor": actor,
                "target": "",
                "type": etype,
            },
        },
        confidence=0.9,
        artifact_sources=[source],
    )


def test_cross_source_findings_correlate():
    # Same actor seen by two DIFFERENT sources within the window -> a correlation.
    findings = [
        _f("a", "mft", "evil.exe", "2026-07-20T10:00:00", "created"),
        _f("b", "evtx", "evil.exe", "2026-07-20T10:00:02", "created"),
    ]
    report = harden_findings(findings, image_sha256=IMAGE, receipt_key=KEY)
    assert report.correlations, "expected a cross-source correlation"


def test_same_actor_different_type_surfaces_unresolved_contradiction():
    findings = [
        _f("a", "mft", "svc.exe", "2026-07-20T10:00:00", "created"),
        _f("b", "evtx", "svc.exe", "2026-07-20T10:00:01", "deleted"),
    ]
    report = harden_findings(findings, image_sha256=IMAGE, receipt_key=KEY)
    assert report.contradictions, "expected an UNRESOLVED contradiction"
    assert all(c.get("status") == "UNRESOLVED" for c in report.contradictions)


def test_findings_without_timeline_evidence_do_not_break_correlation():
    # A plain finding (no timeline evidence) must not error; just yields no corr.
    f = Finding(
        title="plain",
        description="d",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.EXECUTION,
        evidence={"executable": "x.exe"},
        confidence=0.9,
        artifact_sources=["mft"],
    )
    report = harden_findings([f], image_sha256=IMAGE, receipt_key=KEY)
    assert report.correlations == []
    assert report.contradictions == []
    # Hardening itself still happened (receipt minted).
    assert report.receipts_minted == 1


def test_finding_with_malformed_timeline_is_skipped():
    # A timeline dict missing ts/source is skipped (not correlated, no error).
    bad = Finding(
        title="bad",
        description="d",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.EXECUTION,
        evidence={
            "executable": "x.exe",
            "timeline": {"actor": "x.exe"},
        },  # no ts/source
        confidence=0.9,
        artifact_sources=["mft"],
    )
    report = harden_findings([bad], image_sha256=IMAGE, receipt_key=KEY)
    assert report.correlations == []
    assert report.contradictions == []
    assert report.receipts_minted == 1


def test_correlation_does_not_change_finding_count():
    findings = [
        _f("a", "mft", "evil.exe", "2026-07-20T10:00:00", "created"),
        _f("b", "evtx", "evil.exe", "2026-07-20T10:00:02", "created"),
    ]
    report = harden_findings(findings, image_sha256=IMAGE, receipt_key=KEY)
    assert report.finding_count == 2
    assert len(report.hardened) == 2


def test_report_with_correlations_is_json_serializable():
    import json

    findings = [
        _f("a", "mft", "evil.exe", "2026-07-20T10:00:00", "created"),
        _f("b", "pcap", "evil.exe", "2026-07-20T10:00:03", "connected"),
    ]
    report = harden_findings(findings, image_sha256=IMAGE, receipt_key=KEY)
    text = json.dumps(report.to_dict())
    assert "correlations" in json.loads(text)
