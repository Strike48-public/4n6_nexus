"""Tests that the integrity primitives are WIRED into the live orchestrator.

The primitives (hash-chained audit, finding receipts, verdict clamp, chain
verification) landed with unit tests in the prior PR; this suite proves they are
actually exercised by ``InvestigationOrchestrator.run_demo_investigation`` -
i.e. every finding the standalone path emits carries a valid receipt, severities
are structurally clamped, and the report asserts an intact audit chain.

RED-first: the orchestrator did not mint receipts, clamp verdicts, or verify the
chain before this change.
"""

import pytest

from sift_find_evil.orchestration import InvestigationOrchestrator


@pytest.fixture
def run(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    orch = InvestigationOrchestrator(case_id="INC-TEST-001", audit_path=audit_path)
    report = orch.run_demo_investigation()
    return orch, report, audit_path


def test_report_declares_integrity_block(run):
    _orch, report, _ = run
    assert "integrity" in report
    integ = report["integrity"]
    assert integ["audit_chain_verified"] is True
    assert integ["broken_at"] is None
    # The evidence-image binding the receipts commit to is surfaced.
    assert "image_sha256" in integ
    assert len(integ["image_sha256"]) == 64


def test_every_finding_has_a_receipt(run):
    _orch, report, _ = run
    assert report["case_findings"], "demo must emit at least one finding"
    for item in report["case_findings"]:
        assert "receipt" in item, f"{item['finding_id']} has no receipt"
        r = item["receipt"]
        assert len(r["signature"]) == 64
        assert r["image_sha256"] == report["integrity"]["image_sha256"]


def test_receipts_verify_against_run_key(run):
    orch, report, _ = run
    # The orchestrator exposes its run-scoped minter so a verifier can re-check.
    for item in report["case_findings"]:
        assert orch.receipt_minter.verify(item["finding"], item["receipt"]) is True


def test_tampered_finding_fails_its_receipt(run):
    orch, report, _ = run
    item = report["case_findings"][0]
    forged = {**item["finding"], "severity": "info", "title": "nothing to see"}
    assert orch.receipt_minter.verify(forged, item["receipt"]) is False


def test_live_audit_chain_verifies(run):
    orch, _report, _audit_path = run
    ok, broken_at, reason = orch.server.audit_logger.verify_chain()
    assert ok is True, f"chain broke at {broken_at}: {reason}"


def test_standalone_verifier_agrees_on_the_live_log(run):
    import subprocess
    import sys
    from pathlib import Path

    _orch, _report, audit_path = run
    tool = Path(__file__).resolve().parents[1] / "tools" / "verify_chain.py"
    res = subprocess.run(
        [sys.executable, str(tool), str(audit_path)],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, res.stdout + res.stderr


def test_severity_never_exceeds_engine_ceiling(run):
    """No emitted finding is more severe than a single-source finding may be.

    The demo findings are largely single-source; the verdict clamp must have
    prevented any 'critical' that lacks >=2 distinct artifact sources.
    """
    _orch, report, _ = run
    for item in report["case_findings"]:
        f = item["finding"]
        sources = f.get("artifact_sources", [])
        if len({s for s in sources if s}) < 2:
            assert f["severity"] != "critical", (
                f"{item['finding_id']} is single-source but severity=critical "
                "(verdict clamp not applied)"
            )
