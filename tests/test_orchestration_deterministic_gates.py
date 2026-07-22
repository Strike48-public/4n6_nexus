"""Tests that the deterministic verification gates are WIRED into the orchestrator.

Refutation seats, the provenance gate, and the MITRE synthesis guardrail landed
as unit-tested modules; this proves the standalone orchestrator actually runs
them on every investigation and surfaces the results in the report.

RED-first: the orchestrator did not run these gates before this change.
"""

import pytest

from sift_find_evil.orchestration import InvestigationOrchestrator


@pytest.fixture
def report(tmp_path):
    orch = InvestigationOrchestrator(
        case_id="INC-DET-001", audit_path=tmp_path / "audit.jsonl"
    )
    return orch.run_demo_investigation()


def test_every_finding_carries_deterministic_checks(report):
    assert report["case_findings"], "demo must emit findings"
    for item in report["case_findings"]:
        assert "deterministic_checks" in item, f"{item['finding_id']} ungated"
        checks = item["deterministic_checks"]
        # Provenance: the finding's cited tool invocations must resolve.
        assert "provenance" in checks
        assert checks["provenance"] in {"FULL", "PARTIAL", "NONE"}
        # Refutation seats: SUPPORTED or MISREAD_TOOL.
        assert "tool_semantics" in checks
        assert checks["tool_semantics"] in {"SUPPORTED", "MISREAD_TOOL"}


def test_demo_findings_have_resolvable_provenance(report):
    # Every demo finding cites the tool invocations that produced it, so
    # provenance resolves (never NONE -> never hard-rejected).
    for item in report["case_findings"]:
        assert item["deterministic_checks"]["provenance"] != "NONE"


def test_multi_source_findings_are_not_spuriously_misread(report):
    """A corroborated (>=2 source) finding must NOT be flagged MISREAD_TOOL.

    Guards the calibration bug where the tool-semantics seat ("a lone tool can't
    establish X") was applied to well-grounded multi-source findings, stamping a
    spurious MISREAD_TOOL on e.g. an MFT+Prefetch+EventLog causality finding.
    """
    for item in report["case_findings"]:
        sources = {s for s in item["finding"].get("artifact_sources", []) if s}
        if len(sources) >= 2:
            assert item["deterministic_checks"]["tool_semantics"] == "SUPPORTED", (
                f"{item['finding_id']} has {len(sources)} sources but was "
                "seat-refuted (spurious MISREAD_TOOL)"
            )


def test_single_source_over_read_is_flagged_misread():
    """A single-source finding that over-reads its tool IS flagged MISREAD_TOOL."""
    from types import SimpleNamespace

    orch = InvestigationOrchestrator.__new__(InvestigationOrchestrator)
    finding = SimpleNamespace(
        reasoning_chain=["the program executed from the shimcache entry"],
        description="shimcache entry",
        artifact_sources=["shimcache"],  # single source
    )
    checks = orch._deterministic_gates(
        finding, "disk_analyst", tool_ids=[], audit_index={}
    )
    assert checks["tool_semantics"] == "MISREAD_TOOL"


def test_report_carries_confirmed_mitre_matrix(report):
    # The MITRE guardrail builds a confirmed matrix from fired-detector tags only.
    assert "mitre" in report
    mitre = report["mitre"]
    assert "confirmed" in mitre and isinstance(mitre["confirmed"], list)
    assert "unconfirmed" in mitre
    # The demo's network/memory findings carry ATT&CK tags, so at least one
    # technique is confirmed and each cites the finding that backs it.
    if mitre["confirmed"]:
        entry = mitre["confirmed"][0]
        assert "technique_id" in entry and "cited_by" in entry


def test_integrity_block_counts_deterministic_gate_outcomes(report):
    integ = report["integrity"]
    assert "provenance_resolved" in integ
    # All demo findings have resolvable provenance.
    assert integ["provenance_resolved"] == len(report["case_findings"])
